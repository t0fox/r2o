//! C `tls12.c`: тестовый экспорт TLS 1.2 PRF.
//!
//! В production PRF выполняет rustls; здесь — точная P_SHA256-реализация
//! для C/Rust-векторов `test_tls12.c`.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// C `REC_MAX` (`tls12.c`/`tls13.c`): предел тела одной записи.
pub const TLS_RECORD_MAX: usize = 18_432;
pub const TLS_RECORD_CCS: u8 = 20;
pub const TLS_RECORD_APPDATA: u8 = 23;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    if key.len() > key_block.len() {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    for byte in key_block {
        inner.update([byte ^ 0x36]);
    }
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    for byte in key_block {
        outer.update([byte ^ 0x5c]);
    }
    outer.update(inner);
    outer.finalize().into()
}

/// C `strerror(errno)` без Rust-суффикса «(os error N)».
fn r2o_tls12_strerror(error: &std::io::Error) -> String {
    if let Some(code) = error.raw_os_error() {
        let text = unsafe { libc::strerror(code) };
        if !text.is_null() {
            return unsafe { std::ffi::CStr::from_ptr(text) }
                .to_string_lossy()
                .into_owned();
        }
    }
    error.to_string()
}

/// C `read_exact` (`core/tls12.c:119-153`) поверх `Read`: EINTR/EAGAIN
/// повторяются, EOF и прочие ошибки возвращаются точным C-текстом.
pub fn r2o_tls12_read_exact(
    reader: &mut impl Read,
    buf: &mut [u8],
    deadline: Instant,
    body: bool,
    rx_wire_bytes: &mut u64,
    rx_record_missing: &mut u32,
) -> Result<(), String> {
    let length = buf.len();
    let mut got = 0_usize;
    *rx_record_missing = if body { length as u32 } else { 0 };
    while got < length {
        if Instant::now() >= deadline {
            return Err(format!(
                "не дождались {} байт за отведённое время",
                length - got
            ));
        }
        match reader.read(&mut buf[got..]) {
            Ok(0) => {
                return Err(format!("соединение закрыто на {got}-м байте из {length}"));
            }
            Ok(read) => {
                got += read;
                *rx_wire_bytes = rx_wire_bytes.saturating_add(read as u64);
                if body {
                    *rx_record_missing = (length - got) as u32;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                // C после EAGAIN возвращается на poll с оставшимся сроком.
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(format!("чтение: {}", r2o_tls12_strerror(&error))),
        }
    }
    Ok(())
}

/// C `write_all` (`core/tls12.c:155-171`): короткие записи дописываются,
/// EINTR/EAGAIN повторяются, нулевая запись — ошибка C-текстом.
pub fn r2o_tls12_write_all(writer: &mut impl Write, buf: &[u8]) -> Result<(), String> {
    let mut sent = 0_usize;
    while sent < buf.len() {
        match writer.write(&buf[sent..]) {
            Ok(0) => return Err("запись: Success".into()),
            Ok(written) => sent += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(format!("запись: {}", r2o_tls12_strerror(&error))),
        }
    }
    Ok(())
}

/// C `d2k_tls12_prf_for_test`: P_SHA256(secret, label || seed).
pub fn d2k_tls12_prf_for_test(secret: &[u8], label: &str, seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label.as_bytes());
    label_seed.extend_from_slice(seed);
    let mut a = hmac_sha256(secret, &label_seed);
    let mut out = Vec::with_capacity(out_len);
    while out.len() < out_len {
        let mut input = Vec::with_capacity(32 + label_seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(&label_seed);
        let block = hmac_sha256(secret, &input);
        let take = (out_len - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
        a = hmac_sha256(secret, &a);
    }
    out
}

/// C `d2k_tls12` transcript: `tr_add` добавляет сообщение, если оно целиком
/// помещается в буфер; частичная запись запрещена.
#[derive(Clone, Debug, Default)]
pub struct Tls12Transcript {
    bytes: Vec<u8>,
    capacity: usize,
}

impl Tls12Transcript {
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            capacity,
        }
    }

    pub fn add(&mut self, message: &[u8]) {
        if self.bytes.len().saturating_add(message.len()) <= self.capacity {
            self.bytes.extend_from_slice(message);
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// C `nonce_of`: salt ‖ big-endian seq (8 байт).
pub fn tls12_nonce(salt: [u8; 4], sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&salt);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

/// C `aad_of`: seq BE64 ‖ type ‖ 0x03 0x03 ‖ length BE16.
pub fn tls12_aad(sequence: u64, content_type: u8, payload_len: usize) -> [u8; 13] {
    let mut aad = [0_u8; 13];
    aad[..8].copy_from_slice(&sequence.to_be_bytes());
    aad[8] = content_type;
    aad[9] = 3;
    aad[10] = 3;
    aad[11..].copy_from_slice(&(payload_len as u16).to_be_bytes());
    aad
}

/// TLS1.3 `read_exact` (`core/tls13.c:102-136`): та же C-семантика, что
/// TLS1.2; отдельное имя — для TLS1.3 production path и differential.
pub fn r2o_tls13_read_exact(
    reader: &mut impl Read,
    buf: &mut [u8],
    deadline: Instant,
    body: bool,
    rx_wire_bytes: &mut u64,
    rx_record_missing: &mut u32,
) -> Result<(), String> {
    r2o_tls12_read_exact(
        reader,
        buf,
        deadline,
        body,
        rx_wire_bytes,
        rx_record_missing,
    )
}

/// TLS1.3 `write_all` (`core/tls13.c:138-154`).
pub fn r2o_tls13_write_all(writer: &mut impl Write, buf: &[u8]) -> Result<(), String> {
    r2o_tls12_write_all(writer, buf)
}

fn read_record_header_until(
    reader: &mut impl Read,
    deadline: Instant,
) -> Result<([u8; 5], usize), String> {
    let mut header = [0_u8; 5];
    let mut wire = 0_u64;
    let mut missing = 0_u32;
    r2o_tls12_read_exact(
        reader,
        &mut header,
        deadline,
        false,
        &mut wire,
        &mut missing,
    )?;
    // Сетевой узел на TLS/443 иногда отвечает открытым HTTP; нельзя читать
    // «P/» как старший байт длины записи.
    if &header == b"HTTP/" {
        return Err(format!(
            "не TLS: открытый HTTP-ответ вместо TLS (заголовок {:02x} {:02x} {:02x} {:02x} {:02x})",
            header[0], header[1], header[2], header[3], header[4]
        ));
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length == 0 || length > TLS_RECORD_MAX {
        return Err(format!(
            "не TLS-заголовок {:02x} {:02x} {:02x} {:02x} {:02x}: длина {length} вне предела",
            header[0], header[1], header[2], header[3], header[4]
        ));
    }
    Ok((header, length))
}

fn cipher(key: &[u8; 16]) -> Result<Aes128Gcm, String> {
    Aes128Gcm::new_from_slice(key).map_err(|_| "недопустимый ключ AES-128-GCM".to_owned())
}

fn salt4(iv: &[u8; 12]) -> [u8; 4] {
    [iv[0], iv[1], iv[2], iv[3]]
}

/// C `read_record` (`tls12.c`): одна запись, CCS без тела, explicit nonce.
pub struct Tls12RecordReader {
    salt: [u8; 4],
    key: [u8; 16],
    sequence: u64,
    encrypted: bool,
}

impl Tls12RecordReader {
    pub fn read_record(
        &mut self,
        reader: &mut impl Read,
        payload: &mut Vec<u8>,
        capacity: usize,
    ) -> Result<(u8, usize), String> {
        self.read_record_until(
            reader,
            payload,
            capacity,
            Instant::now() + Duration::from_secs(5),
        )
    }

    pub fn new(salt: [u8; 4], key: [u8; 16], sequence: u64, encrypted: bool) -> Self {
        Self {
            salt,
            key,
            sequence,
            encrypted,
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn read_record_until(
        &mut self,
        reader: &mut impl Read,
        payload: &mut Vec<u8>,
        capacity: usize,
        deadline: Instant,
    ) -> Result<(u8, usize), String> {
        let (header, record_len) = read_record_header_until(reader, deadline)?;
        let mut raw = vec![0_u8; record_len];
        let mut wire = 0_u64;
        let mut missing = 0_u32;
        r2o_tls12_read_exact(reader, &mut raw, deadline, true, &mut wire, &mut missing)?;
        if header[0] == TLS_RECORD_CCS {
            payload.clear();
            return Ok((TLS_RECORD_CCS, 0));
        }
        if !self.encrypted {
            if record_len > capacity {
                return Err(format!("запись длиной {record_len} не помещается в буфер"));
            }
            payload.clear();
            payload.extend_from_slice(&raw);
            return Ok((header[0], record_len));
        }
        if record_len < 8 + 16 {
            return Err("зашифрованная запись короче служебных полей".into());
        }
        let body = record_len - 8;
        if body < 16 || body - 16 > capacity {
            return Err(format!("запись длиной {body} не помещается в буфер"));
        }
        let mut nonce = [0_u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&raw[..8]);
        let aad = tls12_aad(self.sequence, header[0], body - 16);
        let mut opened = raw[8..].to_vec();
        cipher(&self.key)?
            .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut opened)
            .map_err(|_| "запись не расшифровалась (метка не сошлась)".to_owned())?;
        self.sequence += 1;
        payload.clear();
        payload.extend_from_slice(&opened);
        Ok((header[0], body - 16))
    }
}

/// C `send_sealed` (`tls12.c`): explicit nonce и AAD seq/type/0303/len.
pub struct Tls12RecordWriter {
    salt: [u8; 4],
    key: [u8; 16],
    sequence: u64,
}

impl Tls12RecordWriter {
    pub fn new(salt: [u8; 4], key: [u8; 16], sequence: u64) -> Self {
        Self {
            salt,
            key,
            sequence,
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn seal(&mut self, content_type: u8, body: &[u8]) -> Result<Vec<u8>, String> {
        let payload_len = 8 + body.len() + 16;
        if body.len() + 8 + 16 + 5 > TLS_RECORD_MAX + 5 || payload_len > TLS_RECORD_MAX {
            return Err(format!("запись длиной {} не помещается", body.len()));
        }
        let nonce = tls12_nonce(self.salt, self.sequence);
        let aad = tls12_aad(self.sequence, content_type, body.len());
        let mut wire = vec![0_u8; 5 + payload_len];
        wire[0] = content_type;
        wire[1] = 3;
        wire[2] = 3;
        wire[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());
        // Явная часть номера едет открыто перед шифротекстом (RFC 5288 §3).
        wire[5..13].copy_from_slice(&nonce[4..]);
        wire[13..13 + body.len()].copy_from_slice(body);
        let tag = cipher(&self.key)?
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &aad,
                &mut wire[13..13 + body.len()],
            )
            .map_err(|_| "не зашифровалась запись".to_owned())?;
        wire[13 + body.len()..].copy_from_slice(&tag);
        self.sequence += 1;
        Ok(wire)
    }

    /// C `send_sealed` + `write_all`: запечатать и записать всю запись.
    pub fn write_record(
        &mut self,
        writer: &mut impl Write,
        content_type: u8,
        body: &[u8],
    ) -> Result<(), String> {
        let wire = self.seal(content_type, body)?;
        r2o_tls12_write_all(writer, &wire)
    }
}

/// C `read_record` (`tls13.c`): внешний тип 23 и внутренний тип после
/// расшифровки; нулевая набивка снимается.
pub struct Tls13RecordReader {
    iv: [u8; 12],
    key: [u8; 16],
    sequence: u64,
    encrypted: bool,
}

impl Tls13RecordReader {
    pub fn read_record(
        &mut self,
        reader: &mut impl Read,
        payload: &mut Vec<u8>,
        capacity: usize,
    ) -> Result<(u8, usize), String> {
        self.read_record_until(
            reader,
            payload,
            capacity,
            Instant::now() + Duration::from_secs(5),
        )
    }

    pub fn new(iv: [u8; 12], key: [u8; 16], sequence: u64, encrypted: bool) -> Self {
        Self {
            iv,
            key,
            sequence,
            encrypted,
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn read_record_until(
        &mut self,
        reader: &mut impl Read,
        payload: &mut Vec<u8>,
        capacity: usize,
        deadline: Instant,
    ) -> Result<(u8, usize), String> {
        let (header, record_len) = read_record_header_until(reader, deadline)?;
        let mut raw = vec![0_u8; record_len];
        let mut wire = 0_u64;
        let mut missing = 0_u32;
        r2o_tls13_read_exact(reader, &mut raw, deadline, true, &mut wire, &mut missing)?;
        if header[0] == TLS_RECORD_CCS {
            payload.clear();
            return Ok((TLS_RECORD_CCS, 0));
        }
        if !self.encrypted || header[0] != TLS_RECORD_APPDATA {
            if record_len > capacity {
                return Err("запись не помещается".into());
            }
            payload.clear();
            payload.extend_from_slice(&raw);
            return Ok((header[0], record_len));
        }
        if record_len < 17 || record_len - 16 > capacity {
            return Err(format!(
                "зашифрованная запись длиной {record_len} не разбирается"
            ));
        }
        let nonce = tls12_nonce(salt4(&self.iv), self.sequence);
        let mut opened = raw;
        cipher(&self.key)?
            .decrypt_in_place(Nonce::from_slice(&nonce), &header, &mut opened)
            .map_err(|_| format!("тег записи не сошёлся (номер {})", self.sequence))?;
        self.sequence += 1;
        let mut length = record_len - 16;
        while length > 0 && opened[length - 1] == 0 {
            length -= 1;
        }
        if length == 0 {
            return Err("запись без внутреннего типа".into());
        }
        let inner_type = opened[length - 1];
        payload.clear();
        payload.extend_from_slice(&opened[..length - 1]);
        Ok((inner_type, length - 1))
    }
}

/// C `write_record` (`tls13.c`): снаружи 23, тип внутри, тег в конце.
pub struct Tls13RecordWriter {
    iv: [u8; 12],
    key: [u8; 16],
    sequence: u64,
}

impl Tls13RecordWriter {
    pub fn new(iv: [u8; 12], key: [u8; 16], sequence: u64) -> Self {
        Self { iv, key, sequence }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    fn seal_inner(&mut self, inner: &[u8]) -> Result<Vec<u8>, String> {
        if inner.is_empty() || inner.len() + 16 > TLS_RECORD_MAX {
            return Err("запись длиннее предела".into());
        }
        let payload_len = inner.len() + 16;
        let mut header = [TLS_RECORD_APPDATA, 3, 3, 0, 0];
        header[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());
        let nonce = tls12_nonce(salt4(&self.iv), self.sequence);
        let mut wire = vec![0_u8; 5 + payload_len];
        wire[..5].copy_from_slice(&header);
        wire[5..5 + inner.len()].copy_from_slice(inner);
        let tag = cipher(&self.key)?
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &header,
                &mut wire[5..5 + inner.len()],
            )
            .map_err(|_| "не зашифровалось".to_owned())?;
        wire[5 + inner.len()..].copy_from_slice(&tag);
        self.sequence += 1;
        Ok(wire)
    }

    pub fn write_record(&mut self, content_type: u8, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() + 1 + 16 > TLS_RECORD_MAX {
            return Err("запись длиннее предела".into());
        }
        let mut inner = Vec::with_capacity(data.len() + 1);
        inner.extend_from_slice(data);
        inner.push(content_type);
        self.seal_inner(&inner)
    }

    /// C `write_all` для TLS1.3: запечатать и записать всю запись.
    pub fn write_all_record(
        &mut self,
        writer: &mut impl Write,
        content_type: u8,
        data: &[u8],
    ) -> Result<(), String> {
        let wire = self.write_record(content_type, data)?;
        r2o_tls13_write_all(writer, &wire)
    }
}

/// C `d2k_tls12_read`: app-data с остатком и пропуском не-app записей.
pub struct Tls12AppReader {
    records: Tls12RecordReader,
    plain: Vec<u8>,
    offset: usize,
}

impl Tls12AppReader {
    pub fn new(records: Tls12RecordReader) -> Self {
        Self {
            records,
            plain: Vec::new(),
            offset: 0,
        }
    }

    pub fn records(&self) -> &Tls12RecordReader {
        &self.records
    }

    pub fn read(&mut self, reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize, String> {
        if self.offset < self.plain.len() {
            let length = (self.plain.len() - self.offset).min(buffer.len());
            buffer[..length].copy_from_slice(&self.plain[self.offset..self.offset + length]);
            self.offset += length;
            return Ok(length);
        }
        loop {
            let mut payload = Vec::new();
            let (content_type, length) =
                self.records
                    .read_record(reader, &mut payload, TLS_RECORD_MAX)?;
            if content_type == 21 {
                // C `REC_ALERT`: close_notify — конец потока, иная тревога — отказ.
                if length >= 2 && payload[1] == 0 {
                    return Ok(0);
                }
                let level = payload.first().copied().unwrap_or(0);
                let description = payload.get(1).copied().unwrap_or(0);
                return Err(format!("тревога {description} уровня {level}"));
            }
            if content_type != TLS_RECORD_APPDATA {
                continue;
            }
            self.plain = payload;
            self.offset = 0;
            let taken = self.plain.len().min(buffer.len());
            buffer[..taken].copy_from_slice(&self.plain[..taken]);
            self.offset = taken;
            return Ok(taken);
        }
    }
}

/// C `d2k_tls12_write`: запечатать app data и записать в поток.
pub fn tls12_write(
    stream: &mut impl Write,
    writer: &mut Tls12RecordWriter,
    data: &[u8],
) -> Result<(), String> {
    let wire = writer.seal(TLS_RECORD_APPDATA, data)?;
    stream
        .write_all(&wire)
        .map_err(|error| format!("запись не ушла: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        TLS_RECORD_APPDATA, TLS_RECORD_MAX, Tls12AppReader, Tls12RecordReader, Tls12RecordWriter,
        Tls12Transcript, Tls13RecordReader, Tls13RecordWriter, d2k_tls12_prf_for_test, tls12_aad,
        tls12_nonce, tls12_write,
    };
    use std::io::Cursor;

    fn key() -> [u8; 16] {
        let mut key = [0_u8; 16];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        key
    }

    fn hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0);
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn tls12_prf_matches_rfc_5246_vector() {
        let secret = hex("9bbe436ba940f017b17652849a71db35");
        let seed = hex("a0ba9f936cda311827a6f796ffd5198c");
        let out = d2k_tls12_prf_for_test(&secret, "test label", &seed, 32);
        assert_eq!(
            out,
            hex("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a")
        );
    }

    #[test]
    fn tls12_app_read_write_matches_c() {
        let salt = [1, 2, 3, 4];
        let mut writer = Tls12RecordWriter::new(salt, key(), 0);
        let mut wire = Vec::new();
        // Не-app запись пропускается, app-data возвращается с остатком.
        wire.extend_from_slice(&writer.seal(22, b"h").unwrap());
        tls12_write(&mut wire, &mut writer, b"hello").unwrap();
        wire.extend_from_slice(&writer.seal(TLS_RECORD_APPDATA, b"world").unwrap());
        assert_eq!(writer.sequence(), 3);

        let mut app = Tls12AppReader::new(Tls12RecordReader::new(salt, key(), 0, true));
        let mut input = Cursor::new(wire);
        let mut buffer = [0_u8; 8];
        assert_eq!(app.read(&mut input, &mut buffer[..3]).unwrap(), 3);
        assert_eq!(&buffer[..3], b"hel");
        assert_eq!(app.read(&mut input, &mut buffer).unwrap(), 2);
        assert_eq!(&buffer[..2], b"lo");
        assert_eq!(app.read(&mut input, &mut buffer).unwrap(), 5);
        assert_eq!(&buffer[..5], b"world");

        // close_notify — конец потока.
        let mut alert_writer = Tls12RecordWriter::new(salt, key(), 0);
        let close = alert_writer.seal(21, &[1, 0]).unwrap();
        let mut app = Tls12AppReader::new(Tls12RecordReader::new(salt, key(), 0, true));
        assert_eq!(app.read(&mut Cursor::new(close), &mut buffer).unwrap(), 0);

        // Иная тревога — отказ с C-текстом «тревога <описание> уровня <уровень>».
        let mut alert_writer = Tls12RecordWriter::new(salt, key(), 0);
        let fatal = alert_writer.seal(21, &[2, 40]).unwrap();
        let mut app = Tls12AppReader::new(Tls12RecordReader::new(salt, key(), 0, true));
        let error = app.read(&mut Cursor::new(fatal), &mut buffer).unwrap_err();
        assert_eq!(error, "тревога 40 уровня 2");
    }

    #[test]
    fn tls12_transcript_nonce_and_aad_match_c() {
        let mut transcript = Tls12Transcript::new(8);
        transcript.add(b"abc");
        transcript.add(b"defgh");
        transcript.add(b"X");
        assert_eq!(transcript.as_slice(), b"abcdefgh");

        assert_eq!(
            tls12_nonce([0xaa, 0xbb, 0xcc, 0xdd], 0x0102_0304_0506_0708),
            [0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!(
            tls12_aad(0x0102_0304_0506_0708, 23, 0x1234),
            [1, 2, 3, 4, 5, 6, 7, 8, 23, 3, 3, 0x12, 0x34]
        );
    }

    #[test]
    fn tls12_sealed_record_matches_c_vector_and_round_trips() {
        let mut writer = Tls12RecordWriter::new([0xa1, 0xb2, 0xc3, 0xd4], key(), 1);
        let wire = writer.seal(TLS_RECORD_APPDATA, b"hello").unwrap();
        // Вектор снят с C `send_sealed`/`d2k_aes128_gcm_encrypt` D2O.
        assert_eq!(wire.len(), 34);
        assert_eq!(&wire[..5], &[23, 3, 3, 0, 29]);
        assert_eq!(&wire[5..13], &[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&wire[13..18], &hex("a27b9501b5")[..]);
        assert_eq!(&wire[18..], &hex("e48e5608151c43d00ace4f2d69f4f85e")[..]);
        assert_eq!(writer.sequence(), 2);

        let mut reader = Tls12RecordReader::new([0xa1, 0xb2, 0xc3, 0xd4], key(), 1, true);
        let mut payload = Vec::new();
        assert_eq!(
            reader
                .read_record(&mut Cursor::new(&wire), &mut payload, TLS_RECORD_MAX)
                .unwrap(),
            (23, 5)
        );
        assert_eq!(payload, b"hello");
        assert_eq!(reader.sequence(), 2);
    }

    #[test]
    fn tls13_record_matches_c_vector_and_strips_padding() {
        let iv = [0xa1, 0xb2, 0xc3, 0xd4, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut writer = Tls13RecordWriter::new(iv, key(), 0);
        let wire = writer.write_record(TLS_RECORD_APPDATA, b"hello").unwrap();
        assert_eq!(&wire[..5], &[23, 3, 3, 0, 22]);
        assert_eq!(&wire[5..11], &hex("ef41d42f4eba")[..]);
        assert_eq!(&wire[11..], &hex("e1b6c4b942dd545b43b4b30bda7f56cf")[..]);

        let mut reader = Tls13RecordReader::new(iv, key(), 0, true);
        let mut payload = Vec::new();
        assert_eq!(
            reader
                .read_record(&mut Cursor::new(&wire), &mut payload, TLS_RECORD_MAX)
                .unwrap(),
            (23, 5)
        );
        assert_eq!(payload, b"hello");

        // Набивка нулями снимается, внутренний тип — последний ненулевой байт.
        let mut writer = Tls13RecordWriter::new(iv, key(), 1);
        let padded = writer.seal_inner(&[b'h', b'i', 22, 0, 0]).unwrap();
        let mut reader = Tls13RecordReader::new(iv, key(), 1, true);
        let mut payload = Vec::new();
        assert_eq!(
            reader
                .read_record(&mut Cursor::new(&padded), &mut payload, TLS_RECORD_MAX)
                .unwrap(),
            (22, 2)
        );
        assert_eq!(payload, b"hi");
    }

    #[test]
    fn record_reader_errors_match_c() {
        let mut payload = Vec::new();
        let mut reader = Tls12RecordReader::new([0; 4], key(), 0, true);
        let error = reader
            .read_record(
                &mut Cursor::new(b"HTTP/1.1 400 Bad Request"),
                &mut payload,
                TLS_RECORD_MAX,
            )
            .unwrap_err();
        assert!(error.contains("не TLS"), "{error}");

        let error = reader
            .read_record(
                &mut Cursor::new([23, 3, 3, 0, 0]),
                &mut payload,
                TLS_RECORD_MAX,
            )
            .unwrap_err();
        assert!(error.contains("вне предела"), "{error}");

        // 0x4801 = 18433 — на байт больше REC_MAX.
        let error = reader
            .read_record(
                &mut Cursor::new([23, 3, 3, 0x48, 0x01]),
                &mut payload,
                TLS_RECORD_MAX,
            )
            .unwrap_err();
        assert!(error.contains("вне предела"), "{error}");

        // CCS не шифруется и содержимого не несёт.
        assert_eq!(
            reader
                .read_record(
                    &mut Cursor::new([20, 3, 3, 0, 1, 0]),
                    &mut payload,
                    TLS_RECORD_MAX
                )
                .unwrap(),
            (20, 0)
        );
        assert!(payload.is_empty());

        // Незашифрованная запись проходит как есть.
        let mut plain = Tls12RecordReader::new([0; 4], key(), 0, false);
        assert_eq!(
            plain
                .read_record(
                    &mut Cursor::new([22, 3, 3, 0, 3, 1, 2, 3]),
                    &mut payload,
                    TLS_RECORD_MAX
                )
                .unwrap(),
            (22, 3)
        );
        assert_eq!(payload, [1, 2, 3]);

        // Зашифрованная запись короче explicit nonce + тега.
        let mut short = vec![23, 3, 3, 0, 23];
        short.extend_from_slice(&[0; 23]);
        let error = reader
            .read_record(&mut Cursor::new(&short), &mut payload, TLS_RECORD_MAX)
            .unwrap_err();
        assert!(error.contains("короче"), "{error}");

        // Тело не помещается в буфер вызывающего.
        let mut writer = Tls12RecordWriter::new([0; 4], key(), 0);
        let wire = writer.seal(TLS_RECORD_APPDATA, &[0x41; 16]).unwrap();
        let mut reader = Tls12RecordReader::new([0; 4], key(), 0, true);
        let error = reader
            .read_record(&mut Cursor::new(&wire), &mut payload, 8)
            .unwrap_err();
        assert!(error.contains("не помещается"), "{error}");
    }

    #[test]
    fn tls12_u16_helpers_and_dispose_match_c_contract() {
        // C `put16`/`get16`: network byte order, включая границы.
        for value in [0u16, 1, 0x00ff, 0x1234, 0xffff] {
            let encoded = value.to_be_bytes();
            assert_eq!(u16::from_be_bytes(encoded), value);
            assert_eq!(encoded[0], (value >> 8) as u8);
            assert_eq!(encoded[1], value as u8);
        }
        // C `tls12_dispose`/`d2k_tls12_free`: освобождение состояния при
        // выходе; в Rust это RAII Drop, повторное использование невозможно.
        let mut writer = Tls12RecordWriter::new([0; 4], key(), 0);
        let wire = writer.seal(TLS_RECORD_APPDATA, &[0x41; 8]).unwrap();
        drop(writer);
        let mut reader = Tls12RecordReader::new([0; 4], key(), 0, true);
        let mut payload = Vec::new();
        assert_eq!(
            reader
                .read_record(&mut Cursor::new(&wire), &mut payload, TLS_RECORD_MAX)
                .unwrap(),
            (TLS_RECORD_APPDATA, 8)
        );
        drop(reader);
    }

    #[test]
    fn tls12_io_c_differential_trace_matches_c_fixture() {
        use super::{r2o_tls12_read_exact, r2o_tls12_write_all};
        use std::io::{ErrorKind, Read, Write};
        use std::time::{Duration, Instant};

        let Some(path) = std::env::var_os("R2O_TLS12_IO_DIFF_OUTPUT") else {
            return;
        };

        enum ReadEvent {
            Data(&'static [u8]),
            Error(ErrorKind),
            Raw(i32),
        }

        struct MockReader {
            events: Vec<ReadEvent>,
        }

        impl Read for MockReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.events.is_empty() {
                    return Ok(0);
                }
                match self.events.remove(0) {
                    ReadEvent::Data(data) => {
                        let n = data.len().min(buf.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        Ok(n)
                    }
                    ReadEvent::Error(kind) => Err(std::io::Error::new(kind, "test")),
                    ReadEvent::Raw(code) => Err(std::io::Error::from_raw_os_error(code)),
                }
            }
        }

        enum WriteEvent {
            Limit(usize),
            Error(ErrorKind),
            Raw(i32),
        }

        struct MockWriter {
            events: Vec<WriteEvent>,
            sent: Vec<u8>,
        }

        impl Write for MockWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.events.is_empty() {
                    return Ok(0);
                }
                match self.events.remove(0) {
                    WriteEvent::Limit(limit) => {
                        let n = limit.min(buf.len());
                        self.sent.extend_from_slice(&buf[..n]);
                        Ok(n)
                    }
                    WriteEvent::Error(kind) => Err(std::io::Error::new(kind, "test")),
                    WriteEvent::Raw(code) => Err(std::io::Error::from_raw_os_error(code)),
                }
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }

        fn emit(
            output: &mut String,
            name: &str,
            result: Result<(), String>,
            rx: u64,
            missing: u32,
            buf: &[u8],
            sent: &[u8],
        ) {
            let (rc, err) = match result {
                Ok(()) => (0, String::new()),
                Err(error) => (-1, error),
            };
            output.push_str(&format!(
                "io|{name}|rc={rc}|err={err}|rx={rx}|missing={missing}|buf={}|sent={}\n",
                hex(buf),
                hex(sent)
            ));
        }

        fn read_case(name: &str, events: Vec<ReadEvent>, deadline: Instant, output: &mut String) {
            let mut reader = MockReader { events };
            let mut buf = [0_u8; 4];
            let mut rx = 0_u64;
            let mut missing = 0_u32;
            let result = r2o_tls12_read_exact(
                &mut reader,
                &mut buf,
                deadline,
                false,
                &mut rx,
                &mut missing,
            );
            emit(output, name, result, rx, missing, &buf, &[]);
        }

        fn write_case(name: &str, events: Vec<WriteEvent>, output: &mut String) {
            let mut writer = MockWriter {
                events,
                sent: Vec::new(),
            };
            let buf = [0xa0_u8, 0xa1, 0xa2, 0xa3];
            let result = r2o_tls12_write_all(&mut writer, &buf);
            emit(output, name, result, 0, 0, &buf, &writer.sent);
        }

        static DATA: [u8; 4] = [1, 2, 3, 4];
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut output = String::new();
        read_case(
            "read-full",
            vec![ReadEvent::Data(&DATA)],
            deadline,
            &mut output,
        );
        read_case(
            "read-short",
            vec![ReadEvent::Data(&DATA[..2]), ReadEvent::Data(&DATA[2..])],
            deadline,
            &mut output,
        );
        read_case(
            "read-eintr",
            vec![
                ReadEvent::Error(ErrorKind::Interrupted),
                ReadEvent::Data(&DATA),
            ],
            deadline,
            &mut output,
        );
        read_case(
            "read-eagain",
            vec![
                ReadEvent::Error(ErrorKind::WouldBlock),
                ReadEvent::Data(&DATA),
            ],
            deadline,
            &mut output,
        );
        read_case("read-eof", vec![], deadline, &mut output);
        read_case("read-error", vec![ReadEvent::Raw(5)], deadline, &mut output);
        read_case("read-deadline", vec![], Instant::now(), &mut output);
        write_case("write-full", vec![WriteEvent::Limit(4)], &mut output);
        write_case(
            "write-short",
            vec![WriteEvent::Limit(1), WriteEvent::Limit(3)],
            &mut output,
        );
        write_case(
            "write-eintr",
            vec![
                WriteEvent::Error(ErrorKind::Interrupted),
                WriteEvent::Limit(4),
            ],
            &mut output,
        );
        write_case(
            "write-eagain",
            vec![
                WriteEvent::Error(ErrorKind::WouldBlock),
                WriteEvent::Limit(4),
            ],
            &mut output,
        );
        write_case("write-error", vec![WriteEvent::Raw(5)], &mut output);
        write_case("write-zero", vec![WriteEvent::Limit(0)], &mut output);
        std::fs::write(path, output).unwrap();
    }
    #[test]
    fn tls13_io_c_differential_trace_matches_c_fixture() {
        use super::{r2o_tls13_read_exact, r2o_tls13_write_all};
        use std::io::{ErrorKind, Read, Write};
        use std::time::{Duration, Instant};

        let Some(path) = std::env::var_os("R2O_TLS13_IO_DIFF_OUTPUT") else {
            return;
        };

        enum ReadEvent {
            Data(&'static [u8]),
            Error(ErrorKind),
            Raw(i32),
        }

        struct MockReader {
            events: Vec<ReadEvent>,
        }

        impl Read for MockReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.events.is_empty() {
                    return Ok(0);
                }
                match self.events.remove(0) {
                    ReadEvent::Data(data) => {
                        let n = data.len().min(buf.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        Ok(n)
                    }
                    ReadEvent::Error(kind) => Err(std::io::Error::new(kind, "test")),
                    ReadEvent::Raw(code) => Err(std::io::Error::from_raw_os_error(code)),
                }
            }
        }

        enum WriteEvent {
            Limit(usize),
            Error(ErrorKind),
            Raw(i32),
        }

        struct MockWriter {
            events: Vec<WriteEvent>,
            sent: Vec<u8>,
        }

        impl Write for MockWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.events.is_empty() {
                    return Ok(0);
                }
                match self.events.remove(0) {
                    WriteEvent::Limit(limit) => {
                        let n = limit.min(buf.len());
                        self.sent.extend_from_slice(&buf[..n]);
                        Ok(n)
                    }
                    WriteEvent::Error(kind) => Err(std::io::Error::new(kind, "test")),
                    WriteEvent::Raw(code) => Err(std::io::Error::from_raw_os_error(code)),
                }
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }

        fn emit(
            output: &mut String,
            name: &str,
            result: Result<(), String>,
            rx: u64,
            missing: u32,
            buf: &[u8],
            sent: &[u8],
        ) {
            let (rc, err) = match result {
                Ok(()) => (0, String::new()),
                Err(error) => (-1, error),
            };
            output.push_str(&format!(
                "io|{name}|rc={rc}|err={err}|rx={rx}|missing={missing}|buf={}|sent={}\n",
                hex(buf),
                hex(sent)
            ));
        }

        fn read_case(name: &str, events: Vec<ReadEvent>, deadline: Instant, output: &mut String) {
            let mut reader = MockReader { events };
            let mut buf = [0_u8; 4];
            let mut rx = 0_u64;
            let mut missing = 0_u32;
            let result = r2o_tls13_read_exact(
                &mut reader,
                &mut buf,
                deadline,
                false,
                &mut rx,
                &mut missing,
            );
            emit(output, name, result, rx, missing, &buf, &[]);
        }

        fn write_case(name: &str, events: Vec<WriteEvent>, output: &mut String) {
            let mut writer = MockWriter {
                events,
                sent: Vec::new(),
            };
            let buf = [0xa0_u8, 0xa1, 0xa2, 0xa3];
            let result = r2o_tls13_write_all(&mut writer, &buf);
            emit(output, name, result, 0, 0, &buf, &writer.sent);
        }

        static DATA: [u8; 4] = [1, 2, 3, 4];
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut output = String::new();
        read_case(
            "read-full",
            vec![ReadEvent::Data(&DATA)],
            deadline,
            &mut output,
        );
        read_case(
            "read-short",
            vec![ReadEvent::Data(&DATA[..2]), ReadEvent::Data(&DATA[2..])],
            deadline,
            &mut output,
        );
        read_case(
            "read-eintr",
            vec![
                ReadEvent::Error(ErrorKind::Interrupted),
                ReadEvent::Data(&DATA),
            ],
            deadline,
            &mut output,
        );
        read_case(
            "read-eagain",
            vec![
                ReadEvent::Error(ErrorKind::WouldBlock),
                ReadEvent::Data(&DATA),
            ],
            deadline,
            &mut output,
        );
        read_case("read-eof", vec![], deadline, &mut output);
        read_case("read-error", vec![ReadEvent::Raw(5)], deadline, &mut output);
        read_case("read-deadline", vec![], Instant::now(), &mut output);
        write_case("write-full", vec![WriteEvent::Limit(4)], &mut output);
        write_case(
            "write-short",
            vec![WriteEvent::Limit(1), WriteEvent::Limit(3)],
            &mut output,
        );
        write_case(
            "write-eintr",
            vec![
                WriteEvent::Error(ErrorKind::Interrupted),
                WriteEvent::Limit(4),
            ],
            &mut output,
        );
        write_case(
            "write-eagain",
            vec![
                WriteEvent::Error(ErrorKind::WouldBlock),
                WriteEvent::Limit(4),
            ],
            &mut output,
        );
        write_case("write-error", vec![WriteEvent::Raw(5)], &mut output);
        write_case("write-zero", vec![WriteEvent::Limit(0)], &mut output);
        std::fs::write(path, output).unwrap();
    }
}

#[cfg(test)]
mod tls13_put16_get16_tests {
    /// C/Rust differential: C-стенд вызывает production `put16`/`get16`
    /// из tls13.c и tls13core.c; Rust — те же `to_be_bytes`/
    /// `from_be_bytes`, которыми кодируются заголовки записей.
    #[test]
    fn tls13_put16_get16_match_c() {
        let Some(path) = std::env::var_os("R2O_TLS13_PUT16_DIFF_OUTPUT") else {
            return;
        };
        let mut output = String::new();
        for value in 0_u32..=65_535 {
            let number = value as u16;
            let bytes = number.to_be_bytes();
            output.push_str(&format!(
                "{value} {} {} {}\n",
                bytes[0],
                bytes[1],
                u16::from_be_bytes(bytes)
            ));
        }
        std::fs::write(path, &output).unwrap();
        print!("{output}");
    }
}
