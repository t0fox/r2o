//! C `tls12.c`: тестовый экспорт TLS 1.2 PRF.
//!
//! В production PRF выполняет rustls; здесь — точная P_SHA256-реализация
//! для C/Rust-векторов `test_tls12.c`.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use sha2::{Digest, Sha256};
use std::io::Read;

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

fn read_record_header(reader: &mut impl Read) -> Result<([u8; 5], usize), String> {
    let mut header = [0_u8; 5];
    reader
        .read_exact(&mut header)
        .map_err(|error| format!("не прочитан TLS-заголовок: {error}"))?;
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

    pub fn read_record(
        &mut self,
        reader: &mut impl Read,
        payload: &mut Vec<u8>,
        capacity: usize,
    ) -> Result<(u8, usize), String> {
        let (header, record_len) = read_record_header(reader)?;
        let mut raw = vec![0_u8; record_len];
        reader
            .read_exact(&mut raw)
            .map_err(|error| format!("не прочитана TLS-запись: {error}"))?;
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

    pub fn read_record(
        &mut self,
        reader: &mut impl Read,
        payload: &mut Vec<u8>,
        capacity: usize,
    ) -> Result<(u8, usize), String> {
        let (header, record_len) = read_record_header(reader)?;
        let mut raw = vec![0_u8; record_len];
        reader
            .read_exact(&mut raw)
            .map_err(|error| format!("не прочитана TLS-запись: {error}"))?;
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
}

#[cfg(test)]
mod tests {
    use super::{
        TLS_RECORD_APPDATA, TLS_RECORD_MAX, Tls12RecordReader, Tls12RecordWriter, Tls12Transcript,
        Tls13RecordReader, Tls13RecordWriter, d2k_tls12_prf_for_test, tls12_aad, tls12_nonce,
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
}
