//! Ограниченная проверка и преобразование начальных пакетов QUIC.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;
const MAX_CID: usize = 20;
pub(crate) const MAX_PACKET: usize = 1500;
const MAX_DATAGRAM: usize = 65_535;
const MAX_CRYPTO_FRAMES: usize = 64;
const MAX_INITIAL_DATAGRAMS: usize = 4;
const MAX_CLIENT_HELLO: usize = 8192;
const R2K_QUIC_RTT_WAIT_FLOOR_MS: u32 = 1_500;
const R2K_QUIC_RTT_WAIT_CEIL_MS: u32 = 6_000;
const R2K_QUIC_DATA_BYTES: u64 = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2kQuicDataVerdict {
    NotRun,
    Pass,
    NoHandshake,
    Cut,
}

/// Применить порядок вердиктов HTTP/3-этапа измерения из исходного кода.
pub fn r2k_quic_data_judge(
    handshake: bool,
    status: u16,
    app_bytes: u64,
    complete: bool,
    stalled: bool,
    need_complete: bool,
    headers_too_long: bool,
    budget_ok: bool,
) -> R2kQuicDataVerdict {
    if !handshake {
        return R2kQuicDataVerdict::NoHandshake;
    }
    if status == 451 {
        return R2kQuicDataVerdict::Cut;
    }
    if status > 0 && complete {
        return R2kQuicDataVerdict::Pass;
    }
    if status > 0 && budget_ok && !stalled {
        return R2kQuicDataVerdict::Pass;
    }
    if stalled {
        return R2kQuicDataVerdict::Cut;
    }
    if status == 0 && headers_too_long {
        return R2kQuicDataVerdict::NotRun;
    }
    if !need_complete && status > 0 && app_bytes >= R2K_QUIC_DATA_BYTES {
        return R2kQuicDataVerdict::Pass;
    }
    R2kQuicDataVerdict::NotRun
}

/// Вычислить время ожидания одного вопроса QUIC по правилу донора `3 × RTT`.
pub fn r2k_quic_dynamic_wait_ms(rtt_ms: u32) -> u32 {
    let wait_ms = if rtt_ms >= R2K_QUIC_RTT_WAIT_CEIL_MS / 3 {
        R2K_QUIC_RTT_WAIT_CEIL_MS
    } else {
        rtt_ms * 3
    };
    if wait_ms < R2K_QUIC_RTT_WAIT_FLOOR_MS {
        R2K_QUIC_RTT_WAIT_FLOOR_MS
    } else {
        wait_ms
    }
}

const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
const RETRY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];
const RETRY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicSplitError {
    Invalid,
    NoNameInDatagram,
}

/// Проверить подлинность поддерживаемого клиентского Initial без требования SNI в ClientHello.
pub fn is_authenticated_initial(input: &[u8]) -> bool {
    if input.len() > MAX_DATAGRAM {
        return false;
    }
    let Some(header) = parse_initial_header(input) else {
        return false;
    };
    if header.packet_len > MAX_PACKET {
        return false;
    }
    let Some(keys) = derive_initial_keys(
        header.version,
        &input[header.dcid_offset..header.dcid_offset + header.dcid_len],
    )
    .ok() else {
        return false;
    };
    open_initial(input, header, keys).is_ok()
}

#[derive(Clone, Copy, Debug)]
struct InitialHeader {
    version: u32,
    dcid_offset: usize,
    dcid_len: usize,
    pn_offset: usize,
    length_claimed: usize,
    length_width: usize,
    packet_len: usize,
}

#[derive(Clone, Copy, Debug)]
struct CryptoFrame {
    offset: u64,
    data_offset: usize,
    len: usize,
}

struct OpenedInitial {
    header: InitialHeader,
    keys: InitialKeys,
    plain: Vec<u8>,
    packet_number: u64,
    pn_len: usize,
    frames: Vec<CryptoFrame>,
    stream: Vec<u8>,
    pings: usize,
}

#[derive(Clone, Copy)]
struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

/// Разрезать SNI в потоке CRYPTO клиентского Initial и заново зашифровать пакет.
///
/// Длина пакета и номер пакета остаются прежними. Разрешены только кадры
/// PADDING, PING и CRYPTO — так работает измеренная операция datapath.
pub fn initial_split_crypto(input: &[u8]) -> Result<Vec<u8>, QuicSplitError> {
    let OpenedInitial {
        header,
        keys,
        plain,
        packet_number,
        pn_len,
        frames,
        stream,
        pings,
    } = open_initial_crypto(input)?;
    let Some((sni_offset, sni_len)) = find_client_hello_sni(&stream) else {
        return Err(QuicSplitError::NoNameInDatagram);
    };
    if sni_len < 2 {
        return Err(QuicSplitError::NoNameInDatagram);
    }
    let middle = sni_offset
        .checked_add(sni_len / 2)
        .ok_or(QuicSplitError::Invalid)? as u64;
    let target = frames.iter().position(|frame| {
        frame.offset < middle
            && frame
                .offset
                .checked_add(frame.len as u64)
                .is_some_and(|end| middle < end)
    });
    let Some(target) = target else {
        return Err(QuicSplitError::NoNameInDatagram);
    };

    let target_frame = frames[target];
    let cut = usize::try_from(middle - target_frame.offset).map_err(|_| QuicSplitError::Invalid)?;
    let mut body = Vec::with_capacity(plain.len());
    append_crypto_frame(
        &mut body,
        target_frame.offset + cut as u64,
        &plain[target_frame.data_offset + cut..target_frame.data_offset + target_frame.len],
        plain.len(),
    )?;
    append_crypto_frame(
        &mut body,
        target_frame.offset,
        &plain[target_frame.data_offset..target_frame.data_offset + cut],
        plain.len(),
    )?;
    for (index, frame) in frames.iter().copied().enumerate() {
        if index != target {
            append_crypto_frame(
                &mut body,
                frame.offset,
                &plain[frame.data_offset..frame.data_offset + frame.len],
                plain.len(),
            )?;
        }
    }
    if pings > plain.len().saturating_sub(body.len()) {
        return Err(QuicSplitError::Invalid);
    }
    body.resize(body.len() + pings, 0x01);
    body.resize(plain.len(), 0x00);

    let mut clear_header = input[..header.pn_offset].to_vec();
    clear_header[0] = input[0] & 0xf0;
    let sealed = seal_initial(&clear_header, &body, packet_number, pn_len, keys)?;
    if sealed.len() != header.packet_len
        || parse_initial_header(&sealed).is_none_or(|sealed_header| {
            sealed_header.length_claimed != header.length_claimed
                || sealed_header.length_width != header.length_width
        })
    {
        return Err(QuicSplitError::Invalid);
    }
    let mut output = Vec::with_capacity(input.len());
    output.extend_from_slice(&sealed);
    output.extend_from_slice(&input[header.packet_len..]);
    Ok(output)
}

/// Прочитать полное SNI из поддерживаемого проверенного клиентского Initial QUIC.
///
/// Успех возможен, только если одна дейтаграмма целиком содержит непрерывное SNI из ClientHello.
pub fn initial_client_hello_sni(input: &[u8]) -> Option<Vec<u8>> {
    let opened = open_initial_crypto(input).ok()?;
    let (offset, length) = find_client_hello_sni(&opened.stream)?;
    Some(
        opened
            .stream
            .get(offset..offset.checked_add(length)?)?
            .to_vec(),
    )
}

/// Собрать свежий QUIC v1 Initial с одним полным TLS ClientHello.
pub fn r2k_quic_initial_build(
    client_hello: &[u8],
    source_connection_id: &[u8],
    target_len: usize,
) -> Option<Vec<u8>> {
    if !(8..=MAX_CID).contains(&source_connection_id.len())
        || !(1200..=MAX_PACKET).contains(&target_len)
        || client_hello.len() < 4
        || client_hello.len() > MAX_CLIENT_HELLO
        || client_hello[0] != 1
        || usize::try_from(read_u24(client_hello, 1)?)
            .ok()?
            .checked_add(4)?
            != client_hello.len()
    {
        return None;
    }
    find_client_hello_sni_result(client_hello).ok()?;

    let mut dcid = [0; 8];
    let mut unique = false;
    for _ in 0..4 {
        getrandom::getrandom(&mut dcid).ok()?;
        if dcid.as_slice() != source_connection_id {
            unique = true;
            break;
        }
    }
    if !unique {
        return None;
    }

    let mut clear_header = Vec::with_capacity(64);
    clear_header.push(0xc0);
    clear_header.extend_from_slice(&QUIC_V1.to_be_bytes());
    clear_header.push(dcid.len() as u8);
    clear_header.extend_from_slice(&dcid);
    clear_header.push(source_connection_id.len() as u8);
    clear_header.extend_from_slice(source_connection_id);
    write_varint(0, &mut clear_header).ok()?;

    let mut plain = Vec::with_capacity(target_len);
    plain.push(0x06);
    write_varint(0, &mut plain).ok()?;
    write_varint(client_hello.len() as u64, &mut plain).ok()?;
    plain.extend_from_slice(client_hello);

    let (length_width, body_len) = [1usize, 2, 4, 8].into_iter().find_map(|width| {
        let length = target_len.checked_sub(clear_header.len().checked_add(width)?)?;
        let varint_width = match length {
            0..=63 => 1,
            64..=16_383 => 2,
            16_384..=1_073_741_823 => 4,
            _ => 8,
        };
        if varint_width != width || length < 20 {
            return None;
        }
        let body_len = usize::try_from(length).ok()?.checked_sub(20)?;
        (body_len >= plain.len()).then_some((width, body_len))
    })?;
    plain.resize(body_len, 0);
    let length = u64::try_from(body_len.checked_add(20)?).ok()?;
    let header_len = clear_header.len();
    write_varint(length, &mut clear_header).ok()?;
    if clear_header.len() - header_len != length_width
        || clear_header.len() + body_len + 20 != target_len
    {
        return None;
    }

    let keys = derive_initial_keys(QUIC_V1, &dcid).ok()?;
    let packet = seal_initial(&clear_header, &plain, 0, 4, keys).ok()?;
    (packet.len() == target_len && is_authenticated_initial(&packet)).then_some(packet)
}

/// Повторно зашифровать клиентский Initial с новым DCID, сохранив его форму.
pub(crate) fn r2k_quic_initial_reseal_for_dcid(input: &[u8], new_dcid: &[u8]) -> Option<Vec<u8>> {
    let header = parse_initial_header(input)?;
    if header.packet_len != input.len() || new_dcid.len() != header.dcid_len {
        return None;
    }
    let old_dcid_end = header.dcid_offset.checked_add(header.dcid_len)?;
    let old_dcid = input.get(header.dcid_offset..old_dcid_end)?;
    let old_keys = derive_initial_keys(header.version, old_dcid).ok()?;
    let (plain, packet_number, packet_number_len) = open_initial(input, header, old_keys).ok()?;
    let new_keys = derive_initial_keys(header.version, new_dcid).ok()?;
    let mut clear_header = input.get(..header.pn_offset)?.to_vec();
    clear_header[0] = input[0] & 0xf0;
    clear_header
        .get_mut(header.dcid_offset..old_dcid_end)?
        .copy_from_slice(new_dcid);

    let sealed = seal_initial(
        &clear_header,
        &plain,
        packet_number,
        packet_number_len,
        new_keys,
    )
    .ok()?;
    if sealed.len() != input.len()
        || parse_initial_header(&sealed).is_none_or(|resealed| {
            resealed.length_claimed != header.length_claimed
                || resealed.length_width != header.length_width
        })
    {
        return None;
    }
    Some(sealed)
}

/// Собрать ClientHello из Initial-датаграмм одного QUIC-полёта.
pub fn r2k_quic_initial_client_hello_from_datagrams(datagrams: &[&[u8]]) -> Option<Vec<u8>> {
    if datagrams.is_empty() || datagrams.len() > MAX_INITIAL_DATAGRAMS {
        return None;
    }
    let first = parse_initial_header(datagrams[0])?;
    let dcid = datagrams[0].get(first.dcid_offset..first.dcid_offset + first.dcid_len)?;
    let keys = derive_initial_keys(first.version, dcid).ok()?;
    let mut stream = [0; MAX_CLIENT_HELLO];
    let mut seen = [false; MAX_CLIENT_HELLO];

    for datagram in datagrams {
        if datagram.len() > MAX_PACKET {
            return None;
        }
        let header = parse_initial_header(datagram)?;
        if header.version != first.version
            || header.dcid_len != first.dcid_len
            || datagram.get(header.dcid_offset..header.dcid_offset + header.dcid_len)? != dcid
        {
            return None;
        }
        let (plain, _, _) = open_initial(datagram, header, keys).ok()?;
        collect_initial_crypto_frames(&plain, &mut stream, &mut seen);
    }

    let filled = seen.iter().take_while(|present| **present).count();
    if filled < 4 || stream[0] != 0x01 {
        return None;
    }
    let claimed =
        (usize::from(stream[1]) << 16) | (usize::from(stream[2]) << 8) | usize::from(stream[3]);
    let whole = 4usize.checked_add(claimed)?;
    (whole <= filled).then(|| stream[..whole].to_vec())
}

/// Вернуть версию и DCID аутентифицированного QUIC Initial.
pub fn r2k_quic_initial_flight_id(input: &[u8]) -> Option<(u32, Vec<u8>)> {
    if input.len() > MAX_PACKET || !is_authenticated_initial(input) {
        return None;
    }
    let header = parse_initial_header(input)?;
    let dcid = input.get(header.dcid_offset..header.dcid_offset + header.dcid_len)?;
    Some((header.version, dcid.to_vec()))
}

/// Verify a server response with the donor's `Answer` criterion.
/// VN and same-version Retry count as answers; a same-version Initial must
/// authenticate with the server keys derived from the client's DCID.
pub fn r2k_quic_initial_verify_donor_response(client: &[u8], response: &[u8]) -> bool {
    if response.len() > MAX_DATAGRAM || !is_authenticated_initial(client) {
        return false;
    }
    let Some(client_header) = parse_initial_header(client) else {
        return false;
    };
    let Some(client_long) = parse_long_header_ids(client) else {
        return false;
    };
    let Some(original_dcid) =
        client.get(client_long.dcid_offset..client_long.dcid_offset + client_long.dcid_len)
    else {
        return false;
    };
    r2k_quic_donor_response_matches(client_header.version, original_dcid, response)
}

/// Verify a donor `Answer` using a known QUIC version and destination CID.
pub fn r2k_quic_donor_response_matches(version: u32, dcid: &[u8], response: &[u8]) -> bool {
    if response.len() > MAX_DATAGRAM || dcid.len() > MAX_CID {
        return false;
    }
    let Some(response_long) = parse_long_header_ids(response) else {
        return false;
    };
    if response_long.version == 0 {
        return true;
    }
    if response_long.version != version {
        return false;
    }
    let (initial_type, retry_type) = match version {
        QUIC_V1 => (0, 3),
        QUIC_V2 => (1, 0),
        _ => return false,
    };
    if response_long.packet_type == retry_type {
        return true;
    }
    if response_long.packet_type != initial_type {
        return false;
    }
    let Some(header) = parse_initial_header(response) else {
        return false;
    };
    let Ok(keys) = derive_initial_keys_for_role(version, dcid, b"server in") else {
        return false;
    };
    open_initial(response, header, keys).is_ok()
}

/// Проверить Initial или Retry сервера, адресованный SCID исходного Initial.
pub(crate) fn r2k_quic_initial_verify_bound_response(client: &[u8], response: &[u8]) -> bool {
    if response.len() > MAX_DATAGRAM || !is_authenticated_initial(client) {
        return false;
    }
    let Some(client_header) = parse_initial_header(client) else {
        return false;
    };
    let Some(client_long) = parse_long_header_ids(client) else {
        return false;
    };
    let Some(response_long) = parse_long_header_ids(response) else {
        return false;
    };
    let original_dcid =
        &client[client_long.dcid_offset..client_long.dcid_offset + client_long.dcid_len];
    let client_scid =
        &client[client_long.scid_offset..client_long.scid_offset + client_long.scid_len];
    let response_dcid =
        &response[response_long.dcid_offset..response_long.dcid_offset + response_long.dcid_len];
    if response_long.version != client_header.version || response_dcid != client_scid {
        return false;
    }

    let (initial_type, retry_type) = match client_header.version {
        QUIC_V1 => (0, 3),
        QUIC_V2 => (1, 0),
        _ => return false,
    };
    if response_long.packet_type == initial_type {
        let Some(header) = parse_initial_header(response) else {
            return false;
        };
        let Ok(keys) =
            derive_initial_keys_for_role(client_header.version, original_dcid, b"server in")
        else {
            return false;
        };
        return open_initial(response, header, keys).is_ok();
    }
    if response_long.packet_type != retry_type {
        return false;
    }

    let retry_scid =
        &response[response_long.scid_offset..response_long.scid_offset + response_long.scid_len];
    let token_offset = response_long.scid_offset + response_long.scid_len;
    if retry_scid.is_empty()
        || retry_scid == original_dcid
        || token_offset
            .checked_add(16)
            .is_none_or(|end| end >= response.len())
    {
        return false;
    }
    retry_integrity_valid(client_header.version, original_dcid, response)
}

#[derive(Clone, Copy)]
struct LongHeaderIds {
    version: u32,
    packet_type: u8,
    dcid_offset: usize,
    dcid_len: usize,
    scid_offset: usize,
    scid_len: usize,
}

fn parse_long_header_ids(input: &[u8]) -> Option<LongHeaderIds> {
    if input.len() < 7 || input[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(input.get(1..5)?.try_into().ok()?);
    let dcid_len = usize::from(*input.get(5)?);
    if dcid_len > MAX_CID {
        return None;
    }
    let dcid_offset = 6usize;
    let scid_len_offset = dcid_offset.checked_add(dcid_len)?;
    let scid_len = usize::from(*input.get(scid_len_offset)?);
    if scid_len > MAX_CID {
        return None;
    }
    let scid_offset = scid_len_offset.checked_add(1)?;
    input.get(scid_offset..scid_offset.checked_add(scid_len)?)?;
    Some(LongHeaderIds {
        version,
        packet_type: (input[0] & 0x30) >> 4,
        dcid_offset,
        dcid_len,
        scid_offset,
        scid_len,
    })
}

fn retry_integrity_valid(version: u32, original_dcid: &[u8], retry: &[u8]) -> bool {
    use aes_gcm::aead::{Aead, Payload};

    if retry.len() < 17
        || original_dcid.len() > MAX_CID
        || retry
            .len()
            .checked_add(1 + original_dcid.len())
            .is_none_or(|length| length > MAX_DATAGRAM)
    {
        return false;
    }
    let body_end = retry.len() - 16;
    let mut pseudo = Vec::with_capacity(1 + original_dcid.len() + body_end);
    pseudo.push(original_dcid.len() as u8);
    pseudo.extend_from_slice(original_dcid);
    pseudo.extend_from_slice(&retry[..body_end]);
    let (key, nonce) = match version {
        QUIC_V1 => (&RETRY_KEY_V1, &RETRY_NONCE_V1),
        QUIC_V2 => (&RETRY_KEY_V2, &RETRY_NONCE_V2),
        _ => return false,
    };
    let Ok(cipher) = Aes128Gcm::new_from_slice(key) else {
        return false;
    };
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &retry[body_end..],
                aad: &pseudo,
            },
        )
        .is_ok_and(|plain| plain.is_empty())
}

/// Извлечь состояние SNI из полного ClientHello, собранного из QUIC Initial-датаграмм.
pub fn r2k_quic_initial_sni_result_from_datagrams(
    datagrams: &[&[u8]],
) -> Result<Option<Vec<u8>>, &'static str> {
    let client_hello = r2k_quic_initial_client_hello_from_datagrams(datagrams)
        .ok_or("полный ClientHello QUIC Initial не найден")?;
    let Some((offset, length)) = find_client_hello_sni_result(&client_hello)? else {
        return Ok(None);
    };
    let end = offset
        .checked_add(length)
        .ok_or("неверная длина имени SNI в ClientHello")?;
    Ok(Some(
        client_hello
            .get(offset..end)
            .ok_or("имя SNI выходит за границы ClientHello")?
            .to_vec(),
    ))
}

/// Извлечь SNI из полного ClientHello; отсутствие и ошибка дают `None`.
pub fn r2k_quic_initial_sni_from_datagrams(datagrams: &[&[u8]]) -> Option<Vec<u8>> {
    r2k_quic_initial_sni_result_from_datagrams(datagrams)
        .ok()
        .flatten()
}

fn collect_initial_crypto_frames(plain: &[u8], stream: &mut [u8], seen: &mut [bool]) {
    let mut cursor = 0;
    while cursor < plain.len() {
        match plain[cursor] {
            0x00 => {
                while cursor < plain.len() && plain[cursor] == 0 {
                    cursor += 1;
                }
            }
            0x01 => cursor += 1,
            0x02 | 0x03 => {
                let ecn = plain[cursor] == 0x03;
                cursor += 1;
                if skip_initial_ack(plain, &mut cursor, ecn).is_none() {
                    break;
                }
            }
            0x06 => {
                cursor += 1;
                let Some(offset) = read_varint(plain, &mut cursor) else {
                    break;
                };
                let Some(length) =
                    read_varint(plain, &mut cursor).and_then(|n| usize::try_from(n).ok())
                else {
                    break;
                };
                let Some(end) = cursor.checked_add(length).filter(|end| *end <= plain.len()) else {
                    break;
                };
                let Some(start) = usize::try_from(offset).ok() else {
                    cursor = end;
                    continue;
                };
                if start < stream.len() {
                    let take = length.min(stream.len() - start);
                    for index in 0..take {
                        let position = start + index;
                        if !seen[position] {
                            stream[position] = plain[cursor + index];
                            seen[position] = true;
                        }
                    }
                }
                cursor = end;
            }
            0x1c => {
                cursor += 1;
                let Some(_) = read_varint(plain, &mut cursor) else {
                    break;
                };
                let Some(_) = read_varint(plain, &mut cursor) else {
                    break;
                };
                let Some(reason_length) =
                    read_varint(plain, &mut cursor).and_then(|length| usize::try_from(length).ok())
                else {
                    break;
                };
                let Some(end) = cursor
                    .checked_add(reason_length)
                    .filter(|end| *end <= plain.len())
                else {
                    break;
                };
                cursor = end;
            }
            _ => break,
        }
    }
}

fn skip_initial_ack(plain: &[u8], cursor: &mut usize, ecn: bool) -> Option<()> {
    read_varint(plain, cursor)?;
    read_varint(plain, cursor)?;
    let range_count = read_varint(plain, cursor)?;
    read_varint(plain, cursor)?;
    for _ in 0..range_count {
        read_varint(plain, cursor)?;
        read_varint(plain, cursor)?;
    }
    if ecn {
        for _ in 0..3 {
            read_varint(plain, cursor)?;
        }
    }
    Some(())
}

fn open_initial_crypto(input: &[u8]) -> Result<OpenedInitial, QuicSplitError> {
    if input.len() > MAX_DATAGRAM {
        return Err(QuicSplitError::Invalid);
    }
    let header = parse_initial_header(input).ok_or(QuicSplitError::Invalid)?;
    let keys = derive_initial_keys(
        header.version,
        &input[header.dcid_offset..header.dcid_offset + header.dcid_len],
    )?;
    let (plain, packet_number, pn_len) = open_initial(input, header, keys)?;

    let mut frames = Vec::new();
    let mut pings = 0usize;
    let mut cursor = 0usize;
    while cursor < plain.len() {
        match plain[cursor] {
            0x00 => cursor += 1,
            0x01 => {
                pings += 1;
                cursor += 1;
            }
            0x06 if frames.len() < MAX_CRYPTO_FRAMES => {
                cursor += 1;
                let offset = read_varint(&plain, &mut cursor).ok_or(QuicSplitError::Invalid)?;
                let len = usize::try_from(
                    read_varint(&plain, &mut cursor).ok_or(QuicSplitError::Invalid)?,
                )
                .map_err(|_| QuicSplitError::Invalid)?;
                let data_end = cursor.checked_add(len).ok_or(QuicSplitError::Invalid)?;
                if data_end > plain.len() {
                    return Err(QuicSplitError::Invalid);
                }
                frames.push(CryptoFrame {
                    offset,
                    data_offset: cursor,
                    len,
                });
                cursor = data_end;
            }
            _ => return Err(QuicSplitError::Invalid),
        }
    }
    if frames.is_empty() {
        return Err(QuicSplitError::Invalid);
    }

    let mut stream = [0u8; MAX_PACKET];
    let mut seen = [false; MAX_PACKET];
    for frame in &frames {
        let start = usize::try_from(frame.offset).map_err(|_| QuicSplitError::Invalid)?;
        if start >= MAX_PACKET {
            continue;
        }
        let take = frame.len.min(MAX_PACKET - start);
        for index in 0..take {
            let pos = start + index;
            if !seen[pos] {
                stream[pos] = plain[frame.data_offset + index];
                seen[pos] = true;
            }
        }
    }
    let filled = seen.iter().take_while(|value| **value).count();
    Ok(OpenedInitial {
        header,
        keys,
        plain,
        packet_number,
        pn_len,
        frames,
        stream: stream[..filled].to_vec(),
        pings,
    })
}

fn parse_initial_header(input: &[u8]) -> Option<InitialHeader> {
    if input.len() < 7 || input[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(input.get(1..5)?.try_into().ok()?);
    let raw_type = (input[0] >> 4) & 0x03;
    let expected_type = match version {
        QUIC_V1 => 0,
        QUIC_V2 => 1,
        _ => return None,
    };
    if raw_type != expected_type {
        return None;
    }

    let mut cursor = 5usize;
    let dcid_len = usize::from(*input.get(cursor)?);
    cursor += 1;
    if dcid_len > MAX_CID || cursor.checked_add(dcid_len)? >= input.len() {
        return None;
    }
    let dcid_offset = cursor;
    cursor += dcid_len;
    let scid_len = usize::from(*input.get(cursor)?);
    cursor += 1;
    if scid_len > MAX_CID || cursor.checked_add(scid_len)? > input.len() {
        return None;
    }
    cursor += scid_len;
    let token_len = usize::try_from(read_varint(input, &mut cursor)?).ok()?;
    cursor = cursor.checked_add(token_len)?;
    if cursor > input.len() {
        return None;
    }
    let length_width = 1usize.checked_shl(u32::from(*input.get(cursor)? >> 6))?;
    let length_claimed = usize::try_from(read_varint(input, &mut cursor)?).ok()?;
    if length_claimed < 17 || length_claimed > input.len().checked_sub(cursor)? {
        return None;
    }
    if cursor.checked_add(20)? > input.len() {
        return None;
    }
    Some(InitialHeader {
        version,
        dcid_offset,
        dcid_len,
        pn_offset: cursor,
        length_claimed,
        length_width,
        packet_len: cursor + length_claimed,
    })
}

fn derive_initial_keys(version: u32, dcid: &[u8]) -> Result<InitialKeys, QuicSplitError> {
    derive_initial_keys_for_role(version, dcid, b"client in")
}

fn derive_initial_keys_for_role(
    version: u32,
    dcid: &[u8],
    role: &[u8],
) -> Result<InitialKeys, QuicSplitError> {
    if dcid.len() > MAX_CID {
        return Err(QuicSplitError::Invalid);
    }
    let (salt, key_label, iv_label, hp_label) = if version == QUIC_V1 {
        (
            &SALT_V1,
            b"quic key".as_slice(),
            b"quic iv".as_slice(),
            b"quic hp".as_slice(),
        )
    } else if version == QUIC_V2 {
        (
            &SALT_V2,
            b"quicv2 key".as_slice(),
            b"quicv2 iv".as_slice(),
            b"quicv2 hp".as_slice(),
        )
    } else {
        return Err(QuicSplitError::Invalid);
    };
    let initial = Hkdf::<Sha256>::new(Some(salt), dcid);
    let mut initial_secret = [0; 32];
    expand_label(&initial, role, &mut initial_secret)?;
    let secret = Hkdf::<Sha256>::from_prk(&initial_secret).map_err(|_| QuicSplitError::Invalid)?;
    let mut keys = InitialKeys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    expand_label(&secret, key_label, &mut keys.key)?;
    expand_label(&secret, iv_label, &mut keys.iv)?;
    expand_label(&secret, hp_label, &mut keys.hp)?;
    Ok(keys)
}

fn expand_label(
    hkdf: &Hkdf<Sha256>,
    label: &[u8],
    output: &mut [u8],
) -> Result<(), QuicSplitError> {
    let mut info = Vec::with_capacity(4 + label.len());
    info.extend_from_slice(&(output.len() as u16).to_be_bytes());
    info.push(u8::try_from(6 + label.len()).map_err(|_| QuicSplitError::Invalid)?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    hkdf.expand(&info, output)
        .map_err(|_| QuicSplitError::Invalid)
}

fn open_initial(
    input: &[u8],
    header: InitialHeader,
    keys: InitialKeys,
) -> Result<(Vec<u8>, u64, usize), QuicSplitError> {
    if header.packet_len > MAX_PACKET || header.length_claimed < 17 {
        return Err(QuicSplitError::Invalid);
    }
    let sample_start = header
        .pn_offset
        .checked_add(4)
        .ok_or(QuicSplitError::Invalid)?;
    let sample = input
        .get(sample_start..sample_start + 16)
        .ok_or(QuicSplitError::Invalid)?;
    let mask = header_mask(&keys.hp, sample)?;
    let first = input[0] ^ (mask[0] & 0x0f);
    let pn_len = usize::from(first & 0x03) + 1;
    let pn_end = header
        .pn_offset
        .checked_add(pn_len)
        .ok_or(QuicSplitError::Invalid)?;
    let protected_pn = input
        .get(header.pn_offset..pn_end)
        .ok_or(QuicSplitError::Invalid)?;
    let mut pn_bytes = [0; 4];
    for (index, byte) in protected_pn.iter().enumerate() {
        pn_bytes[index] = *byte ^ mask[index + 1];
    }
    if header.length_claimed < pn_len + 16 {
        return Err(QuicSplitError::Invalid);
    }
    let mut truncated = 0u64;
    for byte in &pn_bytes[..pn_len] {
        truncated = (truncated << 8) | u64::from(*byte);
    }
    let packet_number = decode_packet_number(0, truncated, pn_len);
    let mut aad = input[..pn_end].to_vec();
    aad[0] = first;
    aad[header.pn_offset..pn_end].copy_from_slice(&pn_bytes[..pn_len]);
    let nonce = packet_nonce(&keys.iv, packet_number);
    let cipher = Aes128Gcm::new_from_slice(&keys.key).map_err(|_| QuicSplitError::Invalid)?;
    let ciphertext = input
        .get(pn_end..header.packet_len)
        .ok_or(QuicSplitError::Invalid)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| QuicSplitError::Invalid)?;
    if first & 0x0c != 0 {
        return Err(QuicSplitError::Invalid);
    }
    Ok((plain, packet_number, pn_len))
}

fn seal_initial(
    clear_header: &[u8],
    plain: &[u8],
    packet_number: u64,
    pn_len: usize,
    keys: InitialKeys,
) -> Result<Vec<u8>, QuicSplitError> {
    if !(1..=4).contains(&pn_len) {
        return Err(QuicSplitError::Invalid);
    }
    let aad_len = clear_header
        .len()
        .checked_add(pn_len)
        .ok_or(QuicSplitError::Invalid)?;
    let packet_len = aad_len
        .checked_add(plain.len())
        .and_then(|len| len.checked_add(16))
        .ok_or(QuicSplitError::Invalid)?;
    if packet_len > MAX_PACKET || pn_len + plain.len() + 16 < 20 {
        return Err(QuicSplitError::Invalid);
    }
    let mut output = vec![0; packet_len];
    output[..clear_header.len()].copy_from_slice(clear_header);
    output[0] = (output[0] & 0xfc) | (pn_len as u8 - 1);
    for index in 0..pn_len {
        output[clear_header.len() + index] = (packet_number >> (8 * (pn_len - 1 - index))) as u8;
    }
    let nonce = packet_nonce(&keys.iv, packet_number);
    let cipher = Aes128Gcm::new_from_slice(&keys.key).map_err(|_| QuicSplitError::Invalid)?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &output[..aad_len],
            },
        )
        .map_err(|_| QuicSplitError::Invalid)?;
    if sealed.len() != packet_len - aad_len {
        return Err(QuicSplitError::Invalid);
    }
    output[aad_len..].copy_from_slice(&sealed);
    let sample_start = clear_header
        .len()
        .checked_add(4)
        .ok_or(QuicSplitError::Invalid)?;
    let mask = header_mask(&keys.hp, &output[sample_start..sample_start + 16])?;
    output[0] ^= mask[0] & 0x0f;
    for index in 0..pn_len {
        output[clear_header.len() + index] ^= mask[index + 1];
    }
    Ok(output)
}

fn header_mask(key: &[u8; 16], sample: &[u8]) -> Result<[u8; 16], QuicSplitError> {
    let cipher = Aes128::new_from_slice(key).map_err(|_| QuicSplitError::Invalid)?;
    let mut block = aes::cipher::Block::<Aes128>::clone_from_slice(
        sample.get(..16).ok_or(QuicSplitError::Invalid)?,
    );
    cipher.encrypt_block(&mut block);
    let mut mask = [0; 16];
    mask.copy_from_slice(&block);
    Ok(mask)
}

fn packet_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for index in 0..8 {
        nonce[11 - index] ^= (packet_number >> (8 * index)) as u8;
    }
    nonce
}

fn decode_packet_number(largest_received: u64, truncated: u64, pn_len: usize) -> u64 {
    let pn_bits = (pn_len * 8) as u32;
    let window = 1u64 << pn_bits;
    let half_window = window / 2;
    let mask = window - 1;
    let expected = largest_received + 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + half_window <= expected && candidate + window < (1u64 << 62) {
        candidate + window
    } else if candidate > expected + half_window && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

fn read_varint(input: &[u8], cursor: &mut usize) -> Option<u64> {
    let first = *input.get(*cursor)?;
    let width = 1usize << (first >> 6);
    let end = cursor.checked_add(width)?;
    let bytes = input.get(*cursor..end)?;
    let mut value = u64::from(bytes[0] & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *cursor = end;
    Some(value)
}

fn write_varint(value: u64, output: &mut Vec<u8>) -> Result<(), QuicSplitError> {
    if value <= 63 {
        output.push(value as u8);
    } else if value <= 16_383 {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value <= 1_073_741_823 {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else if value <= 4_611_686_018_427_387_903 {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    } else {
        return Err(QuicSplitError::Invalid);
    }
    Ok(())
}

fn append_crypto_frame(
    output: &mut Vec<u8>,
    offset: u64,
    data: &[u8],
    capacity: usize,
) -> Result<(), QuicSplitError> {
    let start_len = output.len();
    output.push(0x06);
    write_varint(offset, output)?;
    write_varint(data.len() as u64, output)?;
    if output
        .len()
        .checked_add(data.len())
        .is_none_or(|end| end > capacity)
    {
        output.truncate(start_len);
        return Err(QuicSplitError::Invalid);
    }
    output.extend_from_slice(data);
    Ok(())
}

fn find_client_hello_sni(bytes: &[u8]) -> Option<(usize, usize)> {
    find_client_hello_sni_result(bytes).ok().flatten()
}

/// Replace or remove the host-name entry in a complete TLS ClientHello.
/// Length fields are updated in place; all other handshake bytes are retained.
pub fn r2k_quic_client_hello_rename_sni(
    bytes: &[u8],
    server_name: Option<&str>,
) -> Option<Vec<u8>> {
    let handshake_len = read_u24(bytes, 1)?;
    if bytes.len() != handshake_len.checked_add(4)? {
        return None;
    }
    let details = find_client_hello_sni_details(bytes).ok().flatten();
    let Some(details) = details else {
        return server_name.is_none().then(|| bytes.to_vec());
    };

    let mut output = bytes.to_vec();
    let Some(server_name) = server_name else {
        output.drain(details.extension_start..details.extension_end);
        adjust_u16(
            &mut output,
            details.extensions_len_offset,
            -isize::try_from(details.extension_end - details.extension_start).ok()?,
        )?;
        adjust_u24(
            &mut output,
            1,
            -isize::try_from(details.extension_end - details.extension_start).ok()?,
        )?;
        return Some(output);
    };

    let replacement = server_name.as_bytes();
    if replacement.is_empty() || replacement.len() > 253 || replacement.contains(&0) {
        return None;
    }
    let delta =
        isize::try_from(replacement.len()).ok()? - isize::try_from(details.name_len).ok()?;
    let name_end = details.name_offset.checked_add(details.name_len)?;
    output.splice(details.name_offset..name_end, replacement.iter().copied());
    output
        .get_mut(details.name_offset..details.name_offset + replacement.len())?
        .copy_from_slice(replacement);
    adjust_u16(&mut output, details.name_len_offset, delta)?;
    adjust_u16(&mut output, details.server_name_list_len_offset, delta)?;
    adjust_u16(&mut output, details.extension_len_offset, delta)?;
    adjust_u16(&mut output, details.extensions_len_offset, delta)?;
    adjust_u24(&mut output, 1, delta)?;
    Some(output)
}

fn find_client_hello_sni_result(bytes: &[u8]) -> Result<Option<(usize, usize)>, &'static str> {
    Ok(
        find_client_hello_sni_details(bytes)?
            .map(|details| (details.name_offset, details.name_len)),
    )
}

#[derive(Clone, Copy)]
struct ClientHelloSniDetails {
    extensions_len_offset: usize,
    extension_start: usize,
    extension_end: usize,
    extension_len_offset: usize,
    server_name_list_len_offset: usize,
    name_len_offset: usize,
    name_offset: usize,
    name_len: usize,
}

fn find_client_hello_sni_details(
    bytes: &[u8],
) -> Result<Option<ClientHelloSniDetails>, &'static str> {
    if bytes.len() < 4 || bytes[0] != 1 {
        return Err("неверный заголовок TLS ClientHello");
    }
    let handshake_len = read_u24(bytes, 1).ok_or("неверная длина TLS ClientHello")?;
    let claimed_end = 4usize
        .checked_add(handshake_len)
        .ok_or("неверная длина TLS ClientHello")?;
    if claimed_end > bytes.len() {
        return Err("TLS ClientHello обрезан");
    }
    let end = claimed_end;
    let mut offset = 4usize;
    if offset.checked_add(34).is_none_or(|next| next > end) {
        return Err("TLS ClientHello обрезан до полей версии и случайного числа");
    }
    offset += 34;
    if !skip_u8_vector(bytes, end, &mut offset)
        || !skip_u16_vector(bytes, end, &mut offset)
        || !skip_u8_vector(bytes, end, &mut offset)
    {
        return Err("неверные векторы TLS ClientHello");
    }
    let extensions_len_offset = offset;
    let extensions_len =
        read_u16(bytes, offset).ok_or("отсутствует длина расширений ClientHello")?;
    offset = offset
        .checked_add(2)
        .ok_or("неверная длина расширений ClientHello")?;
    let extensions_end = offset
        .checked_add(extensions_len)
        .filter(|extension_end| *extension_end == end)
        .ok_or("неверная длина расширений ClientHello")?;
    let mut sni_seen = false;
    let mut sni = None;
    while offset < extensions_end {
        if offset
            .checked_add(4)
            .is_none_or(|next| next > extensions_end)
        {
            return Err("обрезан заголовок расширения ClientHello");
        }
        let extension_start = offset;
        let extension_type =
            read_u16(bytes, offset).ok_or("неверный тип расширения ClientHello")?;
        let extension_len =
            read_u16(bytes, offset + 2).ok_or("неверная длина расширения ClientHello")?;
        offset = offset
            .checked_add(4)
            .ok_or("неверная длина расширения ClientHello")?;
        let extension_end = offset
            .checked_add(extension_len)
            .filter(|extension_end| *extension_end <= extensions_end)
            .ok_or("расширение ClientHello выходит за границы списка")?;
        if extension_type == 0 {
            if sni_seen {
                return Err("расширение SNI повторяется в ClientHello");
            }
            sni_seen = true;
            let server_name_list_len_offset = offset;
            let mut cursor = offset;
            let list_len = read_u16(bytes, cursor).ok_or("неверная длина списка SNI")?;
            cursor = cursor.checked_add(2).ok_or("неверная длина списка SNI")?;
            let list_end = cursor
                .checked_add(list_len)
                .filter(|list_end| *list_end == extension_end)
                .ok_or("неверная длина списка SNI")?;
            while cursor < list_end {
                if cursor.checked_add(3).is_none_or(|next| next > list_end) {
                    return Err("обрезана запись имени в списке SNI");
                }
                let name_type = bytes[cursor];
                let name_len_offset = cursor.checked_add(1).ok_or("неверная длина имени SNI")?;
                let name_len = read_u16(bytes, cursor + 1).ok_or("неверная длина имени SNI")?;
                cursor = cursor.checked_add(3).ok_or("неверная длина имени SNI")?;
                let name_end = cursor
                    .checked_add(name_len)
                    .filter(|name_end| *name_end <= list_end)
                    .ok_or("имя выходит за границы списка SNI")?;
                if name_type == 0 {
                    if name_len == 0 {
                        return Err("пустое имя узла в списке SNI");
                    }
                    let details = ClientHelloSniDetails {
                        extensions_len_offset,
                        extension_start,
                        extension_end,
                        extension_len_offset: extension_start + 2,
                        server_name_list_len_offset,
                        name_len_offset,
                        name_offset: cursor,
                        name_len,
                    };
                    if sni.replace(details).is_some() {
                        return Err("имя узла SNI повторяется");
                    }
                }
                cursor = name_end;
            }
        }
        offset = extension_end;
    }
    Ok(sni)
}

fn adjust_u16(bytes: &mut [u8], offset: usize, delta: isize) -> Option<()> {
    let old = i64::try_from(read_u16(bytes, offset)?).ok()?;
    let next = u16::try_from(old.checked_add(i64::try_from(delta).ok()?)?).ok()?;
    bytes
        .get_mut(offset..offset.checked_add(2)?)?
        .copy_from_slice(&next.to_be_bytes());
    Some(())
}

fn adjust_u24(bytes: &mut [u8], offset: usize, delta: isize) -> Option<()> {
    let old = i64::try_from(read_u24(bytes, offset)?).ok()?;
    let next = u32::try_from(old.checked_add(i64::try_from(delta).ok()?)?).ok()?;
    if next > 0x00ff_ffff {
        return None;
    }
    let encoded = next.to_be_bytes();
    bytes
        .get_mut(offset..offset.checked_add(3)?)?
        .copy_from_slice(&encoded[1..]);
    Some(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<usize> {
    let end = offset.checked_add(2)?;
    Some(usize::from(u16::from_be_bytes(
        bytes.get(offset..end)?.try_into().ok()?,
    )))
}

fn read_u24(bytes: &[u8], offset: usize) -> Option<usize> {
    let slice = bytes.get(offset..offset.checked_add(3)?)?;
    Some((usize::from(slice[0]) << 16) | (usize::from(slice[1]) << 8) | usize::from(slice[2]))
}

fn skip_u8_vector(bytes: &[u8], end: usize, offset: &mut usize) -> bool {
    let Some(length) = bytes.get(*offset).copied().map(usize::from) else {
        return false;
    };
    let Some(next) = offset
        .checked_add(1)
        .and_then(|start| start.checked_add(length))
    else {
        return false;
    };
    if next > end {
        return false;
    }
    *offset = next;
    true
}

fn skip_u16_vector(bytes: &[u8], end: usize, offset: &mut usize) -> bool {
    let Some(length) = read_u16(bytes, *offset) else {
        return false;
    };
    let Some(next) = offset
        .checked_add(2)
        .and_then(|start| start.checked_add(length))
    else {
        return false;
    };
    if next > end {
        return false;
    }
    *offset = next;
    true
}

#[cfg(test)]
mod tests {
    use super::QuicSplitError;
    use super::{
        append_crypto_frame, derive_initial_keys, find_client_hello_sni,
        find_client_hello_sni_result, initial_split_crypto, open_initial, parse_initial_header,
        read_varint, seal_initial,
    };
    use sha2::{Digest, Sha256};

    const RFC_9001_INITIAL: &[u8] = include_bytes!("../tests/fixtures/quic_v1_initial.bin");
    const RFC_9369_INITIAL: &[u8] = include_bytes!("../tests/fixtures/quic_v2_initial.bin");

    #[test]
    fn собирает_clienthello_из_двух_initial_и_проверяет_принадлежность_полёту() {
        let (first, second) = fragmented_initials(RFC_9001_INITIAL);
        let expected_packet = opened_frames(RFC_9001_INITIAL);
        let expected = crypto_stream(&expected_packet.frames);

        assert_eq!(
            super::r2k_quic_initial_client_hello_from_datagrams(&[&first, &second]),
            Some(expected.clone())
        );
        assert_eq!(
            super::r2k_quic_initial_client_hello_from_datagrams(&[&second, &first]),
            Some(expected)
        );
        assert_eq!(
            super::r2k_quic_initial_client_hello_from_datagrams(&[&first]),
            None,
            "неполный ClientHello не считается приветствием"
        );
        assert_eq!(
            super::r2k_quic_initial_client_hello_from_datagrams(&[&first, RFC_9369_INITIAL]),
            None,
            "Initial разных версий не склеиваются"
        );
    }

    #[test]
    fn переименовывает_или_удаляет_sni_с_пересчётом_длин_clienthello() {
        let original = super::r2k_quic_initial_client_hello_from_datagrams(&[RFC_9001_INITIAL])
            .expect("тестовый ClientHello расшифровывается");
        let renamed = super::r2k_quic_client_hello_rename_sni(&original, Some("disk.rzd.ru"))
            .expect("SNI заменяется");
        assert_eq!(
            super::find_client_hello_sni_result(&renamed)
                .unwrap()
                .map(|(start, len)| renamed[start..start + len].to_vec()),
            Some(b"disk.rzd.ru".to_vec())
        );
        assert_eq!(
            super::r2k_quic_client_hello_rename_sni(&renamed, Some("example.com")),
            Some(original.clone()),
            "возврат исходного SNI возвращает все длины и байты ClientHello"
        );

        let without_sni = super::r2k_quic_client_hello_rename_sni(&original, None)
            .expect("расширение SNI удаляется");
        assert_eq!(super::find_client_hello_sni_result(&without_sni), Ok(None));
        assert_eq!(
            super::r2k_quic_client_hello_rename_sni(&without_sni, None),
            Some(without_sni.clone())
        );
        assert!(
            super::r2k_quic_client_hello_rename_sni(&without_sni, Some("example.com")).is_none()
        );
    }

    #[test]
    fn критерий_ответа_quic_совпадает_с_donor_parse() {
        let client = RFC_9001_INITIAL;
        let vn = [0x80, 0, 0, 0, 0, 0, 0];
        let retry_v1 = [0xf0, 0, 0, 0, 1, 0, 0];
        let foreign_version = [0xc0, 0, 0, 0, 2, 0, 0];
        let short_header = [0x40, 0, 0, 0, 1, 0, 0];
        let (version, dcid) = super::r2k_quic_initial_flight_id(client).unwrap();
        let answers = [
            ("vn", &vn[..], true),
            ("retry_v1", &retry_v1[..], true),
            ("foreign", &foreign_version[..], false),
            ("short", &short_header[..], false),
        ];
        let mut output = String::new();
        for (name, response, expected) in answers {
            let answered = super::r2k_quic_initial_verify_donor_response(client, response);
            assert_eq!(answered, expected, "{name}");
            assert_eq!(
                super::r2k_quic_donor_response_matches(version, &dcid, response),
                expected,
                "generic donor verifier: {name}"
            );
            output.push_str(&format!("{name}={}\n", u8::from(answered)));
        }
        if let Ok(path) = std::env::var("R2O_QUIC_DONOR_VERIFY_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn извлекает_sni_и_идентификатор_из_пачки_initial() {
        let (first, second) = fragmented_initials(RFC_9001_INITIAL);

        assert_eq!(
            super::r2k_quic_initial_sni_from_datagrams(&[&first, &second]),
            Some(b"example.com".to_vec())
        );
        assert_eq!(
            super::r2k_quic_initial_flight_id(&first),
            super::r2k_quic_initial_flight_id(&second)
        );
        assert_ne!(
            super::r2k_quic_initial_flight_id(RFC_9001_INITIAL),
            super::r2k_quic_initial_flight_id(RFC_9369_INITIAL)
        );
    }

    #[test]
    fn создаёт_аутентифицированный_quic_initial_из_clienthello() {
        let client_hello = crypto_stream(&opened_frames(RFC_9001_INITIAL).frames);
        let initial =
            super::r2k_quic_initial_build(&client_hello, &[1, 2, 3, 4, 5, 6, 7, 8], 1200).unwrap();

        assert_eq!(initial.len(), 1200);
        assert!(super::is_authenticated_initial(&initial));
        assert_eq!(
            super::initial_client_hello_sni(&initial).as_deref(),
            Some(b"example.com".as_slice())
        );
        assert!(super::r2k_quic_initial_build(&client_hello, &[1, 2, 3], 1200).is_none());
        assert!(super::r2k_quic_initial_build(&client_hello, &[1; 8], 1199).is_none());
    }

    #[test]
    fn отличает_отсутствие_sni_от_повреждённого_clienthello() {
        let mut client_hello = crypto_stream(&opened_frames(RFC_9001_INITIAL).frames);
        let (sni_offset, _) = find_client_hello_sni(&client_hello).unwrap();
        let extension_type_offset = sni_offset - 9;
        assert_eq!(
            &client_hello[extension_type_offset..extension_type_offset + 2],
            &[0, 0]
        );
        client_hello[extension_type_offset..extension_type_offset + 2]
            .copy_from_slice(&[0xff, 0xfe]);

        assert_eq!(find_client_hello_sni_result(&client_hello), Ok(None));

        let mut malformed = client_hello;
        malformed[1..4].copy_from_slice(&[0, 0, 0]);
        assert!(find_client_hello_sni_result(&malformed).is_err());
    }

    #[test]
    fn полный_initial_без_sni_остаётся_допустимым() {
        let initial = include_bytes!("../tests/fixtures/quic_v1_initial_no_sni.bin");

        assert!(super::r2k_quic_initial_client_hello_from_datagrams(&[initial]).is_some());
        assert_eq!(
            super::r2k_quic_initial_sni_result_from_datagrams(&[initial]),
            Ok(None)
        );
        assert_eq!(super::r2k_quic_initial_sni_from_datagrams(&[initial]), None);
    }

    #[test]
    fn отклоняет_clienthello_после_connection_close_прикладного_уровня() {
        let (first, second) = fragmented_initials(RFC_9001_INITIAL);
        let first = prepend_initial_frames(&first, &[0x1d, 0, 0]);

        assert_eq!(
            super::r2k_quic_initial_client_hello_from_datagrams(&[&first, &second]),
            None,
            "после запрещённого кадра Initial не продолжается"
        );
    }

    #[test]
    fn пропускает_ack_ack_ecn_и_connection_close_транспортного_уровня() {
        let (first, second) = fragmented_initials(RFC_9001_INITIAL);
        let first = prepend_initial_frames(
            &first,
            &[0x02, 0, 0, 0, 0, 0x03, 0, 0, 0, 0, 0, 0, 0, 0x1c, 0, 0, 0],
        );
        let expected = crypto_stream(&opened_frames(RFC_9001_INITIAL).frames);

        assert_eq!(
            super::r2k_quic_initial_client_hello_from_datagrams(&[&first, &second]),
            Some(expected)
        );
    }

    struct OpenedPacket {
        plain: Vec<u8>,
        packet_number: u64,
        frames: Vec<(u64, Vec<u8>)>,
    }

    #[test]
    fn splits_rfc_9001_initial_without_changing_datagram_length() {
        let split = initial_split_crypto(RFC_9001_INITIAL).unwrap();
        assert_eq!(split.len(), RFC_9001_INITIAL.len());
        assert_ne!(split, RFC_9001_INITIAL);
        assert_eq!(RFC_9001_INITIAL[0], 0xc0);
        assert_eq!(
            format!("{:x}", Sha256::digest(&split)),
            "f809a9eb845c020192bfc4a4b83ff19ffc85ecbb8e458deca8c480cda5d2d6e3"
        );

        let source_packet = opened_frames(RFC_9001_INITIAL);
        let split_packet = opened_frames(&split);
        assert_eq!(source_packet.packet_number, 2);
        assert_eq!(source_packet.packet_number, split_packet.packet_number);
        assert_eq!(source_packet.plain.len(), 1162);
        assert_eq!(source_packet.plain.len(), split_packet.plain.len());
        assert_eq!(source_packet.frames.len(), 1);
        assert_eq!(split_packet.frames.len(), 2);
        assert!(split_packet.frames[0].0 > 0);
        assert_eq!(split_packet.frames[1].0, 0);
        assert_eq!(
            split_packet.frames[0].0 + split_packet.frames[0].1.len() as u64,
            source_packet.frames[0].1.len() as u64
        );
        assert_eq!(
            split_packet.frames[1].1.len() as u64,
            split_packet.frames[0].0
        );
        let source_header = parse_initial_header(RFC_9001_INITIAL).unwrap();
        let split_header = parse_initial_header(&split).unwrap();
        assert_eq!(
            &RFC_9001_INITIAL[1..source_header.pn_offset],
            &split[1..split_header.pn_offset]
        );

        let source_stream = crypto_stream(&source_packet.frames);
        let split_stream = crypto_stream(&split_packet.frames);
        assert_eq!(source_stream, split_stream);
        let (sni_offset, sni_len) = find_client_hello_sni(&source_stream).unwrap();
        assert_eq!(
            &source_stream[sni_offset..sni_offset + sni_len],
            b"example.com"
        );
        assert!(!split_packet.frames.iter().any(|(_, bytes)| {
            bytes
                .windows(b"example.com".len())
                .any(|window| window == b"example.com")
        }));
    }

    #[test]
    fn сохраняет_четырехбайтовую_ширину_поля_length() {
        let source_header = parse_initial_header(RFC_9001_INITIAL).unwrap();
        let keys = derive_initial_keys(
            source_header.version,
            &RFC_9001_INITIAL
                [source_header.dcid_offset..source_header.dcid_offset + source_header.dcid_len],
        )
        .unwrap();
        let (plain, packet_number, pn_len) =
            open_initial(RFC_9001_INITIAL, source_header, keys).unwrap();
        let length_offset = source_header.pn_offset - source_header.length_width;
        let mut wide_header = RFC_9001_INITIAL[..length_offset].to_vec();
        wide_header[0] = RFC_9001_INITIAL[0] & 0xf0;
        let wide_length = u32::try_from(source_header.length_claimed).unwrap() | 0x8000_0000;
        wide_header.extend_from_slice(&wide_length.to_be_bytes());
        let wide_initial =
            super::seal_initial(&wide_header, &plain, packet_number, pn_len, keys).unwrap();

        let wide_header = parse_initial_header(&wide_initial).unwrap();
        assert_eq!(wide_header.length_width, 4);
        assert!(super::is_authenticated_initial(&wide_initial));

        let split = initial_split_crypto(&wide_initial).unwrap();
        assert_eq!(split.len(), wide_initial.len());
        assert_eq!(parse_initial_header(&split).unwrap().length_width, 4);
        assert_eq!(opened_frames(&split).packet_number, packet_number);
    }

    #[test]
    fn splits_rfc_9369_initial_with_v2_keys_and_labels() {
        let split = initial_split_crypto(RFC_9369_INITIAL).unwrap();
        assert_eq!(split.len(), RFC_9369_INITIAL.len());
        assert_eq!(
            format!("{:x}", Sha256::digest(&split)),
            "bae1afa70353dddb59db04b091489eaeb9aed2c18628a0be55d95124d70f0cfc"
        );
        let source_packet = opened_frames(RFC_9369_INITIAL);
        let split_packet = opened_frames(&split);
        assert_eq!(source_packet.packet_number, split_packet.packet_number);
        assert_eq!(source_packet.plain.len(), split_packet.plain.len());
        assert_eq!(source_packet.frames.len(), 1);
        assert_eq!(split_packet.frames.len(), 2);
        assert_eq!(
            crypto_stream(&source_packet.frames),
            crypto_stream(&split_packet.frames)
        );
    }

    #[test]
    fn refuses_when_authenticated_initial_is_modified() {
        let mut corrupted = RFC_9001_INITIAL.to_vec();
        corrupted[600] ^= 1;
        assert_eq!(
            initial_split_crypto(&corrupted),
            Err(QuicSplitError::Invalid)
        );
        assert!(!super::is_authenticated_initial(&corrupted));
        assert!(super::is_authenticated_initial(RFC_9001_INITIAL));
    }

    #[test]
    fn extracts_sni_from_authenticated_v1_and_v2_initials() {
        assert_eq!(
            super::initial_client_hello_sni(RFC_9001_INITIAL).as_deref(),
            Some(b"example.com".as_slice())
        );
        assert_eq!(
            super::initial_client_hello_sni(RFC_9369_INITIAL).as_deref(),
            Some(b"example.com".as_slice())
        );

        let mut corrupted = RFC_9001_INITIAL.to_vec();
        corrupted[600] ^= 1;
        assert_eq!(super::initial_client_hello_sni(&corrupted), None);
    }

    #[test]
    fn привязывает_server_initial_и_retry_к_перезапечатанному_полёту() {
        for initial in [RFC_9001_INITIAL, RFC_9369_INITIAL] {
            let packed = crate::quic_snapshot::r2k_quic_snapshot_pack(&[initial]).unwrap();
            let replay = crate::quic_snapshot::r2k_quic_snapshot_reseal(&packed).unwrap();
            let client = crate::quic_snapshot::r2k_quic_snapshot_parse(&replay)
                .unwrap()
                .datagrams()[0];
            let valid_server = server_initial_for(client, None);
            assert!(
                crate::quic_snapshot::r2k_quic_snapshot_verify_bound_response(
                    &replay,
                    &valid_server
                )
            );

            let wrong_cid_server = server_initial_for(client, Some(&[9, 8, 7, 6, 5, 4, 3, 2]));
            assert!(
                !crate::quic_snapshot::r2k_quic_snapshot_verify_bound_response(
                    &replay,
                    &wrong_cid_server
                )
            );

            let mut corrupted = valid_server.clone();
            *corrupted.last_mut().unwrap() ^= 1;
            assert!(
                !crate::quic_snapshot::r2k_quic_snapshot_verify_bound_response(&replay, &corrupted)
            );

            let valid_retry = retry_for(client);
            assert!(
                crate::quic_snapshot::r2k_quic_snapshot_verify_bound_response(
                    &replay,
                    &valid_retry
                )
            );
            let mut corrupted_retry = valid_retry;
            *corrupted_retry.last_mut().unwrap() ^= 1;
            assert!(
                !crate::quic_snapshot::r2k_quic_snapshot_verify_bound_response(
                    &replay,
                    &corrupted_retry
                )
            );
        }
    }

    fn server_initial_for(client: &[u8], response_dcid: Option<&[u8]>) -> Vec<u8> {
        let client_header = parse_initial_header(client).unwrap();
        let original_dcid =
            &client[client_header.dcid_offset..client_header.dcid_offset + client_header.dcid_len];
        let scid_len_offset = client_header.dcid_offset + client_header.dcid_len;
        let client_scid_len = usize::from(client[scid_len_offset]);
        let client_scid = &client[scid_len_offset + 1..scid_len_offset + 1 + client_scid_len];
        let response_dcid = response_dcid.unwrap_or(client_scid);
        let server_scid = b"server01";
        let mut clear_header = vec![if client_header.version == 1 {
            0xc0
        } else {
            0xd0
        }];
        clear_header.extend_from_slice(&client_header.version.to_be_bytes());
        clear_header.push(response_dcid.len() as u8);
        clear_header.extend_from_slice(response_dcid);
        clear_header.push(server_scid.len() as u8);
        clear_header.extend_from_slice(server_scid);
        clear_header.push(0);
        clear_header.extend_from_slice(&(0x4000_u16 | 20).to_be_bytes());
        let keys =
            super::derive_initial_keys_for_role(client_header.version, original_dcid, b"server in")
                .unwrap();
        super::seal_initial(&clear_header, &[1, 0, 0], 0, 1, keys).unwrap()
    }

    fn retry_for(client: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes128Gcm, KeyInit, Nonce};

        let client_header = parse_initial_header(client).unwrap();
        let original_dcid =
            &client[client_header.dcid_offset..client_header.dcid_offset + client_header.dcid_len];
        let scid_len_offset = client_header.dcid_offset + client_header.dcid_len;
        let client_scid_len = usize::from(client[scid_len_offset]);
        let client_scid = &client[scid_len_offset + 1..scid_len_offset + 1 + client_scid_len];
        let mut server_scid = original_dcid.to_vec();
        server_scid[0] ^= 1;
        let mut retry = vec![if client_header.version == 1 {
            0xf0
        } else {
            0xc0
        }];
        retry.extend_from_slice(&client_header.version.to_be_bytes());
        retry.push(client_scid.len() as u8);
        retry.extend_from_slice(client_scid);
        retry.push(server_scid.len() as u8);
        retry.extend_from_slice(&server_scid);
        retry.extend_from_slice(&[0xaa, 0xbb]);

        let mut pseudo = Vec::with_capacity(1 + original_dcid.len() + retry.len());
        pseudo.push(original_dcid.len() as u8);
        pseudo.extend_from_slice(original_dcid);
        pseudo.extend_from_slice(&retry);
        let (key, nonce) = if client_header.version == 1 {
            (&super::RETRY_KEY_V1, &super::RETRY_NONCE_V1)
        } else {
            (&super::RETRY_KEY_V2, &super::RETRY_NONCE_V2)
        };
        let cipher = Aes128Gcm::new_from_slice(key).unwrap();
        let tag = cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &[],
                    aad: &pseudo,
                },
            )
            .unwrap();
        retry.extend_from_slice(&tag);
        retry
    }

    fn opened_frames(input: &[u8]) -> OpenedPacket {
        let header = parse_initial_header(input).unwrap();
        let keys = derive_initial_keys(
            header.version,
            &input[header.dcid_offset..header.dcid_offset + header.dcid_len],
        )
        .unwrap();
        let (plain, packet_number, _) = open_initial(input, header, keys).unwrap();
        let mut frames = Vec::new();
        let mut cursor = 0;
        while cursor < plain.len() {
            match plain[cursor] {
                0x00 | 0x01 => cursor += 1,
                0x06 => {
                    cursor += 1;
                    let offset = read_varint(&plain, &mut cursor).unwrap();
                    let len = read_varint(&plain, &mut cursor).unwrap() as usize;
                    let end = cursor + len;
                    frames.push((offset, plain[cursor..end].to_vec()));
                    cursor = end;
                }
                frame => panic!("unexpected frame {frame:#x}"),
            }
        }
        OpenedPacket {
            plain,
            packet_number,
            frames,
        }
    }

    fn crypto_stream(frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut stream = [0; super::MAX_PACKET];
        let mut seen = [false; super::MAX_PACKET];
        for (offset, bytes) in frames {
            let start = *offset as usize;
            for (index, byte) in bytes.iter().copied().enumerate() {
                let position = start + index;
                if position < stream.len() && !seen[position] {
                    stream[position] = byte;
                    seen[position] = true;
                }
            }
        }
        let filled = seen.iter().take_while(|value| **value).count();
        stream[..filled].to_vec()
    }

    fn fragmented_initials(input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let header = parse_initial_header(input).unwrap();
        let keys = derive_initial_keys(
            header.version,
            &input[header.dcid_offset..header.dcid_offset + header.dcid_len],
        )
        .unwrap();
        let (plain, packet_number, pn_len) = open_initial(input, header, keys).unwrap();
        let hello = crypto_stream(&opened_frames(input).frames);
        let split = hello.len() / 2;
        let mut fragments = [Vec::new(), Vec::new()];
        append_crypto_frame(&mut fragments[0], 0, &hello[..split], plain.len()).unwrap();
        append_crypto_frame(
            &mut fragments[1],
            split as u64,
            &hello[split..],
            plain.len(),
        )
        .unwrap();
        for fragment in &mut fragments {
            fragment.resize(plain.len(), 0);
        }

        let length_offset = header.pn_offset - header.length_width;
        let seal_fragment = |fragment: &[u8], number: u64| {
            let length = pn_len + fragment.len() + 16;
            let mut clear_header = input[..length_offset].to_vec();
            clear_header[0] = input[0] & 0xf0;
            match header.length_width {
                2 => clear_header.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes()),
                4 => clear_header.extend_from_slice(&((length as u32) | 0x8000_0000).to_be_bytes()),
                width => panic!("неподдержанная ширина поля Length {width}"),
            }
            seal_initial(&clear_header, fragment, number, pn_len, keys).unwrap()
        };
        (
            seal_fragment(&fragments[0], packet_number + 1),
            seal_fragment(&fragments[1], packet_number + 2),
        )
    }

    fn prepend_initial_frames(input: &[u8], frames: &[u8]) -> Vec<u8> {
        let header = parse_initial_header(input).unwrap();
        let keys = derive_initial_keys(
            header.version,
            &input[header.dcid_offset..header.dcid_offset + header.dcid_len],
        )
        .unwrap();
        let (_, packet_number, pn_len) = open_initial(input, header, keys).unwrap();
        let opened = opened_frames(input);
        let mut plain = frames.to_vec();
        for (offset, data) in opened.frames {
            append_crypto_frame(&mut plain, offset, &data, opened.plain.len()).unwrap();
        }
        plain.resize(opened.plain.len(), 0);
        let mut clear_header = input[..header.pn_offset].to_vec();
        clear_header[0] = input[0] & 0xf0;
        let mut sealed = seal_initial(&clear_header, &plain, packet_number, pn_len, keys).unwrap();
        sealed.extend_from_slice(&input[header.packet_len..]);
        sealed
    }
}
