//! Профили ClientHello для первых проб, снятые с эталона на C.

const LEGACY_PROFILE: &str = include_str!("profiles/legacy.hex");
const MODERN_PROFILE: &str = include_str!("profiles/modern.hex");
const R2O_RX_FAKE_PROFILE: &str = include_str!("profiles/r2o_rx_fake.hex");
const TEMPLATE_MAX: usize = 4096;

#[derive(Clone, Copy)]
struct SniLayout {
    name_len: usize,
    name: usize,
    name_len_field: usize,
    list_len_field: usize,
    extension_len_field: usize,
    extensions_len_field: usize,
    handshake_len_field: usize,
    record_len_field: usize,
}

fn u16_at(bytes: &[u8], offset: usize, end: usize) -> Option<(usize, usize)> {
    let field_end = offset.checked_add(2)?;
    if field_end > end {
        return None;
    }
    Some((
        usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]])),
        field_end,
    ))
}

fn u24_at(bytes: &[u8], offset: usize, end: usize) -> Option<(usize, usize)> {
    let field_end = offset.checked_add(3)?;
    if field_end > end {
        return None;
    }
    Some((
        (usize::from(bytes[offset]) << 16)
            | (usize::from(bytes[offset + 1]) << 8)
            | usize::from(bytes[offset + 2]),
        field_end,
    ))
}

fn skip_vector(bytes: &[u8], offset: usize, end: usize, prefix: usize) -> Option<usize> {
    match prefix {
        1 => {
            let len = usize::from(*bytes.get(offset)?);
            let data = offset.checked_add(1)?;
            let next = data.checked_add(len)?;
            (next <= end).then_some(next)
        }
        2 => {
            let (len, data) = u16_at(bytes, offset, end)?;
            let next = data.checked_add(len)?;
            (next <= end).then_some(next)
        }
        _ => None,
    }
}

fn locate_sni(bytes: &[u8]) -> Option<SniLayout> {
    if bytes.len() < 9 || bytes[0] != 0x16 || bytes[1] != 0x03 || bytes[5] != 1 {
        return None;
    }
    let (record_len, _) = u16_at(bytes, 3, bytes.len())?;
    let record_end = 5usize.checked_add(record_len)?;
    if record_end != bytes.len() {
        return None;
    }
    let (handshake_len, handshake_body) = u24_at(bytes, 6, record_end)?;
    if handshake_body.checked_add(handshake_len)? != record_end {
        return None;
    }

    let mut offset = handshake_body.checked_add(34)?; // version + random
    offset = skip_vector(bytes, offset, record_end, 1)?; // session id
    offset = skip_vector(bytes, offset, record_end, 2)?; // cipher suites
    offset = skip_vector(bytes, offset, record_end, 1)?; // compression methods
    let (extensions_len, extensions_data) = u16_at(bytes, offset, record_end)?;
    let extensions_end = extensions_data.checked_add(extensions_len)?;
    if extensions_end != record_end {
        return None;
    }

    let mut extension = extensions_data;
    while extension < extensions_end {
        let (kind, after_kind) = u16_at(bytes, extension, extensions_end)?;
        let (length, data) = u16_at(bytes, after_kind, extensions_end)?;
        let extension_end = data.checked_add(length)?;
        if extension_end > extensions_end {
            return None;
        }
        if kind == 0 {
            // Поле имени сервера.
            let (list_len, names) = u16_at(bytes, data, extension_end)?;
            let list_end = names.checked_add(list_len)?;
            if list_end > extension_end {
                return None;
            }
            let mut name_entry = names;
            while name_entry < list_end {
                let name_kind = *bytes.get(name_entry)?;
                let (name_len, name) = u16_at(bytes, name_entry + 1, list_end)?;
                let name_end = name.checked_add(name_len)?;
                if name_end > list_end {
                    return None;
                }
                if name_kind == 0 && name_len != 0 {
                    return Some(SniLayout {
                        name_len,
                        name,
                        name_len_field: name_entry + 1,
                        list_len_field: data,
                        extension_len_field: after_kind,
                        extensions_len_field: offset,
                        handshake_len_field: 6,
                        record_len_field: 3,
                    });
                }
                name_entry = name_end;
            }
        }
        extension = extension_end;
    }
    None
}

/// Вернуть диапазон байтов первого расширения SNI с именем узла в ClientHello.
pub fn sni_bounds(bytes: &[u8]) -> Option<(usize, usize)> {
    let layout = locate_sni(bytes)?;
    Some((layout.name, layout.name_len))
}

const HELLO_RECORD_HEADER: usize = 5;
const HELLO_HANDSHAKE_HEADER: usize = 4;
const HELLO_TLS_HANDSHAKE: u8 = 0x16;
const HELLO_HS_CLIENT_HELLO: u8 = 0x01;
const HELLO_EXT_SERVER_NAME: u16 = 0x0000;
const HELLO_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const HELLO_EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const HELLO_SNI_HOST_NAME: u8 = 0x00;
const HELLO_TLS13_VERSION: u16 = 0x0304;

/// Вид снятого ClientHello по контракту C-оракула `d2k_hello_shape`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloShape {
    /// Разбор не дошёл до обязательных полей или расширения оборваны без
    /// найденного признака TLS 1.3 — форма не измерена.
    Unknown,
    /// Разобранный ClientHello с `supported_versions`, содержащим 0x0304.
    Modern,
    /// Разобранный ClientHello без признака TLS 1.3.
    Legacy,
}

/// Результат поиска ECH-предложения по контракту `d2k_hello_ech_offer`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloEchOffer {
    /// Снимок неполон либо расширение ECH противоречит себе — C-оракул
    /// возвращает -1, и выводов о предложении делать нельзя.
    Incomplete,
    /// Предложения ECH нет.
    Absent,
    /// Предложение есть; `config_id` — идентификатор конфигурации.
    Present { config_id: u8 },
}

/// Разметка ClientHello, которую C-оракул `core/hello.c` ведёт по ходу
/// `parse_hello`: только координаты, байты не копируются.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct HelloLayout {
    /// Дошли до конца обязательных полей ClientHello.
    parsed: bool,
    /// Рукопожатие по его собственной длине целиком поместилось во вход.
    complete: bool,
    have_exts: bool,
    exts_len_off: usize,
    /// Объявленный блок расширений не поместился в пришедшие байты.
    exts_truncated: bool,
    have_tls13: bool,
    have_sni: bool,
    sni_name_off: usize,
    sni_name_len: usize,
}

fn hello_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let pair = bytes.get(offset..end)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

fn hello_u24(bytes: &[u8], offset: usize) -> Option<usize> {
    let end = offset.checked_add(3)?;
    let triple = bytes.get(offset..end)?;
    Some((usize::from(triple[0]) << 16) | (usize::from(triple[1]) << 8) | usize::from(triple[2]))
}

fn hello_skip_u8_vec(bytes: &[u8], end: usize, offset: usize) -> Option<usize> {
    let length = usize::from(*bytes.get(offset)?);
    let next = offset.checked_add(1)?.checked_add(length)?;
    (next <= end).then_some(next)
}

fn hello_skip_u16_vec(bytes: &[u8], end: usize, offset: usize) -> Option<usize> {
    let length = usize::from(hello_u16(bytes, offset)?);
    let next = offset.checked_add(2)?.checked_add(length)?;
    (next <= end).then_some(next)
}

/// Побайтный перенос `parse_hello` из `core/hello.c`: обход ВСЕХ расширений,
/// trailing-байты за рукопожатием разрешены, а признак TLS 1.3 ставится по
/// любому `supported_versions`, содержащему 0x0304.
fn parse_hello_layout(bytes: &[u8]) -> HelloLayout {
    let mut layout = HelloLayout::default();
    let available = bytes.len();
    if available < 3 || bytes[1] != 0x03 {
        return layout;
    }
    if available < HELLO_RECORD_HEADER || bytes[0] != HELLO_TLS_HANDSHAKE {
        return layout;
    }
    let Some(record_len) = hello_u16(bytes, 3).map(usize::from) else {
        return layout;
    };
    let claimed = HELLO_RECORD_HEADER + record_len;
    let end = claimed.min(available);

    let mut offset = HELLO_RECORD_HEADER;
    if offset + HELLO_HANDSHAKE_HEADER > end || bytes[offset] != HELLO_HS_CLIENT_HELLO {
        return layout;
    }
    let Some(handshake_len) = hello_u24(bytes, offset + 1) else {
        return layout;
    };
    offset += HELLO_HANDSHAKE_HEADER;
    if offset + handshake_len > claimed {
        return layout;
    }
    let mut handshake_end = offset + handshake_len;
    layout.complete = handshake_end <= available;
    if !layout.complete {
        handshake_end = available;
    }

    // client_version(2) + random(32)
    if offset + 34 > handshake_end {
        return layout;
    }
    offset += 34;

    let Some(next) = hello_skip_u8_vec(bytes, handshake_end, offset) else {
        return layout;
    };
    offset = next;
    let Some(next) = hello_skip_u16_vec(bytes, handshake_end, offset) else {
        return layout;
    };
    offset = next;
    let Some(next) = hello_skip_u8_vec(bytes, handshake_end, offset) else {
        return layout;
    };
    offset = next;

    // Обязательные поля кончились — ClientHello подтверждён и без расширений.
    layout.parsed = true;

    if offset + 2 > handshake_end {
        return layout;
    }
    let Some(extensions_len) = hello_u16(bytes, offset).map(usize::from) else {
        return layout;
    };
    layout.exts_len_off = offset;
    layout.have_exts = true;
    offset += 2;
    if offset + extensions_len > claimed {
        return layout;
    }
    let mut extensions_end = offset + extensions_len;
    if extensions_end > handshake_end {
        extensions_end = handshake_end;
        layout.exts_truncated = true;
    }

    let mut position = offset;
    while position + 4 <= extensions_end {
        let Some(extension_type) = hello_u16(bytes, position) else {
            break;
        };
        let Some(extension_len) = hello_u16(bytes, position + 2).map(usize::from) else {
            break;
        };
        let data = position + 4;
        if data + extension_len > extensions_end {
            break;
        }

        if extension_type == HELLO_EXT_SERVER_NAME && !layout.have_sni {
            let mut name_entry = data;
            if name_entry + 2 <= data + extension_len {
                let list_len = usize::from(hello_u16(bytes, name_entry).unwrap_or(0));
                name_entry += 2;
                let list_end = name_entry + list_len;
                if list_end <= data + extension_len {
                    while name_entry + 3 <= list_end {
                        let name_type = bytes[name_entry];
                        let name_len = usize::from(hello_u16(bytes, name_entry + 1).unwrap_or(0));
                        let name_off = name_entry + 3;
                        if name_off + name_len > list_end {
                            break;
                        }
                        if name_type == HELLO_SNI_HOST_NAME && name_len > 0 {
                            layout.have_sni = true;
                            layout.sni_name_off = name_off;
                            layout.sni_name_len = name_len;
                            break;
                        }
                        name_entry = name_off + name_len;
                    }
                }
            }
        } else if extension_type == HELLO_EXT_SUPPORTED_VERSIONS {
            if extension_len >= 1 {
                let list_len = usize::from(bytes[data]);
                if 1 + list_len <= extension_len {
                    let mut version = data + 1;
                    let versions_end = version + list_len;
                    while version + 2 <= versions_end {
                        if hello_u16(bytes, version) == Some(HELLO_TLS13_VERSION) {
                            layout.have_tls13 = true;
                        }
                        version += 2;
                    }
                }
            }
        }
        position = data + extension_len;
    }
    layout
}

/// Проверить, что снимок содержит ровно один полный ClientHello без хвоста.
/// Контракт `d2k_hello_complete`: точные длины записи и рукопожатия.
pub fn hello_complete(bytes: &[u8]) -> bool {
    if bytes.len() < HELLO_RECORD_HEADER + HELLO_HANDSHAKE_HEADER {
        return false;
    }
    let Some(record_len) = hello_u16(bytes, 3).map(usize::from) else {
        return false;
    };
    if HELLO_RECORD_HEADER + record_len != bytes.len() {
        return false;
    }
    let Some(handshake_len) = hello_u24(bytes, 6) else {
        return false;
    };
    if HELLO_RECORD_HEADER + HELLO_HANDSHAKE_HEADER + handshake_len != bytes.len() {
        return false;
    }
    let layout = parse_hello_layout(bytes);
    layout.parsed && layout.complete && !layout.exts_truncated
}

/// Вид ClientHello по контракту `d2k_hello_shape`: UNKNOWN при неразобранном
/// входе или оборванных расширениях без найденного признака TLS 1.3.
pub fn hello_shape(bytes: &[u8]) -> HelloShape {
    let layout = parse_hello_layout(bytes);
    if !layout.parsed {
        return HelloShape::Unknown;
    }
    if layout.exts_truncated && !layout.have_tls13 {
        return HelloShape::Unknown;
    }
    if layout.have_tls13 {
        HelloShape::Modern
    } else {
        HelloShape::Legacy
    }
}

/// Координаты имени SNI по контракту `d2k_hello_sni`: trailing-байты
/// разрешены, требуется разобранный ClientHello и непустое имя узла.
pub fn hello_sni_bounds(bytes: &[u8]) -> Option<(usize, usize)> {
    let layout = parse_hello_layout(bytes);
    (layout.parsed && layout.have_sni).then_some((layout.sni_name_off, layout.sni_name_len))
}

/// ECH-предложение по контракту `d2k_hello_ech_offer`. В отличие от
/// `d2k_tls_parse`, неполный снимок и противоречивое расширение дают
/// `Incomplete` (-1), а не «нет предложения».
pub fn hello_ech_offer(bytes: &[u8]) -> HelloEchOffer {
    if !hello_complete(bytes) {
        return HelloEchOffer::Incomplete;
    }
    let layout = parse_hello_layout(bytes);
    if !layout.have_exts {
        return HelloEchOffer::Absent;
    }
    let Some(extensions_len) = hello_u16(bytes, layout.exts_len_off).map(usize::from) else {
        return HelloEchOffer::Incomplete;
    };
    let mut position = layout.exts_len_off + 2;
    let end = position + extensions_len;
    let mut found = None;
    while position < end {
        if end - position < 4 {
            return HelloEchOffer::Incomplete;
        }
        let Some(extension_len) = hello_u16(bytes, position + 2).map(usize::from) else {
            return HelloEchOffer::Incomplete;
        };
        if extension_len > end - position - 4 {
            return HelloEchOffer::Incomplete;
        }
        if hello_u16(bytes, position) == Some(HELLO_EXT_ENCRYPTED_CLIENT_HELLO) {
            let data = position + 4;
            if found.is_some() || extension_len < 10 || bytes[data] != 0 {
                return HelloEchOffer::Incomplete;
            }
            let encoded_len = usize::from(hello_u16(bytes, data + 6).unwrap_or(0));
            if encoded_len > extension_len - 10 {
                return HelloEchOffer::Incomplete;
            }
            let payload_len = usize::from(hello_u16(bytes, data + 8 + encoded_len).unwrap_or(0));
            if payload_len == 0 || payload_len != extension_len - 10 - encoded_len {
                return HelloEchOffer::Incomplete;
            }
            found = Some(bytes[data + 5]);
        }
        position += 4 + extension_len;
    }
    match found {
        Some(config_id) => HelloEchOffer::Present { config_id },
        None => HelloEchOffer::Absent,
    }
}

/// Клонировать полный TLS ClientHello, заменив только значение SNI и обновив длины.
pub(crate) fn rename_sni(bytes: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || name.contains(&0) || bytes.len() > TEMPLATE_MAX {
        return None;
    }
    let layout = locate_sni_for_record(bytes)?;
    let new_len = bytes
        .len()
        .checked_sub(layout.name_len)?
        .checked_add(name.len())?;
    if new_len > TEMPLATE_MAX {
        return None;
    }

    let mut renamed = Vec::with_capacity(new_len);
    renamed.extend_from_slice(&bytes[..layout.name]);
    renamed.extend_from_slice(name);
    renamed.extend_from_slice(&bytes[layout.name + layout.name_len..]);

    let delta = name.len() as isize - layout.name_len as isize;
    for (offset, width) in [
        (layout.name_len_field, 2),
        (layout.list_len_field, 2),
        (layout.extension_len_field, 2),
        (layout.extensions_len_field, 2),
        (layout.handshake_len_field, 3),
        (layout.record_len_field, 2),
    ] {
        let current = match width {
            2 => u16_at(bytes, offset, bytes.len())?.0,
            3 => u24_at(bytes, offset, bytes.len())?.0,
            _ => return None,
        };
        let updated = current.checked_add_signed(delta)?;
        write_len(&mut renamed, offset, width, updated)?;
    }

    let renamed_layout = locate_sni_for_record(&renamed)?;
    (renamed.len() == new_len
        && renamed.get(renamed_layout.name..renamed_layout.name + renamed_layout.name_len)
            == Some(name))
    .then_some(renamed)
}

/// C `d2k_hello_rename` (`core/hello.c:500-535`): принять тело
/// ClientHello, обернуть его в TLS-запись, заменить SNI и вернуть тело.
pub fn r2o_hello_rename(client_hello: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    if client_hello.is_empty()
        || client_hello.len() > 0xffff
        || client_hello.len() + 5 > TEMPLATE_MAX
        || name.is_empty()
        || name.contains(&0)
    {
        return None;
    }
    let mut record = Vec::with_capacity(client_hello.len() + 5);
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
    record.extend_from_slice(client_hello);
    let renamed = rename_sni(&record, name)?;
    renamed.get(5..).map(|body| body.to_vec())
}

fn locate_sni_for_record(bytes: &[u8]) -> Option<SniLayout> {
    let (handshake_len, _) = u24_at(bytes, 6, bytes.len())?;
    let handshake_end = 9usize.checked_add(handshake_len)?;
    if handshake_end > bytes.len() {
        return None;
    }
    if handshake_end == bytes.len() {
        return locate_sni(bytes);
    }

    // D2O wraps trigger[5..] in a record whose length covers the entire
    // trigger body, while its ClientHello parser stops at the handshake length.
    // Parse the same handshake prefix and keep any following record bytes in
    // the clone.
    let mut handshake = bytes[..handshake_end].to_vec();
    write_len(&mut handshake, 3, 2, handshake_end.checked_sub(5)?)?;
    locate_sni(&handshake)
}

/// C `hex_nibble`: `0-9a-fA-F` → 0..15, иначе `None` (C -1).
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_profile(profile: &str) -> Option<Vec<u8>> {
    let mut hex = Vec::new();
    for line in profile.lines() {
        let source = line.split('#').next()?;
        hex.extend(source.bytes().filter(|byte| !byte.is_ascii_whitespace()));
    }
    if hex.len() % 2 != 0 || hex.len() / 2 > TEMPLATE_MAX {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.chunks(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn read_len(bytes: &[u8], offset: usize, width: usize) -> Option<usize> {
    match width {
        2 => Some(usize::from(u16::from_be_bytes([
            *bytes.get(offset)?,
            *bytes.get(offset + 1)?,
        ]))),
        3 => Some(
            (usize::from(*bytes.get(offset)?) << 16)
                | (usize::from(*bytes.get(offset + 1)?) << 8)
                | usize::from(*bytes.get(offset + 2)?),
        ),
        _ => None,
    }
}

/// C `wr24` (`core/hello.c:61-65`): младшие 24 бита big-endian.
fn wr24(bytes: &mut [u8], offset: usize, value: usize) {
    let value = value & 0x00ff_ffff;
    bytes[offset] = (value >> 16) as u8;
    bytes[offset + 1] = (value >> 8) as u8;
    bytes[offset + 2] = value as u8;
}

fn write_len(bytes: &mut [u8], offset: usize, width: usize, value: usize) -> Option<()> {
    match width {
        2 => {
            if value > u16::MAX as usize {
                return None;
            }
            bytes[offset] = (value >> 8) as u8;
            bytes[offset + 1] = value as u8;
        }
        3 => wr24(bytes, offset, value),
        _ => return None,
    }
    Some(())
}

fn client_hello_from_profile(sni: &str, profile: &str) -> Result<Vec<u8>, &'static str> {
    if sni.is_empty() || sni.as_bytes().contains(&0) || sni.len() > u16::MAX as usize {
        return Err("invalid SNI length or NUL byte");
    }
    let template = decode_profile(profile).ok_or("invalid embedded TLS profile")?;
    let layout = locate_sni(&template).ok_or("embedded TLS profile has no valid SNI")?;
    let new_len = template
        .len()
        .checked_sub(layout.name_len)
        .and_then(|base| base.checked_add(sni.len()))
        .filter(|length| *length <= TEMPLATE_MAX)
        .ok_or("ClientHello size out of range")?;
    let delta = sni.len() as isize - layout.name_len as isize;
    let mut hello = Vec::with_capacity(new_len);
    hello.extend_from_slice(&template[..layout.name]);
    hello.extend_from_slice(sni.as_bytes());
    hello.extend_from_slice(&template[layout.name + layout.name_len..]);

    for (offset, width) in [
        (layout.name_len_field, 2),
        (layout.list_len_field, 2),
        (layout.extension_len_field, 2),
        (layout.extensions_len_field, 2),
        (layout.handshake_len_field, 3),
        (layout.record_len_field, 2),
    ] {
        let old = read_len(&template, offset, width).ok_or("invalid profile length field")?;
        let updated = old
            .checked_add_signed(delta)
            .ok_or("updated TLS length out of range")?;
        write_len(&mut hello, offset, width, updated).ok_or("updated TLS length out of range")?;
    }
    if hello.len() != new_len || locate_sni(&hello).is_none() {
        return Err("generated ClientHello failed validation");
    }
    Ok(hello)
}

/// Собрать снятый ClientHello для пробы TLS 1.2, подставив `sni`.
pub fn legacy_client_hello(sni: &str) -> Result<Vec<u8>, &'static str> {
    client_hello_from_profile(sni, LEGACY_PROFILE)
}

/// Собрать снятый браузерный ClientHello TLS 1.3, подставив `sni`.
pub fn modern_client_hello(sni: &str) -> Result<Vec<u8>, &'static str> {
    client_hello_from_profile(sni, MODERN_PROFILE)
}

/// Собрать снятую TLS-приманку RX-лестницы с заданным именем SNI.
pub fn r2o_rx_fake_client_hello(sni: &str) -> Result<Vec<u8>, &'static str> {
    client_hello_from_profile(sni, R2O_RX_FAKE_PROFILE)
}

#[cfg(test)]
mod tests {
    use super::{
        HelloEchOffer, HelloShape, hello_complete, hello_ech_offer, hello_shape, hello_sni_bounds,
        legacy_client_hello, modern_client_hello,
    };

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut result = kind.to_be_bytes().to_vec();
        result.extend_from_slice(&(data.len() as u16).to_be_bytes());
        result.extend_from_slice(data);
        result
    }

    fn server_name(name: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(name.len() + 5);
        data.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        data.push(0);
        data.extend_from_slice(&(name.len() as u16).to_be_bytes());
        data.extend_from_slice(name);
        extension(0, &data)
    }

    fn supported_versions(versions: &[u16]) -> Vec<u8> {
        let mut values = Vec::with_capacity(versions.len() * 2);
        for version in versions {
            values.extend_from_slice(&version.to_be_bytes());
        }
        let mut data = vec![values.len() as u8];
        data.extend_from_slice(&values);
        extension(0x2b, &data)
    }

    fn key_share() -> Vec<u8> {
        let mut share = 29u16.to_be_bytes().to_vec();
        share.extend_from_slice(&32u16.to_be_bytes());
        share.extend_from_slice(&[0x11; 32]);
        let mut data = (share.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&share);
        extension(0x33, &data)
    }

    fn ech(config_id: u8, payload: &[u8]) -> Vec<u8> {
        // Раскладка тела из core/hello.c: b[0]=0, config_id на +5,
        // enc_len на +6, payload_len на +8+enc_len.
        let mut body = vec![0x00, 0x13, 0x01, 0x00, 0x01, config_id];
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        body.extend_from_slice(payload);
        extension(0xfe0d, &body)
    }

    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x22; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn shape_distinguishes_modern_and_legacy_profiles() {
        let modern = modern_client_hello("shape.example").unwrap();
        assert_eq!(hello_shape(&modern), HelloShape::Modern);
        assert!(hello_complete(&modern));
        let (offset, length) = hello_sni_bounds(&modern).unwrap();
        assert_eq!(&modern[offset..offset + length], b"shape.example");

        let legacy = legacy_client_hello("shape.example").unwrap();
        assert_eq!(hello_shape(&legacy), HelloShape::Legacy);
        assert!(hello_complete(&legacy));
    }

    #[test]
    fn duplicate_supported_versions_are_modern_for_shape() {
        let bytes = client_hello(
            &[
                server_name(b"example.com").as_slice(),
                supported_versions(&[0x0303]).as_slice(),
                supported_versions(&[0x0304]).as_slice(),
                key_share().as_slice(),
            ]
            .concat(),
        );
        assert_eq!(hello_shape(&bytes), HelloShape::Modern);
    }

    #[test]
    fn trailing_bytes_keep_shape_and_sni_but_not_complete() {
        let mut bytes = client_hello(
            &[
                server_name(b"trailing.example").as_slice(),
                supported_versions(&[0x0304]).as_slice(),
            ]
            .concat(),
        );
        bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let (offset, length) = hello_sni_bounds(&bytes).unwrap();
        assert_eq!(&bytes[offset..offset + length], b"trailing.example");
        assert_eq!(hello_shape(&bytes), HelloShape::Modern);
        assert!(!hello_complete(&bytes));
    }

    #[test]
    fn truncated_extensions_without_tls13_are_unknown() {
        let bytes = client_hello(
            &[
                server_name(b"truncated.example").as_slice(),
                key_share().as_slice(),
            ]
            .concat(),
        );
        let cut = bytes.len() - 8;
        assert_eq!(hello_shape(&bytes[..cut]), HelloShape::Unknown);
    }

    #[test]
    fn truncated_extensions_with_found_tls13_stay_modern() {
        let bytes = client_hello(
            &[
                server_name(b"truncated.example").as_slice(),
                supported_versions(&[0x0304]).as_slice(),
                key_share().as_slice(),
            ]
            .concat(),
        );
        let cut = bytes.len() - 8;
        assert_eq!(hello_shape(&bytes[..cut]), HelloShape::Modern);
    }

    #[test]
    fn ech_offer_follows_outer_body_layout() {
        let bytes = client_hello(
            &[
                server_name(b"ech.example").as_slice(),
                supported_versions(&[0x0304]).as_slice(),
                ech(0x2a, b"\xaa\xbb").as_slice(),
            ]
            .concat(),
        );
        assert_eq!(
            hello_ech_offer(&bytes),
            HelloEchOffer::Present { config_id: 0x2a }
        );

        let empty = client_hello(
            &[
                server_name(b"ech.example").as_slice(),
                supported_versions(&[0x0304]).as_slice(),
                ech(0x2a, b"").as_slice(),
            ]
            .concat(),
        );
        assert_eq!(hello_ech_offer(&empty), HelloEchOffer::Incomplete);

        let duplicate = client_hello(
            &[
                server_name(b"ech.example").as_slice(),
                supported_versions(&[0x0304]).as_slice(),
                ech(0x2a, b"\xaa").as_slice(),
                ech(0x2b, b"\xbb").as_slice(),
            ]
            .concat(),
        );
        assert_eq!(hello_ech_offer(&duplicate), HelloEchOffer::Incomplete);
    }

    #[test]
    fn hex_nibble_matches_c() {
        use super::hex_nibble;
        assert_eq!(hex_nibble(b'0'), Some(0));
        assert_eq!(hex_nibble(b'9'), Some(9));
        assert_eq!(hex_nibble(b'a'), Some(10));
        assert_eq!(hex_nibble(b'F'), Some(15));
        assert_eq!(hex_nibble(b'g'), None);
        assert_eq!(hex_nibble(0), None);
        assert_eq!(hex_nibble(b' '), None);
    }

    #[test]
    fn wr24_writes_lower_24_bits_like_c() {
        use super::wr24;
        let mut bytes = [0u8; 3];
        wr24(&mut bytes, 0, 0x12_34_56);
        assert_eq!(bytes, [0x12, 0x34, 0x56]);
        // C пишет младшие 24 бита без отказа.
        wr24(&mut bytes, 0, 0x112_34_56);
        assert_eq!(bytes, [0x12, 0x34, 0x56]);
    }
}
