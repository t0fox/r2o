//! Профили ClientHello для первых проб, снятые с эталона на C.

const LEGACY_PROFILE: &str = include_str!("profiles/legacy.hex");
const MODERN_PROFILE: &str = include_str!("profiles/modern.hex");
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
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        bytes.push(((high << 4) | low) as u8);
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

fn write_len(bytes: &mut [u8], offset: usize, width: usize, value: usize) -> Option<()> {
    let max = if width == 2 {
        u16::MAX as usize
    } else {
        0x00ff_ffff
    };
    if value > max {
        return None;
    }
    for index in 0..width {
        bytes[offset + width - index - 1] = (value >> (index * 8)) as u8;
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
