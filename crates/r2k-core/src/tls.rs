use std::ops::Range;

const RECORD_HEADER: usize = 5;
const HANDSHAKE_HEADER: usize = 4;
const TLS_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const SERVER_HELLO_MIN_BODY: usize = 38;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const TLS_1_3: u16 = 0x0304;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const SNI_HOST_NAME: u8 = 0;

/// Сведения, которые datapath может безопасно получить из уже доступных байтов.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsInfo {
    pub is_tls_record: bool,
    pub record_type: u8,
    pub is_client_hello: bool,
    pub is_server_hello: bool,
    pub is_tls13: bool,
    pub ech_offer: bool,
    pub extensions_truncated: bool,
    pub sni_range: Option<Range<usize>>,
    pub record_end: Option<usize>,
    pub hello_middle: Option<usize>,
}

/// Разобрать записи TLS и заголовки рукопожатия, не доверяя объявленным длинам.
pub fn parse(bytes: &[u8]) -> TlsInfo {
    let mut info = TlsInfo::default();
    if bytes.len() < 3 || bytes[1] != 0x03 {
        return info;
    }

    info.is_tls_record = true;
    info.record_type = bytes[0];
    if bytes.len() < RECORD_HEADER {
        return info;
    }

    let Some(record_length) = read_u16(bytes, 3) else {
        return info;
    };
    let claimed_end = RECORD_HEADER + record_length;
    if claimed_end <= bytes.len() {
        info.record_end = Some(claimed_end);
    }
    if info.record_type != TLS_HANDSHAKE {
        return info;
    }

    let available_end = claimed_end.min(bytes.len());
    let mut offset = RECORD_HEADER;
    if offset + HANDSHAKE_HEADER > available_end {
        return info;
    }

    let handshake_type = bytes[offset];
    let Some(handshake_length) = read_u24(bytes, offset + 1) else {
        return info;
    };
    if handshake_type == HANDSHAKE_SERVER_HELLO {
        let Some(handshake_end) = offset
            .checked_add(HANDSHAKE_HEADER)
            .and_then(|start| start.checked_add(handshake_length))
        else {
            return info;
        };
        info.is_server_hello =
            handshake_length >= SERVER_HELLO_MIN_BODY && handshake_end <= claimed_end;
        return info;
    }
    if handshake_type != HANDSHAKE_CLIENT_HELLO {
        return info;
    }

    offset += HANDSHAKE_HEADER;
    let Some(mut hello_end) = offset.checked_add(handshake_length) else {
        return info;
    };
    if hello_end > claimed_end {
        return info;
    }
    if hello_end <= bytes.len() {
        info.hello_middle = Some(offset + handshake_length / 2);
    } else {
        hello_end = bytes.len();
    }
    info.is_client_hello = true;

    if offset.checked_add(34).is_none_or(|end| end > hello_end) {
        return info;
    }
    offset += 34;
    if !skip_u8_vector(bytes, hello_end, &mut offset)
        || !skip_u16_vector(bytes, hello_end, &mut offset)
        || !skip_u8_vector(bytes, hello_end, &mut offset)
    {
        return info;
    }

    if offset.checked_add(2).is_none_or(|end| end > hello_end) {
        return info;
    }
    let Some(extensions_length) = read_u16(bytes, offset) else {
        return info;
    };
    offset += 2;
    let Some(mut extensions_end) = offset.checked_add(extensions_length) else {
        return info;
    };
    if extensions_end > claimed_end {
        return info;
    }
    if extensions_end > hello_end {
        extensions_end = hello_end;
        info.extensions_truncated = true;
    }

    info.is_tls13 = has_tls13(bytes, offset, extensions_end, info.extensions_truncated);
    info.ech_offer = has_ech_offer(bytes, offset, extensions_end);
    info.sni_range = find_sni(bytes, offset, extensions_end);
    info
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<usize> {
    let end = offset.checked_add(2)?;
    let value = bytes.get(offset..end)?;
    Some(usize::from(u16::from_be_bytes([value[0], value[1]])))
}

fn read_u24(bytes: &[u8], offset: usize) -> Option<usize> {
    let end = offset.checked_add(3)?;
    let value = bytes.get(offset..end)?;
    Some((usize::from(value[0]) << 16) | (usize::from(value[1]) << 8) | usize::from(value[2]))
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

fn has_tls13(bytes: &[u8], mut offset: usize, end: usize, truncated: bool) -> bool {
    let mut key_share = false;
    while offset
        .checked_add(4)
        .is_some_and(|header_end| header_end <= end)
    {
        let Some(extension_type) = read_u16(bytes, offset).map(|value| value as u16) else {
            return false;
        };
        let Some(extension_length) = read_u16(bytes, offset + 2) else {
            return false;
        };
        offset += 4;
        if extension_type == EXT_KEY_SHARE {
            key_share = true;
        }
        let Some(extension_end) = offset.checked_add(extension_length) else {
            return false;
        };
        if extension_end > end {
            break;
        }
        if extension_type == EXT_SUPPORTED_VERSIONS {
            if extension_length < 1 {
                return false;
            }
            let Some(list_length) = bytes.get(offset).copied().map(usize::from) else {
                return false;
            };
            let Some(list_start) = offset.checked_add(1) else {
                return false;
            };
            let Some(list_end) = list_start.checked_add(list_length) else {
                return false;
            };
            if list_end > extension_end {
                return false;
            }
            let mut version_offset = list_start;
            while version_offset
                .checked_add(2)
                .is_some_and(|next| next <= list_end)
            {
                if read_u16(bytes, version_offset) == Some(usize::from(TLS_1_3)) {
                    return true;
                }
                version_offset += 2;
            }
            return false;
        }
        offset = extension_end;
    }
    truncated && key_share
}

fn has_ech_offer(bytes: &[u8], mut offset: usize, end: usize) -> bool {
    while offset
        .checked_add(4)
        .is_some_and(|header_end| header_end <= end)
    {
        let Some(extension_type) = read_u16(bytes, offset).map(|value| value as u16) else {
            return false;
        };
        let Some(extension_length) = read_u16(bytes, offset + 2) else {
            return false;
        };
        offset += 4;
        let Some(extension_end) = offset.checked_add(extension_length) else {
            return false;
        };
        if extension_end > end {
            return false;
        }
        if extension_type == EXT_ENCRYPTED_CLIENT_HELLO {
            if extension_length < 10 || bytes[offset] != 0 {
                return false;
            }
            let Some(encoded_length) = read_u16(bytes, offset + 6) else {
                return false;
            };
            if encoded_length > extension_length - 10 {
                return false;
            }
            let Some(payload_length_offset) = offset
                .checked_add(8)
                .and_then(|start| start.checked_add(encoded_length))
            else {
                return false;
            };
            let Some(payload_length) = read_u16(bytes, payload_length_offset) else {
                return false;
            };
            return payload_length > 0 && payload_length == extension_length - 10 - encoded_length;
        }
        offset = extension_end;
    }
    false
}

fn find_sni(bytes: &[u8], mut offset: usize, end: usize) -> Option<Range<usize>> {
    while offset
        .checked_add(4)
        .is_some_and(|header_end| header_end <= end)
    {
        let extension_type = read_u16(bytes, offset)? as u16;
        let extension_length = read_u16(bytes, offset + 2)?;
        offset += 4;
        let extension_end = offset.checked_add(extension_length)?;
        if extension_end > end {
            return None;
        }
        if extension_type == EXT_SERVER_NAME {
            if offset
                .checked_add(2)
                .is_none_or(|list_length_end| list_length_end > extension_end)
            {
                return None;
            }
            let list_length = read_u16(bytes, offset)?;
            let mut name_offset = offset.checked_add(2)?;
            let list_end = name_offset.checked_add(list_length)?;
            if list_end > extension_end {
                return None;
            }
            while name_offset
                .checked_add(3)
                .is_some_and(|next| next <= list_end)
            {
                let name_type = *bytes.get(name_offset)?;
                let name_length = read_u16(bytes, name_offset + 1)?;
                name_offset += 3;
                let name_end = name_offset.checked_add(name_length)?;
                if name_end > list_end {
                    return None;
                }
                if name_type == SNI_HOST_NAME {
                    return (name_length > 0).then_some(name_offset..name_end);
                }
                name_offset = name_end;
            }
            return None;
        }
        offset = extension_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{RECORD_HEADER, TlsInfo, parse};

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(4 + data.len());
        result.extend_from_slice(&kind.to_be_bytes());
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

    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = Vec::with_capacity(body.len() + 4);
        handshake.push(1);
        handshake.push(((body.len() >> 16) & 0xff) as u8);
        handshake.push(((body.len() >> 8) & 0xff) as u8);
        handshake.push((body.len() & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::with_capacity(handshake.len() + RECORD_HEADER);
        record.extend_from_slice(&[0x16, 0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_complete_tls13_client_hello_and_sni() {
        let name = b"example.test";
        let mut extensions = server_name(name);
        extensions.extend(extension(EXT_SUPPORTED_VERSIONS, &[2, 3, 4]));
        let packet = client_hello(&extensions);

        let parsed = parse(&packet);
        let name_offset = packet
            .windows(name.len())
            .position(|window| window == name)
            .unwrap();
        assert!(parsed.is_tls_record);
        assert_eq!(parsed.record_type, 0x16);
        assert!(parsed.is_client_hello);
        assert!(!parsed.is_server_hello);
        assert!(parsed.is_tls13);
        assert!(!parsed.extensions_truncated);
        assert_eq!(
            parsed.sni_range,
            Some(name_offset..name_offset + name.len())
        );
        assert_eq!(parsed.record_end, Some(packet.len()));
        assert!(parsed.hello_middle.is_some());
    }

    #[test]
    fn partial_key_share_keeps_sni_and_marks_tls13_form_unknown_or_present() {
        let name = b"router.example";
        let mut extensions = server_name(name);
        extensions.extend(extension(EXT_KEY_SHARE, &[0; 1200]));
        let packet = client_hello(&extensions);
        let key_share_header = packet
            .windows(4)
            .position(|window| window == [0, EXT_KEY_SHARE as u8, 0x04, 0xb0])
            .unwrap();
        let prefix = &packet[..key_share_header + 4 + 40];

        let parsed = parse(prefix);
        assert!(parsed.is_client_hello);
        assert!(parsed.extensions_truncated);
        assert!(parsed.is_tls13);
        assert!(parsed.sni_range.is_some());
        assert_eq!(parsed.record_end, None);
        assert_eq!(parsed.hello_middle, None);

        let complete = parse(&packet);
        assert!(
            !complete.is_tls13,
            "complete key_share alone is not TLS 1.3 proof"
        );
    }

    #[test]
    fn complete_supported_versions_overrides_key_share_heuristic() {
        let mut extensions = extension(EXT_KEY_SHARE, &[0, 0]);
        extensions.extend(extension(EXT_SUPPORTED_VERSIONS, &[2, 3, 3]));
        assert!(!parse(&client_hello(&extensions)).is_tls13);
    }

    #[test]
    fn rejects_inconsistent_sni_but_keeps_client_hello_classification() {
        let mut extensions = extension(EXT_SERVER_NAME, &[0, 10, 0, 0, 1]);
        extensions.extend(extension(EXT_SUPPORTED_VERSIONS, &[2, 3, 4]));
        let parsed = parse(&client_hello(&extensions));
        assert!(parsed.is_client_hello);
        assert!(parsed.sni_range.is_none());
        assert!(parsed.is_tls13);
    }

    #[test]
    fn rejects_sni_extension_without_its_list_length() {
        let mut extensions = extension(EXT_SERVER_NAME, &[]);
        extensions.extend(extension(EXT_SUPPORTED_VERSIONS, &[2, 3, 4]));

        let parsed = parse(&client_hello(&extensions));
        assert!(parsed.is_client_hello);
        assert!(parsed.sni_range.is_none());
        assert!(parsed.is_tls13);
    }

    #[test]
    fn recognizes_only_structurally_consistent_ech_offer() {
        let ech = extension(
            EXT_ENCRYPTED_CLIENT_HELLO,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xaa, 0xbb],
        );
        assert!(parse(&client_hello(&ech)).ech_offer);

        let bad_ech = extension(
            EXT_ENCRYPTED_CLIENT_HELLO,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0xaa, 0xbb],
        );
        assert!(!parse(&client_hello(&bad_ech)).ech_offer);
    }

    #[test]
    fn distinguishes_application_record_and_server_hello() {
        let application = [0x17, 0x03, 0x03, 0, 2, 0xaa, 0xbb];
        let parsed = parse(&application);
        assert!(parsed.is_tls_record);
        assert_eq!(parsed.record_end, Some(application.len()));
        assert!(!parsed.is_client_hello);
        assert!(!parsed.is_server_hello);

        let mut server_hello = vec![0x16, 0x03, 0x03, 0, 42, 2, 0, 0, 38];
        server_hello.extend([0; 38]);
        let parsed = parse(&server_hello);
        assert!(parsed.is_server_hello);
        assert!(!parsed.is_client_hello);

        let truncated_header = &server_hello[..9];
        assert!(parse(truncated_header).is_server_hello);
        let mut inconsistent = server_hello.clone();
        inconsistent[8] = 43;
        assert!(!parse(&inconsistent).is_server_hello);
    }

    #[test]
    fn arbitrary_prefixes_never_return_out_of_bounds_anchors() {
        let mut extensions = server_name(b"bounds.example");
        extensions.extend(extension(EXT_SUPPORTED_VERSIONS, &[2, 3, 4]));
        let packet = client_hello(&extensions);

        for end in 0..=packet.len() {
            let parsed = parse(&packet[..end]);
            check_invariants(&parsed, end);
        }

        let mut state = 0x1234_5678u32;
        for length in 0..512 {
            let mut bytes = vec![0; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            check_invariants(&parse(&bytes), bytes.len());
        }
    }

    fn check_invariants(parsed: &TlsInfo, input_len: usize) {
        assert!(!parsed.is_tls13 || parsed.is_client_hello);
        assert!(!parsed.extensions_truncated || parsed.is_client_hello);
        if let Some(range) = &parsed.sni_range {
            assert!(parsed.is_client_hello);
            assert!(range.start < range.end);
            assert!(range.end <= input_len);
        }
        if let Some(end) = parsed.record_end {
            assert!(end <= input_len);
        }
        if let Some(middle) = parsed.hello_middle {
            assert!(parsed.is_client_hello);
            assert!(middle <= input_len);
        }
    }

    const EXT_SERVER_NAME: u16 = 0x0000;
    const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
    const EXT_KEY_SHARE: u16 = 0x0033;
    const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
}
