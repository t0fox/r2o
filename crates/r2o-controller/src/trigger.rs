const TRIGGER_MAX: usize = 16_384;

/// Parse the byte separators and size limits accepted by D2O `d2k_trigger_raw_hex`.
pub fn parse_raw_hex(hex: &str) -> Result<Vec<u8>, &'static str> {
    let mut payload = Vec::new();
    let mut high = None;
    for byte in hex.bytes() {
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b':' | b'-') {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err("classify: триггер не разобран как hex"),
        };
        if let Some(upper) = high.take() {
            if payload.len() >= TRIGGER_MAX {
                return Err("classify: триггер длиннее 16384 байт");
            }
            payload.push((upper << 4) | nibble);
        } else {
            high = Some(nibble);
        }
    }
    if high.is_some() {
        return Err("classify: триггер не разобран как hex");
    }
    if payload.len() < 2 {
        return Err("classify: триггер короче двух байт");
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::parse_raw_hex;
    use crate::classify::{Accept, Trigger};

    #[test]
    fn accepts_d2o_hex_separators_and_mixed_case() {
        assert_eq!(parse_raw_hex("57 41:06-03\n").unwrap(), b"WA\x06\x03");
    }

    #[test]
    fn rejects_odd_invalid_short_and_oversized_triggers() {
        assert!(parse_raw_hex("abc").is_err());
        assert!(parse_raw_hex("zz").is_err());
        assert!(parse_raw_hex("57").is_err());
        assert!(parse_raw_hex(&"00".repeat(16_385)).is_err());
    }

    #[test]
    fn raw_trigger_matches_d2o_name_and_acceptance() {
        let trigger = Trigger::raw_hex("57 41:06-03").unwrap();
        assert_eq!(trigger.name, "raw:4B");
        assert_eq!(trigger.payload, b"WA\x06\x03");
        assert_eq!(trigger.accept, Accept::Any);
    }
}
