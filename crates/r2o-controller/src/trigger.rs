const TRIGGER_MAX: usize = 16_384;

/// Удалить всё расширение server_name из существующего профиля. Временное
/// имя используется только для выбора профиля и никогда не покидает сборщик.
pub(crate) fn tls_profile_without_sni(tls12: bool) -> Result<Vec<u8>, &'static str> {
    let profile = if tls12 {
        crate::hello::legacy_client_hello("r2o.invalid")?
    } else {
        crate::hello::modern_client_hello("r2o.invalid")?
    };
    let handshake = r2k_core::quic::r2k_quic_client_hello_rename_sni(&profile[5..], None)
        .ok_or("не удалось удалить SNI из профиля TLS")?;
    let length = u16::try_from(handshake.len()).map_err(|_| "профиль TLS слишком длинный")?;
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.extend_from_slice(&profile[..3]);
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok(record)
}

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

    #[test]
    fn адресные_tls_профили_сохраняют_версию_и_не_содержат_sni() {
        for tls12 in [false, true] {
            let trigger = Trigger::tls_without_sni(tls12).unwrap();
            let parsed = r2k_core::tls::parse(&trigger.payload);
            assert!(crate::hello::hello_complete(&trigger.payload));
            assert!(parsed.is_client_hello);
            assert_eq!(parsed.is_tls13, !tls12);
            assert!(parsed.sni_range.is_none());
            assert_eq!(trigger.name, "tls:");
            assert_eq!(trigger.sni(), "");
            assert_eq!(trigger.accept, Accept::ServerHello);
            assert!(
                !trigger
                    .payload
                    .windows(11)
                    .any(|bytes| bytes == b"r2o.invalid")
            );
            assert_eq!(
                Trigger::tls_client_hello("", &trigger.payload)
                    .unwrap()
                    .payload,
                trigger.payload,
            );
            assert!(Trigger::tls_client_hello("example.test", &trigger.payload).is_err());
            assert!(Trigger::tls_client_hello("192.0.2.1", &trigger.payload).is_err());
        }
    }

    #[test]
    fn адресный_trigger_не_принимает_повреждённый_или_чужой_sni() {
        let named = Trigger::tls13("example.test").unwrap();
        assert!(Trigger::tls_client_hello("", &named.payload).is_err());
        assert!(Trigger::tls_client_hello("EXAMPLE.TEST", &named.payload).is_ok());
        let mut malformed = named.payload;
        let start = r2k_core::tls::parse(&malformed).sni_range.unwrap().start;
        malformed[start - 2..start].copy_from_slice(&0_u16.to_be_bytes());
        assert!(r2k_core::tls::parse(&malformed).sni_range.is_none());
        assert!(Trigger::tls_client_hello("", &malformed).is_err());
        let mut unnamed = Trigger::tls_without_sni(false).unwrap().payload;
        assert!(Trigger::tls_client_hello("", &unnamed[..unnamed.len() - 1]).is_err());
        unnamed.push(0);
        assert!(Trigger::tls_client_hello("", &unnamed).is_err());
    }
}
