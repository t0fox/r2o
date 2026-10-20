//! Проверка доменных имён и группировка с учётом публичных суффиксов.

/// Нормализовать имя DNS в ASCII по тем же строгим правилам, что и r2o.
///
/// Принимается одна точка в конце. IP-литералы, одночастные имена, не-ASCII
/// символы, пустые части и неверное положение дефисов отклоняются: их нельзя
/// безопасно использовать для группировки регистрируемых доменов.
pub fn normalize(name: &str) -> Result<String, &'static str> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return Err("domain name length is invalid");
    }

    let mut label_len = 0;
    let mut has_non_digit = false;
    let mut previous = None;
    let mut labels = 0;
    let mut normalized = String::with_capacity(name.len());

    for byte in name.bytes() {
        let byte = byte.to_ascii_lowercase();
        match byte {
            b'.' => {
                if label_len == 0 || previous == Some(b'-') {
                    return Err("domain name contains an invalid label");
                }
                labels += 1;
                label_len = 0;
                previous = Some(byte);
                normalized.push('.');
            }
            b'a'..=b'z' | b'0'..=b'9' | b'-' => {
                if label_len == 0 && byte == b'-' {
                    return Err("domain label starts with a hyphen");
                }
                label_len += 1;
                if label_len > 63 {
                    return Err("domain label exceeds 63 bytes");
                }
                has_non_digit |= !byte.is_ascii_digit();
                previous = Some(byte);
                normalized.push(char::from(byte));
            }
            _ => return Err("domain name must contain only ASCII DNS characters"),
        }
    }

    if label_len == 0 || previous == Some(b'-') {
        return Err("domain name contains an invalid final label");
    }
    labels += 1;
    if labels < 2 {
        return Err("single-label domain names are not supported");
    }
    if !has_non_digit {
        return Err("numeric IP literals are not domain names");
    }
    Ok(normalized)
}

/// Вернуть регистрируемый домен, если у имени известен публичный суффикс.
pub fn registrable_domain(name: &str) -> Option<String> {
    let normalized = normalize(name).ok()?;
    let suffix = psl::suffix(normalized.as_bytes())?;
    if !suffix.is_known() {
        return None;
    }
    let domain = psl::domain(normalized.as_bytes())?;
    // Функция `normalize` выше гарантирует, что `domain` содержит только ASCII.
    String::from_utf8(domain.as_bytes().to_vec()).ok()
}

/// Проверить, совпадает ли `name` с суффиксом или является его поддоменом.
pub fn is_member(name: &str, suffix: &str) -> bool {
    let (Ok(name), Ok(suffix)) = (normalize(name), normalize(suffix)) else {
        return false;
    };
    if registrable_domain(&suffix).is_none() {
        return false;
    }
    name == suffix
        || name
            .strip_suffix(&suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}
