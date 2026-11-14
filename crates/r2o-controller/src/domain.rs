//! Проверка доменных имён и группировка с учётом публичных суффиксов.

use std::sync::LazyLock;

/// Отсортированный снимок PSL из D2O `core/profiles/psl_index.h`.
/// Файл сгенерирован из того же блоба, что использует C `rule_exists`.
static PSL_RULES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("../data/psl_rules.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
});

fn rule_exists(rule: &str) -> bool {
    PSL_RULES.binary_search(&rule).is_ok()
}

/// Нормализовать имя DNS в ASCII по тем же строгим правилам, что и r2o.
///
/// Принимается одна точка в конце. IP-литералы, не-ASCII символы, пустые
/// части и неверное положение дефисов отклоняются: их нельзя безопасно
/// использовать для группировки регистрируемых доменов.
pub fn normalize(name: &str) -> Result<String, &'static str> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return Err("domain name length is invalid");
    }

    let mut label_len = 0;
    let mut has_non_digit = false;
    let mut previous = None;
    let mut normalized = String::with_capacity(name.len());

    for byte in name.bytes() {
        let byte = byte.to_ascii_lowercase();
        match byte {
            b'.' => {
                if label_len == 0 || previous == Some(b'-') {
                    return Err("domain name contains an invalid label");
                }
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
    // C `d2k_domain_normalize` принимает односоставное нечисловое имя
    // (`localhost`); ограничение на ≥2 метки относится только к base/member,
    // где нужен известный суффикс PSL.
    if !has_non_digit {
        return Err("numeric IP literals are not domain names");
    }
    Ok(normalized)
}

/// Вернуть регистрируемый домен по точному алгоритму C `d2k_domain_base`:
/// самое длинное правило побеждает, exception снимает один уровень,
/// wildcard `*.suffix` добавляет метку, неизвестный TLD — отказ.
pub fn registrable_domain(name: &str) -> Option<String> {
    let normalized = normalize(name).ok()?;
    let mut starts = Vec::with_capacity(16);
    starts.push(0);
    for (index, byte) in normalized.bytes().enumerate() {
        if byte == b'.' {
            starts.push(index + 1);
        }
    }
    let count = starts.len();
    let mut suffix_count = 0;
    let mut exception_count = 0;
    let mut pattern = String::with_capacity(normalized.len() + 2);
    for (index, &start) in starts.iter().enumerate() {
        let suffix = &normalized[start..];
        let labels = count - index;
        pattern.clear();
        pattern.push('!');
        pattern.push_str(suffix);
        if rule_exists(&pattern) && labels > exception_count {
            exception_count = labels;
        }
        if rule_exists(suffix) && labels > suffix_count {
            suffix_count = labels;
        }
        if index > 0 {
            pattern.clear();
            pattern.push_str("*.");
            pattern.push_str(suffix);
            if rule_exists(&pattern) && labels + 1 > suffix_count {
                suffix_count = labels + 1;
            }
        }
    }
    if exception_count != 0 {
        suffix_count = exception_count - 1;
    }
    if suffix_count == 0 || count <= suffix_count {
        return None;
    }
    let start = starts[count - suffix_count - 1];
    Some(normalized[start..].to_string())
}

/// Проверить, совпадает ли `name` с суффиксом или является его поддоменом.
/// C `SCHED_DECOY` (`core/sched.c:356`): имя-приманка D2K, не цель.
pub const SCHED_DECOY: &str = "disk.rzd.ru";

/// C `is_telegram_tunnel_domain` (`core/sched.c:8167-8178`): точное
/// `telegram.org` или поддомен с границей DNS-метки, без учёта регистра.
pub fn is_telegram_tunnel_domain(name: &str) -> bool {
    const DOMAIN: &[u8] = b"telegram.org";
    let bytes = name.as_bytes();
    if bytes.len() == DOMAIN.len() {
        return bytes.eq_ignore_ascii_case(DOMAIN);
    }
    if bytes.len() <= DOMAIN.len() || bytes[bytes.len() - DOMAIN.len() - 1] != b'.' {
        return false;
    }
    bytes[bytes.len() - DOMAIN.len()..].eq_ignore_ascii_case(DOMAIN)
}

/// C `!strcasecmp(name, SCHED_DECOY)` в `on_suspect`.
pub fn is_sched_decoy(name: &str) -> bool {
    name.eq_ignore_ascii_case(SCHED_DECOY)
}

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

#[cfg(test)]
mod tests {
    use super::{SCHED_DECOY, is_sched_decoy, is_telegram_tunnel_domain};

    #[test]
    fn telegram_tunnel_matches_dns_label_boundary_like_c() {
        for name in [
            "telegram.org",
            "TELEGRAM.ORG",
            "web.telegram.org",
            "a.b.Telegram.Org",
            ".telegram.org",
        ] {
            assert!(is_telegram_tunnel_domain(name), "{name}");
        }
        for name in [
            "",
            "telegram.or",
            "nottelegram.org",
            "xtelegram.org",
            "telegram.org.evil",
            "telegram.org.",
            "telegramxorg",
        ] {
            assert!(!is_telegram_tunnel_domain(name), "{name}");
        }
    }

    #[test]
    fn sched_decoy_matches_case_insensitively_like_c() {
        assert!(is_sched_decoy(SCHED_DECOY));
        assert!(is_sched_decoy("DISK.RZD.RU"));
        assert!(!is_sched_decoy("disk.rzd.ru."));
        assert!(!is_sched_decoy("ddos-guard.net"));
    }
}
