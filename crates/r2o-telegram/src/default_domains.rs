//! Загружает из исходного репозитория и расшифровывает стандартный список
//! доменов Cloudflare proxy.
//!
//! Исходный репозиторий хранит обфусцированный список доменов CF proxy.
//! Для каждой записи используется простой шифр Цезаря: каждая буква префикса
//! домена сдвинута **вперёд** на `n` позиций, где `n` — число букв в префиксе;
//! окончание `.co.uk` заменено на `.com`. Расшифровка отменяет сдвиг и
//! восстанавливает исходное окончание.
//!
//! Эталонная реализация на Python:
//!   <https://github.com/Flowseal/tg-ws-proxy/blob/main/proxy/config.py#L36>

pub(crate) mod http;

use tracing::warn;

use crate::outbound::OutboundConnector;
use http::https_get;

const DOMAINS_URL_HOST: &str = "raw.githubusercontent.com";
const DOMAINS_URL_PATH: &str = "/Flowseal/tg-ws-proxy/refs/heads/main/.github/cfproxy-domains.txt";

/// Исходное доменное окончание, которому соответствует закодированное `.com`.
const REAL_SUFFIX: &str = ".co.uk";
pub(crate) const MIN_VALID_DOMAINS: usize = 3;

/// Встроенный запасной список (обфусцированный), используемый при сбое загрузки с GitHub.
///
/// Синхронизирован с константой `_CFPROXY_ENC` в эталонной реализации на Python.
static FALLBACK_ENCODED: &[&str] = &[
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
    "awzwsldi.com",
    "clngqrflngqin.com",
    "tjacxbqtj.com",
    "bxaxtxmrw.com",
    "dmohrsgmohcrwb.com",
    "vwbmtmoi.com",
    "khgrre.com",
    "ulihssf.com",
    "tmhqsdqmfpmk.com",
    "xwuwoqbm.com",
    "orgcnunpj.com",
    "zhkuldz.com",
    "zypoljnslxa.com",
    "efabnxaowuzs.com",
    "zaftuzsftqdq.com",
];

/// Расшифровать один закодированный домен.
///
/// Алгоритм повторяет `_dd()` из эталонной реализации на Python:
///  1. Требовать окончание `.com`; если его нет — вернуть `None`.
///  2. Посчитать буквы в префиксе и получить `n`.
///  3. Сдвинуть каждую букву **назад** на `n` позиций по модулю 26,
///     сохранив регистр; остальные символы оставить без изменений.
///  4. Заменить `.com` на `.co.uk`.
pub fn deobfuscate(s: &str) -> Option<String> {
    let prefix = s.strip_suffix(".com")?;
    let n = prefix.chars().filter(|c| c.is_ascii_alphabetic()).count() as i32;
    let decoded: String = prefix
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                let v = ((c as i32 - b'a' as i32) - n).rem_euclid(26) as u8 + b'a';
                v as char
            } else if c.is_ascii_uppercase() {
                let v = ((c as i32 - b'A' as i32) - n).rem_euclid(26) as u8 + b'A';
                v as char
            } else {
                c
            }
        })
        .collect();
    Some(format!("{}{}", decoded, REAL_SUFFIX))
}

/// Разобрать текстовый список доменов (по одному на строку; строки с `#` пропускаются).
/// Каждая строка расшифровывается перед добавлением в список.
fn parse_domain_list(text: &str) -> Vec<String> {
    let domains: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(deobfuscate)
        .collect();
    normalize_domain_pool(&domains)
}

pub(crate) fn normalize_domain_pool(domains: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    domains
        .iter()
        .map(|domain| domain.trim().to_ascii_lowercase())
        .filter(|domain| valid_domain(domain) && seen.insert(domain.clone()))
        .collect()
}

pub(crate) fn valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }) {
        return false;
    }
    labels
        .last()
        .is_some_and(|tld| tld.len() >= 2 && tld.chars().any(|c| c.is_ascii_alphabetic()))
}

pub(crate) fn fallback_domains() -> Vec<String> {
    FALLBACK_ENCODED
        .iter()
        .filter_map(|s| deobfuscate(s))
        .collect()
}

/// Загрузить стандартный список доменов CF proxy через прямое исходящее соединение.
///
/// Эта функция сохраняет исходный публичный интерфейс. Исполняемый файл прокси
/// использует [`fetch_default_domains_with_outbound`], чтобы учитывать настройки
/// исходящих соединений.
pub async fn fetch_default_domains() -> Vec<String> {
    let outbound = OutboundConnector::direct();
    fetch_default_domains_with_outbound(&outbound).await
}

/// Загрузить стандартный список доменов CF proxy через заданный исходящий
/// адаптер, расшифровать его и вернуть домены. При любой ошибке использовать
/// встроенный список.
pub async fn fetch_default_domains_with_outbound(outbound: &OutboundConnector) -> Vec<String> {
    match fetch_flowseal_domains_with_outbound(outbound).await {
        Ok(domains) => domains,
        Err(error) => {
            warn!(
                "не удалось обновить список доменов Cloudflare ({error}), используется встроенный список"
            );
            fallback_domains()
        }
    }
}

/// Получить и проверить текущий список Flowseal, не подменяя ошибку резервным набором.
pub(crate) async fn fetch_flowseal_domains_with_outbound(
    outbound: &OutboundConnector,
) -> Result<Vec<String>, String> {
    let body = https_get(DOMAINS_URL_HOST, DOMAINS_URL_PATH, outbound).await?;
    let domains = parse_domain_list(&body);
    if domains.len() < MIN_VALID_DOMAINS {
        return Err(format!(
            "список Flowseal содержит только {} корректных доменов; требуется не меньше {MIN_VALID_DOMAINS}",
            domains.len()
        ));
    }
    Ok(domains)
}

#[cfg(test)]
mod tests;
