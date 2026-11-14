//! Разбор и сопоставление зашифрованных DNS-сервисов D2O current main.
//!
//! Источник: `runtime/d2k_dns_config.c` (`d2k_dns_uri_parse`,
//! `d2k_dns_service_match`). Это чистые функции без сокетов и файлов,
//! поэтому они вынесены в `r2k-core`; чтение UCI/doqd/Keenetic и
//! планировщик подключаются на уровне контроллера.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const DNS_SERVICE_MAX: usize = 32;
pub const DNS_HOST_MAX: usize = 256;
pub const DNS_PATH_MAX: usize = 1024;
pub const DNS_BOOTSTRAP_MAX: usize = 256;
pub const DNS_SOURCE_MAX: usize = 32;

/// C `d2k_dns_service` (`runtime/d2k_dns_config.h`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsService {
    /// `doh`, `dot` или `doq`.
    pub protocol: String,
    pub host: String,
    /// Пусто, если host — IP-литерал.
    pub sni: String,
    pub path: String,
    pub bootstrap_dns: String,
    pub source: String,
    pub port: u16,
}

/// C `d2k_dns_uri_parse`: разобрать `https://`, `tls://` или `quic://`
/// без разрешения имени.
pub fn dns_uri_parse(uri: &str, source: Option<&str>) -> Option<DnsService> {
    let separator = uri.find("://")?;
    let scheme = &uri[..separator];
    let (protocol, default_port) = if scheme.eq_ignore_ascii_case("https") {
        ("doh", 443)
    } else if scheme.eq_ignore_ascii_case("tls") {
        ("dot", 853)
    } else if scheme.eq_ignore_ascii_case("quic") {
        ("doq", 853)
    } else {
        return None;
    };
    let authority = &uri[separator + 3..];
    let end = authority
        .find(['/', '?', '#'])
        .map_or(uri.len(), |offset| separator + 3 + offset);
    let authority = &uri[separator + 3..end];
    let host_start = authority.rfind('@').map_or(0, |at| at + 1);
    let authority = authority.get(host_start..)?;
    if authority.is_empty() {
        return None;
    }

    let (host, port_at) = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = rest.get(..close)?;
        let after = rest.get(close + 1..)?;
        let port_at = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':')?)
        };
        (host, port_at)
    } else {
        if authority.matches(':').count() > 1 {
            return None;
        }
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let host = safe_host(host)?;

    let port = match port_at {
        None => default_port,
        Some(text) => {
            // C `strtoul(..., 10)`: ведущие пробелы, необязательный знак,
            // затем цифры до конца authority; 0 и >65535 — отказ.
            let text = text.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
            let (negative, digits) = match text.as_bytes().first() {
                Some(b'+') => (false, &text[1..]),
                Some(b'-') => (true, &text[1..]),
                _ => (false, text),
            };
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let mut value: u64 = 0;
            for byte in digits.bytes() {
                value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
            }
            let value = if negative {
                value.wrapping_neg()
            } else {
                value
            };
            if value == 0 || value > u64::from(u16::MAX) {
                return None;
            }
            value as u16
        }
    };

    let sni = if host_is_ip(&host) {
        String::new()
    } else {
        host.clone()
    };
    let path = if protocol == "doh" {
        doh_path(uri, end)?
    } else {
        "/".to_owned()
    };
    Some(DnsService {
        protocol: protocol.to_owned(),
        host,
        sni,
        path,
        bootstrap_dns: String::new(),
        source: source.map(truncate_source).unwrap_or_default(),
        port,
    })
}

/// C `safe_host`: только ASCII alnum, `.`, `-`, `:`, `%`; нижний регистр;
/// длина меньше `DNS_HOST_MAX`.
fn safe_host(input: &str) -> Option<String> {
    if input.is_empty() || input.len() >= DNS_HOST_MAX {
        return None;
    }
    let mut host = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'%') {
            host.push(byte.to_ascii_lowercase() as char);
        } else {
            return None;
        }
    }
    Some(host)
}

/// C `host_is_ip`: IPv4 или IPv6 literal; зона IPv6 (`%...`) отбрасывается.
fn host_is_ip(host: &str) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    let without_zone = host.split('%').next().unwrap_or(host);
    without_zone.parse::<Ipv6Addr>().is_ok()
}

/// C `d2k_dns_uri_parse`, ветка DoH: target до `#`, `?` → `/?...`,
/// запрещены байты `<= 32`, `\`, `"`, длина >= `DNS_PATH_MAX`.
fn doh_path(uri: &str, end: usize) -> Option<String> {
    let target = uri.get(end..)?;
    let target_end = target.find('#').unwrap_or(target.len());
    let target = target.get(..target_end)?;
    if target.is_empty() {
        return Some("/".to_owned());
    }
    if let Some(query) = target.strip_prefix('?') {
        if query.len() + 1 >= DNS_PATH_MAX {
            return None;
        }
        return Some(format!("/?{query}"));
    }
    if !target.starts_with('/') || target.len() >= DNS_PATH_MAX {
        return None;
    }
    if target
        .bytes()
        .any(|byte| byte <= b' ' || byte == b'\\' || byte == b'"')
    {
        return None;
    }
    Some(target.to_owned())
}

/// C `snprintf(source, D2K_SOURCE_MAX, ...)`: обрезать по байтам до 31.
fn truncate_source(source: &str) -> String {
    let mut bytes = source
        .as_bytes()
        .get(..DNS_SOURCE_MAX - 1)
        .map_or_else(|| source.as_bytes().to_vec(), |prefix| prefix.to_vec());
    while String::from_utf8(bytes.clone()).is_err() {
        bytes.pop();
    }
    String::from_utf8(bytes).unwrap_or_default()
}

/// C `d2k_dns_service_match`: первый подходящий endpoint.
///
/// `transport` — 6 (TCP: doh/dot) или 17 (UDP: doq). `name`/`ip` могут быть
/// пустыми; сравнение регистронезависимое.
pub fn dns_service_match<'a>(
    items: &'a [DnsService],
    name: Option<&str>,
    ip: Option<&str>,
    port: u16,
    transport: u8,
) -> Option<&'a DnsService> {
    if port == 0 || !matches!(transport, 6 | 17) {
        return None;
    }
    let name = name.filter(|value| !value.is_empty());
    let ip = ip.filter(|value| !value.is_empty());
    items.iter().find(|service| {
        let protocol_ok = if transport == 17 {
            service.protocol == "doq"
        } else {
            service.protocol == "doh" || service.protocol == "dot"
        };
        if !protocol_ok || service.port != port {
            return false;
        }
        let name_matches = name.is_some_and(|name| {
            (!service.sni.is_empty() && name.eq_ignore_ascii_case(&service.sni))
                || (!service.host.is_empty() && name.eq_ignore_ascii_case(&service.host))
        });
        let ip_matches =
            ip.is_some_and(|ip| !service.host.is_empty() && ip.eq_ignore_ascii_case(&service.host));
        name_matches || ip_matches
    })
}

#[cfg(test)]
mod tests {
    use super::{DnsService, dns_service_match, dns_uri_parse};

    fn service(protocol: &str, host: &str, sni: &str, port: u16) -> DnsService {
        DnsService {
            protocol: protocol.into(),
            host: host.into(),
            sni: sni.into(),
            path: "/".into(),
            bootstrap_dns: String::new(),
            source: "test".into(),
            port,
        }
    }

    #[test]
    fn dns_uri_parse_повторяет_донорские_схемы_и_порты() {
        let doh = dns_uri_parse("https://Dns.Example/Path?x=1#frag", Some("uci")).unwrap();
        assert_eq!(doh.protocol, "doh");
        assert_eq!(doh.host, "dns.example");
        assert_eq!(doh.sni, "dns.example");
        assert_eq!(doh.path, "/Path?x=1");
        assert_eq!(doh.port, 443);
        assert_eq!(doh.source, "uci");

        let dot = dns_uri_parse("TLS://1.1.1.1:8853", None).unwrap();
        assert_eq!(dot.protocol, "dot");
        assert_eq!(dot.host, "1.1.1.1");
        assert_eq!(dot.sni, "");
        assert_eq!(dot.path, "/");
        assert_eq!(dot.port, 8853);

        let doq = dns_uri_parse("quic://[2001:db8::1]", None).unwrap();
        assert_eq!(doq.protocol, "doq");
        assert_eq!(doq.host, "2001:db8::1");
        assert_eq!(doq.sni, "");
        assert_eq!(doq.port, 853);

        let scoped = dns_uri_parse("https://[fe80::1%25eth0]:8443", None).unwrap();
        assert_eq!(scoped.host, "fe80::1%25eth0");
        assert_eq!(scoped.sni, "");
        assert_eq!(scoped.path, "/");
    }

    #[test]
    fn dns_uri_parse_отвергает_донорские_негодные_формы() {
        for uri in [
            "",
            "http://dns.example",
            "https://",
            "https://:443",
            "https://dns.example:0",
            "https://dns.example:65536",
            "https://dns.example:abc",
            "https://dns.example/a b",
            "https://dns.example/a\\b",
            "https://dns.example/a\"b",
            "https://dns.example:1:2",
            "https://[2001:db8::1",
            "https://[2001:db8::1]x",
            "https://user@:443",
        ] {
            assert!(dns_uri_parse(uri, None).is_none(), "принят {uri}");
        }
    }

    #[test]
    fn dns_service_match_повторяет_донорский_порядок_и_транспорт() {
        let items = vec![
            service("dot", "dot.example", "dot.example", 853),
            service("doh", "doh.example", "doh.example", 443),
            service("doq", "doq.example", "doq.example", 853),
            service("doh", "1.1.1.1", "", 443),
        ];
        assert_eq!(
            dns_service_match(&items, Some("DOH.EXAMPLE"), None, 443, 6)
                .map(|item| item.host.as_str()),
            Some("doh.example")
        );
        assert_eq!(
            dns_service_match(&items, Some("DOQ.EXAMPLE"), None, 853, 17)
                .map(|item| item.host.as_str()),
            Some("doq.example")
        );
        assert!(
            dns_service_match(&items, Some("DOQ.EXAMPLE"), None, 853, 6).is_none(),
            "doq не матчится по TCP"
        );
        assert_eq!(
            dns_service_match(&items, None, Some("1.1.1.1"), 443, 6).map(|item| item.host.as_str()),
            Some("1.1.1.1")
        );
        assert!(dns_service_match(&items, None, None, 443, 6).is_none());
        assert!(dns_service_match(&items, Some("dot.example"), None, 0, 6).is_none());
        assert!(dns_service_match(&items, Some("dot.example"), None, 853, 1).is_none());
    }

    #[test]
    #[ignore]
    fn d2o_dns_config_trace() {
        let uris = [
            "https://dns.example/Path?x=1#frag",
            "TLS://1.1.1.1:8853",
            "quic://[2001:db8::1]",
            "https://[fe80::1%25eth0]:8443",
            "https://user@dns.example:8443/a",
            "https://dns.example?x=1",
            "https://dns.example#frag",
            "https://dns.example/",
            "https://dns.example:+443",
            "https://dns.example: 443",
            "https://dns.example:000443",
            "https://dns.example:-0",
            "https://dns.example/a b",
            "https://dns.example/a\\b",
            "https://dns.example/a\"b",
            "https://dns.example:0",
            "https://dns.example:65536",
            "https://dns.example:abc",
            "http://dns.example",
            "https://",
            "https://[2001:db8::1",
            "https://[2001:db8::1]x",
        ];
        for (index, uri) in uris.iter().enumerate() {
            match dns_uri_parse(uri, Some("SrC")) {
                None => println!("P{index} fail"),
                Some(parsed) => println!(
                    "P{index} ok {}|{}|{}|{}|{}|{}|{}",
                    parsed.protocol,
                    parsed.host,
                    parsed.sni,
                    parsed.path,
                    parsed.port,
                    parsed.source,
                    parsed.bootstrap_dns
                ),
            }
        }

        let items = vec![
            service("dot", "dot.example", "dot.example", 853),
            service("doh", "doh.example", "doh.example", 443),
            service("doq", "doq.example", "doq.example", 853),
            service("doh", "1.1.1.1", "", 443),
        ];
        let cases: [(&str, Option<&str>, Option<&str>, u16, u8); 9] = [
            ("M0", Some("DOH.EXAMPLE"), None, 443, 6),
            ("M1", Some("DOQ.EXAMPLE"), None, 853, 17),
            ("M2", Some("DOQ.EXAMPLE"), None, 853, 6),
            ("M3", None, Some("1.1.1.1"), 443, 6),
            ("M4", Some("dot.example"), None, 853, 6),
            ("M5", None, None, 443, 6),
            ("M6", Some("dot.example"), None, 0, 6),
            ("M7", Some("dot.example"), None, 853, 1),
            ("M8", Some("unknown"), None, 443, 6),
        ];
        for (name, query, ip, port, transport) in cases {
            match dns_service_match(&items, query, ip, port, transport) {
                None => println!("{name} none"),
                Some(found) => println!("{name} {}", found.host),
            }
        }
    }
}
