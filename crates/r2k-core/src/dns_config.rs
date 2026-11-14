//! Разбор и сопоставление зашифрованных DNS-сервисов D2O current main.
//!
//! Источник: `runtime/d2k_dns_config.c` (`d2k_dns_uri_parse`,
//! `d2k_dns_service_match`). Это чистые функции без сокетов и файлов,
//! поэтому они вынесены в `r2k-core`; чтение UCI/doqd/Keenetic и
//! планировщик подключаются на уровне контроллера.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

/// C `dns_name_encode`: DNS-имя в последовательность length-prefixed labels.
/// Только ASCII alnum/'-', нижний регистр, метка 1..63, имя до 253.
pub fn dns_name_encode(name: &str) -> Option<Vec<u8>> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 253 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() + 2);
    let mut index = 0;
    while index < bytes.len() {
        let end = bytes[index..]
            .iter()
            .position(|byte| *byte == b'.')
            .map_or(bytes.len(), |offset| index + offset);
        let len = end - index;
        if len == 0 || len > 63 || out.len() + len + 1 >= 256 {
            return None;
        }
        out.push(len as u8);
        for byte in &bytes[index..end] {
            if !(byte.is_ascii_alphanumeric() || *byte == b'-') {
                return None;
            }
            out.push(byte.to_ascii_lowercase());
        }
        index = end + 1;
        if end == bytes.len() {
            break;
        }
    }
    out.push(0);
    Some(out)
}

/// C `dns_skip_name`: пропустить имя с compression pointer, не более 16
/// переходов; `offset` обновляется только при первом (не jumped) проходе.
pub fn dns_skip_name(packet: &[u8], offset: &mut usize) -> bool {
    let len = packet.len();
    let mut at = *offset;
    let mut jumps = 0;
    let mut jumped = false;
    while at < len {
        let n = packet[at];
        at += 1;
        if n == 0 {
            if !jumped {
                *offset = at;
            }
            return true;
        }
        if n & 0xc0 == 0xc0 {
            if at >= len {
                return false;
            }
            jumps += 1;
            if jumps > 16 {
                return false;
            }
            let target = (usize::from(n & 0x3f) << 8) | usize::from(packet[at]);
            at += 1;
            if target >= len {
                return false;
            }
            if !jumped {
                *offset = at;
                jumped = true;
            }
            at = target;
        } else {
            if n & 0xc0 != 0 || n > 63 || at + usize::from(n) > len {
                return false;
            }
            at += usize::from(n);
            if !jumped {
                *offset = at;
            }
        }
    }
    false
}

/// C `dns_response_address`: разобрать ответ DNS и вернуть первый A/AAAA
/// class IN для совпавшего вопроса.
pub fn dns_response_address(
    packet: &[u8],
    id: u16,
    qname: &[u8],
    qtype: u16,
) -> Option<std::net::IpAddr> {
    let len = packet.len();
    if len < 12
        || packet[0] != (id >> 8) as u8
        || packet[1] != (id & 0xff) as u8
        || packet[2] & 0x80 == 0
        || packet[2] & 0x78 != 0
        || packet[2] & 0x02 != 0
        || packet[3] & 0x0f != 0
        || (u16::from(packet[4]) << 8 | u16::from(packet[5])) != 1
    {
        return None;
    }
    let mut at = 12;
    if at + qname.len() + 4 > len
        || packet[at..at + qname.len()] != *qname
        || packet[at + qname.len()] != (qtype >> 8) as u8
        || packet[at + qname.len() + 1] != (qtype & 0xff) as u8
        || packet[at + qname.len() + 2] != 0
        || packet[at + qname.len() + 3] != 1
    {
        return None;
    }
    at += qname.len() + 4;
    let answers = (u16::from(packet[6]) << 8 | u16::from(packet[7])) as usize;
    if answers == 0 || answers > 128 {
        return None;
    }
    for _ in 0..answers {
        if !dns_skip_name(packet, &mut at) || at + 10 > len {
            return None;
        }
        let record_type = u16::from(packet[at]) << 8 | u16::from(packet[at + 1]);
        let class = u16::from(packet[at + 2]) << 8 | u16::from(packet[at + 3]);
        let rdlen = (u16::from(packet[at + 8]) << 8 | u16::from(packet[at + 9])) as usize;
        at += 10;
        if at + rdlen > len {
            return None;
        }
        if class == 1 && record_type == qtype {
            match (qtype, rdlen) {
                (1, 4) => {
                    let octets: [u8; 4] = packet[at..at + 4].try_into().ok()?;
                    return Some(std::net::IpAddr::V4(octets.into()));
                }
                (28, 16) => {
                    let octets: [u8; 16] = packet[at..at + 16].try_into().ok()?;
                    return Some(std::net::IpAddr::V6(octets.into()));
                }
                _ => {}
            }
        }
        at += rdlen;
    }
    None
}

/// C `dns_query_one`: UDP/53, один A или AAAA запрос, SO_RCVTIMEO 400 мс,
/// SO_MARK при mark != 0.
#[cfg(unix)]
pub fn dns_query_one(host: &str, server: &str, qtype: u16, mark: u32) -> Option<std::net::IpAddr> {
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    let qname = dns_name_encode(host)?;
    let server_ip: std::net::IpAddr = server.parse().ok()?;
    let peer = std::net::SocketAddr::new(server_ip, 53);
    let bind = if server_ip.is_ipv4() {
        std::net::SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        std::net::SocketAddr::from(([0u16; 8], 0))
    };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    if mark != 0 {
        #[cfg(target_os = "linux")]
        {
            const SOL_SOCKET: std::os::raw::c_int = 1;
            const SO_MARK: std::os::raw::c_int = 36;
            unsafe extern "C" {
                fn setsockopt(
                    fd: std::os::raw::c_int,
                    level: std::os::raw::c_int,
                    option: std::os::raw::c_int,
                    value: *const std::os::raw::c_void,
                    length: u32,
                ) -> std::os::raw::c_int;
            }
            let result = unsafe {
                setsockopt(
                    socket.as_raw_fd(),
                    SOL_SOCKET,
                    SO_MARK,
                    (&mark as *const u32).cast(),
                    std::mem::size_of_val(&mark) as u32,
                )
            };
            if result != 0 {
                return None;
            }
        }
        #[cfg(not(target_os = "linux"))]
        return None;
    }
    socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .ok()?;
    socket.connect(peer).ok()?;
    let id = (std::process::id() as u16)
        ^ (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs() as u16)
        ^ (&qname as *const _ as usize as u16);
    let mut packet = vec![0_u8; 12 + qname.len() + 4];
    packet[0] = (id >> 8) as u8;
    packet[1] = (id & 0xff) as u8;
    packet[2] = 1;
    packet[5] = 1;
    packet[12..12 + qname.len()].copy_from_slice(&qname);
    let mut at = 12 + qname.len();
    packet[at] = (qtype >> 8) as u8;
    packet[at + 1] = (qtype & 0xff) as u8;
    packet[at + 2] = 0;
    packet[at + 3] = 1;
    at += 4;
    socket.send(&packet[..at]).ok()?;
    let mut response = [0_u8; 1024];
    let got = socket.recv(&mut response).ok()?;
    dns_response_address(&response[..got], id, &qname, qtype)
}

/// C `d2k_dns_resolve_bootstrap`: IP literal возвращается как есть; иначе до
/// двух серверов из списка, A затем AAAA. Ошибка/таймаут — None.
#[cfg(unix)]
pub fn dns_resolve_bootstrap(host: &str, servers: &str, mark: u32) -> Option<std::net::IpAddr> {
    if host.is_empty() || servers.is_empty() {
        return None;
    }
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        return Some(address);
    }
    if servers.len() >= DNS_BOOTSTRAP_MAX {
        return None;
    }
    for server in servers.split(',').take(2) {
        let server = server.trim_matches([' ', '\t', '\r']);
        if server.is_empty() {
            continue;
        }
        if let Some(address) = dns_query_one(host, server, 1, mark) {
            return Some(address);
        }
        if let Some(address) = dns_query_one(host, server, 28, mark) {
            return Some(address);
        }
    }
    None
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

/// C `skip_space`: пробелы и табы.
fn skip_space(text: &str) -> &str {
    text.trim_start_matches([' ', '\t'])
}

/// C `config_line`: `config TYPE 'NAME'` (имя может быть пустым).
fn config_line(line: &str) -> Option<(String, String)> {
    let rest = skip_space(line);
    if !rest.starts_with("config") {
        return None;
    }
    if !matches!(rest.as_bytes().get(6), Some(b' ' | b'\t')) {
        return None;
    }
    let rest = skip_space(&rest[6..]);
    let type_len = rest.find([' ', '\t', '\r', '\n']).unwrap_or(rest.len());
    if type_len == 0 || type_len >= 80 {
        return None;
    }
    let kind = &rest[..type_len];
    let rest = skip_space(&rest[type_len..]);
    let name = if matches!(rest.as_bytes().first(), Some(b'\'' | b'"')) {
        let quote = rest.as_bytes()[0] as char;
        let end = rest[1..].find(quote).map_or(rest.len(), |at| at + 1);
        rest[1..end].to_owned()
    } else {
        let end = rest
            .find([' ', '\t', '\r', '\n', '#'])
            .unwrap_or(rest.len());
        rest[..end].to_owned()
    };
    if name.len() >= 80 {
        return None;
    }
    Some((kind.to_owned(), name))
}

/// C `uci_value`: `verb key 'value'` с экранированием в кавычках.
fn uci_value(line: &str, verb: &str, key: &str) -> Option<String> {
    let mut rest = skip_space(line);
    if rest.is_empty() || rest.starts_with('#') {
        return None;
    }
    let verb_end = rest.find([' ', '\t', '\r', '\n']).unwrap_or(rest.len());
    if &rest[..verb_end] != verb {
        return None;
    }
    rest = skip_space(&rest[verb_end..]);
    let key_end = rest.find([' ', '\t', '\r', '\n']).unwrap_or(rest.len());
    if &rest[..key_end] != key {
        return None;
    }
    rest = skip_space(&rest[key_end..]);
    let mut value = String::new();
    if matches!(rest.as_bytes().first(), Some(b'\'' | b'"')) {
        let quote = rest.as_bytes()[0];
        let mut bytes = 1_usize;
        let mut chars = rest[1..].chars().peekable();
        let mut closed = false;
        while let Some(ch) = chars.next() {
            if ch.is_ascii() && ch as u8 == quote {
                closed = true;
                break;
            }
            if ch == '\r' || ch == '\n' {
                return None;
            }
            if ch == '\\' {
                let escaped = chars.next()?;
                value.push(escaped);
                bytes += 1 + escaped.len_utf8();
                continue;
            }
            value.push(ch);
            bytes += ch.len_utf8();
            if bytes + 1 >= 1024 {
                return None;
            }
        }
        if !closed {
            return None;
        }
    } else {
        let end = rest
            .find([' ', '\t', '\r', '\n', '#'])
            .unwrap_or(rest.len());
        value.push_str(&rest[..end]);
        if value.len() + 1 >= 1024 {
            return None;
        }
    }
    (!value.is_empty()).then_some(value)
}

/// C `add`: разобрать URI, добавить bootstrap и схлопнуть дубликат.
fn add_service(items: &mut Vec<DnsService>, uri: &str, source: &str, bootstrap: Option<&str>) {
    if items.len() >= DNS_SERVICE_MAX {
        return;
    }
    let Some(mut candidate) = dns_uri_parse(uri, Some(source)) else {
        return;
    };
    if let Some(bootstrap) = bootstrap.filter(|value| value.len() < DNS_BOOTSTRAP_MAX) {
        candidate.bootstrap_dns = bootstrap.to_owned();
    }
    if let Some(existing) = items.iter_mut().find(|item| {
        item.protocol == candidate.protocol
            && item.host == candidate.host
            && item.port == candidate.port
            && item.sni == candidate.sni
            && item.path == candidate.path
    }) {
        if existing.bootstrap_dns.is_empty() && !candidate.bootstrap_dns.is_empty() {
            existing.bootstrap_dns = candidate.bootstrap_dns;
        }
        return;
    }
    items.push(candidate);
}

/// C `add_candidate`: без разбора URI, только непустые host/port и дедуп.
fn add_candidate(items: &mut Vec<DnsService>, candidate: DnsService) {
    if candidate.host.is_empty() || candidate.port == 0 {
        return;
    }
    if items.iter().any(|item| {
        item.protocol == candidate.protocol
            && item.host == candidate.host
            && item.port == candidate.port
            && item.sni == candidate.sni
            && item.path == candidate.path
    }) {
        return;
    }
    if items.len() < DNS_SERVICE_MAX {
        items.push(candidate);
    }
}

/// C `read_https`: `/etc/config/https-dns-proxy`.
pub fn parse_https_dns_proxy(text: &str) -> Vec<DnsService> {
    let mut items = Vec::new();
    let mut in_section = false;
    let mut enabled = true;
    let mut urls: Vec<String> = Vec::new();
    let mut bootstrap = String::new();
    let flush = |items: &mut Vec<DnsService>,
                 urls: &[String],
                 bootstrap: &str,
                 in_section: bool,
                 enabled: bool| {
        if in_section && enabled {
            for url in urls {
                add_service(items, url, "https-dns-proxy", Some(bootstrap));
            }
        }
    };
    for line in text.lines() {
        if let Some((kind, _name)) = config_line(line) {
            flush(&mut items, &urls, &bootstrap, in_section, enabled);
            in_section = kind == "https-dns-proxy";
            enabled = true;
            urls.clear();
            bootstrap.clear();
        } else if in_section {
            if let Some(value) = uci_value(line, "option", "enabled") {
                enabled = value != "0";
            } else if let Some(value) = uci_value(line, "option", "bootstrap_dns") {
                if value.len() < DNS_BOOTSTRAP_MAX {
                    bootstrap = value;
                }
            } else if urls.len() < 8
                && let Some(value) = uci_value(line, "option", "resolver_url")
            {
                urls.push(value.chars().take(1023).collect());
            }
        }
    }
    flush(&mut items, &urls, &bootstrap, in_section, enabled);
    items
}

/// C `dnsproxy_bootstrap_add`: numeric IP или `IP:53`/`[IPv6]:53`, дедуп.
fn dnsproxy_bootstrap_add(out: &mut String, value: &str) {
    let host = if let Some(rest) = value.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return;
        };
        let after = &rest[close + 1..];
        if !after.is_empty() && after != ":53" {
            return;
        }
        &rest[..close]
    } else if let Some((host, port)) = value.rsplit_once(':') {
        if value.contains('.') && port == "53" {
            host
        } else {
            value
        }
    } else {
        value
    };
    if host.is_empty() || host.len() >= 64 || host.parse::<IpAddr>().is_err() {
        return;
    }
    if out.split(',').any(|known| known == host) {
        return;
    }
    if !out.is_empty() {
        out.push(',');
    }
    out.push_str(host);
}

/// C `read_dnsproxy`: `/etc/config/dnsproxy`.
pub fn parse_dnsproxy(text: &str) -> Vec<DnsService> {
    let mut items = Vec::new();
    let mut enabled = true;
    let mut global = false;
    for line in text.lines() {
        if let Some((kind, name)) = config_line(line) {
            global = kind == "dnsproxy" && name == "global";
        } else if global && let Some(value) = uci_value(line, "option", "enabled") {
            enabled = value != "0";
        }
    }
    if !enabled {
        return items;
    }
    let mut bootstrap = String::new();
    let mut servers = false;
    for line in text.lines() {
        if let Some((kind, name)) = config_line(line) {
            servers = kind == "dnsproxy" && name == "servers";
            continue;
        }
        if servers && let Some(value) = uci_value(line, "list", "bootstrap") {
            dnsproxy_bootstrap_add(&mut bootstrap, &value);
        }
    }
    for line in text.lines() {
        if let Some((kind, name)) = config_line(line) {
            servers = kind == "dnsproxy" && name == "servers";
            continue;
        }
        if servers && let Some(value) = uci_value(line, "list", "upstream") {
            add_service(&mut items, &value, "dnsproxy", Some(&bootstrap));
        }
    }
    items
}

/// C `read_doqd`: строки `upstream`/`fallback` + URI.
pub fn parse_doqd(text: &str, source: &str) -> Vec<DnsService> {
    let mut items = Vec::new();
    for line in text.lines() {
        let rest = skip_space(line);
        if !(rest.starts_with("upstream") || rest.starts_with("fallback")) {
            continue;
        }
        if !matches!(rest.as_bytes().get(8), Some(b' ' | b'\t')) {
            continue;
        }
        let rest = skip_space(&rest[8..]);
        let end = rest
            .find([' ', '\t', '\r', '\n', '#'])
            .unwrap_or(rest.len());
        let mut uri = &rest[..end];
        if matches!(uri.as_bytes().first(), Some(b'\'' | b'"')) {
            let quote = uri.as_bytes()[0] as char;
            if uri.len() < 2 || !uri.ends_with(quote) {
                continue;
            }
            uri = &uri[1..uri.len() - 1];
        }
        add_service(&mut items, uri, source, None);
    }
    items
}

/// C `port_value`: `strtoul`, 1..65535.
fn port_value(text: &str) -> u16 {
    let text = text.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return 0;
    }
    let mut value: u64 = 0;
    for byte in digits.bytes() {
        let Some(next) = value.checked_mul(10) else {
            return 0;
        };
        let Some(next) = next.checked_add(u64::from(byte - b'0')) else {
            return 0;
        };
        value = next;
    }
    if value == 0 || value > u64::from(u16::MAX) {
        0
    } else {
        value as u16
    }
}

/// C `read_keenetic`: вывод `ndmc -c "show dns-proxy"`.
pub fn parse_keenetic(status: &str) -> Vec<DnsService> {
    #[derive(Clone, Copy, PartialEq)]
    enum Section {
        None,
        Tls,
        Https,
    }
    let mut items = Vec::new();
    let mut section = Section::None;
    let mut server = Section::None;
    let mut current = DnsService::default();
    let flush = |items: &mut Vec<DnsService>, current: &mut DnsService| {
        add_candidate(items, std::mem::take(current));
    };
    for raw in status.lines() {
        let line = raw.trim_matches([' ', '\t', '\r']);
        match line {
            "proxy-tls:" => {
                flush(&mut items, &mut current);
                section = Section::Tls;
                server = Section::None;
            }
            "proxy-https:" => {
                flush(&mut items, &mut current);
                section = Section::Https;
                server = Section::None;
            }
            "proxy-tls-filters:" | "proxy-https-filters:" => {
                flush(&mut items, &mut current);
                section = Section::None;
                server = Section::None;
            }
            "server-tls:" if section == Section::Tls => {
                flush(&mut items, &mut current);
                current.protocol = "dot".into();
                current.port = 853;
                current.path = "/".into();
                current.source = "keenetic-system".into();
                server = Section::Tls;
            }
            "server-https:" if section == Section::Https => {
                flush(&mut items, &mut current);
                current.protocol = "doh".into();
                current.port = 443;
                current.path = "/".into();
                current.source = "keenetic-system".into();
                server = Section::Https;
            }
            _ => {
                if server == Section::None {
                    continue;
                }
                if server == Section::Tls {
                    if let Some(rest) = line.strip_prefix("address:") {
                        let value = rest.trim_start_matches([' ', '\t']);
                        let end = value.find([' ', '\t']).unwrap_or(value.len());
                        if let Some(host) = safe_host(&value[..end]) {
                            if !host_is_ip(&host) {
                                current.sni = host.clone();
                            }
                            current.host = host;
                        }
                    } else if let Some(rest) = line.strip_prefix("port:") {
                        let value = rest.trim_start_matches([' ', '\t']);
                        let end = value.find([' ', '\t']).unwrap_or(value.len());
                        let port = port_value(&value[..end]);
                        if port != 0 {
                            current.port = port;
                        }
                    } else if let Some(rest) = line.strip_prefix("sni:") {
                        let value = rest.trim_start_matches([' ', '\t']);
                        let end = value.find([' ', '\t']).unwrap_or(value.len());
                        if let Some(host) = safe_host(&value[..end]) {
                            current.sni = host;
                        }
                    }
                } else if server == Section::Https
                    && let Some(rest) = line.strip_prefix("uri:")
                {
                    let value = rest.trim_start_matches([' ', '\t']);
                    let uri = if matches!(value.as_bytes().first(), Some(b'\'' | b'"')) {
                        let quote = value.as_bytes()[0] as char;
                        let end = value[1..].find(quote).map_or(value.len(), |at| at + 1);
                        &value[1..end]
                    } else {
                        let end = value.find([' ', '\t', '\r']).unwrap_or(value.len());
                        &value[..end]
                    };
                    if let Some(parsed) = dns_uri_parse(uri, Some("keenetic-system")) {
                        current = parsed;
                    }
                }
            }
        }
    }
    flush(&mut items, &mut current);
    items
}

/// C `d2k_dns_services_read`: https → dnsproxy → doqd → Keenetic.
fn merge_service(items: &mut Vec<DnsService>, candidate: DnsService) {
    if let Some(existing) = items.iter_mut().find(|item| {
        item.protocol == candidate.protocol
            && item.host == candidate.host
            && item.port == candidate.port
            && item.sni == candidate.sni
            && item.path == candidate.path
    }) {
        if existing.bootstrap_dns.is_empty() && !candidate.bootstrap_dns.is_empty() {
            existing.bootstrap_dns = candidate.bootstrap_dns;
        }
        return;
    }
    if items.len() < DNS_SERVICE_MAX {
        items.push(candidate);
    }
}

/// C `d2k_dns_services_read`: https → dnsproxy → doqd → Keenetic.
pub fn read_dns_services(
    https_dns_proxy: Option<&str>,
    dnsproxy: Option<&str>,
    doqd: Option<&str>,
    doqd_source: &str,
    keenetic_status: Option<&str>,
) -> Vec<DnsService> {
    let mut items = Vec::new();
    if let Some(text) = https_dns_proxy {
        for service in parse_https_dns_proxy(text) {
            merge_service(&mut items, service);
        }
    }
    if let Some(text) = dnsproxy {
        for service in parse_dnsproxy(text) {
            merge_service(&mut items, service);
        }
    }
    if let Some(text) = doqd {
        let source = if doqd_source == "keenetic-doq-web" {
            "keenetic-doq-web"
        } else {
            "doqd"
        };
        for service in parse_doqd(text, source) {
            merge_service(&mut items, service);
        }
    }
    if let Some(text) = keenetic_status {
        for service in parse_keenetic(text) {
            merge_service(&mut items, service);
        }
    }
    items
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
    fn parse_https_dns_proxy_читает_uci_как_c() {
        let text = r#"
config https-dns-proxy 'a'
    option enabled '1'
    option bootstrap_dns '1.1.1.1,8.8.8.8'
    option resolver_url 'https://dns.example/dns-query'
    option resolver_url 'tls://dot.example'

config https-dns-proxy 'b'
    option enabled '0'
    option resolver_url 'https://disabled.example/dns-query'

config other 'x'
"#;
        let services = super::parse_https_dns_proxy(text);
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].protocol, "doh");
        assert_eq!(services[0].host, "dns.example");
        assert_eq!(services[0].path, "/dns-query");
        assert_eq!(services[0].bootstrap_dns, "1.1.1.1,8.8.8.8");
        assert_eq!(services[1].protocol, "dot");
        assert_eq!(services[1].host, "dot.example");
        assert_eq!(services[1].port, 853);
        assert_eq!(services[1].bootstrap_dns, "1.1.1.1,8.8.8.8");
    }

    #[test]
    fn parse_dnsproxy_читает_глобальный_флаг_bootstrap_и_upstream() {
        let text = r#"
config dnsproxy 'global'
    option enabled '1'

config dnsproxy 'servers'
    list bootstrap '1.1.1.1'
    list bootstrap '[2001:db8::1]:53'
    list bootstrap 'not-an-ip'
    list upstream 'https://dns.example/dns-query'
    list upstream 'tls://dot.example'

config dnsproxy 'global'
    option enabled '0'
"#;
        // Последний global enabled=0 отключает чтение целиком, как C.
        assert!(super::parse_dnsproxy(text).is_empty());

        let enabled = text.replace("option enabled '0'", "option enabled '1'");
        let services = super::parse_dnsproxy(&enabled);
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].bootstrap_dns, "1.1.1.1,2001:db8::1");
        assert_eq!(services[0].host, "dns.example");
        assert_eq!(services[1].host, "dot.example");
        assert_eq!(services[1].port, 853);
        assert_eq!(services[1].bootstrap_dns, "1.1.1.1,2001:db8::1");
    }

    #[test]
    fn parse_doqd_читает_upstream_и_fallback_с_кавычками() {
        let text = r#"
upstream https://dns.example/dns-query
fallback 'tls://dot.example'
upstream "quic://[2001:db8::1]"
# upstream https://ignored.example/
"#;
        let services = super::parse_doqd(text, "doqd");
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].protocol, "doh");
        assert_eq!(services[1].protocol, "dot");
        assert_eq!(services[2].protocol, "doq");
        assert_eq!(services[2].host, "2001:db8::1");
        assert_eq!(services[0].source, "doqd");
    }

    #[test]
    fn parse_keenetic_читает_tls_https_и_фильтры() {
        let status = r#"
proxy-tls:
server-tls:
  address: 1.1.1.1
  port: 853
  sni: dot.example
server-tls:
  address: 2001:db8::1
proxy-https:
server-https:
  address: 9.9.9.9
  uri: https://dns.example/dns-query
proxy-https-filters:
server-https:
  address: ignored.example
  uri: https://after-filter.example/dns-query
"#;
        let services = super::parse_keenetic(status);
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].protocol, "dot");
        assert_eq!(services[0].host, "1.1.1.1");
        assert_eq!(services[0].sni, "dot.example");
        assert_eq!(services[1].protocol, "dot");
        assert_eq!(services[1].host, "2001:db8::1");
        assert_eq!(services[2].protocol, "doh");
        assert_eq!(services[2].host, "dns.example");
        assert_eq!(services[2].path, "/dns-query");
        assert_eq!(services[2].source, "keenetic-system");
    }

    #[test]
    fn read_dns_services_объединяет_источники_и_сохраняет_bootstrap() {
        let https = r#"
config https-dns-proxy 'a'
    option bootstrap_dns '1.1.1.1'
    option resolver_url 'https://dns.example/dns-query'
"#;
        let doqd = "upstream https://dns.example/dns-query\n";
        let services = super::read_dns_services(Some(https), None, Some(doqd), "doqd", None);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].source, "https-dns-proxy");
        assert_eq!(services[0].bootstrap_dns, "1.1.1.1");
    }

    const HTTPS_FIXTURE: &str = r#"
config https-dns-proxy 'a'
    option enabled '1'
    option bootstrap_dns '1.1.1.1,8.8.8.8'
    option resolver_url 'https://dns.example/dns-query'
    option resolver_url 'tls://dot.example'

config https-dns-proxy 'b'
    option enabled '0'
    option resolver_url 'https://disabled.example/dns-query'

config other 'x'
"#;

    const DNSPROXY_FIXTURE: &str = r#"
config dnsproxy 'global'
    option enabled '1'

config dnsproxy 'servers'
    list bootstrap '1.1.1.1'
    list bootstrap '[2001:db8::1]:53'
    list bootstrap 'not-an-ip'
    list upstream 'https://dns.example/dns-query'
    list upstream 'tls://dot.example'
    list upstream 'https://dns.example/dns-query'
"#;

    const DOQD_FIXTURE: &str = r#"
upstream https://dns.example/dns-query
fallback 'tls://dot.example'
upstream "quic://[2001:db8::1]"
# upstream https://ignored.example/
"#;

    const KEENETIC_FIXTURE: &str = r#"
proxy-tls:
server-tls:
  address: 1.1.1.1
  port: 853
  sni: dot.example
server-tls:
  address: 2001:db8::1
proxy-https:
server-https:
  address: 9.9.9.9
  uri: https://keenetic.example/dns-query
proxy-https-filters:
server-https:
  address: ignored.example
  uri: https://after-filter.example/dns-query
"#;

    fn print_services(prefix: char, items: &[super::DnsService]) {
        for (index, service) in items.iter().enumerate() {
            println!(
                "{prefix}{index} {}|{}|{}|{}|{}|{}|{}",
                service.protocol,
                service.host,
                service.sni,
                service.path,
                service.bootstrap_dns,
                service.source,
                service.port
            );
        }
    }

    #[test]
    #[ignore]
    fn d2o_dns_config_readers_trace() {
        print_services('A', &super::parse_https_dns_proxy(HTTPS_FIXTURE));
        print_services('B', &super::parse_dnsproxy(DNSPROXY_FIXTURE));
        print_services('C', &super::parse_doqd(DOQD_FIXTURE, "doqd"));
        print_services('D', &super::parse_keenetic(KEENETIC_FIXTURE));
        print_services(
            'E',
            &super::read_dns_services(
                Some(HTTPS_FIXTURE),
                Some(DNSPROXY_FIXTURE),
                Some(DOQD_FIXTURE),
                "doqd",
                Some(KEENETIC_FIXTURE),
            ),
        );
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

    #[test]
    fn dns_name_encode_повторяет_донорские_метки() {
        assert_eq!(
            super::dns_name_encode("Example.COM").unwrap(),
            b"\x07example\x03com\x00"
        );
        assert_eq!(
            super::dns_name_encode("a-b.example").unwrap(),
            b"\x03a-b\x07example\x00"
        );
        for bad in ["", "a..b", ".a", "a_b", "a b", "a/b"] {
            assert!(super::dns_name_encode(bad).is_none(), "принят {bad:?}");
        }
        let long_label = "a".repeat(64);
        assert!(super::dns_name_encode(&long_label).is_none());
        let long_name = std::iter::repeat_n("abcdefghi", 29)
            .collect::<Vec<_>>()
            .join(".");
        assert!(super::dns_name_encode(&long_name).is_none());
    }

    fn a_response(id: u16, tc: bool, rcode: u8, class: u16) -> (Vec<u8>, Vec<u8>) {
        let qname = super::dns_name_encode("bootstrap.example").unwrap();
        let mut packet = Vec::new();
        packet.extend_from_slice(&id.to_be_bytes());
        packet.push(0x81);
        packet.push(0x80 | u8::from(tc) << 1 | rcode);
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&qname);
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&class.to_be_bytes());
        packet.extend_from_slice(&60_u32.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.extend_from_slice(&[203, 0, 113, 7]);
        (packet, qname)
    }

    #[test]
    fn dns_response_address_повторяет_донорские_проверки() {
        let (packet, qname) = a_response(0x1234, false, 0, 1);
        assert_eq!(
            super::dns_response_address(&packet, 0x1234, &qname, 1),
            Some(std::net::IpAddr::from([203, 0, 113, 7]))
        );
        assert!(super::dns_response_address(&packet, 0x1235, &qname, 1).is_none());
        assert!(super::dns_response_address(&packet, 0x1234, &qname, 28).is_none());
        let (truncated, _) = a_response(0x1234, true, 0, 1);
        assert!(super::dns_response_address(&truncated, 0x1234, &qname, 1).is_none());
        let (rcode, _) = a_response(0x1234, false, 3, 1);
        assert!(super::dns_response_address(&rcode, 0x1234, &qname, 1).is_none());
        let (wrong_class, _) = a_response(0x1234, false, 0, 3);
        assert!(super::dns_response_address(&wrong_class, 0x1234, &qname, 1).is_none());

        // AAAA-ответ.
        let mut aaaa = packet.clone();
        let qtype_at = 12 + qname.len();
        aaaa[qtype_at..qtype_at + 2].copy_from_slice(&28_u16.to_be_bytes());
        aaaa.truncate(qtype_at + 4);
        aaaa.extend_from_slice(&[0xc0, 0x0c]);
        aaaa.extend_from_slice(&28_u16.to_be_bytes());
        aaaa.extend_from_slice(&1_u16.to_be_bytes());
        aaaa.extend_from_slice(&60_u32.to_be_bytes());
        aaaa.extend_from_slice(&16_u16.to_be_bytes());
        let address = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        aaaa.extend_from_slice(&address);
        assert_eq!(
            super::dns_response_address(&aaaa, 0x1234, &qname, 28),
            Some(std::net::IpAddr::from(address))
        );
    }

    #[test]
    fn dns_skip_name_ограничивает_compression_прыжки() {
        let mut offset = 0;
        assert!(super::dns_skip_name(b"\x03one\x03two\x00tail", &mut offset));
        assert_eq!(offset, 9);
        // Указатель назад на терминатор; offset — после указателя.
        let mut offset = 0;
        assert!(super::dns_skip_name(b"\x03one\xc0\x06\x00", &mut offset));
        assert_eq!(offset, 6);
        // Петля: указатель на самого себя.
        let mut offset = 0;
        assert!(!super::dns_skip_name(b"\xc0\x00", &mut offset));
        // Указатель за пределы пакета.
        let mut offset = 0;
        assert!(!super::dns_skip_name(b"\xc0\xff", &mut offset));
    }

    #[test]
    fn dns_bootstrap_vectors_differential() {
        let names = [
            "Example.COM",
            "a-b.example",
            "",
            "a..b",
            ".a",
            "a_b",
            "a b",
            "abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ];
        let mut out = String::new();
        for name in names {
            let encoded = super::dns_name_encode(name);
            let hex = encoded
                .as_ref()
                .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
                .unwrap_or_default();
            out.push_str(&format!(
                "E|{name}|{}|{hex}\n",
                if encoded.is_some() { 1 } else { 0 }
            ));
        }
        let skips: [(&[u8], usize); 4] = [
            (b"\x03one\x03two\x00tail", 11),
            (b"\x03one\xc0\x06\x00", 7),
            (b"\xc0\x00", 2),
            (b"\xc0\xff", 2),
        ];
        for (case, (packet, len)) in skips.iter().enumerate() {
            let mut offset = 0;
            let ok = super::dns_skip_name(&packet[..*len], &mut offset);
            out.push_str(&format!("S|{case}|{}|{offset}\n", if ok { 1 } else { 0 }));
        }
        let (packet, qname) = a_response(0x1234, false, 0, 1);
        let cases: [(&str, u16, bool, u8, u16, bool); 6] = [
            ("a", 1, false, 0, 1, false),
            ("aaaa", 28, false, 0, 1, false),
            ("wrong_id", 1, false, 0, 1, true),
            ("tc", 1, true, 0, 1, false),
            ("rcode", 1, false, 3, 1, false),
            ("class3", 1, false, 0, 3, false),
        ];
        for (name, qtype, tc, rcode, class, wrong_id) in cases {
            let (mut response, qname_for_case) = a_response(0x1234, tc, rcode, class);
            let qtype_at = 12 + qname_for_case.len();
            response[qtype_at..qtype_at + 2].copy_from_slice(&qtype.to_be_bytes());
            response[qtype_at + 2..qtype_at + 4].copy_from_slice(&class.to_be_bytes());
            response.truncate(qtype_at + 4);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&qtype.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&60_u32.to_be_bytes());
            if qtype == 1 {
                response.extend_from_slice(&4_u16.to_be_bytes());
                response.extend_from_slice(&[203, 0, 113, 7]);
            } else {
                response.extend_from_slice(&16_u16.to_be_bytes());
                response.extend_from_slice(&[
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
                ]);
            }
            let id = if wrong_id { 0x1235 } else { 0x1234 };
            let parsed = super::dns_response_address(&response, id, &qname, qtype);
            out.push_str(&format!(
                "R|{name}|{}|{}\n",
                if parsed.is_some() { 1 } else { 0 },
                parsed.map(|ip| ip.to_string()).unwrap_or_default()
            ));
        }
        if let Ok(path) = std::env::var("R2O_DNS_BOOTSTRAP_VECTORS") {
            std::fs::write(path, out.clone()).unwrap();
        }
        assert!(out.contains("R|a|1|203.0.113.7\n"));
        assert!(out.contains("R|aaaa|1|2001:db8::7\n"));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "нужен bind UDP/53: запускать в unshare -Urn через differential"]
    fn dns_bootstrap_loopback() {
        use std::net::{IpAddr, UdpSocket};
        use std::time::Duration;

        let server = UdpSocket::bind(("127.0.0.1", 53)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        let thread = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut request = [0_u8; 1024];
                let Ok((got, peer)) = server.recv_from(&mut request) else {
                    break;
                };
                let qname = super::dns_name_encode("bootstrap.example").unwrap();
                let qtype_at = 12 + qname.len();
                let qtype = u16::from_be_bytes([request[qtype_at], request[qtype_at + 1]]);
                let mut response = Vec::new();
                response.extend_from_slice(&request[..2]);
                response.extend_from_slice(&[0x81, 0x80]);
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&0_u16.to_be_bytes());
                response.extend_from_slice(&0_u16.to_be_bytes());
                response.extend_from_slice(&request[12..qtype_at + 4]);
                response.extend_from_slice(&[0xc0, 0x0c]);
                response.extend_from_slice(&qtype.to_be_bytes());
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&60_u32.to_be_bytes());
                if qtype == 1 {
                    response.extend_from_slice(&4_u16.to_be_bytes());
                    response.extend_from_slice(&[203, 0, 113, 7]);
                } else {
                    response.extend_from_slice(&16_u16.to_be_bytes());
                    response.extend_from_slice(&[
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
                    ]);
                }
                let _ = server.send_to(&response, peer);
                let _ = got;
            }
        });
        let resolved = super::dns_resolve_bootstrap("bootstrap.example", "127.0.0.1", 0);
        assert_eq!(resolved, Some(IpAddr::from([203, 0, 113, 7])));
        thread.join().unwrap();
        let literal = super::dns_resolve_bootstrap("203.0.113.9", "127.0.0.1", 0);
        assert_eq!(literal, Some(IpAddr::from([203, 0, 113, 9])));
        let bad = super::dns_resolve_bootstrap("bootstrap.example", "not-an-ip", 0);
        assert!(bad.is_none());
        if let Ok(path) = std::env::var("R2O_DNS_BOOTSTRAP_LOOPBACK") {
            let text = format!(
                "a {} {}\nliteral {} {}\nbad {} {}\n",
                u8::from(resolved.is_some()),
                resolved.map(|ip| ip.to_string()).unwrap_or_default(),
                u8::from(literal.is_some()),
                literal.map(|ip| ip.to_string()).unwrap_or_default(),
                u8::from(bad.is_some()),
                bad.map(|ip| ip.to_string()).unwrap_or_default(),
            );
            std::fs::write(path, text).unwrap();
        }
    }
}
