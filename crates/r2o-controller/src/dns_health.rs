//! Проверки DNS-обмена для DoH, DoT, DoQ и DoH3.
//!
//! DNS-запрос — публичный `example.com A`, без имени клиента. DoT/DoQ
//! используют length-prefixed frame (RFC 7858/RFC 9250), DoQ — stream 0 и
//! нулевой ID, DoT — ID соединения. DoH — RFC 8484 POST на `path`.

use r2k_core::dns_config::DnsService;
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub const DOH_HEADER_MAX: usize = 8192;
pub const DOH_BODY_MAX: usize = 4096;
const DOH_RESPONSE_MAX: usize = DOH_HEADER_MAX + DOH_BODY_MAX * 2;
const DNS_PROBE_NAME: &str = "example.com";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DohQuery {
    Message(Vec<u8>),
    Json,
}

impl DohQuery {
    pub fn for_service(service: &DnsService) -> Self {
        if service.uses_doh_json() {
            Self::Json
        } else {
            Self::Message(dns_query_message(DNS_QUERY_ID_DOH))
        }
    }

    pub fn request_path<'a>(
        &self,
        path: &'a str,
    ) -> Result<std::borrow::Cow<'a, str>, &'static str> {
        let path = if path.is_empty() { "/" } else { path };
        if matches!(self, Self::Message(_)) {
            return Ok(path.into());
        }
        if !path.starts_with('/') || path.contains('#') {
            return Err("DoH JSON: неверный путь DNS-сервера");
        }
        let uri = path
            .parse::<http::uri::PathAndQuery>()
            .map_err(|_| "DoH JSON: неверный путь DNS-сервера")?;
        let parameters = uri.query().unwrap_or_default();
        if parameters.split('&').any(|part| {
            let key = part.split('=').next().unwrap_or_default();
            ["name", "type"]
                .iter()
                .any(|reserved| doh_parameter_matches(key, reserved))
        }) {
            return Err("DoH JSON: в URL уже заданы параметры DNS-запроса");
        }
        let separator = if uri.query().is_none() {
            "?"
        } else if path.ends_with(['?', '&']) {
            ""
        } else {
            "&"
        };
        Ok(format!("{path}{separator}name={DNS_PROBE_NAME}&type=1").into())
    }

    pub(crate) fn accepts_type(&self, value: &[u8]) -> bool {
        let media = trim_http_value(value.split(|byte| *byte == b';').next().unwrap_or_default());
        match self {
            Self::Message(_) => media.eq_ignore_ascii_case(b"application/dns-message"),
            Self::Json => {
                media.eq_ignore_ascii_case(b"application/dns-json")
                    || media.eq_ignore_ascii_case(b"application/json")
            }
        }
    }

    pub(crate) fn validate_reply(&self, body: &[u8]) -> bool {
        if body.len() > DOH_BODY_MAX {
            return false;
        }
        match self {
            Self::Message(query) => query
                .get(..2)
                .is_some_and(|id| dns_probe_reply(body, u16::from_be_bytes([id[0], id[1]]))),
            Self::Json => doh_json_reply(body),
        }
    }

    pub(crate) fn http1_request(&self, authority: &str, path: &str, connection: &str) -> Vec<u8> {
        match self {
            Self::Message(message) => {
                let mut request = format!(
                    "POST {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
                    message.len()
                ).into_bytes();
                request.extend_from_slice(message);
                request
            }
            Self::Json => format!(
                "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/dns-json\r\nConnection: {connection}\r\n\r\n"
            ).into_bytes(),
        }
    }
}

fn doh_parameter_matches(key: &str, name: &str) -> bool {
    let mut bytes = key.bytes();
    fn hex(byte: u8) -> Option<u8> {
        char::from(byte).to_digit(16).map(|value| value as u8)
    }
    name.bytes().all(|expected| {
        let actual = match bytes.next() {
            Some(b'%') => bytes
                .next()
                .and_then(hex)
                .zip(bytes.next().and_then(hex))
                .map(|(high, low)| high * 16 + low),
            value => value,
        };
        actual == Some(expected)
    }) && bytes.next().is_none()
}

fn doh_json_reply(body: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Question<'a> {
        name: &'a str,
        #[serde(rename = "type")]
        kind: u16,
    }
    #[derive(serde::Deserialize)]
    struct Answer<'a> {
        name: &'a str,
        #[serde(rename = "type")]
        kind: u16,
        data: &'a str,
    }
    #[derive(serde::Deserialize)]
    struct Response<'a> {
        #[serde(rename = "Status")]
        status: u32,
        #[serde(rename = "TC")]
        truncated: bool,
        #[serde(rename = "Question", borrow)]
        questions: Vec<Question<'a>>,
        #[serde(rename = "Answer", default, borrow)]
        answers: Vec<Answer<'a>>,
    }
    fn same_name(a: &str, b: &str) -> bool {
        a.strip_suffix('.')
            .unwrap_or(a)
            .eq_ignore_ascii_case(b.strip_suffix('.').unwrap_or(b))
    }
    fn valid_name(name: &str) -> bool {
        let name = name.strip_suffix('.').unwrap_or(name);
        name.len() <= 253
            && name.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
    }
    let Ok(response) = serde_json::from_slice::<Response<'_>>(body) else {
        return false;
    };
    if response.status != 0
        || response.truncated
        || !matches!(response.questions.as_slice(), [question] if question.kind == 1 && same_name(question.name, DNS_PROBE_NAME))
    {
        return false;
    }
    let mut name = DNS_PROBE_NAME;
    for _ in &response.answers {
        if response.answers.iter().any(|record| {
            record.kind == 1
                && same_name(record.name, name)
                && record.data.parse::<std::net::Ipv4Addr>().is_ok()
        }) {
            return true;
        }
        let Some(alias) = response.answers.iter().find(|record| {
            record.kind == 5 && same_name(record.name, name) && valid_name(record.data)
        }) else {
            return false;
        };
        name = alias.data;
    }
    false
}
const DNS_FRAME_MAX: usize = 4096;
/// C `dns_query[2..4]` для DoH: `0x5a71`.
pub const DNS_QUERY_ID_DOH: u16 = 0x5a71;
const DNS_QUERY_ID_DOT: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsHealthFailure {
    Configuration,
    Local,
    Network,
    Certificate,
    Server,
    DnsResponse,
}

impl DnsHealthFailure {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Local => "local",
            Self::Network => "network",
            Self::Certificate => "certificate",
            Self::Server => "server",
            Self::DnsResponse => "dns_response",
        }
    }
}

/// Результат health-пробы для controller/live.json.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsHealthResult {
    pub local_endpoint: Option<SocketAddr>,
    pub tcp_reachable: bool,
    pub tls_handshake: bool,
    pub http_status: i32,
    pub dns_reply: bool,
    pub elapsed_ms: Option<u64>,
    pub answer_rtt_ms: Option<u64>,
    pub failure: Option<DnsHealthFailure>,
    pub reason: String,
}

impl DnsHealthResult {
    fn fail(mut self, failure: DnsHealthFailure, reason: impl Into<String>) -> Self {
        self.failure = Some(failure);
        self.reason = reason.into();
        self
    }
}

fn socket_failure(error: &std::io::Error) -> DnsHealthFailure {
    use std::io::ErrorKind::*;

    if matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented)
    ) {
        return DnsHealthFailure::Certificate;
    }
    match error.kind() {
        TimedOut | WouldBlock | ConnectionReset | ConnectionAborted | BrokenPipe
        | HostUnreachable => DnsHealthFailure::Network,
        ConnectionRefused | UnexpectedEof | InvalidData => DnsHealthFailure::Server,
        _ => DnsHealthFailure::Local,
    }
}

/// C `dns_query`: 29-байтный length-prefixed DNS-запрос `example.com A`.
///
/// Первые два байта — длина DNS-сообщения (27), затем ID, flags 0100,
/// QDCOUNT 1, AN/NS/AR 0 и вопрос `example.com A IN`.
pub fn dns_query_frame(id: u16) -> Vec<u8> {
    let message = dns_query_message(id);
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&(message.len() as u16).to_be_bytes());
    frame.extend_from_slice(&message);
    frame
}

pub fn dns_query_message(id: u16) -> Vec<u8> {
    let mut message = Vec::with_capacity(27);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100_u16.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    message.extend_from_slice(&[7]);
    message.extend_from_slice(b"example");
    message.extend_from_slice(&[3]);
    message.extend_from_slice(b"com");
    message.push(0);
    message.extend_from_slice(&[0, 1, 0, 1]);
    message
}

fn dns16(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

/// C `ech_dns_name` (`verify.c:63-89`): compression до 16 прыжков,
/// lower-case LDH, метка до 63, имя до 253 байт, курсор после исходной записи.
fn dns_name(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut position = start;
    let mut after = None;
    let mut used = 0usize;
    let mut jumps = 0usize;
    let mut out = String::new();
    while position < bytes.len() {
        let byte = bytes[position];
        position += 1;
        if byte == 0 {
            let next = after.unwrap_or(position);
            return Some((out, next));
        }
        if byte & 0xc0 == 0xc0 {
            let low = *bytes.get(position)?;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            if after.is_none() {
                after = Some(position + 1);
            }
            position = (usize::from(byte & 0x3f) << 8) | usize::from(low);
            continue;
        }
        let length = usize::from(byte);
        if length > 63 || length > bytes.len().saturating_sub(position) {
            return None;
        }
        if used != 0 {
            out.push('.');
            used += 1;
        }
        if used + length > 253 {
            return None;
        }
        for _ in 0..length {
            let value = bytes[position];
            position += 1;
            let value = value.to_ascii_lowercase();
            if !(value.is_ascii_alphanumeric() || value == b'-') {
                return None;
            }
            out.push(value as char);
            used += 1;
        }
    }
    None
}

/// C `dns_probe_reply` (`verify.c:2000-2020`): проверка ID, QR/opcode/TC/rcode,
/// QDCOUNT/ANCOUNT, вопроса и A-записи в ответе.
pub fn dns_probe_reply(message: &[u8], id: u16) -> bool {
    if message.len() < 12
        || dns16(message, 0) != Some(id)
        || dns16(message, 2).is_none_or(|flags| flags & 0xfa0f != 0x8000)
        || dns16(message, 4) != Some(1)
        || dns16(message, 6).is_none_or(|answers| answers == 0)
    {
        return false;
    }
    let Some((question, mut position)) = dns_name(message, 12) else {
        return false;
    };
    if question != "example.com"
        || message.len().saturating_sub(position) < 4
        || dns16(message, position) != Some(1)
        || dns16(message, position + 2) != Some(1)
    {
        return false;
    }
    position += 4;
    let answers = usize::from(dns16(message, 6).unwrap_or(0));
    let records = answers
        + usize::from(dns16(message, 8).unwrap_or(0))
        + usize::from(dns16(message, 10).unwrap_or(0));
    // C не имеет явного предела; 128 — верхняя граница проверенного набора и
    // защита от бессмысленно больших счётчиков в health-пробе.
    if records > 128 {
        return false;
    }
    let mut have_address = false;
    for index in 0..records {
        let Some((name, next)) = dns_name(message, position) else {
            return false;
        };
        position = next;
        if message.len().saturating_sub(position) < 10 {
            return false;
        }
        let rdlen = usize::from(dns16(message, position + 8).unwrap_or(0));
        if rdlen > message.len().saturating_sub(position).saturating_sub(10) {
            return false;
        }
        if index < answers
            && name == "example.com"
            && dns16(message, position) == Some(1)
            && dns16(message, position + 2) == Some(1)
            && rdlen == 4
        {
            have_address = true;
        }
        position += 10 + rdlen;
    }
    position == message.len() && have_address
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DohState {
    NeedMore,
    Complete,
    Invalid,
}

#[derive(Clone, Debug)]
struct DohResponse {
    state: DohState,
    #[cfg(test)]
    rc: i32,
    status: i32,
    #[cfg(test)]
    body_bytes: usize,
    body_expected: usize,
    #[cfg(test)]
    has_length: bool,
    #[cfg(test)]
    chunked: bool,
    dns_reply: bool,
    reason: String,
}

#[derive(Clone, Debug)]
struct DohHeaders {
    status: i32,
    body_len: usize,
    has_length: bool,
    chunked: bool,
    content_type_ok: bool,
}

fn doh_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn trim_http_value(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();
    while start < end && matches!(value[start], b' ' | b'\t') {
        start += 1;
    }
    while end > start && matches!(value[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    &value[start..end]
}

fn doh_parse_headers(data: &[u8], query: &DohQuery) -> Option<DohHeaders> {
    if data.is_empty() || data.len() > DOH_HEADER_MAX {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    let status_bytes = status_line.as_bytes();
    if status_bytes.len() < 12
        || (!status_line.starts_with("HTTP/1.1 ") && !status_line.starts_with("HTTP/1.0 "))
        || !status_bytes[9..12].iter().all(u8::is_ascii_digit)
        || (status_bytes.len() > 12 && status_bytes[12] != b' ')
    {
        return None;
    }
    let status = i32::from(status_bytes[9] - b'0') * 100
        + i32::from(status_bytes[10] - b'0') * 10
        + i32::from(status_bytes[11] - b'0');
    let mut body_len = 0usize;
    let mut has_length = false;
    let mut chunked = false;
    let mut have_transfer = false;
    let mut content_type_ok = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() {
            return None;
        }
        let value = trim_http_value(value.as_bytes());
        if status == 200 && name.eq_ignore_ascii_case("content-type") {
            if content_type_ok || !query.accepts_type(value) {
                return None;
            }
            content_type_ok = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            if has_length || value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let mut length = 0usize;
            for digit in value {
                length = length
                    .checked_mul(10)?
                    .checked_add(usize::from(*digit - b'0'))?;
                if length > DOH_BODY_MAX {
                    return None;
                }
            }
            body_len = length;
            has_length = true;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if have_transfer || !value.eq_ignore_ascii_case(b"chunked") {
                return None;
            }
            have_transfer = true;
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case(b"identity")
        {
            return None;
        }
    }
    if has_length && chunked {
        return None;
    }
    Some(DohHeaders {
        status,
        body_len,
        has_length,
        chunked,
        content_type_ok,
    })
}

fn parse_chunk_line(line: &[u8]) -> Option<usize> {
    if line.is_empty() || line.len() > 64 {
        return None;
    }
    let number = line.split(|byte| *byte == b';').next().unwrap_or_default();
    let number = number
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map_or(&[][..], |start| &number[start..]);
    if number.is_empty() {
        return None;
    }
    let number = std::str::from_utf8(number).ok()?;
    let number = number
        .strip_prefix("0x")
        .or_else(|| number.strip_prefix("0X"))
        .unwrap_or(number);
    usize::from_str_radix(number, 16).ok()
}

fn doh_decode_chunked(raw: &[u8], body: &mut [u8]) -> Result<Option<usize>, ()> {
    let mut position = 0usize;
    let mut used = 0usize;
    loop {
        let line_start = position;
        while position + 1 < raw.len() && !(raw[position] == b'\r' && raw[position + 1] == b'\n') {
            position += 1;
        }
        if position + 1 >= raw.len() {
            return Ok(None);
        }
        let line = &raw[line_start..position];
        let size = parse_chunk_line(line).ok_or(())?;
        if size > body.len().saturating_sub(used) {
            return Err(());
        }
        position += 2;
        if size == 0 {
            if position + 2 <= raw.len() && raw[position] == b'\r' && raw[position + 1] == b'\n' {
                return Ok(Some(used));
            }
            if raw[position..]
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                return Ok(Some(used));
            }
            return Ok(None);
        }
        if size > raw.len().saturating_sub(position)
            || raw.len().saturating_sub(position).saturating_sub(size) < 2
        {
            return Ok(None);
        }
        body[used..used + size].copy_from_slice(&raw[position..position + size]);
        used += size;
        position += size;
        if raw[position] != b'\r' || raw[position + 1] != b'\n' {
            return Err(());
        }
        position += 2;
    }
}

fn doh_response_parse(response: &[u8], query: &DohQuery) -> DohResponse {
    let Some(sep) = doh_header_end(response) else {
        return DohResponse {
            state: if response.len() >= DOH_HEADER_MAX {
                DohState::Invalid
            } else {
                DohState::NeedMore
            },
            #[cfg(test)]
            rc: if response.len() >= DOH_HEADER_MAX {
                -1
            } else {
                0
            },
            status: 0,
            #[cfg(test)]
            body_bytes: 0,
            body_expected: 0,
            #[cfg(test)]
            has_length: false,
            #[cfg(test)]
            chunked: false,
            dns_reply: false,
            reason: "DoH: некорректные HTTP заголовки".into(),
        };
    };
    if sep > DOH_HEADER_MAX {
        return invalid_doh("DoH: некорректные HTTP заголовки");
    }
    let Some(headers) = doh_parse_headers(&response[..sep], query) else {
        return invalid_doh("DoH: некорректные HTTP заголовки");
    };
    if headers.status != 200 {
        return DohResponse {
            state: DohState::Invalid,
            #[cfg(test)]
            rc: 0,
            status: headers.status,
            #[cfg(test)]
            body_bytes: 0,
            body_expected: 0,
            #[cfg(test)]
            has_length: false,
            #[cfg(test)]
            chunked: false,
            dns_reply: false,
            reason: format!("DoH: HTTP {}", headers.status),
        };
    }
    if !headers.content_type_ok || (!headers.has_length && !headers.chunked) {
        return invalid_doh("DoH: неверный тип или framing ответа");
    }
    let body_offset = sep + 4;
    if headers.has_length {
        if headers.body_len > DOH_BODY_MAX {
            return invalid_doh("DoH: неполный или слишком большой DNS body");
        }
        if response.len().saturating_sub(body_offset) < headers.body_len {
            return DohResponse {
                state: DohState::Invalid,
                #[cfg(test)]
                rc: -1,
                status: headers.status,
                #[cfg(test)]
                body_bytes: 0,
                body_expected: headers.body_len,
                #[cfg(test)]
                has_length: false,
                #[cfg(test)]
                chunked: false,
                dns_reply: false,
                reason: "DoH: неполный или слишком большой DNS body".into(),
            };
        }
        let body = &response[body_offset..body_offset + headers.body_len];
        return finish_doh(body, headers, query);
    }
    let mut body = [0u8; DOH_BODY_MAX];
    match doh_decode_chunked(&response[body_offset..], &mut body) {
        Ok(Some(length)) => finish_doh(&body[..length], headers, query),
        Ok(None) => DohResponse {
            state: DohState::NeedMore,
            #[cfg(test)]
            rc: 0,
            status: headers.status,
            #[cfg(test)]
            body_bytes: 0,
            body_expected: 0,
            #[cfg(test)]
            has_length: false,
            #[cfg(test)]
            chunked: false,
            dns_reply: false,
            reason: "DoH: DNS body не завершён".into(),
        },
        Err(()) => invalid_doh("DoH: некорректный chunked body"),
    }
}

fn invalid_doh(reason: &str) -> DohResponse {
    DohResponse {
        state: DohState::Invalid,
        #[cfg(test)]
        rc: -1,
        status: 0,
        #[cfg(test)]
        body_bytes: 0,
        body_expected: 0,
        #[cfg(test)]
        has_length: false,
        #[cfg(test)]
        chunked: false,
        dns_reply: false,
        reason: reason.into(),
    }
}

fn finish_doh(body: &[u8], headers: DohHeaders, query: &DohQuery) -> DohResponse {
    if !query.validate_reply(body) {
        return DohResponse {
            state: DohState::Invalid,
            #[cfg(test)]
            rc: 0,
            status: headers.status,
            #[cfg(test)]
            body_bytes: body.len(),
            body_expected: headers.body_len,
            #[cfg(test)]
            has_length: headers.has_length,
            #[cfg(test)]
            chunked: headers.chunked,
            dns_reply: false,
            reason: "DoH: HTTP завершён, DNS-ответ некорректен".into(),
        };
    }
    DohResponse {
        state: DohState::Complete,
        #[cfg(test)]
        rc: 1,
        status: headers.status,
        #[cfg(test)]
        body_bytes: body.len(),
        body_expected: if headers.has_length {
            headers.body_len
        } else {
            body.len()
        },
        #[cfg(test)]
        has_length: headers.has_length,
        #[cfg(test)]
        chunked: headers.chunked,
        dns_reply: true,
        reason: match query {
            DohQuery::Message(_) => "DoH: корректный RFC 8484 DNS-ответ",
            DohQuery::Json => "DoH JSON: получен корректный DNS-ответ",
        }
        .into(),
    }
}

fn resolve_service(service: &DnsService) -> Result<SocketAddr, String> {
    let host = if service.host.is_empty() {
        service.sni.as_str()
    } else {
        service.host.as_str()
    };
    if host.is_empty() {
        return Err("DNS: пустой endpoint".into());
    }
    let port = if service.port == 0 {
        if service.protocol.eq_ignore_ascii_case("doh")
            || service.protocol.eq_ignore_ascii_case("doh3")
        {
            443
        } else {
            853
        }
    } else {
        service.port
    };
    host.parse::<std::net::IpAddr>()
        .map(|address| SocketAddr::new(address, port))
        .map_err(|_| "DNS: нужен наблюдённый IP endpoint или настроенный bootstrap".into())
}

fn deadline_from(timeout: Duration) -> Result<Instant, String> {
    let timeout = if timeout.is_zero() {
        Duration::from_millis(5000)
    } else {
        timeout
    };
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "DNS: timeout слишком велик".into())
}

fn set_tcp_timeout(stream: &TcpStream, deadline: Instant) -> std::io::Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "DNS: истёк срок",
        ));
    }
    stream
        .set_read_timeout(Some(left))
        .and_then(|()| stream.set_write_timeout(Some(left)))
}

type DnsTlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn read_exact_before(
    stream: &mut DnsTlsStream,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !buffer.is_empty() {
        set_tcp_timeout(&stream.sock, deadline)?;
        match stream.read(buffer) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(length) => buffer = &mut buffer[length..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_dns_frame(stream: &mut DnsTlsStream, deadline: Instant) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 2];
    read_exact_before(stream, &mut header, deadline)?;
    let length = usize::from(u16::from_be_bytes(header));
    if !(14..=DNS_FRAME_MAX).contains(&length) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS: неверная длина frame",
        ));
    }
    let mut body = vec![0u8; length];
    read_exact_before(stream, &mut body, deadline)?;
    Ok(body)
}

#[cfg(target_os = "linux")]
fn connect_tcp(
    address: SocketAddr,
    mark: Option<u32>,
    timeout: Duration,
) -> Result<TcpStream, (DnsHealthFailure, String)> {
    crate::fetch::connect_target(address, mark, timeout).map_err(|error| {
        let kind = if error.local_refusal {
            DnsHealthFailure::Local
        } else {
            socket_failure(&error.source)
        };
        (kind, error.to_string())
    })
}

#[cfg(not(target_os = "linux"))]
fn connect_tcp(
    address: SocketAddr,
    mark: Option<u32>,
    timeout: Duration,
) -> Result<TcpStream, (DnsHealthFailure, String)> {
    let _ = mark;
    TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| (socket_failure(&error), error.to_string()))
}

pub(crate) fn trusted_dns_tls_connection(
    name: &str,
    tls12: bool,
    wire_len: Option<usize>,
    alpn: &[Vec<u8>],
    roots: Arc<RootCertStore>,
    pin: Option<[u8; 32]>,
) -> Result<rustls::ClientConnection, String> {
    let config = trusted_dns_tls_config(tls12, wire_len, alpn, roots, pin)?;
    let name = ServerName::try_from(name.to_owned()).map_err(|_| "DNS: недопустимое имя TLS")?;
    rustls::ClientConnection::new(config, name).map_err(|error| format!("DNS: TLS config: {error}"))
}

fn trusted_dns_tls_config(
    tls12: bool,
    wire_len: Option<usize>,
    alpn: &[Vec<u8>],
    roots: Arc<RootCertStore>,
    pin: Option<[u8; 32]>,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let versions = if tls12 {
        &[&rustls::version::TLS12][..]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12][..]
    };
    let provider = rustls::crypto::ring::default_provider();
    let algorithms = provider.signature_verification_algorithms;
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|error| format!("DNS: TLS config: {error}"))?;
    let mut config = match pin {
        Some(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DnsSpkiVerifier::new(pin, algorithms))),
        None => builder.with_root_certificates(roots),
    }
    .with_no_client_auth();
    config.alpn_protocols = alpn.to_vec();
    config.r2o_client_hello_wire_len = wire_len;
    Ok(Arc::new(config))
}

#[derive(Debug)]
pub(crate) struct DnsSpkiVerifier {
    pin: [u8; 32],
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl DnsSpkiVerifier {
    pub(crate) fn new(
        pin: [u8; 32],
        algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
    ) -> Self {
        Self { pin, algorithms }
    }
}

impl rustls::client::danger::ServerCertVerifier for DnsSpkiVerifier {
    fn verify_server_cert(
        &self,
        leaf: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        name: &ServerName<'_>,
        _ocsp: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use rustls::{CertificateError, Error::InvalidCertificate};
        use sha2::{Digest, Sha256};
        let bad_encoding = InvalidCertificate(CertificateError::BadEncoding);
        let (rest, cert) =
            x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|_| bad_encoding.clone())?;
        if !rest.is_empty() {
            return Err(bad_encoding);
        }
        // Keenetic доверяет настроенному ключу конечного сертификата.
        let digest: [u8; 32] = Sha256::digest(cert.tbs_certificate.subject_pki.raw).into();
        if digest != self.pin {
            return Err(InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(std::io::Error::other(
                    "SPKI сертификата DNS-сервера не совпадает с настройкой",
                ))),
            )));
        }
        let now = i64::try_from(now.as_secs())
            .ok()
            .and_then(|seconds| x509_parser::time::ASN1Time::from_timestamp(seconds).ok())
            .ok_or(CertificateError::Expired)?;
        if now < cert.validity().not_before {
            return Err(CertificateError::NotValidYet.into());
        }
        if now > cert.validity().not_after {
            return Err(CertificateError::Expired.into());
        }
        if cert
            .extended_key_usage()
            .map_err(|_| bad_encoding.clone())?
            .is_some_and(|usage| !usage.value.any && !usage.value.server_auth)
            || cert
                .key_usage()
                .map_err(|_| bad_encoding)?
                .is_some_and(|usage| !usage.value.digital_signature())
        {
            return Err(CertificateError::InvalidPurpose.into());
        }
        rustls::client::verify_server_name(
            &rustls::server::ParsedCertificate::try_from(leaf)?,
            name,
        )?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn tls_connect(
    stream: TcpStream,
    name: &str,
    alpn: &[Vec<u8>],
    deadline: Instant,
    roots: Arc<RootCertStore>,
    pin: Option<[u8; 32]>,
) -> Result<DnsTlsStream, (DnsHealthFailure, String)> {
    let mut connection = trusted_dns_tls_connection(name, false, None, alpn, roots, pin)
        .map_err(|error| (DnsHealthFailure::Configuration, error))?;
    let mut stream = stream;
    while connection.is_handshaking() {
        set_tcp_timeout(&stream, deadline)
            .map_err(|error| (socket_failure(&error), error.to_string()))?;
        match connection.complete_io(&mut stream) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err((socket_failure(&error), format!("TLS: {error}")));
                }
            }
            Err(error) => return Err((socket_failure(&error), format!("TLS: {error}"))),
        }
    }
    Ok(rustls::StreamOwned::new(connection, stream))
}

fn doh_validate(service: &DnsService) -> Result<(), String> {
    if service.host.is_empty() && service.sni.is_empty() {
        return Err("DoH: неверный endpoint".into());
    }
    if service.port == 0 {
        return Err("DoH: неверный endpoint".into());
    }
    let path = if service.path.is_empty() {
        "/"
    } else {
        service.path.as_str()
    };
    if !path.starts_with('/')
        || path
            .bytes()
            .any(|byte| byte <= 32 || byte == 127 || byte == b'\\' || byte == b'"')
    {
        return Err("DoH: недопустимый request target".into());
    }
    Ok(())
}

pub(crate) fn doh_authority(host: &str, port: u16) -> Result<String, String> {
    if host.is_empty() {
        return Err("DoH: недопустимый Host".into());
    }
    if !host.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'%' | b'[' | b']')
    }) {
        return Err("DoH: недопустимый Host".into());
    }
    let ipv6 = host.contains(':');
    let authority_host = if ipv6 && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(if port == 443 {
        authority_host
    } else {
        format!("{authority_host}:{port}")
    })
}

pub(crate) enum DohTls {
    Http1(DnsTlsStream),
    Http2(DohHttp2),
}

pub(crate) struct DohHttp2 {
    runtime: tokio::runtime::Runtime,
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}

pub(crate) struct DohHttp2Result {
    pub health: DnsHealthResult,
    pub tls: Option<&'static str>,
    pub body_len: usize,
    pub content_length: Option<usize>,
}

pub(crate) fn connect_doh_tls(
    socket: TcpStream,
    name: &str,
    tls12: bool,
    wire_len: Option<usize>,
    deadline: Instant,
    roots: Arc<RootCertStore>,
    pin: Option<[u8; 32]>,
) -> Result<DohTls, (DnsHealthFailure, String)> {
    let configuration = |error| (DnsHealthFailure::Configuration, error);
    let local = |error: std::io::Error| (DnsHealthFailure::Local, error.to_string());
    let config = trusted_dns_tls_config(
        tls12,
        wire_len,
        &[b"h2".to_vec(), b"http/1.1".to_vec()],
        roots,
        pin,
    )
    .map_err(configuration)?;
    let name = ServerName::try_from(name.to_owned())
        .map_err(|_| configuration("DNS: недопустимое имя TLS".into()))?;
    socket.set_nonblocking(true).map_err(local)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(local)?;
    let stream = runtime.block_on(async {
        let socket = tokio::net::TcpStream::from_std(socket).map_err(local)?;
        tokio::time::timeout_at(
            deadline.into(),
            tokio_rustls::TlsConnector::from(config).connect(name, socket),
        )
        .await
        .map_err(|_| (DnsHealthFailure::Network, "истёк срок TLS".into()))?
        .map_err(|error| (socket_failure(&error), format!("TLS: {error}")))
    })?;
    if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
        return Ok(DohTls::Http2(DohHttp2 { runtime, stream }));
    }
    // Продолжаем HTTP/1.1 на том же TCP-сокете и в той же TLS-сессии.
    let (socket, connection) = stream.into_inner();
    let socket = socket.into_std().map_err(local)?;
    socket.set_nonblocking(false).map_err(local)?;
    Ok(DohTls::Http1(rustls::StreamOwned::new(connection, socket)))
}

impl DohHttp2 {
    pub(crate) fn exchange(
        self,
        name: &str,
        port: u16,
        path: &str,
        query: &DohQuery,
        deadline: Instant,
    ) -> DohHttp2Result {
        use bytes::Bytes;

        let mut health = DnsHealthResult {
            local_endpoint: self.stream.get_ref().0.local_addr().ok(),
            tcp_reachable: true,
            tls_handshake: true,
            ..Default::default()
        };
        let tls = match self.stream.get_ref().1.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => Some("1.3"),
            Some(rustls::ProtocolVersion::TLSv1_2) => Some("1.2"),
            _ => None,
        };
        let mut body = Vec::new();
        let mut content_length = None;
        let result = self.runtime.block_on(async {
            tokio::time::timeout_at(deadline.into(), async {
                let invalid = |reason: &str| (DnsHealthFailure::DnsResponse, reason.to_owned());
                let h2_error = |error: h2::Error| {
                    let kind = error
                        .get_io()
                        .map_or(DnsHealthFailure::Server, socket_failure);
                    (kind, error.to_string())
                };
                let authority = doh_authority(name, port)
                    .map_err(|error| (DnsHealthFailure::Configuration, error))?;
                let uri = http::Uri::builder()
                    .scheme("https")
                    .authority(authority)
                    .path_and_query(path)
                    .build()
                    .map_err(|error| (DnsHealthFailure::Configuration, error.to_string()))?;
                let request = match query {
                    DohQuery::Message(message) => http::Request::post(uri)
                        .header(http::header::ACCEPT, "application/dns-message")
                        .header(http::header::CONTENT_TYPE, "application/dns-message")
                        .header(http::header::CONTENT_LENGTH, message.len()),
                    DohQuery::Json => {
                        http::Request::get(uri).header(http::header::ACCEPT, "application/dns-json")
                    }
                }
                .version(http::Version::HTTP_2)
                .body(())
                .map_err(|error| (DnsHealthFailure::Configuration, error.to_string()))?;
                let (sender, connection) = h2::client::Builder::new()
                    .enable_push(false)
                    .header_table_size(0)
                    .max_header_list_size(DOH_HEADER_MAX as u32)
                    .initial_window_size((DOH_BODY_MAX + 1) as u32)
                    .handshake(self.stream)
                    .await
                    .map_err(h2_error)?;
                tokio::spawn(connection);

                let mut sender = sender.ready().await.map_err(h2_error)?;
                let sent = Instant::now();
                let (response, mut stream) = sender
                    .send_request(request, matches!(query, DohQuery::Json))
                    .map_err(h2_error)?;
                if let DohQuery::Message(message) = query {
                    stream
                        .send_data(Bytes::copy_from_slice(message), true)
                        .map_err(h2_error)?;
                }
                let response = response.await.map_err(h2_error)?;
                health.http_status = i32::from(response.status().as_u16());
                if response.status() != http::StatusCode::OK {
                    return Err((
                        DnsHealthFailure::Server,
                        format!("сервер вернул HTTP {}", health.http_status),
                    ));
                }
                if !response
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .is_some_and(|value| query.accepts_type(value.as_bytes()))
                {
                    return Err(invalid("неверный Content-Type"));
                }
                let lengths = response.headers().get_all(http::header::CONTENT_LENGTH);
                let mut lengths = lengths.iter();
                if let Some(length) = lengths.next() {
                    content_length = length.to_str().ok().and_then(|value| value.parse().ok());
                    if content_length.is_none_or(|length| length > DOH_BODY_MAX)
                        || lengths.next().is_some()
                    {
                        return Err(invalid("неверный Content-Length"));
                    }
                }
                let mut recv = response.into_body();
                while let Some(chunk) = recv.data().await {
                    let chunk = chunk.map_err(|_| invalid("обрыв DNS-ответа"))?;
                    if body.len() + chunk.len() > DOH_BODY_MAX {
                        return Err(invalid("слишком большой DNS-ответ"));
                    }
                    body.extend_from_slice(&chunk);
                }
                if content_length.is_some_and(|length| length != body.len()) {
                    return Err(invalid("Content-Length не совпадает с DNS-ответом"));
                }
                if !query.validate_reply(&body) {
                    return Err(invalid("некорректный DNS-ответ"));
                }
                Ok(sent.elapsed().as_millis() as u64)
            })
            .await
        });
        health = match result {
            Ok(Ok(rtt)) => {
                health.dns_reply = true;
                health.answer_rtt_ms = Some(rtt);
                health.reason = match query {
                    DohQuery::Message(_) => "DoH (HTTP/2): получен корректный DNS-ответ",
                    DohQuery::Json => "DoH JSON (HTTP/2): получен корректный DNS-ответ",
                }
                .into();
                health
            }
            Ok(Err((kind, reason))) => health.fail(kind, format!("DoH (HTTP/2): {reason}")),
            Err(_) => {
                let kind = if health.http_status == 0 {
                    DnsHealthFailure::Network
                } else {
                    DnsHealthFailure::DnsResponse
                };
                health.fail(kind, "DoH (HTTP/2): истёк срок проверки")
            }
        };
        DohHttp2Result {
            health,
            tls,
            body_len: body.len(),
            content_length,
        }
    }
}

fn probe_doh(
    service: &DnsService,
    mark: Option<u32>,
    deadline: Instant,
    roots: Arc<RootCertStore>,
    pin: Option<[u8; 32]>,
) -> DnsHealthResult {
    let mut result = DnsHealthResult::default();
    if let Err(reason) = doh_validate(service) {
        return result.fail(DnsHealthFailure::Configuration, reason);
    }
    let query = DohQuery::for_service(service);
    let path = match query.request_path(&service.path) {
        Ok(path) => path,
        Err(reason) => return result.fail(DnsHealthFailure::Configuration, reason),
    };
    let address = match resolve_service(service) {
        Ok(address) => address,
        Err(reason) => return result.fail(DnsHealthFailure::Configuration, reason),
    };
    let timeout = deadline.saturating_duration_since(Instant::now());
    let stream = match connect_tcp(address, mark, timeout) {
        Ok(stream) => {
            result.local_endpoint = stream.local_addr().ok();
            result.tcp_reachable = true;
            stream
        }
        Err((kind, error)) => {
            return result.fail(kind, format!("DoH: TCP endpoint недоступен: {error}"));
        }
    };
    let name = if service.sni.is_empty() {
        service.host.as_str()
    } else {
        service.sni.as_str()
    };
    let mut stream = match connect_doh_tls(stream, name, false, None, deadline, roots, pin) {
        Ok(DohTls::Http1(tls)) => {
            result.tls_handshake = true;
            tls
        }
        Ok(DohTls::Http2(tls)) => {
            return tls
                .exchange(name, service.port, &path, &query, deadline)
                .health;
        }
        Err((kind, reason)) => return result.fail(kind, format!("DoH: {reason}")),
    };
    let authority = match doh_authority(name, service.port) {
        Ok(authority) => authority,
        Err(reason) => return result.fail(DnsHealthFailure::Configuration, reason),
    };
    let request = query.http1_request(&authority, &path, "close");
    let sent = Instant::now();
    if let Err(error) = set_tcp_timeout(&stream.sock, deadline)
        .and_then(|()| stream.write_all(&request))
        .and_then(|()| stream.flush())
    {
        return result.fail(
            socket_failure(&error),
            format!("DoH: отправка запроса: {error}"),
        );
    }
    let mut response = Vec::with_capacity(DOH_RESPONSE_MAX);
    let parsed = loop {
        let parsed = doh_response_parse(&response, &query);
        let waiting_body = parsed.state == DohState::Invalid
            && parsed.status == 200
            && parsed.body_expected > 0
            && doh_header_end(&response)
                .is_some_and(|sep| response.len() < sep + 4 + parsed.body_expected);
        if (parsed.state != DohState::NeedMore && !waiting_body)
            || response.len() >= DOH_RESPONSE_MAX
        {
            break parsed;
        }
        let mut buffer = [0u8; 1024];
        let capacity = buffer.len().min(DOH_RESPONSE_MAX - response.len());
        match set_tcp_timeout(&stream.sock, deadline)
            .and_then(|()| stream.read(&mut buffer[..capacity]))
        {
            Ok(0) => break parsed,
            Ok(length) => response.extend_from_slice(&buffer[..length]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if response.is_empty() => {
                return result.fail(
                    socket_failure(&error),
                    format!("DoH: чтение ответа: {error}"),
                );
            }
            Err(_) => break parsed,
        }
    };
    result.http_status = parsed.status;
    result.dns_reply = parsed.dns_reply;
    result.answer_rtt_ms = parsed.dns_reply.then(|| sent.elapsed().as_millis() as u64);
    result.reason = parsed.reason;
    if !result.dns_reply {
        result.failure = Some(if result.http_status != 0 && result.http_status != 200 {
            DnsHealthFailure::Server
        } else {
            DnsHealthFailure::DnsResponse
        });
    }
    result
}

fn probe_dot(
    service: &DnsService,
    mark: Option<u32>,
    deadline: Instant,
    roots: Arc<RootCertStore>,
    pin: Option<[u8; 32]>,
) -> DnsHealthResult {
    let mut result = DnsHealthResult::default();
    let address = match resolve_service(service) {
        Ok(address) => address,
        Err(reason) => return result.fail(DnsHealthFailure::Configuration, reason),
    };
    let timeout = deadline.saturating_duration_since(Instant::now());
    let stream = match connect_tcp(address, mark, timeout) {
        Ok(stream) => {
            result.local_endpoint = stream.local_addr().ok();
            result.tcp_reachable = true;
            stream
        }
        Err((kind, error)) => return result.fail(kind, format!("DoT: нет TCP: {error}")),
    };
    let name = if service.sni.is_empty() {
        service.host.as_str()
    } else {
        service.sni.as_str()
    };
    let mut stream = match tls_connect(stream, name, &[b"dot".to_vec()], deadline, roots, pin) {
        Ok(tls) => {
            result.tls_handshake = true;
            tls
        }
        Err((kind, reason)) => return result.fail(kind, format!("DoT: {reason}")),
    };
    let query = dns_query_frame(DNS_QUERY_ID_DOT);
    let sent = Instant::now();
    if let Err(error) = set_tcp_timeout(&stream.sock, deadline)
        .and_then(|()| stream.write_all(&query))
        .and_then(|()| stream.flush())
    {
        return result.fail(socket_failure(&error), format!("DoT: отправка: {error}"));
    }
    match read_dns_frame(&mut stream, deadline) {
        Ok(body) => {
            result.dns_reply = dns_probe_reply(&body, DNS_QUERY_ID_DOT);
            result.answer_rtt_ms = result.dns_reply.then(|| sent.elapsed().as_millis() as u64);
            result.reason = if result.dns_reply {
                "DoT: получен корректный DNS-ответ".into()
            } else {
                result.failure = Some(DnsHealthFailure::DnsResponse);
                "DoT: нет подтверждённого DNS-ответа".into()
            };
        }
        Err(error) => {
            let kind = match error.kind() {
                std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
                    DnsHealthFailure::DnsResponse
                }
                _ => socket_failure(&error),
            };
            return result.fail(kind, format!("DoT: {error}"));
        }
    }
    result
}

fn probe_quic_dns(
    service: &DnsService,
    mark: Option<u32>,
    deadline: Instant,
    roots: Arc<RootCertStore>,
) -> DnsHealthResult {
    let http3 = service.protocol.eq_ignore_ascii_case("doh3");
    if http3 && let Err(reason) = doh_validate(service) {
        return DnsHealthResult::default().fail(DnsHealthFailure::Configuration, reason);
    }
    let address = match resolve_service(service) {
        Ok(address) => address,
        Err(reason) => {
            return DnsHealthResult {
                reason,
                failure: Some(DnsHealthFailure::Configuration),
                ..Default::default()
            };
        }
    };
    let host = if service.sni.is_empty() {
        service.host.as_str()
    } else {
        service.sni.as_str()
    };
    let socket = match crate::r2o_quic_http3::r2o_quic_http3_udp_socket_fresh(address, mark) {
        Ok((socket, _)) => socket,
        Err(error) => {
            return DnsHealthResult {
                reason: format!("DNS: UDP: {}", error.source),
                failure: Some(DnsHealthFailure::Local),
                ..Default::default()
            };
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return DnsHealthResult {
                reason: format!("DNS: нет Tokio runtime: {error}"),
                failure: Some(DnsHealthFailure::Local),
                ..Default::default()
            };
        }
    };
    let timeout = deadline.saturating_duration_since(Instant::now());
    if http3 {
        runtime.block_on(probe_doh3_on(
            socket, address, host, service, timeout, roots,
        ))
    } else {
        runtime.block_on(probe_doq_on_with_roots(
            socket, address, host, timeout, roots,
        ))
    }
}

/// Проверяет DNS-обмен DoQ или DoH3 на заданном UDP-сокете, в том числе под планом.
pub async fn probe_quic_dns_on(
    socket: std::net::UdpSocket,
    address: SocketAddr,
    host: &str,
    service: &DnsService,
    timeout: Duration,
) -> DnsHealthResult {
    if let Some(reason) = service.verification_limitation() {
        return DnsHealthResult::default().fail(DnsHealthFailure::Configuration, reason);
    }
    match service.protocol.as_str() {
        "doq" => probe_doq_on_with_roots(socket, address, host, timeout, dns_roots()).await,
        "doh3" => probe_doh3_on(socket, address, host, service, timeout, dns_roots()).await,
        _ => DnsHealthResult::default().fail(
            DnsHealthFailure::Configuration,
            "DNS: протокол не использует QUIC",
        ),
    }
}

fn trusted_quic_dns_endpoint(
    socket: std::net::UdpSocket,
    alpn: &[u8],
    roots: Arc<RootCertStore>,
) -> Result<quinn::Endpoint, String> {
    let provider = rustls::crypto::ring::default_provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| format!("TLS config: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| format!("QUIC TLS: {error}"))?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|error| format!("QUIC endpoint: {error}"))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(quinn::VarInt::from_u32(16 * 1024));
    transport.receive_window(quinn::VarInt::from_u32(32 * 1024));
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(0));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(4));
    client_config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

async fn connect_quic_dns(
    endpoint: &quinn::Endpoint,
    address: SocketAddr,
    name: &str,
) -> Result<quinn::Connection, (DnsHealthFailure, String)> {
    let connecting = endpoint
        .connect(address, name)
        .map_err(|error| (DnsHealthFailure::Configuration, error.to_string()))?;
    connecting.await.map_err(|error| {
        let kind = match &error {
            quinn::ConnectionError::TimedOut | quinn::ConnectionError::Reset => {
                DnsHealthFailure::Network
            }
            // RFC 9001 кодирует сообщение TLS как 0x100 + номер alert.
            quinn::ConnectionError::TransportError(error)
                if matches!(u64::from(error.code), 0x12a..=0x12e | 0x130 | 0x174) =>
            {
                DnsHealthFailure::Certificate
            }
            _ => DnsHealthFailure::Server,
        };
        (kind, error.to_string())
    })
}

async fn probe_doq_on_with_roots(
    socket: std::net::UdpSocket,
    address: SocketAddr,
    host: &str,
    timeout: Duration,
    roots: Arc<RootCertStore>,
) -> DnsHealthResult {
    let started = Instant::now();
    let mut result = DnsHealthResult::default();
    let endpoint = match trusted_quic_dns_endpoint(socket, b"doq", roots) {
        Ok(endpoint) => endpoint,
        Err(error) => return result.fail(DnsHealthFailure::Local, format!("DoQ: {error}")),
    };
    let query = dns_query_frame(0);
    let result_from_runtime = tokio::time::timeout(timeout, async {
        let connection = connect_quic_dns(&endpoint, address, host)
            .await
            .map_err(|(kind, error)| (kind, format!("DoQ: {error}")))?;
        result.tcp_reachable = true;
        result.tls_handshake = true;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| (DnsHealthFailure::Server, format!("DoQ: stream: {error}")))?;
        let sent = Instant::now();
        send.write_all(&query)
            .await
            .map_err(|error| (DnsHealthFailure::Server, format!("DoQ: send: {error}")))?;
        send.finish()
            .map_err(|error| (DnsHealthFailure::Server, format!("DoQ: finish: {error}")))?;
        let mut header = [0u8; 2];
        recv.read_exact(&mut header).await.map_err(|error| {
            (
                DnsHealthFailure::DnsResponse,
                format!("DoQ: frame: {error}"),
            )
        })?;
        let length = usize::from(u16::from_be_bytes(header));
        if !(14..=DNS_FRAME_MAX).contains(&length) {
            return Err((
                DnsHealthFailure::DnsResponse,
                "DoQ: неверная длина frame".to_owned(),
            ));
        }
        let mut body = vec![0u8; length];
        recv.read_exact(&mut body).await.map_err(|error| {
            (
                DnsHealthFailure::DnsResponse,
                format!("DoQ: frame body: {error}"),
            )
        })?;
        if recv
            .read(&mut header[..1])
            .await
            .map_err(|error| {
                (
                    DnsHealthFailure::DnsResponse,
                    format!("DoQ: frame: {error}"),
                )
            })?
            .is_some()
        {
            return Err((
                DnsHealthFailure::DnsResponse,
                "DoQ: лишние данные после DNS-ответа".to_owned(),
            ));
        }
        Ok::<_, (DnsHealthFailure, String)>((body, sent.elapsed()))
    })
    .await;
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    match result_from_runtime {
        Ok(Ok((body, roundtrip))) => {
            result.dns_reply = dns_probe_reply(&body, 0);
            result.answer_rtt_ms = result.dns_reply.then(|| roundtrip.as_millis() as u64);
            result.reason = if result.dns_reply {
                "DoQ: получен корректный DNS-ответ".into()
            } else {
                result.failure = Some(DnsHealthFailure::DnsResponse);
                "DoQ: нет подтверждённого DNS-ответа".into()
            };
        }
        Ok(Err((kind, reason))) => result = result.fail(kind, reason),
        Err(_) => result = result.fail(DnsHealthFailure::Network, "DoQ: истёк срок проверки"),
    }
    result.elapsed_ms = Some(started.elapsed().as_millis() as u64);
    result
}

async fn probe_doh3_on(
    socket: std::net::UdpSocket,
    address: SocketAddr,
    host: &str,
    service: &DnsService,
    timeout: Duration,
    roots: Arc<RootCertStore>,
) -> DnsHealthResult {
    use base64::Engine;
    use bytes::{Buf, Bytes};

    let mut result = DnsHealthResult::default();
    let authority = match doh_authority(host, service.port) {
        Ok(authority) => authority,
        Err(error) => return result.fail(DnsHealthFailure::Configuration, error),
    };
    let path = if service.path.is_empty() {
        "/"
    } else {
        &service.path
    };
    let Ok(parsed) = path.parse::<http::uri::PathAndQuery>() else {
        return result.fail(DnsHealthFailure::Configuration, "DoH3: недопустимый URL");
    };
    if path.contains('#')
        || parsed.query().is_some_and(|query| {
            query.split('&').any(|pair| {
                let key = pair.split('=').next().unwrap_or_default();
                doh_parameter_matches(key, "dns")
            })
        })
    {
        return result.fail(
            DnsHealthFailure::Configuration,
            "DoH3: параметры URL конфликтуют с запросом DNS",
        );
    }
    let separator = if parsed.query().is_none() {
        "?"
    } else if path.ends_with(['?', '&']) {
        ""
    } else {
        "&"
    };
    let question = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_query_message(0));
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(format!("{path}{separator}dns={question}"))
        .build();
    let request = match uri.and_then(|uri| {
        http::Request::get(uri)
            .header(http::header::ACCEPT, "application/dns-message")
            .body(())
    }) {
        Ok(request) => request,
        Err(_) => return result.fail(DnsHealthFailure::Configuration, "DoH3: недопустимый URL"),
    };
    let endpoint = match trusted_quic_dns_endpoint(socket, b"h3", roots) {
        Ok(endpoint) => endpoint,
        Err(error) => return result.fail(DnsHealthFailure::Local, format!("DoH3: {error}")),
    };
    let mut drive = None;
    let response = tokio::time::timeout(timeout, async {
        let server = |error: h3::error::StreamError| (DnsHealthFailure::Server, error.to_string());
        let connection = connect_quic_dns(&endpoint, address, host).await?;
        result.tcp_reachable = true;
        result.tls_handshake = true;
        let (mut driver, mut sender): (_, h3::client::SendRequest<_, Bytes>) =
            h3::client::builder()
                .max_field_section_size(DOH_HEADER_MAX as u64)
                .build(h3_quinn::Connection::new(connection))
                .await
                .map_err(|error| (DnsHealthFailure::Server, error.to_string()))?;
        drive = Some(tokio::spawn(async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await
        }));
        let sent = Instant::now();
        let mut stream = sender.send_request(request).await.map_err(server)?;
        stream.finish().await.map_err(server)?;
        let response = stream.recv_response().await.map_err(server)?;
        result.http_status = i32::from(response.status().as_u16());
        if response.status() != http::StatusCode::OK {
            return Err((
                DnsHealthFailure::Server,
                format!("сервер вернул HTTP {}", response.status().as_u16()),
            ));
        }
        let invalid = |reason: &str| (DnsHealthFailure::DnsResponse, reason.to_owned());
        let types = response.headers().get_all(http::header::CONTENT_TYPE);
        let mut types = types.iter();
        let media_type = types
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next());
        if types.next().is_some()
            || !media_type
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/dns-message"))
        {
            return Err(invalid("неверный Content-Type"));
        }
        let mut body = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|_| invalid("обрыв DNS-ответа"))?
        {
            let size = chunk.remaining();
            if body.len().saturating_add(size) > DOH_BODY_MAX {
                return Err(invalid("слишком большой DNS-ответ"));
            }
            body.extend_from_slice(&chunk.copy_to_bytes(size));
        }
        let lengths = response.headers().get_all(http::header::CONTENT_LENGTH);
        let mut lengths = lengths.iter();
        if let Some(length) = lengths.next()
            && (length.to_str().ok().and_then(|value| value.parse().ok()) != Some(body.len())
                || lengths.next().is_some())
        {
            return Err(invalid("Content-Length не совпадает с DNS-ответом"));
        }
        if !dns_probe_reply(&body, 0) {
            return Err(invalid("некорректный DNS-ответ"));
        }
        Ok(sent.elapsed().as_millis() as u64)
    })
    .await;
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    if let Some(driver) = drive {
        driver.abort();
    }
    match response {
        Ok(Ok(rtt)) => {
            result.dns_reply = true;
            result.answer_rtt_ms = Some(rtt);
            result.reason = "DoH3: получен корректный DNS-ответ".into();
            result
        }
        Ok(Err((kind, error))) => result.fail(kind, format!("DoH3: {error}")),
        Err(_) => result.fail(DnsHealthFailure::Network, "DoH3: истёк срок проверки"),
    }
}

fn dns_roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    Arc::clone(ROOTS.get_or_init(|| {
        Arc::new(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    }))
}

/// Проверить DNS endpoint из конфигурации `dns_services`.
pub fn probe_dns_health(
    service: &DnsService,
    mark: Option<u32>,
    timeout: Duration,
) -> DnsHealthResult {
    probe_dns_health_with_roots(service, mark, timeout, dns_roots())
}

pub(crate) fn probe_dns_health_with_roots(
    service: &DnsService,
    mark: Option<u32>,
    timeout: Duration,
    roots: Arc<RootCertStore>,
) -> DnsHealthResult {
    if let Some(reason) = service.verification_limitation() {
        return DnsHealthResult::default().fail(DnsHealthFailure::Configuration, reason);
    }
    let pin = match service.spki_pin() {
        Ok(pin) => pin,
        Err(reason) => {
            return DnsHealthResult::default().fail(DnsHealthFailure::Configuration, reason);
        }
    };
    let started = Instant::now();
    let deadline = match deadline_from(timeout) {
        Ok(deadline) => deadline,
        Err(reason) => {
            return DnsHealthResult {
                reason,
                failure: Some(DnsHealthFailure::Configuration),
                ..Default::default()
            };
        }
    };
    let mut result = if service.protocol.eq_ignore_ascii_case("doh") {
        probe_doh(service, mark, deadline, roots, pin)
    } else if service.protocol.eq_ignore_ascii_case("dot") {
        probe_dot(service, mark, deadline, roots, pin)
    } else if service.protocol.eq_ignore_ascii_case("doq")
        || service.protocol.eq_ignore_ascii_case("doh3")
    {
        probe_quic_dns(service, mark, deadline, roots)
    } else {
        DnsHealthResult {
            reason: format!("DNS: неподдерживаемый протокол {}", service.protocol),
            failure: Some(DnsHealthFailure::Configuration),
            ..Default::default()
        }
    };
    result.elapsed_ms = Some(started.elapsed().as_millis() as u64);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::CertificateDer;

    #[test]
    fn missing_route_is_distinct_from_network_timeout() {
        use std::io::{Error, ErrorKind};

        assert_eq!(
            socket_failure(&Error::from(ErrorKind::NetworkUnreachable)),
            DnsHealthFailure::Local
        );
        assert_eq!(
            socket_failure(&Error::from(ErrorKind::TimedOut)),
            DnsHealthFailure::Network
        );
    }

    fn response(flags: u16, answers: u16, answer_type: u16, rdlen: u16) -> Vec<u8> {
        let mut msg = vec![0u8; 12];
        msg[0..2].copy_from_slice(&0x1234_u16.to_be_bytes());
        msg[2..4].copy_from_slice(&flags.to_be_bytes());
        msg[4..6].copy_from_slice(&1_u16.to_be_bytes());
        msg[6..8].copy_from_slice(&answers.to_be_bytes());
        msg.extend_from_slice(&dns_query_message(0)[12..]);
        let mut answer = vec![0xc0, 12];
        answer.extend_from_slice(&answer_type.to_be_bytes());
        answer.extend_from_slice(&1_u16.to_be_bytes());
        answer.extend_from_slice(&60_u32.to_be_bytes());
        answer.extend_from_slice(&rdlen.to_be_bytes());
        answer.extend(std::iter::repeat_n(0x7f, usize::from(rdlen)));
        msg.extend_from_slice(&answer);
        msg
    }

    #[test]
    fn dns_query_matches_c_wire_and_is_length_prefixed() {
        let frame = dns_query_frame(0);
        assert_eq!(frame.len(), 31);
        assert_eq!(&frame[..2], &[0, 29]);
        assert_eq!(&frame[2..4], &[0, 0]);
        let message = dns_query_message(DNS_QUERY_ID_DOH);
        assert_eq!(&message[..2], &[0x5a, 0x71]);
        assert_eq!(frame.len(), message.len() + 2);
    }

    #[test]
    fn dns_reply_accepts_a_record_and_rejects_bad_variants() {
        let good = response(0x8180, 1, 1, 4);
        assert!(dns_probe_reply(&good, 0x1234));
        let mut bad_id = good.clone();
        bad_id[0] = 0;
        assert!(!dns_probe_reply(&bad_id, 0x1234));
        let mut truncated = good.clone();
        truncated[6..8].copy_from_slice(&2_u16.to_be_bytes());
        assert!(!dns_probe_reply(&truncated, 0x1234));
        let mut no_answer = good.clone();
        no_answer[6..8].copy_from_slice(&0_u16.to_be_bytes());
        let question_end = 12 + 13;
        no_answer.truncate(question_end);
        assert!(!dns_probe_reply(&no_answer, 0x1234));
        let aaaa = response(0x8180, 1, 28, 16);
        assert!(!dns_probe_reply(&aaaa, 0x1234));
    }

    fn c_query_bytes() -> Vec<u8> {
        vec![
            0, 29, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]
    }

    fn dns_header(id: u16, flags: u16, answers: u16) -> Vec<u8> {
        let mut msg = vec![0u8; 12];
        msg[0..2].copy_from_slice(&id.to_be_bytes());
        msg[2..4].copy_from_slice(&flags.to_be_bytes());
        msg[4..6].copy_from_slice(&1_u16.to_be_bytes());
        msg[6..8].copy_from_slice(&answers.to_be_bytes());
        msg.extend_from_slice(&[7]);
        msg.extend_from_slice(b"example");
        msg.extend_from_slice(&[3]);
        msg.extend_from_slice(b"com");
        msg.push(0);
        msg.extend_from_slice(&[0, 1, 0, 1]);
        msg
    }

    fn dns_answer(mut msg: Vec<u8>, kind: u16, class: u16, rdlen: u16) -> Vec<u8> {
        msg.extend_from_slice(&[0xc0, 12]);
        msg.extend_from_slice(&kind.to_be_bytes());
        msg.extend_from_slice(&class.to_be_bytes());
        msg.extend_from_slice(&60_u32.to_be_bytes());
        msg.extend_from_slice(&rdlen.to_be_bytes());
        msg.extend(std::iter::repeat_n(0x7f, usize::from(rdlen)));
        msg
    }

    fn doh_output(name: &str, response: &[u8]) -> String {
        let parsed = doh_response_parse(response, &DohQuery::Message(dns_query_message(0x1234)));
        let state = match parsed.state {
            DohState::NeedMore => 0,
            DohState::Complete => 1,
            DohState::Invalid => 2,
        };
        let rc = parsed.rc;
        let unsupported = if parsed.state == DohState::Invalid {
            1
        } else {
            0
        };
        format!(
            "doh case={name} state={state} rc={rc} status={} dns={} unsupported={} complete={} chunked={} has_length={} body={}\n",
            parsed.status,
            u8::from(parsed.dns_reply),
            unsupported,
            u8::from(parsed.state == DohState::Complete),
            u8::from(parsed.chunked),
            u8::from(parsed.has_length),
            parsed.body_bytes
        )
    }

    #[test]
    fn dns_health_c_differential_matches_current_donor() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        assert_eq!(dns_query_frame(0), c_query_bytes());
        let mut output = format!("query hex={}\n", hex(&dns_query_frame(0)));
        for (name, msg, expected) in [
            (
                "valid-a",
                dns_answer(dns_header(0x1234, 0x8180, 1), 1, 1, 4),
                true,
            ),
            (
                "aaaa-only",
                dns_answer(dns_header(0x1234, 0x8180, 1), 28, 1, 16),
                false,
            ),
            (
                "tc",
                dns_answer(dns_header(0x1234, 0x8380, 1), 1, 1, 4),
                false,
            ),
            (
                "rcode",
                dns_answer(dns_header(0x1234, 0x8183, 1), 1, 1, 4),
                false,
            ),
            (
                "opcode",
                dns_answer(dns_header(0x1234, 0x8980, 1), 1, 1, 4),
                false,
            ),
            (
                "wrong-class",
                dns_answer(dns_header(0x1234, 0x8180, 1), 1, 2, 4),
                false,
            ),
            (
                "short-a",
                dns_answer(dns_header(0x1234, 0x8180, 1), 1, 1, 3),
                false,
            ),
            (
                "extra-answers",
                dns_answer(
                    dns_answer(dns_header(0x1234, 0x8180, 2), 1, 1, 4),
                    28,
                    1,
                    16,
                ),
                true,
            ),
            (
                "wrong-question",
                {
                    let mut msg = dns_header(0x1234, 0x8180, 1);
                    msg.truncate(12);
                    msg.extend_from_slice(&[3, b'w', b'w', b'w']);
                    msg.extend_from_slice(&[7]);
                    msg.extend_from_slice(b"example");
                    msg.extend_from_slice(&[3]);
                    msg.extend_from_slice(b"com");
                    msg.push(0);
                    msg.extend_from_slice(&[0, 1, 0, 1]);
                    dns_answer(msg, 1, 1, 4)
                },
                false,
            ),
        ] {
            let actual = dns_probe_reply(&msg, 0x1234);
            output.push_str(&format!("dns case={name} result={}\n", u8::from(actual)));
            assert_eq!(actual, expected, "case={name}");
        }

        let dns = dns_answer(dns_header(0x1234, 0x8180, 1), 1, 1, 4);
        let length = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            dns.len()
        );
        let mut response = length.into_bytes();
        response.extend_from_slice(&dns);
        output.push_str(&doh_output("length", &response));

        let mut chunked = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        chunked.extend_from_slice(format!("{:x}\r\n", dns.len()).as_bytes());
        chunked.extend_from_slice(&dns);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        output.push_str(&doh_output("chunked", &chunked));

        let wrong_type =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\nx";
        output.push_str(&doh_output("wrong-type", wrong_type));
        let http_413 = b"HTTP/1.1 413 Too Large\r\nContent-Type: application/dns-message\r\nContent-Length: 1\r\n\r\nx";
        output.push_str(&doh_output("http-413", http_413));
        let too_big = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 5000\r\n\r\n";
        output.push_str(&doh_output("too-big", too_big));
        let mut incomplete = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            dns.len()
        )
        .into_bytes();
        incomplete.extend_from_slice(&dns[..3]);
        output.push_str(&doh_output("incomplete", &incomplete));

        if let Ok(path) = std::env::var("R2O_DNS_HEALTH_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains("dns case=valid-a result=1"));
        assert!(output.contains("doh case=length state=1 rc=1 status=200 dns=1"));
    }

    fn reply_for(id: u16) -> Vec<u8> {
        let mut reply = response(0x8180, 1, 1, 4);
        reply[0..2].copy_from_slice(&id.to_be_bytes());
        reply
    }

    fn test_server_config() -> (rustls::ServerConfig, CertificateDer<'static>) {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der()),
        );
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key)
            .unwrap();
        (config, certificate_der)
    }

    #[test]
    fn matching_dns_spki_still_requires_valid_name_and_dates() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::UnixTime;
        use sha2::{Digest, Sha256};

        let (_, der) = test_server_config();
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        let pin = Sha256::digest(cert.tbs_certificate.subject_pki.raw).into();
        let verifier = DnsSpkiVerifier::new(
            pin,
            rustls::crypto::ring::default_provider().signature_verification_algorithms,
        );
        let check = |name, seconds| {
            let name = ServerName::try_from(name).unwrap();
            let now = UnixTime::since_unix_epoch(Duration::from_secs(seconds));
            verifier.verify_server_cert(&der, &[], &name, &[], now)
        };
        assert!(check("localhost", 1_800_000_000).is_ok());
        assert!(check("other.example", 1_800_000_000).is_err());
        assert_eq!(
            check("localhost", 0).unwrap_err(),
            rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidYet)
        );
        assert_eq!(
            check("localhost", 253_402_300_799).unwrap_err(),
            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired)
        );
    }

    #[test]
    fn dns_health_rejects_untrusted_tls_and_missing_bootstrap() {
        let (config, _) = test_server_config();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let config = Arc::new(config);
            for _ in 0..2 {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(Arc::clone(&config)).unwrap(),
                    socket,
                );
                assert!(stream.read(&mut [0u8; 1]).is_err());
            }
        });
        let mut service = DnsService {
            host: "127.0.0.1".into(),
            sni: "localhost".into(),
            path: "/dns-query".into(),
            port,
            ..Default::default()
        };
        for protocol in ["doh", "dot"] {
            service.protocol = protocol.into();
            let result = probe_dns_health(&service, None, Duration::from_secs(2));
            assert!(result.tcp_reachable);
            assert!(!result.tls_handshake);
            assert!(!result.dns_reply);
            assert_eq!(result.failure, Some(DnsHealthFailure::Certificate));
            assert!(result.reason.contains("UnknownIssuer"), "{}", result.reason);
        }
        server.join().unwrap();
        service.host = "example.test".into();
        let missing = probe_dns_health(&service, None, Duration::from_secs(2));
        assert!(!missing.tcp_reachable);
        assert_eq!(missing.failure, Some(DnsHealthFailure::Configuration));
        assert!(missing.reason.contains("bootstrap"));
    }

    #[test]
    fn doh_json_requires_matching_question_and_an_address_on_its_answer_chain() {
        let query = DohQuery::Json;
        let reply = r#"{"Status":0,"TC":false,"Question":[{"name":"Example.COM.","type":1}],"Answer":[{"name":"example.com.","type":5,"data":"target.example."},{"name":"target.example.","type":1,"data":"192.0.2.8"}]}"#;
        assert!(query.validate_reply(reply.as_bytes()));
        for (from, to) in [
            ("Example.COM.", "wrong.example."),
            ("\"type\":1", "\"type\":28"),
            ("\"Status\":0", "\"Status\":3"),
            ("\"TC\":false", "\"TC\":true"),
            ("\"data\":\"target.example.\"", "\"data\":\"example.com.\""),
            ("192.0.2.8", "invalid"),
        ] {
            assert!(!query.validate_reply(reply.replace(from, to).as_bytes()));
        }
        assert!(!query.validate_reply(&vec![b' '; DOH_BODY_MAX + 1]));
        assert_eq!(
            query.request_path("/resolve?profile=a%2Fb").unwrap(),
            "/resolve?profile=a%2Fb&name=example.com&type=1"
        );
        assert_eq!(
            query.request_path("/resolve?").unwrap(),
            "/resolve?name=example.com&type=1"
        );
        for path in [
            "/resolve?%6eame=bad.example",
            "/resolve?type=28",
            "/resolve#fragment",
        ] {
            assert!(query.request_path(path).is_err());
        }
    }

    #[test]
    fn loopback_doh_json_http1_distinguishes_a_refusal_from_a_dns_answer() {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;

        let (config, cert) = test_server_config();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let config = Arc::new(config);
            for (status, mime, body) in [
                (
                    "200 OK",
                    "application/json",
                    r#"{"Status":0,"TC":false,"Question":[{"name":"example.com.","type":1}],"Answer":[{"name":"example.com.","type":1,"data":"192.0.2.8"}]}"#,
                ),
                ("403 Forbidden", "text/html", "Denied"),
            ] {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut tls = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(Arc::clone(&config)).unwrap(),
                    socket,
                );
                let mut reader = BufReader::new(&mut tls);
                let mut request = Vec::new();
                while let Some(line) = reader.by_ref().lines().next() {
                    let line = line.unwrap();
                    if line.is_empty() {
                        break;
                    }
                    request.push(line);
                }
                assert_eq!(
                    request[0],
                    "GET /resolve?profile=a%2Fb&name=example.com&type=1 HTTP/1.1"
                );
                assert!(
                    request
                        .iter()
                        .any(|header| header == "Accept: application/dns-json")
                );
                assert!(
                    !request
                        .iter()
                        .any(|header| header.starts_with("Content-Length:"))
                );
                write!(tls, "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                tls.flush().unwrap();
            }
        });
        let mut service = r2k_core::dns_config::parse_keenetic(&format!(
            "proxy-https:\nserver-https:\n  uri: https://localhost:{port}/resolve?profile=a%2Fb\n  format: json\n"
        )).remove(0);
        service.host = "127.0.0.1".into();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let roots = Arc::new(roots);
        for (status, failure) in [(200, None), (403, Some(DnsHealthFailure::Server))] {
            let result = probe_dns_health_with_roots(
                &service,
                None,
                Duration::from_secs(3),
                Arc::clone(&roots),
            );
            assert_eq!(result.http_status, status, "{result:?}");
            assert_eq!(result.failure, failure, "{result:?}");
            assert_eq!(result.dns_reply, failure.is_none());
        }
        server.join().unwrap();
    }

    #[test]
    fn loopback_doh_health_checks_query_and_distinguishes_server_errors() {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;
        let (config, cert) = test_server_config();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let config = Arc::new(config);
            for (status, reply) in [
                ("200 OK", reply_for(DNS_QUERY_ID_DOH)),
                ("200 OK", reply_for(DNS_QUERY_ID_DOH + 1)),
                ("403 Forbidden", Vec::new()),
            ] {
                let (socket, _) = listener.accept().unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(Arc::clone(&config)).unwrap(),
                    socket,
                );
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line, "POST /dns-query?route=one HTTP/1.1\r\n");
                let mut content_length = 0usize;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0u8; content_length];
                reader.read_exact(&mut body).unwrap();
                assert_eq!(body, dns_query_message(DNS_QUERY_ID_DOH));
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(&reply).unwrap();
                stream.flush().unwrap();
            }
        });
        let service = DnsService {
            protocol: "doh".into(),
            host: "127.0.0.1".into(),
            sni: "localhost".into(),
            path: "/dns-query?route=one".into(),
            bootstrap_dns: String::new(),
            source: "test".into(),
            port,
            keenetic: None,
        };
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let roots = Arc::new(roots);
        let probe = || {
            probe_dns_health_with_roots(&service, None, Duration::from_secs(3), Arc::clone(&roots))
        };
        let result = probe();
        let wrong_dns = probe();
        let refused = probe();
        server.join().unwrap();
        assert!(result.tcp_reachable, "{}", result.reason);
        assert!(result.tls_handshake, "{}", result.reason);
        assert_eq!(result.http_status, 200);
        assert!(result.dns_reply, "{}", result.reason);
        assert!(result.answer_rtt_ms.is_some());
        assert_eq!(wrong_dns.http_status, 200);
        assert_eq!(wrong_dns.failure, Some(DnsHealthFailure::DnsResponse));
        assert_eq!(wrong_dns.answer_rtt_ms, None);
        assert_eq!(refused.http_status, 403);
        assert_eq!(refused.failure, Some(DnsHealthFailure::Server));
        assert!(!refused.dns_reply);
    }

    #[test]
    fn loopback_dot_health_returns_valid_length_prefixed_reply() {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        use std::net::TcpListener;
        let (config, cert) = test_server_config();
        let (_, leaf) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
        let good_pin = Sha256::digest(leaf.tbs_certificate.subject_pki.raw);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let config = Arc::new(config);
            for valid in [true, true, false] {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(Arc::clone(&config)).unwrap(),
                    socket,
                );
                let mut query = [0u8; 31];
                if !valid {
                    assert!(stream.read_exact(&mut query).is_err());
                    continue;
                }
                stream.read_exact(&mut query).unwrap();
                assert_eq!(&query[..2], &[0, 29]);
                let reply = reply_for(DNS_QUERY_ID_DOT);
                stream
                    .write_all(&(reply.len() as u16).to_be_bytes())
                    .unwrap();
                stream.write_all(&reply).unwrap();
                stream.flush().unwrap();
            }
        });
        let service = DnsService {
            protocol: "dot".into(),
            host: "127.0.0.1".into(),
            sni: "localhost".into(),
            path: String::new(),
            bootstrap_dns: String::new(),
            source: "test".into(),
            port,
            keenetic: None,
        };
        let pinned_service = |pin: &[u8]| {
            let pin = base64::engine::general_purpose::STANDARD.encode(pin);
            r2k_core::dns_config::parse_keenetic(&format!(
                "proxy-tls:\nserver-tls:\n  address: 127.0.0.1\n  port: {port}\n  sni: localhost\n  spki: {pin}\n"
            )).remove(0)
        };
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let timeout = Duration::from_secs(3);
        let roots = Arc::new(roots);
        for result in [
            probe_dns_health_with_roots(&service, None, timeout, Arc::clone(&roots)),
            probe_dns_health(&pinned_service(&good_pin), None, timeout),
        ] {
            assert!(result.tcp_reachable, "{}", result.reason);
            assert!(result.tls_handshake, "{}", result.reason);
            assert!(result.dns_reply, "{}", result.reason);
        }
        let rejected = probe_dns_health_with_roots(&pinned_service(&[0; 32]), None, timeout, roots);
        assert_eq!(
            rejected.failure,
            Some(DnsHealthFailure::Certificate),
            "{rejected:?}"
        );
        assert!(rejected.reason.contains("SPKI"));
        assert!(!rejected.dns_reply);
        server.join().unwrap();
    }

    #[test]
    fn loopback_doq_health_uses_stream_zero_and_zero_id() {
        use std::net::UdpSocket;
        let (mut rustls_config, cert) = test_server_config();
        rustls_config.alpn_protocols = vec![b"doq".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config).unwrap();
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(Arc::new(quinn::TransportConfig::default()));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let endpoint = {
                let _guard = runtime.enter();
                quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(server_config),
                    socket,
                    Arc::new(quinn::TokioRuntime),
                )
                .unwrap()
            };
            runtime.block_on(async {
                let untrusted = endpoint.accept().await.unwrap();
                assert!(untrusted.await.is_err());
                let incoming = endpoint.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let mut query = [0u8; 31];
                recv.read_exact(&mut query).await.unwrap();
                assert_eq!(&query[..2], &[0, 29]);
                assert_eq!(&query[2..4], &[0, 0]);
                let reply = reply_for(0);
                let mut frame = Vec::with_capacity(reply.len() + 2);
                frame.extend_from_slice(&(reply.len() as u16).to_be_bytes());
                frame.extend_from_slice(&reply);
                send.write_all(&frame).await.unwrap();
                send.finish().unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
            });
            endpoint.close(quinn::VarInt::from_u32(0), b"");
        });
        let service = DnsService {
            protocol: "doq".into(),
            host: "127.0.0.1".into(),
            sni: "localhost".into(),
            path: String::new(),
            bootstrap_dns: String::new(),
            source: "test".into(),
            port,
            keenetic: None,
        };
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let untrusted = probe_dns_health(&service, None, Duration::from_secs(3));
        assert_eq!(
            untrusted.failure,
            Some(DnsHealthFailure::Certificate),
            "{}",
            untrusted.reason
        );
        assert!(!untrusted.dns_reply);
        let result =
            probe_dns_health_with_roots(&service, None, Duration::from_secs(3), Arc::new(roots));
        server.join().unwrap();
        assert!(result.tcp_reachable, "{}", result.reason);
        assert!(result.tls_handshake, "{}", result.reason);
        assert!(result.dns_reply, "{}", result.reason);
    }

    #[test]
    fn idle_doq_endpoint_hits_network_deadline() {
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let service = DnsService {
            protocol: "doq".into(),
            host: "127.0.0.1".into(),
            sni: "localhost".into(),
            port: listener.local_addr().unwrap().port(),
            ..Default::default()
        };
        let result = probe_dns_health(&service, None, Duration::from_millis(50));
        assert_eq!(
            result.failure,
            Some(DnsHealthFailure::Network),
            "{}",
            result.reason
        );
        assert!(!result.dns_reply);
        assert_eq!(result.answer_rtt_ms, None);
    }

    #[test]
    fn loopback_doh3_requires_matching_dns_reply_on_http3() {
        use base64::Engine;
        use bytes::Bytes;
        use std::net::UdpSocket;

        let (mut tls, cert) = test_server_config();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let socket = UdpSocket::bind("[::1]:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let endpoint = quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(config),
                    socket,
                    Arc::new(quinn::TokioRuntime),
                )
                .unwrap();
                assert!(endpoint.accept().await.unwrap().await.is_err());
                for (status, id, duplicate_type) in [
                    (200, 0, false),
                    (200, 1, false),
                    (403, 0, false),
                    (200, 0, true),
                ] {
                    let connection = endpoint.accept().await.unwrap().await.unwrap();
                    let mut h3 = h3::server::builder()
                        .build(h3_quinn::Connection::new(connection.clone()))
                        .await
                        .unwrap();
                    let (request, mut stream) = h3
                        .accept()
                        .await
                        .unwrap()
                        .unwrap()
                        .resolve_request()
                        .await
                        .unwrap();
                    assert_eq!(request.method(), http::Method::GET);
                    assert_eq!(request.uri().path(), "/dns-query");
                    let encoded = request
                        .uri()
                        .query()
                        .unwrap()
                        .strip_prefix("profile=a%2Fb&dns=")
                        .unwrap();
                    assert_eq!(
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(encoded)
                            .unwrap(),
                        dns_query_message(0)
                    );
                    assert_eq!(request.headers()["accept"], "application/dns-message");
                    assert!(stream.recv_data().await.unwrap().is_none());
                    let reply = reply_for(id);
                    let mut response = http::Response::builder()
                        .status(status)
                        .header("content-type", "application/dns-message")
                        .header("content-length", reply.len());
                    if duplicate_type {
                        response = response.header("content-type", "text/html");
                    }
                    stream
                        .send_response(response.body(()).unwrap())
                        .await
                        .unwrap();
                    stream.send_data(Bytes::from(reply)).await.unwrap();
                    stream.finish().await.unwrap();
                    let _ = tokio::time::timeout(Duration::from_secs(1), connection.closed()).await;
                }
            });
        });
        let configuration = format!(
            "config dnsproxy 'global'\n option enabled '1'\n option http3 '1'\n\
             config dnsproxy 'servers'\n list fallback 'https://localhost:{port}/dns-query?profile=a%2Fb'\n"
        );
        let mut service = r2k_core::dns_config::parse_dnsproxy(&configuration)
            .into_iter()
            .find(|service| service.protocol == "doh3")
            .unwrap();
        // Контроллер подставляет IP, полученный через bootstrap, оставляя имя сертификата.
        service.host = "::1".into();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let roots = Arc::new(roots);
        let probe = |service: &DnsService| {
            probe_dns_health_with_roots(service, None, Duration::from_secs(3), Arc::clone(&roots))
        };
        let unsupported = probe(&service);
        assert_eq!(unsupported.failure, Some(DnsHealthFailure::Configuration));
        assert!(!unsupported.dns_reply);
        // Остальные проверки проверяют транспорт клиента, который сохраняет query.
        service.source.clear();
        let conflicting = probe(&DnsService {
            path: "/dns-query?%64ns=other".into(),
            ..service.clone()
        });
        assert_eq!(conflicting.failure, Some(DnsHealthFailure::Configuration));
        let wrong_name = probe(&DnsService {
            sni: "wrong-name.example".into(),
            ..service.clone()
        });
        assert_eq!(
            wrong_name.failure,
            Some(DnsHealthFailure::Certificate),
            "{}",
            wrong_name.reason
        );
        assert!(!wrong_name.dns_reply);
        let valid = probe(&service);
        let wrong = probe(&service);
        let denied = probe(&service);
        let ambiguous = probe(&service);
        server.join().unwrap();
        assert!(valid.tls_handshake && valid.dns_reply, "{}", valid.reason);
        assert_eq!(valid.http_status, 200);
        assert!(valid.answer_rtt_ms.is_some());
        assert!(wrong.tls_handshake && !wrong.dns_reply);
        assert_eq!(wrong.http_status, 200);
        assert_eq!(wrong.failure, Some(DnsHealthFailure::DnsResponse));
        assert_eq!(wrong.answer_rtt_ms, None);
        assert_eq!(denied.http_status, 403);
        assert_eq!(denied.failure, Some(DnsHealthFailure::Server));
        assert!(!denied.dns_reply);
        assert_eq!(ambiguous.http_status, 200);
        assert_eq!(ambiguous.failure, Some(DnsHealthFailure::DnsResponse));
        assert!(!ambiguous.dns_reply);
    }

    #[test]
    fn doh_parser_honours_length_chunked_and_limits() {
        let body = response(0x8180, 1, 1, 4);
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: "
                .to_vec();
        response.extend_from_slice(format!("{}\r\n\r\n", body.len()).as_bytes());
        response.extend_from_slice(&body);
        let parsed = doh_response_parse(&response, &DohQuery::Message(dns_query_message(0x1234)));
        assert_eq!(parsed.state, DohState::Complete);
        assert!(parsed.dns_reply);
        assert_eq!(parsed.body_bytes, body.len());

        let mut chunked = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        chunked.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        chunked.extend_from_slice(&body);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let parsed = doh_response_parse(&chunked, &DohQuery::Message(dns_query_message(0x1234)));
        assert_eq!(parsed.state, DohState::Complete);
        assert!(parsed.dns_reply);

        let bad_type = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\nx";
        assert_eq!(
            doh_response_parse(bad_type, &DohQuery::Message(dns_query_message(0x1234))).state,
            DohState::Invalid
        );
        let too_big = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            DOH_BODY_MAX + 1
        );
        assert_eq!(
            doh_response_parse(
                too_big.as_bytes(),
                &DohQuery::Message(dns_query_message(0x1234))
            )
            .state,
            DohState::Invalid
        );
    }
}
