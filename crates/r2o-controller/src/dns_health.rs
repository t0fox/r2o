//! Health-пробы DoH/DoT/DoQ из `core/verify.c` current D2O main.
//!
//! DNS-запрос — публичный `example.com A`, без имени клиента. DoT/DoQ
//! используют length-prefixed frame (RFC 7858/RFC 9250), DoQ — stream 0 и
//! нулевой ID, DoT — ID соединения. DoH — RFC 8484 POST на `path`.

use r2k_core::dns_config::DnsService;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DOH_HEADER_MAX: usize = 8192;
pub const DOH_BODY_MAX: usize = 4096;
const DOH_RESPONSE_MAX: usize = DOH_HEADER_MAX + DOH_BODY_MAX * 2;
const DNS_FRAME_MAX: usize = 4096;
const DNS_QUERY_ID_DOH: u16 = 0x5a71;
const DNS_QUERY_ID_DOT: u16 = 1;

/// Результат health-пробы для controller/live.json.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsHealthResult {
    pub tcp_reachable: bool,
    pub tls_handshake: bool,
    pub http_status: i32,
    pub dns_reply: bool,
    pub reason: String,
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
    rc: i32,
    status: i32,
    body_bytes: usize,
    body_expected: usize,
    has_length: bool,
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

fn doh_parse_headers(data: &[u8]) -> Option<DohHeaders> {
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
        if name.eq_ignore_ascii_case("content-type") {
            let value = value.split(|byte| *byte == b';').next().unwrap_or_default();
            let value = trim_http_value(value);
            if content_type_ok || !value.eq_ignore_ascii_case(b"application/dns-message") {
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

fn doh_response_parse(response: &[u8], dns_id: u16) -> DohResponse {
    let Some(sep) = doh_header_end(response) else {
        return DohResponse {
            state: if response.len() >= DOH_HEADER_MAX {
                DohState::Invalid
            } else {
                DohState::NeedMore
            },
            rc: if response.len() >= DOH_HEADER_MAX {
                -1
            } else {
                0
            },
            status: 0,
            body_bytes: 0,
            body_expected: 0,
            has_length: false,
            chunked: false,
            dns_reply: false,
            reason: "DoH: некорректные HTTP заголовки".into(),
        };
    };
    if sep > DOH_HEADER_MAX {
        return invalid_doh("DoH: некорректные HTTP заголовки");
    }
    let Some(headers) = doh_parse_headers(&response[..sep]) else {
        return invalid_doh("DoH: некорректные HTTP заголовки");
    };
    if headers.status != 200 {
        return DohResponse {
            state: DohState::Invalid,
            rc: 0,
            status: headers.status,
            body_bytes: 0,
            body_expected: 0,
            has_length: false,
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
                rc: -1,
                status: headers.status,
                body_bytes: 0,
                body_expected: headers.body_len,
                has_length: false,
                chunked: false,
                dns_reply: false,
                reason: "DoH: неполный или слишком большой DNS body".into(),
            };
        }
        let body = &response[body_offset..body_offset + headers.body_len];
        return finish_doh(body, headers, dns_id);
    }
    let mut body = [0u8; DOH_BODY_MAX];
    match doh_decode_chunked(&response[body_offset..], &mut body) {
        Ok(Some(length)) => finish_doh(&body[..length], headers, dns_id),
        Ok(None) => DohResponse {
            state: DohState::NeedMore,
            rc: 0,
            status: headers.status,
            body_bytes: 0,
            body_expected: 0,
            has_length: false,
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
        rc: -1,
        status: 0,
        body_bytes: 0,
        body_expected: 0,
        has_length: false,
        chunked: false,
        dns_reply: false,
        reason: reason.into(),
    }
}

fn finish_doh(body: &[u8], headers: DohHeaders, dns_id: u16) -> DohResponse {
    if !dns_probe_reply(body, dns_id) {
        return DohResponse {
            state: DohState::Invalid,
            rc: 0,
            status: headers.status,
            body_bytes: body.len(),
            body_expected: headers.body_len,
            has_length: headers.has_length,
            chunked: headers.chunked,
            dns_reply: false,
            reason: "DoH: HTTP завершён, DNS-ответ некорректен".into(),
        };
    }
    DohResponse {
        state: DohState::Complete,
        rc: 1,
        status: headers.status,
        body_bytes: body.len(),
        body_expected: if headers.has_length {
            headers.body_len
        } else {
            body.len()
        },
        has_length: headers.has_length,
        chunked: headers.chunked,
        dns_reply: true,
        reason: "DoH: корректный RFC 8484 DNS-ответ".into(),
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
        if service.protocol.eq_ignore_ascii_case("doh") {
            443
        } else {
            853
        }
    } else {
        service.port
    };
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(address, port));
    }
    (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("DNS: {error}"))?
        .next()
        .ok_or_else(|| "DNS: endpoint IP не получен".into())
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

fn set_tcp_timeout(stream: &TcpStream, deadline: Instant) -> Result<(), String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("DNS: истёк срок".into());
    }
    stream
        .set_read_timeout(Some(left))
        .and_then(|()| stream.set_write_timeout(Some(left)))
        .map_err(|error| format!("DNS: timeout: {error}"))
}

fn read_dns_frame(stream: &mut impl Read, id: u16, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .map_err(|error| format!("DNS: frame: {error}"))?;
    let length = usize::from(u16::from_be_bytes(header));
    if !(14..=DNS_FRAME_MAX).contains(&length) {
        return Err("DNS: неверная длина frame".into());
    }
    let _ = deadline;
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|error| format!("DNS: frame body: {error}"))?;
    Ok(body)
}

#[cfg(target_os = "linux")]
fn connect_tcp(
    address: SocketAddr,
    mark: Option<u32>,
    timeout: Duration,
) -> Result<TcpStream, String> {
    crate::fetch::connect_target(address, mark, timeout).map_err(|error| error.to_string())
}

#[cfg(not(target_os = "linux"))]
fn connect_tcp(
    address: SocketAddr,
    mark: Option<u32>,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let _ = mark;
    TcpStream::connect_timeout(&address, timeout).map_err(|error| error.to_string())
}

fn tls_connect(
    stream: TcpStream,
    name: &str,
    alpn: &[Vec<u8>],
    deadline: Instant,
) -> Result<
    (
        rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
        Option<bool>,
        Option<Vec<u8>>,
    ),
    String,
> {
    let roots = rustls::RootCertStore::empty();
    let mut connection =
        crate::r2o_tls::r2o_tls_client_connection_with_alpn(name, false, None, roots, alpn)?;
    let mut stream = stream;
    while connection.is_handshaking() {
        set_tcp_timeout(&stream, deadline)?;
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
                    return Err(format!("TLS: {error}"));
                }
            }
            Err(error) => return Err(format!("TLS: {error}")),
        }
    }
    let peer_name = connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .and_then(|certificate| {
            crate::response::https_certificate_name_matches(certificate.as_ref(), name)
        });
    let alpn = connection.alpn_protocol().map(<[u8]>::to_vec);
    Ok((
        rustls::StreamOwned::new(connection, stream),
        peer_name,
        alpn,
    ))
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

fn doh_authority(service: &DnsService) -> Result<String, String> {
    let host = if service.sni.is_empty() {
        service.host.as_str()
    } else {
        service.sni.as_str()
    };
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
    Ok(if service.port == 443 {
        authority_host
    } else {
        format!("{authority_host}:{}", service.port)
    })
}

fn probe_doh(service: &DnsService, mark: Option<u32>, deadline: Instant) -> DnsHealthResult {
    let mut result = DnsHealthResult::default();
    if let Err(reason) = doh_validate(service) {
        result.reason = reason;
        return result;
    }
    let address = match resolve_service(service) {
        Ok(address) => address,
        Err(reason) => {
            result.reason = reason;
            return result;
        }
    };
    let timeout = deadline.saturating_duration_since(Instant::now());
    let stream = match connect_tcp(address, mark, timeout) {
        Ok(stream) => {
            result.tcp_reachable = true;
            stream
        }
        Err(error) => {
            result.reason = format!("DoH: TCP endpoint недоступен: {error}");
            return result;
        }
    };
    let name = if service.sni.is_empty() {
        service.host.as_str()
    } else {
        service.sni.as_str()
    };
    let (mut stream, peer_name, _) =
        match tls_connect(stream, name, &[b"http/1.1".to_vec()], deadline) {
            Ok(tls) => {
                result.tls_handshake = true;
                tls
            }
            Err(reason) => {
                result.reason = format!("DoH: {reason}");
                return result;
            }
        };
    let authority = match doh_authority(service) {
        Ok(authority) => authority,
        Err(reason) => {
            result.reason = reason;
            return result;
        }
    };
    let path = if service.path.is_empty() {
        "/"
    } else {
        service.path.as_str()
    };
    let message = dns_query_message(DNS_QUERY_ID_DOH);
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        message.len()
    );
    if stream.write_all(request.as_bytes()).is_err()
        || stream.write_all(&message).is_err()
        || stream.flush().is_err()
    {
        result.reason = "DoH: отправка запроса не удалась".into();
        return result;
    }
    let mut response = Vec::with_capacity(DOH_RESPONSE_MAX);
    let parsed = loop {
        let parsed = doh_response_parse(&response, DNS_QUERY_ID_DOH);
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
        set_tcp_timeout(&mut stream.sock, deadline).ok();
        let mut buffer = [0u8; 1024];
        match stream.read(&mut buffer) {
            Ok(0) => break parsed,
            Ok(length) => response.extend_from_slice(&buffer[..length]),
            Err(_) => break parsed,
        }
    };
    result.http_status = parsed.status;
    result.dns_reply = parsed.dns_reply && peer_name != Some(false);
    result.reason = if parsed.state == DohState::Complete && peer_name == Some(false) {
        "DoH: имя TLS-сервера не совпало".into()
    } else {
        parsed.reason
    };
    result
}

fn probe_dot(service: &DnsService, mark: Option<u32>, deadline: Instant) -> DnsHealthResult {
    let mut result = DnsHealthResult::default();
    let address = match resolve_service(service) {
        Ok(address) => address,
        Err(reason) => {
            result.reason = reason;
            return result;
        }
    };
    let timeout = deadline.saturating_duration_since(Instant::now());
    let stream = match connect_tcp(address, mark, timeout) {
        Ok(stream) => {
            result.tcp_reachable = true;
            stream
        }
        Err(error) => {
            result.reason = format!("DoT: нет TCP: {error}");
            return result;
        }
    };
    let name = if service.sni.is_empty() {
        service.host.as_str()
    } else {
        service.sni.as_str()
    };
    let (mut stream, peer_name, _) = match tls_connect(stream, name, &[], deadline) {
        Ok(tls) => {
            result.tls_handshake = true;
            tls
        }
        Err(reason) => {
            result.reason = format!("DoT: {reason}");
            return result;
        }
    };
    let query = dns_query_frame(DNS_QUERY_ID_DOT);
    if stream.write_all(&query).is_err() || stream.flush().is_err() {
        result.reason = "DoT: отправка не удалась".into();
        return result;
    }
    set_tcp_timeout(&mut stream.sock, deadline).ok();
    match read_dns_frame(&mut stream, DNS_QUERY_ID_DOT, deadline) {
        Ok(body) => {
            result.dns_reply = dns_probe_reply(&body, DNS_QUERY_ID_DOT) && peer_name != Some(false);
            result.reason = if result.dns_reply {
                "DoT: получен корректный DNS-ответ".into()
            } else {
                "DoT: нет подтверждённого DNS-ответа".into()
            };
        }
        Err(error) => result.reason = format!("DoT: {error}"),
    }
    result
}

#[derive(Debug)]
struct DnsQuicVerifier {
    host: String,
    name: Arc<Mutex<i8>>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for DnsQuicVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.name.lock().unwrap() =
            crate::r2o_quic_http3::r2o_quic_peer_name(end_entity.as_ref(), &self.host);
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn probe_doq(service: &DnsService, mark: Option<u32>, deadline: Instant) -> DnsHealthResult {
    let mut result = DnsHealthResult::default();
    let address = match resolve_service(service) {
        Ok(address) => address,
        Err(reason) => {
            result.reason = reason;
            return result;
        }
    };
    let host = if service.sni.is_empty() {
        service.host.as_str()
    } else {
        service.sni.as_str()
    };
    let timeout = deadline.saturating_duration_since(Instant::now());
    let socket = match crate::r2o_quic_http3::r2o_quic_http3_udp_socket_fresh(address, mark) {
        Ok((socket, _)) => socket,
        Err(error) => {
            result.reason = format!("DoQ: UDP: {}", error.source);
            return result;
        }
    };
    let provider = rustls::crypto::ring::default_provider();
    let name = Arc::new(Mutex::new(-1_i8));
    let verifier = Arc::new(DnsQuicVerifier {
        host: host.to_owned(),
        name: Arc::clone(&name),
        algorithms: provider.signature_verification_algorithms.clone(),
    });
    let mut tls = match rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
    {
        Ok(builder) => builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
        Err(error) => {
            result.reason = format!("DoQ: TLS config: {error}");
            return result;
        }
    };
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let crypto = match quinn::crypto::rustls::QuicClientConfig::try_from(tls) {
        Ok(crypto) => crypto,
        Err(error) => {
            result.reason = format!("DoQ: QUIC TLS: {error}");
            return result;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            result.reason = format!("DoQ: нет Tokio runtime: {error}");
            return result;
        }
    };
    let quinn_runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
    let mut endpoint = {
        let _guard = runtime.enter();
        match quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            quinn_runtime,
        ) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                result.reason = format!("DoQ: endpoint: {error}");
                return result;
            }
        }
    };
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(quinn::TransportConfig::default()));
    endpoint.set_default_client_config(client_config);
    let query = dns_query_frame(0);
    let result_from_runtime: Result<(Vec<u8>, i8), String> = runtime.block_on(async {
        let connecting = endpoint
            .connect(address, host)
            .map_err(|error| format!("DoQ: {error}"))?;
        let connection = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| "DoQ: timeout".to_owned())?
            .map_err(|error| format!("DoQ: {error}"))?;
        let peer = *name.lock().unwrap();
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| format!("DoQ: stream: {error}"))?;
        send.write_all(&query)
            .await
            .map_err(|error| format!("DoQ: send: {error}"))?;
        send.finish()
            .map_err(|error| format!("DoQ: finish: {error}"))?;
        let mut header = [0u8; 2];
        recv.read_exact(&mut header)
            .await
            .map_err(|error| format!("DoQ: frame: {error}"))?;
        let length = usize::from(u16::from_be_bytes(header));
        if !(14..=DNS_FRAME_MAX).contains(&length) {
            return Err("DoQ: неверная длина frame".to_owned());
        }
        let mut body = vec![0u8; length];
        recv.read_exact(&mut body)
            .await
            .map_err(|error| format!("DoQ: frame body: {error}"))?;
        Ok::<(Vec<u8>, i8), String>((body, peer))
    });
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    match result_from_runtime {
        Ok((body, peer)) => {
            // C `d2k_verify_dns_on` для DoQ ставит TRANSPORT/HANDSHAKE по
            // факту QUIC-соединения, хотя TCP здесь нет.
            result.tcp_reachable = true;
            result.tls_handshake = true;
            result.dns_reply = dns_probe_reply(&body, 0) && peer != 0;
            result.reason = if result.dns_reply {
                "DoQ: получен корректный DNS-ответ".into()
            } else {
                "DoQ: нет подтверждённого DNS-ответа".into()
            };
        }
        Err(reason) => {
            result.reason = reason;
        }
    }
    result
}

/// Проверить DNS endpoint из конфигурации `dns_services`.
pub fn probe_dns_health(
    service: &DnsService,
    mark: Option<u32>,
    timeout: Duration,
) -> DnsHealthResult {
    let deadline = match deadline_from(timeout) {
        Ok(deadline) => deadline,
        Err(reason) => {
            return DnsHealthResult {
                reason,
                ..Default::default()
            };
        }
    };
    if service.protocol.eq_ignore_ascii_case("doh") {
        probe_doh(service, mark, deadline)
    } else if service.protocol.eq_ignore_ascii_case("dot") {
        probe_dot(service, mark, deadline)
    } else if service.protocol.eq_ignore_ascii_case("doq") {
        probe_doq(service, mark, deadline)
    } else {
        DnsHealthResult {
            reason: format!("DNS: неподдерживаемый протокол {}", service.protocol),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let parsed = doh_response_parse(response, 0x1234);
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
    fn loopback_doh_health_returns_valid_dns_reply() {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;
        let (config, _) = test_server_config();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(config)).unwrap(),
                socket,
            );
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
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
            let reply = reply_for(DNS_QUERY_ID_DOH);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(&reply).unwrap();
            stream.flush().unwrap();
        });
        let service = DnsService {
            protocol: "doh".into(),
            host: "127.0.0.1".into(),
            sni: "localhost".into(),
            path: "/dns-query".into(),
            bootstrap_dns: String::new(),
            source: "test".into(),
            port,
        };
        let result = probe_dns_health(&service, None, Duration::from_secs(3));
        server.join().unwrap();
        assert!(result.tcp_reachable, "{}", result.reason);
        assert!(result.tls_handshake, "{}", result.reason);
        assert_eq!(result.http_status, 200);
        assert!(result.dns_reply, "{}", result.reason);
    }

    #[test]
    fn loopback_dot_health_returns_valid_length_prefixed_reply() {
        use std::net::TcpListener;
        let (config, _) = test_server_config();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(config)).unwrap(),
                socket,
            );
            let mut query = [0u8; 31];
            stream.read_exact(&mut query).unwrap();
            assert_eq!(&query[..2], &[0, 29]);
            let reply = reply_for(DNS_QUERY_ID_DOT);
            let mut frame = Vec::with_capacity(reply.len() + 2);
            frame.extend_from_slice(&(reply.len() as u16).to_be_bytes());
            frame.extend_from_slice(&reply);
            stream.write_all(&frame).unwrap();
            stream.flush().unwrap();
        });
        let service = DnsService {
            protocol: "dot".into(),
            host: "127.0.0.1".into(),
            sni: "localhost".into(),
            path: String::new(),
            bootstrap_dns: String::new(),
            source: "test".into(),
            port,
        };
        let result = probe_dns_health(&service, None, Duration::from_secs(3));
        server.join().unwrap();
        assert!(result.tcp_reachable, "{}", result.reason);
        assert!(result.tls_handshake, "{}", result.reason);
        assert!(result.dns_reply, "{}", result.reason);
    }

    #[test]
    fn loopback_doq_health_uses_stream_zero_and_zero_id() {
        use std::net::UdpSocket;
        let (mut rustls_config, _) = test_server_config();
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
        };
        let result = probe_dns_health(&service, None, Duration::from_secs(3));
        let _ = server.join();
        assert!(result.tcp_reachable, "{}", result.reason);
        assert!(result.tls_handshake, "{}", result.reason);
        assert!(result.dns_reply, "{}", result.reason);
    }

    #[test]
    fn doh_parser_honours_length_chunked_and_limits() {
        let body = response(0x8180, 1, 1, 4);
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: "
                .to_vec();
        response.extend_from_slice(format!("{}\r\n\r\n", body.len()).as_bytes());
        response.extend_from_slice(&body);
        let parsed = doh_response_parse(&response, 0x1234);
        assert_eq!(parsed.state, DohState::Complete);
        assert!(parsed.dns_reply);
        assert_eq!(parsed.body_bytes, body.len());

        let mut chunked = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        chunked.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        chunked.extend_from_slice(&body);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let parsed = doh_response_parse(&chunked, 0x1234);
        assert_eq!(parsed.state, DohState::Complete);
        assert!(parsed.dns_reply);

        let bad_type = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\nx";
        assert_eq!(
            doh_response_parse(bad_type, 0x1234).state,
            DohState::Invalid
        );
        let too_big = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            DOH_BODY_MAX + 1
        );
        assert_eq!(
            doh_response_parse(too_big.as_bytes(), 0x1234).state,
            DohState::Invalid
        );
    }
}
