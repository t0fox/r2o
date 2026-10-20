use r2k_core::control::{AppliedEvent, BindingContext, KEY_LEN, SHAPE_HTTP};
use r2k_core::httpup::portal_location;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

const CANDIDATES: [&str; 5] = [
    "split",
    "fake-badsum-whole",
    "fake-badsum",
    "disorder",
    "fake-seqshift",
];
const FAKE_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: disk.rzd.ru\r\n\r\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Answer {
    Injected,
    Early,
    Garbage,
    Decoy,
    Challenge,
    Real,
    Cut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeIdentity {
    pub plan_id: [u8; 16],
    pub trial_id: [u8; 16],
    pub family: u8,
    pub client: IpAddr,
    pub server: IpAddr,
    pub local_port: u16,
}

pub fn confirmed_applied(
    events: &[AppliedEvent],
    expected: &ProbeIdentity,
    required: usize,
) -> Option<BindingContext> {
    if required == 0
        || expected.local_port == 0
        || !matches!(expected.family, 4 | 6)
        || expected.client.is_ipv4() != (expected.family == 4)
        || expected.server.is_ipv4() != (expected.family == 4)
    {
        return None;
    }
    let mut binding = None;
    let mut executions = std::collections::HashSet::new();
    for event in events {
        let key = &event.key;
        if key[0] != expected.family
            || key[37] != 6
            || event.plan_id != expected.plan_id
            || event.trial_id != expected.trial_id
            || event.execution_id == 0
            || !event.binding.is_known()
            || event.binding.kind != 1
            || event.binding.family != expected.family
            || event.binding.shape != SHAPE_HTTP
            || !event.binding.temporary
        {
            continue;
        }
        let low_port = u16::from_be_bytes([key[33], key[34]]);
        let high_port = u16::from_be_bytes([key[35], key[36]]);
        let pair = if high_port == 80 && low_port == expected.local_port {
            (
                flow_address(key, 1, expected.family),
                flow_address(key, 17, expected.family),
            )
        } else if low_port == 80 && high_port == expected.local_port {
            (
                flow_address(key, 17, expected.family),
                flow_address(key, 1, expected.family),
            )
        } else {
            continue;
        };
        let (Some(client), Some(server)) = pair else {
            continue;
        };
        if (client, server) != (expected.client, expected.server) {
            continue;
        }
        if binding.is_some_and(|known| known != event.binding) {
            return None;
        }
        binding = Some(event.binding);
        executions.insert(event.execution_id);
        if executions.len() >= required {
            return binding;
        }
    }
    None
}

fn flow_address(key: &[u8; KEY_LEN], offset: usize, family: u8) -> Option<IpAddr> {
    match family {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        ))),
        6 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&key[offset..offset + 16]).ok()?,
        ))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Answer, BodyMode, ProbeIdentity, confirmed_applied, parse_response_head,
        read_probe_response, repeatable_path,
    };
    use r2k_core::control::{AppliedEvent, BindingContext, KEY_LEN, SHAPE_HTTP};
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    fn event(execution_id: u64) -> AppliedEvent {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 80]);
        key[33..35].copy_from_slice(&45000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&80_u16.to_be_bytes());
        key[37] = 6;
        AppliedEvent {
            key,
            plan_id: [1; 16],
            trial_id: [2; 16],
            execution_id,
            binding: BindingContext {
                generation: 7,
                kind: 1,
                family: 4,
                shape: SHAPE_HTTP,
                temporary: true,
                epoch: [3; 16],
            },
        }
    }

    #[test]
    fn proof_requires_distinct_matching_executions_for_the_bound_socket() {
        let expected = ProbeIdentity {
            plan_id: [1; 16],
            trial_id: [2; 16],
            family: 4,
            client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            server: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 80)),
            local_port: 45000,
        };

        assert!(confirmed_applied(&[event(11), event(12)], &expected, 2).is_some());
        assert!(confirmed_applied(&[event(11), event(11)], &expected, 2).is_none());
    }

    #[test]
    fn proof_rejects_an_event_from_another_socket_or_trial() {
        let expected = ProbeIdentity {
            plan_id: [1; 16],
            trial_id: [2; 16],
            family: 4,
            client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            server: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 80)),
            local_port: 45000,
        };
        let mut wrong_port = event(11);
        wrong_port.key[33..35].copy_from_slice(&45001_u16.to_be_bytes());

        assert!(confirmed_applied(&[wrong_port, event(12)], &expected, 2).is_none());
        let mut wrong_trial = event(11);
        wrong_trial.trial_id = [4; 16];
        assert!(confirmed_applied(&[wrong_trial, event(12)], &expected, 2).is_none());
    }

    #[test]
    fn response_framing_recognizes_keep_alive_and_complete_body_modes() {
        let fixed = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: keep-alive\r\n\r\n",
        )
        .unwrap();
        assert_eq!(fixed.body, BodyMode::Length(12));
        assert!(!fixed.connection_close);

        let chunked =
            parse_response_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        assert_eq!(chunked.body, BodyMode::Chunked);

        let closed = parse_response_head(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        assert_eq!(closed.body, BodyMode::UntilClose);
        assert!(closed.connection_close);
        assert!(parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 1 2\r\n\r\n").is_none());
    }

    #[test]
    fn response_reader_consumes_two_complete_keep_alive_responses() {
        let bytes =
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\noneHTTP/1.1 204 No Content\r\n\r\n";
        let mut reader = Cursor::new(bytes.as_slice());
        let first = read_probe_response(&mut reader, None, 0, Instant::now()).unwrap();
        let second = read_probe_response(&mut reader, None, 0, Instant::now()).unwrap();

        assert_eq!(first.answer, Answer::Real);
        assert!(first.complete);
        assert!(!first.connection_close);
        assert_eq!(second.status, 204);
        assert!(second.complete);
        assert_eq!(reader.position() as usize, bytes.len());
    }

    #[test]
    fn response_reader_marks_a_short_fixed_body_as_a_reproducible_cut() {
        let bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        let mut reader = Cursor::new(bytes.as_slice());
        let response =
            read_probe_response(&mut reader, Some(b"example.com"), 0, Instant::now()).unwrap();

        assert_eq!(response.answer, Answer::Cut);
        assert!(!response.complete);
        assert_eq!(response.body_bytes, 3);
    }

    #[test]
    fn response_reader_marks_a_short_chunked_body_as_a_reproducible_cut() {
        let bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc";
        let mut reader = Cursor::new(bytes.as_slice());
        let response =
            read_probe_response(&mut reader, Some(b"example.com"), 0, Instant::now()).unwrap();

        assert_eq!(response.answer, Answer::Cut);
        assert!(!response.complete);
        assert_eq!(response.body_bytes, 3);
    }

    #[test]
    fn repeatable_http_paths_match_the_bounded_replay_rules() {
        assert!(repeatable_path(b"/watch/42"));
        assert!(!repeatable_path(b"//other.example/path"));
        assert!(!repeatable_path(b"/search?q=one"));
        assert!(!repeatable_path(b"/back\\slash"));
        assert!(!repeatable_path(b"/non-ascii-\xff"));
    }

    #[test]
    fn response_reader_consumes_chunk_trailers_before_the_next_response() {
        let bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\nX-End: yes\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
        let mut reader = Cursor::new(bytes.as_slice());
        let first = read_probe_response(&mut reader, None, 0, Instant::now()).unwrap();
        let second = read_probe_response(&mut reader, None, 0, Instant::now()).unwrap();

        assert!(first.complete);
        assert_eq!(second.status, 204);
        assert_eq!(reader.position() as usize, bytes.len());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyMode {
    Empty,
    Length(usize),
    Chunked,
    UntilClose,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedResponseHead {
    status: u16,
    body: BodyMode,
    connection_close: bool,
    cloudflare_challenge: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpProbeResponse {
    pub answer: Answer,
    pub status: u16,
    pub complete: bool,
    pub body_bytes: u64,
    pub connection_close: bool,
    pub reply_us: i64,
}

/// Проверить, можно ли безопасно повторить наблюдённый путь HTTP.
pub fn repeatable_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path.len() < 1023
        && path.first() == Some(&b'/')
        && path.get(1) != Some(&b'/')
        && path
            .iter()
            .all(|byte| (33..127).contains(byte) && !matches!(*byte, b'?' | b'#' | b'\\'))
}

pub fn read_probe_response(
    reader: &mut impl Read,
    host: Option<&[u8]>,
    rtt_us: i64,
    request_sent: Instant,
) -> io::Result<HttpProbeResponse> {
    let mut first_byte = None;
    let (head, response, body_bytes, complete) = loop {
        let head = read_response_head(reader, &mut first_byte)?;
        let response = parse_response_head(&head).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "неверный заголовок HTTP-ответа")
        })?;
        if response.cloudflare_challenge {
            break (head, response, 0, false);
        }
        if response.body == BodyMode::Empty {
            if !(100..200).contains(&response.status) || response.status == 101 {
                break (head, response, 0, true);
            }
        } else {
            let (body_bytes, complete) = read_response_body(reader, response.body)?;
            break (head, response, body_bytes, complete);
        }
    };
    let reply_us = first_byte
        .map(|received| received.saturating_duration_since(request_sent).as_micros() as i64)
        .unwrap_or(-1);
    Ok(HttpProbeResponse {
        answer: if response.cloudflare_challenge {
            Answer::Challenge
        } else if !complete {
            Answer::Cut
        } else {
            judge(host, &head, rtt_us, reply_us)
        },
        status: response.status,
        complete,
        body_bytes,
        connection_close: response.connection_close,
        reply_us,
    })
}

fn read_response_head(
    reader: &mut impl Read,
    first_byte: &mut Option<Instant>,
) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "соединение закрыто внутри заголовка HTTP-ответа",
                ));
            }
            Ok(_) => {
                first_byte.get_or_insert_with(Instant::now);
                head.push(byte[0]);
                if head.len() > 65_536 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "заголовок HTTP-ответа превышает 64 КиБ",
                    ));
                }
                if head.ends_with(b"\r\n\r\n") {
                    return Ok(head);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn read_response_body(reader: &mut impl Read, body: BodyMode) -> io::Result<(u64, bool)> {
    match body {
        BodyMode::Empty => Ok((0, true)),
        BodyMode::Length(mut remaining) => {
            let mut buffer = [0; 8192];
            let mut read_total = 0_u64;
            while remaining != 0 {
                let size = remaining.min(buffer.len());
                match reader.read(&mut buffer[..size]) {
                    Ok(0) => return Ok((read_total, false)),
                    Ok(read) => {
                        remaining -= read;
                        read_total += read as u64;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if body_cut_error(&error) => return Ok((read_total, false)),
                    Err(error) => return Err(error),
                }
            }
            Ok((read_total, true))
        }
        BodyMode::Chunked => read_chunked_body(reader),
        BodyMode::UntilClose => {
            let mut buffer = [0; 8192];
            let mut read_total = 0_u64;
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => return Ok((read_total, true)),
                    Ok(read) => read_total = read_total.saturating_add(read as u64),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
        }
    }
}

fn body_cut_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

fn read_chunked_body(reader: &mut impl Read) -> io::Result<(u64, bool)> {
    let mut declared_total = 0_usize;
    let mut body_bytes = 0_u64;
    loop {
        let line = match read_crlf_line(reader, 8192) {
            Ok(line) => line,
            Err(error) if body_cut_error(&error) => return Ok((body_bytes, false)),
            Err(error) => return Err(error),
        };
        let size = line
            .split(|byte| *byte == b';')
            .next()
            .and_then(|size| std::str::from_utf8(size).ok())
            .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "неверный размер HTTP-чанка")
            })?;
        declared_total = declared_total
            .checked_add(size)
            .filter(|size| *size <= 64 * 1024 * 1024)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "тело HTTP-ответа превышает 64 МиБ",
                )
            })?;
        if size == 0 {
            loop {
                match read_crlf_line(reader, 8192) {
                    Ok(line) if line.is_empty() => return Ok((body_bytes, true)),
                    Ok(_) => {}
                    Err(error) if body_cut_error(&error) => {
                        return Ok((body_bytes, false));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        let (read, complete) = read_response_body(reader, BodyMode::Length(size))?;
        body_bytes = body_bytes.saturating_add(read);
        if !complete {
            return Ok((body_bytes, false));
        }
        let mut ending = [0; 2];
        if let Err(error) = reader.read_exact(&mut ending) {
            if body_cut_error(&error) {
                return Ok((body_bytes, false));
            }
            return Err(error);
        }
        if ending != *b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "неверное окончание HTTP-чанка",
            ));
        }
    }
}

fn read_crlf_line(reader: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0; 1];
    loop {
        reader.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "строка HTTP превышает предел",
            ));
        }
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
    }
}

fn parse_response_head(head: &[u8]) -> Option<ParsedResponseHead> {
    let end = head.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let mut lines = head[..end - 2].split(|byte| *byte == b'\n');
    let status_line = lines.next()?.strip_suffix(b"\r")?;
    if status_line.len() < 12
        || &status_line[..7] != b"HTTP/1."
        || !matches!(status_line[7], b'0' | b'1')
        || status_line[8] != b' '
    {
        return None;
    }
    let status = std::str::from_utf8(&status_line[9..12])
        .ok()?
        .parse()
        .ok()?;
    let mut content_length = None;
    let mut chunked = false;
    let mut close = status_line[7] == b'0';
    let mut keep_alive = false;
    let mut cloudflare_challenge = false;
    for raw_line in lines {
        if raw_line.is_empty() {
            break;
        }
        let line = raw_line.strip_suffix(b"\r")?;
        if line.is_empty() {
            break;
        }
        let separator = line.iter().position(|byte| *byte == b':')?;
        let (name, value) = line.split_at(separator);
        let value = &value[1..];
        let name = name.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
        let value = trim_http_whitespace(value)
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect::<Vec<_>>();
        match name.as_slice() {
            b"cf-mitigated" => {
                cloudflare_challenge |= value.eq_ignore_ascii_case(b"challenge");
            }
            b"content-length" => {
                if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                    return None;
                }
                let length = std::str::from_utf8(&value).ok()?.parse::<usize>().ok()?;
                if length > 64 * 1024 * 1024 || content_length.is_some_and(|old| old != length) {
                    return None;
                }
                content_length = Some(length);
            }
            b"transfer-encoding" => {
                let last = value
                    .split(|byte| *byte == b',')
                    .next_back()
                    .map(trim_http_whitespace)?;
                if !last.eq_ignore_ascii_case(b"chunked") {
                    return None;
                }
                chunked = true;
            }
            b"connection" => {
                close |= header_has_token(&value, b"close");
                keep_alive |= header_has_token(&value, b"keep-alive");
            }
            _ => {}
        }
    }
    let body = if (100..200).contains(&status) || matches!(status, 204 | 304) {
        BodyMode::Empty
    } else if chunked {
        BodyMode::Chunked
    } else if let Some(length) = content_length {
        BodyMode::Length(length)
    } else {
        close = true;
        BodyMode::UntilClose
    };
    close |= status == 101;
    if status_line[7] == b'0' && !keep_alive {
        close = true;
    }
    Some(ParsedResponseHead {
        status,
        body,
        connection_close: close,
        cloudflare_challenge,
    })
}

fn trim_http_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn header_has_token(value: &[u8], token: &[u8]) -> bool {
    value
        .split(|byte| *byte == b',')
        .any(|part| trim_http_whitespace(part).eq_ignore_ascii_case(token))
}

pub fn candidate_keys() -> &'static [&'static str] {
    &CANDIDATES
}

pub fn candidate_key_from_plan_text(text: &str) -> Option<String> {
    let mut lines = text.lines();
    if lines.next()? != "r2o-plan 1 11" {
        return None;
    }
    let id_text = lines.next()?.strip_prefix("id ")?;
    if id_text.len() != 32 {
        return None;
    }
    let mut id = [0; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = (hex_value(id_text.as_bytes()[index * 2])? << 4)
            | hex_value(id_text.as_bytes()[index * 2 + 1])?;
    }
    for key in candidate_keys() {
        if candidate_text(key, Some(&id)).as_deref() == Some(text) {
            return Some((*key).to_owned());
        }
    }

    let has_split = text.lines().any(|line| line == "split sni_middle +0");
    let key = if let Some(spec) = text.lines().find_map(|line| line.strip_prefix("poison 1 ")) {
        if spec == "badsum" && !has_split {
            "fake-badsum-whole".to_owned()
        } else if has_split {
            format!(
                "fake:{}",
                spec.split_ascii_whitespace().collect::<Vec<_>>().join("+")
            )
        } else {
            return None;
        }
    } else if has_split
        && text.lines().any(|line| line == "order reverse")
        && text.lines().any(|line| line == "pace 12000")
    {
        "disorder".to_owned()
    } else if has_split {
        "split".to_owned()
    } else {
        return None;
    };
    (candidate_text(&key, Some(&id)).as_deref() == Some(text)).then_some(key)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Формирует текст пробного HTTP-плана, совместимый с r2o-plan.
pub fn candidate_text(key: &str, id: Option<&[u8; 16]>) -> Option<String> {
    let poison = match key {
        "fake-badsum" | "fake-badsum-whole" => Some("badsum".to_owned()),
        "fake-seqshift" => Some("seqshift=-66000".to_owned()),
        key if key.starts_with("fake:") => Some(poison_key_spec(key)?),
        "split" | "disorder" => None,
        _ => return None,
    };
    if poison.is_none() && !matches!(key, "split" | "disorder") {
        return None;
    }

    let id = id.copied().unwrap_or([0; 16]);
    let mut text = String::from("r2o-plan 1 11\nid ");
    append_hex(&mut text, &id);
    text.push_str("\nproto tcp http\n");
    if let Some(spec) = poison {
        text.push_str("payload 1 ");
        append_hex(&mut text, FAKE_REQUEST);
        text.push_str("\npoison 1 ");
        text.push_str(&spec);
        text.push_str("\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\n");
    }
    if key != "fake-badsum-whole" {
        text.push_str("split sni_middle +0\n");
    }
    if key == "disorder" {
        text.push_str("order reverse\npace 12000\n");
    }
    Some(text)
}

/// Извлечь измеренные варианты только из приманок подтверждённого TLS-плана.
pub fn measured_poison_keys(text: &str) -> Vec<String> {
    if !text.lines().any(|line| line == "proto tcp tls") {
        return Vec::new();
    }

    let mut poisons = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("poison ") else {
            continue;
        };
        let Some((id, spec)) = rest.split_once(' ') else {
            continue;
        };
        let Ok(id) = id.parse::<u32>() else {
            continue;
        };
        let spec = spec.trim();
        if id != 0 && !spec.is_empty() && !poisons.iter().any(|(known, _)| *known == id) {
            poisons.push((id, spec.to_owned()));
        }
    }

    let mut used = Vec::new();
    for line in text.lines().filter(|line| line.starts_with("fake ")) {
        for field in line.split_ascii_whitespace() {
            let Some(id) = field.strip_prefix("poison=") else {
                continue;
            };
            if let Ok(id) = id.parse::<u32>()
                && id != 0
                && !used.contains(&id)
            {
                used.push(id);
            }
        }
    }

    let mut keys = Vec::new();
    for (id, spec) in poisons {
        if !used.contains(&id) {
            continue;
        }
        let spec = spec.split_ascii_whitespace().collect::<Vec<_>>().join("+");
        let key = match spec.as_str() {
            "badsum" => "fake-badsum".to_owned(),
            "seqshift=-66000" => "fake-seqshift".to_owned(),
            _ => format!("fake:{spec}"),
        };
        if candidate_text(&key, None).is_some() && !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

/// Скомпилировать HTTP-кандидата в точное представление программы плана.
pub fn candidate_program(key: &str) -> Option<Vec<u8>> {
    let text = candidate_text(key, None)?;
    crate::plan_text::compile_text(&text).ok()
}

pub fn stable_id(key: &str) -> [u8; 16] {
    const OFFSET: u64 = 1_469_598_103_934_665_603;
    const PRIME: u64 = 1_099_511_628_211;
    const ID_PREFIX: &[u8] = &[0x72, 0x32, 0x6f, 0x2d, 0x68, 0x74, 0x74, 0x70, 0x3a];
    let mut hash = OFFSET;
    for byte in ID_PREFIX.iter().chain(key.as_bytes()) {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(PRIME);
    }
    let mut id = [0; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        hash = (hash ^ index as u64).wrapping_mul(PRIME);
        *byte = (hash >> 56) as u8;
    }
    id
}

fn poison_key_spec(key: &str) -> Option<String> {
    if key.len() > 39 {
        return None;
    }
    let suffix = key.strip_prefix("fake:")?;
    let mut fields = Vec::new();
    let mut order = 0;
    let mut has_ttl = false;
    let mut has_poison = false;
    for field in suffix.split('+').filter(|field| !field.is_empty()) {
        let rank = if field == "badsum" {
            has_poison = true;
            2
        } else if let Some(value) = field.strip_prefix("ttl=") {
            if has_ttl || !(1..=255).contains(&parse_decimal(value)?) {
                return None;
            }
            has_ttl = true;
            1
        } else {
            let value = field.strip_prefix("seqshift=")?;
            let value = parse_decimal(value)?;
            if value == 0 || !(-2_147_483_647..=2_147_483_647).contains(&value) {
                return None;
            }
            has_poison = true;
            3
        };
        if rank <= order {
            return None;
        }
        order = rank;
        fields.push(field);
    }
    if fields.is_empty() || (has_ttl && !has_poison) {
        return None;
    }
    Some(fields.join(" "))
}

fn parse_decimal(value: &str) -> Option<i64> {
    let value = value.trim_start_matches(|character: char| character.is_ascii_whitespace());
    value.parse().ok()
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
}

/// Классифицирует начало HTTP-ответа по наблюдаемой цели и RTT.
pub fn judge(host: Option<&[u8]>, head: &[u8], rtt_us: i64, reply_us: i64) -> Answer {
    if head.len() < 12
        || &head[..7] != b"HTTP/1."
        || !matches!(head[7], b'0' | b'1')
        || head[8] != b' '
        || !matches!(head[9], b'1'..=b'5')
        || !head[10].is_ascii_digit()
        || !head[11].is_ascii_digit()
        || !head.windows(4).any(|window| window == b"\r\n\r\n")
    {
        return Answer::Garbage;
    }

    if parse_response_head(head).is_some_and(|response| response.cloudflare_challenge) {
        return Answer::Challenge;
    }

    if host.is_some_and(|host| portal_location(host, head).is_some()) {
        return Answer::Injected;
    }

    let status = u16::from(head[9] - b'0') * 100
        + u16::from(head[10] - b'0') * 10
        + u16::from(head[11] - b'0');
    if matches!(status, 400 | 421)
        || head
            .windows(b"disk.rzd.ru".len())
            .any(|window| window.eq_ignore_ascii_case(b"disk.rzd.ru"))
    {
        return Answer::Decoy;
    }

    if rtt_us > 0 && reply_us >= 0 && i128::from(reply_us) * 2 < i128::from(rtt_us) {
        return Answer::Early;
    }
    Answer::Real
}

#[cfg(test)]
mod candidate_tests {
    use super::{candidate_program, measured_poison_keys};

    #[test]
    fn measured_poison_requires_tls_and_an_actual_fake_reference() {
        let tls_plan = "r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\npoison 1 ttl=64 badsum\npoison 2 seqshift=-66000\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\n";
        assert_eq!(measured_poison_keys(tls_plan), ["fake:ttl=64+badsum"]);

        let http_plan = tls_plan.replace("proto tcp tls", "proto tcp http");
        assert!(measured_poison_keys(&http_plan).is_empty());

        let unreferenced_plan =
            tls_plan.replace("fake payload=1 poison=1 ", "fake payload=1 poison=2 ");
        assert_eq!(measured_poison_keys(&unreferenced_plan), ["fake-seqshift"]);
        let no_fake_plan = tls_plan.replace(
            "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n",
            "",
        );
        assert!(measured_poison_keys(&no_fake_plan).is_empty());
    }

    #[test]
    fn aliases_compile_to_the_same_live_conflict_program() {
        assert_eq!(
            candidate_program("fake-badsum"),
            candidate_program("fake:badsum")
        );
    }
}
