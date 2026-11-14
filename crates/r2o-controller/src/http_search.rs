use r2k_core::control::{AppliedEvent, BindingContext, KEY_LEN, SHAPE_HTTP};
use r2k_core::httpup::portal_location;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

const CANDIDATES: [&str; 5] = [
    "split",
    "fake-badsum-whole",
    "fake-badsum",
    "disorder",
    "fake-seqshift",
];

/// C `CANDS` (`httpsearch.c:250`): публичный список без R2O-расширения.
pub const D2K_HS_CANDIDATES: [&str; 4] = ["split", "disorder", "fake-badsum", "fake-seqshift"];

/// C `d2k_hs_candidate_count`.
pub fn d2k_hs_candidate_count() -> usize {
    D2K_HS_CANDIDATES.len()
}

/// C `d2k_hs_candidate_key`: NULL за пределом списка.
pub fn d2k_hs_candidate_key(index: usize) -> Option<&'static str> {
    D2K_HS_CANDIDATES.get(index).copied()
}
const FAKE_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: disk.rzd.ru\r\n\r\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Answer {
    Injected,
    Early,
    Garbage,
    Decoy,
    Real,
    Cut,
}

/// C `d2k_hs_answer`: все 10 исходов и default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oHsAnswer {
    None,
    Real,
    Injected,
    Early,
    Garbage,
    Silent,
    Reset,
    Closed,
    ConnectFail,
    Decoy,
    Cut,
    Unknown,
}

/// C `d2k_hs_answer_name`: русские имена исходов и default «нет».
pub fn d2k_hs_answer_name(answer: R2oHsAnswer) -> &'static str {
    match answer {
        R2oHsAnswer::Real => "ответ сервера",
        R2oHsAnswer::Injected => "вставка провайдера",
        R2oHsAnswer::Early => "ответ раньше RTT/2 (не сервер)",
        R2oHsAnswer::Garbage => "не ответ HTTP",
        R2oHsAnswer::Silent => "тишина",
        R2oHsAnswer::Reset => "сброс",
        R2oHsAnswer::Closed => "закрытие без ответа",
        R2oHsAnswer::ConnectFail => "соединение не установилось",
        R2oHsAnswer::Decoy => "ответ на приманку, не на запрос цели",
        R2oHsAnswer::Cut => "обрыв тела ответа",
        R2oHsAnswer::None | R2oHsAnswer::Unknown => "нет",
    }
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
    fn repeatable_http_path_accepts_the_donor_1023_byte_limit() {
        let mut maximum = vec![b'a'; 1023];
        maximum[0] = b'/';
        assert!(repeatable_path(&maximum));

        maximum.push(b'a');
        assert!(!repeatable_path(&maximum));
    }

    #[test]
    fn response_reader_reports_provider_block_body_and_keeps_early_outcome() {
        let blocked = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\n\r\naccess blocked by rkn";
        let mut reader = Cursor::new(blocked.as_slice());
        let response =
            read_probe_response(&mut reader, Some(b"rutracker.org"), 0, Instant::now()).unwrap();
        assert_eq!(response.answer, Answer::Injected);
        assert_eq!(response.reply, crate::fetch::R2oFetchHttpOutcome::Blocked);
        assert_eq!(response.reply_evidence, "access blocked by rkn");
        assert!(response.complete);

        let portal = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 15\r\n\r\neais.rkn.gov.ru";
        let mut reader = Cursor::new(portal.as_slice());
        let response =
            read_probe_response(&mut reader, Some(b"rutracker.org"), 0, Instant::now()).unwrap();
        assert_eq!(response.answer, Answer::Injected);
        assert_eq!(response.reply_evidence, "eais.rkn.gov.ru");

        // C `d2k_http_reply_classify` не сканирует сжатое тело.
        let compressed = b"HTTP/1.1 403 Forbidden\r\nContent-Encoding: gzip\r\nContent-Length: 21\r\n\r\naccess blocked by rkn";
        let mut reader = Cursor::new(compressed.as_slice());
        let response =
            read_probe_response(&mut reader, Some(b"rutracker.org"), 0, Instant::now()).unwrap();
        assert_eq!(response.answer, Answer::Real);
        assert_eq!(response.reply, crate::fetch::R2oFetchHttpOutcome::Neutral);

        // C `read_status_buf`: EARLY важнее неполного тела, CUT — только REAL.
        let early = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        let mut reader = Cursor::new(early.as_slice());
        let response =
            read_probe_response(&mut reader, Some(b"rutracker.org"), 98_000, Instant::now())
                .unwrap();
        assert_eq!(response.answer, Answer::Early);
        assert!(!response.complete);
    }

    #[test]
    fn response_reader_matches_donor_for_101_and_invalid_framing() {
        // C `read_status_buf` возвращает 101 без подтверждения полноты, а
        // `d2k_hs_probe_run` превращает REAL в CUT.
        let upgrade = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n";
        let mut reader = Cursor::new(upgrade.as_slice());
        let response =
            read_probe_response(&mut reader, Some(b"rutracker.org"), 0, Instant::now()).unwrap();
        assert_eq!(response.answer, Answer::Cut);
        assert_eq!(response.status, 101);
        assert!(!response.complete);

        // C `read_status_buf`: неоднозначный Content-Length — ответ есть,
        // тело не считается полным; это CUT, а не ошибка разбора.
        let malformed = b"HTTP/1.1 200 OK\r\nContent-Length: 1 2\r\nConnection: close\r\n\r\n";
        let mut reader = Cursor::new(malformed.as_slice());
        let response =
            read_probe_response(&mut reader, Some(b"rutracker.org"), 0, Instant::now()).unwrap();
        assert_eq!(response.answer, Answer::Cut);
        assert_eq!(response.status, 200);
        assert!(!response.complete);

        let duplicate = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx";
        let mut reader = Cursor::new(duplicate.as_slice());
        let response =
            read_probe_response(&mut reader, Some(b"rutracker.org"), 0, Instant::now()).unwrap();
        assert_eq!(response.answer, Answer::Cut);
        assert_eq!(response.status, 200);
        assert!(!response.complete);
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
    /// C `d2k_http_reply_classify`: сжатое тело не сканируется на подпись
    /// блокировки, поэтому `gzip`/несколько `Content-Encoding` дают `false`.
    identity_encoding: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpProbeResponse {
    pub answer: Answer,
    pub status: u16,
    pub complete: bool,
    pub body_bytes: u64,
    pub connection_close: bool,
    pub reply_us: i64,
    /// C `d2k_http_read_result.reply`: исход проверки тела/редиректа.
    pub reply: crate::fetch::R2oFetchHttpOutcome,
    pub reply_evidence: &'static str,
}

/// Проверить, можно ли безопасно повторить наблюдённый путь HTTP.
pub fn repeatable_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path.len() <= 1023
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
    let (head, response, body_prefix, body_bytes, complete) = loop {
        let mut head = Vec::with_capacity(1024);
        if let Err(error) = read_response_head(reader, &mut first_byte, &mut head) {
            if head.is_empty() {
                return Err(error);
            }
            let reply_us = first_byte
                .map(|received| received.saturating_duration_since(request_sent).as_micros() as i64)
                .unwrap_or(-1);
            // C `d2k_hs_probe_run`: частичный заголовок — судимый ответ
            // (обычно GARBAGE), а не ошибка чтения.
            let judged = judge(host, &head, rtt_us, reply_us);
            return Ok(HttpProbeResponse {
                answer: judged,
                status: 0,
                complete: false,
                body_bytes: 0,
                connection_close: false,
                reply_us,
                reply: crate::fetch::R2oFetchHttpOutcome::Neutral,
                reply_evidence: "",
            });
        }
        let Some(parsed) = parse_response_head(&head) else {
            // C `read_status_buf`: неоднозначный Content-Length/Transfer-
            // Encoding не отменяет ответ, но тело считается неполным.
            let Some(status) = parse_status_line(&head) else {
                let reply_us = first_byte
                    .map(|received| {
                        received.saturating_duration_since(request_sent).as_micros() as i64
                    })
                    .unwrap_or(-1);
                return Ok(HttpProbeResponse {
                    answer: Answer::Garbage,
                    status: 0,
                    complete: false,
                    body_bytes: 0,
                    connection_close: false,
                    reply_us,
                    reply: crate::fetch::R2oFetchHttpOutcome::Neutral,
                    reply_evidence: "",
                });
            };
            let response = ParsedResponseHead {
                status,
                body: BodyMode::Empty,
                connection_close: true,
                identity_encoding: true,
            };
            break (head, response, Vec::new(), 0, false);
        };
        if parsed.status == 101 {
            // C `read_status_buf`: 101 без запроса на upgrade — ответ без
            // тела и без подтверждения полноты; probe_run превратит его в CUT
            // (если judge не вернул более специфичный исход).
            break (head, parsed, Vec::new(), 0, false);
        }
        if parsed.body == BodyMode::Empty {
            if !(100..200).contains(&parsed.status) {
                break (head, parsed, Vec::new(), 0, true);
            }
        } else {
            let mut prefix = Vec::new();
            let (body_bytes, complete) = read_response_body(reader, parsed.body, &mut prefix)?;
            break (head, parsed, prefix, body_bytes, complete);
        }
    };
    let reply_us = first_byte
        .map(|received| received.saturating_duration_since(request_sent).as_micros() as i64)
        .unwrap_or(-1);
    let location = response_header(&head, b"location").unwrap_or_default();
    let reply = crate::fetch::r2o_http_reply_classify(
        response.status,
        location,
        response.identity_encoding,
        &body_prefix,
        body_bytes.saturating_add(u64::from(!complete)),
    );
    let judged = judge(host, &head, rtt_us, reply_us);
    // C `d2k_hs_probe_run`: BLOKED-тело важнее неполноты, а CUT получается
    // только из REAL; EARLY/DECOY/INJECTED/GARBAGE сохраняют свой исход.
    let answer = if reply.outcome == crate::fetch::R2oFetchHttpOutcome::Blocked {
        Answer::Injected
    } else if judged == Answer::Real && !complete {
        Answer::Cut
    } else {
        judged
    };
    Ok(HttpProbeResponse {
        answer,
        status: response.status,
        complete,
        body_bytes,
        connection_close: response.connection_close,
        reply_us,
        reply: reply.outcome,
        reply_evidence: reply.evidence,
    })
}

/// C `d2k_hs_judge`/`read_status_rd`: код статуса из первой строки.
fn parse_status_line(head: &[u8]) -> Option<u16> {
    let status_line = head.split(|byte| *byte == b'\n').next()?;
    let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);
    if status_line.len() < 12
        || &status_line[..7] != b"HTTP/1."
        || !matches!(status_line[7], b'0' | b'1')
        || status_line[8] != b' '
    {
        return None;
    }
    std::str::from_utf8(&status_line[9..12]).ok()?.parse().ok()
}

/// Значение первого поля заголовка без завершающих пробелов, как C scanner.
fn response_header<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let end = head.windows(4).position(|window| window == b"\r\n\r\n")? + 2;
    for raw_line in head[..end].split(|byte| *byte == b'\n').skip(1) {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if name.eq_ignore_ascii_case(&line[..separator]) {
            return Some(trim_http_whitespace(&line[separator + 1..]));
        }
    }
    None
}

fn read_response_head(
    reader: &mut impl Read,
    first_byte: &mut Option<Instant>,
    head: &mut Vec<u8>,
) -> io::Result<()> {
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
                    return Ok(());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

/// C `body_stream.prefix[4096]`: начало тела для `d2k_http_reply_classify`.
const HTTP_REPLY_BODY_PREFIX: usize = 4096;

fn capture_body_prefix(prefix: &mut Vec<u8>, bytes: &[u8]) {
    if prefix.len() >= HTTP_REPLY_BODY_PREFIX {
        return;
    }
    let take = bytes.len().min(HTTP_REPLY_BODY_PREFIX - prefix.len());
    prefix.extend_from_slice(&bytes[..take]);
}

fn read_response_body(
    reader: &mut impl Read,
    body: BodyMode,
    prefix: &mut Vec<u8>,
) -> io::Result<(u64, bool)> {
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
                        capture_body_prefix(prefix, &buffer[..read]);
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
        BodyMode::Chunked => read_chunked_body(reader, prefix),
        BodyMode::UntilClose => {
            let mut buffer = [0; 8192];
            let mut read_total = 0_u64;
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => return Ok((read_total, true)),
                    Ok(read) => {
                        capture_body_prefix(prefix, &buffer[..read]);
                        read_total = read_total.saturating_add(read as u64);
                    }
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

fn read_chunked_body(reader: &mut impl Read, prefix: &mut Vec<u8>) -> io::Result<(u64, bool)> {
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
        let (read, complete) = read_response_body(reader, BodyMode::Length(size), prefix)?;
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
    let mut identity_encoding = true;
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
            b"content-encoding" => {
                // C `read_status_buf`: только ровно `identity` разрешает
                // сканировать тело на подпись блокировки; `gzip` и цепочки
                // кодировок дают «не identity».
                identity_encoding &= value == b"identity";
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
        identity_encoding,
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

/// C `d2k_httpsearch_cur.cands`: `N_CANDS*4+8`.
pub const D2K_HS_CANDS_MAX: usize = 24;

/// C `add_cand`: добавить без дублей, не больше предела массива.
pub fn add_candidate(candidates: &mut Vec<String>, key: &str) {
    if candidates.len() >= D2K_HS_CANDS_MAX || candidates.iter().any(|saved| saved == key) {
        return;
    }
    candidates.push(key.to_owned());
}

/// C `d2k_httpsearch_plan_of`: подтверждённый HTTP-план host+family.
pub fn http_plan_of(catalog: &crate::catalog::Catalog, host: &str, family: u8) -> Option<String> {
    for box_record in &catalog.boxes {
        for binding in &box_record.bindings {
            if binding.kind != "name"
                || !binding.target.eq_ignore_ascii_case(host)
                || !binding.enabled
                || binding.transport != 6
                || binding.family != family
                || binding.shape != SHAPE_HTTP
            {
                continue;
            }
            let Some(plan) = box_record
                .plans
                .iter()
                .find(|plan| plan.id.eq_ignore_ascii_case(&binding.plan_id))
            else {
                continue;
            };
            if let Some(key) = candidate_key_from_plan_text(&plan.text) {
                return Some(key);
            }
        }
    }
    None
}

/// C `known_key`: встроенный ключ, `fake-badsum-whole` или валидный `fake:`-spec.
pub fn known_key(key: &str) -> bool {
    matches!(
        key,
        "split" | "disorder" | "fake-badsum" | "fake-seqshift" | "fake-badsum-whole"
    ) || poison_key_spec(key).is_some()
}

/// Формирует текст пробного HTTP-плана в формате R2O (`r2o-plan`).
pub fn candidate_text(key: &str, id: Option<&[u8; 16]>) -> Option<String> {
    if !known_key(key) {
        return None;
    }
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
    stable_id_with_prefix(b"r2o-http:", key)
}

/// C `stable_id`: FNV-1a по префиксу `d2k-http:` и ключу.
pub fn d2k_stable_id(key: &str) -> [u8; 16] {
    stable_id_with_prefix(b"d2k-http:", key)
}

fn stable_id_with_prefix(prefix: &[u8], key: &str) -> [u8; 16] {
    const OFFSET: u64 = 1_469_598_103_934_665_603;
    const PRIME: u64 = 1_099_511_628_211;
    let mut hash = OFFSET;
    for byte in prefix.iter().chain(key.as_bytes()) {
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
mod d2o_http_judge_differential {
    use super::{Answer, judge};

    #[test]
    fn cf_challenge_response_is_judged_like_donor() {
        let response = include_bytes!("../tests/fixtures/d2o_http_challenge_response.bin");
        let response = &response[..response.len() - 1];
        let answer = judge(None, response, 100_000, 100_000);
        let code = if answer == Answer::Real { 1 } else { 2 };
        if let Some(path) = std::env::var_os("R2O_HTTP_JUDGE_DIFF_OUTPUT") {
            std::fs::write(path, format!("{code}\n")).unwrap();
        }
        assert_eq!(code, 1, "d2o d2k_hs_judge classifies this response as REAL");

        let sent = std::time::Instant::now();
        let mut reader = &response[..];
        let probe = super::read_probe_response(&mut reader, None, 0, sent).unwrap();
        // Фикстура — 403 с телом «access blocked by rkn». C `d2k_hs_judge`
        // сам тело не смотрит и даёт REAL, но `d2k_hs_probe_run` применяет
        // `d2k_http_reply_classify` и превращает ответ в INJECTED.
        assert_eq!(probe.answer, Answer::Injected);
        assert_eq!(probe.reply, crate::fetch::R2oFetchHttpOutcome::Blocked);
        assert!(probe.complete);
    }
}

/// C `D2K_HS_RECORD_MAX_BYTES`: предел памяти под записи HTTP-планов.
pub const HTTP_PLANS_RECORD_MAX_BYTES: usize = 256 * 1024;
/// Заголовок файла планов: C сравнивает строку целиком, включая `\n`.
pub const HTTP_PLANS_HEADER: &str = "d2k-http-plans 1\n";

/// Запись подтверждённого HTTP-кандидата (C `rec`): host/family/key/wall.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct R2oHttpPlanRecord {
    pub host: String,
    pub family: u8,
    pub key: String,
    /// Стенные часы подтверждения; 0 — проставить при первом сохранении.
    pub wall: i64,
    pub revoked: bool,
}

/// C `d2k_httpsearch_save` (`httpsearch.c:1446-1473`): атомарная запись
/// `d2k-http-plans 1`; `wall==0` получает `wall_s`, отозванные и пустые
/// ключи пропускаются.
pub fn save_http_plans(
    path: &std::path::Path,
    records: &mut [R2oHttpPlanRecord],
    wall_s: i64,
) -> Result<(), String> {
    let path_text = path.to_string_lossy().into_owned();
    let tmp = format!("{path_text}.tmp");
    if tmp.len() >= 1100 {
        return Err(format!("путь длиннее {}", 1100));
    }
    let mut text = String::with_capacity(HTTP_PLANS_HEADER.len() + records.len() * 64);
    text.push_str(HTTP_PLANS_HEADER);
    for record in records.iter_mut() {
        if record.key.is_empty() || record.revoked {
            continue;
        }
        // Время подтверждения — первое сохранение после него.
        if record.wall == 0 {
            record.wall = wall_s;
        }
        text.push_str(&format!(
            "{} {} {} {}\n",
            record.host, record.family, record.key, record.wall
        ));
    }
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{tmp}: {error}"));
    }
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{path_text}: rename"));
    }
    Ok(())
}

/// Результат C `d2k_httpsearch_load`: записи в порядке появления и счётчик
/// принятых строк.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct R2oHttpPlanLoad {
    pub records: Vec<R2oHttpPlanRecord>,
    pub loaded: usize,
}

/// C `d2k_httpsearch_load` (`httpsearch.c:1475-1514`): заголовок обязателен,
/// битые строки пропускаются, `loaded` считает только принятые.
pub fn load_http_plans(path: &std::path::Path) -> Result<R2oHttpPlanLoad, String> {
    let path_text = path.to_string_lossy().into_owned();
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(R2oHttpPlanLoad::default());
        }
        Err(error) => return Err(format!("{path_text}: {error}")),
    };
    let chunks = r2o_fgets_chunks(&bytes);
    let Some(header) = chunks.first() else {
        return Err(format!(
            "{path_text}: не планы HTTP d2k (нет заголовка «d2k-http-plans 1»)"
        ));
    };
    if *header != HTTP_PLANS_HEADER.as_bytes() {
        return Err(format!(
            "{path_text}: не планы HTTP d2k (нет заголовка «d2k-http-plans 1»)"
        ));
    }
    let mut result = R2oHttpPlanLoad::default();
    // C: максимум записей по бюджету памяти; при переполнении загрузка
    // останавливается на первой сверх лимита.
    let max_records = HTTP_PLANS_RECORD_MAX_BYTES / R2O_HTTP_PLAN_RECORD_BYTES;
    for chunk in chunks.iter().skip(1) {
        let Some((host, family, key, wall)) = r2o_parse_http_plan_line(chunk) else {
            continue;
        };
        let position = result
            .records
            .iter()
            .position(|record| record.family == family && record.host.eq_ignore_ascii_case(&host));
        let record = match position {
            Some(index) => &mut result.records[index],
            None => {
                if result.records.len() >= max_records {
                    break;
                }
                result.records.push(R2oHttpPlanRecord::default());
                let record = result.records.last_mut().expect("только что добавлена");
                record.host = host;
                record.family = family;
                record
            }
        };
        // C `snprintf(r->key, sizeof r->key, "%.39s", key)`.
        record.key = key.chars().take(39).collect();
        record.wall = wall;
        result.loaded += 1;
    }
    Ok(result)
}

/// Приблизительный размер C `rec` для предела числа записей.
const R2O_HTTP_PLAN_RECORD_BYTES: usize = 1_400;

/// C `fgets(line, 512, f)`: не больше 511 байт за вызов, включая `\n`.
fn r2o_fgets_chunks(bytes: &[u8]) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        let max = (position + 511).min(bytes.len());
        let slice = &bytes[position..max];
        let end = slice
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(max, |offset| position + offset + 1);
        chunks.push(&bytes[position..end]);
        position = end;
    }
    chunks
}

fn r2o_http_plan_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// C `sscanf("%299s %u %47s %lld %n")` + `line[used]=='\0'`.
fn r2o_parse_http_plan_line(line: &[u8]) -> Option<(String, u8, String, i64)> {
    let mut offset = 0;
    let skip = |offset: &mut usize| {
        while *offset < line.len() && r2o_http_plan_whitespace(line[*offset]) {
            *offset += 1;
        }
    };
    let token = |offset: &mut usize, width: usize| -> Option<&[u8]> {
        skip(offset);
        let start = *offset;
        while *offset < line.len() && !r2o_http_plan_whitespace(line[*offset]) {
            *offset += 1;
        }
        if *offset - start > width {
            return None;
        }
        Some(&line[start..*offset])
    };

    let host_token = token(&mut offset, 299)?;
    let family_token = token(&mut offset, 32)?;
    let key_token = token(&mut offset, 47)?;
    let wall_token = token(&mut offset, 32)?;
    skip(&mut offset);
    if offset != line.len() {
        return None;
    }
    if host_token.is_empty() || key_token.is_empty() || wall_token.is_empty() {
        return None;
    }

    let family = r2o_parse_unsigned_number(family_token)?;
    if family != 4 && family != 6 {
        return None;
    }
    let wall = r2o_parse_signed_number(wall_token)?;

    let host = std::str::from_utf8(host_token).ok()?;
    if !r2o_http_plan_host_ok(host) {
        return None;
    }
    let key = std::str::from_utf8(key_token).ok()?;
    if !known_key(key) {
        return None;
    }
    Some((host.to_owned(), family as u8, key.to_owned(), wall))
}

/// C `%u`: необязательный знак и цифры; значение обрезается до 32 бит.
fn r2o_parse_unsigned_number(bytes: &[u8]) -> Option<u64> {
    let mut offset = 0;
    while offset < bytes.len() && r2o_http_plan_whitespace(bytes[offset]) {
        offset += 1;
    }
    let negative = bytes.get(offset) == Some(&b'-');
    if matches!(bytes.get(offset), Some(b'+') | Some(b'-')) {
        offset += 1;
    }
    let start = offset;
    let mut value: u64 = 0;
    while let Some(byte) = bytes.get(offset) {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value.wrapping_mul(10).wrapping_add(u64::from(*byte - b'0'));
        offset += 1;
    }
    if offset == start || offset != bytes.len() {
        return None;
    }
    let value = if negative {
        (value as u32 as i32 as i64).unsigned_abs()
    } else {
        value
    };
    Some(value)
}

/// C `%lld`: необязательный знак и цифры, переполнение — отказ.
fn r2o_parse_signed_number(bytes: &[u8]) -> Option<i64> {
    let mut offset = 0;
    while offset < bytes.len() && r2o_http_plan_whitespace(bytes[offset]) {
        offset += 1;
    }
    let negative = bytes.get(offset) == Some(&b'-');
    if matches!(bytes.get(offset), Some(b'+') | Some(b'-')) {
        offset += 1;
    }
    let start = offset;
    let mut value: i64 = 0;
    while let Some(byte) = bytes.get(offset) {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value
            .checked_mul(10)?
            .checked_add(i64::from(*byte - b'0'))?;
        offset += 1;
    }
    if offset == start || offset != bytes.len() {
        return None;
    }
    Some(if negative { -value } else { value })
}

/// C `host_ok`: 1..253, только буквы/цифры/`-`/`.`; последняя метка не IPv4.
fn r2o_http_plan_host_ok(host: &str) -> bool {
    let bytes = host.as_bytes();
    if bytes.is_empty() || bytes.len() > 253 {
        return false;
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return false;
    }
    let last = host.rsplit('.').next().unwrap_or(host);
    !last.is_empty() && !last.bytes().all(|byte| byte.is_ascii_digit())
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
