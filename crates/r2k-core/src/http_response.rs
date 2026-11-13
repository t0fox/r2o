/// C `head[8192]`: максимум сохранённого заголовка — 8191 байт (плюс NUL).
pub const MAX_HTTP_RESPONSE_HEADER_BYTES: usize = 8191;
const HEADER_CAPACITY: usize = MAX_HTTP_RESPONSE_HEADER_BYTES + 1;
const LINE_CAPACITY: usize = 512; // C `char line[512]`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Header,
    FixedBody,
    ChunkSize,
    ChunkBody,
    ChunkCr,
    ChunkLf,
    Trailers,
    CloseBody,
}

#[derive(Clone, Debug)]
pub struct HttpResponseParser {
    header: Vec<u8>,
    line: [u8; LINE_CAPACITY],
    header_len: usize,
    line_len: usize,
    remaining: u64,
    body_bytes: u64,
    status: u16,
    state: State,
    status_line_complete: bool,
    head_only: bool,
    headers_complete: bool,
    complete: bool,
    invalid: bool,
    line_overflow: bool,
    body_error: Option<&'static str>,
    interim: bool,
}

impl HttpResponseParser {
    pub fn new(head_only: bool) -> Self {
        Self::with_header_capacity(head_only, MAX_HTTP_RESPONSE_HEADER_BYTES)
    }

    /// Парсер с увеличенным пределом заголовка. C `read_status_rd`
    /// (`core/verify.c:699-728`) выделяет `D2K_VERIFY_HEADER_LIMIT + 1`
    /// (65537) на кучу: заголовки Meta/YouTube не влезают в 8 КиБ.
    pub fn with_header_capacity(head_only: bool, header_capacity: usize) -> Self {
        Self {
            header: vec![0; header_capacity.saturating_add(1)],
            line: [0; LINE_CAPACITY],
            header_len: 0,
            line_len: 0,
            remaining: 0,
            body_bytes: 0,
            status: 0,
            state: State::Header,
            status_line_complete: false,
            head_only,
            headers_complete: false,
            complete: false,
            invalid: false,
            line_overflow: false,
            body_error: None,
            interim: false,
        }
    }

    pub fn feed(&mut self, bytes: &[u8], fin: bool) {
        if self.invalid {
            return;
        }
        // C `d2k_http_response_feed`: байты после `complete` — не pipeline,
        // а неопределённый framing; ответ становится invalid.
        if self.complete && !bytes.is_empty() {
            self.invalid = true;
            self.complete = false;
            return;
        }
        for &byte in bytes {
            if self.complete {
                self.invalid = true;
                self.complete = false;
                break;
            }
            match self.state {
                State::Header => self.feed_header_byte(byte),
                State::FixedBody | State::ChunkBody | State::CloseBody => {
                    if self.body_bytes == u64::MAX {
                        self.invalid = true;
                        break;
                    }
                    self.body_bytes += 1;
                    if self.state != State::CloseBody {
                        self.remaining -= 1;
                        if self.remaining == 0 {
                            if self.state == State::FixedBody {
                                self.complete = true;
                            } else {
                                self.state = State::ChunkCr;
                            }
                        }
                    }
                }
                State::ChunkCr => {
                    if byte != b'\r' {
                        self.invalid = true;
                        break;
                    }
                    self.state = State::ChunkLf;
                }
                State::ChunkLf => {
                    if byte != b'\n' {
                        self.invalid = true;
                        break;
                    }
                    self.state = State::ChunkSize;
                }
                State::ChunkSize | State::Trailers => {
                    self.feed_line_byte(byte);
                    if self.invalid || byte != b'\n' {
                        continue;
                    }
                    if !self.finish_line() {
                        self.invalid = true;
                        break;
                    }
                }
            }
            if self.invalid {
                break;
            }
        }

        if fin && !self.invalid {
            if self.state == State::CloseBody && self.headers_complete {
                self.complete = true;
            } else if !self.complete {
                self.invalid = true;
            }
        }
        if self.invalid {
            self.complete = false;
        }
    }

    pub const fn headers_complete(&self) -> bool {
        self.headers_complete
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    pub const fn is_invalid(&self) -> bool {
        self.invalid
    }

    /// C `body_line`: переполнение строки, а не иной сбой обрамления.
    pub const fn line_overflow(&self) -> bool {
        self.line_overflow
    }

    /// C `body_say`: текст ошибки chunked-строки.
    pub const fn body_error(&self) -> Option<&'static str> {
        self.body_error
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub const fn body_bytes(&self) -> u64 {
        self.body_bytes
    }

    pub const fn saw_interim_response(&self) -> bool {
        self.interim
    }

    pub fn headers(&self) -> &[u8] {
        &self.header[..self.header_len]
    }

    pub fn fixed_body_remaining(&self) -> Option<u64> {
        if self.state == State::FixedBody && self.headers_complete && !self.invalid {
            Some(self.remaining)
        } else {
            None
        }
    }

    fn feed_header_byte(&mut self, byte: u8) {
        // C `d2k_http_response_feed`: NUL/control, одиночные CR/LF и
        // переполнение отвергаются в любом месте заголовка, не только в
        // строке статуса.
        if invalid_header_byte(byte)
            || self.header_len + 1 >= self.header.len()
            || byte == b'\n' && (self.header_len == 0 || self.header[self.header_len - 1] != b'\r')
            || self.header_len != 0 && self.header[self.header_len - 1] == b'\r' && byte != b'\n'
        {
            self.invalid = true;
            return;
        }
        self.header[self.header_len] = byte;
        self.header_len += 1;
        if !self.status_line_complete
            && self.header_len >= 2
            && self.header[self.header_len - 2..self.header_len] == *b"\r\n"
        {
            self.status_line_complete = true;
        }
        if self.header_len >= 4 && self.header[self.header_len - 4..self.header_len] == *b"\r\n\r\n"
        {
            self.finish_headers();
        }
    }

    fn finish_headers(&mut self) {
        self.status =
            parse_status_line(&self.header[..self.header_len]).map_or(0, |(_, status)| status);
        let Some((status, content_length, chunked)) =
            parse_headers(&self.header[..self.header_len])
        else {
            self.invalid = true;
            return;
        };
        self.status = status;
        if status < 200 {
            if status == 101 || content_length.is_some() || chunked {
                self.invalid = true;
                return;
            }
            self.interim = true;
            self.header_len = 0;
            self.header[0] = 0;
            self.status_line_complete = false;
            return;
        }

        self.headers_complete = true;
        if self.head_only || matches!(status, 204 | 304) {
            self.complete = true;
        } else if chunked {
            self.state = State::ChunkSize;
        } else if let Some(length) = content_length {
            self.state = State::FixedBody;
            self.remaining = length;
            self.complete = length == 0;
        } else {
            self.state = State::CloseBody;
        }
    }

    fn feed_line_byte(&mut self, byte: u8) {
        if invalid_line_byte(byte) {
            self.invalid = true;
            return;
        }
        // C `d2k_http_response_feed`: `line_len+1 >= sizeof line` (512).
        if self.line_len + 1 >= self.line.len() {
            self.invalid = true;
            self.line_overflow = true;
            self.body_error = Some("chunked: строка длиннее 510 байт (предел C)");
            return;
        }
        if byte == b'\n' && (self.line_len == 0 || self.line[self.line_len - 1] != b'\r') {
            self.invalid = true;
            self.body_error = Some("chunked: строка оканчивается LF без CR");
            return;
        }
        if self.line_len != 0 && self.line[self.line_len - 1] == b'\r' && byte != b'\n' {
            self.invalid = true;
            self.body_error = Some("chunked: после CR нет LF");
            return;
        }
        self.line[self.line_len] = byte;
        self.line_len += 1;
    }

    fn finish_line(&mut self) -> bool {
        if self.line_len < 2 || self.line[self.line_len - 2..self.line_len] != *b"\r\n" {
            return false;
        }
        let line_len = self.line_len - 2;
        let line = &self.line[..line_len];
        if self.state == State::Trailers {
            // C `d2k_http_response_feed`: пустая строка завершает ответ,
            // непустая обязана быть валидным полем.
            if line.is_empty() {
                self.complete = true;
            } else if !valid_hr_field(line) {
                return false;
            }
        } else {
            let Some(size) = parse_chunk_size(line) else {
                return false;
            };
            self.remaining = size;
            self.state = if size == 0 {
                State::Trailers
            } else {
                State::ChunkBody
            };
        }
        self.line_len = 0;
        true
    }
}

fn invalid_header_byte(byte: u8) -> bool {
    byte == 0 || byte < 32 && !matches!(byte, b'\r' | b'\n' | b'\t') || byte == 127
}

fn invalid_line_byte(byte: u8) -> bool {
    byte == 0 || byte < 32 && !matches!(byte, b'\r' | b'\n' | b'\t') || byte == 127
}

/// C `span_eq_ascii_ci`: длина и посимвольное сравнение без регистра;
/// `lower` — константа в нижнем регистре, как в C.
fn span_eq_ascii_ci(span: &[u8], lower: &[u8]) -> bool {
    span.len() == lower.len()
        && span
            .iter()
            .zip(lower)
            .all(|(value, expected)| value.to_ascii_lowercase() == *expected)
}

/// C `d2k_hr_token`: допустимый байт имени поля.
fn is_hr_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// C `d2k_hr_field`: двоеточие, непустое token-имя и допустимые байты
/// значения (управляющие отвергаются, TAB разрешён, DEL отвергается).
fn valid_hr_field(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return false;
    };
    if colon == 0 || !line[..colon].iter().all(|byte| is_hr_token(*byte)) {
        return false;
    }
    line[colon + 1..]
        .iter()
        .all(|byte| (*byte >= 32 || *byte == b'\t') && *byte != 127)
}

fn parse_headers(bytes: &[u8]) -> Option<(u16, Option<u64>, bool)> {
    let (status_end, status) = parse_status_line(bytes)?;

    let mut content_length = None;
    let mut transfer_encoding = false;
    let mut cursor = status_end + 2;
    let header_end = bytes.len().checked_sub(2)?;
    while cursor < header_end {
        let relative_end = find_crlf(&bytes[cursor..header_end])?;
        let line_end = cursor + relative_end;
        let line = &bytes[cursor..line_end];
        if !valid_hr_field(line) {
            return None;
        }
        let colon = line.iter().position(|byte| *byte == b':')?;
        let name = &line[..colon];
        let value = trim_ascii_whitespace(&line[colon + 1..]);
        if span_eq_ascii_ci(name, b"content-length") {
            // C `d2k_hr_headers`: второй Content-Length отвергается даже при
            // совпадающем значении (`if (cl++)`).
            if content_length.is_some() {
                return None;
            }
            content_length = Some(parse_decimal(value)?);
        } else if span_eq_ascii_ci(name, b"transfer-encoding") {
            if transfer_encoding || !span_eq_ascii_ci(value, b"chunked") {
                return None;
            }
            transfer_encoding = true;
        }
        cursor = line_end + 2;
    }
    if cursor != header_end || content_length.is_some() && transfer_encoding {
        return None;
    }
    Some((status, content_length, transfer_encoding))
}

fn parse_status_line(bytes: &[u8]) -> Option<(usize, u16)> {
    let status_end = find_crlf(bytes)?;
    let status_line = bytes.get(..status_end)?;
    if status_line.len() < 12
        || !(status_line.starts_with(b"HTTP/1.0 ") || status_line.starts_with(b"HTTP/1.1 "))
        || !(b'1'..=b'5').contains(&status_line[9])
        || status_line[10..12]
            .iter()
            .any(|byte| !byte.is_ascii_digit())
        || status_line.len() > 12 && status_line[12] != b' '
    {
        return None;
    }
    let status = u16::from(status_line[9] - b'0') * 100
        + u16::from(status_line[10] - b'0') * 10
        + u16::from(status_line[11] - b'0');
    Some((status_end, status))
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        bytes = &bytes[1..];
    }
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
    })
}

/// C `d2k_hr_extensions` (`datapath/include/d2k_http_response.h:43-70`):
/// `*(OWS ";" OWS token [OWS "=" OWS (token | quoted-string)])`.
fn valid_hr_extensions(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
            index += 1;
        }
        if index == bytes.len() || bytes[index] != b';' {
            return false;
        }
        index += 1;
        while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && is_hr_token(bytes[index]) {
            index += 1;
        }
        if index == start {
            return false;
        }
        while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
            index += 1;
        }
        if index < bytes.len() && bytes[index] == b'=' {
            index += 1;
            while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
                index += 1;
            }
            if index < bytes.len() && bytes[index] == b'"' {
                index += 1;
                let mut closed = false;
                while index < bytes.len() {
                    let mut byte = bytes[index];
                    index += 1;
                    if byte == b'"' {
                        closed = true;
                        break;
                    }
                    if byte == b'\\' {
                        if index == bytes.len() {
                            return false;
                        }
                        byte = bytes[index];
                        index += 1;
                    }
                    if (byte < 32 && byte != b'\t') || byte == 127 {
                        return false;
                    }
                }
                if !closed {
                    return false;
                }
            } else {
                let start = index;
                while index < bytes.len() && is_hr_token(bytes[index]) {
                    index += 1;
                }
                if index == start {
                    return false;
                }
            }
        }
    }
    true
}

fn parse_chunk_size(line: &[u8]) -> Option<u64> {
    let digits = line
        .iter()
        .position(|byte| matches!(byte, b';' | b' ' | b'\t'))
        .unwrap_or(line.len());
    if digits == 0 || !valid_hr_extensions(&line[digits..]) {
        return None;
    }
    line[..digits].iter().try_fold(0_u64, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(digit)
    })
}

#[cfg(test)]
mod span_tests {
    use super::span_eq_ascii_ci;

    #[test]
    fn span_eq_ascii_ci_matches_c() {
        assert!(span_eq_ascii_ci(b"Content-Length", b"content-length"));
        assert!(span_eq_ascii_ci(b"CHUNKED", b"chunked"));
        assert!(!span_eq_ascii_ci(b"Content-Lengths", b"content-length"));
        assert!(!span_eq_ascii_ci(b"", b"content-length"));
        assert!(!span_eq_ascii_ci(b"transfer", b"chunked"));
    }
}

#[cfg(test)]
mod header_tests {
    use super::{HttpResponseParser, MAX_HTTP_RESPONSE_HEADER_BYTES, parse_headers};

    #[test]
    fn status_line_without_reason_phrase_is_accepted_like_c() {
        // C `d2k_hr_headers`: ровно 12 байт status-line допустимы.
        assert_eq!(
            parse_headers(b"HTTP/1.1 200\r\n\r\n"),
            Some((200, None, false))
        );
        assert_eq!(
            parse_headers(b"HTTP/1.1 200 OK\r\n\r\n"),
            Some((200, None, false))
        );
        assert_eq!(parse_headers(b"HTTP/1.1 200X\r\n\r\n"), None);
        assert_eq!(parse_headers(b"HTTP/1.1 600 OK\r\n\r\n"), None);
    }

    #[test]
    fn header_fields_are_validated_like_c() {
        // Без двоеточия — отказ (C `d2k_hr_field`).
        assert_eq!(parse_headers(b"HTTP/1.1 200 OK\r\nBadHeader\r\n\r\n"), None);
        // Пробел в имени — не token.
        assert_eq!(
            parse_headers(b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n"),
            None
        );
        // Управляющий байт в значении (кроме TAB) — отказ.
        assert_eq!(parse_headers(b"HTTP/1.1 200 OK\r\nX: a\x01b\r\n\r\n"), None);
        // TAB в значении разрешён.
        assert_eq!(
            parse_headers(b"HTTP/1.1 200 OK\r\nX: a\tb\r\n\r\n"),
            Some((200, None, false))
        );
    }

    #[test]
    fn duplicate_content_length_is_rejected_even_when_equal() {
        assert_eq!(
            parse_headers(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n"),
            None
        );
        assert_eq!(
            parse_headers(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
            Some((200, Some(5), false))
        );
        assert_eq!(
            parse_headers(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Some((200, None, true))
        );
    }

    #[test]
    fn read_status_buf_branches_match_c() {
        // 204/304 без тела; 101 без запрошенного upgrade — ошибка, как C.
        for (response, status) in [
            (b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(), 204),
            (b"HTTP/1.1 304 Not Modified\r\n\r\n".as_slice(), 304),
        ] {
            let mut parser = HttpResponseParser::new(false);
            parser.feed(response, false);
            assert!(parser.is_complete(), "status {status}");
            assert_eq!(parser.status(), status);
            assert_eq!(parser.body_bytes(), 0);
        }
        let mut parser = HttpResponseParser::new(false);
        parser.feed(b"HTTP/1.1 101 Switching Protocols\r\n\r\n", false);
        assert!(parser.is_invalid());

        // 1xx промежуточный, затем настоящий ответ с Content-Length.
        let mut parser = HttpResponseParser::new(false);
        parser.feed(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
            false,
        );
        assert!(parser.is_complete());
        assert_eq!(parser.status(), 200);
        assert_eq!(parser.body_bytes(), 3);

        // chunked с trailer.
        let mut parser = HttpResponseParser::new(false);
        parser.feed(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX: y\r\n\r\n",
            false,
        );
        assert!(parser.is_complete());
        assert_eq!(parser.body_bytes(), 3);

        // close-delimited тело до EOF.
        let mut parser = HttpResponseParser::new(false);
        parser.feed(b"HTTP/1.1 200 OK\r\n\r\nhello", true);
        assert_eq!(parser.body_bytes(), 5);

        // Границы статуса: 100 и 599 допустимы, 600 — нет.
        for (status, valid) in [(100, true), (599, true), (600, false)] {
            let response = format!("HTTP/1.1 {status} X\r\n\r\n");
            let mut parser = HttpResponseParser::new(false);
            parser.feed(response.as_bytes(), false);
            assert_eq!(!parser.is_invalid(), valid, "status {status}");
        }

        // NUL в заголовке и повторный Content-Length — ошибки.
        for response in [
            b"HTTP/1.1 200 OK\r\nX: \x00\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n".as_slice(),
        ] {
            let mut parser = HttpResponseParser::new(false);
            parser.feed(response, false);
            assert!(parser.is_invalid());
        }
    }

    #[test]
    fn hr_extensions_differential_matches_c() {
        let cases: &[&[u8]] = &[
            b"",
            b";ext",
            b" ;ext",
            b"\t;ext=value",
            b";ext = \"quoted value\"",
            b";ext=\"a\\\"b\"",
            b";ext=",
            b";ext=\"unterminated",
            b";ext=\"a\x01\"",
            b";",
            b"; ext ; second=1",
            b"1;ext",
            b" ",
            b";ext=val trailing",
        ];
        let mut out = String::new();
        for (index, line) in cases.iter().enumerate() {
            out.push_str(&format!(
                "ext {index}={}\n",
                u8::from(super::valid_hr_extensions(line))
            ));
        }
        if let Ok(path) = std::env::var("R2O_HTTP_EXT_DIFF_OUTPUT") {
            std::fs::write(path, &out).unwrap();
        }
        assert!(super::valid_hr_extensions(b";ext"));
        assert!(!super::valid_hr_extensions(b";ext="));
        assert!(!super::valid_hr_extensions(b";ext=\"unterminated"));
    }

    #[test]
    fn chunk_size_validates_extensions_like_c() {
        assert_eq!(
            super::parse_chunk_size(b"1;ext=val"),
            Some(1),
            "chunk extension accepted"
        );
        assert_eq!(
            super::parse_chunk_size(b"1 ;ext"),
            Some(1),
            "OWS before extension accepted"
        );
        assert_eq!(super::parse_chunk_size(b"1 "), None, "bare trailing OWS");
        assert_eq!(super::parse_chunk_size(b"1;"), None, "empty extension");
        assert_eq!(
            super::parse_chunk_size(b"1;ext=\"unterminated"),
            None,
            "unclosed quoted extension"
        );
    }

    #[test]
    fn hr_field_differential_matches_c() {
        let cases: &[&[u8]] = &[
            b"",
            b"Host",
            b": value",
            b"Host: value",
            b"Host : value",
            b"Host:\tvalue",
            b"Host: a\x01",
            b"Host: a\x7f",
            b"Host: a\tb",
            b"Bad@Name: x",
            b"Content-Length: 10",
            b"X-Empty:",
        ];
        let mut out = String::new();
        for (index, line) in cases.iter().enumerate() {
            out.push_str(&format!(
                "field {index}={}\n",
                u8::from(super::valid_hr_field(line))
            ));
        }
        if let Ok(path) = std::env::var("R2O_HTTP_FIELD_DIFF_OUTPUT") {
            std::fs::write(path, &out).unwrap();
        }
        assert!(super::valid_hr_field(b"Host: value"));
        assert!(!super::valid_hr_field(b"Host : value"));
        assert!(!super::valid_hr_field(b"Host: a\x01"));
    }

    #[test]
    fn verify_header_capacity_accepts_large_headers_like_d2o() {
        // C `read_status_rd`: `D2K_VERIFY_HEADER_LIMIT + 1` = 65537.
        let mut parser = super::HttpResponseParser::with_header_capacity(false, 65_536);
        let mut response = Vec::new();
        response.extend_from_slice(b"HTTP/1.1 200 OK\r\nX-YouTube-Response: ");
        response.extend(std::iter::repeat_n(b'a', 12_000));
        response.extend_from_slice(b"\r\nConnection: close\r\n\r\nok");
        parser.feed(&response, true);
        assert!(!parser.is_invalid());
        assert_eq!(parser.status(), 200);
        assert!(parser.headers_complete());
    }

    #[test]
    fn header_capacity_matches_c_head_buffer() {
        // C `head[8192]`: максимум сохранённых байт — 8191.
        assert_eq!(MAX_HTTP_RESPONSE_HEADER_BYTES, 8191);
        let mut parser = super::HttpResponseParser::new(false);
        let mut response = Vec::new();
        response.extend_from_slice(b"HTTP/1.1 200 OK\r\nX: ");
        response.extend(std::iter::repeat_n(b'a', MAX_HTTP_RESPONSE_HEADER_BYTES));
        parser.feed(&response, false);
        assert!(parser.is_invalid());
    }
}
