const HEADER_CAPACITY: usize = 8192;
const LINE_CAPACITY: usize = 512;

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
    header: [u8; HEADER_CAPACITY],
    line: [u8; LINE_CAPACITY],
    header_len: usize,
    line_len: usize,
    remaining: u64,
    body_bytes: u64,
    status: u16,
    state: State,
    head_only: bool,
    headers_complete: bool,
    complete: bool,
    invalid: bool,
    interim: bool,
}

impl HttpResponseParser {
    pub fn new(head_only: bool) -> Self {
        Self {
            header: [0; HEADER_CAPACITY],
            line: [0; LINE_CAPACITY],
            header_len: 0,
            line_len: 0,
            remaining: 0,
            body_bytes: 0,
            status: 0,
            state: State::Header,
            head_only,
            headers_complete: false,
            complete: false,
            invalid: false,
            interim: false,
        }
    }

    pub fn feed(&mut self, bytes: &[u8], fin: bool) {
        if self.invalid {
            return;
        }
        for &byte in bytes {
            if self.complete {
                self.invalid = true;
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
        if self.header_len >= 4 && self.header[self.header_len - 4..self.header_len] == *b"\r\n\r\n"
        {
            self.finish_headers();
        }
    }

    fn finish_headers(&mut self) {
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
        if invalid_line_byte(byte)
            || self.line_len + 1 >= self.line.len()
            || byte == b'\n' && (self.line_len == 0 || self.line[self.line_len - 1] != b'\r')
            || self.line_len != 0 && self.line[self.line_len - 1] == b'\r' && byte != b'\n'
        {
            self.invalid = true;
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
            if line.is_empty() {
                self.complete = true;
            } else if !valid_field(line) {
                return false;
            }
        } else {
            let Some((size, extension_start)) = parse_chunk_size(line) else {
                return false;
            };
            if !valid_chunk_extensions(&line[extension_start..]) {
                return false;
            }
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

fn parse_headers(bytes: &[u8]) -> Option<(u16, Option<u64>, bool)> {
    let status_end = find_crlf(bytes)?;
    let status_line = bytes.get(..status_end)?;
    if status_line.len() < 12
        || !(status_line.starts_with(b"HTTP/1.0 ") || status_line.starts_with(b"HTTP/1.1 "))
        || status_line[9..12].iter().any(|byte| !byte.is_ascii_digit())
        || status_line.len() > 12 && status_line[12] != b' '
    {
        return None;
    }
    let status = u16::from(status_line[9] - b'0') * 100
        + u16::from(status_line[10] - b'0') * 10
        + u16::from(status_line[11] - b'0');

    let mut content_length = None;
    let mut transfer_encoding = false;
    let mut cursor = status_end + 2;
    let header_end = bytes.len().checked_sub(2)?;
    while cursor < header_end {
        let relative_end = find_crlf(&bytes[cursor..header_end])?;
        let line_end = cursor + relative_end;
        let line = &bytes[cursor..line_end];
        if line.is_empty() || !valid_field(line) {
            return None;
        }
        let colon = line.iter().position(|byte| *byte == b':')?;
        let name = &line[..colon];
        let value = trim_ascii_whitespace(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"Content-Length") {
            if content_length.is_some() {
                return None;
            }
            content_length = Some(parse_decimal(value)?);
        } else if name.eq_ignore_ascii_case(b"Transfer-Encoding") {
            if transfer_encoding || !value.eq_ignore_ascii_case(b"chunked") {
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

fn valid_field(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return false;
    };
    colon != 0
        && line[..colon].iter().all(|byte| is_token(*byte))
        && line[colon + 1..]
            .iter()
            .all(|byte| *byte == b'\t' || *byte >= 32 && *byte != 127)
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn parse_chunk_size(line: &[u8]) -> Option<(u64, usize)> {
    let digits = line
        .iter()
        .position(|byte| matches!(byte, b';' | b' ' | b'\t'))
        .unwrap_or(line.len());
    if digits == 0 {
        return None;
    }
    let size = line[..digits].iter().try_fold(0_u64, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(digit)
    })?;
    Some((size, digits))
}

fn valid_chunk_extensions(bytes: &[u8]) -> bool {
    let mut cursor = 0;
    while cursor < bytes.len() {
        while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
            cursor += 1;
        }
        if cursor == bytes.len() || bytes[cursor] != b';' {
            return false;
        }
        cursor += 1;
        while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
            cursor += 1;
        }
        let start = cursor;
        while cursor < bytes.len() && is_token(bytes[cursor]) {
            cursor += 1;
        }
        if cursor == start {
            return false;
        }
        while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
            cursor += 1;
        }
        if cursor < bytes.len() && bytes[cursor] == b'=' {
            cursor += 1;
            while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
                cursor += 1;
            }
            if cursor < bytes.len() && bytes[cursor] == b'"' {
                cursor += 1;
                let mut closed = false;
                while cursor < bytes.len() {
                    let mut byte = bytes[cursor];
                    cursor += 1;
                    if byte == b'"' {
                        closed = true;
                        break;
                    }
                    if byte == b'\\' {
                        if cursor == bytes.len() {
                            return false;
                        }
                        byte = bytes[cursor];
                        cursor += 1;
                    }
                    if byte < 32 && byte != b'\t' || byte == 127 {
                        return false;
                    }
                }
                if !closed {
                    return false;
                }
            } else {
                let start = cursor;
                while cursor < bytes.len() && is_token(bytes[cursor]) {
                    cursor += 1;
                }
                if cursor == start {
                    return false;
                }
            }
        }
    }
    true
}
