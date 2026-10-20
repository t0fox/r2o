const R2O_RESOURCE_LIMIT: usize = 2;
const R2O_RESOURCE_BODY_LIMIT: usize = 32_768;
const R2O_RESOURCE_TAG_LIMIT: usize = 2048;
const R2O_RESOURCE_URL_LIMIT: usize = 600;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oResourceHint {
    pub host: String,
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct R2oResourceScan {
    tag: Vec<u8>,
    seen: usize,
    active: bool,
    quote: Option<u8>,
    comment: bool,
    raw: u8,
    url: Vec<u8>,
    url_active: bool,
    resources: Vec<R2oResourceHint>,
}

impl Default for R2oResourceScan {
    fn default() -> Self {
        Self {
            tag: Vec::with_capacity(R2O_RESOURCE_TAG_LIMIT),
            seen: 0,
            active: false,
            quote: None,
            comment: false,
            raw: 0,
            url: Vec::with_capacity(R2O_RESOURCE_URL_LIMIT),
            url_active: false,
            resources: Vec::with_capacity(R2O_RESOURCE_LIMIT),
        }
    }
}

impl R2oResourceScan {
    pub fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.seen >= R2O_RESOURCE_BODY_LIMIT || self.resources.len() >= R2O_RESOURCE_LIMIT {
                break;
            }
            self.seen += 1;
            self.r2o_feed_url(byte);
            if !self.active {
                if byte == b'<' {
                    self.active = true;
                    self.tag.clear();
                    self.quote = None;
                }
                continue;
            }
            if self.tag.len() + 1 >= R2O_RESOURCE_TAG_LIMIT {
                self.active = false;
                continue;
            }
            self.tag.push(byte);
            if self.tag.len() == 3 && self.tag == b"!--" {
                self.comment = true;
            }
            if self.comment {
                if self.tag.ends_with(b"-->") {
                    self.active = false;
                    self.comment = false;
                }
                continue;
            }
            if let Some(quote) = self.quote {
                if byte == quote {
                    self.quote = None;
                }
                continue;
            }
            if matches!(byte, b'\'' | b'"') {
                self.quote = Some(byte);
                continue;
            }
            if byte == b'>' {
                self.tag.pop();
                self.r2o_finish_tag();
                self.active = false;
            }
        }
    }

    pub fn resources(&self) -> &[R2oResourceHint] {
        &self.resources
    }

    fn r2o_feed_url(&mut self, byte: u8) {
        if self.url_active {
            if matches!(byte, b'"' | b'\'' | b'(' | b')' | b';' | b',' | b'<' | b'>')
                || r2o_resource_space(byte)
            {
                self.r2o_add_url();
                self.url_active = false;
                self.url.clear();
            } else if self.url.len() + 1 < R2O_RESOURCE_URL_LIMIT {
                self.url.push(byte);
            } else {
                self.url_active = false;
                self.url.clear();
            }
        } else if byte == b'h' {
            self.url_active = true;
            self.url.clear();
            self.url.push(byte);
        }
    }

    fn r2o_finish_tag(&mut self) {
        let tag = self
            .tag
            .split(|byte| *byte == 0)
            .next()
            .unwrap_or_default()
            .to_vec();
        let name_len = tag
            .iter()
            .position(|byte| r2o_resource_space(*byte) || matches!(*byte, b'/' | b'>'))
            .unwrap_or(tag.len());
        let name = &tag[..name_len];
        if self.raw != 0 {
            if self.raw == 1 && name.starts_with(b"/script")
                || self.raw == 2 && name.starts_with(b"/style")
            {
                self.raw = 0;
            }
            return;
        }
        if r2o_resource_word(name, b"script") {
            self.raw = 1;
            return;
        }
        if r2o_resource_word(name, b"style") {
            self.raw = 2;
            return;
        }
        if r2o_resource_word(name, b"body") {
            self.seen = R2O_RESOURCE_BODY_LIMIT;
            return;
        }
        if !r2o_resource_word(name, b"link") {
            return;
        }
        if let Some(href) = r2o_link_stylesheet_href(&tag, name_len) {
            self.r2o_add_url_bytes(href);
        }
    }

    fn r2o_add_url(&mut self) {
        self.r2o_add_url_bytes(&self.url.clone());
    }

    fn r2o_add_url_bytes(&mut self, url: &[u8]) {
        let host_start = if let Some(host) = url.strip_prefix(b"https://") {
            host
        } else if let Some(host) = url.strip_prefix(b"//") {
            host
        } else {
            return;
        };
        let Some(path_start) = host_start.iter().position(|byte| *byte == b'/') else {
            return;
        };
        let host = &host_start[..path_start];
        let path = &host_start[path_start..];
        if host.is_empty()
            || host.len() >= 256
            || host[0] == b'.'
            || host.last() == Some(&b'.')
            || !r2o_resource_path_bytes_ok(path)
        {
            return;
        }
        let mut normalized_host = Vec::with_capacity(host.len());
        for &byte in host {
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.')) {
                return;
            }
            normalized_host.push(byte.to_ascii_lowercase());
        }
        if self
            .resources
            .iter()
            .any(|resource| resource.host.as_bytes() == normalized_host.as_slice())
        {
            return;
        }
        if let (Ok(host), Ok(path)) = (
            String::from_utf8(normalized_host),
            String::from_utf8(path.to_vec()),
        ) {
            self.resources.push(R2oResourceHint { host, path });
        }
    }
}

pub fn r2o_resource_path_ok(path: &str) -> bool {
    r2o_resource_path_bytes_ok(path.as_bytes())
}

fn r2o_resource_path_bytes_ok(path: &[u8]) -> bool {
    if path.is_empty()
        || path.len() >= 512
        || !path.starts_with(b"/")
        || path.starts_with(b"//")
        || path.windows(4).any(|part| part == b"/../")
        || path.windows(3).any(|part| part == b"/./")
    {
        return false;
    }
    if !path
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'-' | b'_'))
    {
        return false;
    }
    path.len() >= 4 && path[path.len() - 4..].eq_ignore_ascii_case(b".css")
}

fn r2o_link_stylesheet_href(tag: &[u8], name_len: usize) -> Option<&[u8]> {
    let mut cursor = name_len;
    let mut href = None;
    let mut href_seen = false;
    let mut rel_seen = false;
    let mut stylesheet = false;
    while cursor < tag.len() {
        while cursor < tag.len() && r2o_resource_space(tag[cursor]) {
            cursor += 1;
        }
        if cursor == tag.len() || matches!(tag[cursor], b'/' | b'>') {
            break;
        }
        let key_start = cursor;
        while cursor < tag.len()
            && !r2o_resource_space(tag[cursor])
            && !matches!(tag[cursor], b'=' | b'>')
        {
            cursor += 1;
        }
        let key_end = cursor;
        while cursor < tag.len() && r2o_resource_space(tag[cursor]) {
            cursor += 1;
        }
        if cursor == tag.len() || tag[cursor] != b'=' {
            if key_start == cursor {
                cursor += 1;
            }
            continue;
        }
        cursor += 1;
        while cursor < tag.len() && r2o_resource_space(tag[cursor]) {
            cursor += 1;
        }
        let quote = tag
            .get(cursor)
            .copied()
            .filter(|byte| matches!(byte, b'\'' | b'"'));
        if quote.is_some() {
            cursor += 1;
        }
        let value_start = cursor;
        while cursor < tag.len()
            && match quote {
                Some(quote) => tag[cursor] != quote,
                None => !r2o_resource_space(tag[cursor]) && tag[cursor] != b'>',
            }
        {
            cursor += 1;
        }
        if quote.is_some() && (cursor == tag.len() || Some(tag[cursor]) != quote) {
            return None;
        }
        let value = &tag[value_start..cursor];
        if quote.is_some() {
            cursor += 1;
        }
        let key = &tag[key_start..key_end];
        if r2o_resource_word(key, b"href") {
            if href_seen || value.len() >= 1024 {
                return None;
            }
            href_seen = true;
            href = Some(value);
        } else if r2o_resource_word(key, b"rel") {
            if rel_seen {
                return None;
            }
            rel_seen = true;
            stylesheet = r2o_resource_word(value, b"stylesheet");
        }
    }
    if stylesheet && href_seen { href } else { None }
}

fn r2o_resource_word(value: &[u8], word: &[u8]) -> bool {
    value.len() == word.len()
        && value
            .iter()
            .zip(word)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn r2o_resource_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c')
}

enum R2oResourceChunkState {
    Size(Vec<u8>),
    Data(usize),
    DataCr,
    DataLf,
    Trailers(Vec<u8>),
    Done,
    Invalid,
}

pub struct R2oResourceBodyTap {
    chunked: bool,
    state: R2oResourceChunkState,
    scanner: R2oResourceScan,
}

impl R2oResourceBodyTap {
    pub fn new(chunked: bool) -> Self {
        Self {
            chunked,
            state: if chunked {
                R2oResourceChunkState::Size(Vec::new())
            } else {
                R2oResourceChunkState::Done
            },
            scanner: R2oResourceScan::default(),
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        if !self.chunked {
            self.scanner.feed(bytes);
            return;
        }
        let mut cursor = 0;
        while cursor < bytes.len() {
            let state = std::mem::replace(&mut self.state, R2oResourceChunkState::Done);
            match state {
                R2oResourceChunkState::Size(mut line) => {
                    let byte = bytes[cursor];
                    cursor += 1;
                    if byte == b'\n' {
                        if line.pop() != Some(b'\r') {
                            self.state = R2oResourceChunkState::Invalid;
                            break;
                        }
                        self.state = match r2o_parse_chunk_size(&line) {
                            Some(0) => R2oResourceChunkState::Trailers(Vec::new()),
                            Some(size) => R2oResourceChunkState::Data(size),
                            None => R2oResourceChunkState::Invalid,
                        };
                    } else if line.len() < 128 {
                        line.push(byte);
                        self.state = R2oResourceChunkState::Size(line);
                    } else {
                        self.state = R2oResourceChunkState::Invalid;
                    }
                }
                R2oResourceChunkState::Data(remaining) => {
                    let length = remaining.min(bytes.len() - cursor);
                    self.scanner.feed(&bytes[cursor..cursor + length]);
                    cursor += length;
                    self.state = if length == remaining {
                        R2oResourceChunkState::DataCr
                    } else {
                        R2oResourceChunkState::Data(remaining - length)
                    };
                }
                R2oResourceChunkState::DataCr => {
                    if bytes[cursor] != b'\r' {
                        self.state = R2oResourceChunkState::Invalid;
                        break;
                    }
                    cursor += 1;
                    self.state = R2oResourceChunkState::DataLf;
                }
                R2oResourceChunkState::DataLf => {
                    if bytes[cursor] != b'\n' {
                        self.state = R2oResourceChunkState::Invalid;
                        break;
                    }
                    cursor += 1;
                    self.state = R2oResourceChunkState::Size(Vec::new());
                }
                R2oResourceChunkState::Trailers(mut line) => {
                    let byte = bytes[cursor];
                    cursor += 1;
                    if byte == b'\n' {
                        if line.pop() != Some(b'\r') {
                            self.state = R2oResourceChunkState::Invalid;
                            break;
                        }
                        self.state = if line.is_empty() {
                            R2oResourceChunkState::Done
                        } else {
                            R2oResourceChunkState::Trailers(Vec::new())
                        };
                    } else if line.len() < 8192 {
                        line.push(byte);
                        self.state = R2oResourceChunkState::Trailers(line);
                    } else {
                        self.state = R2oResourceChunkState::Invalid;
                    }
                }
                R2oResourceChunkState::Done | R2oResourceChunkState::Invalid => {
                    self.state = R2oResourceChunkState::Done;
                    break;
                }
            }
        }
    }

    pub fn resources(&self) -> &[R2oResourceHint] {
        self.scanner.resources()
    }
}

fn r2o_parse_chunk_size(line: &[u8]) -> Option<usize> {
    let digits = &line[..line
        .iter()
        .position(|byte| *byte == b';')
        .unwrap_or(line.len())];
    if digits.is_empty() {
        return None;
    }
    let mut size = 0_usize;
    for &byte in digits {
        let digit = match byte {
            b'0'..=b'9' => usize::from(byte - b'0'),
            b'a'..=b'f' => usize::from(byte - b'a' + 10),
            b'A'..=b'F' => usize::from(byte - b'A' + 10),
            _ => return None,
        };
        size = size.checked_mul(16)?.checked_add(digit)?;
    }
    Some(size)
}
