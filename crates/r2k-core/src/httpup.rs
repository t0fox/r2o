//! Безопасный разбор HTTP/1.x и распознавание страницы блокировки в потоках порта 80.

use std::ops::Range;

#[derive(Clone)]
struct Request<'a> {
    host: &'a [u8],
    target: &'a [u8],
    host_range: Range<usize>,
    method: &'a [u8],
    header_len: usize,
    end_offset: Option<usize>,
}

/// Границы HTTP-запроса, пригодные для выбора плана и отслеживания keep-alive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oHttpPlanRequest {
    /// Диапазон нормализованного имени Host внутри исходного сегмента.
    pub host_range: Range<usize>,
    /// Длина запроса до конца заголовков.
    pub header_len: usize,
    /// Смещение конца запроса, если framing однозначен.
    pub end_offset: Option<usize>,
}

/// C `d2k_http_request_stream` (`datapath/include/d2k_http_request_stream.h`):
/// инкрементальный разбор заголовка запроса без хранения значений.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oHttpRequestStream {
    pub start: u32,
    pub next: u32,
    pub head_len: u32,
    pub end: u32,
    pub length: u64,
    first: bool,
    cr: bool,
    line: bool,
    value: bool,
    field: bool,
    name_len: u8,
    cl_seen: u8,
    digits: u8,
    trailing: u8,
    hosts: u8,
    pub invalid: bool,
    pub header_done: bool,
    pub past_end: bool,
    name: [u8; 18],
}

impl R2oHttpRequestStream {
    pub const fn new(sequence: u32) -> Self {
        Self {
            start: sequence,
            next: sequence,
            head_len: 0,
            end: 0,
            length: 0,
            first: true,
            cr: false,
            line: false,
            value: false,
            field: false,
            name_len: 0,
            cl_seen: 0,
            digits: 0,
            trailing: 0,
            hosts: 0,
            invalid: false,
            header_done: false,
            past_end: false,
            name: [0; 18],
        }
    }

    fn finish_line(&mut self) {
        if self.first {
            self.first = false;
        } else if !self.line {
            let end = u64::from(self.next.wrapping_sub(self.start)) + self.length;
            if self.hosts != 1 || end > 0x7fff_ffff {
                self.invalid = true;
                return;
            }
            self.header_done = true;
            self.head_len = self.next.wrapping_sub(self.start);
            self.end = self.start.wrapping_add(end as u32);
        } else if !self.value || self.field && self.digits == 0 {
            self.invalid = true;
        }
        self.line = false;
        self.value = false;
        self.field = false;
        self.name_len = 0;
        self.digits = 0;
        self.trailing = 0;
    }

    /// C `d2k_http_request_stream_feed`: только непрерывные байты; полностью
    /// старый повтор игнорируется, дыра/частичное перекрытие — invalid.
    pub fn feed(&mut self, sequence: u32, bytes: &[u8]) {
        if self.invalid || bytes.is_empty() {
            return;
        }
        if bytes.len() > 0x7fff_ffff {
            self.invalid = true;
            return;
        }
        if sequence != self.next {
            let old_distance = sequence.wrapping_sub(self.next) as i32;
            let end_distance = sequence
                .wrapping_add(bytes.len() as u32)
                .wrapping_sub(self.next) as i32;
            if old_distance < 0 && end_distance <= 0 {
                return;
            }
            self.invalid = true;
            return;
        }
        for &byte in bytes {
            self.next = self.next.wrapping_add(1);
            if self.next.wrapping_sub(self.start) > 0x7fff_ffff {
                self.invalid = true;
                return;
            }
            if self.header_done {
                if self.next.wrapping_sub(self.end) as i32 > 0 {
                    self.past_end = true;
                }
                continue;
            }
            if self.cr {
                self.cr = false;
                if byte != b'\n' {
                    self.invalid = true;
                    return;
                }
                self.finish_line();
                if self.invalid {
                    return;
                }
                continue;
            }
            if byte == b'\r' {
                self.cr = true;
                continue;
            }
            if byte == b'\n' || byte == 0x7f || byte < 0x20 && byte != b'\t' {
                self.invalid = true;
                return;
            }
            self.line = true;
            if self.first {
                continue;
            }
            if !self.value {
                if byte == b':' {
                    self.value = true;
                    if self.name_len == 14 && &self.name[..14] == b"content-length" {
                        self.cl_seen = self.cl_seen.saturating_add(1);
                        if self.cl_seen > 1 {
                            self.invalid = true;
                            return;
                        }
                        self.field = true;
                    } else if (self.name_len == 17 && &self.name[..17] == b"transfer-encoding")
                        || (self.name_len == 7 && &self.name[..7] == b"upgrade")
                    {
                        self.invalid = true;
                        return;
                    } else if self.name_len == 4 && &self.name[..4] == b"host" {
                        self.hosts = self.hosts.saturating_add(1);
                        if self.hosts > 1 {
                            self.invalid = true;
                            return;
                        }
                    } else if self.name_len == 0 {
                        self.invalid = true;
                        return;
                    }
                } else {
                    let token = byte.is_ascii_lowercase()
                        || byte.is_ascii_uppercase()
                        || byte.is_ascii_digit()
                        || b"!#$%&'*+-.^_`|~".contains(&byte);
                    if !token {
                        self.invalid = true;
                        return;
                    }
                    if usize::from(self.name_len) < self.name.len() {
                        self.name[usize::from(self.name_len)] = if byte.is_ascii_uppercase() {
                            byte + 32
                        } else {
                            byte
                        };
                        self.name_len += 1;
                    }
                }
            } else if self.field {
                if byte == b' ' || byte == b'\t' {
                    if self.digits != 0 {
                        self.trailing = 1;
                    }
                } else if byte.is_ascii_digit() && self.trailing == 0 && self.digits < 10 {
                    self.digits += 1;
                    self.length = self.length * 10 + u64::from(byte - b'0');
                } else {
                    self.invalid = true;
                    return;
                }
            }
        }
    }
}

/// Последовательные HTTP-запросы одного TCP-потока с fail-open при потере границы.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oHttpRequestSequence {
    first: Option<u32>,
    next: Option<u32>,
    checked: bool,
    disabled: bool,
    stream: Option<R2oHttpRequestStream>,
    stream_later: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum R2oHttpRequestCandidate {
    First,
    Later,
    Unaligned,
    Ignored,
}

/// Результат проверки TCP-границы HTTP-запроса.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oHttpRequestObservation {
    /// Сегмент относится к телу, повтору или не наблюдаемой границе.
    Ignored,
    /// Следующая граница пропущена, пересечена или содержит не HTTP-запрос.
    Unaligned,
    /// Запрос распознан на первой или следующей границе.
    Request {
        /// Запрос идёт после первого запроса TCP-потока.
        later: bool,
        /// Конец запроса и тела однозначен по заголовкам.
        end_known: bool,
        /// Сегмент не содержит дополнительные байты за концом запроса.
        aligned: bool,
    },
}

impl R2oHttpRequestSequence {
    /// Начать отслеживание после SYN, который был виден runtime.
    pub const fn new(first: u32) -> Self {
        Self {
            first: Some(first),
            next: None,
            checked: false,
            disabled: false,
            stream: None,
            stream_later: false,
        }
    }

    /// Проверить, начинается ли сегмент на доказанной границе запроса.
    pub fn candidate(&mut self, sequence: u32, payload_len: usize) -> bool {
        matches!(
            self.candidate_state(sequence, payload_len),
            R2oHttpRequestCandidate::First | R2oHttpRequestCandidate::Later
        )
    }

    fn candidate_state(&mut self, sequence: u32, payload_len: usize) -> R2oHttpRequestCandidate {
        if self.disabled {
            return R2oHttpRequestCandidate::Ignored;
        }
        if self.stream.is_some() {
            return if self.stream_later {
                R2oHttpRequestCandidate::Later
            } else {
                R2oHttpRequestCandidate::First
            };
        }
        if !self.checked {
            return if self.first == Some(sequence) {
                R2oHttpRequestCandidate::First
            } else {
                R2oHttpRequestCandidate::Ignored
            };
        }
        let Some(next) = self.next else {
            return R2oHttpRequestCandidate::Ignored;
        };
        let distance = sequence.wrapping_sub(next) as i32;
        if distance == 0 {
            return R2oHttpRequestCandidate::Later;
        }
        let segment_end = sequence.wrapping_add(payload_len as u32);
        if distance > 0 || segment_end.wrapping_sub(next) as i32 > 0 {
            self.next = None;
            self.disabled = true;
            return R2oHttpRequestCandidate::Unaligned;
        }
        R2oHttpRequestCandidate::Ignored
    }

    /// Принять полный запрос и запомнить следующую границу, если framing известен.
    pub fn observe(&mut self, sequence: u32, payload: &[u8]) -> bool {
        matches!(
            self.observe_detailed(sequence, payload),
            R2oHttpRequestObservation::Request { .. }
        )
    }

    /// Обновить последовательность запросов и вернуть диагностический исход.
    pub fn observe_detailed(&mut self, sequence: u32, payload: &[u8]) -> R2oHttpRequestObservation {
        let candidate = self.candidate_state(sequence, payload.len());
        if candidate == R2oHttpRequestCandidate::Unaligned {
            return R2oHttpRequestObservation::Unaligned;
        }
        if !matches!(
            candidate,
            R2oHttpRequestCandidate::First | R2oHttpRequestCandidate::Later
        ) {
            return R2oHttpRequestObservation::Ignored;
        }
        if let Some(mut stream) = self.stream.take() {
            stream.feed(sequence, payload);
            if stream.invalid {
                self.first = None;
                self.next = None;
                self.checked = true;
                self.disabled = true;
                return if candidate == R2oHttpRequestCandidate::Later {
                    R2oHttpRequestObservation::Unaligned
                } else {
                    R2oHttpRequestObservation::Ignored
                };
            }
            if !stream.header_done {
                self.stream = Some(stream);
                return R2oHttpRequestObservation::Ignored;
            }
            let aligned = !stream.past_end;
            self.first = None;
            self.checked = true;
            self.next = aligned.then_some(stream.end);
            if !aligned {
                self.disabled = true;
            }
            return R2oHttpRequestObservation::Request {
                later: self.stream_later,
                end_known: true,
                aligned,
            };
        }
        let Some(request) = r2o_http_plan_request(payload) else {
            let mut stream = R2oHttpRequestStream::new(sequence);
            stream.feed(sequence, payload);
            if stream.invalid {
                self.first = None;
                self.next = None;
                self.checked = true;
                self.disabled = true;
                return if candidate == R2oHttpRequestCandidate::Later {
                    R2oHttpRequestObservation::Unaligned
                } else {
                    R2oHttpRequestObservation::Ignored
                };
            }
            if !stream.header_done {
                self.first = None;
                self.stream = Some(stream);
                self.stream_later = candidate == R2oHttpRequestCandidate::Later;
                return R2oHttpRequestObservation::Ignored;
            }
            let aligned = !stream.past_end;
            self.first = None;
            self.checked = true;
            self.next = aligned.then_some(stream.end);
            if !aligned {
                self.disabled = true;
            }
            return R2oHttpRequestObservation::Request {
                later: candidate == R2oHttpRequestCandidate::Later,
                end_known: true,
                aligned,
            };
        };
        self.first = None;
        self.checked = true;
        let end_known = request.end_offset.is_some();
        let aligned = request.end_offset.is_none_or(|end| end >= payload.len());
        self.next = request
            .end_offset
            .filter(|&end| end >= payload.len())
            .map(|end| sequence.wrapping_add(end as u32));
        if !end_known || !aligned {
            self.disabled = true;
        }
        R2oHttpRequestObservation::Request {
            later: candidate == R2oHttpRequestCandidate::Later,
            end_known,
            aligned,
        }
    }

    /// Сообщить, что первый запрос или keep-alive-запрос уже проверен.
    pub const fn is_checked(self) -> bool {
        self.checked
    }
}

/// `true`, если запрос GET или HEAD полностью получен, не содержит тела и имеет
/// корректный заголовок Host с путём в форме origin.
pub fn request_safe(input: &[u8]) -> bool {
    parse_request(input).is_some()
}

/// Вернуть нормализованный Host и цель запроса в форме origin.
pub fn request_target(input: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let request = parse_request(input)?;
    Some((request.host.to_vec(), request.target.to_vec()))
}

/// Вернуть диапазон нормализованного Host для привязки HTTP, аналогичной SNI.
pub fn request_host_range(input: &[u8]) -> Option<Range<usize>> {
    Some(r2o_http_plan_request(input)?.host_range)
}

/// Разобрать начало HTTP-запроса для выбора плана без предположений о теле.
pub fn r2o_http_plan_request(input: &[u8]) -> Option<R2oHttpPlanRequest> {
    let request = parse_plan_request(input)?;
    Some(R2oHttpPlanRequest {
        host_range: request.host_range,
        header_len: request.header_len,
        end_offset: request.end_offset,
    })
}

/// Вернуть ответ 307 только для безопасного запроса, на который явно ответил
/// портал фильтрации.
pub fn portal_response(request: &[u8], upstream: &[u8]) -> Option<Vec<u8>> {
    let request = parse_request(request)?;
    let portal = portal_host(request.host, upstream)?;
    if !known_portal_host(&portal) && !portal_marker(&portal) {
        return None;
    }
    build_redirect(request.host, request.target)
}

/// Вернуть имя стороннего портала, распознанное в заголовках ответа.
pub fn portal_location(host: &[u8], response: &[u8]) -> Option<Vec<u8>> {
    let portal = portal_host(host, response)?;
    (known_portal_host(&portal) || portal_marker(&portal)).then_some(portal)
}

/// Сформировать соответствующий HTTPS-ответ 307 для проверенного DNS-имени
/// и цели запроса в форме origin.
pub fn redirect_https(host: &[u8], target: &[u8]) -> Option<Vec<u8>> {
    if !valid_dns_host(host)
        || target.first() != Some(&b'/')
        || target
            .iter()
            .any(|&byte| byte <= 0x20 || byte == 0x7f || byte == b'#')
    {
        return None;
    }
    build_redirect(host, target)
}

fn parse_request(input: &[u8]) -> Option<Request<'_>> {
    let request = parse_plan_request(input)?;
    if (request.method != b"GET" && request.method != b"HEAD")
        || request.end_offset != Some(request.header_len)
        || request.header_len != input.len()
    {
        return None;
    }
    Some(request)
}

fn parse_plan_request(input: &[u8]) -> Option<Request<'_>> {
    if input.len() < 16 {
        return None;
    }
    let first_end = find_crlf(input, 0)?;
    let first = &input[..first_end];
    let first_space = first.iter().position(|&byte| byte == b' ')?;
    let method = &first[..first_space];
    if method.is_empty() || method.len() > 20 || !method.iter().all(u8::is_ascii_uppercase) {
        return None;
    }
    let target_start = first_space + 1;
    let second_space = first[target_start..]
        .iter()
        .position(|&byte| byte == b' ')?
        + target_start;
    let target = &first[target_start..second_space];
    if target.first() != Some(&b'/') || target.len() >= 2048 {
        return None;
    }
    if !matches!(&first[second_space + 1..], b"HTTP/1.0" | b"HTTP/1.1")
        || target
            .iter()
            .any(|&byte| byte <= 0x20 || byte == 0x7f || byte == b'#')
    {
        return None;
    }

    let mut host = None;
    let mut host_start = None;
    let mut content_length_seen = false;
    let mut content_length = None;
    let mut boundary_known = true;
    let mut cursor = first_end + 2;
    let mut header_len = 0;
    let mut header_complete = false;
    loop {
        // C `d2k_http_request`: неполная строка заголовка в этом сегменте
        // завершает разбор, но уже найденный Host остаётся действительным.
        let Some(relative_end) = find_crlf(&input[cursor..], 0) else {
            break;
        };
        let line_start = cursor;
        let line_end = cursor + relative_end;
        let line = &input[cursor..line_end];
        cursor = line_end + 2;
        if line.is_empty() {
            header_len = cursor;
            header_complete = true;
            break;
        }
        if line
            .iter()
            .any(|&byte| byte == 0x7f || (byte < 0x20 && byte != b'\t'))
        {
            boundary_known = false;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            boundary_known = false;
            continue;
        };
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|byte| is_http_token(*byte)) {
            boundary_known = false;
        }
        let value = trim_ows(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"Host") {
            if host.is_some() || value.is_empty() || value.len() >= 256 {
                return None;
            }
            let raw_start = colon + 1;
            let leading = line[raw_start..]
                .iter()
                .take_while(|&&byte| matches!(byte, b' ' | b'\t'))
                .count();
            host_start = Some(line_start + raw_start + leading);
            host = Some(value);
        } else if name.eq_ignore_ascii_case(b"Content-Length") {
            if content_length_seen {
                boundary_known = false;
                content_length = None;
            } else if let Some(length) = parse_content_length(value) {
                content_length = Some(length);
            } else {
                boundary_known = false;
            }
            content_length_seen = true;
        } else if name.eq_ignore_ascii_case(b"Transfer-Encoding")
            || name.eq_ignore_ascii_case(b"Upgrade")
        {
            boundary_known = false;
        }
    }
    let end_offset = if header_complete && boundary_known {
        header_len
            .checked_add(content_length.unwrap_or_default())
            .filter(|&end| end <= 0x7fff_ffff)
    } else {
        None
    };

    let mut host = host?;
    let host_start = host_start?;
    if let Some(colon) = host.iter().position(|&byte| byte == b':') {
        if &host[colon..] != b":80" {
            return None;
        }
        host = &host[..colon];
    }
    if host.last() == Some(&b'.') {
        host = &host[..host.len() - 1];
    }
    let host_range = host_start..host_start + host.len();
    valid_http_name_host(host).then_some(Request {
        host,
        target,
        host_range,
        method,
        header_len,
        end_offset,
    })
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn valid_http_name_host(host: &[u8]) -> bool {
    if !valid_dns_host(host) {
        return false;
    }
    let last_label = host.rsplit(|&byte| byte == b'.').next().unwrap_or_default();
    !last_label.iter().all(u8::is_ascii_digit)
}

fn parse_content_length(value: &[u8]) -> Option<usize> {
    if value.is_empty() {
        return None;
    }
    value.iter().try_fold(0_usize, |length, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        length
            .checked_mul(10)?
            .checked_add(usize::from(*byte - b'0'))
    })
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn find_crlf(input: &[u8], start: usize) -> Option<usize> {
    input
        .get(start..)?
        .windows(2)
        .position(|pair| pair == b"\r\n")?
        .checked_add(start)
}

fn valid_dns_host(host: &[u8]) -> bool {
    if host.is_empty() || host.len() > 253 || host[0] == b'.' || host[host.len() - 1] == b'.' {
        return false;
    }
    let mut label_len = 0;
    for (index, &byte) in host.iter().enumerate() {
        if byte == b'.' {
            if label_len == 0 || label_len > 63 || host[index - 1] == b'-' {
                return false;
            }
            label_len = 0;
        } else {
            if !(byte.is_ascii_alphanumeric() || byte == b'-') || (label_len == 0 && byte == b'-') {
                return false;
            }
            label_len += 1;
        }
    }
    label_len > 0 && label_len <= 63 && host[host.len() - 1] != b'-'
}

fn portal_host(request_host: &[u8], upstream: &[u8]) -> Option<Vec<u8>> {
    if upstream.len() < 16 {
        return None;
    }
    let status_end = find_crlf(upstream, 0)?;
    let status = &upstream[..status_end];
    if status.len() < 13
        || &status[..7] != b"HTTP/1."
        || !matches!(status[7], b'0' | b'1')
        || status[8] != b' '
        || &status[9..11] != b"30"
        || status[12] != b' '
        || !matches!(status[11], b'1' | b'2' | b'3' | b'7' | b'8')
    {
        return None;
    }

    let mut location = None;
    let mut cursor = status_end + 2;
    loop {
        let line_end = find_crlf(upstream, cursor)?;
        let line = &upstream[cursor..line_end];
        cursor = line_end + 2;
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(b"Location") {
            if location.is_some() {
                return None;
            }
            location = Some(parse_location_host(trim_ows(&line[colon + 1..]))?);
        }
    }

    let location = location?;
    (!same_host(request_host, &location)).then_some(location)
}

fn parse_location_host(value: &[u8]) -> Option<Vec<u8>> {
    let authority = if value.len() >= 7 && value[..7].eq_ignore_ascii_case(b"http://") {
        &value[7..]
    } else if value.len() >= 8 && value[..8].eq_ignore_ascii_case(b"https://") {
        &value[8..]
    } else {
        return None;
    };
    let end = authority
        .iter()
        .position(|&byte| matches!(byte, b'/' | b'?' | b'#' | b':'))
        .unwrap_or(authority.len());
    let host = &authority[..end];
    valid_dns_host(host).then(|| host.to_vec())
}

fn same_host(left: &[u8], right: &[u8]) -> bool {
    let left = left.strip_suffix(b".").unwrap_or(left);
    let right = right.strip_suffix(b".").unwrap_or(right);
    !left.is_empty() && left.eq_ignore_ascii_case(right)
}

fn portal_marker(host: &[u8]) -> bool {
    const MARKERS: [&[u8]; 8] = [
        b"lawfilter",
        b"blockpage",
        b"blocked",
        b"censorship",
        b"access-denied",
        b"provider-filter",
        b"megafonpro",
        b"blackhole",
    ];
    host.split(|&byte| byte == b'.').any(|label| {
        MARKERS
            .iter()
            .any(|marker| label.eq_ignore_ascii_case(marker))
    })
}

fn known_portal_host(host: &[u8]) -> bool {
    const HOSTS: [&[u8]; 6] = [
        b"eais.rkn.gov.ru",
        b"lawfilter.ertelecom.ru",
        b"blackhole.svyaztelecom.ru",
        b"warning.rt.ru",
        b"warn.beeline.ru",
        b"deny.megafon.ru",
    ];
    HOSTS.iter().any(|known| same_host(host, known))
}

fn build_redirect(host: &[u8], target: &[u8]) -> Option<Vec<u8>> {
    if host.len() >= 256 || target.len() >= 2048 || target.first() != Some(&b'/') {
        return None;
    }
    let mut response = Vec::with_capacity(192 + host.len() + target.len());
    response.extend_from_slice(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://");
    response.extend_from_slice(host);
    response.extend_from_slice(target);
    response.extend_from_slice(
        b"\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\nX-R2O-HTTP-Upgrade: provider-portal\r\n\r\n",
    );
    Some(response)
}

#[cfg(test)]
mod dns_host_tests {
    use super::valid_dns_host;

    #[test]
    fn dns_host_matches_c() {
        assert!(valid_dns_host(b"example.com"));
        assert!(valid_dns_host(b"a"));
        assert!(valid_dns_host(b"a-b.c-d"));
        assert!(valid_dns_host(&[b'a'; 63]));
        assert!(!valid_dns_host(b""));
        assert!(!valid_dns_host(b".example.com"));
        assert!(!valid_dns_host(b"example.com."));
        assert!(!valid_dns_host(b"exa..mple"));
        assert!(!valid_dns_host(b"-a.example"));
        assert!(!valid_dns_host(b"a-.example"));
        assert!(!valid_dns_host(b"a_b.example"));
        assert!(!valid_dns_host(&[b'a'; 64]));
        assert!(!valid_dns_host(&[b'a'; 254]));
    }

    #[test]
    fn http_name_host_rejects_numeric_last_label_like_c() {
        use super::valid_http_name_host;
        assert!(valid_http_name_host(b"example.com"));
        assert!(valid_http_name_host(b"a.1b"));
        assert!(!valid_http_name_host(b"example.123"));
        assert!(!valid_http_name_host(b"123"));
        assert!(!valid_http_name_host(b"a..1"));
        assert!(!valid_http_name_host(b""));
    }
}
