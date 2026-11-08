//! HTTP/3 control/request/status helpers — перенос `core/h3.c`.
//!
//! Разбирается ровно то, что нужно зонду: управляющий поток, GET-запрос и
//! `:status` из первого HEADERS. Динамическая таблица QPACK не объявляется и
//! не принимается.

const H3_DATA: u64 = 0x00;
const H3_HEADERS: u64 = 0x01;
const H3_SETTINGS: u64 = 0x04;

/// Содержимое клиентского управляющего потока: тип потока и пустой SETTINGS.
pub fn control(out: &mut [u8]) -> usize {
    if out.len() < 3 {
        return 0;
    }
    out[0] = 0x00;
    out[1] = H3_SETTINGS as u8;
    out[2] = 0x00;
    3
}

/// QUIC varint (RFC 9000 §16): те же числа, что в `core/quicwire.c`.
fn varint_write(out: &mut [u8], value: u64) -> usize {
    let (width, prefix) = if value < (1 << 6) {
        (1, 0x00)
    } else if value < (1 << 14) {
        (2, 0x40)
    } else if value < (1 << 30) {
        (4, 0x80)
    } else {
        (8, 0xc0)
    };
    if out.len() < width {
        return 0;
    }
    for index in 0..width {
        let shift = (width - 1 - index) * 8;
        out[index] = ((value >> shift) as u8 & 0xff) | if index == 0 { prefix } else { 0 };
    }
    width
}

fn varint_read(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let width = 1 << (first >> 6);
    if input.len() < width {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for &byte in &input[1..width] {
        value = (value << 8) | u64::from(byte);
    }
    Some((value, width))
}

/// QPACK/HPACK prefix integer (RFC 7541 §5.1).
fn prefix_max(prefix_bits: u8) -> u8 {
    if prefix_bits >= 8 {
        0xff
    } else {
        (1_u8 << prefix_bits) - 1
    }
}

fn prefix_int(out: &mut [u8], prefix_bits: u8, flags: u8, value: u64) -> usize {
    let max = prefix_max(prefix_bits);
    if out.is_empty() {
        return 0;
    }
    if value < u64::from(max) {
        out[0] = flags | value as u8;
        return 1;
    }
    out[0] = flags | max;
    let mut offset = 1;
    let mut value = value - u64::from(max);
    while value >= 128 {
        if offset >= out.len() {
            return 0;
        }
        out[offset] = (value as u8 & 0x7f) | 0x80;
        offset += 1;
        value >>= 7;
    }
    if offset >= out.len() {
        return 0;
    }
    out[offset] = value as u8;
    offset + 1
}

fn prefix_int_read(input: &[u8], prefix_bits: u8, value: &mut u64, used: &mut usize) -> bool {
    let Some(&first) = input.first() else {
        return false;
    };
    let max = prefix_max(prefix_bits);
    let mut current = u64::from(first & max);
    let mut offset = 1;
    if current == u64::from(max) {
        let mut shift = 0_u32;
        loop {
            let Some(&byte) = input.get(offset) else {
                return false;
            };
            offset += 1;
            current += u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 56 {
                return false;
            }
        }
    }
    *value = current;
    *used = offset;
    true
}

/// Хаффман RFC 7541 прил. B только для трёх десятичных цифр статуса.
fn huff_status(value: &[u8], status: &mut u16) -> bool {
    if value.len() < 2 || value.len() > 3 {
        return false;
    }
    let mut bits = 0_u32;
    for &byte in value {
        bits = (bits << 8) | u32::from(byte);
    }
    let total = value.len() as i32 * 8;
    let mut position = 0_i32;
    let mut result = 0_u32;
    for _ in 0..3 {
        if total - position < 5 {
            return false;
        }
        let code5 = (bits >> (total - position - 5) as u32) & 0x1f;
        if code5 <= 2 {
            result = result * 10 + code5;
            position += 5;
            continue;
        }
        if total - position < 6 {
            return false;
        }
        let code6 = (bits >> (total - position - 6) as u32) & 0x3f;
        if !(0x19..=0x1f).contains(&code6) {
            return false;
        }
        result = result * 10 + (code6 - 0x19 + 3);
        position += 6;
    }
    let rest = total - position;
    if rest >= 8 {
        return false;
    }
    let mask = if rest == 0 { 0 } else { (1_u32 << rest) - 1 };
    if bits & mask != mask {
        return false;
    }
    *status = result as u16;
    true
}

fn static_status(index: u64) -> Option<u16> {
    match index {
        24 => Some(103),
        25 => Some(200),
        26 => Some(304),
        27 => Some(404),
        28 => Some(503),
        63 => Some(100),
        64 => Some(204),
        65 => Some(206),
        66 => Some(302),
        67 => Some(400),
        68 => Some(403),
        69 => Some(421),
        70 => Some(425),
        71 => Some(500),
        _ => None,
    }
}

fn name_is_status(index: u64) -> bool {
    matches!(index, 24..=28 | 63..=71)
}

fn decode_section(section: &[u8], status: &mut u16) -> bool {
    let mut offset = 0;
    let mut value = 0_u64;
    let mut used = 0_usize;
    if !prefix_int_read(&section[offset..], 8, &mut value, &mut used) {
        return false;
    }
    offset += used;
    if offset >= section.len() {
        return false;
    }
    if !prefix_int_read(&section[offset..], 7, &mut value, &mut used) {
        return false;
    }
    offset += used;

    while offset < section.len() {
        let byte = section[offset];
        if byte & 0x80 != 0 {
            if !prefix_int_read(&section[offset..], 6, &mut value, &mut used) {
                return false;
            }
            offset += used;
            if byte & 0x40 != 0
                && let Some(found) = static_status(value)
            {
                *status = found;
                return true;
            }
        } else if byte & 0xc0 == 0x40 {
            let is_static = byte & 0x10 != 0;
            if !prefix_int_read(&section[offset..], 4, &mut value, &mut used) {
                return false;
            }
            offset += used;
            let name_index = value;
            let Some(&value_first) = section.get(offset) else {
                return false;
            };
            let huffman = value_first & 0x80 != 0;
            let mut value_len = 0_u64;
            if !prefix_int_read(&section[offset..], 7, &mut value_len, &mut used) {
                return false;
            }
            offset += used;
            let value_len = value_len as usize;
            if value_len > section.len() - offset {
                return false;
            }
            if is_static && name_is_status(name_index) {
                if huffman {
                    if huff_status(&section[offset..offset + value_len], status) {
                        return true;
                    }
                } else if value_len == 3 {
                    *status = (u16::from(section[offset] - b'0') * 100)
                        + (u16::from(section[offset + 1] - b'0') * 10)
                        + u16::from(section[offset + 2] - b'0');
                    return true;
                }
            }
            offset += value_len;
        } else if byte & 0xe0 == 0x20 {
            let mut name_len = 0_u64;
            if !prefix_int_read(&section[offset..], 3, &mut name_len, &mut used) {
                return false;
            }
            offset += used;
            let name_len = name_len as usize;
            if name_len > section.len() - offset {
                return false;
            }
            let name_status = byte & 0x08 == 0
                && name_len == 7
                && &section[offset..offset + name_len] == b":status";
            offset += name_len;
            let Some(&value_first) = section.get(offset) else {
                return false;
            };
            let huffman = value_first & 0x80 != 0;
            let mut value_len = 0_u64;
            if !prefix_int_read(&section[offset..], 7, &mut value_len, &mut used) {
                return false;
            }
            offset += used;
            let value_len = value_len as usize;
            if value_len > section.len() - offset {
                return false;
            }
            if name_status {
                if huffman {
                    if huff_status(&section[offset..offset + value_len], status) {
                        return true;
                    }
                } else if value_len == 3 {
                    *status = (u16::from(section[offset] - b'0') * 100)
                        + (u16::from(section[offset + 1] - b'0') * 10)
                        + u16::from(section[offset + 2] - b'0');
                    return true;
                }
            }
            offset += value_len;
        } else if byte & 0x10 != 0 {
            if !prefix_int_read(&section[offset..], 4, &mut value, &mut used) {
                return false;
            }
            offset += used;
        } else {
            if !prefix_int_read(&section[offset..], 3, &mut value, &mut used) {
                return false;
            }
            offset += used;
            let mut value_len = 0_u64;
            if !prefix_int_read(&section[offset..], 7, &mut value_len, &mut used) {
                return false;
            }
            offset += used;
            let value_len = value_len as usize;
            if value_len > section.len() - offset {
                return false;
            }
            offset += value_len;
        }
    }
    false
}

/// Ищет `:status` в первом кадре HEADERS; неизвестные кадры пропускает.
pub fn status(input: &[u8]) -> Option<u16> {
    let mut offset = 0;
    while offset < input.len() {
        let (frame_type, used) = varint_read(&input[offset..])?;
        offset += used;
        let (length, used) = varint_read(&input[offset..])?;
        offset += used;
        let length = usize::try_from(length).ok()?;
        if length > input.len() - offset {
            return None;
        }
        if frame_type == H3_HEADERS {
            let mut result = 0_u16;
            return decode_section(&input[offset..offset + length], &mut result).then_some(result);
        }
        offset += length;
    }
    None
}

/// Кадр HEADERS с GET-запросом к `host`/`path`.
pub fn request(host: &str, path: &str, out: &mut [u8]) -> usize {
    let host = host.as_bytes();
    if host.is_empty() || host.len() > 255 {
        return 0;
    }
    let path = if path.is_empty() { "/" } else { path };
    let path = path.as_bytes();

    let mut section = [0_u8; 512];
    let mut used = 0_usize;
    section[0] = 0;
    section[1] = 0;
    used += 2;
    used += prefix_int(&mut section[used..], 6, 0xc0, 17);
    used += prefix_int(&mut section[used..], 6, 0xc0, 23);
    if path == b"/" {
        used += prefix_int(&mut section[used..], 6, 0xc0, 1);
    }
    used += prefix_int(&mut section[used..], 4, 0x50, 0);
    used += prefix_int(&mut section[used..], 7, 0x00, host.len() as u64);
    if used + host.len() > section.len() {
        return 0;
    }
    section[used..used + host.len()].copy_from_slice(host);
    used += host.len();
    if path != b"/" {
        if path.len() > 255 {
            return 0;
        }
        used += prefix_int(&mut section[used..], 4, 0x50, 1);
        used += prefix_int(&mut section[used..], 7, 0x00, path.len() as u64);
        if used + path.len() > section.len() {
            return 0;
        }
        section[used..used + path.len()].copy_from_slice(path);
        used += path.len();
    }

    if out.is_empty() {
        return 0;
    }
    out[0] = H3_HEADERS as u8;
    let mut total = 1;
    total += varint_write(&mut out[total..], used as u64);
    if total + used > out.len() {
        return 0;
    }
    out[total..total + used].copy_from_slice(&section[..used]);
    total + used
}

/// Тип кадра DATA оставлен для тестов и будущих потребителей разбора.
pub const fn frame_type_data() -> u64 {
    H3_DATA
}

#[cfg(test)]
mod tests {
    use super::{control, request, status};

    #[test]
    fn control_stream_is_type_plus_empty_settings() {
        let mut buffer = [0_u8; 16];
        let length = control(&mut buffer);
        assert_eq!(&buffer[..length], [0x00, 0x04, 0x00]);
    }

    #[test]
    fn request_root_matches_rfc_static_indices() {
        let mut buffer = [0_u8; 128];
        let length = request("example.com", "/", &mut buffer);
        assert!(length > 0);
        assert_eq!(buffer[0], 0x01);
        assert_eq!(&buffer[2..4], [0x00, 0x00]);
        assert_eq!(&buffer[4..9], [0xd1, 0xd7, 0xc1, 0x50, 11]);
        assert_eq!(&buffer[9..20], b"example.com");
    }

    #[test]
    fn request_non_root_carries_exactly_one_literal_path() {
        let mut buffer = [0_u8; 128];
        let length = request("example.com", "/big.css", &mut buffer);
        assert!(length > 0);
        let body = &buffer[2..length];
        assert_eq!(&body[..6], [0x00, 0x00, 0xd1, 0xd7, 0x50, 11]);
        assert_eq!(&body[6..17], b"example.com");
        assert_eq!(
            &body[17..],
            [0x51, 8, b'/', b'b', b'i', b'g', b'.', b'c', b's', b's']
        );
    }

    #[test]
    fn status_reads_static_index_and_huffman_literal() {
        assert_eq!(status(&[0x01, 0x03, 0x00, 0x00, 0xd9]), Some(200));
        assert_eq!(
            status(&[0x01, 0x08, 0x00, 0x00, 0x5f, 0x0c, 0x83, 0x68, 0x0d, 0x7f]),
            Some(404)
        );
        assert_eq!(
            status(&[0x01, 0x08, 0x00, 0x00, 0x5f, 0x0c, 0x03, b'2', b'0', b'1']),
            Some(201)
        );
    }

    #[test]
    fn status_skips_unknown_frame_and_rejects_truncation() {
        assert_eq!(
            status(&[0x21, 0x02, 0xaa, 0xbb, 0x01, 0x03, 0x00, 0x00, 0xd9]),
            Some(200)
        );
        assert_eq!(status(&[0x01, 0x10, 0x00, 0x00]), None);
    }

    #[test]
    fn status_handles_literal_name_and_post_base_forms() {
        assert_eq!(
            status(&[
                0x01, 0x09, 0x00, 0x00, 0x23, b'x', b'-', b'a', 0x01, b'1', 0xd9
            ]),
            Some(200)
        );
        assert_eq!(
            status(&[0x01, 0x07, 0x00, 0x00, 0x11, 0x02, 0x01, b'1', 0xd9]),
            Some(200)
        );
    }
}
