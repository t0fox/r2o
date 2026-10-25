//! NAT-контекст из `/proc/net/nf_conntrack`, как в `d2o/datapath/nat.c`.

use crate::conntrack::{R2oConntrackNatSource, R2oConntrackTuple};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::path::Path;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oProcNatLookup {
    /// `fopen` завершился ошибкой: таблицы нет, следовательно NAT-контекста нет.
    TableMissing,
    /// Таблица есть, но записи потока в ней нет.
    Missing,
    /// Нашлась запись, включая потоки без фактической трансляции.
    Found(R2oConntrackNatSource),
}

pub fn lookup(path: &Path, tuple: &R2oConntrackTuple) -> R2oProcNatLookup {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return R2oProcNatLookup::TableMissing,
    };
    if !matches!(tuple.family, 4 | 6) {
        return R2oProcNatLookup::Missing;
    }
    let protocol = match tuple.protocol {
        6 => b"tcp".as_slice(),
        17 => b"udp".as_slice(),
        _ => return R2oProcNatLookup::Missing,
    };
    let address_len = if tuple.family == 4 { 4 } else { 16 };
    let mut best: Option<(i64, R2oConntrackNatSource)> = None;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();

    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        // C uses fgets(line, 1024) and drains a line that did not fit. Such a
        // line is skipped whole; accepting its prefix could match another flow.
        let content_len = line.len() - usize::from(line.last() == Some(&b'\n'));
        if content_len > 1022 {
            continue;
        }
        if !contains(&line, protocol) {
            continue;
        }
        let fields = fields(&line);
        let Some((src_at, src)) = field_after(&fields, 0, b"src") else {
            continue;
        };
        let Some((dst_at, dst)) = field_after(&fields, src_at + 1, b"dst") else {
            continue;
        };
        let Some((sport_at, sport)) = field_after(&fields, dst_at + 1, b"sport") else {
            continue;
        };
        let Some((dport_at, dport)) = field_after(&fields, sport_at + 1, b"dport") else {
            continue;
        };
        let Some(src) = parse_address(src, tuple.family) else {
            continue;
        };
        let Some(dst) = parse_address(dst, tuple.family) else {
            continue;
        };
        if src[..address_len] != tuple.source[..address_len]
            || dst[..address_len] != tuple.destination[..address_len]
            || c_atoi(sport) as u16 != tuple.source_port
            || c_atoi(dport) as u16 != tuple.destination_port
        {
            continue;
        }

        let Some((reply_dst_at, reply_dst)) = field_after(&fields, dport_at + 1, b"dst") else {
            break;
        };
        let Some((_, reply_dport)) = field_after(&fields, reply_dst_at + 1, b"dport") else {
            break;
        };
        let Some(address) = parse_address(reply_dst, tuple.family) else {
            continue;
        };
        let port = c_atoi(reply_dport) as u16;
        let source = R2oConntrackNatSource {
            family: tuple.family,
            address,
            port,
        };
        let ttl = third_number(&line).unwrap_or(-1);
        if best.is_some_and(|(best_ttl, _)| ttl <= best_ttl) {
            continue;
        }
        best = Some((ttl, source));
    }

    best.map_or(R2oProcNatLookup::Missing, |(_, source)| {
        R2oProcNatLookup::Found(source)
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn fields(line: &[u8]) -> Vec<(&[u8], &[u8])> {
    line.split(|byte| byte.is_ascii_whitespace())
        .filter_map(|field| {
            let equal = field.iter().position(|byte| *byte == b'=')?;
            Some((&field[..equal], &field[equal + 1..]))
        })
        .collect()
}

fn field_after<'a>(
    fields: &'a [(&'a [u8], &'a [u8])],
    from: usize,
    wanted: &[u8],
) -> Option<(usize, &'a [u8])> {
    fields
        .iter()
        .enumerate()
        .skip(from)
        .find_map(|(index, (name, value))| (*name == wanted).then_some((index, *value)))
}

fn parse_address(text: &[u8], family: u8) -> Option<[u8; 16]> {
    let text = std::str::from_utf8(text).ok()?;
    let mut address = [0; 16];
    match family {
        4 => address[..4].copy_from_slice(&parse_ipv4(text)?),
        6 => address = Ipv6Addr::from_str(text).ok()?.octets(),
        _ => return None,
    }
    Some(address)
}

fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut parts = text.split('.');
    let mut address = [0; 4];
    for byte in &mut address {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|digit| digit.is_ascii_digit()) {
            return None;
        }
        let mut value = 0_u16;
        for digit in part.bytes() {
            value = value
                .checked_mul(10)?
                .checked_add(u16::from(digit - b'0'))?;
            if value > 255 {
                return None;
            }
        }
        *byte = value as u8;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(address)
}

fn c_atoi(text: &[u8]) -> i32 {
    let text = text.strip_prefix(b"+").unwrap_or(text);
    let (negative, digits) = if let Some(digits) = text.strip_prefix(b"-") {
        (true, digits)
    } else {
        (false, text)
    };
    let mut value = 0_i64;
    let mut any = false;
    for digit in digits.iter().copied().take_while(u8::is_ascii_digit) {
        any = true;
        value = value
            .saturating_mul(10)
            .saturating_add(i64::from(digit - b'0'));
    }
    if !any {
        return 0;
    }
    let signed = if negative { -value } else { value };
    signed.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

fn third_number(line: &[u8]) -> Option<i64> {
    let mut rest = line;
    let mut numbers = 0;
    while !rest.is_empty() {
        rest = rest.strip_prefix(b" ").unwrap_or(rest);
        if rest.first().is_some_and(u8::is_ascii_digit) {
            let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
            let value = std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()?;
            numbers += 1;
            if numbers == 3 {
                return Some(value);
            }
            rest = &rest[digits..];
        } else if let Some(space) = rest.iter().position(|byte| *byte == b' ') {
            rest = &rest[space..];
        } else {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{R2oProcNatLookup, lookup};
    use crate::conntrack::R2oConntrackTuple;
    use std::path::Path;

    #[test]
    fn отличает_отсутствие_таблицы_от_промаха_по_потоку() {
        let tuple = R2oConntrackTuple {
            family: 4,
            protocol: 6,
            source: [192, 168, 1, 117, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            destination: [157, 240, 205, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            source_port: 50759,
            destination_port: 443,
        };
        assert_eq!(
            lookup(Path::new("/definitely/missing/d2o-nf-conntrack"), &tuple),
            R2oProcNatLookup::TableMissing
        );
        let path = std::env::temp_dir().join(format!("r2o-nat-empty-{}", std::process::id()));
        std::fs::write(&path, "").unwrap();
        assert_eq!(lookup(&path, &tuple), R2oProcNatLookup::Missing);
        let _ = std::fs::remove_file(path);
    }
}
