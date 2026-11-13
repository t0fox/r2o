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
    // C `field_after` завершает значение только на пробеле или переводе
    // строки; прочие whitespace остаются частью значения и ломают разбор.
    line.split(|byte| matches!(byte, b' ' | b'\n'))
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

    #[test]
    fn parse_ip4_and_address_match_c_nat_parser() {
        use super::{parse_address, parse_ipv4};
        // C `parse_ip4` не ограничивает число цифр, пока значение <= 255.
        assert_eq!(parse_ipv4("010.0.0.1"), Some([10, 0, 0, 1]));
        assert_eq!(parse_ipv4("001.002.003.004"), Some([1, 2, 3, 4]));
        assert_eq!(parse_ipv4("0001.2.3.4"), Some([1, 2, 3, 4]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
        for invalid in [
            "",
            "1.2.3",
            "1.2.3.4.5",
            "256.1.1.1",
            "1..2.3",
            "a.b.c.d",
            "1.2.3.4 ",
            "1.2.3.4\n",
        ] {
            assert_eq!(parse_ipv4(invalid), None, "{invalid:?}");
        }

        let mut expected = [0; 16];
        expected[..4].copy_from_slice(&[192, 168, 1, 117]);
        assert_eq!(parse_address(b"192.168.1.117", 4), Some(expected));
        assert_eq!(
            parse_address(b"2001:db8::1", 6),
            Some(
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
            )
        );
        // C `inet_pton` не принимает зону; семейство вне 4/6 отвергается.
        assert_eq!(parse_address(b"fe80::1%eth0", 6), None);
        assert_eq!(parse_address(b"192.168.1.1", 5), None);
    }

    #[test]
    fn field_after_matches_c_word_boundary_and_continuation() {
        use super::{field_after, fields};
        let line = b"ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.117 dst=157.240.205.21 sport=50759 dport=443 src=157.240.205.21 dst=192.168.1.117 sport=443 dport=50759 [ASSURED] mark=0 use=1\n";
        let parsed = fields(line);
        let (src_at, src) = field_after(&parsed, 0, b"src").unwrap();
        assert_eq!(src, b"192.168.1.117");
        let (dst_at, dst) = field_after(&parsed, src_at + 1, b"dst").unwrap();
        assert_eq!(dst, b"157.240.205.21");
        let (sport_at, sport) = field_after(&parsed, dst_at + 1, b"sport").unwrap();
        assert_eq!(sport, b"50759");
        let (dport_at, dport) = field_after(&parsed, sport_at + 1, b"dport").unwrap();
        assert_eq!(dport, b"443");
        // C требует имя на границе слова: `port` не находится внутри `sport`.
        assert!(field_after(&parsed, 0, b"port").is_none());
        let (reply_src_at, reply_src) = field_after(&parsed, dport_at + 1, b"src").unwrap();
        assert_eq!(reply_src, b"157.240.205.21");
        let (_, reply_dport) = field_after(&parsed, reply_src_at + 1, b"dport").unwrap();
        assert_eq!(reply_dport, b"50759");

        // C завершает значение только на пробеле/переводе строки: табуляция
        // остаётся частью значения и ломает последующий разбор адреса.
        let with_tab = fields(b"src=1\t2\n");
        assert_eq!(with_tab[0], (&b"src"[..], &b"1\t2"[..]));
    }
}
