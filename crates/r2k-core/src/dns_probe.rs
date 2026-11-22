//! Точный wire-ключ изолированного DNS-зонда с одним вопросом класса IN.

use sha2::{Digest, Sha256};

pub const DNS_PROBE_QUERY_MIN: usize = 17;
pub const DNS_PROBE_QUERY_MAX: usize = 272;

pub fn is_dns_probe_length(length: usize) -> bool {
    (DNS_PROBE_QUERY_MIN..=DNS_PROBE_QUERY_MAX).contains(&length)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsProbeGuard {
    pub length: u16,
    pub sha256: [u8; 32],
}

impl DnsProbeGuard {
    pub fn decode_prefix(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let (prefix, rest) = bytes.split_at_checked(34)?;
        let length = u16::from_be_bytes(prefix[..2].try_into().ok()?);
        if !is_dns_probe_length(usize::from(length)) {
            return None;
        }
        Some((
            Self {
                length,
                sha256: prefix[2..].try_into().ok()?,
            },
            rest,
        ))
    }

    pub fn from_query(query: &[u8]) -> Option<Self> {
        is_dns_probe_query(query).then(|| Self {
            length: query.len() as u16,
            sha256: Sha256::digest(query).into(),
        })
    }

    pub fn matches(self, query: &[u8]) -> bool {
        usize::from(self.length) == query.len() && Self::from_query(query) == Some(self)
    }
}

pub fn is_dns_probe_query(bytes: &[u8]) -> bool {
    if !is_dns_probe_length(bytes.len())
        || bytes[2] & 0xf8 != 0
        || bytes[4..12] != [0, 1, 0, 0, 0, 0, 0, 0]
    {
        return false;
    }
    let mut offset = 12;
    while let Some(&length) = bytes.get(offset) {
        offset += 1;
        if length == 0 {
            return offset - 12 <= 255
                && bytes.get(offset..).is_some_and(|tail| {
                    tail.len() == 4 && tail[..2] != [0, 0] && tail[2..] == [0, 1]
                });
        }
        // Запрос зонда содержит имя без указателей сжатия.
        if length > 63 {
            return false;
        }
        offset += usize::from(length);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn зонд_принимает_только_исходные_байты_вопроса() {
        let question = *b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01";
        let guard = DnsProbeGuard::from_query(&question).unwrap();
        assert!(guard.matches(&question));

        let mut other = question;
        other[1] ^= 1;
        assert!(is_dns_probe_query(&other));
        assert!(!guard.matches(&other));
        other[2] |= 0x80;
        assert!(!is_dns_probe_query(&other));
        assert!(!is_dns_probe_query(&question[..question.len() - 1]));
        other = question;
        other[12] = 0xc0;
        assert!(!is_dns_probe_query(&other));
    }
}
