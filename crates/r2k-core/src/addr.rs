use std::fmt;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};

/// IP-адрес-литерал в сетевом представлении, используемом datapath.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Address(IpAddr);

impl Address {
    /// Разобрать литерал IPv4 или IPv6. Имена узлов и идентификаторы зоны IPv6
    /// отклоняются.
    pub fn parse(value: &str) -> Result<Self, AddrParseError> {
        value.parse::<IpAddr>().map(Self)
    }

    pub const fn new(value: IpAddr) -> Self {
        Self(value)
    }

    pub const fn family(self) -> u8 {
        match self.0 {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        }
    }

    pub const fn as_ip_addr(self) -> IpAddr {
        self.0
    }

    /// Вернуть байты в сетевом порядке; хвост адреса IPv4 заполнен нулями.
    pub fn bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        match self.0 {
            IpAddr::V4(address) => bytes[..4].copy_from_slice(&address.octets()),
            IpAddr::V6(address) => bytes = address.octets(),
        }
        bytes
    }

    pub(crate) fn from_v4(bytes: [u8; 4]) -> Self {
        Self(IpAddr::V4(Ipv4Addr::from(bytes)))
    }

    pub(crate) fn from_v6(bytes: [u8; 16]) -> Self {
        Self(IpAddr::V6(Ipv6Addr::from(bytes)))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<IpAddr> for Address {
    fn from(value: IpAddr) -> Self {
        Self(value)
    }
}

impl From<Address> for IpAddr {
    fn from(value: Address) -> Self {
        value.0
    }
}

/// C `d2k_ip4_parse` (`core/net4.c:7-30`): 4 октета по 1–3 цифры, 0..255,
/// ведущие нули допустимы; ровно точки и конец строки.
pub fn parse_ipv4_legacy(text: &str) -> Option<Ipv4Addr> {
    let bytes = text.as_bytes();
    let mut octets = [0u8; 4];
    let mut position = 0usize;
    for (index, octet) in octets.iter_mut().enumerate() {
        let start = position;
        let mut value: u16 = 0;
        while position < bytes.len() && bytes[position].is_ascii_digit() {
            if position - start >= 3 {
                return None;
            }
            value = value * 10 + u16::from(bytes[position] - b'0');
            if value > 255 {
                return None;
            }
            position += 1;
        }
        if position == start {
            return None;
        }
        *octet = value as u8;
        if index < 3 {
            if bytes.get(position) != Some(&b'.') {
                return None;
            }
            position += 1;
        }
    }
    (position == bytes.len()).then(|| Ipv4Addr::from(octets))
}

#[cfg(test)]
mod ipv4_legacy_tests {
    use super::parse_ipv4_legacy;
    use std::net::Ipv4Addr;

    #[test]
    fn ip4_parse_accepts_leading_zeros_like_c() {
        assert_eq!(
            parse_ipv4_legacy("010.0.0.1"),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            parse_ipv4_legacy("001.002.003.004"),
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(parse_ipv4_legacy("0.0.0.0"), Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            parse_ipv4_legacy("255.255.255.255"),
            Some(Ipv4Addr::BROADCAST)
        );
        assert_eq!(parse_ipv4_legacy("256.1.1.1"), None);
        assert_eq!(parse_ipv4_legacy("1.2.3"), None);
        assert_eq!(parse_ipv4_legacy("1.2.3.4.5"), None);
        assert_eq!(parse_ipv4_legacy("0001.2.3.4"), None);
        assert_eq!(parse_ipv4_legacy("1..2.3"), None);
        assert_eq!(parse_ipv4_legacy("a.b.c.d"), None);
        assert_eq!(parse_ipv4_legacy(""), None);
        assert_eq!(parse_ipv4_legacy("1.2.3.4."), None);
    }

    #[test]
    fn addr_text_matches_inet_ntop() {
        use super::Address;
        use std::net::IpAddr;
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(Address::new(v4).to_string(), "192.0.2.10");
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(Address::new(v6).to_string(), "2001:db8::1");
        let loopback: IpAddr = "::1".parse().unwrap();
        assert_eq!(Address::new(loopback).to_string(), "::1");
    }
}
