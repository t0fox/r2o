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
