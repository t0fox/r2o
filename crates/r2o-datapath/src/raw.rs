use r2k_core::{addr::Address, packet::PacketView};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Помеченный raw-сокет Linux для целых TCP/UDP-пакетов и UDP-фрагментов IPv4/IPv6.
#[derive(Debug)]
pub struct RawSocket {
    fd: OwnedFd,
    family: i32,
}

impl RawSocket {
    /// Открыть отправитель, чьи пакеты не попадут обратно в очередь без метки.
    pub fn open(family: i32, mark: u32) -> io::Result<Self> {
        if !matches!(family, libc::AF_INET | libc::AF_INET6) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "raw-отправка поддерживает только IPv4 или IPv6",
            ));
        }
        if mark == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "для raw-отправки нужна ненулевая --mark",
            ));
        }

        let fd = unsafe {
            libc::socket(
                family,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let one: libc::c_int = 1;
        let (level, option) = if family == libc::AF_INET {
            (libc::IPPROTO_IP, libc::IP_HDRINCL)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_HDRINCL)
        };
        set_option(fd.as_raw_fd(), level, option, &one)?;
        set_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, &mark)?;
        Ok(Self { fd, family })
    }

    /// Отправить пакет, не ожидая освобождения очереди raw-сокета.
    pub fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        let Some(outbound) = outgoing_packet(packet, self.family) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "raw отправитель принимает целые TCP/UDP-пакеты и корректные UDP-фрагменты",
            ));
        };
        if outbound.family == 4 && outbound.ipv4_id == Some(0) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Linux IP_HDRINCL переписывает нулевой IPv4 ID",
            ));
        }

        let mut destination: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let destination_len = if outbound.family == 4 {
            let address = unsafe { &mut *(&mut destination as *mut _ as *mut libc::sockaddr_in) };
            address.sin_family = libc::AF_INET as libc::sa_family_t;
            address.sin_addr.s_addr = u32::from_ne_bytes(
                outbound.address.bytes()[..4]
                    .try_into()
                    .expect("ширина адреса IPv4"),
            );
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        } else {
            let address = unsafe { &mut *(&mut destination as *mut _ as *mut libc::sockaddr_in6) };
            address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            address.sin6_addr.s6_addr = outbound.address.bytes();
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        };

        loop {
            let sent = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    packet.as_ptr().cast(),
                    packet.len(),
                    libc::MSG_DONTWAIT,
                    &destination as *const libc::sockaddr_storage as *const libc::sockaddr,
                    destination_len,
                )
            };
            if sent >= 0 {
                if sent as usize == packet.len() {
                    return Ok(());
                }
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "raw socket отправил неполный IP-пакет",
                ));
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct OutboundDestination {
    family: u8,
    address: Address,
    ipv4_id: Option<u16>,
}

fn outgoing_packet(packet: &[u8], socket_family: i32) -> Option<OutboundDestination> {
    let family = match socket_family {
        libc::AF_INET => 4,
        libc::AF_INET6 => 6,
        _ => return None,
    };
    if family == 4 && packet.len() >= 20 && packet[0] >> 4 == 4 {
        let flags_offset = u16::from_be_bytes(packet.get(6..8)?.try_into().ok()?);
        if flags_offset & 0x3fff != 0 {
            return ipv4_udp_fragment(packet, family);
        }
    }
    if family == 6 && packet.get(6) == Some(&44) {
        return ipv6_udp_fragment(packet, family);
    }

    let view = PacketView::parse(packet)?;
    if view.total_len != packet.len() || view.family != family {
        return None;
    }
    match view.protocol {
        6 if view.tcp_segment(packet).is_some() => {}
        17 if view.udp_payload_range(packet).is_some() => {}
        _ => return None,
    }
    Some(OutboundDestination {
        family,
        address: view.dst,
        ipv4_id: (family == 4).then_some(view.ip_id),
    })
}

fn ipv4_udp_fragment(packet: &[u8], family: u8) -> Option<OutboundDestination> {
    if family != 4
        || packet.len() < 28
        || packet[0] != 0x45
        || packet[9] != 17
        || usize::from(u16::from_be_bytes(packet.get(2..4)?.try_into().ok()?)) != packet.len()
    {
        return None;
    }
    let ip_id = u16::from_be_bytes(packet.get(4..6)?.try_into().ok()?);
    let flags_offset = u16::from_be_bytes(packet.get(6..8)?.try_into().ok()?);
    let address: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
    let data_len = packet.len() - 20;
    let offset = usize::from(flags_offset & 0x1fff) * 8;
    let more = flags_offset & 0x2000 != 0;
    if ip_id == 0
        || flags_offset & 0xc000 != 0
        || flags_offset & 0x3fff == 0
        || data_len == 0
        || (more && data_len % 8 != 0)
        || offset.checked_add(data_len)? > 65_515
    {
        return None;
    }
    Some(OutboundDestination {
        family,
        address: Address::new(IpAddr::V4(Ipv4Addr::from(address))),
        ipv4_id: Some(ip_id),
    })
}

fn ipv6_udp_fragment(packet: &[u8], family: u8) -> Option<OutboundDestination> {
    if family != 6
        || packet.len() < 56
        || packet[0] >> 4 != 6
        || usize::from(u16::from_be_bytes(packet.get(4..6)?.try_into().ok()?)) + 40 != packet.len()
        || packet[40] != 17
        || packet[41] != 0
    {
        return None;
    }
    let field = u16::from_be_bytes(packet.get(42..44)?.try_into().ok()?);
    let offset = usize::from(field & 0xfff8);
    let more = field & 1 != 0;
    let data_len = packet.len() - 48;
    let identification = u32::from_be_bytes(packet.get(44..48)?.try_into().ok()?);
    let address: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
    if field & 0x0006 != 0
        || identification == 0
        || data_len == 0
        || (more && data_len % 8 != 0)
        || offset.checked_add(data_len)? > 65_535
    {
        return None;
    }
    Some(OutboundDestination {
        family,
        address: Address::new(IpAddr::V6(Ipv6Addr::from(address))),
        ipv4_id: None,
    })
}

fn set_option<T>(fd: i32, level: i32, option: i32, value: &T) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (value as *const T).cast(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::outgoing_packet;
    use proptest::prelude::*;
    use r2k_core::plan::{Emission, EmitKind};

    fn original_v4() -> Vec<u8> {
        let mut packet = vec![0; 36];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&36u16.to_be_bytes());
        packet[4..6].copy_from_slice(&9u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&51234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..26].copy_from_slice(&16u16.to_be_bytes());
        packet[28..].copy_from_slice(b"abcdefgh");
        packet
    }

    fn original_v6() -> Vec<u8> {
        let mut packet = vec![0; 56];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40..42].copy_from_slice(&51234u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443u16.to_be_bytes());
        packet[44..46].copy_from_slice(&16u16.to_be_bytes());
        packet[48..].copy_from_slice(b"abcdefgh");
        packet
    }

    fn fragments(original: &[u8]) -> Vec<Vec<u8>> {
        r2k_core::wire::build_udp_fragments(
            original,
            &Emission {
                kind: EmitKind::Payload,
                delay_us: 0,
                seq: 0,
                ttl: 0,
                poison: 0,
                seq_shift: 0,
                wire_profile: 0,
                ipfrag: 1,
                urgent: false,
                urgent_ptr: 0,
                prefix: Vec::new(),
                bytes: b"abcdefgh".to_vec(),
            },
        )
        .unwrap()
    }

    #[test]
    fn raw_sender_accepts_only_well_formed_ipv4_and_ipv6_udp_fragments() {
        let ipv4 = fragments(&original_v4());
        assert_eq!(outgoing_packet(&ipv4[0], libc::AF_INET).unwrap().family, 4);
        assert_eq!(outgoing_packet(&ipv4[1], libc::AF_INET).unwrap().family, 4);
        assert!(outgoing_packet(&ipv4[0], libc::AF_INET6).is_none());

        let mut invalid_v4 = ipv4[0].clone();
        invalid_v4[4..6].fill(0);
        assert!(outgoing_packet(&invalid_v4, libc::AF_INET).is_none());

        let ipv6 = fragments(&original_v6());
        assert_eq!(outgoing_packet(&ipv6[0], libc::AF_INET6).unwrap().family, 6);
        assert_eq!(outgoing_packet(&ipv6[1], libc::AF_INET6).unwrap().family, 6);
        assert!(outgoing_packet(&ipv6[0], libc::AF_INET).is_none());

        let mut invalid_v6 = ipv6[0].clone();
        invalid_v6[43] |= 2;
        assert!(outgoing_packet(&invalid_v6, libc::AF_INET6).is_none());
    }

    #[test]
    fn r2o_ip_разбор_совпадает_с_etherparse_на_ipv4_и_ipv6() {
        for (packet, family) in [
            (original_v4(), libc::AF_INET),
            (original_v6(), libc::AF_INET6),
        ] {
            let independent = etherparse::SlicedPacket::from_ip(&packet).unwrap();
            assert!(independent.transport.is_some());
            assert_eq!(
                outgoing_packet(&packet, family).unwrap().family,
                if family == libc::AF_INET { 4 } else { 6 }
            );
        }
    }

    proptest! {
        #[test]
        fn r2o_raw_разбор_не_паникует_на_произвольных_пакетах(
            packet in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let _ = outgoing_packet(&packet, libc::AF_INET);
            let _ = outgoing_packet(&packet, libc::AF_INET6);
        }
    }
}
