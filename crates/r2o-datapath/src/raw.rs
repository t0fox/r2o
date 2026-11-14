use r2k_core::{addr::Address, packet::PacketView};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const R2O_ROUTE_MTU_CACHE_CAPACITY: usize = 16;
const R2O_RAW_MTU_FLOOR: usize = 576;
/// C `D2K_RAW_CANT_IPID | D2K_RAW_CANT_IPSUM` (`d2k_raw.h`).
pub const R2O_RAW_CANT_IPID: u32 = 1;
pub const R2O_RAW_CANT_IPSUM: u32 = 2;
pub const R2O_RAW_LIMITS: u32 = R2O_RAW_CANT_IPID | R2O_RAW_CANT_IPSUM;

fn r2o_raw_mark_option(mark: u32) -> Option<u32> {
    (mark != 0).then_some(mark)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawSendStats {
    pub sent: u64,
    pub errors: u64,
    pub busy: u64,
}

fn record_send_outcome(stats: &mut RawSendStats, packet: &[u8], result: &io::Result<()>) {
    match result {
        Ok(()) => stats.sent = stats.sent.saturating_add(1),
        Err(error) if packet.len() >= 20 && matches!(packet[0] >> 4, 4 | 6) => {
            stats.errors = stats.errors.saturating_add(1);
            if error.raw_os_error().is_some_and(|code| {
                code == libc::EAGAIN || code == libc::EWOULDBLOCK || code == libc::ENOBUFS
            }) {
                stats.busy = stats.busy.saturating_add(1);
            }
        }
        Err(_) => {}
    }
}

/// Помеченный raw-сокет Linux для целых TCP/UDP-пакетов и UDP-фрагментов IPv4/IPv6.
#[derive(Debug)]
pub struct RawSocket {
    fd: OwnedFd,
    family: i32,
    mark: u32,
    send_stats: Cell<RawSendStats>,
    maxlen: Cell<usize>,
    maxlen_declared: bool,
    egress_mtu: Cell<Option<usize>>,
    route_mtu_cache: RefCell<R2oRouteMtuCache>,
    /// C `d2k_raw.fragment_fd`: отдельный IPv4-сокет с `IP_NODEFRAG`.
    ///
    /// Обычный сокет не годится: ядро соберёт измеренные фрагменты обратно
    /// перед отправкой и порядок/перекрытие, ради которых они и собраны,
    /// исчезнут. C открывает его лениво при первом фрагменте и никогда не
    /// откатывается на обычный сокет.
    fragment_fd: RefCell<Option<OwnedFd>>,
}

/// C `d2k_send_nosig`: Linux глушит SIGPIPE флагом MSG_NOSIGNAL.
fn r2o_raw_send_flags() -> libc::c_int {
    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL
}

impl RawSocket {
    /// Открыть отправитель, чьи пакеты не попадут обратно в очередь без метки.
    pub fn open(family: i32, mark: u32, interface: Option<&str>) -> io::Result<Self> {
        if !matches!(family, libc::AF_INET | libc::AF_INET6) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                crate::error_text::error_text(96, "raw-отправка поддерживает только IPv4 или IPv6"),
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
        if let Some(mark) = r2o_raw_mark_option(mark) {
            set_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, &mark)?;
        }
        let maxlen_declared = interface.is_some_and(|name| !name.is_empty());
        let maxlen = r2o_pick_maxlen(interface);
        Ok(Self {
            fd,
            family,
            mark,
            send_stats: Cell::new(RawSendStats::default()),
            maxlen: Cell::new(maxlen),
            maxlen_declared,
            egress_mtu: Cell::new(None),
            route_mtu_cache: RefCell::new(R2oRouteMtuCache::default()),
            fragment_fd: RefCell::new(None),
        })
    }

    /// Возвращает общий предел длины одной посылки.
    pub fn maxlen(&self) -> usize {
        self.maxlen.get()
    }

    pub fn send_stats(&self) -> RawSendStats {
        self.send_stats.get()
    }

    /// C `d2k_raw_limits`: маска того, чего этот способ отправки не умеет.
    pub fn limits(&self) -> u32 {
        R2O_RAW_LIMITS
    }

    /// Подстраивает общий предел под MTU интерфейсов текущих выходных маршрутов.
    /// `Some` возвращается только при изменении предела.
    pub fn r2o_adopt_egress(&self, ifindices: &[u32]) -> Option<usize> {
        if self.maxlen_declared {
            return None;
        }
        let mtu = r2o_select_egress_mtu(ifindices, r2o_interface_mtu_by_index)?;
        if self.egress_mtu.replace(Some(mtu)) == Some(mtu) || mtu == self.maxlen.get() {
            return None;
        }
        self.maxlen.set(mtu);
        Some(mtu)
    }

    /// Возвращает предел посылки для семейства и адреса назначения.
    pub fn packet_route_maxlen(&self, packet: &[u8]) -> usize {
        let Some((family, destination)) = r2o_packet_route_key(packet) else {
            return self.maxlen.get();
        };
        if packet.len() < if family == 6 { 40 } else { 20 } {
            return self.maxlen.get();
        }
        self.r2o_route_maxlen(family, destination)
    }

    /// Ограничить TCP-посылку MTU маршрута для TLS-запроса.
    pub fn tls_route_segment_cap(&self, packet: &[u8]) -> usize {
        r2o_tls_route_segment_cap_with(packet, |family, destination| {
            self.r2o_route_maxlen(family, destination)
        })
    }

    fn r2o_route_maxlen(&self, family: u8, destination: [u8; 16]) -> usize {
        let route =
            self.route_mtu_cache
                .borrow_mut()
                .r2o_get_or_lookup(family, destination, || {
                    r2o_route_mtu(self.mark, family, destination)
                });
        r2o_effective_route_maxlen(route, self.maxlen.get(), self.maxlen_declared)
    }

    /// Отправить пакет, не ожидая освобождения очереди raw-сокета.
    pub fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        let result = self.send_packet_inner(packet);
        let mut stats = self.send_stats.get();
        record_send_outcome(&mut stats, packet, &result);
        self.send_stats.set(stats);
        result
    }

    fn send_packet_inner(&self, packet: &[u8]) -> io::Result<()> {
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
        // C `d2k_raw_prepare`: фрагменты IPv4 уходят отдельным сокетом с
        // IP_NODEFRAG. Откат на обычный сокет запрещён — иначе ядро соберёт
        // измеренные фрагменты и отправит не то, что просил план.
        let send_fd = if outbound.fragment && outbound.family == 4 {
            r2o_cached_fragment_fd(&self.fragment_fd, || {
                r2o_open_ipv4_fragment_socket(self.mark)
            })?
        } else {
            self.fd.as_raw_fd()
        };

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
                    send_fd,
                    packet.as_ptr().cast(),
                    packet.len(),
                    r2o_raw_send_flags(),
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
                if error.raw_os_error() == Some(libc::EMSGSIZE)
                    && let Some((family, destination)) = r2o_packet_route_key(packet)
                    && packet.len() > if family == 6 { 1280 } else { 576 }
                {
                    let lowered = packet.len() - 1;
                    self.route_mtu_cache
                        .borrow_mut()
                        .r2o_lower(family, destination, lowered);
                    if lowered < self.maxlen.get() {
                        self.maxlen.set(lowered);
                    }
                }
                return Err(error);
            }
        }
    }
}

#[cfg(test)]
mod send_stats_tests {
    use super::{RawSendStats, record_send_outcome};
    use std::io;

    #[test]
    fn raw_send_stats_count_success_and_busy_errors_like_d2o() {
        let packet = [0x45; 20];
        let mut stats = RawSendStats::default();
        record_send_outcome(&mut stats, &packet, &Ok(()));
        record_send_outcome(
            &mut stats,
            &packet,
            &Err(io::Error::from_raw_os_error(libc::ENOBUFS)),
        );

        assert_eq!(
            stats,
            RawSendStats {
                sent: 1,
                errors: 1,
                busy: 1
            }
        );
    }

    #[test]
    fn raw_send_stats_ignore_input_rejections_before_d2o_send_accounting() {
        let mut stats = RawSendStats::default();
        record_send_outcome(
            &mut stats,
            &[0; 19],
            &Err(io::Error::from_raw_os_error(libc::EINVAL)),
        );
        record_send_outcome(
            &mut stats,
            &[0x75; 20],
            &Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT)),
        );

        assert_eq!(stats, RawSendStats::default());
    }
}

pub fn r2o_pick_maxlen(interface: Option<&str>) -> usize {
    if let Some(interface) = interface.filter(|name| !name.is_empty()) {
        return r2o_interface_mtu(interface).unwrap_or(1500);
    }
    let Ok(interfaces) = std::fs::read_dir("/sys/class/net") else {
        return 1500;
    };
    let mut smallest = None;
    for interface in interfaces.flatten() {
        let path = interface.path();
        let flags = std::fs::read_to_string(path.join("flags"))
            .ok()
            .and_then(|value| r2o_parse_interface_flags(&value));
        let Some(flags) = flags else {
            continue;
        };
        if flags & libc::IFF_UP as u32 == 0 || flags & libc::IFF_LOOPBACK as u32 != 0 {
            continue;
        }
        let Some(mtu) = std::fs::read_to_string(path.join("mtu"))
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|mtu| *mtu != 0)
        else {
            continue;
        };
        smallest = Some(smallest.map_or(mtu, |current: usize| current.min(mtu)));
    }
    smallest.unwrap_or(1500)
}

fn r2o_interface_mtu(interface: &str) -> Option<usize> {
    if interface.contains('/') || interface.contains('\\') || interface == "." || interface == ".."
    {
        return None;
    }
    let path = std::path::Path::new("/sys/class/net").join(interface);
    std::fs::read_to_string(path.join("mtu"))
        .ok()?
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|mtu| *mtu != 0)
}

fn r2o_interface_mtu_by_index(ifindex: u32) -> Option<usize> {
    use std::ffi::CStr;

    if ifindex == 0 {
        return None;
    }
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    if unsafe { libc::if_indextoname(ifindex, name.as_mut_ptr()) }.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(name.as_ptr()) }.to_str().ok()?;
    r2o_interface_mtu(name)
}

fn r2o_select_egress_mtu(
    ifindices: &[u32],
    mut interface_mtu: impl FnMut(u32) -> Option<usize>,
) -> Option<usize> {
    let mut smallest = None;
    for &ifindex in ifindices {
        if ifindex == 0 {
            continue;
        }
        let Some(mtu) = interface_mtu(ifindex).filter(|mtu| *mtu >= R2O_RAW_MTU_FLOOR) else {
            continue;
        };
        smallest = Some(smallest.map_or(mtu, |current: usize| current.min(mtu)));
    }
    smallest
}

fn r2o_parse_interface_flags(value: &str) -> Option<u32> {
    let value = value.trim();
    u32::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).ok()
}

fn r2o_effective_route_maxlen(route: usize, maxlen: usize, declared: bool) -> usize {
    match (route, declared) {
        (0, _) => maxlen,
        (route, true) => route.min(maxlen),
        (route, false) => route,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct R2oRouteMtuEntry {
    family: u8,
    destination: [u8; 16],
    mtu: usize,
}

#[derive(Debug, Default)]
struct R2oRouteMtuCache {
    entries: VecDeque<R2oRouteMtuEntry>,
}

impl R2oRouteMtuCache {
    fn r2o_get_or_lookup(
        &mut self,
        family: u8,
        destination: [u8; 16],
        lookup: impl FnOnce() -> usize,
    ) -> usize {
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.family == family && entry.destination == destination)
        {
            return entry.mtu;
        }
        let mtu = lookup();
        if mtu < if family == 6 { 1280 } else { 576 } {
            return 0;
        }
        if self.entries.len() == R2O_ROUTE_MTU_CACHE_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(R2oRouteMtuEntry {
            family,
            destination,
            mtu,
        });
        mtu
    }

    fn r2o_lower(&mut self, family: u8, destination: [u8; 16], lowered: usize) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.family == family && entry.destination == destination)
            && lowered < entry.mtu
        {
            entry.mtu = lowered;
        }
    }
}

fn r2o_packet_route_key(packet: &[u8]) -> Option<(u8, [u8; 16])> {
    let mut destination = [0; 16];
    match packet.first()? >> 4 {
        4 => destination[..4].copy_from_slice(packet.get(16..20)?),
        6 => destination.copy_from_slice(packet.get(24..40)?),
        _ => return None,
    }
    Some((packet[0] >> 4, destination))
}

fn r2o_tls_route_segment_cap_with(
    packet: &[u8],
    mut route_mtu: impl FnMut(u8, [u8; 16]) -> usize,
) -> usize {
    let Some(probe) = r2o_tls_route_probe(packet) else {
        return 0;
    };
    let mtu = route_mtu(probe.family, probe.destination);
    let overhead = probe.ip_header_len + 32;
    mtu.checked_sub(overhead).unwrap_or(0)
}

#[derive(Clone, Copy)]
struct R2oTlsRouteProbe {
    family: u8,
    destination: [u8; 16],
    ip_header_len: usize,
}

fn r2o_tls_route_probe(packet: &[u8]) -> Option<R2oTlsRouteProbe> {
    if packet.len() < 40 {
        return None;
    }
    let family = packet[0] >> 4;
    let (ip_header_len, tcp_offset, destination) = match family {
        4 => {
            let ip_header_len = usize::from(packet[0] & 0x0f) * 4;
            if ip_header_len < 20
                || packet.len() < ip_header_len + 20
                || packet[9] != libc::IPPROTO_TCP as u8
            {
                return None;
            }
            let mut destination = [0; 16];
            destination[..4].copy_from_slice(packet.get(16..20)?);
            (ip_header_len, ip_header_len, destination)
        }
        6 => {
            if packet.len() < 60 || packet[6] != libc::IPPROTO_TCP as u8 {
                return None;
            }
            let mut destination = [0; 16];
            destination.copy_from_slice(packet.get(24..40)?);
            (40, 40, destination)
        }
        _ => return None,
    };
    let tcp_header_len = usize::from(packet[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < 20
        || packet.len() < tcp_offset + tcp_header_len + 5
        || packet[tcp_offset + tcp_header_len] != 0x16
        || packet[tcp_offset + tcp_header_len + 1] != 3
    {
        return None;
    }
    Some(R2oTlsRouteProbe {
        family,
        destination,
        ip_header_len,
    })
}

fn r2o_route_mtu(mark: u32, family: u8, destination: [u8; 16]) -> usize {
    // C `route_mtu` (`datapath/raw.c:140-176`): IPv6 только при family==6,
    // любой другой family — IPv4; socket SOCK_DGRAM с protocol 0.
    let ipv6 = family == 6;
    let socket_family = if ipv6 { libc::AF_INET6 } else { libc::AF_INET };
    let raw_fd = unsafe { libc::socket(socket_family, libc::SOCK_DGRAM, 0) };
    if raw_fd < 0 {
        return 0;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    if let Some(mark) = r2o_raw_mark_option(mark) {
        let _ = set_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, &mark);
    }
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let (address_len, level, option) = if !ipv6 {
        let address = unsafe { &mut *(&mut address as *mut _ as *mut libc::sockaddr_in) };
        address.sin_family = libc::AF_INET as libc::sa_family_t;
        address.sin_port = 443_u16.to_be();
        address.sin_addr.s_addr = u32::from_ne_bytes(destination[..4].try_into().unwrap());
        (
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            libc::IPPROTO_IP,
            libc::IP_MTU,
        )
    } else {
        let address = unsafe { &mut *(&mut address as *mut _ as *mut libc::sockaddr_in6) };
        address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        address.sin6_port = 443_u16.to_be();
        address.sin6_addr.s6_addr = destination;
        (
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU,
        )
    };
    let connected = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &address as *const libc::sockaddr_storage as *const libc::sockaddr,
            address_len,
        )
    };
    if connected != 0 {
        return 0;
    }
    let mut mtu: libc::c_int = 0;
    let mut mtu_len = std::mem::size_of_val(&mtu) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            option,
            &mut mtu as *mut libc::c_int as *mut libc::c_void,
            &mut mtu_len,
        )
    };
    if result == 0 && mtu > 0 {
        mtu as usize
    } else {
        0
    }
}

#[derive(Clone, Copy)]
struct OutboundDestination {
    family: u8,
    address: Address,
    ipv4_id: Option<u16>,
    /// Пакет несёт заголовок фрагментации (MF или ненулевой offset).
    fragment: bool,
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
        fragment: false,
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
        fragment: true,
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
        fragment: true,
    })
}

/// C `d2k_raw_prepare` (ветка IPv4-фрагмента): отдельный raw-сокет,
/// `IP_HDRINCL`, `IP_NODEFRAG`, метка. Без `IP_NODEFRAG` ядро имеет право
/// собрать фрагменты обратно — тогда на провод уйдёт не измеренная форма.
fn r2o_open_ipv4_fragment_socket(mark: u32) -> io::Result<OwnedFd> {
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_RAW,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let one: libc::c_int = 1;
    set_option(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_HDRINCL, &one)?;
    // C: при сборке без IP_NODEFRAG prepare завершается ENOPROTOOPT, а не
    // отправляет фрагменты обычным путём.
    set_option(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_NODEFRAG, &one)?;
    if let Some(mark) = r2o_raw_mark_option(mark) {
        set_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, &mark)?;
    }
    Ok(fd)
}

/// Ленивый кеш дескриптора фрагментов, как `r->fragment_fd` в C.
///
/// Ошибка открытия не кешируется: C оставляет `fragment_fd == -1` и повторяет
/// попытку на следующем фрагменте.
fn r2o_cached_fragment_fd(
    cache: &RefCell<Option<OwnedFd>>,
    open: impl FnOnce() -> io::Result<OwnedFd>,
) -> io::Result<libc::c_int> {
    if let Some(fd) = cache.borrow().as_ref() {
        return Ok(fd.as_raw_fd());
    }
    let fd = open()?;
    let raw_fd = fd.as_raw_fd();
    *cache.borrow_mut() = Some(fd);
    Ok(raw_fd)
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
    use super::{
        R2O_RAW_CANT_IPID, R2O_RAW_CANT_IPSUM, R2O_RAW_LIMITS, R2O_ROUTE_MTU_CACHE_CAPACITY,
        R2oRouteMtuCache, outgoing_packet, r2o_effective_route_maxlen, r2o_interface_mtu,
        r2o_packet_route_key, r2o_parse_interface_flags, r2o_pick_maxlen, r2o_raw_mark_option,
        r2o_route_mtu, r2o_select_egress_mtu, r2o_tls_route_segment_cap_with,
    };
    use proptest::prelude::*;
    use r2k_core::plan::{Emission, EmitKind};

    fn original_v4() -> Vec<u8> {
        let mut packet = vec![0; 36];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&36u16.to_be_bytes());
        packet[4..6].copy_from_slice(&9u16.to_be_bytes());
        packet[4..6].copy_from_slice(&9_u16.to_be_bytes());
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

    fn tls_route_packet_v4() -> Vec<u8> {
        let mut packet = vec![0; 45];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&45_u16.to_be_bytes());
        packet[9] = libc::IPPROTO_TCP as u8;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[32] = 5 << 4;
        packet[40..45].copy_from_slice(&[0x16, 3, 3, 0, 0]);
        packet
    }

    fn tls_route_packet_v6() -> Vec<u8> {
        let mut packet = vec![0; 65];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&25_u16.to_be_bytes());
        packet[6] = libc::IPPROTO_TCP as u8;
        packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[52] = 5 << 4;
        packet[60..65].copy_from_slice(&[0x16, 3, 3, 0, 0]);
        packet
    }

    #[test]
    fn raw_open_differential_matches_c() {
        let scenario = std::env::var("FAKE_OPEN_SCENARIO").unwrap_or_else(|_| "ok".into());
        let mark = u32::from(scenario.contains("mark"));
        let result = super::RawSocket::open(libc::AF_INET, mark, None);
        let rc = if result.is_ok() { 0 } else { -1 };
        drop(result);
        let output = format!("{scenario} rc={rc}\n");
        if let Ok(path) = std::env::var("R2O_RAW_OPEN_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains(&format!("{scenario} rc=")));
    }

    #[test]
    fn raw_prepare_differential_matches_c() {
        fn wr16(packet: &mut [u8], offset: usize, value: u16) {
            packet[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }
        let mut udp = vec![0_u8; 36];
        udp[0] = 0x45;
        let udp_len = udp.len() as u16;
        wr16(&mut udp, 2, udp_len);
        wr16(&mut udp, 4, 9);
        udp[8] = 64;
        udp[9] = 17;
        udp[12..16].copy_from_slice(&[192, 0, 2, 1]);
        udp[16..20].copy_from_slice(&[198, 51, 100, 2]);
        wr16(&mut udp, 20, 51234);
        wr16(&mut udp, 22, 443);
        wr16(&mut udp, 24, 16);

        let mut bad_version = udp.clone();
        bad_version[0] = 0x75;
        let mut bad_proto = udp.clone();
        wr16(&mut bad_proto, 6, 0x2000);
        bad_proto[9] = 6;
        let mut zero_id = udp.clone();
        wr16(&mut zero_id, 6, 0x2000);
        wr16(&mut zero_id, 4, 0);
        let mut ipv6_bad = vec![0_u8; 56];
        ipv6_bad[0] = 0x60;
        wr16(&mut ipv6_bad, 4, 8);
        ipv6_bad[6] = 17;

        let mut output = String::new();
        for (name, packet) in [
            ("ipv4_plain", udp),
            ("ipv4_bad_version", bad_version),
            ("fragment_bad_proto", bad_proto),
            ("fragment_zero_id", zero_id),
            ("ipv6_bad_len", ipv6_bad),
        ] {
            let family = if packet[0] >> 4 == 6 {
                libc::AF_INET6
            } else {
                libc::AF_INET
            };
            let rc = if super::outgoing_packet(&packet, family).is_some() {
                0
            } else {
                -1
            };
            output.push_str(&format!("{name} rc={rc}\n"));
        }
        if let Ok(path) = std::env::var("R2O_RAW_PREPARE_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains("ipv4_plain rc=0\n"));
        assert!(output.contains("fragment_zero_id rc=-1\n"));
    }

    #[test]
    fn raw_send_differential_matches_c() {
        use std::cell::{Cell, RefCell};
        use std::os::fd::{FromRawFd, OwnedFd};

        let scenario = std::env::var("FAKE_SENDTO_SCENARIO").unwrap_or_else(|_| "ok".into());
        let large = scenario == "emsgsize";
        let mut packet = vec![0_u8; if large { 1200 } else { 36 }];
        packet[0] = 0x45;
        let packet_len = packet.len();
        packet[2..4].copy_from_slice(&(packet_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&9_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&51234_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&((packet_len - 20) as u16).to_be_bytes());

        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(fd >= 0);
        let mut destination = [0_u8; 16];
        destination[..4].copy_from_slice(&packet[16..20]);
        let mut cache = super::R2oRouteMtuCache::default();
        cache.r2o_get_or_lookup(4, destination, || 1500);
        let socket = super::RawSocket {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            family: libc::AF_INET,
            mark: 0,
            send_stats: Cell::new(super::RawSendStats::default()),
            maxlen: Cell::new(1500),
            maxlen_declared: true,
            egress_mtu: Cell::new(None),
            route_mtu_cache: RefCell::new(cache),
            fragment_fd: RefCell::new(None),
        };
        let result = if scenario == "invalid" {
            socket.send_packet(&packet[..19])
        } else {
            socket.send_packet(&packet)
        };
        let stats = socket.send_stats.get();
        let route = socket.route_mtu_cache.borrow().entries[0].mtu;
        let output = format!(
            "{scenario} rc={} sent={} errors={} busy={} maxlen={} route={}\n",
            if result.is_ok() { 0 } else { -1 },
            stats.sent,
            stats.errors,
            stats.busy,
            socket.maxlen.get(),
            route
        );
        if let Ok(path) = std::env::var("R2O_RAW_SEND_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains(&format!("{scenario} rc=")));
    }

    #[test]
    fn route_mtu_differential_matches_c() {
        let mut v4 = [0_u8; 16];
        v4[..4].copy_from_slice(&[127, 0, 0, 1]);
        let mut v6 = [0_u8; 16];
        v6[15] = 1;
        let out = format!(
            "v4 {}\nv6 {}\nbad {}\n",
            r2o_route_mtu(0, 4, v4),
            r2o_route_mtu(0, 6, v6),
            // C: любая family, кроме 6, идёт по IPv4-ветке.
            r2o_route_mtu(0, 5, v4)
        );
        if let Ok(path) = std::env::var("R2O_ROUTE_MTU_DIFF_OUTPUT") {
            std::fs::write(path, &out).unwrap();
        }
        assert!(r2o_route_mtu(0, 4, v4) > 0);
        assert!(r2o_route_mtu(0, 6, v6) > 0);
        assert_eq!(r2o_route_mtu(0, 5, v4), r2o_route_mtu(0, 4, v4));
    }

    #[test]
    fn предел_tls_tcp_учитывает_семейство_и_заголовки_маршрута() {
        let ipv4 = tls_route_packet_v4();
        let mut queried = None;
        assert_eq!(
            r2o_tls_route_segment_cap_with(&ipv4, |family, destination| {
                queried = Some((family, destination));
                1500
            }),
            1448
        );
        assert_eq!(
            queried,
            Some((4, [198, 51, 100, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
        );

        let ipv6 = tls_route_packet_v6();
        let mut queried = None;
        assert_eq!(
            r2o_tls_route_segment_cap_with(&ipv6, |family, destination| {
                queried = Some((family, destination));
                1500
            }),
            1428
        );
        assert_eq!(queried.unwrap().0, 6);
        assert_eq!(&queried.unwrap().1[..4], &[0x20, 1, 0x0d, 0xb8]);
    }

    #[test]
    fn поиск_маршрута_пропускает_неподдержанные_пакеты() {
        let mut packet = tls_route_packet_v4();
        packet[9] = libc::IPPROTO_UDP as u8;
        let mut called = false;
        assert_eq!(
            r2o_tls_route_segment_cap_with(&packet, |_, _| {
                called = true;
                1500
            }),
            0
        );
        assert!(!called);

        let mut packet = tls_route_packet_v6();
        packet[6] = 0; // расширение IPv6: быстрый путь его не угадывает
        assert_eq!(
            r2o_tls_route_segment_cap_with(&packet, |_, _| panic!("маршрут не запрашивается")),
            0
        );
    }

    #[test]
    fn кэш_mtu_сохраняет_только_полезные_маршруты_и_ограничен() {
        let mut cache = R2oRouteMtuCache::default();
        let destination = [198, 51, 100, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut calls = 0;
        assert_eq!(cache.r2o_get_or_lookup(4, destination, || 0), 0);
        assert_eq!(
            cache.r2o_get_or_lookup(4, destination, || {
                calls += 1;
                1500
            }),
            1500
        );
        assert_eq!(
            cache.r2o_get_or_lookup(4, destination, || panic!("кэш промахнулся")),
            1500
        );
        assert_eq!(calls, 1);
        cache.r2o_lower(4, destination, 1300);
        cache.r2o_lower(4, destination, 1400);
        assert_eq!(
            cache.r2o_get_or_lookup(4, destination, || panic!("кэш промахнулся")),
            1300
        );

        for index in 0..R2O_ROUTE_MTU_CACHE_CAPACITY {
            let mut next = destination;
            next[0] = index as u8;
            next[1] = (index >> 8) as u8;
            cache.r2o_get_or_lookup(4, next, || 1400);
        }
        assert_eq!(cache.entries.len(), R2O_ROUTE_MTU_CACHE_CAPACITY);
    }

    #[test]
    fn предел_маршрута_учитывает_объявленный_интерфейс_и_запасной_mtu() {
        assert_eq!(r2o_effective_route_maxlen(0, 1500, false), 1500);
        assert_eq!(r2o_effective_route_maxlen(0, 1200, true), 1200);
        assert_eq!(r2o_effective_route_maxlen(1400, 1200, true), 1200);
        assert_eq!(r2o_effective_route_maxlen(9000, 1200, false), 9000);
    }

    #[test]
    fn читает_шестнадцатеричные_флаги_интерфейса_из_sysfs() {
        assert_eq!(r2o_parse_interface_flags("0x1003\n"), Some(0x1003));
        assert_eq!(r2o_parse_interface_flags("1003"), Some(0x1003));
        assert_eq!(r2o_parse_interface_flags("unknown"), None);
    }

    #[test]
    fn общий_предел_берёт_наименьший_доступный_mtu_выходных_интерфейсов() {
        let mut queried = Vec::new();
        let mtu = r2o_select_egress_mtu(&[7, 0, 9, 7, 11], |ifindex| {
            queried.push(ifindex);
            match ifindex {
                7 => Some(1500),
                9 => Some(1280),
                11 => Some(575),
                _ => None,
            }
        });
        assert_eq!(mtu, Some(1280));
        assert_eq!(queried, [7, 9, 7, 11]);
        assert_eq!(r2o_select_egress_mtu(&[1, 2], |_| Some(575)), None);
        assert_eq!(r2o_select_egress_mtu(&[0], |_| Some(1500)), None);
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

    #[test]
    fn raw_mark_zero_is_allowed_and_limits_match_c_mask() {
        assert_eq!(r2o_raw_mark_option(0), None);
        assert_eq!(r2o_raw_mark_option(0x2e), Some(0x2e));
        assert_eq!(R2O_RAW_LIMITS, R2O_RAW_CANT_IPID | R2O_RAW_CANT_IPSUM);
        assert_eq!(R2O_RAW_LIMITS, 3);
    }

    #[test]
    fn packet_route_key_extracts_ipv4_and_ipv6_destination() {
        let mut v4 = vec![0; 20];
        v4[0] = 0x45;
        v4[16..20].copy_from_slice(&[198, 51, 100, 2]);
        let mut expected = [0; 16];
        expected[..4].copy_from_slice(&[198, 51, 100, 2]);
        assert_eq!(r2o_packet_route_key(&v4), Some((4, expected)));

        let mut v6 = vec![0; 40];
        v6[0] = 0x60;
        let address = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        v6[24..40].copy_from_slice(&address);
        assert_eq!(r2o_packet_route_key(&v6), Some((6, address)));

        assert_eq!(r2o_packet_route_key(&[0x30; 20]), None);
        assert_eq!(r2o_packet_route_key(&[0x45; 10]), None);
    }

    #[test]
    fn interface_mtu_reads_sysfs_and_named_limit_uses_it() {
        assert_eq!(r2o_interface_mtu("../lo"), None);
        assert_eq!(r2o_interface_mtu("."), None);
        if let Some(mtu) = r2o_interface_mtu("lo") {
            assert!(mtu > 0);
            assert_eq!(r2o_pick_maxlen(Some("lo")), mtu);
        }
    }

    #[test]
    fn raw_send_flags_include_nosignal() {
        assert_ne!(super::r2o_raw_send_flags() & libc::MSG_NOSIGNAL, 0);
        assert_ne!(super::r2o_raw_send_flags() & libc::MSG_DONTWAIT, 0);
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

    #[test]
    fn исходящий_разбор_помечает_фрагменты_для_отдельного_сокета() {
        let ipv4 = fragments(&original_v4());
        assert!(outgoing_packet(&ipv4[0], libc::AF_INET).unwrap().fragment);
        assert!(outgoing_packet(&ipv4[1], libc::AF_INET).unwrap().fragment);
        assert!(
            !outgoing_packet(&original_v4(), libc::AF_INET)
                .unwrap()
                .fragment
        );

        let ipv6 = fragments(&original_v6());
        assert!(outgoing_packet(&ipv6[0], libc::AF_INET6).unwrap().fragment);
        assert!(
            !outgoing_packet(&original_v6(), libc::AF_INET6)
                .unwrap()
                .fragment
        );
    }

    #[test]
    fn ленивый_сокет_фрагментов_открывается_один_раз_и_не_кеширует_ошибку() {
        use std::cell::RefCell;
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

        let cache = RefCell::new(None);
        let mut opens = 0;
        let open = |opens: &mut usize| -> std::io::Result<OwnedFd> {
            *opens += 1;
            let file = std::fs::File::open("/dev/null")?;
            Ok(unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) })
        };
        let first = super::r2o_cached_fragment_fd(&cache, || open(&mut opens)).unwrap();
        let second = super::r2o_cached_fragment_fd(&cache, || open(&mut opens)).unwrap();
        assert_eq!(first, second);
        assert_eq!(opens, 1);

        // Ошибка не запоминается: C оставляет fragment_fd == -1 и повторяет.
        let cache = RefCell::new(None);
        let mut opens = 0;
        let error = super::r2o_cached_fragment_fd(&cache, || {
            opens += 1;
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        let recovered = super::r2o_cached_fragment_fd(&cache, || open(&mut opens)).unwrap();
        assert!(recovered >= 0);
        assert_eq!(opens, 2);
    }

    #[test]
    #[ignore = "нужен Linux CAP_NET_RAW"]
    fn сокет_фрагментов_выключает_дефрагментацию_ядра() {
        use std::os::fd::AsRawFd;

        let fd = super::r2o_open_ipv4_fragment_socket(0).expect("открыть сокет фрагментов");
        let mut value: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_NODEFRAG,
                &mut value as *mut libc::c_int as *mut libc::c_void,
                &mut length,
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        assert_eq!(value, 1, "IP_NODEFRAG должен быть включён");
    }

    fn тестовый_raw_сокет(declared: bool) -> super::RawSocket {
        use std::cell::{Cell, RefCell};
        use std::os::fd::{FromRawFd, OwnedFd};

        let fd: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        super::RawSocket {
            fd,
            family: libc::AF_INET,
            mark: 0,
            send_stats: Cell::new(super::RawSendStats::default()),
            maxlen: Cell::new(super::r2o_pick_maxlen(None)),
            maxlen_declared: declared,
            egress_mtu: Cell::new(None),
            route_mtu_cache: RefCell::new(super::R2oRouteMtuCache::default()),
            fragment_fd: RefCell::new(None),
        }
    }

    #[test]
    fn raw_adopt_egress_differential_matches_c() {
        let loopback = unsafe { libc::if_nametoindex(b"lo\0".as_ptr().cast()) };
        assert_ne!(loopback, 0, "интерфейс lo отсутствует");

        let mut output = String::new();
        output.push_str(&format!("pick_null {}\n", super::r2o_pick_maxlen(None)));
        output.push_str(&format!("pick_lo {}\n", super::r2o_pick_maxlen(Some("lo"))));

        let socket = тестовый_raw_сокет(false);
        let adopted = socket.r2o_adopt_egress(&[loopback]);
        output.push_str(&format!(
            "adopt_lo {} maxlen={} egress={}\n",
            i32::from(adopted.is_some()),
            socket.maxlen.get(),
            socket.egress_mtu.get().unwrap_or(0)
        ));
        let again = socket.r2o_adopt_egress(&[loopback]);
        output.push_str(&format!(
            "adopt_lo_again {} maxlen={} egress={}\n",
            i32::from(again.is_some()),
            socket.maxlen.get(),
            socket.egress_mtu.get().unwrap_or(0)
        ));
        let missing = socket.r2o_adopt_egress(&[0x7fff_fff0]);
        output.push_str(&format!(
            "adopt_missing {} maxlen={}\n",
            if missing.is_some() { 1 } else { -1 },
            socket.maxlen.get()
        ));

        let declared = тестовый_raw_сокет(true);
        let refused = declared.r2o_adopt_egress(&[loopback]);
        output.push_str(&format!(
            "adopt_declared {} maxlen={}\n",
            if refused.is_some() { 1 } else { -1 },
            declared.maxlen.get()
        ));

        if let Ok(path) = std::env::var("R2O_RAW_ADOPT_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains("adopt_lo "));
    }

    #[test]
    fn raw_fragment_differential_matches_c() {
        let scenario = std::env::var("FAKE_OPEN_SCENARIO").unwrap_or_else(|_| "ok".into());
        let mut output = String::new();
        let socket = match super::RawSocket::open(libc::AF_INET, 0, None) {
            Ok(socket) => socket,
            Err(error) => {
                // Без CAP_NET_RAW тест не может открыть сокет; содержательная
                // проверка идёт через scripts/test-datapath-raw-fragment-differential.sh
                // с LD_PRELOAD-шивом socket/setsockopt.
                output.push_str(&format!("{scenario} open rc=-1 error={error}\n"));
                if let Ok(path) = std::env::var("R2O_RAW_FRAGMENT_DIFF_OUTPUT") {
                    std::fs::write(path, &output).unwrap();
                }
                eprintln!("raw socket не открылся ({error}); differential требует CAP_NET_RAW");
                return;
            }
        };
        let fragments = fragments(&original_v4());
        let mut plain = original_v4();
        plain[6..8].fill(0);

        for (kind, packet) in [("fragment", &fragments[0]), ("plain", &plain)] {
            let result = socket.send_packet(packet);
            let stats = socket.send_stats();
            let fragment_open = usize::from(socket.fragment_fd.borrow().is_some());
            output.push_str(&format!(
                "{scenario} {kind} rc={} fd={fragment_open} sent={} errors={} busy={}\n",
                if result.is_ok() { 0 } else { -1 },
                stats.sent,
                stats.errors,
                stats.busy
            ));
        }
        if let Ok(path) = std::env::var("R2O_RAW_FRAGMENT_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains(&format!("{scenario} fragment rc=")));
    }
}

#[cfg(test)]
mod tls_route_cap_tests {
    use super::r2o_tls_route_segment_cap_with;

    fn put16(packet: &mut [u8], at: usize, value: u16) {
        packet[at..at + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn fill(packet: &mut [u8]) {
        for (index, byte) in packet.iter_mut().enumerate() {
            *byte = 0x30_u8.wrapping_add(index as u8 & 0x3f);
        }
    }

    fn v4(
        length: usize,
        ihl: u8,
        proto: u8,
        tcp_data_offset: u8,
        first: u8,
        second: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0; 96];
        fill(&mut packet);
        packet[0] = 0x40 | ihl;
        put16(&mut packet, 2, length as u16);
        packet[8] = 64;
        packet[9] = proto;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        let tcp = usize::from(ihl) * 4;
        put16(&mut packet, tcp, 40000);
        put16(&mut packet, tcp + 2, 443);
        packet[tcp + 12] = tcp_data_offset << 4;
        let payload = tcp + usize::from(tcp_data_offset) * 4;
        packet[payload] = first;
        packet[payload + 1] = second;
        packet.truncate(length);
        packet
    }

    fn v6(length: usize, next: u8, tcp_data_offset: u8, first: u8, second: u8) -> Vec<u8> {
        let mut packet = vec![0; 96];
        fill(&mut packet);
        packet[0] = 0x60;
        packet[6] = next;
        packet[7] = 64;
        for offset in 0..16 {
            packet[8 + offset] = 0x20 + offset as u8;
            packet[24 + offset] = 0x40 + offset as u8;
        }
        packet[52] = tcp_data_offset << 4;
        let payload = 40 + usize::from(tcp_data_offset) * 4;
        packet[payload] = first;
        packet[payload + 1] = second;
        packet.truncate(length);
        packet
    }

    fn run(name: &str, packet: &[u8], mtu: usize) {
        let cap = r2o_tls_route_segment_cap_with(packet, |_, _| mtu);
        println!("{name} cap={cap}");
    }

    #[test]
    #[ignore]
    fn d2o_tls_route_cap_trace() {
        run("A v4-tls", &v4(60, 5, 6, 5, 0x16, 3), 1500);
        run("B v4-ihl6", &v4(64, 6, 6, 5, 0x16, 3), 1400);
        run("C v4-udp", &v4(60, 5, 17, 5, 0x16, 3), 1500);
        run("D v4-not-tls", &v4(60, 5, 6, 5, 0x17, 3), 1500);
        run("E v4-wrong-ver", &v4(60, 5, 6, 5, 0x16, 2), 1500);
        run("F v4-short-doff", &v4(60, 5, 6, 4, 0x16, 3), 1500);
        run("G v4-too-short", &v4(39, 5, 6, 5, 0x16, 3), 1500);
        run("H v4-exact", &v4(45, 5, 6, 5, 0x16, 3), 1500);
        run("I v4-small-mtu", &v4(60, 5, 6, 5, 0x16, 3), 40);
        run("J v6-tls", &v6(70, 6, 5, 0x16, 3), 1280);
        run("K v6-short", &v6(59, 6, 5, 0x16, 3), 1280);
        run("L v6-not-tcp", &v6(70, 17, 5, 0x16, 3), 1280);
        run("M v4-tls-2", &v4(60, 5, 6, 5, 0x16, 3), 1500);
        let mut bad = v4(60, 5, 6, 5, 0x16, 3);
        bad[0] = 0x55;
        run("N bad-version", &bad, 1500);
    }
}
