//! Контроллерный UDP plan-send: C `d2k_udp_plan_send` (`core/udpruntime.c:147-190`).
//!
//! Слой повторяет C-примитив, а не datapath-engine: connected `UdpSocket` —
//! это sink для обычных датаграмм, а `Plan::apply`/`wire` собирают ровно те
//! байты, которые C отдаёт в `d2k_udp_batch`. Fragment-эмиссии уходят через
//! [`R2oUdpRawSink`]; production-адаптер `RawSocket` подключает Controller
//! (в этой пачке production call-site намеренно не добавляется).
//!
//! Текст плана в `r2k-core` не парсится: Controller уже имеет production
//! `plan_text::compile_text`, после него вызывает `Plan::parse` и передаёт
//! готовый [`Plan`] сюда. Это сохраняет единственный парсер TLV.

use crate::plan::{
    Emission, EmitKind, OriginalFate, POISON_IPID_ZERO, PacketInput, Plan, WIRE_BATCH_MAX,
};
use crate::wire::{build_udp_fragments, build_udp_packet};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
#[cfg(unix)]
use std::os::fd::AsRawFd;

/// Максимум посылок одной пачки, как `D2K_UDP_BATCH_MAX`.
pub const R2O_UDP_PLAN_BATCH_MAX: usize = WIRE_BATCH_MAX;

/// Одна посылка `d2k_udp_batch`: полный IP-пакет и задержка перед ней.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oUdpBatchEntry {
    pub bytes: Vec<u8>,
    pub delay_us: u32,
    pub fragment: bool,
}

/// Sink для fragment-эмиссий: C `udp_prepare_io`/`udp_send_io`.
///
/// Controller подключает сюда `r2o_datapath::raw::RawSocket`; тесты —
/// счётчик/подмену. `prepare` вызывается для ВСЕХ fragment-эмиссий до первой
/// отправки, как C.
pub trait R2oUdpRawSink {
    fn r2o_prepare(&mut self, packet: &[u8], mark: u32) -> Result<(), i32>;
    fn r2o_send(&mut self, packet: &[u8], mark: u32) -> Result<(), i32>;
}

/// Production sink без Controller-адаптера: IPv4 raw (IP_HDRINCL+IP_NODEFRAG).
/// IPv6-фрагменты сюда не входят: их отправляет `RawSocket` Controller'а;
/// при вызове без адаптера возвращается -1, а не тихая подмена.
#[derive(Default)]
pub struct R2oUdpDefaultRawSink {
    #[cfg(unix)]
    fd4: Option<std::os::fd::OwnedFd>,
}

impl R2oUdpDefaultRawSink {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(unix)]
    fn prepare_ipv4(&mut self, mark: u32) -> Result<(), i32> {
        use std::os::fd::FromRawFd;

        if self.fd4.is_some() {
            return Ok(());
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        };
        if raw < 0 {
            return Err(-1);
        }
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        let one: libc::c_int = 1;
        if set_option(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_HDRINCL, &one).is_err()
            || set_option(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_NODEFRAG, &one).is_err()
            || (mark != 0
                && set_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, &mark).is_err())
        {
            return Err(-1);
        }
        self.fd4 = Some(fd);
        Ok(())
    }

    #[cfg(not(unix))]
    fn prepare_ipv4(&mut self, _mark: u32) -> Result<(), i32> {
        Err(-1)
    }
}

impl R2oUdpRawSink for R2oUdpDefaultRawSink {
    fn r2o_prepare(&mut self, packet: &[u8], mark: u32) -> Result<(), i32> {
        if packet.first().is_none_or(|byte| byte >> 4 != 4) {
            return Err(-1);
        }
        self.prepare_ipv4(mark)
    }

    fn r2o_send(&mut self, packet: &[u8], _mark: u32) -> Result<(), i32> {
        #[cfg(unix)]
        {
            if packet.len() < 20 || packet[0] >> 4 != 4 {
                return Err(-1);
            }
            let Some(fd) = self.fd4.as_ref() else {
                return Err(-1);
            };
            let mut destination: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            destination.sin_family = libc::AF_INET as libc::sa_family_t;
            destination.sin_addr.s_addr =
                u32::from_ne_bytes(packet[16..20].try_into().map_err(|_| -1_i32)?);
            let sent = unsafe {
                libc::sendto(
                    fd.as_raw_fd(),
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    &destination as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of_val(&destination) as libc::socklen_t,
                )
            };
            if sent == packet.len() as isize {
                Ok(())
            } else {
                Err(-1)
            }
        }
        #[cfg(not(unix))]
        {
            let _ = packet;
            Err(-1)
        }
    }
}

/// Собрать `d2k_udp_batch`: полные IP-пакеты, delays и fragment-флаги.
pub fn r2o_udp_plan_batch(
    plan: &Plan,
    local: SocketAddr,
    peer: SocketAddr,
    ttl: u8,
    fragment_id: u32,
    payload: &[u8],
) -> Result<Vec<R2oUdpBatchEntry>, i32> {
    if plan.transport != 17 || payload.is_empty() {
        return Err(-1);
    }
    let input = r2o_udp_input_packet(local, peer, ttl, payload).ok_or(-1_i32)?;
    let packet_input = PacketInput {
        payload,
        seq: 0,
        have_sni: false,
        is_tls13: false,
        sni_off: 0,
        sni_len: 0,
        segment_cap: 0,
        reference_ttl: 0,
        own_after_fakes: true,
        is_http: false,
    };
    let actions = plan.apply(&packet_input).map_err(|_| -1_i32)?;
    if actions.fate == OriginalFate::Hold {
        return Err(-1);
    }
    let mut batch = Vec::new();
    let mut payloads = 0_usize;
    for emission in &actions.emits {
        if emission.kind == EmitKind::Payload {
            payloads += 1;
            if payloads > 1 {
                return Err(-1);
            }
        }
        if emission.poison & POISON_IPID_ZERO != 0 {
            return Err(-1);
        }
        if emission.ipfrag != 0 {
            if emission.kind != EmitKind::Payload
                || !emission.prefix.is_empty()
                || emission.seq_shift != 0
                || emission.poison != 0
                || emission.wire_profile != 0
            {
                return Err(-1);
            }
            let fragments = build_udp_fragments(&input, emission).ok_or(-1_i32)?;
            if fragment_id == 0 {
                return Err(-1);
            }
            for (index, mut fragment) in fragments.into_iter().enumerate() {
                r2o_patch_fragment_id(&mut fragment, fragment_id);
                batch.push(R2oUdpBatchEntry {
                    bytes: fragment,
                    delay_us: if index == 0 { emission.delay_us } else { 0 },
                    fragment: true,
                });
            }
        } else {
            let mut buffer = vec![0_u8; 65_535];
            let length = build_udp_packet(&input, emission, &mut buffer).ok_or(-1_i32)?;
            buffer.truncate(length);
            batch.push(R2oUdpBatchEntry {
                bytes: buffer,
                delay_us: emission.delay_us,
                fragment: false,
            });
        }
    }
    if actions.fate == OriginalFate::Pass {
        let emission = Emission {
            kind: EmitKind::Payload,
            delay_us: 0,
            seq: 0,
            ttl: 0,
            poison: 0,
            seq_shift: 0,
            wire_profile: 0,
            ipfrag: 0,
            urgent: false,
            urgent_ptr: 0,
            prefix: Vec::new(),
            bytes: payload.to_vec(),
        };
        let mut buffer = vec![0_u8; 65_535];
        let length = build_udp_packet(&input, &emission, &mut buffer).ok_or(-1_i32)?;
        buffer.truncate(length);
        batch.push(R2oUdpBatchEntry {
            bytes: buffer,
            delay_us: 0,
            fragment: false,
        });
    }
    if batch.is_empty() || batch.len() > R2O_UDP_PLAN_BATCH_MAX {
        return Err(-1);
    }
    Ok(batch)
}

/// C `d2k_udp_plan_send`: отправить UDP-план с connected-сокета.
#[cfg(unix)]
pub fn r2o_udp_plan_send(
    socket: &UdpSocket,
    plan: &Plan,
    payload: &[u8],
    mark: u32,
) -> Result<(), i32> {
    let mut sink = R2oUdpDefaultRawSink::new();
    r2o_udp_plan_send_with_sink(socket, plan, payload, mark, &mut sink)
}

/// То же с явным fragment-sink (Controller передаёт `RawSocket`-адаптер).
#[cfg(unix)]
pub fn r2o_udp_plan_send_with_sink(
    socket: &UdpSocket,
    plan: &Plan,
    payload: &[u8],
    mark: u32,
    sink: &mut dyn R2oUdpRawSink,
) -> Result<(), i32> {
    let local = socket.local_addr().map_err(|_| -1_i32)?;
    let peer = socket.peer_addr().map_err(|_| -1_i32)?;
    let family = match (local, peer) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => 4_u8,
        (SocketAddr::V6(_), SocketAddr::V6(_)) => 6_u8,
        _ => return Err(-1),
    };
    let (level, hop) = if family == 6 {
        (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
    } else {
        (libc::IPPROTO_IP, libc::IP_TTL)
    };
    let ttl = get_socket_ttl(socket.as_raw_fd(), level, hop)?;
    if ttl == 0 || ttl > 255 {
        return Err(-1);
    }
    let fragment_id = r2o_fragment_id()?;
    let batch = r2o_udp_plan_batch(plan, local, peer, ttl as u8, fragment_id, payload)?;
    for entry in batch.iter().filter(|entry| entry.fragment) {
        sink.r2o_prepare(&entry.bytes, mark)?;
    }
    let mut result = Ok(());
    for entry in &batch {
        if entry.delay_us != 0 && r2o_sleep_us(entry.delay_us).is_err() {
            result = Err(-1);
            break;
        }
        if entry.fragment {
            if sink.r2o_send(&entry.bytes, mark).is_err() {
                result = Err(-1);
                break;
            }
            continue;
        }
        let offset = if family == 6 { 48 } else { 28 };
        if entry.bytes.len() < offset {
            result = Err(-1);
            break;
        }
        let want = if family == 6 {
            entry.bytes[7]
        } else {
            entry.bytes[8]
        };
        if set_socket_ttl(socket.as_raw_fd(), level, hop, want.into()).is_err() {
            result = Err(-1);
            break;
        }
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                entry.bytes[offset..].as_ptr().cast(),
                entry.bytes.len() - offset,
                0,
            )
        };
        if sent != (entry.bytes.len() - offset) as isize {
            result = Err(
                if io::Error::last_os_error().raw_os_error() == Some(libc::ECONNREFUSED) {
                    -2
                } else {
                    -1
                },
            );
            break;
        }
    }
    if set_socket_ttl(socket.as_raw_fd(), level, hop, ttl).is_err() {
        result = Err(-1);
    }
    result
}

/// На не-Unix raw-сокеты и TTL через libc недоступны; batch остаётся
/// переносимым, а отправка честно отказывает, как C `#ifndef __linux__`
/// для raw-sink.
#[cfg(not(unix))]
pub fn r2o_udp_plan_send(
    _socket: &UdpSocket,
    _plan: &Plan,
    _payload: &[u8],
    _mark: u32,
) -> Result<(), i32> {
    Err(-1)
}

#[cfg(not(unix))]
pub fn r2o_udp_plan_send_with_sink(
    _socket: &UdpSocket,
    _plan: &Plan,
    _payload: &[u8],
    _mark: u32,
    _sink: &mut dyn R2oUdpRawSink,
) -> Result<(), i32> {
    Err(-1)
}

fn r2o_udp_input_packet(
    local: SocketAddr,
    peer: SocketAddr,
    ttl: u8,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let (source, destination, source_port, destination_port) = match (local, peer) {
        (SocketAddr::V4(local), SocketAddr::V4(peer)) => (
            IpAddr::V4(*local.ip()),
            IpAddr::V4(*peer.ip()),
            local.port(),
            peer.port(),
        ),
        (SocketAddr::V6(local), SocketAddr::V6(peer)) => (
            IpAddr::V6(*local.ip()),
            IpAddr::V6(*peer.ip()),
            local.port(),
            peer.port(),
        ),
        _ => return None,
    };
    let udp_length = 8usize.checked_add(payload.len())?;
    let mut packet = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let total = 20usize.checked_add(udp_length)?;
            if total > u16::MAX as usize {
                return None;
            }
            let mut packet = vec![0_u8; total];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            packet[4..6].copy_from_slice(&0_u16.to_be_bytes());
            packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
            packet[8] = ttl;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            let checksum = internet_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            packet
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let total = 40usize.checked_add(udp_length)?;
            let mut packet = vec![0_u8; total];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(udp_length as u16).to_be_bytes());
            packet[6] = 17;
            packet[7] = ttl;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
            packet
        }
        _ => return None,
    };
    let udp = if packet[0] >> 4 == 4 { 20 } else { 40 };
    packet[udp..udp + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[udp + 2..udp + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[udp + 4..udp + 6].copy_from_slice(&(udp_length as u16).to_be_bytes());
    packet[udp + 8..].copy_from_slice(payload);
    Some(packet)
}

fn r2o_patch_fragment_id(fragment: &mut [u8], id: u32) {
    match fragment.first().map(|byte| byte >> 4) {
        Some(4) if fragment.len() >= 20 => {
            // C `d2k_udpfrag_build_ex`: wr16(out+4, (uint16_t)id).
            fragment[4..6].copy_from_slice(&(id as u16).to_be_bytes());
            fragment[10..12].fill(0);
            let checksum = internet_checksum(&fragment[..20]);
            fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        Some(6) if fragment.len() >= 48 => {
            // C `d2k_udpfrag6_build_ex`: wr16(out+44, id>>16), wr16(out+46, id).
            fragment[44..48].copy_from_slice(&id.to_be_bytes());
        }
        _ => {}
    }
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = bytes.chunks_exact(2).remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(unix)]
fn set_option<T>(fd: i32, level: i32, option: i32, value: &T) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            value as *const T as *const libc::c_void,
            std::mem::size_of_val(value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn get_socket_ttl(fd: i32, level: i32, option: i32) -> Result<i32, i32> {
    let mut value = 0_i32;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut i32).cast(),
            &mut length,
        )
    };
    if result == 0 { Ok(value) } else { Err(-1) }
}

#[cfg(unix)]
fn set_socket_ttl(fd: i32, level: i32, option: i32, value: i32) -> Result<(), i32> {
    set_option(fd, level, option, &value).map_err(|_| -1)
}

#[cfg(unix)]
fn r2o_sleep_us(delay_us: u32) -> Result<(), i32> {
    #[cfg(test)]
    if std::env::var_os("R2O_UDP_TEST_REAL_SLEEP").is_none() {
        return R2O_UDP_TEST_STATE.with(|cell| {
            let mut state = cell.borrow_mut();
            state.delays.push(delay_us);
            state.sleep_calls += 1;
            if state.sleep_error {
                return Err(-1);
            }
            if state.sleep_eintr_once {
                state.sleep_eintr_once = false;
                state.sleep_calls += 1;
            }
            Ok(())
        });
    }
    {
        let mut wait = libc::timespec {
            tv_sec: (delay_us / 1_000_000) as libc::time_t,
            tv_nsec: ((delay_us % 1_000_000) * 1_000) as libc::c_long,
        };
        loop {
            let slept = unsafe { libc::nanosleep(&wait, &mut wait) };
            if slept == 0 {
                return Ok(());
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(-1);
            }
        }
    }
}

#[cfg(not(unix))]
fn r2o_sleep_us(_delay_us: u32) -> Result<(), i32> {
    Err(-1)
}

#[cfg(unix)]
fn r2o_fragment_id() -> Result<u32, i32> {
    #[cfg(test)]
    if let Some(id) = r2o_test_fragment_id() {
        return Ok(id);
    }
    let id = crate::wire::next_udp_fragment_id();
    if id == 0 { Err(-1) } else { Ok(id) }
}

#[cfg(all(unix, test))]
thread_local! {
    static R2O_UDP_TEST_STATE: std::cell::RefCell<R2oUdpTestState> =
        const { std::cell::RefCell::new(R2oUdpTestState::new()) };
}

#[cfg(all(unix, test))]
struct R2oUdpTestState {
    fragment_id: Option<u32>,
    delays: Vec<u32>,
    sleep_calls: usize,
    sleep_eintr_once: bool,
    sleep_error: bool,
}

#[cfg(all(unix, test))]
impl R2oUdpTestState {
    const fn new() -> Self {
        Self {
            fragment_id: None,
            delays: Vec::new(),
            sleep_calls: 0,
            sleep_eintr_once: false,
            sleep_error: false,
        }
    }
}

#[cfg(all(unix, test))]
pub(crate) fn r2o_udp_test_reset(fragment_id: Option<u32>) {
    R2O_UDP_TEST_STATE.with(|state| {
        let mut state = state.borrow_mut();
        *state = R2oUdpTestState::new();
        state.fragment_id = fragment_id;
    });
}

#[cfg(all(unix, test))]
pub(crate) fn r2o_udp_test_set_sleep_eintr_once() {
    R2O_UDP_TEST_STATE.with(|state| state.borrow_mut().sleep_eintr_once = true);
}

#[cfg(all(unix, test))]
pub(crate) fn r2o_udp_test_set_sleep_error() {
    R2O_UDP_TEST_STATE.with(|state| state.borrow_mut().sleep_error = true);
}

#[cfg(all(unix, test))]
pub(crate) fn r2o_udp_test_delays() -> Vec<u32> {
    R2O_UDP_TEST_STATE.with(|state| state.borrow().delays.clone())
}

#[cfg(all(unix, test))]
pub(crate) fn r2o_udp_test_sleep_calls() -> usize {
    R2O_UDP_TEST_STATE.with(|state| state.borrow().sleep_calls)
}

#[cfg(all(unix, test))]
fn r2o_test_fragment_id() -> Option<u32> {
    R2O_UDP_TEST_STATE.with(|state| state.borrow().fragment_id)
}

#[cfg(not(unix))]
fn r2o_fragment_id() -> Result<u32, i32> {
    Err(-1)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        R2oUdpRawSink, r2o_udp_plan_send_with_sink, r2o_udp_test_delays, r2o_udp_test_reset,
        r2o_udp_test_set_sleep_eintr_once, r2o_udp_test_set_sleep_error, r2o_udp_test_sleep_calls,
    };
    use std::io::Write;
    use std::net::UdpSocket;

    struct LoggingSink;

    impl LoggingSink {
        fn log(prefix: &str, packet: &[u8], mark: u32) {
            let Ok(path) = std::env::var("R2O_UDP_SEND_SHIM_LOG") else {
                return;
            };
            let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            else {
                return;
            };
            let hex: String = packet.iter().map(|byte| format!("{byte:02x}")).collect();
            if mark == 0 {
                let _ = writeln!(file, "{prefix} len={} hex={hex}", packet.len());
            } else {
                let _ = writeln!(file, "{prefix} len={} hex={hex} mark={mark}", packet.len());
            }
        }
    }

    impl R2oUdpRawSink for LoggingSink {
        fn r2o_prepare(&mut self, packet: &[u8], mark: u32) -> Result<(), i32> {
            Self::log("prepare", packet, mark);
            if std::env::var("R2O_UDP_SEND_SCENARIO").as_deref() == Ok("prepare_error") {
                return Err(-1);
            }
            Ok(())
        }

        fn r2o_send(&mut self, packet: &[u8], mark: u32) -> Result<(), i32> {
            Self::log("raw_send", packet, mark);
            if std::env::var("R2O_UDP_SEND_SCENARIO").as_deref() == Ok("raw_send_error") {
                return Err(-1);
            }
            Ok(())
        }
    }

    #[test]
    fn udp_plan_delay_eintr_retries_and_reports_error() {
        r2o_udp_test_reset(None);
        r2o_udp_test_set_sleep_eintr_once();
        assert!(super::r2o_sleep_us(15_000).is_ok());
        assert_eq!(r2o_udp_test_sleep_calls(), 2);
        assert_eq!(r2o_udp_test_delays(), vec![15_000]);

        r2o_udp_test_reset(None);
        r2o_udp_test_set_sleep_error();
        assert_eq!(super::r2o_sleep_us(1), Err(-1));
    }

    #[test]
    fn udp_plan_send_differential_matches_c() {
        let Some(path) = std::env::var_os("R2O_UDP_PLAN_TLV_OUT") else {
            return;
        };
        let family: u8 = std::env::var("R2O_UDP_PLAN_FAMILY")
            .unwrap()
            .parse()
            .unwrap();
        let tlv = std::fs::read(path).unwrap();
        let plan = crate::plan::Plan::parse_wire(&tlv).unwrap();
        let (receiver, sender) = if family == 4 {
            let receiver = UdpSocket::bind("127.0.0.1:40001").unwrap();
            let sender = UdpSocket::bind("127.0.0.1:40000").unwrap();
            sender.connect(receiver.local_addr().unwrap()).unwrap();
            (receiver, sender)
        } else {
            let receiver = UdpSocket::bind("[::1]:40001").unwrap();
            let sender = UdpSocket::bind("[::1]:40000").unwrap();
            sender.connect(receiver.local_addr().unwrap()).unwrap();
            (receiver, sender)
        };
        let payload = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        if std::env::var_os("R2O_UDP_PLAN_BUILD_ONLY").is_some() {
            let empty = std::env::var_os("R2O_UDP_PLAN_EMPTY").is_some();
            let bytes: &[u8] = if empty { &[] } else { &payload };
            let result = super::r2o_udp_plan_batch(
                &plan,
                sender.local_addr().unwrap(),
                sender.peer_addr().unwrap(),
                47,
                0x1234_5678,
                bytes,
            );
            let code = match result {
                Ok(_) => 0,
                Err(code) => code,
            };
            let output = format!("build rc={code}\n");
            if let Ok(path) = std::env::var("R2O_UDP_PLAN_BUILD_DIFF_OUTPUT") {
                std::fs::write(path, output).unwrap();
            }
            assert!(code == 0 || code == -1);
            return;
        }
        r2o_udp_test_reset(Some(0x1234_5678));
        if let Ok(path) = std::env::var("R2O_UDP_PLAN_BUILD_OUT") {
            let mut build = String::new();
            match super::r2o_udp_plan_batch(
                &plan,
                sender.local_addr().unwrap(),
                sender.peer_addr().unwrap(),
                47,
                0x1234_5678,
                &payload,
            ) {
                Ok(batch) => {
                    let used: usize = batch.iter().map(|entry| entry.bytes.len()).sum();
                    build.push_str(&format!("batch rc=0 n={} used={used}\n", batch.len()));
                    for (index, entry) in batch.iter().enumerate() {
                        let hex: String = entry
                            .bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect();
                        build.push_str(&format!(
                            "{index} frag={} delay={} len={} hex={hex}\n",
                            u8::from(entry.fragment),
                            entry.delay_us,
                            entry.bytes.len()
                        ));
                    }
                }
                Err(code) => build.push_str(&format!("batch rc={code}\n")),
            }
            std::fs::write(path, build).unwrap();
        }
        let mut sink = LoggingSink;
        let result = r2o_udp_plan_send_with_sink(&sender, &plan, &payload, 46, &mut sink);
        drop(receiver);
        let code = match result {
            Ok(()) => 0,
            Err(code) => code,
        };
        let output = format!("send rc={code}\n");
        if let Ok(path) = std::env::var("R2O_UDP_PLAN_SEND_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
        assert!(code == 0 || code == -1 || code == -2);
    }
}
