//! Сопоставление меток маршрутизации и выходных интерфейсов для потоков R2O.

use std::collections::HashMap;
use std::convert::TryInto;
use std::time::{Duration, Instant};

pub const R2O_ROUTE_OTHER_DEV: u32 = u32::MAX;
pub const R2O_ROUTE_OUTSIDE: u32 = u32::MAX - 1;

const R2O_NLMSG_HEADER_LEN: usize = 16;
const R2O_FIB_RULE_HEADER_LEN: usize = 12;
const R2O_ROUTE_HEADER_LEN: usize = 12;
const R2O_NLA_HEADER_LEN: usize = 4;
const R2O_RTNEXTHOP_HEADER_LEN: usize = 8;
const R2O_NLMSG_ERROR: u16 = 2;
const R2O_NLMSG_DONE: u16 = 3;
const R2O_RTM_NEWROUTE: u16 = 24;
const R2O_RTM_DELROUTE: u16 = 25;
const R2O_RTM_GETROUTE: u16 = 26;
const R2O_RTM_NEWRULE: u16 = 32;
const R2O_RTM_DELRULE: u16 = 33;
const R2O_RTM_GETRULE: u16 = 34;
const R2O_NLM_F_REQUEST: u16 = 0x01;
const R2O_NLM_F_DUMP: u16 = 0x300;
const R2O_NLA_TYPE_MASK: u16 = 0x3fff;
const R2O_FRA_FWMARK: u16 = 10;
const R2O_FRA_FWMASK: u16 = 16;
const R2O_FIB_RULE_INVERT: u32 = 0x2;
const R2O_RTA_DST: u16 = 1;
const R2O_RTA_OIF: u16 = 4;
const R2O_RTA_MULTIPATH: u16 = 9;
const R2O_RTN_UNICAST: u8 = 1;
const R2O_ROUTE_FLOW_CAPACITY: usize = 4096;
const R2O_ROUTE_FLOW_IDLE: Duration = Duration::from_secs(120);

#[cfg(target_os = "linux")]
const R2O_NETLINK_ROUTE: i32 = 0;
#[cfg(target_os = "linux")]
const R2O_NETLINK_ADD_MEMBERSHIP: i32 = 1;
#[cfg(target_os = "linux")]
const R2O_SOL_NETLINK: i32 = 270;
#[cfg(target_os = "linux")]
pub const R2O_ROUTE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
pub const R2O_ROUTE_SETTLE_INTERVAL: Duration = Duration::from_millis(100);
const R2O_ROUTE_RULE_CAPACITY: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oRouteFamily {
    Ipv4,
    Ipv6,
}

impl R2oRouteFamily {
    const fn r2o_id(self) -> u8 {
        match self {
            Self::Ipv4 => 2,
            Self::Ipv6 => 10,
        }
    }

    const fn r2o_probe(self) -> &'static [u8] {
        match self {
            Self::Ipv4 => &[192, 0, 2, 1],
            Self::Ipv6 => &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oFwSelector {
    pub mark: u32,
    pub mask: u32,
    pub family: R2oRouteFamily,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oRoutePolicy {
    pub found: bool,
    pub mark: u32,
    pub mask: u32,
}

impl R2oRoutePolicy {
    pub const fn new(found: bool, mark: u32, mask: u32) -> Self {
        Self {
            found,
            mark: mark & mask,
            mask,
        }
    }

    const fn r2o_matches(self, mark: u32) -> bool {
        self.found && ((mark ^ self.mark) & self.mask) == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oRoutePacket {
    pub family: R2oRouteFamily,
    pub outbound: bool,
    pub mark: Option<u32>,
    pub probe_mark: u32,
    pub datapath_mark: u32,
    pub output_ifindex: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct R2oRouteGate {
    r2o_rules_v4: Option<Vec<R2oFwSelector>>,
    r2o_rules_v6: Option<Vec<R2oFwSelector>>,
    r2o_default_ifindices_v4: Option<Vec<u32>>,
    r2o_default_ifindices_v6: Option<Vec<u32>>,
    r2o_policy: Option<R2oRoutePolicy>,
}

impl R2oRouteGate {
    /// Сохраняет успешно прочитанный набор правил конкретного семейства.
    pub fn r2o_set_rules(&mut self, family: R2oRouteFamily, mut rules: Vec<R2oFwSelector>) {
        rules.retain(|rule| rule.family == family);
        for rule in &mut rules {
            rule.mark &= rule.mask;
        }
        match family {
            R2oRouteFamily::Ipv4 => self.r2o_rules_v4 = Some(rules),
            R2oRouteFamily::Ipv6 => self.r2o_rules_v6 = Some(rules),
        }
    }

    /// Задаёт устройства маршрута по умолчанию; `None` означает, что чтение неизвестно.
    pub fn r2o_set_default_ifindices(
        &mut self,
        family: R2oRouteFamily,
        ifindices: Option<Vec<u32>>,
    ) {
        let ifindices = ifindices.map(|values| {
            let mut unique = Vec::with_capacity(values.len());
            for value in values {
                if value != 0 && !unique.contains(&value) {
                    unique.push(value);
                }
            }
            unique
        });
        match family {
            R2oRouteFamily::Ipv4 => self.r2o_default_ifindices_v4 = ifindices,
            R2oRouteFamily::Ipv6 => self.r2o_default_ifindices_v6 = ifindices,
        }
    }

    /// Включает ограничение выбранной политикой или отключает его значением `None`.
    pub fn r2o_set_policy(&mut self, policy: Option<R2oRoutePolicy>) {
        self.r2o_policy = policy;
    }

    /// Проверяет, направляет ли метка поток по чужому правилу маршрутизации.
    pub fn r2o_mark_is_routed(&self, family: R2oRouteFamily, mark: u32) -> bool {
        if mark == 0 {
            return false;
        }
        if mark == R2O_ROUTE_OTHER_DEV || mark == R2O_ROUTE_OUTSIDE {
            return true;
        }
        if self
            .r2o_policy
            .is_some_and(|policy| policy.r2o_matches(mark))
        {
            return false;
        }
        let rules = match family {
            R2oRouteFamily::Ipv4 => self.r2o_rules_v4.as_deref(),
            R2oRouteFamily::Ipv6 => self.r2o_rules_v6.as_deref(),
        };
        let Some(rules) = rules else {
            return true;
        };
        rules
            .iter()
            .any(|rule| ((mark ^ rule.mark) & rule.mask) == 0)
    }

    /// Возвращает метку потока, которую runtime должен передать обработчикам.
    pub fn r2o_route_mark(&self, packet: R2oRoutePacket) -> u32 {
        let mark = packet.mark.unwrap_or(0);
        if packet.outbound && self.r2o_policy.is_some() {
            let own = mark != 0 && (mark == packet.probe_mark || mark == packet.datapath_mark);
            let selected = packet.mark.is_some_and(|value| {
                self.r2o_policy
                    .is_some_and(|policy| policy.r2o_matches(value))
            });
            if !own && !selected {
                return R2O_ROUTE_OUTSIDE;
            }
        }

        if packet.mark.is_some()
            && mark != 0
            && mark != packet.probe_mark
            && mark != packet.datapath_mark
            && self.r2o_mark_is_routed(packet.family, mark)
        {
            return mark;
        }

        if !packet.outbound {
            return 0;
        }
        let Some(output_ifindex) = packet.output_ifindex else {
            return 0;
        };
        let default_ifindices = match packet.family {
            R2oRouteFamily::Ipv4 => self.r2o_default_ifindices_v4.as_deref(),
            R2oRouteFamily::Ipv6 => self.r2o_default_ifindices_v6.as_deref(),
        };
        let Some(default_ifindices) = default_ifindices else {
            return 0;
        };
        if default_ifindices.contains(&output_ifindex) {
            0
        } else {
            R2O_ROUTE_OTHER_DEV
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum R2oRouteParseError {
    Malformed,
    Kernel(i32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oRouteRuleBatch {
    pub selectors: Vec<R2oFwSelector>,
    pub done: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum R2oRouteLookup {
    Pending,
    Unicast(Vec<u32>),
    NoRoute,
}

/// Дамп rtnetlink и подписка на изменения правил и маршрутов Linux.
#[cfg(target_os = "linux")]
pub struct R2oRouteMonitor {
    watch: Option<std::os::fd::OwnedFd>,
    sequence: u32,
}

#[cfg(target_os = "linux")]
impl Default for R2oRouteMonitor {
    fn default() -> Self {
        Self {
            watch: None,
            sequence: 1,
        }
    }
}

#[cfg(target_os = "linux")]
impl R2oRouteMonitor {
    /// Подписывается на группы IPv4/IPv6; при недоступности подписки остаётся опрос.
    pub fn r2o_open_watch(&mut self) -> std::io::Result<()> {
        use std::os::fd::{FromRawFd, OwnedFd};

        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                R2O_NETLINK_ROUTE,
            )
        };
        if raw_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let result = unsafe {
            libc::bind(
                raw_fd,
                &local as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        for (group, required) in [(8_i32, true), (7, true), (19, false), (11, false)] {
            let result = unsafe {
                libc::setsockopt(
                    raw_fd,
                    R2O_SOL_NETLINK,
                    R2O_NETLINK_ADD_MEMBERSHIP,
                    &group as *const i32 as *const libc::c_void,
                    std::mem::size_of_val(&group) as libc::socklen_t,
                )
            };
            if result != 0 && required {
                return Err(std::io::Error::last_os_error());
            }
        }
        self.watch = Some(fd);
        Ok(())
    }

    /// Дескриптор уведомлений для совместного ожидания с NFQUEUE.
    pub fn r2o_watch_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        self.watch.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// Забирает ограниченную пачку уведомлений; потеря уведомления требует обновления.
    pub fn r2o_drain_watch(&self) -> std::io::Result<bool> {
        use std::os::fd::AsRawFd;
        let Some(watch) = self.watch.as_ref() else {
            return Ok(false);
        };
        let mut bytes = [0_u8; 8192];
        let mut changed = false;
        for _ in 0..256 {
            let received = unsafe {
                libc::recv(
                    watch.as_raw_fd(),
                    bytes.as_mut_ptr() as *mut libc::c_void,
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if received > 0 {
                changed |= r2o_route_watch_relevant(&bytes[..received as usize]);
                continue;
            }
            if received == 0 {
                return Ok(changed);
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ENOBUFS) => {
                    changed = true;
                    continue;
                }
                Some(libc::EAGAIN) => return Ok(changed),
                _ => return Err(error),
            }
        }
        Ok(true)
    }

    /// Обновляет семейства независимо и сохраняет прежние данные при ошибке.
    pub fn r2o_refresh(&mut self, gate: &mut R2oRouteGate) -> Vec<String> {
        let mut errors = Vec::new();
        for family in [R2oRouteFamily::Ipv4, R2oRouteFamily::Ipv6] {
            match self.r2o_dump_rules(family) {
                Ok(rules) => gate.r2o_set_rules(family, rules),
                Err(error) => errors.push(format!("правила {family:?}: {error}")),
            }
            match self.r2o_lookup_default(family) {
                Ok(R2oRouteLookup::Unicast(ifindices)) if ifindices.is_empty() => {
                    gate.r2o_set_default_ifindices(family, None);
                }
                Ok(R2oRouteLookup::Unicast(ifindices)) => {
                    gate.r2o_set_default_ifindices(family, Some(ifindices));
                }
                Ok(R2oRouteLookup::NoRoute) => {
                    gate.r2o_set_default_ifindices(family, Some(Vec::new()));
                }
                Ok(R2oRouteLookup::Pending) => errors.push(format!(
                    "маршрут {family:?}: ядро не ответило на одиночный поиск"
                )),
                Err(error) => errors.push(format!("маршрут {family:?}: {error}")),
            }
        }
        errors
    }

    fn r2o_dump_rules(&mut self, family: R2oRouteFamily) -> std::io::Result<Vec<R2oFwSelector>> {
        let mut selectors = Vec::new();
        let sequence = self.r2o_next_sequence();
        let request = r2o_route_rule_request(family, sequence);
        self.r2o_receive_request(request, |bytes| {
            let batch = match r2o_route_parse_rules(bytes) {
                Ok(batch) => batch,
                Err(R2oRouteParseError::Kernel(code))
                    if family == R2oRouteFamily::Ipv6 && matches!(code, -97 | -95) =>
                {
                    selectors.clear();
                    return Ok(true);
                }
                Err(error) => return Err(r2o_parse_io_error(error)),
            };
            if selectors.len() + batch.selectors.len() > R2O_ROUTE_RULE_CAPACITY {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "число правил fwmark превысило безопасный предел",
                ));
            }
            selectors.extend(batch.selectors);
            Ok(batch.done)
        })?;
        Ok(selectors)
    }

    fn r2o_lookup_default(&mut self, family: R2oRouteFamily) -> std::io::Result<R2oRouteLookup> {
        let mut result = R2oRouteLookup::Pending;
        let sequence = self.r2o_next_sequence();
        let request = r2o_route_lookup_request(family, sequence);
        self.r2o_receive_request(request, |bytes| {
            result = match r2o_route_parse_lookup(bytes) {
                Ok(result) => result,
                Err(R2oRouteParseError::Kernel(-97 | -100 | -101 | -113)) => {
                    R2oRouteLookup::NoRoute
                }
                Err(error) => return Err(r2o_parse_io_error(error)),
            };
            if matches!(&result, R2oRouteLookup::Unicast(ifindices) if ifindices.len() > 16) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "число выходных интерфейсов превышает безопасный предел",
                ));
            }
            Ok(!matches!(result, R2oRouteLookup::Pending))
        })?;
        Ok(result)
    }

    fn r2o_receive_request(
        &mut self,
        request: Vec<u8>,
        mut parse: impl FnMut(&[u8]) -> std::io::Result<bool>,
    ) -> std::io::Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                R2O_NETLINK_ROUTE,
            )
        };
        if raw_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let bound = unsafe {
            libc::bind(
                raw_fd,
                &local as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bound != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        let configured = unsafe {
            libc::setsockopt(
                raw_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        };
        if configured != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut destination: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        destination.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let sent = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                request.as_ptr() as *const libc::c_void,
                request.len(),
                0,
                &destination as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent != request.len() as isize {
            return Err(std::io::Error::last_os_error());
        }

        let mut bytes = [0_u8; 32768];
        for _ in 0..4096 {
            let received = unsafe {
                libc::recv(
                    fd.as_raw_fd(),
                    bytes.as_mut_ptr() as *mut libc::c_void,
                    bytes.len(),
                    0,
                )
            };
            if received < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if parse(&bytes[..received as usize])? {
                return Ok(());
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ответ rtnetlink не завершился в заданном пределе",
        ))
    }

    fn r2o_next_sequence(&mut self) -> u32 {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1).max(1);
        sequence
    }
}

#[cfg(target_os = "linux")]
fn r2o_parse_io_error(error: R2oRouteParseError) -> std::io::Error {
    use std::io::{Error, ErrorKind};
    match error {
        R2oRouteParseError::Malformed => {
            Error::new(ErrorKind::InvalidData, "повреждённый ответ rtnetlink")
        }
        R2oRouteParseError::Kernel(code) => Error::from_raw_os_error(code.saturating_neg()),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct R2oRouteFlowKey {
    family: u8,
    protocol: u8,
    source: r2k_core::addr::Address,
    destination: r2k_core::addr::Address,
    source_port: u16,
    destination_port: u16,
}

impl R2oRouteFlowKey {
    fn r2o_reverse(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            source_port: self.destination_port,
            destination_port: self.source_port,
            ..self
        }
    }
}

/// Сохраняет решение route-gate для обеих сторон ограниченного TCP/UDP-потока.
#[derive(Clone, Debug)]
pub struct R2oRoutedFlows {
    flows: HashMap<R2oRouteFlowKey, Instant>,
    next_expire: Instant,
}

impl Default for R2oRoutedFlows {
    fn default() -> Self {
        Self {
            flows: HashMap::with_capacity(R2O_ROUTE_FLOW_CAPACITY),
            next_expire: Instant::now(),
        }
    }
}

impl R2oRoutedFlows {
    /// Возвращает `true`, если пакет нужно оставить ядру без обработки датапатом.
    pub fn r2o_skip_packet(&mut self, packet: &[u8], route_mark: u32, now: Instant) -> bool {
        self.r2o_expire(now);
        let Some(key) = r2o_route_flow_key(packet) else {
            return route_mark != 0;
        };
        let reverse = key.r2o_reverse();
        if route_mark != 0 {
            self.r2o_insert(key, reverse, now);
            return true;
        }

        if !self.flows.contains_key(&key) {
            return false;
        }
        if key.protocol == 6 && r2o_is_new_syn(packet, key) {
            self.flows.remove(&key);
            self.flows.remove(&reverse);
            return false;
        }
        self.flows.insert(key, now);
        self.flows.insert(reverse, now);
        true
    }

    /// Убирает потоки без пакетов дольше заданного окна простоя.
    pub fn r2o_expire(&mut self, now: Instant) {
        if now < self.next_expire {
            return;
        }
        self.flows.retain(|_, last_seen| {
            now.saturating_duration_since(*last_seen) <= R2O_ROUTE_FLOW_IDLE
        });
        self.next_expire = now + Duration::from_secs(1);
    }

    fn r2o_insert(&mut self, key: R2oRouteFlowKey, reverse: R2oRouteFlowKey, now: Instant) {
        if !self.flows.contains_key(&key) && self.flows.len() + 2 > R2O_ROUTE_FLOW_CAPACITY {
            self.r2o_evict_oldest();
        }
        self.flows.insert(key, now);
        self.flows.insert(reverse, now);
    }

    fn r2o_evict_oldest(&mut self) {
        let Some(oldest) = self
            .flows
            .iter()
            .min_by_key(|(_, last_seen)| **last_seen)
            .map(|(key, _)| *key)
        else {
            return;
        };
        self.flows.remove(&oldest);
        self.flows.remove(&oldest.r2o_reverse());
    }
}

fn r2o_route_flow_key(packet: &[u8]) -> Option<R2oRouteFlowKey> {
    let view = r2k_core::packet::PacketView::parse(packet)?;
    let ports = packet.get(view.l4_offset..view.l4_offset.checked_add(4)?)?;
    Some(R2oRouteFlowKey {
        family: view.family,
        protocol: view.protocol,
        source: view.src,
        destination: view.dst,
        source_port: u16::from_be_bytes([ports[0], ports[1]]),
        destination_port: u16::from_be_bytes([ports[2], ports[3]]),
    })
}

fn r2o_is_new_syn(packet: &[u8], key: R2oRouteFlowKey) -> bool {
    if key.protocol != 6 {
        return false;
    }
    let Some(view) = r2k_core::packet::PacketView::parse(packet) else {
        return false;
    };
    packet
        .get(view.l4_offset + 13)
        .is_some_and(|flags| flags & 0x12 == 0x02)
}

/// Формирует запрос на чтение правил `fwmark` одного семейства.
pub fn r2o_route_rule_request(family: R2oRouteFamily, sequence: u32) -> Vec<u8> {
    let length = R2O_NLMSG_HEADER_LEN + R2O_FIB_RULE_HEADER_LEN;
    let mut message = vec![0; length];
    message[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    message[4..6].copy_from_slice(&R2O_RTM_GETRULE.to_ne_bytes());
    message[6..8].copy_from_slice(&(R2O_NLM_F_REQUEST | R2O_NLM_F_DUMP).to_ne_bytes());
    message[8..12].copy_from_slice(&sequence.to_ne_bytes());
    message[R2O_NLMSG_HEADER_LEN] = family.r2o_id();
    message
}

/// Формирует один поиск маршрута без метки и адреса источника.
pub fn r2o_route_lookup_request(family: R2oRouteFamily, sequence: u32) -> Vec<u8> {
    let probe = family.r2o_probe();
    let attribute_length = R2O_NLA_HEADER_LEN + probe.len();
    let length = R2O_NLMSG_HEADER_LEN + R2O_ROUTE_HEADER_LEN + attribute_length;
    let mut message = vec![0; length];
    message[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    message[4..6].copy_from_slice(&R2O_RTM_GETROUTE.to_ne_bytes());
    message[6..8].copy_from_slice(&R2O_NLM_F_REQUEST.to_ne_bytes());
    message[8..12].copy_from_slice(&sequence.to_ne_bytes());
    let route = R2O_NLMSG_HEADER_LEN;
    message[route] = family.r2o_id();
    message[route + 1] = (probe.len() * 8) as u8;
    let attribute = route + R2O_ROUTE_HEADER_LEN;
    message[attribute..attribute + 2].copy_from_slice(&(attribute_length as u16).to_ne_bytes());
    message[attribute + 2..attribute + 4].copy_from_slice(&R2O_RTA_DST.to_ne_bytes());
    message[attribute + R2O_NLA_HEADER_LEN..].copy_from_slice(probe);
    message
}

/// Разбирает часть дампа правил; несколько частей можно объединить до `done`.
pub fn r2o_route_parse_rules(bytes: &[u8]) -> Result<R2oRouteRuleBatch, R2oRouteParseError> {
    let messages = r2o_route_messages(bytes)?;
    let mut selectors = Vec::new();
    for message in messages {
        if message.kind == R2O_NLMSG_DONE {
            return Ok(R2oRouteRuleBatch {
                selectors,
                done: true,
            });
        }
        if message.kind == R2O_NLMSG_ERROR {
            return Err(R2oRouteParseError::Kernel(r2o_kernel_error(message.body)?));
        }
        if message.kind != R2O_RTM_NEWRULE || message.body.len() < R2O_FIB_RULE_HEADER_LEN {
            continue;
        }
        let family = match message.body[0] {
            2 => R2oRouteFamily::Ipv4,
            10 => R2oRouteFamily::Ipv6,
            _ => continue,
        };
        let flags = u32::from_ne_bytes(
            message.body[8..12]
                .try_into()
                .map_err(|_| R2oRouteParseError::Malformed)?,
        );
        let mut mark = None;
        let mut mask = None;
        for (kind, value) in r2o_route_attributes(message.body, R2O_FIB_RULE_HEADER_LEN)? {
            if value.len() < 4 {
                continue;
            }
            let value = u32::from_ne_bytes(
                value[..4]
                    .try_into()
                    .map_err(|_| R2oRouteParseError::Malformed)?,
            );
            match kind {
                R2O_FRA_FWMARK => mark = Some(value),
                R2O_FRA_FWMASK => mask = Some(value),
                _ => {}
            }
        }
        let Some(mark) = mark.or_else(|| mask.map(|_| 0)) else {
            continue;
        };
        let mask = mask.unwrap_or(if mark != 0 { u32::MAX } else { 0 });
        if mask == 0 || flags & R2O_FIB_RULE_INVERT != 0 {
            continue;
        }
        selectors.push(R2oFwSelector {
            mark: mark & mask,
            mask,
            family,
        });
    }
    Ok(R2oRouteRuleBatch {
        selectors,
        done: false,
    })
}

/// Разбирает ответ одного поиска маршрута, включая все устройства multipath.
pub fn r2o_route_parse_lookup(bytes: &[u8]) -> Result<R2oRouteLookup, R2oRouteParseError> {
    for message in r2o_route_messages(bytes)? {
        if message.kind == R2O_NLMSG_ERROR {
            return Err(R2oRouteParseError::Kernel(r2o_kernel_error(message.body)?));
        }
        if message.kind != R2O_RTM_NEWROUTE || message.body.len() < R2O_ROUTE_HEADER_LEN {
            continue;
        }
        if message.body[7] != R2O_RTN_UNICAST {
            return Ok(R2oRouteLookup::NoRoute);
        }
        let mut ifindices = Vec::new();
        for (kind, value) in r2o_route_attributes(message.body, R2O_ROUTE_HEADER_LEN)? {
            match kind {
                R2O_RTA_OIF if value.len() >= 4 => {
                    let ifindex = u32::from_ne_bytes(
                        value[..4]
                            .try_into()
                            .map_err(|_| R2oRouteParseError::Malformed)?,
                    );
                    r2o_route_add_ifindex(&mut ifindices, ifindex);
                }
                R2O_RTA_MULTIPATH => r2o_route_parse_multipath(value, &mut ifindices)?,
                _ => {}
            }
        }
        return Ok(R2oRouteLookup::Unicast(ifindices));
    }
    Ok(R2oRouteLookup::Pending)
}

/// Уведомления о правилах, маршрутах по умолчанию и повреждённые данные требуют обновления.
pub fn r2o_route_watch_relevant(bytes: &[u8]) -> bool {
    let Ok(messages) = r2o_route_messages(bytes) else {
        return true;
    };
    messages.iter().any(|message| {
        if matches!(message.kind, R2O_RTM_NEWRULE | R2O_RTM_DELRULE) {
            return true;
        }
        matches!(message.kind, R2O_RTM_NEWROUTE | R2O_RTM_DELROUTE)
            && (message.body.len() < R2O_ROUTE_HEADER_LEN || message.body[1] == 0)
    })
}

struct R2oNetlinkMessage<'a> {
    kind: u16,
    body: &'a [u8],
}

fn r2o_route_messages(bytes: &[u8]) -> Result<Vec<R2oNetlinkMessage<'_>>, R2oRouteParseError> {
    let mut messages = Vec::new();
    let mut offset = 0;
    while bytes.len() - offset >= R2O_NLMSG_HEADER_LEN {
        let remaining = &bytes[offset..];
        let length = usize::try_from(u32::from_ne_bytes(
            remaining[..4]
                .try_into()
                .map_err(|_| R2oRouteParseError::Malformed)?,
        ))
        .map_err(|_| R2oRouteParseError::Malformed)?;
        if !(R2O_NLMSG_HEADER_LEN..=remaining.len()).contains(&length) {
            return Err(R2oRouteParseError::Malformed);
        }
        let kind = u16::from_ne_bytes(
            remaining[4..6]
                .try_into()
                .map_err(|_| R2oRouteParseError::Malformed)?,
        );
        messages.push(R2oNetlinkMessage {
            kind,
            body: &remaining[R2O_NLMSG_HEADER_LEN..length],
        });
        let step = r2o_align4(length).ok_or(R2oRouteParseError::Malformed)?;
        if step > remaining.len() {
            if length == remaining.len() {
                offset = bytes.len();
                break;
            }
            return Err(R2oRouteParseError::Malformed);
        }
        offset += step;
    }
    if bytes.len() - offset >= 4 {
        return Err(R2oRouteParseError::Malformed);
    }
    Ok(messages)
}

fn r2o_kernel_error(body: &[u8]) -> Result<i32, R2oRouteParseError> {
    let code = body
        .get(..4)
        .ok_or(R2oRouteParseError::Malformed)
        .and_then(|bytes| {
            bytes
                .try_into()
                .map(i32::from_ne_bytes)
                .map_err(|_| R2oRouteParseError::Malformed)
        })?;
    Ok(code)
}

fn r2o_route_attributes(
    body: &[u8],
    mut offset: usize,
) -> Result<Vec<(u16, &[u8])>, R2oRouteParseError> {
    let mut attributes = Vec::new();
    while body.len().saturating_sub(offset) >= R2O_NLA_HEADER_LEN {
        let remaining = &body[offset..];
        let length = usize::from(u16::from_ne_bytes(
            remaining[..2]
                .try_into()
                .map_err(|_| R2oRouteParseError::Malformed)?,
        ));
        if !(R2O_NLA_HEADER_LEN..=remaining.len()).contains(&length) {
            return Err(R2oRouteParseError::Malformed);
        }
        let kind = u16::from_ne_bytes(
            remaining[2..4]
                .try_into()
                .map_err(|_| R2oRouteParseError::Malformed)?,
        ) & R2O_NLA_TYPE_MASK;
        attributes.push((kind, &remaining[R2O_NLA_HEADER_LEN..length]));
        let step = r2o_align4(length).ok_or(R2oRouteParseError::Malformed)?;
        if step > remaining.len() {
            if length == remaining.len() {
                offset = body.len();
                break;
            }
            return Err(R2oRouteParseError::Malformed);
        }
        offset += step;
    }
    if body.len().saturating_sub(offset) >= R2O_NLA_HEADER_LEN {
        return Err(R2oRouteParseError::Malformed);
    }
    Ok(attributes)
}

fn r2o_route_parse_multipath(
    bytes: &[u8],
    ifindices: &mut Vec<u32>,
) -> Result<(), R2oRouteParseError> {
    let mut offset = 0;
    while bytes.len().saturating_sub(offset) >= R2O_RTNEXTHOP_HEADER_LEN {
        let remaining = &bytes[offset..];
        let length = usize::from(u16::from_ne_bytes(
            remaining[..2]
                .try_into()
                .map_err(|_| R2oRouteParseError::Malformed)?,
        ));
        if !(R2O_RTNEXTHOP_HEADER_LEN..=remaining.len()).contains(&length) {
            return Err(R2oRouteParseError::Malformed);
        }
        let ifindex = u32::from_ne_bytes(
            remaining[4..8]
                .try_into()
                .map_err(|_| R2oRouteParseError::Malformed)?,
        );
        r2o_route_add_ifindex(ifindices, ifindex);
        let step = r2o_align4(length).ok_or(R2oRouteParseError::Malformed)?;
        if step > remaining.len() {
            if length == remaining.len() {
                offset = bytes.len();
                break;
            }
            return Err(R2oRouteParseError::Malformed);
        }
        offset += step;
    }
    if bytes.len().saturating_sub(offset) >= R2O_RTNEXTHOP_HEADER_LEN {
        return Err(R2oRouteParseError::Malformed);
    }
    Ok(())
}

fn r2o_route_add_ifindex(ifindices: &mut Vec<u32>, ifindex: u32) {
    if ifindex != 0 && !ifindices.contains(&ifindex) {
        ifindices.push(ifindex);
    }
}

fn r2o_align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r2o_packet(
        outbound: bool,
        mark: Option<u32>,
        output_ifindex: Option<u32>,
    ) -> R2oRoutePacket {
        R2oRoutePacket {
            family: R2oRouteFamily::Ipv4,
            outbound,
            mark,
            probe_mark: 0x2e,
            datapath_mark: 0x2d,
            output_ifindex,
        }
    }

    #[test]
    fn r2o_метки_fwmark_учитывают_маску_семейство_и_неизвестные_правила() {
        let mut gate = R2oRouteGate::default();
        assert!(gate.r2o_mark_is_routed(R2oRouteFamily::Ipv4, 0x1234));
        assert!(!gate.r2o_mark_is_routed(R2oRouteFamily::Ipv4, 0));

        gate.r2o_set_rules(
            R2oRouteFamily::Ipv4,
            vec![R2oFwSelector {
                mark: 0x200,
                mask: u32::MAX,
                family: R2oRouteFamily::Ipv4,
            }],
        );
        gate.r2o_set_rules(
            R2oRouteFamily::Ipv6,
            vec![R2oFwSelector {
                mark: 0x100,
                mask: 0xff00,
                family: R2oRouteFamily::Ipv6,
            }],
        );
        assert!(gate.r2o_mark_is_routed(R2oRouteFamily::Ipv4, 0x200));
        assert!(!gate.r2o_mark_is_routed(R2oRouteFamily::Ipv4, 0x201));
        assert!(gate.r2o_mark_is_routed(R2oRouteFamily::Ipv6, 0x1ff));
        assert!(!gate.r2o_mark_is_routed(R2oRouteFamily::Ipv6, 0x2ff));
        assert!(gate.r2o_mark_is_routed(R2oRouteFamily::Ipv4, R2O_ROUTE_OTHER_DEV));
    }

    #[test]
    fn r2o_политика_отделяет_чужие_потоки_и_сохраняет_свои_метки() {
        let mut gate = R2oRouteGate::default();
        gate.r2o_set_rules(
            R2oRouteFamily::Ipv4,
            vec![R2oFwSelector {
                mark: 0x100,
                mask: 0xff00,
                family: R2oRouteFamily::Ipv4,
            }],
        );
        gate.r2o_set_policy(Some(R2oRoutePolicy::new(true, 0x500, 0xff00)));
        assert_eq!(
            gate.r2o_route_mark(r2o_packet(true, Some(0x5a5), Some(4))),
            0
        );
        assert_eq!(
            gate.r2o_route_mark(r2o_packet(true, Some(0x123), Some(4))),
            R2O_ROUTE_OUTSIDE
        );
        assert_eq!(
            gate.r2o_route_mark(r2o_packet(true, None, Some(4))),
            R2O_ROUTE_OUTSIDE
        );
        assert_eq!(
            gate.r2o_route_mark(r2o_packet(true, Some(0x2e), Some(4))),
            0
        );
        assert_eq!(
            gate.r2o_route_mark(r2o_packet(true, Some(0x2d), Some(4))),
            0
        );

        gate.r2o_set_policy(Some(R2oRoutePolicy::new(false, 0, 0)));
        assert_eq!(
            gate.r2o_route_mark(r2o_packet(true, Some(0x500), Some(4))),
            R2O_ROUTE_OUTSIDE
        );
        assert_eq!(
            gate.r2o_route_mark(r2o_packet(true, Some(0x2e), Some(4))),
            0
        );
        assert!(gate.r2o_mark_is_routed(R2oRouteFamily::Ipv4, R2O_ROUTE_OUTSIDE));
    }

    #[test]
    fn r2o_устройства_по_умолчанию_включают_multipath_и_не_затрагивают_ответы() {
        let mut gate = R2oRouteGate::default();
        assert_eq!(gate.r2o_route_mark(r2o_packet(true, None, Some(9))), 0);
        gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, Some(vec![5, 8, 8, 0]));
        assert_eq!(gate.r2o_route_mark(r2o_packet(true, None, Some(5))), 0);
        assert_eq!(gate.r2o_route_mark(r2o_packet(true, None, Some(8))), 0);
        assert_eq!(
            gate.r2o_route_mark(r2o_packet(true, None, Some(9))),
            R2O_ROUTE_OTHER_DEV
        );
        assert_eq!(gate.r2o_route_mark(r2o_packet(false, None, Some(9))), 0);
        gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, Some(Vec::new()));
        assert_eq!(
            gate.r2o_route_mark(r2o_packet(true, None, Some(5))),
            R2O_ROUTE_OTHER_DEV
        );
        gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, None);
        assert_eq!(gate.r2o_route_mark(r2o_packet(true, None, Some(9))), 0);
    }

    #[test]
    fn r2o_запросы_содержат_семейство_последовательность_и_адрес_поиска() {
        let rules = r2o_route_rule_request(R2oRouteFamily::Ipv6, 17);
        assert_eq!(rules.len(), 28);
        assert_eq!(
            u16::from_ne_bytes(rules[4..6].try_into().unwrap()),
            R2O_RTM_GETRULE
        );
        assert_eq!(u16::from_ne_bytes(rules[6..8].try_into().unwrap()), 0x301);
        assert_eq!(u32::from_ne_bytes(rules[8..12].try_into().unwrap()), 17);
        assert_eq!(rules[16], 10);

        let route = r2o_route_lookup_request(R2oRouteFamily::Ipv4, 23);
        assert_eq!(route.len(), 36);
        assert_eq!(
            u16::from_ne_bytes(route[4..6].try_into().unwrap()),
            R2O_RTM_GETROUTE
        );
        assert_eq!(route[16], 2);
        assert_eq!(route[17], 32);
        assert_eq!(&route[32..], &[192, 0, 2, 1]);
    }

    #[test]
    fn r2o_разбор_правил_учитывает_маску_инверсию_и_завершение_дампа() {
        let mut body = vec![0; R2O_FIB_RULE_HEADER_LEN];
        body[0] = 2;
        r2o_test_attr(&mut body, R2O_FRA_FWMARK, &0x1234_u32.to_ne_bytes());
        r2o_test_attr(&mut body, R2O_FRA_FWMASK, &0xff00_u32.to_ne_bytes());
        let mut messages = r2o_test_message(R2O_RTM_NEWRULE, &body);

        let mut exact = vec![0; R2O_FIB_RULE_HEADER_LEN];
        exact[0] = 2;
        r2o_test_attr(&mut exact, R2O_FRA_FWMARK, &0x200_u32.to_ne_bytes());
        messages.extend(r2o_test_message(R2O_RTM_NEWRULE, &exact));

        let mut inverted = vec![0; R2O_FIB_RULE_HEADER_LEN];
        inverted[0] = 10;
        inverted[8..12].copy_from_slice(&R2O_FIB_RULE_INVERT.to_ne_bytes());
        r2o_test_attr(&mut inverted, R2O_FRA_FWMARK, &0x500_u32.to_ne_bytes());
        messages.extend(r2o_test_message(R2O_RTM_NEWRULE, &inverted));
        messages.extend(r2o_test_message(R2O_NLMSG_DONE, &[]));

        let batch = r2o_route_parse_rules(&messages).unwrap();
        assert!(batch.done);
        assert_eq!(batch.selectors.len(), 2);
        assert_eq!(batch.selectors[0].mark, 0x1200);
        assert_eq!(batch.selectors[0].mask, 0xff00);
        assert_eq!(batch.selectors[1].mask, u32::MAX);
    }

    #[test]
    fn r2o_разбор_маршрута_собирает_основной_и_multipath_интерфейсы() {
        let mut route = vec![0; R2O_ROUTE_HEADER_LEN];
        route[0] = 2;
        route[7] = R2O_RTN_UNICAST;
        r2o_test_attr(&mut route, R2O_RTA_OIF, &5_u32.to_ne_bytes());
        let mut multipath = Vec::new();
        r2o_test_hop(&mut multipath, 8);
        r2o_test_hop(&mut multipath, 5);
        r2o_test_hop(&mut multipath, 0);
        r2o_test_attr(&mut route, R2O_RTA_MULTIPATH, &multipath);
        let messages = r2o_test_message(R2O_RTM_NEWROUTE, &route);
        assert_eq!(
            r2o_route_parse_lookup(&messages).unwrap(),
            R2oRouteLookup::Unicast(vec![5, 8])
        );

        route[7] = 7;
        assert_eq!(
            r2o_route_parse_lookup(&r2o_test_message(R2O_RTM_NEWROUTE, &route)).unwrap(),
            R2oRouteLookup::NoRoute
        );
    }

    #[test]
    fn r2o_ошибки_и_повреждённые_сообщения_не_принимаются_за_пустые_маршруты() {
        assert_eq!(
            r2o_route_parse_rules(&[1, 2, 3, 4]),
            Err(R2oRouteParseError::Malformed)
        );
        assert_eq!(
            r2o_route_parse_lookup(&[1, 2, 3, 4]),
            Err(R2oRouteParseError::Malformed)
        );

        let error = r2o_test_message(R2O_NLMSG_ERROR, &(-22_i32).to_ne_bytes());
        assert_eq!(
            r2o_route_parse_lookup(&error),
            Err(R2oRouteParseError::Kernel(-22))
        );

        let mut bad_route = vec![0; R2O_ROUTE_HEADER_LEN];
        bad_route[7] = R2O_RTN_UNICAST;
        bad_route.extend_from_slice(&3_u16.to_ne_bytes());
        bad_route.extend_from_slice(&R2O_RTA_OIF.to_ne_bytes());
        let malformed = r2o_test_message(R2O_RTM_NEWROUTE, &bad_route);
        assert_eq!(
            r2o_route_parse_lookup(&malformed),
            Err(R2oRouteParseError::Malformed)
        );
    }

    #[test]
    fn r2o_уведомления_обновляют_состояние_только_для_правил_и_маршрутов_по_умолчанию() {
        let mut route = vec![0; R2O_ROUTE_HEADER_LEN];
        route[1] = 24;
        assert!(!r2o_route_watch_relevant(&r2o_test_message(
            R2O_RTM_NEWROUTE,
            &route
        )));
        route[1] = 0;
        assert!(r2o_route_watch_relevant(&r2o_test_message(
            R2O_RTM_NEWROUTE,
            &route
        )));
        assert!(r2o_route_watch_relevant(&r2o_test_message(
            R2O_RTM_DELRULE,
            &[]
        )));
        assert!(r2o_route_watch_relevant(&[0; 4]));
    }

    #[test]
    fn r2o_маршрутный_поток_пропускает_обе_стороны_сбрасывается_на_syn_и_истекает() {
        let mut flows = R2oRoutedFlows::default();
        let now = Instant::now();
        let client_syn = r2o_test_tcp([192, 0, 2, 1], [198, 51, 100, 2], 40_000, 443, 0x02);
        let server_syn_ack = r2o_test_tcp([198, 51, 100, 2], [192, 0, 2, 1], 443, 40_000, 0x12);
        let client_ack = r2o_test_tcp([192, 0, 2, 1], [198, 51, 100, 2], 40_000, 443, 0x10);

        assert!(flows.r2o_skip_packet(&client_syn, R2O_ROUTE_OTHER_DEV, now));
        assert!(flows.r2o_skip_packet(&server_syn_ack, 0, now + Duration::from_millis(1)));
        assert!(flows.r2o_skip_packet(&client_ack, 0, now + Duration::from_millis(2)));
        assert!(!flows.r2o_skip_packet(&client_syn, 0, now + Duration::from_millis(3)));
        assert!(!flows.r2o_skip_packet(&server_syn_ack, 0, now + Duration::from_millis(4)));

        assert!(flows.r2o_skip_packet(&client_syn, R2O_ROUTE_OTHER_DEV, now));
        flows.r2o_expire(now + R2O_ROUTE_FLOW_IDLE + Duration::from_secs(1));
        assert!(!flows.r2o_skip_packet(
            &server_syn_ack,
            0,
            now + R2O_ROUTE_FLOW_IDLE + Duration::from_secs(1)
        ));
    }

    #[test]
    fn r2o_некорректный_пакет_с_маршрутной_меткой_пропускается_без_состояния() {
        let mut flows = R2oRoutedFlows::default();
        let now = Instant::now();
        assert!(flows.r2o_skip_packet(&[0; 12], R2O_ROUTE_OUTSIDE, now));
        assert!(!flows.r2o_skip_packet(&[0; 12], 0, now));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn r2o_монитор_читает_правила_и_маршрут_текущего_ядра() {
        let mut monitor = R2oRouteMonitor::default();
        let _watch_opened = monitor.r2o_open_watch().is_ok();
        let mut gate = R2oRouteGate::default();
        let errors = monitor.r2o_refresh(&mut gate);
        if errors
            .iter()
            .any(|error| error.contains("Operation not supported (os error 95)"))
        {
            eprintln!("текущее ядро не предоставляет чтение rtnetlink для правил маршрутизации");
            return;
        }
        assert!(
            errors.iter().all(|error| {
                !error.starts_with("правила Ipv4:") && !error.starts_with("маршрут Ipv4:")
            }),
            "ошибка чтения обязательного IPv4 rtnetlink: {errors:?}"
        );
        assert!(gate.r2o_rules_v4.is_some());
    }

    fn r2o_test_message(kind: u16, body: &[u8]) -> Vec<u8> {
        let length = R2O_NLMSG_HEADER_LEN + body.len();
        let mut message = vec![0; r2o_align4(length).unwrap()];
        message[..4].copy_from_slice(&(length as u32).to_ne_bytes());
        message[4..6].copy_from_slice(&kind.to_ne_bytes());
        message[R2O_NLMSG_HEADER_LEN..length].copy_from_slice(body);
        message
    }

    fn r2o_test_attr(body: &mut Vec<u8>, kind: u16, value: &[u8]) {
        let length = R2O_NLA_HEADER_LEN + value.len();
        body.extend_from_slice(&(length as u16).to_ne_bytes());
        body.extend_from_slice(&kind.to_ne_bytes());
        body.extend_from_slice(value);
        body.resize(r2o_align4(body.len()).unwrap(), 0);
    }

    fn r2o_test_hop(bytes: &mut Vec<u8>, ifindex: u32) {
        let offset = bytes.len();
        bytes.resize(offset + R2O_RTNEXTHOP_HEADER_LEN, 0);
        bytes[offset..offset + 2].copy_from_slice(&(R2O_RTNEXTHOP_HEADER_LEN as u16).to_ne_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&ifindex.to_ne_bytes());
    }

    fn r2o_test_tcp(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet
    }
}
