//! Сопоставление меток маршрутизации и выходных интерфейсов для потоков R2O.

use r2k_core::addr::Address;
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
/// C `D2K_ROUTEMARK_OIF_MAX`: устройства сверх 16 отбрасываются, а не
/// превращают чтение маршрута в ошибку.
const R2O_ROUTEMARK_OIF_MAX: usize = 16;
const R2O_LOOKUP_ROUNDS: usize = 4;
const R2O_LOOKUP_BUFFER: usize = 8192;
const R2O_DUMP_ROUNDS: usize = 4096;
const R2O_DUMP_BUFFER: usize = 32768;

/// C `routes_refresh` (`d2kd.c:302-370`): состояние одной из четырёх частей.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum R2oRoutePartStatus {
    /// Часть не прочитана; прежнее значение сохраняется.
    #[default]
    Unread,
    /// Прочитана (маршрут может быть и пустым).
    Read,
    /// Маршрут есть, но интерфейса в ответе нет: проверка выхода выключена.
    NoDevice,
}

/// C `d2k_routemark_status`: итог merge/refresh по семействам.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct R2oRouteRefreshStatus {
    pub v4_ok: bool,
    pub v6_ok: bool,
    pub found: usize,
    pub truncated: bool,
    pub changed: bool,
    /// C `routes4_ok/routes6_ok`: 0 — не прочитан, 1 — прочитан,
    /// 2 — маршрут без интерфейса (только проверка метки).
    pub v4_route: R2oRoutePartStatus,
    pub v6_route: R2oRoutePartStatus,
    /// Первый текст ошибки, как C `d2k_routemark_load`.
    pub first_error: Option<String>,
    /// Все четыре части (правила/маршруты v4/v6) упали.
    pub all_failed: bool,
}

/// C `routes_refresh`: четыре части в порядке логов C.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oRoutesPart {
    RulesV4,
    RulesV6,
    RouteV4,
    RouteV6,
}

/// События C `routes_refresh`; текст с префиксом `d2kd:` формирует `main.rs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oRoutesChange {
    RefreshFailed {
        first: bool,
    },
    RefreshRecovered,
    PartAgain(R2oRoutesPart),
    PartNoDevice(R2oRoutesPart),
    PartUnread(R2oRoutesPart),
    Truncated {
        found: usize,
    },
    /// Смена применена сразу; строка печатается не чаще раза в 600 с.
    Changed {
        changes: u32,
    },
}

/// C `ROUTES_QUIET_NS = 600 с`.
pub const R2O_ROUTES_QUIET: Duration = Duration::from_secs(600);

/// Состояние лога `routes_refresh` между обновлениями.
#[derive(Clone, Debug)]
pub struct R2oRoutesRefreshLog {
    last_fail: bool,
    last: [R2oRoutePartStatus; 4],
    last_truncated: bool,
    first: bool,
    changes: u32,
    quiet_until: Option<Instant>,
}

impl Default for R2oRoutesRefreshLog {
    fn default() -> Self {
        // C: last_v4=last_v6=last_r4=last_r6=1, first=1, last_trunc=0.
        Self {
            last_fail: false,
            last: [
                R2oRoutePartStatus::Read,
                R2oRoutePartStatus::Read,
                R2oRoutePartStatus::Read,
                R2oRoutePartStatus::Read,
            ],
            last_truncated: false,
            first: true,
            changes: 0,
            quiet_until: None,
        }
    }
}

impl R2oRoutesRefreshLog {
    /// C `routes_refresh`: вернуть события в порядке печати C.
    pub fn r2o_observe(
        &mut self,
        status: &R2oRouteRefreshStatus,
        now: Instant,
    ) -> Vec<R2oRoutesChange> {
        let mut events = Vec::new();
        if status.all_failed {
            if !self.last_fail {
                events.push(R2oRoutesChange::RefreshFailed { first: self.first });
            }
            self.last_fail = true;
            self.first = false;
            return events;
        }
        if self.last_fail {
            events.push(R2oRoutesChange::RefreshRecovered);
        }
        self.last_fail = false;
        self.first = false;

        let now_parts = [
            if status.v4_ok {
                R2oRoutePartStatus::Read
            } else {
                R2oRoutePartStatus::Unread
            },
            if status.v6_ok {
                R2oRoutePartStatus::Read
            } else {
                R2oRoutePartStatus::Unread
            },
            status.v4_route,
            status.v6_route,
        ];
        let parts = [
            R2oRoutesPart::RulesV4,
            R2oRoutesPart::RulesV6,
            R2oRoutesPart::RouteV4,
            R2oRoutesPart::RouteV6,
        ];
        for index in 0..4 {
            if now_parts[index] == self.last[index] {
                continue;
            }
            let event = match now_parts[index] {
                R2oRoutePartStatus::NoDevice => R2oRoutesChange::PartNoDevice(parts[index]),
                R2oRoutePartStatus::Read => R2oRoutesChange::PartAgain(parts[index]),
                R2oRoutePartStatus::Unread => R2oRoutesChange::PartUnread(parts[index]),
            };
            events.push(event);
            self.last[index] = now_parts[index];
        }
        if status.truncated != self.last_truncated {
            if status.truncated {
                events.push(R2oRoutesChange::Truncated {
                    found: status.found,
                });
            }
            self.last_truncated = status.truncated;
        }
        if status.changed {
            self.changes = self.changes.saturating_add(1);
        }
        if self.changes != 0 && self.quiet_until.is_none_or(|until| now >= until) {
            events.push(R2oRoutesChange::Changed {
                changes: self.changes,
            });
            self.changes = 0;
            self.quiet_until = Some(now + R2O_ROUTES_QUIET);
        }
        events
    }
}

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
    ///
    /// Возвращает C `d2k_routemark_set.changed`: изменились ли длина или
    /// тройки mark/mask/family. Отсутствие чтения (`None`) не считается
    /// изменением само по себе — как и в C, где `changed` сравнивает только
    /// `n` и содержимое.
    pub fn r2o_set_rules(&mut self, family: R2oRouteFamily, mut rules: Vec<R2oFwSelector>) -> bool {
        rules.retain(|rule| rule.family == family);
        for rule in &mut rules {
            rule.mark &= rule.mask;
        }
        let slot = match family {
            R2oRouteFamily::Ipv4 => &mut self.r2o_rules_v4,
            R2oRouteFamily::Ipv6 => &mut self.r2o_rules_v6,
        };
        let changed = match slot.as_deref() {
            Some(previous) => previous != rules.as_slice(),
            None => !rules.is_empty(),
        };
        *slot = Some(rules);
        changed
    }

    /// Число сохранённых правил семейства (для `merge.found`).
    pub fn r2o_rule_count(&self, family: R2oRouteFamily) -> usize {
        match family {
            R2oRouteFamily::Ipv4 => self.r2o_rules_v4.as_ref().map_or(0, Vec::len),
            R2oRouteFamily::Ipv6 => self.r2o_rules_v6.as_ref().map_or(0, Vec::len),
        }
    }

    /// Задаёт устройства маршрута по умолчанию; `None` означает, что чтение неизвестно.
    ///
    /// Возвращает C `d2k_routemark_set_oifs/clear_oifs.changed`: для `None`
    /// это факт наличия прежнего чтения, для `Some` — отличие после
    /// дедупликации от прежнего списка.
    pub fn r2o_set_default_ifindices(
        &mut self,
        family: R2oRouteFamily,
        ifindices: Option<Vec<u32>>,
    ) -> bool {
        let ifindices = ifindices.map(|values| {
            let mut unique = Vec::with_capacity(values.len().min(R2O_ROUTEMARK_OIF_MAX));
            for value in values {
                if value != 0 && unique.len() < R2O_ROUTEMARK_OIF_MAX && !unique.contains(&value) {
                    unique.push(value);
                }
            }
            unique
        });
        let slot = match family {
            R2oRouteFamily::Ipv4 => &mut self.r2o_default_ifindices_v4,
            R2oRouteFamily::Ipv6 => &mut self.r2o_default_ifindices_v6,
        };
        let changed = match (slot.as_deref(), ifindices.as_deref()) {
            (None, None) => false,
            (None, Some(_)) | (Some(_), None) => true,
            (Some(previous), Some(current)) => previous != current,
        };
        *slot = ifindices;
        changed
    }

    /// C `d2k_routemark_describe`: `0xmark/0xmask v4, ...` или `нет`.
    ///
    /// `cap` — размер буфера C; возвращается не больше `cap - 1` байт.
    /// Нулевой `cap` даёт пустую строку, как и C-функция.
    pub fn r2o_describe_rules(&self, cap: usize) -> String {
        if cap == 0 {
            return String::new();
        }
        let mut described = String::new();
        for rules in [self.r2o_rules_v4.as_deref(), self.r2o_rules_v6.as_deref()]
            .into_iter()
            .flatten()
        {
            for rule in rules {
                if !described.is_empty() {
                    described.push_str(", ");
                }
                described.push_str(&format!(
                    "0x{:x}/0x{:x} {}",
                    rule.mark,
                    rule.mask,
                    if rule.family == R2oRouteFamily::Ipv6 {
                        "v6"
                    } else {
                        "v4"
                    }
                ));
            }
        }
        if described.is_empty() {
            described.push_str("нет");
        }
        described.truncate(cap - 1);
        described
    }

    /// Возвращает объединённые выходные интерфейсы известных IPv4/IPv6 маршрутов.
    pub fn r2o_egress_ifindices(&self) -> Option<Vec<u32>> {
        let mut ifindices = Vec::new();
        for values in [
            self.r2o_default_ifindices_v4.as_deref(),
            self.r2o_default_ifindices_v6.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            for ifindex in values {
                if *ifindex != 0 && !ifindices.contains(ifindex) {
                    ifindices.push(*ifindex);
                }
            }
        }
        (!ifindices.is_empty()).then_some(ifindices)
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

    /// C `d2k_routemark_client`: чужая метка, если она направлена правилом.
    ///
    /// Нет метки/ноль/свои probe и datapath — 0. Иначе routed ? mark : 0.
    /// Гейт политики вызывается отдельно, поэтому функция не смотрит на
    /// outbound и output ifindex.
    pub fn r2o_client_mark(
        &self,
        family: R2oRouteFamily,
        mark: Option<u32>,
        probe_mark: u32,
        datapath_mark: u32,
    ) -> u32 {
        let Some(mark) = mark else {
            return 0;
        };
        if mark == 0 || mark == probe_mark || mark == datapath_mark {
            return 0;
        }
        if self.r2o_mark_is_routed(family, mark) {
            mark
        } else {
            0
        }
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

        let client = self.r2o_client_mark(
            packet.family,
            packet.mark,
            packet.probe_mark,
            packet.datapath_mark,
        );
        if client != 0 {
            return client;
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
                // C `d2k_routemark_watch_drain`: любая иная ошибка recv
                // возвращает уже накопленный `any`, а не Err.
                Some(libc::EAGAIN) | _ => return Ok(changed),
            }
        }
        Ok(true)
    }

    /// Обновляет семейства независимо и сохраняет прежние данные при ошибке.
    pub fn r2o_refresh(&mut self, gate: &mut R2oRouteGate) -> Vec<String> {
        self.r2o_refresh_with_status(gate).0
    }

    /// C `d2k_routemark_load/merge`: ошибки плюс `found/truncated/changed`
    /// и независимые `v4_ok/v6_ok`.
    ///
    /// `found` считает правила ДО усечения (как C `found += n4/n6`), а
    /// `truncated` — `found > 32`.
    pub fn r2o_refresh_with_status(
        &mut self,
        gate: &mut R2oRouteGate,
    ) -> (Vec<String>, R2oRouteRefreshStatus) {
        let previous4 = gate.r2o_rule_count(R2oRouteFamily::Ipv4);
        let previous6 = gate.r2o_rule_count(R2oRouteFamily::Ipv6);
        let mut errors = Vec::new();
        let mut changed = false;
        let mut v4_ok = false;
        let mut found4 = 0;
        match self.r2o_dump_rules(R2oRouteFamily::Ipv4) {
            Ok((rules, found)) => {
                v4_ok = true;
                found4 = found;
                changed |= gate.r2o_set_rules(R2oRouteFamily::Ipv4, rules);
            }
            Err(error) => errors.push(format!("правила Ipv4: {error}")),
        }
        let mut v6_ok = false;
        let mut found6 = 0;
        match self.r2o_dump_rules(R2oRouteFamily::Ipv6) {
            Ok((rules, found)) => {
                v6_ok = true;
                found6 = found;
                changed |= gate.r2o_set_rules(R2oRouteFamily::Ipv6, rules);
            }
            Err(error) => errors.push(format!("правила Ipv6: {error}")),
        }
        let status =
            r2o_route_merge_status(previous4, previous6, v4_ok, found4, v6_ok, found6, changed);
        let mut lookup4_ok = false;
        let mut lookup6_ok = false;
        let mut route4 = R2oRoutePartStatus::Unread;
        let mut route6 = R2oRoutePartStatus::Unread;
        for family in [R2oRouteFamily::Ipv4, R2oRouteFamily::Ipv6] {
            let mut lookup_ok = false;
            let mut route_status = R2oRoutePartStatus::Unread;
            match self.r2o_lookup_default(family) {
                Ok(R2oRouteLookup::Unicast(ifindices)) if ifindices.is_empty() => {
                    // C `lookup_route`: маршрут без устройства — rc=2.
                    lookup_ok = true;
                    route_status = R2oRoutePartStatus::NoDevice;
                    gate.r2o_set_default_ifindices(family, None);
                }
                Ok(R2oRouteLookup::Unicast(ifindices)) => {
                    lookup_ok = true;
                    route_status = R2oRoutePartStatus::Read;
                    gate.r2o_set_default_ifindices(family, Some(ifindices));
                }
                Ok(R2oRouteLookup::NoRoute) => {
                    // C rc=3: известный пустой список устройств.
                    lookup_ok = true;
                    route_status = R2oRoutePartStatus::Read;
                    gate.r2o_set_default_ifindices(family, Some(Vec::new()));
                }
                Ok(R2oRouteLookup::Pending) => errors.push(format!(
                    "маршрут {family:?}: ядро не ответило на одиночный поиск"
                )),
                Err(error) => errors.push(format!("маршрут {family:?}: {error}")),
            }
            match family {
                R2oRouteFamily::Ipv4 => {
                    lookup4_ok = lookup_ok;
                    route4 = route_status;
                }
                R2oRouteFamily::Ipv6 => {
                    lookup6_ok = lookup_ok;
                    route6 = route_status;
                }
            }
        }
        let mut status = status;
        status.v4_route = route4;
        status.v6_route = route6;
        status.first_error = errors.first().cloned();
        status.all_failed = r2o_route_all_failed(v4_ok, v6_ok, lookup4_ok, lookup6_ok);
        (errors, status)
    }

    fn r2o_dump_rules(
        &mut self,
        family: R2oRouteFamily,
    ) -> std::io::Result<(Vec<R2oFwSelector>, usize)> {
        let mut selectors = Vec::new();
        let mut found = 0_usize;
        let sequence = self.r2o_next_sequence();
        let request = r2o_route_rule_request(family, sequence);
        self.r2o_receive_request(request, R2O_DUMP_BUFFER, R2O_DUMP_ROUNDS, |bytes| {
            let batch = match r2o_route_parse_rules(bytes) {
                Ok(batch) => batch,
                // C `dump` (`routemark_nl.c:48-56`) считает и
                // `-EAFNOSUPPORT`, и `-EOPNOTSUPP` пустым успехом для любого
                // семейства, а не только для IPv6.
                Err(R2oRouteParseError::Kernel(code)) if r2o_rules_error_is_empty_success(code) => {
                    selectors.clear();
                    found = 0;
                    return Ok(true);
                }
                Err(error) => return Err(r2o_parse_io_error(error)),
            };
            // C `merge.found` считает правила до усечения.
            found = found.saturating_add(batch.selectors.len());
            let mut truncated = false;
            r2o_extend_rule_selectors(&mut selectors, batch.selectors, &mut truncated);
            let _ = truncated;
            Ok(batch.done)
        })?;
        Ok((selectors, found))
    }

    fn r2o_lookup_default(&mut self, family: R2oRouteFamily) -> std::io::Result<R2oRouteLookup> {
        let mut result = R2oRouteLookup::Pending;
        let sequence = self.r2o_next_sequence();
        let request = r2o_route_lookup_request(family, sequence);
        self.r2o_receive_request(request, R2O_LOOKUP_BUFFER, R2O_LOOKUP_ROUNDS, |bytes| {
            result = match r2o_route_parse_lookup(bytes) {
                Ok(result) => result,
                Err(R2oRouteParseError::Kernel(-97 | -100 | -101 | -113)) => {
                    R2oRouteLookup::NoRoute
                }
                Err(error) => return Err(r2o_parse_io_error(error)),
            };
            Ok(!matches!(result, R2oRouteLookup::Pending))
        })?;
        Ok(result)
    }

    fn r2o_receive_request(
        &mut self,
        request: Vec<u8>,
        buffer_len: usize,
        rounds: usize,
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

        let mut bytes = vec![0_u8; buffer_len];
        for _ in 0..rounds {
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
    /// C `s->routed_flows`: кумулятивное число впервые помеченных потоков.
    routed_flows: u64,
}

impl Default for R2oRoutedFlows {
    fn default() -> Self {
        Self {
            flows: HashMap::with_capacity(R2O_ROUTE_FLOW_CAPACITY),
            next_expire: Instant::now(),
            routed_flows: 0,
        }
    }
}

impl R2oRoutedFlows {
    /// C `d2k_session_routed_flows`: кумулятивное число впервые помеченных
    /// потоков. Не уменьшается при истечении или новом SYN.
    pub fn routed_flows(&self) -> u64 {
        self.routed_flows
    }

    /// Текущее число записей в таблице (обе стороны потока).
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// C `fl->routed`: поток уже пропущен ядром по метке маршрутизатора.
    /// Ключ канонический (low/high), поэтому проверяются оба направления.
    pub fn r2o_is_routed_key(&self, key: &[u8; r2k_core::control::KEY_LEN]) -> bool {
        let Some(low) = r2o_route_key_address(key[0], key.get(1..17)) else {
            return false;
        };
        let Some(high) = r2o_route_key_address(key[0], key.get(17..33)) else {
            return false;
        };
        let forward = R2oRouteFlowKey {
            family: key[0],
            protocol: key[37],
            source: low,
            destination: high,
            source_port: u16::from_be_bytes([key[33], key[34]]),
            destination_port: u16::from_be_bytes([key[35], key[36]]),
        };
        self.flows.contains_key(&forward) || self.flows.contains_key(&forward.r2o_reverse())
    }

    /// Возвращает `true`, если пакет нужно оставить ядру без обработки датапатом.
    pub fn r2o_skip_packet(&mut self, packet: &[u8], route_mark: u32, now: Instant) -> bool {
        self.r2o_expire(now);
        // C `routed_flow`: только целый не-фрагмент TCP/UDP с 4 байтами L4.
        // Иначе метка не делает пакет «нашим» — он идёт обычным путём.
        // `PacketView::parse` сам отвергает фрагменты, поэтому проверяем
        // заголовок до него.
        match packet.first().map(|first| first >> 4) {
            Some(4) if packet.len() >= 20 => {
                if !matches!(packet[9], 6 | 17)
                    || u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0
                {
                    return false;
                }
            }
            Some(6) if packet.len() >= 40 => {
                if !matches!(packet[6], 6 | 17) {
                    return false;
                }
            }
            _ => return route_mark != 0,
        }
        let Some(view) = r2k_core::packet::PacketView::parse(packet) else {
            return route_mark != 0;
        };
        if !matches!(view.protocol, 6 | 17)
            || view.fragment & 0x1fff != 0
            || packet.len() < view.l4_offset.saturating_add(4)
        {
            return false;
        }
        let Some(key) = r2o_route_flow_key(packet) else {
            return false;
        };
        let reverse = key.r2o_reverse();
        if route_mark != 0 {
            if !self.flows.contains_key(&key) {
                self.routed_flows = self.routed_flows.wrapping_add(1);
            }
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

fn r2o_route_key_address(family: u8, bytes: Option<&[u8]>) -> Option<Address> {
    let bytes = bytes?;
    match family {
        4 => Some(Address::new(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes.get(..4)?).ok()?,
        )))),
        6 => Some(Address::new(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes.get(..16)?).ok()?,
        )))),
        _ => None,
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

/// C `d2k_routemark_merge`: найденное сверх `D2K_ROUTEMARK_MAX=32`
/// усекается, а не превращается в ошибку (`routemark.c:246-261`).
fn r2o_rules_error_is_empty_success(code: i32) -> bool {
    matches!(code, -97 | -95)
}

/// C `d2k_routemark_merge`: `found` считает новые правила для успешных
/// семейств и прежние — для упавших; `truncated` — превышение 32.
fn r2o_route_merge_status(
    previous4: usize,
    previous6: usize,
    v4_ok: bool,
    found4: usize,
    v6_ok: bool,
    found6: usize,
    changed: bool,
) -> R2oRouteRefreshStatus {
    let found = if v4_ok { found4 } else { previous4 } + if v6_ok { found6 } else { previous6 };
    R2oRouteRefreshStatus {
        v4_ok,
        v6_ok,
        found,
        truncated: found > R2O_ROUTE_RULE_CAPACITY,
        changed,
        ..R2oRouteRefreshStatus::default()
    }
}

/// C `d2k_routemark_load`: -1, если упали все четыре части.
fn r2o_route_all_failed(
    rules4_ok: bool,
    rules6_ok: bool,
    lookup4_ok: bool,
    lookup6_ok: bool,
) -> bool {
    !(rules4_ok || rules6_ok || lookup4_ok || lookup6_ok)
}

fn r2o_extend_rule_selectors(
    selectors: &mut Vec<R2oFwSelector>,
    batch: Vec<R2oFwSelector>,
    truncated: &mut bool,
) {
    let room = R2O_ROUTE_RULE_CAPACITY.saturating_sub(selectors.len());
    if batch.len() > room {
        *truncated = true;
    }
    selectors.extend(batch.into_iter().take(room));
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
            // C `routemark_parse` принимает любой family и кладёт его в
            // селектор; merge относит всё, кроме 10, к IPv4-набору.
            _ => R2oRouteFamily::Ipv4,
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
    // C `nl_error` (`routemark.c:49-51`): тело короче четырёх байт даёт 0,
    // после чего вызывающий всё равно отвергает ответ как неразобранный.
    let Some(bytes) = body.get(..4) else {
        return Ok(0);
    };
    bytes
        .try_into()
        .map(i32::from_ne_bytes)
        .map_err(|_| R2oRouteParseError::Malformed)
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
    // C `add_oif`: ноль пропускается, дубли не хранятся, а всё сверх
    // D2K_ROUTEMARK_OIF_MAX отбрасывается (счётчик C растёт, но копируется
    // только 16 значений). Ошибкой это не считается.
    if ifindex != 0 && ifindices.len() < R2O_ROUTEMARK_OIF_MAX && !ifindices.contains(&ifindex) {
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

    fn route_status(
        v4_ok: bool,
        v6_ok: bool,
        v4_route: R2oRoutePartStatus,
        v6_route: R2oRoutePartStatus,
    ) -> R2oRouteRefreshStatus {
        R2oRouteRefreshStatus {
            v4_ok,
            v6_ok,
            v4_route,
            v6_route,
            ..R2oRouteRefreshStatus::default()
        }
    }

    #[test]
    fn routes_refresh_log_повторяет_переходы_c() {
        use R2oRoutePartStatus::{NoDevice, Read, Unread};
        use R2oRoutesChange::{
            Changed, PartAgain, PartNoDevice, PartUnread, RefreshFailed, RefreshRecovered,
            Truncated,
        };
        use R2oRoutesPart::{RouteV4, RulesV4};

        let t0 = Instant::now();
        let mut log = R2oRoutesRefreshLog::default();

        // Первый полный отказ печатается один раз, с first=1.
        let mut failed = route_status(false, false, Unread, Unread);
        failed.all_failed = true;
        assert_eq!(
            log.r2o_observe(&failed, t0),
            vec![RefreshFailed { first: true }]
        );
        assert!(log.r2o_observe(&failed, t0).is_empty());

        // Восстановление.
        assert_eq!(
            log.r2o_observe(&route_status(true, true, Read, Read), t0),
            vec![RefreshRecovered]
        );

        // Части: unread -> again -> no-device -> again.
        assert_eq!(
            log.r2o_observe(&route_status(false, true, Unread, Read), t0),
            vec![PartUnread(RulesV4), PartUnread(RouteV4),]
        );
        assert_eq!(
            log.r2o_observe(&route_status(true, true, Read, Read), t0),
            vec![PartAgain(RulesV4), PartAgain(RouteV4)]
        );
        assert_eq!(
            log.r2o_observe(&route_status(true, true, NoDevice, Read), t0),
            vec![PartNoDevice(RouteV4)]
        );
        assert_eq!(
            log.r2o_observe(&route_status(true, true, Read, Read), t0),
            vec![PartAgain(RouteV4)]
        );

        // Усечение — один раз при появлении.
        let mut truncated = route_status(true, true, Read, Read);
        truncated.truncated = true;
        truncated.found = 33;
        assert_eq!(
            log.r2o_observe(&truncated, t0),
            vec![Truncated { found: 33 }]
        );
        assert!(log.r2o_observe(&truncated, t0).is_empty());
    }

    #[test]
    fn routes_refresh_quiet_окно_600_с_и_счётчик_смен_как_c() {
        use R2oRoutePartStatus::Read;
        use R2oRoutesChange::Changed;

        let t0 = Instant::now();
        let mut log = R2oRoutesRefreshLog::default();
        let mut status = route_status(true, true, Read, Read);
        assert!(log.r2o_observe(&status, t0).is_empty());

        status.changed = true;
        assert_eq!(log.r2o_observe(&status, t0), vec![Changed { changes: 1 }]);
        // Внутри окна смены применяются, но не печатаются.
        assert!(
            log.r2o_observe(&status, t0 + Duration::from_secs(1))
                .is_empty()
        );
        assert!(
            log.r2o_observe(&status, t0 + Duration::from_secs(2))
                .is_empty()
        );
        // Через 600 с печатается число смен, накопленных после прошлой строки.
        assert_eq!(
            log.r2o_observe(&status, t0 + R2O_ROUTES_QUIET),
            vec![Changed { changes: 3 }]
        );
        // Без новых смен строки нет.
        assert!(
            log.r2o_observe(&route_status(true, true, Read, Read), t0 + R2O_ROUTES_QUIET)
                .is_empty()
        );
    }

    #[test]
    fn route_nl_differential_matches_c() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        fn append(destination: &mut Vec<u8>, message: &[u8]) {
            destination.extend_from_slice(message);
        }

        let mut output = String::new();
        output.push_str(&format!(
            "request rules_v4 {}\n",
            hex(&r2o_route_rule_request(R2oRouteFamily::Ipv4, 7))
        ));
        output.push_str(&format!(
            "request rules_v6 {}\n",
            hex(&r2o_route_rule_request(R2oRouteFamily::Ipv6, 8))
        ));
        output.push_str(&format!(
            "request lookup_v4 {}\n",
            hex(&r2o_route_lookup_request(R2oRouteFamily::Ipv4, 9))
        ));
        output.push_str(&format!(
            "request lookup_v6 {}\n",
            hex(&r2o_route_lookup_request(R2oRouteFamily::Ipv6, 10))
        ));

        fn rule(mark: u32, mask: Option<u32>, flags: u32) -> Vec<u8> {
            let mut body = vec![0; R2O_FIB_RULE_HEADER_LEN];
            body[0] = 2;
            body[8..12].copy_from_slice(&flags.to_ne_bytes());
            r2o_test_attr(&mut body, R2O_FRA_FWMARK, &mark.to_ne_bytes());
            if let Some(mask) = mask {
                r2o_test_attr(&mut body, R2O_FRA_FWMASK, &mask.to_ne_bytes());
            }
            r2o_test_message(R2O_RTM_NEWRULE, &body)
        }
        fn print_rules(name: &str, bytes: &[u8], output: &mut String) {
            let (rc, found, kerr) = match r2o_route_parse_rules(bytes) {
                Ok(batch) => (i32::from(batch.done), batch.selectors, 0),
                Err(R2oRouteParseError::Kernel(code)) => (-1, Vec::new(), code),
                Err(R2oRouteParseError::Malformed) => (-1, Vec::new(), 0),
            };
            output.push_str(&format!(
                "rules {name} rc={rc} n={} kerr={kerr}",
                found.len()
            ));
            for (index, selector) in found.iter().take(2).enumerate() {
                output.push_str(&format!(
                    " mark{index}=0x{:x} mask{index}=0x{:x} family{index}={}",
                    selector.mark,
                    selector.mask,
                    if selector.family == R2oRouteFamily::Ipv6 {
                        10
                    } else {
                        2
                    }
                ));
            }
            output.push('\n');
        }
        fn print_lookup(name: &str, bytes: &[u8], output: &mut String) {
            let (rc, ifindices, kerr) = match r2o_route_parse_lookup(bytes) {
                Ok(R2oRouteLookup::Unicast(ifindices)) => (1, ifindices, 0),
                Ok(R2oRouteLookup::NoRoute) => (2, Vec::new(), 0),
                Ok(R2oRouteLookup::Pending) => (0, Vec::new(), 0),
                Err(R2oRouteParseError::Kernel(code)) => (-1, Vec::new(), code),
                Err(R2oRouteParseError::Malformed) => (-1, Vec::new(), 0),
            };
            let oifs = ifindices
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            output.push_str(&format!(
                "lookup {name} rc={rc} n={} kerr={kerr} oifs={oifs}\n",
                ifindices.len()
            ));
        }

        let mut buffer = Vec::new();
        append(&mut buffer, &rule(0x1234, Some(0xff00), 0));
        append(&mut buffer, &rule(0x200, None, 0));
        append(&mut buffer, &r2o_test_message(R2O_NLMSG_DONE, &[]));
        print_rules("two", &buffer, &mut output);

        let mut buffer = Vec::new();
        append(&mut buffer, &rule(0x1234, Some(0), 0));
        append(&mut buffer, &rule(0x500, Some(0xff), R2O_FIB_RULE_INVERT));
        append(&mut buffer, &r2o_test_message(R2O_NLMSG_DONE, &[]));
        print_rules("skip", &buffer, &mut output);

        let buffer = rule(0x1234, Some(0xff00), 0);
        print_rules("incomplete", &buffer, &mut output);

        let mut body = vec![0; R2O_FIB_RULE_HEADER_LEN];
        body[0] = 2;
        r2o_test_attr(&mut body, R2O_FRA_FWMASK, &0xff00_u32.to_ne_bytes());
        let mut buffer = r2o_test_message(R2O_RTM_NEWRULE, &body);
        append(&mut buffer, &r2o_test_message(R2O_NLMSG_DONE, &[]));
        print_rules("mask_only", &buffer, &mut output);

        let mut body = vec![0; R2O_FIB_RULE_HEADER_LEN];
        body[0] = 2;
        let mut wide = [0_u8; 8];
        wide[..4].copy_from_slice(&0x4321_u32.to_ne_bytes());
        r2o_test_attr(&mut body, R2O_FRA_FWMARK, &wide);
        let mut buffer = r2o_test_message(R2O_RTM_NEWRULE, &body);
        append(&mut buffer, &r2o_test_message(R2O_NLMSG_DONE, &[]));
        print_rules("wide_mark", &buffer, &mut output);

        let mut body = vec![0; R2O_FIB_RULE_HEADER_LEN + 4];
        body[0] = 2;
        body[R2O_FIB_RULE_HEADER_LEN..R2O_FIB_RULE_HEADER_LEN + 2]
            .copy_from_slice(&3_u16.to_ne_bytes());
        body[R2O_FIB_RULE_HEADER_LEN + 2..R2O_FIB_RULE_HEADER_LEN + 4]
            .copy_from_slice(&R2O_FRA_FWMARK.to_ne_bytes());
        let buffer = r2o_test_message(R2O_RTM_NEWRULE, &body);
        print_rules("malformed", &buffer, &mut output);

        let mut buffer = r2o_test_message(R2O_NLMSG_DONE, &[]);
        append(&mut buffer, &rule(0x1234, Some(0xff00), 0));
        print_rules("done_first", &buffer, &mut output);

        let mut truncated = vec![0; 17];
        truncated[..4].copy_from_slice(&32_u32.to_ne_bytes());
        truncated[4..6].copy_from_slice(&R2O_RTM_NEWRULE.to_ne_bytes());
        print_rules("truncated", &truncated, &mut output);

        let mut done_tail = r2o_test_message(R2O_NLMSG_DONE, &[]);
        done_tail.extend_from_slice(&[0; 3]);
        print_rules("done_tail", &done_tail, &mut output);

        let mut body = vec![0; R2O_FIB_RULE_HEADER_LEN + 8];
        body[0] = 2;
        body[R2O_FIB_RULE_HEADER_LEN..R2O_FIB_RULE_HEADER_LEN + 2]
            .copy_from_slice(&20_u16.to_ne_bytes());
        body[R2O_FIB_RULE_HEADER_LEN + 2..R2O_FIB_RULE_HEADER_LEN + 4]
            .copy_from_slice(&R2O_FRA_FWMARK.to_ne_bytes());
        let buffer = r2o_test_message(R2O_RTM_NEWRULE, &body);
        print_rules("bad_attr", &buffer, &mut output);

        let buffer = r2o_test_message(R2O_NLMSG_ERROR, &[0, 0]);
        print_rules("short_error", &buffer, &mut output);

        let error = r2o_test_message(R2O_NLMSG_ERROR, &(-22_i32).to_ne_bytes());
        print_rules("error", &error, &mut output);

        fn route_body(route_type: u8) -> Vec<u8> {
            let mut body = vec![0; R2O_ROUTE_HEADER_LEN];
            body[0] = 2;
            body[7] = route_type;
            body
        }
        let mut body = route_body(R2O_RTN_UNICAST);
        r2o_test_attr(&mut body, R2O_RTA_OIF, &5_u32.to_ne_bytes());
        let mut multipath = Vec::new();
        r2o_test_hop(&mut multipath, 8);
        r2o_test_hop(&mut multipath, 5);
        r2o_test_hop(&mut multipath, 0);
        r2o_test_attr(&mut body, R2O_RTA_MULTIPATH, &multipath);
        let message = r2o_test_message(R2O_RTM_NEWROUTE, &body);
        print_lookup("oif_multipath", &message, &mut output);

        let mut body = route_body(R2O_RTN_UNICAST);
        let mut multipath = Vec::new();
        for ifindex in 100..120 {
            r2o_test_hop(&mut multipath, ifindex);
        }
        r2o_test_attr(&mut body, R2O_RTA_MULTIPATH, &multipath);
        let message = r2o_test_message(R2O_RTM_NEWROUTE, &body);
        print_lookup("many_hops", &message, &mut output);

        let message = r2o_test_message(R2O_RTM_NEWROUTE, &route_body(R2O_RTN_UNICAST));
        print_lookup("no_device", &message, &mut output);
        let message = r2o_test_message(R2O_RTM_NEWROUTE, &route_body(7));
        print_lookup("unreachable", &message, &mut output);

        let mut body = route_body(R2O_RTN_UNICAST);
        let offset = body.len();
        body.resize(offset + 8, 0);
        body[offset..offset + 2].copy_from_slice(&4_u16.to_ne_bytes());
        body[offset + 2..offset + 4].copy_from_slice(&R2O_RTA_MULTIPATH.to_ne_bytes());
        let message = r2o_test_message(R2O_RTM_NEWROUTE, &body);
        print_lookup("bad_multipath", &message, &mut output);

        let mut body = route_body(R2O_RTN_UNICAST);
        let mut bad_hop = vec![0_u8; 8];
        bad_hop[..2].copy_from_slice(&4_u16.to_ne_bytes());
        r2o_test_attr(&mut body, R2O_RTA_MULTIPATH, &bad_hop);
        let message = r2o_test_message(R2O_RTM_NEWROUTE, &body);
        print_lookup("bad_hop", &message, &mut output);

        let mut body = route_body(R2O_RTN_UNICAST);
        r2o_test_attr(&mut body, R2O_RTA_MULTIPATH, &[]);
        let message = r2o_test_message(R2O_RTM_NEWROUTE, &body);
        print_lookup("empty_multipath", &message, &mut output);

        let done_only = r2o_test_message(R2O_NLMSG_DONE, &[]);
        print_lookup("done_only", &done_only, &mut output);

        let mut truncated = vec![0; 20];
        truncated[..4].copy_from_slice(&32_u32.to_ne_bytes());
        truncated[4..6].copy_from_slice(&R2O_RTM_NEWROUTE.to_ne_bytes());
        print_lookup("truncated", &truncated, &mut output);

        let short_error = r2o_test_message(R2O_NLMSG_ERROR, &[0, 0]);
        print_lookup("short_error", &short_error, &mut output);

        let error = r2o_test_message(R2O_NLMSG_ERROR, &(-101_i32).to_ne_bytes());
        print_lookup("error", &error, &mut output);

        let incomplete = r2o_test_message(R2O_RTM_NEWROUTE, &vec![0; 8]);
        print_lookup("incomplete", &incomplete, &mut output);

        let rule_message = r2o_test_message(R2O_RTM_NEWRULE, &[]);
        output.push_str(&format!(
            "watch rule={}\n",
            u8::from(r2o_route_watch_relevant(&rule_message))
        ));
        let default_route = r2o_test_message(R2O_RTM_NEWROUTE, &route_body(R2O_RTN_UNICAST));
        output.push_str(&format!(
            "watch default_route={}\n",
            u8::from(r2o_route_watch_relevant(&default_route))
        ));
        let mut other = route_body(R2O_RTN_UNICAST);
        other[1] = 24;
        let other_route = r2o_test_message(R2O_RTM_NEWROUTE, &other);
        output.push_str(&format!(
            "watch other_route={}\n",
            u8::from(r2o_route_watch_relevant(&other_route))
        ));
        output.push_str(&format!(
            "watch malformed={}\n",
            u8::from(r2o_route_watch_relevant(&[0; 3]))
        ));

        if let Ok(path) = std::env::var("R2O_ROUTE_NL_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains("rules two rc=1 n=2"));
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
    fn r2o_выходные_интерфейсы_объединяют_семейства_и_убирают_дубли() {
        let mut gate = R2oRouteGate::default();
        assert_eq!(gate.r2o_egress_ifindices(), None);
        gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, Some(vec![5, 8, 8, 0]));
        gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv6, Some(vec![8, 9]));
        assert_eq!(gate.r2o_egress_ifindices(), Some(vec![5, 8, 9]));
        gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, Some(Vec::new()));
        gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv6, Some(Vec::new()));
        assert_eq!(gate.r2o_egress_ifindices(), None);
    }

    #[test]
    fn r2o_устройства_маршрута_усекаются_до_16_как_c() {
        let mut gate = R2oRouteGate::default();
        gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, Some((1..21).collect()));
        assert_eq!(
            gate.r2o_egress_ifindices(),
            Some((1..=16).collect::<Vec<u32>>())
        );
        // Нули и дубли не занимают места в пределе 16; 8/9 уже есть в IPv4.
        gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv6, Some(vec![0, 0, 8, 8, 17]));
        assert_eq!(
            gate.r2o_egress_ifindices(),
            Some((1..=16).chain([17]).collect())
        );
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
    fn r2o_статус_merge_считает_found_до_усечения_как_c() {
        let status = r2o_route_merge_status(2, 1, true, 33, true, 0, true);
        assert_eq!(status.found, 33);
        assert!(status.truncated);
        assert!(status.v4_ok && status.v6_ok && status.changed);

        let status = r2o_route_merge_status(2, 1, false, 0, true, 2, true);
        assert_eq!(status.found, 4);
        assert!(!status.v4_ok && status.v6_ok);
        assert!(!status.truncated);

        let status = r2o_route_merge_status(1, 1, false, 0, false, 0, false);
        assert_eq!(status.found, 2);
        assert!(!status.truncated && !status.changed);
    }

    #[test]
    fn r2o_route_all_failed_matches_c() {
        assert!(r2o_route_all_failed(false, false, false, false));
        assert!(!r2o_route_all_failed(true, false, false, false));
        assert!(!r2o_route_all_failed(false, true, false, false));
        assert!(!r2o_route_all_failed(false, false, true, false));
        assert!(!r2o_route_all_failed(false, false, false, true));
    }

    #[test]
    fn r2o_разбор_правил_принимает_неизвестный_family_как_c() {
        let mut body = vec![0; R2O_FIB_RULE_HEADER_LEN];
        body[0] = 0;
        r2o_test_attr(&mut body, R2O_FRA_FWMARK, &0x33_u32.to_ne_bytes());
        let mut messages = r2o_test_message(R2O_RTM_NEWRULE, &body);
        messages.extend(r2o_test_message(R2O_NLMSG_DONE, &[]));
        let batch = r2o_route_parse_rules(&messages).unwrap();
        assert_eq!(batch.selectors.len(), 1);
        assert_eq!(batch.selectors[0].family, R2oRouteFamily::Ipv4);
        assert_eq!(batch.selectors[0].mark, 0x33);
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
    fn r2o_маршрутный_ключ_виден_по_каноническому_wire_key() {
        let mut flows = R2oRoutedFlows::default();
        let now = Instant::now();
        let client_syn = r2o_test_tcp([192, 0, 2, 1], [198, 51, 100, 2], 40_000, 443, 0x02);
        let server_syn_ack = r2o_test_tcp([198, 51, 100, 2], [192, 0, 2, 1], 443, 40_000, 0x12);
        let other_syn = r2o_test_tcp([192, 0, 2, 1], [198, 51, 100, 2], 40_001, 443, 0x02);
        let key = crate::capture::TcpFlowKey::from_packet(&client_syn)
            .unwrap()
            .wire_key();
        let reverse_key = crate::capture::TcpFlowKey::from_packet(&server_syn_ack)
            .unwrap()
            .wire_key();
        let other_key = crate::capture::TcpFlowKey::from_packet(&other_syn)
            .unwrap()
            .wire_key();
        assert!(!flows.r2o_is_routed_key(&key));
        assert!(flows.r2o_skip_packet(&client_syn, R2O_ROUTE_OTHER_DEV, now));
        assert!(flows.r2o_is_routed_key(&key));
        assert!(flows.r2o_is_routed_key(&reverse_key));
        assert!(!flows.r2o_is_routed_key(&other_key));
        // Новый SYN снимает метку — C сбрасывает `fl->routed`.
        assert!(!flows.r2o_skip_packet(&client_syn, 0, now + Duration::from_millis(1)));
        assert!(
            !flows.r2o_is_routed_key(&key),
            "новый SYN без метки — новое соединение"
        );
    }

    #[test]
    fn r2o_маршрутная_метка_не_берёт_фрагменты_и_чужие_протоколы_как_c() {
        let mut flows = R2oRoutedFlows::default();
        let now = Instant::now();
        let mut fragment = r2o_test_tcp([192, 0, 2, 1], [198, 51, 100, 2], 40_000, 443, 0x02);
        fragment[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert!(
            !flows.r2o_skip_packet(&fragment, R2O_ROUTE_OTHER_DEV, now),
            "C routed_flow отвергает не первый фрагмент"
        );
        let mut icmp = vec![0_u8; 28];
        icmp[0] = 0x45;
        icmp[2..4].copy_from_slice(&28_u16.to_be_bytes());
        icmp[8] = 64;
        icmp[9] = 1;
        icmp[12..16].copy_from_slice(&[192, 0, 2, 1]);
        icmp[16..20].copy_from_slice(&[198, 51, 100, 2]);
        assert!(
            !flows.r2o_skip_packet(&icmp, R2O_ROUTE_OTHER_DEV, now),
            "C routed_flow ведёт только TCP/UDP"
        );
        assert_eq!(flows.routed_flows(), 0);
    }

    #[test]
    #[ignore]
    fn d2o_routed_flow_trace() {
        fn run_ex(
            name: &str,
            flows: &mut R2oRoutedFlows,
            packet: &[u8],
            mark: u32,
            now: Instant,
            compare_skip: bool,
        ) {
            let before = flows.routed_flows();
            let skip = flows.r2o_skip_packet(packet, mark, now);
            let first = flows.routed_flows() != before;
            let skip = if compare_skip {
                u8::from(skip).to_string()
            } else {
                "-".to_owned()
            };
            println!(
                "{name} skip={skip} first={} mark={}",
                u8::from(first),
                if first { mark } else { 0 }
            );
        }
        fn run(name: &str, flows: &mut R2oRoutedFlows, packet: &[u8], mark: u32, now: Instant) {
            run_ex(name, flows, packet, mark, now, true);
        }
        let mut flows = R2oRoutedFlows::default();
        let start = Instant::now();
        let syn = r2o_test_tcp([192, 0, 2, 10], [198, 51, 100, 20], 40_000, 443, 0x02);
        run("A mark-syn", &mut flows, &syn, 77, start);
        let data = {
            let mut packet = r2o_test_tcp([192, 0, 2, 10], [198, 51, 100, 20], 40_000, 443, 0x18);
            packet.push(b'x');
            packet[2..4].copy_from_slice(&41_u16.to_be_bytes());
            packet
        };
        run("B follow", &mut flows, &data, 0, start);
        let again = {
            let mut packet = syn.clone();
            packet[24..28].copy_from_slice(&2000_u32.to_be_bytes());
            packet
        };
        run_ex("C new-syn", &mut flows, &again, 0, start, false);
        run("K mark-after-new-syn", &mut flows, &again, 77, start);
        let other = r2o_test_tcp([192, 0, 2, 10], [198, 51, 100, 20], 40_001, 443, 0x02);
        run_ex("D unknown", &mut flows, &other, 0, start, false);
        run("L mark-unknown", &mut flows, &other, 77, start);
        let udp = r2o_test_udp([192, 0, 2, 10], [198, 51, 100, 20], 50_000, 443, b"q");
        run("E mark-udp", &mut flows, &udp, 77, start);
        let reverse = r2o_test_udp([198, 51, 100, 20], [192, 0, 2, 10], 443, 50_000, b"r");
        run("F udp-reverse", &mut flows, &reverse, 0, start);
        run("J udp-again", &mut flows, &udp, 77, start);
    }

    #[test]
    fn r2o_счётчик_маршрутных_потоков_кумулятивный_как_c() {
        let mut flows = R2oRoutedFlows::default();
        let now = Instant::now();
        let client_syn = r2o_test_tcp([192, 0, 2, 1], [198, 51, 100, 2], 40_000, 443, 0x02);
        let second_syn = r2o_test_tcp([192, 0, 2, 1], [198, 51, 100, 2], 40_001, 443, 0x02);
        assert_eq!(flows.routed_flows(), 0);
        assert!(flows.r2o_skip_packet(&client_syn, R2O_ROUTE_OTHER_DEV, now));
        assert_eq!(flows.routed_flows(), 1);
        assert!(flows.r2o_skip_packet(&client_syn, R2O_ROUTE_OTHER_DEV, now));
        assert_eq!(flows.routed_flows(), 1, "повторная метка не считается");
        flows.r2o_expire(now + R2O_ROUTE_FLOW_IDLE + Duration::from_secs(1));
        assert_eq!(flows.routed_flows(), 1, "истечение не уменьшает счётчик");
        assert!(flows.r2o_skip_packet(
            &second_syn,
            R2O_ROUTE_OTHER_DEV,
            now + R2O_ROUTE_FLOW_IDLE + Duration::from_secs(1)
        ));
        assert_eq!(flows.routed_flows(), 2);
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

    fn r2o_test_udp(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0; 28 + payload.len()];
        let total = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(8_u16 + payload.len() as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        packet
    }

    fn r2o_selector(mark: u32, mask: u32, family: R2oRouteFamily) -> R2oFwSelector {
        R2oFwSelector { mark, mask, family }
    }

    #[test]
    fn r2o_описание_правил_совпадает_с_c_описанием_и_обрезается_по_cap() {
        let mut gate = R2oRouteGate::default();
        assert_eq!(gate.r2o_describe_rules(32), "нет");
        assert_eq!(gate.r2o_describe_rules(0), "");

        gate.r2o_set_rules(
            R2oRouteFamily::Ipv4,
            vec![r2o_selector(0x1, 0xff, R2oRouteFamily::Ipv4)],
        );
        gate.r2o_set_rules(
            R2oRouteFamily::Ipv6,
            vec![r2o_selector(0x2, 0xff, R2oRouteFamily::Ipv6)],
        );
        assert_eq!(gate.r2o_describe_rules(64), "0x1/0xff v4, 0x2/0xff v6");
        // C `snprintf(buf, cap, ...)` оставляет не больше cap-1 байт.
        assert_eq!(gate.r2o_describe_rules(8), "0x1/0xf");
    }

    #[test]
    fn r2o_признак_изменения_правил_и_устройств_совпадает_с_c() {
        let mut gate = R2oRouteGate::default();
        assert!(!gate.r2o_set_rules(R2oRouteFamily::Ipv4, Vec::new()));
        assert!(gate.r2o_set_rules(
            R2oRouteFamily::Ipv4,
            vec![r2o_selector(1, 0xff, R2oRouteFamily::Ipv4)]
        ));
        assert!(!gate.r2o_set_rules(
            R2oRouteFamily::Ipv4,
            vec![r2o_selector(1, 0xff, R2oRouteFamily::Ipv4)]
        ));
        assert!(gate.r2o_set_rules(
            R2oRouteFamily::Ipv4,
            vec![r2o_selector(2, 0xff, R2oRouteFamily::Ipv4)]
        ));

        assert!(!gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, None));
        assert!(gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, Some(vec![5])));
        assert!(!gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, Some(vec![5, 5, 0])));
        assert!(gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, Some(vec![6])));
        assert!(gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, None));
        assert!(!gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, None));
    }

    #[test]
    fn r2o_клиентская_метка_отделена_от_выходного_гейта_как_в_c() {
        let mut gate = R2oRouteGate::default();
        gate.r2o_set_rules(
            R2oRouteFamily::Ipv4,
            vec![r2o_selector(0x10, 0xff, R2oRouteFamily::Ipv4)],
        );
        assert_eq!(gate.r2o_client_mark(R2oRouteFamily::Ipv4, None, 1, 2), 0);
        assert_eq!(gate.r2o_client_mark(R2oRouteFamily::Ipv4, Some(0), 1, 2), 0);
        assert_eq!(gate.r2o_client_mark(R2oRouteFamily::Ipv4, Some(1), 1, 2), 0);
        assert_eq!(gate.r2o_client_mark(R2oRouteFamily::Ipv4, Some(2), 1, 2), 0);
        assert_eq!(
            gate.r2o_client_mark(R2oRouteFamily::Ipv4, Some(0x10), 1, 2),
            0x10
        );
        assert_eq!(
            gate.r2o_client_mark(R2oRouteFamily::Ipv4, Some(0x11), 1, 2),
            0
        );

        // Клиентская метка возвращается до проверки outbound/outdev.
        assert_eq!(
            gate.r2o_route_mark(r2o_packet(false, Some(0x10), Some(9))),
            0x10
        );
    }

    #[test]
    fn r2o_короткий_nlmsg_error_даёт_код_ноль_как_c() {
        let mut message = vec![0; 18];
        message[..4].copy_from_slice(&18_u32.to_ne_bytes());
        message[4..6].copy_from_slice(&R2O_NLMSG_ERROR.to_ne_bytes());
        assert_eq!(
            r2o_route_parse_rules(&message),
            Err(R2oRouteParseError::Kernel(0))
        );
    }

    #[test]
    fn r2o_коды_пустого_дампа_и_лимиты_lookup_совпадают_с_c() {
        assert!(r2o_rules_error_is_empty_success(-97));
        assert!(r2o_rules_error_is_empty_success(-95));
        assert!(!r2o_rules_error_is_empty_success(-1));
        assert_eq!(R2O_LOOKUP_ROUNDS, 4);
        assert_eq!(R2O_LOOKUP_BUFFER, 8192);
        assert_eq!(R2O_DUMP_ROUNDS, 4096);
        assert_eq!(R2O_DUMP_BUFFER, 32768);
    }

    #[test]
    fn r2o_watch_other_error_returns_accumulated_not_err() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let monitor = R2oRouteMonitor {
            watch: Some(std::os::fd::OwnedFd::from(file)),
            sequence: 1,
        };
        assert!(!monitor.r2o_drain_watch().unwrap());
    }

    #[test]
    fn r2o_избыток_правил_усекается_до_32_как_в_c() {
        let mut selectors = Vec::new();
        let mut truncated = false;
        let batch: Vec<_> = (0..33)
            .map(|index| r2o_selector(index, 0xff, R2oRouteFamily::Ipv4))
            .collect();
        r2o_extend_rule_selectors(&mut selectors, batch, &mut truncated);
        assert_eq!(selectors.len(), R2O_ROUTE_RULE_CAPACITY);
        assert!(truncated);

        let mut exact = Vec::new();
        let mut exact_truncated = false;
        r2o_extend_rule_selectors(
            &mut exact,
            (0..32)
                .map(|index| r2o_selector(index, 0xff, R2oRouteFamily::Ipv4))
                .collect(),
            &mut exact_truncated,
        );
        assert_eq!(exact.len(), R2O_ROUTE_RULE_CAPACITY);
        assert!(!exact_truncated);
    }
}
