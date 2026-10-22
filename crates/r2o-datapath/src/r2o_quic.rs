//! Наблюдение молчания UDP-потоков после QUIC Initial.

#[cfg(target_os = "linux")]
use crate::conntrack::{
    R2oConntrackInfo, R2oConntrackTuple, r2o_conntrack_tuple_from_socket_addrs,
};
use crate::flow_capacity::R2oFlowCapacity;
use crate::netlink::{
    R2O_NF_INET_LOCAL_IN, R2O_NF_INET_LOCAL_OUT, R2O_NF_INET_POST_ROUTING, R2O_NF_INET_PRE_ROUTING,
};
use r2k_core::addr::Address;
use r2k_core::control::{KEY_LEN, R2oQuicSuspectEvent};
use r2k_core::packet::PacketView;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const MAX_INITIAL_RING: usize = 32;
const MAX_INITIAL_DATAGRAMS: usize = 4;
const QUIC_SILENCE: Duration = Duration::from_secs(2);
const QUIC_IDLE: Duration = Duration::from_secs(120);
#[cfg(target_os = "linux")]
const QUIC_STALL_MIN: Duration = Duration::from_secs(1);

pub(crate) fn r2o_quic_client_direction(
    source_port: u16,
    destination_port: u16,
    hook: Option<u8>,
) -> bool {
    match hook {
        Some(R2O_NF_INET_LOCAL_OUT | R2O_NF_INET_POST_ROUTING) => true,
        Some(R2O_NF_INET_PRE_ROUTING | R2O_NF_INET_LOCAL_IN) => false,
        _ => destination_port == 443 && source_port != 443,
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Endpoint {
    address: Address,
    port: u16,
}

impl Endpoint {
    fn order_key(self) -> (u8, [u8; 16], u16) {
        (self.address.family(), self.address.bytes(), self.port)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    low: Endpoint,
    high: Endpoint,
}

impl FlowKey {
    fn new(source: Endpoint, destination: Endpoint) -> (Self, bool) {
        if source.order_key() <= destination.order_key() {
            (
                Self {
                    low: source,
                    high: destination,
                },
                true,
            )
        } else {
            (
                Self {
                    low: destination,
                    high: source,
                },
                false,
            )
        }
    }

    fn wire_key(self) -> [u8; KEY_LEN] {
        let mut key = [0; KEY_LEN];
        key[0] = self.low.address.family();
        key[1..17].copy_from_slice(&self.low.address.bytes());
        key[17..33].copy_from_slice(&self.high.address.bytes());
        key[33..35].copy_from_slice(&self.low.port.to_be_bytes());
        key[35..37].copy_from_slice(&self.high.port.to_be_bytes());
        key[37] = 17;
        key
    }
}

struct FlowState {
    client: Endpoint,
    server: Endpoint,
    client_is_low: bool,
    first_initial: Instant,
    last_forward: Instant,
    last_reverse: Option<Instant>,
    #[cfg(target_os = "linux")]
    reverse_packets: u32,
    #[cfg(target_os = "linux")]
    first_response_rtt: Option<Duration>,
    #[cfg(target_os = "linux")]
    conntrack_mark: Option<R2oQuicConntrackMark>,
    #[cfg(target_os = "linux")]
    quic_stall_excluded: bool,
    last_seen: Instant,
    forward_after_initial: u32,
    exchange_told: bool,
    suspected: bool,
    plan_applied: bool,
}

/// Событие UDP-обмена или протокольного подтверждения для журнала.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oUdpExchangeEvent {
    /// Канонический ключ UDP-потока.
    pub key: [u8; KEY_LEN],
    /// Код подтверждения: ноль означает только общий факт UDP-обмена.
    pub code: u8,
    /// Длина полезной нагрузки ответной датаграммы.
    pub num: u32,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct R2oQuicConntrackMark {
    original_packets: u64,
    reply_packets: u64,
    at: Instant,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oQuicStallProbe {
    pub key: [u8; KEY_LEN],
    pub tuple: R2oConntrackTuple,
}

struct InitialDatagram {
    key: FlowKey,
    version: u32,
    dcid: Vec<u8>,
    bytes: Vec<u8>,
}

/// Ограниченное состояние для наблюдения за повторами QUIC Initial без ответа.
pub struct R2oQuicSessions {
    flows: HashMap<FlowKey, FlowState>,
    initial_ring: VecDeque<InitialDatagram>,
    hello_reported: HashMap<FlowKey, Instant>,
    udp_exchange_events: VecDeque<R2oUdpExchangeEvent>,
    flow_limit: usize,
    r2o_idle_timeout: Duration,
}

impl R2oQuicSessions {
    /// Создать состояние с тем же пределом потоков, что и у UDP-таблицы.
    pub fn try_with_capacity(
        flow_capacity: R2oFlowCapacity,
    ) -> Result<Self, std::collections::TryReserveError> {
        let flow_limit = flow_capacity.limit();
        let mut flows = HashMap::new();
        flows.try_reserve(flow_limit)?;
        let mut hello_reported = HashMap::new();
        hello_reported.try_reserve(flow_limit)?;
        let mut udp_exchange_events = VecDeque::new();
        udp_exchange_events.try_reserve(flow_limit)?;
        Ok(Self {
            flows,
            initial_ring: VecDeque::new(),
            hello_reported,
            udp_exchange_events,
            flow_limit,
            r2o_idle_timeout: QUIC_IDLE,
        })
    }

    /// Настроить срок хранения состояния QUIC-потоков и снимков приветствий.
    pub fn r2o_set_idle_timeout(&mut self, timeout: Duration) {
        self.r2o_idle_timeout = timeout;
    }

    /// Собрать имя из проверенных Initial одного UDP-потока.
    pub fn capture_hello(&mut self, packet: &[u8]) -> Option<super::capture::QuicHello> {
        self.capture_hello_at_hook(packet, None)
    }

    pub fn capture_hello_at_hook(
        &mut self,
        packet: &[u8],
        hook: Option<u8>,
    ) -> Option<super::capture::QuicHello> {
        self.capture_hello_at_hook_at(packet, hook, Instant::now())
    }

    fn capture_hello_at_hook_at(
        &mut self,
        packet: &[u8],
        hook: Option<u8>,
        now: Instant,
    ) -> Option<super::capture::QuicHello> {
        let view = PacketView::parse(packet)
            .filter(|view| view.protocol == 17 && view.fragment & 0x3fff == 0)?;
        let udp = packet.get(view.l4_offset..view.total_len)?;
        if udp.len() < 8 {
            return None;
        }
        let source = Endpoint {
            address: view.src,
            port: u16::from_be_bytes([udp[0], udp[1]]),
        };
        let destination = Endpoint {
            address: view.dst,
            port: u16::from_be_bytes([udp[2], udp[3]]),
        };
        let hook = self.quic_direction_hook(source, destination, hook);
        if !r2o_quic_client_direction(source.port, destination.port, hook) {
            return None;
        }
        let payload = packet.get(view.udp_payload_range(packet)?)?;
        let (version, dcid) = r2k_core::quic::r2k_quic_initial_flight_id(payload)?;
        let key = FlowKey::new(source, destination).0;

        let idle_timeout = self.r2o_idle_timeout;
        self.hello_reported
            .retain(|_, last_seen| now.saturating_duration_since(*last_seen) < idle_timeout);
        if let Some(last_seen) = self.hello_reported.get_mut(&key) {
            *last_seen = now;
            self.initial_ring.retain(|entry| entry.key != key);
            return None;
        }

        if !self
            .initial_ring
            .iter()
            .any(|entry| entry.key == key && entry.bytes == payload)
        {
            if self.initial_ring.len() == MAX_INITIAL_RING {
                self.initial_ring.pop_front();
            }
            self.initial_ring.push_back(InitialDatagram {
                key,
                version,
                dcid: dcid.clone(),
                bytes: payload.to_vec(),
            });
        }

        let (host, snapshot) = {
            let matching = self
                .initial_ring
                .iter()
                .filter(|entry| entry.key == key && entry.version == version && entry.dcid == dcid)
                .collect::<Vec<_>>();
            let start = matching.len().saturating_sub(MAX_INITIAL_DATAGRAMS);
            let datagrams = matching[start..]
                .iter()
                .map(|entry| entry.bytes.as_slice())
                .collect::<Vec<_>>();
            let host = r2k_core::quic::r2k_quic_initial_sni_result_from_datagrams(&datagrams)
                .ok()?
                .unwrap_or_default();
            let snapshot = r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&datagrams)?;
            (host, snapshot)
        };

        self.initial_ring.retain(|entry| entry.key != key);
        if self.hello_reported.len() == self.flow_limit {
            if let Some(oldest) = self.hello_reported.keys().next().copied() {
                self.hello_reported.remove(&oldest);
            }
        }
        self.hello_reported.insert(key, now);
        Some(super::capture::QuicHello {
            key: key.wire_key(),
            host,
            snapshot: Some(snapshot),
        })
    }

    /// Запомнить проверенный клиентский Initial и последующие пакеты потока.
    pub fn observe_packet(&mut self, packet: &[u8], now: Instant) {
        self.observe_packet_at_hook(packet, now, None);
    }

    pub fn take_udp_exchange_events(&mut self) -> Vec<R2oUdpExchangeEvent> {
        self.udp_exchange_events.drain(..).collect()
    }

    /// Отметить, что к этому QUIC-потоку был применён план.
    pub fn mark_plan_applied(&mut self, packet: &[u8]) -> bool {
        let Some(view) = PacketView::parse(packet)
            .filter(|view| view.protocol == 17 && view.fragment & 0x3fff == 0)
        else {
            return false;
        };
        let Some(udp) = packet
            .get(view.l4_offset..view.total_len)
            .filter(|udp| udp.len() >= 8)
        else {
            return false;
        };
        let source = Endpoint {
            address: view.src,
            port: u16::from_be_bytes([udp[0], udp[1]]),
        };
        let destination = Endpoint {
            address: view.dst,
            port: u16::from_be_bytes([udp[2], udp[3]]),
        };
        let (key, _) = FlowKey::new(source, destination);
        let Some(flow) = self.flows.get_mut(&key) else {
            return false;
        };
        flow.plan_applied = true;
        true
    }

    pub fn observe_packet_at_hook(&mut self, packet: &[u8], now: Instant, hook: Option<u8>) {
        let Some(view) = PacketView::parse(packet)
            .filter(|view| view.protocol == 17 && view.fragment & 0x3fff == 0)
        else {
            return;
        };
        let Some(udp) = packet
            .get(view.l4_offset..view.total_len)
            .filter(|udp| udp.len() >= 8)
        else {
            return;
        };
        let source = Endpoint {
            address: view.src,
            port: u16::from_be_bytes([udp[0], udp[1]]),
        };
        let destination = Endpoint {
            address: view.dst,
            port: u16::from_be_bytes([udp[2], udp[3]]),
        };
        let hook = self.quic_direction_hook(source, destination, hook);
        let Some(payload_range) = view.udp_payload_range(packet) else {
            return;
        };
        let Some(payload) = packet.get(payload_range) else {
            return;
        };

        if r2o_quic_client_direction(source.port, destination.port, hook)
            && r2k_core::quic::is_authenticated_initial(payload)
        {
            let (key, client_is_low) = FlowKey::new(source, destination);
            if let Some(last_seen) = self.hello_reported.get_mut(&key) {
                *last_seen = now;
            }
            let first_initial = !self.flows.contains_key(&key);
            if first_initial && self.flows.len() >= self.flow_limit {
                return;
            }
            let flow = self.flows.entry(key).or_insert_with(|| FlowState {
                client: source,
                server: destination,
                client_is_low,
                first_initial: now,
                last_forward: now,
                last_reverse: None,
                #[cfg(target_os = "linux")]
                reverse_packets: 0,
                #[cfg(target_os = "linux")]
                first_response_rtt: None,
                #[cfg(target_os = "linux")]
                conntrack_mark: None,
                #[cfg(target_os = "linux")]
                quic_stall_excluded: false,
                last_seen: now,
                forward_after_initial: 0,
                exchange_told: false,
                suspected: false,
                plan_applied: false,
            });
            if !first_initial {
                flow.forward_after_initial = flow.forward_after_initial.saturating_add(1);
            }
            flow.last_forward = now;
            flow.last_seen = now;
            return;
        }

        let (key, _) = FlowKey::new(source, destination);
        if let Some(last_seen) = self.hello_reported.get_mut(&key) {
            *last_seen = now;
        }
        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };
        if source == flow.client && destination == flow.server {
            #[cfg(target_os = "linux")]
            if r2k_core::stun::is_binding_request(payload)
                || r2k_core::stun::is_discord_ip_discovery_request(payload)
            {
                flow.quic_stall_excluded = true;
            }
            flow.forward_after_initial = flow.forward_after_initial.saturating_add(1);
            flow.last_forward = now;
        } else if source == flow.server && destination == flow.client {
            if flow.last_reverse.is_none() && !flow.exchange_told {
                flow.exchange_told = true;
                if self.udp_exchange_events.len() < self.flow_limit {
                    self.udp_exchange_events.push_back(R2oUdpExchangeEvent {
                        key: key.wire_key(),
                        code: 0,
                        num: payload.len().min(u32::MAX as usize) as u32,
                    });
                }
            }
            #[cfg(target_os = "linux")]
            {
                if flow.last_reverse.is_none() {
                    flow.first_response_rtt =
                        Some(now.saturating_duration_since(flow.first_initial));
                }
                flow.reverse_packets = flow.reverse_packets.saturating_add(1);
            }
            flow.last_reverse = Some(now);
        } else {
            return;
        }
        flow.last_seen = now;
    }

    pub fn quic_direction_hook_for_packet(&self, packet: &[u8], hook: Option<u8>) -> Option<u8> {
        let Some(view) = PacketView::parse(packet).filter(|view| view.protocol == 17) else {
            return hook;
        };
        let Some(udp) = packet
            .get(view.l4_offset..view.total_len)
            .filter(|udp| udp.len() >= 8)
        else {
            return hook;
        };
        let source = Endpoint {
            address: view.src,
            port: u16::from_be_bytes([udp[0], udp[1]]),
        };
        let destination = Endpoint {
            address: view.dst,
            port: u16::from_be_bytes([udp[2], udp[3]]),
        };
        self.quic_direction_hook(source, destination, hook)
    }

    fn quic_direction_hook(
        &self,
        source: Endpoint,
        destination: Endpoint,
        hook: Option<u8>,
    ) -> Option<u8> {
        if matches!(
            hook,
            Some(
                R2O_NF_INET_LOCAL_OUT
                    | R2O_NF_INET_POST_ROUTING
                    | R2O_NF_INET_PRE_ROUTING
                    | R2O_NF_INET_LOCAL_IN
            )
        ) {
            return hook;
        }
        let (key, source_is_low) = FlowKey::new(source, destination);
        self.flows
            .get(&key)
            .map(|flow| {
                if source_is_low == flow.client_is_low {
                    R2O_NF_INET_LOCAL_OUT
                } else {
                    R2O_NF_INET_LOCAL_IN
                }
            })
            .map(Some)
            .unwrap_or(hook)
    }

    /// Выдать одно наблюдение после повтора Initial и двух секунд без ответа.
    pub fn sweep(&mut self, now: Instant, reverse_queue_visible: bool) -> Vec<R2oQuicSuspectEvent> {
        let mut events = Vec::new();
        if reverse_queue_visible {
            for (key, flow) in &mut self.flows {
                if flow.suspected
                    || flow.forward_after_initial == 0
                    || now.saturating_duration_since(flow.first_initial) < QUIC_SILENCE
                    || flow
                        .last_reverse
                        .is_some_and(|last_reverse| last_reverse >= flow.last_forward)
                {
                    continue;
                }
                events.push(R2oQuicSuspectEvent {
                    key: key.wire_key(),
                    client_is_low: flow.client_is_low,
                    planned: flow.plan_applied,
                });
            }
        }
        self.expire(now);
        events
    }

    #[cfg(target_os = "linux")]
    pub fn r2o_quic_stall_candidates(&self) -> Vec<R2oQuicStallProbe> {
        self.flows
            .iter()
            .filter_map(|(key, flow)| {
                if flow.suspected
                    || flow.quic_stall_excluded
                    || flow.last_reverse.is_none()
                    || flow.first_response_rtt.is_none()
                {
                    return None;
                }
                let client =
                    std::net::SocketAddr::new(flow.client.address.as_ip_addr(), flow.client.port);
                let server =
                    std::net::SocketAddr::new(flow.server.address.as_ip_addr(), flow.server.port);
                Some(R2oQuicStallProbe {
                    key: key.wire_key(),
                    tuple: r2o_conntrack_tuple_from_socket_addrs(client, server, 17)?,
                })
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    pub fn update_r2o_quic_stall(
        &mut self,
        now: Instant,
        key: &[u8; KEY_LEN],
        info: R2oConntrackInfo,
    ) -> Option<R2oQuicSuspectEvent> {
        let (flow_key, flow) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)?;
        if flow.suspected || flow.quic_stall_excluded || flow.last_reverse.is_none() {
            return None;
        }
        if flow
            .conntrack_mark
            .is_none_or(|mark| mark.reply_packets != info.reply_packets)
        {
            flow.conntrack_mark = Some(R2oQuicConntrackMark {
                original_packets: info.original_packets,
                reply_packets: info.reply_packets,
                at: now,
            });
            return None;
        }
        let mark = flow.conntrack_mark?;
        if info.reply_packets <= u64::from(flow.reverse_packets)
            || info.original_packets < mark.original_packets
            || info.original_packets - mark.original_packets < 3
        {
            return None;
        }
        let pto = flow
            .first_response_rtt
            .unwrap_or_default()
            .saturating_mul(3)
            .max(QUIC_STALL_MIN);
        if now.saturating_duration_since(mark.at) < pto {
            return None;
        }
        Some(R2oQuicSuspectEvent {
            key: flow_key.wire_key(),
            client_is_low: flow.client_is_low,
            planned: flow.plan_applied,
        })
    }

    /// Не повторять событие до истечения состояния потока.
    pub fn mark_suspected(&mut self, key: &[u8; KEY_LEN]) {
        if let Some((_, flow)) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)
        {
            flow.suspected = true;
        }
    }

    /// Не считать поток молчащим, если к нему применился план `quicdeny`.
    pub fn suppress_packet(&mut self, packet: &[u8]) {
        let Some(view) = PacketView::parse(packet).filter(|view| view.protocol == 17) else {
            return;
        };
        let Some(udp) = packet
            .get(view.l4_offset..view.total_len)
            .filter(|udp| udp.len() >= 8)
        else {
            return;
        };
        let source = Endpoint {
            address: view.src,
            port: u16::from_be_bytes([udp[0], udp[1]]),
        };
        let destination = Endpoint {
            address: view.dst,
            port: u16::from_be_bytes([udp[2], udp[3]]),
        };
        let (key, _) = FlowKey::new(source, destination);
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.suspected = true;
        }
    }

    fn expire(&mut self, now: Instant) {
        let idle_timeout = self.r2o_idle_timeout;
        self.flows
            .retain(|_, flow| now.saturating_duration_since(flow.last_seen) < idle_timeout);
        self.hello_reported
            .retain(|_, last_seen| now.saturating_duration_since(*last_seen) < idle_timeout);
    }
}

impl Default for R2oQuicSessions {
    fn default() -> Self {
        Self {
            flows: HashMap::new(),
            initial_ring: VecDeque::new(),
            hello_reported: HashMap::new(),
            udp_exchange_events: VecDeque::new(),
            flow_limit: R2oFlowCapacity::default().limit(),
            r2o_idle_timeout: QUIC_IDLE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{QUIC_IDLE, QUIC_SILENCE, R2oQuicSessions, r2o_quic_client_direction};
    #[cfg(target_os = "linux")]
    use crate::conntrack::R2oConntrackInfo;
    use crate::flow_capacity::R2oFlowCapacity;
    use crate::netlink::{
        R2O_NF_INET_FORWARD, R2O_NF_INET_LOCAL_IN, R2O_NF_INET_LOCAL_OUT, R2O_NF_INET_POST_ROUTING,
        R2O_NF_INET_PRE_ROUTING,
    };
    use r2k_core::control::{EVENT_R2O_QUIC_SUSPECT, Frame, decode_r2o_quic_suspect};
    use std::net::Ipv6Addr;
    use std::time::{Duration, Instant};

    const INITIAL: &[u8] = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
    const INITIAL_NO_SNI: &[u8] =
        include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial_no_sni.bin");
    const INITIAL_FIRST: &[u8] = include_bytes!("../tests/fixtures/quic_v1_initial_first.bin");
    const INITIAL_SECOND: &[u8] = include_bytes!("../tests/fixtures/quic_v1_initial_second.bin");

    #[test]
    fn quic_учёт_не_превышает_порог_ёмкости_udp_таблицы() {
        let now = Instant::now();
        let limit = R2oFlowCapacity::default().limit();
        let mut sessions = R2oQuicSessions::default();
        for offset in 0..=limit {
            sessions.observe_packet(
                &ipv4_packet(
                    [192, 0, 2, 10],
                    [198, 51, 100, 20],
                    40_000 + offset as u16,
                    443,
                    INITIAL,
                ),
                now,
            );
        }
        assert_eq!(sessions.flows.len(), limit);
    }

    #[test]
    fn quic_учёт_поддерживает_увеличенную_настройку_ёмкости() {
        let now = Instant::now();
        let capacity = R2oFlowCapacity::from_requested(4096).unwrap();
        let mut sessions = R2oQuicSessions::try_with_capacity(capacity).unwrap();
        for offset in 0..2049 {
            sessions.observe_packet(
                &ipv4_packet(
                    [192, 0, 2, 10],
                    [198, 51, 100, 20],
                    40_000 + offset as u16,
                    443,
                    INITIAL,
                ),
                now,
            );
        }
        assert_eq!(sessions.flows.len(), 2049);
    }

    #[test]
    fn quic_журналирует_только_первую_обратную_датаграмму_включая_пустую() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let initial = ipv4_packet(client, server, 53_123, 443, INITIAL);
        let mut sessions = R2oQuicSessions::default();
        sessions.observe_packet(&initial, start);
        assert!(sessions.take_udp_exchange_events().is_empty());

        sessions.observe_packet(
            &ipv4_packet(server, client, 443, 53_123, b"reply"),
            start + Duration::from_millis(100),
        );
        let events = sessions.take_udp_exchange_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].key[37], 17);
        assert_eq!(&events[0].key[1..5], &client);
        assert_eq!(&events[0].key[17..21], &server);
        assert_eq!(events[0].code, 0);
        assert_eq!(events[0].num, 5);

        sessions.observe_packet(
            &ipv4_packet(server, client, 443, 53_123, b"later"),
            start + Duration::from_millis(200),
        );
        assert!(sessions.take_udp_exchange_events().is_empty());

        let second_client = [192, 0, 2, 11];
        sessions.observe_packet(
            &ipv4_packet(second_client, server, 53_124, 443, INITIAL),
            start + Duration::from_millis(300),
        );
        sessions.observe_packet(
            &ipv4_packet(server, second_client, 443, 53_124, &[]),
            start + Duration::from_millis(400),
        );
        let empty = sessions.take_udp_exchange_events();
        assert_eq!(empty.len(), 1);
        assert_eq!(empty[0].num, 0);
    }

    fn ipv4_packet(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        body: &[u8],
    ) -> Vec<u8> {
        let total = 20 + 8 + body.len();
        let mut packet = vec![0; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + body.len()) as u16).to_be_bytes());
        packet[28..].copy_from_slice(body);
        packet
    }

    fn ipv6_packet(
        source: [u8; 16],
        destination: [u8; 16],
        source_port: u16,
        destination_port: u16,
        body: &[u8],
    ) -> Vec<u8> {
        let payload_len = 8 + body.len();
        let mut packet = vec![0; 40 + payload_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..46].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[48..].copy_from_slice(body);
        packet
    }

    fn event_frame(event: &r2k_core::control::R2oQuicSuspectEvent) -> Frame {
        Frame {
            kind: EVENT_R2O_QUIC_SUSPECT,
            body: event.event_body().unwrap(),
        }
    }

    #[test]
    fn quic_initial_молчание_требует_повтора_и_видимого_обратного_пути() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let initial = ipv4_packet(client, server, 53_123, 443, INITIAL);
        assert!(r2k_core::quic::is_authenticated_initial(INITIAL));

        let mut sessions = R2oQuicSessions::default();
        sessions.observe_packet(&initial, start);
        assert!(sessions.mark_plan_applied(&initial));
        assert!(sessions.sweep(start + QUIC_SILENCE, true).is_empty());

        sessions.observe_packet(
            &ipv4_packet(client, server, 53_123, 443, INITIAL),
            start + Duration::from_millis(800),
        );
        assert!(sessions.sweep(start + QUIC_SILENCE, false).is_empty());
        let events = sessions.sweep(start + QUIC_SILENCE, true);
        assert_eq!(events.len(), 1);
        let decoded = decode_r2o_quic_suspect(&event_frame(&events[0])).unwrap();
        assert!(decoded.client_is_low);
        assert!(decoded.planned);
        assert_eq!(&decoded.key[1..5], &client);
        assert_eq!(decoded.key[0], 4);

        sessions.mark_suspected(&decoded.key);
        assert!(
            sessions
                .sweep(start + QUIC_SILENCE + Duration::from_secs(1), true)
                .is_empty()
        );
    }

    #[test]
    fn r2o_quic_проверяет_тишину_до_удаления_по_idle() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oQuicSessions::default();
        sessions.r2o_set_idle_timeout(Duration::from_secs(1));
        sessions.observe_packet(&ipv4_packet(client, server, 53_123, 443, INITIAL), start);
        sessions.observe_packet(
            &ipv4_packet(client, server, 53_123, 443, INITIAL),
            start + Duration::from_millis(800),
        );

        let events = sessions.sweep(start + QUIC_SILENCE, true);
        assert_eq!(events.len(), 1);
        assert!(sessions.flows.is_empty());
    }

    #[test]
    fn собирает_событие_из_проверенного_initial() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let initial = ipv4_packet(client, server, 53_123, 443, INITIAL);
        let mut sessions = R2oQuicSessions::default();

        let hello = sessions
            .capture_hello_at_hook_at(&initial, None, start)
            .unwrap();
        let event = r2k_core::control::decode_hello(&Frame {
            kind: r2k_core::control::EVENT_HELLO,
            body: hello.event_body().unwrap(),
        })
        .unwrap();
        assert_eq!(event.host.as_deref(), Some(b"example.com".as_slice()));
        assert_eq!(event.key[0], 4);
        assert_eq!(&event.key[1..5], &client);
        assert_eq!(&event.key[17..21], &server);
        let snapshot = r2k_core::quic_snapshot::r2k_quic_snapshot_parse(
            event.quic_snapshot.as_deref().unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot.datagrams(), &[INITIAL]);
        assert!(
            sessions
                .capture_hello_at_hook_at(&initial, None, start + Duration::from_secs(1))
                .is_none()
        );
        assert!(
            sessions
                .capture_hello_at_hook_at(
                    &initial,
                    None,
                    start + QUIC_IDLE + Duration::from_secs(1)
                )
                .is_some()
        );
    }

    #[test]
    fn передаёт_снимок_quic_без_sni_как_событие_по_ip() {
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let initial = ipv4_packet(client, server, 53_123, 443, INITIAL_NO_SNI);
        let mut sessions = R2oQuicSessions::default();

        let hello = sessions.capture_hello(&initial).unwrap();
        assert!(hello.host.is_empty());
        let event = r2k_core::control::decode_hello(&Frame {
            kind: r2k_core::control::EVENT_HELLO,
            body: hello.event_body().unwrap(),
        })
        .unwrap();
        assert_eq!(event.host, None);
        assert_eq!(event.key[37], 17);
        assert!(event.quic_snapshot.is_some());
        assert!(sessions.capture_hello(&initial).is_none());
    }

    #[test]
    fn quic_на_нестандартном_порту_требует_исходящий_hook() {
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let packet = ipv4_packet(client, server, 53_123, 8443, INITIAL);
        let mut sessions = R2oQuicSessions::default();

        let hello = sessions
            .capture_hello_at_hook(&packet, Some(R2O_NF_INET_POST_ROUTING))
            .unwrap();

        assert_eq!(hello.host, b"example.com");
        assert!(
            sessions
                .capture_hello_at_hook(&packet, Some(R2O_NF_INET_LOCAL_IN))
                .is_none()
        );
        assert!(sessions.capture_hello(&packet).is_none());
        assert!(r2o_quic_client_direction(
            53_123,
            8443,
            Some(R2O_NF_INET_LOCAL_OUT)
        ));
        assert!(!r2o_quic_client_direction(
            53_123,
            8443,
            Some(R2O_NF_INET_PRE_ROUTING)
        ));
        assert!(!r2o_quic_client_direction(
            53_123,
            8443,
            Some(R2O_NF_INET_FORWARD)
        ));
        assert!(r2o_quic_client_direction(
            53_123,
            443,
            Some(R2O_NF_INET_FORWARD)
        ));
        assert!(r2o_quic_client_direction(53_123, 443, None));
        assert!(!r2o_quic_client_direction(443, 53_123, None));

        let start = Instant::now();
        sessions.observe_packet_at_hook(&packet, start, Some(R2O_NF_INET_POST_ROUTING));
        sessions.observe_packet_at_hook(
            &ipv4_packet(client, server, 53_123, 8443, b"retry"),
            start + Duration::from_millis(800),
            Some(R2O_NF_INET_POST_ROUTING),
        );
        sessions.observe_packet_at_hook(
            &ipv4_packet(server, client, 8443, 53_123, b"reply"),
            start + Duration::from_millis(900),
            Some(R2O_NF_INET_LOCAL_IN),
        );
        assert!(sessions.sweep(start + QUIC_SILENCE, true).is_empty());
    }

    #[test]
    fn известное_направление_разрешает_forward_quic_на_нестандартном_порту() {
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let initial = ipv4_packet(client, server, 53_123, 8443, INITIAL);
        let start = Instant::now();
        let mut sessions = R2oQuicSessions::default();

        sessions.observe_packet_at_hook(&initial, start, Some(R2O_NF_INET_POST_ROUTING));
        assert_eq!(
            sessions.quic_direction_hook_for_packet(&initial, Some(R2O_NF_INET_FORWARD)),
            Some(R2O_NF_INET_LOCAL_OUT)
        );
        assert!(
            sessions
                .capture_hello_at_hook(&initial, Some(R2O_NF_INET_FORWARD))
                .is_some()
        );
        let reply = ipv4_packet(server, client, 8443, 53_123, INITIAL);
        assert_eq!(
            sessions.quic_direction_hook_for_packet(&reply, Some(R2O_NF_INET_FORWARD)),
            Some(R2O_NF_INET_LOCAL_IN)
        );
        assert!(
            sessions
                .capture_hello_at_hook(&reply, Some(R2O_NF_INET_FORWARD))
                .is_none()
        );
    }

    #[test]
    fn собирает_событие_из_двух_initial_только_одного_потока() {
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oQuicSessions::default();

        assert!(
            sessions
                .capture_hello(&ipv4_packet(client, server, 53_123, 443, INITIAL_FIRST),)
                .is_none()
        );
        assert!(
            sessions
                .capture_hello(&ipv4_packet(
                    [192, 0, 2, 11],
                    server,
                    53_124,
                    443,
                    INITIAL_SECOND
                ),)
                .is_none()
        );
        let hello = sessions
            .capture_hello(&ipv4_packet(client, server, 53_123, 443, INITIAL_SECOND))
            .unwrap();

        assert_eq!(hello.host, b"example.com");
        assert_eq!(hello.key[0], 4);
        assert_eq!(&hello.key[1..5], &client);
        assert_eq!(&hello.key[17..21], &server);
        let snapshot =
            r2k_core::quic_snapshot::r2k_quic_snapshot_parse(hello.snapshot.as_deref().unwrap())
                .unwrap();
        assert_eq!(snapshot.datagrams(), &[INITIAL_FIRST, INITIAL_SECOND]);
        assert!(
            sessions
                .capture_hello(&ipv4_packet(client, server, 53_123, 443, INITIAL_SECOND,))
                .is_none()
        );
    }

    #[test]
    fn r2o_quic_сохраняет_неполный_initial_после_истечения_состояния_потока() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oQuicSessions::default();
        sessions.r2o_set_idle_timeout(Duration::from_secs(5));

        assert!(
            sessions
                .capture_hello_at_hook_at(
                    &ipv4_packet(client, server, 53_123, 443, INITIAL_FIRST),
                    None,
                    start,
                )
                .is_none()
        );
        assert_eq!(sessions.initial_ring.len(), 1);
        assert!(
            sessions
                .sweep(start + Duration::from_secs(6), false)
                .is_empty()
        );
        assert_eq!(sessions.initial_ring.len(), 1);
        let hello = sessions
            .capture_hello_at_hook_at(
                &ipv4_packet(client, server, 53_123, 443, INITIAL_SECOND),
                None,
                start + Duration::from_secs(6),
            )
            .unwrap();
        assert_eq!(hello.host, b"example.com");
        assert!(sessions.initial_ring.is_empty());
    }

    #[test]
    fn ответ_после_последнего_повтора_снимает_подозрение() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oQuicSessions::default();
        sessions.observe_packet(&ipv4_packet(client, server, 53_123, 443, INITIAL), start);
        sessions.observe_packet(
            &ipv4_packet(client, server, 53_123, 443, b"retry"),
            start + Duration::from_millis(700),
        );
        sessions.observe_packet(
            &ipv4_packet(server, client, 443, 53_123, b"reply"),
            start + Duration::from_millis(900),
        );
        assert!(sessions.sweep(start + QUIC_SILENCE, true).is_empty());

        sessions.observe_packet(
            &ipv4_packet(client, server, 53_123, 443, b"retry again"),
            start + Duration::from_millis(1_100),
        );
        assert_eq!(sessions.sweep(start + QUIC_SILENCE, true).len(), 1);
    }

    #[test]
    fn quicdeny_исключает_поток_из_подозрений() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oQuicSessions::default();
        sessions.observe_packet(&ipv4_packet(client, server, 53_123, 443, INITIAL), start);
        let retry = ipv4_packet(client, server, 53_123, 443, b"retry");
        sessions.observe_packet(&retry, start + Duration::from_millis(800));
        sessions.suppress_packet(&retry);
        assert!(sessions.sweep(start + QUIC_SILENCE, true).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quic_зависание_сверяет_скрытый_ответ_с_conntrack() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oQuicSessions::default();
        sessions.observe_packet(&ipv4_packet(client, server, 53_123, 443, INITIAL), start);
        sessions.observe_packet(
            &ipv4_packet(server, client, 443, 53_123, "ответ".as_bytes()),
            start + Duration::from_millis(500),
        );

        let probe = sessions.r2o_quic_stall_candidates().pop().unwrap();
        assert_eq!(probe.tuple.protocol, 17);
        assert_eq!(&probe.tuple.source[..4], &client);
        assert_eq!(&probe.tuple.destination[..4], &server);
        let baseline = R2oConntrackInfo {
            original_packets: 10,
            reply_packets: 5,
            tcp_state: None,
        };
        assert_eq!(
            sessions.update_r2o_quic_stall(start + Duration::from_secs(1), &probe.key, baseline),
            None
        );
        assert_eq!(
            sessions.update_r2o_quic_stall(
                start + Duration::from_millis(2499),
                &probe.key,
                R2oConntrackInfo {
                    original_packets: 13,
                    ..baseline
                },
            ),
            None
        );
        let event = sessions
            .update_r2o_quic_stall(
                start + Duration::from_millis(2500),
                &probe.key,
                R2oConntrackInfo {
                    original_packets: 13,
                    ..baseline
                },
            )
            .unwrap();
        assert_eq!(event.key, probe.key);
        assert!(event.client_is_low);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quic_зависание_не_срабатывает_без_скрытых_ответов_или_после_quicdeny() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oQuicSessions::default();
        let initial = ipv4_packet(client, server, 53_123, 443, INITIAL);
        sessions.observe_packet(&initial, start);
        assert!(sessions.r2o_quic_stall_candidates().is_empty());
        sessions.observe_packet(
            &ipv4_packet(server, client, 443, 53_123, "ответ".as_bytes()),
            start + Duration::from_millis(100),
        );
        let probe = sessions.r2o_quic_stall_candidates().pop().unwrap();
        let baseline = R2oConntrackInfo {
            original_packets: 10,
            reply_packets: 1,
            tcp_state: None,
        };
        assert_eq!(
            sessions.update_r2o_quic_stall(start + Duration::from_secs(1), &probe.key, baseline),
            None
        );
        assert_eq!(
            sessions.update_r2o_quic_stall(
                start + Duration::from_secs(2),
                &probe.key,
                R2oConntrackInfo {
                    original_packets: 13,
                    ..baseline
                },
            ),
            None
        );

        sessions.suppress_packet(&initial);
        assert!(sessions.r2o_quic_stall_candidates().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quic_зависание_исключает_stun_и_discord_discovery_из_одного_потока() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let initial = ipv4_packet(client, server, 53_123, 443, INITIAL);
        let reply = ipv4_packet(server, client, 443, 53_123, b"reply");

        let mut discovery = [0; 74];
        discovery[..4].copy_from_slice(&[0, 1, 0, 70]);
        discovery[4..8].copy_from_slice(&[1, 2, 3, 4]);
        let stun = r2k_core::stun::binding_request([5; 12]);

        for request in [stun.as_slice(), discovery.as_slice()] {
            let mut sessions = R2oQuicSessions::default();
            sessions.observe_packet(&initial, start);
            sessions.observe_packet(&reply, start + Duration::from_millis(500));
            let probe = sessions.r2o_quic_stall_candidates().pop().unwrap();
            let baseline = R2oConntrackInfo {
                original_packets: 10,
                reply_packets: 9,
                tcp_state: None,
            };
            assert_eq!(
                sessions.update_r2o_quic_stall(
                    start + Duration::from_millis(600),
                    &probe.key,
                    baseline,
                ),
                None
            );

            sessions.observe_packet(
                &ipv4_packet(client, server, 53_123, 443, request),
                start + Duration::from_millis(700),
            );
            sessions.observe_packet(&reply, start + Duration::from_millis(900));

            assert!(sessions.r2o_quic_stall_candidates().is_empty());
            assert_eq!(
                sessions.update_r2o_quic_stall(
                    start + Duration::from_millis(2_200),
                    &probe.key,
                    R2oConntrackInfo {
                        original_packets: 13,
                        ..baseline
                    },
                ),
                None
            );
        }
    }

    #[test]
    fn quic_initial_ipv6_создаёт_канонический_поток() {
        let start = Instant::now();
        let client = "2001:db8::10".parse::<Ipv6Addr>().unwrap().octets();
        let server = "2001:db8::20".parse::<Ipv6Addr>().unwrap().octets();
        let mut sessions = R2oQuicSessions::default();
        sessions.observe_packet(&ipv6_packet(client, server, 53_123, 443, INITIAL), start);
        sessions.observe_packet(
            &ipv6_packet(client, server, 53_123, 443, b"retry"),
            start + Duration::from_millis(800),
        );
        let events = sessions.sweep(start + QUIC_SILENCE, true);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].key[0], 6);
        assert_eq!(&events[0].key[1..17], &Ipv6Addr::from(client).octets());
    }

    #[test]
    fn неподлинный_initial_не_создаёт_поток() {
        let start = Instant::now();
        let mut sessions = R2oQuicSessions::default();
        sessions.observe_packet(
            &ipv4_packet(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                53_123,
                443,
                b"fake Initial",
            ),
            start,
        );
        assert!(sessions.sweep(start + QUIC_SILENCE * 2, true).is_empty());
    }
}
