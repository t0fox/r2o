use r2k_core::control::{
    KEY_LEN, R2oTcpFinRetryEvent, R2oTcpRstAfterAppEvent, R2oTcpSilenceEvent, R2oTcpStallEvent,
};
use r2k_core::packet::PacketView;
use r2k_core::plan::{
    EmitKind, GUARD_RST_ALIEN, OriginalFate, POISON_IPID_ZERO, PROTO_HTTP, PROTO_VOICE,
    PacketInput, Plan,
};
use r2k_core::quic::is_authenticated_initial;
use std::collections::{HashMap, TryReserveError, VecDeque};
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use crate::conntrack::{R2oConntrackInfo, R2oConntrackTuple, tuple_from_socket_addrs};
use crate::flow_capacity::R2oFlowCapacity;

const TCP_STALL_PACKET_BUDGET: u64 = 25;
const TCP_STALL_PACKET_SLACK: u64 = 3;
const TCP_STALL_BUDGETS_MAX: usize = 8;
const TCP_HELLO_WINDOW: u32 = 8;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TcpEndpoint {
    address: r2k_core::addr::Address,
    port: u16,
}

impl TcpEndpoint {
    fn order_key(self) -> (u8, [u8; 16], u16) {
        (self.address.family(), self.address.bytes(), self.port)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TcpFlowKey {
    low: TcpEndpoint,
    high: TcpEndpoint,
}

impl TcpFlowKey {
    fn from_packet(packet: &[u8]) -> Option<Self> {
        let view = PacketView::parse(packet)?;
        if view.protocol != 6 {
            return None;
        }
        let tcp = view.tcp_segment(packet)?;
        let source = TcpEndpoint {
            address: view.src,
            port: tcp.source_port,
        };
        let destination = TcpEndpoint {
            address: view.dst,
            port: tcp.destination_port,
        };
        Some(Self::from_endpoints(source, destination))
    }

    fn from_endpoints(source: TcpEndpoint, destination: TcpEndpoint) -> Self {
        if source.order_key() <= destination.order_key() {
            Self {
                low: source,
                high: destination,
            }
        } else {
            Self {
                low: destination,
                high: source,
            }
        }
    }

    fn wire_key(self) -> [u8; KEY_LEN] {
        let mut key = [0; KEY_LEN];
        key[0] = self.low.address.family();
        key[1..17].copy_from_slice(&self.low.address.bytes());
        key[17..33].copy_from_slice(&self.high.address.bytes());
        key[33..35].copy_from_slice(&self.low.port.to_be_bytes());
        key[35..37].copy_from_slice(&self.high.port.to_be_bytes());
        key[37] = 6;
        key
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Накопленные счётчики пакетов и сетевых байтов по направлениям TCP-потока.
pub struct R2oTcpFlowMetrics {
    /// Число пакетов от стороны, начавшей поток.
    pub forward_packets: u32,
    /// Число пакетов от обратной стороны потока.
    pub reverse_packets: u32,
    /// Суммарная длина IP-пакетов в прямом направлении.
    pub forward_bytes: u64,
    /// Суммарная длина IP-пакетов в обратном направлении.
    pub reverse_bytes: u64,
}

struct TcpSession {
    initiator: TcpEndpoint,
    direction_known: bool,
    controller_probe: bool,
    r2o_http_requests: r2k_core::httpup::R2oHttpRequestSequence,
    metrics: R2oTcpFlowMetrics,
    reverse_ttl: Option<u8>,
    client_offered_tcp_timestamps: Option<bool>,
    guards: u8,
    execution_id: u64,
    r2o_execution_pending: bool,
    damaged: bool,
    first_syn: Option<Instant>,
    rtt: Option<Duration>,
    hello_at: Option<Instant>,
    hello_seq: Option<u32>,
    hello_repeats: u8,
    repeat_reported: bool,
    hello_ack: Option<u32>,
    reverse_seen: bool,
    reverse_syn_ack_seen: bool,
    response_payload: bool,
    reverse_tls_app_data: bool,
    reverse_server_hello: bool,
    reverse_tls_reply: bool,
    reverse_payload_bytes_after_hello: u32,
    reverse_packets_after_hello: u32,
    reverse_first_record_type: u8,
    reverse_record_types: u8,
    exchange_told: bool,
    appdata_told: bool,
    plan_done: bool,
    reverse_rst: bool,
    hello_has_sni: bool,
    forward_data_packets: u32,
    reverse_data_packets: u32,
    silence_reported: bool,
    conntrack_reply_packets: Option<u64>,
    conntrack_reply_at: Option<Instant>,
    conntrack_original_mark: u64,
    stall_watch_off: bool,
    stall_reported: bool,
    pending_fin_at: Option<Instant>,
    pending_fin_sequence_end: Option<u32>,
    fin_retry_queued: bool,
    fin_retry_reported: bool,
    rst_cut_reported: bool,
    r2o_reply_hidden_reported: bool,
    client_shape: u8,
    last_seen: Instant,
}

impl TcpSession {
    fn new(
        initiator: TcpEndpoint,
        direction_known: bool,
        first_syn: Option<Instant>,
        now: Instant,
    ) -> Self {
        Self {
            initiator,
            direction_known,
            controller_probe: false,
            r2o_http_requests: r2k_core::httpup::R2oHttpRequestSequence::default(),
            metrics: R2oTcpFlowMetrics::default(),
            reverse_ttl: None,
            client_offered_tcp_timestamps: None,
            guards: 0,
            execution_id: 0,
            r2o_execution_pending: false,
            damaged: false,
            first_syn,
            rtt: None,
            hello_at: None,
            hello_seq: None,
            hello_repeats: 0,
            repeat_reported: false,
            hello_ack: None,
            reverse_seen: false,
            reverse_syn_ack_seen: false,
            response_payload: false,
            reverse_tls_app_data: false,
            reverse_server_hello: false,
            reverse_tls_reply: false,
            reverse_payload_bytes_after_hello: 0,
            reverse_packets_after_hello: 0,
            reverse_first_record_type: 0,
            reverse_record_types: 0,
            exchange_told: false,
            appdata_told: false,
            plan_done: false,
            reverse_rst: false,
            hello_has_sni: false,
            forward_data_packets: 0,
            reverse_data_packets: 0,
            silence_reported: false,
            conntrack_reply_packets: None,
            conntrack_reply_at: None,
            conntrack_original_mark: 0,
            stall_watch_off: false,
            stall_reported: false,
            pending_fin_at: None,
            pending_fin_sequence_end: None,
            fin_retry_queued: false,
            fin_retry_reported: false,
            rst_cut_reported: false,
            r2o_reply_hidden_reported: false,
            client_shape: 0,
            last_seen: now,
        }
    }
}

/// Уровень ответного TCP-обмена, собранный по пакетам одного потока.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oTcpExchangeEvent {
    /// Канонический ключ TCP-потока.
    pub key: [u8; KEY_LEN],
    /// Тип первой TLS-записи в ответе сервера.
    pub code: u8,
    /// Число байтов ответа после ClientHello на момент события.
    pub num: u32,
    /// Набор встреченных типов TLS-записей: биты для типов 20–23.
    pub tos: u8,
    /// Был ли разобран ServerHello.
    pub server_hello: bool,
    /// Выполнялся ли к этому потоку план: 1 — да, 2 — нет.
    pub planned: u8,
}

/// Отпечаток чужого RST, снятого защитой до первого ответа после ClientHello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oTcpRstCutEvent {
    /// Канонический ключ TCP-потока.
    pub key: [u8; KEY_LEN],
    /// TTL снятого пакета и первого обратного пакета этого потока.
    pub ttl: u8,
    pub reference_ttl: u8,
    /// Поля IP-заголовка снятого RST.
    pub traffic_class: u8,
    pub ip_id: u16,
    /// Был ли замечен ServerHello до сброса.
    pub server_hello: bool,
    /// Был ли успешно применён план к этому потоку: 1 — да, 2 — нет.
    pub planned: u8,
    /// Наблюдавшаяся форма ClientHello.
    pub client_shape: u8,
    /// Направление клиента в каноническом ключе.
    pub client_is_low: bool,
}

/// Отпечаток первого обратного RST после ClientHello, который пропущен дальше.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oTcpRstEvent {
    /// Канонический ключ TCP-потока.
    pub key: [u8; KEY_LEN],
    pub ttl: u8,
    pub reference_ttl: u8,
    pub traffic_class: u8,
    pub ip_id: u16,
    pub server_hello: bool,
    /// 1 — план исполнен, 2 — план не исполнен.
    pub planned: u8,
    /// Наблюдавшаяся форма ClientHello.
    pub client_shape: u8,
    pub client_is_low: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oTcpRepeatEvent {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
    pub planned: bool,
}

impl R2oTcpExchangeEvent {
    pub const PLANNED_YES: u8 = 1;
    pub const PLANNED_NO: u8 = 2;
}

/// Итоговые счётчики разбора HTTP keep-alive в потоках TCP.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oHttpKeepAliveStats {
    /// Число распознанных запросов после первого запроса потока.
    pub later: u64,
    /// Число неоднозначных или пропущенных границ запросов.
    pub unaligned: u64,
    /// Число запросов без известного конца тела.
    pub open_end: u64,
}

/// Счётчики TCP-нагрузки, не распознанной как ClientHello.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oTcpPayloadStats {
    /// Пакеты с нагрузкой в обратном направлении.
    pub reverse: u64,
    /// Прямые пакеты с нагрузкой после распознанного ClientHello.
    pub after_hello: u64,
    /// Прямые пакеты, пришедшие после окна поиска ClientHello.
    pub late: u64,
    /// Прямые пакеты в окне, которые не разобраны как ClientHello или HTTP.
    pub not_hello: u64,
    /// Первый байт последней нагрузки, не распознанной как ClientHello.
    pub last_first_byte: u8,
    /// ClientHello распознан, но SNI и конец TLS-записи ещё не видны.
    pub sni_next_seg: u64,
}

#[derive(Clone, Copy)]
struct TrackedTcpPacket {
    key: TcpFlowKey,
    reverse: bool,
    flags: u8,
    keep_fin_session: bool,
    hello_was_seen: bool,
    tls_parse_attempted: bool,
    tls_is_client_hello: bool,
    sni_next_segment: bool,
    forward_packet_count: u32,
    first_payload_byte: Option<u8>,
    controller_probe: bool,
}

/// Ограниченное состояние потока для runtime-защит и очистки соединений.
pub struct TcpSessions {
    flows: HashMap<TcpFlowKey, TcpSession>,
    flow_capacity: R2oFlowCapacity,
    tcp_flow_refusals: u64,
    http_keepalive_stats: R2oHttpKeepAliveStats,
    tcp_payload_stats: R2oTcpPayloadStats,
    tcp_stall_budgets: Vec<u16>,
    reverse_visible_by_family: [bool; 2],
    r2o_tcp_hello_flows: u64,
    r2o_reply_hidden: u64,
    tcp_exchange_events: VecDeque<R2oTcpExchangeEvent>,
    tcp_rst_events: VecDeque<R2oTcpRstEvent>,
    tcp_repeat_events: VecDeque<R2oTcpRepeatEvent>,
    tcp_rst_cut_events: VecDeque<R2oTcpRstCutEvent>,
    fin_retry_events: VecDeque<R2oTcpFinRetryEvent>,
    rst_after_app_events: VecDeque<R2oTcpRstAfterAppEvent>,
}

impl Default for TcpSessions {
    fn default() -> Self {
        Self::try_with_capacity(R2oFlowCapacity::default())
            .expect("не удалось выделить таблицу TCP-потоков r2o")
    }
}

impl TcpSessions {
    /// Создать таблицу TCP-потоков заданного размера с проверкой выделения памяти.
    pub fn try_with_capacity(flow_capacity: R2oFlowCapacity) -> Result<Self, TryReserveError> {
        let mut flows = HashMap::new();
        flows.try_reserve(flow_capacity.slots())?;
        let mut tcp_exchange_events = VecDeque::new();
        tcp_exchange_events.try_reserve(flow_capacity.slots().saturating_mul(2))?;
        let mut tcp_rst_events = VecDeque::new();
        tcp_rst_events.try_reserve(flow_capacity.slots())?;
        let mut tcp_repeat_events = VecDeque::new();
        tcp_repeat_events.try_reserve(flow_capacity.slots())?;
        let mut tcp_rst_cut_events = VecDeque::new();
        tcp_rst_cut_events.try_reserve(flow_capacity.slots())?;
        Ok(Self {
            flows,
            flow_capacity,
            tcp_flow_refusals: 0,
            http_keepalive_stats: R2oHttpKeepAliveStats::default(),
            tcp_payload_stats: R2oTcpPayloadStats::default(),
            tcp_stall_budgets: vec![TCP_STALL_PACKET_BUDGET as u16],
            reverse_visible_by_family: [false; 2],
            r2o_tcp_hello_flows: 0,
            r2o_reply_hidden: 0,
            tcp_exchange_events,
            tcp_rst_events,
            tcp_repeat_events,
            tcp_rst_cut_events,
            fin_retry_events: VecDeque::new(),
            rst_after_app_events: VecDeque::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn r2o_tcp_flow_capacity(&self) -> usize {
        self.flow_capacity.slots()
    }

    pub fn r2o_tcp_flow_refusals(&self) -> u64 {
        self.tcp_flow_refusals
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Заменить набор порогов «зависания на бюджете»; пустой список сбрасывает полевой порог.
    pub fn set_tcp_stall_budgets(&mut self, budgets: &[u16]) -> Result<(), &'static str> {
        if budgets.len() > TCP_STALL_BUDGETS_MAX || budgets.contains(&0) {
            return Err("для бюджета TCP допустимы не более восьми ненулевых значений");
        }
        self.tcp_stall_budgets.clear();
        if budgets.is_empty() {
            self.tcp_stall_budgets.push(TCP_STALL_PACKET_BUDGET as u16);
        } else {
            self.tcp_stall_budgets.extend_from_slice(budgets);
        }
        Ok(())
    }

    /// Возвращает счётчики активного потока по его ключу сетевого протокола.
    pub fn r2o_flow_metrics(&self, key: &[u8; KEY_LEN]) -> Option<R2oTcpFlowMetrics> {
        self.flows.iter().find_map(|(flow_key, session)| {
            (flow_key.wire_key() == *key && !session.controller_probe).then_some(session.metrics)
        })
    }

    /// Вернуть признак TCP timestamp option из начального SYN клиентской стороны.
    pub fn r2o_client_offers_tcp_timestamps_for_packet(&self, packet: &[u8]) -> Option<bool> {
        let key = TcpFlowKey::from_packet(packet)?;
        self.flows
            .get(&key)
            .filter(|session| !session.controller_probe)
            .and_then(|session| session.client_offered_tcp_timestamps)
    }

    /// Обновить предварительную форму ClientHello после полной сборки захвата.
    pub fn r2o_note_captured_client_shape(&mut self, packet: &[u8], shape: u8) -> bool {
        if shape != r2k_core::control::SHAPE_ECH_TCP {
            return false;
        }
        let Some(key) = TcpFlowKey::from_packet(packet) else {
            return false;
        };
        let Some(session) = self.flows.get_mut(&key) else {
            return false;
        };
        if session.client_shape != r2k_core::control::SHAPE_MODERN {
            return false;
        }
        session.client_shape = r2k_core::control::SHAPE_ECH_TCP;
        true
    }

    /// Проверить, наблюдалось ли обратное TCP-рукопожатие для пакета.
    pub fn r2o_syn_ack_seen_for_packet(&self, packet: &[u8]) -> bool {
        let Some(view) = PacketView::parse(packet).filter(|view| view.protocol == 6) else {
            return false;
        };
        let Some(tcp) = view.tcp_segment(packet) else {
            return false;
        };
        let source = TcpEndpoint {
            address: view.src,
            port: tcp.source_port,
        };
        let destination = TcpEndpoint {
            address: view.dst,
            port: tcp.destination_port,
        };
        let key = if source.order_key() <= destination.order_key() {
            TcpFlowKey {
                low: source,
                high: destination,
            }
        } else {
            TcpFlowKey {
                low: destination,
                high: source,
            }
        };
        self.flows
            .get(&key)
            .is_some_and(|session| session.reverse_syn_ack_seen)
    }

    pub fn r2o_http_keepalive_stats(&self) -> R2oHttpKeepAliveStats {
        self.http_keepalive_stats
    }

    pub fn r2o_tcp_payload_stats(&self) -> R2oTcpPayloadStats {
        self.tcp_payload_stats
    }

    /// Число распознанных пользовательских TCP-потоков с ClientHello.
    pub fn r2o_tcp_hello_flows(&self) -> u64 {
        self.r2o_tcp_hello_flows
    }

    /// Число потоков, где ACK указал на невидимый очереди ответ сервера.
    pub fn r2o_reply_hidden(&self) -> u64 {
        self.r2o_reply_hidden
    }

    pub fn take_tcp_exchange_events(&mut self) -> Vec<R2oTcpExchangeEvent> {
        self.tcp_exchange_events.drain(..).collect()
    }

    pub fn take_tcp_rst_events(&mut self) -> Vec<R2oTcpRstEvent> {
        self.tcp_rst_events.drain(..).collect()
    }

    pub fn take_tcp_repeat_events(&mut self) -> Vec<R2oTcpRepeatEvent> {
        self.tcp_repeat_events.drain(..).collect()
    }

    pub fn take_tcp_rst_cut_events(&mut self) -> Vec<R2oTcpRstCutEvent> {
        self.tcp_rst_cut_events.drain(..).collect()
    }

    pub fn mark_plan_done(&mut self, key: &[u8; KEY_LEN]) {
        if let Some((_, session)) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)
        {
            session.r2o_execution_pending = false;
            session.plan_done = true;
        }
    }

    /// Привязать попытку отправки к текущему поколению TCP-потока.
    pub fn r2o_begin_execution(
        &mut self,
        packet: &[u8],
        execution_id: u64,
    ) -> Option<[u8; KEY_LEN]> {
        if execution_id == 0 {
            return None;
        }
        let key = TcpFlowKey::from_packet(packet)?;
        let session = self.flows.get_mut(&key)?;
        if session.damaged {
            return None;
        }
        session.execution_id = execution_id;
        session.r2o_execution_pending = true;
        Some(key.wire_key())
    }

    /// Проверить, испорчено ли текущее поколение TCP-потока.
    pub fn r2o_is_damaged_packet(&self, packet: &[u8]) -> bool {
        TcpFlowKey::from_packet(packet)
            .and_then(|key| self.flows.get(&key))
            .is_some_and(|session| session.damaged)
    }

    /// Проверить, что отложенная посылка относится к активному исполнению.
    pub fn r2o_send_pending(&self, key: &[u8; KEY_LEN], execution_id: u64) -> bool {
        self.flows
            .iter()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)
            .is_some_and(|(_, session)| {
                execution_id != 0
                    && session.execution_id == execution_id
                    && session.r2o_execution_pending
                    && !session.damaged
            })
    }

    /// Зачесть завершение только той попытке, которая ещё принадлежит потоку.
    pub fn r2o_mark_plan_done_for_execution(
        &mut self,
        key: &[u8; KEY_LEN],
        execution_id: u64,
    ) -> bool {
        let Some((_, session)) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)
        else {
            return false;
        };
        if execution_id == 0
            || session.execution_id != execution_id
            || !session.r2o_execution_pending
            || session.damaged
        {
            return false;
        }
        session.plan_done = true;
        session.r2o_execution_pending = false;
        true
    }

    /// Снять ожидание попытки, которая завершилась без порчи потока.
    pub fn r2o_mark_execution_failed_for_execution(
        &mut self,
        key: &[u8; KEY_LEN],
        execution_id: u64,
    ) -> bool {
        let Some((_, session)) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)
        else {
            return false;
        };
        if execution_id == 0 || session.execution_id != execution_id || session.damaged {
            return false;
        }
        session.r2o_execution_pending = false;
        true
    }

    /// Пометить поток испорченным после частичной отправки полезной нагрузки.
    pub fn r2o_mark_damaged_for_execution(
        &mut self,
        key: &[u8; KEY_LEN],
        execution_id: u64,
    ) -> bool {
        let Some((_, session)) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)
        else {
            return false;
        };
        if execution_id == 0 || session.execution_id != execution_id || session.damaged {
            return false;
        }
        session.damaged = true;
        session.r2o_execution_pending = false;
        session.guards = 0;
        true
    }

    pub fn expire(&mut self, now: Instant, idle: Duration) -> usize {
        self.expire_with_silent(now, idle, |_| {})
    }

    /// Сообщить о ClientHello без ответа перед удалением устаревшего потока.
    pub fn expire_with_silent(
        &mut self,
        now: Instant,
        idle: Duration,
        mut on_silent: impl FnMut(R2oTcpSilenceEvent),
    ) -> usize {
        let reverse_visible_by_family = self.reverse_visible_by_family;
        let before = self.flows.len();
        self.flows.retain(|key, session| {
            let idle_expired = now.saturating_duration_since(session.last_seen) >= idle;
            let fin_expired = session.pending_fin_at.is_some_and(|started| {
                now.checked_duration_since(started)
                    .is_some_and(|elapsed| elapsed >= fin_retry_window(session.rtt))
            });

            if idle_expired && !fin_expired {
                let family_index = match key.low.address.family() {
                    4 => Some(0),
                    6 => Some(1),
                    _ => None,
                };
                if !session.controller_probe
                    && family_index.is_some_and(|index| reverse_visible_by_family[index])
                    && !session.silence_reported
                    && session.reverse_packets_after_hello == 0
                    && let Some(hello_at) = session.hello_at
                {
                    let elapsed = now.saturating_duration_since(hello_at);
                    on_silent(R2oTcpSilenceEvent {
                        key: key.wire_key(),
                        client_is_low: session.initiator == key.low,
                        planned: session.plan_done,
                        elapsed_ms: elapsed.as_millis().min(u128::from(u32::MAX)) as u32,
                    });
                }
            }

            !idle_expired && !fin_expired
        });
        before - self.flows.len()
    }

    pub fn fin_retry_candidates(&self) -> Vec<R2oTcpFinRetryEvent> {
        self.fin_retry_events.iter().cloned().collect()
    }

    pub fn mark_fin_retry(&mut self, key: &[u8; KEY_LEN]) {
        self.fin_retry_events.retain(|event| event.key != *key);
        if let Some((_, session)) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)
        {
            session.fin_retry_queued = false;
            session.fin_retry_reported = true;
        }
    }

    pub fn rst_after_app_candidates(&self) -> Vec<R2oTcpRstAfterAppEvent> {
        self.rst_after_app_events.iter().cloned().collect()
    }

    pub fn mark_rst_after_app(&mut self, key: &[u8; KEY_LEN]) {
        self.rst_after_app_events.retain(|event| event.key != *key);
    }

    pub fn sweep_silent(
        &mut self,
        now: Instant,
        reverse_queue_visible: bool,
    ) -> Vec<R2oTcpSilenceEvent> {
        if !reverse_queue_visible {
            return Vec::new();
        }
        let mut events = Vec::new();
        for (key, session) in &mut self.flows {
            let Some(hello_at) = session.hello_at else {
                continue;
            };
            if session.silence_reported
                || session.controller_probe
                || !session.reverse_seen
                || session.response_payload
                || session.reverse_rst
                || now < hello_at
            {
                continue;
            }
            let elapsed = now.duration_since(hello_at);
            let deadline = session.rtt.map_or(Duration::from_secs(2), |rtt| {
                rtt.saturating_mul(8)
                    .clamp(Duration::from_secs(1), Duration::from_secs(5))
            });
            if elapsed < deadline {
                continue;
            }
            events.push(R2oTcpSilenceEvent {
                key: key.wire_key(),
                client_is_low: session.initiator == key.low,
                planned: session.plan_done,
                elapsed_ms: elapsed.as_millis().min(u128::from(u32::MAX)) as u32,
            });
        }
        events
    }

    pub fn mark_silent(&mut self, key: &[u8; KEY_LEN]) {
        if let Some((_, session)) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)
        {
            session.silence_reported = true;
        }
    }

    #[cfg(target_os = "linux")]
    pub fn tcp_stall_candidates(&self) -> Vec<R2oTcpStallProbe> {
        self.flows
            .iter()
            .filter_map(|(key, session)| {
                if !session.direction_known
                    || session.controller_probe
                    || !session.hello_has_sni
                    || !session.response_payload
                    || session.reverse_rst
                    || session.guards != 0
                    || session.stall_watch_off
                    || session.stall_reported
                {
                    return None;
                }
                let server = if session.initiator == key.low {
                    key.high
                } else {
                    key.low
                };
                let client_addr = SocketAddr::new(
                    session.initiator.address.as_ip_addr(),
                    session.initiator.port,
                );
                let server_addr = SocketAddr::new(server.address.as_ip_addr(), server.port);
                Some(R2oTcpStallProbe {
                    key: key.wire_key(),
                    tuple: tuple_from_socket_addrs(client_addr, server_addr)?,
                })
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    pub fn update_tcp_stall(
        &mut self,
        now: Instant,
        key: &[u8; KEY_LEN],
        info: R2oConntrackInfo,
    ) -> Option<R2oTcpStallEvent> {
        let (flow_key, session) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)?;
        if session.stall_watch_off || session.stall_reported || session.guards != 0 {
            return None;
        }
        let Some(state) = info.tcp_state else {
            return None;
        };
        if state != 3 {
            session.stall_watch_off = true;
            return None;
        }

        let unseen = info
            .reply_packets
            .saturating_sub(u64::from(session.metrics.reverse_packets));
        let estimate = u64::from(session.forward_data_packets)
            .saturating_add(u64::from(session.reverse_data_packets))
            .saturating_add(unseen);
        let band_top = u64::from(
            self.tcp_stall_budgets
                .iter()
                .copied()
                .max()
                .unwrap_or(TCP_STALL_PACKET_BUDGET as u16),
        ) + TCP_STALL_PACKET_SLACK;
        if estimate > band_top {
            session.stall_watch_off = true;
            return None;
        }
        if session.conntrack_reply_packets != Some(info.reply_packets) {
            session.conntrack_reply_packets = Some(info.reply_packets);
            session.conntrack_original_mark = info.original_packets;
            session.conntrack_reply_at = Some(now);
            return None;
        }
        if unseen == 0
            || info
                .original_packets
                .saturating_sub(session.conntrack_original_mark)
                < 3
        {
            return None;
        }
        let reply_at = session.conntrack_reply_at?;
        let elapsed = now.checked_duration_since(reply_at)?;
        let rto = session
            .rtt
            .map_or(Duration::ZERO, |rtt| rtt.saturating_mul(3))
            .max(Duration::from_secs(2));
        let inside_budget = self.tcp_stall_budgets.iter().any(|budget| {
            estimate.saturating_add(TCP_STALL_PACKET_SLACK) >= u64::from(*budget)
                && estimate <= u64::from(*budget) + TCP_STALL_PACKET_SLACK
        });
        if elapsed < rto || !inside_budget {
            return None;
        }
        Some(R2oTcpStallEvent {
            key: flow_key.wire_key(),
            client_is_low: session.initiator == flow_key.low,
            elapsed_ms: elapsed.as_millis().min(u128::from(u32::MAX)) as u32,
            estimated_packets: estimate.min(u64::from(u32::MAX)) as u32,
            planned: session.plan_done,
        })
    }

    pub fn mark_tcp_stall(&mut self, key: &[u8; KEY_LEN]) {
        if let Some((_, session)) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)
        {
            session.stall_reported = true;
        }
    }

    #[cfg(test)]
    fn track_packet(&mut self, packet: &[u8], now: Instant) -> Option<TrackedTcpPacket> {
        self.track_packet_mode(packet, now, false)
    }

    fn track_packet_mode(
        &mut self,
        packet: &[u8],
        now: Instant,
        controller_probe: bool,
    ) -> Option<TrackedTcpPacket> {
        let view = PacketView::parse(packet)?;
        if view.protocol != 6 {
            return None;
        }
        let tcp = view.tcp_segment(packet)?;
        let source = TcpEndpoint {
            address: view.src,
            port: tcp.source_port,
        };
        let destination = TcpEndpoint {
            address: view.dst,
            port: tcp.destination_port,
        };
        let key = TcpFlowKey::from_endpoints(source, destination);
        let syn = tcp.flags & 0x02 != 0;
        let ack = tcp.flags & 0x10 != 0;
        let rst = tcp.flags & 0x04 != 0;
        let fin = tcp.flags & 0x01 != 0;
        let new_connection = syn && !ack;
        let payload = packet.get(tcp.payload.clone()).unwrap_or_default();

        if new_connection {
            if !self.flows.contains_key(&key) && self.flows.len() >= self.flow_capacity.limit() {
                self.tcp_flow_refusals = self.tcp_flow_refusals.wrapping_add(1);
                return None;
            }
            let metrics = self
                .flows
                .get(&key)
                .map_or_else(R2oTcpFlowMetrics::default, |session| session.metrics);
            let mut session = TcpSession::new(source, true, Some(now), now);
            session.controller_probe = controller_probe;
            session.client_offered_tcp_timestamps =
                Some(crate::capture::tcp_timestamp_option_present(
                    packet.get(tcp.options.clone()).unwrap_or_default(),
                ));
            if destination.port == 80 {
                session.r2o_http_requests =
                    r2k_core::httpup::R2oHttpRequestSequence::new(tcp.sequence.wrapping_add(1));
            }
            session.metrics = metrics;
            self.flows.insert(key, session);
        } else if !self.flows.contains_key(&key) {
            if self.flows.len() >= self.flow_capacity.limit() {
                self.tcp_flow_refusals = self.tcp_flow_refusals.wrapping_add(1);
                return None;
            }
            let initiator = if syn && ack { destination } else { source };
            self.flows
                .insert(key, TcpSession::new(initiator, syn && ack, None, now));
        }

        let reverse_visible_by_family = &mut self.reverse_visible_by_family;
        let r2o_tcp_hello_flows = &mut self.r2o_tcp_hello_flows;
        let r2o_reply_hidden = &mut self.r2o_reply_hidden;
        let family_index = match key.low.address.family() {
            4 => Some(0),
            6 => Some(1),
            _ => None,
        };
        let session = self.flows.get_mut(&key)?;
        if controller_probe {
            session.controller_probe = true;
        }
        let controller_probe = session.controller_probe;
        let hello_was_seen = session.hello_at.is_some();
        let reverse_tls_app_data_before_packet = session.reverse_tls_app_data;
        let reverse_packets_after_hello_before_packet = session.reverse_packets_after_hello;
        let reverse_ttl_before_packet = session.reverse_ttl;
        if syn && ack && !session.direction_known {
            session.initiator = destination;
            session.direction_known = true;
        }
        let reverse_before_hello = source != session.initiator;
        let forward_packet_count_before_hello = if session.direction_known {
            session
                .metrics
                .forward_packets
                .saturating_add(u32::from(!reverse_before_hello))
        } else {
            session
                .metrics
                .forward_packets
                .saturating_add(session.metrics.reverse_packets)
                .saturating_add(1)
        };
        let tls_parse_attempted = !hello_was_seen
            && !rst
            && !fin
            && (!reverse_before_hello || !session.direction_known)
            && !payload.is_empty()
            && forward_packet_count_before_hello <= TCP_HELLO_WINDOW;
        let hello = if tls_parse_attempted {
            let parsed = r2k_core::tls::parse(payload);
            parsed.is_client_hello.then_some(parsed)
        } else {
            None
        };
        let sni_next_segment = hello
            .as_ref()
            .is_some_and(|parsed| parsed.sni_range.is_none() && parsed.record_end.is_none());
        let tls_is_client_hello = hello.is_some();
        if let Some(hello) = hello {
            if !session.direction_known {
                if source != session.initiator {
                    std::mem::swap(
                        &mut session.metrics.forward_packets,
                        &mut session.metrics.reverse_packets,
                    );
                    std::mem::swap(
                        &mut session.metrics.forward_bytes,
                        &mut session.metrics.reverse_bytes,
                    );
                    std::mem::swap(
                        &mut session.forward_data_packets,
                        &mut session.reverse_data_packets,
                    );
                    session.reverse_seen = session.metrics.reverse_packets != 0;
                    if !controller_probe
                        && session.reverse_seen
                        && let Some(index) = family_index
                    {
                        reverse_visible_by_family[index] = true;
                    }
                    session.reverse_ttl = None;
                    session.reverse_rst = false;
                }
                session.initiator = source;
                session.direction_known = true;
            }
            session.hello_at = Some(now);
            session.hello_seq = Some(tcp.sequence);
            if !controller_probe {
                *r2o_tcp_hello_flows = (*r2o_tcp_hello_flows).wrapping_add(1);
            }
            session.hello_ack = ack.then_some(tcp.acknowledgment);
            session.hello_has_sni = hello.sni_range.is_some();
            session.client_shape = if session.hello_has_sni {
                if hello.is_tls13 {
                    if hello.ech_offer {
                        r2k_core::control::SHAPE_ECH_TCP
                    } else {
                        r2k_core::control::SHAPE_MODERN
                    }
                } else if !hello.extensions_truncated {
                    r2k_core::control::SHAPE_LEGACY
                } else {
                    0
                }
            } else {
                0
            };
        }
        session.last_seen = now;
        let reverse = source != session.initiator;
        let packet_bytes = view.total_len as u64;
        if reverse {
            if !controller_probe && let Some(index) = family_index {
                reverse_visible_by_family[index] = true;
            }
            session.metrics.reverse_packets = session.metrics.reverse_packets.saturating_add(1);
            session.metrics.reverse_bytes =
                session.metrics.reverse_bytes.saturating_add(packet_bytes);
            session.reverse_seen = true;
            session.reverse_syn_ack_seen |= syn && ack;
            if session.hello_at.is_some() {
                session.reverse_packets_after_hello =
                    session.reverse_packets_after_hello.saturating_add(1);
            }
            if syn && ack && session.rtt.is_none() {
                session.rtt = session
                    .first_syn
                    .and_then(|first_syn| now.checked_duration_since(first_syn));
            }
            if session.reverse_ttl.is_none() {
                session.reverse_ttl = Some(view.hop_limit);
            }
            if !payload.is_empty() {
                session.reverse_data_packets = session.reverse_data_packets.saturating_add(1);
            }
            if session.hello_at.is_some() && !payload.is_empty() {
                session.response_payload = true;
                session.reverse_payload_bytes_after_hello = session
                    .reverse_payload_bytes_after_hello
                    .saturating_add(payload.len().min(u32::MAX as usize) as u32);
                session.reverse_tls_app_data |= payload.first() == Some(&0x17);
                let response_tls = r2k_core::tls::parse(payload);
                session.reverse_server_hello |= response_tls.is_server_hello;
                session.reverse_tls_reply |= response_tls.is_server_hello
                    || (response_tls.is_tls_record
                        && response_tls.record_type == 23
                        && response_tls.record_end.is_some_and(|end| end > 5)
                        && payload.get(2).is_some_and(|minor| *minor <= 3));
                if session.reverse_first_record_type == 0 {
                    session.reverse_first_record_type = payload[0];
                }
                if (20..=23).contains(&payload[0]) {
                    session.reverse_record_types |= 1 << (payload[0] - 20);
                }
                let has_application_data = session.reverse_record_types & (1 << 3) != 0;
                if !session.exchange_told || (!session.appdata_told && has_application_data) {
                    session.exchange_told = true;
                    session.appdata_told |= has_application_data;
                    let event = R2oTcpExchangeEvent {
                        key: key.wire_key(),
                        code: session.reverse_first_record_type,
                        num: session.reverse_payload_bytes_after_hello,
                        tos: session.reverse_record_types,
                        server_hello: session.reverse_server_hello,
                        planned: if session.plan_done {
                            R2oTcpExchangeEvent::PLANNED_YES
                        } else {
                            R2oTcpExchangeEvent::PLANNED_NO
                        },
                    };
                    if !controller_probe
                        && self.tcp_exchange_events.len()
                            < self.flow_capacity.slots().saturating_mul(2)
                    {
                        self.tcp_exchange_events.push_back(event);
                    }
                }
            }
            if tcp.flags & 0x04 != 0 {
                session.reverse_rst = true;
            }
        } else {
            if !payload.is_empty() {
                session.forward_data_packets = session.forward_data_packets.saturating_add(1);
            }
        }
        let mut repeat_event = None;
        if !controller_probe
            && !rst
            && !fin
            && hello_was_seen
            && !reverse
            && !payload.is_empty()
            && session.hello_seq == Some(tcp.sequence)
            && !session.reverse_tls_reply
            && !session.repeat_reported
        {
            session.hello_repeats = session.hello_repeats.saturating_add(1).min(2);
            if session.hello_repeats >= 2 {
                repeat_event = Some(R2oTcpRepeatEvent {
                    key: key.wire_key(),
                    client_is_low: session.initiator == key.low,
                    planned: session.plan_done,
                });
            }
        }
        if !reverse {
            session.metrics.forward_packets = session.metrics.forward_packets.saturating_add(1);
            session.metrics.forward_bytes =
                session.metrics.forward_bytes.saturating_add(packet_bytes);
        }
        if !controller_probe
            && !reverse
            && ack
            && !syn
            && !session.r2o_reply_hidden_reported
            && reverse_packets_after_hello_before_packet == 0
            && session
                .hello_ack
                .is_some_and(|hello_ack| (tcp.acknowledgment.wrapping_sub(hello_ack) as i32) > 0)
        {
            *r2o_reply_hidden = (*r2o_reply_hidden).wrapping_add(1);
            session.r2o_reply_hidden_reported = true;
        }
        let mut keep_fin_session = false;
        let mut fin_retry_event = None;
        let mut rst_after_app_event = None;
        let mut rst_event = None;
        let mut rst_cut_event = None;
        let rst_dropped = rst
            && reverse
            && session.guards & GUARD_RST_ALIEN != 0
            && reverse_ttl_before_packet.is_some_and(|reference| reference != view.hop_limit);
        if !controller_probe
            && rst
            && reverse
            && session.hello_at.is_some()
            && reverse_packets_after_hello_before_packet == 0
            && !rst_dropped
        {
            rst_event = Some(R2oTcpRstEvent {
                key: key.wire_key(),
                ttl: view.hop_limit,
                reference_ttl: reverse_ttl_before_packet.unwrap_or_default(),
                traffic_class: view.traffic_class,
                ip_id: view.ip_id,
                server_hello: session.reverse_server_hello,
                planned: if session.plan_done { 1 } else { 2 },
                client_shape: session.client_shape,
                client_is_low: session.initiator == key.low,
            });
        }
        if !controller_probe
            && rst
            && reverse
            && session.hello_at.is_some()
            && reverse_packets_after_hello_before_packet == 0
            && session.guards & GUARD_RST_ALIEN != 0
            && reverse_ttl_before_packet.is_some_and(|reference| reference != view.hop_limit)
            && !session.rst_cut_reported
        {
            rst_cut_event = Some(R2oTcpRstCutEvent {
                key: key.wire_key(),
                ttl: view.hop_limit,
                reference_ttl: reverse_ttl_before_packet.unwrap_or_default(),
                traffic_class: view.traffic_class,
                ip_id: view.ip_id,
                server_hello: session.reverse_server_hello,
                planned: if session.plan_done { 1 } else { 2 },
                client_shape: session.client_shape,
                client_is_low: session.initiator == key.low,
            });
        }
        if !controller_probe
            && rst
            && session.hello_at.is_some()
            && reverse_tls_app_data_before_packet
        {
            rst_after_app_event = Some(R2oTcpRstAfterAppEvent {
                key: key.wire_key(),
                client_is_low: session.initiator == key.low,
                planned: session.plan_done,
            });
        }
        if fin
            && !rst
            && !reverse
            && session.hello_at.is_some()
            && (session.plan_done || !controller_probe)
        {
            let ack_beyond_response =
                ack && session.hello_ack.is_some_and(|hello_ack| {
                    let acknowledged = tcp.acknowledgment.wrapping_sub(hello_ack);
                    (acknowledged as i32) > 0
                        && acknowledged > session.reverse_payload_bytes_after_hello
                }) && session.reverse_server_hello;
            if session.reverse_tls_app_data || ack_beyond_response {
                let fin_sequence_end = tcp.sequence.wrapping_add(payload.len() as u32);
                let same_active_fin = session.pending_fin_sequence_end == Some(fin_sequence_end)
                    && session.pending_fin_at.is_some_and(|started| {
                        now.checked_duration_since(started)
                            .is_some_and(|elapsed| elapsed < fin_retry_window(session.rtt))
                    });
                if same_active_fin {
                    if !session.fin_retry_reported && !session.fin_retry_queued {
                        fin_retry_event = Some(R2oTcpFinRetryEvent {
                            key: key.wire_key(),
                            client_is_low: session.initiator == key.low,
                            planned: session.plan_done,
                        });
                    }
                } else {
                    session.pending_fin_at = Some(now);
                    session.pending_fin_sequence_end = Some(fin_sequence_end);
                }
                keep_fin_session = true;
            }
        }
        if !controller_probe && let Some(event) = fin_retry_event {
            let already_queued = self
                .fin_retry_events
                .iter()
                .any(|queued| queued.key == event.key);
            if already_queued {
                session.fin_retry_queued = true;
            } else if self.fin_retry_events.len() < self.flow_capacity.slots() {
                self.fin_retry_events.push_back(event);
                session.fin_retry_queued = true;
            }
        }
        if !controller_probe && let Some(event) = rst_after_app_event {
            let already_queued = self
                .rst_after_app_events
                .iter()
                .any(|queued| queued.key == event.key);
            if !already_queued && self.rst_after_app_events.len() < self.flow_capacity.slots() {
                self.rst_after_app_events.push_back(event);
            }
        }
        if !controller_probe
            && let Some(event) = rst_event
            && self.tcp_rst_events.len() < self.flow_capacity.slots()
        {
            self.tcp_rst_events.push_back(event);
        }
        if !controller_probe
            && let Some(event) = repeat_event
            && self.tcp_repeat_events.len() < self.flow_capacity.slots()
        {
            self.tcp_repeat_events.push_back(event);
            session.repeat_reported = true;
        }
        if !controller_probe
            && let Some(event) = rst_cut_event
            && self.tcp_rst_cut_events.len() < self.flow_capacity.slots()
        {
            self.tcp_rst_cut_events.push_back(event);
            session.rst_cut_reported = true;
        }
        Some(TrackedTcpPacket {
            key,
            reverse,
            flags: tcp.flags,
            keep_fin_session,
            hello_was_seen,
            tls_parse_attempted,
            tls_is_client_hello,
            sni_next_segment,
            forward_packet_count: session.metrics.forward_packets,
            first_payload_byte: (!rst && !fin).then(|| payload.first().copied()).flatten(),
            controller_probe,
        })
    }
}

fn fin_retry_window(rtt: Option<Duration>) -> Duration {
    rtt.map_or(Duration::from_secs(3), |rtt| {
        rtt.saturating_mul(9).max(Duration::from_secs(3))
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oTcpStallProbe {
    pub key: [u8; KEY_LEN],
    pub tuple: R2oConntrackTuple,
}

/// Применить план пакета с ограниченным состоянием TCP-потока для защит соединения.
pub fn decide_with_session(
    sessions: &mut TcpSessions,
    plan: &Plan,
    packet: &[u8],
) -> PacketDecision {
    decide_with_session_mode(sessions, plan, packet, false, 0)
}

/// Применить план в потоке зонда, не выдавая его за пользовательское наблюдение.
pub fn decide_with_session_probe(
    sessions: &mut TcpSessions,
    plan: &Plan,
    packet: &[u8],
) -> PacketDecision {
    decide_with_session_mode(sessions, plan, packet, true, 0)
}

/// Применить план с пределом TCP-посылки, вычисленным по MTU маршрута.
pub fn decide_with_session_mtu(
    sessions: &mut TcpSessions,
    plan: &Plan,
    packet: &[u8],
    tcp_segment_cap: usize,
) -> PacketDecision {
    decide_with_session_mode(sessions, plan, packet, false, tcp_segment_cap)
}

/// Применить план зонда с пределом TCP-посылки по MTU маршрута.
pub fn decide_with_session_probe_mtu(
    sessions: &mut TcpSessions,
    plan: &Plan,
    packet: &[u8],
    tcp_segment_cap: usize,
) -> PacketDecision {
    decide_with_session_mode(sessions, plan, packet, true, tcp_segment_cap)
}

fn decide_with_session_mode(
    sessions: &mut TcpSessions,
    plan: &Plan,
    packet: &[u8],
    controller_probe: bool,
    tcp_segment_cap: usize,
) -> PacketDecision {
    let now = Instant::now();
    let Some(tracked) = sessions.track_packet_mode(packet, now, controller_probe) else {
        let is_tcp = PacketView::parse(packet).is_some_and(|view| view.protocol == 6);
        if is_tcp && plan.transport == 6 && plan.proto == PROTO_HTTP {
            return PacketDecision::Accept;
        }
        return if is_tcp && plan.guards & GUARD_RST_ALIEN != 0 {
            PacketDecision::Accept
        } else {
            decide_packet_with_segment_cap(plan, packet, tcp_segment_cap, 0)
        };
    };
    let key = tracked.key;
    let reverse = tracked.reverse;
    let flags = tracked.flags;
    let keep_fin_session = tracked.keep_fin_session;

    let view = PacketView::parse(packet).expect("tracked TCP packet remains parseable");
    let rst = flags & 0x04 != 0;
    let fin = flags & 0x01 != 0;
    if rst
        && reverse
        && sessions.flows.get(&key).is_some_and(|session| {
            session.guards & GUARD_RST_ALIEN != 0
                && session
                    .reverse_ttl
                    .is_some_and(|reference| reference != view.hop_limit)
        })
    {
        return PacketDecision::Drop;
    }
    if rst || fin {
        if !keep_fin_session {
            sessions.flows.remove(&key);
        }
        return PacketDecision::Accept;
    }
    if sessions
        .flows
        .get(&key)
        .is_some_and(|session| session.damaged)
    {
        return PacketDecision::Accept;
    }

    let http_observation = view
        .tcp_segment(packet)
        .filter(|tcp| !reverse && tcp.destination_port == 80)
        .and_then(|tcp| {
            let payload = packet.get(tcp.payload.clone())?;
            if payload.is_empty() {
                return None;
            }
            Some(sessions.flows.get_mut(&key).map_or(
                r2k_core::httpup::R2oHttpRequestObservation::Ignored,
                |session| {
                    session
                        .r2o_http_requests
                        .observe_detailed(tcp.sequence, payload)
                },
            ))
        })
        .unwrap_or(r2k_core::httpup::R2oHttpRequestObservation::Ignored);
    let http_request = matches!(
        http_observation,
        r2k_core::httpup::R2oHttpRequestObservation::Request { .. }
    );
    if !tracked.controller_probe {
        match http_observation {
            r2k_core::httpup::R2oHttpRequestObservation::Request {
                later,
                end_known,
                aligned,
            } => {
                if later {
                    sessions.http_keepalive_stats.later =
                        sessions.http_keepalive_stats.later.saturating_add(1);
                }
                if !end_known {
                    sessions.http_keepalive_stats.open_end =
                        sessions.http_keepalive_stats.open_end.saturating_add(1);
                }
                if !aligned {
                    sessions.http_keepalive_stats.unaligned =
                        sessions.http_keepalive_stats.unaligned.saturating_add(1);
                }
            }
            r2k_core::httpup::R2oHttpRequestObservation::Unaligned => {
                sessions.http_keepalive_stats.unaligned =
                    sessions.http_keepalive_stats.unaligned.saturating_add(1);
            }
            r2k_core::httpup::R2oHttpRequestObservation::Ignored => {}
        }
    }
    if !tracked.controller_probe
        && let Some(first_byte) = tracked.first_payload_byte
    {
        if reverse {
            sessions.tcp_payload_stats.reverse =
                sessions.tcp_payload_stats.reverse.saturating_add(1);
        } else if tracked.hello_was_seen {
            sessions.tcp_payload_stats.after_hello =
                sessions.tcp_payload_stats.after_hello.saturating_add(1);
        } else if tracked.forward_packet_count > TCP_HELLO_WINDOW {
            sessions.tcp_payload_stats.late = sessions.tcp_payload_stats.late.saturating_add(1);
        } else if tracked.tls_parse_attempted && !tracked.tls_is_client_hello && !http_request {
            sessions.tcp_payload_stats.not_hello =
                sessions.tcp_payload_stats.not_hello.saturating_add(1);
            sessions.tcp_payload_stats.last_first_byte = first_byte;
        }
        if !reverse && tracked.sni_next_segment {
            sessions.tcp_payload_stats.sni_next_seg =
                sessions.tcp_payload_stats.sni_next_seg.saturating_add(1);
        }
    }
    let execution_state = sessions.flows.get(&key);
    if execution_state.is_some_and(|session| {
        (session.plan_done && !http_request) || (session.r2o_execution_pending && http_request)
    }) {
        return PacketDecision::Accept;
    }
    let r2o_http_plan = plan.transport == 6 && plan.proto == PROTO_HTTP;
    let r2o_http_plan_allowed = !r2o_http_plan || http_request;
    let decision = if !r2o_http_plan_allowed {
        PacketDecision::Accept
    } else {
        decide_packet_with_segment_cap(
            plan,
            packet,
            tcp_segment_cap,
            execution_state
                .and_then(|session| session.reverse_ttl)
                .unwrap_or(0),
        )
    };
    let applied = matches!(
        &decision,
        PacketDecision::Drop | PacketDecision::Replace(_) | PacketDecision::Transmit { .. }
    ) || (r2o_http_plan_allowed
        && plan.guards & GUARD_RST_ALIEN != 0
        && guard_plan_applies_without_emissions(plan, packet, tcp_segment_cap));
    if applied
        && !reverse
        && !rst
        && !fin
        && let Some(session) = sessions.flows.get_mut(&key)
    {
        session.guards = plan.guards;
    }
    if applied && matches!(&decision, PacketDecision::Accept | PacketDecision::Drop) {
        if let Some(session) = sessions.flows.get_mut(&key) {
            session.plan_done = true;
            session.r2o_execution_pending = false;
        }
    }
    decision
}

fn guard_plan_applies_without_emissions(
    plan: &Plan,
    packet: &[u8],
    tcp_segment_cap: usize,
) -> bool {
    let Some(view) = PacketView::parse(packet).filter(|view| view.protocol == 6) else {
        return false;
    };
    let Some(input) = tcp_plan_input(plan, packet, &view, tcp_segment_cap, 0) else {
        return false;
    };
    plan.apply(&input)
        .is_ok_and(|actions| actions.emits.is_empty() && actions.fate != OriginalFate::Hold)
}

fn tcp_plan_input<'a>(
    plan: &Plan,
    packet: &'a [u8],
    view: &PacketView,
    tcp_segment_cap: usize,
    reference_ttl: u8,
) -> Option<PacketInput<'a>> {
    if plan.transport != 6 || !matches!(plan.proto, 1 | PROTO_HTTP) {
        return None;
    }
    let tcp = view.tcp_segment(packet)?;
    let payload = packet
        .get(tcp.payload.clone())
        .filter(|bytes| !bytes.is_empty())?;

    let tls = r2k_core::tls::parse(payload);
    let http_host = r2k_core::httpup::request_host_range(payload);
    let is_http = http_host.is_some();
    if (plan.proto == PROTO_HTTP && !is_http) || (plan.proto != PROTO_HTTP && !tls.is_client_hello)
    {
        return None;
    }

    let mut input = PacketInput::new(payload, tcp.sequence);
    input.is_tls13 = tls.is_tls13;
    if let Some(range) =
        http_host.or_else(|| tls.sni_range.filter(|range| range.end <= payload.len()))
    {
        input.have_sni = true;
        input.sni_off = range.start;
        input.sni_len = range.len();
    }
    input.segment_cap = tcp_segment_cap;
    input.reference_ttl = reference_ttl;
    input.is_http = is_http;
    Some(input)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketDecision {
    Accept,
    Drop,
    Refused {
        plan_id: [u8; 16],
    },
    FlowUnfit {
        plan_id: [u8; 16],
    },
    Replace(Vec<u8>),
    Transmit {
        packets: Vec<WirePacket>,
        fate: OriginalFate,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WirePacket {
    pub packet: Vec<u8>,
    pub kind: EmitKind,
    pub delay_us: u32,
}

/// Применить план без состояния потока. Планы с защитами проходят без изменений;
/// для них демон должен использовать [`decide_with_session`].
pub fn decide(plan: &Plan, packet: &[u8]) -> PacketDecision {
    if plan.guards & GUARD_RST_ALIEN != 0 {
        return PacketDecision::Accept;
    }
    decide_packet_with_segment_cap(plan, packet, 0, 0)
}

fn decide_packet_with_segment_cap(
    plan: &Plan,
    packet: &[u8],
    tcp_segment_cap: usize,
    reference_ttl: u8,
) -> PacketDecision {
    let Some(view) = PacketView::parse(packet) else {
        return PacketDecision::Accept;
    };
    if view.protocol == 6 {
        return decide_tcp(plan, packet, &view, tcp_segment_cap, reference_ttl);
    }
    if view.protocol != 17 {
        return PacketDecision::Accept;
    }
    let Some(payload_range) = view.udp_payload_range(packet) else {
        return PacketDecision::Accept;
    };
    let payload = &packet[payload_range.clone()];

    if plan.transport == 17 && plan.proto == PROTO_VOICE {
        return decide_voice(plan, packet, &view, payload);
    }

    if plan.qdeny != 0 {
        return if is_authenticated_initial(payload) {
            PacketDecision::Drop
        } else {
            PacketDecision::Accept
        };
    }
    let clearance = plan.r2k_is_quic_clearance_probe();
    let ttl_probe = plan.r2k_is_quic_ttl_probe() || plan.r2k_is_quic_fallback_ttl_probe();
    let length_probe = plan.r2k_is_quic_udp_length_probe();
    let fragment_probe = plan.r2k_is_quic_ipfrag_plan();
    let fake_probe = plan.r2k_is_quic_fake_probe();
    if plan.qsplit == 0
        && !length_probe
        && !clearance
        && !ttl_probe
        && !fragment_probe
        && !fake_probe
    {
        return PacketDecision::Accept;
    }
    if (plan.qsplit != 0 || length_probe || clearance || ttl_probe || fragment_probe || fake_probe)
        && !is_authenticated_initial(payload)
    {
        return PacketDecision::Accept;
    }

    let mut input = PacketInput::new(payload, 0);
    input.own_after_fakes = clearance;
    let Ok(actions) = plan.apply(&input) else {
        return PacketDecision::Refused { plan_id: plan.id };
    };
    if fragment_probe {
        if actions.emits.len() != 1 || actions.emits[0].ipfrag != plan.ipfrag {
            return PacketDecision::Accept;
        }
        let emission = &actions.emits[0];
        let Some(fragments) = r2k_core::wire::build_udp_fragments(packet, emission) else {
            return PacketDecision::Accept;
        };
        let packets = fragments
            .into_iter()
            .map(|packet| WirePacket {
                packet,
                kind: emission.kind,
                delay_us: emission.delay_us,
            })
            .collect();
        return PacketDecision::Transmit {
            packets,
            fate: actions.fate,
        };
    }
    if actions.emits.len() == 1
        && !fake_probe
        && (plan.udplen != 0 || actions.emits[0].bytes.len() == payload.len())
    {
        let Some(replacement) =
            replace_udp_payload(packet, &view, &payload_range, &actions.emits[0].bytes)
        else {
            return PacketDecision::Accept;
        };
        return PacketDecision::Replace(replacement);
    }
    if (!clearance && !ttl_probe && !fake_probe)
        || actions.emits.is_empty()
        || ((!fake_probe) && actions.emits.len() != 2)
    {
        return PacketDecision::Accept;
    }
    let mut packets = Vec::with_capacity(actions.emits.len());
    for emission in &actions.emits {
        let mut wire = vec![0; emission.bytes.len().saturating_add(48)];
        let Some(length) = r2k_core::wire::build_udp_packet(packet, emission, &mut wire) else {
            return PacketDecision::Accept;
        };
        wire.truncate(length);
        packets.push(WirePacket {
            packet: wire,
            kind: emission.kind,
            delay_us: emission.delay_us,
        });
    }
    PacketDecision::Transmit {
        packets,
        fate: actions.fate,
    }
}

fn decide_voice(plan: &Plan, packet: &[u8], view: &PacketView, payload: &[u8]) -> PacketDecision {
    let Some(destination_port) = packet
        .get(view.l4_offset + 2..view.l4_offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
    else {
        return PacketDecision::Accept;
    };
    if !r2k_core::stun::is_discord_voice_request(payload, destination_port)
        && !r2k_core::stun::is_binding_request(payload)
    {
        return PacketDecision::Accept;
    }
    let Ok(actions) = plan.apply(&PacketInput::new(payload, 0)) else {
        return PacketDecision::Refused { plan_id: plan.id };
    };
    if actions.emits.is_empty() {
        return if actions.fate == OriginalFate::Drop {
            PacketDecision::Drop
        } else {
            PacketDecision::Accept
        };
    }

    let mut packets = Vec::with_capacity(actions.emits.len());
    for emission in &actions.emits {
        let mut wire = vec![0; emission.bytes.len().saturating_add(48)];
        let Some(length) = r2k_core::wire::build_udp_packet(packet, emission, &mut wire) else {
            return PacketDecision::Accept;
        };
        wire.truncate(length);
        packets.push(WirePacket {
            packet: wire,
            kind: emission.kind,
            delay_us: emission.delay_us,
        });
    }
    PacketDecision::Transmit {
        packets,
        fate: actions.fate,
    }
}

fn decide_tcp(
    plan: &Plan,
    packet: &[u8],
    view: &PacketView,
    tcp_segment_cap: usize,
    reference_ttl: u8,
) -> PacketDecision {
    let Some(input) = tcp_plan_input(plan, packet, view, tcp_segment_cap, reference_ttl) else {
        return PacketDecision::Accept;
    };

    if plan.wire_profile == r2k_core::plan::WIRE_TCP_TEMPLATE
        && plan.poison_used() & r2k_core::plan::POISON_TCPTS_BACK != 0
        && !input.is_http
        && let Some(tcp) = view.tcp_segment(packet)
        && !crate::capture::tcp_timestamp_option_present(
            packet.get(tcp.options.clone()).unwrap_or_default(),
        )
    {
        return PacketDecision::FlowUnfit { plan_id: plan.id };
    }

    let Ok(actions) = plan.apply(&input) else {
        return PacketDecision::Refused { plan_id: plan.id };
    };
    if actions.emits.is_empty() {
        return if actions.fate == OriginalFate::Drop {
            PacketDecision::Drop
        } else {
            PacketDecision::Accept
        };
    }
    let Some(max_packet_len) = actions
        .emits
        .iter()
        .filter_map(|emission| {
            emission
                .prefix
                .len()
                .checked_add(emission.bytes.len())?
                .checked_add(100)
        })
        .max()
    else {
        return PacketDecision::Accept;
    };
    let mut buffer = vec![0; max_packet_len];
    let mut packets = Vec::with_capacity(actions.emits.len());
    for emission in &actions.emits {
        let Some(len) = r2k_core::wire::build_tcp_packet(packet, emission, &mut buffer) else {
            return PacketDecision::Accept;
        };
        packets.push(WirePacket {
            packet: buffer[..len].to_vec(),
            kind: emission.kind,
            delay_us: emission.delay_us,
        });
    }
    PacketDecision::Transmit {
        packets,
        fate: actions.fate,
    }
}

fn replace_udp_payload(
    packet: &[u8],
    view: &PacketView,
    payload_range: &std::ops::Range<usize>,
    replacement: &[u8],
) -> Option<Vec<u8>> {
    if view.total_len > packet.len() || payload_range.end != view.total_len {
        return None;
    }
    let udp_len = replacement.len().checked_add(8)?;
    let udp_len_field = u16::try_from(udp_len).ok()?;
    let total_len = view.l4_offset.checked_add(udp_len)?;
    let mut output = packet[..payload_range.start].to_vec();
    output.extend_from_slice(replacement);
    if total_len != view.total_len {
        match view.family {
            4 => {
                let total_len_field = u16::try_from(total_len).ok()?;
                output
                    .get_mut(2..4)?
                    .copy_from_slice(&total_len_field.to_be_bytes());
                update_ipv4_checksum(&mut output, view.l4_offset)?;
            }
            6 => {
                let payload_len = u16::try_from(total_len.checked_sub(40)?).ok()?;
                output
                    .get_mut(4..6)?
                    .copy_from_slice(&payload_len.to_be_bytes());
            }
            _ => return None,
        }
        output
            .get_mut(view.l4_offset + 4..view.l4_offset + 6)?
            .copy_from_slice(&udp_len_field.to_be_bytes());
    }
    let updated_view = PacketView::parse(&output)?;
    update_udp_checksum(&mut output, &updated_view)?;
    Some(output)
}

fn update_ipv4_checksum(packet: &mut [u8], header_len: usize) -> Option<()> {
    if header_len < 20 || header_len > packet.len() {
        return None;
    }
    packet.get_mut(10..12)?.fill(0);
    let checksum = finish_checksum(sum_words(&packet[..header_len], 0));
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    Some(())
}

fn update_udp_checksum(packet: &mut [u8], view: &PacketView) -> Option<()> {
    let udp_start = view.l4_offset;
    let udp_len = view.total_len.checked_sub(udp_start)?;
    if udp_len < 8 || udp_len > u16::MAX as usize || view.total_len > packet.len() {
        return None;
    }
    packet.get_mut(udp_start + 6..udp_start + 8)?.fill(0);
    let mut sum = 0u64;
    match view.family {
        4 => {
            sum = sum_words(packet.get(12..20)?, sum);
            sum += 17;
            sum += udp_len as u64;
        }
        6 => {
            sum = sum_words(packet.get(8..40)?, sum);
            sum += ((udp_len as u32) >> 16) as u64;
            sum += (udp_len as u32 & 0xffff) as u64;
            sum += 17;
        }
        _ => return None,
    }
    sum = sum_words(packet.get(udp_start..udp_start + udp_len)?, sum);
    let checksum = finish_checksum(sum);
    packet[udp_start + 6..udp_start + 8].copy_from_slice(&checksum.to_be_bytes());
    Some(())
}

fn sum_words(bytes: &[u8], mut sum: u64) -> u64 {
    let mut offset = 0;
    while offset + 1 < bytes.len() {
        sum += u64::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
        offset += 2;
    }
    if offset < bytes.len() {
        sum += u64::from(bytes[offset]) << 8;
    }
    sum
}

fn finish_checksum(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    if checksum == 0 { 0xffff } else { checksum }
}

pub fn validate_runtime_plan(plan: &Plan) -> Result<(), &'static str> {
    if plan.transport == 17 && plan.proto == PROTO_VOICE {
        if plan.qsplit != 0
            || plan.qdeny != 0
            || plan.ipfrag != 0
            || plan.udplen != 0
            || !plan.splits.is_empty()
            || !plan.seq_overlays.is_empty()
            || plan.oob_enabled
            || plan.order != 0
            || plan.segment_size != 0
            || plan.wire_profile != 0
            || plan.input_tls
            || plan.input_len != 0
            || plan.input_sni_off != 0
            || plan.input_sni_len != 0
            || plan.guards != 0
            || plan.poison_used() != 0
            || plan.poisons.iter().any(|poison| poison.seq_shift != 0)
            || plan
                .fakes
                .iter()
                .any(|fake| fake.placement != 0 || fake.tls_mod != 0)
        {
            return Err(
                "runtime исполняет только UDP voice fake-before планы без неподдерживаемых операций",
            );
        }
        return Ok(());
    }
    if plan.r2k_is_quic_clearance_probe() {
        return Ok(());
    }
    if plan.r2k_is_quic_ttl_probe() || plan.r2k_is_quic_fallback_ttl_probe() {
        return Ok(());
    }
    if plan.r2k_is_quic_ipfrag_plan() {
        return Ok(());
    }
    if plan.r2k_is_quic_fake_probe() {
        if plan.order != 0
            || plan.guards != 0
            || plan.input_len != 0
            || plan.input_sni_off != 0
            || plan.input_sni_len != 0
            || plan.input_tls
            || plan.settle_us != 0
            || plan.segment_size != 0
            || plan.wire_profile != 0
            || plan.oob_enabled
            || plan.oob_anchor != 0
            || plan.oob_byte != 0
            || plan.pace_us != 0
            || plan.delay_us != 0
            || !plan.splits.is_empty()
            || !plan.seq_overlays.is_empty()
            || plan.poison_used() != 0
            || plan.poisons.iter().any(|poison| poison.seq_shift != 0)
            || plan
                .fakes
                .iter()
                .any(|fake| fake.placement != 0 || fake.gap_us != 0 || fake.tls_mod != 0)
        {
            return Err("QUIC-приманка поддерживает отправку перед Initial без TCP-операций");
        }
        return Ok(());
    }
    if plan.guards != 0 && !(plan.transport == 6 && matches!(plan.proto, 1 | PROTO_HTTP)) {
        return Err("TCP guards требуют TLS или HTTP плана с состоянием потока");
    }
    if plan.qsplit != 0 || plan.qdeny != 0 {
        return Ok(());
    }
    if plan.r2k_is_quic_udp_length_probe() {
        return Ok(());
    }
    if plan.transport == 6 && matches!(plan.proto, 1 | PROTO_HTTP) {
        if plan.guards & !GUARD_RST_ALIEN != 0 {
            return Err("runtime не поддерживает один из TCP guards этого плана");
        }
        if plan.poison_used() & POISON_IPID_ZERO != 0 {
            return Err("Linux raw socket меняет нулевой IPv4 ID; такой poison не исполняется");
        }
        return Ok(());
    }
    Err("runtime исполняет UDP QUIC/udplen и пакетные TCP TLS/HTTP планы")
}

#[cfg(test)]
mod tests {
    use super::{
        KEY_LEN, PacketDecision, R2oTcpFlowMetrics, TcpFlowKey, TcpSessions, decide,
        decide_with_session, decide_with_session_mtu, decide_with_session_probe, tcp_plan_input,
        validate_runtime_plan,
    };
    #[cfg(target_os = "linux")]
    use crate::conntrack::R2oConntrackInfo;
    use crate::flow_capacity::R2oFlowCapacity;
    use proptest::prelude::*;
    use r2k_core::packet::PacketView;
    use r2k_core::plan::{
        EmitKind, OriginalFate, POISON_TCPTS_BACK, PROTO_HTTP, Plan, WIRE_TCP_TEMPLATE,
    };
    use std::time::{Duration, Instant};

    const V1_INITIAL: &[u8] = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
    const V2_INITIAL: &[u8] = include_bytes!("../../r2k-core/tests/fixtures/quic_v2_initial.bin");

    #[test]
    fn autottl_uses_the_observed_reverse_tcp_ttl_without_client_timestamps() {
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let plan = Plan {
            minexec: 13,
            transport: 6,
            proto: 1,
            payloads: vec![r2k_core::plan::Payload {
                id: 1,
                bytes: b"decoy".to_vec(),
            }],
            poisons: vec![r2k_core::plan::Poison {
                id: 1,
                ttl: 0,
                flags: 0,
                seq_shift: 0,
                autottl: Some(r2k_core::plan::AutoTtl {
                    delta: 1,
                    min: 2,
                    max: 12,
                }),
            }],
            fakes: vec![r2k_core::plan::Fake {
                payload_id: 1,
                poison_id: 1,
                repeats: 1,
                placement: 0,
                gap_us: 0,
                tls_mod: 0,
            }],
            ..Plan::default()
        };
        let mut sessions = TcpSessions::default();
        let syn = ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]);
        let syn_ack = ipv4_tcp_packet(server, client, 0x12, 57, 900, &[]);
        let hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        assert_eq!(
            decide_with_session(&mut sessions, &plan, &syn),
            PacketDecision::Accept
        );
        assert_eq!(
            sessions.r2o_client_offers_tcp_timestamps_for_packet(&hello),
            Some(false),
            "возможность клиента берётся из SYN, а не из ClientHello сегмента",
        );
        assert_eq!(
            decide_with_session(&mut sessions, &Plan::default(), &syn_ack),
            PacketDecision::Accept
        );

        let PacketDecision::Transmit { packets, .. } =
            decide_with_session(&mut sessions, &plan, &hello)
        else {
            panic!("autottl plan did not transmit for the client without TCP timestamps");
        };
        assert_eq!(PacketView::parse(&packets[0].packet).unwrap().hop_limit, 8);

        let mut no_reply_sessions = TcpSessions::default();
        decide_with_session(&mut no_reply_sessions, &Plan::default(), &syn);
        let PacketDecision::Transmit { packets, .. } =
            decide_with_session(&mut no_reply_sessions, &plan, &hello)
        else {
            panic!("autottl plan without a reverse response did not transmit");
        };
        assert_eq!(PacketView::parse(&packets[0].packet).unwrap().hop_limit, 64);

        let timestamp_client = ([192, 0, 2, 11], 41001);
        let mut timestamp_syn = ipv4_tcp_packet(timestamp_client, server, 0x02, 64, 800, &[]);
        timestamp_syn.extend_from_slice(&[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
        let timestamp_syn_len = timestamp_syn.len() as u16;
        timestamp_syn[2..4].copy_from_slice(&timestamp_syn_len.to_be_bytes());
        timestamp_syn[32] = 8 << 4;
        let timestamp_probe = ipv4_tcp_packet(timestamp_client, server, 0x18, 64, 801, &[]);
        let mut timestamp_sessions = TcpSessions::default();
        assert_eq!(
            decide_with_session(&mut timestamp_sessions, &Plan::default(), &timestamp_syn),
            PacketDecision::Accept
        );
        assert_eq!(
            timestamp_sessions.r2o_client_offers_tcp_timestamps_for_packet(&timestamp_probe),
            Some(true),
        );
    }

    #[test]
    fn tcp_template_timestamp_requirement_matches_d2o_session_fixture() {
        let client = ([192, 168, 1, 67], 41400);
        let server = ([1, 2, 3, 4], 443);
        let plan_id = [0x7a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let hello = d2o_flow_unfit_client_hello();
        let plan = Plan {
            minexec: 8,
            id: plan_id,
            transport: 6,
            proto: 1,
            input_tls: true,
            wire_profile: WIRE_TCP_TEMPLATE,
            payloads: vec![r2k_core::plan::Payload {
                id: 1,
                bytes: hello.clone(),
            }],
            poisons: vec![r2k_core::plan::Poison {
                id: 1,
                ttl: 0,
                flags: POISON_TCPTS_BACK,
                seq_shift: 0,
                autottl: None,
            }],
            fakes: vec![r2k_core::plan::Fake {
                payload_id: 1,
                poison_id: 1,
                repeats: 1,
                placement: 0,
                gap_us: 0,
                tls_mod: 3,
            }],
            ..Plan::default()
        };

        let mut no_timestamp = TcpSessions::default();
        let syn = d2o_flow_unfit_client_packet(41400, 0x02, &[], false);
        let syn_ack = d2o_flow_unfit_server_packet(41400, 0x12);
        let hello_packet = d2o_flow_unfit_client_packet(41400, 0x18, &hello, false);
        assert_eq!(
            decide_with_session(&mut no_timestamp, &plan, &syn),
            PacketDecision::Accept
        );
        assert_eq!(
            decide_with_session(&mut no_timestamp, &Plan::default(), &syn_ack),
            PacketDecision::Accept
        );
        assert_eq!(
            decide_with_session(&mut no_timestamp, &plan, &hello_packet),
            PacketDecision::FlowUnfit { plan_id },
            "как datapath/test_session.c: поток без TCP timestamp должен получить FLOW_UNFIT",
        );

        let mut with_timestamp = TcpSessions::default();
        let syn = d2o_flow_unfit_client_packet(41401, 0x02, &[], true);
        let syn_ack = d2o_flow_unfit_server_packet(41401, 0x12);
        let hello_packet = d2o_flow_unfit_client_packet(41401, 0x18, &hello, true);
        assert_eq!(
            decide_with_session(&mut with_timestamp, &plan, &syn),
            PacketDecision::Accept
        );
        assert_eq!(
            decide_with_session(&mut with_timestamp, &Plan::default(), &syn_ack),
            PacketDecision::Accept
        );
        assert!(matches!(
            decide_with_session(&mut with_timestamp, &plan, &hello_packet),
            PacketDecision::Transmit { .. }
        ));

        let http = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let http_plan = Plan {
            minexec: 8,
            id: plan_id,
            transport: 6,
            proto: PROTO_HTTP,
            wire_profile: WIRE_TCP_TEMPLATE,
            payloads: vec![r2k_core::plan::Payload {
                id: 1,
                bytes: http.to_vec(),
            }],
            poisons: vec![r2k_core::plan::Poison {
                id: 1,
                ttl: 0,
                flags: POISON_TCPTS_BACK,
                seq_shift: 0,
                autottl: None,
            }],
            fakes: vec![r2k_core::plan::Fake {
                payload_id: 1,
                poison_id: 1,
                repeats: 1,
                placement: 0,
                gap_us: 0,
                tls_mod: 0,
            }],
            ..Plan::default()
        };
        let http_packet = ipv4_tcp_packet(client, server, 0x18, 64, 3001, http);
        let http_view = PacketView::parse(&http_packet).unwrap();
        assert!(
            tcp_plan_input(&http_plan, &http_packet, &http_view, 0, 0)
                .is_some_and(|input| input.is_http)
        );
        assert!(!matches!(
            decide(&http_plan, &http_packet),
            PacketDecision::FlowUnfit { .. }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_обнаруживает_зависший_поток_только_после_трёх_пакетов_и_двух_секунд() {
        let mut sessions = TcpSessions::default();
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(
                client,
                server,
                0x18,
                64,
                701,
                &client_hello_with_sni_and_large_extension(),
            ),
            start + Duration::from_millis(100),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &[1, 2, 3]),
            start + Duration::from_millis(200),
        );
        let probe = sessions.tcp_stall_candidates().pop().unwrap();
        let baseline = R2oConntrackInfo {
            original_packets: 10,
            reply_packets: 25,
            tcp_state: Some(3),
        };
        assert_eq!(
            sessions.update_tcp_stall(start + Duration::from_secs(1), &probe.key, baseline),
            None
        );
        assert_eq!(
            sessions.update_tcp_stall(
                start + Duration::from_secs(3),
                &probe.key,
                R2oConntrackInfo {
                    original_packets: 12,
                    ..baseline
                },
            ),
            None
        );
        let event = sessions
            .update_tcp_stall(
                start + Duration::from_millis(3100),
                &probe.key,
                R2oConntrackInfo {
                    original_packets: 13,
                    ..baseline
                },
            )
            .unwrap();
        assert_eq!(event.elapsed_ms, 2100);
        assert_eq!(event.estimated_packets, 25);
        assert!(!event.planned);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_учитывает_измеренный_бюджет_из_каталога() {
        let mut sessions = TcpSessions::default();
        sessions.set_tcp_stall_budgets(&[15, 35]).unwrap();
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(
                client,
                server,
                0x18,
                64,
                701,
                &client_hello_with_sni_and_large_extension(),
            ),
            start + Duration::from_millis(100),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &[1, 2, 3]),
            start + Duration::from_millis(200),
        );
        let probe = sessions.tcp_stall_candidates().pop().unwrap();
        let baseline = R2oConntrackInfo {
            original_packets: 10,
            reply_packets: 15,
            tcp_state: Some(3),
        };
        assert_eq!(
            sessions.update_tcp_stall(start + Duration::from_secs(1), &probe.key, baseline),
            None
        );
        let event = sessions
            .update_tcp_stall(
                start + Duration::from_millis(3100),
                &probe.key,
                R2oConntrackInfo {
                    original_packets: 13,
                    ..baseline
                },
            )
            .unwrap();
        assert_eq!(event.estimated_packets, 15);
    }

    #[test]
    fn tcp_бюджеты_отвергают_ноль_и_список_длиннее_восьми() {
        let mut sessions = TcpSessions::default();
        assert!(sessions.set_tcp_stall_budgets(&[0]).is_err());
        assert!(sessions.set_tcp_stall_budgets(&[1; 9]).is_err());
        sessions.set_tcp_stall_budgets(&[]).unwrap();
        assert!(sessions.set_tcp_stall_budgets(&[25]).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_определяет_клиента_по_hello_если_syn_не_попал_в_очередь() {
        let mut sessions = TcpSessions::default();
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        sessions.track_packet(&ipv4_tcp_packet(server, client, 0x10, 124, 900, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(
                client,
                server,
                0x18,
                64,
                701,
                &client_hello_with_sni_and_large_extension(),
            ),
            start + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &[1, 2, 3]),
            start + Duration::from_millis(100),
        );

        let probe = sessions.tcp_stall_candidates().pop().unwrap();
        assert_eq!(probe.tuple.source_port, 41000);
        assert_eq!(probe.tuple.destination_port, 443);
    }

    #[test]
    fn tcp_считает_пакеты_и_байты_по_направлениям_и_сохраняет_их_при_syn() {
        let mut sessions = TcpSessions::default();
        let now = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);

        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), now);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            now + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, b"request"),
            now + Duration::from_millis(100),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, b"answer"),
            now + Duration::from_millis(150),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x02, 64, 1200, &[]),
            now + Duration::from_millis(200),
        );

        let key = sessions.flows.keys().next().unwrap().wire_key();
        assert_eq!(
            sessions.r2o_flow_metrics(&key),
            Some(R2oTcpFlowMetrics {
                forward_packets: 3,
                reverse_packets: 2,
                forward_bytes: 127,
                reverse_bytes: 86,
            })
        );
    }

    #[test]
    fn r2o_tcp_учитывает_невидимый_ответ_один_раз_по_продвинутому_ack() {
        let mut sessions = TcpSessions::default();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        hello[28..32].copy_from_slice(&1000_u32.to_be_bytes());
        sessions.track_packet(&hello, Instant::now());
        assert_eq!(sessions.r2o_tcp_hello_flows(), 1);
        assert_eq!(sessions.r2o_reply_hidden(), 0);

        let mut ack = ipv4_tcp_packet(client, server, 0x10, 64, 1200, &[]);
        ack[28..32].copy_from_slice(&1100_u32.to_be_bytes());
        assert_eq!(
            decide_with_session(&mut sessions, &Plan::default(), &ack),
            PacketDecision::Accept
        );
        assert_eq!(sessions.r2o_reply_hidden(), 1);

        ack[28..32].copy_from_slice(&1200_u32.to_be_bytes());
        decide_with_session(&mut sessions, &Plan::default(), &ack);
        assert_eq!(sessions.r2o_reply_hidden(), 1);
    }

    #[test]
    fn r2o_tcp_не_считает_видимый_ответ_и_повтор_hello_невидимыми() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);

        let mut visible = TcpSessions::default();
        let mut hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        hello[28..32].copy_from_slice(&1000_u32.to_be_bytes());
        visible.track_packet(&hello, start);
        visible.track_packet(
            &ipv4_tcp_packet(server, client, 0x10, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        let mut ack = ipv4_tcp_packet(client, server, 0x10, 64, 1200, &[]);
        ack[28..32].copy_from_slice(&1100_u32.to_be_bytes());
        visible.track_packet(&ack, start + Duration::from_millis(100));
        assert_eq!(visible.r2o_tcp_hello_flows(), 1);
        assert_eq!(visible.r2o_reply_hidden(), 0);

        let mut repeat = TcpSessions::default();
        let mut hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        hello[28..32].copy_from_slice(&1000_u32.to_be_bytes());
        repeat.track_packet(&hello, start);
        repeat.track_packet(&hello, start + Duration::from_millis(50));
        assert_eq!(repeat.r2o_tcp_hello_flows(), 1);
        assert_eq!(repeat.r2o_reply_hidden(), 0);

        let mut without_ack = TcpSessions::default();
        let hello = ipv4_tcp_packet(client, server, 0x08, 64, 701, &client_hello());
        without_ack.track_packet(&hello, start);
        let mut ack = ipv4_tcp_packet(client, server, 0x10, 64, 1200, &[]);
        ack[28..32].copy_from_slice(&1100_u32.to_be_bytes());
        without_ack.track_packet(&ack, start + Duration::from_millis(50));
        assert_eq!(without_ack.r2o_tcp_hello_flows(), 1);
        assert_eq!(without_ack.r2o_reply_hidden(), 0);
    }

    #[test]
    fn r2o_tcp_подозревает_два_повтора_clienthello_с_тем_же_sequence() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        let mut sessions = TcpSessions::default();

        sessions.track_packet(&hello, start);
        assert!(sessions.take_tcp_repeat_events().is_empty());
        sessions.track_packet(&hello, start + Duration::from_millis(50));
        assert!(sessions.take_tcp_repeat_events().is_empty());
        sessions.track_packet(&hello, start + Duration::from_millis(100));

        let events = sessions.take_tcp_repeat_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].key,
            sessions.flows.keys().next().unwrap().wire_key()
        );
        assert!(events[0].client_is_low);
        assert!(!events[0].planned);

        sessions.track_packet(&hello, start + Duration::from_millis(150));
        assert!(sessions.take_tcp_repeat_events().is_empty());

        let mut planned = TcpSessions::default();
        planned.track_packet(&hello, start);
        let key = planned.flows.keys().next().unwrap().wire_key();
        planned.mark_plan_done(&key);
        planned.track_packet(&hello, start + Duration::from_millis(50));
        planned.track_packet(&hello, start + Duration::from_millis(100));
        assert!(planned.take_tcp_repeat_events()[0].planned);
    }

    #[test]
    fn r2o_tcp_повтор_учитывает_только_клиентский_sequence_без_ответа_tls() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        let mut server_hello = vec![0x16, 0x03, 0x03, 0, 42, 2, 0, 0, 38, 0x03, 0x03];
        server_hello.extend_from_slice(&[0; 32]);
        server_hello.extend_from_slice(&[0, 0x13, 0x01, 0]);
        let replies = [
            (vec![0x17, 0x03, 0x03, 0, 1, 0], true),
            (server_hello, true),
            (vec![0x17], false),
            (vec![0x17, 0x03, 0xff, 0, 1, 0], false),
        ];

        for (reply, answered) in replies {
            let mut sessions = TcpSessions::default();
            sessions.track_packet(&hello, start);
            sessions.track_packet(
                &ipv4_tcp_packet(server, client, 0x18, 124, 900, &reply),
                start + Duration::from_millis(25),
            );
            sessions.track_packet(&hello, start + Duration::from_millis(50));
            sessions.track_packet(&hello, start + Duration::from_millis(75));
            assert_eq!(
                !sessions.take_tcp_repeat_events().is_empty(),
                !answered,
                "TLS-ответ={reply:02x?}"
            );
        }

        let mut sessions = TcpSessions::default();
        sessions.track_packet(&hello, start);
        let mut other_sequence = hello.clone();
        other_sequence[24..28].copy_from_slice(&702_u32.to_be_bytes());
        sessions.track_packet(&other_sequence, start + Duration::from_millis(50));
        sessions.track_packet(&other_sequence, start + Duration::from_millis(75));
        assert!(sessions.take_tcp_repeat_events().is_empty());
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 701, &client_hello()),
            start + Duration::from_millis(100),
        );
        assert!(sessions.take_tcp_repeat_events().is_empty());
    }

    #[test]
    fn r2o_tcp_сравнивает_ack_с_переполнением_серийного_номера() {
        let mut sessions = TcpSessions::default();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        hello[28..32].copy_from_slice(&(u32::MAX - 7).to_be_bytes());
        sessions.track_packet(&hello, Instant::now());

        let mut ack = ipv4_tcp_packet(client, server, 0x10, 64, 1200, &[]);
        ack[28..32].copy_from_slice(&5_u32.to_be_bytes());
        sessions.track_packet(&ack, Instant::now());
        assert_eq!(sessions.r2o_reply_hidden(), 1);

        let mut reverse_wrap = TcpSessions::default();
        let mut hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        hello[28..32].copy_from_slice(&5_u32.to_be_bytes());
        reverse_wrap.track_packet(&hello, Instant::now());
        ack[28..32].copy_from_slice(&(u32::MAX - 7).to_be_bytes());
        reverse_wrap.track_packet(&ack, Instant::now());
        assert_eq!(reverse_wrap.r2o_reply_hidden(), 0);
    }

    #[test]
    fn tcp_таблица_отказывает_после_трёх_четвертей_слотов_и_обновляет_известные_потоки() {
        let mut sessions =
            TcpSessions::try_with_capacity(R2oFlowCapacity::from_requested(64).unwrap()).unwrap();
        let start = Instant::now();
        for index in 0..48_u16 {
            let packet = ipv4_tcp_packet(
                ([10, 0, (index >> 8) as u8, index as u8], 1000 + index),
                ([203, 0, 113, 8], 443),
                0x10,
                64,
                u32::from(index),
                &[],
            );
            assert!(sessions.track_packet(&packet, start).is_some());
        }

        let refused = ipv4_tcp_packet(
            ([10, 1, 0, 1], 50000),
            ([203, 0, 113, 8], 443),
            0x10,
            64,
            0,
            &[],
        );
        assert!(sessions.track_packet(&refused, start).is_none());
        let known = ipv4_tcp_packet(
            ([10, 0, 0, 0], 1000),
            ([203, 0, 113, 8], 443),
            0x10,
            64,
            0,
            &[],
        );
        assert!(sessions.track_packet(&known, start).is_some());
        assert_eq!(sessions.len(), 48);
    }

    #[test]
    fn tcp_table_capacity_differential_matches_d2o() {
        let capacity64 = R2oFlowCapacity::from_requested(64).unwrap();
        let capacity65 = R2oFlowCapacity::from_requested(65).unwrap();
        let mut sessions = TcpSessions::try_with_capacity(capacity64).unwrap();
        let start = Instant::now();

        for index in 1..=48_u16 {
            let packet = ipv4_tcp_packet(
                ([10, 0, 0, index as u8], 10_000 + index),
                ([203, 0, 113, 8], 443),
                0x10,
                64,
                u32::from(index),
                &[],
            );
            assert!(sessions.track_packet(&packet, start).is_some());
        }

        let refused_a = ipv4_tcp_packet(
            ([10, 0, 0, 49], 10_049),
            ([203, 0, 113, 8], 443),
            0x10,
            64,
            49,
            &[],
        );
        let refused_b = ipv4_tcp_packet(
            ([10, 0, 0, 50], 10_050),
            ([203, 0, 113, 8], 443),
            0x10,
            64,
            50,
            &[],
        );
        assert!(
            sessions
                .track_packet(&refused_a, start + Duration::from_nanos(100))
                .is_none()
        );
        assert!(
            sessions
                .track_packet(&refused_b, start + Duration::from_nanos(101))
                .is_none()
        );

        let reverse_known = ipv4_tcp_packet(
            ([203, 0, 113, 8], 443),
            ([10, 0, 0, 1], 10_001),
            0x10,
            64,
            1,
            &[],
        );
        assert!(
            sessions
                .track_packet(&reverse_known, start + Duration::from_nanos(202))
                .is_some()
        );

        let refusals_at_limit = sessions.r2o_tcp_flow_refusals();
        let count_at_limit = sessions.len();
        let expired = sessions.expire(
            start + Duration::from_nanos(60_202),
            Duration::from_nanos(60_000),
        );
        let count_after_expiry = sessions.len();
        let accepted_after_expiry = sessions
            .track_packet(&refused_a, start + Duration::from_nanos(60_203))
            .is_some();
        let refusals_after_expiry = sessions.r2o_tcp_flow_refusals();
        let count_after_reuse = sessions.len();

        assert_eq!(refusals_at_limit, 2);
        assert_eq!(count_at_limit, 48);
        assert_eq!(expired, 48);
        assert_eq!(count_after_expiry, 0);
        assert!(accepted_after_expiry);
        assert_eq!(refusals_after_expiry, 2);
        assert_eq!(count_after_reuse, 1);

        if let Ok(path) = std::env::var("R2O_TCP_TABLE_DIFF_OUTPUT") {
            let output = format!(
                "request64_slots={}_limit={}_inserted=48_refused=2_reverse_hit=1_count={count_at_limit}_refusals={refusals_at_limit}\nrequest65_slots={}_limit={}\nexpired={expired}_remaining={count_after_expiry}_accepted_after_expiry={}_refusals={refusals_after_expiry}_count={count_after_reuse}\n",
                sessions.r2o_tcp_flow_capacity(),
                capacity64.limit(),
                capacity65.slots(),
                capacity65.limit(),
                u8::from(accepted_after_expiry),
            );
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn tcp_журнал_повышает_уровень_обмена_при_tls_application_data() {
        let mut sessions = TcpSessions::default();
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(100),
        );

        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x10, 124, 900, &[]),
            start + Duration::from_millis(125),
        );
        assert!(sessions.take_tcp_exchange_events().is_empty());

        let mut handshake_record = vec![0x16, 0x03, 0x03, 0, 42, 2, 0, 0, 38];
        handshake_record.extend_from_slice(&[0; 38]);
        assert!(r2k_core::tls::parse(&handshake_record).is_server_hello);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &handshake_record),
            start + Duration::from_millis(150),
        );
        let first = sessions.take_tcp_exchange_events();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].code, 0x16);
        assert_eq!(first[0].num, 47);
        assert_eq!(first[0].tos, 0x04);
        assert!(first[0].server_hello);
        assert_eq!(first[0].planned, 2);

        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &handshake_record),
            start + Duration::from_millis(200),
        );
        assert!(sessions.take_tcp_exchange_events().is_empty());

        let application_data = [0x17, 0x03, 0x03, 0, 1, 0];
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 947, &application_data),
            start + Duration::from_millis(250),
        );
        let second = sessions.take_tcp_exchange_events();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].code, 0x16);
        assert_eq!(second[0].num, 100);
        assert_eq!(second[0].tos, 0x0c);
        assert_eq!(second[0].planned, 2);

        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 953, &application_data),
            start + Duration::from_millis(300),
        );
        assert!(sessions.take_tcp_exchange_events().is_empty());
    }

    #[test]
    fn tcp_журналирует_application_data_как_первый_ответ_один_раз() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = r2o_tcp_hello_flow(start, client, server);
        let application_data = [0x17, 0x03, 0x03, 0, 1, 0];

        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &application_data),
            start + Duration::from_millis(150),
        );
        let events = sessions.take_tcp_exchange_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].code, 0x17);
        assert_eq!(events[0].num, 6);
        assert_eq!(events[0].tos, 0x08);
        assert!(!events[0].server_hello);
        assert_eq!(events[0].planned, 2);

        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 906, &application_data),
            start + Duration::from_millis(200),
        );
        assert!(sessions.take_tcp_exchange_events().is_empty());
    }

    #[test]
    fn tcp_журнал_отмечает_план_только_после_подтверждённого_applied() {
        let mut sessions = TcpSessions::default();
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(50),
        );
        let key = sessions.flows.keys().next().unwrap().wire_key();
        sessions.mark_plan_done(&key);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &[0x16, 0x03, 0x03, 0, 1, 1]),
            start + Duration::from_millis(100),
        );
        let events = sessions.take_tcp_exchange_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].planned, 1);
    }

    #[test]
    fn r2o_tcp_silence_uses_rtt_and_requires_visible_reverse_traffic() {
        let mut sessions = TcpSessions::default();
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(100),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x10, 124, 900, &[]),
            start + Duration::from_millis(200),
        );
        let key = sessions.flows.keys().next().unwrap().wire_key();
        sessions.mark_plan_done(&key);

        let deadline = start + Duration::from_millis(1100);
        assert!(sessions.sweep_silent(deadline, false).is_empty());
        let events = sessions.sweep_silent(deadline, true);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].elapsed_ms, 1000);
        assert_eq!(events[0].key[37], 6);
        assert!(events[0].planned);
        sessions.mark_silent(&events[0].key);
        assert!(
            sessions
                .sweep_silent(start + Duration::from_secs(10), true)
                .is_empty()
        );
    }

    #[test]
    fn tcp_истечение_сообщает_о_clienthello_без_ответа_при_видимом_обратном_пути() {
        let start = Instant::now();
        let mut sessions = TcpSessions::default();
        let witness_client = ([192, 0, 2, 10], 41000);
        let witness_server = ([198, 51, 100, 20], 443);
        sessions.track_packet(
            &ipv4_tcp_packet(witness_client, witness_server, 0x02, 64, 700, &[]),
            start,
        );
        sessions.track_packet(
            &ipv4_tcp_packet(witness_server, witness_client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );

        let client = ([192, 0, 2, 11], 41001);
        let server = ([198, 51, 100, 21], 443);
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
            start + Duration::from_millis(60),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(100),
        );

        let mut events = Vec::new();
        let expired = sessions.expire_with_silent(
            start + Duration::from_secs(120) + Duration::from_millis(100),
            Duration::from_secs(120),
            |event| events.push(event),
        );
        assert_eq!(expired, 2);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].key[37], 6);
        assert!(events[0].client_is_low);
        assert!(!events[0].planned);
        assert_eq!(events[0].elapsed_ms, 120_000);
    }

    #[test]
    fn tcp_истечение_использует_ранее_увиденный_обратный_путь() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let deadline = start + Duration::from_secs(120) + Duration::from_millis(100);

        let mut unseen = TcpSessions::default();
        unseen.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        unseen.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(100),
        );
        let mut events = Vec::new();
        unseen.expire_with_silent(deadline, Duration::from_secs(120), |event| {
            events.push(event)
        });
        assert!(events.is_empty());

        let mut visible = TcpSessions::default();
        visible.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        visible.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        visible.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(100),
        );
        let key = visible.flows.keys().next().unwrap().wire_key();
        visible.mark_plan_done(&key);
        visible.expire_with_silent(deadline, Duration::from_secs(120), |event| {
            events.push(event)
        });
        assert_eq!(events.len(), 1);
        assert!(events[0].planned);
    }

    #[test]
    fn tcp_истечение_не_сообщает_если_после_clienthello_уже_был_ответ() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(100),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x10, 124, 900, &[]),
            start + Duration::from_millis(200),
        );

        let mut events = Vec::new();
        sessions.expire_with_silent(
            start + Duration::from_secs(120) + Duration::from_millis(200),
            Duration::from_secs(120),
            |event| events.push(event),
        );
        assert!(events.is_empty());
    }

    #[test]
    fn tcp_истечение_не_сообщает_при_одновременном_истечении_окна_fin() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(100),
        );
        sessions
            .flows
            .values_mut()
            .find(|session| session.hello_at.is_some())
            .unwrap()
            .pending_fin_at = Some(start + Duration::from_millis(100));

        let mut events = Vec::new();
        sessions.expire_with_silent(
            start + Duration::from_secs(120) + Duration::from_millis(100),
            Duration::from_secs(120),
            |event| events.push(event),
        );
        assert!(events.is_empty());
    }

    #[test]
    fn r2o_tcp_silence_is_suppressed_by_server_payload_or_reset() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);

        let mut replied = r2o_tcp_hello_flow(start, client, server);
        replied.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, b"response"),
            start + Duration::from_millis(250),
        );
        assert!(
            replied
                .sweep_silent(start + Duration::from_secs(5), true)
                .is_empty()
        );

        let mut reset = r2o_tcp_hello_flow(start, client, server);
        reset.track_packet(
            &ipv4_tcp_packet(server, client, 0x14, 124, 900, &[]),
            start + Duration::from_millis(250),
        );
        assert!(
            reset
                .sweep_silent(start + Duration::from_secs(5), true)
                .is_empty()
        );
    }

    #[test]
    fn r2o_tcp_silence_without_measured_rtt_waits_two_seconds() {
        let mut sessions = TcpSessions::default();
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x10, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(100),
        );

        assert!(
            sessions
                .sweep_silent(start + Duration::from_millis(2099), true)
                .is_empty()
        );
        assert_eq!(
            sessions
                .sweep_silent(start + Duration::from_millis(2100), true)
                .len(),
            1
        );
    }

    #[test]
    fn tcp_повтор_fin_после_ответа_сохраняет_поток_и_создаёт_улику_один_раз() {
        let plan = Plan::default();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        let mut hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        hello[28..32].copy_from_slice(&901_u32.to_be_bytes());
        decide_with_session(&mut sessions, &plan, &hello);
        let application_data = [0x17, 0x03, 0x03, 0, 1, 0];
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &application_data),
        );

        let fin_sequence = 701 + client_hello().len() as u32;
        let fin = ipv4_tcp_packet(client, server, 0x11, 64, fin_sequence, &[]);
        assert_eq!(
            decide_with_session(&mut sessions, &plan, &fin),
            PacketDecision::Accept
        );
        assert_eq!(sessions.len(), 1);
        assert!(sessions.fin_retry_candidates().is_empty());

        assert_eq!(
            decide_with_session(&mut sessions, &plan, &fin),
            PacketDecision::Accept
        );
        let events = sessions.fin_retry_candidates();
        assert_eq!(events.len(), 1);
        assert!(events[0].client_is_low);
        assert!(!events[0].planned);
        assert_eq!(events[0].key[37], 6);
        assert_eq!(
            decide_with_session(&mut sessions, &plan, &fin),
            PacketDecision::Accept
        );
        assert_eq!(sessions.fin_retry_candidates().len(), 1);

        let key = events[0].key;
        sessions.mark_fin_retry(&key);
        assert!(sessions.fin_retry_candidates().is_empty());
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x11, 124, 906, &[]),
        );
        assert!(sessions.is_empty());
    }

    #[test]
    fn tcp_повтор_fin_передаёт_признак_применённого_плана() {
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let start = Instant::now();
        let mut sessions = TcpSessions::default();
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        let mut hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        hello[28..32].copy_from_slice(&901_u32.to_be_bytes());
        sessions.track_packet(&hello, start + Duration::from_millis(100));
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &[0x17, 0x03, 0x03, 0, 1, 0]),
            start + Duration::from_millis(150),
        );
        let key = sessions.flows.keys().next().unwrap().wire_key();
        sessions.mark_plan_done(&key);

        let fin_sequence = 701 + client_hello().len() as u32;
        let fin = ipv4_tcp_packet(client, server, 0x11, 64, fin_sequence, &[]);
        sessions.track_packet(&fin, start + Duration::from_millis(200));
        sessions.track_packet(&fin, start + Duration::from_millis(300));

        let events = sessions.fin_retry_candidates();
        assert_eq!(events.len(), 1);
        assert!(events[0].planned);
    }

    #[test]
    fn tcp_rst_после_tls_app_data_создаёт_наблюдение_для_обоих_направлений() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let application_data = [0x17, 0x03, 0x03, 0, 1, 0];

        for (source, destination) in [(client, server), (server, client)] {
            let mut sessions = TcpSessions::default();
            sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
            sessions.track_packet(
                &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
                start + Duration::from_millis(50),
            );
            sessions.track_packet(
                &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
                start + Duration::from_millis(100),
            );
            sessions.track_packet(
                &ipv4_tcp_packet(server, client, 0x18, 124, 900, &application_data),
                start + Duration::from_millis(200),
            );
            sessions.track_packet(
                &ipv4_tcp_packet(source, destination, 0x14, 64, 1000, &[]),
                start + Duration::from_millis(300),
            );

            let events = sessions.rst_after_app_candidates();
            assert_eq!(events.len(), 1);
            assert!(events[0].client_is_low);
            assert_eq!(events[0].key[37], 6);
            assert!(!events[0].planned);
        }
    }

    #[test]
    fn tcp_полный_ech_capture_уточняет_форму_для_последующего_rst() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut client_hello = client_hello_with_sni();
        let supported_versions = [0, 43, 0, 3, 2, 3, 4];
        client_hello.extend_from_slice(&supported_versions);
        let extensions_len = u16::from_be_bytes([client_hello[50], client_hello[51]])
            .wrapping_add(supported_versions.len() as u16);
        client_hello[50..52].copy_from_slice(&extensions_len.to_be_bytes());
        let handshake_len =
            u32::from_be_bytes([0, client_hello[6], client_hello[7], client_hello[8]])
                + supported_versions.len() as u32;
        client_hello[6..9].copy_from_slice(&handshake_len.to_be_bytes()[1..]);
        let record_len = u16::from_be_bytes([client_hello[3], client_hello[4]])
            .wrapping_add(supported_versions.len() as u16);
        client_hello[3..5].copy_from_slice(&record_len.to_be_bytes());
        assert!(r2k_core::tls::parse(&client_hello).is_tls13);
        let mut sessions = TcpSessions::default();
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello),
            start,
        );
        assert_eq!(
            sessions.flows.values().next().unwrap().client_shape,
            r2k_core::control::SHAPE_MODERN,
        );

        let packet = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello);
        assert!(
            sessions.r2o_note_captured_client_shape(&packet, r2k_core::control::SHAPE_ECH_TCP,)
        );
        assert!(
            !sessions.r2o_note_captured_client_shape(&packet, r2k_core::control::SHAPE_LEGACY,)
        );

        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x04, 124, 900, &[]),
            start + Duration::from_millis(10),
        );
        let events = sessions.take_tcp_rst_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].client_shape, r2k_core::control::SHAPE_ECH_TCP);
    }

    #[test]
    fn tcp_rst_до_tls_app_data_не_создаёт_наблюдение_позднего_сброса() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(100),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x14, 64, 1200, &[]),
            start + Duration::from_millis(200),
        );

        assert!(sessions.rst_after_app_candidates().is_empty());
    }

    #[test]
    fn tcp_подтверждение_после_server_hello_учитывает_все_видимые_байты() {
        let plan = tcp_guard_only_plan();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        let mut hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        hello[28..32].copy_from_slice(&901_u32.to_be_bytes());
        decide_with_session(&mut sessions, &plan, &hello);

        let mut server_hello = vec![0x16, 0x03, 0x03, 0, 42, 2, 0, 0, 38];
        server_hello.extend_from_slice(&[0; 38]);
        assert!(r2k_core::tls::parse(&server_hello).is_server_hello);
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &server_hello),
        );

        let fin_sequence = 701 + client_hello().len() as u32;
        let mut fin = ipv4_tcp_packet(client, server, 0x11, 64, fin_sequence, &[]);
        fin[28..32].copy_from_slice(&(901_u32 + server_hello.len() as u32 + 1).to_be_bytes());
        decide_with_session(&mut sessions, &plan, &fin);
        decide_with_session(&mut sessions, &plan, &fin);
        assert_eq!(sessions.fin_retry_candidates().len(), 1);

        let mut boundary = TcpSessions::default();
        decide_with_session(
            &mut boundary,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
        );
        decide_with_session(
            &mut boundary,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        decide_with_session(&mut boundary, &plan, &hello);
        decide_with_session(
            &mut boundary,
            &plan,
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &server_hello),
        );
        let mut boundary_fin = ipv4_tcp_packet(client, server, 0x11, 64, fin_sequence, &[]);
        boundary_fin[28..32].copy_from_slice(&(901_u32 + server_hello.len() as u32).to_be_bytes());
        decide_with_session(&mut boundary, &plan, &boundary_fin);
        assert!(boundary.is_empty());
    }

    #[test]
    fn tcp_поток_после_fin_истекает_по_ограниченному_окну_повтора() {
        let start = Instant::now();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        let mut hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        hello[28..32].copy_from_slice(&901_u32.to_be_bytes());
        sessions.track_packet(&hello, start + Duration::from_millis(100));
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &[0x17, 3, 3, 0, 1, 0]),
            start + Duration::from_millis(200),
        );
        let fin_sequence = 701 + client_hello().len() as u32;
        let tracked = sessions
            .track_packet(
                &ipv4_tcp_packet(client, server, 0x11, 64, fin_sequence, &[]),
                start + Duration::from_millis(300),
            )
            .unwrap();
        let key = tracked.key;
        assert!(tracked.keep_fin_session);

        assert_eq!(
            sessions.expire(
                start + Duration::from_millis(3299),
                Duration::from_secs(120),
            ),
            0
        );
        assert!(sessions.flows.contains_key(&key));
        assert_eq!(
            sessions.expire(
                start + Duration::from_millis(3300),
                Duration::from_secs(120),
            ),
            1
        );
        assert!(sessions.is_empty());
    }

    fn r2o_tcp_hello_flow(
        start: Instant,
        client: ([u8; 4], u16),
        server: ([u8; 4], u16),
    ) -> TcpSessions {
        let mut sessions = TcpSessions::default();
        sessions.track_packet(&ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]), start);
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            start + Duration::from_millis(50),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
            start + Duration::from_millis(100),
        );
        sessions.track_packet(
            &ipv4_tcp_packet(server, client, 0x10, 124, 900, &[]),
            start + Duration::from_millis(200),
        );
        sessions
    }

    #[test]
    fn qsplit_replaces_only_quic_payload_and_recomputes_ipv4_udp_checksum() {
        let plan = qsplit_plan();
        let input = ipv4_udp(V1_INITIAL);
        let original = input.clone();
        let PacketDecision::Replace(output) = decide(&plan, &input) else {
            panic!("valid IPv4 QUIC Initial should be replaced");
        };
        let view = PacketView::parse(&output).unwrap();
        let payload = view.udp_payload_range(&output).unwrap();
        let expected = r2k_core::quic::initial_split_crypto(V1_INITIAL).unwrap();
        assert_eq!(&output[payload], expected);
        assert_eq!(&output[..20], &input[..20]);
        assert_eq!(&output[20..26], &input[20..26]);
        assert_ne!(&output[26..28], &input[26..28]);
        assert_udp_checksum_valid(&output);
        assert_eq!(input, original);
    }

    #[test]
    fn отказ_udp_исполнителя_сохраняет_идентификатор_плана() {
        let plan = udplen_refusal_plan();
        let decision = decide(&plan, &ipv4_udp(V1_INITIAL));

        assert_eq!(
            decision,
            PacketDecision::Refused {
                plan_id: [0x77; 16],
            }
        );
    }

    #[test]
    fn qsplit_recomputes_mandatory_ipv6_udp_checksum() {
        let plan = qsplit_plan();
        let input = ipv6_udp(V2_INITIAL);
        let PacketDecision::Replace(output) = decide(&plan, &input) else {
            panic!("valid IPv6 QUIC Initial should be replaced");
        };
        let view = PacketView::parse(&output).unwrap();
        let payload = view.udp_payload_range(&output).unwrap();
        assert_eq!(
            &output[payload],
            r2k_core::quic::initial_split_crypto(V2_INITIAL)
                .unwrap()
                .as_slice()
        );
        assert_udp_checksum_valid(&output);
    }

    #[test]
    fn ipv4_quic_ipfrag_emits_the_selected_fragment_shape_and_drops_original() {
        for shape in 1..=4 {
            let plan = quic_ipfrag_plan(shape);
            assert!(validate_runtime_plan(&plan).is_ok());
            let input = ipv4_udp(V1_INITIAL);
            let PacketDecision::Transmit { packets, fate } = decide(&plan, &input) else {
                panic!("аутентичный QUIC Initial должен стать набором IP-фрагментов");
            };
            assert_eq!(fate, OriginalFate::Drop);
            assert_eq!(packets.len(), if shape < 3 { 2 } else { 3 });
            assert!(
                packets
                    .iter()
                    .all(|packet| packet.kind == EmitKind::Payload && packet.delay_us == 0)
            );
            assert_eq!(
                decide(&plan, &ipv4_udp(b"ordinary UDP")),
                PacketDecision::Accept
            );
        }
    }

    #[test]
    fn ipv6_quic_ipfrag_emits_the_selected_fragment_shape_and_drops_original() {
        for shape in 1..=4 {
            let plan = quic_ipfrag_plan(shape);
            let input = ipv6_udp(V2_INITIAL);
            let PacketDecision::Transmit { packets, fate } = decide(&plan, &input) else {
                panic!("аутентичный QUIC Initial IPv6 должен дать IP-фрагменты");
            };
            assert_eq!(fate, OriginalFate::Drop);
            assert_eq!(packets.len(), if shape < 3 { 2 } else { 3 });
            assert!(packets.iter().all(|packet| packet.packet[6] == 44));
        }
    }

    #[test]
    fn qdeny_only_drops_an_authenticated_quic_initial() {
        let plan =
            Plan::parse(&plan_bytes(11, &[tlv(0x0002, &[17, 2]), tlv(0x0110, &[1])])).unwrap();
        assert!(validate_runtime_plan(&plan).is_ok());
        assert_eq!(decide(&plan, &ipv4_udp(V1_INITIAL)), PacketDecision::Drop);
        assert_eq!(
            decide(&plan, &ipv4_udp(b"ordinary UDP")),
            PacketDecision::Accept
        );

        let mut corrupted = V1_INITIAL.to_vec();
        corrupted[600] ^= 1;
        assert_eq!(decide(&plan, &ipv4_udp(&corrupted)), PacketDecision::Accept);
    }

    #[test]
    fn voice_plan_sends_udp_fake_for_discord_and_regular_stun_requests() {
        let plan = Plan::parse(&plan_bytes(
            1,
            &[
                tlv(0x0002, &[17, 3]),
                tlv(0x0010, &[0, 1, b'F', b'A', b'K', b'E']),
                tlv(0x0011, &[0, 1, 2, 0, 0, 0, 0, 0]),
                tlv(0x0101, &[0, 1, 0, 1, 1, 0, 0, 0, 0, 0]),
            ],
        ))
        .unwrap();
        assert!(validate_runtime_plan(&plan).is_ok());

        let mut stun = [0; 20];
        stun[..8].copy_from_slice(&[0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
        let mut input = ipv4_udp(&stun);
        input[22..24].copy_from_slice(&50004_u16.to_be_bytes());
        let PacketDecision::Transmit { packets, fate } = decide(&plan, &input) else {
            panic!("Discord voice Binding request should produce its configured fake");
        };
        assert_eq!(fate, OriginalFate::Pass);
        assert_eq!(packets.len(), 1);
        let fake = &packets[0].packet;
        let view = PacketView::parse(fake).unwrap();
        let payload = view.udp_payload_range(fake).unwrap();
        assert_eq!(&fake[payload], b"FAKE");
        assert_eq!(
            fake[8], 2,
            "configured poison TTL must reach the wire packet"
        );
        assert_eq!(&fake[20..24], &input[20..24]);
        assert_udp_checksum_valid(fake);
        assert_eq!(
            decide(&plan, &input),
            PacketDecision::Transmit {
                packets: packets.clone(),
                fate: OriginalFate::Pass,
            }
        );

        input[22..24].copy_from_slice(&3478_u16.to_be_bytes());
        assert!(matches!(
            decide(&plan, &input),
            PacketDecision::Transmit { .. }
        ));
        input[29] = 9;
        assert_eq!(decide(&plan, &input), PacketDecision::Accept);

        let mut input_v6 = ipv6_udp(&stun);
        input_v6[42..44].copy_from_slice(&50004_u16.to_be_bytes());
        let PacketDecision::Transmit { packets, .. } = decide(&plan, &input_v6) else {
            panic!("IPv6 Discord voice request should produce its configured fake");
        };
        let fake_v6 = &packets[0].packet;
        let view = PacketView::parse(fake_v6).unwrap();
        assert_eq!(view.family, 6);
        assert_eq!(fake_v6[7], 2);
        assert_udp_checksum_valid(fake_v6);
    }

    #[test]
    fn udplen_appends_zeroes_and_updates_ipv4_and_udp_lengths_and_checksums() {
        let plan = udplen_plan(7);
        assert!(validate_runtime_plan(&plan).is_ok());
        let input = ipv4_udp(V1_INITIAL);
        let original = input.clone();
        let PacketDecision::Replace(output) = decide(&plan, &input) else {
            panic!("udplen plan should replace the authenticated QUIC Initial");
        };
        let view = PacketView::parse(&output).unwrap();
        let payload = view.udp_payload_range(&output).unwrap();
        assert_eq!(&output[payload.clone()][..V1_INITIAL.len()], V1_INITIAL);
        assert_eq!(&output[payload][V1_INITIAL.len()..], &[0; 7]);
        assert_eq!(view.total_len, 20 + 8 + V1_INITIAL.len() + 7);
        assert_eq!(
            u16::from_be_bytes([output[2], output[3]]) as usize,
            output.len()
        );
        assert_eq!(
            u16::from_be_bytes([output[view.l4_offset + 4], output[view.l4_offset + 5]]) as usize,
            8 + V1_INITIAL.len() + 7
        );
        assert_ipv4_checksum_valid(&output, view.l4_offset);
        assert_udp_checksum_valid(&output);
        assert_eq!(input, original);
    }

    #[test]
    fn udplen_updates_ipv6_payload_length_and_mandatory_udp_checksum() {
        let plan = udplen_plan(3);
        let input = ipv6_udp(V1_INITIAL);
        let PacketDecision::Replace(output) = decide(&plan, &input) else {
            panic!("udplen plan should replace the authenticated QUIC Initial");
        };
        let view = PacketView::parse(&output).unwrap();
        let payload = view.udp_payload_range(&output).unwrap();
        assert_eq!(&output[payload.clone()][..V1_INITIAL.len()], V1_INITIAL);
        assert_eq!(&output[payload][V1_INITIAL.len()..], &[0; 3]);
        assert_eq!(
            usize::from(u16::from_be_bytes([output[4], output[5]])),
            output.len() - 40
        );
        assert_eq!(
            u16::from_be_bytes([output[view.l4_offset + 4], output[view.l4_offset + 5]]) as usize,
            8 + V1_INITIAL.len() + 3
        );
        assert_udp_checksum_valid(&output);
    }

    #[test]
    fn runtime_rejects_udplen_plans_that_need_multiple_raw_sends() {
        let fake = [0, 1, 0, 0, 1, 0, 0, 0, 0, 0];
        let plan = Plan::parse(&plan_bytes(
            9,
            &[
                tlv(0x0002, &[17, 2]),
                tlv(0x0010, &[0, 1, b'x']),
                tlv(0x0101, &fake),
                tlv(0x010e, &3_u16.to_be_bytes()),
            ],
        ))
        .unwrap();
        assert!(validate_runtime_plan(&plan).is_err());
        assert_eq!(decide(&plan, &ipv4_udp(b"payload")), PacketDecision::Accept);
    }

    #[test]
    fn r2o_безобидная_датаграмма_идёт_перед_quic_initial() {
        let plan = r2o_quic_clearance_plan();
        assert!(validate_runtime_plan(&plan).is_ok());

        let input = ipv4_udp(V1_INITIAL);
        let PacketDecision::Transmit { packets, fate } = decide(&plan, &input) else {
            panic!("QUIC clearance should send a benign datagram before the Initial");
        };
        assert_eq!(fate, OriginalFate::Drop);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].kind, EmitKind::Fake);
        assert_eq!(packets[1].kind, EmitKind::Payload);
        for (packet, expected) in [
            (&packets[0].packet, &[0; 16][..]),
            (&packets[1].packet, V1_INITIAL),
        ] {
            let view = PacketView::parse(packet).unwrap();
            let payload = view.udp_payload_range(packet).unwrap();
            assert_eq!(&packet[payload], expected);
            assert_udp_checksum_valid(packet);
        }

        assert_eq!(
            decide(&plan, &ipv4_udp(b"later QUIC datagram")),
            PacketDecision::Accept
        );
    }

    #[test]
    fn d2o_quic_fake_plans_allow_empty_poison_records_and_repeats() {
        for (repeats, payload_len) in [(1, 16), (6, 1200), (11, 620)] {
            let mut payload = vec![0, 1];
            payload.extend(vec![0; payload_len]);
            let plan = Plan::parse(&plan_bytes(
                1,
                &[
                    tlv(0x0002, &[17, 2]),
                    tlv(0x0010, &payload),
                    tlv(0x0011, &[0, 1, 0, 0, 0, 0, 0, 0]),
                    tlv(0x0101, &[0, 1, 0, 1, repeats, 0, 0, 0, 0, 0]),
                ],
            ))
            .unwrap();

            assert!(plan.r2k_is_quic_fake_probe());
            assert!(plan.r2k_is_quic_address_plan());
            assert!(validate_runtime_plan(&plan).is_ok());
            let PacketDecision::Transmit { packets, fate } = decide(&plan, &ipv4_udp(V1_INITIAL))
            else {
                panic!("D2O QUIC fake план должен отправить свои повторы");
            };
            assert_eq!(fate, OriginalFate::Pass);
            assert_eq!(packets.len(), usize::from(repeats));
            for packet in packets {
                assert_eq!(packet.kind, EmitKind::Fake);
                assert_eq!(packet.delay_us, 0);
                let view = PacketView::parse(&packet.packet).unwrap();
                let range = view.udp_payload_range(&packet.packet).unwrap();
                let emitted = &packet.packet[range];
                assert_eq!(emitted.len(), payload_len);
                assert!(emitted.iter().all(|byte| *byte == 0));
                assert_udp_checksum_valid(&packet.packet);
            }
            assert_eq!(
                decide(&plan, &ipv4_udp(b"ordinary UDP")),
                PacketDecision::Accept
            );
        }
    }

    #[test]
    fn r2o_quic_ttl_probe_emits_two_exact_fakes_with_ttl_three() {
        let plan = r2o_quic_ttl_probe_plan();
        assert!(plan.r2k_is_quic_ttl_probe());
        assert!(plan.r2k_is_quic_address_plan());
        assert!(validate_runtime_plan(&plan).is_ok());

        let input = ipv4_udp(V1_INITIAL);
        let PacketDecision::Transmit { packets, fate } = decide(&plan, &input) else {
            panic!("QUIC TTL-проба должна отправить две фальшивые датаграммы");
        };
        assert_eq!(fate, OriginalFate::Pass);
        assert_eq!(packets.len(), 2);
        for packet in &packets {
            assert_eq!(packet.kind, EmitKind::Fake);
            assert_eq!(packet.packet[8], 3);
            let view = PacketView::parse(&packet.packet).unwrap();
            let payload = view.udp_payload_range(&packet.packet).unwrap();
            assert_eq!(
                &packet.packet[payload],
                r2k_core::plan::R2K_QUIC_TTL_PROBE_PAYLOAD
            );
            assert_udp_checksum_valid(&packet.packet);
        }

        assert_eq!(
            decide(&plan, &ipv4_udp("не QUIC Initial".as_bytes())),
            PacketDecision::Accept
        );
    }

    #[test]
    fn r2o_quic_резервная_ttl_лестница_разрешает_только_штатные_значения() {
        let mut payload = vec![0, 1];
        payload.extend_from_slice(r2k_core::plan::R2K_QUIC_TTL_PROBE_PAYLOAD);

        for ttl in [5, 8, 12] {
            let plan = Plan::parse(&plan_bytes(
                10,
                &[
                    tlv(0x0002, &[17, 2]),
                    tlv(0x0010, &payload),
                    tlv(0x0011, &[0, 1, ttl, 0, 0, 0, 0, 0]),
                    tlv(0x0101, &[0, 1, 0, 1, 2, 0, 0, 0, 0, 0]),
                ],
            ))
            .unwrap();

            assert!(plan.r2k_is_quic_address_plan());
            assert!(validate_runtime_plan(&plan).is_ok());
            let PacketDecision::Transmit { packets, .. } = decide(&plan, &ipv4_udp(V1_INITIAL))
            else {
                panic!("резервная QUIC-проба TTL должна отправить две приманки");
            };
            assert_eq!(packets.len(), 2);
            assert!(packets.iter().all(|packet| packet.packet[8] == ttl));
        }

        let invalid = Plan::parse(&plan_bytes(
            10,
            &[
                tlv(0x0002, &[17, 2]),
                tlv(0x0010, &payload),
                tlv(0x0011, &[0, 1, 4, 0, 0, 0, 0, 0]),
                tlv(0x0101, &[0, 1, 0, 1, 2, 0, 0, 0, 0, 0]),
            ],
        ))
        .unwrap();
        assert!(!invalid.r2k_is_quic_address_plan());
    }

    #[test]
    fn r2o_quic_приманки_и_адаптивный_разрез_выполняются_как_единое_испытание() {
        let decoy = b"QUIC decoy";
        let mut payload = vec![0, 1];
        payload.extend_from_slice(decoy);
        let plan = Plan::parse(&plan_bytes(
            10,
            &[
                tlv(0x0002, &[17, 2]),
                tlv(0x0010, &payload),
                tlv(0x0101, &[0, 1, 0, 0, 1, 0, 0, 0, 0, 0]),
            ],
        ))
        .unwrap();
        assert!(plan.r2k_is_quic_address_plan());
        assert!(validate_runtime_plan(&plan).is_ok());
        let PacketDecision::Transmit { packets, fate } = decide(&plan, &ipv4_udp(V1_INITIAL))
        else {
            panic!("QUIC-проба должна отправить исходную приманку перед Initial");
        };
        assert_eq!(fate, OriginalFate::Pass);
        assert_eq!(packets.len(), 1);
        let view = PacketView::parse(&packets[0].packet).unwrap();
        let range = view.udp_payload_range(&packets[0].packet).unwrap();
        assert_eq!(&packets[0].packet[range], decoy);
        assert_eq!(
            decide(&plan, &ipv4_udp(b"ordinary UDP")),
            PacketDecision::Accept
        );

        let mut default_payload = vec![0, 1];
        default_payload.push(0x40);
        default_payload.extend_from_slice(&[0; 619]);
        let combined = Plan::parse(&plan_bytes(
            10,
            &[
                tlv(0x0002, &[17, 2]),
                tlv(0x0010, &default_payload),
                tlv(0x010f, &[1]),
                tlv(0x0101, &[0, 1, 0, 0, 11, 0, 0, 0, 0, 0]),
            ],
        ))
        .unwrap();
        assert!(validate_runtime_plan(&combined).is_ok());
        let PacketDecision::Transmit { packets, fate } = decide(&combined, &ipv4_udp(V1_INITIAL))
        else {
            panic!("комбинация приманки и разреза CRYPTO должна дать пакетную серию");
        };
        assert_eq!(fate, OriginalFate::Drop);
        assert_eq!(packets.len(), 12);
        for packet in &packets[..11] {
            let view = PacketView::parse(&packet.packet).unwrap();
            let range = view.udp_payload_range(&packet.packet).unwrap();
            assert_eq!(&packet.packet[range], &default_payload[2..]);
            assert_udp_checksum_valid(&packet.packet);
        }
        let view = PacketView::parse(&packets[11].packet).unwrap();
        let range = view.udp_payload_range(&packets[11].packet).unwrap();
        assert_eq!(
            &packets[11].packet[range],
            r2k_core::quic::initial_split_crypto(V1_INITIAL).unwrap()
        );
        assert_udp_checksum_valid(&packets[11].packet);
    }

    #[test]
    fn udplen_that_exceeds_the_ipv4_total_length_is_reported_as_refused() {
        let plan = udplen_plan(u16::MAX);
        let input = ipv4_udp(V1_INITIAL);
        assert_eq!(
            decide(&plan, &input),
            PacketDecision::Refused { plan_id: [0; 16] }
        );
    }

    #[test]
    fn malformed_and_unsupported_packets_are_passed_through() {
        let plan = qsplit_plan();
        assert_eq!(decide(&plan, b"short"), PacketDecision::Accept);
        assert_eq!(
            decide(&plan, &ipv4_udp(b"not QUIC")),
            PacketDecision::Accept
        );
        assert!(validate_runtime_plan(&Plan::default()).is_err());
    }

    #[test]
    fn complete_tls_client_hello_becomes_a_wire_fake_and_keeps_the_original() {
        let plan = tcp_fake_plan();
        assert!(validate_runtime_plan(&plan).is_ok());
        let input = ipv4_tcp(&client_hello(), 700);
        let PacketDecision::Transmit { packets, fate } = decide(&plan, &input) else {
            panic!("a complete TCP ClientHello should produce its configured fake");
        };
        assert_eq!(fate, OriginalFate::Pass);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].kind, EmitKind::Fake);
        let wire = &packets[0].packet;
        let view = PacketView::parse(wire).unwrap();
        let tcp = view.tcp_segment(wire).unwrap();
        assert_eq!(tcp.sequence, 700);
        assert_eq!(&wire[tcp.payload], b"FAKE");
        assert!(r2k_core::wire::tcp_checksum_ok(wire));
    }

    #[test]
    fn controller_probe_applies_tcp_plan_without_user_metrics_or_events() {
        let client = ([192, 0, 2, 10], 41_001);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        let hello = ipv4_tcp_packet(client, server, 0x18, 64, 700, &client_hello());
        let decision = decide_with_session_probe(&mut sessions, &tcp_fake_plan(), &hello);
        let PacketDecision::Transmit { packets, .. } = decision else {
            panic!("TCP-план не применился к probe ClientHello");
        };
        assert_eq!(packets.len(), 1);
        assert_eq!(sessions.r2o_tcp_hello_flows(), 0);
        assert_eq!(sessions.r2o_reply_hidden(), 0);
        assert!(sessions.take_tcp_exchange_events().is_empty());
        assert!(sessions.take_tcp_rst_events().is_empty());
        assert!(sessions.take_tcp_repeat_events().is_empty());
        assert!(sessions.take_tcp_rst_cut_events().is_empty());

        let key = sessions.flows.keys().next().unwrap().wire_key();
        assert!(sessions.r2o_flow_metrics(&key).is_none());
        let reply = ipv4_tcp_packet(server, client, 0x18, 120, 900, &[0x17, 0x03, 0x03, 0, 1, 0]);
        let _ = decide_with_session(&mut sessions, &Plan::default(), &reply);
        assert!(sessions.take_tcp_exchange_events().is_empty());
        assert!(
            sessions
                .sweep_silent(Instant::now() + Duration::from_secs(10), true)
                .is_empty()
        );

        let mut silent = Vec::new();
        sessions.expire_with_silent(
            Instant::now() + Duration::from_secs(121),
            Duration::from_secs(120),
            |event| silent.push(event),
        );
        assert!(silent.is_empty());
    }

    #[test]
    fn rst_alien_guard_profiles_the_reverse_ttl_and_keeps_the_flow_alive() {
        let plan = tcp_fake_plan_with_rst_guard();
        assert!(validate_runtime_plan(&plan).is_ok());
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        assert_eq!(
            decide(&plan, &ipv4_tcp(&client_hello(), 700)),
            PacketDecision::Accept,
            "stateless callers cannot silently run a plan whose guard they cannot enforce",
        );

        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
            ),
            PacketDecision::Accept,
        );
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            ),
            PacketDecision::Accept,
        );
        assert!(matches!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, 700, &client_hello()),
            ),
            PacketDecision::Transmit { .. }
        ));
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x14, 127, 900, &[]),
            ),
            PacketDecision::Drop,
            "RST с TTL, отличным от первого ответа сервера, снимается",
        );
        assert_eq!(sessions.len(), 1, "снятый RST не закрывает поток");
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x14, 124, 900, &[]),
            ),
            PacketDecision::Accept,
            "настоящий RST с тем же TTL проходит",
        );
        assert_eq!(sessions.len(), 0, "настоящий RST закрывает поток");
    }

    #[test]
    fn tcp_отказ_повреждает_только_свое_поколение_и_снимает_защиту_rst() {
        let plan = tcp_fake_plan_with_rst_guard();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        let syn = ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]);
        let syn_ack = ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]);
        let hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());

        assert_eq!(
            decide_with_session(&mut sessions, &plan, &syn),
            PacketDecision::Accept
        );
        assert_eq!(
            decide_with_session(&mut sessions, &plan, &syn_ack),
            PacketDecision::Accept
        );
        assert!(matches!(
            decide_with_session(&mut sessions, &plan, &hello),
            PacketDecision::Transmit { .. }
        ));
        let key = sessions.r2o_begin_execution(&hello, 41).unwrap();
        assert!(sessions.r2o_send_pending(&key, 41));
        assert!(!sessions.r2o_is_damaged_packet(&hello));
        assert!(!sessions.r2o_mark_damaged_for_execution(&key, 40));
        assert!(!sessions.r2o_mark_plan_done_for_execution(&key, 40));
        assert!(sessions.r2o_mark_damaged_for_execution(&key, 41));
        assert!(!sessions.r2o_send_pending(&key, 41));
        assert!(sessions.r2o_is_damaged_packet(&hello));
        let flow_key = TcpFlowKey::from_packet(&hello).unwrap();
        assert_eq!(sessions.flows[&flow_key].guards, 0);
        assert_eq!(
            decide_with_session(&mut sessions, &plan, &hello),
            PacketDecision::Accept
        );
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x14, 127, 900, &[]),
            ),
            PacketDecision::Accept,
            "испорченный поток не удерживает поддельный RST",
        );
        assert!(sessions.is_empty(), "RST закрывает испорченное соединение");

        let new_syn = ipv4_tcp_packet(client, server, 0x02, 64, 3000, &[]);
        assert_eq!(
            decide_with_session(&mut sessions, &plan, &new_syn),
            PacketDecision::Accept
        );
        assert!(!sessions.r2o_is_damaged_packet(&new_syn));
        assert!(!sessions.r2o_mark_damaged_for_execution(&key, 41));
        assert!(!sessions.r2o_mark_plan_done_for_execution(&key, 41));
        let new_hello = ipv4_tcp_packet(client, server, 0x18, 64, 3001, &client_hello());
        assert!(matches!(
            decide_with_session(&mut sessions, &plan, &new_hello),
            PacketDecision::Transmit { .. }
        ));
        let new_key = sessions.r2o_begin_execution(&new_hello, 43).unwrap();
        assert_eq!(new_key, key);
        assert!(sessions.r2o_send_pending(&new_key, 43));
        assert!(!sessions.r2o_send_pending(&new_key, 41));
        assert!(!sessions.r2o_mark_damaged_for_execution(&new_key, 41));
        assert!(sessions.r2o_mark_plan_done_for_execution(&new_key, 43));
    }

    #[test]
    fn tcp_fin_не_получает_план_и_закрывает_запись_потока() {
        let plan = tcp_fake_plan_with_rst_guard();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
            ),
            PacketDecision::Accept
        );
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            ),
            PacketDecision::Accept
        );
        let hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        assert!(matches!(
            decide_with_session(&mut sessions, &plan, &hello),
            PacketDecision::Transmit { .. }
        ));

        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x11, 64, 701, &[]),
            ),
            PacketDecision::Accept
        );
        assert!(sessions.is_empty(), "обычный FIN освобождает запись потока");
    }

    #[test]
    fn tcp_clienthello_в_терминальном_пакете_не_разбирается() {
        let plan = tcp_fake_plan_with_rst_guard();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );

        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x19, 64, 701, &client_hello()),
            ),
            PacketDecision::Accept
        );
        assert_eq!(sessions.r2o_tcp_hello_flows(), 0);
        assert!(sessions.is_empty());
    }

    #[test]
    fn tcp_повторный_clienthello_не_получает_уже_выполненный_план() {
        let plan = tcp_fake_plan_with_rst_guard();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        let hello = ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello());
        assert!(matches!(
            decide_with_session(&mut sessions, &plan, &hello),
            PacketDecision::Transmit { .. }
        ));
        let key = sessions.r2o_begin_execution(&hello, 51).unwrap();
        assert!(sessions.r2o_send_pending(&key, 51));
        assert!(sessions.r2o_mark_plan_done_for_execution(&key, 51));
        assert!(!sessions.r2o_send_pending(&key, 51));
        assert_eq!(
            decide_with_session(&mut sessions, &plan, &hello),
            PacketDecision::Accept,
        );
    }

    #[test]
    fn r2o_http_keepalive_ждёт_завершения_предыдущего_исполнения() {
        let plan = http_split_plan();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 80);
        let mut sessions = TcpSessions::default();
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, 1000, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        let first = b"GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let first_sequence = 1001;
        let first_packet = ipv4_tcp_packet(client, server, 0x18, 64, first_sequence, first);
        assert!(matches!(
            decide_with_session(&mut sessions, &plan, &first_packet),
            PacketDecision::Transmit { .. }
        ));
        let key = sessions.r2o_begin_execution(&first_packet, 61).unwrap();

        let second = b"GET /second HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let second_sequence = first_sequence.wrapping_add(first.len() as u32);
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, second_sequence, second),
            ),
            PacketDecision::Accept,
        );
        assert!(sessions.r2o_mark_plan_done_for_execution(&key, 61));

        let third = b"GET /third HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let third_sequence = second_sequence.wrapping_add(second.len() as u32);
        assert!(matches!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, third_sequence, third),
            ),
            PacketDecision::Transmit { .. }
        ));
    }

    #[test]
    fn rst_alien_guard_журналирует_чужой_сброс_до_ответа_один_раз() {
        let plan = tcp_fake_plan_with_rst_guard();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();

        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
            ),
            PacketDecision::Accept,
        );
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            ),
            PacketDecision::Accept,
        );
        assert!(matches!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, 700, &client_hello_with_sni()),
            ),
            PacketDecision::Transmit { .. }
        ));
        let mut wire_key = [0; KEY_LEN];
        wire_key[0] = 4;
        wire_key[1..5].copy_from_slice(&client.0);
        wire_key[17..21].copy_from_slice(&server.0);
        wire_key[33..35].copy_from_slice(&client.1.to_be_bytes());
        wire_key[35..37].copy_from_slice(&server.1.to_be_bytes());
        wire_key[37] = 6;
        sessions.mark_plan_done(&wire_key);

        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x14, 127, 900, &[]),
            ),
            PacketDecision::Drop,
        );
        let events = sessions.take_tcp_rst_cut_events();
        assert_eq!(events.len(), 1);
        assert!(events[0].client_is_low);
        assert_eq!(events[0].ttl, 127);
        assert_eq!(events[0].reference_ttl, 124);
        assert_eq!(events[0].planned, 1);
        assert_eq!(events[0].client_shape, r2k_core::control::SHAPE_LEGACY);
        assert!(sessions.take_tcp_rst_events().is_empty());

        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x14, 127, 900, &[]),
            ),
            PacketDecision::Drop,
        );
        assert!(sessions.take_tcp_rst_cut_events().is_empty());
        assert_eq!(sessions.len(), 1, "снятый чужой RST не закрывает поток");
    }

    #[test]
    fn tcp_ранний_rst_создаёт_отдельное_наблюдение() {
        let plan = Plan::default();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();

        for packet in [
            ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
            ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
            ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello_with_sni()),
        ] {
            assert_eq!(
                decide_with_session(&mut sessions, &plan, &packet),
                PacketDecision::Accept,
            );
        }

        let mut rst = ipv4_tcp_packet(server, client, 0x14, 127, 900, &[]);
        rst[1] = 0x2e;
        rst[4..6].copy_from_slice(&0x5a17_u16.to_be_bytes());
        assert_eq!(
            decide_with_session(&mut sessions, &plan, &rst),
            PacketDecision::Accept,
        );

        let events = sessions.take_tcp_rst_events();
        assert_eq!(events.len(), 1);
        let event = events[0];
        assert_eq!(event.ttl, 127);
        assert_eq!(event.reference_ttl, 124);
        assert_eq!(event.traffic_class, 0x2e);
        assert_eq!(event.ip_id, 0x5a17);
        assert_eq!(event.planned, 2);
        assert_eq!(event.client_shape, r2k_core::control::SHAPE_LEGACY);
        assert!(event.client_is_low);
        assert!(sessions.is_empty());
        println!(
            "R2O_DIFF code=1 ttl={} ref={} tos={} ipid={} planned={} shape={} client_is_low={}",
            event.ttl,
            event.reference_ttl,
            event.traffic_class,
            event.ip_id,
            event.planned,
            event.client_shape,
            u8::from(event.client_is_low),
        );
    }

    #[test]
    fn rst_alien_guard_после_tls_app_data_не_теряет_сигнал_объёма() {
        let plan = tcp_fake_plan_with_rst_guard();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x18, 64, 701, &client_hello()),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &[0x17, 0x03, 0x03, 0, 1, 0]),
        );
        let key = sessions.flows.keys().next().unwrap().wire_key();
        sessions.mark_plan_done(&key);

        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x14, 127, 900, &[]),
            ),
            PacketDecision::Drop,
        );
        let events = sessions.rst_after_app_candidates();
        assert_eq!(events.len(), 1);
        assert!(events[0].client_is_low);
        assert!(events[0].planned);
        sessions.mark_rst_after_app(&events[0].key);
        assert!(sessions.rst_after_app_candidates().is_empty());
    }

    #[test]
    fn rst_alien_guard_does_not_apply_without_a_successful_plan() {
        let plan = tcp_fake_plan();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        assert!(matches!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, 700, &client_hello()),
            ),
            PacketDecision::Transmit { .. }
        ));
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x14, 127, 900, &[]),
            ),
            PacketDecision::Accept,
            "план без guard не меняет судьбу входящего RST",
        );
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn rst_alien_guard_activates_for_a_valid_no_emission_plan() {
        let plan = tcp_guard_only_plan();
        assert!(validate_runtime_plan(&plan).is_ok());
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 443);
        let mut sessions = TcpSessions::default();
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, 700, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, 700, &client_hello()),
            ),
            PacketDecision::Accept,
            "guard-only plan leaves the original packet untouched",
        );
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(server, client, 0x14, 127, 900, &[]),
            ),
            PacketDecision::Drop,
            "successfully evaluated no-emission plan still installs its guard",
        );
    }

    #[test]
    fn tcp_session_table_expires_idle_flows_at_the_configured_boundary() {
        let mut sessions = TcpSessions::default();
        let now = Instant::now();
        let packet = ipv4_tcp_packet(
            ([192, 0, 2, 10], 41000),
            ([198, 51, 100, 20], 443),
            0x02,
            64,
            700,
            &[],
        );
        sessions.track_packet(&packet, now).unwrap();
        assert_eq!(
            sessions.expire(now + Duration::from_secs(119), Duration::from_secs(120)),
            0
        );
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions.expire(now + Duration::from_secs(120), Duration::from_secs(120)),
            1
        );
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn complete_http_request_splits_at_its_normalized_host_midpoint() {
        let plan = http_split_plan();
        let request = b"GET /p?q=1 HTTP/1.1\r\nHost: example.test:80\r\n\r\n";
        let input = ipv4_tcp(request, 1000);
        let PacketDecision::Transmit { packets, fate } = decide(&plan, &input) else {
            panic!("a complete HTTP request should produce its configured split");
        };
        assert_eq!(fate, OriginalFate::Drop);
        assert_eq!(packets.len(), 2);
        let first = PacketView::parse(&packets[0].packet).unwrap();
        let first_tcp = first.tcp_segment(&packets[0].packet).unwrap();
        assert_eq!(
            &packets[0].packet[first_tcp.payload.clone()],
            &request[..33]
        );
        let second = PacketView::parse(&packets[1].packet).unwrap();
        let second_tcp = second.tcp_segment(&packets[1].packet).unwrap();
        assert_eq!(
            &packets[1].packet[second_tcp.payload.clone()],
            &request[33..]
        );
        assert_eq!(second_tcp.sequence, 1033);
    }

    #[test]
    fn r2o_http_keepalive_учитывает_тело_post_и_игнорирует_подделку() {
        let plan = http_split_plan();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 80);
        let mut sessions = TcpSessions::default();
        let syn_sequence = u32::MAX - 300;
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x02, 64, syn_sequence, &[]),
            ),
            PacketDecision::Accept,
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );

        let first = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut sequence = syn_sequence.wrapping_add(1);
        assert!(matches!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, sequence, first),
            ),
            PacketDecision::Transmit { .. }
        ));
        sequence = sequence.wrapping_add(first.len() as u32);

        let post = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 70000\r\n\r\n";
        assert!(matches!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, sequence, post),
            ),
            PacketDecision::Transmit { .. }
        ));
        let body_start = sequence.wrapping_add(post.len() as u32);
        let body_end = body_start.wrapping_add(70000);
        let fake = b"GET /inside-body HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut body = vec![b'x'; 70000];
        body[..fake.len()].copy_from_slice(fake);
        for (index, chunk) in body.chunks(1400).enumerate() {
            let body_sequence = body_start.wrapping_add((index * 1400) as u32);
            assert_eq!(
                decide_with_session(
                    &mut sessions,
                    &plan,
                    &ipv4_tcp_packet(client, server, 0x18, 64, body_sequence, chunk),
                ),
                PacketDecision::Accept,
                "данные тела POST не должны получать план",
            );
        }

        let second = b"GET /after-upload HTTP/1.1\r\nHost: example.test\r\n\r\n";
        assert!(matches!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, body_end, second),
            ),
            PacketDecision::Transmit { .. }
        ));
    }

    #[test]
    fn r2o_http_keepalive_пропускает_конвейер_и_пересечённую_границу() {
        let plan = http_split_plan();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 80);
        let mut sessions = TcpSessions::default();
        let mut sequence = 1000_u32;
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, sequence, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        sequence = sequence.wrapping_add(1);

        let pipelined = b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\nGET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
        assert!(matches!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, sequence, pipelined),
            ),
            PacketDecision::Transmit { .. }
        ));
        let second = b"GET /later HTTP/1.1\r\nHost: example.test\r\n\r\n";
        assert_eq!(
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, sequence.wrapping_add(39), second,),
            ),
            PacketDecision::Accept,
            "конвейер делает следующую границу неоднозначной",
        );

        let mut crossed = TcpSessions::default();
        sequence = 5000;
        decide_with_session(
            &mut crossed,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, sequence, &[]),
        );
        decide_with_session(
            &mut crossed,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        sequence = sequence.wrapping_add(1);
        let post = b"POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\n";
        assert!(matches!(
            decide_with_session(
                &mut crossed,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, sequence, post),
            ),
            PacketDecision::Transmit { .. }
        ));
        let boundary = sequence.wrapping_add(post.len() as u32).wrapping_add(5);
        let mut combined = b"abcde".to_vec();
        combined.extend_from_slice(second);
        assert_eq!(
            decide_with_session(
                &mut crossed,
                &plan,
                &ipv4_tcp_packet(
                    client,
                    server,
                    0x18,
                    64,
                    boundary.wrapping_sub(5),
                    &combined,
                ),
            ),
            PacketDecision::Accept,
            "сегмент, пересёкший границу тела и запроса, пропускается",
        );
        assert_eq!(
            decide_with_session(
                &mut crossed,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, boundary, second),
            ),
            PacketDecision::Accept,
            "после пересечения границы поток больше не классифицируется",
        );
    }

    #[test]
    fn r2o_http_неоднозначный_framing_не_задаёт_следующую_границу() {
        for request in [
            b"POST /x HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: example.test\r\nBad Header: x\r\n\r\n",
        ] {
            let parsed = r2k_core::httpup::r2o_http_plan_request(request).unwrap();
            assert!(parsed.host_range.end <= request.len());
            assert_eq!(parsed.end_offset, None);
            assert!(!r2k_core::httpup::request_safe(request));
        }

        assert!(
            r2k_core::httpup::r2o_http_plan_request(b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n")
                .is_none()
        );
    }

    #[test]
    fn r2o_http_keepalive_считает_поздние_невыравненные_и_открытые_концы() {
        let plan = http_split_plan();
        let client = ([192, 0, 2, 10], 41000);
        let server = ([198, 51, 100, 20], 80);
        let mut sessions = TcpSessions::default();
        let mut sequence = 1000_u32;
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, sequence, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        sequence = sequence.wrapping_add(1);
        let first = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x18, 64, sequence, first),
        );
        sequence = sequence.wrapping_add(first.len() as u32);
        let post = b"POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\n";
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x18, 64, sequence, post),
        );
        let crossing = b"abcdeGET /next HTTP/1.1\r\nHost: example.test\r\n\r\n";
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(
                client,
                server,
                0x18,
                64,
                sequence.wrapping_add(post.len() as u32),
                crossing,
            ),
        );

        let next_client = (client.0, client.1 + 1);
        let next_sequence = 5000_u32;
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(next_client, server, 0x02, 64, next_sequence, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, next_client, 0x12, 124, 1900, &[]),
        );
        let chunked =
            b"POST /x HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n";
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(
                next_client,
                server,
                0x18,
                64,
                next_sequence.wrapping_add(1),
                chunked,
            ),
        );

        let stats = sessions.r2o_http_keepalive_stats();
        assert_eq!(stats.later, 1);
        assert_eq!(stats.unaligned, 1);
        assert_eq!(stats.open_end, 1);
    }

    #[test]
    fn r2o_tcp_сводка_нагрузки_разделяет_направление_окно_и_sni() {
        let mut sessions = TcpSessions::default();
        let plan = Plan::default();
        let server = ([198, 51, 100, 20], 443);
        let client = ([192, 0, 2, 10], 41000);
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x02, 64, 1000, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x12, 124, 900, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x10, 64, 1001, &[]),
        );
        let not_hello = [0x16, 0x03, 0x03];
        for index in 0..6 {
            decide_with_session(
                &mut sessions,
                &plan,
                &ipv4_tcp_packet(client, server, 0x18, 64, 1001 + index, &not_hello),
            );
        }
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x18, 64, 2000, &not_hello),
        );
        let after_window_hello = client_hello();
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(client, server, 0x18, 64, 2100, &after_window_hello),
        );
        assert_eq!(sessions.r2o_tcp_hello_flows(), 0);
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, client, 0x18, 124, 900, &[0x17, 3, 3]),
        );

        let partial_client = (client.0, client.1 + 1);
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(partial_client, server, 0x02, 64, 3000, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(server, partial_client, 0x12, 124, 4000, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(partial_client, server, 0x10, 64, 3001, &[]),
        );
        let mut hello = client_hello_with_sni();
        hello.truncate(60);
        let partial = r2k_core::tls::parse(&hello);
        assert!(partial.is_client_hello);
        assert!(partial.sni_range.is_none());
        assert!(partial.record_end.is_none());
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(partial_client, server, 0x18, 64, 3001, &hello),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(partial_client, server, 0x18, 64, 3061, &[1, 2, 3]),
        );

        let http_client = (client.0, client.1 + 2);
        let http_server = (server.0, 80);
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(http_client, http_server, 0x02, 64, 5000, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(http_server, http_client, 0x12, 124, 6000, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(http_client, http_server, 0x10, 64, 5001, &[]),
        );
        decide_with_session(
            &mut sessions,
            &plan,
            &ipv4_tcp_packet(
                http_client,
                http_server,
                0x18,
                64,
                5001,
                b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
            ),
        );

        let stats = sessions.r2o_tcp_payload_stats();
        assert_eq!(stats.reverse, 1);
        assert_eq!(stats.after_hello, 1);
        assert_eq!(stats.late, 2);
        assert_eq!(stats.not_hello, 6);
        assert_eq!(stats.last_first_byte, 0x16);
        assert_eq!(stats.sni_next_seg, 1);
        println!(
            "СВОДКА {} {} {} {} {:02x} {}",
            stats.reverse,
            stats.after_hello,
            stats.late,
            stats.not_hello,
            stats.last_first_byte,
            stats.sni_next_seg
        );
    }

    proptest! {
        #[test]
        fn r2o_http_content_length_задаёт_точную_границу(
            first in any::<u32>(),
            body_len in 1_u32..10_000,
        ) {
            let request = format!(
                "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {body_len}\r\n\r\n"
            );
            let parsed = r2k_core::httpup::r2o_http_plan_request(request.as_bytes()).unwrap();
            prop_assert_eq!(parsed.end_offset, Some(request.len() + body_len as usize));

            let mut sequence = r2k_core::httpup::R2oHttpRequestSequence::new(first);
            prop_assert!(sequence.observe(first, request.as_bytes()));
            let body_sequence = first.wrapping_add(request.len() as u32);
            prop_assert!(!sequence.candidate(body_sequence, body_len as usize));
            let next_sequence = body_sequence.wrapping_add(body_len);
            let next = b"GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n";
            prop_assert!(sequence.candidate(next_sequence, next.len()));
            prop_assert!(sequence.observe(next_sequence, next));
        }
    }

    #[test]
    fn tcp_plan_over_wire_batch_limit_is_reported_as_refused() {
        let plan = Plan::parse(&plan_bytes(
            3,
            &[
                tlv(0x0002, &[6, 1]),
                tlv(0x0100, &[0, 0, 0, 1]),
                tlv(0x0108, &[0, 0, 0, 1]),
            ],
        ))
        .unwrap();
        let input = ipv4_tcp(&client_hello(), 700);

        assert_eq!(
            decide(&plan, &input),
            PacketDecision::Refused { plan_id: [0; 16] }
        );
    }

    #[test]
    fn partial_tls_client_hello_can_split_at_its_complete_sni() {
        let plan = Plan::parse(&plan_bytes(
            2,
            &[tlv(0x0002, &[6, 1]), tlv(0x0100, &[0, 5, 0, 0])],
        ))
        .unwrap();
        let hello = client_hello_with_sni_and_large_extension();
        let first_segment_len = 73;
        let input = ipv4_tcp(&hello[..first_segment_len], 700);

        let PacketDecision::Transmit { packets, fate } = decide(&plan, &input) else {
            panic!("a complete SNI in a partial ClientHello should permit its split");
        };
        assert_eq!(fate, OriginalFate::Drop);
        assert_eq!(packets.len(), 2);
        let first = PacketView::parse(&packets[0].packet).unwrap();
        let first_tcp = first.tcp_segment(&packets[0].packet).unwrap();
        assert_eq!(first_tcp.payload.len(), 67);
        let second = PacketView::parse(&packets[1].packet).unwrap();
        let second_tcp = second.tcp_segment(&packets[1].packet).unwrap();
        assert_eq!(second_tcp.sequence, 767);
        assert_eq!(&packets[1].packet[second_tcp.payload.clone()], b"e.test");
    }

    #[test]
    fn tcp_маршрутный_mtu_ограничивает_каждую_посылку_полезной_нагрузки() {
        let plan = Plan::parse(&plan_bytes(
            0,
            &[
                tlv(0x0002, &[6, 1]),
                tlv(0x0010, &[0, 1, b'F', b'A', b'K', b'E']),
                tlv(0x0101, &[0, 1, 0, 0, 1, 0, 0, 0, 0, 0]),
                tlv(0x0105, &[0, 0, 0x3a, 0x98]),
            ],
        ))
        .unwrap();
        let packet = ipv4_tcp(&client_hello_with_sni_and_large_extension(), 700);
        let mut sessions = TcpSessions::default();
        let PacketDecision::Transmit { packets, .. } =
            decide_with_session_mtu(&mut sessions, &plan, &packet, 128)
        else {
            panic!("маршрутный предел должен разбить TCP-посылки плана");
        };

        let mut fake_packets = 0;
        let mut payload_packets = 0;
        for emitted in packets
            .iter()
            .filter(|emitted| emitted.kind == EmitKind::Fake)
        {
            let view = PacketView::parse(&emitted.packet).unwrap();
            let tcp = view.tcp_segment(&emitted.packet).unwrap();
            assert_eq!(tcp.payload.len(), 4);
            fake_packets += 1;
        }
        for emitted in packets
            .iter()
            .filter(|emitted| emitted.kind == EmitKind::Payload)
        {
            let view = PacketView::parse(&emitted.packet).unwrap();
            let tcp = view.tcp_segment(&emitted.packet).unwrap();
            assert!(tcp.payload.len() <= 128);
            payload_packets += 1;
        }
        assert_eq!(fake_packets, 1);
        assert!(payload_packets > 2);
    }

    #[test]
    fn delayed_tcp_fakes_are_returned_with_their_relative_deadlines() {
        let plan = Plan::parse(&plan_bytes(
            0,
            &[
                tlv(0x0002, &[6, 1]),
                tlv(0x0010, &[0, 1, b'F', b'A', b'K', b'E']),
                tlv(0x0101, &[0, 1, 0, 0, 2, 0, 0, 1, 0x86, 0xa0]),
            ],
        ))
        .unwrap();
        assert!(validate_runtime_plan(&plan).is_ok());

        let PacketDecision::Transmit { packets, fate } =
            decide(&plan, &ipv4_tcp(&client_hello(), 700))
        else {
            panic!("delayed fake plan should produce a scheduled emission batch");
        };
        assert_eq!(fate, OriginalFate::Pass);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].delay_us, 0);
        assert_eq!(packets[1].delay_us, 100_000);
    }

    fn qsplit_plan() -> Plan {
        Plan::parse(&plan_bytes(10, &[tlv(0x0002, &[17, 2]), tlv(0x010f, &[1])])).unwrap()
    }

    fn udplen_refusal_plan() -> Plan {
        Plan::parse(&plan_bytes(
            9,
            &[
                tlv(0x0001, &[0x77; 16]),
                tlv(0x0002, &[17, 2]),
                tlv(0x010e, &u16::MAX.to_be_bytes()),
            ],
        ))
        .unwrap()
    }

    fn quic_ipfrag_plan(shape: u8) -> Plan {
        Plan::parse(&plan_bytes(
            7,
            &[tlv(0x0002, &[17, 2]), tlv(0x010c, &[shape])],
        ))
        .unwrap()
    }

    fn udplen_plan(increment: u16) -> Plan {
        Plan::parse(&plan_bytes(
            9,
            &[tlv(0x0002, &[17, 2]), tlv(0x010e, &increment.to_be_bytes())],
        ))
        .unwrap()
    }

    fn r2o_quic_clearance_plan() -> Plan {
        let mut payload = vec![0, 1];
        payload.extend_from_slice(&[0; 16]);
        Plan::parse(&plan_bytes(
            10,
            &[
                tlv(0x0002, &[17, 2]),
                tlv(0x0010, &payload),
                tlv(0x0101, &[0, 1, 0, 0, 1, 0, 0, 0, 0, 0]),
            ],
        ))
        .unwrap()
    }

    fn r2o_quic_ttl_probe_plan() -> Plan {
        let mut payload = vec![0, 1];
        payload.extend_from_slice(r2k_core::plan::R2K_QUIC_TTL_PROBE_PAYLOAD);
        Plan::parse(&plan_bytes(
            10,
            &[
                tlv(0x0002, &[17, 2]),
                tlv(0x0010, &payload),
                tlv(0x0011, &[0, 1, 3, 0, 0, 0, 0, 0]),
                tlv(0x0101, &[0, 1, 0, 1, 2, 0, 0, 0, 0, 0]),
            ],
        ))
        .unwrap()
    }

    fn tcp_fake_plan() -> Plan {
        Plan::parse(&plan_bytes(
            0,
            &[
                tlv(0x0002, &[6, 1]),
                tlv(0x0010, &[0, 1, b'F', b'A', b'K', b'E']),
                tlv(0x0101, &[0, 1, 0, 0, 1, 0, 0, 0, 0, 0]),
            ],
        ))
        .unwrap()
    }

    fn tcp_fake_plan_with_rst_guard() -> Plan {
        Plan::parse(&plan_bytes(
            0,
            &[
                tlv(0x0002, &[6, 1]),
                tlv(0x0010, &[0, 1, b'F', b'A', b'K', b'E']),
                tlv(0x0101, &[0, 1, 0, 0, 1, 0, 0, 0, 0, 0]),
                tlv(0x0104, &[1]),
            ],
        ))
        .unwrap()
    }

    fn tcp_guard_only_plan() -> Plan {
        Plan::parse(&plan_bytes(0, &[tlv(0x0002, &[6, 1]), tlv(0x0104, &[1])])).unwrap()
    }

    fn http_split_plan() -> Plan {
        Plan::parse(&plan_bytes(
            11,
            &[tlv(0x0002, &[6, 4]), tlv(0x0100, &[0, 5, 0, 0])],
        ))
        .unwrap()
    }

    fn plan_bytes(minexec: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&r2k_core::plan::PLAN_MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&minexec.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            bytes.extend_from_slice(record);
        }
        bytes
    }

    fn tlv(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + value.len());
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(value);
        bytes
    }

    fn ipv4_udp(payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut packet = vec![0; 20 + udp_len];
        packet[0] = 0x45;
        let ip_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&ip_len.to_be_bytes());
        packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&12345_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        packet
    }

    fn ipv6_udp(payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut packet = vec![0; 40 + udp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[24..40].copy_from_slice(
            &"2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[40..42].copy_from_slice(&12345_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443_u16.to_be_bytes());
        packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[48..].copy_from_slice(payload);
        packet
    }

    fn ipv4_tcp(payload: &[u8], sequence: u32) -> Vec<u8> {
        ipv4_tcp_packet(
            ([192, 0, 2, 10], 41000),
            ([198, 51, 100, 20], 443),
            0x18,
            64,
            sequence,
            payload,
        )
    }

    fn ipv4_tcp_packet(
        source: ([u8; 4], u16),
        destination: ([u8; 4], u16),
        flags: u8,
        ttl: u8,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0; 40 + payload.len()];
        packet[0] = 0x45;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = ttl;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source.0);
        packet[16..20].copy_from_slice(&destination.0);
        packet[20..22].copy_from_slice(&source.1.to_be_bytes());
        packet[22..24].copy_from_slice(&destination.1.to_be_bytes());
        packet[24..28].copy_from_slice(&sequence.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet[34..36].copy_from_slice(&4096u16.to_be_bytes());
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn client_hello() -> Vec<u8> {
        let mut hello = vec![0x16, 0x03, 0x03, 0, 47, 1, 0, 0, 43, 0x03, 0x03];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
        hello
    }

    fn d2o_flow_unfit_client_hello() -> Vec<u8> {
        let host = b"hetzner.com";
        let mut body = vec![0x03, 0x03];
        body.extend(0_u8..32);
        body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        let mut extension = vec![
            0,
            0,
            0,
            (5 + host.len()) as u8,
            0,
            (3 + host.len()) as u8,
            0,
            0,
            host.len() as u8,
        ];
        extension.extend_from_slice(host);
        body.push(0);
        body.push(extension.len() as u8);
        body.extend_from_slice(&extension);

        let mut handshake = vec![
            1,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        handshake.extend_from_slice(&body);
        let mut record = vec![
            0x16,
            0x03,
            0x01,
            (handshake.len() >> 8) as u8,
            handshake.len() as u8,
        ];
        record.extend_from_slice(&handshake);
        record
    }

    // Byte layout mirrors donor datapath/test_session.c build_pkt/build_pkt_ts.
    fn d2o_flow_unfit_client_packet(
        source_port: u16,
        flags: u8,
        payload: &[u8],
        timestamp: bool,
    ) -> Vec<u8> {
        let options: &[u8] = if timestamp {
            &[1, 1, 8, 10, 0x00, 0x12, 0x34, 0x56, 0, 0, 0, 0]
        } else {
            &[]
        };
        let tcp_header_len = 20 + options.len();
        let mut packet = vec![0; 20 + tcp_header_len + payload.len()];
        packet[0] = 0x45;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[4..6].copy_from_slice(&0x1000_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 168, 1, 67]);
        packet[16..20].copy_from_slice(&[1, 2, 3, 4]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[24..28].copy_from_slice(&1000_u32.to_be_bytes());
        packet[28..32].copy_from_slice(&0x1122_3344_u32.to_be_bytes());
        packet[32] = ((tcp_header_len / 4) as u8) << 4;
        packet[33] = flags;
        packet[34..36].copy_from_slice(&64240_u16.to_be_bytes());
        packet[40..40 + options.len()].copy_from_slice(options);
        packet[40 + options.len()..].copy_from_slice(payload);
        packet
    }

    // Byte layout mirrors donor datapath/test_session.c build_rev_pkt.
    fn d2o_flow_unfit_server_packet(client_port: u16, flags: u8) -> Vec<u8> {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[4..6].copy_from_slice(&0x2000_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[1, 2, 3, 4]);
        packet[16..20].copy_from_slice(&[192, 168, 1, 67]);
        packet[20..22].copy_from_slice(&443_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&client_port.to_be_bytes());
        packet[24..28].copy_from_slice(&5000_u32.to_be_bytes());
        packet[28..32].copy_from_slice(&1001_u32.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet[34..36].copy_from_slice(&64240_u16.to_be_bytes());
        packet
    }

    fn client_hello_with_sni() -> Vec<u8> {
        let host = b"example.test";
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1];
        handshake.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn client_hello_with_sni_and_large_extension() -> Vec<u8> {
        let host = b"example.test";
        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni_data.push(0);
        sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(host);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_data);
        extensions.extend_from_slice(&0x0015_u16.to_be_bytes());
        extensions.extend_from_slice(&400_u16.to_be_bytes());
        extensions.extend_from_slice(&[0x5a; 400]);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1];
        handshake.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn assert_udp_checksum_valid(packet: &[u8]) {
        let view = PacketView::parse(packet).unwrap();
        let mut expected = packet.to_vec();
        expected[view.l4_offset + 6..view.l4_offset + 8].fill(0);
        super::update_udp_checksum(&mut expected, &view).unwrap();
        assert_eq!(
            &packet[view.l4_offset + 6..view.l4_offset + 8],
            &expected[view.l4_offset + 6..view.l4_offset + 8]
        );
    }

    fn assert_ipv4_checksum_valid(packet: &[u8], header_len: usize) {
        let mut sum = 0_u64;
        for word in packet[..header_len].chunks(2) {
            sum += u64::from(u16::from_be_bytes([word[0], word[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum, 0xffff);
    }
}
