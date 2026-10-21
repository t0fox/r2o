use crate::flow_capacity::R2oFlowCapacity;
use crate::netlink::{
    R2O_NF_INET_LOCAL_IN, R2O_NF_INET_LOCAL_OUT, R2O_NF_INET_POST_ROUTING, R2O_NF_INET_PRE_ROUTING,
};
use crate::r2o_quic::R2oUdpExchangeEvent;
use r2k_core::addr::Address;
use r2k_core::control::KEY_LEN;
use r2k_core::packet::PacketView;
use std::collections::{HashMap, TryReserveError, VecDeque};
use std::time::{Duration, Instant};

const UDP_IDLE: Duration = Duration::from_secs(120);
const UDP_HELLO_WINDOW: u8 = 8;
const R2O_UDP_PROOF_NONE: u8 = 0;
const R2O_UDP_PROOF_STUN: u8 = 2;
const STUN_TRANSACTION_ID_LEN: usize = 12;

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
pub(crate) struct R2oUdpFlowKey {
    low: Endpoint,
    high: Endpoint,
}

impl R2oUdpFlowKey {
    fn new(source: Endpoint, destination: Endpoint) -> Self {
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
        key[37] = 17;
        key
    }
}

struct StunFlow {
    client: Endpoint,
    server: Endpoint,
    transaction_id: [u8; STUN_TRANSACTION_ID_LEN],
    exchange_told: bool,
    proof_told: bool,
}

struct FlowState {
    last_seen: Instant,
    plan_applied: bool,
    hello_seen: bool,
    hold_attempts: u8,
    r2o_client_is_low: Option<bool>,
    r2o_client_packets_seen: u8,
    stun: Option<StunFlow>,
}

pub(crate) fn flow_key_from_packet(packet: &[u8]) -> Option<R2oUdpFlowKey> {
    let view = PacketView::parse(packet)
        .filter(|view| view.protocol == 17 && view.fragment & 0x1fff == 0)?;
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
    Some(R2oUdpFlowKey::new(source, destination))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oUdpTableStats {
    pub flows: usize,
    pub capacity: usize,
    pub refusals: u64,
}

/// Ограниченное состояние всех корректных UDP-кортежей datapath.
pub struct R2oUdpSessions {
    flows: HashMap<R2oUdpFlowKey, FlowState>,
    udp_exchange_events: VecDeque<R2oUdpExchangeEvent>,
    flow_capacity: R2oFlowCapacity,
    refusals: u64,
}

impl R2oUdpSessions {
    pub fn new() -> Result<Self, TryReserveError> {
        Self::with_capacity(R2oFlowCapacity::default())
    }

    /// Создать таблицу UDP-потоков заданного размера с проверкой выделения памяти.
    pub fn with_capacity(flow_capacity: R2oFlowCapacity) -> Result<Self, TryReserveError> {
        let mut flows = HashMap::new();
        flows.try_reserve(flow_capacity.slots())?;
        let mut udp_exchange_events = VecDeque::new();
        udp_exchange_events.try_reserve(flow_capacity.limit())?;
        Ok(Self {
            flows,
            udp_exchange_events,
            flow_capacity,
            refusals: 0,
        })
    }

    /// Обновить поток, если пакет содержит целый UDP-заголовок.
    pub fn observe_packet(&mut self, packet: &[u8], now: Instant) -> bool {
        self.r2o_observe_packet_at_hook(packet, now, None)
    }

    /// Обновить поток и счётчик клиентских датаграмм с учётом направления NFQUEUE.
    pub fn r2o_observe_packet_at_hook(
        &mut self,
        packet: &[u8],
        now: Instant,
        hook: Option<u8>,
    ) -> bool {
        let Some(key) = flow_key_from_packet(packet) else {
            return false;
        };
        let r2o_known_client_is_low = self
            .flows
            .get(&key)
            .and_then(|r2o_flow| r2o_flow.r2o_client_is_low);
        let (r2o_client_packet, r2o_client_is_low) =
            r2o_udp_packet_direction(packet, key, hook, r2o_known_client_is_low)
                .unwrap_or((false, r2o_known_client_is_low));

        if let Some(flow) = self.flows.get_mut(&key) {
            flow.last_seen = now;
            flow.r2o_client_is_low = r2o_client_is_low;
            if r2o_client_packet {
                flow.r2o_client_packets_seen = flow.r2o_client_packets_seen.saturating_add(1);
            }
            return true;
        }
        if self.flows.len() >= self.flow_capacity.limit() {
            self.refusals = self.refusals.saturating_add(1);
            return false;
        }
        self.flows.insert(
            key,
            FlowState {
                last_seen: now,
                plan_applied: false,
                hello_seen: false,
                hold_attempts: 0,
                r2o_client_is_low,
                r2o_client_packets_seen: u8::from(r2o_client_packet),
                stun: None,
            },
        );
        true
    }

    /// Связать ответный STUN Binding с первым запросом UDP-потока.
    pub fn r2o_observe_stun_packet_at_hook(
        &mut self,
        packet: &[u8],
        now: Instant,
        hook: Option<u8>,
    ) {
        let Some(view) = PacketView::parse(packet)
            .filter(|view| view.protocol == 17 && view.fragment & 0x1fff == 0)
        else {
            return;
        };
        let Some(udp) = packet.get(view.l4_offset..view.total_len) else {
            return;
        };
        if udp.len() < 8 {
            return;
        }
        let Some(payload_range) = view.udp_payload_range(packet) else {
            return;
        };
        let Some(payload) = packet.get(payload_range) else {
            return;
        };
        let key = R2oUdpFlowKey::new(
            Endpoint {
                address: view.src,
                port: u16::from_be_bytes([udp[0], udp[1]]),
            },
            Endpoint {
                address: view.dst,
                port: u16::from_be_bytes([udp[2], udp[3]]),
            },
        );
        let source = Endpoint {
            address: view.src,
            port: u16::from_be_bytes([udp[0], udp[1]]),
        };
        let destination = Endpoint {
            address: view.dst,
            port: u16::from_be_bytes([udp[2], udp[3]]),
        };
        let client_hook = matches!(hook, Some(R2O_NF_INET_LOCAL_OUT | R2O_NF_INET_POST_ROUTING));

        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };
        flow.last_seen = now;

        if flow.stun.is_none() {
            if !client_hook || !r2k_core::stun::is_binding_request(payload) {
                return;
            }
            let Some(transaction_id) = payload.get(8..20).and_then(|bytes| bytes.try_into().ok())
            else {
                return;
            };
            flow.stun = Some(StunFlow {
                client: source,
                server: destination,
                transaction_id,
                exchange_told: false,
                proof_told: false,
            });
            return;
        }

        let Some(stun) = flow.stun.as_mut() else {
            return;
        };
        if source == stun.client && destination == stun.server {
            return;
        }
        if source != stun.server || destination != stun.client {
            return;
        }

        let proof_matches = r2k_core::stun::is_binding_response_for(payload, &stun.transaction_id);
        if proof_matches && !stun.proof_told {
            stun.proof_told = true;
            stun.exchange_told = true;
            if self.udp_exchange_events.len() < self.flow_capacity.limit() {
                self.udp_exchange_events.push_back(R2oUdpExchangeEvent {
                    key: key.wire_key(),
                    code: R2O_UDP_PROOF_STUN,
                    num: payload.len().min(u32::MAX as usize) as u32,
                });
            }
        } else if !stun.exchange_told {
            stun.exchange_told = true;
            if self.udp_exchange_events.len() < self.flow_capacity.limit() {
                self.udp_exchange_events.push_back(R2oUdpExchangeEvent {
                    key: key.wire_key(),
                    code: R2O_UDP_PROOF_NONE,
                    num: payload.len().min(u32::MAX as usize) as u32,
                });
            }
        }
    }

    /// Забрать накопленные события UDP-обмена и STUN-подтверждения.
    pub fn r2o_take_udp_exchange_events(&mut self) -> Vec<R2oUdpExchangeEvent> {
        self.udp_exchange_events.drain(..).collect()
    }

    /// Проверить, применялся ли уже план к этому UDP-потоку.
    pub fn r2o_plan_applied(&self, packet: &[u8]) -> bool {
        flow_key_from_packet(packet)
            .and_then(|key| self.flows.get(&key))
            .is_some_and(|flow| flow.plan_applied)
    }

    /// Отметить первое применение плана к UDP-потоку.
    pub fn r2o_mark_plan_applied(&mut self, packet: &[u8]) -> bool {
        let Some(flow) = flow_key_from_packet(packet).and_then(|key| self.flows.get_mut(&key))
        else {
            return false;
        };
        !std::mem::replace(&mut flow.plan_applied, true)
    }

    /// Разрешить повтор плана после потери UDP-датаграммы при его исполнении.
    pub fn r2o_note_execution_failure(
        &mut self,
        r2o_packet: &[u8],
        r2o_sends_done: bool,
        r2o_payload_on_wire: bool,
        r2o_original_spent: bool,
        r2o_original_taken: bool,
    ) -> bool {
        let Some(flow) = flow_key_from_packet(r2o_packet).and_then(|key| self.flows.get_mut(&key))
        else {
            return false;
        };
        if !flow.plan_applied || r2o_payload_on_wire {
            return false;
        }
        let lost = if r2o_original_spent {
            r2o_original_taken
        } else {
            r2o_sends_done
        };
        if lost {
            flow.plan_applied = false;
        }
        lost
    }

    /// Начать удержание QUIC Initial только в пределах окна первых попыток.
    pub fn r2o_begin_hold(&mut self, packet: &[u8]) -> bool {
        let Some(flow) = flow_key_from_packet(packet).and_then(|key| self.flows.get_mut(&key))
        else {
            return false;
        };
        if flow.plan_applied
            || flow.hello_seen
            || flow.hold_attempts >= UDP_HELLO_WINDOW
            || flow.r2o_client_packets_seen > UDP_HELLO_WINDOW
        {
            return false;
        }
        flow.hold_attempts += 1;
        true
    }

    /// Запретить повторное удержание после сборки ClientHello.
    pub fn r2o_mark_hello_seen(&mut self, packet: &[u8]) -> bool {
        let Some(flow) = flow_key_from_packet(packet).and_then(|key| self.flows.get_mut(&key))
        else {
            return false;
        };
        !std::mem::replace(&mut flow.hello_seen, true)
    }

    /// Удалить записи, не обновлявшиеся в течение заданного срока.
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.flows.len();
        self.flows.retain(|_, flow| {
            !(now >= flow.last_seen && now.duration_since(flow.last_seen) >= UDP_IDLE)
        });
        before - self.flows.len()
    }

    pub fn stats(&self) -> R2oUdpTableStats {
        R2oUdpTableStats {
            flows: self.flows.len(),
            capacity: self.flow_capacity.slots(),
            refusals: self.refusals,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

fn r2o_udp_packet_direction(
    packet: &[u8],
    key: R2oUdpFlowKey,
    hook: Option<u8>,
    r2o_known_client_is_low: Option<bool>,
) -> Option<(bool, Option<bool>)> {
    let Some(view) =
        PacketView::parse(packet).filter(|view| view.protocol == 17 && view.fragment & 0x3fff == 0)
    else {
        return None;
    };
    let Some(udp) = packet.get(view.l4_offset..view.total_len) else {
        return None;
    };
    if udp.len() < 8 {
        return None;
    }
    let r2o_source = Endpoint {
        address: view.src,
        port: u16::from_be_bytes([udp[0], udp[1]]),
    };
    let r2o_source_is_low = r2o_source == key.low;
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    match hook {
        Some(R2O_NF_INET_LOCAL_OUT | R2O_NF_INET_POST_ROUTING) => {
            Some((true, Some(r2o_source_is_low)))
        }
        Some(R2O_NF_INET_LOCAL_IN | R2O_NF_INET_PRE_ROUTING) => {
            Some((false, r2o_known_client_is_low))
        }
        _ if let Some(r2o_client_is_low) = r2o_known_client_is_low => Some((
            r2o_source_is_low == r2o_client_is_low,
            Some(r2o_client_is_low),
        )),
        // FORWARD видит обе стороны транзитного потока; без сохранённого
        // направления QUIC-клиента используем донорский резерв по порту 443.
        _ => {
            let r2o_from_client = destination_port == 443 && source_port != 443;
            Some((
                r2o_from_client,
                r2o_from_client.then_some(r2o_source_is_low),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::R2oUdpSessions;
    use crate::flow_capacity::R2oFlowCapacity;
    use crate::netlink::{R2O_NF_INET_FORWARD, R2O_NF_INET_POST_ROUTING};
    use r2k_core::stun::binding_request;
    use std::time::Instant;

    fn r2o_udp_packet(source_port: u16) -> Vec<u8> {
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
        packet
    }

    fn r2o_stun_packet(
        source: ([u8; 4], u16),
        destination: ([u8; 4], u16),
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0; 28 + payload.len()];
        let packet_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.0);
        packet[16..20].copy_from_slice(&destination.0);
        packet[20..22].copy_from_slice(&source.1.to_be_bytes());
        packet[22..24].copy_from_slice(&destination.1.to_be_bytes());
        packet[24..26].copy_from_slice(&(8_u16 + payload.len() as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        packet
    }

    fn r2o_stun_response(transaction_id: [u8; 12]) -> [u8; 20] {
        let mut response = [0; 20];
        response[..8].copy_from_slice(&[0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
        response[8..].copy_from_slice(&transaction_id);
        response
    }

    #[test]
    fn r2o_udp_настраивает_ёмкость_и_отказывает_после_трёх_четвертей() {
        let capacity = R2oFlowCapacity::from_requested(64).unwrap();
        let mut sessions = R2oUdpSessions::with_capacity(capacity).unwrap();
        let now = Instant::now();
        for port in 1000..1048 {
            assert!(sessions.observe_packet(&r2o_udp_packet(port), now));
        }
        assert!(!sessions.observe_packet(&r2o_udp_packet(2000), now));
        assert!(sessions.observe_packet(&r2o_udp_packet(1000), now));
        assert_eq!(sessions.stats().flows, 48);
        assert_eq!(sessions.stats().capacity, 64);
        assert_eq!(sessions.stats().refusals, 1);
    }

    #[test]
    fn r2o_udp_повторяет_план_только_если_исполнение_потеряло_датаграмму() {
        let packet = r2o_udp_packet(44300);
        let mut sessions = R2oUdpSessions::new().unwrap();
        let now = Instant::now();
        assert!(sessions.observe_packet(&packet, now));
        assert!(sessions.r2o_mark_plan_applied(&packet));

        assert!(!sessions.r2o_note_execution_failure(&packet, true, true, true, true));
        assert!(sessions.r2o_plan_applied(&packet));

        assert!(!sessions.r2o_note_execution_failure(&packet, true, false, true, false));
        assert!(sessions.r2o_plan_applied(&packet));

        assert!(sessions.r2o_note_execution_failure(&packet, false, false, true, true));
        assert!(!sessions.r2o_plan_applied(&packet));
        assert!(sessions.r2o_mark_plan_applied(&packet));

        assert!(sessions.r2o_note_execution_failure(&packet, true, false, false, true));
        assert!(!sessions.r2o_plan_applied(&packet));
        assert!(sessions.r2o_mark_plan_applied(&packet));

        assert!(!sessions.r2o_note_execution_failure(&packet, false, false, false, true));
        assert!(sessions.r2o_plan_applied(&packet));
    }

    #[test]
    fn r2o_stun_сверяет_transaction_id_и_отдельно_журналирует_обмен() {
        let client = ([192, 0, 2, 10], 53_123);
        let server = ([198, 51, 100, 20], 3478);
        let transaction_id = [9; 12];
        let request = binding_request(transaction_id);
        let mut foreign_id = transaction_id;
        foreign_id[0] ^= 0xff;
        let foreign_response = r2o_stun_response(foreign_id);
        let matching_response = r2o_stun_response(transaction_id);
        let start = Instant::now();
        let mut sessions = R2oUdpSessions::new().unwrap();

        let request_packet = r2o_stun_packet(client, server, &request);
        assert!(sessions.observe_packet(&request_packet, start));
        sessions.r2o_observe_stun_packet_at_hook(
            &request_packet,
            start,
            Some(R2O_NF_INET_POST_ROUTING),
        );
        assert!(sessions.r2o_take_udp_exchange_events().is_empty());

        let foreign_packet = r2o_stun_packet(server, client, &foreign_response);
        assert!(sessions.observe_packet(&foreign_packet, start));
        sessions.r2o_observe_stun_packet_at_hook(
            &foreign_packet,
            start + std::time::Duration::from_millis(10),
            Some(R2O_NF_INET_FORWARD),
        );
        let generic = sessions.r2o_take_udp_exchange_events();
        assert_eq!(generic.len(), 1);
        assert_eq!(generic[0].code, 0);
        assert_eq!(generic[0].num, 20);

        let matching_packet = r2o_stun_packet(server, client, &matching_response);
        assert!(sessions.observe_packet(&matching_packet, start));
        sessions.r2o_observe_stun_packet_at_hook(
            &matching_packet,
            start + std::time::Duration::from_millis(20),
            Some(R2O_NF_INET_FORWARD),
        );
        let proof = sessions.r2o_take_udp_exchange_events();
        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0].code, 2);
        assert_eq!(proof[0].num, 20);
        assert_eq!(proof[0].key[37], 17);

        sessions.r2o_observe_stun_packet_at_hook(
            &matching_packet,
            start + std::time::Duration::from_millis(30),
            Some(R2O_NF_INET_FORWARD),
        );
        assert!(sessions.r2o_take_udp_exchange_events().is_empty());
    }

    #[test]
    fn r2o_stun_не_создаёт_транзакцию_на_входящем_запросе() {
        let client = ([192, 0, 2, 10], 53_123);
        let server = ([198, 51, 100, 20], 3478);
        let request = binding_request([4; 12]);
        let response = r2o_stun_response([4; 12]);
        let start = Instant::now();
        let mut sessions = R2oUdpSessions::new().unwrap();
        let request_packet = r2o_stun_packet(server, client, &request);
        assert!(sessions.observe_packet(&request_packet, start));
        sessions.r2o_observe_stun_packet_at_hook(&request_packet, start, Some(R2O_NF_INET_FORWARD));

        let response_packet = r2o_stun_packet(client, server, &response);
        assert!(sessions.observe_packet(&response_packet, start));
        sessions.r2o_observe_stun_packet_at_hook(
            &response_packet,
            start + std::time::Duration::from_millis(10),
            Some(R2O_NF_INET_FORWARD),
        );
        assert!(sessions.r2o_take_udp_exchange_events().is_empty());
    }
}
