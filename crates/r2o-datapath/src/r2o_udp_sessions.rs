use crate::flow_capacity::R2oFlowCapacity;
use r2k_core::addr::Address;
use r2k_core::packet::PacketView;
use std::collections::{HashMap, TryReserveError};
use std::time::{Duration, Instant};

const UDP_IDLE: Duration = Duration::from_secs(120);
const UDP_HELLO_WINDOW: u8 = 8;

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
}

#[derive(Clone, Copy)]
struct FlowState {
    last_seen: Instant,
    plan_applied: bool,
    hello_seen: bool,
    hold_attempts: u8,
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
        Ok(Self {
            flows,
            flow_capacity,
            refusals: 0,
        })
    }

    /// Обновить поток, если пакет содержит целый UDP-заголовок.
    pub fn observe_packet(&mut self, packet: &[u8], now: Instant) -> bool {
        let Some(key) = flow_key_from_packet(packet) else {
            return false;
        };

        if let Some(flow) = self.flows.get_mut(&key) {
            flow.last_seen = now;
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
            },
        );
        true
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
        if flow.plan_applied || flow.hello_seen || flow.hold_attempts >= UDP_HELLO_WINDOW {
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

#[cfg(test)]
mod tests {
    use super::R2oUdpSessions;
    use crate::flow_capacity::R2oFlowCapacity;
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
}
