use r2k_core::addr::Address;
use r2k_core::packet::PacketView;
use std::collections::HashMap;
use std::collections::TryReserveError;
use std::time::{Duration, Instant};

const UDP_FLOW_SLOTS: usize = 2048;
const UDP_FLOW_LIMIT: usize = UDP_FLOW_SLOTS - UDP_FLOW_SLOTS / 4;
const UDP_IDLE: Duration = Duration::from_secs(120);

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oUdpTableStats {
    pub flows: usize,
    pub capacity: usize,
    pub refusals: u64,
}

/// Ограниченное состояние всех корректных UDP-кортежей datapath.
pub struct R2oUdpSessions {
    flows: HashMap<FlowKey, Instant>,
    refusals: u64,
}

impl R2oUdpSessions {
    pub fn new() -> Result<Self, TryReserveError> {
        let mut flows = HashMap::new();
        flows.try_reserve(UDP_FLOW_LIMIT)?;
        Ok(Self { flows, refusals: 0 })
    }

    /// Обновить поток, если пакет содержит целый UDP-заголовок.
    pub fn observe_packet(&mut self, packet: &[u8], now: Instant) -> bool {
        let Some(view) = PacketView::parse(packet)
            .filter(|view| view.protocol == 17 && view.fragment & 0x1fff == 0)
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
        let key = FlowKey::new(source, destination);

        if let Some(last_seen) = self.flows.get_mut(&key) {
            *last_seen = now;
            return true;
        }
        if self.flows.len() >= UDP_FLOW_LIMIT {
            self.refusals = self.refusals.saturating_add(1);
            return false;
        }
        self.flows.insert(key, now);
        true
    }

    /// Удалить записи, не обновлявшиеся в течение заданного срока.
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.flows.len();
        self.flows.retain(|_, last_seen| {
            !(now >= *last_seen && now.duration_since(*last_seen) >= UDP_IDLE)
        });
        before - self.flows.len()
    }

    pub fn stats(&self) -> R2oUdpTableStats {
        R2oUdpTableStats {
            flows: self.flows.len(),
            capacity: UDP_FLOW_SLOTS,
            refusals: self.refusals,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}
