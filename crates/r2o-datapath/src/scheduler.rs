use crate::engine::WirePacket;
use r2k_core::packet::PacketView;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MAX_FLOW_IDLE: Duration = Duration::from_secs(120);
pub const MAX_SCHEDULED_PACKETS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Endpoint {
    address: IpAddr,
    port: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    first: Endpoint,
    second: Endpoint,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowTicket {
    key: FlowKey,
    direction: u8,
    batch: u64,
}

struct FlowState {
    last_seen: Instant,
    fin_mask: u8,
}

struct ScheduledPacket {
    due: Instant,
    order: u64,
    ticket: FlowTicket,
    packet: WirePacket,
}

struct Reservation {
    ticket: FlowTicket,
    remaining: usize,
}

pub struct ScheduledQueue {
    capacity: usize,
    entries: Vec<ScheduledPacket>,
    flows: HashMap<FlowKey, FlowState>,
    reservations: HashMap<u64, Reservation>,
    reserved_packets: usize,
    next_order: u64,
    next_batch: u64,
}

impl ScheduledQueue {
    pub fn with_capacity(capacity: usize) -> io::Result<Self> {
        if capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "scheduler должен иметь ненулевую вместимость",
            ));
        }
        Ok(Self {
            capacity,
            entries: Vec::new(),
            flows: HashMap::new(),
            reservations: HashMap::new(),
            reserved_packets: 0,
            next_order: 0,
            next_batch: 1,
        })
    }

    pub fn reserve(&mut self, flow_packet: &[u8], count: usize) -> Option<FlowTicket> {
        let now = Instant::now();
        self.expire(now);
        let (key, direction, flags) = flow_identity(flow_packet)?;
        if flags & (0x01 | 0x04) != 0 {
            return None;
        }
        if flags & 0x02 != 0 && flags & 0x10 == 0 {
            self.cancel_flow(key);
        }
        let used = self.entries.len().checked_add(self.reserved_packets)?;
        if count == 0 || count > self.capacity.saturating_sub(used) {
            return None;
        }
        if self
            .flows
            .get(&key)
            .is_some_and(|flow| flow.fin_mask & direction != 0)
            || (!self.flows.contains_key(&key) && self.flows.len() >= self.capacity)
            || self.entries.try_reserve(count).is_err()
            || self.reservations.try_reserve(1).is_err()
            || (!self.flows.contains_key(&key) && self.flows.try_reserve(1).is_err())
        {
            return None;
        }
        let flow = self.flows.entry(key).or_insert(FlowState {
            last_seen: now,
            fin_mask: 0,
        });
        flow.last_seen = now;
        let batch = self.next_batch;
        self.next_batch = self.next_batch.wrapping_add(1).max(1);
        let ticket = FlowTicket {
            key,
            direction,
            batch,
        };
        self.reserved_packets += count;
        self.reservations.insert(
            batch,
            Reservation {
                ticket,
                remaining: count,
            },
        );
        Some(ticket)
    }

    pub fn push_reserved(
        &mut self,
        ticket: FlowTicket,
        due: Instant,
        packet: WirePacket,
    ) -> Result<(), WirePacket> {
        let Some(reservation) = self.reservations.get(&ticket.batch) else {
            return Err(packet);
        };
        if reservation.ticket != ticket || reservation.remaining == 0 {
            return Err(packet);
        }
        let remaining = reservation.remaining - 1;
        self.reserved_packets -= 1;
        if remaining == 0 {
            self.reservations.remove(&ticket.batch);
        } else if let Some(reservation) = self.reservations.get_mut(&ticket.batch) {
            reservation.remaining = remaining;
        }
        let now = Instant::now();
        self.flows.entry(ticket.key).or_insert(FlowState {
            last_seen: now,
            fin_mask: 0,
        });
        let order = self.next_order;
        self.next_order = self.next_order.wrapping_add(1);
        let index = self
            .entries
            .partition_point(|entry| (entry.due, entry.order) <= (due, order));
        self.entries.insert(
            index,
            ScheduledPacket {
                due,
                order,
                ticket,
                packet,
            },
        );
        Ok(())
    }

    pub fn observe(&mut self, packet: &[u8], now: Instant) {
        self.expire(now);
        let Some((key, direction, flags)) = flow_identity(packet) else {
            return;
        };
        if !self.flows.contains_key(&key) {
            return;
        }
        if flags & 0x04 != 0 || flags & 0x02 != 0 && flags & 0x10 == 0 {
            self.cancel_flow(key);
            return;
        }
        let mut close_flow = false;
        if flags & 0x01 != 0 {
            let flow = self.flows.get_mut(&key).expect("flow checked above");
            flow.last_seen = now;
            flow.fin_mask |= direction;
            close_flow = flow.fin_mask == 0x03;
            self.cancel_direction(key, direction);
        } else if let Some(flow) = self.flows.get_mut(&key) {
            flow.last_seen = now;
        }
        if close_flow {
            self.cancel_flow(key);
        }
    }

    pub fn pop_due(&mut self, now: Instant) -> Option<(WirePacket, FlowTicket)> {
        self.expire(now);
        if self.entries.first().is_none_or(|entry| entry.due > now) {
            return None;
        }
        let scheduled = self.entries.remove(0);
        Some((scheduled.packet, scheduled.ticket))
    }

    pub fn has_pending(&self, ticket: FlowTicket) -> bool {
        self.reservations
            .get(&ticket.batch)
            .is_some_and(|reservation| reservation.ticket == ticket)
            || self.entries.iter().any(|entry| entry.ticket == ticket)
    }

    pub fn timeout_ms(&self, now: Instant, max_ms: i32) -> i32 {
        let Some(next) = self.entries.first().map(|entry| entry.due) else {
            return max_ms.max(0);
        };
        if next <= now || max_ms <= 0 {
            return 0;
        }
        let nanos = next.duration_since(now).as_nanos();
        let milliseconds = nanos.div_ceil(1_000_000).min(i32::MAX as u128) as i32;
        milliseconds.min(max_ms)
    }

    pub fn cancel(&mut self, ticket: FlowTicket) {
        self.entries
            .retain(|entry| entry.ticket.batch != ticket.batch);
        if let Some(reservation) = self.reservations.remove(&ticket.batch) {
            self.reserved_packets -= reservation.remaining;
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn cancel_flow(&mut self, key: FlowKey) {
        self.entries.retain(|entry| entry.ticket.key != key);
        let mut released = 0;
        self.reservations.retain(|_, reservation| {
            if reservation.ticket.key == key {
                released += reservation.remaining;
                false
            } else {
                true
            }
        });
        self.reserved_packets -= released;
        self.flows.remove(&key);
    }

    fn cancel_direction(&mut self, key: FlowKey, direction: u8) {
        self.entries
            .retain(|entry| entry.ticket.key != key || entry.ticket.direction != direction);
        let mut released = 0;
        self.reservations.retain(|_, reservation| {
            if reservation.ticket.key == key && reservation.ticket.direction == direction {
                released += reservation.remaining;
                false
            } else {
                true
            }
        });
        self.reserved_packets -= released;
    }

    fn expire(&mut self, now: Instant) {
        self.flows
            .retain(|_, flow| now.saturating_duration_since(flow.last_seen) < MAX_FLOW_IDLE);
        let flows = &self.flows;
        self.entries
            .retain(|entry| flows.contains_key(&entry.ticket.key));
        let mut released = 0;
        self.reservations.retain(|_, reservation| {
            if flows.contains_key(&reservation.ticket.key) {
                true
            } else {
                released += reservation.remaining;
                false
            }
        });
        self.reserved_packets -= released;
    }
}

impl Default for ScheduledQueue {
    fn default() -> Self {
        Self::with_capacity(MAX_SCHEDULED_PACKETS).expect("fixed scheduler capacity is nonzero")
    }
}

fn flow_identity(packet: &[u8]) -> Option<(FlowKey, u8, u8)> {
    let view = PacketView::parse(packet)?;
    let tcp = view.tcp_segment(packet)?;
    let source = Endpoint {
        address: view.src.as_ip_addr(),
        port: tcp.source_port,
    };
    let destination = Endpoint {
        address: view.dst.as_ip_addr(),
        port: tcp.destination_port,
    };
    if source <= destination {
        Some((
            FlowKey {
                first: source,
                second: destination,
            },
            0x01,
            tcp.flags,
        ))
    } else {
        Some((
            FlowKey {
                first: destination,
                second: source,
            },
            0x02,
            tcp.flags,
        ))
    }
}
