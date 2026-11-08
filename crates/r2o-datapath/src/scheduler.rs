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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduledOwner {
    /// Посылка плана, привязанная к потоку (production-путь).
    Flow(FlowTicket),
    /// Отложенный UDP-хвост, владеющий NFQUEUE-ID до выдачи.
    Owned(u32),
    /// Лабораторная посылка без потока (paired differential).
    Raw,
}

struct ScheduledPacket {
    due: Instant,
    order: u64,
    owner: ScheduledOwner,
    packet: WirePacket,
}

/// Исход `pop_due_ex`; повторяет коды C `d2k_sched_pop_due_ex`.
pub enum ScheduledPop {
    Emitted {
        packet: WirePacket,
        owner: ScheduledOwner,
    },
    /// Владеющая посылка не влезла в буфер: ID возвращается вызывающему.
    OversizedOwned { owner_id: u32 },
    /// Обычная посылка не влезла и выброшена (C возвращает 0).
    Dropped,
    /// Созревших нет.
    Empty,
}

struct Reservation {
    ticket: FlowTicket,
    remaining: usize,
}

pub struct ScheduledQueue {
    capacity: usize,
    slot_size: usize,
    entries: Vec<ScheduledPacket>,
    flows: HashMap<FlowKey, FlowState>,
    reservations: HashMap<u64, Reservation>,
    reserved_packets: usize,
    next_order: u64,
    next_batch: u64,
    refusals: u64,
}

impl ScheduledQueue {
    pub fn with_capacity(capacity: usize) -> io::Result<Self> {
        Self::with_limits(capacity, 65536)
    }

    /// Вместимость и предельный размер посылки — как `d2k_sched_new`.
    pub fn with_limits(capacity: usize, slot_size: usize) -> io::Result<Self> {
        if capacity == 0 || slot_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "scheduler должен иметь ненулевую вместимость и слот",
            ));
        }
        Ok(Self {
            capacity,
            slot_size,
            entries: Vec::new(),
            flows: HashMap::new(),
            reservations: HashMap::new(),
            reserved_packets: 0,
            next_order: 0,
            next_batch: 1,
            refusals: 0,
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
        if count == 0 {
            return None;
        }
        let available = self.capacity.saturating_sub(used);
        if count > available {
            self.refusals = self
                .refusals
                .saturating_add(count.saturating_sub(available) as u64);
            return None;
        }
        if self
            .flows
            .get(&key)
            .is_some_and(|flow| flow.fin_mask & direction != 0)
        {
            return None;
        }
        if (!self.flows.contains_key(&key) && self.flows.len() >= self.capacity)
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
                owner: ScheduledOwner::Flow(ticket),
                packet,
            },
        );
        Ok(())
    }

    /// Лабораторная посылка без потока: сравнивает ядро очереди с C.
    pub fn push_raw(&mut self, due: Instant, packet: WirePacket) -> Result<(), WirePacket> {
        self.push_owner(due, packet, ScheduledOwner::Raw)
    }

    /// Отложенный UDP-хвост, владеющий NFQUEUE-ID до выдачи.
    pub fn push_owned(
        &mut self,
        due: Instant,
        packet: WirePacket,
        owner_id: u32,
    ) -> Result<(), WirePacket> {
        self.push_owner(due, packet, ScheduledOwner::Owned(owner_id))
    }

    fn push_owner(
        &mut self,
        due: Instant,
        packet: WirePacket,
        owner: ScheduledOwner,
    ) -> Result<(), WirePacket> {
        // C `push`: пустая посылка — -2 без счётчика; слишком длинная и
        // переполнение — -2/-1 со счётчиком отказов.
        if packet.packet.is_empty() {
            return Err(packet);
        }
        if packet.packet.len() > self.slot_size {
            self.refusals = self.refusals.saturating_add(1);
            return Err(packet);
        }
        if self.entries.len() >= self.capacity {
            self.refusals = self.refusals.saturating_add(1);
            return Err(packet);
        }
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
                owner,
                packet,
            },
        );
        Ok(())
    }

    /// Увеличить предельный размер слота; коды как `d2k_sched_grow_slot_size`.
    pub fn grow_slot_size(&mut self, slot_size: usize) -> i32 {
        if slot_size == 0 {
            return -1;
        }
        if slot_size <= self.slot_size {
            return 0;
        }
        if self.capacity > usize::MAX / slot_size {
            return -1;
        }
        self.slot_size = slot_size;
        1
    }

    /// Забрать созревшую посылку с C-семантикой `d2k_sched_pop_due_ex`.
    pub fn pop_due_ex(&mut self, now: Instant, outcap: usize) -> ScheduledPop {
        self.expire(now);
        let Some(entry) = self.entries.first() else {
            return ScheduledPop::Empty;
        };
        if entry.due > now {
            return ScheduledPop::Empty;
        }
        if entry.packet.packet.len() > outcap {
            self.refusals = self.refusals.saturating_add(1);
            let removed = self.entries.remove(0);
            return match removed.owner {
                ScheduledOwner::Owned(owner_id) => ScheduledPop::OversizedOwned { owner_id },
                _ => ScheduledPop::Dropped,
            };
        }
        let removed = self.entries.remove(0);
        ScheduledPop::Emitted {
            packet: removed.packet,
            owner: removed.owner,
        }
    }

    pub fn next_due(&self) -> Option<Instant> {
        self.entries.first().map(|entry| entry.due)
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
        let entry = self.entries.first()?;
        if entry.due > now || !matches!(entry.owner, ScheduledOwner::Flow(_)) {
            return None;
        }
        let scheduled = self.entries.remove(0);
        match scheduled.owner {
            ScheduledOwner::Flow(ticket) => Some((scheduled.packet, ticket)),
            _ => None,
        }
    }

    pub fn has_pending(&self, ticket: FlowTicket) -> bool {
        self.reservations
            .get(&ticket.batch)
            .is_some_and(|reservation| reservation.ticket == ticket)
            || self
                .entries
                .iter()
                .any(|entry| matches!(entry.owner, ScheduledOwner::Flow(owner) if owner == ticket))
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
        self.entries.retain(|entry| {
            !matches!(entry.owner, ScheduledOwner::Flow(owner) if owner.batch == ticket.batch)
        });
        if let Some(reservation) = self.reservations.remove(&ticket.batch) {
            self.reserved_packets -= reservation.remaining;
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn refusals(&self) -> u64 {
        self.refusals
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn cancel_flow(&mut self, key: FlowKey) {
        self.entries.retain(
            |entry| !matches!(entry.owner, ScheduledOwner::Flow(owner) if owner.key == key),
        );
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
        self.entries.retain(|entry| {
            !matches!(entry.owner, ScheduledOwner::Flow(owner)
                if owner.key == key && owner.direction == direction)
        });
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
        self.entries.retain(|entry| match entry.owner {
            ScheduledOwner::Flow(owner) => flows.contains_key(&owner.key),
            _ => true,
        });
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
    let (source_port, destination_port, flags) = match view.protocol {
        6 => {
            let tcp = view.tcp_segment(packet)?;
            (tcp.source_port, tcp.destination_port, tcp.flags)
        }
        17 => {
            let udp = packet.get(view.l4_offset..view.total_len)?;
            if udp.len() < 8 {
                return None;
            }
            (
                u16::from_be_bytes([udp[0], udp[1]]),
                u16::from_be_bytes([udp[2], udp[3]]),
                0,
            )
        }
        _ => return None,
    };
    let source = Endpoint {
        address: view.src.as_ip_addr(),
        port: source_port,
    };
    let destination = Endpoint {
        address: view.dst.as_ip_addr(),
        port: destination_port,
    };
    if source <= destination {
        Some((
            FlowKey {
                first: source,
                second: destination,
            },
            0x01,
            flags,
        ))
    } else {
        Some((
            FlowKey {
                first: destination,
                second: source,
            },
            0x02,
            flags,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::ScheduledQueue;
    use crate::engine::WirePacket;
    use r2k_core::plan::EmitKind;
    use std::time::{Duration, Instant};

    fn udp_packet(source_port: u16, destination_port: u16, reverse: bool) -> Vec<u8> {
        let (source, destination) = if reverse {
            ([198, 51, 100, 2], [192, 0, 2, 1])
        } else {
            ([192, 0, 2, 1], [198, 51, 100, 2])
        };
        let (source_port, destination_port) = if reverse {
            (destination_port, source_port)
        } else {
            (source_port, destination_port)
        };
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
        packet
    }

    #[test]
    fn delayed_udp_emit_survives_observing_the_reverse_packet() {
        let request = udp_packet(40156, 50005, false);
        let response = udp_packet(40156, 50005, true);
        let now = Instant::now();
        let mut scheduled = ScheduledQueue::default();
        let ticket = scheduled
            .reserve(&request, 1)
            .expect("a voice plan must reserve its paced UDP payload");
        let delayed_payload = WirePacket {
            packet: request.clone(),
            kind: EmitKind::Payload,
            delay_us: 0,
        };
        assert!(
            scheduled
                .push_reserved(ticket, now + Duration::from_millis(15), delayed_payload)
                .is_ok()
        );

        scheduled.observe(&response, now + Duration::from_millis(1));

        assert!(scheduled.has_pending(ticket));
        assert!(scheduled.pop_due(now + Duration::from_millis(14)).is_none());
        let (emitted, released_ticket) = scheduled
            .pop_due(now + Duration::from_millis(16))
            .expect("paced UDP payload should become due");
        assert_eq!(released_ticket, ticket);
        assert_eq!(emitted.packet, request);
        let hex = emitted
            .packet
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("RESULT delay_us=15000 packet={hex}");
    }

    #[test]
    fn scheduled_queue_statistics_count_capacity_refusal() {
        let request = udp_packet(40156, 50005, false);
        let now = Instant::now();
        let mut scheduled = ScheduledQueue::with_capacity(1).expect("capacity is nonzero");
        let ticket = scheduled
            .reserve(&request, 1)
            .expect("first slot is available");
        assert!(
            scheduled
                .push_reserved(
                    ticket,
                    now + Duration::from_millis(15),
                    WirePacket {
                        packet: request.clone(),
                        kind: EmitKind::Payload,
                        delay_us: 0,
                    },
                )
                .is_ok()
        );

        assert!(scheduled.reserve(&request, 1).is_none());
        assert_eq!(scheduled.len(), 1);
        assert_eq!(scheduled.refusals(), 1);
        println!(
            "METRICS queue={} refusals={}",
            scheduled.len(),
            scheduled.refusals()
        );
    }
}
