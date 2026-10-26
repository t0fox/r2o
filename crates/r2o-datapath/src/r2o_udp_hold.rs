use crate::netlink::{
    R2O_NF_INET_FORWARD, R2O_NF_INET_LOCAL_IN, R2O_NF_INET_LOCAL_OUT, R2O_NF_INET_POST_ROUTING,
    R2O_NF_INET_PRE_ROUTING,
};
use crate::r2o_udp_sessions::{R2oUdpFlowKey, flow_key_from_packet};
use r2k_core::packet::PacketView;
use std::time::{Duration, Instant};

const R2O_UDP_HOLD_SLOTS: usize = 16;
const R2O_UDP_HOLD_PACKETS: usize = 8;
const R2O_UDP_HOLD_PACKET_MAX: usize = 1600;
const R2O_UDP_HOLD_WAIT: Duration = Duration::from_millis(100);
const R2O_UDP_RELEASE_SLOTS: usize = 16;
const R2O_UDP_RELEASE_PACKETS: usize = 8;
const R2O_UDP_FOLLOW_SLOTS: usize = 256;
const R2O_UDP_FOLLOW_WAIT: Duration = Duration::from_millis(5);

/// Проверить безопасное направление и тип клиентской QUIC Initial-датаграммы.
pub fn r2o_udp_hold_candidate(packet: &[u8], hook: Option<u8>) -> bool {
    let Some(view) =
        PacketView::parse(packet).filter(|view| view.protocol == 17 && view.fragment & 0x3fff == 0)
    else {
        return false;
    };
    let Some(udp) = packet.get(view.l4_offset..view.total_len) else {
        return false;
    };
    if udp.len() < 8 {
        return false;
    }
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    let client_direction = match hook {
        Some(R2O_NF_INET_LOCAL_OUT | R2O_NF_INET_POST_ROUTING) => true,
        Some(R2O_NF_INET_LOCAL_IN | R2O_NF_INET_PRE_ROUTING | R2O_NF_INET_FORWARD) => false,
        _ => destination_port == 443 && source_port != 443,
    };
    if !client_direction {
        return false;
    }
    let Some(payload_range) = view.udp_payload_range(packet) else {
        return false;
    };
    packet
        .get(payload_range)
        .is_some_and(|payload| r2k_core::quic::r2k_quic_initial_flight_id(payload).is_some())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oUdpHeldPacket {
    pub id: u32,
    pub mark: u32,
    pub packet: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct R2oUdpHoldBatch {
    pub(crate) key: R2oUdpFlowKey,
    pub packets: Vec<R2oUdpHeldPacket>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oUdpReleaseStats {
    pub resent: usize,
    pub resend_failed: usize,
    pub verdict_failures: usize,
    pub head_succeeded: bool,
}

/// Освободить удержанную пачку в порядке «голова, хвост raw, DROP копии».
pub fn r2o_release_batch_with(
    batch: &R2oUdpHoldBatch,
    head_verdict: u32,
    head_already_released: bool,
    can_resend: bool,
    mut is_neutral: impl FnMut(&R2oUdpHeldPacket) -> bool,
    mut resend: impl FnMut(&R2oUdpHeldPacket) -> std::io::Result<()>,
    mut on_permanent_failure: impl FnMut(&R2oUdpHeldPacket),
    mut send_verdict: impl FnMut(u32, u32) -> std::io::Result<()>,
) -> R2oUdpReleaseStats {
    let mut stats = R2oUdpReleaseStats::default();
    if batch.packets.is_empty() || batch.packets.len() > R2O_UDP_RELEASE_PACKETS {
        return stats;
    }

    let head_succeeded = if head_already_released {
        true
    } else if send_verdict(batch.packets[0].id, head_verdict).is_ok() {
        true
    } else {
        stats.verdict_failures += 1;
        false
    };
    stats.head_succeeded = head_succeeded;

    for tail in batch.packets.iter().skip(1) {
        let can_send_raw = head_succeeded && can_resend && is_neutral(tail);
        let verdict = if can_send_raw {
            match resend(tail) {
                Ok(()) => {
                    stats.resent += 1;
                    0
                }
                Err(error) => {
                    stats.resend_failed += 1;
                    if !r2o_udp_send_busy(&error) {
                        on_permanent_failure(tail);
                    }
                    1
                }
            }
        } else {
            1
        };
        if send_verdict(tail.id, verdict).is_err() {
            stats.verdict_failures += 1;
            if verdict == 0 && send_verdict(tail.id, 1).is_err() {
                stats.verdict_failures += 1;
            }
        }
    }
    stats
}

#[derive(Debug, Eq, PartialEq)]
pub enum R2oUdpHoldFeed {
    Held,
    Refused,
    Overflow(R2oUdpHoldBatch),
}

struct R2oUdpHoldSlot {
    key: R2oUdpFlowKey,
    deadline: Instant,
    packets: Vec<R2oUdpHeldPacket>,
}

/// Ограниченное владение NFQUEUE ID для собираемого QUIC ClientHello.
pub struct R2oUdpHoldTable {
    slots: [Option<R2oUdpHoldSlot>; R2O_UDP_HOLD_SLOTS],
}

impl R2oUdpHoldTable {
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
        }
    }

    /// Сохранить полную датаграмму и её mark, не перенося владение при отказе.
    pub fn r2o_feed(&mut self, id: u32, mark: u32, packet: &[u8], now: Instant) -> R2oUdpHoldFeed {
        if packet.len() > R2O_UDP_HOLD_PACKET_MAX {
            return R2oUdpHoldFeed::Refused;
        }
        let Some(key) = flow_key_from_packet(packet) else {
            return R2oUdpHoldFeed::Refused;
        };
        let index = self
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.key == key));
        let Some(index) = index.or_else(|| self.slots.iter().position(Option::is_none)) else {
            return R2oUdpHoldFeed::Refused;
        };
        if let Some(slot) = self.slots[index].as_mut() {
            if slot.packets.len() == R2O_UDP_HOLD_PACKETS {
                let slot = self.slots[index].take().expect("занятая ячейка найдена");
                return R2oUdpHoldFeed::Overflow(R2oUdpHoldBatch {
                    key: slot.key,
                    packets: slot.packets,
                });
            }
            slot.packets.push(R2oUdpHeldPacket {
                id,
                mark,
                packet: packet.to_vec(),
            });
        } else {
            let mut packets = Vec::with_capacity(R2O_UDP_HOLD_PACKETS);
            packets.push(R2oUdpHeldPacket {
                id,
                mark,
                packet: packet.to_vec(),
            });
            self.slots[index] = Some(R2oUdpHoldSlot {
                key,
                deadline: now + R2O_UDP_HOLD_WAIT,
                packets,
            });
        }
        R2oUdpHoldFeed::Held
    }

    /// Забрать всю FIFO-пачку потока, не выдавая вердикты её ID.
    pub fn r2o_take(&mut self, packet: &[u8]) -> Option<R2oUdpHoldBatch> {
        let key = flow_key_from_packet(packet)?;
        let index = self
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.key == key))?;
        let slot = self.slots[index].take()?;
        Some(R2oUdpHoldBatch {
            key: slot.key,
            packets: slot.packets,
        })
    }

    /// Забрать все пачки, чей срок удержания истёк.
    pub fn r2o_flush(&mut self, now: Instant) -> Vec<R2oUdpHoldBatch> {
        let mut expired = Vec::new();
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|slot| now >= slot.deadline)
                && let Some(slot) = slot.take()
            {
                expired.push(R2oUdpHoldBatch {
                    key: slot.key,
                    packets: slot.packets,
                });
            }
        }
        expired
    }

    /// Забрать все удержанные пачки для fail-open или завершения runtime.
    pub fn r2o_drain(&mut self) -> Vec<R2oUdpHoldBatch> {
        self.slots
            .iter_mut()
            .filter_map(Option::take)
            .map(|slot| R2oUdpHoldBatch {
                key: slot.key,
                packets: slot.packets,
            })
            .collect()
    }

    /// Вернуть срок до ближайшего истечения пачки.
    pub fn timeout_ms(&self, now: Instant, max_ms: i32) -> i32 {
        let Some(next) = self
            .slots
            .iter()
            .filter_map(|slot| slot.as_ref().map(|entry| entry.deadline))
            .min()
        else {
            return max_ms.max(0);
        };
        if next <= now || max_ms <= 0 {
            return 0;
        }
        let milliseconds = next.duration_since(now).as_nanos().div_ceil(1_000_000);
        milliseconds.min(i32::MAX as u128).min(max_ms as u128) as i32
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }
}

impl Default for R2oUdpHoldTable {
    fn default() -> Self {
        Self::new()
    }
}

struct R2oUdpDeferredBatch {
    due: Instant,
    order: u64,
    flow_key: Option<R2oUdpFollowKey>,
    count: usize,
    ids: [u32; R2O_UDP_RELEASE_PACKETS],
    verdicts: [u32; R2O_UDP_RELEASE_PACKETS],
}

/// Ограниченная очередь вердиктов, ожидающих отложенные UDP-отправки.
pub struct R2oUdpDeferredVerdicts {
    slots: [Option<R2oUdpDeferredBatch>; R2O_UDP_RELEASE_SLOTS],
    next_order: u64,
}

impl R2oUdpDeferredVerdicts {
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            next_order: 0,
        }
    }

    /// Принять ограниченную пачку ID и соответствующих ей вердиктов.
    pub fn r2o_enqueue(
        &mut self,
        due: Instant,
        ids: &[u32],
        verdicts: &[u32],
        flow_packet: Option<&[u8]>,
    ) -> bool {
        if ids.is_empty() || ids.len() > R2O_UDP_RELEASE_PACKETS || ids.len() != verdicts.len() {
            return false;
        }
        let flow_key = match flow_packet {
            Some(packet) => R2oUdpFollowKey::from_packet(packet),
            None => None,
        };
        if flow_packet.is_some() && flow_key.is_none() {
            return false;
        }
        let Some(index) = self.slots.iter().position(Option::is_none) else {
            return false;
        };
        let mut entry = R2oUdpDeferredBatch {
            due,
            order: self.next_order,
            flow_key,
            count: ids.len(),
            ids: [0; R2O_UDP_RELEASE_PACKETS],
            verdicts: [0; R2O_UDP_RELEASE_PACKETS],
        };
        entry.ids[..ids.len()].copy_from_slice(ids);
        entry.verdicts[..verdicts.len()].copy_from_slice(verdicts);
        self.next_order = self.next_order.wrapping_add(1);
        self.slots[index] = Some(entry);
        true
    }

    /// Отменить поздние вердикты потока, чей отложенный emit не завершился.
    pub fn r2o_cancel_flow(&mut self, packet: &[u8]) -> Vec<u32> {
        let Some(key) = R2oUdpFollowKey::from_packet(packet) else {
            return Vec::new();
        };
        let mut ids = Vec::new();
        for slot in &mut self.slots {
            if slot
                .as_ref()
                .is_some_and(|entry| entry.flow_key == Some(key))
                && let Some(entry) = slot.take()
            {
                ids.extend_from_slice(&entry.ids[..entry.count]);
            }
        }
        ids
    }

    /// Выдать все созревшие пачки по сроку и исходному порядку.
    pub fn r2o_flush(
        &mut self,
        now: Instant,
        mut send: impl FnMut(u32, u32) -> std::io::Result<()>,
    ) -> std::io::Result<usize> {
        let mut released = 0;
        let mut first_error = None;
        loop {
            let next = self
                .slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| {
                    let entry = slot.as_ref()?;
                    (entry.due <= now).then_some((index, entry.due, entry.order))
                })
                .min_by_key(|(_, due, order)| (*due, *order))
                .map(|(index, _, _)| index);
            let Some(index) = next else {
                break;
            };
            let entry = self.slots[index].take().expect("созревшая ячейка найдена");
            for (&id, &verdict) in entry.ids[..entry.count]
                .iter()
                .zip(&entry.verdicts[..entry.count])
            {
                if let Err(error) = send(id, verdict) {
                    first_error.get_or_insert(error);
                }
            }
            released += 1;
        }
        first_error.map_or(Ok(released), Err)
    }

    /// Принять все ещё удержанные ID, например при штатном завершении.
    pub fn r2o_drain_accept(&mut self) -> Vec<u32> {
        let mut ids = Vec::new();
        for slot in &mut self.slots {
            if let Some(entry) = slot.take() {
                ids.extend_from_slice(&entry.ids[..entry.count]);
            }
        }
        ids
    }

    /// Вернуть срок до следующей выдачи, ограниченный заданным интервалом.
    pub fn timeout_ms(&self, now: Instant, max_ms: i32) -> i32 {
        let Some(next) = self
            .slots
            .iter()
            .filter_map(|slot| slot.as_ref().map(|v| v.due))
            .min()
        else {
            return max_ms.max(0);
        };
        if next <= now || max_ms <= 0 {
            return 0;
        }
        let milliseconds = next.duration_since(now).as_nanos().div_ceil(1_000_000);
        milliseconds.min(i32::MAX as u128).min(max_ms as u128) as i32
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }
}

impl Default for R2oUdpDeferredVerdicts {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct R2oUdpFollowKey {
    family: u8,
    source: [u8; 16],
    destination: [u8; 16],
    ports: [u8; 4],
}

impl R2oUdpFollowKey {
    fn from_packet(packet: &[u8]) -> Option<Self> {
        let view = PacketView::parse(packet)
            .filter(|view| view.protocol == 17 && view.fragment & 0x3fff == 0)?;
        let udp = packet.get(view.l4_offset..view.total_len)?;
        if udp.len() < 8 {
            return None;
        }
        let destination = view.dst.bytes();
        if view.family == 4 && destination[0] >= 224 || view.family == 6 && destination[0] == 0xff {
            return None;
        }
        Some(Self {
            family: view.family,
            source: view.src.bytes(),
            destination,
            ports: udp[..4].try_into().ok()?,
        })
    }
}

struct R2oUdpFollowEntry {
    key: R2oUdpFollowKey,
    until: Instant,
    deferred_at: Option<Instant>,
    receive_seq: u64,
    failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oUdpFollowMatch {
    pub at: Option<Instant>,
    pub failed: bool,
}

/// Ограниченное окно сопоставления поздних копий уже выпущенной UDP-головы.
pub struct R2oUdpFollowTable {
    slots: [Option<R2oUdpFollowEntry>; R2O_UDP_FOLLOW_SLOTS],
    live: usize,
}

impl R2oUdpFollowTable {
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            live: 0,
        }
    }

    /// Запомнить направленный клиентский кортеж после выпуска его головы.
    pub fn r2o_mark(
        &mut self,
        packet: &[u8],
        now: Instant,
        at: Option<Instant>,
        receive_seq: u64,
    ) -> bool {
        let Some(key) = R2oUdpFollowKey::from_packet(packet) else {
            return false;
        };
        let deferred_at = at.filter(|due| *due > now);
        let anchor = deferred_at.unwrap_or(now);
        let Some(index) = self
            .slots
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.key == key))
            .or_else(|| self.slots.iter().position(Option::is_none))
            .or_else(|| {
                self.slots
                    .iter()
                    .enumerate()
                    .filter_map(|(index, entry)| entry.as_ref().map(|entry| (index, entry.until)))
                    .min_by_key(|(_, until)| *until)
                    .map(|(index, _)| index)
            })
        else {
            return false;
        };
        if self.slots[index].is_none() {
            self.live += 1;
        }
        self.slots[index] = Some(R2oUdpFollowEntry {
            key,
            until: anchor + R2O_UDP_FOLLOW_WAIT,
            deferred_at,
            receive_seq,
            failed: false,
        });
        true
    }

    /// Найти только прямую копию в той же пачке приёма или в окне 5 мс.
    pub fn r2o_match(
        &mut self,
        packet: &[u8],
        now: Instant,
        receive_seq: u64,
    ) -> Option<R2oUdpFollowMatch> {
        let key = R2oUdpFollowKey::from_packet(packet)?;
        for index in 0..self.slots.len() {
            let Some(entry) = self.slots[index].as_ref() else {
                continue;
            };
            let stale = now >= entry.until
                && !(receive_seq != 0 && entry.receive_seq == receive_seq)
                && (entry.receive_seq == 0 || receive_seq != 0 && entry.receive_seq < receive_seq);
            if stale {
                self.slots[index] = None;
                self.live = self.live.saturating_sub(1);
                continue;
            }
            if entry.key == key
                && ((receive_seq != 0 && entry.receive_seq == receive_seq) || now < entry.until)
            {
                return Some(R2oUdpFollowMatch {
                    at: entry.deferred_at,
                    failed: entry.failed,
                });
            }
        }
        None
    }

    /// Прекратить raw-повторы после постоянного отказа отправки потока.
    pub fn r2o_mark_failed(&mut self, packet: &[u8]) -> bool {
        let Some(key) = R2oUdpFollowKey::from_packet(packet) else {
            return false;
        };
        let Some(entry) = self
            .slots
            .iter_mut()
            .filter_map(Option::as_mut)
            .find(|entry| entry.key == key)
        else {
            return false;
        };
        entry.failed = true;
        true
    }

    /// Удалить окна, которые не подходят ни по времени, ни по номеру приёма.
    pub fn r2o_age(&mut self, now: Instant, receive_seq: u64) {
        for slot in &mut self.slots {
            let stale = slot.as_ref().is_some_and(|entry| {
                now >= entry.until
                    && !(receive_seq != 0 && entry.receive_seq == receive_seq)
                    && (entry.receive_seq == 0
                        || receive_seq != 0 && entry.receive_seq < receive_seq)
            });
            if stale {
                *slot = None;
                self.live = self.live.saturating_sub(1);
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }
}

impl Default for R2oUdpFollowTable {
    fn default() -> Self {
        Self::new()
    }
}

struct R2oUdpDeferredResend {
    due: Instant,
    order: u64,
    id: u32,
    flow_key: R2oUdpFollowKey,
    packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oUdpDeferredResendStats {
    pub flushed: usize,
    pub resend_failed: usize,
    pub verdict_failed: usize,
}

/// Ограниченное хранение позднего хвоста до завершения отложенной головы.
pub struct R2oUdpDeferredResends {
    slots: [Option<R2oUdpDeferredResend>; R2O_UDP_RELEASE_SLOTS],
    next_order: u64,
}

impl R2oUdpDeferredResends {
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            next_order: 0,
        }
    }

    /// Принять ID и копию сырого хвоста до его срока повторной отправки.
    pub fn r2o_enqueue(&mut self, due: Instant, id: u32, packet: &[u8]) -> bool {
        let Some(flow_key) = R2oUdpFollowKey::from_packet(packet) else {
            return false;
        };
        let Some(index) = self.slots.iter().position(Option::is_none) else {
            return false;
        };
        let mut stored = Vec::new();
        if stored.try_reserve_exact(packet.len()).is_err() {
            return false;
        }
        stored.extend_from_slice(packet);
        self.slots[index] = Some(R2oUdpDeferredResend {
            due,
            order: self.next_order,
            id,
            flow_key,
            packet: stored,
        });
        self.next_order = self.next_order.wrapping_add(1);
        true
    }

    /// Отменить поздние raw-повторы потока, чей отложенный emit не завершился.
    pub fn r2o_cancel_flow(&mut self, packet: &[u8]) -> Vec<u32> {
        let Some(key) = R2oUdpFollowKey::from_packet(packet) else {
            return Vec::new();
        };
        self.slots
            .iter_mut()
            .filter_map(|slot| {
                let matches = slot.as_ref().is_some_and(|entry| entry.flow_key == key);
                if matches {
                    slot.take().map(|entry| entry.id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Отправить созревшие хвосты и выдать DROP либо fail-open ACCEPT.
    pub fn r2o_flush(
        &mut self,
        now: Instant,
        mut resend: impl FnMut(u32, &[u8]) -> std::io::Result<()>,
        mut send_verdict: impl FnMut(u32, u32) -> std::io::Result<()>,
    ) -> R2oUdpDeferredResendStats {
        let mut stats = R2oUdpDeferredResendStats::default();
        loop {
            let next = self
                .slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| {
                    let entry = slot.as_ref()?;
                    (entry.due <= now).then_some((index, entry.due, entry.order))
                })
                .min_by_key(|(_, due, order)| (*due, *order))
                .map(|(index, _, _)| index);
            let Some(index) = next else {
                break;
            };
            let entry = self.slots[index].take().expect("созревший хвост найден");
            let verdict = match resend(entry.id, &entry.packet) {
                Ok(()) => 0,
                Err(_) => {
                    stats.resend_failed += 1;
                    1
                }
            };
            if send_verdict(entry.id, verdict).is_err() {
                stats.verdict_failed += 1;
                if verdict == 0 && send_verdict(entry.id, 1).is_err() {
                    stats.verdict_failed += 1;
                }
            }
            stats.flushed += 1;
        }
        stats
    }

    /// Принять ID всех ещё ожидающих поздних хвостов.
    pub fn r2o_drain_accept(&mut self) -> Vec<u32> {
        self.slots
            .iter_mut()
            .filter_map(Option::take)
            .map(|entry| entry.id)
            .collect()
    }

    /// Вернуть срок до ближайшего позднего хвоста.
    pub fn timeout_ms(&self, now: Instant, max_ms: i32) -> i32 {
        let Some(next) = self
            .slots
            .iter()
            .filter_map(|slot| slot.as_ref().map(|entry| entry.due))
            .min()
        else {
            return max_ms.max(0);
        };
        if next <= now || max_ms <= 0 {
            return 0;
        }
        let milliseconds = next.duration_since(now).as_nanos().div_ceil(1_000_000);
        milliseconds.min(i32::MAX as u128).min(max_ms as u128) as i32
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }
}

impl Default for R2oUdpDeferredResends {
    fn default() -> Self {
        Self::new()
    }
}

/// Проверить, является ли отказ raw-сокета временным заполнением.
pub fn r2o_udp_send_busy(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EAGAIN) | Some(libc::ENOBUFS)
    )
}
