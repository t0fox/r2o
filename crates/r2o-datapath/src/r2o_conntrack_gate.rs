//! Подтверждение conntrack перед исполнением сетевого плана.

use crate::conntrack::{R2oConntrackNatSource, R2oConntrackTuple, tuple_from_packet};
use crate::engine::{PacketDecision, WirePacket};
use crate::proc_nat::R2oProcNatLookup;
use std::collections::{HashMap, hash_map::Entry};
use std::path::Path;
use std::time::{Duration, Instant};

const R2O_CONNTRACK_CACHE_IDLE: Duration = Duration::from_secs(120);
const R2O_CONNTRACK_LOOKUP_ATTEMPTS: usize = 3;
const D2O_CONNTRACK_PATH: &str = "/proc/net/nf_conntrack";

/// Пакет на время выбора и окончательной проверки одного решения.
pub struct R2oConntrackPacket<'a> {
    bytes: &'a [u8],
    tuple: Option<Option<R2oConntrackTuple>>,
}

impl<'a> R2oConntrackPacket<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, tuple: None }
    }

    #[inline(never)]
    fn tuple(&mut self) -> Option<R2oConntrackTuple> {
        *self
            .tuple
            .get_or_insert_with(|| tuple_from_packet(self.bytes))
    }
}

#[derive(Clone, Copy)]
struct CachedEntry {
    status: CachedStatus,
    seen: Instant,
}

impl CachedEntry {
    fn expired(self, now: Instant, idle_timeout: Duration) -> bool {
        self.status == CachedStatus::Tracked
            && now.saturating_duration_since(self.seen) >= idle_timeout
    }
}

/// C `d2k_key`: состояние NAT принадлежит ПОТОКУ, а не направлению пакета.
/// Канонический ключ (low/high) общий для прямого и обратного кортежа.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct R2oFlowKey {
    family: u8,
    protocol: u8,
    low: [u8; 16],
    high: [u8; 16],
    low_port: u16,
    high_port: u16,
}

impl R2oFlowKey {
    fn r2o_from_tuple(tuple: R2oConntrackTuple) -> Self {
        let forward = (tuple.source, tuple.source_port);
        let reverse = (tuple.destination, tuple.destination_port);
        let (low, low_port, high, high_port) = if forward <= reverse {
            (forward.0, forward.1, reverse.0, reverse.1)
        } else {
            (reverse.0, reverse.1, forward.0, forward.1)
        };
        Self {
            family: tuple.family,
            protocol: tuple.protocol,
            low,
            high,
            low_port,
            high_port,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CachedStatus {
    Tracked,
    NoConntrackTable,
}

/// Ограниченный кеш только подтверждённых записей conntrack.
pub struct R2oConntrackGate {
    entries: HashMap<R2oFlowKey, CachedEntry>,
    capacity: usize,
    idle_timeout: Duration,
    /// C `g_nat_ok/miss/none/retried` (`session.c:648-656`).
    nat_ok: u64,
    nat_miss: u64,
    nat_none: u64,
    nat_retried: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Confirmation {
    FirstPacket,
    TcpSynAck,
    NoConntrackTable,
    Tracked,
    Missing,
}

impl R2oConntrackGate {
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_idle_timeout(capacity, R2O_CONNTRACK_CACHE_IDLE)
    }

    pub fn with_idle_timeout(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity,
            idle_timeout,
            nat_ok: 0,
            nat_miss: 0,
            nat_none: 0,
            nat_retried: 0,
        }
    }

    /// C `d2k_session_nat_stats`: (ok, miss, none, retried).
    pub fn nat_stats(&self) -> (u64, u64, u64, u64) {
        (self.nat_ok, self.nat_miss, self.nat_none, self.nat_retried)
    }

    fn confirm(
        &mut self,
        tuple: R2oConntrackTuple,
        first_packet: bool,
        tcp_syn_ack_seen: bool,
        now: Instant,
        query: &mut impl FnMut(&R2oConntrackTuple) -> R2oProcNatLookup,
    ) -> Confirmation {
        let key = R2oFlowKey::r2o_from_tuple(tuple);
        if let Entry::Occupied(mut entry) = self.entries.entry(key) {
            let cached = entry.get_mut();
            if !cached.expired(now, self.idle_timeout) {
                cached.seen = now;
                return match cached.status {
                    CachedStatus::Tracked => Confirmation::Tracked,
                    CachedStatus::NoConntrackTable => Confirmation::NoConntrackTable,
                };
            }
            entry.remove();
        }
        // C `session_packet` всегда передаёт first_packet=0 для TCP; API
        // остаётся безопасным, даже если вызывающий передаст 1.
        let first_packet = first_packet && tuple.protocol == 17;
        if first_packet {
            return Confirmation::FirstPacket;
        }
        if tuple.protocol == 6 && tcp_syn_ack_seen {
            self.insert(key, CachedStatus::Tracked, now);
            self.nat_ok = self.nat_ok.saturating_add(1);
            return Confirmation::TcpSynAck;
        }

        for attempt in 0..R2O_CONNTRACK_LOOKUP_ATTEMPTS {
            match query(&tuple) {
                R2oProcNatLookup::TableMissing => {
                    // C `flow_tracked`: `rc >= 0` завершает цикл, и при
                    // attempt > 0 счётчик перепроверки увеличивается ещё до
                    // разбора rc (в том числе для «таблицы нет»).
                    if attempt > 0 {
                        self.nat_retried = self.nat_retried.saturating_add(1);
                    }
                    self.insert(key, CachedStatus::NoConntrackTable, now);
                    self.nat_none = self.nat_none.saturating_add(1);
                    return Confirmation::NoConntrackTable;
                }
                R2oProcNatLookup::Missing => continue,
                R2oProcNatLookup::Found(_) => {}
            }
            if attempt > 0 {
                self.nat_retried = self.nat_retried.saturating_add(1);
            }
            self.insert(key, CachedStatus::Tracked, now);
            self.nat_ok = self.nat_ok.saturating_add(1);
            return Confirmation::Tracked;
        }
        self.nat_miss = self.nat_miss.saturating_add(1);
        Confirmation::Missing
    }

    fn insert(&mut self, key: R2oFlowKey, status: CachedStatus, now: Instant) {
        if self.capacity == 0 {
            return;
        }
        if self.entries.len() >= self.capacity {
            // Reclaim all stale entries in one pass before evicting a live
            // entry. Remember the oldest live entry during that same pass.
            let mut oldest = None;
            self.entries.retain(|key, cached| {
                if cached.expired(now, self.idle_timeout) {
                    return false;
                }
                if oldest.is_none_or(|(_, seen)| cached.seen < seen) {
                    oldest = Some((*key, cached.seen));
                }
                true
            });
            if self.entries.len() >= self.capacity
                && let Some((oldest, _)) = oldest
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, CachedEntry { status, seen: now });
    }

    /// C `flow_tracked` ДО `plan_apply`: `false` — план нельзя применять
    /// (`-1`), оригинал должен пройти как есть.
    pub fn r2o_preflight(
        &mut self,
        packet: &[u8],
        has_plan: bool,
        first_packet: bool,
        tcp_syn_ack_seen: bool,
    ) -> bool {
        self.r2o_preflight_packet(
            &mut R2oConntrackPacket::new(packet),
            has_plan,
            first_packet,
            tcp_syn_ack_seen,
        )
    }

    pub fn r2o_preflight_packet(
        &mut self,
        packet: &mut R2oConntrackPacket<'_>,
        has_plan: bool,
        first_packet: bool,
        tcp_syn_ack_seen: bool,
    ) -> bool {
        // D2O проверяет conntrack только для пакета с выбранным планом.
        if !has_plan {
            return true;
        }
        self.preflight_tuple(packet.tuple(), first_packet, tcp_syn_ack_seen, |tuple| {
            crate::proc_nat::lookup(Path::new(D2O_CONNTRACK_PATH), tuple)
        })
    }

    /// То же с подставляемым procfs-lookup для unit-тестов.
    pub fn r2o_preflight_with_lookup(
        &mut self,
        packet: &[u8],
        first_packet: bool,
        tcp_syn_ack_seen: bool,
        lookup: impl FnMut(&R2oConntrackTuple) -> R2oProcNatLookup,
    ) -> bool {
        self.preflight_tuple(
            tuple_from_packet(packet),
            first_packet,
            tcp_syn_ack_seen,
            lookup,
        )
    }

    fn preflight_tuple(
        &mut self,
        tuple: Option<R2oConntrackTuple>,
        first_packet: bool,
        tcp_syn_ack_seen: bool,
        mut lookup: impl FnMut(&R2oConntrackTuple) -> R2oProcNatLookup,
    ) -> bool {
        let Some(tuple) = tuple else {
            return true;
        };
        self.confirm(
            tuple,
            first_packet,
            tcp_syn_ack_seen,
            Instant::now(),
            &mut lookup,
        ) != Confirmation::Missing
    }
}

/// Не допускать применение плана к неподтверждённому потоку.
pub fn guard_decision(
    gate: &mut R2oConntrackGate,
    packet: &[u8],
    decision: PacketDecision,
    plan_id: [u8; 16],
    first_packet: bool,
    tcp_syn_ack_seen: bool,
) -> PacketDecision {
    guard_packet_decision(
        gate,
        &mut R2oConntrackPacket::new(packet),
        decision,
        plan_id,
        first_packet,
        tcp_syn_ack_seen,
    )
}

pub fn guard_packet_decision(
    gate: &mut R2oConntrackGate,
    packet: &mut R2oConntrackPacket<'_>,
    decision: PacketDecision,
    plan_id: [u8; 16],
    first_packet: bool,
    tcp_syn_ack_seen: bool,
) -> PacketDecision {
    guard_packet_decision_with_lookup(
        gate,
        packet,
        decision,
        plan_id,
        first_packet,
        tcp_syn_ack_seen,
        |tuple| crate::proc_nat::lookup(Path::new(D2O_CONNTRACK_PATH), tuple),
    )
}

pub fn guard_decision_with_lookup(
    gate: &mut R2oConntrackGate,
    packet: &[u8],
    decision: PacketDecision,
    plan_id: [u8; 16],
    first_packet: bool,
    tcp_syn_ack_seen: bool,
    lookup: impl FnMut(&R2oConntrackTuple) -> R2oProcNatLookup,
) -> PacketDecision {
    guard_packet_decision_with_lookup(
        gate,
        &mut R2oConntrackPacket::new(packet),
        decision,
        plan_id,
        first_packet,
        tcp_syn_ack_seen,
        lookup,
    )
}

fn guard_packet_decision_with_lookup(
    gate: &mut R2oConntrackGate,
    packet: &mut R2oConntrackPacket<'_>,
    decision: PacketDecision,
    plan_id: [u8; 16],
    first_packet: bool,
    tcp_syn_ack_seen: bool,
    lookup: impl FnMut(&R2oConntrackTuple) -> R2oProcNatLookup,
) -> PacketDecision {
    if !matches!(
        &decision,
        PacketDecision::Drop | PacketDecision::Replace(_) | PacketDecision::Transmit { .. }
    ) {
        return decision;
    }
    let Some(tuple) = packet.tuple() else {
        return decision;
    };
    let mapping_required = tuple.protocol == 17 && decision_has_udp_fragments(&decision);
    let mut lookup = lookup;
    let confirmation = gate.confirm(
        tuple,
        first_packet,
        tcp_syn_ack_seen,
        Instant::now(),
        &mut lookup,
    );
    match confirmation {
        Confirmation::FirstPacket if mapping_required => {
            fragment_decision(decision, plan_id, true, first_packet, lookup(&tuple))
        }
        Confirmation::FirstPacket => decision,
        Confirmation::TcpSynAck => decision,
        Confirmation::NoConntrackTable if mapping_required => PacketDecision::Refused { plan_id },
        Confirmation::NoConntrackTable => decision,
        Confirmation::Tracked if mapping_required => {
            fragment_decision(decision, plan_id, true, first_packet, lookup(&tuple))
        }
        Confirmation::Tracked => decision,
        Confirmation::Missing if first_packet && mapping_required => PacketDecision::Accept,
        Confirmation::Missing => PacketDecision::Refused { plan_id },
    }
}

fn fragment_decision(
    decision: PacketDecision,
    plan_id: [u8; 16],
    mapping_required: bool,
    first_packet: bool,
    lookup: R2oProcNatLookup,
) -> PacketDecision {
    if !mapping_required {
        return decision;
    }
    let mapping = match lookup {
        R2oProcNatLookup::Found(mapping)
            if mapping.port != 0
                && (mapping.family == 6 || mapping.address[..4] != [0, 0, 0, 0]) =>
        {
            mapping
        }
        R2oProcNatLookup::Missing if first_packet => return PacketDecision::Accept,
        _ => return PacketDecision::Refused { plan_id },
    };
    match decision {
        PacketDecision::Transmit { mut packets, fate } => {
            if rewrite_fragment_group(&mut packets, mapping) {
                PacketDecision::Transmit { packets, fate }
            } else {
                PacketDecision::Refused { plan_id }
            }
        }
        _ => PacketDecision::Refused { plan_id },
    }
}

fn decision_has_udp_fragments(decision: &PacketDecision) -> bool {
    let PacketDecision::Transmit { packets, .. } = decision else {
        return false;
    };
    packets.iter().any(|packet| is_udp_fragment(&packet.packet))
}

fn rewrite_fragment_group(packets: &mut [WirePacket], mapping: R2oConntrackNatSource) -> bool {
    let mut fragments = 0;
    let mut first_fragments = 0;
    for wire in packets {
        if !is_udp_fragment(&wire.packet) {
            continue;
        }
        fragments += 1;
        match rewrite_fragment(&mut wire.packet, mapping) {
            Some(true) => first_fragments += 1,
            Some(false) => {}
            None => return false,
        }
    }
    fragments > 1 && first_fragments == 1
}

fn is_udp_fragment(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            packet[9] == 17 && u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
        }
        Some(6) if packet.len() >= 48 => packet[6] == 44 && packet[40] == 17,
        _ => false,
    }
}

fn rewrite_fragment(packet: &mut [u8], mapping: R2oConntrackNatSource) -> Option<bool> {
    let family = packet.first().copied()? >> 4;
    if family != mapping.family {
        return None;
    }
    let (source_range, udp_offset, first) = if family == 4 {
        let header_len = usize::from(packet[0] & 0x0f).checked_mul(4)?;
        // C `handle_udp` строит IPv4-фрагменты только при ihl == 20:
        // «copying/fragmenting IPv4 options needs its own measured path».
        // Переписывать адрес в таком фрагменте, не пересчитав опции, нельзя.
        if header_len != 20 || packet.len() < header_len + 8 || packet[9] != 17 {
            return None;
        }
        let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
        if flags_offset & 0x3fff == 0 {
            return None;
        }
        (12..16, header_len, flags_offset & 0x1fff == 0)
    } else if family == 6 {
        if packet.len() < 56 || packet[6] != 44 || packet[40] != 17 {
            return None;
        }
        let offset_and_more = u16::from_be_bytes([packet[42], packet[43]]);
        if offset_and_more & 0xfff9 == 0 {
            return None;
        }
        (8..24, 48, offset_and_more & 0xfff8 == 0)
    } else {
        return None;
    };

    let mut old_address = [0; 16];
    let address_len = if family == 4 { 4 } else { 16 };
    old_address[..address_len].copy_from_slice(packet.get(source_range.clone())?);
    let old_port = if first {
        Some(u16::from_be_bytes([
            *packet.get(udp_offset)?,
            *packet.get(udp_offset + 1)?,
        ]))
    } else {
        None
    };
    let checksum_offset = udp_offset.checked_add(6)?;
    let old_checksum = if first {
        Some(u16::from_be_bytes([
            *packet.get(checksum_offset)?,
            *packet.get(checksum_offset + 1)?,
        ]))
    } else {
        None
    };

    packet.get_mut(source_range.clone())?[..].copy_from_slice(&mapping.address[..address_len]);
    if family == 4 {
        let header_len = source_range.end.checked_add(4)?;
        packet.get_mut(10..12)?.fill(0);
        let checksum = internet_checksum(packet.get(..header_len)?);
        packet
            .get_mut(10..12)?
            .copy_from_slice(&checksum.to_be_bytes());
    }
    if first {
        let old_port = old_port?;
        let old_checksum = old_checksum?;
        packet
            .get_mut(udp_offset..udp_offset + 2)?
            .copy_from_slice(&mapping.port.to_be_bytes());
        if old_checksum != 0 {
            let mut old_words = Vec::with_capacity(address_len / 2 + 1);
            let mut new_words = Vec::with_capacity(address_len / 2 + 1);
            for pair in old_address[..address_len].chunks_exact(2) {
                old_words.push(u16::from_be_bytes([pair[0], pair[1]]));
            }
            for pair in mapping.address[..address_len].chunks_exact(2) {
                new_words.push(u16::from_be_bytes([pair[0], pair[1]]));
            }
            old_words.push(old_port);
            new_words.push(mapping.port);
            let checksum = update_checksum(old_checksum, &old_words, &new_words);
            packet
                .get_mut(checksum_offset..checksum_offset + 2)?
                .copy_from_slice(&checksum.to_be_bytes());
        } else if family == 6 {
            return None;
        }
    }
    Some(first)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(last) = bytes.chunks_exact(2).remainder().first() {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn update_checksum(checksum: u16, old_words: &[u16], new_words: &[u16]) -> u16 {
    let mut sum = u32::from(!checksum);
    for (old, new) in old_words.iter().zip(new_words) {
        sum += u32::from(!*old) + u32::from(*new);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    if checksum == 0 { u16::MAX } else { checksum }
}

#[cfg(test)]
mod tests {
    use super::{
        Confirmation, R2oConntrackGate, guard_decision_with_lookup, internet_checksum,
        rewrite_fragment_group, update_checksum,
    };
    use crate::conntrack::{R2oConntrackNatSource, R2oConntrackTuple};
    use crate::engine::{PacketDecision, WirePacket};
    use crate::proc_nat::R2oProcNatLookup;
    use r2k_core::plan::EmitKind;
    use std::time::{Duration, Instant};

    fn tuple(protocol: u8) -> R2oConntrackTuple {
        R2oConntrackTuple {
            family: 4,
            protocol,
            source: [192, 168, 1, 67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            destination: [198, 51, 100, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            source_port: 51000,
            destination_port: 443,
        }
    }

    fn mapped_source() -> R2oConntrackNatSource {
        R2oConntrackNatSource {
            family: 4,
            address: [203, 0, 113, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            port: 62000,
        }
    }

    fn reverse_tuple(mut tuple: R2oConntrackTuple) -> R2oConntrackTuple {
        std::mem::swap(&mut tuple.source, &mut tuple.destination);
        std::mem::swap(&mut tuple.source_port, &mut tuple.destination_port);
        tuple
    }

    #[test]
    fn reverse_hit_refreshes_tracked_entry_until_exact_idle_deadline() {
        let mut gate = R2oConntrackGate::with_idle_timeout(2, Duration::from_secs(10));
        let flow = tuple(17);
        let start = Instant::now();
        assert_eq!(
            gate.confirm(flow, false, false, start, &mut |_| R2oProcNatLookup::Found(
                mapped_source()
            )),
            Confirmation::Tracked
        );
        assert_eq!(
            gate.confirm(
                reverse_tuple(flow),
                false,
                false,
                start + Duration::from_secs(9),
                &mut |_| panic!("cache hit")
            ),
            Confirmation::Tracked
        );
        assert_eq!(
            gate.confirm(
                flow,
                false,
                false,
                start + Duration::from_secs(19),
                &mut |_| R2oProcNatLookup::Missing
            ),
            Confirmation::Missing
        );
        assert_eq!(gate.nat_stats(), (1, 1, 0, 0));
    }

    #[test]
    fn insertion_reclaims_expired_entry_before_evicting_persistent_entry() {
        let mut gate = R2oConntrackGate::with_idle_timeout(3, Duration::from_secs(10));
        let persistent = tuple(17);
        let expired = R2oConntrackTuple {
            source_port: 51001,
            ..persistent
        };
        let also_expired = R2oConntrackTuple {
            source_port: 51003,
            ..persistent
        };
        let incoming = R2oConntrackTuple {
            source_port: 51002,
            ..persistent
        };
        let start = Instant::now();
        assert_eq!(
            gate.confirm(persistent, false, false, start, &mut |_| {
                R2oProcNatLookup::TableMissing
            }),
            Confirmation::NoConntrackTable
        );
        gate.confirm(
            expired,
            false,
            false,
            start + Duration::from_secs(1),
            &mut |_| R2oProcNatLookup::Found(mapped_source()),
        );
        gate.confirm(
            also_expired,
            false,
            false,
            start + Duration::from_secs(1),
            &mut |_| R2oProcNatLookup::Found(mapped_source()),
        );
        let now = start + Duration::from_secs(11);
        assert_eq!(
            gate.confirm(incoming, false, false, now, &mut |_| {
                R2oProcNatLookup::Found(mapped_source())
            }),
            Confirmation::Tracked
        );
        assert_eq!(
            gate.confirm(persistent, false, false, now, &mut |_| panic!(
                "persistent cache hit"
            )),
            Confirmation::NoConntrackTable
        );
        assert_eq!(
            gate.confirm(expired, true, false, now, &mut |_| panic!(
                "first UDP packet bypasses lookup"
            )),
            Confirmation::FirstPacket
        );
        assert_eq!(gate.entries.len(), 2);
    }

    #[test]
    fn отсутствие_таблицы_не_истекает_как_nat_state_3_c() {
        let mut gate = R2oConntrackGate::with_idle_timeout(4, std::time::Duration::from_secs(120));
        let now = Instant::now();
        assert_eq!(
            gate.confirm(tuple(17), false, false, now, &mut |_| {
                R2oProcNatLookup::TableMissing
            }),
            Confirmation::NoConntrackTable
        );
        // C nat_state=3 не сбрасывается по времени; запись потока живёт до
        // собственного истечения/вытеснения, а не 120 с NAT-кеша.
        assert_eq!(
            gate.confirm(
                tuple(17),
                false,
                false,
                now + std::time::Duration::from_secs(121),
                &mut |_| panic!("nat_state=3 должен остаться навсегда")
            ),
            Confirmation::NoConntrackTable
        );
        assert_eq!(gate.nat_stats(), (0, 0, 1, 0));
    }

    #[test]
    fn tcp_первый_пакет_не_получает_исключение_как_c() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        assert_eq!(
            gate.confirm(tuple(6), true, false, Instant::now(), &mut |_| {
                R2oProcNatLookup::Missing
            }),
            Confirmation::Missing
        );
        assert_eq!(gate.nat_stats(), (0, 1, 0, 0));
    }

    #[test]
    fn flow_tracked_differential_matches_c() {
        use super::{CachedEntry, CachedStatus, R2oFlowKey};
        use std::time::Instant;

        fn seed(
            gate: &mut R2oConntrackGate,
            tuple: R2oConntrackTuple,
            status: CachedStatus,
            now: Instant,
        ) {
            gate.entries.insert(
                R2oFlowKey::r2o_from_tuple(tuple),
                CachedEntry { status, seen: now },
            );
        }
        fn run(
            name: &str,
            proto: u8,
            first: bool,
            synack: bool,
            preset: Option<CachedStatus>,
            answers: &[R2oProcNatLookup],
            output: &mut String,
        ) {
            let mut gate = R2oConntrackGate::with_capacity(4);
            let now = Instant::now();
            let tuple = tuple(proto);
            if let Some(status) = preset {
                seed(&mut gate, tuple, status, now);
            }
            let mut calls = 0_usize;
            let confirmation = gate.confirm(tuple, first, synack, now, &mut |_| {
                let value = answers[calls.min(answers.len().saturating_sub(1))];
                calls += 1;
                value
            });
            let (rc, state) = match confirmation {
                Confirmation::Missing => (-1, 0),
                Confirmation::FirstPacket => (0, 0),
                Confirmation::Tracked | Confirmation::TcpSynAck => (0, 1),
                Confirmation::NoConntrackTable => (0, 3),
            };
            let (ok, miss, none, retried) = gate.nat_stats();
            output.push_str(&format!(
                "{name} rc={rc} state={state} ok={ok} miss={miss} none={none} retried={retried} calls={calls}\n"
            ));
        }

        let found = || R2oProcNatLookup::Found(mapped_source());
        let missing = R2oProcNatLookup::Missing;
        let table_missing = R2oProcNatLookup::TableMissing;
        let mut output = String::new();
        run(
            "first_missing",
            17,
            true,
            false,
            None,
            &[missing],
            &mut output,
        );
        run("found", 17, false, false, None, &[found()], &mut output);
        run(
            "table_missing",
            17,
            false,
            false,
            None,
            &[table_missing],
            &mut output,
        );
        run(
            "miss",
            17,
            false,
            false,
            None,
            &[missing, missing, missing],
            &mut output,
        );
        run(
            "retry_found",
            17,
            false,
            false,
            None,
            &[missing, found()],
            &mut output,
        );
        run(
            "retry_table_missing",
            17,
            false,
            false,
            None,
            &[missing, table_missing],
            &mut output,
        );
        run("synack", 6, false, true, None, &[missing], &mut output);
        run(
            "preset_known",
            17,
            false,
            false,
            Some(CachedStatus::Tracked),
            &[missing],
            &mut output,
        );
        run(
            "preset_no_table",
            17,
            false,
            false,
            Some(CachedStatus::NoConntrackTable),
            &[missing],
            &mut output,
        );
        run(
            "first_with_known",
            17,
            true,
            false,
            Some(CachedStatus::Tracked),
            &[missing],
            &mut output,
        );
        run(
            "tcp_retry",
            6,
            false,
            false,
            None,
            &[missing, found()],
            &mut output,
        );

        // C nat_state=3: table-missing не истекает по времени NAT-кеша.
        let mut gate = R2oConntrackGate::with_idle_timeout(4, std::time::Duration::from_secs(120));
        let now = Instant::now();
        let first = gate.confirm(tuple(17), false, false, now, &mut |_| {
            R2oProcNatLookup::TableMissing
        });
        let second = gate.confirm(
            tuple(17),
            false,
            false,
            now + std::time::Duration::from_secs(121),
            &mut |_| panic!("nat_state=3 должен остаться навсегда"),
        );
        let (ok, miss, none, retried) = gate.nat_stats();
        output.push_str(&format!(
            "table_missing_permanent rc1={} rc2={} state={} ok={ok} miss={miss} none={none} retried={retried} calls=1\n",
            i32::from(first == Confirmation::Missing),
            i32::from(second == Confirmation::Missing),
            if second == Confirmation::NoConntrackTable { 3 } else { 0 }
        ));
        if let Ok(path) = std::env::var("R2O_FLOW_TRACKED_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains("retry_table_missing rc=0 state=3"));
    }

    #[test]
    fn состояние_nat_общее_для_обоих_направлений_потока_как_c() {
        let forward = tuple(17);
        let reverse = reverse_tuple(forward);
        let mut gate = R2oConntrackGate::with_capacity(4);
        let now = Instant::now();

        assert_eq!(
            gate.confirm(forward, true, false, now, &mut |_| panic!()),
            Confirmation::FirstPacket
        );
        assert_eq!(
            gate.confirm(forward, false, false, now, &mut |_| {
                R2oProcNatLookup::Found(mapped_source())
            }),
            Confirmation::Tracked
        );
        // Обратный пакет того же потока не читает таблицу и не добавляет
        // второй nat_ok: C хранит nat_state в записи потока.
        assert_eq!(
            gate.confirm(reverse, false, false, now, &mut |_| {
                panic!("обратное направление должно попасть в кеш потока")
            }),
            Confirmation::Tracked
        );
        assert_eq!(gate.nat_stats(), (1, 0, 0, 0));

        // Другой поток с теми же адресами, но другим портом — отдельный ключ.
        let mut other = forward;
        other.source_port = other.source_port.wrapping_add(1);
        assert_eq!(
            gate.confirm(other, false, false, now, &mut |_| {
                R2oProcNatLookup::Missing
            }),
            Confirmation::Missing
        );
    }

    #[test]
    fn первый_пакет_потока_не_читает_таблицу() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        assert_eq!(
            gate.confirm(tuple(17), true, false, Instant::now(), &mut |_| {
                calls += 1;
                R2oProcNatLookup::Missing
            }),
            Confirmation::FirstPacket
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn первый_обычный_пакет_проходит_без_nat_lookup() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let source = ipv4_udp_packet();
        let decision = PacketDecision::Transmit {
            packets: vec![WirePacket {
                packet: source.clone(),
                kind: EmitKind::Payload,
                delay_us: 0,
            }],
            fate: r2k_core::plan::OriginalFate::Drop,
        };
        assert_eq!(
            guard_decision_with_lookup(
                &mut gate,
                &source,
                decision.clone(),
                [5; 16],
                true,
                false,
                |_| panic!("C flow_tracked пропускает первый обычный пакет без чтения таблицы"),
            ),
            decision
        );
    }

    #[test]
    fn tcp_syn_ack_кэширует_доказанную_запись_потока() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        assert_eq!(
            gate.confirm(tuple(6), false, true, Instant::now(), &mut |_| {
                calls += 1;
                R2oProcNatLookup::Missing
            }),
            Confirmation::TcpSynAck
        );
        assert_eq!(
            gate.confirm(tuple(6), false, false, Instant::now(), &mut |_| {
                calls += 1;
                R2oProcNatLookup::Missing
            }),
            Confirmation::Tracked
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn отсутствие_таблицы_conntrack_кэшируется_как_в_d2o() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        assert_eq!(
            gate.confirm(tuple(17), false, false, Instant::now(), &mut |_| {
                R2oProcNatLookup::TableMissing
            }),
            Confirmation::NoConntrackTable
        );
        assert_eq!(
            gate.confirm(tuple(17), false, false, Instant::now(), &mut |_| {
                panic!("кэшированное состояние d2o не перечитывается")
            }),
            Confirmation::NoConntrackTable
        );
    }

    #[test]
    fn не_кэширует_промахи_и_повторяет_поиск_до_трёх_раз() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        assert_eq!(
            gate.confirm(tuple(17), false, false, Instant::now(), &mut |_| {
                calls += 1;
                if calls == 1 {
                    R2oProcNatLookup::Missing
                } else {
                    R2oProcNatLookup::Found(mapped_source())
                }
            }),
            Confirmation::Tracked
        );
        assert_eq!(calls, 2);
        let mut next_calls = 0;
        assert_eq!(
            gate.confirm(tuple(6), false, false, Instant::now(), &mut |_| {
                next_calls += 1;
                R2oProcNatLookup::Missing
            }),
            Confirmation::Missing
        );
        assert_eq!(next_calls, 3);
    }

    #[test]
    fn первый_фрагментированный_initial_повторяется_после_подтверждения_conntrack() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        let source = ipv4_udp_packet();
        let wires = fragment_fixture(4, 1);
        let decision = PacketDecision::Transmit {
            packets: wires.into_iter().skip(1).collect(),
            fate: r2k_core::plan::OriginalFate::Drop,
        };
        assert_eq!(
            guard_decision_with_lookup(
                &mut gate,
                &source,
                decision.clone(),
                [4; 16],
                true,
                false,
                |_| {
                    calls += 1;
                    R2oProcNatLookup::Missing
                },
            ),
            PacketDecision::Accept
        );
        assert_eq!(calls, 1);
        calls = 0;
        let result =
            guard_decision_with_lookup(&mut gate, &source, decision, [4; 16], false, false, |_| {
                calls += 1;
                R2oProcNatLookup::Found(mapped_source())
            });
        let PacketDecision::Transmit { packets, .. } = result else {
            panic!("подтверждённая IP-fragment проба должна быть передана")
        };
        assert_eq!(packets.len(), 2);
        assert!(
            packets
                .iter()
                .all(|packet| packet.packet[12..16] == [203, 0, 113, 9])
        );
        assert_eq!(calls, 2); // одна запись подтверждает поток, одна даёт IP-fragment NAT.
    }

    #[test]
    fn отсутствие_таблицы_не_разрешает_ip_fragment_без_nat_mapping() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let source = ipv4_udp_packet();
        let wires = fragment_fixture(4, 1);
        let decision = PacketDecision::Transmit {
            packets: wires.into_iter().skip(1).collect(),
            fate: r2k_core::plan::OriginalFate::Drop,
        };
        assert_eq!(
            guard_decision_with_lookup(&mut gate, &source, decision, [4; 16], false, false, |_| {
                R2oProcNatLookup::TableMissing
            },),
            PacketDecision::Refused { plan_id: [4; 16] }
        );
    }

    #[test]
    fn preflight_отказывает_missing_до_применения_плана() {
        let source = ipv4_udp_packet();
        let mut gate = R2oConntrackGate::with_capacity(4);
        assert!(
            !gate.r2o_preflight_with_lookup(&source, false, false, |_| {
                R2oProcNatLookup::Missing
            })
        );
        assert_eq!(gate.nat_stats(), (0, 1, 0, 0));

        let mut gate = R2oConntrackGate::with_capacity(4);
        assert!(gate.r2o_preflight_with_lookup(&source, true, false, |_| {
            panic!("первому пакету таблицу не читаем")
        }));
        let mut gate = R2oConntrackGate::with_capacity(4);
        assert!(gate.r2o_preflight_with_lookup(&source, false, false, |_| {
            R2oProcNatLookup::Found(mapped_source())
        }));
        let mut gate = R2oConntrackGate::with_capacity(4);
        assert!(gate.r2o_preflight_with_lookup(&source, false, false, |_| {
            R2oProcNatLookup::TableMissing
        }));

        let mut tcp = vec![0_u8; 40];
        tcp[0] = 0x45;
        tcp[2..4].copy_from_slice(&40_u16.to_be_bytes());
        tcp[8] = 64;
        tcp[9] = 6;
        tcp[12..16].copy_from_slice(&[192, 168, 1, 67]);
        tcp[16..20].copy_from_slice(&[198, 51, 100, 8]);
        tcp[20..22].copy_from_slice(&51000_u16.to_be_bytes());
        tcp[22..24].copy_from_slice(&443_u16.to_be_bytes());
        tcp[32] = 5 << 4;
        let mut gate = R2oConntrackGate::with_capacity(4);
        assert!(
            !gate.r2o_preflight_with_lookup(&tcp, true, false, |_| { R2oProcNatLookup::Missing })
        );
    }

    #[test]
    fn preflight_без_плана_не_читает_conntrack() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let packet = ipv4_udp_packet();
        assert!(crate::conntrack::tuple_from_packet(&packet).is_some());
        assert!(gate.r2o_preflight(&packet, false, false, false));
        assert_eq!(gate.nat_stats(), (0, 0, 0, 0));
    }

    #[test]
    fn packet_caches_an_unparseable_tuple_only_when_needed() {
        let mut packet = super::R2oConntrackPacket::new(&[0]);
        let mut gate = R2oConntrackGate::with_capacity(1);
        assert!(gate.r2o_preflight_packet(&mut packet, false, false, false));
        assert_eq!(packet.tuple, None);
        assert!(gate.r2o_preflight_packet(&mut packet, true, false, false));
        assert_eq!(packet.tuple, Some(None));
        assert!(matches!(
            super::guard_packet_decision(
                &mut gate,
                &mut packet,
                PacketDecision::Drop,
                [0; 16],
                false,
                false
            ),
            PacketDecision::Drop
        ));
        assert_eq!(packet.tuple, Some(None));
    }

    #[test]
    fn preflight_покрывает_четыре_call_site_и_не_повторяет_lookup() {
        // 1. UDP Pass первого пакета: исключение first_packet не читает
        // таблицу ни в preflight, ни в guard_decision.
        let udp = ipv4_udp_packet();
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        assert!(gate.r2o_preflight_with_lookup(&udp, true, false, |_| {
            calls += 1;
            panic!("первому UDP-пакету таблица не нужна")
        }));
        let _ = guard_decision_with_lookup(
            &mut gate,
            &udp,
            PacketDecision::Drop,
            [9; 16],
            true,
            false,
            |_| {
                calls += 1;
                panic!("guard первого UDP-пакета не читает таблицу")
            },
        );
        assert_eq!(calls, 0);

        // 2. UDP Pass не первого пакета: preflight читает ровно один раз и
        // кеширует Tracked; guard_decision обязан попасть в кеш.
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        assert!(gate.r2o_preflight_with_lookup(&udp, false, false, |_| {
            calls += 1;
            R2oProcNatLookup::Found(mapped_source())
        }));
        let _ = guard_decision_with_lookup(
            &mut gate,
            &udp,
            PacketDecision::Drop,
            [9; 16],
            false,
            false,
            |_| {
                calls += 1;
                panic!("guard после preflight не должен повторять lookup")
            },
        );
        assert_eq!(calls, 1);

        // 3. TCP Ready/Observed: preflight получает Missing и отказывает до
        // применения плана; guard_decision в этом call-site не вызывается.
        // C `flow_tracked` делает три попытки lookup, поэтому здесь тоже 3.
        let mut tcp = udp.clone();
        tcp.resize(40, 0);
        tcp[2..4].copy_from_slice(&40_u16.to_be_bytes());
        tcp[9] = 6;
        tcp[32] = 5 << 4;
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        assert!(!gate.r2o_preflight_with_lookup(&tcp, false, false, |_| {
            calls += 1;
            R2oProcNatLookup::Missing
        }));
        assert_eq!(calls, 3);
        assert_eq!(gate.nat_stats(), (0, 1, 0, 0));

        // 4. TCP с отсутствующей таблицей: preflight разрешает (nat_state=3),
        // guard берёт кеш и не повторяет lookup.
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        assert!(gate.r2o_preflight_with_lookup(&tcp, false, false, |_| {
            calls += 1;
            R2oProcNatLookup::TableMissing
        }));
        let _ = guard_decision_with_lookup(
            &mut gate,
            &tcp,
            PacketDecision::Drop,
            [9; 16],
            false,
            false,
            |_| {
                calls += 1;
                panic!("nat_state=3 кешируется и не читает таблицу повторно")
            },
        );
        assert_eq!(calls, 1);
        assert_eq!(gate.nat_stats(), (0, 0, 1, 0));
    }

    #[test]
    fn tcp_первый_пакет_не_проходит_по_исключению_первого_пакета() {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 168, 1, 67]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 8]);
        packet[20..22].copy_from_slice(&51000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[32] = 5 << 4;
        let mut gate = R2oConntrackGate::with_capacity(4);
        assert_eq!(
            guard_decision_with_lookup(
                &mut gate,
                &mut packet,
                PacketDecision::Drop,
                [7; 16],
                true,
                false,
                |_| R2oProcNatLookup::Missing,
            ),
            PacketDecision::Refused { plan_id: [7; 16] }
        );
    }

    #[test]
    fn пересчитывает_контрольную_сумму_при_замене_кортежа() {
        let old = 0x9a17;
        let old_words = [0xc0a8, 0x0143, 0xc633, 0x6408, 51000];
        let new_words = [0xcb00, 0x7107, 0xc633, 0x6408, 62000];
        let updated = update_checksum(old, &old_words, &new_words);
        assert_ne!(updated, 0);
        assert_eq!(update_checksum(updated, &new_words, &old_words), old);
    }

    #[test]
    fn переносит_nat_на_все_формы_ipv4_ipv6_фрагментов_оставляя_fake_нетронутым() {
        for family in [4, 6] {
            for shape in 1..=4 {
                let mapping = if family == 4 {
                    R2oConntrackNatSource {
                        family,
                        address: [203, 0, 113, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        port: 62000,
                    }
                } else {
                    R2oConntrackNatSource {
                        family,
                        address: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
                        port: 62000,
                    }
                };
                let mut wires = fragment_fixture(family, shape);
                let fake_before = wires[0].packet.clone();
                assert!(rewrite_fragment_group(&mut wires, mapping));
                assert_eq!(wires[0].packet, fake_before);
                assert_rewritten_fragment_group(&wires[1..], family, mapping);
            }
        }
    }

    #[test]
    fn ipv4_фрагменты_с_опциями_не_переписываются_как_в_c() {
        // C собирает IPv4-фрагменты только при ihl == 20: опции требуют
        // отдельного измеренного пути. Переписать адрес, не пересчитав
        // заголовок с опциями, нельзя — план должен быть отвергнут.
        let mut wires = fragment_fixture(4, 1);
        for wire in &mut wires[1..] {
            wire.packet[0] = 0x46;
        }
        assert!(!rewrite_fragment_group(&mut wires, mapped_source()));
    }

    fn ipv4_udp_packet() -> Vec<u8> {
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 168, 1, 67]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 8]);
        packet[20..22].copy_from_slice(&51000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn fragment_fixture(family: u8, shape: u8) -> Vec<WirePacket> {
        let source4 = [192, 168, 1, 67];
        let destination4 = [198, 51, 100, 8];
        let source6 = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination6 = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut datagram = vec![0; 40];
        datagram[..2].copy_from_slice(&51000_u16.to_be_bytes());
        datagram[2..4].copy_from_slice(&443_u16.to_be_bytes());
        datagram[4..6].copy_from_slice(&40_u16.to_be_bytes());
        for (index, byte) in datagram[8..].iter_mut().enumerate() {
            *byte = (index + 1) as u8;
        }
        let mut pseudo = Vec::new();
        if family == 4 {
            pseudo.extend_from_slice(&source4);
            pseudo.extend_from_slice(&destination4);
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&40_u16.to_be_bytes());
        } else {
            pseudo.extend_from_slice(&source6);
            pseudo.extend_from_slice(&destination6);
            pseudo.extend_from_slice(&40_u32.to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
        }
        pseudo.extend_from_slice(&datagram);
        let checksum = internet_checksum(&pseudo);
        datagram[6..8]
            .copy_from_slice(&(if checksum == 0 { u16::MAX } else { checksum }).to_be_bytes());

        let ranges: &[(usize, usize)] = if shape <= 2 {
            &[(0, 16), (16, 24)]
        } else {
            &[(0, 16), (16, 8), (24, 16)]
        };
        let mut fragments = ranges
            .iter()
            .enumerate()
            .map(|(index, (offset, length))| {
                let mut fragment = if family == 4 {
                    let mut packet = vec![0; 20 + length];
                    packet[0] = 0x45;
                    packet[1] = 0x2e;
                    packet[2..4].copy_from_slice(&((20 + length) as u16).to_be_bytes());
                    packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
                    let more = index + 1 < ranges.len();
                    let field = ((*offset / 8) as u16) | if more { 0x2000 } else { 0 };
                    packet[6..8].copy_from_slice(&field.to_be_bytes());
                    packet[8] = 47;
                    packet[9] = 17;
                    packet[12..16].copy_from_slice(&source4);
                    packet[16..20].copy_from_slice(&destination4);
                    packet[20..].copy_from_slice(&datagram[*offset..*offset + *length]);
                    let checksum = internet_checksum(&packet[..20]);
                    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
                    packet
                } else {
                    let mut packet = vec![0; 48 + length];
                    packet[..4].copy_from_slice(&0x6000_0000_u32.to_be_bytes());
                    packet[4..6].copy_from_slice(&((8 + length) as u16).to_be_bytes());
                    packet[6] = 44;
                    packet[7] = 47;
                    packet[8..24].copy_from_slice(&source6);
                    packet[24..40].copy_from_slice(&destination6);
                    packet[40] = 17;
                    let more = index + 1 < ranges.len();
                    let field = (*offset as u16) | if more { 1 } else { 0 };
                    packet[42..44].copy_from_slice(&field.to_be_bytes());
                    packet[44..48].copy_from_slice(&0x1234_5678_u32.to_be_bytes());
                    packet[48..].copy_from_slice(&datagram[*offset..*offset + *length]);
                    packet
                };
                WirePacket {
                    packet: std::mem::take(&mut fragment),
                    kind: EmitKind::Payload,
                    delay_us: 0,
                }
            })
            .collect::<Vec<_>>();
        if shape % 2 == 0 {
            fragments.reverse();
        }
        let fake = WirePacket {
            packet: vec![
                0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, 192, 168, 1, 67, 198, 51, 100, 8, 0xc7,
                0x38, 1, 0xbb, 0, 8, 0, 1,
            ],
            kind: EmitKind::Fake,
            delay_us: 0,
        };
        std::iter::once(fake).chain(fragments).collect()
    }

    fn assert_rewritten_fragment_group(
        packets: &[WirePacket],
        family: u8,
        mapping: R2oConntrackNatSource,
    ) {
        let mut datagram = vec![0; 40];
        for wire in packets {
            let packet = &wire.packet;
            if family == 4 {
                assert_eq!(&packet[12..16], &mapping.address[..4]);
                assert_eq!(internet_checksum(&packet[..20]), 0);
                let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
                let offset = usize::from(flags_offset & 0x1fff) * 8;
                datagram[offset..offset + packet.len() - 20].copy_from_slice(&packet[20..]);
            } else {
                assert_eq!(&packet[8..24], &mapping.address);
                let field = u16::from_be_bytes([packet[42], packet[43]]);
                let offset = usize::from(field & 0xfff8);
                datagram[offset..offset + packet.len() - 48].copy_from_slice(&packet[48..]);
            }
        }
        assert_eq!(u16::from_be_bytes([datagram[0], datagram[1]]), mapping.port);
        let mut pseudo = Vec::new();
        if family == 4 {
            pseudo.extend_from_slice(&mapping.address[..4]);
            pseudo.extend_from_slice(&[198, 51, 100, 8]);
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&40_u16.to_be_bytes());
        } else {
            pseudo.extend_from_slice(&mapping.address);
            pseudo.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
            pseudo.extend_from_slice(&40_u32.to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
        }
        pseudo.extend_from_slice(&datagram);
        assert_eq!(internet_checksum(&pseudo), 0);
    }
}

#[cfg(test)]
mod nat_stats_tests {
    use super::*;
    use std::time::Instant;

    fn tuple(protocol: u8) -> R2oConntrackTuple {
        let mut source = [0; 16];
        source[..4].copy_from_slice(&[192, 0, 2, 1]);
        let mut destination = [0; 16];
        destination[..4].copy_from_slice(&[198, 51, 100, 2]);
        R2oConntrackTuple {
            family: 4,
            protocol,
            source,
            destination,
            source_port: 40000,
            destination_port: 443,
        }
    }

    fn found() -> R2oProcNatLookup {
        R2oProcNatLookup::Found(R2oConntrackNatSource {
            family: 4,
            address: [203, 0, 113, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            port: 50000,
        })
    }

    #[test]
    fn nat_stats_match_d2o_counters() {
        let now = Instant::now();

        let mut gate = R2oConntrackGate::with_capacity(8);
        assert_eq!(
            gate.confirm(tuple(17), true, false, now, &mut |_| panic!()),
            Confirmation::FirstPacket
        );
        assert_eq!(gate.nat_stats(), (0, 0, 0, 0));

        let mut gate = R2oConntrackGate::with_capacity(8);
        assert_eq!(
            gate.confirm(tuple(6), false, true, now, &mut |_| panic!()),
            Confirmation::TcpSynAck
        );
        assert_eq!(gate.nat_stats(), (1, 0, 0, 0));

        let mut gate = R2oConntrackGate::with_capacity(8);
        assert_eq!(
            gate.confirm(tuple(17), false, false, now, &mut |_| {
                R2oProcNatLookup::TableMissing
            }),
            Confirmation::NoConntrackTable
        );
        assert_eq!(gate.nat_stats(), (0, 0, 1, 0));

        let mut gate = R2oConntrackGate::with_capacity(8);
        assert_eq!(
            gate.confirm(tuple(17), false, false, now, &mut |_| {
                R2oProcNatLookup::Missing
            }),
            Confirmation::Missing
        );
        assert_eq!(gate.nat_stats(), (0, 1, 0, 0));

        let mut gate = R2oConntrackGate::with_capacity(8);
        let mut calls = 0;
        assert_eq!(
            gate.confirm(tuple(17), false, false, now, &mut |_| {
                calls += 1;
                if calls == 1 {
                    R2oProcNatLookup::Missing
                } else {
                    found()
                }
            }),
            Confirmation::Tracked
        );
        assert_eq!(calls, 2);
        assert_eq!(gate.nat_stats(), (1, 0, 0, 1));

        // C `flow_tracked`: повторная попытка, на которой таблица исчезла,
        // тоже считается перепроверкой (`g_nat_retried++`), а не только
        // успешный повтор.
        let mut gate = R2oConntrackGate::with_capacity(8);
        let mut calls = 0;
        assert_eq!(
            gate.confirm(tuple(17), false, false, now, &mut |_| {
                calls += 1;
                if calls == 1 {
                    R2oProcNatLookup::Missing
                } else {
                    R2oProcNatLookup::TableMissing
                }
            }),
            Confirmation::NoConntrackTable
        );
        assert_eq!(calls, 2);
        assert_eq!(gate.nat_stats(), (0, 0, 1, 1));
    }
}
