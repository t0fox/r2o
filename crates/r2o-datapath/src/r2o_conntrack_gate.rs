//! Подтверждение conntrack перед исполнением сетевого плана.

use crate::conntrack::{
    R2oConntrackClient, R2oConntrackEntry, R2oConntrackNatSource, R2oConntrackTuple,
    tuple_from_packet,
};
use crate::engine::{PacketDecision, WirePacket};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const R2O_CONNTRACK_CACHE_IDLE: Duration = Duration::from_secs(120);
const R2O_CONNTRACK_LOOKUP_ATTEMPTS: usize = 3;

#[derive(Clone, Copy)]
struct CachedEntry {
    entry: R2oConntrackEntry,
    seen: Instant,
}

/// Ограниченный кеш только подтверждённых записей conntrack.
pub struct R2oConntrackGate {
    entries: HashMap<R2oConntrackTuple, CachedEntry>,
    capacity: usize,
    no_conntrack_table: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Confirmation {
    FirstPacket,
    TcpSynAck,
    NoConntrackTable,
    Entry(Option<R2oConntrackNatSource>),
    Missing,
}

impl R2oConntrackGate {
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_table_state(capacity, false)
    }

    pub fn with_table_state(capacity: usize, no_conntrack_table: bool) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity,
            no_conntrack_table,
        }
    }

    fn confirm(
        &mut self,
        tuple: R2oConntrackTuple,
        first_packet: bool,
        tcp_syn_ack_seen: bool,
        mapping_required: bool,
        now: Instant,
        mut query: impl FnMut(&R2oConntrackTuple) -> Option<R2oConntrackEntry>,
    ) -> Confirmation {
        self.entries.retain(|_, cached| {
            now.saturating_duration_since(cached.seen) < R2O_CONNTRACK_CACHE_IDLE
        });
        if let Some(cached) = self.entries.get_mut(&tuple) {
            let mapped = cached
                .entry
                .nat_source
                .is_some_and(|source| source.family == tuple.family && source.port != 0);
            if !mapping_required || mapped {
                cached.seen = now;
                return Confirmation::Entry(cached.entry.nat_source);
            }
        }
        if first_packet && !mapping_required {
            return Confirmation::FirstPacket;
        }
        if tuple.protocol == 6 && tcp_syn_ack_seen && !mapping_required {
            return Confirmation::TcpSynAck;
        }
        if self.no_conntrack_table {
            return Confirmation::NoConntrackTable;
        }

        for _ in 0..R2O_CONNTRACK_LOOKUP_ATTEMPTS {
            let Some(entry) = query(&tuple) else {
                continue;
            };
            let has_mapping = entry
                .nat_source
                .is_some_and(|source| source.family == tuple.family && source.port != 0);
            if mapping_required && !has_mapping {
                continue;
            }
            if self.capacity != 0 {
                if self.entries.len() >= self.capacity && !self.entries.contains_key(&tuple) {
                    if let Some(oldest) = self
                        .entries
                        .iter()
                        .min_by_key(|(_, cached)| cached.seen)
                        .map(|(key, _)| *key)
                    {
                        self.entries.remove(&oldest);
                    }
                }
                self.entries.insert(tuple, CachedEntry { entry, seen: now });
            }
            return Confirmation::Entry(entry.nat_source);
        }
        Confirmation::Missing
    }
}

/// Не допускать применение плана к неподтверждённому потоку.
pub fn guard_decision(
    gate: &mut R2oConntrackGate,
    conntrack: &mut Option<R2oConntrackClient>,
    packet: &[u8],
    decision: PacketDecision,
    plan_id: [u8; 16],
    first_packet: bool,
    tcp_syn_ack_seen: bool,
) -> PacketDecision {
    if !matches!(
        &decision,
        PacketDecision::Drop | PacketDecision::Replace(_) | PacketDecision::Transmit { .. }
    ) {
        return decision;
    }
    let Some(tuple) = tuple_from_packet(packet) else {
        return decision;
    };
    let mapping_required = tuple.protocol == 17 && decision_has_udp_fragments(&decision);
    let confirmation = gate.confirm(
        tuple,
        first_packet,
        tcp_syn_ack_seen,
        mapping_required,
        Instant::now(),
        |tuple| {
            conntrack
                .as_mut()
                .and_then(|client| client.query_entry(tuple))
        },
    );
    match confirmation {
        Confirmation::FirstPacket | Confirmation::TcpSynAck => decision,
        Confirmation::NoConntrackTable if !mapping_required => decision,
        Confirmation::NoConntrackTable => PacketDecision::Refused { plan_id },
        Confirmation::Entry(mapping) => {
            if !mapping_required {
                return decision;
            }
            let Some(mapping) = mapping else {
                return PacketDecision::Refused { plan_id };
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
        Confirmation::Missing if first_packet && mapping_required => PacketDecision::Accept,
        Confirmation::Missing => PacketDecision::Refused { plan_id },
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
        if header_len < 20 || header_len.checked_add(8)? > packet.len() || packet[9] != 17 {
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
        Confirmation, R2oConntrackGate, guard_decision, internet_checksum, rewrite_fragment_group,
        update_checksum,
    };
    use crate::conntrack::{
        R2oConntrackEntry, R2oConntrackInfo, R2oConntrackNatSource, R2oConntrackTuple,
    };
    use crate::engine::{PacketDecision, WirePacket};
    use r2k_core::plan::EmitKind;
    use std::time::Instant;

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

    fn entry() -> R2oConntrackEntry {
        R2oConntrackEntry {
            info: Some(R2oConntrackInfo {
                original_packets: 1,
                reply_packets: 0,
                tcp_state: None,
            }),
            nat_source: None,
        }
    }

    fn mapped_entry() -> R2oConntrackEntry {
        R2oConntrackEntry {
            nat_source: Some(R2oConntrackNatSource {
                family: 4,
                address: [203, 0, 113, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                port: 62000,
            }),
            ..entry()
        }
    }

    #[test]
    fn пропускает_первый_пакет_без_чтения_таблицы() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        assert_eq!(
            gate.confirm(tuple(17), true, false, false, Instant::now(), |_| {
                calls += 1;
                None
            }),
            Confirmation::FirstPacket
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn пропускает_tcp_после_syn_ack_без_повторного_чтения() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        assert_eq!(
            gate.confirm(tuple(6), false, true, false, Instant::now(), |_| {
                calls += 1;
                None
            }),
            Confirmation::TcpSynAck
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn различает_отсутствие_таблицы_и_промах_потока() {
        let mut gate = R2oConntrackGate::with_table_state(4, true);
        assert_eq!(
            gate.confirm(tuple(17), false, false, false, Instant::now(), |_| {
                panic!("ctnetlink не должен опрашиваться без conntrack-таблицы")
            }),
            Confirmation::NoConntrackTable
        );
        assert_eq!(
            gate.confirm(tuple(17), true, false, true, Instant::now(), |_| {
                panic!("фрагментация не должна запрашивать отсутствующую таблицу")
            }),
            Confirmation::NoConntrackTable
        );
    }

    #[test]
    fn не_кэширует_промахи_и_повторяет_поиск_до_трёх_раз() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        let query = |_: &R2oConntrackTuple| {
            calls += 1;
            if calls == 2 { Some(entry()) } else { None }
        };
        assert_eq!(
            gate.confirm(tuple(17), false, false, false, Instant::now(), query),
            Confirmation::Entry(None)
        );
        assert_eq!(calls, 2);
        let mut next_calls = 0;
        assert_eq!(
            gate.confirm(tuple(17), false, false, true, Instant::now(), |_| {
                next_calls += 1;
                None
            }),
            Confirmation::Missing
        );
        assert_eq!(next_calls, 3);
    }

    #[test]
    fn промах_первой_фрагментированной_датаграммы_не_мешает_повтору() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut calls = 0;
        assert_eq!(
            gate.confirm(tuple(17), true, false, true, Instant::now(), |_| {
                calls += 1;
                None
            }),
            Confirmation::Missing
        );
        assert_eq!(calls, 3);
        assert_eq!(
            gate.confirm(tuple(17), false, false, true, Instant::now(), |_| {
                calls += 1;
                Some(mapped_entry())
            }),
            Confirmation::Entry(mapped_entry().nat_source)
        );
        assert_eq!(calls, 4);
    }

    #[test]
    fn первый_udp_initial_откладывается_если_nat_mapping_ещё_нет() {
        let mut gate = R2oConntrackGate::with_capacity(4);
        let mut conntrack = None;
        let source = ipv4_udp_packet();
        let wires = fragment_fixture(4, 1);
        let decision = PacketDecision::Transmit {
            packets: wires.into_iter().skip(1).collect(),
            fate: r2k_core::plan::OriginalFate::Drop,
        };
        assert_eq!(
            guard_decision(
                &mut gate,
                &mut conntrack,
                &source,
                decision.clone(),
                [4; 16],
                true,
                false,
            ),
            PacketDecision::Accept
        );
        assert_eq!(
            guard_decision(
                &mut gate,
                &mut conntrack,
                &source,
                decision,
                [4; 16],
                false,
                false,
            ),
            PacketDecision::Refused { plan_id: [4; 16] }
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
