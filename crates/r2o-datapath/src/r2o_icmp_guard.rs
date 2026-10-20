//! Отсекает входящие сообщения ICMP «время жизни истекло» на свои пакеты с пониженным TTL.

use crate::netlink::{R2O_NF_INET_FORWARD, R2O_NF_INET_LOCAL_IN};

const R2O_ICMP_GUARD_SLOTS: usize = 256;
const R2O_ICMP_GUARD_KEEP_NS: u64 = 5_000_000_000;

#[derive(Clone, Copy, Default)]
struct R2oIcmpGuardSlot {
    at_ns: u64,
    family: u8,
    protocol: u8,
    ttl: u8,
    have_id: bool,
    source: [u8; 16],
    destination: [u8; 16],
    source_port: [u8; 2],
    destination_port: [u8; 2],
    transport_word: [u8; 4],
    ip_len: u16,
    ip_id: u16,
}

pub struct R2oIcmpGuard {
    slots: [R2oIcmpGuardSlot; R2O_ICMP_GUARD_SLOTS],
    next: usize,
    seen: u64,
    noted: u64,
    dropped: u64,
}

impl Default for R2oIcmpGuard {
    fn default() -> Self {
        Self {
            slots: [R2oIcmpGuardSlot::default(); R2O_ICMP_GUARD_SLOTS],
            next: 0,
            seen: 0,
            noted: 0,
            dropped: 0,
        }
    }
}

struct R2oIcmpQuote<'a> {
    family: u8,
    protocol: u8,
    ttl: u8,
    source: &'a [u8],
    destination: &'a [u8],
    transport: &'a [u8],
    ip_len: u16,
    ip_id: u16,
}

impl R2oIcmpGuard {
    pub fn r2o_note(&mut self, packet: &[u8], original_ttl: u8, now_ns: u64) -> bool {
        let Some(quote) = r2o_parse_icmp_quote(packet) else {
            return false;
        };
        if quote.ttl >= original_ttl {
            return false;
        }

        let index = self.next;
        self.next = (self.next + 1) % R2O_ICMP_GUARD_SLOTS;
        self.slots[index] = R2oIcmpGuardSlot {
            at_ns: now_ns.max(1),
            family: quote.family,
            protocol: quote.protocol,
            ttl: quote.ttl,
            have_id: quote.family == 4 && quote.ip_id != 0,
            source: r2o_copy_address(quote.source),
            destination: r2o_copy_address(quote.destination),
            source_port: quote.transport[..2]
                .try_into()
                .expect("порт занимает два байта"),
            destination_port: quote.transport[2..4]
                .try_into()
                .expect("порт занимает два байта"),
            transport_word: quote.transport[4..8]
                .try_into()
                .expect("разбор проверил длину заголовка транспорта"),
            ip_len: quote.ip_len,
            ip_id: quote.ip_id,
        };
        self.noted = self.noted.wrapping_add(1);
        true
    }

    pub fn r2o_check(&mut self, packet: &[u8], now_ns: u64) -> bool {
        let Some((family, quote_start)) = r2o_icmp_quote_start(packet) else {
            return false;
        };
        let Some(quote) = packet
            .get(quote_start..)
            .and_then(r2o_parse_icmp_quote)
            .filter(|quote| quote.family == family)
        else {
            return false;
        };
        let address_len = if family == 6 { 16 } else { 4 };

        for slot in &self.slots {
            if slot.at_ns == 0
                || now_ns < slot.at_ns
                || now_ns - slot.at_ns > R2O_ICMP_GUARD_KEEP_NS
                || slot.family != family
                || slot.protocol != quote.protocol
                || slot.source[..address_len] != *quote.source
                || slot.destination[..address_len] != *quote.destination
                || slot.source_port != quote.transport[..2]
                || slot.destination_port != quote.transport[2..4]
                || slot.ip_len != quote.ip_len
                || (slot.have_id && slot.ip_id != quote.ip_id)
                || quote.transport[4..4 + if quote.protocol == 6 { 4 } else { 2 }]
                    != slot.transport_word[..if quote.protocol == 6 { 4 } else { 2 }]
                || quote.ttl > slot.ttl
            {
                continue;
            }
            self.dropped = self.dropped.wrapping_add(1);
            return true;
        }
        false
    }

    pub fn r2o_handle_at_hook(
        &mut self,
        packet: &[u8],
        hook: Option<u8>,
        now_ns: u64,
    ) -> Option<bool> {
        if !r2o_is_icmp_packet(packet) {
            return None;
        }
        self.seen = self.seen.wrapping_add(1);
        let inbound = matches!(hook, Some(R2O_NF_INET_LOCAL_IN) | Some(R2O_NF_INET_FORWARD));
        Some(inbound && self.r2o_check(packet, now_ns))
    }

    pub fn r2o_seen(&self) -> u64 {
        self.seen
    }

    pub fn r2o_noted(&self) -> u64 {
        self.noted
    }

    pub fn r2o_dropped(&self) -> u64 {
        self.dropped
    }
}

fn r2o_is_icmp_packet(packet: &[u8]) -> bool {
    let Some(version) = packet.first().map(|byte| byte >> 4) else {
        return false;
    };
    match version {
        4 => packet.len() >= 20 && packet[9] == 1,
        6 => packet.len() >= 40 && packet[6] == 58,
        _ => false,
    }
}

fn r2o_icmp_quote_start(packet: &[u8]) -> Option<(u8, usize)> {
    match packet.first()? >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let flags_offset = r2o_u16(packet, 6)?;
            if header_len < 20
                || packet[9] != 1
                || flags_offset & 0x3fff != 0
                || packet.len() < header_len + 8
                || packet[header_len] != 11
                || packet[header_len + 1] != 0
            {
                return None;
            }
            Some((4, header_len + 8))
        }
        6 => {
            if packet.len() < 48 || packet[6] != 58 || packet[40] != 3 || packet[41] != 0 {
                return None;
            }
            Some((6, 48))
        }
        _ => None,
    }
}

fn r2o_parse_icmp_quote(packet: &[u8]) -> Option<R2oIcmpQuote<'_>> {
    let family = packet.first()? >> 4;
    let (header_len, protocol, ttl, ip_len, ip_id, source, destination) = match family {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || r2o_u16(packet, 6)? & 0x1fff != 0 {
                return None;
            }
            (
                header_len,
                packet[9],
                packet[8],
                r2o_u16(packet, 2)?,
                r2o_u16(packet, 4)?,
                packet.get(12..16)?,
                packet.get(16..20)?,
            )
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            (
                40,
                packet[6],
                packet[7],
                r2o_u16(packet, 4)?,
                0,
                packet.get(8..24)?,
                packet.get(24..40)?,
            )
        }
        _ => return None,
    };
    if protocol != 6 && protocol != 17 {
        return None;
    }
    let transport = packet.get(header_len..header_len.checked_add(8)?)?;
    Some(R2oIcmpQuote {
        family,
        protocol,
        ttl,
        source,
        destination,
        transport,
        ip_len,
        ip_id,
    })
}

fn r2o_u16(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        packet
            .get(offset..offset.checked_add(2)?)?
            .try_into()
            .ok()?,
    ))
}

fn r2o_copy_address(address: &[u8]) -> [u8; 16] {
    let mut result = [0; 16];
    result[..address.len()].copy_from_slice(address);
    result
}
