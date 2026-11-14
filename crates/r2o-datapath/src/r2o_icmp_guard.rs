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

    pub fn r2o_stats_line(&self) -> Option<String> {
        if self.seen == 0 && self.noted == 0 {
            return None;
        }
        Some(format!(
            "ICMP time-exceeded: получено {}, снято на свои фальшивки {}; фальшивок с пониженным TTL запомнено {}",
            self.seen, self.dropped, self.noted
        ))
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

#[cfg(test)]
mod tests {
    use super::r2o_parse_icmp_quote;

    fn put16(packet: &mut [u8], at: usize, value: u16) {
        packet[at..at + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn fill(packet: &mut [u8]) {
        for (index, byte) in packet.iter_mut().enumerate() {
            *byte = 0x30_u8.wrapping_add(index as u8 & 0x3f);
        }
    }

    fn v4(
        length: usize,
        ihl: u8,
        fragment: u16,
        proto: u8,
        ttl: u8,
        ip_len: u16,
        ip_id: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0; 64];
        fill(&mut packet);
        packet[0] = 0x40 | ihl;
        put16(&mut packet, 2, ip_len);
        put16(&mut packet, 4, ip_id);
        put16(&mut packet, 6, fragment);
        packet[8] = ttl;
        packet[9] = proto;
        packet[12..16].copy_from_slice(&[10, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 2, 2]);
        packet.truncate(length);
        packet
    }

    fn v6(length: usize, proto: u8, ttl: u8, payload_len: u16) -> Vec<u8> {
        let mut packet = vec![0; 64];
        fill(&mut packet);
        packet[0] = 0x60;
        put16(&mut packet, 4, payload_len);
        packet[6] = proto;
        packet[7] = ttl;
        for offset in 0..16 {
            packet[8 + offset] = 0x20 + offset as u8;
            packet[24 + offset] = 0x40 + offset as u8;
        }
        packet.truncate(length);
        packet
    }

    fn run(name: &str, packet: &[u8]) {
        match r2o_parse_icmp_quote(packet) {
            None => println!("{name} ok=0"),
            Some(quote) => {
                print!(
                    "{name} ok=1 fam={} proto={} ttl={} ip_len={} ip_id={} src=",
                    quote.family, quote.protocol, quote.ttl, quote.ip_len, quote.ip_id
                );
                for byte in quote.source {
                    print!("{byte:02x}");
                }
                print!(" dst=");
                for byte in quote.destination {
                    print!("{byte:02x}");
                }
                print!(" l4=");
                for byte in quote.transport {
                    print!("{byte:02x}");
                }
                println!();
            }
        }
    }

    #[test]
    #[ignore]
    fn d2o_parse_ip_trace() {
        run("A v4-tcp", &v4(28, 5, 0, 6, 64, 40, 1));
        run("B v4-udp", &v4(28, 5, 0, 17, 63, 40, 2));
        run("C v4-short20", &v4(19, 5, 0, 6, 64, 40, 1));
        run("D v4-bad-ihl", &v4(28, 4, 0, 6, 64, 40, 1));
        run("E v4-fragment", &v4(28, 5, 1, 6, 64, 40, 1));
        run("F v4-icmp-proto", &v4(28, 5, 0, 1, 64, 40, 1));
        run("G v4-need-l4", &v4(27, 5, 0, 6, 64, 40, 1));
        run("H v4-mf-first", &v4(28, 5, 0x2000, 6, 64, 40, 7));
        run("I v6-tcp", &v6(48, 6, 64, 8));
        run("J v6-short", &v6(39, 6, 64, 0));
        run("K v6-icmpv6-proto", &v6(48, 58, 64, 8));
        run("L v6-need-l4", &v6(47, 6, 64, 7));
        run("M v6-udp-ttl1", &v6(48, 17, 1, 8));
        run("N one-byte", &v4(1, 5, 0, 6, 64, 40, 1));
        run("O empty", &[]);
    }
}
