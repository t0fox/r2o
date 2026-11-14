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

    const FAKE4_PACKET: [u8; 28] = [
        0x45, 0x70, 0x04, 0xcc, 0x00, 0x01, 0x40, 0x00, 0x03, 0x11, 0x16, 0x59, 0xc0, 0xa8, 0x01,
        0x43, 0x68, 0x15, 0x34, 0x57, 0xd8, 0x8b, 0x01, 0xbb, 0x04, 0xb8, 0x34, 0x8e,
    ];

    const FIELD_ICMP: [u8; 56] = [
        0x45, 0x70, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x01, 0x2d, 0x19, 0x3e, 0x73, 0x91,
        0xdd, 0xc0, 0xa8, 0x01, 0x43, 0x0b, 0x00, 0xe1, 0x72, 0x00, 0x00, 0x00, 0x00, 0x45, 0x70,
        0x04, 0xcc, 0x00, 0x01, 0x40, 0x00, 0x01, 0x11, 0x16, 0x59, 0xc0, 0xa8, 0x01, 0x43, 0x68,
        0x15, 0x34, 0x57, 0xd8, 0x8b, 0x01, 0xbb, 0x04, 0xb8, 0x34, 0x8e,
    ];

    fn fake4() -> Vec<u8> {
        let mut packet = vec![0; 1228];
        packet[..FAKE4_PACKET.len()].copy_from_slice(&FAKE4_PACKET);
        packet[2..4].copy_from_slice(&1228_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&1208_u16.to_be_bytes());
        packet
    }

    fn run_icmp_step(name: &str, payload: Option<&[u8]>, hook: Option<u8>, with_fake: bool) {
        use super::R2oIcmpGuard;

        let mut guard = R2oIcmpGuard::default();
        if with_fake {
            assert!(guard.r2o_note(&fake4(), 64, 1_000_000_000));
        }
        let handled =
            payload.and_then(|payload| guard.r2o_handle_at_hook(payload, hook, 1_000_000_000));
        println!(
            "{name} handled={} drop={} seen={} noted={} dropped={}",
            u8::from(handled.is_some()),
            u8::from(handled == Some(true)),
            guard.r2o_seen(),
            guard.r2o_noted(),
            guard.r2o_dropped()
        );
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

    #[test]
    #[ignore]
    fn d2o_icmp_step_trace() {
        use crate::netlink::{R2O_NF_INET_FORWARD, R2O_NF_INET_LOCAL_IN, R2O_NF_INET_POST_ROUTING};

        let short_packet = [0x45_u8];
        let v4_tcp = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6];
        let v6_tcp = [0x60, 0, 0, 0, 0, 0, 6, 64];
        let mut mutated = FIELD_ICMP;
        mutated[48] ^= 1;

        run_icmp_step("A no-payload", None, Some(R2O_NF_INET_FORWARD), true);
        run_icmp_step(
            "B one-byte",
            Some(&short_packet),
            Some(R2O_NF_INET_FORWARD),
            true,
        );
        run_icmp_step(
            "C v4-non-icmp",
            Some(&v4_tcp),
            Some(R2O_NF_INET_FORWARD),
            true,
        );
        run_icmp_step(
            "D v6-non-icmp",
            Some(&v6_tcp),
            Some(R2O_NF_INET_FORWARD),
            true,
        );
        run_icmp_step(
            "E v4-no-fake",
            Some(&FIELD_ICMP),
            Some(R2O_NF_INET_FORWARD),
            false,
        );
        run_icmp_step(
            "F v4-forward",
            Some(&FIELD_ICMP),
            Some(R2O_NF_INET_FORWARD),
            true,
        );
        run_icmp_step(
            "G v4-input",
            Some(&FIELD_ICMP),
            Some(R2O_NF_INET_LOCAL_IN),
            true,
        );
        run_icmp_step(
            "H v4-postrouting",
            Some(&FIELD_ICMP),
            Some(R2O_NF_INET_POST_ROUTING),
            true,
        );
        run_icmp_step("I v4-prerouting", Some(&FIELD_ICMP), Some(0), true);
        run_icmp_step(
            "J v4-mutated",
            Some(&mutated),
            Some(R2O_NF_INET_FORWARD),
            true,
        );
    }
}
