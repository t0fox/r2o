//! DoH DNS-wire A/AAAA: точный перенос C `route_dns.c`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::cf_proxy_doh::is_usable_edge_ip;

pub const MAX_ADDRESSES: usize = 8;

/// C `dns_encode_question`: QDCOUNT=1, random/literal ID, A/AAAA.
pub fn encode_question(domain: &str, qtype: u16, id: u16) -> Result<Vec<u8>, String> {
    if domain.is_empty() {
        return Err("пустой DoH-домен".to_string());
    }
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 || packet.len() + label.len() + 7 > 512 {
            return Err("неверная метка DoH-домена".to_string());
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&[0, 1]);
    Ok(packet)
}

fn skip_name(packet: &[u8], offset: &mut usize) -> Result<(), String> {
    let mut cursor = *offset;
    let mut next = cursor;
    let mut jumped = false;
    let mut steps = 0usize;
    while cursor < packet.len() && steps < packet.len() {
        steps += 1;
        let label = packet[cursor];
        cursor += 1;
        if label & 0xc0 == 0xc0 {
            if cursor >= packet.len() {
                return Err("DNS: обрезанный compression pointer".to_string());
            }
            let pointer = ((usize::from(label & 0x3f)) << 8) | usize::from(packet[cursor]);
            cursor += 1;
            if pointer >= packet.len() {
                return Err("DNS: compression pointer вне пакета".to_string());
            }
            if !jumped {
                next = cursor;
            }
            cursor = pointer;
            jumped = true;
            continue;
        }
        if label & 0xc0 != 0 {
            return Err("DNS: неверный label".to_string());
        }
        if label == 0 {
            if !jumped {
                next = cursor;
            }
            *offset = next;
            return Ok(());
        }
        let label = usize::from(label);
        if label > 63 || label > packet.len().saturating_sub(cursor) {
            return Err("DNS: обрезанный label".to_string());
        }
        cursor += label;
        if !jumped {
            next = cursor;
        }
    }
    Err("DNS: незавершённое имя".to_string())
}

/// C `tg_route_dns_parse_response`: ID/флаги/секции, A/AAAA, public-target.
pub fn parse_response(packet: &[u8], expected_id: u16) -> Result<Vec<IpAddr>, String> {
    if packet.len() < 12 {
        return Err("DNS: короткий ответ".to_string());
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);
    if id != expected_id
        || flags & 0x8000 == 0
        || flags & 0x0200 != 0
        || flags & 0x000f != 0
        || questions > 16
        || answers > 256
    {
        return Err("DNS: неверный заголовок".to_string());
    }
    let mut offset = 12usize;
    for _ in 0..questions {
        skip_name(packet, &mut offset)?;
        if packet.len().saturating_sub(offset) < 4 {
            return Err("DNS: обрезанный вопрос".to_string());
        }
        offset += 4;
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        skip_name(packet, &mut offset)?;
        if packet.len().saturating_sub(offset) < 10 {
            return Err("DNS: обрезанный ответ".to_string());
        }
        let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let data_len = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]);
        offset += 10;
        let data_len = usize::from(data_len);
        if data_len > packet.len().saturating_sub(offset) {
            return Err("DNS: обрезанные данные ответа".to_string());
        }
        let address = match (class, record_type, data_len) {
            (1, 1, 4) => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&packet[offset..offset + 4]);
                Some(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            (1, 28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[offset..offset + 16]);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        };
        if let Some(address) = address
            && is_usable_edge_ip(&address)
            && !addresses.contains(&address)
            && addresses.len() < MAX_ADDRESSES
        {
            addresses.push(address);
        }
        offset += data_len;
    }
    if addresses.is_empty() {
        Err("DNS: нет публичных A/AAAA".to_string())
    } else {
        Ok(addresses)
    }
}
