use r2k_core::addr::Address;
use r2k_core::packet::PacketView;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;

pub fn build_http_redirect_packets(input: &[u8], redirect: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let view = PacketView::parse(input)?;
    if view.total_len != input.len()
        || view.protocol != 6
        || view.fragment & 0x3fff != 0
        || redirect.is_empty()
    {
        return None;
    }
    let tcp = view.tcp_segment(input)?;
    if tcp.source_port != 80 || tcp.destination_port == 80 || tcp.flags & 0x10 == 0 {
        return None;
    }

    let response = build_segment(SegmentSpec {
        family: view.family,
        source: view.src,
        destination: view.dst,
        source_port: tcp.source_port,
        destination_port: tcp.destination_port,
        sequence: tcp.sequence,
        acknowledgment: tcp.acknowledgment,
        flags: 0x19,
        window: tcp.window,
        hop_limit: view.hop_limit,
        traffic_class: view.traffic_class,
        flow_label: view.flow_label,
        ip_id: view.ip_id,
        payload: redirect,
    })?;
    let reset_id = if view.family == 4 {
        view.ip_id.wrapping_add(1).max(1)
    } else {
        0
    };
    let reset = build_segment(SegmentSpec {
        family: view.family,
        source: view.dst,
        destination: view.src,
        source_port: tcp.destination_port,
        destination_port: tcp.source_port,
        sequence: tcp.acknowledgment,
        acknowledgment: tcp.sequence,
        flags: 0x14,
        window: 0,
        hop_limit: 64,
        traffic_class: 0,
        flow_label: 0,
        ip_id: reset_id,
        payload: &[],
    })?;
    Some((response, reset))
}

struct SegmentSpec<'a> {
    family: u8,
    source: Address,
    destination: Address,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    window: u16,
    hop_limit: u8,
    traffic_class: u8,
    flow_label: u32,
    ip_id: u16,
    payload: &'a [u8],
}

fn build_segment(spec: SegmentSpec<'_>) -> Option<Vec<u8>> {
    let SegmentSpec {
        family,
        source,
        destination,
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        flags,
        window,
        hop_limit,
        traffic_class,
        flow_label,
        ip_id,
        payload,
    } = spec;
    let ip_len = match family {
        4 => IPV4_HEADER_LEN,
        6 => IPV6_HEADER_LEN,
        _ => return None,
    };
    let tcp_len = TCP_HEADER_LEN.checked_add(payload.len())?;
    let total_len = ip_len.checked_add(tcp_len)?;
    if total_len > usize::from(u16::MAX) || family == 6 && tcp_len > usize::from(u16::MAX) {
        return None;
    }

    let mut packet = vec![0; total_len];
    if family == 4 {
        packet[0] = 0x45;
        packet[1] = traffic_class;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&ip_id.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = hop_limit;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source.bytes()[..4]);
        packet[16..20].copy_from_slice(&destination.bytes()[..4]);
        let checksum = checksum(sum16(&packet[..IPV4_HEADER_LEN], 0));
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    } else {
        packet[0] = 0x60 | (traffic_class >> 4);
        packet[1] = (traffic_class & 0x0f) << 4 | ((flow_label >> 16) as u8 & 0x0f);
        packet[2] = (flow_label >> 8) as u8;
        packet[3] = flow_label as u8;
        packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[7] = hop_limit;
        packet[8..24].copy_from_slice(&source.bytes());
        packet[24..40].copy_from_slice(&destination.bytes());
    }

    let tcp_start = ip_len;
    packet[tcp_start..tcp_start + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[tcp_start + 2..tcp_start + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[tcp_start + 4..tcp_start + 8].copy_from_slice(&sequence.to_be_bytes());
    packet[tcp_start + 8..tcp_start + 12].copy_from_slice(&acknowledgment.to_be_bytes());
    packet[tcp_start + 12] = 0x50;
    packet[tcp_start + 13] = flags;
    packet[tcp_start + 14..tcp_start + 16].copy_from_slice(&window.to_be_bytes());
    packet[tcp_start + TCP_HEADER_LEN..].copy_from_slice(payload);
    let checksum_sum = pseudo_sum(family, source, destination, tcp_len);
    let tcp_checksum = checksum(sum16(&packet[tcp_start..], checksum_sum));
    packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    Some(packet)
}

fn pseudo_sum(family: u8, source: Address, destination: Address, tcp_len: usize) -> u64 {
    let mut sum = 6 + tcp_len as u64;
    let width = if family == 4 { 4 } else { 16 };
    sum = sum16(&source.bytes()[..width], sum);
    sum16(&destination.bytes()[..width], sum)
}

fn sum16(bytes: &[u8], mut sum: u64) -> u64 {
    for word in bytes.chunks(2) {
        sum += if word.len() == 2 {
            u64::from(u16::from_be_bytes([word[0], word[1]]))
        } else {
            u64::from(word[0]) << 8
        };
    }
    sum
}

fn checksum(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::build_http_redirect_packets;
    use r2k_core::packet::PacketView;
    use r2k_core::wire::tcp_checksum_ok;

    fn server_packet(family: u8) -> Vec<u8> {
        let payload = b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.example/blocked\r\n\r\n";
        let ip_len = if family == 4 { 20 } else { 40 };
        let mut packet = vec![0; ip_len + 20 + payload.len()];
        if family == 4 {
            packet[0] = 0x45;
            packet[1] = 0x2e;
            let total_len = packet.len() as u16;
            packet[2..4].copy_from_slice(&total_len.to_be_bytes());
            packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
            packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
            packet[8] = 51;
            packet[9] = 6;
            packet[12..16].copy_from_slice(&[198, 51, 100, 2]);
            packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        } else {
            packet[0] = 0x6a;
            packet[1] = 0xb0;
            packet[2] = 0x12;
            packet[3] = 0x34;
            packet[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
            packet[6] = 6;
            packet[7] = 51;
            packet[8..24]
                .copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
            packet[24..40]
                .copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        }
        let tcp = ip_len;
        packet[tcp..tcp + 2].copy_from_slice(&80_u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[tcp + 4..tcp + 8].copy_from_slice(&9001_u32.to_be_bytes());
        packet[tcp + 8..tcp + 12].copy_from_slice(&2048_u32.to_be_bytes());
        packet[tcp + 12] = 0x50;
        packet[tcp + 13] = 0x18;
        packet[tcp + 14..tcp + 16].copy_from_slice(&4096_u16.to_be_bytes());
        packet[tcp + 20..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn builds_checksum_valid_307_and_reset_packets_for_ipv4_and_ipv6() {
        let redirect = r2k_core::httpup::redirect_https(b"example.test", b"/path?q=1").unwrap();
        for family in [4, 6] {
            let original = server_packet(family);
            let (response, reset) = build_http_redirect_packets(&original, &redirect).unwrap();
            let response_view = PacketView::parse(&response).unwrap();
            let response_tcp = response_view.tcp_segment(&response).unwrap();
            assert_eq!(response_view.family, family);
            assert_eq!(response_view.src, PacketView::parse(&original).unwrap().src);
            assert_eq!(response_view.dst, PacketView::parse(&original).unwrap().dst);
            assert_eq!(response_tcp.source_port, 80);
            assert_eq!(response_tcp.destination_port, 40_000);
            assert_eq!(response_tcp.sequence, 9001);
            assert_eq!(response_tcp.acknowledgment, 2048);
            assert_eq!(response_tcp.flags, 0x19);
            assert_eq!(&response[response_tcp.payload], redirect.as_slice());
            assert!(tcp_checksum_ok(&response));

            let reset_view = PacketView::parse(&reset).unwrap();
            let reset_tcp = reset_view.tcp_segment(&reset).unwrap();
            assert_eq!(reset_view.src, response_view.dst);
            assert_eq!(reset_view.dst, response_view.src);
            assert_eq!(reset_tcp.source_port, 40_000);
            assert_eq!(reset_tcp.destination_port, 80);
            assert_eq!(reset_tcp.sequence, 2048);
            assert_eq!(reset_tcp.acknowledgment, 9001);
            assert_eq!(reset_tcp.flags, 0x14);
            assert!(tcp_checksum_ok(&reset));
            if family == 4 {
                assert_ne!(reset_view.ip_id, 0);
            }
        }
    }
}
