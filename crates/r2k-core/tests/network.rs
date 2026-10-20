use r2k_core::addr::Address;
use r2k_core::packet::PacketView;
use std::net::IpAddr;

#[test]
fn address_literals_round_trip_without_scope_ids() {
    let ipv4 = Address::parse("192.0.2.1").unwrap();
    assert_eq!(ipv4.family(), 4);
    assert_eq!(ipv4.to_string(), "192.0.2.1");
    assert_eq!(ipv4.bytes()[..4], [192, 0, 2, 1]);
    assert!(ipv4.bytes()[4..].iter().all(|byte| *byte == 0));

    let ipv6 = Address::parse("2001:0db8:0:0:0:0:0:1").unwrap();
    assert_eq!(ipv6.family(), 6);
    assert_eq!(ipv6.to_string(), "2001:db8::1");
    assert_eq!(ipv6, Address::parse("2001:db8::1").unwrap());
    assert_ne!(ipv6, ipv4);
    assert_eq!(ipv6.as_ip_addr(), "2001:db8::1".parse::<IpAddr>().unwrap());
}

#[test]
fn invalid_address_forms_are_rejected() {
    for input in [
        "",
        "host.example",
        "2001:::1",
        "256.0.0.1",
        "::1junk",
        "[::1]",
        "fe80::1%eth0",
    ] {
        assert!(Address::parse(input).is_err(), "accepted {input}");
    }
}

#[test]
fn parses_ipv4_tcp_and_preserves_header_facts() {
    let packet = ipv4_packet(6, 20, 0x2000);
    let view = PacketView::parse(&packet).unwrap();
    assert_eq!(view.src.to_string(), "192.0.2.1");
    assert_eq!(view.dst.to_string(), "198.51.100.2");
    assert_eq!(view.family, 4);
    assert_eq!(view.protocol, 6);
    assert_eq!(view.total_len, packet.len());
    assert_eq!(view.l4_offset, 20);
    assert_eq!(view.hop_limit, 55);
    assert_eq!(view.traffic_class, 0x2e);
    assert_eq!(view.ip_id, 0x1234);
    assert_eq!(view.fragment, 0x2000);
}

#[test]
fn returns_udp_payload_only_when_the_udp_length_matches_the_ip_packet() {
    let packet = ipv4_udp(b"datagram");
    let view = PacketView::parse(&packet).unwrap();
    let range = view.udp_payload_range(&packet).unwrap();
    assert_eq!(&packet[range], b"datagram");

    let mut bad_length = packet;
    bad_length[24..26].copy_from_slice(&7_u16.to_be_bytes());
    let view = PacketView::parse(&bad_length).unwrap();
    assert!(view.udp_payload_range(&bad_length).is_none());
}

#[test]
fn rejects_noninitial_ipv4_fragments_and_short_transports() {
    assert!(PacketView::parse(&ipv4_packet(6, 20, 1)).is_none());
    assert!(PacketView::parse(&ipv4_packet(6, 19, 0)).is_none());
    assert!(PacketView::parse(&ipv4_packet(17, 7, 0)).is_none());
    assert!(PacketView::parse(&ipv4_packet(1, 20, 0)).is_none());
}

#[test]
fn parses_ipv6_padding_extensions_and_rejects_semantic_options() {
    let packet = ipv6_packet(0);
    let view = PacketView::parse(&packet).unwrap();
    assert_eq!(view.src, Address::parse("2000::1").unwrap());
    assert_eq!(view.dst, Address::parse("2000::2").unwrap());
    assert_eq!(view.family, 6);
    assert_eq!(view.protocol, 6);
    assert_eq!(view.l4_offset, 48);
    assert_eq!(view.total_len, packet.len());
    assert_eq!(view.hop_limit, 55);

    let mut semantic_option = packet;
    semantic_option[42] = 5; // Router Alert must stay outside this parser's remit.
    assert!(PacketView::parse(&semantic_option).is_none());
}

#[test]
fn unsupported_ipv6_headers_and_jumbograms_are_rejected() {
    let mut routing = ipv6_packet(43);
    routing[40] = 6;
    assert!(PacketView::parse(&routing).is_none());

    let mut fragment = ipv6_packet(44);
    fragment[40] = 6;
    assert!(PacketView::parse(&fragment).is_none());

    let mut jumbo = ipv6_packet(17);
    jumbo[4] = 0;
    jumbo[5] = 0;
    assert!(PacketView::parse(&jumbo).is_none());
}

#[test]
fn arbitrary_bytes_never_produce_out_of_bounds_packet_views() {
    let mut state = 0x6d2b_79f5_u32;
    for length in 0..1024 {
        let mut bytes = vec![0; length];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        if let Some(view) = PacketView::parse(&bytes) {
            assert!(view.total_len <= bytes.len());
            assert!(view.l4_offset <= view.total_len);
            assert!(matches!(view.protocol, 6 | 17));
        }
    }
}

fn ipv4_packet(protocol: u8, payload_length: usize, fragment: u16) -> Vec<u8> {
    let total = 20 + payload_length;
    let mut packet = vec![0; total];
    packet[0] = 0x45;
    packet[1] = 0x2e;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
    packet[6..8].copy_from_slice(&fragment.to_be_bytes());
    packet[8] = 55;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
    if protocol == 6 && payload_length >= 13 {
        packet[32] = 0x50;
    }
    packet
}

fn ipv4_udp(payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut packet = vec![0; 20 + udp_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((20 + udp_len) as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[1, 2, 3, 4]);
    packet[16..20].copy_from_slice(&[5, 6, 7, 8]);
    packet[20..22].copy_from_slice(&12345_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

fn ipv6_packet(protocol: u8) -> Vec<u8> {
    let extension_length = usize::from(protocol == 0) * 8;
    let payload_length = extension_length + 20;
    let mut packet = vec![0; 40 + payload_length];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
    packet[6] = protocol;
    packet[7] = 55;
    packet[8] = 0x20;
    packet[23] = 1;
    packet[24] = 0x20;
    packet[39] = 2;
    let tcp_offset = if protocol == 0 {
        packet[40] = 6;
        packet[41] = 0;
        48
    } else {
        40
    };
    packet[tcp_offset + 12] = 0x50;
    packet
}
