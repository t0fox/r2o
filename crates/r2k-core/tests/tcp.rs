use r2k_core::packet::PacketView;

fn ipv4_tcp(options: &[u8], payload: &[u8]) -> Vec<u8> {
    let tcp_header_len = 20 + options.len();
    let mut packet = vec![0; 20 + tcp_header_len + payload.len()];
    packet[0] = 0x45;
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
    let tcp = 20;
    packet[tcp..tcp + 2].copy_from_slice(&41000u16.to_be_bytes());
    packet[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
    packet[tcp + 4..tcp + 8].copy_from_slice(&0x1020_3040u32.to_be_bytes());
    packet[tcp + 8..tcp + 12].copy_from_slice(&0x5060_7080u32.to_be_bytes());
    packet[tcp + 12] = ((tcp_header_len / 4) as u8) << 4;
    packet[tcp + 13] = 0x18;
    packet[tcp + 14..tcp + 16].copy_from_slice(&3000u16.to_be_bytes());
    packet[tcp + 18..tcp + 20].copy_from_slice(&7u16.to_be_bytes());
    packet[tcp + 20..tcp + tcp_header_len].copy_from_slice(options);
    packet[tcp + tcp_header_len..].copy_from_slice(payload);
    packet
}

#[test]
fn tcp_view_exposes_header_fields_and_exact_options_and_payload_ranges() {
    let options = [1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2];
    let packet = ipv4_tcp(&options, &[0xaa, 0xbb, 0xcc]);
    let view = PacketView::parse(&packet).unwrap();
    let tcp = view.tcp_segment(&packet).unwrap();
    assert_eq!(tcp.source_port, 41000);
    assert_eq!(tcp.destination_port, 443);
    assert_eq!(tcp.sequence, 0x1020_3040);
    assert_eq!(tcp.acknowledgment, 0x5060_7080);
    assert_eq!(tcp.flags, 0x18);
    assert_eq!(tcp.window, 3000);
    assert_eq!(tcp.urgent_pointer, 7);
    assert_eq!(tcp.header_len, 32);
    assert_eq!(tcp.options, 40..52);
    assert_eq!(tcp.payload, 52..55);
}

#[test]
fn tcp_view_rejects_bad_data_offsets_and_non_tcp_packets() {
    let mut packet = ipv4_tcp(&[], &[1]);
    let view = PacketView::parse(&packet).unwrap();
    packet[32] = 0x40;
    assert!(view.tcp_segment(&packet).is_none());

    packet[32] = 0xf0;
    assert!(view.tcp_segment(&packet).is_none());

    let mut udp = vec![0; 28];
    udp[0] = 0x45;
    udp[2..4].copy_from_slice(&28u16.to_be_bytes());
    udp[9] = 17;
    assert!(PacketView::parse(&udp).unwrap().tcp_segment(&udp).is_none());
}
