use r2k_core::addr::Address;
use r2k_core::control::{
    EVENT_CLIENT_SHAPE, EVENT_HELLO, EVENT_HTTP_PORTAL, Frame, HttpPortalEvent, SHAPE_LEGACY,
    SHAPE_MODERN, SHAPE_QUIC, decode_client_shape, decode_hello, decode_http_portal,
};
use r2o_datapath::capture::{TcpFlowKey, quic_hello_from_packet, tcp_hello_from_bytes};

fn decode_profile(profile: &str) -> Vec<u8> {
    let hex: Vec<_> = profile
        .lines()
        .flat_map(|line| line.split('#').next().unwrap_or_default().bytes())
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let (pairs, remainder) = hex.as_slice().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            ((high << 4) | low) as u8
        })
        .collect()
}

fn key() -> TcpFlowKey {
    TcpFlowKey {
        low_address: Address::parse("192.0.2.1").unwrap(),
        high_address: Address::parse("198.51.100.2").unwrap(),
        low_port: 50000,
        high_port: 443,
    }
}

#[test]
fn captured_client_hello_events_keep_tls12_and_tls13_shapes_distinct() {
    let legacy = decode_profile(include_str!("../../r2o-controller/src/profiles/legacy.hex"));
    let modern = decode_profile(include_str!("../../r2o-controller/src/profiles/modern.hex"));

    let legacy_event = tcp_hello_from_bytes(key(), &legacy).unwrap();
    let modern_event = tcp_hello_from_bytes(key(), &modern).unwrap();

    assert_eq!(legacy_event.shape, SHAPE_LEGACY);
    assert_eq!(modern_event.shape, SHAPE_MODERN);
    assert_eq!(legacy_event.host.as_deref(), Some(b"__SNI__".as_slice()));
    assert_eq!(modern_event.host.as_deref(), Some(b"__SNI__".as_slice()));

    let r2o_body = modern_event.event_body();
    assert_eq!(
        usize::from(u16::from_be_bytes(
            r2o_body[r2o_body.len() - 2..].try_into().unwrap()
        )),
        modern.len(),
        "событие должно сообщать длину TLS-записи целиком"
    );

    let decoded = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body: r2o_body,
    })
    .unwrap();
    assert_eq!(decoded.shape, Some(SHAPE_MODERN));
    assert_eq!(decoded.host, modern_event.host);
    assert_eq!(decoded.r2o_wire_len, Some(modern.len()));

    let shape_body = modern_event.shape_event_body().unwrap();
    let shape = decode_client_shape(&Frame {
        kind: EVENT_CLIENT_SHAPE,
        body: shape_body,
    })
    .unwrap();
    assert_eq!(shape.client_hello, modern);
    assert_eq!(shape.host.as_slice(), b"__SNI__");
}

#[test]
fn authenticated_quic_initials_emit_udp_events_with_the_complete_sni() {
    let initial = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
    let packet = ipv4_udp(initial, 443);

    let hello = quic_hello_from_packet(&packet).unwrap();
    assert_eq!(hello.key[0], 4);
    assert_eq!(hello.key[37], 17);
    assert_eq!(hello.host, b"example.com");

    let decoded = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body: hello.event_body().unwrap(),
    })
    .unwrap();
    assert_eq!(decoded.key[37], 17);
    assert_eq!(decoded.host.as_deref(), Some(b"example.com".as_slice()));
    assert_eq!(decoded.shape, Some(SHAPE_QUIC));
    let snapshot =
        r2k_core::quic_snapshot::r2k_quic_snapshot_parse(decoded.quic_snapshot.as_deref().unwrap())
            .unwrap();
    assert_eq!(snapshot.datagrams(), &[initial.as_slice()]);

    let mut corrupted = initial.to_vec();
    corrupted[600] ^= 1;
    assert!(quic_hello_from_packet(&ipv4_udp(&corrupted, 443)).is_none());
    assert!(quic_hello_from_packet(&ipv4_udp(initial, 8443)).is_none());

    let v2 = include_bytes!("../../r2k-core/tests/fixtures/quic_v2_initial.bin");
    let hello6 = quic_hello_from_packet(&ipv6_udp(v2)).unwrap();
    assert_eq!(hello6.key[0], 6);
    assert_eq!(&hello6.key[1..17], &ipv6(1));
    assert_eq!(&hello6.key[17..33], &ipv6(2));
    assert_eq!(hello6.host, b"example.com");
}

#[test]
fn authenticated_quic_initial_without_sni_emits_an_ip_keyed_event() {
    let initial = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial_no_sni.bin");
    let hello = quic_hello_from_packet(&ipv4_udp(initial, 443)).unwrap();
    assert!(hello.host.is_empty());

    let decoded = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body: hello.event_body().unwrap(),
    })
    .unwrap();
    assert_eq!(decoded.host, None);
    assert_eq!(decoded.shape, Some(SHAPE_QUIC));
    assert!(decoded.quic_snapshot.is_some());
}

#[test]
fn quic_event_body_accepts_the_maximum_dns_name_length() {
    let host = vec![b'a'; 253];
    let mut key = [0; r2k_core::control::KEY_LEN];
    key[0] = 4;
    key[37] = 17;
    let hello = r2o_datapath::capture::QuicHello {
        key,
        host: host.clone(),
        snapshot: None,
    };

    let decoded = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body: hello.event_body().unwrap(),
    })
    .unwrap();

    assert_eq!(decoded.host, Some(host));
    assert_eq!(decoded.shape, Some(SHAPE_QUIC));
}

#[test]
fn control_decoder_accepts_http_portal_response_events() {
    let mut flow_key = key();
    flow_key.high_port = 80;
    let portal = HttpPortalEvent {
        key: flow_key.wire_key(),
        answered: false,
        host: b"example.test".to_vec(),
    };
    let decoded = decode_http_portal(&Frame {
        kind: EVENT_HTTP_PORTAL,
        body: portal.event_body().unwrap(),
    })
    .unwrap();

    assert_eq!(decoded.key, portal.key);
    assert!(!decoded.answered);
    assert_eq!(decoded.host, b"example.test");
}

#[test]
fn complete_http_requests_emit_shape_tagged_name_events() {
    let request = b"GET /path HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";
    let mut packet = vec![0; 40 + request.len()];
    packet[0] = 0x45;
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
    packet[20..22].copy_from_slice(&50000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&80_u16.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = 0x18;
    packet[40..].copy_from_slice(request);

    let event = r2o_datapath::capture::tcp_http_hello_from_packet(&packet).unwrap();
    let decoded = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body: event.event_body(),
    })
    .unwrap();

    assert_eq!(event.host.as_deref(), Some(b"example.test".as_slice()));
    assert_eq!(event.shape, r2k_core::control::SHAPE_HTTP);
    assert_eq!(decoded.host, event.host);
    assert_eq!(decoded.shape, Some(r2k_core::control::SHAPE_HTTP));
}

fn ipv4_udp(payload: &[u8], destination_port: u16) -> Vec<u8> {
    let total_len = 28 + payload.len();
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
    packet[20..22].copy_from_slice(&50000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

fn ipv6_udp(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 48 + payload.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&ipv6(1));
    packet[24..40].copy_from_slice(&ipv6(2));
    packet[40..42].copy_from_slice(&50000_u16.to_be_bytes());
    packet[42..44].copy_from_slice(&443_u16.to_be_bytes());
    packet[44..46].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[48..].copy_from_slice(payload);
    packet
}

fn ipv6(last_byte: u8) -> [u8; 16] {
    let mut address = [0; 16];
    address[0..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    address[15] = last_byte;
    address
}
