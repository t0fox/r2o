use r2k_core::addr::Address;
use r2k_core::control::{EVENT_HELLO, Frame, decode_hello};
use r2o_controller::classify::{Accept, Trigger};
use r2o_controller::hello::{legacy_client_hello, modern_client_hello, r2o_rx_fake_client_hello};
use r2o_datapath::capture::{TcpFlowKey, tcp_hello_from_bytes};

fn assert_lengths_match(hello: &[u8]) {
    assert_eq!(hello[0], 0x16);
    assert_eq!(hello[1], 0x03);
    assert_eq!(
        u16::from_be_bytes([hello[3], hello[4]]) as usize,
        hello.len() - 5
    );
    assert_eq!(hello[5], 0x01);
    let handshake_len =
        (usize::from(hello[6]) << 16) | (usize::from(hello[7]) << 8) | usize::from(hello[8]);
    assert_eq!(handshake_len, hello.len() - 9);
}

#[test]
fn legacy_profile_replaces_sni_and_updates_nested_lengths() {
    for sni in ["youtube.com", "x.io", "video.edge.example.net"] {
        let hello = legacy_client_hello(sni).unwrap();
        assert_lengths_match(&hello);
        assert!(
            hello
                .windows(sni.len())
                .any(|window| window == sni.as_bytes())
        );
        assert!(!hello.windows(7).any(|window| window == b"__SNI__"));
    }
}

#[test]
fn legacy_profile_rejects_empty_nul_and_unrepresentable_sni() {
    assert!(legacy_client_hello("").is_err());
    assert!(legacy_client_hello("bad\0name.example").is_err());
    assert!(legacy_client_hello(&"a".repeat(65_536)).is_err());
}

#[test]
fn legacy_profile_matches_c_reference_byte_for_byte() {
    assert_eq!(
        legacy_client_hello("youtube.com").unwrap(),
        include_bytes!("fixtures/legacy-youtube-c.bin")
    );
}

#[test]
fn modern_profile_replaces_sni_and_preserves_tls13_shape() {
    let hello = modern_client_hello("youtube.com").unwrap();
    let (offset, length) = r2o_controller::hello::sni_bounds(&hello).unwrap();

    assert_eq!(hello.len(), 1530 - 7 + "youtube.com".len());
    assert_eq!(offset, 137);
    assert_eq!(&hello[offset..offset + length], b"youtube.com");
    assert!(r2k_core::tls::parse(&hello).is_tls13);
    assert_eq!(hello, include_bytes!("fixtures/modern-youtube-c.bin"));
}

#[test]
fn r2o_rx_fake_profile_matches_c_reference_byte_for_byte() {
    assert_eq!(
        r2o_rx_fake_client_hello("hcaptcha.com").unwrap(),
        include_bytes!("fixtures/r2o-rx-fake-hcaptcha-c.bin")
    );
    assert_eq!(
        r2o_rx_fake_client_hello("video.edge.example.net").unwrap(),
        include_bytes!("fixtures/r2o-rx-fake-longname-c.bin")
    );
}

#[test]
fn discovery_events_preserve_the_maximum_valid_dns_name() {
    let host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(host.len(), 253);

    let hello = legacy_client_hello(&host).unwrap();
    let key = TcpFlowKey {
        low_address: Address::parse("192.0.2.1").unwrap(),
        high_address: Address::parse("198.51.100.2").unwrap(),
        low_port: 443,
        high_port: 50000,
    };
    let event = tcp_hello_from_bytes(key, &hello).unwrap();
    let decoded = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body: event.event_body(),
    })
    .unwrap();

    assert_eq!(event.host.as_deref(), Some(host.as_bytes()));
    assert_eq!(decoded.host.as_deref(), Some(host.as_bytes()));
}

#[test]
fn tls13_trigger_uses_the_modern_profile() {
    let trigger = Trigger::tls13("youtube.com").unwrap();

    assert_eq!(trigger.name, "tls:youtube.com");
    assert_eq!(trigger.accept, Accept::ServerHello);
    assert_eq!(
        trigger.payload,
        include_bytes!("fixtures/modern-youtube-c.bin")
    );
}
