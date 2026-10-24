use r2k_core::control::{
    HelloEvent, HttpPortalEvent, SHAPE_ECH_TCP, SHAPE_HTTP, SHAPE_LEGACY, SHAPE_MODERN,
};
use r2o_controller::catalog::Catalog;
use r2o_controller::discovery::{DiscoveryTarget, add_measured_binding, has_usable_binding};
use r2o_controller::http_search::{candidate_text, stable_id};

fn hello(host: Option<&str>, family: u8, shape: Option<u8>) -> HelloEvent {
    let mut key = [0; r2k_core::control::KEY_LEN];
    key[0] = family;
    if family == 4 {
        key[1..5].copy_from_slice(&[192, 0, 2, 1]);
        key[17..21].copy_from_slice(&[198, 51, 100, 2]);
    } else {
        key[1..17].copy_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        key[17..33].copy_from_slice(
            &"2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
    }
    key[33..35].copy_from_slice(&50000_u16.to_be_bytes());
    key[35..37].copy_from_slice(&443_u16.to_be_bytes());
    key[37] = 6;
    HelloEvent {
        key,
        host: host.map(|host| host.as_bytes().to_vec()),
        shape,
        r2o_wire_len: None,
        quic_snapshot: None,
        tcp_has_timestamp: None,
    }
}

const PLAN_TEXT: &str =
    "r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +0\n";

#[test]
fn event_target_uses_the_remote_endpoint_and_keeps_tls_shapes_separate() {
    let target =
        DiscoveryTarget::from_event(&hello(Some("Example.Com."), 4, Some(SHAPE_MODERN))).unwrap();

    assert_eq!(target.host, "example.com");
    assert_eq!(target.endpoint, "198.51.100.2:443");
    assert_eq!(target.family, 4);
    assert_eq!(target.shape, SHAPE_MODERN);
}

#[test]
fn событие_выбирает_ech_для_зашифрованной_пробы_clienthello() {
    let target =
        DiscoveryTarget::from_event(&hello(Some("cloudflare-ech.com"), 4, Some(SHAPE_ECH_TCP)))
            .unwrap();

    assert_eq!(target.host, "cloudflare-ech.com");
    assert_eq!(target.shape, SHAPE_ECH_TCP);
}

#[test]
fn discovery_accepts_a_maximum_length_dns_name_from_the_event() {
    let host = format!(
        "{}.{}.{}.{}.com",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(57)
    );
    assert_eq!(host.len(), 253);
    let mut event = hello(None, 4, Some(SHAPE_LEGACY));
    event.host = Some(host.as_bytes().to_vec());

    let target = DiscoveryTarget::from_event(&event).unwrap();

    assert_eq!(target.host, host);
    assert_eq!(target.endpoint, "198.51.100.2:443");
}

#[test]
fn event_target_formats_ipv6_and_skips_unknown_or_non_tls_events() {
    let target =
        DiscoveryTarget::from_event(&hello(Some("example.com"), 6, Some(SHAPE_LEGACY))).unwrap();
    assert_eq!(target.endpoint, "[2001:db8::2]:443");
    assert_eq!(
        DiscoveryTarget::from_event(&hello(Some("example.com"), 4, None)),
        None
    );
    assert_eq!(
        DiscoveryTarget::from_event(&hello(None, 4, Some(SHAPE_MODERN))),
        None
    );
    let mut udp = hello(Some("example.com"), 4, Some(SHAPE_MODERN));
    udp.key[37] = 17;
    assert_eq!(DiscoveryTarget::from_event(&udp), None);
}

#[test]
fn http_portal_target_uses_the_endpoint_on_port_80_and_skips_redirects() {
    let mut key = [0; r2k_core::control::KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 1]);
    key[17..21].copy_from_slice(&[198, 51, 100, 2]);
    key[33..35].copy_from_slice(&80_u16.to_be_bytes());
    key[35..37].copy_from_slice(&50123_u16.to_be_bytes());
    key[37] = 6;
    let portal = HttpPortalEvent {
        key,
        answered: false,
        host: b"Example.Com.".to_vec(),
    };

    let target = DiscoveryTarget::from_http_portal(&portal).unwrap();

    assert_eq!(target.host, "example.com");
    assert_eq!(target.endpoint, "192.0.2.1:80");
    assert_eq!(target.family, 4);
    assert_eq!(target.shape, SHAPE_HTTP);
    let mut redirected = portal;
    redirected.answered = true;
    assert_eq!(DiscoveryTarget::from_http_portal(&redirected), None);
}

#[test]
fn measured_http_plan_is_stored_and_selected_as_an_http_binding() {
    let mut key = [0; r2k_core::control::KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 1]);
    key[17..21].copy_from_slice(&[198, 51, 100, 2]);
    key[33..35].copy_from_slice(&50_123_u16.to_be_bytes());
    key[35..37].copy_from_slice(&80_u16.to_be_bytes());
    key[37] = 6;
    let event = HttpPortalEvent {
        key,
        answered: false,
        host: b"example.com".to_vec(),
    };
    let target = DiscoveryTarget::from_http_portal(&event).unwrap();
    let id = stable_id("split");
    let plan = candidate_text("split", Some(&id)).unwrap();
    let mut catalog = Catalog::default();

    add_measured_binding(&mut catalog, &target, &plan, 1_800_000_000).unwrap();

    assert!(has_usable_binding(&catalog, &target));
    assert_eq!(catalog.boxes[0].plans[0].proto, "http");
    assert_eq!(catalog.boxes[0].bindings[0].shape, SHAPE_HTTP);
    assert!(catalog.domain_state.is_none());
}

#[test]
fn measured_plan_is_stored_with_a_shape_specific_binding_and_group_evidence() {
    let target =
        DiscoveryTarget::from_event(&hello(Some("example.com"), 4, Some(SHAPE_MODERN))).unwrap();
    let mut catalog = Catalog::default();

    let id = add_measured_binding(&mut catalog, &target, PLAN_TEXT, 1_800_000_000).unwrap();

    assert!(has_usable_binding(&catalog, &target));
    assert_eq!(catalog.boxes.len(), 1);
    assert_eq!(catalog.boxes[0].plans.len(), 1);
    assert_eq!(catalog.boxes[0].plans[0].id, id);
    assert!(catalog.boxes[0].plans[0].text.contains(&format!("id {id}")));
    assert_eq!(catalog.boxes[0].bindings.len(), 1);
    assert_eq!(catalog.boxes[0].bindings[0].family, 4);
    assert_eq!(catalog.boxes[0].bindings[0].shape, SHAPE_MODERN);
    let state = catalog.domain_state.as_ref().unwrap();
    assert_eq!(state.observations.len(), 1);
    assert_eq!(state.observations[0].evidence, 1);

    let persisted = catalog.to_json_at(1_800_000_000).unwrap();
    let restored = Catalog::parse(persisted.as_bytes()).unwrap();
    assert!(has_usable_binding(&restored, &target));
}

#[test]
fn repeated_measurement_updates_one_binding_and_keeps_other_shapes_independent() {
    let modern =
        DiscoveryTarget::from_event(&hello(Some("example.com"), 4, Some(SHAPE_MODERN))).unwrap();
    let legacy =
        DiscoveryTarget::from_event(&hello(Some("example.com"), 4, Some(SHAPE_LEGACY))).unwrap();
    let mut catalog = Catalog::default();

    let modern_id = add_measured_binding(&mut catalog, &modern, PLAN_TEXT, 1_800_000_000).unwrap();
    let same_id = add_measured_binding(&mut catalog, &modern, PLAN_TEXT, 1_800_000_001).unwrap();
    let legacy_id = add_measured_binding(&mut catalog, &legacy, PLAN_TEXT, 1_800_000_002).unwrap();

    assert_eq!(modern_id, same_id);
    assert_ne!(modern_id, legacy_id);
    assert!(has_usable_binding(&catalog, &modern));
    assert!(has_usable_binding(&catalog, &legacy));
    assert_eq!(catalog.boxes.len(), 2);
    assert_eq!(
        catalog
            .boxes
            .iter()
            .map(|record| record.bindings.len())
            .sum::<usize>(),
        2
    );
}

#[test]
fn invalid_discovery_endpoint_does_not_mutate_the_catalog() {
    let mut target =
        DiscoveryTarget::from_event(&hello(Some("example.com"), 4, Some(SHAPE_MODERN))).unwrap();
    target.endpoint = "198.51.100.2:8443".into();
    let mut catalog = Catalog::default();

    assert!(add_measured_binding(&mut catalog, &target, PLAN_TEXT, 1_800_000_000).is_err());
    assert!(catalog.boxes.is_empty());
    assert!(catalog.domain_state.is_none());
}
