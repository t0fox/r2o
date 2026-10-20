use r2k_core::dns::{DNS_RESOLVERS, DnsProvider};
use r2k_core::dns::{DnsError, build_a_query, parse_a_reply};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

fn answer_header(query: &[u8], answers: u16) -> Vec<u8> {
    let mut message = query[..12].to_vec();
    message[2] = 0x81;
    message[3] = 0x80;
    message[6..8].copy_from_slice(&answers.to_be_bytes());
    message.extend_from_slice(&query[12..]);
    message
}

fn push_a(message: &mut Vec<u8>, owner_pointer: u16, address: [u8; 4]) {
    message.extend_from_slice(&owner_pointer.to_be_bytes());
    message.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
    message.extend_from_slice(&address);
}

#[test]
fn builds_a_query_for_the_requested_hostname() {
    let query = build_a_query(0x1234, "instagram.com").unwrap();
    assert_eq!(&query[..6], &[0x12, 0x34, 0x01, 0x00, 0, 1]);
    assert_eq!(
        &query[12..],
        &[
            9, b'i', b'n', b's', b't', b'a', b'g', b'r', b'a', b'm', 3, b'c', b'o', b'm', 0, 0, 1,
            0, 1
        ]
    );
}

#[test]
fn parses_and_deduplicates_a_answers() {
    let query = build_a_query(0x1234, "instagram.com").unwrap();
    let mut message = answer_header(&query, 3);
    push_a(&mut message, 0xc00c, [157, 240, 0, 174]);
    push_a(&mut message, 0xc00c, [57, 144, 248, 34]);
    push_a(&mut message, 0xc00c, [157, 240, 0, 174]);
    assert_eq!(
        parse_a_reply(&message, &query, "instagram.com").unwrap(),
        [
            Ipv4Addr::new(157, 240, 0, 174),
            Ipv4Addr::new(57, 144, 248, 34)
        ]
    );
}

#[test]
fn follows_cname_in_the_same_dns_reply() {
    let query = build_a_query(0x1234, "example.com").unwrap();
    let mut message = answer_header(&query, 2);
    let target_offset = message.len();
    message.extend_from_slice(&0xc00cu16.to_be_bytes());
    message.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 30, 0, 17]);
    message.extend_from_slice(&[
        3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    let target_pointer = 0xc000_u16 | target_offset as u16;
    push_a(&mut message, target_pointer, [203, 0, 113, 9]);
    assert_eq!(
        parse_a_reply(&message, &query, "example.com").unwrap(),
        [Ipv4Addr::new(203, 0, 113, 9)]
    );
}

#[test]
fn rejects_mismatched_truncated_and_forward_pointer_replies() {
    let query = build_a_query(0x1234, "instagram.com").unwrap();
    let mut message = answer_header(&query, 1);
    push_a(&mut message, 0xc00c, [157, 240, 0, 174]);

    let mut wrong_id = message.clone();
    wrong_id[1] ^= 1;
    assert_eq!(
        parse_a_reply(&wrong_id, &query, "instagram.com"),
        Err(DnsError::Mismatch)
    );

    let mut truncated = message.clone();
    truncated[2] |= 2;
    assert_eq!(
        parse_a_reply(&truncated, &query, "instagram.com"),
        Err(DnsError::Mismatch)
    );

    assert_eq!(
        parse_a_reply(&message[..20], &query, "instagram.com"),
        Err(DnsError::Malformed)
    );

    let mut forward_pointer = answer_header(&query, 1);
    push_a(&mut forward_pointer, 0xc0ff, [157, 240, 0, 174]);
    assert_eq!(
        parse_a_reply(&forward_pointer, &query, "instagram.com"),
        Err(DnsError::Malformed)
    );
}

#[test]
fn configured_resolvers_cover_all_three_requested_providers() {
    let providers = DNS_RESOLVERS
        .iter()
        .map(|resolver| resolver.provider)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        providers,
        BTreeSet::from([
            DnsProvider::WebShift,
            DnsProvider::AstraCat,
            DnsProvider::Mafioznik,
        ])
    );
    assert_eq!(DNS_RESOLVERS.len(), 9);
    assert_eq!(
        DNS_RESOLVERS
            .iter()
            .map(|resolver| resolver.address)
            .collect::<Vec<_>>(),
        vec![
            Ipv4Addr::new(79, 174, 90, 44),
            Ipv4Addr::new(31, 31, 207, 68),
            Ipv4Addr::new(176, 125, 254, 77),
            Ipv4Addr::new(108, 165, 164, 224),
            Ipv4Addr::new(108, 165, 164, 201),
            Ipv4Addr::new(135, 106, 217, 200),
            Ipv4Addr::new(87, 120, 165, 90),
            Ipv4Addr::new(185, 139, 69, 24),
            Ipv4Addr::new(103, 27, 157, 38),
        ]
    );
    assert_eq!(
        DNS_RESOLVERS
            .iter()
            .map(|resolver| resolver.provider.hostname())
            .collect::<Vec<_>>(),
        vec![
            "dns.webshiftvpn.ru",
            "dns.webshiftvpn.ru",
            "dns.astracat.ru",
            "dns.astracat.ru",
            "dns.astracat.ru",
            "dns.astracat.ru",
            "dns.astracat.ru",
            "dns.astracat.ru",
            "dns.mafioznik.xyz",
        ]
    );
}
