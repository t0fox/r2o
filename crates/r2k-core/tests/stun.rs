use r2k_core::stun::{
    MappedAddress, is_binding_request, is_discord_ip_discovery_request,
    is_discord_ip_discovery_response, is_discord_voice_request, parse_binding_response,
};

const TXID: [u8; 12] = [
    0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
];

const RESPONSE_V4: &[u8] = &[
    0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
    0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9,
    0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
];

const RESPONSE_V6: &[u8] = &[
    0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa,
    0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9, 0x00, 0x08, 0x00, 0x14,
    0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c, 0x82, 0x92, 0xc2, 0x75,
    0xbf, 0xe3, 0xed, 0x41, 0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb, 0x0b, 0x4c,
];

#[test]
fn parses_rfc5769_xor_mapped_v4_and_v6_addresses() {
    assert_eq!(
        parse_binding_response(RESPONSE_V4, &TXID).unwrap(),
        Some(MappedAddress::V4 {
            address: [192, 0, 2, 1],
            port: 32853,
        })
    );
    assert_eq!(
        parse_binding_response(RESPONSE_V6, &TXID).unwrap(),
        Some(MappedAddress::V6 {
            address: [
                0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77,
            ],
            port: 32853,
        })
    );
}

#[test]
fn rejects_foreign_and_malformed_binding_responses() {
    let mut foreign = TXID;
    foreign[0] ^= 0xff;
    assert!(parse_binding_response(RESPONSE_V4, &foreign).is_err());
    assert!(parse_binding_response(&RESPONSE_V4[..19], &TXID).is_err());

    let mut truncated = RESPONSE_V4.to_vec();
    truncated[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(parse_binding_response(&truncated, &TXID).is_err());

    let mut bare_response = vec![0; 20];
    bare_response[..8].copy_from_slice(&[0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
    bare_response[8..].copy_from_slice(&TXID);
    assert_eq!(parse_binding_response(&bare_response, &TXID).unwrap(), None);

    let mut malformed_address = bare_response;
    malformed_address[2..4].copy_from_slice(&12_u16.to_be_bytes());
    malformed_address.extend_from_slice(&[0, 0x20, 0, 8, 0, 3, 0, 0, 0, 0, 0, 0]);
    assert!(parse_binding_response(&malformed_address, &TXID).is_err());
}

#[test]
fn recognizes_only_discord_ip_discovery_or_media_port_stun() {
    let mut discovery = vec![0; 74];
    discovery[..4].copy_from_slice(&[0, 1, 0, 70]);
    assert!(is_discord_ip_discovery_request(&discovery));
    assert!(is_discord_voice_request(&discovery, 443));

    let mut stun = vec![0; 20];
    stun[..8].copy_from_slice(&[0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
    assert!(is_binding_request(&stun));
    assert!(!is_discord_voice_request(&stun, 3478));
    assert!(is_discord_voice_request(&stun, 50000));
    assert!(is_discord_voice_request(&stun, 50099));
    assert!(!is_discord_voice_request(&stun, 50100));

    discovery[8] = 1;
    assert!(!is_discord_ip_discovery_request(&discovery));
}

fn r2o_discovery_response() -> Vec<u8> {
    let mut r2o_packet = vec![0; 74];
    r2o_packet[..4].copy_from_slice(&[0, 2, 0, 70]);
    r2o_packet[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    r2o_packet[8..20].copy_from_slice(b"203.0.113.7\0");
    r2o_packet[72..74].copy_from_slice(&50_012_u16.to_be_bytes());
    r2o_packet
}

#[test]
fn r2o_discovery_принимает_ответ_с_совпадающим_ssrc_и_адресом_ipv4() {
    assert!(is_discord_ip_discovery_response(
        &r2o_discovery_response(),
        &[0x12, 0x34, 0x56, 0x78],
    ));
}

#[test]
fn r2o_discovery_отвергает_чужой_ssrc_и_неверный_ответ() {
    let r2o_valid = r2o_discovery_response();
    assert!(!is_discord_ip_discovery_response(
        &r2o_valid,
        &[0x12, 0x34, 0x56, 0x79],
    ));

    let mut r2o_bad_address = r2o_valid.clone();
    r2o_bad_address[8..20].copy_from_slice(b"203.0.113.x\0");
    assert!(!is_discord_ip_discovery_response(
        &r2o_bad_address,
        &[0x12, 0x34, 0x56, 0x78],
    ));

    let mut r2o_zero_port = r2o_valid.clone();
    r2o_zero_port[72..74].fill(0);
    assert!(!is_discord_ip_discovery_response(
        &r2o_zero_port,
        &[0x12, 0x34, 0x56, 0x78],
    ));

    let mut r2o_no_terminator = r2o_valid;
    r2o_no_terminator[8..72].fill(b'1');
    assert!(!is_discord_ip_discovery_response(
        &r2o_no_terminator,
        &[0x12, 0x34, 0x56, 0x78],
    ));
}
