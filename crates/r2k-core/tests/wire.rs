use r2k_core::{
    plan::{
        Emission, EmitKind, POISON_BADSUM, POISON_IPID_ZERO, POISON_MD5, POISON_TCPTS_BACK,
        WIRE_DETECT_TCP, WIRE_TCP_TEMPLATE,
    },
    wire,
};

const GOLDEN_CLEAN: [u8; 45] = [
    0x45, 0x00, 0x00, 0x2d, 0x10, 0x01, 0x40, 0x00, 0x40, 0x06, 0x64, 0xd9, 0xc0, 0xa8, 0x01, 0x43,
    0x01, 0x02, 0x03, 0x04, 0x9c, 0x40, 0x01, 0xbb, 0x00, 0x00, 0x03, 0xe8, 0x11, 0x22, 0x33, 0x44,
    0x50, 0x18, 0xfa, 0xf0, 0x59, 0xfe, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x11,
];

fn original_v4(options: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 20 + 20 + options.len()];
    packet[0] = 0x45;
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[4..6].copy_from_slice(&0x1000u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[192, 168, 1, 67]);
    packet[16..20].copy_from_slice(&[1, 2, 3, 4]);
    let tcp = 20;
    packet[tcp..tcp + 2].copy_from_slice(&40000u16.to_be_bytes());
    packet[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
    packet[tcp + 8..tcp + 12].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[tcp + 12] = (((20 + options.len()) / 4) as u8) << 4;
    packet[tcp + 13] = 0x10;
    packet[tcp + 14..tcp + 16].copy_from_slice(&64240u16.to_be_bytes());
    packet[tcp + 20..].copy_from_slice(options);
    packet
}

fn original_v6() -> Vec<u8> {
    let mut packet = vec![0; 60];
    packet[0] = 0x6a;
    packet[1] = 0xb1;
    packet[2] = 0x23;
    packet[3] = 0x45;
    packet[4..6].copy_from_slice(&20u16.to_be_bytes());
    packet[6] = 6;
    packet[7] = 32;
    packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    packet[40..42].copy_from_slice(&5555u16.to_be_bytes());
    packet[42..44].copy_from_slice(&443u16.to_be_bytes());
    packet[48..52].copy_from_slice(&0x0102_0304u32.to_be_bytes());
    packet[52] = 0x50;
    packet[53] = 0x10;
    packet[54..56].copy_from_slice(&4096u16.to_be_bytes());
    packet
}

fn emission(bytes: &[u8]) -> Emission {
    Emission {
        kind: EmitKind::Payload,
        delay_us: 0,
        seq: 1000,
        ttl: 0,
        poison: 0,
        seq_shift: 0,
        wire_profile: 0,
        ipfrag: 0,
        urgent: false,
        urgent_ptr: 0,
        prefix: Vec::new(),
        bytes: bytes.to_vec(),
    }
}

fn build(input: &[u8], emitted: &Emission) -> Option<Vec<u8>> {
    let mut out = [0; 256];
    let len = wire::build_tcp_packet(input, emitted, &mut out)?;
    Some(out[..len].to_vec())
}

#[test]
fn clean_ipv4_matches_the_r2o_golden_packet() {
    let packet = original_v4(&[]);
    let emitted = emission(&[0xde, 0xad, 0xbe, 0xef, 0x11]);
    let built = build(&packet, &emitted).unwrap();
    assert_eq!(built, GOLDEN_CLEAN);
    assert!(wire::tcp_checksum_ok(&built));
}

#[test]
fn legacy_timestamp_poison_adds_a_valid_tcp_option() {
    let packet = original_v4(&[]);
    let mut emitted = emission(&[1, 2, 3]);
    emitted.poison = POISON_TCPTS_BACK;
    let built = build(&packet, &emitted).unwrap();
    assert_eq!(built[32] >> 4, 8);
    assert_eq!(&built[40..52], &[1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(wire::tcp_checksum_ok(&built));
}

#[test]
fn template_profile_preserves_options_and_shifts_timestamp_only_on_fake() {
    let options = [1, 1, 8, 10, 0, 0, 0x13, 0x88, 0, 0, 0x23, 0x28];
    let packet = original_v4(&options);
    let mut emitted = emission(&[0x16, 3]);
    emitted.wire_profile = WIRE_TCP_TEMPLATE;
    emitted.kind = EmitKind::Fake;
    emitted.poison = POISON_TCPTS_BACK;
    let built = build(&packet, &emitted).unwrap();
    assert_eq!(
        &built[40..52],
        &[1, 1, 8, 10, 0, 0, 0x0f, 0xa0, 0, 0, 0x23, 0x28]
    );
    assert!(wire::tcp_checksum_ok(&built));

    emitted.kind = EmitKind::Payload;
    emitted.poison = 0;
    let built = build(&packet, &emitted).unwrap();
    assert_eq!(&built[40..52], &options);
}

#[test]
fn malformed_inputs_and_inapplicable_emissions_fail_closed() {
    let packet = original_v4(&[]);
    let mut emitted = emission(&[0x0f]);
    emitted.urgent = true;
    emitted.urgent_ptr = 2;
    assert!(build(&packet, &emitted).is_none());

    emitted.urgent = false;
    emitted.urgent_ptr = 0;
    emitted.ipfrag = 1;
    assert!(build(&packet, &emitted).is_none());

    emitted.ipfrag = 0;
    assert!(build(&packet[..39], &emitted).is_none());
}

#[test]
fn bad_checksum_poison_is_deterministic_and_really_invalid() {
    let packet = original_v4(&[]);
    let mut emitted = emission(&[0xde, 0xad, 0xbe, 0xef, 0x11]);
    emitted.poison = POISON_BADSUM;
    let first = build(&packet, &emitted).unwrap();
    let second = build(&packet, &emitted).unwrap();
    assert_eq!(first, second);
    assert!(!wire::tcp_checksum_ok(&first));
}

#[test]
fn measured_profile_sets_measured_headers_and_md5_options() {
    let packet = original_v4(&[]);
    let mut emitted = emission(&[0x16, 3]);
    emitted.wire_profile = WIRE_DETECT_TCP;
    emitted.poison = POISON_MD5;
    let built = build(&packet, &emitted).unwrap();
    assert_eq!(built[6..8], [0, 0]);
    assert_eq!(built[8], 64);
    assert_eq!(&built[34..36], &u16::MAX.to_be_bytes());
    assert_eq!(built[32] >> 4, 10);
    assert_eq!(&built[40..42], &[19, 18]);
    assert!(built[42..58].iter().all(|&byte| byte == 0));
    assert_eq!(&built[58..60], &[1, 1]);
    assert_eq!(&built[60..62], &[0x16, 3]);
    assert_ne!(&built[4..6], &[0xff, 0xff]);
    assert!(wire::tcp_checksum_ok(&built));

    emitted.ttl = 3;
    emitted.poison |= POISON_IPID_ZERO;
    let built = build(&packet, &emitted).unwrap();
    assert_eq!(built[4..6], [0, 0]);
    assert_eq!(built[8], 3);
}

#[test]
fn urgent_prefix_and_wrapping_sequence_are_serialized() {
    let packet = original_v4(&[]);
    let mut emitted = emission(&[0x0f]);
    emitted.seq = u32::MAX;
    emitted.seq_shift = 2;
    emitted.prefix = vec![0xaa, 0xbb];
    emitted.urgent = true;
    emitted.urgent_ptr = 1;
    let built = build(&packet, &emitted).unwrap();
    assert_eq!(&built[24..28], &1u32.to_be_bytes());
    assert_eq!(built[33], 0x38);
    assert_eq!(&built[38..40], &1u16.to_be_bytes());
    assert_eq!(&built[40..43], &[0xaa, 0xbb, 0x0f]);
    assert!(wire::tcp_checksum_ok(&built));
}

#[test]
fn native_timestamp_poison_requires_a_valid_timestamp_option() {
    let packet = original_v4(&[1, 1, 2, 4]);
    let mut emitted = emission(&[0x16]);
    emitted.wire_profile = WIRE_TCP_TEMPLATE;
    emitted.poison = POISON_TCPTS_BACK;
    assert!(build(&packet, &emitted).is_none());

    let packet = original_v4(&[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
    assert!(build(&packet, &emitted).is_some());
}

#[test]
fn ipv6_preserves_class_label_addresses_and_valid_checksum() {
    let packet = original_v6();
    let mut emitted = emission(&[0xa0]);
    emitted.seq = 0xfedc_ba98;
    let built = build(&packet, &emitted).unwrap();
    assert_eq!(built.len(), 61);
    assert_eq!(&built[..4], &[0x6a, 0xb1, 0x23, 0x45]);
    assert_eq!(&built[8..24], &packet[8..24]);
    assert_eq!(&built[24..40], &packet[24..40]);
    assert_eq!(&built[40..44], &packet[40..44]);
    assert_eq!(&built[44..48], &0xfedc_ba98u32.to_be_bytes());
    assert_eq!(built[7], 32);
    assert!(wire::tcp_checksum_ok(&built));
}

#[test]
fn output_capacity_failure_does_not_partially_write_a_packet() {
    let packet = original_v4(&[]);
    let emitted = emission(&[1, 2, 3, 4, 5]);
    let mut out = [0xa5; 44];
    assert!(wire::build_tcp_packet(&packet, &emitted, &mut out).is_none());
    assert_eq!(out, [0xa5; 44]);
}
