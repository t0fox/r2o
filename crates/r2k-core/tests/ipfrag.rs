use r2k_core::{
    plan::{Emission, EmitKind},
    wire,
};

fn original_v4(payload_len: usize) -> Vec<u8> {
    let total_len = 20 + 8 + payload_len;
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[1] = 0xa5;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    packet[8] = 57;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
    packet[20..22].copy_from_slice(&51234u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    for (index, byte) in packet[28..].iter_mut().enumerate() {
        *byte = index as u8;
    }
    packet
}

fn original_v6(payload_len: usize) -> Vec<u8> {
    let udp_len = 8 + payload_len;
    let mut packet = vec![0; 40 + udp_len];
    packet[0] = 0x6a;
    packet[1] = 0xb1;
    packet[2] = 0x23;
    packet[3] = 0x45;
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 57;
    packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    packet[40..42].copy_from_slice(&51234u16.to_be_bytes());
    packet[42..44].copy_from_slice(&443u16.to_be_bytes());
    packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    for (index, byte) in packet[48..].iter_mut().enumerate() {
        *byte = index as u8;
    }
    packet
}

fn emission(payload_len: usize, shape: u8) -> Emission {
    Emission {
        kind: EmitKind::Payload,
        delay_us: 0,
        seq: 0,
        ttl: 0,
        poison: 0,
        seq_shift: 0,
        wire_profile: 0,
        ipfrag: shape,
        urgent: false,
        urgent_ptr: 0,
        prefix: Vec::new(),
        bytes: (0..payload_len).map(|index| index as u8).collect(),
    }
}

fn checksum_sum(bytes: &[u8], mut sum: u64) -> u64 {
    for pair in bytes.chunks(2) {
        sum += u64::from(pair[0]) << 8;
        if let Some(low) = pair.get(1) {
            sum += u64::from(*low);
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn expected_offsets(shape: u8) -> &'static [usize] {
    match shape {
        1 => &[0, 8],
        2 => &[8, 0],
        3 => &[24, 8, 0],
        4 => &[40, 8, 0],
        _ => unreachable!(),
    }
}

fn expected_fragment_lengths(shape: u8) -> &'static [usize] {
    match shape {
        1 => &[8, 1200],
        2 => &[1200, 8],
        3 => &[1184, 24, 8],
        4 => &[1168, 40, 16],
        _ => unreachable!(),
    }
}

#[test]
fn ipv4_quic_fragment_shapes_preserve_udp_datagram_and_donor_order() {
    for shape in 1..=4 {
        let original = original_v4(1200);
        let emitted = emission(1200, shape);
        let fragments = wire::build_udp_fragments(&original, &emitted).unwrap();
        let expected = expected_offsets(shape);
        let expected_lengths = expected_fragment_lengths(shape);
        assert_eq!(fragments.len(), expected.len());

        let id = u16::from_be_bytes(fragments[0][4..6].try_into().unwrap());
        assert_ne!(id, 0);
        let mut restored = vec![0; 1208];
        for ((fragment, expected_offset), expected_len) in
            fragments.iter().zip(expected).zip(expected_lengths)
        {
            assert_eq!(fragment[1], 0xa5);
            assert_eq!(fragment[8], 57);
            assert_eq!(fragment[9], 17);
            assert_eq!(&fragment[12..20], &original[12..20]);
            assert_eq!(u16::from_be_bytes(fragment[4..6].try_into().unwrap()), id);
            assert_eq!(checksum_sum(&fragment[..20], 0), 0xffff);

            let field = u16::from_be_bytes(fragment[6..8].try_into().unwrap());
            let offset = usize::from(field & 0x1fff) * 8;
            assert_eq!(offset, *expected_offset);
            let logical_index = match shape {
                1 => usize::from(offset != 0),
                2 => usize::from(offset != 0),
                3 => [0, 8, 24]
                    .iter()
                    .position(|value| *value == offset)
                    .unwrap(),
                4 => [0, 8, 40]
                    .iter()
                    .position(|value| *value == offset)
                    .unwrap(),
                _ => unreachable!(),
            };
            assert_eq!(field & 0x2000 != 0, logical_index + 1 < expected.len());
            let data = &fragment[20..];
            assert_eq!(data.len(), *expected_len);
            restored[offset..offset + data.len()].copy_from_slice(data);
        }

        assert_eq!(&restored[..2], &51234u16.to_be_bytes());
        assert_eq!(&restored[2..4], &443u16.to_be_bytes());
        assert_eq!(&restored[4..6], &1208u16.to_be_bytes());
        assert_eq!(
            checksum_sum(&original[12..20], checksum_sum(&restored, 17 + 1208)),
            0xffff
        );
        assert_eq!(&restored[8..], &emitted.bytes);
    }
}

#[test]
fn ipv6_quic_fragment_shapes_use_rfc_offsets_and_preserve_udp_datagram() {
    for shape in 1..=4 {
        let original = original_v6(1200);
        let emitted = emission(1200, shape);
        let fragments = wire::build_udp_fragments(&original, &emitted).unwrap();
        let expected = expected_offsets(shape);
        let expected_lengths = expected_fragment_lengths(shape);
        assert_eq!(fragments.len(), expected.len());

        let id = &fragments[0][44..48];
        assert_ne!(id, &[0, 0, 0, 0]);
        let mut restored = vec![0; 1208];
        for ((fragment, expected_offset), expected_len) in
            fragments.iter().zip(expected).zip(expected_lengths)
        {
            assert_eq!(&fragment[..4], &original[..4]);
            assert_eq!(fragment[6], 44);
            assert_eq!(fragment[7], 57);
            assert_eq!(&fragment[8..40], &original[8..40]);
            assert_eq!(fragment[40], 17);
            assert_eq!(&fragment[44..48], id);

            let field = u16::from_be_bytes(fragment[42..44].try_into().unwrap());
            let offset = usize::from(field & 0xfff8);
            assert_eq!(offset, *expected_offset);
            let logical_index = match shape {
                1 => usize::from(offset != 0),
                2 => usize::from(offset != 0),
                3 => [0, 8, 24]
                    .iter()
                    .position(|value| *value == offset)
                    .unwrap(),
                4 => [0, 8, 40]
                    .iter()
                    .position(|value| *value == offset)
                    .unwrap(),
                _ => unreachable!(),
            };
            assert_eq!(field & 1 != 0, logical_index + 1 < expected.len());
            let data = &fragment[48..];
            assert_eq!(data.len(), *expected_len);
            restored[offset..offset + data.len()].copy_from_slice(data);
        }

        assert_eq!(&restored[..2], &51234u16.to_be_bytes());
        assert_eq!(&restored[2..4], &443u16.to_be_bytes());
        assert_eq!(&restored[4..6], &1208u16.to_be_bytes());
        let mut pseudo = Vec::from(&original[8..40]);
        pseudo.extend_from_slice(&1208u32.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        assert_eq!(checksum_sum(&restored, checksum_sum(&pseudo, 0)), 0xffff);
        assert_eq!(&restored[8..], &emitted.bytes);
    }
}

#[test]
fn udp_fragment_builder_rejects_invalid_shape_and_inapplicable_emission() {
    let original = original_v4(16);
    assert!(wire::build_udp_fragments(&original, &emission(16, 0)).is_none());
    assert!(wire::build_udp_fragments(&original, &emission(16, 5)).is_none());

    let mut invalid = emission(16, 1);
    invalid.poison = 1;
    assert!(wire::build_udp_fragments(&original, &invalid).is_none());
}
