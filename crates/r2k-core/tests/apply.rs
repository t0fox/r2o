use r2k_core::plan::{EmitKind, OriginalFate, PLAN_MAGIC, PacketInput, Plan};

#[test]
fn no_action_plan_passes_original_and_fake_only_plan_keeps_original() {
    let empty = Plan::parse(&plan(1, 0, &[])).unwrap();
    let input = PacketInput::new(b"plain payload", 100);
    let actions = empty.apply(&input).unwrap();
    assert_eq!(actions.fate, OriginalFate::Pass);
    assert!(actions.emits.is_empty());

    let fake_only = Plan::parse(&plan(
        1,
        2,
        &[
            tlv(0x0010, &[0, 7, b'f']),
            tlv(0x0101, &[0, 7, 0, 0, 2, 0, 0, 0, 0, 5]),
        ],
    ))
    .unwrap();
    let actions = fake_only.apply(&input).unwrap();
    assert_eq!(actions.fate, OriginalFate::Pass);
    assert_eq!(actions.emits.len(), 2);
    assert!(actions.emits.iter().all(|emit| emit.kind == EmitKind::Fake));
    assert_eq!(actions.emits[0].bytes, b"f");
    assert_eq!(actions.emits[0].seq, 100);
    assert_eq!(actions.emits[0].delay_us, 0);
    assert_eq!(actions.emits[1].delay_us, 5);
}

#[test]
fn split_owns_original_and_reverse_order_preserves_sequence_ranges() {
    let split = Plan::parse(&plan(
        1,
        2,
        &[tlv(0x0100, &[0, 1, 0, 0]), tlv(0x0103, &[1])],
    ))
    .unwrap();
    let mut input = PacketInput::new(b"abcdefgh", 100);
    input.have_sni = true;
    input.sni_off = 2;
    input.sni_len = 4;

    let actions = split.apply(&input).unwrap();
    assert_eq!(actions.fate, OriginalFate::Drop);
    assert_eq!(actions.emits.len(), 2);
    assert_eq!(actions.emits[0].bytes, b"cdefgh");
    assert_eq!(actions.emits[0].seq, 102);
    assert_eq!(actions.emits[1].bytes, b"ab");
    assert_eq!(actions.emits[1].seq, 100);
}

#[test]
fn interleaved_fakes_stay_in_place_when_payload_pieces_are_reversed() {
    let plan = Plan::parse(&plan(
        1,
        5,
        &[
            tlv(0x0010, &[0, 7, b'x']),
            tlv(0x0100, &[0, 0, 0, 3]),
            tlv(0x0100, &[0, 0, 0, 6]),
            tlv(0x0101, &[0, 7, 0, 0, 1, 1, 0, 0, 0, 0]),
            tlv(0x0103, &[1]),
        ],
    ))
    .unwrap();
    let actions = plan.apply(&PacketInput::new(b"abcdefgh", 200)).unwrap();

    assert_eq!(actions.fate, OriginalFate::Drop);
    assert_eq!(actions.emits.len(), 5);
    assert_eq!(actions.emits[0].bytes, b"gh");
    assert_eq!(actions.emits[1].kind, EmitKind::Fake);
    assert_eq!(actions.emits[2].bytes, b"def");
    assert_eq!(actions.emits[3].kind, EmitKind::Fake);
    assert_eq!(actions.emits[4].bytes, b"abc");
    assert_eq!(actions.emits[4].seq, 200);
}

#[test]
fn overlay_precedes_payload_and_moves_its_sequence_number_back() {
    let plan = Plan::parse(&plan(
        1,
        3,
        &[
            tlv(0x0010, &[0, 7, 0xaa, 0xbb]),
            tlv(0x0102, &[0, 7, 0, 0]),
            tlv(0x0103, &[0]),
        ],
    ))
    .unwrap();
    let actions = plan.apply(&PacketInput::new(b"body", 50)).unwrap();
    assert_eq!(actions.fate, OriginalFate::Drop);
    assert_eq!(actions.emits.len(), 1);
    assert_eq!(actions.emits[0].prefix, [0xaa, 0xbb]);
    assert_eq!(actions.emits[0].bytes, b"body");
    assert_eq!(actions.emits[0].seq, 48);
}

#[test]
fn own_after_fakes_emits_original_after_fakes_and_drops_queue_copy() {
    let plan = Plan::parse(&plan(
        1,
        2,
        &[
            tlv(0x0010, &[0, 7, b'x']),
            tlv(0x0101, &[0, 7, 0, 0, 1, 0, 0, 0, 0, 0]),
        ],
    ))
    .unwrap();
    let mut input = PacketInput::new(b"original", 90);
    input.own_after_fakes = true;
    let actions = plan.apply(&input).unwrap();
    assert_eq!(actions.fate, OriginalFate::Drop);
    assert_eq!(actions.emits.len(), 2);
    assert_eq!(actions.emits[0].kind, EmitKind::Fake);
    assert_eq!(actions.emits[1].kind, EmitKind::Payload);
    assert_eq!(actions.emits[1].bytes, b"original");
    assert_eq!(actions.emits[1].seq, 90);
}

#[test]
fn sni_middle_anchor_is_clamped_inside_short_payload_and_requires_sni() {
    let plan = Plan::parse(&plan(1, 1, &[tlv(0x0100, &[0, 5, 0, 0])])).unwrap();
    let mut input = PacketInput::new(b"0123456789", 600);
    input.have_sni = true;
    input.sni_off = 1;
    input.sni_len = 1;
    let actions = plan.apply(&input).unwrap();
    assert_eq!(actions.emits[0].bytes, b"01");
    assert_eq!(actions.emits[1].seq, 602);

    input.sni_off = 8;
    input.sni_len = 4;
    let actions = plan.apply(&input).unwrap();
    assert_eq!(actions.emits[0].bytes, b"012345678");
    assert_eq!(actions.emits[1].seq, 609);

    input.have_sni = false;
    assert_eq!(plan.apply(&input).unwrap_err().kind(), "missing-sni");
}

#[test]
fn settle_and_delay_apply_to_the_first_payload_with_delay_taking_precedence() {
    let plan = Plan::parse(&plan(
        6,
        6,
        &[
            tlv(0x0002, &[6, 1]),
            tlv(0x0010, &[0, 7, b'x']),
            tlv(0x0101, &[0, 7, 0, 0, 1, 0, 0, 0, 0, 0]),
            tlv(0x0100, &[0, 0, 0, 3]),
            tlv(0x0107, &[0, 0, 0, 20]),
            tlv(0x010b, &[0, 0, 0, 30]),
        ],
    ))
    .unwrap();
    let actions = plan.apply(&PacketInput::new(b"abcdef", 10)).unwrap();
    assert_eq!(actions.emits.len(), 3);
    assert_eq!(actions.emits[0].kind, EmitKind::Fake);
    assert_eq!(actions.emits[1].bytes, b"abc");
    assert_eq!(actions.emits[1].delay_us, 30);
    assert_eq!(actions.emits[2].bytes, b"def");
    assert_eq!(actions.emits[2].delay_us, 0);
}

#[test]
fn udp_fragment_shape_is_attached_to_the_owned_datagram() {
    let plan = Plan::parse(&plan(7, 2, &[tlv(0x0002, &[17, 2]), tlv(0x010c, &[3])])).unwrap();
    let actions = plan.apply(&PacketInput::new(b"udp payload", 5)).unwrap();
    assert_eq!(actions.fate, OriginalFate::Drop);
    assert_eq!(actions.emits.len(), 1);
    assert_eq!(actions.emits[0].ipfrag, 3);
}

#[test]
fn measured_tcp_input_must_match_and_http_plans_are_separated() {
    let input_guard = Plan::parse(&plan(
        5,
        3,
        &[
            tlv(0x0002, &[6, 1]),
            tlv(0x010a, &[]),
            tlv(0x0100, &[0, 0, 0, 1]),
        ],
    ))
    .unwrap();
    let mut input = PacketInput::new(b"short", 0);
    input.payload = &[0x16, 3, 1, 0, 9, 1, 0, 0, 5, 3, 3, 0, 0, 0, 0];
    assert_eq!(input_guard.apply(&input).unwrap_err().kind(), "tls-input");

    let http = Plan::parse(&plan(11, 1, &[tlv(0x0002, &[6, 4])])).unwrap();
    assert_eq!(
        http.apply(&PacketInput::new(b"GET /", 0))
            .unwrap_err()
            .kind(),
        "http-mismatch"
    );
}

#[test]
fn quic_deny_drops_without_sending_anything() {
    let plan = Plan::parse(&plan(11, 2, &[tlv(0x0002, &[17, 2]), tlv(0x0110, &[1])])).unwrap();
    let actions = plan.apply(&PacketInput::new(b"initial", 10)).unwrap();
    assert_eq!(actions.fate, OriginalFate::Drop);
    assert!(actions.emits.is_empty());
}

#[test]
fn quic_split_reseals_initial_and_replaces_original_datagram() {
    let source = include_bytes!("fixtures/quic_v1_initial.bin");
    let split_plan =
        Plan::parse(&plan(10, 2, &[tlv(0x0002, &[17, 2]), tlv(0x010f, &[1])])).unwrap();
    let expected = r2k_core::quic::initial_split_crypto(source).unwrap();
    let actions = split_plan.apply(&PacketInput::new(source, 0)).unwrap();

    assert_eq!(actions.fate, OriginalFate::Drop);
    assert_eq!(actions.emits.len(), 1);
    assert_eq!(actions.emits[0].kind, EmitKind::Payload);
    assert_eq!(actions.emits[0].bytes, expected);
    assert_eq!(actions.emits[0].bytes.len(), source.len());
    assert_eq!(source[0], 0xc0);
}

#[test]
fn udp_lengthening_copies_payload_and_appends_zero_bytes() {
    let plan = Plan::parse(&plan(9, 2, &[tlv(0x0002, &[17, 2]), tlv(0x010e, &[0, 3])])).unwrap();
    let actions = plan.apply(&PacketInput::new(b"udp", 7)).unwrap();
    assert_eq!(actions.fate, OriginalFate::Drop);
    assert_eq!(actions.emits.len(), 1);
    assert_eq!(actions.emits[0].bytes, b"udp\0\0\0");
}

#[test]
fn tls_fake_modifiers_copy_session_id_randomize_and_keep_repeat_bytes_equal() {
    let template = tls_client_hello();
    let payload_record = [vec![0, 1], template.clone()].concat();
    let plan = Plan::parse(&plan(
        8,
        8,
        &[
            tlv(0x0001, &[0; 16]),
            tlv(0x0002, &[6, 1]),
            tlv(0x0010, &payload_record),
            tlv(0x0011, &[0, 1, 3, 2, 0, 0, 0, 0]),
            tlv(0x0101, &[0, 1, 0, 1, 2, 0, 0, 0, 0, 5, 3]),
            tlv(0x0103, &[0]),
            tlv(0x0109, &[2]),
            tlv(0x010a, &[]),
        ],
    ))
    .unwrap();
    assert_eq!(plan.max_emit(), 171);

    let mut input = PacketInput::new(&template, 500);
    input.have_sni = true;
    input.is_tls13 = true;
    input.sni_off = 20;
    input.sni_len = 8;
    let actions = plan.apply(&input).unwrap();
    assert_eq!(actions.fate, OriginalFate::Pass);
    assert_eq!(actions.emits.len(), 2);
    for emit in &actions.emits {
        assert_eq!(emit.bytes.len(), template.len());
        assert_ne!(&emit.bytes[11..43], &template[11..43]);
        assert_eq!(&emit.bytes[44..76], &template[44..76]);
        assert_eq!(emit.ttl, 3);
        assert_eq!(emit.poison, 2);
    }
    assert_eq!(actions.emits[0].bytes, actions.emits[1].bytes);
    assert_eq!(actions.emits[1].delay_us, 5);
}

#[test]
fn urgent_oob_plan_sends_prefix_urgent_byte_and_suffix() {
    let hello = tls_client_hello();
    let plan = Plan::parse(&plan(
        8,
        4,
        &[
            tlv(0x0002, &[6, 1]),
            tlv(0x0109, &[1]),
            tlv(0x010a, &[]),
            tlv(0x010d, &[0, 5, 0x0f]),
        ],
    ))
    .unwrap();
    let mut input = PacketInput::new(&hello, 700);
    input.have_sni = true;
    input.sni_off = 20;
    input.sni_len = 8;

    let actions = plan.apply(&input).unwrap();
    assert_eq!(actions.fate, OriginalFate::Drop);
    assert_eq!(actions.emits.len(), 3);
    assert_eq!(actions.emits[0].bytes, &hello[..24]);
    assert_eq!(actions.emits[1].bytes, [0x0f]);
    assert!(actions.emits[1].urgent);
    assert_eq!(actions.emits[1].urgent_ptr, 1);
    assert_eq!(actions.emits[1].seq, 724);
    assert_eq!(actions.emits[2].bytes, &hello[24..]);
    assert_eq!(actions.emits[2].seq, 725);
}

#[test]
fn cancellation_drops_only_after_payload_bytes_were_emitted() {
    let plan = Plan::parse(&plan(
        1,
        3,
        &[
            tlv(0x0010, &[0, 1, b'x']),
            tlv(0x0101, &[0, 1, 0, 0, 1, 0, 0, 0, 0, 0]),
            tlv(0x0100, &[0, 0, 0, 1]),
        ],
    ))
    .unwrap();
    let actions = plan.apply(&PacketInput::new(b"hello", 50)).unwrap();
    let before_payload = actions.cancel(1);
    assert!(before_payload.partial);
    assert!(!before_payload.stream_damaged);
    assert_eq!(before_payload.fate, OriginalFate::Pass);
    let after_payload = actions.cancel(2);
    assert!(after_payload.partial);
    assert!(after_payload.stream_damaged);
    assert_eq!(after_payload.fate, OriginalFate::Drop);
}

#[test]
fn route_segment_cap_splits_owned_tcp_payload_without_changing_bytes() {
    let plan = Plan::parse(&plan(
        1,
        3,
        &[
            tlv(0x0002, &[6, 1]),
            tlv(0x0100, &[0, 0, 0, 4]),
            tlv(0x0105, &[0, 0, 0, 7]),
        ],
    ))
    .unwrap();
    let mut input = PacketInput::new(b"abcdefgh", 300);
    input.segment_cap = 3;
    let actions = plan.apply(&input).unwrap();
    assert_eq!(actions.fate, OriginalFate::Drop);
    assert_eq!(actions.emits.len(), 4);
    assert_eq!(actions.emits[0].bytes, b"abc");
    assert_eq!(actions.emits[0].seq, 300);
    assert_eq!(actions.emits[0].delay_us, 0);
    assert_eq!(actions.emits[1].bytes, b"d");
    assert_eq!(actions.emits[1].seq, 303);
    assert_eq!(actions.emits[1].delay_us, 0);
    assert_eq!(actions.emits[2].bytes, b"efg");
    assert_eq!(actions.emits[2].seq, 304);
    assert_eq!(actions.emits[2].delay_us, 7);
    assert_eq!(actions.emits[3].bytes, b"h");
    assert_eq!(actions.emits[3].seq, 307);
    assert_eq!(actions.emits[3].delay_us, 0);
}

fn tlv(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + value.len());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn plan(minexec: u16, count: usize, records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&PLAN_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&minexec.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&(count as u16).to_be_bytes());
    for record in records {
        bytes.extend_from_slice(record);
    }
    bytes
}

fn tls_client_hello() -> Vec<u8> {
    let mut hello = vec![0; 87];
    hello[0] = 0x16;
    hello[1] = 3;
    hello[2] = 1;
    hello[3..5].copy_from_slice(&82_u16.to_be_bytes());
    hello[5] = 1;
    hello[6..9].copy_from_slice(&[0, 0, 78]);
    hello[9] = 3;
    hello[10] = 3;
    for (index, byte) in hello[11..43].iter_mut().enumerate() {
        *byte = 0x40 + index as u8;
    }
    hello[43] = 32;
    for (index, byte) in hello[44..76].iter_mut().enumerate() {
        *byte = 0x80 + index as u8;
    }
    hello[76..84].copy_from_slice(&[0, 2, 0x13, 1, 1, 0, 0, 0]);
    hello
}
