use r2k_core::plan::{PLAN_MAGIC, PROTO_HTTP, Plan, WIRE_DETECT_TCP};

#[test]
fn parses_minimal_canonical_plan() {
    assert_eq!(PLAN_MAGIC, *b"R2OP");
    let bytes = plan(1, 1, &[tlv(0x0103, &[0])]);
    let parsed = Plan::parse(&bytes).unwrap();
    assert_eq!(parsed.schema, 1);
    assert_eq!(parsed.minexec, 1);
    assert_eq!(parsed.order, 0);
    assert_eq!(parsed.transport, 0);
    assert_eq!(parsed.id, [0; 16]);
}

#[test]
fn parses_payload_fake_and_cross_references() {
    let bytes = plan(
        1,
        1,
        &[
            tlv(0x0010, &[0, 7, 0xde, 0xad]),
            tlv(0x0101, &[0, 7, 0, 0, 2, 0, 0, 0, 0, 0]),
        ],
    );
    let parsed = Plan::parse(&bytes).unwrap();
    assert_eq!(parsed.payloads.len(), 1);
    assert_eq!(parsed.payloads[0].id, 7);
    assert_eq!(parsed.payloads[0].bytes, [0xde, 0xad]);
    assert_eq!(parsed.fakes.len(), 1);
    assert_eq!(parsed.fakes[0].payload_id, 7);
    assert_eq!(parsed.fakes[0].repeats, 2);
    assert_eq!(parsed.fakes[0].tls_mod, 0);
}

#[test]
fn r2k_quic_ttl_probe_requires_exact_bounded_probe_shape() {
    let mut payload = vec![0, 1];
    payload.extend_from_slice(include_bytes!("../src/quic/quic_ttl_probe.bin"));
    let valid = plan(
        1,
        10,
        &[
            tlv(0x0002, &[17, 2]),
            tlv(0x0010, &payload),
            tlv(0x0011, &[0, 1, 3, 0, 0, 0, 0, 0]),
            tlv(0x0101, &[0, 1, 0, 1, 2, 0, 0, 0, 0, 0]),
        ],
    );
    let parsed = Plan::parse(&valid).unwrap();
    assert!(parsed.r2k_is_quic_ttl_probe());
    assert!(parsed.r2k_is_quic_address_plan());

    let invalid_ttl = plan(
        1,
        10,
        &[
            tlv(0x0002, &[17, 2]),
            tlv(0x0010, &payload),
            tlv(0x0011, &[0, 1, 4, 0, 0, 0, 0, 0]),
            tlv(0x0101, &[0, 1, 0, 1, 2, 0, 0, 0, 0, 0]),
        ],
    );
    let parsed = Plan::parse(&invalid_ttl).unwrap();
    assert!(!parsed.r2k_is_quic_ttl_probe());
    assert!(!parsed.r2k_is_quic_address_plan());
}

#[test]
fn parses_measured_tcp_context_and_wire_contract() {
    let bytes = plan(
        1,
        12,
        &[
            tlv(0x0002, &[6, 1]),
            tlv(0x0106, &[0, 0, 1, 44, 0, 0, 0, 40, 0, 0, 0, 12]),
            tlv(0x0109, &[WIRE_DETECT_TCP]),
            tlv(0x010a, &[]),
            tlv(0x0105, &[0, 0, 0x2e, 0xe0]),
            tlv(0x0107, &[0, 0, 0, 20]),
            tlv(0x0108, &[0, 0, 0x10, 0]),
        ],
    );
    let parsed = Plan::parse(&bytes).unwrap();
    assert_eq!(parsed.transport, 6);
    assert_eq!(parsed.proto, 1);
    assert_eq!(parsed.input_len, 300);
    assert_eq!(parsed.input_sni_off, 40);
    assert_eq!(parsed.input_sni_len, 12);
    assert!(parsed.input_tls);
    assert_eq!(parsed.wire_profile, WIRE_DETECT_TCP);
    assert_eq!(parsed.pace_us, 12_000);
    assert_eq!(parsed.settle_us, 20);
    assert_eq!(parsed.segment_size, 4096);
    assert!(parsed.stream_input());
    assert_eq!(parsed.proto, 1);
}

#[test]
fn permits_http_only_with_tcp_and_executor_version_eleven() {
    let valid = plan(1, 11, &[tlv(0x0002, &[6, PROTO_HTTP])]);
    assert_eq!(Plan::parse(&valid).unwrap().proto, PROTO_HTTP);

    let low_version = plan(1, 10, &[tlv(0x0002, &[6, PROTO_HTTP])]);
    assert!(Plan::parse(&low_version).is_err());
    let udp = plan(1, 11, &[tlv(0x0002, &[17, PROTO_HTTP])]);
    assert!(Plan::parse(&udp).is_err());
}

#[test]
fn rejects_bad_header_lengths_records_and_unknown_versions() {
    let valid = plan(1, 1, &[tlv(0x0103, &[0])]);
    for end in [0, 4, 11, valid.len() - 1] {
        assert!(Plan::parse(&valid[..end]).is_err(), "accepted prefix {end}");
    }

    let mut bad_magic = valid.clone();
    bad_magic[0] = b'X';
    assert!(Plan::parse(&bad_magic).is_err());
    let mut bad_schema = valid.clone();
    bad_schema[5] = 2;
    assert!(Plan::parse(&bad_schema).is_err());
    let mut bad_version = valid.clone();
    bad_version[7] = 13;
    assert!(Plan::parse(&bad_version).is_err());
    let mut bad_flags = valid.clone();
    bad_flags[9] = 1;
    assert!(Plan::parse(&bad_flags).is_err());

    let mismatch = plan(1, 1, &[tlv(0x7777, &[1])]);
    assert!(Plan::parse(&mismatch).is_err());
    let mut bad_length = valid;
    bad_length[15] = 0xff;
    assert!(Plan::parse(&bad_length).is_err());
}

#[test]
fn rejects_dangling_references_and_invalid_operation_combinations() {
    let dangling_fake = plan(1, 1, &[tlv(0x0101, &[0, 7, 0, 0, 1, 0, 0, 0, 0, 0])]);
    assert!(Plan::parse(&dangling_fake).is_err());

    let between_without_split = plan(
        1,
        1,
        &[
            tlv(0x0010, &[0, 7]),
            tlv(0x0101, &[0, 7, 0, 0, 1, 1, 0, 0, 0, 0]),
        ],
    );
    assert!(Plan::parse(&between_without_split).is_err());

    let qdeny_with_payload = plan(
        1,
        11,
        &[
            tlv(0x0002, &[17, 2]),
            tlv(0x0010, &[0, 1]),
            tlv(0x0110, &[1]),
        ],
    );
    assert!(Plan::parse(&qdeny_with_payload).is_err());

    let udp_tls_input = plan(
        1,
        5,
        &[
            tlv(0x0002, &[17, 2]),
            tlv(0x0106, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
        ],
    );
    assert!(Plan::parse(&udp_tls_input).is_err());
}

#[test]
fn declared_record_count_is_exact_and_malformed_bytes_never_panic() {
    let mut count_mismatch = plan(1, 1, &[tlv(0x0103, &[0])]);
    count_mismatch[11] = 2;
    assert!(Plan::parse(&count_mismatch).is_err());

    let mut state = 0x4f1b_bcdd_u32;
    for length in 0..1024 {
        let mut bytes = vec![0; length];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        let _ = Plan::parse(&bytes);
    }
}

fn tlv(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + value.len());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn plan(schema: u16, minexec: u16, records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&PLAN_MAGIC);
    bytes.extend_from_slice(&schema.to_be_bytes());
    bytes.extend_from_slice(&minexec.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&(records.len() as u16).to_be_bytes());
    for record in records {
        bytes.extend_from_slice(record);
    }
    bytes
}
