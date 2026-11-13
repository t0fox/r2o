use r2k_core::control::{
    AppliedEvent, BindingContext, COMMAND_DEL_ADDR, COMMAND_DEL_ADDR_PROBE, COMMAND_DEL_NAME,
    COMMAND_DEL_NAME_PROBE, COMMAND_SET_ADDR, COMMAND_SET_ADDR_PROBE, COMMAND_SET_HTTPS,
    COMMAND_SET_NAME, COMMAND_SET_NAME_PROBE, COMMAND_SET_TCP_STALL_BUDGETS,
    COMMAND_SET_VOICE_ADDR, COMMAND_SET_VOICE_ADDR_PROBE, EVENT_APPLIED, EVENT_HELLO,
    EVENT_HTTP_RESPONSE, EVENT_R2O_QUIC_STALL, EVENT_R2O_QUIC_SUSPECT, EVENT_R2O_TCP_FIN_RETRY,
    EVENT_R2O_TCP_RST_AFTER_APP, EVENT_R2O_TCP_SILENT, EVENT_R2O_TCP_STALL, EVENT_R2O_VOICE_PROOF,
    EVENT_R2O_VOICE_RTP_PROOF, EVENT_R2O_VOICE_STUN_PROOF, EVENT_R2O_VOICE_SUSPECT, Frame,
    HttpPortalEvent, HttpResponseEvent, KEY_LEN, R2oQuicSuspectEvent, R2oTcpFinRetryEvent,
    R2oTcpRstAfterAppEvent, R2oTcpSilenceEvent, R2oTcpStallEvent, R2oVoiceProofEvent,
    R2oVoiceProofKind, R2oVoiceSuspectEvent, SHAPE_ECH_NO_TS, SHAPE_ECH_TCP, SHAPE_ECH_TS,
    SHAPE_HTTP, SHAPE_LEGACY_NO_TS, SHAPE_LEGACY_TS, SHAPE_MODERN, SHAPE_MODERN_NO_TS,
    SHAPE_MODERN_TS, SHAPE_QUIC, decode_ack, decode_applied, decode_hello, decode_http_response,
    decode_r2o_quic_stall, decode_r2o_quic_suspect, decode_r2o_tcp_fin_retry,
    decode_r2o_tcp_rst_after_app, decode_r2o_tcp_silence, decode_r2o_tcp_stall,
    decode_r2o_voice_proof, decode_r2o_voice_suspect, decode_set_tcp_stall_budgets,
    encode_ack_for_trial, encode_delete_addr, encode_delete_addr_probe, encode_delete_name,
    encode_delete_name_probe, encode_set_addr, encode_set_addr_probe, encode_set_https,
    encode_set_name, encode_set_name_family, encode_set_name_probe, encode_set_tcp_stall_budgets,
    encode_set_voice_addr, encode_set_voice_addr_probe, r2o_binding_equal, read_frame,
};
use std::io::Cursor;

fn r2o_tls_plan_records() -> Vec<u8> {
    let mut plan = b"R2OP".to_vec();
    plan.extend_from_slice(&1_u16.to_be_bytes());
    plan.extend_from_slice(&1_u16.to_be_bytes());
    plan.extend_from_slice(&0_u16.to_be_bytes());
    plan.extend_from_slice(&2_u16.to_be_bytes());
    plan.extend_from_slice(&[0, 1, 0, 16]);
    plan.extend_from_slice(&[0x31; 16]);
    plan.extend_from_slice(&[0, 2, 0, 2, 6, 1]);
    plan
}

fn r2o_quic_plan_records() -> Vec<u8> {
    let mut plan = b"R2OP".to_vec();
    plan.extend_from_slice(&1_u16.to_be_bytes());
    plan.extend_from_slice(&10_u16.to_be_bytes());
    plan.extend_from_slice(&0_u16.to_be_bytes());
    plan.extend_from_slice(&3_u16.to_be_bytes());
    plan.extend_from_slice(&[0, 1, 0, 16]);
    plan.extend_from_slice(&[0x31; 16]);
    plan.extend_from_slice(&[0, 2, 0, 2, 17, 2]);
    plan.extend_from_slice(&[1, 15, 0, 1, 1]);
    plan
}

#[test]
fn d2o_control_frames_match_donor_wire_decoding() {
    let mut output = Vec::new();
    for line in include_str!("fixtures/d2o_control_events.hex").lines() {
        let mut fields = line.split_whitespace();
        let event_kind = fields.next().unwrap();
        let wire_hex = fields.next().unwrap();
        let expected = fields.next().unwrap();
        let wire = (0..wire_hex.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&wire_hex[offset..offset + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let frame = read_frame(&mut Cursor::new(wire)).unwrap();
        if expected.starts_with("REJECT:") {
            assert!(
                decode_applied(&frame).is_err(),
                "shared {event_kind} wire fixture should be rejected"
            );
            output.push(expected.to_owned());
            continue;
        }
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };

        let actual = match event_kind {
            "ACK" => {
                let event = decode_ack(&frame).unwrap();
                let trial_id = event
                    .trial_id
                    .map(|id| hex(&id))
                    .unwrap_or_else(|| "-".to_owned());
                format!(
                    "ACK:{}:{}:{}:{}",
                    event.command,
                    u8::from(event.ok),
                    event.reason,
                    trial_id
                )
            }
            "APPLIED" => {
                let event = decode_applied(&frame).unwrap();
                format!(
                    "APPLIED:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
                    event.key[0],
                    hex(&event.key[1..17]),
                    hex(&event.key[17..33]),
                    u16::from_be_bytes([event.key[33], event.key[34]]),
                    u16::from_be_bytes([event.key[35], event.key[36]]),
                    event.key[37],
                    hex(&event.plan_id),
                    hex(&event.trial_id),
                    event.execution_id,
                    event.binding.generation,
                    event.binding.kind,
                    event.binding.family,
                    event.binding.shape,
                    u8::from(event.binding.temporary),
                    hex(&event.binding.epoch)
                )
            }
            other => panic!("unknown shared d2o control event {other}"),
        };
        assert_eq!(actual, expected, "shared {event_kind} wire fixture");
        output.push(actual);
    }

    if let Ok(path) = std::env::var("R2O_CONTROL_DIFF_OUTPUT") {
        std::fs::write(path, format!("{}\n", output.join("\n"))).unwrap();
    }
}

#[test]
fn кодирует_временную_quic_привязку_к_полному_udp_потоку() {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    let source: SocketAddr = "192.0.2.1:12345".parse().unwrap();
    let destination: SocketAddr = "198.51.100.2:443".parse().unwrap();
    let plan = r2o_quic_plan_records();
    let trial_id = [0xa5; 16];
    let set = read_frame(&mut Cursor::new(
        encode_set_addr_probe(source, destination, 120_000, &plan, trial_id).unwrap(),
    ))
    .unwrap();
    assert_eq!(set.kind, COMMAND_SET_ADDR_PROBE);
    assert_eq!(set.body.len(), KEY_LEN + 20 + plan.len());
    assert_eq!(set.body[0], 4);
    assert_eq!(&set.body[1..5], &[192, 0, 2, 1]);
    assert_eq!(&set.body[5..17], &[0; 12]);
    assert_eq!(&set.body[17..21], &[198, 51, 100, 2]);
    assert_eq!(&set.body[21..33], &[0; 12]);
    assert_eq!(&set.body[33..35], &12345_u16.to_be_bytes());
    assert_eq!(&set.body[35..37], &443_u16.to_be_bytes());
    assert_eq!(set.body[37], 17);
    assert_eq!(&set.body[38..54], &trial_id);
    assert_eq!(&set.body[54..58], &120_000_u32.to_be_bytes());
    assert_eq!(&set.body[58..], plan);

    let remove = read_frame(&mut Cursor::new(
        encode_delete_addr_probe(source, destination, trial_id).unwrap(),
    ))
    .unwrap();
    assert_eq!(remove.kind, COMMAND_DEL_ADDR_PROBE);
    assert_eq!(remove.body.len(), KEY_LEN + 16);
    assert_eq!(&remove.body[..KEY_LEN], &set.body[..KEY_LEN]);
    assert_eq!(&remove.body[KEY_LEN..], &trial_id);

    let ack = encode_ack_for_trial(COMMAND_SET_ADDR_PROBE, true, 0, Some(trial_id)).unwrap();
    let ack = decode_ack(&read_frame(&mut Cursor::new(ack)).unwrap()).unwrap();
    assert_eq!(ack.trial_id, Some(trial_id));

    let source_v6 = SocketAddr::new(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        12345,
    );
    let destination_v6 =
        SocketAddr::new(IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()), 443);
    let set_v6 = read_frame(&mut Cursor::new(
        encode_set_addr_probe(source_v6, destination_v6, 1, &plan, trial_id).unwrap(),
    ))
    .unwrap();
    assert_eq!(set_v6.body[0], 6);
    let std::net::SocketAddr::V6(source_v6) = source_v6 else {
        unreachable!()
    };
    assert_eq!(&set_v6.body[1..17], &source_v6.ip().octets());
    assert_eq!(set_v6.body[37], 17);

    assert!(encode_set_addr_probe(source, destination, 120_001, &plan, trial_id).is_err());
    assert!(encode_set_addr_probe(source, destination, 1, &plan, [0; 16]).is_err());
    // C не сверяет план с формой: чужой план энкодер принимает.
    assert!(
        encode_set_addr_probe(source, destination, 1, &r2o_tls_plan_records(), trial_id).is_ok()
    );
    assert!(encode_delete_addr_probe(source, destination, [0; 16]).is_err());
}

#[test]
fn addr_probe_flow_allows_zero_source_port_and_foreign_plan_like_c() {
    use std::net::SocketAddr;

    let trial = [7; 16];
    let source_zero_port: SocketAddr = "192.0.2.10:0".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let set = read_frame(&mut Cursor::new(
        encode_set_addr_probe(source_zero_port, destination, 1, &[], trial).unwrap(),
    ))
    .unwrap();
    assert_eq!(set.kind, COMMAND_SET_ADDR_PROBE);
    assert_eq!(&set.body[33..35], &[0, 0]);
    assert_eq!(&set.body[35..37], &443_u16.to_be_bytes());

    // C не сверяет план с формой; пустой/чужой план принимается.
    assert!(encode_set_addr_probe(destination, destination, 1, &[0xff], trial).is_ok());
    // dst_port == 0 отвергается.
    let zero_destination: SocketAddr = "198.51.100.20:0".parse().unwrap();
    assert!(encode_set_addr_probe(source_zero_port, zero_destination, 1, &[], trial).is_err());
    assert!(encode_delete_addr_probe(source_zero_port, zero_destination, trial).is_err());

    // Смешанные семейства C допускает: ширина по family источника.
    let source_v4: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let destination_v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    assert!(encode_set_addr_probe(source_v4, destination_v6, 1, &[], trial).is_ok());
    assert!(encode_delete_addr_probe(source_v4, destination_v6, trial).is_ok());

    assert!(encode_set_addr_probe(source_v4, destination, 0, &[], trial).is_err());
    assert!(encode_set_addr_probe(source_v4, destination, 1, &[], [0; 16]).is_err());
}

#[test]
fn arm_shape_accepts_empty_and_255_byte_name_like_c() {
    use r2k_core::control::{decode_arm_shape, encode_arm_shape};

    let frame = read_frame(&mut Cursor::new(encode_arm_shape("", 6, 4).unwrap())).unwrap();
    assert_eq!(frame.body, vec![0, 6, 4]);

    let name = "a".repeat(255);
    let frame = read_frame(&mut Cursor::new(encode_arm_shape(&name, 17, 6).unwrap())).unwrap();
    assert_eq!(frame.body[0], 255);
    assert_eq!(&frame.body[1..256], name.as_bytes());
    assert_eq!(&frame.body[256..258], &[17, 6]);
    assert_eq!(
        decode_arm_shape(&frame).unwrap().name.as_slice(),
        name.as_bytes()
    );

    assert!(encode_arm_shape(&"a".repeat(256), 6, 4).is_err());
}

#[test]
fn кодирует_адресные_планы_ipv4_ipv6_и_удаляет_только_заданную_форму() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let tls_plan = r2o_tls_plan_records();
    let set_v4 = read_frame(&mut Cursor::new(
        encode_set_addr(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            SHAPE_MODERN,
            &tls_plan,
        )
        .unwrap(),
    ))
    .unwrap();
    assert_eq!(set_v4.kind, COMMAND_SET_ADDR);
    assert_eq!(
        &set_v4.body[..18],
        &[
            4,
            198,
            51,
            100,
            20,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            SHAPE_MODERN
        ]
    );
    assert_eq!(&set_v4.body[18..], tls_plan);

    let address_v6 = Ipv6Addr::LOCALHOST;
    let delete_v6 = read_frame(&mut Cursor::new(
        encode_delete_addr(IpAddr::V6(address_v6), SHAPE_ECH_TCP).unwrap(),
    ))
    .unwrap();
    assert_eq!(delete_v6.kind, COMMAND_DEL_ADDR);
    assert_eq!(delete_v6.body.len(), 18);
    assert_eq!(delete_v6.body[0], 6);
    assert_eq!(&delete_v6.body[1..17], &address_v6.octets());
    assert_eq!(delete_v6.body[17], SHAPE_ECH_TCP);

    assert!(encode_set_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), SHAPE_HTTP, &tls_plan).is_err());
    // C `d2k_link_set_addr_family` не сверяет план с формой.
    assert!(encode_set_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), SHAPE_QUIC, &tls_plan).is_ok());
    assert!(encode_delete_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), SHAPE_HTTP).is_err());
}

#[test]
fn addr_commands_accept_tcp_context_shapes_like_c() {
    use std::net::{IpAddr, Ipv4Addr};

    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    for shape in [
        SHAPE_MODERN_NO_TS,
        SHAPE_LEGACY_NO_TS,
        SHAPE_ECH_NO_TS,
        SHAPE_MODERN_TS,
        SHAPE_LEGACY_TS,
        SHAPE_ECH_TS,
    ] {
        assert!(encode_set_addr(v4, shape, &[]).is_ok(), "set {shape}");
        assert!(encode_delete_addr(v4, shape).is_ok(), "del {shape}");
    }
    // C не сверяет план с формой; чужой/пустой план принимается.
    assert!(encode_set_addr(v4, SHAPE_MODERN, &[0xff, 0x00]).is_ok());
    assert!(encode_delete_addr(v4, 0).is_err());
}

#[test]
fn событие_зависшего_tcp_потока_кодируется_и_строго_проверяется() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    key[17..21].copy_from_slice(&[198, 51, 100, 20]);
    key[33..35].copy_from_slice(&50000_u16.to_be_bytes());
    key[35..37].copy_from_slice(&443_u16.to_be_bytes());
    key[37] = 6;
    let event = R2oTcpStallEvent {
        key,
        client_is_low: true,
        elapsed_ms: 2_500,
        estimated_packets: 25,
        planned: true,
    };
    let frame = Frame {
        kind: EVENT_R2O_TCP_STALL,
        body: event.event_body().unwrap(),
    };
    assert_eq!(decode_r2o_tcp_stall(&frame).unwrap(), event);

    let mut invalid = frame;
    invalid.body[KEY_LEN + 9] = 2;
    assert!(decode_r2o_tcp_stall(&invalid).is_err());
}

#[test]
fn бюджеты_tcp_кодируются_и_проверяются_включая_сброс_по_умолчанию() {
    let encoded = encode_set_tcp_stall_budgets(&[25, 17, 41]).unwrap();
    let frame = read_frame(&mut Cursor::new(encoded)).unwrap();
    assert_eq!(frame.kind, COMMAND_SET_TCP_STALL_BUDGETS);
    assert_eq!(decode_set_tcp_stall_budgets(&frame).unwrap(), [25, 17, 41]);

    let reset = read_frame(&mut Cursor::new(encode_set_tcp_stall_budgets(&[]).unwrap())).unwrap();
    assert!(decode_set_tcp_stall_budgets(&reset).unwrap().is_empty());
    assert!(encode_set_tcp_stall_budgets(&[0]).is_err());
    assert!(encode_set_tcp_stall_budgets(&[1; 9]).is_err());

    let mut malformed = frame;
    malformed.body[0] = 2;
    assert!(decode_set_tcp_stall_budgets(&malformed).is_err());
    let mut zero = read_frame(&mut Cursor::new(
        encode_set_tcp_stall_budgets(&[25]).unwrap(),
    ))
    .unwrap();
    zero.body[1..3].copy_from_slice(&0_u16.to_be_bytes());
    assert!(decode_set_tcp_stall_budgets(&zero).is_err());
}

#[test]
fn событие_повтора_fin_tcp_кодируется_и_строго_проверяется() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    key[17..21].copy_from_slice(&[198, 51, 100, 20]);
    key[33..35].copy_from_slice(&50000_u16.to_be_bytes());
    key[35..37].copy_from_slice(&443_u16.to_be_bytes());
    key[37] = 6;
    let event = R2oTcpFinRetryEvent {
        key,
        client_is_low: true,
        planned: false,
    };
    let frame = Frame {
        kind: EVENT_R2O_TCP_FIN_RETRY,
        body: event.event_body().unwrap(),
    };
    assert_eq!(decode_r2o_tcp_fin_retry(&frame).unwrap(), event);

    let planned = R2oTcpFinRetryEvent {
        planned: true,
        ..event.clone()
    };
    let planned_frame = Frame {
        kind: EVENT_R2O_TCP_FIN_RETRY,
        body: planned.event_body().unwrap(),
    };
    assert_eq!(decode_r2o_tcp_fin_retry(&planned_frame).unwrap(), planned);

    let mut invalid = frame;
    invalid.body[KEY_LEN] = 2;
    assert!(decode_r2o_tcp_fin_retry(&invalid).is_err());

    let mut invalid = event.event_body().unwrap();
    invalid[KEY_LEN + 1] = 2;
    assert!(
        decode_r2o_tcp_fin_retry(&Frame {
            kind: EVENT_R2O_TCP_FIN_RETRY,
            body: invalid,
        })
        .is_err()
    );
}

#[test]
fn событие_rst_после_tls_app_data_кодируется_и_строго_проверяется() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    key[17..21].copy_from_slice(&[198, 51, 100, 20]);
    key[33..35].copy_from_slice(&50000_u16.to_be_bytes());
    key[35..37].copy_from_slice(&443_u16.to_be_bytes());
    key[37] = 6;
    let event = R2oTcpRstAfterAppEvent {
        key,
        client_is_low: true,
        planned: true,
    };
    let frame = Frame {
        kind: EVENT_R2O_TCP_RST_AFTER_APP,
        body: event.event_body().unwrap(),
    };
    assert_eq!(decode_r2o_tcp_rst_after_app(&frame).unwrap(), event);

    let mut invalid = frame;
    invalid.body[KEY_LEN + 1] = 2;
    assert!(decode_r2o_tcp_rst_after_app(&invalid).is_err());
}

#[test]
fn событие_голосового_потока_кодируется_и_строго_проверяется() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    key[17..21].copy_from_slice(&[198, 51, 100, 20]);
    key[33..35].copy_from_slice(&50000_u16.to_be_bytes());
    key[35..37].copy_from_slice(&50004_u16.to_be_bytes());
    key[37] = 17;
    let event = R2oVoiceSuspectEvent {
        key,
        client_is_low: true,
    };
    let frame = Frame {
        kind: EVENT_R2O_VOICE_SUSPECT,
        body: event.event_body().unwrap(),
    };
    assert_eq!(decode_r2o_voice_suspect(&frame).unwrap(), event);

    let mut invalid_direction = frame.clone();
    invalid_direction.body[KEY_LEN] = 2;
    assert!(decode_r2o_voice_suspect(&invalid_direction).is_err());

    let mut invalid_transport = frame.clone();
    invalid_transport.body[37] = 6;
    assert!(decode_r2o_voice_suspect(&invalid_transport).is_err());

    let mut invalid_family = frame;
    invalid_family.body[0] = 6;
    assert!(decode_r2o_voice_suspect(&invalid_family).is_err());
}

#[test]
fn событие_молчания_quic_строго_проверяет_ipv6_ключ() {
    let mut key = [0; KEY_LEN];
    key[0] = 6;
    key[1..17].copy_from_slice(
        &"2001:db8::10"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    key[17..33].copy_from_slice(
        &"2001:db8::20"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    key[33..35].copy_from_slice(&53_123_u16.to_be_bytes());
    key[35..37].copy_from_slice(&443_u16.to_be_bytes());
    key[37] = 17;
    let event = R2oQuicSuspectEvent {
        key,
        client_is_low: true,
        planned: false,
    };
    let frame = Frame {
        kind: EVENT_R2O_QUIC_SUSPECT,
        body: event.event_body().unwrap(),
    };
    assert_eq!(decode_r2o_quic_suspect(&frame).unwrap(), event);

    let mut invalid_direction = frame.clone();
    invalid_direction.body[KEY_LEN] = 2;
    assert!(decode_r2o_quic_suspect(&invalid_direction).is_err());

    let mut invalid_transport = frame;
    invalid_transport.body[37] = 6;
    assert!(decode_r2o_quic_suspect(&invalid_transport).is_err());
}

#[test]
fn r2o_событие_quic_зависания_проверяет_ключ_и_направление() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    key[17..21].copy_from_slice(&[198, 51, 100, 20]);
    key[33..35].copy_from_slice(&53_123_u16.to_be_bytes());
    key[35..37].copy_from_slice(&443_u16.to_be_bytes());
    key[37] = 17;
    let event = R2oQuicSuspectEvent {
        key,
        client_is_low: true,
        planned: true,
    };
    let frame = Frame {
        kind: EVENT_R2O_QUIC_STALL,
        body: event.event_body().unwrap(),
    };
    assert_eq!(decode_r2o_quic_stall(&frame).unwrap(), event);
    assert!(decode_r2o_quic_suspect(&frame).is_err());
}

#[test]
fn r2o_событие_молчания_tcp_проверяет_ключ_направление_и_интервал() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    key[17..21].copy_from_slice(&[198, 51, 100, 20]);
    key[33..35].copy_from_slice(&41000_u16.to_be_bytes());
    key[35..37].copy_from_slice(&443_u16.to_be_bytes());
    key[37] = 6;
    let event = R2oTcpSilenceEvent {
        key,
        client_is_low: true,
        planned: true,
        elapsed_ms: 1000,
    };
    let frame = Frame {
        kind: EVENT_R2O_TCP_SILENT,
        body: event.event_body().unwrap(),
    };
    assert_eq!(decode_r2o_tcp_silence(&frame).unwrap(), event);

    let mut invalid_transport = frame.clone();
    invalid_transport.body[37] = 17;
    assert!(decode_r2o_tcp_silence(&invalid_transport).is_err());

    let mut invalid_direction = frame.clone();
    invalid_direction.body[KEY_LEN] = 2;
    assert!(decode_r2o_tcp_silence(&invalid_direction).is_err());

    let mut invalid_planned = frame.clone();
    invalid_planned.body[KEY_LEN + 1] = 2;
    assert!(decode_r2o_tcp_silence(&invalid_planned).is_err());

    let mut invalid_interval = frame;
    invalid_interval.body[KEY_LEN + 2..KEY_LEN + 6].copy_from_slice(&0_u32.to_be_bytes());
    assert!(decode_r2o_tcp_silence(&invalid_interval).is_err());
}

#[test]
fn delete_name_matches_c_transport_shape_rules() {
    // C `d2k_link_del_name_family`: любая пара transport 6/17 + shape != 0.
    assert!(encode_delete_name("example.test", 17, SHAPE_MODERN, 4).is_ok());
    assert!(encode_delete_name("example.test", 6, SHAPE_QUIC, 4).is_ok());
    assert!(encode_delete_name("example.test", 6, 0, 4).is_err());
    assert!(encode_delete_name("example.test", 5, SHAPE_MODERN, 4).is_err());
    assert!(encode_delete_name("example.test", 6, SHAPE_MODERN, 5).is_err());
    assert!(encode_delete_name("", 6, SHAPE_MODERN, 4).is_err());
    assert!(encode_delete_name(&"a".repeat(256), 6, SHAPE_MODERN, 4).is_err());
}

#[test]
fn delete_name_probe_ignores_shape_like_c() {
    // C `d2k_link_del_name_probe_family` не проверяет shape.
    assert!(encode_delete_name_probe("example.test", 0, 4, 40123).is_ok());
    assert!(encode_delete_name_probe("example.test", 99, 6, 40123).is_ok());
    assert!(encode_delete_name_probe("example.test", SHAPE_MODERN, 5, 40123).is_err());
    assert!(encode_delete_name_probe("example.test", SHAPE_MODERN, 4, 0).is_err());
}

#[test]
fn link_wrappers_emit_c_family4_frames() {
    use r2k_core::control::{
        COMMAND_ARM_SHAPE, COMMAND_SET_NAME, encode_arm_shape, encode_set_name,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let plan = r2o_tls_plan_records();
    let trial = [0x5a; 16];

    // C `d2k_link_set_name`: SET_NAME, family=4, без местного порта.
    let frame = read_frame(&mut Cursor::new(
        encode_set_name("example.test", SHAPE_MODERN, 4, &plan).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_SET_NAME);
    assert_eq!(frame.body[0], 12);
    assert_eq!(&frame.body[1..13], b"example.test");
    assert_eq!(&frame.body[13..15], &[SHAPE_MODERN, 4]);
    assert_eq!(&frame.body[15..], &plan[..]);

    // C `d2k_link_set_name_probe`/`_probe_trial`: sport BE и 16-байтный trial.
    let frame = read_frame(&mut Cursor::new(
        encode_set_name_probe("example.test", SHAPE_MODERN, 4, 40123, &plan, trial).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_SET_NAME_PROBE);
    assert_eq!(&frame.body[13..15], &[SHAPE_MODERN, 4]);
    assert_eq!(&frame.body[15..17], &40123_u16.to_be_bytes());
    assert_eq!(&frame.body[17..17 + plan.len()], &plan[..]);
    assert_eq!(&frame.body[17 + plan.len()..], &trial[..]);

    // Постоянная проба (`area_id=NULL`) шлёт 16 нулевых байт, как C.
    let frame = read_frame(&mut Cursor::new(
        encode_set_name_probe("example.test", SHAPE_MODERN, 4, 40123, &plan, [0; 16]).unwrap(),
    ))
    .unwrap();
    assert_eq!(&frame.body[17 + plan.len()..], &[0; 16]);
    // C `d2k_link_set_name_probe_trial`: нулевой порт — отказ.
    assert!(encode_set_name_probe("example.test", SHAPE_MODERN, 4, 0, &plan, trial).is_err());

    // `d2k_link_set_addr`: family=4, 16-байтное поле с нулями после IPv4.
    let frame = read_frame(&mut Cursor::new(
        encode_set_addr(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            SHAPE_QUIC,
            &r2o_quic_plan_records(),
        )
        .unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_SET_ADDR);
    assert_eq!(frame.body[0], 4);
    assert_eq!(&frame.body[1..5], &[192, 0, 2, 10]);
    assert_eq!(&frame.body[5..17], &[0; 12]);
    assert_eq!(frame.body[17], SHAPE_QUIC);

    // `d2k_link_del_addr`: family+16 байт+shape.
    let frame = read_frame(&mut Cursor::new(
        encode_delete_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), SHAPE_QUIC).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_DEL_ADDR);
    assert_eq!(frame.body.len(), 18);
    assert_eq!(frame.body[0], 4);
    assert_eq!(&frame.body[1..5], &[192, 0, 2, 10]);
    assert_eq!(&frame.body[5..17], &[0; 12]);
    assert_eq!(frame.body[17], SHAPE_QUIC);

    // `d2k_link_arm_shape`: имя+transport+family.
    let frame = read_frame(&mut Cursor::new(
        encode_arm_shape("example.test", 6, 4).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_ARM_SHAPE);
    assert_eq!(frame.body[0], 12);
    assert_eq!(&frame.body[1..13], b"example.test");
    assert_eq!(&frame.body[13..15], &[6, 4]);

    // `d2k_link_del_name_probe`: имя+shape+family+sport BE.
    let frame = read_frame(&mut Cursor::new(
        encode_delete_name_probe("example.test", SHAPE_MODERN, 4, 40123).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_DEL_NAME_PROBE);
    assert_eq!(&frame.body[13..15], &[SHAPE_MODERN, 4]);
    assert_eq!(&frame.body[15..17], &40123_u16.to_be_bytes());

    // `d2k_link_set_addr_probe`: flow 38 байт + trial + lease + план.
    let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let quic = r2o_quic_plan_records();
    let frame = read_frame(&mut Cursor::new(
        encode_set_addr_probe(source, destination, 5000, &quic, trial).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_SET_ADDR_PROBE);
    assert_eq!(frame.body[0], 4);
    assert_eq!(&frame.body[1..5], &[192, 0, 2, 10]);
    assert_eq!(&frame.body[5..17], &[0; 12]);
    assert_eq!(&frame.body[17..21], &[198, 51, 100, 20]);
    assert_eq!(&frame.body[21..33], &[0; 12]);
    assert_eq!(&frame.body[33..35], &41000_u16.to_be_bytes());
    assert_eq!(&frame.body[35..37], &443_u16.to_be_bytes());
    assert_eq!(frame.body[37], 17);
    assert_eq!(&frame.body[38..54], &trial[..]);
    assert_eq!(&frame.body[54..58], &5000_u32.to_be_bytes());
    assert_eq!(&frame.body[58..], &quic[..]);

    // `d2k_link_del_addr_probe`: flow + trial.
    let frame = read_frame(&mut Cursor::new(
        encode_delete_addr_probe(source, destination, trial).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_DEL_ADDR_PROBE);
    assert_eq!(&frame.body[38..54], &trial[..]);
    assert_eq!(frame.body.len(), 54);
}

#[test]
fn set_name_family_selects_command_by_source_port_like_c() {
    let plan = r2o_tls_plan_records();
    let trial = [0x5a; 16];
    let permanent = read_frame(&mut Cursor::new(
        encode_set_name_family("example.test", 6, SHAPE_MODERN, 4, 0, &plan, trial).unwrap(),
    ))
    .unwrap();
    assert_eq!(permanent.kind, COMMAND_SET_NAME);
    assert!(!permanent.body.ends_with(&trial));

    let probe = read_frame(&mut Cursor::new(
        encode_set_name_family("example.test", 6, SHAPE_MODERN, 4, 40123, &plan, trial).unwrap(),
    ))
    .unwrap();
    assert_eq!(probe.kind, COMMAND_SET_NAME_PROBE);
    assert_eq!(&probe.body[probe.body.len() - 16..], &trial);
    assert_eq!(&probe.body[15..17], &40123_u16.to_be_bytes());

    // C `send_name_plan` принимает только transport 6/17.
    assert!(encode_set_name_family("example.test", 17, SHAPE_QUIC, 4, 0, &plan, trial).is_ok());
    assert!(encode_set_name_family("example.test", 5, SHAPE_MODERN, 4, 0, &plan, trial).is_err());
}

#[test]
fn send_name_plan_writes_any_shape_and_unchecked_plan_like_c() {
    // C `send_name_plan` (`link.c:584-607`) пишет shape как есть и не
    // разбирает план: принимает любой байт формы и произвольные байты плана.
    let frame = read_frame(&mut Cursor::new(
        encode_set_name("example.test", 0xee, 4, &[0xff, 0x00, 0x7f]).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_SET_NAME);
    assert_eq!(frame.body[13], 0xee);
    assert_eq!(&frame.body[15..], &[0xff, 0x00, 0x7f]);

    // Пустое имя, имя длиннее 255 и family вне 4/6 — отказ, как в C.
    assert!(encode_set_name("", SHAPE_MODERN, 4, &[]).is_err());
    assert!(encode_set_name(&"a".repeat(256), SHAPE_MODERN, 4, &[]).is_err());
    assert!(encode_set_name("example.test", SHAPE_MODERN, 5, &[]).is_err());

    // Пустой план соответствует `plan_text == NULL` в C.
    let empty = read_frame(&mut Cursor::new(
        encode_set_name("example.test", SHAPE_MODERN, 6, &[]).unwrap(),
    ))
    .unwrap();
    assert_eq!(empty.body.len(), 15);
}

#[test]
fn encodes_http_probe_command_and_round_trips_its_correlated_ack() {
    let mut plan = r2o_tls_plan_records();
    plan[6..8].copy_from_slice(&11_u16.to_be_bytes());
    *plan.last_mut().unwrap() = r2k_core::plan::PROTO_HTTP;
    let trial_id = [0x5a; 16];
    let bytes =
        encode_set_name_probe("example.test", SHAPE_HTTP, 6, 40123, &plan, trial_id).unwrap();
    let command = read_frame(&mut Cursor::new(bytes)).unwrap();
    assert_eq!(command.kind, COMMAND_SET_NAME_PROBE);
    assert_eq!(command.body[0], 12);
    assert_eq!(&command.body[1..13], b"example.test");
    assert_eq!(&command.body[13..18], &[SHAPE_HTTP, 6, 0x9c, 0xbb, b'R']);
    assert_eq!(&command.body[command.body.len() - 16..], &trial_id);

    let ack_bytes = encode_ack_for_trial(COMMAND_SET_NAME_PROBE, true, 0, Some(trial_id)).unwrap();
    let ack_frame = read_frame(&mut Cursor::new(ack_bytes)).unwrap();
    let ack = decode_ack(&ack_frame).unwrap();
    assert!(ack.ok);
    assert_eq!(ack.trial_id, Some(trial_id));
}

#[test]
fn tcp_probe_encoder_accepts_any_shape_and_foreign_plan_like_c() {
    let plan = r2o_tls_plan_records();
    for shape in [SHAPE_MODERN, SHAPE_ECH_TCP, SHAPE_QUIC, SHAPE_HTTP, 0, 99] {
        assert!(encode_set_name_probe("example.test", shape, 4, 40123, &plan, [0x31; 16]).is_ok());
    }

    let mut http_plan = plan;
    http_plan[6..8].copy_from_slice(&11_u16.to_be_bytes());
    *http_plan.last_mut().unwrap() = r2k_core::plan::PROTO_HTTP;
    // C `send_name_plan` не сверяет план с формой/транспортом.
    assert!(
        encode_set_name_probe(
            "example.test",
            SHAPE_MODERN,
            4,
            40123,
            &http_plan,
            [0x31; 16]
        )
        .is_ok()
    );
}

fn voice_plan_records() -> Vec<u8> {
    let mut records = Vec::new();
    let mut r2o_add = |kind: u16, value: &[u8]| {
        records.extend_from_slice(&kind.to_be_bytes());
        records.extend_from_slice(&(value.len() as u16).to_be_bytes());
        records.extend_from_slice(value);
    };
    r2o_add(0x0001, &[1; 16]);
    r2o_add(0x0002, &[17, 3]);
    let mut payload = vec![0, 1];
    payload.extend_from_slice(&r2k_core::stun::binding_request([0x44; 12]));
    r2o_add(0x0010, &payload);
    r2o_add(0x0011, &[0, 1, 64, 1, 0, 0, 0, 0]);
    r2o_add(0x0101, &[0, 1, 0, 1, 1, 0, 0, 0, 0, 0]);
    r2o_add(0x0103, &[0]);
    r2o_add(0x0105, &15_000_u32.to_be_bytes());
    let mut plan = b"R2OP".to_vec();
    plan.extend_from_slice(&1_u16.to_be_bytes());
    plan.extend_from_slice(&1_u16.to_be_bytes());
    plan.extend_from_slice(&0_u16.to_be_bytes());
    plan.extend_from_slice(&7_u16.to_be_bytes());
    plan.extend_from_slice(&records);
    plan
}

#[test]
fn кодирует_адресный_voice_опыт_с_точным_клиентом_сервером_и_идентификатором() {
    use std::net::{Ipv4Addr, SocketAddrV4};

    let r2o_plan = voice_plan_records();
    let r2o_client = Ipv4Addr::new(192, 0, 2, 10);
    let r2o_server = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 50_004);
    let r2o_trial_id = [0x5a; 16];
    let r2o_bytes =
        encode_set_voice_addr_probe(r2o_client, r2o_server, 120_000, &r2o_plan, r2o_trial_id)
            .unwrap();
    let r2o_command = read_frame(&mut Cursor::new(r2o_bytes)).unwrap();
    assert_eq!(r2o_command.kind, COMMAND_SET_VOICE_ADDR_PROBE);
    assert_eq!(&r2o_command.body[..4], &r2o_client.octets());
    assert_eq!(&r2o_command.body[4..8], &r2o_server.ip().octets());
    assert_eq!(&r2o_command.body[8..10], &50_004_u16.to_be_bytes());
    assert_eq!(&r2o_command.body[10..14], &120_000_u32.to_be_bytes());
    assert_eq!(
        &r2o_command.body[r2o_command.body.len() - 16..],
        &r2o_trial_id
    );

    let r2o_ack =
        encode_ack_for_trial(COMMAND_SET_VOICE_ADDR_PROBE, true, 0, Some(r2o_trial_id)).unwrap();
    let r2o_ack = decode_ack(&read_frame(&mut Cursor::new(r2o_ack)).unwrap()).unwrap();
    assert!(r2o_ack.ok);
    assert_eq!(r2o_ack.trial_id, Some(r2o_trial_id));

    let r2o_permanent = encode_set_voice_addr(*r2o_server.ip(), &r2o_plan).unwrap();
    assert_eq!(
        read_frame(&mut Cursor::new(r2o_permanent)).unwrap().kind,
        COMMAND_SET_VOICE_ADDR
    );
    assert!(
        encode_set_voice_addr_probe(r2o_client, r2o_server, 120_001, &r2o_plan, r2o_trial_id)
            .is_err()
    );
    assert!(encode_set_voice_addr(Ipv4Addr::UNSPECIFIED, &r2o_plan).is_err());
}

#[test]
fn кодирует_только_подтверждение_с_валидным_discovery_ответом() {
    let mut r2o_key = [0; KEY_LEN];
    r2o_key[0] = 4;
    r2o_key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    r2o_key[17..21].copy_from_slice(&[198, 51, 100, 20]);
    r2o_key[33..35].copy_from_slice(&50_000_u16.to_be_bytes());
    r2o_key[35..37].copy_from_slice(&50_004_u16.to_be_bytes());
    r2o_key[37] = 17;
    let r2o_event = R2oVoiceProofEvent {
        key: r2o_key,
        trial_id: [0x33; 16],
        proof: R2oVoiceProofKind::DiscordDiscovery {
            mapped_ip: "203.0.113.8".parse().unwrap(),
            mapped_port: 52_000,
        },
    };
    let r2o_frame = Frame {
        kind: EVENT_R2O_VOICE_PROOF,
        body: r2o_event.event_body().unwrap(),
    };
    assert_eq!(decode_r2o_voice_proof(&r2o_frame).unwrap(), r2o_event);

    let mut r2o_invalid = r2o_frame;
    r2o_invalid.body[KEY_LEN..KEY_LEN + 16].fill(0);
    assert!(decode_r2o_voice_proof(&r2o_invalid).is_err());

    let r2o_stun_event = R2oVoiceProofEvent {
        key: r2o_key,
        trial_id: [0x34; 16],
        proof: R2oVoiceProofKind::StunBinding,
    };
    let r2o_stun_frame = Frame {
        kind: EVENT_R2O_VOICE_STUN_PROOF,
        body: r2o_stun_event.event_body().unwrap(),
    };
    assert_eq!(
        decode_r2o_voice_proof(&r2o_stun_frame).unwrap(),
        r2o_stun_event
    );
}

#[test]
fn r2o_voice_rtp_proof_round_trips_directional_packet_counts() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    key[17..21].copy_from_slice(&[198, 51, 100, 20]);
    key[33..35].copy_from_slice(&50_000_u16.to_be_bytes());
    key[35..37].copy_from_slice(&50_004_u16.to_be_bytes());
    key[37] = 17;
    let r2o_event = R2oVoiceProofEvent {
        key,
        trial_id: [0x31; 16],
        proof: R2oVoiceProofKind::RtpMedia {
            outbound_packets: 3,
            inbound_packets: 3,
        },
    };
    let r2o_frame = Frame {
        kind: EVENT_R2O_VOICE_RTP_PROOF,
        body: r2o_event.event_body().unwrap(),
    };
    assert_eq!(r2o_event.event_type(), EVENT_R2O_VOICE_RTP_PROOF);
    assert_eq!(decode_r2o_voice_proof(&r2o_frame).unwrap(), r2o_event);
}

#[test]
fn r2o_voice_rtp_proof_rejects_a_direction_without_sequence_progress() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    key[17..21].copy_from_slice(&[198, 51, 100, 20]);
    key[33..35].copy_from_slice(&50_000_u16.to_be_bytes());
    key[35..37].copy_from_slice(&50_004_u16.to_be_bytes());
    key[37] = 17;
    let r2o_event = R2oVoiceProofEvent {
        key,
        trial_id: [0x32; 16],
        proof: R2oVoiceProofKind::RtpMedia {
            outbound_packets: 3,
            inbound_packets: 2,
        },
    };
    assert!(r2o_event.event_body().is_none());
}

#[test]
fn encodes_a_bounded_exact_name_binding_delete() {
    let frame = read_frame(&mut Cursor::new(
        encode_delete_name("example.com", 6, SHAPE_HTTP, 4).unwrap(),
    ))
    .unwrap();

    assert_eq!(frame.kind, COMMAND_DEL_NAME);
    let mut expected = vec![11];
    expected.extend_from_slice(b"example.com");
    expected.extend_from_slice(&[6, SHAPE_HTTP, 4]);
    assert_eq!(frame.body, expected);
    assert!(encode_delete_name("", 6, SHAPE_HTTP, 4).is_err());
    assert!(encode_delete_name("example.com", 17, SHAPE_HTTP, 4).is_err());
    assert!(encode_delete_name("example.com", 6, SHAPE_HTTP, 7).is_err());
}

#[test]
fn delete_name_probe_encodes_any_shape_like_d2o() {
    let frame = read_frame(&mut Cursor::new(
        encode_delete_name_probe("example.test", 0, 4, 40_123).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_DEL_NAME_PROBE);
    let mut expected = vec![12];
    expected.extend_from_slice(b"example.test");
    expected.extend_from_slice(&[0, 4]);
    expected.extend_from_slice(&40_123_u16.to_be_bytes());
    assert_eq!(frame.body, expected);

    // C-командный слой проверяет family и порт, но не shape.
    assert!(encode_delete_name_probe("example.test", SHAPE_MODERN, 7, 40_123).is_err());
    assert!(encode_delete_name_probe("example.test", SHAPE_MODERN, 4, 0).is_err());
}

#[test]
fn encodes_the_exact_https_name_and_ttl_for_the_datapath() {
    let frame = read_frame(&mut Cursor::new(
        encode_set_https("Example.test", 3600).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_SET_HTTPS);
    assert_eq!(frame.body[0], 12);
    assert_eq!(&frame.body[1..13], b"Example.test");
    assert_eq!(&frame.body[13..], &3600_u32.to_be_bytes());
    // C-кодировщик `d2k_link_set_https` не ограничивает TTL: обрезку
    // до семи суток делает датапат. Проверяем, что срок доезжает как есть.
    let frame = read_frame(&mut Cursor::new(
        encode_set_https("example.test", 21_601).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_SET_HTTPS);
    assert_eq!(&frame.body[13..], &21_601_u32.to_be_bytes());
    let frame = read_frame(&mut Cursor::new(
        encode_set_https("example.test", u32::MAX).unwrap(),
    ))
    .unwrap();
    assert_eq!(frame.kind, COMMAND_SET_HTTPS);
    assert_eq!(&frame.body[13..], &u32::MAX.to_be_bytes());
    assert!(encode_set_https("bad host.test", 1).is_err());
}

#[test]
fn round_trips_an_applied_http_probe_with_its_exact_binding_identity() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 1]);
    key[17..21].copy_from_slice(&[198, 51, 100, 2]);
    key[33..35].copy_from_slice(&40123_u16.to_be_bytes());
    key[35..37].copy_from_slice(&80_u16.to_be_bytes());
    key[37] = 6;
    let event = AppliedEvent {
        key,
        plan_id: [0x11; 16],
        trial_id: [0x22; 16],
        execution_id: 42,
        binding: BindingContext {
            generation: 9,
            kind: 1,
            family: 4,
            shape: SHAPE_HTTP,
            temporary: true,
            epoch: [0x33; 16],
        },
    };

    let body = event.event_body().unwrap();
    assert_eq!(body.len(), KEY_LEN + 16 + 16 + 8 + 28);
    assert_eq!(&body[KEY_LEN..KEY_LEN + 16], &[0x11; 16]);
    assert_eq!(&body[KEY_LEN + 16..KEY_LEN + 32], &[0x22; 16]);
    assert_eq!(&body[KEY_LEN + 32..KEY_LEN + 40], &42_u64.to_be_bytes());
    assert_eq!(&body[KEY_LEN + 40..KEY_LEN + 48], &9_u64.to_be_bytes());
    assert_eq!(&body[KEY_LEN + 48..KEY_LEN + 52], &[1, 4, SHAPE_HTTP, 1]);
    assert_eq!(&body[KEY_LEN + 52..], &[0x33; 16]);

    let decoded = decode_applied(&Frame {
        kind: EVENT_APPLIED,
        body,
    })
    .unwrap();
    assert_eq!(decoded, event);
    assert!(decoded.binding.is_known());
}

#[test]
fn rejects_applied_events_with_invalid_binding_fields() {
    let mut body = vec![0; KEY_LEN + 32 + 36];
    body[0] = 4;
    body[37] = 6;
    body[KEY_LEN + 48] = 5;
    let decoded = decode_applied(&Frame {
        kind: EVENT_APPLIED,
        body,
    });
    assert!(decoded.is_err());
}

#[test]
fn decodes_a_tcp_hello_event_with_its_canonical_key_and_sni() {
    let mut body = vec![0; KEY_LEN];
    body[0] = 4;
    body[1..5].copy_from_slice(&[192, 0, 2, 1]);
    body[17..21].copy_from_slice(&[198, 51, 100, 2]);
    body[33..35].copy_from_slice(&50000_u16.to_be_bytes());
    body[35..37].copy_from_slice(&443_u16.to_be_bytes());
    body[37] = 6;
    body.push(12);
    body.extend_from_slice(b"example.test");
    body.push(r2k_core::control::SHAPE_MODERN);

    let hello = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body,
    })
    .unwrap();

    assert_eq!(hello.key[0], 4);
    assert_eq!(&hello.key[1..5], &[192, 0, 2, 1]);
    assert_eq!(&hello.key[17..21], &[198, 51, 100, 2]);
    assert_eq!(hello.host.as_deref(), Some(b"example.test".as_slice()));
    assert_eq!(hello.shape, Some(r2k_core::control::SHAPE_MODERN));
}

#[test]
fn decodes_the_wire_length_of_a_tcp_client_hello() {
    let mut body = vec![0; KEY_LEN];
    body[0] = 4;
    body[37] = 6;
    body.push(12);
    body.extend_from_slice(b"example.test");
    body.push(SHAPE_MODERN);
    body.extend_from_slice(&1275_u16.to_be_bytes());

    let hello = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body,
    })
    .unwrap();
    assert_eq!(hello.r2o_wire_len, Some(1275));
}

#[test]
fn rejects_invalid_r2o_tls_record_lengths_and_trailing_bytes() {
    let mut short_record = vec![0; KEY_LEN];
    short_record[0] = 4;
    short_record[37] = 6;
    short_record.push(12);
    short_record.extend_from_slice(b"example.test");
    short_record.push(SHAPE_MODERN);
    short_record.extend_from_slice(&4_u16.to_be_bytes());
    assert!(
        decode_hello(&Frame {
            kind: EVENT_HELLO,
            body: short_record,
        })
        .is_err()
    );

    let mut trailing = vec![0; KEY_LEN];
    trailing[0] = 4;
    trailing[37] = 6;
    trailing.push(12);
    trailing.extend_from_slice(b"example.test");
    trailing.push(SHAPE_MODERN);
    trailing.extend_from_slice(&1275_u16.to_be_bytes());
    trailing.push(0);
    assert!(
        decode_hello(&Frame {
            kind: EVENT_HELLO,
            body: trailing,
        })
        .is_err()
    );
}

#[test]
fn decodes_a_quic_initial_event_with_a_udp_key_and_quic_shape() {
    let mut body = vec![0; KEY_LEN];
    body[0] = 4;
    body[1..5].copy_from_slice(&[192, 0, 2, 1]);
    body[17..21].copy_from_slice(&[198, 51, 100, 2]);
    body[33..35].copy_from_slice(&50000_u16.to_be_bytes());
    body[35..37].copy_from_slice(&443_u16.to_be_bytes());
    body[37] = 17;
    body.push(11);
    body.extend_from_slice(b"example.com");
    body.push(r2k_core::control::SHAPE_QUIC);

    let hello = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body,
    })
    .unwrap();

    assert_eq!(hello.key[37], 17);
    assert_eq!(hello.host.as_deref(), Some(b"example.com".as_slice()));
    assert_eq!(hello.shape, Some(r2k_core::control::SHAPE_QUIC));
}

#[test]
fn событие_quic_initial_декодирует_исходный_снимок() {
    let initial = include_bytes!("fixtures/quic_v1_initial.bin");
    let snapshot = r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[initial]).unwrap();
    let mut body = vec![0; KEY_LEN];
    body[0] = 4;
    body[1..5].copy_from_slice(&[192, 0, 2, 1]);
    body[17..21].copy_from_slice(&[198, 51, 100, 2]);
    body[33..35].copy_from_slice(&50000_u16.to_be_bytes());
    body[35..37].copy_from_slice(&443_u16.to_be_bytes());
    body[37] = 17;
    body.push(11);
    body.extend_from_slice(b"example.com");
    body.push(r2k_core::control::SHAPE_QUIC);
    body.extend_from_slice(&(snapshot.len() as u16).to_be_bytes());
    body.extend_from_slice(&snapshot);

    let hello = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body,
    })
    .unwrap();

    assert_eq!(hello.quic_snapshot.as_deref(), Some(snapshot.as_slice()));
}

#[test]
fn отвергает_снимок_quic_если_sni_не_совпадает_с_событием() {
    let initial = include_bytes!("fixtures/quic_v1_initial.bin");
    let snapshot = r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[initial]).unwrap();
    let mut body = vec![0; KEY_LEN];
    body[0] = 4;
    body[37] = 17;
    body.push(11);
    body.extend_from_slice(b"other.test");
    body.push(r2k_core::control::SHAPE_QUIC);
    body.extend_from_slice(&(snapshot.len() as u16).to_be_bytes());
    body.extend_from_slice(&snapshot);

    assert!(
        decode_hello(&Frame {
            kind: EVENT_HELLO,
            body,
        })
        .is_err()
    );
}

#[test]
fn accepts_legacy_hello_events_without_the_shape_extension() {
    let mut body = vec![0; KEY_LEN];
    body[0] = 4;
    body[37] = 6;
    body.push(0);
    let hello = decode_hello(&Frame {
        kind: EVENT_HELLO,
        body,
    })
    .unwrap();

    assert_eq!(hello.shape, None);
    assert_eq!(hello.host, None);
}

#[test]
fn rejects_a_hello_event_with_a_truncated_host() {
    let mut body = vec![0; KEY_LEN];
    body[0] = 4;
    body[37] = 6;
    body.extend_from_slice(&[8, b'e', b'x', b'a']);

    assert!(
        decode_hello(&Frame {
            kind: EVENT_HELLO,
            body,
        })
        .is_err()
    );
}

#[test]
fn rejects_a_hello_event_with_an_unknown_shape() {
    let mut body = vec![0; KEY_LEN];
    body[0] = 4;
    body[37] = 6;
    body.push(0);
    body.push(99);
    assert!(
        decode_hello(&Frame {
            kind: EVENT_HELLO,
            body
        })
        .is_err()
    );
}

#[test]
fn decodes_r2o_http_response_context_and_measurements() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 1]);
    key[17..21].copy_from_slice(&[198, 51, 100, 2]);
    key[33..35].copy_from_slice(&40123_u16.to_be_bytes());
    key[35..37].copy_from_slice(&80_u16.to_be_bytes());
    key[37] = 6;

    let event = HttpResponseEvent {
        key,
        code: 4,
        host: b"cdn.example.test".to_vec(),
        execution_id: 42,
        plan_id: [0x11; 16],
        trial_id: [0; 16],
        request_ms: 123_456,
        path: b"/assets/app.css".to_vec(),
        binding: BindingContext {
            generation: 9,
            kind: 1,
            family: 4,
            shape: SHAPE_HTTP,
            temporary: false,
            epoch: [0x33; 16],
        },
        status: 200,
        body_bytes: 33_120,
        request_no: 3,
    };

    let mut body = Vec::new();
    body.extend_from_slice(&event.key);
    body.push(event.code);
    body.push(event.host.len() as u8);
    body.extend_from_slice(&event.host);
    body.extend_from_slice(&event.execution_id.to_be_bytes());
    body.extend_from_slice(&event.plan_id);
    body.extend_from_slice(&event.trial_id);
    body.extend_from_slice(&event.request_ms.to_be_bytes());
    body.extend_from_slice(&(event.path.len() as u16).to_be_bytes());
    body.extend_from_slice(&event.path);
    body.extend_from_slice(&event.binding.generation.to_be_bytes());
    body.extend_from_slice(&[
        event.binding.kind,
        event.binding.family,
        event.binding.shape,
        u8::from(event.binding.temporary),
    ]);
    body.extend_from_slice(&event.binding.epoch);
    body.extend_from_slice(&event.status.to_be_bytes());
    body.extend_from_slice(&event.body_bytes.to_be_bytes());
    body.extend_from_slice(&event.request_no.to_be_bytes());
    assert_eq!(event.event_body().as_deref(), Some(body.as_slice()));

    let decoded = decode_http_response(&Frame {
        kind: EVENT_HTTP_RESPONSE,
        body,
    })
    .unwrap();
    assert_eq!(decoded, event);
}

#[test]
fn rejects_http_response_events_with_invalid_outcome_or_truncated_context() {
    let mut body = vec![0; KEY_LEN + 2];
    body[0] = 4;
    body[37] = 6;
    body[KEY_LEN] = 5;
    body[KEY_LEN + 1] = 1;
    body.push(b'x');
    assert!(
        decode_http_response(&Frame {
            kind: EVENT_HTTP_RESPONSE,
            body: body.clone(),
        })
        .is_err()
    );

    body[KEY_LEN] = 4;
    assert!(
        decode_http_response(&Frame {
            kind: EVENT_HTTP_RESPONSE,
            body,
        })
        .is_err()
    );
}

#[test]
fn binding_known_requires_kind_and_equal_requires_both_sides() {
    let known = BindingContext {
        generation: 1,
        kind: 1,
        family: 4,
        shape: SHAPE_HTTP,
        temporary: false,
        epoch: [1; 16],
    };
    assert!(known.is_known());
    let mut unknown = known;
    unknown.kind = 0;
    assert!(!unknown.is_known());
    assert!(r2o_binding_equal(&known, &known));
    assert!(!r2o_binding_equal(&known, &unknown));
    let mut different = known;
    different.shape = SHAPE_MODERN;
    assert!(!r2o_binding_equal(&known, &different));
}

#[test]
fn http_portal_and_response_bodies_match_donor_shapes() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 1]);
    key[17..21].copy_from_slice(&[198, 51, 100, 2]);
    key[33..35].copy_from_slice(&40123_u16.to_be_bytes());
    key[35..37].copy_from_slice(&80_u16.to_be_bytes());
    key[37] = 6;
    let host = b"example.test".to_vec();

    let portal = HttpPortalEvent {
        key,
        answered: true,
        host: host.clone(),
    };
    let body = portal.event_body().unwrap();
    assert_eq!(body.len(), KEY_LEN + 2 + host.len());
    assert_eq!(body[KEY_LEN], 1);
    assert_eq!(body[KEY_LEN + 1] as usize, host.len());

    let response = HttpResponseEvent {
        key,
        code: 1,
        host: host.clone(),
        execution_id: 1,
        plan_id: [1; 16],
        trial_id: [2; 16],
        request_ms: 3,
        path: b"/x".to_vec(),
        binding: BindingContext {
            generation: 7,
            kind: 1,
            family: 4,
            shape: SHAPE_HTTP,
            temporary: false,
            epoch: [3; 16],
        },
        status: 200,
        body_bytes: 4,
        request_no: 1,
    };
    let body = response.event_body().unwrap();
    assert_eq!(
        body.len(),
        KEY_LEN + 2 + host.len() + 8 + 16 + 16 + 8 + 2 + b"/x".len() + 28 + 18
    );
    let tail = &body[body.len() - 18..];
    assert_eq!(&tail[..2], &200_u16.to_be_bytes());
    assert_eq!(&tail[2..10], &4_u64.to_be_bytes());
    assert_eq!(&tail[10..18], &1_u64.to_be_bytes());
}
