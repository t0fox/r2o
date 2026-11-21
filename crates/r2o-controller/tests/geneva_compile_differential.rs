//! Байтовый дифференциал Geneva → R2OP на реальном ClientHello.
//!
//! Эталон снят с geneva_c (`bdb767d`, `tests/golden/in.pcap`, пакет 10):
//!
//! ```sh
//! build/geneva apply \
//!   -s '[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-' \
//!   -i tests/golden/in.pcap -o out.pcap -p 443 --rng-seed 1
//! ```
//!
//! Оригинал и изменённая копия сравниваются после нормализации случайных
//! полей (IP ID и контрольные суммы), как требует `docs/geneva-c-adoption.md`.

use r2k_core::packet::PacketView;
use r2k_core::plan::{PacketInput, Plan};
use r2k_core::wire::build_tcp_packet;
use r2o_controller::discovery::{plan_ident, plan_text_for_trial};
use r2o_controller::geneva::parse_strategy;
use r2o_controller::geneva_compile::{compile_plan_for_packet, discovery_midpoint_candidate};
use r2o_datapath::engine::{PacketDecision, decide};

const INPUT: &[u8] = include_bytes!("fixtures/geneva/clienthello_in.bin");
const EXPECTED_ORIGINAL: &[u8] = include_bytes!("fixtures/geneva/clienthello_original.bin");
const EXPECTED_TAMPERED: &[u8] = include_bytes!("fixtures/geneva/clienthello_flags_rst.bin");

#[test]
fn discovery_prepares_a_guarded_midpoint_for_short_legacy_hello() {
    let view = PacketView::parse(INPUT).unwrap();
    let payload = view.tcp_segment(INPUT).unwrap().payload;
    assert!(discovery_midpoint_candidate(&INPUT[payload.clone()], 1492).is_none());

    let mut packet = INPUT.to_vec();
    // Подменяем TLS 1.3 на TLS 1.2 в единственной версии supported_versions.
    assert_eq!(&packet[packet.len() - 7..], &[0, 43, 0, 3, 2, 3, 4]);
    *packet.last_mut().unwrap() = 3;
    let text = discovery_midpoint_candidate(&packet[payload.clone()], 1492).unwrap();
    assert!(discovery_midpoint_candidate(&packet[payload], 120).is_none());

    let (_, trial_plan_id) = plan_ident(&text).unwrap();
    let trial_text = plan_text_for_trial(&text, trial_plan_id).unwrap();
    let bytes = r2o_controller::plan_text::compile_text(&trial_text).unwrap();
    let plan = Plan::parse(&bytes).unwrap();
    assert_eq!(plan.id, trial_plan_id);
    assert_eq!(plan.input_tcp_flags, Some(0x18));
    assert!(matches!(
        decide(&plan, &packet),
        PacketDecision::Transmit { packets, .. } if packets.len() == 2
    ));
    packet[view.l4_offset + 12] |= 1;
    assert_eq!(decide(&plan, &packet), PacketDecision::Accept);
    packet[view.l4_offset + 12] &= !1;
    packet[view.l4_offset + 13] = 0x10;
    assert_eq!(decide(&plan, &packet), PacketDecision::Accept);
    assert!(r2o_controller::plan_text::compile_text(&text.replacen("1 15", "1 14", 1)).is_err());
}

#[test]
fn trigger_rejects_other_flags_spellings_and_packet_contexts() {
    let strategy = |trigger: &str| {
        parse_strategy(&format!("[TCP:flags:{trigger}]-fragment{{tcp:-1:True}}-")).unwrap()
    };
    assert!(compile_plan_for_packet(&strategy("PA"), INPUT, [1; 16]).is_ok());
    for trigger in ["A", "S", "AP", "24", "PA*", "PA:1"] {
        assert!(
            compile_plan_for_packet(&strategy(trigger), INPUT, [1; 16]).is_err(),
            "{trigger}"
        );
    }
    let view = PacketView::parse(INPUT).unwrap();
    for flags in [0x10, 0x02, 0x58] {
        let mut packet = INPUT.to_vec();
        packet[view.l4_offset + 13] = flags;
        assert!(compile_plan_for_packet(&strategy("PA"), &packet, [1; 16]).is_err());
    }
    let mut packet = INPUT.to_vec();
    packet[view.l4_offset + 12] |= 1;
    assert!(compile_plan_for_packet(&strategy("PA"), &packet, [1; 16]).is_err());
    assert!(compile_plan_for_packet(&strategy("PA"), &INPUT[..INPUT.len() - 1], [1; 16]).is_err());
}

#[test]
fn fragment_uses_geneva_payload_midpoint_in_both_orders() {
    let view = PacketView::parse(INPUT).unwrap();
    let tcp = view.tcp_segment(INPUT).unwrap();
    let payload = &INPUT[tcp.payload];
    let cut = payload.len() / 2;
    for (size, order) in [(-1, "True"), (200, "True"), (-1, "False")] {
        let strategy =
            parse_strategy(&format!("[TCP:flags:PA]-fragment{{tcp:{size}:{order}}}-")).unwrap();
        let plan =
            Plan::parse(&compile_plan_for_packet(&strategy, INPUT, [1; 16]).unwrap()).unwrap();
        let mut input = PacketInput::new(payload, tcp.sequence);
        input.tcp_flags = Some(tcp.wire_flags);
        let actions = plan.apply(&input).unwrap();
        let expected = [
            (tcp.sequence, &payload[..cut]),
            (tcp.sequence.wrapping_add(cut as u32), &payload[cut..]),
        ];
        let expected = if order == "True" {
            expected
        } else {
            [expected[1], expected[0]]
        };
        assert_eq!(
            actions
                .emits
                .iter()
                .map(|part| (part.seq, part.bytes.as_slice()))
                .collect::<Vec<_>>(),
            expected
        );
    }
}

fn normalize(mut packet: Vec<u8>) -> Vec<u8> {
    let ip_header_len = usize::from(packet[0] & 0x0f) * 4;
    packet[4..6].fill(0); // IP ID
    packet[10..12].fill(0); // IP checksum
    packet[ip_header_len + 16..ip_header_len + 18].fill(0); // TCP checksum
    packet
}

#[test]
fn compiled_duplicate_matches_geneva_bytes_after_normalization() {
    let view = PacketView::parse(INPUT).expect("input packet");
    let tcp = view.tcp_segment(INPUT).expect("tcp");
    let payload = &INPUT[tcp.payload.clone()];
    let mut input = PacketInput::new(payload, tcp.sequence);
    input.tcp_flags = Some(tcp.wire_flags);

    let strategy = parse_strategy(
        "[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-",
    )
    .expect("strategy");
    let bytes = compile_plan_for_packet(&strategy, INPUT, [0x42; 16]).expect("compile");
    let plan = Plan::parse(&bytes).expect("plan");
    let actions = plan.apply(&input).expect("apply");
    assert_eq!(actions.emits.len(), 2, "оригинал и фальшивка");

    let build = |index: usize| {
        let mut out = vec![0u8; 2048];
        let length = build_tcp_packet(INPUT, &actions.emits[index], &mut out).expect("wire");
        out[..length].to_vec()
    };

    assert_eq!(
        normalize(build(0)),
        normalize(EXPECTED_ORIGINAL.to_vec()),
        "оригинал уходит без изменений"
    );
    assert_eq!(
        normalize(build(1)),
        normalize(EXPECTED_TAMPERED.to_vec()),
        "фальшивка: flags=R, badsum, тот же seq/ack и нагрузка"
    );
}
