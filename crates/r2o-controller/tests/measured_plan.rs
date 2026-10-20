use r2k_core::plan::{POISON_BADSUM, Plan};
use r2o_controller::classify::{Poison, Trigger, plan_for_poison, poisons};
use std::net::Ipv4Addr;

fn trigger() -> Trigger {
    Trigger::tls("probe.example").unwrap()
}

#[test]
fn seqovl_one_keeps_the_measured_single_byte_prefix() {
    let trigger = trigger();
    let poison = Poison {
        name: "seqovl-1".into(),
        seqovl: 1,
        ..Poison::default()
    };

    let plan = plan_for_poison(&poison, &trigger, None, 0).unwrap();
    assert_eq!(plan.transport, 6);
    assert_eq!(plan.proto, 1);
    assert_eq!(plan.wire_profile, 1);
    assert!(plan.input_tls);
    assert_eq!(plan.payloads.len(), 1);
    assert_eq!(plan.payloads[0].bytes, [0x0f]);
    assert_eq!(plan.seq_overlays.len(), 1);
    assert_eq!(plan.seq_overlays[0].payload_id, plan.payloads[0].id);
}

#[test]
fn badsum_poison_uses_two_trigger_lengths_and_measured_repeat_gap() {
    let trigger = trigger();
    let poison = Poison {
        name: "badsum-x2-g20".into(),
        badsum: true,
        repeats: 2,
        gap_ms: 20,
        ..Poison::default()
    };

    let plan = plan_for_poison(&poison, &trigger, None, 0).unwrap();
    assert!(plan.input_tls);
    assert_eq!(plan.minexec, 5);
    assert_eq!(plan.payloads[0].bytes.len(), trigger.payload.len() * 2);
    assert!(plan.payloads[0].bytes.iter().all(|byte| *byte == 0x0f));
    assert_eq!(plan.poisons[0].flags, POISON_BADSUM);
    assert_eq!(plan.fakes[0].repeats, 2);
    assert_eq!(plan.fakes[0].gap_us, 20_000);
    assert_eq!(plan.settle_us, 15_000);
}

#[test]
fn disorder_pos_keeps_fixed_cut_and_reverse_order() {
    let trigger = trigger();
    let poison = Poison {
        name: "disorder-pos2".into(),
        disorder: true,
        disorder_pos: 2,
        ..Poison::default()
    };

    let plan = plan_for_poison(&poison, &trigger, None, 0).unwrap();
    assert!(plan.input_tls);
    assert_eq!(plan.splits.len(), 1);
    assert_eq!(plan.splits[0].offset, 2);
    assert_eq!(plan.order, 1);
    assert_eq!(plan.pace_us, 0);
}

#[test]
fn syn_data_is_reported_as_unrepresentable() {
    let trigger = trigger();
    let poison = Poison {
        name: "syndata".into(),
        syn_data: true,
        ..Poison::default()
    };

    let error = plan_for_poison(&poison, &trigger, None, 0).unwrap_err();
    assert!(error.contains("SYN"));
}

#[test]
fn fake_between_discards_overlap_like_the_measured_sender() {
    let trigger = trigger();
    let poison = Poison {
        name: "fakedsplit+overlap".into(),
        badsum: true,
        fake_between: true,
        seqovl: 22,
        ..Poison::default()
    };

    let plan = plan_for_poison(&poison, &trigger, None, 0).unwrap();
    assert!(plan.seq_overlays.is_empty());
    assert_eq!(plan.fakes[0].placement, 1);
}

#[test]
fn generated_bytes_are_accepted_by_datapath_plan_parser() {
    let trigger = trigger();
    let poison = Poison {
        name: "badsum".into(),
        badsum: true,
        ..Poison::default()
    };

    let bytes =
        r2o_controller::classify::plan_bytes_for_poison(&poison, &trigger, None, 0).unwrap();
    let parsed = Plan::parse(&bytes).unwrap();
    assert_eq!(parsed, plan_for_poison(&poison, &trigger, None, 0).unwrap());
}

#[test]
fn measured_hit_can_be_saved_as_text_and_recompiled_without_changing_the_plan() {
    let trigger = trigger();
    let poison = Poison {
        name: "badsum".into(),
        badsum: true,
        ..Poison::default()
    };

    let text = r2o_controller::classify::plan_text_for_poison(&poison, &trigger, None, 0).unwrap();
    let compiled = r2o_controller::plan_text::compile_text(&text).unwrap();
    let direct =
        r2o_controller::classify::plan_bytes_for_poison(&poison, &trigger, None, 0).unwrap();
    assert_eq!(compiled, direct);
}

#[test]
fn every_catalog_hypothesis_is_either_planned_or_explicitly_unrepresentable() {
    let trigger = trigger();
    let decoy: Vec<u8> = (0..681).map(|index| (index * 23 + 5) as u8).collect();
    let mut runtime_rejections = Vec::new();

    for poison in poisons() {
        let result = plan_for_poison(poison, &trigger, Some(&decoy), 0);
        if poison.syn_data || (poison.seq_shift != 0 && poison.seq_shift != -66_000) {
            assert!(
                result.is_err(),
                "{} must refuse unsupported semantics",
                poison.name
            );
        } else {
            let plan = result.unwrap_or_else(|error| panic!("{}: {error}", poison.name));
            if let Err(error) = r2o_datapath::engine::validate_runtime_plan(&plan) {
                runtime_rejections.push((poison.name.as_str(), error));
            } else {
                let packet = ipv4_tcp(&trigger.payload);
                let r2o_datapath::engine::PacketDecision::Transmit { packets, fate } =
                    r2o_datapath::engine::decide(&plan, &packet)
                else {
                    panic!("{} did not produce a datapath transmission", poison.name);
                };
                assert_eq!(fate, r2k_core::plan::OriginalFate::Drop, "{}", poison.name);
                assert!(!packets.is_empty(), "{}", poison.name);
            }
        }
    }
    assert_eq!(
        runtime_rejections,
        [(
            "badsum+ipid",
            "Linux raw socket меняет нулевой IPv4 ID; такой poison не исполняется"
        )]
    );
}

fn ipv4_tcp(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40 + payload.len()];
    packet[0] = 0x45;
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
    packet[16..20].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 2).octets());
    packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[24..28].copy_from_slice(&0x1234_5678_u32.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = 0x18;
    packet[34..36].copy_from_slice(&u16::MAX.to_be_bytes());
    packet[40..].copy_from_slice(payload);
    packet
}
