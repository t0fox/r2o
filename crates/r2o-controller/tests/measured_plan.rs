use r2k_core::plan::{POISON_BADSUM, Plan};
use r2o_controller::classify::{Poison, Trigger, plan_for_poison, plan_text_for_poison, poisons};
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

#[test]
fn autottl_fields_reach_the_plan_like_c_arm() {
    let poison = Poison {
        name: "autottl".into(),
        autottl: true,
        autottl_delta: -3,
        autottl_min: 2,
        autottl_max: 10,
        ..Poison::default()
    };
    let text = plan_text_for_poison(&poison, &trigger(), None, 0).unwrap();
    assert!(text.starts_with("r2o-plan 1 13\n"), "{text}");
    assert!(text.contains(" autottl=-3,2-10"), "{text}");
    let plan = plan_for_poison(&poison, &trigger(), None, 0).unwrap();
    assert_eq!(plan.minexec, 13);
    assert!(!plan.fakes.is_empty());
}

#[test]
fn tcp_ts_up_reaches_the_plan_like_c_arm() {
    let poison = Poison {
        name: "ts-up".into(),
        tcp_ts: true,
        tcp_ts_up: true,
        ..Poison::default()
    };
    let text = plan_text_for_poison(&poison, &trigger(), None, 0).unwrap();
    assert!(text.contains(" tcpts tsup"), "{text}");
}

#[test]
fn compose_all_at_once_accepts_an_empty_control_like_c() {
    let poison = Poison {
        name: "СОБРАНО: всё сразу".into(),
        badsum: true,
        decoy_hello: true,
        seqovl_exact: true,
        disorder: true,
        repeats: 7,
        ..Poison::default()
    };
    let text = plan_text_for_poison(&poison, &trigger(), Some(&[]), 0).unwrap();
    assert!(text.contains("payload-pad64 1"), "{text}");
    assert!(text.contains("poison 1 badsum"), "{text}");
    assert!(text.contains("fake payload=1"), "{text}");
    assert!(text.contains("order reverse"), "{text}");
}

#[test]
#[ignore = "C/Rust full measured-plan differential: run by scripts/test-plan-measured-cap-differential.sh"]
fn d2o_arm_plan_measured_cap_differential_matches_c() {
    use r2o_controller::hello::sni_bounds;

    let trigger = Trigger::tls13("probe.example").unwrap();
    assert_eq!(trigger.payload.len(), 1536);
    assert_eq!(sni_bounds(&trigger.payload), Some((137, 13)));
    let decoy: Vec<u8> = (0..681).map(|index| (index * 23 + 5) as u8).collect();

    let cases: Vec<(&str, Poison)> = vec![
        ("default", Poison::default()),
        (
            "badsum",
            Poison {
                badsum: true,
                ..Poison::default()
            },
        ),
        (
            "badsum-x2",
            Poison {
                badsum: true,
                repeats: 2,
                gap_ms: 20,
                ..Poison::default()
            },
        ),
        (
            "autottl",
            Poison {
                autottl: true,
                autottl_delta: -3,
                autottl_min: 2,
                autottl_max: 10,
                ..Poison::default()
            },
        ),
        (
            "ts-up",
            Poison {
                tcp_ts: true,
                tcp_ts_up: true,
                ..Poison::default()
            },
        ),
        (
            "seqovl-1",
            Poison {
                seqovl: 1,
                ..Poison::default()
            },
        ),
        (
            "seqovl-hello",
            Poison {
                seqovl_exact: true,
                seqovl: 681,
                ..Poison::default()
            },
        ),
        (
            "seqovl-hello-empty",
            Poison {
                seqovl_exact: true,
                seqovl: 681,
                ..Poison::default()
            },
        ),
        (
            "decoy-badsum",
            Poison {
                decoy_hello: true,
                badsum: true,
                repeats: 7,
                ..Poison::default()
            },
        ),
        (
            "composite-ts",
            Poison {
                decoy_hello: true,
                tcp_ts: true,
                repeats: 8,
                split_pos: 2,
                ..Poison::default()
            },
        ),
        (
            "between",
            Poison {
                fake_between: true,
                badsum: true,
                repeats: 7,
                gap_ms: 300,
                ..Poison::default()
            },
        ),
        (
            "disorder",
            Poison {
                disorder: true,
                disorder_pos: 2,
                ..Poison::default()
            },
        ),
        (
            "oob",
            Poison {
                oob: true,
                ..Poison::default()
            },
        ),
        (
            "md5",
            Poison {
                md5: true,
                ..Poison::default()
            },
        ),
        (
            "split",
            Poison {
                split_pos: 2,
                ..Poison::default()
            },
        ),
        (
            "ipid",
            Poison {
                ip_id_zero: true,
                ..Poison::default()
            },
        ),
        (
            "syn-data",
            Poison {
                syn_data: true,
                ..Poison::default()
            },
        ),
        (
            "seq-invalid",
            Poison {
                seq_shift: -123,
                ..Poison::default()
            },
        ),
    ];
    let runs: &[(&str, Option<&[u8]>, usize)] = &[
        ("default", None, 1500),
        ("badsum", None, 1500),
        ("badsum-x2", None, 1500),
        ("autottl", None, 1280),
        ("ts-up", None, 1400),
        ("seqovl-1", None, 1500),
        ("seqovl-hello", Some(&decoy), 1280),
        ("seqovl-hello", Some(&decoy), 1500),
        ("seqovl-hello-empty", None, 1400),
        ("decoy-badsum", Some(&decoy), 1280),
        ("decoy-badsum", Some(&decoy), 1500),
        ("composite-ts", Some(&decoy), 1500),
        ("composite-ts", Some(&decoy), 1280),
        ("between", None, 1400),
        ("disorder", None, 1500),
        ("oob", None, 1500),
        ("md5", None, 1280),
        ("split", None, 1400),
        ("ipid", None, 1500),
        ("syn-data", None, 1500),
        ("seq-invalid", None, 1500),
        ("badsum", None, 72),
        ("badsum", None, 1),
        ("badsum", None, 65535),
        ("badsum", None, 1280),
        ("badsum", None, 1400),
        ("badsum", None, 1500),
    ];

    let mut output = String::new();
    for (name, decoy_bytes, send_cap) in runs {
        let poison = cases
            .iter()
            .find(|(case, _)| case == name)
            .map(|(_, poison)| poison.clone())
            .expect("plan case");
        let result = plan_text_for_poison(&poison, &trigger, *decoy_bytes, *send_cap);
        output.push_str(&format!(
            "plan|{name}|{}|{send_cap}|{}\n",
            decoy_bytes.map_or(0, <[u8]>::len),
            i32::from(result.is_err()).wrapping_neg()
        ));
        if let Ok(text) = result {
            output.push_str(&text);
        }
    }
    let nameless = Trigger::raw_hex(&"16".repeat(200)).unwrap();
    let nameless_badsum = Poison {
        badsum: true,
        ..Poison::default()
    };
    let result = plan_text_for_poison(&nameless_badsum, &nameless, None, 1400);
    output.push_str(&format!(
        "plan|badsum-nameless|0|1400|{}\n",
        i32::from(result.is_err()).wrapping_neg()
    ));
    if let Ok(text) = result {
        output.push_str(&text);
    }
    if let Ok(path) = std::env::var("R2O_PLAN_MEASURED_OUTPUT") {
        std::fs::write(path, &output).expect("write measured plan output");
    }
    assert!(output.contains("plan|badsum|0|1500|0\n"));
    assert!(output.contains("segment 1208\n"));
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
