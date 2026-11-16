//! C/Rust differential входа моста планировщика и нейтрального ACK.
//!
//! C-сторона — `tests/d2o_bridge_input_differential.c` и
//! `tests/d2o_bridge_ack_differential.c`, включающие production
//! `detect/bridge.c`; Rust-сторона — production `r2o_bridge_input` и
//! `r2o_detect_sched_tcp_ack_with`.

use std::cell::{Cell, RefCell};
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use r2o_controller::classify::{
    Accept, ProbeError, R2oBridgeHello, R2oBridgeInput, R2oBridgeProducts, r2o_bridge_input,
    r2o_detect_sched_tcp_ack_with,
};

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn accept_code(accept: Accept) -> i32 {
    match accept {
        Accept::Any => 0,
        Accept::ServerHello => 1,
        Accept::TlsRecord => 2,
    }
}

fn build_variant(variant: &str, control: bool) -> Vec<u8> {
    match variant {
        "none" => Vec::new(),
        "short" => vec![0x16, 0x03],
        "tiny" => vec![0x16],
        "sni_256" => {
            let name = "a".repeat(256);
            r2o_controller::hello::legacy_client_hello(&name).unwrap()
        }
        _ => {
            let mut hello = if control {
                r2o_controller::hello::legacy_client_hello("disk.rzd.ru").unwrap()
            } else {
                r2o_controller::hello::modern_client_hello("target.example").unwrap()
            };
            match variant {
                "wrong_type" => hello[0] = 0x17,
                "without_sni" => {
                    let (offset, _) = r2o_controller::hello::sni_bounds(&hello).unwrap();
                    hello[offset - 3] = 1;
                }
                "nul_sni" => {
                    let (offset, _) = r2o_controller::hello::sni_bounds(&hello).unwrap();
                    hello[offset] = 0;
                }
                "modern" | "legacy" => {}
                other => panic!("unknown bridge-input fixture variant {other}"),
            }
            hello
        }
    }
}

struct Case<'a> {
    name: &'a str,
    ip: &'a str,
    port: u16,
    trigger_variant: &'a str,
    control_variant: &'a str,
    white_variant: &'a str,
    snapped: bool,
    tcp_known: bool,
    tcp_large: bool,
    mark: u32,
    repeats: usize,
    gap_us: u32,
    wait_ms: u32,
    task_stop: bool,
}

fn output_line(case: &Case<'_>) -> String {
    let trigger = build_variant(case.trigger_variant, false);
    let control = build_variant(case.control_variant, true);
    let white = build_variant(case.white_variant, false);
    let mut options = if case.tcp_known {
        if case.tcp_large {
            vec![0_u8; 41]
        } else {
            vec![
                0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00,
            ]
        }
    } else {
        Vec::new()
    };
    let stop = Arc::new(AtomicBool::new(case.task_stop));
    let products: R2oBridgeProducts = r2o_bridge_input(R2oBridgeInput {
        ip: case.ip,
        port: case.port,
        trigger: R2oBridgeHello {
            bytes: (!trigger.is_empty()).then_some(trigger.as_slice()),
            tcp_known: case.tcp_known,
            tcp_options: &options,
            snapped: case.snapped,
        },
        trigger_name: None,
        control: (!control.is_empty()).then_some(control.as_slice()),
        white: (!white.is_empty()).then_some(white.as_slice()),
        mark: Some(case.mark),
        repeats: case.repeats,
        gap_us: case.gap_us,
        wait_ms: case.wait_ms,
        stop: Some(stop.clone()),
        client_tcp_has_timestamps: None,
    });

    let (trigger_len, trigger_accept, trigger_name, sni_off, sni_len, trigger_hex) =
        match products.trigger.as_ref() {
            Some(trigger) => {
                let (sni_off, sni_len) = r2o_controller::hello::sni_bounds(&trigger.payload)
                    .map_or((0, 0), |(offset, length)| (offset as i32, length as i32));
                (
                    trigger.payload.len(),
                    accept_code(trigger.accept),
                    trigger.name.clone(),
                    sni_off,
                    sni_len,
                    hex(&trigger.payload),
                )
            }
            None => (0, 0, String::new(), 0, 0, "-".into()),
        };
    let (control_len, control_accept, control_name, control_hex) =
        match products.options.control.as_ref() {
            Some(control) => (
                control.payload.len(),
                accept_code(control.accept),
                control.name.clone(),
                hex(&control.payload),
            ),
            None => (0, 0, String::new(), "-".into()),
        };
    let (white_len, white_accept, white_name, white_hex) = match products.options.white.as_ref() {
        Some(white) => (
            white.payload.len(),
            accept_code(white.accept),
            white.name.clone(),
            hex(&white.payload),
        ),
        None => (0, 0, String::new(), "-".into()),
    };
    let (decoy_len, decoy_type, decoy_accept, decoy_hex) = match products.decoy.as_ref() {
        Some(decoy) => (decoy.len(), i32::from(decoy[0]), 2, hex(decoy)),
        None => (0, 0, 0, "-".into()),
    };
    let cancel_task = products
        .options
        .cancel
        .as_ref()
        .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed));
    let cancel_set = products.options.cancel.is_some();
    let global = r2o_controller::classify::r2o_detect_stop_all_requested();
    format!(
        "case={} rc={} owns={} verdict={} reason={} addr={} tr_len={} tr_accept={} tr_name={} tr_sni_off={} tr_sni_len={} tr_tcp_known={} tr_tcp_len={} tr_tcp_offers_ts={} tr_tcp={} tr_hex={} ctl_len={} ctl_accept={} ctl_name={} ctl_vouched={} ctl_hex={} white_len={} white_accept={} white_name={} white_hex={} decoy_len={} decoy_type={:02x} decoy_accept={} decoy_hex={} repeats={} gap_ms={} timeout_ms={} mark={} cancel_set={} cancel_task={} cancel_null={}",
        case.name,
        if products.error.is_some() { -1 } else { 0 },
        i32::from(products.owns_search),
        if products.error.is_some() { 5 } else { 0 },
        products.error.as_deref().unwrap_or("-"),
        if products.addr.is_empty() {
            "-".into()
        } else {
            products.addr.clone()
        },
        trigger_len,
        trigger_accept,
        if trigger_name.is_empty() {
            "-".into()
        } else {
            trigger_name
        },
        sni_off,
        sni_len,
        i32::from(products.client_tcp_known),
        products.client_tcp_options.len(),
        if products.client_tcp_known {
            i32::from(r2o_controller::classify::r2o_trigger_offers_ts(
                &products.client_tcp_options,
            ))
        } else {
            -1
        },
        hex(&products.client_tcp_options),
        trigger_hex,
        control_len,
        control_accept,
        if control_name.is_empty() {
            "-".into()
        } else {
            control_name
        },
        i32::from(products.options.control_vouched),
        control_hex,
        white_len,
        white_accept,
        if white_name.is_empty() {
            "-".into()
        } else {
            white_name
        },
        white_hex,
        decoy_len,
        decoy_type,
        decoy_accept,
        decoy_hex,
        products.options.repeats,
        products.options.write_gap.as_millis(),
        products.options.timeout.as_millis(),
        products.options.mark.unwrap_or(0),
        i32::from(cancel_set),
        i32::from(cancel_task),
        i32::from(global),
    )
}

#[test]
fn bridge_input_products_match_the_c_fixture() {
    let cases = [
        Case {
            name: "error_empty",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "none",
            control_variant: "none",
            white_variant: "none",
            snapped: false,
            tcp_known: false,
            tcp_large: false,
            mark: 0x2f,
            repeats: 3,
            gap_us: 60_000,
            wait_ms: 6000,
            task_stop: false,
        },
        Case {
            name: "error_tiny",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "tiny",
            control_variant: "none",
            white_variant: "none",
            snapped: false,
            tcp_known: false,
            tcp_large: false,
            mark: 0x2f,
            repeats: 3,
            gap_us: 60_000,
            wait_ms: 6000,
            task_stop: false,
        },
        Case {
            name: "minimal",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "short",
            control_variant: "none",
            white_variant: "none",
            snapped: false,
            tcp_known: false,
            tcp_large: false,
            mark: 0x2f,
            repeats: 4,
            gap_us: 12_345,
            wait_ms: 321,
            task_stop: false,
        },
        Case {
            name: "full_clone",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "modern",
            control_variant: "legacy",
            white_variant: "modern",
            snapped: true,
            tcp_known: true,
            tcp_large: false,
            mark: 0x2d,
            repeats: 2,
            gap_us: 7000,
            wait_ms: 1500,
            task_stop: false,
        },
        Case {
            name: "tcp_options_overflow",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "modern",
            control_variant: "none",
            white_variant: "none",
            snapped: false,
            tcp_known: true,
            tcp_large: true,
            mark: 0x2f,
            repeats: 3,
            gap_us: 60_000,
            wait_ms: 6000,
            task_stop: false,
        },
        Case {
            name: "control_missing",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "modern",
            control_variant: "none",
            white_variant: "none",
            snapped: true,
            tcp_known: false,
            tcp_large: false,
            mark: 0x2f,
            repeats: 3,
            gap_us: 60_000,
            wait_ms: 6000,
            task_stop: false,
        },
        Case {
            name: "control_short",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "modern",
            control_variant: "short",
            white_variant: "none",
            snapped: true,
            tcp_known: false,
            tcp_large: false,
            mark: 0x2f,
            repeats: 3,
            gap_us: 60_000,
            wait_ms: 6000,
            task_stop: false,
        },
        Case {
            name: "control_without_sni",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "modern",
            control_variant: "without_sni",
            white_variant: "none",
            snapped: true,
            tcp_known: false,
            tcp_large: false,
            mark: 0x2f,
            repeats: 3,
            gap_us: 60_000,
            wait_ms: 6000,
            task_stop: false,
        },
        Case {
            name: "control_nul_sni",
            ip: "2001:db8::1",
            port: 8443,
            trigger_variant: "modern",
            control_variant: "nul_sni",
            white_variant: "none",
            snapped: true,
            tcp_known: false,
            tcp_large: false,
            mark: 0x2f,
            repeats: 3,
            gap_us: 60_000,
            wait_ms: 6000,
            task_stop: false,
        },
        Case {
            name: "control_sni_256",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "modern",
            control_variant: "sni_256",
            white_variant: "none",
            snapped: true,
            tcp_known: false,
            tcp_large: false,
            mark: 0x2f,
            repeats: 3,
            gap_us: 60_000,
            wait_ms: 6000,
            task_stop: false,
        },
        Case {
            name: "snapped_wrong_type",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "wrong_type",
            control_variant: "legacy",
            white_variant: "none",
            snapped: true,
            tcp_known: false,
            tcp_large: false,
            mark: 0x2f,
            repeats: 3,
            gap_us: 60_000,
            wait_ms: 6000,
            task_stop: false,
        },
        Case {
            name: "task_stop",
            ip: "192.0.2.1",
            port: 443,
            trigger_variant: "modern",
            control_variant: "legacy",
            white_variant: "none",
            snapped: true,
            tcp_known: false,
            tcp_large: false,
            mark: 0,
            repeats: 0,
            gap_us: 0,
            wait_ms: 0,
            task_stop: true,
        },
    ];

    let mut output = String::new();
    for case in &cases {
        output.push_str(&output_line(case));
        output.push('\n');
    }
    if let Ok(path) = std::env::var("R2O_BRIDGE_INPUT_DIFF_OUTPUT") {
        std::fs::write(path, &output).expect("write Rust bridge input differential output");
    }
    assert!(output.contains("case=error_empty rc=-1 owns=1 verdict=5"));
    assert!(output.contains("case=full_clone"));
    assert!(output.contains("tr_name=tls:target.example"));
    assert!(output.contains("tr_tcp_known=1 tr_tcp_len=16 tr_tcp_offers_ts=1"));
    assert!(output.contains("decoy_type=16 decoy_accept=2"));
    assert!(output.contains("case=control_nul_sni"));
    assert!(output.contains("addr=[2001:db8::1]:8443"));
    assert!(output.contains("case=task_stop"));
    assert!(output.contains("cancel_task=1"));
}

fn ack_line(name: &str, ip: &str, port: u16, pattern: &str, stop_set: bool) -> String {
    let calls = Cell::new(0_usize);
    let seen = RefCell::new(None::<(String, u16, Duration, Option<u32>)>);
    let stop = AtomicBool::new(stop_set);
    let result = r2o_detect_sched_tcp_ack_with(
        ip,
        port,
        Some(0x2f),
        Duration::from_millis(6000),
        3,
        Some(&stop),
        |target, timeout, mark, _stop| {
            let index = calls.get();
            calls.set(index + 1);
            *seen.borrow_mut() = Some((target.host.clone(), target.port, timeout, mark));
            let bytes = pattern.as_bytes();
            let step = bytes
                .get(index)
                .copied()
                .unwrap_or_else(|| *bytes.last().expect("pattern is not empty"));
            match step {
                b'e' => Err(ProbeError::Local("dial failed".into())),
                b'u' => Err(ProbeError::Unsupported("unobservable".into())),
                b'+' => Ok(true),
                _ => Ok(false),
            }
        },
    );
    let (host, seen_port, timeout, mark) = seen.borrow().clone().map_or_else(
        || ("-".to_owned(), 0, Duration::ZERO, 0),
        |(host, port, timeout, mark)| (host, port, timeout, mark.unwrap_or(0)),
    );
    format!(
        "case={name} rc={} probes={} calls={} host={host} port={} mark={mark} timeout={}",
        result.code,
        result.probes,
        calls.get(),
        if seen_port == 0 {
            "-".to_owned()
        } else {
            seen_port.to_string()
        },
        timeout.as_millis(),
    )
}

#[test]
fn neutral_ack_hook_matches_the_c_codes() {
    let mut lines = vec![
        ack_line("silent", "192.0.2.1", 443, "-", false),
        ack_line("ack_after_two", "2001:db8::1", 443, "-+", false),
        ack_line("local_error", "192.0.2.1", 443, "e", false),
        ack_line("unsupported", "192.0.2.1", 443, "u", false),
        ack_line("stopped", "192.0.2.1", 443, "-", true),
    ];
    for (name, ip, port) in [
        ("invalid_ip", "", 443_u16),
        ("invalid_port_zero", "192.0.2.1", 0_u16),
    ] {
        let result = r2o_detect_sched_tcp_ack_with(
            ip,
            port,
            Some(0x2f),
            Duration::from_millis(6000),
            3,
            None,
            |_target, _timeout, _mark, _stop| panic!("invalid input must not probe"),
        );
        lines.push(format!(
            "case={name} rc={} probes={} calls=0 host=- port=- mark=0 timeout=0",
            result.code, result.probes
        ));
    }
    let output = lines.join("\n") + "\n";
    if let Ok(path) = std::env::var("R2O_BRIDGE_ACK_DIFF_OUTPUT") {
        std::fs::write(path, &output).expect("write Rust neutral-ack differential output");
    }
    assert!(output.contains(
        "case=silent rc=0 probes=3 calls=3 host=192.0.2.1 port=443 mark=47 timeout=6000"
    ));
    assert!(output.contains("case=ack_after_two rc=1 probes=2 calls=2 host=2001:db8::1"));
    assert!(output.contains("case=local_error rc=-1 probes=1 calls=1"));
    assert!(output.contains("case=unsupported rc=-1 probes=0 calls=1"));
    assert!(output.contains("case=stopped rc=-1 probes=0 calls=0 host=- port=- mark=0 timeout=0"));
    assert!(output.contains("case=invalid_ip rc=-1 probes=0 calls=0"));
    assert!(output.contains("case=invalid_port_zero rc=-1 probes=0 calls=0"));
}
