//! C/Rust differential: `d2k_meas_once` response and local-error branches.
//!
//! Rust-ветвь использует production `response::probe_trigger` через
//! `TcpProbeBackend`, как и остальные meas differential.

#![cfg(target_os = "linux")]

use r2o_controller::classify::{
    Accept, ProbeBackend, ProbeError, ProbeOutcome, ProbeRequest, ProbeTarget, TcpProbeBackend,
    Trigger,
};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::thread;
use std::time::Duration;

fn normalize(result: Result<ProbeOutcome, ProbeError>) -> &'static str {
    match result {
        Ok(ProbeOutcome::Accepted | ProbeOutcome::AcceptedUnmarked) => "PASS",
        Ok(ProbeOutcome::Unproven | ProbeOutcome::UnprovenUnmarked) => "UNPROVEN",
        Ok(ProbeOutcome::Rejected | ProbeOutcome::RejectedUnmarked) => "SILENT",
        Err(_) => "ERROR",
    }
}

fn run_network(
    scenario: &'static str,
    response: Option<&'static [u8]>,
    reset: bool,
    accept: Accept,
) -> (&'static str, &'static str) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback listener");
    let target = ProbeTarget {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
    };
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept measurement probe");
        let mut received = 0;
        let mut buffer = [0_u8; 8192];
        while received < 64 {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => received += n,
            }
        }
        if let Some(bytes) = response {
            let _ = stream.write_all(bytes);
        }
        if reset {
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            let _ = unsafe {
                libc::setsockopt(
                    std::os::fd::AsRawFd::as_raw_fd(&stream),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&linger as *const libc::linger).cast(),
                    std::mem::size_of_val(&linger) as libc::socklen_t,
                )
            };
        }
        drop(stream);
    });
    let trigger = Trigger {
        name: "meas-branches".into(),
        payload: vec![0xa5; 64],
        accept,
    };
    let mut backend = TcpProbeBackend;
    let result = backend.probe_outcome(ProbeRequest {
        target: &target,
        trigger: &trigger,
        cuts: &[],
        gap: Duration::ZERO,
        timeout: Duration::from_millis(500),
        mark: Some(0),
        no_raw: false,
        client_tcp_has_timestamps: None,
        cancel: None,
    });
    server.join().unwrap();
    (scenario, normalize(result))
}

#[test]
fn d2o_measurement_response_and_local_error_branches_match() {
    let mut lines = Vec::new();
    lines.push(run_network("pass-any", Some(b"x"), false, Accept::Any));
    lines.push(run_network(
        "serverhello",
        Some(&[0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00]),
        false,
        Accept::ServerHello,
    ));
    lines.push(run_network(
        "bad-serverhello",
        Some(&[0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]),
        false,
        Accept::ServerHello,
    ));
    lines.push(run_network(
        "short-response",
        Some(b"x"),
        false,
        Accept::ServerHello,
    ));
    lines.push(run_network("closed", None, false, Accept::Any));
    lines.push(run_network("rst", None, true, Accept::Any));

    let refused = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let refused_port = refused.local_addr().unwrap().port();
    drop(refused);
    let target = ProbeTarget {
        host: "127.0.0.1".into(),
        port: refused_port,
    };
    let trigger = Trigger {
        name: "meas-branches".into(),
        payload: vec![0xa5; 64],
        accept: Accept::Any,
    };
    let mut backend = TcpProbeBackend;
    let result = backend.probe_outcome(ProbeRequest {
        target: &target,
        trigger: &trigger,
        cuts: &[],
        gap: Duration::ZERO,
        timeout: Duration::from_millis(500),
        mark: Some(0),
        no_raw: false,
        client_tcp_has_timestamps: None,
        cancel: None,
    });
    lines.push(("connect-refused", normalize(result)));

    let invalid_target = ProbeTarget {
        host: "127.0.0.1%bad".into(),
        port: 1,
    };
    let result = backend.probe_outcome(ProbeRequest {
        target: &invalid_target,
        trigger: &trigger,
        cuts: &[],
        gap: Duration::ZERO,
        timeout: Duration::from_millis(500),
        mark: Some(0),
        no_raw: false,
        client_tcp_has_timestamps: None,
        cancel: None,
    });
    lines.push(("invalid-ip", normalize(result)));

    // Живой listener нужен, чтобы connect состоялся: иначе отказ соединения
    // замаскировал бы проверку самих точек разреза.
    let cut_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let cut_target = ProbeTarget {
        host: "127.0.0.1".into(),
        port: cut_listener.local_addr().unwrap().port(),
    };
    let result = backend.probe_outcome(ProbeRequest {
        target: &cut_target,
        trigger: &trigger,
        cuts: &[0],
        gap: Duration::ZERO,
        timeout: Duration::from_millis(500),
        mark: Some(0),
        no_raw: false,
        client_tcp_has_timestamps: None,
        cancel: None,
    });
    lines.push(("invalid-cuts", normalize(result)));
    drop(cut_listener);

    let empty = Trigger {
        name: "meas-branches".into(),
        payload: Vec::new(),
        accept: Accept::Any,
    };
    let result = backend.probe_outcome(ProbeRequest {
        target: &target,
        trigger: &empty,
        cuts: &[],
        gap: Duration::ZERO,
        timeout: Duration::from_millis(500),
        mark: Some(0),
        no_raw: false,
        client_tcp_has_timestamps: None,
        cancel: None,
    });
    lines.push(("empty-payload", normalize(result)));

    if let Some(path) = std::env::var_os("R2O_MEAS_BRANCH_OUTPUT") {
        let text = lines
            .iter()
            .map(|(name, result)| format!("{name}={result}\n"))
            .collect::<String>();
        std::fs::write(path, text).expect("write measurement branch output");
    }
    for (name, result) in &lines {
        println!("{name}={result}");
    }
}
