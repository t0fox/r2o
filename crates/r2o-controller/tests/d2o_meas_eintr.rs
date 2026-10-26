#![cfg(target_os = "linux")]

use r2o_controller::classify::{
    Accept, ProbeBackend, ProbeError, ProbeOutcome, ProbeRequest, ProbeTarget, TcpProbeBackend,
    Trigger,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

static SIGNAL_LOCK: Mutex<()> = Mutex::new(());

extern "C" fn ignore_sigusr1(_: libc::c_int) {}

#[test]
fn d2o_measurement_receive_interruption_matches_silence() {
    assert_eq!(
        run_fixture(include_str!("fixtures/d2o_meas_eintr.tsv")),
        "REJECTED"
    );
}

#[test]
fn d2o_measurement_send_interruption_matches_error() {
    assert_eq!(
        run_fixture(include_str!("fixtures/d2o_meas_send_eintr.tsv")),
        "ERROR"
    );
}

fn run_fixture(fixture_text: &str) -> &'static str {
    let _signal_lock = SIGNAL_LOCK.lock().unwrap();
    let fixture: std::collections::HashMap<String, u64> = fixture_text
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').expect("fixture key=value");
            (key.to_owned(), value.parse().expect("fixture integer"))
        })
        .collect();

    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = ignore_sigusr1 as *const () as usize;
    action.sa_flags = 0;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut previous) },
        0
    );
    struct RestoreSignal(libc::sigaction);
    impl Drop for RestoreSignal {
        fn drop(&mut self) {
            unsafe { libc::sigaction(libc::SIGUSR1, &self.0, std::ptr::null_mut()) };
        }
    }
    let _restore = RestoreSignal(previous);

    let listener =
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind loopback listener");
    let local = listener.local_addr().unwrap();
    let target = ProbeTarget {
        host: local.ip().to_string(),
        port: local.port(),
    };
    let payload_bytes = fixture["payload_bytes"] as usize;
    let send_phase = fixture["send_phase"] != 0;
    let interrupt_delay_ms = fixture["interrupt_delay_ms"];
    let signal_count = fixture["signal_count"];
    let signal_interval_ms = fixture["signal_interval_ms"];
    let response_delay_ms = fixture["response_delay_ms"];
    let target_thread = unsafe { libc::pthread_self() };
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept measurement probe");
        if !send_phase {
            let mut payload = vec![0; payload_bytes];
            stream
                .read_exact(&mut payload)
                .expect("read full probe payload");
        }
        thread::sleep(Duration::from_millis(interrupt_delay_ms));
        for index in 0..signal_count {
            assert_eq!(
                unsafe { libc::pthread_kill(target_thread, libc::SIGUSR1) },
                0
            );
            if index + 1 < signal_count {
                thread::sleep(Duration::from_millis(signal_interval_ms));
            }
        }
        let elapsed = interrupt_delay_ms + signal_count.saturating_sub(1) * signal_interval_ms;
        if response_delay_ms > elapsed {
            thread::sleep(Duration::from_millis(response_delay_ms - elapsed));
        }
        if send_phase {
            let mut received = 0;
            let mut buffer = [0_u8; 8192];
            while received < payload_bytes {
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received += n,
                }
            }
            if received == payload_bytes {
                let _ = stream.write_all(b"x");
            }
        } else {
            let _ = stream.write_all(b"x");
        }
    });

    let trigger = Trigger {
        name: "measurement-eintr-fixture".into(),
        payload: vec![0xa5; payload_bytes],
        accept: Accept::Any,
    };
    let mut backend = TcpProbeBackend;
    let result = backend.probe_outcome(ProbeRequest {
        target: &target,
        trigger: &trigger,
        cuts: &[],
        gap: Duration::ZERO,
        timeout: Duration::from_millis(fixture["timeout_ms"]),
        mark: Some(0),
        cancel: None,
    });
    server.join().unwrap();

    let normalized = match result {
        Ok(ProbeOutcome::Rejected) => "REJECTED",
        Ok(ProbeOutcome::Accepted) => "ACCEPTED",
        Ok(ProbeOutcome::Unproven) => "UNPROVEN",
        Err(ProbeError::Transport(_)) | Err(ProbeError::Local(_)) => "ERROR",
        Err(ProbeError::DialTimeout(_)) => "DIAL_TIMEOUT",
        Err(ProbeError::Unsupported(_)) => "UNSUPPORTED",
    };
    if let Some(path) = std::env::var_os("R2O_MEAS_EINTR_OUTPUT") {
        std::fs::write(path, format!("C_RESULT:{normalized}\n"))
            .expect("write normalized Rust measurement result");
    }
    println!("RUST_RESULT:{normalized}");
    assert_eq!(fixture["payload_bytes"], trigger.payload.len() as u64);
    normalized
}
