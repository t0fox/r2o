use r2o_controller::classify::{
    Accept, ProbeBackend, ProbeError, ProbeOutcome, ProbeRequest, ProbeTarget, TcpProbeBackend,
    Trigger,
};
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::thread;
use std::time::Duration;

fn fixture() -> std::collections::HashMap<&'static str, u64> {
    include_str!("fixtures/d2o_meas_send_timeout.tsv")
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').expect("fixture key=value");
            (key, value.parse().expect("fixture integer"))
        })
        .collect()
}

#[test]
fn d2o_send_timeout_is_an_experiment_error_not_a_negative_probe() {
    let fixture = fixture();
    let send_timeout_ms = fixture["send_timeout_ms"];
    assert_eq!(
        send_timeout_ms, 8_000,
        "must match donor's 8-second send timeout"
    );
    assert!(fixture["server_hold_ms"] > send_timeout_ms * 2);

    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let receive_buffer_bytes = fixture["server_receive_buffer_bytes"] as libc::c_int;
    let set_buffer = unsafe {
        libc::setsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&receive_buffer_bytes as *const libc::c_int).cast(),
            std::mem::size_of_val(&receive_buffer_bytes) as libc::socklen_t,
        )
    };
    assert_eq!(set_buffer, 0, "set local server receive window");
    let target = ProbeTarget {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
    };
    let hold_ms = fixture["server_hold_ms"];
    let _server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept measurement");
        thread::sleep(Duration::from_millis(hold_ms));
        drop(stream);
    });

    let trigger = Trigger {
        name: "send-timeout-fixture".into(),
        payload: vec![0xa5; fixture["payload_bytes"] as usize],
        accept: Accept::Any,
    };
    let mut backend = TcpProbeBackend;
    let result = backend.probe_outcome(ProbeRequest {
        target: &target,
        trigger: &trigger,
        cuts: &[],
        gap: Duration::ZERO,
        timeout: Duration::from_millis(fixture["response_timeout_ms"]),
        mark: Some(fixture["mark"] as u32),
        no_raw: false,
        client_tcp_has_timestamps: None,
        cancel: None,
    });
    let result_name = match &result {
        Err(ProbeError::Transport(_))
        | Err(ProbeError::RawConnectTimeout { .. })
        | Err(ProbeError::Local(_)) => "ERROR",
        Ok(ProbeOutcome::Rejected) => "REJECTED",
        Ok(ProbeOutcome::Accepted) => "ACCEPTED",
        Ok(ProbeOutcome::Unproven) => "UNPROVEN",
        Err(ProbeError::DialTimeout(_)) => "DIAL_TIMEOUT",
        Err(ProbeError::Unsupported(_)) => "UNSUPPORTED",
    };
    println!("RUST_RESULT:{result_name}");
    assert!(
        matches!(
            result,
            Err(ProbeError::Transport(_))
                | Err(ProbeError::RawConnectTimeout { .. })
                | Err(ProbeError::Local(_))
        ),
        "d2o treats a timed-out write as an experiment error; Rust returned {result_name}"
    );
    assert_eq!(fixture["payload_bytes"], trigger.payload.len() as u64);
}
