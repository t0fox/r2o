use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use classify::{
    Accept, ClassifyOptions, ProbeBackend, ProbeError, ProbeOutcome, ProbeRequest, ProbeTarget,
    Trigger, run_with_backend_progress,
};

struct Backend {
    control_calls: usize,
    ack_calls: usize,
}

impl ProbeBackend for Backend {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        self.probe_outcome(request).map(|outcome| {
            matches!(
                outcome,
                ProbeOutcome::Accepted | ProbeOutcome::AcceptedUnmarked
            )
        })
    }

    fn probe_outcome(&mut self, request: ProbeRequest<'_>) -> Result<ProbeOutcome, ProbeError> {
        if request.trigger.name == "control" {
            self.control_calls += 1;
            Err(ProbeError::Transport("connection refused".into()))
        } else {
            Ok(ProbeOutcome::Rejected)
        }
    }

    fn neutral_ack(
        &mut self,
        _: &ProbeTarget,
        _: Duration,
        _: Option<u32>,
        _: Option<&AtomicBool>,
    ) -> Result<bool, ProbeError> {
        self.ack_calls += 1;
        Err(ProbeError::Transport("connection refused".into()))
    }

    fn tcp_control_peer(
        &mut self,
        _: SocketAddr,
        _: Duration,
        _: Option<u32>,
    ) -> Result<(), ProbeError> {
        Err(ProbeError::Unsupported("not used".into()))
    }
}

fn main() {
    let trigger = Trigger {
        name: "fixture".into(),
        payload: b"WA\x06\x03SIGNATURE-AND-THEN-SOME-PAYLOAD-BYTES".to_vec(),
        accept: Accept::Any,
    };
    let control = Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Accept::Any,
    };
    let options = ClassifyOptions {
        repeats: 3,
        timeout: Duration::from_millis(400),
        write_gap: Duration::from_millis(2),
        long_gap: Duration::from_millis(10),
        allow_loopback: true,
        no_raw: true,
        control: Some(control),
        ..ClassifyOptions::default()
    };
    let mut backend = Backend {
        control_calls: 0,
        ack_calls: 0,
    };
    let result = run_with_backend_progress(
        "192.0.2.44:443",
        &trigger,
        options,
        &mut backend,
        &mut |_, _, _, _| {},
    );
    println!(
        "{:?}|{}|{}",
        result.verdict, result.probes, backend.ack_calls
    );
}
