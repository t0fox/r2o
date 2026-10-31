use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use classify::{
    Accept, ClassifyOptions, ProbeBackend, ProbeError, ProbeOutcome, ProbeRequest, ProbeTarget,
    Trigger, run_with_backend_progress,
};

struct Backend {
    control_outcomes: VecDeque<Result<ProbeOutcome, ProbeError>>,
    ack_outcomes: VecDeque<Result<bool, ProbeError>>,
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
            self.control_outcomes.pop_front().expect("control outcome")
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
        self.ack_outcomes.pop_front().expect("neutral ACK outcome")
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

fn run_case(
    control_outcomes: Vec<Result<ProbeOutcome, ProbeError>>,
    ack_outcomes: Vec<Result<bool, ProbeError>>,
) -> (classify::ClassifyResult, usize) {
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
        control_outcomes: control_outcomes.into(),
        ack_outcomes: ack_outcomes.into(),
        ack_calls: 0,
    };
    let result = run_with_backend_progress(
        "192.0.2.44:443",
        &trigger,
        options,
        &mut backend,
        &mut |_, _, _, _| {},
    );
    (result, backend.ack_calls)
}

fn main() {
    let (transport_error, transport_ack_calls) = run_case(
        vec![Err(ProbeError::Transport("connection refused".into())); 3],
        vec![Err(ProbeError::Transport("connection refused".into()))],
    );
    println!(
        "{:?}|{}|{}",
        transport_error.verdict, transport_error.probes, transport_ack_calls
    );

    let (control_pass, control_ack_calls) = run_case(
        vec![
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
        ],
        vec![],
    );
    println!(
        "{:?}|{}|{}",
        control_pass.verdict, control_pass.probes, control_ack_calls
    );

    let (control_unproven, control_ack_calls) =
        run_case(vec![Ok(ProbeOutcome::Unproven); 3], vec![Ok(false); 3]);
    println!(
        "{:?}|{}|{}",
        control_unproven.verdict, control_unproven.probes, control_ack_calls
    );
}
