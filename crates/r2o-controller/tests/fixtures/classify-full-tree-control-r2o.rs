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
    target_outcome: ProbeOutcome,
    target_error: Option<ProbeError>,
    target_error_at: Option<usize>,
    target_timeouts: Vec<u128>,
    target_calls: usize,
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
            self.target_timeouts.push(request.timeout.as_millis());
            let target_call = self.target_calls;
            self.target_calls += 1;
            if self.target_error_at == Some(target_call) {
                return Err(ProbeError::Transport("connection refused".into()));
            }
            if let Some(error) = &self.target_error {
                Err(error.clone())
            } else {
                Ok(self.target_outcome)
            }
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
    target_outcome: ProbeOutcome,
    control_accept: Accept,
    target_error: Option<ProbeError>,
    target_error_at: Option<usize>,
) -> (classify::ClassifyResult, usize, Vec<u128>) {
    let trigger = Trigger {
        name: "fixture".into(),
        payload: b"WA\x06\x03SIGNATURE-AND-THEN-SOME-PAYLOAD-BYTES".to_vec(),
        accept: Accept::ServerHello,
    };
    let control = Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: control_accept,
    };
    let options = ClassifyOptions {
        repeats: 3,
        timeout: Duration::from_millis(400),
        write_gap: Duration::from_millis(2),
        long_gap: Duration::from_millis(10),
        allow_loopback: true,
        no_raw: true,
        full_detect_semantics: true,
        confirm_clear: false,
        control: Some(control),
        ..ClassifyOptions::default()
    };
    let mut backend = Backend {
        control_outcomes: control_outcomes.into(),
        ack_outcomes: ack_outcomes.into(),
        target_outcome,
        target_error,
        target_error_at,
        target_timeouts: Vec::new(),
        target_calls: 0,
        ack_calls: 0,
    };
    let result = run_with_backend_progress(
        "192.0.2.44:443",
        &trigger,
        options,
        &mut backend,
        &mut |_, _, _, _| {},
    );
    (result, backend.ack_calls, backend.target_timeouts)
}

fn main() {
    let (transport_error, transport_ack_calls, _) = run_case(
        vec![Err(ProbeError::Transport("connection refused".into())); 3],
        vec![Err(ProbeError::Transport("connection refused".into()))],
        ProbeOutcome::Rejected,
        Accept::Any,
        None,
        None,
    );
    println!(
        "{:?}|{}|{}",
        transport_error.verdict, transport_error.probes, transport_ack_calls
    );

    let (control_pass, control_ack_calls, _) = run_case(
        vec![
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
        ],
        vec![],
        ProbeOutcome::Rejected,
        Accept::Any,
        None,
        None,
    );
    println!(
        "{:?}|{}|{}",
        control_pass.verdict, control_pass.probes, control_ack_calls
    );

    let (control_unproven, control_ack_calls, _) = run_case(
        vec![Ok(ProbeOutcome::Unproven); 3],
        vec![Ok(false); 3],
        ProbeOutcome::Rejected,
        Accept::TlsRecord,
        None,
        None,
    );
    println!(
        "{:?}|{}|{}",
        control_unproven.verdict, control_unproven.probes, control_ack_calls
    );

    let (target_unproven, target_ack_calls, _) = run_case(
        vec![Ok(ProbeOutcome::Accepted)],
        vec![],
        ProbeOutcome::Unproven,
        Accept::Any,
        None,
        None,
    );
    println!(
        "{:?}|{}|{}",
        target_unproven.verdict, target_unproven.probes, target_ack_calls
    );

    let (baseline_deadline, baseline_ack_calls, timeouts) = run_case(
        vec![],
        vec![],
        ProbeOutcome::Rejected,
        Accept::Any,
        Some(ProbeError::DialTimeout(
            "dial tcp 192.0.2.44:443: i/o timeout".into(),
        )),
        None,
    );
    let timeout_csv = timeouts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{:?}|{}|{}|{}",
        baseline_deadline.verdict, baseline_deadline.probes, baseline_ack_calls, timeout_csv
    );

    let (baseline_mixed_error, baseline_ack_calls, _) = run_case(
        vec![],
        vec![],
        ProbeOutcome::Rejected,
        Accept::Any,
        None,
        Some(0),
    );
    println!(
        "{:?}|{}|{}",
        baseline_mixed_error.verdict, baseline_mixed_error.probes, baseline_ack_calls
    );

    let (baseline_clear, baseline_ack_calls, _) = run_case(
        vec![],
        vec![],
        ProbeOutcome::Accepted,
        Accept::Any,
        None,
        None,
    );
    println!(
        "{:?}|{}|{}",
        baseline_clear.verdict, baseline_clear.probes, baseline_ack_calls
    );
}
