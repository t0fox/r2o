use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use classify::{
    Accept, ClassifyOptions, ClassifyResult, ProbeBackend, ProbeError, ProbeOutcome, ProbeRequest,
    Trigger, Verdict, run_with_backend,
};

struct ScriptedBackend {
    outcomes: VecDeque<Result<ProbeOutcome, ProbeError>>,
    cancel: Arc<AtomicBool>,
    cancel_after: Option<usize>,
    probes: usize,
}

impl ProbeBackend for ScriptedBackend {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        self.probe_outcome(request)
            .map(|outcome| outcome == ProbeOutcome::Accepted)
    }

    fn probe_outcome(&mut self, _: ProbeRequest<'_>) -> Result<ProbeOutcome, ProbeError> {
        self.probes += 1;
        if self.cancel_after == Some(self.probes) {
            self.cancel.store(true, Ordering::Relaxed);
        }
        self.outcomes.pop_front().expect("scripted probe result")
    }
}

fn trigger() -> Trigger {
    Trigger {
        name: "fixture".into(),
        payload: b"ABCD".to_vec(),
        accept: Accept::Any,
    }
}

fn run_case(
    outcomes: Vec<Result<ProbeOutcome, ProbeError>>,
    cancel_after: Option<usize>,
    control: Option<Trigger>,
) -> ClassifyResult {
    let cancel = Arc::new(AtomicBool::new(false));
    let mut backend = ScriptedBackend {
        outcomes: outcomes.into(),
        cancel: cancel.clone(),
        cancel_after,
        probes: 0,
    };
    let options = ClassifyOptions {
        repeats: 3,
        cancel: cancel_after.map(|_| cancel),
        control,
        ..ClassifyOptions::default()
    };
    run_with_backend("192.0.2.44:443", &trigger(), options, &mut backend)
}

fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Clear => "Clear",
        Verdict::Flaky => "Flaky",
        Verdict::Inconclusive => "Inconclusive",
        Verdict::Unreachable => "Unreachable",
        _ => "Other",
    }
}

fn main() {
    let clear = run_case(vec![Ok(ProbeOutcome::Accepted); 5], None, None);
    let silent = run_case(
        vec![
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
        ],
        None,
        None,
    );
    let connect_error = run_case(
        vec![
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
            Err(ProbeError::Transport("connection refused".into())),
            Err(ProbeError::Transport("connection refused".into())),
        ],
        None,
        None,
    );
    let cancel = run_case(vec![Ok(ProbeOutcome::Accepted); 3], Some(3), None);
    let all_baseline_errors = run_case(
        vec![Err(ProbeError::DialTimeout("dial timed out".into())); 6],
        None,
        None,
    );
    let partial_base_error = run_case(
        vec![
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Err(ProbeError::Transport("connection refused".into())),
            Err(ProbeError::Transport("connection refused".into())),
            Err(ProbeError::Transport("connection refused".into())),
            Err(ProbeError::Transport("connection refused".into())),
        ],
        None,
        None,
    );
    let unproven = run_case(
        vec![
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
        ],
        None,
        Some(Trigger {
            name: "control".into(),
            payload: b"WXYZ".to_vec(),
            accept: Accept::Any,
        }),
    );
    let control_partial = run_case(
        vec![
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
        ],
        None,
        Some(Trigger {
            name: "control".into(),
            payload: b"WXYZ".to_vec(),
            accept: Accept::Any,
        }),
    );
    let control_error = run_case(
        vec![
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Accepted),
            Err(ProbeError::Transport("connection refused".into())),
            Err(ProbeError::Transport("connection refused".into())),
        ],
        None,
        Some(Trigger {
            name: "control".into(),
            payload: b"WXYZ".to_vec(),
            accept: Accept::Any,
        }),
    );

    println!("clear={}/{}", verdict_name(clear.verdict), clear.probes);
    println!("silent={}/{}", verdict_name(silent.verdict), silent.probes);
    println!(
        "connect-error={}/{}",
        verdict_name(connect_error.verdict),
        connect_error.probes
    );
    println!("cancel={}/{}", verdict_name(cancel.verdict), cancel.probes);
    println!(
        "all-baseline-errors={}/{}",
        verdict_name(all_baseline_errors.verdict),
        all_baseline_errors.probes
    );
    println!(
        "partial-base-error={}/{}",
        verdict_name(partial_base_error.verdict),
        partial_base_error.probes
    );
    println!(
        "unproven={}/{}",
        verdict_name(unproven.verdict),
        unproven.probes
    );
    println!(
        "control-partial={}/{}",
        verdict_name(control_partial.verdict),
        control_partial.probes
    );
    println!(
        "control-error={}/{}",
        verdict_name(control_error.verdict),
        control_error.probes
    );

    assert_eq!(clear.verdict, Verdict::Clear);
    assert_eq!(clear.probes, 5);
    assert_eq!(silent.verdict, Verdict::Flaky);
    assert_eq!(silent.probes, 5);
    assert_eq!(connect_error.verdict, Verdict::Flaky);
    assert_eq!(connect_error.probes, 5);
    assert_eq!(cancel.verdict, Verdict::Inconclusive);
    assert_eq!(cancel.probes, 3);
    assert_eq!(all_baseline_errors.verdict, Verdict::Unreachable);
    assert_eq!(all_baseline_errors.probes, 3);
    assert_eq!(partial_base_error.verdict, Verdict::Flaky);
    assert_eq!(partial_base_error.probes, 6);
    assert_eq!(unproven.verdict, Verdict::Inconclusive);
    assert_eq!(unproven.probes, 9);
    assert_eq!(control_partial.verdict, Verdict::Flaky);
    assert_eq!(control_partial.probes, 9);
    assert_eq!(control_error.verdict, Verdict::Flaky);
    assert_eq!(control_error.probes, 9);
}
