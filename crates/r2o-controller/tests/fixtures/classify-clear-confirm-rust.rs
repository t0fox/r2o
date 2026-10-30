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
        ..ClassifyOptions::default()
    };
    run_with_backend("192.0.2.44:443", &trigger(), options, &mut backend)
}

fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Clear => "Clear",
        Verdict::Flaky => "Flaky",
        Verdict::Inconclusive => "Inconclusive",
        _ => "Other",
    }
}

fn main() {
    let clear = run_case(vec![Ok(ProbeOutcome::Accepted); 5], None);
    let silent = run_case(
        vec![
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
        ],
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
    );
    let cancel = run_case(vec![Ok(ProbeOutcome::Accepted); 3], Some(3));

    println!("clear={}/{}", verdict_name(clear.verdict), clear.probes);
    println!("silent={}/{}", verdict_name(silent.verdict), silent.probes);
    println!(
        "connect-error={}/{}",
        verdict_name(connect_error.verdict),
        connect_error.probes
    );
    println!("cancel={}/{}", verdict_name(cancel.verdict), cancel.probes);

    assert_eq!(clear.verdict, Verdict::Clear);
    assert_eq!(clear.probes, 5);
    assert_eq!(silent.verdict, Verdict::Flaky);
    assert_eq!(silent.probes, 5);
    assert_eq!(connect_error.verdict, Verdict::Flaky);
    assert_eq!(connect_error.probes, 5);
    assert_eq!(cancel.verdict, Verdict::Inconclusive);
    assert_eq!(cancel.probes, 3);
}
