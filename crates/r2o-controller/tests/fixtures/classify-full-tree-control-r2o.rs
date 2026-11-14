use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use classify::{
    Accept, ClassifyOptions, DpiProps, PoisonHit, ProbeBackend, ProbeError, ProbeOutcome,
    ProbeRequest, ProbeTarget, TriState, Trigger, run_with_backend_progress,
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

struct ComposeBackend;

impl ProbeBackend for ComposeBackend {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(request.trigger.name == "control")
    }

    fn raw_supported(&self) -> bool {
        true
    }

    fn sweep_poisons(
        &mut self,
        _: &ProbeTarget,
        _: &Trigger,
        _: &ClassifyOptions,
        result: &mut classify::ClassifyResult,
    ) -> Result<Option<PoisonHit>, ProbeError> {
        result.props = DpiProps {
            parses_l7: TriState::True,
            validates_checksum: TriState::False,
            tolerates_reorder: TriState::True,
            tolerates_left_overlap: TriState::True,
            ..DpiProps::default()
        };
        result.path = Some("собрано".into());
        result.composed = true;
        Ok(Some(PoisonHit {
            name: "СОБРАНО: всё сразу".into(),
            strategy: "fixture".into(),
            plan_text: String::new(),
            plan: Vec::new(),
            gap_ms: 0,
        }))
    }
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
    run_case_with_progress(
        control_outcomes,
        ack_outcomes,
        target_outcome,
        control_accept,
        target_error,
        target_error_at,
        3,
        false,
    )
}

fn run_json_case() -> (classify::ClassifyResult, usize) {
    let payload = b"WA\x06\x03SIGNATURE-AND-THEN-SOME-PAYLOAD-BYTES";
    let raw_hex = payload
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let trigger = Trigger::raw_hex(&raw_hex).unwrap();
    let control = Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Accept::Any,
    };
    let options = ClassifyOptions {
        repeats: 3,
        timeout: Duration::from_millis(400),
        write_gap: Duration::from_millis(60),
        long_gap: Duration::from_millis(700),
        allow_loopback: true,
        no_raw: true,
        full_detect_semantics: true,
        confirm_clear: false,
        control: Some(control),
        ..ClassifyOptions::default()
    };
    let mut backend = Backend {
        control_outcomes: VecDeque::new(),
        ack_outcomes: VecDeque::new(),
        target_outcome: ProbeOutcome::Accepted,
        target_error: None,
        target_error_at: None,
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
    (result, trigger.payload.len())
}

fn run_composed_json_case() -> (classify::ClassifyResult, usize) {
    let trigger = Trigger::raw_hex("574106035349474e4154555245").unwrap();
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
        no_raw: false,
        full_detect_semantics: true,
        confirm_clear: false,
        control: Some(control),
        ..ClassifyOptions::default()
    };
    let mut backend = ComposeBackend;
    let result = run_with_backend_progress(
        "192.0.2.44:443",
        &trigger,
        options,
        &mut backend,
        &mut |_, _, _, _| {},
    );
    (result, trigger.payload.len())
}

fn run_case_with_progress(
    control_outcomes: Vec<Result<ProbeOutcome, ProbeError>>,
    ack_outcomes: Vec<Result<bool, ProbeError>>,
    target_outcome: ProbeOutcome,
    control_accept: Accept,
    target_error: Option<ProbeError>,
    target_error_at: Option<usize>,
    repeats: usize,
    capture_progress: bool,
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
        repeats,
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
        &mut |probe, _, passed, failed| {
            let completed = passed.saturating_add(failed);
            let observation_complete = completed >= repeats
                || (probe == "control" || probe == "neutral-ack") && passed > 0
                || probe.starts_with("transport:");
            if capture_progress && completed > 0 && observation_complete {
                println!("PROGRESS|{probe}|{passed}|{failed}");
            }
        },
    );
    (result, backend.ack_calls, backend.target_timeouts)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TreeModel {
    None,
    Prefix,
    Whole,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TreeSweep {
    None,
    Hit(&'static str),
    SelftestFail,
}

struct TreeBackend {
    model: TreeModel,
    boundary: usize,
    reassembles: bool,
    target_pat: Option<&'static str>,
    fail_call: i32,
    trigger_calls: usize,
    control_pat: &'static str,
    control_calls: usize,
    ack_pat: &'static str,
    ack_calls: usize,
    sweep: TreeSweep,
    long_gap: Duration,
}

fn tree_pat_char(pattern: &str, index: usize) -> char {
    let bytes = pattern.as_bytes();
    let byte = bytes[index.min(bytes.len().saturating_sub(1))];
    byte as char
}

fn tree_control_outcome(character: char) -> ProbeOutcome {
    match character {
        '+' | 'A' => ProbeOutcome::Accepted,
        _ => ProbeOutcome::Rejected,
    }
}

impl ProbeBackend for TreeBackend {
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
            let character = tree_pat_char(self.control_pat, self.control_calls);
            self.control_calls += 1;
            return Ok(tree_control_outcome(character));
        }
        let call = self.trigger_calls;
        self.trigger_calls += 1;
        if self.fail_call == call as i32 {
            return Err(ProbeError::Transport("write: Broken pipe".into()));
        }
        if let Some(pattern) = self.target_pat {
            return Ok(tree_control_outcome(tree_pat_char(pattern, call)));
        }
        if self.model == TreeModel::None {
            return Ok(ProbeOutcome::Rejected);
        }
        let length = request.trigger.payload.len();
        let first = request.cuts.first().copied().unwrap_or(length);
        let partial = first > 0 && first < length;
        let mut pass = match self.model {
            TreeModel::Prefix => partial && first < self.boundary,
            TreeModel::Whole => partial,
            TreeModel::None => false,
        };
        if pass && self.reassembles && request.gap == self.long_gap {
            pass = false;
        }
        Ok(if pass {
            ProbeOutcome::Accepted
        } else {
            ProbeOutcome::Rejected
        })
    }

    fn neutral_ack(
        &mut self,
        _: &ProbeTarget,
        _: Duration,
        _: Option<u32>,
        _: Option<&AtomicBool>,
    ) -> Result<bool, ProbeError> {
        let character = tree_pat_char(self.ack_pat, self.ack_calls);
        self.ack_calls += 1;
        match character {
            '+' => Ok(true),
            '-' => Ok(false),
            'e' => Err(ProbeError::Transport("dial tcp: i/o timeout".into())),
            'u' => Err(ProbeError::Unsupported(
                "подтверждение не наблюдается".into(),
            )),
            _ => Ok(false),
        }
    }

    fn tcp_control_peer(
        &mut self,
        _: SocketAddr,
        _: Duration,
        _: Option<u32>,
    ) -> Result<(), ProbeError> {
        Err(ProbeError::Unsupported("not used".into()))
    }

    fn raw_supported(&self) -> bool {
        true
    }

    fn sweep_poisons_with_progress(
        &mut self,
        _: &ProbeTarget,
        _: &Trigger,
        _: &ClassifyOptions,
        result: &mut classify::ClassifyResult,
        _: &mut dyn FnMut(&str, usize, usize, usize),
    ) -> Result<Option<PoisonHit>, ProbeError> {
        match self.sweep {
            TreeSweep::None => Ok(None),
            TreeSweep::SelftestFail => Err(ProbeError::Unsupported(
                "classify: SYN-ACK не пришёл".into(),
            )),
            TreeSweep::Hit(name) => {
                let poison = classify::poisons()
                    .iter()
                    .find(|poison| poison.name == name)
                    .expect("tree sweep poison");
                result.path = Some("свойство".into());
                Ok(Some(PoisonHit {
                    name: name.into(),
                    strategy: classify::strategy_for_poison(poison).unwrap_or_default(),
                    plan_text: String::new(),
                    plan: Vec::new(),
                    gap_ms: poison.gap_ms,
                }))
            }
        }
    }
}

fn tree_tri(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "1",
        Some(false) => "0",
        None => "u",
    }
}

fn tree_print_result(name: &str, result: &classify::ClassifyResult, include_trace: bool) {
    let boundary = result.boundary.unwrap_or(0);
    let split_pos = result.split_pos.unwrap_or(0);
    let path = result.path.as_deref().unwrap_or("-");
    let strategy = result.strategy.as_deref().unwrap_or("");
    let hit = result.hit.as_ref().map_or("-", |hit| hit.name.as_str());
    print!(
        "CASE|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        name,
        result.verdict.as_str(),
        boundary,
        split_pos,
        tree_tri(result.reassembles),
        if path.is_empty() { "-" } else { path },
        u8::from(result.composed),
        u8::from(result.raw_usable),
        strategy,
        hit
    );
    if include_trace {
        print!("|{}", result.probes);
    }
    println!();
    println!("REASON|{}|{}", name, result.reason);
    for note in &result.notes {
        println!("NOTE|{}|{}", name, note);
    }
    if let Some(response) = &result.response {
        println!(
            "RESP|{}|{}|{}|{}|{}",
            name,
            response.verdict.as_str(),
            response.target,
            response.control,
            response.reason
        );
    }
    if !include_trace {
        return;
    }
    for observation in &result.trace {
        let cuts = if observation.cuts.is_empty() {
            "-".to_owned()
        } else {
            format!(
                "[{}]",
                observation
                    .cuts
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        };
        println!(
            "TRACE|{}|{}|{}|{}|{}|{}|{}",
            name,
            observation.probe,
            cuts,
            observation.delay.as_millis(),
            observation.pass,
            observation.fail,
            observation.error.as_deref().unwrap_or("")
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn run_tree_case(
    name: &str,
    target_pat: Option<&'static str>,
    model: TreeModel,
    boundary: usize,
    reassembles: bool,
    fail_call: i32,
    repeats: usize,
    no_raw: bool,
    control_pat: &'static str,
    ack_pat: &'static str,
    with_control: bool,
    vouched: bool,
    tls12: bool,
    gap_ms: u64,
    long_ms: u64,
    include_trace: bool,
    sweep: TreeSweep,
    trigger_name: &str,
) {
    let trigger = Trigger {
        name: trigger_name.into(),
        payload: b"WA\x06\x03SIGNATURE-AND-THEN-SOME-PAYLOAD-BYTES".to_vec(),
        accept: Accept::ServerHello,
    };
    let control = with_control.then(|| Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Accept::Any,
    });
    let options = ClassifyOptions {
        repeats,
        timeout: Duration::from_millis(400),
        write_gap: Duration::from_millis(gap_ms),
        long_gap: Duration::from_millis(long_ms),
        allow_loopback: true,
        no_raw,
        full_detect_semantics: true,
        confirm_clear: false,
        control,
        control_vouched: vouched,
        cross_check_tls12: tls12,
        ..ClassifyOptions::default()
    };
    let mut backend = TreeBackend {
        model,
        boundary,
        reassembles,
        target_pat,
        fail_call,
        trigger_calls: 0,
        control_pat,
        control_calls: 0,
        ack_pat,
        ack_calls: 0,
        sweep,
        long_gap: Duration::from_millis(long_ms),
    };
    let result = run_with_backend_progress(
        "192.0.2.44:443",
        &trigger,
        options,
        &mut backend,
        &mut |_, _, _, _| {},
    );
    tree_print_result(name, &result, include_trace);
}

fn run_tree_diff() {
    run_tree_case(
        "no-sni-clear",
        Some("AAA"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        true,
        "+",
        "e",
        false,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "",
    );
    run_tree_case(
        "whole-packet",
        None,
        TreeModel::Whole,
        0,
        false,
        -1,
        3,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "prefix",
        None,
        TreeModel::Prefix,
        10,
        false,
        -1,
        3,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "prefix-reassemble",
        None,
        TreeModel::Prefix,
        5,
        true,
        -1,
        3,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "prefix-gaps",
        None,
        TreeModel::Prefix,
        10,
        false,
        -1,
        3,
        true,
        "+",
        "e",
        true,
        false,
        false,
        7,
        13,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "prefix-cross-tls12",
        None,
        TreeModel::Prefix,
        10,
        false,
        -1,
        3,
        true,
        "+",
        "e",
        true,
        false,
        true,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "prefix-r1",
        None,
        TreeModel::Prefix,
        10,
        false,
        -1,
        1,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "prefix-r2",
        None,
        TreeModel::Prefix,
        10,
        false,
        -1,
        2,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "partial-base",
        Some("ARA"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "partial-split",
        Some("RRRARA"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "split-error",
        Some("RRR"),
        TreeModel::None,
        0,
        false,
        3,
        3,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "long-error",
        Some("RRRAAA"),
        TreeModel::None,
        0,
        false,
        6,
        3,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "last-error",
        Some("RRRAAAAAA"),
        TreeModel::None,
        0,
        false,
        9,
        3,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "mid-partial",
        Some("RRRAAAAAARRRARA"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        true,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "no-control",
        Some("RRRRRR"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        true,
        "-",
        "e",
        false,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "control-dead",
        Some("RRRRRR"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        true,
        "-",
        "---",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "control-dead-vouched",
        Some("RRRRRR"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        true,
        "-",
        "---",
        true,
        true,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "ack-late",
        Some("RRRRRR"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        true,
        "-",
        "-+",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "ack-unseen",
        Some("RRRRRR"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        true,
        "-",
        "u",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "ack-error",
        Some("RRRRRR"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        true,
        "-",
        "e",
        true,
        false,
        false,
        2,
        10,
        true,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "raw-selftest-fail",
        Some("RRRRRR"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        false,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        false,
        TreeSweep::SelftestFail,
        "test",
    );
    run_tree_case(
        "raw-hit",
        Some("RRRRRR"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        false,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        false,
        TreeSweep::Hit("badsum+hello"),
        "test",
    );
    run_tree_case(
        "raw-miss",
        Some("RRRRRR"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        false,
        "+",
        "e",
        true,
        false,
        false,
        2,
        10,
        false,
        TreeSweep::None,
        "test",
    );
    run_tree_case(
        "raw-control-dead-hit",
        Some("RRRRRR"),
        TreeModel::None,
        0,
        false,
        -1,
        3,
        false,
        "-",
        "+",
        true,
        false,
        false,
        2,
        10,
        false,
        TreeSweep::Hit("badsum+hello"),
        "test",
    );
}

fn run_display_diff() {
    let mut result = classify::ClassifyResult::new("example.com:443", 3);
    result.verdict = classify::Verdict::Prefix;
    result.reason = "причина \"x\" \\ \u{1} префикс".into();
    result.probes = 9;
    result.duration = Duration::from_millis(42);
    result.boundary = Some(7);
    result.split_pos = Some(1);
    result.reassembles = Some(true);
    result.strategy =
        Some("--lua-desync=multisplit:payload=unknown:dir=out:pos=1".into());
    result.notes = vec![
        "оговорка с \"кавычкой\" и \\ обратной".into(),
        "вторая оговорка".into(),
    ];
    result.covers_tls12 = TriState::False;
    result.response = Some(response::ResponseResult {
        verdict: response::ResponseVerdict::Clear,
        reason: "ответное направление чисто".into(),
        target: 3,
        control: 2,
        probes: 0,
    });
    result.props = DpiProps {
        reassembles: TriState::True,
        parses_l7: TriState::False,
        validates_checksum: TriState::True,
        tolerates_reorder: TriState::Unset,
        hop_ttl: Some(5),
        ..DpiProps::default()
    };
    result.path = Some("перебор".into());
    result.composed = true;
    result.raw_usable = true;
    result.trace = vec![
        classify::Observation {
            probe: "whole".into(),
            cuts: Vec::new(),
            delay: Duration::from_millis(60),
            pass: 3,
            fail: 0,
            error: None,
        },
        classify::Observation {
            probe: "split".into(),
            cuts: vec![1, 2],
            delay: Duration::from_millis(60),
            pass: 2,
            fail: 1,
            error: Some("write: ошибка".into()),
        },
    ];
    let trigger = Trigger {
        name: "tls:example.com".into(),
        payload: vec![0; 41],
        accept: Accept::ServerHello,
    };
    print!(
        "{}{}",
        detect_cli::format_json(&result, 41),
        detect_cli::format_human(&result, &trigger, 41)
    );
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("tree-diff") {
        run_tree_diff();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("display-diff") {
        run_display_diff();
        return;
    }
    if let Ok(path) = std::env::var("R2O_CLASSIFIER_JSON_FIXTURE") {
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("read D2O classifier JSON"))
                .expect("parse D2O classifier JSON");
        let (mut result, trigger_len) = run_json_case();
        result.target = expected["target"].as_str().unwrap().to_owned();
        result.duration = Duration::ZERO;
        let mut actual = classify_json::result_json_value(&result, trigger_len);
        assert!(actual["duration"].as_str().unwrap().ends_with("ms"));
        actual["duration"] = expected["duration"].clone();
        assert_eq!(expected, actual, "R2O classifier JSON differs from D2O");
        println!("JSON|match");
    }

    if let Ok(path) = std::env::var("R2O_CLASSIFIER_COMPOSE_JSON_FIXTURE") {
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("read D2O composed JSON"))
                .expect("parse D2O composed JSON");
        let (result, trigger_len) = run_composed_json_case();
        let actual = classify_json::result_json_value(&result, trigger_len);
        assert_eq!(result.verdict, classify::Verdict::Poisonable);
        assert_eq!(expected["composed"], actual["composed"]);
        assert_eq!(expected["path"], actual["path"]);
        assert_eq!(expected["props"], actual["props"]);
        println!("COMPOSE_JSON|match");
    }

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

    let (progress_control_pass, progress_ack_calls, _) = run_case_with_progress(
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
        3,
        true,
    );
    println!(
        "{:?}|{}|{}",
        progress_control_pass.verdict, progress_control_pass.probes, progress_ack_calls
    );

    let (neutral_ack_progress, neutral_ack_calls, _) = run_case_with_progress(
        vec![Ok(ProbeOutcome::Rejected); 3],
        vec![Ok(false), Ok(true)],
        ProbeOutcome::Rejected,
        Accept::Any,
        None,
        None,
        3,
        true,
    );
    println!(
        "NeutralAck|{}|{}",
        neutral_ack_progress.probes, neutral_ack_calls
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

    let (progress_clear, progress_ack_calls, _) = run_case_with_progress(
        vec![],
        vec![],
        ProbeOutcome::Accepted,
        Accept::Any,
        None,
        None,
        3,
        true,
    );
    println!(
        "{:?}|{}|{}",
        progress_clear.verdict, progress_clear.probes, progress_ack_calls
    );
}
