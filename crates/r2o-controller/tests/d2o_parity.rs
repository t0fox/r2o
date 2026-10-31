use r2o_controller::classify::{
    Accept, ClassifyOptions, ProbeBackend, ProbeError, ProbeOutcome, ProbeRequest, Trigger,
    Verdict, run_with_backend,
};
use std::time::Duration;

struct Fixture {
    target: String,
    payload: Vec<u8>,
    repeats: usize,
    timeout: Duration,
    write_gap: Duration,
    allow_loopback: bool,
    mark: Option<u32>,
    outcomes: Vec<ProbeOutcome>,
}

fn fixture() -> Fixture {
    let values = include_str!("fixtures/d2o_clear.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once('=').expect("fixture key=value"))
        .collect::<std::collections::HashMap<_, _>>();
    let payload = values["payload_hex"]
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hex = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(hex, 16).unwrap()
        })
        .collect();
    Fixture {
        target: values["target"].into(),
        payload,
        repeats: values["repeats"].parse().unwrap(),
        timeout: Duration::from_millis(values["timeout_ms"].parse().unwrap()),
        write_gap: Duration::from_millis(values["write_gap_ms"].parse().unwrap()),
        allow_loopback: values["allow_loopback"] == "true",
        mark: Some(values["mark"].parse().unwrap()),
        outcomes: values["outcomes"]
            .bytes()
            .map(|outcome| match outcome {
                b'+' => ProbeOutcome::Accepted,
                b'-' => ProbeOutcome::Rejected,
                _ => panic!("unsupported fixture outcome"),
            })
            .collect(),
    }
}

struct ScriptedBackend {
    fixture: Fixture,
    calls: usize,
}

impl ProbeBackend for ScriptedBackend {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(self.probe_outcome(request)? == ProbeOutcome::Accepted)
    }

    fn probe_outcome(&mut self, request: ProbeRequest<'_>) -> Result<ProbeOutcome, ProbeError> {
        assert_eq!(request.target.host, "127.0.0.1");
        assert_eq!(request.target.port, 37229);
        assert_eq!(request.trigger.payload, self.fixture.payload);
        assert_eq!(request.mark, self.fixture.mark);
        assert_eq!(request.timeout, self.fixture.timeout);
        assert_eq!(request.gap, self.fixture.write_gap);
        let outcome = self.fixture.outcomes[self.calls.min(self.fixture.outcomes.len() - 1)];
        self.calls += 1;
        Ok(outcome)
    }
}

#[test]
fn d2o_clear_vector_uses_only_the_base_series_and_ignores_disabled_mark() {
    let fixture = fixture();
    let target = fixture.target.clone();
    let repeats = fixture.repeats;
    let trigger = Trigger {
        name: "test".into(),
        payload: fixture.payload.clone(),
        accept: Accept::Any,
    };
    let mut backend = ScriptedBackend { fixture, calls: 0 };
    let result = run_with_backend(
        &target,
        &trigger,
        ClassifyOptions {
            repeats,
            timeout: backend.fixture.timeout,
            write_gap: backend.fixture.write_gap,
            long_gap: Duration::from_millis(10),
            allow_loopback: backend.fixture.allow_loopback,
            no_raw: true,
            confirm_clear: false,
            mark: backend.fixture.mark,
            ..ClassifyOptions::default()
        },
        &mut backend,
    );

    assert_eq!(result.verdict, Verdict::Clear);
    assert_eq!(result.probes, repeats);
    assert_eq!(backend.calls, repeats);
    if let Some(path) = std::env::var_os("R2O_CLEAR_DIFF_OUTPUT") {
        std::fs::write(
            path,
            format!(
                "clear probes={} repeats={} mark={} target={}\n",
                result.probes,
                result.repeats,
                backend.fixture.mark.unwrap_or_default(),
                result.target
            ),
        )
        .unwrap();
    }
}
