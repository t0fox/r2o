use r2o_controller::classify::{
    Accept, ClassifyOptions, DpiProps, Poison, ProbeBackend, ProbeError, ProbeOutcome,
    ProbeRequest, ProbeTarget, Span, TriState, Trigger, Verdict, note_props_hit, note_props_miss,
    plan_bytes_for_poison, poison_has_fake, poison_supports_family, poisons, run, run_with_backend,
    split_offsets, strategy_for_poison, trigger_accepts,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;

struct PrefixMatcher {
    signature_len: usize,
}

impl ProbeBackend for PrefixMatcher {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(request
            .cuts
            .first()
            .is_some_and(|cut| *cut < self.signature_len))
    }
}

struct WholePacketMatcher;

impl ProbeBackend for WholePacketMatcher {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(!request.cuts.is_empty())
    }
}

struct OpaqueMatcher;

impl ProbeBackend for OpaqueMatcher {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(request.trigger.name == "control")
    }
}

struct MixedControl {
    control_probes: usize,
}

struct UnprovenControl;

impl ProbeBackend for UnprovenControl {
    fn probe(&mut self, _request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(false)
    }

    fn probe_outcome(&mut self, request: ProbeRequest<'_>) -> Result<ProbeOutcome, ProbeError> {
        Ok(if request.trigger.name == "control" {
            ProbeOutcome::Unproven
        } else {
            ProbeOutcome::Rejected
        })
    }

    fn neutral_ack(
        &mut self,
        _target: &ProbeTarget,
        _timeout: Duration,
        _mark: Option<u32>,
        _cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<bool, ProbeError> {
        Ok(false)
    }
}

struct UnprovenTrigger;

impl ProbeBackend for UnprovenTrigger {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(request.trigger.name == "control")
    }

    fn probe_outcome(&mut self, request: ProbeRequest<'_>) -> Result<ProbeOutcome, ProbeError> {
        Ok(if request.trigger.name == "control" {
            ProbeOutcome::Accepted
        } else {
            ProbeOutcome::Unproven
        })
    }
}

struct PartialBaseFailure {
    trigger_probes: usize,
}

impl ProbeBackend for PartialBaseFailure {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        if request.trigger.name == "control" {
            return Ok(true);
        }
        self.trigger_probes += 1;
        if self.trigger_probes == 1 {
            Err(ProbeError::Transport("test connection failure".into()))
        } else {
            Ok(false)
        }
    }
}

impl ProbeBackend for MixedControl {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        if request.trigger.name == "control" {
            self.control_probes += 1;
            Ok(self.control_probes == 1)
        } else {
            Ok(false)
        }
    }
}

struct AddressBlocked;

impl ProbeBackend for AddressBlocked {
    fn probe(&mut self, _request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(false)
    }

    fn neutral_ack(
        &mut self,
        _target: &ProbeTarget,
        _timeout: Duration,
        _mark: Option<u32>,
        _cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<bool, ProbeError> {
        Ok(false)
    }
}

struct ControlSilent;

impl ProbeBackend for ControlSilent {
    fn probe(&mut self, _request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(false)
    }
}

struct RawSelftestFailure;

impl ProbeBackend for RawSelftestFailure {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(request.trigger.name == "control")
    }

    fn raw_supported(&self) -> bool {
        true
    }

    fn sweep_poisons(
        &mut self,
        _target: &ProbeTarget,
        _trigger: &Trigger,
        _options: &ClassifyOptions,
        _result: &mut r2o_controller::classify::ClassifyResult,
    ) -> Result<Option<r2o_controller::classify::PoisonHit>, ProbeError> {
        Err(ProbeError::Unsupported("raw handshake unavailable".into()))
    }
}

struct MeasuredPoisonHit;

impl ProbeBackend for MeasuredPoisonHit {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(request.trigger.name == "control")
    }

    fn raw_supported(&self) -> bool {
        true
    }

    fn sweep_poisons(
        &mut self,
        _target: &ProbeTarget,
        trigger: &Trigger,
        _options: &ClassifyOptions,
        _result: &mut r2o_controller::classify::ClassifyResult,
    ) -> Result<Option<r2o_controller::classify::PoisonHit>, ProbeError> {
        let poison = Poison {
            name: "badsum".into(),
            badsum: true,
            ..Poison::default()
        };
        let plan = plan_bytes_for_poison(&poison, trigger, None, 0).map_err(ProbeError::Local)?;
        let plan_text = r2o_controller::classify::plan_text_for_poison(&poison, trigger, None, 0)
            .map_err(ProbeError::Local)?;
        Ok(Some(r2o_controller::classify::PoisonHit {
            name: poison.name,
            strategy: "--lua-desync=multisplit:badsum".into(),
            plan_text,
            plan,
        }))
    }
}

struct AlwaysPass;

impl ProbeBackend for AlwaysPass {
    fn probe(&mut self, _request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        Ok(true)
    }
}

struct FailConfirmation {
    probes: usize,
}

impl ProbeBackend for FailConfirmation {
    fn probe(&mut self, _request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        self.probes += 1;
        Ok(self.probes <= 2)
    }
}

struct DialTimeouts(Vec<Duration>);

impl ProbeBackend for DialTimeouts {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        self.0.push(request.timeout);
        Err(ProbeError::DialTimeout(
            "dial tcp 203.0.113.10:443: i/o timeout".into(),
        ))
    }
}

fn test_options() -> ClassifyOptions {
    ClassifyOptions {
        repeats: 2,
        timeout: Duration::from_millis(900),
        write_gap: Duration::from_millis(10),
        long_gap: Duration::from_millis(40),
        allow_loopback: true,
        no_raw: true,
        mark: Some(0),
        ..ClassifyOptions::default()
    }
}

fn test_trigger() -> Trigger {
    Trigger {
        name: "test".into(),
        payload: b"WA\x06\x03SIGNATURE-AND-THEN-SOME-PAYLOAD-BYTES".to_vec(),
        accept: Default::default(),
    }
}

#[test]
fn split_offsets_sorts_deduplicates_and_discards_edge_cuts() {
    assert_eq!(
        split_offsets(&[4, 0, 2, 4, 10, usize::MAX], 10, 8),
        [
            Span { from: 0, to: 2 },
            Span { from: 2, to: 4 },
            Span { from: 4, to: 10 },
        ]
    );
}

#[test]
fn split_offsets_keeps_the_donors_eight_cut_limit_and_output_capacity() {
    assert_eq!(
        split_offsets(&[1, 2, 3, 4, 5, 6, 7, 8, 9], 10, 8),
        (0..8)
            .map(|from| Span { from, to: from + 1 })
            .collect::<Vec<_>>()
    );
    assert_eq!(split_offsets(&[2, 5], 10, 1), [Span { from: 0, to: 2 }]);
    assert!(split_offsets(&[2, 5], 10, 0).is_empty());
}

#[test]
fn split_offsets_without_valid_cuts_returns_the_whole_payload() {
    assert_eq!(
        split_offsets(&[0, 6, usize::MAX], 6, 8),
        [Span { from: 0, to: 6 }]
    );
}

#[test]
fn prefix_matcher_finds_the_first_blocked_split_boundary() {
    let trigger = test_trigger();
    let mut backend = PrefixMatcher { signature_len: 4 };
    let result = run_with_backend("192.0.2.10:443", &trigger, test_options(), &mut backend);

    assert_eq!(result.verdict, Verdict::Prefix);
    assert_eq!(result.boundary, Some(4));
    assert_eq!(result.split_pos, Some(1));
    assert_eq!(
        result.strategy.as_deref(),
        Some("--lua-desync=multisplit:payload=unknown:dir=out:pos=1")
    );
}

#[test]
fn target_loopback_guard_stops_before_any_probe() {
    let trigger = test_trigger();
    let mut backend = PrefixMatcher { signature_len: 4 };
    let mut options = test_options();
    options.allow_loopback = false;
    let result = run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Flaky);
    assert_eq!(result.probes, 0);
}

#[test]
fn packet_matcher_is_distinguished_from_a_prefix_matcher() {
    let trigger = test_trigger();
    let mut backend = WholePacketMatcher;
    let result = run_with_backend("192.0.2.10:443", &trigger, test_options(), &mut backend);

    assert_eq!(result.verdict, Verdict::WholePacket);
    assert_eq!(result.split_pos, Some(1));
    assert_eq!(result.boundary, None);
}

#[test]
fn an_answering_control_and_failed_split_produce_opaque_without_a_plan() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.control = Some(Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Default::default(),
    });
    let mut backend = OpaqueMatcher;
    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Opaque);
    assert!(result.strategy.is_none());
    assert!(result.reassembles.is_none());
}

#[test]
fn mixed_control_repeats_are_flaky_instead_of_a_positive_control() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.control = Some(Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Default::default(),
    });
    let mut backend = MixedControl { control_probes: 0 };

    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Flaky);
    assert!(result.reason.contains("контроль"));
    let observation = result
        .trace
        .iter()
        .find(|observation| observation.probe == "control")
        .unwrap();
    assert_eq!(observation.pass, 1);
    assert_eq!(observation.fail, 1);
    assert_eq!(backend.control_probes, 2);
}

#[test]
fn unrecognized_control_replies_are_inconclusive_not_address_blocking() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.control = Some(Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Accept::TlsRecord,
    });
    let mut backend = UnprovenControl;

    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert!(result.reason.contains("не записью TLS"));
    assert!(
        !result
            .trace
            .iter()
            .any(|probe| probe.probe == "neutral-ack")
    );
}

#[test]
fn unrecognized_trigger_reply_prevents_an_opaque_verdict() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.control = Some(Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Accept::TlsRecord,
    });
    let mut backend = UnprovenTrigger;

    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert!(result.reason.contains("на триггер ответили"));
}

#[test]
fn partial_base_transport_errors_continue_to_the_split_measurement() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.control = Some(Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Default::default(),
    });
    let mut backend = PartialBaseFailure { trigger_probes: 0 };

    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Opaque);
    assert_eq!(result.probes, 6);
    assert!(result.trace[0].error.is_some());
    assert_eq!(result.trace[1].probe, "split");
}

#[test]
fn raw_selftest_failure_is_visible_and_does_not_claim_a_completed_sweep() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.control = Some(Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Default::default(),
    });
    options.no_raw = false;
    let mut backend = RawSelftestFailure;
    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Opaque);
    assert!(!result.raw_usable);
    assert!(result.reason.contains("raw handshake unavailable"));
    assert!(result.trace.iter().any(|probe| {
        probe.probe == "raw-selftest" && probe.error.as_deref() == Some("raw handshake unavailable")
    }));
}

#[test]
fn measured_poison_result_exposes_a_plan_accepted_by_the_datapath_parser() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.control = Some(Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Default::default(),
    });
    options.no_raw = false;
    let mut backend = MeasuredPoisonHit;

    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Poisonable);
    let hit = result.hit.as_ref().unwrap();
    assert_eq!(r2k_core::plan::Plan::parse(&hit.plan).unwrap().proto, 1);
    assert_eq!(
        r2o_controller::plan_text::compile_text(&hit.plan_text).unwrap(),
        hit.plan
    );
}

#[test]
fn failed_control_without_ack_support_is_inconclusive() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.control = Some(Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Default::default(),
    });
    let mut backend = ControlSilent;
    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert!(
        result
            .trace
            .iter()
            .any(|probe| probe.probe == "neutral-ack")
    );
    assert!(result.strategy.is_none());
}

#[test]
fn no_tcp_ack_for_trigger_or_control_is_an_address_verdict() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.control = Some(Trigger {
        name: "control".into(),
        payload: b"BENIGN-CONTROL-PAYLOAD".to_vec(),
        accept: Default::default(),
    });
    let mut backend = AddressBlocked;
    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Address);
    assert_eq!(result.trace.last().unwrap().fail, 2);
}

#[test]
fn seeded_whole_measurement_is_reused_and_still_gets_confirmation() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.mark = Some(0x2d);
    options.seed_whole = Some(r2o_controller::classify::SeedWhole {
        repeats: options.repeats,
        pass: options.repeats,
        fail: 0,
        errors: 0,
        error: None,
    });
    let mut backend = AlwaysPass;
    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Clear);
    assert_eq!(result.probes, 2);
    assert_eq!(result.trace[0].pass, 2);
    assert_eq!(result.trace[1].probe, "whole-confirm");
    assert_eq!(result.trace[1].pass, 2);
}

#[test]
fn clear_requires_two_more_successful_probes() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.mark = Some(0x2d);
    let mut backend = AlwaysPass;

    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Clear);
    assert_eq!(result.probes, 4);
    assert_eq!(result.trace[1].probe, "whole-confirm");
    assert_eq!(result.trace[1].pass, 2);
}

#[test]
fn failed_clear_confirmation_is_flaky() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.mark = Some(0x2d);
    let mut backend = FailConfirmation { probes: 0 };

    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Flaky);
    assert!(result.reason.contains("подтвердилась"));
    assert_eq!(result.probes, 4);
    assert_eq!(result.trace[1].pass, 0);
    assert_eq!(result.trace[1].fail, 2);
}

#[test]
fn unmarked_baseline_cannot_be_reported_clear() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.mark = Some(0);
    let mut backend = AlwaysPass;

    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert!(result.reason.contains("метк"));
    assert_eq!(result.probes, 4);
}

#[test]
fn only_our_connect_deadline_gets_one_doubled_retry_and_stays_flaky() {
    let trigger = test_trigger();
    let options = test_options();
    let initial_timeout = options.timeout;
    let mut backend = DialTimeouts(Vec::new());
    let result = run_with_backend("203.0.113.10:443", &trigger, options, &mut backend);

    assert_eq!(result.verdict, Verdict::Flaky);
    assert!(result.reason.contains("замер не состоялся"));
    assert_eq!(result.probes, 4);
    assert_eq!(
        backend.0,
        [
            initial_timeout,
            initial_timeout,
            initial_timeout * 2,
            initial_timeout * 2
        ]
    );
}

#[test]
fn cancellation_marks_the_result_and_skips_all_network_probes() {
    let trigger = test_trigger();
    let mut options = test_options();
    options.cancel = Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        true,
    )));
    let mut backend = PrefixMatcher { signature_len: 4 };
    let result = run_with_backend("192.0.2.10:443", &trigger, options, &mut backend);

    assert!(result.stopped);
    assert_eq!(result.probes, 0);
    assert!(result.strategy.is_none());
}

#[test]
fn trigger_acceptance_matches_the_donor_rules() {
    assert!(trigger_accepts(Accept::Any, b"x"));
    assert!(!trigger_accepts(Accept::Any, b""));
    assert!(trigger_accepts(
        Accept::ServerHello,
        &[0x16, 0x03, 0, 0, 0, 0x02]
    ));
    assert!(!trigger_accepts(
        Accept::ServerHello,
        &[0x16, 0x03, 0, 0, 0, 0x15]
    ));
    assert!(trigger_accepts(Accept::TlsRecord, &[0x15, 0x03, 0]));
    assert!(trigger_accepts(Accept::TlsRecord, &[0x16, 0x03, 0]));
    assert!(!trigger_accepts(Accept::TlsRecord, &[0x17, 0x03, 0]));
}

#[test]
fn живой_clienthello_становится_точным_триггером_классификатора() {
    let captured = r2o_controller::hello::modern_client_hello("example.test").unwrap();
    let trigger = Trigger::tls_client_hello("example.test", &captured).unwrap();

    assert_eq!(trigger.payload, captured);
    assert_eq!(trigger.accept, Accept::ServerHello);
    assert!(Trigger::tls_client_hello("other.test", &trigger.payload).is_err());
    assert!(Trigger::tls_client_hello("example.test", &trigger.payload[..20]).is_err());
}

#[test]
fn poison_catalog_keeps_the_donor_order_and_all_85_unique_hypotheses() {
    let candidates = poisons();
    assert_eq!(candidates.len(), 85);
    assert_eq!(candidates[0].name, "seqovl-1");
    assert_eq!(candidates[1].name, "badsum-x2-g20");
    assert_eq!(candidates[2].name, "badsum-x2-g80");
    assert_eq!(candidates[3].name, "badsum-x7");
    assert_eq!(candidates.last().unwrap().name, "badsum+hello");
    for (index, left) in candidates.iter().enumerate() {
        assert!(
            candidates[index + 1..]
                .iter()
                .all(|right| !left.same_hypothesis(right))
        );
    }
}

#[test]
fn poison_strategy_preserves_measured_repeat_timestamp_and_ipid_fields() {
    let candidates = poisons();
    let badsum = candidates
        .iter()
        .find(|poison| poison.name == "badsum-x2-g20")
        .unwrap();
    assert!(poison_has_fake(badsum));
    assert!(strategy_for_poison(badsum).unwrap().contains(":repeats=2"));
    let timestamp = candidates
        .iter()
        .find(|poison| poison.name == "badsum+ts")
        .unwrap();
    assert!(poison_has_fake(timestamp));
    assert!(
        strategy_for_poison(timestamp)
            .unwrap()
            .contains(":tcp_ts=-1000")
    );
    let ipid = candidates
        .iter()
        .find(|poison| poison.name == "badsum+ipid")
        .unwrap();
    assert!(strategy_for_poison(ipid).unwrap().contains(":ip_id=zero"));
    assert!(!poison_supports_family(ipid, 6));
    assert!(poison_supports_family(ipid, 4));
}

#[test]
fn poison_outcomes_update_only_properties_they_prove() {
    let candidates = poisons();
    let checksum = candidates
        .iter()
        .find(|poison| poison.name == "badsum")
        .unwrap();
    let disorder = candidates
        .iter()
        .find(|poison| poison.name == "disorder")
        .unwrap();
    let overlap = candidates
        .iter()
        .find(|poison| poison.name == "seqovl-16")
        .unwrap();
    let timestamp = candidates
        .iter()
        .find(|poison| poison.name == "ttl-62")
        .unwrap();
    let decoy = candidates
        .iter()
        .find(|poison| poison.name == "seqovl-2+hello")
        .unwrap();

    let mut properties = DpiProps::default();
    note_props_miss(&mut properties, checksum);
    assert_eq!(properties.validates_checksum, TriState::Unset);
    note_props_hit(&mut properties, checksum);
    assert_eq!(properties.validates_checksum, TriState::False);
    note_props_hit(&mut properties, disorder);
    assert_eq!(properties.tolerates_reorder, TriState::False);
    note_props_miss(&mut properties, overlap);
    assert_eq!(properties.tolerates_left_overlap, TriState::True);
    note_props_hit(&mut properties, timestamp);
    assert_eq!(properties.hop_ttl, Some(62));
    note_props_hit(&mut properties, decoy);
    assert_eq!(properties.parses_l7, TriState::True);
}

#[test]
fn tls_trigger_uses_the_captured_profile_and_serverhello_acceptance() {
    let trigger = Trigger::tls("youtube.com").unwrap();
    assert_eq!(trigger.name, "tls:youtube.com");
    assert_eq!(trigger.accept, Accept::ServerHello);
    assert_eq!(
        trigger.payload,
        include_bytes!("fixtures/legacy-youtube-c.bin")
    );
}

#[test]
fn live_tcp_backend_runs_base_and_confirmation_with_the_original_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let payload = b"baseline trigger".to_vec();
    let expected_payload = payload.clone();
    let server = thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; expected_payload.len()];
            stream.read_exact(&mut received).unwrap();
            assert_eq!(received, expected_payload);
            stream.write_all(b"accepted").unwrap();
        }
    });

    let trigger = Trigger {
        name: "test".into(),
        payload,
        accept: Accept::Any,
    };
    let options = ClassifyOptions {
        allow_loopback: true,
        mark: Some(0),
        ..test_options()
    };
    let result = run(&format!("{address}"), &trigger, options);
    server.join().unwrap();

    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert_eq!(result.probes, 4);
}

#[test]
fn live_neutral_ack_confirms_delivery_even_when_control_is_silent() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut first_byte = [0];
            stream.read_exact(&mut first_byte).unwrap();
        }
    });
    let mut options = ClassifyOptions {
        repeats: 1,
        timeout: Duration::from_millis(30),
        write_gap: Duration::from_millis(1),
        long_gap: Duration::from_millis(2),
        allow_loopback: true,
        mark: Some(0),
        ..ClassifyOptions::default()
    };
    options.control = Some(Trigger {
        name: "control".into(),
        payload: b"control bytes".to_vec(),
        accept: Accept::Any,
    });
    let result = run(&format!("{address}"), &test_trigger(), options);
    server.join().unwrap();

    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert!(result.trace.iter().any(|observation| {
        observation.probe == "neutral-ack" && observation.pass == 1 && observation.fail == 0
    }));
}

#[test]
fn classify_cli_runs_the_tls_probe_and_reports_the_response_check() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        for index in 0..6 {
            let deadline = Instant::now() + Duration::from_secs(3);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return index;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            let mut header = [0; 5];
            stream.read_exact(&mut header).unwrap();
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let response = if index < 4 {
                vec![0x16, 0x03, 0x03, 0, 1, 2]
            } else {
                vec![0x16, 0x03, 0x03, 0, 4, 14, 0, 0, 0]
            };
            stream.write_all(&response).unwrap();
        }
        6
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--classify",
            "127.0.0.1",
            &port.to_string(),
            "youtube.com",
            "1",
            "--allow-loopback",
        ])
        .output()
        .unwrap();
    let accepted = server.join().unwrap();

    assert!(
        output.status.success(),
        "accepted={accepted}; {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("вердикт: clear"), "{stdout}");
    assert!(stdout.contains("зонды: 6"), "{stdout}");
    assert!(stdout.contains("ответное направление"), "{stdout}");
}
