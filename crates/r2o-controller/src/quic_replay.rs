//! Повторить ограниченный снимок QUIC Initial через заранее занятый UDP-сокет.

use r2k_core::quic::{R2kQuicDataVerdict, r2k_quic_data_judge};
use r2k_core::quic_snapshot::{
    r2k_quic_snapshot_parse, r2k_quic_snapshot_reseal, r2k_quic_snapshot_verify_bound_response,
};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const R2O_QUIC_REPLAY_DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
const R2O_QUIC_REPLAY_MAX_TIMEOUT: Duration = Duration::from_secs(10);
const R2O_QUIC_REPLAY_MAX_RESPONSE: usize = 65_535;
pub const R2O_QUIC_FRAGMENT_CONTROL_NAME: &str = "контроль прохождения IP-фрагментов, форма 1";

/// Сформировать QSN с новым QUIC v1 Initial для холодного старта Discovery.
pub fn r2o_quic_profile_snapshot(server_name: Option<&str>) -> Option<Vec<u8>> {
    let provider = rustls::crypto::ring::default_provider();
    let mut random = [0; 32];
    provider.secure_random.fill(&mut random).ok()?;
    let mut source_connection_id = [0; 8];
    provider
        .secure_random
        .fill(&mut source_connection_id)
        .ok()?;
    let key_exchange = rustls::crypto::ring::kx_group::X25519.start().ok()?;
    let public_key: [u8; 32] = key_exchange.pub_key().try_into().ok()?;

    let mut extra_extensions = Vec::with_capacity(56);
    extra_extensions.extend_from_slice(&[0, 0x39, 0, 52]);
    extra_extensions.extend_from_slice(&[
        0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x03, 0x02, 0x45, 0xc0, 0x04, 0x04, 0x80, 0x10, 0x00,
        0x00, 0x05, 0x04, 0x80, 0x04, 0x00, 0x00, 0x06, 0x04, 0x80, 0x04, 0x00, 0x00, 0x07, 0x04,
        0x80, 0x04, 0x00, 0x00, 0x08, 0x02, 0x40, 0x64, 0x09, 0x02, 0x40, 0x64, 0x0f, 0x08,
    ]);
    extra_extensions.extend_from_slice(&source_connection_id);
    let client_hello =
        crate::r2o_tls::r2o_tls13_client_hello(&crate::r2o_tls::R2oTls13ClientHelloOptions {
            server_name,
            public_key: &public_key,
            random: &random,
            session_id_len: 0,
            offer_tls12: false,
            alpn: Some("h3"),
            alpn_wire: None,
            extra_extensions: &extra_extensions,
            pad_to: 0,
        })
        .ok()?;
    let initial =
        r2k_core::quic::r2k_quic_initial_build(&client_hello, &source_connection_id, 1200)?;
    r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[&initial])
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuicReplayResult {
    pub sent_datagrams: usize,
    pub foreign_responses: usize,
    pub handshake_confirmed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oQuicFilterDecision {
    Pass,
    No,
    Retry,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oQuicCandidateKind {
    TtlStrategy,
    Clearance,
    SplitCrypto,
    UdpLength,
    FragmentControl,
    FragmentShape(u8),
    OriginalSingle(u8),
    OriginalRepeats { blob: u8, copies: u8 },
    AdaptiveSplit,
    OriginalTtl(u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oQuicDiscoveryCandidate {
    pub kind: R2oQuicCandidateKind,
    pub name: String,
    pub directives: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oQuicFilterResult {
    pub decision: R2oQuicFilterDecision,
    pub answered: usize,
    pub measured: usize,
}

const R2O_QUIC_ORIGINAL_BLOBS: [&[u8]; 4] = [
    include_bytes!("../../r2k-core/src/quic/quic_ttl_probe.bin"),
    include_bytes!("../../r2k-core/src/quic/quic_google.bin"),
    include_bytes!("../../r2k-core/src/quic/quic_rutracker.bin"),
    include_bytes!("../../r2k-core/src/quic/quic_default.bin"),
];

/// Классифицировать серию повторов для одного QUIC-вопроса.
pub fn r2o_quic_filter_round_decision(
    answered: usize,
    measured: usize,
    attempt: usize,
    repeats: usize,
) -> R2oQuicFilterDecision {
    if repeats == 0 || answered > measured || measured > repeats || attempt > 1 {
        return R2oQuicFilterDecision::Unknown;
    }
    if measured != repeats {
        return if attempt == 0 {
            R2oQuicFilterDecision::Retry
        } else {
            R2oQuicFilterDecision::Unknown
        };
    }
    if answered == repeats {
        R2oQuicFilterDecision::Pass
    } else if answered == 0 {
        R2oQuicFilterDecision::No
    } else if attempt == 0 {
        R2oQuicFilterDecision::Retry
    } else {
        R2oQuicFilterDecision::Unknown
    }
}

/// Разрешить формы IP-фрагментации только после успешного фильтра и точного подтверждения.
pub fn r2o_quic_fragment_control_succeeded(
    filter_decision: R2oQuicFilterDecision,
    exact_applied: bool,
) -> bool {
    filter_decision == R2oQuicFilterDecision::Pass && exact_applied
}

/// Учесть результат фильтра и этапа данных для одного вопроса стратегии.
pub fn r2o_quic_strategy_attempt_decision(
    filter_decision: R2oQuicFilterDecision,
    data_verdict: Option<R2kQuicDataVerdict>,
    attempt: usize,
) -> R2oQuicFilterDecision {
    if attempt > 1 {
        return R2oQuicFilterDecision::Unknown;
    }
    if filter_decision == R2oQuicFilterDecision::No {
        return R2oQuicFilterDecision::No;
    }
    if filter_decision == R2oQuicFilterDecision::Unknown {
        return R2oQuicFilterDecision::Unknown;
    }
    if filter_decision == R2oQuicFilterDecision::Retry {
        return if attempt == 0 {
            R2oQuicFilterDecision::Retry
        } else {
            R2oQuicFilterDecision::Unknown
        };
    }
    if filter_decision != R2oQuicFilterDecision::Pass {
        return R2oQuicFilterDecision::Unknown;
    }
    let Some(data_verdict) = data_verdict else {
        return R2oQuicFilterDecision::Unknown;
    };
    if data_verdict == R2kQuicDataVerdict::Pass {
        return R2oQuicFilterDecision::Pass;
    }
    if data_verdict == R2kQuicDataVerdict::NoHandshake || data_verdict == R2kQuicDataVerdict::Cut {
        return R2oQuicFilterDecision::No;
    }
    if data_verdict == R2kQuicDataVerdict::NotRun && attempt == 0 {
        return R2oQuicFilterDecision::Retry;
    }
    R2oQuicFilterDecision::Unknown
}

/// Разрешить сохранение QUIC-плана только при рукопожатии, HTTP/3-успехе и точном APPLIED.
pub fn r2o_quic_data_proof_confirmed(
    handshake_confirmed: bool,
    applied: bool,
    data_verdict: R2kQuicDataVerdict,
) -> bool {
    handshake_confirmed && applied && matches!(data_verdict, R2kQuicDataVerdict::Pass)
}

/// Применить вердикт HTTP/3 с ограничением полноты для повторного бюджета.
pub fn r2o_quic_trial_data_verdict(
    result: &crate::r2o_quic_http3::R2oQuicHttp3Result,
) -> R2kQuicDataVerdict {
    r2k_quic_data_judge(
        result.handshake_confirmed,
        result.status,
        result.body_bytes,
        result.complete,
        result.r2o_quic_stalled,
        result.budget_required,
        false,
        result.budget_passed,
    )
}

/// Построить начальные QUIC-вопросы по порядку донорской стратегии.
pub fn r2o_quic_discovery_candidates(
    baseline: &crate::r2o_quic_http3::R2oQuicHttp3Result,
    split_applicable: bool,
) -> Vec<R2oQuicDiscoveryCandidate> {
    let stalled = baseline.handshake_confirmed && baseline.r2o_quic_stalled;
    let mut candidates = Vec::with_capacity(4);
    if stalled {
        candidates.push(r2o_quic_blob_candidate(
            R2oQuicCandidateKind::TtlStrategy,
            "фальшивка quic5 ×2, TTL 3",
            0,
            2,
            Some(3),
            false,
        ));
    }
    candidates.push(r2o_quic_blob_candidate(
        R2oQuicCandidateKind::Clearance,
        "безобидная датаграмма",
        4,
        1,
        None,
        false,
    ));
    if split_applicable {
        candidates.push(R2oQuicDiscoveryCandidate {
            kind: R2oQuicCandidateKind::SplitCrypto,
            name: "разрез ClientHello по CRYPTO".to_owned(),
            directives: "quicsplit 1\n".to_owned(),
        });
    }
    candidates.push(R2oQuicDiscoveryCandidate {
        kind: R2oQuicCandidateKind::UdpLength,
        name: "удлинение UDP на 100 байт".to_owned(),
        directives: "udplen 100\n".to_owned(),
    });
    candidates
}

/// Построить отдельный контроль и формы фрагментации по очереди.
pub fn r2o_quic_fragment_candidates() -> Vec<R2oQuicDiscoveryCandidate> {
    let mut candidates = Vec::with_capacity(5);
    candidates.push(R2oQuicDiscoveryCandidate {
        kind: R2oQuicCandidateKind::FragmentControl,
        name: R2O_QUIC_FRAGMENT_CONTROL_NAME.to_owned(),
        directives: "ipfrag 1\n".to_owned(),
    });
    candidates.extend((1..=4).map(|shape| R2oQuicDiscoveryCandidate {
        kind: R2oQuicCandidateKind::FragmentShape(shape),
        name: format!("IP-фрагментация, форма {shape}"),
        directives: format!("ipfrag {shape}\n"),
    }));
    candidates
}

/// Построить резервный перебор образцов и пропустить уже заданные вопросы.
pub fn r2o_quic_original_fallback_candidates(
    benign_asked: bool,
    ttl_three_answered_no: bool,
    fragment_questions_used: bool,
) -> Vec<R2oQuicDiscoveryCandidate> {
    let mut candidates = Vec::with_capacity(18);
    for blob in 0..5 {
        if blob == 4 && benign_asked {
            continue;
        }
        candidates.push(r2o_quic_blob_candidate(
            R2oQuicCandidateKind::OriginalSingle(blob),
            r2o_quic_blob_name(blob),
            blob,
            1,
            None,
            false,
        ));
    }
    for blob in [0, 3] {
        for copies in [6, 11] {
            candidates.push(r2o_quic_blob_candidate(
                R2oQuicCandidateKind::OriginalRepeats { blob, copies },
                format!("{} ×{copies}", r2o_quic_blob_name(blob)),
                blob,
                copies,
                None,
                false,
            ));
        }
    }
    for ttl in [3, 5, 8, 12] {
        if ttl == 3 && ttl_three_answered_no {
            continue;
        }
        candidates.push(r2o_quic_blob_candidate(
            R2oQuicCandidateKind::OriginalTtl(ttl),
            format!("quic5 ×2, TTL {ttl}"),
            0,
            2,
            Some(ttl),
            false,
        ));
    }
    if !fragment_questions_used {
        candidates.extend(r2o_quic_fragment_candidates());
    }
    candidates
}

/// Создать измеряемое сочетание исходной приманки и разреза CRYPTO.
pub fn r2o_quic_adaptive_split_candidate() -> R2oQuicDiscoveryCandidate {
    r2o_quic_blob_candidate(
        R2oQuicCandidateKind::AdaptiveSplit,
        "fake_default ×11 с разрезом CRYPTO",
        3,
        11,
        None,
        true,
    )
}

/// Проверить точное условие адаптивного вопроса `fake_default ×11` с CRYPTO.
pub fn r2o_quic_adaptive_split_eligible(
    split_decision: R2oQuicFilterDecision,
    split_applicable: bool,
    answered: usize,
    measured: usize,
    data_verdict: Option<R2kQuicDataVerdict>,
) -> bool {
    split_decision == R2oQuicFilterDecision::No
        && split_applicable
        && answered > 0
        && ((measured == 3 && answered < 3)
            || matches!(
                data_verdict,
                Some(R2kQuicDataVerdict::Cut | R2kQuicDataVerdict::NoHandshake)
            ))
}

fn r2o_quic_blob_candidate(
    kind: R2oQuicCandidateKind,
    name: impl Into<String>,
    blob: u8,
    copies: u8,
    ttl: Option<u8>,
    split: bool,
) -> R2oQuicDiscoveryCandidate {
    let benign = blob == 4;
    let bytes: &[u8] = if benign {
        &[0; 16]
    } else {
        R2O_QUIC_ORIGINAL_BLOBS[usize::from(blob)]
    };
    let payload = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut directives = format!("payload 1 {payload}\n");
    if split {
        directives.push_str("quicsplit 1\n");
    }
    let poison_id = if let Some(ttl) = ttl {
        directives.push_str(&format!("poison 1 ttl={ttl}\n"));
        1
    } else {
        0
    };
    if benign {
        directives.push_str("fake payload=1 poison=0 repeats=1 gap_us=0 place=before\n");
    } else {
        directives.push_str(&format!(
            "fake payload=1 poison={poison_id} repeats={copies} gap_us=0 place=before\n"
        ));
    }
    R2oQuicDiscoveryCandidate {
        kind,
        name: name.into(),
        directives,
    }
}

fn r2o_quic_blob_name(blob: u8) -> &'static str {
    match blob {
        0 => "исходная приманка quic5",
        1 => "исходная приманка quic_google",
        2 => "исходная приманка quic_rutracker",
        3 => "исходная приманка fake_default_quic",
        4 => "безобидная датаграмма",
        _ => unreachable!(),
    }
}

pub struct QuicReplayProbe {
    socket: UdpSocket,
    endpoint: SocketAddr,
    local_endpoint: SocketAddr,
    snapshot: Vec<u8>,
    datagrams: Vec<Vec<u8>>,
}

impl QuicReplayProbe {
    /// Подготовить UDP-сокет и перепечатать снимок, не отправляя датаграммы.
    pub fn prepare(endpoint: SocketAddr, snapshot: &[u8], mark: Option<u32>) -> io::Result<Self> {
        if endpoint.port() == 0 || endpoint.ip().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "адрес QUIC-узла имеет нулевой порт или неопределённый IP",
            ));
        }
        let snapshot = r2k_quic_snapshot_reseal(snapshot).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "снимок QUIC Initial не прошёл проверку или повторную упаковку",
            )
        })?;
        let parsed = r2k_quic_snapshot_parse(&snapshot).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "перезапечатанный снимок QUIC повреждён",
            )
        })?;
        let datagrams = parsed
            .datagrams()
            .iter()
            .map(|datagram| datagram.to_vec())
            .collect();

        let socket = crate::r2o_quic_http3::r2o_quic_http3_udp_socket(endpoint, mark)?;
        let local_endpoint = socket.local_addr()?;
        Ok(Self {
            socket,
            endpoint,
            local_endpoint,
            snapshot,
            datagrams,
        })
    }

    /// Вернуть точную локальную пару, которую нужно указать во временной пробе.
    pub fn local_endpoint(&self) -> SocketAddr {
        self.local_endpoint
    }

    /// Создать ещё одну ссылку на тот же UDP-сокет для HTTP/3-клиента.
    pub fn try_clone_socket(&self) -> io::Result<UdpSocket> {
        self.socket.try_clone()
    }

    /// Перезапечатать и отправить новый полёт, ожидая связанный Initial или подлинный Retry.
    pub fn run(&mut self, timeout: Duration) -> io::Result<QuicReplayResult> {
        let result = self.r2o_run_inner(timeout);
        let reset_timeout = self.socket.set_read_timeout(None);
        match result {
            Err(error) => Err(error),
            Ok(result) => {
                reset_timeout?;
                Ok(result)
            }
        }
    }

    fn r2o_run_inner(&mut self, timeout: Duration) -> io::Result<QuicReplayResult> {
        let snapshot = r2k_quic_snapshot_reseal(&self.snapshot).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "не удалось создать новый идентификатор соединения QUIC",
            )
        })?;
        let parsed = r2k_quic_snapshot_parse(&snapshot).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "перезапечатанный снимок QUIC повреждён",
            )
        })?;
        let datagrams = parsed
            .datagrams()
            .iter()
            .map(|datagram| datagram.to_vec())
            .collect();
        self.snapshot = snapshot;
        self.datagrams = datagrams;

        let mut result = QuicReplayResult::default();
        for datagram in &self.datagrams {
            let sent = self.socket.send(datagram)?;
            if sent != datagram.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "датаграмма QUIC Initial отправлена не полностью",
                ));
            }
            result.sent_datagrams += 1;
        }

        let timeout = if timeout.is_zero() {
            R2O_QUIC_REPLAY_DEFAULT_TIMEOUT
        } else {
            timeout.min(R2O_QUIC_REPLAY_MAX_TIMEOUT)
        };
        let deadline = Instant::now() + timeout;
        let mut response = vec![0; R2O_QUIC_REPLAY_MAX_RESPONSE];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(result);
            }
            self.socket.set_read_timeout(Some(remaining))?;
            match self.socket.recv(&mut response) {
                Ok(length) => {
                    if r2k_quic_snapshot_verify_bound_response(&self.snapshot, &response[..length])
                    {
                        result.handshake_confirmed = true;
                        return Ok(result);
                    }
                    result.foreign_responses = result.foreign_responses.saturating_add(1);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(result);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Выполнить три сетевые пробы и классифицировать один раунд вопроса.
    pub fn r2o_quic_probe_filter(
        &mut self,
        timeout: Duration,
        attempt: usize,
    ) -> R2oQuicFilterResult {
        const REPEATS: usize = 3;
        let mut answered = 0;
        let mut measured = 0;
        for _ in 0..REPEATS {
            match self.run(timeout) {
                Ok(result) if result.sent_datagrams > 0 => {
                    measured += 1;
                    answered += usize::from(result.handshake_confirmed);
                }
                Ok(_) | Err(_) => {}
            }
        }
        R2oQuicFilterResult {
            decision: r2o_quic_filter_round_decision(answered, measured, attempt, REPEATS),
            answered,
            measured,
        }
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::{
        QuicReplayProbe, R2oQuicCandidateKind, R2oQuicFilterDecision,
        r2o_quic_adaptive_split_eligible, r2o_quic_data_proof_confirmed,
        r2o_quic_discovery_candidates, r2o_quic_filter_round_decision,
        r2o_quic_fragment_control_succeeded, r2o_quic_original_fallback_candidates,
        r2o_quic_strategy_attempt_decision, r2o_quic_trial_data_verdict,
    };
    use r2k_core::quic::R2kQuicDataVerdict;
    use std::net::UdpSocket;
    use std::time::Duration;

    #[test]
    fn r2o_quic_ttl_кандидат_добавляется_только_после_подтверждённого_зависания() {
        let no_handshake = crate::r2o_quic_http3::R2oQuicHttp3Result {
            r2o_quic_stalled: true,
            ..Default::default()
        };
        let handshake_without_stall = crate::r2o_quic_http3::R2oQuicHttp3Result {
            handshake_confirmed: true,
            ..Default::default()
        };
        assert_eq!(r2o_quic_discovery_candidates(&no_handshake, true).len(), 3);
        assert_eq!(
            r2o_quic_discovery_candidates(&handshake_without_stall, true).len(),
            3
        );

        let stalled = crate::r2o_quic_http3::R2oQuicHttp3Result {
            handshake_confirmed: true,
            r2o_quic_stalled: true,
            ..Default::default()
        };
        let candidates = r2o_quic_discovery_candidates(&stalled, true);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].kind, R2oQuicCandidateKind::TtlStrategy);
        assert_eq!(candidates[1].kind, R2oQuicCandidateKind::Clearance);
        assert_eq!(candidates[2].kind, R2oQuicCandidateKind::SplitCrypto);
        assert_eq!(candidates[3].kind, R2oQuicCandidateKind::UdpLength);

        let no_split = r2o_quic_discovery_candidates(&stalled, false);
        assert_eq!(no_split.len(), 3);
        assert_eq!(no_split[1].kind, R2oQuicCandidateKind::Clearance);
        assert_eq!(no_split[2].kind, R2oQuicCandidateKind::UdpLength);

        let plan_text = format!(
            "r2o-plan 1 10\nproto udp quic\n{}",
            candidates[0].directives
        );
        let plan =
            r2k_core::plan::Plan::parse(&crate::plan_text::compile_text(&plan_text).unwrap())
                .unwrap();
        assert!(plan.r2k_is_quic_ttl_probe());
    }

    #[test]
    fn r2o_quic_резервная_лестница_повторяет_порядок_донора() {
        let candidates = r2o_quic_original_fallback_candidates(false, false, false);
        let kinds = candidates
            .iter()
            .map(|candidate| candidate.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                R2oQuicCandidateKind::OriginalSingle(0),
                R2oQuicCandidateKind::OriginalSingle(1),
                R2oQuicCandidateKind::OriginalSingle(2),
                R2oQuicCandidateKind::OriginalSingle(3),
                R2oQuicCandidateKind::OriginalSingle(4),
                R2oQuicCandidateKind::OriginalRepeats { blob: 0, copies: 6 },
                R2oQuicCandidateKind::OriginalRepeats {
                    blob: 0,
                    copies: 11
                },
                R2oQuicCandidateKind::OriginalRepeats { blob: 3, copies: 6 },
                R2oQuicCandidateKind::OriginalRepeats {
                    blob: 3,
                    copies: 11
                },
                R2oQuicCandidateKind::OriginalTtl(3),
                R2oQuicCandidateKind::OriginalTtl(5),
                R2oQuicCandidateKind::OriginalTtl(8),
                R2oQuicCandidateKind::OriginalTtl(12),
                R2oQuicCandidateKind::FragmentControl,
                R2oQuicCandidateKind::FragmentShape(1),
                R2oQuicCandidateKind::FragmentShape(2),
                R2oQuicCandidateKind::FragmentShape(3),
                R2oQuicCandidateKind::FragmentShape(4),
            ]
        );

        let filtered = r2o_quic_original_fallback_candidates(true, true, true);
        assert!(!filtered.iter().any(|candidate| matches!(
            candidate.kind,
            R2oQuicCandidateKind::OriginalSingle(4)
                | R2oQuicCandidateKind::OriginalTtl(3)
                | R2oQuicCandidateKind::FragmentControl
                | R2oQuicCandidateKind::FragmentShape(_)
        )));

        for (candidate, expected) in [
            (&candidates[5], (0, 6)),
            (&candidates[6], (0, 11)),
            (&candidates[7], (3, 6)),
            (&candidates[8], (3, 11)),
        ] {
            let plan_text = format!("r2o-plan 1 10\nproto udp quic\n{}", candidate.directives);
            let plan =
                r2k_core::plan::Plan::parse(&crate::plan_text::compile_text(&plan_text).unwrap())
                    .unwrap();
            assert_eq!(plan.fakes[0].repeats, expected.1);
            assert_eq!(
                plan.payloads[0].bytes.len(),
                if expected.0 == 0 { 1200 } else { 620 }
            );
        }

        let adaptive = super::r2o_quic_adaptive_split_candidate();
        assert_eq!(adaptive.kind, R2oQuicCandidateKind::AdaptiveSplit);
        let plan_text = format!("r2o-plan 1 10\nproto udp quic\n{}", adaptive.directives);
        let plan =
            r2k_core::plan::Plan::parse(&crate::plan_text::compile_text(&plan_text).unwrap())
                .unwrap();
        assert_eq!(plan.qsplit, 1);
        assert_eq!(plan.fakes[0].repeats, 11);
        assert_eq!(plan.payloads[0].bytes.len(), 620);
    }

    #[test]
    fn r2o_quic_адаптивный_разрез_запускается_только_по_контрасту_донора() {
        use R2kQuicDataVerdict::{Cut, NoHandshake, NotRun, Pass};

        assert!(r2o_quic_adaptive_split_eligible(
            R2oQuicFilterDecision::No,
            true,
            1,
            3,
            None,
        ));
        assert!(r2o_quic_adaptive_split_eligible(
            R2oQuicFilterDecision::No,
            true,
            3,
            3,
            Some(Cut),
        ));
        assert!(r2o_quic_adaptive_split_eligible(
            R2oQuicFilterDecision::No,
            true,
            3,
            3,
            Some(NoHandshake),
        ));
        for (split, applicable, answered, measured, verdict) in [
            (R2oQuicFilterDecision::Unknown, true, 1, 3, None),
            (R2oQuicFilterDecision::Pass, true, 1, 3, None),
            (R2oQuicFilterDecision::No, false, 1, 3, None),
            (R2oQuicFilterDecision::No, true, 0, 3, Some(Cut)),
            (R2oQuicFilterDecision::No, true, 3, 3, Some(Pass)),
            (R2oQuicFilterDecision::No, true, 2, 1, Some(NotRun)),
        ] {
            assert!(!r2o_quic_adaptive_split_eligible(
                split, applicable, answered, measured, verdict,
            ));
        }
    }

    #[test]
    fn r2o_quic_контроль_фрагментов_требует_фильтр_и_applied() {
        assert!(r2o_quic_fragment_control_succeeded(
            R2oQuicFilterDecision::Pass,
            true
        ));
        assert!(!r2o_quic_fragment_control_succeeded(
            R2oQuicFilterDecision::Pass,
            false
        ));
        for decision in [
            R2oQuicFilterDecision::No,
            R2oQuicFilterDecision::Retry,
            R2oQuicFilterDecision::Unknown,
        ] {
            assert!(!r2o_quic_fragment_control_succeeded(decision, true));
        }
    }

    #[test]
    fn r2o_quic_профиль_собирает_проверяемый_clienthello_с_sni_и_без_него() {
        for server_name in [Some("quic.example"), None] {
            let packed = super::r2o_quic_profile_snapshot(server_name).unwrap();
            let snapshot = r2k_core::quic_snapshot::r2k_quic_snapshot_parse(&packed).unwrap();
            let datagrams = snapshot.datagrams();
            assert_eq!(datagrams.len(), 1);
            assert_eq!(datagrams[0].len(), 1200);
            assert!(r2k_core::quic::is_authenticated_initial(datagrams[0]));
            assert_eq!(
                r2k_core::quic::r2k_quic_initial_sni_result_from_datagrams(datagrams).unwrap(),
                server_name.map(|name| name.as_bytes().to_vec())
            );

            let client_hello =
                r2k_core::quic::r2k_quic_initial_client_hello_from_datagrams(datagrams).unwrap();
            let scid_length_offset = 6 + usize::from(datagrams[0][5]);
            let scid_length = usize::from(datagrams[0][scid_length_offset]);
            let scid_start = scid_length_offset + 1;
            let scid = &datagrams[0][scid_start..scid_start + scid_length];
            assert!(client_hello.windows(56).any(|extension| {
                extension[..4] == [0, 0x39, 0, 52]
                    && extension[4..46]
                        == [
                            0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x03, 0x02, 0x45, 0xc0, 0x04, 0x04,
                            0x80, 0x10, 0x00, 0x00, 0x05, 0x04, 0x80, 0x04, 0x00, 0x00, 0x06, 0x04,
                            0x80, 0x04, 0x00, 0x00, 0x07, 0x04, 0x80, 0x04, 0x00, 0x00, 0x08, 0x02,
                            0x40, 0x64, 0x09, 0x02, 0x40, 0x64,
                        ]
                    && extension[46..48] == [0x0f, 0x08]
                    && &extension[48..] == scid
            }));
            let mut record = vec![22, 3, 1];
            record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
            record.extend_from_slice(&client_hello);
            let (remaining, messages) = tls_parser::parse_tls_plaintext(&record).unwrap();
            assert!(remaining.is_empty());
            assert!(matches!(
                messages.msg.as_slice(),
                [tls_parser::TlsMessage::Handshake(
                    tls_parser::TlsMessageHandshake::ClientHello(_)
                )]
            ));
        }
    }

    #[test]
    fn r2o_quic_решение_повтора_сохраняет_нет_неполный_ответ_и_unknown() {
        assert_eq!(
            r2o_quic_filter_round_decision(3, 3, 0, 3),
            R2oQuicFilterDecision::Pass
        );
        assert_eq!(
            r2o_quic_filter_round_decision(0, 3, 0, 3),
            R2oQuicFilterDecision::No
        );
        assert_eq!(
            r2o_quic_filter_round_decision(2, 3, 0, 3),
            R2oQuicFilterDecision::Retry
        );
        assert_eq!(
            r2o_quic_filter_round_decision(2, 3, 1, 3),
            R2oQuicFilterDecision::Unknown
        );
        assert_eq!(
            r2o_quic_filter_round_decision(2, 2, 0, 3),
            R2oQuicFilterDecision::Retry
        );
        assert_eq!(
            r2o_quic_filter_round_decision(2, 2, 1, 3),
            R2oQuicFilterDecision::Unknown
        );
    }

    #[test]
    fn r2o_quic_повторяет_этап_данных_только_при_not_run() {
        assert_eq!(
            r2o_quic_strategy_attempt_decision(
                R2oQuicFilterDecision::Pass,
                Some(R2kQuicDataVerdict::NotRun),
                0,
            ),
            R2oQuicFilterDecision::Retry
        );
        assert_eq!(
            r2o_quic_strategy_attempt_decision(
                R2oQuicFilterDecision::Pass,
                Some(R2kQuicDataVerdict::NotRun),
                1,
            ),
            R2oQuicFilterDecision::Unknown
        );
        assert_eq!(
            r2o_quic_strategy_attempt_decision(
                R2oQuicFilterDecision::Pass,
                Some(R2kQuicDataVerdict::Pass),
                1,
            ),
            R2oQuicFilterDecision::Pass
        );
        assert_eq!(
            r2o_quic_strategy_attempt_decision(
                R2oQuicFilterDecision::Pass,
                Some(R2kQuicDataVerdict::NoHandshake),
                0,
            ),
            R2oQuicFilterDecision::No
        );
        assert_eq!(
            r2o_quic_strategy_attempt_decision(R2oQuicFilterDecision::No, None, 0,),
            R2oQuicFilterDecision::No
        );
    }

    #[test]
    fn r2o_quic_ноль_ответов_после_трёх_проб_даёт_нет() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let endpoint = server.local_addr().unwrap();
        let receiver = std::thread::spawn(move || {
            let mut received = Vec::new();
            for _ in 0..3 {
                let mut packet = [0; 1500];
                let (length, peer) = server.recv_from(&mut packet).expect("приём QUIC-пробы");
                let (_, dcid) =
                    r2k_core::quic::r2k_quic_initial_flight_id(&packet[..length]).unwrap();
                received.push((dcid, peer));
            }
            received
        });
        let initial = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
        let snapshot = r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[&initial[..]]).unwrap();
        let mut probe = QuicReplayProbe::prepare(endpoint, &snapshot, None).unwrap();

        assert_eq!(
            probe.r2o_quic_probe_filter(Duration::from_millis(20), 0),
            super::R2oQuicFilterResult {
                decision: R2oQuicFilterDecision::No,
                answered: 0,
                measured: 3,
            }
        );
        let received = receiver.join().unwrap();
        assert_eq!(received.len(), 3);
        assert_ne!(received[0].0, received[1].0);
        assert_ne!(received[1].0, received[2].0);
        assert_eq!(received[0].1, received[2].1);
        assert_eq!(
            probe.try_clone_socket().unwrap().read_timeout().unwrap(),
            None
        );
    }

    #[test]
    fn рукопожатие_и_applied_без_http3_ответа_не_подтверждают_обход() {
        assert!(!r2o_quic_data_proof_confirmed(
            true,
            true,
            r2k_core::quic::R2kQuicDataVerdict::NotRun,
        ));
        assert!(r2o_quic_data_proof_confirmed(
            true,
            true,
            r2k_core::quic::R2kQuicDataVerdict::Pass,
        ));
        assert!(!r2o_quic_data_proof_confirmed(
            false,
            true,
            r2k_core::quic::R2kQuicDataVerdict::Pass,
        ));
    }

    #[test]
    fn повторный_замер_не_проходит_только_по_порогу_32_киби() {
        let result = crate::r2o_quic_http3::R2oQuicHttp3Result {
            handshake_confirmed: true,
            status: 200,
            body_bytes: 32_768,
            budget_required: true,
            budget_passed: false,
            ..crate::r2o_quic_http3::R2oQuicHttp3Result::default()
        };

        assert_eq!(
            r2o_quic_trial_data_verdict(&result),
            R2kQuicDataVerdict::NotRun
        );
    }

    #[test]
    fn каждый_повтор_использует_новый_dcid_на_том_же_udp_сокете() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let endpoint = server.local_addr().unwrap();
        let receiver = std::thread::spawn(move || {
            let mut received = Vec::new();
            for _ in 0..2 {
                let mut packet = [0; 1500];
                let (length, peer) = server.recv_from(&mut packet).unwrap();
                let (_, dcid) =
                    r2k_core::quic::r2k_quic_initial_flight_id(&packet[..length]).unwrap();
                received.push((dcid, peer));
            }
            received
        });

        let initial = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
        let snapshot = r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[&initial[..]]).unwrap();
        let mut probe = QuicReplayProbe::prepare(endpoint, &snapshot, None).unwrap();
        let local = probe.local_endpoint();

        assert!(
            !probe
                .run(Duration::from_millis(20))
                .unwrap()
                .handshake_confirmed
        );
        assert!(
            !probe
                .run(Duration::from_millis(20))
                .unwrap()
                .handshake_confirmed
        );

        let received = receiver.join().unwrap();
        assert_eq!(received.len(), 2);
        assert_ne!(received[0].0, received[1].0);
        assert_eq!(received[0].1, local);
        assert_eq!(received[1].1, local);
        assert_eq!(probe.local_endpoint(), local);
    }
}
