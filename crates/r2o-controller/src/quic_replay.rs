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
const R2O_QUIC_PROFILE_RANDOM: std::ops::Range<usize> = 6..38;
const R2O_QUIC_PROFILE_SCID: std::ops::Range<usize> = 142..150;
const R2O_QUIC_PROFILE_KEY_SHARE: std::ops::Range<usize> = 243..275;
const R2O_QUIC_PROFILE_HELLO: &[u8] = include_bytes!("profiles/quic_probe_client_hello.bin");
pub const R2O_QUIC_MAX_ADDRS: usize = 8;
pub const R2O_QUIC_RESIDUAL_GAP: Duration = Duration::from_millis(60);
pub const R2O_QUIC_FRAGMENT_CONTROL_NAME: &str = "контроль прохождения IP-фрагментов, форма 1";

/// Match d2o `d2k_ip4_private` / `d2k_ip6_private` for QUIC targets.
pub fn r2o_quic_address_is_local(address: SocketAddr) -> bool {
    fn ipv4_is_local(address: std::net::Ipv4Addr) -> bool {
        let [a, b, _, _] = address.octets();
        address.is_unspecified()
            || a == 10
            || a == 127
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || (a == 169 && b == 254)
            || (a == 100 && (64..=127).contains(&b))
    }

    match address.ip() {
        std::net::IpAddr::V4(address) => ipv4_is_local(address),
        std::net::IpAddr::V6(address) => {
            let octets = address.octets();
            let mapped_v4 = octets[..10] == [0; 10] && octets[10..12] == [0xff, 0xff];
            if mapped_v4 {
                let mapped =
                    std::net::Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return ipv4_is_local(mapped);
            }

            address.is_unspecified()
                || address.is_loopback()
                || (octets[0] & 0xfe) == 0xfc
                || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
                || octets[0] == 0xff
        }
    }
}

/// Build the same-family, deduplicated address pool used by d2o `build_pool`.
pub fn r2o_quic_address_pool(
    primary: SocketAddr,
    resolved: impl IntoIterator<Item = SocketAddr>,
) -> Vec<SocketAddr> {
    let mut pool = vec![primary];
    for address in resolved
        .into_iter()
        .filter(|address| address.is_ipv4() == primary.is_ipv4())
        .take(R2O_QUIC_MAX_ADDRS)
    {
        if pool.len() == R2O_QUIC_MAX_ADDRS {
            break;
        }
        let address = SocketAddr::new(address.ip(), primary.port());
        if !pool.iter().any(|known| known.ip() == address.ip()) {
            pool.push(address);
        }
    }
    pool
}

/// Select the address for one question using d2o `qp_pinned_or_next` rules.
pub fn r2o_quic_next_question_address(
    primary: SocketAddr,
    pool: &[SocketAddr],
    next: &mut usize,
    residual_detected: bool,
) -> Option<SocketAddr> {
    if !residual_detected {
        return Some(primary);
    }
    let address = pool.get(*next).copied()?;
    *next += 1;
    Some(address)
}

/// `classify_run` treats any completed silent control as residual blocking.
pub fn r2o_quic_residual_detected(pass: usize, err: usize) -> Option<bool> {
    (err == 0).then_some(pass == 0)
}

/// Сформировать донорский Go crypto/tls ClientHello и QUIC v1 Initial.
pub fn r2o_quic_profile_snapshot(server_name: Option<&str>) -> Option<Vec<u8>> {
    if server_name.is_some_and(str::is_empty) {
        return None;
    }
    let provider = rustls::crypto::ring::default_provider();
    let mut client_hello = R2O_QUIC_PROFILE_HELLO.to_vec();
    if client_hello.len() != 275 {
        return None;
    }
    #[cfg(any(target_arch = "mips", target_arch = "mips64"))]
    if client_hello.get(39..41)? == [0, 6] {
        client_hello[41..47].copy_from_slice(&[0x13, 0x03, 0x13, 0x01, 0x13, 0x02]);
    }

    let mut random = [0; 32];
    provider.secure_random.fill(&mut random).ok()?;
    client_hello
        .get_mut(R2O_QUIC_PROFILE_RANDOM.clone())?
        .copy_from_slice(&random);
    let mut source_connection_id = [0; 8];
    provider
        .secure_random
        .fill(&mut source_connection_id)
        .ok()?;
    client_hello
        .get_mut(R2O_QUIC_PROFILE_SCID.clone())?
        .copy_from_slice(&source_connection_id);
    let key_exchange = rustls::crypto::ring::kx_group::X25519.start().ok()?;
    let public_key: [u8; 32] = key_exchange.pub_key().try_into().ok()?;
    client_hello
        .get_mut(R2O_QUIC_PROFILE_KEY_SHARE.clone())?
        .copy_from_slice(&public_key);
    let server_name = server_name.filter(|name| name.parse::<std::net::Ipv4Addr>().is_err());
    let client_hello =
        r2k_core::quic::r2k_quic_client_hello_rename_sni(&client_hello, server_name)?;
    let initial =
        r2k_core::quic::r2k_quic_initial_build(&client_hello, &source_connection_id, 1200)?;
    r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[&initial])
}

/// Сформировать три свежих нейтральных SNI, как `neutralName()` в d2o.
pub fn r2o_quic_neutral_control_snapshots() -> Option<Vec<Vec<u8>>> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let provider = rustls::crypto::ring::default_provider();
    let mut snapshots = Vec::with_capacity(3);
    for _ in 0..3 {
        let mut random = [0; 5];
        provider.secure_random.fill(&mut random).ok()?;
        let mut name = String::with_capacity(23);
        name.push('z');
        for byte in random {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        name.push_str(".example.com");
        snapshots.push(r2o_quic_profile_snapshot(Some(&name))?);
    }
    Some(snapshots)
}

/// Build the donor's padded GREASE-version packet and its response key CID.
fn r2o_quic_build_vn_probe() -> Option<(Vec<u8>, Vec<u8>)> {
    const GREASE_VERSION: u32 = 0x1a2a_3a4a;
    const PACKET_LEN: usize = 1200;
    let provider = rustls::crypto::ring::default_provider();
    let mut dcid = vec![0; 8];
    let mut scid = [0; 8];
    provider.secure_random.fill(&mut dcid).ok()?;
    provider.secure_random.fill(&mut scid).ok()?;
    let mut packet = vec![0; PACKET_LEN];
    packet[0] = 0xc0;
    packet[1..5].copy_from_slice(&GREASE_VERSION.to_be_bytes());
    packet[5] = 8;
    packet[6..14].copy_from_slice(&dcid);
    packet[14] = 8;
    packet[15..23].copy_from_slice(&scid);
    Some((packet, dcid))
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oQuicBaseResult {
    pub clear: bool,
    pub base_blocked: bool,
    pub probes: usize,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oQuicRawAskResult {
    pub pass: usize,
    pub err: usize,
    pub refused: usize,
    pub sent: usize,
    pub marked: bool,
    pub rtt_ms: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oQuicDirectAction {
    Stop,
    Candidates,
    Data,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oQuicDirectDataAction {
    Clear,
    Repeat,
    Flaky,
    Inconclusive,
    CutConfirmed,
}

/// Follow d2o `classify_run`'s two-fresh-connection direct HTTP/3 gate.
pub fn r2o_quic_direct_data_action(
    first: R2kQuicDataVerdict,
    repeated: Option<R2kQuicDataVerdict>,
) -> R2oQuicDirectDataAction {
    match first {
        R2kQuicDataVerdict::Pass => R2oQuicDirectDataAction::Clear,
        R2kQuicDataVerdict::Cut => match repeated {
            None => R2oQuicDirectDataAction::Repeat,
            Some(R2kQuicDataVerdict::Pass) => R2oQuicDirectDataAction::Flaky,
            Some(R2kQuicDataVerdict::Cut) => R2oQuicDirectDataAction::CutConfirmed,
            Some(R2kQuicDataVerdict::NotRun | R2kQuicDataVerdict::NoHandshake) => {
                R2oQuicDirectDataAction::Inconclusive
            }
        },
        R2kQuicDataVerdict::NotRun | R2kQuicDataVerdict::NoHandshake => {
            R2oQuicDirectDataAction::Inconclusive
        }
    }
}

/// Follow the direct-Initial branches in d2o `classify_run`.
pub fn r2o_quic_direct_action(pass: usize, err: usize, repeats: usize) -> R2oQuicDirectAction {
    if err != 0 {
        R2oQuicDirectAction::Stop
    } else if pass == repeats {
        R2oQuicDirectAction::Data
    } else if pass == 0 {
        R2oQuicDirectAction::Candidates
    } else {
        R2oQuicDirectAction::Stop
    }
}

/// Классифицировать контроль живости и прямой QUIC Initial как d2o `d2k_quic_base`.
pub fn r2o_quic_base_result(
    control_pass: usize,
    control_sent: usize,
    trigger: Option<(usize, usize, usize)>,
    repeats: usize,
) -> Option<R2oQuicBaseResult> {
    if control_pass == 0 {
        return Some(R2oQuicBaseResult {
            clear: false,
            base_blocked: false,
            probes: control_sent,
            reason: format!(
                "базовый вопрос: контроль молчит (0/{repeats}) — блокировка имени не доказана"
            ),
        });
    }
    let (trigger_pass, trigger_err, trigger_sent) = trigger?;
    let base_blocked = trigger_pass == 0 && trigger_err == 0;
    let reason = if base_blocked {
        format!(
            "базовый вопрос: контроль отвечает ({control_pass}/{repeats}), наш Initial молчит (0/{repeats})"
        )
    } else {
        format!(
            "базовый вопрос: контроль {control_pass}/{repeats}, наш Initial {trigger_pass}/{repeats} — блокировки рукопожатия нет"
        )
    };
    Some(R2oQuicBaseResult {
        clear: trigger_pass == repeats,
        base_blocked,
        probes: control_sent.saturating_add(trigger_sent),
        reason,
    })
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
        result.app_bytes,
        result.complete,
        result.r2o_quic_stalled,
        result.budget_required,
        false,
        result.budget_passed,
    )
}

/// Короткий контрольный ответ засчитывается только после получения FIN, как в D2O.
pub fn r2o_quic_short_control_data_verdict(
    result: &crate::r2o_quic_http3::R2oQuicHttp3Result,
) -> R2kQuicDataVerdict {
    r2k_quic_data_judge(
        result.handshake_confirmed,
        result.status,
        result.app_bytes,
        result.complete,
        result.r2o_quic_stalled,
        true,
        false,
        result.budget_passed,
    )
}

/// Построить начальные QUIC-вопросы по порядку донорской стратегии.
pub fn r2o_quic_discovery_candidates(
    baseline: Option<&crate::r2o_quic_http3::R2oQuicHttp3Result>,
    split_applicable: bool,
) -> Vec<R2oQuicDiscoveryCandidate> {
    let stalled =
        baseline.is_some_and(|result| result.handshake_confirmed && result.r2o_quic_stalled);
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
        let socket = crate::r2o_quic_http3::r2o_quic_http3_udp_socket(endpoint, mark)?;
        Self::from_socket(endpoint, snapshot, socket)
    }

    /// Подготовить снимок на новом UDP-порту с best-effort SO_MARK, как d2o.
    pub fn prepare_fresh(
        endpoint: SocketAddr,
        snapshot: &[u8],
        mark: Option<u32>,
    ) -> io::Result<(Self, bool)> {
        let (socket, marked) =
            crate::r2o_quic_http3::r2o_quic_http3_udp_socket_fresh(endpoint, mark)
                .map_err(|error| error.source)?;
        Ok((Self::from_socket(endpoint, snapshot, socket)?, marked))
    }

    fn from_socket(endpoint: SocketAddr, snapshot: &[u8], socket: UdpSocket) -> io::Result<Self> {
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

type R2oQuicPendingDonorAsk = (tokio::net::UdpSocket, u32, Vec<u8>, Instant);

enum R2oQuicDonorReceive {
    Answer(Duration),
    Refused,
    Silent,
}

async fn r2o_quic_collect_donor_answers(
    pending: Vec<R2oQuicPendingDonorAsk>,
    timeout: Duration,
    result: &mut R2oQuicRawAskResult,
) {
    let timeout = if timeout.is_zero() {
        Duration::from_millis(1500)
    } else {
        timeout
    };
    let deadline = tokio::time::Instant::now() + timeout;
    let mut tasks = tokio::task::JoinSet::new();
    for (socket, version, dcid, sent_at) in pending {
        tasks.spawn(async move {
            let mut response = [0; 2048];
            loop {
                match socket.recv(&mut response).await {
                    Ok(length)
                        if r2k_core::quic::r2k_quic_donor_response_matches(
                            version,
                            &dcid,
                            &response[..length],
                        ) =>
                    {
                        return R2oQuicDonorReceive::Answer(sent_at.elapsed());
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                        return R2oQuicDonorReceive::Refused;
                    }
                    Err(_) => return R2oQuicDonorReceive::Silent,
                }
            }
        });
    }
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok(R2oQuicDonorReceive::Answer(rtt)))) => {
                result.pass = result.pass.saturating_add(1);
                let rtt_ms = u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX);
                if result.rtt_ms == 0 || rtt_ms < result.rtt_ms {
                    result.rtt_ms = rtt_ms;
                }
            }
            Ok(Some(Ok(R2oQuicDonorReceive::Refused))) => {
                result.refused = result.refused.saturating_add(1);
            }
            Ok(Some(Ok(R2oQuicDonorReceive::Silent) | Err(_))) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
}

/// Выполнить параллельные raw Initial-пробы с критерием ответа d2o.
pub async fn r2o_quic_ask_donor_parallel(
    endpoint: SocketAddr,
    snapshots: &[Vec<u8>],
    mark: Option<u32>,
    timeout: Duration,
) -> R2oQuicRawAskResult {
    let mut result = R2oQuicRawAskResult {
        marked: mark.is_none_or(|mark| mark == 0),
        ..R2oQuicRawAskResult::default()
    };
    let mut pending = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        let (socket, marked) =
            match crate::r2o_quic_http3::r2o_quic_http3_udp_socket_fresh(endpoint, mark) {
                Ok(socket) => socket,
                Err(_) => {
                    result.err = result.err.saturating_add(1);
                    result.marked = false;
                    continue;
                }
            };
        result.marked &= marked;
        let probe = match QuicReplayProbe::from_socket(endpoint, snapshot, socket) {
            Ok(probe) => probe,
            Err(_) => {
                result.err = result.err.saturating_add(1);
                continue;
            }
        };
        let Some(client_initial) = probe.datagrams.first() else {
            result.err = result.err.saturating_add(1);
            continue;
        };
        let Some((version, dcid)) = r2k_core::quic::r2k_quic_initial_flight_id(client_initial)
        else {
            result.err = result.err.saturating_add(1);
            continue;
        };
        let sent = probe.datagrams.iter().try_for_each(|datagram| {
            let written = probe.socket.send(datagram)?;
            if written == datagram.len() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "датаграмма QUIC Initial отправлена не полностью",
                ))
            }
        });
        if sent.is_err() {
            result.err = result.err.saturating_add(1);
            continue;
        }
        result.sent = result.sent.saturating_add(1);
        let sent_at = Instant::now();
        if probe.socket.set_nonblocking(true).is_err() {
            continue;
        }
        let socket = match tokio::net::UdpSocket::from_std(probe.socket) {
            Ok(socket) => socket,
            Err(_) => continue,
        };
        pending.push((socket, version, dcid, sent_at));
    }
    r2o_quic_collect_donor_answers(pending, timeout, &mut result).await;
    result
}

/// Probe path liveness with the donor's GREASE Version Negotiation question.
pub async fn r2o_quic_ask_donor_version_negotiation(
    endpoint: SocketAddr,
    mark: Option<u32>,
    timeout: Duration,
) -> R2oQuicRawAskResult {
    let mut result = R2oQuicRawAskResult {
        marked: mark.is_none_or(|mark| mark == 0),
        ..R2oQuicRawAskResult::default()
    };
    let mut pending = Vec::with_capacity(3);
    for _ in 0..3 {
        let Some((packet, dcid)) = r2o_quic_build_vn_probe() else {
            result.err = result.err.saturating_add(1);
            continue;
        };
        let (socket, marked) =
            match crate::r2o_quic_http3::r2o_quic_http3_udp_socket_fresh(endpoint, mark) {
                Ok(socket) => socket,
                Err(_) => {
                    result.err = result.err.saturating_add(1);
                    result.marked = false;
                    continue;
                }
            };
        result.marked &= marked;
        match socket.send(&packet) {
            Ok(length) if length == packet.len() => {}
            _ => {
                result.err = result.err.saturating_add(1);
                continue;
            }
        }
        result.sent = result.sent.saturating_add(1);
        let sent_at = Instant::now();
        if socket.set_nonblocking(true).is_err() {
            continue;
        }
        let socket = match tokio::net::UdpSocket::from_std(socket) {
            Ok(socket) => socket,
            Err(_) => continue,
        };
        pending.push((socket, 1, dcid, sent_at));
    }
    r2o_quic_collect_donor_answers(pending, timeout, &mut result).await;
    result
}

#[cfg(test)]
mod tests {
    use super::{
        QuicReplayProbe, R2oQuicCandidateKind, R2oQuicFilterDecision,
        r2o_quic_adaptive_split_eligible, r2o_quic_ask_donor_parallel,
        r2o_quic_data_proof_confirmed, r2o_quic_direct_action, r2o_quic_discovery_candidates,
        r2o_quic_filter_round_decision, r2o_quic_fragment_control_succeeded,
        r2o_quic_neutral_control_snapshots, r2o_quic_original_fallback_candidates,
        r2o_quic_short_control_data_verdict, r2o_quic_strategy_attempt_decision,
        r2o_quic_trial_data_verdict,
    };
    use r2k_core::quic::R2kQuicDataVerdict;
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Duration;

    #[test]
    fn r2o_quic_base_result_matches_d2o() {
        let mut output = String::new();
        for (name, control_pass, control_sent, trigger, expected_calls) in [
            ("blocked", 3, 3, Some((0, 0, 3)), 1),
            ("clear", 1, 3, Some((3, 0, 3)), 1),
            ("control-silent", 0, 3, None, 0),
            ("target-error", 3, 3, Some((0, 1, 3)), 1),
        ] {
            let result =
                super::r2o_quic_base_result(control_pass, control_sent, trigger, 3).unwrap();
            output.push_str(&format!(
                "case={name}\nclear={}\nbase_blocked={}\nprobes={}\ncontrol_calls=1\ntrigger_calls={expected_calls}\nreason={}\n",
                u8::from(result.clear),
                u8::from(result.base_blocked),
                result.probes,
                result.reason,
            ));
        }
        if let Ok(path) = std::env::var("R2O_QUIC_BASE_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn r2o_quic_direct_action_matches_d2o_classify_run() {
        let mut output = String::new();
        for (pass, err) in [(0, 0), (1, 0), (2, 0), (3, 0), (0, 1)] {
            let action = r2o_quic_direct_action(pass, err, 3);
            let name = match action {
                super::R2oQuicDirectAction::Stop => "stop",
                super::R2oQuicDirectAction::Candidates => "candidates",
                super::R2oQuicDirectAction::Data => "data",
            };
            output.push_str(&format!("pass={pass} err={err} next={name}\n"));
        }
        if let Ok(path) = std::env::var("R2O_QUIC_DIRECT_ACTION_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn r2o_quic_direct_http3_repeat_gate_matches_d2o_classify_run() {
        use r2k_core::quic::R2kQuicDataVerdict as Data;

        let cases = [
            ("pass", Data::Pass, None, "clear", 1, false),
            ("cut-pass", Data::Cut, Some(Data::Pass), "flaky", 2, false),
            (
                "cut-not-run",
                Data::Cut,
                Some(Data::NotRun),
                "inconclusive",
                2,
                false,
            ),
            (
                "cut-no-handshake",
                Data::Cut,
                Some(Data::NoHandshake),
                "inconclusive",
                2,
                false,
            ),
            (
                "no-handshake",
                Data::NoHandshake,
                None,
                "inconclusive",
                1,
                false,
            ),
            (
                "cut-cut",
                Data::Cut,
                Some(Data::Cut),
                "cut-confirmed",
                2,
                true,
            ),
        ];
        let mut output = String::new();
        for (case, first, repeated, expected, calls, cut_seen) in cases {
            let mut action = super::r2o_quic_direct_data_action(first, None);
            if action == super::R2oQuicDirectDataAction::Repeat {
                action = super::r2o_quic_direct_data_action(first, repeated);
            }
            let verdict = match action {
                super::R2oQuicDirectDataAction::Clear => "clear",
                super::R2oQuicDirectDataAction::Repeat => "repeat",
                super::R2oQuicDirectDataAction::Flaky => "flaky",
                super::R2oQuicDirectDataAction::Inconclusive => "inconclusive",
                super::R2oQuicDirectDataAction::CutConfirmed => "cut-confirmed",
            };
            assert_eq!(verdict, expected, "{case}");
            output.push_str(&format!(
                "case={case} verdict={verdict} direct_data_calls={calls} probes={} data_cut_seen={}\n",
                6 + calls,
                u8::from(cut_seen),
            ));
        }
        if let Ok(path) = std::env::var("R2O_QUIC_DIRECT_HTTP3_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn r2o_quic_residual_control_and_address_pool_match_d2o() {
        let primary: std::net::SocketAddr = "192.0.2.1:443".parse().unwrap();
        let resolved = [
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.1:8443".parse().unwrap(),
            "192.0.2.2:8443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
            "192.0.2.3:443".parse().unwrap(),
            "192.0.2.4:443".parse().unwrap(),
            "192.0.2.5:443".parse().unwrap(),
            "192.0.2.6:443".parse().unwrap(),
            "192.0.2.7:443".parse().unwrap(),
            "192.0.2.8:443".parse().unwrap(),
        ];
        let pool = super::r2o_quic_address_pool(primary, resolved);
        assert_eq!(
            pool,
            [
                "192.0.2.1:443",
                "192.0.2.2:443",
                "192.0.2.3:443",
                "192.0.2.4:443",
                "192.0.2.5:443",
                "192.0.2.6:443",
                "192.0.2.7:443",
            ]
            .map(|address| address.parse().unwrap())
        );

        let mut next = 1;
        assert_eq!(
            super::r2o_quic_next_question_address(primary, &pool, &mut next, false),
            Some(primary)
        );
        assert_eq!(next, 1, "pinned questions do not consume the address pool");
        assert_eq!(
            super::r2o_quic_next_question_address(primary, &pool, &mut next, true),
            Some("192.0.2.2:443".parse().unwrap())
        );
        assert_eq!(next, 2);
        let mut exhausted_next = 1;
        assert_eq!(
            super::r2o_quic_next_question_address(primary, &pool[..1], &mut exhausted_next, true),
            None,
            "residual questions are unasked when the donor pool has no fresh address"
        );
        assert_eq!(super::r2o_quic_residual_detected(0, 0), Some(true));
        assert_eq!(super::r2o_quic_residual_detected(2, 0), Some(false));
        assert_eq!(super::r2o_quic_residual_detected(0, 1), None);

        let mut output = String::new();
        for (pass, err, pool, expected) in [
            (3, 0, &pool[..1], "pinned"),
            (0, 0, &pool[..1], "unasked"),
            (0, 0, &pool[..], "fresh"),
            (0, 1, &pool[..], "stop"),
        ] {
            let action = match super::r2o_quic_residual_detected(pass, err) {
                None => "stop",
                Some(residual) => {
                    let mut next = 1;
                    match super::r2o_quic_next_question_address(primary, pool, &mut next, residual)
                    {
                        Some(address) if address == primary => "pinned",
                        Some(_) => "fresh",
                        None => "unasked",
                    }
                }
            };
            assert_eq!(action, expected);
            output.push_str(&format!("same_pass={pass} err={err} next={action}\n"));
        }
        if let Ok(path) = std::env::var("R2O_QUIC_RESIDUAL_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn r2o_quic_local_address_policy_matches_d2o() {
        let fixture = include_str!("../tests/fixtures/d2o_quic_local_address.tsv");
        let mut output = String::new();
        for line in fixture.lines().filter(|line| !line.trim().is_empty()) {
            let (name, address, expected) = {
                let mut fields = line.split('\t');
                (
                    fields.next().unwrap(),
                    fields.next().unwrap(),
                    fields.next().unwrap().parse::<bool>().unwrap(),
                )
            };
            let address = SocketAddr::new(address.parse().unwrap(), 443);
            let actual = super::r2o_quic_address_is_local(address);
            assert_eq!(actual, expected, "{name}: {address}");
            output.push_str(&format!("{name}={}\n", u8::from(actual)));
        }
        if let Ok(path) = std::env::var("R2O_QUIC_LOCAL_ADDRESS_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn r2o_quic_version_negotiation_probe_matches_d2o_wire_shape() {
        let (packet, dcid) = super::r2o_quic_build_vn_probe().unwrap();
        assert_eq!(packet.len(), 1200);
        assert_eq!(packet[0], 0xc0);
        assert_eq!(&packet[1..5], &[0x1a, 0x2a, 0x3a, 0x4a]);
        assert_eq!(packet[5], 8);
        assert_eq!(&packet[6..14], dcid.as_slice());
        assert_eq!(packet[14], 8);
        assert_eq!(packet[23], 0);
        assert!(packet[24..].iter().all(|byte| *byte == 0));
        assert!(r2k_core::quic::r2k_quic_donor_response_matches(
            1,
            &dcid,
            &[0x80, 0, 0, 0, 0, 0, 0]
        ));

        let output = format!(
            "len={}\nfirst={:02x}\nversion={}\ndcid_len={}\nscid_len={}\ntoken={}\nzero_padding={}\n",
            packet.len(),
            packet[0],
            u32::from_be_bytes(packet[1..5].try_into().unwrap()),
            packet[5],
            packet[14],
            packet[23],
            u8::from(packet[24..].iter().all(|byte| *byte == 0)),
        );
        if let Ok(path) = std::env::var("R2O_QUIC_VN_SHAPE_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn r2o_quic_version_negotiation_uses_donor_parallel_answers() {
        let server = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let endpoint = server.local_addr().unwrap();
        let server_thread = std::thread::spawn(move || {
            let mut first_request = Vec::new();
            let response = [0x80, 0, 0, 0, 0, 0, 0];
            let mut received = 0;
            for _ in 0..3 {
                let mut packet = [0; 1500];
                let (length, peer) = server.recv_from(&mut packet).unwrap();
                if received == 0 {
                    first_request.extend_from_slice(&packet[..length]);
                }
                received += 1;
                server.send_to(&response, peer).unwrap();
            }
            (received, first_request)
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(super::r2o_quic_ask_donor_version_negotiation(
            endpoint,
            None,
            Duration::from_secs(1),
        ));
        let (received, packet) = server_thread.join().unwrap();
        assert_eq!(received, 3);
        assert_eq!(result.pass, 3);
        assert_eq!(result.err, 0);
        assert_eq!(result.refused, 0);
        assert_eq!(result.sent, 3);
        assert!(result.marked);

        let zero_padding = packet[24..].iter().all(|byte| *byte == 0);
        let answer = usize::from(result.pass > 0);
        let verdict = if answer == 1 { "no_quic" } else { "address" };
        let output = format!(
            "received={received}\nlen={}\nfirst={:02x}\nversion={}\ndcid_len={}\nscid_len={}\ntoken={}\nzero_padding={}\nanswer={answer}\nsent={}\nverdict={verdict}\nprobes=6\ntrigger_calls=0\n",
            packet.len(),
            packet[0],
            u32::from_be_bytes(packet[1..5].try_into().unwrap()),
            packet[5],
            packet[14],
            packet[23],
            u8::from(zero_padding),
            result.sent,
        );
        if let Ok(path) = std::env::var("R2O_QUIC_VN_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn r2o_quic_donor_parallel_control_matches_d2o() {
        let server = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let endpoint = server.local_addr().unwrap();
        let server_thread = std::thread::spawn(move || {
            let mut source_ports = Vec::new();
            let mut peers = Vec::new();
            let response = [0x80, 0, 0, 0, 0, 0, 0];
            for _ in 0..3 {
                let mut request = [0; 2048];
                let (length, peer) = server.recv_from(&mut request).unwrap();
                assert!(length > 0);
                source_ports.push(peer.port());
                peers.push(peer);
            }
            for peer in peers {
                server.send_to(&response, peer).unwrap();
            }
            source_ports
        });
        let snapshots = r2o_quic_neutral_control_snapshots().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(r2o_quic_ask_donor_parallel(
            endpoint,
            &snapshots,
            None,
            Duration::from_secs(1),
        ));
        let source_ports = server_thread.join().unwrap();
        let unique_ports = source_ports
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(result.pass, 3);
        assert_eq!(result.err, 0);
        assert_eq!(result.sent, 3);
        assert!(result.marked);
        assert_eq!(unique_ports.len(), 3);
        if let Ok(path) = std::env::var("R2O_QUIC_DONOR_PARALLEL_DIFF_OUTPUT") {
            std::fs::write(
                path,
                format!(
                    "pass={}\nerr={}\nsent={}\nmarked={}\nunique_ports={}\n",
                    result.pass,
                    result.err,
                    result.sent,
                    u8::from(result.marked),
                    u8::from(unique_ports.len() == 3),
                ),
            )
            .unwrap();
        }
    }

    #[test]
    fn r2o_quic_profile_clienthello_matches_d2o_donor_shape() {
        let packed = super::r2o_quic_profile_snapshot(Some("disk.rzd.ru")).unwrap();
        let snapshot = r2k_core::quic_snapshot::r2k_quic_snapshot_parse(&packed).unwrap();
        let mut client_hello =
            r2k_core::quic::r2k_quic_initial_client_hello_from_datagrams(snapshot.datagrams())
                .unwrap();
        assert_eq!(client_hello.len(), 271);
        client_hello[6..38].fill(0);
        client_hello[138..146].fill(0);
        client_hello[239..271].fill(0);
        let mut output = client_hello
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        output.push('\n');
        if let Ok(path) = std::env::var("R2O_QUIC_PROFILE_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

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
        assert_eq!(
            r2o_quic_discovery_candidates(Some(&no_handshake), true).len(),
            3
        );
        assert_eq!(r2o_quic_discovery_candidates(None, true).len(), 3);
        assert_eq!(
            r2o_quic_discovery_candidates(Some(&handshake_without_stall), true).len(),
            3
        );

        let stalled = crate::r2o_quic_http3::R2oQuicHttp3Result {
            handshake_confirmed: true,
            r2o_quic_stalled: true,
            ..Default::default()
        };
        let candidates = r2o_quic_discovery_candidates(Some(&stalled), true);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].kind, R2oQuicCandidateKind::TtlStrategy);
        assert_eq!(candidates[1].kind, R2oQuicCandidateKind::Clearance);
        assert_eq!(candidates[2].kind, R2oQuicCandidateKind::SplitCrypto);
        assert_eq!(candidates[3].kind, R2oQuicCandidateKind::UdpLength);

        let no_split = r2o_quic_discovery_candidates(Some(&stalled), false);
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
    fn короткий_контроль_требует_полный_ответ_как_d2o() {
        let incomplete = crate::r2o_quic_http3::R2oQuicHttp3Result {
            handshake_confirmed: true,
            status: 200,
            app_bytes: 32_768,
            ..Default::default()
        };
        assert_eq!(
            r2o_quic_short_control_data_verdict(&incomplete),
            R2kQuicDataVerdict::NotRun
        );

        let complete = crate::r2o_quic_http3::R2oQuicHttp3Result {
            complete: true,
            ..incomplete
        };
        assert_eq!(
            r2o_quic_short_control_data_verdict(&complete),
            R2kQuicDataVerdict::Pass
        );
    }

    #[test]
    fn незавершённый_http3_порог_использует_байты_потока_как_d2o() {
        let result = crate::r2o_quic_http3::R2oQuicHttp3Result {
            handshake_confirmed: true,
            status: 200,
            app_bytes: 32 * 1024,
            budget_required: false,
            ..Default::default()
        };

        assert_eq!(
            r2o_quic_trial_data_verdict(&result),
            R2kQuicDataVerdict::Pass
        );
        if let Ok(path) = std::env::var("R2O_QUIC_HTTP3_STREAM_BYTES_DIFF_OUTPUT") {
            std::fs::write(path, "stream-bytes=Pass\n").unwrap();
        }
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
