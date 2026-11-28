use std::cell::Cell;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, Once, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::classify::{
    ClassifyOptions, ClassifyResult, DpiProps, Observation, Poison, PoisonHit, ProbeError,
    ProbeTarget, TriState, Trigger, UnplannablePoison, note_props_hit, note_props_miss,
    poison_selected, poison_supports_family, poisons, select_bridge_decoy, strategy_for_poison,
    trigger_accepts,
};
use r2k_core::plan::{OriginalFate, Plan};
use r2o_datapath::engine::{PacketDecision, decide};

const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const BYPASS_MARK: u32 = 0x2d;
const MAX_TRACE: usize = 512;
const MAX_RAW_RESPONSE: usize = 8192;
const RST_TIMEOUT: Duration = Duration::from_secs(300);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const RST_PENDING_MAX: usize = 64;
const RST_RELEASE_ATTEMPTS: u8 = 5;
static RAW_SELFTESTS: OnceLock<Mutex<RawSelftestState>> = OnceLock::new();
static HOST_TCP_TIMESTAMPS: OnceLock<bool> = OnceLock::new();
thread_local! {
    static RST_RULE_FAILURES: Cell<u64> = const { Cell::new(0) };
    static RAW_DIALS: Cell<u64> = const { Cell::new(0) };
}
static RST_COMMENT_SUPPORTED: AtomicBool = AtomicBool::new(true);
static RST_STALE_RULE_SWEEP: Once = Once::new();
static RST_ABANDON_REPORTED: Once = Once::new();

// C `detect/raw.c:57-61`: нормализованная iptables-строка правила подавления
// RST. Legacy-форма не несёт владельца; owned-форма несёт `d2k-rst:PID`.
const RST_PREFIX: &str = "-A OUTPUT -p tcp -m tcp --sport ";
const RST_LEGACY_SUFFIX: &str = " --tcp-flags RST RST -j DROP";
const RST_OWNED_MID: &str = " --tcp-flags RST RST -m comment --comment ";
const RST_OWNED_TAG: &str = "d2k-rst:";
const RST_OWNED_TAG_R2O: &str = "r2o-rst:";
const RST_OWNED_SUFFIX: &str = " -j DROP";

struct RawSelftestState {
    checked_at: [Option<Instant>; 4],
    error_streak: [usize; 4],
}

impl Default for RawSelftestState {
    fn default() -> Self {
        Self {
            checked_at: std::array::from_fn(|_| None),
            error_streak: [0; 4],
        }
    }
}

pub(crate) fn rst_rule_failure_count() -> u64 {
    RST_RULE_FAILURES.with(Cell::get)
}

pub(crate) fn raw_dial_count() -> u64 {
    RAW_DIALS.with(Cell::get)
}

fn note_raw_dial() {
    RAW_DIALS.with(|count| count.set(count.get().saturating_add(1)));
}

/// C `d2k_raw_supported` (`detect/raw.c:164`): на Linux сырой слой
/// доступен всегда; отказ ядра проявится при открытии сокета отправки.
pub fn raw_supported() -> bool {
    true
}

pub fn sweep_poisons(
    target: &ProbeTarget,
    trigger: &Trigger,
    options: &ClassifyOptions,
    result: &mut ClassifyResult,
    progress: &mut dyn FnMut(&str, usize, usize, usize),
) -> Result<Option<PoisonHit>, ProbeError> {
    let remote = resolve_target(target)?;
    let family = if remote.is_ipv4() { 4 } else { 6 };
    let offer_ts = raw_offer_timestamps(options.client_tcp_has_timestamps);
    // C `d2k_opts_decoy`: приманка — клон, если он собрался, иначе control.
    let (decoy, cloned_decoy) = select_bridge_decoy(
        &trigger.payload,
        options
            .control
            .as_ref()
            .map(|control| control.payload.as_slice()),
        options.trigger_snapped,
    );
    let selected_decoy = decoy.or_else(|| {
        options
            .control
            .as_ref()
            .filter(|control| control.payload.len() >= 2)
            .map(|control| control.payload.clone())
    });
    let props0 = result.props.clone();
    let mut props = props0.clone();
    let mut answered = Vec::new();
    let mut raw_ok = 0usize;
    let mut raw_errors = 0usize;
    let mut cached_selftest = false;

    if let Some(age) = raw_selftest_age(family, offer_ts) {
        cached_selftest = true;
        add_observation(
            result,
            Observation {
                probe: "raw-selftest:кэш".into(),
                cuts: Vec::new(),
                delay: Duration::ZERO,
                pass: 0,
                fail: 0,
                error: Some(format!(
                    "прошла {} с назад в этом процессе, зондов не было",
                    age.as_secs()
                )),
            },
        );
    } else {
        let mut observation = Observation {
            probe: "raw-selftest".into(),
            cuts: Vec::new(),
            delay: Duration::ZERO,
            pass: 0,
            fail: 0,
            error: None,
        };
        let mut last_error = None;
        for _ in 0..options.repeats {
            if is_cancelled(options) || result.probes >= options.probe_limit {
                result.stopped = true;
                add_observation(result, observation);
                return Err(ProbeError::Local("context canceled".into()));
            }
            result.probes += 1;
            match RawConn::connect(
                remote,
                options.timeout,
                effective_mark(options.mark),
                options.cancel.as_deref(),
                offer_ts,
            ) {
                Ok(Some(connection)) => {
                    drop(connection);
                    observation.pass += 1;
                    progress(
                        "raw-selftest",
                        result.probes,
                        observation.pass,
                        observation.fail,
                    );
                    break;
                }
                Ok(None) => {
                    observation.fail += 1;
                    progress(
                        "raw-selftest",
                        result.probes,
                        observation.pass,
                        observation.fail,
                    );
                }
                Err(error) => {
                    observation.fail += 1;
                    if observation.error.is_none() {
                        observation.error = Some(error.message().to_string());
                    }
                    last_error = Some(error);
                    progress(
                        "raw-selftest",
                        result.probes,
                        observation.pass,
                        observation.fail,
                    );
                }
            }
        }
        add_observation(result, observation.clone());
        let passed = observation.pass > 0;
        store_raw_selftest(family, offer_ts, passed);
        if !passed {
            return Err(last_error.unwrap_or_else(|| {
                ProbeError::Transport("classify: SYN-ACK не пришёл при самопроверке raw".into())
            }));
        }
    }
    result.raw_usable = true;

    // C `classify.c:945`: отказ правила подавления RST — не свойство сети,
    // а своя поломка; трасса обязана сказать это до отрицательных исходов.
    if result.rst_rule_failures_since_start() > 0 {
        add_observation(
            result,
            Observation {
                probe: "внимание:правило подавления RST не встало".into(),
                cuts: Vec::new(),
                delay: Duration::ZERO,
                pass: 0,
                fail: 0,
                error: Some(
                    "iptables отверг вставку; отрицательные исходы сырых зондов недостоверны"
                        .into(),
                ),
            },
        );
    }

    for property in property_probes()
        .into_iter()
        .filter(|_| options.only_poison.is_none())
    {
        if is_cancelled(options) || result.probes >= options.probe_limit {
            result.stopped = true;
            break;
        }
        let Some(mut poison) = property_probe_poison(&property, offer_ts, &props) else {
            continue;
        };
        if !poison_selected(options, &poison.name) {
            continue;
        }
        let mut decoy = None;
        match property.set {
            Property::OverlapSni => {
                let Some((offset, length)) = crate::hello::sni_bounds(&trigger.payload) else {
                    continue;
                };
                if offset == 0 || length == 0 || offset + length >= trigger.payload.len() {
                    continue;
                }
                poison.seqovl = (offset + length) as i32;
            }
            Property::WhiteTimestamp => {
                let Some(white) = options
                    .white
                    .as_ref()
                    .filter(|white| white.payload.len() >= 2)
                else {
                    continue;
                };
                decoy = Some(white.payload.as_slice());
            }
            _ if poison.decoy_hello => {
                // C `d2k_opts_decoy`: при отсутствии контроля приманка —
                // пустой буфер, а не повод пропустить вопрос.
                decoy = Some(selected_decoy.as_deref().unwrap_or(&[]));
            }
            _ => {}
        }

        let mut observation = Observation {
            probe: property_probe_label(
                property.label,
                property.set,
                &poison,
                cloned_decoy && !matches!(property.set, Property::WhiteTimestamp),
            ),
            cuts: Vec::new(),
            delay: Duration::from_millis(poison.gap_ms.max(0) as u64),
            pass: 0,
            fail: 0,
            error: None,
        };
        let mut local_error = false;
        for _ in 0..options.repeats {
            if is_cancelled(options) || result.probes >= options.probe_limit {
                result.stopped = true;
                break;
            }
            result.probes += 1;
            match raw_probe_once(
                remote,
                trigger,
                &poison,
                decoy,
                options.timeout,
                options.mark,
                raw_offer_timestamps(options.client_tcp_has_timestamps),
                options.cancel.as_deref(),
            ) {
                Ok(true) => {
                    note_raw_probe(family, false);
                    observation.pass += 1;
                }
                Ok(false) => {
                    note_raw_probe(family, false);
                    observation.fail += 1;
                }
                Err(error) => {
                    note_raw_probe(family, true);
                    local_error = true;
                    raw_errors += 1;
                    observation.fail += 1;
                    observation.error = Some(error.message().to_string());
                    progress(
                        &observation.probe,
                        result.probes,
                        observation.pass,
                        observation.fail,
                    );
                    break;
                }
            }
            progress(
                &observation.probe,
                result.probes,
                observation.pass,
                observation.fail,
            );
            raw_ok += 1;
            if majority(observation.pass, options.repeats)
                || !majority(
                    observation.pass + (options.repeats - observation.pass - observation.fail),
                    options.repeats,
                )
            {
                break;
            }
        }
        if !local_error {
            answered.push(poison.clone());
            apply_property(
                &mut props,
                property.set,
                majority(observation.pass, options.repeats),
                &poison,
            );
        }
        if !local_error && majority(observation.pass, options.repeats) {
            match executable_poison_hit(&poison, trigger, decoy) {
                Ok(hit) => {
                    add_observation(result, observation);
                    note_props_hit(&mut props, &poison);
                    result.props = props.clone();
                    result.path = Some("свойство".into());
                    return Ok(Some(hit));
                }
                Err(unplannable) => {
                    observation.error = Some(format!(
                        "найдено, но не исполняется: {}",
                        unplannable.reason
                    ));
                    result.unplannable.push(unplannable);
                }
            }
        }
        if !local_error && observation.pass == 0 {
            note_props_miss(&mut props, &poison);
        }
        add_observation(result, observation.clone());
        if should_recheck(cached_selftest, raw_ok, raw_errors) {
            if !raw_recheck(remote, options, result, progress)? {
                result.props = props0.clone();
                result.raw_usable = false;
                return Err(ProbeError::Local(
                    "classify: raw self-test failed after local probe errors".into(),
                ));
            }
            cached_selftest = false;
            raw_ok = 0;
            raw_errors = 0;
        }
    }

    for poison in compose_from_props(&props, selected_decoy.as_deref())
        .into_iter()
        .filter(|poison| options.only_poison.is_none() && poison_selected(options, &poison.name))
    {
        if is_cancelled(options) || result.probes >= options.probe_limit {
            result.stopped = true;
            break;
        }
        if !raw_profile_allows(&poison, offer_ts) {
            continue;
        }
        let decoy = poison
            .decoy_hello
            .then_some(selected_decoy.as_deref().unwrap_or(&[]));
        let mut observation = Observation {
            probe: poison.name.clone(),
            cuts: Vec::new(),
            delay: Duration::from_millis(poison.gap_ms.max(0) as u64),
            pass: 0,
            fail: 0,
            error: None,
        };
        let mut local_error = false;
        for _ in 0..options.repeats {
            if is_cancelled(options) || result.probes >= options.probe_limit {
                result.stopped = true;
                break;
            }
            result.probes += 1;
            match raw_probe_once(
                remote,
                trigger,
                &poison,
                decoy,
                options.timeout,
                options.mark,
                raw_offer_timestamps(options.client_tcp_has_timestamps),
                options.cancel.as_deref(),
            ) {
                Ok(true) => {
                    note_raw_probe(family, false);
                    observation.pass += 1;
                    raw_ok += 1;
                }
                Ok(false) => {
                    note_raw_probe(family, false);
                    observation.fail += 1;
                    raw_ok += 1;
                    progress(
                        &observation.probe,
                        result.probes,
                        observation.pass,
                        observation.fail,
                    );
                    break;
                }
                Err(error) => {
                    note_raw_probe(family, true);
                    observation.fail += 1;
                    observation.error = Some(error.message().to_string());
                    raw_errors += 1;
                    local_error = true;
                    progress(
                        &observation.probe,
                        result.probes,
                        observation.pass,
                        observation.fail,
                    );
                    break;
                }
            }
            progress(
                &observation.probe,
                result.probes,
                observation.pass,
                observation.fail,
            );
        }
        if !local_error && observation.pass == options.repeats {
            match executable_poison_hit(&poison, trigger, decoy) {
                Ok(hit) => {
                    add_observation(result, observation);
                    result.props = props.clone();
                    result.composed = true;
                    result.path = Some("собрано".into());
                    return Ok(Some(hit));
                }
                Err(unplannable) => {
                    observation.error = Some(format!(
                        "найдено, но не исполняется: {}",
                        unplannable.reason
                    ));
                    result.unplannable.push(unplannable);
                }
            }
        }
        add_observation(result, observation.clone());
        if should_recheck(cached_selftest, raw_ok, raw_errors) {
            if !raw_recheck(remote, options, result, progress)? {
                result.props = props0.clone();
                result.raw_usable = false;
                return Err(ProbeError::Local(
                    "classify: raw self-test failed after local probe errors".into(),
                ));
            }
            cached_selftest = false;
            raw_ok = 0;
            raw_errors = 0;
        }
    }

    result.props = props.clone();
    for poison in poisons()
        .iter()
        .filter(|poison| poison_selected(options, &poison.name))
    {
        if is_cancelled(options) || result.probes >= options.probe_limit {
            result.stopped = true;
            break;
        }
        if !poison_supports_family(poison, family)
            || !raw_profile_allows(poison, offer_ts)
            || poison.disorder_pos > 0 && poison.disorder_pos as usize >= trigger.payload.len()
            || answered
                .iter()
                .any(|previous| previous.same_hypothesis(poison))
        {
            continue;
        }
        let decoy = poison
            .decoy_hello
            .then_some(selected_decoy.as_deref().unwrap_or(&[]));
        let mut observation = Observation {
            probe: format!("poison:{}", poison.name),
            cuts: Vec::new(),
            delay: Duration::from_millis(poison.gap_ms.max(0) as u64),
            pass: 0,
            fail: 0,
            error: None,
        };
        let mut local_error = false;
        for _ in 0..options.repeats {
            if is_cancelled(options) || result.probes >= options.probe_limit {
                result.stopped = true;
                break;
            }
            result.probes += 1;
            match raw_probe_once(
                remote,
                trigger,
                poison,
                decoy,
                options.timeout,
                options.mark,
                raw_offer_timestamps(options.client_tcp_has_timestamps),
                options.cancel.as_deref(),
            ) {
                Ok(true) => {
                    note_raw_probe(family, false);
                    observation.pass += 1;
                    raw_ok += 1;
                }
                Ok(false) => {
                    note_raw_probe(family, false);
                    observation.fail += 1;
                    raw_ok += 1;
                    progress(
                        &observation.probe,
                        result.probes,
                        observation.pass,
                        observation.fail,
                    );
                    break;
                }
                Err(error) => {
                    note_raw_probe(family, true);
                    observation.fail += 1;
                    raw_errors += 1;
                    observation.error = Some(error.message().to_string());
                    local_error = true;
                    progress(
                        &observation.probe,
                        result.probes,
                        observation.pass,
                        observation.fail,
                    );
                    break;
                }
            }
            progress(
                &observation.probe,
                result.probes,
                observation.pass,
                observation.fail,
            );
        }
        if !local_error && observation.pass == options.repeats {
            match make_poison_hit(poison, trigger, decoy) {
                Ok(Some(hit)) => {
                    add_observation(result, observation);
                    note_props_hit(&mut props, poison);
                    result.props = props.clone();
                    if result.path.is_none() {
                        result.path = Some("перебор".into());
                    }
                    return Ok(Some(hit));
                }
                Ok(None) => {}
                Err(error) => {
                    observation.error = Some(format!("найдено, но не исполняется: {error}"))
                }
            }
        }
        if observation.pass == 0 && observation.error.is_none() {
            note_props_miss(&mut props, poison);
        }
        add_observation(result, observation.clone());
        if should_recheck(cached_selftest, raw_ok, raw_errors) {
            if !raw_recheck(remote, options, result, progress)? {
                result.props = props0.clone();
                result.raw_usable = false;
                return Err(ProbeError::Local(
                    "classify: raw self-test failed after local probe errors".into(),
                ));
            }
            cached_selftest = false;
            raw_ok = 0;
            raw_errors = 0;
        }
        if should_recheck(cached_selftest, raw_ok, raw_errors) {
            if !raw_recheck(remote, options, result, progress)? {
                result.props = props0.clone();
                result.raw_usable = false;
                return Err(ProbeError::Local(
                    "classify: raw self-test failed after local probe errors".into(),
                ));
            }
            cached_selftest = false;
            raw_ok = 0;
            raw_errors = 0;
        }
    }
    result.props = props;
    Ok(None)
}

fn add_observation(result: &mut ClassifyResult, observation: Observation) {
    if result.trace.len() < MAX_TRACE {
        result.trace.push(observation);
    }
}

fn effective_mark(mark: Option<u32>) -> u32 {
    mark.unwrap_or(BYPASS_MARK)
}

/// C `d2k_detect_stopped`/`stop_asked`: липкий общий флаг службы или флаг
/// этой задачи.
fn is_cancelled(options: &ClassifyOptions) -> bool {
    crate::classify::r2o_detect_stop_all_requested()
        || options
            .cancel
            .as_ref()
            .is_some_and(|cancel| cancel.load(Ordering::Relaxed))
}

fn resolve_target(target: &ProbeTarget) -> Result<SocketAddr, ProbeError> {
    let ipv6 = target.host.contains(':');
    (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|error| ProbeError::Transport(format!("dial tcp: {error}")))?
        .find(|address| address.is_ipv6() == ipv6)
        .ok_or_else(|| ProbeError::Transport("classify: адрес цели не разрешился".into()))
}

fn resolve_split_target(target: &ProbeTarget) -> Result<SocketAddr, ProbeError> {
    (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|error| ProbeError::Transport(format!("dial tcp: {error}")))?
        .next()
        .ok_or_else(|| ProbeError::Transport("classify: адрес цели не разрешился".into()))
}

fn majority(pass: usize, total: usize) -> bool {
    total != 0 && pass > total / 2
}

fn should_recheck(cached: bool, successes: usize, errors: usize) -> bool {
    cached && successes == 0 && errors >= 2
}

/// C `host_offers_ts` (`detect/trigger.c:158-178`): кэшированное чтение
/// `/proc/sys/net/ipv4/tcp_timestamps`, по умолчанию 1. Это профиль
/// синтезированного триггера CLI-сканера, а не наблюдение за клиентом.
fn host_offers_ts() -> bool {
    *HOST_TCP_TIMESTAMPS.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/net/ipv4/tcp_timestamps")
            .ok()
            .and_then(|value| value.trim().parse::<i32>().ok())
            .unwrap_or(1)
            != 0
    })
}

fn raw_offer_timestamps(client_profile: Option<bool>) -> bool {
    client_profile.unwrap_or_else(host_offers_ts)
}

const R2O_SELFTEST_TTL: Duration = Duration::from_secs(600);

/// C `selftest_cached_age`: `0 <= age < TTL` → возраст, иначе кэш негоден.
fn selftest_age_from(at: Option<Instant>, now: Instant) -> Option<Duration> {
    let at = at?;
    let age = now.saturating_duration_since(at);
    (age < R2O_SELFTEST_TTL).then_some(age)
}

fn raw_selftest_age(family: u8, offer_ts: bool) -> Option<Duration> {
    let mut cache = RAW_SELFTESTS
        .get_or_init(|| Mutex::new(RawSelftestState::default()))
        .lock()
        .ok()?;
    let index = raw_selftest_index(family, offer_ts);
    let at = cache.checked_at[index]?;
    let age = selftest_age_from(Some(at), Instant::now());
    if age.is_none() {
        cache.checked_at[index] = None;
    }
    age
}

fn note_raw_probe(family: u8, local_error: bool) {
    let family_index = if family == 6 { 1 } else { 0 };
    if let Ok(mut cache) = RAW_SELFTESTS
        .get_or_init(|| Mutex::new(RawSelftestState::default()))
        .lock()
    {
        if local_error {
            cache.error_streak[family_index] = cache.error_streak[family_index].saturating_add(1);
            if cache.error_streak[family_index] >= 3 {
                cache.checked_at[raw_selftest_index(family, true)] = None;
                cache.checked_at[raw_selftest_index(family, false)] = None;
            }
        } else {
            cache.error_streak[family_index] = 0;
        }
    }
}

fn fam_ix(family: u8) -> usize {
    if family == 6 { 1 } else { 0 }
}

fn raw_selftest_index(family: u8, offer_ts: bool) -> usize {
    fam_ix(family) + if offer_ts { 0 } else { 2 }
}

fn raw_syn_options(offer_ts: bool) -> &'static [u8] {
    const WITH_TS: &[u8] = &[
        2, 4, 0x05, 0xac, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    const WITHOUT_TS: &[u8] = &[2, 4, 0x05, 0xac, 1, 3, 3, 7, 1, 1, 4, 2];
    if offer_ts { WITH_TS } else { WITHOUT_TS }
}

fn raw_profile_allows(poison: &Poison, offer_ts: bool) -> bool {
    !poison.tcp_ts || offer_ts
}

fn store_raw_selftest(family: u8, offer_ts: bool, passed: bool) {
    if let Ok(mut cache) = RAW_SELFTESTS
        .get_or_init(|| Mutex::new(RawSelftestState::default()))
        .lock()
    {
        let index = raw_selftest_index(family, offer_ts);
        cache.checked_at[index] = passed.then(Instant::now);
        cache.error_streak[index] = 0;
    }
}

fn raw_recheck(
    remote: SocketAddr,
    options: &ClassifyOptions,
    result: &mut ClassifyResult,
    progress: &mut dyn FnMut(&str, usize, usize, usize),
) -> Result<bool, ProbeError> {
    let mut observation = Observation {
        probe: "raw-selftest".into(),
        cuts: Vec::new(),
        delay: Duration::ZERO,
        pass: 0,
        fail: 0,
        error: None,
    };
    for _ in 0..options.repeats {
        if is_cancelled(options) || result.probes >= options.probe_limit {
            result.stopped = true;
            observation.error = Some("context canceled".into());
            break;
        }
        result.probes += 1;
        match RawConn::connect(
            remote,
            options.timeout,
            effective_mark(options.mark),
            options.cancel.as_deref(),
            raw_offer_timestamps(options.client_tcp_has_timestamps),
        ) {
            Ok(Some(connection)) => {
                drop(connection);
                observation.pass += 1;
                progress(
                    "raw-selftest",
                    result.probes,
                    observation.pass,
                    observation.fail,
                );
                break;
            }
            Ok(None) => {
                observation.fail += 1;
                if observation.error.is_none() {
                    observation.error = Some("classify: SYN-ACK не пришёл".into());
                }
                progress(
                    "raw-selftest",
                    result.probes,
                    observation.pass,
                    observation.fail,
                );
            }
            Err(error) => {
                observation.fail += 1;
                if observation.error.is_none() {
                    observation.error = Some(error.message().to_string());
                }
                progress(
                    "raw-selftest",
                    result.probes,
                    observation.pass,
                    observation.fail,
                );
            }
        }
    }
    add_observation(result, observation.clone());
    let passed = observation.pass > 0;
    store_raw_selftest(
        if remote.is_ipv6() { 6 } else { 4 },
        raw_offer_timestamps(options.client_tcp_has_timestamps),
        passed,
    );
    Ok(passed)
}

#[derive(Clone, Copy)]
enum Property {
    LeftOverlap,
    Reorder,
    Checksum,
    ParsesL7,
    Duplicates,
    Md5,
    SequenceWindow,
    Timestamps,
    OverlapSni,
    UrgentByte,
    DenseDuplicates,
    WhiteTimestamp,
    Syn,
}

struct PropertyProbe {
    label: &'static str,
    poison: Poison,
    set: Property,
}

fn property_probes() -> Vec<PropertyProbe> {
    let mut probes = Vec::with_capacity(13);
    let mut add = |label: &'static str, name: &'static str, set: Property, poison: Poison| {
        probes.push(PropertyProbe {
            label,
            poison: Poison {
                name: name.into(),
                ..poison
            },
            set,
        });
    };
    // Сокрытие имени — первое, что измеряется у коробки, которая уже
    // отбросила целое приветствие и простой разрез: это самые дешёвые и
    // самые результативные примитивы против SNI-фильтра. Остальные вопросы
    // идут после, чтобы успешное плечо возвращалось раньше.
    add(
        "перекрытие до конца имени",
        "seqovl-sni",
        Property::OverlapSni,
        Poison::default(),
    );
    add(
        "срочный байт в середине имени",
        "oob-sni-middle",
        Property::UrgentByte,
        Poison {
            oob: true,
            ..Poison::default()
        },
    );
    add(
        "перекрытие слева",
        "seqovl-1",
        Property::LeftOverlap,
        Poison {
            seqovl: 1,
            ..Poison::default()
        },
    );
    add(
        "порядок сегментов",
        "disorder",
        Property::Reorder,
        Poison {
            disorder: true,
            ..Poison::default()
        },
    );
    add(
        "контрольная сумма",
        "badsum",
        Property::Checksum,
        Poison {
            badsum: true,
            ..Poison::default()
        },
    );
    add(
        "разбор протокола",
        "badsum+hello",
        Property::ParsesL7,
        Poison {
            badsum: true,
            decoy_hello: true,
            ..Poison::default()
        },
    );
    add(
        "повтор как ретрансмит",
        "badsum-x2-g20",
        Property::Duplicates,
        Poison {
            badsum: true,
            repeats: 2,
            gap_ms: 20,
            ..Poison::default()
        },
    );
    add(
        "сверка MD5",
        "md5",
        Property::Md5,
        Poison {
            md5: true,
            ..Poison::default()
        },
    );
    add(
        "окно seq",
        "seq-out-of-window",
        Property::SequenceWindow,
        Poison {
            seq_shift: -66_000,
            ..Poison::default()
        },
    );
    add(
        "метка времени",
        "ts",
        Property::Timestamps,
        Poison {
            tcp_ts: true,
            ..Poison::default()
        },
    );
    add(
        "плотная серия",
        "badsum-x7",
        Property::DenseDuplicates,
        Poison {
            badsum: true,
            repeats: 7,
            ..Poison::default()
        },
    );
    add(
        "ECH-приветствие под меткой",
        "white-hello-ts",
        Property::WhiteTimestamp,
        Poison {
            tcp_ts: true,
            decoy_hello: true,
            repeats: 8,
            split_pos: 2,
            ..Poison::default()
        },
    );
    add(
        "данные в SYN",
        "syndata",
        Property::Syn,
        Poison {
            syn_data: true,
            ..Poison::default()
        },
    );
    probes
}

/// C `tri_yes` (`detect/props.c:419`): свойство подтверждено.
fn tri_yes(value: TriState) -> bool {
    value == TriState::True
}

/// C `tri_no` (`detect/props.c:418`): свойство опровергнуто.
#[cfg(test)]
fn tri_no(value: TriState) -> bool {
    value == TriState::False
}

fn property_probe_poison(
    property: &PropertyProbe,
    offer_ts: bool,
    props: &DpiProps,
) -> Option<Poison> {
    if raw_profile_allows(&property.poison, offer_ts) {
        return Some(property.poison.clone());
    }
    if !matches!(property.set, Property::WhiteTimestamp) || tri_yes(props.validates_checksum) {
        return None;
    }

    let mut poison = property.poison.clone();
    poison.tcp_ts = false;
    poison.badsum = true;
    Some(poison)
}

fn property_probe_label(
    label: &str,
    property: Property,
    poison: &Poison,
    cloned_decoy: bool,
) -> String {
    let label = if matches!(property, Property::WhiteTimestamp) && !poison.tcp_ts {
        "свойство:ECH-приветствие под битой суммой".into()
    } else {
        format!("свойство:{label}")
    };
    if cloned_decoy && poison.decoy_hello {
        format!("{label} (приманка — клон клиента)")
    } else {
        label
    }
}

fn apply_property(props: &mut DpiProps, property: Property, passed: bool, poison: &Poison) {
    match property {
        Property::LeftOverlap => {
            props.tolerates_left_overlap = if passed {
                TriState::False
            } else {
                TriState::True
            }
        }
        Property::Reorder => {
            props.tolerates_reorder = if passed {
                TriState::False
            } else {
                TriState::True
            }
        }
        Property::Checksum if passed => props.validates_checksum = TriState::False,
        Property::ParsesL7 if passed => {
            props.parses_l7 = TriState::True;
            props.validates_checksum = TriState::False;
        }
        Property::Duplicates | Property::DenseDuplicates if passed => {
            props.counts_duplicates = TriState::True
        }
        Property::Md5 if passed => props.validates_md5 = TriState::False,
        Property::SequenceWindow if passed => props.validates_seq_window = TriState::False,
        Property::Timestamps if passed => props.validates_timestamps = TriState::False,
        Property::OverlapSni if passed => props.overlap_covers_sni = TriState::True,
        Property::WhiteTimestamp if passed => {
            props.parses_l7 = TriState::True;
            if poison.tcp_ts {
                props.validates_timestamps = TriState::False;
            }
            if poison.badsum {
                props.validates_checksum = TriState::False;
            }
        }
        Property::Syn if passed => props.inspects_syn = TriState::False,
        _ => {}
    }
}

fn compose_from_props(props: &DpiProps, control: Option<&[u8]>) -> Vec<Poison> {
    let mut base = Poison {
        badsum: !tri_yes(props.validates_checksum),
        decoy_hello: tri_yes(props.parses_l7),
        ..Poison::default()
    };
    let mut out = Vec::with_capacity(4);
    if tri_yes(props.counts_duplicates) {
        let mut spaced = base.clone();
        spaced.name = "СОБРАНО: серия с паузой".into();
        spaced.repeats = 2;
        spaced.gap_ms = 20;
        out.push(spaced);
        let mut dense = base.clone();
        dense.name = "СОБРАНО: плотная серия".into();
        dense.repeats = 7;
        out.push(dense);
    }
    if props.tolerates_left_overlap == TriState::False {
        let mut overlap = base.clone();
        overlap.name = "СОБРАНО: фальшивка + перекрытие".into();
        overlap.seqovl_exact = true;
        overlap.decoy_hello = true;
        overlap.repeats = 7;
        if let Some(control) = control {
            overlap.seqovl = control.len() as i32;
        }
        out.push(overlap);
    }
    if props.tolerates_reorder == TriState::False {
        let mut disorder = base.clone();
        disorder.name = "СОБРАНО: фальшивка + порядок".into();
        disorder.disorder = true;
        disorder.repeats = 7;
        out.push(disorder);
    }
    if out.is_empty() {
        base = Poison {
            name: "СОБРАНО: всё сразу".into(),
            badsum: true,
            decoy_hello: true,
            seqovl_exact: true,
            disorder: true,
            repeats: 7,
            seqovl: control.map_or(0, |bytes| bytes.len() as i32),
            ..Poison::default()
        };
        // C `d2k_compose_from_props` выдаёт «всё сразу» и без контроля:
        // пустая приманка — допустимый вход, а не отсутствие кандидата.
        out.push(base);
    }
    out
}

fn make_poison_hit(
    poison: &Poison,
    trigger: &Trigger,
    decoy: Option<&[u8]>,
) -> Result<Option<PoisonHit>, String> {
    let Some(strategy) = strategy_for_poison(poison) else {
        return Ok(None);
    };
    let plan_text = crate::classify::plan_text_for_poison(poison, trigger, decoy, 0)?;
    let plan = crate::plan_text::compile_text(&plan_text)?;
    let parsed = Plan::parse(&plan).map_err(|error| format!("compiled R2OP rejected: {error}"))?;
    r2o_datapath::engine::validate_runtime_plan(&parsed)
        .map_err(|error| format!("r2o-datapath runtime rejected: {error}"))?;
    Ok(Some(PoisonHit {
        name: poison.name.clone(),
        strategy,
        plan_text,
        plan,
        gap_ms: poison.gap_ms,
    }))
}

fn executable_poison_hit(
    poison: &Poison,
    trigger: &Trigger,
    decoy: Option<&[u8]>,
) -> Result<PoisonHit, UnplannablePoison> {
    match make_poison_hit(poison, trigger, decoy) {
        Ok(Some(hit)) => Ok(hit),
        Ok(None) => Err(UnplannablePoison {
            name: poison.name.clone(),
            reason: "для приёма нет исполняемого выражения плана".into(),
        }),
        Err(reason) => Err(UnplannablePoison {
            name: poison.name.clone(),
            reason,
        }),
    }
}

pub(crate) fn probe_tcp_split(
    target: &ProbeTarget,
    trigger: &Trigger,
    cuts: &[usize],
    gap: Duration,
    timeout: Duration,
    mark: Option<u32>,
    client_tcp_has_timestamps: Option<bool>,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<crate::classify::ProbeOutcome, ProbeError> {
    if cuts.len() != 1 || cuts[0] == 0 || cuts[0] >= trigger.payload.len() {
        return Err(ProbeError::Local("split runtime: invalid cut".into()));
    }
    let remote = resolve_split_target(target)?;
    let mut split = Poison::default();
    split.name = "tcp-split".into();
    split.split_pos = cuts[0] as i32;
    split.gap_ms = gap.as_millis().min(i32::MAX as u128) as i32;
    match raw_probe_once(
        remote,
        trigger,
        &split,
        None,
        timeout,
        mark,
        raw_offer_timestamps(client_tcp_has_timestamps),
        cancel,
    ) {
        Ok(true) => Ok(crate::classify::ProbeOutcome::Accepted),
        Ok(false) => Ok(crate::classify::ProbeOutcome::Rejected),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod test_script {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone, Copy, Debug)]
    pub(super) enum Outcome {
        Fail,
        Error,
    }

    thread_local! {
        static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) };
    }

    struct Script {
        replies: VecDeque<(Option<String>, Outcome)>,
        cancel: Option<(Arc<AtomicBool>, usize)>,
        calls: usize,
        connect_ok: bool,
    }

    pub(super) fn begin(
        replies: Vec<(Option<&str>, Outcome)>,
        cancel_after: Option<(Arc<AtomicBool>, usize)>,
        connect_ok: bool,
    ) {
        SCRIPT.with(|cell| {
            *cell.borrow_mut() = Some(Script {
                replies: replies
                    .into_iter()
                    .map(|(name, outcome)| (name.map(str::to_owned), outcome))
                    .collect(),
                cancel: cancel_after,
                calls: 0,
                connect_ok,
            });
        });
    }

    pub(super) fn take(name: &str) -> Option<Outcome> {
        SCRIPT.with(|cell| {
            let mut script = cell.borrow_mut();
            let script = script.as_mut()?;
            script.calls += 1;
            if let Some((cancel, after)) = &script.cancel {
                if script.calls >= *after {
                    cancel.store(true, Ordering::Relaxed);
                }
            }
            let position = script
                .replies
                .iter()
                .position(|(filter, _)| filter.as_deref().is_none_or(|filter| filter == name));
            Some(
                position
                    .and_then(|index| script.replies.remove(index))
                    .map_or(Outcome::Error, |(_, outcome)| outcome),
            )
        })
    }

    pub(super) fn connect_ok() -> bool {
        SCRIPT.with(|cell| {
            cell.borrow()
                .as_ref()
                .is_some_and(|script| script.connect_ok)
        })
    }

    pub(super) fn calls() -> usize {
        SCRIPT.with(|cell| cell.borrow().as_ref().map_or(0, |script| script.calls))
    }

    pub(super) fn finish() {
        SCRIPT.with(|cell| *cell.borrow_mut() = None);
    }
}

fn raw_probe_once(
    remote: SocketAddr,
    trigger: &Trigger,
    poison: &Poison,
    decoy: Option<&[u8]>,
    timeout: Duration,
    mark: Option<u32>,
    offer_ts: bool,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<bool, ProbeError> {
    // Решение принимается по первому ответу сервера: рабочий обход отвечает
    // за единицы RTT, а молчание уже наступило. Ждать шесть секунд на каждую
    // отрицательную гипотезу — это минуты перебора без пользы.
    const PROBE_TIMEOUT_CAP: Duration = Duration::from_millis(2_500);
    let timeout = timeout.min(PROBE_TIMEOUT_CAP);
    #[cfg(test)]
    if let Some(outcome) = test_script::take(&poison.name) {
        return match outcome {
            test_script::Outcome::Fail => Ok(false),
            test_script::Outcome::Error => Err(ProbeError::Local("scripted local error".into())),
        };
    }
    let mut connection =
        match RawConn::connect(remote, timeout, effective_mark(mark), cancel, offer_ts)? {
            Some(connection) => connection,
            None => {
                return Err(ProbeError::RawConnectTimeout {
                    message: "classify: SYN-ACK не пришёл".into(),
                    peer: remote,
                });
            }
        };

    if poison.name == "none" || poison.syn_data {
        let flags = if poison.syn_data {
            TCP_PSH | TCP_ACK | TCP_SYN
        } else {
            TCP_PSH | TCP_ACK
        };
        connection
            .send_payload_io(&trigger.payload, flags, &[])
            .map_err(|error| ProbeError::Local(format!("classify: {error}")))?;
        connection.sequence = connection
            .sequence
            .wrapping_add(trigger.payload.len() as u32);
    } else {
        let plan = crate::classify::plan_for_poison(poison, trigger, decoy, 0)
            .map_err(ProbeError::Local)?;
        let tcp_options = connection.template_options.as_deref().unwrap_or(&[]);
        let input = build_control_packet(
            connection.local,
            connection.remote,
            connection.source_port,
            connection.destination_port,
            connection.sequence,
            connection.acknowledgment,
            TCP_ACK | TCP_PSH,
            tcp_options,
            &trigger.payload,
        )
        .ok_or_else(|| ProbeError::Local("classify: входной TCP пакет не собран".into()))?;
        match decide(&plan, &input) {
            PacketDecision::Transmit {
                packets,
                fate: OriginalFate::Drop,
            } => {
                emit_plan_packets(
                    packets
                        .into_iter()
                        .map(|packet| (packet.delay_us, packet.packet)),
                    cancel,
                    crate::response::r2o_nap,
                    |packet| connection.send_ip_packet(packet),
                )?;
            }
            _ => {
                return Err(ProbeError::Local(
                    "не удалось исполнить измерительный план".into(),
                ));
            }
        }
        connection.sequence = connection
            .sequence
            .wrapping_add(trigger.payload.len() as u32 + u32::from(poison.oob));
        if poison.disorder
            && poison.disorder_pos == 0
            && poison.seqovl == 0
            && !poison.seqovl_exact
            && !poison.fake_between
        {
            thread::sleep(Duration::from_millis(12));
        }
    }

    let Some(response) = connection.read_payload(timeout, cancel)? else {
        return Ok(false);
    };
    Ok(trigger_accepts(trigger.accept, &response))
}

fn emit_plan_packets(
    packets: impl IntoIterator<Item = (u32, Vec<u8>)>,
    cancel: Option<&std::sync::atomic::AtomicBool>,
    mut sleep: impl FnMut(Duration),
    mut send: impl FnMut(&[u8]) -> Result<(), ProbeError>,
) -> Result<(), ProbeError> {
    for (delay_us, packet) in packets {
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err(ProbeError::Local("context canceled".into()));
        }
        if delay_us != 0 {
            sleep(Duration::from_micros(u64::from(delay_us)));
        }
        send(&packet)?;
    }
    Ok(())
}

fn command_fds_cloexec_from_proc() -> std::io::Result<()> {
    use std::io::Error;

    let directory = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if directory < 0 {
        return Err(Error::last_os_error());
    }
    let result = (|| {
        let mut buffer = [0_u8; 1024];
        loop {
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    directory,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            };
            if count == 0 {
                return Ok(());
            }
            if count < 0 {
                let error = Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let mut entries = &buffer[..count as usize];
            // linux_dirent64: ino (8), off (8), reclen (2), type (1), name.
            while entries.len() >= 20 {
                let length = u16::from_ne_bytes([entries[16], entries[17]]) as usize;
                if !(20..=entries.len()).contains(&length) {
                    break;
                }
                let name = entries[19..length].split(|&byte| byte == 0).next();
                let fd = name
                    .and_then(|name| std::str::from_utf8(name).ok())
                    .and_then(|name| name.parse::<libc::c_int>().ok());
                if let Some(fd) = fd.filter(|&fd| fd >= 3)
                    && unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
                {
                    return Err(Error::last_os_error());
                }
                entries = &entries[length..];
            }
            if !entries.is_empty() {
                return Err(Error::from_raw_os_error(libc::EIO));
            }
        }
    })();
    unsafe { libc::close(directory) };
    result
}

fn command_fds_cloexec() -> std::io::Result<()> {
    // Keep Rust's exec-status pipe open until exec succeeds. The old-kernel
    // path also uses only syscalls and stack storage in the forked child.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        command_fds_cloexec_from_proc()
    }
}

fn run_command(program: &str, args: &[String]) -> Result<std::process::ExitStatus, String> {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // C `raw_rule_system`: своя группа процессов, чтобы по сроку убить и sh,
    // и iptables/nft, а не оставить потомка ждать замок xtables.
    command.process_group(0);
    unsafe {
        command.pre_exec(command_fds_cloexec);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("{program}: {error}"))?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let pid = child.id() as libc::pid_t;
                let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program}: command timed out"));
            }
            Err(error) => return Err(format!("{program}: {error}")),
        }
    }
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        if chunk.len() == 2 {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        } else {
            sum += u32::from(chunk[0]) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
fn tcp_checksum_valid(source: IpAddr, destination: IpAddr, segment: &[u8]) -> bool {
    tcp_checksum(source, destination, segment) == 0
}

fn tcp_checksum(source: IpAddr, destination: IpAddr, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + segment.len());
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&[0, libc::IPPROTO_TCP as u8]);
            pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, libc::IPPROTO_TCP as u8]);
        }
        _ => return 0,
    }
    pseudo.extend_from_slice(segment);
    internet_checksum(&pseudo)
}

#[allow(clippy::too_many_arguments)]
fn build_control_packet(
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if source.is_ipv4() != destination.is_ipv4()
        || options.len() > 40
        || !options.len().is_multiple_of(4)
    {
        return None;
    }
    let tcp_len = 20usize
        .checked_add(options.len())?
        .checked_add(payload.len())?;
    if tcp_len > u16::MAX as usize {
        return None;
    }
    let ip_len: usize = if source.is_ipv4() { 20 } else { 40 };
    let total_len = ip_len.checked_add(tcp_len)?;
    if source.is_ipv4() && total_len > u16::MAX as usize {
        return None;
    }
    let mut packet = vec![0; total_len];
    let tcp_offset = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            let id = random_u32() as u16;
            packet[4..6].copy_from_slice(&if id == 0 { 1 } else { id }.to_be_bytes());
            packet[8] = 64;
            packet[9] = libc::IPPROTO_TCP as u8;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            let checksum = internet_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            20
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            packet[6] = libc::IPPROTO_TCP as u8;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
            40
        }
        _ => return None,
    };
    let tcp = &mut packet[tcp_offset..];
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgment.to_be_bytes());
    tcp[12] = (((20 + options.len()) / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    tcp[20..20 + options.len()].copy_from_slice(options);
    tcp[20 + options.len()..].copy_from_slice(payload);
    let checksum = tcp_checksum(source, destination, tcp);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    Some(packet)
}

fn random_u32() -> u32 {
    let mut output = 0u32;
    let result = unsafe {
        libc::getrandom(
            (&mut output as *mut u32).cast(),
            std::mem::size_of::<u32>(),
            0,
        )
    };
    if result as usize == std::mem::size_of::<u32>() {
        output
    } else {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32)
            ^ (std::process::id().rotate_left(7))
    }
}

static NEXT_SOURCE_PORT: OnceLock<AtomicU32> = OnceLock::new();

fn next_source_port() -> u16 {
    let next = NEXT_SOURCE_PORT.get_or_init(|| AtomicU32::new(random_u32() % 25_000));
    // C `next_source_port`: сначала `g_sport_counter++`, затем `% 25000`.
    source_port_from_counter(next.fetch_add(1, Ordering::Relaxed).wrapping_add(1))
}

/// C `next_source_port`: `30000 + counter % 25000`, счётчик уже увеличен.
fn source_port_from_counter(counter: u32) -> u16 {
    (30_000 + counter % 25_000) as u16
}

fn set_option<T>(fd: i32, level: i32, option: i32, value: &T) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (value as *const T).cast(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn local_address_for(remote: SocketAddr) -> io::Result<IpAddr> {
    let bind_address = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_address)?;
    socket.connect(remote)?;
    Ok(socket.local_addr()?.ip())
}

static IPTABLES_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static RST_PENDING: OnceLock<Mutex<Vec<PendingRstRelease>>> = OnceLock::new();
static RST_CLEANUP_REGISTERED: Once = Once::new();

#[derive(Clone)]
struct RstRule {
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
    nft: bool,
    comment: bool,
}

struct PendingRstRelease {
    rule: RstRule,
    attempts: u8,
}

struct RstGuard {
    rule: Option<RstRule>,
}

/// C `rst_nft`: `D2K_FW == "nft"`; R2O дополнительно принимает `R2O_FW`.
fn r2o_rst_uses_nft(d2k_fw: Option<&str>, r2o_fw: Option<&str>) -> bool {
    d2k_fw.or(r2o_fw) == Some("nft")
}

fn run_rule_command(
    program: &str,
    args: &[String],
    rule: &RstRule,
) -> Result<std::process::ExitStatus, ProbeError> {
    match run_command(program, args) {
        Ok(status) => Ok(status),
        Err(error) => {
            // C `raw_rule_system` мог успеть зафиксировать правило за миг до
            // SIGKILL: D2K_RAW_RULE_KILLED → rst_release_locked.
            if error.ends_with("command timed out") {
                rst_release_locked(rule);
            }
            Err(ProbeError::Local(format!("classify: {error}")))
        }
    }
}

impl RstRule {
    fn install(source_port: u16, destination: SocketAddr) -> Result<Self, ProbeError> {
        // C `rst_nft` читает `D2K_FW`; R2O дополнительно принимает `R2O_FW`.
        let d2k_fw = std::env::var("D2K_FW").ok();
        let r2o_fw = std::env::var("R2O_FW").ok();
        let nft = r2o_rst_uses_nft(d2k_fw.as_deref(), r2o_fw.as_deref());
        let mut guard = Self {
            source_port,
            destination: destination.ip(),
            destination_port: destination.port(),
            nft,
            comment: RST_COMMENT_SUPPORTED.load(Ordering::Relaxed),
        };
        if !nft {
            RST_STALE_RULE_SWEEP.call_once(sweep_stale_iptables);
        }
        let _lock = IPTABLES_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retry_pending_rst_releases_locked(false);
        register_rst_cleanup();
        if nft {
            let args = guard.nft_args("add");
            let status = run_rule_command("nft", &args, &guard)?;
            if !status.success() {
                return Err(ProbeError::Local(
                    "classify: nft не добавил ключ подавления RST".into(),
                ));
            }
            return Ok(guard);
        }

        let args = guard.iptables_args(guard.comment, "-I");
        let program = if destination.is_ipv6() {
            "ip6tables"
        } else {
            "iptables"
        };
        let status = run_rule_command(program, &args, &guard)?;
        if status.success() {
            return Ok(guard);
        }
        if !guard.comment || !matches!(status.code(), Some(1 | 2)) {
            return Err(ProbeError::Local(format!(
                "classify: {program} не установил подавление ядерного RST"
            )));
        }
        let fallback = guard.iptables_args(false, "-I");
        let status = run_rule_command(program, &fallback, &guard)?;
        if status.success() {
            RST_COMMENT_SUPPORTED.store(false, Ordering::Relaxed);
            guard.comment = false;
            return Ok(guard);
        }
        Err(ProbeError::Local(format!(
            "classify: {program} не установил подавление ядерного RST"
        )))
    }

    fn nft_args(&self, verb: &str) -> Vec<String> {
        let family = if self.destination.is_ipv6() {
            "rst6"
        } else {
            "rst4"
        };
        let address = self.destination.to_string();
        let timeout = if verb == "add" {
            format!(" timeout {}s", RST_TIMEOUT.as_secs())
        } else {
            String::new()
        };
        vec![
            verb.into(),
            "element".into(),
            "inet".into(),
            "r2o_rst".into(),
            family.into(),
            format!(
                "{{ {} . {} . {}{} }}",
                self.source_port, address, self.destination_port, timeout
            ),
        ]
    }

    fn iptables_args(&self, comment: bool, operation: &str) -> Vec<String> {
        let mut args = vec![
            "-w".into(),
            operation.into(),
            "OUTPUT".into(),
            "-p".into(),
            "tcp".into(),
            "--sport".into(),
            self.source_port.to_string(),
            "--tcp-flags".into(),
            "RST".into(),
            "RST".into(),
        ];
        if comment {
            args.extend([
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                format!("r2o-rst:{}", std::process::id()),
            ]);
        }
        args.extend(["-j".into(), "DROP".into()]);
        args
    }
}

impl RstGuard {
    fn install(source_port: u16, destination: SocketAddr) -> Self {
        RST_RULE_FAILURES.with(|failures| {
            Self::from_install_result(RstRule::install(source_port, destination), failures)
        })
    }

    fn release(&mut self) {
        if let Some(rule) = self.rule.take() {
            rst_release(&rule);
        }
    }

    fn from_install_result(result: Result<RstRule, ProbeError>, failures: &Cell<u64>) -> Self {
        match result {
            Ok(rule) => Self { rule: Some(rule) },
            Err(_) => {
                failures.set(failures.get().saturating_add(1));
                Self { rule: None }
            }
        }
    }
}

impl Drop for RstGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// C `rc_exit1` (`detect/raw.c:407-410`): `WIFEXITED && WEXITSTATUS==1`.
fn rc_exit1(status: &std::process::ExitStatus) -> bool {
    status.code() == Some(1)
}

fn rst_delete_once_locked(rule: &RstRule) -> bool {
    if rule.nft {
        let deleted = run_command("nft", &rule.nft_args("delete"));
        if deleted.as_ref().is_ok_and(|status| status.success()) {
            return true;
        }
        return deleted.as_ref().is_ok_and(|status| rc_exit1(status))
            && run_command("nft", &rule.nft_args("get")).is_ok_and(|status| rc_exit1(&status));
    }

    let program = if rule.destination.is_ipv6() {
        "ip6tables"
    } else {
        "iptables"
    };
    let deleted = run_command(program, &rule.iptables_args(rule.comment, "-D"));
    if deleted.as_ref().is_ok_and(|status| status.success()) {
        return true;
    }
    deleted.as_ref().is_ok_and(|status| rc_exit1(status))
        && run_command(program, &rule.iptables_args(rule.comment, "-C"))
            .is_ok_and(|status| rc_exit1(&status))
}

fn r2o_rst_abandon_message(rule: &RstRule) -> String {
    format!(
        "r2o: правило подавления RST ({}, порт {}) не снято за 5 попыток — больше не повторяю \
         до выхода процесса; при выходе попробую ещё раз, оставшееся снимет уборка следующего \
         запуска r2o",
        if rule.destination.is_ipv6() {
            "ip6tables"
        } else {
            "iptables"
        },
        rule.source_port
    )
}

fn rst_release_locked(rule: &RstRule) {
    if !rst_delete_once_locked(rule) && !rst_delete_once_locked(rule) {
        let pending = RST_PENDING.get_or_init(|| Mutex::new(Vec::new()));
        let mut pending = pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending.len() < RST_PENDING_MAX {
            pending.push(PendingRstRelease {
                rule: rule.clone(),
                attempts: 2,
            });
        } else {
            let message = r2o_rst_abandon_message(rule);
            RST_ABANDON_REPORTED.call_once(|| {
                eprintln!("{message}");
            });
        }
    }
}

fn rst_release(rule: &RstRule) {
    let _lock = IPTABLES_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    rst_release_locked(rule);
}

fn retry_pending_rst_releases_locked(final_attempt: bool) {
    let Some(pending) = RST_PENDING.get() else {
        return;
    };
    let mut pending = pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut index = 0;
    while index < pending.len() {
        if !final_attempt && pending[index].attempts >= RST_RELEASE_ATTEMPTS {
            index += 1;
            continue;
        }
        if rst_delete_once_locked(&pending[index].rule) {
            pending.remove(index);
            continue;
        }
        pending[index].attempts = pending[index].attempts.saturating_add(1);
        if pending[index].attempts >= RST_RELEASE_ATTEMPTS && !final_attempt {
            let message = r2o_rst_abandon_message(&pending[index].rule);
            RST_ABANDON_REPORTED.call_once(|| {
                eprintln!("{message}");
            });
        }
        index += 1;
    }
}

fn retry_pending_rst_releases(final_attempt: bool) {
    if RST_PENDING.get().is_none() {
        return;
    }
    let _lock = IPTABLES_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    retry_pending_rst_releases_locked(final_attempt);
}

/// C `d2k_raw_pending_count` (`detect/raw.c:488-495`): число отложенных
/// снятий RST-правил под mutex.
#[cfg(test)]
pub(crate) fn rst_pending_count() -> usize {
    RST_PENDING.get().map_or(0, |pending| {
        pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    })
}

extern "C" fn rst_cleanup_at_exit() {
    retry_pending_rst_releases(true);
}

fn register_rst_cleanup() {
    RST_CLEANUP_REGISTERED.call_once(|| unsafe {
        libc::atexit(rst_cleanup_at_exit);
    });
}

pub(crate) fn flush_pending_rst_releases() {
    retry_pending_rst_releases(false);
}

fn parse_long_exact(bytes: &[u8]) -> Option<std::os::raw::c_long> {
    if bytes.is_empty() || bytes.len() >= 32 || !bytes.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

/// C `d2k_parse_rst_rule` (`detect/raw.c:79-118`): наше ли правило, порт и
/// необязательный PID владельца. Разбор чисто строчный, без iptables.
fn parse_rst_rule(line: &str) -> Option<(u16, Option<i64>)> {
    let line = line.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if !line.starts_with(RST_PREFIX) {
        return None;
    }
    let rest = &line[RST_PREFIX.len()..];
    let digits_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if digits_end == 0 {
        return None;
    }
    let port = parse_long_exact(&rest.as_bytes()[..digits_end])?;
    if !(30000..=54999).contains(&port) {
        return None;
    }
    let after = &rest[digits_end..];
    if after == RST_LEGACY_SUFFIX {
        return Some((port as u16, None));
    }
    if after.len() > RST_OWNED_MID.len() + RST_OWNED_TAG.len() + RST_OWNED_SUFFIX.len()
        && after.starts_with(RST_OWNED_MID)
        && line.ends_with(RST_OWNED_SUFFIX)
    {
        let mut owner = &after[RST_OWNED_MID.len()..after.len() - RST_OWNED_SUFFIX.len()];
        if owner.starts_with('"') {
            if owner.len() < 2 || !owner.ends_with('"') {
                return None;
            }
            owner = &owner[1..owner.len() - 1];
        }
        if !owner.starts_with(RST_OWNED_TAG) && !owner.starts_with(RST_OWNED_TAG_R2O) {
            return None;
        }
        let pid_text = owner
            .strip_prefix(RST_OWNED_TAG)
            .or_else(|| owner.strip_prefix(RST_OWNED_TAG_R2O))?;
        let pid = parse_long_exact(pid_text.as_bytes())?;
        if pid <= 0 {
            return None;
        }
        return Some((port as u16, Some(i64::from(pid))));
    }
    None
}

/// C `d2k_parse_stale_rst_rule`: порт нашего правила любого формата.
#[cfg(test)]
fn parse_stale_rst_rule(line: &str) -> Option<u16> {
    parse_rst_rule(line).map(|(port, _)| port)
}

fn pid_alive(pid: i64) -> bool {
    if pid <= 0 || pid > i32::MAX as i64 {
        return false;
    }
    let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
    alive || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// C `d2k_rst_rule_stale`: правило разобралось, владельца нет или он мёртв.
fn rst_rule_stale_with(line: &str, alive: impl Fn(i64) -> bool) -> Option<(u16, Option<i64>)> {
    let (port, owner) = parse_rst_rule(line)?;
    match owner {
        None => Some((port, None)),
        Some(pid) if !alive(pid) => Some((port, Some(pid))),
        _ => None,
    }
}

fn rst_rule_stale(line: &str) -> Option<(u16, Option<i64>)> {
    rst_rule_stale_with(line, pid_alive)
}

fn sweep_stale_iptables() {
    for program in ["iptables", "ip6tables"] {
        let args: Vec<String> = vec!["-w".into(), "-S".into(), "OUTPUT".into()];
        let Ok(mut child) = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let mut timed_out = false;
        loop {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            crate::now_ms::d2k_sleep_ms(10);
        }
        if timed_out {
            let _ = child.wait();
        }
        let Ok(output) = child.wait_with_output() else {
            continue;
        };
        let rules = String::from_utf8_lossy(&output.stdout);
        for line in rules.lines() {
            // Legacy-правило без метки и owned-правило `d2k-rst:PID` —
            // только брошенные (`detect/raw.c:137-143`).
            if let Some((port, owner)) = rst_rule_stale(line) {
                let mut args = vec![
                    "-w".to_string(),
                    "-D".to_string(),
                    "OUTPUT".to_string(),
                    "-p".to_string(),
                    "tcp".to_string(),
                    "--sport".to_string(),
                    port.to_string(),
                    "--tcp-flags".to_string(),
                    "RST".to_string(),
                    "RST".to_string(),
                ];
                if let Some(pid) = owner {
                    args.extend([
                        "-m".to_string(),
                        "comment".to_string(),
                        "--comment".to_string(),
                        format!("d2k-rst:{pid}"),
                    ]);
                }
                args.extend(["-j".to_string(), "DROP".to_string()]);
                let _ = run_command(program, &args);
                continue;
            }
            let Some((_, owner)) = line.split_once("--comment r2o-rst:") else {
                continue;
            };
            let owner = owner.split_whitespace().next().unwrap_or_default();
            let Ok(pid) = owner.parse::<i32>() else {
                continue;
            };
            if unsafe { libc::kill(pid, 0) } == 0
                || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
            {
                continue;
            }
            let Some((_, source_port)) = line.split_once("--sport ") else {
                continue;
            };
            let source_port = source_port.split_whitespace().next().unwrap_or_default();
            let Ok(port) = source_port.parse::<u16>() else {
                continue;
            };
            let args = vec![
                "-w".into(),
                "-D".into(),
                "OUTPUT".into(),
                "-p".into(),
                "tcp".into(),
                "--sport".into(),
                port.to_string(),
                "--tcp-flags".into(),
                "RST".into(),
                "RST".into(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                format!("r2o-rst:{pid}"),
                "-j".into(),
                "DROP".into(),
            ];
            let _ = run_command(program, &args);
        }
    }
}

struct RawConn {
    sender: Option<OwnedFd>,
    receiver: Option<OwnedFd>,
    rst_guard: RstGuard,
    local: IpAddr,
    remote: IpAddr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    template_options: Option<Vec<u8>>,
    recv_buffer: Vec<u8>,
}

/// C `raw_sendto` (`detect/raw.c:773`): IPv4 считает успехом любой
/// неотрицательный результат (короткая запись не проверяется), IPv6 требует
/// ровно `len`. Это решение обязано совпадать с донором, даже если Linux
/// обычно не режет датаграмму.
fn raw_sendto_ok(family: u8, sent: isize, len: usize) -> bool {
    if family == 6 {
        sent >= 0 && sent as usize == len
    } else {
        sent >= 0
    }
}

/// Test-only инъекция системных вызовов сырого слоя. В production-сборке
/// модуль отсутствует, а обёртки ниже вызывают libc напрямую.
#[cfg(test)]
mod test_io {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io;
    use std::net::IpAddr;

    #[derive(Clone, Copy)]
    pub(super) enum SendReply {
        Ok(isize),
        OkLen,
        Err(i32),
    }
    pub(super) enum RecvReply {
        Packet {
            bytes: Vec<u8>,
            peer: Option<(libc::c_int, IpAddr)>,
        },
        Err(i32),
    }

    pub(super) enum PollReply {
        Ready(i16),
    }

    pub(super) enum CloseReply {
        Ok,
    }

    #[derive(Default)]
    pub(super) struct Script {
        pub active: bool,
        pub send: VecDeque<SendReply>,
        pub recv: VecDeque<RecvReply>,
        pub poll: VecDeque<PollReply>,
        pub close: VecDeque<CloseReply>,
        pub sent: Vec<Vec<u8>>,
        pub closed: Vec<&'static str>,
    }

    thread_local! {
        static SCRIPT: RefCell<Script> = RefCell::new(Script::default());
    }

    pub(super) fn begin(script: Script) {
        SCRIPT.with(|cell| {
            let mut script = script;
            script.active = true;
            *cell.borrow_mut() = script;
        });
    }

    pub(super) fn finish() -> Script {
        SCRIPT.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
    }

    pub(super) fn sendto(bytes: &[u8]) -> Option<io::Result<isize>> {
        SCRIPT.with(|cell| {
            let mut script = cell.borrow_mut();
            if !script.active {
                return None;
            }
            script.sent.push(bytes.to_vec());
            Some(script.send.pop_front().map_or(
                Err(io::Error::from_raw_os_error(libc::EAGAIN)),
                |reply| match reply {
                    SendReply::Ok(sent) => Ok(sent),
                    SendReply::OkLen => Ok(bytes.len() as isize),
                    SendReply::Err(errno) => Err(io::Error::from_raw_os_error(errno)),
                },
            ))
        })
    }

    pub(super) fn recvfrom() -> Option<RecvReply> {
        SCRIPT.with(|cell| {
            let mut script = cell.borrow_mut();
            if !script.active {
                return None;
            }
            Some(
                script
                    .recv
                    .pop_front()
                    .unwrap_or(RecvReply::Err(libc::EAGAIN)),
            )
        })
    }

    pub(super) fn poll() -> Option<io::Result<(i32, i16)>> {
        SCRIPT.with(|cell| {
            let mut script = cell.borrow_mut();
            if !script.active {
                return None;
            }
            Some(
                script
                    .poll
                    .pop_front()
                    .map_or(Ok((0, 0)), |reply| match reply {
                        PollReply::Ready(revents) => Ok((1, revents)),
                    }),
            )
        })
    }

    pub(super) fn close() -> Option<io::Result<()>> {
        SCRIPT.with(|cell| {
            let mut script = cell.borrow_mut();
            if !script.active {
                return None;
            }
            Some(
                script
                    .close
                    .pop_front()
                    .map_or(Ok(()), |reply| match reply {
                        CloseReply::Ok => Ok(()),
                    }),
            )
        })
    }

    pub(super) fn note_closed(label: &'static str) {
        SCRIPT.with(|cell| cell.borrow_mut().closed.push(label));
    }
}

#[cfg(test)]
fn test_peer_sockaddr(
    storage: &mut libc::sockaddr_storage,
    len: &mut libc::socklen_t,
    family: libc::c_int,
    address: IpAddr,
) {
    match address {
        IpAddr::V4(value) => {
            let peer = unsafe { &mut *(storage as *mut _ as *mut libc::sockaddr_in) };
            peer.sin_family = family as libc::sa_family_t;
            peer.sin_addr.s_addr = u32::from_ne_bytes(value.octets());
            *len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        }
        IpAddr::V6(value) => {
            let peer = unsafe { &mut *(storage as *mut _ as *mut libc::sockaddr_in6) };
            peer.sin6_family = family as libc::sa_family_t;
            peer.sin6_addr.s6_addr = value.octets();
            *len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        }
    }
}

fn sys_sendto(
    fd: libc::c_int,
    packet: &[u8],
    flags: libc::c_int,
    destination: *const libc::sockaddr_storage,
    destination_len: libc::socklen_t,
) -> io::Result<isize> {
    #[cfg(test)]
    if let Some(reply) = test_io::sendto(packet) {
        return reply;
    }
    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr().cast(),
            packet.len(),
            flags,
            destination.cast(),
            destination_len,
        )
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sent)
    }
}

fn sys_poll(fd: libc::c_int, events: i16, timeout_ms: libc::c_int) -> io::Result<(i32, i16)> {
    #[cfg(test)]
    if let Some(reply) = test_io::poll() {
        return reply;
    }
    let mut pollfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let polled = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
    if polled < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((polled, pollfd.revents))
    }
}

fn sys_recvfrom(
    fd: libc::c_int,
    buffer: &mut [u8],
    peer: &mut libc::sockaddr_storage,
    peer_len: &mut libc::socklen_t,
) -> io::Result<usize> {
    #[cfg(test)]
    if let Some(reply) = test_io::recvfrom() {
        return match reply {
            test_io::RecvReply::Err(errno) => Err(io::Error::from_raw_os_error(errno)),
            test_io::RecvReply::Packet {
                bytes,
                peer: address,
            } => {
                let count = bytes.len().min(buffer.len());
                buffer[..count].copy_from_slice(&bytes[..count]);
                if let Some((family, address)) = address {
                    test_peer_sockaddr(peer, peer_len, family, address);
                }
                Ok(count)
            }
        };
    }
    let count = unsafe {
        libc::recvfrom(
            fd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_DONTWAIT,
            (peer as *mut libc::sockaddr_storage).cast(),
            peer_len,
        )
    };
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(count as usize)
    }
}

/// C `strerror(errno)` без приписки Rust `(os error N)`.
fn raw_error_text(error: &io::Error) -> String {
    if let Some(errno) = error.raw_os_error() {
        let message = unsafe { libc::strerror(errno) };
        if !message.is_null() {
            return unsafe { std::ffi::CStr::from_ptr(message) }
                .to_string_lossy()
                .into_owned();
        }
    }
    error.to_string()
}

fn raw_close_fd(fd: libc::c_int) -> bool {
    #[cfg(test)]
    if let Some(result) = test_io::close() {
        let _ = result;
        return false;
    }
    let _ = unsafe { libc::close(fd) };
    true
}

impl RawConn {
    fn connect(
        remote: SocketAddr,
        timeout: Duration,
        mark: u32,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        offer_ts: bool,
    ) -> Result<Option<Self>, ProbeError> {
        #[cfg(test)]
        if test_script::connect_ok() {
            return Ok(Some(Self::test_connection(
                remote.ip(),
                remote.ip(),
                40_000,
                remote.port(),
                1000,
                0,
            )));
        }
        let local = local_address_for(remote).map_err(|error| {
            ProbeError::Local(format!(
                "classify: не удалось определить свой адрес: {error}"
            ))
        })?;
        let family = if remote.is_ipv6() {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        let sender_fd = unsafe {
            libc::socket(
                family,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        };
        if sender_fd < 0 {
            return Err(ProbeError::Unsupported(format!(
                "classify: raw sender: {}",
                io::Error::last_os_error()
            )));
        }
        let sender = unsafe { OwnedFd::from_raw_fd(sender_fd) };
        let hdrincl = 1 as libc::c_int;
        let option = if remote.is_ipv6() {
            libc::IPV6_HDRINCL
        } else {
            libc::IP_HDRINCL
        };
        set_option(
            sender.as_raw_fd(),
            if remote.is_ipv6() {
                libc::IPPROTO_IPV6
            } else {
                libc::IPPROTO_IP
            },
            option,
            &hdrincl,
        )
        .map_err(|error| ProbeError::Local(format!("classify: IP_HDRINCL: {error}")))?;
        if mark != 0 {
            set_option(sender.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, &mark)
                .map_err(|error| ProbeError::Local(format!("classify: SO_MARK: {error}")))?;
        }
        let receiver_fd = unsafe {
            libc::socket(
                family,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::IPPROTO_TCP,
            )
        };
        if receiver_fd < 0 {
            return Err(ProbeError::Unsupported(format!(
                "classify: сырой сокет на приём: {}",
                io::Error::last_os_error()
            )));
        }
        let receiver = unsafe { OwnedFd::from_raw_fd(receiver_fd) };
        if let IpAddr::V6(local) = local {
            let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            address.sin6_addr.s6_addr = local.octets();
            let status = unsafe {
                libc::bind(
                    receiver.as_raw_fd(),
                    (&address as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if status != 0 {
                return Err(ProbeError::Local(format!(
                    "classify: IPv6 receive bind: {}",
                    io::Error::last_os_error()
                )));
            }
        }
        let source_port = next_source_port();
        note_raw_dial();
        let rst_guard = RstGuard::install(source_port, remote);
        let mut connection = Self {
            sender: Some(sender),
            receiver: Some(receiver),
            rst_guard,
            local,
            remote: remote.ip(),
            source_port,
            destination_port: remote.port(),
            sequence: random_u32(),
            acknowledgment: 0,
            template_options: None,
            recv_buffer: vec![0; u16::MAX as usize],
        };
        let syn_options = raw_syn_options(offer_ts);
        let established = connection.handshake(timeout, cancel, syn_options)?;
        Ok(established.then_some(connection))
    }

    fn handshake(
        &mut self,
        timeout: Duration,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        syn_options: &[u8],
    ) -> Result<bool, ProbeError> {
        let mut rto = Duration::from_secs(1);
        let deadline = Instant::now() + timeout;
        let mut next_syn = Instant::now();
        loop {
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err(ProbeError::Local("context canceled".into()));
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            if Instant::now() >= next_syn {
                let packet = build_control_packet(
                    self.local,
                    self.remote,
                    self.source_port,
                    self.destination_port,
                    self.sequence,
                    0,
                    TCP_SYN,
                    syn_options,
                    &[],
                )
                .ok_or_else(|| ProbeError::Local("classify: SYN пакет не собран".into()))?;
                self.send_packet_io(&packet)
                    .map_err(|error| ProbeError::Local(raw_error_text(&error)))?;
                next_syn = Instant::now() + rto;
                rto = rto.saturating_mul(2);
            }
            let wait_until = deadline.min(next_syn);
            let Some(segment) = self.receive_segment(wait_until, cancel)? else {
                continue;
            };
            if segment.flags & TCP_RST != 0 {
                return Err(ProbeError::Local(
                    "classify: сервер ответил RST на SYN".into(),
                ));
            }
            if segment.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK
                && segment.acknowledgment == self.sequence.wrapping_add(1)
            {
                if let Some(timestamp) = timestamp_value(&segment.options) {
                    self.template_options = Some(timestamp_options(timestamp));
                }
                self.sequence = self.sequence.wrapping_add(1);
                self.acknowledgment = segment.sequence.wrapping_add(1);
                let ack = build_control_packet(
                    self.local,
                    self.remote,
                    self.source_port,
                    self.destination_port,
                    self.sequence,
                    self.acknowledgment,
                    TCP_ACK,
                    &[],
                    &[],
                )
                .ok_or_else(|| ProbeError::Local("classify: ACK пакет не собран".into()))?;
                self.send_packet_io(&ack)
                    .map_err(|error| ProbeError::Local(raw_error_text(&error)))?;
                return Ok(true);
            }
        }
    }

    fn sender_fd(&self) -> io::Result<libc::c_int> {
        self.sender
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
    }

    fn receiver_fd(&self) -> io::Result<libc::c_int> {
        self.receiver
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
    }

    fn send_packet_io(&self, packet: &[u8]) -> io::Result<()> {
        let family = if matches!(self.remote, IpAddr::V6(_)) {
            6
        } else {
            4
        };
        let mut destination: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let destination_len = match self.remote {
            IpAddr::V4(address) => {
                let sockaddr =
                    unsafe { &mut *(&mut destination as *mut _ as *mut libc::sockaddr_in) };
                sockaddr.sin_family = libc::AF_INET as libc::sa_family_t;
                sockaddr.sin_addr.s_addr = u32::from_ne_bytes(address.octets());
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            IpAddr::V6(address) => {
                let sockaddr =
                    unsafe { &mut *(&mut destination as *mut _ as *mut libc::sockaddr_in6) };
                sockaddr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sockaddr.sin6_addr.s6_addr = address.octets();
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        };
        let sent = sys_sendto(
            self.sender_fd()?,
            packet,
            libc::MSG_DONTWAIT,
            &destination,
            destination_len,
        )?;
        if raw_sendto_ok(family, sent, packet.len()) {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::WriteZero))
        }
    }

    /// C `raw_send` (`detect/raw.c:830`): полезная нагрузка уходит
    /// сегментами не длиннее `segment_max`, номера идут встык.
    fn send_payload_io(&self, payload: &[u8], flags: u8, options: &[u8]) -> io::Result<()> {
        let segment = crate::classify_measured::segment_max().max(1);
        let mut offset = 0;
        loop {
            let end = (offset + segment).min(payload.len());
            let packet = build_control_packet(
                self.local,
                self.remote,
                self.source_port,
                self.destination_port,
                self.sequence.wrapping_add(offset as u32),
                self.acknowledgment,
                flags,
                options,
                &payload[offset..end],
            )
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            self.send_packet_io(&packet)?;
            if end >= payload.len() {
                return Ok(());
            }
            offset = end;
        }
    }

    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), ProbeError> {
        self.send_packet_io(packet)
            .map_err(|error| ProbeError::Local(format!("classify: {error}")))
    }

    fn receive_segment(
        &mut self,
        until: Instant,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Option<ReceivedSegment>, ProbeError> {
        loop {
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err(ProbeError::Local("context canceled".into()));
            }
            let now = Instant::now();
            if now >= until {
                return Ok(None);
            }
            let millis = until
                .saturating_duration_since(now)
                .min(Duration::from_millis(100))
                .as_millis()
                .max(1) as libc::c_int;
            let receiver_fd = self
                .receiver_fd()
                .map_err(|error| ProbeError::Local(format!("classify: poll: {error}")))?;
            let (polled, _revents) = match sys_poll(receiver_fd, libc::POLLIN, millis) {
                Ok(result) => result,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(ProbeError::Local(format!("classify: poll: {error}")));
                }
            };
            if polled == 0 {
                continue;
            }
            let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut peer_len = std::mem::size_of_val(&peer) as libc::socklen_t;
            let count =
                match sys_recvfrom(receiver_fd, &mut self.recv_buffer, &mut peer, &mut peer_len) {
                    Ok(count) => count,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => {
                        return Err(ProbeError::Local(format!("classify: recvfrom: {error}")));
                    }
                };
            let packet = &self.recv_buffer[..count];
            let (tcp_offset, packet_end) = match self.remote {
                IpAddr::V4(remote) => {
                    if packet.len() < 40
                        || packet[0] >> 4 != 4
                        || packet[9] != libc::IPPROTO_TCP as u8
                    {
                        continue;
                    }
                    let header = usize::from(packet[0] & 0x0f) * 4;
                    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
                    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
                    if header < 20
                        || total > packet.len()
                        || total < header + 20
                        || fragment & 0x1fff != 0
                        || packet[12..16] != remote.octets()
                        || packet[16..20]
                            != match self.local {
                                IpAddr::V4(local) => local.octets(),
                                _ => continue,
                            }
                    {
                        continue;
                    }
                    (header, total)
                }
                IpAddr::V6(remote) => {
                    if packet.len() < 20 || peer.ss_family != libc::AF_INET6 as libc::sa_family_t {
                        continue;
                    }
                    let peer_address =
                        unsafe { &*(&peer as *const _ as *const libc::sockaddr_in6) };
                    if peer_address.sin6_addr.s6_addr != remote.octets() {
                        continue;
                    }
                    (0, packet.len())
                }
            };
            let tcp = &packet[tcp_offset..packet_end];
            let header_len = usize::from(tcp[12] >> 4) * 4;
            if header_len < 20
                || header_len > tcp.len()
                || u16::from_be_bytes([tcp[0], tcp[1]]) != self.destination_port
                || u16::from_be_bytes([tcp[2], tcp[3]]) != self.source_port
            {
                continue;
            }
            let options = tcp[20..header_len].to_vec();
            return Ok(Some(ReceivedSegment {
                flags: tcp[13],
                sequence: u32::from_be_bytes(tcp[4..8].try_into().expect("bounded TCP sequence")),
                acknowledgment: u32::from_be_bytes(tcp[8..12].try_into().expect("bounded TCP ack")),
                options,
                payload: tcp[header_len..].to_vec(),
            }));
        }
    }

    fn read_payload(
        &mut self,
        timeout: Duration,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Option<Vec<u8>>, ProbeError> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let Some(segment) = self.receive_segment(deadline, cancel)? else {
                break;
            };
            if segment.flags & TCP_RST != 0 {
                return Ok(None);
            }
            if !segment.payload.is_empty() {
                if (segment.sequence.wrapping_sub(self.acknowledgment) as i32) > 0 {
                    continue;
                }
                let skip = self.acknowledgment.wrapping_sub(segment.sequence) as usize;
                if skip >= segment.payload.len() {
                    continue;
                }
                return Ok(Some(
                    segment.payload[skip..]
                        .iter()
                        .copied()
                        .take(MAX_RAW_RESPONSE)
                        .collect(),
                ));
            }
        }
        Ok(None)
    }

    /// C `raw_close` (`detect/raw.c:990`): сначала снять правило подавления
    /// RST, затем закрыть сокеты отправки и приёма.
    fn close(&mut self) {
        self.rst_guard.release();
        if let Some(fd) = self.sender.take() {
            #[cfg(test)]
            test_io::note_closed("send");
            let raw = fd.as_raw_fd();
            if raw_close_fd(raw) {
                std::mem::forget(fd);
            }
        }
        if let Some(fd) = self.receiver.take() {
            #[cfg(test)]
            test_io::note_closed("recv");
            let raw = fd.as_raw_fd();
            if raw_close_fd(raw) {
                std::mem::forget(fd);
            }
        }
        self.recv_buffer.clear();
    }
}

impl Drop for RawConn {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
impl RawConn {
    fn test_connection(
        remote: IpAddr,
        local: IpAddr,
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgment: u32,
    ) -> Self {
        let open = || std::fs::File::open("/dev/null").expect("/dev/null").into();
        Self {
            sender: Some(open()),
            receiver: Some(open()),
            rst_guard: RstGuard { rule: None },
            local,
            remote,
            source_port,
            destination_port,
            sequence,
            acknowledgment,
            template_options: None,
            recv_buffer: vec![0; u16::MAX as usize],
        }
    }
}

struct ReceivedSegment {
    flags: u8,
    sequence: u32,
    acknowledgment: u32,
    options: Vec<u8>,
    payload: Vec<u8>,
}

fn timestamp_value(options: &[u8]) -> Option<u32> {
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => break,
            1 => offset += 1,
            8 if offset + 10 <= options.len() && options[offset + 1] == 10 => {
                return Some(u32::from_be_bytes(
                    options[offset + 2..offset + 6].try_into().ok()?,
                ));
            }
            _ if offset + 2 <= options.len() => {
                let length = usize::from(options[offset + 1]);
                if length < 2 || offset + length > options.len() {
                    break;
                }
                offset += length;
            }
            _ => break,
        }
    }
    None
}

fn timestamp_options(server_timestamp: u32) -> Vec<u8> {
    let mut options = vec![1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0];
    options[8..12].copy_from_slice(&server_timestamp.to_be_bytes());
    options
}

#[cfg(test)]
mod tests {
    use super::{
        Property, RAW_SELFTESTS, RawSelftestState, apply_property, compose_from_props,
        note_raw_probe, property_probes, raw_selftest_age, raw_selftest_index, raw_sendto_ok,
        store_raw_selftest, sweep_poisons, test_script,
    };
    use crate::classify::{
        Accept, ClassifyOptions, ClassifyResult, DpiProps, Poison, ProbeTarget, TriState, Trigger,
    };
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn свойства_сокрытия_имени_измеряются_первыми() {
        let probes = super::property_probes();
        assert_eq!(probes.len(), 13);
        assert!(
            matches!(probes[0].set, Property::OverlapSni),
            "первым обязан идти вопрос перекрытия до конца имени"
        );
        assert!(
            matches!(probes[1].set, Property::UrgentByte),
            "вторым идёт срочный байт в середине имени"
        );
        assert!(probes.iter().any(|probe| probe.poison.oob));
        for probe in &probes {
            let same = probes
                .iter()
                .filter(|other| other.poison.name == probe.poison.name)
                .count();
            assert_eq!(same, 1, "плечо {} повторяется", probe.poison.name);
        }
    }

    fn set_name(property: Property) -> &'static str {
        match property {
            Property::LeftOverlap => "LEFT_OVERLAP",
            Property::Reorder => "REORDER",
            Property::Checksum => "CHECKSUM",
            Property::ParsesL7 => "PARSES_L7",
            Property::Duplicates => "DUPLICATES",
            Property::Syn => "SYN",
            Property::Md5 => "MD5",
            Property::SequenceWindow => "SEQ_WINDOW",
            Property::Timestamps => "TIMESTAMPS",
            Property::OverlapSni => "OVERLAP_SNI",
            Property::UrgentByte => "URGENT_BYTE",
            Property::DenseDuplicates => "DUP_DENSE",
            Property::WhiteTimestamp => "WHITE_TS",
        }
    }

    fn tri(value: TriState) -> &'static str {
        match value {
            TriState::True => "1",
            TriState::False => "0",
            TriState::Unset => "u",
        }
    }

    fn poison_fields(poison: &Poison) -> String {
        format!(
            "|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            poison.name,
            poison.ttl,
            u8::from(poison.badsum),
            poison.seq_shift,
            u8::from(poison.md5),
            u8::from(poison.decoy_hello),
            u8::from(poison.disorder),
            poison.disorder_pos,
            u8::from(poison.tcp_ts),
            u8::from(poison.ip_id_zero),
            u8::from(poison.autottl),
            poison.gap_ms,
            u8::from(poison.syn_data),
            u8::from(poison.oob),
            u8::from(poison.fake_between),
            poison.repeats,
            u8::from(poison.seqovl_exact),
            poison.seqovl,
            poison.split_pos
        )
    }

    fn props_fields(props: &DpiProps) -> String {
        format!(
            "|{}{}{}{}{}{}{}{}{}{}{}|{}",
            tri(props.reassembles),
            tri(props.parses_l7),
            tri(props.validates_checksum),
            tri(props.tolerates_reorder),
            tri(props.tolerates_left_overlap),
            tri(props.counts_duplicates),
            tri(props.inspects_syn),
            tri(props.validates_md5),
            tri(props.validates_seq_window),
            tri(props.validates_timestamps),
            tri(props.overlap_covers_sni),
            props.hop_ttl.unwrap_or(0)
        )
    }

    #[test]
    fn d2o_props_compose_differential_matches_c() {
        let mut output = String::new();
        let probes = property_probes();
        output.push_str(&format!("props|{}\n", probes.len()));
        for (index, probe) in probes.iter().enumerate() {
            output.push_str(&format!(
                "prop|{}|{}|{}{}\n",
                index,
                probe.label,
                set_name(probe.set),
                poison_fields(&probe.poison)
            ));
        }
        let sets = [
            Property::LeftOverlap,
            Property::Reorder,
            Property::Checksum,
            Property::ParsesL7,
            Property::Duplicates,
            Property::Syn,
            Property::Md5,
            Property::SequenceWindow,
            Property::Timestamps,
            Property::OverlapSni,
            Property::DenseDuplicates,
            Property::WhiteTimestamp,
        ];
        for property in sets {
            for ok in [false, true] {
                let mut props = DpiProps::default();
                apply_property(&mut props, property, ok, &Poison::default());
                output.push_str(&format!(
                    "apply|{}|{}{}\n",
                    set_name(property),
                    u8::from(ok),
                    props_fields(&props)
                ));
            }
        }
        let compose = |name: &str, props: &DpiProps, control: Option<&[u8]>| {
            let out = compose_from_props(props, control);
            let mut line = format!("compose|{name}|{}", out.len());
            for poison in &out {
                line.push_str(&poison_fields(poison));
            }
            line.push('\n');
            line
        };
        let empty = DpiProps::default();
        output.push_str(&compose("empty-none", &empty, None));
        output.push_str(&compose(
            "empty-control",
            &empty,
            Some(b"BENIGN-CONTROL-PAYLOAD"),
        ));
        let duplicates = DpiProps {
            counts_duplicates: TriState::True,
            ..DpiProps::default()
        };
        output.push_str(&compose("duplicates", &duplicates, None));
        let all = DpiProps {
            counts_duplicates: TriState::True,
            tolerates_left_overlap: TriState::False,
            tolerates_reorder: TriState::False,
            ..DpiProps::default()
        };
        output.push_str(&compose("all", &all, None));
        let overlap = DpiProps {
            tolerates_left_overlap: TriState::False,
            ..DpiProps::default()
        };
        output.push_str(&compose("overlap", &overlap, None));
        let reorder = DpiProps {
            tolerates_reorder: TriState::False,
            ..DpiProps::default()
        };
        output.push_str(&compose("reorder", &reorder, None));
        if let Ok(path) = std::env::var("R2O_COMPOSE_PROPS_OUTPUT") {
            std::fs::write(path, &output).expect("write compose/props output");
        }
        assert!(
            output.starts_with("props|13\n"),
            "набор вопросов коробки: перекрытие до конца имени и срочный байт идут первыми"
        );
        assert!(output.contains("compose|empty-none|1|СОБРАНО: всё сразу|"));
    }

    #[test]
    fn trigger_timestamp_helpers_match_c() {
        let plain = super::Poison::default();
        let tcp_ts = super::Poison {
            tcp_ts: true,
            ..super::Poison::default()
        };
        assert!(super::raw_profile_allows(&plain, false));
        assert!(!super::raw_profile_allows(&tcp_ts, false));
        assert!(super::raw_profile_allows(&tcp_ts, true));
        assert!(super::raw_offer_timestamps(Some(true)));
        assert!(!super::raw_offer_timestamps(Some(false)));
    }

    #[test]
    fn parse_rst_rule_accepts_d2o_and_r2o_owner_tags() {
        let legacy = "-A OUTPUT -p tcp -m tcp --sport 40123 --tcp-flags RST RST -j DROP";
        assert_eq!(super::parse_stale_rst_rule(legacy), Some(40_123));

        let d2o = "-A OUTPUT -p tcp -m tcp --sport 40124 --tcp-flags RST RST -m comment \
                   --comment \"d2k-rst:123\" -j DROP";
        assert_eq!(super::parse_stale_rst_rule(d2o), Some(40_124));

        let r2o = "-A OUTPUT -p tcp -m tcp --sport 40125 --tcp-flags RST RST -m comment \
                   --comment \"r2o-rst:456\" -j DROP";
        assert_eq!(super::parse_stale_rst_rule(r2o), Some(40_125));

        let foreign = "-A OUTPUT -p tcp -m tcp --sport 40126 --tcp-flags RST RST -m comment \
                       --comment \"other-rst:456\" -j DROP";
        assert_eq!(super::parse_stale_rst_rule(foreign), None);
    }

    #[test]
    fn rst_abandon_message_includes_family_and_port_like_c() {
        let rule = super::RstRule {
            source_port: 40_123,
            destination: "2001:db8::1".parse().unwrap(),
            destination_port: 443,
            nft: false,
            comment: true,
        };
        assert_eq!(
            super::r2o_rst_abandon_message(&rule),
            "r2o: правило подавления RST (ip6tables, порт 40123) не снято за 5 попыток — \
             больше не повторяю до выхода процесса; при выходе попробую ещё раз, оставшееся \
             снимет уборка следующего запуска r2o"
        );
        let v4 = super::RstRule {
            destination: "192.0.2.1".parse().unwrap(),
            ..rule
        };
        assert!(super::r2o_rst_abandon_message(&v4).contains("(iptables, порт 40123)"));
    }
    use super::*;
    use r2k_core::plan::Plan;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn snapped_client_hello_is_the_decoy_and_control_sni_is_preserved() {
        fn build_variant(variant: &str, control: bool) -> Vec<u8> {
            match variant {
                "none" => Vec::new(),
                "short" => vec![0x16, 0x03],
                "sni_255" | "sni_256" => {
                    let length = if variant == "sni_255" { 255 } else { 256 };
                    let name = "a".repeat(length);
                    crate::hello::legacy_client_hello(&name).unwrap()
                }
                _ => {
                    let mut hello = if control {
                        crate::hello::legacy_client_hello("disk.rzd.ru").unwrap()
                    } else {
                        crate::hello::modern_client_hello("target.example").unwrap()
                    };
                    match variant {
                        "truncated" => {
                            hello.pop();
                        }
                        "padded" => {
                            let record_len =
                                usize::from(u16::from_be_bytes([hello[3], hello[4]])) + 4;
                            hello.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
                            hello[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
                        }
                        "wrong_record_type" => hello[0] = 0x17,
                        "without_sni" => {
                            let (offset, _) = crate::hello::sni_bounds(&hello).unwrap();
                            hello[offset - 3] = 1;
                        }
                        "nul_sni" => {
                            let (offset, _) = crate::hello::sni_bounds(&hello).unwrap();
                            hello[offset] = 0;
                        }
                        "valid" => {}
                        other => panic!("unknown bridge-clone fixture variant {other}"),
                    }
                    hello
                }
            }
        }

        fn hex(bytes: &[u8]) -> String {
            if bytes.is_empty() {
                return "-".into();
            }
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }

        let fixture = include_str!("../tests/fixtures/d2o_bridge_clone_decoy.tsv");
        let mut rows = Vec::new();
        for line in fixture
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            assert_eq!(fields.len(), 4, "invalid bridge clone fixture row: {line}");
            let snapped = fields[1] == "1";
            let trigger = build_variant(fields[2], false);
            let control = build_variant(fields[3], true);
            let (decoy, cloned) = select_bridge_decoy(
                &trigger,
                (!control.is_empty()).then_some(control.as_slice()),
                snapped,
            );
            let selected = decoy.or_else(|| (control.len() >= 2).then(|| control.clone()));
            let property = Poison {
                decoy_hello: true,
                ..Poison::default()
            };
            assert_eq!(
                property_probe_label("parse-l7", Property::ParsesL7, &property, cloned)
                    .ends_with(" (приманка — клон клиента)"),
                cloned,
                "the observation must identify when the captured client hello was cloned"
            );
            assert!(
                !property_probe_label("checksum", Property::Checksum, &Poison::default(), true)
                    .ends_with(" (приманка — клон клиента)")
            );

            match fields[0] {
                "clone" => {
                    assert!(cloned, "a captured ClientHello must be cloned");
                    let selected = selected.as_deref().expect("cloned decoy");
                    let (offset, length) = crate::hello::sni_bounds(selected).unwrap();
                    assert_eq!(&selected[offset..offset + length], b"disk.rzd.ru");
                    assert_eq!(&selected[..3], &trigger[..3]);
                }
                "trigger_padded" => assert!(
                    cloned,
                    "complete ClientHello records with trailing record bytes are cloneable"
                ),
                "control_sni_255" => assert!(cloned, "255-byte control SNI is accepted"),
                "control_sni_256" => assert!(!cloned, "256-byte control SNI uses fallback"),
                _ => assert!(!cloned, "{} must use the control fallback", fields[0]),
            }
            rows.push(format!(
                "{}\t{}",
                fields[0],
                selected.as_deref().map_or_else(|| "-".into(), hex)
            ));
        }

        assert!(rows.iter().any(|row| row.starts_with("clone\t")));
        if let Ok(output_path) = std::env::var("R2O_BRIDGE_CLONE_DIFF_OUTPUT") {
            std::fs::write(output_path, rows.join("\n") + "\n")
                .expect("write Rust bridge clone differential output");
        }
        println!("{}", rows.join("\n"));
    }

    #[test]
    fn raw_syn_profile_matches_the_d2o_fixture() {
        let inputs = include_str!("../tests/fixtures/d2o/raw-syn-profile.tsv")
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let fields = line
                    .split_whitespace()
                    .map(|field| field.split_once('=').expect("fixture key=value"))
                    .collect::<std::collections::HashMap<_, _>>();
                (
                    fields["family"].parse::<u8>().unwrap(),
                    fields["offer_ts"] == "1",
                )
            })
            .collect::<Vec<_>>();
        let profile_rows = inputs
            .iter()
            .map(|(family, offer_ts)| {
                let offer_ts = raw_offer_timestamps(Some(*offer_ts));
                let options = raw_syn_options(offer_ts)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let poison = Poison {
                    tcp_ts: true,
                    ..Poison::default()
                };
                format!(
                    "RAW_SYN_PROFILE family={family} offer_ts={} options={options} allow_ts_poison={}",
                    u8::from(offer_ts),
                    u8::from(raw_profile_allows(&poison, offer_ts))
                )
            })
            .collect::<Vec<_>>();
        let cache_rows = inputs
            .iter()
            .map(|(family, offer_ts)| {
                format!(
                    "RAW_SELFTEST_KEY family={family} offer_ts={} cache_index={}",
                    u8::from(*offer_ts),
                    raw_selftest_index(*family, *offer_ts)
                )
            })
            .collect::<Vec<_>>();
        let mut rows = profile_rows;
        rows.extend(cache_rows);
        *RAW_SELFTESTS
            .get_or_init(|| Mutex::new(RawSelftestState::default()))
            .lock()
            .unwrap() = RawSelftestState::default();
        for family in [4, 6] {
            store_raw_selftest(family, true, true);
            store_raw_selftest(family, false, true);
        }
        let mut error_streaks = [0usize; 2];
        let invalidation_rows = include_str!("../tests/fixtures/d2o/raw-selftest-errors.tsv")
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let fields = line
                    .split_whitespace()
                    .map(|field| field.split_once('=').expect("fixture key=value"))
                    .collect::<std::collections::HashMap<_, _>>();
                let family = fields["family"].parse::<u8>().unwrap();
                assert_eq!(fields["result"], "error");
                let family_index = if family == 6 { 1 } else { 0 };
                error_streaks[family_index] += 1;
                note_raw_probe(family, true);
                format!(
                    "RAW_SELFTEST_INVALIDATION family={family} errors={} with_ts={} without_ts={}",
                    error_streaks[family_index],
                    u8::from(raw_selftest_age(family, true).is_some()),
                    u8::from(raw_selftest_age(family, false).is_some())
                )
            })
            .collect::<Vec<_>>();
        rows.extend(invalidation_rows);
        assert_eq!(
            rows,
            [
                "RAW_SYN_PROFILE family=4 offer_ts=0 options=020405ac0103030701010402 allow_ts_poison=0",
                "RAW_SYN_PROFILE family=4 offer_ts=1 options=020405ac0402080a000000010000000001030307 allow_ts_poison=1",
                "RAW_SYN_PROFILE family=6 offer_ts=0 options=020405ac0103030701010402 allow_ts_poison=0",
                "RAW_SYN_PROFILE family=6 offer_ts=1 options=020405ac0402080a000000010000000001030307 allow_ts_poison=1",
                "RAW_SELFTEST_KEY family=4 offer_ts=0 cache_index=2",
                "RAW_SELFTEST_KEY family=4 offer_ts=1 cache_index=0",
                "RAW_SELFTEST_KEY family=6 offer_ts=0 cache_index=3",
                "RAW_SELFTEST_KEY family=6 offer_ts=1 cache_index=1",
                "RAW_SELFTEST_INVALIDATION family=4 errors=1 with_ts=1 without_ts=1",
                "RAW_SELFTEST_INVALIDATION family=6 errors=1 with_ts=1 without_ts=1",
                "RAW_SELFTEST_INVALIDATION family=4 errors=2 with_ts=1 without_ts=1",
                "RAW_SELFTEST_INVALIDATION family=4 errors=3 with_ts=0 without_ts=0",
                "RAW_SELFTEST_INVALIDATION family=6 errors=2 with_ts=1 without_ts=1",
                "RAW_SELFTEST_INVALIDATION family=6 errors=3 with_ts=0 without_ts=0",
            ]
        );

        println!("{}", rows.join("\n"));
        if let Ok(c_output) = std::env::var("R2O_RAW_PROFILE_C_OUTPUT") {
            let c_rows = std::fs::read_to_string(c_output)
                .expect("read C differential output")
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let mut c_rows = c_rows;
            let mut rust_rows = rows.clone();
            c_rows.sort();
            rust_rows.sort();
            assert_eq!(rust_rows, c_rows, "C/Rust raw profile vectors differ");
        }
    }

    #[test]
    fn white_hello_ts_composite_is_not_filtered_for_a_client_without_timestamps() {
        let white = property_probes()
            .into_iter()
            .find(|property| matches!(property.set, Property::WhiteTimestamp))
            .expect("white ECH composite property");
        let mut properties = DpiProps::default();
        let poison = property_probe_poison(&white, false, &properties)
            .expect("D2O keeps the white ECH composite without client timestamps");
        let probe = property_probe_label(white.label, white.set, &poison, false);

        assert!(!poison.tcp_ts);
        assert!(poison.badsum);
        assert!(poison.decoy_hello);
        assert_eq!(poison.repeats, 8);
        assert_eq!(poison.split_pos, 2);
        assert_eq!(probe, "свойство:ECH-приветствие под битой суммой");

        apply_property(&mut properties, white.set, true, &poison);
        assert_eq!(properties.parses_l7, TriState::True);
        assert_eq!(properties.validates_checksum, TriState::False);
        assert_eq!(properties.validates_timestamps, TriState::Unset);

        let mut known_checksum = DpiProps::default();
        known_checksum.validates_checksum = TriState::True;
        assert!(property_probe_poison(&white, false, &known_checksum).is_none());

        let row = format!(
            "WHITE_TS_NO_CLIENT_TIMESTAMPS name={} probe={} tcp_ts={} badsum={} decoy_hello={} repeats={} split_pos={} parses_l7={} validates_checksum_false={} validates_timestamps_unset={}",
            poison.name,
            probe,
            u8::from(poison.tcp_ts),
            u8::from(poison.badsum),
            u8::from(poison.decoy_hello),
            poison.repeats,
            poison.split_pos,
            u8::from(properties.parses_l7 == TriState::True),
            u8::from(properties.validates_checksum == TriState::False),
            u8::from(properties.validates_timestamps == TriState::Unset),
        );
        if let Ok(c_output) = std::env::var("R2O_WHITE_TS_C_OUTPUT") {
            let c_rows = std::fs::read_to_string(c_output)
                .expect("read D2O white ECH composite differential output");
            let c_row = c_rows
                .lines()
                .find(|line| line.starts_with("WHITE_TS_NO_CLIENT_TIMESTAMPS "))
                .expect("D2O white ECH composite result");
            assert_eq!(row, c_row, "C/Rust white ECH composite differs");
        }
        println!("{row}");
    }

    #[test]
    fn raw_selftest_recheck_requires_a_cached_check_and_zero_successes() {
        let cold_errors = should_recheck(false, 0, 3);
        let cached_errors = should_recheck(true, 0, 2);
        let cached_with_success = should_recheck(true, 1, 3);

        assert!(
            !cold_errors,
            "a fresh self-test was repeated after local errors"
        );
        assert!(
            cached_errors,
            "a doubtful cached self-test was not rechecked"
        );
        assert!(
            !cached_with_success,
            "successful raw probes did not suppress recheck"
        );

        let row = format!(
            "RAW_SELFTEST_RECHECK cold_three_errors={} cached_two_errors={} cached_with_success={}",
            u8::from(cold_errors),
            u8::from(cached_errors),
            u8::from(cached_with_success),
        );
        if let Ok(c_output) = std::env::var("R2O_RAW_RECHECK_C_OUTPUT") {
            let c_rows = std::fs::read_to_string(c_output)
                .expect("read D2O raw self-test recheck differential output");
            let c_row = c_rows
                .lines()
                .find(|line| line.starts_with("RAW_SELFTEST_RECHECK "))
                .expect("D2O raw self-test recheck result");
            assert_eq!(row, c_row, "C/Rust raw self-test recheck differs");
        }
        println!("{row}");
    }

    #[test]
    fn measured_tcp_split_wire_packets_match_donor() {
        let trigger = Trigger {
            name: "fixture".into(),
            payload: vec![
                0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00,
            ],
            accept: crate::classify::Accept::Any,
        };
        let poison = Poison {
            name: "tcp-split".into(),
            split_pos: 5,
            gap_ms: 20,
            ..Poison::default()
        };
        let plan = crate::classify::plan_for_poison(&poison, &trigger, None, 0).unwrap();
        let input = build_control_packet(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            41_000,
            443,
            0x1234_5678,
            0x90ab_cdef,
            TCP_ACK | TCP_PSH,
            &[],
            &trigger.payload,
        )
        .unwrap();
        let PacketDecision::Transmit { packets, fate } = decide(&plan, &input) else {
            panic!("the donor tcp-split plan must produce packets");
        };
        assert_eq!(fate, OriginalFate::Drop);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].delay_us, 0);
        assert_eq!(packets[1].delay_us, 20_000);
        let packet_emissions = packets
            .iter()
            .map(|packet| (packet.delay_us, packet.packet.clone()))
            .collect::<Vec<_>>();

        let mut rows = Vec::new();
        for packet in packets {
            let mut bytes = packet.packet;
            if bytes.len() >= 20 && bytes[0] >> 4 == 4 {
                bytes[4..6].fill(0);
                bytes[10..12].fill(0);
            }
            let hex = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            rows.push(format!("RAW_SPLIT_PACKET|{hex}"));
        }
        if let Ok(c_output) = std::env::var("R2O_RAW_SPLIT_C_OUTPUT") {
            let c_rows = std::fs::read_to_string(c_output)
                .expect("read D2O raw split packet output")
                .lines()
                .filter(|line| line.starts_with("RAW_SPLIT_PACKET|"))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert_eq!(rows, c_rows, "C/Rust production raw split packets differ");
        }
        for row in rows {
            println!("{row}");
        }

        let cancelled = AtomicBool::new(false);
        let mut sent = Vec::new();
        let mut waited_ms = 0u128;
        let result = emit_plan_packets(
            packet_emissions,
            Some(&cancelled),
            |duration| waited_ms += duration.as_millis(),
            |packet| {
                sent.push(packet.to_vec());
                if sent.len() == 1 {
                    cancelled.store(true, Ordering::Relaxed);
                }
                Ok(())
            },
        );
        let cancel_row = format!(
            "RAW_SPLIT_CANCEL result=cancelled packets={} waited_ms={waited_ms}",
            sent.len(),
        );
        assert!(matches!(result, Err(ProbeError::Local(error)) if error == "context canceled"));
        assert_eq!(sent.len(), 1);
        assert_eq!(waited_ms, 0);
        if let Ok(c_output) = std::env::var("R2O_RAW_SPLIT_C_OUTPUT") {
            let c_row = std::fs::read_to_string(c_output)
                .expect("read D2O between-span cancellation output")
                .lines()
                .find(|line| line.starts_with("RAW_SPLIT_CANCEL "))
                .expect("D2O between-span cancellation result")
                .to_owned();
            assert_eq!(
                cancel_row, c_row,
                "C/Rust between-span cancellation differs"
            );
        }
        println!("{cancel_row}");
    }

    #[test]
    fn measured_emission_finishes_an_started_gap_before_observing_cancellation() {
        let trigger = Trigger::tls("probe.example").unwrap();
        let poison = Poison {
            name: "badsum-x3-g20".into(),
            badsum: true,
            repeats: 3,
            gap_ms: 20,
            ..Poison::default()
        };
        let plan = crate::classify::plan_for_poison(&poison, &trigger, None, 0).unwrap();
        let input = build_control_packet(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            41_000,
            443,
            0x1234_5678,
            0x90ab_cdef,
            TCP_ACK | TCP_PSH,
            &[],
            &trigger.payload,
        )
        .unwrap();
        let PacketDecision::Transmit { packets, .. } = decide(&plan, &input) else {
            panic!("the donor's repeated badsum plan must produce emissions");
        };
        assert!(packets.len() >= 3);
        assert_eq!(packets[0].delay_us, 0);
        assert_eq!(packets[1].delay_us, 20_000);
        assert_eq!(packets[2].delay_us, 20_000);

        let cancelled = AtomicBool::new(false);
        let mut sent = Vec::new();
        let mut waited_ms = 0u128;
        let result = emit_plan_packets(
            packets
                .into_iter()
                .map(|packet| (packet.delay_us, packet.packet)),
            Some(&cancelled),
            |duration| {
                waited_ms += duration.as_millis();
                cancelled.store(true, Ordering::Relaxed);
            },
            |packet| {
                sent.push(packet.to_vec());
                Ok(())
            },
        );
        let row = format!(
            "RAW_EMISSION_CANCEL result=cancelled packets={} waited_ms={waited_ms}",
            sent.len(),
        );
        assert!(matches!(result, Err(ProbeError::Local(error)) if error == "context canceled"));
        assert_eq!(
            sent.len(),
            2,
            "a started emission gap must finish its packet"
        );
        if let Ok(c_output) = std::env::var("R2O_RAW_EMISSION_C_OUTPUT") {
            let c_rows =
                std::fs::read_to_string(c_output).expect("read D2O emission cancellation output");
            let c_row = c_rows
                .lines()
                .find(|line| line.starts_with("RAW_EMISSION_CANCEL "))
                .expect("D2O emission cancellation result");
            assert_eq!(row, c_row, "C/Rust raw emission cancellation differs");
        }
        println!("{row}");
    }

    #[test]
    fn nft_rst_rule_uses_r2o_table_and_exact_tuple_with_donor_timeout() {
        let fixture = include_str!("../tests/fixtures/d2o_nft_rst.txt")
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.split_once('=').expect("fixture key=value"))
            .collect::<std::collections::HashMap<_, _>>();
        let nft = r2o_rst_uses_nft(Some(fixture["firewall"]), None);
        assert!(nft);
        assert!(!r2o_rst_uses_nft(None, None));
        // C-паритет `D2K_FW` важнее R2O-имени; неизвестное значение не nft.
        assert!(r2o_rst_uses_nft(None, Some("nft")));
        assert!(!r2o_rst_uses_nft(Some("iptables"), Some("nft")));
        let rule = RstRule {
            source_port: fixture["source_port"].parse().unwrap(),
            destination: fixture["destination"].parse().unwrap(),
            destination_port: fixture["destination_port"].parse().unwrap(),
            nft,
            comment: true,
        };

        assert_eq!(
            rule.nft_args("add"),
            fixture["rust_add_args"]
                .split('|')
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            rule.nft_args("delete"),
            fixture["rust_delete_args"]
                .split('|')
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn failed_rst_suppression_is_counted_without_aborting_the_raw_probe() {
        let failures = Cell::new(0);
        let guard = RstGuard::from_install_result(
            Err(ProbeError::Local("nft rejected the element".into())),
            &failures,
        );

        assert!(guard.rule.is_none());
        assert_eq!(failures.get(), 1);
        drop(guard);
    }

    #[test]
    fn rst_rule_failure_counts_are_per_worker_thread() {
        let before = rst_rule_failure_count();
        thread::spawn(|| RST_RULE_FAILURES.with(|failures| failures.set(7)))
            .join()
            .unwrap();
        assert_eq!(rst_rule_failure_count(), before);
    }

    #[test]
    fn successful_poison_hit_carries_compiled_datapath_plan() {
        let trigger = Trigger::tls("probe.example").unwrap();
        let poison = Poison {
            name: "badsum".into(),
            badsum: true,
            ..Poison::default()
        };

        let hit = make_poison_hit(&poison, &trigger, None).unwrap().unwrap();
        let plan = Plan::parse(&hit.plan).unwrap();

        assert_eq!(hit.name, "badsum");
        assert!(hit.strategy.contains("badsum"));
        assert_eq!(
            crate::plan_text::compile_text(&hit.plan_text).unwrap(),
            hit.plan
        );
        assert_eq!(
            plan,
            crate::classify::plan_for_poison(&poison, &trigger, None, 0).unwrap()
        );
    }

    #[test]
    fn accepted_syn_data_poison_is_retained_with_its_plan_rejection_reason() {
        let trigger = Trigger::tls("probe.example").unwrap();
        let poison = Poison {
            name: "syndata".into(),
            syn_data: true,
            ..Poison::default()
        };

        let unplannable = executable_poison_hit(&poison, &trigger, None).unwrap_err();

        assert_eq!(unplannable.name, "syndata");
        assert!(unplannable.reason.contains("SYN"));
        assert!(unplannable.reason.contains("языком плана не выражаются"));
    }

    #[test]
    fn measured_hit_plan_executes_through_the_datapath_packet_engine() {
        let trigger = Trigger::tls("probe.example").unwrap();
        let poison = Poison {
            name: "badsum".into(),
            badsum: true,
            ..Poison::default()
        };
        let hit = make_poison_hit(&poison, &trigger, None).unwrap().unwrap();
        let plan = Plan::parse(&hit.plan).unwrap();
        let input = build_control_packet(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            40_000,
            443,
            0x1234_5678,
            0,
            TCP_PSH | TCP_ACK,
            &[],
            &trigger.payload,
        )
        .unwrap();

        let r2o_datapath::engine::PacketDecision::Transmit { packets, .. } =
            r2o_datapath::engine::decide(&plan, &input)
        else {
            panic!("the measured poison plan must execute in r2o-datapath");
        };
        assert!(!packets.is_empty());
        let fake = &packets[0].packet;
        let view = r2k_core::packet::PacketView::parse(fake).unwrap();
        let tcp = view.tcp_segment(fake).unwrap();
        assert_eq!(fake[tcp.payload].len(), trigger.payload.len() * 2);
    }

    #[test]
    fn runtime_rejected_poison_cannot_be_reported_as_a_hit() {
        let trigger = Trigger::tls("probe.example").unwrap();
        let poison = Poison {
            name: "badsum+ipid".into(),
            badsum: true,
            ip_id_zero: true,
            ..Poison::default()
        };

        let error = make_poison_hit(&poison, &trigger, None).unwrap_err();

        assert!(error.contains("r2o-datapath runtime rejected"));
        assert!(error.contains("IPv4 ID"));
    }

    #[test]
    fn builds_an_ipv4_syn_with_valid_ip_and_tcp_checksums() {
        let packet = build_control_packet(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            40_000,
            443,
            0x1234_5678,
            0,
            TCP_SYN,
            &[],
            &[],
        )
        .unwrap();

        assert_eq!(packet.len(), 40);
        assert_eq!(&packet[..4], &[0x45, 0, 0, 40]);
        assert_eq!(internet_checksum(&packet[..20]), 0);
        assert_eq!(&packet[24..28], &0x1234_5678u32.to_be_bytes());
        assert!(tcp_checksum_valid(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            &packet[20..]
        ));
    }

    #[test]
    fn rst_rule_parser_matches_donor_legacy_and_owned_forms() {
        let legacy = "-A OUTPUT -p tcp -m tcp --sport 40000 --tcp-flags RST RST -j DROP";
        assert_eq!(parse_rst_rule(legacy), Some((40000, None)));
        assert_eq!(parse_stale_rst_rule(legacy), Some(40000));

        let owned = "-A OUTPUT -p tcp -m tcp --sport 40001 --tcp-flags RST RST -m comment --comment d2k-rst:1234 -j DROP";
        assert_eq!(parse_rst_rule(owned), Some((40001, Some(1234))));
        let quoted = "-A OUTPUT -p tcp -m tcp --sport 40002 --tcp-flags RST RST -m comment --comment \"d2k-rst:4321\" -j DROP";
        assert_eq!(parse_rst_rule(quoted), Some((40002, Some(4321))));

        assert_eq!(
            parse_rst_rule("-A OUTPUT -p tcp -m tcp --sport 29999 --tcp-flags RST RST -j DROP"),
            None
        );
        assert_eq!(
            parse_rst_rule("-A OUTPUT -p tcp -m tcp --sport 55000 --tcp-flags RST RST -j DROP"),
            None
        );
        assert_eq!(
            parse_rst_rule("-A OUTPUT -p tcp -m tcp --sport 40000 --tcp-flags RST RST -j ACCEPT"),
            None
        );
        assert_eq!(
            parse_rst_rule(
                "-A OUTPUT -p tcp -m tcp --sport 40000 --tcp-flags RST RST -m comment --comment d2k-rst:0 -j DROP"
            ),
            None
        );

        assert_eq!(rst_rule_stale_with(legacy, |_| false), Some((40000, None)));
        assert_eq!(
            rst_rule_stale_with(owned, |_| false),
            Some((40001, Some(1234)))
        );
        assert_eq!(rst_rule_stale_with(owned, |_| true), None);
    }

    #[test]
    fn rst_pending_count_starts_empty_and_is_bounded() {
        assert!(rst_pending_count() <= RST_PENDING_MAX);
    }

    #[test]
    fn builds_an_ipv6_syn_with_valid_tcp_checksum() {
        let source = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let destination = IpAddr::V6("2001:db8::2".parse().unwrap());
        let packet = build_control_packet(
            source,
            destination,
            40_001,
            8443,
            0x8765_4321,
            0,
            TCP_SYN,
            &[],
            &[],
        )
        .unwrap();

        assert_eq!(packet.len(), 60);
        assert_eq!(packet[0] >> 4, 6);
        assert!(tcp_checksum_valid(source, destination, &packet[40..]));
    }

    #[test]
    fn selftest_cached_age_ttl_matches_c() {
        let now = std::time::Instant::now();
        assert!(selftest_age_from(None, now).is_none());
        assert_eq!(
            selftest_age_from(Some(now), now),
            Some(std::time::Duration::ZERO)
        );
        let fresh = now
            .checked_sub(std::time::Duration::from_secs(599))
            .unwrap();
        assert!(selftest_age_from(Some(fresh), now).is_some());
        let stale = now
            .checked_sub(std::time::Duration::from_secs(600))
            .unwrap();
        assert!(selftest_age_from(Some(stale), now).is_none());
    }

    #[test]
    fn selftest_cache_age_and_local_error_streak_match_c() {
        let index = raw_selftest_index(6, false);
        {
            let mut cache = RAW_SELFTESTS
                .get_or_init(|| std::sync::Mutex::new(RawSelftestState::default()))
                .lock()
                .unwrap();
            cache.checked_at[index] = Some(
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(599))
                    .unwrap(),
            );
            cache.error_streak[1] = 0;
        }
        assert!(raw_selftest_age(6, false).is_some());
        {
            let mut cache = RAW_SELFTESTS
                .get_or_init(|| std::sync::Mutex::new(RawSelftestState::default()))
                .lock()
                .unwrap();
            cache.checked_at[index] = Some(
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(600))
                    .unwrap(),
            );
        }
        assert!(raw_selftest_age(6, false).is_none());

        {
            let mut cache = RAW_SELFTESTS
                .get_or_init(|| std::sync::Mutex::new(RawSelftestState::default()))
                .lock()
                .unwrap();
            cache.checked_at[raw_selftest_index(6, true)] = Some(std::time::Instant::now());
            cache.checked_at[index] = Some(std::time::Instant::now());
            cache.error_streak[1] = 0;
        }
        note_raw_probe(6, true);
        note_raw_probe(6, true);
        note_raw_probe(6, true);
        assert!(raw_selftest_age(6, true).is_none());
        assert!(raw_selftest_age(6, false).is_none());
        note_raw_probe(6, false);
        assert_eq!(
            RAW_SELFTESTS
                .get_or_init(|| std::sync::Mutex::new(RawSelftestState::default()))
                .lock()
                .unwrap()
                .error_streak[1],
            0
        );
    }

    #[test]
    fn raw_supported_matches_c_linux_contract() {
        // C `detect/raw.c:164`: на Linux всегда 1, отказ ядра виден при отправке.
        assert!(raw_supported());
    }

    #[test]
    fn rc_exit1_matches_c_wait_status() {
        use std::process::Command;
        let one = Command::new("sh").arg("-c").arg("exit 1").status().unwrap();
        assert!(rc_exit1(&one));
        let zero = Command::new("sh").arg("-c").arg("exit 0").status().unwrap();
        assert!(!rc_exit1(&zero));
        let two = Command::new("sh").arg("-c").arg("exit 2").status().unwrap();
        assert!(!rc_exit1(&two));
    }

    #[test]
    fn parse_long_exact_matches_c_bounds() {
        assert_eq!(parse_long_exact(b"0"), Some(0));
        assert_eq!(parse_long_exact(b"30000"), Some(30000));
        assert_eq!(parse_long_exact(b""), None);
        assert_eq!(parse_long_exact(b"+1"), None);
        assert_eq!(parse_long_exact(b"-1"), None);
        assert_eq!(parse_long_exact(b"12a"), None);
        assert_eq!(parse_long_exact(&[b'0'; 31]), Some(0));
        assert!(parse_long_exact(&[b'0'; 32]).is_none());
        let overflow = (i128::from(std::os::raw::c_long::MAX) + 1).to_string();
        assert!(parse_long_exact(overflow.as_bytes()).is_none());
    }

    #[test]
    fn tri_yes_no_match_donor() {
        assert!(tri_yes(TriState::True));
        assert!(!tri_yes(TriState::False));
        assert!(!tri_yes(TriState::Unset));
        assert!(tri_no(TriState::False));
        assert!(!tri_no(TriState::True));
        assert!(!tri_no(TriState::Unset));
    }

    #[test]
    fn source_port_counter_matches_c_increment_and_range() {
        assert_eq!(source_port_from_counter(0), 30_000);
        assert_eq!(source_port_from_counter(24_999), 54_999);
        assert_eq!(source_port_from_counter(25_000), 30_000);
        assert_eq!(
            source_port_from_counter(u32::MAX),
            (30_000 + (u32::MAX % 25_000)) as u16
        );
        // seed_once + next_source_port: два вызова идут по счётчику C.
        let first = next_source_port();
        let second = next_source_port();
        assert!((30_000..=54_999).contains(&first));
        assert_eq!(second, if first == 54_999 { 30_000 } else { first + 1 });
    }

    #[test]
    fn opts_acceptable_matches_plannable_filter() {
        let trigger = Trigger::tls("probe.example").unwrap();
        let plain = Poison {
            name: "plain".into(),
            ..Poison::default()
        };
        // C `plannable_hit` отвергает невыразимую гипотезу.
        assert!(make_poison_hit(&plain, &trigger, None).unwrap().is_none());
        let badsum = Poison {
            name: "badsum".into(),
            badsum: true,
            ..Poison::default()
        };
        assert!(make_poison_hit(&badsum, &trigger, None).unwrap().is_some());
    }

    #[test]
    fn prop_majority_matches_c() {
        // C `d2k_prop_majority`: repeats>0 && pass > repeats/2.
        assert!(!majority(0, 0));
        assert!(!majority(0, 1));
        assert!(majority(1, 1));
        assert!(!majority(1, 2));
        assert!(majority(2, 3));
        assert!(!majority(2, 4));
        assert!(majority(3, 4));
    }

    #[test]
    fn rst_key_fields_are_used_in_both_command_forms() {
        // C `rst_key_of`: sport/dport/family/dst попадают в ключ правила.
        let rule = RstRule {
            source_port: 40_123,
            destination: "2001:db8::2".parse().unwrap(),
            destination_port: 443,
            nft: false,
            comment: true,
        };
        let nft = rule.nft_args("add").join(" ");
        assert!(nft.contains("rst6"));
        assert!(nft.contains("2001:db8::2"));
        assert!(nft.contains("40123"));
        assert!(nft.contains("443"));
        let iptables = rule.iptables_args(true, "-I").join(" ");
        assert!(iptables.contains("--sport 40123"));
        assert!(iptables.contains("--comment r2o-rst:"));

        let v4 = RstRule {
            source_port: 40_124,
            destination: "198.51.100.2".parse().unwrap(),
            destination_port: 80,
            nft: true,
            comment: false,
        };
        let nft4 = v4.nft_args("delete").join(" ");
        assert!(nft4.contains("rst4"));
        assert!(nft4.contains("198.51.100.2"));
        assert!(nft4.contains("40124"));
        assert!(nft4.contains("80"));
    }

    #[test]
    fn raw_dial_counter_matches_c() {
        let before = raw_dial_count();
        note_raw_dial();
        assert_eq!(raw_dial_count(), before + 1);
    }

    #[test]
    fn run_command_timeout_matches_c_rule_deadline() {
        let started = std::time::Instant::now();
        let error = run_command("sh", &["-c".to_owned(), "sleep 30".to_owned()])
            .expect_err("command must time out");
        assert!(error.contains("command timed out"), "{error}");
        assert!(started.elapsed() < COMMAND_TIMEOUT * 2);
    }

    #[test]
    #[ignore = "C/Rust production poison differential: run inside netns"]
    fn raw_poison_production_harness() {
        use std::time::Duration;
        let target = std::env::var("R2O_RAW_POISON_TARGET").expect("target");
        let timeout = std::env::var("R2O_RAW_POISON_TIMEOUT_MS")
            .expect("timeout")
            .parse::<u64>()
            .expect("timeout number");
        let name = std::env::var("R2O_RAW_POISON_NAME").expect("poison name");
        let remote = target
            .parse::<std::net::SocketAddr>()
            .expect("socket address");
        let trigger = Trigger {
            accept: crate::classify::Accept::Any,
            ..Trigger::tls13("probe.example").expect("modern hello")
        };
        let mut poison = Poison {
            name: name.clone(),
            ..Poison::default()
        };
        match name.as_str() {
            "badsum" => poison.badsum = true,
            "split" => {
                poison.split_pos = 1;
                poison.gap_ms = 20;
            }
            "seqovl" => poison.seqovl = 1,
            "syn_data" => poison.syn_data = true,
            "none" => {}
            other => panic!("unknown poison {other}"),
        }
        let before = raw_dial_count();
        let result = raw_probe_once(
            remote,
            &trigger,
            &poison,
            None,
            Duration::from_millis(timeout),
            Some(0),
            false,
            None,
        );
        let dials = raw_dial_count().saturating_sub(before);
        let (rc, error) = match result {
            Ok(true) => (1, String::new()),
            Ok(false) => (0, String::new()),
            Err(ProbeError::RawConnectTimeout { message, .. }) => (-2, message),
            Err(error) => (-1, error.message().to_string()),
        };
        let line = format!("poison|{name}|{rc}|err={error}|dials={dials}\n");
        if let Ok(path) = std::env::var("R2O_RAW_POISON_OUTPUT") {
            std::fs::write(path, line).expect("write poison output");
        }
    }

    #[test]
    #[ignore = "C/Rust live raw socket differential: run inside netns"]
    fn raw_live_io_harness() {
        use std::time::Duration;
        let target = std::env::var("R2O_RAW_LIVE_TARGET").expect("target");
        let timeout = std::env::var("R2O_RAW_LIVE_TIMEOUT_MS")
            .expect("timeout")
            .parse::<u64>()
            .expect("timeout number");
        let remote = target
            .parse::<std::net::SocketAddr>()
            .expect("socket address");
        let line = match RawConn::connect(remote, Duration::from_millis(timeout), 0, None, true) {
            Ok(None) => "io|dial=-2|err=classify: SYN-ACK не пришёл\n".to_string(),
            Err(error) => format!("io|dial=-1|err={}\n", error.message()),
            Ok(Some(mut connection)) => {
                let send = connection.send_payload_io(b"hello", TCP_PSH | TCP_ACK, &[]);
                if let Err(error) = send {
                    format!("io|dial=0|send=-1|err={}\n", raw_error_text(&error))
                } else {
                    connection.sequence = connection.sequence.wrapping_add(5);
                    let read = connection
                        .read_payload(Duration::from_millis(timeout), None)
                        .map_err(|error| error.message().to_string());
                    let _ = connection.close();
                    match read {
                        Ok(Some(data)) => {
                            let printable: String = data
                                .iter()
                                .take(32)
                                .map(|byte| {
                                    if (0x20..0x7f).contains(byte) {
                                        char::from(*byte).to_string()
                                    } else {
                                        format!("\\x{byte:02x}")
                                    }
                                })
                                .collect();
                            format!(
                                "io|dial=0|send=0|read=0|len={}|data={printable}\nclose=0\n",
                                data.len()
                            )
                        }
                        Ok(None) => "io|dial=0|send=0|read=-1|len=0|data=\nclose=0\n".to_string(),
                        Err(_) => "io|dial=0|send=0|read=-2|len=0|data=\nclose=0\n".to_string(),
                    }
                }
            }
        };
        if let Ok(path) = std::env::var("R2O_RAW_LIVE_OUTPUT") {
            std::fs::write(path, line).expect("write live output");
        }
    }

    #[test]
    fn run_command_closes_inherited_fds_like_c() {
        use super::command_fds_cloexec_from_proc;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        let file = std::fs::File::open("/dev/null").expect("file to inherit");
        let inherited = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 64) };
        assert!(inherited >= 64);
        let _descriptor = unsafe { OwnedFd::from_raw_fd(inherited) };
        let marker = format!("test -e /dev/fd/{inherited}");
        let status = run_command("sh", &["-c".to_owned(), marker.clone()]).expect("command");
        assert!(
            !status.success(),
            "raw rule child inherited fd {inherited}: {status:?}"
        );

        let mut command = Command::new("sh");
        command.args(["-c", &marker]);
        unsafe { command.pre_exec(command_fds_cloexec_from_proc) };
        let status = command
            .status()
            .expect("command with old kernel FD handling");
        assert!(
            !status.success(),
            "old kernel path inherited fd {inherited}: {status:?}"
        );
        assert!(run_command("/no-such-r2o-firewall-command", &[]).is_err());
    }

    #[test]
    fn local_address_for_loopback_matches_c() {
        let v4 = local_address_for("127.0.0.1:9".parse().unwrap()).expect("IPv4 local address");
        assert_eq!(v4, "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        if let Ok(v6) = local_address_for("[::1]:9".parse().unwrap()) {
            assert_eq!(v6, "::1".parse::<std::net::IpAddr>().unwrap());
        }
    }

    #[test]
    #[ignore = "C/Rust production handshake differential: run inside netns"]
    fn raw_connect_production_harness() {
        use std::time::Duration;
        let target = std::env::var("R2O_RAW_CONNECT_TARGET").expect("target");
        let timeout = std::env::var("R2O_RAW_CONNECT_TIMEOUT_MS")
            .expect("timeout")
            .parse::<u64>()
            .expect("timeout number");
        let remote = target
            .parse::<std::net::SocketAddr>()
            .expect("socket address");
        let line = match RawConn::connect(remote, Duration::from_millis(timeout), 0, None, true) {
            Ok(Some(connection)) => {
                drop(connection);
                "1|\n".to_string()
            }
            Ok(None) => "-2|classify: SYN-ACK не пришёл\n".to_string(),
            Err(error) => format!("-1|{}\n", error.message()),
        };
        if let Ok(path) = std::env::var("R2O_RAW_CONNECT_OUTPUT") {
            std::fs::write(path, line).expect("write handshake output");
        }
    }

    #[test]
    #[ignore = "C/Rust raw I/O differential: run alone (segment_max is global)"]
    fn d2o_raw_io_differential_matches_c() {
        use super::test_io::{self, CloseReply, PollReply, RecvReply, Script, SendReply};
        fn connection(family: u8) -> RawConn {
            let (remote, local) = if family == 6 {
                (
                    "2001:db8::7".parse::<std::net::IpAddr>().unwrap(),
                    "2001:db8::1".parse::<std::net::IpAddr>().unwrap(),
                )
            } else {
                (
                    "198.51.100.7".parse::<std::net::IpAddr>().unwrap(),
                    "192.0.2.1".parse::<std::net::IpAddr>().unwrap(),
                )
            };
            RawConn::test_connection(remote, local, 40_000, 443, 1000, 0)
        }
        fn packet(
            src: std::net::IpAddr,
            dst: std::net::IpAddr,
            sport: u16,
            dport: u16,
            seq: u32,
            ack: u32,
            flags: u8,
            payload: &[u8],
            options: &[u8],
        ) -> Vec<u8> {
            build_control_packet(src, dst, sport, dport, seq, ack, flags, options, payload)
                .expect("packet")
        }
        fn inbound(conn: &RawConn, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
            packet(
                conn.remote,
                conn.local,
                conn.destination_port,
                conn.source_port,
                seq,
                conn.sequence,
                flags,
                payload,
                &[],
            )
        }
        fn receive(
            conn: &mut RawConn,
            pieces: Vec<Vec<u8>>,
            peer: Option<(libc::c_int, std::net::IpAddr)>,
            error: Option<libc::c_int>,
            timeout: Duration,
        ) -> String {
            let mut script = Script::default();
            if let Some(errno) = error {
                script.poll.push_back(PollReply::Ready(libc::POLLIN));
                script.recv.push_back(RecvReply::Err(errno));
            } else {
                for bytes in pieces {
                    script.poll.push_back(PollReply::Ready(libc::POLLIN));
                    script.recv.push_back(RecvReply::Packet { bytes, peer });
                }
            }
            test_io::begin(script);
            let result = conn.receive_segment(Instant::now() + timeout, None);
            let _ = test_io::finish();
            match result {
                Ok(Some(segment)) => format!(
                    "0|flags={}|seq={}|ack={}|payload={}",
                    segment.flags,
                    segment.sequence,
                    segment.acknowledgment,
                    String::from_utf8_lossy(&segment.payload)
                ),
                Ok(None) => "wait".into(),
                Err(_) => "error".into(),
            }
        }
        fn read(
            conn: &mut RawConn,
            pieces: Vec<Vec<u8>>,
            error: Option<libc::c_int>,
            timeout: Duration,
        ) -> String {
            let mut script = Script::default();
            if let Some(errno) = error {
                script.poll.push_back(PollReply::Ready(libc::POLLIN));
                script.recv.push_back(RecvReply::Err(errno));
            } else {
                for bytes in pieces {
                    script.poll.push_back(PollReply::Ready(libc::POLLIN));
                    script
                        .recv
                        .push_back(RecvReply::Packet { bytes, peer: None });
                }
            }
            test_io::begin(script);
            let result = conn.read_payload(timeout, None);
            let _ = test_io::finish();
            match result {
                Ok(Some(payload)) => {
                    format!("0|{}", String::from_utf8_lossy(&payload))
                }
                Ok(None) => "-1|".into(),
                Err(_) => "-2|".into(),
            }
        }
        fn segment_label(packet: &[u8], family: u8) -> String {
            let ip = if family == 6 { 40 } else { 20 };
            let tcp = &packet[ip..];
            let seq = u32::from_be_bytes(tcp[4..8].try_into().unwrap());
            let header = usize::from(tcp[12] >> 4) * 4;
            format!("{}:{}", seq.wrapping_sub(1000), packet.len() - ip - header)
        }
        fn send_case(name: &str, family: u8, size: usize, reply: SendReply) -> String {
            let segment = crate::classify_measured::segment_max().max(1);
            let replies = size.div_ceil(segment).max(1);
            test_io::begin(Script {
                send: vec![reply; replies].into(),
                ..Script::default()
            });
            let conn = connection(family);
            let payload = vec![0x5a; size];
            let result = conn.send_payload_io(&payload, TCP_PSH | TCP_ACK, &[]);
            let script = test_io::finish();
            match result {
                Ok(()) => format!(
                    "send|{name}|0|segs={}",
                    script
                        .sent
                        .iter()
                        .map(|packet| segment_label(packet, family))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                Err(error) => format!(
                    "send|{name}|-1|errno={}|segs=",
                    error
                        .raw_os_error()
                        .map_or_else(|| "short".to_string(), |errno| errno.to_string())
                ),
            }
        }
        fn handshake(
            name: &str,
            family: u8,
            send: Vec<SendReply>,
            poll: Vec<PollReply>,
            recv: Vec<RecvReply>,
            timeout: Duration,
        ) -> String {
            test_io::begin(Script {
                send: send.into(),
                poll: poll.into(),
                recv: recv.into(),
                ..Script::default()
            });
            let mut conn = connection(family);
            let result = conn.handshake(timeout, None, raw_syn_options(true));
            let options = conn.template_options.as_ref().map_or(0, Vec::len);
            let _ = conn.close();
            let _ = test_io::finish();
            match result {
                Ok(true) => format!("hs|{name}|ok|ts={options}"),
                Ok(false) => {
                    format!("hs|{name}|-2|err=classify: SYN-ACK не пришёл")
                }
                Err(ProbeError::Local(message)) => format!("hs|{name}|-1|err={message}"),
                Err(error) => format!("hs|{name}|-1|err={error:?}"),
            }
        }
        fn synack(conn: &RawConn, options: &[u8], family: u8) -> Vec<u8> {
            let full = packet(
                conn.remote,
                conn.local,
                conn.destination_port,
                conn.source_port,
                7000,
                conn.sequence.wrapping_add(1),
                TCP_SYN | TCP_ACK,
                &[],
                options,
            );
            if family == 6 {
                full[40..].to_vec()
            } else {
                full
            }
        }

        let mut lines = Vec::new();
        {
            let mut conn = connection(4);
            let valid = inbound(&conn, 1001, TCP_ACK, b"abc");
            lines.push(format!(
                "recv|valid|{}",
                receive(
                    &mut conn,
                    vec![valid],
                    None,
                    None,
                    Duration::from_millis(20)
                )
            ));
        }
        {
            let mut conn = connection(4);
            let rst = inbound(&conn, 1001, TCP_RST, b"");
            lines.push(format!(
                "recv|rst|{}",
                receive(&mut conn, vec![rst], None, None, Duration::from_millis(20))
            ));
        }
        {
            let mut conn = connection(4);
            let noise = packet(
                "203.0.113.9".parse().unwrap(),
                conn.local,
                443,
                conn.source_port,
                1001,
                conn.sequence,
                TCP_ACK,
                b"noise",
                &[],
            );
            let valid = inbound(&conn, 1001, TCP_ACK, b"abc");
            lines.push(format!(
                "recv|noise|{}",
                receive(
                    &mut conn,
                    vec![noise, valid],
                    None,
                    None,
                    Duration::from_millis(20)
                )
            ));
        }
        {
            let mut conn = connection(4);
            let valid = inbound(&conn, 1001, TCP_ACK, b"abc");
            lines.push(format!(
                "recv|short|{}",
                receive(
                    &mut conn,
                    vec![vec![0; 10], valid],
                    None,
                    None,
                    Duration::from_millis(20)
                )
            ));
        }
        {
            let mut conn = connection(4);
            test_io::begin(Script {
                poll: [PollReply::Ready(libc::POLLIN)].into(),
                recv: [RecvReply::Err(libc::EAGAIN)].into(),
                ..Script::default()
            });
            let result = conn.receive_segment(Instant::now() + Duration::from_millis(2), None);
            let _ = test_io::finish();
            lines.push(format!(
                "recv|eagain|{}",
                if result.ok().flatten().is_none() {
                    "wait"
                } else {
                    "unexpected"
                }
            ));
        }
        {
            let mut conn = connection(4);
            test_io::begin(Script {
                poll: [PollReply::Ready(libc::POLLIN)].into(),
                recv: [RecvReply::Err(libc::EINTR)].into(),
                ..Script::default()
            });
            let result = conn.receive_segment(Instant::now() + Duration::from_millis(2), None);
            let _ = test_io::finish();
            lines.push(format!(
                "recv|eintr|{}",
                if result.ok().flatten().is_none() {
                    "wait"
                } else {
                    "unexpected"
                }
            ));
        }
        {
            let mut conn = connection(4);
            lines.push(format!(
                "recv|error|{}",
                receive(
                    &mut conn,
                    Vec::new(),
                    None,
                    Some(libc::EIO),
                    Duration::from_millis(20)
                )
            ));
        }
        {
            let mut conn = connection(4);
            test_io::begin(Script {
                poll: [PollReply::Ready(libc::POLLERR)].into(),
                recv: [RecvReply::Err(libc::ECONNRESET)].into(),
                ..Script::default()
            });
            let result = conn.receive_segment(Instant::now() + Duration::from_millis(20), None);
            let _ = test_io::finish();
            lines.push(format!(
                "recv|pollerr|{}",
                if result.is_err() {
                    "error"
                } else {
                    "unexpected"
                }
            ));
        }
        {
            let mut conn = connection(6);
            let valid = inbound(&conn, 1001, TCP_ACK, b"abc");
            let peer = conn.remote;
            lines.push(format!(
                "recv|v6|{}",
                receive(
                    &mut conn,
                    vec![valid[40..].to_vec()],
                    Some((libc::AF_INET6, peer)),
                    None,
                    Duration::from_millis(20)
                )
            ));
        }

        {
            let mut conn = connection(4);
            conn.acknowledgment = 1001;
            let data = inbound(&conn, 1001, TCP_ACK, b"abc");
            lines.push(format!(
                "read|data|{}",
                read(&mut conn, vec![data], None, Duration::from_millis(20))
            ));
        }
        {
            let mut conn = connection(4);
            conn.acknowledgment = 1001;
            let rst = inbound(&conn, 1001, TCP_RST, b"");
            lines.push(format!(
                "read|rst|{}",
                read(&mut conn, vec![rst], None, Duration::from_millis(20))
            ));
        }
        {
            let mut conn = connection(4);
            conn.acknowledgment = 1001;
            lines.push(format!(
                "read|silence|{}",
                read(&mut conn, Vec::new(), None, Duration::from_millis(2))
            ));
        }
        {
            let mut conn = connection(4);
            conn.acknowledgment = 1001;
            let later = inbound(&conn, 2441, TCP_ACK, b"later");
            let start = inbound(&conn, 1001, TCP_ACK, b"start");
            lines.push(format!(
                "read|ahead|{}",
                read(
                    &mut conn,
                    vec![later, start],
                    None,
                    Duration::from_millis(20)
                )
            ));
        }
        {
            let mut conn = connection(4);
            conn.acknowledgment = 1001;
            let overlap = inbound(&conn, 999, TCP_ACK, b"xxabc");
            lines.push(format!(
                "read|overlap|{}",
                read(&mut conn, vec![overlap], None, Duration::from_millis(20))
            ));
        }
        {
            let mut conn = connection(4);
            conn.acknowledgment = 1001;
            lines.push(format!(
                "read|error|{}",
                read(
                    &mut conn,
                    Vec::new(),
                    Some(libc::EIO),
                    Duration::from_millis(20)
                )
            ));
        }

        {
            test_io::begin(Script {
                close: [CloseReply::Ok, CloseReply::Ok].into(),
                ..Script::default()
            });
            let mut conn = connection(4);
            conn.recv_buffer = vec![1, 2, 3];
            conn.close();
            let script = test_io::finish();
            lines.push(format!(
                "close|order={}|cleared={}|fds={}",
                script.closed.join(","),
                u8::from(conn.recv_buffer.is_empty()),
                u8::from(conn.sender.is_none() && conn.receiver.is_none())
            ));
        }

        let before = crate::classify_measured::segment_max();
        crate::classify_measured::set_segment_max(1400);
        lines.push(send_case("small", 4, 10, SendReply::OkLen));
        lines.push(send_case("split", 4, 2900, SendReply::OkLen));
        lines.push(send_case("zero", 4, 0, SendReply::OkLen));
        lines.push(send_case("enobufs", 4, 20, SendReply::Err(libc::ENOBUFS)));
        lines.push(send_case("emsgsize", 4, 20, SendReply::Err(libc::EMSGSIZE)));
        lines.push(send_case("eintr", 4, 20, SendReply::Err(libc::EINTR)));
        lines.push(send_case("short4", 4, 20, SendReply::Ok(10)));
        lines.push(send_case("short6", 6, 20, SendReply::Ok(10)));
        let _ = crate::classify_measured::set_segment_max(before);

        let ts = [1u8, 1, 8, 10, 0, 0, 0x23, 0x28, 0, 0, 0, 1];
        {
            let conn = connection(4);
            let synack = synack(&conn, &ts, 4);
            lines.push(handshake(
                "v4-success",
                4,
                vec![SendReply::OkLen, SendReply::OkLen],
                vec![PollReply::Ready(libc::POLLIN)],
                vec![RecvReply::Packet {
                    bytes: synack,
                    peer: None,
                }],
                Duration::from_millis(50),
            ));
        }
        {
            let conn = connection(4);
            let rst = inbound(&conn, 7000, TCP_RST, b"");
            lines.push(handshake(
                "v4-rst",
                4,
                vec![SendReply::OkLen],
                vec![PollReply::Ready(libc::POLLIN)],
                vec![RecvReply::Packet {
                    bytes: rst,
                    peer: None,
                }],
                Duration::from_millis(50),
            ));
        }
        lines.push(handshake(
            "refused",
            4,
            vec![SendReply::Err(libc::ECONNREFUSED)],
            Vec::new(),
            Vec::new(),
            Duration::from_millis(50),
        ));
        lines.push(handshake(
            "timeout",
            4,
            vec![SendReply::OkLen],
            Vec::new(),
            Vec::new(),
            Duration::from_millis(2),
        ));
        {
            let conn = connection(6);
            let synack = synack(&conn, &ts, 6);
            lines.push(handshake(
                "v6-success",
                6,
                vec![SendReply::OkLen, SendReply::OkLen],
                vec![PollReply::Ready(libc::POLLIN)],
                vec![RecvReply::Packet {
                    bytes: synack,
                    peer: Some((libc::AF_INET6, conn.remote)),
                }],
                Duration::from_millis(50),
            ));
        }
        {
            let conn = connection(4);
            let synack = synack(&conn, &[], 4);
            lines.push(handshake(
                "no-ts",
                4,
                vec![SendReply::OkLen, SendReply::OkLen],
                vec![PollReply::Ready(libc::POLLIN)],
                vec![RecvReply::Packet {
                    bytes: synack,
                    peer: None,
                }],
                Duration::from_millis(50),
            ));
        }

        let output = lines.join("\n") + "\n";
        if let Ok(path) = std::env::var("R2O_RAW_IO_OUTPUT") {
            std::fs::write(path, &output).expect("write raw I/O output");
        }
        assert!(output.contains("recv|valid|0|flags="));
        assert!(output.contains("read|data|0|abc"));
        assert!(output.contains("send|split|0|segs=0:1400,1400:1400,2800:100"));
        assert!(output.contains("hs|v4-success|ok|ts=12"));
    }

    #[test]
    fn scripted_property_local_error_does_not_change_props() {
        let trigger = Trigger::tls13("probe.example").unwrap();
        let target = ProbeTarget {
            host: "127.0.0.1".into(),
            port: 443,
        };
        let mut options = ClassifyOptions {
            repeats: 3,
            white: Some(Trigger {
                name: "white".into(),
                payload: vec![0, 1],
                accept: Accept::TlsRecord,
            }),
            ..ClassifyOptions::default()
        };
        options.only_poison = None;
        store_raw_selftest(4, true, true);
        store_raw_selftest(4, false, true);
        let mut result = ClassifyResult::new("127.0.0.1:443", 3);
        test_script::begin(vec![(None, test_script::Outcome::Error)], None, true);
        let outcome = sweep_poisons(
            &target,
            &trigger,
            &options,
            &mut result,
            &mut |_, _, _, _| {},
        );
        test_script::finish();
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(result.props, DpiProps::default());
        assert!(result.hit.is_none());
        assert!(result.path.is_none());
        let properties: Vec<_> = result
            .trace
            .iter()
            .filter(|observation| observation.probe.starts_with("свойство:"))
            .collect();
        assert!(!properties.is_empty());
        assert!(
            properties
                .iter()
                .all(|observation| observation.error.is_some())
        );
        if let Ok(path) = std::env::var("R2O_PROPS_LOCAL_OUTPUT") {
            std::fs::write(path, "LOCAL rc=0 props_zero=1 answered=0 hit=0\n")
                .expect("write local error row");
        }
    }

    #[test]
    fn scripted_md5_local_error_keeps_md5_in_sweep() {
        let trigger = Trigger::tls13("probe.example").unwrap();
        let target = ProbeTarget {
            host: "127.0.0.1".into(),
            port: 443,
        };
        let options = ClassifyOptions {
            repeats: 1,
            ..ClassifyOptions::default()
        };
        store_raw_selftest(4, true, true);
        store_raw_selftest(4, false, true);
        let mut result = ClassifyResult::new("127.0.0.1:443", 1);
        test_script::begin(
            vec![
                (Some("md5"), test_script::Outcome::Error),
                (None, test_script::Outcome::Fail),
            ],
            None,
            true,
        );
        let outcome = sweep_poisons(
            &target,
            &trigger,
            &options,
            &mut result,
            &mut |_, _, _, _| {},
        );
        test_script::finish();
        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(
            result
                .trace
                .iter()
                .any(|observation| observation.probe == "poison:md5"),
            "local md5 error removed md5 from the fallback sweep"
        );
        if let Ok(path) = std::env::var("R2O_PROPS_MD5_OUTPUT") {
            std::fs::write(path, "MD5_ERR poison_md5=1\n").expect("write md5 row");
        }
    }

    #[test]
    fn scripted_property_stop_does_not_run_extra_probes() {
        let trigger = Trigger::tls13("probe.example").unwrap();
        let target = ProbeTarget {
            host: "127.0.0.1".into(),
            port: 443,
        };
        let mut options = ClassifyOptions {
            repeats: 1,
            ..ClassifyOptions::default()
        };
        store_raw_selftest(4, true, true);
        store_raw_selftest(4, false, true);
        let cancel = Arc::new(AtomicBool::new(false));
        options.cancel = Some(Arc::clone(&cancel));
        let mut result = ClassifyResult::new("127.0.0.1:443", 1);
        test_script::begin(
            vec![(None, test_script::Outcome::Fail)],
            Some((Arc::clone(&cancel), 2)),
            true,
        );
        let outcome = sweep_poisons(
            &target,
            &trigger,
            &options,
            &mut result,
            &mut |_, _, _, _| {},
        );
        let calls = test_script::calls();
        test_script::finish();
        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(result.stopped);
        assert_eq!(calls, 2, "stop must not run extra property probes");
        let properties = result
            .trace
            .iter()
            .filter(|observation| observation.probe.starts_with("свойство:"))
            .count();
        assert_eq!(properties, 2);
        if let Ok(path) = std::env::var("R2O_PROPS_STOP_OUTPUT") {
            std::fs::write(
                path,
                format!("STOP rc=0 obs={calls} probes={calls} stopped=1\n"),
            )
            .expect("write stop row");
        }
    }

    #[test]
    fn d2o_raw_sendto_short_write_matches_c() {
        let mut output = String::new();
        for (name, family, sent, len) in [
            ("v4-short", 4, 10, 20),
            ("v4-full", 4, 20, 20),
            ("v4-error", 4, -1, 20),
            ("v6-short", 6, 10, 20),
            ("v6-full", 6, 20, 20),
            ("v6-error", 6, -1, 20),
        ] {
            let rc = if raw_sendto_ok(family, sent, len) {
                0
            } else {
                -1
            };
            output.push_str(&format!("{name}|{rc}\n"));
        }
        if let Ok(path) = std::env::var("R2O_RAW_SENDTO_OUTPUT") {
            std::fs::write(path, &output).expect("write raw sendto output");
        }
        assert!(output.contains("v4-short|0"));
        assert!(output.contains("v6-short|-1"));
    }

    #[test]
    fn d2o_raw_local_addr_differential_matches_c() {
        fn hex(address: std::net::IpAddr) -> String {
            match address {
                std::net::IpAddr::V4(value) => value
                    .octets()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                std::net::IpAddr::V6(value) => value
                    .octets()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            }
        }
        let mut output = String::new();
        for (name, remote) in [("v4-loopback", "127.0.0.1:9"), ("v6-loopback", "[::1]:9")] {
            let address = local_address_for(remote.parse().unwrap());
            match address {
                Ok(address) => output.push_str(&format!("{name}|1|{}\n", hex(address))),
                Err(_) => output.push_str(&format!("{name}|0|\n")),
            }
        }
        if let Ok(path) = std::env::var("R2O_RAW_LOCAL_ADDR_OUTPUT") {
            std::fs::write(path, &output).expect("write local address output");
        }
        assert!(output.contains("v4-loopback|1|7f000001"));
    }

    #[test]
    fn register_rst_cleanup_is_once() {
        // C `register_atexit` вызывается под `pthread_once`.
        register_rst_cleanup();
        register_rst_cleanup();
        assert!(RST_CLEANUP_REGISTERED.is_completed());
    }

    #[test]
    fn fam_ix_matches_c_family_slots() {
        assert_eq!(fam_ix(4), 0);
        assert_eq!(fam_ix(6), 1);
        assert_eq!(fam_ix(0), 0);
        assert_eq!(raw_selftest_index(4, true), 0);
        assert_eq!(raw_selftest_index(6, true), 1);
        assert_eq!(raw_selftest_index(4, false), 2);
        assert_eq!(raw_selftest_index(6, false), 3);
    }

    #[test]
    fn compose_from_props_without_control_keeps_all_at_once_like_c() {
        let empty = compose_from_props(&DpiProps::default(), None);
        assert_eq!(empty.len(), 1);
        assert_eq!(empty[0].name, "СОБРАНО: всё сразу");
        assert!(empty[0].badsum);
        assert!(empty[0].decoy_hello);
        assert!(empty[0].seqovl_exact);
        assert!(empty[0].disorder);
        assert_eq!(empty[0].repeats, 7);
        assert_eq!(empty[0].seqovl, 0);

        let with_empty = compose_from_props(&DpiProps::default(), Some(&[]));
        assert_eq!(with_empty.len(), 1);
        assert_eq!(with_empty[0].name, empty[0].name);
        assert_eq!(with_empty[0].seqovl, 0);

        let control = b"BENIGN-CONTROL-PAYLOAD";
        let with_control = compose_from_props(&DpiProps::default(), Some(control));
        assert_eq!(with_control.len(), 1);
        assert_eq!(with_control[0].seqovl, control.len() as i32);
    }

    #[test]
    fn compose_from_props_order_and_maximum_match_c() {
        let duplicates = DpiProps {
            counts_duplicates: TriState::True,
            ..DpiProps::default()
        };
        let series = compose_from_props(&duplicates, None);
        assert_eq!(series.len(), 2);
        assert_eq!(series[0].name, "СОБРАНО: серия с паузой");
        assert_eq!(series[0].repeats, 2);
        assert_eq!(series[0].gap_ms, 20);
        assert_eq!(series[1].name, "СОБРАНО: плотная серия");
        assert_eq!(series[1].repeats, 7);

        let all = DpiProps {
            counts_duplicates: TriState::True,
            tolerates_left_overlap: TriState::False,
            tolerates_reorder: TriState::False,
            ..DpiProps::default()
        };
        let candidates = compose_from_props(&all, None);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].name, "СОБРАНО: серия с паузой");
        assert_eq!(candidates[1].name, "СОБРАНО: плотная серия");
        assert_eq!(candidates[2].name, "СОБРАНО: фальшивка + перекрытие");
        assert_eq!(candidates[2].seqovl_exact, true);
        assert_eq!(candidates[2].seqovl, 0);
        assert_eq!(candidates[3].name, "СОБРАНО: фальшивка + порядок");
        assert!(candidates[3].disorder);
        // C `d2k_compose_from_props` имеет cap 8; Rust Vec не переполняет
        // массив, но максимум тоже 4.
        assert!(candidates.len() <= 8);
    }

    #[test]
    fn prop_probes_order_names_and_apply_set_match_c() {
        let probes = property_probes();
        assert_eq!(probes.len(), 13);
        let expected = [
            ("перекрытие до конца имени", "seqovl-sni"),
            ("срочный байт в середине имени", "oob-sni-middle"),
            ("перекрытие слева", "seqovl-1"),
            ("порядок сегментов", "disorder"),
            ("контрольная сумма", "badsum"),
            ("разбор протокола", "badsum+hello"),
            ("повтор как ретрансмит", "badsum-x2-g20"),
            ("сверка MD5", "md5"),
            ("окно seq", "seq-out-of-window"),
            ("метка времени", "ts"),
            ("плотная серия", "badsum-x7"),
            ("ECH-приветствие под меткой", "white-hello-ts"),
            ("данные в SYN", "syndata"),
        ];
        for (index, (label, name)) in expected.iter().enumerate() {
            assert_eq!(probes[index].label, *label);
            assert_eq!(probes[index].poison.name, *name);
        }
        assert_eq!(probes[0].poison.seqovl, 0);
        assert!(probes[1].poison.oob);
        assert_eq!(probes[2].poison.seqovl, 1);
        assert!(probes[3].poison.disorder);
        assert!(probes[4].poison.badsum);
        assert!(probes[5].poison.decoy_hello);
        assert_eq!(probes[6].poison.repeats, 2);
        assert_eq!(probes[6].poison.gap_ms, 20);
        assert!(probes[7].poison.md5);
        assert_eq!(probes[8].poison.seq_shift, -66_000);
        assert!(probes[9].poison.tcp_ts);
        assert_eq!(probes[10].poison.repeats, 7);
        assert_eq!(probes[11].poison.repeats, 8);
        assert_eq!(probes[11].poison.split_pos, 2);
        assert!(probes[12].poison.syn_data);

        let mut props = DpiProps::default();
        apply_property(&mut props, Property::LeftOverlap, false, &probes[2].poison);
        assert_eq!(props.tolerates_left_overlap, TriState::True);
        apply_property(&mut props, Property::LeftOverlap, true, &probes[2].poison);
        assert_eq!(props.tolerates_left_overlap, TriState::False);
        apply_property(&mut props, Property::Checksum, false, &probes[2].poison);
        assert_eq!(props.validates_checksum, TriState::Unset);
        apply_property(&mut props, Property::ParsesL7, true, &probes[5].poison);
        assert_eq!(props.parses_l7, TriState::True);
        assert_eq!(props.validates_checksum, TriState::False);
        apply_property(&mut props, Property::Syn, true, &probes[12].poison);
        assert_eq!(props.inspects_syn, TriState::False);
        apply_property(
            &mut props,
            Property::WhiteTimestamp,
            true,
            &probes[11].poison,
        );
        assert_eq!(props.validates_timestamps, TriState::False);
        assert_eq!(props.validates_checksum, TriState::False);
    }
}
