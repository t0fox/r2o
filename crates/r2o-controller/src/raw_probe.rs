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
    poison_selected, poison_supports_family, poisons, strategy_for_poison, trigger_accepts,
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

/// Проверить, может ли текущий процесс открыть raw-сокет отправки IPv4.
pub fn raw_supported() -> bool {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_RAW,
        )
    };
    if fd < 0 {
        return false;
    }
    unsafe { libc::close(fd) };
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
    let (selected_decoy, cloned_decoy) = select_bridge_decoy(
        &trigger.payload,
        options
            .control
            .as_ref()
            .map(|control| control.payload.as_slice()),
        options.trigger_snapped,
    );
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
            if is_cancelled(options) {
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
                        observation.error = Some(format!("{error:?}"));
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

    for property in property_probes()
        .into_iter()
        .filter(|_| options.only_poison.is_none())
    {
        if is_cancelled(options) {
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
                let Some(selected_decoy) = selected_decoy.as_deref() else {
                    continue;
                };
                decoy = Some(selected_decoy);
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
            if is_cancelled(options) {
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
                    observation.error = Some(format!("{error:?}"));
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
        if is_cancelled(options) {
            result.stopped = true;
            break;
        }
        if !raw_profile_allows(&poison, offer_ts) {
            continue;
        }
        let decoy = poison
            .decoy_hello
            .then_some(selected_decoy.as_deref())
            .flatten();
        if poison.decoy_hello && decoy.is_none() {
            continue;
        }
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
            if is_cancelled(options) {
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
                    observation.error = Some(format!("{error:?}"));
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
        if is_cancelled(options) {
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
        let decoy = if poison.decoy_hello {
            let Some(selected_decoy) = selected_decoy.as_deref() else {
                continue;
            };
            Some(selected_decoy)
        } else {
            None
        };
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
            if is_cancelled(options) {
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
                    break;
                }
                Err(error) => {
                    note_raw_probe(family, true);
                    observation.fail += 1;
                    raw_errors += 1;
                    observation.error = Some(format!("{error:?}"));
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

fn select_bridge_decoy(
    trigger: &[u8],
    control: Option<&[u8]>,
    trigger_snapped: bool,
) -> (Option<Vec<u8>>, bool) {
    let fallback = control
        .filter(|control| control.len() >= 2)
        .map(<[u8]>::to_vec);
    if !trigger_snapped || trigger.len() <= 5 || trigger[0] != 0x16 {
        return (fallback, false);
    }
    let Some(control) = control.filter(|control| control.len() >= 2) else {
        return (fallback, false);
    };
    let Some((offset, length)) = crate::hello::sni_bounds(control) else {
        return (fallback, false);
    };
    let Some(name) = control.get(offset..offset.saturating_add(length)) else {
        return (fallback, false);
    };
    if name.is_empty() || name.len() >= 256 || name.contains(&0) {
        return (fallback, false);
    }
    let Some(clone) = crate::hello::rename_sni(trigger, name) else {
        return (fallback, false);
    };
    (Some(clone), true)
}

fn add_observation(result: &mut ClassifyResult, observation: Observation) {
    if result.trace.len() < MAX_TRACE {
        result.trace.push(observation);
    }
}

fn effective_mark(mark: Option<u32>) -> u32 {
    mark.unwrap_or(BYPASS_MARK)
}

fn is_cancelled(options: &ClassifyOptions) -> bool {
    options
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

fn raw_offer_timestamps(client_profile: Option<bool>) -> bool {
    client_profile.unwrap_or_else(|| {
        *HOST_TCP_TIMESTAMPS.get_or_init(|| {
            std::fs::read_to_string("/proc/sys/net/ipv4/tcp_timestamps")
                .ok()
                .and_then(|value| value.trim().parse::<i32>().ok())
                .unwrap_or(1)
                != 0
        })
    })
}

fn raw_selftest_age(family: u8, offer_ts: bool) -> Option<Duration> {
    let mut cache = RAW_SELFTESTS
        .get_or_init(|| Mutex::new(RawSelftestState::default()))
        .lock()
        .ok()?;
    let index = raw_selftest_index(family, offer_ts);
    let at = cache.checked_at[index]?;
    let age = at.elapsed();
    if age < Duration::from_secs(600) {
        Some(age)
    } else {
        cache.checked_at[index] = None;
        None
    }
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

fn raw_selftest_index(family: u8, offer_ts: bool) -> usize {
    (if family == 6 { 1 } else { 0 }) + if offer_ts { 0 } else { 2 }
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
        if is_cancelled(options) {
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
                    observation.error = Some(format!("{error:?}"));
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
    let mut probes = Vec::with_capacity(12);
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
        "перекрытие до конца имени",
        "seqovl-sni",
        Property::OverlapSni,
        Poison::default(),
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

fn property_probe_poison(
    property: &PropertyProbe,
    offer_ts: bool,
    props: &DpiProps,
) -> Option<Poison> {
    if raw_profile_allows(&property.poison, offer_ts) {
        return Some(property.poison.clone());
    }
    if !matches!(property.set, Property::WhiteTimestamp)
        || props.validates_checksum == TriState::True
    {
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
        badsum: props.validates_checksum != TriState::True,
        decoy_hello: props.parses_l7 == TriState::True,
        ..Poison::default()
    };
    let mut out = Vec::with_capacity(4);
    if props.counts_duplicates == TriState::True {
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
        if control.is_some() {
            out.push(base);
        }
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

    if poison.syn_data {
        let packet = build_control_packet(
            connection.local,
            connection.remote,
            connection.source_port,
            connection.destination_port,
            connection.sequence,
            connection.acknowledgment,
            TCP_PSH | TCP_ACK | TCP_SYN,
            &[],
            &trigger.payload,
        )
        .ok_or_else(|| ProbeError::Local("classify: SYN-data пакет не собран".into()))?;
        connection.send_ip_packet(&packet)?;
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
                    thread::sleep,
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

fn run_command(program: &str, args: &[String]) -> Result<std::process::ExitStatus, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("{program}: {error}"))?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
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
    30_000 + (next.fetch_add(1, Ordering::Relaxed) % 25_000) as u16
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

fn r2o_rst_uses_nft(firewall: Option<&str>) -> bool {
    firewall == Some("nft")
}

impl RstRule {
    fn install(source_port: u16, destination: SocketAddr) -> Result<Self, ProbeError> {
        let firewall = std::env::var("R2O_FW").ok();
        let nft = r2o_rst_uses_nft(firewall.as_deref());
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
            let status = run_command("nft", &args)
                .map_err(|error| ProbeError::Local(format!("classify: {error}")))?;
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
        let status = run_command(program, &args)
            .map_err(|error| ProbeError::Local(format!("classify: {error}")))?;
        if status.success() {
            return Ok(guard);
        }
        if !guard.comment || !matches!(status.code(), Some(1 | 2)) {
            return Err(ProbeError::Local(format!(
                "classify: {program} не установил подавление ядерного RST"
            )));
        }
        let fallback = guard.iptables_args(false, "-I");
        let status = run_command(program, &fallback)
            .map_err(|error| ProbeError::Local(format!("classify: {error}")))?;
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
        if let Some(rule) = &self.rule {
            rst_release(rule);
        }
    }
}

fn rst_delete_once_locked(rule: &RstRule) -> bool {
    if rule.nft {
        let deleted = run_command("nft", &rule.nft_args("delete"));
        if deleted.as_ref().is_ok_and(|status| status.success()) {
            return true;
        }
        return deleted
            .as_ref()
            .is_ok_and(|status| status.code() == Some(1))
            && run_command("nft", &rule.nft_args("get"))
                .is_ok_and(|status| status.code() == Some(1));
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
    deleted
        .as_ref()
        .is_ok_and(|status| status.code() == Some(1))
        && run_command(program, &rule.iptables_args(rule.comment, "-C"))
            .is_ok_and(|status| status.code() == Some(1))
}

fn rst_delete_once(rule: &RstRule) -> bool {
    let _lock = IPTABLES_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    rst_delete_once_locked(rule)
}

fn rst_release(rule: &RstRule) {
    for _ in 0..2 {
        if rst_delete_once(rule) {
            return;
        }
    }
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
        RST_ABANDON_REPORTED.call_once(|| {
            eprintln!("r2o: достигнут предел отложенного снятия RST-правил (64)");
        });
    }
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
            RST_ABANDON_REPORTED.call_once(|| {
                eprintln!("r2o: правило подавления RST не снято за 5 попыток; повторю при выходе");
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
            thread::sleep(Duration::from_millis(10));
        }
        if timed_out {
            let _ = child.wait();
        }
        let Ok(output) = child.wait_with_output() else {
            continue;
        };
        let rules = String::from_utf8_lossy(&output.stdout);
        for line in rules
            .lines()
            .filter(|line| line.contains("--comment r2o-rst:"))
        {
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
    sender: OwnedFd,
    receiver: OwnedFd,
    _rst_guard: RstGuard,
    local: IpAddr,
    remote: IpAddr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    template_options: Option<Vec<u8>>,
    recv_buffer: Vec<u8>,
}

impl RawConn {
    fn connect(
        remote: SocketAddr,
        timeout: Duration,
        mark: u32,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        offer_ts: bool,
    ) -> Result<Option<Self>, ProbeError> {
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
        RAW_DIALS.with(|count| count.set(count.get().saturating_add(1)));
        let rst_guard = RstGuard::install(source_port, remote);
        let mut connection = Self {
            sender,
            receiver,
            _rst_guard: rst_guard,
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
        let mut rto = Duration::from_secs(1);
        let deadline = Instant::now() + timeout;
        let mut next_syn = Instant::now();
        loop {
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err(ProbeError::Local("context canceled".into()));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            if Instant::now() >= next_syn {
                let packet = build_control_packet(
                    connection.local,
                    connection.remote,
                    connection.source_port,
                    connection.destination_port,
                    connection.sequence,
                    0,
                    TCP_SYN,
                    syn_options,
                    &[],
                )
                .ok_or_else(|| ProbeError::Local("classify: SYN пакет не собран".into()))?;
                connection.send_ip_packet(&packet)?;
                next_syn = Instant::now() + rto;
                rto = rto.saturating_mul(2);
            }
            let wait_until = deadline.min(next_syn);
            let Some(segment) = connection.receive_segment(wait_until, cancel)? else {
                continue;
            };
            if segment.flags & TCP_RST != 0 {
                return Ok(None);
            }
            if segment.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK
                && segment.acknowledgment == connection.sequence.wrapping_add(1)
            {
                if let Some(timestamp) = timestamp_value(&segment.options) {
                    connection.template_options = Some(timestamp_options(timestamp));
                }
                connection.sequence = connection.sequence.wrapping_add(1);
                connection.acknowledgment = segment.sequence.wrapping_add(1);
                let ack = build_control_packet(
                    connection.local,
                    connection.remote,
                    connection.source_port,
                    connection.destination_port,
                    connection.sequence,
                    connection.acknowledgment,
                    TCP_ACK,
                    &[],
                    &[],
                )
                .ok_or_else(|| ProbeError::Local("classify: ACK пакет не собран".into()))?;
                connection.send_ip_packet(&ack)?;
                return Ok(Some(connection));
            }
        }
    }

    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), ProbeError> {
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
        let sent = unsafe {
            libc::sendto(
                self.sender.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_DONTWAIT,
                (&destination as *const libc::sockaddr_storage).cast(),
                destination_len,
            )
        };
        if sent >= 0 && sent as usize == packet.len() {
            return Ok(());
        }
        let error = if sent < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::from(io::ErrorKind::WriteZero)
        };
        Err(ProbeError::Local(format!("classify: {error}")))
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
            let mut pollfd = libc::pollfd {
                fd: self.receiver.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut pollfd, 1, millis) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(ProbeError::Local(format!("classify: poll: {error}")));
            }
            if polled == 0 {
                continue;
            }
            let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut peer_len = std::mem::size_of_val(&peer) as libc::socklen_t;
            let count = unsafe {
                libc::recvfrom(
                    self.receiver.as_raw_fd(),
                    self.recv_buffer.as_mut_ptr().cast(),
                    self.recv_buffer.len(),
                    libc::MSG_DONTWAIT,
                    (&mut peer as *mut libc::sockaddr_storage).cast(),
                    &mut peer_len,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                return Err(ProbeError::Local(format!("classify: recvfrom: {error}")));
            }
            let packet = &self.recv_buffer[..count as usize];
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
            let (selected, cloned) = select_bridge_decoy(
                &trigger,
                (!control.is_empty()).then_some(control.as_slice()),
                snapped,
            );
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
        let nft = r2o_rst_uses_nft(Some(fixture["firewall"]));
        assert!(nft);
        assert!(!r2o_rst_uses_nft(None));
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
}
