use std::collections::VecDeque;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const R2O_DEFAULT_MEASUREMENT_LIMIT: usize = 2;
const R2O_MAX_MEASUREMENT_WORKERS: usize = 64;
const R2O_MEASUREMENT_START_GAP_MS: u64 = 250;
const R2O_CPU_SAMPLE_INTERVAL_MS: u64 = 1000;
const R2O_CPU_EWMA_INTERVAL_MS: u64 = 10_000;
const R2O_CPU_SHRINK_FREE: u64 = 250_000;
const R2O_CPU_GROW_FREE: u64 = 400_000;
const R2O_MEMORY_RESERVE_MIN_KB: u64 = 32 * 1024;
const R2O_MEMORY_RESERVE_PERCENT: u64 = 20;
const R2O_CONNTRACK_LIMIT_PERCENT: u64 = 60;
const R2O_LIMIT_LOG_STABLE_MS: u64 = 10_000;
const R2O_MEASUREMENT_LIMIT_CPU: u8 = 1;
const R2O_MEASUREMENT_LIMIT_MEMORY: u8 = 2;
const R2O_MEASUREMENT_LIMIT_CONNTRACK: u8 = 4;
const R2O_MEASUREMENT_LIMIT_SLOTS: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct R2oCpuCounters {
    busy: u64,
    total: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct R2oMemoryStats {
    available_kb: u64,
    total_kb: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct R2oConntrackStats {
    count: u64,
    max: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct R2oResourceReading {
    cpu: Option<R2oCpuCounters>,
    memory: Option<R2oMemoryStats>,
    conntrack: Option<R2oConntrackStats>,
}

fn r2o_parse_cpu_stat(line: &str) -> Option<R2oCpuCounters> {
    let fields = line.strip_prefix("cpu ")?;
    let mut values = [0_u64; 8];
    let mut count = 0;
    for field in fields.split_whitespace().take(values.len()) {
        values[count] = field.parse().ok()?;
        count += 1;
    }
    if count < 4 {
        return None;
    }
    let total = values[..count]
        .iter()
        .try_fold(0_u64, |sum, value| sum.checked_add(*value))?;
    let idle = values[3].checked_add(values.get(4).copied().unwrap_or_default())?;
    Some(R2oCpuCounters {
        busy: total.checked_sub(idle)?,
        total,
    })
}

fn r2o_meminfo_field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        line.strip_prefix(key)?
            .strip_prefix(':')?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

fn r2o_parse_meminfo(text: &str) -> Option<R2oMemoryStats> {
    let total_kb = r2o_meminfo_field(text, "MemTotal")?;
    let available_kb = r2o_meminfo_field(text, "MemAvailable")?;
    (total_kb > 0).then_some(R2oMemoryStats {
        available_kb,
        total_kb,
    })
}

fn r2o_read_counter(path: &str) -> Option<u64> {
    fs::read_to_string(path)
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

impl R2oResourceReading {
    fn r2o_read_proc() -> Self {
        let cpu = fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|text| text.lines().next().and_then(r2o_parse_cpu_stat));
        let memory = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| r2o_parse_meminfo(&text));
        let conntrack = r2o_read_counter("/proc/sys/net/netfilter/nf_conntrack_count")
            .zip(r2o_read_counter("/proc/sys/net/netfilter/nf_conntrack_max"))
            .filter(|(_, max)| *max > 0)
            .map(|(count, max)| R2oConntrackStats { count, max });
        Self {
            cpu,
            memory,
            conntrack,
        }
    }
}

pub fn r2o_measurement_worker_cap(_cores: Option<usize>, _total_memory_kb: Option<u64>) -> usize {
    R2O_MAX_MEASUREMENT_WORKERS
}

pub fn r2o_system_measurement_worker_cap() -> usize {
    r2o_measurement_worker_cap(None, None)
}

struct R2oAdaptiveLimit {
    max_slots: usize,
    limit: usize,
    grow_pending: bool,
    cpu_previous: Option<R2oCpuCounters>,
    cpu_free_u: Option<u64>,
    cpu_try_ms: Option<u64>,
    memory: Option<R2oMemoryStats>,
    conntrack: Option<R2oConntrackStats>,
    limiter: u8,
    limit_since_ms: u64,
    logged_valid: bool,
    logged_limit: usize,
    logged_limiter: u8,
}

impl R2oAdaptiveLimit {
    fn new(max_slots: usize) -> Self {
        let max_slots = max_slots.max(1);
        let default_limit = R2O_DEFAULT_MEASUREMENT_LIMIT.min(max_slots);
        Self {
            max_slots,
            limit: default_limit,
            grow_pending: false,
            cpu_previous: None,
            cpu_free_u: None,
            cpu_try_ms: None,
            memory: None,
            conntrack: None,
            limiter: 0,
            limit_since_ms: 0,
            logged_valid: false,
            logged_limit: default_limit,
            logged_limiter: 0,
        }
    }

    fn limit(&self) -> usize {
        self.limit
    }

    fn r2o_sample(
        &mut self,
        now_ms: u64,
        reading: R2oResourceReading,
        active: usize,
        queued: usize,
    ) -> Option<String> {
        let previous_limit = self.limit;
        let previous_limiter = self.limiter;
        let elapsed_ms = self
            .cpu_try_ms
            .map_or(0, |previous| now_ms.saturating_sub(previous).max(1));
        self.cpu_try_ms = Some(now_ms);
        self.memory = reading.memory.filter(|memory| memory.total_kb > 0);
        self.conntrack = reading.conntrack.filter(|stats| stats.max > 0);

        match reading.cpu {
            Some(current) => {
                if let Some(previous) = self.cpu_previous {
                    if current.total > previous.total && current.busy >= previous.busy {
                        let busy_delta = current.busy - previous.busy;
                        let total_delta = current.total - previous.total;
                        if busy_delta <= total_delta {
                            let instant_free = 1_000_000
                                - (u128::from(busy_delta) * 1_000_000 / u128::from(total_delta))
                                    as u64;
                            self.cpu_free_u = Some(match self.cpu_free_u {
                                None => instant_free,
                                Some(previous_free) => {
                                    let delta =
                                        i128::from(instant_free) - i128::from(previous_free);
                                    let change = delta * i128::from(elapsed_ms)
                                        / i128::from(elapsed_ms + R2O_CPU_EWMA_INTERVAL_MS);
                                    (i128::from(previous_free) + change) as u64
                                }
                            });
                        } else {
                            self.cpu_free_u = None;
                        }
                    } else {
                        self.cpu_free_u = None;
                    }
                } else {
                    self.cpu_free_u = None;
                }
                self.cpu_previous = Some(current);
            }
            None => {
                self.cpu_previous = None;
                self.cpu_free_u = None;
            }
        }

        let valid = self.cpu_free_u.is_some() && self.memory.is_some();
        let cpu_free = self.cpu_free_u.unwrap_or_default();
        let cpu_shrink = self
            .cpu_free_u
            .is_some_and(|free| free < R2O_CPU_SHRINK_FREE);
        let cpu_hold = self
            .cpu_free_u
            .is_some_and(|free| !cpu_shrink && free < R2O_CPU_GROW_FREE);
        let memory_short = self.memory.is_some_and(|memory| {
            memory.available_kb
                < R2O_MEMORY_RESERVE_MIN_KB.max(memory.total_kb * R2O_MEMORY_RESERVE_PERCENT / 100)
        });
        let conntrack_short = self.conntrack.is_some_and(|stats| {
            u128::from(stats.count) * 100
                >= u128::from(stats.max) * u128::from(R2O_CONNTRACK_LIMIT_PERCENT)
        });

        if !valid {
            self.limit = R2O_DEFAULT_MEASUREMENT_LIMIT.min(self.max_slots);
            self.grow_pending = false;
        } else if cpu_shrink || memory_short || conntrack_short {
            self.limit = (self.limit / 2).max(1);
            self.grow_pending = false;
        } else {
            if !cpu_hold
                && (self.grow_pending || (active >= self.limit && queued > 0))
                && self.limit < self.max_slots
            {
                self.limit += 1;
            }
            self.grow_pending = false;
        }

        let mut limiter = 0;
        if valid {
            if cpu_shrink || cpu_hold {
                limiter |= R2O_MEASUREMENT_LIMIT_CPU;
            }
            if memory_short {
                limiter |= R2O_MEASUREMENT_LIMIT_MEMORY;
            }
            if conntrack_short {
                limiter |= R2O_MEASUREMENT_LIMIT_CONNTRACK;
            }
            if limiter == 0 && self.limit >= self.max_slots {
                limiter |= R2O_MEASUREMENT_LIMIT_SLOTS;
            }
        }
        if self.limit != previous_limit || limiter != previous_limiter {
            self.limit_since_ms = now_ms;
        }
        self.limiter = limiter;

        if valid == self.logged_valid
            && ((self.limit == self.logged_limit && limiter == self.logged_limiter)
                || now_ms.saturating_sub(self.limit_since_ms) < R2O_LIMIT_LOG_STABLE_MS)
        {
            return None;
        }
        self.logged_valid = valid;
        self.logged_limit = self.limit;
        self.logged_limiter = limiter;
        if !valid {
            return Some(format!(
                "замеров {active} из {} (нет данных о загрузке процессора и памяти — прежний предел)",
                self.limit
            ));
        }

        let reason = r2o_limiter_text(limiter);
        let memory = self.memory.expect("проверенная память");
        let conntrack = self
            .conntrack
            .map(|stats| format!("{} %", r2o_conntrack_percent(stats)))
            .unwrap_or_else(|| "нет данных".into());
        Some(format!(
            "замеров {active} из {}, {}, процессор свободен {} %, память доступна {} МБ из {}, conntrack {conntrack}",
            self.limit,
            if reason.is_empty() {
                "запас по всем ресурсам"
            } else {
                &reason
            },
            (cpu_free + 5000) / 10_000,
            memory.available_kb / 1024,
            memory.total_kb / 1024,
        ))
    }

    fn r2o_mark_started(&mut self, active: usize) {
        if active >= self.limit {
            self.grow_pending = true;
        }
    }
}

fn r2o_conntrack_percent(stats: R2oConntrackStats) -> u64 {
    if stats.count >= stats.max {
        100
    } else {
        (u128::from(stats.count) * 100 / u128::from(stats.max)) as u64
    }
}

fn r2o_limiter_text(limiter: u8) -> String {
    [
        (R2O_MEASUREMENT_LIMIT_CPU, "процессор"),
        (R2O_MEASUREMENT_LIMIT_MEMORY, "память"),
        (R2O_MEASUREMENT_LIMIT_CONNTRACK, "conntrack"),
        (R2O_MEASUREMENT_LIMIT_SLOTS, "слоты"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (limiter & bit != 0).then_some(name))
    .collect::<Vec<_>>()
    .join(" / ")
}

struct R2oGateState {
    adaptive: R2oAdaptiveLimit,
    active: usize,
    initial_start_limit: usize,
    initial_starts: usize,
    waiters: VecDeque<R2oMeasurementWaiter>,
    next_waiter: u64,
    last_sample: Option<Instant>,
    last_started: Option<Instant>,
    scheduler_tick_seen: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum R2oMeasurementWaiterKind {
    Tcp,
    FamilyRecovery,
    Other,
    QuicYield,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct R2oMeasurementWaiter {
    id: u64,
    kind: R2oMeasurementWaiterKind,
}

fn r2o_queue_measurement_waiter(state: &mut R2oGateState, kind: R2oMeasurementWaiterKind) -> u64 {
    let waiter = R2oMeasurementWaiter {
        id: state.next_waiter,
        kind,
    };
    state.next_waiter = state.next_waiter.wrapping_add(1);
    state.waiters.push_back(waiter);
    waiter.id
}

fn r2o_next_measurement_waiter(state: &R2oGateState) -> Option<u64> {
    let tcp_waiting = state.waiters.iter().any(|waiter| {
        matches!(
            waiter.kind,
            R2oMeasurementWaiterKind::Tcp | R2oMeasurementWaiterKind::FamilyRecovery
        )
    });
    let quic_parked = state
        .waiters
        .iter()
        .any(|waiter| waiter.kind == R2oMeasurementWaiterKind::QuicYield);
    if quic_parked && tcp_waiting {
        return state
            .waiters
            .iter()
            .find(|waiter| {
                matches!(
                    waiter.kind,
                    R2oMeasurementWaiterKind::Tcp | R2oMeasurementWaiterKind::FamilyRecovery
                )
            })
            .map(|waiter| waiter.id);
    }
    state
        .waiters
        .iter()
        .find(|waiter| waiter.kind == R2oMeasurementWaiterKind::FamilyRecovery)
        .or_else(|| state.waiters.front())
        .map(|waiter| waiter.id)
}

struct R2oGateShared {
    state: Mutex<R2oGateState>,
    changed: Condvar,
    started: Instant,
    minimum_start_gap: Option<Duration>,
}

#[derive(Clone)]
pub struct R2oMeasurementGate {
    shared: Arc<R2oGateShared>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oMeasurementSnapshot {
    pub active: usize,
    pub limit: usize,
    pub queued: usize,
    pub cores: Option<u32>,
    pub free_pct: Option<u64>,
    pub mem_avail_mb: Option<u64>,
    pub mem_total_mb: Option<u64>,
    pub conntrack_pct: Option<u64>,
    pub limited_by: Option<String>,
}

pub struct R2oMeasurementPermit {
    shared: Arc<R2oGateShared>,
    active: bool,
    yielded_duration: Duration,
}

impl R2oMeasurementGate {
    pub fn new(max_slots: usize) -> Self {
        Self::r2o_new(max_slots, None)
    }

    pub fn r2o_with_start_gap(max_slots: usize) -> Self {
        Self::r2o_new(
            max_slots,
            Some(Duration::from_millis(R2O_MEASUREMENT_START_GAP_MS)),
        )
    }

    pub fn r2o_scheduler_tick(&self) {
        if self.shared.minimum_start_gap.is_none() {
            return;
        }
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.scheduler_tick_seen {
            return;
        }
        state.scheduler_tick_seen = true;
        if state.last_started.is_some() {
            state.last_started = Some(Instant::now());
        }
        self.shared.changed.notify_all();
    }

    pub fn r2o_live_snapshot(&self) -> R2oMeasurementSnapshot {
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let memory = state.adaptive.memory;
        let limited_by = r2o_limiter_text(state.adaptive.limiter);
        R2oMeasurementSnapshot {
            active: state.active,
            limit: state.adaptive.limit,
            queued: state.waiters.len(),
            cores: std::thread::available_parallelism()
                .ok()
                .and_then(|cores| u32::try_from(cores.get()).ok()),
            free_pct: state
                .adaptive
                .cpu_free_u
                .map(|free| (free.saturating_add(5_000) / 10_000).min(100)),
            mem_avail_mb: memory.map(|memory| memory.available_kb / 1024),
            mem_total_mb: memory.map(|memory| memory.total_kb / 1024),
            conntrack_pct: state.adaptive.conntrack.map(r2o_conntrack_percent),
            limited_by: (!limited_by.is_empty()).then_some(limited_by),
        }
    }

    pub fn r2o_max_slots(&self) -> usize {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .adaptive
            .max_slots
    }

    fn r2o_new(max_slots: usize, minimum_start_gap: Option<Duration>) -> Self {
        Self {
            shared: Arc::new(R2oGateShared {
                state: Mutex::new(R2oGateState {
                    adaptive: R2oAdaptiveLimit::new(max_slots),
                    active: 0,
                    initial_start_limit: R2O_DEFAULT_MEASUREMENT_LIMIT.min(max_slots.max(1)),
                    initial_starts: 0,
                    waiters: VecDeque::new(),
                    next_waiter: 1,
                    last_sample: None,
                    last_started: None,
                    scheduler_tick_seen: false,
                }),
                changed: Condvar::new(),
                started: Instant::now(),
                minimum_start_gap,
            }),
        }
    }

    pub fn r2o_try_acquire(&self) -> Option<R2oMeasurementPermit> {
        self.r2o_refresh_if_due();
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        if state.active >= state.adaptive.limit()
            || (state.scheduler_tick_seen
                && r2o_start_gap_remaining(state.last_started, now, self.shared.minimum_start_gap)
                    .is_some())
        {
            return None;
        }
        state.active += 1;
        if self.shared.minimum_start_gap.is_some() && !state.scheduler_tick_seen {
            state.initial_starts = state.initial_starts.saturating_add(1);
        }
        state.last_started = Some(now);
        let active = state.active;
        state.adaptive.r2o_mark_started(active);
        self.shared.changed.notify_all();
        Some(R2oMeasurementPermit {
            shared: Arc::clone(&self.shared),
            active: true,
            yielded_duration: Duration::ZERO,
        })
    }

    /// Немедленно берёт слот только для уже ожидающей работы и сохраняет её очередь.
    pub fn r2o_try_acquire_queued(&self) -> Option<R2oMeasurementPermit> {
        self.r2o_refresh_if_due();
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        if !state.waiters.is_empty()
            || state.active >= state.adaptive.limit()
            || r2o_initial_queue_waits_for_tick(&state, self.shared.minimum_start_gap)
            || (state.scheduler_tick_seen
                && r2o_start_gap_remaining(state.last_started, now, self.shared.minimum_start_gap)
                    .is_some())
        {
            return None;
        }
        state.active += 1;
        if self.shared.minimum_start_gap.is_some() && !state.scheduler_tick_seen {
            state.initial_starts = state.initial_starts.saturating_add(1);
        }
        state.last_started = Some(now);
        let active = state.active;
        state.adaptive.r2o_mark_started(active);
        self.shared.changed.notify_all();
        Some(R2oMeasurementPermit {
            shared: Arc::clone(&self.shared),
            active: true,
            yielded_duration: Duration::ZERO,
        })
    }

    pub fn r2o_acquire(&self, cancel: &AtomicBool) -> Option<R2oMeasurementPermit> {
        self.r2o_acquire_with_kind(cancel, R2oMeasurementWaiterKind::Other)
    }

    pub fn r2o_acquire_tcp(&self, cancel: &AtomicBool) -> Option<R2oMeasurementPermit> {
        self.r2o_acquire_with_kind(cancel, R2oMeasurementWaiterKind::Tcp)
    }

    pub fn r2o_acquire_family_recovery(&self, cancel: &AtomicBool) -> Option<R2oMeasurementPermit> {
        self.r2o_acquire_with_kind(cancel, R2oMeasurementWaiterKind::FamilyRecovery)
    }

    fn r2o_acquire_with_kind(
        &self,
        cancel: &AtomicBool,
        kind: R2oMeasurementWaiterKind,
    ) -> Option<R2oMeasurementPermit> {
        let waiter = {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            r2o_queue_measurement_waiter(&mut state, kind)
        };

        self.r2o_wait_for_measurement_turn(waiter, cancel)
    }

    fn r2o_wait_for_measurement_turn(
        &self,
        waiter: u64,
        cancel: &AtomicBool,
    ) -> Option<R2oMeasurementPermit> {
        loop {
            if cancel.load(Ordering::Relaxed) {
                let mut state = self
                    .shared
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.waiters.retain(|queued| queued.id != waiter);
                self.shared.changed.notify_all();
                return None;
            }
            self.r2o_refresh_if_due();
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if cancel.load(Ordering::Relaxed) {
                state.waiters.retain(|queued| queued.id != waiter);
                self.shared.changed.notify_all();
                return None;
            }
            if r2o_next_measurement_waiter(&state) == Some(waiter)
                && state.active < state.adaptive.limit()
            {
                let now = Instant::now();
                if r2o_initial_queue_waits_for_tick(&state, self.shared.minimum_start_gap) {
                    let (state, _) = self
                        .shared
                        .changed
                        .wait_timeout(state, Duration::from_millis(100))
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    drop(state);
                    continue;
                }
                if state.scheduler_tick_seen
                    && let Some(delay) = r2o_start_gap_remaining(
                        state.last_started,
                        now,
                        self.shared.minimum_start_gap,
                    )
                {
                    let (state, _) = self
                        .shared
                        .changed
                        .wait_timeout(state, delay.min(Duration::from_millis(100)))
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    drop(state);
                    continue;
                }
                let position = state
                    .waiters
                    .iter()
                    .position(|queued| queued.id == waiter)
                    .expect("selected measurement waiter stays queued");
                state.waiters.remove(position);
                state.active += 1;
                if self.shared.minimum_start_gap.is_some() && !state.scheduler_tick_seen {
                    state.initial_starts = state.initial_starts.saturating_add(1);
                }
                state.last_started = Some(now);
                let active = state.active;
                state.adaptive.r2o_mark_started(active);
                self.shared.changed.notify_all();
                return Some(R2oMeasurementPermit {
                    shared: Arc::clone(&self.shared),
                    active: true,
                    yielded_duration: Duration::ZERO,
                });
            }
            let (state, _) = self
                .shared
                .changed
                .wait_timeout(state, Duration::from_millis(100))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            drop(state);
        }
    }

    fn r2o_refresh_if_due(&self) {
        let now = Instant::now();
        {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.last_sample.is_some_and(|last| {
                now.saturating_duration_since(last)
                    < Duration::from_millis(R2O_CPU_SAMPLE_INTERVAL_MS)
            }) {
                return;
            }
            state.last_sample = Some(now);
        }

        let reading = R2oResourceReading::r2o_read_proc();
        let now_ms = now
            .saturating_duration_since(self.shared.started)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let status = {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let active = state.active;
            let queued = state.waiters.len();
            let status = state.adaptive.r2o_sample(now_ms, reading, active, queued);
            self.shared.changed.notify_all();
            status
        };
        if let Some(status) = status {
            println!("r2o-controller: {status}");
        }
    }
}

fn r2o_initial_queue_waits_for_tick(
    state: &R2oGateState,
    minimum_start_gap: Option<Duration>,
) -> bool {
    minimum_start_gap.is_some()
        && !state.scheduler_tick_seen
        && state.initial_starts >= state.initial_start_limit
}

impl R2oMeasurementPermit {
    pub fn r2o_yielded_duration(&self) -> Duration {
        self.yielded_duration
    }

    pub fn r2o_yield_if_contended(&mut self) {
        let _ = self.r2o_yield_if_contended_with_cancel(&AtomicBool::new(false));
    }

    pub fn r2o_yield_if_contended_with_cancel(&mut self, cancel: &AtomicBool) -> bool {
        if !self.active {
            return false;
        }
        let shared = Arc::clone(&self.shared);
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if cancel.load(Ordering::Relaxed) {
            self.active = false;
            state.active = state.active.saturating_sub(1);
            drop(state);
            shared.changed.notify_all();
            return false;
        }
        let tcp_waiting = state.waiters.iter().any(|waiter| {
            matches!(
                waiter.kind,
                R2oMeasurementWaiterKind::Tcp | R2oMeasurementWaiterKind::FamilyRecovery
            )
        });
        if !tcp_waiting || state.active < state.adaptive.limit() {
            return true;
        }
        let r2o_yield_started = Instant::now();
        self.active = false;
        let gate = R2oMeasurementGate {
            shared: Arc::clone(&shared),
        };
        let waiter = r2o_queue_measurement_waiter(&mut state, R2oMeasurementWaiterKind::QuicYield);
        state.active = state.active.saturating_sub(1);
        drop(state);
        shared.changed.notify_all();

        let Some(mut replacement) = gate.r2o_wait_for_measurement_turn(waiter, cancel) else {
            return false;
        };
        self.yielded_duration = self
            .yielded_duration
            .saturating_add(r2o_yield_started.elapsed());
        std::mem::swap(&mut self.active, &mut replacement.active);
        true
    }
}

fn r2o_start_gap_remaining(
    last_started: Option<Instant>,
    now: Instant,
    minimum_start_gap: Option<Duration>,
) -> Option<Duration> {
    let last_started = last_started?;
    let minimum_start_gap = minimum_start_gap?;
    let elapsed = now.saturating_duration_since(last_started);
    (elapsed < minimum_start_gap).then(|| minimum_start_gap - elapsed)
}

impl Drop for R2oMeasurementPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active = state.active.saturating_sub(1);
        self.shared.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        R2oAdaptiveLimit, R2oConntrackStats, R2oCpuCounters, R2oMeasurementGate,
        R2oMeasurementWaiterKind, R2oMemoryStats, R2oResourceReading, r2o_measurement_worker_cap,
        r2o_next_measurement_waiter, r2o_parse_cpu_stat, r2o_parse_meminfo,
        r2o_queue_measurement_waiter,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::Duration;

    #[test]
    fn worker_slots_match_the_d2o_scheduler_capacity() {
        assert_eq!(r2o_measurement_worker_cap(Some(4), Some(1_048_576)), 64);
        assert_eq!(r2o_measurement_worker_cap(Some(1), Some(65_536)), 64);
        assert_eq!(r2o_measurement_worker_cap(Some(8), None), 64);
        assert_eq!(r2o_measurement_worker_cap(None, Some(32_768)), 64);
    }

    #[test]
    fn scheduler_uses_the_d2o_measurement_start_gap() {
        let gate = R2oMeasurementGate::r2o_with_start_gap(64);
        assert_eq!(gate.r2o_max_slots(), 64);
        assert_eq!(
            gate.shared.minimum_start_gap,
            Some(Duration::from_millis(250))
        );
    }

    #[test]
    fn r2o_live_snapshot_reports_actual_gate_occupancy() {
        let gate = R2oMeasurementGate::new(3);
        let initial = gate.r2o_live_snapshot();
        assert_eq!((initial.active, initial.limit, initial.queued), (0, 2, 0));

        let permit = gate.r2o_try_acquire().unwrap();
        let active = gate.r2o_live_snapshot();
        assert_eq!((active.active, active.limit, active.queued), (1, 2, 0));
        drop(permit);
        assert_eq!(gate.r2o_live_snapshot().active, 0);
    }

    #[test]
    fn r2o_разбор_cpu_исключает_idle_и_iowait() {
        assert_eq!(
            r2o_parse_cpu_stat("cpu  100 5 50 800 40 3 2 0 0 0\n"),
            Some(R2oCpuCounters {
                busy: 160,
                total: 1000
            }),
        );
        assert_eq!(r2o_parse_cpu_stat("cpu0 1 2 3 4\n"), None);
        assert_eq!(r2o_parse_cpu_stat("cpu 1 2 3\n"), None);
        assert_eq!(
            r2o_parse_cpu_stat("cpu 1 2 3 4 18446744073709551616\n"),
            None
        );
    }

    #[test]
    fn r2o_разбор_meminfo_требует_memavailable_и_ненулевой_memtotal() {
        assert_eq!(
            r2o_parse_meminfo(
                "MemTotal:         254000 kB\nMemFree: 10000 kB\nMemAvailable: 120000 kB\n"
            ),
            Some(R2oMemoryStats {
                available_kb: 120000,
                total_kb: 254000
            }),
        );
        assert_eq!(
            r2o_parse_meminfo("MemTotal: 254000 kB\nMemFree: 10000 kB\n"),
            None
        );
        assert_eq!(
            r2o_parse_meminfo("MemTotal: 0 kB\nMemAvailable: 1 kB\n"),
            None
        );
    }

    #[test]
    fn r2o_предел_растёт_по_одному_и_снижается_вдвое_при_нехватке_памяти() {
        let mut limit = R2oAdaptiveLimit::new(4);
        limit.r2o_sample(
            0,
            R2oResourceReading {
                cpu: Some(R2oCpuCounters {
                    busy: 100,
                    total: 1000,
                }),
                memory: Some(R2oMemoryStats {
                    available_kb: 400_000,
                    total_kb: 512_000,
                }),
                conntrack: Some(R2oConntrackStats {
                    count: 10,
                    max: 100,
                }),
            },
            0,
            0,
        );
        assert_eq!(limit.limit(), 2);

        limit.r2o_sample(
            1000,
            R2oResourceReading {
                cpu: Some(R2oCpuCounters {
                    busy: 200,
                    total: 2000,
                }),
                memory: Some(R2oMemoryStats {
                    available_kb: 400_000,
                    total_kb: 512_000,
                }),
                conntrack: Some(R2oConntrackStats {
                    count: 10,
                    max: 100,
                }),
            },
            2,
            1,
        );
        assert_eq!(limit.limit(), 3);

        limit.r2o_sample(
            2000,
            R2oResourceReading {
                cpu: Some(R2oCpuCounters {
                    busy: 300,
                    total: 3000,
                }),
                memory: Some(R2oMemoryStats {
                    available_kb: 100_000,
                    total_kb: 512_000,
                }),
                conntrack: Some(R2oConntrackStats {
                    count: 10,
                    max: 100,
                }),
            },
            3,
            1,
        );
        assert_eq!(limit.limit(), 1);

        limit.r2o_sample(
            3000,
            R2oResourceReading {
                cpu: Some(R2oCpuCounters {
                    busy: 400,
                    total: 4000,
                }),
                memory: Some(R2oMemoryStats {
                    available_kb: 400_000,
                    total_kb: 512_000,
                }),
                conntrack: Some(R2oConntrackStats {
                    count: 10,
                    max: 100,
                }),
            },
            1,
            1,
        );
        assert_eq!(limit.limit(), 2);
    }

    #[test]
    fn r2o_cpu_и_conntrack_ограничивают_новые_замеры() {
        let mut limit = R2oAdaptiveLimit::new(4);
        limit.r2o_sample(
            0,
            R2oResourceReading {
                cpu: Some(R2oCpuCounters {
                    busy: 100,
                    total: 1000,
                }),
                memory: Some(R2oMemoryStats {
                    available_kb: 400_000,
                    total_kb: 512_000,
                }),
                conntrack: Some(R2oConntrackStats {
                    count: 10,
                    max: 100,
                }),
            },
            0,
            0,
        );
        limit.r2o_sample(
            1000,
            R2oResourceReading {
                cpu: Some(R2oCpuCounters {
                    busy: 900,
                    total: 2000,
                }),
                memory: Some(R2oMemoryStats {
                    available_kb: 400_000,
                    total_kb: 512_000,
                }),
                conntrack: Some(R2oConntrackStats {
                    count: 10,
                    max: 100,
                }),
            },
            2,
            1,
        );
        assert_eq!(limit.limit(), 1);

        let mut limit = R2oAdaptiveLimit::new(4);
        limit.r2o_sample(
            0,
            R2oResourceReading {
                cpu: Some(R2oCpuCounters {
                    busy: 100,
                    total: 1000,
                }),
                memory: Some(R2oMemoryStats {
                    available_kb: 400_000,
                    total_kb: 512_000,
                }),
                conntrack: Some(R2oConntrackStats {
                    count: 10,
                    max: 100,
                }),
            },
            0,
            0,
        );
        limit.r2o_sample(
            1000,
            R2oResourceReading {
                cpu: Some(R2oCpuCounters {
                    busy: 200,
                    total: 2000,
                }),
                memory: Some(R2oMemoryStats {
                    available_kb: 400_000,
                    total_kb: 512_000,
                }),
                conntrack: Some(R2oConntrackStats {
                    count: 60,
                    max: 100,
                }),
            },
            2,
            1,
        );
        assert_eq!(limit.limit(), 1);
    }

    #[test]
    fn r2o_полоса_cpu_от_двадцати_пяти_до_сорока_процентов_не_меняет_предел() {
        let mut limit = R2oAdaptiveLimit::new(4);
        let reading = |busy, total| R2oResourceReading {
            cpu: Some(R2oCpuCounters { busy, total }),
            memory: Some(R2oMemoryStats {
                available_kb: 400_000,
                total_kb: 512_000,
            }),
            conntrack: None,
        };
        limit.r2o_sample(0, reading(100, 1000), 0, 0);
        limit.r2o_sample(1000, reading(800, 2000), 2, 1);
        assert_eq!(limit.limit(), 2);
        limit.r2o_sample(2000, reading(1500, 3000), 2, 1);
        assert_eq!(limit.limit(), 2);
    }

    #[test]
    fn r2o_conntrack_без_счётчика_не_ограничивает_замеры() {
        let mut limit = R2oAdaptiveLimit::new(4);
        let reading = |busy, total| R2oResourceReading {
            cpu: Some(R2oCpuCounters { busy, total }),
            memory: Some(R2oMemoryStats {
                available_kb: 400_000,
                total_kb: 512_000,
            }),
            conntrack: None,
        };
        limit.r2o_sample(0, reading(100, 1000), 0, 0);
        limit.r2o_sample(1000, reading(200, 2000), 2, 1);
        assert_eq!(limit.limit(), 3);
    }

    #[test]
    fn r2o_причина_ограничения_журналируется_после_десяти_секунд_без_дребезга() {
        let mut limit = R2oAdaptiveLimit::new(4);
        let reading = |busy, total, available_kb| R2oResourceReading {
            cpu: Some(R2oCpuCounters { busy, total }),
            memory: Some(R2oMemoryStats {
                available_kb,
                total_kb: 512_000,
            }),
            conntrack: Some(R2oConntrackStats {
                count: 10,
                max: 100,
            }),
        };
        assert!(
            limit
                .r2o_sample(0, reading(100, 1000, 400_000), 0, 0)
                .is_none()
        );
        assert!(
            limit
                .r2o_sample(1000, reading(200, 2000, 400_000), 0, 0)
                .is_some()
        );
        assert!(
            limit
                .r2o_sample(2000, reading(300, 3000, 100_000), 0, 0)
                .is_none()
        );
        assert!(
            limit
                .r2o_sample(11_999, reading(400, 4000, 100_000), 0, 0)
                .is_none()
        );
        assert!(
            limit
                .r2o_sample(12_000, reading(500, 5000, 100_000), 0, 0)
                .is_some()
        );
    }

    #[test]
    fn r2o_ожидающий_замер_отменяется_без_удержания_слота() {
        let gate = R2oMeasurementGate::new(1);
        let held = gate.r2o_acquire(&AtomicBool::new(false)).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_gate = gate.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let acquired = worker_gate.r2o_acquire(&worker_cancel).is_some();
            sender.send(acquired).unwrap();
        });

        std::thread::sleep(Duration::from_millis(30));
        cancel.store(true, Ordering::Relaxed);
        assert!(!receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        drop(held);
        worker.join().unwrap();
        assert!(gate.r2o_acquire(&AtomicBool::new(false)).is_some());
    }

    #[test]
    fn r2o_неблокирующий_замер_уважает_предел_и_освобождение_слота() {
        let gate = R2oMeasurementGate::new(1);
        let first = gate.r2o_try_acquire().unwrap();
        assert!(gate.r2o_try_acquire().is_none());
        drop(first);
        assert!(gate.r2o_try_acquire().is_some());
    }

    #[test]
    fn r2o_quic_уступает_слот_ожидающему_замеру() {
        let gate = R2oMeasurementGate::new(1);
        let mut quic = gate.r2o_acquire(&AtomicBool::new(false)).unwrap();
        let worker_gate = gate.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let permit = worker_gate
                .r2o_acquire_tcp(&AtomicBool::new(false))
                .unwrap();
            sender.send(()).unwrap();
            drop(permit);
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let queued = gate
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .waiters
                .len();
            if queued == 1 {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }

        quic.r2o_yield_if_contended();

        receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            gate.shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active,
            1
        );
        drop(quic);
        worker.join().unwrap();
    }

    #[test]
    fn r2o_quic_не_уступает_слот_пока_лимит_не_достигнут() {
        let gate = R2oMeasurementGate::r2o_with_start_gap(2);
        let mut quic = gate.r2o_try_acquire().unwrap();
        gate.r2o_scheduler_tick();

        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_gate = gate.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let acquired = worker_gate.r2o_acquire_tcp(&worker_cancel).is_some();
            sender.send(acquired).unwrap();
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let state = gate
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.waiters.len() == 1 {
                assert_eq!((state.active, state.adaptive.limit()), (1, 2));
                break;
            }
            drop(state);
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }

        assert!(quic.r2o_yield_if_contended_with_cancel(&AtomicBool::new(false)));
        assert!(quic.active);
        assert_eq!(quic.r2o_yielded_duration(), Duration::ZERO);
        cancel.store(true, Ordering::Relaxed);
        assert!(!receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        drop(quic);
        worker.join().unwrap();
    }

    #[test]
    fn r2o_quic_не_уступает_слот_ожидающему_не_tcp_замеру() {
        let gate = R2oMeasurementGate::new(1);
        let mut quic = gate.r2o_acquire(&AtomicBool::new(false)).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_gate = gate.clone();
        let worker = std::thread::spawn(move || worker_gate.r2o_acquire(&worker_cancel).is_some());

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let state = gate
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.waiters.len() == 1 {
                assert_eq!(
                    state.waiters.front().unwrap().kind,
                    R2oMeasurementWaiterKind::Other
                );
                break;
            }
            drop(state);
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }

        assert!(quic.r2o_yield_if_contended_with_cancel(&AtomicBool::new(false)));
        assert!(quic.active);
        assert_eq!(gate.shared.state.lock().unwrap().active, 1);
        cancel.store(true, Ordering::Relaxed);
        assert!(!worker.join().unwrap());
        drop(quic);
    }

    #[test]
    fn queued_turn_matches_family_recovery_and_quic_tcp_priority() {
        let gate = R2oMeasurementGate::new(1);
        let mut state = gate.shared.state.lock().unwrap();
        let other = r2o_queue_measurement_waiter(&mut state, R2oMeasurementWaiterKind::Other);
        let recovery =
            r2o_queue_measurement_waiter(&mut state, R2oMeasurementWaiterKind::FamilyRecovery);
        assert_eq!(r2o_next_measurement_waiter(&state), Some(recovery));

        let _quic = r2o_queue_measurement_waiter(&mut state, R2oMeasurementWaiterKind::QuicYield);
        let tcp = r2o_queue_measurement_waiter(&mut state, R2oMeasurementWaiterKind::Tcp);
        assert_eq!(r2o_next_measurement_waiter(&state), Some(recovery));
        state.waiters.retain(|waiter| waiter.id != recovery);
        assert_eq!(r2o_next_measurement_waiter(&state), Some(tcp));
        state.waiters.retain(|waiter| waiter.id != tcp);
        assert_eq!(r2o_next_measurement_waiter(&state), Some(other));
    }

    #[test]
    fn r2o_quic_возобновляется_после_одного_ожидающего_замера() {
        let gate = R2oMeasurementGate::new(1);
        let mut quic = gate.r2o_acquire(&AtomicBool::new(false)).unwrap();
        let first_gate = gate.clone();
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first = std::thread::spawn(move || {
            let _permit = first_gate.r2o_acquire_tcp(&AtomicBool::new(false)).unwrap();
            first_started_tx.send(()).unwrap();
            release_first_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
        });
        let first_waiting_deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let queued = gate
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .waiters
                .len();
            if queued == 1 {
                break;
            }
            assert!(std::time::Instant::now() < first_waiting_deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let second_gate = gate.clone();
        let (second_started_tx, second_started_rx) = mpsc::channel();
        let second = std::thread::spawn(move || {
            let _permit = second_gate
                .r2o_acquire_tcp(&AtomicBool::new(false))
                .unwrap();
            second_started_tx.send(()).unwrap();
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let queued = gate
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .waiters
                .len();
            if queued == 2 {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }

        let (resumed_tx, resumed_rx) = mpsc::channel();
        let resume = std::thread::spawn(move || {
            let resumed = quic.r2o_yield_if_contended_with_cancel(&AtomicBool::new(false));
            resumed_tx.send((resumed, quic)).unwrap();
        });
        first_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert!(matches!(
            second_started_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        std::thread::sleep(Duration::from_millis(20));
        release_first_tx.send(()).unwrap();

        second_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let (resumed, quic) = resumed_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(resumed);
        assert!(quic.r2o_yielded_duration() >= Duration::from_millis(10));
        drop(quic);
        first.join().unwrap();
        second.join().unwrap();
        resume.join().unwrap();
        assert_eq!(
            gate.shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active,
            0
        );
    }

    #[test]
    fn r2o_quic_отменяется_без_утечки_слота() {
        let gate = R2oMeasurementGate::new(1);
        let mut quic = gate.r2o_acquire(&AtomicBool::new(false)).unwrap();
        let worker_gate = gate.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let permit = worker_gate
                .r2o_acquire_tcp(&AtomicBool::new(false))
                .unwrap();
            sender.send(()).unwrap();
            drop(permit);
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let queued = gate
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .waiters
                .len();
            if queued == 1 {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }

        let cancel = AtomicBool::new(true);
        assert!(!quic.r2o_yield_if_contended_with_cancel(&cancel));
        receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(quic);
        worker.join().unwrap();
        assert_eq!(
            gate.shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active,
            0
        );
        assert!(gate.r2o_try_acquire().is_some());
    }

    #[test]
    fn r2o_quic_отмена_без_ожидающих_слотов_освобождает_слот() {
        let gate = R2oMeasurementGate::new(1);
        let mut quic = gate.r2o_acquire(&AtomicBool::new(false)).unwrap();

        assert!(!quic.r2o_yield_if_contended_with_cancel(&AtomicBool::new(true)));
        assert_eq!(
            gate.shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active,
            0
        );
        assert!(gate.r2o_try_acquire().is_some());
    }

    #[test]
    fn r2o_ожидающие_старты_разделены_интервалом_в_250_мс() {
        let gate = R2oMeasurementGate::r2o_with_start_gap(2);
        let first_started = std::time::Instant::now();
        let first = gate.r2o_try_acquire().unwrap();
        gate.r2o_scheduler_tick();

        assert!(gate.r2o_try_acquire().is_none());

        let worker_gate = gate.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let acquired = worker_gate.r2o_acquire(&AtomicBool::new(false)).is_some();
            sender.send(acquired).unwrap();
        });

        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert_eq!(
            gate.shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active,
            1
        );
        assert!(receiver.recv_timeout(Duration::from_secs(1)).unwrap());
        assert!(first_started.elapsed() >= Duration::from_millis(250));

        drop(first);
        worker.join().unwrap();
    }

    #[test]
    fn r2o_до_первого_тика_разрешает_начальную_пачку_до_лимита() {
        let gate = R2oMeasurementGate::r2o_with_start_gap(2);
        let first = gate.r2o_try_acquire().unwrap();
        let second = gate.r2o_try_acquire().unwrap();

        assert!(gate.r2o_try_acquire().is_none());
        drop(first);
        let third = gate.r2o_try_acquire().unwrap();

        gate.r2o_scheduler_tick();
        drop(second);
        drop(third);
        assert!(gate.r2o_try_acquire().is_none());
    }
}
