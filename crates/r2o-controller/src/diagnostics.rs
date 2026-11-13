//! Локальный opt-in снимок истории поиска и ресурсов для панели.

use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::ffi::{c_int, c_long};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::size_of;
use std::path::{Path, PathBuf};
#[cfg(not(target_has_atomic = "64"))]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_has_atomic = "64")]
type AtomicU64 = std::sync::atomic::AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
#[derive(Default)]
struct AtomicU64(Mutex<u64>);

#[cfg(not(target_has_atomic = "64"))]
#[allow(dead_code)]
impl AtomicU64 {
    const fn new(value: u64) -> Self {
        Self(Mutex::new(value))
    }

    fn load(&self, _ordering: Ordering) -> u64 {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn store(&self, value: u64, _ordering: Ordering) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    fn fetch_add(&self, value: u64, _ordering: Ordering) -> u64 {
        let mut current = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = *current;
        *current = current.wrapping_add(value);
        previous
    }

    fn fetch_sub(&self, value: u64, _ordering: Ordering) -> u64 {
        let mut current = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = *current;
        *current = current.wrapping_sub(value);
        previous
    }

    fn compare_exchange_weak(
        &self,
        current: u64,
        new: u64,
        _success: Ordering,
        _failure: Ordering,
    ) -> Result<u64, u64> {
        let mut value = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *value == current {
            *value = new;
            Ok(current)
        } else {
            Err(*value)
        }
    }
}

pub const MEMORY_SITE_COUNT: usize = 6;
pub const MADVISE_ERRNO_SLOTS: usize = 4;
const MEMORY_SITE_SPECS: [(&str, &str, &str); MEMORY_SITE_COUNT] = [
    (
        "tcp.worker_arg",
        "TCP worker argument",
        "core/sched.c:start_worker",
    ),
    (
        "tls12.session",
        "TLS 1.2 session",
        "core/tls12.c:d2k_tls12_connect/resume",
    ),
    (
        "tls13.session",
        "TLS 1.3 session",
        "core/tls13.c:tls_connect_internal",
    ),
    (
        "tcp.tls_rx_buffer",
        "TCP/TLS receive buffer",
        "core/verify.c:TCP/TLS response buffer",
    ),
    (
        "quic.connection",
        "QUIC connection",
        "core/quicconn.c:d2k_qc_first_initial/connect",
    ),
    (
        "quic.response_header",
        "QUIC response header",
        "core/verify.c and quicprobe.c:HTTP/3 response buffers",
    ),
];
static MEMORY_ENABLED: AtomicBool = AtomicBool::new(false);
static MEMORY_SITES: [MemorySiteCounters; MEMORY_SITE_COUNT] = [
    MemorySiteCounters::new(),
    MemorySiteCounters::new(),
    MemorySiteCounters::new(),
    MemorySiteCounters::new(),
    MemorySiteCounters::new(),
    MemorySiteCounters::new(),
];

struct MemorySiteCounters {
    live_bytes: AtomicU64,
    peak_bytes: AtomicU64,
    live_objects: AtomicU64,
    created: AtomicU64,
    destroyed: AtomicU64,
    alloc_failures: AtomicU64,
}

impl MemorySiteCounters {
    const fn new() -> Self {
        Self {
            live_bytes: AtomicU64::new(0),
            peak_bytes: AtomicU64::new(0),
            live_objects: AtomicU64::new(0),
            created: AtomicU64::new(0),
            destroyed: AtomicU64::new(0),
            alloc_failures: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemorySite {
    pub live_bytes: u64,
    pub peak_bytes: u64,
    pub live_objects: u64,
    pub created: u64,
    pub destroyed: u64,
    pub alloc_failures: u64,
}

pub fn memory_enable(enabled: bool) {
    MEMORY_ENABLED.store(enabled, Ordering::Release);
}

pub fn memory_active() -> bool {
    MEMORY_ENABLED.load(Ordering::Relaxed)
}

/// Учесть объект, выделенный при включённом сборе. Возвращает true, если
/// объект нужно освобождать парным `memory_release`.
pub fn memory_acquire(site: usize, bytes: usize) -> bool {
    if site >= MEMORY_SITE_COUNT || !memory_active() || bytes > u32::MAX as usize {
        return false;
    }
    let counters = &MEMORY_SITES[site];
    let bytes = bytes as u64;
    let live = counters.live_bytes.fetch_add(bytes, Ordering::AcqRel) + bytes;
    counters.live_objects.fetch_add(1, Ordering::AcqRel);
    counters.created.fetch_add(1, Ordering::AcqRel);
    let mut peak = counters.peak_bytes.load(Ordering::Acquire);
    while live > peak {
        match counters.peak_bytes.compare_exchange_weak(
            peak,
            live,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(seen) => peak = seen,
        }
    }
    true
}

pub fn memory_release(site: usize, bytes: usize, tracked: bool) {
    if !tracked || site >= MEMORY_SITE_COUNT || bytes > u32::MAX as usize {
        return;
    }
    let counters = &MEMORY_SITES[site];
    counters
        .live_bytes
        .fetch_sub(bytes as u64, Ordering::AcqRel);
    counters.live_objects.fetch_sub(1, Ordering::AcqRel);
    counters.destroyed.fetch_add(1, Ordering::AcqRel);
}

pub fn memory_alloc_failure(site: usize) {
    if site < MEMORY_SITE_COUNT && memory_active() {
        MEMORY_SITES[site]
            .alloc_failures
            .fetch_add(1, Ordering::AcqRel);
    }
}

pub fn memory_snapshot() -> [MemorySite; MEMORY_SITE_COUNT] {
    std::array::from_fn(|index| {
        let counters = &MEMORY_SITES[index];
        MemorySite {
            live_bytes: counters.live_bytes.load(Ordering::Acquire),
            peak_bytes: counters.peak_bytes.load(Ordering::Acquire),
            live_objects: counters.live_objects.load(Ordering::Acquire),
            created: counters.created.load(Ordering::Acquire),
            destroyed: counters.destroyed.load(Ordering::Acquire),
            alloc_failures: counters.alloc_failures.load(Ordering::Acquire),
        }
    })
}

/// (tracked_tcp, tracked_tls, tracked_quic) в байтах, как в C
/// `d2k_diag_memory_counts`.
pub fn tracked_memory_bytes() -> (u64, u64, u64) {
    let sites = memory_snapshot();
    (
        sites[0].live_bytes + sites[3].live_bytes,
        sites[1].live_bytes + sites[2].live_bytes,
        sites[4].live_bytes + sites[5].live_bytes,
    )
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MadviseErrno {
    pub error: i32,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MadviseStats {
    pub successes: u64,
    pub failures: u64,
    pub requested_bytes: u64,
    pub failed_requested_bytes: u64,
    pub last_errno: i32,
    pub other_errno_count: u64,
    pub errno_hist: [MadviseErrno; MADVISE_ERRNO_SLOTS],
}

pub fn memory_tracking_json() -> Value {
    let sites = memory_snapshot();
    let entries: Vec<Value> = sites
        .iter()
        .enumerate()
        .map(|(index, site)| {
            json!({
                "id": MEMORY_SITE_SPECS[index].0,
                "name": MEMORY_SITE_SPECS[index].1,
                "location": MEMORY_SITE_SPECS[index].2,
                "live_bytes": site.live_bytes,
                "peak_bytes": site.peak_bytes,
                "live_objects": site.live_objects,
                "created": site.created,
                "destroyed": site.destroyed,
                "alloc_failures": site.alloc_failures,
            })
        })
        .collect();
    json!({
        "enabled": memory_active(),
        "coverage": "учитываются объекты, выделенные при включённом сборе; уже существующие объекты задним числом не учитываются",
        "sites": entries,
    })
}

pub fn madvise_json(stats: &MadviseStats) -> Value {
    let errno: Vec<Value> = stats
        .errno_hist
        .iter()
        .filter(|entry| entry.error != 0)
        .map(|entry| json!({"code": entry.error, "count": entry.count}))
        .collect();
    json!({
        "successes": stats.successes,
        "failures": stats.failures,
        "requested_bytes": stats.requested_bytes,
        "failed_requested_bytes": stats.failed_requested_bytes,
        "last_errno": if stats.last_errno == 0 { Value::Null } else { json!(stats.last_errno) },
        "other_errno_count": stats.other_errno_count,
        "errno": errno,
    })
}

const EVENT_CAPACITY: usize = 64;
const LIMIT_CAPACITY: usize = 32;
const SAMPLE_CAPACITY: usize = 120;
const MEMORY_HISTORY_CAPACITY: usize = 1440;
const ANOMALY_CAPACITY: usize = 8;
const GROWTH_CAPACITY: usize = 10;
const SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
// D2O: D2K_DIAG_REPORT_MAX (448 КиБ). История 1440 строк не помещается
// в прежние 256 КиБ и молча перестала бы записываться.
const REPORT_MAX: usize = 448 * 1024;
const MEMORY_HISTORY_FIELDS: [&str; 20] = [
    "at_delta_s",
    "mono_delta_s",
    "rss_kib",
    "vm_data_kib",
    "vm_swap_kib",
    "smaps_rollup_status_code",
    "smaps_rollup_errno",
    "smaps_rollup_kib",
    "rss_anon_kib",
    "catalog_bytes",
    "http_bytes",
    "snapshot_bytes",
    "tracked_tcp_bytes",
    "tracked_quic_bytes",
    "tracked_tls_bytes",
    "tasks",
    "workers_live",
    "workers_result_pending",
    "workers_join_pending",
    "d2kc_epoch",
];
const TASK_STATE_NAMES: [&str; 15] = [
    "free",
    "queued",
    "asking",
    "shape_wait",
    "props_contact",
    "props_wait",
    "planning",
    "trial_settle",
    "verify",
    "verify_wait",
    "watching",
    "resting",
    "voice_measure",
    "voice_trial",
    "voice_watch",
];
const D2O_PROCESS_CAPACITY: usize = 3;
const PROCESS_SPECS: [ProcessSpec; 3] = [
    ProcessSpec {
        name: "r2o-controller",
        comm: "r2o-controller",
        pidfile: "r2o-controller.pid",
        fallback_pidfile: Some("r2o-controller4.pid"),
    },
    ProcessSpec {
        name: "r2o-datapath",
        comm: "r2o-datapath",
        pidfile: "r2o-datapath.pid",
        fallback_pidfile: Some("r2o-datapath4.pid"),
    },
    ProcessSpec {
        name: "r2o-panel",
        comm: "r2o-panel",
        pidfile: "r2o-panel.pid",
        fallback_pidfile: None,
    },
];

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticProcMem {
    pid: c_long,
    rss: i64,
    hwm: i64,
    anon: i64,
    threads: i64,
    vm_data: i64,
    vm_swap: i64,
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticMemoryDetail {
    pid: c_long,
    at: i64,
    mono: i64,
    rss: i64,
    start_ticks: i64,
    vm: [i64; 4],
    fds: i64,
    rollup_status: c_int,
    rollup_errno: c_int,
    rollup_source: c_int,
    rollup: [i64; 5],
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticEvent {
    id: u64,
    at: i64,
    elapsed: i64,
    queued: i64,
    units: i64,
    family: u32,
    trigger: u32,
    shape: u32,
    target: [u8; 256],
    protocol: [u8; 16],
    outcome: [u8; 32],
    reason: [u8; 256],
    ip: [u8; 48],
    path: [u8; 16],
    kind: [u8; 8],
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticErrnoCount {
    error: c_int,
    count: u64,
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticMadvise {
    successes: u64,
    failures: u64,
    requested_bytes: u64,
    failed_requested_bytes: u64,
    other_errno_count: u64,
    last_errno: c_int,
    errno_hist: [D2oDiagnosticErrnoCount; 4],
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticCounts {
    boxes: u64,
    bindings: u64,
    plans: u64,
    observations: u64,
    active: u64,
    queued: u64,
    tasks: u64,
    snapshots: u64,
    http_records: u64,
    http_queued: u64,
    task_states: [u64; 15],
    snapshot_bytes: u64,
    catalog_bytes: u64,
    tracked_tcp_bytes: u64,
    tracked_quic_bytes: u64,
    tracked_tls_bytes: u64,
    workers_running: u64,
    workers_live: u64,
    workers_result_pending: u64,
    workers_join_pending: u64,
    worker_oldest_age_ms: i64,
    last_measurement_age_ms: i64,
    workers_started: u64,
    workers_joined: u64,
    worker_start_failures: u64,
    worker_join_failures: u64,
    http_failures: u64,
    http_bytes: u64,
    http_records_bytes: u64,
    http_queue_bytes: u64,
    http_failure_bytes: u64,
    http_records_limit_bytes: u64,
    http_queue_limit_bytes: u64,
    http_failure_limit_bytes: u64,
    http_failure_record_limit_bytes: u64,
    http_failure_limit_hits: u64,
    http_failure_record_limit_hits: u64,
    http_failure_alloc_failures: u64,
    http_record_limit_hits: u64,
    http_record_alloc_failures: u64,
    http_queue_limit_hits: u64,
    http_queue_alloc_failures: u64,
    worker_oldest_type: [u8; 12],
    measurement_limit: u64,
    measurement_slots: u64,
    resource_sequence: u64,
    limit_sequence: u64,
    limit_age_ms: u64,
    mem_avail_kb: u64,
    mem_total_kb: u64,
    mem_reserve_kb: u64,
    conntrack_count: u64,
    conntrack_max: u64,
    cpu_free_pct: i64,
    limiter_mask: u32,
    resources_valid: c_int,
    cpu_valid: c_int,
    mem_valid: c_int,
    conntrack_valid: c_int,
    grow_pending: c_int,
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticLimitEvent {
    at: i64,
    mono: i64,
    cpu_free_pct: i64,
    limit: u64,
    slots: u64,
    resource_seq: u64,
    limit_seq: u64,
    mem_avail: u64,
    mem_total: u64,
    mem_reserve: u64,
    ct_count: u64,
    ct_max: u64,
    mask: u32,
    flags: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticSample {
    at: i64,
    mono: i64,
    total: i64,
    available: i64,
    conntrack: i64,
    counts: D2oDiagnosticCounts,
    procs: [D2oDiagnosticProcMem; D2O_PROCESS_CAPACITY],
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticMemorySample {
    at_s: u32,
    mono_s: u32,
    rss: i32,
    vm_data: i32,
    vm_swap: i32,
    rollup: [i32; 5],
    rollup_errno: i32,
    rollup_status: u8,
    d2kc_epoch: u16,
    rss_anon_kib: i32,
    catalog_bytes: i32,
    http_bytes: i32,
    snapshot_bytes: i32,
    tracked_tcp_bytes: i32,
    tracked_quic_bytes: i32,
    tracked_tls_bytes: i32,
    tasks: u8,
    workers_live: u8,
    workers_result_pending: u8,
    workers_join_pending: u8,
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticGrowthPoint {
    mono: i64,
    rss: i32,
    accounted: i32,
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticAnomaly {
    at: u64,
    code: i32,
    rss_delta: i32,
    accounted_delta: i32,
    kind: u8,
    stage: [u8; 24],
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticRing {
    first: [D2oDiagnosticMemoryDetail; D2O_PROCESS_CAPACITY],
    latest: [D2oDiagnosticMemoryDetail; D2O_PROCESS_CAPACITY],
    events: [D2oDiagnosticEvent; EVENT_CAPACITY],
    limits: [D2oDiagnosticLimitEvent; LIMIT_CAPACITY],
    samples: [D2oDiagnosticSample; SAMPLE_CAPACITY],
    memory_history: [D2oDiagnosticMemorySample; MEMORY_HISTORY_CAPACITY],
    anomalies: [D2oDiagnosticAnomaly; ANOMALY_CAPACITY],
    growth: [D2oDiagnosticGrowthPoint; GROWTH_CAPACITY],
    madvise: D2oDiagnosticMadvise,
    ne: usize,
    nl: usize,
    ns: usize,
    nm: usize,
    na: usize,
    ng: usize,
    growth_next: usize,
    event_total: u64,
    limit_total: u64,
    sample_total: u64,
    memory_total: u64,
    anomaly_total: u64,
    write_failures: u64,
    growth_pid: i32,
    memory_pid: c_long,
    memory_start_ticks: i64,
    last_unattributed_ms: i64,
    last_ms: i64,
    d2kc_epoch: u16,
    memory_pid_seen: c_int,
    sampled: c_int,
}

fn d2o_ring_bytes() -> usize {
    size_of::<D2oDiagnosticRing>()
}

#[derive(Clone, Copy)]
struct ProcessSpec {
    name: &'static str,
    comm: &'static str,
    pidfile: &'static str,
    // При аварийном откате S99r2o поднимает раздельные процессы. Диагностика
    // должна продолжать показывать работающий IPv4-компонент, а не нули.
    fallback_pidfile: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Counts {
    pub boxes: usize,
    pub bindings: usize,
    pub plans: usize,
    pub observations: usize,
    pub active: usize,
    pub queued: usize,
    pub tasks: usize,
    pub snapshots: usize,
    pub http_records: usize,
    pub http_queued: usize,
    pub http_failures: u64,
    pub catalog_bytes: u64,
    pub snapshot_bytes: u64,
    pub http_bytes: u64,
    pub http_records_bytes: u64,
    pub http_queue_bytes: u64,
    pub http_failure_bytes: u64,
    pub http_records_limit_bytes: u64,
    pub http_queue_limit_bytes: u64,
    pub http_failure_limit_bytes: u64,
    pub http_failure_record_limit_bytes: u64,
    pub http_failure_limit_hits: u64,
    pub http_failure_record_limit_hits: u64,
    pub http_failure_alloc_failures: u64,
    pub http_record_limit_hits: u64,
    pub http_record_alloc_failures: u64,
    pub http_queue_limit_hits: u64,
    pub http_queue_alloc_failures: u64,
    pub measurement_limit: u64,
    pub measurement_slots: u64,
    pub limiter_mask: u32,
    pub grow_pending: bool,
    pub resource_sequence: u64,
    pub limit_sequence: u64,
    pub resources_valid: bool,
    pub cpu_valid: bool,
    pub cpu_free_pct: Option<u64>,
    pub mem_valid: bool,
    pub mem_avail_kb: u64,
    pub mem_total_kb: u64,
    pub mem_reserve_kb: u64,
    pub conntrack_valid: bool,
    pub conntrack_count: u64,
    pub conntrack_max: u64,
    pub tracked_tcp_bytes: u64,
    pub tracked_quic_bytes: u64,
    pub tracked_tls_bytes: u64,
    pub workers_running: u64,
    pub workers_live: u64,
    pub workers_result_pending: u64,
    pub workers_join_pending: u64,
    pub worker_oldest_age_ms: Option<u64>,
    pub last_measurement_age_ms: Option<u64>,
    pub workers_started: u64,
    pub workers_joined: u64,
    pub worker_start_failures: u64,
    pub worker_join_failures: u64,
    pub worker_oldest_type: &'static str,
}

pub struct Recorder {
    dir: PathBuf,
    run_dir: PathBuf,
    proc_dir: PathBuf,
    enabled: bool,
    started: Instant,
    checked: Option<Instant>,
    sampled: Option<Instant>,
    event_total: u64,
    sample_total: u64,
    events: VecDeque<Value>,
    samples: VecDeque<Value>,
    limit_total: u64,
    limits: VecDeque<Value>,
    last_counts: Option<Counts>,
    last_limit_change: Option<Instant>,
    memory_total: u64,
    // Кортеж: (абсолютное время at, абсолютное mono_ms, значения строки без времени).
    memory_history: VecDeque<(u64, u64, Vec<Value>)>,
    anomaly_total: u64,
    anomalies: VecDeque<Value>,
    write_failures: u64,
    growth: VecDeque<(u64, i64, i64)>,
    last_unattributed: Option<Instant>,
    memory_pid: Option<u64>,
    memory_start_ticks: Option<u64>,
    memory_epoch: u64,
    first_details: HashMap<String, Value>,
    madvise: MadviseStats,
}

impl Recorder {
    pub fn new(dir: PathBuf, run_dir: PathBuf) -> Self {
        Self {
            dir,
            run_dir,
            proc_dir: PathBuf::from("/proc"),
            enabled: false,
            started: Instant::now(),
            checked: None,
            sampled: None,
            event_total: 0,
            sample_total: 0,
            events: VecDeque::with_capacity(EVENT_CAPACITY),
            samples: VecDeque::with_capacity(SAMPLE_CAPACITY),
            limit_total: 0,
            limits: VecDeque::with_capacity(LIMIT_CAPACITY),
            last_counts: None,
            last_limit_change: None,
            memory_total: 0,
            memory_history: VecDeque::with_capacity(MEMORY_HISTORY_CAPACITY),
            anomaly_total: 0,
            anomalies: VecDeque::with_capacity(ANOMALY_CAPACITY),
            write_failures: 0,
            growth: VecDeque::with_capacity(GROWTH_CAPACITY),
            last_unattributed: None,
            memory_pid: None,
            memory_start_ticks: None,
            memory_epoch: 0,
            first_details: HashMap::new(),
            madvise: MadviseStats::default(),
        }
    }

    pub fn set_madvise(&mut self, stats: MadviseStats) {
        self.madvise = stats;
    }

    pub fn madvise_stats(&self) -> MadviseStats {
        self.madvise
    }

    pub fn reset_madvise(&mut self) {
        self.madvise = MadviseStats::default();
    }

    pub fn record(&mut self, mut event: Value) {
        if !self.enabled {
            return;
        }
        let Some(object) = event.as_object_mut() else {
            return;
        };
        self.event_total = self.event_total.saturating_add(1);
        if !object.get("id").is_some_and(Value::is_u64) {
            object.insert("id".into(), json!(self.event_total));
        }
        object.insert("at".into(), json!(unix_seconds()));
        for (key, limit) in [
            ("target", 255),
            ("protocol", 15),
            ("outcome", 31),
            // C `event.reason[256]`: предел 255 байт, как у остальных строк.
            ("reason", 255),
            ("ip", 47),
            ("path", 15),
            ("kind", 7),
        ] {
            let value = object
                .get_mut(key)
                .and_then(|value| value.as_str())
                .map(str::to_owned)
                .unwrap_or_default();
            object.insert(key.into(), json!(d2o_event_text(value, limit)));
        }
        if self.events.len() == EVENT_CAPACITY {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn tick(&mut self, collect_counts: impl FnOnce() -> Counts) {
        let now = Instant::now();
        if self
            .checked
            .is_some_and(|last| now.saturating_duration_since(last) < Duration::from_secs(1))
        {
            return;
        }
        self.checked = Some(now);
        let enabled = diagnostics_enabled(&self.dir);
        if !enabled {
            memory_enable(false);
            if self.enabled {
                self.events.clear();
                self.samples.clear();
                self.limits.clear();
                self.memory_history.clear();
                self.anomalies.clear();
                self.growth.clear();
                self.event_total = 0;
                self.sample_total = 0;
                self.limit_total = 0;
                self.memory_total = 0;
                self.anomaly_total = 0;
                self.write_failures = 0;
                self.last_counts = None;
                self.last_limit_change = None;
                self.last_unattributed = None;
                self.memory_pid = None;
                self.memory_start_ticks = None;
                self.memory_epoch = 0;
                self.first_details.clear();
                if ensure_diagnostics_dir(&self.dir, true) {
                    for name in ["enabled", "report.json", "report.new"] {
                        let _ = fs::remove_file(self.dir.join(name));
                    }
                }
            }
            self.enabled = false;
            self.sampled = None;
            return;
        }
        if !self.enabled {
            self.enabled = true;
            self.sampled = None;
            memory_enable(true);
        }
        if self
            .sampled
            .is_some_and(|last| now.saturating_duration_since(last) < SAMPLE_INTERVAL)
        {
            return;
        }
        let counts = collect_counts();
        self.sampled = Some(now);
        self.sample_total = self.sample_total.saturating_add(1);
        let at = unix_seconds();
        let mono_ms = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;

        // D2O пишет переход AIMD только при смене маски/лимита, а не каждый снимок.
        let limit_changed = self.last_counts.is_none_or(|previous| {
            previous.limiter_mask != counts.limiter_mask
                || previous.measurement_limit != counts.measurement_limit
                || previous.measurement_slots != counts.measurement_slots
                || previous.resources_valid != counts.resources_valid
                || previous.cpu_valid != counts.cpu_valid
                || previous.mem_valid != counts.mem_valid
                || previous.conntrack_valid != counts.conntrack_valid
        });
        if limit_changed {
            self.limit_total = self.limit_total.saturating_add(1);
            let event = limit_event_json(at, mono_ms, &counts);
            if self.limits.len() == LIMIT_CAPACITY {
                self.limits.pop_front();
            }
            self.limits.push_back(event);
            self.last_limit_change = Some(now);
        }
        self.last_counts = Some(counts);

        let processes = process_memory(&self.proc_dir, &self.run_dir);
        let mut details = Vec::with_capacity(processes.len());
        for process in &processes {
            if process["pid"].as_u64().unwrap_or(0) != 0 {
                let name = process["name"].as_str().unwrap_or_default();
                let detail = process_detail(process, at, mono_ms, &self.proc_dir);
                let previous = self.first_details.get(name);
                if previous.is_none_or(|old| {
                    old["pid"] != detail["pid"]
                        || detail["start_ticks"]
                            .as_u64()
                            .is_some_and(|ticks| old["start_ticks"].as_u64() != Some(ticks))
                }) {
                    self.first_details.insert(name.to_owned(), detail.clone());
                }
                details.push(json!({
                    "name": name,
                    "first": self.first_details.get(name),
                    "latest": detail,
                }));
            } else {
                let name = process["name"].as_str().unwrap_or_default();
                details
                    .push(json!({"name":name,"first":self.first_details.get(name),"latest":null}));
            }
        }

        // Строка истории памяти по объединённому контроллеру.
        let primary = processes
            .iter()
            .find(|process| process["name"] == "r2o-controller")
            .or_else(|| processes.first());
        let primary_pid = primary
            .and_then(|process| process["pid"].as_u64())
            .unwrap_or(0);
        let primary_start_ticks = details
            .iter()
            .find(|detail| detail["name"] == "r2o-controller")
            .and_then(|detail| detail["latest"]["start_ticks"].as_u64());
        if primary_pid != 0
            && (self.memory_pid != Some(primary_pid)
                || primary_start_ticks.is_some()
                    && self.memory_start_ticks.is_some()
                    && self.memory_start_ticks != primary_start_ticks)
        {
            self.memory_epoch = self.memory_epoch.saturating_add(1);
            self.memory_pid = Some(primary_pid);
            self.memory_start_ticks = primary_start_ticks;
        }
        let field_i64 = |process: Option<&Value>, key: &str| {
            process
                .and_then(|process| process.get(key))
                .and_then(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
                })
        };
        let primary_name = primary
            .and_then(|process| process["name"].as_str())
            .unwrap_or_default();
        let primary_detail = details
            .iter()
            .find(|detail| detail["name"].as_str() == Some(primary_name))
            .map(|detail| &detail["latest"]);
        let detail_i64 = |key: &str| {
            primary_detail
                .and_then(|detail| detail.get(key))
                .and_then(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
                })
        };
        let rollup_status = rollup_status_code(
            primary_detail
                .and_then(|detail| detail["smaps_rollup_status"].as_str())
                .unwrap_or("not-read"),
        );
        let rollup_errno = detail_i64("smaps_rollup_errno").filter(|error| *error != 0);
        let rollup_value = |key: &str| {
            primary_detail
                .and_then(|detail| detail.get("smaps_rollup"))
                .and_then(|rollup| rollup.get(key))
                .and_then(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
                })
                .unwrap_or(-1)
        };
        let rollup = if rollup_status != ROLLUP_OK && rollup_value("rss_kib") < 0 {
            Value::Null
        } else {
            json!([
                compact_kib(rollup_value("rss_kib")),
                compact_kib(rollup_value("pss_kib")),
                compact_kib(rollup_value("anonymous_kib")),
                compact_kib(rollup_value("private_dirty_kib")),
                compact_kib(rollup_value("swap_kib")),
            ])
        };
        let rss_kib = compact_kib(field_i64(primary, "rss_kib").unwrap_or(-1));
        let vm_data_kib = compact_kib(field_i64(primary, "vm_data_kib").unwrap_or(-1));
        let vm_swap_kib = compact_kib(field_i64(primary, "vm_swap_kib").unwrap_or(-1));
        let rss_anon_kib = compact_kib(field_i64(primary, "anon_kib").unwrap_or(-1));
        let accounted_bytes = counts
            .tracked_tcp_bytes
            .saturating_add(counts.tracked_quic_bytes)
            .saturating_add(counts.tracked_tls_bytes)
            .saturating_add(counts.catalog_bytes)
            .saturating_add(counts.http_bytes)
            .saturating_add(counts.snapshot_bytes);
        let memory_tail = vec![
            json!(rss_kib),
            json!(vm_data_kib),
            json!(vm_swap_kib),
            json!(rollup_status),
            json!(rollup_errno),
            json!(rollup),
            json!(rss_anon_kib),
            json!(compact_bytes(counts.catalog_bytes)),
            json!(compact_bytes(counts.http_bytes)),
            json!(compact_bytes(counts.snapshot_bytes)),
            json!(compact_bytes(counts.tracked_tcp_bytes)),
            json!(compact_bytes(counts.tracked_quic_bytes)),
            json!(compact_bytes(counts.tracked_tls_bytes)),
            json!(compact_count(counts.tasks as u64)),
            json!(compact_count(counts.workers_live)),
            json!(compact_count(counts.workers_result_pending)),
            json!(compact_count(counts.workers_join_pending)),
            json!(self.memory_epoch),
        ];
        self.memory_total = self.memory_total.saturating_add(1);
        if self.memory_history.len() == MEMORY_HISTORY_CAPACITY {
            self.memory_history.pop_front();
        }
        self.memory_history.push_back((at, mono_ms, memory_tail));

        // Критерий D2O: устойчивый рост RSS без сопоставимого роста учтённых объектов.
        if primary_pid != 0
            && let Some(rss_kib) = compact_kib(field_i64(primary, "rss_kib").unwrap_or(-1))
            && rss_kib > 0
            && let Some(accounted_kib) = compact_bytes_kib(accounted_bytes)
        {
            self.growth
                .push_back((mono_ms, i64::from(rss_kib), i64::from(accounted_kib)));
            while self.growth.len() > GROWTH_CAPACITY {
                self.growth.pop_front();
            }
            if self.growth.len() == GROWTH_CAPACITY {
                let points: Vec<(u64, i64, i64)> = self.growth.iter().copied().collect();
                let span_ms = points
                    .last()
                    .map(|last| last.0)
                    .unwrap_or(0)
                    .saturating_sub(points.first().map(|first| first.0).unwrap_or(0));
                let rising = points
                    .windows(2)
                    .filter(|pair| pair[1].1 > pair[0].1)
                    .count();
                let rss_delta = points.last().map(|last| last.1).unwrap_or(0)
                    - points.first().map(|first| first.1).unwrap_or(0);
                let accounted_delta = points.last().map(|last| last.2).unwrap_or(0)
                    - points.first().map(|first| first.2).unwrap_or(0);
                let cooldown_ok = self.last_unattributed.is_none_or(|last| {
                    now.saturating_duration_since(last) >= Duration::from_secs(30 * 60)
                });
                if span_ms >= 9 * 60_000
                    && rising >= 7
                    && rss_delta >= 1024
                    && accounted_delta < rss_delta / 4
                    && cooldown_ok
                {
                    self.record_anomaly(json!({
                        "kind": "unattributed-rss-growth",
                        "at": at,
                        "error_code": null,
                        "stage": "",
                        "rss_delta_kib": rss_delta,
                        "accounted_delta_kib": accounted_delta,
                        "window_samples": GROWTH_CAPACITY,
                    }));
                    self.last_unattributed = Some(now);
                }
            }
        }

        let conntrack_count =
            read_number(&self.proc_dir.join("sys/net/netfilter/nf_conntrack_count"));
        let limit_age_ms = self.last_limit_change.map(|started| {
            now.saturating_duration_since(started)
                .as_millis()
                .min(u64::MAX as u128) as u64
        });
        let sample = json!({
            "at": at,
            "mono_ms": mono_ms,
            "mem_total_kib": meminfo(&self.proc_dir, "MemTotal:"),
            "mem_available_kib": meminfo(&self.proc_dir, "MemAvailable:"),
            "system_conntrack": conntrack_count,
            "datapath_flows": null,
            "http_records": counts.http_records,
            "http_queued": counts.http_queued,
            "boxes": counts.boxes,
            "bindings": counts.bindings,
            "plans": counts.plans,
            "observations": counts.observations,
            "active": counts.active,
            "queued": counts.queued,
            "tasks": counts.tasks,
            "snapshots": counts.snapshots,
            "snapshot_bytes": counts.snapshot_bytes,
            "catalog_bytes": counts.catalog_bytes,
            "workers_running": counts.workers_running,
            "workers_live": counts.workers_live,
            "workers_result_pending": counts.workers_result_pending,
            "workers_join_pending": counts.workers_join_pending,
            "worker_oldest_age_ms": counts.worker_oldest_age_ms,
            "worker_oldest_type": counts.worker_oldest_type,
            "last_measurement_age_ms": counts.last_measurement_age_ms,
            "workers_started": counts.workers_started,
            "workers_joined": counts.workers_joined,
            "worker_start_failures": counts.worker_start_failures,
            "worker_join_failures": counts.worker_join_failures,
            "http_failures": counts.http_failures,
            "http_bytes": counts.http_bytes,
            "http_records_bytes": counts.http_records_bytes,
            "http_queue_bytes": counts.http_queue_bytes,
            "http_failure_bytes": counts.http_failure_bytes,
            "http_failure_limit_hits": counts.http_failure_limit_hits,
            "http_failure_record_limit_hits": counts.http_failure_record_limit_hits,
            "http_failure_alloc_failures": counts.http_failure_alloc_failures,
            "http_record_limit_hits": counts.http_record_limit_hits,
            "http_record_alloc_failures": counts.http_record_alloc_failures,
            "http_queue_limit_hits": counts.http_queue_limit_hits,
            "http_queue_alloc_failures": counts.http_queue_alloc_failures,
            "measurement_limit": counts.measurement_limit,
            "measurement_slots": counts.measurement_slots,
            "resources_valid": counts.resources_valid,
            "cpu_valid": counts.cpu_valid,
            "cpu_free_pct": counts.cpu_free_pct,
            "mem_valid": counts.mem_valid,
            "scheduler_mem_avail_kib": counts.mem_valid.then_some(counts.mem_avail_kb),
            "scheduler_mem_total_kib": counts.mem_valid.then_some(counts.mem_total_kb),
            "scheduler_mem_reserve_kib": counts.mem_valid.then_some(counts.mem_reserve_kb),
            "conntrack_valid": counts.conntrack_valid,
            "conntrack_count": counts.conntrack_valid.then_some(counts.conntrack_count),
            "conntrack_max": counts.conntrack_valid.then_some(counts.conntrack_max),
            "limiter_mask": counts.limiter_mask,
            "grow_pending": counts.grow_pending,
            "resource_sequence": counts.resource_sequence,
            "limit_sequence": counts.limit_sequence,
            "limit_age_ms": limit_age_ms,
            "task_states": task_states_json(&counts),
            "limit_reason": limit_reason_values(&counts),
            "processes": processes,
        });
        if self.samples.len() == SAMPLE_CAPACITY {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);

        let memory_base = self
            .memory_history
            .front()
            .map(|(row_at, row_mono, _)| (*row_at, *row_mono));
        let memory_rows: Vec<Value> = self
            .memory_history
            .iter()
            .map(|(row_at, row_mono, tail)| {
                let (base_at, base_mono) = memory_base.unwrap_or((*row_at, *row_mono));
                let mut row = Vec::with_capacity(2 + tail.len());
                row.push(json!(row_at.saturating_sub(base_at)));
                row.push(json!(row_mono.saturating_sub(base_mono)));
                row.extend(tail.iter().cloned());
                Value::Array(row)
            })
            .collect();
        let memory_time_base = memory_base
            .map(|(base_at, base_mono)| json!([base_at, base_mono]))
            .unwrap_or_else(|| json!([null, null]));
        let report = json!({
            "schema": 1,
            "enabled": true,
            "controller_pid": std::process::id(),
            "release": option_env!("R2O_RELEASE_ID").unwrap_or("dev"),
            "ring_bytes": d2o_ring_bytes(),
            "event_capacity": EVENT_CAPACITY,
            "limit_transition_capacity": LIMIT_CAPACITY,
            "sample_capacity": SAMPLE_CAPACITY,
            "sample_interval_ms": SAMPLE_INTERVAL.as_millis(),
            "memory_history_capacity": MEMORY_HISTORY_CAPACITY,
            "memory_history_interval_ms": SAMPLE_INTERVAL.as_millis(),
            "events_overwritten": self.event_total.saturating_sub(self.events.len() as u64),
            "limit_transitions_overwritten": self.limit_total.saturating_sub(self.limits.len() as u64),
            "samples_overwritten": self.sample_total.saturating_sub(self.samples.len() as u64),
            "memory_history_overwritten": self.memory_total.saturating_sub(self.memory_history.len() as u64),
            "http_storage_limits": {
                "records_bytes": counts.http_records_limit_bytes,
                "queue_bytes": counts.http_queue_limit_bytes,
                "failures_bytes": counts.http_failure_limit_bytes,
                "failure_record_bytes": counts.http_failure_record_limit_bytes,
            },
            "memory_tracking": memory_tracking_json(),
            "madvise": madvise_json(&self.madvise),
            "anomalies_overwritten": self.anomaly_total.saturating_sub(self.anomalies.len() as u64),
            "diagnostic_write_failures": self.write_failures,
            "anomalies": self.anomalies,
            "events": self.events,
            "limit_transitions": self.limits,
            "memory_history": {
                "capacity": MEMORY_HISTORY_CAPACITY,
                "sample_interval_ms": SAMPLE_INTERVAL.as_millis(),
                "time_base": memory_time_base,
                "smaps_rollup_status_codes": ["not-read","unavailable","ok","parse-error","unsupported"],
                "fields": MEMORY_HISTORY_FIELDS,
                "samples": memory_rows,
            },
            "samples": self.samples,
            "memory_details": details,
        });
        self.write_report(&report);
    }

    fn record_anomaly(&mut self, anomaly: Value) {
        self.anomaly_total = self.anomaly_total.saturating_add(1);
        if self.anomalies.len() == ANOMALY_CAPACITY {
            self.anomalies.pop_front();
        }
        self.anomalies.push_back(anomaly);
    }

    fn last_errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn record_write_error(&mut self, stage: &'static str, error_code: i32) {
        self.write_failures = self.write_failures.saturating_add(1);
        let anomaly = json!({
            "kind": "diagnostic-json-write-error",
            "at": unix_seconds(),
            "error_code": error_code,
            "stage": stage,
            "rss_delta_kib": null,
            "accounted_delta_kib": null,
            "window_samples": 0,
        });
        self.record_anomaly(anomaly);
    }

    fn write_report(&mut self, report: &Value) {
        if !ensure_diagnostics_dir(&self.dir, true) {
            let error = Self::last_errno();
            self.record_write_error("path", error);
            return;
        }
        let bytes = match serde_json::to_vec(report) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.record_write_error("serialize", 0);
                return;
            }
        };
        if bytes.is_empty() || !diagnostics_enabled(&self.dir) {
            return;
        }
        if bytes.len() > REPORT_MAX {
            self.record_write_error("size-limit", libc::EFBIG);
            return;
        }
        let tmp = self.dir.join("report.new");
        let path = self.dir.join("report.json");
        if let Err(error) = fs::remove_file(&tmp)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            self.record_write_error("remove-old-temp", error.raw_os_error().unwrap_or(0));
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let Ok(mut file) = options.open(&tmp) else {
            let error = Self::last_errno();
            self.record_write_error("open-temp", error);
            return;
        };
        let write_result = file.write_all(&bytes).and_then(|()| file.sync_all());
        let write_error = write_result
            .as_ref()
            .err()
            .and_then(std::io::Error::raw_os_error)
            .unwrap_or(0);
        let write_failed = write_result.is_err();
        if write_failed
            || fs::metadata(&tmp).map_or(true, |metadata| metadata.len() as usize > REPORT_MAX)
            || !diagnostics_enabled(&self.dir)
        {
            let _ = fs::remove_file(&tmp);
            if write_failed {
                self.record_write_error("flush-close", write_error);
            }
            return;
        }
        drop(file);
        if let Err(error) = fs::rename(&tmp, &path) {
            let code = error.raw_os_error().unwrap_or(0);
            let _ = fs::remove_file(&tmp);
            self.record_write_error("rename", code);
        }
    }
}

/// C `compact_kib`: отрицательное или слишком большое значение — null.
fn compact_kib(value: i64) -> Option<i32> {
    (0..=i64::from(i32::MAX))
        .contains(&value)
        .then_some(value as i32)
}

/// C `compact_bytes_kib`: байты в KiB с округлением вверх.
fn compact_bytes_kib(bytes: u64) -> Option<i32> {
    let kib = bytes / 1024 + u64::from(bytes % 1024 != 0);
    (kib <= i32::MAX as u64).then_some(kib as i32)
}

/// C `compact_bytes`: байты в i32 или null при переполнении.
fn compact_bytes(bytes: u64) -> Option<i32> {
    (bytes <= i32::MAX as u64).then_some(bytes as i32)
}

/// C `compact_count`: счётчик в u8 с насыщением.
fn compact_count(count: u64) -> u8 {
    count.min(u64::from(u8::MAX)) as u8
}

/// C `value(line,key)`: число после ключа в /proc; отрицательное — None.
fn proc_field(line: &str, key: &str) -> Option<i64> {
    let rest = line.strip_prefix(key)?;
    // C `value` принимает ключ с двоеточием; допускаем и форму без него.
    let rest = rest.strip_prefix(':').unwrap_or(rest);
    let value = rest.split_whitespace().next()?.parse::<i64>().ok()?;
    (value >= 0).then_some(value)
}

fn limit_reason_values(counts: &Counts) -> Vec<&'static str> {
    if !counts.resources_valid {
        return vec!["resource-data-unavailable"];
    }
    if counts.limiter_mask == 0 {
        return vec!["no-current-resource-limit"];
    }
    let mut reasons = Vec::new();
    if counts.limiter_mask & 1 != 0 {
        reasons.push("cpu");
    }
    if counts.limiter_mask & 2 != 0 {
        reasons.push("memory");
    }
    if counts.limiter_mask & 4 != 0 {
        reasons.push("conntrack");
    }
    if counts.limiter_mask & 8 != 0 {
        reasons.push("slots");
    }
    reasons
}

fn limit_event_json(at: u64, mono_ms: u64, counts: &Counts) -> Value {
    json!({
        "at": at,
        "mono_ms": mono_ms,
        "measurement_limit": counts.measurement_limit,
        "measurement_slots": counts.measurement_slots,
        "limiter_mask": counts.limiter_mask,
        "grow_pending": counts.grow_pending,
        "resource_sequence": counts.resource_sequence,
        "limit_sequence": counts.limit_sequence,
        "resources_valid": counts.resources_valid,
        "cpu_valid": counts.cpu_valid,
        "cpu_free_pct": counts.cpu_free_pct,
        "mem_valid": counts.mem_valid,
        "mem_available_kib": counts.mem_valid.then_some(counts.mem_avail_kb),
        "mem_total_kib": counts.mem_valid.then_some(counts.mem_total_kb),
        "mem_reserve_kib": counts.mem_valid.then_some(counts.mem_reserve_kb),
        "conntrack_valid": counts.conntrack_valid,
        "conntrack_count": counts.conntrack_valid.then_some(counts.conntrack_count),
        "conntrack_max": counts.conntrack_valid.then_some(counts.conntrack_max),
        "limit_reason": limit_reason_values(counts),
    })
}

fn task_states_json(counts: &Counts) -> Value {
    let mut states = serde_json::Map::new();
    for name in TASK_STATE_NAMES {
        states.insert(name.to_owned(), json!(0));
    }
    states.insert("queued".into(), json!(counts.queued));
    states.insert("planning".into(), json!(counts.active));
    states.insert(
        "free".into(),
        json!(
            counts
                .tasks
                .saturating_sub(counts.active.saturating_add(counts.queued))
        ),
    );
    Value::Object(states)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn truncate_utf8(mut value: String, max_bytes: usize) -> String {
    if value.len() > max_bytes {
        let mut end = max_bytes;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    value
}

fn d2o_event_text(value: String, max_bytes: usize) -> String {
    let value = value.split('\0').next().unwrap_or_default();
    truncate_utf8(
        value
            .chars()
            .map(|character| {
                if character < ' ' && character != '\n' {
                    '?'
                } else {
                    character
                }
            })
            .collect(),
        max_bytes,
    )
}

fn ensure_diagnostics_dir(dir: &Path, create: bool) -> bool {
    if create && !dir.exists() {
        if let Err(error) = fs::create_dir(dir) {
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return false;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).is_err() {
                return false;
            }
        }
    }
    let Ok(metadata) = fs::symlink_metadata(dir) else {
        return false;
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        metadata.uid() == unsafe { libc::geteuid() } && metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn diagnostics_enabled(dir: &Path) -> bool {
    if !ensure_diagnostics_dir(dir, false) {
        return false;
    }
    let marker = dir.join("enabled");
    let Ok(metadata) = fs::symlink_metadata(marker) else {
        return false;
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        metadata.uid() == unsafe { libc::geteuid() } && metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn read_number(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn meminfo(proc_dir: &Path, key: &str) -> Option<u64> {
    fs::read_to_string(proc_dir.join("meminfo"))
        .ok()?
        .lines()
        .find_map(|line| {
            let (name, rest) = line.split_once(':')?;
            (name == key.trim_end_matches(':'))
                .then(|| rest.split_whitespace().next()?.parse().ok())
                .flatten()
        })
}

fn process_memory(proc_dir: &Path, run_dir: &Path) -> Vec<Value> {
    PROCESS_SPECS
        .iter()
        .map(|spec| {
            let read_pid = |pidfile: &str| {
                fs::read_to_string(run_dir.join(pidfile))
                    .ok()
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .filter(|pid| *pid > 0 && *pid <= i32::MAX as u64)
            };
            let pid = read_pid(spec.pidfile)
                .or_else(|| spec.fallback_pidfile.and_then(|pidfile| read_pid(pidfile)));
            let Some(pid) = pid else {
                return empty_process(spec.name);
            };
            let base = proc_dir.join(pid.to_string());
            // Ядро усекает comm до 15 символов: r2o-controller-linux…
            // превращается в r2o-controller-. Проверяем префикс, иначе
            // диагностика показывала pid=0 и нулевой RSS для всех процессов.
            let comm_matches = fs::read_to_string(base.join("comm")).is_ok_and(|name| {
                let name = name.trim_end_matches(['\r', '\n']);
                name == spec.comm || name.starts_with(spec.comm)
            });
            if !comm_matches {
                return empty_process(spec.name);
            }
            let status = fs::read_to_string(base.join("status")).unwrap_or_default();
            let field = |key: &str| {
                status
                    .lines()
                    .find_map(|line| proc_field(line, key))
                    .map(|value| value as u64)
            };
            json!({
                "name":spec.name,"pid":pid,"rss_kib":field("VmRSS"),"hwm_kib":field("VmHWM"),
                "anon_kib":field("RssAnon"),"threads":field("Threads"),
                "vm_data_kib":field("VmData"),"vm_swap_kib":field("VmSwap")
            })
        })
        .collect()
}

fn empty_process(name: &str) -> Value {
    json!({"name":name,"pid":0,"rss_kib":null,"hwm_kib":null,"anon_kib":null,"threads":null,
        "vm_data_kib":null,"vm_swap_kib":null})
}

fn process_detail(process: &Value, at: u64, mono_ms: u64, proc_dir: &Path) -> Value {
    let pid = process["pid"].as_u64().unwrap_or(0);
    let base = proc_dir.join(pid.to_string());
    let status = fs::read_to_string(base.join("status")).unwrap_or_default();
    let field = |key: &str| {
        status
            .lines()
            .find_map(|line| proc_field(line, key))
            .map(|value| value as u64)
    };
    let start_ticks = fs::read_to_string(base.join("stat")).ok().and_then(|stat| {
        let close = stat.rfind(')')?;
        stat[close + 1..]
            .split_whitespace()
            .nth(19)?
            .parse::<u64>()
            .ok()
    });
    let fd_count = read_fd_count(&base.join("fd"));
    // D2O читает только smaps_rollup; полный smaps не обходит даже как
    // fallback, потому что это дорого и не требуется для отчёта.
    let (rollup_status, rollup_source, rollup_errno, rollup) = read_smaps_rollup(&base);
    json!({
        "pid":pid,"at":at,"mono_ms":mono_ms,"rss_kib":process["rss_kib"],
        "start_ticks":start_ticks,"vm_size_kib":field("VmSize"),"vm_data_kib":field("VmData"),
        "vm_stack_kib":field("VmStk"),"vm_swap_kib":field("VmSwap"),"fd_count":fd_count,
        "smaps_rollup_status":rollup_status,
        "smaps_rollup_source":rollup_source,
        "smaps_rollup_errno":rollup_errno,
        "smaps_rollup":rollup,
        "smaps_status":"not-read",
        "smaps_errno":null,
        "smaps":null
    })
}

/// Повторяет семантику D2O `read_detail`: отсутствие smaps_rollup при
/// существующем каталоге процесса — ожидаемое ограничение ядра
/// (unsupported без errno), а не ошибка чтения.
const ROLLUP_UNAVAILABLE: u8 = 1;
const ROLLUP_OK: u8 = 2;
const ROLLUP_PARSE_ERROR: u8 = 3;
const ROLLUP_UNSUPPORTED: u8 = 4;

/// C `proc_pid_dir_present`: каталог `/proc/<pid>` существует.
fn proc_pid_dir_present(base: &Path) -> bool {
    base.is_dir()
}

/// C `optional_proc_status`: ENOENT при живом pid — unsupported без errno,
/// иначе unavailable с errno.
fn optional_proc_status(error: &std::io::Error, pid_dir_present: bool) -> (u8, Option<i32>) {
    if error.kind() == std::io::ErrorKind::NotFound && pid_dir_present {
        (ROLLUP_UNSUPPORTED, None)
    } else {
        (ROLLUP_UNAVAILABLE, error.raw_os_error())
    }
}

/// C `read_status`: код статуса smaps_rollup в строку.
fn rollup_status_text(code: u8) -> &'static str {
    match code {
        ROLLUP_UNAVAILABLE => "unavailable",
        ROLLUP_OK => "ok",
        ROLLUP_PARSE_ERROR => "parse-error",
        ROLLUP_UNSUPPORTED => "unsupported",
        _ => "not-read",
    }
}

/// Обратное отображение строки статуса в код C `read_status`.
fn rollup_status_code(text: &str) -> u8 {
    match text {
        "unavailable" => ROLLUP_UNAVAILABLE,
        "ok" => ROLLUP_OK,
        "parse-error" => ROLLUP_PARSE_ERROR,
        "unsupported" => ROLLUP_UNSUPPORTED,
        _ => 0,
    }
}

fn read_smaps_rollup(base: &Path) -> (&'static str, &'static str, Option<i32>, Option<Value>) {
    let path = base.join("smaps_rollup");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            let (code, errno) = optional_proc_status(&error, proc_pid_dir_present(base));
            return (rollup_status_text(code), "unavailable", errno, None);
        }
    };
    let mut values = [None; 5];
    let keys = ["Rss", "Pss", "Anonymous", "Private_Dirty", "Swap"];
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(index) = keys.iter().position(|key| *key == name) else {
            continue;
        };
        values[index] = rest
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok());
    }
    if values.iter().any(Option::is_none) {
        return (
            rollup_status_text(ROLLUP_PARSE_ERROR),
            "unavailable",
            None,
            None,
        );
    }
    let value = json!({
        "rss_kib": values[0],
        "pss_kib": values[1],
        "anonymous_kib": values[2],
        "private_dirty_kib": values[3],
        "swap_kib": values[4],
    });
    (
        rollup_status_text(ROLLUP_OK),
        "smaps_rollup",
        None,
        Some(value),
    )
}

fn read_fd_count(path: &Path) -> Option<u64> {
    let entries = fs::read_dir(path).ok()?;
    let mut count = 0_u64;
    for entry in entries {
        let entry = entry.ok()?;
        if !entry.file_name().to_string_lossy().starts_with('.') {
            count = count.checked_add(1)?;
        }
    }
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::{
        Counts, EVENT_CAPACITY, MADVISE_ERRNO_SLOTS, MEMORY_SITE_COUNT, MadviseErrno, MadviseStats,
        Recorder, compact_bytes, compact_bytes_kib, compact_count, compact_kib, d2o_ring_bytes,
        limit_event_json, limit_reason_values, madvise_json, memory_acquire, memory_active,
        memory_alloc_failure, memory_enable, memory_release, memory_snapshot, memory_tracking_json,
        optional_proc_status, proc_field, proc_pid_dir_present, read_smaps_rollup,
        rollup_status_text, tracked_memory_bytes,
    };
    use serde_json::json;
    use std::fs::{self, OpenOptions};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static MEMORY_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    #[test]
    fn madvise_get_and_reset_match_c() {
        let mut recorder = Recorder::new(std::env::temp_dir(), std::env::temp_dir());
        let mut stats = MadviseStats::default();
        stats.successes = 3;
        stats.failures = 2;
        stats.requested_bytes = 4096;
        stats.failed_requested_bytes = 512;
        stats.last_errno = libc::EINVAL;
        stats.other_errno_count = 1;
        stats.errno_hist[0] = MadviseErrno {
            error: libc::EINVAL,
            count: 1,
        };
        recorder.set_madvise(stats);
        assert_eq!(recorder.madvise_stats(), stats);
        recorder.reset_madvise();
        assert_eq!(recorder.madvise_stats(), MadviseStats::default());
    }

    #[test]
    fn memory_tracking_and_madvise_json_match_d2o_shape() {
        let _guard = MEMORY_TEST_LOCK.lock().unwrap();
        memory_enable(true);
        let tracked = memory_acquire(2, 77);
        let tracking = memory_tracking_json();
        assert_eq!(tracking["enabled"], true);
        let sites = tracking["sites"].as_array().unwrap();
        assert_eq!(sites.len(), 6);
        assert_eq!(sites[2]["id"], "tls13.session");
        assert_eq!(sites[2]["location"], "core/tls13.c:tls_connect_internal");
        assert!(sites[2]["live_bytes"].as_u64().unwrap() >= 77);
        assert!(sites[2]["peak_bytes"].as_u64().unwrap() >= 77);
        assert_eq!(
            tracking["coverage"],
            "учитываются объекты, выделенные при включённом сборе; уже существующие объекты задним числом не учитываются"
        );
        for site in sites {
            for key in [
                "id",
                "name",
                "location",
                "live_bytes",
                "peak_bytes",
                "live_objects",
                "created",
                "destroyed",
                "alloc_failures",
            ] {
                assert!(site.get(key).is_some(), "memory site missing {key}");
            }
        }
        assert!(sites[2]["live_objects"].as_u64().unwrap() >= 1);
        assert!(sites[2]["created"].as_u64().unwrap() >= 1);
        memory_release(2, 77, tracked);
        memory_enable(false);

        let mut stats = MadviseStats {
            successes: 3,
            failures: 2,
            requested_bytes: 1000,
            failed_requested_bytes: 500,
            last_errno: 0,
            other_errno_count: 1,
            errno_hist: [MadviseErrno::default(); MADVISE_ERRNO_SLOTS],
        };
        let madvise = madvise_json(&stats);
        assert_eq!(madvise["successes"], 3);
        assert_eq!(madvise["failures"], 2);
        assert_eq!(madvise["requested_bytes"], 1000);
        assert_eq!(madvise["failed_requested_bytes"], 500);
        assert_eq!(madvise["other_errno_count"], 1);
        assert!(madvise["last_errno"].is_null());
        assert_eq!(madvise["errno"].as_array().unwrap().len(), 0);

        stats.last_errno = libc::EINVAL;
        stats.errno_hist[0] = MadviseErrno {
            error: libc::EINVAL,
            count: 1,
        };
        stats.errno_hist[1] = MadviseErrno {
            error: libc::EACCES,
            count: 2,
        };
        let madvise = madvise_json(&stats);
        assert_eq!(madvise["last_errno"], json!(libc::EINVAL));
        let errno = madvise["errno"].as_array().unwrap();
        assert_eq!(errno.len(), 2);
        assert_eq!(errno[0]["code"], json!(libc::EINVAL));
        assert_eq!(errno[0]["count"], json!(1));
        assert_eq!(errno[1]["code"], json!(libc::EACCES));
        assert_eq!(errno[1]["count"], json!(2));
    }

    #[cfg(unix)]
    #[test]
    fn report_anomalies_match_c_shape() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let dir = std::env::temp_dir().join(format!("r2o-diag-anomalies-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("enabled"))
            .unwrap();
        let mut recorder = Recorder::new(dir.clone(), dir.join("run"));
        recorder.record_write_error("open-temp", libc::EACCES);
        recorder.record_write_error("rename", libc::ENOENT);
        let report = json!({
            "diagnostic_write_failures": recorder.write_failures,
            "anomalies_overwritten": recorder.anomaly_total.saturating_sub(recorder.anomalies.len() as u64),
            "anomalies": recorder.anomalies.clone(),
        });
        recorder.write_report(&report);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("report.json")).unwrap()).unwrap();
        assert_eq!(report["diagnostic_write_failures"], json!(2));
        assert_eq!(report["anomalies_overwritten"], json!(0));
        let anomalies = report["anomalies"].as_array().unwrap();
        assert_eq!(anomalies.len(), 2);
        assert_eq!(anomalies[0]["kind"], "diagnostic-json-write-error");
        assert_eq!(anomalies[0]["stage"], "open-temp");
        assert_eq!(anomalies[0]["error_code"], json!(libc::EACCES));
        assert_eq!(anomalies[1]["stage"], "rename");
        assert_eq!(anomalies[1]["error_code"], json!(libc::ENOENT));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn memory_tracking_branches_match_c() {
        let _guard = MEMORY_TEST_LOCK.lock().unwrap();

        // C `d2k_diag_memory_enable`/`_active`: выключенный сбор блокирует
        // acquire и alloc_failure, счётчики не меняются.
        memory_enable(false);
        assert!(!memory_active());
        assert!(!memory_acquire(0, 1));
        let frozen = memory_snapshot();
        memory_alloc_failure(0);
        assert_eq!(memory_snapshot(), frozen);

        memory_enable(true);
        assert!(memory_active());
        let before = memory_snapshot();

        // acquire: live/objects/created/peak; peak только растёт.
        assert!(memory_acquire(0, 100));
        assert!(memory_acquire(0, 50));
        let after = memory_snapshot();
        assert_eq!(after[0].live_bytes, before[0].live_bytes + 150);
        assert_eq!(after[0].live_objects, before[0].live_objects + 2);
        assert_eq!(after[0].created, before[0].created + 2);
        assert_eq!(after[0].peak_bytes, after[0].live_bytes);
        let peak = after[0].peak_bytes;

        // site >= 6 и bytes > UINT32_MAX отвергаются без изменения пика.
        assert!(!memory_acquire(MEMORY_SITE_COUNT, 1));
        if let Ok(oversized) = usize::try_from(u32::MAX as u64 + 1) {
            assert!(!memory_acquire(0, oversized));
        }
        assert_eq!(memory_snapshot()[0].peak_bytes, peak);

        // release: tracked=false / site>=6 / bytes>UINT32_MAX ничего не меняют.
        let before_release = memory_snapshot();
        memory_release(0, 100, false);
        memory_release(MEMORY_SITE_COUNT, 1, true);
        if let Ok(oversized) = usize::try_from(u32::MAX as u64 + 1) {
            memory_release(0, oversized, true);
        }
        assert_eq!(memory_snapshot(), before_release);

        // Корректный release: live−=bytes, objects−=1, destroyed+=1, peak не падает.
        memory_release(0, 100, true);
        let after_release = memory_snapshot();
        assert_eq!(
            after_release[0].live_bytes,
            before_release[0].live_bytes - 100
        );
        assert_eq!(
            after_release[0].live_objects,
            before_release[0].live_objects - 1
        );
        assert_eq!(after_release[0].destroyed, before_release[0].destroyed + 1);
        assert_eq!(after_release[0].peak_bytes, peak);

        // alloc_failure: активный валидный сайт +1; site>=6 — нет.
        let before_failure = memory_snapshot();
        memory_alloc_failure(0);
        memory_alloc_failure(MEMORY_SITE_COUNT);
        let after_failure = memory_snapshot();
        assert_eq!(
            after_failure[0].alloc_failures,
            before_failure[0].alloc_failures + 1
        );
        for site in 1..MEMORY_SITE_COUNT {
            assert_eq!(
                after_failure[site].alloc_failures,
                before_failure[site].alloc_failures
            );
        }

        // counts: tcp = site0+site3, tls = site1+site2, quic = site4+site5.
        let counts_before = tracked_memory_bytes();
        for (site, bytes) in [(0, 11), (1, 22), (2, 33), (3, 44), (4, 55), (5, 66)] {
            assert!(memory_acquire(site, bytes));
        }
        let counts_after = tracked_memory_bytes();
        assert_eq!(counts_after.0 - counts_before.0, 11 + 44);
        assert_eq!(counts_after.1 - counts_before.1, 22 + 33);
        assert_eq!(counts_after.2 - counts_before.2, 55 + 66);
        for (site, bytes) in [(0, 11), (1, 22), (2, 33), (3, 44), (4, 55), (5, 66)] {
            memory_release(site, bytes, true);
        }

        // Отключение не сбрасывает накопленное, но блокирует новые записи.
        memory_enable(false);
        let frozen = memory_snapshot();
        assert!(!memory_acquire(0, 1));
        memory_alloc_failure(0);
        assert_eq!(memory_snapshot(), frozen);
    }

    #[test]
    fn record_write_error_stores_code_and_keeps_last_eight_anomalies() {
        let mut recorder = Recorder::new(std::env::temp_dir(), std::env::temp_dir());
        recorder.record_write_error("open-temp", libc::EACCES);
        assert_eq!(recorder.write_failures, 1);
        assert_eq!(recorder.anomalies.len(), 1);
        let anomaly = recorder.anomalies.back().unwrap();
        assert_eq!(anomaly["kind"], "diagnostic-json-write-error");
        assert_eq!(anomaly["stage"], "open-temp");
        // C `d2k_diag_record_write_error` сохраняет error в anomaly.code.
        assert_eq!(anomaly["error_code"], json!(libc::EACCES));
        assert!(anomaly["rss_delta_kib"].is_null());
        assert!(anomaly["accounted_delta_kib"].is_null());
        assert_eq!(anomaly["window_samples"], json!(0));

        for code in 1..=10 {
            recorder.record_write_error("rename", code);
        }
        assert_eq!(recorder.write_failures, 11);
        assert_eq!(recorder.anomaly_total, 11);
        assert_eq!(recorder.anomalies.len(), 8);
        assert_eq!(recorder.anomalies.back().unwrap()["error_code"], json!(10));
    }

    #[test]
    fn record_event_ring_and_text_limits_match_c() {
        let mut recorder = Recorder::new(std::env::temp_dir(), std::env::temp_dir());
        recorder.enabled = true;
        for id in 1..=70 {
            recorder.record(json!({
                "id": id,
                "target": "a".repeat(300),
                "protocol": "b".repeat(20),
                "outcome": "c".repeat(40),
                "reason": "d".repeat(300),
                "ip": "e".repeat(60),
                "path": "f".repeat(20),
                "kind": "g".repeat(10),
            }));
        }
        assert_eq!(recorder.event_total, 70);
        assert_eq!(recorder.events.len(), EVENT_CAPACITY);
        assert_eq!(recorder.events.front().unwrap()["id"], json!(7));
        assert_eq!(recorder.events.back().unwrap()["id"], json!(70));

        // C `copy` режет строки по размерам полей event (cap-1 байт).
        let last = recorder.events.back().unwrap();
        assert_eq!(last["target"].as_str().unwrap().len(), 255);
        assert_eq!(last["protocol"].as_str().unwrap().len(), 15);
        assert_eq!(last["outcome"].as_str().unwrap().len(), 31);
        assert_eq!(last["reason"].as_str().unwrap().len(), 255);
        assert_eq!(last["ip"].as_str().unwrap().len(), 47);
        assert_eq!(last["path"].as_str().unwrap().len(), 15);
        assert_eq!(last["kind"].as_str().unwrap().len(), 7);
        assert!(last["at"].is_u64());

        // Событие без id получает event_total; не-объект и выключенный
        // сбор игнорируются.
        recorder.record(json!({"target": "x"}));
        assert_eq!(recorder.events.back().unwrap()["id"], json!(71));
        let total = recorder.event_total;
        recorder.record(json!(1));
        assert_eq!(recorder.event_total, total);
        recorder.enabled = false;
        recorder.record(json!({"id": 99}));
        assert_eq!(recorder.event_total, total);
    }

    #[test]
    fn compact_helpers_and_proc_field_match_c() {
        // C `compact_kib`: v<0 || v>INT32_MAX → -1 (в JSON null).
        assert_eq!(compact_kib(-1), None);
        assert_eq!(compact_kib(0), Some(0));
        assert_eq!(compact_kib(i64::from(i32::MAX)), Some(i32::MAX));
        assert_eq!(compact_kib(i64::from(i32::MAX) + 1), None);

        // C `compact_bytes_kib`: ceil(bytes/1024), переполнение → -1.
        assert_eq!(compact_bytes_kib(0), Some(0));
        assert_eq!(compact_bytes_kib(1), Some(1));
        assert_eq!(compact_bytes_kib(1024), Some(1));
        assert_eq!(compact_bytes_kib(1025), Some(2));
        assert_eq!(compact_bytes_kib(i32::MAX as u64 * 1024), Some(i32::MAX));
        assert_eq!(compact_bytes_kib(i32::MAX as u64 * 1024 + 1), None);

        // C `compact_bytes`: bytes>INT32_MAX → -1.
        assert_eq!(compact_bytes(i32::MAX as u64), Some(i32::MAX));
        assert_eq!(compact_bytes(i32::MAX as u64 + 1), None);

        // C `compact_count`: насыщение до UINT8_MAX.
        assert_eq!(compact_count(0), 0);
        assert_eq!(compact_count(255), 255);
        assert_eq!(compact_count(256), 255);
        assert_eq!(compact_count(u64::MAX), 255);

        // C `value(line,key)`: число после ключа, отрицательное — отказ.
        assert_eq!(proc_field("VmRSS:\t 2048 kB\n", "VmRSS:"), Some(2048));
        assert_eq!(proc_field("VmRSS:\t 2048 kB\n", "VmRSS"), Some(2048));
        assert_eq!(proc_field("VmRSS: -1 kB\n", "VmRSS:"), None);
        assert_eq!(proc_field("VmHWM: 4096 kB\n", "VmRSS:"), None);
        assert_eq!(proc_field("VmRSS:\n", "VmRSS:"), None);
    }

    #[cfg(unix)]
    #[test]
    fn smaps_rollup_statuses_match_c() {
        // C `read_status`: 1 unavailable, 2 ok, 3 parse-error, 4 unsupported,
        // иначе not-read.
        assert_eq!(rollup_status_text(1), "unavailable");
        assert_eq!(rollup_status_text(2), "ok");
        assert_eq!(rollup_status_text(3), "parse-error");
        assert_eq!(rollup_status_text(4), "unsupported");
        assert_eq!(rollup_status_text(0), "not-read");
        assert_eq!(rollup_status_text(5), "not-read");

        // C `optional_proc_status`: ENOENT при живом pid — unsupported без
        // errno, иначе unavailable с errno.
        assert_eq!(
            optional_proc_status(&std::io::Error::from_raw_os_error(libc::ENOENT), true),
            (4, None)
        );
        assert_eq!(
            optional_proc_status(&std::io::Error::from_raw_os_error(libc::ENOENT), false),
            (1, Some(libc::ENOENT))
        );
        assert_eq!(
            optional_proc_status(&std::io::Error::from_raw_os_error(libc::EACCES), true),
            (1, Some(libc::EACCES))
        );

        let root = std::env::temp_dir().join(format!("r2o-rollup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        assert!(proc_pid_dir_present(&root));
        assert!(!proc_pid_dir_present(&root.join("999")));

        // Каталог pid есть, файла нет — unsupported без errno.
        let (status, source, errno, values) = read_smaps_rollup(&root);
        assert_eq!(status, "unsupported");
        assert_eq!(source, "unavailable");
        assert_eq!(errno, None);
        assert!(values.is_none());

        // Каталога pid нет — unavailable с ENOENT.
        let (status, _, errno, _) = read_smaps_rollup(&root.join("999"));
        assert_eq!(status, "unavailable");
        assert_eq!(errno, Some(libc::ENOENT));

        // Неполный набор ключей — parse-error.
        fs::write(root.join("smaps_rollup"), "Rss: 1 kB\n").unwrap();
        let (status, _, _, values) = read_smaps_rollup(&root);
        assert_eq!(status, "parse-error");
        assert!(values.is_none());

        // Полный набор — ok и пять полей.
        fs::write(
            root.join("smaps_rollup"),
            "Rss: 1 kB\nPss: 2 kB\nAnonymous: 3 kB\nPrivate_Dirty: 4 kB\nSwap: 5 kB\n",
        )
        .unwrap();
        let (status, source, errno, values) = read_smaps_rollup(&root);
        assert_eq!(status, "ok");
        assert_eq!(source, "smaps_rollup");
        assert_eq!(errno, None);
        let values = values.unwrap();
        assert_eq!(values["rss_kib"], json!(1));
        assert_eq!(values["pss_kib"], json!(2));
        assert_eq!(values["anonymous_kib"], json!(3));
        assert_eq!(values["private_dirty_kib"], json!(4));
        assert_eq!(values["swap_kib"], json!(5));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn limit_reason_branches_match_c() {
        let mut counts = Counts::default();
        counts.resources_valid = false;
        assert_eq!(
            limit_reason_values(&counts),
            vec!["resource-data-unavailable"]
        );
        counts.resources_valid = true;
        counts.limiter_mask = 0;
        assert_eq!(
            limit_reason_values(&counts),
            vec!["no-current-resource-limit"]
        );
        for (mask, expected) in [
            (1, vec!["cpu"]),
            (2, vec!["memory"]),
            (4, vec!["conntrack"]),
            (8, vec!["slots"]),
            (5, vec!["cpu", "conntrack"]),
            (15, vec!["cpu", "memory", "conntrack", "slots"]),
        ] {
            counts.limiter_mask = mask;
            assert_eq!(limit_reason_values(&counts), expected, "mask {mask}");
        }
    }

    #[test]
    fn limit_event_json_matches_c_fields() {
        let mut counts = Counts::default();
        counts.measurement_limit = 7;
        counts.measurement_slots = 12;
        counts.limiter_mask = 3;
        counts.grow_pending = true;
        counts.resource_sequence = 14;
        counts.limit_sequence = 12;
        counts.resources_valid = true;
        counts.cpu_valid = true;
        let event = limit_event_json(100, 200, &counts);
        // C `d2k_diag_record_limit`/`write_limit_reason`: grow_pending и
        // resource/limit sequence берутся из снимка ресурсов.
        assert_eq!(event["grow_pending"], true);
        assert_eq!(event["resource_sequence"], json!(14));
        assert_eq!(event["limit_sequence"], json!(12));
        assert_eq!(event["limiter_mask"], json!(3));
        assert_eq!(event["limit_reason"], json!(["cpu", "memory"]));
    }

    #[cfg(unix)]
    #[test]
    fn memory_history_rollup_fields_match_c() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let root = std::env::temp_dir().join(format!("r2o-diag-history-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let proc_dir = root.join("proc");
        let run_dir = root.join("run");
        let diag_dir = root.join("diag");
        fs::create_dir_all(proc_dir.join("124/fd")).unwrap();
        fs::create_dir_all(&run_dir).unwrap();
        fs::create_dir_all(&diag_dir).unwrap();
        fs::set_permissions(&diag_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(proc_dir.join("124/comm"), "r2o-controller\n").unwrap();
        fs::write(
            proc_dir.join("124/status"),
            "VmRSS: 1024 kB\nVmHWM: 2048 kB\nRssAnon: 512 kB\nThreads: 3\nVmData: 4096 kB\nVmSwap: 8 kB\nVmSize: 8192 kB\nVmStk: 132 kB\n",
        )
        .unwrap();
        fs::write(
            proc_dir.join("124/stat"),
            "124 (r2o-controller) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20 21\n",
        )
        .unwrap();
        fs::write(proc_dir.join("124/fd/0"), "").unwrap();
        fs::write(proc_dir.join("124/fd/1"), "").unwrap();
        fs::write(
            proc_dir.join("124/smaps_rollup"),
            "Rss: 1024 kB\nPss: 2048 kB\nAnonymous: 512 kB\nPrivate_Dirty: 256 kB\nSwap: 8 kB\n",
        )
        .unwrap();
        fs::write(run_dir.join("r2o-controller4.pid"), "124\n").unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(diag_dir.join("enabled"))
            .unwrap();

        let mut recorder = Recorder::new(diag_dir, run_dir);
        recorder.proc_dir = proc_dir;
        recorder.tick(|| Counts::default());
        assert_eq!(recorder.memory_history.len(), 1);
        let row = &recorder.memory_history.front().unwrap().2;
        assert_eq!(row[0], json!(1024));
        assert_eq!(row[1], json!(4096));
        assert_eq!(row[2], json!(8));
        // C memory_history: rollup_status_code/errno/rollup[5].
        assert_eq!(row[3], json!(2));
        assert_eq!(row[4], json!(null));
        assert_eq!(row[5], json!([1024, 2048, 512, 256, 8]));
        assert_eq!(row[6], json!(512));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn recorder_toggles_memory_tracking_with_enabled_file() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let _guard = MEMORY_TEST_LOCK.lock().unwrap();
        let root =
            std::env::temp_dir().join(format!("r2o-diag-memory-toggle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let diag = root.join("diag");
        let run = root.join("run");
        fs::create_dir_all(&diag).unwrap();
        fs::create_dir_all(&run).unwrap();
        fs::set_permissions(&diag, fs::Permissions::from_mode(0o700)).unwrap();
        let enabled = diag.join("enabled");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&enabled)
            .unwrap();

        let mut recorder = Recorder::new(diag.clone(), run);
        // C `d2k_diag_new` = calloc: пустые кольца и нулевые счётчики.
        assert!(recorder.events.is_empty());
        assert!(recorder.samples.is_empty());
        assert!(recorder.memory_history.is_empty());
        assert!(recorder.limits.is_empty());
        assert!(recorder.anomalies.is_empty());
        assert_eq!(recorder.event_total, 0);
        assert_eq!(recorder.sample_total, 0);
        assert_eq!(recorder.memory_total, 0);

        recorder.tick(|| Counts::default());
        assert!(
            memory_active(),
            "включённая диагностика включает memory tracking"
        );
        // C `d2k_diag_sample_count`/`memory_history_count`: tick добавил
        // по одной записи в каждое кольцо.
        assert_eq!(recorder.samples.len(), 1);
        assert_eq!(recorder.memory_history.len(), 1);

        // Второй tick после интервала добавляет ещё по записи.
        recorder.checked = Some(Instant::now() - Duration::from_secs(2));
        recorder.sampled = Some(Instant::now() - Duration::from_secs(60));
        recorder.tick(|| Counts::default());
        assert_eq!(recorder.samples.len(), 2);
        assert_eq!(recorder.memory_history.len(), 2);

        fs::remove_file(&enabled).unwrap();
        recorder.checked = Some(Instant::now() - Duration::from_secs(2));
        recorder.tick(|| Counts::default());
        assert!(
            !memory_active(),
            "выключенная диагностика выключает memory tracking"
        );
        // C-очистка при выключении: кольца пусты.
        assert!(recorder.samples.is_empty());
        assert!(recorder.memory_history.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "run through scripts/test-diagnostics-rss-differential.sh"]
    fn d2o_periodic_rss_sample_matches_c() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let root = std::path::PathBuf::from(
            std::env::var_os("R2O_DIAG_RSS_ROOT").expect("test helper provides proc/run root"),
        );
        let c_trace = std::fs::read_to_string(
            std::env::var_os("R2O_DIAG_RSS_C_TRACE").expect("test helper provides C trace"),
        )
        .unwrap();
        let diag_dir = root.join("state/diagnostics");
        std::fs::create_dir_all(&diag_dir).unwrap();
        std::fs::set_permissions(&diag_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(diag_dir.join("enabled"))
            .unwrap();
        let mut recorder = Recorder::new(diag_dir.clone(), root.join("run"));
        recorder.proc_dir = root.join("proc");
        let counts = || Counts {
            boxes: 2,
            bindings: 3,
            plans: 4,
            ..Counts::default()
        };
        recorder.checked = None;
        recorder.sampled = None;
        recorder.tick(counts);
        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.sampled = Some(Instant::now() - Duration::from_secs(60));
        recorder.tick(counts);
        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.sampled = Some(Instant::now());
        recorder.tick(counts);
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(diag_dir.join("report.json")).unwrap()).unwrap();
        let samples = report["samples"].as_array().unwrap();
        assert_eq!(samples.len(), 2);
        let field = |sample: &serde_json::Value, key: &str| {
            sample["processes"][0]
                .get(key)
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-1)
        };
        let line = |sample: &serde_json::Value| {
            format!(
                "rss={} hwm={} anon={} threads={} vm_data={} vm_swap={}",
                field(sample, "rss_kib"),
                field(sample, "hwm_kib"),
                field(sample, "anon_kib"),
                field(sample, "threads"),
                field(sample, "vm_data_kib"),
                field(sample, "vm_swap_kib")
            )
        };
        let detail = &report["memory_details"][0]["latest"];
        let detail_i64 = |value: &serde_json::Value, key: &str| {
            value
                .get(key)
                .and_then(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
                })
                .unwrap_or(-1)
        };
        let rust_trace = format!(
            "samples={}\n{}\n{}\ndetail pid={} rss={} start={} vm={},{},{},{} fds={} status={} source={} errno={} rollup={},{},{},{},{}\n",
            samples.len(),
            line(&samples[0]),
            line(&samples[1]),
            detail_i64(&detail, "pid"),
            detail_i64(&detail, "rss_kib"),
            detail_i64(&detail, "start_ticks"),
            detail_i64(&detail, "vm_size_kib"),
            detail_i64(&detail, "vm_data_kib"),
            detail_i64(&detail, "vm_stack_kib"),
            detail_i64(&detail, "vm_swap_kib"),
            detail_i64(&detail, "fd_count"),
            detail["smaps_rollup_status"].as_str().unwrap_or("not-read"),
            detail["smaps_rollup_source"]
                .as_str()
                .unwrap_or("unavailable"),
            detail["smaps_rollup_errno"].as_i64().unwrap_or(0),
            detail_i64(&detail["smaps_rollup"], "rss_kib"),
            detail_i64(&detail["smaps_rollup"], "pss_kib"),
            detail_i64(&detail["smaps_rollup"], "anonymous_kib"),
            detail_i64(&detail["smaps_rollup"], "private_dirty_kib"),
            detail_i64(&detail["smaps_rollup"], "swap_kib"),
        );
        assert_eq!(rust_trace, c_trace);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn records_only_while_enabled_and_exports_d2o_ring_shape() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("r2o-diagnostics-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut recorder = Recorder::new(dir.clone(), dir.join("run"));
        recorder.record(json!({"target":"ignored"}));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("enabled"))
            .unwrap();
        recorder.tick(|| Counts {
            boxes: 2,
            bindings: 3,
            plans: 4,
            observations: 5,
            active: 1,
            queued: 2,
            tasks: 3,
            snapshots: 4,
            http_records: 5,
            http_queued: 6,
            workers_started: 12,
            workers_joined: 9,
            ..Counts::default()
        });
        for id in 0..64 {
            recorder.record(json!({"target":format!("target-{id}"),"outcome":"inconclusive"}));
        }
        recorder.record(json!({"target":"я".repeat(200),"outcome":"plan-found"}));
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("report.json")).unwrap()).unwrap();
        assert_eq!(report["schema"], 1);
        assert_eq!(report["event_capacity"], 64);
        assert_eq!(report["sample_capacity"], 120);
        assert_eq!(report["samples"][0]["bindings"], 3);
        assert_eq!(report["samples"][0]["snapshots"], 4);
        assert_eq!(report["samples"][0]["http_records"], 5);
        assert_eq!(report["samples"][0]["http_queued"], 6);
        assert_eq!(report["samples"][0]["workers_started"], 12);
        assert_eq!(report["samples"][0]["workers_joined"], 9);
        assert_eq!(
            report["samples"][0]["processes"].as_array().unwrap().len(),
            3
        );
        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.sampled = Some(Instant::now() - Duration::from_secs(60));
        recorder.tick(Counts::default);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("report.json")).unwrap()).unwrap();
        assert_eq!(report["events"].as_array().unwrap().len(), 64);
        assert_eq!(report["events_overwritten"], 1);
        assert_eq!(report["events"][63]["target"].as_str().unwrap().len(), 254);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn legacy_split_pidfile_is_visible_under_merged_process_name() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let root = std::env::temp_dir().join(format!("r2o-diag-legacy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let diag = root.join("diag");
        let proc_dir = root.join("proc");
        let run = root.join("run");
        fs::create_dir_all(proc_dir.join("321")).unwrap();
        fs::create_dir_all(&run).unwrap();
        fs::create_dir_all(&diag).unwrap();
        fs::set_permissions(&diag, fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(diag.join("enabled"))
            .unwrap();
        fs::write(run.join("r2o-controller4.pid"), "321\n").unwrap();
        fs::write(proc_dir.join("321/comm"), "r2o-controller\n").unwrap();
        fs::write(proc_dir.join("321/status"), "VmRSS: 2048 kB\n").unwrap();
        let mut recorder = Recorder::new(diag.clone(), run);
        recorder.proc_dir = proc_dir;
        recorder.tick(Counts::default);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(diag.join("report.json")).unwrap()).unwrap();
        let process = report["samples"][0]["processes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|process| process["name"] == "r2o-controller")
            .unwrap();
        assert_eq!(process["pid"], 321);
        assert_eq!(process["rss_kib"], 2048);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_tick_lifecycle_matches_d2o() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let root =
            std::env::temp_dir().join(format!("r2o-diagnostics-tick-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let dir = root.join("diagnostics");
        let mut recorder = Recorder::new(dir.clone(), root.join("run"));
        recorder.tick(Counts::default);
        let mut output = format!("disabled_start_dir={}\n", dir.exists() as u8);
        assert!(!dir.exists());

        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("enabled"))
            .unwrap();
        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.tick(Counts::default);
        output.push_str(&format!(
            "first={} report={}\n",
            recorder.samples.len(),
            dir.join("report.json").is_file() as u8
        ));

        recorder.checked = Some(Instant::now() - Duration::from_millis(500));
        recorder.tick(Counts::default);
        output.push_str(&format!("subsecond={}\n", recorder.samples.len()));

        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.sampled = Some(Instant::now() - Duration::from_secs(60));
        recorder.tick(Counts::default);
        output.push_str(&format!("minute={}\n", recorder.samples.len()));

        fs::write(dir.join("report.new"), b"unfinished").unwrap();
        fs::remove_file(dir.join("enabled")).unwrap();
        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.tick(Counts::default);
        output.push_str(&format!(
            "disabled={} report={} pending={}\n",
            (!recorder.enabled) as u8,
            dir.join("report.json").exists() as u8,
            dir.join("report.new").exists() as u8
        ));
        assert!(!recorder.enabled);
        assert!(!dir.join("enabled").exists());
        assert!(!dir.join("report.json").exists());
        assert!(!dir.join("report.new").exists());
        if let Ok(path) = std::env::var("R2O_DIAGNOSTIC_TICK_DIFF_OUTPUT") {
            fs::write(path, output).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn diagnostics_id_and_counts_match_d2o() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let dir = std::env::temp_dir().join(format!("r2o-diagnostics-diff-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("enabled"))
            .unwrap();
        let counts = Counts {
            snapshots: 4,
            http_records: 5,
            http_queued: 6,
            http_failures: 2,
            grow_pending: true,
            resource_sequence: 14,
            limit_sequence: 12,
            limiter_mask: 3,
            resources_valid: true,
            ..Counts::default()
        };
        let mut recorder = Recorder::new(dir.clone(), dir.join("run"));
        recorder.tick(|| counts);
        recorder.record(json!({
            "id": 77,
            "family": 4,
            "trigger": 3,
            "elapsed_ms": null,
            "queue_ms": null,
            "probe_units": null,
            "target": "example.com",
            "ip": null,
            "path": "httpsearch",
            "kind": "name",
            "shape": 1,
            "protocol": "http",
            "outcome": "inconclusive",
            "reason": "bad\t\u{1}line\n\0ignored",
            "reason_source": "terminal-code"
        }));
        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.sampled = Some(Instant::now() - Duration::from_secs(60));
        recorder.tick(|| counts);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("report.json")).unwrap()).unwrap();
        let mut event = report["events"][0].clone();
        event.as_object_mut().unwrap().remove("at");
        let sample = &report["samples"][0];
        assert_eq!(report["ring_bytes"], d2o_ring_bytes());
        assert_eq!(event["id"], 77);
        assert_eq!(event["reason"], "bad??line\n");
        assert_eq!(event["ip"], "");
        assert_eq!(sample["snapshots"], 4);
        assert_eq!(sample["http_records"], 5);
        assert_eq!(sample["http_queued"], 6);
        assert_eq!(sample["http_failures"], 2);
        assert_eq!(sample["grow_pending"], true);
        assert_eq!(sample["resource_sequence"], 14);
        assert_eq!(sample["limit_sequence"], 12);
        assert_eq!(sample["limiter_mask"], 3);
        assert_eq!(sample["limit_reason"], json!(["cpu", "memory"]));
        assert_eq!(event["reason_source"], "terminal-code");
        assert!(report["http_storage_limits"]["records_bytes"].is_u64());
        if let Ok(path) = std::env::var("R2O_DIAGNOSTICS_DIFF_OUTPUT") {
            fs::write(
                path,
                format!(
                    "ring_bytes={}\nevent_json={}\nevent_id={}\nreason_hex={}\nsnapshots={}\nhttp_records={}\nhttp_queued={}\n",
                    report["ring_bytes"],
                    serde_json::to_string(&event).unwrap(),
                    event["id"],
                    event["reason"]
                        .as_str()
                        .unwrap()
                        .as_bytes()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    sample["snapshots"],
                    sample["http_records"],
                    sample["http_queued"]
                ),
            )
            .unwrap();
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn first_process_detail_survives_process_exit_like_d2o() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let root = std::env::temp_dir().join(format!("r2o-diag-exit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let diag = root.join("diag");
        let proc_dir = root.join("proc");
        let run = root.join("run");
        fs::create_dir_all(proc_dir.join("123")).unwrap();
        fs::create_dir_all(&run).unwrap();
        fs::create_dir(&diag).unwrap();
        fs::set_permissions(&diag, fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(diag.join("enabled"))
            .unwrap();
        fs::write(run.join("r2o-controller.pid"), "123\n").unwrap();
        fs::write(proc_dir.join("123/comm"), "r2o-controller\n").unwrap();
        fs::write(proc_dir.join("123/status"), "VmRSS: 1024 kB\n").unwrap();
        let mut recorder = Recorder::new(diag.clone(), run.clone());
        recorder.proc_dir = proc_dir;
        recorder.tick(Counts::default);
        fs::remove_file(run.join("r2o-controller.pid")).unwrap();
        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.sampled = Some(Instant::now() - Duration::from_secs(60));
        recorder.tick(Counts::default);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(diag.join("report.json")).unwrap()).unwrap();
        let detail = &report["memory_details"][0];
        if let Ok(path) = std::env::var("R2O_DIAG_EXIT_DIFF_OUTPUT") {
            fs::write(
                path,
                format!(
                    "first_pid={}\nlatest_null={}\n",
                    detail["first"]["pid"],
                    detail["latest"].is_null()
                ),
            )
            .unwrap();
        }
        assert_eq!(detail["first"]["pid"], 123);
        assert!(detail["latest"].is_null());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn process_memory_follows_pidfiles_and_restarts_first_detail_on_pid_reuse() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let root =
            std::env::temp_dir().join(format!("r2o-diagnostics-proc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let proc_dir = root.join("proc");
        let run_dir = root.join("run");
        let diag_dir = root.join("state/diagnostics");
        fs::create_dir_all(proc_dir.join("sys/net/netfilter")).unwrap();
        fs::create_dir_all(diag_dir.parent().unwrap()).unwrap();
        fs::set_permissions(
            diag_dir.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::create_dir(&diag_dir).unwrap();
        fs::set_permissions(&diag_dir, fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(diag_dir.join("enabled"))
            .unwrap();
        fs::create_dir_all(&run_dir).unwrap();
        fs::create_dir_all(proc_dir.join("123")).unwrap();
        fs::write(run_dir.join("r2o-controller.pid"), "123\n").unwrap();
        fs::write(proc_dir.join("123/comm"), "r2o-controller\n").unwrap();
        fs::write(
            proc_dir.join("123/status"),
            "VmRSS: 1024 kB\nVmHWM: 2048 kB\nRssAnon: 512 kB\nThreads: 3\n",
        )
        .unwrap();
        fs::write(
            proc_dir.join("123/smaps_rollup"),
            "Rss: 32 kB\nPss: 30 kB\nAnonymous: 24 kB\nPrivate_Dirty: 24 kB\nSwap: 0 kB\n",
        )
        .unwrap();
        fs::create_dir_all(proc_dir.join("124")).unwrap();
        fs::write(proc_dir.join("124/comm"), "r2o-controller\n").unwrap();
        fs::write(proc_dir.join("124/status"), "VmRSS: 9999 kB\n").unwrap();
        fs::create_dir_all(proc_dir.join("125")).unwrap();
        fs::write(proc_dir.join("125/comm"), "r2o-controller\n").unwrap();
        fs::write(proc_dir.join("125/status"), "VmRSS: 8192 kB\n").unwrap();
        fs::write(
            proc_dir.join("meminfo"),
            "MemTotal: 65536 kB\nMemAvailable: 8192 kB\n",
        )
        .unwrap();

        let mut recorder = Recorder::new(diag_dir.clone(), run_dir);
        recorder.proc_dir = proc_dir.clone();
        recorder.tick(Counts::default);
        let read_report = || -> serde_json::Value {
            serde_json::from_slice(&fs::read(diag_dir.join("report.json")).unwrap()).unwrap()
        };
        let first = read_report();
        let process = first["samples"][0]["processes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|process| process["name"] == "r2o-controller")
            .unwrap();
        assert_eq!(process["pid"], 123);
        assert_eq!(process["rss_kib"], 1024);
        assert!(
            !first["samples"][0]["processes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|process| process["pid"] == 124 || process["pid"] == 125)
        );
        assert_eq!(first["samples"][0]["mem_available_kib"], 8192);
        assert_eq!(first["samples"][0]["mem_total_kib"], 65536);
        assert_eq!(
            first["samples"][0]["system_conntrack"],
            serde_json::Value::Null
        );
        assert_eq!(first["memory_details"][0]["first"]["rss_kib"], 1024);
        assert_eq!(
            first["memory_details"][0]["first"]["fd_count"],
            serde_json::Value::Null
        );
        assert_eq!(
            first["memory_details"][0]["first"]["smaps_rollup_status"],
            "ok"
        );
        assert_eq!(
            first["memory_details"][0]["first"]["smaps_rollup"]["rss_kib"],
            32
        );
        assert_eq!(
            first["memory_details"][0]["first"]["smaps_rollup"]["pss_kib"],
            30
        );
        assert!(first["memory_details"][0]["first"]["smaps"].is_null());
        assert_eq!(
            first["memory_details"][0]["first"]["smaps_status"],
            "not-read"
        );
        assert!(!first.to_string().contains("never-export-me"));

        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.sampled = Some(Instant::now() - Duration::from_secs(60));
        fs::write(
            proc_dir.join("123/status"),
            "VmRSS: 4096 kB\nVmHWM: 4096 kB\nVmSize: 8192 kB\nVmData: 4096 kB\nVmStk: 128 kB\nVmSwap: 0 kB\nRssAnon: 3072 kB\nThreads: 1\n",
        )
        .unwrap();
        recorder.tick(Counts::default);
        let second = read_report();
        let detail = &second["memory_details"][0];
        assert_eq!(detail["first"]["rss_kib"], 1024);
        assert_eq!(detail["latest"]["rss_kib"], 4096);
        assert_eq!(detail["latest"]["vm_size_kib"], 8192);
        assert_eq!(detail["latest"]["fd_count"], serde_json::Value::Null);
        assert_eq!(detail["latest"]["smaps_rollup_status"], "ok");
        assert_eq!(detail["latest"]["smaps_rollup"]["rss_kib"], 32);
        assert!(detail["latest"]["smaps"].is_null());

        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.sampled = Some(Instant::now() - Duration::from_secs(60));
        fs::write(
            proc_dir.join("123/stat"),
            "123 (r2o-controller) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0\n",
        )
        .unwrap();
        fs::create_dir_all(proc_dir.join("123/fd")).unwrap();
        fs::write(proc_dir.join("123/fd/0"), "").unwrap();
        fs::write(proc_dir.join("123/fd/1"), "").unwrap();
        recorder.tick(Counts::default);
        let identified = read_report();
        assert_eq!(identified["memory_details"][0]["first"]["rss_kib"], 4096);
        assert_eq!(
            identified["memory_details"][0]["first"]["start_ticks"],
            12345
        );
        assert_eq!(identified["memory_details"][0]["first"]["fd_count"], 2);

        recorder.checked = Some(Instant::now() - Duration::from_secs(1));
        recorder.sampled = Some(Instant::now() - Duration::from_secs(60));
        fs::write(
            proc_dir.join("123/stat"),
            "123 (r2o-controller) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 222 0\n",
        )
        .unwrap();
        fs::write(
            proc_dir.join("123/status"),
            "VmRSS: 5120 kB\nVmHWM: 5120 kB\nRssAnon: 512 kB\nThreads: 3\nVmSize: 4096 kB\nVmData: 1024 kB\nVmStk: 64 kB\nVmSwap: 0 kB\n",
        )
        .unwrap();
        recorder.tick(Counts::default);
        let reused = read_report();
        assert_eq!(reused["memory_details"][0]["first"]["rss_kib"], 5120);
        assert_eq!(reused["memory_details"][0]["first"]["start_ticks"], 222);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn json_string_escaping_matches_c() {
        // C `write_json_string`/`json_string`: 7 escape, control <0x20 →
        // `\u00xx`, валидный UTF-8 как есть. serde_json даёт те же escape.
        let value = json!("a\"b\\c\n\r\t\u{8}\u{c}\u{1}\u{1f}пример");
        let text = serde_json::to_string(&value).unwrap();
        assert!(text.contains("\\\""), "{text}");
        assert!(text.contains("\\\\"), "{text}");
        assert!(text.contains("\\n"), "{text}");
        assert!(text.contains("\\r"), "{text}");
        assert!(text.contains("\\t"), "{text}");
        assert!(text.contains("\\b"), "{text}");
        assert!(text.contains("\\f"), "{text}");
        assert!(text.contains("\\u0001"), "{text}");
        assert!(text.contains("\\u001f"), "{text}");
        assert!(text.contains("пример"), "{text}");
    }
}
