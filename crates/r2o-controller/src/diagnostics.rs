//! Локальный opt-in снимок истории поиска и ресурсов для панели.

use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::ffi::{c_int, c_long};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const EVENT_CAPACITY: usize = 64;
const SAMPLE_CAPACITY: usize = 120;
const SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
const REPORT_MAX: usize = 256 * 1024;
const D2O_PROCESS_CAPACITY: usize = 3;
const PROCESS_SPECS: [ProcessSpec; 5] = [
    ProcessSpec {
        name: "r2o-controller4",
        comm: "r2o-controller",
        pidfile: "r2o-controller4.pid",
    },
    ProcessSpec {
        name: "r2o-controller6",
        comm: "r2o-controller",
        pidfile: "r2o-controller6.pid",
    },
    ProcessSpec {
        name: "r2o-datapath4",
        comm: "r2o-datapath",
        pidfile: "r2o-datapath4.pid",
    },
    ProcessSpec {
        name: "r2o-datapath6",
        comm: "r2o-datapath",
        pidfile: "r2o-datapath6.pid",
    },
    ProcessSpec {
        name: "r2o-panel",
        comm: "r2o-panel",
        pidfile: "r2o-panel.pid",
    },
];

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticProcessMemory {
    pid: c_long,
    rss: i64,
    hwm: i64,
    anon: i64,
    threads: i64,
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
    smaps_ok: c_int,
    groups: [[i64; 5]; 4],
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
    processes: [D2oDiagnosticProcessMemory; D2O_PROCESS_CAPACITY],
}

#[allow(dead_code)]
#[repr(C)]
struct D2oDiagnosticRing {
    first: [D2oDiagnosticMemoryDetail; D2O_PROCESS_CAPACITY],
    latest: [D2oDiagnosticMemoryDetail; D2O_PROCESS_CAPACITY],
    events: [D2oDiagnosticEvent; EVENT_CAPACITY],
    samples: [D2oDiagnosticSample; SAMPLE_CAPACITY],
    event_count: usize,
    sample_count: usize,
    event_total: u64,
    sample_total: u64,
    last_ms: i64,
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
    first_details: HashMap<String, Value>,
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
            first_details: HashMap::new(),
        }
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
            if self.enabled {
                self.events.clear();
                self.samples.clear();
                self.event_total = 0;
                self.sample_total = 0;
                self.first_details.clear();
            }
            self.enabled = false;
            self.sampled = None;
            return;
        }
        if !self.enabled {
            self.enabled = true;
            self.sampled = None;
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
        let sample = json!({
            "at": at,
            "mono_ms": mono_ms,
            "mem_total_kib": meminfo(&self.proc_dir, "MemTotal:"),
            "mem_available_kib": meminfo(&self.proc_dir, "MemAvailable:"),
            "system_conntrack": read_number(&self.proc_dir.join("sys/net/netfilter/nf_conntrack_count")),
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
            "processes": processes,
        });
        if self.samples.len() == SAMPLE_CAPACITY {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
        let report = json!({
            "schema": 1,
            "enabled": true,
            "controller_pid": std::process::id(),
            "release": option_env!("R2O_RELEASE_ID").unwrap_or("dev"),
            "ring_bytes": d2o_ring_bytes(),
            "event_capacity": EVENT_CAPACITY,
            "sample_capacity": SAMPLE_CAPACITY,
            "sample_interval_ms": SAMPLE_INTERVAL.as_millis(),
            "events_overwritten": self.event_total.saturating_sub(self.events.len() as u64),
            "samples_overwritten": self.sample_total.saturating_sub(self.samples.len() as u64),
            "events": self.events,
            "samples": self.samples,
            "memory_details": details,
        });
        self.write_report(&report);
    }

    fn write_report(&self, report: &Value) {
        if !ensure_diagnostics_dir(&self.dir) {
            return;
        }
        let bytes = serde_json::to_vec(report).unwrap_or_default();
        if bytes.is_empty() || bytes.len() > REPORT_MAX || !diagnostics_enabled(&self.dir) {
            return;
        }
        let tmp = self.dir.join("report.new");
        let path = self.dir.join("report.json");
        let _ = fs::remove_file(&tmp);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let Ok(mut file) = options.open(&tmp) else {
            return;
        };
        if file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .is_err()
            || fs::metadata(&tmp).map_or(true, |metadata| metadata.len() as usize > REPORT_MAX)
            || !diagnostics_enabled(&self.dir)
        {
            let _ = fs::remove_file(&tmp);
            return;
        }
        drop(file);
        if fs::rename(&tmp, &path).is_err() {
            let _ = fs::remove_file(&tmp);
        }
    }
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

fn ensure_diagnostics_dir(dir: &Path) -> bool {
    if !dir.exists() {
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
    if !ensure_diagnostics_dir(dir) {
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
            let pid = fs::read_to_string(run_dir.join(spec.pidfile))
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .filter(|pid| *pid > 0 && *pid <= i32::MAX as u64);
            let Some(pid) = pid else {
                return empty_process(spec.name);
            };
            let base = proc_dir.join(pid.to_string());
            let comm_matches = fs::read_to_string(base.join("comm"))
                .is_ok_and(|name| name.trim_end_matches(['\r', '\n']) == spec.comm);
            if !comm_matches {
                return empty_process(spec.name);
            }
            let status = fs::read_to_string(base.join("status")).unwrap_or_default();
            let field = |key: &str| {
                status.lines().find_map(|line| {
                    let (name, rest) = line.split_once(':')?;
                    (name == key)
                        .then(|| rest.split_whitespace().next()?.parse::<u64>().ok())
                        .flatten()
                })
            };
            json!({
                "name":spec.name,"pid":pid,"rss_kib":field("VmRSS"),"hwm_kib":field("VmHWM"),
                "anon_kib":field("RssAnon"),"threads":field("Threads")
            })
        })
        .collect()
}

fn empty_process(name: &str) -> Value {
    json!({"name":name,"pid":0,"rss_kib":null,"hwm_kib":null,"anon_kib":null,"threads":null})
}

fn process_detail(process: &Value, at: u64, mono_ms: u64, proc_dir: &Path) -> Value {
    let pid = process["pid"].as_u64().unwrap_or(0);
    let base = proc_dir.join(pid.to_string());
    let status = fs::read_to_string(base.join("status")).unwrap_or_default();
    let field = |key: &str| {
        status.lines().find_map(|line| {
            let (name, rest) = line.split_once(':')?;
            (name == key)
                .then(|| rest.split_whitespace().next()?.parse::<u64>().ok())
                .flatten()
        })
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
    json!({
        "pid":pid,"at":at,"mono_ms":mono_ms,"rss_kib":process["rss_kib"],
        "start_ticks":start_ticks,"vm_size_kib":field("VmSize"),"vm_data_kib":field("VmData"),
        "vm_stack_kib":field("VmStk"),"vm_swap_kib":field("VmSwap"),"fd_count":fd_count,
        "smaps":read_smaps(proc_dir, pid)
    })
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

fn smaps_group(line: &str) -> Option<usize> {
    let mut tokens = line.split_whitespace();
    let (start, end) = tokens.next()?.split_once('-')?;
    if u64::from_str_radix(start, 16).is_err() || u64::from_str_radix(end, 16).is_err() {
        return None;
    }
    for _ in 0..4 {
        tokens.next()?;
    }
    Some(match tokens.next() {
        None => 0,
        Some("[heap]") => 1,
        Some(label) if label.starts_with("[stack") => 2,
        Some(_) => 3,
    })
}

fn read_smaps(proc_dir: &Path, pid: u64) -> Option<Value> {
    let text = fs::read_to_string(proc_dir.join(pid.to_string()).join("smaps")).ok()?;
    let mut groups = [[0_u64; 5]; 4];
    let mut current = None;
    let mut maps = 0_u64;
    let mut fields = 0_u64;
    for line in text.lines() {
        if let Some(group) = smaps_group(line) {
            current = Some(group);
            groups[group][0] = groups[group][0].checked_add(1)?;
            maps = maps.checked_add(1)?;
            continue;
        }
        let Some(group) = current else { continue };
        for (field, key) in [
            (1, "Size"),
            (2, "Rss"),
            (3, "Anonymous"),
            (4, "Private_Dirty"),
        ] {
            if let Some((name, value)) = line.split_once(':')
                && name == key
            {
                let kib = value.split_whitespace().next()?.parse::<u64>().ok()?;
                groups[group][field] = groups[group][field].checked_add(kib)?;
                fields = fields.checked_add(1)?;
            }
        }
    }
    if maps == 0 || fields != maps.checked_mul(4)? {
        return None;
    }
    let group_names = ["anonymous", "heap", "stack", "other"];
    let metric_names = [
        "maps",
        "size_kib",
        "rss_kib",
        "anonymous_kib",
        "private_dirty_kib",
    ];
    let mut result = serde_json::Map::new();
    for (index, name) in group_names.into_iter().enumerate() {
        let mut metrics = serde_json::Map::new();
        for (metric, value) in metric_names.into_iter().zip(groups[index]) {
            metrics.insert(metric.into(), json!(value));
        }
        result.insert(name.into(), Value::Object(metrics));
    }
    Some(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::{Counts, Recorder, d2o_ring_bytes};
    use serde_json::json;
    use std::fs::{self, OpenOptions};
    use std::time::{Duration, Instant};

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
        assert_eq!(
            report["samples"][0]["processes"].as_array().unwrap().len(),
            5
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
        fs::write(run.join("r2o-controller4.pid"), "123\n").unwrap();
        fs::write(proc_dir.join("123/comm"), "r2o-controller\n").unwrap();
        fs::write(proc_dir.join("123/status"), "VmRSS: 1024 kB\n").unwrap();
        let mut recorder = Recorder::new(diag.clone(), run.clone());
        recorder.proc_dir = proc_dir;
        recorder.tick(Counts::default);
        fs::remove_file(run.join("r2o-controller4.pid")).unwrap();
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
        fs::write(run_dir.join("r2o-controller4.pid"), "123\n").unwrap();
        fs::write(run_dir.join("r2o-controller6.pid"), "125\n").unwrap();
        fs::write(proc_dir.join("123/comm"), "r2o-controller\n").unwrap();
        fs::write(
            proc_dir.join("123/status"),
            "VmRSS: 1024 kB\nVmHWM: 2048 kB\nRssAnon: 512 kB\nThreads: 3\n",
        )
        .unwrap();
        fs::write(
            proc_dir.join("123/smaps"),
            "1000-2000 rw-p 00000000 00:00 0 [heap]\nSize: 16 kB\nRss: 8 kB\nAnonymous: 8 kB\nPrivate_Dirty: 8 kB\n2000-3000 rw-p 00000000 00:00 0\nSize: 32 kB\nRss: 24 kB\nAnonymous: 24 kB\nPrivate_Dirty: 24 kB\n3000-4000 r--p 00000000 00:00 1 /private/never-export-me\nSize: 4 kB\nRss: 4 kB\nAnonymous: 0 kB\nPrivate_Dirty: 0 kB\n",
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
            .find(|process| process["name"] == "r2o-controller4")
            .unwrap();
        assert_eq!(process["pid"], 123);
        assert_eq!(process["rss_kib"], 1024);
        let controller6 = first["samples"][0]["processes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|process| process["name"] == "r2o-controller6")
            .unwrap();
        assert_eq!(controller6["pid"], 125);
        assert_eq!(controller6["rss_kib"], 8192);
        assert!(
            !first["samples"][0]["processes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|process| process["pid"] == 124)
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
            first["memory_details"][0]["first"]["smaps"]["heap"]["rss_kib"],
            8
        );
        assert_eq!(
            first["memory_details"][0]["first"]["smaps"]["anonymous"]["rss_kib"],
            24
        );
        assert_eq!(
            first["memory_details"][0]["first"]["smaps"]["other"]["rss_kib"],
            4
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
        assert_eq!(detail["latest"]["smaps"]["heap"]["rss_kib"], 8);

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
}
