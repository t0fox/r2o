//! Локальный opt-in снимок истории поиска и ресурсов для панели.

use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const EVENT_CAPACITY: usize = 64;
const SAMPLE_CAPACITY: usize = 120;
const SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
const REPORT_MAX: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub struct Counts {
    pub boxes: usize,
    pub bindings: usize,
    pub plans: usize,
    pub observations: usize,
    pub active: usize,
    pub queued: usize,
    pub tasks: usize,
}

pub struct Recorder {
    dir: PathBuf,
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
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
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
        object.insert("id".into(), json!(self.event_total));
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
            if let Some(value) = object
                .get_mut(key)
                .and_then(|value| value.as_str())
                .map(str::to_owned)
            {
                object.insert(key.into(), json!(truncate_utf8(value, limit)));
            }
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
        let processes = process_memory();
        let mut details = Vec::with_capacity(processes.len());
        for process in &processes {
            if process["pid"].as_u64().unwrap_or(0) != 0 {
                let name = process["name"].as_str().unwrap_or_default();
                let detail = process_detail(process, at, mono_ms);
                let previous = self.first_details.get(name);
                if previous.is_none_or(|old| old["pid"] != detail["pid"]) {
                    self.first_details.insert(name.to_owned(), detail.clone());
                }
                details.push(json!({
                    "name": name,
                    "first": self.first_details.get(name),
                    "latest": detail,
                }));
            } else {
                details.push(json!({"name":process["name"],"first":null,"latest":null}));
            }
        }
        let sample = json!({
            "at": at,
            "mono_ms": mono_ms,
            "mem_total_kib": meminfo("MemTotal:"),
            "mem_available_kib": meminfo("MemAvailable:"),
            "system_conntrack": read_number("/proc/sys/net/netfilter/nf_conntrack_count"),
            "datapath_flows": null,
            "http_records": null,
            "http_queued": null,
            "boxes": counts.boxes,
            "bindings": counts.bindings,
            "plans": counts.plans,
            "observations": counts.observations,
            "active": counts.active,
            "queued": counts.queued,
            "tasks": counts.tasks,
            "snapshots": null,
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
            "ring_bytes": self.events.iter().map(Value::to_string).map(|s| s.len()).sum::<usize>()
                + self.samples.iter().map(Value::to_string).map(|s| s.len()).sum::<usize>(),
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

fn read_number(path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn meminfo(key: &str) -> Option<u64> {
    fs::read_to_string("/proc/meminfo")
        .ok()?
        .lines()
        .find_map(|line| {
            let (name, rest) = line.split_once(':')?;
            (name == key.trim_end_matches(':'))
                .then(|| rest.split_whitespace().next()?.parse().ok())
                .flatten()
        })
}

fn process_memory() -> Vec<Value> {
    let wanted = ["r2o-controller", "r2o-datapath", "r2o-panel"];
    let mut found = HashMap::<String, Value>::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return wanted.iter().map(|name| empty_process(name)).collect();
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let base = entry.path();
        let Ok(comm) = fs::read_to_string(base.join("comm")) else {
            continue;
        };
        let name = comm.trim();
        if !wanted.contains(&name) || found.contains_key(name) {
            continue;
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
        found.insert(
            name.to_owned(),
            json!({
                "name":name,"pid":pid,"rss_kib":field("VmRSS"),"hwm_kib":field("VmHWM"),
                "anon_kib":field("RssAnon"),"threads":field("Threads")
            }),
        );
    }
    wanted
        .iter()
        .map(|name| found.remove(*name).unwrap_or_else(|| empty_process(name)))
        .collect()
}

fn empty_process(name: &str) -> Value {
    json!({"name":name,"pid":0,"rss_kib":null,"hwm_kib":null,"anon_kib":null,"threads":null})
}

fn process_detail(process: &Value, at: u64, mono_ms: u64) -> Value {
    let pid = process["pid"].as_u64().unwrap_or(0);
    let status_path = format!("/proc/{pid}/status");
    let status = fs::read_to_string(status_path).unwrap_or_default();
    let field = |key: &str| {
        status.lines().find_map(|line| {
            let (name, rest) = line.split_once(':')?;
            (name == key)
                .then(|| rest.split_whitespace().next()?.parse::<u64>().ok())
                .flatten()
        })
    };
    let start_ticks = fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let close = stat.rfind(')')?;
            stat[close + 1..]
                .split_whitespace()
                .nth(19)?
                .parse::<u64>()
                .ok()
        });
    let fd_count = fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()
        .map(|fds| fds.count());
    json!({
        "pid":pid,"at":at,"mono_ms":mono_ms,"rss_kib":process["rss_kib"],
        "start_ticks":start_ticks,"vm_size_kib":field("VmSize"),"vm_data_kib":field("VmData"),
        "vm_stack_kib":field("VmStk"),"vm_swap_kib":field("VmSwap"),"fd_count":fd_count,
        "smaps":read_smaps(pid)
    })
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

fn read_smaps(pid: u64) -> Option<Value> {
    let text = fs::read_to_string(format!("/proc/{pid}/smaps")).ok()?;
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
    use super::{Counts, Recorder};
    use serde_json::json;
    use std::fs::{self, OpenOptions};
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    #[test]
    fn records_only_while_enabled_and_exports_d2o_ring_shape() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("r2o-diagnostics-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut recorder = Recorder::new(dir.clone());
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
}
