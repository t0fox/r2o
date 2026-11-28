//! Локальный контекст снимка. Читаем только ограниченные поля существующих источников.

use super::{Path, Read, Value, fs, json};
use serde::Deserialize;
use std::io::BufReader;

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct DnsOrigin {
    pub configured: usize,
    pub active: usize,
    pub observed: usize,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct RawControllerStatus {
    pub requested: bool,
    pub ready: bool,
    pub reason: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct Components {
    pub catalog_snapshot_bytes: Option<u64>,
    pub catalog_snapshot_copies: Option<usize>,
    pub catalog_snapshot_owners: Option<usize>,
    pub catalog_generation: Option<u64>,
    pub catalog_dirty: Option<bool>,
    pub snapshot_payload_bytes: Option<u64>,
    pub discovery_suspects: Option<u64>,
    pub discovery_confirmations: Option<u64>,
    pub discovery_client_unfit: Option<u64>,
    pub tcp_order_experiments: Option<u64>,
    pub tcp_order_probes: Option<u64>,
    pub tcp_order_confirmations: Option<u64>,
    pub raw_discovery: Option<RawControllerStatus>,
    pub raw_trials: Option<[usize; 3]>,
    pub dns_inventory: usize,
    pub dns_by_source: [DnsOrigin; 6],
    pub dns_active: usize,
    pub dns_observed: usize,
    pub dns_health_current: usize,
    pub dns_answer: usize,
    pub dns_verified_recovery: usize,
    pub meta_enabled: Option<bool>,
    pub meta_observed_names: Option<usize>,
    pub meta_pending_searches: Option<usize>,
}

pub(super) fn process_totals(processes: &[Value]) -> Value {
    let mut count = 0;
    let mut totals = [(0_u64, 0_usize); 4];
    let fields = ["rss_kib", "anon_kib", "hwm_kib", "heap_live_bytes"];
    for (index, process) in processes.iter().enumerate() {
        let Some(pid) = process["pid"].as_u64().filter(|pid| *pid != 0) else {
            continue;
        };
        if processes[..index]
            .iter()
            .any(|previous| previous["pid"].as_u64() == Some(pid))
        {
            continue;
        }
        count += 1;
        for (key, (sum, measured)) in fields.into_iter().zip(&mut totals) {
            if let Some(value) = process[key].as_u64() {
                *sum = sum.saturating_add(value);
                *measured += 1;
            }
        }
    }
    let [rss, anonymous, hwm, heap] = totals.map(
        |(sum, measured)| json!({ "sum": (measured != 0).then_some(sum), "measured": measured }),
    );
    json!({
        "scope": "validated-r2o-pidfiles",
        "processes": count,
        "rss_kib": rss,
        "rss_anon_kib": anonymous,
        "sum_of_process_hwm_kib": hwm,
        "rust_heap_live_bytes": heap,
    })
}

fn bounded_text(path: &Path, limit: u64) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > limit {
        return None;
    }
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text).ok()?;
    (text.len() as u64 <= limit).then_some(text)
}

pub(super) fn network(proc_dir: &Path) -> Value {
    const MAX: usize = 32;
    let Some(text) = bounded_text(&proc_dir.join("net/dev"), 16 * 1024) else {
        return Value::Null;
    };
    let mut names = text.lines().skip(2).filter_map(|line| {
        let (iface, _) = line.split_once(':')?;
        let iface = iface.trim();
        (!iface.is_empty()
            && iface.len() < libc::IFNAMSIZ
            && iface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
        .then_some(iface)
    });
    let interfaces: Vec<_> = names
        .by_ref()
        .take(MAX)
        .map(|name| {
            let base = Path::new("/sys/class/net").join(name);
            let ifindex = (proc_dir == Path::new("/proc"))
                .then(|| super::read_number(&base.join("ifindex")))
                .flatten();
            let kind_hint = if name.starts_with("awg") {
                Some("amneziawg-name")
            } else if name.starts_with("wg") {
                Some("wireguard-name")
            } else if name.starts_with("ppp") {
                Some("ppp-name")
            } else {
                None
            };
            json!({"name": name, "ifindex": ifindex, "interface_name_hint": kind_hint})
        })
        .collect();
    let truncated = names.next().is_some();
    json!({
        "source": "proc-net-dev",
        "interfaces": interfaces,
        "truncated": truncated,
        "amneziawg_module_present": (proc_dir == Path::new("/proc") && Path::new("/sys/module/amneziawg").is_dir()).then_some(true),
        "wireguard_module_present": (proc_dir == Path::new("/proc") && Path::new("/sys/module/wireguard").is_dir()).then_some(true),
        "interface_presence_is_flow_proof": false,
    })
}

pub(super) fn telegram(
    health_dir: &Path,
    proc_dir: &Path,
    pid: Option<u64>,
    ticks: Option<u64>,
) -> Value {
    let Some(text) = bounded_text(&health_dir.join("d2ktg.health"), 512) else {
        return Value::Null;
    };
    let mut fields = text.split_whitespace();
    let (Some("D2KH1"), Some(heartbeat_pid), Some(start_ticks), Some(at_ms), Some(boot_id)) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Value::Null;
    };
    if pid.is_none()
        || ticks.is_none()
        || heartbeat_pid.parse().ok() != pid
        || start_ticks.parse().ok() != ticks
        || !bounded_text(&proc_dir.join("sys/kernel/random/boot_id"), 64)
            .is_some_and(|current| current.trim() == boot_id)
    {
        return Value::Null;
    }
    let flag = |field| match field {
        Some("0") => Some(false),
        Some("1") => Some(true),
        _ => None,
    };
    let connected = flag(fields.nth(3));
    let ready = flag(fields.next());
    let external = flag(fields.next());
    let age = bounded_text(&proc_dir.join("uptime"), 128).and_then(|uptime| {
        let millis = uptime.split_whitespace().next()?.parse::<f64>().ok()? * 1000.0;
        (millis.round() as u64).checked_sub(at_ms.parse().ok()?)
    });
    let fresh = age.is_some_and(|ms| ms <= 15_000);
    json!({
        "source": "watchdog-heartbeat",
        "age_ms": age,
        "fresh": fresh,
        "connected": fresh.then_some(connected).flatten(),
        "ready": fresh.then_some(ready).flatten(),
        "external_mode": fresh.then_some(external).flatten(),
        "end_to_end_result": null,
    })
}

fn saved<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Option<T> {
    let file = fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > limit {
        return None;
    }
    serde_json::from_reader(BufReader::new(file.take(limit + 1))).ok()
}

#[derive(Deserialize, serde::Serialize)]
pub(super) struct MetaResult {
    checked_at: u64,
    ipv4_prefixes: u64,
    ipv6_prefixes: u64,
    families: Vec<MetaFamily>,
}

#[derive(Deserialize, serde::Serialize)]
struct MetaFamily {
    product: String,
    observed: usize,
    dns_ok: usize,
    verified_domains: usize,
    checked_at: u64,
}

pub(super) fn meta_result(state: &Path) -> Option<MetaResult> {
    let report: MetaResult = saved(&state.join("meta-status.json"), 64 * 1024)?;
    // На данный момент источник пишет только несколько семейств продуктов.
    (report.families.len() <= r2k_core::meta::PRODUCTS.len()
        && report
            .families
            .iter()
            .all(|item| r2k_core::meta::PRODUCTS.contains(&item.product.as_str())))
    .then_some(report)
}

#[derive(Deserialize)]
struct TelegramCheck {
    state: TelegramCheckState,
    checked_at: u64,
    data_centers: Vec<TelegramDc>,
}

#[derive(Deserialize)]
struct TelegramDc {
    dc: u8,
    state: TelegramCheckState,
}

#[derive(Clone, Copy, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum TelegramCheckState {
    Healthy,
    Partial,
    Unavailable,
    Unverified,
}

pub(super) fn telegram_check(state: &Path) -> Value {
    let Some(report) = saved::<TelegramCheck>(&state.join("telegram-diagnostics.json"), 256 * 1024)
    else {
        return Value::Null;
    };
    if report.data_centers.len() != 5
        || !report
            .data_centers
            .iter()
            .enumerate()
            .all(|(index, dc)| usize::from(dc.dc) == index + 1)
    {
        return Value::Null;
    }
    json!({
        "scope": "previous-explicit-probe",
        "checked_at": report.checked_at,
        "state": report.state,
        "dc_states": report.data_centers.iter().map(|dc| dc.state).collect::<Vec<_>>(),
    })
}
