use crate::catalog::{Catalog, CatalogError, DomainGroup, DomainObservation};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const DOMAIN_BLOCKED: u8 = 1;
const DOMAIN_DIRECT_CLEAR: u8 = 2;
const DOMAIN_PLAN_FAILED: u8 = 4;

#[derive(Clone, Debug)]
pub struct DiscoveryStatus {
    pub autopick: Value,
    pub probes_used: u64,
    pub client_unfit: u64,
}

impl Default for DiscoveryStatus {
    fn default() -> Self {
        Self {
            autopick: json!({
                "reason": "нет событий от datapath",
                "target": "",
                "plan_id": "",
                "datapath_events": 0,
                "suspect_events": 0,
                "transport": 6,
                "family": 4,
                "cooldown_seconds_left": null,
            }),
            probes_used: 0,
            client_unfit: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LiveGroupKey {
    pub suffix: String,
    pub plan_id: String,
    pub transport: u8,
    pub family: u8,
    pub shape: u8,
    pub probe_path: String,
    pub ech_origin: String,
}

impl From<&DomainGroup> for LiveGroupKey {
    fn from(group: &DomainGroup) -> Self {
        Self {
            suffix: group.suffix.clone(),
            plan_id: group.plan_id.clone(),
            transport: group.key.transport,
            family: group.key.family,
            shape: group.key.shape,
            probe_path: group.key.probe_path.clone(),
            ech_origin: group.key.ech_origin.clone(),
        }
    }
}

pub fn snapshot(
    catalog: &Catalog,
    catalog_path: &Path,
    active_groups: &HashSet<LiveGroupKey>,
    searches: Vec<Value>,
    measurements: Value,
    discovery_status: DiscoveryStatus,
) -> Result<Value, CatalogError> {
    let mut boxes = Vec::with_capacity(catalog.boxes.len());
    let mut targets = 0_u64;
    let mut confirms = 0_u64;
    for record in &catalog.boxes {
        let mut value = serde_json::to_value(record)
            .map_err(|error| CatalogError::new(format!("serialize live box: {error}")))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| CatalogError::new("serialized live box is not an object"))?;
        let fingerprint = object
            .remove("fingerprint")
            .unwrap_or_else(|| json!({"signals": []}));
        let mut signals = fingerprint
            .get("signals")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for signal in &mut signals {
            if let Some(signal_object) = signal.as_object_mut() {
                let kind = signal_object
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let volume = signal_object
                    .get("volume")
                    .and_then(Value::as_i64)
                    .unwrap_or(0) as i32;
                let ttl = signal_object
                    .get("ttl")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u8;
                let ttl_delta = signal_object
                    .get("ttl_delta")
                    .and_then(Value::as_i64)
                    .unwrap_or(0) as i32;
                let tos = signal_object
                    .get("tos")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u8;
                let ipid = signal_object
                    .get("ipid")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u16;
                signal_object.insert(
                    "human".into(),
                    Value::String(signal_human(&kind, volume, ttl, ttl_delta, tos, ipid)),
                );
            }
        }
        for plan in object
            .get_mut("plans")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if let Some(plan) = plan.as_object_mut() {
                plan.insert("human".into(), Value::String(String::new()));
            }
        }
        for binding in object
            .get_mut("bindings")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if let Some(binding) = binding.as_object_mut() {
                let level = binding.get("level").and_then(Value::as_i64).unwrap_or(0) as i32;
                let recheck = binding
                    .get("recheck_since")
                    .is_some_and(|value| !value.is_null());
                binding.insert("level_name".into(), Value::String(level_name(level).into()));
                binding.insert("recheck".into(), Value::Bool(recheck));
            }
        }
        targets += record.bindings.len() as u64;
        confirms += record
            .bindings
            .iter()
            .filter(|binding| {
                binding.enabled && binding.level >= 3 && binding.recheck_since.is_none()
            })
            .count() as u64;
        object.insert("signals".into(), Value::Array(signals));
        boxes.push(value);
    }

    let groups = catalog.domain_state.as_ref().map(|state| {
        state.groups.iter().map(|group| {
            let evidence = state.observations.iter().filter(|observation| group_evidence(group, observation))
                .map(|observation| Value::String(observation.name.clone())).collect::<Vec<_>>();
            let exceptions = state.observations.iter().filter(|observation| group_exception(catalog, group, observation))
                .map(|observation| json!({
                    "name": observation.name,
                    "reason": if observation.evidence & DOMAIN_DIRECT_CLEAR != 0 { "Напрямую работает" } else { "Общий план не подошёл" }
                })).collect::<Vec<_>>();
            json!({
                "suffix": group.suffix,
                "transport": group.key.transport,
                "family": group.key.family,
                "shape": group.key.shape,
                "evidence_count": group.evidence_count,
                "plan_id": group.plan_id,
                "probe_path": group.key.probe_path,
                "ech_origin": group.key.ech_origin,
                "active": active_groups.contains(&LiveGroupKey::from(group)),
                "evidence": evidence,
                "exceptions": exceptions,
            })
        }).collect::<Vec<_>>()
    }).unwrap_or_default();

    Ok(json!({
        "linked": true,
        "link_note": "",
        "catalog_at": catalog_path.to_string_lossy(),
        "boxes": boxes,
        "groups": groups,
        "searches": searches,
        "measurements": measurements,
        "autopick": discovery_status.autopick,
        "targets": targets,
        "confirms": confirms,
        "probes_used": discovery_status.probes_used,
        "client_unfit": discovery_status.client_unfit,
    }))
}

pub fn write_snapshot(path: &Path, value: &Value) -> Result<(), CatalogError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| CatalogError::new("live path has no file name"))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CatalogError::new(format!("system clock: {error}")))?
        .as_nanos();
    let mut temporary_name = file_name.to_os_string();
    temporary_name.push(format!(".new.{}.{}", std::process::id(), nonce));
    let temporary_path: PathBuf = path.with_file_name(temporary_name);
    let result = (|| {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|error| CatalogError::new(format!("serialize live snapshot: {error}")))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|error| CatalogError::new(format!("{}: {error}", temporary_path.display())))?;
        file.write_all(&bytes)
            .map_err(|error| CatalogError::new(format!("write live snapshot: {error}")))?;
        file.sync_all()
            .map_err(|error| CatalogError::new(format!("sync live snapshot: {error}")))?;
        drop(file);
        fs::rename(&temporary_path, path)
            .map_err(|error| CatalogError::new(format!("replace live snapshot: {error}")))?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| CatalogError::new(format!("sync live directory: {error}")))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn group_evidence(group: &DomainGroup, observation: &DomainObservation) -> bool {
    observation.evidence & DOMAIN_BLOCKED != 0
        && observation.key == group.key
        && observation.plan_id == group.plan_id
        && domain_member(&observation.name, &group.suffix)
}

fn group_exception(
    catalog: &Catalog,
    group: &DomainGroup,
    observation: &DomainObservation,
) -> bool {
    let direct_clear = observation.evidence & DOMAIN_DIRECT_CLEAR != 0;
    let failed_group_plan = observation.evidence & DOMAIN_PLAN_FAILED != 0
        && observation.plan_id == group.plan_id
        && !has_confirmed_exact_binding(catalog, observation);
    (direct_clear || failed_group_plan)
        && observation.key == group.key
        && domain_member(&observation.name, &group.suffix)
}

fn has_confirmed_exact_binding(catalog: &Catalog, observation: &DomainObservation) -> bool {
    catalog.boxes.iter().any(|box_record| {
        box_record.bindings.iter().any(|binding| {
            binding.enabled
                && binding.level >= 3
                && binding.recheck_since.is_none()
                && binding.kind == "name"
                && crate::domain::normalize(&binding.target)
                    .is_ok_and(|name| name == observation.name)
                && (binding.transport == observation.key.transport
                    || binding.transport == 0 && observation.key.transport == 6)
                && (binding.family == observation.key.family
                    || binding.family == 0 && observation.key.family == 4)
                && group_shape_fits(binding.shape, observation.key.shape)
                && group_path(binding.transport, &binding.probe_path)
                    == group_path(observation.key.transport, &observation.key.probe_path)
                && binding.ech_origin == observation.key.ech_origin
        })
    })
}

fn group_shape_fits(saved: u8, observed: u8) -> bool {
    saved == 0
        || saved == observed
        || saved == r2k_core::control::SHAPE_MODERN && observed == r2k_core::control::SHAPE_ECH_TCP
}

fn group_path(transport: u8, path: &str) -> &str {
    if transport == 17 || path.is_empty() {
        "/"
    } else {
        path
    }
}

fn domain_member(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn level_name(level: i32) -> &'static str {
    match level {
        1 => "транспорт установился",
        2 => "сервер ответил",
        3 => "обмен прошёл",
        4 => "прикладной обмен в проверенном объёме",
        5 => "подтверждён последующими соединениями",
        _ => "не измерено",
    }
}

fn signal_human(kind: &str, volume: i32, ttl: u8, ttl_delta: i32, tos: u8, ipid: u16) -> String {
    match kind {
        "rst" => format!(
            "подделанный сброс, TTL {ttl} (на {ttl_delta} от сервера), ToS 0x{tos:02x}, ip id {ipid}"
        ),
        "volume" => format!("обрыв по объёму около {volume} КБ"),
        "rx-volume" => format!("identity-ответ стабильно оборвался около {volume} КБ"),
        "rx-volume-wire" => {
            format!("TLS-запись дважды оборвалась около {volume} КБ RX; меньший gzip дошёл")
        }
        "silent" => "ответа на приветствие не было".into(),
        "repeat" => "приветствие повторено".into(),
        _ => kind.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Binding, BoxRecord, DomainState, Fingerprint, Plan, Signal};

    #[test]
    fn snapshot_projects_saved_catalog_and_exact_group_install_status() {
        let key = crate::catalog::GroupKey {
            transport: 6,
            family: 4,
            shape: 1,
            probe_path: "/".into(),
            ech_origin: String::new(),
        };
        let group = DomainGroup {
            suffix: "example.com".into(),
            plan_id: "plan-1".into(),
            key: key.clone(),
            evidence_count: 1,
            at: 1,
        };
        let catalog = Catalog {
            boxes: vec![BoxRecord {
                id: "box-1".into(),
                fingerprint: Fingerprint {
                    method: 2,
                    signals: vec![Signal {
                        kind: "volume".into(),
                        volume: 40,
                        seen: 2,
                        ..Signal::default()
                    }],
                },
                plans: vec![Plan {
                    id: "plan-1".into(),
                    text: "plan".into(),
                    enabled: true,
                    ..Plan::default()
                }],
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: "a.example.com".into(),
                    plan_id: "plan-1".into(),
                    level: 3,
                    enabled: true,
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            domain_state: Some(DomainState {
                groups: vec![group.clone()],
                observations: vec![
                    DomainObservation {
                        name: "a.example.com".into(),
                        plan_id: "plan-1".into(),
                        key: key.clone(),
                        evidence: DOMAIN_BLOCKED,
                        at: 1,
                    },
                    DomainObservation {
                        name: "a.example.com".into(),
                        plan_id: "plan-1".into(),
                        key: key.clone(),
                        evidence: DOMAIN_PLAN_FAILED,
                        at: 2,
                    },
                    DomainObservation {
                        name: "b.example.com".into(),
                        plan_id: "plan-1".into(),
                        key,
                        evidence: DOMAIN_PLAN_FAILED,
                        at: 3,
                    },
                ],
                ..DomainState::default()
            }),
            ..Catalog::default()
        };
        let active = HashSet::from([LiveGroupKey::from(&group)]);
        let search = json!({
            "target": "a.example.com",
            "family": 4,
            "transport": 6,
            "ip": "192.0.2.2",
            "port": 443,
            "phase": "проверяем выведенный план",
            "since": "2026-10-24T00:00:00Z",
            "attempts": 1,
            "probes": 3,
            "question": "",
            "candidate": "план поставлен",
            "source": "выведен из замера",
            "plan": "split sni_middle +0 · fake payload=1 poison=1…",
            "application": "точный APPLIED получен",
            "last_result": "план применён; получен полный HTTPS-ответ HTTP 200",
            "shape": 1,
        });
        let live = snapshot(
            &catalog,
            Path::new("/state/catalog.json"),
            &active,
            vec![search],
            json!({"active": 0, "limit": 2, "queued": 0}),
            DiscoveryStatus::default(),
        )
        .unwrap();
        assert_eq!(live["linked"], true);
        assert_eq!(live["targets"], 1);
        assert_eq!(live["confirms"], 1);
        assert_eq!(
            live["boxes"][0]["signals"][0]["human"],
            "обрыв по объёму около 40 КБ"
        );
        assert_eq!(
            live["boxes"][0]["bindings"][0]["level_name"],
            "обмен прошёл"
        );
        assert_eq!(live["groups"][0]["active"], true);
        assert_eq!(live["groups"][0]["evidence"][0], "a.example.com");
        assert_eq!(live["groups"][0]["exceptions"].as_array().unwrap().len(), 1);
        assert_eq!(live["groups"][0]["exceptions"][0]["name"], "b.example.com");
        assert_eq!(live["searches"][0]["phase"], "проверяем выведенный план");
        assert_eq!(live["searches"][0]["attempts"], 1);
        assert_eq!(live["searches"][0]["probes"], 3);
        assert_eq!(
            live["searches"][0]["plan"],
            "split sni_middle +0 · fake payload=1 poison=1…"
        );
        assert_eq!(live["searches"][0]["application"], "точный APPLIED получен");
        assert_eq!(
            live["searches"][0]["last_result"],
            "план применён; получен полный HTTPS-ответ HTTP 200"
        );
        for field in [
            "target",
            "family",
            "transport",
            "ip",
            "port",
            "phase",
            "since",
            "attempts",
            "probes",
            "question",
            "candidate",
            "source",
            "plan",
            "application",
            "last_result",
        ] {
            assert!(live["searches"][0].get(field).is_some(), "missing {field}");
        }
        for field in [
            "reason",
            "target",
            "plan_id",
            "datapath_events",
            "suspect_events",
            "transport",
            "family",
            "cooldown_seconds_left",
        ] {
            assert!(live["autopick"].get(field).is_some(), "missing {field}");
        }
        assert_eq!(live["probes_used"], 0);
        assert_eq!(live["client_unfit"], 0);
        assert_eq!(live["autopick"]["reason"], "нет событий от datapath");
        assert_eq!(live["autopick"]["datapath_events"], 0);
    }

    #[test]
    fn write_snapshot_atomically_replaces_the_panel_file() {
        let directory = std::env::temp_dir().join(format!(
            "r2o-live-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("live.json");
        write_snapshot(&path, &json!({"linked": true, "searches": []})).unwrap();
        let live: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(live["linked"], true);
        assert!(live["searches"].as_array().unwrap().is_empty());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
