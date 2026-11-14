use crate::catalog::{Catalog, CatalogError, DomainGroup, DomainObservation};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const DOMAIN_BLOCKED: u8 = 1;
const DOMAIN_DIRECT_CLEAR: u8 = 2;
const DOMAIN_PLAN_FAILED: u8 = 4;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DnsServiceState {
    #[default]
    Detected,
    Checking,
    DirectOk,
    Failed,
}

/// C `dns_service_live` (`core/sched.c:1276-1305`).
#[derive(Clone, Debug)]
pub struct DnsServiceLive {
    pub generation: u64,
    pub ip: String,
    pub applied_plan_id: String,
    pub state: DnsServiceState,
    pub tcp_reachable: bool,
    pub tls_handshake: bool,
    pub http_status: i32,
    pub dns_answer: bool,
    pub plan_applied: bool,
    /// C `t->ver_ok` задачи T_DNS_HEALTH: план применился к пробному
    /// DNS-соединению. Без plan-based health-пробы остаётся false.
    pub candidate_plan_applied: bool,
    pub attempts: u32,
    /// Стенные секунды для live.json; None — проверки ещё не было.
    pub checked_at: Option<i64>,
    /// Монотонный срок следующей health-проверки.
    pub next_check: Option<std::time::Instant>,
    pub plan_applied_at: Option<i64>,
    pub reason: String,
}

impl Default for DnsServiceLive {
    fn default() -> Self {
        Self {
            generation: 0,
            ip: String::new(),
            applied_plan_id: String::new(),
            state: DnsServiceState::Detected,
            tcp_reachable: false,
            tls_handshake: false,
            http_status: 0,
            dns_answer: false,
            plan_applied: false,
            candidate_plan_applied: false,
            attempts: 0,
            checked_at: None,
            next_check: None,
            plan_applied_at: None,
            reason: String::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveryStatus {
    pub autopick: Value,
    pub probes_used: u64,
    pub client_unfit: u64,
    /// C `s->confirms`: подтверждения за сессию процесса, не число
    /// подтверждённых привязок в каталоге.
    pub confirms: u64,
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
            confirms: 0,
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

/// Снимок `installed_area` для live.json.
#[derive(Clone, Debug, Default)]
pub struct LiveAreaState {
    pub kind: u8,
    pub name: String,
    pub transport: u8,
    pub shape: u8,
    pub family: u8,
    pub plan_id: Option<String>,
    pub confirmed: bool,
    pub maybe_active: bool,
    pub remove_pending: bool,
    pub permanent: bool,
    pub retry_count: u32,
    pub reason: String,
    pub reason_code: u32,
    pub detail: String,
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

fn group_plan_available(catalog: &Catalog, group: &DomainGroup) -> bool {
    let proto = if group.key.transport == 17 {
        "quic"
    } else {
        "tls"
    };
    catalog.boxes.iter().any(|box_record| {
        box_record.plans.iter().any(|plan| {
            plan.enabled && !plan.text.is_empty() && plan.id == group.plan_id && plan.proto == proto
        })
    })
}

fn desired_exception(
    catalog: &Catalog,
    group: &DomainGroup,
    groups: &[DomainGroup],
    observation: &DomainObservation,
) -> bool {
    if !group_exception(catalog, group, observation) {
        return false;
    }
    if observation.evidence & DOMAIN_DIRECT_CLEAR != 0 {
        return true;
    }
    observation.evidence & DOMAIN_PLAN_FAILED != 0
        && !has_confirmed_exact_binding(catalog, observation)
        && groups.iter().any(|candidate| {
            candidate.key == observation.key
                && candidate.plan_id == observation.plan_id
                && domain_member(&observation.name, &candidate.suffix)
        })
}

fn group_exception_status(
    catalog: &Catalog,
    group: &DomainGroup,
    groups: &[DomainGroup],
    observations: &[DomainObservation],
    areas: &[LiveAreaState],
) -> (String, String, u32, String) {
    let mut found = false;
    let mut best = 0_u8;
    let mut state = "none".to_owned();
    let mut reason = String::new();
    let mut reason_code = 0;
    let mut detail = String::new();
    for observation in observations
        .iter()
        .filter(|observation| desired_exception(catalog, group, groups, observation))
    {
        found = true;
        let installed = areas.iter().find(|area| {
            area.kind == 2
                && area.name == observation.name
                && area.transport == group.key.transport
                && area.shape == group.key.shape
                && area.family == group.key.family
        });
        if let Some(area) = installed
            && area.confirmed
            && !area.remove_pending
        {
            continue;
        }
        let (candidate, rank) = if installed.is_some_and(|area| area.permanent) {
            ("rejected", 3)
        } else if installed.is_some_and(|area| area.retry_count > 0) {
            ("retrying", 2)
        } else {
            ("pending", 1)
        };
        if rank > best {
            best = rank;
            state = candidate.to_owned();
            if let Some(area) = installed {
                reason.clone_from(&area.reason);
                reason_code = area.reason_code;
                detail.clone_from(&area.detail);
            } else {
                reason.clear();
                reason_code = 0;
                detail.clear();
            }
        }
    }
    if found && best == 0 {
        state = "active".to_owned();
    }
    (state, reason, reason_code, detail)
}

pub fn snapshot(
    catalog: &Catalog,
    catalog_path: &Path,
    active_groups: &HashSet<LiveGroupKey>,
    searches: Vec<Value>,
    measurements: Value,
    discovery_status: DiscoveryStatus,
) -> Result<Value, CatalogError> {
    snapshot_with_areas(
        catalog,
        catalog_path,
        active_groups,
        searches,
        measurements,
        discovery_status,
        &[],
    )
}

pub fn snapshot_with_areas(
    catalog: &Catalog,
    catalog_path: &Path,
    active_groups: &HashSet<LiveGroupKey>,
    searches: Vec<Value>,
    measurements: Value,
    discovery_status: DiscoveryStatus,
    areas: &[LiveAreaState],
) -> Result<Value, CatalogError> {
    snapshot_with_areas_and_dns(
        catalog,
        catalog_path,
        active_groups,
        searches,
        measurements,
        discovery_status,
        areas,
        &[],
        &[],
    )
}

/// Полный снимок live.json с секцией `dns_services` (D2O current main).
pub fn snapshot_with_areas_and_dns(
    catalog: &Catalog,
    catalog_path: &Path,
    active_groups: &HashSet<LiveGroupKey>,
    searches: Vec<Value>,
    measurements: Value,
    discovery_status: DiscoveryStatus,
    areas: &[LiveAreaState],
    dns_services: &[r2k_core::dns_config::DnsService],
    dns_live: &[DnsServiceLive],
) -> Result<Value, CatalogError> {
    let mut boxes = Vec::with_capacity(catalog.boxes.len());
    let mut targets = 0_u64;
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
            let (exception_state, exception_reason, exception_reason_code, exception_detail) =
                group_exception_status(
                    catalog,
                    group,
                    &state.groups,
                    &state.observations,
                    areas,
                );
            let exceptions_ready = matches!(exception_state.as_str(), "none" | "active");
            let mut install_state = "pending";
            let mut install_reason = String::new();
            let mut install_reason_code = 0;
            let mut install_detail = String::new();
            let mut active = false;
            let mut possibly_active = false;
            let mut remove_pending = false;
            if !group_plan_available(catalog, group) {
                install_state = "rejected";
                install_reason = "plan_unavailable".into();
            } else if let Some(area) = areas.iter().find(|area| {
                area.kind == 1
                    && area.name == group.suffix
                    && area.transport == group.key.transport
                    && area.shape == group.key.shape
                    && area.family == group.key.family
                    && area.plan_id.as_deref().is_none_or(|plan| plan == group.plan_id)
            }) {
                remove_pending = area.remove_pending;
                install_reason.clone_from(&area.reason);
                install_reason_code = area.reason_code;
                install_detail.clone_from(&area.detail);
                if area.permanent {
                    install_state = "rejected";
                } else if area.remove_pending {
                    install_state = if area.retry_count > 0 { "retrying" } else { "removing" };
                } else if area.retry_count > 0 {
                    install_state = "retrying";
                } else if area.confirmed && exceptions_ready {
                    install_state = "active";
                    active = true;
                } else if (area.confirmed || area.maybe_active) && !exceptions_ready {
                    install_state = "removing";
                    install_detail = "Общее правило требуется снять перед установкой исключения".into();
                }
                possibly_active = (area.confirmed || area.maybe_active) && !active;
            }
            if areas.is_empty() {
                active = active_groups.contains(&LiveGroupKey::from(group));
            }
            json!({
                "suffix": group.suffix,
                "transport": group.key.transport,
                "family": group.key.family,
                "shape": group.key.shape,
                "evidence_count": group.evidence_count,
                "plan_id": group.plan_id,
                "probe_path": group.key.probe_path,
                "ech_origin": group.key.ech_origin,
                "install_state": install_state,
                "install_reason": install_reason,
                "install_reason_code": install_reason_code,
                "install_detail": install_detail,
                "exception_install_state": exception_state,
                "exception_install_reason": exception_reason,
                "exception_install_reason_code": exception_reason_code,
                "exception_install_detail": exception_detail,
                "remove_pending": remove_pending,
                "active": active,
                "possibly_active": possibly_active,
                "evidence": evidence,
                "exceptions": exceptions,
            })
        }).collect::<Vec<_>>()
    }).unwrap_or_default();

    let dns_services = r2o_live_dns_services(catalog, dns_services, dns_live);
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
        "confirms": discovery_status.confirms,
        "probes_used": discovery_status.probes_used,
        "client_unfit": discovery_status.client_unfit,
        "dns_services": dns_services,
    }))
}

/// C `write_live_dns_services` (`sched.c:6652`) для состояния «конфигурация
/// найдена, health-проб ещё нет»: state=detected, health-поля пустые.
fn r2o_live_dns_services(
    catalog: &Catalog,
    services: &[r2k_core::dns_config::DnsService],
    live: &[DnsServiceLive],
) -> Vec<Value> {
    services
        .iter()
        .enumerate()
        .map(|(index, service)| {
            let state = live.get(index).cloned().unwrap_or_default();
            let resolved_ip = if state.ip.is_empty() {
                if service.host.parse::<std::net::IpAddr>().is_ok() {
                    service.host.clone()
                } else {
                    String::new()
                }
            } else {
                state.ip.clone()
            };
            let transport = if service.protocol == "doq" { 17 } else { 6 };
            let family = if resolved_ip.contains(':') { 6 } else { 4 };
            let target = if service.sni.is_empty() {
                &service.host
            } else {
                &service.sni
            };
            let known_plan_id = catalog
                .boxes
                .iter()
                .flat_map(|box_record| &box_record.bindings)
                .find(|binding| {
                    binding.enabled
                        && binding.recheck_since.is_none()
                        && binding.target == *target
                        && (if binding.transport == 0 {
                            6
                        } else {
                            binding.transport
                        }) == transport
                        && (if binding.family == 0 {
                            4
                        } else {
                            binding.family
                        }) == family
                })
                .map(|binding| binding.plan_id.clone())
                .unwrap_or_default();
            let detected_reason = if resolved_ip.is_empty() {
                "Конфигурация найдена; ожидается наблюдение реального адреса endpoint."
            } else {
                "Адрес endpoint обнаружен; автоматическая проверка ожидает очереди."
            };
            let candidate_plan_applied = state.candidate_plan_applied;
            let dns_answer_via_plan = candidate_plan_applied && state.dns_answer;
            let (state_name, reason) = if dns_answer_via_plan {
                (
                    "bypass_ok",
                    "Плановый DoH-зонд получил корректный DNS-ответ; применение к обычному потоку показывается отдельно.".to_owned(),
                )
            } else {
                match state.state {
                    DnsServiceState::Checking => (
                        "checking",
                        if state.reason.is_empty() {
                            "Автоматически проверяется корректный DNS-ответ endpoint.".to_owned()
                        } else {
                            state.reason.clone()
                        },
                    ),
                    DnsServiceState::DirectOk => (
                        "direct_ok",
                        if state.reason.is_empty() {
                            "Прямое соединение подтверждено.".to_owned()
                        } else {
                            state.reason.clone()
                        },
                    ),
                    DnsServiceState::Failed if state.plan_applied => (
                        "plan_applied",
                        format!(
                            "Датапат подтвердил план {} на DNS-соединении; DNS-ответ отдельно ещё не подтверждён. Автопроверка: {}",
                            state.applied_plan_id,
                            if state.reason.is_empty() {
                                "DNS-ответ не подтверждён; одиночная ошибка не считается блокировкой."
                            } else {
                                &state.reason
                            }
                        ),
                    ),
                    DnsServiceState::Detected if state.plan_applied => (
                        "plan_applied",
                        format!(
                            "Датапат подтвердил план {} на DNS-соединении; DNS-ответ отдельно ещё не подтверждён.",
                            state.applied_plan_id
                        ),
                    ),
                    DnsServiceState::Failed => (
                        "failed",
                        if state.reason.is_empty() {
                            "DNS-ответ не подтверждён; одиночная ошибка не считается блокировкой."
                                .to_owned()
                        } else {
                            state.reason.clone()
                        },
                    ),
                    DnsServiceState::Detected => ("detected", detected_reason.to_owned()),
                }
            };
            let path = service.path.split('?').next().unwrap_or("/").to_owned();
            json!({
                "protocol": service.protocol,
                "host": service.host,
                "port": service.port,
                "sni": service.sni,
                "path": path,
                "source": service.source,
                "state": state_name,
                "status_reason": reason,
                "resolved_ip": resolved_ip,
                "checked_at": r2o_live_optional_time(state.checked_at),
                "direct_tcp_reachable": state.tcp_reachable,
                "direct_tls_handshake": state.tls_handshake,
                "http_status": state.http_status,
                "check_attempts": state.attempts,
                "known_plan_id": known_plan_id,
                "applied_plan_id": state.applied_plan_id,
                "plan_applied_at": r2o_live_optional_time(state.plan_applied_at),
                "plan_applied": state.plan_applied,
                "candidate_plan_applied": candidate_plan_applied,
                "dns_answer_via_plan": dns_answer_via_plan,
                "dns_answer_confirmed": state.dns_answer,
            })
        })
        .collect()
}

fn r2o_live_optional_time(seconds: Option<i64>) -> Value {
    use time::format_description::well_known::Rfc3339;
    seconds
        .filter(|value| *value > 0)
        .and_then(|value| time::OffsetDateTime::from_unix_timestamp(value).ok())
        .and_then(|value| value.format(&Rfc3339).ok())
        .map(Value::String)
        .unwrap_or(Value::Null)
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
        && observation.evidence & (DOMAIN_DIRECT_CLEAR | DOMAIN_PLAN_FAILED) == 0
        && observation.name != group.suffix
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
        && !has_confirmed_exact_binding(catalog, observation);
    (direct_clear || failed_group_plan)
        && observation.key == group.key
        && domain_member(&observation.name, &group.suffix)
}

/// Единая реализация C `own_exact_confirmed` (`sched.c:6278-6293`):
/// точное имя, транспорт/семейство и `tcp_context(shape, tcp_profile)`
/// для TCP. Дубль в live.rs раньше расходился с main.rs; оставлен один.
fn has_confirmed_exact_binding(catalog: &Catalog, observation: &DomainObservation) -> bool {
    crate::discovery::has_confirmed_exact_binding(catalog, observation)
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
            DiscoveryStatus {
                confirms: 1,
                ..DiscoveryStatus::default()
            },
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
    fn live_group_install_and_exception_states_match_c() {
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
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                plans: vec![Plan {
                    id: "plan-1".into(),
                    proto: "tls".into(),
                    text: "plan".into(),
                    enabled: true,
                    ..Plan::default()
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
                        name: "b.example.com".into(),
                        plan_id: "plan-1".into(),
                        key: key.clone(),
                        evidence: DOMAIN_DIRECT_CLEAR,
                        at: 2,
                    },
                ],
                ..DomainState::default()
            }),
            ..Catalog::default()
        };
        let group_area =
            |confirmed: bool, retry: u32, reason: &str, permanent: bool| LiveAreaState {
                kind: 1,
                name: "example.com".into(),
                transport: 6,
                shape: 1,
                family: 4,
                plan_id: Some("plan-1".into()),
                confirmed,
                reason: reason.into(),
                retry_count: retry,
                permanent,
                ..LiveAreaState::default()
            };
        let exception_area =
            |confirmed: bool, retry: u32, reason: &str, permanent: bool| LiveAreaState {
                kind: 2,
                name: "b.example.com".into(),
                transport: 6,
                shape: 1,
                family: 4,
                confirmed,
                reason: reason.into(),
                retry_count: retry,
                permanent,
                ..LiveAreaState::default()
            };
        let snapshot = |areas: &[LiveAreaState], catalog: &Catalog| {
            snapshot_with_areas(
                catalog,
                Path::new("/state/catalog.json"),
                &HashSet::new(),
                Vec::new(),
                json!({}),
                DiscoveryStatus::default(),
                areas,
            )
            .unwrap()
        };

        let active = snapshot(
            &[
                group_area(true, 0, "", false),
                exception_area(true, 0, "", false),
            ],
            &catalog,
        );
        assert_eq!(active["groups"][0]["install_state"], "active");
        assert_eq!(active["groups"][0]["exception_install_state"], "active");
        assert_eq!(active["groups"][0]["active"], true);
        assert_eq!(active["groups"][0]["possibly_active"], false);

        let pending_exception = snapshot(
            &[
                group_area(true, 0, "", false),
                exception_area(false, 1, "bad_plan", true),
            ],
            &catalog,
        );
        assert_eq!(
            pending_exception["groups"][0]["exception_install_state"],
            "rejected"
        );
        assert_eq!(pending_exception["groups"][0]["install_state"], "removing");
        assert_eq!(pending_exception["groups"][0]["possibly_active"], true);

        let no_area = snapshot(&[], &catalog);
        assert_eq!(no_area["groups"][0]["install_state"], "pending");

        let removing = snapshot(
            &[
                LiveAreaState {
                    remove_pending: true,
                    ..group_area(true, 0, "", false)
                },
                exception_area(true, 0, "", false),
            ],
            &catalog,
        );
        assert_eq!(removing["groups"][0]["install_state"], "removing");
        assert_eq!(removing["groups"][0]["remove_pending"], true);

        let retrying = snapshot(&[group_area(false, 2, "ack_timeout", false)], &catalog);
        assert_eq!(retrying["groups"][0]["install_state"], "retrying");
        assert_eq!(retrying["groups"][0]["install_reason"], "ack_timeout");

        catalog.boxes[0].plans[0].enabled = false;
        let unavailable = snapshot(&[group_area(true, 0, "", false)], &catalog);
        assert_eq!(unavailable["groups"][0]["install_state"], "rejected");
        assert_eq!(
            unavailable["groups"][0]["install_reason"],
            "plan_unavailable"
        );
    }

    #[test]
    fn live_groups_differential_matches_c() {
        let key = crate::catalog::GroupKey {
            transport: 6,
            family: 4,
            shape: 1,
            probe_path: String::new(),
            ech_origin: String::new(),
        };
        let catalog = |plan_enabled: bool| Catalog {
            boxes: vec![BoxRecord {
                plans: vec![Plan {
                    id: "plan-1".into(),
                    proto: "tls".into(),
                    text: "plan".into(),
                    enabled: plan_enabled,
                    successes: 1,
                    ..Plan::default()
                }],
                ..BoxRecord::default()
            }],
            domain_state: Some(DomainState {
                groups: vec![DomainGroup {
                    suffix: "example.com".into(),
                    plan_id: "plan-1".into(),
                    key: key.clone(),
                    evidence_count: 1,
                    at: 1,
                }],
                observations: vec![
                    DomainObservation {
                        name: "a.example.com".into(),
                        plan_id: "plan-1".into(),
                        key: key.clone(),
                        evidence: DOMAIN_BLOCKED,
                        at: 1,
                    },
                    DomainObservation {
                        name: "b.example.com".into(),
                        plan_id: "plan-1".into(),
                        key: key.clone(),
                        evidence: DOMAIN_DIRECT_CLEAR,
                        at: 2,
                    },
                    DomainObservation {
                        name: "example.com".into(),
                        plan_id: "plan-1".into(),
                        key: key.clone(),
                        evidence: DOMAIN_BLOCKED,
                        at: 3,
                    },
                    DomainObservation {
                        name: "d.example.com".into(),
                        plan_id: "plan-2".into(),
                        key: key.clone(),
                        evidence: DOMAIN_BLOCKED | DOMAIN_PLAN_FAILED,
                        at: 4,
                    },
                ],
                ..DomainState::default()
            }),
            ..Catalog::default()
        };
        let area = |kind: u8,
                    name: &str,
                    plan_id: Option<&str>,
                    confirmed: bool,
                    maybe_active: bool,
                    remove_pending: bool,
                    permanent: bool,
                    retry_count: u32,
                    reason: &str,
                    reason_code: u32,
                    detail: &str| LiveAreaState {
            kind,
            name: name.into(),
            transport: 6,
            shape: 1,
            family: 4,
            plan_id: plan_id.map(str::to_owned),
            confirmed,
            maybe_active,
            remove_pending,
            permanent,
            retry_count,
            reason: reason.into(),
            reason_code,
            detail: detail.into(),
        };
        let groups = |plan_enabled: bool, areas: &[LiveAreaState]| {
            let catalog = catalog(plan_enabled);
            let live = snapshot_with_areas(
                &catalog,
                Path::new("/state/catalog.json"),
                &HashSet::new(),
                Vec::new(),
                json!({}),
                DiscoveryStatus::default(),
                areas,
            )
            .unwrap();
            live["groups"][0].clone()
        };
        let active_group = area(
            1,
            "example.com",
            Some("plan-1"),
            true,
            false,
            false,
            false,
            0,
            "",
            0,
            "",
        );
        let active_exc = area(
            2,
            "b.example.com",
            None,
            true,
            false,
            false,
            false,
            0,
            "",
            0,
            "",
        );
        let retry_group = area(
            1,
            "example.com",
            Some("plan-1"),
            false,
            true,
            false,
            false,
            2,
            "ack_timeout",
            0,
            "ACK не пришёл",
        );
        let rejected_group = area(
            1,
            "example.com",
            Some("plan-1"),
            false,
            true,
            false,
            true,
            1,
            "bad_plan",
            17,
            "план не разобрался",
        );
        let removing_group = area(
            1,
            "example.com",
            Some("plan-1"),
            true,
            false,
            true,
            false,
            0,
            "",
            0,
            "",
        );
        let removing_retry_group = area(
            1,
            "example.com",
            Some("plan-1"),
            true,
            false,
            true,
            false,
            1,
            "ack_timeout",
            0,
            "",
        );
        let retry_exc = area(
            2,
            "b.example.com",
            None,
            false,
            true,
            false,
            false,
            1,
            "ack_timeout",
            0,
            "ACK не пришёл",
        );
        let rejected_exc = area(
            2,
            "b.example.com",
            None,
            false,
            true,
            false,
            true,
            1,
            "bad_args",
            9,
            "аргументы команды не разобрались",
        );

        let mut scenarios = Vec::new();
        scenarios.push(
            json!({"scenario": "active", "groups": [groups(true, &[active_group.clone(), active_exc.clone()])]}),
        );
        scenarios.push(
            json!({"scenario": "retrying", "groups": [groups(true, &[retry_group, active_exc.clone()])]}),
        );
        scenarios.push(json!({"scenario": "rejected", "groups": [groups(true, &[rejected_group, active_exc.clone()])]}));
        scenarios.push(json!({"scenario": "remove_pending", "groups": [groups(true, &[removing_group, active_exc.clone()])]}));
        scenarios.push(json!({"scenario": "remove_pending_retry", "groups": [groups(true, &[removing_retry_group, active_exc.clone()])]}));
        scenarios.push(json!({"scenario": "exception_retrying", "groups": [groups(true, &[active_group.clone(), retry_exc])]}));
        scenarios.push(json!({"scenario": "exception_rejected", "groups": [groups(true, &[active_group.clone(), rejected_exc])]}));
        scenarios.push(json!({"scenario": "no_area", "groups": [groups(true, &[])]}));
        scenarios.push(json!({"scenario": "plan_unavailable", "groups": [groups(false, &[active_group.clone(), active_exc.clone()])]}));
        let mut no_exc_catalog = catalog(true);
        if let Some(state) = &mut no_exc_catalog.domain_state {
            state.observations.truncate(1);
        }
        let no_exc = snapshot_with_areas(
            &no_exc_catalog,
            Path::new("/state/catalog.json"),
            &HashSet::new(),
            Vec::new(),
            json!({}),
            DiscoveryStatus::default(),
            &[active_group, active_exc],
        )
        .unwrap();
        scenarios
            .push(json!({"scenario": "no_exceptions", "groups": [no_exc["groups"][0].clone()]}));

        assert_eq!(
            scenarios[0]["groups"][0]["evidence"],
            json!(["a.example.com"])
        );
        assert_eq!(scenarios[0]["groups"][0]["install_state"], "active");
        assert_eq!(scenarios[1]["groups"][0]["install_state"], "retrying");
        assert_eq!(scenarios[2]["groups"][0]["install_reason"], "bad_plan");
        assert_eq!(scenarios[4]["groups"][0]["install_state"], "retrying");
        assert_eq!(scenarios[7]["groups"][0]["install_state"], "pending");
        assert_eq!(
            scenarios[8]["groups"][0]["install_reason"],
            "plan_unavailable"
        );
        if let Ok(path) = std::env::var("R2O_LIVE_GROUPS_DIFF_OUTPUT") {
            std::fs::write(path, serde_json::to_string(&scenarios).unwrap()).unwrap();
        }
    }

    #[test]
    fn live_dns_state_machine_maps_current_d2o_states() {
        use r2k_core::dns_config::DnsService;

        let service = DnsService {
            protocol: "doh".into(),
            host: "dns.example".into(),
            sni: "dns.example".into(),
            path: "/dns-query".into(),
            bootstrap_dns: String::new(),
            source: "https-dns-proxy".into(),
            port: 443,
        };
        let base = DnsServiceLive {
            generation: 7,
            ip: "198.51.100.80".into(),
            ..DnsServiceLive::default()
        };
        let states = [
            DnsServiceLive {
                state: DnsServiceState::Checking,
                attempts: 2,
                reason: "Автоматически проверяется корректный DNS-ответ endpoint.".into(),
                ..base.clone()
            },
            DnsServiceLive {
                state: DnsServiceState::DirectOk,
                tcp_reachable: true,
                tls_handshake: true,
                http_status: 200,
                dns_answer: true,
                attempts: 1,
                checked_at: Some(1_700_000_000),
                reason: "doh: получен корректный DNS-ответ".into(),
                ..base.clone()
            },
            DnsServiceLive {
                state: DnsServiceState::Failed,
                tcp_reachable: true,
                http_status: 413,
                reason: "HTTP 413: это ошибка endpoint".into(),
                ..base.clone()
            },
            DnsServiceLive {
                plan_applied: true,
                applied_plan_id: "ab".repeat(16),
                plan_applied_at: Some(1_700_000_001),
                ..base.clone()
            },
        ];
        let expected = ["checking", "direct_ok", "failed", "plan_applied"];
        for (live, expected) in states.iter().zip(expected) {
            let snapshot = snapshot_with_areas_and_dns(
                &Catalog::default(),
                Path::new("/state/catalog.json"),
                &HashSet::new(),
                Vec::new(),
                json!({}),
                DiscoveryStatus::default(),
                &[],
                std::slice::from_ref(&service),
                std::slice::from_ref(live),
            )
            .unwrap();
            assert_eq!(snapshot["dns_services"][0]["state"], expected);
            assert_eq!(snapshot["dns_services"][0]["resolved_ip"], "198.51.100.80");
        }
        let direct = snapshot_with_areas_and_dns(
            &Catalog::default(),
            Path::new("/state/catalog.json"),
            &HashSet::new(),
            Vec::new(),
            json!({}),
            DiscoveryStatus::default(),
            &[],
            std::slice::from_ref(&service),
            &[states[1].clone()],
        )
        .unwrap();
        assert_eq!(
            direct["dns_services"][0]["checked_at"],
            "2023-11-14T22:13:20Z"
        );
        assert_eq!(direct["dns_services"][0]["direct_tcp_reachable"], true);
        assert_eq!(direct["dns_services"][0]["dns_answer_confirmed"], true);
        let applied = snapshot_with_areas_and_dns(
            &Catalog::default(),
            Path::new("/state/catalog.json"),
            &HashSet::new(),
            Vec::new(),
            json!({}),
            DiscoveryStatus::default(),
            &[],
            std::slice::from_ref(&service),
            &[states[3].clone()],
        )
        .unwrap();
        assert_eq!(applied["dns_services"][0]["plan_applied"], true);
        assert_eq!(
            applied["dns_services"][0]["plan_applied_at"],
            "2023-11-14T22:13:21Z"
        );
        assert_eq!(
            applied["dns_services"][0]["applied_plan_id"],
            "ab".repeat(16)
        );
    }

    #[test]
    fn dns_live_differential_matches_current_d2o() {
        use crate::catalog::{Binding, BoxRecord, Plan};
        use r2k_core::dns_config::DnsService;

        let catalog = Catalog {
            boxes: vec![BoxRecord {
                id: "box-dns".into(),
                plans: vec![Plan {
                    id: "plan-dns".into(),
                    proto: "tls".into(),
                    text: "r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n".into(),
                    enabled: true,
                    successes: 1,
                    ..Plan::default()
                }],
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: "dns.example".into(),
                    plan_id: "plan-dns".into(),
                    level: 3,
                    enabled: true,
                    transport: 6,
                    family: 4,
                    shape: 1,
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        let services = vec![
            DnsService {
                protocol: "doh".into(),
                host: "dns.example".into(),
                sni: "dns.example".into(),
                path: "/dns-query?token=secret".into(),
                bootstrap_dns: String::new(),
                source: "https-dns-proxy".into(),
                port: 443,
            },
            DnsService {
                protocol: "dot".into(),
                host: "1.1.1.1".into(),
                sni: String::new(),
                path: "/".into(),
                bootstrap_dns: String::new(),
                source: "dnsproxy".into(),
                port: 853,
            },
            DnsService {
                protocol: "doq".into(),
                host: "2001:db8::1".into(),
                sni: String::new(),
                path: "/".into(),
                bootstrap_dns: String::new(),
                source: "doqd".into(),
                port: 853,
            },
        ];
        let live = snapshot_with_areas_and_dns(
            &catalog,
            Path::new("/state/catalog.json"),
            &HashSet::new(),
            Vec::new(),
            json!({}),
            DiscoveryStatus::default(),
            &[],
            &services,
            &[],
        )
        .unwrap();
        if let Ok(path) = std::env::var("R2O_DNS_LIVE_DIFF_OUTPUT") {
            std::fs::write(
                path,
                serde_json::to_string(&json!({"dns_services": live["dns_services"]})).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(live["dns_services"][0]["known_plan_id"], "plan-dns");
        assert_eq!(live["dns_services"][0]["path"], "/dns-query");
        assert_eq!(live["dns_services"][1]["resolved_ip"], "1.1.1.1");
        assert_eq!(live["dns_services"][2]["resolved_ip"], "2001:db8::1");
    }

    #[test]
    fn live_dns_services_section_matches_current_d2o_shape() {
        use crate::catalog::{Binding, BoxRecord};
        use r2k_core::dns_config::DnsService;

        let catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: "dns.example".into(),
                    plan_id: "plan-dns".into(),
                    enabled: true,
                    transport: 6,
                    family: 4,
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        let services = vec![
            DnsService {
                protocol: "doh".into(),
                host: "dns.example".into(),
                sni: "dns.example".into(),
                path: "/dns-query?token=secret".into(),
                bootstrap_dns: String::new(),
                source: "https-dns-proxy".into(),
                port: 443,
            },
            DnsService {
                protocol: "dot".into(),
                host: "1.1.1.1".into(),
                sni: String::new(),
                path: "/".into(),
                bootstrap_dns: String::new(),
                source: "dnsproxy".into(),
                port: 853,
            },
            DnsService {
                protocol: "doq".into(),
                host: "2001:db8::1".into(),
                sni: String::new(),
                path: "/".into(),
                bootstrap_dns: String::new(),
                source: "doqd".into(),
                port: 853,
            },
        ];
        let live = snapshot_with_areas_and_dns(
            &catalog,
            Path::new("/state/catalog.json"),
            &HashSet::new(),
            Vec::new(),
            json!({}),
            DiscoveryStatus::default(),
            &[],
            &services,
            &[],
        )
        .unwrap();
        let section = live["dns_services"].as_array().unwrap();
        assert_eq!(section.len(), 3);
        assert_eq!(section[0]["protocol"], "doh");
        assert_eq!(section[0]["path"], "/dns-query");
        assert_eq!(section[0]["state"], "detected");
        assert_eq!(section[0]["known_plan_id"], "plan-dns");
        assert_eq!(section[0]["resolved_ip"], "");
        assert_eq!(section[0]["plan_applied_at"], Value::Null);
        assert_eq!(section[1]["resolved_ip"], "1.1.1.1");
        assert_eq!(section[1]["known_plan_id"], "");
        assert_eq!(section[2]["resolved_ip"], "2001:db8::1");
        assert_eq!(section[2]["port"], 853);
        // Плоский пустой набор — пустой массив, а не пропущенное поле.
        let empty = snapshot_with_areas_and_dns(
            &Catalog::default(),
            Path::new("/state/catalog.json"),
            &HashSet::new(),
            Vec::new(),
            json!({}),
            DiscoveryStatus::default(),
            &[],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(empty["dns_services"], json!([]));
    }

    #[test]
    fn live_dns_bypass_state_requires_plan_and_dns_answer() {
        use r2k_core::dns_config::DnsService;

        let service = DnsService {
            protocol: "doh".into(),
            host: "dns.example".into(),
            sni: "dns.example".into(),
            path: "/dns-query".into(),
            bootstrap_dns: String::new(),
            source: "https-dns-proxy".into(),
            port: 443,
        };
        let live = DnsServiceLive {
            generation: 1,
            plan_applied: true,
            candidate_plan_applied: true,
            applied_plan_id: "ab".repeat(16),
            dns_answer: true,
            plan_applied_at: Some(1000),
            ..DnsServiceLive::default()
        };
        let snapshot = snapshot_with_areas_and_dns(
            &Catalog::default(),
            Path::new("/state/catalog.json"),
            &HashSet::new(),
            Vec::new(),
            json!({}),
            DiscoveryStatus::default(),
            &[],
            std::slice::from_ref(&service),
            std::slice::from_ref(&live),
        )
        .unwrap();
        assert_eq!(snapshot["dns_services"][0]["state"], "bypass_ok");
        assert_eq!(snapshot["dns_services"][0]["candidate_plan_applied"], true);
        assert_eq!(snapshot["dns_services"][0]["dns_answer_via_plan"], true);
    }

    #[test]
    fn live_confirms_counts_session_events_not_catalog_bindings() {
        use crate::catalog::{Binding, BoxRecord};

        let catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![
                    Binding {
                        kind: "name".into(),
                        target: "a.example.com".into(),
                        plan_id: "plan-1".into(),
                        level: 3,
                        confirmed: 10,
                        successes: 2,
                        enabled: true,
                        transport: 6,
                        family: 4,
                        shape: 1,
                        ..Binding::default()
                    },
                    Binding {
                        kind: "name".into(),
                        target: "b.example.com".into(),
                        plan_id: "plan-1".into(),
                        level: 4,
                        confirmed: 11,
                        successes: 3,
                        enabled: true,
                        transport: 6,
                        family: 4,
                        shape: 1,
                        ..Binding::default()
                    },
                ],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        let snapshot = |confirms| {
            snapshot(
                &catalog,
                Path::new("/state/catalog.json"),
                &HashSet::new(),
                Vec::new(),
                json!({}),
                DiscoveryStatus {
                    confirms,
                    ..DiscoveryStatus::default()
                },
            )
            .unwrap()
        };
        // C `confirms` — счётчик подтверждений за сессию процесса, а не
        // число подтверждённых привязок в каталоге.
        assert_eq!(snapshot(0)["confirms"], 0);
        assert_eq!(snapshot(0)["targets"], 2);
        assert_eq!(snapshot(7)["confirms"], 7);
    }

    #[test]
    fn live_snapshot_differential_matches_c() {
        use crate::catalog::{Binding, BoxRecord, Fingerprint, GroupKey, Plan, Signal};

        let key = GroupKey {
            transport: 6,
            family: 4,
            shape: 1,
            probe_path: String::new(),
            ech_origin: String::new(),
        };
        let catalog = Catalog {
            boxes: vec![
                BoxRecord {
                    id: "box-1".into(),
                    created: 1000,
                    updated: 2000,
                    fingerprint: Fingerprint {
                        method: 2,
                        signals: vec![
                            Signal {
                                kind: "volume".into(),
                                volume: 40,
                                seen: 2,
                                ..Signal::default()
                            },
                            Signal {
                                kind: "rx-volume".into(),
                                volume: 16,
                                seen: 3,
                                packets: 22,
                                ..Signal::default()
                            },
                        ],
                    },
                    plans: vec![
                        Plan {
                            id: "plan-1".into(),
                            proto: "tls".into(),
                            text: "r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n".into(),
                            added: 1100,
                            successes: 5,
                            enabled: true,
                        },
                        Plan {
                            id: "plan-2".into(),
                            proto: "http".into(),
                            text: "r2o-plan 1 5\nproto tcp http\nsegment 1400\n".into(),
                            added: 1200,
                            successes: 1,
                            enabled: true,
                        },
                    ],
                    bindings: vec![
                        Binding {
                            kind: "name".into(),
                            target: "example.com".into(),
                            plan_id: "plan-1".into(),
                            level: 3,
                            confirmed: 1500,
                            successes: 4,
                            enabled: true,
                            transport: 6,
                            family: 4,
                            shape: 1,
                            tcp_profile: 0,
                            verified_by: 1,
                            input: 2,
                            probe_path: "/main.css".into(),
                            budget: 3,
                            ..Binding::default()
                        },
                        Binding {
                            kind: "name".into(),
                            target: "other.example".into(),
                            plan_id: "plan-3".into(),
                            level: 1,
                            confirmed: 1600,
                            successes: 1,
                            enabled: false,
                            transport: 6,
                            family: 6,
                            shape: 0,
                            recheck_since: Some(1700),
                            ..Binding::default()
                        },
                    ],
                    ..BoxRecord::default()
                },
                BoxRecord {
                    id: "box-2".into(),
                    created: 3000,
                    updated: 3000,
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
                        id: "plan-3".into(),
                        proto: "tls".into(),
                        text: "r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n".into(),
                        added: 1100,
                        successes: 2,
                        enabled: false,
                    }],
                    bindings: vec![Binding {
                        kind: "addr".into(),
                        target: "198.51.100.80".into(),
                        plan_id: "plan-3".into(),
                        level: 3,
                        confirmed: 3000,
                        successes: 2,
                        enabled: true,
                        transport: 6,
                        family: 4,
                        shape: 1,
                        ..Binding::default()
                    }],
                    ..BoxRecord::default()
                },
            ],
            domain_state: Some(DomainState {
                groups: vec![DomainGroup {
                    suffix: "example.com".into(),
                    plan_id: "plan-1".into(),
                    key: key.clone(),
                    evidence_count: 2,
                    at: 1500,
                }],
                observations: vec![
                    DomainObservation {
                        name: "a.example.com".into(),
                        plan_id: "plan-1".into(),
                        key: key.clone(),
                        evidence: DOMAIN_BLOCKED,
                        at: 1400,
                    },
                    DomainObservation {
                        name: "b.example.com".into(),
                        plan_id: "plan-1".into(),
                        key,
                        evidence: DOMAIN_DIRECT_CLEAR,
                        at: 1450,
                    },
                ],
                ..DomainState::default()
            }),
            ..Catalog::default()
        };
        let areas = [LiveAreaState {
            kind: 1,
            name: "example.com".into(),
            transport: 6,
            shape: 1,
            family: 4,
            plan_id: Some("plan-1".into()),
            confirmed: true,
            ..LiveAreaState::default()
        }];
        let measurements = json!({
            "active": 1,
            "limit": 3,
            "queued": 0,
            "cores": 4,
            "free_pct": 75,
            "mem_avail_mb": 500,
            "mem_total_mb": 1024,
            "conntrack_pct": 10,
            "limited_by": "процессор",
        });
        let status = DiscoveryStatus {
            autopick: json!({
                "reason": "поиск не активен; ожидается новый сигнал datapath",
                "target": "target.example",
                "plan_id": "",
                "datapath_events": 10,
                "suspect_events": 5,
                "transport": 6,
                "family": 4,
                "cooldown_seconds_left": null,
            }),
            probes_used: 42,
            client_unfit: 3,
            confirms: 7,
        };
        let searches = vec![json!({
            "target": "",
            "family": 0,
            "transport": 0,
            "ip": "",
            "port": 0,
            "phase": "распознаём поведение",
            "since": "1970-01-01T00:33:24Z",
            "attempts": 0,
            "probes": 0,
            "question": "",
            "candidate": "",
            "source": "",
        })];
        let live = snapshot_with_areas(
            &catalog,
            Path::new("catalog.json"),
            &HashSet::new(),
            searches,
            measurements,
            status,
            &areas,
        )
        .unwrap();
        assert_eq!(live["targets"], 3);
        assert_eq!(live["confirms"], 7);
        assert_eq!(live["groups"][0]["exception_install_state"], "pending");
        assert_eq!(live["groups"][0]["install_state"], "removing");
        assert_eq!(live["groups"][0]["active"], false);
        assert_eq!(live["groups"][0]["possibly_active"], true);
        if let Ok(path) = std::env::var("R2O_LIVE_SNAPSHOT_DIFF_OUTPUT") {
            std::fs::write(path, serde_json::to_string(&live).unwrap()).unwrap();
        }
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
