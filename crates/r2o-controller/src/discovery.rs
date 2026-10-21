//! Разбор событий и постоянное хранение измеренных результатов TCP-поиска.

use r2k_core::control::{
    HelloEvent, HttpPortalEvent, HttpResponseEvent, SHAPE_ECH_TCP, SHAPE_HTTP, SHAPE_LEGACY,
    SHAPE_MODERN, SHAPE_QUIC,
};
use r2k_core::plan::Plan as RuntimePlan;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::catalog::{Binding, BoxRecord, Catalog, DomainObservation, DomainState, GroupKey, Plan};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DiscoveryTarget {
    pub host: String,
    pub endpoint: String,
    pub family: u8,
    pub shape: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectClearBindingUpdate {
    pub marked: usize,
    pub removed: usize,
    pub waiting: usize,
    pub delete_runtime: bool,
}

impl DiscoveryTarget {
    /// Выбирать только именованные потоки TLS на стандартном порту HTTPS.
    pub fn from_event(event: &HelloEvent) -> Option<Self> {
        if event.key[37] != 6 {
            return None;
        }
        let shape = event.shape?;
        if !matches!(shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP) {
            return None;
        }
        let host = String::from_utf8(event.host.clone()?).ok()?;
        let host = crate::domain::normalize(&host).ok()?;
        crate::domain::registrable_domain(&host)?;

        let family = event.key[0];
        let low_port = u16::from_be_bytes([event.key[33], event.key[34]]);
        let high_port = u16::from_be_bytes([event.key[35], event.key[36]]);
        let (address, port) = match (low_port, high_port) {
            (443, 443) => return None,
            (_, 443) => (&event.key[17..33], 443),
            (443, _) => (&event.key[1..17], 443),
            _ => return None,
        };
        let endpoint = match family {
            4 => format!(
                "{}:{port}",
                Ipv4Addr::new(address[0], address[1], address[2], address[3])
            ),
            6 => {
                let address: [u8; 16] = address.try_into().ok()?;
                format!("[{}]:{port}", Ipv6Addr::from(address))
            }
            _ => return None,
        };
        Some(Self {
            host,
            endpoint,
            family,
            shape,
        })
    }

    /// Преобразовать полный снимок TCP в цель того же классификатора.
    pub fn from_client_shape(event: &r2k_core::control::ClientShapeEvent) -> Option<Self> {
        Self::from_event(&HelloEvent {
            key: event.key,
            host: Some(event.host.clone()),
            shape: Some(event.shape),
            r2o_wire_len: Some(event.client_hello.len()),
            quic_snapshot: None,
        })
    }

    /// Выбрать цель пассивного наблюдения портала HTTP на порту 80.
    pub fn from_http_portal(event: &HttpPortalEvent) -> Option<Self> {
        if event.answered || event.key[37] != 6 || !matches!(event.key[0], 4 | 6) {
            return None;
        }
        let host = String::from_utf8(event.host.clone()).ok()?;
        let host = crate::domain::normalize(&host).ok()?;
        crate::domain::registrable_domain(&host)?;

        let low_port = u16::from_be_bytes([event.key[33], event.key[34]]);
        let high_port = u16::from_be_bytes([event.key[35], event.key[36]]);
        let (address, port) = match (low_port, high_port) {
            (80, 80) => return None,
            (80, _) => (&event.key[1..17], 80),
            (_, 80) => (&event.key[17..33], 80),
            _ => return None,
        };
        let endpoint = match event.key[0] {
            4 => format!(
                "{}:{port}",
                Ipv4Addr::new(address[0], address[1], address[2], address[3])
            ),
            6 => {
                let address: [u8; 16] = address.try_into().ok()?;
                format!("[{}]:{port}", Ipv6Addr::from(address))
            }
            _ => return None,
        };
        Some(Self {
            host,
            endpoint,
            family: event.key[0],
            shape: SHAPE_HTTP,
        })
    }

    /// Выбрать поток HTTP-ответа, путь которого можно повторить при поиске.
    pub fn from_http_response(event: &HttpResponseEvent) -> Option<Self> {
        if !matches!(event.code, 3 | 4)
            || event.key[37] != 6
            || !matches!(event.key[0], 4 | 6)
            || event.trial_id.iter().any(|byte| *byte != 0)
            || !crate::http_search::repeatable_path(&event.path)
        {
            return None;
        }
        let host = String::from_utf8(event.host.clone()).ok()?;
        let host = crate::domain::normalize(&host).ok()?;
        crate::domain::registrable_domain(&host)?;

        let low_port = u16::from_be_bytes([event.key[33], event.key[34]]);
        let high_port = u16::from_be_bytes([event.key[35], event.key[36]]);
        if low_port == 80 || high_port != 80 {
            return None;
        }
        let address = &event.key[17..33];
        let endpoint = match event.key[0] {
            4 => format!(
                "{}:80",
                Ipv4Addr::new(address[0], address[1], address[2], address[3])
            ),
            6 => {
                let address: [u8; 16] = address.try_into().ok()?;
                format!("[{}]:80", Ipv6Addr::from(address))
            }
            _ => return None,
        };
        Some(Self {
            host,
            endpoint,
            family: event.key[0],
            shape: SHAPE_HTTP,
        })
    }
}

const R2O_ECH_WITNESS_LIMIT: usize = 32;

/// Собрать ограниченный список HTTPS-владельцев, способных подтвердить ECH.
pub fn r2o_ech_witness_candidates(catalog: &Catalog, target: &DiscoveryTarget) -> Vec<String> {
    if target.shape != SHAPE_ECH_TCP {
        return Vec::new();
    }

    let mut candidates = Vec::with_capacity(R2O_ECH_WITNESS_LIMIT);
    let mut add = |name: &str| {
        if !name.is_empty()
            && name != target.host
            && candidates.len() < R2O_ECH_WITNESS_LIMIT
            && !candidates.iter().any(|candidate| candidate == name)
        {
            candidates.push(name.to_owned());
        }
    };

    for family_pass in [target.family, if target.family == 4 { 6 } else { 4 }] {
        for binding in catalog.boxes.iter().flat_map(|record| &record.bindings) {
            if binding.enabled
                && binding.level >= 3
                && binding.transport == 6
                && binding.family == family_pass
                && binding.target == target.host
                && !binding.ech_origin.is_empty()
            {
                add(&binding.ech_origin);
            }
        }
    }

    for binding in catalog.boxes.iter().flat_map(|record| &record.bindings) {
        if binding.enabled && binding.level >= 3 && !binding.ech_origin.is_empty() {
            add(&binding.ech_origin);
        }
    }

    let mut confirmed_names: Vec<_> = catalog
        .boxes
        .iter()
        .flat_map(|record| &record.bindings)
        .filter(|binding| {
            binding.enabled
                && binding.level >= 3
                && binding.kind == "name"
                && !binding.target.is_empty()
                && binding.ech_origin.is_empty()
        })
        .map(|binding| (binding.confirmed, binding.target.as_str()))
        .collect();
    confirmed_names.sort_by(|left, right| right.0.cmp(&left.0));
    for (_, name) in confirmed_names {
        add(name);
    }

    candidates
}

/// Отозвать HTTP-привязку только при совпадении сохранённого плана и живого события.
pub fn revoke_http_response_binding(
    catalog: &mut Catalog,
    event: &HttpResponseEvent,
    target: &DiscoveryTarget,
    now: i64,
) -> bool {
    let zero = [0; 16];
    if now < 0
        || event.code != 3
        || event.key[37] != 6
        || event.key[0] != target.family
        || target.shape != SHAPE_HTTP
        || !crate::http_search::repeatable_path(&event.path)
        || event.trial_id != zero
        || event.execution_id == 0
        || event.request_ms == 0
        || event.request_no == 0
        || !event.binding.is_known()
        || event.binding.temporary
        || event.binding.kind != 1
        || event.binding.family != target.family
        || event.binding.shape != SHAPE_HTTP
    {
        return false;
    }
    let Ok(host) = std::str::from_utf8(&event.host) else {
        return false;
    };
    if crate::domain::normalize(host).ok().as_deref() != Some(target.host.as_str()) {
        return false;
    }
    let Ok(endpoint) = target.endpoint.parse::<std::net::SocketAddr>() else {
        return false;
    };
    if endpoint.port() != 80 || endpoint.is_ipv4() != (target.family == 4) {
        return false;
    }
    let high_port = u16::from_be_bytes([event.key[35], event.key[36]]);
    if high_port != 80 {
        return false;
    }
    let server_matches = match endpoint.ip() {
        std::net::IpAddr::V4(ip) => event.key[17..21] == ip.octets()[..],
        std::net::IpAddr::V6(ip) => event.key[17..33] == ip.octets()[..],
    };
    if !server_matches {
        return false;
    }
    let plan_id: String = event
        .plan_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if plan_id.bytes().all(|byte| byte == b'0') {
        return false;
    }
    let mut revoked = false;
    for box_record in &mut catalog.boxes {
        if !box_record
            .plans
            .iter()
            .any(|plan| plan.enabled && plan.id.eq_ignore_ascii_case(&plan_id))
        {
            continue;
        }
        for binding in &mut box_record.bindings {
            if binding.enabled
                && binding.kind == "name"
                && binding.target == target.host
                && binding.plan_id.eq_ignore_ascii_case(&plan_id)
                && binding.transport == 6
                && binding.family == target.family
                && binding.shape == SHAPE_HTTP
                && binding.verified_by == 1
                && binding.input == 2
            {
                binding.enabled = false;
                binding.recheck_since = Some(now);
                revoked = true;
            }
        }
    }
    revoked
}

/// Проверить, покрывает ли пригодная точная привязка это имя и форму TLS.
pub fn has_usable_binding(catalog: &Catalog, target: &DiscoveryTarget) -> bool {
    has_usable_binding_with_input(catalog, target, None)
}

/// Проверить, покрывает ли цель привязка, измеренная только профилем.
pub fn has_usable_profile_binding(catalog: &Catalog, target: &DiscoveryTarget) -> bool {
    has_usable_binding_with_input(catalog, target, Some(2))
}

fn has_usable_binding_with_input(
    catalog: &Catalog,
    target: &DiscoveryTarget,
    input: Option<u8>,
) -> bool {
    catalog.boxes.iter().any(|box_record| {
        box_record.bindings.iter().any(|binding| {
            if !binding.enabled
                || binding.kind != "name"
                || binding.target != target.host
                || !(binding.family == target.family || binding.family == 0 && target.family == 4)
                || !(binding.transport == 6 || binding.transport == 0)
                || !(binding.shape == target.shape || binding.shape == 0)
                || input.is_some_and(|expected| binding.input != expected)
            {
                return false;
            }
            box_record
                .plans
                .iter()
                .find(|plan| plan.id == binding.plan_id && plan.enabled)
                .is_some_and(|saved| {
                    crate::plan_text::compile_text(&saved.text)
                        .ok()
                        .and_then(|bytes| RuntimePlan::parse(&bytes).ok())
                        .is_some_and(|plan| {
                            usable_runtime_plan(&plan, target.shape)
                                && r2o_datapath::engine::validate_runtime_plan(&plan).is_ok()
                        })
                })
        })
    })
}

/// Сохранить прямой проход для точной TLS-привязки, не затрагивая другие формы.
pub fn update_direct_clear_bindings(
    catalog: &mut Catalog,
    target: &DiscoveryTarget,
    now: i64,
    monotonic_now: std::time::Instant,
) -> DirectClearBindingUpdate {
    const RECHECK_GAP: std::time::Duration = std::time::Duration::from_secs(60);

    let mut update = DirectClearBindingUpdate::default();
    if now < 0
        || !matches!(target.family, 4 | 6)
        || !matches!(target.shape, SHAPE_MODERN | SHAPE_LEGACY)
    {
        return update;
    }

    for box_record in &mut catalog.boxes {
        let mut changed = false;
        let mut index = 0;
        while index < box_record.bindings.len() {
            let binding = &mut box_record.bindings[index];
            let transport = if binding.transport == 0 {
                6
            } else {
                binding.transport
            };
            let family = if binding.family == 0 {
                4
            } else {
                binding.family
            };
            let matches_target = binding.kind == "name"
                && binding.target == target.host
                && transport == 6
                && family == target.family
                && (binding.shape == 0 || binding.shape == target.shape);
            if !matches_target {
                index += 1;
                continue;
            }

            if binding.recheck_since.is_some() {
                let independent = binding.recheck_mono.is_none_or(|started| {
                    monotonic_now.saturating_duration_since(started) >= RECHECK_GAP
                });
                if independent {
                    box_record.bindings.remove(index);
                    update.removed += 1;
                    changed = true;
                    continue;
                }
                update.waiting += 1;
                index += 1;
                continue;
            }

            binding.recheck_since = Some(now.max(1));
            binding.recheck_mono = Some(monotonic_now);
            update.marked += 1;
            changed = true;
            update.delete_runtime |=
                transport == 6 && family == target.family && binding.shape == target.shape;
            index += 1;
        }
        if changed {
            box_record.updated = now.max(1);
        }
    }

    update
}

/// Сохранить измеренный план и соответствующую точную привязку имени.
pub fn add_measured_binding(
    catalog: &mut Catalog,
    target: &DiscoveryTarget,
    source_text: &str,
    now: i64,
) -> Result<String, String> {
    add_measured_binding_with_input(catalog, target, source_text, now, 2)
}

/// Сохранить измеренный план с источником входного ClientHello.
pub fn add_measured_binding_with_input(
    catalog: &mut Catalog,
    target: &DiscoveryTarget,
    source_text: &str,
    now: i64,
    input: u8,
) -> Result<String, String> {
    if !matches!(target.family, 4 | 6)
        || !matches!(target.shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_HTTP)
        || !matches!(input, 1 | 2)
    {
        return Err("discovery target or input source is unsupported".into());
    }
    let normalized = crate::domain::normalize(&target.host)
        .map_err(|_| "discovery target has an invalid hostname")?;
    if normalized != target.host || crate::domain::registrable_domain(&normalized).is_none() {
        return Err("discovery target hostname must be a canonical registrable name".into());
    }
    let endpoint: std::net::SocketAddr = target
        .endpoint
        .parse()
        .map_err(|_| "discovery endpoint must be an IP socket address")?;
    let expected_port = if target.shape == SHAPE_HTTP { 80 } else { 443 };
    if endpoint.port() != expected_port || endpoint.is_ipv4() != (target.family == 4) {
        return Err("discovery endpoint disagrees with its target family or port".into());
    }
    if now < 0 {
        return Err("discovery timestamp must be nonnegative".into());
    }
    let canonical_text = canonical_plan_text(source_text)?;
    let plan_id = catalog
        .boxes
        .iter()
        .find_map(|box_record| {
            box_record.plans.iter().find(|plan| {
                plan.enabled
                    && box_record.bindings.iter().any(|binding| {
                        binding.enabled
                            && binding.transport == 6
                            && binding.family == target.family
                            && binding.shape == target.shape
                            && binding.plan_id == plan.id
                    })
                    && canonical_plan_text(&plan.text).ok().as_deref() == Some(&canonical_text)
            })
        })
        .map(|plan| plan.id.clone())
        .unwrap_or_else(|| stable_plan_id(target.family, target.shape, &canonical_text));
    let plan_text = text_with_id(&canonical_text, &plan_id)?;
    let bytes = crate::plan_text::compile_text(&plan_text)?;
    let plan = RuntimePlan::parse(&bytes).map_err(|error| error.to_string())?;
    if !usable_runtime_plan(&plan, target.shape) {
        return Err("measured plan does not match the target TCP shape".into());
    }
    r2o_datapath::engine::validate_runtime_plan(&plan)
        .map_err(|error| format!("r2o-datapath runtime rejected measured plan: {error}"))?;

    let box_index = if let Some(index) = catalog
        .boxes
        .iter()
        .position(|box_record| box_record.plans.iter().any(|saved| saved.id == plan_id))
    {
        index
    } else {
        let id = format!("auto-{plan_id}");
        catalog.boxes.push(BoxRecord {
            id,
            created: now,
            updated: now,
            ..BoxRecord::default()
        });
        catalog.boxes.len() - 1
    };

    let mut prior_successes = 0_i32;
    for box_record in &mut catalog.boxes {
        for binding in &box_record.bindings {
            if exact_key(binding, target) {
                prior_successes = prior_successes.max(binding.successes);
            }
        }
        box_record
            .bindings
            .retain(|binding| !exact_key(binding, target));
    }

    let selected = &mut catalog.boxes[box_index];
    if let Some(saved) = selected.plans.iter_mut().find(|saved| saved.id == plan_id) {
        saved.text = plan_text;
        saved.proto = if target.shape == SHAPE_HTTP {
            "http"
        } else {
            "tls"
        }
        .into();
        saved.enabled = true;
        saved.added = now;
        saved.successes = saved.successes.saturating_add(1);
    } else {
        selected.plans.push(Plan {
            id: plan_id.clone(),
            proto: if target.shape == SHAPE_HTTP {
                "http"
            } else {
                "tls"
            }
            .into(),
            text: plan_text,
            added: now,
            successes: 1,
            enabled: true,
        });
    }
    selected.updated = now;
    selected.bindings.push(Binding {
        kind: "name".into(),
        target: target.host.clone(),
        plan_id: plan_id.clone(),
        level: 3,
        confirmed: now,
        successes: prior_successes.saturating_add(1),
        enabled: true,
        transport: 6,
        family: target.family,
        shape: target.shape,
        verified_by: 1,
        input,
        ..Binding::default()
    });

    if target.shape != SHAPE_HTTP {
        let state = catalog
            .domain_state
            .get_or_insert_with(DomainState::default);
        state
            .learn(DomainObservation {
                name: target.host.clone(),
                plan_id: plan_id.clone(),
                key: GroupKey {
                    transport: 6,
                    family: target.family,
                    shape: target.shape,
                    ..GroupKey::default()
                },
                evidence: 1,
                at: now,
            })
            .map_err(|error| format!("catalog domain observation: {error}"))?;
    }

    Ok(plan_id)
}

/// Сохранить QUIC-адрес только после подтверждённого повтора рукопожатия.
pub fn add_confirmed_quic_address_binding(
    catalog: &mut Catalog,
    address: std::net::IpAddr,
    source_text: &str,
    now: i64,
) -> Result<String, String> {
    if address.is_unspecified() || address.is_multicast() || now < 0 {
        return Err("QUIC-привязка имеет недопустимый адрес или время".into());
    }
    let family = if address.is_ipv4() { 4 } else { 6 };
    let canonical = canonical_plan_text(source_text)?;
    let plan_id = stable_plan_id(family, SHAPE_QUIC, &canonical);
    let plan_text = text_with_id(&canonical, &plan_id)?;
    let bytes = crate::plan_text::compile_text(&plan_text)?;
    let plan = RuntimePlan::parse(&bytes).map_err(|error| error.to_string())?;
    if !plan.r2k_is_quic_address_plan() {
        return Err("подтверждённый QUIC-кандидат имеет неподдерживаемую форму".into());
    }
    r2o_datapath::engine::validate_runtime_plan(&plan)
        .map_err(|error| format!("r2o-datapath отверг подтверждённый QUIC-план: {error}"))?;

    let target = address.to_string();
    let box_index = if let Some(index) = catalog
        .boxes
        .iter()
        .position(|record| record.plans.iter().any(|saved| saved.id == plan_id))
    {
        index
    } else {
        catalog.boxes.push(BoxRecord {
            id: format!("auto-{plan_id}"),
            created: now,
            updated: now,
            ..BoxRecord::default()
        });
        catalog.boxes.len() - 1
    };

    let mut prior_successes = 0_i32;
    for record in &mut catalog.boxes {
        for binding in &record.bindings {
            if quic_binding_key(binding, &target, family) {
                prior_successes = prior_successes.max(binding.successes);
            }
        }
        record
            .bindings
            .retain(|binding| !quic_binding_key(binding, &target, family));
    }

    let selected = &mut catalog.boxes[box_index];
    if let Some(saved) = selected.plans.iter_mut().find(|saved| saved.id == plan_id) {
        saved.proto = "quic".into();
        saved.text = plan_text;
        saved.enabled = true;
        saved.added = now;
        saved.successes = saved.successes.saturating_add(1);
    } else {
        selected.plans.push(crate::catalog::Plan {
            id: plan_id.clone(),
            proto: "quic".into(),
            text: plan_text,
            added: now,
            successes: 1,
            enabled: true,
        });
    }
    selected.updated = now;
    selected.bindings.push(Binding {
        kind: "addr".into(),
        target,
        plan_id: plan_id.clone(),
        level: 3,
        confirmed: now,
        successes: prior_successes.saturating_add(1),
        enabled: true,
        transport: 17,
        family,
        shape: SHAPE_QUIC,
        verified_by: 6,
        input: 1,
        ..Binding::default()
    });
    Ok(plan_id)
}

/// Проверить, что у адреса уже есть применимый QUIC-план с replay-доказательством.
pub fn has_usable_quic_address_binding(catalog: &Catalog, address: std::net::IpAddr) -> bool {
    let family = if address.is_ipv4() { 4 } else { 6 };
    let target = address.to_string();
    catalog.boxes.iter().any(|record| {
        record.bindings.iter().any(|binding| {
            quic_binding_key(binding, &target, family)
                && binding.verified_by == 6
                && binding.input == 1
                && record
                    .plans
                    .iter()
                    .find(|saved| saved.enabled && saved.id == binding.plan_id)
                    .and_then(|saved| {
                        crate::plan_text::compile_text(&saved.text)
                            .ok()
                            .and_then(|bytes| RuntimePlan::parse(&bytes).ok())
                    })
                    .is_some_and(|plan| {
                        plan.r2k_is_quic_address_plan()
                            && r2o_datapath::engine::validate_runtime_plan(&plan).is_ok()
                    })
        })
    })
}

fn quic_binding_key(binding: &Binding, target: &str, family: u8) -> bool {
    binding.kind == "addr"
        && binding.target == target
        && binding.transport == 17
        && binding.family == family
        && binding.shape == SHAPE_QUIC
}

fn exact_key(binding: &Binding, target: &DiscoveryTarget) -> bool {
    binding.kind == "name"
        && binding.target == target.host
        && (binding.family == target.family || binding.family == 0 && target.family == 4)
        && (binding.transport == 6 || binding.transport == 0)
        && (binding.shape == target.shape || binding.shape == 0)
}

fn usable_runtime_plan(plan: &RuntimePlan, shape: u8) -> bool {
    plan.transport == 6
        && match shape {
            SHAPE_HTTP => plan.proto == r2k_core::plan::PROTO_HTTP,
            SHAPE_MODERN | SHAPE_LEGACY => plan.proto == 1,
            _ => false,
        }
}

fn canonical_plan_text(text: &str) -> Result<String, String> {
    const ZERO_ID: &str = "00000000000000000000000000000000";
    let mut found = false;
    let mut lines = Vec::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("id ") {
            if found || value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("measured plan must have one 32-digit hex id".into());
            }
            found = true;
            lines.push(format!("id {ZERO_ID}"));
        } else {
            lines.push(line.to_owned());
        }
    }
    if !found {
        return Err("measured plan is missing its id directive".into());
    }
    let mut canonical = lines.join("\n");
    if text.ends_with('\n') {
        canonical.push('\n');
    }
    Ok(canonical)
}

fn text_with_id(canonical: &str, id: &str) -> Result<String, String> {
    const ZERO_ID: &str = "00000000000000000000000000000000";
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("catalog plan id is invalid".into());
    }
    let replacement = format!("id {id}");
    let Some((before, after)) = canonical.split_once(&format!("id {ZERO_ID}")) else {
        return Err("canonical plan id directive is missing".into());
    };
    if after.contains(&format!("id {ZERO_ID}")) {
        return Err("measured plan has multiple id directives".into());
    }
    Ok(format!("{before}{replacement}{after}"))
}

/// Подставить отдельный идентификатор для временной проверки измеренного плана.
pub fn plan_text_for_trial(text: &str, id: [u8; 16]) -> Result<String, String> {
    let canonical = canonical_plan_text(text)?;
    let id = id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    text_with_id(&canonical, &id)
}

fn stable_plan_id(family: u8, shape: u8, text: &str) -> String {
    fn hash(seed: u64, bytes: impl IntoIterator<Item = u8>) -> u64 {
        bytes.into_iter().fold(seed, |value, byte| {
            (value ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        })
    }
    let mut input = vec![family, shape];
    input.extend_from_slice(text.as_bytes());
    let first = hash(0xcbf29ce484222325, input.iter().copied());
    let second = hash(0x84222325cbf29ce4, input.iter().rev().copied());
    format!("{first:016x}{second:016x}")
}

#[cfg(test)]
mod tests {
    use super::{DiscoveryTarget, r2o_ech_witness_candidates};
    use r2k_core::control::{BindingContext, HttpResponseEvent, KEY_LEN, SHAPE_HTTP};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn r2o_ech_свидетели_сохраняют_приоритет_каталога_и_семейства() {
        use crate::catalog::{Binding, BoxRecord, Catalog};

        fn binding(target: &str, origin: &str, family: u8, confirmed: i64) -> Binding {
            Binding {
                kind: "name".into(),
                target: target.into(),
                ech_origin: origin.into(),
                level: 3,
                confirmed,
                enabled: true,
                transport: 6,
                family,
                ..Binding::default()
            }
        }

        let target = DiscoveryTarget {
            host: "cloudflare-ech.com".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_ECH_TCP,
        };
        let catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![
                    binding(&target.host, "family-witness.example", 4, 50),
                    binding(&target.host, "other-family.example", 6, 40),
                    binding("other-target.example", "third-witness.example", 6, 30),
                    binding("new-target.example", "", 4, 200),
                    binding("old-target.example", "", 6, 100),
                ],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };

        assert_eq!(
            r2o_ech_witness_candidates(&catalog, &target),
            [
                "family-witness.example",
                "other-family.example",
                "third-witness.example",
                "new-target.example",
                "old-target.example",
            ]
        );
    }

    fn response() -> HttpResponseEvent {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 80]);
        key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&80_u16.to_be_bytes());
        key[37] = 6;
        HttpResponseEvent {
            key,
            code: 4,
            host: b"Example.com".to_vec(),
            execution_id: 0,
            plan_id: [0; 16],
            trial_id: [0; 16],
            request_ms: 0,
            path: b"/watch/42".to_vec(),
            binding: BindingContext {
                generation: 0,
                kind: 0,
                family: 0,
                shape: 0,
                temporary: false,
                epoch: [0; 16],
            },
            status: 200,
            body_bytes: 1024,
            request_no: 1,
        }
    }

    #[test]
    fn response_cut_target_uses_the_http_server_and_safe_original_path() {
        let event = response();
        let target = DiscoveryTarget::from_http_response(&event).unwrap();

        assert_eq!(target.host, "example.com");
        assert_eq!(target.endpoint, "198.51.100.80:80");
        assert_eq!(target.family, 4);
        assert_eq!(target.shape, SHAPE_HTTP);
        assert_eq!(event.path, b"/watch/42");
        assert_eq!(
            target
                .endpoint
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .ip(),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 80))
        );
    }

    #[test]
    fn профильная_привязка_отличается_от_проверенной_живыми_байтами() {
        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_MODERN,
        };
        let mut catalog = crate::catalog::Catalog::default();
        super::add_measured_binding(
            &mut catalog,
            &target,
            "r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +0\n",
            100,
        )
        .unwrap();

        assert!(super::has_usable_binding(&catalog, &target));
        assert!(super::has_usable_profile_binding(&catalog, &target));
        catalog.boxes[0].bindings[0].input = 1;
        assert!(!super::has_usable_profile_binding(&catalog, &target));
    }

    #[test]
    fn временный_план_получает_уникальный_id_без_изменения_его_содержимого() {
        let text = "r2o-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +8\n";
        let trial = super::plan_text_for_trial(text, [0x5a; 16]).unwrap();

        assert!(trial.contains("id 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\n"));
        assert!(trial.ends_with("proto tcp tls\nsplit sni_middle +8\n"));
    }

    #[test]
    fn сохраняет_адресный_quic_план_только_для_точного_адреса() {
        let address = "198.51.100.23".parse().unwrap();
        let mut catalog = crate::catalog::Catalog::default();
        let plan_id = super::add_confirmed_quic_address_binding(
            &mut catalog,
            address,
            "r2o-plan 1 10\nid 00000000000000000000000000000000\nproto udp quic\nquicsplit 1\n",
            123,
        )
        .unwrap();

        assert_eq!(catalog.boxes.len(), 1);
        assert_eq!(catalog.boxes[0].plans[0].proto, "quic");
        assert_eq!(catalog.boxes[0].bindings[0].kind, "addr");
        assert_eq!(catalog.boxes[0].bindings[0].target, "198.51.100.23");
        assert_eq!(catalog.boxes[0].bindings[0].transport, 17);
        assert_eq!(
            catalog.boxes[0].bindings[0].shape,
            r2k_core::control::SHAPE_QUIC
        );
        assert_eq!(catalog.boxes[0].bindings[0].verified_by, 6);
        assert_eq!(catalog.boxes[0].bindings[0].input, 1);
        assert_eq!(catalog.boxes[0].bindings[0].plan_id, plan_id);
        assert!(super::has_usable_quic_address_binding(&catalog, address));
        assert!(!super::has_usable_quic_address_binding(
            &catalog,
            "198.51.100.24".parse().unwrap()
        ));
    }

    #[test]
    fn r2o_сохраняет_подтверждённые_quic_планы_других_форм() {
        let plans = [
            "r2o-plan 1 10\nid 00000000000000000000000000000000\nproto udp quic\npayload 1 00000000000000000000000000000000\nfake payload=1 poison=0 repeats=1 gap_us=0 place=before\n",
            "r2o-plan 1 9\nid 00000000000000000000000000000000\nproto udp quic\nudplen 100\n",
        ];
        for (index, text) in plans.into_iter().enumerate() {
            let address = std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30 + index as u8));
            let mut catalog = crate::catalog::Catalog::default();
            super::add_confirmed_quic_address_binding(&mut catalog, address, text, 124).unwrap();
            assert!(super::has_usable_quic_address_binding(&catalog, address));
        }
    }

    #[test]
    fn response_cut_target_rejects_unrepeatable_or_temporary_events() {
        let mut event = response();
        event.path = b"/search?q=private".to_vec();
        assert!(DiscoveryTarget::from_http_response(&event).is_none());

        let mut event = response();
        event.trial_id = [1; 16];
        assert!(DiscoveryTarget::from_http_response(&event).is_none());

        let mut event = response();
        event.key[33..35].copy_from_slice(&80_u16.to_be_bytes());
        event.key[35..37].copy_from_slice(&45000_u16.to_be_bytes());
        assert!(DiscoveryTarget::from_http_response(&event).is_none());
    }

    #[test]
    fn live_portal_failure_revokes_only_its_confirmed_http_binding() {
        use super::revoke_http_response_binding;
        use crate::catalog::{Binding, BoxRecord, Catalog, Plan};

        let mut event = response();
        event.code = 3;
        event.execution_id = 5;
        event.request_ms = 10;
        event.plan_id = [0x11; 16];
        event.binding = BindingContext {
            generation: 7,
            kind: 1,
            family: 4,
            shape: SHAPE_HTTP,
            temporary: false,
            epoch: [3; 16],
        };
        let target = DiscoveryTarget::from_http_response(&event).unwrap();
        let binding = Binding {
            kind: "name".into(),
            target: "example.com".into(),
            plan_id: "11".repeat(16),
            enabled: true,
            transport: 6,
            family: 4,
            shape: SHAPE_HTTP,
            verified_by: 1,
            input: 2,
            ..Binding::default()
        };
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                plans: vec![Plan {
                    id: "11".repeat(16),
                    proto: "http".into(),
                    enabled: true,
                    ..Plan::default()
                }],
                bindings: vec![binding],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };

        assert!(revoke_http_response_binding(
            &mut catalog,
            &event,
            &target,
            100
        ));
        assert!(!catalog.boxes[0].bindings[0].enabled);
        assert_eq!(catalog.boxes[0].bindings[0].recheck_since, Some(100));

        let mut unrelated = catalog.clone();
        unrelated.boxes[0].bindings[0].enabled = true;
        event.execution_id += 1;
        event.plan_id = [0x22; 16];
        assert!(!revoke_http_response_binding(
            &mut unrelated,
            &event,
            &target,
            101
        ));
        assert!(unrelated.boxes[0].bindings[0].enabled);
    }

    #[test]
    fn прямой_clear_снимает_только_точную_форму_и_ждёт_независимого_повтора() {
        use super::{DiscoveryTarget, update_direct_clear_bindings};
        use crate::catalog::{Binding, BoxRecord, Catalog};
        use r2k_core::control::{SHAPE_ECH_TCP, SHAPE_LEGACY, SHAPE_MODERN, SHAPE_QUIC};
        use std::time::{Duration, Instant};

        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let binding = |host: &str, family, shape| Binding {
            kind: "name".into(),
            target: host.into(),
            enabled: true,
            transport: 6,
            family,
            shape,
            ..Binding::default()
        };
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![
                    binding("example.com", 4, SHAPE_MODERN),
                    binding("example.com", 4, SHAPE_LEGACY),
                    binding("example.com", 4, SHAPE_ECH_TCP),
                    binding("example.com", 4, SHAPE_QUIC),
                    binding("example.com", 6, SHAPE_MODERN),
                    binding("other.example", 4, SHAPE_MODERN),
                ],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        let started = Instant::now();

        let first = update_direct_clear_bindings(&mut catalog, &target, 100, started);

        assert_eq!(first.marked, 1);
        assert_eq!(first.removed, 0);
        assert_eq!(first.waiting, 0);
        assert!(first.delete_runtime);
        assert_eq!(catalog.boxes[0].bindings[0].recheck_since, Some(100));
        assert_eq!(catalog.boxes[0].bindings[0].recheck_mono, Some(started));
        assert!(
            catalog.boxes[0].bindings[1..]
                .iter()
                .all(|binding| binding.recheck_since.is_none())
        );

        let same_measurement = update_direct_clear_bindings(
            &mut catalog,
            &target,
            159,
            started + Duration::from_secs(59),
        );
        assert_eq!(same_measurement.waiting, 1);
        assert_eq!(same_measurement.removed, 0);
        assert!(!same_measurement.delete_runtime);

        let independent_measurement = update_direct_clear_bindings(
            &mut catalog,
            &target,
            160,
            started + Duration::from_secs(60),
        );
        assert_eq!(independent_measurement.removed, 1);
        assert_eq!(independent_measurement.marked, 0);
        assert_eq!(independent_measurement.waiting, 0);
        assert!(!independent_measurement.delete_runtime);
        assert_eq!(catalog.boxes[0].bindings.len(), 5);
        assert!(
            catalog.boxes[0]
                .bindings
                .iter()
                .all(|binding| binding.shape != SHAPE_MODERN
                    || binding.target != "example.com"
                    || binding.family != 4)
        );
        assert!(catalog.boxes[0].bindings.iter().any(|binding| {
            binding.target == "example.com" && binding.family == 6 && binding.shape == SHAPE_MODERN
        }));
    }

    #[test]
    fn метка_перепроверки_после_перезапуска_считается_отдельным_замером() {
        use super::{DiscoveryTarget, update_direct_clear_bindings};
        use crate::catalog::{Binding, BoxRecord, Catalog};
        use r2k_core::control::SHAPE_MODERN;

        let target = DiscoveryTarget {
            host: "restart.example".into(),
            endpoint: "198.51.100.81:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: target.host.clone(),
                    enabled: true,
                    transport: 6,
                    family: 4,
                    shape: SHAPE_MODERN,
                    recheck_since: Some(99),
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };

        let result =
            update_direct_clear_bindings(&mut catalog, &target, 100, std::time::Instant::now());

        assert_eq!(result.removed, 1);
        assert_eq!(result.marked, 0);
        assert!(catalog.boxes[0].bindings.is_empty());
    }
}
