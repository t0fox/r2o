//! Разбор событий и постоянное хранение измеренных результатов TCP-поиска.

use r2k_core::control::{
    HelloEvent, HttpPortalEvent, HttpResponseEvent, SHAPE_ECH_TCP, SHAPE_HTTP, SHAPE_LEGACY,
    SHAPE_MODERN, SHAPE_QUIC,
};
use r2k_core::plan::Plan as RuntimePlan;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::catalog::{Binding, BoxRecord, Catalog, DomainObservation, DomainState, GroupKey, Plan};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DiscoveryTarget {
    pub host: String,
    pub endpoint: String,
    pub family: u8,
    pub shape: u8,
}

/// Перевести неподтверждённый ECH offer на обычный TLS-путь GREASE.
pub fn regrade_ech_grease(target: &mut DiscoveryTarget) -> bool {
    if target.shape != SHAPE_ECH_TCP {
        return false;
    }
    target.shape = SHAPE_MODERN;
    true
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectClearBindingUpdate {
    pub marked: usize,
    pub removed: usize,
    pub waiting: usize,
    pub delete_runtime: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnPlanCandidate {
    pub box_id: String,
    pub plan_id: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownPlanCandidate {
    pub box_id: String,
    pub text: String,
}

/// Return the plan bound to the exact name/TCP/family/shape slot, using the
/// same winner selection as `core/sched.c::bound_plan_here`.
pub fn own_first_bound_plan_id(
    catalog: &Catalog,
    target: &DiscoveryTarget,
    shape: u8,
) -> Option<String> {
    for box_record in &catalog.boxes {
        for binding in &box_record.bindings {
            if !binding.enabled
                || binding.recheck_since.is_some_and(|since| since != 0)
                || binding.level > 0 && binding.level < 3
                || binding.kind != "name"
                || binding.target != target.host
                || normalized_transport(binding.transport) != 6
                || normalized_family(binding.family) != target.family
                || binding.shape != shape
                || binding.tcp_profile != target.tcp_profile()
                || newer_name_binding(catalog, binding)
                || !box_record
                    .plans
                    .iter()
                    .any(|plan| plan.id == binding.plan_id)
            {
                continue;
            }
            return Some(binding.plan_id.clone());
        }
    }
    None
}

fn normalized_transport(transport: u8) -> u8 {
    if transport == 0 { 6 } else { transport }
}

fn normalized_family(family: u8) -> u8 {
    if family == 0 { 4 } else { family }
}

fn binding_budget_rank(budget: u8) -> u8 {
    match budget {
        1 => 2, // D2K_CAT_BUDGET_PASSED
        3 => 0, // D2K_CAT_BUDGET_CUT
        _ => 1,
    }
}

fn binding_beats(left: &Binding, right: &Binding) -> bool {
    let left_budget = binding_budget_rank(left.budget);
    let right_budget = binding_budget_rank(right.budget);
    left_budget > right_budget || left_budget == right_budget && left.confirmed > right.confirmed
}

fn newer_name_binding(catalog: &Catalog, binding: &Binding) -> bool {
    if binding.kind != "name" {
        return false;
    }
    catalog.boxes.iter().any(|box_record| {
        box_record.bindings.iter().any(|other| {
            !std::ptr::eq(other, binding)
                && other.enabled
                && other.recheck_since.is_none_or(|since| since == 0)
                && !(other.level > 0 && other.level < 3)
                && binding_beats(other, binding)
                && other.kind == "name"
                && other.target == binding.target
                && normalized_transport(other.transport) == normalized_transport(binding.transport)
                && normalized_family(other.family) == normalized_family(binding.family)
                && other.shape == binding.shape
                && (normalized_transport(other.transport) != 6
                    || other.tcp_profile == binding.tcp_profile)
                && box_record.plans.iter().any(|plan| plan.id == other.plan_id)
        })
    })
}

#[derive(Clone)]
struct RankedOwnPlan {
    candidate: OwnPlanCandidate,
    lead: bool,
    tier: u8,
    successes: i32,
    confirmed: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnFirstResultAction {
    TryNext,
    Accept,
    StopForChallenge,
    ContinueFullClassifier,
}

pub fn own_first_result_action(
    phase_time_available: bool,
    verified: bool,
    cloudflare_challenge: bool,
) -> OwnFirstResultAction {
    if !phase_time_available {
        OwnFirstResultAction::ContinueFullClassifier
    } else if verified {
        OwnFirstResultAction::Accept
    } else if cloudflare_challenge {
        OwnFirstResultAction::StopForChallenge
    } else {
        OwnFirstResultAction::TryNext
    }
}

/// Select the next donor-sized batch of already-confirmed plans.
pub fn own_first_plans(
    catalog: &Catalog,
    target: &DiscoveryTarget,
    ech_replay: bool,
    bound_plan_id: Option<&str>,
    tried: &[u64],
    seen: &[u64],
) -> Vec<OwnPlanCandidate> {
    const BATCH: usize = 8;
    const SEEN_CAP: usize = 256;

    if target.shape == SHAPE_ECH_TCP && !ech_replay
        || !matches!(target.shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP)
        || seen.len() >= SEEN_CAP
    {
        return Vec::new();
    }
    let want = if target.shape == SHAPE_LEGACY {
        SHAPE_LEGACY
    } else {
        SHAPE_MODERN
    };
    let cross = if want == SHAPE_LEGACY {
        Some(SHAPE_MODERN)
    } else {
        Some(SHAPE_LEGACY)
    };
    let mut ranked = Vec::<RankedOwnPlan>::new();
    for box_record in &catalog.boxes {
        for plan in &box_record.plans {
            if !plan.enabled || plan.proto != "tls" || plan.text.len() >= 4096 {
                continue;
            }
            let mut best_binding: Option<(u8, i64)> = None;
            for binding in &box_record.bindings {
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
                let shape_matches = if ech_replay {
                    binding.shape == want && binding.ech_origin.is_empty()
                        || binding.shape == SHAPE_ECH_TCP
                } else {
                    (binding.shape == want || Some(binding.shape) == cross)
                        && binding.ech_origin.is_empty()
                };
                if binding.plan_id != plan.id
                    || !binding.enabled
                    || binding.level < 3
                    || binding.recheck_since.is_some()
                    || binding.kind != "name"
                    || transport != 6
                    || family != target.family
                    || binding.tcp_profile != target.tcp_profile()
                    || !shape_matches
                {
                    continue;
                }
                let tier = u8::from(binding.shape != want);
                if best_binding.is_none_or(|(best_tier, newest)| {
                    tier < best_tier || tier == best_tier && binding.confirmed > newest
                }) {
                    best_binding = Some((tier, binding.confirmed));
                }
            }
            let Some((tier, confirmed)) = best_binding else {
                continue;
            };
            let hash = crate::r2o_fallback::tried_key(&plan.text);
            if tried.contains(&hash) || seen.contains(&hash) {
                continue;
            }
            let candidate = RankedOwnPlan {
                candidate: OwnPlanCandidate {
                    box_id: box_record.id.clone(),
                    plan_id: plan.id.clone(),
                    text: plan.text.clone(),
                },
                lead: bound_plan_id == Some(plan.id.as_str()),
                tier,
                successes: plan.successes,
                confirmed,
            };
            if let Some(duplicate) = ranked
                .iter_mut()
                .find(|saved| saved.candidate.text == plan.text)
            {
                if own_rank_before(&candidate, duplicate) {
                    *duplicate = candidate;
                }
            } else {
                ranked.push(candidate);
            }
        }
    }
    ranked.sort_by(|left, right| {
        right
            .lead
            .cmp(&left.lead)
            .then_with(|| left.tier.cmp(&right.tier))
            .then_with(|| right.successes.cmp(&left.successes))
            .then_with(|| right.confirmed.cmp(&left.confirmed))
    });
    ranked
        .into_iter()
        .take(BATCH.min(SEEN_CAP - seen.len()))
        .map(|ranked| ranked.candidate)
        .collect()
}

/// Select the same first batch as `core/sched.c::known_plans`.
pub fn known_plans(
    catalog: &Catalog,
    target: &DiscoveryTarget,
    observed: &crate::catalog::Fingerprint,
    tried: &[u64],
) -> Vec<KnownPlanCandidate> {
    if observed.signals.is_empty() {
        return Vec::new();
    }
    let proto = if target.shape == SHAPE_QUIC {
        "quic"
    } else {
        "tls"
    };
    let mut ranked = Vec::new();
    for box_record in &catalog.boxes {
        if !box_record.fingerprint.is_compatible_with(observed) {
            continue;
        }
        let same_volume_bucket = observed.signals.iter().any(|signal| {
            matches!(
                signal.kind.as_str(),
                "volume" | "rx-volume" | "rx-volume-wire"
            ) && volume_bucket(signal.volume) > 0
                && box_record.fingerprint.signals.iter().any(|saved| {
                    saved.kind == signal.kind
                        && volume_bucket(saved.volume) == volume_bucket(signal.volume)
                })
        });
        for plan in &box_record.plans {
            if !plan.enabled
                || plan.proto != proto
                || plan.text.len() >= 4096
                || tried.contains(&crate::r2o_fallback::tried_key(&plan.text))
            {
                continue;
            }
            ranked.push((
                same_volume_bucket,
                plan.successes,
                KnownPlanCandidate {
                    box_id: box_record.id.clone(),
                    text: plan.text.clone(),
                },
            ));
        }
    }
    ranked.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
    let mut plans = Vec::new();
    for (_, _, candidate) in ranked {
        if !plans
            .iter()
            .any(|saved: &KnownPlanCandidate| saved.text == candidate.text)
        {
            plans.push(candidate);
            if plans.len() == 8 {
                break;
            }
        }
    }
    plans
}

fn volume_bucket(volume: i32) -> i32 {
    if volume <= 0 {
        return 0;
    }
    (i32::BITS - volume.leading_zeros()) as i32
}

fn own_rank_before(left: &RankedOwnPlan, right: &RankedOwnPlan) -> bool {
    left.lead > right.lead
        || left.lead == right.lead
            && (left.tier < right.tier
                || left.tier == right.tier
                    && (left.successes > right.successes
                        || left.successes == right.successes && left.confirmed > right.confirmed))
}

/// C `EPHEMERAL_FROM` (`core/sched.c:1778`): с этого порта начинается
/// клиентский (эфемерный) диапазон.
pub const EPHEMERAL_FROM: u16 = 32_768;

/// C `server_is_low` (`core/sched.c:1798-1805`): сервер — тот конец, чей
/// порт не эфемерный; если оба одинаковы по «эфемерности» — меньший порт.
pub const fn server_is_low(low_port: u16, high_port: u16) -> bool {
    let low_ephemeral = low_port >= EPHEMERAL_FROM;
    let high_ephemeral = high_port >= EPHEMERAL_FROM;
    if low_ephemeral != high_ephemeral {
        return high_ephemeral;
    }
    low_port <= high_port
}

/// C `client_ip_of` (`core/sched.c:1807-1811`): IP клиента — противоположный
/// серверу конец, младшие 4 байта для IPv4, все 16 для IPv6.
pub fn client_ip_of(
    family: u8,
    low_ip: [u8; 16],
    high_ip: [u8; 16],
    low_port: u16,
    high_port: u16,
) -> [u8; 16] {
    let mut client = if server_is_low(low_port, high_port) {
        high_ip
    } else {
        low_ip
    };
    if family != 6 {
        client[4..].fill(0);
    }
    client
}

/// C `server_of` (`core/sched.c:1813-1822`): адрес и порт серверного конца.
pub fn server_of(
    family: u8,
    low_ip: [u8; 16],
    low_port: u16,
    high_ip: [u8; 16],
    high_port: u16,
) -> Option<(IpAddr, u16)> {
    let (address, port) = if server_is_low(low_port, high_port) {
        (low_ip, low_port)
    } else {
        (high_ip, high_port)
    };
    match family {
        4 => Some((
            IpAddr::V4(Ipv4Addr::new(
                address[0], address[1], address[2], address[3],
            )),
            port,
        )),
        6 => Some((IpAddr::V6(Ipv6Addr::from(address)), port)),
        _ => None,
    }
}

impl DiscoveryTarget {
    /// TCP-профиль цели: контекстные формы 8–13 несут NO_TS/TS, базовые
    /// 1/2/6 — «не измерено» (0), как C `task_wire_shape`/`trigger_tcp_profile`.
    pub const fn tcp_profile(&self) -> u8 {
        r2k_core::control::r2k_link_shape_tcp_profile(self.shape)
    }

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
        let low_ip: [u8; 16] = event.key[1..17].try_into().ok()?;
        let high_ip: [u8; 16] = event.key[17..33].try_into().ok()?;
        // C `server_of`: серверный конец по эфемерности/величине портов, а не
        // по зашитому 443 — d2k охватывает весь IP-трафик на всех портах.
        let (address, port) = server_of(family, low_ip, low_port, high_ip, high_port)?;
        let endpoint = match address {
            IpAddr::V4(address) => format!("{address}:{port}"),
            IpAddr::V6(address) => format!("[{address}]:{port}"),
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
            tcp_has_timestamp: event.tcp_has_timestamp,
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
            || event.code == 4 && !crate::http_search::repeatable_path(&event.path)
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

pub const R2O_ECH_WITNESS_LIMIT: usize = 32;

/// Собрать ограниченный список HTTPS-владельцев, способных подтвердить ECH.
pub fn r2o_ech_witness_candidates(
    catalog: &Catalog,
    target: &DiscoveryTarget,
    recent_names: &[(String, bool)],
) -> Vec<String> {
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

    for (name, same_address) in recent_names {
        if *same_address {
            add(name);
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

    for (name, same_address) in recent_names {
        if !same_address {
            add(name);
        }
    }

    candidates
}

pub fn r2o_ech_witness_challenge_order(
    candidates: &[String],
    challenged: &[String],
) -> Vec<String> {
    candidates
        .iter()
        .filter(|candidate| {
            !challenged
                .iter()
                .any(|name| name.as_str() == candidate.as_str())
        })
        .chain(candidates.iter().filter(|candidate| {
            challenged
                .iter()
                .any(|name| name.as_str() == candidate.as_str())
        }))
        .cloned()
        .collect()
}

/// Проверить, что live-ответ относится к действующему сохранённому HTTP-плану.
pub fn matches_confirmed_http_catalog_owner(
    catalog: &Catalog,
    event: &HttpResponseEvent,
    acknowledged_binding: r2k_core::control::BindingContext,
) -> bool {
    let zero = [0; 16];
    if !matches!(event.code, 1 | 2)
        || event.key[37] != 6
        || u16::from_be_bytes([event.key[35], event.key[36]]) != 80
        || event.trial_id != zero
        || event.execution_id == 0
        || event.request_ms == 0
        || event.request_no == 0
        || !event.binding.is_known()
        || event.binding.temporary
        || event.binding.kind != 1
        || event.binding.family != event.key[0]
        || event.binding.shape != SHAPE_HTTP
        || event.binding != acknowledged_binding
        || !matches!(event.key[0], 4 | 6)
    {
        return false;
    }
    let Ok(host) = std::str::from_utf8(&event.host) else {
        return false;
    };
    let Some(host) = crate::domain::normalize(host).ok() else {
        return false;
    };
    let plan_id: String = event
        .plan_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if plan_id.bytes().all(|byte| byte == b'0') {
        return false;
    }

    catalog.boxes.iter().any(|box_record| {
        box_record
            .plans
            .iter()
            .any(|plan| plan.enabled && plan.id.eq_ignore_ascii_case(&plan_id))
            && box_record.bindings.iter().any(|binding| {
                binding.enabled
                    && binding.recheck_since.is_none()
                    && binding.level >= 3
                    && binding.kind == "name"
                    && crate::domain::normalize(&binding.target).is_ok_and(|target| target == host)
                    && binding.plan_id.eq_ignore_ascii_case(&plan_id)
                    && binding.transport == 6
                    && binding.family == event.key[0]
                    && binding.shape == SHAPE_HTTP
            })
    })
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

/// Отозвать текущую HTTP-привязку только для точного сохранённого plan ID.
pub fn revoke_http_search_binding(
    catalog: &mut Catalog,
    target: &DiscoveryTarget,
    plan_id: [u8; 16],
    now: i64,
) -> bool {
    if now < 0 || target.shape != SHAPE_HTTP || !matches!(target.family, 4 | 6) {
        return false;
    }
    let Ok(host) = crate::domain::normalize(&target.host) else {
        return false;
    };
    if host != target.host || plan_id.iter().all(|byte| *byte == 0) {
        return false;
    }
    let plan_id: String = plan_id.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut revoked = false;
    for box_record in &mut catalog.boxes {
        let owns_plan = box_record.plans.iter().any(|plan| {
            plan.enabled
                && plan.proto.eq_ignore_ascii_case("http")
                && plan.id.eq_ignore_ascii_case(&plan_id)
        });
        if !owns_plan {
            continue;
        }
        let previous_len = box_record.bindings.len();
        box_record.bindings.retain(|binding| {
            let owned = binding.enabled
                && binding.recheck_since.is_none()
                && binding.kind == "name"
                && binding.target == host
                && binding.plan_id.eq_ignore_ascii_case(&plan_id)
                && binding.level >= 3
                && binding.transport == 6
                && binding.family == target.family
                && binding.shape == SHAPE_HTTP
                && binding.verified_by == 1
                && binding.input == 2;
            if owned {
                revoked = true;
            }
            !owned
        });
        if box_record.bindings.len() != previous_len {
            box_record.updated = box_record.updated.max(now.max(1));
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

/// Проверить, покрывает ли активная подтверждённая привязка видимую форму потока.
/// Мягкие привязки и привязки на повторной проверке не подавляют новое наблюдение.
pub fn has_covering_binding(catalog: &Catalog, target: &DiscoveryTarget) -> bool {
    catalog.boxes.iter().any(|box_record| {
        box_record.bindings.iter().any(|binding| {
            let family = if binding.family == 0 {
                4
            } else {
                binding.family
            };
            let transport = if binding.transport == 0 {
                6
            } else {
                binding.transport
            };
            binding.enabled
                && binding.level >= 3
                && binding.recheck_since.is_none()
                && binding.kind == "name"
                && binding.target == target.host
                && family == target.family
                && transport == 6
                && binding.tcp_profile == target.tcp_profile()
                && (binding.shape == 0
                    || binding.shape == target.shape
                    || binding.shape == SHAPE_MODERN && target.shape == SHAPE_ECH_TCP)
        })
    })
}

/// C `own_exact_confirmed` (`sched.c:6278-6293`): точное имя, транспорт и
/// семейство; для TCP — `!shape || tcp_context(shape, tcp_profile)==key.shape`.
pub fn has_confirmed_exact_binding(catalog: &Catalog, observation: &DomainObservation) -> bool {
    catalog.boxes.iter().any(|box_record| {
        box_record.bindings.iter().any(|binding| {
            let transport = normalized_transport(binding.transport);
            let family = normalized_family(binding.family);
            let shape_matches = if transport == 6 {
                binding.shape == 0
                    || r2k_core::control::r2k_link_shape_tcp_context(
                        binding.shape,
                        binding.tcp_profile,
                    ) == observation.key.shape
            } else {
                binding.shape == observation.key.shape
            };
            binding.enabled
                && binding.level >= 3
                && binding.recheck_since.is_none()
                && binding.kind == "name"
                && binding.target == observation.name
                && transport == observation.key.transport
                && family == observation.key.family
                && shape_matches
        })
    })
}

fn has_usable_binding_with_input(
    catalog: &Catalog,
    target: &DiscoveryTarget,
    input: Option<u8>,
) -> bool {
    catalog.boxes.iter().any(|box_record| {
        box_record.bindings.iter().any(|binding| {
            if !binding.enabled
                || binding.recheck_since.is_some()
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
        || !matches!(target.shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP)
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
            // MODERN-привязка покрывает ECH/TLS 1.3 так же, как в
            // has_covering_binding и в C binding_covering. Без этого
            // direct-clear ECH-потока не снимал бы устаревшую MODERN-привязку.
            let modern_covers_ech = binding.shape == SHAPE_MODERN && target.shape == SHAPE_ECH_TCP;
            let matches_target = binding.kind == "name"
                && binding.target == target.host
                && transport == 6
                && family == target.family
                && binding.tcp_profile == target.tcp_profile()
                && (binding.shape == 0 || binding.shape == target.shape || modern_covers_ech);
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
            update.delete_runtime |= transport == 6
                && family == target.family
                && (binding.shape == target.shape || modern_covers_ech);
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
    add_measured_binding_with_fingerprint(catalog, target, source_text, now, input, None)
}

/// Сохранить план и связать его с отпечатком, подтверждённым тем же замером.
pub fn add_measured_binding_with_fingerprint(
    catalog: &mut Catalog,
    target: &DiscoveryTarget,
    source_text: &str,
    now: i64,
    input: u8,
    observed_fingerprint: Option<&crate::catalog::Fingerprint>,
) -> Result<String, String> {
    add_measured_binding_with_fingerprint_in_box(
        catalog,
        target,
        source_text,
        now,
        input,
        observed_fingerprint,
        None,
    )
}

/// Сохранить подтверждённый план в той же коробке, откуда он был взят.
pub fn add_measured_binding_with_fingerprint_in_box(
    catalog: &mut Catalog,
    target: &DiscoveryTarget,
    source_text: &str,
    now: i64,
    input: u8,
    observed_fingerprint: Option<&crate::catalog::Fingerprint>,
    preferred_box_id: Option<&str>,
) -> Result<String, String> {
    if !matches!(target.family, 4 | 6)
        || !(matches!(
            target.shape,
            SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP | SHAPE_HTTP
        ) || r2k_core::control::is_tcp_context_shape(target.shape))
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
    // C `bind_confirmed` принимает любой серверный порт: d2k охватывает весь
    // IP-трафик, а не только 443/80. Порт 80 для HTTP задаёт
    // `from_http_portal`, здесь проверяется лишь семейство и ненулевой порт.
    if endpoint.port() == 0 || endpoint.is_ipv4() != (target.family == 4) {
        return Err("discovery endpoint disagrees with its target family or port".into());
    }
    if now < 0 {
        return Err("discovery timestamp must be nonnegative".into());
    }
    let canonical_text = canonical_plan_text(source_text)?;
    let compatible_boxes: Vec<usize> = observed_fingerprint
        .map(|observed| {
            catalog
                .boxes
                .iter()
                .enumerate()
                .filter_map(|(index, box_record)| {
                    box_record
                        .fingerprint
                        .is_compatible_with(observed)
                        .then_some(index)
                })
                .collect()
        })
        .unwrap_or_default();
    let preferred_box_index = if let Some(box_id) = preferred_box_id {
        // C-оракул (box_id_for): коробка, узнанная при планировании
        // (t->box_id), принимает подтверждение безусловно. Несовпадение
        // отпечатка не отменяет найденный план: bind_confirmed не смешивает
        // чужие identity-признаки, а обновляет только объёмные.
        let index = catalog
            .boxes
            .iter()
            .position(|box_record| box_record.id == box_id)
            .ok_or("known plan owner disappeared from the catalog")?;
        Some(index)
    } else {
        None
    };
    let plan_search_boxes: Vec<usize> = if observed_fingerprint.is_some() {
        if let Some(preferred) = preferred_box_index {
            std::iter::once(preferred)
                .chain(
                    compatible_boxes
                        .iter()
                        .copied()
                        .filter(|index| *index != preferred),
                )
                .collect()
        } else {
            compatible_boxes.clone()
        }
    } else {
        (0..catalog.boxes.len()).collect()
    };
    let plan_id = plan_search_boxes
        .iter()
        .filter_map(|index| catalog.boxes.get(*index))
        .find_map(|box_record| {
            box_record.plans.iter().find(|plan| {
                plan.enabled
                    && (observed_fingerprint.is_some()
                        || box_record.bindings.iter().any(|binding| {
                            binding.enabled
                                && binding.transport == 6
                                && binding.family == target.family
                                && binding.shape == target.shape
                                && binding.plan_id == plan.id
                        }))
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

    let matching_plan_box = plan_search_boxes.iter().copied().find(|index| {
        catalog.boxes[*index]
            .plans
            .iter()
            .any(|saved| saved.id == plan_id)
    });
    let box_index = if let Some(index) = preferred_box_index {
        index
    } else if let Some(index) = matching_plan_box {
        index
    } else if observed_fingerprint.is_some() && compatible_boxes.len() == 1 {
        compatible_boxes[0]
    } else if observed_fingerprint.is_none()
        && let Some(index) = catalog
            .boxes
            .iter()
            .position(|box_record| box_record.plans.iter().any(|saved| saved.id == plan_id))
    {
        index
    } else {
        let base_id = format!("auto-{plan_id}");
        let id = if catalog
            .boxes
            .iter()
            .all(|box_record| box_record.id != base_id)
        {
            base_id
        } else {
            let mut selected_id = None;
            for salt in 0_u8..=u8::MAX {
                let candidate = format!("auto-{}-{salt:02x}", &plan_id[..30]);
                if catalog
                    .boxes
                    .iter()
                    .all(|box_record| box_record.id != candidate)
                {
                    selected_id = Some(candidate);
                    break;
                }
            }
            selected_id.ok_or("could not allocate a catalog box id")?
        };
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
    if let Some(observed) = observed_fingerprint {
        if selected.fingerprint.signals.is_empty() {
            selected.fingerprint = observed.clone();
        } else if selected.fingerprint.is_compatible_with(observed) {
            selected.fingerprint.merge_observed(observed);
        } else {
            // C bind_confirmed: у заведённой коробки обновляются только
            // объёмные приметы; identity не переписывается чужым замером.
            selected.fingerprint.merge_volume_observed(observed);
        }
    }
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
        tcp_profile: r2k_core::control::r2k_link_shape_tcp_profile(target.shape),
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
    add_confirmed_quic_binding(
        catalog,
        "addr",
        &address.to_string(),
        family,
        "",
        source_text,
        now,
    )
}

pub fn add_confirmed_quic_name_binding(
    catalog: &mut Catalog,
    host: &str,
    family: u8,
    probe_path: &str,
    source_text: &str,
    now: i64,
) -> Result<String, String> {
    let host = crate::domain::normalize(host)
        .map_err(|error| format!("имя QUIC-привязки недопустимо: {error}"))?;
    if host.parse::<std::net::IpAddr>().is_ok()
        || crate::domain::registrable_domain(&host).is_none()
        || !matches!(family, 4 | 6)
        || (!probe_path.is_empty() && !crate::r2o_resource::r2o_resource_path_ok(probe_path))
        || now < 0
    {
        return Err("QUIC-привязка имени имеет недопустимые имя, путь или семейство".into());
    }
    add_confirmed_quic_binding(catalog, "name", &host, family, probe_path, source_text, now)
}

fn add_confirmed_quic_binding(
    catalog: &mut Catalog,
    kind: &str,
    target: &str,
    family: u8,
    probe_path: &str,
    source_text: &str,
    now: i64,
) -> Result<String, String> {
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

    let matches_binding = |binding: &Binding| {
        if kind == "addr" {
            quic_binding_key(binding, target, family)
        } else {
            binding.kind == kind
                && binding.target == target
                && binding.transport == 17
                && (binding.family == family || binding.family == 0 && family == 4)
                && binding.shape == SHAPE_QUIC
        }
    };
    let mut prior_successes = 0_i32;
    for record in &mut catalog.boxes {
        for binding in &record.bindings {
            if matches_binding(binding) {
                prior_successes = prior_successes.max(binding.successes);
            }
        }
        record.bindings.retain(|binding| !matches_binding(binding));
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
        kind: kind.into(),
        target: target.into(),
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
        probe_path: probe_path.into(),
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
        && binding.tcp_profile == target.tcp_profile()
}

fn usable_runtime_plan(plan: &RuntimePlan, shape: u8) -> bool {
    plan.transport == 6
        && match shape {
            SHAPE_HTTP => plan.proto == r2k_core::plan::PROTO_HTTP,
            // ECH-предложение — тоже TLS 1.3 по TCP: C-оракул пишет привязку
            // формой D2K_LINK_SHAPE_ECH_TCP и принимает те же TLS-планы.
            SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.proto == 1,
            _ if r2k_core::control::is_tcp_context_shape(shape) => plan.proto == 1,
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

/// C `plan_ident` (`core/sched.c:3598-3605`): `plan-%08x` от младших 32 бит
/// FNV-1a текста плана; на провод уходят ASCII-байты строки, добитые нулями
/// до 16. Текст хешируется в каноническом виде (id из нулей).
pub fn plan_ident(text: &str) -> Result<(String, [u8; 16]), String> {
    let canonical = canonical_plan_text(text)?;
    let mut hash = 1_469_598_103_934_665_603_u64;
    for byte in canonical.bytes() {
        hash = (hash ^ u64::from(byte)).wrapping_mul(1_099_511_628_211);
    }
    let name = format!("plan-{:08x}", (hash & 0xffff_ffff) as u32);
    let mut wire = [0_u8; 16];
    let bytes = name.as_bytes();
    let length = bytes.len().min(wire.len());
    wire[..length].copy_from_slice(&bytes[..length]);
    Ok((name, wire))
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
    use super::{
        DiscoveryTarget, OwnFirstResultAction, exact_key, has_covering_binding, known_plans,
        newer_name_binding, own_first_bound_plan_id, own_first_plans, own_first_result_action,
        r2o_ech_witness_candidates, r2o_ech_witness_challenge_order, update_direct_clear_bindings,
    };
    use r2k_core::control::{
        BindingContext, HttpResponseEvent, KEY_LEN, SHAPE_ECH_TCP, SHAPE_HTTP, SHAPE_MODERN,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn hello_key(
        family: u8,
        low_ip: &[u8],
        high_ip: &[u8],
        low_port: u16,
        high_port: u16,
    ) -> [u8; KEY_LEN] {
        let mut key = [0_u8; KEY_LEN];
        key[0] = family;
        key[1..1 + low_ip.len()].copy_from_slice(low_ip);
        key[17..17 + high_ip.len()].copy_from_slice(high_ip);
        key[33..35].copy_from_slice(&low_port.to_be_bytes());
        key[35..37].copy_from_slice(&high_port.to_be_bytes());
        key[37] = 6;
        key
    }

    #[test]
    fn server_selection_matches_c_sched_helpers() {
        // C `server_is_low`: эфемерный конец — клиент.
        assert!(!super::server_is_low(51_000, 443));
        assert!(super::server_is_low(443, 51_000));
        // Оба не эфемерные — сервер меньший порт; оба эфемерные — тоже меньший.
        assert!(super::server_is_low(80, 8443));
        assert!(!super::server_is_low(8443, 80));
        assert!(super::server_is_low(50_000, 60_000));

        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut low = [0_u8; 16];
        low[..4].copy_from_slice(&client);
        let mut high = [0_u8; 16];
        high[..4].copy_from_slice(&server);
        assert_eq!(
            &super::client_ip_of(4, low, high, 51_000, 443)[..4],
            &client
        );
        assert_eq!(
            super::server_of(4, low, 51_000, high, 443),
            Some((IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443))
        );
        assert_eq!(
            super::server_of(4, low, 443, high, 51_000),
            Some((IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443))
        );

        // Нестандартный серверный порт 8443 теперь тоже даёт цель.
        let event = r2k_core::control::HelloEvent {
            key: hello_key(4, &client, &server, 40_000, 8443),
            host: Some(b"example.com".to_vec()),
            shape: Some(super::SHAPE_MODERN),
            r2o_wire_len: None,
            quic_snapshot: None,
            tcp_has_timestamp: None,
        };
        let target = DiscoveryTarget::from_event(&event).unwrap();
        assert_eq!(target.endpoint, "198.51.100.20:8443");
        assert_eq!(target.host, "example.com");

        let event = r2k_core::control::HelloEvent {
            key: hello_key(4, &client, &server, 8443, 40_000),
            host: Some(b"example.com".to_vec()),
            shape: Some(super::SHAPE_MODERN),
            r2o_wire_len: None,
            quic_snapshot: None,
            tcp_has_timestamp: None,
        };
        let target = DiscoveryTarget::from_event(&event).unwrap();
        assert_eq!(target.endpoint, "192.0.2.10:8443");

        let event = r2k_core::control::HelloEvent {
            key: hello_key(4, &client, &server, 443, 443),
            host: Some(b"example.com".to_vec()),
            shape: Some(super::SHAPE_MODERN),
            r2o_wire_len: None,
            quic_snapshot: None,
            tcp_has_timestamp: None,
        };
        let target = DiscoveryTarget::from_event(&event).unwrap();
        assert_eq!(target.endpoint, "192.0.2.10:443");
    }

    #[test]
    fn own_first_plan_batches_match_donor_scheduler() {
        use crate::catalog::{Binding, BoxRecord, Catalog, Plan};
        use crate::r2o_fallback::tried_key;

        let mut catalog = Catalog::default();
        let mut tried = Vec::new();
        for row in include_str!("../tests/fixtures/d2o_own_first.tsv").lines() {
            if row.starts_with('#') || row.is_empty() {
                continue;
            }
            let columns: Vec<_> = row.split('\t').collect();
            assert_eq!(columns.len(), 14, "fixture row: {row}");
            let box_index = catalog
                .boxes
                .iter()
                .position(|box_record| box_record.id == columns[0])
                .unwrap_or_else(|| {
                    catalog.boxes.push(BoxRecord {
                        id: columns[0].into(),
                        ..BoxRecord::default()
                    });
                    catalog.boxes.len() - 1
                });
            let number = |index: usize| columns[index].parse::<i64>().unwrap();
            let plan_id = columns[1].to_owned();
            let text = columns[2].to_owned();
            catalog.boxes[box_index].plans.push(Plan {
                id: plan_id.clone(),
                proto: "tls".into(),
                text: text.clone(),
                successes: number(3) as i32,
                enabled: number(4) != 0,
                ..Plan::default()
            });
            catalog.boxes[box_index].bindings.push(Binding {
                kind: "name".into(),
                target: "other.example".into(),
                plan_id,
                level: number(6) as i32,
                confirmed: number(12),
                enabled: number(5) != 0,
                transport: number(7) as u8,
                family: number(8) as u8,
                shape: number(9) as u8,
                recheck_since: (number(10) != 0).then_some(100),
                ech_origin: columns[11].into(),
                ..Binding::default()
            });
            if number(13) != 0 {
                tried.push(tried_key(&text));
            }
        }
        let target = DiscoveryTarget {
            host: "other.example".into(),
            endpoint: "192.0.2.1:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let planned = std::env::var("R2O_OWN_FIRST_DIFF_PLANNED").is_ok_and(|value| value == "1");
        let bound_plan = planned
            .then(|| own_first_bound_plan_id(&catalog, &target, target.shape))
            .flatten();
        let mut seen = Vec::new();
        let mut output = String::new();
        loop {
            let batch = own_first_plans(
                &catalog,
                &target,
                false,
                bound_plan.as_deref(),
                &tried,
                &seen,
            );
            if batch.is_empty() {
                break;
            }
            for candidate in batch {
                output.push_str(&format!("{}\t{}\n", candidate.box_id, candidate.text));
                seen.push(tried_key(&candidate.text));
            }
        }
        if let Ok(path) = std::env::var("R2O_OWN_FIRST_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
        assert!(
            seen.len() >= 8,
            "the fixture exercises multiple donor batches"
        );
    }

    #[test]
    fn own_first_deadline_precedes_late_verified_and_challenge_results() {
        let mut output = String::new();
        for (label, elapsed_ms, verified, challenge) in [
            ("on_time_verified", 600_000_u64, true, false),
            ("late_verified", 600_001, true, false),
            ("on_time_challenge", 600_000, false, true),
            ("late_challenge", 600_001, false, true),
        ] {
            let phase_time_available = elapsed_ms <= 600_000;
            let action = own_first_result_action(phase_time_available, verified, challenge);
            let accepted = action == OwnFirstResultAction::Accept;
            let continue_full = action == OwnFirstResultAction::ContinueFullClassifier;
            output.push_str(&format!(
                "{label}:accepted={},continue_full={}\n",
                u8::from(accepted),
                u8::from(continue_full)
            ));
        }
        if let Ok(path) = std::env::var("R2O_OWN_FIRST_DEADLINE_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert_eq!(
            output,
            concat!(
                "on_time_verified:accepted=1,continue_full=0\n",
                "late_verified:accepted=0,continue_full=1\n",
                "on_time_challenge:accepted=0,continue_full=0\n",
                "late_challenge:accepted=0,continue_full=1\n",
            )
        );
    }

    #[test]
    fn ech_witness_search_retries_challenged_names_after_unchallenged_names() {
        let candidates = ["u1", "challenged-c1", "u2"].map(str::to_owned);
        let challenged = ["challenged-c1".to_owned()];
        let order = r2o_ech_witness_challenge_order(&candidates, &challenged);
        let selected = order
            .iter()
            .find(|name| {
                matches!(name.as_str(), "u1" | "u2")
                    .then_some("other.example")
                    .or_else(|| (name.as_str() == "challenged-c1").then_some("public.example"))
                    == Some("public.example")
            })
            .map(String::as_str)
            .unwrap_or("none");
        let output = format!("witnesses:chosen={selected}\n");
        if let Ok(path) = std::env::var("R2O_ECH_WITNESS_ORDER_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert_eq!(order, ["u1", "u2", "challenged-c1"]);
        assert_eq!(output, "witnesses:chosen=challenged-c1\n");
    }

    #[test]
    fn known_plan_candidates_match_donor_scheduler() {
        use crate::catalog::{BoxRecord, Catalog, Fingerprint, Plan, Signal};
        use crate::r2o_fallback::tried_key;

        struct Case {
            id: String,
            catalog: Catalog,
            observed: Fingerprint,
            transport: u8,
            tried: Vec<u64>,
        }
        let mut cases: Vec<Case> = Vec::new();
        for row in include_str!("../tests/fixtures/d2o_known_plans.tsv").lines() {
            if row.starts_with('#') || row.is_empty() {
                continue;
            }
            let columns: Vec<_> = row.split('\t').collect();
            assert_eq!(columns.len(), 21, "fixture row: {row}");
            let number = |index: usize| columns[index].parse::<i32>().unwrap();
            let index = cases
                .iter()
                .position(|case| case.id == columns[0])
                .unwrap_or_else(|| {
                    cases.push(Case {
                        id: columns[0].into(),
                        catalog: Catalog::default(),
                        observed: Fingerprint {
                            method: number(20),
                            signals: Vec::new(),
                        },
                        transport: number(17) as u8,
                        tried: Vec::new(),
                    });
                    cases.len() - 1
                });
            let case = &mut cases[index];
            assert_eq!(
                case.transport,
                number(17) as u8,
                "fixture case: {}",
                case.id
            );
            assert_eq!(
                case.observed.method,
                number(20),
                "fixture case: {}",
                case.id
            );
            if columns[1].is_empty() {
                continue;
            }
            let box_index = case
                .catalog
                .boxes
                .iter()
                .position(|box_record| box_record.id == columns[1])
                .unwrap_or_else(|| {
                    case.catalog.boxes.push(BoxRecord {
                        id: columns[1].into(),
                        fingerprint: Fingerprint {
                            method: crate::catalog::FINGERPRINT_METHOD,
                            signals: Vec::new(),
                        },
                        ..BoxRecord::default()
                    });
                    case.catalog.boxes.len() - 1
                });
            let box_record = &mut case.catalog.boxes[box_index];
            box_record.fingerprint.method = number(19);
            if !columns[2].is_empty() {
                if !box_record.plans.iter().any(|plan| plan.id == columns[2]) {
                    box_record.plans.push(Plan {
                        id: columns[2].into(),
                        proto: columns[3].into(),
                        text: columns[4].into(),
                        successes: number(5),
                        enabled: number(6) != 0,
                        ..Plan::default()
                    });
                }
                if number(18) != 0 {
                    case.tried.push(tried_key(columns[4]));
                }
            }
            let signal = |kind: &str, ttl, tos, ipid, volume| {
                (kind != "-").then(|| Signal {
                    kind: kind.into(),
                    ttl,
                    tos,
                    ipid,
                    volume,
                    seen: 1,
                    ..Signal::default()
                })
            };
            if let Some(signal) = signal(
                columns[7],
                number(8) as u8,
                number(9) as u8,
                number(10) as u16,
                number(11),
            ) {
                box_record.fingerprint.signals.push(signal);
            }
            if let Some(signal) = signal(
                columns[12],
                number(13) as u8,
                number(14) as u8,
                number(15) as u16,
                number(16),
            ) {
                case.observed.merge_observed(&Fingerprint {
                    method: crate::catalog::FINGERPRINT_METHOD,
                    signals: vec![signal],
                });
            }
        }

        let mut output = String::new();
        for case in cases {
            let target = DiscoveryTarget {
                host: case.id.clone(),
                endpoint: "192.0.2.1:443".into(),
                family: 4,
                shape: if case.transport == 17 {
                    r2k_core::control::SHAPE_QUIC
                } else {
                    SHAPE_MODERN
                },
            };
            for candidate in known_plans(&case.catalog, &target, &case.observed, &case.tried) {
                output.push_str(&format!(
                    "{}\t{}\t{}\n",
                    case.id, candidate.box_id, candidate.text
                ));
            }
            if case.id == "empty" {
                assert!(case.observed.signals.is_empty());
            }
        }
        if let Ok(path) = std::env::var("R2O_KNOWN_PLANS_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

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
            r2o_ech_witness_candidates(&catalog, &target, &[]),
            [
                "family-witness.example",
                "other-family.example",
                "third-witness.example",
                "new-target.example",
                "old-target.example",
            ]
        );
    }

    #[test]
    fn современная_привязка_покрывает_ech_и_снятая_с_проверки_не_покрывает() {
        use crate::catalog::{Binding, BoxRecord, Catalog};

        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: SHAPE_ECH_TCP,
        };
        let binding = Binding {
            kind: "name".into(),
            target: target.host.clone(),
            level: 3,
            enabled: true,
            transport: 6,
            family: 4,
            shape: SHAPE_MODERN,
            ..Binding::default()
        };
        let catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![binding.clone()],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        assert!(super::has_covering_binding(&catalog, &target));

        let mut recheck = binding;
        recheck.recheck_since = Some(1);
        let recheck_catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![recheck],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        assert!(!super::has_covering_binding(&recheck_catalog, &target));
    }

    #[test]
    fn direct_clear_помечает_modern_привязку_для_ech() {
        use crate::catalog::{Binding, BoxRecord, Catalog};

        let target = DiscoveryTarget {
            host: "discord.com".into(),
            endpoint: "198.51.100.81:443".into(),
            family: 4,
            shape: SHAPE_ECH_TCP,
        };
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: target.host.clone(),
                    level: 3,
                    enabled: true,
                    transport: 6,
                    family: 4,
                    shape: SHAPE_MODERN,
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        let update = super::update_direct_clear_bindings(
            &mut catalog,
            &target,
            100,
            std::time::Instant::now(),
        );
        assert_eq!(update.marked, 1);
        assert!(update.delete_runtime);
        assert_eq!(catalog.boxes[0].bindings[0].recheck_since, Some(100));
    }

    #[test]
    fn неподтверждённый_ech_offer_переходит_на_обычную_форму_tls13() {
        let mut target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: SHAPE_ECH_TCP,
        };
        assert!(super::regrade_ech_grease(&mut target));
        assert_eq!(target.shape, SHAPE_MODERN);
        assert!(!super::regrade_ech_grease(&mut target));
    }

    #[test]
    fn r2o_ech_свидетели_ставят_свежие_имена_по_приоритету_адреса() {
        use crate::catalog::{Binding, BoxRecord, Catalog};

        let target = DiscoveryTarget {
            host: "cloudflare-ech.com".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_ECH_TCP,
        };
        let catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: "own.example".into(),
                    level: 3,
                    confirmed: 100,
                    enabled: true,
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };

        let recent_names = vec![
            ("same-address.example".into(), true),
            ("other-address.example".into(), false),
        ];
        assert_eq!(
            r2o_ech_witness_candidates(&catalog, &target, &recent_names),
            [
                "same-address.example",
                "own.example",
                "other-address.example"
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
    fn ech_предложение_сохраняет_подтверждённый_tls_план_формой_ech() {
        // C-оракул: record_shape ECH-задачи — D2K_LINK_SHAPE_ECH_TCP,
        // bind_confirmed пишет привязку этой формой. Сохранение не должно
        // отвергать цель только за то, что клиент предложил ECH.
        let target = DiscoveryTarget {
            host: "gateway.discord.gg".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: SHAPE_ECH_TCP,
        };
        let mut catalog = crate::catalog::Catalog::default();
        let plan_id = super::add_measured_binding_with_fingerprint(
            &mut catalog,
            &target,
            "r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +0\n",
            100,
            1,
            None,
        )
        .unwrap();

        assert!(!plan_id.is_empty());
        let binding = &catalog.boxes[0].bindings[0];
        assert_eq!(binding.target, "gateway.discord.gg");
        assert_eq!(binding.shape, SHAPE_ECH_TCP);
        assert_eq!(binding.input, 1);
        assert_eq!(binding.level, 3);
        assert!(super::has_usable_binding(&catalog, &target));
    }

    #[test]
    fn подтверждение_известной_коробки_принимает_чужой_отпечаток_без_смешивания_identity() {
        use crate::catalog::{BoxRecord, Catalog, Fingerprint, Signal};

        let target = DiscoveryTarget {
            host: "updates.discord.com".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                id: "known-box".into(),
                fingerprint: Fingerprint {
                    method: 2,
                    signals: vec![
                        Signal {
                            kind: "rx-volume".into(),
                            volume: 16,
                            seen: 3,
                            packets: 10,
                            ..Signal::default()
                        },
                        Signal {
                            kind: "rst".into(),
                            ttl: 128,
                            ..Signal::default()
                        },
                    ],
                },
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        let observed = Fingerprint {
            method: 2,
            signals: vec![
                Signal {
                    kind: "rx-volume".into(),
                    volume: 16,
                    seen: 1,
                    packets: 22,
                    ..Signal::default()
                },
                Signal {
                    kind: "rst".into(),
                    ttl: 64,
                    ttl_delta: 63,
                    ..Signal::default()
                },
            ],
        };

        super::add_measured_binding_with_fingerprint_in_box(
            &mut catalog,
            &target,
            "r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +0\n",
            100,
            1,
            Some(&observed),
            Some("known-box"),
        )
        .unwrap();

        assert_eq!(catalog.boxes.len(), 1);
        assert_eq!(catalog.boxes[0].id, "known-box");
        assert_eq!(catalog.boxes[0].bindings[0].target, "updates.discord.com");
        let volume = catalog.boxes[0]
            .fingerprint
            .signals
            .iter()
            .find(|signal| signal.kind == "rx-volume")
            .unwrap();
        assert_eq!(volume.packets, 22);
        assert_eq!(volume.seen, 4);
        let rst = catalog.boxes[0]
            .fingerprint
            .signals
            .iter()
            .find(|signal| signal.kind == "rst")
            .unwrap();
        assert_eq!(rst.ttl, 128, "identity чужого замера не перезаписывается");
    }

    #[test]
    fn прямой_проход_помечает_привязку_ech_цели() {
        use super::update_direct_clear_bindings;
        use crate::catalog::{Binding, BoxRecord, Catalog};

        let target = DiscoveryTarget {
            host: "gateway.discord.gg".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: SHAPE_ECH_TCP,
        };
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: target.host.clone(),
                    enabled: true,
                    transport: 6,
                    family: 4,
                    shape: SHAPE_ECH_TCP,
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };

        let result =
            update_direct_clear_bindings(&mut catalog, &target, 100, std::time::Instant::now());

        assert_eq!(result.marked, 1);
        assert_eq!(result.removed, 0);
        assert!(result.delete_runtime);
        assert_eq!(catalog.boxes[0].bindings[0].recheck_since, Some(100));
    }

    #[test]
    fn measured_volume_plan_updates_only_its_unambiguous_compatible_box() {
        use crate::catalog::{BoxRecord, Fingerprint, Signal};

        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_MODERN,
        };
        let observed = Fingerprint {
            method: 2,
            signals: vec![Signal {
                kind: "rx-volume".into(),
                volume: 19,
                seen: 1,
                packets: 22,
                ..Signal::default()
            }],
        };
        let mut catalog = crate::catalog::Catalog {
            boxes: vec![BoxRecord {
                id: "rx-volume-16kb".into(),
                fingerprint: Fingerprint {
                    method: 2,
                    signals: vec![Signal {
                        kind: "rx-volume".into(),
                        volume: 16,
                        seen: 3,
                        packets: 30,
                        ..Signal::default()
                    }],
                },
                ..BoxRecord::default()
            }],
            ..crate::catalog::Catalog::default()
        };
        let text = "r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +8\n";
        super::add_measured_binding_with_fingerprint(
            &mut catalog,
            &target,
            text,
            100,
            2,
            Some(&observed),
        )
        .unwrap();

        assert_eq!(catalog.boxes.len(), 1);
        assert_eq!(catalog.boxes[0].id, "rx-volume-16kb");
        let saved = &catalog.boxes[0].fingerprint.signals[0];
        assert_eq!(saved.volume, 16);
        assert_eq!(saved.seen, 4);
        assert_eq!(saved.packets, 22);
        assert_eq!(catalog.boxes[0].plans.len(), 1);

        let mut ambiguous = catalog.clone();
        ambiguous.boxes.push(BoxRecord {
            id: "rx-volume-20kb".into(),
            fingerprint: Fingerprint {
                method: 2,
                signals: vec![Signal {
                    kind: "rx-volume".into(),
                    volume: 20,
                    seen: 1,
                    packets: 18,
                    ..Signal::default()
                }],
            },
            ..BoxRecord::default()
        });
        let another_target = DiscoveryTarget {
            host: "other.example.com".into(),
            ..target
        };
        super::add_measured_binding_with_fingerprint(
            &mut ambiguous,
            &another_target,
            "r2o-plan 1 11\nid 11111111111111111111111111111111\nproto tcp tls\nsplit sni_middle +9\n",
            101,
            2,
            Some(&observed),
        )
        .unwrap();
        assert_eq!(ambiguous.boxes.len(), 3);
        assert_eq!(ambiguous.boxes[0].plans.len(), 1);
        assert_eq!(ambiguous.boxes[1].plans.len(), 0);
        assert_eq!(ambiguous.boxes[2].fingerprint.signals[0].volume, 19);
        assert_eq!(ambiguous.boxes[2].plans.len(), 1);
    }

    #[test]
    fn measured_known_plan_keeps_the_box_that_supplied_it() {
        use crate::catalog::{BoxRecord, Fingerprint, Plan, Signal};

        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_MODERN,
        };
        let observed = Fingerprint {
            method: 2,
            signals: vec![Signal {
                kind: "rx-volume".into(),
                volume: 19,
                seen: 1,
                packets: 22,
                ..Signal::default()
            }],
        };
        let plan_a_id = "aa".repeat(16);
        let plan_b_id = "bb".repeat(16);
        let plan_text =
            |id: &str| format!("r2o-plan 1 11\nid {id}\nproto tcp tls\nsplit sni_middle +8\n");
        let mut catalog = crate::catalog::Catalog {
            boxes: vec![
                BoxRecord {
                    id: "box-a".into(),
                    fingerprint: Fingerprint {
                        method: 2,
                        signals: vec![Signal {
                            kind: "rx-volume".into(),
                            volume: 16,
                            seen: 1,
                            ..Signal::default()
                        }],
                    },
                    plans: vec![Plan {
                        id: plan_a_id.clone(),
                        proto: "tls".into(),
                        text: plan_text(&plan_a_id),
                        enabled: true,
                        ..Plan::default()
                    }],
                    ..BoxRecord::default()
                },
                BoxRecord {
                    id: "box-b".into(),
                    fingerprint: Fingerprint {
                        method: 2,
                        signals: vec![Signal {
                            kind: "rx-volume".into(),
                            volume: 20,
                            seen: 1,
                            ..Signal::default()
                        }],
                    },
                    plans: vec![Plan {
                        id: plan_b_id.clone(),
                        proto: "tls".into(),
                        text: plan_text(&plan_b_id),
                        enabled: true,
                        ..Plan::default()
                    }],
                    ..BoxRecord::default()
                },
            ],
            ..crate::catalog::Catalog::default()
        };

        let saved_plan_id = super::add_measured_binding_with_fingerprint_in_box(
            &mut catalog,
            &target,
            &plan_text(&plan_b_id),
            100,
            2,
            Some(&observed),
            Some("box-b"),
        )
        .unwrap();

        assert_eq!(saved_plan_id, plan_b_id);
        assert_eq!(catalog.boxes[0].bindings.len(), 0);
        assert_eq!(catalog.boxes[1].bindings[0].target, target.host);
        assert_eq!(catalog.boxes[1].bindings[0].plan_id, plan_b_id);
        assert_eq!(catalog.boxes[0].fingerprint.signals[0].seen, 1);
        assert_eq!(catalog.boxes[1].fingerprint.signals[0].seen, 2);
    }

    #[test]
    fn plan_ident_matches_c_fnv_and_ascii_wire_id() {
        let text = "r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +0\n";
        let (name, wire) = super::plan_ident(text).unwrap();
        // C-вектор: FNV-1a(text) & 0xffffffff = 0x6dcd9d91.
        assert_eq!(name, "plan-6dcd9d91");
        assert_eq!(
            wire,
            [
                0x70, 0x6c, 0x61, 0x6e, 0x2d, 0x36, 0x64, 0x63, 0x64, 0x39, 0x64, 0x39, 0x31, 0, 0,
                0
            ]
        );
        let stamped = super::plan_text_for_trial(text, wire).unwrap();
        assert!(stamped.contains("id 706c616e2d3664636439643931000000"));
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
    fn сохраняет_quic_именную_привязку_с_путём_проверки() {
        let mut catalog = crate::catalog::Catalog::default();
        let plan_id = super::add_confirmed_quic_name_binding(
            &mut catalog,
            "media.example.net",
            4,
            "/static/app.css",
            "r2o-plan 1 10\nid 00000000000000000000000000000000\nproto udp quic\nquicsplit 1\n",
            125,
        )
        .unwrap();

        let binding = &catalog.boxes[0].bindings[0];
        assert_eq!(binding.kind, "name");
        assert_eq!(binding.target, "media.example.net");
        assert_eq!(binding.transport, 17);
        assert_eq!(binding.shape, r2k_core::control::SHAPE_QUIC);
        assert_eq!(binding.probe_path, "/static/app.css");
        assert_eq!(binding.plan_id, plan_id);
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
    fn live_http_diagnostic_requires_a_confirmed_catalog_owner() {
        use super::matches_confirmed_http_catalog_owner;
        use crate::catalog::{Binding, BoxRecord, Catalog, Plan};
        use r2k_core::control::BindingContext;

        let mut event = response();
        event.code = 1;
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
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                plans: vec![Plan {
                    id: "11".repeat(16),
                    proto: "http".into(),
                    enabled: true,
                    ..Plan::default()
                }],
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: "example.com".into(),
                    plan_id: "11".repeat(16),
                    level: 3,
                    enabled: true,
                    transport: 6,
                    family: 4,
                    shape: SHAPE_HTTP,
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };

        let acknowledged_binding = event.binding;
        assert!(matches_confirmed_http_catalog_owner(
            &catalog,
            &event,
            acknowledged_binding
        ));

        event.code = 2;
        assert!(matches_confirmed_http_catalog_owner(
            &catalog,
            &event,
            acknowledged_binding
        ));

        let mut stale_generation = event.clone();
        stale_generation.binding.generation += 1;
        assert!(!matches_confirmed_http_catalog_owner(
            &catalog,
            &stale_generation,
            acknowledged_binding
        ));

        let mut foreign_plan = event.clone();
        foreign_plan.plan_id = [0x22; 16];
        assert!(!matches_confirmed_http_catalog_owner(
            &catalog,
            &foreign_plan,
            acknowledged_binding
        ));

        let mut probe = event.clone();
        probe.trial_id = [1; 16];
        assert!(!matches_confirmed_http_catalog_owner(
            &catalog,
            &probe,
            acknowledged_binding
        ));

        let mut temporary = event.clone();
        temporary.binding.temporary = true;
        assert!(!matches_confirmed_http_catalog_owner(
            &catalog,
            &temporary,
            acknowledged_binding
        ));

        catalog.boxes[0].bindings[0].recheck_since = Some(100);
        assert!(!matches_confirmed_http_catalog_owner(
            &catalog,
            &event,
            acknowledged_binding
        ));
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

    #[test]
    fn direct_clear_requires_the_target_tcp_profile() {
        use crate::catalog::{Binding, BoxRecord, Catalog};

        let target = DiscoveryTarget {
            host: "profile.example".into(),
            endpoint: String::new(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: target.host.clone(),
                    level: 3,
                    enabled: true,
                    transport: 6,
                    family: 4,
                    shape: SHAPE_MODERN,
                    tcp_profile: 1,
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        let update =
            update_direct_clear_bindings(&mut catalog, &target, 100, std::time::Instant::now());
        assert_eq!(update.marked, 0, "измеренный профиль не совпадает с base=0");
        catalog.boxes[0].bindings[0].tcp_profile = 0;
        let update =
            update_direct_clear_bindings(&mut catalog, &target, 100, std::time::Instant::now());
        assert_eq!(update.marked, 1);
    }

    #[test]
    fn exact_key_and_covering_binding_respect_tcp_profile() {
        use crate::catalog::{Binding, BoxRecord, Catalog};

        let target = DiscoveryTarget {
            host: "profile.example".into(),
            endpoint: String::new(),
            family: 4,
            shape: 8,
        };
        let binding = Binding {
            kind: "name".into(),
            target: target.host.clone(),
            family: 4,
            transport: 6,
            shape: 8,
            tcp_profile: 1,
            ..Binding::default()
        };
        assert_eq!(target.tcp_profile(), 1);
        assert!(exact_key(&binding, &target));
        let mut mismatched = binding.clone();
        mismatched.tcp_profile = 2;
        assert!(!exact_key(&mismatched, &target));

        let catalog = Catalog {
            boxes: vec![BoxRecord {
                id: "box".into(),
                bindings: vec![Binding {
                    enabled: true,
                    level: 3,
                    ..binding
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        assert!(has_covering_binding(&catalog, &target));
        let mut mismatched_catalog = catalog.clone();
        mismatched_catalog.boxes[0].bindings[0].tcp_profile = 2;
        assert!(!has_covering_binding(&mismatched_catalog, &target));
    }

    #[test]
    fn newer_name_binding_requires_the_same_tcp_profile() {
        use crate::catalog::{Binding, BoxRecord, Catalog, Plan};

        let binding = Binding {
            kind: "name".into(),
            target: "profile.example".into(),
            plan_id: "old".into(),
            level: 3,
            enabled: true,
            transport: 6,
            family: 4,
            shape: 8,
            tcp_profile: 1,
            confirmed: 10,
            ..Binding::default()
        };
        let newer = Binding {
            plan_id: "new".into(),
            tcp_profile: 2,
            confirmed: 20,
            ..binding.clone()
        };
        let catalog = Catalog {
            boxes: vec![BoxRecord {
                id: "box".into(),
                plans: vec![Plan {
                    id: "new".into(),
                    proto: "tls".into(),
                    text: "plan".into(),
                    enabled: true,
                    ..Plan::default()
                }],
                bindings: vec![binding.clone(), newer],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        assert!(!newer_name_binding(&catalog, &catalog.boxes[0].bindings[0]));
        let mut same_profile = catalog.clone();
        same_profile.boxes[0].bindings[1].tcp_profile = 1;
        assert!(newer_name_binding(
            &same_profile,
            &same_profile.boxes[0].bindings[0]
        ));
    }

    #[test]
    fn own_first_binding_and_plans_require_the_target_tcp_profile() {
        use crate::catalog::{Binding, BoxRecord, Catalog, Plan};

        let target = DiscoveryTarget {
            host: "profile.example".into(),
            endpoint: String::new(),
            family: 4,
            shape: 8,
        };
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                id: "box".into(),
                plans: vec![Plan {
                    id: "plan".into(),
                    proto: "tls".into(),
                    text: "r2o-plan 1 1".into(),
                    enabled: true,
                    ..Plan::default()
                }],
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: target.host.clone(),
                    plan_id: "plan".into(),
                    level: 3,
                    enabled: true,
                    transport: 6,
                    family: 4,
                    shape: 8,
                    tcp_profile: 1,
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        assert_eq!(
            own_first_bound_plan_id(&catalog, &target, 8).as_deref(),
            Some("plan")
        );
        catalog.boxes[0].bindings[0].tcp_profile = 2;
        assert!(own_first_bound_plan_id(&catalog, &target, 8).is_none());

        // Базовой форме 1 соответствует «профиль не измерен» (0).
        let base_target = DiscoveryTarget {
            shape: SHAPE_MODERN,
            ..target
        };
        catalog.boxes[0].bindings[0].shape = SHAPE_MODERN;
        catalog.boxes[0].bindings[0].tcp_profile = 1;
        assert!(own_first_plans(&catalog, &base_target, false, None, &[], &[]).is_empty());
        catalog.boxes[0].bindings[0].tcp_profile = 0;
        assert_eq!(
            own_first_plans(&catalog, &base_target, false, None, &[], &[]).len(),
            1
        );
    }
}
