use crate::catalog::{CatalogError, DomainGroup, DomainObservation, DomainState, GroupKey};
use crate::domain::{normalize, registrable_domain};

const BLOCKED: u8 = 1;
const DIRECT_CLEAR: u8 = 2;
const PLAN_FAILED: u8 = 4;
const INCONCLUSIVE: u8 = 8;
const ADMITTED_EXCEPTION: u8 = 16;
/// Операторский запрет плана для имени. В отличие от обычного PLAN_FAILED,
/// последующее успешное подтверждение плана не снимает его.
const OPERATOR_REJECT: u8 = 32;
const MAX_GROUPS: usize = 64;
const MAX_OBSERVATIONS: usize = 256;

pub(crate) fn restore(state: &mut DomainState) -> Result<(), CatalogError> {
    if state.observations.len() > MAX_OBSERVATIONS {
        return Err(CatalogError::new("too many domain observations"));
    }
    if state.disabled_at.is_some_and(|at| at < 0) {
        return Err(CatalogError::new(
            "domain groups disabled_at must be nonnegative",
        ));
    }

    for index in 0..state.observations.len() {
        let (prior_observations, current_and_future) = state.observations.split_at_mut(index);
        let observation = &mut current_and_future[0];
        let name = normalize(&observation.name)
            .map_err(|_| CatalogError::new("invalid domain observation name"))?;
        if registrable_domain(&name).is_none() {
            return Err(CatalogError::new(
                "domain observation has no known registrable domain",
            ));
        }
        if observation.at < 0 {
            return Err(CatalogError::new(
                "domain observation timestamp must be nonnegative",
            ));
        }
        validate_key(&observation.key)?;

        let canonical = canonical_evidence(observation.evidence)?;
        if canonical & (BLOCKED | PLAN_FAILED) != 0 && observation.plan_id.is_empty() {
            return Err(CatalogError::new(
                "blocked and failed observations require a plan id",
            ));
        }
        observation.name = name;

        for prior in prior_observations {
            if prior.name == observation.name
                && prior.key == observation.key
                && (prior.plan_id == observation.plan_id
                    || ((prior.evidence | observation.evidence) & PLAN_FAILED == 0))
            {
                return Err(CatalogError::new("duplicate domain observation"));
            }
        }
    }

    rebuild(state);
    Ok(())
}

pub(crate) fn learn(
    state: &mut DomainState,
    mut observation: DomainObservation,
) -> Result<bool, CatalogError> {
    let base_evidence = observation.evidence & !OPERATOR_REJECT;
    let valid_base = base_evidence == BLOCKED
        || base_evidence == PLAN_FAILED
        || base_evidence == (BLOCKED | PLAN_FAILED)
        || base_evidence == DIRECT_CLEAR
        || base_evidence == INCONCLUSIVE;
    if !valid_base
        || observation.evidence & OPERATOR_REJECT != 0
            && !(base_evidence == BLOCKED
                || base_evidence == PLAN_FAILED
                || base_evidence == (BLOCKED | PLAN_FAILED))
    {
        return Err(CatalogError::new("invalid domain observation evidence"));
    }
    if base_evidence & (BLOCKED | PLAN_FAILED) != 0 && observation.plan_id.is_empty() {
        return Err(CatalogError::new(
            "blocked and failed observations require a plan id",
        ));
    }
    validate_key(&observation.key)?;
    if observation.name.len() > 255
        || observation.plan_id.len() > 39
        || observation.name.as_bytes().contains(&0)
        || observation.plan_id.as_bytes().contains(&0)
    {
        return Err(CatalogError::new("invalid domain observation strings"));
    }
    if observation.at < 0 {
        return Err(CatalogError::new(
            "domain observation timestamp must be nonnegative",
        ));
    }
    if state.groups.len() > MAX_GROUPS || state.observations.len() > MAX_OBSERVATIONS {
        return Err(CatalogError::new(
            "domain state exceeds its bounded capacity",
        ));
    }
    let name = normalize(&observation.name)
        .map_err(|_| CatalogError::new("invalid domain observation name"))?;
    if registrable_domain(&name).is_none() {
        return Err(CatalogError::new(
            "domain observation has no known registrable domain",
        ));
    }
    observation.name = name;
    if state.observations.iter().any(|old| {
        old.name == observation.name
            && old.key == observation.key
            && old.evidence & OPERATOR_REJECT != 0
    }) {
        // Операторский запрет снимается только правкой каталога, а не
        // последующим автоматическим замером.
        return Ok(false);
    }

    let mut admitted_clear = observation.evidence == DIRECT_CLEAR
        && covering_group(state, &observation.name, &observation.key).is_some();
    let mut slot = None;
    let mut any = None;
    let mut replace = None;
    for (index, old) in state.observations.iter().enumerate() {
        if old.name != observation.name || old.key != observation.key {
            continue;
        }
        if old.plan_id == observation.plan_id {
            slot = Some(index);
            break;
        }
        if matches!(observation.evidence, DIRECT_CLEAR | INCONCLUSIVE) && any.is_none() {
            any = Some(index);
        }
        if observation.evidence == BLOCKED && old.evidence & PLAN_FAILED == 0 && replace.is_none() {
            replace = Some(index);
        }
    }
    if slot.is_none() {
        slot = any.or(replace);
    }
    // C применяет проверки `at<old->at`/INCONCLUSIVE только к найденному
    // существующему слоту, но не к новой вставке/реклайму.
    let replacing_existing = slot.is_some();

    if slot.is_none() {
        if state.frozen || state.observations.len() == MAX_OBSERVATIONS {
            let mut changed = !state.frozen;
            state.frozen = true;
            if !matches!(observation.evidence, DIRECT_CLEAR | PLAN_FAILED) {
                return Ok(changed);
            }

            if state.disabled {
                let disabled_at = state.disabled_at.unwrap_or_default();
                let mut index = 0;
                while index < state.observations.len() {
                    let old = &state.observations[index];
                    // C `d2k_group_learn`: при disabled удаляются только
                    // точные BLOCKED (не маски с DIRECT_CLEAR/PLAN_FAILED).
                    if old.evidence == BLOCKED && old.at <= disabled_at {
                        state.observations.swap_remove(index);
                    } else {
                        index += 1;
                    }
                }
            }

            let mut reclaim =
                (state.observations.len() < MAX_OBSERVATIONS).then_some(state.observations.len());
            if reclaim.is_none() {
                reclaim = oldest_expired(state, &observation, INCONCLUSIVE);
            }
            if reclaim.is_none() {
                reclaim = oldest_expired(state, &observation, BLOCKED);
            }
            if reclaim.is_none() {
                reclaim = state
                    .observations
                    .iter()
                    .position(|old| old.evidence == INCONCLUSIVE);
            }
            if reclaim.is_none() {
                reclaim = state
                    .observations
                    .iter()
                    .position(|old| old.evidence == BLOCKED);
            }
            let Some(reclaim) = reclaim else {
                changed |= !state.disabled;
                state.disabled = true;
                state.groups.clear();
                let latest = state
                    .observations
                    .iter()
                    .map(|old| old.at)
                    .chain([observation.at])
                    .max()
                    .unwrap_or_default();
                let disabled_at = state.disabled_at.unwrap_or_default();
                changed |= latest > disabled_at;
                state.disabled_at = Some(disabled_at.max(latest));
                return Ok(changed);
            };

            slot = Some(reclaim);
            if reclaim == state.observations.len() {
                state.observations.push(observation.clone());
            } else {
                state.observations[reclaim] = observation.clone();
            }
            state.disabled = false;
            state.disabled_at = None;
            if state.observations.len() < MAX_OBSERVATIONS {
                state.frozen = false;
            }
        } else {
            slot = Some(state.observations.len());
            state.observations.push(observation.clone());
        }
    }
    if let Some(index) = slot {
        let old = &mut state.observations[index];
        if replacing_existing && (observation.at < old.at || observation.evidence == INCONCLUSIVE) {
            return Ok(false);
        }
        if observation.evidence == DIRECT_CLEAR && old.evidence & ADMITTED_EXCEPTION != 0 {
            admitted_clear = true;
        }
        if observation.evidence == PLAN_FAILED {
            if observation.plan_id != old.plan_id {
                return Ok(false);
            }
            old.evidence |= PLAN_FAILED;
            old.at = observation.at;
        } else if admitted_clear && old.evidence & BLOCKED != 0 {
            old.evidence = BLOCKED | DIRECT_CLEAR | ADMITTED_EXCEPTION;
            old.at = observation.at;
        } else {
            *old = observation.clone();
        }
    }

    let mut slot = slot.expect("observation inserted or replaced");
    if admitted_clear {
        state.observations[slot].evidence |= ADMITTED_EXCEPTION;
    }
    if matches!(observation.evidence, BLOCKED | DIRECT_CLEAR) {
        let mut index = 0;
        while index < state.observations.len() {
            let other = &state.observations[index];
            if index != slot
                && other.name == observation.name
                && other.key == observation.key
                && other.evidence & PLAN_FAILED == 0
            {
                let last = state.observations.len() - 1;
                state.observations.swap_remove(index);
                if slot == last {
                    slot = index;
                }
            } else {
                index += 1;
            }
        }
    }
    if observation.evidence != INCONCLUSIVE {
        rebuild(state);
    }
    Ok(true)
}

pub(crate) fn forget_failures(
    state: &mut DomainState,
    name: &str,
    transport: u8,
    family: u8,
) -> usize {
    if state.observations.len() > MAX_OBSERVATIONS {
        return 0;
    }
    let Ok(name) = normalize(name) else {
        return 0;
    };
    let mut dropped = 0;
    let mut index = 0;
    while index < state.observations.len() {
        let observation = &state.observations[index];
        if observation.name == name
            && observation.key.transport == transport
            && observation.key.family == family
            && observation.evidence & PLAN_FAILED != 0
        {
            state.observations.swap_remove(index);
            dropped += 1;
        } else {
            index += 1;
        }
    }
    if dropped != 0 {
        rebuild(state);
    }
    dropped
}

pub(crate) fn expire_failures(state: &mut DomainState, now: i64, max_age: i64) -> usize {
    if max_age <= 0 || now < max_age || state.observations.len() > MAX_OBSERVATIONS {
        return 0;
    }
    let cutoff = now - max_age;
    let mut dropped = 0;
    let mut index = 0;
    while index < state.observations.len() {
        let observation = &state.observations[index];
        if observation.evidence & PLAN_FAILED != 0 && observation.at < cutoff {
            state.observations.swap_remove(index);
            dropped += 1;
        } else {
            index += 1;
        }
    }
    if dropped != 0 {
        rebuild(state);
    }
    dropped
}

fn rebuild(state: &mut DomainState) {
    state.groups.clear();
    if state.disabled {
        return;
    }
    let observations = state.observations.clone();
    for observation in &observations {
        if observation.evidence & BLOCKED == 0 {
            continue;
        }
        let Some(base) = registrable_domain(&observation.name) else {
            continue;
        };
        let mut best: Option<(String, u32, i64)> = None;
        let labels: Vec<_> = observation.name.split('.').collect();
        for start in 1..labels.len() {
            let suffix = labels[start..].join(".");
            if suffix.len() < base.len() {
                continue;
            }
            let count = votes(state, &suffix, observation);
            if count != 0 {
                let latest = latest_vote(state, &suffix, observation);
                best = Some((suffix, count, latest));
            }
        }
        if let Some((suffix, count, at)) = best {
            add_group(state, &suffix, observation, count, at);
        }
    }
}

pub(crate) fn match_domain<'a>(
    state: &'a DomainState,
    name: &str,
    key: &GroupKey,
) -> Option<&'a DomainGroup> {
    if state.disabled
        || state.groups.len() > MAX_GROUPS
        || state.observations.len() > MAX_OBSERVATIONS
    {
        return None;
    }
    let name = normalize(name).ok()?;
    let mut best: Option<&DomainGroup> = None;
    for group in &state.groups {
        if group.key != *key || !member(&name, &group.suffix) {
            continue;
        }
        let excluded = state.observations.iter().any(|observation| {
            observation.name == name
                && observation.key == *key
                && (observation.evidence & (DIRECT_CLEAR | OPERATOR_REJECT) != 0
                    || (observation.evidence & PLAN_FAILED != 0
                        && observation.plan_id == group.plan_id))
        });
        if !excluded && best.is_none_or(|previous| group.suffix.len() > previous.suffix.len()) {
            best = Some(group);
        }
    }
    best
}

fn canonical_evidence(evidence: u8) -> Result<u8, CatalogError> {
    let operator_reject = evidence & OPERATOR_REJECT != 0;
    if operator_reject {
        let base = evidence & !OPERATOR_REJECT;
        if !matches!(base, BLOCKED | PLAN_FAILED | 5) {
            return Err(CatalogError::new("invalid operator-reject evidence"));
        }
        return Ok(base | OPERATOR_REJECT);
    }
    let mut evidence = evidence;
    if evidence != INCONCLUSIVE {
        evidence &= !INCONCLUSIVE;
    }
    if evidence & ADMITTED_EXCEPTION != 0 {
        if evidence & DIRECT_CLEAR == 0 {
            return Err(CatalogError::new(
                "admitted exception requires direct-clear evidence",
            ));
        }
        evidence &= !ADMITTED_EXCEPTION;
    }
    if evidence & BLOCKED != 0 {
        evidence &= !(DIRECT_CLEAR | PLAN_FAILED);
    } else if evidence & DIRECT_CLEAR != 0 && evidence & PLAN_FAILED != 0 {
        evidence = PLAN_FAILED;
    }
    if !matches!(
        evidence,
        BLOCKED | DIRECT_CLEAR | PLAN_FAILED | INCONCLUSIVE
    ) {
        return Err(CatalogError::new("invalid domain observation evidence"));
    }
    Ok(evidence)
}

fn validate_key(key: &GroupKey) -> Result<(), CatalogError> {
    let valid = (key.transport == 6
        && (matches!(key.shape, 1 | 2 | 6) || r2k_core::control::is_tcp_context_shape(key.shape)))
        || (key.transport == 17 && key.shape == 3);
    if !matches!(key.family, 4 | 6) || !valid {
        return Err(CatalogError::new(
            "invalid domain observation transport, family, or shape",
        ));
    }
    if key.probe_path.len() > 255
        || key.ech_origin.len() > 255
        || key.probe_path.as_bytes().contains(&0)
        || key.ech_origin.as_bytes().contains(&0)
    {
        return Err(CatalogError::new("invalid domain observation key strings"));
    }
    Ok(())
}

fn member(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn covering_group<'a>(
    state: &'a DomainState,
    name: &str,
    key: &GroupKey,
) -> Option<&'a DomainGroup> {
    if state.disabled || state.groups.len() > MAX_GROUPS {
        return None;
    }
    state
        .groups
        .iter()
        .filter(|group| group.key == *key && member(name, &group.suffix))
        .max_by_key(|group| group.suffix.len())
}

fn oldest_expired(
    state: &DomainState,
    observation: &DomainObservation,
    evidence: u8,
) -> Option<usize> {
    let mut oldest = None;
    for (index, candidate) in state.observations.iter().enumerate() {
        if candidate.evidence != evidence
            || observation.at.saturating_sub(candidate.at) <= 30 * 86_400
        {
            continue;
        }
        if oldest.is_none_or(|previous: usize| candidate.at < state.observations[previous].at) {
            oldest = Some(index);
        }
    }
    oldest
}

fn votes(state: &DomainState, suffix: &str, seed: &DomainObservation) -> u32 {
    let mut live = 0_u32;
    let mut stale = 0_u32;
    for observation in &state.observations {
        if observation.key != seed.key || !member(&observation.name, suffix) {
            continue;
        }
        if observation.evidence & DIRECT_CLEAR != 0
            && observation.evidence & ADMITTED_EXCEPTION == 0
        {
            return 0;
        }
        if observation.evidence & BLOCKED != 0
            && observation.name != suffix
            && observation.plan_id == seed.plan_id
        {
            if observation.evidence & (PLAN_FAILED | DIRECT_CLEAR) != 0 {
                stale += 1;
            } else {
                live += 1;
            }
        }
    }
    if live >= 2 && live > stale && live + stale >= 3 {
        live
    } else {
        0
    }
}

fn latest_vote(state: &DomainState, suffix: &str, seed: &DomainObservation) -> i64 {
    state
        .observations
        .iter()
        .filter(|observation| {
            observation.key == seed.key
                && observation.plan_id == seed.plan_id
                && observation.evidence & BLOCKED != 0
                && observation.evidence & (PLAN_FAILED | DIRECT_CLEAR) == 0
                && observation.name != suffix
                && member(&observation.name, suffix)
        })
        .map(|observation| observation.at)
        .max()
        .unwrap_or(0)
}

fn failures(state: &DomainState, suffix: &str, key: &GroupKey, plan_id: &str) -> usize {
    state
        .observations
        .iter()
        .filter(|observation| {
            observation.evidence & PLAN_FAILED != 0
                && observation.key == *key
                && observation.plan_id == plan_id
                && member(&observation.name, suffix)
        })
        .count()
}

fn add_group(
    state: &mut DomainState,
    suffix: &str,
    seed: &DomainObservation,
    evidence_count: u32,
    at: i64,
) {
    if let Some(index) = state
        .groups
        .iter()
        .position(|group| group.key == seed.key && group.suffix == suffix)
    {
        let existing = &state.groups[index];
        let candidate_failures = failures(state, suffix, &seed.key, &seed.plan_id);
        let elected_failures = failures(state, suffix, &existing.key, &existing.plan_id);
        let better = candidate_failures < elected_failures
            || (candidate_failures == elected_failures
                && (evidence_count > existing.evidence_count
                    || (evidence_count == existing.evidence_count
                        && (at > existing.at
                            || (at == existing.at && seed.plan_id < existing.plan_id)))));
        if better {
            let existing = &mut state.groups[index];
            existing.plan_id.clone_from(&seed.plan_id);
            existing.evidence_count = evidence_count;
            existing.at = at;
            existing.at = at;
        }
        return;
    }

    if state.groups.iter().any(|group| {
        group.key == seed.key && group.plan_id == seed.plan_id && member(suffix, &group.suffix)
    }) {
        return;
    }
    state.groups.retain(|group| {
        !(group.key == seed.key && group.plan_id == seed.plan_id && member(&group.suffix, suffix))
    });
    if state.groups.len() == MAX_GROUPS {
        state.frozen = true;
        return;
    }
    state.groups.push(DomainGroup {
        suffix: suffix.to_owned(),
        plan_id: seed.plan_id.clone(),
        key: seed.key.clone(),
        evidence_count,
        at,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(shape: u8) -> GroupKey {
        GroupKey {
            transport: 6,
            family: 4,
            shape,
            probe_path: String::new(),
            ech_origin: String::new(),
        }
    }

    fn observation(
        name: &str,
        plan: &str,
        evidence: u8,
        at: i64,
        key: &GroupKey,
    ) -> DomainObservation {
        DomainObservation {
            name: name.into(),
            plan_id: plan.into(),
            key: key.clone(),
            evidence,
            at,
        }
    }

    fn state(observations: Vec<DomainObservation>) -> DomainState {
        DomainState {
            observations,
            ..DomainState::default()
        }
    }

    fn trace_key() -> GroupKey {
        GroupKey {
            transport: 6,
            family: 4,
            shape: 1,
            probe_path: String::new(),
            ech_origin: String::new(),
        }
    }

    fn trace_obs(name: &str, plan: &str, evidence: u8, at: i64) -> DomainObservation {
        DomainObservation {
            name: name.into(),
            plan_id: plan.into(),
            key: trace_key(),
            evidence,
            at,
        }
    }

    fn trace_state(tag: &str, rc: i32, state: &DomainState) -> String {
        let mut out = format!(
            "scenario {tag} rc={rc} n_obs={} n_groups={} frozen={} disabled={} disabled_at={}\n",
            state.observations.len(),
            state.groups.len(),
            u8::from(state.frozen),
            u8::from(state.disabled),
            state.disabled_at.unwrap_or_default()
        );
        for (index, observation) in state.observations.iter().enumerate() {
            out.push_str(&format!(
                "obs {index} name={} plan={} t={} f={} s={} path={} origin={} ev={} at={}\n",
                observation.name,
                observation.plan_id,
                observation.key.transport,
                observation.key.family,
                observation.key.shape,
                observation.key.probe_path,
                observation.key.ech_origin,
                observation.evidence,
                observation.at
            ));
        }
        for (index, group) in state.groups.iter().enumerate() {
            out.push_str(&format!(
                "group {index} suffix={} plan={} t={} f={} s={} path={} origin={} count={} at={}\n",
                group.suffix,
                group.plan_id,
                group.key.transport,
                group.key.family,
                group.key.shape,
                group.key.probe_path,
                group.key.ech_origin,
                group.evidence_count,
                group.at
            ));
        }
        out
    }

    fn trace_learn(state: &mut DomainState, observation: DomainObservation) -> i32 {
        match learn(state, observation) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    }

    /// C/Rust differential-трасса `d2k_group_learn`/`d2k_group_restore`.
    /// Скрипт `scripts/test-groups-differential.sh` сравнивает файл с C-оракулом.
    #[test]
    fn groups_learn_restore_trace_matches_c() {
        let mut out = String::new();

        // A: общие ветви learn (evidence 1/2/4/8, без расширений R2O).
        let mut state = DomainState::default();
        out.push_str(&trace_state("A0", 0, &state));
        let steps: [(&str, &str, &str, u8, i64); 14] = [
            ("A1", "a.example.org", "p1", BLOCKED, 10),
            ("A2", "b.example.org", "p1", BLOCKED, 20),
            ("A3", "c.example.org", "p1", BLOCKED, 30),
            ("A4", "c.example.org", "p1", BLOCKED, 25),
            ("A5", "c.example.org", "p1", BLOCKED, 40),
            ("A6", "d.example.org", "p2", BLOCKED, 50),
            ("A7", "b.example.org", "p1", PLAN_FAILED, 60),
            ("A8", "e.example.org", "p1", BLOCKED, 70),
            ("A9", "f.example.org", "p1", BLOCKED, 80),
            ("A10", "c.example.org", "p1", DIRECT_CLEAR, 90),
            ("A11", "e.example.org", "p1", DIRECT_CLEAR, 100),
            ("A12", "f.example.org", "p1", INCONCLUSIVE, 110),
            ("A13", "g.example.org", "p1", INCONCLUSIVE, 120),
            ("A14", "g.example.org", "p1", INCONCLUSIVE, 130),
        ];
        for (tag, name, plan, evidence, at) in steps {
            let rc = trace_learn(&mut state, trace_obs(name, plan, evidence, at));
            out.push_str(&trace_state(tag, rc, &state));
        }
        let mut invalid = trace_obs("h.example.org", "p1", BLOCKED, 140);
        invalid.key.family = 5;
        let rc = trace_learn(&mut state, invalid);
        out.push_str(&trace_state("A15", rc, &state));
        let rc = trace_learn(
            &mut state,
            trace_obs("d.example.org", "p3", DIRECT_CLEAR, 150),
        );
        out.push_str(&trace_state("A16", rc, &state));

        // B: предел наблюдений и frozen.
        let mut state = DomainState::default();
        out.push_str(&trace_state("B0", 0, &state));
        for index in 0..MAX_OBSERVATIONS {
            let name = format!("h{index}.example.org");
            if trace_learn(
                &mut state,
                trace_obs(&name, "p1", BLOCKED, 1000 + index as i64),
            ) != 1
            {
                out.push_str(&format!("B-fill-fail {index}\n"));
                break;
            }
        }
        out.push_str(&trace_state("B1", 0, &state));
        let rc = trace_learn(
            &mut state,
            trace_obs("overflow.example.org", "p1", BLOCKED, 2000),
        );
        out.push_str(&trace_state("B2", rc, &state));
        let rc = trace_learn(
            &mut state,
            trace_obs("overflow2.example.org", "p1", BLOCKED, 2001),
        );
        out.push_str(&trace_state("B3", rc, &state));

        // C: предел групп (64) включает frozen.
        let mut state = DomainState::default();
        for domain in 0..MAX_GROUPS {
            for member in 0..3 {
                let name = format!("m{member}.example{domain}.org");
                let _ = trace_learn(
                    &mut state,
                    trace_obs(&name, "p1", BLOCKED, 1000 + domain as i64 * 10 + member),
                );
            }
        }
        out.push_str(&trace_state("C1", 0, &state));
        let rc = trace_learn(
            &mut state,
            trace_obs("m0.example64.org", "p1", BLOCKED, 2000),
        );
        out.push_str(&trace_state("C2", rc, &state));
        let rc = trace_learn(
            &mut state,
            trace_obs("m1.example64.org", "p1", BLOCKED, 2001),
        );
        out.push_str(&trace_state("C3", rc, &state));

        // D: disabled + frozen, повторное включение после удаления BLOCKED.
        let mut state = DomainState::default();
        for index in 0..MAX_OBSERVATIONS - 1 {
            state.observations.push(trace_obs(
                &format!("b{index}.example.org"),
                "p1",
                BLOCKED,
                10,
            ));
        }
        state
            .observations
            .push(trace_obs("p.example.org", "p1", PLAN_FAILED, 20));
        state.frozen = true;
        state.disabled = true;
        state.disabled_at = Some(20);
        out.push_str(&trace_state("D0", 0, &state));
        let rc = trace_learn(
            &mut state,
            trace_obs("q.example.org", "p1", PLAN_FAILED, 30),
        );
        out.push_str(&trace_state("D1", rc, &state));

        // E: restore и его отказы.
        let mut state = DomainState::default();
        for observation in [
            trace_obs("a.example.org", "p1", INCONCLUSIVE | PLAN_FAILED, 10),
            trace_obs("b.example.org", "p1", BLOCKED | PLAN_FAILED, 20),
            trace_obs("c.example.org", "p1", BLOCKED | DIRECT_CLEAR, 30),
            trace_obs("d.example.org", "p1", DIRECT_CLEAR | PLAN_FAILED, 40),
            trace_obs("e.example.org", "p1", BLOCKED, 50),
            trace_obs("f.example.org", "p1", DIRECT_CLEAR, 60),
            trace_obs("g.example.org", "p1", INCONCLUSIVE, 70),
        ] {
            state.observations.push(observation);
        }
        let rc = i32::from(restore(&mut state).is_err()).wrapping_neg();
        out.push_str(&trace_state("E1", rc, &state));

        let mut state = DomainState::default();
        state
            .observations
            .push(trace_obs("a.example.org", "p1", ADMITTED_EXCEPTION, 10));
        let rc = i32::from(restore(&mut state).is_err()).wrapping_neg();
        out.push_str(&trace_state("E2", rc, &state));

        let mut state = DomainState::default();
        state
            .observations
            .push(trace_obs("a.example.org", "p1", BLOCKED, 10));
        state
            .observations
            .push(trace_obs("a.example.org", "p1", DIRECT_CLEAR, 20));
        let rc = i32::from(restore(&mut state).is_err()).wrapping_neg();
        out.push_str(&trace_state("E3", rc, &state));

        let mut state = DomainState::default();
        state
            .observations
            .push(trace_obs("a.example.org", "p1", BLOCKED, 10));
        state.disabled_at = Some(-1);
        let rc = i32::from(restore(&mut state).is_err()).wrapping_neg();
        out.push_str(&trace_state("E4", rc, &state));

        let mut state = DomainState::default();
        state
            .observations
            .push(trace_obs("a.example.org", "p1", BLOCKED, -1));
        let rc = i32::from(restore(&mut state).is_err()).wrapping_neg();
        out.push_str(&trace_state("E5", rc, &state));

        let mut state = DomainState::default();
        state
            .observations
            .push(trace_obs("a.example.not-a-real-tld", "p1", BLOCKED, 10));
        let rc = i32::from(restore(&mut state).is_err()).wrapping_neg();
        out.push_str(&trace_state("E6", rc, &state));

        if let Ok(path) = std::env::var("R2O_GROUPS_DIFF_OUTPUT") {
            std::fs::write(path, &out).unwrap();
        }
        assert!(
            out.contains("scenario A3 rc=1 n_obs=3 n_groups=1"),
            "A3: {out}"
        );
        assert!(out.contains("scenario E2 rc=-1"), "E2: {out}");
        assert_eq!(state.observations.len(), 1);
    }

    #[test]
    fn group_key_and_evidence_validation_match_c() {
        let mut k = key(1);
        assert!(validate_key(&k).is_ok());

        k.probe_path = "a".repeat(255);
        assert!(validate_key(&k).is_ok());
        k.probe_path = "a".repeat(256);
        assert!(validate_key(&k).is_err());
        k.probe_path.clear();

        k.ech_origin = "a".repeat(256);
        assert!(validate_key(&k).is_err());
        k.ech_origin.clear();

        k.probe_path = "a\0b".into();
        assert!(validate_key(&k).is_err());
        k.probe_path.clear();
        k.family = 5;
        assert!(validate_key(&k).is_err());
        k.family = 4;
        k.transport = 17;
        k.shape = 3;
        assert!(validate_key(&k).is_ok());
        k.shape = 1;
        assert!(validate_key(&k).is_err());
        k.transport = 6;
        k.shape = 1;
        assert!(validate_key(&k).is_ok());
        k.shape = 99;
        assert!(validate_key(&k).is_err());
        k.shape = 1;
        k.transport = 7;
        assert!(validate_key(&k).is_err());

        // C `valid`: после канонизации допустимы ровно 1/2/4/8.
        assert_eq!(canonical_evidence(BLOCKED).unwrap(), BLOCKED);
        assert_eq!(canonical_evidence(INCONCLUSIVE).unwrap(), INCONCLUSIVE);
        assert_eq!(canonical_evidence(INCONCLUSIVE | BLOCKED).unwrap(), BLOCKED);
        assert_eq!(canonical_evidence(BLOCKED | DIRECT_CLEAR).unwrap(), BLOCKED);
        assert_eq!(
            canonical_evidence(DIRECT_CLEAR | PLAN_FAILED).unwrap(),
            PLAN_FAILED
        );
        assert_eq!(
            canonical_evidence(DIRECT_CLEAR | ADMITTED_EXCEPTION).unwrap(),
            DIRECT_CLEAR
        );
        for invalid in [0, ADMITTED_EXCEPTION, INCONCLUSIVE | ADMITTED_EXCEPTION] {
            assert!(canonical_evidence(invalid).is_err(), "accepted {invalid}");
        }
        // R2O-расширение OPERATOR_REJECT (нет в C `valid`).
        assert_eq!(
            canonical_evidence(OPERATOR_REJECT | BLOCKED).unwrap(),
            OPERATOR_REJECT | BLOCKED
        );
        assert!(canonical_evidence(OPERATOR_REJECT).is_err());
    }

    #[test]
    fn votes_and_latest_vote_match_c_rule() {
        let k = key(1);
        let seed = observation("seed.example.org", "p1", BLOCKED, 10, &k);
        let live = state(vec![
            seed.clone(),
            observation("a.example.org", "p1", BLOCKED, 20, &k),
            observation("b.example.org", "p1", BLOCKED, 30, &k),
        ]);
        assert_eq!(votes(&live, "example.org", &seed), 3);
        assert_eq!(latest_vote(&live, "example.org", &seed), 30);

        // live=2, stale=2: live > stale ложно → 0.
        let stale_equal = state(vec![
            seed.clone(),
            observation("a.example.org", "p1", BLOCKED, 20, &k),
            observation("b.example.org", "p1", BLOCKED | PLAN_FAILED, 30, &k),
            observation("c.example.org", "p1", BLOCKED | DIRECT_CLEAR, 40, &k),
        ]);
        assert_eq!(votes(&stale_equal, "example.org", &seed), 0);

        // live=3, stale=1: live > stale и сумма ≥3 → 3; latest только live.
        let stale_one = state(vec![
            seed.clone(),
            observation("a.example.org", "p1", BLOCKED, 20, &k),
            observation("b.example.org", "p1", BLOCKED, 30, &k),
            observation("c.example.org", "p1", BLOCKED | PLAN_FAILED, 99, &k),
        ]);
        assert_eq!(votes(&stale_one, "example.org", &seed), 3);
        assert_eq!(latest_vote(&stale_one, "example.org", &seed), 30);

        // DIRECT_CLEAR без ADMITTED_EXCEPTION обрывает голосование.
        let mut clear = live.clone();
        clear
            .observations
            .push(observation("c.example.org", "p1", DIRECT_CLEAR, 40, &k));
        assert_eq!(votes(&clear, "example.org", &seed), 0);
        clear.observations.last_mut().unwrap().evidence = DIRECT_CLEAR | ADMITTED_EXCEPTION;
        assert_eq!(votes(&clear, "example.org", &seed), 3);
    }

    #[test]
    fn failures_are_scoped_by_plan_key_and_suffix_like_c() {
        let k = key(1);
        let s = state(vec![
            observation("a.example.org", "p1", PLAN_FAILED, 1, &k),
            observation("b.sub.example.org", "p1", PLAN_FAILED, 2, &k),
            observation("c.example.org", "p2", PLAN_FAILED, 3, &k),
            observation("d.example.org", "p1", BLOCKED, 4, &k),
        ]);
        assert_eq!(failures(&s, "example.org", &k, "p1"), 2);
        assert_eq!(failures(&s, "example.org", &k, "p2"), 1);
        assert_eq!(failures(&s, "sub.example.org", &k, "p1"), 1);
        assert_eq!(failures(&s, "example.org", &key(2), "p1"), 0);
    }

    #[test]
    fn covering_group_returns_longest_suffix_and_respects_disabled() {
        let k = key(1);
        let mut s = state(vec![]);
        for suffix in ["example.org", "sub.example.org"] {
            s.groups.push(DomainGroup {
                suffix: suffix.into(),
                plan_id: "p1".into(),
                key: k.clone(),
                evidence_count: 3,
                at: 1,
            });
        }
        assert_eq!(
            covering_group(&s, "a.sub.example.org", &k).map(|group| group.suffix.as_str()),
            Some("sub.example.org")
        );
        assert!(covering_group(&s, "a.other.org", &k).is_none());
        s.disabled = true;
        assert!(covering_group(&s, "a.sub.example.org", &k).is_none());
    }

    #[test]
    fn rebuild_chooses_last_nonzero_suffix_and_clears_when_disabled() {
        let k = key(1);
        let mut s = state(vec![
            observation("a.example.org", "p1", BLOCKED, 1, &k),
            observation("b.example.org", "p1", BLOCKED, 2, &k),
            observation("c.example.org", "p1", BLOCKED, 3, &k),
            observation("d.sub.example.org", "p1", BLOCKED, 4, &k),
            observation("e.sub.example.org", "p1", BLOCKED, 5, &k),
            observation("f.sub.example.org", "p1", BLOCKED, 6, &k),
        ]);
        rebuild(&mut s);
        assert_eq!(s.groups.len(), 1);
        assert_eq!(s.groups[0].suffix, "example.org");
        assert_eq!(s.groups[0].evidence_count, 6);

        s.disabled = true;
        rebuild(&mut s);
        assert!(s.groups.is_empty());
    }

    #[test]
    fn add_group_prefers_failures_count_at_plan_and_covers_narrow_groups() {
        let k = key(1);
        let mut s = state(vec![]);
        let p1 = observation("a.example.org", "p1", BLOCKED, 10, &k);
        add_group(&mut s, "sub.example.org", &p1, 2, 100);
        assert_eq!(s.groups.len(), 1);

        // Широкая группа того же плана удаляет покрытую узкую.
        add_group(&mut s, "example.org", &p1, 3, 200);
        assert_eq!(s.groups.len(), 1);
        assert_eq!(s.groups[0].suffix, "example.org");
        assert_eq!(s.groups[0].evidence_count, 3);

        // Узкая группа под широкой того же плана отвергается.
        add_group(&mut s, "sub.example.org", &p1, 4, 300);
        assert_eq!(s.groups.len(), 1);

        // Меньше PLAN_FAILED важнее count/at: p2 вытесняет p1.
        s.observations
            .push(observation("b.example.org", "p1", PLAN_FAILED, 5, &k));
        let p2 = observation("a.example.org", "p2", BLOCKED, 20, &k);
        add_group(&mut s, "example.org", &p2, 2, 400);
        assert_eq!(s.groups[0].plan_id, "p2");

        // Предел 64: новая группа не добавляется, state.frozen.
        let mut full = state(vec![]);
        for index in 0..MAX_GROUPS {
            full.groups.push(DomainGroup {
                suffix: format!("g{index}.example"),
                plan_id: "p1".into(),
                key: k.clone(),
                evidence_count: 1,
                at: 1,
            });
        }
        add_group(&mut full, "new.example", &p1, 1, 1);
        assert_eq!(full.groups.len(), MAX_GROUPS);
        assert!(full.frozen);
    }

    #[test]
    fn match_domain_applies_plan_exceptions_and_direct_clear_like_c() {
        let k = key(1);
        let mut s = state(vec![]);
        for (suffix, plan) in [("example.org", "p1"), ("sub.example.org", "p1")] {
            s.groups.push(DomainGroup {
                suffix: suffix.into(),
                plan_id: plan.into(),
                key: k.clone(),
                evidence_count: 3,
                at: 1,
            });
        }
        assert_eq!(
            match_domain(&s, "a.sub.example.org", &k).map(|group| group.suffix.as_str()),
            Some("sub.example.org")
        );

        // PLAN_FAILED p1 исключает только группы p1; p2 остаётся.
        s.groups.push(DomainGroup {
            suffix: "sub.example.org".into(),
            plan_id: "p2".into(),
            key: k.clone(),
            evidence_count: 3,
            at: 2,
        });
        s.observations
            .push(observation("a.sub.example.org", "p1", PLAN_FAILED, 1, &k));
        assert_eq!(
            match_domain(&s, "a.sub.example.org", &k).map(|group| group.plan_id.as_str()),
            Some("p2")
        );

        // DIRECT_CLEAR исключает все группы этого ключа.
        s.observations
            .push(observation("a.sub.example.org", "p2", DIRECT_CLEAR, 2, &k));
        assert!(match_domain(&s, "a.sub.example.org", &k).is_none());

        s.disabled = true;
        assert!(match_domain(&s, "a.sub.example.org", &k).is_none());
    }
}
