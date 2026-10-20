use crate::catalog::{CatalogError, DomainGroup, DomainObservation, DomainState, GroupKey};
use crate::domain::{normalize, registrable_domain};

const BLOCKED: u8 = 1;
const DIRECT_CLEAR: u8 = 2;
const PLAN_FAILED: u8 = 4;
const INCONCLUSIVE: u8 = 8;
const ADMITTED_EXCEPTION: u8 = 16;
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
    if !matches!(
        observation.evidence,
        BLOCKED | DIRECT_CLEAR | PLAN_FAILED | INCONCLUSIVE
    ) {
        return Err(CatalogError::new("invalid domain observation evidence"));
    }
    if matches!(observation.evidence, BLOCKED | PLAN_FAILED) && observation.plan_id.is_empty() {
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
                    if old.evidence & BLOCKED != 0 && old.at <= disabled_at {
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
        if observation.at < old.at || observation.evidence == INCONCLUSIVE {
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
    rebuild(state);
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
                && (observation.evidence & DIRECT_CLEAR != 0
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
    let valid = (key.transport == 6 && matches!(key.shape, 1 | 2 | 6))
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
