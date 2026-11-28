//! Bounded records of local verifier outcomes. These records only rank candidates.

use crate::catalog::{CatalogError, write_atomic};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CAPACITY: usize = 64;
const MAX_FILE_BYTES: u64 = 24 * 1024;
const MAX_AGE: u64 = 7 * 24 * 60 * 60;
const SAVE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProbeScope {
    pub path: [u8; 16],
    pub port: u16,
    pub family: u8,
    pub shape: u8,
    pub profile: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultKind {
    Application,
    Handshake,
    Rejected,
    Unknown,
    LocalError,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Diagnostics {
    pub application: u64,
    pub handshake: u64,
    pub rejected: u64,
    pub unknown: u64,
    pub local_error: u64,
    pub cancelled: u64,
    pub applied: u64,
    pub transport_established: u64,
    pub charged_probes: u64,
    pub unknown_path: u64,
    pub ranked_searches: u64,
    pub changed_first: u64,
    pub records: usize,
    pub evicted: u64,
    pub saves: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Entry {
    scope: ProbeScope,
    plan: u64,
    program: u64,
    successes: u16,
    success_at: u64,
    average_ms: u16,
    average_probes: u8,
    rejected_at: u64,
    rejected_target: u64,
}

impl Entry {
    fn recent(&self) -> u64 {
        self.success_at.max(self.rejected_at)
    }
}

#[derive(Default)]
pub struct Outcomes {
    entries: Vec<Entry>,
    diagnostics: Diagnostics,
    dirty: bool,
}

#[derive(Clone, Copy)]
pub struct Observation {
    pub scope: Option<ProbeScope>,
    pub plan: u64,
    pub program: u64,
    pub target: u64,
    pub result: ResultKind,
    pub applied: bool,
    pub transport_established: bool,
    pub probes: usize,
    pub elapsed: Duration,
}

/// A candidate (including its internal retries) has one terminal result.
/// The worker hands it off once. IPC events never write directly into history.
#[derive(Default)]
pub struct Completion(Option<Observation>);

impl Completion {
    pub fn new(observation: Observation) -> Self {
        Self(Some(observation))
    }

    pub fn commit(&mut self, outcomes: &mut Outcomes, now: u64) {
        if let Some(observation) = self.0.take() {
            outcomes.record(observation, now);
        }
    }
}

#[derive(Default)]
pub struct Ranking(Vec<(u64, u64, u32)>);

impl Ranking {
    pub fn for_plan(&self, id: &str, text: &str) -> u32 {
        if self.0.is_empty() {
            return 0;
        }
        let key = plan_key(id);
        let index = self.0.partition_point(|entry| entry.0 < key);
        let matching = &self.0[index..];
        if matching.first().is_none_or(|entry| entry.0 != key) {
            return 0;
        }
        let program = plan_key(text);
        matching
            .iter()
            .take_while(|entry| entry.0 == key)
            .find(|entry| entry.1 == program)
            .map_or(0, |entry| entry.2)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub fn plan_key(id: &str) -> u64 {
    crate::r2o_fallback::tried_key(id)
}

fn fresh(at: u64, now: u64) -> bool {
    at != 0 && at <= now && now - at <= MAX_AGE
}

impl Outcomes {
    fn record(&mut self, observation: Observation, now: u64) {
        use ResultKind::*;
        let d = &mut self.diagnostics;
        let counter = match observation.result {
            Application => &mut d.application,
            Handshake => &mut d.handshake,
            Rejected => &mut d.rejected,
            Unknown => &mut d.unknown,
            LocalError => &mut d.local_error,
            Cancelled => &mut d.cancelled,
        };
        *counter = counter.saturating_add(1);
        d.applied = d.applied.saturating_add(u64::from(observation.applied));
        d.transport_established = d
            .transport_established
            .saturating_add(u64::from(observation.transport_established));
        d.charged_probes = d.charged_probes.saturating_add(observation.probes as u64);
        d.unknown_path = d
            .unknown_path
            .saturating_add(u64::from(observation.scope.is_none()));

        let Some(scope) = observation.scope.filter(|_| {
            observation.applied
                && observation.probes != 0
                && now != 0
                && matches!(observation.result, Application | Rejected)
        }) else {
            return;
        };
        let mut eviction = (0, (true, u64::MAX));
        let mut found = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.scope == scope
                && entry.plan == observation.plan
                && entry.program == observation.program
            {
                found = Some(index);
                break;
            }
            let priority = (fresh(entry.success_at, now), entry.recent());
            if priority < eviction.1 {
                eviction = (index, priority);
            }
        }
        let mut entry = found
            .map(|index| self.entries[index])
            .filter(|entry| fresh(entry.recent(), now))
            .unwrap_or(Entry {
                scope,
                plan: observation.plan,
                program: observation.program,
                successes: 0,
                success_at: 0,
                average_ms: 0,
                average_probes: 0,
                rejected_at: 0,
                rejected_target: 0,
            });
        match observation.result {
            Application => {
                let ms = observation.elapsed.as_millis().clamp(1, u16::MAX.into()) as u16;
                let probes = observation.probes.min(u8::MAX.into()) as u8;
                if fresh(entry.success_at, now) {
                    entry.average_ms =
                        ((u32::from(entry.average_ms) * 3 + u32::from(ms)) / 4) as u16;
                    entry.average_probes =
                        ((u16::from(entry.average_probes) * 3 + u16::from(probes)) / 4) as u8;
                    entry.successes = entry.successes.saturating_add(1);
                } else {
                    entry.average_ms = ms;
                    entry.average_probes = probes;
                    entry.successes = 1;
                }
                entry.success_at = now;
                if entry.rejected_target == observation.target {
                    entry.rejected_at = 0;
                }
            }
            Rejected => {
                entry.rejected_at = now;
                entry.rejected_target = observation.target;
            }
            _ => unreachable!(),
        }
        if let Some(index) = found {
            self.entries[index] = entry;
        } else if self.entries.len() == CAPACITY {
            self.entries[eviction.0] = entry;
            d.evicted = d.evicted.saturating_add(1);
        } else {
            if self.entries.is_empty() {
                self.entries.reserve_exact(CAPACITY);
            }
            self.entries.push(entry);
        }
        self.dirty = true;
    }

    pub fn ranking(&self, scope: ProbeScope, target: u64, now: u64) -> Ranking {
        let mut ranking = Ranking::default();
        for entry in &self.entries {
            if entry.scope != scope || !fresh(entry.success_at, now) {
                continue;
            }
            // A rejection only withdraws our extra preference for the same
            // target and local route. It never changes eligibility or catalog proof.
            if entry.rejected_target == target && fresh(entry.rejected_at, now) {
                continue;
            }
            let age = ((now - entry.success_at) / (24 * 60 * 60)) as u8;
            // 2 bits for repeatability, 4 for age, 8 for probes and 15 for
            // the elapsed cost in 2-ms units. Fits the selector's existing padding.
            let rank = u32::from(entry.successes.min(3)) << 27
                | u32::from(8 - age) << 23
                | u32::from(u8::MAX - entry.average_probes) << 15
                | u32::from((u16::MAX - entry.average_ms) / 2);
            ranking.0.push((entry.plan, entry.program, rank));
        }
        ranking.0.sort_unstable_by_key(|entry| entry.0);
        ranking
    }

    pub fn note_ranked(&mut self, changed_first: bool) {
        self.diagnostics.ranked_searches = self.diagnostics.ranked_searches.saturating_add(1);
        self.diagnostics.changed_first = self
            .diagnostics
            .changed_first
            .saturating_add(u64::from(changed_first));
    }

    pub fn diagnostics(&self) -> Diagnostics {
        Diagnostics {
            records: self.entries.len(),
            ..self.diagnostics
        }
    }
}

pub struct Persistence {
    path: PathBuf,
    last_write: Instant,
}

impl Persistence {
    pub fn load(catalog: &Path, ipv6: Option<bool>, now: Instant) -> (Self, Outcomes) {
        let path = catalog.with_extension(match ipv6 {
            Some(false) => "outcomes4.json",
            Some(true) => "outcomes6.json",
            None => "outcomes.json",
        });
        let mut outcomes = Outcomes::default();
        if let Ok(file) = std::fs::File::open(&path) {
            let mut bytes = Vec::new();
            if file
                .take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .is_ok()
                && bytes.len() as u64 <= MAX_FILE_BYTES
                && let Ok(mut entries) = serde_json::from_slice::<Vec<Entry>>(&bytes)
                && entries.len() <= CAPACITY
            {
                // Trust only one aggregate per key even after a manual file edit.
                entries.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.recent()));
                for entry in entries {
                    if !outcomes.entries.iter().any(|saved| {
                        saved.plan == entry.plan
                            && saved.program == entry.program
                            && saved.scope == entry.scope
                    }) {
                        outcomes.entries.push(entry);
                    }
                }
            }
        }
        (
            Self {
                path,
                last_write: now,
            },
            outcomes,
        )
    }

    pub fn save(
        &mut self,
        outcomes: &std::sync::Mutex<Outcomes>,
        now: Instant,
        wall: u64,
        shutdown: bool,
    ) -> Result<(), CatalogError> {
        if !shutdown && now.saturating_duration_since(self.last_write) < SAVE_INTERVAL {
            return Ok(());
        }
        self.last_write = now;
        let entries = {
            let mut outcomes = outcomes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !outcomes.dirty {
                return Ok(());
            }
            outcomes.entries.retain(|entry| fresh(entry.recent(), wall));
            outcomes.dirty = false;
            outcomes.entries.clone()
        };
        let result = write_atomic(&self.path, 1024, MAX_FILE_BYTES, true, |writer| {
            serde_json::to_writer(writer, &entries)
                .map_err(|error| CatalogError::new(format!("write Discovery outcomes: {error}")))
        });
        let mut outcomes = outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if result.is_ok() {
            outcomes.diagnostics.saves = outcomes.diagnostics.saves.saturating_add(1);
        } else {
            outcomes.dirty = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOPE: ProbeScope = ProbeScope {
        path: [7; 16],
        port: 443,
        family: 4,
        shape: 1,
        profile: 1,
    };

    fn observation(result: ResultKind) -> Observation {
        Observation {
            scope: Some(SCOPE),
            plan: plan_key("ready"),
            program: plan_key("ready program"),
            target: 1,
            result,
            applied: true,
            transport_established: true,
            probes: 2,
            elapsed: Duration::from_millis(70),
        }
    }

    #[test]
    fn only_terminal_authenticated_outcomes_can_supply_a_preference() {
        let mut outcomes = Outcomes::default();
        for result in [
            ResultKind::Cancelled,
            ResultKind::LocalError,
            ResultKind::Unknown,
            ResultKind::Handshake,
        ] {
            Completion::new(observation(result)).commit(&mut outcomes, 50);
        }
        let good = observation(ResultKind::Application);
        Completion::new(Observation {
            scope: None,
            ..good
        })
        .commit(&mut outcomes, 50);
        Completion::new(Observation {
            applied: false,
            ..good
        })
        .commit(&mut outcomes, 50);
        assert_eq!(outcomes.diagnostics().records, 0);
        let mut completion = Completion::new(good);
        completion.commit(&mut outcomes, 51);
        completion.commit(&mut outcomes, 52);
        assert_eq!(outcomes.entries[0].successes, 1);
        assert_eq!(outcomes.diagnostics().application, 3);
        assert!(
            outcomes
                .ranking(SCOPE, 2, 52)
                .for_plan("ready", "ready program")
                > 0
        );
        assert!(
            outcomes
                .ranking(
                    ProbeScope {
                        path: [8; 16],
                        ..SCOPE
                    },
                    2,
                    52
                )
                .is_empty()
        );
        assert!(outcomes.ranking(SCOPE, 2, 52 + MAX_AGE).is_empty());
        Completion::new(observation(ResultKind::Rejected)).commit(&mut outcomes, 55);
        assert_eq!(
            outcomes
                .ranking(SCOPE, 1, 55)
                .for_plan("ready", "ready program"),
            0
        );
        assert!(
            outcomes
                .ranking(SCOPE, 2, 55)
                .for_plan("ready", "ready program")
                > 0
        );
    }

    #[test]
    fn another_targets_success_keeps_a_fresh_rejection_in_effect() {
        let mut outcomes = Outcomes::default();
        let app_a = observation(ResultKind::Application);
        let app_b = Observation { target: 2, ..app_a };
        let rank = |outcomes: &Outcomes, target, now| {
            outcomes
                .ranking(SCOPE, target, now)
                .for_plan("ready", "ready program")
        };

        Completion::new(app_a).commit(&mut outcomes, 50);
        Completion::new(Observation {
            result: ResultKind::Rejected,
            ..app_b
        })
        .commit(&mut outcomes, 51);
        Completion::new(app_a).commit(&mut outcomes, 53);

        assert_eq!(rank(&outcomes, 2, 53), 0);
        assert!(rank(&outcomes, 1, 53) > 0);
        assert!(rank(&outcomes, 3, 53) > 0);
        assert!(rank(&outcomes, 2, 51 + MAX_AGE + 1) > 0);

        Completion::new(app_b).commit(&mut outcomes, 54);
        assert!(rank(&outcomes, 2, 54) > 0);
    }

    #[test]
    fn bounded_persistence_survives_restart_and_keeps_catalog_independent() {
        let dir = std::env::temp_dir().join(format!("r2o-outcomes-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("catalog.json");
        std::fs::write(&path, b"{\"boxes\":[]}").unwrap();
        let now = Instant::now();
        let (mut persistence, mut outcomes) = Persistence::load(&path, Some(false), now);
        let observation = observation(ResultKind::Application);
        for plan in 1..=CAPACITY as u64 + 1 {
            Completion::new(Observation {
                plan,
                ..observation
            })
            .commit(&mut outcomes, plan);
        }
        assert_eq!(outcomes.entries.len(), CAPACITY);
        assert_eq!(outcomes.diagnostics().evicted, 1);
        assert!(outcomes.entries.iter().all(|entry| entry.plan != 1));
        assert!(outcomes.entries.capacity() <= CAPACITY);
        let outcomes = std::sync::Mutex::new(outcomes);
        persistence.save(&outcomes, now, 80, false).unwrap();
        assert!(!persistence.path.exists());
        persistence
            .save(&outcomes, now + SAVE_INTERVAL, 80, false)
            .unwrap();
        assert!(std::fs::metadata(&persistence.path).unwrap().len() <= MAX_FILE_BYTES);
        let (_, restored) = Persistence::load(&path, Some(false), now);
        assert_eq!(restored.entries.len(), CAPACITY);
        let (_, ipv6) = Persistence::load(&path, Some(true), now);
        assert!(ipv6.entries.is_empty());
        std::fs::remove_file(&persistence.path).unwrap();
        assert_eq!(
            crate::catalog::Catalog::load(&path).unwrap(),
            crate::catalog::Catalog::default()
        );
        let (_, rolled_back) = Persistence::load(&path, Some(false), now);
        assert!(rolled_back.entries.is_empty());
        assert!(CAPACITY * std::mem::size_of::<Entry>() < 8192);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verified_experience_reorders_compatible_plans_but_keeps_bound_and_shape_priority() {
        use crate::catalog::{Binding, BoxRecord, Catalog, Plan};
        use crate::discovery::{DiscoveryTarget, OwnFirstBatches};
        let target = DiscoveryTarget {
            host: "test.example.net".into(),
            endpoint: "198.51.100.1:443".into(),
            family: 4,
            shape: 1,
            tcp_profile: 1,
        };
        let candidate = |index, id: &str, proto: &str, profile, successes| BoxRecord {
            id: id.into(),
            plans: vec![Plan {
                id: id.into(),
                text: format!("r2o-plan 1 10\nproto tcp tls\nsplit payload_start +{index}\n"),
                proto: proto.into(),
                enabled: true,
                successes,
                ..Plan::default()
            }],
            bindings: vec![Binding {
                kind: "name".into(),
                target: "saved.example.net".into(),
                plan_id: id.into(),
                enabled: true,
                level: 3,
                family: 4,
                transport: 6,
                shape: 1,
                tcp_profile: profile,
                successes,
                ..Binding::default()
            }],
            ..BoxRecord::default()
        };
        let catalog = Catalog {
            boxes: vec![
                candidate(1, "legacy-rank", "tls", 1, 20),
                candidate(2, "ready", "tls", 1, 1),
                candidate(3, "wrong-profile", "tls", 2, 1),
                candidate(4, "wrong-protocol", "quic", 1, 1),
            ],
            ..Catalog::default()
        };
        let mut outcomes = Outcomes::default();
        for entry in &catalog.boxes[1..] {
            let plan = &entry.plans[0];
            Completion::new(Observation {
                plan: plan_key(&plan.id),
                program: plan_key(&plan.text),
                ..observation(ResultKind::Application)
            })
            .commit(&mut outcomes, 100);
        }
        let ranking = outcomes.ranking(SCOPE, 2, 101);
        let select = |bound, score| {
            OwnFirstBatches::with_experience(&catalog, &target, false, bound, &[], &[], score)
                .next_batch()
                .into_iter()
                .map(|value| value.plan.id.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(select(None, None), ["legacy-rank", "ready"]);
        assert_eq!(select(None, Some(&ranking)), ["ready", "legacy-rank"]);
        assert_eq!(
            select(Some("legacy-rank"), Some(&ranking)),
            ["legacy-rank", "ready"]
        );
    }
}
