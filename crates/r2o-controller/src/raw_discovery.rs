//! Bounded leases for measured opaque TCP retransmissions. Catalog entries
//! only supply a candidate to a newly measured flow.
use crate::catalog::{Binding, BoxRecord, Catalog};
use crate::r2o_resource_limit::R2oMeasurementPermit;
use r2k_core::raw_flow::{
    LEASE, MAX_ACTIVE, Profile, Report, ResultKind, SHAPE_RAW_TCP, Sample, Trial,
};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

const MAX_BINDINGS: usize = 64;
const MAX_RECENT_MEASUREMENTS: usize = 64;
const VERIFIED_TRANSPORT_ACK: u8 = 8;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn from_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.is_ascii() {
        return None;
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn binding_profile(binding: &Binding) -> Option<Profile> {
    Profile::decode(&from_hex::<{ Profile::WIDTH }>(&binding.raw_profile)?)
}

pub fn valid_binding(binding: &Binding) -> bool {
    binding.kind == "raw"
        && binding.shape == SHAPE_RAW_TCP
        && binding.transport == 6
        && matches!(binding.family, 4 | 6)
        && binding.port != 0
        && binding.verified_by == VERIFIED_TRANSPORT_ACK
        && binding_profile(binding).is_some_and(|profile| profile.tcp == binding.tcp_profile)
        && binding.target.parse::<IpAddr>().is_ok_and(|ip| {
            ip.to_string() == binding.target
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && ip.is_ipv4() == (binding.family == 4)
        })
}

fn plan_text(profile: Profile, id: [u8; 16]) -> String {
    let id = hex(&id);
    format!(
        "r2o-plan 1 1\nid {id}\nproto tcp unknown\nsplit payload_start +{}\norder forward\n",
        profile.length / 2
    )
}

fn compatible(binding: &Binding, endpoint: SocketAddr, profile: Profile) -> bool {
    valid_binding(binding)
        && binding.enabled
        && binding.level >= 3
        && binding.recheck_since.is_none()
        && binding.port == endpoint.port()
        && binding.target.parse::<IpAddr>().ok() == Some(endpoint.ip())
        && binding_profile(binding) == Some(profile)
}

pub fn candidate(catalog: &Catalog, sample: Sample) -> Option<([u8; 16], bool)> {
    let endpoint = sample.server();
    if sample.key[37] != 6
        || endpoint.port() == 0
        || endpoint.ip().is_unspecified()
        || endpoint.ip().is_multicast()
    {
        return None;
    }
    let own = catalog
        .boxes
        .iter()
        .flat_map(|record| {
            record
                .bindings
                .iter()
                .filter(|binding| compatible(binding, endpoint, sample.profile))
                .filter_map(|binding| {
                    let plan = record.plans.iter().find(|plan| {
                        plan.id == binding.plan_id && plan.enabled && plan.proto == "raw"
                    })?;
                    let id = from_hex(&plan.id)?;
                    (id != [0; 16] && plan.text == plan_text(sample.profile, id))
                        .then_some((binding.confirmed, id))
                })
        })
        .max_by_key(|(confirmed, _)| *confirmed);
    if let Some((_, id)) = own {
        return Some((id, true));
    }
    let mut digest = Sha256::new();
    digest.update(b"r2o-raw-tcp-split-v1");
    digest.update(sample.profile.encode());
    let digest = digest.finalize();
    Some((digest[..16].try_into().unwrap(), false))
}

pub fn save_confirmed(catalog: &mut Catalog, report: Report, now: i64) -> Result<(), String> {
    let sample = report.trial.sample;
    if report.kind != ResultKind::TransportAck
        || report.execution == 0
        || candidate(catalog, sample).is_none()
    {
        return Err("RAW report has no verified transport context".into());
    }
    let endpoint = sample.server();
    let mut digest = Sha256::new();
    digest.update(b"r2o-raw-tcp-endpoint-v1");
    digest.update(endpoint.to_string().as_bytes());
    let digest = digest.finalize();
    let box_id = format!("raw-{}", hex(&digest[..16]));
    let plan_id = hex(&report.trial.plan);
    let index = match catalog.boxes.iter().position(|record| record.id == box_id) {
        Some(index) => index,
        None => {
            let mut raw_boxes = catalog.boxes.iter().enumerate().filter(|(_, record)| {
                !record.bindings.is_empty() && record.bindings.iter().all(|b| b.kind == "raw")
            });
            let oldest = raw_boxes
                .by_ref()
                .min_by_key(|(_, record)| record.updated)
                .map(|(i, _)| i);
            let raw_count = catalog
                .boxes
                .iter()
                .filter(|record| record.bindings.iter().any(|b| b.kind == "raw"))
                .count();
            if raw_count >= MAX_BINDINGS {
                if let Some(oldest) = oldest {
                    catalog.boxes.remove(oldest);
                } else {
                    return Err("RAW endpoint capacity is exhausted".into());
                }
            }
            catalog.boxes.push(BoxRecord {
                id: box_id.clone(),
                created: now,
                updated: now,
                ..BoxRecord::default()
            });
            catalog.boxes.len() - 1
        }
    };
    let record = &mut catalog.boxes[index];
    if record.bindings.iter().any(|binding| binding.kind != "raw")
        || record.plans.iter().any(|plan| plan.proto != "raw")
    {
        return Err("RAW endpoint box conflicts with an existing catalog entry".into());
    }
    let profile_text = hex(&sample.profile.encode());
    record
        .bindings
        .retain(|binding| binding.raw_profile == profile_text && binding.plan_id == plan_id);
    record.plans.retain(|plan| plan.id == plan_id);

    crate::discovery::bind_confirmed(
        catalog,
        &box_id,
        &plan_id,
        &plan_text(sample.profile, report.trial.plan),
        "raw",
        &endpoint.ip().to_string(),
        "raw",
        6,
        sample.key[0],
        SHAPE_RAW_TCP,
        sample.profile.tcp,
        VERIFIED_TRANSPORT_ACK,
        crate::discovery::R2O_D2K_INPUT_CLIENT,
        now,
        endpoint.port(),
        None,
    )?;
    catalog.boxes[index].bindings[0].raw_profile = profile_text;
    Ok(())
}

struct Pending {
    trial: Trial,
    expires: Instant,
    execution: Option<u64>,
    _permit: R2oMeasurementPermit,
}

#[derive(Default)]
pub struct Trials {
    pending: Vec<Pending>,
    recent: VecDeque<(Sample, Instant)>,
}

impl Trials {
    pub fn expire(&mut self, now: Instant) {
        self.pending.retain(|entry| {
            if now >= entry.expires {
                eprintln!(
                    "RAW {} measurement={}: inconclusive (deadline)",
                    entry.trial.sample.server(),
                    entry.trial.sample.measurement
                );
                false
            } else {
                true
            }
        });
        self.recent.retain(|(_, until)| now < *until);
    }

    pub fn admits(&self, sample: Sample) -> bool {
        self.pending.len() < MAX_ACTIVE && !self.recent.iter().any(|(seen, _)| *seen == sample)
    }

    pub fn installed(&mut self, trial: Trial, permit: R2oMeasurementPermit, now: Instant) {
        if !self.admits(trial.sample) {
            return;
        }
        if self.recent.len() == MAX_RECENT_MEASUREMENTS {
            self.recent.pop_front();
        }
        self.recent.push_back((trial.sample, now + LEASE));
        self.pending.push(Pending {
            trial,
            expires: now + LEASE,
            execution: None,
            _permit: permit,
        });
    }

    pub fn report(&mut self, report: Report, now: Instant) -> Option<Report> {
        self.expire(now);
        let index = self
            .pending
            .iter()
            .position(|entry| entry.trial == report.trial)?;
        let entry = &mut self.pending[index];
        match report.kind {
            ResultKind::Executed if entry.execution.is_none() => {
                entry.execution = Some(report.execution);
                None
            }
            ResultKind::TransportAck if entry.execution == Some(report.execution) => {
                self.pending.swap_remove(index);
                Some(report)
            }
            _ => None,
        }
    }
}
