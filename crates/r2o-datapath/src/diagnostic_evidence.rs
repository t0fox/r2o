//! Короткая выборка локальных доказательств из существующих событий и решений.

use r2k_core::control::KEY_LEN;
use r2k_core::packet::PacketView;
use r2o_datapath::flow_journal::{R2oFlowJournal, R2oFlowJournalKind as Kind};
use r2o_datapath::netlink::{QueuePacket, R2O_NF_INET_LOCAL_OUT, R2O_NF_INET_POST_ROUTING};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, SocketAddr};

const ROUTE_ROWS: usize = 8;
const ROUTE_ATTEMPTS_PER_SNAPSHOT: u8 = 32;
const JOURNAL_ROWS: usize = 12;

struct RouteSample {
    at_ms: u64,
    flow: u64,
    decision: &'static str,
    provenance: &'static str,
    destination: Option<SocketAddr>,
    ifindex: Option<u32>,
    mark: Option<u32>,
    hook: Option<u8>,
}

#[derive(Default)]
pub(super) struct Evidence {
    session: Option<RandomState>,
    routes: VecDeque<RouteSample>,
    remaining: u8,
}

impl Evidence {
    pub(super) fn set_enabled(&mut self, enabled: bool) {
        match (enabled, self.session.is_some()) {
            (true, false) => {
                self.session = Some(RandomState::new());
                self.remaining = ROUTE_ATTEMPTS_PER_SNAPSHOT;
            }
            (false, true) => *self = Self::default(),
            _ => {}
        }
    }

    pub(super) fn enabled(&self) -> bool {
        self.session.is_some()
    }

    pub(super) fn wants_route(&self) -> bool {
        self.remaining != 0
    }

    pub(super) fn route(
        &mut self,
        packet: &QueuePacket<'_>,
        decision: &'static str,
        controller_probe: bool,
        now_ns: u64,
    ) {
        if self.remaining == 0 {
            return;
        }
        self.remaining -= 1;
        let Some(salt) = &self.session else { return };
        let Some((key, destination)) = packet.payload.and_then(packet_key) else {
            return;
        };
        let flow = flow_token(salt, &key);
        let at_ms = now_ns / 1_000_000;
        // Повторные пакеты одной попытки не вытесняют события других потоков.
        if self.routes.iter().any(|row| {
            row.flow == flow
                && row.decision == decision
                && row.mark == packet.mark
                && row.ifindex == packet.output_device
                && at_ms.saturating_sub(row.at_ms) < 5_000
        }) {
            return;
        }
        if self.routes.len() == ROUTE_ROWS {
            self.routes.pop_front();
        }
        self.routes.push_back(RouteSample {
            at_ms,
            flow,
            decision,
            provenance: if controller_probe {
                "controller-probe"
            } else if packet.hook == Some(R2O_NF_INET_LOCAL_OUT) {
                "router-local-output"
            } else {
                "unknown"
            },
            destination: matches!(
                packet.hook,
                Some(R2O_NF_INET_LOCAL_OUT | R2O_NF_INET_POST_ROUTING)
            )
            .then_some(destination),
            ifindex: packet.output_device,
            mark: packet.mark,
            hook: packet.hook,
        });
    }

    pub(super) fn snapshot(&mut self, journal: &R2oFlowJournal, now_ns: u64) -> Value {
        let Some(salt) = &self.session else {
            return Value::Null;
        };
        let route_budget_exhausted = self.remaining == 0;
        self.remaining = ROUTE_ATTEMPTS_PER_SNAPSHOT;
        let route_decisions = self
            .routes
            .iter()
            .map(|row| {
                json!({
                    "at_monotonic_ms": row.at_ms,
                    "flow": format!("{:016x}", row.flow),
                    "decision": row.decision,
                    "provenance": row.provenance,
                    "destination": row.destination,
                    "oif": row.ifindex,
                    "mark": row.mark,
                    "hook": row.hook,
                })
            })
            .collect::<Vec<_>>();
        let mut journal_rows = Vec::with_capacity(JOURNAL_ROWS);
        for index in (0..journal.count()).rev() {
            let Some(row) = journal.get(index) else {
                continue;
            };
            if !matches!(row.key[0], 4 | 6) || !matches!(row.key[37], 6 | 17) {
                continue;
            }
            let stage = match row.kind {
                Kind::Observation | Kind::Shape => continue,
                Kind::Hello => "hello-observed",
                Kind::PlanApplied => "plan-prepared",
                Kind::PlanDone => "plan-executed",
                Kind::PlanRefused => "plan-refused",
                Kind::PlanUnsent => "plan-unsent",
                Kind::PlanDamaged => "flow-damaged",
                Kind::Exchange => "transport-exchange",
                Kind::R2oVoiceProof => "voice-exchange",
                Kind::R2oTcpRstCut => "rst-filtered",
                _ => "suspected-failure",
            };
            let name = row
                .name
                .get(..usize::from(row.name_len))
                .and_then(|name| std::str::from_utf8(name).ok())
                .filter(|name| {
                    !name.is_empty()
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
                });
            journal_rows.push(json!({
                "at_monotonic_ms": row.at_ns / 1_000_000,
                "flow": format!("{:016x}", flow_token(salt, &row.key)),
                "transport": row.key[37],
                "stage": stage,
                "event": row.kind.russian_name(),
                "code": row.code,
                "server_hello": (row.kind == Kind::Exchange && row.key[37] == 6).then_some(row.server_hello),
                "observed_response_bytes": (row.kind == Kind::Exchange && row.key[37] == 6).then_some(row.num),
                "target": name,
                "server": row.client_is_low.and_then(|low| endpoint(&row.key, low)),
                "temporary_binding": row.binding.filter(|b| b.is_known()).map(|b| b.temporary),
                "execution_id": (row.execution_id != 0).then_some(row.execution_id),
                "elapsed_ms": (row.elapsed_ms != 0).then_some(row.elapsed_ms),
            }));
            if journal_rows.len() == JOURNAL_ROWS {
                break;
            }
        }
        journal_rows.reverse();
        json!({
            "route_decisions": route_decisions,
            "journal": journal_rows,
            "journal_overwritten": journal.dropped(),
            "snapshot_at_monotonic_ms": now_ns / 1_000_000,
            "coverage": "bounded-sample",
            "route_sample_budget_exhausted": route_budget_exhausted,
        })
    }
}

fn endpoint(key: &[u8; KEY_LEN], high: bool) -> Option<SocketAddr> {
    let address = 1 + 16 * usize::from(high);
    let port = 33 + 2 * usize::from(high);
    let ip = match key[0] {
        4 => IpAddr::from(<[u8; 4]>::try_from(&key[address..address + 4]).ok()?),
        6 => IpAddr::from(<[u8; 16]>::try_from(&key[address..address + 16]).ok()?),
        _ => return None,
    };
    Some(SocketAddr::new(
        ip,
        u16::from_be_bytes([key[port], key[port + 1]]),
    ))
}

fn flow_token(salt: &RandomState, key: &[u8; KEY_LEN]) -> u64 {
    let mut ends = [endpoint(key, false), endpoint(key, true)];
    ends.sort_unstable();
    salt.hash_one((key[37], ends))
}

fn packet_key(bytes: &[u8]) -> Option<([u8; KEY_LEN], SocketAddr)> {
    let view = PacketView::parse(bytes)?;
    if !matches!(view.protocol, 6 | 17) {
        return None;
    }
    let ports = bytes.get(view.l4_offset..view.l4_offset.checked_add(4)?)?;
    let mut key = [0; KEY_LEN];
    key[0] = view.family;
    key[1..17].copy_from_slice(&view.src.bytes());
    key[17..33].copy_from_slice(&view.dst.bytes());
    key[33..37].copy_from_slice(ports);
    key[37] = view.protocol;
    Some((key, endpoint(&key, true)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2o_datapath::flow_journal::R2oFlowJournalEntry;

    #[test]
    fn correlates_skip_and_execution_without_exposing_client_address() {
        let mut evidence = Evidence::default();
        evidence.set_enabled(true);
        let mut bytes = [0_u8; 40];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&40_u16.to_be_bytes());
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[203, 0, 113, 2]);
        bytes[20..22].copy_from_slice(&2000_u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&443_u16.to_be_bytes());
        let packet = QueuePacket {
            hook: Some(R2O_NF_INET_POST_ROUTING),
            payload: Some(&bytes),
            output_device: Some(35),
            mark: Some(0xffffaab),
            ..Default::default()
        };
        evidence.route(&packet, "route-mark", false, 1_000_000);
        evidence.route(&packet, "route-mark", false, 1_001_000);
        let mut journal = R2oFlowJournal::with_capacity(4).unwrap();
        let (key, _) = packet_key(&bytes).unwrap();
        for (execution_id, kind) in [(15, Kind::PlanApplied), (15, Kind::PlanDone)] {
            journal.push(R2oFlowJournalEntry {
                key,
                kind,
                execution_id,
                client_is_low: Some(true),
                ..Default::default()
            });
        }
        let snapshot = evidence.snapshot(&journal, 1_001_000);
        let routes = snapshot["route_decisions"].as_array().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0]["destination"], "203.0.113.2:443");
        assert_eq!(routes[0]["provenance"], "unknown");
        assert_eq!(routes[0]["flow"], snapshot["journal"][0]["flow"]);
        assert_eq!(snapshot["journal"][0]["stage"], "plan-prepared");
        assert_eq!(snapshot["journal"][1]["stage"], "plan-executed");
        assert!(!snapshot.to_string().contains("192.0.2.1"));
        evidence.set_enabled(false);
        assert!(evidence.snapshot(&journal, 1_001_000).is_null());
    }
}
