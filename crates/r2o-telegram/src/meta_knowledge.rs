//! Компактная база проверок Meta. Записи источников сами по себе не создают DNS-правил.

use crate::list_update::{ListKind, ListPaths, SOURCES, is_meta_source, verified_meta_source};
use crate::meta_dns::{atomic_write, parse_meta_ranges};
use crate::meta_edge::META_HOSTS;
use r2k_core::meta::product;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

const MAX_BYTES: usize = 1536 * 1024;
const MAX_HOSTS: usize = 640;
const MAX_EXTERNAL_PER_PRODUCT: usize = 64;
const CHECKS_PER_TICK: usize = 8;
const DAY: u64 = 86400;

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Knowledge {
    pub hosts: BTreeMap<String, Host>,
    pub sources: BTreeMap<String, Source>,
    pub checked_at: u64,
    pub error: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Host {
    pub product: String,
    pub sources: Vec<String>,
    pub observed_at: u64,
    pub checked_at: u64,
    pub dns_addresses: usize,
    #[serde(default)]
    pub local_dns: String,
    pub addresses: Vec<Address>,
    pub last_failure: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Address {
    pub ip: IpAddr,
    pub asn: Option<u32>,
    pub resolver: String,
    pub checked_at: u64,
    pub verified_at: u64,
    pub result: String,
    pub pinned: bool,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Source {
    pub url: String,
    pub synced_at: u64,
    pub sha256: String,
    pub entries: usize,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<(IpAddr, u8)>,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u8,
    sha256: String,
    data: Knowledge,
}

fn read_bounded(path: &Path, limit: usize) -> Option<String> {
    let mut buf = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(limit as u64 + 1)
        .read_to_string(&mut buf)
        .ok()?;
    (buf.len() <= limit).then_some(buf)
}

fn digest(value: &Knowledge) -> Result<String, serde_json::Error> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

impl Knowledge {
    pub fn load(state: &Path) -> Self {
        let read = |name| {
            let raw = read_bounded(&state.join(name), MAX_BYTES)?;
            let snapshot: Snapshot = serde_json::from_str(&raw).ok()?;
            (snapshot.version == 1
                && snapshot.data.hosts.len() <= MAX_HOSTS
                && digest(&snapshot.data).ok()? == snapshot.sha256)
                .then_some(snapshot.data)
        };
        read("meta-knowledge.json")
            .or_else(|| read("meta-knowledge.previous.json"))
            .unwrap_or_default()
    }

    pub fn persist(self, state: &Path) -> Result<(), String> {
        let summary = self.summary();
        let path = state.join("meta-knowledge.json");
        let snapshot = Snapshot {
            version: 1,
            sha256: digest(&self).map_err(|error| error.to_string())?,
            data: self,
        };
        let bytes = serde_json::to_vec(&snapshot).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_BYTES {
            return Err("снимок Meta превышает допустимый размер".into());
        }
        if let Some(previous) = read_bounded(&path, MAX_BYTES)
            && previous.as_bytes() == bytes
        {
            return write_summary(state, &summary);
        }
        if let Some(previous) = read_bounded(&path, MAX_BYTES)
            && let Ok(old) = serde_json::from_str::<Snapshot>(&previous)
            && old.version == 1
            && digest(&old.data).ok().as_deref() == Some(&old.sha256)
        {
            atomic_write(
                &state.join("meta-knowledge.previous.json"),
                previous.as_bytes(),
            )?;
        }
        atomic_write(&path, &bytes)?;
        write_summary(state, &summary)
    }

    fn summary(&self) -> serde_json::Value {
        use serde_json::json;
        let families: Vec<_> = r2k_core::meta::PRODUCTS.iter().map(|family| {
            let hosts: Vec<_> = self.hosts.iter().filter(|(_, host)| host.product == *family).collect();
            let verified = |a: &Address| a.verified_at != 0 && a.verified_at == a.checked_at;
            let ips: Vec<_> = hosts.iter().flat_map(|(_, host)| &host.addresses).collect();
            let last_failure = hosts.iter().filter(|(_, host)| host.last_failure.is_some())
                .max_by_key(|(_, host)| host.checked_at)
                .map(|(name, host)| json!({"host":name,"detail":host.last_failure,"at":host.checked_at}));
            let mut samples: Vec<_> = hosts.iter().flat_map(|(name, host)| {
                host.addresses.iter().map(move |address| (*name, address))
            }).collect();
            samples.sort_unstable_by_key(|(_, address)| std::cmp::Reverse(address.checked_at));
            let samples: Vec<_> = samples.iter().filter(|(_, a)| verified(a)).take(3)
                .chain(samples.iter().filter(|(_, a)| !verified(a)).take(3))
                .map(|(name, address)| json!({"host":name,"address":address})).collect();
            let unique = |v6, passed| ips.iter().filter(|a| a.ip.is_ipv6() == v6 && verified(a) == passed)
                .map(|a| a.ip).collect::<std::collections::BTreeSet<_>>().len();
            let local_dns = hosts.iter().filter(|(_, host)| !host.local_dns.is_empty()).max_by_key(|(_, host)| host.checked_at)
                .map(|(name, host)| json!({"host":name,"status":host.local_dns}));
            json!({
                "product":family,"local_dns":local_dns, "domains":hosts.len(),
                "observed":hosts.iter().filter(|(_, host)| host.observed_at != 0).count(),
                "dns_ok":hosts.iter().filter(|(_, host)| host.dns_addresses != 0).count(),
                "checked":hosts.iter().filter(|(_, host)| host.checked_at != 0).count(),
                "verified_domains":hosts.iter().filter(|(_, host)| host.addresses.iter().any(verified)).count(),
                "ipv4":unique(false, true), "ipv6":unique(true, true),
                "unverified":unique(false, false) + unique(true, false),
                "pinned":ips.iter().filter(|ip| ip.pinned).count(),
                "last_failure":last_failure, "sample":samples,
                "checked_at":hosts.iter().map(|(_, host)| host.checked_at).max().unwrap_or_default(),
            })
        }).collect();
        let sources: Vec<_> = self
            .sources
            .iter()
            .map(|(name, source)| {
                json!({
                    "id":name,"url":source.url,"synced_at":source.synced_at,"sha256":source.sha256,
                    "entries":source.entries,"error":source.error,
                })
            })
            .collect();
        let prefixes = self
            .sources
            .values()
            .flat_map(|source| source.prefixes.iter().copied())
            .collect::<std::collections::BTreeSet<_>>();
        let ipv4_prefixes = prefixes.iter().filter(|(ip, _)| ip.is_ipv4()).count();
        json!({"checked_at":self.checked_at,"error":self.error,"families":families,"sources":sources,
            "ipv4_prefixes":ipv4_prefixes,"ipv6_prefixes":prefixes.len() - ipv4_prefixes})
    }

    pub fn add_host(&mut self, raw: &str, source: &str, observed_at: u64) {
        let host = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
        let Some(family) = product(&host) else {
            return;
        };
        if !self.hosts.contains_key(&host) && self.hosts.len() >= MAX_HOSTS {
            let replace = self
                .hosts
                .iter()
                .filter(|(_, entry)| {
                    observed_at != 0
                        && observed_at.saturating_sub(entry.observed_at) > DAY
                        && entry
                            .addresses
                            .iter()
                            .all(|addr| addr.verified_at == 0 && !addr.pinned)
                        && !entry.sources.iter().any(|source| source == "bootstrap")
                })
                .min_by_key(|(_, entry)| (entry.observed_at, entry.checked_at))
                .map(|(name, _)| name.clone());
            let Some(victim) = replace else {
                return;
            };
            self.hosts.remove(&victim);
        }
        let entry = self.hosts.entry(host).or_default();
        if !entry.sources.iter().any(|found| found == source) {
            entry.sources.push(source.to_owned());
        }
        entry.product = family.to_owned();
        entry.observed_at = entry.observed_at.max(observed_at);
    }

    pub fn refresh_sources(&mut self, lists: &ListPaths, runtime: &Path, now: u64) {
        for host in META_HOSTS {
            self.add_host(host, "bootstrap", 0);
        }
        for file in [
            "meta-observed-v4.json",
            "meta-observed-v6.json",
            "meta-observed-dual.json",
        ] {
            if let Some(body) = read_bounded(&runtime.join(file), 96 * 1024)
                && let Ok(rows) = serde_json::from_str::<Vec<(String, String, u64)>>(&body)
            {
                for (host, kind, timestamp) in rows.into_iter().take(256) {
                    if timestamp <= now
                        && now - timestamp <= DAY
                        && matches!(
                            kind.as_str(),
                            "tls-sni" | "quic-sni" | "dns" | "certificate"
                        )
                    {
                        self.add_host(&host, &kind, timestamp);
                    }
                }
            }
        }
        for source in SOURCES.iter().filter(|source| is_meta_source(source)) {
            let error = read_bounded(&lists.dir.join(format!("{}.error", source.name)), 512);
            let Some((synced_at, sha256, body)) = verified_meta_source(&lists.dir, source) else {
                let current = self.sources.entry(source.name.to_owned()).or_default();
                current.url = source.parts.join(", ");
                current.error =
                    error.or_else(|| Some("нет снимка с подтверждённой целостностью".into()));
                continue;
            };
            let prefixes = if source.kind == ListKind::Cidr {
                parse_meta_ranges(&body).unwrap_or_default()
            } else {
                Vec::new()
            };
            let mut count = 0;
            if source.kind == ListKind::Domains {
                for host in body.lines().filter(|host| product(host).is_some()) {
                    let family = product(host).unwrap();
                    let already_known = self.hosts.contains_key(host);
                    if already_known
                        || self
                            .hosts
                            .values()
                            .filter(|entry| entry.product == family)
                            .take(MAX_EXTERNAL_PER_PRODUCT)
                            .count()
                            < MAX_EXTERNAL_PER_PRODUCT
                    {
                        self.add_host(host, source.name, 0);
                    }
                    count += 1;
                }
            } else {
                count = body
                    .lines()
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .count();
            }
            self.sources.insert(
                source.name.to_owned(),
                Source {
                    url: source.parts.join(", "),
                    synced_at,
                    sha256,
                    entries: count,
                    error,
                    prefixes,
                },
            );
        }
    }

    pub fn due(&self, now: u64, force: bool) -> Vec<String> {
        let mut due: Vec<_> = self
            .hosts
            .iter()
            .filter(|(_, host)| {
                force
                    || host.checked_at == 0
                    || (host.observed_at > host.checked_at
                        && now.saturating_sub(host.checked_at) >= 300)
                    || now.saturating_sub(host.checked_at)
                        >= if host.last_failure.is_some() {
                            1800
                        } else {
                            DAY
                        }
            })
            .collect();
        due.sort_unstable_by_key(|(name, host)| {
            (
                host.checked_at != 0,
                host.observed_at == 0,
                !META_HOSTS.contains(&name.as_str()),
                host.checked_at,
            )
        });
        due.truncate(if force {
            3 * CHECKS_PER_TICK
        } else {
            CHECKS_PER_TICK
        });
        due.into_iter().map(|(host, _)| host.clone()).collect()
    }

    pub fn ranges(&self) -> Vec<(IpAddr, u8)> {
        self.sources
            .iter()
            .filter(|(name, _)| asn_for_source(name).is_some())
            .flat_map(|(_, source)| source.prefixes.iter().copied())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn asn(&self, address: IpAddr) -> Option<u32> {
        self.sources
            .iter()
            .filter_map(|(id, source)| {
                let asn = asn_for_source(id)?;
                let prefix = source
                    .prefixes
                    .iter()
                    .filter(|range| {
                        crate::meta_dns::is_meta_ip(std::slice::from_ref(range), address)
                    })
                    .map(|(_, prefix)| *prefix)
                    .max()?;
                Some((prefix, asn))
            })
            .max_by_key(|(prefix, _)| *prefix)
            .map(|(_, asn)| asn)
    }
}

fn write_summary(state: &Path, summary: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(summary).map_err(|error| error.to_string())?;
    let path = state.join("meta-status.json");
    if read_bounded(&path, 64 * 1024).is_some_and(|old| old.as_bytes() == bytes) {
        return Ok(());
    }
    atomic_write(&path, &bytes)
}

fn asn_for_source(source: &str) -> Option<u32> {
    match source {
        "meta-ranges" | "meta-as32934-v6" => Some(32934),
        "meta-as63293-v4" | "meta-as63293-v6" => Some(63293),
        "meta-as54115-v4" | "meta-as54115-v6" => Some(54115),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_names_are_candidates_and_saved_snapshot_survives_corruption() {
        let path = std::env::temp_dir().join(format!("r2o-meta-kb-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        let mut kb = Knowledge::default();
        kb.add_host("new-cdn.WhatsApp.net", "tls-sni", 42);
        kb.add_host("a.whatsapp.net.attacker.test", "tls-sni", 43);
        assert_eq!(kb.due(43, false), ["new-cdn.whatsapp.net"]);
        assert!(kb.hosts["new-cdn.whatsapp.net"].addresses.is_empty());
        kb.persist(&path).unwrap();
        let mut second = Knowledge::load(&path);
        second.checked_at = 1;
        second.persist(&path).unwrap();
        std::fs::write(path.join("meta-knowledge.json"), "{}").unwrap();
        assert_eq!(Knowledge::load(&path).hosts.len(), 1);
        std::fs::remove_dir_all(path).unwrap();
    }
}
