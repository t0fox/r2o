//! Наблюдения Discovery для очереди проверки Meta. В файлах нет данных клиентов.

use r2k_core::control::{HelloEvent, SHAPE_HTTP, SHAPE_MODERN};
use r2k_core::meta::{disabled_products, product, product_marker, protection_enabled};
use r2o_controller::discovery::DiscoveryTarget;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const CAPACITY: usize = 256;
const STALE: u64 = 300;
const POLL_INTERVAL: Duration = Duration::from_secs(15);

pub(crate) struct MetaTraffic {
    state: PathBuf,
    observations: PathBuf,
    requests: PathBuf,
    family: Option<u8>,
    names: BTreeMap<String, (&'static str, u64)>,
    updated: bool,
    enabled: bool,
    disabled_products: Vec<&'static str>,
    poll_at: Instant,
    request_stamp: u64,
    pub pending: HashMap<DiscoveryTarget, Instant>,
}

impl MetaTraffic {
    pub fn from_env(family: Option<u8>) -> Option<Self> {
        let state = PathBuf::from(std::env::var_os("R2O_META_STATE_DIR")?);
        let runtime = PathBuf::from(
            std::env::var_os("R2O_RUNTIME_DIR").or_else(|| std::env::var_os("R2O_RUN_DIR"))?,
        );
        let suffix = match family {
            Some(4) => "v4",
            Some(6) => "v6",
            _ => "dual",
        };
        Some(Self {
            enabled: protection_enabled(&state),
            disabled_products: disabled_products(&state),
            state,
            observations: runtime.join(format!("meta-observed-{suffix}.json")),
            requests: runtime.join("meta-discovery-requests.json"),
            family,
            names: BTreeMap::new(),
            updated: false,
            poll_at: Instant::now(),
            request_stamp: 0,
            pending: HashMap::new(),
        })
    }

    pub fn observe(&mut self, hello: &HelloEvent, name: &str, timestamp: u64) {
        if !self.accepts(name) {
            return;
        }
        let kind = match hello.key[37] {
            6 if hello
                .shape
                .is_some_and(|shape| shape != SHAPE_HTTP && !crate::r2o_is_ech_shape(shape)) =>
            {
                "tls-sni"
            }
            17 if hello
                .quic_snapshot
                .as_deref()
                .is_some_and(|snapshot| !crate::r2o_quic_snapshot_has_ech(snapshot)) =>
            {
                "quic-sni"
            }
            _ => return,
        };
        self.note(name, kind, timestamp);
    }

    pub fn observe_dns(&mut self, name: &str, timestamp: u64) {
        if self.accepts(name) {
            self.note(name, "dns", timestamp);
        }
    }

    fn accepts(&self, host: &str) -> bool {
        self.enabled && product(host).is_some_and(|name| !self.disabled_products.contains(&name))
    }

    fn note(&mut self, name: &str, kind: &'static str, timestamp: u64) {
        if self.names.get(name).is_some_and(|&(previous, seen)| {
            previous == kind && timestamp.saturating_sub(seen) < STALE
        }) {
            return;
        }
        if self.names.len() >= CAPACITY
            && !self.names.contains_key(name)
            && let Some((oldest, _)) = self.names.iter().min_by_key(|(_, (_, seen))| *seen)
        {
            let oldest = oldest.clone();
            self.names.remove(&oldest);
        }
        self.names.insert(name.into(), (kind, timestamp));
        self.updated = true;
    }

    fn enabled(&self) -> bool {
        protection_enabled(&self.state)
    }

    pub fn diagnostic_counts(&self) -> (bool, usize, usize) {
        (self.enabled, self.names.len(), self.pending.len())
    }

    pub fn enabled_for(&self, host: &str) -> bool {
        self.enabled()
            && product(host)
                .and_then(|name| product_marker(&self.state, name))
                .is_some_and(|path| !path.exists())
    }

    pub fn poll(&mut self, now: Instant, wall: u64) -> Vec<DiscoveryTarget> {
        if now < self.poll_at {
            return Vec::new();
        }
        self.poll_at = now + POLL_INTERVAL;
        self.enabled = self.enabled();
        if !self.enabled {
            self.names.clear();
            let _ = std::fs::remove_file(&self.observations);
            return Vec::new();
        }
        self.disabled_products = disabled_products(&self.state);
        let before = self.names.len();
        self.names.retain(|host, _| {
            product(host).is_some_and(|name| !self.disabled_products.contains(&name))
        });
        self.updated |= self.names.len() != before;
        if self.updated {
            let rows: Vec<_> = self
                .names
                .iter()
                .map(|(host, (kind, seen))| (host, kind, seen))
                .collect();
            self.updated =
                r2o_controller::live::write_snapshot(&self.observations, &serde_json::json!(rows))
                    .is_err();
        }
        if self.pending.len() >= 4 {
            return Vec::new();
        }
        let mut bytes = Vec::new();
        let Some((stamp, rows)) = std::fs::File::open(&self.requests)
            .ok()
            .and_then(|file| file.take(8193).read_to_end(&mut bytes).ok())
            .filter(|&len| len <= 8192)
            .and_then(|_| serde_json::from_slice::<(u64, Vec<(String, IpAddr)>)>(&bytes).ok())
        else {
            return Vec::new();
        };
        if stamp <= self.request_stamp || stamp > wall || wall - stamp > STALE {
            return Vec::new();
        }
        self.request_stamp = stamp;
        rows.into_iter()
            .filter_map(|(host, ip)| {
                let family = if ip.is_ipv4() { 4 } else { 6 };
                if self.family.is_some_and(|wanted| wanted != family)
                    || !self.accepts(&host)
                    || !self
                        .names
                        .get(&host)
                        .is_some_and(|(_, seen)| wall.saturating_sub(*seen) <= STALE)
                {
                    return None;
                }
                Some(DiscoveryTarget {
                    host,
                    endpoint: SocketAddr::new(ip, 443).to_string(),
                    family,
                    shape: SHAPE_MODERN,
                    tcp_profile: 0,
                })
            })
            .take(4 - self.pending.len())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_handoff_requires_recent_network_observation_and_enabled_state() {
        let path = std::env::temp_dir().join(format!("r2o-meta-handoff-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        let now = Instant::now();
        let mut meta = MetaTraffic {
            state: path.clone(),
            observations: path.join("observations.json"),
            requests: path.join("requests.json"),
            family: Some(6),
            names: BTreeMap::new(),
            updated: false,
            enabled: true,
            disabled_products: Vec::new(),
            poll_at: now,
            request_stamp: 0,
            pending: HashMap::new(),
        };
        assert!(!meta.enabled());
        std::fs::write(path.join("meta-protection.enabled"), b"1\n").unwrap();
        assert!(meta.enabled());
        meta.observe_dns("media-new.whatsapp.net", 1000);
        let requests = serde_json::json!([
            1000,
            [
                ["media-new.whatsapp.net", "2a03:2880::2"],
                ["media-new.whatsapp.net", "157.240.0.2"],
                ["www.facebook.com", "2a03:2880::3"],
                ["whatsapp.net.example.org", "2a03:2880::4"],
            ]
        ]);
        std::fs::write(&meta.requests, requests.to_string()).unwrap();
        let targets = meta.poll(now, 1001);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "media-new.whatsapp.net");
        assert_eq!(targets[0].endpoint, "[2a03:2880::2]:443");
        assert!(meta.poll(now + POLL_INTERVAL, 1020).is_empty());
        std::fs::write(product_marker(&path, "whatsapp").unwrap(), b"0").unwrap();
        assert!(!meta.enabled_for("media-new.whatsapp.net"));
        assert!(meta.enabled_for("www.facebook.com"));
        meta.poll(now + 2 * POLL_INTERVAL, 1030);
        meta.observe_dns("media-new.whatsapp.net", 1031);
        assert!(!meta.names.contains_key("media-new.whatsapp.net"));

        std::fs::write(path.join("meta-protection.disabled"), b"0").unwrap();
        assert!(meta.poll(now + 3 * POLL_INTERVAL, 1045).is_empty());
        assert!(!meta.enabled());
        std::fs::remove_dir_all(path).unwrap();
    }
}
