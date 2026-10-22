//! Ограниченная очередь проверок HTTPS для имён из HTTP-порталов.

use crate::response::{HttpsProbeState, probe_https_state};
use r2k_core::control::{HttpPortalEvent, HttpResponseEvent, KEY_LEN};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const VERIFIED_TTL_SECONDS: u32 = 6 * 60 * 60;
const QUEUE_CAPACITY: usize = 16;
const CACHE_CAPACITY: usize = 128;
const MAX_CACHE_BYTES: u64 = 64 * 1024;

struct Job {
    host: String,
    address: SocketAddr,
}

pub struct HttpsProbeResult {
    pub host: String,
    pub ttl_seconds: u32,
    pub state: HttpsProbeState,
}

pub fn target_from_portal(event: &HttpPortalEvent) -> Option<(String, SocketAddr)> {
    if event.answered {
        return None;
    }
    target_from_http_key(&event.key, &event.host)
}

/// Returns the HTTPS target for an unsolicited HTTP portal observation, which
/// the datapath reports as HTTP_RESPONSE rather than HTTP_PORTAL.
pub fn target_from_http_response(event: &HttpResponseEvent) -> Option<(String, SocketAddr)> {
    if event.code != 3
        || event.trial_id.iter().any(|byte| *byte != 0)
        || u16::from_be_bytes([event.key[35], event.key[36]]) != 80
    {
        return None;
    }
    target_from_http_key(&event.key, &event.host)
}

fn target_from_http_key(key: &[u8; KEY_LEN], host_bytes: &[u8]) -> Option<(String, SocketAddr)> {
    if key[37] != 6 || !matches!(key[0], 4 | 6) {
        return None;
    }
    let host = std::str::from_utf8(host_bytes).ok()?;
    let host = crate::domain::normalize(host).ok()?;
    if r2k_core::control::encode_set_https(&host, 1).is_err() {
        return None;
    }
    let low_port = u16::from_be_bytes([key[33], key[34]]);
    let high_port = u16::from_be_bytes([key[35], key[36]]);
    let address = match (low_port, high_port) {
        (80, 80) => return None,
        (80, _) => &key[1..17],
        (_, 80) => &key[17..33],
        _ => return None,
    };
    let ip = match key[0] {
        4 => IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        )),
        6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(address).ok()?)),
        _ => return None,
    };
    Some((host, SocketAddr::new(ip, 443)))
}

struct CachedResult {
    expires: Instant,
    state: HttpsProbeState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpsCacheFile {
    schema: u8,
    written_at: u64,
    entries: Vec<HttpsCacheEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpsCacheEntry {
    host: String,
    state: HttpsProbeState,
    expires_at: u64,
}

pub struct HttpsProbeWorker {
    jobs: Option<SyncSender<Job>>,
    results: Receiver<HttpsProbeResult>,
    thread: Option<JoinHandle<()>>,
    pending: HashSet<String>,
    cache: HashMap<String, CachedResult>,
}

impl HttpsProbeWorker {
    pub fn new(mark: Option<u32>) -> Self {
        let (jobs, job_queue) = mpsc::sync_channel::<Job>(QUEUE_CAPACITY);
        let (result_sender, results) = mpsc::sync_channel::<HttpsProbeResult>(QUEUE_CAPACITY);
        let thread = thread::Builder::new()
            .name("r2o-проверка-https".into())
            .spawn(move || {
                while let Ok(job) = job_queue.recv() {
                    let state = probe_https_state(&job.host, job.address, mark);
                    let result = HttpsProbeResult {
                        host: job.host,
                        ttl_seconds: if state.should_redirect() {
                            state.ttl_seconds()
                        } else {
                            0
                        },
                        state,
                    };
                    if result_sender.send(result).is_err() {
                        break;
                    }
                }
            })
            .ok();
        Self {
            jobs: thread.as_ref().map(|_| jobs),
            results,
            thread,
            pending: HashSet::new(),
            cache: HashMap::new(),
        }
    }

    pub fn submit(&mut self, host: &str, address: SocketAddr, now: Instant) -> bool {
        let host = host.to_ascii_lowercase();
        if r2k_core::control::encode_set_https(&host, 1).is_err()
            || self.pending.contains(&host)
            || self
                .cache
                .get(&host)
                .is_some_and(|entry| entry.expires > now)
        {
            return false;
        }
        self.cache.remove(&host);
        let Some(jobs) = &self.jobs else {
            return false;
        };
        match jobs.try_send(Job {
            host: host.clone(),
            address,
        }) {
            Ok(()) => {
                self.pending.insert(host);
                true
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }

    pub fn try_result(&mut self) -> Option<HttpsProbeResult> {
        match self.results.try_recv() {
            Ok(result) => {
                self.pending.remove(&result.host);
                self.insert_cache(
                    result.host.clone(),
                    result.state,
                    result.state.ttl_seconds(),
                    Instant::now(),
                );
                Some(result)
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }

    pub fn verified_names(&self, now: Instant) -> impl Iterator<Item = (&str, u32)> {
        self.cache.iter().filter_map(move |(host, entry)| {
            (entry.state.should_redirect() && entry.expires > now).then_some((
                host.as_str(),
                entry.expires.saturating_duration_since(now).as_secs() as u32,
            ))
        })
    }

    pub fn restore_verified(&mut self, host: &str, ttl_seconds: u32, now: Instant) -> bool {
        self.restore_cached(host, HttpsProbeState::Served, ttl_seconds, now)
    }

    pub fn restore_cached(
        &mut self,
        host: &str,
        state: HttpsProbeState,
        ttl_seconds: u32,
        now: Instant,
    ) -> bool {
        let Ok(host) = crate::domain::normalize(host) else {
            return false;
        };
        if ttl_seconds == 0
            || ttl_seconds > state.ttl_seconds()
            || r2k_core::control::encode_set_https(&host, 1).is_err()
        {
            return false;
        }
        self.insert_cache(host, state, ttl_seconds, now);
        true
    }

    fn insert_cache(
        &mut self,
        host: String,
        state: HttpsProbeState,
        ttl_seconds: u32,
        now: Instant,
    ) {
        if !self.cache.contains_key(&host)
            && self.cache.len() >= CACHE_CAPACITY
            && let Some(oldest) = self
                .cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(name, _)| name.clone())
        {
            self.cache.remove(&oldest);
        }
        self.cache.insert(
            host,
            CachedResult {
                expires: now + Duration::from_secs(u64::from(ttl_seconds)),
                state,
            },
        );
    }

    pub fn load_cache(
        path: impl AsRef<Path>,
        wall_now: u64,
    ) -> Result<Vec<(String, HttpsProbeState, u32)>, String> {
        let path = path.as_ref();
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        if bytes.len() as u64 > MAX_CACHE_BYTES {
            return Err("файл кэша HTTPS превышает 64 КиБ".into());
        }
        let file: HttpsCacheFile =
            serde_json::from_slice(&bytes).map_err(|error| format!("кэш HTTPS: {error}"))?;
        if file.schema != 1 || file.entries.len() > CACHE_CAPACITY {
            return Err("неподдерживаемая схема или размер кэша HTTPS".into());
        }
        if file.written_at > wall_now {
            return Ok(Vec::new());
        }
        let mut entries = BTreeMap::new();
        for entry in file.entries {
            let Ok(host) = crate::domain::normalize(&entry.host) else {
                continue;
            };
            if host != entry.host || r2k_core::control::encode_set_https(&host, 1).is_err() {
                continue;
            }
            let ttl = entry
                .expires_at
                .saturating_sub(wall_now)
                .min(u64::from(entry.state.ttl_seconds())) as u32;
            if ttl > 0 {
                entries.insert(host, (entry.state, ttl));
            }
        }
        Ok(entries
            .into_iter()
            .map(|(host, (state, ttl))| (host, state, ttl))
            .collect())
    }

    pub fn load_verified(
        path: impl AsRef<Path>,
        wall_now: u64,
    ) -> Result<Vec<(String, u32)>, String> {
        Ok(Self::load_cache(path, wall_now)?
            .into_iter()
            .filter(|(_, state, _)| state.should_redirect())
            .map(|(host, _, ttl)| (host, ttl))
            .collect())
    }

    pub fn save_cache(
        &self,
        path: impl AsRef<Path>,
        wall_now: u64,
        now: Instant,
    ) -> Result<(), String> {
        let path = path.as_ref();
        let mut entries: Vec<_> = self
            .cache
            .iter()
            .filter_map(|(host, cached)| {
                let ttl = cached.expires.saturating_duration_since(now).as_secs();
                (ttl > 0).then(|| HttpsCacheEntry {
                    host: host.clone(),
                    state: cached.state,
                    expires_at: wall_now
                        .saturating_add(ttl.min(u64::from(cached.state.ttl_seconds()))),
                })
            })
            .collect();
        entries.sort_by(|left, right| left.host.cmp(&right.host));
        let file = HttpsCacheFile {
            schema: 1,
            written_at: wall_now,
            entries,
        };
        let mut bytes = serde_json::to_vec_pretty(&file)
            .map_err(|error| format!("не удалось собрать кэш HTTPS: {error}"))?;
        bytes.push(b'\n');
        let file_name = path
            .file_name()
            .ok_or_else(|| "у кэша HTTPS нет имени файла".to_owned())?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("часы системы: {error}"))?
            .as_nanos();
        let mut temporary_name = file_name.to_os_string();
        temporary_name.push(format!(".new.{}.{}", std::process::id(), nonce));
        let temporary_path: PathBuf = path.with_file_name(temporary_name);
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let result = (|| {
            let mut temporary = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary_path)
                .map_err(|error| format!("{}: {error}", temporary_path.display()))?;
            temporary
                .write_all(&bytes)
                .map_err(|error| format!("не удалось записать кэш HTTPS: {error}"))?;
            temporary
                .sync_all()
                .map_err(|error| format!("не удалось сбросить кэш HTTPS на диск: {error}"))?;
            drop(temporary);
            fs::rename(&temporary_path, path)
                .map_err(|error| format!("не удалось заменить кэш HTTPS: {error}"))?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("не удалось синхронизировать каталог кэша: {error}"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }
}

impl Drop for HttpsProbeWorker {
    fn drop(&mut self) {
        self.jobs.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpsProbeWorker, target_from_http_response, target_from_portal};
    use crate::response::HttpsProbeState;
    use r2k_core::control::{BindingContext, HttpPortalEvent, HttpResponseEvent, KEY_LEN};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    #[test]
    fn portal_probe_uses_the_server_ip_and_exact_normalized_host() {
        let mut key = [0; r2k_core::control::KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 1]);
        key[17..21].copy_from_slice(&[198, 51, 100, 2]);
        key[33..35].copy_from_slice(&40_123_u16.to_be_bytes());
        key[35..37].copy_from_slice(&80_u16.to_be_bytes());
        key[37] = 6;
        let event = HttpPortalEvent {
            key,
            answered: false,
            host: b"Example.test".to_vec(),
        };

        assert_eq!(
            target_from_portal(&event),
            Some((
                "example.test".to_owned(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 443),
            ))
        );
    }

    fn portal_response() -> HttpResponseEvent {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 1]);
        key[17..21].copy_from_slice(&[198, 51, 100, 2]);
        key[33..35].copy_from_slice(&40_123_u16.to_be_bytes());
        key[35..37].copy_from_slice(&80_u16.to_be_bytes());
        key[37] = 6;
        HttpResponseEvent {
            key,
            code: 3,
            host: b"Example.test".to_vec(),
            execution_id: 0,
            plan_id: [0; 16],
            trial_id: [0; 16],
            request_ms: 0,
            path: b"/blocked".to_vec(),
            binding: BindingContext {
                generation: 0,
                kind: 0,
                family: 0,
                shape: 0,
                temporary: false,
                epoch: [0; 16],
            },
            status: 302,
            body_bytes: 0,
            request_no: 1,
        }
    }

    #[test]
    fn late_portal_response_starts_https_probe_without_trial() {
        let response = portal_response();
        assert_eq!(
            target_from_http_response(&response),
            Some((
                "example.test".to_owned(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 443),
            ))
        );
    }

    #[test]
    fn only_unowned_http_portal_responses_start_https_probe() {
        let mut response = portal_response();
        response.trial_id[0] = 1;
        assert_eq!(target_from_http_response(&response), None);

        let mut response = portal_response();
        response.code = 1;
        assert_eq!(target_from_http_response(&response), None);

        let mut response = portal_response();
        response.key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        assert_eq!(target_from_http_response(&response), None);

        let mut response = portal_response();
        response.key[33..35].copy_from_slice(&80_u16.to_be_bytes());
        response.key[35..37].copy_from_slice(&40_123_u16.to_be_bytes());
        assert_eq!(target_from_http_response(&response), None);
    }

    #[test]
    fn https_cache_round_trip_keeps_only_the_remaining_positive_ttl() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-https-cache-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("cache.json");
        let now = Instant::now();
        let mut worker = HttpsProbeWorker::new(None);

        assert!(worker.restore_verified("Example.Test", 3600, now));
        worker.save_cache(&path, 1000, now).unwrap();

        let loaded = HttpsProbeWorker::load_verified(&path, 1100).unwrap();
        assert_eq!(loaded, vec![("example.test".to_owned(), 3500)]);
        assert!(
            HttpsProbeWorker::load_verified(&path, 4700)
                .unwrap()
                .is_empty()
        );
        assert!(
            HttpsProbeWorker::load_verified(&path, 999)
                .unwrap()
                .is_empty()
        );

        drop(worker);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn https_cache_persists_negative_states_with_their_shorter_ttl() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "r2o-https-cache-negative-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("cache.json");
        let now = Instant::now();
        let mut worker = HttpsProbeWorker::new(None);

        assert!(worker.restore_cached("closed.test", HttpsProbeState::Closed, 1800, now));
        assert!(!worker.restore_cached("late.test", HttpsProbeState::Closed, 1801, now));
        worker.save_cache(&path, 2000, now).unwrap();

        assert_eq!(
            HttpsProbeWorker::load_cache(&path, 2000).unwrap(),
            vec![("closed.test".to_owned(), HttpsProbeState::Closed, 1800)]
        );
        assert!(
            HttpsProbeWorker::load_verified(&path, 2000)
                .unwrap()
                .is_empty()
        );

        drop(worker);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
