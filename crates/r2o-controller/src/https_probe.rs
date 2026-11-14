//! Ограниченная очередь проверок HTTPS для имён из HTTP-порталов.

use crate::response::{HttpsProbeState, probe_https_state};
use r2k_core::control::{HttpPortalEvent, HttpResponseEvent, KEY_LEN};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const VERIFIED_TTL_SECONDS: u32 = 6 * 60 * 60;
const QUEUE_CAPACITY: usize = 16;
const CACHE_CAPACITY: usize = 128;
const HTTPS_PROBE_IDLE: Duration = Duration::from_secs(10);
/// C `cache_put(PROBING, now + PROBE_MS * 4)`: имя можно перепроверить после
/// 10 секунд, даже если результат потерялся в полном `done[]`.
const HTTPS_PROBING_TTL: Duration = Duration::from_secs(10);

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
    host: String,
    expires: Instant,
    /// Момент последней записи — по нему C `cache_put` выбирает жертву.
    stamp: Instant,
    state: HttpsProbeState,
}

/// Проверка имени из кэша — побайтный перенос C `host_ok`: только ASCII
/// буквы, цифры, дефис и точка, длина 1..=253.
fn cache_host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

fn cache_find(cache: &[CachedResult], host: &str) -> Option<usize> {
    cache
        .iter()
        .position(|entry| entry.host.eq_ignore_ascii_case(host))
}

/// Разобрать десятичное целое так же строго, как `%lld`: необязательный
/// знак и цифры до конца токена.
fn parse_signed_decimal(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let (negative, digits) = match bytes.first() {
        Some(b'-') => (true, &bytes[1..]),
        Some(b'+') => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let digits = std::str::from_utf8(digits).ok()?;
    let magnitude = digits.parse::<i128>().ok()?;
    let value = if negative { -magnitude } else { magnitude };
    i64::try_from(value).ok()
}

/// C `mono_ms`: монотонные миллисекунды пробы HTTPS.
pub fn mono_ms() -> i64 {
    use std::sync::OnceLock;

    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_millis().min(i64::MAX as u128) as i64
}

/// C `worker`: результат кладётся в `done[]`; при переполнении `lost++` и
/// воркер продолжает, а не блокируется на полном потребителе.
fn deliver_result(
    sender: &SyncSender<HttpsProbeResult>,
    wake_write: &Option<UnixStream>,
    result: HttpsProbeResult,
    lost: &AtomicU64,
) -> bool {
    match sender.try_send(result) {
        Ok(()) => {
            if let Some(wake) = wake_write.as_ref() {
                let _ = (&*wake).write(b"x");
            }
            true
        }
        Err(TrySendError::Full(_)) => {
            lost.fetch_add(1, Ordering::Relaxed);
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

pub struct HttpsProbeWorker {
    jobs: Option<SyncSender<Job>>,
    result_sender: SyncSender<HttpsProbeResult>,
    results: Receiver<HttpsProbeResult>,
    /// C `wake[0]`: pollable read-end, воркер пишет байт после результата.
    wake_read: Option<UnixStream>,
    /// C `wake[1]`: write-end (nonblock), клон уходит в поток.
    wake_write: Option<UnixStream>,
    mark: Option<u32>,
    thread: Option<JoinHandle<()>>,
    /// C `PROBING`-запись: имя и момент постановки; по TTL снимается.
    pending: HashMap<String, Instant>,
    /// C `d2k_httpsprobe.lost`: результаты, не влезшие в `done[17]`.
    /// Заполненная очередь заданий, наоборот, просто не принимает новое имя.
    lost: Arc<AtomicU64>,
    /// Слоты кэша в порядке C-массива: загрузка и сохранение обязаны давать
    /// тот же файл, что `d2k_httpsprobe_load/save`.
    cache: Vec<CachedResult>,
}

/// C `d2k_httpsprobe_portal`: rc=2 (resend), 1 (queued) или 0 (busy).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsPortalOutcome {
    Resend { ttl_seconds: u32 },
    Queued,
    Busy,
}

impl HttpsProbeWorker {
    pub fn new(mark: Option<u32>) -> Self {
        // C `done[D2K_HTTPSPROBE_JOBS + 1]`: на один готовый результат больше
        // числа заданий.
        let (result_sender, results) = mpsc::sync_channel::<HttpsProbeResult>(QUEUE_CAPACITY + 1);
        // C `wake`: неблокирующая пара; ошибка pipe → wake=-1, new→NULL.
        // В Rust нет NULL-контракта: при ошибке wake_fd() отдаёт -1.
        let (wake_read, wake_write) = match UnixStream::pair() {
            Ok((read, write)) => {
                let _ = read.set_nonblocking(true);
                let _ = write.set_nonblocking(true);
                (Some(read), Some(write))
            }
            Err(_) => (None, None),
        };
        let mut worker = Self {
            jobs: None,
            result_sender,
            results,
            wake_read,
            wake_write,
            mark,
            thread: None,
            pending: HashMap::new(),
            lost: Arc::new(AtomicU64::new(0)),
            cache: Vec::new(),
        };
        worker.r2o_ensure_worker();
        worker
    }

    /// C `d2k_httpsprobe_wake_fd`: pollable read-end или -1.
    pub fn wake_fd(&self) -> i32 {
        self.wake_read
            .as_ref()
            .map_or(-1, |stream| stream.as_raw_fd())
    }

    fn drain_wake(&self) {
        let Some(stream) = self.wake_read.as_ref() else {
            return;
        };
        let mut buffer = [0_u8; 64];
        loop {
            let read =
                unsafe { libc::read(stream.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            if read <= 0 {
                break;
            }
        }
    }

    fn r2o_ensure_worker(&mut self) {
        if self
            .thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
        {
            return;
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let (jobs, job_queue) = mpsc::sync_channel::<Job>(QUEUE_CAPACITY);
        let result_sender = self.result_sender.clone();
        let mut wake_write = self
            .wake_write
            .as_ref()
            .and_then(|stream| stream.try_clone().ok());
        let mark = self.mark;
        let lost = Arc::clone(&self.lost);
        let thread = thread::Builder::new()
            .name("r2o-проверка-https".into())
            .spawn(move || {
                loop {
                    let job = match job_queue.recv_timeout(HTTPS_PROBE_IDLE) {
                        Ok(job) => job,
                        Err(mpsc::RecvTimeoutError::Timeout)
                        | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
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
                    if !deliver_result(&result_sender, &wake_write, result, &lost) {
                        break;
                    }
                }
            })
            .ok();
        self.jobs = thread.as_ref().map(|_| jobs);
        self.thread = thread;
    }

    fn expire_pending(&mut self, now: Instant) {
        self.pending
            .retain(|_, started| now.saturating_duration_since(*started) < HTTPS_PROBING_TTL);
    }

    pub fn submit(&mut self, host: &str, address: SocketAddr, now: Instant) -> bool {
        let host = host.to_ascii_lowercase();
        self.expire_pending(now);
        if !cache_host_ok(&host)
            || self.pending.contains_key(&host)
            || cache_find(&self.cache, &host).is_some_and(|index| self.cache[index].expires > now)
        {
            return false;
        }
        self.r2o_ensure_worker();
        let Some(jobs) = self.jobs.clone() else {
            return false;
        };
        let job = Job {
            host: host.clone(),
            address,
        };
        match jobs.try_send(job) {
            Ok(()) => {
                self.pending.insert(host, now);
                true
            }
            Err(TrySendError::Full(_)) => {
                // C `d2k_httpsprobe_portal`: полная очередь заданий просто
                // возвращает 0, не увеличивая `lost`.
                false
            }
            Err(TrySendError::Disconnected(job)) => {
                self.r2o_ensure_worker();
                let Some(jobs) = self.jobs.clone() else {
                    return false;
                };
                if jobs.try_send(job).is_ok() {
                    self.pending.insert(host, now);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// C `d2k_httpsprobe_portal`: результат постановки/повтора.
    pub fn portal(
        &mut self,
        host: &str,
        address: SocketAddr,
        answered: bool,
        now: Instant,
    ) -> HttpsPortalOutcome {
        let host = host.to_ascii_lowercase();
        if !cache_host_ok(&host) {
            return HttpsPortalOutcome::Busy;
        }
        if let Some(index) = cache_find(&self.cache, &host) {
            let entry = &self.cache[index];
            if entry.expires > now {
                if entry.state.should_redirect() && !answered {
                    let left = (entry.expires - now).as_secs().min(u64::from(u32::MAX)) as u32;
                    if left > 0 {
                        return HttpsPortalOutcome::Resend { ttl_seconds: left };
                    }
                }
                return HttpsPortalOutcome::Busy;
            }
        }
        if self.submit(&host, address, now) {
            HttpsPortalOutcome::Queued
        } else {
            HttpsPortalOutcome::Busy
        }
    }

    /// C `d2k_httpsprobe_lost`: число запросов, потерянных при полной очереди.
    pub fn lost(&self) -> u64 {
        self.lost.load(Ordering::Relaxed)
    }

    pub fn cached_state(&self, host: &str, now: Instant) -> Option<HttpsProbeState> {
        let index = cache_find(&self.cache, host)?;
        let entry = &self.cache[index];
        (entry.expires > now).then_some(entry.state)
    }

    pub fn is_pending(&self, host: &str) -> bool {
        self.pending
            .get(&host.to_ascii_lowercase())
            .is_some_and(|started| started.elapsed() < HTTPS_PROBING_TTL)
    }

    pub fn try_result(&mut self) -> Option<HttpsProbeResult> {
        // C `d2k_httpsprobe_done`: сначала осушить pipe пробуждения.
        self.drain_wake();
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
        self.cache.iter().filter_map(move |entry| {
            (entry.state.should_redirect() && entry.expires > now).then_some((
                entry.host.as_str(),
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
        if ttl_seconds == 0 || ttl_seconds > state.ttl_seconds() || !cache_host_ok(host) {
            return false;
        }
        self.insert_cache(host.to_owned(), state, ttl_seconds, now);
        true
    }

    fn insert_cache(
        &mut self,
        host: String,
        state: HttpsProbeState,
        ttl_seconds: u32,
        now: Instant,
    ) {
        let expires = now + Duration::from_secs(u64::from(ttl_seconds));
        if let Some(index) = cache_find(&self.cache, &host) {
            let entry = &mut self.cache[index];
            entry.state = state;
            entry.stamp = now;
            entry.expires = expires;
            return;
        }
        if self.cache.len() < CACHE_CAPACITY {
            self.cache.push(CachedResult {
                host,
                expires,
                stamp: now,
                state,
            });
            return;
        }
        // Как C `cache_put`: жертва — самая давняя запись; при равных
        // отметках сохраняется порядок слотов.
        let victim = self
            .cache
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.stamp)
            .map(|(index, _)| index)
            .unwrap_or(0);
        self.cache[victim] = CachedResult {
            host,
            expires,
            stamp: now,
            state,
        };
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
        let mut lines = bytes.split_inclusive(|byte| *byte == b'\n');
        let header_bytes = lines
            .next()
            .ok_or_else(|| format!("{}: пустой кэш HTTPS", path.display()))?;
        let header = std::str::from_utf8(header_bytes)
            .map_err(|_| format!("{}: не кэш HTTPS d2k", path.display()))?;
        let written = if header == "d2k-https 1\n" {
            None
        } else if let Some(rest) = header.strip_prefix("d2k-https 2 ") {
            let number = rest
                .strip_suffix('\n')
                .ok_or_else(|| format!("{}: не кэш HTTPS d2k", path.display()))?;
            let value = parse_signed_decimal(number)
                .filter(|value| *value >= 0)
                .ok_or_else(|| format!("{}: не кэш HTTPS d2k", path.display()))?;
            Some(value)
        } else {
            return Err(format!("{}: не кэш HTTPS d2k", path.display()));
        };
        // Файл записан позже, чем «сейчас»: часы отстают. Не оживляем.
        if written.is_some_and(|written| written > wall_now as i64) {
            return Ok(Vec::new());
        }
        let wall_now = wall_now as i64;
        let mut entries = Vec::new();
        for line_bytes in lines {
            let Ok(line) = std::str::from_utf8(line_bytes) else {
                continue;
            };
            let line = line.strip_suffix('\n').unwrap_or(line);
            let mut fields = line.split_ascii_whitespace();
            let (Some(state_name), Some(expires_text), Some(host)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if fields.next().is_some()
                || state_name.len() > 31
                || host.len() > 299
                || !cache_host_ok(host)
            {
                continue;
            }
            let Some(expires) = parse_signed_decimal(expires_text) else {
                continue;
            };
            let Some(state) = HttpsProbeState::from_stored_name(state_name) else {
                continue;
            };
            if expires <= wall_now {
                continue;
            }
            let ttl = (expires - wall_now).min(i64::from(state.ttl_seconds())) as u32;
            entries.push((host.to_owned(), state, ttl));
        }
        Ok(entries)
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
        let mut bytes = format!("d2k-https 2 {wall_now}\n").into_bytes();
        for cached in &self.cache {
            let ttl = cached.expires.saturating_duration_since(now).as_secs();
            if ttl == 0 {
                continue;
            }
            bytes.extend_from_slice(
                format!(
                    "{} {} {}\n",
                    cached.state.stored_name(),
                    wall_now.saturating_add(ttl),
                    cached.host
                )
                .as_bytes(),
            );
        }
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
        // Разорвать канал результатов до join: иначе воркер, заблокированный
        // на send при полном канале, не даст Drop завершиться.
        let (_, closed) = mpsc::sync_channel(0);
        let results = std::mem::replace(&mut self.results, closed);
        drop(results);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HttpsPortalOutcome, HttpsProbeWorker, cache_host_ok, target_from_http_response,
        target_from_portal,
    };
    use crate::response::{
        HTTPS_CONNECTED, HTTPS_NO_ANSWER, HTTPS_REFUSED, HttpsProbeState, classify_https_probe,
    };
    use r2k_core::control::{BindingContext, HttpPortalEvent, HttpResponseEvent, KEY_LEN};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn mono_ms_is_monotonic_like_c() {
        let first = super::mono_ms();
        assert!(first >= 0);
        std::thread::sleep(Duration::from_millis(2));
        let second = super::mono_ms();
        assert!(second > first);
    }

    #[test]
    fn cache_host_ok_matches_c() {
        // C `host_ok`: 1..253 и только `[A-Za-z0-9.-]`; структура меток,
        // дефисы и цифровая последняя метка не проверяются.
        for accepted in [
            "example.com",
            "EXAMPLE.COM",
            "-",
            ".",
            "..",
            "--..--",
            "127.0.0.1",
            "a-b.c",
        ] {
            assert!(cache_host_ok(accepted), "rejected {accepted:?}");
        }
        for rejected in ["", "a_b.com", "a b.com", "a/b.com", "é.example", "a\tb"] {
            assert!(!cache_host_ok(rejected), "accepted {rejected:?}");
        }
        assert!(cache_host_ok(&"a".repeat(253)));
        assert!(!cache_host_ok(&"a".repeat(254)));
    }

    #[test]
    fn cached_state_and_pending_lookup_follow_host_and_expiry() {
        let now = Instant::now();
        let mut worker = HttpsProbeWorker::new(None);
        worker.cache.push(super::CachedResult {
            host: "example.com".into(),
            expires: now + Duration::from_secs(30),
            stamp: now,
            state: HttpsProbeState::Served,
        });
        worker.pending.insert("pending.example".into(), now);

        assert_eq!(
            worker.cached_state("EXAMPLE.COM", now),
            Some(HttpsProbeState::Served)
        );
        assert_eq!(
            worker.cached_state("example.com", now + Duration::from_secs(30)),
            None
        );
        assert!(worker.is_pending("PENDING.EXAMPLE"));
        assert!(!worker.is_pending("missing.example"));
        worker
            .pending
            .insert("stale.example".into(), now - super::HTTPS_PROBING_TTL);
        assert!(!worker.is_pending("stale.example"));
    }

    #[test]
    fn classify_matches_d2o_https_state_machine() {
        assert_eq!(
            classify_https_probe(HTTPS_REFUSED, true, true, 1),
            HttpsProbeState::Closed
        );
        assert_eq!(
            classify_https_probe(HTTPS_NO_ANSWER, true, true, 1),
            HttpsProbeState::Unconfirmed
        );
        assert_eq!(
            classify_https_probe(HTTPS_CONNECTED, false, false, -1),
            HttpsProbeState::TlsBlocked
        );
        assert_eq!(
            classify_https_probe(HTTPS_CONNECTED, true, false, -1),
            HttpsProbeState::Unconfirmed
        );
        assert_eq!(
            classify_https_probe(HTTPS_CONNECTED, true, true, 1),
            HttpsProbeState::Served
        );
        assert_eq!(
            classify_https_probe(HTTPS_CONNECTED, true, true, 0),
            HttpsProbeState::OtherName
        );
        assert_eq!(
            classify_https_probe(HTTPS_CONNECTED, true, true, -1),
            HttpsProbeState::Unconfirmed
        );
    }

    #[test]
    fn https_cache_reads_d2o_text_format_and_skips_bad_lines() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "r2o-https-text-cache-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("cache.txt");
        std::fs::write(
            &path,
            "d2k-https 1\n\
             served 1700003600 Example.Test\n\
             probing 1700003600 skipped.test\n\
             served 1700003600 bad_host\n\
             closed 1699999999 expired.test\n\
             served 1700003600 extra.test tail\n",
        )
        .unwrap();
        assert_eq!(
            HttpsProbeWorker::load_cache(&path, 1_700_000_000).unwrap(),
            vec![("Example.Test".to_owned(), HttpsProbeState::Served, 3600)]
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

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

    #[test]
    fn httpsprobe_portal_cached_upgrade_resends_like_c() {
        let now = Instant::now();
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let mut worker = HttpsProbeWorker::new(None);
        worker.insert_cache(
            "served.example".into(),
            HttpsProbeState::Served,
            6 * 60 * 60,
            now,
        );
        // C rc=2: upgrade-кэш и ответа клиенту не было — остаток TTL.
        assert_eq!(
            worker.portal("SERVED.example", address, false, now),
            HttpsPortalOutcome::Resend {
                ttl_seconds: 6 * 60 * 60
            }
        );
        // answered=true — не resend; кэш непустой, постановка не нужна.
        assert_eq!(
            worker.portal("served.example", address, true, now),
            HttpsPortalOutcome::Busy
        );

        worker.insert_cache(
            "closed.example".into(),
            HttpsProbeState::Closed,
            30 * 60,
            now,
        );
        assert_eq!(
            worker.portal("closed.example", address, false, now),
            HttpsPortalOutcome::Busy
        );
        assert_eq!(
            worker.portal("bad_host", address, false, now),
            HttpsPortalOutcome::Busy
        );
    }

    #[test]
    fn httpsprobe_portal_queues_uncached_and_rejects_pending_like_c() {
        // Порт 1 на loopback заведомо закрыт: проба завершится быстро.
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let now = Instant::now();
        let mut worker = HttpsProbeWorker::new(None);
        assert_eq!(
            worker.portal("queue.example", address, false, now),
            HttpsPortalOutcome::Queued
        );
        assert!(worker.is_pending("queue.example"));
        assert_eq!(
            worker.portal("queue.example", address, false, now),
            HttpsPortalOutcome::Busy
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
        let path = directory.join("cache.txt");
        let now = Instant::now();
        let mut worker = HttpsProbeWorker::new(None);

        assert!(worker.restore_verified("Example.Test", 3600, now));
        worker.save_cache(&path, 1000, now).unwrap();

        let loaded = HttpsProbeWorker::load_verified(&path, 1100).unwrap();
        assert_eq!(loaded, vec![("Example.Test".to_owned(), 3500)]);
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
        let path = directory.join("cache.txt");
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

    #[test]
    fn idle_https_probe_worker_exits_and_restarts() {
        let mut worker = HttpsProbeWorker::new(None);
        let deadline = Instant::now() + Duration::from_secs(13);
        while worker
            .thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
        {
            assert!(
                Instant::now() < deadline,
                "HTTPS probe worker не завершился по idle-timeout"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            worker
                .thread
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
        );
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        assert!(worker.submit("idle-https.example", address, Instant::now()));
        assert!(
            worker
                .thread
                .as_ref()
                .is_some_and(|thread| !thread.is_finished()),
            "submit обязан поднять новый HTTPS probe worker"
        );
    }

    #[test]
    fn httpsprobe_drop_unblocks_full_results_channel_like_c_free() {
        let (result_sender, results) = mpsc::sync_channel::<super::HttpsProbeResult>(1);
        result_sender
            .send(super::HttpsProbeResult {
                host: "prefill.example".into(),
                ttl_seconds: 0,
                state: HttpsProbeState::Closed,
            })
            .unwrap();
        let thread_sender = result_sender.clone();
        let (jobs, _job_receiver) = mpsc::sync_channel::<super::Job>(1);
        let (release, wait) = mpsc::channel::<()>();
        let (worker_done, worker_finished) = mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let _ = wait.recv();
            // Канал результатов полон: send блокируется, пока Drop не
            // разорвёт receiver (C free сначала останавливает поток).
            let _ = thread_sender.send(super::HttpsProbeResult {
                host: "blocked.example".into(),
                ttl_seconds: 0,
                state: HttpsProbeState::Closed,
            });
            let _ = worker_done.send(());
        });
        let worker = HttpsProbeWorker {
            jobs: Some(jobs),
            result_sender,
            results,
            wake_read: None,
            wake_write: None,
            mark: None,
            thread: Some(thread),
            pending: std::collections::HashMap::new(),
            lost: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cache: Vec::new(),
        };
        release.send(()).unwrap();
        let (dropped, drop_done) = mpsc::channel::<()>();
        let dropper = std::thread::spawn(move || {
            drop(worker);
            let _ = dropped.send(());
        });
        drop_done
            .recv_timeout(Duration::from_secs(2))
            .expect("Drop завис на полном канале результатов");
        dropper.join().unwrap();
        worker_finished
            .recv_timeout(Duration::from_secs(2))
            .expect("воркер не разблокировался после Drop");
    }

    #[test]
    fn httpsprobe_wake_fd_signals_a_ready_result_like_c() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let mut worker = HttpsProbeWorker::new(None);
        let fd = worker.wake_fd();
        assert!(fd >= 0);
        assert!(worker.submit("wake.example", address, Instant::now()));

        let started = Instant::now();
        loop {
            let mut descriptor = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, 50) };
            if ready > 0 && descriptor.revents & libc::POLLIN != 0 {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "wake-fd не стал читаемым после результата"
            );
        }
        assert!(worker.try_result().is_some());
        // C `d2k_httpsprobe_done` осушает pipe — после try_result fd не читаем.
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 0) }, 0);
    }

    #[test]
    fn full_job_queue_is_busy_but_not_lost_like_c_portal() {
        let address: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let (jobs, _receiver) = std::sync::mpsc::sync_channel(1);
        jobs.try_send(super::Job {
            host: "queued.example".into(),
            address,
        })
        .unwrap();
        let (result_sender, results) = std::sync::mpsc::sync_channel(1);
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let _ = wait.recv();
        });
        let mut worker = HttpsProbeWorker {
            jobs: Some(jobs),
            result_sender,
            results,
            wake_read: None,
            wake_write: None,
            mark: None,
            thread: Some(thread),
            pending: std::collections::HashMap::new(),
            lost: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cache: Vec::new(),
        };
        assert!(!worker.submit("busy.example", address, Instant::now()));
        // C `d2k_httpsprobe_portal` при полной очереди заданий возвращает 0
        // и не трогает `lost`.
        assert_eq!(worker.lost(), 0);
        release.send(()).unwrap();
        drop(worker);
    }

    #[test]
    fn lost_counts_results_that_do_not_fit_the_done_buffer() {
        let (sender, receiver) = mpsc::sync_channel::<super::HttpsProbeResult>(1);
        sender
            .send(super::HttpsProbeResult {
                host: "prefill.example".into(),
                ttl_seconds: 0,
                state: HttpsProbeState::Closed,
            })
            .unwrap();
        let lost = std::sync::atomic::AtomicU64::new(0);
        assert!(super::deliver_result(
            &sender,
            &None,
            super::HttpsProbeResult {
                host: "dropped.example".into(),
                ttl_seconds: 0,
                state: HttpsProbeState::Closed,
            },
            &lost,
        ));
        assert_eq!(lost.load(std::sync::atomic::Ordering::Relaxed), 1);
        drop(receiver);
    }
}
