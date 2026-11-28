//! Publish host records through the directory mounted by OpenWrt's dnsmasq service.

use super::{PinPair, atomic_write_with_mode, dnsmasq_section, is_managed_host, read_manifest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HOSTS_DIR: &str = "/tmp/hosts";
const HEADER: &str = "# R2O Meta Protection";
const DHCP_CONFIG: &str = "/etc/config/dhcp";
const DHCP_DELTA: &str = "/tmp/.uci/dhcp";
const STATE_LIMIT: usize = 64 * 1024;
const INSTANCE_LIMIT: usize = 64;
const RETRY_INITIAL: u64 = 60;
const RETRY_MAX: u64 = 3600;
const NOTIFY_BUDGET: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Instance {
    name: String,
    pid: u32,
    config: PathBuf,
}

impl Instance {
    fn same_process(&self, other: &Self) -> bool {
        self.name == other.name && self.pid == other.pid
    }
}

#[derive(Default)]
struct Instances {
    running: Vec<Instance>,
    eligible: Vec<Instance>,
}

trait Runtime {
    fn snapshot(&mut self) -> Result<Instances, String>;
    fn signal(&mut self, instance: &Instance) -> Result<(), String>;
}

struct SystemRuntime;

impl Runtime for SystemRuntime {
    fn snapshot(&mut self) -> Result<Instances, String> {
        let service = ubus("list", json!({"name": "dnsmasq", "verbose": true}))?;
        inspect_instances(&service, HOSTS_DIR, read_instance_config)
    }

    fn signal(&mut self, instance: &Instance) -> Result<(), String> {
        // Recheck the PID immediately before asking procd to signal by name.
        // A replacement process reads the current file at startup and receives
        // its own acknowledgment on the next pass.
        let current = self.snapshot()?;
        if !current.eligible.contains(instance) {
            return Err("экземпляр dnsmasq изменился до применения Meta DNS".into());
        }
        ubus(
            "signal",
            json!({"name": "dnsmasq", "instance": instance.name, "signal": libc::SIGHUP}),
        )?;
        Ok(())
    }
}

#[derive(Default, Deserialize, Serialize)]
struct Notification {
    version: u8,
    generation: String,
    previous: Vec<Instance>,
    acknowledged: Vec<Instance>,
    failures: u32,
    retry_at: u64,
    #[serde(default)]
    untracked_previous: bool,
}

fn wall_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generation(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

fn read_notification(path: &Path) -> Result<Option<Notification>, String> {
    let Some(body) = read_regular(path, STATE_LIMIT)? else {
        return Ok(None);
    };
    // Older releases used an empty marker with no per-instance state.
    if body.is_empty() {
        return Ok(Some(Notification::default()));
    }
    let state: Notification = serde_json::from_str(&body)
        .map_err(|error| format!("повреждён журнал применения Meta DNS: {error}"))?;
    let valid_instance = |instance: &Instance| {
        !instance.name.is_empty()
            && instance.name.len() <= 128
            && instance.pid != 0
            && instance.pid <= i32::MAX as u32
            && instance.config.as_os_str().len() <= 1024
    };
    if state.version != 1
        || state.generation.len() != 64
        || !state
            .generation
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || state.previous.len() > INSTANCE_LIMIT
        || state.acknowledged.len() > INSTANCE_LIMIT
        || !state.previous.iter().all(valid_instance)
        || !state.acknowledged.iter().all(valid_instance)
    {
        return Err("неподдерживаемый журнал применения Meta DNS".into());
    }
    Ok(Some(state))
}

fn read_regular(path: &Path, limit: usize) -> Result<Option<String>, String> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("не удалось открыть {}: {error}", path.display())),
    };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(format!("неподдерживаемый файл {}", path.display()));
    }
    let mut body = String::new();
    file.take(limit as u64 + 1)
        .read_to_string(&mut body)
        .map_err(|error| format!("не удалось прочитать {}: {error}", path.display()))?;
    if body.len() > limit {
        return Err(format!("слишком большой файл {}", path.display()));
    }
    Ok(Some(body))
}

pub(super) struct DnsmasqHosts {
    path: PathBuf,
}

impl Default for DnsmasqHosts {
    fn default() -> Self {
        Self {
            path: Path::new(HOSTS_DIR).join("r2o-meta"),
        }
    }
}

impl DnsmasqHosts {
    fn contents(&self) -> Result<Option<String>, String> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;

        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "не удалось открыть {}: {error}",
                    self.path.display()
                ));
            }
        };
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.len() > 256 * 1024 {
            return Err(format!("неподдерживаемый файл {}", self.path.display()));
        }
        let mut body = String::new();
        match file.take(256 * 1024 + 1).read_to_string(&mut body) {
            Ok(size) if size <= 256 * 1024 && body.lines().next() == Some(HEADER) => Ok(Some(body)),
            Ok(_) => Err(format!("файл {} не принадлежит R2O", self.path.display())),
            Err(error) => Err(format!(
                "не удалось прочитать {}: {error}",
                self.path.display()
            )),
        }
    }

    pub(super) fn records(&self) -> Result<Vec<(String, IpAddr)>, String> {
        let Some(body) = self.contents()? else {
            return Ok(Vec::new());
        };
        Ok(body
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_ascii_whitespace();
                let (Some(address), Some(host), None) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    return None;
                };
                if !is_managed_host(host) {
                    return None;
                }
                Some((host.to_owned(), address.parse().ok()?))
            })
            .collect())
    }

    pub(super) fn needs_refresh(&self) -> bool {
        !self.path.is_file() && Path::new(HOSTS_DIR).is_dir()
    }

    fn notification(&self) -> PathBuf {
        self.path.with_file_name(".r2o-meta.notify")
    }

    fn applied(&self) -> PathBuf {
        self.path.with_file_name(".r2o-meta.applied")
    }

    pub(super) fn notification_pending(&self) -> bool {
        self.notification().is_file()
    }

    pub(super) fn resume(&self) -> Result<(), String> {
        self.resume_with(wall_time(), &mut SystemRuntime)
    }

    fn resume_with(&self, now: u64, runtime: &mut impl Runtime) -> Result<(), String> {
        let deadline = Instant::now() + NOTIFY_BUDGET;
        let Some(mut state) = read_notification(&self.notification())? else {
            return Ok(());
        };
        let body = self.contents()?.unwrap_or_else(|| format!("{HEADER}\n"));
        let current = generation(&body);
        if state.generation != current {
            // Covers an old empty marker and a crash before the hosts rename.
            state = self.prepare_notification(&body, body.lines().count() <= 1)?;
        }
        if now < state.retry_at && state.retry_at - now <= RETRY_MAX {
            return Err("применение Meta DNS отложено после ошибки dnsmasq".into());
        }
        let instances = match runtime.snapshot() {
            Ok(instances) => instances,
            Err(error) => return self.defer(&mut state, now, error),
        };
        self.notify(state, instances, now, runtime, deadline)
    }

    #[cfg(test)]
    fn test_staging_path(&self) -> std::path::PathBuf {
        self.path.with_file_name(".r2o-meta.tmp.abandoned")
    }

    pub(super) fn publish(&self, pairs: &BTreeSet<PinPair>) -> Result<(), String> {
        self.publish_with(pairs, wall_time(), &mut SystemRuntime)
    }

    fn publish_with(
        &self,
        pairs: &BTreeSet<PinPair>,
        now: u64,
        runtime: &mut impl Runtime,
    ) -> Result<(), String> {
        let deadline = Instant::now() + NOTIFY_BUDGET;
        let mut body = format!("{HEADER}\n");
        for (host, address) in pairs {
            if !is_managed_host(host) || address.parse::<IpAddr>().is_err() {
                return Err("недопустимая запись в файле Meta DNS".into());
            }
            body.push_str(&format!("{address} {host}\n"));
        }
        if body.len() > 256 * 1024 {
            return Err("превышен предел размера файла Meta DNS".into());
        }
        let previous = self.contents()?;
        if previous.is_none()
            && pairs.is_empty()
            && !self.notification_pending()
            && !self.applied().exists()
        {
            return Ok(());
        }
        let changed = previous.as_deref() != Some(&body);
        if !changed {
            return self.resume_with(now, runtime);
        }
        let instances = match runtime.snapshot() {
            Ok(instances) => instances,
            Err(error) if pairs.is_empty() => {
                // Remove the persisted overrides even during a procd outage.
                let mut state = self.prepare_notification(&body, true)?;
                write_hosts(&self.path, body.as_bytes())?;
                return self.defer(&mut state, now, error);
            }
            Err(error) => return Err(error),
        };
        if instances.eligible.is_empty() && !pairs.is_empty() {
            return Err("dnsmasq не запущен с доступным каталогом /tmp/hosts".into());
        }
        let state = self.prepare_notification(&body, pairs.is_empty())?;
        write_hosts(&self.path, body.as_bytes())?;
        if now < state.retry_at && state.retry_at - now <= RETRY_MAX {
            return Err("применение Meta DNS отложено после ошибки dnsmasq".into());
        }
        self.notify(state, instances, now, runtime, deadline)
    }

    #[cfg(test)]
    fn pending_notification(&self) -> Result<(), String> {
        match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(self.notification())
        {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(format!(
                "не удалось записать состояние применения Meta DNS: {error}"
            )),
        }
    }

    fn store_notification(&self, state: &Notification) -> Result<(), String> {
        let bytes = serde_json::to_vec(state).map_err(|error| error.to_string())?;
        if bytes.len() > STATE_LIMIT {
            return Err("превышен размер журнала применения Meta DNS".into());
        }
        atomic_write_with_mode(&self.notification(), &bytes, 0o600)
    }

    fn prepare_notification(&self, body: &str, removing: bool) -> Result<Notification, String> {
        let pending = read_notification(&self.notification())?;
        let applied = read_notification(&self.applied())?;
        let mut previous = Vec::new();
        for instance in pending
            .iter()
            .flat_map(|state| state.previous.iter().chain(&state.acknowledged))
            .chain(applied.iter().flat_map(|state| &state.acknowledged))
        {
            if !previous
                .iter()
                .any(|old: &Instance| old.same_process(instance))
            {
                previous.push(instance.clone());
            }
        }
        if previous.len() > INSTANCE_LIMIT {
            return Err("слишком много экземпляров в журнале Meta DNS".into());
        }
        let state = Notification {
            version: 1,
            generation: generation(body),
            previous,
            acknowledged: Vec::new(),
            failures: pending.as_ref().map_or(0, |state| state.failures),
            retry_at: if removing {
                0
            } else {
                pending.as_ref().map_or(0, |state| state.retry_at)
            },
            untracked_previous: pending
                .as_ref()
                .is_some_and(|state| state.version == 0 || state.untracked_previous)
                || (applied.is_none()
                    && self.contents()?.is_some_and(|old| old.lines().count() > 1)),
        };
        self.store_notification(&state)?;
        Ok(state)
    }

    fn defer(&self, state: &mut Notification, now: u64, error: String) -> Result<(), String> {
        state.failures = state.failures.saturating_add(1);
        let delay = RETRY_INITIAL
            .saturating_mul(1_u64 << state.failures.saturating_sub(1).min(6))
            .min(RETRY_MAX);
        state.retry_at = now.saturating_add(delay);
        self.store_notification(state)?;
        Err(error)
    }

    fn notify(
        &self,
        mut state: Notification,
        instances: Instances,
        now: u64,
        runtime: &mut impl Runtime,
        deadline: Instant,
    ) -> Result<(), String> {
        if state.untracked_previous {
            // An old installation has no consumer ledger. A currently
            // unsupported instance may still hold records it read earlier,
            // even when another instance can consume the new file normally.
            for instance in &instances.running {
                if !state.previous.iter().any(|old| old.same_process(instance)) {
                    state.previous.push(instance.clone());
                }
            }
            state.untracked_previous = false;
        }
        state.previous.retain(|old| {
            instances
                .running
                .iter()
                .any(|current| old.same_process(current))
        });
        state
            .acknowledged
            .retain(|old| instances.eligible.contains(old));
        // Even a crash immediately after a signal cannot start a tight retry
        // loop if its acknowledgment has not reached disk yet.
        state.retry_at = now.saturating_add(RETRY_INITIAL);
        self.store_notification(&state)?;
        let mut error = None;
        for instance in &instances.eligible {
            if state.acknowledged.contains(instance) {
                continue;
            }
            // Each IPC is bounded separately; also stop starting new work
            // after this pass's budget, even when many instances are alive.
            if Instant::now() >= deadline {
                error = Some("достигнут бюджет применения Meta DNS".into());
                break;
            }
            match runtime.signal(instance) {
                Ok(()) => {
                    state.acknowledged.push(instance.clone());
                    // Persist each success before another instance can fail.
                    self.store_notification(&state)?;
                }
                Err(failure) => error = Some(failure),
            }
        }
        if state
            .previous
            .iter()
            .any(|old| !state.acknowledged.iter().any(|ack| old.same_process(ack)))
        {
            error = Some(
                "работающий экземпляр dnsmasq ещё не подтвердил снятие прежних записей Meta".into(),
            );
        }
        if instances.eligible.is_empty()
            && self
                .contents()?
                .is_some_and(|body| body.lines().count() > 1)
        {
            error = Some("Meta DNS ожидает запуска поддерживаемого экземпляра dnsmasq".into());
        }
        if let Some(error) = error {
            return self.defer(&mut state, now, error);
        }
        state.previous.clear();
        state.failures = 0;
        state.retry_at = 0;
        let bytes = serde_json::to_vec(&state).map_err(|error| error.to_string())?;
        atomic_write_with_mode(&self.applied(), &bytes, 0o600)?;
        fs::remove_file(self.notification()).map_err(|error| error.to_string())
    }
}

fn write_hosts(path: &Path, body: &[u8]) -> Result<(), String> {
    // A kill during a write can leave at most one hidden staging file. dnsmasq
    // ignores dotfiles when scanning addn-hosts directories.
    let temporary = path.with_file_name(".r2o-meta.pending");
    let _ = fs::remove_file(&temporary);
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("не удалось подготовить Meta DNS: {error}"))?;
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .and_then(|()| file.write_all(body))
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, path))
        .map_err(|error| format!("не удалось опубликовать Meta DNS: {error}"))
}

fn verified_sections(body: &str, pairs: &[(String, IpAddr)]) -> (String, BTreeSet<String>) {
    let mut next = String::with_capacity(body.len());
    let mut removed = BTreeSet::new();
    let mut starts = body
        .split_inclusive('\n')
        .scan((0, None, false), |(offset, quote, continued), line| {
            let start = *offset;
            let boundary = quote.is_none() && !*continued;
            *offset += line.len();
            *continued = false;
            let mut bytes = line.trim_end_matches('\n').bytes();
            while let Some(byte) = bytes.next() {
                match (byte, *quote) {
                    (b'#', None) => break,
                    (b'\\', None | Some(b'"')) => *continued = bytes.next().is_none(),
                    (b'\'' | b'"', None) => *quote = Some(byte),
                    (_, Some(delimiter)) if byte == delimiter => *quote = None,
                    _ => {}
                }
            }
            Some((start, line, boundary))
        })
        .filter_map(|(offset, line, boundary)| {
            (boundary && line.split_ascii_whitespace().next() == Some("config")).then_some(offset)
        })
        .peekable();
    let prefix = starts.peek().copied().unwrap_or(body.len());
    next.push_str(&body[..prefix]);
    while let Some(start) = starts.next() {
        let block = &body[start..starts.peek().copied().unwrap_or(body.len())];
        let mut lines = block.lines().filter(|line| !line.trim().is_empty());
        let header = lines.next().unwrap_or_default();
        let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
        let Some(pair) = (match fields.as_slice() {
            ["config", "hostrecord", section] => pairs
                .iter()
                .find(|(host, ip)| section.trim_matches('\'') == dnsmasq_section(host, *ip)),
            _ => None,
        }) else {
            next.push_str(block);
            continue;
        };
        let mut name = None;
        let mut ip = None;
        let valid = lines.all(|line| {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            match fields.as_slice() {
                ["option", "name", value] if name.is_none() => {
                    name = Some(value.trim_matches('\''));
                    true
                }
                ["option", "ip", value] if ip.is_none() => {
                    ip = value.trim_matches('\'').parse::<IpAddr>().ok();
                    ip.is_some()
                }
                _ => false,
            }
        });
        if valid && name == Some(pair.0.as_str()) && ip == Some(pair.1) {
            removed.insert(pair.0.clone());
        } else {
            next.push_str(block);
        }
    }
    (next, removed)
}

pub(super) fn retire_legacy(manifest: &Path) -> Result<BTreeSet<String>, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let pairs = read_manifest(manifest)?;
    if pairs.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut config = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(DHCP_CONFIG)
        .map_err(|error| format!("не удалось открыть dhcp для миграции: {error}"))?;
    config
        .try_lock()
        .map_err(|error| format!("UCI dhcp занят: {error}"))?;
    let metadata = config.metadata().map_err(|error| error.to_string())?;
    let mut body = String::new();
    std::io::Read::by_ref(&mut config)
        .take(4 * 1024 * 1024)
        .read_to_string(&mut body)
        .map_err(|error| error.to_string())?;
    if metadata.len() != body.len() as u64 {
        return Err("размер конфигурации dhcp изменился".into());
    }
    let (next, removed) = verified_sections(&body, &pairs);
    if !removed.is_empty() {
        // The package's original bytes and staged user changes stay independent.
        // Apply only to the standard root-owned package, alongside libuci's lock.
        let has_delta = match fs::metadata(DHCP_DELTA) {
            Ok(metadata) => metadata.len() > 0,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.to_string()),
        };
        if has_delta {
            return Err("есть несохранённые настройки UCI dhcp, миграция отложена".into());
        }
        for entry in fs::read_dir("/etc/config").map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".dhcp.uci-")
            {
                return Err("UCI обновляет dhcp, миграция отложена".into());
            }
        }
        let current = fs::symlink_metadata(DHCP_CONFIG).map_err(|error| error.to_string())?;
        if current.ino() != metadata.ino()
            || current.dev() != metadata.dev()
            || current.uid() != 0
            || current.gid() != 0
            || fs::read(DHCP_CONFIG).map_err(|error| error.to_string())? != body.as_bytes()
        {
            return Err("файл dhcp изменился во время подготовки миграции".into());
        }
        atomic_write_with_mode(
            Path::new(DHCP_CONFIG),
            next.as_bytes(),
            current.mode() & 0o777,
        )?;
    }
    drop(config);

    // SIGHUP cannot remove host-record directives already parsed at startup.
    // Keep the journal until the platform has naturally replaced those records.
    let mut active = removed;
    let instances = SystemRuntime.snapshot()?;
    active.extend(active_legacy_hosts(
        &pairs,
        &instances.running,
        read_instance_config,
    )?);
    if active.is_empty() && !body.contains("r2o_meta_") {
        fs::remove_file(manifest).map_err(|error| error.to_string())?;
    }
    Ok(active)
}

fn active_legacy_hosts(
    pairs: &[(String, IpAddr)],
    running: &[Instance],
    mut read_config: impl FnMut(&Path) -> Result<Option<String>, String>,
) -> Result<BTreeSet<String>, String> {
    let mut active = BTreeSet::new();
    for instance in running {
        let body = read_config(&instance.config)?
            .ok_or("не удалось проверить действующую конфигурацию dnsmasq при миграции")?;
        for (host, ip) in pairs {
            if body.lines().any(|line| {
                line.strip_prefix("host-record=")
                    .and_then(|line| line.split_once(','))
                    .is_some_and(|(name, address)| {
                        name == host && address.parse::<IpAddr>().ok() == Some(*ip)
                    })
            }) {
                active.insert(host.clone());
            }
        }
    }
    Ok(active)
}

fn ubus(method: &str, payload: Value) -> Result<Value, String> {
    let output = bounded_output(
        Command::new("ubus").args(["-t", "2", "call", "service", method, &payload.to_string()]),
        Duration::from_secs(3),
        256 * 1024,
    )?;
    if !output.status.success() {
        return Err(format!(
            "ubus service {method}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if output.stdout.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("ответ ubus service {method}: {error}"))
}

fn read_instance_config(config: &Path) -> Result<Option<String>, String> {
    if config.parent() != Some(Path::new("/var/etc")) {
        return Ok(None);
    }
    read_regular(config, 1024 * 1024)
}

fn inspect_instances(
    service: &Value,
    directory: &str,
    mut read_config: impl FnMut(&Path) -> Result<Option<String>, String>,
) -> Result<Instances, String> {
    let mut result = Instances::default();
    let object = service
        .as_object()
        .ok_or("неподдерживаемый ответ procd dnsmasq")?;
    let Some(dnsmasq) = object.get("dnsmasq") else {
        return Ok(result);
    };
    let instances = dnsmasq
        .get("instances")
        .and_then(Value::as_object)
        .ok_or("не удалось прочитать экземпляры dnsmasq")?;
    if instances.len() > INSTANCE_LIMIT {
        return Err("слишком много экземпляров dnsmasq".into());
    }
    for (name, instance) in instances {
        if instance.get("running").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let pid = instance
            .get("pid")
            .and_then(Value::as_u64)
            .filter(|pid| *pid != 0 && *pid <= i32::MAX as u64)
            .ok_or("procd не вернул PID работающего dnsmasq")? as u32;
        if name.is_empty() || name.len() > 128 {
            return Err("неподдерживаемое имя экземпляра dnsmasq".into());
        }
        let config = instance
            .get("command")
            .and_then(Value::as_array)
            .and_then(|command| {
                command.windows(2).find_map(|args| {
                    (args[0].as_str() == Some("-C"))
                        .then(|| args[1].as_str())
                        .flatten()
                })
            })
            .unwrap_or_default();
        if config.len() > 1024 {
            return Err("слишком длинный путь конфигурации dnsmasq".into());
        }
        let current = Instance {
            name: name.clone(),
            pid,
            config: config.into(),
        };
        result.running.push(current.clone());
        // For ujail, verify the directory mount. Mounting a single file pins its
        // inode, so dnsmasq would miss a subsequent atomic rename.
        if instance.get("jail").is_some()
            && instance
                .get("mount")
                .and_then(|mount| mount.get(directory))
                .is_none()
        {
            continue;
        }
        let Some(body) = read_config(&current.config)? else {
            continue;
        };
        if body.lines().any(|line| {
            line.trim().split_once('=').is_some_and(|(key, path)| {
                key == "addn-hosts" && path.trim_end_matches('/') == directory
            })
        }) {
            result.eligible.push(current);
        }
    }
    Ok(result)
}

fn bounded_output(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
) -> Result<std::process::Output, String> {
    use std::os::fd::AsRawFd;

    struct Reap(std::process::Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            // Only the helper process belongs to us, never the DNS service.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("не удалось запустить ubus: {error}"))?;
    let mut child = Reap(child);
    let mut stdout = child.0.stdout.take().expect("stdout pipe");
    let mut stderr = child.0.stderr.take().expect("stderr pipe");
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(format!(
                "не удалось ограничить чтение ubus: {}",
                io::Error::last_os_error()
            ));
        }
    }
    let deadline = Instant::now() + timeout;
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let mut stdout_done = false;
    let mut stderr_done = false;
    loop {
        stdout_done |= drain_pipe(&mut stdout, &mut output, limit)?;
        stderr_done |= drain_pipe(&mut stderr, &mut errors, 4096)?;
        let status = child.0.try_wait().map_err(|error| error.to_string())?;
        if let Some(status) = status
            && stdout_done
            && stderr_done
        {
            return Ok(std::process::Output {
                status,
                stdout: output,
                stderr: errors,
            });
        }
        if Instant::now() >= deadline {
            return Err("ubus не завершился за отведённое время".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn drain_pipe(reader: &mut impl Read, out: &mut Vec<u8>, limit: usize) -> Result<bool, String> {
    let mut buffer = [0; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(size) if size <= limit.saturating_sub(out.len()) => {
                out.extend_from_slice(&buffer[..size])
            }
            Ok(_) => return Err("ubus превысил предел размера ответа".into()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("не удалось прочитать ответ ubus: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        hosts: DnsmasqHosts,
        directory: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let directory = std::env::temp_dir().join(format!(
                "r2o-meta-notify-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&directory).unwrap();
            Self {
                hosts: DnsmasqHosts {
                    path: directory.join("r2o-meta"),
                },
                directory,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn instance(name: &str, pid: u32) -> Instance {
        Instance {
            name: name.into(),
            pid,
            config: format!("/var/etc/dnsmasq.conf.{name}").into(),
        }
    }

    fn pairs(ip: &str) -> BTreeSet<PinPair> {
        BTreeSet::from([("www.instagram.com".into(), ip.into())])
    }

    struct FakeRuntime {
        running: Vec<Instance>,
        eligible: Vec<Instance>,
        failed: BTreeSet<String>,
        snapshot_error: bool,
        snapshots: usize,
        signals: Vec<Instance>,
    }

    impl FakeRuntime {
        fn new() -> Self {
            let eligible = vec![instance("lan", 123), instance("guest", 124)];
            Self {
                running: eligible.clone(),
                eligible,
                failed: BTreeSet::new(),
                snapshot_error: false,
                snapshots: 0,
                signals: Vec::new(),
            }
        }
    }

    impl Runtime for FakeRuntime {
        fn snapshot(&mut self) -> Result<Instances, String> {
            self.snapshots += 1;
            if self.snapshot_error {
                return Err("procd unavailable".into());
            }
            Ok(Instances {
                running: self.running.clone(),
                eligible: self.eligible.clone(),
            })
        }

        fn signal(&mut self, instance: &Instance) -> Result<(), String> {
            self.signals.push(instance.clone());
            if self.failed.contains(&instance.name) {
                Err("signal failed".into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn partial_notification_retries_only_unacknowledged_instances_after_backoff() {
        let fixture = Fixture::new();
        let hosts = &fixture.hosts;
        let mut runtime = FakeRuntime::new();
        runtime.failed.insert("guest".into());
        assert!(
            hosts
                .publish_with(&pairs("157.240.1.1"), 1000, &mut runtime)
                .is_err()
        );
        assert_eq!(
            runtime.signals,
            [instance("lan", 123), instance("guest", 124)]
        );
        let saved = read_notification(&hosts.notification()).unwrap().unwrap();
        assert_eq!(saved.acknowledged, [instance("lan", 123)]);
        assert_eq!(saved.retry_at, 1060);

        // Reconstruct the adapter to model a killed/restarted scheduler.
        let hosts = DnsmasqHosts {
            path: hosts.path.clone(),
        };
        assert!(hosts.resume_with(1059, &mut runtime).is_err());
        assert_eq!(runtime.snapshots, 1);
        runtime.failed.clear();
        hosts.resume_with(1060, &mut runtime).unwrap();
        assert_eq!(
            runtime.signals,
            [
                instance("lan", 123),
                instance("guest", 124),
                instance("guest", 124)
            ]
        );
        assert!(!hosts.notification_pending());
        let snapshots = runtime.snapshots;
        hosts
            .publish_with(&pairs("157.240.1.1"), 1061, &mut runtime)
            .unwrap();
        assert_eq!(runtime.snapshots, snapshots);
        assert_eq!(runtime.signals.len(), 3);
    }

    #[test]
    fn notification_budget_preserves_successes_and_defers_remaining_instances() {
        let fixture = Fixture::new();
        let hosts = &fixture.hosts;
        let mut runtime = FakeRuntime::new();
        runtime.failed.insert("guest".into());
        assert!(
            hosts
                .publish_with(&pairs("157.240.1.1"), 1000, &mut runtime)
                .is_err()
        );
        let state = read_notification(&hosts.notification()).unwrap().unwrap();
        let instances = runtime.snapshot().unwrap();
        runtime.failed.clear();
        assert!(
            hosts
                .notify(state, instances, 1060, &mut runtime, Instant::now())
                .is_err()
        );
        assert_eq!(
            runtime.signals,
            [instance("lan", 123), instance("guest", 124)]
        );
        let state = read_notification(&hosts.notification()).unwrap().unwrap();
        assert_eq!(state.acknowledged, [instance("lan", 123)]);
        assert_eq!(state.retry_at, 1180);
        hosts.resume_with(1180, &mut runtime).unwrap();
        assert_eq!(
            runtime.signals,
            [
                instance("lan", 123),
                instance("guest", 124),
                instance("guest", 124)
            ]
        );
        assert!(!hosts.notification_pending());
    }

    #[test]
    fn a_restarted_instance_has_to_acknowledge_the_pending_generation() {
        let fixture = Fixture::new();
        let hosts = &fixture.hosts;
        let mut runtime = FakeRuntime::new();
        runtime.failed.insert("guest".into());
        assert!(
            hosts
                .publish_with(&pairs("157.240.1.1"), 1000, &mut runtime)
                .is_err()
        );
        runtime.eligible[0].pid = 125;
        runtime.running[0].pid = 125;
        runtime.failed.clear();
        hosts.resume_with(1060, &mut runtime).unwrap();
        assert_eq!(
            runtime.signals,
            [
                instance("lan", 123),
                instance("guest", 124),
                instance("lan", 125),
                instance("guest", 124)
            ]
        );
    }

    #[test]
    fn deletion_waits_for_previous_consumer_but_ignores_unrelated_instances() {
        let fixture = Fixture::new();
        let hosts = &fixture.hosts;
        let mut runtime = FakeRuntime::new();
        runtime.eligible.truncate(1);
        runtime.running.push(instance("unrelated", 126));
        hosts
            .publish_with(&pairs("157.240.1.1"), 1000, &mut runtime)
            .unwrap();
        assert_eq!(runtime.signals, [instance("lan", 123)]);
        // The same live process is no longer inspectable; its memory can still
        // contain the old records even though the managed file is now empty.
        runtime.eligible.clear();
        assert!(
            hosts
                .publish_with(&BTreeSet::new(), 1001, &mut runtime)
                .is_err()
        );
        assert!(hosts.records().unwrap().is_empty());
        assert!(hosts.notification_pending());
        runtime.running.retain(|instance| instance.name != "lan");
        hosts.resume_with(1061, &mut runtime).unwrap();
        assert!(!hosts.notification_pending());
        assert_eq!(runtime.signals.len(), 1);
    }

    #[test]
    fn old_empty_marker_survives_missing_file_and_uninspectable_running_dnsmasq() {
        let fixture = Fixture::new();
        let hosts = &fixture.hosts;
        hosts.pending_notification().unwrap();
        let mut runtime = FakeRuntime::new();
        runtime.eligible.clear();
        assert!(
            hosts
                .publish_with(&BTreeSet::new(), 1000, &mut runtime)
                .is_err()
        );
        assert!(hosts.notification_pending());
        runtime.running.clear();
        hosts.resume_with(1060, &mut runtime).unwrap();
        assert!(!hosts.notification_pending());
        assert!(runtime.signals.is_empty());
    }

    #[test]
    fn old_marker_keeps_an_unknown_consumer_pending_when_another_instance_succeeds() {
        let fixture = Fixture::new();
        let hosts = &fixture.hosts;
        hosts.pending_notification().unwrap();
        let mut runtime = FakeRuntime::new();
        runtime.eligible.truncate(1);
        assert!(
            hosts
                .publish_with(&BTreeSet::new(), 1000, &mut runtime)
                .is_err()
        );
        assert_eq!(runtime.signals, [instance("lan", 123)]);
        assert!(hosts.notification_pending());
        runtime.running.retain(|instance| instance.name != "guest");
        hosts.resume_with(1060, &mut runtime).unwrap();
        assert!(!hosts.notification_pending());
        assert_eq!(runtime.signals, [instance("lan", 123)]);
    }

    #[test]
    fn publication_preserves_backoff_but_deletion_can_be_applied_immediately() {
        let fixture = Fixture::new();
        let hosts = &fixture.hosts;
        let mut runtime = FakeRuntime::new();
        runtime.failed.insert("guest".into());
        assert!(
            hosts
                .publish_with(&pairs("157.240.1.1"), 1000, &mut runtime)
                .is_err()
        );
        assert!(
            hosts
                .publish_with(&pairs("157.240.1.2"), 1001, &mut runtime)
                .is_err()
        );
        assert_eq!(runtime.signals.len(), 2);
        runtime.failed.clear();
        hosts
            .publish_with(&BTreeSet::new(), 1002, &mut runtime)
            .unwrap();
        assert_eq!(runtime.signals.len(), 4);
        assert!(hosts.records().unwrap().is_empty());
    }

    #[test]
    fn unavailable_procd_keeps_deletion_pending_and_bounds_retries() {
        let fixture = Fixture::new();
        let hosts = &fixture.hosts;
        let mut runtime = FakeRuntime::new();
        hosts
            .publish_with(&pairs("157.240.1.1"), 1000, &mut runtime)
            .unwrap();
        runtime.snapshot_error = true;
        assert!(
            hosts
                .publish_with(&BTreeSet::new(), 1001, &mut runtime)
                .is_err()
        );
        assert!(hosts.records().unwrap().is_empty());
        let mut now = 1061;
        for expected in [120, 240, 480, 960, 1920, 3600, 3600] {
            assert!(hosts.resume_with(now, &mut runtime).is_err());
            let pending = read_notification(&hosts.notification()).unwrap().unwrap();
            assert_eq!(pending.retry_at - now, expected);
            now = pending.retry_at;
        }
        runtime.snapshot_error = false;
        hosts.resume_with(now, &mut runtime).unwrap();
        assert!(!hosts.notification_pending());
    }

    #[test]
    fn instance_inspection_requires_the_hosts_directory_mount_and_ignores_stopped_configs() {
        let service = json!({"dnsmasq":{"instances":{
            "lan":{"running":true,"pid":123,"command":["dnsmasq","-C","/var/etc/dnsmasq.conf.lan"],"jail":{},"mount":{"/tmp/hosts":"0"}},
            "file-only":{"running":true,"pid":124,"command":["dnsmasq","-C","/var/etc/dnsmasq.conf.file-only"],"jail":{},"mount":{"/tmp/hosts/r2o-meta":"0"}},
            "ignored":{"running":true,"pid":125,"command":["dnsmasq","-C","/var/etc/dnsmasq.conf.ignored"]},
            "old":{"running":false,"command":["dnsmasq","-C","/var/etc/dnsmasq.conf.old"]}
        }}});
        let mut read = Vec::new();
        let instances = inspect_instances(&service, HOSTS_DIR, |path| {
            read.push(path.to_path_buf());
            Ok(Some(
                if path.ends_with("dnsmasq.conf.lan") {
                    "addn-hosts=/tmp/hosts/\n"
                } else {
                    "no-hosts\n"
                }
                .into(),
            ))
        })
        .unwrap();
        assert_eq!(instances.eligible, [instance("lan", 123)]);
        assert_eq!(instances.running.len(), 3);
        assert!(!read.iter().any(|path| path.ends_with("dnsmasq.conf.old")));
        assert!(
            !read
                .iter()
                .any(|path| path.ends_with("dnsmasq.conf.file-only"))
        );
    }

    #[test]
    fn legacy_retirement_reads_only_running_instance_configs() {
        let pairs = [("instagram.com".into(), "157.240.1.1".parse().unwrap())];
        let active = active_legacy_hosts(&pairs, &[instance("lan", 123)], |path| {
            assert!(path.ends_with("dnsmasq.conf.lan"));
            Ok(Some("addn-hosts=/tmp/hosts\n".into()))
        })
        .unwrap();
        assert!(active.is_empty());
        let active = active_legacy_hosts(&pairs, &[instance("lan", 123)], |_| {
            Ok(Some("host-record=instagram.com,157.240.1.1\n".into()))
        })
        .unwrap();
        assert_eq!(active, BTreeSet::from(["instagram.com".into()]));
        assert!(active_legacy_hosts(&pairs, &[instance("lan", 123)], |_| Ok(None)).is_err());
    }

    #[test]
    fn helper_output_and_wall_time_are_bounded() {
        let output = bounded_output(
            Command::new("sh").args(["-c", "printf '{\"ok\":true}'"]),
            Duration::from_secs(1),
            512,
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"{\"ok\":true}");
        let noisy = bounded_output(
            Command::new("sh").args(["-c", "while :; do printf '0123456789'; done"]),
            Duration::from_secs(1),
            512,
        );
        assert!(noisy.unwrap_err().contains("размера"));
        let started = Instant::now();
        let hung = bounded_output(
            Command::new("sh").args(["-c", "exec sleep 2"]),
            Duration::from_millis(50),
            512,
        );
        assert!(hung.unwrap_err().contains("время"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn migration_removes_only_exact_records_from_the_ownership_manifest() {
        let ip = "157.240.1.10".parse().unwrap();
        let host = "instagram.com";
        let owned = format!(
            "config hostrecord '{}'\n\toption name '{}'\n\toption ip '{}'\n\n",
            dnsmasq_section(host, ip),
            host,
            ip
        );
        let foreign = "config dnsmasq\n\toption nonwildcard '1'\n\tlist notinterface 'Beeline'\n\n";
        let multiline = format!("config dnsmasq 'other'\n\toption comment \"\n{owned}\t\"\n\n");
        let changed = owned.replace("157.240.1.10", "157.240.1.12");
        let user_record =
            "config hostrecord 'user'\n\toption name 'instagram.com'\n\toption ip '192.0.2.1'\n";
        let pairs = [(host.to_owned(), ip)];
        let input = format!("{foreign}{multiline}{owned}{user_record}");
        assert_eq!(
            verified_sections(&input, &pairs),
            (
                format!("{foreign}{multiline}{user_record}"),
                BTreeSet::from([host.to_owned()])
            )
        );
        let input = format!("{foreign}{changed}{user_record}");
        assert_eq!(verified_sections(&input, &pairs), (input, BTreeSet::new()));
    }

    // Execute the ignored test inside a disposable, running OpenWrt guest.
    #[test]
    #[ignore = "requires an isolated OpenWrt guest with real procd and dnsmasq"]
    fn openwrt_procd_hosts_soak() {
        assert_eq!(std::env::var("R2O_OPENWRT_TEST").as_deref(), Ok("isolated"));
        let hosts = DnsmasqHosts::default();
        assert!(hosts.contents().unwrap().is_none());
        let config = fs::read("/etc/config/dhcp").unwrap();
        let dnsmasq = || {
            ubus("list", json!({"name": "dnsmasq", "verbose": true})).unwrap()
                ["dnsmasq"]["instances"].as_object().unwrap().iter()
                .filter_map(|(key, value)| Some((key.clone(), value.get("pid")?.as_u64()?)))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let initial = dnsmasq();
        let mut samples = Vec::new();
        let nslookup = |rr, expected: &str| {
            let output = Command::new("nslookup")
                .args([
                    rr,
                    "-timeout=1",
                    "-retry=1",
                    "www.instagram.com",
                    "127.0.0.1",
                ])
                .output()
                .unwrap();
            let response = String::from_utf8_lossy(&output.stdout);
            output.status.success()
                && response
                    .lines()
                    .any(|line| line.split_whitespace().last() == Some(expected))
        };
        // A hidden incomplete file models SIGKILL before atomic rename.
        fs::write(hosts.test_staging_path(), "192.0.2.5 www.instagram.com\n").unwrap();
        for index in 0..1000 {
            if index % 20 == 0 {
                let state = if index % 40 == 0 { "down" } else { "up" };
                assert!(
                    Command::new("ip")
                        .args(["link", "set", "Beeline", state])
                        .status()
                        .unwrap()
                        .success()
                );
            }
            let v4 = format!("192.0.2.{}", index % 200 + 10);
            let v6 = format!("2001:db8::{:x}", index % 200 + 10);
            let start = std::time::Instant::now();
            hosts
                .publish(&BTreeSet::from([
                    ("www.instagram.com".into(), v4.clone()),
                    ("www.instagram.com".into(), v6.clone()),
                ]))
                .unwrap();
            let mut found = false;
            for _ in 0..10 {
                if nslookup("-type=A", &v4) && nslookup("-type=AAAA", &v6) {
                    found = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(found, "DNS update {index} did not reach dnsmasq");
            samples.push(start.elapsed().as_micros());
        }
        assert_eq!(initial, dnsmasq());
        assert_eq!(config, fs::read("/etc/config/dhcp").unwrap());
        fs::remove_file(hosts.test_staging_path()).unwrap();
        // A writer can exit after rename and before signaling procd.
        hosts.pending_notification().unwrap();
        write_hosts(
            &hosts.path,
            format!("{HEADER}\n192.0.2.250 www.instagram.com\n").as_bytes(),
        )
        .unwrap();
        assert!(hosts.notification_pending());
        hosts.resume().unwrap();
        assert!(!hosts.notification_pending());
        for _ in 0..10 {
            if nslookup("-type=A", "192.0.2.250") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(nslookup("-type=A", "192.0.2.250"));
        let output = Command::new("nslookup")
            .args([
                "-type=A",
                "-timeout=1",
                "-retry=1",
                "r2o-fixture.lan",
                "127.0.0.1",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("192.0.2.3")
        );
        hosts.publish(&BTreeSet::new()).unwrap();
        assert!(hosts.records().unwrap().is_empty());
        samples.sort_unstable();
        println!(
            "cycles=1000 queries=2000 pid_changes=0 p50_us={} p95_us={} p99_us={}",
            samples[499], samples[949], samples[989]
        );
    }
}
