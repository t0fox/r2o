//! Publish host records through the directory mounted by OpenWrt's dnsmasq service.

use super::{PinPair, atomic_write_with_mode, dnsmasq_section, is_managed_host, read_manifest};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

const HOSTS_DIR: &str = "/tmp/hosts";
const HEADER: &str = "# R2O Meta Protection";
const DHCP_CONFIG: &str = "/etc/config/dhcp";
const DHCP_DELTA: &str = "/tmp/.uci/dhcp";

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

    pub(super) fn notification_pending(&self) -> bool {
        self.notification().is_file()
    }

    pub(super) fn resume(&self) -> Result<(), String> {
        if !self.notification_pending() {
            return Ok(());
        }
        let instances = running_instances()?;
        self.notify(instances)
    }

    #[cfg(test)]
    fn test_staging_path(&self) -> std::path::PathBuf {
        self.path.with_file_name(".r2o-meta.tmp.abandoned")
    }

    pub(super) fn publish(&self, pairs: &BTreeSet<PinPair>) -> Result<(), String> {
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
        if previous.is_none() && pairs.is_empty() {
            return Ok(());
        }
        let changed = previous.as_deref() != Some(&body);
        if !changed {
            return self.resume();
        }
        let instances = match running_instances() {
            Ok(instances) => instances,
            Err(error) if pairs.is_empty() => {
                // Remove the persisted overrides even during a procd outage.
                self.pending_notification()?;
                write_hosts(&self.path, body.as_bytes())?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if instances.is_empty() && !pairs.is_empty() {
            return Err("dnsmasq не запущен с доступным каталогом /tmp/hosts".into());
        }
        self.pending_notification()?;
        write_hosts(&self.path, body.as_bytes())?;
        self.notify(instances)
    }

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

    fn notify(&self, instances: Vec<String>) -> Result<(), String> {
        if instances.is_empty() {
            return Ok(());
        }
        let mut error = None;
        for instance in instances {
            if let Err(failure) = ubus(
                "signal",
                json!({"name": "dnsmasq", "instance": instance, "signal": libc::SIGHUP}),
            ) {
                error = Some(failure);
            }
        }
        if let Some(error) = error {
            return Err(error);
        }
        fs::remove_file(self.notification()).map_err(|error| error.to_string())
    }
}

fn running_instances() -> Result<Vec<String>, String> {
    let service = ubus("list", json!({"name": "dnsmasq", "verbose": true}))?;
    eligible_instances(&service, HOSTS_DIR)
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
    let generated = fs::read_dir("/var/etc").map_err(|error| error.to_string())?;
    for config in generated.flatten().filter(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .starts_with("dnsmasq.conf.")
    }) {
        let body = fs::read_to_string(config.path()).map_err(|error| error.to_string())?;
        for (host, ip) in &pairs {
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
    if active.is_empty() && !body.contains("r2o_meta_") {
        fs::remove_file(manifest).map_err(|error| error.to_string())?;
    }
    Ok(active)
}

fn ubus(method: &str, payload: Value) -> Result<Value, String> {
    let output = Command::new("ubus")
        .args(["-t", "2", "call", "service", method, &payload.to_string()])
        .output()
        .map_err(|error| format!("не удалось запустить ubus: {error}"))?;
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

fn eligible_instances(service: &Value, directory: &str) -> Result<Vec<String>, String> {
    let mut eligible = Vec::new();
    let Some(instances) = service
        .pointer("/dnsmasq/instances")
        .and_then(Value::as_object)
    else {
        return Ok(eligible);
    };
    for (name, instance) in instances {
        if instance.get("running").and_then(Value::as_bool) != Some(true) {
            continue;
        }
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
        let Some(command) = instance.get("command").and_then(Value::as_array) else {
            continue;
        };
        let Some(config) = command.windows(2).find_map(|args| {
            (args[0].as_str() == Some("-C"))
                .then(|| args[1].as_str())
                .flatten()
        }) else {
            continue;
        };
        let config = Path::new(config);
        if config.parent() != Some(Path::new("/var/etc")) {
            continue;
        }
        let body = match fs::read_to_string(config) {
            Ok(body) => body,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "не удалось прочитать {}: {error}",
                    config.display()
                ));
            }
        };
        if body.lines().any(|line| {
            line.trim().split_once('=').is_some_and(|(key, path)| {
                key == "addn-hosts" && path.trim_end_matches('/') == directory
            })
        }) {
            eligible.push(name.clone());
        }
    }
    Ok(eligible)
}

#[cfg(test)]
mod tests {
    use super::*;

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
