//! Проверка и управление точными DNS-записями Meta на роутере.

use crate::cf_proxy_doh::{doh_tls, protected_address_lookup};
use crate::meta_edge::{META_HOSTS, MetaTls};
use crate::meta_knowledge::{Address, Knowledge};
use futures_util::{StreamExt, stream};
use r2k_core::meta::{product as meta_family, protection_enabled};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::future::Future;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

mod dnsmasq;
use dnsmasq::DnsmasqHosts;

const MAX_HOST_ADDRESSES: usize = 2;
const MAX_PROBE_CANDIDATES: usize = 8;
const REFRESH_BUDGET: Duration = Duration::from_secs(180);
const RESOLVE_BUDGET: Duration = Duration::from_secs(60);
type DnsAnswers = BTreeMap<String, Vec<IpAddr>>;
type TlsChecks = BTreeMap<(String, IpAddr), Result<Option<u16>, String>>;

type NetFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type PinPair = (String, String);

struct ProbePolicy<'a> {
    attempts: usize,
    retry_delay: Duration,
    log: &'a Path,
    deadline: tokio::time::Instant,
}

pub trait MetaNetwork: Send + Sync {
    fn includes_host(&self, _host: &str) -> bool {
        true
    }
    fn ordered_hosts(&self) -> Vec<String> {
        Vec::new()
    }
    fn resolve<'a>(&'a self) -> NetFuture<'a, Result<BTreeMap<String, Vec<IpAddr>>, String>>;
    fn verify<'a>(&'a self, host: &'a str, address: IpAddr) -> NetFuture<'a, bool>;
}

pub trait Ndm: Send {
    fn requires_exclusive_hostname(&self) -> bool {
        false
    }

    fn supports_address(&self, _address: IpAddr) -> bool {
        true
    }
    fn running_config(&mut self) -> Result<String, String>;
    fn add(&mut self, host: &str, address: IpAddr) -> Result<(), String>;
    fn remove(&mut self, host: &str, address: IpAddr) -> Result<(), String>;
    fn save(&mut self) -> Result<(), String>;
}

pub struct DirectMetaNetwork {
    ca_bundle: Option<PathBuf>,
    hosts: Vec<String>,
    prefixes: Vec<(IpAddr, u8)>,
    tls: std::sync::OnceLock<Result<MetaTls, String>>,
    candidates: std::sync::Mutex<BTreeMap<(String, IpAddr), String>>,
    checks: std::sync::Mutex<TlsChecks>,
    cert_names: std::sync::Mutex<BTreeSet<String>>,
    local_dns: std::sync::Mutex<BTreeMap<String, &'static str>>,
    saved: DnsAnswers,
    attempted: std::sync::Mutex<BTreeSet<String>>,
    deadline: tokio::time::Instant,
}

impl DirectMetaNetwork {
    pub fn new(ca_bundle: Option<PathBuf>) -> Self {
        Self {
            ca_bundle,
            hosts: META_HOSTS.iter().map(ToString::to_string).collect(),
            prefixes: Vec::new(),
            tls: std::sync::OnceLock::new(),
            candidates: Default::default(),
            checks: Default::default(),
            cert_names: Default::default(),
            local_dns: Default::default(),
            saved: Default::default(),
            attempted: Default::default(),
            deadline: tokio::time::Instant::now() + REFRESH_BUDGET,
        }
    }

    fn seed_knowledge(&mut self, knowledge: &Knowledge) {
        for host in &self.hosts {
            let Some(entry) = knowledge.hosts.get(host) else {
                continue;
            };
            let mut addresses: Vec<_> = entry
                .addresses
                .iter()
                .filter(|address| address.verified_at != 0)
                .collect();
            addresses.sort_unstable_by_key(|address| std::cmp::Reverse(address.verified_at));
            let mut saved = Vec::new();
            for address in addresses {
                if !saved.contains(&address.ip)
                    && saved
                        .iter()
                        .filter(|ip: &&IpAddr| ip.is_ipv6() == address.ip.is_ipv6())
                        .count()
                        < MAX_PROBE_CANDIDATES
                {
                    saved.push(address.ip);
                }
            }
            if !saved.is_empty() {
                self.saved.insert(host.clone(), saved);
            }
        }
    }

    fn accepts_resolver_candidate(&self, address: IpAddr) -> bool {
        crate::cf_proxy_doh::is_usable_edge_ip(&address)
            && (self.prefixes.is_empty() || is_meta_ip(&self.prefixes, address))
    }
}

impl MetaNetwork for DirectMetaNetwork {
    fn includes_host(&self, host: &str) -> bool {
        self.hosts.iter().any(|name| name == host)
    }
    fn ordered_hosts(&self) -> Vec<String> {
        self.hosts.clone()
    }

    fn resolve<'a>(&'a self) -> NetFuture<'a, Result<DnsAnswers, String>> {
        Box::pin(async move {
            let deadline = self
                .deadline
                .min(tokio::time::Instant::now() + RESOLVE_BUDGET - Duration::from_secs(1));
            let lookup_deadline = deadline
                .min(tokio::time::Instant::now() + RESOLVE_BUDGET - Duration::from_secs(10));
            let tls = doh_tls(None).ok();
            let mut results = self.saved.clone();
            {
                let mut candidates = self.candidates.lock().expect("поток Meta DNS");
                for (host, addresses) in &results {
                    for address in addresses {
                        candidates.insert((host.clone(), *address), "сохранённый адрес".into());
                    }
                }
            }
            let replies = stream::iter(self.hosts.clone())
                .map(|host| {
                    let tls = &tls;
                    async move {
                        if tokio::time::Instant::now() >= lookup_deadline {
                            return None;
                        }
                        self.attempted
                            .lock()
                            .expect("поток Meta DNS")
                            .insert(host.clone());
                        let mut addresses: Vec<_> = self
                            .saved
                            .get(&host)
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .map(|ip| (ip, "сохранённый адрес"))
                            .collect();
                        // A saved address is useful after reboot without any external DNS,
                        // but an old failed address must not prevent trying another source.
                        for (address, _) in &addresses {
                            if is_meta_ip(&self.prefixes, *address)
                                && self.verify(&host, *address).await
                            {
                                return Some((host, addresses));
                            }
                        }
                        addresses.clear();
                        let lookup_name = host.clone();
                        let system = tokio::time::timeout(
                            Duration::from_millis(750),
                            tokio::net::lookup_host((lookup_name.as_str(), 443)),
                        )
                        .await;
                        let local = system.map(|reply| {
                            reply.map(|ips| ips.take(16).map(|ip| ip.ip()).collect::<Vec<_>>())
                        });
                        let diagnosis = match local {
                            Ok(Ok(ref ips)) if !self.prefixes.is_empty() => {
                                if ips.is_empty() {
                                    "нет адресов"
                                } else if !ips.iter().any(|ip| is_meta_ip(&self.prefixes, *ip)) {
                                    "адреса вне префиксов Meta"
                                } else {
                                    "получены адреса Meta"
                                }
                            }
                            Ok(Ok(_)) => "получен ответ",
                            _ => "не ответил",
                        };
                        self.local_dns
                            .lock()
                            .expect("поток локального DNS")
                            .insert(host.clone(), diagnosis);
                        if let Ok(Ok(ips)) = local {
                            for ip in ips.into_iter().filter(|ip| {
                                crate::cf_proxy_doh::is_usable_edge_ip(ip)
                                    && is_meta_ip(&self.prefixes, *ip)
                            }) {
                                if !addresses.iter().any(|(known, _)| *known == ip)
                                    && addresses
                                        .iter()
                                        .filter(|(known, _)| known.is_ipv6() == ip.is_ipv6())
                                        .count()
                                        < MAX_PROBE_CANDIDATES
                                {
                                    addresses.push((ip, "системный DNS"));
                                }
                            }
                        }
                        {
                            let mut candidates = self.candidates.lock().expect("поток Meta DNS");
                            for (ip, source) in &addresses {
                                candidates.insert((host.clone(), *ip), (*source).into());
                            }
                        }
                        for (address, source) in &addresses {
                            if *source == "системный DNS" && self.verify(&host, *address).await
                            {
                                return Some((host, addresses));
                            }
                        }
                        addresses.clear();
                        if let Some(tls) = tls {
                            for (ip, source) in protected_address_lookup(&host, tls).await {
                                if self.accepts_resolver_candidate(ip)
                                    && !addresses.iter().any(|(known, _)| *known == ip)
                                    && addresses
                                        .iter()
                                        .filter(|(known, _)| known.is_ipv6() == ip.is_ipv6())
                                        .count()
                                        < MAX_PROBE_CANDIDATES
                                {
                                    addresses.push((ip, source));
                                }
                            }
                        }
                        Some((host, addresses))
                    }
                })
                .buffer_unordered(2);
            futures_util::pin_mut!(replies);
            while let Ok(Some(reply)) =
                tokio::time::timeout_at(lookup_deadline, replies.next()).await
            {
                let Some((host, addresses)) = reply else {
                    break;
                };
                let mut candidates = self.candidates.lock().expect("поток Meta DNS");
                for (ip, provider) in &addresses {
                    candidates
                        .entry((host.clone(), *ip))
                        .or_insert_with(|| (*provider).into());
                }
                results.insert(host, addresses.into_iter().map(|(ip, _)| ip).collect());
            }
            let missing: Vec<_> = {
                let checks = self.checks.lock().expect("поток Meta TLS");
                self.attempted
                    .lock()
                    .expect("поток Meta DNS")
                    .iter()
                    .filter(|host| {
                        results.get(*host).is_none_or(|ips| {
                            !ips.iter().any(|ip| {
                                self.accepts_resolver_candidate(*ip)
                                    && checks
                                        .get(&((*host).clone(), *ip))
                                        .is_none_or(Result::is_ok)
                            })
                        })
                    })
                    .take(8)
                    .cloned()
                    .collect()
            };
            let fallback = tokio::time::timeout_at(deadline, controller_dns_fallback(&missing))
                .await
                .unwrap_or_default();
            let mut candidates = self.candidates.lock().expect("поток Meta DNS");
            for (host, addresses) in fallback {
                let ips = results.entry(host.clone()).or_default();
                for (ip, provider) in addresses {
                    if self.accepts_resolver_candidate(ip)
                        && !ips.contains(&ip)
                        && ips
                            .iter()
                            .filter(|known| known.is_ipv6() == ip.is_ipv6())
                            .count()
                            < MAX_PROBE_CANDIDATES
                    {
                        candidates.insert((host.clone(), ip), provider);
                        ips.push(ip);
                    }
                }
            }
            if results.values().all(Vec::is_empty) {
                return Err("источники DNS и сохранённые адреса Meta недоступны".into());
            }
            Ok(results)
        })
    }

    fn verify<'a>(&'a self, host: &'a str, address: IpAddr) -> NetFuture<'a, bool> {
        Box::pin(async move {
            if let Some(result) = self
                .checks
                .lock()
                .expect("поток Meta TLS")
                .get(&(host.to_owned(), address))
            {
                return result.is_ok();
            }
            if tokio::time::Instant::now() >= self.deadline {
                return false;
            }
            self.attempted
                .lock()
                .expect("поток Meta DNS")
                .insert(host.to_owned());
            let result = match self
                .tls
                .get_or_init(|| MetaTls::new(self.ca_bundle.as_deref()))
            {
                Ok(tls) => tls.verify(host, address).await,
                Err(error) => Err(error.clone()),
            };
            let verified = result.is_ok();
            let result = result.map(|evidence| {
                self.cert_names
                    .lock()
                    .expect("поток Meta TLS")
                    .extend(evidence.certificate_names);
                evidence.http_status
            });
            self.checks
                .lock()
                .expect("поток Meta TLS")
                .insert((host.to_owned(), address), result);
            verified
        })
    }
}

async fn controller_dns_fallback(hosts: &[String]) -> BTreeMap<String, Vec<(IpAddr, String)>> {
    let Some(manager) = std::env::var_os("R2O_MANAGER") else {
        return BTreeMap::new();
    };
    if hosts.is_empty() {
        return BTreeMap::new();
    }
    let root = std::env::var_os("R2O_DIR").unwrap_or_else(|| "/opt/r2o".into());
    let mut command = tokio::process::Command::new(manager);
    command
        .arg("exec")
        .arg("--root")
        .arg(root)
        .args([
            "--component",
            "r2o-controller",
            "--",
            "--meta-encrypted-resolve",
        ])
        .args(hosts)
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .ok()
        .and_then(Result::ok)
        .filter(|output| output.status.success() && output.stdout.len() <= 32 * 1024)
        .and_then(|output| serde_json::from_slice(&output.stdout).ok())
        .unwrap_or_default()
}

pub async fn resolve_meta_direct() -> Result<DnsAnswers, String> {
    DirectMetaNetwork::new(None).resolve().await
}

pub struct SystemNdm {
    executable: OsString,
}

impl Default for SystemNdm {
    fn default() -> Self {
        Self {
            executable: OsString::from("ndmc"),
        }
    }
}

impl Ndm for SystemNdm {
    fn requires_exclusive_hostname(&self) -> bool {
        true
    }

    fn supports_address(&self, address: IpAddr) -> bool {
        // Синтаксис статического AAAA в ndmc зависит от прошивки.
        address.is_ipv4()
    }

    fn running_config(&mut self) -> Result<String, String> {
        let output = ndmc(&self.executable, "show running-config")?;
        let config = String::from_utf8(output.stdout)
            .map_err(|_| "ndmc вернул конфигурацию в неподдерживаемой кодировке".to_string())?;
        if !output.status.success() || config.trim().is_empty() {
            return Err("ndmc вернул пустую конфигурацию или сообщил об ошибке чтения".into());
        }
        Ok(config)
    }

    fn add(&mut self, host: &str, address: IpAddr) -> Result<(), String> {
        ndmc(&self.executable, &format!("ip host {host} {address}"))
            .and_then(command_success("ndmc отклонил добавление DNS-записи"))
    }

    fn remove(&mut self, host: &str, address: IpAddr) -> Result<(), String> {
        ndmc(&self.executable, &format!("no ip host {host} {address}"))
            .and_then(command_success("ndmc отклонил удаление DNS-записи"))
    }

    fn save(&mut self) -> Result<(), String> {
        ndmc(&self.executable, "system configuration save").and_then(command_success(
            "ndmc не смог сохранить конфигурацию роутера",
        ))
    }
}

fn ndmc(executable: &OsString, command: &str) -> Result<std::process::Output, String> {
    Command::new(executable)
        .env("LD_LIBRARY_PATH", "")
        .args(["-c", command])
        .output()
        .map_err(|error| format!("не удалось запустить ndmc: {error}"))
}

/// Проверить наличие программы в PATH без запуска.
/// `ndmc -c show version` нельзя использовать как probe: D2O не делает
/// такого вызова, а differential-тест сравнивает точную трассу команд.
fn command_exists(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| directory.join(program).is_file())
}

fn dnsmasq_section(host: &str, address: IpAddr) -> String {
    if address.is_ipv6() || host.len() > 72 {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(format!("{host} {address}").as_bytes());
        return format!("r2o_meta_{}", hex::encode(&digest[..16]));
    }
    let host = host
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>();
    format!("r2o_meta_{host}_{}", address.to_string().replace('.', "_"))
}

fn command_success(
    message: &'static str,
) -> impl FnOnce(std::process::Output) -> Result<(), String> {
    move |output| {
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{message} (exit {})",
                output.status.code().unwrap_or(-1)
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub struct MetaDnsPaths {
    pub r2o_dir: PathBuf,
    pub meta_ranges: PathBuf,
    pub manifest: PathBuf,
    pub log: PathBuf,
    pub success_mark: PathBuf,
}

impl MetaDnsPaths {
    pub fn from_env() -> Self {
        let r2o_dir = std::env::var_os("R2O_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/opt/r2o"));
        Self {
            meta_ranges: std::env::var_os("R2O_META_RANGES")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| default_meta_ranges_path(&r2o_dir)),
            manifest: std::env::var_os("R2O_INSTAGRAM_MANIFEST")
                .map(PathBuf::from)
                .unwrap_or_else(|| r2o_dir.join("state/instagram-ip-hosts.tsv")),
            log: std::env::var_os("R2O_INSTAGRAM_LOG")
                .map(PathBuf::from)
                .unwrap_or_else(|| r2o_dir.join("log/instagram-dns.log")),
            success_mark: std::env::var_os("R2O_INSTAGRAM_SCHED_STATE")
                .map(PathBuf::from)
                .unwrap_or_else(|| r2o_dir.join("state/instagram-dns-last-success")),
            r2o_dir,
        }
    }
}

/// Актуальный список диапазонов Meta: сначала база, обновлённая ночным
/// загрузчиком, затем поставляемый с выпуском снимок. Пустой файл в state
/// считается отсутствующим, чтобы повреждённое обновление не отключило
/// проверку диапазонов.
pub(crate) fn default_meta_ranges_path(r2o_dir: &Path) -> PathBuf {
    let updated = r2o_dir.join("state/lists/meta-ranges.txt");
    if let Ok(body) = std::fs::read_to_string(&updated)
        && parse_meta_ranges(&body)
            .map(|ranges| ranges.len() >= 10)
            .unwrap_or(false)
    {
        return updated;
    }
    r2o_dir.join("files/meta-ranges.txt")
}

pub struct MetaDnsManager<N, D> {
    network: N,
    ndm: D,
    dnsmasq: Option<DnsmasqHosts>,
    paths: MetaDnsPaths,
    meta_ranges: Vec<(IpAddr, u8)>,
    probe_attempts: usize,
    probe_retry_delay: Duration,
    resolve_attempts: usize,
    resolve_retry_delay: Duration,
    deadline: tokio::time::Instant,
}

impl<N: MetaNetwork> MetaDnsManager<N, SystemNdm> {
    fn from_system(network: N, paths: MetaDnsPaths) -> Self {
        let mut manager = Self::new(network, SystemNdm::default(), paths);
        if !command_exists("ndmc") && Path::new("/etc/init.d/dnsmasq").is_file() {
            manager.dnsmasq = Some(DnsmasqHosts::default());
        }
        manager
    }
}

impl<N: MetaNetwork, D: Ndm> MetaDnsManager<N, D> {
    pub fn new(network: N, ndm: D, paths: MetaDnsPaths) -> Self {
        Self {
            network,
            ndm,
            dnsmasq: None,
            paths,
            meta_ranges: Vec::new(),
            probe_attempts: env_bounded("R2O_IP_PROBE_ATTEMPTS", 2, 1, 5) as usize,
            probe_retry_delay: Duration::from_secs(env_bounded(
                "R2O_IP_PROBE_RETRY_DELAY",
                1,
                0,
                60,
            )),
            resolve_attempts: env_bounded("R2O_RESOLVE_ATTEMPTS", 3, 1, 8) as usize,
            resolve_retry_delay: Duration::from_secs(env_bounded(
                "R2O_RESOLVE_RETRY_DELAY",
                3,
                0,
                120,
            )),
            deadline: tokio::time::Instant::now() + REFRESH_BUDGET,
        }
    }

    fn pins(&self) -> Result<Vec<(String, IpAddr)>, String> {
        match &self.dnsmasq {
            Some(dnsmasq) => dnsmasq.records(),
            None => read_manifest(&self.paths.manifest),
        }
    }

    pub async fn refresh(&mut self) -> Result<(), String> {
        if self.meta_ranges.is_empty() {
            let ranges = std::fs::read_to_string(&self.paths.meta_ranges).map_err(|error| {
                format!(
                    "не удалось прочитать диапазоны Meta из {}: {error}",
                    self.paths.meta_ranges.display()
                )
            })?;
            self.meta_ranges = parse_meta_ranges(&ranges)?;
        }
        if self.meta_ranges.is_empty() {
            return Err("в файле диапазонов Meta нет допустимых сетей".into());
        }
        let mut prior = self.pins()?;
        let initial_config = if prior.is_empty() || self.dnsmasq.is_some() {
            None
        } else {
            let config = self.ndm.running_config()?;
            if config.trim().is_empty() {
                return Err("ndmc вернул пустую текущую конфигурацию".into());
            }
            Some(config)
        };
        let order: BTreeMap<_, _> = self
            .network
            .ordered_hosts()
            .into_iter()
            .enumerate()
            .map(|(index, host)| (host, index))
            .collect();
        let mut prior_checks: Vec<_> = prior
            .iter()
            .filter(|(host, address)| {
                is_managed_host(host)
                    && self.network.includes_host(host)
                    && (self.dnsmasq.is_some()
                        || initial_config
                            .as_deref()
                            .is_some_and(|config| config_has_pair(config, host, *address)))
            })
            .collect();
        prior_checks
            .sort_unstable_by_key(|(host, _)| order.get(host).copied().unwrap_or(usize::MAX));
        let prior_deadline = self
            .deadline
            .min(tokio::time::Instant::now() + RESOLVE_BUDGET);
        let mut dead = Vec::new();
        let mut retained_verified = BTreeMap::<String, Vec<IpAddr>>::new();
        {
            let manager = &*self;
            let prior_checks = stream::iter(prior_checks)
                .map(|(host, address)| async move {
                    let verified = is_meta_ip(&manager.meta_ranges, *address)
                        && verify_with_retry(
                            &manager.network,
                            host,
                            *address,
                            manager.probe_attempts,
                            manager.probe_retry_delay,
                            &manager.paths.log,
                            prior_deadline,
                        )
                        .await;
                    (host, address, verified)
                })
                .buffered(4);
            futures_util::pin_mut!(prior_checks);
            while let Ok(Some((host, address, verified))) =
                tokio::time::timeout_at(prior_deadline, prior_checks.next()).await
            {
                if verified {
                    retained_verified
                        .entry(host.clone())
                        .or_default()
                        .push(*address);
                } else {
                    dead.push((host.clone(), *address));
                    append_log(
                        &self.paths.log,
                        &format!("своя запись не прошла TLS-проверку: {host} {address}"),
                    );
                }
            }
        }

        let answers = match resolve_with_retry(
            &self.network,
            self.resolve_attempts,
            self.resolve_retry_delay,
            &self.paths.log,
            self.deadline
                .min(tokio::time::Instant::now() + RESOLVE_BUDGET),
        )
        .await
        {
            Ok(answers) => answers,
            Err(error) => {
                append_log(
                    &self.paths.log,
                    &format!(
                        "DNS недоступен ({error}); проверяем сохранённые адреса и адреса семейства"
                    ),
                );
                BTreeMap::new()
            }
        };

        let mut filtered = BTreeMap::<String, Vec<IpAddr>>::new();
        let mut ordered_answers: Vec<_> = answers.iter().collect();
        ordered_answers
            .sort_unstable_by_key(|(host, _)| order.get(*host).copied().unwrap_or(usize::MAX));
        for (host, ips) in ordered_answers {
            if tokio::time::Instant::now() >= self.deadline {
                append_log(
                    &self.paths.log,
                    "Достигнут бюджет обновления Meta; непроверенные имена отложены, прежние DNS-записи сохранены",
                );
                break;
            }
            if !is_managed_host(host) {
                continue;
            }
            let manager = &*self;
            let check_family = |ipv6| async move {
                stream::iter(
                    ips.iter()
                        .copied()
                        .filter(|ip| ip.is_ipv6() == ipv6 && is_meta_ip(&manager.meta_ranges, *ip))
                        .take(MAX_PROBE_CANDIDATES),
                )
                .map(|address| async move {
                    verify_with_retry(
                        &manager.network,
                        host,
                        address,
                        manager.probe_attempts,
                        manager.probe_retry_delay,
                        &manager.paths.log,
                        manager.deadline,
                    )
                    .await
                    .then_some(address)
                })
                .buffered(2)
                .filter_map(std::future::ready)
                .take(MAX_HOST_ADDRESSES)
                .collect::<Vec<_>>()
                .await
            };
            let (mut verified, verified_v6) = tokio::join!(check_family(false), check_family(true));
            verified.extend(verified_v6);
            if !verified.is_empty() {
                filtered.insert(host.clone(), verified);
            }
        }

        // A DNS outage does not invalidate a previously installed address that
        // just passed its own TLS check. Keep it eligible for family fallback.
        for (host, addresses) in retained_verified {
            let fresh = filtered.entry(host).or_default();
            let fresh_v4 = fresh.iter().any(IpAddr::is_ipv4);
            let fresh_v6 = fresh.iter().any(IpAddr::is_ipv6);
            for address in addresses {
                if (address.is_ipv4() && !fresh_v4) || (address.is_ipv6() && !fresh_v6) {
                    fresh.push(address);
                }
            }
        }

        apply_family_fallback(
            &self.network,
            &self.meta_ranges,
            ProbePolicy {
                attempts: self.probe_attempts,
                retry_delay: self.probe_retry_delay,
                log: &self.paths.log,
                deadline: self.deadline,
            },
            &answers,
            &prior,
            &dead,
            &mut filtered,
        )
        .await;
        if filtered.is_empty() {
            append_log(
                &self.paths.log,
                "нет адресов Meta с доступным TLS и подходящим сертификатом; остальные DNS-записи не изменены",
            );
            return Err("нет проверенных адресов узлов Meta".into());
        }

        if !protection_enabled(&state_dirs(&self.paths).0) {
            return Err("Meta Protection выключена".into());
        }
        if let Some(dnsmasq) = &self.dnsmasq {
            let legacy = dnsmasq::retire_legacy(&self.paths.manifest)?;
            if !legacy.is_empty() {
                append_log(
                    &self.paths.log,
                    "Старые записи Meta сняты с конфигурации UCI и останутся в памяти до штатного перезапуска dnsmasq",
                );
                filtered.retain(|host, _| !legacy.contains(host));
                prior.retain(|(host, _)| !legacy.contains(host));
            }
            dnsmasq.publish(&openwrt_pins(&prior, &filtered))?;
            return self.mark_success();
        }
        let mut view = NdmView::new(&mut self.ndm);
        view.config = initial_config;
        let mut next = BTreeSet::<PinPair>::new();
        for (host, address) in read_manifest(&self.paths.manifest)? {
            if is_managed_host(&host) && view.exists(&host, address)? {
                next.insert((host, address.to_string()));
            }
        }

        let mut add_failed = false;
        let mut published = DnsAnswers::new();
        for (host, addresses) in &filtered {
            // На Keenetic не меняем имя, для которого есть пользовательская запись.
            if view.ndm.requires_exclusive_hostname()
                && configured_host_addresses(view.config()?, host)
                    .any(|ip| !next.contains(&(host.clone(), ip.to_string())))
            {
                continue;
            }
            for address in addresses {
                if !view.ndm.supports_address(*address) {
                    continue;
                }
                if view.exists(host, *address)? {
                    published.entry(host.clone()).or_default().push(*address);
                    continue;
                }
                let pair = (host.clone(), address.to_string());
                next.insert(pair.clone());
                write_manifest(&self.paths.manifest, &next)?;
                match view.add(host, *address) {
                    Ok(()) => {
                        published.entry(host.clone()).or_default().push(*address);
                        append_log(
                            &self.paths.log,
                            &format!("добавлена R2O-запись {host} {address}"),
                        );
                    }
                    Err(error) => {
                        next.remove(&pair);
                        write_manifest(&self.paths.manifest, &next)?;
                        add_failed = true;
                        append_log(
                            &self.paths.log,
                            &format!("ошибка добавления {host} {address}: {error}"),
                        );
                    }
                }
            }
        }
        if add_failed {
            view.save_if_changed()?;
            return Err("ndmc отклонил одну или несколько новых DNS-записей Meta".into());
        }

        for (host, address) in read_manifest(&self.paths.manifest)? {
            let Some(fresh) = published.get(&host) else {
                continue;
            };
            if fresh.contains(&address) || !fresh.iter().any(|ip| ip.is_ipv6() == address.is_ipv6())
            {
                continue;
            }
            if view.exists(&host, address)? {
                view.remove(&host, address)?;
                append_log(
                    &self.paths.log,
                    &format!("удалена устаревшая R2O-запись {host} {address}"),
                );
            }
            next.remove(&(host, address.to_string()));
        }

        view.save_if_changed()?;
        write_manifest(&self.paths.manifest, &next)?;
        self.mark_success()
    }

    fn mark_success(&self) -> Result<(), String> {
        if let Err(error) = write_success_mark(&self.paths.success_mark) {
            append_log(
                &self.paths.log,
                &format!("обновление успешно, но дату запуска не удалось сохранить: {error}"),
            );
        }
        append_log(
            &self.paths.log,
            "обновление DNS Instagram/WhatsApp завершено",
        );
        Ok(())
    }

    pub fn remove_owned(&mut self) -> Result<(), String> {
        self.remove_owned_where(|_| true)
    }

    fn remove_owned_where(&mut self, remove_host: impl Fn(&str) -> bool) -> Result<(), String> {
        if let Some(dnsmasq) = &self.dnsmasq {
            let remaining = dnsmasq
                .records()?
                .into_iter()
                .filter(|(host, _)| !remove_host(host))
                .map(|(host, address)| (host, address.to_string()))
                .collect();
            dnsmasq.publish(&remaining)?;
            if dnsmasq::retire_legacy(&self.paths.manifest)?
                .iter()
                .any(|host| remove_host(host))
            {
                return Err(
                    "старые записи Meta останутся в памяти до штатного перезапуска dnsmasq".into(),
                );
            }
            return Ok(());
        }
        let manifest = read_manifest(&self.paths.manifest)?;
        if manifest.is_empty() {
            let _ = std::fs::remove_file(&self.paths.manifest);
            append_log(&self.paths.log, "нет R2O-owned Meta DNS записей");
            return Ok(());
        }
        let mut view = NdmView::new(&mut self.ndm);
        let mut remaining = BTreeSet::new();
        let mut matched = false;
        for (host, address) in manifest {
            if !is_managed_host(&host) || !remove_host(&host) {
                remaining.insert((host, address.to_string()));
                continue;
            }
            matched = true;
            if view.exists(&host, address)? {
                view.remove(&host, address)?;
                append_log(
                    &self.paths.log,
                    &format!("удалена R2O-запись {host} {address}"),
                );
            }
        }
        if !matched {
            return Ok(());
        }
        view.ndm.save()?;
        if remaining.is_empty() {
            std::fs::remove_file(&self.paths.manifest).map_err(|error| {
                format!(
                    "не удалось удалить журнал принадлежащих записей {}: {error}",
                    self.paths.manifest.display()
                )
            })
        } else {
            write_manifest(&self.paths.manifest, &remaining)
        }
    }
}

fn openwrt_pins(prior: &[(String, IpAddr)], fresh: &DnsAnswers) -> BTreeSet<PinPair> {
    prior
        .iter()
        .filter(|pair| {
            let (host, address) = pair;
            fresh.get(host).is_none_or(|addresses| {
                addresses.contains(address)
                    || !addresses.iter().any(|ip| ip.is_ipv6() == address.is_ipv6())
            })
        })
        .map(|(host, address)| (host.clone(), address.to_string()))
        .chain(fresh.iter().flat_map(|(host, addresses)| {
            addresses
                .iter()
                .map(|address| (host.clone(), address.to_string()))
        }))
        .collect()
}

async fn resolve_with_retry<N: MetaNetwork>(
    network: &N,
    attempts: usize,
    retry_delay: Duration,
    log: &Path,
    deadline: tokio::time::Instant,
) -> Result<BTreeMap<String, Vec<IpAddr>>, String> {
    let mut last_error = None;
    for attempt in 1..=attempts {
        let reply = tokio::time::timeout_at(deadline, network.resolve())
            .await
            .unwrap_or_else(|_| Err("достигнут бюджет получения адресов Meta".into()));
        match reply {
            Ok(answers) => return Ok(answers),
            Err(error) => {
                last_error = Some(error);
                append_log(
                    log,
                    &format!("прямой DNS-запрос: попытка {attempt}/{attempts} не удалась"),
                );
                if attempt < attempts
                    && (tokio::time::Instant::now() >= deadline
                        || tokio::time::timeout_at(deadline, sleep(retry_delay))
                            .await
                            .is_err())
                {
                    break;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| "прямой DNS-запрос не выполнен".into()))
}

async fn verify_with_retry<N: MetaNetwork>(
    network: &N,
    host: &str,
    address: IpAddr,
    attempts: usize,
    retry_delay: Duration,
    log: &Path,
    deadline: tokio::time::Instant,
) -> bool {
    for attempt in 1..=attempts {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        if tokio::time::timeout_at(deadline, network.verify(host, address))
            .await
            .unwrap_or(false)
        {
            return true;
        }
        if attempt < attempts {
            append_log(
                log,
                &format!("повтор TLS-пробы {attempt}/{attempts}: {host} {address}"),
            );
            if tokio::time::timeout_at(deadline, sleep(retry_delay))
                .await
                .is_err()
            {
                return false;
            }
        }
    }
    false
}

async fn apply_family_fallback<N: MetaNetwork>(
    network: &N,
    ranges: &[(IpAddr, u8)],
    policy: ProbePolicy<'_>,
    answers: &BTreeMap<String, Vec<IpAddr>>,
    prior: &[(String, IpAddr)],
    dead: &[(String, IpAddr)],
    filtered: &mut BTreeMap<String, Vec<IpAddr>>,
) {
    let mut hosts = network.ordered_hosts();
    if hosts.is_empty() {
        hosts = META_HOSTS.iter().map(|host| (*host).to_owned()).collect();
    }
    for host in &hosts {
        if tokio::time::Instant::now() >= policy.deadline {
            break;
        }
        if !network.includes_host(host) || filtered.contains_key(host) {
            continue;
        }
        let Some(family) = meta_family(host) else {
            continue;
        };
        let answered: BTreeSet<_> = answers.get(host).into_iter().flatten().copied().collect();
        let mut candidates = Vec::new();
        for (sibling, addresses) in filtered.iter() {
            candidates.extend(addresses.iter().map(|address| (sibling.clone(), *address)));
        }
        candidates.extend(
            prior
                .iter()
                .map(|(sibling, address)| (sibling.clone(), *address)),
        );
        let mut seen = BTreeSet::new();
        let mut tries = 0;
        let mut verified = Vec::new();
        for (sibling, address) in candidates {
            if sibling == *host
                || meta_family(&sibling) != Some(family)
                || dead
                    .iter()
                    .any(|(dead_host, dead_ip)| dead_host == &sibling && *dead_ip == address)
                || answered.contains(&address)
                || !seen.insert(address)
                || !is_meta_ip(ranges, address)
            {
                continue;
            }
            if tries >= MAX_PROBE_CANDIDATES {
                break;
            }
            tries += 1;
            if verify_with_retry(
                network,
                host,
                address,
                policy.attempts,
                policy.retry_delay,
                policy.log,
                policy.deadline,
            )
            .await
            {
                verified.push(address);
                append_log(
                    policy.log,
                    &format!(
                        "адрес семейства: {host} {address} (от {sibling}), сертификат проверен для {host}"
                    ),
                );
                if verified.len() == MAX_HOST_ADDRESSES {
                    break;
                }
            }
        }
        if !verified.is_empty() {
            filtered.insert(host.clone(), verified);
        }
    }
}

pub(crate) fn is_meta_ip(ranges: &[(IpAddr, u8)], address: IpAddr) -> bool {
    use crate::cf_proxy_doh::is_usable_edge_ip;
    if !is_usable_edge_ip(&address)
        || matches!(address, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
    {
        return false;
    }
    ranges
        .iter()
        .any(|(network, prefix)| match (network, address) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                u32::from(*net) >> (32 - prefix) == u32::from(ip) >> (32 - prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(*net) >> (128 - prefix) == u128::from(ip) >> (128 - prefix)
            }
            _ => false,
        })
}

fn config_has_pair(config: &str, host: &str, address: IpAddr) -> bool {
    configured_host_addresses(config, host).any(|found| found == address)
}

fn configured_host_addresses<'a>(
    config: &'a str,
    host: &'a str,
) -> impl Iterator<Item = IpAddr> + 'a {
    config.lines().filter_map(move |line| {
        let mut fields = line.split_ascii_whitespace();
        let (Some("ip"), Some("host"), Some(name), Some(address)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return None;
        };
        name.eq_ignore_ascii_case(host)
            .then(|| address.parse().ok())
            .flatten()
    })
}

struct NdmView<'a, D> {
    ndm: &'a mut D,
    config: Option<String>,
    changed: bool,
}

impl<'a, D: Ndm> NdmView<'a, D> {
    fn new(ndm: &'a mut D) -> Self {
        Self {
            ndm,
            config: None,
            changed: false,
        }
    }

    fn config(&mut self) -> Result<&str, String> {
        if self.config.is_none() {
            let config = self.ndm.running_config()?;
            if config.trim().is_empty() {
                return Err("ndmc вернул пустую текущую конфигурацию".into());
            }
            self.config = Some(config);
        }
        Ok(self.config.as_deref().expect("конфигурация уже загружена"))
    }

    fn exists(&mut self, host: &str, address: IpAddr) -> Result<bool, String> {
        Ok(config_has_pair(self.config()?, host, address))
    }

    fn add(&mut self, host: &str, address: IpAddr) -> Result<(), String> {
        let result = self.ndm.add(host, address);
        self.changed = true;
        if result.is_ok()
            && let Some(config) = &mut self.config
        {
            config.push_str(&format!("\nip host {host} {address}\n"));
        }
        result
    }

    fn remove(&mut self, host: &str, address: IpAddr) -> Result<(), String> {
        let result = self.ndm.remove(host, address);
        self.changed = true;
        self.config = None;
        result
    }

    fn save_if_changed(&mut self) -> Result<(), String> {
        if self.changed {
            self.ndm.save()?;
            self.changed = false;
        }
        Ok(())
    }
}

fn state_dirs(paths: &MetaDnsPaths) -> (PathBuf, PathBuf) {
    let state = std::env::var_os("R2O_META_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| paths.r2o_dir.join("state"));
    let runtime = std::env::var_os("R2O_RUNTIME_DIR")
        .or_else(|| std::env::var_os("R2O_RUN_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| paths.r2o_dir.join("run"));
    (state, runtime)
}

fn state_lock(state: &Path) -> Result<std::fs::File, String> {
    std::fs::create_dir_all(state).map_err(|error| error.to_string())?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join("meta-protection.lock"))
        .map_err(|error| error.to_string())?;
    lock.try_lock()
        .map_err(|error| format!("Meta Protection: операция уже выполняется: {error}"))?;
    Ok(lock)
}

pub async fn refresh_from_env() -> Result<(), String> {
    refresh_knowledge(true).await
}

async fn refresh_knowledge(force: bool) -> Result<(), String> {
    let paths = MetaDnsPaths::from_env();
    let (state, runtime) = state_dirs(&paths);
    let _lock = state_lock(&state)?;
    if !protection_enabled(&state) {
        return Err("Meta Protection выключена".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let mut knowledge = Knowledge::load(&state);
    let disabled = r2k_core::meta::disabled_products(&state);
    if !disabled.is_empty() {
        let mut cleanup = MetaDnsManager::from_system(DirectMetaNetwork::new(None), paths.clone());
        let inactive = |host: &str| is_disabled_host(&disabled, host);
        match cleanup.remove_owned_where(inactive) {
            Ok(()) => clear_pin_status(&mut knowledge, inactive),
            Err(error) => append_log(&paths.log, &error),
        }
    }
    knowledge.refresh_sources(&crate::list_update::ListPaths::from_env(), &runtime, now);
    let network = DirectMetaNetwork::new(std::env::var_os("R2O_IP_CA_BUNDLE").map(PathBuf::from));
    let mut manager = MetaDnsManager::from_system(network, paths);
    let restore = manager
        .dnsmasq
        .as_ref()
        .is_some_and(DnsmasqHosts::needs_refresh);
    let network = &mut manager.network;
    let paths = &manager.paths;
    network.hosts = knowledge.due(now, force || restore, |host| {
        !is_disabled_host(&disabled, host)
    });
    if network.hosts.is_empty() {
        if manager
            .dnsmasq
            .as_ref()
            .is_some_and(DnsmasqHosts::notification_pending)
        {
            let error = format!("{PENDING_APPLY_ERROR}снятие прежних записей не завершено");
            knowledge.error = Some(error.clone());
            knowledge.persist(&state)?;
            return Err(error);
        }
        return knowledge.persist(&state);
    }

    network.prefixes = knowledge.ranges();
    if network.prefixes.is_empty() || std::env::var_os("R2O_META_RANGES").is_some() {
        let fallback = if std::env::var_os("R2O_META_RANGES").is_some() {
            paths.meta_ranges.clone()
        } else {
            paths.r2o_dir.join("files/meta-ranges.txt")
        };
        if let Ok(body) = std::fs::read_to_string(fallback) {
            network.prefixes = parse_meta_ranges(&body)?;
        }
    }
    network.seed_knowledge(&knowledge);
    let ranges = network.prefixes.clone();
    manager.probe_attempts = 1;
    manager.resolve_attempts = 1;
    manager.meta_ranges = ranges;
    if std::env::var_os("R2O_META_RANGES").is_none() {
        manager.paths.meta_ranges = manager.paths.r2o_dir.join("files/meta-ranges.txt");
    }
    let result = manager.refresh().await;
    let pending = manager
        .dnsmasq
        .as_ref()
        .is_some_and(DnsmasqHosts::notification_pending);
    let result = if pending {
        Err(format!(
            "{PENDING_APPLY_ERROR}{}",
            result
                .err()
                .unwrap_or_else(|| "ожидается отправка сигнала dnsmasq".into())
        ))
    } else {
        result
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let mut recovery = Vec::new();
    let pins: BTreeSet<_> = if pending {
        knowledge
            .hosts
            .iter()
            .flat_map(|(host, entry)| {
                entry
                    .addresses
                    .iter()
                    .filter(|address| address.pinned)
                    .map(|address| (host.clone(), address.ip))
            })
            .collect()
    } else {
        manager.pins()?.into_iter().collect()
    };
    let candidates = manager
        .network
        .candidates
        .into_inner()
        .expect("поток Meta DNS");
    let checks = manager.network.checks.into_inner().expect("поток Meta TLS");
    let local_dns = manager
        .network
        .local_dns
        .into_inner()
        .expect("поток локального DNS");
    let attempted = manager
        .network
        .attempted
        .into_inner()
        .expect("поток Meta DNS");
    for name in manager
        .network
        .cert_names
        .into_inner()
        .expect("поток Meta TLS")
    {
        knowledge.add_host(&name, "certificate", 0);
    }

    for host in manager.network.hosts {
        if !attempted.contains(&host) {
            continue;
        }
        let ips: BTreeSet<_> = candidates
            .keys()
            .chain(checks.keys())
            .filter_map(|(name, ip)| (*name == host).then_some(*ip))
            .collect();
        let asns: BTreeMap<_, _> = ips.iter().map(|ip| (*ip, knowledge.asn(*ip))).collect();
        let entry = knowledge.hosts.get_mut(&host).expect("имя из базы");
        let mut verified_now = false;
        let mut last_failure = None;
        entry.local_dns = local_dns.get(&host).copied().unwrap_or_default().into();
        entry.dns_addresses = candidates
            .iter()
            .filter(|((name, _), source)| *name == host && source.as_str() != "сохранённый адрес")
            .count();
        for ip in ips {
            let key = (host.clone(), ip);
            let resolver = candidates
                .get(&key)
                .map(String::as_str)
                .unwrap_or("сохранённый адрес");
            let (verified, detail) = match checks.get(&key) {
                Some(Ok(status)) => (
                    true,
                    status.map_or_else(
                        || "TLS подтверждён".to_owned(),
                        |status| format!("TLS подтверждён · HTTP {status}"),
                    ),
                ),
                Some(Err(error)) => (false, error.clone()),
                None if !is_meta_ip(&manager.meta_ranges, ip) => {
                    (false, "вне подтверждённых префиксов Meta".into())
                }
                None => (false, "ожидает проверки".into()),
            };
            let old = entry.addresses.iter().find(|record| record.ip == ip);
            let verified_at = if verified {
                now
            } else {
                old.map_or(0, |record| record.verified_at)
            };
            verified_now |= verified;
            if !verified && !detail.starts_with("ожидает") {
                last_failure = Some(detail.clone());
            }
            entry.addresses.retain(|record| record.ip != ip);
            entry.addresses.push(Address {
                ip,
                asn: asns[&ip],
                resolver: resolver.to_string(),
                checked_at: now,
                verified_at,
                result: detail,
                pinned: pins.contains(&key),
            });
        }
        if !verified_now
            && entry.observed_at != 0
            && now.saturating_sub(entry.observed_at) <= 300
            && let Some(address) = entry.addresses.iter().find(|record| {
                record.checked_at == now
                    && record.asn.is_some()
                    && record.resolver != "сохранённый адрес"
                    && (record.result.starts_with("TCP:")
                        || record.result == "TLS: тайм-аут"
                        || record.result.starts_with("TLS: Connection reset")
                        || record.result.starts_with("TLS: unexpected end of file"))
            })
        {
            recovery.push((host.clone(), address.ip));
        }
        entry.addresses.sort_unstable_by_key(|addr| {
            (
                !addr.pinned,
                std::cmp::Reverse(addr.verified_at),
                std::cmp::Reverse(addr.checked_at),
            )
        });
        entry.addresses.truncate(12);
        entry.checked_at = now;
        entry.last_failure = if verified_now {
            None
        } else {
            last_failure
                .or_else(|| result.as_ref().err().cloned())
                .or_else(|| {
                    (entry.dns_addresses == 0).then(|| "источники DNS не вернули адреса".into())
                })
        };
    }
    for (host, entry) in &mut knowledge.hosts {
        for address in &mut entry.addresses {
            address.pinned = pins.contains(&(host.clone(), address.ip));
        }
    }
    knowledge.checked_at = now;
    knowledge.error = result.as_ref().err().cloned();
    if protection_enabled(&state) && !recovery.is_empty() {
        std::fs::create_dir_all(&runtime).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec(&(now, recovery)).map_err(|error| error.to_string())?;
        atomic_write(&runtime.join("meta-discovery-requests.json"), &bytes)?;
    }
    knowledge.persist(&state)?;
    result
}

pub fn remove_from_env() -> Result<(), String> {
    let paths = MetaDnsPaths::from_env();
    let (state, runtime) = state_dirs(&paths);
    let _lock = state_lock(&state)?;
    let mut manager = MetaDnsManager::from_system(DirectMetaNetwork::new(None), paths);
    manager.remove_owned()?;
    let mut knowledge = Knowledge::load(&state);
    clear_pin_status(&mut knowledge, |_| true);
    let _ = std::fs::remove_file(runtime.join("meta-discovery-requests.json"));
    for name in [
        "meta-observed-v4.json",
        "meta-observed-v6.json",
        "meta-observed-dual.json",
    ] {
        let _ = std::fs::remove_file(runtime.join(name));
    }
    knowledge.persist(&state)
}

fn is_disabled_host(disabled: &[&str], host: &str) -> bool {
    r2k_core::meta::product(host).is_some_and(|name| disabled.contains(&name))
}

fn clear_pin_status(knowledge: &mut Knowledge, matches: impl Fn(&str) -> bool) {
    for (name, host) in &mut knowledge.hosts {
        if matches(name) {
            for address in &mut host.addresses {
                address.pinned = false;
            }
        }
    }
}

pub fn set_product_from_env(product: &str, mode: &str) -> Result<(), String> {
    let paths = MetaDnsPaths::from_env();
    let (state, _) = state_dirs(&paths);
    let marker =
        r2k_core::meta::product_marker(&state, product).ok_or("неизвестный сервис Meta")?;
    let _lock = state_lock(&state)?;
    let mut knowledge = Knowledge::load(&state);
    let matches = |host: &str| r2k_core::meta::product(host) == Some(product);
    match mode {
        "on" => {
            if marker.exists() {
                for (host, entry) in &mut knowledge.hosts {
                    if matches(host) {
                        entry.checked_at = 0;
                    }
                }
                knowledge.persist(&state)?;
                std::fs::remove_file(marker).map_err(|error| error.to_string())?;
                match std::fs::remove_file(&paths.success_mark) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!("не удалось запланировать проверку Meta: {error}"));
                    }
                }
            }
            Ok(())
        }
        "off" => {
            atomic_write(&marker, b"0\n")?;
            let mut manager = MetaDnsManager::from_system(DirectMetaNetwork::new(None), paths);
            manager.remove_owned_where(matches)?;
            clear_pin_status(&mut knowledge, matches);
            knowledge.persist(&state)
        }
        _ => Err("ожидается on или off".into()),
    }
}

const PENDING_APPLY_ERROR: &str = "Meta DNS ожидает применения: ";

fn reconcile_pin_status(state: &Path, pins: &[(String, IpAddr)]) -> Result<(), String> {
    let mut knowledge = Knowledge::load(state);
    let pins: BTreeSet<_> = pins.iter().collect();
    let mut changed = false;
    for (host, entry) in &mut knowledge.hosts {
        for address in &mut entry.addresses {
            let pinned = pins.contains(&(host.clone(), address.ip));
            changed |= address.pinned != pinned;
            address.pinned = pinned;
        }
    }
    if knowledge
        .error
        .as_deref()
        .is_some_and(|error| error.starts_with(PENDING_APPLY_ERROR))
    {
        knowledge.error = None;
        changed = true;
    }
    if changed {
        knowledge.persist(state)
    } else {
        Ok(())
    }
}

pub async fn run_scheduler() -> Result<(), String> {
    let paths = MetaDnsPaths::from_env();
    let (state, _) = state_dirs(&paths);
    let openwrt = !command_exists("ndmc") && Path::new("/etc/init.d/dnsmasq").is_file();
    let dnsmasq = openwrt.then(DnsmasqHosts::default);
    let mut reconcile_pins = true;
    let mut scheduler = MetaDnsScheduler::from_env();
    let mut lists = crate::list_update::ListUpdater::from_env();
    let meta_disabled = std::env::var("R2O_META_DNS_DISABLED").as_deref() == Ok("1");
    let mut sync = Box::pin(async {
        loop {
            if protection_enabled(&state) && !meta_disabled {
                let _ = lists.update_meta().await;
            }
            sleep(Duration::from_secs(3600)).await;
        }
    });
    loop {
        let cycle = async {
            if protection_enabled(&state) && !meta_disabled {
                if let Some(dnsmasq) = &dnsmasq {
                    reconcile_pins |= dnsmasq.notification_pending();
                    if reconcile_pins && let Ok(_lock) = state_lock(&state) {
                        match dnsmasq
                            .resume()
                            .and_then(|()| reconcile_pin_status(&state, &dnsmasq.records()?))
                        {
                            Ok(()) => reconcile_pins = false,
                            Err(error) => append_log(&scheduler.log, &error),
                        }
                    }
                }
                let restore = should_restore_hosts(
                    dnsmasq.as_ref().is_some_and(DnsmasqHosts::needs_refresh),
                    &state,
                );
                if let Err(error) = scheduler.tick(restore).await {
                    append_log(&scheduler.log, &error);
                }
            }
            sleep(scheduler.interval).await;
        };
        tokio::select! {
            _ = &mut sync => unreachable!(),
            _ = cycle => {},
        }
    }
}

fn should_restore_hosts(hosts_missing: bool, state: &Path) -> bool {
    hosts_missing && r2k_core::meta::disabled_products(state).len() < r2k_core::meta::PRODUCTS.len()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Clock {
    pub(crate) day: String,
    pub(crate) hhmm: String,
    pub(crate) epoch: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Attempt {
    pub(crate) last_epoch: u64,
    pub(crate) last_day: Option<String>,
    pub(crate) failures: u32,
}

struct MetaDnsScheduler {
    state: PathBuf,
    attempt: PathBuf,
    offset: PathBuf,
    log: PathBuf,
    interval: Duration,
    retry_after: u64,
    explicit_run_at: Option<String>,
}

impl MetaDnsScheduler {
    fn from_env() -> Self {
        let paths = MetaDnsPaths::from_env();
        let attempt = std::env::var_os("R2O_INSTAGRAM_SCHED_ATTEMPT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp/r2o-instagram-dns-last-attempt"));
        let offset = std::env::var_os("R2O_INSTAGRAM_SCHED_OFFSET")
            .map(PathBuf::from)
            .unwrap_or_else(|| paths.r2o_dir.join("state/instagram-dns-offset"));
        let log = std::env::var_os("R2O_INSTAGRAM_SCHED_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|| paths.r2o_dir.join("log/instagram-dns-scheduler.log"));
        Self {
            state: paths.success_mark,
            attempt,
            offset,
            log,
            interval: Duration::from_secs(env_bounded("R2O_SCHEDULER_INTERVAL", 60, 1, 3600)),
            retry_after: env_bounded("R2O_SCHEDULER_RETRY_AFTER", 1800, 1, 86400),
            explicit_run_at: std::env::var("R2O_INSTAGRAM_REFRESH_AT").ok(),
        }
    }

    async fn tick(&mut self, restore: bool) -> Result<(), String> {
        self.tick_with_refresh(local_clock()?, restore, || refresh_knowledge(true))
            .await
    }

    async fn tick_with_refresh<F, Fut>(
        &mut self,
        clock: Clock,
        restore: bool,
        refresh: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        let offset = self.refresh_offset()?;
        let run_at = self.run_at(offset);
        if !valid_hhmm(&run_at) {
            return Err("R2O_INSTAGRAM_REFRESH_AT должен содержать время HHMM".into());
        }
        let mut attempt = read_attempt(&self.attempt);
        // При переводе часов назад переносим начало ожидания один раз: иначе
        // старый epoch может блокировать восстановление до синхронизации NTP.
        if attempt.failures != 0 && attempt.last_epoch > clock.epoch {
            attempt.last_epoch = clock.epoch;
            attempt.last_day = Some(clock.day.clone());
            write_attempt(&self.attempt, &attempt)?;
        }
        // Неудача не становится новой попыткой из-за полуночи или потери /tmp.
        if clock.epoch.saturating_sub(attempt.last_epoch)
            < backoff_after(attempt.failures, self.retry_after)
        {
            return Ok(());
        }
        if !restore && !should_run(&self.state, &attempt, &clock, &run_at, self.retry_after) {
            return Ok(());
        }

        let next = Attempt {
            last_epoch: clock.epoch,
            last_day: Some(clock.day.clone()),
            failures: attempt.failures.saturating_add(1),
        };
        write_attempt(&self.attempt, &next)?;
        append_log(&self.log, "обновление DNS Meta: старт");
        // Даже пустой проход (например, все продукты отключены) завершает
        // суточную задачу. Отметка не зависит от наличия изменений в hosts.
        let result = refresh().await.and_then(|()| {
            atomic_write(
                &self.state,
                format!("{}\n{}\n", clock.day, clock.epoch).as_bytes(),
            )
        });
        match result {
            Ok(()) => {
                write_attempt(
                    &self.attempt,
                    &Attempt {
                        failures: 0,
                        ..next
                    },
                )?;
                append_log(
                    &self.log,
                    &format!("DNS Meta проверен; следующий запуск после {run_at} завтра"),
                );
            }
            Err(error) => {
                let delay = backoff_after(next.failures, self.retry_after);
                append_log(
                    &self.log,
                    &format!(
                        "Meta DNS не обновлён ({error}); подряд неудач: {}, следующая попытка примерно через {delay} с",
                        next.failures
                    ),
                );
            }
        }
        Ok(())
    }

    /// Явный HHMM перекрывает оконный слот; иначе 01:00 + offset минут.
    fn run_at(&self, offset: u64) -> String {
        self.explicit_run_at
            .clone()
            .unwrap_or_else(|| format!("{:02}{:02}", 1 + offset / 60, offset % 60))
    }

    fn refresh_offset(&self) -> Result<u64, String> {
        let stored = std::fs::read_to_string(&self.offset).unwrap_or_default();
        // Командная подстановка в C снимает только хвостовые '\n'; пробелы и
        // '\r' остаются и делают строку негодной — повторяем это точно.
        let stored = stored.trim_end_matches('\n');
        if let Some(offset) = parse_stored_v2_offset(stored) {
            return Ok(offset);
        }
        if let Some(old) = parse_legacy_offset(stored) {
            let offset = old * 4 + (random_u16()? % 4) as u64;
            self.store_offset(offset)?;
            append_log(
                &self.log,
                &format!(
                    "окно DNS обновления перенесено: прежняя минута {old} → 01:00 + {offset} мин"
                ),
            );
            return Ok(offset);
        }
        let offset = (random_u16()? % 240) as u64;
        self.store_offset(offset)?;
        Ok(offset)
    }

    fn store_offset(&self, offset: u64) -> Result<(), String> {
        atomic_write(&self.offset, format!("v2 {offset}\n").as_bytes())
    }
}

pub(crate) fn local_clock() -> Result<Clock, String> {
    let output = Command::new("date")
        .arg("+%Y-%m-%d|%H%M|%s")
        .output()
        .map_err(|error| format!("не удалось прочитать местные часы роутера: {error}"))?;
    if !output.status.success() {
        return Err("команда date не смогла прочитать местные часы роутера".into());
    }
    let output = String::from_utf8(output.stdout)
        .map_err(|_| "команда date вернула данные в неподдерживаемой кодировке".to_string())?;
    let mut fields = output.trim().split('|');
    let (Some(day), Some(hhmm), Some(epoch), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err("команда date вернула некорректное значение времени".into());
    };
    let epoch = epoch
        .parse::<u64>()
        .map_err(|_| "команда date вернула некорректное время Unix".to_string())?;
    if !valid_hhmm(hhmm) || day.len() != 10 {
        return Err("команда date вернула некорректную местную дату или время".into());
    }
    Ok(Clock {
        day: day.to_string(),
        hhmm: hhmm.to_string(),
        epoch,
    })
}

fn valid_hhmm(value: &str) -> bool {
    if value.len() != 4 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Ok(hour) = value[..2].parse::<u8>() else {
        return false;
    };
    let Ok(minute) = value[2..].parse::<u8>() else {
        return false;
    };
    hour <= 23 && minute <= 59
}

pub(crate) fn read_attempt(path: &Path) -> Attempt {
    let Ok(input) = std::fs::read_to_string(path) else {
        return Attempt::default();
    };
    let mut fields = input.split_ascii_whitespace();
    let (Some(epoch), Some(day), Some(failures)) = (fields.next(), fields.next(), fields.next())
    else {
        return Attempt::default();
    };
    let (Ok(last_epoch), Ok(failures)) = (epoch.parse(), failures.parse()) else {
        return Attempt::default();
    };
    if fields.next().is_some() {
        return Attempt::default();
    }
    Attempt {
        last_epoch,
        last_day: Some(day.to_string()),
        failures,
    }
}

/// Точный перенос C-шаблонов `'v2 '[0-9] | 'v2 '[1-9][0-9] |
/// 'v2 1'[0-9][0-9] | 'v2 2'[0-3][0-9]`: ведущие нули, знак и лишние
/// пробелы не допускаются.
fn parse_stored_v2_offset(stored: &str) -> Option<u64> {
    let raw = stored.strip_prefix("v2 ")?;
    let bytes = raw.as_bytes();
    let valid = match bytes {
        [digit] => digit.is_ascii_digit(),
        [first, second] => first.is_ascii_digit() && second.is_ascii_digit() && *first != b'0',
        [b'1', second, third] => second.is_ascii_digit() && third.is_ascii_digit(),
        [b'2', second @ b'0'..=b'3', third] => second.is_ascii_digit() && third.is_ascii_digit(),
        _ => false,
    };
    valid.then(|| raw.parse().ok()).flatten()
}

/// Точный перенос C-шаблонов `[0-9] | [1-5][0-9] | 0[0-9]`.
fn parse_legacy_offset(stored: &str) -> Option<u64> {
    let bytes = stored.as_bytes();
    let valid = match bytes {
        [digit] => digit.is_ascii_digit(),
        [b'0', second] => second.is_ascii_digit(),
        [b'1'..=b'5', second] => second.is_ascii_digit(),
        _ => false,
    };
    valid.then(|| stored.parse().ok()).flatten()
}

pub(crate) fn should_run(
    state: &Path,
    attempt: &Attempt,
    clock: &Clock,
    run_at: &str,
    retry_after: u64,
) -> bool {
    let last_epoch = attempt.last_epoch.min(clock.epoch);
    if state.exists() {
        if clock.hhmm.as_str() < run_at
            || read_success_day(state).as_deref() == Some(clock.day.as_str())
        {
            return false;
        }
        if attempt.last_day.as_deref() == Some(clock.day.as_str()) {
            return clock.epoch.saturating_sub(last_epoch)
                >= backoff_after(attempt.failures, retry_after);
        }
        true
    } else {
        clock.epoch.saturating_sub(last_epoch) >= backoff_after(attempt.failures, retry_after)
    }
}

pub(crate) fn read_success_day(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| contents.lines().next().map(str::to_string))
}

pub(crate) fn backoff_after(failures: u32, retry_after: u64) -> u64 {
    if failures == 0 {
        return 0;
    }
    let exponent = failures.saturating_sub(1).min(16);
    retry_after.saturating_mul(1_u64 << exponent).min(86_400)
}

pub(crate) fn write_attempt(path: &Path, attempt: &Attempt) -> Result<(), String> {
    let day = attempt.last_day.as_deref().unwrap_or("");
    atomic_write(
        path,
        format!("{} {day} {}\n", attempt.last_epoch, attempt.failures).as_bytes(),
    )
}

pub(crate) fn random_u16() -> Result<u16, String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0_u8; 2];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "криптографический источник случайных данных недоступен".to_string())?;
    Ok(u16::from_ne_bytes(bytes))
}

pub fn parse_meta_ranges(input: &str) -> Result<Vec<(IpAddr, u8)>, String> {
    let mut ranges = Vec::new();
    for line in input.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some((address, prefix)) = line.split_once('/') else {
            continue;
        };
        let (Ok(address), Ok(prefix)) = (address.parse::<IpAddr>(), prefix.parse::<u8>()) else {
            continue;
        };
        let valid = match address {
            IpAddr::V4(_) => (8..=32).contains(&prefix),
            IpAddr::V6(_) => (16..=128).contains(&prefix),
        };
        if valid {
            ranges.push((address, prefix));
        }
    }
    Ok(ranges)
}

fn is_managed_host(host: &str) -> bool {
    meta_family(host).is_some()
}

fn read_manifest(path: &Path) -> Result<Vec<(String, IpAddr)>, String> {
    let input = match std::fs::read_to_string(path) {
        Ok(input) => input,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!(
                "не удалось прочитать манифест принадлежащих записей {}: {error}",
                path.display()
            ));
        }
    };
    let mut pairs = BTreeSet::<(String, String)>::new();
    for line in input.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(host), Some(address), None) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !is_managed_host(host) {
            continue;
        }
        if let Ok(address) = address.parse::<IpAddr>() {
            pairs.insert((host.to_string(), address.to_string()));
        }
    }
    Ok(pairs
        .into_iter()
        .filter_map(|(host, address)| address.parse().ok().map(|address| (host, address)))
        .collect())
}

fn write_manifest(path: &Path, pairs: &BTreeSet<PinPair>) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| {
        format!(
            "не удалось создать каталог манифеста {}: {error}",
            parent.display()
        )
    })?;
    let mut data = String::new();
    for (host, address) in pairs {
        data.push_str(host);
        data.push(' ');
        data.push_str(address);
        data.push('\n');
    }
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
    let file_name = path
        .file_name()
        .ok_or_else(|| "manifest path has no filename".to_string())?;
    let mut temporary = PathBuf::new();
    let mut file = None;
    for _ in 0..16 {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        temporary = parent.join(format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            id
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        match options.open(&temporary) {
            Ok(opened) => {
                file = Some(opened);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("не удалось создать временный манифест: {error}")),
        }
    }
    let mut file =
        file.ok_or_else(|| "не удалось выделить временный файл манифеста".to_string())?;
    file.write_all(data.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("не удалось записать временный манифест: {error}"))?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        format!(
            "не удалось атомарно обновить манифест {}: {error}",
            path.display()
        )
    })?;
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn write_success_mark(path: &Path) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let date = Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|date| date.trim().to_string())
        .filter(|date| !date.is_empty())
        .ok_or_else(|| "не удалось прочитать местную дату роутера".to_string())?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("не удалось создать каталог состояния планировщика: {error}"))?;
    atomic_write(path, format!("{date}\n{now}\n").as_bytes())
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), String> {
    atomic_write_with_mode(path, contents, 0o600)
}

fn atomic_write_with_mode(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("не удалось создать каталог состояния: {error}"))?;
    let name = path.file_name().ok_or("у файла состояния нет имени")?;
    let temporary = parent.join(format!(
        ".{}.tmp.{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(mode)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("не удалось создать временный файл состояния: {error}"))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("не удалось записать файл состояния: {error}"))?;
    #[cfg(unix)]
    if mode != 0o600 {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|error| format!("не удалось выставить права файла: {error}"))?;
    }
    drop(file);
    std::fs::rename(&temporary, path).map_err(|error| {
        format!(
            "не удалось заменить файл состояния {}: {error}",
            path.display()
        )
    })?;
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

pub(crate) fn append_log(path: &Path, message: &str) {
    let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) else {
        return;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = writeln!(log, "[{now}] {message}");
}

pub(crate) fn env_bounded(key: &str, default: u64, minimum: u64, maximum: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(minimum, maximum))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeNetwork {
        answers: Mutex<Result<BTreeMap<String, Vec<IpAddr>>, String>>,
        default_verified: bool,
        verified: BTreeSet<(String, IpAddr)>,
        rejected: BTreeSet<(String, IpAddr)>,
        probes: Mutex<Vec<(String, IpAddr)>>,
    }

    impl FakeNetwork {
        fn with_answers(answers: BTreeMap<String, Vec<IpAddr>>) -> Self {
            Self {
                answers: Mutex::new(Ok(answers)),
                default_verified: true,
                verified: BTreeSet::new(),
                rejected: BTreeSet::new(),
                probes: Mutex::new(Vec::new()),
            }
        }
    }

    impl MetaNetwork for FakeNetwork {
        fn resolve<'a>(&'a self) -> NetFuture<'a, Result<BTreeMap<String, Vec<IpAddr>>, String>> {
            Box::pin(async move { self.answers.lock().unwrap().clone() })
        }

        fn verify<'a>(&'a self, host: &'a str, address: IpAddr) -> NetFuture<'a, bool> {
            Box::pin(async move {
                self.probes
                    .lock()
                    .unwrap()
                    .push((host.to_string(), address));
                if self.rejected.contains(&(host.to_string(), address)) {
                    false
                } else {
                    self.default_verified || self.verified.contains(&(host.to_string(), address))
                }
            })
        }
    }

    #[derive(Default)]
    struct FakeNdm {
        records: BTreeSet<(String, IpAddr)>,
        exclusive_hostname: bool,
        fail_add: bool,
        empty_config: bool,
        saves: usize,
        mutations: Vec<String>,
    }

    impl Ndm for FakeNdm {
        fn requires_exclusive_hostname(&self) -> bool {
            self.exclusive_hostname
        }

        fn running_config(&mut self) -> Result<String, String> {
            if self.empty_config {
                return Ok(String::new());
            }
            let mut config = String::from("system name test-router\n");
            for (host, address) in &self.records {
                config.push_str(&format!("ip host {host} {address}\n"));
            }
            Ok(config)
        }

        fn add(&mut self, host: &str, address: IpAddr) -> Result<(), String> {
            self.mutations.push(format!("add {host} {address}"));
            if self.fail_add {
                return Err("injected add failure".into());
            }
            self.records.insert((host.to_string(), address));
            Ok(())
        }

        fn remove(&mut self, host: &str, address: IpAddr) -> Result<(), String> {
            self.mutations.push(format!("remove {host} {address}"));
            self.records.remove(&(host.to_string(), address));
            Ok(())
        }

        fn save(&mut self) -> Result<(), String> {
            self.saves += 1;
            Ok(())
        }
    }

    fn paths(label: &str) -> MetaDnsPaths {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("r2o-meta-dns-{}-{label}-{id}", std::process::id()));
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::write(root.join("state/meta-protection.enabled"), b"1\n").unwrap();
        std::fs::create_dir_all(root.join("files")).unwrap();
        let ranges = root.join("files/meta-ranges.txt");
        std::fs::write(&ranges, "157.240.0.0/16\n57.144.0.0/14\n").unwrap();
        MetaDnsPaths {
            r2o_dir: root.clone(),
            meta_ranges: ranges,
            manifest: root.join("state/manifest.tsv"),
            log: root.join("log/meta.log"),
            success_mark: root.join("state/success"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn system_ndm_uses_the_expected_cli_and_reports_command_failures() {
        use std::os::unix::fs::PermissionsExt;

        let paths = paths("system-ndmc");
        let executable = paths.r2o_dir.join("ndmc");
        std::fs::write(
            &executable,
            r##"#!/bin/sh
printf '%s\n' "$*" >> "${0%/*}/commands"
case "$*" in
    '-c show running-config') printf 'system name test-router\n' ;;
    '-c ip host reject.test 203.0.113.9') exit 7 ;;
esac
"##,
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut ndm = SystemNdm {
            executable: executable.into_os_string(),
        };
        assert_eq!(ndm.running_config().unwrap(), "system name test-router\n");
        let address = "157.240.9.174".parse().unwrap();
        ndm.add("instagram.com", address).unwrap();
        ndm.remove("instagram.com", address).unwrap();
        ndm.save().unwrap();
        let failure = ndm.add("reject.test", "203.0.113.9".parse().unwrap());
        assert!(failure.unwrap_err().contains("exit 7"));

        assert_eq!(
            std::fs::read_to_string(paths.r2o_dir.join("commands")).unwrap(),
            concat!(
                "-c show running-config\n",
                "-c ip host instagram.com 157.240.9.174\n",
                "-c no ip host instagram.com 157.240.9.174\n",
                "-c system configuration save\n",
                "-c ip host reject.test 203.0.113.9\n",
            )
        );
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[cfg(unix)]
    #[test]
    fn system_ndm_removes_only_manifest_owned_records_and_saves_once() {
        use std::os::unix::fs::PermissionsExt;

        let paths = paths("system-ndmc-remove-owned");
        let executable = paths.r2o_dir.join("ndmc");
        let state = paths.r2o_dir.join("running-config");
        std::fs::write(
            &state,
            concat!(
                "system name test-router\n",
                "ip host instagram.com 157.240.9.174\n",
                "ip host instagram.com 157.240.9.175\n",
                "ip host web.whatsapp.com 57.144.245.32\n",
                "ip host unrelated.example 192.0.2.7\n",
            ),
        )
        .unwrap();
        std::fs::write(
            &executable,
            r##"#!/bin/sh
command=$2
printf '%s\n' "$*" >> "${0%/*}/commands"
case "$command" in
    'show running-config') cat "${0%/*}/running-config" ;;
    'no ip host '*)
        set -- $command
        host=$4
        address=$5
        awk -v h="$host" -v ip="$address" \
            '!($1 == "ip" && $2 == "host" && $3 == h && $4 == ip)' \
            "${0%/*}/running-config" > "${0%/*}/running-config.tmp"
        mv "${0%/*}/running-config.tmp" "${0%/*}/running-config"
        ;;
    'system configuration save') : ;;
    *) exit 2 ;;
esac
"##,
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            &paths.manifest,
            concat!(
                "instagram.com 157.240.9.174\n",
                "web.whatsapp.com 57.144.245.32\n",
                "unrelated.example 192.0.2.7\n",
            ),
        )
        .unwrap();

        let network = FakeNetwork::with_answers(BTreeMap::new());
        let ndm = SystemNdm {
            executable: executable.into_os_string(),
        };
        let mut manager = MetaDnsManager::new(network, ndm, paths.clone());
        manager.remove_owned().unwrap();

        assert!(!paths.manifest.exists());
        assert_eq!(
            std::fs::read_to_string(&state).unwrap(),
            concat!(
                "system name test-router\n",
                "ip host instagram.com 157.240.9.175\n",
                "ip host unrelated.example 192.0.2.7\n",
            )
        );
        assert_eq!(
            std::fs::read_to_string(paths.r2o_dir.join("commands")).unwrap(),
            concat!(
                "-c show running-config\n",
                "-c no ip host instagram.com 157.240.9.174\n",
                "-c show running-config\n",
                "-c no ip host web.whatsapp.com 57.144.245.32\n",
                "-c system configuration save\n",
            )
        );
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    fn manager(
        network: FakeNetwork,
        ndm: FakeNdm,
        paths: MetaDnsPaths,
    ) -> MetaDnsManager<FakeNetwork, FakeNdm> {
        let mut manager = MetaDnsManager::new(network, ndm, paths);
        manager.probe_attempts = 1;
        manager.probe_retry_delay = Duration::ZERO;
        manager.resolve_attempts = 1;
        manager.resolve_retry_delay = Duration::ZERO;
        manager
    }

    fn answer(host: &str, addresses: &[&str]) -> (String, Vec<IpAddr>) {
        (
            host.to_string(),
            addresses
                .iter()
                .map(|value| value.parse().unwrap())
                .collect(),
        )
    }

    #[test]
    fn cidr_and_family_classification_match_the_fixed_host_contract() {
        let ranges = parse_meta_ranges("# Meta\n157.240.0.0/16\n57.144.0.0/14\ninvalid\n").unwrap();
        assert!(is_meta_ip(&ranges, "157.240.9.174".parse().unwrap()));
        assert!(is_meta_ip(&ranges, "57.144.245.32".parse().unwrap()));
        assert!(!is_meta_ip(&ranges, "8.8.8.8".parse().unwrap()));
        assert_eq!(meta_family("static.cdninstagram.com"), Some("instagram"));
        assert_eq!(meta_family("static.xx.fbcdn.net"), Some("fbcdn"));
        assert_eq!(meta_family("static.whatsapp.net"), Some("whatsapp"));
        assert_eq!(meta_family("evil.whatsapp.com"), Some("whatsapp"));
        assert_eq!(meta_family("example.com"), None);
    }

    #[tokio::test]
    async fn refresh_adds_only_verified_meta_addresses_and_owns_only_new_pairs() {
        let paths = paths("initial");
        let mut ndm = FakeNdm::default();
        ndm.records
            .insert(("instagram.com".into(), "203.0.113.10".parse().unwrap()));
        ndm.records
            .insert(("www.instagram.com".into(), "157.240.9.175".parse().unwrap()));
        ndm.records
            .insert(("unrelated.example".into(), "192.0.2.7".parse().unwrap()));
        let network = FakeNetwork::with_answers(BTreeMap::from([
            answer(
                "instagram.com",
                &["157.240.9.174", "8.8.8.8", "157.240.9.176", "157.240.9.177"],
            ),
            answer("www.instagram.com", &["157.240.9.175"]),
            answer("web.whatsapp.com", &["57.144.245.32", "57.144.245.33"]),
            answer("static.xx.fbcdn.net", &["157.240.205.11"]),
        ]));
        let mut manager = manager(network, ndm, paths.clone());

        manager.refresh().await.unwrap();
        let ndm = manager.ndm;
        assert!(
            ndm.records
                .contains(&("instagram.com".into(), "157.240.9.174".parse().unwrap()))
        );
        assert!(
            ndm.records
                .contains(&("instagram.com".into(), "157.240.9.176".parse().unwrap()))
        );
        assert!(
            !ndm.records
                .contains(&("instagram.com".into(), "157.240.9.177".parse().unwrap()))
        );
        assert!(
            ndm.records
                .contains(&("web.whatsapp.com".into(), "57.144.245.32".parse().unwrap()))
        );
        assert!(
            ndm.records
                .contains(&("web.whatsapp.com".into(), "57.144.245.33".parse().unwrap()))
        );
        assert!(ndm.records.contains(&(
            "static.xx.fbcdn.net".into(),
            "157.240.205.11".parse().unwrap()
        )));
        assert!(
            ndm.records
                .contains(&("instagram.com".into(), "203.0.113.10".parse().unwrap()))
        );
        assert!(
            ndm.records
                .contains(&("www.instagram.com".into(), "157.240.9.175".parse().unwrap()))
        );
        assert!(
            ndm.records
                .contains(&("unrelated.example".into(), "192.0.2.7".parse().unwrap()))
        );
        let manifest = std::fs::read_to_string(&paths.manifest).unwrap();
        assert!(manifest.contains("instagram.com 157.240.9.174"));
        assert!(manifest.contains("web.whatsapp.com 57.144.245.32"));
        assert!(!manifest.contains("www.instagram.com 157.240.9.175"));
        assert_eq!(ndm.saves, 1);
        assert!(paths.success_mark.is_file());
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[tokio::test]
    async fn fresh_verified_pairs_replace_stale_owned_pairs_but_keep_user_entries() {
        let paths = paths("replace");
        let old_owned = "157.240.9.170".parse().unwrap();
        let old_user = "157.240.9.171".parse().unwrap();
        let new_edge = "157.240.9.180".parse().unwrap();
        let mut ndm = FakeNdm::default();
        ndm.records.insert(("instagram.com".into(), old_owned));
        ndm.records.insert(("instagram.com".into(), old_user));
        std::fs::write(&paths.manifest, format!("instagram.com {old_owned}\n")).unwrap();
        let mut network = FakeNetwork::with_answers(BTreeMap::from([answer(
            "instagram.com",
            &["157.240.9.180"],
        )]));
        network.rejected.insert(("instagram.com".into(), old_owned));
        let mut manager = manager(network, ndm, paths.clone());

        manager.refresh().await.unwrap();
        assert!(
            !manager
                .ndm
                .records
                .contains(&("instagram.com".into(), old_owned))
        );
        assert!(
            manager
                .ndm
                .records
                .contains(&("instagram.com".into(), old_user))
        );
        assert!(
            manager
                .ndm
                .records
                .contains(&("instagram.com".into(), new_edge))
        );
        let manifest = std::fs::read_to_string(&paths.manifest).unwrap();
        assert!(
            manifest
                .lines()
                .any(|line| line == format!("instagram.com {new_edge}"))
        );
        assert!(
            !manifest
                .lines()
                .any(|line| line == format!("instagram.com {old_owned}"))
        );
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[tokio::test]
    async fn failed_add_keeps_previous_pin_even_when_its_fresh_probe_failed() {
        let paths = paths("add-failure");
        let old_edge = "157.240.9.170".parse().unwrap();
        let new_edge = "157.240.9.180".parse().unwrap();
        let mut ndm = FakeNdm {
            fail_add: true,
            ..FakeNdm::default()
        };
        ndm.records.insert(("instagram.com".into(), old_edge));
        std::fs::write(&paths.manifest, format!("instagram.com {old_edge}\n")).unwrap();
        let mut network = FakeNetwork::with_answers(BTreeMap::from([answer(
            "instagram.com",
            &["157.240.9.180"],
        )]));
        network.rejected.insert(("instagram.com".into(), old_edge));
        let mut manager = manager(network, ndm, paths.clone());

        assert!(manager.refresh().await.is_err());
        assert!(
            manager
                .ndm
                .records
                .contains(&("instagram.com".into(), old_edge))
        );
        assert!(
            !manager
                .ndm
                .records
                .contains(&("instagram.com".into(), new_edge))
        );
        assert!(
            std::fs::read_to_string(&paths.manifest)
                .unwrap()
                .contains(&old_edge.to_string())
        );
        assert!(
            manager
                .ndm
                .mutations
                .iter()
                .all(|operation| !operation.starts_with("remove "))
        );
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[tokio::test]
    async fn resolver_outage_keeps_inconclusive_pins_when_another_owned_pin_is_alive() {
        let paths = paths("heal");
        let dead = "157.240.9.170".parse().unwrap();
        let alive = "57.144.245.32".parse().unwrap();
        let mut ndm = FakeNdm::default();
        ndm.records.insert(("instagram.com".into(), dead));
        ndm.records.insert(("web.whatsapp.com".into(), alive));
        std::fs::write(
            &paths.manifest,
            format!("instagram.com {dead}\nweb.whatsapp.com {alive}\n"),
        )
        .unwrap();
        let mut network = FakeNetwork::with_answers(BTreeMap::new());
        *network.answers.lock().unwrap() = Err("relay down".into());
        network.default_verified = false;
        network.verified.insert(("web.whatsapp.com".into(), alive));
        let mut manager = manager(network, ndm, paths.clone());

        manager.refresh().await.unwrap();
        assert!(
            manager
                .ndm
                .records
                .contains(&("instagram.com".into(), dead))
        );
        assert!(
            manager
                .ndm
                .records
                .contains(&("web.whatsapp.com".into(), alive))
        );
        assert_eq!(
            std::fs::read_to_string(&paths.manifest).unwrap(),
            format!("instagram.com {dead}\nweb.whatsapp.com {alive}\n")
        );
        assert_eq!(manager.ndm.saves, 0);
        assert!(manager.ndm.mutations.is_empty());
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[tokio::test]
    async fn every_resolver_can_fail_and_family_fallback_still_requires_exact_tls() {
        let paths = paths("offline-family-fallback");
        let edge: IpAddr = "57.144.245.32".parse().unwrap();
        let mut network = FakeNetwork::with_answers(BTreeMap::new());
        *network.answers.lock().unwrap() = Err("all resolvers unavailable".into());
        network.default_verified = false;
        network.verified.extend([
            ("web.whatsapp.com".into(), edge),
            ("static.whatsapp.net".into(), edge),
        ]);
        let mut ndm = FakeNdm::default();
        ndm.records.insert(("web.whatsapp.com".into(), edge));
        std::fs::write(&paths.manifest, format!("web.whatsapp.com {edge}\n")).unwrap();
        let mut manager = manager(network, ndm, paths.clone());

        manager.refresh().await.unwrap();

        assert_eq!(
            manager.ndm.records,
            BTreeSet::from([
                ("web.whatsapp.com".into(), edge),
                ("static.whatsapp.net".into(), edge),
            ])
        );
        let probes = manager.network.probes.lock().unwrap();
        assert!(probes.contains(&("static.whatsapp.net".into(), edge)));
        assert!(
            !probes
                .iter()
                .any(|(host, _)| meta_family(host) != Some("whatsapp"))
        );
        assert!(
            manager
                .ndm
                .mutations
                .iter()
                .all(|operation| operation.starts_with("add "))
        );
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[tokio::test]
    async fn failed_checks_without_replacement_keep_all_owned_pins() {
        let paths = paths("offline-no-replacement");
        let edge: IpAddr = "157.240.9.170".parse().unwrap();
        let mut network = FakeNetwork::with_answers(BTreeMap::new());
        *network.answers.lock().unwrap() = Err("all resolvers unavailable".into());
        network.default_verified = false;
        let mut ndm = FakeNdm::default();
        ndm.records.insert(("instagram.com".into(), edge));
        let manifest = format!("instagram.com {edge}\n");
        std::fs::write(&paths.manifest, &manifest).unwrap();
        let mut manager = manager(network, ndm, paths.clone());

        assert!(manager.refresh().await.is_err());

        assert_eq!(
            manager.ndm.records,
            BTreeSet::from([("instagram.com".into(), edge)])
        );
        assert!(manager.ndm.mutations.is_empty());
        assert_eq!(std::fs::read_to_string(&paths.manifest).unwrap(), manifest);
        assert!(!paths.success_mark.exists());
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[test]
    fn partial_publication_only_replaces_the_verified_hostname_and_ip_family() {
        let old_v4 = "157.240.9.170".parse().unwrap();
        let new_v4 = "157.240.9.180".parse().unwrap();
        let v6 = "2a03:2880:f001:face::2".parse().unwrap();
        let whatsapp = "57.144.245.32".parse().unwrap();
        let prior = vec![
            ("instagram.com".into(), old_v4),
            ("instagram.com".into(), v6),
            ("web.whatsapp.com".into(), whatsapp),
        ];
        let published = openwrt_pins(
            &prior,
            &BTreeMap::from([("instagram.com".into(), vec![new_v4])]),
        );
        assert_eq!(
            published,
            BTreeSet::from([
                ("instagram.com".into(), new_v4.to_string()),
                ("instagram.com".into(), v6.to_string()),
                ("web.whatsapp.com".into(), whatsapp.to_string()),
            ])
        );
    }

    #[tokio::test]
    async fn refresh_deadline_stops_pending_probes_and_never_removes_pins() {
        struct StalledNetwork(AtomicUsize);
        impl MetaNetwork for StalledNetwork {
            fn resolve<'a>(&'a self) -> NetFuture<'a, Result<DnsAnswers, String>> {
                Box::pin(std::future::pending())
            }
            fn verify<'a>(&'a self, _: &'a str, _: IpAddr) -> NetFuture<'a, bool> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Box::pin(std::future::pending())
            }
        }
        let paths = paths("bounded-refresh");
        let edge: IpAddr = "157.240.9.170".parse().unwrap();
        let manifest = format!("instagram.com {edge}\n");
        std::fs::write(&paths.manifest, &manifest).unwrap();
        let mut ndm = FakeNdm::default();
        ndm.records.insert(("instagram.com".into(), edge));
        let mut manager =
            MetaDnsManager::new(StalledNetwork(AtomicUsize::new(0)), ndm, paths.clone());
        manager.deadline = tokio::time::Instant::now() + Duration::from_millis(20);
        let result = tokio::time::timeout(Duration::from_secs(1), manager.refresh()).await;
        assert!(result.unwrap().is_err());
        assert_eq!(manager.network.0.load(Ordering::Relaxed), 1);
        assert!(manager.ndm.mutations.is_empty());
        assert_eq!(std::fs::read_to_string(&paths.manifest).unwrap(), manifest);
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[tokio::test]
    async fn verified_persistent_candidates_restore_missing_pins_without_dns() {
        let paths = paths("restore-saved-addresses");
        let state = paths.r2o_dir.join("state");
        let host = "web.whatsapp.com";
        let edge: IpAddr = "57.144.245.32".parse().unwrap();
        let unverified: IpAddr = "57.144.245.33".parse().unwrap();
        let mut knowledge = Knowledge::default();
        knowledge.add_host(host, "bootstrap", 0);
        knowledge.hosts.get_mut(host).unwrap().addresses = vec![
            Address {
                ip: edge,
                asn: Some(32934),
                resolver: "old resolver".into(),
                checked_at: 50,
                verified_at: 50,
                result: "TLS подтверждён".into(),
                pinned: true,
            },
            Address {
                ip: unverified,
                asn: Some(32934),
                resolver: "old resolver".into(),
                checked_at: 50,
                verified_at: 0,
                result: "TLS: тайм-аут".into(),
                pinned: false,
            },
        ];
        knowledge.persist(&state).unwrap();
        let mut network = DirectMetaNetwork::new(None);
        network.hosts = vec![host.into()];
        network.prefixes = parse_meta_ranges("57.144.0.0/14").unwrap();
        network.seed_knowledge(&Knowledge::load(&state));
        assert_eq!(network.saved[host], [edge]);
        // Stub the exact-host verifier's successful result for this refresh.
        network
            .checks
            .lock()
            .unwrap()
            .insert((host.into(), edge), Ok(Some(200)));
        let mut manager = MetaDnsManager::new(network, FakeNdm::default(), paths.clone());
        assert!(!paths.manifest.exists());

        manager.refresh().await.unwrap();

        assert_eq!(manager.ndm.records, BTreeSet::from([(host.into(), edge)]));
        assert!(manager.network.local_dns.lock().unwrap().is_empty());
        assert_eq!(
            manager.network.candidates.lock().unwrap()[&(host.into(), edge)],
            "сохранённый адрес"
        );
        assert_eq!(
            read_manifest(&paths.manifest).unwrap(),
            [(host.into(), edge)]
        );
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[test]
    fn persistent_candidates_are_bounded_per_ip_family() {
        let host = "web.whatsapp.com";
        let mut knowledge = Knowledge::default();
        knowledge.add_host(host, "bootstrap", 0);
        for index in 1..=20 {
            let ip: IpAddr = format!("157.240.0.{index}").parse().unwrap();
            knowledge
                .hosts
                .get_mut(host)
                .unwrap()
                .addresses
                .push(Address {
                    ip,
                    asn: Some(32934),
                    resolver: String::new(),
                    checked_at: index,
                    verified_at: index,
                    result: String::new(),
                    pinned: false,
                });
        }
        let mut network = DirectMetaNetwork::new(None);
        network.hosts = vec![host.into()];
        network.seed_knowledge(&knowledge);
        assert_eq!(network.saved[host].len(), MAX_PROBE_CANDIDATES);
        assert_eq!(
            network.saved[host][0],
            "157.240.0.20".parse::<IpAddr>().unwrap()
        );
        assert!(!network.saved[host].contains(&"157.240.0.1".parse().unwrap()));
    }

    #[test]
    fn resolver_cli_can_collect_candidates_without_a_prefix_database() {
        let mut network = DirectMetaNetwork::new(None);
        let candidate = "157.240.9.174".parse().unwrap();
        assert!(network.accepts_resolver_candidate(candidate));
        assert!(!network.accepts_resolver_candidate("127.0.0.1".parse().unwrap()));
        network.prefixes = parse_meta_ranges("157.240.0.0/16").unwrap();
        assert!(network.accepts_resolver_candidate(candidate));
        assert!(!network.accepts_resolver_candidate("8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn empty_ndm_read_fails_closed_without_changing_manifest_or_dns() {
        let paths = paths("empty-config");
        let owned: IpAddr = "157.240.9.170".parse().unwrap();
        std::fs::write(&paths.manifest, format!("instagram.com {owned}\n")).unwrap();
        let network = FakeNetwork::with_answers(BTreeMap::from([answer(
            "instagram.com",
            &["157.240.9.180"],
        )]));
        let ndm = FakeNdm {
            empty_config: true,
            ..FakeNdm::default()
        };
        let mut manager = manager(network, ndm, paths.clone());

        assert!(manager.refresh().await.is_err());
        assert!(manager.ndm.mutations.is_empty());
        assert_eq!(
            std::fs::read_to_string(&paths.manifest).unwrap(),
            format!("instagram.com {owned}\n")
        );
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[tokio::test]
    async fn family_fallback_rechecks_the_borrowed_name_and_never_crosses_families() {
        let paths = paths("family-fallback");
        let borrowed: IpAddr = "57.144.245.32".parse().unwrap();
        let network = FakeNetwork {
            answers: Mutex::new(Ok(BTreeMap::from([
                answer("web.whatsapp.com", &["57.144.245.32"]),
                answer("static.whatsapp.net", &["157.240.0.60"]),
                answer("static.xx.fbcdn.net", &["157.240.0.62"]),
            ]))),
            default_verified: false,
            verified: BTreeSet::from([
                ("web.whatsapp.com".into(), borrowed),
                ("static.whatsapp.net".into(), borrowed),
            ]),
            rejected: BTreeSet::new(),
            probes: Mutex::new(Vec::new()),
        };
        let mut manager = manager(network, FakeNdm::default(), paths.clone());

        manager.refresh().await.unwrap();
        assert!(
            manager
                .ndm
                .records
                .contains(&("static.whatsapp.net".into(), borrowed))
        );
        assert!(
            !manager
                .ndm
                .records
                .iter()
                .any(|(host, _)| host == "static.xx.fbcdn.net")
        );
        assert!(
            manager
                .network
                .probes
                .lock()
                .unwrap()
                .contains(&("static.whatsapp.net".into(), borrowed))
        );
        assert!(
            !manager
                .network
                .probes
                .lock()
                .unwrap()
                .iter()
                .any(|(host, ip)| { host == "static.xx.fbcdn.net" && *ip == borrowed })
        );
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[test]
    fn remove_uses_the_ownership_manifest_and_keeps_user_mappings() {
        let paths = paths("remove");
        let owned: IpAddr = "157.240.9.174".parse().unwrap();
        let user: IpAddr = "157.240.9.175".parse().unwrap();
        std::fs::write(&paths.manifest, format!("instagram.com {owned}\n")).unwrap();
        let mut ndm = FakeNdm::default();
        ndm.records.insert(("instagram.com".into(), owned));
        ndm.records.insert(("instagram.com".into(), user));
        let mut manager = manager(
            FakeNetwork::with_answers(BTreeMap::new()),
            ndm,
            paths.clone(),
        );

        manager.remove_owned().unwrap();
        assert!(
            !manager
                .ndm
                .records
                .contains(&("instagram.com".into(), owned))
        );
        assert!(
            manager
                .ndm
                .records
                .contains(&("instagram.com".into(), user))
        );
        assert!(!paths.manifest.exists());
        assert_eq!(manager.ndm.saves, 1);
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[test]
    fn disabling_one_product_preserves_other_owned_and_user_dns_records() {
        let paths = paths("remove-product");
        let ip = "157.240.9.174".parse::<IpAddr>().unwrap();
        let user = "157.240.9.175".parse::<IpAddr>().unwrap();
        std::fs::write(
            &paths.manifest,
            format!("instagram.com {ip}\nwww.facebook.com {ip}\n"),
        )
        .unwrap();
        let mut ndm = FakeNdm::default();
        ndm.records.extend([
            ("instagram.com".into(), ip),
            ("instagram.com".into(), user),
            ("www.facebook.com".into(), ip),
        ]);
        let mut manager = manager(
            FakeNetwork::with_answers(BTreeMap::new()),
            ndm,
            paths.clone(),
        );

        let inactive = |host: &str| is_disabled_host(&["instagram"], host);
        manager.remove_owned_where(inactive).unwrap();
        manager.remove_owned_where(inactive).unwrap();
        assert_eq!(
            read_manifest(&paths.manifest).unwrap(),
            [("www.facebook.com".into(), ip)]
        );
        assert_eq!(manager.ndm.records.len(), 2);
        assert!(
            manager
                .ndm
                .records
                .contains(&("instagram.com".into(), user))
        );
        assert!(
            manager
                .ndm
                .records
                .contains(&("www.facebook.com".into(), ip))
        );
        assert_eq!(manager.ndm.saves, 1);
        std::fs::remove_dir_all(paths.r2o_dir).unwrap();
    }

    #[tokio::test]
    async fn new_meta_hostname_needs_bgp_and_exact_tls_before_aaaa_is_pinned() {
        let paths = paths("new-whatsapp-ipv6");
        let edge: IpAddr = "2a03:2880:f001:face::2".parse().unwrap();
        let wrong_tls: IpAddr = "2a03:2880:f001:face::3".parse().unwrap();
        let outside: IpAddr = "2606:4700::1111".parse().unwrap();
        std::fs::write(&paths.meta_ranges, "2a03:2880::/32\n157.240.0.0/16\n").unwrap();
        let host = "media-new.whatsapp.net";
        let mut network = FakeNetwork::with_answers(BTreeMap::from([(
            host.into(),
            vec![outside, wrong_tls, edge],
        )]));
        network.default_verified = false;
        network.verified.insert((host.into(), edge));
        network.rejected.insert((host.into(), wrong_tls));
        let mut manager = manager(network, FakeNdm::default(), paths.clone());
        manager.refresh().await.unwrap();
        assert_eq!(
            read_manifest(&paths.manifest).unwrap(),
            [(host.into(), edge)]
        );
        assert!(!manager.ndm.records.contains(&(host.into(), outside)));
        assert!(!manager.ndm.records.contains(&(host.into(), wrong_tls)));
        assert!(
            !manager
                .network
                .probes
                .lock()
                .unwrap()
                .contains(&(host.into(), outside))
        );
        manager.remove_owned().unwrap();
        assert!(manager.ndm.records.is_empty());
        std::fs::remove_dir_all(paths.r2o_dir).unwrap();
    }

    #[tokio::test]
    async fn keenetic_user_hostname_is_preserved_even_when_the_address_differs() {
        let paths = paths("keenetic-user-override");
        let user = ("WWW.FACEBOOK.COM".into(), "203.0.113.5".parse().unwrap());
        let ndm = FakeNdm {
            records: BTreeSet::from([user.clone()]),
            exclusive_hostname: true,
            ..FakeNdm::default()
        };
        let mut network = FakeNetwork::with_answers(BTreeMap::from([answer(
            "www.facebook.com",
            &["157.240.9.180"],
        )]));
        network.default_verified = false;
        network
            .verified
            .insert(("www.facebook.com".into(), "157.240.9.180".parse().unwrap()));
        let mut manager = manager(network, ndm, paths.clone());
        manager.refresh().await.unwrap();
        assert_eq!(manager.ndm.records, BTreeSet::from([user]));
        assert!(read_manifest(&paths.manifest).unwrap().is_empty());
        std::fs::remove_dir_all(paths.r2o_dir).unwrap();
    }

    #[tokio::test]
    async fn skipped_replacement_never_retires_an_old_owned_pin() {
        let paths = paths("skipped-replacement");
        let host = "www.facebook.com";
        let old: IpAddr = "157.240.9.170".parse().unwrap();
        let user: IpAddr = "203.0.113.5".parse().unwrap();
        let records = BTreeSet::from([(host.into(), old), (host.into(), user)]);
        let ndm = FakeNdm {
            records: records.clone(),
            exclusive_hostname: true,
            ..FakeNdm::default()
        };
        let mut network =
            FakeNetwork::with_answers(BTreeMap::from([answer(host, &["157.240.9.180"])]));
        network.default_verified = false;
        network
            .verified
            .insert((host.into(), "157.240.9.180".parse().unwrap()));
        let manifest = format!("{host} {old}\n");
        std::fs::write(&paths.manifest, &manifest).unwrap();
        let mut manager = manager(network, ndm, paths.clone());

        manager.refresh().await.unwrap();

        assert_eq!(manager.ndm.records, records);
        assert_eq!(std::fs::read_to_string(&paths.manifest).unwrap(), manifest);
        assert!(manager.ndm.mutations.is_empty());
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[test]
    fn persistent_disable_marker_survives_reload_and_lock_is_exclusive() {
        let paths = paths("disabled");
        let state = paths.r2o_dir.join("state");
        let lock = state_lock(&state).unwrap();
        assert!(state_lock(&state).is_err());
        let opt_in = state.join("meta-protection.enabled");
        std::fs::remove_file(&opt_in).unwrap();
        assert!(!protection_enabled(&state));
        atomic_write(&opt_in, b"1\n").unwrap();
        assert!(protection_enabled(&state));
        atomic_write(&state.join("meta-protection.disabled"), b"0\n").unwrap();
        drop(lock);
        assert!(state_lock(&state).is_ok());
        assert!(!protection_enabled(&state));
        std::fs::remove_file(state.join("meta-protection.disabled")).unwrap();
        assert!(protection_enabled(&state));
        std::fs::remove_dir_all(paths.r2o_dir).unwrap();
    }

    #[test]
    fn resumed_publication_reconciles_pin_status_and_only_clears_its_pending_error() {
        let paths = paths("scheduler-pin-status");
        let state = paths.r2o_dir.join("state");
        let host = "instagram.com";
        let old: IpAddr = "157.240.1.1".parse().unwrap();
        let new: IpAddr = "157.240.1.2".parse().unwrap();
        let mut knowledge = Knowledge::default();
        knowledge.add_host(host, "bootstrap", 0);
        knowledge.hosts.get_mut(host).unwrap().addresses = [old, new]
            .into_iter()
            .map(|ip| Address {
                ip,
                asn: Some(32934),
                resolver: "saved".into(),
                checked_at: 100,
                verified_at: 100,
                result: "TLS подтверждён".into(),
                pinned: ip == old,
            })
            .collect();
        knowledge.error = Some(format!("{PENDING_APPLY_ERROR}ubus unavailable"));
        knowledge.persist(&state).unwrap();

        reconcile_pin_status(&state, &[(host.into(), new)]).unwrap();
        let mut knowledge = Knowledge::load(&state);
        assert_eq!(knowledge.error, None);
        assert!(!knowledge.hosts[host].addresses[0].pinned);
        assert!(knowledge.hosts[host].addresses[1].pinned);
        assert_eq!(knowledge.hosts[host].addresses[0].verified_at, 100);

        knowledge.error = Some("TLS verification failed".into());
        knowledge.persist(&state).unwrap();
        reconcile_pin_status(&state, &[]).unwrap();
        let knowledge = Knowledge::load(&state);
        assert_eq!(knowledge.error.as_deref(), Some("TLS verification failed"));
        assert!(
            knowledge.hosts[host]
                .addresses
                .iter()
                .all(|address| !address.pinned)
        );
        std::fs::remove_dir_all(paths.r2o_dir).unwrap();
    }

    fn test_scheduler(paths: &MetaDnsPaths) -> MetaDnsScheduler {
        let scheduler = MetaDnsScheduler {
            state: paths.success_mark.clone(),
            attempt: paths.r2o_dir.join("attempt"),
            offset: paths.r2o_dir.join("offset"),
            log: paths.log.clone(),
            interval: Duration::from_secs(60),
            retry_after: 1800,
            explicit_run_at: None,
        };
        scheduler.store_offset(60).unwrap();
        scheduler
    }

    #[tokio::test]
    async fn default_scheduler_runs_once_then_waits_for_the_next_local_slot() {
        let paths = paths("scheduler-default-daily");
        let mut scheduler = test_scheduler(&paths);
        let runs = std::cell::Cell::new(0);
        let refresh = || async {
            runs.set(runs.get() + 1);
            Ok(())
        };
        let first = Clock {
            day: "2026-11-28".into(),
            hhmm: "1200".into(),
            epoch: 100_000,
        };
        // Initial use, including a successful batch without any changed pins.
        scheduler
            .tick_with_refresh(first.clone(), false, refresh)
            .await
            .unwrap();
        assert_eq!(runs.get(), 1);
        assert_eq!(
            read_success_day(&scheduler.state).as_deref(),
            Some("2026-11-28")
        );

        // Restarting the scheduler does not discard the daily success marker.
        let mut scheduler = test_scheduler(&paths);
        scheduler
            .tick_with_refresh(
                Clock {
                    epoch: first.epoch + 60,
                    ..first.clone()
                },
                false,
                refresh,
            )
            .await
            .unwrap();
        assert_eq!(runs.get(), 1);
        let tomorrow = Clock {
            day: "2026-11-29".into(),
            hhmm: "0159".into(),
            epoch: first.epoch + 50_340,
        };
        scheduler
            .tick_with_refresh(tomorrow.clone(), false, refresh)
            .await
            .unwrap();
        assert_eq!(runs.get(), 1);
        scheduler
            .tick_with_refresh(
                Clock {
                    hhmm: "0200".into(),
                    epoch: tomorrow.epoch + 60,
                    ..tomorrow
                },
                false,
                refresh,
            )
            .await
            .unwrap();
        assert_eq!(runs.get(), 2);
        std::fs::remove_dir_all(paths.r2o_dir).unwrap();
    }

    #[test]
    fn all_products_disabled_do_not_request_empty_runtime_restore_every_tick() {
        let paths = paths("scheduler-empty-restore");
        let state = paths.r2o_dir.join("state");
        assert!(should_restore_hosts(true, &state));
        assert!(!should_restore_hosts(false, &state));
        for product in r2k_core::meta::PRODUCTS {
            atomic_write(
                &r2k_core::meta::product_marker(&state, product).unwrap(),
                b"0\n",
            )
            .unwrap();
        }
        assert!(!should_restore_hosts(true, &state));
        std::fs::remove_file(r2k_core::meta::product_marker(&state, "instagram").unwrap()).unwrap();
        assert!(should_restore_hosts(true, &state));
        std::fs::remove_dir_all(paths.r2o_dir).unwrap();
    }

    #[tokio::test]
    async fn missing_runtime_hosts_can_be_restored_after_success_today() {
        let paths = paths("scheduler-restore");
        let mut scheduler = test_scheduler(&paths);
        std::fs::write(&scheduler.state, "2026-11-28\n").unwrap();
        let clock = Clock {
            day: "2026-11-28".into(),
            hhmm: "1200".into(),
            epoch: 100_000,
        };
        let runs = std::cell::Cell::new(0);
        let refresh = || async {
            runs.set(runs.get() + 1);
            Ok(())
        };
        scheduler
            .tick_with_refresh(clock.clone(), false, refresh)
            .await
            .unwrap();
        assert_eq!(runs.get(), 0);
        scheduler
            .tick_with_refresh(clock, true, refresh)
            .await
            .unwrap();
        assert_eq!(runs.get(), 1);
        std::fs::remove_dir_all(paths.r2o_dir).unwrap();
    }

    #[tokio::test]
    async fn meta_backoff_survives_midnight_and_missing_runtime_hosts() {
        let paths = paths("scheduler-cross-midnight");
        let mut scheduler = test_scheduler(&paths);
        std::fs::write(&scheduler.state, "2026-11-26\n").unwrap();
        let clock = Clock {
            day: "2026-11-28".into(),
            hhmm: "2359".into(),
            epoch: 200_000,
        };
        write_attempt(
            &scheduler.attempt,
            &Attempt {
                last_epoch: clock.epoch - 86_400,
                last_day: Some("2026-11-27".into()),
                failures: 6,
            },
        )
        .unwrap();
        scheduler
            .tick_with_refresh(clock.clone(), false, || async {
                Err("network unavailable".into())
            })
            .await
            .unwrap();
        assert_eq!(read_attempt(&scheduler.attempt).failures, 7);
        let tomorrow = Clock {
            day: "2026-11-29".into(),
            hhmm: "0200".into(),
            epoch: clock.epoch + 7260,
        };
        let runs = std::cell::Cell::new(0);
        let refresh = || async {
            runs.set(runs.get() + 1);
            Ok(())
        };
        scheduler
            .tick_with_refresh(tomorrow.clone(), false, refresh)
            .await
            .unwrap();
        scheduler
            .tick_with_refresh(tomorrow.clone(), true, refresh)
            .await
            .unwrap();
        assert_eq!(runs.get(), 0);
        scheduler
            .tick_with_refresh(
                Clock {
                    hhmm: "2359".into(),
                    epoch: clock.epoch + 86_400,
                    ..tomorrow
                },
                true,
                refresh,
            )
            .await
            .unwrap();
        assert_eq!(runs.get(), 1);
        assert_eq!(read_attempt(&scheduler.attempt).failures, 0);
        std::fs::remove_dir_all(paths.r2o_dir).unwrap();
    }

    #[tokio::test]
    async fn meta_backoff_rebases_once_when_router_clock_moves_backwards() {
        let paths = paths("scheduler-clock-rollback");
        let mut scheduler = test_scheduler(&paths);
        let clock = Clock {
            day: "2026-11-28".into(),
            hhmm: "1200".into(),
            epoch: 100_000,
        };
        write_attempt(
            &scheduler.attempt,
            &Attempt {
                last_epoch: clock.epoch + 86_400,
                last_day: Some("2026-11-29".into()),
                failures: 1,
            },
        )
        .unwrap();
        let runs = std::cell::Cell::new(0);
        let refresh = || async {
            runs.set(runs.get() + 1);
            Ok(())
        };
        scheduler
            .tick_with_refresh(clock.clone(), true, refresh)
            .await
            .unwrap();
        assert_eq!(runs.get(), 0);
        assert_eq!(read_attempt(&scheduler.attempt).last_epoch, clock.epoch);
        scheduler
            .tick_with_refresh(
                Clock {
                    hhmm: "1230".into(),
                    epoch: clock.epoch + 1800,
                    ..clock
                },
                true,
                refresh,
            )
            .await
            .unwrap();
        assert_eq!(runs.get(), 1);
        std::fs::remove_dir_all(paths.r2o_dir).unwrap();
    }

    #[test]
    fn scheduler_obeys_daily_slot_and_first_install_runs_immediately() {
        let paths = paths("scheduler-slot");
        let clock = Clock {
            day: "2026-09-29".into(),
            hhmm: "0159".into(),
            epoch: 1_790_654_340,
        };
        assert!(should_run(
            &paths.success_mark,
            &Attempt::default(),
            &clock,
            "0200",
            1800
        ));
        std::fs::write(&paths.success_mark, "2026-09-28\n1790560000\n").unwrap();
        assert!(!should_run(
            &paths.success_mark,
            &Attempt {
                last_epoch: clock.epoch - 600,
                last_day: Some(clock.day.clone()),
                failures: 1,
            },
            &clock,
            "0200",
            1800
        ));
        let at_slot = Clock {
            hhmm: "0200".into(),
            ..clock
        };
        assert!(should_run(
            &paths.success_mark,
            &Attempt {
                last_epoch: at_slot.epoch - 1800,
                last_day: Some(at_slot.day.clone()),
                failures: 1,
            },
            &at_slot,
            "0200",
            1800
        ));
        assert!(should_run(
            &paths.success_mark,
            &Attempt {
                last_epoch: at_slot.epoch - 1800,
                last_day: Some("2026-09-28".into()),
                failures: 7,
            },
            &at_slot,
            "0200",
            1800
        ));
        std::fs::write(&paths.success_mark, "2026-09-29\n").unwrap();
        let after_success = Clock {
            hhmm: "0600".into(),
            ..at_slot
        };
        assert!(!should_run(
            &paths.success_mark,
            &Attempt::default(),
            &after_success,
            "0200",
            1800
        ));
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[test]
    fn scheduler_backoff_doubles_and_stops_at_one_day() {
        assert_eq!(backoff_after(0, 1800), 0);
        assert_eq!(backoff_after(1, 1800), 1800);
        assert_eq!(backoff_after(2, 1800), 3600);
        assert_eq!(backoff_after(3, 1800), 7200);
        assert_eq!(backoff_after(20, 1800), 86_400);
        assert!(valid_hhmm("0000"));
        assert!(valid_hhmm("2359"));
        assert!(!valid_hhmm("2400"));
        assert!(!valid_hhmm("2360"));
    }

    #[test]
    fn scheduler_migrates_old_offsets_once_and_keeps_the_randomized_slot() {
        let paths = paths("scheduler-offset");
        let scheduler = MetaDnsScheduler {
            state: paths.success_mark.clone(),
            attempt: paths.r2o_dir.join("attempt"),
            offset: paths.r2o_dir.join("offset"),
            log: paths.log.clone(),
            interval: Duration::from_secs(60),
            retry_after: 1800,
            explicit_run_at: None,
        };
        std::fs::write(&scheduler.offset, "37\n").unwrap();
        let migrated = scheduler.refresh_offset().unwrap();
        assert!((148..=151).contains(&migrated));
        assert_eq!(scheduler.refresh_offset().unwrap(), migrated);
        std::fs::write(&scheduler.offset, "v2 239\n").unwrap();
        assert_eq!(scheduler.refresh_offset().unwrap(), 239);
        std::fs::write(&scheduler.offset, "junk\n").unwrap();
        let regenerated = scheduler.refresh_offset().unwrap();
        assert!(regenerated <= 239);
        assert_eq!(scheduler.refresh_offset().unwrap(), regenerated);
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[test]
    #[ignore]
    fn b48_scheduler_trace() {
        let dir = PathBuf::from(std::env::var("R2O_B48_TRACE_DIR").expect("trace dir"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut scheduler = MetaDnsScheduler {
            state: dir.join("state"),
            attempt: dir.join("attempt"),
            offset: dir.join("offset"),
            log: dir.join("log"),
            interval: Duration::from_secs(60),
            retry_after: 1800,
            explicit_run_at: None,
        };
        for (name, content) in [
            ("v2-0", "v2 0"),
            ("v2-9", "v2 9"),
            ("v2-10", "v2 10"),
            ("v2-99", "v2 99"),
            ("v2-100", "v2 100"),
            ("v2-199", "v2 199"),
            ("v2-200", "v2 200"),
            ("v2-239", "v2 239"),
            ("v2-240", "v2 240"),
            ("v2-007", "v2 007"),
            ("v2-07", "v2 07"),
            ("v2-00", "v2 00"),
            ("v2-plus", "v2 +5"),
            ("v2-space", "v2 5 "),
            ("bare-0", "0"),
            ("bare-9", "9"),
            ("bare-00", "00"),
            ("bare-09", "09"),
            ("bare-10", "10"),
            ("bare-59", "59"),
            ("bare-60", "60"),
            ("bare-007", "007"),
            ("bare-plus", "+5"),
            ("bare-space", " 5"),
            ("junk", "junk"),
            ("empty", ""),
        ] {
            std::fs::write(&scheduler.offset, content).unwrap();
            let stored = content.trim_end_matches('\n');
            let classification = if let Some(value) = parse_stored_v2_offset(stored) {
                format!("stored value={value}")
            } else if parse_legacy_offset(stored).is_some() {
                "migrated".to_string()
            } else {
                "regenerated".to_string()
            };
            let value = scheduler.refresh_offset().unwrap();
            if classification.starts_with("stored") {
                assert_eq!(classification, format!("stored value={value}"));
            }
            println!("offset {name} {classification}");
        }
        for retry in [60_u64, 1800, 86400] {
            for failures in 0..=12_u32 {
                println!(
                    "backoff retry={retry} failures={failures} secs={}",
                    backoff_after(failures, retry)
                );
            }
        }
        for offset in [0_u64, 1, 59, 60, 120, 239] {
            scheduler.explicit_run_at = None;
            println!(
                "run_at explicit=none offset={offset} value={}",
                scheduler.run_at(offset)
            );
        }
        scheduler.explicit_run_at = Some("0345".to_string());
        println!(
            "run_at explicit=0345 offset=10 value={}",
            scheduler.run_at(10)
        );
        scheduler.explicit_run_at = None;

        struct TickCase {
            name: &'static str,
            day: &'static str,
            hhmm: &'static str,
            epoch: u64,
            state_day: Option<&'static str>,
            attempt: Option<(u64, &'static str, u32)>,
        }
        let cases = [
            TickCase {
                name: "first-install",
                day: "2026-11-08",
                hhmm: "0000",
                epoch: 1000,
                state_day: None,
                attempt: None,
            },
            TickCase {
                name: "backoff-wait",
                day: "2026-11-08",
                hhmm: "0000",
                epoch: 1000,
                state_day: None,
                attempt: Some((0, "2026-11-07", 1)),
            },
            TickCase {
                name: "backoff-elapsed",
                day: "2026-11-08",
                hhmm: "0000",
                epoch: 2000,
                state_day: None,
                attempt: Some((0, "2026-11-07", 1)),
            },
            TickCase {
                name: "before-slot",
                day: "2026-11-08",
                hhmm: "0059",
                epoch: 1000,
                state_day: Some("2026-11-07"),
                attempt: None,
            },
            TickCase {
                name: "at-slot",
                day: "2026-11-08",
                hhmm: "0100",
                epoch: 1000,
                state_day: Some("2026-11-07"),
                attempt: None,
            },
            TickCase {
                name: "already-today",
                day: "2026-11-08",
                hhmm: "0100",
                epoch: 1000,
                state_day: Some("2026-11-08"),
                attempt: None,
            },
            TickCase {
                name: "today-fail-wait",
                day: "2026-11-08",
                hhmm: "0100",
                epoch: 2000,
                state_day: Some("2026-11-07"),
                attempt: Some((1000, "2026-11-08", 1)),
            },
            TickCase {
                name: "today-fail-elapsed",
                day: "2026-11-08",
                hhmm: "0100",
                epoch: 2000,
                state_day: Some("2026-11-07"),
                attempt: Some((0, "2026-11-08", 1)),
            },
            TickCase {
                name: "yesterday-attempt",
                day: "2026-11-08",
                hhmm: "0100",
                epoch: 2000,
                state_day: Some("2026-11-07"),
                attempt: Some((1000, "2026-11-07", 1)),
            },
            TickCase {
                name: "future-attempt",
                day: "2026-11-08",
                hhmm: "0000",
                epoch: 1000,
                state_day: None,
                attempt: Some((5000, "2026-11-07", 0)),
            },
        ];
        for case in cases {
            let state = dir.join("state");
            if let Some(day) = case.state_day {
                std::fs::write(&state, format!("{day}\n0\n")).unwrap();
            } else {
                let _ = std::fs::remove_file(&state);
            }
            let attempt = case
                .attempt
                .map_or_else(Attempt::default, |(last, day, failures)| Attempt {
                    last_epoch: last,
                    last_day: Some(day.to_string()),
                    failures,
                });
            let clock = Clock {
                day: case.day.to_string(),
                hhmm: case.hhmm.to_string(),
                epoch: case.epoch,
            };
            println!(
                "tick {} run={}",
                case.name,
                u8::from(should_run(&state, &attempt, &clock, "0100", 1800))
            );
        }
    }

    #[test]
    fn scheduler_offset_parser_matches_d2o_shell_patterns() {
        for (stored, want) in [
            ("v2 0", Some(0)),
            ("v2 9", Some(9)),
            ("v2 10", Some(10)),
            ("v2 99", Some(99)),
            ("v2 100", Some(100)),
            ("v2 199", Some(199)),
            ("v2 200", Some(200)),
            ("v2 239", Some(239)),
            ("v2 240", None),
            ("v2 007", None),
            ("v2 07", None),
            ("v2 00", None),
            ("v2 +5", None),
            ("v2 5 ", None),
            ("v2 5\r", None),
        ] {
            assert_eq!(parse_stored_v2_offset(stored), want, "{stored:?}");
        }
        for (stored, want) in [
            ("0", Some(0)),
            ("9", Some(9)),
            ("00", Some(0)),
            ("09", Some(9)),
            ("10", Some(10)),
            ("59", Some(59)),
            ("60", None),
            ("007", None),
            ("+5", None),
            (" 5", None),
            ("5 ", None),
            ("5\r", None),
        ] {
            assert_eq!(parse_legacy_offset(stored), want, "{stored:?}");
        }
    }

    #[test]
    fn default_meta_ranges_prefers_nonempty_state_database() {
        let dir = std::env::temp_dir().join(format!(
            "r2o-meta-ranges-path-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("files")).unwrap();
        std::fs::create_dir_all(dir.join("state/lists")).unwrap();
        let shipped = dir.join("files/meta-ranges.txt");
        std::fs::write(&shipped, "31.13.24.0/21\n").unwrap();
        assert_eq!(default_meta_ranges_path(&dir), shipped);
        let updated = dir.join("state/lists/meta-ranges.txt");
        std::fs::write(&updated, "31.13.24.0/21\n").unwrap();
        assert_eq!(default_meta_ranges_path(&dir), shipped);
        let mut many = String::new();
        for index in 0..10 {
            many.push_str(&format!("31.13.{}.0/24\n", index));
        }
        std::fs::write(&updated, &many).unwrap();
        assert_eq!(default_meta_ranges_path(&dir), updated);
        std::fs::write(&updated, "").unwrap();
        assert_eq!(default_meta_ranges_path(&dir), shipped);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
