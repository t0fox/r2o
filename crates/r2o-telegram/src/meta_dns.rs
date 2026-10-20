//! Проверенный lifecycle статических Meta DNS pins на Keenetic.

use crate::meta_edge::{META_HOSTS, check_meta_edge};
use r2k_core::dns::{DNS_RESOLVERS, DnsResolver, build_a_query, parse_a_reply};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::{sleep, timeout};

const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const SYSTEM_DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_PACKET_LIMIT: usize = 4096;
const DNS_ADDRESS_LIMIT: usize = 8;
static NEXT_DNS_ID: AtomicU16 = AtomicU16::new(1);

const MAX_HOST_ADDRESSES: usize = 2;
const MAX_PROBE_CANDIDATES: usize = 4;

type NetFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type PinPair = (String, String);

struct ProbePolicy<'a> {
    attempts: usize,
    retry_delay: Duration,
    log: &'a Path,
}

pub trait MetaNetwork: Send + Sync {
    fn resolve<'a>(&'a self) -> NetFuture<'a, Result<BTreeMap<String, Vec<Ipv4Addr>>, String>>;
    fn verify<'a>(&'a self, host: &'a str, address: Ipv4Addr) -> NetFuture<'a, bool>;
}

pub trait Ndm: Send {
    fn running_config(&mut self) -> Result<String, String>;
    fn add(&mut self, host: &str, address: Ipv4Addr) -> Result<(), String>;
    fn remove(&mut self, host: &str, address: Ipv4Addr) -> Result<(), String>;
    fn save(&mut self) -> Result<(), String>;
}

pub struct DirectMetaNetwork {
    ca_bundle: Option<PathBuf>,
}

impl DirectMetaNetwork {
    pub fn new(ca_bundle: Option<PathBuf>) -> Self {
        Self { ca_bundle }
    }
}

impl MetaNetwork for DirectMetaNetwork {
    fn resolve<'a>(&'a self) -> NetFuture<'a, Result<BTreeMap<String, Vec<Ipv4Addr>>, String>> {
        Box::pin(resolve_meta_direct())
    }

    fn verify<'a>(&'a self, host: &'a str, address: Ipv4Addr) -> NetFuture<'a, bool> {
        Box::pin(async move {
            let Some(ca_bundle) = self.ca_bundle.as_deref() else {
                return false;
            };
            check_meta_edge(host, address, ca_bundle).await.is_ok()
        })
    }
}

pub async fn resolve_meta_direct() -> Result<BTreeMap<String, Vec<Ipv4Addr>>, String> {
    let answers =
        futures_util::future::join_all(META_HOSTS.iter().map(|host| resolve_host(host))).await;
    let mut results = BTreeMap::new();
    let mut first_error = None;
    for (host, answer) in META_HOSTS.iter().zip(answers) {
        match answer {
            Ok(addresses) => {
                results.insert((*host).to_owned(), addresses);
            }
            Err(error) => {
                first_error.get_or_insert(error);
                results.insert((*host).to_owned(), Vec::new());
            }
        }
    }
    if results.values().all(Vec::is_empty) {
        return Err(first_error.unwrap_or_else(|| "DNS не вернул адреса Meta".to_owned()));
    }
    Ok(results)
}

async fn resolve_host(host: &'static str) -> Result<Vec<Ipv4Addr>, String> {
    let id = NEXT_DNS_ID.fetch_add(1, Ordering::Relaxed);
    let query = build_a_query(id, host).map_err(|_| format!("некорректное имя DNS: {host}"))?;
    let system_lookup = timeout(SYSTEM_DNS_TIMEOUT, lookup_host((host, 443)));
    let direct_lookups = futures_util::future::join_all(
        DNS_RESOLVERS.map(|resolver| query_public_resolver(resolver, &query, host)),
    );
    let (system, direct) = tokio::join!(system_lookup, direct_lookups);
    let mut addresses = Vec::with_capacity(DNS_ADDRESS_LIMIT);
    if let Ok(Ok(results)) = system {
        for address in results.filter_map(|address| match address.ip() {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        }) {
            append_address(&mut addresses, address);
        }
    }
    for answer in direct.into_iter().flatten() {
        for address in answer {
            append_address(&mut addresses, address);
        }
    }
    if addresses.is_empty() {
        return Err(format!(
            "локальный DNS и прямые серверы не разрешили {host}"
        ));
    }
    Ok(addresses)
}

async fn query_public_resolver(
    resolver: DnsResolver,
    query: &[u8],
    host: &str,
) -> Result<Vec<Ipv4Addr>, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| format!("не удалось открыть DNS-сокет: {error}"))?;
    socket
        .connect(SocketAddr::new(IpAddr::V4(resolver.address), 53))
        .await
        .map_err(|error| {
            format!(
                "не удалось подключиться к DNS {} {}: {error}",
                resolver.provider.name(),
                resolver.address
            )
        })?;
    timeout(DNS_TIMEOUT, async {
        socket
            .send(query)
            .await
            .map_err(|error| format!("не удалось отправить DNS-запрос: {error}"))?;
        let mut response = [0_u8; DNS_PACKET_LIMIT];
        let length = socket
            .recv(&mut response)
            .await
            .map_err(|error| format!("не удалось получить DNS-ответ: {error}"))?;
        parse_a_reply(&response[..length], query, host).map_err(|_| {
            format!(
                "DNS {} вернул некорректный ответ для {host}",
                resolver.provider.name()
            )
        })
    })
    .await
    .map_err(|_| {
        format!(
            "истёк таймаут DNS-запроса к {} {}",
            resolver.provider.name(),
            resolver.address
        )
    })?
}

fn append_address(addresses: &mut Vec<Ipv4Addr>, address: Ipv4Addr) {
    if addresses.len() < DNS_ADDRESS_LIMIT && !addresses.contains(&address) {
        addresses.push(address);
    }
}

#[derive(Default)]
pub struct SystemNdm;

impl Ndm for SystemNdm {
    fn running_config(&mut self) -> Result<String, String> {
        let output = ndmc("show running-config")?;
        let config = String::from_utf8(output.stdout)
            .map_err(|_| "ndmc вернул конфигурацию в неподдерживаемой кодировке".to_string())?;
        if !output.status.success() || config.trim().is_empty() {
            return Err("ndmc вернул пустую конфигурацию или сообщил об ошибке чтения".into());
        }
        Ok(config)
    }

    fn add(&mut self, host: &str, address: Ipv4Addr) -> Result<(), String> {
        ndmc(&format!("ip host {host} {address}"))
            .and_then(command_success("ndmc отклонил добавление DNS-записи"))
    }

    fn remove(&mut self, host: &str, address: Ipv4Addr) -> Result<(), String> {
        ndmc(&format!("no ip host {host} {address}"))
            .and_then(command_success("ndmc отклонил удаление DNS-записи"))
    }

    fn save(&mut self) -> Result<(), String> {
        ndmc("system configuration save").and_then(command_success(
            "ndmc не смог сохранить конфигурацию роутера",
        ))
    }
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

fn ndmc(command: &str) -> Result<std::process::Output, String> {
    Command::new("ndmc")
        .env("LD_LIBRARY_PATH", "")
        .args(["-c", command])
        .output()
        .map_err(|error| format!("не удалось запустить ndmc: {error}"))
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
                .map(PathBuf::from)
                .unwrap_or_else(|| r2o_dir.join("files/meta-ranges.txt")),
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

pub struct MetaDnsManager<N, D> {
    network: N,
    ndm: D,
    paths: MetaDnsPaths,
    meta_ranges: Vec<(u32, u8)>,
    probe_attempts: usize,
    probe_retry_delay: Duration,
    resolve_attempts: usize,
    resolve_retry_delay: Duration,
}

impl<N: MetaNetwork, D: Ndm> MetaDnsManager<N, D> {
    pub fn new(network: N, ndm: D, paths: MetaDnsPaths) -> Self {
        Self {
            network,
            ndm,
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
        }
    }

    pub async fn refresh(&mut self) -> Result<(), String> {
        let ranges = std::fs::read_to_string(&self.paths.meta_ranges).map_err(|error| {
            format!(
                "не удалось прочитать диапазоны Meta из {}: {error}",
                self.paths.meta_ranges.display()
            )
        })?;
        self.meta_ranges = parse_meta_ranges(&ranges)?;
        if self.meta_ranges.is_empty() {
            return Err("в файле диапазонов Meta нет допустимых сетей".into());
        }
        let prior = read_manifest(&self.paths.manifest)?;
        let initial_config = if prior.is_empty() {
            None
        } else {
            let config = self.ndm.running_config()?;
            if config.trim().is_empty() {
                return Err("ndmc вернул пустую текущую конфигурацию".into());
            }
            Some(config)
        };
        let mut dead = Vec::new();
        let mut alive = 0_usize;
        for (host, address) in &prior {
            if !is_managed_host(host) {
                continue;
            }
            if !initial_config
                .as_deref()
                .is_some_and(|config| config_has_pair(config, host, *address))
            {
                continue;
            }
            if verify_with_retry(
                &self.network,
                host,
                *address,
                self.probe_attempts,
                self.probe_retry_delay,
                &self.paths.log,
            )
            .await
            {
                alive += 1;
            } else {
                dead.push((host.clone(), *address));
                append_log(
                    &self.paths.log,
                    &format!("своя запись не прошла TLS-проверку: {host} {address}"),
                );
            }
        }

        let answers = match resolve_with_retry(
            &self.network,
            self.resolve_attempts,
            self.resolve_retry_delay,
            &self.paths.log,
        )
        .await
        {
            Ok(answers) => answers,
            Err(error) => {
                if !dead.is_empty() && alive > 0 {
                    let mut view = NdmView::new(&mut self.ndm);
                    view.config = initial_config.clone();
                    drop_dead_pins(
                        &mut view,
                        &self.paths.manifest,
                        &self.paths.log,
                        &prior,
                        &dead,
                    )?;
                    view.save_if_changed()?;
                    append_log(
                        &self.paths.log,
                        "прямые DNS-службы недоступны; сняты только локально подтверждённые мёртвые записи",
                    );
                } else if !dead.is_empty() {
                    append_log(
                        &self.paths.log,
                        "прямые DNS-службы недоступны, а свои записи не прошли проверку; DNS оставлен без изменений",
                    );
                } else {
                    append_log(
                        &self.paths.log,
                        "прямые DNS-службы недоступны; текущие DNS-записи не изменены",
                    );
                }
                return Err(error);
            }
        };

        let mut filtered = BTreeMap::<String, Vec<Ipv4Addr>>::new();
        for host in META_HOSTS {
            let mut candidates_tried = 0;
            let mut verified = Vec::new();
            for address in answers.get(*host).into_iter().flatten().take(8) {
                if !is_meta_ip(&self.meta_ranges, *address) {
                    append_log(
                        &self.paths.log,
                        &format!("отброшен адрес вне диапазонов Meta: {host} {address}"),
                    );
                    continue;
                }
                if candidates_tried >= MAX_PROBE_CANDIDATES {
                    break;
                }
                candidates_tried += 1;
                if verify_with_retry(
                    &self.network,
                    host,
                    *address,
                    self.probe_attempts,
                    self.probe_retry_delay,
                    &self.paths.log,
                )
                .await
                {
                    verified.push(*address);
                    if verified.len() == MAX_HOST_ADDRESSES {
                        break;
                    }
                }
            }
            if !verified.is_empty() {
                filtered.insert((*host).to_string(), verified);
            }
        }

        apply_family_fallback(
            &self.network,
            &self.meta_ranges,
            ProbePolicy {
                attempts: self.probe_attempts,
                retry_delay: self.probe_retry_delay,
                log: &self.paths.log,
            },
            &answers,
            &prior,
            &dead,
            &mut filtered,
        )
        .await;
        if !filtered.contains_key("instagram.com") {
            let before = filtered.len();
            filtered.retain(|host, _| meta_family(host) != Some("instagram"));
            if filtered.len() != before {
                append_log(
                    &self.paths.log,
                    "семейство instagram не изменено: нет проверенного адреса instagram.com",
                );
            }
        }

        if filtered.is_empty() {
            if !dead.is_empty() && alive > 0 {
                let mut view = NdmView::new(&mut self.ndm);
                view.config = initial_config.clone();
                drop_dead_pins(
                    &mut view,
                    &self.paths.manifest,
                    &self.paths.log,
                    &prior,
                    &dead,
                )?;
                view.save_if_changed()?;
            }
            append_log(
                &self.paths.log,
                "нет адресов Meta с доступным TLS и подходящим сертификатом; остальные DNS-записи не изменены",
            );
            return Err("нет проверенных адресов узлов Meta".into());
        }

        let mut view = NdmView::new(&mut self.ndm);
        view.config = initial_config;
        drop_dead_pins(
            &mut view,
            &self.paths.manifest,
            &self.paths.log,
            &prior,
            &dead,
        )?;
        let mut next = BTreeSet::<PinPair>::new();
        for (host, address) in read_manifest(&self.paths.manifest)? {
            if is_managed_host(&host) && view.exists(&host, address)? {
                next.insert((host, address.to_string()));
            }
        }

        let mut add_failed = false;
        for host in META_HOSTS {
            for address in filtered.get(*host).into_iter().flatten() {
                if view.exists(host, *address)? {
                    continue;
                }
                let pair = ((*host).to_string(), address.to_string());
                next.insert(pair.clone());
                write_manifest(&self.paths.manifest, &next)?;
                match view.add(host, *address) {
                    Ok(()) => append_log(
                        &self.paths.log,
                        &format!("добавлена R2O-запись {host} {address}"),
                    ),
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
            let Some(fresh) = filtered.get(&host) else {
                continue;
            };
            if fresh.contains(&address) {
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

        write_manifest(&self.paths.manifest, &next)?;
        view.save_if_changed()?;
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
        let manifest = read_manifest(&self.paths.manifest)?;
        if manifest.is_empty() {
            let _ = std::fs::remove_file(&self.paths.manifest);
            append_log(&self.paths.log, "нет R2O-owned Meta DNS записей");
            return Ok(());
        }
        let mut view = NdmView::new(&mut self.ndm);
        for (host, address) in &manifest {
            if !is_managed_host(host) {
                continue;
            }
            if !view.exists(host, *address)? {
                continue;
            }
            view.remove(host, *address)?;
            append_log(
                &self.paths.log,
                &format!("удалена R2O-запись {host} {address}"),
            );
        }
        view.save_if_changed()?;
        std::fs::remove_file(&self.paths.manifest).map_err(|error| {
            format!(
                "не удалось удалить журнал принадлежащих записей {}: {error}",
                self.paths.manifest.display()
            )
        })?;
        Ok(())
    }
}

async fn resolve_with_retry<N: MetaNetwork>(
    network: &N,
    attempts: usize,
    retry_delay: Duration,
    log: &Path,
) -> Result<BTreeMap<String, Vec<Ipv4Addr>>, String> {
    let mut last_error = None;
    for attempt in 1..=attempts {
        match network.resolve().await {
            Ok(answers) => return Ok(answers),
            Err(error) => {
                last_error = Some(error);
                append_log(
                    log,
                    &format!("прямой DNS-запрос: попытка {attempt}/{attempts} не удалась"),
                );
                if attempt < attempts {
                    sleep(retry_delay).await;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| "прямой DNS-запрос не выполнен".into()))
}

async fn verify_with_retry<N: MetaNetwork>(
    network: &N,
    host: &str,
    address: Ipv4Addr,
    attempts: usize,
    retry_delay: Duration,
    log: &Path,
) -> bool {
    for attempt in 1..=attempts {
        if network.verify(host, address).await {
            return true;
        }
        if attempt < attempts {
            append_log(
                log,
                &format!("повтор TLS-пробы {attempt}/{attempts}: {host} {address}"),
            );
            sleep(retry_delay).await;
        }
    }
    false
}

async fn apply_family_fallback<N: MetaNetwork>(
    network: &N,
    ranges: &[(u32, u8)],
    policy: ProbePolicy<'_>,
    answers: &BTreeMap<String, Vec<Ipv4Addr>>,
    prior: &[(String, Ipv4Addr)],
    dead: &[(String, Ipv4Addr)],
    filtered: &mut BTreeMap<String, Vec<Ipv4Addr>>,
) {
    for host in META_HOSTS {
        if filtered.contains_key(*host) {
            continue;
        }
        let Some(family) = meta_family(host) else {
            continue;
        };
        let answered: BTreeSet<_> = answers.get(*host).into_iter().flatten().copied().collect();
        let mut candidates = Vec::new();
        for sibling in META_HOSTS {
            if let Some(addresses) = filtered.get(*sibling) {
                candidates.extend(
                    addresses
                        .iter()
                        .map(|address| ((*sibling).to_string(), *address)),
                );
            }
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
            filtered.insert((*host).to_string(), verified);
        }
    }
}

fn is_meta_ip(ranges: &[(u32, u8)], address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    ranges.iter().any(|(network, prefix)| {
        let mask = if *prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(*prefix))
        };
        value & mask == *network & mask
    })
}

fn config_has_pair(config: &str, host: &str, address: Ipv4Addr) -> bool {
    config.lines().any(|line| {
        let mut fields = line.split_ascii_whitespace();
        matches!(
            (fields.next(), fields.next(), fields.next(), fields.next()),
            (Some("ip"), Some("host"), Some(found_host), Some(found_ip))
                if found_host == host && found_ip == address.to_string()
        )
    })
}

fn drop_dead_pins<D: Ndm>(
    view: &mut NdmView<'_, D>,
    manifest_path: &Path,
    log: &Path,
    prior: &[(String, Ipv4Addr)],
    dead: &[(String, Ipv4Addr)],
) -> Result<(), String> {
    if dead.is_empty() {
        return Ok(());
    }
    for (host, address) in dead {
        if view.exists(host, *address)? {
            view.remove(host, *address)?;
            append_log(
                log,
                &format!(
                    "удалена недоступная R2O-запись {host} {address}; имя снова разрешается обычным DNS"
                ),
            );
        }
    }
    let dead_set: BTreeSet<_> = dead.iter().cloned().collect();
    let remaining: BTreeSet<_> = prior
        .iter()
        .filter(|pair| !dead_set.contains(*pair))
        .map(|(host, address)| (host.clone(), address.to_string()))
        .collect();
    write_manifest(manifest_path, &remaining)
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

    fn exists(&mut self, host: &str, address: Ipv4Addr) -> Result<bool, String> {
        Ok(config_has_pair(self.config()?, host, address))
    }

    fn add(&mut self, host: &str, address: Ipv4Addr) -> Result<(), String> {
        let result = self.ndm.add(host, address);
        self.changed = true;
        self.config = None;
        result
    }

    fn remove(&mut self, host: &str, address: Ipv4Addr) -> Result<(), String> {
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

pub async fn refresh_from_env() -> Result<(), String> {
    let paths = MetaDnsPaths::from_env();
    let ca_bundle = resolve_ca_bundle()?;
    let network = DirectMetaNetwork::new(Some(ca_bundle));
    let mut manager = MetaDnsManager::new(network, SystemNdm, paths);
    manager.refresh().await
}

pub fn remove_from_env() -> Result<(), String> {
    let paths = MetaDnsPaths::from_env();
    let mut manager = MetaDnsManager::new(DirectMetaNetwork::new(None), SystemNdm, paths);
    manager.remove_owned()
}

pub async fn run_scheduler() -> Result<(), String> {
    let mut scheduler = MetaDnsScheduler::from_env();
    loop {
        if let Err(error) = scheduler.tick().await {
            append_log(
                &scheduler.log,
                &format!("ошибка планировщика Meta DNS: {error}"),
            );
        }
        sleep(scheduler.interval).await;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Clock {
    day: String,
    hhmm: String,
    epoch: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Attempt {
    last_epoch: u64,
    last_day: Option<String>,
    failures: u32,
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

    async fn tick(&mut self) -> Result<(), String> {
        let clock = local_clock()?;
        let offset = self.refresh_offset()?;
        let run_at = self
            .explicit_run_at
            .clone()
            .unwrap_or_else(|| format!("{:02}{:02}", 1 + offset / 60, offset % 60));
        let attempt = read_attempt(&self.attempt);
        if !should_run(&self.state, &attempt, &clock, &run_at, self.retry_after) {
            return Ok(());
        }

        let next = Attempt {
            last_epoch: clock.epoch,
            last_day: Some(clock.day.clone()),
            failures: attempt.failures.saturating_add(1),
        };
        write_attempt(&self.attempt, &next)?;
        append_log(&self.log, "обновление DNS Instagram/WhatsApp: старт");
        match refresh_from_env().await {
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
                    &format!(
                        "DNS Instagram/WhatsApp обновлён; следующий запуск после {run_at} завтра"
                    ),
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

    fn refresh_offset(&self) -> Result<u64, String> {
        let stored = std::fs::read_to_string(&self.offset).unwrap_or_default();
        let stored = stored.trim();
        if let Some(raw) = stored.strip_prefix("v2 ")
            && let Ok(offset) = raw.parse::<u64>()
            && offset <= 239
        {
            return Ok(offset);
        }
        if let Ok(old) = stored.parse::<u64>()
            && old <= 59
        {
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

fn local_clock() -> Result<Clock, String> {
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

fn read_attempt(path: &Path) -> Attempt {
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

fn should_run(
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

fn read_success_day(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| contents.lines().next().map(str::to_string))
}

fn backoff_after(failures: u32, retry_after: u64) -> u64 {
    if failures == 0 {
        return 0;
    }
    let exponent = failures.saturating_sub(1).min(16);
    retry_after.saturating_mul(1_u64 << exponent).min(86_400)
}

fn write_attempt(path: &Path, attempt: &Attempt) -> Result<(), String> {
    let day = attempt.last_day.as_deref().unwrap_or("");
    atomic_write(
        path,
        format!("{} {day} {}\n", attempt.last_epoch, attempt.failures).as_bytes(),
    )
}

fn random_u16() -> Result<u16, String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0_u8; 2];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "криптографический источник случайных данных недоступен".to_string())?;
    Ok(u16::from_ne_bytes(bytes))
}

fn resolve_ca_bundle() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("R2O_IP_CA_BUNDLE") {
        let path = PathBuf::from(path);
        return if path.is_file() {
            Ok(path)
        } else {
            Err(format!(
                "набор сертификатов CA недоступен для чтения: {}",
                path.display()
            ))
        };
    }
    for candidate in [
        PathBuf::from("/opt/etc/ssl/certs/ca-certificates.crt"),
        PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err("системный набор сертификатов CA для проверки узлов Meta недоступен".into())
}

pub fn parse_meta_ranges(input: &str) -> Result<Vec<(u32, u8)>, String> {
    let mut ranges = Vec::new();
    for line in input.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some((address, prefix)) = line.split_once('/') else {
            continue;
        };
        let (Ok(address), Ok(prefix)) = (address.parse::<Ipv4Addr>(), prefix.parse::<u8>()) else {
            continue;
        };
        if prefix > 32 {
            continue;
        }
        let network = u32::from(address);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix))
        };
        ranges.push((network & mask, prefix));
    }
    Ok(ranges)
}

fn is_managed_host(host: &str) -> bool {
    META_HOSTS.contains(&host)
}

fn meta_family(host: &str) -> Option<&'static str> {
    if host == "instagram.com"
        || (host.ends_with(".instagram.com") && host != "instagram.c10r.instagram.com")
        || host.ends_with(".cdninstagram.com")
        || host == "instagram.c10r.instagram.com"
    {
        Some("instagram")
    } else if host.ends_with(".fbcdn.net") {
        Some("fbcdn")
    } else if host.ends_with(".whatsapp.net") || host.ends_with(".whatsapp.com") {
        Some("whatsapp")
    } else {
        None
    }
}

fn read_manifest(path: &Path) -> Result<Vec<(String, Ipv4Addr)>, String> {
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
        if let Ok(address) = address.parse::<Ipv4Addr>() {
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

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("не удалось создать каталог состояния: {error}"))?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("не удалось создать временный файл состояния: {error}"))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("не удалось записать файл состояния: {error}"))?;
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

fn append_log(path: &Path, message: &str) {
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

fn env_bounded(key: &str, default: u64, minimum: u64, maximum: u64) -> u64 {
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

    #[test]
    fn direct_dns_results_are_unique_and_bounded() {
        let mut addresses = Vec::new();
        for last_octet in 1..=10 {
            append_address(&mut addresses, Ipv4Addr::new(157, 240, 0, last_octet));
        }
        append_address(&mut addresses, Ipv4Addr::new(157, 240, 0, 1));
        assert_eq!(addresses.len(), DNS_ADDRESS_LIMIT);
        assert_eq!(addresses[0], Ipv4Addr::new(157, 240, 0, 1));
        assert_eq!(addresses[7], Ipv4Addr::new(157, 240, 0, 8));
    }

    struct FakeNetwork {
        answers: Mutex<Result<BTreeMap<String, Vec<Ipv4Addr>>, String>>,
        default_verified: bool,
        verified: BTreeSet<(String, Ipv4Addr)>,
        rejected: BTreeSet<(String, Ipv4Addr)>,
        probes: Mutex<Vec<(String, Ipv4Addr)>>,
    }

    impl FakeNetwork {
        fn with_answers(answers: BTreeMap<String, Vec<Ipv4Addr>>) -> Self {
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
        fn resolve<'a>(&'a self) -> NetFuture<'a, Result<BTreeMap<String, Vec<Ipv4Addr>>, String>> {
            Box::pin(async move { self.answers.lock().unwrap().clone() })
        }

        fn verify<'a>(&'a self, host: &'a str, address: Ipv4Addr) -> NetFuture<'a, bool> {
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
        records: BTreeSet<(String, Ipv4Addr)>,
        fail_add: bool,
        empty_config: bool,
        saves: usize,
        mutations: Vec<String>,
    }

    impl Ndm for FakeNdm {
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

        fn add(&mut self, host: &str, address: Ipv4Addr) -> Result<(), String> {
            self.mutations.push(format!("add {host} {address}"));
            if self.fail_add {
                return Err("injected add failure".into());
            }
            self.records.insert((host.to_string(), address));
            Ok(())
        }

        fn remove(&mut self, host: &str, address: Ipv4Addr) -> Result<(), String> {
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

    fn answer(host: &str, addresses: &[&str]) -> (String, Vec<Ipv4Addr>) {
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
        let network = FakeNetwork::with_answers(BTreeMap::from([answer(
            "instagram.com",
            &["157.240.9.180"],
        )]));
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
    async fn failed_add_keeps_previous_working_pins_and_does_not_retire_them() {
        let paths = paths("add-failure");
        let old_edge = "157.240.9.170".parse().unwrap();
        let new_edge = "157.240.9.180".parse().unwrap();
        let mut ndm = FakeNdm {
            fail_add: true,
            ..FakeNdm::default()
        };
        ndm.records.insert(("instagram.com".into(), old_edge));
        std::fs::write(&paths.manifest, format!("instagram.com {old_edge}\n")).unwrap();
        let network = FakeNetwork::with_answers(BTreeMap::from([answer(
            "instagram.com",
            &["157.240.9.180"],
        )]));
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
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[tokio::test]
    async fn unavailable_relay_removes_dead_pins_only_when_another_owned_pin_is_alive() {
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

        assert!(manager.refresh().await.is_err());
        assert!(
            !manager
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
            format!("web.whatsapp.com {alive}\n")
        );
        assert_eq!(manager.ndm.saves, 1);
        let _ = std::fs::remove_dir_all(paths.r2o_dir);
    }

    #[tokio::test]
    async fn empty_ndm_read_fails_closed_without_changing_manifest_or_dns() {
        let paths = paths("empty-config");
        let owned: Ipv4Addr = "157.240.9.170".parse().unwrap();
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
        let borrowed: Ipv4Addr = "57.144.245.32".parse().unwrap();
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
        let owned: Ipv4Addr = "157.240.9.174".parse().unwrap();
        let user: Ipv4Addr = "157.240.9.175".parse().unwrap();
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
}
