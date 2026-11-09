//! Ночное обновление IP-диапазонов и доменных списков без VPS.
//!
//! Модуль переиспользует планировщик и атомарную запись `meta_dns`, но
//! хранит свои state-файлы в `state/lists`. Источники — публичные GitHub
//! Raw, резервное зеркало — jsDelivr. Скачанные данные проверяются,
//! сравниваются с last-known-good и только потом заменяют файл.
//!
//! Списки не превращаются в маршруты: updater не вызывает nft/ndmc и не
//! трогает Discovery. Meta-диапазоны читает существующий `meta_dns`,
//! остальные списки доступны как сохранённая база для следующих этапов.

use crate::meta_dns::{
    Attempt, append_log, atomic_write, backoff_after, env_bounded, local_clock, random_u16,
    read_attempt, should_run, write_attempt,
};
use r2k_core::dns::{DNS_RESOLVERS, build_a_query, parse_a_reply};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

const USER_AGENT: &str = "r2o-list-updater/1";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const FETCH_ATTEMPTS: usize = 2;
const MAX_REDIRECTS: usize = 3;
const MAX_GEOSITE_FILES: usize = 32;
const MAX_GEOSITE_DEPTH: usize = 4;
const MANIFEST_VERSION: u32 = 1;
const MANIFEST_LIMIT: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListKind {
    Cidr,
    Domains,
}

#[derive(Clone, Copy, Debug)]
pub struct ListSource {
    pub name: &'static str,
    pub kind: ListKind,
    pub parts: &'static [&'static str],
    pub min_lines: usize,
    pub max_lines: usize,
}

/// Актуальные источники. ASN-файлы ipverse обновляются ежедневно по BGP;
/// geosite-файлы v2fly содержат `include:` и разрешаются рекурсивно.
pub const SOURCES: &[ListSource] = &[
    ListSource {
        name: "meta-ranges",
        kind: ListKind::Cidr,
        parts: &[
            "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/32934/ipv4-aggregated.txt",
        ],
        min_lines: 10,
        max_lines: 4096,
    },
    ListSource {
        name: "telegram-cidr",
        kind: ListKind::Cidr,
        parts: &[
            "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/62041/ipv4-aggregated.txt",
            "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/59930/ipv4-aggregated.txt",
        ],
        min_lines: 5,
        max_lines: 4096,
    },
    ListSource {
        name: "google-cidr",
        kind: ListKind::Cidr,
        parts: &[
            "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/15169/ipv4-aggregated.txt",
        ],
        min_lines: 20,
        max_lines: 16_384,
    },
    ListSource {
        name: "cloudflare-cidr",
        kind: ListKind::Cidr,
        parts: &[
            "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/13335/ipv4-aggregated.txt",
        ],
        min_lines: 10,
        max_lines: 32_768,
    },
    ListSource {
        name: "geosite-meta",
        kind: ListKind::Domains,
        parts: &["https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/meta"],
        min_lines: 3,
        max_lines: 100_000,
    },
    ListSource {
        name: "geosite-telegram",
        kind: ListKind::Domains,
        parts: &[
            "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/telegram",
        ],
        min_lines: 3,
        max_lines: 100_000,
    },
    ListSource {
        name: "geosite-google",
        kind: ListKind::Domains,
        parts: &[
            "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/google",
        ],
        min_lines: 10,
        max_lines: 100_000,
    },
    ListSource {
        name: "geosite-cloudflare",
        kind: ListKind::Domains,
        parts: &[
            "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/cloudflare",
        ],
        min_lines: 3,
        max_lines: 100_000,
    },
];

#[derive(Clone, Debug)]
pub struct ListPaths {
    pub r2o_dir: PathBuf,
    pub dir: PathBuf,
    pub log: PathBuf,
}

impl ListPaths {
    pub fn from_env() -> Self {
        let r2o_dir = std::env::var_os("R2O_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/opt/r2o"));
        let dir = std::env::var_os("R2O_LISTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| r2o_dir.join("state/lists"));
        let log = std::env::var_os("R2O_LISTS_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|| r2o_dir.join("log/lists-update.log"));
        Self { r2o_dir, dir, log }
    }
}

#[derive(Clone, Debug)]
pub struct FetchResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub etag: Option<String>,
}

pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<FetchResponse, String>> + Send + 'a>>;

pub trait ListFetch: Send + Sync {
    fn get<'a>(&'a self, url: &'a str, max_bytes: usize, etag: Option<&'a str>) -> FetchFuture<'a>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DirectFetch;

impl ListFetch for DirectFetch {
    fn get<'a>(&'a self, url: &'a str, max_bytes: usize, etag: Option<&'a str>) -> FetchFuture<'a> {
        Box::pin(async move { self.fetch(url, max_bytes, etag).await })
    }
}

impl DirectFetch {
    async fn fetch(
        &self,
        url: &str,
        max_bytes: usize,
        etag: Option<&str>,
    ) -> Result<FetchResponse, String> {
        timeout(FETCH_TIMEOUT, fetch_redirects(url, max_bytes, etag, 0))
            .await
            .map_err(|_| format!("истёк общий тайм-аут загрузки {url}"))?
    }
}

#[derive(Debug)]
enum FetchOutcome {
    Response(FetchResponse),
    Redirect(String),
}

async fn fetch_redirects(
    url: &str,
    max_bytes: usize,
    etag: Option<&str>,
    redirects: usize,
) -> Result<FetchResponse, String> {
    if redirects > MAX_REDIRECTS {
        return Err(format!("слишком много перенаправлений для {url}"));
    }
    let parts = parse_https_url(url)?;
    let addresses = resolve_ips(parts.host).await?;
    let mut last_error = None;
    for address in addresses.into_iter().take(4) {
        match fetch_once(&parts, address, max_bytes, etag).await {
            Ok(FetchOutcome::Response(response)) => return Ok(response),
            Ok(FetchOutcome::Redirect(location)) => {
                let next = resolve_location(url, &location)?;
                return Box::pin(fetch_redirects(&next, max_bytes, etag, redirects + 1)).await;
            }
            Err(error) => last_error = Some(format!("{address}: {error}")),
        }
    }
    Err(last_error.unwrap_or_else(|| format!("не удалось подключиться к {}", parts.host)))
}

struct UrlParts<'a> {
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_https_url(url: &str) -> Result<UrlParts<'_>, String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("разрешён только https: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .map_err(|_| format!("неверный порт в URL: {url}"))?,
        ),
        None => (authority, 443),
    };
    if host.is_empty()
        || host.contains('@')
        || host.contains('[')
        || host.contains(']')
        || path.is_empty()
    {
        return Err(format!("неверный URL: {url}"));
    }
    Ok(UrlParts { host, port, path })
}

fn resolve_location(base: &str, location: &str) -> Result<String, String> {
    if location.starts_with("https://") {
        return Ok(location.to_owned());
    }
    if let Some(path) = location.strip_prefix('/') {
        let parts = parse_https_url(base)?;
        return Ok(format!("https://{}{}", parts.host, format!("/{path}")));
    }
    Err(format!("неподдерживаемое перенаправление: {location}"))
}

async fn resolve_ips(host: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut result = Vec::new();
    if let Ok(Ok(addresses)) = timeout(DNS_TIMEOUT, lookup_host((host, 443))).await {
        for address in addresses {
            if let std::net::IpAddr::V4(address) = address.ip() {
                push_unique(&mut result, address);
            }
        }
    }
    // Системный DNS может отдать устаревший/подменённый адрес. Прямые
    // запросы к публичным резолверам добавляем всегда, а не только при
    // пустом ответе: иначе первый же неверный A-рекорд блокирует загрузку.
    let direct = futures_util::future::join_all(
        DNS_RESOLVERS
            .iter()
            .take(4)
            .map(|resolver| query_public_dns(resolver.address, host)),
    )
    .await;
    for addresses in direct.into_iter().flatten() {
        for address in addresses {
            push_unique(&mut result, address);
        }
    }
    if result.is_empty() {
        return Err(format!("DNS не разрешил {host}"));
    }
    Ok(result)
}

async fn query_public_dns(resolver: Ipv4Addr, host: &str) -> Result<Vec<Ipv4Addr>, String> {
    let id = random_u16()?;
    let query = build_a_query(id, host).map_err(|_| format!("некорректное DNS-имя {host}"))?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| format!("не удалось открыть DNS-сокет: {error}"))?;
    socket
        .connect(SocketAddr::from((resolver, 53)))
        .await
        .map_err(|error| format!("не удалось подключиться к DNS {resolver}: {error}"))?;
    timeout(DNS_TIMEOUT, async {
        socket
            .send(&query)
            .await
            .map_err(|error| format!("не удалось отправить DNS-запрос: {error}"))?;
        let mut response = [0_u8; 4096];
        let length = socket
            .recv(&mut response)
            .await
            .map_err(|error| format!("не удалось получить DNS-ответ: {error}"))?;
        parse_a_reply(&response[..length], &query, host)
            .map_err(|_| format!("DNS {resolver} вернул некорректный ответ для {host}"))
    })
    .await
    .map_err(|_| format!("истёк DNS-тайм-аут {resolver} для {host}"))?
}

async fn fetch_once(
    parts: &UrlParts<'_>,
    address: Ipv4Addr,
    max_bytes: usize,
    etag: Option<&str>,
) -> Result<FetchOutcome, String> {
    let tcp = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect(SocketAddr::from((address, parts.port))),
    )
    .await
    .map_err(|_| format!("тайм-аут TCP к {address}"))?
    .map_err(|error| format!("TCP к {address}: {error}"))?;
    tcp.set_nodelay(true).ok();

    let config = tls_config()?;
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from(parts.host.to_owned())
        .map_err(|_| format!("неверное TLS-имя {}", parts.host))?;
    let mut stream = timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| format!("тайм-аут TLS к {}", parts.host))?
        .map_err(|error| format!("TLS к {}: {error}", parts.host))?;

    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n",
        parts.path, parts.host, USER_AGENT
    );
    if let Some(etag) = etag {
        request.push_str(&format!("If-None-Match: {etag}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("не удалось отправить HTTP-запрос: {error}"))?;

    let (head, mut body) = read_headers(&mut stream).await?;
    let parsed = parse_response_head(&head)?;
    if matches!(parsed.status, 301 | 302 | 303 | 307 | 308) {
        let location = parsed
            .location
            .ok_or_else(|| "перенаправление без Location".to_string())?;
        return Ok(FetchOutcome::Redirect(location));
    }
    if parsed.status == 304 {
        return Ok(FetchOutcome::Response(FetchResponse {
            status: 304,
            body: Vec::new(),
            etag: parsed.etag,
        }));
    }
    if !(200..300).contains(&parsed.status) {
        return Err(format!("HTTP {}", parsed.status));
    }
    if body.len() > max_bytes {
        return Err(format!("ответ больше {max_bytes} байт"));
    }
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("чтение тела ответа: {error}"))?;
        if read == 0 {
            break;
        }
        if body.len().saturating_add(read) > max_bytes {
            return Err(format!("ответ больше {max_bytes} байт"));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(FetchOutcome::Response(FetchResponse {
        status: parsed.status,
        body,
        etag: parsed.etag,
    }))
}

fn tls_config() -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

async fn read_headers(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(index) = find_bytes(&buffer, b"\r\n\r\n") {
            return Ok((buffer[..index + 4].to_vec(), buffer[index + 4..].to_vec()));
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err("HTTP-заголовки больше предела".to_string());
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("чтение HTTP-заголовков: {error}"))?;
        if read == 0 {
            return Err("соединение закрыто до конца HTTP-заголовков".to_string());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

struct ParsedHead {
    status: u16,
    location: Option<String>,
    etag: Option<String>,
}

fn parse_response_head(head: &[u8]) -> Result<ParsedHead, String> {
    let text = std::str::from_utf8(head).map_err(|_| "HTTP-заголовки не UTF-8".to_string())?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "пустой HTTP-ответ".to_string())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| format!("неверная HTTP-статусная строка: {status_line}"))?;
    let mut location = None;
    let mut etag = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("location") {
            location = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("etag") {
            etag = Some(value.to_owned());
        }
    }
    Ok(ParsedHead {
        status,
        location,
        etag,
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn push_unique(values: &mut Vec<Ipv4Addr>, value: Ipv4Addr) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ListManifest {
    version: u32,
    source: String,
    fetched_at: u64,
    etag: Option<String>,
    sha256: String,
    lines: usize,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceOutcome {
    Updated,
    Fresh,
    NotModified,
    KeptLastKnownGood,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ListSummary {
    pub updated: usize,
    pub fresh: usize,
    pub kept: usize,
    pub failed: usize,
}

pub struct ListUpdater<F: ListFetch> {
    fetch: F,
    paths: ListPaths,
    state: PathBuf,
    attempt: PathBuf,
    offset: PathBuf,
    ttl: Duration,
    retry_after: u64,
    retry_delay: Duration,
    force: bool,
}

impl ListUpdater<DirectFetch> {
    pub fn from_env() -> Self {
        let paths = ListPaths::from_env();
        let state = std::env::var_os("R2O_LISTS_SCHED_STATE")
            .map(PathBuf::from)
            .unwrap_or_else(|| paths.r2o_dir.join("state/lists-update-last-success"));
        let attempt = std::env::var_os("R2O_LISTS_SCHED_ATTEMPT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp/r2o-lists-update-last-attempt"));
        let offset = std::env::var_os("R2O_LISTS_SCHED_OFFSET")
            .map(PathBuf::from)
            .unwrap_or_else(|| paths.r2o_dir.join("state/lists-update-offset"));
        Self {
            fetch: DirectFetch,
            paths,
            state,
            attempt,
            offset,
            ttl: Duration::from_secs(env_bounded("R2O_LISTS_TTL", 86_400, 3_600, 604_800)),
            retry_after: env_bounded("R2O_LISTS_RETRY_AFTER", 1_800, 60, 86_400),
            retry_delay: Duration::from_secs(2),
            force: std::env::var("R2O_LISTS_FORCE").as_deref() == Ok("1"),
        }
    }
}

impl<F: ListFetch> ListUpdater<F> {
    pub fn new(fetch: F, paths: ListPaths) -> Self {
        let r2o_dir = paths.r2o_dir.clone();
        Self {
            fetch,
            state: r2o_dir.join("state/lists-update-last-success"),
            attempt: r2o_dir.join("state/lists-update-last-attempt"),
            offset: r2o_dir.join("state/lists-update-offset"),
            paths,
            ttl: Duration::from_secs(86_400),
            retry_after: 1_800,
            retry_delay: Duration::from_secs(2),
            force: false,
        }
    }

    #[cfg(test)]
    fn with_retry_delay(mut self, retry_delay: Duration) -> Self {
        self.retry_delay = retry_delay;
        self
    }

    pub async fn tick(&mut self) -> Result<(), String> {
        let clock = local_clock()?;
        let offset = self.refresh_offset()?;
        let run_at = run_at_for_offset(offset);
        if !self.state.exists() && clock.hhmm.as_str() < run_at.as_str() {
            return Ok(());
        }
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
        append_log(&self.paths.log, "обновление списков: старт");
        match self.update_all_with_now(clock.epoch, self.force).await {
            Ok(summary) => {
                write_attempt(
                    &self.attempt,
                    &Attempt {
                        failures: 0,
                        ..next
                    },
                )?;
                atomic_write(&self.state, format!("{}\n", clock.day).as_bytes())?;
                append_log(
                    &self.paths.log,
                    &format!(
                        "списки обновлены: updated={}, fresh={}, kept={}, failed={}",
                        summary.updated, summary.fresh, summary.kept, summary.failed
                    ),
                );
            }
            Err(error) => {
                let delay = backoff_after(next.failures, self.retry_after);
                append_log(
                    &self.paths.log,
                    &format!(
                        "списки не обновлены ({error}); подряд неудач: {}, следующая попытка через {delay} с",
                        next.failures
                    ),
                );
            }
        }
        Ok(())
    }

    pub async fn update_all(&mut self, force: bool) -> Result<ListSummary, String> {
        let now = now_epoch()?;
        self.update_all_with_now(now, force).await
    }

    async fn update_all_with_now(&mut self, now: u64, force: bool) -> Result<ListSummary, String> {
        let mut summary = ListSummary::default();
        let mut fatal = None;
        for source in SOURCES {
            match self.update_one(source, now, force).await {
                Ok(SourceOutcome::Updated) => summary.updated += 1,
                Ok(SourceOutcome::Fresh | SourceOutcome::NotModified) => summary.fresh += 1,
                Ok(SourceOutcome::KeptLastKnownGood) => summary.kept += 1,
                Err(error) => {
                    summary.failed += 1;
                    append_log(
                        &self.paths.log,
                        &format!("{}: {error}; last-known-good не найден", source.name),
                    );
                    if source.name == "meta-ranges" {
                        fatal = Some(error);
                    }
                }
            }
        }
        if let Some(error) = fatal {
            return Err(format!("нет актуальных диапазонов Meta: {error}"));
        }
        Ok(summary)
    }

    async fn update_one(
        &mut self,
        source: &ListSource,
        now: u64,
        force: bool,
    ) -> Result<SourceOutcome, String> {
        let destination = self.paths.dir.join(format!("{}.txt", source.name));
        let manifest_path = self.paths.dir.join(format!("{}.json", source.name));
        let existing = read_existing(source, &destination, &manifest_path, now);
        let has_saved = existing.is_some() || self.shipped_fallback(source).is_some();
        if !force
            && let Some((manifest, _)) = &existing
            && now.saturating_sub(manifest.fetched_at) <= self.ttl.as_secs()
        {
            return Ok(SourceOutcome::Fresh);
        }
        let etag = if source.parts.len() == 1 {
            existing
                .as_ref()
                .and_then(|(manifest, _)| manifest.etag.as_deref())
        } else {
            None
        };
        match self.download_source(source, etag).await {
            Ok(None) => {
                if let Some((mut manifest, _)) = existing {
                    manifest.fetched_at = now;
                    self.write_manifest(&manifest_path, &manifest)?;
                    Ok(SourceOutcome::NotModified)
                } else {
                    Err("источник вернул 304 без сохранённой базы".to_string())
                }
            }
            Ok(Some(body)) => {
                if body.len() > MAX_RESPONSE_BYTES {
                    return self.keep_or_fail(
                        source,
                        has_saved,
                        format!("ответ больше {MAX_RESPONSE_BYTES}"),
                    );
                }
                let text = match String::from_utf8(body) {
                    Ok(text) => text,
                    Err(_) => {
                        return self.keep_or_fail(
                            source,
                            has_saved,
                            "источник вернул не-UTF-8 данные".to_string(),
                        );
                    }
                };
                let normalized = match source.kind {
                    ListKind::Cidr => normalize_cidrs(&text, source),
                    ListKind::Domains => self.collect_domains(source, &text).await,
                };
                let normalized = match normalized {
                    Ok(normalized) => normalized,
                    Err(error) => {
                        return self.keep_or_fail(source, has_saved, error);
                    }
                };
                let lines = count_data_lines(&normalized);
                if let Some((old, _)) = &existing
                    && old.lines > 0
                    && lines.saturating_mul(2) < old.lines
                {
                    return self.keep_or_fail(
                        source,
                        has_saved,
                        format!(
                            "список {} ужался более чем вдвое: {} -> {} строк",
                            source.name, old.lines, lines
                        ),
                    );
                }
                let bytes = normalized.as_bytes();
                let sha256 = sha256_hex(bytes);
                let changed = existing
                    .as_ref()
                    .map(|(_, old_body)| old_body != &normalized)
                    .unwrap_or(true);
                if changed {
                    atomic_write(&destination, bytes)?;
                }
                let manifest = ListManifest {
                    version: MANIFEST_VERSION,
                    source: source.parts.join(","),
                    fetched_at: now,
                    etag: None,
                    sha256,
                    lines,
                    bytes: bytes.len(),
                };
                self.write_manifest(&manifest_path, &manifest)?;
                append_log(
                    &self.paths.log,
                    &format!("{}: {} строк, {} байт", source.name, lines, bytes.len()),
                );
                Ok(if changed {
                    SourceOutcome::Updated
                } else {
                    SourceOutcome::NotModified
                })
            }
            Err(error) => self.keep_or_fail(source, has_saved, error),
        }
    }

    fn keep_or_fail(
        &self,
        source: &ListSource,
        has_existing: bool,
        error: String,
    ) -> Result<SourceOutcome, String> {
        if has_existing {
            append_log(
                &self.paths.log,
                &format!("{}: {error}; оставлена сохранённая база", source.name),
            );
            Ok(SourceOutcome::KeptLastKnownGood)
        } else {
            Err(error)
        }
    }

    /// Поставляемый с выпуском снимок тоже считается сохранённой базой:
    /// на чистой установке без интернета Meta-диапазоны уже есть в
    /// `files/meta-ranges.txt`, и первый ночной прогон не должен падать.
    fn shipped_fallback(&self, source: &ListSource) -> Option<String> {
        let path = self
            .paths
            .r2o_dir
            .join("files")
            .join(format!("{}.txt", source.name));
        let body = std::fs::read_to_string(path).ok()?;
        match source.kind {
            ListKind::Cidr => normalize_cidrs(&body, source).ok(),
            ListKind::Domains => {
                let valid = body
                    .lines()
                    .filter_map(|line| normalize_domain(line.trim()))
                    .count();
                (valid >= source.min_lines).then_some(body)
            }
        }
    }

    async fn download_source(
        &self,
        source: &ListSource,
        etag: Option<&str>,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut body = Vec::new();
        for part in source.parts {
            match self.download_text(part, MAX_RESPONSE_BYTES, etag).await? {
                Some(text) => {
                    body.extend_from_slice(text.as_bytes());
                    body.push(b'\n');
                }
                None => return Ok(None),
            }
        }
        Ok(Some(body))
    }

    async fn download_text(
        &self,
        url: &str,
        max_bytes: usize,
        etag: Option<&str>,
    ) -> Result<Option<String>, String> {
        let mut candidates = vec![url.to_owned()];
        if let Some(mirror) = mirror_url(url) {
            candidates.push(mirror);
        }
        let mut last_error = None;
        for (index, candidate) in candidates.iter().enumerate() {
            for attempt in 0..FETCH_ATTEMPTS {
                match self
                    .fetch
                    .get(candidate, max_bytes, if index == 0 { etag } else { None })
                    .await
                {
                    Ok(response) if response.status == 304 => return Ok(None),
                    Ok(response) if response.status == 200 => {
                        return String::from_utf8(response.body)
                            .map(Some)
                            .map_err(|_| format!("{candidate}: ответ не UTF-8"));
                    }
                    Ok(response) => {
                        last_error = Some(format!("{}: HTTP {}", candidate, response.status));
                    }
                    Err(error) => {
                        last_error = Some(format!("{candidate}: {error}"));
                    }
                }
                if attempt + 1 < FETCH_ATTEMPTS {
                    tokio::time::sleep(self.retry_delay).await;
                }
            }
        }
        Err(last_error.unwrap_or_else(|| format!("не удалось скачать {url}")))
    }

    async fn collect_domains(
        &self,
        source: &ListSource,
        root_text: &str,
    ) -> Result<String, String> {
        let root_url = source
            .parts
            .first()
            .ok_or_else(|| format!("{}: нет источника", source.name))?;
        let base = root_url
            .rsplit_once('/')
            .map(|(base, _)| base)
            .ok_or_else(|| format!("{root_url}: нет базового URL"))?;
        let mut domains = BTreeSet::new();
        let mut visited = HashSet::new();
        let mut files = 0;
        self.collect_geosite(
            base,
            root_url,
            root_text,
            0,
            &mut files,
            &mut visited,
            &mut domains,
        )
        .await?;
        if domains.len() < source.min_lines {
            return Err(format!(
                "{}: слишком мало доменов ({} < {})",
                source.name,
                domains.len(),
                source.min_lines
            ));
        }
        if domains.len() > source.max_lines {
            return Err(format!(
                "{}: слишком много доменов ({} > {})",
                source.name,
                domains.len(),
                source.max_lines
            ));
        }
        let mut output = format!("# R2O {}\n# source: {}\n", source.name, source.parts[0]);
        for domain in &domains {
            output.push_str(domain);
            output.push('\n');
        }
        Ok(output)
    }

    async fn collect_geosite(
        &self,
        base: &str,
        url: &str,
        text: &str,
        depth: usize,
        files: &mut usize,
        visited: &mut HashSet<String>,
        domains: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if depth > MAX_GEOSITE_DEPTH {
            return Err("geosite: слишком глубокая вложенность include".to_string());
        }
        *files += 1;
        if *files > MAX_GEOSITE_FILES {
            return Err("geosite: слишком много include-файлов".to_string());
        }
        if !visited.insert(url.to_owned()) {
            return Ok(());
        }
        let mut includes = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix("include:") {
                let name = name.split_whitespace().next().unwrap_or_default();
                if valid_include_name(name) {
                    includes.push(name.to_owned());
                } else {
                    return Err(format!("geosite: небезопасный include {name}"));
                }
                continue;
            }
            let token = line.split_whitespace().next().unwrap_or_default();
            let candidate = token
                .strip_prefix("domain:")
                .or_else(|| token.strip_prefix("full:"))
                .unwrap_or(token);
            if token.starts_with("keyword:") || token.starts_with("regexp:") {
                continue;
            }
            if let Some(domain) = normalize_domain(candidate) {
                domains.insert(domain);
            }
            if domains.len() > 100_000 {
                return Err("geosite: слишком много доменов".to_string());
            }
        }
        for name in includes {
            let include_url = format!("{base}/{name}");
            let text = self
                .download_text(&include_url, MAX_RESPONSE_BYTES, None)
                .await?
                .ok_or_else(|| format!("{include_url}: неожиданный 304"))?;
            Box::pin(self.collect_geosite(
                base,
                &include_url,
                &text,
                depth + 1,
                files,
                visited,
                domains,
            ))
            .await?;
        }
        Ok(())
    }

    fn write_manifest(&self, path: &Path, manifest: &ListManifest) -> Result<(), String> {
        let body = serde_json::to_vec(manifest).map_err(|error| error.to_string())?;
        atomic_write(path, &body)
    }

    fn refresh_offset(&self) -> Result<u64, String> {
        let stored = std::fs::read_to_string(&self.offset).unwrap_or_default();
        if let Ok(offset) = stored.trim_end_matches('\n').parse::<u64>()
            && offset <= 30
        {
            return Ok(offset);
        }
        let offset = (random_u16()? % 31) as u64;
        atomic_write(&self.offset, format!("{offset}\n").as_bytes())?;
        append_log(
            &self.paths.log,
            &format!("окно обновления списков: 03:00 + {offset} мин"),
        );
        Ok(offset)
    }
}

fn read_existing(
    source: &ListSource,
    path: &Path,
    manifest_path: &Path,
    now: u64,
) -> Option<(ListManifest, String)> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_RESPONSE_BYTES as u64 {
        return None;
    }
    let body = std::fs::read_to_string(path).ok()?;
    match source.kind {
        ListKind::Cidr => {
            normalize_cidrs(&body, source).ok()?;
        }
        ListKind::Domains => {
            if body
                .lines()
                .filter_map(|line| normalize_domain(line.trim()))
                .count()
                < source.min_lines
            {
                return None;
            }
            ()
        }
    };
    let body_for_compare = std::fs::read_to_string(path).ok()?;
    let mut manifest = read_manifest(manifest_path).unwrap_or_else(|| ListManifest {
        version: MANIFEST_VERSION,
        source: source.parts.join(","),
        fetched_at: 0,
        etag: None,
        sha256: String::new(),
        lines: count_data_lines(&body_for_compare),
        bytes: body_for_compare.len(),
    });
    if manifest.version != MANIFEST_VERSION
        || manifest.sha256 != sha256_hex(body_for_compare.as_bytes())
    {
        manifest.fetched_at = 0;
    }
    let _ = now;
    Some((manifest, body_for_compare))
}

fn read_manifest(path: &Path) -> Option<ListManifest> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MANIFEST_LIMIT {
        return None;
    }
    let body = std::fs::read(path).ok()?;
    serde_json::from_slice(&body).ok()
}

fn normalize_cidrs(text: &str, source: &ListSource) -> Result<String, String> {
    if looks_like_markup(text) {
        return Err("ответ похож на HTML/JSON, а не на CIDR".to_string());
    }
    let mut networks = BTreeSet::new();
    let mut total = 0usize;
    let mut invalid = 0usize;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        total += 1;
        let (address, prefix) = match line.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (line, None),
        };
        let Ok(address) = address.parse::<Ipv4Addr>() else {
            invalid += 1;
            continue;
        };
        let prefix = match prefix {
            Some(prefix) => match prefix.parse::<u8>() {
                Ok(prefix) if prefix <= 32 => prefix,
                _ => {
                    invalid += 1;
                    continue;
                }
            },
            None => 32,
        };
        if prefix == 0 {
            invalid += 1;
            continue;
        }
        networks.insert((u32::from(address), prefix));
    }
    if total == 0 {
        return Err("в ответе нет CIDR-строк".to_string());
    }
    if invalid.saturating_mul(100) > total.saturating_mul(5) {
        return Err(format!(
            "слишком много некорректных CIDR: {invalid}/{total}"
        ));
    }
    if networks.len() < source.min_lines {
        return Err(format!(
            "слишком мало CIDR: {} < {}",
            networks.len(),
            source.min_lines
        ));
    }
    if networks.len() > source.max_lines {
        return Err(format!(
            "слишком много CIDR: {} > {}",
            networks.len(),
            source.max_lines
        ));
    }
    let mut output = format!(
        "# R2O {}\n# source: {}\n",
        source.name,
        source.parts.join(" ")
    );
    for (address, prefix) in networks {
        output.push_str(&format!("{}/{prefix}\n", Ipv4Addr::from(address)));
    }
    Ok(output)
}

fn normalize_domain(raw: &str) -> Option<String> {
    let value = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.parse::<Ipv4Addr>().is_ok()
        || value.contains('*')
        || value.contains('/')
        || value.contains(':')
    {
        return None;
    }
    let mut labels = 0;
    for label in value.split('.') {
        labels += 1;
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
    }
    if labels < 2 {
        return None;
    }
    Some(value)
}

fn valid_include_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 96
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
}

fn looks_like_markup(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with('<') || trimmed.starts_with('{') || trimmed.starts_with('[')
}

fn count_data_lines(text: &str) -> usize {
    text.lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
        .count()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

fn mirror_url(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://raw.githubusercontent.com/")?;
    let mut parts = rest.splitn(4, '/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    let gitref = parts.next()?;
    let path = parts.next()?;
    Some(format!(
        "https://cdn.jsdelivr.net/gh/{owner}/{repo}@{gitref}/{path}"
    ))
}

fn now_epoch() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "часы роутера ушли до Unix epoch".to_string())
}

fn run_at_for_offset(offset: u64) -> String {
    format!("03{:02}", offset.min(30))
}

pub async fn refresh_from_env(force: bool) -> Result<ListSummary, String> {
    let mut updater = ListUpdater::from_env();
    updater.update_all(force).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Default)]
    struct MockFetch {
        responses: Arc<Mutex<HashMap<String, Result<FetchResponse, String>>>>,
        calls: Arc<AtomicUsize>,
    }

    impl MockFetch {
        fn with(pairs: &[(&str, Result<&str, &str>)]) -> Self {
            let mock = Self::default();
            {
                let mut responses = mock.responses.lock().unwrap();
                for (url, result) in pairs {
                    responses.insert(
                        (*url).to_owned(),
                        result
                            .map(|body| FetchResponse {
                                status: 200,
                                body: body.as_bytes().to_vec(),
                                etag: None,
                            })
                            .map_err(|error| (*error).to_owned()),
                    );
                }
            }
            mock
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl ListFetch for MockFetch {
        fn get<'a>(
            &'a self,
            url: &'a str,
            _max_bytes: usize,
            _etag: Option<&'a str>,
        ) -> FetchFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                self.responses
                    .lock()
                    .unwrap()
                    .get(url)
                    .cloned()
                    .unwrap_or_else(|| Err("нет ответа в mock".to_string()))
            })
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "r2o-list-{tag}-{}-{}",
                std::process::id(),
                now_epoch().unwrap()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn paths(root: &Path) -> ListPaths {
        ListPaths {
            r2o_dir: root.to_path_buf(),
            dir: root.join("state/lists"),
            log: root.join("log/lists-update.log"),
        }
    }

    fn cidr_body(count: usize) -> String {
        let mut body = String::from("# fixture\n");
        for index in 0..count {
            body.push_str(&format!("31.13.{}.0/24\n", index % 250));
        }
        body
    }

    #[test]
    fn run_at_is_0300_plus_bounded_jitter() {
        assert_eq!(run_at_for_offset(0), "0300");
        assert_eq!(run_at_for_offset(17), "0317");
        assert_eq!(run_at_for_offset(30), "0330");
        assert_eq!(run_at_for_offset(999), "0330");
    }

    #[test]
    fn cidr_validation_rejects_html_and_short_lists() {
        let source = &SOURCES[0];
        assert!(normalize_cidrs("<html>error</html>", source).is_err());
        assert!(normalize_cidrs("31.13.24.0/21\n", source).is_err());
        let valid = normalize_cidrs(&cidr_body(12), source).unwrap();
        assert_eq!(count_data_lines(&valid), 12);
    }

    #[test]
    fn domain_validation_rejects_unsafe_names() {
        assert_eq!(
            normalize_domain("Domain:Instagram.com").or_else(|| normalize_domain("instagram.com")),
            Some("instagram.com".to_string())
        );
        assert!(normalize_domain("bad..example").is_none());
        assert!(normalize_domain("-bad.example").is_none());
        assert!(normalize_domain("127.0.0.1").is_none());
        assert!(normalize_domain("*.example.com").is_none());
    }

    #[tokio::test]
    async fn mirror_fallback_updates_meta_ranges() {
        let temp = TempDir::new("mirror");
        let primary = SOURCES[0].parts[0];
        let mirror = mirror_url(primary).unwrap();
        let body = cidr_body(12);
        let mock = MockFetch::with(&[(primary, Err("raw blocked")), (&mirror, Ok(body.as_str()))]);
        let mut updater =
            ListUpdater::new(mock.clone(), paths(&temp.0)).with_retry_delay(Duration::ZERO);
        let result = updater.update_one(&SOURCES[0], 1_000, true).await.unwrap();
        assert_eq!(result, SourceOutcome::Updated);
        let written = std::fs::read_to_string(temp.0.join("state/lists/meta-ranges.txt")).unwrap();
        assert_eq!(count_data_lines(&written), 12);
        assert!(temp.0.join("state/lists/meta-ranges.json").is_file());
        assert!(mock.calls() >= 2);
    }

    #[tokio::test]
    async fn corrupt_download_keeps_last_known_good() {
        let temp = TempDir::new("lkg");
        let updater_paths = paths(&temp.0);
        std::fs::create_dir_all(&updater_paths.dir).unwrap();
        let destination = updater_paths.dir.join("meta-ranges.txt");
        std::fs::write(&destination, cidr_body(12)).unwrap();
        let primary = SOURCES[0].parts[0];
        let mirror = mirror_url(primary).unwrap();
        let mock = MockFetch::with(&[
            (primary, Ok("<html>broken</html>")),
            (&mirror, Ok("<html>broken</html>")),
        ]);
        let mut updater = ListUpdater::new(mock, paths(&temp.0)).with_retry_delay(Duration::ZERO);
        let result = updater.update_one(&SOURCES[0], 2_000, true).await.unwrap();
        assert_eq!(result, SourceOutcome::KeptLastKnownGood);
        assert_eq!(
            count_data_lines(&std::fs::read_to_string(&destination).unwrap()),
            12
        );
    }

    #[tokio::test]
    async fn fresh_ttl_skips_network() {
        let temp = TempDir::new("ttl");
        let updater_paths = paths(&temp.0);
        std::fs::create_dir_all(&updater_paths.dir).unwrap();
        let destination = updater_paths.dir.join("meta-ranges.txt");
        let body = cidr_body(12);
        std::fs::write(&destination, &body).unwrap();
        let manifest = ListManifest {
            version: MANIFEST_VERSION,
            source: SOURCES[0].parts[0].to_string(),
            fetched_at: 10_000,
            etag: None,
            sha256: sha256_hex(body.as_bytes()),
            lines: 12,
            bytes: body.len(),
        };
        std::fs::write(
            updater_paths.dir.join("meta-ranges.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let mock = MockFetch::default();
        let calls = mock.clone();
        let mut updater = ListUpdater::new(mock, paths(&temp.0));
        let result = updater
            .update_one(&SOURCES[0], 10_100, false)
            .await
            .unwrap();
        assert_eq!(result, SourceOutcome::Fresh);
        assert_eq!(calls.calls(), 0);
    }

    #[tokio::test]
    async fn geosite_includes_are_resolved_and_deduplicated() {
        let temp = TempDir::new("geosite");
        let domain_source = SOURCES
            .iter()
            .find(|source| source.name == "geosite-meta")
            .unwrap();
        let mock = MockFetch::with(&[
            (
                "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/meta",
                Ok("include:instagram\n"),
            ),
            (
                "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/instagram",
                Ok(
                    "domain:instagram.com\nfull:www.instagram.com\napi.instagram.com\nkeyword:reels\n",
                ),
            ),
        ]);
        let mut updater = ListUpdater::new(mock, paths(&temp.0)).with_retry_delay(Duration::ZERO);
        let result = updater
            .update_one(domain_source, 3_000, true)
            .await
            .unwrap();
        assert_eq!(result, SourceOutcome::Updated);
        let written = std::fs::read_to_string(temp.0.join("state/lists/geosite-meta.txt")).unwrap();
        assert!(written.contains("instagram.com"));
        assert!(written.contains("www.instagram.com"));
        assert!(!written.contains("reels"));
        assert_eq!(written.matches("instagram.com").count(), 3);
    }

    #[tokio::test]
    async fn shrink_guard_rejects_truncated_update() {
        let temp = TempDir::new("shrink");
        let updater_paths = paths(&temp.0);
        std::fs::create_dir_all(&updater_paths.dir).unwrap();
        let destination = updater_paths.dir.join("meta-ranges.txt");
        let big = cidr_body(20);
        std::fs::write(&destination, &big).unwrap();
        let manifest = ListManifest {
            version: MANIFEST_VERSION,
            source: SOURCES[0].parts[0].to_string(),
            fetched_at: 1,
            etag: None,
            sha256: sha256_hex(big.as_bytes()),
            lines: 20,
            bytes: big.len(),
        };
        std::fs::write(
            updater_paths.dir.join("meta-ranges.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let primary = SOURCES[0].parts[0];
        let mirror = mirror_url(primary).unwrap();
        let small = cidr_body(2);
        let mock = MockFetch::with(&[(primary, Ok(small.as_str())), (&mirror, Ok(small.as_str()))]);
        let mut updater = ListUpdater::new(mock, paths(&temp.0)).with_retry_delay(Duration::ZERO);
        let result = updater.update_one(&SOURCES[0], 4_000, true).await.unwrap();
        assert_eq!(result, SourceOutcome::KeptLastKnownGood);
        assert_eq!(
            count_data_lines(&std::fs::read_to_string(&destination).unwrap()),
            20
        );
    }

    #[tokio::test]
    async fn offline_saved_database_is_kept_on_forced_failure() {
        let temp = TempDir::new("offline");
        let updater_paths = paths(&temp.0);
        std::fs::create_dir_all(&updater_paths.dir).unwrap();
        let destination = updater_paths.dir.join("meta-ranges.txt");
        let body = cidr_body(12);
        std::fs::write(&destination, &body).unwrap();
        let mock = MockFetch::default();
        let mut updater = ListUpdater::new(mock, paths(&temp.0)).with_retry_delay(Duration::ZERO);
        let result = updater.update_one(&SOURCES[0], 5_000, true).await.unwrap();
        assert_eq!(result, SourceOutcome::KeptLastKnownGood);
        assert!(destination.is_file());
    }

    #[tokio::test]
    async fn corrupt_existing_file_without_lkg_is_rejected() {
        let temp = TempDir::new("corrupt-existing");
        let updater_paths = paths(&temp.0);
        std::fs::create_dir_all(&updater_paths.dir).unwrap();
        std::fs::write(
            updater_paths.dir.join("meta-ranges.txt"),
            "<html>not a list</html>",
        )
        .unwrap();
        let mock = MockFetch::default();
        let mut updater = ListUpdater::new(mock, paths(&temp.0)).with_retry_delay(Duration::ZERO);
        assert!(updater.update_one(&SOURCES[0], 6_000, true).await.is_err());
    }

    #[tokio::test]
    async fn offline_first_run_uses_shipped_meta_ranges() {
        let temp = TempDir::new("shipped");
        std::fs::create_dir_all(temp.0.join("files")).unwrap();
        std::fs::write(temp.0.join("files/meta-ranges.txt"), cidr_body(12)).unwrap();
        let mock = MockFetch::default();
        let mut updater = ListUpdater::new(mock, paths(&temp.0)).with_retry_delay(Duration::ZERO);
        let result = updater.update_one(&SOURCES[0], 7_000, true).await.unwrap();
        assert_eq!(result, SourceOutcome::KeptLastKnownGood);
    }

    #[tokio::test]
    async fn corrupt_manifest_still_uses_valid_file_as_lkg() {
        let temp = TempDir::new("bad-manifest");
        let updater_paths = paths(&temp.0);
        std::fs::create_dir_all(&updater_paths.dir).unwrap();
        std::fs::write(updater_paths.dir.join("meta-ranges.txt"), cidr_body(12)).unwrap();
        std::fs::write(updater_paths.dir.join("meta-ranges.json"), "{broken").unwrap();
        let mock = MockFetch::default();
        let mut updater = ListUpdater::new(mock, paths(&temp.0)).with_retry_delay(Duration::ZERO);
        let result = updater.update_one(&SOURCES[0], 8_000, true).await.unwrap();
        assert_eq!(result, SourceOutcome::KeptLastKnownGood);
        assert_eq!(
            count_data_lines(
                &std::fs::read_to_string(updater_paths.dir.join("meta-ranges.txt")).unwrap()
            ),
            12
        );
    }

    #[test]
    fn offset_is_bounded_and_persisted() {
        let temp = TempDir::new("offset");
        let mock = MockFetch::default();
        let updater = ListUpdater::new(mock, paths(&temp.0));
        std::fs::create_dir_all(temp.0.join("state")).unwrap();
        std::fs::write(temp.0.join("state/lists-update-offset"), "17\n").unwrap();
        assert_eq!(updater.refresh_offset().unwrap(), 17);
        std::fs::write(temp.0.join("state/lists-update-offset"), "99\n").unwrap();
        let generated = updater.refresh_offset().unwrap();
        assert!(generated <= 30);
        let stored = std::fs::read_to_string(temp.0.join("state/lists-update-offset")).unwrap();
        assert_eq!(stored.trim().parse::<u64>().unwrap(), generated);
    }
}
