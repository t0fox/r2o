//! WebSocket-клиент для соединений с узлами Telegram DC.
//!
//! Telegram предоставляет WebSocket-endpoint `wss://kwsN.web.telegram.org/apiws`,
//! где N — номер DC. Прокси устанавливает TCP-соединение с заданным **IP**,
//! а в TLS SNI и HTTP Host указывает **домен**, как в эталонной реализации на Python.
//!
//! Номера DC без собственного имени WebSocket (например, тестовый DC 203)
//! перед построением домена преобразуются в соответствующий стандартный номер
//! через `config::websocket_dc()`. Так сертификат TLS сервера Telegram остаётся
//! действительным.
//!
//! Сертификаты TLS всегда проверяются по встроенному хранилищу WebPKI.

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::hash::Hash;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::websocket_dc;
use crate::outbound::OutboundConnector;

use futures_util::{SinkExt, StreamExt, stream::FuturesUnordered};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, http::HeaderValue},
};
use tracing::{debug, warn};
use tungstenite::Error as WsError;
use tungstenite::Message;
use tungstenite::protocol::WebSocketConfig;

/// Открытое WebSocket-соединение с узлом Telegram DC.
pub type TgWsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

type CandidateFuture<'a, T, E> = Pin<Box<dyn Future<Output = (String, Result<T, E>)> + Send + 'a>>;

fn queue_ws_candidate<'a, T, E, F, Fut>(
    domain: String,
    pending: &mut FuturesUnordered<CandidateFuture<'a, T, E>>,
    connect: &F,
) where
    T: Send + 'a,
    E: Send + 'a,
    F: Fn(String) -> Fut + Clone + Send + 'a,
    Fut: Future<Output = Result<T, E>> + Send + 'a,
{
    let result_domain = domain.clone();
    let future = connect.clone()(domain);
    pending.push(Box::pin(async move { (result_domain, future.await) }));
}

pub(crate) async fn race_ws_candidates<'a, T, E, F, Fut>(
    domains: Vec<String>,
    hedge_delay: Duration,
    connect: F,
    should_stop: impl Fn(&[(String, E)]) -> bool + Send,
) -> (Option<(String, T)>, Vec<(String, E)>)
where
    T: Send + 'a,
    E: Send + 'a,
    F: Fn(String) -> Fut + Clone + Send + 'a,
    Fut: Future<Output = Result<T, E>> + Send + 'a,
{
    let mut remaining = VecDeque::from(domains);
    let mut pending = FuturesUnordered::new();
    if let Some(domain) = remaining.pop_front() {
        queue_ws_candidate(domain, &mut pending, &connect);
    }

    let delay = tokio::time::sleep(hedge_delay);
    tokio::pin!(delay);
    let mut hedge_started = false;
    let mut failures = Vec::new();

    while !pending.is_empty() || !remaining.is_empty() {
        if pending.is_empty() {
            if let Some(domain) = remaining.pop_front() {
                queue_ws_candidate(domain, &mut pending, &connect);
            }
            continue;
        }

        tokio::select! {
            outcome = pending.next() => {
                if let Some((domain, result)) = outcome {
                    match result {
                        Ok(value) => return (Some((domain, value)), failures),
                        Err(error) => {
                            failures.push((domain, error));
                            if should_stop(&failures) {
                                return (None, failures);
                            }
                        }
                    }
                    if let Some(domain) = remaining.pop_front() {
                        queue_ws_candidate(domain, &mut pending, &connect);
                    }
                }
            }
            _ = &mut delay, if !hedge_started && pending.len() < 2 && !remaining.is_empty() => {
                hedge_started = true;
                if let Some(domain) = remaining.pop_front() {
                    queue_ws_candidate(domain, &mut pending, &connect);
                }
            }
        }
    }

    (None, failures)
}

const DIRECT_WS_HEDGE_DELAY: Duration = Duration::from_millis(125);
static DIRECT_WS_DIALS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

async fn race_direct_ws_domains<T, F, Fut>(
    domains: Vec<String>,
    connect: F,
) -> (Option<(String, T)>, Vec<(String, WsConnectResult)>)
where
    T: Send,
    F: Fn(String) -> Fut + Clone + Send,
    Fut: Future<Output = Result<T, WsConnectResult>> + Send,
{
    race_ws_candidates(domains, DIRECT_WS_HEDGE_DELAY, connect, |failures| {
        failures
            .iter()
            .any(|(_, result)| !should_try_next_ws_domain(result))
    })
    .await
}

/// Суффикс медиасервера в журнале (`DC2` или `DC2m`).
///
/// В журнале указывается признак медиасервера для каждого DC; эта функция
/// упрощает форматирование примерно в 30 местах прокси.
pub(crate) fn media_tag(is_media: bool) -> &'static str {
    if is_media { "m" } else { "" }
}

// ─── Предпочтительные IP-адреса Cloudflare (--cf-ip) ──────────────────────────

/// Общий счётчик циклического выбора для `--cf-ip`, чтобы распределять нагрузку
/// между узлами Cloudflare, а не направлять её только на первый адрес.
static CF_IP_ROTATION: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct CooldownMap<K> {
    entries: StdMutex<Option<HashMap<K, Instant>>>,
}

impl<K: Eq + Hash> CooldownMap<K> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: StdMutex::new(None),
        }
    }

    pub(crate) fn set(&self, key: K, cooldown: Duration)
    where
        K: Clone,
    {
        let mut entries = self.entries.lock().unwrap();
        let entries = entries.get_or_insert_with(HashMap::new);
        let now = Instant::now();
        entries.retain(|_, until| now < *until);
        if entries.len() >= 512
            && !entries.contains_key(&key)
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, until)| *until)
                .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(key, now + cooldown);
    }

    pub(crate) fn clear<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if let Some(entries) = self.entries.lock().unwrap().as_mut() {
            entries.remove(key);
        }
    }

    pub(crate) fn active<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let entries = self.entries.lock().unwrap();
        match entries.as_ref().and_then(|entries| entries.get(key)) {
            Some(&until) => Instant::now() < until,
            None => false,
        }
    }

    pub(crate) fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.entries
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|entries| entries.contains_key(key))
    }
}

/// Один сетевой probe на маршрут одновременно.
pub(crate) struct ProbeSet<K> {
    entries: StdMutex<Option<HashSet<K>>>,
}

impl<K> ProbeSet<K> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: StdMutex::new(None),
        }
    }
}

impl<K: Eq + Hash + Clone> ProbeSet<K> {
    pub(crate) fn try_acquire(&self, key: K) -> Option<ProbeGuard<'_, K>> {
        let mut entries = self.entries.lock().unwrap();
        if !entries.get_or_insert_with(HashSet::new).insert(key.clone()) {
            return None;
        }
        Some(ProbeGuard { set: self, key })
    }
}

pub(crate) struct ProbeGuard<'a, K: Eq + Hash> {
    set: &'a ProbeSet<K>,
    key: K,
}

impl<K: Eq + Hash> Drop for ProbeGuard<'_, K> {
    fn drop(&mut self) {
        if let Some(entries) = self.set.entries.lock().unwrap().as_mut() {
            entries.remove(&self.key);
        }
    }
}

type CfEdgeRouteKey = (IpAddr, String, String);

static CF_EDGE_TLS_FAIL: CooldownMap<CfEdgeRouteKey> = CooldownMap::new();
static CF_EDGE_PREFERRED: OnceLock<StdMutex<HashMap<String, (IpAddr, Instant)>>> = OnceLock::new();
const CF_EDGE_PREFERENCE_TTL: Duration = Duration::from_secs(120);
const CF_EDGE_HEDGE_DELAY: Duration = Duration::from_millis(125);

/// Настройки соединения с Cloudflare, общие для proxy, Worker и списка доменов.
#[derive(Clone, Copy)]
pub struct CfDialOpts<'a> {
    pub cf_ips: &'a [IpAddr],
    pub fail_cooldown: Duration,
}

/// Начальный индекс для одного логического соединения с Cloudflare. До отказа
/// проверяются все заданные IP; ротация меняет лишь адрес первой попытки.
fn cf_ip_start(ips: &[IpAddr]) -> usize {
    if ips.len() <= 1 {
        return 0;
    }
    CF_IP_ROTATION.fetch_add(1, AtomicOrdering::Relaxed) % ips.len()
}

fn cf_ip_attempts(
    ips: &[IpAddr],
    first: usize,
    domain: &str,
    route_scope: &str,
    cooldowns: &CooldownMap<CfEdgeRouteKey>,
) -> Vec<IpAddr> {
    let entries = cooldowns.entries.lock().unwrap();
    let now = Instant::now();
    let is_cooling = |ip: &IpAddr| {
        entries
            .as_ref()
            .and_then(|entries| entries.get(&(*ip, domain.to_string(), route_scope.to_string())))
            .is_some_and(|&until| now < until)
    };
    let all_cooling = ips.iter().all(is_cooling);
    let limit = if all_cooling { 1 } else { ips.len() };
    let mut ordered = (0..ips.len())
        .map(move |offset| ips[(first + offset) % ips.len()])
        .collect::<Vec<_>>();
    if let Some(preferred) = preferred_cf_edge(domain)
        && let Some(position) = ordered.iter().position(|ip| *ip == preferred)
    {
        ordered.swap(0, position);
    }
    ordered
        .into_iter()
        .filter(|ip| all_cooling || !is_cooling(ip))
        .take(limit)
        .collect()
}

fn preferred_cf_edge(domain: &str) -> Option<IpAddr> {
    let mut entries = CF_EDGE_PREFERRED
        .get_or_init(|| StdMutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let now = Instant::now();
    entries.retain(|_, (_, remembered_at)| {
        now.duration_since(*remembered_at) < CF_EDGE_PREFERENCE_TTL
    });
    entries.get(domain).map(|(ip, _)| *ip)
}

fn remember_cf_edge(domain: &str, ip: IpAddr) {
    let mut entries = CF_EDGE_PREFERRED
        .get_or_init(|| StdMutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let now = Instant::now();
    entries.retain(|_, (_, remembered_at)| {
        now.duration_since(*remembered_at) < CF_EDGE_PREFERENCE_TTL
    });
    if entries.len() >= 256
        && !entries.contains_key(domain)
        && let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, (_, remembered_at))| *remembered_at)
            .map(|(key, _)| key.clone())
    {
        entries.remove(&oldest);
    }
    entries.insert(domain.to_string(), (ip, now));
}

/// Домены WebSocket для заданного DC.
///
/// Telegram предоставляет два имени для каждого DC; проверка обоих повышает
/// устойчивость. Для медиасерверов сначала используется `kwsN-1`.
///
/// Нестандартные номера (например, тестовый DC 203) преобразуются в стандартный
/// номер WebSocket через `config::websocket_dc()`. Это необходимо для проверки
/// сертификата TLS: сертификат Telegram покрывает только рабочие DC 1–5.
pub fn ws_domains(dc: u32, is_media: bool) -> Vec<String> {
    let effective_dc = websocket_dc(dc);

    ordered_records(
        format!("kws{}.web.telegram.org", effective_dc),
        format!("kws{}-1.web.telegram.org", effective_dc),
        is_media,
    )
}

/// Упорядочить пару записей `kws{N}` и `kws{N}-1`: медиасерверы начинают с `-1`,
/// остальные — с основной записи.
fn ordered_records(base: String, dash_one: String, is_media: bool) -> Vec<String> {
    if is_media {
        vec![dash_one, base]
    } else {
        vec![base, dash_one]
    }
}

/// Результат попытки WebSocket-соединения.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum WsConnectResult {
    /// WebSocket-соединение установлено.
    Connected(TgWsStream),
    /// Сервер вернул перенаправление (301/302/303/307/308).
    /// Telegram иногда делает это при недоступности WS; вызывающий код должен
    /// перейти на прямой TCP.
    Redirect(u16),
    /// HTTP-ответ без redirect и без успешного WebSocket upgrade.
    HttpStatus(u16),
    /// Системный DNS не смог разрешить имя Cloudflare-хоста.
    DnsFailed(String),
    /// Другая ошибка транспорта.
    Failed(String),
    /// Истёк тайм-аут TCP-подключения: `ip:443` не ответил.
    ///
    /// Отличается от [`Self::TimedOut`]: TCP-узел не ответил.
    ConnectTimedOut(String),
    /// TCP ответил, но истёк тайм-аут TLS или перехода на WebSocket.
    TimedOut,
}

/// Результат перебора WSS-доменов одного DC.
pub(crate) struct WsAttempt {
    pub ws: Option<TgWsStream>,
    /// Все имена вернули перенаправление: Telegram отключил WebSocket для этого
    /// DC, а сеть не блокирует его.
    pub all_redirects: bool,
    /// TCP-подключение зависло: адрес не ответил.
    pub connect_timed_out: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct WsProbeTiming {
    pub dns_ms: Option<u64>,
    pub tcp_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub websocket_ms: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct WsProbeError {
    pub phase: &'static str,
    pub reason: String,
    pub http_status: Option<u16>,
    pub timing: WsProbeTiming,
}

impl WsAttempt {
    fn connected(ws: TgWsStream) -> Self {
        Self {
            ws: Some(ws),
            all_redirects: false,
            connect_timed_out: false,
        }
    }
}

/// Открыть TLS/WSS-соединение к заданному DC IP и домену.
async fn connect_ws_with_path(
    ip: &str,
    domain: &str,
    path: &str,
    request_binary_subprotocol: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> WsConnectResult {
    let tcp = match outbound.connect(ip, 443, timeout).await {
        Ok(stream) => stream,
        Err(error) if error.timed_out => {
            crate::stats::global().record_failure("timeout");
            return WsConnectResult::ConnectTimedOut(error.reason);
        }
        Err(error) if error.dns_failed => {
            crate::stats::global().record_failure("dns");
            return WsConnectResult::DnsFailed(error.reason);
        }
        Err(error) => {
            crate::stats::global().record_failure("tcp");
            return WsConnectResult::Failed(error.reason);
        }
    };
    let _ = tcp.set_nodelay(true);

    let request = match websocket_request(domain, path, request_binary_subprotocol) {
        Ok(request) => request,
        Err(error) => return WsConnectResult::Failed(error),
    };

    match tokio::time::timeout(timeout, tls_handshake_and_upgrade(tcp, request)).await {
        Ok(Ok((ws, response))) if response.status().as_u16() == 101 => {
            crate::stats::global().record_wss_established();
            WsConnectResult::Connected(ws)
        }
        Ok(Ok((_, response)))
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) =>
        {
            WsConnectResult::Redirect(response.status().as_u16())
        }
        Ok(Ok((_, response))) => {
            record_http_failure(response.status().as_u16());
            WsConnectResult::HttpStatus(response.status().as_u16())
        }
        Ok(Err(WsError::Http(response)))
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) =>
        {
            WsConnectResult::Redirect(response.status().as_u16())
        }
        Ok(Err(WsError::Http(response))) => {
            record_http_failure(response.status().as_u16());
            WsConnectResult::HttpStatus(response.status().as_u16())
        }
        Ok(Err(WsError::Tls(_))) => {
            crate::stats::global().record_failure("tls");
            WsConnectResult::Failed("ошибка TLS handshake".to_string())
        }
        Ok(Err(error)) => {
            crate::stats::global().record_failure("websocket");
            WsConnectResult::Failed(error.to_string())
        }
        Err(_) => {
            crate::stats::global().record_failure("timeout");
            WsConnectResult::TimedOut
        }
    }
}

fn record_http_failure(status: u16) {
    match status {
        429 => crate::stats::global().record_failure("http_429"),
        503 => crate::stats::global().record_failure("http_503"),
        _ => crate::stats::global().record_failure("websocket"),
    }
}

fn websocket_request(
    domain: &str,
    path: &str,
    request_binary_subprotocol: bool,
) -> Result<tungstenite::http::Request<()>, String> {
    let url = format!("wss://{domain}{path}");
    let mut request = url
        .into_client_request()
        .map_err(|error| format!("некорректный URL: {error}"))?;
    let headers = request.headers_mut();
    if request_binary_subprotocol {
        headers.insert("Sec-WebSocket-Protocol", HeaderValue::from_static("binary"));
    }
    headers.insert(
        "Origin",
        HeaderValue::from_static("https://web.telegram.org"),
    );
    headers.insert(
        "User-Agent",
        HeaderValue::from_static(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        ),
    );
    Ok(request)
}

pub(crate) async fn connect_probe_ws(
    ip: &str,
    domain: &str,
    path: &str,
    request_binary_subprotocol: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> Result<(TgWsStream, WsProbeTiming), WsProbeError> {
    connect_probe_ws_with_config(
        ip,
        domain,
        path,
        request_binary_subprotocol,
        443,
        timeout,
        outbound,
        verifying_rustls_config(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn connect_probe_ws_with_config(
    ip: &str,
    domain: &str,
    path: &str,
    request_binary_subprotocol: bool,
    target_port: u16,
    timeout: Duration,
    outbound: &OutboundConnector,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<(TgWsStream, WsProbeTiming), WsProbeError> {
    let mut timing = WsProbeTiming::default();
    let started = Instant::now();
    let tcp = match tokio::time::timeout(timeout, outbound.connect(ip, target_port, timeout)).await
    {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(error)) => {
            return Err(WsProbeError {
                phase: if error.dns_failed { "dns" } else { "tcp" },
                reason: error.to_string(),
                http_status: None,
                timing,
            });
        }
        Err(_) => {
            return Err(WsProbeError {
                phase: "tcp",
                reason: "истёк тайм-аут TCP connect".to_string(),
                http_status: None,
                timing,
            });
        }
    };
    timing.tcp_ms = Some(elapsed_ms(started));
    let _ = tcp.set_nodelay(true);

    let server_name = ServerName::try_from(domain.to_string()).map_err(|error| WsProbeError {
        phase: "tls",
        reason: format!("неверное имя TLS-сервера: {error}"),
        http_status: None,
        timing: timing.clone(),
    })?;
    let started = Instant::now();
    let tls_stream = match tokio::time::timeout(
        timeout,
        tokio_rustls::TlsConnector::from(tls_config).connect(server_name, tcp),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            return Err(WsProbeError {
                phase: "tls",
                reason: error.to_string(),
                http_status: None,
                timing,
            });
        }
        Err(_) => {
            return Err(WsProbeError {
                phase: "tls",
                reason: "истёк тайм-аут TLS handshake".to_string(),
                http_status: None,
                timing,
            });
        }
    };
    timing.tls_ms = Some(elapsed_ms(started));

    let request = websocket_request(domain, path, request_binary_subprotocol).map_err(|error| {
        WsProbeError {
            phase: "websocket",
            reason: error,
            http_status: None,
            timing: timing.clone(),
        }
    })?;
    let started = Instant::now();
    let stream = MaybeTlsStream::Rustls(tls_stream);
    let (ws, _response) = match tokio::time::timeout(
        timeout,
        tokio_tungstenite::client_async_with_config(request, stream, Some(ws_config())),
    )
    .await
    {
        Ok(Ok(result)) if result.1.status().as_u16() == 101 => result,
        Ok(Ok((_, response))) => {
            let status = response.status().as_u16();
            timing.websocket_ms = Some(elapsed_ms(started));
            return Err(WsProbeError {
                phase: "websocket",
                reason: format!("сервер ответил HTTP {status}"),
                http_status: Some(status),
                timing,
            });
        }
        Ok(Err(WsError::Http(response))) => {
            let status = response.status().as_u16();
            timing.websocket_ms = Some(elapsed_ms(started));
            return Err(WsProbeError {
                phase: "websocket",
                reason: format!("сервер ответил HTTP {status}"),
                http_status: Some(status),
                timing,
            });
        }
        Ok(Err(error)) => {
            timing.websocket_ms = Some(elapsed_ms(started));
            return Err(WsProbeError {
                phase: "websocket",
                reason: error.to_string(),
                http_status: None,
                timing,
            });
        }
        Err(_) => {
            timing.websocket_ms = Some(elapsed_ms(started));
            return Err(WsProbeError {
                phase: "websocket",
                reason: "истёк тайм-аут WebSocket upgrade".to_string(),
                http_status: None,
                timing,
            });
        }
    };
    timing.websocket_ms = Some(elapsed_ms(started));
    Ok((ws, timing))
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}
/// Подключиться к домену Cloudflare через заданные предпочтительные узлы.
///
/// Если предпочтительные IP не заданы, DNS выбирает anycast-узел Cloudflare.
/// При `--cf-ip` DNS не используется для TCP-адреса: проверяются все заданные
/// адреса, начиная с меняющейся позиции. `domain` остаётся TLS SNI и HTTP Host
/// для каждой попытки.
#[allow(clippy::too_many_arguments)]
async fn connect_cf_with_path(
    domain: &str,
    path: &str,
    route_scope: &str,
    request_binary_subprotocol: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    opts: CfDialOpts<'_>,
) -> WsConnectResult {
    let ips = if opts.cf_ips.is_empty() {
        match crate::cf_proxy_doh::resolve_cf_ips(domain, outbound).await {
            Ok(ips) => ips,
            Err(reason) => {
                crate::stats::global().record_failure("dns");
                return WsConnectResult::DnsFailed(reason);
            }
        }
    } else {
        opts.cf_ips.to_vec()
    };
    if ips.is_empty() {
        return WsConnectResult::DnsFailed(format!("DNS CF-хоста {domain} не вернул адресов"));
    }

    let first = cf_ip_start(&ips);
    let cooldowns = &CF_EDGE_TLS_FAIL;
    let route_ips = cf_ip_attempts(&ips, first, domain, route_scope, cooldowns);
    let candidates = route_ips
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let domain_owned = domain.to_string();
    let path_owned = path.to_string();
    let route_scope_owned = route_scope.to_string();
    let (winner, failures) = race_ws_candidates(
        candidates,
        CF_EDGE_HEDGE_DELAY,
        move |target| {
            let domain = domain_owned.clone();
            let path = path_owned.clone();
            let outbound = outbound;
            async move {
                match connect_ws_with_path(
                    &target,
                    &domain,
                    &path,
                    request_binary_subprotocol,
                    timeout,
                    outbound,
                )
                .await
                {
                    WsConnectResult::Connected(ws) => Ok(ws),
                    error => Err(error),
                }
            }
        },
        |failures| {
            failures
                .iter()
                .any(|(_, result)| matches!(result, WsConnectResult::HttpStatus(429)))
        },
    )
    .await;

    if let Some((target, ws)) = winner
        && let Ok(ip) = target.parse::<IpAddr>()
    {
        cooldowns.clear(&(ip, domain.to_string(), route_scope.to_string()));
        remember_cf_edge(domain, ip);
        return WsConnectResult::Connected(ws);
    }

    let mut last_non_redirect = None;
    let mut last_redirect = None;
    for (target, result) in failures {
        let Ok(ip) = target.parse::<IpAddr>() else {
            continue;
        };
        let route_key = (ip, domain.to_string(), route_scope_owned.clone());
        match result {
            WsConnectResult::Redirect(code) => {
                cooldowns.clear(&route_key);
                last_redirect = Some(code);
            }
            WsConnectResult::HttpStatus(429) => {
                cooldowns.clear(&route_key);
                return WsConnectResult::HttpStatus(429);
            }
            WsConnectResult::HttpStatus(code) => {
                cooldowns.clear(&route_key);
                last_non_redirect = Some(WsConnectResult::HttpStatus(code));
            }
            WsConnectResult::DnsFailed(reason) => {
                cooldowns.clear(&route_key);
                last_non_redirect = Some(WsConnectResult::DnsFailed(reason));
            }
            WsConnectResult::Failed(reason) => {
                cooldowns.set(route_key, opts.fail_cooldown);
                last_non_redirect = Some(WsConnectResult::Failed(reason));
            }
            WsConnectResult::TimedOut => {
                cooldowns.set(route_key, opts.fail_cooldown);
                last_non_redirect = Some(WsConnectResult::TimedOut);
            }
            WsConnectResult::ConnectTimedOut(reason) => {
                cooldowns.set(route_key, opts.fail_cooldown);
                last_non_redirect = Some(WsConnectResult::ConnectTimedOut(reason));
            }
            WsConnectResult::Connected(_) => {
                unreachable!("race returns successful streams separately")
            }
        }
    }

    last_non_redirect.unwrap_or_else(|| {
        last_redirect.map_or(WsConnectResult::TimedOut, WsConnectResult::Redirect)
    })
}

#[allow(clippy::result_large_err)]
async fn tls_handshake_and_upgrade<R>(
    tcp: TcpStream,
    request: R,
) -> Result<(TgWsStream, tungstenite::handshake::client::Response), WsError>
where
    R: IntoClientRequest + Unpin,
{
    let connector = Connector::Rustls(verifying_rustls_config());
    client_async_tls_with_config(request, tcp, Some(ws_config()), Some(connector)).await
}
/// Верхний размер входного WebSocket-кадра и собранного сообщения.
///
/// По умолчанию Tungstenite допускает кадры до 16 МиБ и сообщения до 64 МиБ;
/// входной буфер сохраняет максимальную ёмкость, достигнутую соединением.
/// Части медиа Telegram не превышают 1 МиБ, поэтому предел 4 МиБ оставляет
/// запас протоколу и не удерживает десятки мегабайт из-за необычного кадра.
const WS_MAX_FRAME: usize = 4 * 1024 * 1024;

/// Целевой размер буфера записи Tungstenite для одного соединения.
///
/// Мост ожидает отправки и очистки буфера перед следующим сообщением, поэтому
/// стандартная цель пакетирования 128 КиБ только увеличивает занимаемую память.
const WS_WRITE_BUFFER: usize = 16 * 1024;
/// Предел исходящей очереди: один MTProto-пакет максимального размера и запас.
const WS_MAX_WRITE_BUFFER: usize = WS_MAX_FRAME + WS_WRITE_BUFFER;

fn ws_config() -> WebSocketConfig {
    WebSocketConfig {
        write_buffer_size: WS_WRITE_BUFFER,
        max_write_buffer_size: WS_MAX_WRITE_BUFFER,
        max_frame_size: Some(WS_MAX_FRAME),
        max_message_size: Some(WS_MAX_FRAME),
        ..WebSocketConfig::default()
    }
}

/// Путь для режима TCP-туннеля Cloudflare Worker.
///
/// Worker принимает WebSocket на `/apiws`, открывает обычное TCP-соединение
/// с `dst:443` и пересылает полезные данные каждого сообщения как байты TCP.
pub fn cf_worker_path(dst: &str, dc: u32, is_media: bool) -> String {
    format!(
        "/apiws?dst={}&dc={}&media={}",
        dst,
        dc,
        if is_media { 1 } else { 0 }
    )
}

pub(crate) async fn connect_ws_for_dc_with_outbound(
    ip: &str,
    dc: u32,
    is_media: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> WsAttempt {
    let domains = ws_domains(dc, is_media);
    let media = media_tag(is_media);
    let ip = ip.to_string();
    let (winner, failures) = race_direct_ws_domains(domains, move |domain| {
        let ip = ip.clone();
        async move {
            debug!(
                "DC{}{}: проверка WS-домена {} через {}",
                dc, media, domain, ip
            );
            let _dial = DIRECT_WS_DIALS
                .acquire()
                .await
                .expect("семафор direct WSS неожиданно закрыт");
            match connect_ws_with_path(&ip, &domain, "/apiws", true, timeout, outbound).await {
                WsConnectResult::Connected(ws) => Ok(ws),
                result => {
                    log_ws_domain_failure(dc, is_media, &domain, &result);
                    Err(result)
                }
            }
        }
    })
    .await;

    if let Some((_, ws)) = winner {
        return WsAttempt::connected(ws);
    }

    let mut all_redirects = !failures.is_empty();
    let mut connect_timed_out = false;
    for (_, result) in failures {
        match result {
            WsConnectResult::Redirect(_) => {}
            WsConnectResult::ConnectTimedOut(_) => {
                connect_timed_out = true;
                all_redirects = false;
            }
            _ => all_redirects = false,
        }
    }

    WsAttempt {
        ws: None,
        all_redirects,
        connect_timed_out,
    }
}

fn log_ws_domain_failure(dc: u32, is_media: bool, domain: &str, result: &WsConnectResult) {
    let media = media_tag(is_media);
    match result {
        WsConnectResult::Connected(_) => {}
        WsConnectResult::Redirect(code) => warn!(
            "DC{}{}: домен {} ответил кодом HTTP {} (перенаправление)",
            dc, media, domain, code
        ),
        WsConnectResult::HttpStatus(code) => {
            warn!(
                "DC{}{}: WS-домен {} ответил HTTP {}",
                dc, media, domain, code
            )
        }
        WsConnectResult::DnsFailed(reason) | WsConnectResult::Failed(reason) => warn!(
            "DC{}{}: ошибка WS-подключения к {}: {}",
            dc, media, domain, reason
        ),
        WsConnectResult::TimedOut => warn!(
            "DC{}{}: истекло время ожидания WS-подключения к {}",
            dc, media, domain
        ),
        WsConnectResult::ConnectTimedOut(reason) => warn!(
            "DC{}{}: ошибка WS-подключения к {}: {}",
            dc, media, domain, reason
        ),
    }
}

fn should_try_next_ws_domain(result: &WsConnectResult) -> bool {
    !matches!(result, WsConnectResult::ConnectTimedOut(_))
}

fn should_retry_cf_domain(result: &WsConnectResult) -> bool {
    matches!(
        result,
        WsConnectResult::Failed(_) | WsConnectResult::TimedOut
    )
}

/// Имена CF-прокси возвращаются в порядке попытки для каждой зоны.
///
/// Media сначала пробует `kws{N}-1`, затем `kws{N}`: не каждая зона содержит
/// отдельную media-запись, поэтому базовое имя остаётся fallback. Номер DC не
/// переназначается, включая нестандартные идентификаторы из официальной карты.
pub fn cf_ws_domains(dc: u32, cf_domains: &[String], is_media: bool) -> Vec<String> {
    let mut hosts = Vec::with_capacity(cf_domains.len() * if is_media { 2 } else { 1 });
    for cf_domain in cf_domains {
        if is_media {
            hosts.push(format!("kws{dc}-1.{cf_domain}"));
        }
        hosts.push(format!("kws{dc}.{cf_domain}"));
    }
    hosts
}

pub(crate) async fn connect_cf_domain_with_outbound_opts(
    dc: u32,
    cf_domain: &str,
    is_media: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    opts: CfDialOpts<'_>,
) -> WsConnectResult {
    let hosts = cf_ws_domains(dc, &[cf_domain.to_string()], is_media);
    let route_scope = format!("dc={dc};media={is_media};transport=cf-proxy");
    let mut last_result = WsConnectResult::Failed("список CF-хостов пуст".to_string());
    for host in hosts {
        let result =
            connect_cf_with_path(&host, "/apiws", &route_scope, true, timeout, outbound, opts)
                .await;
        let result = if should_retry_cf_domain(&result) {
            debug!(
                "DC{}{}: повторная попытка CF-хоста {}",
                dc,
                media_tag(is_media),
                host
            );
            connect_cf_with_path(&host, "/apiws", &route_scope, true, timeout, outbound, opts).await
        } else {
            result
        };
        if matches!(
            result,
            WsConnectResult::Connected(_) | WsConnectResult::HttpStatus(429)
        ) {
            return result;
        }
        last_result = result;
    }
    last_result
}

/// Порядок попыток в цикле соединения Cloudflare.
///
/// Запись `kws{N}` для каждого домена проверяется дважды подряд, повторяющиеся
/// домены пропускаются. Вторая попытка отменяется после истечения тайм-аута
/// первой: повтор добавил бы ещё один полный тайм-аут до перехода к следующему
/// резервному маршруту.
///
/// Вторая попытка необходима. Раньше она неявно выполнялась вместо отсутствующей
/// записи `kws{N}-1`; удаление повтора заметно увеличивало долю подключений через
/// часто заблокированный TCP fallback. В одной сети доля выросла с 5,9% до 11,4%,
/// добавляя каждому такому соединению полный `--tcp-fallback-timeout`.
struct CfAttempts<'a> {
    dc: u32,
    domains: &'a [String],
    first_domain: usize,
    next_ordinal: usize,
    /// Домен, который уже проверен один раз и ожидает повторной попытки.
    pending_retry: Option<usize>,
}

impl<'a> CfAttempts<'a> {
    #[cfg(test)]
    fn new(dc: u32, domains: &'a [String]) -> Self {
        Self::with_offset(dc, domains, 0)
    }

    fn with_offset(dc: u32, domains: &'a [String], first_domain: usize) -> Self {
        Self {
            dc,
            domains,
            first_domain: if domains.is_empty() {
                0
            } else {
                first_domain % domains.len()
            },
            next_ordinal: 0,
            pending_retry: None,
        }
    }

    /// Следующая запись для проверки.
    fn next_domain(&mut self) -> Option<String> {
        if let Some(domain_index) = self.pending_retry.take() {
            return Some(self.hostname(domain_index));
        }

        while self.next_ordinal < self.domains.len() {
            let ordinal = self.next_ordinal;
            self.next_ordinal += 1;
            let domain_index = (self.first_domain + ordinal) % self.domains.len();
            if (0..ordinal).any(|prior| {
                self.domains[(self.first_domain + prior) % self.domains.len()]
                    == self.domains[domain_index]
            }) {
                continue;
            }

            self.pending_retry = Some(domain_index);
            return Some(self.hostname(domain_index));
        }

        None
    }

    /// Запомнить, что соединение для результата `next_domain` превысило тайм-аут,
    /// чтобы не повторять эту попытку.
    fn note_timed_out(&mut self) {
        self.skip_retry();
    }

    fn skip_retry(&mut self) {
        self.pending_retry = None;
    }

    fn hostname(&self, domain_index: usize) -> String {
        format!("kws{}.{}", self.dc, self.domains[domain_index])
    }
}

pub(crate) async fn connect_cf_ws_for_dc_with_outbound_opts(
    dc: u32,
    cf_domains: &[String],
    is_media: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    opts: CfDialOpts<'_>,
) -> (Option<TgWsStream>, Option<String>, bool) {
    connect_cf_ws_for_dc_with_outbound_ordered(dc, cf_domains, is_media, timeout, outbound, 0, opts)
        .await
}

pub(crate) async fn connect_cf_ws_for_dc_with_outbound_ordered(
    dc: u32,
    cf_domains: &[String],
    is_media: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    first_domain: usize,
    opts: CfDialOpts<'_>,
) -> (Option<TgWsStream>, Option<String>, bool) {
    let media = media_tag(is_media);
    let mut all_redirects = true;
    let mut attempts = CfAttempts::with_offset(dc, cf_domains, first_domain);

    while let Some(domain) = attempts.next_domain() {
        debug!("DC{}{}: проверка WS через CF-домен {}", dc, media, domain);
        let route_scope = format!("dc={dc};media={is_media};transport=cf-proxy");
        match connect_cf_with_path(
            &domain,
            "/apiws",
            &route_scope,
            true,
            timeout,
            outbound,
            opts,
        )
        .await
        {
            WsConnectResult::Connected(ws) => return (Some(ws), Some(domain), false),
            WsConnectResult::Redirect(code) => {
                warn!(
                    "DC{}{}: CF-домен {} ответил кодом HTTP {} (перенаправление)",
                    dc, media, domain, code
                );
            }
            WsConnectResult::HttpStatus(code) => {
                warn!(
                    "DC{}{}: CF-домен {} ответил HTTP {}",
                    dc, media, domain, code
                );
                attempts.skip_retry();
                all_redirects = false;
            }
            WsConnectResult::DnsFailed(reason) => {
                warn!(
                    "DC{}{}: DNS-ошибка CF-хоста {}: {}",
                    dc, media, domain, reason
                );
                attempts.skip_retry();
                all_redirects = false;
            }
            WsConnectResult::Failed(reason) => {
                warn!(
                    "DC{}{}: ошибка CF WS-подключения к {}: {}",
                    dc, media, domain, reason
                );
                all_redirects = false;
            }
            WsConnectResult::TimedOut | WsConnectResult::ConnectTimedOut(_) => {
                warn!(
                    "DC{}{}: истекло время ожидания CF WS-подключения к {}",
                    dc, media, domain
                );
                attempts.note_timed_out();
                all_redirects = false;
            }
        }
    }

    (None, None, all_redirects)
}
pub(crate) async fn connect_cf_worker_ws_for_dc_with_outbound_opts(
    worker_domain: &str,
    dst: &str,
    dc: u32,
    is_media: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    opts: CfDialOpts<'_>,
) -> Option<TgWsStream> {
    let path = cf_worker_path(dst, dc, is_media);
    let media = media_tag(is_media);
    let route_scope = format!("dc={dc};media={is_media};dst={dst};transport=cf-worker");
    debug!(
        "DC{}{}: проверка CF Worker {} через {}",
        dc, media, dst, worker_domain
    );

    match connect_cf_with_path(
        worker_domain,
        &path,
        &route_scope,
        false,
        timeout,
        outbound,
        opts,
    )
    .await
    {
        WsConnectResult::Connected(ws) => Some(ws),
        WsConnectResult::Redirect(code) => {
            warn!(
                "DC{}{}: CF Worker {} ответил кодом HTTP {} (перенаправление)",
                dc, media, worker_domain, code
            );
            None
        }
        WsConnectResult::HttpStatus(code) => {
            warn!(
                "DC{}{}: CF Worker {} ответил HTTP {}",
                dc, media, worker_domain, code
            );
            None
        }
        WsConnectResult::DnsFailed(reason) => {
            warn!(
                "DC{}{}: DNS-ошибка CF Worker {}: {}",
                dc, media, worker_domain, reason
            );
            None
        }
        WsConnectResult::Failed(reason) => {
            warn!(
                "DC{}{}: ошибка CF Worker-подключения к {}: {}",
                dc, media, worker_domain, reason
            );
            None
        }
        WsConnectResult::TimedOut | WsConnectResult::ConnectTimedOut(_) => {
            warn!(
                "DC{}{}: истекло время ожидания CF Worker {}",
                dc, media, worker_domain
            );
            None
        }
    }
}
/// Отправить двоичное сообщение WebSocket и очистить буфер.
pub async fn ws_send(ws: &mut TgWsStream, data: Vec<u8>) -> Result<(), String> {
    ws.send(Message::Binary(data))
        .await
        .map_err(|e| e.to_string())
}

/// Получить следующее двоичное сообщение WebSocket.
/// Вернуть `None`, если соединение закрыто штатно.
#[allow(dead_code)]
pub async fn ws_recv(ws: &mut TgWsStream) -> Option<Vec<u8>> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => return Some(b),
            Some(Ok(Message::Text(t))) => return Some(t.into_bytes()),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => return None,
            Some(Err(_)) => return None,
            Some(Ok(_)) => continue,
        }
    }
}

// ─── Вспомогательные функции TLS-коннектора ───────────────────────────────────

// Оба клиентских профиля создаются один раз и используются всеми соединениями.
//
// Повторное создание профиля для каждого соединения каждый раз копировало бы
// хранилище примерно из 150 корней WebPKI и создавало бы новый кэш TLS-сеансов.
// `rustls` хранит билеты возобновления в `ClientConfig`, поэтому профиль,
// живущий одно соединение, не может ничего возобновить. Тогда каждое соединение
// проходило бы полное рукопожатие TLS 1.3. Общий профиль позволяет возобновлять
// соединения с тем же DC или доменом CF и экономит вычисления обмена ключами и
// проверки сертификата — основную нагрузку CPU на роутерах и телефонах.
//
// `ClientConfig` реализует `Sync`, а хранилище сеансов защищено блокировкой,
// поэтому профиль можно использовать совместно нескольким соединениям.
static VERIFYING_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// Число TLS-сеансов для возобновления — значение по умолчанию в `rustls`.
/// Оно указано явно, поскольку его легко ошибочно уменьшить: текущий размер
/// оставляет запас для самой большой реалистичной конфигурации.
///
/// Кэш хранит по одной записи на *имя хоста*, а прокси подключается ко многим
/// именам. Каждый домен CF добавляет `kws{N}` для каждого используемого DC
/// (медиа и обычный трафик делят это имя), прямой маршрут —
/// `kws{1..5}[-1].web.telegram.org`, каждый Worker — ещё одно имя. С
/// `--default-domains` получается примерно:
///
/// ```text
///   21 домен × 3 узла ЦОД + 10 + 1  ≈ 75 имён
///   21 домен × 6 узлов ЦОД + 10 + 1 ≈ 140 имён
/// ```
///
/// Параметр `--cf-balance` намеренно поддерживает все эти записи активными.
/// Уменьшать кэш невыгодно: память всё равно занята, но записи вытесняются до
/// повторного использования, и рукопожатия приходится выполнять заново.
const TLS_SESSION_CACHE_SIZE: usize = 256;

/// Общая конфигурация TLS-клиента со встроенными корнями WebPKI.
fn verifying_rustls_config() -> Arc<rustls::ClientConfig> {
    VERIFYING_CONFIG
        .get_or_init(|| {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            config.resumption =
                rustls::client::Resumption::in_memory_sessions(TLS_SESSION_CACHE_SIZE);

            Arc::new(config)
        })
        .clone()
}

#[cfg(test)]
mod tests;
