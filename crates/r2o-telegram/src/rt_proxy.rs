//! Прозрачный RuTracker-прокси: TLS SNI → публичный HTTPS CONNECT-пул.
//!
//! Это Rust-порт проверенной схемы официального расширения RuTracker:
//! клиент приходит на локальный порт после nft REDIRECT, прокси читает SNI
//! из ClientHello, выбирает живой upstream из пула `ps1.blockme.site`,
//! открывает через него CONNECT и перекладывает байты без расшифровки
//! клиентского TLS. Пул проверяется сквозным TLS/HTTP-запросом, а не только
//! ответом CONNECT 200. При отказе пула разрешён прямой fallback только для
//! явного списка доменов RuTracker.

use crate::meta_dns::random_u16;
use r2k_core::dns::{DNS_RESOLVERS, build_a_query, parse_a_reply};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    ReadBuf,
};
use tokio::net::{TcpListener, TcpStream, UdpSocket, lookup_host};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;

const BUF_SIZE: usize = 33 * 1024;
const TLS_RECORD_LIMIT: usize = 16_384;
const MAX_CLIENT_HELLO: usize = 64 * 1024;
const SO_MARK: libc::c_int = 36;
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(8);
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);
const RECOVER_INTERVAL: Duration = Duration::from_secs(10);
const PICK_WAIT: Duration = Duration::from_secs(15);
const MAX_TRIES: usize = 4;
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(8);
const UPSTREAM_CONCURRENCY: usize = 1;
const HEALTH_TARGET: &str = "rutracker.org:443";
const PROBE_PATH: &str = "/forum/index.php";
const PROBE_BYTES: usize = 8192;

#[derive(Clone, Debug)]
pub struct RtProxySettings {
    pub listen: String,
    pub idle_timeout: Duration,
    pub mark: u32,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub max_clients: usize,
    pub health_interval: Duration,
    pub direct_hosts: Vec<String>,
    pub direct_fallback: bool,
    pub verbose: bool,
    pub health_spki_pin: Option<String>,
}

impl Default for RtProxySettings {
    fn default() -> Self {
        Self {
            listen: ":1445".to_string(),
            idle_timeout: Duration::from_secs(15 * 60),
            mark: 0,
            proxy_host: "ps1.blockme.site".to_string(),
            proxy_port: 443,
            max_clients: 128,
            health_interval: Duration::from_secs(90),
            direct_hosts: vec![
                "rutracker.org".to_string(),
                "rutracker.wiki".to_string(),
                "rutracker.cc".to_string(),
                "t-ru.org".to_string(),
                // ECH-клиенты (Chrome) отправляют наружу SNI
                // cloudflare-ech.com; direct fallback доводит ECH до
                // Cloudflare, не отключая ECH глобально.
                "cloudflare-ech.com".to_string(),
            ],
            direct_fallback: true,
            verbose: false,
            health_spki_pin: None,
        }
    }
}

#[derive(Clone)]
struct RtConfig {
    settings: RtProxySettings,
}

impl RtConfig {
    fn health_target_host(&self) -> &str {
        HEALTH_TARGET
            .split_once(':')
            .map(|(host, _)| host)
            .unwrap_or(HEALTH_TARGET)
    }
}

pub fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("пустая длительность".to_string());
    }
    let (number, multiplier) = if let Some(value) = value.strip_suffix('h') {
        (value, 3600)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1)
    } else {
        (value, 1)
    };
    let number = number
        .parse::<u64>()
        .map_err(|_| format!("неверная длительность: {value}"))?;
    let seconds = number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("слишком большая длительность: {value}"))?;
    Ok(Duration::from_secs(seconds))
}

fn parse_listen(value: &str) -> Result<SocketAddr, String> {
    if let Some(port) = value.strip_prefix(':') {
        return format!("0.0.0.0:{port}")
            .parse()
            .map_err(|_| format!("неверный адрес прослушивания: {value}"));
    }
    value
        .parse()
        .map_err(|_| format!("неверный адрес прослушивания: {value}"))
}

pub async fn run(settings: RtProxySettings) -> Result<(), String> {
    let listen = parse_listen(&settings.listen)?;
    let config = Arc::new(RtConfig { settings });
    let pool = Arc::new(ProxyPool::new(config.clone()));
    tokio::spawn(health_loop(pool.clone()));

    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| format!("rt-proxy: listen {listen}: {error}"))?;
    log(
        &config,
        &format!(
            "listening on {listen}, upstream {}:{}",
            config.settings.proxy_host, config.settings.proxy_port
        ),
    );
    let semaphore = Arc::new(Semaphore::new(config.settings.max_clients));
    // Публичный CONNECT-пул blockme.site не выдерживает пачку параллельных
    // туннелей от Chrome: страница открывает 6+ соединений к static, пул
    // отвечает только части, остальные получают ERR_FAILED. Ограничиваем
    // одновременные upstream-сессии, чтобы ассеты грузились очередью.
    let upstream_limit = Arc::new(Semaphore::new(UPSTREAM_CONCURRENCY));
    let mut refused = 0_u64;
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                log(&config, &format!("accept: {error}"));
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                refused += 1;
                if refused == 1 || refused % 100 == 0 {
                    log(
                        &config,
                        &format!(
                            "достигнут предел {} соединений — отклонено {refused}",
                            config.settings.max_clients
                        ),
                    );
                }
                drop(client);
                continue;
            }
        };
        let pool = pool.clone();
        let config = config.clone();
        let upstream_limit = upstream_limit.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                handle_client(client, peer, pool, upstream_limit, config.clone()).await
            {
                if config.settings.verbose {
                    log(&config, &format!("{peer}: {error}"));
                }
            }
        });
    }
}

fn log(config: &RtConfig, message: &str) {
    if config.settings.verbose || !message.starts_with("DEBUG") {
        eprintln!("[rt-proxy] {message}");
    }
}

// ---------------------------------------------------------------------------
// пул upstream-адресов и health-check
// ---------------------------------------------------------------------------

struct PoolState {
    seed: Vec<IpAddr>,
    all: Vec<IpAddr>,
    live: Vec<IpAddr>,
    rr: usize,
}

struct ProxyPool {
    state: Mutex<PoolState>,
    config: Arc<RtConfig>,
}

impl ProxyPool {
    fn new(config: Arc<RtConfig>) -> Self {
        Self {
            state: Mutex::new(PoolState {
                seed: Vec::new(),
                all: Vec::new(),
                live: Vec::new(),
                rr: 0,
            }),
            config,
        }
    }

    fn pick(&self) -> Option<IpAddr> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.live.is_empty() {
            return None;
        }
        state.rr = state.rr.wrapping_add(1);
        Some(state.live[state.rr % state.live.len()])
    }

    fn demote(&self, ip: IpAddr) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.live.retain(|candidate| *candidate != ip);
    }

    fn live_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .live
            .len()
    }

    async fn resolve(&self) {
        let host = self.config.settings.proxy_host.clone();
        let port = self.config.settings.proxy_port;
        let mut resolved = Vec::new();
        if let Ok(Ok(addresses)) =
            timeout(Duration::from_secs(5), lookup_host((host.as_str(), port))).await
        {
            for address in addresses {
                push_unique(&mut resolved, address.ip());
            }
        }
        let direct = futures_util::future::join_all(
            DNS_RESOLVERS
                .iter()
                .take(4)
                .map(|resolver| query_public_ipv4(resolver.address, host.as_str())),
        )
        .await;
        for addresses in direct.into_iter().flatten() {
            for address in addresses {
                push_unique(&mut resolved, IpAddr::V4(address));
            }
        }
        if resolved.is_empty() {
            if self.config.settings.verbose {
                log(
                    &self.config,
                    &format!("resolve {host}: пусто, оставляю прежний пул"),
                );
            }
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let seed = std::mem::take(&mut state.seed);
        let live = state.live.clone();
        let mut all = Vec::new();
        for ip in seed.iter().chain(resolved.iter()).chain(live.iter()) {
            push_unique(&mut all, *ip);
        }
        state.seed = seed;
        state.all = all;
    }

    async fn probe_all(&self) {
        let all = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.all.clone()
        };
        let mut set = JoinSet::new();
        for ip in all.iter().copied() {
            let config = self.config.clone();
            set.spawn(async move { (ip, probe_proxy(ip, config).await) });
        }
        let mut live = Vec::new();
        let mut degraded = Vec::new();
        while let Some(result) = set.join_next().await {
            let Ok((ip, (full, handshake))) = result else {
                continue;
            };
            if full {
                live.push(ip);
            }
            if handshake {
                degraded.push(ip);
            }
        }
        if live.is_empty() && !degraded.is_empty() {
            log(
                &self.config,
                &format!(
                    "ни один upstream не отдал тело {PROBE_PATH} — использую {} узлов только с рукопожатием",
                    degraded.len()
                ),
            );
            live = degraded;
        }
        let previous = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = state.live.len();
            state.live = live;
            previous
        };
        if self.config.settings.verbose || self.live_count() != previous || self.live_count() == 0 {
            let total = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .all
                .len();
            log(
                &self.config,
                &format!("health: {}/{total} upstream IP live", self.live_count()),
            );
        }
    }
}

async fn health_loop(pool: Arc<ProxyPool>) {
    pool.resolve().await;
    let config = pool.config.clone();
    let refresh_pool = pool.clone();
    tokio::spawn(async move {
        loop {
            sleep(config.settings.health_interval).await;
            refresh_pool.resolve().await;
        }
    });
    loop {
        pool.probe_all().await;
        let delay = if pool.live_count() == 0 {
            RECOVER_INTERVAL
        } else {
            pool.config.settings.health_interval
        };
        if pool.live_count() == 0 {
            pool.resolve().await;
        }
        sleep(delay).await;
    }
}

async fn probe_proxy(ip: IpAddr, config: Arc<RtConfig>) -> (bool, bool) {
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let Ok(tcp) = connect_marked(
        SocketAddr::new(ip, config.settings.proxy_port),
        config.settings.mark,
        remaining(deadline),
    )
    .await
    else {
        return (false, false);
    };
    let Ok(tls) = tls_connect(tcp, &config.settings.proxy_host, true, remaining(deadline)).await
    else {
        return (false, false);
    };
    let mut up = BufReader::with_capacity(BUF_SIZE, tls);
    if !send_connect(&mut up, HEALTH_TARGET, remaining(deadline)).await {
        return (false, false);
    }
    let connector = TlsConnector::from(no_verify_config());
    let Ok(inner) = timeout(
        remaining(deadline),
        connector.connect(
            ServerName::try_from(config.health_target_host().to_string()).unwrap(),
            up,
        ),
    )
    .await
    else {
        return (false, false);
    };
    let Ok(inner) = inner else {
        return (false, false);
    };
    if let Some(pin) = &config.settings.health_spki_pin
        && !spki_pin_matches(inner.get_ref().1.peer_certificates(), pin)
    {
        return (false, false);
    }
    let mut inner = BufReader::new(inner);
    let request = format!(
        "GET {PROBE_PATH} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        config.health_target_host()
    );
    if timeout(
        remaining(deadline),
        inner.get_mut().write_all(request.as_bytes()),
    )
    .await
    .is_err()
    {
        return (false, true);
    }
    let Ok(line) = read_line(&mut inner, remaining(deadline)).await else {
        return (false, true);
    };
    if !status_is_200(&line) {
        return (false, true);
    }
    if !drain_headers(&mut inner, remaining(deadline)).await {
        return (false, true);
    }
    let mut body = 0_usize;
    let mut chunk = [0_u8; 4096];
    while body < PROBE_BYTES {
        let left = remaining(deadline);
        if left.is_zero() {
            return (false, true);
        }
        let read = match timeout(left, inner.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => read,
            Ok(Err(_)) => break,
        };
        body = body.saturating_add(read);
    }
    (body >= PROBE_BYTES, true)
}

async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    pool: Arc<ProxyPool>,
    upstream_limit: Arc<Semaphore>,
    config: Arc<RtConfig>,
) -> Result<(), String> {
    let (sni, hello) = timeout(CLIENT_HELLO_TIMEOUT, peek_client_hello(&mut client))
        .await
        .map_err(|_| "тайм-аут ClientHello".to_string())?
        .map_err(|error| format!("ClientHello: {error}"))?;
    if sni.is_empty() {
        return Err("в ClientHello нет SNI".to_string());
    }
    let _upstream_permit = upstream_limit
        .acquire()
        .await
        .map_err(|_| "upstream-лимит остановлен".to_string())?;
    if let Some((up, flight)) = dial_upstream(&pool, &sni, &hello, &config).await {
        if config.settings.verbose {
            log(&config, &format!("{peer} -> {sni}:443 через upstream"));
        }
        return splice(client, up, flight, config).await;
    }
    if config.settings.direct_fallback
        && let Some((up, flight)) = dial_direct(&sni, &hello, &config).await
    {
        if config.settings.verbose {
            log(&config, &format!("{peer} -> {sni}:443 напрямую"));
        }
        return splice(client, up, flight, config).await;
    }
    Err(format!("нет рабочего upstream для {sni}"))
}

/// ECH-клиент (Chrome) отправляет наружу SNI `cloudflare-ech.com`, а
/// внутреннее имя остаётся зашифрованным. Через публичный CONNECT-пул нужно
/// открыть туннель к настоящему хосту RuTracker, иначе ECH-приветствие уйдёт
/// на чужой edge и рукопожатие не состоится. Проверенные адреса берём из
/// `direct-fallback-hosts`, исключая сам внешний SNI.
fn upstream_targets(sni: &str, direct_hosts: &[String]) -> Vec<String> {
    if is_ech_outer_sni(sni) {
        let targets = direct_hosts
            .iter()
            .filter(|host| !host.eq_ignore_ascii_case(sni))
            .map(|host| format!("{host}:443"))
            .collect::<Vec<_>>();
        if !targets.is_empty() {
            return targets;
        }
    }
    vec![format!("{sni}:443")]
}

fn is_ech_outer_sni(sni: &str) -> bool {
    sni.eq_ignore_ascii_case("cloudflare-ech.com")
}

async fn dial_upstream(
    pool: &ProxyPool,
    sni: &str,
    hello: &[u8],
    config: &Arc<RtConfig>,
) -> Option<(
    BufReader<tokio_rustls::client::TlsStream<TcpStream>>,
    Vec<u8>,
)> {
    let targets = upstream_targets(sni, &config.settings.direct_hosts);
    let deadline = Instant::now() + PICK_WAIT;
    let mut tries = 0_usize;
    let mut demoted = false;
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        let Some(ip) = pool.pick() else {
            sleep(Duration::from_millis(250)).await;
            continue;
        };
        let mut reachable = false;
        let mut wrote_hello = false;
        let mut verified = None;
        for target in &targets {
            if Instant::now() >= deadline {
                break;
            }
            match open_tunnel(ip, target, config).await {
                Ok(mut up) => {
                    reachable = true;
                    if timeout(remaining(deadline), up.get_mut().write_all(hello))
                        .await
                        .is_err()
                    {
                        continue;
                    }
                    wrote_hello = true;
                    if let Some(flight) =
                        verify_first_flight(&mut up, FIRST_BYTE_TIMEOUT.min(remaining(deadline)))
                            .await
                    {
                        verified = Some((up, flight));
                        break;
                    }
                }
                Err(OpenError::Unreachable) => {}
                Err(OpenError::Rejected) => {
                    reachable = true;
                }
            }
        }
        if let Some(result) = verified {
            return Some(result);
        }
        // Демотируем только при отказе соединения/CONNECT/записи. Тайм-аут
        // первого ответа при параллельной нагрузке не должен выбивать живой
        // upstream из общего пула: иначе пачка static-запросов опустошает пул
        // и все соединения страницы падают. Для ECH неверный внутренний
        // кандидат также не является отказом upstream-адреса.
        if !reachable || !wrote_hello {
            demote_once(pool, &mut demoted, ip, config);
        }
        tries += 1;
        if tries >= MAX_TRIES {
            return None;
        }
    }
}

fn demote_once(pool: &ProxyPool, demoted: &mut bool, ip: IpAddr, config: &Arc<RtConfig>) {
    if *demoted {
        if config.settings.verbose {
            log(
                config,
                &format!("{ip} тоже не сработал — больше не демотирую в этом запросе"),
            );
        }
        return;
    }
    pool.demote(ip);
    *demoted = true;
}

enum OpenError {
    Unreachable,
    Rejected,
}

async fn open_tunnel(
    ip: IpAddr,
    target: &str,
    config: &Arc<RtConfig>,
) -> Result<BufReader<tokio_rustls::client::TlsStream<TcpStream>>, OpenError> {
    let deadline = Instant::now() + DIAL_TIMEOUT;
    let tcp = connect_marked(
        SocketAddr::new(ip, config.settings.proxy_port),
        config.settings.mark,
        remaining(deadline),
    )
    .await
    .map_err(|_| OpenError::Unreachable)?;
    let tls = tls_connect(tcp, &config.settings.proxy_host, true, remaining(deadline))
        .await
        .map_err(|_| OpenError::Unreachable)?;
    let mut up = BufReader::with_capacity(BUF_SIZE, tls);
    if !send_connect(&mut up, target, remaining(deadline)).await {
        return Err(OpenError::Rejected);
    }
    Ok(up)
}

async fn dial_direct(
    sni: &str,
    hello: &[u8],
    config: &Arc<RtConfig>,
) -> Option<(
    BufReader<tokio_rustls::client::TlsStream<TcpStream>>,
    Vec<u8>,
)> {
    if !direct_host_allowed(sni, &config.settings.direct_hosts) {
        log(
            config,
            &format!("{sni} не входит в direct-fallback-hosts — не перенаправляю"),
        );
        return None;
    }
    let addresses = resolve_direct(sni).await;
    for ip in addresses {
        if !routable_unicast(ip) {
            continue;
        }
        let deadline = Instant::now() + DIAL_TIMEOUT;
        let Ok(tcp) =
            connect_marked(SocketAddr::new(ip, 443), config.settings.mark, DIAL_TIMEOUT).await
        else {
            continue;
        };
        let Ok(tls) = tls_connect(tcp, sni, false, remaining(deadline)).await else {
            continue;
        };
        let mut up = BufReader::with_capacity(BUF_SIZE, tls);
        if timeout(remaining(deadline), up.get_mut().write_all(hello))
            .await
            .is_err()
        {
            continue;
        }
        if let Some(flight) =
            verify_first_flight(&mut up, FIRST_BYTE_TIMEOUT.min(remaining(deadline))).await
        {
            log(config, &format!("{sni} обслужен напрямую через {ip}"));
            return Some((up, flight));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// TLS, CONNECT и проверка первого server flight
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl NoVerify {
    fn new() -> Self {
        Self(Arc::new(rustls::crypto::ring::default_provider()))
    }
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn no_verify_config() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify::new()))
            .with_no_client_auth(),
    )
}

async fn tls_connect(
    tcp: TcpStream,
    host: &str,
    alpn: bool,
    budget: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify::new()))
        .with_no_client_auth();
    if alpn {
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|_| format!("неверное TLS-имя {host}"))?;
    timeout(budget, connector.connect(server_name, tcp))
        .await
        .map_err(|_| format!("тайм-аут TLS к {host}"))?
        .map_err(|error| format!("TLS к {host}: {error}"))
}

async fn send_connect(
    up: &mut BufReader<tokio_rustls::client::TlsStream<TcpStream>>,
    target: &str,
    budget: Duration,
) -> bool {
    let request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    if timeout(budget, up.get_mut().write_all(request.as_bytes()))
        .await
        .is_err()
    {
        return false;
    }
    let Ok(line) = read_line(up, budget).await else {
        return false;
    };
    if !status_is_200(&line) {
        return false;
    }
    drain_headers(up, budget).await
}

fn status_is_200(line: &[u8]) -> bool {
    let text = String::from_utf8_lossy(line);
    text.split_whitespace().nth(1) == Some("200")
}

async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    budget: Duration,
) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    let read = timeout(budget, reader.read_until(b'\n', &mut line))
        .await
        .map_err(|_| "тайм-аут чтения строки".to_string())?
        .map_err(|error| error.to_string())?;
    if read == 0 || line.is_empty() {
        return Err("соединение закрыто".to_string());
    }
    Ok(line)
}

async fn drain_headers<R: AsyncBufRead + Unpin>(reader: &mut R, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        let left = remaining(deadline);
        if left.is_zero() {
            return false;
        }
        let Ok(line) = read_line(reader, left).await else {
            return false;
        };
        if line == b"\r\n" || line == b"\n" {
            return true;
        }
    }
}

async fn verify_first_flight<R: AsyncRead + Unpin>(
    up: &mut BufReader<R>,
    budget: Duration,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + budget;
    let mut flight = Vec::new();
    let mut header = [0_u8; 5];
    read_exact_before(up, &mut header, remaining(deadline)).await?;
    flight.extend_from_slice(&header);
    if header[0] != 0x16 {
        return None;
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if length == 0 || length > TLS_RECORD_LIMIT {
        return None;
    }
    let mut body = vec![0_u8; length];
    read_exact_before(up, &mut body, remaining(deadline)).await?;
    flight.extend_from_slice(&body);
    // TLS 1.3 HelloRetryRequest может состоять из одной записи ServerHello:
    // сервер ждёт второй ClientHello и не присылает следующий record сразу.
    // Раньше ожидание второй записи закрывало туннель Chrome до ответа.
    Some(flight)
}

async fn read_exact_before<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
    budget: Duration,
) -> Option<()> {
    if budget.is_zero() {
        return None;
    }
    timeout(budget, reader.read_exact(buffer))
        .await
        .ok()?
        .ok()
        .map(|_| ())
}

// ---------------------------------------------------------------------------
// SNI
// ---------------------------------------------------------------------------

async fn peek_client_hello<R: AsyncRead + Unpin>(client: &mut R) -> io::Result<(String, Vec<u8>)> {
    let mut header = [0_u8; 5];
    client.read_exact(&mut header).await?;
    if header[0] != 0x16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "не TLS handshake",
        ));
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if length == 0 || length > TLS_RECORD_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "неверная длина TLS-записи",
        ));
    }
    let mut body = vec![0_u8; length];
    client.read_exact(&mut body).await?;
    let mut hello = Vec::with_capacity(5 + length);
    hello.extend_from_slice(&header);
    hello.extend_from_slice(&body);

    // Chrome может разбить ClientHello на несколько TLS-записей. Если
    // отправить только первую и ждать ServerHello, сервер будет ждать
    // остаток рукопожатия, а прокси — ответ: получается взаимная блокировка.
    let mut handshake = body;
    let mut hello_len = 0_usize;
    if handshake.len() >= 4 && handshake[0] == 0x01 {
        hello_len = 4
            + (((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize);
    }
    while hello_len > handshake.len() {
        if hello_len > MAX_CLIENT_HELLO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "слишком большой ClientHello",
            ));
        }
        let mut next_header = [0_u8; 5];
        client.read_exact(&mut next_header).await?;
        if next_header[0] != 0x16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello продолжен не handshake-записью",
            ));
        }
        let next_length = u16::from_be_bytes([next_header[3], next_header[4]]) as usize;
        if next_length == 0 || next_length > TLS_RECORD_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "неверная длина продолжения ClientHello",
            ));
        }
        let mut next_body = vec![0_u8; next_length];
        client.read_exact(&mut next_body).await?;
        hello.extend_from_slice(&next_header);
        hello.extend_from_slice(&next_body);
        handshake.extend_from_slice(&next_body);
    }
    Ok((parse_client_hello(&handshake).unwrap_or_default(), hello))
}

fn parse_client_hello(body: &[u8]) -> Option<String> {
    if body.len() < 38 || body[0] != 0x01 {
        return None;
    }
    let mut position = 38;
    let session = *body.get(position)? as usize;
    position += 1 + session;
    let cipher = u16::from_be_bytes([*body.get(position)?, *body.get(position + 1)?]) as usize;
    position += 2 + cipher;
    let compression = *body.get(position)? as usize;
    position += 1 + compression;
    let extensions = u16::from_be_bytes([*body.get(position)?, *body.get(position + 1)?]) as usize;
    position += 2;
    let end = position.checked_add(extensions)?.min(body.len());
    while position + 4 <= end {
        let kind = u16::from_be_bytes([body[position], body[position + 1]]);
        let length = u16::from_be_bytes([body[position + 2], body[position + 3]]) as usize;
        position += 4;
        let data = body.get(position..position + length)?;
        position += length;
        if kind == 0 {
            if data.len() < 5 || data[2] != 0 {
                return None;
            }
            let name_length = u16::from_be_bytes([data[3], data[4]]) as usize;
            let name = data.get(5..5 + name_length)?;
            return String::from_utf8(name.to_vec()).ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// DNS, SO_MARK, адреса
// ---------------------------------------------------------------------------

async fn connect_marked(address: SocketAddr, mark: u32, budget: Duration) -> io::Result<TcpStream> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    if mark != 0 {
        let result = unsafe {
            libc::setsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&socket),
                libc::SOL_SOCKET,
                SO_MARK,
                (&mark as *const u32).cast(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    match socket.connect(&address.into()) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(error) => return Err(error),
    }
    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    timeout(budget, async {
        stream.writable().await?;
        match stream.take_error()? {
            Some(error) => Err(error),
            None => Ok(()),
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "тайм-аут connect"))??;
    Ok(stream)
}

async fn resolve_direct(host: &str) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    let direct = futures_util::future::join_all(
        DNS_RESOLVERS
            .iter()
            .take(4)
            .map(|resolver| query_public_ipv4(resolver.address, host)),
    )
    .await;
    for answer in direct.into_iter().flatten() {
        for address in answer {
            push_unique(&mut addresses, IpAddr::V4(address));
        }
    }
    if addresses.is_empty()
        && let Ok(Ok(resolved)) = timeout(Duration::from_secs(3), lookup_host((host, 443))).await
    {
        for address in resolved {
            push_unique(&mut addresses, address.ip());
        }
    }
    addresses
}

async fn query_public_ipv4(resolver: Ipv4Addr, host: &str) -> Result<Vec<Ipv4Addr>, String> {
    let id = random_u16()?;
    let query = build_a_query(id, host).map_err(|_| "неверное DNS-имя".to_string())?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| error.to_string())?;
    socket
        .connect(SocketAddr::from((resolver, 53)))
        .await
        .map_err(|error| error.to_string())?;
    timeout(Duration::from_secs(3), async {
        socket
            .send(&query)
            .await
            .map_err(|error| error.to_string())?;
        let mut reply = [0_u8; 4096];
        let length = socket
            .recv(&mut reply)
            .await
            .map_err(|error| error.to_string())?;
        parse_a_reply(&reply[..length], &query, host).map_err(|_| "неверный DNS-ответ".to_string())
    })
    .await
    .map_err(|_| "тайм-аут DNS".to_string())?
}

fn direct_host_allowed(host: &str, allowed: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allowed.iter().any(|suffix| {
        let suffix = suffix.trim().to_ascii_lowercase();
        !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
    })
}

fn routable_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let value = u32::from(ip);
            !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !(value >= 0x6440_0000 && value <= 0x647f_ffff) // 100.64.0.0/10 CGNAT
                && !(value >= 0xc000_0000 && value <= 0xc000_00ff) // 192.0.0.0/24
                && !(value >= 0xc000_0200 && value <= 0xc000_02ff) // TEST-NET-1
                && !(value >= 0xc633_6400 && value <= 0xc633_64ff) // TEST-NET-2
                && !(value >= 0xcb00_7100 && value <= 0xcb00_71ff) // TEST-NET-3
                && !(value >= 0xf000_0000) // 240.0.0.0/4
        }
        IpAddr::V6(ip) => !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast(),
    }
}

fn push_unique(values: &mut Vec<IpAddr>, value: IpAddr) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn spki_pin_matches(certificates: Option<&[CertificateDer<'_>]>, pin: &str) -> bool {
    let Some(certificate) = certificates.and_then(|certs| certs.first()) else {
        return false;
    };
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(certificate.as_ref()) else {
        return false;
    };
    let digest = Sha256::digest(parsed.tbs_certificate.subject_pki.raw);
    base64_encode(&digest) == pin
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

// ---------------------------------------------------------------------------
// splice с half-close и idle-watchdog
// ---------------------------------------------------------------------------

async fn splice(
    client: TcpStream,
    up: BufReader<tokio_rustls::client::TlsStream<TcpStream>>,
    flight: Vec<u8>,
    config: Arc<RtConfig>,
) -> Result<(), String> {
    let (client_read, client_write) = client.into_split();
    let (up_read, up_write) = tokio::io::split(up);
    let up_read = PrefixReader::new(flight, up_read);
    let last = Arc::new(AtomicUsize::new(epoch_seconds()));
    let first = last.clone();
    let second = last.clone();
    let mut client_to_up = tokio::spawn(copy_activity(client_read, up_write, first));
    let mut up_to_client = tokio::spawn(copy_activity(up_read, client_write, second));
    let mut watchdog = tokio::spawn({
        let config = config.clone();
        let last = last.clone();
        async move {
            let tick = (config.settings.idle_timeout / 4)
                .min(Duration::from_secs(30))
                .max(Duration::from_secs(1));
            loop {
                sleep(tick).await;
                if epoch_seconds().saturating_sub(last.load(Ordering::Relaxed))
                    >= config.settings.idle_timeout.as_secs() as usize
                {
                    return;
                }
            }
        }
    });
    tokio::select! {
        _ = async {
            let _ = (&mut client_to_up).await;
            let _ = (&mut up_to_client).await;
        } => {}
        _ = &mut watchdog => {
            client_to_up.abort();
            up_to_client.abort();
        }
    }
    watchdog.abort();
    Ok(())
}

struct PrefixReader<R> {
    prefix: Vec<u8>,
    position: usize,
    inner: R,
}

impl<R> PrefixReader<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.position < self.prefix.len() {
            let available = self.prefix.len() - self.position;
            let count = available.min(buffer.remaining());
            buffer.put_slice(&self.prefix[self.position..self.position + count]);
            self.position += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

async fn copy_activity<R, W>(
    mut reader: R,
    mut writer: W,
    last: Arc<AtomicUsize>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut copied = 0_u64;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        last.store(epoch_seconds(), Ordering::Relaxed);
        writer.write_all(&buffer[..read]).await?;
        last.store(epoch_seconds(), Ordering::Relaxed);
        copied = copied.saturating_add(read as u64);
    }
    writer.shutdown().await?;
    Ok(copied)
}

fn epoch_seconds() -> usize {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parser_supports_go_units() {
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("42").unwrap(), Duration::from_secs(42));
        assert!(parse_duration("12x").is_err());
    }

    #[test]
    fn listen_parser_matches_go_short_form() {
        assert_eq!(
            parse_listen(":1445").unwrap(),
            "0.0.0.0:1445".parse().unwrap()
        );
        assert_eq!(
            parse_listen("127.0.0.1:1445").unwrap(),
            "127.0.0.1:1445".parse().unwrap()
        );
    }

    #[test]
    fn direct_fallback_is_dot_anchored() {
        let allowed = vec!["rutracker.org".to_string(), "t-ru.org".to_string()];
        assert!(direct_host_allowed("rutracker.org", &allowed));
        assert!(direct_host_allowed("www.rutracker.org", &allowed));
        assert!(direct_host_allowed("RUTRACKER.ORG", &allowed));
        assert!(!direct_host_allowed("rutracker.org.evil.tld", &allowed));
        assert!(!direct_host_allowed("notrutracker.org", &allowed));
    }

    #[test]
    fn ech_outer_sni_uses_real_ru_tracker_hosts() {
        let hosts = vec![
            "rutracker.org".to_string(),
            "rutracker.wiki".to_string(),
            "cloudflare-ech.com".to_string(),
        ];
        assert_eq!(
            upstream_targets("cloudflare-ech.com", &hosts),
            vec!["rutracker.org:443", "rutracker.wiki:443"]
        );
        assert_eq!(
            upstream_targets("CLOUDFLARE-ECH.COM", &hosts),
            vec!["rutracker.org:443", "rutracker.wiki:443"]
        );
        assert_eq!(
            upstream_targets("rutracker.org", &hosts),
            vec!["rutracker.org:443"]
        );
        assert!(is_ech_outer_sni("cloudflare-ech.com"));
        assert!(is_ech_outer_sni("Cloudflare-ECH.com"));
        assert!(!is_ech_outer_sni("rutracker.org"));
    }

    #[test]
    fn loopback_and_private_direct_targets_are_rejected() {
        assert!(!routable_unicast("10.171.171.171".parse().unwrap()));
        assert!(!routable_unicast("127.0.0.1".parse().unwrap()));
        assert!(!routable_unicast("169.254.1.1".parse().unwrap()));
        assert!(routable_unicast("172.67.182.196".parse().unwrap()));
    }

    #[tokio::test]
    async fn single_server_hello_record_is_a_complete_first_flight() {
        let record = [0x16, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb];
        let mut reader = BufReader::new(&record[..]);
        let flight = verify_first_flight(&mut reader, Duration::from_secs(1))
            .await
            .expect("одна запись ServerHello должна подтверждать туннель");
        assert_eq!(flight, record);
    }

    fn test_client_hello(name: &str) -> Vec<u8> {
        let mut body = vec![0x01, 0, 0, 0, 0x03, 0x03];
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression
        let name = name.as_bytes();
        let mut extension = Vec::new();
        extension.extend_from_slice(&[0x00, 0x00]); // server_name
        let list_len = 1 + 2 + name.len();
        extension.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
        extension.extend_from_slice(&(list_len as u16).to_be_bytes());
        extension.push(0);
        extension.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extension.extend_from_slice(name);
        body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension);
        let payload_len = body.len() - 4;
        body[1] = (payload_len >> 16) as u8;
        body[2] = (payload_len >> 8) as u8;
        body[3] = payload_len as u8;
        body
    }

    #[tokio::test]
    async fn fragmented_client_hello_is_forwarded_as_one_flight() {
        let body = test_client_hello("rutracker.org");
        let cut = body.len() / 2;
        let mut wire = Vec::new();
        for part in [&body[..cut], &body[cut..]] {
            wire.extend_from_slice(&[0x16, 0x03, 0x01]);
            wire.extend_from_slice(&(part.len() as u16).to_be_bytes());
            wire.extend_from_slice(part);
        }
        let mut reader = &wire[..];
        let (sni, hello) = peek_client_hello(&mut reader).await.unwrap();
        assert_eq!(sni, "rutracker.org");
        assert_eq!(hello, wire);
    }

    #[test]
    fn client_hello_sni_is_parsed_without_handshake() {
        let mut body = vec![0x01, 0x00, 0x00, 0x00, 0x03, 0x03];
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression
        let name = b"rutracker.org";
        let mut extension = Vec::new();
        extension.extend_from_slice(&[0x00, 0x00]); // server_name
        let list_len = 1 + 2 + name.len();
        extension.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
        extension.extend_from_slice(&(list_len as u16).to_be_bytes());
        extension.push(0);
        extension.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extension.extend_from_slice(name);
        body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension);
        assert_eq!(parse_client_hello(&body).as_deref(), Some("rutracker.org"));
    }

    #[test]
    fn base64_matches_rfc4648_examples() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }
}
