//! Активная проверка доступности маршрутов Telegram без запуска listener.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use serde::Serialize;

use crate::config::{CfTransportMode, Config, default_dc_ips};
use crate::dc_discovery::{probe_res_pq, start_ws_byte_stream};
use crate::routing::{RouteFeedback, confirm_route, reject_route};
use crate::runtime::Runtime;
use crate::ws_client::{
    WsProbeError, WsProbeTiming, cf_pool_tls_name, cf_ws_domains, connect_probe_plain_ws,
    connect_probe_ws, race_ws_candidates, ws_domains,
};

const ROUTE_TIMEOUT: Duration = Duration::from_secs(4);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(7);
const DC_PHASE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_TIMEOUT: Duration = Duration::from_secs(3);
const MTPROTO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PARALLEL_ROUTES: usize = 3;
const EDGE_HEDGE_DELAY: Duration = Duration::from_millis(125);
const MAX_EDGE_ATTEMPTS: usize = 3;
// Шесть фаз, по десять проверок (чат и медиа), плюс время на передачу отчёта.
pub(crate) const SOCKET_WAIT: Duration = Duration::from_secs(
    6 * 10_usize.div_ceil(MAX_PARALLEL_ROUTES) as u64 * DC_PHASE_TIMEOUT.as_secs() + 5,
);

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticReport {
    pub checked_at: u64,
    pub state: &'static str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<&'static str>,
    pub data_centers: Vec<DcDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DcDiagnostic {
    pub dc: u32,
    pub state: &'static str,
    #[serde(skip_serializing_if = "no_pending")]
    pub pending: usize,
    pub routes: Vec<RouteDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RouteDiagnostic {
    pub transport: &'static str,
    pub domain: Option<String>,
    pub selected_ip: Option<IpAddr>,
    pub state: &'static str,
    pub failed_stage: Option<&'static str>,
    pub http_status: Option<u16>,
    pub reason: Option<String>,
    pub dns_ms: Option<u64>,
    pub tcp_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub websocket_ms: Option<u64>,
    pub mtproto_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_response_ms: Option<u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub extended: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_media: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

impl DiagnosticReport {
    pub fn has_healthy_route(&self) -> bool {
        self.data_centers.iter().all(|dc| dc.state == "healthy")
    }
}

#[derive(Clone)]
struct RouteSpec {
    dc: u32,
    transport: &'static str,
    domain: Option<String>,
    target_ip: Option<IpAddr>,
    path: String,
    binary_subprotocol: bool,
    is_media: bool,
}

/// Проверить DC1–DC5 по активным маршрутам из текущей конфигурации.
/// Успех засчитывается только после получения и разбора `resPQ`.
pub async fn run(config: &Config) -> Result<DiagnosticReport, String> {
    if let Some(path) = config.ca_bundle.as_deref() {
        crate::cf_proxy_doh::validate_doh_ca_bundle(path)?;
    }
    let runtime = Runtime::new(config.outbound_connector())
        .with_dc_map_path(config.dc_map_path.clone())
        .with_cf_domain_pool(
            config.cf_domains.clone(),
            config.default_domains,
            config
                .dc_map_path
                .with_file_name("telegram-cf-domains.json"),
        )
        .with_cf_ips(config.cf_ips.clone())
        .with_cf_worker_domains(config.cf_worker_domains.clone())
        .with_cf_transport(config.cf_transport)
        .with_cf_fail_cooldown(Duration::from_secs(config.cf_fail_cooldown))
        .with_ca_bundle(config.ca_bundle.clone());

    Ok(run_with_runtime(
        &runtime,
        config.direct_wss,
        config.check_extended,
        config.check_progress_path.as_deref(),
    )
    .await)
}

pub(crate) async fn run_with_runtime(
    runtime: &Runtime,
    direct_wss: bool,
    extended: bool,
    progress_path: Option<&Path>,
) -> DiagnosticReport {
    let routes = route_specs(runtime, direct_wss);
    check_routes(
        &routes,
        extended,
        |spec| probe_route(runtime, spec),
        |spec, result| update_route(runtime, spec.dc, spec, result),
        |report| {
            if let Some(path) = progress_path
                && let Err(error) = write_progress(path, report)
            {
                tracing::debug!(%error, "не удалось сохранить прогресс проверки Telegram");
            }
        },
    )
    .await
}

#[derive(Clone, Copy)]
enum Phase {
    Worker,
    Proxy,
    Direct,
    Public,
    Tcp,
    Extended,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Proxy => "proxy",
            Self::Direct => "direct",
            Self::Public => "fallback",
            Self::Tcp => "tcp",
            Self::Extended => "extended",
        }
    }

    fn routes(self, target: &TargetRoutes) -> &[RouteSpec] {
        match self {
            Self::Worker => &target.worker,
            Self::Proxy => &target.proxy,
            Self::Direct => &target.direct,
            Self::Public | Self::Extended => &target.public,
            Self::Tcp => &target.tcp,
        }
    }
}

struct TargetRoutes {
    dc: u32,
    is_media: bool,
    worker: Vec<RouteSpec>,
    proxy: Vec<RouteSpec>,
    direct: Vec<RouteSpec>,
    public: Vec<RouteSpec>,
    tcp: Vec<RouteSpec>,
}

async fn check_routes<F>(
    targets: &[TargetRoutes],
    extended: bool,
    probe: impl Fn(RouteSpec) -> F + Sync,
    feedback: impl Fn(&RouteSpec, &RouteDiagnostic) + Sync,
    progress: impl Fn(&DiagnosticReport) + Sync,
) -> DiagnosticReport
where
    F: Future<Output = RouteDiagnostic> + Send,
{
    let mut report = DiagnosticReport {
        checked_at: unix_time(),
        state: "unverified",
        running: true,
        phase: None,
        data_centers: (1..=5)
            .map(|dc| DcDiagnostic {
                dc,
                state: "unverified",
                pending: 0,
                routes: Vec::new(),
            })
            .collect(),
    };
    progress(&report);
    for phase in [
        Phase::Worker,
        Phase::Proxy,
        Phase::Direct,
        Phase::Public,
        Phase::Tcp,
        Phase::Extended,
    ] {
        if matches!(phase, Phase::Extended) && !extended {
            break;
        }
        let mut lanes = Vec::new();
        for target in targets {
            let center = &mut report.data_centers[(target.dc - 1) as usize];
            let candidates = phase.routes(target);
            if candidates.is_empty()
                || (matches!(phase, Phase::Public | Phase::Tcp)
                    && confirmed(&center.routes, target.is_media))
            {
                continue;
            }
            center.pending += 1;
            lanes.push((target.dc, candidates));
        }
        if lanes.is_empty() {
            continue;
        }

        report.phase = Some(phase.label());
        progress(&report);
        let report_lock = Mutex::new(&mut report);
        futures_util::stream::iter(lanes)
            .for_each_concurrent(MAX_PARALLEL_ROUTES, |(dc, candidates)| {
                let report_lock = &report_lock;
                let probe = &probe;
                let feedback = &feedback;
                let progress = &progress;
                async move {
                    let deadline = tokio::time::Instant::now() + DC_PHASE_TIMEOUT;
                    for spec in candidates {
                        let started = std::time::Instant::now();
                        let attempt_deadline = tokio::time::Instant::now() + ATTEMPT_TIMEOUT;
                        let mut result = tokio::time::timeout_at(
                            deadline.min(attempt_deadline),
                            probe(spec.clone()),
                        )
                        .await
                        .unwrap_or_else(|_| {
                            let mut result =
                                RouteDiagnostic::empty(spec.transport, spec.domain.clone(), None);
                            let reason = if tokio::time::Instant::now() >= deadline {
                                "истёк лимит времени проверки этого DC"
                            } else {
                                "истёк лимит времени проверки маршрута"
                            };
                            result.fail("timeout", reason.into());
                            result
                        });
                        result.is_media = Some(spec.is_media);
                        result.extended = matches!(phase, Phase::Extended);
                        let healthy = result.state == "healthy";
                        if healthy {
                            result.first_response_ms = Some(elapsed_ms(started));
                        }
                        if !result.extended {
                            feedback(spec, &result);
                        }

                        let mut report = report_lock.lock().unwrap();
                        report.data_centers[(dc - 1) as usize].routes.push(result);
                        update_report_state(&mut report);
                        progress(&report);
                        if healthy || tokio::time::Instant::now() >= deadline {
                            break;
                        }
                    }
                    let mut report = report_lock.lock().unwrap();
                    report.data_centers[(dc - 1) as usize].pending -= 1;
                    progress(&report);
                }
            })
            .await;
    }

    report.running = false;
    report.phase = None;
    progress(&report);
    report
}

fn update_report_state(report: &mut DiagnosticReport) {
    for center in &mut report.data_centers {
        center.state = dc_state(&center.routes);
    }
    report.state = if report.has_healthy_route() {
        "healthy"
    } else if report
        .data_centers
        .iter()
        .any(|center| matches!(center.state, "healthy" | "partial"))
    {
        "partial"
    } else if report
        .data_centers
        .iter()
        .all(|center| center.state == "unverified")
    {
        "unverified"
    } else {
        "unavailable"
    };
}

fn write_progress(path: &Path, report: &DiagnosticReport) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("new.{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&temporary)?;
    let result = serde_json::to_writer(file, report)
        .map_err(std::io::Error::other)
        .and_then(|()| std::fs::rename(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn route_specs(runtime: &Runtime, direct_wss: bool) -> Vec<TargetRoutes> {
    let fallback = default_dc_ips();
    let map = runtime.dc_map().current();
    let pool = runtime.cf_domain_pool();
    let configured = pool.manual_domains();
    let snapshot = pool.snapshot();
    let defaults;
    let pool_domains = if pool.enabled() {
        &snapshot.domains
    } else {
        defaults = crate::default_domains::fallback_domains();
        &defaults
    };
    let public: Vec<String> = pool_domains
        .iter()
        .filter(|zone| !configured.contains(zone))
        .take(8)
        .cloned()
        .collect();
    let mut targets = Vec::new();

    for is_media in [false, true] {
        for dc in 1..=5 {
            let dc_ip = |media| {
                map.as_ref()?
                    .endpoints
                    .iter()
                    .find(|endpoint| {
                        endpoint.id == dc
                            && endpoint.port == 443
                            && endpoint.media_only == media
                            && !endpoint.tcpo_only
                            && !endpoint.cdn
                            && endpoint.secret.is_none()
                    })
                    .map(|endpoint| endpoint.address)
            };
            let chat_ip = dc_ip(false).or_else(|| fallback.get(&dc)?.parse().ok());
            let media_ip = dc_ip(true);
            let target_ip = if is_media {
                media_ip.or(chat_ip)
            } else {
                chat_ip
            };
            let spec = |transport, domain, path: String, binary_subprotocol| RouteSpec {
                dc,
                transport,
                domain,
                target_ip,
                path,
                binary_subprotocol,
                is_media,
            };
            let worker = target_ip
                .into_iter()
                .flat_map(|ip| {
                    runtime.cf_worker_domains().iter().map(move |domain| {
                        spec(
                            "cf-worker",
                            Some(domain.clone()),
                            crate::ws_client::cf_worker_path(&ip.to_string(), dc, is_media),
                            false,
                        )
                    })
                })
                .collect();
            let cf = |zones: &[String]| {
                let mut routes = Vec::new();
                for zone in zones.iter().take(8) {
                    if is_media && runtime.cf_transport() != CfTransportMode::Plain {
                        routes.push(spec("cf-h2", Some(zone.clone()), "/api".into(), false));
                    }
                    for domain in cf_ws_domains(dc, std::slice::from_ref(zone), is_media) {
                        routes.push(spec("cf-proxy", Some(domain), "/apiws".into(), true));
                    }
                }
                routes
            };
            let direct = if direct_wss && target_ip.is_some() {
                ws_domains(dc, is_media)
                    .into_iter()
                    .map(|host| spec("direct-wss", Some(host), "/apiws".into(), true))
                    .collect()
            } else {
                Vec::new()
            };
            let tcp = if target_ip.is_some() && (!is_media || media_ip.is_some()) {
                vec![spec("tcp-fallback", None, String::new(), false)]
            } else {
                Vec::new()
            };
            targets.push(TargetRoutes {
                dc,
                is_media,
                worker,
                proxy: cf(configured),
                direct,
                public: cf(&public),
                tcp,
            });
        }
    }
    targets
}

async fn probe_route(runtime: &Runtime, spec: RouteSpec) -> RouteDiagnostic {
    if spec.transport == "tcp-fallback" {
        return match spec.target_ip {
            Some(target_ip) => probe_tcp(runtime, spec, target_ip).await,
            None => RouteDiagnostic::unverified(spec.transport),
        };
    }
    let Some(domain) = spec.domain.clone() else {
        return RouteDiagnostic::unverified(spec.transport);
    };
    if route_requires_target_ip(&spec) && spec.target_ip.is_none() {
        return RouteDiagnostic::unverified(spec.transport);
    }
    if spec.transport == "cf-h2" {
        return probe_h2(runtime, &spec, &domain).await;
    }
    let target_ip = spec.target_ip;
    probe_wss(runtime, spec, target_ip, &domain).await
}

fn route_requires_target_ip(spec: &RouteSpec) -> bool {
    spec.transport != "cf-proxy"
}

async fn probe_h2(runtime: &Runtime, spec: &RouteSpec, zone: &str) -> RouteDiagnostic {
    let mut result = RouteDiagnostic::empty("cf-h2", Some(format!("kws{}.{zone}", spec.dc)), None);
    result.wire = Some("h2/443");
    result.sni = Some(zone.to_owned());
    match crate::cf_h2::connect(runtime, spec.dc, zone).await {
        Ok(Some((client, latency))) => {
            result.selected_ip = Some(client.peer.ip());
            result.mtproto_ms = Some(latency.as_millis() as u64);
            result.state = "healthy";
            crate::cf_h2::clear_cooldown(spec.dc, zone);
        }
        Ok(None) => {
            result.state = "unverified";
            result.reason = Some("занят лимит HTTP/2".into());
        }
        Err(error) => {
            result.selected_ip = error.ip;
            result.http_status = error.http_status;
            result.fail(error.stage, error.reason);
        }
    }
    result
}

fn update_route(runtime: &Runtime, dc: u32, spec: &RouteSpec, result: &RouteDiagnostic) {
    let Some(ip) = spec.target_ip else {
        return;
    };
    let ip = ip.to_string();
    let media = spec.is_media;
    let timeout = runtime.cf_fail_cooldown();
    if spec.transport == "tcp-fallback" && result.mtproto_ms.is_some() {
        crate::routing::record_tcp_connect_success(dc, media, &ip);
        return;
    }
    let feedback = match (
        spec.transport,
        spec.domain.as_deref(),
        result.selected_ip,
        result.wire,
    ) {
        ("direct-wss", _, _, _) => RouteFeedback::direct(dc, media, &ip, timeout),
        ("cf-worker", Some(host), Some(edge), Some(wire)) => {
            RouteFeedback::cf_worker(dc, media, &ip, host, timeout)
                .with_peer(host.to_owned(), SocketAddr::new(edge, wire_port(wire)))
        }
        ("cf-proxy", Some(host), Some(edge), Some(wire)) => {
            let Some(zone) = cf_pool_tls_name(host) else {
                return;
            };
            RouteFeedback::cf_proxy(
                dc,
                media,
                ip,
                zone.to_owned(),
                Arc::clone(runtime.cf_domain_pool()),
                timeout,
            )
            .with_peer(host.to_owned(), SocketAddr::new(edge, wire_port(wire)))
        }
        _ => return,
    };
    if let Some(latency_ms) = result.mtproto_ms {
        confirm_route(&feedback, Duration::from_millis(latency_ms));
    } else if result.failed_stage == Some("mtproto") && spec.transport != "direct-wss" {
        // Отказ отдельной пробы не отменяет уже подтверждённый маршрут через другой транспорт.
        reject_route(&feedback, false);
    }
}

fn wire_port(wire: &str) -> u16 {
    if wire == "ws/80" { 80 } else { 443 }
}

async fn probe_tcp(runtime: &Runtime, spec: RouteSpec, ip: IpAddr) -> RouteDiagnostic {
    let mut result = RouteDiagnostic::empty(spec.transport, spec.domain, Some(ip));
    let started = std::time::Instant::now();
    let stream = match tokio::time::timeout(
        TCP_TIMEOUT,
        runtime
            .outbound()
            .connect(&ip.to_string(), 443, TCP_TIMEOUT),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            result.fail("tcp", error.to_string());
            return result;
        }
        Err(_) => {
            result.fail("tcp", "истёк тайм-аут TCP connect".into());
            return result;
        }
    };
    result.tcp_ms = Some(elapsed_ms(started));
    result.wire = Some("tcp");
    let mut stream = stream;
    let started = std::time::Instant::now();
    match tokio::time::timeout(MTPROTO_TIMEOUT, probe_res_pq(&mut stream)).await {
        Ok(Ok(_)) => {
            result.mtproto_ms = Some(elapsed_ms(started));
            result.state = "healthy";
        }
        Ok(Err(error)) => result.fail("mtproto", error),
        Err(_) => result.fail("mtproto", "истёк тайм-аут req_pq_multi/resPQ".into()),
    }
    result
}

async fn probe_wss(
    runtime: &Runtime,
    spec: RouteSpec,
    target_ip: Option<IpAddr>,
    domain: &str,
) -> RouteDiagnostic {
    let mut result = RouteDiagnostic::empty(spec.transport, spec.domain.clone(), target_ip);
    let (ips, dns_ms) = if spec.transport == "direct-wss" {
        match target_ip {
            Some(target_ip) => (vec![target_ip], None),
            None => {
                result.fail("dns", "неизвестен IP Telegram DC для direct WSS".into());
                return result;
            }
        }
    } else if !runtime.cf_ips().is_empty() {
        (runtime.cf_ips().to_vec(), None)
    } else {
        result.selected_ip = None;
        let started = std::time::Instant::now();
        match tokio::time::timeout(
            Duration::from_secs(3),
            crate::cf_proxy_doh::resolve_cf_ips(domain, runtime.outbound(), runtime.ca_bundle()),
        )
        .await
        {
            Ok(Ok(ips)) => (ips, Some(elapsed_ms(started))),
            Ok(Err(error)) => {
                result.fail("dns", error);
                return result;
            }
            Err(_) => {
                result.fail("dns", "истёк тайм-аут DNS".into());
                return result;
            }
        }
    };
    result.dns_ms = dns_ms;
    let candidates = ips
        .into_iter()
        .take(if spec.transport == "direct-wss" {
            1
        } else {
            MAX_EDGE_ATTEMPTS
        })
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        result.fail("dns", "DNS не вернул пригодных IP-адресов".into());
        return result;
    }

    let domain_owned = domain.to_string();
    let path = spec.path.clone();
    let binary_subprotocol = spec.binary_subprotocol;
    let mode = if spec.transport == "direct-wss" {
        CfTransportMode::Tls
    } else {
        runtime.cf_transport()
    };
    let outbound = runtime.outbound();
    let (winner, failures) = race_ws_candidates(
        candidates,
        EDGE_HEDGE_DELAY,
        move |target| {
            let domain = domain_owned.clone();
            let path = path.clone();
            async move {
                probe_wss_edge(outbound, &target, &domain, &path, binary_subprotocol, mode).await
            }
        },
        |_| false,
    )
    .await;
    if let Some((selected_ip, (timing, mtproto_ms, use_tls))) = winner {
        result.selected_ip = selected_ip.parse().ok();
        result.set_wire(&spec, domain, use_tls);
        result.tcp_ms = timing.tcp_ms;
        result.tls_ms = timing.tls_ms;
        result.websocket_ms = timing.websocket_ms;
        result.mtproto_ms = Some(mtproto_ms);
        result.state = "healthy";
        return result;
    }
    if let Some((selected_ip, (error, use_tls))) = failures
        .into_iter()
        .max_by_key(|(_, (error, _))| probe_stage(error))
    {
        result.selected_ip = selected_ip.parse().ok();
        result.set_wire(&spec, domain, use_tls);
        result.apply_ws_error(error);
    } else {
        result.fail("websocket", "все попытки WSS отменены".into());
    }
    result
}

async fn probe_wss_edge(
    outbound: &crate::outbound::OutboundConnector,
    ip: &str,
    domain: &str,
    path: &str,
    binary_subprotocol: bool,
    mode: CfTransportMode,
) -> Result<(WsProbeTiming, u64, bool), (WsProbeError, bool)> {
    let modes = match mode {
        CfTransportMode::Auto if !binary_subprotocol => vec!["wss".to_owned(), "ws".to_owned()],
        CfTransportMode::Auto => vec!["ws".to_owned(), "wss".to_owned()],
        CfTransportMode::Plain => vec!["ws".to_owned()],
        CfTransportMode::Tls => vec!["wss".to_owned()],
    };
    let (winner, failures) = race_ws_candidates(
        modes,
        EDGE_HEDGE_DELAY,
        |wire| async move {
            let use_tls = wire == "wss";
            probe_wss_edge_mode(outbound, ip, domain, path, binary_subprotocol, use_tls)
                .await
                .map(|(timing, elapsed)| (timing, elapsed, use_tls))
                .map_err(|error| (error, use_tls))
        },
        |_| false,
    )
    .await;
    winner.map(|(_, result)| result).ok_or_else(|| {
        failures
            .into_iter()
            .map(|(_, failure)| failure)
            .max_by_key(|(error, _)| probe_stage(error))
            .expect("нет результата попытки")
    })
}

fn probe_stage(error: &WsProbeError) -> u8 {
    match error.phase {
        "mtproto" => 5,
        "websocket" if error.http_status.is_some() => 4,
        "websocket" => 3,
        "tls" => 2,
        "tcp" => 1,
        _ => 0,
    }
}

async fn probe_wss_edge_mode(
    outbound: &crate::outbound::OutboundConnector,
    ip: &str,
    domain: &str,
    path: &str,
    binary_subprotocol: bool,
    use_tls: bool,
) -> Result<(WsProbeTiming, u64), WsProbeError> {
    let (ws, timing) = if use_tls {
        connect_probe_ws(
            ip,
            domain,
            path,
            binary_subprotocol,
            ROUTE_TIMEOUT,
            outbound,
        )
        .await?
    } else {
        connect_probe_plain_ws(
            ip,
            domain,
            path,
            binary_subprotocol,
            ROUTE_TIMEOUT,
            outbound,
        )
        .await?
    };
    probe_mtproto(ws, binary_subprotocol, timing).await
}

async fn probe_mtproto(
    ws: crate::ws_client::TgWsStream,
    framed: bool,
    timing: WsProbeTiming,
) -> Result<(WsProbeTiming, u64), WsProbeError> {
    let mut stream = start_ws_byte_stream(ws, framed);
    let started = std::time::Instant::now();
    match tokio::time::timeout(MTPROTO_TIMEOUT, probe_res_pq(&mut stream)).await {
        Ok(Ok(_)) => Ok((timing, elapsed_ms(started))),
        Ok(Err(reason)) => Err(WsProbeError {
            phase: "mtproto",
            reason,
            http_status: None,
            timing,
        }),
        Err(_) => Err(WsProbeError {
            phase: "mtproto",
            reason: "истёк тайм-аут req_pq_multi/resPQ".into(),
            http_status: None,
            timing,
        }),
    }
}

impl RouteDiagnostic {
    fn empty(transport: &'static str, domain: Option<String>, ip: Option<IpAddr>) -> Self {
        Self {
            transport,
            domain,
            selected_ip: ip,
            state: "unavailable",
            failed_stage: None,
            http_status: None,
            reason: None,
            dns_ms: None,
            tcp_ms: None,
            tls_ms: None,
            websocket_ms: None,
            mtproto_ms: None,
            first_response_ms: None,
            extended: false,
            is_media: None,
            wire: None,
            sni: None,
        }
    }

    fn unverified(transport: &'static str) -> Self {
        let mut result = Self::empty(transport, None, None);
        result.state = "unverified";
        result
    }

    fn fail(&mut self, stage: &'static str, reason: String) {
        self.failed_stage = Some(stage);
        self.state = route_failure_state(stage, &reason);
        self.reason = Some(reason);
    }

    fn set_wire(&mut self, spec: &RouteSpec, domain: &str, use_tls: bool) {
        self.wire = Some(if use_tls { "wss/443" } else { "ws/80" });
        if use_tls {
            self.sni = Some(if spec.transport == "cf-proxy" {
                cf_pool_tls_name(domain).unwrap_or(domain).to_owned()
            } else {
                domain.to_owned()
            });
        }
    }

    fn apply_ws_error(&mut self, error: WsProbeError) {
        self.dns_ms = self.dns_ms.or(error.timing.dns_ms);
        self.tcp_ms = error.timing.tcp_ms;
        self.tls_ms = error.timing.tls_ms;
        self.websocket_ms = error.timing.websocket_ms;
        self.http_status = error.http_status;
        self.fail(error.phase, error.reason);
    }
}

fn route_failure_state(stage: &str, reason: &str) -> &'static str {
    if stage == "dns" {
        return "unavailable";
    }
    if stage == "websocket" && (reason.contains("HTTP 403") || reason.contains("HTTP 451")) {
        return "blocked";
    }
    "unavailable"
}

fn confirmed(routes: &[RouteDiagnostic], is_media: bool) -> bool {
    routes.iter().any(|route| {
        !route.extended
            && route.state == "healthy"
            && route.is_media.is_none_or(|media| media == is_media)
    })
}

fn no_pending(pending: &usize) -> bool {
    *pending == 0
}

fn dc_state(routes: &[RouteDiagnostic]) -> &'static str {
    match (confirmed(routes, false), confirmed(routes, true)) {
        (true, true) => "healthy",
        (true, false) | (false, true) => "partial",
        _ => {
            let primary = routes.iter().filter(|route| !route.extended);
            if primary.clone().all(|route| route.state == "unverified") {
                "unverified"
            } else if primary.clone().any(|route| route.state == "blocked") {
                "blocked"
            } else {
                "unavailable"
            }
        }
    }
}

fn elapsed_ms(started: std::time::Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        RouteDiagnostic, RouteSpec, dc_state, route_failure_state, route_requires_target_ip,
    };

    fn targets(direct: bool) -> Vec<super::TargetRoutes> {
        let runtime = super::Runtime::new(crate::outbound::OutboundConnector::direct())
            .with_cf_worker_domains(vec!["worker.example".into(), "unused.example".into()])
            .with_cf_domain_pool(vec!["proxy.example".into()], false, Default::default())
            .with_cf_transport(super::CfTransportMode::Plain);
        super::route_specs(&runtime, direct)
    }

    fn simulated_result(spec: &RouteSpec, healthy: bool) -> RouteDiagnostic {
        let mut result = RouteDiagnostic::empty(spec.transport, spec.domain.clone(), None);
        if healthy {
            result.state = "healthy";
            result.mtproto_ms = Some(1);
        } else {
            result.fail("websocket", "HTTP 403".into());
        }
        result
    }

    #[tokio::test]
    async fn подтверждённый_worker_пропускает_публичный_резерв_и_следующий_worker() {
        let report = super::check_routes(
            &targets(false),
            false,
            |spec| async move {
                let domain = spec.domain.as_deref().unwrap();
                match spec.transport {
                    "cf-worker" => {
                        assert_eq!(domain, "worker.example");
                        simulated_result(&spec, true)
                    }
                    "cf-proxy" => {
                        assert!(domain.ends_with(".proxy.example"));
                        simulated_result(&spec, false)
                    }
                    transport => panic!("лишняя проверка {transport}"),
                }
            },
            |_, _| {},
            |report| {
                if report.phase == Some("proxy") {
                    assert!(report.data_centers.iter().all(|dc| dc.state == "healthy"));
                    assert!(report.running);
                }
            },
        )
        .await;
        assert_eq!(report.state, "healthy");
    }

    #[tokio::test]
    async fn worker_proxy_и_явно_включённый_direct_дают_независимые_результаты() {
        let report = super::check_routes(
            &targets(true),
            false,
            |spec| async move {
                let healthy = match spec.transport {
                    "cf-worker" => spec.dc <= 2,
                    "cf-proxy" if spec.domain.as_deref().unwrap().ends_with(".proxy.example") => {
                        spec.dc == 2 || spec.dc == 3
                    }
                    "direct-wss" => spec.dc == 4 && !spec.is_media,
                    _ => false,
                };
                simulated_result(&spec, healthy)
            },
            |_, _| {},
            |_| {},
        )
        .await;
        assert_eq!(report.state, "partial");
        assert_eq!(
            report
                .data_centers
                .iter()
                .map(|dc| dc.state)
                .collect::<Vec<_>>(),
            ["healthy", "healthy", "healthy", "partial", "blocked"]
        );
        let dc2 = &report.data_centers[1];
        assert!(
            dc2.routes
                .iter()
                .any(|r| r.transport == "cf-worker" && r.state == "healthy")
        );
        assert!(
            dc2.routes
                .iter()
                .any(|r| r.transport == "cf-proxy" && r.state == "healthy")
        );
        assert!(
            dc2.routes
                .iter()
                .any(|r| r.transport == "direct-wss" && r.state == "blocked")
        );
        let dc5 = &report.data_centers[4];
        assert!(dc5.routes.iter().any(|r| r.transport == "tcp-fallback"));
    }

    #[tokio::test]
    async fn все_маршруты_недоступны() {
        let report = super::check_routes(
            &targets(false),
            false,
            |spec| async move { simulated_result(&spec, false) },
            |_, _| {},
            |_| {},
        )
        .await;
        assert_eq!(report.state, "unavailable");
        assert!(!report.has_healthy_route());
        assert!(
            report
                .data_centers
                .iter()
                .all(|dc| dc.state == "blocked" && dc.pending == 0)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn таймаут_расширения_отменяет_пробы_и_оставляет_результат_worker() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Pending<'a>(&'a AtomicUsize);
        impl Drop for Pending<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let cancelled = AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        let report = super::check_routes(
            &targets(false),
            true,
            |spec| {
                let cancelled = &cancelled;
                async move {
                    if spec.transport == "cf-proxy"
                        && !spec.domain.as_deref().unwrap().ends_with(".proxy.example")
                    {
                        let _pending = Pending(cancelled);
                        std::future::pending::<()>().await;
                    }
                    simulated_result(&spec, spec.transport == "cf-worker")
                }
            },
            |_, route| assert!(!route.extended),
            |report| {
                if report.phase == Some("extended") {
                    assert!(report.has_healthy_route());
                    assert!(report.running);
                }
            },
        )
        .await;
        assert_eq!(report.state, "healthy");
        assert!(!report.running);
        assert_eq!(cancelled.load(Ordering::Relaxed), 20);
        assert!(started.elapsed() <= 4 * super::DC_PHASE_TIMEOUT);
        assert!(report.data_centers.iter().all(|dc| {
            dc.routes
                .iter()
                .any(|r| r.extended && r.failed_stage == Some("timeout"))
                && dc.pending == 0
        }));
    }

    #[test]
    fn только_res_pq_может_пометить_dc_работающим() {
        let mut route =
            RouteDiagnostic::empty("direct-wss", Some("kws1.web.telegram.org".into()), None);
        assert_eq!(route.state, "unavailable");
        route.state = "healthy";
        assert_eq!(dc_state(&[route]), "healthy");
    }

    #[test]
    fn различает_непроверенный_недоступный_и_явно_заблокированный_маршрут() {
        assert_eq!(route_failure_state("dns", "NXDOMAIN"), "unavailable");
        assert_eq!(
            route_failure_state("websocket", "сервер ответил HTTP 403"),
            "blocked"
        );
        assert_eq!(
            dc_state(&[RouteDiagnostic::unverified("cf-worker")]),
            "unverified"
        );
    }

    #[test]
    fn cf_proxy_route_resolves_its_own_edge_without_a_dc_ip_hint() {
        let route = RouteSpec {
            dc: 1,
            transport: "cf-proxy",
            domain: Some("kws1.cf.example".into()),
            target_ip: None,
            path: "/apiws".into(),
            binary_subprotocol: true,
            is_media: false,
        };
        assert!(!route_requires_target_ip(&route));
        let worker = RouteSpec {
            dc: 1,
            transport: "cf-worker",
            domain: Some("worker.example".into()),
            target_ip: None,
            path: "/telegram".into(),
            binary_subprotocol: false,
            is_media: false,
        };
        assert!(route_requires_target_ip(&worker));
    }

    #[tokio::test]
    async fn http_101_worker_без_mtproto_завершается_таймаутом() {
        use futures_util::StreamExt;
        use tokio::net::{TcpListener, TcpStream};
        use tokio_tungstenite::MaybeTlsStream;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            assert!(ws.next().await.unwrap().unwrap().is_binary());
            assert!(ws.next().await.unwrap().unwrap().is_binary());
            std::future::pending::<()>().await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (ws, response) = tokio_tungstenite::client_async(
            "ws://worker.example/apiws?dst=149.154.167.51",
            MaybeTlsStream::Plain(crate::ws_client::WsTcpStream::new(tcp)),
        )
        .await
        .unwrap();
        assert_eq!(response.status().as_u16(), 101);
        let error = super::probe_mtproto(
            ws,
            false,
            super::WsProbeTiming {
                websocket_ms: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.phase, "mtproto");
        assert_eq!(error.timing.websocket_ms, Some(1));
        assert!(error.reason.contains("тайм-аут"));
        server.abort();
    }

    #[test]
    fn чат_и_медиа_подтверждаются_отдельно() {
        let mut chat = RouteDiagnostic::empty("cf-proxy", None, None);
        chat.is_media = Some(false);
        chat.state = "healthy";
        let mut media = chat.clone();
        media.is_media = Some(true);
        assert_ne!(dc_state(std::slice::from_ref(&chat)), "healthy");
        assert_eq!(dc_state(&[chat, media]), "healthy");
    }
}
