//! Активная проверка доступности маршрутов Telegram без запуска listener.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::config::{CfTransportMode, Config, default_dc_ips};
use crate::dc_discovery::{probe_res_pq, start_ws_byte_stream};
use crate::routing::{RouteFeedback, confirm_route, reject_route};
use crate::runtime::Runtime;
use crate::ws_client::{
    WsProbeError, WsProbeTiming, cf_pool_tls_name, cf_ws_domains, connect_probe_plain_ws,
    connect_probe_ws, race_ws_candidates, ws_domains,
};

const ROUTE_TIMEOUT: Duration = Duration::from_secs(4);
const CHECK_TIMEOUT: Duration = Duration::from_secs(53);
const TCP_TIMEOUT: Duration = Duration::from_secs(3);
const MTPROTO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PARALLEL_ROUTES: usize = 3;
const EDGE_HEDGE_DELAY: Duration = Duration::from_millis(125);
const MAX_EDGE_ATTEMPTS: usize = 3;

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticReport {
    pub checked_at: u64,
    pub state: &'static str,
    pub data_centers: Vec<DcDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DcDiagnostic {
    pub dc: u32,
    pub state: &'static str,
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

    Ok(run_with_runtime(&runtime).await)
}

pub(crate) async fn run_with_runtime(runtime: &Runtime) -> DiagnosticReport {
    let specs = route_specs(runtime);
    let deadline = tokio::time::Instant::now() + CHECK_TIMEOUT;
    let semaphore = std::sync::Arc::new(Semaphore::new(MAX_PARALLEL_ROUTES));
    let futures = specs.into_iter().map(|(dc, sequence, spec)| {
        let semaphore = std::sync::Arc::clone(&semaphore);
        async move {
            let result = tokio::time::timeout_at(deadline, async {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .expect("закрыт лимит диагностики");
                let result = probe_route(runtime, spec.clone()).await;
                update_route(runtime, dc, &spec, &result);
                result
            })
            .await
            .unwrap_or_else(|_| {
                let mut result = RouteDiagnostic::empty(spec.transport, spec.domain, None);
                result.state = "unverified";
                result.reason = Some("истёк общий лимит времени диагностики".into());
                result
            });
            let mut result = result;
            result.is_media = Some(spec.is_media);
            (dc, sequence, result)
        }
    });
    let mut routes = join_all(futures).await;
    routes.sort_by_key(|route| (route.0, route.1));

    let mut data_centers = Vec::with_capacity(5);
    for dc in 1..=5 {
        let dc_routes = routes
            .iter()
            .filter(|route| route.0 == dc)
            .map(|route| route.2.clone())
            .collect::<Vec<_>>();
        data_centers.push(DcDiagnostic {
            dc,
            state: dc_state(&dc_routes),
            routes: dc_routes,
        });
    }

    DiagnosticReport {
        checked_at: unix_time(),
        state: if data_centers.iter().all(|dc| dc.state == "healthy") {
            "healthy"
        } else if data_centers
            .iter()
            .any(|dc| dc.routes.iter().any(|route| route.state == "healthy"))
        {
            "partial"
        } else if data_centers.iter().all(|dc| dc.state == "unverified") {
            "unverified"
        } else {
            "unavailable"
        },
        data_centers,
    }
}

fn route_specs(runtime: &Runtime) -> Vec<(u32, usize, RouteSpec)> {
    let fallback = default_dc_ips();
    let map = runtime.dc_map().current();
    let cf_domains = runtime.cf_domains();
    let mut routes = Vec::new();

    for dc in 1..=5 {
        let dc_ip = |is_media| {
            map.as_ref()
                .and_then(|snapshot| {
                    snapshot.endpoints.iter().find(|endpoint| {
                        endpoint.id == dc
                            && endpoint.port == 443
                            && endpoint.media_only == is_media
                            && !endpoint.tcpo_only
                            && !endpoint.cdn
                            && endpoint.secret.is_none()
                    })
                })
                .map(|endpoint| endpoint.address)
        };
        let chat_ip = dc_ip(false).or_else(|| fallback.get(&dc)?.parse().ok());
        let mut sequence = 0;
        for (is_media, target_ip) in [(false, chat_ip), (true, dc_ip(true).or(chat_ip))] {
            let mut add = |transport, domain, target_ip, path, binary_subprotocol| {
                routes.push((
                    dc,
                    sequence,
                    RouteSpec {
                        dc,
                        transport,
                        domain,
                        target_ip,
                        path,
                        binary_subprotocol,
                        is_media,
                    },
                ));
                sequence += 1;
            };
            if let Some(ip) = target_ip {
                if !is_media || dc_ip(true).is_some() {
                    add("tcp-fallback", None, Some(ip), String::new(), false);
                }
                for host in ws_domains(dc, is_media) {
                    add("direct-wss", Some(host), Some(ip), "/apiws".into(), true);
                }
                for domain in runtime.cf_worker_domains() {
                    add(
                        "cf-worker",
                        Some(domain.clone()),
                        Some(ip),
                        crate::ws_client::cf_worker_path(&ip.to_string(), dc, is_media),
                        false,
                    );
                }
            }
            if runtime.cf_worker_domains().is_empty() {
                add("cf-worker", None, None, String::new(), false);
            }
            let zones = &cf_domains.domains[..cf_domains.domains.len().min(8)];
            for domain in cf_ws_domains(dc, zones, is_media) {
                add("cf-proxy", Some(domain), target_ip, "/apiws".into(), true);
            }
            if is_media && runtime.cf_transport() != CfTransportMode::Plain {
                for zone in zones {
                    add("cf-h2", Some(zone.clone()), target_ip, "/api".into(), false);
                }
            }
            if cf_domains.domains.is_empty() {
                add("cf-proxy", None, None, String::new(), false);
            }
        }
    }

    // Чередуем DC и тип трафика, чтобы общий тайм-аут не оставил последние DC без проверки.
    let mut ordinal = std::collections::BTreeMap::new();
    let mut scheduled = routes
        .into_iter()
        .map(|route| {
            let index = ordinal
                .entry((route.0, route.2.is_media, route.2.transport))
                .or_insert(0);
            let ordinal = *index;
            *index += 1;
            (ordinal, route)
        })
        .collect::<Vec<_>>();
    scheduled
        .sort_by_key(|(ordinal, (dc, _, spec))| (*ordinal, spec.transport, *dc, spec.is_media));
    scheduled.into_iter().map(|(_, route)| route).collect()
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
        reject_route(&feedback);
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

fn dc_state(routes: &[RouteDiagnostic]) -> &'static str {
    let healthy = |is_media| {
        routes.iter().any(|route| {
            route.state == "healthy" && (route.is_media == is_media || route.is_media.is_none())
        })
    };
    if healthy(Some(false)) && healthy(Some(true)) {
        "healthy"
    } else if routes.iter().all(|route| route.state == "unverified") {
        "unverified"
    } else if routes.iter().any(|route| route.state == "blocked") {
        "blocked"
    } else {
        "unavailable"
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
            MaybeTlsStream::Plain(tcp),
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
