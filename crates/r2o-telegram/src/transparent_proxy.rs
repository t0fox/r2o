//! Прозрачный MTProto перехват, выбор WSS fallback и передача потока.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::dc_map::RouteLookupError;
use crate::routing::{self, Upstream};
use crate::runtime::Runtime;
use crate::stats::ConnectionTelemetry;
use crate::transparent;
use crate::ws_client::media_tag;

const INITIAL_PREFIX_LEN: usize = 8;

#[derive(Clone, Copy)]
enum TrafficDirection {
    FromClients,
    FromUpstreams,
}

struct TelemetryStream<'a, S> {
    stream: &'a mut S,
    telemetry: Option<ConnectionTelemetry>,
    direction: TrafficDirection,
}

impl<S: AsyncRead + Unpin> AsyncRead for TelemetryStream<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let previous_len = buffer.filled().len();
        let result = Pin::new(&mut *this.stream).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) {
            let bytes = buffer.filled().len().saturating_sub(previous_len) as u64;
            if let Some(telemetry) = this.telemetry.as_ref() {
                match this.direction {
                    TrafficDirection::FromClients => telemetry.record_client_bytes(bytes),
                    TrafficDirection::FromUpstreams => telemetry.record_upstream_bytes(bytes),
                }
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TelemetryStream<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().stream).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_shutdown(context)
    }
}

async fn copy_bidirectional_with_telemetry<C, U>(
    client: &mut C,
    upstream: &mut U,
    telemetry: Option<ConnectionTelemetry>,
) -> io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = TelemetryStream {
        stream: client,
        telemetry: telemetry.clone(),
        direction: TrafficDirection::FromClients,
    };
    let mut upstream = TelemetryStream {
        stream: upstream,
        telemetry,
        direction: TrafficDirection::FromUpstreams,
    };
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await
}

async fn read_client_exact(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    telemetry: &ConnectionTelemetry,
) -> io::Result<()> {
    let mut stream = TelemetryStream {
        stream,
        telemetry: Some(telemetry.clone()),
        direction: TrafficDirection::FromClients,
    };
    stream.read_exact(buffer).await?;
    Ok(())
}

async fn read_initial_prefix(
    stream: &mut TcpStream,
    telemetry: &ConnectionTelemetry,
) -> io::Result<[u8; INITIAL_PREFIX_LEN]> {
    let mut prefix = [0u8; INITIAL_PREFIX_LEN];
    read_client_exact(stream, &mut prefix, telemetry).await?;
    Ok(prefix)
}

fn effective_media_route(client_is_media: bool, endpoint_media_only: bool) -> bool {
    client_is_media || endpoint_media_only
}

fn should_forward_unmapped_direct(error: &RouteLookupError, dc_hint: Option<u32>) -> bool {
    *error == RouteLookupError::AddressNotListed && dc_hint.is_none()
}

async fn wait_for_client_reset(client: &TcpStream) {
    let mut byte = [0u8; 1];
    loop {
        match client.peek(&mut byte).await {
            Ok(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return,
        }
    }
}

async fn complete_unless_client_resets<F: Future>(
    client: &TcpStream,
    operation: F,
) -> Option<F::Output> {
    tokio::select! {
        result = operation => Some(result),
        _ = wait_for_client_reset(client) => None,
    }
}

struct DirectPayload {
    initial: [u8; crate::crypto::HANDSHAKE_LEN],
    destination: SocketAddr,
    peer: SocketAddr,
    is_media: bool,
    transport: &'static str,
    telemetry: Option<ConnectionTelemetry>,
}

async fn bridge_direct_payload(
    mut client: TcpStream,
    payload: DirectPayload,
    config: Arc<Config>,
    runtime: Arc<Runtime>,
) {
    let attempt = payload
        .telemetry
        .as_ref()
        .map(|telemetry| telemetry.begin_attempt("direct", "tcp_passthrough"));
    let host = payload.destination.ip().to_string();
    let timeout = Duration::from_secs(config.tcp_fallback_timeout);
    let connect = runtime
        .outbound()
        .connect(&host, payload.destination.port(), timeout);
    let Some(result) = complete_unless_client_resets(&client, connect).await else {
        drop(attempt);
        debug!(
            "[{}] клиент сбросил соединение во время выбора прямого TCP-маршрута",
            payload.peer
        );
        return;
    };
    match result {
        Ok(mut remote) => {
            if let Err(error) = remote.write_all(&payload.initial).await {
                if let Some(attempt) = attempt {
                    attempt.finish("failed");
                }
                warn!(
                    "[{}] не удалось передать начальные данные по маршруту {} к {}: {}",
                    payload.peer, payload.transport, payload.destination, error
                );
                return;
            }
            if let Some(attempt) = attempt {
                attempt.finish("connected");
            }
            if let Some(telemetry) = payload.telemetry.as_ref() {
                telemetry.select_transport("direct", "tcp_passthrough");
            }
            match copy_bidirectional_with_telemetry(
                &mut client,
                &mut remote,
                payload.telemetry.clone(),
            )
            .await
            {
                Ok((bytes_up, bytes_down)) => info!(
                    "[{}] маршрут {} к исходному назначению {}{} завершён: вверх {} байт, вниз {} байт",
                    payload.peer,
                    payload.transport,
                    payload.destination,
                    media_tag(payload.is_media),
                    bytes_up + payload.initial.len() as u64,
                    bytes_down
                ),
                Err(error) => debug!(
                    "[{}] поток маршрута {} к {}{} завершился с ошибкой: {}",
                    payload.peer,
                    payload.transport,
                    payload.destination,
                    media_tag(payload.is_media),
                    error
                ),
            }
        }
        Err(error) => {
            if let Some(attempt) = attempt {
                attempt.finish("failed");
            }
            warn!(
                "[{}] не удалось открыть маршрут {} к исходному назначению {}: {}",
                payload.peer, payload.transport, payload.destination, error
            );
        }
    }
}

/// Путь для прозрачного перехвата правилами REDIRECT на роутере. Начальный
/// пакет obfuscated2 содержит DC и признак media, а SO_ORIGINAL_DST — точный IP DC.
/// Начальный пакет и все последующие байты передаются выбранному узлу без изменений.
pub async fn handle_transparent_client_with_runtime(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    runtime: Arc<Runtime>,
    telemetry: ConnectionTelemetry,
) {
    telemetry.set_stage("reading_original_destination");
    let destination = match transparent::original_destination(&stream) {
        Ok(destination) => destination,
        Err(error) => {
            warn!(
                "[{}] прозрачное перенаправление: SO_ORIGINAL_DST недоступен: {}",
                peer, error
            );
            return;
        }
    };
    debug!(
        "[{}] исходное назначение прозрачного потока: {}",
        peer, destination
    );
    if !transparent::supports_destination_port(destination.port(), &config.transparent_ports) {
        debug!(
            "[{}] прозрачное перенаправление отклонено: порт {} отсутствует в политике",
            peer,
            destination.port()
        );
        return;
    }
    if !transparent::is_telegram_destination(destination.ip(), &config.transparent_cidrs) {
        debug!(
            "[{}] прозрачное перенаправление отклонено: IP назначения {} не входит в CIDR Telegram",
            peer,
            destination.ip()
        );
        return;
    }
    let _ = stream.set_nodelay(true);

    let handshake_deadline =
        tokio::time::Instant::now() + Duration::from_secs(config.handshake_timeout);
    let first_bytes = match tokio::time::timeout_at(
        handshake_deadline,
        read_initial_prefix(&mut stream, &telemetry),
    )
    .await
    {
        Ok(Ok(prefix)) => prefix,
        Ok(Err(error)) => {
            debug!(
                "[{}] не удалось прочитать начало MTProto-потока: {}",
                peer, error
            );
            return;
        }
        Err(_) => {
            debug!("[{}] истекло время ожидания начала MTProto-потока", peer);
            return;
        }
    };

    let mut init = [0u8; crate::crypto::HANDSHAKE_LEN];
    init[..INITIAL_PREFIX_LEN].copy_from_slice(&first_bytes);
    match tokio::time::timeout_at(
        handshake_deadline,
        read_client_exact(&mut stream, &mut init[INITIAL_PREFIX_LEN..], &telemetry),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            debug!(
                "[{}] не удалось прочитать начальный пакет obfuscated2: {}",
                peer, error
            );
            return;
        }
        Err(_) => {
            debug!(
                "[{}] истекло время ожидания начального пакета obfuscated2",
                peer
            );
            return;
        }
    }
    let secret_candidates = runtime
        .dc_map()
        .handshake_secrets_for(destination.ip(), destination.port());
    let Some(init_info) = transparent::parse_client_init_with_secrets(&init, &secret_candidates)
    else {
        debug!(
            "[{}] неизвестное или повреждённое рукопожатие MTProto для назначения {}",
            peer, destination
        );
        return;
    };
    let (destination_route, map_source) = match runtime
        .dc_map()
        .resolve_for_transparent_with_source(
            destination.ip(),
            destination.port(),
            init_info.is_media,
            init_info.dc,
        ) {
        Ok(route) => route,
        Err(error) if should_forward_unmapped_direct(&error, init_info.dc) => {
            warn!(
                "[{}] адрес {} отсутствует в проверенной DC-карте; WSS relay не выбирается, поток направляется только к тому же исходному IP:port",
                peer, destination
            );
            bridge_direct_payload(
                stream,
                DirectPayload {
                    initial: init,
                    destination,
                    peer,
                    is_media: init_info.is_media,
                    transport: "прямой TCP",
                    telemetry: Some(telemetry),
                },
                Arc::clone(&config),
                Arc::clone(&runtime),
            )
            .await;
            return;
        }
        Err(error) => {
            warn!(
                "[{}] прозрачный маршрут отклонён для {}: {} (DC из рукопожатия: {:?}, media: {})",
                peer, destination, error, init_info.dc, init_info.is_media
            );
            return;
        }
    };
    let dc = destination_route.id;
    let is_media = effective_media_route(init_info.is_media, destination_route.media_only);
    telemetry.set_dc(dc, is_media);
    telemetry.set_stage("routing");
    info!(
        "[{}] dcOption для {}: DC{}{}, карта={}, CDN={}, TCP-only={}, this-port-only={}, порт опции={}, порт клиента={}",
        peer,
        destination,
        dc,
        media_tag(is_media),
        map_source.as_str(),
        destination_route.cdn,
        destination_route.tcpo_only,
        destination_route.this_port_only,
        destination_route.port,
        destination.port()
    );
    if destination_route.cdn {
        info!(
            "[{}] официальный CDN DC{} направляется только прямым TCP к исходному назначению {}",
            peer, destination_route.id, destination
        );
        bridge_direct_payload(
            stream,
            DirectPayload {
                initial: init,
                destination,
                peer,
                is_media: effective_media_route(init_info.is_media, destination_route.media_only),
                transport: "прямой TCP",
                telemetry: Some(telemetry),
            },
            Arc::clone(&config),
            Arc::clone(&runtime),
        )
        .await;
        return;
    }
    let label = peer;
    let target_ip = destination.ip().to_string();
    let route = routing::Route::new(
        label,
        &config,
        &runtime,
        dc,
        is_media,
        Some(telemetry.clone()),
    );
    let tcp_fallback_timeout = route.tcp_fallback_timeout();
    let tcp_failure_cooldown = route.tcp_fallback_failure_cooldown();
    let Some(upstream) =
        complete_unless_client_resets(&stream, routing::select_upstream(&route, &target_ip))
            .await
            .flatten()
    else {
        return;
    };
    match upstream {
        Upstream::Ws {
            ws,
            framing,
            route_type,
            feedback,
        } => {
            let (branch, transport) = match route_type {
                "прямой WSS" => ("direct", "direct_wss"),
                "WSS через Cloudflare Worker" => ("fallback", "cloudflare_worker"),
                "WSS через Cloudflare proxy" => ("fallback", "cloudflare_proxy"),
                _ => ("fallback", "unknown_wss"),
            };
            telemetry.select_transport(branch, transport);
            crate::bridge::bridge_transparent_ws(
                stream,
                *ws,
                init,
                label,
                destination,
                dc,
                is_media,
                init_info.proto,
                framing,
                route_type,
                feedback,
                telemetry.clone(),
            )
            .await;
        }
        Upstream::Tcp(host) => {
            let (fallback_host, fallback_port) =
                transparent::tcp_fallback_target(&host, destination);
            let attempt = telemetry.begin_attempt("fallback", "tcp_fallback");
            let connect =
                runtime
                    .outbound()
                    .connect(&fallback_host, fallback_port, tcp_fallback_timeout);
            let Some(result) = complete_unless_client_resets(&stream, connect).await else {
                debug!(
                    "[{}] клиент сбросил соединение во время выбора резервного TCP",
                    peer
                );
                return;
            };
            match result {
                Ok(mut remote) => {
                    routing::record_tcp_connect_success(dc, is_media, &target_ip);
                    if let Err(error) = remote.write_all(&init).await {
                        routing::record_tcp_connect_failure(
                            dc,
                            is_media,
                            &target_ip,
                            tcp_failure_cooldown,
                        );
                        attempt.finish("failed");
                        telemetry.mark_cooldown("fallback", "tcp_fallback");
                        warn!(
                            "[{}] не удалось передать начальный пакет по резервному TCP: {}",
                            peer, error
                        );
                        return;
                    }
                    attempt.finish("connected");
                    telemetry.select_transport("fallback", "tcp_fallback");
                    let mut client = stream;
                    match copy_bidirectional_with_telemetry(
                        &mut client,
                        &mut remote,
                        Some(telemetry.clone()),
                    )
                    .await
                    {
                        Ok((bytes_up, bytes_down)) => info!(
                            "[{}] прозрачный маршрут=резервный TCP DC{}{} закрыт клиентом: вверх {} байт, вниз {} байт",
                            peer,
                            dc,
                            media_tag(is_media),
                            bytes_up,
                            bytes_down
                        ),
                        Err(error) => debug!(
                            "[{}] прозрачный маршрут=резервный TCP DC{}{} закрыт с ошибкой: {}",
                            peer,
                            dc,
                            media_tag(is_media),
                            error
                        ),
                    }
                }
                Err(error) => {
                    attempt.finish("failed");
                    routing::record_tcp_connect_failure(
                        dc,
                        is_media,
                        &target_ip,
                        tcp_failure_cooldown,
                    );
                    telemetry.mark_cooldown("fallback", "tcp_fallback");
                    warn!(
                        "[{}] не удалось открыть резервное TCP-соединение с {}: {}; маршрут приостановлен на {} с",
                        peer,
                        host,
                        error,
                        tcp_failure_cooldown.as_secs()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DirectPayload, TelemetryStream, TrafficDirection, bridge_direct_payload,
        complete_unless_client_resets, copy_bidirectional_with_telemetry, effective_media_route,
        should_forward_unmapped_direct,
    };
    use crate::config::Config;
    use crate::dc_map::{DcEndpoint, DcMapStore, DcSnapshot, RouteLookupError, lookup_endpoint};
    use crate::outbound::OutboundConnector;
    use crate::runtime::Runtime;
    use crate::stats::RuntimeStats;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn tcp_учитывает_полученные_байты_до_их_пересылки() {
        let stats = Arc::new(RuntimeStats::new());
        let guard = stats.connection_started();
        let telemetry = guard.telemetry();
        let (mut proxy, mut peer) = tokio::io::duplex(64);
        let mut proxy = TelemetryStream {
            stream: &mut proxy,
            telemetry: Some(telemetry),
            direction: TrafficDirection::FromClients,
        };

        peer.write_all(b"received").await.unwrap();
        let mut received = [0; 8];
        proxy.read_exact(&mut received).await.unwrap();

        assert_eq!(&received, b"received");
        assert_eq!(stats.snapshot().active_sessions[0].bytes_from_clients, 8);
        assert_eq!(stats.snapshot().active_sessions[0].bytes_from_upstreams, 0);
        drop(guard);
    }

    #[tokio::test]
    async fn прозрачный_tcp_учитывает_байты_обоих_направлений() {
        let stats = Arc::new(RuntimeStats::new());
        let guard = stats.connection_started();
        let telemetry = guard.telemetry();
        let (mut client_peer, mut client_proxy) = tokio::io::duplex(64);
        let (mut upstream_proxy, mut upstream_peer) = tokio::io::duplex(64);

        let relay = copy_bidirectional_with_telemetry(
            &mut client_proxy,
            &mut upstream_proxy,
            Some(telemetry),
        );
        let peers = async {
            client_peer.write_all(b"request-upstream").await.unwrap();
            client_peer.shutdown().await.unwrap();
            let mut request = vec![0; b"request-upstream".len()];
            upstream_peer.read_exact(&mut request).await.unwrap();
            assert_eq!(request, b"request-upstream");

            upstream_peer.write_all(b"reply-client").await.unwrap();
            upstream_peer.shutdown().await.unwrap();
            let mut response = vec![0; b"reply-client".len()];
            client_peer.read_exact(&mut response).await.unwrap();
            assert_eq!(response, b"reply-client");
        };
        let (result, ()) = tokio::join!(relay, peers);

        assert_eq!(
            result.unwrap(),
            (
                b"request-upstream".len() as u64,
                b"reply-client".len() as u64
            )
        );
        let session = &stats.snapshot().active_sessions[0];
        assert_eq!(session.bytes_from_clients, b"request-upstream".len() as u64);
        assert_eq!(session.bytes_from_upstreams, b"reply-client".len() as u64);
        drop(guard);
    }

    #[test]
    fn ordinary_dc_option_preserves_the_clients_media_session_hint() {
        assert!(effective_media_route(true, false));
        assert!(effective_media_route(true, true));
        assert!(!effective_media_route(false, false));
    }

    #[test]
    fn unmapped_tcp_passthrough_does_not_guess_a_dc_or_bypass_other_validation_errors() {
        assert!(should_forward_unmapped_direct(
            &RouteLookupError::AddressNotListed,
            None
        ));
        assert!(!should_forward_unmapped_direct(
            &RouteLookupError::AddressNotListed,
            Some(2)
        ));
        assert!(!should_forward_unmapped_direct(
            &RouteLookupError::MediaFlagMismatch,
            None
        ));
        assert!(!should_forward_unmapped_direct(
            &RouteLookupError::DcMismatch,
            None
        ));
    }

    #[test]
    fn observed_unmapped_addresses_use_exact_direct_fallback_only_without_dc_hint() {
        let store = DcMapStore::without_cache("/tmp/tg-transparent-unmapped-test.json");
        for address in ["149.154.167.43", "91.108.56.137"] {
            let error = store
                .resolve_with_source(address.parse().unwrap(), 443, true, None)
                .unwrap_err();
            assert_eq!(error, RouteLookupError::AddressNotListed, "{address}");
            assert!(should_forward_unmapped_direct(&error, None), "{address}");
            assert!(
                !should_forward_unmapped_direct(&error, Some(2)),
                "DC hint must not let an unknown IP select a WSS route: {address}"
            );
        }
    }

    #[test]
    fn official_regular_dc_option_keeps_media_session_and_media_only_validation() {
        let now = 1_800_000_000;
        let regular = DcEndpoint {
            id: 2,
            address: "149.154.167.151".parse::<IpAddr>().unwrap(),
            port: 443,
            ipv6: false,
            media_only: false,
            tcpo_only: false,
            cdn: false,
            is_static: false,
            this_port_only: false,
            secret: None,
            last_seen: now,
        };
        let snapshot = DcSnapshot {
            schema_version: 1,
            fetched_at: now,
            config_date: now,
            config_expires: now + 86_400,
            this_dc: 2,
            endpoints: vec![regular],
        };
        let route = lookup_endpoint(
            &snapshot,
            "149.154.167.151".parse().unwrap(),
            443,
            true,
            Some(2),
        )
        .unwrap();
        assert!(!route.media_only);
        assert!(effective_media_route(true, route.media_only));

        let mut media_only_snapshot = snapshot;
        media_only_snapshot.endpoints[0].media_only = true;
        assert_eq!(
            lookup_endpoint(
                &media_only_snapshot,
                "149.154.167.151".parse().unwrap(),
                443,
                false,
                Some(2),
            ),
            Err(RouteLookupError::MediaFlagMismatch)
        );
    }

    #[tokio::test]
    async fn unmapped_connection_passes_the_same_destination_and_mtproto_bytes_directly() {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let destination = target.local_addr().unwrap();
        let client_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut client = TcpStream::connect(client_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (proxy_side, peer) = client_listener.accept().await.unwrap();
        let config = Arc::new(Config::try_from_cli_line("--tcp-fallback-timeout=1").unwrap());
        let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
        let init = [0x5a; 64];
        let forward = tokio::spawn(bridge_direct_payload(
            proxy_side,
            DirectPayload {
                initial: init,
                destination,
                peer,
                is_media: true,
                transport: "прямой TCP",
                telemetry: None,
            },
            config,
            runtime,
        ));

        client.write_all(b"data").await.unwrap();
        client.shutdown().await.unwrap();
        let (mut upstream, _) = target.accept().await.unwrap();
        let mut received_init = [0; 64];
        upstream.read_exact(&mut received_init).await.unwrap();
        let mut received_payload = [0; 4];
        upstream.read_exact(&mut received_payload).await.unwrap();
        assert_eq!(received_init, init);
        assert_eq!(&received_payload, b"data");
        upstream.write_all(b"resPQ").await.unwrap();
        upstream.shutdown().await.unwrap();

        let mut response = [0; 5];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"resPQ");
        forward.await.unwrap();
    }

    #[tokio::test]
    async fn reset_client_cancels_pending_route_selection() {
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (proxy_side, _) = listener.accept().await.unwrap();
        socket2::SockRef::from(&client)
            .set_linger(Some(Duration::ZERO))
            .unwrap();

        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_for_operation = Arc::clone(&dropped);
        let operation = async move {
            let _drop_flag = DropFlag(dropped_for_operation);
            std::future::pending::<()>().await;
        };
        let task =
            tokio::spawn(
                async move { complete_unless_client_resets(&proxy_side, operation).await },
            );
        drop(client);

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap(),
            None
        );
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tcp_half_close_does_not_cancel_pending_route_selection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (proxy_side, _) = listener.accept().await.unwrap();
        client.shutdown().await.unwrap();

        let result = complete_unless_client_resets(&proxy_side, async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            7
        })
        .await;

        assert_eq!(result, Some(7));
    }
}
