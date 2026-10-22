//! HTTP/3-пробы QUIC по заранее привязанному UDP-сокету.

use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Buf;
use rustls::RootCertStore;

pub const R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS: u32 = 25;
const R2O_QUIC_HTTP3_MAX_BODY_BYTES: u64 = 16 * 1024 * 1024;

/// Создать привязанный UDP-сокет для QUIC до установки соединения.
pub fn r2o_quic_http3_udp_socket(
    server: SocketAddr,
    mark: Option<u32>,
) -> std::io::Result<UdpSocket> {
    r2o_quic_http3_udp_socket_detailed(server, mark).map_err(|error| error.source)
}

/// Ошибка настройки UDP-сокета и признак локального отказа установки метки.
#[derive(Debug)]
pub struct R2oQuicUdpSocketError {
    pub source: std::io::Error,
    pub local_refusal: bool,
}

/// Создать QUIC-сокет, сохранив причину отказа установки SO_MARK.
pub fn r2o_quic_http3_udp_socket_detailed(
    server: SocketAddr,
    mark: Option<u32>,
) -> Result<UdpSocket, R2oQuicUdpSocketError> {
    r2o_quic_http3_udp_socket_with_mark_setter(server, mark, r2o_quic_http3_set_socket_mark)
}

fn r2o_quic_http3_udp_socket_with_mark_setter(
    server: SocketAddr,
    mark: Option<u32>,
    set_mark: impl FnOnce(&UdpSocket, u32) -> std::io::Result<()>,
) -> Result<UdpSocket, R2oQuicUdpSocketError> {
    let bind = SocketAddr::new(
        match server.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        0,
    );
    let socket = UdpSocket::bind(bind).map_err(R2oQuicUdpSocketError::ordinary)?;
    if let Some(mark) = mark {
        set_mark(&socket, mark).map_err(R2oQuicUdpSocketError::local_refusal)?;
    }
    socket
        .connect(server)
        .map_err(R2oQuicUdpSocketError::ordinary)?;
    Ok(socket)
}

impl R2oQuicUdpSocketError {
    fn ordinary(source: std::io::Error) -> Self {
        Self {
            source,
            local_refusal: false,
        }
    }

    fn local_refusal(source: std::io::Error) -> Self {
        Self {
            source,
            local_refusal: true,
        }
    }
}

#[cfg(target_os = "linux")]
fn r2o_quic_http3_set_socket_mark(socket: &UdpSocket, mark: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const u32).cast(),
            std::mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn r2o_quic_http3_set_socket_mark(_socket: &UdpSocket, _mark: u32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "метка SO_MARK поддерживается только в Linux",
    ))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct R2oQuicHttp3Result {
    pub local_refusal: bool,
    pub handshake_confirmed: bool,
    pub status: u16,
    pub body_bytes: u64,
    pub complete: bool,
    pub requests: u32,
    pub datagrams: u64,
    pub budget_required: bool,
    pub budget_passed: bool,
    pub r2o_quic_stalled: bool,
    pub r2o_quic_one_way: bool,
    pub r2o_ping_probes: u32,
    pub r2o_ping_acks: u32,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum R2oQuicHttp3StallAction {
    Continue,
    Probe,
    Stalled,
    OneWay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum R2oQuicHttp3StallEnd {
    Stalled,
    OneWay,
}

/// Хранит порог пакетов и рост тела, необходимый для подтверждения бюджета.
struct R2oQuicHttp3Budget {
    need: u64,
    progress_mark: Option<u64>,
}

impl R2oQuicHttp3Budget {
    fn r2o_initialize(budget_packets: u32) -> Self {
        let packets = if budget_packets == 0 {
            R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS
        } else {
            budget_packets
        };
        Self {
            need: u64::from(packets).saturating_mul(2),
            progress_mark: None,
        }
    }

    fn r2o_mark(&mut self, packets: u64, progress: u64) {
        if packets >= self.need {
            self.progress_mark.get_or_insert(progress);
        }
    }

    fn r2o_step(
        &mut self,
        packets: u64,
        progress: u64,
        status: u16,
        now: tokio::time::Instant,
        last_progress_at: tokio::time::Instant,
        rto: Duration,
    ) -> bool {
        self.r2o_mark(packets, progress);
        status > 0
            && self.progress_mark.is_some_and(|mark| progress > mark)
            && now.saturating_duration_since(last_progress_at) < rto
    }
}

struct R2oQuicHttp3Stall {
    rto: Duration,
    last_progress_at: tokio::time::Instant,
    probe_at: Option<tokio::time::Instant>,
    progress_seen: u64,
    wire_seen: u64,
    wire_at_probe: u64,
    probe_packet_number: Option<u64>,
    unanswered: u8,
    probes_sent: u32,
    probes_acked: u32,
}

impl R2oQuicHttp3Stall {
    fn r2o_initialize(rtt: Duration, progress: u64, wire: u64) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            rto: rtt.saturating_mul(3).max(Duration::from_secs(1)),
            last_progress_at: now,
            probe_at: None,
            progress_seen: progress,
            wire_seen: wire,
            wire_at_probe: wire,
            probe_packet_number: None,
            unanswered: 0,
            probes_sent: 0,
            probes_acked: 0,
        }
    }

    fn r2o_sent(&mut self, packet_number: u64) {
        self.probe_packet_number = Some(packet_number);
        self.probes_sent = self.probes_sent.saturating_add(1);
    }

    fn r2o_capture_ack(&mut self, largest_acked: Option<u64>) -> bool {
        if !self
            .probe_packet_number
            .zip(largest_acked)
            .is_some_and(|(probe, acked)| acked >= probe)
        {
            return false;
        }

        self.probe_at = None;
        self.probe_packet_number = None;
        self.unanswered = 0;
        self.probes_acked = self.probes_acked.saturating_add(1);
        true
    }

    #[inline(never)]
    fn r2o_step(
        &mut self,
        now: tokio::time::Instant,
        progress: u64,
        wire: u64,
        largest_acked: Option<u64>,
    ) -> R2oQuicHttp3StallAction {
        self.wire_seen = wire;
        let probe_acked = self.r2o_capture_ack(largest_acked);
        if progress != self.progress_seen {
            self.progress_seen = progress;
            self.last_progress_at = now;
            self.probe_at = None;
            self.probe_packet_number = None;
            self.unanswered = 0;
            return R2oQuicHttp3StallAction::Continue;
        }
        if probe_acked {
            return R2oQuicHttp3StallAction::Continue;
        }
        let Some(probe_at) = self.probe_at else {
            if now.duration_since(self.last_progress_at) >= self.rto {
                self.probe_at = Some(now);
                self.probe_packet_number = None;
                self.wire_at_probe = self.wire_seen;
                return R2oQuicHttp3StallAction::Probe;
            }
            return R2oQuicHttp3StallAction::Continue;
        };
        if now.duration_since(probe_at) < self.rto {
            return R2oQuicHttp3StallAction::Continue;
        }
        if self.probe_packet_number.is_none() {
            self.probe_at = Some(now);
            return R2oQuicHttp3StallAction::Probe;
        }
        self.unanswered = self.unanswered.saturating_add(1);
        if self.unanswered >= 2 {
            return if self.wire_seen != self.wire_at_probe {
                R2oQuicHttp3StallAction::OneWay
            } else {
                R2oQuicHttp3StallAction::Stalled
            };
        }
        self.probe_at = Some(now);
        self.probe_packet_number = None;
        R2oQuicHttp3StallAction::Probe
    }
}

/// Выполнить один GET и вернуть статус, объём тела и признак полного ответа.
pub async fn r2o_quic_http3_get(
    socket: UdpSocket,
    server: SocketAddr,
    server_name: &str,
    path: &str,
    timeout: Duration,
    roots: RootCertStore,
) -> R2oQuicHttp3Result {
    r2o_quic_http3_get_with_wire_len(socket, server, server_name, path, timeout, roots, None).await
}

/// Выполнить один GET с заданной длиной ClientHello внутри QUIC.
pub async fn r2o_quic_http3_get_with_wire_len(
    socket: UdpSocket,
    server: SocketAddr,
    server_name: &str,
    path: &str,
    timeout: Duration,
    roots: RootCertStore,
    wire_len: Option<usize>,
) -> R2oQuicHttp3Result {
    r2o_quic_http3_measure_with_wire_len(
        socket,
        server,
        server_name,
        path,
        timeout,
        roots,
        0,
        wire_len,
    )
    .await
}

/// Измерить ответ HTTP/3, при необходимости повторяя GET до прохождения бюджета датаграмм.
pub async fn r2o_quic_http3_measure(
    socket: UdpSocket,
    server: SocketAddr,
    server_name: &str,
    path: &str,
    timeout: Duration,
    roots: RootCertStore,
    budget_packets: u32,
) -> R2oQuicHttp3Result {
    r2o_quic_http3_measure_with_wire_len(
        socket,
        server,
        server_name,
        path,
        timeout,
        roots,
        budget_packets,
        None,
    )
    .await
}

/// Выполнить HTTP/3-замер с бюджетом датаграмм и заданной длиной ClientHello.
pub async fn r2o_quic_http3_measure_with_wire_len(
    socket: UdpSocket,
    server: SocketAddr,
    server_name: &str,
    path: &str,
    timeout: Duration,
    roots: RootCertStore,
    budget_packets: u32,
    wire_len: Option<usize>,
) -> R2oQuicHttp3Result {
    let repeated = budget_packets > 0;
    let result = Arc::new(Mutex::new(R2oQuicHttp3Result {
        budget_required: repeated,
        ..R2oQuicHttp3Result::default()
    }));
    if server.port() == 0 || timeout.is_zero() {
        let mut state = result.lock().unwrap();
        state.error = Some("адрес или срок ожидания HTTP/3 неверен".into());
        return state.clone();
    }
    if !path.starts_with('/')
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'#')
    {
        let mut state = result.lock().unwrap();
        state.error = Some("путь HTTP/3 должен быть абсолютным".into());
        return state.clone();
    }
    if rustls::pki_types::ServerName::try_from(server_name.to_owned()).is_err() {
        let mut state = result.lock().unwrap();
        state.error = Some("имя HTTP/3-узла недопустимо для TLS".into());
        return state.clone();
    }

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.r2o_client_hello_wire_len = wire_len;
    let crypto = match quinn::crypto::rustls::QuicClientConfig::try_from(tls) {
        Ok(crypto) => crypto,
        Err(error) => {
            result.lock().unwrap().error = Some(format!("не настроен QUIC TLS: {error}"));
            return result.lock().unwrap().clone();
        }
    };
    let runtime = match quinn::default_runtime() {
        Some(runtime) => runtime,
        None => {
            result.lock().unwrap().error = Some("HTTP/3-клиент запущен без Tokio runtime".into());
            return result.lock().unwrap().clone();
        }
    };
    let mut endpoint =
        match quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                result.lock().unwrap().error = Some(format!("не создан QUIC endpoint: {error}"));
                return result.lock().unwrap().clone();
            }
        };
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

    let connecting = match endpoint.connect(server, server_name) {
        Ok(connecting) => connecting,
        Err(error) => {
            result.lock().unwrap().error = Some(format!("не начато QUIC-рукопожатие: {error}"));
            return result.lock().unwrap().clone();
        }
    };
    let connection = match tokio::time::timeout(timeout, connecting).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            result.lock().unwrap().error = Some(format!("QUIC-рукопожатие не завершено: {error}"));
            return result.lock().unwrap().clone();
        }
        Err(_) => {
            result.lock().unwrap().error = Some("истёк срок QUIC-рукопожатия".into());
            return result.lock().unwrap().clone();
        }
    };
    result.lock().unwrap().handshake_confirmed = true;

    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut send_request) =
        match tokio::time::timeout(timeout, h3::client::new(h3_connection)).await {
            Ok(Ok(client)) => client,
            Ok(Err(error)) => {
                result.lock().unwrap().error = Some(format!("не запущен HTTP/3-клиент: {error}"));
                return result.lock().unwrap().clone();
            }
            Err(_) => {
                result.lock().unwrap().error = Some("истёк срок настройки HTTP/3".into());
                return result.lock().unwrap().clone();
            }
        };
    let drive_task =
        tokio::spawn(async move { poll_fn(|context| driver.poll_close(context)).await });

    let authority = r2o_quic_http3_authority(server, server_name);
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path)
        .build();
    let uri = match uri {
        Ok(uri) => uri,
        Err(_) => {
            result.lock().unwrap().error = Some("не построен URI HTTP/3 GET".into());
            connection.close(quinn::VarInt::from_u32(0), "проба r2o завершена".as_bytes());
            drive_task.abort();
            return result.lock().unwrap().clone();
        }
    };

    let rto = connection
        .rtt()
        .saturating_mul(3)
        .max(Duration::from_secs(1));
    let request_timeout = timeout.saturating_mul(4).max(rto.saturating_mul(4));
    let mut datagrams_before = r2o_quic_http3_datagrams(&connection);
    let mut total_body_bytes = 0_u64;
    let mut status = 0_u16;
    let mut requests = 0_u32;
    let mut last_response_complete = false;
    let mut last_progress_at = tokio::time::Instant::now();
    let mut budget = R2oQuicHttp3Budget::r2o_initialize(budget_packets);
    let mut budget_passed = false;
    let mut stall = R2oQuicHttp3Stall::r2o_initialize(
        connection.rtt(),
        total_body_bytes,
        r2o_quic_http3_wire_bytes(&connection),
    );
    let mut stall_end = None;

    loop {
        let request_result = tokio::time::timeout(request_timeout, async {
            status = 0;
            result.lock().unwrap().status = status;
            let request = http::Request::builder()
                .method(http::Method::GET)
                .uri(uri.clone())
                .body(())
                .map_err(|error| format!("не построен HTTP/3 GET: {error}"))?;
            let mut stream = send_request
                .send_request(request)
                .await
                .map_err(|error| format!("HTTP/3 GET не отправлен: {error}"))?;
            stream
                .finish()
                .await
                .map_err(|error| format!("HTTP/3 GET не завершён: {error}"))?;
            if requests == 0 {
                datagrams_before = r2o_quic_http3_datagrams(&connection);
            }
            requests = requests.saturating_add(1);
            result.lock().unwrap().requests = requests;

            let response = r2o_quic_http3_wait_with_stall(
                &connection,
                &mut stall,
                &mut budget,
                repeated,
                datagrams_before,
                total_body_bytes,
                stream.recv_response(),
            )
            .await
            .map_err(|end| {
                stall_end = Some(end);
                match end {
                    R2oQuicHttp3StallEnd::Stalled => {
                        "QUIC-ответ завис: PING не подтверждён".to_owned()
                    }
                    R2oQuicHttp3StallEnd::OneWay => {
                        "QUIC-сервер продолжает передачу, но не подтверждает наши пакеты".to_owned()
                    }
                }
            })?
            .map_err(|error| format!("заголовки HTTP/3-ответа не получены: {error}"))?;
            status = response.status().as_u16();
            result.lock().unwrap().status = status;
            if status == 451 {
                return Ok::<bool, String>(false);
            }
            let expected = response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok());
            let mut response_bytes = 0_u64;
            loop {
                let received = r2o_quic_http3_wait_with_stall(
                    &connection,
                    &mut stall,
                    &mut budget,
                    repeated,
                    datagrams_before,
                    total_body_bytes,
                    stream.recv_data(),
                )
                .await
                .map_err(|end| {
                    stall_end = Some(end);
                    match end {
                        R2oQuicHttp3StallEnd::Stalled => {
                            "QUIC-ответ завис: PING не подтверждён".to_owned()
                        }
                        R2oQuicHttp3StallEnd::OneWay => {
                            "QUIC-сервер продолжает передачу, но не подтверждает наши пакеты"
                                .to_owned()
                        }
                    }
                })?;
                match received {
                    Ok(Some(chunk)) => {
                        let length = chunk.remaining() as u64;
                        response_bytes = response_bytes.saturating_add(length);
                        total_body_bytes = total_body_bytes.saturating_add(length);
                        if total_body_bytes > R2O_QUIC_HTTP3_MAX_BODY_BYTES {
                            return Err("HTTP/3-ответы превысили предел 16 МиБ".into());
                        }

                        let now = tokio::time::Instant::now();
                        let packets =
                            r2o_quic_http3_datagrams(&connection).saturating_sub(datagrams_before);
                        if length > 0 {
                            last_progress_at = now;
                        }
                        if repeated {
                            budget_passed = budget.r2o_step(
                                packets,
                                total_body_bytes,
                                status,
                                now,
                                last_progress_at,
                                rto,
                            );
                        }
                        let mut state = result.lock().unwrap();
                        state.body_bytes = total_body_bytes;
                        state.datagrams = packets;
                        state.budget_passed = budget_passed;
                        if budget_passed {
                            return Ok(false);
                        }
                    }
                    Ok(None) => {
                        if expected.is_some_and(|length| length != response_bytes) {
                            return Err("длина HTTP/3-тела не совпала с Content-Length".into());
                        }
                        return Ok(true);
                    }
                    Err(error) => return Err(format!("ошибка чтения HTTP/3-тела: {error}")),
                }
            }
        })
        .await;

        match request_result {
            Ok(Ok(complete)) => last_response_complete = complete,
            Ok(Err(error)) => {
                let mut state = result.lock().unwrap();
                state.error = Some(error);
                if let Some(end) = stall_end {
                    state.r2o_quic_stalled = true;
                    state.r2o_quic_one_way = end == R2oQuicHttp3StallEnd::OneWay;
                }
                break;
            }
            Err(_) => {
                result.lock().unwrap().error = Some("истёк срок HTTP/3 GET".into());
                break;
            }
        }

        if !repeated || budget_passed || status == 451 || !last_response_complete {
            break;
        }
    }

    let datagrams = r2o_quic_http3_datagrams(&connection).saturating_sub(datagrams_before);
    stall.r2o_capture_ack(connection.r2o_largest_acked_packet_number());
    {
        let mut state = result.lock().unwrap();
        state.requests = requests;
        state.datagrams = datagrams;
        state.budget_passed = budget_passed;
        state.complete = !repeated && last_response_complete && !state.r2o_quic_stalled;
        state.r2o_ping_probes = stall.probes_sent;
        state.r2o_ping_acks = stall.probes_acked;
    }
    connection.close(quinn::VarInt::from_u32(0), "проба r2o завершена".as_bytes());
    drive_task.abort();
    result.lock().unwrap().clone()
}

fn r2o_quic_http3_authority(server: SocketAddr, server_name: &str) -> String {
    let authority_host = if server_name.parse::<Ipv6Addr>().is_ok() {
        format!("[{server_name}]")
    } else {
        server_name.to_owned()
    };
    if server.port() == 443 {
        authority_host
    } else {
        format!("{authority_host}:{}", server.port())
    }
}

fn r2o_quic_http3_datagrams(connection: &quinn::Connection) -> u64 {
    let stats = connection.stats();
    stats
        .udp_tx
        .datagrams
        .saturating_add(stats.udp_rx.datagrams)
}

fn r2o_quic_http3_wire_bytes(connection: &quinn::Connection) -> u64 {
    connection.stats().udp_rx.bytes
}

async fn r2o_quic_http3_wait_with_stall<F: Future>(
    connection: &quinn::Connection,
    stall: &mut R2oQuicHttp3Stall,
    budget: &mut R2oQuicHttp3Budget,
    budget_active: bool,
    datagrams_before: u64,
    progress: u64,
    future: F,
) -> Result<F::Output, R2oQuicHttp3StallEnd> {
    tokio::pin!(future);
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            output = &mut future => return Ok(output),
            _ = interval.tick() => {
                let now = tokio::time::Instant::now();
                if budget_active {
                    budget.r2o_mark(
                        r2o_quic_http3_datagrams(connection).saturating_sub(datagrams_before),
                        progress,
                    );
                }
                let action = stall.r2o_step(
                    now,
                    progress,
                    r2o_quic_http3_wire_bytes(connection),
                    connection.r2o_largest_acked_packet_number(),
                );
                match action {
                    R2oQuicHttp3StallAction::Continue => {}
                    R2oQuicHttp3StallAction::Probe => {
                        if let Some(packet_number) = connection.r2o_ping() {
                            stall.r2o_sent(packet_number);
                        }
                    }
                    R2oQuicHttp3StallAction::Stalled => {
                        return Err(R2oQuicHttp3StallEnd::Stalled);
                    }
                    R2oQuicHttp3StallAction::OneWay => {
                        return Err(R2oQuicHttp3StallEnd::OneWay);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        R2oQuicHttp3Budget, R2oQuicHttp3Stall, R2oQuicHttp3StallAction as Action,
        r2o_quic_http3_authority, r2o_quic_http3_udp_socket_with_mark_setter,
    };
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn ошибка_установки_quic_метки_классифицируется_как_локальный_отказ() {
        let error = r2o_quic_http3_udp_socket_with_mark_setter(
            "127.0.0.1:443".parse().unwrap(),
            Some(0x2f),
            |_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "тестовый отказ SO_MARK",
                ))
            },
        )
        .unwrap_err();

        assert!(error.local_refusal);
        assert_eq!(error.source.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn заключает_ipv6_literal_в_скобки_в_http3_authority() {
        let server: SocketAddr = "[2001:db8::1]:8443".parse().unwrap();
        assert_eq!(
            r2o_quic_http3_authority(server, "2001:db8::1"),
            "[2001:db8::1]:8443"
        );
    }

    #[test]
    fn r2o_quic_ping_ack_сверяется_с_номером_пакета() {
        let mut stall = R2oQuicHttp3Stall::r2o_initialize(Duration::from_millis(40), 1000, 5000);
        let start = stall.last_progress_at;

        assert_eq!(
            stall.r2o_step(start + Duration::from_secs(1), 1000, 5000, None),
            Action::Probe
        );
        stall.r2o_sent(41);
        assert_eq!(
            stall.r2o_step(start + Duration::from_secs(2), 1000, 5000, Some(40)),
            Action::Probe
        );
        stall.r2o_sent(42);
        assert_eq!(
            stall.r2o_step(start + Duration::from_millis(2500), 1000, 5000, Some(41)),
            Action::Continue
        );
        assert_eq!(
            stall.r2o_step(start + Duration::from_secs(3), 1000, 5000, Some(42)),
            Action::Continue
        );
        assert_eq!(stall.probes_acked, 1);
    }

    #[test]
    fn r2o_quic_ping_ack_учитывается_при_одновременном_росте_тела() {
        let mut stall = R2oQuicHttp3Stall::r2o_initialize(Duration::from_millis(40), 1000, 5000);
        let start = stall.last_progress_at;

        assert_eq!(
            stall.r2o_step(start + Duration::from_secs(1), 1000, 5000, None),
            Action::Probe
        );
        stall.r2o_sent(41);

        assert_eq!(
            stall.r2o_step(start + Duration::from_millis(1200), 1016, 5032, Some(41)),
            Action::Continue
        );
        assert_eq!(stall.probes_acked, 1);
        assert_eq!(stall.probe_packet_number, None);
    }

    #[test]
    fn r2o_quic_различает_обрыв_и_одностороннюю_передачу() {
        let mut stalled = R2oQuicHttp3Stall::r2o_initialize(Duration::from_millis(20), 1000, 5000);
        let start = stalled.last_progress_at;
        assert_eq!(
            stalled.r2o_step(start + Duration::from_secs(1), 1000, 5000, None),
            Action::Probe
        );
        stalled.r2o_sent(10);
        assert_eq!(
            stalled.r2o_step(start + Duration::from_secs(2), 1000, 5000, None),
            Action::Probe
        );
        stalled.r2o_sent(11);
        assert_eq!(
            stalled.r2o_step(start + Duration::from_secs(3), 1000, 5000, None),
            Action::Stalled
        );

        let mut one_way = R2oQuicHttp3Stall::r2o_initialize(Duration::from_millis(20), 1000, 5000);
        let one_way_start = one_way.last_progress_at;
        assert_eq!(
            one_way.r2o_step(one_way_start + Duration::from_secs(1), 1000, 5000, None),
            Action::Probe
        );
        one_way.r2o_sent(20);
        assert_eq!(
            one_way.r2o_step(one_way_start + Duration::from_secs(2), 1000, 5100, None),
            Action::Probe
        );
        one_way.r2o_sent(21);
        assert_eq!(
            one_way.r2o_step(one_way_start + Duration::from_secs(3), 1000, 5100, None),
            Action::OneWay
        );
    }

    #[test]
    fn r2o_quic_бюджет_требует_свежий_рост_после_порога() {
        let start = Instant::now() + Duration::from_millis(10);
        let mut budget = R2oQuicHttp3Budget::r2o_initialize(1);

        assert!(!budget.r2o_step(1, 100, 200, start, start, Duration::from_secs(1)));
        assert!(!budget.r2o_step(2, 100, 200, start, start, Duration::from_secs(1)));
        assert_eq!(budget.progress_mark, Some(100));
        assert!(!budget.r2o_step(
            3,
            120,
            200,
            start + Duration::from_secs(2),
            start,
            Duration::from_secs(1)
        ));
        assert!(!budget.r2o_step(
            3,
            130,
            0,
            start + Duration::from_millis(200),
            start + Duration::from_millis(200),
            Duration::from_secs(1)
        ));
        assert!(budget.r2o_step(
            3,
            140,
            200,
            start + Duration::from_millis(300),
            start + Duration::from_millis(300),
            Duration::from_secs(1)
        ));
    }
}
