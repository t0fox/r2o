//! HTTP/3-пробы QUIC по заранее привязанному UDP-сокету.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use rustls::RootCertStore;

pub const R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS: u32 = 25;
const R2O_QUIC_RECENT_PORTS: usize = 4096;
const R2O_QUIC_HTTP3_HEADER_LIMIT: u64 = 65_536;
const R2O_QUIC_FRESH_PORT_TRIES: usize = 16;
const R2O_QUIC_RESIDUAL_PORT_MS: i64 = 480_000;

/// C `tp_build` (`core/quicconn.c:380-403`): транспортные параметры
/// клиентского QUIC-зонда.
pub(crate) const R2O_QUIC_TP_IDLE_MS: u64 = 30_000;
pub(crate) const R2O_QUIC_TP_MAX_UDP_PAYLOAD: u16 = 1452;
pub(crate) const R2O_QUIC_TP_INITIAL_MAX_DATA: u64 = 1024 * 1024;
pub(crate) const R2O_QUIC_TP_STREAM_WINDOW: u64 = 256 * 1024;
pub(crate) const R2O_QUIC_TP_STREAMS: u64 = 16;

/// Собрать `TransportConfig` со значениями C `tp_build`. Отображение на
/// параметры QUIC (quinn `TransportParameters::new`):
/// `receive_window` → initial_max_data, `stream_receive_window` → три
/// initial_max_stream_data, `max_concurrent_*` → initial_max_streams_*,
/// `max_idle_timeout` → max_idle_timeout.
pub(crate) fn r2o_quic_transport_config() -> Result<quinn::TransportConfig, String> {
    let idle = quinn::IdleTimeout::try_from(Duration::from_millis(R2O_QUIC_TP_IDLE_MS))
        .map_err(|_| "idle timeout QUIC вне диапазона".to_owned())?;
    let varint = |value: u64| {
        quinn::VarInt::from_u64(value).map_err(|_| format!("QUIC varint вне диапазона: {value}"))
    };
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(idle));
    transport.receive_window(varint(R2O_QUIC_TP_INITIAL_MAX_DATA)?);
    transport.stream_receive_window(varint(R2O_QUIC_TP_STREAM_WINDOW)?);
    transport.max_concurrent_bidi_streams(varint(R2O_QUIC_TP_STREAMS)?);
    transport.max_concurrent_uni_streams(varint(R2O_QUIC_TP_STREAMS)?);
    Ok(transport)
}

/// `max_udp_payload_size` клиентского TP берётся из `EndpointConfig`.
pub(crate) fn r2o_quic_endpoint_config() -> Result<quinn::EndpointConfig, String> {
    let mut endpoint = quinn::EndpointConfig::default();
    endpoint
        .max_udp_payload_size(R2O_QUIC_TP_MAX_UDP_PAYLOAD)
        .map_err(|_| "max_udp_payload_size QUIC вне диапазона".to_owned())?;
    Ok(endpoint)
}

static R2O_QUIC_RECENT_PORTS_STATE: OnceLock<Mutex<(VecDeque<(u16, i64)>, usize)>> =
    OnceLock::new();

#[derive(Debug, Default)]
struct R2oQuicHttp3AppState {
    ranges: r2k_core::quic_ranges::R2oQuicRanges,
    total: u64,
}

/// Учёт app-байт ответа: текущий поток — C `d2k_qw_ranges`, сумма — как
/// раньше (уникальные байты всех запросов).
type R2oQuicHttp3AppCounter = Mutex<R2oQuicHttp3AppState>;

fn r2o_quic_http3_app_reset(app: &R2oQuicHttp3AppCounter) {
    let mut state = app
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.ranges.reset();
}

fn r2o_quic_http3_app_add(app: &R2oQuicHttp3AppCounter, offset: u64, length: u64, fin: bool) {
    let mut state = app
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let before = state.ranges.bytes();
    state.ranges.add(offset, length, fin);
    let after = state.ranges.bytes();
    state.total = state.total.saturating_add(after.saturating_sub(before));
}

fn r2o_quic_http3_app_complete(app: &R2oQuicHttp3AppCounter) -> bool {
    app.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .ranges
        .complete()
}

fn r2o_quic_http3_app_current_bytes(app: &R2oQuicHttp3AppCounter) -> u64 {
    app.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .ranges
        .bytes()
}

fn r2o_quic_http3_bounded_timeout_at(
    timeout: Duration,
    deadline: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> Duration {
    deadline.map_or(timeout, |deadline| {
        timeout.min(deadline.saturating_duration_since(now))
    })
}

fn r2o_quic_http3_bounded_timeout(
    timeout: Duration,
    deadline: Option<tokio::time::Instant>,
) -> Duration {
    r2o_quic_http3_bounded_timeout_at(timeout, deadline, tokio::time::Instant::now())
}

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

/// Создать новый raw-сокет QUIC, не используя порт из окна остаточной блокировки.
/// Ошибка SO_MARK сохраняется в `marked`, но, как в d2o, сама отправка продолжается.
pub fn r2o_quic_http3_udp_socket_fresh(
    server: SocketAddr,
    mark: Option<u32>,
) -> Result<(UdpSocket, bool), R2oQuicUdpSocketError> {
    let bind = SocketAddr::new(
        match server.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        0,
    );
    let mut held = Vec::new();
    for _ in 0..=R2O_QUIC_FRESH_PORT_TRIES {
        let socket = UdpSocket::bind(bind).map_err(R2oQuicUdpSocketError::ordinary)?;
        let mut marked = mark.is_none_or(|mark| mark == 0);
        if let Some(mark) = mark.filter(|mark| *mark != 0) {
            marked = match r2o_quic_http3_set_socket_mark(&socket, mark) {
                Ok(()) => true,
                Err(error) => {
                    eprintln!("QUIC SO_MARK {mark:#x} не установился: {error}");
                    false
                }
            };
        }
        socket
            .connect(server)
            .map_err(R2oQuicUdpSocketError::ordinary)?;
        let port = socket
            .local_addr()
            .map_err(R2oQuicUdpSocketError::ordinary)?
            .port();
        if port == 0 {
            return Err(R2oQuicUdpSocketError::ordinary(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "локальный UDP-порт не назначен",
            )));
        }
        if r2o_quic_port_was_recently_claimed(port) {
            if held.len() == R2O_QUIC_FRESH_PORT_TRIES {
                return Err(R2oQuicUdpSocketError::ordinary(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "не найден свежий локальный UDP-порт за 16 попыток",
                )));
            }
            held.push(socket);
            continue;
        }
        drop(held);
        return Ok((socket, marked));
    }
    Err(R2oQuicUdpSocketError::ordinary(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "не найден свежий локальный UDP-порт за 16 попыток",
    )))
}

/// C `qp_open_fresh` с явным `src_port`: bind на заданный локальный порт,
/// best-effort SO_MARK, connect. Свежий порт не подменяется — C в этом
/// режиме тоже уважает запрошенный порт или отказывает.
pub fn r2o_quic_http3_udp_socket_fresh_src_port(
    server: SocketAddr,
    mark: Option<u32>,
    src_port: u16,
) -> Result<(UdpSocket, bool), R2oQuicUdpSocketError> {
    if src_port == 0 {
        return r2o_quic_http3_udp_socket_fresh(server, mark);
    }
    let bind = SocketAddr::new(
        match server.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        src_port,
    );
    let socket = UdpSocket::bind(bind).map_err(R2oQuicUdpSocketError::ordinary)?;
    let mut marked = mark.is_none_or(|mark| mark == 0);
    if let Some(mark) = mark.filter(|mark| *mark != 0) {
        marked = match r2o_quic_http3_set_socket_mark(&socket, mark) {
            Ok(()) => true,
            Err(error) => {
                eprintln!("QUIC SO_MARK {mark:#x} не установился: {error}");
                false
            }
        };
    }
    socket
        .connect(server)
        .map_err(R2oQuicUdpSocketError::ordinary)?;
    Ok((socket, marked))
}

/// C `d2k_udp_port_forget_all`: сбросить реестр недавних UDP-портов.
pub fn r2o_quic_port_forget_all() {
    let Some(state) = R2O_QUIC_RECENT_PORTS_STATE.get() else {
        return;
    };
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.0.clear();
    state.1 = 0;
}

/// C `d2k_udp_port_claim` (`core/meas.c:313-339`) без fd: `-1` — порт 0,
/// `1` — порт уже занимали меньше 480 с назад, `0` — новый (записан).
pub fn r2o_quic_udp_port_claim(port: u16) -> i32 {
    if port == 0 {
        return -1;
    }
    i32::from(r2o_quic_port_was_recently_claimed(port))
}

/// C `udp_now_ms` (`core/meas.c:307-311`): `CLOCK_MONOTONIC` в целых мс.
pub(crate) fn r2o_udp_now_ms() -> i64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return 0;
    }
    i64::try_from(time.tv_sec)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000)
        .saturating_add(i64::try_from(time.tv_nsec).unwrap_or_default() / 1_000_000)
}

fn r2o_quic_port_was_recently_claimed(port: u16) -> bool {
    let state = R2O_QUIC_RECENT_PORTS_STATE
        .get_or_init(|| Mutex::new((VecDeque::with_capacity(R2O_QUIC_RECENT_PORTS), 0)));
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (ports, next) = &mut *state;
    let now = r2o_udp_now_ms();
    if ports.iter().any(|(recent_port, at)| {
        *recent_port == port && *at != 0 && now - *at < R2O_QUIC_RESIDUAL_PORT_MS
    }) {
        return true;
    }
    let entry = (port, if now != 0 { now } else { 1 });
    if ports.len() < R2O_QUIC_RECENT_PORTS {
        ports.push_back(entry);
    } else {
        ports[*next] = entry;
        *next = (*next + 1) % R2O_QUIC_RECENT_PORTS;
    }
    false
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
    if let Some(mark) = mark.filter(|mark| *mark != 0) {
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
pub fn r2o_quic_http3_set_socket_mark(socket: &UdpSocket, mark: u32) -> std::io::Result<()> {
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
pub fn r2o_quic_http3_set_socket_mark(_socket: &UdpSocket, _mark: u32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "метка SO_MARK поддерживается только в Linux",
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oQuicHttp3Result {
    pub local_refusal: bool,
    pub handshake_confirmed: bool,
    pub status: u16,
    pub body_bytes: u64,
    /// Уникальные байты целевого HTTP/3 bidi-потока, включая HEADERS и framing.
    pub app_bytes: u64,
    /// C `d2k_qc_app_progress`: уникальные байты ТЕКУЩЕГО потока.
    pub current_app_bytes: u64,
    pub complete: bool,
    pub requests: u32,
    pub datagrams: u64,
    pub budget_required: bool,
    pub budget_passed: bool,
    pub budget: R2oQuicBudgetOutcome,
    pub r2o_quic_stalled: bool,
    pub r2o_quic_one_way: bool,
    pub r2o_ping_probes: u32,
    pub r2o_ping_acks: u32,
    /// C `d2k_qc.peer_name`: -1 — не проверялось, 0 — имя не совпало, 1 — совпало.
    pub peer_name: i8,
    pub error: Option<String>,
}

impl Default for R2oQuicHttp3Result {
    fn default() -> Self {
        Self {
            local_refusal: false,
            handshake_confirmed: false,
            status: 0,
            body_bytes: 0,
            app_bytes: 0,
            current_app_bytes: 0,
            complete: false,
            requests: 0,
            datagrams: 0,
            budget_required: false,
            budget_passed: false,
            budget: R2oQuicBudgetOutcome::NotChecked,
            r2o_quic_stalled: false,
            r2o_quic_one_way: false,
            r2o_ping_probes: 0,
            r2o_ping_acks: 0,
            // C `d2k_qc_connect` инициализирует peer_name = -1.
            peer_name: -1,
            error: None,
        }
    }
}

impl R2oQuicHttp3Result {
    /// C `d2k_qc_peer_name`: результат сверки имени сертификата.
    pub fn d2k_qc_peer_name(&self) -> i8 {
        self.peer_name
    }
}

/// C `d2k_t13_cert_name_ok`: сверка имени листового сертификата.
/// `None` (C -1) — сертификат не разобран или SAN не найден.
pub fn r2o_quic_peer_name(der: &[u8], host: &str) -> i8 {
    match crate::response::https_certificate_name_matches(der, host) {
        Some(true) => 1,
        Some(false) => 0,
        None => -1,
    }
}

/// C `d2k_qc_connect` продолжает рукопожатие даже при чужом имени:
/// `peer_name` — наблюдение, а не условие допуска. Поэтому verifier
/// записывает результат и принимает сертификат.
#[derive(Debug)]
struct R2oQuicNameRecordingVerifier {
    host: String,
    result: Arc<Mutex<R2oQuicHttp3Result>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for R2oQuicNameRecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let value = r2o_quic_peer_name(end_entity.as_ref(), &self.host);
        self.result.lock().unwrap().peer_name = value;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct R2oQuicHttp3CountedConnection {
    inner: h3_quinn::Connection,
    connection: quinn::Connection,
    app_bytes: Arc<R2oQuicHttp3AppCounter>,
}

struct R2oQuicHttp3CountedOpenStreams {
    inner: h3_quinn::OpenStreams,
    connection: quinn::Connection,
    app_bytes: Arc<R2oQuicHttp3AppCounter>,
}

struct R2oQuicHttp3CountedRecvStream {
    inner: h3_quinn::RecvStream,
    app_bytes: Arc<R2oQuicHttp3AppCounter>,
    connection: Option<quinn::Connection>,
    stream_id: Option<quinn::StreamId>,
    last_seen: u64,
    count: bool,
}

struct R2oQuicHttp3CountedBidiStream {
    send: h3_quinn::SendStream<Bytes>,
    recv: R2oQuicHttp3CountedRecvStream,
}

fn r2o_quic_http3_app_bytes_load(app_bytes: &R2oQuicHttp3AppCounter) -> u64 {
    app_bytes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .total
}

impl h3::quic::RecvStream for R2oQuicHttp3CountedRecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, h3::quic::StreamErrorIncoming>> {
        let result = h3::quic::RecvStream::poll_data(&mut self.inner, cx);
        if self.count {
            let received = self
                .connection
                .as_ref()
                .zip(self.stream_id)
                .and_then(|(connection, stream_id)| connection.r2o_recv_stream_bytes(stream_id));
            if let Some(received) = received {
                let received = received.max(self.last_seen);
                if received > self.last_seen {
                    r2o_quic_http3_app_add(
                        &self.app_bytes,
                        self.last_seen,
                        received - self.last_seen,
                        false,
                    );
                    self.last_seen = received;
                }
            } else if let Poll::Ready(Ok(Some(bytes))) = &result {
                let received = self.last_seen.saturating_add(bytes.remaining() as u64);
                if received > self.last_seen {
                    r2o_quic_http3_app_add(
                        &self.app_bytes,
                        self.last_seen,
                        received - self.last_seen,
                        false,
                    );
                    self.last_seen = received;
                }
            }
            // Конец тела — это FIN потока: C `d2k_qw_ranges_add(off,0,fin)`
            // запоминает fin_off, не добавляя байт.
            if let Poll::Ready(Ok(None)) = &result {
                r2o_quic_http3_app_add(&self.app_bytes, self.last_seen, 0, true);
            }
        }
        result
    }

    fn stop_sending(&mut self, error_code: u64) {
        h3::quic::RecvStream::stop_sending(&mut self.inner, error_code);
    }

    fn recv_id(&self) -> h3::quic::StreamId {
        h3::quic::RecvStream::recv_id(&self.inner)
    }
}

impl R2oQuicHttp3CountedBidiStream {
    fn new(
        inner: h3_quinn::BidiStream<Bytes>,
        app_bytes: Arc<R2oQuicHttp3AppCounter>,
        count: bool,
        connection: quinn::Connection,
    ) -> Self {
        let stream_id = quinn::StreamId::from(
            quinn::VarInt::from_u64(h3::quic::RecvStream::recv_id(&inner).into_inner())
                .expect("HTTP/3 stream ID is a QUIC variable integer"),
        );
        let tracked = !count || connection.r2o_track_recv_stream_bytes(stream_id);
        debug_assert!(tracked, "opened HTTP/3 request stream must be tracked");
        if count && tracked {
            // C `d2k_qw_ranges_reset(&c->app_rx)` при новом клиентском потоке.
            r2o_quic_http3_app_reset(&app_bytes);
        }
        let (send, recv) = h3::quic::BidiStream::<Bytes>::split(inner);
        Self {
            send,
            recv: R2oQuicHttp3CountedRecvStream {
                inner: recv,
                app_bytes,
                connection: count.then_some(connection),
                stream_id: count.then_some(stream_id),
                last_seen: 0,
                count: count && tracked,
            },
        }
    }
}

impl h3::quic::RecvStream for R2oQuicHttp3CountedBidiStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, h3::quic::StreamErrorIncoming>> {
        h3::quic::RecvStream::poll_data(&mut self.recv, cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        h3::quic::RecvStream::stop_sending(&mut self.recv, error_code);
    }

    fn recv_id(&self) -> h3::quic::StreamId {
        h3::quic::RecvStream::recv_id(&self.recv)
    }
}

impl h3::quic::SendStream<Bytes> for R2oQuicHttp3CountedBidiStream {
    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        h3::quic::SendStream::poll_ready(&mut self.send, cx)
    }

    fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(
        &mut self,
        data: T,
    ) -> Result<(), h3::quic::StreamErrorIncoming> {
        h3::quic::SendStream::send_data(&mut self.send, data)
    }

    fn poll_finish(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        h3::quic::SendStream::poll_finish(&mut self.send, cx)
    }

    fn reset(&mut self, reset_code: u64) {
        h3::quic::SendStream::reset(&mut self.send, reset_code);
    }

    fn send_id(&self) -> h3::quic::StreamId {
        h3::quic::SendStream::send_id(&self.send)
    }
}

impl h3::quic::BidiStream<Bytes> for R2oQuicHttp3CountedBidiStream {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type RecvStream = R2oQuicHttp3CountedRecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl h3::quic::OpenStreams<Bytes> for R2oQuicHttp3CountedOpenStreams {
    type BidiStream = R2oQuicHttp3CountedBidiStream;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::StreamErrorIncoming>> {
        h3::quic::OpenStreams::poll_open_bidi(&mut self.inner, cx).map(|result| {
            result.map(|inner| {
                R2oQuicHttp3CountedBidiStream::new(
                    inner,
                    Arc::clone(&self.app_bytes),
                    true,
                    self.connection.clone(),
                )
            })
        })
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, h3::quic::StreamErrorIncoming>> {
        h3::quic::OpenStreams::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        h3::quic::OpenStreams::<Bytes>::close(&mut self.inner, code, reason);
    }
}

impl h3::quic::OpenStreams<Bytes> for R2oQuicHttp3CountedConnection {
    type BidiStream = R2oQuicHttp3CountedBidiStream;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::StreamErrorIncoming>> {
        h3::quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.inner, cx).map(|result| {
            result.map(|inner| {
                R2oQuicHttp3CountedBidiStream::new(
                    inner,
                    Arc::clone(&self.app_bytes),
                    true,
                    self.connection.clone(),
                )
            })
        })
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, h3::quic::StreamErrorIncoming>> {
        h3::quic::OpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        h3::quic::OpenStreams::<Bytes>::close(&mut self.inner, code, reason);
    }
}

impl h3::quic::Connection<Bytes> for R2oQuicHttp3CountedConnection {
    type RecvStream = R2oQuicHttp3CountedRecvStream;
    type OpenStreams = R2oQuicHttp3CountedOpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, h3::quic::ConnectionErrorIncoming>> {
        h3::quic::Connection::<Bytes>::poll_accept_recv(&mut self.inner, cx).map(|result| {
            result.map(|inner| R2oQuicHttp3CountedRecvStream {
                inner,
                app_bytes: Arc::clone(&self.app_bytes),
                connection: None,
                stream_id: None,
                last_seen: 0,
                count: false,
            })
        })
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::ConnectionErrorIncoming>> {
        h3::quic::Connection::<Bytes>::poll_accept_bidi(&mut self.inner, cx).map(|result| {
            result.map(|inner| {
                R2oQuicHttp3CountedBidiStream::new(
                    inner,
                    Arc::clone(&self.app_bytes),
                    false,
                    self.connection.clone(),
                )
            })
        })
    }

    fn opener(&self) -> Self::OpenStreams {
        R2oQuicHttp3CountedOpenStreams {
            inner: h3::quic::Connection::<Bytes>::opener(&self.inner),
            connection: self.connection.clone(),
            app_bytes: Arc::clone(&self.app_bytes),
        }
    }
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

/// Хранит порог пакетов и рост байтов целевого QUIC-потока для freshness
/// проверки `d2k_qbudget_ok`. Production budget_quic использует
/// `R2oQuicBudgetDriver`; этот helper оставлен только для unit-тестов.
#[cfg(test)]
struct R2oQuicHttp3Budget {
    need: u64,
    progress_mark: Option<u64>,
}

pub fn r2o_quic_http3_budget_datagrams(budget_packets: u32) -> u32 {
    let packets = if budget_packets == 0 {
        R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS
    } else {
        budget_packets
    };
    packets.wrapping_mul(2)
}

#[cfg(test)]
impl R2oQuicHttp3Budget {
    fn r2o_initialize(budget_packets: u32) -> Self {
        Self {
            need: u64::from(r2o_quic_http3_budget_datagrams(budget_packets)),
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

/// C `budget_quic`: итоговый бюджет и счётчики одного прогона.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum R2oQuicBudgetOutcome {
    #[default]
    NotChecked,
    Passed,
    Cut,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oQuicBudgetResult {
    pub budget: R2oQuicBudgetOutcome,
    pub need: u32,
    pub requests: u32,
    pub packets: u32,
    pub uncountable: bool,
}

/// Событие C `budget_quic` без IO: scripted-ответы mock `quic_budget_io`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oQuicBudgetEvent {
    Packets(i64),
    Progress {
        progress: u64,
        status: u16,
    },
    Complete {
        progress: u64,
        request_ok: bool,
    },
    Headers {
        closed: bool,
        status: i32,
        got: usize,
    },
    Recv {
        n: i64,
        progress_changed: bool,
        timed_out: bool,
    },
    Closed,
    Error,
    Silence,
}

/// Решение production-loop после события. `Request` — complete-ответ
/// требует новый поток (`sid + 4`), остальные — финальные/продолжение.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oQuicBudgetDecision {
    Continue,
    Passed,
    Cut,
    NotApplicable,
    Request,
}

/// Единый stateful-драйвер C `budget_quic`: каждое событие проходит здесь,
/// batch-функция ниже использует тот же драйвер.
#[derive(Clone, Debug)]
pub struct R2oQuicBudgetDriver {
    need: u32,
    requests: u32,
    packets: u32,
    uncountable: bool,
    budget: R2oQuicBudgetOutcome,
    marked: bool,
    progress_mark: u64,
    asked_at: Option<u64>,
    done: u64,
    current_packets: i64,
}

impl R2oQuicBudgetDriver {
    pub fn r2o_new(budget_packets: u32) -> Self {
        Self {
            need: r2o_quic_http3_budget_datagrams(budget_packets),
            requests: 1,
            packets: 0,
            uncountable: false,
            budget: R2oQuicBudgetOutcome::NotChecked,
            marked: false,
            progress_mark: 0,
            asked_at: None,
            done: 0,
            current_packets: 0,
        }
    }

    pub fn r2o_event(&mut self, event: R2oQuicBudgetEvent) -> R2oQuicBudgetDecision {
        match event {
            R2oQuicBudgetEvent::Packets(value) => {
                if value < 0 {
                    self.uncountable = true;
                    self.budget = R2oQuicBudgetOutcome::NotApplicable;
                    return R2oQuicBudgetDecision::NotApplicable;
                }
                self.current_packets = value;
                self.packets = value as u32;
                R2oQuicBudgetDecision::Continue
            }
            R2oQuicBudgetEvent::Progress { progress, status } => {
                let progress = self.done.saturating_add(progress);
                if self.current_packets >= 0 && self.current_packets as u64 >= u64::from(self.need)
                {
                    if !self.marked {
                        self.marked = true;
                        self.progress_mark = progress;
                    }
                    if status > 0 && progress > self.progress_mark {
                        self.budget = R2oQuicBudgetOutcome::Passed;
                        return R2oQuicBudgetDecision::Passed;
                    }
                }
                R2oQuicBudgetDecision::Continue
            }
            R2oQuicBudgetEvent::Complete {
                progress,
                request_ok,
            } => {
                let current = self.current_packets.max(0) as u64;
                if self.asked_at.is_some_and(|asked| current <= asked) {
                    self.budget = R2oQuicBudgetOutcome::NotApplicable;
                    return R2oQuicBudgetDecision::NotApplicable;
                }
                self.asked_at = Some(current);
                self.done = self.done.saturating_add(progress);
                self.requests = self.requests.saturating_add(1);
                if !request_ok {
                    self.budget = R2oQuicBudgetOutcome::NotApplicable;
                    return R2oQuicBudgetDecision::NotApplicable;
                }
                R2oQuicBudgetDecision::Request
            }
            R2oQuicBudgetEvent::Headers {
                closed,
                status,
                got,
            } => {
                if closed || (status == 0 && got > 0) {
                    self.budget = R2oQuicBudgetOutcome::NotApplicable;
                    return R2oQuicBudgetDecision::NotApplicable;
                }
                if status == 0 {
                    self.budget = R2oQuicBudgetOutcome::Cut;
                    return R2oQuicBudgetDecision::Cut;
                }
                R2oQuicBudgetDecision::Continue
            }
            R2oQuicBudgetEvent::Recv {
                n,
                progress_changed,
                timed_out,
            } => {
                if n < 0 {
                    self.budget = R2oQuicBudgetOutcome::NotApplicable;
                    return R2oQuicBudgetDecision::NotApplicable;
                }
                if !progress_changed && timed_out {
                    self.budget = R2oQuicBudgetOutcome::Cut;
                    return R2oQuicBudgetDecision::Cut;
                }
                R2oQuicBudgetDecision::Continue
            }
            R2oQuicBudgetEvent::Closed | R2oQuicBudgetEvent::Error => {
                self.budget = R2oQuicBudgetOutcome::NotApplicable;
                R2oQuicBudgetDecision::NotApplicable
            }
            R2oQuicBudgetEvent::Silence => {
                self.budget = R2oQuicBudgetOutcome::Cut;
                R2oQuicBudgetDecision::Cut
            }
        }
    }

    pub fn r2o_result(&self) -> R2oQuicBudgetResult {
        R2oQuicBudgetResult {
            budget: self.budget,
            need: self.need,
            requests: self.requests,
            packets: self.packets,
            uncountable: self.uncountable,
        }
    }
}

/// Production-порт C `budget_quic` без IO: те же порог, рост, новый поток,
/// HEADERS и молчание. Batch-путь использует единый R2oQuicBudgetDriver.
pub fn r2o_quic_budget_from_events(
    budget_packets: u32,
    events: &[R2oQuicBudgetEvent],
) -> R2oQuicBudgetResult {
    let mut driver = R2oQuicBudgetDriver::r2o_new(budget_packets);
    for event in events {
        if matches!(
            driver.r2o_event(*event),
            R2oQuicBudgetDecision::Passed
                | R2oQuicBudgetDecision::Cut
                | R2oQuicBudgetDecision::NotApplicable
        ) {
            break;
        }
    }
    driver.r2o_result()
}

/// Production-loop: Packets и Progress всегда идут парой через драйвер.
fn r2o_quic_budget_observe(
    driver: &mut R2oQuicBudgetDriver,
    result: &mut R2oQuicHttp3Result,
    packets: u64,
    progress: u64,
    status: u16,
) -> R2oQuicBudgetDecision {
    match r2o_quic_budget_apply_event(driver, result, R2oQuicBudgetEvent::Packets(packets as i64)) {
        R2oQuicBudgetDecision::Continue => {}
        decision => return decision,
    }
    r2o_quic_budget_apply_event(
        driver,
        result,
        R2oQuicBudgetEvent::Progress {
            progress,
            status: if status == 0 { 200 } else { status },
        },
    )
}

/// Единая точка production-loop: событие → драйвер → поля
/// `R2oQuicHttp3Result.budget/budget_passed`.
fn r2o_quic_budget_apply_event(
    driver: &mut R2oQuicBudgetDriver,
    result: &mut R2oQuicHttp3Result,
    event: R2oQuicBudgetEvent,
) -> R2oQuicBudgetDecision {
    let decision = driver.r2o_event(event);
    let budget = driver.r2o_result();
    result.budget = budget.budget;
    result.budget_passed = budget.budget == R2oQuicBudgetOutcome::Passed;
    decision
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

/// Измерить HTTP/3-ответ в пределах оставшегося срока задачи.
pub async fn r2o_quic_http3_measure_with_max_duration(
    socket: UdpSocket,
    server: SocketAddr,
    server_name: &str,
    path: &str,
    timeout: Duration,
    roots: RootCertStore,
    budget_packets: u32,
    max_duration: Duration,
) -> R2oQuicHttp3Result {
    r2o_quic_http3_measure_with_wire_len_and_max_duration(
        socket,
        server,
        server_name,
        path,
        timeout,
        roots,
        budget_packets,
        None,
        Some(max_duration),
        false,
    )
    .await
}

/// Выполнить один HTTP/3 GET в пределах оставшегося срока задачи.
pub async fn r2o_quic_http3_get_with_max_duration(
    socket: UdpSocket,
    server: SocketAddr,
    server_name: &str,
    path: &str,
    timeout: Duration,
    roots: RootCertStore,
    max_duration: Duration,
) -> R2oQuicHttp3Result {
    r2o_quic_http3_measure_with_max_duration(
        socket,
        server,
        server_name,
        path,
        timeout,
        roots,
        0,
        max_duration,
    )
    .await
}

/// Выполнить короткий контрольный GET с бюджетом коробки, не повторяя запрос.
pub async fn r2o_quic_http3_short_control_get_with_max_duration(
    socket: UdpSocket,
    server: SocketAddr,
    server_name: &str,
    path: &str,
    timeout: Duration,
    roots: RootCertStore,
    max_duration: Duration,
) -> R2oQuicHttp3Result {
    r2o_quic_http3_measure_with_wire_len_and_max_duration(
        socket,
        server,
        server_name,
        path,
        timeout,
        roots,
        0,
        None,
        Some(max_duration),
        true,
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
    r2o_quic_http3_measure_with_wire_len_and_max_duration(
        socket,
        server,
        server_name,
        path,
        timeout,
        roots,
        budget_packets,
        wire_len,
        None,
        false,
    )
    .await
}

async fn r2o_quic_http3_measure_with_wire_len_and_max_duration(
    socket: UdpSocket,
    server: SocketAddr,
    server_name: &str,
    path: &str,
    timeout: Duration,
    roots: RootCertStore,
    budget_packets: u32,
    wire_len: Option<usize>,
    max_duration: Option<Duration>,
    track_one_shot_budget: bool,
) -> R2oQuicHttp3Result {
    let deadline = max_duration.map(|duration| tokio::time::Instant::now() + duration);
    let repeated = budget_packets > 0;
    let budget_active = repeated || track_one_shot_budget;
    let result = Arc::new(Mutex::new(R2oQuicHttp3Result {
        budget_required: repeated,
        ..R2oQuicHttp3Result::default()
    }));
    if server.port() == 0
        || timeout.is_zero()
        || max_duration.is_some_and(|duration| duration.is_zero())
    {
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

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(R2oQuicNameRecordingVerifier {
        host: server_name.to_owned(),
        result: Arc::clone(&result),
        provider: Arc::clone(&provider),
    });
    let builder = match rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
    {
        Ok(builder) => builder,
        Err(error) => {
            result.lock().unwrap().error = Some(format!("не настроены версии QUIC TLS: {error}"));
            return result.lock().unwrap().clone();
        }
    };
    let mut tls = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // C `d2k_qc_connect` не рвёт рукопожатие при чужом имени сертификата:
    // webpki-цепочка здесь не проверяется, `peer_name` — наблюдение зонда.
    let _ = roots;
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
    let transport = match r2o_quic_transport_config() {
        Ok(transport) => transport,
        Err(error) => {
            result.lock().unwrap().error = Some(error);
            return result.lock().unwrap().clone();
        }
    };
    let endpoint_config = match r2o_quic_endpoint_config() {
        Ok(config) => config,
        Err(error) => {
            result.lock().unwrap().error = Some(error);
            return result.lock().unwrap().clone();
        }
    };
    let mut endpoint = match quinn::Endpoint::new(endpoint_config, None, socket, runtime) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            result.lock().unwrap().error = Some(format!("не создан QUIC endpoint: {error}"));
            return result.lock().unwrap().clone();
        }
    };
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_config);

    let connecting = match endpoint.connect(server, server_name) {
        Ok(connecting) => connecting,
        Err(error) => {
            result.lock().unwrap().error = Some(format!("не начато QUIC-рукопожатие: {error}"));
            return result.lock().unwrap().clone();
        }
    };
    let connection_timeout = r2o_quic_http3_bounded_timeout(timeout, deadline);
    let connection = match tokio::time::timeout(connection_timeout, connecting).await {
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

    let app_bytes = Arc::new(Mutex::new(R2oQuicHttp3AppState::default()));
    let h3_connection = R2oQuicHttp3CountedConnection {
        inner: h3_quinn::Connection::new(connection.clone()),
        connection: connection.clone(),
        app_bytes: Arc::clone(&app_bytes),
    };
    let mut h3_client = h3::client::builder();
    h3_client.max_field_section_size(R2O_QUIC_HTTP3_HEADER_LIMIT);
    let (mut driver, mut send_request) = match tokio::time::timeout(
        r2o_quic_http3_bounded_timeout(timeout, deadline),
        h3_client.build(h3_connection),
    )
    .await
    {
        Ok(Ok(client)) => client,
        Ok(Err(error)) => {
            result.lock().unwrap().error = Some(format!("не запущен HTTP/3-клиент: {error}"));
            return result.lock().unwrap().clone();
        }
        Err(_) => {
            let mut state = result.lock().unwrap();
            state.error = Some("истёк срок настройки HTTP/3".into());
            // D2O counts the first GET attempt after QUIC connects even when
            // H3 setup cannot obtain its control stream; keep Quinn's stream limit.
            if connection.close_reason().is_none() {
                state.requests = 1;
            }
            return state.clone();
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
    let mut last_complete_response_app_bytes = 0_u64;
    let mut failed_repeat_app_bytes = 0_u64;
    let mut last_progress_at = tokio::time::Instant::now();
    let mut last_app_progress = r2o_quic_http3_app_bytes_load(&app_bytes);
    // A one-shot default-budget check is reserved for the short-control probe.
    let mut budget_driver = R2oQuicBudgetDriver::r2o_new(budget_packets);
    let mut stall = R2oQuicHttp3Stall::r2o_initialize(
        connection.rtt(),
        last_app_progress,
        r2o_quic_http3_wire_bytes(&connection),
    );
    let mut stall_end = None;

    loop {
        let request_timeout = r2o_quic_http3_bounded_timeout(request_timeout, deadline);
        if request_timeout.is_zero() {
            result.lock().unwrap().error = Some("истёк срок HTTP/3-пробы для задачи".into());
            break;
        }
        if budget_active && requests > 0 {
            let packets = r2o_quic_http3_datagrams(&connection).saturating_sub(datagrams_before);
            let progress = r2o_quic_http3_app_bytes_load(&app_bytes);
            let decision = {
                let mut state = result.lock().unwrap();
                r2o_quic_budget_observe(&mut budget_driver, &mut state, packets, progress, status)
            };
            match decision {
                R2oQuicBudgetDecision::Passed => break,
                R2oQuicBudgetDecision::Cut => {
                    result.lock().unwrap().error =
                        Some("сервер замолчал посреди повторов HTTP/3".into());
                    break;
                }
                R2oQuicBudgetDecision::NotApplicable => {
                    result.lock().unwrap().error =
                        Some("счётчик датаграмм не растёт — бюджет не проверен".into());
                    break;
                }
                R2oQuicBudgetDecision::Continue | R2oQuicBudgetDecision::Request => {}
            }
        }
        let requests_before_attempt = requests;
        let request_app_bytes_start = r2o_quic_http3_app_bytes_load(&app_bytes);
        let request_result = tokio::time::timeout(request_timeout, async {
            status = 0;
            result.lock().unwrap().status = status;
            let request = http::Request::builder()
                .method(http::Method::GET)
                .uri(uri.clone())
                .body(())
                .map_err(|error| format!("не построен HTTP/3 GET: {error}"))?;
            let first_request = requests == 0;
            let connection_open_before_send = connection.close_reason().is_none();
            if first_request && connection_open_before_send {
                requests = requests.saturating_add(1);
                result.lock().unwrap().requests = requests;
            }
            let mut stream = match send_request.send_request(request).await {
                Ok(stream) => stream,
                Err(error) => {
                    if !first_request && connection_open_before_send {
                        requests = requests.saturating_add(1);
                        result.lock().unwrap().requests = requests;
                    }
                    return Err(format!("HTTP/3 GET не отправлен: {error}"));
                }
            };
            stream
                .finish()
                .await
                .map_err(|error| format!("HTTP/3 GET не завершён: {error}"))?;
            if !first_request && connection_open_before_send {
                requests = requests.saturating_add(1);
                result.lock().unwrap().requests = requests;
            }
            if first_request {
                datagrams_before = r2o_quic_http3_datagrams(&connection);
            }

            loop {
                let response_status = r2o_quic_http3_wait_with_stall(
                    &connection,
                    &mut stall,
                    &app_bytes,
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
                            "QUIC-сервер продолжает передачу, но не подтверждает наши пакеты"
                                .to_owned()
                        }
                    }
                })?
                .map_err(|error| format!("заголовки HTTP/3-ответа не получены: {error}"))?
                .status()
                .as_u16();
                if status == 0 {
                    status = response_status;
                    result.lock().unwrap().status = status;
                }
                if status == 451 {
                    return Ok::<bool, String>(false);
                }
                if budget_active {
                    let decision = {
                        let mut state = result.lock().unwrap();
                        r2o_quic_budget_apply_event(
                            &mut budget_driver,
                            &mut state,
                            R2oQuicBudgetEvent::Headers {
                                closed: false,
                                status: response_status as i32,
                                got: 1,
                            },
                        )
                    };
                    match decision {
                        R2oQuicBudgetDecision::Cut => {
                            return Err("сервер замолчал на HEADERS HTTP/3".to_owned());
                        }
                        R2oQuicBudgetDecision::NotApplicable => {
                            return Err(
                                "HEADERS HTTP/3 не разобран — бюджет не проверен".to_owned()
                            );
                        }
                        _ => {}
                    }
                }
                let app_progress = r2o_quic_http3_app_bytes_load(&app_bytes);
                let now = tokio::time::Instant::now();
                if app_progress > last_app_progress {
                    last_app_progress = app_progress;
                    last_progress_at = now;
                }
                if budget_active {
                    let packets =
                        r2o_quic_http3_datagrams(&connection).saturating_sub(datagrams_before);
                    let decision = {
                        let mut state = result.lock().unwrap();
                        r2o_quic_budget_observe(
                            &mut budget_driver,
                            &mut state,
                            packets,
                            app_progress,
                            status,
                        )
                    };
                    match decision {
                        R2oQuicBudgetDecision::Passed => return Ok::<bool, String>(false),
                        R2oQuicBudgetDecision::Cut => {
                            return Err("сервер замолчал посреди повторов HTTP/3".to_owned());
                        }
                        R2oQuicBudgetDecision::NotApplicable => {
                            return Err(
                                "датаграммы HTTP/3 не считаются — бюджет не проверен".to_owned()
                            );
                        }
                        _ => {}
                    }
                }
                if response_status == 101 || !(100..200).contains(&response_status) {
                    break;
                }
            }
            loop {
                let received = r2o_quic_http3_wait_with_stall(
                    &connection,
                    &mut stall,
                    &app_bytes,
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
                        total_body_bytes = total_body_bytes.saturating_add(length);

                        let now = tokio::time::Instant::now();
                        let app_progress = r2o_quic_http3_app_bytes_load(&app_bytes);
                        let packets =
                            r2o_quic_http3_datagrams(&connection).saturating_sub(datagrams_before);
                        if app_progress > last_app_progress {
                            last_app_progress = app_progress;
                            last_progress_at = now;
                        }
                        if budget_active {
                            let decision = {
                                let mut state = result.lock().unwrap();
                                r2o_quic_budget_observe(
                                    &mut budget_driver,
                                    &mut state,
                                    packets,
                                    app_progress,
                                    status,
                                )
                            };
                            match decision {
                                R2oQuicBudgetDecision::Passed => {
                                    let mut state = result.lock().unwrap();
                                    state.body_bytes = total_body_bytes;
                                    state.app_bytes = app_progress;
                                    state.current_app_bytes =
                                        r2o_quic_http3_app_current_bytes(&app_bytes);
                                    state.datagrams = packets;
                                    return Ok(false);
                                }
                                R2oQuicBudgetDecision::Cut => {
                                    return Err("сервер замолчал посреди тела HTTP/3".to_owned());
                                }
                                R2oQuicBudgetDecision::NotApplicable => {
                                    return Err(
                                        "счётчик датаграмм HTTP/3 не растёт — бюджет не проверен"
                                            .to_owned(),
                                    );
                                }
                                _ => {}
                            }
                        }
                        let mut state = result.lock().unwrap();
                        state.body_bytes = total_body_bytes;
                        state.app_bytes = app_progress;
                        state.current_app_bytes = r2o_quic_http3_app_current_bytes(&app_bytes);
                        state.datagrams = packets;
                        state.budget_passed =
                            budget_driver.r2o_result().budget == R2oQuicBudgetOutcome::Passed;
                    }
                    Ok(None) => {
                        if stream
                            .recv_trailers()
                            .await
                            .map_err(|error| format!("ошибка чтения HTTP/3 trailers: {error}"))?
                            .is_some()
                        {
                            continue;
                        }
                        let now = tokio::time::Instant::now();
                        let app_progress = r2o_quic_http3_app_bytes_load(&app_bytes);
                        if app_progress > last_app_progress {
                            last_app_progress = app_progress;
                            last_progress_at = now;
                        }
                        if budget_active {
                            let packets = r2o_quic_http3_datagrams(&connection)
                                .saturating_sub(datagrams_before);
                            let decision = {
                                let mut state = result.lock().unwrap();
                                r2o_quic_budget_observe(
                                    &mut budget_driver,
                                    &mut state,
                                    packets,
                                    app_progress,
                                    status,
                                )
                            };
                            match decision {
                                R2oQuicBudgetDecision::Passed => {
                                    let mut state = result.lock().unwrap();
                                    state.body_bytes = total_body_bytes;
                                    state.app_bytes = app_progress;
                                    state.current_app_bytes =
                                        r2o_quic_http3_app_current_bytes(&app_bytes);
                                    state.datagrams = packets;
                                    return Ok(false);
                                }
                                R2oQuicBudgetDecision::Cut => {
                                    return Err(
                                        "сервер замолчал на завершении тела HTTP/3".to_owned()
                                    );
                                }
                                R2oQuicBudgetDecision::NotApplicable => {
                                    return Err(
                                        "счётчик датаграмм HTTP/3 не растёт — бюджет не проверен"
                                            .to_owned(),
                                    );
                                }
                                _ => {}
                            }
                            let decision = {
                                let mut state = result.lock().unwrap();
                                r2o_quic_budget_apply_event(
                                    &mut budget_driver,
                                    &mut state,
                                    R2oQuicBudgetEvent::Complete {
                                        progress: 0,
                                        request_ok: true,
                                    },
                                )
                            };
                            match decision {
                                R2oQuicBudgetDecision::Request => {}
                                R2oQuicBudgetDecision::NotApplicable => {
                                    return Err(
                                        "счётчик датаграмм HTTP/3 не растёт — бюджет не проверен"
                                            .to_owned(),
                                    );
                                }
                                R2oQuicBudgetDecision::Cut => {
                                    return Err("сервер замолчал на новом потоке HTTP/3".to_owned());
                                }
                                _ => {}
                            }
                        }
                        return Ok(true);
                    }
                    Err(error) => return Err(format!("ошибка чтения HTTP/3-тела: {error}")),
                }
            }
        })
        .await;

        match request_result {
            Ok(Ok(complete)) => {
                last_response_complete = complete;
                if complete {
                    last_complete_response_app_bytes = r2o_quic_http3_app_bytes_load(&app_bytes)
                        .saturating_sub(request_app_bytes_start);
                }
            }
            Ok(Err(error)) => {
                if repeated && last_response_complete && requests == requests_before_attempt {
                    failed_repeat_app_bytes = last_complete_response_app_bytes;
                }
                if repeated
                    && budget_active
                    && budget_driver.r2o_result().budget == R2oQuicBudgetOutcome::NotChecked
                {
                    let event = if connection.close_reason().is_some() {
                        R2oQuicBudgetEvent::Closed
                    } else {
                        R2oQuicBudgetEvent::Error
                    };
                    let mut state = result.lock().unwrap();
                    r2o_quic_budget_apply_event(&mut budget_driver, &mut state, event);
                }
                let mut state = result.lock().unwrap();
                state.error = Some(error);
                if let Some(end) = stall_end {
                    state.r2o_quic_stalled = true;
                    state.r2o_quic_one_way = end == R2oQuicHttp3StallEnd::OneWay;
                }
                break;
            }
            Err(_) => {
                if repeated && last_response_complete && requests == requests_before_attempt {
                    failed_repeat_app_bytes = last_complete_response_app_bytes;
                }
                if repeated
                    && budget_active
                    && budget_driver.r2o_result().budget == R2oQuicBudgetOutcome::NotChecked
                {
                    let mut state = result.lock().unwrap();
                    r2o_quic_budget_apply_event(
                        &mut budget_driver,
                        &mut state,
                        R2oQuicBudgetEvent::Silence,
                    );
                }
                result.lock().unwrap().error = Some("истёк срок HTTP/3 GET".into());
                break;
            }
        }

        if !repeated
            || budget_driver.r2o_result().budget == R2oQuicBudgetOutcome::Passed
            || status == 451
            || !last_response_complete
        {
            break;
        }
    }

    let datagrams = r2o_quic_http3_datagrams(&connection).saturating_sub(datagrams_before);
    stall.r2o_capture_ack(connection.r2o_largest_acked_packet_number());
    let budget_result = budget_driver.r2o_result();
    let budget_passed = budget_result.budget == R2oQuicBudgetOutcome::Passed;
    let app_complete = r2o_quic_http3_app_complete(&app_bytes);
    {
        let mut state = result.lock().unwrap();
        state.requests = requests;
        state.app_bytes =
            r2o_quic_http3_app_bytes_load(&app_bytes).saturating_add(failed_repeat_app_bytes);
        state.current_app_bytes = r2o_quic_http3_app_current_bytes(&app_bytes);
        state.datagrams = datagrams;
        state.budget_passed = budget_passed;
        state.budget = budget_result.budget;
        state.complete =
            !repeated && last_response_complete && app_complete && !state.r2o_quic_stalled;
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
    r2o_quic_datagrams_sum(stats.udp_tx.datagrams, stats.udp_rx.datagrams)
}

/// C `d2k_qbudget_grew` (`core/include/d2k_quicprobe.h:637-639`): при
/// `pkts>=need` отметить прогресс, затем `status>0 && progress>mark`;
/// свежесть при `now=last=0, rto=1` всегда истинна.
#[cfg(test)]
fn r2o_quic_budget_grew(
    packets: u32,
    need: u32,
    status: u16,
    progress: u64,
    progress_mark: &mut Option<u64>,
) -> bool {
    if packets >= need && progress_mark.is_none() {
        *progress_mark = Some(progress);
    }
    status > 0 && progress_mark.is_some_and(|mark| progress > mark)
}

/// C `d2k_qc_datagrams` (`core/quicconn.c:1432-1435`): сумма tx+rx.
fn r2o_quic_datagrams_sum(tx: u64, rx: u64) -> u64 {
    tx.saturating_add(rx)
}

fn r2o_quic_http3_wire_bytes(connection: &quinn::Connection) -> u64 {
    connection.stats().udp_rx.bytes
}

async fn r2o_quic_http3_wait_with_stall<F: Future>(
    connection: &quinn::Connection,
    stall: &mut R2oQuicHttp3Stall,
    app_bytes: &R2oQuicHttp3AppCounter,
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
                let progress = r2o_quic_http3_app_bytes_load(app_bytes);
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
        R2O_QUIC_TP_IDLE_MS, R2O_QUIC_TP_INITIAL_MAX_DATA, R2O_QUIC_TP_MAX_UDP_PAYLOAD,
        R2O_QUIC_TP_STREAM_WINDOW, R2O_QUIC_TP_STREAMS, R2oQuicHttp3AppState, R2oQuicHttp3Budget,
        R2oQuicHttp3Stall, R2oQuicHttp3StallAction as Action, r2o_quic_endpoint_config,
        r2o_quic_http3_app_add, r2o_quic_http3_app_bytes_load, r2o_quic_http3_app_complete,
        r2o_quic_http3_app_current_bytes, r2o_quic_http3_app_reset, r2o_quic_http3_authority,
        r2o_quic_http3_bounded_timeout_at, r2o_quic_http3_udp_socket_with_mark_setter,
        r2o_quic_transport_config,
    };
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::time::Instant;

    /// C/Rust differential: `d2k_qc_app_progress` — байты и complete
    /// ТЕКУЩЕГО потока после reset, при сохранении кумулятивного total.
    #[test]
    fn qc_app_progress_matches_c() {
        let Some(path) = std::env::var_os("R2O_QC_APP_PROGRESS_OUTPUT") else {
            return;
        };
        let app = Mutex::new(R2oQuicHttp3AppState::default());
        let mut output = String::new();
        let mut report = |label: &str| {
            output.push_str(&format!(
                "{label},{},{}\n",
                r2o_quic_http3_app_current_bytes(&app),
                u8::from(r2o_quic_http3_app_complete(&app))
            ));
        };

        r2o_quic_http3_app_add(&app, 0, 4, false);
        r2o_quic_http3_app_add(&app, 2, 8, false);
        r2o_quic_http3_app_add(&app, 0, 10, true);
        report("stream1");

        r2o_quic_http3_app_reset(&app);
        r2o_quic_http3_app_add(&app, 1000, 2000, true);
        r2o_quic_http3_app_add(&app, 0, 1000, false);
        report("stream2");

        r2o_quic_http3_app_reset(&app);
        r2o_quic_http3_app_add(&app, 0, 1000, false);
        r2o_quic_http3_app_add(&app, 2000, 1000, true);
        report("stream3");

        r2o_quic_http3_app_reset(&app);
        r2o_quic_http3_app_add(&app, 0, 0, true);
        report("stream4");

        r2o_quic_http3_app_reset(&app);
        r2o_quic_http3_app_add(&app, 0, 100, false);
        r2o_quic_http3_app_add(&app, 100, 0, true);
        report("stream5");

        r2o_quic_http3_app_reset(&app);
        report("stream6");

        assert_eq!(r2o_quic_http3_app_bytes_load(&app), 5110);
        std::fs::write(path, &output).unwrap();
        print!("{output}");
    }

    #[test]
    fn udp_now_ms_совпадает_с_clock_monotonic() {
        let before = super::r2o_udp_now_ms();
        assert!(before > 0, "CLOCK_MONOTONIC не вернул время");
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) },
            0
        );
        let direct = time.tv_sec * 1000 + time.tv_nsec / 1_000_000;
        assert!(
            (direct - before).abs() < 1_000,
            "udp_now_ms={before}, clock_gettime={direct}"
        );
        assert!(super::r2o_udp_now_ms() >= before);
    }

    #[test]
    fn udp_port_claim_maps_zero_and_recent_ports_like_c() {
        assert_eq!(super::r2o_quic_udp_port_claim(0), -1);
        assert_eq!(super::r2o_quic_udp_port_claim(38_990), 0);
        assert_eq!(super::r2o_quic_udp_port_claim(38_990), 1);
    }

    #[test]
    fn quic_transport_parameters_match_c_tp_build() {
        // C `tp_build` (`core/quicconn.c:380-403`).
        assert_eq!(R2O_QUIC_TP_IDLE_MS, 30_000);
        assert_eq!(R2O_QUIC_TP_MAX_UDP_PAYLOAD, 1452);
        assert_eq!(R2O_QUIC_TP_INITIAL_MAX_DATA, 1024 * 1024);
        assert_eq!(R2O_QUIC_TP_STREAM_WINDOW, 256 * 1024);
        assert_eq!(R2O_QUIC_TP_STREAMS, 16);
        let endpoint = r2o_quic_endpoint_config().expect("endpoint config");
        assert_eq!(
            endpoint.get_max_udp_payload_size(),
            u64::from(R2O_QUIC_TP_MAX_UDP_PAYLOAD)
        );
        let _transport = r2o_quic_transport_config().expect("transport config");
    }

    #[test]
    fn http3_app_ranges_match_d2o_unique_range_totals() {
        let app_bytes = Mutex::new(R2oQuicHttp3AppState::default());
        r2o_quic_http3_app_add(&app_bytes, 0, 4, false);
        assert_eq!(r2o_quic_http3_app_bytes_load(&app_bytes), 4);
        assert!(!r2o_quic_http3_app_complete(&app_bytes));
        r2o_quic_http3_app_add(&app_bytes, 2, 8, false);
        assert_eq!(r2o_quic_http3_app_bytes_load(&app_bytes), 10);
        r2o_quic_http3_app_add(&app_bytes, 0, 10, true);
        assert_eq!(r2o_quic_http3_app_bytes_load(&app_bytes), 10);
        assert!(r2o_quic_http3_app_complete(&app_bytes));
        r2o_quic_http3_app_add(&app_bytes, 10, 5, true);
        assert_eq!(r2o_quic_http3_app_bytes_load(&app_bytes), 15);
        assert!(r2o_quic_http3_app_complete(&app_bytes));
        // Новый клиентский поток: C `d2k_qw_ranges_reset`, сумма прежних
        // потоков остаётся в total.
        r2o_quic_http3_app_reset(&app_bytes);
        assert_eq!(r2o_quic_http3_app_bytes_load(&app_bytes), 15);
        assert!(!r2o_quic_http3_app_complete(&app_bytes));
        r2o_quic_http3_app_add(&app_bytes, 0, 3, true);
        assert_eq!(r2o_quic_http3_app_bytes_load(&app_bytes), 18);
        assert!(r2o_quic_http3_app_complete(&app_bytes));
    }

    #[test]
    fn http3_app_byte_total_saturates_at_u64_max() {
        let mut state = R2oQuicHttp3AppState::default();
        state.total = u64::MAX - 1;
        let app_bytes = Mutex::new(state);
        r2o_quic_http3_app_add(&app_bytes, 0, 3, false);
        assert_eq!(r2o_quic_http3_app_bytes_load(&app_bytes), u64::MAX);
    }

    #[test]
    fn http3_timeout_is_capped_by_the_task_deadline() {
        let now = Instant::now();
        assert_eq!(
            r2o_quic_http3_bounded_timeout_at(
                Duration::from_secs(10),
                Some(now + Duration::from_secs(2)),
                now,
            ),
            Duration::from_secs(2)
        );
        assert_eq!(
            r2o_quic_http3_bounded_timeout_at(Duration::from_secs(10), None, now),
            Duration::from_secs(10)
        );
        assert_eq!(
            r2o_quic_http3_bounded_timeout_at(Duration::from_secs(10), Some(now), now),
            Duration::ZERO
        );
    }

    #[test]
    fn нулевая_quic_метка_не_устанавливается() {
        let mut set_mark_called = false;
        let socket = r2o_quic_http3_udp_socket_with_mark_setter(
            "127.0.0.1:443".parse().unwrap(),
            Some(0),
            |_, _| {
                set_mark_called = true;
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "нулевая метка не должна устанавливаться",
                ))
            },
        );

        assert!(!set_mark_called);
        assert!(socket.is_ok());
    }

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
    fn r2o_quic_ping_ack_учитывается_при_одновременном_росте_потока() {
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
    fn d2o_quic_budget_growth_differential_matches_c() {
        let mut output = String::new();
        for budget in [0u32, 1, 25, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
            output.push_str(&format!(
                "need|{budget}|{}\n",
                R2oQuicHttp3Budget::r2o_initialize(budget).need
            ));
        }
        fn run(name: &str, budget: u32, steps: &[(u64, u64, u16)], output: &mut String) {
            let mut state = R2oQuicHttp3Budget::r2o_initialize(budget);
            output.push_str(&format!("budget|{name}|need={}\n", state.need));
            let now = tokio::time::Instant::now();
            for (index, (packets, progress, status)) in steps.iter().enumerate() {
                let grew = state.r2o_step(
                    *packets,
                    *progress,
                    *status,
                    now,
                    now,
                    Duration::from_secs(1),
                );
                output.push_str(&format!("grew|{name}|{index}|{}\n", u8::from(grew)));
            }
        }
        run(
            "grow",
            1,
            &[
                (1, 100, 200),
                (2, 100, 200),
                (2, 100, 200),
                (2, 120, 200),
                (2, 130, 0),
            ],
            &mut output,
        );
        run(
            "status",
            1,
            &[(2, 100, 200), (3, 100, 0), (3, 101, 200)],
            &mut output,
        );
        run("double", 2, &[(4, 50, 200), (5, 60, 200)], &mut output);
        if let Ok(path) = std::env::var("R2O_QUIC_BUDGET_DIFF_OUTPUT") {
            std::fs::write(path, &output).expect("write QUIC budget output");
        }
        assert!(output.contains("budget|grow|need=2\n"));
    }

    #[test]
    fn d2o_quic_budget_io_oracle_differential_matches_c() {
        use super::{
            R2oQuicBudgetEvent as Event, R2oQuicBudgetOutcome as Outcome,
            r2o_quic_budget_from_events,
        };

        fn emit(name: &str, budget: u32, events: &[Event], output: &mut String) {
            let result = r2o_quic_budget_from_events(budget, events);
            let value = match result.budget {
                Outcome::NotChecked => 0,
                Outcome::Passed => 1,
                Outcome::Cut => 2,
                Outcome::NotApplicable => 3,
            };
            output.push_str(&format!(
                "quic|{name}|budget={value}|need={}|requests={}|packets={}|uncountable={}|reason=\n",
                result.need, result.requests, result.packets, u8::from(result.uncountable)
            ));
        }

        let mut output = String::new();
        emit("packets-negative", 1, &[Event::Packets(-1)], &mut output);
        emit(
            "grew",
            3,
            &[
                Event::Packets(6),
                Event::Progress {
                    progress: 100,
                    status: 200,
                },
                Event::Recv {
                    n: 1,
                    progress_changed: true,
                    timed_out: false,
                },
                Event::Packets(6),
                Event::Progress {
                    progress: 120,
                    status: 200,
                },
            ],
            &mut output,
        );
        emit(
            "request-error",
            2,
            &[
                Event::Packets(0),
                Event::Progress {
                    progress: 0,
                    status: 200,
                },
                Event::Complete {
                    progress: 0,
                    request_ok: false,
                },
            ],
            &mut output,
        );
        emit(
            "silence",
            1,
            &[
                Event::Packets(0),
                Event::Progress {
                    progress: 0,
                    status: 200,
                },
                Event::Recv {
                    n: 0,
                    progress_changed: false,
                    timed_out: true,
                },
            ],
            &mut output,
        );
        emit(
            "recv-error",
            1,
            &[
                Event::Packets(0),
                Event::Progress {
                    progress: 0,
                    status: 200,
                },
                Event::Recv {
                    n: -1,
                    progress_changed: false,
                    timed_out: false,
                },
            ],
            &mut output,
        );
        emit(
            "complete-headers-pass",
            1,
            &[
                Event::Packets(0),
                Event::Progress {
                    progress: 0,
                    status: 200,
                },
                Event::Complete {
                    progress: 0,
                    request_ok: true,
                },
                Event::Headers {
                    closed: false,
                    status: 200,
                    got: 1,
                },
                Event::Packets(2),
                Event::Progress {
                    progress: 120,
                    status: 200,
                },
                Event::Complete {
                    progress: 120,
                    request_ok: true,
                },
                Event::Headers {
                    closed: false,
                    status: 200,
                    got: 1,
                },
                Event::Packets(2),
                Event::Progress {
                    progress: 10,
                    status: 200,
                },
            ],
            &mut output,
        );
        emit(
            "complete-headers-unparsed",
            1,
            &[
                Event::Packets(0),
                Event::Progress {
                    progress: 0,
                    status: 200,
                },
                Event::Complete {
                    progress: 0,
                    request_ok: true,
                },
                Event::Headers {
                    closed: false,
                    status: 0,
                    got: 1,
                },
            ],
            &mut output,
        );
        emit(
            "complete-headers-silence",
            1,
            &[
                Event::Packets(0),
                Event::Progress {
                    progress: 0,
                    status: 200,
                },
                Event::Complete {
                    progress: 0,
                    request_ok: true,
                },
                Event::Headers {
                    closed: false,
                    status: 0,
                    got: 0,
                },
            ],
            &mut output,
        );
        emit(
            "complete-closed",
            1,
            &[
                Event::Packets(0),
                Event::Progress {
                    progress: 0,
                    status: 200,
                },
                Event::Complete {
                    progress: 0,
                    request_ok: true,
                },
                Event::Headers {
                    closed: true,
                    status: 0,
                    got: 0,
                },
            ],
            &mut output,
        );
        if let Ok(path) = std::env::var("R2O_QUIC_BUDGET_ORACLE_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn production_budget_loop_sequences_update_result_budget() {
        use super::{
            R2oQuicBudgetDriver, R2oQuicBudgetEvent as Event, R2oQuicBudgetOutcome as Outcome,
            R2oQuicHttp3Result, r2o_quic_budget_apply_event,
        };

        fn run(events: &[Event]) -> (R2oQuicHttp3Result, R2oQuicBudgetDriver) {
            let mut result = R2oQuicHttp3Result::default();
            let mut driver = R2oQuicBudgetDriver::r2o_new(1);
            for event in events {
                r2o_quic_budget_apply_event(&mut driver, &mut result, *event);
            }
            (result, driver)
        }

        let (passed, driver) = run(&[
            Event::Packets(2),
            Event::Progress {
                progress: 0,
                status: 200,
            },
            Event::Packets(2),
            Event::Progress {
                progress: 10,
                status: 200,
            },
        ]);
        assert_eq!(passed.budget, Outcome::Passed);
        assert!(passed.budget_passed);
        assert_eq!(driver.r2o_result().need, 2);
        assert_eq!(driver.r2o_result().packets, 2);

        let (silence, _) = run(&[
            Event::Packets(0),
            Event::Progress {
                progress: 0,
                status: 200,
            },
            Event::Recv {
                n: 0,
                progress_changed: false,
                timed_out: true,
            },
        ]);
        assert_eq!(silence.budget, Outcome::Cut);
        assert!(!silence.budget_passed);

        let (closed, _) = run(&[
            Event::Packets(0),
            Event::Progress {
                progress: 0,
                status: 200,
            },
            Event::Closed,
        ]);
        assert_eq!(closed.budget, Outcome::NotApplicable);

        let (recv_error, _) = run(&[
            Event::Packets(0),
            Event::Progress {
                progress: 0,
                status: 200,
            },
            Event::Recv {
                n: -1,
                progress_changed: false,
                timed_out: false,
            },
        ]);
        assert_eq!(recv_error.budget, Outcome::NotApplicable);

        let (unparsed, _) = run(&[
            Event::Packets(0),
            Event::Progress {
                progress: 0,
                status: 200,
            },
            Event::Headers {
                closed: false,
                status: 0,
                got: 1,
            },
        ]);
        assert_eq!(unparsed.budget, Outcome::NotApplicable);

        let (complete_headers, driver) = run(&[
            Event::Packets(0),
            Event::Progress {
                progress: 0,
                status: 200,
            },
            Event::Complete {
                progress: 0,
                request_ok: true,
            },
            Event::Headers {
                closed: false,
                status: 200,
                got: 1,
            },
            Event::Packets(2),
            Event::Progress {
                progress: 120,
                status: 200,
            },
            Event::Complete {
                progress: 120,
                request_ok: true,
            },
            Event::Headers {
                closed: false,
                status: 200,
                got: 1,
            },
            Event::Packets(2),
            Event::Progress {
                progress: 10,
                status: 200,
            },
        ]);
        assert_eq!(complete_headers.budget, Outcome::Passed);
        assert!(complete_headers.budget_passed);
        assert_eq!(driver.r2o_result().requests, 3);
        assert_eq!(driver.r2o_result().packets, 2);
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

    #[test]
    fn r2o_quic_budget_need_matches_d2o_unsigned_multiplication() {
        for (r2o_packets, r2o_expected) in [
            (0, 50),
            (1, 2),
            (25, 50),
            (u32::MAX / 2, u32::MAX - 1),
            (u32::MAX / 2 + 1, 0),
            (u32::MAX, u32::MAX - 1),
        ] {
            assert_eq!(
                R2oQuicHttp3Budget::r2o_initialize(r2o_packets).need,
                u64::from(r2o_expected)
            );
        }
    }

    #[test]
    fn r2o_quic_бюджет_может_пройти_по_заголовкам_следующего_потока_как_d2o() {
        let start = Instant::now() + Duration::from_millis(10);
        let mut budget = R2oQuicHttp3Budget::r2o_initialize(1);

        assert!(!budget.r2o_step(2, 100, 200, start, start, Duration::from_secs(1)));
        assert_eq!(budget.progress_mark, Some(100));
        assert!(budget.r2o_step(
            2,
            120,
            200,
            start + Duration::from_millis(100),
            start + Duration::from_millis(100),
            Duration::from_secs(1)
        ));
        if let Ok(path) = std::env::var("R2O_QUIC_HTTP3_NEXT_STREAM_DIFF_OUTPUT") {
            std::fs::write(path, "budget-next-stream=Pass\n").unwrap();
        }
    }

    #[test]
    fn forget_all_clears_recent_udp_ports() {
        let port = 65530;
        super::r2o_quic_port_forget_all();
        assert!(!super::r2o_quic_port_was_recently_claimed(port));
        assert!(super::r2o_quic_port_was_recently_claimed(port));
        super::r2o_quic_port_forget_all();
        assert!(!super::r2o_quic_port_was_recently_claimed(port));
    }

    #[test]
    fn quic_peer_name_matches_donor_semantics() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["example.test".to_owned()]).unwrap();
        let der = certificate.serialize_der().unwrap();
        assert_eq!(super::r2o_quic_peer_name(&der, "example.test"), 1);
        assert_eq!(super::r2o_quic_peer_name(&der, "other.test"), 0);
        assert_eq!(super::r2o_quic_peer_name(b"garbage", "example.test"), -1);
        assert_eq!(super::R2oQuicHttp3Result::default().d2k_qc_peer_name(), -1);
        let mut result = super::R2oQuicHttp3Result::default();
        result.peer_name = 0;
        assert_eq!(result.d2k_qc_peer_name(), 0);
    }

    #[test]
    fn quic_datagrams_sum_matches_c() {
        // C `d2k_qc_datagrams`: tx+rx, NULL-объект даёт 0.
        assert_eq!(super::r2o_quic_datagrams_sum(0, 0), 0);
        assert_eq!(super::r2o_quic_datagrams_sum(3, 4), 7);
        assert_eq!(super::r2o_quic_datagrams_sum(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn quic_budget_grew_matches_c() {
        // C `d2k_qbudget_grew`: pkts>=need отмечает progress, затем
        // status>0 && progress>mark без проверки свежести.
        let mut mark = None;
        assert!(!super::r2o_quic_budget_grew(1, 2, 200, 10, &mut mark));
        assert_eq!(mark, None);
        assert!(!super::r2o_quic_budget_grew(2, 2, 0, 10, &mut mark));
        assert_eq!(mark, Some(10));
        assert!(!super::r2o_quic_budget_grew(3, 2, 200, 10, &mut mark));
        assert!(super::r2o_quic_budget_grew(3, 2, 200, 11, &mut mark));
    }
}
