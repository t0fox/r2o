//! HTTP/3-пробы QUIC по заранее привязанному UDP-сокету.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use rustls::RootCertStore;

pub const R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS: u32 = 25;
const R2O_QUIC_RECENT_PORTS: usize = 4096;
const R2O_QUIC_FRESH_PORT_TRIES: usize = 16;
const R2O_QUIC_RESIDUAL_PORT_AGE: Duration = Duration::from_secs(480);

static R2O_QUIC_RECENT_PORTS_STATE: OnceLock<Mutex<(VecDeque<(u16, Instant)>, usize)>> =
    OnceLock::new();

#[cfg(target_has_atomic = "64")]
type R2oQuicHttp3AppByteCounter = AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
type R2oQuicHttp3AppByteCounter = Mutex<u64>;

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
            marked = r2o_quic_http3_set_socket_mark(&socket, mark).is_ok();
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

fn r2o_quic_port_was_recently_claimed(port: u16) -> bool {
    let state = R2O_QUIC_RECENT_PORTS_STATE
        .get_or_init(|| Mutex::new((VecDeque::with_capacity(R2O_QUIC_RECENT_PORTS), 0)));
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (ports, next) = &mut *state;
    if ports
        .iter()
        .any(|(recent_port, at)| *recent_port == port && at.elapsed() < R2O_QUIC_RESIDUAL_PORT_AGE)
    {
        return true;
    }
    let entry = (port, Instant::now());
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
    /// Уникальные байты целевого HTTP/3 bidi-потока, включая HEADERS и framing.
    pub app_bytes: u64,
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

struct R2oQuicHttp3CountedConnection {
    inner: h3_quinn::Connection,
    connection: quinn::Connection,
    app_bytes: Arc<R2oQuicHttp3AppByteCounter>,
}

struct R2oQuicHttp3CountedOpenStreams {
    inner: h3_quinn::OpenStreams,
    connection: quinn::Connection,
    app_bytes: Arc<R2oQuicHttp3AppByteCounter>,
}

struct R2oQuicHttp3CountedRecvStream {
    inner: h3_quinn::RecvStream,
    app_bytes: Arc<R2oQuicHttp3AppByteCounter>,
    connection: Option<quinn::Connection>,
    stream_id: Option<quinn::StreamId>,
    last_seen: u64,
    count: bool,
}

struct R2oQuicHttp3CountedBidiStream {
    send: h3_quinn::SendStream<Bytes>,
    recv: R2oQuicHttp3CountedRecvStream,
}

fn r2o_quic_http3_count_app_bytes(app_bytes: &R2oQuicHttp3AppByteCounter, count: u64) {
    #[cfg(target_has_atomic = "64")]
    {
        let _ = app_bytes.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(count))
        });
    }
    #[cfg(not(target_has_atomic = "64"))]
    {
        let mut current = app_bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = current.saturating_add(count);
    }
}

fn r2o_quic_http3_app_bytes_load(app_bytes: &R2oQuicHttp3AppByteCounter) -> u64 {
    #[cfg(target_has_atomic = "64")]
    {
        app_bytes.load(Ordering::Relaxed)
    }
    #[cfg(not(target_has_atomic = "64"))]
    {
        *app_bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
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
                r2o_quic_http3_count_app_bytes(
                    &self.app_bytes,
                    received.saturating_sub(self.last_seen),
                );
                self.last_seen = self.last_seen.max(received);
            } else if let Poll::Ready(Ok(Some(bytes))) = &result {
                let received = self.last_seen.saturating_add(bytes.remaining() as u64);
                r2o_quic_http3_count_app_bytes(
                    &self.app_bytes,
                    received.saturating_sub(self.last_seen),
                );
                self.last_seen = received;
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
        app_bytes: Arc<R2oQuicHttp3AppByteCounter>,
        count: bool,
        connection: quinn::Connection,
    ) -> Self {
        let stream_id = quinn::StreamId::from(
            quinn::VarInt::from_u64(h3::quic::RecvStream::recv_id(&inner).into_inner())
                .expect("HTTP/3 stream ID is a QUIC variable integer"),
        );
        let tracked = !count || connection.r2o_track_recv_stream_bytes(stream_id);
        debug_assert!(tracked, "opened HTTP/3 request stream must be tracked");
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

/// Хранит порог пакетов и рост байтов целевого QUIC-потока для бюджета.
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
) -> R2oQuicHttp3Result {
    let deadline = max_duration.map(|duration| tokio::time::Instant::now() + duration);
    let repeated = budget_packets > 0;
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

    let app_bytes = Arc::new(R2oQuicHttp3AppByteCounter::new(0));
    let h3_connection = R2oQuicHttp3CountedConnection {
        inner: h3_quinn::Connection::new(connection.clone()),
        connection: connection.clone(),
        app_bytes: Arc::clone(&app_bytes),
    };
    let (mut driver, mut send_request) = match tokio::time::timeout(
        r2o_quic_http3_bounded_timeout(timeout, deadline),
        h3::client::new(h3_connection),
    )
    .await
    {
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
    let mut last_app_progress = r2o_quic_http3_app_bytes_load(&app_bytes);
    let mut budget = R2oQuicHttp3Budget::r2o_initialize(budget_packets);
    let mut budget_passed = false;
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
            let app_progress = r2o_quic_http3_app_bytes_load(&app_bytes);
            let now = tokio::time::Instant::now();
            if app_progress > last_app_progress {
                last_app_progress = app_progress;
                last_progress_at = now;
            }
            if repeated {
                let packets =
                    r2o_quic_http3_datagrams(&connection).saturating_sub(datagrams_before);
                budget_passed =
                    budget.r2o_step(packets, app_progress, status, now, last_progress_at, rto);
                if budget_passed {
                    return Ok::<bool, String>(false);
                }
            }
            loop {
                let received = r2o_quic_http3_wait_with_stall(
                    &connection,
                    &mut stall,
                    &mut budget,
                    repeated,
                    datagrams_before,
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
                        if repeated {
                            budget_passed = budget.r2o_step(
                                packets,
                                app_progress,
                                status,
                                now,
                                last_progress_at,
                                rto,
                            );
                        }
                        let mut state = result.lock().unwrap();
                        state.body_bytes = total_body_bytes;
                        state.app_bytes = app_progress;
                        state.datagrams = packets;
                        state.budget_passed = budget_passed;
                        if budget_passed {
                            return Ok(false);
                        }
                    }
                    Ok(None) => {
                        let now = tokio::time::Instant::now();
                        let app_progress = r2o_quic_http3_app_bytes_load(&app_bytes);
                        if app_progress > last_app_progress {
                            last_app_progress = app_progress;
                            last_progress_at = now;
                        }
                        if repeated {
                            let packets = r2o_quic_http3_datagrams(&connection)
                                .saturating_sub(datagrams_before);
                            budget_passed = budget.r2o_step(
                                packets,
                                app_progress,
                                status,
                                now,
                                last_progress_at,
                                rto,
                            );
                        }
                        if budget_passed {
                            let mut state = result.lock().unwrap();
                            state.body_bytes = total_body_bytes;
                            state.app_bytes = app_progress;
                            state.datagrams = r2o_quic_http3_datagrams(&connection)
                                .saturating_sub(datagrams_before);
                            state.budget_passed = true;
                            return Ok(false);
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
        state.app_bytes = r2o_quic_http3_app_bytes_load(&app_bytes);
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
    app_bytes: &R2oQuicHttp3AppByteCounter,
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
        R2oQuicHttp3AppByteCounter, R2oQuicHttp3Budget, R2oQuicHttp3Stall,
        R2oQuicHttp3StallAction as Action, r2o_quic_http3_app_bytes_load, r2o_quic_http3_authority,
        r2o_quic_http3_bounded_timeout_at, r2o_quic_http3_count_app_bytes,
        r2o_quic_http3_udp_socket_with_mark_setter,
    };
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn http3_app_byte_counter_matches_d2o_unique_range_totals() {
        let app_bytes = R2oQuicHttp3AppByteCounter::new(0);
        for (delta, expected) in [
            (4, 4),
            (6, 10),
            (1_u64 << 32, (1_u64 << 32) + 10),
            (1_u64 << 32, (2_u64 << 32) + 10),
            (0, (2_u64 << 32) + 10),
        ] {
            r2o_quic_http3_count_app_bytes(&app_bytes, delta);
            assert_eq!(r2o_quic_http3_app_bytes_load(&app_bytes), expected);
        }
    }

    #[test]
    fn http3_app_byte_counter_saturates_at_u64_max() {
        let app_bytes = R2oQuicHttp3AppByteCounter::new(u64::MAX - 1);
        r2o_quic_http3_count_app_bytes(&app_bytes, 3);
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
}
