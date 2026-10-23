//! Прямая HTTPS-проверка с измерением полноты HTTP-ответа.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::http_search::repeatable_path;
use r2k_core::http_response::HttpResponseParser;
use rustls::pki_types::ServerName;
use rustls::{ProtocolVersion, RootCertStore, StreamOwned};

const SO_MARK: libc::c_int = 36;
const R2O_VOLUME_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const R2O_VOLUME_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const R2O_VOLUME_TX_STEPS: usize = 10;
const R2O_VOLUME_TX_CHUNK_BYTES: usize = 4000;
const R2O_VOLUME_TX_INITIAL_READ: Duration = Duration::from_secs(12);
const R2O_VOLUME_TX_READ_MIN: Duration = Duration::from_millis(1500);
const R2O_VOLUME_TX_READ_MAX: Duration = Duration::from_secs(12);
const R2O_VOLUME_TX_CHUNK_GAP: Duration = Duration::from_millis(50);
const R2O_VOLUME_RX_DEADLINE: Duration = Duration::from_secs(6);
const R2O_VOLUME_RX_PROBE_GAP: Duration = Duration::from_millis(500);

/// Дождаться ClientHello TCP с заданным именем и вернуть длину его TLS-записи.
pub fn r2o_fetch_snapshot_wire_len(
    name: &str,
    control_path: &Path,
    r2o_wait: Duration,
) -> Result<usize, String> {
    let r2o_host = crate::domain::normalize(name)
        .map_err(|error| format!("имя для снимка ClientHello недопустимо: {error}"))?;
    let r2o_path = r2k_core::control::r2k_snapshot_socket_path(control_path);
    let mut r2o_stream = UnixStream::connect(&r2o_path).map_err(|error| {
        format!(
            "не удалось подключиться к каналу снимка {}: {error}",
            r2o_path.display()
        )
    })?;
    let r2o_deadline = Instant::now()
        .checked_add(r2o_wait)
        .ok_or_else(|| "срок ожидания снимка слишком велик".to_owned())?;
    let r2o_greeting = loop {
        let r2o_remaining = r2o_deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| format!("не дождались приветствия браузера к {name}"))?;
        r2o_stream
            .set_read_timeout(Some(r2o_remaining))
            .map_err(|error| format!("не удалось настроить ожидание снимка: {error}"))?;
        let r2o_frame = r2k_core::control::read_frame(&mut r2o_stream).map_err(|error| {
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) {
                format!("не дождались приветствия датапата для {name}")
            } else {
                format!("связь с каналом снимка прервана: {error}")
            }
        })?;
        if r2o_frame.kind == r2k_core::control::EVENT_PROTOCOL {
            break r2k_core::control::decode_greeting(&r2o_frame)
                .map_err(|error| format!("приветствие канала снимка: {error}"))?;
        }
        return Err("канал снимка не прислал приветствие датапата первым".into());
    };
    if r2o_greeting.version != r2k_core::control::PROTOCOL_VERSION
        || r2o_greeting.release_id != r2k_core::control::RELEASE_ID
    {
        return Err(format!(
            "несовместимый r2o-datapath: wire={}, release={}, нужен wire={}, release={}",
            r2o_greeting.version,
            r2o_greeting.release_id,
            r2k_core::control::PROTOCOL_VERSION,
            r2k_core::control::RELEASE_ID
        ));
    }

    eprintln!(
        "жду приветствие браузера к {name} (до {} мс): откройте сайт",
        r2o_wait.as_millis()
    );
    loop {
        let r2o_remaining = r2o_deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| format!("не дождались приветствия браузера к {name}"))?;
        r2o_stream
            .set_read_timeout(Some(r2o_remaining))
            .map_err(|error| format!("не удалось настроить ожидание снимка: {error}"))?;
        let r2o_frame = r2k_core::control::read_frame(&mut r2o_stream).map_err(|error| {
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) {
                format!("не дождались приветствия браузера к {name}")
            } else {
                format!("связь с каналом снимка прервана: {error}")
            }
        })?;
        if r2o_frame.kind != r2k_core::control::EVENT_HELLO {
            continue;
        }
        let r2o_hello = r2k_core::control::decode_hello(&r2o_frame)
            .map_err(|error| format!("событие снимка ClientHello: {error}"))?;
        if r2o_hello.key[37] != 6
            || r2o_hello
                .host
                .as_deref()
                .is_none_or(|host| !host.eq_ignore_ascii_case(r2o_host.as_bytes()))
        {
            continue;
        }
        let Some(r2o_wire_len) = r2o_hello.r2o_wire_len else {
            continue;
        };
        eprintln!("снято приветствие браузера: {r2o_wire_len} байт");
        return Ok(r2o_wire_len);
    }
}

/// Параметры одного GET через TLS.
#[derive(Clone, Debug)]
pub struct FetchOptions {
    pub name: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub path: String,
    pub deadline: Duration,
    pub tls12: bool,
    pub wire_len: Option<usize>,
    pub mark: Option<u32>,
}

fn effective_mark(mark: Option<u32>) -> Option<u32> {
    mark.filter(|mark| *mark != 0)
}

impl FetchOptions {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty()
            || self.name.bytes().any(|byte| {
                byte.is_ascii_control() || matches!(byte, b' ' | b'/' | b'\\' | b'@' | b'[' | b']')
            })
            || ServerName::try_from(self.name.clone()).is_err()
        {
            return Err("имя цели недопустимо для SNI и заголовка Host".into());
        }
        if self.port == 0 {
            return Err("порт должен быть в диапазоне 1–65535".into());
        }
        if !repeatable_path(self.path.as_bytes()) {
            return Err(
                "путь должен быть безопасным абсолютным путём без запроса и фрагмента".into(),
            );
        }
        if self.deadline.is_zero() {
            return Err("срок ожидания должен быть больше нуля".into());
        }
        if self
            .wire_len
            .is_some_and(|length| length == 0 || length > 4096)
        {
            return Err("длина ClientHello должна быть от 1 до 4096 байт".into());
        }
        Ok(())
    }
}

/// Результат TLS-рукопожатия и чтения одного HTTP-ответа.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchResult {
    pub address: SocketAddr,
    pub local_port: u16,
    pub tls: Option<&'static str>,
    pub status: u16,
    pub http_outcome: R2oFetchHttpOutcome,
    pub cloudflare_challenge: bool,
    pub body_bytes: u64,
    pub body_expected: Option<u64>,
    pub body_has_length: bool,
    pub location: String,
    pub chunked: bool,
    pub gzip: bool,
    pub complete: bool,
    pub application_verified: bool,
    pub elapsed: Duration,
    pub reason: Option<String>,
    pub r2o_volume_observation: crate::r2o_volume::R2oVolumeObservation,
    pub r2o_resources: Vec<crate::r2o_resource::R2oResourceHint>,
}

/// Проверяет завершённый HTTP-ответ для прямого RX-результата.
pub fn r2o_fetch_result_is_direct_complete(result: &FetchResult) -> bool {
    (200..300).contains(&result.status)
        && result.complete
        && result.application_verified
        && !matches!(
            result.http_outcome,
            R2oFetchHttpOutcome::Blocked | R2oFetchHttpOutcome::LegalDenial
        )
}

/// Проверяет, можно ли сохранить ресурсы ответа как подсказки планировщика.
pub fn r2o_fetch_result_can_remember_resources(result: &FetchResult) -> bool {
    (200..300).contains(&result.status)
        && result.complete
        && !matches!(
            result.http_outcome,
            R2oFetchHttpOutcome::Blocked | R2oFetchHttpOutcome::LegalDenial
        )
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum R2oFetchHttpOutcome {
    #[default]
    Neutral,
    Positive,
    Blocked,
    LegalDenial,
}

/// Ошибка прямого HTTPS-замера с отдельной отметкой локального отказа.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oFetchError {
    pub message: String,
    pub local_refusal: bool,
}

impl From<String> for R2oFetchError {
    fn from(message: String) -> Self {
        Self {
            message,
            local_refusal: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oFetchEncoding {
    Identity,
    Gzip,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct R2oFetchVolumeRxResult {
    pub first: Option<FetchResult>,
    pub second: Option<FetchResult>,
    pub third: Option<FetchResult>,
    pub gzip: Option<FetchResult>,
    pub evidence: Option<crate::r2o_volume::R2oVolumeRxEvidence>,
    pub short_bytes: Option<u64>,
    pub direct_complete: bool,
    pub rx_unmeasured: bool,
    pub rx_tls_unavailable: bool,
    pub measured_path: Option<String>,
    pub retry_path: Option<String>,
    pub failures: Vec<String>,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oFetchVolumeTxVerdict {
    Unreachable,
    Short,
    Cut,
    Passed,
}

impl R2oFetchVolumeTxVerdict {
    pub const fn r2o_label(self) -> &'static str {
        match self {
            Self::Unreachable => "цель не ответила",
            Self::Short => "объём не набран — вердикта нет",
            Self::Cut => "обрыв по объёму",
            Self::Passed => "объём прошёл",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oFetchVolumeTxResult {
    pub address: SocketAddr,
    pub verdict: R2oFetchVolumeTxVerdict,
    pub at_kb: u32,
    pub elapsed: Duration,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oQuicFetchResult {
    pub address: SocketAddr,
    pub local_port: u16,
    pub elapsed: Duration,
    pub data: crate::r2o_quic_http3::R2oQuicHttp3Result,
}

/// Выполнить один GET через QUIC и HTTP/3.
pub fn r2o_fetch_quic(options: &FetchOptions) -> Result<R2oQuicFetchResult, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    r2o_fetch_quic_with_roots(options, roots)
}

/// Выполнить QUIC GET с явно заданными корнями доверия.
pub fn r2o_fetch_quic_with_roots(
    options: &FetchOptions,
    roots: RootCertStore,
) -> Result<R2oQuicFetchResult, String> {
    r2o_fetch_quic_with_roots_and_budget(options, roots, 0)
}

/// Выполнить HTTP/3-замер с системными корнями и бюджетом датаграмм.
pub fn r2o_fetch_quic_with_budget(
    options: &FetchOptions,
    budget_packets: u32,
) -> Result<R2oQuicFetchResult, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    r2o_fetch_quic_with_roots_and_budget(options, roots, budget_packets)
}

/// Выполнить HTTP/3-замер с заданными корнями и бюджетом датаграмм.
pub fn r2o_fetch_quic_with_roots_and_budget(
    options: &FetchOptions,
    roots: RootCertStore,
    budget_packets: u32,
) -> Result<R2oQuicFetchResult, String> {
    options.validate()?;
    if options.tls12 {
        return Err("QUIC использует TLS 1.3 и не поддерживает --tls12".into());
    }
    let started = Instant::now();
    let address = resolve_target(options)?;
    let socket = match crate::r2o_quic_http3::r2o_quic_http3_udp_socket_detailed(
        address,
        effective_mark(options.mark),
    ) {
        Ok(socket) => socket,
        Err(error) if error.local_refusal => {
            return Ok(r2o_quic_fetch_setup_failure(
                address,
                started,
                "метка измерительного сокета не поставилась".into(),
                true,
                budget_packets > 0,
            ));
        }
        Err(error) => {
            return Ok(r2o_quic_fetch_setup_failure(
                address,
                started,
                format!(
                    "рукопожатия нет: не удалось подготовить UDP-сокет для {address}: {}",
                    error.source
                ),
                false,
                budget_packets > 0,
            ));
        }
    };
    let local_port = match socket.local_addr() {
        Ok(address) => address.port(),
        Err(error) => {
            return Ok(r2o_quic_fetch_setup_failure(
                address,
                started,
                format!("рукопожатия нет: не удалось получить местный UDP-порт: {error}"),
                false,
                budget_packets > 0,
            ));
        }
    };
    let r2o_socket_monitor = socket.try_clone().ok();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return Ok(r2o_quic_fetch_setup_failure(
                address,
                started,
                format!("рукопожатия нет: не удалось запустить QUIC runtime: {error}"),
                false,
                budget_packets > 0,
            ));
        }
    };
    let mut data = runtime.block_on(crate::r2o_quic_http3::r2o_quic_http3_measure_with_wire_len(
        socket,
        address,
        &options.name,
        &options.path,
        options.deadline,
        roots,
        budget_packets,
        options.wire_len,
    ));
    if !data.handshake_confirmed && data.status == 0 {
        if let Some(monitor) = r2o_socket_monitor {
            if let Ok(Some(error)) = monitor.take_error() {
                data.error = Some(format!(
                    "рукопожатия нет: датаграмма не прочиталась: {error}"
                ));
            }
        }
    }
    Ok(R2oQuicFetchResult {
        address,
        local_port,
        elapsed: started.elapsed(),
        data,
    })
}

fn r2o_quic_fetch_setup_failure(
    address: SocketAddr,
    started: Instant,
    reason: String,
    local_refusal: bool,
    budget_required: bool,
) -> R2oQuicFetchResult {
    R2oQuicFetchResult {
        address,
        local_port: 0,
        elapsed: started.elapsed(),
        data: crate::r2o_quic_http3::R2oQuicHttp3Result {
            local_refusal,
            budget_required,
            error: Some(reason),
            ..Default::default()
        },
    }
}

/// Выполнить один HTTPS GET и дождаться конца HTTP-тела либо срока ожидания.
pub fn fetch(options: &FetchOptions) -> Result<FetchResult, String> {
    r2o_fetch_with_encoding(options, R2oFetchEncoding::Identity)
}

/// Выполнить HTTPS GET по уже соединённому TCP-сокету.
///
/// Сокет можно заранее привязать к точному локальному порту для временной
/// сетевой пробы. Адрес соединения сверяется с параметрами запроса.
pub fn r2o_fetch_connected_stream(
    options: &FetchOptions,
    stream: TcpStream,
) -> Result<FetchResult, String> {
    r2o_fetch_connected_stream_with_packet_budget(options, stream, None)
}

/// Выполнить GET по временному плану и проверить keep-alive поток до заданного бюджета TCP-пакетов.
pub fn r2o_fetch_connected_stream_with_packet_budget(
    options: &FetchOptions,
    stream: TcpStream,
    packet_budget: Option<u32>,
) -> Result<FetchResult, String> {
    options.validate()?;
    if packet_budget == Some(0) {
        return Err("бюджет TCP-пакетов должен быть больше нуля".into());
    }
    let address = resolve_target(options)?;
    let peer = stream
        .peer_addr()
        .map_err(|error| format!("не удалось проверить адрес HTTPS-зонда: {error}"))?;
    if peer != address {
        return Err(format!(
            "TCP-сокет подключён к {peer}, ожидался HTTPS-адрес {address}"
        ));
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    r2o_fetch_connected_stream_with_roots_and_encoding(
        options,
        stream,
        address,
        Instant::now(),
        R2oFetchEncoding::Identity,
        roots,
        None,
        packet_budget,
    )
}

/// Выполнить HTTP GET по ECH и завершиться ошибкой, если сервер его отклонил.
pub fn r2o_fetch_ech_connected_stream(
    options: &FetchOptions,
    stream: TcpStream,
    ech: &rustls::client::EchConfig,
) -> Result<FetchResult, String> {
    options.validate()?;
    let address = resolve_target(options)?;
    let peer = stream
        .peer_addr()
        .map_err(|error| format!("не удалось проверить адрес ECH-зонда: {error}"))?;
    if peer != address {
        return Err(format!(
            "TCP-сокет подключён к {peer}, ожидался HTTPS-адрес {address}"
        ));
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    r2o_fetch_connected_stream_with_roots_and_encoding(
        options,
        stream,
        address,
        Instant::now(),
        R2oFetchEncoding::Identity,
        roots,
        Some(ech),
        None,
    )
}

/// Выполнить HTTPS GET с выбранным кодированием тела и собрать сетевые признаки.
pub fn r2o_fetch_with_encoding(
    options: &FetchOptions,
    r2o_encoding: R2oFetchEncoding,
) -> Result<FetchResult, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    r2o_fetch_with_roots_and_encoding(options, r2o_encoding, roots)
}

/// Выполнить HTTPS GET и сохранить признак локального отказа SO_MARK для CLI.
pub fn r2o_fetch_detailed(options: &FetchOptions) -> Result<FetchResult, R2oFetchError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    r2o_fetch_with_roots_and_encoding_detailed(options, R2oFetchEncoding::Identity, roots)
}

fn r2o_fetch_with_roots_and_encoding(
    options: &FetchOptions,
    r2o_encoding: R2oFetchEncoding,
    roots: RootCertStore,
) -> Result<FetchResult, String> {
    r2o_fetch_with_roots_and_encoding_detailed(options, r2o_encoding, roots)
        .map_err(|error| error.message)
}

fn r2o_fetch_with_roots_and_encoding_detailed(
    options: &FetchOptions,
    r2o_encoding: R2oFetchEncoding,
    roots: RootCertStore,
) -> Result<FetchResult, R2oFetchError> {
    options.validate()?;
    let address = resolve_target(options)?;
    let started = Instant::now();
    let deadline = started
        .checked_add(options.deadline)
        .ok_or_else(|| "срок ожидания слишком велик".to_owned())?;
    let socket = connect_target(address, options.mark, remaining(deadline)?).map_err(|error| {
        R2oFetchError {
            message: if error.local_refusal {
                "метка измерительного сокета не поставилась".into()
            } else {
                format!("не удалось подключиться к {address}: {}", error.source)
            },
            local_refusal: error.local_refusal,
        }
    })?;
    r2o_fetch_connected_stream_with_roots_and_encoding(
        options,
        socket,
        address,
        started,
        r2o_encoding,
        roots,
        None,
        None,
    )
    .map_err(Into::into)
}

fn r2o_fetch_connected_stream_with_roots_and_encoding(
    options: &FetchOptions,
    socket: TcpStream,
    address: SocketAddr,
    started: Instant,
    r2o_encoding: R2oFetchEncoding,
    roots: RootCertStore,
    ech: Option<&rustls::client::EchConfig>,
    packet_budget: Option<u32>,
) -> Result<FetchResult, String> {
    r2o_fetch_connected_stream_with_roots_and_encoding_and_counter(
        options,
        socket,
        address,
        started,
        r2o_encoding,
        roots,
        ech,
        packet_budget,
        |socket| r2o_tcp_counters(socket).data_packets,
    )
}

fn r2o_fetch_connected_stream_with_roots_and_encoding_and_counter(
    options: &FetchOptions,
    socket: TcpStream,
    address: SocketAddr,
    started: Instant,
    r2o_encoding: R2oFetchEncoding,
    roots: RootCertStore,
    ech: Option<&rustls::client::EchConfig>,
    packet_budget: Option<u32>,
    mut packet_counter: impl FnMut(&TcpStream) -> Option<u32>,
) -> Result<FetchResult, String> {
    let deadline = started
        .checked_add(options.deadline)
        .ok_or_else(|| "срок ожидания слишком велик".to_owned())?;
    socket
        .set_nodelay(true)
        .map_err(|error| format!("не удалось настроить TCP-сокет: {error}"))?;

    let mut connection = if let Some(ech) = ech {
        crate::r2o_tls::r2o_tls_ech_client_connection(&options.name, roots, ech.clone())?
    } else {
        crate::r2o_tls::r2o_tls_client_connection(
            &options.name,
            options.tls12,
            options.wire_len,
            roots,
        )?
    };
    let mut r2o_socket = R2oTlsTcpStream::new(socket);
    while connection.is_handshaking() {
        set_deadline(&r2o_socket.socket, deadline)?;
        connection
            .complete_io(&mut r2o_socket)
            .map_err(|error| format!("TLS-рукопожатие не завершилось: {error}"))?;
    }
    if ech.is_some() && connection.ech_status() != rustls::client::EchStatus::Accepted {
        return Err(format!(
            "сервер не подтвердил ECH: {:?}",
            connection.ech_status()
        ));
    }
    r2o_socket.r2o_reset_after_handshake();
    let tls = match connection.protocol_version() {
        Some(ProtocolVersion::TLSv1_3) => Some("1.3"),
        Some(ProtocolVersion::TLSv1_2) => Some("1.2"),
        _ => None,
    };

    let mut stream = StreamOwned::new(connection, r2o_socket);
    let local_port = stream
        .sock
        .socket
        .local_addr()
        .map_err(|error| format!("не удалось получить местный порт: {error}"))?
        .port();
    let mut request_path = options.path.clone();
    let root_probe = options.path == "/";
    let mut redirects = 0;
    loop {
        let request = build_request(&options.name, &request_path, r2o_encoding);
        set_deadline(&stream.sock.socket, deadline)?;
        stream
            .write_all(&request)
            .and_then(|()| stream.flush())
            .map_err(|error| format!("не удалось отправить HTTP-запрос: {error}"))?;

        let mut parser = HttpResponseParser::new(false);
        let mut buffer = [0_u8; 16 * 1024];
        let mut reason = None;
        let mut r2o_framing_valid = true;
        let mut r2o_local_limit = false;
        let mut r2o_body_expected_at_eof = None;
        let mut r2o_pending_response = Vec::with_capacity(16 * 1024);
        let mut r2o_pending_overflow = false;
        let mut r2o_resource_tap: Option<crate::r2o_resource::R2oResourceBodyTap> = None;
        let mut r2o_reply_body_tap: Option<crate::r2o_resource::R2oResourceBodyTap> = None;
        loop {
            if parser.is_complete() || parser.is_invalid() {
                break;
            }
            if let Err(error) = set_deadline(&stream.sock.socket, deadline) {
                reason = Some(error);
                break;
            }
            match stream.read(&mut buffer) {
                Ok(0) => {
                    r2o_framing_valid &= parser.headers_complete() && !parser.is_invalid();
                    r2o_body_expected_at_eof = parser
                        .fixed_body_remaining()
                        .map(|remaining| parser.body_bytes().saturating_add(remaining));
                    parser.feed(&[], true);
                    if !parser.is_complete() {
                        reason = Some("сервер закрыл TLS-поток до завершения HTTP-ответа".into());
                    }
                    break;
                }
                Ok(length) => {
                    let r2o_bytes = &buffer[..length];
                    if parser.headers_complete() {
                        if let Some(tap) = &mut r2o_resource_tap {
                            tap.feed(r2o_bytes);
                        }
                        if let Some(tap) = &mut r2o_reply_body_tap {
                            tap.feed(r2o_bytes);
                        }
                    } else if !r2o_pending_overflow {
                        if r2o_pending_response.len() + length <= 64 * 1024 {
                            r2o_pending_response.extend_from_slice(r2o_bytes);
                        } else {
                            r2o_pending_response.clear();
                            r2o_pending_overflow = true;
                        }
                    }
                    parser.feed(&buffer[..length], false);
                    if parser.headers_complete() && r2o_resource_tap.is_none() {
                        let r2o_headers = parser.headers();
                        if !parser.is_invalid()
                            && !r2o_pending_overflow
                            && r2o_fetch_resource_scan_allowed(parser.status(), r2o_headers)
                            && let Some(r2o_header_start) = r2o_pending_response
                                .windows(r2o_headers.len())
                                .rposition(|window| window == r2o_headers)
                        {
                            let r2o_body_start = r2o_header_start + r2o_headers.len();
                            let mut r2o_tap = crate::r2o_resource::R2oResourceBodyTap::new(
                                r2o_fetch_chunked(r2o_headers),
                            );
                            r2o_tap.feed(&r2o_pending_response[r2o_body_start..]);
                            r2o_resource_tap = Some(r2o_tap);
                        }
                        if !parser.is_invalid()
                            && !r2o_pending_overflow
                            && (400..=599).contains(&parser.status())
                            && r2o_fetch_body_encoding(r2o_headers)
                                == crate::r2o_volume::R2oVolumeRxEncoding::Identity
                            && let Some(r2o_header_start) = r2o_pending_response
                                .windows(r2o_headers.len())
                                .rposition(|window| window == r2o_headers)
                        {
                            let r2o_body_start = r2o_header_start + r2o_headers.len();
                            let mut r2o_tap =
                                crate::r2o_resource::R2oResourceBodyTap::new_body_only(
                                    r2o_fetch_chunked(r2o_headers),
                                );
                            r2o_tap.feed(&r2o_pending_response[r2o_body_start..]);
                            r2o_reply_body_tap = Some(r2o_tap);
                        }
                        r2o_pending_response.clear();
                    }
                    if parser.is_invalid() {
                        r2o_framing_valid = false;
                        r2o_local_limit =
                            !parser.headers_complete() && parser.headers().len() >= 8191;
                        reason = Some("HTTP-ответ содержит неверное обрамление".into());
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    reason = Some("срок ожидания HTTP-ответа истёк".into());
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    r2o_framing_valid &= parser.headers_complete() && !parser.is_invalid();
                    r2o_body_expected_at_eof = parser
                        .fixed_body_remaining()
                        .map(|remaining| parser.body_bytes().saturating_add(remaining));
                    parser.feed(&[], true);
                    reason = Some("TLS-поток оборвался до завершения HTTP-ответа".into());
                    break;
                }
                Err(error) => {
                    reason = Some(format!("ошибка чтения HTTP-ответа: {error}"));
                    break;
                }
            }
        }

        if parser.is_invalid() && reason.is_none() {
            reason = Some("HTTP-ответ содержит неверное обрамление".into());
        }
        let body_expected = parser
            .fixed_body_remaining()
            .map(|remaining| parser.body_bytes().saturating_add(remaining))
            .or(r2o_body_expected_at_eof);
        let headers = parser.headers();
        let cloudflare_challenge = r2o_fetch_is_cloudflare_challenge(headers);
        let r2o_body_encoding = r2o_fetch_body_encoding(headers);
        let r2o_body_has_length = header_value(headers, b"content-length").is_some();
        let location = header_value(headers, b"location")
            .map(|value| String::from_utf8_lossy(trim_ascii(value)).into_owned())
            .unwrap_or_default();
        let r2o_body_chunked = header_value(headers, b"transfer-encoding")
            .is_some_and(|value| value.eq_ignore_ascii_case(b"chunked"));
        let chunked = header_value(headers, b"transfer-encoding")
            .is_some_and(|value| value.eq_ignore_ascii_case(b"chunked"));
        let gzip = header_value(headers, b"content-encoding").is_some_and(|value| {
            value
                .split(|byte| *byte == b',')
                .any(|encoding| trim_ascii(encoding).eq_ignore_ascii_case(b"gzip"))
        });
        let location_count = header_values(headers, b"location").count();
        let location_valid = location_count <= 1
            && (location.is_empty() || !location.bytes().any(|byte| byte <= 0x20 || byte == 0x7f));
        r2o_framing_valid &= location_valid;
        let complete = parser.is_complete() && !parser.is_invalid() && location_valid;
        let http_outcome = r2o_fetch_http_outcome(
            parser.status(),
            location.as_bytes(),
            r2o_body_encoding == crate::r2o_volume::R2oVolumeRxEncoding::Identity,
            r2o_reply_body_tap
                .as_ref()
                .map_or(&[][..], crate::r2o_resource::R2oResourceBodyTap::prefix),
            parser.body_bytes().saturating_add(u64::from(!complete)),
        );
        let mut application_verified = complete
            && parser.status() >= 200
            && !cloudflare_challenge
            && !matches!(
                http_outcome,
                R2oFetchHttpOutcome::Blocked | R2oFetchHttpOutcome::LegalDenial
            );
        let is_redirect = (300..400).contains(&parser.status());
        if is_redirect {
            application_verified = false;
            let same_origin_path = r2o_fetch_same_origin_redirect(&location, &options.name);
            if complete
                && r2o_framing_valid
                && let Some(next_path) = same_origin_path.as_ref()
            {
                if redirects < 3
                    && (root_probe || crate::r2o_resource::r2o_resource_path_ok(next_path))
                {
                    request_path.clone_from(next_path);
                    redirects += 1;
                    continue;
                }
                if !root_probe && !crate::r2o_resource::r2o_resource_path_ok(next_path) {
                    reason = Some("stylesheet перенаправлен не на ресурс; не подтверждено".into());
                }
            } else if root_probe
                && complete
                && same_origin_path.is_none()
                && http_outcome != R2oFetchHttpOutcome::Blocked
                && !cloudflare_challenge
                && r2o_fetch_external_https_redirect(parser.status(), location.as_bytes())
            {
                application_verified = true;
            }
            if !application_verified && reason.is_none() {
                reason = Some(format!(
                    "HTTP {} redirect не подтверждает страницу этой цели",
                    parser.status()
                ));
            }
        }
        let r2o_resources = if complete && r2o_fetch_resource_scan_allowed(parser.status(), headers)
        {
            r2o_resource_tap
                .as_ref()
                .map(|tap| tap.resources().to_vec())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let r2o_packet_budget = if let Some(need) = packet_budget {
            if complete && parser.status() >= 100 && parser.headers_complete() {
                r2o_measure_http_packet_budget(
                    &mut stream,
                    options,
                    r2o_encoding,
                    deadline,
                    need,
                    r2o_http_connection_closes(parser.headers()),
                    &mut packet_counter,
                )
            } else {
                crate::r2o_volume::R2oVolumePacketBudget::NotApplicable
            }
        } else {
            crate::r2o_volume::R2oVolumePacketBudget::NotMeasured
        };
        let r2o_tcp_after = r2o_tcp_counters(&stream.sock.socket);
        let r2o_tls_wire_bytes = stream.sock.r2o_wire_bytes;
        let r2o_data_packets = r2o_tcp_after.data_packets.unwrap_or(0);
        let r2o_negotiated_tls = match tls {
            Some("1.3") => Some(0x0304),
            Some("1.2") => Some(0x0303),
            _ => None,
        };
        let r2o_stage = if parser.status() != 0 || parser.headers_complete() {
            crate::r2o_volume::R2oVolumeProbeStage::Application
        } else {
            crate::r2o_volume::R2oVolumeProbeStage::Handshake
        };
        let r2o_volume_observation = crate::r2o_volume::R2oVolumeObservation {
            stage: r2o_stage,
            name_valid: r2o_negotiated_tls.is_some(),
            negotiated_tls: r2o_negotiated_tls,
            local_limit: r2o_local_limit,
            status: parser.status(),
            body_complete: complete,
            body_encoding: r2o_body_encoding,
            body_framing_valid: parser.headers_complete() && r2o_framing_valid,
            body_has_length: r2o_body_has_length,
            body_chunked: r2o_body_chunked,
            body_expected: body_expected.unwrap_or(0),
            body_bytes: parser.body_bytes(),
            rx_tls_wire_bytes: r2o_tls_wire_bytes,
            rx_tls_record_missing: stream.sock.r2o_record_missing(),
            data_packets: r2o_data_packets,
            packet_budget: r2o_packet_budget,
            ..Default::default()
        };

        return Ok(FetchResult {
            address,
            local_port,
            tls,
            status: parser.status(),
            http_outcome,
            cloudflare_challenge,
            body_bytes: parser.body_bytes(),
            body_expected,
            body_has_length: r2o_body_has_length,
            location,
            chunked,
            gzip,
            complete,
            application_verified,
            elapsed: started.elapsed(),
            reason,
            r2o_volume_observation,
            r2o_resources,
        });
    }
}

fn r2o_fetch_resource_scan_allowed(status: u16, headers: &[u8]) -> bool {
    (200..300).contains(&status)
        && header_value(headers, b"content-type").is_some_and(|value| {
            value
                .split(|byte| *byte == b';')
                .next()
                .is_some_and(|media_type| trim_ascii(media_type).eq_ignore_ascii_case(b"text/html"))
        })
        && r2o_fetch_body_encoding(headers) == crate::r2o_volume::R2oVolumeRxEncoding::Identity
        && !r2o_fetch_is_cloudflare_challenge(headers)
}

fn r2o_fetch_is_cloudflare_challenge(headers: &[u8]) -> bool {
    headers.split(|byte| *byte == b'\n').skip(1).any(|line| {
        line.strip_suffix(b"\r")
            .and_then(|line| {
                let colon = line.iter().position(|byte| *byte == b':')?;
                line[..colon]
                    .eq_ignore_ascii_case(b"cf-mitigated")
                    .then_some(trim_ascii(&line[colon + 1..]))
            })
            .is_some_and(|value| value.eq_ignore_ascii_case(b"challenge"))
    })
}

fn r2o_fetch_chunked(headers: &[u8]) -> bool {
    header_value(headers, b"transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case(b"chunked"))
}

/// Выполнить отдельную RX-проверку identity/gzip с донорскими повторами.
pub fn r2o_fetch_measure_rx_volume(options: &FetchOptions) -> R2oFetchVolumeRxResult {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    r2o_fetch_measure_rx_volume_with_roots(options, roots)
}

pub fn r2o_fetch_measure_rx_volume_with_fallback_path(
    options: &FetchOptions,
    fallback_path: Option<&str>,
) -> R2oFetchVolumeRxResult {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    r2o_fetch_measure_rx_volume_with_fallback_path_and_roots(options, fallback_path, roots)
}

fn r2o_fetch_rx_probe(
    options: &FetchOptions,
    encoding: R2oFetchEncoding,
    roots: RootCertStore,
) -> Result<FetchResult, String> {
    let first = r2o_fetch_with_roots_and_encoding(options, encoding, roots.clone())?;
    if !r2o_fetch_rx_probe_needs_repeat(&first) {
        return Ok(first);
    }

    drop(first);
    std::thread::sleep(R2O_VOLUME_RX_PROBE_GAP);
    r2o_fetch_with_roots_and_encoding(options, encoding, roots)
}

fn r2o_fetch_rx_probe_needs_repeat(result: &FetchResult) -> bool {
    let observation = &result.r2o_volume_observation;
    let early_success = (200..300).contains(&result.status)
        && !result.complete
        && result.body_bytes < crate::r2o_volume::R2O_VOLUME_MIN_BYTES;
    (result.status == 0 || early_success)
        && observation.name_valid
        && matches!(observation.negotiated_tls, Some(0x0303 | 0x0304))
        && !observation.local_limit
        && !crate::r2o_volume::r2o_volume_rx_partial(observation)
}

fn r2o_fetch_rx_probe_is_unmeasured(result: &FetchResult) -> bool {
    r2o_fetch_rx_probe_needs_repeat(result)
}

fn r2o_fetch_measure_rx_volume_with_fallback_path_and_roots(
    options: &FetchOptions,
    fallback_path: Option<&str>,
    roots: RootCertStore,
) -> R2oFetchVolumeRxResult {
    let primary = r2o_fetch_measure_rx_volume_with_roots(options, roots.clone());
    let Some(short_bytes) = primary.short_bytes else {
        return primary;
    };
    let Some(path) = fallback_path.filter(|path| {
        *path != options.path
            && primary.retry_path.as_deref() != Some(*path)
            && crate::r2o_resource::r2o_resource_path_ok(path)
    }) else {
        return primary;
    };

    std::thread::sleep(R2O_VOLUME_RX_PROBE_GAP);
    let mut fallback_options = options.clone();
    fallback_options.path = path.into();
    let fallback = r2o_fetch_measure_rx_volume_with_roots(&fallback_options, roots);
    r2o_fetch_rx_fallback_result(primary, fallback, path, short_bytes)
}

fn r2o_fetch_rx_fallback_result(
    mut primary: R2oFetchVolumeRxResult,
    mut fallback: R2oFetchVolumeRxResult,
    path: &str,
    short_bytes: u64,
) -> R2oFetchVolumeRxResult {
    if fallback.evidence.is_some() {
        if fallback.measured_path.is_none() {
            fallback.measured_path = Some(path.into());
        }
        fallback.retry_path = Some(path.into());
        fallback.reason = format!(
            "запасной путь {path} подтвердил RX-обрыв после короткого ответа ({short_bytes} байт): {}",
            fallback.reason
        );
        fallback
    } else {
        primary.retry_path = Some(path.into());
        primary.reason = format!(
            "{}; запасной путь {path} не подтвердил RX-обрыв: {}",
            primary.reason, fallback.reason
        );
        primary
    }
}

fn r2o_fetch_measure_rx_volume_with_roots(
    options: &FetchOptions,
    roots: RootCertStore,
) -> R2oFetchVolumeRxResult {
    let r2o_result = r2o_fetch_measure_rx_volume_once(options, roots.clone());
    let Some(r2o_short_bytes) = r2o_result.short_bytes else {
        return r2o_result;
    };
    let r2o_direct_complete = r2o_result.direct_complete;
    let r2o_original_first = r2o_result.first.clone();
    let Some(r2o_first) = r2o_result.first.as_ref() else {
        return r2o_result;
    };
    let Some(r2o_resource) = r2o_first.r2o_resources.iter().find(|resource| {
        resource.host.eq_ignore_ascii_case(&options.name)
            && crate::r2o_resource::r2o_resource_path_ok(&resource.path)
            && resource.path != options.path
    }) else {
        return r2o_result;
    };
    let r2o_retry_path = r2o_resource.path.clone();
    std::thread::sleep(R2O_VOLUME_RX_PROBE_GAP);
    let mut r2o_retry_options = options.clone();
    r2o_retry_options.path = r2o_retry_path.clone();
    let mut r2o_retry = r2o_fetch_measure_rx_volume_once(&r2o_retry_options, roots);
    r2o_retry.retry_path = Some(r2o_retry_path.clone());
    if r2o_retry.rx_tls_unavailable
        && r2o_retry.evidence.is_none()
        && r2o_retry.short_bytes.is_none()
    {
        r2o_retry.short_bytes = Some(r2o_short_bytes);
        r2o_retry.direct_complete = r2o_direct_complete;
        if r2o_retry.first.is_none() {
            r2o_retry.first = r2o_original_first;
        }
        r2o_retry.reason = format!(
            "повтор по {r2o_retry_path} не установил TLS; исходный ответ завершился на {r2o_short_bytes} байтах, измерить обрыв нельзя: {}",
            r2o_retry.reason
        );
    } else {
        r2o_retry.reason = format!(
            "повтор по CSS-пути {r2o_retry_path} после короткого ответа ({r2o_short_bytes} байт): {}",
            r2o_retry.reason
        );
    }
    r2o_retry
}

fn r2o_fetch_measure_rx_volume_once(
    options: &FetchOptions,
    roots: RootCertStore,
) -> R2oFetchVolumeRxResult {
    let mut r2o_result = R2oFetchVolumeRxResult::default();
    if options.port == 80 {
        r2o_result.reason = "для обычного HTTP отдельная TLS RX-проверка не применяется".into();
        return r2o_result;
    }
    let mut r2o_options = options.clone();
    r2o_options.deadline = R2O_VOLUME_RX_DEADLINE;
    let r2o_first =
        match r2o_fetch_rx_probe(&r2o_options, R2oFetchEncoding::Identity, roots.clone()) {
            Ok(result) => result,
            Err(error) => {
                r2o_result.rx_tls_unavailable =
                    error.starts_with("TLS-рукопожатие не завершилось:");
                r2o_result.failures.push(error.clone());
                r2o_result.reason =
                    format!("первая identity-проверка не установила TLS/HTTP: {error}");
                return r2o_result;
            }
        };
    r2o_result.direct_complete = r2o_fetch_result_is_direct_complete(&r2o_first);
    let r2o_first_observation = r2o_first.r2o_volume_observation;
    if !crate::r2o_volume::r2o_volume_rx_partial(&r2o_first_observation) {
        r2o_result.rx_unmeasured = r2o_fetch_rx_probe_is_unmeasured(&r2o_first)
            && !r2o_result.direct_complete
            && !r2o_result.rx_tls_unavailable;
        if r2o_first.status > 0 && r2o_first.complete && r2o_first.body_bytes < 12 * 1024 {
            r2o_result.short_bytes = Some(r2o_first.body_bytes);
            r2o_result.reason = format!(
                "полный ответ содержит {} байт, меньше порога 12 КБ; RX-обрыв не измерен",
                r2o_first.body_bytes
            );
        } else {
            r2o_result.reason = format!(
                "первая identity-проверка не подтвердила RX-обрыв: HTTP {}, {} байт{}",
                r2o_first.status,
                r2o_first.body_bytes,
                r2o_first
                    .reason
                    .as_deref()
                    .map(|reason| format!(" ({reason})"))
                    .unwrap_or_default()
            );
        }
        r2o_result.first = Some(r2o_first);
        return r2o_result;
    }
    r2o_result.first = Some(r2o_first);
    std::thread::sleep(R2O_VOLUME_RX_PROBE_GAP);
    let r2o_second =
        match r2o_fetch_rx_probe(&r2o_options, R2oFetchEncoding::Identity, roots.clone()) {
            Ok(result) => result,
            Err(error) => {
                r2o_result.failures.push(error.clone());
                r2o_result.reason = format!("повтор identity не завершился: {error}");
                return r2o_result;
            }
        };
    let r2o_second_observation = r2o_second.r2o_volume_observation;
    let mut r2o_confirming_observation = r2o_second_observation;
    if !crate::r2o_volume::r2o_volume_rx_pair_agrees(
        &r2o_first_observation,
        &r2o_second_observation,
    ) {
        if !crate::r2o_volume::r2o_volume_rx_needs_repeat(
            &r2o_first_observation,
            &r2o_second_observation,
        ) {
            r2o_result.reason = format!(
                "identity-обрывы не согласовались: HTTP {}, {} байт, complete={}",
                r2o_second.status, r2o_second.body_bytes, r2o_second.complete
            );
            r2o_result.second = Some(r2o_second);
            return r2o_result;
        }
        r2o_result.second = Some(r2o_second);
        std::thread::sleep(R2O_VOLUME_RX_PROBE_GAP);
        let r2o_third =
            match r2o_fetch_rx_probe(&r2o_options, R2oFetchEncoding::Identity, roots.clone()) {
                Ok(result) => result,
                Err(error) => {
                    r2o_result.failures.push(error.clone());
                    r2o_result.reason = format!("третий identity-замер не завершился: {error}");
                    return r2o_result;
                }
            };
        r2o_confirming_observation = r2o_third.r2o_volume_observation;
        if !crate::r2o_volume::r2o_volume_rx_pair_agrees(
            &r2o_first_observation,
            &r2o_confirming_observation,
        ) {
            r2o_result.reason = format!(
                "третий identity-замер не подтвердил первый: HTTP {}, {} байт",
                r2o_third.status, r2o_third.body_bytes
            );
            r2o_result.third = Some(r2o_third);
            return r2o_result;
        }
        r2o_result.third = Some(r2o_third);
    } else {
        r2o_result.second = Some(r2o_second);
    }

    std::thread::sleep(R2O_VOLUME_RX_PROBE_GAP);
    let r2o_gzip = match r2o_fetch_rx_probe(&r2o_options, R2oFetchEncoding::Gzip, roots) {
        Ok(result) => result,
        Err(error) => {
            r2o_result.failures.push(error.clone());
            r2o_result.reason = format!("gzip-контроль не завершился: {error}");
            return r2o_result;
        }
    };
    r2o_result.evidence = crate::r2o_volume::r2o_volume_rx_evidence(
        &r2o_first_observation,
        &r2o_confirming_observation,
        &r2o_gzip.r2o_volume_observation,
    );
    if let Some(evidence) = &r2o_result.evidence {
        r2o_result.reason = evidence.reason.clone();
        r2o_result.measured_path = Some(options.path.clone());
    } else {
        r2o_result.reason = format!(
            "gzip не подтвердил identity-обрыв: HTTP {}, {} байт, complete={}",
            r2o_gzip.status, r2o_gzip.body_bytes, r2o_gzip.complete
        );
    }
    r2o_result.gzip = Some(r2o_gzip);
    r2o_result
}

/// Выполнить десять HEAD-шагов по одному TLS/TCP-соединению.
pub fn r2o_fetch_measure_tx_volume(
    options: &FetchOptions,
) -> Result<R2oFetchVolumeTxResult, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    r2o_fetch_measure_tx_volume_with_roots(options, roots)
}

fn r2o_fetch_measure_tx_volume_with_roots(
    options: &FetchOptions,
    roots: RootCertStore,
) -> Result<R2oFetchVolumeTxResult, String> {
    options.validate()?;
    let r2o_started = Instant::now();
    let r2o_address = resolve_target(options)?;
    let r2o_socket = match connect_target(r2o_address, options.mark, R2O_VOLUME_CONNECT_TIMEOUT) {
        Ok(socket) => socket,
        Err(error) => {
            return Ok(R2oFetchVolumeTxResult {
                address: r2o_address,
                verdict: R2oFetchVolumeTxVerdict::Unreachable,
                at_kb: 0,
                elapsed: r2o_started.elapsed(),
                reason: format!("нет TCP к {r2o_address}: {error}"),
            });
        }
    };
    if let Err(error) = r2o_socket.set_nodelay(true) {
        return Ok(R2oFetchVolumeTxResult {
            address: r2o_address,
            verdict: R2oFetchVolumeTxVerdict::Unreachable,
            at_kb: 0,
            elapsed: r2o_started.elapsed(),
            reason: format!("не удалось настроить TCP-сокет: {error}"),
        });
    }
    let r2o_stream = if options.port == 80 {
        R2oFetchVolumeStream::Plain(r2o_socket)
    } else {
        let r2o_deadline = Instant::now()
            .checked_add(R2O_VOLUME_HANDSHAKE_TIMEOUT)
            .ok_or_else(|| "срок TLS-рукопожатия слишком велик".to_owned())?;
        let mut connection = match crate::r2o_tls::r2o_tls_client_connection(
            &options.name,
            options.tls12,
            options.wire_len,
            roots,
        ) {
            Ok(connection) => connection,
            Err(error) => {
                return Ok(R2oFetchVolumeTxResult {
                    address: r2o_address,
                    verdict: R2oFetchVolumeTxVerdict::Unreachable,
                    at_kb: 0,
                    elapsed: r2o_started.elapsed(),
                    reason: format!("не удалось подготовить TLS: {error}"),
                });
            }
        };
        let mut r2o_tracked_socket = R2oTlsTcpStream::new(r2o_socket);
        while connection.is_handshaking() {
            if let Err(error) = set_deadline(&r2o_tracked_socket.socket, r2o_deadline) {
                return Ok(R2oFetchVolumeTxResult {
                    address: r2o_address,
                    verdict: R2oFetchVolumeTxVerdict::Unreachable,
                    at_kb: 0,
                    elapsed: r2o_started.elapsed(),
                    reason: error,
                });
            }
            if let Err(error) = connection.complete_io(&mut r2o_tracked_socket) {
                return Ok(R2oFetchVolumeTxResult {
                    address: r2o_address,
                    verdict: R2oFetchVolumeTxVerdict::Unreachable,
                    at_kb: 0,
                    elapsed: r2o_started.elapsed(),
                    reason: format!("TLS-рукопожатие не завершилось: {error}"),
                });
            }
        }
        r2o_tracked_socket.r2o_reset_after_handshake();
        R2oFetchVolumeStream::Tls(StreamOwned::new(connection, r2o_tracked_socket))
    };
    let mut r2o_stream = r2o_stream;
    if let Err(error) = r2o_stream.r2o_set_write_timeout(R2O_VOLUME_CONNECT_TIMEOUT) {
        return Ok(R2oFetchVolumeTxResult {
            address: r2o_address,
            verdict: R2oFetchVolumeTxVerdict::Unreachable,
            at_kb: 0,
            elapsed: r2o_started.elapsed(),
            reason: format!("не удалось настроить срок отправки: {error}"),
        });
    }
    let r2o_padding = r2o_volume_padding();
    let mut r2o_read_timeout = R2O_VOLUME_TX_INITIAL_READ;
    for r2o_step in 0..R2O_VOLUME_TX_STEPS {
        let r2o_request = r2o_volume_head_request(&options.name, &r2o_padding, r2o_step != 0);
        let r2o_request_started = Instant::now();
        let r2o_result = r2o_stream
            .write_all(&r2o_request)
            .and_then(|()| r2o_stream.flush())
            .and_then(|()| r2o_drain_head_response(&mut r2o_stream, r2o_read_timeout));
        if let Err(error) = r2o_result {
            let r2o_at_kb = (r2o_step * R2O_VOLUME_TX_CHUNK_BYTES / 1024) as u32;
            let r2o_verdict = if r2o_step == 0 {
                R2oFetchVolumeTxVerdict::Unreachable
            } else if r2o_at_kb >= 12 {
                R2oFetchVolumeTxVerdict::Cut
            } else {
                R2oFetchVolumeTxVerdict::Short
            };
            return Ok(R2oFetchVolumeTxResult {
                address: r2o_address,
                verdict: r2o_verdict,
                at_kb: r2o_at_kb,
                elapsed: r2o_started.elapsed(),
                reason: format!("HEAD-шаг {} не прошёл: {error}", r2o_step + 1),
            });
        }
        if r2o_step == 0 {
            let r2o_rtt_ms = r2o_request_started.elapsed().as_millis();
            let r2o_read_ms = r2o_rtt_ms.saturating_mul(3).clamp(
                R2O_VOLUME_TX_READ_MIN.as_millis(),
                R2O_VOLUME_TX_READ_MAX.as_millis(),
            );
            r2o_read_timeout = Duration::from_millis(r2o_read_ms as u64);
        }
        std::thread::sleep(R2O_VOLUME_TX_CHUNK_GAP);
    }

    Ok(R2oFetchVolumeTxResult {
        address: r2o_address,
        verdict: R2oFetchVolumeTxVerdict::Passed,
        at_kb: (R2O_VOLUME_TX_STEPS * R2O_VOLUME_TX_CHUNK_BYTES / 1024) as u32,
        elapsed: r2o_started.elapsed(),
        reason: "лестница пройдена целиком".into(),
    })
}

fn build_request(name: &str, path: &str, encoding: R2oFetchEncoding) -> Vec<u8> {
    let mut request = Vec::with_capacity(name.len() + path.len() + 128);
    request.extend_from_slice(b"GET ");
    request.extend_from_slice(path.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(b"\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nAccept-Encoding: ");
    request.extend_from_slice(match encoding {
        R2oFetchEncoding::Identity => b"identity",
        R2oFetchEncoding::Gzip => b"gzip",
    });
    request.extend_from_slice(b"\r\nConnection: keep-alive\r\n\r\n");
    request
}

fn r2o_fetch_body_encoding(headers: &[u8]) -> crate::r2o_volume::R2oVolumeRxEncoding {
    let mut r2o_encoding = None;
    for r2o_line in headers.split(|byte| *byte == b'\n').skip(1) {
        let r2o_line = r2o_line.strip_suffix(b"\r").unwrap_or(r2o_line);
        let Some(r2o_colon) = r2o_line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if !r2o_line[..r2o_colon].eq_ignore_ascii_case(b"content-encoding") {
            continue;
        }
        if r2o_encoding.is_some() {
            return crate::r2o_volume::R2oVolumeRxEncoding::Other;
        }
        let r2o_value = trim_ascii(&r2o_line[r2o_colon + 1..]);
        r2o_encoding = Some(if r2o_value.eq_ignore_ascii_case(b"gzip") {
            crate::r2o_volume::R2oVolumeRxEncoding::Gzip
        } else if r2o_value.eq_ignore_ascii_case(b"identity") {
            crate::r2o_volume::R2oVolumeRxEncoding::Identity
        } else {
            crate::r2o_volume::R2oVolumeRxEncoding::Other
        });
    }
    r2o_encoding.unwrap_or(crate::r2o_volume::R2oVolumeRxEncoding::Identity)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct R2oTcpCounters {
    data_packets: Option<u32>,
}

/// Считает байты и границы TLS-записей после рукопожатия, отделяя обрыв записи от FIN после полной записи.
#[derive(Clone, Debug)]
struct R2oTlsRecordTracker {
    header: [u8; 5],
    header_len: usize,
    body_remaining: usize,
    valid: bool,
}

impl Default for R2oTlsRecordTracker {
    fn default() -> Self {
        Self {
            header: [0; 5],
            header_len: 0,
            body_remaining: 0,
            valid: true,
        }
    }
}

impl R2oTlsRecordTracker {
    fn observe(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if !self.valid {
                return;
            }
            if self.body_remaining != 0 {
                self.body_remaining -= 1;
                continue;
            }
            self.header[self.header_len] = byte;
            self.header_len += 1;
            if self.header_len != self.header.len() {
                continue;
            }
            let content_type = self.header[0];
            let version_major = self.header[1];
            let version_minor = self.header[2];
            let body_len = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
            self.valid = matches!(content_type, 20..=24)
                && version_major == 3
                && (1..=3).contains(&version_minor)
                && body_len <= 18_432;
            self.header_len = 0;
            self.body_remaining = body_len;
        }
    }

    fn body_is_missing(&self) -> bool {
        self.valid && self.body_remaining != 0
    }
}

struct R2oTlsTcpStream {
    socket: TcpStream,
    r2o_wire_bytes: u64,
    r2o_records: R2oTlsRecordTracker,
}

impl R2oTlsTcpStream {
    fn new(socket: TcpStream) -> Self {
        Self {
            socket,
            r2o_wire_bytes: 0,
            r2o_records: R2oTlsRecordTracker::default(),
        }
    }

    fn r2o_reset_after_handshake(&mut self) {
        self.r2o_wire_bytes = 0;
        self.r2o_records = R2oTlsRecordTracker::default();
    }

    fn r2o_record_missing(&self) -> bool {
        self.r2o_records.body_is_missing()
    }
}

impl Read for R2oTlsTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = self.socket.read(buffer)?;
        if length != 0 {
            self.r2o_wire_bytes = self.r2o_wire_bytes.saturating_add(length as u64);
            self.r2o_records.observe(&buffer[..length]);
        }
        Ok(length)
    }
}

impl Write for R2oTlsTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.socket.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

enum R2oFetchVolumeStream {
    Plain(TcpStream),
    Tls(StreamOwned<rustls::ClientConnection, R2oTlsTcpStream>),
}

impl R2oFetchVolumeStream {
    fn r2o_set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.set_read_timeout(Some(timeout)),
            Self::Tls(stream) => stream.sock.socket.set_read_timeout(Some(timeout)),
        }
    }

    fn r2o_set_write_timeout(&self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.set_write_timeout(Some(timeout)),
            Self::Tls(stream) => stream.sock.socket.set_write_timeout(Some(timeout)),
        }
    }
}

impl Read for R2oFetchVolumeStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for R2oFetchVolumeStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

fn r2o_volume_head_request(name: &str, padding: &[u8], padded: bool) -> Vec<u8> {
    let mut request = Vec::with_capacity(name.len() + padding.len() + 128);
    request.extend_from_slice(b"HEAD / HTTP/1.1\r\nHost: ");
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(b"\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n");
    if padded {
        request.extend_from_slice(b"X-Pad: ");
        request.extend_from_slice(padding);
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request
}

fn r2o_volume_padding() -> Vec<u8> {
    const R2O_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut random = vec![0_u8; R2O_VOLUME_TX_CHUNK_BYTES];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .is_err()
    {
        for (index, byte) in random.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(31).wrapping_add(7);
        }
    }
    random
        .into_iter()
        .map(|byte| R2O_ALPHABET[usize::from(byte) % R2O_ALPHABET.len()])
        .collect()
}

fn r2o_drain_head_response(stream: &mut R2oFetchVolumeStream, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "слишком долгий срок ответа"))?;
    let mut parser = HttpResponseParser::new(true);
    let mut buffer = [0_u8; 4096];
    loop {
        if parser.is_complete() {
            return Ok(());
        }
        if parser.is_invalid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ответ HEAD содержит неверное обрамление",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "истёк срок ожидания ответа HEAD",
            ));
        }
        stream.r2o_set_read_timeout(remaining)?;
        match stream.read(&mut buffer) {
            Ok(0) => {
                parser.feed(&[], true);
                if parser.is_complete() {
                    return Ok(());
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "сервер закрыл ответ HEAD до конца заголовков",
                ));
            }
            Ok(length) => parser.feed(&buffer[..length], false),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
fn r2o_tcp_counters(stream: &TcpStream) -> R2oTcpCounters {
    let mut r2o_info = std::mem::MaybeUninit::<libc::tcp_info>::zeroed();
    let mut r2o_length = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let r2o_result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            r2o_info.as_mut_ptr().cast(),
            &mut r2o_length,
        )
    };
    if r2o_result != 0 {
        return R2oTcpCounters::default();
    }
    let r2o_info = unsafe { r2o_info.assume_init() };
    let r2o_length = r2o_length as usize;
    let r2o_packets_end = std::mem::offset_of!(libc::tcp_info, tcpi_data_segs_out)
        + std::mem::size_of_val(&r2o_info.tcpi_data_segs_out);
    R2oTcpCounters {
        data_packets: (r2o_length >= r2o_packets_end).then_some(
            r2o_info
                .tcpi_data_segs_in
                .saturating_add(r2o_info.tcpi_data_segs_out),
        ),
    }
}

fn r2o_http_connection_closes(headers: &[u8]) -> bool {
    headers
        .split(|byte| *byte == b'\n')
        .skip(1)
        .filter_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|byte| *byte == b':')?;
            line[..colon]
                .eq_ignore_ascii_case(b"connection")
                .then_some(&line[colon + 1..])
        })
        .any(|value| {
            value
                .split(|byte| *byte == b',')
                .any(|token| trim_ascii(token).eq_ignore_ascii_case(b"close"))
        })
}

fn r2o_measure_http_packet_budget(
    stream: &mut StreamOwned<rustls::ClientConnection, R2oTlsTcpStream>,
    options: &FetchOptions,
    encoding: R2oFetchEncoding,
    deadline: Instant,
    need: u32,
    mut connection_close: bool,
    packet_counter: &mut impl FnMut(&TcpStream) -> Option<u32>,
) -> crate::r2o_volume::R2oVolumePacketBudget {
    use crate::r2o_volume::R2oVolumePacketBudget as Budget;

    let Some(mut packets) = packet_counter(&stream.sock.socket) else {
        return Budget::NotApplicable;
    };
    let mut previous = None;
    loop {
        if packets >= need {
            return Budget::Passed;
        }
        if connection_close || previous.is_some_and(|last| packets <= last) {
            return Budget::NotApplicable;
        }
        previous = Some(packets);

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Budget::Cut;
        }
        if stream
            .sock
            .socket
            .set_write_timeout(Some(remaining))
            .is_err()
        {
            return Budget::NotApplicable;
        }
        let request = build_request(&options.name, &options.path, encoding);
        if stream
            .write_all(&request)
            .and_then(|()| stream.flush())
            .is_err()
        {
            return Budget::NotApplicable;
        }
        let mut parser = HttpResponseParser::new(false);
        let mut buffer = [0_u8; 16 * 1024];
        let mut eof = false;
        while !parser.is_complete() && !parser.is_invalid() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Budget::Cut;
            }
            if stream
                .sock
                .socket
                .set_read_timeout(Some(remaining))
                .is_err()
            {
                return Budget::NotApplicable;
            }
            match stream.read(&mut buffer) {
                Ok(0) => {
                    eof = true;
                    parser.feed(&[], true);
                    break;
                }
                Ok(length) => parser.feed(&buffer[..length], false),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Budget::Cut;
                }
                Err(_) => return Budget::NotApplicable,
            }
        }
        if parser.is_invalid() || !parser.is_complete() {
            return Budget::NotApplicable;
        }
        connection_close = eof || r2o_http_connection_closes(parser.headers());
        let Some(current) = packet_counter(&stream.sock.socket) else {
            return Budget::NotApplicable;
        };
        packets = current;
    }
}

#[cfg(not(target_os = "linux"))]
fn r2o_tcp_counters(_stream: &TcpStream) -> R2oTcpCounters {
    R2oTcpCounters::default()
}

fn header_value<'a>(headers: &'a [u8], expected: &'a [u8]) -> Option<&'a [u8]> {
    header_values(headers, expected).next()
}

fn header_values<'a>(headers: &'a [u8], expected: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
    headers
        .split(|byte| *byte == b'\n')
        .skip(1)
        .filter_map(|line| line.strip_suffix(b"\r"))
        .filter_map(move |line| {
            let colon = line.iter().position(|byte| *byte == b':')?;
            line[..colon]
                .eq_ignore_ascii_case(expected)
                .then_some(trim_ascii(&line[colon + 1..]))
        })
}

fn r2o_fetch_same_origin_redirect(location: &str, host: &str) -> Option<String> {
    let value = location.as_bytes();
    if value
        .iter()
        .any(|&byte| byte <= 0x20 || byte == 0x7f || byte == b'#')
    {
        return None;
    }

    let mut path = value;
    if value.len() >= 8 && value[..8].eq_ignore_ascii_case(b"https://") {
        let authority_start = 8;
        let authority_end = value[authority_start..]
            .iter()
            .position(|&byte| matches!(byte, b'/' | b'?' | b'#'))
            .map_or(value.len(), |offset| authority_start + offset);
        let authority = &value[authority_start..authority_end];
        let same_host = authority.eq_ignore_ascii_case(host.as_bytes())
            || authority.len() == host.len() + 4
                && authority[..host.len()].eq_ignore_ascii_case(host.as_bytes())
                && authority[host.len()..].eq_ignore_ascii_case(b":443");
        if !same_host {
            return None;
        }
        path = &value[authority_end..];
        if path.first() == Some(&b'?') {
            let mut with_root = Vec::with_capacity(path.len() + 1);
            with_root.push(b'/');
            with_root.extend_from_slice(path);
            return String::from_utf8(with_root).ok();
        }
        if path.first() != Some(&b'/') {
            path = b"/";
        }
    } else if path.first() != Some(&b'/') {
        return None;
    }

    if path.is_empty()
        || path.len() >= 1024
        || path[0] != b'/'
        || path
            .iter()
            .any(|&byte| byte <= 0x20 || byte == 0x7f || byte == b'#')
    {
        return None;
    }
    String::from_utf8(path.to_vec()).ok()
}

fn r2o_fetch_external_https_redirect(status: u16, location: &[u8]) -> bool {
    if !matches!(status, 301 | 302 | 303 | 307 | 308)
        || location.len() < 9
        || !location[..8].eq_ignore_ascii_case(b"https://")
    {
        return false;
    }
    let authority_end = location[8..]
        .iter()
        .position(|&byte| matches!(byte, b'/' | b'?' | b'#'))
        .map_or(location.len(), |offset| offset + 8);
    let authority = &location[8..authority_end];
    let host_chars = authority
        .iter()
        .filter(|&&byte| byte.is_ascii_alphanumeric())
        .count();
    host_chars != 0
        && authority.iter().all(|&byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
        && location[authority_end..]
            .iter()
            .all(|&byte| byte > 0x20 && byte != 0x7f)
}

fn r2o_fetch_http_outcome(
    status: u16,
    location: &[u8],
    identity_encoding: bool,
    body_prefix: &[u8],
    body_total: u64,
) -> R2oFetchHttpOutcome {
    if status == 451 {
        return R2oFetchHttpOutcome::LegalDenial;
    }
    if (200..300).contains(&status) || status == 304 {
        return R2oFetchHttpOutcome::Positive;
    }
    if matches!(status, 301 | 302 | 303 | 307 | 308) {
        if r2o_fetch_portal_location(location).is_some() {
            return R2oFetchHttpOutcome::Blocked;
        }
        return if location.first() == Some(&b'/')
            && location.get(1).is_some_and(|byte| *byte != b'/')
        {
            R2oFetchHttpOutcome::Positive
        } else {
            R2oFetchHttpOutcome::Neutral
        };
    }
    if !(400..=599).contains(&status) || !identity_encoding {
        return R2oFetchHttpOutcome::Neutral;
    }
    if r2o_fetch_ascii_contains(body_prefix, b"access blocked by rkn")
        || r2o_fetch_body_has_portal(body_prefix, body_total)
    {
        R2oFetchHttpOutcome::Blocked
    } else {
        R2oFetchHttpOutcome::Neutral
    }
}

fn r2o_fetch_portal_location(location: &[u8]) -> Option<&'static str> {
    let mut authority = if location.len() >= 7 && location[..7].eq_ignore_ascii_case(b"http://") {
        &location[7..]
    } else if location.len() >= 8 && location[..8].eq_ignore_ascii_case(b"https://") {
        &location[8..]
    } else if location.starts_with(b"//") {
        &location[2..]
    } else {
        return None;
    };
    let end = authority
        .iter()
        .position(|&byte| matches!(byte, b'/' | b'?' | b'#') || byte <= 0x20)
        .unwrap_or(authority.len());
    authority = &authority[..end];
    if let Some(userinfo) = authority.iter().rposition(|&byte| byte == b'@') {
        authority = &authority[userinfo + 1..];
    }
    if let Some(colon) = authority.iter().rposition(|&byte| byte == b':')
        && colon + 1 < authority.len()
        && authority[colon + 1..].iter().all(u8::is_ascii_digit)
    {
        authority = &authority[..colon];
    }
    let authority = authority.strip_suffix(b".").unwrap_or(authority);
    [
        (b"eais.rkn.gov.ru" as &[u8], "eais.rkn.gov.ru"),
        (b"lawfilter.ertelecom.ru", "lawfilter.ertelecom.ru"),
        (b"blackhole.svyaztelecom.ru", "blackhole.svyaztelecom.ru"),
        (b"warning.rt.ru", "warning.rt.ru"),
        (b"warn.beeline.ru", "warn.beeline.ru"),
        (b"deny.megafon.ru", "deny.megafon.ru"),
    ]
    .into_iter()
    .find_map(|(known, name)| authority.eq_ignore_ascii_case(known).then_some(name))
}

fn r2o_fetch_ascii_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn r2o_fetch_body_has_portal(body: &[u8], total: u64) -> bool {
    const PORTALS: [&[u8]; 6] = [
        b"eais.rkn.gov.ru",
        b"lawfilter.ertelecom.ru",
        b"blackhole.svyaztelecom.ru",
        b"warning.rt.ru",
        b"warn.beeline.ru",
        b"deny.megafon.ru",
    ];
    PORTALS.iter().any(|portal| {
        body.windows(portal.len())
            .enumerate()
            .any(|(start, window)| {
                if !window.eq_ignore_ascii_case(portal)
                    || start != 0 && r2o_fetch_http_host_char(body[start - 1])
                    || start + portal.len() == body.len() && total > body.len() as u64
                {
                    return false;
                }
                start + portal.len() == body.len()
                    || !r2o_fetch_http_host_char(body[start + portal.len()])
            })
    })
}

fn r2o_fetch_http_host_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn resolve_target(options: &FetchOptions) -> Result<SocketAddr, String> {
    if let Some(ip) = options.ip {
        return Ok(SocketAddr::new(ip, options.port));
    }
    (options.name.as_str(), options.port)
        .to_socket_addrs()
        .map_err(|error| format!("имя {} не разрешилось: {error}", options.name))?
        .next()
        .ok_or_else(|| format!("для имени {} не найден адрес", options.name))
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        Err("срок ожидания TLS/HTTP-запроса истёк".into())
    } else {
        Ok(duration)
    }
}

fn set_deadline(stream: &TcpStream, deadline: Instant) -> Result<(), String> {
    let timeout = remaining(deadline)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| format!("не удалось задать срок ожидания сокета: {error}"))
}

#[derive(Debug)]
struct ConnectTargetError {
    source: io::Error,
    local_refusal: bool,
}

impl ConnectTargetError {
    fn ordinary(source: io::Error) -> Self {
        Self {
            source,
            local_refusal: false,
        }
    }

    fn local_refusal(source: io::Error) -> Self {
        Self {
            source,
            local_refusal: true,
        }
    }
}

impl From<io::Error> for ConnectTargetError {
    fn from(source: io::Error) -> Self {
        Self::ordinary(source)
    }
}

impl std::fmt::Display for ConnectTargetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

fn connect_target(
    address: SocketAddr,
    mark: Option<u32>,
    timeout: Duration,
) -> Result<TcpStream, ConnectTargetError> {
    if let Some(mark) = effective_mark(mark) {
        return connect_marked(address, mark, timeout);
    }
    TcpStream::connect_timeout(&address, timeout).map_err(Into::into)
}

#[cfg(target_os = "linux")]
fn connect_marked(
    address: SocketAddr,
    mark: u32,
    timeout: Duration,
) -> Result<TcpStream, ConnectTargetError> {
    connect_marked_with_setter(address, mark, timeout, |fd, mark| {
        set_socket_option(fd, libc::SOL_SOCKET, SO_MARK, mark as libc::c_int)
    })
}

#[cfg(target_os = "linux")]
fn connect_marked_with_setter(
    address: SocketAddr,
    mark: u32,
    timeout: Duration,
    set_mark: impl FnOnce(std::os::fd::RawFd, u32) -> io::Result<()>,
) -> Result<TcpStream, ConnectTargetError> {
    use std::os::fd::RawFd;

    let domain = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let raw_fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::IPPROTO_TCP,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let fd = owned.as_raw_fd();
    set_mark(fd, mark).map_err(ConnectTargetError::local_refusal)?;
    set_socket_option(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)?;
    let connect_result = connect_socket(fd, address)?;
    if connect_result != 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINPROGRESS | libc::EALREADY | libc::EINTR)
        ) {
            return Err(error.into());
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "слишком долгий срок"))?;
        let mut poll_descriptor = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "истёк срок подключения").into(),
                );
            }
            let millis = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
            let result = unsafe { libc::poll(&mut poll_descriptor, 1, millis) };
            if result > 0 {
                break;
            }
            if result == 0 {
                continue;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        let mut socket_error: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if socket_error != 0 {
            return Err(io::Error::from_raw_os_error(socket_error).into());
        }
    }
    let fd: RawFd = owned.into_raw_fd();
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
fn connect_marked(
    _address: SocketAddr,
    _mark: u32,
    _timeout: Duration,
) -> Result<TcpStream, ConnectTargetError> {
    Err(ConnectTargetError::local_refusal(io::Error::new(
        io::ErrorKind::Unsupported,
        "метка SO_MARK доступна только в Linux",
    )))
}

#[cfg(target_os = "linux")]
fn set_socket_option(
    fd: libc::c_int,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn connect_socket(fd: libc::c_int, address: SocketAddr) -> io::Result<libc::c_int> {
    match address {
        SocketAddr::V4(address) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            let result = unsafe {
                libc::connect(
                    fd,
                    (&raw as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&raw) as libc::socklen_t,
                )
            };
            Ok(result)
        }
        SocketAddr::V6(address) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            let result = unsafe {
                libc::connect(
                    fd,
                    (&raw as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of_val(&raw) as libc::socklen_t,
                )
            };
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r2o_volume::R2oVolumeRxEncoding;

    #[test]
    fn нулевая_tcp_метка_означает_обычный_непомеченный_сокет() {
        assert_eq!(effective_mark(None), None);
        assert_eq!(effective_mark(Some(0)), None);
        assert_eq!(effective_mark(Some(0x2f)), Some(0x2f));
    }

    fn response_for_classification(
        status: u16,
        http_outcome: R2oFetchHttpOutcome,
        complete: bool,
        application_verified: bool,
    ) -> FetchResult {
        FetchResult {
            address: "127.0.0.1:443".parse().unwrap(),
            local_port: 0,
            tls: Some("1.3"),
            status,
            http_outcome,
            cloudflare_challenge: false,
            body_bytes: 20 * 1024,
            body_expected: Some(20 * 1024),
            body_has_length: true,
            location: String::new(),
            chunked: false,
            gzip: false,
            complete,
            application_verified,
            elapsed: Duration::ZERO,
            reason: None,
            r2o_volume_observation: crate::r2o_volume::R2oVolumeObservation::default(),
            r2o_resources: Vec::new(),
        }
    }

    #[test]
    fn http_отказы_не_становятся_прямым_ответом_или_подсказками_ресурсов() {
        let accepted = response_for_classification(200, R2oFetchHttpOutcome::Neutral, true, true);
        assert!(r2o_fetch_result_is_direct_complete(&accepted));
        assert!(r2o_fetch_result_can_remember_resources(&accepted));

        for outcome in [
            R2oFetchHttpOutcome::Blocked,
            R2oFetchHttpOutcome::LegalDenial,
        ] {
            let refusal = response_for_classification(200, outcome, true, false);
            assert!(!r2o_fetch_result_is_direct_complete(&refusal));
            assert!(!r2o_fetch_result_can_remember_resources(&refusal));
        }

        let incomplete =
            response_for_classification(200, R2oFetchHttpOutcome::Neutral, false, false);
        assert!(!r2o_fetch_result_is_direct_complete(&incomplete));
        assert!(!r2o_fetch_result_can_remember_resources(&incomplete));

        let missing_page =
            response_for_classification(404, R2oFetchHttpOutcome::Neutral, true, true);
        assert!(!r2o_fetch_result_is_direct_complete(&missing_page));
        assert!(!r2o_fetch_result_can_remember_resources(&missing_page));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ошибка_установки_tcp_метки_классифицируется_как_локальный_отказ() {
        let error = connect_marked_with_setter(
            "127.0.0.1:443".parse().unwrap(),
            0x2f,
            Duration::from_secs(1),
            |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "тестовый отказ SO_MARK",
                ))
            },
        )
        .unwrap_err();

        assert!(error.local_refusal);
        assert_eq!(error.source.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn запрос_проверки_передаёт_выбранное_кодирование() {
        let identity = build_request("example.com", "/", R2oFetchEncoding::Identity);
        let gzip = build_request("example.com", "/", R2oFetchEncoding::Gzip);

        assert!(
            identity
                .windows(b"Accept-Encoding: identity".len())
                .any(|window| window == b"Accept-Encoding: identity")
        );
        assert!(
            gzip.windows(b"Accept-Encoding: gzip".len())
                .any(|window| window == b"Accept-Encoding: gzip")
        );
    }

    #[test]
    fn сканирование_ресурсов_доступно_только_для_identity_html_без_challenge() {
        let html = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n";
        assert!(r2o_fetch_resource_scan_allowed(200, html));
        assert!(!r2o_fetch_resource_scan_allowed(
            200,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n"
        ));
        assert!(!r2o_fetch_resource_scan_allowed(
            200,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\ncf-mitigated: challenge\r\n\r\n"
        ));
        assert!(!r2o_fetch_resource_scan_allowed(
            200,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n"
        ));
        assert!(!r2o_fetch_resource_scan_allowed(403, html));
    }

    #[test]
    fn r2o_fetch_отличает_точный_cf_challenge_от_похожих_заголовков() {
        assert!(r2o_fetch_is_cloudflare_challenge(
            b"HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\n\r\n"
        ));
        assert!(!r2o_fetch_is_cloudflare_challenge(
            b"HTTP/1.1 403 Forbidden\r\nx-cf-mitigated: challenge\r\n\r\n"
        ));
        assert!(!r2o_fetch_is_cloudflare_challenge(
            b"HTTP/1.1 403 Forbidden\r\ncf-mitigated: not-a-challenge\r\n\r\n"
        ));
    }

    #[test]
    fn классификатор_кодирования_отвергает_неизвестную_и_составную_форму() {
        assert_eq!(
            r2o_fetch_body_encoding(b"HTTP/1.1 200 OK\r\n\r\n"),
            R2oVolumeRxEncoding::Identity
        );
        assert_eq!(
            r2o_fetch_body_encoding(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n"),
            R2oVolumeRxEncoding::Gzip
        );
        assert_eq!(
            r2o_fetch_body_encoding(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip, br\r\n\r\n"),
            R2oVolumeRxEncoding::Other
        );
        assert_eq!(
            r2o_fetch_body_encoding(
                b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\n\r\n"
            ),
            R2oVolumeRxEncoding::Other
        );
    }

    #[test]
    fn same_origin_redirects_are_safe_and_portals_match_donor_signatures() {
        assert_eq!(
            r2o_fetch_same_origin_redirect("/next?q=1", "example.com").as_deref(),
            Some("/next?q=1")
        );
        assert_eq!(
            r2o_fetch_same_origin_redirect("https://EXAMPLE.com:443/next", "example.com")
                .as_deref(),
            Some("/next")
        );
        assert_eq!(
            r2o_fetch_same_origin_redirect("https://example.com?next=1", "example.com").as_deref(),
            Some("/?next=1")
        );
        assert!(r2o_fetch_same_origin_redirect("https://other.example/", "example.com").is_none());
        assert!(r2o_fetch_same_origin_redirect("/next#fragment", "example.com").is_none());
        assert!(r2o_fetch_same_origin_redirect("/bad path", "example.com").is_none());
        assert!(r2o_fetch_external_https_redirect(
            302,
            b"https://other.example/next"
        ));
        assert!(!r2o_fetch_external_https_redirect(
            300,
            b"https://other.example/next"
        ));

        assert_eq!(
            r2o_fetch_http_outcome(
                302,
                b"https://user@WARNING.RT.RU.:443/blocked",
                true,
                &[],
                0,
            ),
            R2oFetchHttpOutcome::Blocked
        );
        assert_eq!(
            r2o_fetch_http_outcome(302, b"https://warning.rt.ru.evil.example/", true, &[], 0),
            R2oFetchHttpOutcome::Neutral
        );
        assert_eq!(
            r2o_fetch_http_outcome(302, b"/login", true, &[], 0),
            R2oFetchHttpOutcome::Positive
        );
        assert_eq!(
            r2o_fetch_http_outcome(403, b"", true, b"Access Blocked By RKN", 21),
            R2oFetchHttpOutcome::Blocked
        );
        assert_eq!(
            r2o_fetch_http_outcome(403, b"", true, b"eais.rkn.gov.ru", 15),
            R2oFetchHttpOutcome::Blocked
        );
        assert_eq!(
            r2o_fetch_http_outcome(403, b"", true, b"eais.rkn.gov.ru", 16),
            R2oFetchHttpOutcome::Neutral
        );
        assert_eq!(
            r2o_fetch_http_outcome(403, b"", false, b"access blocked by rkn", 21),
            R2oFetchHttpOutcome::Neutral
        );
        assert_eq!(
            r2o_fetch_http_outcome(403, b"", true, b"xnot-eais.rkn.gov.ru", 20),
            R2oFetchHttpOutcome::Neutral
        );
        assert_eq!(
            r2o_fetch_http_outcome(451, b"", true, &[], 0),
            R2oFetchHttpOutcome::LegalDenial
        );

        let mut body = crate::r2o_resource::R2oResourceBodyTap::new_body_only(true);
        body.feed(b"5\r\neais.");
        body.feed(b"\r\nA\r\nrkn.gov.ru\r\n0\r\n\r\n");
        assert_eq!(body.prefix(), b"eais.rkn.gov.ru");
    }

    #[test]
    fn https_fetch_follows_same_origin_redirects_on_the_original_tls_connection() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().expect("принять HTTPS-соединение");
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, socket);
            let mut requests = Vec::new();
            for response in [
                &b"HTTP/1.1 302 Found\r\nLocation: /landing\r\nContent-Length: 0\r\n\r\n"[..],
                &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npage"[..],
            ]
            .into_iter()
            {
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream
                        .read_exact(&mut byte)
                        .expect("прочитать заголовки запроса");
                    request.push(byte[0]);
                }
                requests.push(request);
                stream.write_all(response).expect("отправить HTTP-ответ");
                stream.flush().expect("сбросить HTTP-ответ");
            }
            request_sender.send(requests).unwrap();
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let result = r2o_fetch_with_roots_and_encoding(&options, R2oFetchEncoding::Identity, roots)
            .expect("завершить HTTPS-замер с redirect");
        let requests = request_receiver.recv().expect("получить оба HTTP-запроса");
        server.join().unwrap();

        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with(b"GET / HTTP/1.1\r\n"));
        assert!(requests[1].starts_with(b"GET /landing HTTP/1.1\r\n"));
        assert_eq!(result.status, 200);
        assert_eq!(result.http_outcome, R2oFetchHttpOutcome::Positive);
        assert!(result.complete);
        assert!(result.application_verified);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tx_packet_budget_repeats_complete_gets_on_the_same_tls_connection() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().expect("принять HTTPS-соединение");
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, socket);
            let large_body = vec![b'x'; 256 * 1024];
            let mut requests = 0;
            for body in [&b"denied"[..], &b"denied-again"[..], large_body.as_slice()] {
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream
                        .read_exact(&mut byte)
                        .expect("прочитать заголовки запроса");
                    request.push(byte[0]);
                }
                requests += 1;
                let headers = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).unwrap();
                stream.write_all(body).unwrap();
                stream.flush().unwrap();
            }
            let mut extra = [0_u8; 1];
            let third_request = stream.read(&mut extra).unwrap_or(0) != 0;
            request_sender.send((requests, third_request)).unwrap();
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/denied".into(),
            deadline: Duration::from_secs(5),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let stream = TcpStream::connect(address).expect("подключить HTTPS-пробу");
        let mut packet_counts = [4, 12, 51].into_iter();
        let result = r2o_fetch_connected_stream_with_roots_and_encoding_and_counter(
            &options,
            stream,
            address,
            Instant::now(),
            R2oFetchEncoding::Identity,
            roots,
            None,
            Some(50),
            |_| packet_counts.next(),
        )
        .expect("завершить HTTP-проверку бюджета TCP");
        assert_eq!(result.status, 403);
        assert!(result.complete);
        assert!(result.application_verified);
        assert_eq!(
            result.r2o_volume_observation.packet_budget,
            crate::r2o_volume::R2oVolumePacketBudget::Passed
        );
        assert_eq!(
            request_receiver.recv().expect("получить число запросов"),
            (3, false)
        );
        server.join().unwrap();
    }

    #[test]
    fn https_замер_сохраняет_частичное_тело_tls_и_сетевые_счётчики() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().expect("принять HTTPS-соединение");
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream
                    .read_exact(&mut byte)
                    .expect("прочитать заголовки запроса");
                request.push(byte[0]);
            }
            request_sender.send(request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Encoding: gzip\r\n\r\nabc",
                )
                .expect("отправить неполный ответ");
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let result = r2o_fetch_with_roots_and_encoding(&options, R2oFetchEncoding::Gzip, roots)
            .expect("завершить HTTPS-замер");
        let request = request_receiver.recv().expect("получить HTTP-запрос");
        server.join().unwrap();

        assert!(
            request
                .windows(b"Accept-Encoding: gzip".len())
                .any(|window| window == b"Accept-Encoding: gzip")
        );
        assert_eq!(result.status, 200);
        assert_eq!(result.body_bytes, 3);
        assert_eq!(result.body_expected, Some(12));
        assert!(!result.complete);
        assert_eq!(
            result.r2o_volume_observation.body_encoding,
            R2oVolumeRxEncoding::Gzip
        );
        assert!(result.r2o_volume_observation.body_framing_valid);
        assert!(!result.r2o_volume_observation.rx_tls_record_missing);
        assert!(result.r2o_volume_observation.rx_tls_wire_bytes > 0);
    }

    #[test]
    fn https_замер_подтверждает_неполное_тело_tls_записи() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let mut server_config =
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der.clone()], private_key)
                .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        let address = listener.local_addr().unwrap();
        let (alpn_sender, alpn_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().expect("принять HTTPS-соединение");
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream
                    .read_exact(&mut byte)
                    .expect("прочитать заголовки запроса");
                request.push(byte[0]);
            }
            alpn_sender
                .send(stream.conn.alpn_protocol().map(<[u8]>::to_vec))
                .unwrap();
            stream
                .conn
                .writer()
                .write_all(&vec![b'x'; 16_000])
                .expect("поставить TLS-данные в очередь");
            let mut encrypted = Vec::new();
            stream
                .conn
                .write_tls(&mut encrypted)
                .expect("зашифровать TLS-запись");
            assert!(encrypted.len() > 12 * 1024);
            stream
                .sock
                .write_all(&encrypted[..12 * 1024])
                .expect("отправить только часть TLS-записи");
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: true,
            wire_len: None,
            mark: None,
        };
        let result = r2o_fetch_with_roots_and_encoding(&options, R2oFetchEncoding::Identity, roots)
            .expect("завершить HTTPS-замер");
        server.join().unwrap();

        assert_eq!(result.status, 0);
        assert_eq!(result.tls, Some("1.2"));
        assert_eq!(
            alpn_receiver.recv().unwrap().as_deref(),
            Some(&b"http/1.1"[..])
        );
        assert!(result.r2o_volume_observation.rx_tls_record_missing);
        assert!(result.r2o_volume_observation.rx_tls_wire_bytes >= 12 * 1024);
        assert!(crate::r2o_volume::r2o_volume_rx_partial(
            &result.r2o_volume_observation
        ));
    }

    #[test]
    fn rx_повторяет_тот_же_запрос_после_незавершённого_tls_ответа() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        fn accept_before(listener: &TcpListener) -> TcpStream {
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            loop {
                match listener.accept() {
                    Ok((socket, _)) => return socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "повторный RX-запрос не пришёл"
                        );
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("принять RX-запрос: {error}"),
                }
            }
        }

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der.clone()], private_key)
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            for attempt in 0..2 {
                let socket = accept_before(&listener);
                let connection = ServerConnection::new(server_config.clone()).unwrap();
                let mut stream = StreamOwned::new(connection, socket);
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).expect("прочитать RX-запрос");
                    request.push(byte[0]);
                }
                request_sender.send(request).unwrap();
                if attempt == 0 {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
                        .expect("оборвать первый RX-ответ");
                } else {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Type: text/plain\r\n\r\nx")
                        .expect("завершить повторный RX-ответ");
                }
            }
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/same".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let result = r2o_fetch_rx_probe(&options, R2oFetchEncoding::Identity, roots)
            .expect("завершить повторный RX-запрос");
        let requests = request_receiver.try_iter().collect::<Vec<_>>();
        server.join().unwrap();

        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.starts_with(b"GET /same HTTP/1.1\r\n"))
        );
        assert_eq!(result.status, 200);
        assert!(result.complete);
        assert_eq!(result.body_bytes, 1);
    }

    #[test]
    fn rx_объём_решает_противоречие_третьим_identity_и_gzip_контролем() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der.clone()], private_key)
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            for attempt in 0..4 {
                let (socket, _) = listener.accept().expect("принять HTTPS-соединение");
                let connection = ServerConnection::new(server_config.clone()).unwrap();
                let mut stream = StreamOwned::new(connection, socket);
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream
                        .read_exact(&mut byte)
                        .expect("прочитать заголовки запроса");
                    request.push(byte[0]);
                }
                request_sender.send(request).unwrap();
                let (encoding, length, body_length) = match attempt {
                    0 | 2 => ("identity", 20 * 1024, 16 * 1024),
                    1 => ("identity", 16 * 1024, 16 * 1024),
                    _ => ("gzip", 2 * 1024, 2 * 1024),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nContent-Encoding: {encoding}\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("отправить заголовки ответа");
                stream
                    .write_all(&vec![b'x'; body_length])
                    .expect("отправить тело ответа");
            }
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let result = r2o_fetch_measure_rx_volume_with_roots(&options, roots);
        let requests = request_receiver
            .try_iter()
            .map(|request| String::from_utf8_lossy(&request).to_ascii_lowercase())
            .collect::<Vec<_>>();
        server.join().unwrap();

        assert_eq!(requests.len(), 4);
        assert!(requests[0].contains("accept-encoding: identity"));
        assert!(requests[1].contains("accept-encoding: identity"));
        assert!(requests[2].contains("accept-encoding: identity"));
        assert!(requests[3].contains("accept-encoding: gzip"));
        assert!(result.first.is_some());
        assert!(
            result
                .second
                .as_ref()
                .is_some_and(|response| response.complete)
        );
        assert!(result.third.is_some());
        assert!(
            result
                .gzip
                .as_ref()
                .is_some_and(|response| response.complete)
        );
        let evidence = result.evidence.expect("получить RX-вердикт");
        assert_eq!(
            evidence.domain,
            crate::r2o_volume::R2oVolumeRxDomain::HttpBody
        );
        assert_eq!(evidence.cut_kb, 16);
        assert!(result.reason.contains("identity-тело"));
    }

    #[test]
    fn rx_короткий_html_один_раз_повторяется_по_css_того_же_имени() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der.clone()], private_key)
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            for attempt in 0..2 {
                let (socket, _) = listener.accept().expect("принять HTTPS-соединение");
                let connection = ServerConnection::new(server_config.clone()).unwrap();
                let mut stream = StreamOwned::new(connection, socket);
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream
                        .read_exact(&mut byte)
                        .expect("прочитать заголовки запроса");
                    request.push(byte[0]);
                }
                request_sender
                    .send(String::from_utf8_lossy(&request).into_owned())
                    .unwrap();
                let (content_type, body) = if attempt == 0 {
                    (
                        "text/html",
                        b"<link rel=stylesheet href='https://localhost/css/site.css'>".to_vec(),
                    )
                } else {
                    ("text/css", vec![b'x'; 128])
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("отправить заголовки ответа");
                stream.write_all(&body).expect("отправить тело ответа");
            }
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let result = r2o_fetch_measure_rx_volume_with_roots(&options, roots);
        let requests = request_receiver.try_iter().collect::<Vec<_>>();
        server.join().unwrap();

        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET / HTTP/1.1\r\n"));
        assert!(requests[1].starts_with("GET /css/site.css HTTP/1.1\r\n"));
        assert_eq!(result.retry_path.as_deref(), Some("/css/site.css"));
        assert_eq!(result.short_bytes, Some(128));
        assert!(result.reason.contains("после короткого ответа"));
    }

    #[test]
    fn запасной_путь_принимается_только_с_доказанным_rx_обрывом() {
        let primary = R2oFetchVolumeRxResult {
            short_bytes: Some(243),
            direct_complete: true,
            reason: "основной путь ответил коротким телом".into(),
            ..Default::default()
        };
        let fallback = R2oFetchVolumeRxResult {
            short_bytes: Some(512),
            reason: "запасной путь тоже короткий".into(),
            ..Default::default()
        };

        let kept = r2o_fetch_rx_fallback_result(primary.clone(), fallback, "/css/known.css", 243);
        assert_eq!(kept.short_bytes, Some(243));
        assert!(kept.evidence.is_none());
        assert!(kept.reason.contains("основной путь"));

        let proven = R2oFetchVolumeRxResult {
            evidence: Some(crate::r2o_volume::R2oVolumeRxEvidence {
                domain: crate::r2o_volume::R2oVolumeRxDomain::HttpBody,
                cut_kb: 16,
                expected_kb: 20,
                cut_packets: 0,
                compressed_complete: true,
                reason: "identity-тело оборвано".into(),
            }),
            ..Default::default()
        };
        let selected = r2o_fetch_rx_fallback_result(primary, proven, "/css/known.css", 243);
        assert!(selected.evidence.is_some());
        assert_eq!(selected.measured_path.as_deref(), Some("/css/known.css"));
        assert_eq!(selected.retry_path.as_deref(), Some("/css/known.css"));
    }

    #[test]
    fn rx_короткий_ответ_повторяется_по_уже_наблюдавшемуся_пути() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der.clone()], private_key)
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            for attempt in 0..5 {
                let (socket, _) = listener.accept().expect("принять HTTPS-соединение");
                let connection = ServerConnection::new(server_config.clone()).unwrap();
                let mut stream = StreamOwned::new(connection, socket);
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream
                        .read_exact(&mut byte)
                        .expect("прочитать заголовки запроса");
                    request.push(byte[0]);
                }
                request_sender.send(request).unwrap();
                let (encoding, length, body_length) = match attempt {
                    0 => ("identity", 128, 128),
                    1 | 3 => ("identity", 20 * 1024, 16 * 1024),
                    2 => ("identity", 16 * 1024, 16 * 1024),
                    _ => ("gzip", 2 * 1024, 2 * 1024),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nContent-Encoding: {encoding}\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("отправить заголовки ответа");
                stream
                    .write_all(&vec![b'x'; body_length])
                    .expect("отправить тело ответа");
            }
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let result = r2o_fetch_measure_rx_volume_with_fallback_path_and_roots(
            &options,
            Some("/css/known.css"),
            roots,
        );
        let requests = request_receiver
            .try_iter()
            .map(|request| String::from_utf8_lossy(&request).to_ascii_lowercase())
            .collect::<Vec<_>>();
        server.join().unwrap();

        assert_eq!(requests.len(), 5);
        assert!(requests[0].starts_with("get / http/1.1\r\n"));
        assert!(
            requests[1..]
                .iter()
                .all(|request| request.starts_with("get /css/known.css http/1.1\r\n"))
        );
        assert_eq!(result.measured_path.as_deref(), Some("/css/known.css"));
        assert_eq!(result.retry_path.as_deref(), Some("/css/known.css"));
        assert_eq!(
            result.evidence.as_ref().map(|evidence| evidence.cut_kb),
            Some(16)
        );
        assert!(result.reason.contains("запасной путь"));
    }

    #[test]
    fn rx_сохраняет_исходный_короткий_ответ_если_tls_css_повтор_не_начался() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der.clone()], private_key)
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().expect("принять исходный запрос");
            let connection = ServerConnection::new(server_config.clone()).unwrap();
            let mut stream = StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream
                    .read_exact(&mut byte)
                    .expect("прочитать исходный запрос");
                request.push(byte[0]);
            }
            let body = b"<link rel=stylesheet href='https://localhost/css/site.css'>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("отправить заголовки исходного ответа");
            stream
                .write_all(body)
                .expect("отправить исходное короткое тело");
            drop(stream);

            let (socket, _) = listener.accept().expect("принять CSS-повтор");
            drop(socket);
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let result = r2o_fetch_measure_rx_volume_with_roots(&options, roots);
        server.join().unwrap();

        assert_eq!(result.retry_path.as_deref(), Some("/css/site.css"));
        assert_eq!(
            result.short_bytes,
            result.first.as_ref().map(|response| response.body_bytes)
        );
        assert!(result.direct_complete);
        assert!(
            result
                .first
                .as_ref()
                .is_some_and(|response| response.complete)
        );
        assert!(result.rx_tls_unavailable);
        assert!(result.reason.contains("исходный ответ завершился"));
    }

    #[test]
    fn исходящая_лестница_отправляет_десять_head_шагов_в_одном_tls_потоке() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().expect("принять HTTPS-соединение");
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, socket);
            for _ in 0..R2O_VOLUME_TX_STEPS {
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).expect("прочитать HEAD-запрос");
                    request.push(byte[0]);
                }
                request_sender.send(request).unwrap();
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .expect("ответить на HEAD-запрос");
            }
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let result = r2o_fetch_measure_tx_volume_with_roots(&options, roots).unwrap();
        let requests = request_receiver
            .try_iter()
            .map(|request| String::from_utf8_lossy(&request).into_owned())
            .collect::<Vec<_>>();
        server.join().unwrap();

        assert_eq!(result.verdict, R2oFetchVolumeTxVerdict::Passed);
        assert_eq!(result.at_kb, 39);
        assert_eq!(requests.len(), 10);
        assert!(requests[0].starts_with("HEAD / HTTP/1.1\r\n"));
        assert!(!requests[0].contains("X-Pad:"));
        for request in &requests[1..] {
            let padding = request
                .split_once("\r\nX-Pad: ")
                .and_then(|(_, tail)| tail.split_once("\r\n"))
                .map(|(padding, _)| padding)
                .unwrap();
            assert_eq!(padding.len(), R2O_VOLUME_TX_CHUNK_BYTES);
            assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn исходящая_лестница_считает_обрыв_после_двенадцати_килобайт() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("создать сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть HTTPS-приёмник");
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().expect("принять HTTPS-соединение");
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, socket);
            for step in 0..5 {
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).expect("прочитать HEAD-запрос");
                    request.push(byte[0]);
                }
                request_sender.send(request).unwrap();
                if step != 4 {
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                        .expect("ответить на HEAD-запрос");
                }
            }
        });

        let options = FetchOptions {
            name: "localhost".into(),
            port: address.port(),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let result = r2o_fetch_measure_tx_volume_with_roots(&options, roots).unwrap();
        let requests = request_receiver.try_iter().count();
        server.join().unwrap();

        assert_eq!(requests, 5);
        assert_eq!(result.verdict, R2oFetchVolumeTxVerdict::Cut);
        assert_eq!(result.at_kb, 15);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn счётчики_tcp_info_содержат_принятые_байты_и_пакеты() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("открыть TCP-приёмник");
        let address = listener.local_addr().expect("адрес TCP-приёмника");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("принять соединение");
            let mut request = [0_u8; 8];
            stream.read_exact(&mut request).expect("прочитать запрос");
            stream.write_all(b"answer!!").expect("отправить ответ");
        });
        let mut stream = TcpStream::connect(address).expect("подключиться к TCP-приёмнику");
        stream.write_all(b"request!").expect("отправить запрос");
        let mut response = [0_u8; 8];
        stream.read_exact(&mut response).expect("прочитать ответ");
        server.join().expect("дождаться TCP-приёмника");

        let counters = r2o_tcp_counters(&stream);
        assert!(counters.data_packets.is_none_or(|packets| packets >= 2));
    }

    #[test]
    fn tls_счётчик_отличает_неполное_тело_записи_от_полной_записи() {
        let mut tracker = R2oTlsRecordTracker::default();
        tracker.observe(&[23, 3, 3, 0, 10, 1, 2, 3]);
        assert!(tracker.body_is_missing());
        tracker.observe(&[4, 5, 6, 7, 8, 9, 10]);
        assert!(!tracker.body_is_missing());
    }

    #[test]
    fn заданная_длина_client_hello_учитывает_заголовок_tls_записи() {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut connection =
            crate::r2o_tls::r2o_tls_client_connection("example.com", false, Some(1275), roots)
                .expect("создать TLS-соединение");
        let mut bytes = Vec::new();
        connection
            .write_tls(&mut bytes)
            .expect("записать ClientHello");

        let record_len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        assert_eq!(record_len + 5, 1275);
    }
}
