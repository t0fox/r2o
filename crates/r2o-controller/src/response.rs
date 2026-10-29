//! Наблюдение ответного направления TLS 1.2 и обработка вердиктов.

use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::classify::{
    ProbeError, ProbeOutcome, ProbeTarget, Trigger, split_offsets, trigger_accepts,
};
use crate::hello::legacy_client_hello;
use serde::{Deserialize, Serialize};

const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(6);
const PROBE_SEND_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scan12 {
    NeedMore,
    ServerHello,
    ServerHelloDone,
    FatalAlert,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseVerdict {
    NotApplicable,
    Clear,
    Blocked,
    Flaky,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseResult {
    pub verdict: ResponseVerdict,
    pub reason: String,
    pub target: i32,
    pub control: i32,
    pub probes: usize,
}

/// Ограничения одного замера ответного направления для цели и контроля.
#[derive(Clone, Copy, Debug)]
pub struct ResponseOptions {
    pub repeats: usize,
    pub timeout: Duration,
    /// `None` включает `R2O_BYPASS_MARK`; `Some(0)` отключает маркировку.
    pub mark: Option<u32>,
}

impl Default for ResponseOptions {
    fn default() -> Self {
        Self {
            repeats: 3,
            timeout: Duration::from_secs(3),
            mark: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Trial {
    Done,
    Failed,
    Unmeasured,
}

const RESPONSE_CAP: usize = 65_536;
const SO_MARK: libc::c_int = 36;
const BYPASS_MARK: u32 = 0x2d;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpsProbeState {
    Served,
    TlsBlocked,
    Closed,
    OtherName,
    Unconfirmed,
}

impl HttpsProbeState {
    pub const fn ttl_seconds(self) -> u32 {
        match self {
            Self::Served => 6 * 60 * 60,
            Self::TlsBlocked => 60 * 60,
            Self::Closed | Self::OtherName => 30 * 60,
            Self::Unconfirmed => 2 * 60,
        }
    }

    pub const fn should_redirect(self) -> bool {
        matches!(self, Self::Served | Self::TlsBlocked)
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Served => "TLS подтверждён, имя совпало с сертификатом",
            Self::TlsBlocked => "443 принимает соединение, но не отвечает TLS",
            Self::Closed => "порт 443 закрыт или недоступен",
            Self::OtherName => "сертификат TLS выдан для другого имени",
            Self::Unconfirmed => "HTTPS не удалось подтвердить",
        }
    }
}

fn response_timeout(timeout: Duration) -> Duration {
    let maximum = Duration::from_secs(3);
    if !timeout.is_zero() && timeout < maximum {
        timeout
    } else {
        maximum
    }
}

fn not_applicable(reason: String, target: i32, control: i32, probes: usize) -> ResponseResult {
    ResponseResult {
        verdict: ResponseVerdict::NotApplicable,
        reason,
        target,
        control,
        probes,
    }
}

fn resolve_address(host: &str, port: u16) -> Result<SocketAddr, String> {
    let ipv6 = host.contains(':');
    (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("не удалось разрешить адрес зонда: {error}"))?
        .find(|address| address.is_ipv6() == ipv6)
        .ok_or_else(|| "для зонда не найден адрес нужного семейства IP".to_owned())
}

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
            Ok(unsafe {
                libc::connect(
                    fd,
                    (&raw as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&raw) as libc::socklen_t,
                )
            })
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
            Ok(unsafe {
                libc::connect(
                    fd,
                    (&raw as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of_val(&raw) as libc::socklen_t,
                )
            })
        }
    }
}

fn connect_until(fd: libc::c_int, address: SocketAddr, timeout: Duration) -> io::Result<bool> {
    if connect_socket(fd, address)? == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(libc::EINPROGRESS | libc::EALREADY | libc::EINTR)
    ) {
        return Err(error);
    }
    let deadline = Instant::now() + timeout;
    if !poll_until(fd, libc::POLLOUT, deadline)? {
        return Ok(false);
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
        return Err(io::Error::last_os_error());
    }
    if socket_error != 0 {
        return Err(io::Error::from_raw_os_error(socket_error));
    }
    Ok(true)
}

fn probe_socket(address: SocketAddr, mark: u32) -> io::Result<OwnedFd> {
    let domain = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let raw_fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let fd = owned_fd.as_raw_fd();
    let _ = set_socket_option(fd, libc::SOL_SOCKET, SO_MARK, mark as libc::c_int);
    let _ = set_socket_option(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
    Ok(owned_fd)
}

pub fn probe_https_name(host: &str, address: SocketAddr, mark: Option<u32>) -> bool {
    probe_https_state(host, address, mark) == HttpsProbeState::Served
}

fn https_client_config() -> std::sync::Arc<rustls::ClientConfig> {
    let verifier = HttpsProbeVerifier {
        algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
    };
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
        .with_no_client_auth();
    std::sync::Arc::new(config)
}

#[derive(Debug)]
struct HttpsProbeVerifier {
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for HttpsProbeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // The donor classifies leaf SANs without a trust store; TLS signatures remain verified.
        if !https_certificate_der_is_parseable(end_entity.as_ref()) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn https_connection(
    config: std::sync::Arc<rustls::ClientConfig>,
    host: &str,
) -> Result<rustls::ClientConnection, HttpsProbeState> {
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| HttpsProbeState::Unconfirmed)?;
    rustls::ClientConnection::new(config, server_name).map_err(|_| HttpsProbeState::Unconfirmed)
}

fn https_certificate_der_is_parseable(der: &[u8]) -> bool {
    matches!(
        x509_parser::parse_x509_certificate(der),
        Ok((remaining, _)) if remaining.is_empty()
    )
}

pub(crate) fn https_certificate_name_matches(der: &[u8], host: &str) -> Option<bool> {
    const SUBJECT_ALT_NAME_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x11];
    let host = host.split('\0').next().unwrap_or_default();
    if host.is_empty() {
        return None;
    }
    let host_ip = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address.octets().to_vec(),
        Ok(IpAddr::V6(address)) => address.octets().to_vec(),
        Err(_) => Vec::new(),
    };

    for (offset, window) in der.windows(SUBJECT_ALT_NAME_OID.len()).enumerate() {
        if window != SUBJECT_ALT_NAME_OID {
            continue;
        }
        let Some(mut value_offset) = offset.checked_add(SUBJECT_ALT_NAME_OID.len()) else {
            continue;
        };
        if value_offset
            .checked_add(3)
            .is_some_and(|end| end <= der.len())
            && der[value_offset] == 0x01
            && der[value_offset + 1] == 0x01
        {
            value_offset += 3;
        }
        if der.get(value_offset) != Some(&0x04) {
            continue;
        }
        let (extension_len, extension_header) =
            https_der_length(der.get(value_offset + 1..).unwrap_or_default());
        if extension_len == 0 {
            continue;
        }
        let Some(general_names_start) = value_offset
            .checked_add(1)
            .and_then(|offset| offset.checked_add(extension_header))
        else {
            continue;
        };
        let Some(general_names_end) = general_names_start.checked_add(extension_len) else {
            continue;
        };
        let Some(general_names) = der.get(general_names_start..general_names_end) else {
            continue;
        };
        if general_names.len() < 2 || general_names[0] != 0x30 {
            continue;
        }
        let (names_len, names_header) =
            https_der_length(general_names.get(1..).unwrap_or_default());
        if names_len == 0 {
            continue;
        }
        let Some(names_start) = 1_usize.checked_add(names_header) else {
            continue;
        };
        let Some(names_end) = names_start.checked_add(names_len) else {
            continue;
        };
        let Some(mut names) = general_names.get(names_start..names_end) else {
            continue;
        };
        let (mut saw_dns, mut saw_ip) = (false, false);
        while names.len() >= 2 {
            let tag = names[0];
            let (name_len, name_header) = https_der_length(&names[1..]);
            let Some(entry_size) = 1_usize
                .checked_add(name_header)
                .and_then(|size| size.checked_add(name_len))
            else {
                break;
            };
            if entry_size > names.len() {
                break;
            }
            let name = &names[1 + name_header..entry_size];
            if tag == 0x82 {
                saw_dns = true;
                if host_ip.is_empty() && https_dns_name_bytes_match(name, host.as_bytes()) {
                    return Some(true);
                }
            } else if tag == 0x87 {
                saw_ip = true;
                if name == host_ip.as_slice() {
                    return Some(true);
                }
            }
            names = &names[entry_size..];
        }
        return (saw_dns || saw_ip).then_some(false);
    }
    None
}

fn https_der_length(bytes: &[u8]) -> (usize, usize) {
    let Some(&first) = bytes.first() else {
        return (0, 0);
    };
    if first < 0x80 {
        return (usize::from(first), 1);
    }
    let length_bytes = usize::from(first & 0x7f);
    if length_bytes == 0 || length_bytes > 4 || bytes.len() < length_bytes + 1 {
        return (0, 0);
    }
    let value = bytes[1..=length_bytes]
        .iter()
        .fold(0_usize, |value, byte| (value << 8) | usize::from(*byte));
    (value, length_bytes + 1)
}

#[cfg(test)]
fn https_dns_name_matches(pattern: &str, host: &str) -> bool {
    https_dns_name_bytes_match(pattern.as_bytes(), host.as_bytes())
}

fn https_dns_name_bytes_match(pattern: &[u8], host: &[u8]) -> bool {
    fn lower_ascii(byte: u8) -> u8 {
        if byte.is_ascii_uppercase() {
            byte + (b'a' - b'A')
        } else {
            byte
        }
    }

    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    if pattern.len() > 2 && pattern.starts_with(b"*.") {
        let Some(dot) = host.iter().position(|byte| *byte == b'.') else {
            return false;
        };
        if dot == 0 {
            return false;
        }
        let suffix = &host[dot + 1..];
        return suffix.len() == pattern.len() - 2
            && suffix
                .iter()
                .zip(&pattern[2..])
                .all(|(host, pattern)| lower_ascii(*host) == lower_ascii(*pattern));
    }
    pattern.len() == host.len()
        && host
            .iter()
            .zip(pattern)
            .all(|(host, pattern)| lower_ascii(*host) == lower_ascii(*pattern))
}

fn https_socket(
    address: SocketAddr,
    expected_mark: u32,
    timeout: Duration,
) -> Result<TcpStream, HttpsProbeState> {
    let socket = probe_socket(address, expected_mark).map_err(|_| HttpsProbeState::Unconfirmed)?;
    if get_socket_mark(socket.as_raw_fd()).ok() != Some(expected_mark as libc::c_int) {
        return Err(HttpsProbeState::Unconfirmed);
    }
    let stream = TcpStream::from(socket);
    match connect_until(stream.as_raw_fd(), address, timeout) {
        Ok(true) => {}
        Ok(false) => return Err(HttpsProbeState::Unconfirmed),
        Err(error) => {
            return Err(
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ECONNREFUSED | libc::EHOSTUNREACH | libc::ENETUNREACH)
                ) {
                    HttpsProbeState::Closed
                } else {
                    HttpsProbeState::Unconfirmed
                },
            );
        }
    }
    if stream.set_nonblocking(false).is_err() || stream.set_nodelay(true).is_err() {
        return Err(HttpsProbeState::Unconfirmed);
    }
    Ok(stream)
}

fn receives_tls_record(
    stream: &mut TcpStream,
    config: std::sync::Arc<rustls::ClientConfig>,
    host: &str,
) -> bool {
    let Ok(mut connection) = https_connection(config, host) else {
        return false;
    };
    while connection.wants_write() {
        if stream
            .set_write_timeout(Some(Duration::from_millis(2000)))
            .is_err()
        {
            return false;
        }
        match connection.write_tls(stream) {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
    }
    if stream
        .set_read_timeout(Some(Duration::from_millis(2000)))
        .is_err()
    {
        return false;
    }
    let mut prefix = [0; 2];
    let length = match stream.read(&mut prefix) {
        Ok(length) => length,
        Err(_) => return false,
    };
    length > 0 && matches!(prefix[0], 0x15 | 0x16) && (length < 2 || prefix[1] == 0x03)
}

pub fn probe_https_state(host: &str, address: SocketAddr, mark: Option<u32>) -> HttpsProbeState {
    if rustls::pki_types::ServerName::try_from(host.to_owned()).is_err() {
        return HttpsProbeState::Unconfirmed;
    }
    let expected_mark = mark.unwrap_or(BYPASS_MARK);
    let config = https_client_config();
    let mut first_stream = match https_socket(address, expected_mark, Duration::from_millis(1500)) {
        Ok(stream) => stream,
        Err(state) => return state,
    };
    if !receives_tls_record(&mut first_stream, std::sync::Arc::clone(&config), host) {
        return HttpsProbeState::TlsBlocked;
    }
    drop(first_stream);

    let deadline = Instant::now() + Duration::from_millis(2500);
    let connect_timeout = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_millis(1500));
    if connect_timeout.is_zero() {
        return HttpsProbeState::Unconfirmed;
    }
    let mut stream = match https_socket(address, expected_mark, connect_timeout) {
        Ok(stream) => stream,
        Err(_) => return HttpsProbeState::Unconfirmed,
    };
    let mut connection = match https_connection(config, host) {
        Ok(connection) => connection,
        Err(state) => return state,
    };
    while connection.is_handshaking() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero()
            || stream.set_read_timeout(Some(remaining)).is_err()
            || stream.set_write_timeout(Some(remaining)).is_err()
        {
            return HttpsProbeState::Unconfirmed;
        }
        match connection.complete_io(&mut stream) {
            Ok((0, 0)) => return HttpsProbeState::Unconfirmed,
            Err(error) => {
                let invalid_name = error
                    .get_ref()
                    .and_then(|cause| cause.downcast_ref::<rustls::Error>())
                    .is_some_and(|cause| {
                        matches!(
                            cause,
                            rustls::Error::InvalidCertificate(
                                rustls::CertificateError::NotValidForName
                            )
                        )
                    });
                return if invalid_name {
                    HttpsProbeState::OtherName
                } else {
                    HttpsProbeState::Unconfirmed
                };
            }
            Ok(_) => {}
        }
    }
    let Some(leaf) = connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
    else {
        return HttpsProbeState::Unconfirmed;
    };
    match https_certificate_name_matches(leaf.as_ref(), host) {
        Some(true) => HttpsProbeState::Served,
        Some(false) => HttpsProbeState::OtherName,
        None => HttpsProbeState::Unconfirmed,
    }
}

fn get_socket_mark(fd: libc::c_int) -> io::Result<libc::c_int> {
    let mut mark: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&mark) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_MARK,
            (&mut mark as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result == 0 {
        Ok(mark)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn dial_probe_target(
    target: &ProbeTarget,
    timeout: Duration,
    mark: Option<u32>,
) -> Result<(OwnedFd, SocketAddr), ProbeError> {
    let ipv6 = target.host.contains(':');
    let addresses = (&target.host[..], target.port)
        .to_socket_addrs()
        .map_err(|error| ProbeError::Transport(format!("dial tcp: {error}")))?;
    let mut last_failure = None;
    for address in addresses.filter(|address| address.is_ipv6() == ipv6) {
        let socket = match probe_socket(address, mark.unwrap_or(BYPASS_MARK)) {
            Ok(socket) => socket,
            Err(error) => {
                last_failure = Some(Err(error));
                continue;
            }
        };
        match connect_until(socket.as_raw_fd(), address, timeout) {
            Ok(true) => return Ok((socket, address)),
            Ok(false) => last_failure = Some(Ok(())),
            Err(error) => last_failure = Some(Err(error)),
        }
    }
    let endpoint = format!("{}:{}", target.host, target.port);
    match last_failure {
        Some(Ok(())) => Err(ProbeError::DialTimeout(format!(
            "dial tcp {endpoint}: i/o timeout"
        ))),
        Some(Err(error)) => Err(ProbeError::Transport(format!(
            "dial tcp {endpoint}: {error}"
        ))),
        None => Err(ProbeError::Transport(format!(
            "dial tcp {endpoint}: no address found"
        ))),
    }
}

pub(crate) fn probe_tcp_control_peer(
    peer: SocketAddr,
    timeout: Duration,
    mark: Option<u32>,
) -> Result<(), ProbeError> {
    let target = ProbeTarget {
        host: peer.ip().to_string(),
        port: peer.port(),
    };
    let _ = dial_probe_target(&target, effective_probe_timeout(timeout), mark)?;
    Ok(())
}

/// Отправить один триггер по программе разрезания TCP и правилу принятия эталона.
pub(crate) fn probe_trigger(
    target: &ProbeTarget,
    trigger: &Trigger,
    cuts: &[usize],
    gap: Duration,
    timeout: Duration,
    mark: Option<u32>,
    no_raw: bool,
    client_tcp_has_timestamps: Option<bool>,
    cancel: Option<&AtomicBool>,
) -> Result<ProbeOutcome, ProbeError> {
    let timeout = effective_probe_timeout(timeout);
    #[cfg(target_os = "linux")]
    if raw_split_enabled(cuts, no_raw, crate::raw_probe::raw_supported) {
        return crate::raw_probe::probe_tcp_split(
            target,
            trigger,
            cuts,
            gap,
            timeout,
            mark,
            client_tcp_has_timestamps,
            cancel,
        );
    }

    let (socket, _) = dial_probe_target(target, timeout, mark)?;
    let fd = socket.as_raw_fd();
    let deadline = Instant::now() + timeout;
    for span in split_offsets(cuts, trigger.payload.len(), 8) {
        let mut offset = span.from;
        while offset < span.to {
            let sent = unsafe {
                libc::send(
                    fd,
                    trigger.payload[offset..span.to].as_ptr().cast(),
                    span.to - offset,
                    libc::MSG_NOSIGNAL,
                )
            };
            if sent > 0 {
                offset += sent as usize;
                continue;
            }
            if sent == 0 {
                return Err(ProbeError::Local(
                    "send зонда завершился без передачи данных".into(),
                ));
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Err(ProbeError::Transport(format!("write: {error}")));
            }
            if would_block(&error) {
                match poll_once(fd, libc::POLLOUT, Instant::now() + PROBE_SEND_TIMEOUT) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(ProbeError::Transport(format!(
                            "write: {}",
                            io::Error::new(io::ErrorKind::TimedOut, "operation timed out")
                        )));
                    }
                    Err(error) => {
                        return Err(ProbeError::Transport(format!("write: {error}")));
                    }
                }
                continue;
            }
            return Err(ProbeError::Transport(format!("write: {error}")));
        }
        if span.to < trigger.payload.len() {
            if Instant::now() + gap > deadline {
                return Err(ProbeError::Transport("context deadline exceeded".into()));
            }
            if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                return Err(ProbeError::Local("context canceled".into()));
            }
            if !gap.is_zero() {
                std::thread::sleep(gap);
            }
        }
    }

    match poll_once(fd, libc::POLLIN, deadline) {
        Ok(true) => {}
        Ok(false) => return Ok(ProbeOutcome::Rejected),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            // d2o's blocking recv returns silence when a signal interrupts it.
            return Ok(ProbeOutcome::Rejected);
        }
        Err(error) => {
            return Err(ProbeError::Local(format!(
                "ошибка ожидания ответа: {error}"
            )));
        }
    }
    let mut bytes = [0_u8; 512];
    let received = unsafe { libc::recv(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if received <= 0 {
        return Ok(ProbeOutcome::Rejected);
    }
    Ok(
        if trigger_accepts(trigger.accept, &bytes[..received as usize]) {
            ProbeOutcome::Accepted
        } else {
            ProbeOutcome::Unproven
        },
    )
}

fn effective_probe_timeout(timeout: Duration) -> Duration {
    if timeout.is_zero() {
        DEFAULT_PROBE_TIMEOUT
    } else {
        timeout
    }
}

fn raw_split_enabled(cuts: &[usize], no_raw: bool, raw_supported: impl FnOnce() -> bool) -> bool {
    // On Linux d2o assumes raw support; a permission failure is a local probe
    // error, not a reason to reinterpret the measured split as socket writes.
    !cuts.is_empty() && !no_raw && (cfg!(target_os = "linux") || raw_supported())
}

/// Подтвердить, что обычный байт данных TCP дошёл до стека TCP узла.
pub(crate) fn probe_neutral_ack(
    target: &ProbeTarget,
    timeout: Duration,
    mark: Option<u32>,
    cancel: Option<&AtomicBool>,
) -> Result<bool, ProbeError> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (target, timeout, mark, cancel);
        return Err(ProbeError::Unsupported(
            "подтверждение TCP-данных не наблюдается на этой платформе".into(),
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let (socket, _) = dial_probe_target(target, timeout, mark)?;
        let fd = socket.as_raw_fd();
        unacked_bytes(fd)
            .map_err(|error| ProbeError::Local(format!("очередь отправки не читается: {error}")))?;
        let sent = unsafe { libc::send(fd, b"x".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) };
        if sent != 1 {
            return Err(ProbeError::Transport(format!(
                "write: {}",
                io::Error::last_os_error()
            )));
        }
        let deadline = Instant::now() + timeout;
        loop {
            if cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
                return Err(ProbeError::Local("context canceled".into()));
            }
            if unacked_bytes(fd).map_err(|error| {
                ProbeError::Local(format!("очередь отправки не читается: {error}"))
            })? == 0
            {
                return Ok(true);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            if poll_until(
                fd,
                libc::POLLIN,
                Instant::now() + remaining.min(Duration::from_millis(20)),
            )
            .map_err(|error| ProbeError::Local(format!("ошибка ожидания TCP ACK: {error}")))?
            {
                return Ok(true);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn unacked_bytes(fd: libc::c_int) -> io::Result<libc::c_int> {
    let mut bytes = 0;
    if unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut bytes) } == 0 {
        Ok(bytes)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn unacked_bytes(fd: libc::c_int) -> io::Result<libc::c_int> {
    const SO_NWRITE: libc::c_int = 0x1024;
    let mut bytes = 0;
    let mut length = std::mem::size_of_val(&bytes) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_NWRITE,
            (&mut bytes as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result == 0 {
        Ok(bytes)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn poll_until(fd: libc::c_int, events: libc::c_short, deadline: Instant) -> io::Result<bool> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result == 0 {
            return Ok(false);
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::other("poll reported an invalid socket"));
        }
        return Ok(true);
    }
}

fn poll_once(fd: libc::c_int, events: libc::c_short, deadline: Instant) -> io::Result<bool> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(false);
    }
    let millis = remaining
        .as_millis()
        .saturating_add(1)
        .min(i32::MAX as u128) as i32;
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
    if result == 0 {
        return Ok(false);
    }
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if descriptor.revents & libc::POLLNVAL != 0 {
        return Err(io::Error::other("poll reported an invalid socket"));
    }
    Ok(true)
}

fn would_block(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK
    )
}

fn handshake(address: SocketAddr, sni: &str, options: ResponseOptions) -> Result<Trial, String> {
    let hello = legacy_client_hello(sni)
        .map_err(|error| format!("не удалось собрать TLS-зонд: {error}"))?;
    let domain = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let raw_fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        return Ok(Trial::Failed);
    }
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let fd = owned_fd.as_raw_fd();
    let mark = options
        .mark
        .filter(|mark| *mark != 0)
        .unwrap_or(BYPASS_MARK) as libc::c_int;
    if mark != 0 {
        let _ = set_socket_option(fd, libc::SOL_SOCKET, SO_MARK, mark);
    }
    let _ = set_socket_option(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
    let timeout = response_timeout(options.timeout);
    let timeout_ms = timeout.as_millis().min(i64::MAX as u128) as i64;
    let socket_timeout = libc::timeval {
        tv_sec: (timeout_ms / 1000) as _,
        tv_usec: ((timeout_ms % 1000) * 1000) as _,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&socket_timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&socket_timeout) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&socket_timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&socket_timeout) as libc::socklen_t,
        );
    }

    let connect = connect_socket(fd, address).unwrap_or(-1);
    if connect != 0 {
        return Ok(Trial::Failed);
    }

    let sent = unsafe { libc::send(fd, hello.as_ptr().cast(), hello.len(), libc::MSG_NOSIGNAL) };
    if sent != hello.len() as libc::ssize_t {
        return Ok(Trial::Failed);
    }

    let deadline = Instant::now() + timeout;
    let mut bytes = vec![0_u8; RESPONSE_CAP];
    let mut have = 0;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // d2o treats one interrupted poll as a failed TLS attempt.
        if unsafe { libc::poll(&mut descriptor, 1, millis) } <= 0 {
            break;
        }
        let result = unsafe {
            libc::recv(
                fd,
                bytes[have..].as_mut_ptr().cast(),
                RESPONSE_CAP - have,
                0,
            )
        };
        if result == 0 {
            break;
        }
        if result < 0 {
            break;
        }
        have += result as usize;
        let scanned = scan12(&bytes[..have]);
        match scanned {
            Scan12::ServerHelloDone => return Ok(Trial::Done),
            Scan12::ServerHello | Scan12::NeedMore => {}
            Scan12::FatalAlert => return Ok(Trial::Failed),
        }
        if have == RESPONSE_CAP {
            return Ok(Trial::Unmeasured);
        }
    }
    Ok(Trial::Failed)
}

fn count_handshakes(
    address: SocketAddr,
    sni: &str,
    options: ResponseOptions,
    unmeasured: &mut i32,
    probes: &mut usize,
) -> Result<i32, String> {
    let mut done = 0;
    for _ in 0..options.repeats {
        *probes = (*probes).saturating_add(1);
        match handshake(address, sni, options)? {
            Trial::Done => done += 1,
            Trial::Failed => {}
            Trial::Unmeasured => *unmeasured += 1,
        }
    }
    Ok(done)
}

fn neutral_sni() -> String {
    let mut random = [0_u8; 10];
    if File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .is_err()
    {
        static COUNTER: std::sync::Mutex<u64> = std::sync::Mutex::new(0);
        let counter = COUNTER
            .lock()
            .map(|mut counter| {
                *counter = counter.wrapping_add(1);
                *counter
            })
            .unwrap_or(1);
        let mut state = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
            ^ (std::process::id() as u64).rotate_left(17)
            ^ counter.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        for byte in &mut random {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state >> 24) as u8;
        }
    }
    let suffix: String = random
        .iter()
        .map(|byte| char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]))
        .collect();
    format!("z{suffix}.example.com")
}

/// Проверить видимость ответов TLS 1.2 для целевого и нейтрального SNI на одном
/// разрешённом адресе сервера. Ошибки локальной настройки не считаются замером.
pub fn probe_response(
    host: &str,
    port: u16,
    sni: &str,
    options: ResponseOptions,
) -> ResponseResult {
    let repeats = match i32::try_from(options.repeats) {
        Ok(repeats) if repeats > 0 => repeats,
        _ => {
            return not_applicable(
                "число повторов TLS-зонда должно быть положительным и представимым".into(),
                0,
                0,
                0,
            );
        }
    };
    if let Err(error) = legacy_client_hello(sni) {
        return not_applicable(format!("недопустимое имя для TLS-зонда: {error}"), 0, 0, 0);
    }
    let address = match resolve_address(host, port) {
        Ok(address) => address,
        Err(error) => return not_applicable(error, 0, 0, 0),
    };
    let mut options = options;
    options.timeout = response_timeout(options.timeout);
    let mut probes = 0;
    let mut unmeasured = 0;
    let target = match count_handshakes(address, sni, options, &mut unmeasured, &mut probes) {
        Ok(count) => count,
        Err(error) => return not_applicable(error, 0, 0, probes),
    };
    let neutral = neutral_sni();
    let control = match count_handshakes(address, &neutral, options, &mut unmeasured, &mut probes) {
        Ok(count) => count,
        Err(error) => return not_applicable(error, target, 0, probes),
    };
    let mut result = decide(target, control, unmeasured, repeats);
    result.probes = probes;
    result
}

/// Найти ServerHelloDone TLS 1.2 или фатальное оповещение в полных записях TLS.
/// Сообщения рукопожатия рассматриваются как один поток, даже если они разбиты по записям.
pub fn scan12(bytes: &[u8]) -> Scan12 {
    let mut position = 0;
    let mut header = [0_u8; 4];
    let mut header_bytes = 0;
    let mut body_bytes = 0_usize;

    while bytes.len() - position >= 5 {
        let record_len = usize::from(u16::from_be_bytes([
            bytes[position + 3],
            bytes[position + 4],
        ]));
        let record_end = position + 5 + record_len;
        if record_end > bytes.len() {
            break;
        }

        match bytes[position] {
            0x15 => return Scan12::FatalAlert,
            0x16 => {
                for byte in &bytes[position + 5..record_end] {
                    if body_bytes != 0 {
                        body_bytes -= 1;
                        continue;
                    }
                    header[header_bytes] = *byte;
                    header_bytes += 1;
                    if header_bytes == header.len() {
                        header_bytes = 0;
                        body_bytes = (usize::from(header[1]) << 16)
                            | (usize::from(header[2]) << 8)
                            | usize::from(header[3]);
                        if header[0] == 14 && body_bytes == 0 {
                            return Scan12::ServerHelloDone;
                        }
                    }
                }
            }
            _ => {}
        }
        position = record_end;
    }
    Scan12::NeedMore
}

/// Применить правило `r2o_accept_serverhello` эталона к первой записи TLS.
pub fn scan_server_hello(bytes: &[u8]) -> Scan12 {
    if bytes.len() >= 6 && bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[5] == 2 {
        Scan12::ServerHello
    } else if bytes.len() >= 3 && bytes[0] == 0x15 && bytes[1] == 0x03 {
        Scan12::FatalAlert
    } else {
        Scan12::NeedMore
    }
}

/// Классифицировать доступность ответов по контрольным счётчикам TLS 1.2 на одном адресе.
pub fn decide(target: i32, control: i32, unmeasured: i32, repeats: i32) -> ResponseResult {
    let (verdict, reason) = if unmeasured > 0 {
        (
            ResponseVerdict::NotApplicable,
            format!(
                "ответ сервера не поместился в локальный предел буфера (64 КБ) в {unmeasured} прогонах — про ответное направление вывода нет"
            ),
        )
    } else if control == 0 {
        (
            ResponseVerdict::NotApplicable,
            "контрольное рукопожатие по TLS 1.2 не завершается — сервер его не поддерживает или мешает что-то ещё; про ответное направление вывода нет".into(),
        )
    } else if target == repeats {
        (
            ResponseVerdict::Clear,
            "рукопожатие TLS 1.2 доходит до конца — сертификат не режут".into(),
        )
    } else if target == 0 {
        (
            ResponseVerdict::Blocked,
            "запрос проходит, а рукопожатие не завершается: с нейтральным именем на тот же адрес оно завершается каждый раз. Значит режут ОТВЕТ — сертификат в TLS 1.2 идёт открытым текстом".into(),
        )
    } else {
        (
            ResponseVerdict::Flaky,
            format!("рукопожатий дошло {target} из {repeats} — не воспроизводится"),
        )
    };
    ResponseResult {
        verdict,
        reason,
        target,
        control,
        probes: 0,
    }
}

#[cfg(test)]
mod x509_tests {
    use super::{
        https_certificate_der_is_parseable, https_certificate_name_matches, https_dns_name_matches,
    };

    #[test]
    fn r2o_tls_измеритель_разбирает_сертификат_через_x509_parser() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["example.test".to_owned()]).unwrap();
        let der = certificate.serialize_der().unwrap();

        assert!(https_certificate_der_is_parseable(&der));
        assert!(!https_certificate_der_is_parseable(&der[..der.len() - 1]));
        assert!(!https_certificate_der_is_parseable(&[]));
    }

    #[test]
    fn https_probe_matches_only_a_single_donor_wildcard_label() {
        assert!(https_dns_name_matches("*.example.test", "a.example.test"));
        assert!(!https_dns_name_matches("*.example.test", "example.test"));
        assert!(!https_dns_name_matches(
            "*.example.test",
            "a.b.example.test"
        ));
        assert!(https_dns_name_matches("EXAMPLE.test", "example.TEST"));
    }

    #[test]
    fn https_probe_matches_ip_subject_alternative_names() {
        let mut parameters = rcgen::CertificateParams::default();
        parameters.subject_alt_names =
            vec![rcgen::SanType::IpAddress("192.0.2.1".parse().unwrap())];
        let certificate = rcgen::Certificate::from_params(parameters).unwrap();
        let der = certificate.serialize_der().unwrap();

        assert_eq!(
            https_certificate_name_matches(&der, "192.0.2.1"),
            Some(true)
        );
        assert_eq!(
            https_certificate_name_matches(&der, "192.0.2.2"),
            Some(false)
        );
        assert_eq!(
            https_certificate_name_matches(&der, "example.test"),
            Some(false)
        );
    }
}

#[cfg(test)]
mod tcp_split_transport_tests {
    use super::{effective_probe_timeout, probe_trigger, raw_split_enabled};
    use crate::classify::{Accept, ProbeError, ProbeTarget, Trigger};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::Duration;

    #[test]
    #[cfg(target_os = "linux")]
    fn split_probes_follow_the_donor_linux_gate_without_cap_net_raw() {
        assert!(raw_split_enabled(&[1], false, || true));
        assert!(!raw_split_enabled(&[], false, || panic!("no cuts")));
        assert!(!raw_split_enabled(&[1], true, || panic!("raw disabled")));
        assert!(raw_split_enabled(&[1], false, || false));
        if let Ok(path) = std::env::var("R2O_RAW_SPLIT_SUPPORT_DIFF_OUTPUT") {
            std::fs::write(
                path,
                format!(
                    "raw_split={}\n",
                    u8::from(raw_split_enabled(&[1], false, || false))
                ),
            )
            .unwrap();
        }
        assert_eq!(
            effective_probe_timeout(Duration::ZERO),
            Duration::from_secs(6)
        );
        assert_eq!(
            effective_probe_timeout(Duration::from_secs(7)),
            Duration::from_secs(7)
        );
    }

    #[test]
    fn socket_split_stops_before_the_next_segment_when_cancelled() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).unwrap();
            received
        });
        let target = ProbeTarget {
            host: "127.0.0.1".into(),
            port,
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: Accept::Any,
        };
        let cancelled = AtomicBool::new(true);
        let result = probe_trigger(
            &target,
            &trigger,
            &[2],
            Duration::from_millis(1),
            Duration::from_millis(100),
            Some(0),
            true,
            None,
            Some(&cancelled),
        );

        assert!(matches!(result, Err(ProbeError::Local(error)) if error == "context canceled"));
        assert_eq!(server.join().unwrap(), b"AB");
    }

    #[test]
    fn socket_split_gap_counts_against_the_donor_probe_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).unwrap();
            received
        });
        let target = ProbeTarget {
            host: "127.0.0.1".into(),
            port,
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: Accept::Any,
        };
        let result = probe_trigger(
            &target,
            &trigger,
            &[2],
            Duration::from_millis(250),
            Duration::from_millis(100),
            Some(0),
            true,
            None,
            None,
        );
        let received = server.join().unwrap();
        let bytes = received
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let row = format!("SOCKET_SPLIT_DEADLINE result=deadline bytes={bytes}");

        assert!(matches!(
            result,
            Err(ProbeError::Transport(error)) if error == "context deadline exceeded"
        ));
        assert_eq!(received, b"AB");
        if let Ok(c_output) = std::env::var("R2O_SOCKET_SPLIT_DEADLINE_C_OUTPUT") {
            let c_rows =
                std::fs::read_to_string(c_output).expect("read D2O socket split deadline output");
            let c_row = c_rows
                .lines()
                .find(|line| line.starts_with("SOCKET_SPLIT_DEADLINE "))
                .expect("D2O socket split deadline result");
            assert_eq!(row, c_row, "C/Rust socket split deadline differs");
        }
        println!("{row}");
    }

    #[test]
    fn socket_probe_waits_for_the_configured_response_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            thread::sleep(Duration::from_millis(5_500));
            stream.write_all(b"x").unwrap();
        });
        let target = ProbeTarget {
            host: "127.0.0.1".into(),
            port,
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"PING".to_vec(),
            accept: Accept::Any,
        };

        let result = probe_trigger(
            &target,
            &trigger,
            &[],
            Duration::ZERO,
            Duration::from_secs(6),
            Some(0),
            true,
            None,
            None,
        );

        assert_eq!(result.unwrap(), crate::classify::ProbeOutcome::Accepted);
        server.join().unwrap();
    }
}
