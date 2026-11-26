use super::network::NetworkState;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream, lookup_host};

/// Ошибка исходящего TCP-подключения.
#[derive(Debug, Clone)]
pub struct OutboundError {
    pub reason: String,
    pub timed_out: bool,
    pub dns_failed: bool,
}

impl OutboundError {
    fn failed(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            timed_out: false,
            dns_failed: false,
        }
    }

    fn dns_failed(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            timed_out: false,
            dns_failed: true,
        }
    }

    fn timed_out(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            timed_out: true,
            dns_failed: false,
        }
    }
}

impl std::fmt::Display for OutboundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for OutboundError {}

pub struct OutboundConnector {
    socket_mark: Option<u32>,
    network: NetworkState,
}

impl OutboundConnector {
    pub fn direct() -> Self {
        Self {
            socket_mark: None,
            network: NetworkState::default(),
        }
    }

    pub fn with_socket_mark(mut self, mark: Option<u32>) -> Self {
        self.socket_mark = mark;
        self
    }

    pub(crate) fn network(&self) -> &NetworkState {
        &self.network
    }

    pub async fn connect(
        &self,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, OutboundError> {
        match tokio::time::timeout(timeout, self.connect_tcp(target_host, target_port)).await {
            Ok(result) => result,
            Err(_) => Err(OutboundError::timed_out("истёк тайм-аут подключения TCP")),
        }
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, OutboundError> {
        let addresses = lookup_host((host, port)).await.map_err(|error| {
            OutboundError::dns_failed(format!("Поиск адреса TCP-хоста: {error}"))
        })?;
        let mut last_error = None;
        let mut found_address = false;
        for address in addresses {
            found_address = true;
            let address = match address {
                SocketAddr::V6(ip) => ip.ip().to_ipv4_mapped().map_or(address, |v4| {
                    SocketAddr::V4(SocketAddrV4::new(v4, ip.port()))
                }),
                SocketAddr::V4(_) => address,
            };
            if !self.network.permits(address.ip()) {
                continue;
            }
            let socket = if address.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            };
            let socket = match socket {
                Ok(socket) => socket,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            if let Some(mark) = self.socket_mark {
                #[cfg(target_os = "linux")]
                set_socket_mark(&socket, mark)
                    .map_err(|error| OutboundError::failed(format!("Метка SO_MARK: {error}")))?;
                #[cfg(not(target_os = "linux"))]
                return Err(OutboundError::failed(
                    "Метка SO_MARK поддерживается только в Linux",
                ));
            }
            match socket.connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        if !found_address {
            return Err(OutboundError::dns_failed(
                "Поиск адреса TCP-хоста: DNS не вернул адресов",
            ));
        }
        let reason = last_error.map_or_else(
            || "в сети отсутствует адрес нужного семейства".to_owned(),
            |error| error.to_string(),
        );
        Err(OutboundError::failed(format!("Подключение TCP: {reason}")))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn set_socket_mark(socket: &TcpSocket, mark: u32) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
