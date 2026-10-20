use crate::netlink::{
    MessageIter, NF_ACCEPT, NFQNL_CFG_CMD_BIND, NFQNL_CFG_CMD_UNBIND, config_command,
    config_params, kernel_error, verdict, verdict_payload,
};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const ACK_TIMEOUT_MS: i32 = 1000;
const ACK_ATTEMPTS: usize = 8;
const RECEIVE_CAPACITY: usize = 1 << 17;

#[derive(Debug)]
pub enum ReceiveError {
    LostPackets,
    Io(io::Error),
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LostPackets => formatter.write_str("ядро сообщило о потерянных пакетах"),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ReceiveError {}

pub struct QueueSocket {
    fd: OwnedFd,
    queue: u16,
    protocol_family: u16,
    sequence: u32,
}

impl QueueSocket {
    pub fn open(
        queue: u16,
        protocol_family: u16,
        copy_range: u32,
        max_len: u32,
        fail_open: bool,
        receive_buffer: i32,
    ) -> io::Result<Self> {
        if copy_range < 64 || max_len == 0 || !matches!(protocol_family, 2 | 10) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "некорректные параметры NFQUEUE",
            ));
        }
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                crate::netlink::NETLINK_NETFILTER,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &local as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if receive_buffer > 0 {
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &receive_buffer as *const i32 as *const libc::c_void,
                    std::mem::size_of_val(&receive_buffer) as libc::socklen_t,
                );
            }
        }

        let mut socket = Self {
            fd,
            queue,
            protocol_family,
            sequence: 1,
        };
        let bind = config_command(
            queue,
            socket.next_sequence(),
            NFQNL_CFG_CMD_BIND,
            protocol_family,
        );
        socket.configure(&bind)?;
        let params = config_params(
            queue,
            socket.next_sequence(),
            copy_range,
            max_len,
            fail_open,
        );
        socket.configure(&params)?;
        Ok(socket)
    }

    pub fn receive(&self, bytes: &mut Vec<u8>) -> Result<(), ReceiveError> {
        self.receive_timeout(bytes, -1).map(|_| ())
    }

    /// Ожидать одну дейтаграмму NFQUEUE; `false` означает, что истёк таймер.
    pub fn receive_timeout(
        &self,
        bytes: &mut Vec<u8>,
        timeout_ms: i32,
    ) -> Result<bool, ReceiveError> {
        self.receive_timeout_with_fd(bytes, timeout_ms, None)
            .map(|(received, _)| received)
    }

    /// Совместно ожидает NFQUEUE и дополнительный дескриптор без лишнего таймера опроса.
    pub fn receive_timeout_with_fd(
        &self,
        bytes: &mut Vec<u8>,
        timeout_ms: i32,
        extra_fd: Option<RawFd>,
    ) -> Result<(bool, bool), ReceiveError> {
        if timeout_ms < -1 {
            return Err(ReceiveError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "таймаут NFQUEUE не может быть меньше -1 мс",
            )));
        }
        bytes.resize(RECEIVE_CAPACITY, 0);
        let mut descriptors = [
            libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: extra_fd.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let count = if extra_fd.is_some() { 2 } else { 1 };
        let ready = unsafe { libc::poll(descriptors.as_mut_ptr(), count, timeout_ms) };
        if ready == 0 {
            return Ok((false, false));
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            return Err(ReceiveError::Io(error));
        }
        let extra_ready = extra_fd.is_some()
            && descriptors[1].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0;
        if descriptors[0].revents & libc::POLLIN == 0 {
            if descriptors[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0 {
                return Ok((false, extra_ready));
            }
            return Err(ReceiveError::Io(io::Error::other(
                "NFQUEUE socket сообщил ошибку без готового пакета",
            )));
        }
        let received = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                bytes.as_mut_ptr() as *mut libc::c_void,
                bytes.len(),
                0,
            )
        };
        if received >= 0 {
            bytes.truncate(received as usize);
            return Ok((true, extra_ready));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENOBUFS) => Err(ReceiveError::LostPackets),
            _ => Err(ReceiveError::Io(error)),
        }
    }

    pub fn send_verdict(&mut self, packet_id: u32, action: u32) -> io::Result<()> {
        let bytes = verdict(self.queue, self.next_sequence(), packet_id, action);
        send_to_kernel(self.fd.as_raw_fd(), &bytes)
    }

    pub fn send_replacement(&mut self, packet_id: u32, packet: &[u8]) -> io::Result<()> {
        let bytes = verdict_payload(
            self.queue,
            self.next_sequence(),
            packet_id,
            NF_ACCEPT,
            packet,
        )
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "замена не помещается в netlink",
            )
        })?;
        send_to_kernel(self.fd.as_raw_fd(), &bytes)
    }

    fn configure(&mut self, message: &[u8]) -> io::Result<()> {
        let sequence = u32::from_ne_bytes(message[8..12].try_into().expect("netlink header"));
        send_to_kernel(self.fd.as_raw_fd(), message)?;
        self.await_ack(sequence)
    }

    fn await_ack(&self, sequence: u32) -> io::Result<()> {
        for _ in 0..ACK_ATTEMPTS {
            let mut descriptor = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, ACK_TIMEOUT_MS) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            let mut response = [0; 4096];
            let received = recv_once(self.fd.as_raw_fd(), &mut response)?;
            for message in MessageIter::new(&response[..received]) {
                if message.sequence != sequence {
                    continue;
                }
                if let Some(error) = kernel_error(&message) {
                    return if error == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::from_raw_os_error(error.saturating_neg()))
                    };
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "ядро не подтвердило настройку NFQUEUE за 8 секунд",
        ))
    }

    fn next_sequence(&mut self) -> u32 {
        let current = self.sequence;
        self.sequence = self.sequence.wrapping_add(1).max(1);
        current
    }
}

impl Drop for QueueSocket {
    fn drop(&mut self) {
        let message = config_command(
            self.queue,
            self.next_sequence(),
            NFQNL_CFG_CMD_UNBIND,
            self.protocol_family,
        );
        let _ = send_to_kernel(self.fd.as_raw_fd(), &message);
    }
}

fn send_to_kernel(fd: libc::c_int, bytes: &[u8]) -> io::Result<()> {
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    loop {
        let sent = unsafe {
            libc::sendto(
                fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                0,
                &kernel as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent >= 0 {
            if sent as usize == bytes.len() {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "короткая запись netlink сообщения",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

fn recv_once(fd: libc::c_int, bytes: &mut [u8]) -> io::Result<usize> {
    loop {
        let received =
            unsafe { libc::recv(fd, bytes.as_mut_ptr() as *mut libc::c_void, bytes.len(), 0) };
        if received >= 0 {
            return Ok(received as usize);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}
