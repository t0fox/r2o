use crate::netlink::{
    MessageIter, NF_ACCEPT, NF_DROP, NFQNL_CFG_CMD_BIND, NFQNL_CFG_CMD_UNBIND, config_command,
    config_params, kernel_error, verdict, verdict_payload,
};
use std::cell::Cell;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const ACK_TIMEOUT_MS: i32 = 1000;
const ACK_ATTEMPTS: usize = 8;
const RECEIVE_CAPACITY: usize = 1 << 17;

/// C `d2k_nfq_recv` (`datapath/nfq.c:254-274`): EAGAIN/EWOULDBLOCK/EINTR —
/// пустое ожидание (0), ENOBUFS — потеря пакета (-2), иное — ошибка (-1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum R2oNfqRecvOutcome {
    Wait,
    Lost,
    Io,
}

fn r2o_nfq_recv_error_outcome(error: &io::Error) -> R2oNfqRecvOutcome {
    match error.raw_os_error() {
        Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK) | Some(libc::EINTR) => R2oNfqRecvOutcome::Wait,
        Some(libc::ENOBUFS) => R2oNfqRecvOutcome::Lost,
        _ => R2oNfqRecvOutcome::Io,
    }
}

fn set_receive_buffer_with(
    requested: i32,
    force_option: Option<i32>,
    normal_option: i32,
    mut set_option: impl FnMut(i32, i32) -> io::Result<()>,
    mut get_effective: impl FnMut(i32) -> io::Result<i32>,
) -> io::Result<i32> {
    let forced = match force_option {
        Some(option) => set_option(option, requested).is_ok(),
        None => false,
    };
    if !forced {
        set_option(normal_option, requested)?;
    }
    get_effective(normal_option)
}

fn set_receive_buffer(fd: RawFd, requested: i32) -> io::Result<i32> {
    set_receive_buffer_with(
        requested,
        Some(libc::SO_RCVBUFFORCE),
        libc::SO_RCVBUF,
        |option, value| {
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    &value as *const i32 as *const libc::c_void,
                    std::mem::size_of_val(&value) as libc::socklen_t,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        },
        |option| {
            let mut effective = 0_i32;
            let mut length = std::mem::size_of_val(&effective) as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    &mut effective as *mut i32 as *mut libc::c_void,
                    &mut length,
                )
            };
            if result == 0 {
                Ok(effective)
            } else {
                Err(io::Error::last_os_error())
            }
        },
    )
}

#[derive(Debug)]
pub enum ReceiveError {
    Wait(io::Error),
    LostPackets,
    Io(io::Error),
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LostPackets => formatter.write_str("ядро сообщило о потерянных пакетах"),
            Self::Wait(error) | Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ReceiveError {}

fn record_lost_packet(counter: &Cell<u64>) {
    counter.set(counter.get().saturating_add(1));
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueueStats {
    pub packets: u64,
    pub bytes: u64,
    pub accepted: u64,
    pub dropped: u64,
    pub truncated: u64,
    pub no_payload: u64,
    pub no_header: u64,
    /// C `st.verdict_fail`: ошибки выдачи вердикта NFQUEUE.
    pub verdict_failures: u64,
    /// C `st.recv_err`: ошибки чтения/потерь NFQUEUE.
    pub receive_errors: u64,
}

pub struct QueueSocket {
    fd: OwnedFd,
    queue: u16,
    protocol_family: u16,
    sequence: u32,
    lost_packets: Cell<u64>,
    stats: Cell<QueueStats>,
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
            match set_receive_buffer(fd.as_raw_fd(), receive_buffer) {
                Ok(effective) if effective < receive_buffer => eprintln!(
                    "r2o-datapath: SO_RCVBUF NFQUEUE ограничен: запрос {receive_buffer}, ядро установило {effective}"
                ),
                Ok(_) => {}
                Err(error) => {
                    eprintln!("r2o-datapath: не удалось настроить SO_RCVBUF NFQUEUE: {error}")
                }
            }
        }

        let mut socket = Self {
            fd,
            queue,
            protocol_family,
            sequence: 1,
            lost_packets: Cell::new(0),
            stats: Cell::new(QueueStats::default()),
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
            // C `d2k_nfq_recv` на EINTR отдаёт 0 (пустое ожидание);
            // остальные ошибки recv — -1, то есть сброс TCP-удержаний.
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok((false, false));
            }
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
        match r2o_nfq_recv_error_outcome(&error) {
            R2oNfqRecvOutcome::Wait => Ok((false, extra_ready)),
            R2oNfqRecvOutcome::Lost => {
                record_lost_packet(&self.lost_packets);
                Err(ReceiveError::LostPackets)
            }
            R2oNfqRecvOutcome::Io => Err(ReceiveError::Io(error)),
        }
    }

    pub fn lost_packets(&self) -> u64 {
        self.lost_packets.get()
    }

    pub fn stats(&self) -> QueueStats {
        self.stats.get()
    }

    pub fn record_received_packet(&self, payload_bytes: Option<usize>, truncated: bool) {
        let mut stats = self.stats.get();
        stats.packets = stats.packets.saturating_add(1);
        match payload_bytes {
            Some(payload_bytes) => {
                stats.bytes = stats.bytes.saturating_add(payload_bytes as u64);
                if truncated {
                    stats.truncated = stats.truncated.saturating_add(1);
                }
            }
            None => stats.no_payload = stats.no_payload.saturating_add(1),
        }
        self.stats.set(stats);
    }

    pub fn record_missing_header(&self) {
        let mut stats = self.stats.get();
        stats.no_header = stats.no_header.saturating_add(1);
        self.stats.set(stats);
    }

    pub fn record_verdict_failure(&self) {
        let mut stats = self.stats.get();
        stats.verdict_failures = stats.verdict_failures.saturating_add(1);
        self.stats.set(stats);
    }

    pub fn record_receive_error(&self) {
        let mut stats = self.stats.get();
        stats.receive_errors = stats.receive_errors.saturating_add(1);
        self.stats.set(stats);
    }

    fn record_verdict(&self, action: u32) {
        let mut stats = self.stats.get();
        if action == NF_DROP {
            stats.dropped = stats.dropped.saturating_add(1);
        } else {
            stats.accepted = stats.accepted.saturating_add(1);
        }
        self.stats.set(stats);
    }

    pub fn send_verdict(&mut self, packet_id: u32, action: u32) -> io::Result<()> {
        let bytes = verdict(self.queue, self.next_sequence(), packet_id, action);
        if let Err(error) = send_to_kernel(self.fd.as_raw_fd(), &bytes) {
            self.record_verdict_failure();
            return Err(error);
        }
        self.record_verdict(action);
        Ok(())
    }

    pub fn send_replacement(&mut self, packet_id: u32, packet: &[u8]) -> io::Result<()> {
        let bytes = match verdict_payload(
            self.queue,
            self.next_sequence(),
            packet_id,
            NF_ACCEPT,
            packet,
        ) {
            Some(bytes) => bytes,
            None => {
                self.record_verdict_failure();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "замена не помещается в netlink",
                ));
            }
        };
        if let Err(error) = send_to_kernel(self.fd.as_raw_fd(), &bytes) {
            self.record_verdict_failure();
            return Err(error);
        }
        self.record_verdict(NF_ACCEPT);
        Ok(())
    }

    fn configure(&mut self, message: &[u8]) -> io::Result<()> {
        let sequence = u32::from_ne_bytes(message[8..12].try_into().expect("netlink header"));
        send_to_kernel(self.fd.as_raw_fd(), message)?;
        self.await_ack(sequence)
    }

    fn await_ack(&self, sequence: u32) -> io::Result<()> {
        Self::await_ack_with(sequence, |bytes| {
            loop {
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
                    return Ok(None);
                }
                return recv_once(self.fd.as_raw_fd(), bytes).map(Some);
            }
        })
    }

    fn await_ack_with(
        sequence: u32,
        mut receive: impl FnMut(&mut [u8]) -> io::Result<Option<usize>>,
    ) -> io::Result<()> {
        for _ in 0..ACK_ATTEMPTS {
            let mut response = [0; 4096];
            let Some(received) = receive(&mut response)? else {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ядро не подтвердило настройку очереди за секунду",
                ));
            };
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
            "подтверждение настройки очереди не пришло",
        ))
    }

    fn next_sequence(&mut self) -> u32 {
        let current = self.sequence;
        self.sequence = self.sequence.wrapping_add(1).max(1);
        current
    }
}

impl AsRawFd for QueueSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for QueueSocket {
    fn drop(&mut self) {
        let message = self.unbind_message();
        let _ = send_to_kernel(self.fd.as_raw_fd(), &message);
    }
}

impl QueueSocket {
    /// C `d2k_nfq_close`: UNBIND без ACK, `seq++`.
    fn unbind_message(&mut self) -> Vec<u8> {
        config_command(
            self.queue,
            self.next_sequence(),
            NFQNL_CFG_CMD_UNBIND,
            self.protocol_family,
        )
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

#[cfg(test)]
mod tests {
    use super::{QueueSocket, R2oNfqRecvOutcome, r2o_nfq_recv_error_outcome};
    use crate::netlink::{NFQNL_CFG_CMD_UNBIND, config_command};
    use std::cell::Cell;
    use std::io;
    use std::io::ErrorKind;
    use std::os::fd::{AsRawFd, OwnedFd};

    #[test]
    fn nfq_recv_error_mapping_matches_c() {
        for errno in [libc::EAGAIN, libc::EWOULDBLOCK, libc::EINTR] {
            assert_eq!(
                r2o_nfq_recv_error_outcome(&io::Error::from_raw_os_error(errno)),
                R2oNfqRecvOutcome::Wait,
                "errno {errno}"
            );
        }
        assert_eq!(
            r2o_nfq_recv_error_outcome(&io::Error::from_raw_os_error(libc::ENOBUFS)),
            R2oNfqRecvOutcome::Lost
        );
        assert_eq!(
            r2o_nfq_recv_error_outcome(&io::Error::from_raw_os_error(libc::EBADF)),
            R2oNfqRecvOutcome::Io
        );
    }

    fn test_socket() -> QueueSocket {
        let fd: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        QueueSocket {
            fd,
            queue: 0,
            protocol_family: libc::AF_INET as u16,
            sequence: 1,
            lost_packets: Cell::new(0),
            stats: Cell::new(Default::default()),
        }
    }

    #[test]
    fn unbind_message_and_fd_match_c_close() {
        let mut socket = test_socket();
        let message = socket.unbind_message();
        assert_eq!(
            message,
            config_command(0, 1, NFQNL_CFG_CMD_UNBIND, libc::AF_INET as u16)
        );
        assert_eq!(socket.sequence, 2, "C seq++ после UNBIND");

        let fd = socket.as_raw_fd();
        assert!(fd >= 0);
        drop(socket);
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn await_ack_stops_after_first_timeout() {
        let calls = Cell::new(0);
        let error = QueueSocket::await_ack_with(7, |_| {
            calls.set(calls.get() + 1);
            Ok(None)
        })
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn record_lost_packet_counts_each_kernel_report() {
        let count = Cell::new(0_u64);
        super::record_lost_packet(&count);
        super::record_lost_packet(&count);

        assert_eq!(count.get(), 2);
    }

    #[test]
    fn record_missing_header_does_not_count_a_verdict_packet() {
        let socket = test_socket();
        socket.record_missing_header();

        assert_eq!(socket.stats().no_header, 1);
        assert_eq!(socket.stats().packets, 0);
        assert_eq!(socket.stats().accepted, 0);
        assert_eq!(socket.stats().dropped, 0);
    }

    #[test]
    fn receive_buffer_uses_privileged_override_and_reads_back_effective_size() {
        let mut options = Vec::new();
        let requested = 4 * 1024 * 1024;
        let effective = super::set_receive_buffer_with(
            requested,
            Some(1),
            2,
            |option, value| {
                options.push((option, value));
                Ok(())
            },
            |option| {
                assert_eq!(option, 2);
                Ok(requested * 2)
            },
        )
        .unwrap();

        assert_eq!(effective, requested * 2);
        assert_eq!(options, [(1, requested)]);
    }

    #[test]
    fn receive_buffer_falls_back_and_reports_kernel_cap() {
        let mut options = Vec::new();
        let requested = 4 * 1024 * 1024;
        let effective = super::set_receive_buffer_with(
            requested,
            Some(1),
            2,
            |option, value| {
                options.push((option, value));
                if option == 1 {
                    Err(std::io::Error::from_raw_os_error(libc::EPERM))
                } else {
                    Ok(())
                }
            },
            |option| {
                assert_eq!(option, 2);
                Ok(425_984)
            },
        )
        .unwrap();

        assert_eq!(effective, 425_984);
        assert_eq!(options, [(1, requested), (2, requested)]);
        assert!(effective < requested);
    }

    #[test]
    fn receive_buffer_returns_fallback_error_without_readback() {
        let mut readback_called = false;
        let error = super::set_receive_buffer_with(
            4096,
            Some(1),
            2,
            |option, _| {
                assert!(option == 1 || option == 2);
                Err(std::io::Error::from_raw_os_error(libc::EPERM))
            },
            |_| {
                readback_called = true;
                Ok(0)
            },
        )
        .unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        assert!(!readback_called);
    }
}
