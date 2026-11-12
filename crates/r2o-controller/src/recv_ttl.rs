//! C `quicprobe.c:qp_recv_ttl`: приём датаграммы вместе с TTL/hop limit.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

/// Включить доставку TTL/hop limit в управляющих сообщениях сокета.
pub fn enable_recv_ttl(socket: &UdpSocket) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let one: libc::c_int = 1;
    let (level, option) = if socket.local_addr()?.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_RECVTTL)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            &one as *const libc::c_int as *const libc::c_void,
            size_of_val(&one) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// C `qp_recv_ttl`: `recvmsg` и разбор `IP_TTL`/`IPV6_HOPLIMIT`.
pub fn recv_with_ttl(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<(usize, Option<u8>)> {
    let fd = socket.as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut control = [0_u8; 128];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() as _;
    let received = unsafe { libc::recvmsg(fd, &mut message, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut ttl = None;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let control = unsafe { &*header };
        let family_matches = (control.cmsg_level == libc::IPPROTO_IP
            && control.cmsg_type == libc::IP_TTL)
            || (control.cmsg_level == libc::IPPROTO_IPV6
                && control.cmsg_type == libc::IPV6_HOPLIMIT);
        if family_matches {
            let data = unsafe { libc::CMSG_DATA(header) };
            let mut value: libc::c_int = 0;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data,
                    &mut value as *mut libc::c_int as *mut u8,
                    size_of::<libc::c_int>(),
                );
            }
            ttl = Some(value.clamp(0, u8::MAX as libc::c_int) as u8);
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    Ok((received as usize, ttl))
}

#[cfg(test)]
mod tests {
    use super::{enable_recv_ttl, recv_with_ttl};
    use std::net::UdpSocket;

    #[test]
    fn recv_with_ttl_reports_loopback_ttl() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        enable_recv_ttl(&receiver).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"ttl", receiver.local_addr().unwrap())
            .unwrap();
        let mut buffer = [0_u8; 8];
        let (length, ttl) = recv_with_ttl(&receiver, &mut buffer).unwrap();
        assert_eq!(length, 3);
        assert_eq!(&buffer[..3], b"ttl");
        assert!(ttl.is_some(), "IP_RECVTTL обязан вернуть TTL");
    }
}
