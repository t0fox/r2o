#![cfg(target_os = "linux")]

use r2o_datapath::raw::RawSocket;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "invalid hex length");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

fn set_receive_timeout(fd: i32) {
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
}

fn open_ipv6_udp_receiver(port: u16) -> OwnedFd {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    assert!(fd >= 0, "{}", std::io::Error::last_os_error());
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_receive_timeout(fd.as_raw_fd());

    let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    address.sin6_port = port.to_be();
    address.sin6_addr.s6_addr = std::net::Ipv6Addr::LOCALHOST.octets();
    let result = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_in6).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    fd
}

fn open_loopback_packet_capture() -> OwnedFd {
    let protocol = libc::htons(libc::ETH_P_ALL as u16);
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            protocol as i32,
        )
    };
    assert!(fd >= 0, "{}", std::io::Error::last_os_error());
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_receive_timeout(fd.as_raw_fd());

    let interface = unsafe { libc::if_nametoindex(b"lo\0".as_ptr().cast()) };
    assert_ne!(interface, 0, "{}", std::io::Error::last_os_error());
    let address = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as libc::sa_family_t,
        sll_protocol: protocol,
        sll_ifindex: interface as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    let result = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    fd
}

fn receive_matching_ipv6_packet(capture: &OwnedFd, expected: &[u8]) -> Vec<u8> {
    let mut bytes = [0u8; 2048];
    loop {
        let mut source: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut source_len = std::mem::size_of_val(&source) as libc::socklen_t;
        let received = unsafe {
            libc::recvfrom(
                capture.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                0,
                (&mut source as *mut libc::sockaddr_ll).cast(),
                &mut source_len,
            )
        };
        assert!(
            received >= 0,
            "IPv6 raw frame not captured: {}",
            std::io::Error::last_os_error()
        );
        let frame = &bytes[..received as usize];
        if source.sll_pkttype != libc::PACKET_OUTGOING
            || frame.len() < 48
            || expected.len() < 48
            || frame[0] >> 4 != 6
            || frame[6] != expected[6]
            || frame[8..40] != expected[8..40]
        {
            continue;
        }
        let matches_packet = if expected[6] == libc::IPPROTO_UDP as u8 {
            frame[40..44] == expected[40..44]
        } else if expected[6] == 44 {
            frame[44..48] == expected[44..48]
        } else {
            false
        };
        if matches_packet {
            return frame.to_vec();
        }
    }
}

fn receive_udp_body(receiver: &OwnedFd, body: &[u8]) {
    let mut received = [0u8; 128];
    let length = unsafe {
        libc::recv(
            receiver.as_raw_fd(),
            received.as_mut_ptr().cast(),
            received.len(),
            0,
        )
    };
    assert_eq!(
        length,
        body.len() as isize,
        "IPv6 raw UDP payload was not reassembled: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(&received[..body.len()], body);
}

fn assert_no_udp_delivery(receiver: &OwnedFd, fragment: &str) {
    let mut ready = libc::pollfd {
        fd: receiver.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut ready, 1, 1000) };
    assert_eq!(result, 0, "unexpected IPv6 UDP delivery after {fragment}");
}

#[test]
#[ignore = "requires Linux CAP_NET_RAW/CAP_NET_ADMIN and the pinned D2O raw sender"]
fn ipv6_raw_send_matches_d2o_on_live_loopback() {
    let oracle = std::env::var("D2O_RAW6_SEND_ORACLE_BIN")
        .expect("D2O_RAW6_SEND_ORACLE_BIN must point to the pinned C raw-send oracle");
    let output = Command::new(oracle).output().unwrap();
    assert!(
        output.status.success(),
        "D2O raw-send oracle failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let mut port = None;
    let mut c_packets = Vec::new();
    let mut c_deliveries = Vec::new();
    let mut c_non_deliveries = Vec::new();
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("PORT") => port = Some(fields.next().unwrap().parse::<u16>().unwrap()),
            Some("PACKET") => {
                let name = fields.next().unwrap().to_owned();
                let bytes = decode_hex(fields.next().unwrap());
                c_packets.push((name, bytes));
            }
            Some("DELIVERED") => c_deliveries.push(fields.next().unwrap().to_owned()),
            Some("NOT_DELIVERED") => c_non_deliveries.push(fields.next().unwrap().to_owned()),
            other => panic!("unexpected D2O raw-send output line: {other:?}: {line}"),
        }
    }

    let mut expected_labels = vec!["base".to_owned()];
    for shape in 1..=4 {
        let count = if shape <= 2 { 2 } else { 3 };
        expected_labels.extend((0..count).map(|index| format!("shape{shape}_{index}")));
    }
    assert_eq!(
        c_packets.iter().map(|(name, _)| name).collect::<Vec<_>>(),
        expected_labels.iter().collect::<Vec<_>>()
    );
    assert_eq!(c_deliveries, ["base", "shape1", "shape2"]);
    assert_eq!(c_non_deliveries, ["shape3", "shape4"]);

    let receiver = open_ipv6_udp_receiver(port.expect("D2O raw sender omitted port"));
    let capture = open_loopback_packet_capture();
    let sender = RawSocket::open(libc::AF_INET6, 0xd200, Some("lo")).unwrap();
    let mut body = [0u8; 64];
    body[..22].copy_from_slice(b"native IPv6 raw packet");

    for (name, packet) in &c_packets {
        sender.send_packet(packet).unwrap_or_else(|error| {
            panic!("R2O raw-send failed for {name}: {error}");
        });
        let r2o_wire_packet = receive_matching_ipv6_packet(&capture, packet);
        assert_eq!(
            r2o_wire_packet, *packet,
            "D2O and R2O raw-send bytes differ for {name}"
        );
        if name == "base" || name == "shape1_1" || name == "shape2_1" {
            receive_udp_body(&receiver, &body);
        } else if name == "shape3_2" || name == "shape4_2" {
            assert_no_udp_delivery(&receiver, name);
        }
    }

    eprintln!(
        "D2O/R2O IPv6 raw-send matched {} live loopback packets; base and fragment shapes 1-2 reassembled",
        c_packets.len()
    );
}
