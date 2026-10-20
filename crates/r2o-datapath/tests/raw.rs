use r2k_core::plan::{Emission, EmitKind};
use r2o_datapath::raw::RawSocket;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[test]
fn raw_tcp_sender_requires_a_nonzero_queue_bypass_mark() {
    let error = RawSocket::open(libc::AF_INET, 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
#[ignore = "requires Linux CAP_NET_RAW/CAP_NET_ADMIN and loopback"]
fn marked_ipv4_tcp_packet_is_visible_on_loopback() {
    let receiver_fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    assert!(receiver_fd >= 0, "{}", std::io::Error::last_os_error());
    let receiver = unsafe { OwnedFd::from_raw_fd(receiver_fd) };
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    let set_timeout = unsafe {
        libc::setsockopt(
            receiver.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    };
    assert_eq!(set_timeout, 0, "{}", std::io::Error::last_os_error());

    let mut bind_address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    bind_address.sin_family = libc::AF_INET as libc::sa_family_t;
    bind_address.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    let bind_result = unsafe {
        libc::bind(
            receiver.as_raw_fd(),
            (&bind_address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&bind_address) as libc::socklen_t,
        )
    };
    assert_eq!(bind_result, 0, "{}", std::io::Error::last_os_error());

    let mut original = vec![0; 41];
    original[0] = 0x45;
    original[2..4].copy_from_slice(&41u16.to_be_bytes());
    original[4..6].copy_from_slice(&7u16.to_be_bytes());
    original[8] = 64;
    original[9] = 6;
    original[12..16].copy_from_slice(&[127, 0, 0, 1]);
    original[16..20].copy_from_slice(&[127, 0, 0, 1]);
    original[20..22].copy_from_slice(&40000u16.to_be_bytes());
    original[22..24].copy_from_slice(&65001u16.to_be_bytes());
    original[24..28].copy_from_slice(&123u32.to_be_bytes());
    original[28..32].copy_from_slice(&456u32.to_be_bytes());
    original[32] = 0x50;
    original[33] = 0x18;
    original[34..36].copy_from_slice(&4096u16.to_be_bytes());
    original[40] = b'x';
    let emitted = Emission {
        kind: EmitKind::Fake,
        delay_us: 0,
        seq: 123,
        ttl: 0,
        poison: 0,
        seq_shift: 0,
        wire_profile: 0,
        ipfrag: 0,
        urgent: false,
        urgent_ptr: 0,
        prefix: Vec::new(),
        bytes: b"raw-smoke".to_vec(),
    };
    let mut packet = [0; 128];
    let packet_len = r2k_core::wire::build_tcp_packet(&original, &emitted, &mut packet).unwrap();
    let sender = RawSocket::open(libc::AF_INET, 0x5252).unwrap();
    sender.send_packet(&packet[..packet_len]).unwrap();

    let mut received = [0; 256];
    loop {
        let received_len = unsafe {
            libc::recv(
                receiver.as_raw_fd(),
                received.as_mut_ptr().cast(),
                received.len(),
                0,
            )
        };
        if received_len < 0 {
            panic!(
                "loopback packet not received: {}",
                std::io::Error::last_os_error()
            );
        }
        let received_packet = &received[..received_len as usize];
        let Some(view) = r2k_core::packet::PacketView::parse(received_packet) else {
            continue;
        };
        let Some(tcp) = view.tcp_segment(received_packet) else {
            continue;
        };
        if tcp.source_port == 40000 && tcp.destination_port == 65001 && tcp.sequence == 123 {
            assert_eq!(&received_packet[tcp.payload], b"raw-smoke");
            return;
        }
    }
}

#[test]
#[ignore = "requires Linux CAP_NET_RAW/CAP_NET_ADMIN and loopback"]
fn marked_ipv4_udp_packet_is_visible_on_loopback() {
    let receiver_fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    assert!(receiver_fd >= 0, "{}", std::io::Error::last_os_error());
    let receiver = unsafe { OwnedFd::from_raw_fd(receiver_fd) };
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    let set_timeout = unsafe {
        libc::setsockopt(
            receiver.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    };
    assert_eq!(set_timeout, 0, "{}", std::io::Error::last_os_error());

    let mut bind_address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    bind_address.sin_family = libc::AF_INET as libc::sa_family_t;
    bind_address.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    let bind_result = unsafe {
        libc::bind(
            receiver.as_raw_fd(),
            (&bind_address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&bind_address) as libc::socklen_t,
        )
    };
    assert_eq!(bind_result, 0, "{}", std::io::Error::last_os_error());

    let mut original = vec![0; 29];
    original[0] = 0x45;
    original[2..4].copy_from_slice(&29u16.to_be_bytes());
    original[4..6].copy_from_slice(&7u16.to_be_bytes());
    original[8] = 64;
    original[9] = 17;
    original[12..16].copy_from_slice(&[127, 0, 0, 1]);
    original[16..20].copy_from_slice(&[127, 0, 0, 1]);
    original[20..22].copy_from_slice(&40001u16.to_be_bytes());
    original[22..24].copy_from_slice(&65002u16.to_be_bytes());
    original[24..26].copy_from_slice(&9u16.to_be_bytes());
    original[28] = b'x';
    let emitted = Emission {
        kind: EmitKind::Fake,
        delay_us: 0,
        seq: 0,
        ttl: 2,
        poison: 0,
        seq_shift: 0,
        wire_profile: 0,
        ipfrag: 0,
        urgent: false,
        urgent_ptr: 0,
        prefix: Vec::new(),
        bytes: b"raw-udp-smoke".to_vec(),
    };
    let mut packet = [0; 128];
    let packet_len = r2k_core::wire::build_udp_packet(&original, &emitted, &mut packet).unwrap();
    let sender = RawSocket::open(libc::AF_INET, 0x5252).unwrap();
    sender.send_packet(&packet[..packet_len]).unwrap();

    let mut received = [0; 256];
    loop {
        let received_len = unsafe {
            libc::recv(
                receiver.as_raw_fd(),
                received.as_mut_ptr().cast(),
                received.len(),
                0,
            )
        };
        if received_len < 0 {
            panic!(
                "loopback UDP packet not received: {}",
                std::io::Error::last_os_error()
            );
        }
        let received_packet = &received[..received_len as usize];
        let Some(view) = r2k_core::packet::PacketView::parse(received_packet) else {
            continue;
        };
        let Some(payload) = view.udp_payload_range(received_packet) else {
            continue;
        };
        if received_packet[20..22] == 40001u16.to_be_bytes()
            && received_packet[22..24] == 65002u16.to_be_bytes()
        {
            assert_eq!(received_packet[8], 2);
            assert_eq!(&received_packet[payload], b"raw-udp-smoke");
            return;
        }
    }
}

#[test]
#[ignore = "нужны Linux CAP_NET_RAW/CAP_NET_ADMIN и loopback"]
fn marked_ipv4_udp_fragments_reassemble_on_loopback() {
    let receiver_fd =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(receiver_fd >= 0, "{}", std::io::Error::last_os_error());
    let receiver = unsafe { OwnedFd::from_raw_fd(receiver_fd) };
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    let set_timeout = unsafe {
        libc::setsockopt(
            receiver.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    };
    assert_eq!(set_timeout, 0, "{}", std::io::Error::last_os_error());

    let mut bind_address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    bind_address.sin_family = libc::AF_INET as libc::sa_family_t;
    bind_address.sin_port = 65003u16.to_be();
    bind_address.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    let bind_result = unsafe {
        libc::bind(
            receiver.as_raw_fd(),
            (&bind_address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&bind_address) as libc::socklen_t,
        )
    };
    assert_eq!(bind_result, 0, "{}", std::io::Error::last_os_error());

    let mut original = vec![0; 20 + 8 + 1200];
    original[0] = 0x45;
    let ip_len = original.len() as u16;
    original[2..4].copy_from_slice(&ip_len.to_be_bytes());
    original[4..6].copy_from_slice(&7u16.to_be_bytes());
    original[8] = 64;
    original[9] = 17;
    original[12..16].copy_from_slice(&[127, 0, 0, 1]);
    original[16..20].copy_from_slice(&[127, 0, 0, 1]);
    original[20..22].copy_from_slice(&40001u16.to_be_bytes());
    original[22..24].copy_from_slice(&65003u16.to_be_bytes());
    original[24..26].copy_from_slice(&1208u16.to_be_bytes());

    let payload = (0..1200).map(|index| index as u8).collect::<Vec<_>>();
    let emitted = Emission {
        kind: EmitKind::Payload,
        delay_us: 0,
        seq: 0,
        ttl: 0,
        poison: 0,
        seq_shift: 0,
        wire_profile: 0,
        ipfrag: 2,
        urgent: false,
        urgent_ptr: 0,
        prefix: Vec::new(),
        bytes: payload.clone(),
    };
    let fragments = r2k_core::wire::build_udp_fragments(&original, &emitted).unwrap();
    let sender = RawSocket::open(libc::AF_INET, 0x5252).unwrap();
    for fragment in &fragments {
        sender.send_packet(fragment).unwrap();
    }

    let mut received = [0; 2048];
    loop {
        let received_len = unsafe {
            libc::recv(
                receiver.as_raw_fd(),
                received.as_mut_ptr().cast(),
                received.len(),
                0,
            )
        };
        if received_len < 0 {
            panic!(
                "фрагментированная UDP-датаграмма не собрана: {}",
                std::io::Error::last_os_error()
            );
        }
        if received_len as usize == payload.len() && received[..payload.len()] == payload {
            return;
        }
    }
}
