//! TG15: разбор SO_ORIGINAL_DST в формате C-оракула.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use r2o_telegram::transparent::decode_original_destination;

fn v4_bytes(family: u16, port: u16, address: [u8; 4]) -> Vec<u8> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = family;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from_ne_bytes(address);
    // SAFETY: читаем инициализированную локальную struct как байты.
    unsafe {
        std::slice::from_raw_parts(
            &addr as *const _ as *const u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        )
        .to_vec()
    }
}

fn v6_bytes(family: u16, port: u16, address: [u8; 16]) -> Vec<u8> {
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    addr.sin6_family = family;
    addr.sin6_port = port.to_be();
    addr.sin6_flowinfo = 0x1234;
    addr.sin6_scope_id = 5;
    addr.sin6_addr.s6_addr = address;
    // SAFETY: читаем инициализированную локальную struct как байты.
    unsafe {
        std::slice::from_raw_parts(
            &addr as *const _ as *const u8,
            std::mem::size_of::<libc::sockaddr_in6>(),
        )
        .to_vec()
    }
}

fn report(name: &str, decoded: Option<SocketAddr>) {
    match decoded {
        Some(SocketAddr::V4(addr)) => {
            print!("{name} ok=1 family=2 port={} addr=", addr.port());
            for byte in addr.ip().octets() {
                print!("{byte:02x}");
            }
            println!();
        }
        Some(SocketAddr::V6(addr)) => {
            print!("{name} ok=1 family=10 port={} addr=", addr.port());
            for byte in addr.ip().octets() {
                print!("{byte:02x}");
            }
            println!();
        }
        None => println!("{name} ok=0"),
    }
}

fn with_extra(mut bytes: Vec<u8>, extra: usize) -> Vec<u8> {
    bytes.resize(bytes.len() + extra, 0);
    bytes
}

fn main() {
    let v4 = v4_bytes(libc::AF_INET as u16, 443, [149, 154, 167, 51]);
    report("v4-valid", decode_original_destination(&v4));
    report(
        "v4-port0",
        decode_original_destination(&v4_bytes(libc::AF_INET as u16, 0, [149, 154, 167, 51])),
    );
    report(
        "v4-family-wrong",
        decode_original_destination(&v4_bytes(libc::AF_INET6 as u16, 443, [149, 154, 167, 51])),
    );
    report("v4-short", decode_original_destination(&v4[..v4.len() - 1]));
    report(
        "v4-extra",
        decode_original_destination(&with_extra(v4.clone(), 4)),
    );
    report(
        "v4-zero-address",
        decode_original_destination(&v4_bytes(libc::AF_INET as u16, 443, [0, 0, 0, 0])),
    );

    let ipv6: Ipv6Addr = "2001:67c:4e8:f002::a".parse().unwrap();
    let v6 = v6_bytes(libc::AF_INET6 as u16, 443, ipv6.octets());
    report("v6-valid", decode_original_destination(&v6));
    report(
        "v6-port0",
        decode_original_destination(&v6_bytes(libc::AF_INET6 as u16, 0, ipv6.octets())),
    );
    report(
        "v6-family-wrong",
        decode_original_destination(&v6_bytes(libc::AF_INET as u16, 443, ipv6.octets())),
    );
    report("v6-short", decode_original_destination(&v6[..v6.len() - 1]));
    report(
        "v6-extra",
        decode_original_destination(&with_extra(v6.clone(), 4)),
    );
    let mapped: Ipv6Addr = "::ffff:149.154.167.51".parse().unwrap();
    report(
        "v6-mapped",
        decode_original_destination(&v6_bytes(libc::AF_INET6 as u16, 443, mapped.octets())),
    );

    let mut unknown = [0u8; 16];
    unknown[0] = 1;
    report("unknown-family", decode_original_destination(&unknown));
    report("too-short", decode_original_destination(&unknown[..1]));
    report("null-buffer", decode_original_destination(&[]));
    let _ = Ipv4Addr::LOCALHOST;
}
