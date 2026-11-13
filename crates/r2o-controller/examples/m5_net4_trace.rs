//! M5: Rust trace net4 — IPv4 parse/text/private и IPv6 private.

use r2o_controller::quic_replay::r2o_quic_address_is_local;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn is_local(address: IpAddr) -> bool {
    r2o_quic_address_is_local(SocketAddr::new(address, 443))
}

fn print_parse(text: &str) {
    let name = if text.is_empty() { "empty" } else { text };
    println!("case parse-{name}");
    match r2k_core::addr::parse_ipv4_legacy(text) {
        Some(address) => println!("result ok text={address}"),
        None => println!("result err"),
    }
}

fn main() {
    for text in [
        "0.0.0.0",
        "127.0.0.1",
        "192.168.1.1",
        "255.255.255.255",
        "010.0.0.1",
        "001.002.003.004",
    ] {
        print_parse(text);
    }
    for text in [
        "",
        "1.2.3",
        "1.2.3.4.5",
        "256.1.1.1",
        "1..2.3",
        "a.b.c.d",
        "0001.2.3.4",
        "1.2.3.4.",
    ] {
        print_parse(text);
    }

    for text in [
        "0.0.0.0",
        "10.0.0.1",
        "127.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "172.32.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "100.128.0.1",
        "8.8.8.8",
    ] {
        let address: Ipv4Addr = text.parse().unwrap();
        println!(
            "case private4-{text}\nvalue={}",
            u8::from(is_local(IpAddr::V4(address)))
        );
    }

    for (name, text) in [
        ("unspecified", "::"),
        ("loopback", "::1"),
        ("fc00", "fc00::1"),
        ("fe80", "fe80::1"),
        ("ff02", "ff02::1"),
        ("mapped-private", "::ffff:192.168.1.1"),
        ("mapped-public", "::ffff:8.8.8.8"),
        ("public", "2001:db8::1"),
    ] {
        let address: Ipv6Addr = text.parse().unwrap();
        println!(
            "case private6-{name}\nvalue={}",
            u8::from(is_local(IpAddr::V6(address)))
        );
    }
}
