//! D18: Rust trace addr helpers.

use r2k_core::addr::Address;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let cases = [
        ("v4-zero", "0.0.0.0"),
        ("v4-loop", "127.0.0.1"),
        ("v4-doc", "192.0.2.1"),
        ("v4-broadcast", "255.255.255.255"),
        ("v4-leading-zero", "192.000.002.001"),
        ("v4-short", "192.0.2"),
        ("v4-long", "192.0.2.1.5"),
        ("v4-big", "256.0.0.1"),
        ("v4-garbage", "abc"),
        ("v4-empty", ""),
        ("v4-zone", "192.0.2.1%eth0"),
        ("v6-zero", "::"),
        ("v6-loop", "::1"),
        ("v6-doc", "2001:db8::1"),
        ("v6-link", "fe80::1"),
        ("v6-full", "2001:0db8:0000:0000:0000:0000:0000:0001"),
        ("v6-mapped", "::ffff:192.0.2.1"),
        ("v6-zone", "fe80::1%lo"),
        ("v6-bad", "2001:db8::g"),
    ];
    let mut parsed = Vec::new();
    for (name, text) in cases {
        match Address::parse(text) {
            Ok(address) => {
                let family = address.family();
                let bytes = address.bytes();
                let length = if family == 4 { 4 } else { 16 };
                println!(
                    "parse {name} ok=1 family={family} bytes={}",
                    hex(&bytes[..length])
                );
                let text = address.to_string();
                println!("text {name} ok={} text={text}", text.len());
                parsed.push(Some(address));
            }
            Err(_) => {
                println!("parse {name} ok=0");
                parsed.push(None);
            }
        }
    }
    let pairs = [
        ("v4-zero", "v4-zero"),
        ("v4-loop", "v4-doc"),
        ("v6-doc", "v6-doc"),
        ("v6-mapped", "v4-doc"),
        ("v6-loop", "v6-zero"),
    ];
    for (left, right) in pairs {
        let left_index = cases.iter().position(|(name, _)| *name == left).unwrap();
        let right_index = cases.iter().position(|(name, _)| *name == right).unwrap();
        let equal = parsed[left_index]
            .is_some_and(|address| parsed[right_index].is_some_and(|other| address == other));
        println!("equal {left} {right} ={}", u8::from(equal));
    }
}
