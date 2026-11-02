use r2o_datapath::conntrack::{R2oConntrackTuple, encode_get};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

#[test]
#[ignore = "run through scripts/r2o-conntrack-ctget-differential.sh"]
fn ct_get_bytes_match_d2o_for_ipv4_and_ipv6() {
    let oracle = std::env::var_os("D2O_CONNTRACK_ORACLE").expect("C oracle path is set");
    let cases = [
        (4, 6, "192.0.2.17", 12345, "198.51.100.9", 443),
        (4, 17, "192.0.2.53", 53000, "198.51.100.53", 53),
        (6, 6, "2001:db8::17", 12345, "2001:db8:1::9", 443),
        (6, 17, "2001:db8:ffff::53", 53000, "2001:db8:ffff::9", 5353),
    ];

    for (family, protocol, source, source_port, destination, destination_port) in cases {
        let mut source_bytes = [0; 16];
        let mut destination_bytes = [0; 16];
        if family == 4 {
            source_bytes[..4].copy_from_slice(&source.parse::<Ipv4Addr>().unwrap().octets());
            destination_bytes[..4]
                .copy_from_slice(&destination.parse::<Ipv4Addr>().unwrap().octets());
        } else {
            source_bytes = source.parse::<Ipv6Addr>().unwrap().octets();
            destination_bytes = destination.parse::<Ipv6Addr>().unwrap().octets();
        }
        let tuple = R2oConntrackTuple {
            family,
            protocol,
            source: source_bytes,
            destination: destination_bytes,
            source_port,
            destination_port,
        };
        let rust = encode_get(0x01020304, &tuple).expect("supported conntrack tuple");
        let output = Command::new(&oracle)
            .args([
                family.to_string(),
                protocol.to_string(),
                source.to_owned(),
                source_port.to_string(),
                destination.to_owned(),
                destination_port.to_string(),
            ])
            .output()
            .expect("run D2O C oracle");
        assert!(
            output.status.success(),
            "C oracle rejected {family}/{protocol} {source}:{source_port} -> {destination}:{destination_port}: {:?}",
            output
        );
        let c_hex = String::from_utf8(output.stdout).unwrap();
        let c = decode_hex(c_hex.trim());
        assert_eq!(
            rust, c,
            "CT_GET request mismatch for {family}/{protocol} {source}:{source_port} -> {destination}:{destination_port}"
        );
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "odd-length C output: {text}");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let byte = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(byte, 16).unwrap()
        })
        .collect()
}
