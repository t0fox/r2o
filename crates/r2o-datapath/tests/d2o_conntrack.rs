use r2o_datapath::conntrack::{R2oConntrackTuple, decode_info, encode_get};
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

#[test]
#[ignore = "run through scripts/r2o-conntrack-ctget-differential.sh"]
fn ct_get_ipv6_responses_match_d2o_counters_and_tcp_state() {
    let oracle = std::env::var_os("D2O_CONNTRACK_ORACLE").expect("C oracle path is set");
    let cases = [
        (7, 1_u64 << 32 | 2, 7, true, Some(3)),
        (8, 123, 456, false, None),
    ];

    for (sequence, original, reply, wide_counters, tcp_state) in cases {
        let message = ipv6_response(sequence, original, reply, wide_counters, tcp_state);
        let rust = decode_info(&message, sequence).expect("valid IPv6 conntrack response");
        let output = Command::new(&oracle)
            .args(["decode", &sequence.to_string(), &encode_hex(&message)])
            .output()
            .expect("run D2O C parser");
        assert!(
            output.status.success(),
            "C parser invocation failed: {output:?}"
        );
        let c = String::from_utf8(output.stdout).unwrap();
        let expected = format!(
            "0 {} {} {} {}",
            rust.original_packets,
            rust.reply_packets,
            u8::from(rust.tcp_state.is_some()),
            rust.tcp_state.unwrap_or_default()
        );
        assert_eq!(c.trim(), expected, "C/Rust IPv6 conntrack parser mismatch");
    }
}

fn ipv6_response(
    sequence: u32,
    original_packets: u64,
    reply_packets: u64,
    wide_counters: bool,
    tcp_state: Option<u8>,
) -> Vec<u8> {
    let original_counter = counter_attribute(original_packets, wide_counters);
    let reply_counter = counter_attribute(reply_packets, wide_counters);
    let mut body = vec![10, 0, 0, 0];
    body.extend(nest(9, &original_counter));
    body.extend(nest(10, &reply_counter));

    let mut reply_ip = Vec::new();
    reply_ip.extend(attribute(
        3,
        &"2001:db8:1::2".parse::<Ipv6Addr>().unwrap().octets(),
    ));
    reply_ip.extend(attribute(
        4,
        &"2001:db8:100::10".parse::<Ipv6Addr>().unwrap().octets(),
    ));
    let mut reply_protocol = Vec::new();
    reply_protocol.extend(attribute(1, &[6]));
    reply_protocol.extend(attribute(2, &443_u16.to_be_bytes()));
    reply_protocol.extend(attribute(3, &62000_u16.to_be_bytes()));
    let mut reply_tuple = Vec::new();
    reply_tuple.extend(nest(1, &reply_ip));
    reply_tuple.extend(nest(2, &reply_protocol));
    body.extend(nest(2, &reply_tuple));

    if let Some(state) = tcp_state {
        let tcp = attribute(1, &[state]);
        let protocol_info = nest(1, &tcp);
        body.extend(nest(4, &protocol_info));
    }

    let mut message = vec![0; 16];
    message.extend_from_slice(&body);
    let length = u32::try_from(message.len()).unwrap();
    message[..4].copy_from_slice(&length.to_ne_bytes());
    message[4..6].copy_from_slice(&0x0100_u16.to_ne_bytes());
    message[8..12].copy_from_slice(&sequence.to_ne_bytes());
    message
}

fn counter_attribute(value: u64, wide: bool) -> Vec<u8> {
    if wide {
        attribute(1, &value.to_be_bytes())
    } else {
        attribute(3, &(value as u32).to_be_bytes())
    }
}

fn nest(kind: u16, value: &[u8]) -> Vec<u8> {
    attribute(kind | 0x8000, value)
}

fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(4 + value.len()).unwrap();
    let mut result = Vec::new();
    result.extend_from_slice(&length.to_ne_bytes());
    result.extend_from_slice(&kind.to_ne_bytes());
    result.extend_from_slice(value);
    while result.len() % 4 != 0 {
        result.push(0);
    }
    result
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
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
