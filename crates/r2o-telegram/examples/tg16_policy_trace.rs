//! TG16: печатает политику прозрачного перехвата в формате C-оракула.
//!
//! Использование: `tg16_policy_trace`

use r2o_telegram::transparent::destination_allowed;

fn cidrs(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn case(
    name: &str,
    address: &str,
    port: u16,
    ports: Vec<u16>,
    cidrs: Vec<String>,
) -> (String, String, u16, Vec<u16>, Vec<String>) {
    (name.to_string(), address.to_string(), port, ports, cidrs)
}

fn main() {
    let ports = vec![443u16, 5222];
    let valid = cidrs(&["149.154.0.0/16", "2001:67c::/32", "0.0.0.0/0"]);
    let cases = vec![
        case(
            "valid-v4",
            "149.154.167.51",
            443,
            ports.clone(),
            valid.clone(),
        ),
        case(
            "valid-v6",
            "2001:67c:4e8:f002::a",
            443,
            ports.clone(),
            valid.clone(),
        ),
        case(
            "port-80",
            "149.154.167.51",
            80,
            ports.clone(),
            valid.clone(),
        ),
        case("port-0", "149.154.167.51", 0, ports.clone(), valid.clone()),
        case(
            "port-not-listed",
            "149.154.167.51",
            8080,
            ports.clone(),
            valid.clone(),
        ),
        case(
            "empty-ports",
            "149.154.167.51",
            443,
            Vec::new(),
            valid.clone(),
        ),
        case(
            "too-many-ports",
            "149.154.167.51",
            443,
            vec![443; 33],
            valid.clone(),
        ),
        case(
            "empty-cidrs",
            "149.154.167.51",
            443,
            ports.clone(),
            Vec::new(),
        ),
        case(
            "too-many-cidrs",
            "149.154.167.51",
            443,
            ports.clone(),
            cidrs(&["0.0.0.0/0"; 65]),
        ),
        case(
            "cidr-miss",
            "8.8.8.8",
            443,
            ports.clone(),
            valid[..1].to_vec(),
        ),
        case("private-v4", "10.0.0.1", 443, ports.clone(), valid.clone()),
        case("cgnat", "100.64.0.1", 443, ports.clone(), valid.clone()),
        case("loopback", "127.0.0.1", 443, ports.clone(), valid.clone()),
        case(
            "link-local",
            "169.254.1.1",
            443,
            ports.clone(),
            valid.clone(),
        ),
        case("multicast", "224.0.0.1", 443, ports.clone(), valid.clone()),
        case(
            "broadcast",
            "255.255.255.255",
            443,
            ports.clone(),
            valid.clone(),
        ),
        case("unspecified", "0.0.0.0", 443, ports.clone(), valid.clone()),
        case(
            "documentation",
            "203.0.113.1",
            443,
            ports.clone(),
            valid.clone(),
        ),
        case("ula", "fd00::1", 443, ports.clone(), valid.clone()),
        case(
            "link-local-v6",
            "fe80::1",
            443,
            ports.clone(),
            valid.clone(),
        ),
        case(
            "documentation-v6",
            "2001:db8::1",
            443,
            ports.clone(),
            valid.clone(),
        ),
        case(
            "mapped-public",
            "::ffff:149.154.167.51",
            443,
            ports.clone(),
            valid.clone(),
        ),
        case(
            "mapped-loopback",
            "::ffff:127.0.0.1",
            443,
            ports.clone(),
            valid.clone(),
        ),
        case(
            "invalid-prefix-v4",
            "149.154.167.51",
            443,
            ports.clone(),
            cidrs(&["149.154.0.0/33"]),
        ),
        case(
            "invalid-prefix-v6",
            "2001:67c:4e8:f002::a",
            443,
            ports.clone(),
            cidrs(&["2001:67c::/129"]),
        ),
        case(
            "prefix-not-number",
            "149.154.167.51",
            443,
            ports.clone(),
            cidrs(&["149.154.0.0/x"]),
        ),
        case(
            "prefix-empty",
            "149.154.167.51",
            443,
            ports.clone(),
            cidrs(&["149.154.0.0/"]),
        ),
        case(
            "exact-ip",
            "149.154.167.51",
            443,
            ports,
            cidrs(&["149.154.167.51"]),
        ),
    ];
    for (name, address, port, ports, cidrs) in cases {
        let destination = format!("{address}:{port}")
            .parse::<std::net::SocketAddr>()
            .unwrap_or_else(|_| format!("[{address}]:{port}").parse().unwrap());
        println!(
            "{name} allowed={}",
            u8::from(destination_allowed(destination, &ports, &cidrs))
        );
    }
}
