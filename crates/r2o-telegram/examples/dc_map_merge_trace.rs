//! Печатает merge DC map в формате C `d2o_dc_map_merge_trace.c`.

use r2o_telegram::dc_map::{DcSnapshot, merge_snapshots, validate_snapshot};
use std::net::IpAddr;

const NOW: i64 = 1_800_000_000;

const VALID_JSON: &str = "{\"schema_version\":1,\"fetched_at\":1800000000,\
\"config_date\":1799999900,\"config_expires\":1800086400,\
\"this_dc\":2,\"endpoints\":[\
{\"id\":1,\"address\":\"149.154.175.50\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":true,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":\"aabbccdd\",\"last_seen\":1800000000},\
{\"id\":2,\"address\":\"149.154.167.51\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},\
{\"id\":3,\"address\":\"149.154.175.100\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},\
{\"id\":4,\"address\":\"149.154.167.91\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},\
{\"id\":5,\"address\":\"149.154.171.5\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}]}";

fn parse(json: &str) -> Option<DcSnapshot> {
    let snapshot = serde_json::from_str::<DcSnapshot>(json).ok()?;
    validate_snapshot(&snapshot, NOW).ok()?;
    Some(snapshot)
}

fn insert(json: &str, extra: &str) -> String {
    format!("{},{}]}}", &json[..json.len() - 2], extra)
}

fn print_address(address: IpAddr) {
    match address {
        IpAddr::V4(ip) => {
            for byte in ip.octets() {
                print!("{byte:02x}");
            }
        }
        IpAddr::V6(ip) => {
            for byte in ip.octets() {
                print!("{byte:02x}");
            }
        }
    }
}

fn family(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 2,
        IpAddr::V6(_) => 10,
    }
}

fn report(name: &str, previous: Option<&str>, incoming: &str) {
    let Some(incoming) = parse(incoming) else {
        println!("{name} ok=0");
        return;
    };
    let Some(previous) = previous.and_then(parse) else {
        println!("{name} ok=0");
        return;
    };
    match merge_snapshots(&previous, &incoming, NOW) {
        Ok(merged) => {
            print!("{name} ok=1 count={}", merged.endpoints.len());
            for (index, endpoint) in merged.endpoints.iter().enumerate() {
                print!(
                    " e{index}={}/{}/{}/{}/{}/{}/{}/{}/",
                    endpoint.id,
                    family(endpoint.address),
                    endpoint.port,
                    u8::from(endpoint.media_only),
                    u8::from(endpoint.tcpo_only),
                    u8::from(endpoint.cdn),
                    u8::from(endpoint.is_static),
                    u8::from(endpoint.this_port_only)
                );
                print_address(endpoint.address);
                print!("/{}", endpoint.secret.as_ref().map_or(0, |s| s.len() / 2));
            }
            println!();
        }
        Err(_) => println!("{name} ok=0"),
    }
}

fn main() {
    report("same", Some(VALID_JSON), VALID_JSON);

    let older = "{\"schema_version\":1,\"fetched_at\":1799999000,\
\"config_date\":1799999000,\"config_expires\":1800086400,\
\"this_dc\":2,\"endpoints\":[\
{\"id\":1,\"address\":\"149.154.175.50\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000},\
{\"id\":2,\"address\":\"149.154.167.51\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000},\
{\"id\":3,\"address\":\"149.154.175.100\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000},\
{\"id\":4,\"address\":\"149.154.167.91\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000},\
{\"id\":5,\"address\":\"149.154.171.5\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000}]}";
    report("older", Some(VALID_JSON), older);

    let previous = insert(
        VALID_JSON,
        "{\"id\":6,\"address\":\"8.8.8.8\",\"port\":443,\"ipv6\":false,\
\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\
\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000},\
{\"id\":7,\"address\":\"1.1.1.1\",\"port\":443,\"ipv6\":false,\
\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\
\"this_port_only\":false,\"secret\":null,\"last_seen\":1792223999},\
{\"id\":9,\"address\":\"149.154.167.51\",\"port\":443,\"ipv6\":false,\
\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\
\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000}",
    );
    report("retain-expire-replace", Some(&previous), VALID_JSON);

    let previous = insert(
        VALID_JSON,
        "{\"id\":2,\"address\":\"149.154.167.51\",\"port\":443,\"ipv6\":false,\
\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\
\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000}",
    );
    report("identity-ignores-static", Some(&previous), VALID_JSON);

    let incoming = insert(
        VALID_JSON,
        "{\"id\":4,\"address\":\"149.154.167.43\",\"port\":443,\"ipv6\":false,\
\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\
\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}",
    );
    report("builtin-conflict", Some(VALID_JSON), &incoming);
}
