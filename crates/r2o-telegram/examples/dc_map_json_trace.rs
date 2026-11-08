//! Печатает parse/validate DC map в формате C `d2o_dc_map_json_trace.c`.

use r2o_telegram::dc_map::{DcSnapshot, validate_snapshot};
use std::net::IpAddr;

const VALID_JSON: &str = "{\"schema_version\":1,\"fetched_at\":1800000000,\
\"config_date\":1799999900,\"config_expires\":1800086400,\
\"this_dc\":2,\"endpoints\":[\
{\"id\":1,\"address\":\"149.154.175.50\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":true,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":\"aabbccdd\",\"last_seen\":1800000000},\
{\"id\":2,\"address\":\"149.154.167.51\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},\
{\"id\":3,\"address\":\"149.154.175.100\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},\
{\"id\":4,\"address\":\"149.154.167.91\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},\
{\"id\":5,\"address\":\"149.154.171.5\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}]}";

fn with_endpoint(endpoint: &str) -> String {
    format!("{},{}]}}", &VALID_JSON[..VALID_JSON.len() - 2], endpoint)
}

fn family(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 2,
        IpAddr::V6(_) => 10,
    }
}

fn report(name: &str, json: &str, now: i64) {
    let parsed = if json.len() > 1024 * 1024 {
        None
    } else {
        serde_json::from_str::<DcSnapshot>(json)
            .ok()
            .filter(|snapshot| validate_snapshot(snapshot, now).is_ok())
    };
    print!("{name} ok={}", u8::from(parsed.is_some()));
    if let Some(snapshot) = parsed {
        print!(
            " schema={} fetched={} date={} expires={} this_dc={} count={}",
            snapshot.schema_version,
            snapshot.fetched_at,
            snapshot.config_date,
            snapshot.config_expires,
            snapshot.this_dc,
            snapshot.endpoints.len()
        );
        for (index, endpoint) in snapshot.endpoints.iter().enumerate() {
            print!(
                " e{index}={}/{}/{}/{}/{}/{}/{}/{}/{}",
                endpoint.id,
                family(endpoint.address),
                endpoint.port,
                u8::from(endpoint.media_only),
                u8::from(endpoint.tcpo_only),
                u8::from(endpoint.cdn),
                u8::from(endpoint.is_static),
                u8::from(endpoint.this_port_only),
                endpoint
                    .secret
                    .as_ref()
                    .map_or(0, |secret| secret.len() / 2)
            );
        }
    }
    println!();
}

fn main() {
    report("valid", VALID_JSON, 1_800_000_000);
    report(
        "duplicate",
        "{\"schema_version\":1,\"schema_version\":1}",
        1_800_000_000,
    );
    report("unknown", "{\"unexpected\":true}", 1_800_000_000);
    let bad_address = "{\"schema_version\":1,\"fetched_at\":1800000000,\
\"config_date\":1799999900,\"config_expires\":1800086400,\
\"this_dc\":2,\"endpoints\":[{\"id\":1,\"address\":\"bad\"}]}";
    report("bad-address", bad_address, 1_800_000_000);
    let marker = "\"this_dc\":2,";
    if let Some(at) = VALID_JSON.find(marker) {
        let offset = at + marker.len();
        let duplicate = format!(
            "{}{}{}",
            &VALID_JSON[..offset],
            marker,
            &VALID_JSON[offset..]
        );
        report("duplicate-valid", &duplicate, 1_800_000_000);
    }
    report("future-clock", VALID_JSON, i64::MIN);

    let mut oversized = VALID_JSON.as_bytes().to_vec();
    oversized.resize(1024 * 1024 + 1, b' ');
    report(
        "oversized",
        std::str::from_utf8(&oversized).unwrap(),
        1_800_000_000,
    );

    let wrong_schema = "{\"schema_version\":2,\"fetched_at\":1800000000,\
\"config_date\":1799999900,\"config_expires\":1800086400,\
\"this_dc\":2,\"endpoints\":[]}";
    report("wrong-schema", wrong_schema, 1_800_000_000);

    let cgnat = with_endpoint(
        "{\"id\":1,\"address\":\"100.64.0.1\",\"port\":443,\"ipv6\":false,\
\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\
\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}",
    );
    report("cgnat", &cgnat, 1_800_000_000);

    let mapped = with_endpoint(
        "{\"id\":1,\"address\":\"::ffff:127.0.0.1\",\"port\":443,\"ipv6\":true,\
\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\
\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}",
    );
    report("v4-mapped-loopback", &mapped, 1_800_000_000);

    let documentation = with_endpoint(
        "{\"id\":1,\"address\":\"2001:db8::1\",\"port\":443,\"ipv6\":true,\
\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\
\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}",
    );
    report("documentation-v6", &documentation, 1_800_000_000);

    let mismatch = with_endpoint(
        "{\"id\":1,\"address\":\"149.154.175.50\",\"port\":443,\"ipv6\":true,\
\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\
\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}",
    );
    report("ipv6-flag-mismatch", &mismatch, 1_800_000_000);

    let odd_secret = with_endpoint(
        "{\"id\":1,\"address\":\"149.154.175.50\",\"port\":443,\"ipv6\":false,\
\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\
\"this_port_only\":false,\"secret\":\"abc\",\"last_seen\":1800000000}",
    );
    report("odd-secret", &odd_secret, 1_800_000_000);
}
