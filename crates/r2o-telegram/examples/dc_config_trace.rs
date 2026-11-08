//! TG4: сгенерировать TL-байты `help.getConfig` и напечатать Rust snapshot.
//!
//! Использование: `dc_config_trace OUTPUT_DIR`
//!
//! В каталог пишутся `<case>.bin` и `cases.txt` (порядок кейсов), чтобы тот же
//! набор байтов разобрал C-оракул `tg_mtproto_config_parse`.

use std::fs;
use std::io::Write as _;
use std::net::IpAddr;

use grammers_tl_types::Serializable;
use grammers_tl_types::{self as tl};
use r2o_telegram::dc_discovery::config_bytes_to_snapshot;

const NOW: i64 = 1_800_000_000;

#[allow(clippy::too_many_arguments)]
fn option_full(
    id: i32,
    address: &str,
    port: i32,
    ipv6: bool,
    media_only: bool,
    tcpo_only: bool,
    cdn: bool,
    is_static: bool,
    this_port_only: bool,
    secret: Option<Vec<u8>>,
) -> tl::enums::DcOption {
    tl::types::DcOption {
        ipv6,
        media_only,
        tcpo_only,
        cdn,
        r#static: is_static,
        this_port_only,
        id,
        ip_address: address.to_string(),
        port,
        secret,
    }
    .into()
}

fn option(id: i32, address: &str) -> tl::enums::DcOption {
    option_full(
        id,
        address,
        443,
        address.parse::<IpAddr>().unwrap().is_ipv6(),
        false,
        false,
        false,
        true,
        false,
        None,
    )
}

fn primary_options() -> Vec<tl::enums::DcOption> {
    vec![
        option(1, "149.154.175.50"),
        option(2, "149.154.167.51"),
        option(3, "149.154.175.100"),
        option(4, "149.154.167.91"),
        option(5, "149.154.171.5"),
    ]
}

fn base_config(
    date: i32,
    expires: i32,
    this_dc: i32,
    dc_options: Vec<tl::enums::DcOption>,
) -> tl::types::Config {
    tl::types::Config {
        default_p2p_contacts: true,
        preload_featured_stickers: true,
        revoke_pm_inbox: true,
        blocked_mode: true,
        force_try_ipv6: false,
        date,
        expires,
        test_mode: false,
        this_dc,
        dc_options,
        dc_txt_domain_name: "apv3.stel.com".to_string(),
        chat_size_max: 200,
        megagroup_size_max: 200000,
        forwarded_count_max: 100,
        online_update_period_ms: 120000,
        offline_blur_timeout_ms: 5000,
        offline_idle_timeout_ms: 30000,
        online_cloud_timeout_ms: 300000,
        notify_cloud_delay_ms: 30000,
        notify_default_delay_ms: 5000,
        push_chat_period_ms: 60000,
        push_chat_limit: 2,
        edit_time_limit: 172800,
        revoke_time_limit: 172800,
        revoke_pm_time_limit: 2147483647,
        rating_e_decay: 2419200,
        stickers_recent_limit: 200,
        channels_read_media_period: 604800,
        tmp_sessions: None,
        call_receive_timeout_ms: 20000,
        call_ring_timeout_ms: 90000,
        call_connect_timeout_ms: 30000,
        call_packet_timeout_ms: 10000,
        me_url_prefix: "https://t.me/".to_string(),
        autoupdate_url_prefix: None,
        gif_search_username: None,
        venue_search_username: None,
        img_search_username: None,
        static_maps_provider: None,
        caption_length_max: 1024,
        message_length_max: 4096,
        webfile_dc_id: 4,
        suggested_lang_code: None,
        lang_pack_version: None,
        base_lang_pack_version: None,
        reactions_default: None,
        autologin_token: None,
    }
}

fn fresh_config(options: Vec<tl::enums::DcOption>) -> tl::types::Config {
    base_config(NOW as i32 - 100, NOW as i32 + 86_400, 2, options)
}

fn valid_config() -> tl::types::Config {
    let mut options = primary_options();
    options[0] = option_full(
        1,
        "149.154.175.50",
        443,
        false,
        false,
        true,
        false,
        true,
        false,
        Some(vec![0xaa, 0xbb, 0xcc, 0xdd]),
    );
    options.push(option_full(
        4,
        "2001:67c:4e8:f004::a",
        5222,
        true,
        true,
        false,
        false,
        false,
        true,
        None,
    ));
    options.push(option_full(
        203,
        "91.105.192.100",
        443,
        false,
        false,
        false,
        true,
        true,
        false,
        None,
    ));
    fresh_config(options)
}

/// Полный TL-объект `config#cc1a241e`, как его присылает Telegram и ждёт C.
fn serialize(config: tl::types::Config) -> Vec<u8> {
    tl::enums::Config::Config(config).to_bytes()
}

fn tl_bytes_field(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if value.len() < 254 {
        out.push(value.len() as u8);
    } else {
        out.push(254);
        out.push(value.len() as u8);
        out.push((value.len() >> 8) as u8);
        out.push((value.len() >> 16) as u8);
    }
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn gzip_packed(payload: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(payload).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&0x3072_cfa1_u32.to_le_bytes());
    out.extend_from_slice(&tl_bytes_field(&compressed));
    out
}

fn find_constructor(haystack: &[u8], constructor: u32) -> Option<usize> {
    haystack
        .windows(4)
        .position(|window| window == constructor.to_le_bytes())
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

fn report_bytes(name: &str, bytes: &[u8], dir: &str) {
    fs::write(format!("{dir}/{name}.bin"), bytes).unwrap();
    match config_bytes_to_snapshot(bytes, NOW) {
        Ok(snapshot) => {
            print!(
                "{name} ok=1 schema={} fetched={} date={} expires={} this_dc={} count={}",
                snapshot.schema_version,
                snapshot.fetched_at,
                snapshot.config_date,
                snapshot.config_expires,
                snapshot.this_dc,
                snapshot.endpoints.len()
            );
            for (index, endpoint) in snapshot.endpoints.iter().enumerate() {
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
                print!(
                    "/{}",
                    endpoint
                        .secret
                        .as_ref()
                        .map_or(0, |secret| secret.len() / 2)
                );
            }
            println!();
        }
        Err(_) => println!("{name} ok=0"),
    }
}

fn report(name: &str, config: tl::types::Config, dir: &str) {
    report_bytes(name, &serialize(config), dir);
}

fn replace_primary(replacement: tl::enums::DcOption) -> tl::types::Config {
    let mut options = primary_options();
    options[0] = replacement;
    fresh_config(options)
}

fn main() {
    let dir = std::env::args().nth(1).expect("OUTPUT_DIR");
    fs::create_dir_all(&dir).unwrap();

    let valid = valid_config();
    report("valid", valid.clone(), &dir);
    let valid_bytes = serialize(valid.clone());
    report_bytes("valid-gzip", &gzip_packed(&valid_bytes), &dir);
    report_bytes(
        "valid-gzip-nested",
        &gzip_packed(&gzip_packed(&valid_bytes)),
        &dir,
    );

    let mut unknown_config_flag = valid_bytes.clone();
    let flags = u32::from_le_bytes(unknown_config_flag[4..8].try_into().unwrap());
    unknown_config_flag[4..8].copy_from_slice(&(flags | (1 << 5)).to_le_bytes());
    report_bytes("unknown-config-flag", &unknown_config_flag, &dir);

    let mut trailing = valid_bytes.clone();
    trailing.extend_from_slice(&[0, 0, 0, 0]);
    report_bytes("trailing-bytes", &trailing, &dir);

    let mut unknown_dc_flag = valid_bytes.clone();
    if let Some(at) = find_constructor(&valid_bytes, 0x18b7_a10d) {
        let flags = u32::from_le_bytes(unknown_dc_flag[at + 4..at + 8].try_into().unwrap());
        unknown_dc_flag[at + 4..at + 8].copy_from_slice(&(flags | (1 << 6)).to_le_bytes());
    }
    report_bytes("unknown-dc-flag", &unknown_dc_flag, &dir);

    report("empty-options", fresh_config(Vec::new()), &dir);
    let mut missing = primary_options();
    missing.pop();
    report("missing-primary", fresh_config(missing), &dir);

    report(
        "bad-id",
        replace_primary(option_full(
            0,
            "149.154.175.50",
            443,
            false,
            false,
            false,
            false,
            true,
            false,
            None,
        )),
        &dir,
    );
    report(
        "bad-port",
        replace_primary(option_full(
            1,
            "149.154.175.50",
            0,
            false,
            false,
            false,
            false,
            true,
            false,
            None,
        )),
        &dir,
    );
    report(
        "bad-address",
        replace_primary(option_full(
            1,
            "not-an-ip",
            443,
            false,
            false,
            false,
            false,
            true,
            false,
            None,
        )),
        &dir,
    );
    report(
        "ipv6-flag-mismatch",
        replace_primary(option_full(
            1,
            "2001:67c:4e8:f001::a",
            443,
            false,
            false,
            false,
            false,
            true,
            false,
            None,
        )),
        &dir,
    );
    report(
        "cgnat",
        replace_primary(option_full(
            1,
            "100.64.0.1",
            443,
            false,
            false,
            false,
            false,
            true,
            false,
            None,
        )),
        &dir,
    );
    report(
        "documentation-v6",
        replace_primary(option_full(
            1,
            "2001:db8::1",
            443,
            true,
            false,
            false,
            false,
            true,
            false,
            None,
        )),
        &dir,
    );
    report(
        "empty-secret",
        replace_primary(option_full(
            1,
            "149.154.175.50",
            443,
            false,
            false,
            false,
            false,
            true,
            false,
            Some(Vec::new()),
        )),
        &dir,
    );
    report(
        "wrong-expires",
        base_config(
            NOW as i32 - 100,
            NOW as i32 - 100,
            2,
            valid.dc_options.clone(),
        ),
        &dir,
    );
    report(
        "this-dc-zero",
        base_config(
            NOW as i32 - 100,
            NOW as i32 + 86_400,
            0,
            valid.dc_options.clone(),
        ),
        &dir,
    );

    let names = [
        "valid",
        "valid-gzip",
        "valid-gzip-nested",
        "unknown-config-flag",
        "trailing-bytes",
        "unknown-dc-flag",
        "empty-options",
        "missing-primary",
        "bad-id",
        "bad-port",
        "bad-address",
        "ipv6-flag-mismatch",
        "cgnat",
        "documentation-v6",
        "empty-secret",
        "wrong-expires",
        "this-dc-zero",
    ];
    let mut cases = String::new();
    for name in names {
        cases.push_str(name);
        cases.push('\n');
    }
    fs::write(format!("{dir}/cases.txt"), cases).unwrap();
}
