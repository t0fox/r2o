//! TG1: печатает нормализованный shared-интерфейс конфигурации.
//!
//! Используется differential-скриптом против z2kOW; R2O-only modes/пути
//! намеренно исключены (решение: core/CLI из z2kOW, R2O-режимы сохраняются).

use std::fmt::Display;

use r2o_telegram::config::Config;

const ENV_KEYS: &[&str] = &[
    "TG_CHECK",
    "TG_STATS_SOCKET",
    "TG_DC_MAP_PATH",
    "TG_DC_MAP_ENDPOINTS_PATH",
    "TG_DC_MAP_REFRESH_SECS",
    "TG_PORT",
    "TG_HOST",
    "TG_MAX_CONNECTIONS",
    "TG_VERBOSE",
    "TG_QUIET",
    "TG_LOG_FILE",
    "TG_CF_DOMAIN",
    "TG_CF_WORKER_DOMAIN",
    "TG_CF_BALANCE",
    "TG_CF_IP",
    "TG_WS_ROUTING",
    "TG_WS_HEDGE_DELAY_MS",
    "TG_WS_HEDGE_LIMIT",
    "TG_WS_CONNECT_TIMEOUT",
    "TG_WS_FAIL_PROBE_TIMEOUT",
    "TG_WS_FAIL_COOLDOWN",
    "TG_WS_REDIRECT_COOLDOWN",
    "TG_IP_FAIL_COOLDOWN",
    "TG_HANDSHAKE_TIMEOUT",
    "TG_TCP_FALLBACK_TIMEOUT",
    "TG_CF_CONNECT_TIMEOUT",
    "TG_CF_FAIL_COOLDOWN",
    "TG_DEFAULT_DOMAINS",
];

fn flag(value: bool) -> u8 {
    u8::from(value)
}

fn optional<T: Display>(value: &Option<T>) -> String {
    value
        .as_ref()
        .map_or_else(|| "-".to_string(), ToString::to_string)
}

fn list<T: Display>(values: &[T]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn print_config(name: &str, config: &Config) {
    println!(
        "{name} ok=1 check={} stats={} ports={} cidrs={} refresh={} port={} host={} max={} verbose={} quiet={} log={} cf={} worker={} balance={} cf_ips={} routing={:?} hedge_delay={} hedge_limit={} connect={} probe={} fail={} redirect={} ip_fail={} handshake={} tcp_fallback={} cf_connect={} cf_fail={} default_domains={}",
        flag(config.check),
        flag(config.stats),
        list(&config.transparent_ports),
        list(&config.transparent_cidrs),
        config.dc_map_refresh_secs,
        config.port,
        optional(&config.host),
        optional(&config.max_connections),
        flag(config.verbose),
        flag(config.quiet),
        optional(&config.log_file),
        list(&config.cf_domains),
        list(&config.cf_worker_domains),
        flag(config.cf_balance),
        list(&config.cf_ips),
        config.ws_routing,
        config.ws_hedge_delay_ms,
        config.ws_hedge_limit,
        config.ws_connect_timeout,
        config.ws_fail_probe_timeout,
        config.ws_fail_cooldown,
        config.ws_redirect_cooldown,
        config.ip_fail_cooldown,
        config.handshake_timeout,
        config.tcp_fallback_timeout,
        config.cf_connect_timeout,
        config.cf_fail_cooldown,
        flag(config.default_domains),
    );
}

fn main() {
    let path = std::env::args().nth(1).expect("CASES_TSV");
    let text = std::fs::read_to_string(path).expect("cases file");
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 3 {
            continue;
        }
        let (name, arguments, env) = (fields[0], fields[1], fields[2]);
        for key in ENV_KEYS {
            // SAFETY: probe однопоточный; env меняется до разбора Config.
            unsafe { std::env::remove_var(key) };
        }
        for pair in env.split(';').filter(|pair| !pair.is_empty()) {
            if let Some((key, value)) = pair.split_once('=') {
                // SAFETY: probe однопоточный; env меняется до разбора Config.
                unsafe { std::env::set_var(key, value) };
            }
        }
        match Config::try_from_cli_line(arguments) {
            Ok(config) => print_config(name, &config),
            Err(_) => println!("{name} ok=0"),
        }
    }
}
