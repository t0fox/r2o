//! CL13: Rust trace HTTPS-зонда и кэша состояний.
//!
//! ```text
//! tg_cl13_httpsprobe_trace DIR CASES OUTDIR
//! ```

use r2o_controller::https_probe::HttpsProbeWorker;
use r2o_controller::response::{HttpsProbeState, classify_https_probe};
use std::time::{Duration, Instant};

fn state_by_number(number: i32) -> Option<HttpsProbeState> {
    match number {
        1 => Some(HttpsProbeState::Served),
        2 => Some(HttpsProbeState::Closed),
        3 => Some(HttpsProbeState::OtherName),
        4 => Some(HttpsProbeState::Unconfirmed),
        6 => Some(HttpsProbeState::TlsBlocked),
        _ => None,
    }
}

fn state_name(number: i32) -> &'static str {
    match number {
        0 => "unknown",
        1 => "served",
        2 => "closed",
        3 => "other-name",
        4 => "unconfirmed",
        5 => "probing",
        6 => "tls-blocked",
        _ => "unknown",
    }
}

fn print_file(name: &str, path: &std::path::Path) {
    let Ok(bytes) = std::fs::read(path) else {
        println!("file {name} <open-error>");
        return;
    };
    let text = String::from_utf8_lossy(&bytes);
    for line in text.split_inclusive('\n') {
        // Строка уже содержит '\n'; println добавил бы лишнюю пустую строку,
        // которой у C-оракула нет.
        print!("file {name} {line}");
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("DIR");
    let cases_path = args.next().expect("CASES");
    let out_dir = args.next().expect("OUTDIR");

    for connect in 0..=3 {
        for server_tls in 0..=1 {
            for tls_ok in 0..=1 {
                for peer_name in -1..=1 {
                    let state =
                        classify_https_probe(connect, server_tls != 0, tls_ok != 0, peer_name);
                    println!(
                        "classify cr={connect} st={server_tls} tls={tls_ok} pn={peer_name} -> {}",
                        state.stored_name()
                    );
                }
            }
        }
    }

    for number in 0..=7 {
        match state_by_number(number) {
            Some(state) => println!(
                "state {number} upgrade={} ttl={} name={}",
                u8::from(state.should_redirect()),
                state.ttl_seconds(),
                state.stored_name()
            ),
            None => println!("state {number} upgrade=0 ttl=0 name={}", state_name(number)),
        }
    }

    let cases = std::fs::read_to_string(cases_path).expect("cases");
    for name in cases.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let path = std::path::Path::new(&dir).join(format!("{name}.txt"));
        let out_path = std::path::Path::new(&out_dir).join(format!("{name}.txt"));
        let loaded = HttpsProbeWorker::load_cache(&path, 1_700_000_000);
        match loaded {
            Ok(entries) => {
                let push: Vec<_> = entries
                    .iter()
                    .filter(|(_, state, _)| state.should_redirect())
                    .take(128)
                    .collect();
                println!(
                    "load {name} rc=0 loaded={} push={}",
                    entries.len(),
                    push.len()
                );
                for (host, state, ttl) in push {
                    println!("push {name} {host} {} {ttl}", state.stored_name());
                }
                let mut worker = HttpsProbeWorker::new(None);
                let base = Instant::now();
                for (host, state, ttl) in &entries {
                    worker.restore_cached(host, *state, *ttl, base);
                }
                let saved =
                    worker.save_cache(&out_path, 1_700_000_010, base + Duration::from_secs(10));
                println!("save {name} rc={}", i32::from(saved.is_err()));
                print_file(name, &out_path);
            }
            Err(_) => println!("load {name} rc=-1 loaded=0 push=0"),
        }
    }
}
