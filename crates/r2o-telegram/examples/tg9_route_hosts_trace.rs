//! TG9: печатает DC→WSS/CF host lists в формате donor-дифференциала.
//!
//! ```text
//! tg9_route_hosts_trace CASES_TSV
//! ```

use r2o_telegram::ws_client::{cf_ws_domains, ws_domains};

fn print_list(name: &str, hosts: Vec<String>) {
    if hosts.is_empty() {
        println!("{name} hosts=-");
    } else {
        println!("{name} hosts={}", hosts.join(","));
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("CASES_TSV");
    let text = std::fs::read_to_string(path).expect("cases file");
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            ["ws", name, dc, media] => {
                let dc: u32 = dc.parse().unwrap();
                let media = *media == "1";
                print_list(&format!("ws-{name}"), ws_domains(dc, media));
            }
            ["cf", name, dc, media, domains] => {
                let dc: u32 = dc.parse().unwrap();
                let media = *media == "1";
                let domains = domains
                    .split(',')
                    .filter(|domain| !domain.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                print_list(&format!("cf-{name}"), cf_ws_domains(dc, &domains, media));
            }
            _ => continue,
        }
    }
}
