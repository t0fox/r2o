//! TG9: Rust trace `route_plan` в формате C-оракула.
//!
//! ```text
//! tg9_plan_trace PLAN_CASES HOSTNAME_CASES
//! ```

use r2o_telegram::route_plan::{RoutingPolicy, build_plan, cf_proxy_hostname};

fn parse_int(text: &str) -> Option<i32> {
    text.trim().parse().ok()
}

fn run_plans(path: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 8 {
            continue;
        }
        let name = fields[0];
        let Some(dc) = parse_int(fields[1]).and_then(|value| u32::try_from(value).ok()) else {
            println!("plan {name} ok=0");
            continue;
        };
        let Some(media) = parse_int(fields[2]) else {
            println!("plan {name} ok=0");
            continue;
        };
        let Some(policy) = parse_int(fields[3])
            .and_then(|value| u32::try_from(value).ok())
            .and_then(RoutingPolicy::from_number)
        else {
            println!("plan {name} ok=0");
            continue;
        };
        let Some(prefer) = parse_int(fields[4]) else {
            println!("plan {name} ok=0");
            continue;
        };
        let Some(workers) = parse_int(fields[5]).and_then(|value| usize::try_from(value).ok())
        else {
            println!("plan {name} ok=0");
            continue;
        };
        let Some(cf) = parse_int(fields[6]).and_then(|value| usize::try_from(value).ok()) else {
            println!("plan {name} ok=0");
            continue;
        };
        let Some(diag) = parse_int(fields[7]) else {
            println!("plan {name} ok=0");
            continue;
        };
        if !matches!(media, 0 | 1) || !matches!(prefer, 0 | 1) || !matches!(diag, 0 | 1) {
            println!("plan {name} ok=0");
            continue;
        }
        let Some(plan) = build_plan(dc, media == 1, policy, prefer == 1, workers, cf, diag == 1)
        else {
            println!("plan {name} ok=0");
            continue;
        };
        print!("plan {name} ok=1 count={} steps=", plan.steps.len());
        for (index, step) in plan.steps.iter().enumerate() {
            if index != 0 {
                print!(",");
            }
            print!("{}:{}", step.kind.number(), step.index);
        }
        println!();
    }
}

fn run_hostnames(path: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 5 {
            continue;
        }
        let name = fields[0];
        let Some(dc) = parse_int(fields[1]).and_then(|value| u32::try_from(value).ok()) else {
            println!("hostname {name} ok=0");
            continue;
        };
        let Some(media) = parse_int(fields[2]).and_then(|value| u8::try_from(value).ok()) else {
            println!("hostname {name} ok=0");
            continue;
        };
        let Some(capacity) = parse_int(fields[4]).and_then(|value| usize::try_from(value).ok())
        else {
            println!("hostname {name} ok=0");
            continue;
        };
        match cf_proxy_hostname(dc, media, fields[3], capacity) {
            Some(hostname) => println!("hostname {name} ok=1 value={hostname}"),
            None => println!("hostname {name} ok=0"),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run_plans(&args[0]);
    run_hostnames(&args[1]);
}
