//! TG13: CF-домены/кэш в формате C-оракула.
//!
//! ```text
//! tg13_trace parse DIR NAME...
//! tg13_trace pool NAME CACHE MANUAL
//! tg13_trace write CACHE
//! ```

use std::path::Path;

use r2o_telegram::cf_domain_pool::CfDomainPool;
use r2o_telegram::default_domains::parse_remote_domains;

fn print_pool(pool: &CfDomainPool) {
    let snapshot = pool.snapshot();
    print!("count={}", snapshot.domains.len());
    for domain in &snapshot.domains {
        print!(" {domain}");
    }
    println!(" fetched={}", snapshot.fetched_at);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("parse") => {
            let dir = &args[1];
            for name in &args[2..] {
                let path = Path::new(dir).join(format!("{name}.txt"));
                let Ok(text) = std::fs::read(&path) else {
                    println!("{name} ok=-1");
                    continue;
                };
                let Ok(text) = std::str::from_utf8(&text) else {
                    println!("{name} ok=0");
                    continue;
                };
                match parse_remote_domains(text) {
                    Ok(domains) => {
                        print!("{name} ok=1 count={}", domains.len());
                        for domain in domains {
                            print!(" {domain}");
                        }
                        println!();
                    }
                    Err(_) => println!("{name} ok=0"),
                }
            }
        }
        Some("pool") => {
            let name = &args[1];
            let cache = &args[2];
            let manual = &args[3];
            let manual = if manual.is_empty() {
                Vec::new()
            } else {
                vec![manual.clone()]
            };
            let pool = CfDomainPool::new(manual, true, cache.into());
            print!("pool {name} ok=1 ");
            print_pool(&pool);
        }
        Some("write") => {
            let cache = &args[1];
            let pool = CfDomainPool::new(Vec::new(), true, cache.into());
            let installed = pool
                .replace_remote(
                    vec![
                        "alpha.co.uk".to_string(),
                        "beta.co.uk".to_string(),
                        "gamma.co.uk".to_string(),
                    ],
                    456,
                )
                .is_ok();
            print!("write init=1 install={} ", u8::from(installed));
            print_pool(&pool);
            if installed {
                let bytes = std::fs::read(cache).unwrap();
                print!("cache=");
                for byte in bytes {
                    print!("{byte:02x}");
                }
                println!();
            }
        }
        _ => panic!("режим"),
    }
}
