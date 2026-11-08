//! TG14: DNS-wire encode/parse в формате C-оракула.

use std::path::Path;

use r2o_telegram::doh_wire::{encode_question, parse_response};

fn print_address(address: std::net::IpAddr) {
    match address {
        std::net::IpAddr::V4(ip) => {
            for byte in ip.octets() {
                print!("{byte:02x}");
            }
        }
        std::net::IpAddr::V6(ip) => {
            for byte in ip.octets() {
                print!("{byte:02x}");
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("encode") => {
            let domain = &args[1];
            let qtype: u16 = args[2].parse().unwrap();
            match encode_question(domain, qtype, 0x1234) {
                Ok(packet) => {
                    print!("encode {domain} ok=1 hex=");
                    for byte in packet {
                        print!("{byte:02x}");
                    }
                    println!();
                }
                Err(_) => println!("encode {domain} ok=0"),
            }
        }
        Some("parse") => {
            let dir = &args[1];
            for name in &args[2..] {
                let path = Path::new(dir).join(format!("{name}.bin"));
                let Ok(packet) = std::fs::read(&path) else {
                    println!("parse {name} ok=-1");
                    continue;
                };
                match parse_response(&packet, 0x1234) {
                    Ok(addresses) => {
                        print!("parse {name} ok=1 count={}", addresses.len());
                        for address in addresses {
                            print!(" ");
                            print_address(address);
                        }
                        println!();
                    }
                    Err(_) => println!("parse {name} ok=0 count=0"),
                }
            }
        }
        _ => panic!("режим"),
    }
}
