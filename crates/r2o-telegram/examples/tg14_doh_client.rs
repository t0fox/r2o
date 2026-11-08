//! TG14: Rust DoH-only lookup в формате C-оракула `doh_lookup`.
//!
//! ```text
//! tg14_doh_client CA_PEM DOMAIN
//! ```

use std::path::Path;

use r2o_telegram::cf_proxy_doh::resolve_cf_ips_via_doh;
use r2o_telegram::outbound::OutboundConnector;

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

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ca = &args[0];
    let domain = &args[1];
    match resolve_cf_ips_via_doh(domain, &OutboundConnector::direct(), Some(Path::new(ca))).await {
        Ok(addresses) => {
            print!("ok=1 count={}", addresses.len());
            for address in addresses {
                print!(" ");
                print_address(address);
            }
            println!();
        }
        Err(error) => {
            eprintln!("doh: {error}");
            println!("ok=0");
        }
    }
}
