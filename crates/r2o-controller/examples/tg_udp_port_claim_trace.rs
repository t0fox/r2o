//! C/Rust differential: `d2k_udp_port_claim` (кольцо недавних UDP-портов).
//!
//! ```text
//! tg_udp_port_claim_trace PORTS
//! ```

use r2o_controller::r2o_quic_http3::r2o_quic_udp_port_claim;

fn main() {
    let ports = std::env::args().nth(1).expect("PORTS");
    let text = std::fs::read_to_string(ports).expect("ports");
    for line in text.lines() {
        let Ok(port) = line.trim().parse::<u16>() else {
            continue;
        };
        println!("{port} rc={}", r2o_quic_udp_port_claim(port));
    }
}
