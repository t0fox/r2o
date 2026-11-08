//! Q2: Rust trace address pool / next-question.

use r2o_controller::quic_replay::{
    r2o_quic_address_pool, r2o_quic_next_question_address,
};
use std::net::SocketAddr;

fn extras() -> Vec<SocketAddr> {
    [
        "192.0.2.1:443",
        "[2001:db8::2]:443",
        "192.0.2.1:443",
        "192.0.2.3:443",
    ]
    .into_iter()
    .map(|value| value.parse().unwrap())
    .collect()
}

fn print_pool(name: &str, primary: &str) {
    let primary: SocketAddr = primary.parse().unwrap();
    let pool = r2o_quic_address_pool(primary, extras());
    println!("case {name}\nn={}", pool.len());
    for (index, address) in pool.iter().enumerate() {
        println!("{index}={}", address.ip());
    }
}

fn main() {
    print_pool("pool-v4", "192.0.2.2:443");
    print_pool("pool-v6", "[2001:db8:1234:5678::1]:443");

    let primary: SocketAddr = "192.0.2.2:443".parse().unwrap();
    let pool: Vec<SocketAddr> = ["192.0.2.2:443", "192.0.2.1:443", "192.0.2.3:443"]
        .into_iter()
        .map(|value| value.parse().unwrap())
        .collect();

    let mut next = 0;
    let address = r2o_quic_next_question_address(primary, &pool, &mut next, false);
    println!(
        "case next-pinned\naddr={}\nnext={next}",
        address.map_or_else(|| "none".to_owned(), |value| value.ip().to_string())
    );

    next = 0;
    for step in 0..4 {
        let address = r2o_quic_next_question_address(primary, &pool, &mut next, true);
        println!(
            "case next-residual-{step}\naddr={}\nnext={next}",
            address.map_or_else(|| "none".to_owned(), |value| value.ip().to_string())
        );
    }
}
