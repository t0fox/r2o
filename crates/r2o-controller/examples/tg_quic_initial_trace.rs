//! C/Rust differential: `d2k_quic_is_initial` (структура без AEAD).
//!
//! ```text
//! tg_quic_initial_trace DIR CASES
//! ```

use r2k_core::quic::r2k_quic_is_initial;

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("DIR");
    let cases = args.next().expect("CASES");
    let text = std::fs::read_to_string(cases).expect("cases");
    for name in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let path = format!("{dir}/{name}.bin");
        match std::fs::read(&path) {
            Ok(bytes) => println!("{name} initial={}", u8::from(r2k_quic_is_initial(&bytes))),
            Err(_) => println!("{name} read-error"),
        }
    }
}
