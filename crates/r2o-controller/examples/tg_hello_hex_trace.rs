//! C/Rust differential: строгий `hex_decode` из `core/hello.c`.
//!
//! ```text
//! tg_hello_hex_trace CASES
//! ```

use r2o_controller::hello::r2o_hex_decode;

fn main() {
    let cases = std::env::args().nth(1).expect("CASES");
    let text = std::fs::read_to_string(cases).expect("cases");
    for line in text.lines() {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        match r2o_hex_decode(trimmed.as_bytes(), 16) {
            Some(bytes) => {
                print!("{trimmed} rc=0 len={} hex=", bytes.len());
                for byte in &bytes {
                    print!("{byte:02x}");
                }
                println!();
            }
            None => println!("{trimmed} rc=-1 len=0 hex="),
        }
    }
}
