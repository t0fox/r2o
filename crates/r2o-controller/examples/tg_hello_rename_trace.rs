//! C/Rust differential: `d2k_hello_rename`/`splice_sni`.
//!
//! ```text
//! tg_hello_rename_trace DIR CASES
//! ```

use r2o_controller::hello::r2o_hello_rename;

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("DIR");
    let cases = args.next().expect("CASES");
    let text = std::fs::read_to_string(cases).expect("cases");
    for name in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let path = format!("{dir}/{name}.bin");
        let Ok(bytes) = std::fs::read(&path) else {
            println!("{name} read-error");
            continue;
        };
        let body = if bytes.len() >= 5 {
            &bytes[5..]
        } else {
            bytes.as_slice()
        };
        let renamed = r2o_hello_rename(body, b"new.example");
        match &renamed {
            Some(output) => {
                print!("{name} rename=0 len={} hex=", output.len());
                for byte in output {
                    print!("{byte:02x}");
                }
                println!();
            }
            None => println!("{name} rename=-1 len=0 hex="),
        }
    }
}
