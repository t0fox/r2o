//! Печать TLS1.2 sealed-записи для C/Rust differential.

use r2o_controller::tls12::Tls12RecordWriter;

fn main() {
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut writer = Tls12RecordWriter::new([0xa1, 0xb2, 0xc3, 0xd4], key, 1);
    match writer.seal(23, b"hello") {
        Ok(wire) => {
            print!("sealed|");
            for byte in &wire {
                print!("{byte:02x}");
            }
            println!("|seq={}", writer.sequence());
        }
        Err(error) => println!("sealed|-|err={error}"),
    }
}
