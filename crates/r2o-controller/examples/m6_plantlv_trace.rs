//! M6: Rust trace `plantlv` — текст плана в TLV, общая фикстура с C.

use r2o_controller::plan_text::compile_text;

fn print_case(name: &str, text: &str) {
    println!("case {name}");
    match compile_text(text) {
        Ok(bytes) => {
            print!("result ok\nhex ");
            for byte in bytes {
                print!("{byte:02x}");
            }
            println!();
        }
        Err(error) => {
            eprintln!("{name}: {error}");
            println!("result err");
        }
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: m6_plantlv_trace FIXTURE");
    let data = std::fs::read_to_string(&path).expect("fixture must be UTF-8");
    let mut position = 0;
    let mut current: Option<(&str, usize)> = None;
    for line in data.split_inclusive('\n') {
        let line_start = position;
        position += line.len();
        if let Some(rest) = line.strip_prefix("### ") {
            if let Some((name, start)) = current {
                print_case(name, &data[start..line_start]);
            }
            current = Some((rest.trim_end_matches(['\r', '\n']), position));
        }
    }
    if let Some((name, start)) = current {
        print_case(name, &data[start..]);
    }
}
