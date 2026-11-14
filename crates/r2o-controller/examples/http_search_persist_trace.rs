//! C/Rust differential: `d2k_httpsearch_save/load` — файл `d2k-http-plans 1`.
//!
//! ```text
//! http_search_persist_trace <каталог>
//! ```

use r2o_controller::http_search::{R2oHttpPlanRecord, load_http_plans, save_http_plans};

fn write_file(dir: &std::path::Path, name: &str, text: &str) {
    std::fs::write(dir.join(name), text).unwrap();
}

fn print_hex(label: &str, dir: &std::path::Path, name: &str) {
    let path = dir.join(name);
    match std::fs::read(&path) {
        Ok(bytes) => {
            print!("{label} present=1 hex=");
            for byte in bytes {
                print!("{byte:02x}");
            }
            println!();
        }
        Err(_) => println!("{label} present=0 hex="),
    }
}

fn load_case(dir: &std::path::Path, name: &str, text: Option<&str>) {
    if let Some(text) = text {
        write_file(dir, name, text);
    }
    let result = load_http_plans(&dir.join(name));
    match result {
        Ok(result) => {
            print!("{name} rc=0 n={}", result.loaded);
            for record in &result.records {
                print!(
                    " rec={}/{}/{}/{}",
                    record.host, record.family, record.key, record.wall
                );
            }
            println!();
        }
        Err(_) => println!("{name} rc=-1 n=0"),
    }
}

fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).expect("каталог"));
    {
        let mut records = vec![
            R2oHttpPlanRecord {
                host: "alpha.example".into(),
                family: 4,
                key: "split".into(),
                wall: 111,
                revoked: false,
            },
            R2oHttpPlanRecord {
                host: "beta.example".into(),
                family: 6,
                key: "fake-badsum".into(),
                wall: 0,
                revoked: false,
            },
            R2oHttpPlanRecord {
                host: "gamma.example".into(),
                family: 4,
                key: String::new(),
                wall: 0,
                revoked: false,
            },
            R2oHttpPlanRecord {
                host: "delta.example".into(),
                family: 4,
                key: "disorder".into(),
                wall: 0,
                revoked: true,
            },
            R2oHttpPlanRecord {
                host: "eps.example".into(),
                family: 4,
                key: "fake-seqshift".into(),
                wall: -5,
                revoked: false,
            },
        ];
        let saved = save_http_plans(&dir.join("plans.txt"), &mut records, 999);
        println!(
            "save rc={} wall-a={} wall-b={} wall-e={}",
            i32::from(saved.is_err()),
            records[0].wall,
            records[1].wall,
            records[4].wall
        );
        print_hex("save", &dir, "plans.txt");
    }
    load_case(
        &dir,
        "valid.txt",
        Some(
            "d2k-http-plans 1\nalpha.example 4 split 111\n\
             beta.example 6 fake-badsum 222\n",
        ),
    );
    load_case(
        &dir,
        "bad-header.txt",
        Some("d2k-http-plans 2\nalpha.example 4 split 111\n"),
    );
    load_case(&dir, "no-header-newline.txt", Some("d2k-http-plans 1"));
    load_case(
        &dir,
        "bad-family.txt",
        Some("d2k-http-plans 1\nalpha.example 5 split 111\n"),
    );
    load_case(
        &dir,
        "bad-host.txt",
        Some("d2k-http-plans 1\n_bad.example 4 split 111\n"),
    );
    load_case(
        &dir,
        "unknown-key.txt",
        Some("d2k-http-plans 1\nalpha.example 4 other 111\n"),
    );
    load_case(
        &dir,
        "extra-token.txt",
        Some("d2k-http-plans 1\nalpha.example 4 split 111 x\n"),
    );
    load_case(
        &dir,
        "duplicate.txt",
        Some(
            "d2k-http-plans 1\nalpha.example 4 split 111\n\
             ALPHA.example 4 disorder 222\n",
        ),
    );
    load_case(
        &dir,
        "blank.txt",
        Some("d2k-http-plans 1\n\nalpha.example 4 split 111\n\n"),
    );
    load_case(
        &dir,
        "crlf.txt",
        Some("d2k-http-plans 1\r\nalpha.example 4 split 111\r\n"),
    );
    load_case(
        &dir,
        "negative-wall.txt",
        Some("d2k-http-plans 1\nalpha.example 4 split -7\n"),
    );
    load_case(&dir, "missing.txt", None);
}
