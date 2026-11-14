//! C/Rust differential: `http_ready` — tri-state готовности HTTP-головы.
//!
//! ```text
//! r2o_http_ready_trace
//! ```

use r2o_datapath::capture::r2o_http_ready_trace;

fn run(name: &str, bytes: &[u8], high: usize) {
    println!("{name} rc={}", r2o_http_ready_trace(bytes, high));
}

fn main() {
    let valid = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    let no_blank = b"GET / HTTP/1.1\r\nHost: a\r\n";
    let host_partial = b"GET / HTTP/1.1\r\nHost: a";
    let no_host = b"GET / HTTP/1.1\r\nX: y\r\n\r\n";
    let hash = b"GET /a#b HTTP/1.1\r\nHost: a\r\n\r\n";
    let bad_target = b"GET /a\x01b HTTP/1.1\r\nHost: a\r\n\r\n";

    run("A valid-full", valid, valid.len());
    run("B no-blank", no_blank, no_blank.len());
    run("C host-partial", host_partial, host_partial.len());
    run("D n-less-high", valid, valid.len() + 1);
    run("E no-host-full", no_host, no_host.len());
    run("F no-host-partial", no_host, no_host.len() + 3);
    run("G hash", hash, hash.len());
    run("H bad-target", bad_target, bad_target.len());

    let mut long_target = b"GET /".to_vec();
    long_target.extend(std::iter::repeat_n(b'a', 2100));
    long_target.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(long_target.len(), 2127);
    run("I long-target", &long_target, long_target.len());

    let garbage = vec![b'G'; 4096];
    run("J buffer-full", &garbage, garbage.len());
}
