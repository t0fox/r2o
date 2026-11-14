//! C/Rust differential: `name_same` — ASCII case-fold, no dot normalization.

use r2o_datapath::control::r2o_name_same;

fn run(name: &str, a: &[u8], b: &[u8]) {
    println!("{name} result={}", u8::from(r2o_name_same(a, b)));
}

fn main() {
    run("equal", b"example.com", b"example.com");
    run("case", b"Example.COM", b"example.com");
    run("short", b"example.co", b"example.com");
    run("trailing-dot", b"example.com.", b"example.com");
    run("digits", b"a1-b2.c3", b"A1-B2.C3");
    run("empty", b"", b"");
    run("empty-vs-one", b"", b"a");
    run("high-case", &[0x80, b'A'], &[0x80, b'a']);
    run("high-diff", &[0x80, b'a'], &[0x81, b'a']);
    run("dash-case", b"A-B", b"a-b");
}
