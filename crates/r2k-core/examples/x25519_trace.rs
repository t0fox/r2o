//! Печать X25519-векторов для C/Rust differential (см.
//! `scripts/test-x25519-differential.sh`).

use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

const SCALARS: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0200000000000000000000000000000000000000000000000000000000000000",
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "0000000000000000000000000000000000000000000000000000000000000000",
];

fn hex(text: &str) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).expect("hex");
    }
    out
}

fn main() {
    for scalar in SCALARS {
        let public = x25519(hex(scalar), X25519_BASEPOINT_BYTES);
        println!("base {scalar} {}", hex_text(&public));
    }
    for scalar in SCALARS {
        for peer in SCALARS {
            let peer_public = x25519(hex(peer), X25519_BASEPOINT_BYTES);
            let shared = x25519(hex(scalar), peer_public);
            println!("ecdh {scalar} {peer} {}", hex_text(&shared));
        }
    }
}

fn hex_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
