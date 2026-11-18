//! Печать P-256-векторов для C/Rust differential (см.
//! `scripts/test-p256-differential.sh`).

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};

const SCALARS: [&str; 6] = [
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "0000000000000000000000000000000000000000000000000000000000000003",
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
];

fn bytes(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[2 * index..2 * index + 2], 16).expect("hex"))
        .collect()
}

fn public(scalar: &str) -> Option<Vec<u8>> {
    let secret = SecretKey::from_slice(&bytes(scalar)).ok()?;
    Some(secret.public_key().to_encoded_point(false).as_bytes().to_vec())
}

fn ecdh(scalar: &str, peer_public: &[u8]) -> Option<Vec<u8>> {
    let secret = SecretKey::from_slice(&bytes(scalar)).ok()?;
    let peer = PublicKey::from_sec1_bytes(peer_public).ok()?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Some(shared.raw_secret_bytes().to_vec())
}

fn hex_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn main() {
    for scalar in SCALARS {
        match public(scalar) {
            Some(public) => println!("pub {scalar} {}", hex_text(&public)),
            None => println!("pub {scalar} -"),
        }
    }
    for scalar in SCALARS {
        for peer in SCALARS {
            let Some(peer_public) = public(peer) else {
                continue;
            };
            match ecdh(scalar, &peer_public) {
                Some(shared) => println!("ecdh {scalar} {peer} {}", hex_text(&shared)),
                None => println!("ecdh {scalar} {peer} -"),
            }
        }
    }
}
