//! M6: Rust trace crypto.c — SHA/HMAC/HKDF/AES-128-ECB/AES-128-GCM.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::{Aead, AeadInPlace, Payload};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn print_case(name: &str, bytes: &[u8]) {
    println!("case {name}\n{}", hex(bytes));
}

fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], out_len: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let hkdf = Hkdf::<Sha256>::from_prk(secret).expect("PRK");
    let mut output = vec![0u8; out_len];
    hkdf.expand(&info, &mut output).expect("HKDF expand");
    output
}

fn main() {
    let plain: Vec<u8> = (0..100u16).map(|value| value as u8).collect();
    let key: Vec<u8> = (0..100u16).map(|value| (0xa0 + value) as u8).collect();
    let message: Vec<u8> = (0..50u16).map(|value| (0x30 + value) as u8).collect();

    print_case("sha256-abc", &Sha256::digest(b"abc"));
    print_case("sha256-100", &Sha256::digest(&plain));

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"key").unwrap();
    mac.update(b"message");
    print_case("hmac-key-message", &mac.finalize().into_bytes());
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
    mac.update(&message);
    print_case("hmac-long", &mac.finalize().into_bytes());

    let salt = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&salt), &dcid);
    print_case("hkdf-extract", &prk);
    let secret = prk.as_slice();
    print_case(
        "hkdf-client-in",
        &hkdf_expand_label(secret, "client in", &[], 32),
    );
    print_case(
        "hkdf-quic-key",
        &hkdf_expand_label(secret, "quic key", &[], 16),
    );
    print_case(
        "hkdf-derived-ctx",
        &hkdf_expand_label(secret, "derived", &plain[..32], 32),
    );

    let fips_key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let fips_plain = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let cipher = Aes128::new_from_slice(&fips_key).unwrap();
    let mut block = aes::Block::clone_from_slice(&fips_plain);
    cipher.encrypt_block(&mut block);
    print_case("aes128-ecb", &block);

    let gcm_key = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
        0x08,
    ];
    let gcm_iv = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
    ];
    let aad = b"additional data";
    let gcm_plain = b"hello gcm world";
    let gcm = Aes128Gcm::new_from_slice(&gcm_key).unwrap();
    let nonce = Nonce::from_slice(&gcm_iv);
    let sealed = gcm
        .encrypt(
            nonce,
            Payload {
                msg: gcm_plain,
                aad,
            },
        )
        .unwrap();
    let (ciphertext, tag) = sealed.split_at(gcm_plain.len());
    print_case("gcm-ciphertext", ciphertext);
    print_case("gcm-tag", tag);

    let mut opened = ciphertext.to_vec();
    gcm.decrypt_in_place_detached(nonce, aad, &mut opened, Tag::from_slice(tag))
        .unwrap();
    print_case("gcm-opened", &opened);

    let mut bad_opened = vec![0xaau8; ciphertext.len()];
    let mut bad_tag = tag.to_vec();
    bad_tag[0] ^= 0x01;
    let bad = gcm.decrypt_in_place_detached(nonce, aad, &mut bad_opened, Tag::from_slice(&bad_tag));
    println!("case gcm-bad-tag\nrc={}", if bad.is_ok() { 0 } else { -1 });
    println!("{}", hex(&bad_opened));
}
