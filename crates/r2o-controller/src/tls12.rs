//! C `tls12.c`: тестовый экспорт TLS 1.2 PRF.
//!
//! В production PRF выполняет rustls; здесь — точная P_SHA256-реализация
//! для C/Rust-векторов `test_tls12.c`.

use sha2::{Digest, Sha256};

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    if key.len() > key_block.len() {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    for byte in key_block {
        inner.update([byte ^ 0x36]);
    }
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    for byte in key_block {
        outer.update([byte ^ 0x5c]);
    }
    outer.update(inner);
    outer.finalize().into()
}

/// C `d2k_tls12_prf_for_test`: P_SHA256(secret, label || seed).
pub fn d2k_tls12_prf_for_test(secret: &[u8], label: &str, seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label.as_bytes());
    label_seed.extend_from_slice(seed);
    let mut a = hmac_sha256(secret, &label_seed);
    let mut out = Vec::with_capacity(out_len);
    while out.len() < out_len {
        let mut input = Vec::with_capacity(32 + label_seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(&label_seed);
        let block = hmac_sha256(secret, &input);
        let take = (out_len - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
        a = hmac_sha256(secret, &a);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::d2k_tls12_prf_for_test;

    fn hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0);
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn tls12_prf_matches_rfc_5246_vector() {
        let secret = hex("9bbe436ba940f017b17652849a71db35");
        let seed = hex("a0ba9f936cda311827a6f796ffd5198c");
        let out = d2k_tls12_prf_for_test(&secret, "test label", &seed, 32);
        assert_eq!(
            out,
            hex("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a")
        );
    }
}
