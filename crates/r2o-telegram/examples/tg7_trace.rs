//! TG7: MTProto 2.0 decrypt в формате C-оракула `tg_mtproto_v2_decrypt`.

use grammers_crypto::{AuthKey, decrypt_data_v2};

const SERVER_CIPHERTEXT: &str = concat!(
    "7a7183c2c10e4f4df945fa9a9abd35e7c3840b61f045304f39674c19c0e20978",
    "4f50f6226a073529d675c92cbf0bfa8c99a79b3f39c72a5d9a026d431ab7407c",
    "a04ecc55187d6c45f17871524edd90cea02ed728e14d7cb18aea2a636158f094",
    "59a9437710d894c79f368c4e8164b7647ea98612aefe942c5d92121acb8db02d",
    "ccceb66d0f8720ac12a06db0582bfd955be34f365118e3bab8cd080ce6b45b28",
    "eac56dcd2a29374e"
);
const SERVER_AUTH_KEY: &str = concat!(
    "5d2e7d65f49ec28bd029a88761ea27b8a4c79f12226525443e7d7c596ef33035",
    "30db2107e89aa997c7a0164ab694187adeff156bd6ef7118a1962347753c0e7e",
    "89a0354b8ec364f9997e71bc6923fb86e8e43491e010606a6ce845e2fa019409",
    "77ef0aa32adf5a97dbf6d428ec0434d717a2d3ad19622cc05887642113c7965f",
    "fb862a3e3ccb0ab95addda57f89245dbd76b492348f8e94bd5a7c0e0b8480852",
    "3cfd1ea80b32fe9ad198bc2e103fceb7d52492ecc0273a28674bc923eee59265",
    "ab17a002df1f4aa2c59b819a5e5e1d105ec117336f5c76c6b187037d4b4270c",
    "ee9cc21071d97e9bca220c6d7b01b998cf2e5cdb9a50ecda1852a36e635690c8e"
);
const SERVER_PLAINTEXT: &str = concat!(
    "fc826a02248b28fd60f2c4822443ad6801f0c1c2918b305e0200000058000000",
    "dcf8f1730200000001a8c1c2918b305e010000001c0000000809c29ec4fd33ad",
    "918b305e18a88ea607ee5816fc826a02248b28fd01ccc1c2918b305e0200000014",
    "000000c5737734c4fd33ad918b305e6408300000000000fce66704a3cd8ee9d0a",
    "e6fab672c60c04a3f1fd4490e51f6"
);

fn auth_key() -> AuthKey {
    let mut bytes = [0u8; 256];
    hex::decode_to_slice(SERVER_AUTH_KEY, &mut bytes).unwrap();
    AuthKey::from_bytes(bytes)
}

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{byte:02x}");
    }
}

fn run_case(name: &str, ciphertext: &str, tamper: Option<usize>) {
    let mut packet = hex::decode(ciphertext).unwrap();
    match tamper {
        Some(usize::MAX) => packet.truncate(packet.len() - 8),
        Some(offset) => packet[offset] ^= 1,
        None => {}
    }
    match decrypt_data_v2(&mut packet, &auth_key()) {
        Ok(plaintext) => {
            print!("{name} ok=1 len={} plain=", plaintext.len());
            print_hex(plaintext);
            println!();
        }
        Err(_) => println!("{name} ok=0"),
    }
}

fn main() {
    run_case("valid", SERVER_CIPHERTEXT, None);
    run_case("tampered-message-key", SERVER_CIPHERTEXT, Some(24));
    run_case("wrong-key-id", SERVER_CIPHERTEXT, Some(0));
    let mut packet = hex::decode(SERVER_CIPHERTEXT).unwrap();
    let expected = hex::decode(SERVER_PLAINTEXT).unwrap();
    let matches = decrypt_data_v2(&mut packet, &auth_key())
        .is_ok_and(|plaintext| plaintext == expected.as_slice());
    println!("vector-match ok={}", u8::from(matches));
    run_case("truncated", SERVER_CIPHERTEXT, Some(usize::MAX));
}
