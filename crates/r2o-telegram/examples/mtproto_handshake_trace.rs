//! Печатает разбор obfuscated2/secret в формате C `d2o_mtproto_handshake_trace.c`.

use r2o_telegram::crypto::{HANDSHAKE_LEN, ProtoTag, parse_handshake};

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).expect("hex")
}

fn proto_number(proto: ProtoTag) -> u8 {
    match proto {
        ProtoTag::Abridged => 1,
        ProtoTag::Intermediate => 2,
        ProtoTag::PaddedIntermediate => 3,
    }
}

fn report(name: &str, packet: &[u8; HANDSHAKE_LEN], secret: &[u8]) {
    match parse_handshake(packet, secret) {
        Some(info) => {
            print!(
                "{name} ok=1 dc={} media={} proto={} prekey=",
                info.dc_id,
                u8::from(info.is_media),
                proto_number(info.proto)
            );
            for byte in info.prekey_and_iv {
                print!("{byte:02x}");
            }
            println!();
        }
        None => println!("{name} ok=0"),
    }
}

fn main() {
    let direct = unhex(
        "0001020304050607000102030405060708090a0b0c0d0e0f\
         101112131415161718191a1b1c1d1e1f0001020304050607\
         08090a0b0c0d0e0f87aeb3fe059b4807",
    );
    let direct: [u8; HANDSHAKE_LEN] = direct.try_into().unwrap();
    report("direct", &direct, &[]);

    let secret_packet = unhex(
        "0001020304050607000102030405060708090a0b0c0d0e0f\
         101112131415161718191a1b1c1d1e1f0001020304050607\
         08090a0b0c0d0e0f7c380b6e418caed2",
    );
    let secret_packet: [u8; HANDSHAKE_LEN] = secret_packet.try_into().unwrap();
    let secret = unhex("101112131415161718191a1b1c1d1e1f");
    report("secret", &secret_packet, &secret);
    report("wrong-secret", &secret_packet, &[0xa5; 16]);

    report("zero", &[0u8; HANDSHAKE_LEN], &[]);

    let mut reserved = direct;
    reserved[..4].copy_from_slice(b"GET ");
    report("get-prefix", &reserved, &[]);
    let mut reserved = direct;
    reserved[4..8].fill(0);
    report("zero-prefix", &reserved, &[]);
}
