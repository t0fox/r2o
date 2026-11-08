//! TG17: сгенерировать официальные secret/DD-рукопожатия и напечатать
//! C-совместимый trace выбора секретов и маршрута.
//!
//! ```text
//! tg17_trace generate DIR
//! tg17_trace trace DIR SNAPSHOT_JSON
//! ```

use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use cipher::StreamCipher;
use sha2::{Digest, Sha256};

use r2o_telegram::crypto::{HANDSHAKE_LEN, ProtoTag, make_cipher, parse_handshake};
use r2o_telegram::dc_map::{DcMapStore, DcSnapshot};
use r2o_telegram::transparent::{
    ClientInit, TransparentSelection, destination_allowed, parse_client_init_with_secrets,
    select_transparent_route,
};

const NOW: i64 = 1_800_000_000;
const PORTS: &[u16] = &[443, 5222, 1443];
const CIDRS: &[&str] = &["149.154.0.0/16", "2001:67c::/32", "0.0.0.0/0"];

fn make_handshake(
    secret: Option<&[u8]>,
    dc: u32,
    media: bool,
    proto: ProtoTag,
) -> [u8; HANDSHAKE_LEN] {
    let mut packet = [0u8; HANDSHAKE_LEN];
    for (index, byte) in packet.iter_mut().take(56).enumerate() {
        *byte = ((index * 37 + 11) & 0xff) as u8;
    }
    let key: [u8; 32] = match secret {
        Some(secret) => {
            let mut hash = Sha256::new();
            hash.update(&packet[8..40]);
            hash.update(secret);
            hash.finalize().into()
        }
        None => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&packet[8..40]);
            key
        }
    };
    let mut cipher = make_cipher(&key, &packet[40..56]);
    let mut keystream = [0u8; HANDSHAKE_LEN];
    cipher.apply_keystream(&mut keystream);
    let mut plain = [0u8; HANDSHAKE_LEN];
    plain[56..60].copy_from_slice(&proto.as_bytes());
    let signed_dc: i16 = if media {
        -(dc as i32) as i16
    } else {
        dc as i16
    };
    plain[60..62].copy_from_slice(&signed_dc.to_le_bytes());
    for index in 56..HANDSHAKE_LEN {
        packet[index] = plain[index] ^ keystream[index];
    }
    packet
}

fn proto_number(proto: ProtoTag) -> u8 {
    match proto {
        ProtoTag::Abridged => 1,
        ProtoTag::Intermediate => 2,
        ProtoTag::PaddedIntermediate => 3,
    }
}

fn secrets_trace(store: &DcMapStore) {
    for (name, address, port, now) in [
        ("exact", "149.154.167.151", 5222, NOW),
        ("mapped", "::ffff:149.154.167.151", 5222, NOW),
        ("port-zero", "149.154.167.151", 0, NOW),
        ("thisport-443", "149.154.167.156", 443, NOW),
        ("non-tcpo", "149.154.167.152", 5222, NOW),
        ("ipv6", "2001:67c:4e8:f005::a", 5222, NOW),
        ("empty-secret", "149.154.167.153", 5222, NOW),
        (
            "stale",
            "149.154.167.151",
            5222,
            NOW + 90 * 24 * 60 * 60 + 1,
        ),
        ("many", "149.154.167.160", 5222, NOW),
    ] {
        let address = address.parse().expect("IP");
        let secrets = store.handshake_secrets_for_at(address, port, now);
        print!("secrets {name} count={}", secrets.len());
        for secret in secrets {
            print!(" {}", hex::encode(secret));
        }
        println!();
    }
}

fn route_trace(store: &DcMapStore, dir: &Path) {
    let cases = [
        ("normal", "direct_dc4_media.bin", "149.154.167.91:443"),
        ("tcpo", "direct_dc2.bin", "149.154.167.151:5222"),
        ("secret", "secret_dc2.bin", "149.154.167.151:5222"),
        ("cdn", "direct_dc2.bin", "149.154.167.155:443"),
        ("ipv6", "direct_dc4_media.bin", "[2001:67c:4e8:f004::a]:443"),
        ("unlisted-no-dc", "direct_dc0.bin", "8.8.8.8:443"),
        ("unlisted-hint", "direct_dc2.bin", "8.8.8.8:443"),
        ("port80", "direct_dc4_media.bin", "149.154.167.91:80"),
        ("private", "direct_dc4_media.bin", "10.0.0.1:443"),
        (
            "this-port-mismatch",
            "direct_dc2.bin",
            "149.154.167.156:443",
        ),
    ];
    let cidrs: Vec<String> = CIDRS.iter().map(|value| (*value).to_string()).collect();
    for (name, file, destination) in cases {
        let destination: SocketAddr = destination.parse().expect("destination");
        if !destination_allowed(destination, PORTS, &cidrs) {
            println!("route {name} ok=0");
            continue;
        }
        let bytes = fs::read(dir.join(file)).expect("handshake file");
        let handshake: [u8; HANDSHAKE_LEN] = bytes.try_into().expect("64 bytes");
        let secrets = store.handshake_secrets_for_at(destination.ip(), destination.port(), NOW);
        let Some(init) = parse_client_init_with_secrets(&handshake, &secrets) else {
            println!("route {name} ok=0");
            continue;
        };
        let lookup = store.resolve_for_transparent_with_source(
            destination.ip(),
            destination.port(),
            init.is_media,
            init.dc,
        );
        let selection = match lookup {
            Ok((endpoint, _)) => select_transparent_route(&init, Some(&endpoint)),
            Err(_) if init.dc.is_none() => select_transparent_route(&init, None),
            Err(_) => TransparentSelection::Reject,
        };
        print_route(name, &init, selection);
    }
}

fn print_route(name: &str, init: &ClientInit, selection: TransparentSelection) {
    match selection {
        TransparentSelection::DirectTcp { dc, is_media } => println!(
            "route {name} ok=1 dc={dc} media={} proto={} tcp_only=1",
            u8::from(is_media),
            proto_number(init.proto)
        ),
        TransparentSelection::Wss { dc, is_media } => println!(
            "route {name} ok=1 dc={dc} media={} proto={} tcp_only=0",
            u8::from(is_media),
            proto_number(init.proto)
        ),
        TransparentSelection::Reject => println!("route {name} ok=0"),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("generate|trace");
    let dir = args.next().expect("DIR");
    match mode.as_str() {
        "generate" => {
            fs::create_dir_all(&dir).unwrap();
            let secret = hex::decode("aabbccdd").unwrap();
            let cases: [(&str, [u8; HANDSHAKE_LEN]); 3] = [
                (
                    "direct_dc2.bin",
                    make_handshake(None, 2, false, ProtoTag::Intermediate),
                ),
                (
                    "direct_dc4_media.bin",
                    make_handshake(None, 4, true, ProtoTag::Intermediate),
                ),
                (
                    "secret_dc2.bin",
                    make_handshake(Some(&secret), 2, false, ProtoTag::Intermediate),
                ),
            ];
            for (name, handshake) in cases {
                // Проверка, что рукопожатие действительно разбирается.
                assert!(
                    parse_handshake(
                        &handshake,
                        if name.starts_with("secret") {
                            &secret
                        } else {
                            &[]
                        }
                    )
                    .is_some(),
                    "{name}"
                );
                fs::write(Path::new(&dir).join(name), handshake).unwrap();
            }
            fs::write(
                Path::new(&dir).join("direct_dc0.bin"),
                make_handshake(None, 0, false, ProtoTag::Intermediate),
            )
            .unwrap();
        }
        "trace" => {
            let snapshot_path = args.next().expect("SNAPSHOT_JSON");
            let bytes = fs::read(&snapshot_path).unwrap();
            let snapshot: DcSnapshot = serde_json::from_slice(&bytes).unwrap();
            let store = DcMapStore::without_cache(Path::new(&dir).join("unused.json"));
            store.install(snapshot, NOW).unwrap();
            secrets_trace(&store);
            route_trace(&store, Path::new(&dir));
        }
        other => panic!("неизвестный режим {other}"),
    }
}
