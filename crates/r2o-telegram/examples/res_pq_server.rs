//! TG8: общий fake MTProto DC для C/Rust resPQ probe.
//!
//! ```text
//! res_pq_server PORT_FILE MODE COUNT
//! ```
//!
//! MODE: valid | wrong-nonce | non-plain | pq-too-long |
//!       empty-fingerprints | trailing | bad-msg-id

use std::io::Write as _;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use grammers_tl_types::{Serializable, enums, types};
use r2o_telegram::crypto::{ProtoTag, make_cipher, parse_handshake};
use r2o_telegram::transparent::direct_stream_ciphers;

const REQ_PQ_MULTI: u32 = 0xbe7e_8ef1;

fn proto_number(proto: ProtoTag) -> u8 {
    match proto {
        ProtoTag::Abridged => 1,
        ProtoTag::Intermediate => 2,
        ProtoTag::PaddedIntermediate => 3,
    }
}

async fn serve(mut stream: TcpStream, mode: &str) {
    let mut handshake = [0u8; 64];
    if stream.read_exact(&mut handshake).await.is_err() {
        return;
    }
    let Some(init) = parse_handshake(&handshake, &[]) else {
        eprintln!("bad handshake");
        return;
    };
    let (mut decrypt, _) = direct_stream_ciphers(&handshake);
    // Obfuscated2: направление server→client использует обратный prekey/IV
    // и начинает счётчик с нуля (C tg_mtproto_make_obfuscated2_init).
    let mut reversed = [0u8; 48];
    for (index, byte) in reversed.iter_mut().enumerate() {
        *byte = handshake[55 - index];
    }
    let mut encrypt = make_cipher(&reversed[..32], &reversed[32..48]);

    let mut length = [0u8; 4];
    if stream.read_exact(&mut length).await.is_err() {
        return;
    }
    cipher::StreamCipher::apply_keystream(&mut decrypt, &mut length);
    let request_len = u32::from_le_bytes(length) as usize;
    if request_len == 0 || request_len > 64 * 1024 {
        return;
    }
    let mut request = vec![0u8; request_len];
    if stream.read_exact(&mut request).await.is_err() {
        return;
    }
    cipher::StreamCipher::apply_keystream(&mut decrypt, &mut request);
    let valid = request.len() >= 20
        && request[..8] == [0u8; 8]
        && u32::from_le_bytes(request[16..20].try_into().unwrap()) as usize == request.len() - 20
        && request.len() >= 24
        && u32::from_le_bytes(request[20..24].try_into().unwrap()) == REQ_PQ_MULTI
        && request.len() == 40;
    if !valid {
        eprintln!("bad request");
        return;
    }
    let nonce: [u8; 16] = request[24..40].try_into().unwrap();
    println!(
        "probe request=req_pq_multi dc={} media={} proto={}",
        init.dc_id,
        u8::from(init.is_media),
        proto_number(init.proto)
    );
    let _ = std::io::stdout().flush();

    let response_nonce = if mode == "wrong-nonce" {
        let mut wrong = nonce;
        wrong[0] ^= 1;
        wrong
    } else {
        nonce
    };
    let pq = if mode == "pq-too-long" {
        vec![0x17; 9]
    } else {
        vec![0x17, 0x2f, 0x4a, 0x91]
    };
    let fingerprints = if mode == "empty-fingerprints" {
        Vec::new()
    } else {
        vec![0x0102_0304_0506_0708_i64]
    };
    let response = enums::ResPq::Pq(types::ResPq {
        nonce: response_nonce,
        server_nonce: [0x11; 16],
        pq,
        server_public_key_fingerprints: fingerprints,
    });
    let mut body = response.to_bytes();
    if mode == "trailing" {
        body.extend_from_slice(&[0, 0, 0, 0]);
    }

    let message_id: i64 = if mode == "bad-msg-id" {
        2
    } else {
        0x0000_0001_0000_0001
    };
    let mut plain = Vec::with_capacity(20 + body.len());
    if mode == "non-plain" {
        plain.extend_from_slice(&1u64.to_le_bytes());
    } else {
        plain.extend_from_slice(&0u64.to_le_bytes());
    }
    plain.extend_from_slice(&message_id.to_le_bytes());
    plain.extend_from_slice(&(body.len() as u32).to_le_bytes());
    plain.extend_from_slice(&body);

    let mut framed = Vec::with_capacity(4 + plain.len());
    framed.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    framed.extend_from_slice(&plain);
    cipher::StreamCipher::apply_keystream(&mut encrypt, &mut framed);
    let _ = stream.write_all(&framed).await;
    let _ = stream.shutdown().await;
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let port_file = args.next().expect("PORT_FILE");
    let mode = args.next().expect("MODE");
    let count: usize = args.next().expect("COUNT").parse().expect("COUNT");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    std::fs::write(&port_file, port.to_string()).unwrap();
    for _ in 0..count {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        serve(stream, &mode).await;
    }
}
