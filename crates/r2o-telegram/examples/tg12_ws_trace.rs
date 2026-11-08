//! TG12: Rust WebSocket upgrade/frame trace.
//!
//! Upgrade идёт через production `ws_upgrade` (точный порт C ws.c), кадры —
//! через production tungstenite parser.
//!
//! ```text
//! tg12_ws_trace upgrade
//! tg12_ws_trace frames DIR CASES_FILE
//! ```

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

use r2o_telegram::ws_frames::FrameGuard;
use r2o_telegram::ws_upgrade;

const MAX_MESSAGE: usize = 4 * 1024 * 1024;

const VARIANTS: &[&str] = &[
    "valid",
    "wrong-accept",
    "missing-accept",
    "upgrade-case",
    "connection-list",
    "connection-missing",
    "missing-upgrade",
    "status-200",
    "subprotocol-missing",
    "subprotocol-wrong",
    "control-char",
    "extra-bytes",
];

fn config() -> WebSocketConfig {
    WebSocketConfig {
        max_frame_size: Some(MAX_MESSAGE),
        max_message_size: Some(MAX_MESSAGE),
        ..WebSocketConfig::default()
    }
}

async fn read_request(stream: &mut DuplexStream) -> Option<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            return String::from_utf8(buffer).ok();
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn build_response(variant: &str, accept: &str) -> Vec<u8> {
    let mut response = String::new();
    response.push_str(if variant == "status-200" {
        "HTTP/1.1 200 OK\r\n"
    } else {
        "HTTP/1.1 101 Switching Protocols\r\n"
    });
    if variant != "missing-upgrade" {
        response.push_str(if variant == "upgrade-case" {
            "Upgrade: WebSocket\r\n"
        } else {
            "Upgrade: websocket\r\n"
        });
    }
    if variant != "connection-missing" {
        response.push_str(if variant == "connection-list" {
            "Connection: keep-alive, Upgrade\r\n"
        } else {
            "Connection: Upgrade\r\n"
        });
    }
    if variant != "missing-accept" {
        response.push_str("Sec-WebSocket-Accept: ");
        response.push_str(accept);
        if variant == "wrong-accept" {
            response.push('x');
        }
        response.push_str("\r\n");
    }
    if variant != "subprotocol-missing" {
        response.push_str(if variant == "subprotocol-wrong" {
            "Sec-WebSocket-Protocol: text\r\n"
        } else {
            "Sec-WebSocket-Protocol: binary\r\n"
        });
    }
    if variant == "control-char" {
        response.push_str("X-Test: bad\u{1}value\r\n");
    }
    response.push_str("\r\n");
    let mut bytes = response.into_bytes();
    if variant == "extra-bytes" {
        bytes.extend_from_slice(&[0x82, 0x03, b'a', b'b', b'c']);
    }
    bytes
}

async fn serve_handshake(mut stream: DuplexStream, variant: &'static str, accept: String) {
    if read_request(&mut stream).await.is_none() {
        return;
    }
    let response = build_response(variant, &accept);
    let _ = stream.write_all(&response).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

async fn run_upgrade() {
    for variant in VARIANTS {
        let upgrade = ws_upgrade::begin(
            "relay.test",
            "/ws",
            Some("binary"),
            Some("https://web.telegram.org"),
            Some("r2o-tg12/1.0"),
        )
        .unwrap();
        let accept = upgrade.expected_accept().to_string();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(serve_handshake(server, variant, accept));
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            ws_upgrade::perform(&mut client, &upgrade),
        )
        .await;
        println!(
            "upgrade {variant} ok={}",
            u8::from(matches!(result, Ok(Ok((101, _)))))
        );
        server_task.abort();
    }
}

async fn serve_frames(mut stream: DuplexStream, payload: Vec<u8>) {
    if stream.write_all(&payload).await.is_err() {
        return;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
}

fn payload_sum(payload: &[u8]) -> u32 {
    payload
        .iter()
        .fold(0u32, |sum, byte| (sum + u32::from(*byte)) & 0xff)
}

async fn run_frames(dir: &str, cases_path: &str) {
    let cases = std::fs::read_to_string(cases_path).unwrap();
    for name in cases.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let path = format!("{dir}/{name}.bin");
        let Ok(payload) = std::fs::read(&path) else {
            println!("frames {name} error");
            continue;
        };
        let (client, server) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(serve_frames(server, payload));
        let guarded = FrameGuard::new(client);
        let mut ws = WebSocketStream::from_raw_socket(guarded, Role::Client, Some(config())).await;
        print!("frames {name}");
        loop {
            match tokio::time::timeout(Duration::from_millis(350), ws.next()).await {
                Err(_) | Ok(None) => {
                    println!(" eof");
                    break;
                }
                Ok(Some(Err(_))) => {
                    println!(" error");
                    break;
                }
                Ok(Some(Ok(message))) => match message {
                    Message::Binary(data) => {
                        print!(" binary len={} sum={}", data.len(), payload_sum(&data));
                    }
                    Message::Text(_) => {
                        // C `dispatch_frames` отвергает TEXT.
                        println!(" error");
                        break;
                    }
                    Message::Ping(data) => {
                        print!(" ping len={}", data.len());
                        let _ = ws.send(Message::Pong(data)).await;
                    }
                    Message::Pong(data) => print!(" pong len={}", data.len()),
                    Message::Close(_) => {
                        println!(" close eof");
                        break;
                    }
                    Message::Frame(_) => {}
                },
            }
        }
        server_task.abort();
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("upgrade") => run_upgrade().await,
        Some("frames") => run_frames(&args[1], &args[2]).await,
        _ => panic!("режим"),
    }
}
