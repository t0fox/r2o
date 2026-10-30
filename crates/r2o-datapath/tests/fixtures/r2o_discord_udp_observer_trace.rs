use crate::r2o_voice::R2oVoiceSessions;
use std::time::{Duration, Instant};

fn packet(body: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 28 + body.len()];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((28 + body.len()) as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[192, 168, 1, 67]);
    packet[16..20].copy_from_slice(&[1, 2, 3, 4]);
    packet[20..22].copy_from_slice(&50_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&50_004_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + body.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(body);
    packet
}

fn discovery(ssrc: u32) -> [u8; 74] {
    let mut payload = [0; 74];
    payload[..4].copy_from_slice(&[0, 1, 0, 70]);
    payload[4..8].copy_from_slice(&ssrc.to_be_bytes());
    payload
}

pub fn run() {
    let start = Instant::now();
    let mut sessions = R2oVoiceSessions::default();
    sessions.observe_packet(&packet(&discovery(1)), start);
    sessions.observe_packet(&packet(b"media"), start + Duration::from_millis(100));
    let first = sessions.sweep(start + Duration::from_secs(2) + Duration::from_nanos(1), true);
    let first_count = first.len();
    for event in &first {
        sessions.mark_suspected(&event.key);
    }

    sessions.observe_packet(&packet(&discovery(2)), start + Duration::from_secs(3));
    sessions.observe_packet(&packet(b"media"), start + Duration::from_millis(3_100));
    let reconnect = sessions.sweep(start + Duration::from_secs(5) + Duration::from_nanos(1), true);
    println!(
        "first={} reconnect={} suspects={}",
        first_count,
        reconnect.len(),
        first_count + reconnect.len()
    );
}
