use crate::r2o_voice::R2oVoiceSessions;
use std::time::{Duration, Instant};

fn packet_between(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    body: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0; 28 + body.len()];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((28 + body.len()) as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + body.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(body);
    packet
}

fn packet(body: &[u8]) -> Vec<u8> {
    packet_between([192, 168, 1, 67], [1, 2, 3, 4], 50_000, 50_004, body)
}

fn discovery(ssrc: u32) -> [u8; 74] {
    let mut payload = [0; 74];
    payload[..4].copy_from_slice(&[0, 1, 0, 70]);
    payload[4..8].copy_from_slice(&ssrc.to_be_bytes());
    payload
}

fn rtp(ssrc: u32, sequence: u16) -> [u8; 16] {
    let mut payload = [0; 16];
    payload[0] = 0x80;
    payload[1] = 0x78;
    payload[2..4].copy_from_slice(&sequence.to_be_bytes());
    payload[8..12].copy_from_slice(&ssrc.to_be_bytes());
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
    let reconnect_events =
        sessions.sweep(start + Duration::from_secs(5) + Duration::from_nanos(1), true);
    let reconnect = reconnect_events.len();
    for event in &reconnect_events {
        sessions.mark_suspected(&event.key);
    }
    println!(
        "ssrc_reconnect first={} reconnect={} suspects={}",
        first_count,
        reconnect,
        first_count + reconnect
    );

    let changed_server = [1, 2, 3, 5];
    sessions.observe_packet(
        &packet_between(
            [192, 168, 1, 67],
            changed_server,
            50_000,
            50_005,
            &discovery(3),
        ),
        start + Duration::from_secs(7),
    );
    sessions.observe_packet(
        &packet_between(
            [192, 168, 1, 67],
            changed_server,
            50_000,
            50_005,
            b"media",
        ),
        start + Duration::from_millis(7_100),
    );
    let changed = sessions.sweep(start + Duration::from_millis(9_000), true);
    assert_eq!(changed.len(), 1);
    let endpoint_port = if changed[0].key[1..5] == changed_server {
        &changed[0].key[33..35]
    } else {
        assert_eq!(&changed[0].key[17..21], &changed_server);
        &changed[0].key[35..37]
    };
    assert_eq!(endpoint_port, &50_005_u16.to_be_bytes());
    for event in &changed {
        sessions.mark_suspected(&event.key);
    }
    println!("endpoint_change={}", changed.len());

    let long_start = Instant::now();
    let client = [192, 168, 1, 67];
    let server = [1, 2, 3, 4];
    let mut long_session = R2oVoiceSessions::default();
    long_session.observe_packet(
        &packet_between(client, server, 50_000, 50_004, &discovery(4)),
        long_start,
    );
    let mut long_events = 0;
    for interval in 1..=20 {
        let now = long_start + Duration::from_secs(interval * 30);
        long_session.observe_packet(
            &packet_between(client, server, 50_000, 50_004, &rtp(4, interval as u16)),
            now,
        );
        long_session.observe_packet(
            &packet_between(server, client, 50_004, 50_000, &rtp(5, interval as u16)),
            now + Duration::from_millis(1),
        );
        long_events += long_session.sweep(now + Duration::from_millis(2), true).len();
        assert_eq!(long_session.len(), 1);
    }
    let last_packet = long_start + Duration::from_secs(600) + Duration::from_millis(1);
    assert_eq!(long_session.expire(last_packet + Duration::from_secs(119)), 0);
    let expired = long_session.expire(last_packet + Duration::from_secs(120));
    assert_eq!(expired, 1);
    println!("long_session=active600 events={long_events} expire={expired}");
}
