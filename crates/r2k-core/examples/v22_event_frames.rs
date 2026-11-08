//! Печатает кадры, которые r2o-datapath отправляет в v22-профиле.
//!
//! C-оракул `scripts/fixtures/control_v22_events.c` разбирает их production
//! `core/link.c`; differential проверяет, что D2O понимает каждый кадр.

use r2k_core::control::{
    self, ClientShapeEvent, EVENT_CLIENT_SHAPE, EVENT_R2O_TCP_EARLY_RST, EVENT_R2O_TCP_EXCHANGE,
    EVENT_R2O_TCP_FIN_RETRY, EVENT_R2O_TCP_REPEAT, EVENT_R2O_TCP_RST_AFTER_APP,
    EVENT_R2O_TCP_RST_CUT, EVENT_R2O_TCP_SILENT, EVENT_R2O_TCP_STALL, KEY_LEN, R2oTcpEarlyRstEvent,
    R2oTcpExchangeEvent, R2oTcpFinRetryEvent, R2oTcpRepeatEvent, R2oTcpRstAfterAppEvent,
    R2oTcpRstCutSignalEvent, R2oTcpSilenceEvent, R2oTcpStallEvent, SHAPE_MODERN,
};

fn tcp_key() -> [u8; KEY_LEN] {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    key[17..21].copy_from_slice(&[198, 51, 100, 80]);
    key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
    key[35..37].copy_from_slice(&443_u16.to_be_bytes());
    key[37] = 6;
    key
}

fn client_hello(host: &str) -> Vec<u8> {
    let host = host.as_bytes();
    let mut server_name = Vec::with_capacity(host.len() + 5);
    server_name.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    server_name.push(0);
    server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    server_name.extend_from_slice(host);
    let mut extensions = vec![0x00, 0x00];
    extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&server_name);
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[0x42; 32]);
    hello.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&[
        ((hello.len() >> 16) & 0xff) as u8,
        ((hello.len() >> 8) & 0xff) as u8,
        (hello.len() & 0xff) as u8,
    ]);
    handshake.extend_from_slice(&hello);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn emit(kind: u16, body: &[u8]) {
    for (legacy_kind, legacy_body) in control::translate_event_to_v22(kind, body) {
        let frame = control::encode_frame(legacy_kind, &legacy_body).unwrap();
        for byte in frame {
            print!("{byte:02x}");
        }
        println!();
    }
}

fn main() {
    let key = tcp_key();
    let shape = ClientShapeEvent {
        key,
        host: b"example.com".to_vec(),
        shape: SHAPE_MODERN,
        client_hello: client_hello("example.com"),
        tcp_has_timestamp: Some(true),
    };
    emit(EVENT_CLIENT_SHAPE, &shape.event_body().unwrap());
    emit(
        EVENT_R2O_TCP_STALL,
        &R2oTcpStallEvent {
            key,
            client_is_low: true,
            elapsed_ms: 4200,
            estimated_packets: 700,
            planned: true,
        }
        .event_body()
        .unwrap(),
    );
    emit(
        EVENT_R2O_TCP_EXCHANGE,
        &R2oTcpExchangeEvent {
            key,
            first_record_type: 22,
            bytes_after_client_hello: 900,
            record_types: 0b1010,
            server_hello: true,
            planned: false,
        }
        .event_body()
        .unwrap(),
    );
    emit(
        EVENT_R2O_TCP_EARLY_RST,
        &R2oTcpEarlyRstEvent {
            key,
            client_is_low: true,
            planned: true,
            ttl: 63,
            reference_ttl: 64,
            traffic_class: 0x88,
            ip_id: 0x4321,
        }
        .event_body()
        .unwrap(),
    );
    emit(
        EVENT_R2O_TCP_RST_CUT,
        &R2oTcpRstCutSignalEvent {
            key,
            client_is_low: true,
            ttl: 62,
            reference_ttl: 64,
            traffic_class: 0x44,
            ip_id: 0x1234,
        }
        .event_body()
        .unwrap(),
    );
    emit(
        EVENT_R2O_TCP_SILENT,
        &R2oTcpSilenceEvent {
            key,
            client_is_low: true,
            planned: false,
            elapsed_ms: 5000,
        }
        .event_body()
        .unwrap(),
    );
    emit(
        EVENT_R2O_TCP_REPEAT,
        &R2oTcpRepeatEvent {
            key,
            client_is_low: true,
            planned: true,
        }
        .event_body()
        .unwrap(),
    );
    emit(
        EVENT_R2O_TCP_FIN_RETRY,
        &R2oTcpFinRetryEvent {
            key,
            client_is_low: false,
            planned: false,
        }
        .event_body()
        .unwrap(),
    );
    emit(
        EVENT_R2O_TCP_RST_AFTER_APP,
        &R2oTcpRstAfterAppEvent {
            key,
            client_is_low: true,
            planned: true,
        }
        .event_body()
        .unwrap(),
    );
}
