use r2k_core::quic_snapshot::{r2k_quic_snapshot_pack, r2k_quic_snapshot_parse};
use r2o_controller::quic_replay::QuicReplayProbe;
use std::net::UdpSocket;
use std::time::Duration;

#[test]
fn повторяет_снимок_на_локальном_сервере_и_не_принимает_чужой_ответ() {
    let initial = &include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin")[..];
    let snapshot = r2k_quic_snapshot_pack(&[initial, initial]).unwrap();
    let expected = r2k_quic_snapshot_parse(&snapshot).unwrap();
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let endpoint = server.local_addr().unwrap();
    let server_thread = std::thread::spawn(move || {
        let mut source = None;
        for _ in 0..2 {
            let mut packet = [0; 1500];
            let (length, peer) = server.recv_from(&mut packet).unwrap();
            let (_, dcid) = r2k_core::quic::r2k_quic_initial_flight_id(&packet[..length]).unwrap();
            assert_ne!(dcid, b"\x83\x94\xc8\xf0\x3e\x51\x57\x08");
            if let Some(previous) = &source {
                assert_eq!(previous, &peer);
            }
            source = Some(peer);
        }
        server
            .send_to(b"foreign response", source.unwrap())
            .unwrap();
    });

    let mut probe = QuicReplayProbe::prepare(endpoint, &snapshot, None).unwrap();
    assert_ne!(probe.local_endpoint().port(), 0);
    let result = probe.run(Duration::from_millis(100)).unwrap();

    server_thread.join().unwrap();
    assert_eq!(result.sent_datagrams, expected.datagrams().len());
    assert_eq!(result.foreign_responses, 1);
    assert!(!result.handshake_confirmed);
}
