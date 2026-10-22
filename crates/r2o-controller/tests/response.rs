use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use r2o_controller::response::{
    HttpsProbeState, ResponseOptions, ResponseResult, ResponseVerdict, Scan12, decide,
    probe_https_name, probe_https_state, probe_response, scan_server_hello, scan12,
};

fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = vec![kind, 3, 3];
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    output
}

fn self_signed_tls_server(name: &str) -> (SocketAddr, thread::JoinHandle<()>) {
    let certificate = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
    let cert = rustls::pki_types::CertificateDer::from(certificate.serialize_der().unwrap());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der());
    let config = std::sync::Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut connection =
                rustls::ServerConnection::new(std::sync::Arc::clone(&config)).unwrap();
            while connection.is_handshaking() {
                if connection.complete_io(&mut stream).is_err() {
                    break;
                }
            }
        }
    });
    (address, server)
}

#[test]
fn https_probe_does_not_accept_a_plain_http_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut hello = [0; 5];
        let _ = stream.read(&mut hello);
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
    });

    assert_eq!(
        probe_https_state("example.test", address, Some(0)),
        HttpsProbeState::TlsBlocked
    );
    assert!(!probe_https_name("example.test", address, Some(0)));
    server.join().unwrap();
}

#[test]
fn https_probe_matches_the_leaf_name_without_requiring_a_trust_chain() {
    let (address, server) = self_signed_tls_server("example.test");

    assert_eq!(
        probe_https_state("example.test", address, Some(0)),
        HttpsProbeState::Served
    );
    server.join().unwrap();
}

#[test]
fn https_probe_classifies_a_different_leaf_name_after_tls() {
    let (address, server) = self_signed_tls_server("other.test");

    assert_eq!(
        probe_https_state("example.test", address, Some(0)),
        HttpsProbeState::OtherName
    );
    server.join().unwrap();
}

#[test]
fn https_probe_classifies_a_refused_port_as_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    assert_eq!(
        probe_https_state("example.test", address, Some(0)),
        HttpsProbeState::Closed
    );
}

fn fragmented(records: &[&[u8]]) -> Vec<u8> {
    records
        .iter()
        .flat_map(|record| record.iter().copied())
        .collect()
}

fn read_client_hello(stream: &mut impl Read) -> Vec<u8> {
    let mut record_header = [0_u8; 5];
    stream.read_exact(&mut record_header).unwrap();
    let record_len = usize::from(u16::from_be_bytes([record_header[3], record_header[4]]));
    let mut hello = record_header.to_vec();
    hello.resize(5 + record_len, 0);
    stream.read_exact(&mut hello[5..]).unwrap();
    hello
}

#[test]
fn scans_handshake_messages_across_tls_records_and_large_certificates() {
    let mut handshake = vec![2, 0, 0, 10];
    handshake.extend_from_slice(&[0x22; 10]);
    handshake.extend_from_slice(&[11, 0, 0x4e, 0x20]);
    handshake.extend_from_slice(&vec![0xab; 20_000]);
    handshake.extend_from_slice(&[14, 0, 0, 0]);

    let first = record(22, &handshake[..16_384]);
    let second = record(22, &handshake[16_384..]);
    assert_eq!(
        scan12(&fragmented(&[&first, &second])),
        Scan12::ServerHelloDone
    );
}

#[test]
fn ignores_server_hello_done_bytes_inside_certificate_body() {
    let mut handshake = vec![11, 0, 0x4e, 0x20];
    handshake.extend_from_slice(&vec![0xab; 20_000]);
    handshake[16_380..16_384].copy_from_slice(&[14, 0, 0, 0]);
    let first = record(22, &handshake[..16_384]);
    let second = record(22, &handshake[16_384..]);
    assert_eq!(scan12(&fragmented(&[&first, &second])), Scan12::NeedMore);

    let mut at_record_start = handshake;
    at_record_start[16_384..16_388].copy_from_slice(&[14, 0, 0, 0]);
    let first = record(22, &at_record_start[..16_384]);
    let second = record(22, &at_record_start[16_384..]);
    assert_eq!(scan12(&fragmented(&[&first, &second])), Scan12::NeedMore);
}

fn serve_responses(mut server: impl FnMut(&[u8]) -> bool + Send + 'static) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for index in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let hello = read_client_hello(&mut stream);
            if index == 0 {
                stream.write_all(&record(22, &[2, 0, 0, 1, 0xaa])).unwrap();
            } else if server(&hello) {
                stream
                    .write_all(&record(22, &[2, 0, 0, 1, 0xaa, 14, 0, 0, 0]))
                    .unwrap();
            }
        }
    });
    port
}

#[test]
fn response_limit_is_unmeasured_instead_of_a_block_verdict() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for index in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_client_hello(&mut stream);
            if index == 0 {
                stream.write_all(&record(22, &[2, 0, 0, 1, 0xaa])).unwrap();
                continue;
            }
            let mut first = vec![0xaa; 32_768];
            first[..4].copy_from_slice(&[11, 0xff, 0xff, 0xff]);
            let second = vec![0xbb; 32_768];
            let first = record(22, &first);
            let second = record(22, &second);
            stream.write_all(&fragmented(&[&first, &second])).unwrap();
        }
    });
    let result = probe_response(
        "127.0.0.1",
        port,
        "youtube.com",
        ResponseOptions {
            repeats: 1,
            timeout: Duration::from_secs(1),
            mark: Some(0),
        },
    );
    assert_eq!(result.verdict, ResponseVerdict::NotApplicable);
    assert_eq!((result.target, result.control), (0, 0));
    assert!(result.reason.contains("2 прогонах"));
}

#[test]
fn loopback_probe_uses_same_address_control_and_reports_clear() {
    let port = serve_responses(|_| true);
    let result = probe_response(
        "127.0.0.1",
        port,
        "youtube.com",
        ResponseOptions {
            repeats: 1,
            timeout: Duration::from_secs(1),
            mark: Some(0),
        },
    );
    assert_eq!(result.verdict, ResponseVerdict::Clear);
    assert_eq!((result.target, result.control), (1, 1));
}

#[test]
fn loopback_probe_requires_target_failure_and_control_success_for_blocked() {
    let port = serve_responses(|hello| !hello.windows(11).any(|window| window == b"youtube.com"));
    let result = probe_response(
        "127.0.0.1",
        port,
        "youtube.com",
        ResponseOptions {
            repeats: 1,
            timeout: Duration::from_millis(75),
            mark: Some(0),
        },
    );
    assert_eq!(result.verdict, ResponseVerdict::Blocked);
    assert_eq!((result.target, result.control), (0, 1));
}

#[test]
fn accepts_a_message_header_split_across_records_and_recognizes_alerts() {
    let first = record(22, &[14]);
    let second = record(22, &[0, 0, 0]);
    assert_eq!(
        scan12(&fragmented(&[&first, &second])),
        Scan12::ServerHelloDone
    );
    assert_eq!(scan12(&record(21, &[2, 40])), Scan12::FatalAlert);
    let server_hello = fragmented(&[&record(22, &[2]), &record(22, &[0, 0, 1, 0xaa])]);
    assert_eq!(scan_server_hello(&server_hello), Scan12::ServerHello);
}

#[test]
fn r2o_tls_измеритель_сверяется_с_независимым_tls_parser() {
    let server_done = record(22, &[14, 0, 0, 0]);
    let (remaining, parsed) = tls_parser::parse_tls_plaintext(&server_done).unwrap();
    assert!(remaining.is_empty());
    assert!(matches!(
        parsed.msg.as_slice(),
        [tls_parser::TlsMessage::Handshake(
            tls_parser::TlsMessageHandshake::ServerDone(_)
        )]
    ));
    assert_eq!(scan12(&server_done), Scan12::ServerHelloDone);

    let alert = record(21, &[2, 40]);
    let (remaining, parsed) = tls_parser::parse_tls_plaintext(&alert).unwrap();
    assert!(remaining.is_empty());
    assert!(matches!(
        parsed.msg.as_slice(),
        [tls_parser::TlsMessage::Alert(_)]
    ));
    assert_eq!(scan12(&alert), Scan12::FatalAlert);
}

proptest::proptest! {
    #[test]
    fn r2o_tls_измеритель_не_паникует_на_произвольных_ответах(
        bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..4096)
    ) {
        let _ = scan12(&bytes);
        let _ = scan_server_hello(&bytes);
    }
}

#[test]
fn response_probe_is_not_applicable_without_a_target_server_hello() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_client_hello(&mut stream);
    });
    let result = probe_response(
        "127.0.0.1",
        port,
        "youtube.com",
        ResponseOptions {
            repeats: 1,
            timeout: Duration::from_millis(75),
            mark: Some(0),
        },
    );
    assert_eq!(result.verdict, ResponseVerdict::NotApplicable);
    assert!(result.reason.contains("целевой TLS 1.2 ClientHello"));
}

#[test]
fn incomplete_tls_record_is_not_mistaken_for_a_completed_handshake() {
    let mut bytes = record(22, &[14, 0, 0, 0]);
    bytes.pop();
    assert_eq!(scan12(&bytes), Scan12::NeedMore);
    assert_eq!(scan12(&[]), Scan12::NeedMore);
}

#[test]
fn response_verdicts_keep_unmeasured_control_and_flaky_cases_distinct() {
    let cases = [
        (
            0,
            3,
            1,
            3,
            ResponseVerdict::NotApplicable,
            "ответ сервера не поместился в локальный предел буфера (64 КБ) в 1 прогонах — про ответное направление вывода нет",
        ),
        (
            0,
            0,
            0,
            3,
            ResponseVerdict::NotApplicable,
            "контрольное рукопожатие по TLS 1.2 не завершается — сервер его не поддерживает или мешает что-то ещё; про ответное направление вывода нет",
        ),
        (
            3,
            3,
            0,
            3,
            ResponseVerdict::Clear,
            "рукопожатие TLS 1.2 доходит до конца — сертификат не режут",
        ),
        (
            0,
            3,
            0,
            3,
            ResponseVerdict::Blocked,
            "запрос проходит, а рукопожатие не завершается: с нейтральным именем на тот же адрес оно завершается каждый раз. Значит режут ОТВЕТ — сертификат в TLS 1.2 идёт открытым текстом",
        ),
        (
            2,
            3,
            0,
            3,
            ResponseVerdict::Flaky,
            "рукопожатий дошло 2 из 3 — не воспроизводится",
        ),
    ];
    for (target, control, unmeasured, repeats, verdict, reason) in cases {
        assert_eq!(
            decide(target, control, unmeasured, repeats),
            ResponseResult {
                verdict,
                target,
                control,
                reason: reason.into(),
            }
        );
    }
}
