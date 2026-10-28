use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use r2o_controller::fetch::{
    FetchOptions, R2O_D2O_VERIFY_STEP_TIMEOUT, R2O_D2O_VOLUME_RX_TIMEOUT,
    r2o_d2o_volume_candidate_encoding, r2o_fetch_measure_rx_volume_with_fallback_path_and_timeouts,
    r2o_fetch_with_encoding, r2o_fetch_with_phase_timeout,
};

fn serve(config: Arc<rustls::ServerConfig>, listener: TcpListener, requests: usize) {
    for _ in 0..requests {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = socket.set_write_timeout(Some(Duration::from_secs(3)));
        let Ok(mut connection) = rustls::ServerConnection::new(Arc::clone(&config)) else {
            continue;
        };
        while connection.is_handshaking() {
            if connection.complete_io(&mut socket).is_err() {
                break;
            }
        }
        if connection.is_handshaking() {
            continue;
        }

        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let Ok(length) = stream.read(&mut buffer) else {
                break;
            };
            if length == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..length]);
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            let _ = stream.flush();
        }
    }
}

fn serve_with_response(
    config: Arc<rustls::ServerConfig>,
    listener: TcpListener,
    requests: usize,
    response: Vec<u8>,
) {
    serve_with_response_delay(config, listener, requests, response, Duration::ZERO);
}

fn serve_with_response_delay(
    config: Arc<rustls::ServerConfig>,
    listener: TcpListener,
    requests: usize,
    response: Vec<u8>,
    delay: Duration,
) {
    for _ in 0..requests {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = socket.set_write_timeout(Some(Duration::from_secs(3)));
        thread::sleep(delay);
        let Ok(mut connection) = rustls::ServerConnection::new(Arc::clone(&config)) else {
            continue;
        };
        while connection.is_handshaking() {
            if connection.complete_io(&mut socket).is_err() {
                break;
            }
        }
        if connection.is_handshaking() {
            continue;
        }

        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let Ok(length) = stream.read(&mut buffer) else {
                break;
            };
            if length == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..length]);
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            stream.conn.send_close_notify();
            let _ = stream.conn.complete_io(&mut stream.sock);
        }
    }
}

fn serve_with_hello_lengths(
    config: Arc<rustls::ServerConfig>,
    listener: TcpListener,
    requests: usize,
    hello_lengths: std::sync::mpsc::Sender<Vec<usize>>,
) {
    let mut lengths = Vec::with_capacity(requests);
    for _ in 0..requests {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = socket.set_write_timeout(Some(Duration::from_secs(3)));
        lengths.push(capture_client_hello_wire_len(&socket));
        let Ok(mut connection) = rustls::ServerConnection::new(Arc::clone(&config)) else {
            continue;
        };
        while connection.is_handshaking() {
            if connection.complete_io(&mut socket).is_err() {
                break;
            }
        }
        if connection.is_handshaking() {
            continue;
        }

        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let Ok(length) = stream.read(&mut buffer) else {
                break;
            };
            if length == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..length]);
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            let _ = stream.flush();
        }
    }
    let _ = hello_lengths.send(lengths);
}

fn capture_client_hello_wire_len(socket: &TcpStream) -> usize {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let mut header = [0_u8; 5];
        match socket.peek(&mut header) {
            Ok(0) => panic!("client closed before sending ClientHello"),
            Ok(length) if length >= header.len() => {
                assert_eq!(header[0], 0x16, "first TLS record is not handshake data");
                return 5 + usize::from(u16::from_be_bytes([header[3], header[4]]));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("peek ClientHello record: {error}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "ClientHello header timed out"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn server_config(
    tls12: bool,
    invalid_finished: bool,
    short_finished: bool,
) -> Arc<rustls::ServerConfig> {
    let builder = if tls12 {
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
    } else {
        rustls::ServerConfig::builder()
    };
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate_der =
        rustls::pki_types::CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der());
    let mut config = builder
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key.into())
        .unwrap();
    config.r2o_test_invalid_finished = invalid_finished;
    config.r2o_test_short_server_finished = short_finished;
    Arc::new(config)
}

fn server_config_with_alpn(protocols: Vec<Vec<u8>>) -> Arc<rustls::ServerConfig> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate_der =
        rustls::pki_types::CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der());
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key.into())
        .unwrap();
    config.alpn_protocols = protocols;
    Arc::new(config)
}

fn captured_tls13_client_hello(alpn: Option<&str>, ech: bool) -> Vec<u8> {
    let ech_extension = [0xfe, 0x0d, 0, 2, 0, 0];
    let handshake = r2o_controller::r2o_tls::r2o_tls13_client_hello(
        &r2o_controller::r2o_tls::R2oTls13ClientHelloOptions {
            server_name: Some("localhost"),
            public_key: &[7; 32],
            random: &[9; 32],
            session_id_len: 0,
            offer_tls12: false,
            alpn,
            alpn_wire: None,
            extra_extensions: if ech { &ech_extension } else { &[] },
            pad_to: 0,
        },
    )
    .unwrap();
    let length = u16::try_from(handshake.len()).unwrap();
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn serve_alpn_handshakes(
    config: Arc<rustls::ServerConfig>,
    listener: TcpListener,
    selected: std::sync::mpsc::Sender<Option<Vec<u8>>>,
) {
    for _ in 0..2 {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = socket.set_write_timeout(Some(Duration::from_secs(3)));
        let Ok(mut connection) = rustls::ServerConnection::new(Arc::clone(&config)) else {
            let _ = selected.send(None);
            continue;
        };
        while connection.is_handshaking() {
            if connection.complete_io(&mut socket).is_err() {
                break;
            }
        }
        let negotiated =
            (!connection.is_handshaking()).then(|| connection.alpn_protocol().map(<[u8]>::to_vec));
        let _ = selected.send(negotiated.flatten());
    }
}

fn serve_replayed_client_hellos(
    listener: TcpListener,
    requests: usize,
    response_type: u8,
    captured: std::sync::mpsc::Sender<Vec<u8>>,
) {
    for _ in 0..requests {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
        let mut header = [0; 5];
        if socket.read_exact(&mut header).is_err() {
            continue;
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut hello = header.to_vec();
        hello.resize(5 + length, 0);
        if socket.read_exact(&mut hello[5..]).is_err() {
            continue;
        }
        let _ = captured.send(hello);
        let _ = socket.write_all(&[0x16, 0x03, 0x03, 0, 1, response_type]);
    }
}

fn serve_slow_replayed_client_hellos(
    listener: TcpListener,
    requests: usize,
    delay: Duration,
    captured: std::sync::mpsc::Sender<Vec<u8>>,
) {
    for _ in 0..requests {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
        let mut header = [0; 5];
        if socket.read_exact(&mut header).is_err() {
            continue;
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut hello = header.to_vec();
        hello.resize(5 + length, 0);
        if socket.read_exact(&mut hello[5..]).is_err() {
            continue;
        }
        let _ = captured.send(hello);
        let _ = socket.write_all(&[0x16]);
        thread::sleep(delay);
        let _ = socket.write_all(&[0x03, 0x03, 0, 1]);
        thread::sleep(delay);
        let _ = socket.write_all(&[2]);
    }
}

fn server_config_with_invalid_utf8_dns_san() -> Arc<rustls::ServerConfig> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut certificate_der = certificate.serialize_der().unwrap();
    let san_name = certificate_der
        .windows(11)
        .position(|window| window[0] == 0x82 && window[1] == 9 && &window[2..] == b"localhost")
        .expect("DER contains the localhost dNSName SAN");
    certificate_der[san_name + 2] = 0xff;
    let certificate_der = rustls::pki_types::CertificateDer::from(certificate_der);
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key.into())
        .unwrap();
    Arc::new(config)
}

fn server_config_with_truncated_dns_san_trailer() -> Arc<rustls::ServerConfig> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut certificate_der = certificate.serialize_der().unwrap();
    let san_name = certificate_der
        .windows(11)
        .position(|window| window[0] == 0x82 && window[1] == 9 && &window[2..] == b"localhost")
        .expect("DER contains the localhost dNSName SAN");
    certificate_der[san_name + 1] = 0;
    let certificate_der = rustls::pki_types::CertificateDer::from(certificate_der);
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key.into())
        .unwrap();
    Arc::new(config)
}

fn server_config_with_zero_length_ip_san() -> Arc<rustls::ServerConfig> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut certificate_der = certificate.serialize_der().unwrap();
    let san_name = certificate_der
        .windows(11)
        .position(|window| window[0] == 0x82 && window[1] == 9 && &window[2..] == b"localhost")
        .expect("DER contains the localhost dNSName SAN");
    certificate_der[san_name] = 0x87;
    certificate_der[san_name + 1] = 0;
    let certificate_der = rustls::pki_types::CertificateDer::from(certificate_der);
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key.into())
        .unwrap();
    Arc::new(config)
}

fn assert_invalid_finished_result(protocol: &str, tls12: bool) {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || serve(server_config(tls12, true, false), listener, 2));
    let port = address.port().to_string();

    let c_result = Command::new(&helper)
        .args(["127.0.0.1", port.as_str(), "localhost", protocol])
        .output()
        .expect("run donor C verifier");
    assert!(
        c_result.status.success(),
        "donor verifier exited with {}: {}",
        c_result.status,
        String::from_utf8_lossy(&c_result.stderr)
    );
    assert_eq!(
        String::from_utf8(c_result.stdout).unwrap().trim(),
        "1\t1\t200\t1",
        "C accepts an invalid Finished inside a validly encrypted record"
    );

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12,
        wire_len: None,
        mark: None,
    };
    let rust_result = r2o_fetch_with_phase_timeout(&options, Duration::from_secs(3))
        .expect("r2o must accept the same Finished result as d2o");
    assert_eq!(rust_result.tls, Some(if tls12 { "1.2" } else { "1.3" }));
    assert_eq!(rust_result.peer_name_ok, Some(true));
    assert_eq!(rust_result.status, 200);
    assert!(rust_result.complete);
    assert!(rust_result.application_verified);
    server.join().unwrap();
}

fn serve_and_capture_requests(
    config: Arc<rustls::ServerConfig>,
    listener: TcpListener,
    sender: std::sync::mpsc::Sender<Vec<u8>>,
) {
    for _ in 0..2 {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = socket.set_write_timeout(Some(Duration::from_secs(3)));
        let Ok(mut connection) = rustls::ServerConnection::new(Arc::clone(&config)) else {
            continue;
        };
        while connection.is_handshaking() {
            if connection.complete_io(&mut socket).is_err() {
                break;
            }
        }
        if connection.is_handshaking() {
            continue;
        }

        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if stream.read_exact(&mut byte).is_err() {
                break;
            }
            request.push(byte[0]);
        }
        if request.ends_with(b"\r\n\r\n") {
            if sender.send(request).is_err() {
                return;
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            let _ = stream.flush();
        }
    }
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_send_the_same_default_verification_request() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        serve_and_capture_requests(server_config(false, false, false), listener, sender)
    });
    let port = address.port().to_string();

    let c_result = Command::new(&helper)
        .args(["127.0.0.1", port.as_str(), "localhost", "tls13"])
        .output()
        .expect("run donor C verifier");
    assert!(c_result.status.success());
    assert_eq!(
        String::from_utf8(c_result.stdout).unwrap().trim(),
        "1\t1\t200\t1"
    );
    let c_request = receiver.recv().expect("capture d2o verification request");

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12: false,
        wire_len: None,
        mark: None,
    };
    let rust_result = r2o_fetch_with_phase_timeout(&options, Duration::from_secs(3))
        .expect("r2o must complete the same verification request");
    assert!(rust_result.application_verified);
    let rust_request = receiver.recv().expect("capture r2o verification request");
    server.join().unwrap();

    assert_eq!(
        c_request, rust_request,
        "d2o and r2o must send the same GET / request for ordinary TLS verification"
    );
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_send_the_same_tx_only_volume_candidate_request() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        serve_and_capture_requests(server_config(false, false, false), listener, sender)
    });
    let port = address.port().to_string();

    let c_result = Command::new(&helper)
        .args(["127.0.0.1", port.as_str(), "localhost", "tls13"])
        .output()
        .expect("run donor C verifier for TX-only volume candidate");
    assert!(c_result.status.success());
    assert_eq!(
        String::from_utf8(c_result.stdout).unwrap().trim(),
        "1\t1\t200\t1"
    );
    let c_request = receiver.recv().expect("capture d2o candidate request");

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12: false,
        wire_len: None,
        mark: None,
    };
    let rust_result =
        r2o_fetch_with_encoding(&options, r2o_d2o_volume_candidate_encoding("/", false))
            .expect("complete the r2o volume-candidate request");
    assert!(rust_result.application_verified);
    let rust_request = receiver.recv().expect("capture r2o candidate request");
    server.join().unwrap();

    assert_eq!(
        c_request, rust_request,
        "a TX-only volume cut must keep the same default GET encoding in d2o and r2o"
    );
}

fn assert_short_tls12_finished_is_rejected() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || serve(server_config(true, false, true), listener, 2));
    let port = address.port().to_string();

    let c_result = Command::new(&helper)
        .args(["127.0.0.1", port.as_str(), "localhost", "tls12"])
        .output()
        .expect("run donor C verifier");
    assert!(c_result.status.success());
    assert_eq!(
        String::from_utf8(c_result.stdout).unwrap().trim(),
        "0\t-1\t0\t0",
        "d2o rejects a TLS 1.2 Finished whose verify_data is not 12 bytes"
    );

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12: true,
        wire_len: None,
        mark: None,
    };
    let rust_result = r2o_fetch_with_phase_timeout(&options, Duration::from_secs(3));
    server.join().unwrap();
    assert!(
        rust_result.is_err(),
        "r2o must reject the short Finished just as d2o does"
    );
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_accept_youtube_sized_response_headers() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let long_value = "a".repeat(12_000);
    let response = format!(
        "HTTP/1.1 200 OK\r\nX-YouTube-Response: {long_value}\r\nConnection: close\r\n\r\nok"
    )
    .into_bytes();
    let server = thread::spawn(move || {
        serve_with_response(server_config(false, false, false), listener, 2, response)
    });
    let port = address.port().to_string();

    let c_result = Command::new(&helper)
        .args(["127.0.0.1", port.as_str(), "localhost", "tls13"])
        .output()
        .expect("run donor C verifier with the large response header");
    assert!(
        c_result.status.success(),
        "donor verifier exited with {}: {}",
        c_result.status,
        String::from_utf8_lossy(&c_result.stderr)
    );
    assert_eq!(
        String::from_utf8(c_result.stdout).unwrap().trim(),
        "1\t1\t200\t1",
        "d2o accepts YouTube's large response header"
    );

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12: false,
        wire_len: None,
        mark: None,
    };
    let rust_result = r2o_fetch_with_phase_timeout(&options, Duration::from_secs(3))
        .expect("r2o must complete the same HTTPS verification");
    server.join().unwrap();

    assert_eq!(rust_result.status, 200);
    assert!(rust_result.complete, "r2o result: {rust_result:?}");
    assert!(
        rust_result.application_verified,
        "r2o result: {rust_result:?}"
    );
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_candidate_probes_keep_the_client_hello_wire_length() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let wire_length = 900_usize;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let (length_sender, length_receiver) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        serve_with_hello_lengths(
            server_config(false, false, false),
            listener,
            2,
            length_sender,
        )
    });

    let c_result = Command::new(&helper)
        .args([
            "127.0.0.1",
            &address.port().to_string(),
            "localhost",
            "tls13-pad",
            &wire_length.to_string(),
        ])
        .output()
        .expect("run donor C verifier with the captured ClientHello length");
    assert!(
        c_result.status.success(),
        "donor verifier exited with {}: {}",
        c_result.status,
        String::from_utf8_lossy(&c_result.stderr)
    );
    assert_eq!(
        String::from_utf8(c_result.stdout).unwrap().trim(),
        "1\t1\t200\t1"
    );

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12: false,
        wire_len: Some(wire_length),
        mark: None,
    };
    let rust_result = r2o_fetch_with_phase_timeout(&options, Duration::from_secs(3))
        .expect("r2o must finish the same HTTPS verification");
    assert_eq!(rust_result.status, 200);
    assert!(rust_result.complete);
    let lengths = length_receiver
        .recv()
        .expect("capture both ClientHello lengths");
    server.join().unwrap();

    assert_eq!(lengths.len(), 2);
    assert_eq!(
        lengths[0], wire_length,
        "d2o pads to the supplied trigger length"
    );
    assert_eq!(
        lengths[1], wire_length,
        "r2o candidate TLS probe must match d2o's trigger wire length"
    );
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_tls_results_match_for_matching_and_mismatched_certificate_names() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || serve(server_config(false, false, false), listener, 4));

    for (name, expected_name_ok) in [("localhost", true), ("wrong.example", false)] {
        let c_result = Command::new(&helper)
            .args(["127.0.0.1", &address.port().to_string(), name, "tls13"])
            .output()
            .expect("run donor C verifier");
        assert!(
            c_result.status.success(),
            "donor verifier exited with {}: {}",
            c_result.status,
            String::from_utf8_lossy(&c_result.stderr)
        );
        assert_eq!(
            String::from_utf8(c_result.stdout).unwrap().trim(),
            format!("1\t{}\t200\t1", u8::from(expected_name_ok)),
            "C reports application level, SAN result, HTTP 200, complete body for {name}"
        );

        let options = FetchOptions {
            name: name.into(),
            ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: address.port(),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: None,
            mark: None,
        };
        let rust_result = r2o_fetch_with_phase_timeout(&options, Duration::from_secs(3));
        let rust_result = rust_result.expect("Rust verifier should accept the donor's TLS result");
        assert_eq!(rust_result.tls, Some("1.3"));
        assert_eq!(rust_result.peer_name_ok, Some(expected_name_ok));
        assert_eq!(rust_result.status, 200);
        assert!(rust_result.complete);
        assert!(rust_result.application_verified);
    }
    server.join().unwrap();
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_rx_probe_accept_tls_response_before_six_second_deadline() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        serve_with_response_delay(
            server_config(false, false, false),
            listener,
            2,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
            Duration::from_millis(5400),
        )
    });
    let port = address.port().to_string();
    let c_result = Command::new(&helper)
        .args(["127.0.0.1", port.as_str(), "localhost", "tls13-rx"])
        .output()
        .expect("run donor RX verifier");
    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(8),
        tls12: false,
        wire_len: None,
        mark: None,
    };
    let rust_result = r2o_fetch_measure_rx_volume_with_fallback_path_and_timeouts(
        &options,
        None,
        R2O_D2O_VERIFY_STEP_TIMEOUT,
        R2O_D2O_VOLUME_RX_TIMEOUT,
    );
    server.join().unwrap();

    assert!(
        c_result.status.success(),
        "donor verifier exited with {}: {}",
        c_result.status,
        String::from_utf8_lossy(&c_result.stderr)
    );
    assert_eq!(
        String::from_utf8(c_result.stdout).unwrap().trim(),
        "1\t1\t200\t1",
        "d2o waits the full six-second RX TLS deadline"
    );
    let first = rust_result
        .first
        .as_ref()
        .expect("r2o must complete TLS/HTTP");
    assert_eq!(first.status, 200);
    assert!(first.complete);
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_report_invalid_utf8_dns_san_as_a_name_mismatch() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server =
        thread::spawn(move || serve(server_config_with_invalid_utf8_dns_san(), listener, 2));
    let port = address.port().to_string();
    let c_result = Command::new(helper)
        .args(["127.0.0.1", port.as_str(), "localhost", "tls13"])
        .output()
        .expect("run donor C verifier");

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12: false,
        wire_len: None,
        mark: None,
    };
    let rust_result = r2o_fetch_with_phase_timeout(&options, Duration::from_secs(3));
    server.join().unwrap();

    assert!(
        c_result.status.success(),
        "donor verifier exited with {}: {}",
        c_result.status,
        String::from_utf8_lossy(&c_result.stderr)
    );
    assert_eq!(
        String::from_utf8(c_result.stdout).unwrap().trim(),
        "1\t0\t200\t1",
        "d2o treats a present but unmatchable dNSName SAN as a mismatch"
    );
    let rust_result = rust_result.expect("r2o must accept the same TLS application response");
    assert_eq!(rust_result.tls, Some("1.3"));
    assert_eq!(rust_result.peer_name_ok, Some(false));
    assert_eq!(rust_result.status, 200);
    assert!(rust_result.complete);
    assert!(rust_result.application_verified);
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_keep_a_seen_dns_san_mismatch_when_its_trailer_is_truncated() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server =
        thread::spawn(move || serve(server_config_with_truncated_dns_san_trailer(), listener, 2));
    let port = address.port().to_string();
    let c_result = Command::new(helper)
        .args(["127.0.0.1", port.as_str(), "localhost", "tls13"])
        .output()
        .expect("run donor C verifier");

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12: false,
        wire_len: None,
        mark: None,
    };
    let rust_result = r2o_fetch_with_phase_timeout(&options, Duration::from_secs(3));
    server.join().unwrap();

    assert!(
        c_result.status.success(),
        "donor verifier exited with {}: {}",
        c_result.status,
        String::from_utf8_lossy(&c_result.stderr)
    );
    assert_eq!(
        String::from_utf8(c_result.stdout).unwrap().trim(),
        "1\t0\t200\t1",
        "d2o keeps the seen dNSName as a mismatch when a later SAN entry is truncated"
    );
    let rust_result = rust_result.expect("r2o must accept the same TLS application response");
    assert_eq!(rust_result.tls, Some("1.3"));
    assert_eq!(rust_result.peer_name_ok, Some(false));
    assert_eq!(rust_result.status, 200);
    assert!(rust_result.complete);
    assert!(rust_result.application_verified);
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_preserve_zero_length_ip_san_match_for_a_dns_host() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || serve(server_config_with_zero_length_ip_san(), listener, 2));
    let port = address.port().to_string();
    let c_result = Command::new(helper)
        .args(["127.0.0.1", port.as_str(), "localhost", "tls13"])
        .output()
        .expect("run donor C verifier");

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12: false,
        wire_len: None,
        mark: None,
    };
    let rust_result = r2o_fetch_with_phase_timeout(&options, Duration::from_secs(3));
    server.join().unwrap();

    assert!(
        c_result.status.success(),
        "donor verifier exited with {}: {}",
        c_result.status,
        String::from_utf8_lossy(&c_result.stderr)
    );
    assert_eq!(
        String::from_utf8(c_result.stdout).unwrap().trim(),
        "1\t1\t200\t1",
        "d2o compares empty iPAddress data with the empty non-IP host-address buffer"
    );
    let rust_result = rust_result.expect("r2o must accept the same TLS application response");
    assert_eq!(rust_result.tls, Some("1.3"));
    assert_eq!(rust_result.peer_name_ok, Some(true));
    assert_eq!(rust_result.status, 200);
    assert!(rust_result.complete);
    assert!(rust_result.application_verified);
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_ignore_tls13_server_finished_verify_data() {
    assert_invalid_finished_result("tls13", false);
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_ignore_tls12_server_finished_verify_data() {
    assert_invalid_finished_result("tls12", true);
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_reject_short_tls12_server_finished() {
    assert_short_tls12_finished_is_rejected();
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_preserve_captured_mqtt_and_absent_alpn() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    for (client_alpn, mode, expected_server_alpn) in [
        (Some("mqtt"), "alpn-mqtt", Some(b"mqtt".to_vec())),
        (None, "alpn-none", None),
    ] {
        let client_hello = captured_tls13_client_hello(client_alpn, false);
        let offered = r2o_controller::r2o_tls::r2o_tls_client_hello_non_http_alpn(&client_hello)
            .expect("the captured non-HTTP/no-ALPN shape must be replayable");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (selected_sender, selected_receiver) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            serve_alpn_handshakes(
                server_config_with_alpn(vec![b"mqtt".to_vec()]),
                listener,
                selected_sender,
            )
        });
        let port = address.port().to_string();
        let c_result = Command::new(&helper)
            .args(["127.0.0.1", port.as_str(), "localhost", mode])
            .output()
            .expect("run donor C verifier with captured ALPN");
        assert!(
            c_result.status.success(),
            "donor verifier exited with {}: {}",
            c_result.status,
            String::from_utf8_lossy(&c_result.stderr)
        );
        assert_eq!(String::from_utf8(c_result.stdout).unwrap().trim(), "1\t1");
        assert_eq!(selected_receiver.recv().unwrap(), expected_server_alpn);

        let options = FetchOptions {
            name: "localhost".into(),
            ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: address.port(),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: Some(client_hello.len()),
            mark: None,
        };
        let stream = TcpStream::connect(address).unwrap();
        let rust_result = r2o_controller::fetch::r2o_verify_tls_connected_stream_with_alpn(
            &options,
            stream,
            &offered,
            Duration::from_secs(3),
        )
        .expect("r2o must finish the same handshake-only verification");
        assert!(rust_result.handshake_verified);
        assert!(!rust_result.application_verified);
        assert_eq!(selected_receiver.recv().unwrap(), expected_server_alpn);
        server.join().unwrap();
    }
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_require_server_hello_when_replaying_captured_ech() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let client_hello = captured_tls13_client_hello(None, true);
    assert!(r2o_controller::r2o_tls::r2o_tls_client_hello_non_http_alpn(&client_hello).is_none());
    assert!(client_hello.windows(2).any(|window| window == [0xfe, 0x0d]));
    let hex = client_hello
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    for (response_type, expected) in [(2_u8, true), (8_u8, false)] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (captured_sender, captured_receiver) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            serve_replayed_client_hellos(listener, 2, response_type, captured_sender)
        });
        let port = address.port().to_string();
        let c_result = Command::new(&helper)
            .args(["127.0.0.1", port.as_str(), "localhost", "replay", &hex])
            .output()
            .expect("run donor C verifier with captured ECH ClientHello");
        assert!(c_result.status.success());
        assert_eq!(
            String::from_utf8(c_result.stdout).unwrap().trim(),
            if expected { "1\t1" } else { "0\t0" }
        );
        assert_eq!(captured_receiver.recv().unwrap(), client_hello);

        let options = FetchOptions {
            name: "localhost".into(),
            ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: address.port(),
            path: "/".into(),
            deadline: Duration::from_secs(3),
            tls12: false,
            wire_len: Some(client_hello.len()),
            mark: None,
        };
        let stream = TcpStream::connect(address).unwrap();
        let rust_result = r2o_controller::fetch::r2o_verify_tls_replayed_client_hello(
            &options,
            stream,
            &client_hello,
            Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(rust_result.handshake_verified, expected);
        assert!(!rust_result.application_verified);
        assert_eq!(captured_receiver.recv().unwrap(), client_hello);
        server.join().unwrap();
    }
}

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_apply_an_absolute_deadline_to_replayed_client_hello() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let client_hello = captured_tls13_client_hello(None, true);
    let hex = client_hello
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let deadline = Duration::from_millis(500);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let (captured_sender, captured_receiver) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        serve_slow_replayed_client_hellos(listener, 2, Duration::from_millis(300), captured_sender)
    });
    let port = address.port().to_string();
    let c_result = Command::new(&helper)
        .args([
            "127.0.0.1",
            port.as_str(),
            "localhost",
            "replay",
            &hex,
            "500",
        ])
        .output()
        .expect("run donor C verifier with bounded replay deadline");
    assert!(c_result.status.success());
    assert_eq!(String::from_utf8(c_result.stdout).unwrap().trim(), "0\t0");
    assert_eq!(captured_receiver.recv().unwrap(), client_hello);

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12: false,
        wire_len: Some(client_hello.len()),
        mark: None,
    };
    let stream = TcpStream::connect(address).unwrap();
    let rust_result = r2o_controller::fetch::r2o_verify_tls_replayed_client_hello(
        &options,
        stream,
        &client_hello,
        deadline,
    )
    .unwrap();
    assert!(!rust_result.handshake_verified);
    assert_eq!(captured_receiver.recv().unwrap(), client_hello);
    server.join().unwrap();
}
