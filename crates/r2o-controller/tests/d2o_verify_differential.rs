use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use r2o_controller::fetch::{FetchOptions, r2o_fetch_with_phase_timeout};

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
