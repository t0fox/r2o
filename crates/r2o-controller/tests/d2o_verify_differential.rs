use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use r2o_controller::fetch::{FetchOptions, r2o_fetch_with_phase_timeout};

fn serve_one(config: Arc<rustls::ServerConfig>, listener: TcpListener) {
    for _ in 0..4 {
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

#[test]
#[ignore = "run by scripts/r2o-tls-verify-differential.sh with the donor C verifier"]
fn donor_and_r2o_tls_results_match_for_matching_and_mismatched_certificate_names() {
    let helper = std::env::var_os("R2O_D2O_VERIFY_HELPER")
        .expect("differential script must provide the donor C verifier");
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate_der =
        rustls::pki_types::CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der());
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key.into())
            .unwrap(),
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || serve_one(config, listener));

    for (name, expected_name_ok) in [("localhost", true), ("wrong.example", false)] {
        let c_result = Command::new(&helper)
            .args(["127.0.0.1", &address.port().to_string(), name])
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
