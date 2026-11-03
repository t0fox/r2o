use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

async fn spawn_quic_drop_proxy(
    upstream: SocketAddr,
    drop_requests: Arc<AtomicBool>,
    drop_replies: Arc<AtomicBool>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut client = None;
        let mut packet = [0; 65_535];
        loop {
            let Ok((length, source)) = socket.recv_from(&mut packet).await else {
                break;
            };
            if source == upstream {
                if !drop_replies.load(Ordering::Acquire) {
                    if let Some(client) = client {
                        let _ = socket.send_to(&packet[..length], client).await;
                    }
                }
            } else {
                client = Some(source);
                if !drop_requests.load(Ordering::Acquire)
                    && socket.send_to(&packet[..length], upstream).await.is_err()
                {
                    break;
                }
            }
        }
    });
    (address, task)
}
fn write_d2o_http3_differential(
    env_name: &str,
    name: &str,
    result: &r2o_controller::r2o_quic_http3::R2oQuicHttp3Result,
) {
    let Ok(path) = std::env::var(env_name) else {
        return;
    };
    let verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(result);
    std::fs::write(path, format!("{name}={verdict:?}\n")).unwrap();
}

use h3_quinn::quinn;
use r2o_controller::fetch::{FetchOptions, r2o_fetch_quic_with_roots_and_budget};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};

use r2o_controller::r2o_quic_http3::{
    r2o_quic_http3_get, r2o_quic_http3_get_with_max_duration, r2o_quic_http3_measure,
};

#[tokio::test]
async fn r2o_http3_соблюдает_оставшийся_срок_задачи() {
    let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    let certificate = rcgen::Certificate::from_params(certificate_params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut h3_connection = h3::server::builder()
            .build(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let resolver = h3_connection.accept().await.unwrap().unwrap();
        let (_, mut stream) = resolver.resolve_request().await.unwrap();
        stream
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_LENGTH, "16")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = stream
            .send_data(bytes::Bytes::from_static("проверка".as_bytes()))
            .await;
    });

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        r2o_quic_http3_get_with_max_duration(
            socket,
            server_address,
            "localhost",
            "/",
            Duration::from_secs(3),
            roots,
            Duration::from_secs(2),
        ),
    )
    .await
    .expect("HTTP/3-замер превысил общий срок задачи");

    assert!(result.handshake_confirmed, "результат HTTP/3: {result:?}");
    assert_eq!(result.status, 200, "результат HTTP/3: {result:?}");
    assert!(result.error.is_some(), "результат HTTP/3: {result:?}");
    assert!(started.elapsed() < Duration::from_secs(4));
    server.abort();
}

#[tokio::test]
async fn r2o_http3_transport_close_is_not_stall_and_matches_d2o() {
    let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    let certificate = rcgen::Certificate::from_params(certificate_params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut h3_connection = h3::server::builder()
            .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        let resolver = h3_connection.accept().await.unwrap().unwrap();
        let _ = resolver.resolve_request().await.unwrap();
        connection.close(quinn::VarInt::from_u32(1), b"test transport close");
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        r2o_quic_http3_get(
            socket,
            server_address,
            "localhost",
            "/",
            Duration::from_secs(2),
            roots,
        ),
    )
    .await
    .expect("HTTP/3 transport-close test timed out");

    assert!(result.handshake_confirmed, "result: {result:?}");
    assert_eq!(result.status, 0, "result: {result:?}");
    assert!(result.error.is_some(), "result: {result:?}");
    assert!(!result.r2o_quic_stalled, "result: {result:?}");
    assert_eq!(
        format!(
            "{:?}",
            r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&result)
        ),
        "NotRun"
    );
    write_d2o_http3_differential(
        "R2O_QUIC_HTTP3_TRANSPORT_ERROR_DIFF_OUTPUT",
        "transport-error",
        &result,
    );
    server.abort();
}

#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_connection_close_after_partial_body_matches_d2o() {
    let d2o_binary = std::env::var("D2O_QUIC_DATA_STAGE_BIN")
        .expect("D2O_QUIC_DATA_STAGE_BIN must point to the pinned C data-stage harness");
    let certificate = rcgen::Certificate::from_params(rcgen::CertificateParams::new(vec![
        "localhost".to_owned(),
    ]))
    .unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let mut h3_connection = h3::server::builder()
                .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            let resolver = h3_connection.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            stream
                .send_response(
                    http::Response::builder()
                        .status(200)
                        .header(http::header::CONTENT_LENGTH, "4096")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            stream
                .send_data(bytes::Bytes::from_static(b"partial"))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            connection.close(quinn::VarInt::from_u32(1), b"test close after partial body");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let c_address = address;
    let c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(d2o_binary)
            .args([
                "127.0.0.1",
                &c_address.port().to_string(),
                "localhost",
                "/close-after-partial-body",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !c_output.status.success(),
        "D2O unexpectedly passed after an incomplete response: stdout={} stderr={}",
        String::from_utf8_lossy(&c_output.stdout),
        String::from_utf8_lossy(&c_output.stderr)
    );
    let c_result = String::from_utf8(c_output.stdout).unwrap();
    let c_field = |name: &str| {
        c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(6),
        r2o_quic_http3_get(
            socket,
            address,
            "localhost",
            "/close-after-partial-body",
            Duration::from_secs(2),
            roots,
        ),
    )
    .await
    .expect("HTTP/3 connection-close test timed out");
    let verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&result);

    assert!(result.handshake_confirmed, "R2O={result:?}");
    assert_eq!(result.status, 200, "R2O={result:?}");
    assert!(!result.complete, "R2O={result:?}");
    assert!(result.error.is_some(), "R2O={result:?}");
    assert!(!result.r2o_quic_stalled, "R2O={result:?}");
    assert_eq!(c_field("verdict"), "NotRun", "D2O={c_result}");
    assert_eq!(
        format!("{verdict:?}"),
        c_field("verdict"),
        "D2O={c_result} R2O={result:?}"
    );
    assert!(
        result.app_bytes > 0,
        "R2O did not observe the partial response: {result:?}"
    );
    assert_eq!(
        result.app_bytes,
        c_field("app_bytes").parse::<u64>().unwrap()
    );
    assert_eq!(result.requests, 1);
    assert_eq!(result.requests, c_field("requests").parse::<u32>().unwrap());
    write_d2o_http3_differential(
        "R2O_QUIC_HTTP3_CONNECTION_CLOSE_DIFF_OUTPUT",
        "connection-close-after-partial-body",
        &result,
    );
    server.await.unwrap();
}

#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_alpn_refusal_matches_d2o() {
    let d2o_binary = std::env::var("D2O_QUIC_DATA_STAGE_BIN")
        .expect("D2O_QUIC_DATA_STAGE_BIN must point to the pinned C data-stage harness");
    let certificate = rcgen::Certificate::from_params(rcgen::CertificateParams::new(vec![
        "localhost".to_owned(),
    ]))
    .unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let Some(incoming) = endpoint.accept().await else {
                return;
            };
            let _ = incoming.await;
        }
    });

    let c_address = address;
    let c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(d2o_binary)
            .args([
                "127.0.0.1",
                &c_address.port().to_string(),
                "localhost",
                "/alpn-refused",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !c_output.status.success(),
        "D2O unexpectedly accepted a server without HTTP/3 ALPN: stdout={} stderr={}",
        String::from_utf8_lossy(&c_output.stdout),
        String::from_utf8_lossy(&c_output.stderr)
    );
    let c_result = String::from_utf8(c_output.stdout).unwrap();
    let c_field = |name: &str| {
        c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(6),
        r2o_quic_http3_get(
            socket,
            address,
            "localhost",
            "/alpn-refused",
            Duration::from_secs(2),
            roots,
        ),
    )
    .await
    .expect("HTTP/3 ALPN-refusal test timed out");
    let verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&result);

    assert!(!result.handshake_confirmed, "R2O={result:?}");
    assert_eq!(result.status, 0, "R2O={result:?}");
    assert!(result.error.is_some(), "R2O={result:?}");
    assert_eq!(c_field("verdict"), "NoHandshake", "D2O={c_result}");
    assert_eq!(
        format!("{verdict:?}"),
        c_field("verdict"),
        "D2O={c_result} R2O={result:?}"
    );
    assert_eq!(
        result.app_bytes,
        c_field("app_bytes").parse::<u64>().unwrap()
    );
    assert_eq!(result.requests, c_field("requests").parse::<u32>().unwrap());
    assert_eq!(result.requests, 0, "R2O={result:?}");
    write_d2o_http3_differential(
        "R2O_QUIC_HTTP3_ALPN_REFUSAL_DIFF_OUTPUT",
        "alpn-refusal",
        &result,
    );
    server.await.unwrap();
}

async fn spawn_quic_peer_without_settings(
    close_after_handshake: bool,
    max_concurrent_uni_streams: Option<u32>,
) -> (
    SocketAddr,
    CertificateDer<'static>,
    tokio::task::JoinHandle<()>,
) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    let certificate = rcgen::Certificate::from_params(params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    if let Some(max_concurrent_uni_streams) = max_concurrent_uni_streams {
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(max_concurrent_uni_streams));
        server_config.transport_config(Arc::new(transport));
    }
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                if close_after_handshake {
                    connection.close(quinn::VarInt::from_u32(1), b"closed before H3 settings");
                } else {
                    tokio::time::sleep(Duration::from_secs(12)).await;
                    connection.close(quinn::VarInt::from_u32(1), b"no H3 settings");
                }
            });
        }
    });

    (server_address, certificate_der, server)
}

#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_without_peer_settings_matches_d2o() {
    let d2o_binary = std::env::var("D2O_QUIC_DATA_STAGE_BIN")
        .expect("D2O_QUIC_DATA_STAGE_BIN must point to the pinned C data-stage harness");
    let (server_address, certificate_der, server) =
        spawn_quic_peer_without_settings(false, None).await;

    let address = server_address;
    let c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(d2o_binary)
            .args([
                "127.0.0.1",
                &address.port().to_string(),
                "localhost",
                "/no-settings",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !c_output.status.success(),
        "D2O without peer SETTINGS unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&c_output.stdout),
        String::from_utf8_lossy(&c_output.stderr)
    );
    let c_result = String::from_utf8(c_output.stdout).unwrap();
    let c_field = |name: &str| {
        c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {c_result}"))
    };
    assert_ne!(c_field("verdict"), "Pass", "D2O={c_result}");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let rust_result = tokio::time::timeout(
        Duration::from_secs(9),
        r2o_quic_http3_get(
            socket,
            server_address,
            "localhost",
            "/no-settings",
            Duration::from_secs(1),
            roots,
        ),
    )
    .await
    .expect("HTTP/3 missing peer SETTINGS test timed out");
    let rust_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&rust_result);

    assert!(rust_result.handshake_confirmed, "R2O={rust_result:?}");
    assert_eq!(rust_result.status, 0, "R2O={rust_result:?}");
    assert_eq!(c_field("verdict"), format!("{rust_verdict:?}"));
    assert_eq!(
        c_field("app_bytes").parse::<u64>().unwrap(),
        rust_result.app_bytes,
        "D2O={c_result} R2O={rust_result:?}"
    );
    assert_eq!(
        c_field("requests").parse::<u32>().unwrap(),
        rust_result.requests,
        "D2O={c_result} R2O={rust_result:?}"
    );
    write_d2o_http3_differential(
        "R2O_QUIC_HTTP3_NO_SETTINGS_DIFF_OUTPUT",
        "no-settings",
        &rust_result,
    );
    server.abort();
}

#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_zero_peer_uni_credit_matches_d2o() {
    let d2o_binary = std::env::var("D2O_QUIC_DATA_STAGE_BIN")
        .expect("D2O_QUIC_DATA_STAGE_BIN must point to the pinned C data-stage harness");
    let (server_address, certificate_der, server) =
        spawn_quic_peer_without_settings(false, Some(0)).await;

    let c_address = server_address;
    let c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(d2o_binary)
            .args([
                "127.0.0.1",
                &c_address.port().to_string(),
                "localhost",
                "/zero-peer-uni-credit",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !c_output.status.success(),
        "D2O without peer unidirectional stream credit unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&c_output.stdout),
        String::from_utf8_lossy(&c_output.stderr)
    );
    let c_result = String::from_utf8(c_output.stdout).unwrap();
    let c_field = |name: &str| {
        c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {c_result}"))
    };
    assert_eq!(c_field("verdict"), "NotRun", "D2O={c_result}");
    assert_eq!(c_field("app_bytes"), "0", "D2O={c_result}");
    assert_eq!(c_field("requests"), "1", "D2O={c_result}");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let rust_result = tokio::time::timeout(
        Duration::from_secs(9),
        r2o_quic_http3_get(
            socket,
            server_address,
            "localhost",
            "/zero-peer-uni-credit",
            Duration::from_secs(1),
            roots,
        ),
    )
    .await
    .expect("HTTP/3 peer unidirectional stream-credit test timed out");
    let rust_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&rust_result);
    assert!(rust_result.handshake_confirmed, "R2O={rust_result:?}");
    assert_eq!(rust_result.status, 0, "R2O={rust_result:?}");
    assert!(rust_result.error.is_some(), "R2O={rust_result:?}");
    assert_eq!(
        format!("{rust_verdict:?}"),
        c_field("verdict"),
        "R2O={rust_result:?}"
    );
    assert_eq!(rust_result.app_bytes, 0, "R2O={rust_result:?}");
    assert_eq!(
        rust_result.requests,
        c_field("requests").parse::<u32>().unwrap(),
        "D2O={c_result} R2O={rust_result:?}"
    );
    write_d2o_http3_differential(
        "R2O_QUIC_HTTP3_ZERO_PEER_UNI_CREDIT_DIFF_OUTPUT",
        "zero-peer-uni-credit",
        &rust_result,
    );
    server.abort();
}

#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_connection_close_before_settings_matches_d2o() {
    let d2o_binary = std::env::var("D2O_QUIC_DATA_STAGE_BIN")
        .expect("D2O_QUIC_DATA_STAGE_BIN must point to the pinned C data-stage harness");
    let (server_address, certificate_der, server) =
        spawn_quic_peer_without_settings(true, None).await;

    let address = server_address;
    let c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(d2o_binary)
            .args([
                "127.0.0.1",
                &address.port().to_string(),
                "localhost",
                "/close-before-settings",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !c_output.status.success(),
        "D2O connection close unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&c_output.stdout),
        String::from_utf8_lossy(&c_output.stderr)
    );
    let c_result = String::from_utf8(c_output.stdout).unwrap();
    let c_field = |name: &str| {
        c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {c_result}"))
    };
    assert_eq!(c_field("verdict"), "NotRun", "D2O={c_result}");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let rust_result = tokio::time::timeout(
        Duration::from_secs(9),
        r2o_quic_http3_get(
            socket,
            server_address,
            "localhost",
            "/close-before-settings",
            Duration::from_secs(1),
            roots,
        ),
    )
    .await
    .expect("HTTP/3 connection-close test timed out");
    let rust_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&rust_result);

    assert!(rust_result.handshake_confirmed, "R2O={rust_result:?}");
    assert_eq!(rust_result.status, 0, "R2O={rust_result:?}");
    assert!(rust_result.error.is_some(), "R2O={rust_result:?}");
    assert_eq!(rust_result.app_bytes, 0, "R2O={rust_result:?}");
    assert_eq!(rust_result.requests, 1, "R2O={rust_result:?}");
    assert!(!rust_result.r2o_quic_stalled, "R2O={rust_result:?}");
    assert_eq!(format!("{rust_verdict:?}"), "NotRun", "R2O={rust_result:?}");
    assert_eq!(c_field("verdict"), format!("{rust_verdict:?}"));
    assert_eq!(
        c_field("app_bytes").parse::<u64>().unwrap(),
        rust_result.app_bytes,
        "D2O={c_result} R2O={rust_result:?}"
    );
    assert_eq!(
        c_field("requests").parse::<u32>().unwrap(),
        rust_result.requests,
        "D2O={c_result} R2O={rust_result:?}"
    );
    write_d2o_http3_differential(
        "R2O_QUIC_HTTP3_CLOSE_BEFORE_SETTINGS_DIFF_OUTPUT",
        "close-before-settings",
        &rust_result,
    );
    server.abort();
}

async fn spawn_quic_udp_reply_drop_fixture() -> (
    SocketAddr,
    CertificateDer<'static>,
    Arc<AtomicBool>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    let certificate = rcgen::Certificate::from_params(certificate_params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let drop_replies = Arc::new(AtomicBool::new(false));
    let server_drop_replies = Arc::clone(&drop_replies);
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut h3_connection = h3::server::builder()
            .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let resolver = h3_connection.accept().await.unwrap().unwrap();
        let (_, mut stream) = resolver.resolve_request().await.unwrap();
        stream
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_LENGTH, "16")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        server_drop_replies.store(true, Ordering::Release);
        let _ = shutdown_receiver.await;
    });
    (
        server_address,
        certificate_der,
        drop_replies,
        shutdown_sender,
        server,
    )
}

#[tokio::test]
#[ignore = "slow UDP stall fixture; run scripts/test-quic-http3-full-stage-differential.sh or scripts/r2o-diagnostics-differential.sh"]
async fn r2o_http3_udp_reply_drop_is_a_stall() {
    let d2o_result = if let Ok(d2o_binary) = std::env::var("D2O_QUIC_DATA_STAGE_BIN") {
        let (d2o_server_address, _, d2o_drop_replies, d2o_shutdown, d2o_server) =
            spawn_quic_udp_reply_drop_fixture().await;
        let (d2o_proxy_address, d2o_proxy) = spawn_quic_drop_proxy(
            d2o_server_address,
            Arc::new(AtomicBool::new(false)),
            Arc::clone(&d2o_drop_replies),
        )
        .await;
        let d2o_port = d2o_proxy_address.port().to_string();
        let d2o_output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(d2o_binary)
                .args(["127.0.0.1", &d2o_port, "localhost", "/", "0"])
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            !d2o_output.status.success(),
            "D2O reply-drop case unexpectedly passed: stdout={} stderr={}",
            String::from_utf8_lossy(&d2o_output.stdout),
            String::from_utf8_lossy(&d2o_output.stderr)
        );
        let d2o_result = String::from_utf8(d2o_output.stdout).unwrap();
        let _ = d2o_shutdown.send(());
        d2o_proxy.abort();
        d2o_server.abort();
        Some(d2o_result)
    } else {
        None
    };

    let (rust_server_address, certificate_der, rust_drop_replies, rust_shutdown, rust_server) =
        spawn_quic_udp_reply_drop_fixture().await;
    let (rust_proxy_address, rust_proxy) = spawn_quic_drop_proxy(
        rust_server_address,
        Arc::new(AtomicBool::new(false)),
        Arc::clone(&rust_drop_replies),
    )
    .await;
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(rust_proxy_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        r2o_quic_http3_get_with_max_duration(
            socket,
            rust_proxy_address,
            "localhost",
            "/",
            Duration::from_secs(1),
            roots,
            Duration::from_secs(6),
        ),
    )
    .await
    .expect("HTTP/3 UDP-drop test timed out");

    assert!(result.handshake_confirmed, "R2O result: {result:?}");
    assert_eq!(result.status, 200, "R2O result: {result:?}");
    assert!(result.r2o_quic_stalled, "R2O result: {result:?}");
    assert!(!result.r2o_quic_one_way, "R2O result: {result:?}");
    assert!(result.r2o_ping_probes >= 2, "R2O result: {result:?}");
    let verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&result);
    assert_eq!(format!("{verdict:?}"), "Cut", "R2O={result:?}");
    if let Some(d2o_result) = d2o_result {
        let d2o_field = |name: &str| {
            d2o_result
                .split_whitespace()
                .find_map(|field| field.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("missing {name} in D2O result: {d2o_result}"))
        };
        assert_eq!(d2o_field("verdict"), "Cut", "D2O={d2o_result}");
        assert_eq!(d2o_field("oneway"), "0", "D2O={d2o_result}");
        assert_eq!(
            format!("{verdict:?}"),
            d2o_field("verdict"),
            "D2O={d2o_result} R2O={result:?}"
        );
        assert_eq!(
            result.app_bytes,
            d2o_field("app_bytes").parse::<u64>().unwrap(),
            "D2O={d2o_result} R2O={result:?}"
        );
        assert_eq!(
            result.requests,
            d2o_field("requests").parse::<u32>().unwrap(),
            "D2O={d2o_result} R2O={result:?}"
        );
    }
    write_d2o_http3_differential("R2O_QUIC_HTTP3_STALL_DIFF_OUTPUT", "stall", &result);
    let _ = rust_shutdown.send(());
    rust_proxy.abort();
    rust_server.abort();
}

async fn spawn_quic_one_way_fixture() -> (
    SocketAddr,
    CertificateDer<'static>,
    Arc<AtomicBool>,
    tokio::task::JoinHandle<()>,
) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    let certificate = rcgen::Certificate::from_params(params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_millis(250)));
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = endpoint.local_addr().unwrap();
    let drop_requests = Arc::new(AtomicBool::new(false));
    let server_drop_requests = Arc::clone(&drop_requests);
    let server = tokio::spawn(async move {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let Ok(connection) = incoming.await else {
            return;
        };
        let Ok(mut h3_connection) = h3::server::builder()
            .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection))
            .await
        else {
            return;
        };
        let Ok(Some(resolver)) = h3_connection.accept().await else {
            return;
        };
        let Ok((_, mut stream)) = resolver.resolve_request().await else {
            return;
        };
        if stream
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_LENGTH, "16")
                    .body(())
                    .unwrap(),
            )
            .await
            .is_err()
        {
            return;
        }
        server_drop_requests.store(true, Ordering::Release);
        let _stream = stream;
        std::future::pending::<()>().await;
    });
    (server_address, certificate_der, drop_requests, server)
}

#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_one_way_reply_activity_matches_d2o() {
    let (d2o_server_address, _, d2o_drop_requests, d2o_server) = spawn_quic_one_way_fixture().await;
    let (d2o_proxy_address, d2o_proxy) = spawn_quic_drop_proxy(
        d2o_server_address,
        d2o_drop_requests,
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    let d2o_binary = std::env::var("D2O_QUIC_DATA_STAGE_BIN")
        .expect("D2O_QUIC_DATA_STAGE_BIN must point to the pinned C data-stage harness");
    let d2o_address = d2o_proxy_address;
    let d2o_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(d2o_binary)
            .args([
                "127.0.0.1",
                &d2o_address.port().to_string(),
                "localhost",
                "/one-way",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !d2o_output.status.success(),
        "D2O one-way reply case unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&d2o_output.stdout),
        String::from_utf8_lossy(&d2o_output.stderr)
    );
    let d2o_result = String::from_utf8(d2o_output.stdout).unwrap();
    let d2o_field = |name: &str| {
        d2o_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {d2o_result}"))
    };
    assert_eq!(d2o_field("verdict"), "Cut");
    assert_eq!(d2o_field("oneway"), "1");
    assert_eq!(d2o_field("requests"), "1");
    d2o_proxy.abort();
    d2o_server.abort();

    let (rust_server_address, certificate_der, rust_drop_requests, rust_server) =
        spawn_quic_one_way_fixture().await;
    let (rust_proxy_address, rust_proxy) = spawn_quic_drop_proxy(
        rust_server_address,
        rust_drop_requests,
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(rust_proxy_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        r2o_quic_http3_get(
            socket,
            rust_proxy_address,
            "localhost",
            "/one-way",
            Duration::from_secs(5),
            roots,
        ),
    )
    .await
    .expect("HTTP/3 one-way reply test timed out");
    let verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&result);

    assert!(result.handshake_confirmed, "R2O result: {result:?}");
    assert_eq!(result.status, 200, "R2O result: {result:?}");
    assert!(result.error.is_some(), "R2O result: {result:?}");
    assert!(!result.complete, "R2O result: {result:?}");
    assert!(result.r2o_quic_stalled, "R2O result: {result:?}");
    assert!(result.r2o_quic_one_way, "R2O result: {result:?}");
    assert!(result.r2o_ping_probes >= 2, "R2O result: {result:?}");
    assert_eq!(format!("{verdict:?}"), d2o_field("verdict"));
    assert_eq!(format!("{verdict:?}"), "Cut");
    assert_eq!(
        result.app_bytes,
        d2o_field("app_bytes").parse::<u64>().unwrap(),
        "D2O={d2o_result} R2O={result:?}"
    );
    assert_eq!(
        result.requests,
        d2o_field("requests").parse::<u32>().unwrap(),
        "D2O={d2o_result} R2O={result:?}"
    );
    write_d2o_http3_differential("R2O_QUIC_HTTP3_ONE_WAY_DIFF_OUTPUT", "one-way", &result);
    rust_proxy.abort();
    rust_server.abort();
}
#[tokio::test]
async fn r2o_http3_не_проверяет_content_length_вне_правила_d2o() {
    let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    let certificate = rcgen::Certificate::from_params(certificate_params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut h3_connection = h3::server::builder()
            .build(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let resolver = h3_connection.accept().await.unwrap().unwrap();
        let (_, mut stream) = resolver.resolve_request().await.unwrap();
        stream
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_LENGTH, "100")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream
            .send_data(bytes::Bytes::from_static(b"ok"))
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let _ = shutdown_receiver.await;
    });

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/",
        Duration::from_secs(3),
        roots,
    )
    .await;

    assert!(result.handshake_confirmed, "результат HTTP/3: {result:?}");
    assert_eq!(result.status, 200, "результат HTTP/3: {result:?}");
    assert_eq!(result.body_bytes, 2, "результат HTTP/3: {result:?}");
    assert!(result.complete, "результат HTTP/3: {result:?}");
    assert!(result.error.is_none(), "результат HTTP/3: {result:?}");
    write_d2o_http3_differential(
        "R2O_QUIC_HTTP3_CONTENT_LENGTH_DIFF_OUTPUT",
        "content-length",
        &result,
    );
    let _ = shutdown_sender.send(());
    server.abort();
}

#[tokio::test]
async fn r2o_http3_не_обрезает_ответ_на_16_миб() {
    const BODY_LEN: usize = 16 * 1024 * 1024 + 1;
    let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    let certificate = rcgen::Certificate::from_params(certificate_params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut h3_connection = h3::server::builder()
            .build(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let resolver = h3_connection.accept().await.unwrap().unwrap();
        let (_, mut stream) = resolver.resolve_request().await.unwrap();
        stream
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_LENGTH, BODY_LEN.to_string())
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream
            .send_data(bytes::Bytes::from(vec![b'x'; BODY_LEN]))
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let _ = shutdown_receiver.await;
    });

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        r2o_quic_http3_get(
            socket,
            server_address,
            "localhost",
            "/",
            Duration::from_secs(10),
            roots,
        ),
    )
    .await
    .expect("HTTP/3-замер превысил срок теста");

    assert!(result.handshake_confirmed, "результат HTTP/3: {result:?}");
    assert_eq!(result.status, 200, "результат HTTP/3: {result:?}");
    assert_eq!(
        result.body_bytes, BODY_LEN as u64,
        "результат HTTP/3: {result:?}"
    );
    assert!(result.complete, "результат HTTP/3: {result:?}");
    assert!(result.error.is_none(), "результат HTTP/3: {result:?}");
    write_d2o_http3_differential(
        "R2O_QUIC_HTTP3_LARGE_BODY_DIFF_OUTPUT",
        "large-body",
        &result,
    );
    let _ = shutdown_sender.send(());
    server.abort();
}

#[tokio::test]
async fn r2o_http3_учитывает_заголовки_потока_при_росте_бюджета() {
    let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    let certificate = rcgen::Certificate::from_params(certificate_params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut h3_connection = h3::server::builder()
            .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        for _ in 0..16 {
            let resolver = h3_connection.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            stream
                .send_response(http::Response::builder().status(204).body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();
        }
        let _ = shutdown_receiver.await;
    });

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(6),
        r2o_quic_http3_measure(
            socket,
            server_address,
            "localhost",
            "/",
            Duration::from_millis(100),
            roots,
            1,
        ),
    )
    .await
    .expect("HTTP/3-замер превысил срок теста");

    assert!(result.handshake_confirmed, "результат HTTP/3: {result:?}");
    assert_eq!(result.body_bytes, 0, "результат HTTP/3: {result:?}");
    assert!(
        result.app_bytes > 0,
        "HEADERS и framing — байты потока: {result:?}"
    );
    assert!(
        result.budget_passed,
        "заголовки и framing — прогресс потока: {result:?}"
    );
    assert!(
        result.requests >= 2,
        "нужен новый поток после порога: {result:?}"
    );
    let _ = shutdown_sender.send(());
    server.abort();
}

#[tokio::test]
async fn r2o_http3_повторяет_get_до_прохождения_пакетного_бюджета() {
    let mut certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    certificate_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let certificate = rcgen::Certificate::from_params(certificate_params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let mut shutdown_receiver = Some(shutdown_receiver);
    let server = tokio::spawn(async move {
        for connection_index in 0..4 {
            let incoming = server_endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let mut h3_connection = h3::server::builder()
                .build(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            let (request_sender, mut request_receiver) = tokio::sync::mpsc::channel(3);
            tokio::spawn(async move {
                while let Ok(Some(resolver)) = h3_connection.accept().await {
                    let (_, stream) = match resolver.resolve_request().await {
                        Ok(request) => request,
                        Err(_) => break,
                    };
                    if request_sender.send(stream).await.is_err() {
                        break;
                    }
                }
            });
            for _ in 0..3 {
                let mut stream = match request_receiver.recv().await {
                    Some(stream) => stream,
                    _ => break,
                };
                let response = http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_LENGTH, "16")
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                if connection_index == 1 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                stream
                    .send_data(bytes::Bytes::from_static("проверка".as_bytes()))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            }
            if connection_index == 3 {
                let _ = shutdown_receiver.take().unwrap().await;
            }
        }
    });

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        r2o_quic_http3_measure(
            socket,
            server_address,
            "localhost",
            "/",
            Duration::from_secs(3),
            roots.clone(),
            1,
        ),
    )
    .await
    .unwrap();

    assert!(result.handshake_confirmed);
    assert_eq!(result.status, 200, "результат HTTP/3: {result:?}");
    assert_eq!(
        result.body_bytes, 16,
        "бюджет может пройти по росту заголовков следующего потока до чтения его DATA: {result:?}"
    );
    assert!(
        result.app_bytes > result.body_bytes,
        "результат HTTP/3: {result:?}"
    );
    assert!((2..=3).contains(&result.requests));
    assert!(result.budget_passed);
    assert!(!result.complete);

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        r2o_quic_http3_get(
            socket,
            server_address,
            "localhost",
            "/",
            Duration::from_secs(3),
            roots.clone(),
        ),
    )
    .await
    .unwrap();
    assert!(result.handshake_confirmed);
    assert_eq!(result.status, 200, "результат HTTP/3: {result:?}");
    assert_eq!(result.body_bytes, 16);
    assert_eq!(result.requests, 1);
    assert!(result.complete);
    assert!(result.r2o_ping_probes > 0, "результат HTTP/3: {result:?}");
    assert!(result.r2o_ping_acks > 0, "результат HTTP/3: {result:?}");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        r2o_quic_http3_get(
            socket,
            server_address,
            "127.0.0.1",
            "/",
            Duration::from_secs(3),
            roots.clone(),
        ),
    )
    .await
    .unwrap();
    assert!(
        result.handshake_confirmed,
        "результат HTTP/3 по IP: {result:?}"
    );
    assert_eq!(result.status, 200, "результат HTTP/3 по IP: {result:?}");
    assert!(result.complete);

    let options = FetchOptions {
        name: "localhost".into(),
        ip: Some(server_address.ip()),
        port: server_address.port(),
        path: "/".into(),
        deadline: Duration::from_secs(3),
        tls12: false,
        wire_len: None,
        mark: None,
    };
    let result = tokio::task::spawn_blocking(move || {
        r2o_fetch_quic_with_roots_and_budget(&options, roots, 1)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.data.status, 200, "результат r2o-fetch: {result:?}");
    assert!(result.data.body_bytes >= 16);
    assert!(result.data.requests > 1);
    assert!(result.data.budget_required);
    assert!(result.data.budget_passed);
    assert!(!result.data.complete);
    assert_ne!(result.local_port, 0);

    let _ = shutdown_sender.send(());
    server.abort();
}

#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_full_data_stage_matches_d2o_on_complete_budget_no_growth_refusal_slow_body_drop_and_close()
 {
    let d2o_binary = std::env::var("D2O_QUIC_DATA_STAGE_BIN")
        .expect("D2O_QUIC_DATA_STAGE_BIN must point to the pinned C data-stage harness");
    let mut certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    certificate_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let certificate = rcgen::Certificate::from_params(certificate_params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let drop_upstream_replies = Arc::new(AtomicBool::new(false));
    let server_drop_replies = Arc::clone(&drop_upstream_replies);
    let server = tokio::spawn(async move {
        while let Some(incoming) = server_endpoint.accept().await {
            let drop_replies = Arc::clone(&server_drop_replies);
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let connection_for_close = connection.clone();
                let Ok(mut h3_connection) = h3::server::builder()
                    .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                let mut request_count = 0_u32;
                loop {
                    let resolver = match h3_connection.accept().await {
                        Ok(Some(resolver)) => resolver,
                        Ok(None) | Err(_) => break,
                    };
                    let Ok((request, mut stream)) = resolver.resolve_request().await else {
                        break;
                    };
                    request_count = request_count.saturating_add(1);
                    if request.uri().path() == "/stream-reset-before-headers" {
                        stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                        continue;
                    }
                    if request.uri().path() == "/budget-close" && request_count > 1 {
                        connection_for_close
                            .close(quinn::VarInt::from_u32(3), b"budget second GET closed");
                        break;
                    }

                    if request.uri().path() == "/close" {
                        connection_for_close
                            .close(quinn::VarInt::from_u32(1), b"test transport close");
                        break;
                    }
                    let path = request.uri().path();
                    let status = if matches!(
                        path,
                        "/stage"
                            | "/content-length"
                            | "/content-length-open"
                            | "/incomplete-over-threshold"
                            | "/stream-reset"
                            | "/stream-reset-no-error"
                            | "/stream-reset-after-headers"
                            | "/growth"
                            | "/growth-rto"
                            | "/deadline"
                            | "/refuse"
                            | "/slow"
                            | "/slow-headers"
                            | "/budget-slow"
                            | "/drop"
                            | "/body-close"
                            | "/partial-close"
                            | "/budget-close"
                            | "/no-content"
                            | "/early-refuse"
                            | "/trailers"
                            | "/trailers-open"
                    ) {
                        if matches!(path, "/refuse" | "/early-refuse") {
                            451
                        } else if path == "/no-content" {
                            204
                        } else {
                            200
                        }
                    } else {
                        451
                    };
                    if request.uri().path() == "/slow-headers" {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    let content_length = if path == "/content-length" {
                        "100"
                    } else if path == "/content-length-open" {
                        "2"
                    } else if path == "/incomplete-over-threshold" {
                        "131072"
                    } else {
                        "13"
                    };
                    if path == "/early-refuse"
                        && stream
                            .send_response(http::Response::builder().status(103).body(()).unwrap())
                            .await
                            .is_err()
                    {
                        break;
                    }
                    let response = http::Response::builder().status(status);
                    let response = if path == "/no-content" {
                        response
                    } else {
                        response.header(http::header::CONTENT_LENGTH, content_length)
                    };
                    if stream
                        .send_response(response.body(()).unwrap())
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if path == "/no-content" {
                        if stream.finish().await.is_err() {
                            break;
                        }
                        continue;
                    }
                    if path == "/incomplete-over-threshold" {
                        for _ in 0..8 {
                            if stream
                                .send_data(bytes::Bytes::from(vec![b'x'; 8 * 1024]))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(80)).await;
                        }
                        std::future::pending::<()>().await;
                        break;
                    }
                    if request.uri().path() == "/stream-reset-after-headers" {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                        continue;
                    }
                    if request.uri().path() == "/partial-close" {
                        if stream
                            .send_data(bytes::Bytes::from_static(b"partial"))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        connection_for_close
                            .close(quinn::VarInt::from_u32(4), b"test close after partial body");
                        break;
                    }
                    if request.uri().path() == "/body-close" {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        connection_for_close
                            .close(quinn::VarInt::from_u32(2), b"test close during body");
                        break;
                    }
                    if request.uri().path() == "/slow" {
                        tokio::time::sleep(Duration::from_secs(6)).await;
                    }
                    if request.uri().path() == "/deadline" {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    if request.uri().path() == "/budget-slow" {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    if matches!(request.uri().path(), "/growth" | "/growth-rto") {
                        if stream
                            .send_data(bytes::Bytes::from_static(b"quic-"))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        let pause_ms = if request.uri().path() == "/growth-rto" {
                            1600
                        } else {
                            250
                        };
                        tokio::time::sleep(Duration::from_millis(pause_ms)).await;
                        if stream
                            .send_data(bytes::Bytes::from_static(b"stage-ok"))
                            .await
                            .is_err()
                            || stream.finish().await.is_err()
                        {
                            break;
                        }
                        continue;
                    }
                    if request.uri().path() == "/drop" {
                        if stream
                            .send_data(bytes::Bytes::from_static(b"partial"))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        drop_replies.store(true, Ordering::Release);
                        std::future::pending::<()>().await;
                        break;
                    }
                    if matches!(
                        request.uri().path(),
                        "/stream-reset" | "/stream-reset-no-error"
                    ) {
                        if stream
                            .send_data(bytes::Bytes::from_static(b"partial"))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        let code = if request.uri().path() == "/stream-reset-no-error" {
                            h3::error::Code::H3_NO_ERROR
                        } else {
                            h3::error::Code::H3_INTERNAL_ERROR
                        };
                        stream.stop_stream(code);
                        continue;
                    }
                    if matches!(
                        request.uri().path(),
                        "/content-length" | "/content-length-open"
                    ) {
                        if stream
                            .send_data(bytes::Bytes::from_static(b"ok"))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        if request.uri().path() == "/content-length-open" {
                            std::future::pending::<()>().await;
                            break;
                        }
                        if stream.finish().await.is_err() {
                            break;
                        }
                        continue;
                    }
                    if stream
                        .send_data(bytes::Bytes::from_static(b"quic-stage-ok"))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if matches!(path, "/trailers" | "/trailers-open") {
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("x-r2o", "done".parse().unwrap());
                        if stream.send_trailers(trailers).await.is_err() {
                            break;
                        }
                        if path == "/trailers-open" {
                            std::future::pending::<()>().await;
                            break;
                        }
                        if stream.finish().await.is_err() {
                            break;
                        }
                        continue;
                    }
                    if stream.finish().await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let c_address = server_address;
    let c_binary = d2o_binary.clone();
    let c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(c_binary)
            .args([
                "127.0.0.1",
                &c_address.port().to_string(),
                "localhost",
                "/stage",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        c_output.status.success(),
        "D2O data stage failed: stdout={} stderr={}",
        String::from_utf8_lossy(&c_output.stdout),
        String::from_utf8_lossy(&c_output.stderr)
    );
    let c_result = String::from_utf8(c_output.stdout).unwrap();
    let c_field = |name: &str| {
        c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let rust_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/stage",
        Duration::from_secs(5),
        roots,
    )
    .await;
    let rust_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&rust_result);

    assert!(
        rust_result.handshake_confirmed,
        "R2O result: {rust_result:?}"
    );
    assert_eq!(rust_result.status, 200, "R2O result: {rust_result:?}");
    assert!(rust_result.complete, "R2O result: {rust_result:?}");
    assert_eq!(rust_result.body_bytes, 13, "R2O result: {rust_result:?}");
    assert_eq!(c_field("verdict"), format!("{rust_verdict:?}"));
    assert_eq!(
        c_field("app_bytes").parse::<u64>().unwrap(),
        rust_result.app_bytes,
        "D2O={c_result} R2O={rust_result:?}"
    );
    assert_eq!(
        c_field("requests").parse::<u32>().unwrap(),
        rust_result.requests,
        "D2O={c_result} R2O={rust_result:?}"
    );

    let empty_c_binary = d2o_binary.clone();
    let empty_c_address = server_address;
    let empty_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(empty_c_binary)
            .args([
                "127.0.0.1",
                &empty_c_address.port().to_string(),
                "localhost",
                "/no-content",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        empty_c_output.status.success(),
        "D2O 204 response failed: stdout={} stderr={}",
        String::from_utf8_lossy(&empty_c_output.stdout),
        String::from_utf8_lossy(&empty_c_output.stderr)
    );
    let empty_c_result = String::from_utf8(empty_c_output.stdout).unwrap();
    let empty_c_field = |name: &str| {
        empty_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {empty_c_result}"))
    };

    let empty_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    empty_socket.connect(server_address).unwrap();
    let mut empty_roots = RootCertStore::empty();
    empty_roots.add(certificate_der.clone()).unwrap();
    let empty_rust_result = r2o_quic_http3_get(
        empty_socket,
        server_address,
        "localhost",
        "/no-content",
        Duration::from_secs(5),
        empty_roots,
    )
    .await;
    let empty_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&empty_rust_result);
    assert_eq!(empty_rust_result.status, 204, "R2O={empty_rust_result:?}");
    assert_eq!(empty_rust_result.body_bytes, 0, "R2O={empty_rust_result:?}");
    assert!(empty_rust_result.complete, "R2O={empty_rust_result:?}");
    assert_eq!(empty_c_field("verdict"), format!("{empty_rust_verdict:?}"));
    assert_eq!(empty_c_field("verdict"), "Pass");
    assert_eq!(
        empty_c_field("complete"),
        "1",
        "D2O={empty_c_result} R2O={empty_rust_result:?}"
    );
    assert_eq!(
        empty_c_field("app_bytes").parse::<u64>().unwrap(),
        empty_rust_result.app_bytes,
        "D2O={empty_c_result} R2O={empty_rust_result:?}"
    );
    assert_eq!(
        empty_c_field("requests").parse::<u32>().unwrap(),
        empty_rust_result.requests,
        "D2O={empty_c_result} R2O={empty_rust_result:?}"
    );

    let trailer_c_binary = d2o_binary.clone();
    let trailer_c_address = server_address;
    let trailer_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(trailer_c_binary)
            .args([
                "127.0.0.1",
                &trailer_c_address.port().to_string(),
                "localhost",
                "/trailers",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        trailer_c_output.status.success(),
        "D2O response trailers failed: stdout={} stderr={}",
        String::from_utf8_lossy(&trailer_c_output.stdout),
        String::from_utf8_lossy(&trailer_c_output.stderr)
    );
    let trailer_c_result = String::from_utf8(trailer_c_output.stdout).unwrap();
    let trailer_c_field = |name: &str| {
        trailer_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {trailer_c_result}"))
    };

    let trailer_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    trailer_socket.connect(server_address).unwrap();
    let mut trailer_roots = RootCertStore::empty();
    trailer_roots.add(certificate_der.clone()).unwrap();
    let trailer_rust_result = r2o_quic_http3_get(
        trailer_socket,
        server_address,
        "localhost",
        "/trailers",
        Duration::from_secs(5),
        trailer_roots,
    )
    .await;
    let trailer_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&trailer_rust_result);
    assert_eq!(
        trailer_rust_result.status, 200,
        "R2O={trailer_rust_result:?}"
    );
    assert_eq!(
        trailer_rust_result.body_bytes, 13,
        "R2O={trailer_rust_result:?}"
    );
    assert!(trailer_rust_result.complete, "R2O={trailer_rust_result:?}");
    assert_eq!(
        trailer_c_field("verdict"),
        format!("{trailer_rust_verdict:?}")
    );
    assert_eq!(trailer_c_field("verdict"), "Pass");
    assert_eq!(
        trailer_c_field("complete"),
        "1",
        "D2O={trailer_c_result} R2O={trailer_rust_result:?}"
    );
    assert_eq!(
        trailer_c_field("app_bytes").parse::<u64>().unwrap(),
        trailer_rust_result.app_bytes,
        "D2O={trailer_c_result} R2O={trailer_rust_result:?}"
    );
    assert_eq!(
        trailer_c_field("requests").parse::<u32>().unwrap(),
        trailer_rust_result.requests,
        "D2O={trailer_c_result} R2O={trailer_rust_result:?}"
    );

    let open_trailer_c_binary = d2o_binary.clone();
    let open_trailer_c_address = server_address;
    let open_trailer_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(open_trailer_c_binary)
            .args([
                "127.0.0.1",
                &open_trailer_c_address.port().to_string(),
                "localhost",
                "/trailers-open",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !open_trailer_c_output.status.success(),
        "D2O incomplete response trailers unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&open_trailer_c_output.stdout),
        String::from_utf8_lossy(&open_trailer_c_output.stderr)
    );
    let open_trailer_c_result = String::from_utf8(open_trailer_c_output.stdout).unwrap();
    let open_trailer_c_field = |name: &str| {
        open_trailer_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {open_trailer_c_result}"))
    };
    assert_eq!(open_trailer_c_field("verdict"), "NotRun");
    assert_eq!(open_trailer_c_field("complete"), "0");

    let open_trailer_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    open_trailer_socket.connect(server_address).unwrap();
    let mut open_trailer_roots = RootCertStore::empty();
    open_trailer_roots.add(certificate_der.clone()).unwrap();
    let open_trailer_rust_result = r2o_quic_http3_get(
        open_trailer_socket,
        server_address,
        "localhost",
        "/trailers-open",
        Duration::from_secs(1),
        open_trailer_roots,
    )
    .await;
    let open_trailer_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&open_trailer_rust_result);
    assert_eq!(
        open_trailer_rust_result.status, 200,
        "R2O={open_trailer_rust_result:?}"
    );
    assert_eq!(
        open_trailer_rust_result.body_bytes, 13,
        "R2O={open_trailer_rust_result:?}"
    );
    assert!(
        !open_trailer_rust_result.complete,
        "R2O={open_trailer_rust_result:?}"
    );
    assert_eq!(format!("{open_trailer_rust_verdict:?}"), "NotRun");
    assert_eq!(
        open_trailer_c_field("app_bytes").parse::<u64>().unwrap(),
        open_trailer_rust_result.app_bytes,
        "D2O={open_trailer_c_result} R2O={open_trailer_rust_result:?}"
    );
    assert_eq!(
        open_trailer_c_field("requests").parse::<u32>().unwrap(),
        open_trailer_rust_result.requests,
        "D2O={open_trailer_c_result} R2O={open_trailer_rust_result:?}"
    );

    let early_c_binary = d2o_binary.clone();
    let early_c_address = server_address;
    let early_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(early_c_binary)
            .args([
                "127.0.0.1",
                &early_c_address.port().to_string(),
                "localhost",
                "/early-refuse",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        early_c_output.status.success(),
        "D2O early 103 + 451 failed: stdout={} stderr={}",
        String::from_utf8_lossy(&early_c_output.stdout),
        String::from_utf8_lossy(&early_c_output.stderr)
    );
    let early_c_result = String::from_utf8(early_c_output.stdout).unwrap();
    let early_c_field = |name: &str| {
        early_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {early_c_result}"))
    };

    let early_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    early_socket.connect(server_address).unwrap();
    let mut early_roots = RootCertStore::empty();
    early_roots.add(certificate_der.clone()).unwrap();
    let early_rust_result = r2o_quic_http3_get(
        early_socket,
        server_address,
        "localhost",
        "/early-refuse",
        Duration::from_secs(5),
        early_roots,
    )
    .await;
    let early_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&early_rust_result);
    assert_eq!(early_c_field("verdict"), "Pass");
    assert_eq!(early_rust_result.status, 103, "R2O={early_rust_result:?}");
    assert_eq!(format!("{early_rust_verdict:?}"), "Pass");
    assert!(early_rust_result.complete, "R2O={early_rust_result:?}");
    assert_eq!(
        early_c_field("app_bytes").parse::<u64>().unwrap(),
        early_rust_result.app_bytes,
        "D2O={early_c_result} R2O={early_rust_result:?}"
    );
    assert_eq!(
        early_c_field("requests").parse::<u32>().unwrap(),
        early_rust_result.requests,
        "D2O={early_c_result} R2O={early_rust_result:?}"
    );

    let incomplete_c_binary = d2o_binary.clone();
    let incomplete_c_address = server_address;
    let incomplete_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(incomplete_c_binary)
            .args([
                "127.0.0.1",
                &incomplete_c_address.port().to_string(),
                "localhost",
                "/incomplete-over-threshold",
                "0",
                "1",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        incomplete_c_output.status.success(),
        "D2O failed to pass its live budget on an incomplete response: stdout={} stderr={}",
        String::from_utf8_lossy(&incomplete_c_output.stdout),
        String::from_utf8_lossy(&incomplete_c_output.stderr)
    );
    let incomplete_c_result = String::from_utf8(incomplete_c_output.stdout).unwrap();
    let incomplete_c_field = |name: &str| {
        incomplete_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {incomplete_c_result}"))
    };
    assert_eq!(
        incomplete_c_field("verdict"),
        "Pass",
        "D2O={incomplete_c_result}"
    );
    assert!(
        incomplete_c_field("need_complete") == "1" && incomplete_c_field("complete") == "0",
        "expected an incomplete response with need_complete set: {incomplete_c_result}"
    );
    assert!(
        incomplete_c_field("packets").parse::<u64>().unwrap() >= 50,
        "D2O={incomplete_c_result}"
    );

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let incomplete_rust_result = tokio::time::timeout(
        Duration::from_secs(8),
        r2o_controller::r2o_quic_http3::r2o_quic_http3_short_control_get_with_max_duration(
            socket,
            server_address,
            "localhost",
            "/incomplete-over-threshold",
            Duration::from_secs(1),
            roots,
            Duration::from_secs(8),
        ),
    )
    .await
    .expect("R2O incomplete response test timed out");
    let incomplete_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_short_control_data_verdict(&incomplete_rust_result);
    assert!(
        incomplete_rust_result.handshake_confirmed,
        "R2O={incomplete_rust_result:?}"
    );
    assert_eq!(incomplete_rust_result.status, 200);
    assert!(
        incomplete_rust_result.budget_passed,
        "R2O={incomplete_rust_result:?}"
    );
    assert!(incomplete_rust_result.body_bytes > 32 * 1024);
    assert!(incomplete_rust_result.body_bytes < 131_072);
    assert!(
        !incomplete_rust_result.complete,
        "R2O={incomplete_rust_result:?}"
    );
    assert!(
        !incomplete_rust_result.r2o_quic_stalled,
        "R2O={incomplete_rust_result:?}"
    );
    assert_eq!(
        incomplete_c_field("verdict"),
        format!("{incomplete_rust_verdict:?}"),
        "D2O={incomplete_c_result} R2O={incomplete_rust_result:?}"
    );

    let content_length_binary = d2o_binary.clone();
    let content_length_address = server_address;
    let content_length_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(content_length_binary)
            .args([
                "127.0.0.1",
                &content_length_address.port().to_string(),
                "localhost",
                "/content-length",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        content_length_c_output.status.success(),
        "D2O Content-Length mismatch failed: stdout={} stderr={}",
        String::from_utf8_lossy(&content_length_c_output.stdout),
        String::from_utf8_lossy(&content_length_c_output.stderr)
    );
    let content_length_c_result = String::from_utf8(content_length_c_output.stdout).unwrap();
    let content_length_c_field = |name: &str| {
        content_length_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {content_length_c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let content_length_rust_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/content-length",
        Duration::from_secs(5),
        roots,
    )
    .await;
    let content_length_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&content_length_rust_result);
    assert!(
        content_length_rust_result.handshake_confirmed,
        "R2O Content-Length mismatch: {content_length_rust_result:?}"
    );
    assert_eq!(
        content_length_rust_result.status, 200,
        "R2O Content-Length mismatch: {content_length_rust_result:?}"
    );
    assert_eq!(
        content_length_rust_result.body_bytes, 2,
        "R2O Content-Length mismatch: {content_length_rust_result:?}"
    );
    assert!(
        content_length_rust_result.complete,
        "R2O Content-Length mismatch: {content_length_rust_result:?}"
    );
    assert!(
        content_length_rust_result.error.is_none(),
        "R2O Content-Length mismatch: {content_length_rust_result:?}"
    );
    assert_eq!(
        content_length_c_field("verdict"),
        format!("{content_length_rust_verdict:?}"),
        "D2O={content_length_c_result} R2O={content_length_rust_result:?}"
    );
    assert_eq!(
        content_length_c_field("app_bytes").parse::<u64>().unwrap(),
        content_length_rust_result.app_bytes,
        "D2O={content_length_c_result} R2O={content_length_rust_result:?}"
    );
    assert_eq!(
        content_length_c_field("requests").parse::<u32>().unwrap(),
        content_length_rust_result.requests,
        "D2O={content_length_c_result} R2O={content_length_rust_result:?}"
    );

    let content_length_open_c_binary = d2o_binary.clone();
    let content_length_open_c_address = server_address;
    let content_length_open_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(content_length_open_c_binary)
            .args([
                "127.0.0.1",
                &content_length_open_c_address.port().to_string(),
                "localhost",
                "/content-length-open",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !content_length_open_c_output.status.success(),
        "D2O open Content-Length response unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&content_length_open_c_output.stdout),
        String::from_utf8_lossy(&content_length_open_c_output.stderr)
    );
    let content_length_open_c_result =
        String::from_utf8(content_length_open_c_output.stdout).unwrap();
    let content_length_open_c_field = |name: &str| {
        content_length_open_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| {
                panic!("missing {name} in D2O result: {content_length_open_c_result}")
            })
    };
    assert_eq!(content_length_open_c_field("verdict"), "NotRun");
    assert_eq!(content_length_open_c_field("complete"), "0");

    let content_length_open_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    content_length_open_socket.connect(server_address).unwrap();
    let mut content_length_open_roots = RootCertStore::empty();
    content_length_open_roots
        .add(certificate_der.clone())
        .unwrap();
    let content_length_open_rust_result = r2o_quic_http3_get(
        content_length_open_socket,
        server_address,
        "localhost",
        "/content-length-open",
        Duration::from_secs(1),
        content_length_open_roots,
    )
    .await;
    let content_length_open_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&content_length_open_rust_result);
    assert_eq!(content_length_open_rust_result.status, 200);
    assert_eq!(content_length_open_rust_result.body_bytes, 2);
    assert!(!content_length_open_rust_result.complete);
    assert!(!content_length_open_rust_result.r2o_quic_stalled);
    assert_eq!(format!("{content_length_open_rust_verdict:?}"), "NotRun");
    assert_eq!(
        content_length_open_c_field("app_bytes")
            .parse::<u64>()
            .unwrap(),
        content_length_open_rust_result.app_bytes,
        "D2O={content_length_open_c_result} R2O={content_length_open_rust_result:?}"
    );
    assert_eq!(
        content_length_open_c_field("requests")
            .parse::<u32>()
            .unwrap(),
        content_length_open_rust_result.requests,
        "D2O={content_length_open_c_result} R2O={content_length_open_rust_result:?}"
    );

    let reset_binary = d2o_binary.clone();
    let reset_address = server_address;
    let reset_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(reset_binary)
            .args([
                "127.0.0.1",
                &reset_address.port().to_string(),
                "localhost",
                "/stream-reset",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !reset_c_output.status.success(),
        "D2O stream reset unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&reset_c_output.stdout),
        String::from_utf8_lossy(&reset_c_output.stderr)
    );
    let reset_c_result = String::from_utf8(reset_c_output.stdout).unwrap();
    let reset_c_field = |name: &str| {
        reset_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {reset_c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let reset_rust_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/stream-reset",
        Duration::from_secs(5),
        roots,
    )
    .await;
    let reset_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&reset_rust_result);
    assert!(
        reset_rust_result.handshake_confirmed,
        "R2O stream reset: {reset_rust_result:?}"
    );
    assert_eq!(
        reset_rust_result.status, 200,
        "R2O stream reset: {reset_rust_result:?}"
    );
    assert_eq!(
        reset_rust_result.body_bytes, 7,
        "R2O stream reset: {reset_rust_result:?}"
    );
    assert!(
        !reset_rust_result.complete,
        "R2O stream reset: {reset_rust_result:?}"
    );
    assert!(
        reset_rust_result.error.is_some(),
        "R2O stream reset: {reset_rust_result:?}"
    );
    assert!(
        !reset_rust_result.r2o_quic_stalled,
        "R2O stream reset is an explicit stream error, not a stall: {reset_rust_result:?}"
    );
    assert_eq!(
        reset_c_field("verdict"),
        format!("{reset_rust_verdict:?}"),
        "D2O={reset_c_result} R2O={reset_rust_result:?}"
    );
    assert_eq!(
        reset_c_field("app_bytes").parse::<u64>().unwrap(),
        reset_rust_result.app_bytes,
        "D2O={reset_c_result} R2O={reset_rust_result:?}"
    );
    assert_eq!(
        reset_c_field("requests").parse::<u32>().unwrap(),
        reset_rust_result.requests,
        "D2O={reset_c_result} R2O={reset_rust_result:?}"
    );

    let reset_no_error_binary = d2o_binary.clone();
    let reset_no_error_address = server_address;
    let reset_no_error_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(reset_no_error_binary)
            .args([
                "127.0.0.1",
                &reset_no_error_address.port().to_string(),
                "localhost",
                "/stream-reset-no-error",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !reset_no_error_c_output.status.success(),
        "D2O H3_NO_ERROR reset unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&reset_no_error_c_output.stdout),
        String::from_utf8_lossy(&reset_no_error_c_output.stderr)
    );
    let reset_no_error_c_result = String::from_utf8(reset_no_error_c_output.stdout).unwrap();
    let reset_no_error_c_field = |name: &str| {
        reset_no_error_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {reset_no_error_c_result}"))
    };
    assert_eq!(reset_no_error_c_field("verdict"), "NotRun");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let reset_no_error_rust_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/stream-reset-no-error",
        Duration::from_secs(5),
        roots,
    )
    .await;
    let reset_no_error_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&reset_no_error_rust_result);
    assert_eq!(reset_no_error_rust_result.status, 200);
    assert_eq!(reset_no_error_rust_result.body_bytes, 7);
    assert!(!reset_no_error_rust_result.complete);
    assert_eq!(format!("{reset_no_error_rust_verdict:?}"), "NotRun");
    assert_eq!(
        reset_no_error_c_field("app_bytes").parse::<u64>().unwrap(),
        reset_no_error_rust_result.app_bytes,
        "D2O={reset_no_error_c_result} R2O={reset_no_error_rust_result:?}"
    );
    assert_eq!(
        reset_no_error_c_field("requests").parse::<u32>().unwrap(),
        reset_no_error_rust_result.requests,
        "D2O={reset_no_error_c_result} R2O={reset_no_error_rust_result:?}"
    );

    let headers_reset_binary = d2o_binary.clone();
    let headers_reset_address = server_address;
    let headers_reset_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(headers_reset_binary)
            .args([
                "127.0.0.1",
                &headers_reset_address.port().to_string(),
                "localhost",
                "/stream-reset-before-headers",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !headers_reset_output.status.success(),
        "D2O header reset unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&headers_reset_output.stdout),
        String::from_utf8_lossy(&headers_reset_output.stderr)
    );
    let headers_reset_c_result = String::from_utf8(headers_reset_output.stdout).unwrap();
    let headers_reset_c_field = |name: &str| {
        headers_reset_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {headers_reset_c_result}"))
    };
    assert_eq!(headers_reset_c_field("verdict"), "NotRun");
    assert_eq!(headers_reset_c_field("requests"), "1");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let headers_reset_result = tokio::time::timeout(
        Duration::from_secs(8),
        r2o_quic_http3_get(
            socket,
            server_address,
            "localhost",
            "/stream-reset-before-headers",
            Duration::from_secs(2),
            roots,
        ),
    )
    .await
    .expect("HTTP/3 stream reset before headers timed out");
    let headers_reset_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&headers_reset_result);
    assert!(
        headers_reset_result.handshake_confirmed,
        "R2O header reset: {headers_reset_result:?}"
    );
    assert_eq!(
        headers_reset_result.status, 0,
        "R2O header reset: {headers_reset_result:?}"
    );
    assert!(
        headers_reset_result.error.is_some(),
        "R2O header reset: {headers_reset_result:?}"
    );
    assert!(
        !headers_reset_result.r2o_quic_stalled,
        "H3 RESET_STREAM is not a QUIC transport stall: {headers_reset_result:?}"
    );
    assert_eq!(format!("{headers_reset_verdict:?}"), "NotRun");
    assert_eq!(
        headers_reset_c_field("verdict"),
        format!("{headers_reset_verdict:?}")
    );
    assert_eq!(
        headers_reset_c_field("app_bytes").parse::<u64>().unwrap(),
        headers_reset_result.app_bytes,
        "D2O={headers_reset_c_result} R2O={headers_reset_result:?}"
    );
    assert_eq!(
        headers_reset_c_field("requests").parse::<u32>().unwrap(),
        headers_reset_result.requests,
        "D2O={headers_reset_c_result} R2O={headers_reset_result:?}"
    );

    let response_reset_binary = d2o_binary.clone();
    let response_reset_address = server_address;
    let response_reset_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(response_reset_binary)
            .args([
                "127.0.0.1",
                &response_reset_address.port().to_string(),
                "localhost",
                "/stream-reset-after-headers",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !response_reset_output.status.success(),
        "D2O response reset unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&response_reset_output.stdout),
        String::from_utf8_lossy(&response_reset_output.stderr)
    );
    let response_reset_c_result = String::from_utf8(response_reset_output.stdout).unwrap();
    let response_reset_c_field = |name: &str| {
        response_reset_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {response_reset_c_result}"))
    };
    assert_eq!(response_reset_c_field("verdict"), "NotRun");
    assert_eq!(response_reset_c_field("requests"), "1");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let response_reset_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/stream-reset-after-headers",
        Duration::from_secs(2),
        roots,
    )
    .await;
    let response_reset_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&response_reset_result);
    assert!(
        response_reset_result.handshake_confirmed,
        "R2O response reset: {response_reset_result:?}"
    );
    assert_eq!(
        response_reset_result.status, 200,
        "R2O response reset: {response_reset_result:?}"
    );
    assert_eq!(response_reset_result.body_bytes, 0);
    assert!(!response_reset_result.complete);
    assert!(
        response_reset_result.error.is_some(),
        "R2O response reset: {response_reset_result:?}"
    );
    assert!(
        !response_reset_result.r2o_quic_stalled,
        "H3 RESET_STREAM after HEADERS is not a QUIC transport stall: {response_reset_result:?}"
    );
    assert_eq!(format!("{response_reset_verdict:?}"), "NotRun");
    assert_eq!(
        response_reset_c_field("verdict"),
        format!("{response_reset_verdict:?}")
    );
    assert_eq!(
        response_reset_c_field("app_bytes").parse::<u64>().unwrap(),
        response_reset_result.app_bytes,
        "D2O={response_reset_c_result} R2O={response_reset_result:?}"
    );
    assert_eq!(
        response_reset_c_field("requests").parse::<u32>().unwrap(),
        response_reset_result.requests,
        "D2O={response_reset_c_result} R2O={response_reset_result:?}"
    );

    let repeated_binary = d2o_binary.clone();
    let repeated_address = server_address;
    let repeated_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(repeated_binary)
            .args([
                "127.0.0.1",
                &repeated_address.port().to_string(),
                "localhost",
                "/stage",
                "2",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        repeated_c_output.status.success(),
        "D2O budget replay failed: stdout={} stderr={}",
        String::from_utf8_lossy(&repeated_c_output.stdout),
        String::from_utf8_lossy(&repeated_c_output.stderr)
    );
    let repeated_c_result = String::from_utf8(repeated_c_output.stdout).unwrap();
    let repeated_c_field = |name: &str| {
        repeated_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {repeated_c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let repeated_rust_result = r2o_quic_http3_measure(
        socket,
        server_address,
        "localhost",
        "/stage",
        Duration::from_secs(5),
        roots,
        2,
    )
    .await;
    let repeated_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&repeated_rust_result);

    assert!(
        repeated_rust_result.handshake_confirmed,
        "R2O={repeated_rust_result:?}"
    );
    assert_eq!(
        repeated_rust_result.status, 200,
        "R2O={repeated_rust_result:?}"
    );
    assert!(
        repeated_rust_result.body_bytes > 0,
        "R2O={repeated_rust_result:?}"
    );
    assert!(
        repeated_rust_result.budget_passed,
        "R2O={repeated_rust_result:?}"
    );
    assert_eq!(
        repeated_c_field("verdict"),
        format!("{repeated_rust_verdict:?}")
    );
    assert_eq!(
        repeated_c_field("app_bytes").parse::<u64>().unwrap(),
        repeated_rust_result.app_bytes,
        "D2O={repeated_c_result} R2O={repeated_rust_result:?}"
    );
    assert_eq!(
        repeated_c_field("requests").parse::<u32>().unwrap(),
        repeated_rust_result.requests,
        "D2O={repeated_c_result} R2O={repeated_rust_result:?}"
    );
    assert!(
        repeated_rust_result.requests > 1,
        "budget run did not repeat GET: {repeated_rust_result:?}"
    );

    for (growth_path, pause_ms) in [("/growth", 250), ("/growth-rto", 1600)] {
        let growth_binary = d2o_binary.clone();
        let growth_address = server_address;
        let growth_path_for_c = growth_path.to_owned();
        let growth_c_output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(growth_binary)
                .args([
                    "127.0.0.1",
                    &growth_address.port().to_string(),
                    "localhost",
                    &growth_path_for_c,
                    "2",
                ])
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            growth_c_output.status.success(),
            "D2O {growth_path} replay failed: stdout={} stderr={}",
            String::from_utf8_lossy(&growth_c_output.stdout),
            String::from_utf8_lossy(&growth_c_output.stderr)
        );
        let growth_c_result = String::from_utf8(growth_c_output.stdout).unwrap();
        let growth_c_field = |name: &str| {
            growth_c_result
                .split_whitespace()
                .find_map(|field| field.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("missing {name} in D2O result: {growth_c_result}"))
        };
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(server_address).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der.clone()).unwrap();
        let growth_rust_result = r2o_quic_http3_measure(
            socket,
            server_address,
            "localhost",
            growth_path,
            Duration::from_secs(5),
            roots,
            2,
        )
        .await;
        let growth_rust_verdict =
            r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&growth_rust_result);
        assert!(
            growth_rust_result.handshake_confirmed,
            "{growth_path}: {growth_rust_result:?}"
        );
        assert_eq!(growth_rust_result.status, 200, "{growth_path}");
        assert_eq!(growth_rust_result.body_bytes, 13, "{growth_path}");
        assert!(
            growth_rust_result.budget_passed,
            "{growth_path}: {growth_rust_result:?}"
        );
        assert_eq!(
            growth_c_field("verdict"),
            format!("{growth_rust_verdict:?}"),
            "{growth_path}: D2O={growth_c_result} R2O={growth_rust_result:?}"
        );
        assert_eq!(growth_c_field("verdict"), "Pass", "{growth_path}");
        assert_eq!(
            growth_c_field("app_bytes").parse::<u64>().unwrap(),
            growth_rust_result.app_bytes,
            "{growth_path}: D2O={growth_c_result} R2O={growth_rust_result:?}"
        );
        assert_eq!(
            growth_c_field("requests").parse::<u32>().unwrap(),
            growth_rust_result.requests,
            "{growth_path}: D2O={growth_c_result} R2O={growth_rust_result:?}"
        );
        if pause_ms > 1000 {
            assert!(
                growth_rust_result.r2o_ping_probes > 0,
                "{growth_path} did not cross the RTO to send a PING: {growth_rust_result:?}"
            );
            assert!(
                growth_rust_result.r2o_ping_acks > 0,
                "{growth_path} PING was not acknowledged: {growth_rust_result:?}"
            );
        }
    }

    let stalled_budget_binary = d2o_binary.clone();
    let stalled_budget_address = server_address;
    let stalled_budget_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(stalled_budget_binary)
            .args([
                "127.0.0.1",
                &stalled_budget_address.port().to_string(),
                "localhost",
                "/budget-slow",
                "2",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !stalled_budget_c_output.status.success(),
        "D2O no-growth budget replay unexpectedly passed: {}",
        String::from_utf8_lossy(&stalled_budget_c_output.stdout)
    );
    let stalled_budget_c_result = String::from_utf8(stalled_budget_c_output.stdout).unwrap();
    let stalled_budget_c_field = |name: &str| {
        stalled_budget_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {stalled_budget_c_result}"))
    };
    let packet_need = stalled_budget_c_field("need").parse::<u64>().unwrap();
    let packets_seen = stalled_budget_c_field("packets").parse::<u64>().unwrap();
    assert_eq!(packet_need, 4, "D2O={stalled_budget_c_result}");
    assert!(
        packets_seen >= packet_need,
        "D2O budget threshold not reached: {stalled_budget_c_result}"
    );

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let stalled_budget_rust_result = r2o_quic_http3_measure(
        socket,
        server_address,
        "localhost",
        "/budget-slow",
        Duration::from_secs(1),
        roots,
        2,
    )
    .await;
    let stalled_budget_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&stalled_budget_rust_result);

    assert!(
        stalled_budget_rust_result.handshake_confirmed,
        "R2O={stalled_budget_rust_result:?}"
    );
    assert_eq!(
        stalled_budget_rust_result.status, 200,
        "R2O={stalled_budget_rust_result:?}"
    );
    assert_eq!(
        stalled_budget_rust_result.body_bytes, 0,
        "R2O={stalled_budget_rust_result:?}"
    );
    assert!(
        !stalled_budget_rust_result.complete,
        "R2O={stalled_budget_rust_result:?}"
    );
    assert!(
        stalled_budget_rust_result.budget_required,
        "R2O={stalled_budget_rust_result:?}"
    );
    assert!(
        !stalled_budget_rust_result.budget_passed,
        "R2O={stalled_budget_rust_result:?}"
    );
    assert!(
        !stalled_budget_rust_result.r2o_quic_stalled,
        "live server was classified as stalled: {stalled_budget_rust_result:?}"
    );
    assert_eq!(
        stalled_budget_c_field("verdict"),
        format!("{stalled_budget_rust_verdict:?}"),
        "D2O={stalled_budget_c_result} R2O={stalled_budget_rust_result:?}"
    );
    assert_eq!(stalled_budget_c_field("verdict"), "NotRun");
    assert_eq!(
        stalled_budget_c_field("app_bytes").parse::<u64>().unwrap(),
        stalled_budget_rust_result.app_bytes,
        "D2O={stalled_budget_c_result} R2O={stalled_budget_rust_result:?}"
    );
    assert_eq!(
        stalled_budget_c_field("requests").parse::<u32>().unwrap(),
        stalled_budget_rust_result.requests,
        "D2O={stalled_budget_c_result} R2O={stalled_budget_rust_result:?}"
    );

    let refusal_binary = d2o_binary.clone();
    let refusal_address = server_address;
    let refusal_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(refusal_binary)
            .args([
                "127.0.0.1",
                &refusal_address.port().to_string(),
                "localhost",
                "/refuse",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !refusal_c_output.status.success(),
        "D2O HTTP 451 unexpectedly passed: {}",
        String::from_utf8_lossy(&refusal_c_output.stdout)
    );
    let refusal_c_result = String::from_utf8(refusal_c_output.stdout).unwrap();
    let refusal_c_field = |name: &str| {
        refusal_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {refusal_c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let refusal_rust_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/refuse",
        Duration::from_secs(2),
        roots,
    )
    .await;
    let refusal_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&refusal_rust_result);

    assert!(
        refusal_rust_result.handshake_confirmed,
        "R2O={refusal_rust_result:?}"
    );
    assert_eq!(
        refusal_rust_result.status, 451,
        "R2O={refusal_rust_result:?}"
    );
    assert!(
        !refusal_rust_result.r2o_quic_stalled,
        "HTTP refusal was classified as a stall: {refusal_rust_result:?}"
    );
    assert_eq!(
        refusal_c_field("verdict"),
        format!("{refusal_rust_verdict:?}")
    );
    assert_eq!(refusal_c_field("verdict"), "Cut");
    assert_eq!(
        refusal_c_field("requests").parse::<u32>().unwrap(),
        refusal_rust_result.requests,
        "D2O={refusal_c_result} R2O={refusal_rust_result:?}"
    );

    let delayed_headers_binary = d2o_binary.clone();
    let delayed_headers_address = server_address;
    let delayed_headers_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(delayed_headers_binary)
            .args([
                "127.0.0.1",
                &delayed_headers_address.port().to_string(),
                "localhost",
                "/slow-headers",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !delayed_headers_c_output.status.success(),
        "D2O delayed-header replay unexpectedly passed: {}",
        String::from_utf8_lossy(&delayed_headers_c_output.stdout)
    );
    let delayed_headers_c_result = String::from_utf8(delayed_headers_c_output.stdout).unwrap();
    let delayed_headers_c_field = |name: &str| {
        delayed_headers_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {delayed_headers_c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let delayed_headers_rust_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/slow-headers",
        Duration::from_secs(1),
        roots,
    )
    .await;
    let delayed_headers_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&delayed_headers_rust_result);

    assert!(
        delayed_headers_rust_result.handshake_confirmed,
        "R2O={delayed_headers_rust_result:?}"
    );
    assert_eq!(
        delayed_headers_rust_result.status, 0,
        "R2O={delayed_headers_rust_result:?}"
    );
    assert_eq!(delayed_headers_rust_result.body_bytes, 0);
    assert!(!delayed_headers_rust_result.complete);
    assert!(
        delayed_headers_rust_result.error.is_some(),
        "R2O={delayed_headers_rust_result:?}"
    );
    assert!(
        !delayed_headers_rust_result.r2o_quic_stalled,
        "live transport was classified as stalled: {delayed_headers_rust_result:?}"
    );
    assert_eq!(
        delayed_headers_c_field("verdict"),
        format!("{delayed_headers_rust_verdict:?}"),
        "D2O={delayed_headers_c_result} R2O={delayed_headers_rust_result:?}"
    );
    assert_eq!(delayed_headers_c_field("verdict"), "NotRun");
    assert_eq!(
        delayed_headers_c_field("app_bytes").parse::<u64>().unwrap(),
        delayed_headers_rust_result.app_bytes,
        "D2O={delayed_headers_c_result} R2O={delayed_headers_rust_result:?}"
    );
    assert_eq!(
        delayed_headers_c_field("requests").parse::<u32>().unwrap(),
        delayed_headers_rust_result.requests,
        "D2O={delayed_headers_c_result} R2O={delayed_headers_rust_result:?}"
    );
    assert_eq!(delayed_headers_rust_result.requests, 1);

    let slow_binary = d2o_binary.clone();
    let slow_address = server_address;
    let slow_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(slow_binary)
            .args([
                "127.0.0.1",
                &slow_address.port().to_string(),
                "localhost",
                "/slow",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !slow_c_output.status.success(),
        "D2O delayed-body replay unexpectedly passed: {}",
        String::from_utf8_lossy(&slow_c_output.stdout)
    );
    let slow_c_result = String::from_utf8(slow_c_output.stdout).unwrap();
    let slow_c_field = |name: &str| {
        slow_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {slow_c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let slow_rust_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/slow",
        Duration::from_secs(1),
        roots,
    )
    .await;
    let slow_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&slow_rust_result);

    assert!(
        slow_rust_result.handshake_confirmed,
        "R2O={slow_rust_result:?}"
    );
    assert_eq!(slow_rust_result.status, 200, "R2O={slow_rust_result:?}");
    assert_eq!(slow_rust_result.body_bytes, 0, "R2O={slow_rust_result:?}");
    assert!(!slow_rust_result.complete, "R2O={slow_rust_result:?}");
    assert!(slow_rust_result.error.is_some(), "R2O={slow_rust_result:?}");
    assert!(
        !slow_rust_result.r2o_quic_stalled,
        "live transport was classified as a stall: {slow_rust_result:?}"
    );
    assert_eq!(slow_c_field("verdict"), format!("{slow_rust_verdict:?}"));
    assert_eq!(slow_c_field("verdict"), "NotRun");
    assert_eq!(
        slow_c_field("app_bytes").parse::<u64>().unwrap(),
        slow_rust_result.app_bytes,
        "D2O={slow_c_result} R2O={slow_rust_result:?}"
    );
    assert_eq!(
        slow_c_field("requests").parse::<u32>().unwrap(),
        slow_rust_result.requests,
        "D2O={slow_c_result} R2O={slow_rust_result:?}"
    );

    drop_upstream_replies.store(false, Ordering::Release);
    let (drop_c_proxy_address, drop_c_proxy) = spawn_quic_drop_proxy(
        server_address,
        Arc::new(AtomicBool::new(false)),
        Arc::clone(&drop_upstream_replies),
    )
    .await;
    let drop_c_binary = d2o_binary.clone();
    let drop_c_address = drop_c_proxy_address;
    let drop_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(drop_c_binary)
            .args([
                "127.0.0.1",
                &drop_c_address.port().to_string(),
                "localhost",
                "/drop",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    drop_c_proxy.abort();
    assert!(
        !drop_c_output.status.success(),
        "D2O dropped-reply replay unexpectedly passed: {}",
        String::from_utf8_lossy(&drop_c_output.stdout)
    );
    let drop_c_result = String::from_utf8(drop_c_output.stdout).unwrap();
    let drop_c_field = |name: &str| {
        drop_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {drop_c_result}"))
    };

    drop_upstream_replies.store(false, Ordering::Release);
    let (drop_rust_proxy_address, drop_rust_proxy) = spawn_quic_drop_proxy(
        server_address,
        Arc::new(AtomicBool::new(false)),
        Arc::clone(&drop_upstream_replies),
    )
    .await;
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(drop_rust_proxy_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let drop_rust_result = r2o_quic_http3_get(
        socket,
        drop_rust_proxy_address,
        "localhost",
        "/drop",
        Duration::from_secs(5),
        roots,
    )
    .await;
    drop_rust_proxy.abort();
    let drop_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&drop_rust_result);

    assert!(
        drop_rust_result.handshake_confirmed,
        "R2O={drop_rust_result:?}"
    );
    assert_eq!(drop_rust_result.status, 200, "R2O={drop_rust_result:?}");
    assert!(drop_rust_result.body_bytes > 0, "R2O={drop_rust_result:?}");
    assert!(!drop_rust_result.complete, "R2O={drop_rust_result:?}");
    assert!(
        drop_rust_result.r2o_quic_stalled,
        "dropped replies were not classified as a stall: {drop_rust_result:?}"
    );
    assert_eq!(drop_c_field("verdict"), format!("{drop_rust_verdict:?}"));
    assert_eq!(drop_c_field("verdict"), "Cut");
    assert_eq!(
        drop_c_field("app_bytes").parse::<u64>().unwrap(),
        drop_rust_result.app_bytes,
        "D2O={drop_c_result} R2O={drop_rust_result:?}"
    );
    assert_eq!(
        drop_c_field("requests").parse::<u32>().unwrap(),
        drop_rust_result.requests,
        "D2O={drop_c_result} R2O={drop_rust_result:?}"
    );

    let close_binary = d2o_binary.clone();
    let close_address = server_address;
    let close_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(close_binary)
            .args([
                "127.0.0.1",
                &close_address.port().to_string(),
                "localhost",
                "/close",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !close_c_output.status.success(),
        "D2O transport-close unexpectedly passed: {}",
        String::from_utf8_lossy(&close_c_output.stdout)
    );
    let close_c_result = String::from_utf8(close_c_output.stdout).unwrap();
    let close_c_field = |name: &str| {
        close_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {close_c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let close_rust_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/close",
        Duration::from_secs(2),
        roots,
    )
    .await;
    let close_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&close_rust_result);

    assert!(
        close_rust_result.handshake_confirmed,
        "R2O={close_rust_result:?}"
    );
    assert_eq!(close_rust_result.status, 0, "R2O={close_rust_result:?}");
    assert!(
        close_rust_result.error.is_some(),
        "R2O={close_rust_result:?}"
    );
    assert!(
        !close_rust_result.r2o_quic_stalled,
        "transport close was misclassified as stall: {close_rust_result:?}"
    );
    assert_eq!(close_c_field("verdict"), format!("{close_rust_verdict:?}"));
    assert_eq!(close_c_field("verdict"), "NotRun");
    assert_eq!(
        close_c_field("app_bytes").parse::<u64>().unwrap(),
        close_rust_result.app_bytes,
        "D2O={close_c_result} R2O={close_rust_result:?}"
    );
    assert_eq!(
        close_c_field("requests").parse::<u32>().unwrap(),
        close_rust_result.requests,
        "D2O={close_c_result} R2O={close_rust_result:?}"
    );
    let body_close_binary = d2o_binary.clone();
    let body_close_address = server_address;
    let body_close_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(body_close_binary)
            .args([
                "127.0.0.1",
                &body_close_address.port().to_string(),
                "localhost",
                "/body-close",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !body_close_c_output.status.success(),
        "D2O body-close replay unexpectedly passed: {}",
        String::from_utf8_lossy(&body_close_c_output.stdout)
    );
    let body_close_c_result = String::from_utf8(body_close_c_output.stdout).unwrap();
    let body_close_c_field = |name: &str| {
        body_close_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {body_close_c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let body_close_rust_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/body-close",
        Duration::from_secs(1),
        roots,
    )
    .await;
    let body_close_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&body_close_rust_result);
    assert!(
        body_close_rust_result.handshake_confirmed,
        "R2O={body_close_rust_result:?}"
    );
    assert_eq!(
        body_close_rust_result.status, 200,
        "R2O={body_close_rust_result:?}"
    );
    assert_eq!(
        body_close_rust_result.body_bytes, 0,
        "R2O={body_close_rust_result:?}"
    );
    assert!(
        !body_close_rust_result.complete,
        "R2O={body_close_rust_result:?}"
    );
    assert!(
        body_close_rust_result.error.is_some(),
        "R2O={body_close_rust_result:?}"
    );
    assert!(
        !body_close_rust_result.r2o_quic_stalled,
        "transport close after headers was misclassified as stall: {body_close_rust_result:?}"
    );
    assert_eq!(
        body_close_c_field("verdict"),
        format!("{body_close_rust_verdict:?}"),
        "D2O={body_close_c_result} R2O={body_close_rust_result:?}"
    );
    assert_eq!(body_close_c_field("verdict"), "NotRun");
    assert_eq!(
        body_close_c_field("app_bytes").parse::<u64>().unwrap(),
        body_close_rust_result.app_bytes,
        "D2O={body_close_c_result} R2O={body_close_rust_result:?}"
    );
    assert_eq!(
        body_close_c_field("requests").parse::<u32>().unwrap(),
        body_close_rust_result.requests,
        "D2O={body_close_c_result} R2O={body_close_rust_result:?}"
    );

    let baseline_c_binary = d2o_binary.clone();
    let baseline_c_address = server_address;
    let baseline_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(baseline_c_binary)
            .args([
                "127.0.0.1",
                &baseline_c_address.port().to_string(),
                "localhost",
                "/budget-close",
                "25",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !baseline_c_output.status.success(),
        "D2O repeated baseline unexpectedly passed: {}",
        String::from_utf8_lossy(&baseline_c_output.stdout)
    );
    let baseline_c_result = String::from_utf8(baseline_c_output.stdout).unwrap();
    let baseline_c_field = |name: &str| {
        baseline_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {baseline_c_result}"))
    };
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let baseline_rust_result =
        r2o_controller::r2o_quic_http3::r2o_quic_http3_measure_with_max_duration(
            socket,
            server_address,
            "localhost",
            "/budget-close",
            Duration::from_secs(1),
            roots,
            r2o_controller::r2o_quic_http3::R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS,
            Duration::from_secs(10),
        )
        .await;
    let baseline_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&baseline_rust_result);
    assert!(
        baseline_rust_result.handshake_confirmed,
        "R2O={baseline_rust_result:?}"
    );
    assert!(
        !baseline_rust_result.complete,
        "R2O={baseline_rust_result:?}"
    );
    assert!(
        baseline_rust_result.budget_required,
        "R2O={baseline_rust_result:?}"
    );
    assert!(
        !baseline_rust_result.budget_passed,
        "R2O={baseline_rust_result:?}"
    );
    assert!(
        baseline_rust_result.requests > 1,
        "R2O={baseline_rust_result:?}"
    );
    assert_eq!(
        baseline_c_field("verdict"),
        format!("{baseline_rust_verdict:?}"),
        "D2O={baseline_c_result} R2O={baseline_rust_result:?}"
    );
    assert_eq!(baseline_c_field("verdict"), "NotRun");
    assert_eq!(
        baseline_c_field("app_bytes").parse::<u64>().unwrap(),
        baseline_rust_result.app_bytes,
        "D2O={baseline_c_result} R2O={baseline_rust_result:?}"
    );
    assert_eq!(
        baseline_c_field("requests").parse::<u32>().unwrap(),
        baseline_rust_result.requests,
        "D2O={baseline_c_result} R2O={baseline_rust_result:?}"
    );

    let partial_close_binary = d2o_binary.clone();
    let partial_close_address = server_address;
    let partial_close_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(partial_close_binary)
            .args([
                "127.0.0.1",
                &partial_close_address.port().to_string(),
                "localhost",
                "/partial-close",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !partial_close_c_output.status.success(),
        "D2O partial-body close unexpectedly passed: {}",
        String::from_utf8_lossy(&partial_close_c_output.stdout)
    );
    let partial_close_c_result = String::from_utf8(partial_close_c_output.stdout).unwrap();
    let partial_close_c_field = |name: &str| {
        partial_close_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {partial_close_c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let partial_close_rust_result = r2o_quic_http3_get(
        socket,
        server_address,
        "localhost",
        "/partial-close",
        Duration::from_secs(2),
        roots,
    )
    .await;
    let partial_close_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&partial_close_rust_result);
    assert!(
        partial_close_rust_result.handshake_confirmed,
        "R2O={partial_close_rust_result:?}"
    );
    assert_eq!(
        partial_close_rust_result.status, 200,
        "R2O={partial_close_rust_result:?}"
    );
    assert!(
        partial_close_rust_result.body_bytes > 0,
        "partial DATA was not observed: {partial_close_rust_result:?}"
    );
    assert!(
        !partial_close_rust_result.complete,
        "R2O={partial_close_rust_result:?}"
    );
    assert!(
        partial_close_rust_result.error.is_some(),
        "R2O={partial_close_rust_result:?}"
    );
    assert!(
        !partial_close_rust_result.r2o_quic_stalled,
        "CONNECTION_CLOSE after partial DATA was misclassified as stall: {partial_close_rust_result:?}"
    );
    assert_eq!(
        partial_close_c_field("verdict"),
        format!("{partial_close_rust_verdict:?}"),
        "D2O={partial_close_c_result} R2O={partial_close_rust_result:?}"
    );
    assert_eq!(partial_close_c_field("verdict"), "NotRun");
    assert_eq!(
        partial_close_c_field("app_bytes").parse::<u64>().unwrap(),
        partial_close_rust_result.app_bytes,
        "D2O={partial_close_c_result} R2O={partial_close_rust_result:?}"
    );
    assert_eq!(
        partial_close_c_field("requests").parse::<u32>().unwrap(),
        partial_close_rust_result.requests,
        "D2O={partial_close_c_result} R2O={partial_close_rust_result:?}"
    );

    let deadline_binary = d2o_binary.clone();
    let deadline_address = server_address;
    let deadline_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(deadline_binary)
            .args([
                "127.0.0.1",
                &deadline_address.port().to_string(),
                "localhost",
                "/deadline",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !deadline_c_output.status.success(),
        "D2O deadline case should be NotRun: stdout={} stderr={}",
        String::from_utf8_lossy(&deadline_c_output.stdout),
        String::from_utf8_lossy(&deadline_c_output.stderr)
    );
    let deadline_c_result = String::from_utf8(deadline_c_output.stdout).unwrap();
    let deadline_c_field = |name: &str| {
        deadline_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {deadline_c_result}"))
    };
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let rust_deadline_result = r2o_quic_http3_get_with_max_duration(
        socket,
        server_address,
        "localhost",
        "/deadline",
        Duration::from_secs(5),
        roots,
        Duration::from_secs(4),
    )
    .await;
    let rust_deadline_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&rust_deadline_result);
    assert_eq!(
        deadline_c_field("verdict"),
        format!("{rust_deadline_verdict:?}")
    );
    assert_eq!(deadline_c_field("verdict"), "NotRun");
    assert_eq!(
        rust_deadline_result.status, 200,
        "R2O={rust_deadline_result:?}"
    );
    assert_eq!(
        rust_deadline_result.body_bytes, 0,
        "R2O={rust_deadline_result:?}"
    );
    assert!(
        rust_deadline_result.error.is_some(),
        "R2O={rust_deadline_result:?}"
    );
    assert_eq!(
        deadline_c_field("app_bytes").parse::<u64>().unwrap(),
        rust_deadline_result.app_bytes,
        "D2O={deadline_c_result} R2O={rust_deadline_result:?}"
    );
    assert_eq!(
        deadline_c_field("requests").parse::<u32>().unwrap(),
        rust_deadline_result.requests,
        "D2O={deadline_c_result} R2O={rust_deadline_result:?}"
    );

    server.abort();
}

#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_goaway_repeated_request_matches_d2o() {
    let d2o_binary = std::env::var("D2O_QUIC_DATA_STAGE_BIN")
        .expect("D2O_QUIC_DATA_STAGE_BIN must point to the pinned C data-stage harness");
    let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    let certificate = rcgen::Certificate::from_params(certificate_params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        while let Some(incoming) = server_endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let Ok(mut h3_connection) = h3::server::builder()
                    .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                let Ok(Some(resolver)) = h3_connection.accept().await else {
                    return;
                };
                let Ok((request, mut stream)) = resolver.resolve_request().await else {
                    return;
                };
                let path = request.uri().path();
                if !matches!(path, "/goaway" | "/reset-second-stream") {
                    return;
                }
                if stream
                    .send_response(
                        http::Response::builder()
                            .status(200)
                            .header(http::header::CONTENT_LENGTH, "15")
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .is_err()
                {
                    return;
                }
                // Graceful shutdown allows stream 0 but rejects the next client stream.
                if (path == "/goaway" && h3_connection.shutdown(0).await.is_err())
                    || stream
                        .send_data(bytes::Bytes::from_static(b"goaway-response"))
                        .await
                        .is_err()
                    || stream.finish().await.is_err()
                {
                    return;
                }
                if path == "/reset-second-stream" {
                    let Ok(Some(resolver)) = h3_connection.accept().await else {
                        return;
                    };
                    let Ok((request, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    if request.uri().path() != path {
                        return;
                    }
                    stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            });
        }
    });

    let c_address = server_address;
    let c_binary = d2o_binary.clone();
    let c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(c_binary)
            .args([
                "127.0.0.1",
                &c_address.port().to_string(),
                "localhost",
                "/goaway",
                "25",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let c_result = String::from_utf8(c_output.stdout).unwrap();
    let c_field = |name: &str| {
        c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {c_result}"))
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    assert_eq!(c_field("verdict"), "NotRun");
    assert_eq!(c_field("requests"), "2");

    let rust_result = r2o_controller::r2o_quic_http3::r2o_quic_http3_measure_with_max_duration(
        socket,
        server_address,
        "localhost",
        "/goaway",
        Duration::from_secs(1),
        roots,
        r2o_controller::r2o_quic_http3::R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS,
        Duration::from_secs(10),
    )
    .await;
    let rust_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&rust_result);

    assert_eq!(
        c_field("verdict"),
        format!("{rust_verdict:?}"),
        "D2O={c_result} R2O={rust_result:?}"
    );
    assert_eq!(
        c_field("app_bytes").parse::<u64>().unwrap(),
        rust_result.app_bytes,
        "D2O={c_result} R2O={rust_result:?}"
    );
    assert_eq!(
        c_field("requests").parse::<u32>().unwrap(),
        rust_result.requests,
        "D2O={c_result} R2O={rust_result:?}"
    );

    let reset_c_binary = d2o_binary.clone();
    let reset_c_address = server_address;
    let reset_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(reset_c_binary)
            .args([
                "127.0.0.1",
                &reset_c_address.port().to_string(),
                "localhost",
                "/reset-second-stream",
                "25",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let reset_c_result = String::from_utf8(reset_c_output.stdout).unwrap();
    let reset_c_field = |name: &str| {
        reset_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {reset_c_result}"))
    };
    assert_eq!(reset_c_field("verdict"), "NotRun", "D2O={reset_c_result}");
    assert_eq!(reset_c_field("requests"), "2", "D2O={reset_c_result}");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let reset_rust_result =
        r2o_controller::r2o_quic_http3::r2o_quic_http3_measure_with_max_duration(
            socket,
            server_address,
            "localhost",
            "/reset-second-stream",
            Duration::from_secs(1),
            roots,
            r2o_controller::r2o_quic_http3::R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS,
            Duration::from_secs(10),
        )
        .await;
    let reset_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&reset_rust_result);
    assert!(
        reset_rust_result.handshake_confirmed,
        "R2O={reset_rust_result:?}"
    );
    assert_eq!(reset_rust_result.status, 0, "R2O={reset_rust_result:?}");
    assert!(!reset_rust_result.complete, "R2O={reset_rust_result:?}");
    assert_eq!(
        reset_c_field("verdict"),
        format!("{reset_rust_verdict:?}"),
        "D2O={reset_c_result} R2O={reset_rust_result:?}"
    );
    assert_eq!(
        reset_c_field("app_bytes").parse::<u64>().unwrap(),
        reset_rust_result.app_bytes,
        "D2O={reset_c_result} R2O={reset_rust_result:?}"
    );
    assert_eq!(
        reset_c_field("requests").parse::<u32>().unwrap(),
        reset_rust_result.requests,
        "D2O={reset_c_result} R2O={reset_rust_result:?}"
    );

    server.abort();
}
#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_bidi_stream_limits_count_attempt_like_d2o() {
    let d2o_binary = std::env::var("D2O_QUIC_DATA_STAGE_BIN")
        .expect("D2O_QUIC_DATA_STAGE_BIN must point to the pinned C data-stage harness");
    let repeated_d2o_binary = d2o_binary.clone();
    let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
    let certificate = rcgen::Certificate::from_params(certificate_params).unwrap();
    let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(0));
    server_config.transport_config(Arc::new(transport));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        while let Some(incoming) = server_endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let Ok(mut h3_connection) = h3::server::builder()
                    .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                let _ = h3_connection.accept().await;
            });
        }
    });

    let c_address = server_address;
    let c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(d2o_binary)
            .args([
                "127.0.0.1",
                &c_address.port().to_string(),
                "localhost",
                "/stream-limit",
                "0",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!c_output.status.success());
    let c_result = String::from_utf8(c_output.stdout).unwrap();
    let c_field = |name: &str| {
        c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {c_result}"))
    };
    assert_eq!(c_field("verdict"), "NotRun", "D2O={c_result}");
    assert_eq!(c_field("app_bytes"), "0", "D2O={c_result}");
    assert_eq!(c_field("requests"), "1", "D2O={c_result}");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der.clone()).unwrap();
    let rust_result = tokio::time::timeout(
        Duration::from_secs(8),
        r2o_quic_http3_get(
            socket,
            server_address,
            "localhost",
            "/stream-limit",
            Duration::from_secs(1),
            roots,
        ),
    )
    .await
    .expect("R2O timed out opening a stream under the server limit");
    let rust_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&rust_result);

    assert!(rust_result.handshake_confirmed, "R2O={rust_result:?}");
    assert_eq!(rust_result.status, 0, "R2O={rust_result:?}");
    assert!(!rust_result.complete, "R2O={rust_result:?}");
    assert_eq!(format!("{rust_verdict:?}"), c_field("verdict"));
    assert_eq!(
        rust_result.app_bytes,
        c_field("app_bytes").parse::<u64>().unwrap()
    );
    // Quinn treats a missing initial_max_streams_bidi as zero and waits for
    // stream credit; still count the attempted GET without opening stream 0.
    assert_eq!(rust_result.requests, 1, "R2O={rust_result:?}");
    assert_eq!(
        c_field("requests"),
        rust_result.requests.to_string(),
        "D2O={c_result} R2O={rust_result:?}"
    );

    server.abort();

    let repeat_private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut repeat_tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], repeat_private_key)
        .unwrap();
    repeat_tls.alpn_protocols = vec![b"h3".to_vec()];
    let repeat_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(repeat_tls).unwrap();
    let mut repeat_config = quinn::ServerConfig::with_crypto(Arc::new(repeat_crypto));
    let mut repeat_transport = quinn::TransportConfig::default();
    repeat_transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1));
    repeat_config.transport_config(Arc::new(repeat_transport));
    let repeat_endpoint =
        quinn::Endpoint::server(repeat_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let repeat_address = repeat_endpoint.local_addr().unwrap();
    let repeat_server = tokio::spawn(async move {
        while let Some(incoming) = repeat_endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let Ok(mut h3_connection) = h3::server::builder()
                    .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                let Ok(Some(resolver)) = h3_connection.accept().await else {
                    return;
                };
                let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                    return;
                };
                if stream
                    .send_response(http::Response::builder().status(200).body(()).unwrap())
                    .await
                    .is_err()
                    || stream
                        .send_data(bytes::Bytes::from_static(b"ok"))
                        .await
                        .is_err()
                    || stream.finish().await.is_err()
                {
                    return;
                }
                let _ = h3_connection.accept().await;
            });
        }
    });

    let repeat_c_address = repeat_address;
    let repeat_c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(repeated_d2o_binary)
            .args([
                "127.0.0.1",
                &repeat_c_address.port().to_string(),
                "localhost",
                "/repeat-stream-limit",
                "25",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!repeat_c_output.status.success());
    let repeat_c_result = String::from_utf8(repeat_c_output.stdout).unwrap();
    let repeat_c_field = |name: &str| {
        repeat_c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {repeat_c_result}"))
    };
    assert_eq!(repeat_c_field("verdict"), "NotRun", "D2O={repeat_c_result}");
    assert_eq!(repeat_c_field("requests"), "1", "D2O={repeat_c_result}");

    let repeat_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    repeat_socket.connect(repeat_address).unwrap();
    let mut repeat_roots = RootCertStore::empty();
    repeat_roots.add(certificate_der).unwrap();
    let repeat_rust_result = tokio::time::timeout(
        Duration::from_secs(8),
        r2o_quic_http3_measure(
            repeat_socket,
            repeat_address,
            "localhost",
            "/repeat-stream-limit",
            Duration::from_secs(1),
            repeat_roots,
            25,
        ),
    )
    .await
    .expect("R2O repeated GET exceeded the bounded stream-credit timeout");
    let repeat_rust_verdict =
        r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&repeat_rust_result);
    assert_eq!(
        format!("{repeat_rust_verdict:?}"),
        repeat_c_field("verdict")
    );
    // D2O double-counts the prior stream when its next raw send is rejected.
    assert_eq!(
        repeat_rust_result.app_bytes,
        repeat_c_field("app_bytes").parse::<u64>().unwrap(),
        "D2O={repeat_c_result} R2O={repeat_rust_result:?}"
    );
    assert_eq!(repeat_rust_result.requests, 1, "R2O={repeat_rust_result:?}");
    assert_eq!(
        repeat_rust_result.requests.to_string(),
        repeat_c_field("requests"),
        "D2O={repeat_c_result} R2O={repeat_rust_result:?}"
    );

    repeat_server.abort();
}

async fn assert_quic_no_handshake_matches_d2o(
    address: SocketAddr,
    peer_description: &str,
    diff_output: &str,
) {
    let d2o_binary = std::env::var("D2O_QUIC_DATA_STAGE_BIN")
        .expect("D2O_QUIC_DATA_STAGE_BIN must point to the pinned C data-stage harness");
    let port = address.port().to_string();
    let c_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(d2o_binary)
            .args(["127.0.0.1", &port, "localhost", "/", "0"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !c_output.status.success(),
        "D2O unexpectedly completed a handshake with {peer_description}: stdout={} stderr={}",
        String::from_utf8_lossy(&c_output.stdout),
        String::from_utf8_lossy(&c_output.stderr)
    );
    let c_result = String::from_utf8(c_output.stdout).unwrap();
    let c_field = |name: &str| {
        c_result
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing {name} in D2O result: {c_result}"))
    };
    assert_eq!(c_field("verdict"), "NoHandshake", "D2O={c_result}");
    assert_eq!(c_field("app_bytes"), "0", "D2O={c_result}");
    assert_eq!(c_field("requests"), "0", "D2O={c_result}");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(address).unwrap();
    let rust_result = tokio::time::timeout(
        Duration::from_secs(4),
        r2o_quic_http3_get(
            socket,
            address,
            "localhost",
            "/",
            Duration::from_secs(2),
            RootCertStore::empty(),
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("HTTP/3 {peer_description} test timed out"));
    assert!(!rust_result.handshake_confirmed, "R2O={rust_result:?}");
    assert_eq!(rust_result.status, 0, "R2O={rust_result:?}");
    let verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&rust_result);
    assert_eq!(
        format!("{verdict:?}"),
        c_field("verdict"),
        "D2O={c_result} R2O={rust_result:?}"
    );
    assert_eq!(
        rust_result.app_bytes,
        c_field("app_bytes").parse::<u64>().unwrap()
    );
    assert_eq!(
        rust_result.requests,
        c_field("requests").parse::<u32>().unwrap()
    );
    write_d2o_http3_differential(diff_output, peer_description, &rust_result);
}

#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_udp_port_unreachable_matches_d2o() {
    let closed_port = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = closed_port.local_addr().unwrap();
    drop(closed_port);
    assert_quic_no_handshake_matches_d2o(
        address,
        "port-unreachable",
        "R2O_QUIC_HTTP3_PORT_UNREACHABLE_DIFF_OUTPUT",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires the pinned D2O harness; run scripts/test-quic-http3-full-stage-differential.sh"]
async fn r2o_http3_silent_udp_peer_timeout_matches_d2o() {
    let silent_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = silent_peer.local_addr().unwrap();
    assert_quic_no_handshake_matches_d2o(
        address,
        "silent-peer-timeout",
        "R2O_QUIC_HTTP3_SILENT_PEER_DIFF_OUTPUT",
    )
    .await;
    drop(silent_peer);
}
