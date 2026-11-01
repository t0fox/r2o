use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
async fn r2o_http3_udp_reply_drop_is_a_stall_and_matches_d2o() {
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
    let drop_after_headers = Arc::clone(&drop_replies);
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
        drop_after_headers.store(true, Ordering::SeqCst);
        let _ = shutdown_receiver.await;
    });

    let proxy_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy_socket.local_addr().unwrap();
    let proxy_drop_replies = Arc::clone(&drop_replies);
    let (proxy_stop_sender, mut proxy_stop_receiver) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(async move {
        let mut client_address = None;
        let mut packet = vec![0_u8; 65_536];
        loop {
            tokio::select! {
                _ = &mut proxy_stop_receiver => break,
                received = proxy_socket.recv_from(&mut packet) => {
                    let Ok((length, peer)) = received else { break };
                    if peer == server_address {
                        if !proxy_drop_replies.load(Ordering::SeqCst) {
                            if let Some(client) = client_address {
                                let _ = proxy_socket.send_to(&packet[..length], client).await;
                            }
                        }
                    } else {
                        client_address = Some(peer);
                        let _ = proxy_socket.send_to(&packet[..length], server_address).await;
                    }
                }
            }
        }
    });

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(proxy_address).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        r2o_quic_http3_get_with_max_duration(
            socket,
            proxy_address,
            "localhost",
            "/",
            Duration::from_secs(1),
            roots,
            Duration::from_secs(6),
        ),
    )
    .await
    .expect("HTTP/3 UDP-drop test timed out");

    assert!(result.handshake_confirmed, "result: {result:?}");
    assert_eq!(result.status, 200, "result: {result:?}");
    assert!(result.r2o_quic_stalled, "result: {result:?}");
    assert!(!result.r2o_quic_one_way, "result: {result:?}");
    assert!(result.r2o_ping_probes >= 2, "result: {result:?}");
    assert_eq!(
        format!(
            "{:?}",
            r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&result)
        ),
        "Cut"
    );
    write_d2o_http3_differential("R2O_QUIC_HTTP3_STALL_DIFF_OUTPUT", "stall", &result);
    let _ = shutdown_sender.send(());
    let _ = proxy_stop_sender.send(());
    server.abort();
    proxy.abort();
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
async fn r2o_http3_full_data_stage_matches_d2o_on_complete_response() {
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
                loop {
                    let resolver = match h3_connection.accept().await {
                        Ok(Some(resolver)) => resolver,
                        Ok(None) | Err(_) => break,
                    };
                    let Ok((request, mut stream)) = resolver.resolve_request().await else {
                        break;
                    };
                    let status = if request.uri().path() == "/stage" {
                        200
                    } else {
                        451
                    };
                    if stream
                        .send_response(
                            http::Response::builder()
                                .status(status)
                                .header(http::header::CONTENT_LENGTH, "13")
                                .body(())
                                .unwrap(),
                        )
                        .await
                        .is_err()
                        || stream
                            .send_data(bytes::Bytes::from_static(b"quic-stage-ok"))
                            .await
                            .is_err()
                        || stream.finish().await.is_err()
                    {
                        break;
                    }
                }
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
                "/stage",
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
    roots.add(certificate_der).unwrap();
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
    server.abort();
}
