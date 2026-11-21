use super::*;
use grammers_tl_types::Serializable;
use tokio::net::TcpListener;

fn response_for(request: &[u8]) -> Bytes {
    let nonce = request[24..40].try_into().unwrap();
    let packet = grammers_tl_types::enums::ResPq::Pq(grammers_tl_types::types::ResPq {
        nonce,
        server_nonce: [1; 16],
        pq: vec![0x11, 0x22],
        server_public_key_fingerprints: vec![1],
    })
    .to_bytes();
    let mut bytes = vec![0; 8];
    bytes.extend_from_slice(&1_i64.to_le_bytes());
    bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&packet);
    Bytes::from(bytes)
}

#[tokio::test]
async fn media_post_по_tls_h2_проверяет_nonce_и_возвращает_ошибку_http() {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["zone.example".into()]).unwrap();
    let der = rustls_pki_types::CertificateDer::from(cert.serialize_der().unwrap());
    let key = rustls_pki_types::PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key.into())
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            .accept(tcp)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some("zone.example"));
        let mut conn = h2::server::handshake(tls).await.unwrap();
        let mut number = 0;
        while let Some(request) = conn.accept().await {
            let (request, mut reply) = request.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/api");
            assert_eq!(request.uri().authority().unwrap(), "kws4.zone.example");
            number += 1;
            tokio::spawn(async move {
                let mut body = request.into_body();
                let mut data = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                    data.extend_from_slice(&chunk);
                }
                if number == 1 {
                    let response = response_for(&data);
                    let head = http::Response::builder()
                        .header("content-length", response.len())
                        .body(())
                        .unwrap();
                    let mut stream = reply.send_response(head, false).unwrap();
                    stream.send_data(response, true).unwrap();
                } else {
                    let head = http::Response::builder().status(503).body(()).unwrap();
                    reply.send_response(head, true).unwrap();
                }
            });
        }
    });
    let budget = Arc::new(MemoryBudget::new(256 * 1024));
    let buffers = Some(Arc::clone(&budget));
    let permit = CONNECTIONS.try_acquire().unwrap();
    let window = reserve(&buffers, WINDOW * 2).unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (client, _) = open(
        tcp,
        "kws4.zone.example",
        "zone.example",
        tokio::time::Instant::now() + SETUP_TIMEOUT,
        buffers,
        permit,
        window,
        Arc::new(client_config),
    )
    .await
    .unwrap();
    assert_eq!(budget.used(), WINDOW * 2);
    let result = tokio::time::timeout(
        SETUP_TIMEOUT,
        client.post(Bytes::from_static(&[0; 40]), 1024),
    )
    .await
    .unwrap();
    assert_eq!(result.err().unwrap().http_status, Some(503));
    let zone = "h2-recovery.example";
    use_ws_fallback(4, zone);
    assert!(falling_back(4));
    assert!(!falling_back(2));
    WS_FALLBACK.clear(&4);
    clear_cooldown(4, zone);
    drop(client);
    assert_eq!(budget.used(), 0);
    server.abort();
}

#[tokio::test]
async fn читает_и_восстанавливает_кадрирование_media() {
    for proto in [
        ProtoTag::Abridged,
        ProtoTag::Intermediate,
        ProtoTag::PaddedIntermediate,
    ] {
        let key = [0x55; 32];
        let iv = [0x23; 16];
        let mut body = vec![0x55; 600];
        let mut input = response_header(body.len(), proto);
        input.append(&mut body);
        crate::crypto::make_cipher(&key, &iv).apply_keystream(&mut input);
        let mut cipher = crate::crypto::make_cipher(&key, &iv);
        let budget = Arc::new(MemoryBudget::new(1024));
        let (payload, memory) = read_packet(
            &mut input.as_slice(),
            &mut cipher,
            proto,
            &Some(Arc::clone(&budget)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(payload.as_ref(), &[0x55; 600]);
        assert_eq!(budget.used(), 600);
        drop(memory);
        assert_eq!(budget.used(), 0);
    }
}
