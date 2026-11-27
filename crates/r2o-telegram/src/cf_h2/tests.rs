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
async fn media_post_по_tls_h2_проверяет_nonce_ошибку_http_и_параллельную_загрузку() {
    const MEDIA_BLOCK: usize = 128 * 1024;
    let ready_to_send = Arc::new(tokio::sync::Barrier::new(MAX_REQUESTS));
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
            let ready_to_send = Arc::clone(&ready_to_send);
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
                } else if number == 2 {
                    let head = http::Response::builder().status(503).body(()).unwrap();
                    reply.send_response(head, true).unwrap();
                } else if data == [0x54; 40] {
                    let head = http::Response::builder().status(404).body(()).unwrap();
                    reply.send_response(head, true).unwrap();
                } else if data == [0x51; 40] {
                    tokio::time::sleep(RESPONSE_IDLE_TIMEOUT * 2).await;
                    drop(reply);
                } else if data == [0x52; 40] || data == [0x53; 40] {
                    let mut stream = reply.send_response(http::Response::new(()), false).unwrap();
                    stream.send_data(Bytes::from_static(b"abc"), false).unwrap();
                    if data == [0x53; 40] {
                        let gap = RESPONSE_IDLE_TIMEOUT / 2 + Duration::from_millis(100);
                        tokio::time::sleep(gap).await;
                        stream.send_data(Bytes::from_static(b"def"), false).unwrap();
                        tokio::time::sleep(gap).await;
                        stream.send_data(Bytes::from_static(b"ghi"), true).unwrap();
                    } else {
                        tokio::time::sleep(RESPONSE_IDLE_TIMEOUT * 2).await;
                        drop(stream);
                    }
                } else {
                    let head = http::Response::builder()
                        .header("content-length", MEDIA_BLOCK)
                        .body(())
                        .unwrap();
                    let mut stream = reply.send_response(head, false).unwrap();
                    stream.reserve_capacity(MEDIA_BLOCK);
                    poll_fn(|cx| stream.poll_capacity(cx))
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(
                        stream.capacity() >= MEDIA_BLOCK,
                        "окно {} меньше блока медиа {MEDIA_BLOCK}",
                        stream.capacity()
                    );
                    // Ни один запрос не отправляет DATA, пока все три не получили кредит.
                    ready_to_send.wait().await;
                    stream
                        .send_data(Bytes::from(vec![0xa5; MEDIA_BLOCK]), true)
                        .unwrap();
                }
            });
        }
    });
    let budget = Arc::new(MemoryBudget::new(WINDOW * 2 + MEDIA_BLOCK * MAX_REQUESTS));
    let buffers = Some(Arc::clone(&budget));
    let permit = CONNECTIONS.try_acquire().unwrap();
    let window = reserve_media_window(&buffers).unwrap();
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
    let missing = client
        .post(Bytes::from_static(&[0x54; 40]), 1024)
        .await
        .err()
        .unwrap();
    assert_eq!(missing.http_status, Some(404));
    assert!(missing.is_upstream_failure());
    let packet = Bytes::from_static(&[0; 40]);
    let replies = tokio::time::timeout(
        SETUP_TIMEOUT,
        futures_util::future::try_join_all(
            (0..MAX_REQUESTS).map(|_| client.post(packet.clone(), MEDIA_BLOCK)),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(budget.used(), WINDOW * 2 + MEDIA_BLOCK * MAX_REQUESTS);
    for reply in replies {
        assert_eq!(reply.bytes, vec![0xa5; MEDIA_BLOCK]);
    }
    let (headers, body, advancing) = tokio::time::timeout(RESPONSE_IDLE_TIMEOUT * 2, async {
        tokio::join!(
            client.post(Bytes::from_static(&[0x51; 40]), 1024),
            client.post(Bytes::from_static(&[0x52; 40]), 1024),
            client.post(Bytes::from_static(&[0x53; 40]), 1024),
        )
    })
    .await
    .unwrap();
    assert_eq!(
        headers.err().unwrap().reason,
        "тайм-аут заголовков POST /api"
    );
    assert_eq!(
        body.err().unwrap().reason,
        "тайм-аут передачи тела POST /api"
    );
    assert_eq!(advancing.unwrap().bytes, b"abcdefghi");
    assert_eq!(budget.used(), WINDOW * 2);
    drop(client);
    tokio::time::timeout(SETUP_TIMEOUT, async {
        while budget.used() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("отменённый HTTP/2 driver должен освободить память и сокет");
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn h2_после_сбоя_разрешает_одну_живую_проверку_и_наращивает_паузу() {
    let zone = "h2-recovery.example";
    let mut first = LiveRoute::admit(5).unwrap();
    assert!(LiveRoute::admit(5).is_none());
    assert!(LiveRoute::admit(3).is_some());

    first.failed(zone);
    assert!(cooling(5, zone));
    clear_cooldown(5, zone);
    first.confirmed();
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(LiveRoute::admit(5).is_none());

    tokio::time::advance(WS_FALLBACK_DELAY - Duration::from_secs(10)).await;
    let second = LiveRoute::admit(5).unwrap();
    assert!(LiveRoute::admit(5).is_none());
    second.failed(zone);
    tokio::time::advance(WS_FALLBACK_DELAY).await;
    assert!(LiveRoute::admit(5).is_none());

    tokio::time::advance(WS_FALLBACK_DELAY).await;
    let mut recovered = LiveRoute::admit(5).unwrap();
    assert!(LiveRoute::admit(5).is_none());
    recovered.confirmed();
    let concurrent = LiveRoute::admit(5).unwrap();
    second.failed(zone);
    assert!(LiveRoute::admit(5).is_some());

    concurrent.failed(zone);
    assert!(LiveRoute::admit(5).is_none());
    tokio::time::advance(WS_FALLBACK_DELAY).await;
    assert!(LiveRoute::admit(5).is_some());
    clear_cooldown(5, zone);
}

#[tokio::test(start_paused = true)]
async fn h2_отключение_клиента_не_оставляет_постоянную_паузу() {
    let cancelled = LiveRoute::admit(4).unwrap();
    drop(cancelled);
    assert!(LiveRoute::admit(4).is_none());
    tokio::time::advance(CANCELLED_TRIAL_DELAY).await;
    let idle = LiveRoute::admit(4).unwrap();
    assert!(LiveRoute::admit(4).is_none());
    tokio::time::advance(TRIAL_LEASE).await;
    let current = LiveRoute::admit(4).unwrap();
    drop(idle);
    tokio::time::advance(CANCELLED_TRIAL_DELAY).await;
    assert!(LiveRoute::admit(4).is_none());
    drop(current);
}

#[test]
fn media_выбирает_малое_окно_при_нехватке_памяти() {
    let budget = Arc::new(MemoryBudget::new(SMALL_WINDOW * 2));
    let buffers = Some(Arc::clone(&budget));
    let (window, reservation) = reserve_media_window(&buffers).unwrap();
    assert_eq!(window, SMALL_WINDOW);
    assert_eq!(budget.used(), SMALL_WINDOW * 2);
    assert!(reserve_media_window(&buffers).is_err());
    drop(reservation);
    assert_eq!(budget.used(), 0);
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
