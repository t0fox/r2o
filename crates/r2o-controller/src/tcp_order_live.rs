use super::*;
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[test]
#[ignore = "root and NFQUEUE fixture: scripts/test-tcp-order-nfq.sh"]
fn tcp_order_nfq_lifecycle() {
    let mode = std::env::var("R2O_ORDER_TEST_PHASE").unwrap();
    let dir = PathBuf::from(std::env::var_os("R2O_ORDER_TEST_DIR").unwrap());
    let socket = dir.join("dp.sock");
    let path = dir.join("catalog.json");
    let target = r2o_controller::discovery::DiscoveryTarget {
        host: "order.example".into(),
        endpoint: "198.51.100.2:18443".into(),
        family: 4,
        shape: SHAPE_MODERN,
        tcp_profile: control::TCP_PROFILE_TS,
    };
    if mode == "prepare" {
        for _ in 0..16 {
            let mut tls = r2o_controller::r2o_tls::r2o_tls_client_connection(
                &target.host,
                false,
                Some(640),
                rustls::RootCertStore::empty(),
            )
            .unwrap();
            let mut hello = Vec::new();
            tls.write_tls(&mut hello).unwrap();
            let sni = r2k_core::tls::complete_sni(&hello).unwrap();
            if sni.end < hello.len() {
                std::fs::write(dir.join("hello"), hello).unwrap();
                std::fs::write(
                    dir.join("ranges"),
                    format!("{} {}\n", sni.start + 1, sni.end),
                )
                .unwrap();
                return;
            }
        }
        panic!("fixture could not prepare a measurable ClientHello");
    }
    let hello = std::fs::read(dir.join("hello")).unwrap();
    let sni = r2k_core::tls::complete_sni(&hello).unwrap();
    if mode == "reuse" {
        let catalog = Catalog::load(&path).unwrap();
        let saved = catalog
            .boxes
            .iter()
            .find(|record| record.bindings.iter().any(|b| b.kind == "tcpord"))
            .unwrap();
        assert_eq!(saved.bindings[0].port, 18443);
        assert!(saved.plans[0].text.contains("order 1,3,2"));
        if let Some(legacy) = std::env::var_os("R2O_ORDER_TEST_LEGACY") {
            let output = std::process::Command::new(legacy)
                .args(["--mark-recheck", "absent.example", "4", "1"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(Catalog::load(&path).unwrap(), catalog);
            println!("TCP order: previous controller read and rewrote the catalog");
        }
        apply_catalog(socket, path).unwrap();
        let destination: std::net::SocketAddr = target.endpoint.parse().unwrap();
        let stream = TcpStream::connect_timeout(&destination, Duration::from_secs(3)).unwrap();
        let options = r2o_controller::fetch::FetchOptions {
            name: target.host,
            ip: Some(destination.ip()),
            port: destination.port(),
            path: "/".into(),
            deadline: Duration::from_secs(4),
            tls12: false,
            wire_len: Some(hello.len()),
            mark: None,
        };
        let result = r2o_controller::fetch::fetch_tcp_order(
            &options,
            stream,
            hello.len(),
            sni.start,
            r2o_controller::fetch::R2oFetchEncoding::Identity,
        );
        assert!(r2o_tcp_order_https_verified(&result), "{result:?}");
        println!("TCP order: confirmed HTTPS with restored permanent plan");
        return;
    }
    let cut = sni.start + 1;
    let measured = format!(
        "r2o-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsegment 1400\nsplit payload_start +{cut}\norder forward\n"
    );
    let experiment =
        r2o_controller::tcp_order::Experiment::from_measured(&target, &hello, &measured, 1500)
            .unwrap();
    let (commands, receiver) = mpsc::sync_channel(4);
    let mut probes = 0;
    let started = Instant::now();
    let (text, fetch, mut client) = std::thread::scope(|scope| {
        let catalog_path = &path;
        let service = scope.spawn(move || {
            let mut client = ControlClient::connect(socket).unwrap();
            let mut catalog = Catalog::default();
            while let Ok(command) = receiver.recv() {
                client
                    .service_http_search_command(command, &mut catalog, catalog_path, None)
                    .unwrap();
            }
            client
        });
        let result = r2o_run_tcp_order_experiment(
            &target,
            &experiment,
            "/",
            Some(291),
            &commands,
            true,
            &AtomicBool::new(false),
            &AtomicUsize::new(0),
            started + Duration::from_secs(28),
            &mut probes,
        );
        drop(commands);
        let client = service.join().unwrap();
        let (text, fetch) = result.expect("exact executed plan and full HTTPS proof");
        (text, fetch, client)
    });
    if mode == "direct" {
        assert_eq!(probes, 1);
        assert!(text.contains("order 1,2"));
        return;
    }
    assert_eq!(probes, 3);
    assert!(text.contains("order 1,3,2"));
    let mut catalog = Catalog::default();
    let outcome = DiscoveryOutcome {
        target,
        plan_text: Some(text),
        detail: String::new(),
        queue_expired: false,
        address_failure: false,
        address_recheck_acknowledged: false,
        address_recheck_probes: 0,
        direct_clear: false,
        volume_recovery: false,
        budget_mark: 0,
        group_block_proven: false,
        transferred_own_plan: false,
        bound_plan_id: None,
        ech_origin: None,
        volume_fingerprint: None,
        volume_box_id: None,
        retry_after: None,
    };
    let mut handshake_only = fetch.clone();
    handshake_only.application_verified = false;
    handshake_only.complete = false;
    handshake_only.handshake_verified = true;
    assert!(!r2o_tcp_order_https_verified(&Ok(handshake_only)));
    let outcome = r2o_confirm_discovery_outcome(outcome, Ok(fetch), true);
    let mut confirmed = false;
    client
        .apply_confirmed_discovery_outcome(
            outcome,
            &mut catalog,
            &path,
            r2o_controller::discovery::R2O_D2K_INPUT_CLIENT,
            Some(true),
            Some("/"),
            &mut confirmed,
            None,
            Some(R2O_D2K_VERBY_PROBE),
        )
        .unwrap();
    assert!(confirmed);
    assert_eq!(Catalog::load(&path).unwrap(), catalog);
    println!(
        "TCP order: saved after {} ms and {probes} probes",
        started.elapsed().as_millis()
    );
}
