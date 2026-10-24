use std::process::Command;

fn r2o_run_fetch(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_r2o-fetch"))
        .args(args)
        .output()
        .expect("r2o-fetch должен запускаться")
}

#[test]
fn r2o_short_version_flag_matches_donor() {
    let output = r2o_run_fetch(&["-v"]);

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("r2o-fetch "));
}

#[test]
fn r2o_help_показывает_бюджет_quic_и_значение_по_умолчанию() {
    let output = r2o_run_fetch(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("[--quic-budget N]"));
    assert!(help.contains("--quic-budget N"));
    assert!(help.contains("по умолчанию N=25"));
    assert!(help.contains("0 отключает бюджет"));
    assert!(!help.contains("пока нет донорского пакетного бюджета"));
}

#[test]
fn r2o_budget_quic_без_quic_завершается_ошибкой_аргумента() {
    let output = r2o_run_fetch(&["--name", "example.com", "--quic-budget", "1"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("требует --quic"));
}

#[test]
fn r2o_budget_quic_принимает_целое_и_отклоняет_tls12_до_сети() {
    let output = r2o_run_fetch(&[
        "--name",
        "example.com",
        "--quic",
        "--quic-budget",
        "1",
        "--tls12",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("QUIC использует TLS 1.3"));
}

#[test]
fn r2o_json_resolves_an_empty_ip_like_the_donor() {
    let output = r2o_run_fetch(&[
        "--name",
        "localhost",
        "--ip",
        "",
        "--port",
        "1",
        "--deadline",
        "100",
        "--quic",
        "--json",
    ]);

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("--json must return a QUIC result");
    assert_eq!(value["schema"], 2);
    assert_eq!(value["shape"], "quic");
    assert!(
        value["ip"]
            .as_str()
            .and_then(|address| address.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback())
    );
}

#[cfg(unix)]
#[test]
fn r2o_fetch_snapshot_precedes_address_validation() {
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let work = std::env::temp_dir().join(format!("r2o-fetch-cli-snapshot-{nonce}"));
    std::fs::create_dir(&work).unwrap();
    let control = work.join("datapath.sock");
    let snapshot = r2k_core::control::r2k_snapshot_socket_path(&control);
    let listener = UnixListener::bind(&snapshot).unwrap();
    let datapath = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .write_all(&r2k_core::control::encode_greeting(4096).unwrap())
            .unwrap();
        let mut body = vec![0; r2k_core::control::KEY_LEN];
        body[0] = 4;
        body[37] = 6;
        body.push(b"example.test".len() as u8);
        body.extend_from_slice(b"example.test");
        body.push(r2k_core::control::SHAPE_MODERN);
        body.extend_from_slice(&1200_u16.to_be_bytes());
        stream
            .write_all(
                &r2k_core::control::encode_frame(r2k_core::control::EVENT_HELLO, &body).unwrap(),
            )
            .unwrap();
    });

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_r2o-fetch"))
        .args([
            "--name",
            "example.test",
            "--ip",
            "not-an-ip",
            "--snapshot=1000",
        ])
        .arg("--control")
        .arg(&control)
        .output()
        .expect("запустить r2o-fetch");
    let error = String::from_utf8_lossy(&output.stderr);

    assert!(
        error.contains("снято приветствие браузера: 1200 байт"),
        "{error}"
    );
    assert!(error.contains("неверный IP-адрес"), "{error}");
    datapath.join().unwrap();
    std::fs::remove_dir_all(work).unwrap();
}

#[cfg(unix)]
#[test]
fn r2o_fetch_quic_snapshot_preserves_client_hello_wire_length() {
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let work = std::env::temp_dir().join(format!("r2o-fetch-quic-snapshot-{nonce}"));
    std::fs::create_dir(&work).unwrap();
    let control = work.join("datapath.sock");
    let snapshot = r2k_core::control::r2k_snapshot_socket_path(&control);
    let listener = UnixListener::bind(&snapshot).unwrap();
    let datapath = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .write_all(&r2k_core::control::encode_greeting(4096).unwrap())
            .unwrap();
        let mut body = vec![0; r2k_core::control::KEY_LEN];
        body[0] = 4;
        body[37] = 6;
        body.push(b"example.test".len() as u8);
        body.extend_from_slice(b"example.test");
        body.push(r2k_core::control::SHAPE_MODERN);
        body.extend_from_slice(&1200_u16.to_be_bytes());
        stream
            .write_all(
                &r2k_core::control::encode_frame(r2k_core::control::EVENT_HELLO, &body).unwrap(),
            )
            .unwrap();
    });

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_r2o-fetch"))
        .args([
            "--name",
            "example.test",
            "--ip",
            "127.0.0.1",
            "--port",
            "1",
            "--quic",
            "--deadline",
            "100",
            "--snapshot=1000",
            "--json",
        ])
        .arg("--control")
        .arg(&control)
        .output()
        .expect("запустить r2o-fetch");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("QUIC --json must return a result");

    assert_eq!(value["shape"], "quic");
    assert_eq!(value["wire_requested"], 1200);
    datapath.join().unwrap();
    std::fs::remove_dir_all(work).unwrap();
}

#[test]
fn r2o_json_keeps_quic_stream_bytes_separate_from_http_body_bytes() {
    let output = r2o_run_fetch(&[
        "--name",
        "stand.example",
        "--ip",
        "127.0.0.1",
        "--port",
        "1",
        "--quic",
        "--deadline",
        "100",
        "--mark",
        "0x2f",
        "--json",
    ]);

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("QUIC --json must return a JSON result");
    assert!(value["body_bytes"].is_null());
    assert!(value["quic_stream_bytes"].is_u64());
    assert_eq!(value["headers_inspected"], false);
    assert!(value["location"].is_null());
    assert_eq!(value["level"], 0);
    assert_eq!(value["local_port"], 0);
    assert_eq!(value["mark"], 0);
    assert_eq!(value["local_refusal"], false);
}

#[test]
fn r2o_json_reports_tcp_transport_failure_in_the_c_schema() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    drop(listener);
    let output = r2o_run_fetch(&[
        "--name",
        "stand.example",
        "--ip",
        "127.0.0.1",
        "--port",
        &port,
        "--deadline",
        "100",
        "--json",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("TCP --json must return a JSON result");
    assert_eq!(value["schema"], 2);
    assert_eq!(value["client"], "d2k-own-profile");
    assert_eq!(value["shape"], "tcp");
    assert_eq!(value["ip"], "127.0.0.1");
    assert_eq!(value["http_status"], 0);
    assert_eq!(value["response_complete"], false);
    assert_eq!(value["headers_inspected"], true);
    assert_eq!(value["level"], 0);
    assert_eq!(value["measured"], true);
    assert_eq!(value["reason"], "нет TCP");
}

#[test]
fn r2o_json_keeps_transmit_and_receive_ladder_results_separate() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    drop(listener);
    let output = r2o_run_fetch(&[
        "--name",
        "stand.example",
        "--ip",
        "127.0.0.1",
        "--port",
        &port,
        "--ladder",
        "--json",
    ]);

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("ladder --json must return a JSON result");
    assert_eq!(value["shape"], "ladder");
    assert_eq!(value["tx_passed"], false);
    assert!(value["reason"].as_str().unwrap().starts_with("нет TCP:"));
    assert!(value["rx_cut"].is_boolean());
    assert!(value["rx_short"].is_boolean());
    assert!(value["rx_unmeasured"].is_boolean());
    assert!(value["rx_direct_complete"].is_boolean());
    assert!(value["rx_tls_unavailable"].is_boolean());
    assert!(value["measured_path"].is_string());
    assert_eq!(value["rx_reason"], "");
}

#[test]
fn r2o_json_combines_ladder_and_quic_when_both_are_requested() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    drop(listener);
    let output = r2o_run_fetch(&[
        "--name",
        "stand.example",
        "--ip",
        "127.0.0.1",
        "--port",
        &port,
        "--deadline",
        "100",
        "--ladder",
        "--quic",
        "--quic-budget",
        "0",
        "--json",
    ]);

    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("combined --json must return one JSON result");
    assert_eq!(value["shape"], "combined");
    assert_eq!(value["ladder"]["shape"], "ladder");
    assert_eq!(value["quic"]["shape"], "quic");
    assert_eq!(value["quic"]["wire_requested"], 0);
}
