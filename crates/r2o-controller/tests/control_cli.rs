#![cfg(unix)]

use r2k_core::plan::PLAN_MAGIC;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROTO_VERSION: u16 = r2k_core::control::PROTOCOL_VERSION;
const KEY_LEN: usize = 38;
static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn plan_header(minexec: u16, records: u16) -> Vec<u8> {
    let mut bytes = PLAN_MAGIC.to_vec();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&minexec.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&records.to_be_bytes());
    bytes
}

#[test]
fn set_name_sends_a_c_compatible_plan_after_matching_the_wire_version() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let plan_path = work.join("plan.r2op");
    let records = [
        0x00, 0x02, 0x00, 0x02, 0x06, 0x01, // TCP TLS plan
        0x00, 0x10, 0x00, 0x06, 0x00, 0x01, b'F', b'A', b'K', b'E', // payload
        0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // poison
        0x01, 0x01, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut plan = plan_header(0, 4);
    plan.extend_from_slice(&records);
    fs::write(&plan_path, &plan).unwrap();

    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let expected_plan = plan;
    let server = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("controller did not connect".to_owned());
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(format!("control accept failed: {error}")),
            }
        };
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();

        let (kind, body) = read_frame(&mut stream);
        assert_eq!(kind, 0x0081);
        let mut expected = vec!["example.test".len() as u8];
        expected.extend_from_slice(b"example.test");
        expected.extend_from_slice(&[1, 4]); // modern ClientHello, IPv4
        expected.extend_from_slice(&expected_plan);
        assert_eq!(body, expected);

        let mut hello = vec![0; KEY_LEN];
        hello[0] = 4;
        hello[1..5].copy_from_slice(&[192, 0, 2, 1]);
        hello[17..21].copy_from_slice(&[198, 51, 100, 2]);
        hello[33..35].copy_from_slice(&50000_u16.to_be_bytes());
        hello[35..37].copy_from_slice(&443_u16.to_be_bytes());
        hello[37] = 6;
        hello.extend_from_slice(&[12]);
        hello.extend_from_slice(b"example.test");
        hello.push(1);
        stream.write_all(&frame(0x0001, &hello)).unwrap();

        let mut ack = vec![0; KEY_LEN];
        ack[0] = 4;
        ack.extend_from_slice(&[0x00, 0x81, 1, 0]);
        stream.write_all(&frame(0x0008, &ack)).unwrap();
        Ok(())
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--set-name",
            socket_path.to_str().unwrap(),
            "example.test",
            "ipv4",
            "modern",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "r2o-controller failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap().unwrap();
    let _ = fs::remove_dir_all(&work);
    assert!(String::from_utf8_lossy(&output.stdout).contains("план установлен"));
}

#[test]
fn set_name_accepts_a_quic_split_plan_and_sends_udp_shape() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let plan_path = work.join("plan.r2op");
    let mut plan = plan_header(10, 3);
    plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
    plan.extend_from_slice(&[0; 16]);
    plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x11, 0x02]);
    plan.extend_from_slice(&[0x01, 0x0f, 0x00, 0x01, 0x01]);
    fs::write(&plan_path, &plan).unwrap();

    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let expected_plan = plan;
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "controller did not connect");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("control accept failed: {error}"),
            }
        };
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();

        let (kind, body) = read_frame(&mut stream);
        assert_eq!(kind, 0x0081);
        let mut expected = vec!["example.test".len() as u8];
        expected.extend_from_slice(b"example.test");
        expected.extend_from_slice(&[3, 4]); // QUIC Initial SNI, IPv4
        expected.extend_from_slice(&expected_plan);
        assert_eq!(body, expected);

        let mut ack = vec![0; KEY_LEN];
        ack[0] = 4;
        ack.extend_from_slice(&[0x00, 0x81, 1, 0]);
        stream.write_all(&frame(0x0008, &ack)).unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--set-name",
            socket_path.to_str().unwrap(),
            "example.test",
            "ipv4",
            "quic",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "r2o-controller failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
    let _ = fs::remove_dir_all(&work);
    assert!(String::from_utf8_lossy(&output.stdout).contains("план установлен"));
}

#[test]
fn version_reports_control_protocol_and_release_id() {
    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("r2o-controller release=dev wire={PROTO_VERSION}")
    );
}

#[test]
fn watch_reports_a_tls_hello_event_and_exits_cleanly_when_datapath_closes() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("controller did not connect".to_owned());
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(format!("control accept failed: {error}")),
            }
        };
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();

        let mut hello = vec![0; KEY_LEN];
        hello[0] = 4;
        hello[1..5].copy_from_slice(&[192, 0, 2, 1]);
        hello[17..21].copy_from_slice(&[198, 51, 100, 2]);
        hello[33..35].copy_from_slice(&50000_u16.to_be_bytes());
        hello[35..37].copy_from_slice(&443_u16.to_be_bytes());
        hello[37] = 6;
        hello.extend_from_slice(&[12]);
        hello.extend_from_slice(b"example.test");
        hello.push(1);
        stream.write_all(&frame(0x0001, &hello)).unwrap();
        Ok(())
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args(["--watch", socket_path.to_str().unwrap()])
        .output()
        .unwrap();
    let server_result = server.join().unwrap();
    assert!(
        output.status.success(),
        "r2o-controller watch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server_result.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("example.test"));
    assert!(stdout.contains("форма=TLS 1.3"));
    let _ = fs::remove_dir_all(&work);
}

#[test]
fn watch_reports_http_response_outcome_and_request_context() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();

        let mut event = vec![0; KEY_LEN];
        event[0] = 4;
        event[1..5].copy_from_slice(&[192, 0, 2, 1]);
        event[17..21].copy_from_slice(&[198, 51, 100, 2]);
        event[33..35].copy_from_slice(&40123_u16.to_be_bytes());
        event[35..37].copy_from_slice(&80_u16.to_be_bytes());
        event[37] = 6;
        event.extend_from_slice(&[1, 16]);
        event.extend_from_slice(b"cdn.example.test");
        event.extend_from_slice(&42_u64.to_be_bytes());
        event.extend_from_slice(&[0x11; 16]);
        event.extend_from_slice(&[0; 16]);
        event.extend_from_slice(&123_456_u64.to_be_bytes());
        event.extend_from_slice(&15_u16.to_be_bytes());
        event.extend_from_slice(b"/assets/app.css");
        event.extend_from_slice(&[0; 28]);
        event.extend_from_slice(&200_u16.to_be_bytes());
        event.extend_from_slice(&7_u64.to_be_bytes());
        event.extend_from_slice(&3_u64.to_be_bytes());
        stream.write_all(&frame(0x000c, &event)).unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args(["--watch", socket_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "r2o-controller watch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("полный ответ"));
    assert!(stdout.contains("cdn.example.test"));
    assert!(stdout.contains("/assets/app.css"));
    assert!(stdout.contains("номер запроса=3"));
    fs::remove_dir_all(work).unwrap();
}

#[test]
fn serve_catalog_installs_plans_and_consumes_hello_on_the_same_connection() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let catalog_path = work.join("catalog.json");
    fs::write(
        &catalog_path,
        br#"{"boxes":[{"id":"box-1","created":"2026-10-18T00:00:00Z","updated":"2026-10-18T00:00:00Z","plans":[{"id":"plan-1","proto":"tls","text":"r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +0\n","added":"2026-10-18T00:00:00Z","successes":1,"enabled":true}],"bindings":[{"kind":"name","target":"example.test","plan_id":"plan-1","level":3,"confirmed":"2026-10-18T00:00:00Z","successes":1,"enabled":true,"transport":6,"family":4,"shape":1}]}]}"#,
    )
    .unwrap();

    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("controller did not connect".to_owned());
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(format!("control accept failed: {error}")),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();

        let (kind, body) = read_frame(&mut stream);
        assert_eq!(kind, 0x0081);
        assert!(
            body.windows(b"example.test".len())
                .any(|part| part == b"example.test")
        );
        let mut hello = vec![0; KEY_LEN];
        hello[0] = 4;
        hello[1..5].copy_from_slice(&[192, 0, 2, 1]);
        hello[17..21].copy_from_slice(&[198, 51, 100, 2]);
        hello[33..35].copy_from_slice(&50000_u16.to_be_bytes());
        hello[35..37].copy_from_slice(&443_u16.to_be_bytes());
        hello[37] = 6;
        hello.extend_from_slice(&[12]);
        hello.extend_from_slice(b"example.test");
        hello.push(2);
        stream.write_all(&frame(0x0001, &hello)).unwrap();

        let mut ack = vec![0; KEY_LEN];
        ack[0] = 4;
        ack.extend_from_slice(&[0x00, 0x81, 1, 0]);
        stream.write_all(&frame(0x0008, &ack)).unwrap();
        Ok(())
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--serve",
            socket_path.to_str().unwrap(),
            catalog_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let server_result = server.join().unwrap();
    assert!(
        output.status.success(),
        "r2o-controller serve failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server_result.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("установлено 1"));
    assert!(stdout.contains("SNI=\"example.test\""));
    assert!(stdout.contains("форма=TLS 1.2"));
    let live: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("live.json")).unwrap()).unwrap();
    assert_eq!(live["linked"], true);
    assert_eq!(live["catalog_at"], catalog_path.to_string_lossy().as_ref());
    assert_eq!(live["boxes"][0]["id"], "box-1");
    assert_eq!(live["targets"], 1);
    assert_eq!(live["measurements"]["active"], 0);
    let _ = fs::remove_dir_all(&work);
}

#[test]
fn serve_discover_remembers_hello_without_starting_a_search() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let catalog_path = work.join("catalog.json");
    fs::write(&catalog_path, br#"{"boxes":[]}"#).unwrap();
    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("controller did not connect".to_owned());
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(format!("control accept failed: {error}")),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();

        let mut hello = vec![0; KEY_LEN];
        hello[0] = 4;
        hello[1..5].copy_from_slice(&[192, 0, 2, 1]);
        hello[17..21].copy_from_slice(&[127, 0, 0, 1]);
        hello[33..35].copy_from_slice(&50000_u16.to_be_bytes());
        hello[35..37].copy_from_slice(&443_u16.to_be_bytes());
        hello[37] = 6;
        hello.extend_from_slice(&[11]);
        hello.extend_from_slice(b"example.com");
        hello.push(1);
        stream.write_all(&frame(0x0001, &hello)).unwrap();
        let key: [u8; KEY_LEN] = hello[..KEY_LEN].try_into().unwrap();
        let suspicion = r2k_core::control::R2oTcpSilenceEvent {
            key,
            client_is_low: true,
            planned: false,
            elapsed_ms: 1_200,
        };
        stream
            .write_all(&frame(
                r2k_core::control::EVENT_R2O_TCP_SILENT,
                &suspicion.event_body().unwrap(),
            ))
            .unwrap();
        Ok(())
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--serve",
            socket_path.to_str().unwrap(),
            catalog_path.to_str().unwrap(),
            "--discover",
        ])
        .output()
        .unwrap();
    server.join().unwrap().unwrap();
    assert!(
        output.status.success(),
        "r2o-controller auto-discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("поставлен в очередь классификации"));
    assert!(stdout.contains("форма=TLS 1.3"));
    assert!(stdout.contains(
        "молчание TCP без чистого рукопожатия поставило example.com в очередь классификации"
    ));
    let _ = fs::remove_dir_all(&work);
}

#[test]
fn set_name_does_not_send_when_the_datapath_wire_version_is_mismatched() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let plan_path = work.join("plan.r2op");
    let mut plan = plan_header(0, 2);
    plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
    plan.extend_from_slice(&[0; 16]);
    plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
    fs::write(&plan_path, plan).unwrap();

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|error| format!("control accept failed: {error}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|error| format!("set timeout failed: {error}"))?;
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&(PROTO_VERSION - 1).to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();
        let mut prefix = [0; 4];
        match stream.read_exact(&mut prefix) {
            Ok(()) => Err("controller sent a command on an incompatible wire".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
            Err(error) => Err(format!("unexpected read result: {error}")),
        }
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--set-name",
            socket_path.to_str().unwrap(),
            "example.test",
            "ipv4",
            "modern",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("несовместимый r2o-datapath"));
    server.join().unwrap().unwrap();
    let _ = fs::remove_dir_all(&work);
}

#[test]
fn apply_catalog_compiles_and_installs_tcp_and_discord_voice_name_bindings() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let catalog_path = work.join("catalog.json");
    fs::write(
        &catalog_path,
        br#"{"boxes":[{"id":"box-1","created":"2026-10-18T00:00:00Z","updated":"2026-10-18T00:00:00Z","plans":[{"id":"plan-1","proto":"tls","text":"r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +0\n","added":"2026-10-18T00:00:00Z","successes":1,"enabled":true},{"id":"voice-1","proto":"voice","text":"r2o-plan 1 1\nid 00000000000000000000000000000000\nproto udp voice\npayload 1 46414b45\npoison 1 ttl=2\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\n","added":"2026-10-18T00:00:00Z","successes":1,"enabled":true}],"bindings":[{"kind":"name","target":"example.test","plan_id":"plan-1","level":3,"confirmed":"2026-10-18T00:00:00Z","successes":1,"enabled":true,"transport":6,"family":4,"shape":1},{"kind":"name","target":"@discord-voice","plan_id":"voice-1","level":3,"confirmed":"2026-10-18T00:00:00Z","successes":1,"enabled":true,"transport":17,"family":4,"shape":5}]}]}"#,
    )
    .unwrap();

    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("controller did not connect".to_owned());
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(format!("control accept failed: {error}")),
            }
        };
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();

        let (kind, body) = read_frame(&mut stream);
        assert_eq!(kind, 0x0081);
        let mut expected = vec!["example.test".len() as u8];
        expected.extend_from_slice(b"example.test");
        expected.extend_from_slice(&[1, 4]);
        expected.extend_from_slice(&plan_header(11, 4));
        expected.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        expected.extend_from_slice(&[0; 16]);
        expected.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        expected.extend_from_slice(&[0x01, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00]);
        expected.extend_from_slice(&[0x01, 0x03, 0x00, 0x01, 0x00]);
        assert_eq!(body, expected);

        let mut ack = vec![0; KEY_LEN];
        ack[0] = 4;
        ack.extend_from_slice(&[0x00, 0x81, 1, 0]);
        stream.write_all(&frame(0x0008, &ack)).unwrap();

        let (kind, body) = read_frame(&mut stream);
        assert_eq!(kind, 0x0081);
        let mut expected = vec![b"@discord-voice".len() as u8];
        expected.extend_from_slice(b"@discord-voice");
        expected.extend_from_slice(&[5, 4]);
        expected.extend_from_slice(&plan_header(1, 6));
        expected.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        expected.extend_from_slice(&[0; 16]);
        expected.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x11, 0x03]);
        expected.extend_from_slice(&[0x00, 0x10, 0x00, 0x06, 0x00, 0x01, b'F', b'A', b'K', b'E']);
        expected.extend_from_slice(&[0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x02, 0, 0, 0, 0, 0]);
        expected.extend_from_slice(&[
            0x01, 0x01, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0,
        ]);
        expected.extend_from_slice(&[0x01, 0x03, 0x00, 0x01, 0x00]);
        assert_eq!(body, expected);

        let mut ack = vec![0; KEY_LEN];
        ack[0] = 4;
        ack.extend_from_slice(&[0x00, 0x81, 1, 0]);
        stream.write_all(&frame(0x0008, &ack)).unwrap();
        Ok(())
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--apply-catalog",
            socket_path.to_str().unwrap(),
            catalog_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "r2o-controller failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap().unwrap();
    let _ = fs::remove_dir_all(&work);
    assert!(String::from_utf8_lossy(&output.stdout).contains("установлено 2"));
}

#[test]
fn apply_catalog_sends_failed_group_exception_before_suffix_plan() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let catalog_path = work.join("catalog.json");
    fs::write(
        &catalog_path,
        br#"{"boxes":[{"id":"box-1","created":"2026-10-18T00:00:00Z","updated":"2026-10-18T00:00:00Z","plans":[{"id":"plan-1","proto":"tls","text":"r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +0\n","added":"2026-10-18T00:00:00Z","successes":4,"enabled":true}],"bindings":[]}],"domain_observations":[{"name":"a.googlevideo.com","plan_id":"plan-1","transport":6,"family":4,"shape":1,"evidence":1,"at":"2026-10-18T00:00:00Z"},{"name":"b.googlevideo.com","plan_id":"plan-1","transport":6,"family":4,"shape":1,"evidence":1,"at":"2026-10-18T00:01:00Z"},{"name":"c.googlevideo.com","plan_id":"plan-1","transport":6,"family":4,"shape":1,"evidence":1,"at":"2026-10-18T00:02:00Z"},{"name":"d.googlevideo.com","plan_id":"plan-1","transport":6,"family":4,"shape":1,"evidence":1,"at":"2026-10-18T00:03:00Z"},{"name":"failed.googlevideo.com","plan_id":"plan-1","transport":6,"family":4,"shape":1,"evidence":4,"at":"2026-10-18T00:04:00Z"}]}"#,
    )
    .unwrap();

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|error| format!("control accept failed: {error}"))?;
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();

        let (kind, body) = read_frame(&mut stream);
        assert_eq!(kind, 0x008e);
        let mut expected = vec![b"failed.googlevideo.com".len() as u8];
        expected.extend_from_slice(b"failed.googlevideo.com");
        expected.extend_from_slice(&[6, 1, 4]);
        assert_eq!(body, expected);
        let mut ack = vec![0; KEY_LEN];
        ack[0] = 4;
        ack.extend_from_slice(&[0x00, 0x8e, 1, 0]);
        stream.write_all(&frame(0x0008, &ack)).unwrap();

        let (kind, body) = read_frame(&mut stream);
        assert_eq!(kind, 0x008c);
        let mut expected = vec![b"googlevideo.com".len() as u8];
        expected.extend_from_slice(b"googlevideo.com");
        expected.extend_from_slice(&[1, 4]);
        expected.extend_from_slice(&plan_header(11, 4));
        expected.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        expected.extend_from_slice(&[0; 16]);
        expected.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        expected.extend_from_slice(&[0x01, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00]);
        expected.extend_from_slice(&[0x01, 0x03, 0x00, 0x01, 0x00]);
        assert_eq!(body, expected);
        let mut ack = vec![0; KEY_LEN];
        ack[0] = 4;
        ack.extend_from_slice(&[0x00, 0x8c, 1, 0]);
        stream.write_all(&frame(0x0008, &ack)).unwrap();
        Ok(())
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--apply-catalog",
            socket_path.to_str().unwrap(),
            catalog_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "r2o-controller failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap().unwrap();
    let _ = fs::remove_dir_all(&work);
    assert!(String::from_utf8_lossy(&output.stdout).contains("установлено 2"));
}

#[test]
fn apply_empty_catalog_does_not_clear_existing_name_plans() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let catalog_path = work.join("catalog.json");
    fs::write(&catalog_path, br#"{"boxes":[]}"#).unwrap();

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|error| format!("control accept failed: {error}"))?;
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();

        let mut byte = [0; 1];
        assert_eq!(
            stream.read(&mut byte).unwrap(),
            0,
            "empty catalog sent a datapath command"
        );
        Ok(())
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--apply-catalog",
            socket_path.to_str().unwrap(),
            catalog_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "r2o-controller failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap().unwrap();
    let _ = fs::remove_dir_all(&work);
    assert!(String::from_utf8_lossy(&output.stdout).contains("установлено 0"));
}

#[test]
fn apply_catalog_skips_refused_binding_and_installs_following_binding() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let catalog_path = work.join("catalog.json");
    fs::write(
        &catalog_path,
        br#"{"boxes":[{"id":"box-1","created":"2026-10-18T00:00:00Z","updated":"2026-10-18T00:00:00Z","plans":[{"id":"plan-1","proto":"tls","text":"r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n","added":"2026-10-18T00:00:00Z","successes":1,"enabled":true},{"id":"plan-2","proto":"tls","text":"r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n","added":"2026-10-18T00:00:00Z","successes":1,"enabled":true}],"bindings":[{"kind":"name","target":"rejected.example.test","plan_id":"plan-1","level":3,"confirmed":"2026-10-18T00:00:00Z","successes":1,"enabled":true,"transport":6,"family":4,"shape":1},{"kind":"name","target":"accepted.example.test","plan_id":"plan-2","level":3,"confirmed":"2026-10-18T00:00:00Z","successes":1,"enabled":true,"transport":6,"family":4,"shape":1}]}]}"#,
    )
    .unwrap();

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|error| format!("control accept failed: {error}"))?;
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();

        let (kind, _) = read_frame(&mut stream);
        assert_eq!(kind, 0x0081);
        let mut nack = vec![0; KEY_LEN];
        nack[0] = 4;
        nack.extend_from_slice(&[0x00, 0x81, 0, 2]);
        stream.write_all(&frame(0x0008, &nack)).unwrap();

        let (kind, _) = read_frame(&mut stream);
        assert_eq!(kind, 0x0081);
        let mut ack = vec![0; KEY_LEN];
        ack[0] = 4;
        ack.extend_from_slice(&[0x00, 0x81, 1, 0]);
        stream.write_all(&frame(0x0008, &ack)).unwrap();
        Ok(())
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--apply-catalog",
            socket_path.to_str().unwrap(),
            catalog_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("датапат отверг планов с прошлой сводки: 1"));
    assert!(stdout.contains("каталог обработан: установлено 1"));
    server.join().unwrap().unwrap();
    let _ = fs::remove_dir_all(&work);
}

#[test]
fn clear_catalog_atomically_removes_discovered_state_and_keeps_regular_file_safety() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let catalog_path = work.join("catalog.json");
    fs::write(
        &catalog_path,
        br#"{"schema":1,"boxes":[{"id":"found"}],"domain_observations":[]}"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args(["--clear-catalog", catalog_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cleared: serde_json::Value =
        serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap();
    assert_eq!(cleared["schema"], 1);
    assert_eq!(cleared["boxes"], serde_json::json!([]));
    assert!(cleared["updated"].as_str().is_some());
    assert!(
        fs::symlink_metadata(work.join("catalog.json.lock"))
            .unwrap()
            .is_file()
    );

    let linked_path = work.join("linked-catalog.json");
    std::os::unix::fs::symlink(&catalog_path, &linked_path).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args(["--clear-catalog", linked_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&catalog_path).unwrap()).unwrap()["boxes"],
        serde_json::json!([])
    );
    fs::remove_dir_all(work).unwrap();
}

fn temporary_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "r2o-control-{}-{nonce}-{sequence}",
        std::process::id()
    ))
}

#[test]
fn temporary_directory_paths_are_unique_under_parallel_calls() {
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier};

    const CALLS: usize = 32;
    let barrier = Arc::new(Barrier::new(CALLS));
    let paths = thread::scope(|scope| {
        let workers = (0..CALLS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    temporary_directory()
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    let unique = paths.iter().collect::<HashSet<_>>();
    assert_eq!(unique.len(), CALLS);
}

fn frame(kind: u16, body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len() + 2).unwrap();
    [length.to_be_bytes().as_slice(), &kind.to_be_bytes(), body].concat()
}

fn read_frame(stream: &mut UnixStream) -> (u16, Vec<u8>) {
    let mut header = [0; 6];
    stream.read_exact(&mut header).unwrap();
    let length = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
    assert!((2..=65_536).contains(&length));
    let kind = u16::from_be_bytes(header[4..6].try_into().unwrap());
    let mut body = vec![0; length - 2];
    stream.read_exact(&mut body).unwrap();
    (kind, body)
}
