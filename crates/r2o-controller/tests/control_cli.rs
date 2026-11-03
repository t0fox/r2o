#![cfg(unix)]

use r2k_core::plan::PLAN_MAGIC;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROTO_VERSION: u16 = r2k_core::control::PROTOCOL_VERSION;
const KEY_LEN: usize = 38;
static NEXT_TEMP_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

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
    assert!(stdout.contains("каталог синхронизирован: отправлено 1"));
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
fn serve_restart_reapplies_saved_discord_voice_binding() {
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let catalog_path = work.join("catalog.json");
    fs::write(
        &catalog_path,
        br#"{"boxes":[{"id":"box-1","created":"2026-10-18T00:00:00Z","updated":"2026-10-18T00:00:00Z","plans":[{"id":"voice-1","proto":"voice","text":"r2o-plan 1 1\nid 00000000000000000000000000000000\nproto udp voice\npayload 1 46414b45\npoison 1 ttl=2\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\n","added":"2026-10-18T00:00:00Z","successes":1,"enabled":true}],"bindings":[{"kind":"name","target":"@discord-voice","plan_id":"voice-1","level":3,"confirmed":"2026-10-18T00:00:00Z","successes":1,"enabled":true,"transport":17,"family":4,"shape":5}]}]}"#,
    )
    .unwrap();

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

    for restart in 0..2 {
        let socket_path = work.join(format!("control-{restart}.sock"));
        let listener = UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (binding_sender, binding_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let server = thread::spawn(move || -> Result<(), String> {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err("controller did not reconnect".to_owned());
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(format!("control accept failed: {error}")),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .map_err(|error| format!("set control timeout failed: {error}"))?;
            let mut greeting = vec![0; KEY_LEN];
            greeting[0] = 4;
            greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
            greeting.extend_from_slice(&65_535_u32.to_be_bytes());
            greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
            stream
                .write_all(&frame(0x000a, &greeting))
                .map_err(|error| format!("write datapath greeting failed: {error}"))?;
            let applied = read_frame(&mut stream);
            binding_sender
                .send(applied)
                .map_err(|error| format!("report voice binding failed: {error}"))?;
            release_receiver
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| format!("release datapath fixture failed: {error}"))?;
            Ok(())
        });

        let mut child = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
            .args([
                "--serve",
                socket_path.to_str().unwrap(),
                catalog_path.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let applied = binding_receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("controller did not apply the saved voice binding");
        assert!(child.try_wait().unwrap().is_none());
        assert_eq!(applied.0, 0x0081);
        assert_eq!(applied.1, expected, "restart {restart}");
        child.kill().unwrap();
        child.wait().unwrap();
        release_sender.send(()).unwrap();
        server.join().unwrap().unwrap();
    }

    let _ = fs::remove_dir_all(work);
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

#[cfg(target_os = "linux")]
fn can_set_socket_mark(mark: u32) -> bool {
    use std::os::fd::AsRawFd;

    let Ok(socket) = std::net::UdpSocket::bind(("127.0.0.1", 0)) else {
        return false;
    };
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const u32).cast(),
            std::mem::size_of_val(&mark) as libc::socklen_t,
        ) == 0
    }
}

#[cfg(target_os = "linux")]
#[test]
fn serve_discover_runs_discord_ip_discovery_in_process_and_closes_cleanly() {
    let mark_supported = can_set_socket_mark(291);
    let discovery_timeout = if mark_supported {
        Duration::from_secs(8)
    } else {
        Duration::from_millis(500)
    };
    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    let socket_path = work.join("control.sock");
    let catalog_path = work.join("catalog.json");
    fs::write(&catalog_path, br#"{"boxes":[]}"#).unwrap();

    let udp = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let server_port = udp.local_addr().unwrap().port();
    let discovery = thread::spawn(move || -> Result<usize, String> {
        let result = (|| {
            let deadline = Instant::now() + discovery_timeout;
            let mut received = 0;
            let mut request = [0; 2048];
            while received < usize::from(r2o_controller::voice_discovery::R2O_DISCOVERY_EXCHANGES) {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "received only {received} Discord Discovery requests"
                    ));
                }
                let (length, peer) = match udp.recv_from(&mut request) {
                    Ok(packet) => packet,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(format!("UDP receive failed: {error}")),
                };
                if !r2k_core::stun::is_discord_ip_discovery_request(&request[..length]) {
                    return Err(format!(
                        "unexpected Discord Discovery request length {length}"
                    ));
                }
                let mut response = [0; 74];
                response[..4].copy_from_slice(&[0, 2, 0, 70]);
                response[4..8].copy_from_slice(&request[4..8]);
                let address = b"203.0.113.7";
                response[8..8 + address.len()].copy_from_slice(address);
                response[72..74].copy_from_slice(&50_000_u16.to_be_bytes());
                udp.send_to(&response, peer)
                    .map_err(|error| format!("UDP response failed: {error}"))?;
                received += 1;
            }
            Ok(received)
        })();
        result
    });

    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (result_sender, result_receiver) = std::sync::mpsc::channel();
    let server = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(3);
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
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|error| format!("set control timeout failed: {error}"))?;
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream
            .write_all(&frame(0x000a, &greeting))
            .map_err(|error| format!("write datapath greeting failed: {error}"))?;

        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[127, 0, 0, 1]);
        key[17..21].copy_from_slice(&[192, 0, 2, 1]);
        key[33..35].copy_from_slice(&server_port.to_be_bytes());
        key[35..37].copy_from_slice(&50_000_u16.to_be_bytes());
        key[37] = 17;
        let event = r2k_core::control::R2oVoiceSuspectEvent {
            key,
            client_is_low: false,
        };
        stream
            .write_all(&frame(
                r2k_core::control::EVENT_R2O_VOICE_SUSPECT,
                &event.event_body().unwrap(),
            ))
            .map_err(|error| format!("write voice event failed: {error}"))?;
        result_receiver
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| format!("Discovery responder did not finish: {error}"))?;
        Ok(())
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--serve",
            socket_path.to_str().unwrap(),
            catalog_path.to_str().unwrap(),
            "--discover",
            "--mark",
            "291",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let process_stdout = child.stdout.take().unwrap();
    let output_reader = thread::spawn(move || -> std::io::Result<String> {
        use std::io::BufRead;

        let mut reader = std::io::BufReader::new(process_stdout);
        let mut output = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            output.push_str(&line);
            if line.contains("поиск Discord Discovery") {
                let _ = result_sender.send(());
            }
        }
        Ok(output)
    });
    let output = child.wait_with_output().unwrap();
    let stdout = output_reader.join().unwrap().unwrap();
    let discovery_result = discovery.join().unwrap();
    let server_result = server.join().unwrap();
    assert!(
        output.status.success(),
        "r2o-controller Discord discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server_result.unwrap();
    match discovery_result {
        Ok(received) => {
            assert!(
                mark_supported,
                "Discord Discovery sent packets without a usable SO_MARK"
            );
            assert_eq!(
                received,
                usize::from(r2o_controller::voice_discovery::R2O_DISCOVERY_EXCHANGES)
            );
        }
        Err(error) => {
            assert!(
                !mark_supported,
                "Discord Discovery failed despite a usable SO_MARK: {error}"
            );
            assert_eq!(error, "received only 0 Discord Discovery requests");
            assert!(stdout.contains("поиск Discord Discovery"));
            assert!(!stdout.contains("временный адресный план поставлен для следующего потока"));
            fs::remove_dir_all(work).unwrap();
            return;
        }
    }
    assert!(stdout.contains("обнаружен Discord voice"));
    assert!(stdout.contains("зонд поставлен в ограниченную очередь"));
    assert!(stdout.contains("Discovery отвечает без кандидата на исправление"));
    fs::remove_dir_all(work).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn serve_discover_applies_confirms_persists_and_reapplies_voice_candidate() {
    use r2k_core::control::{
        AppliedEvent, BindingContext, COMMAND_DEL_VOICE_ADDR_PROBE, COMMAND_SET_ADDR,
        COMMAND_SET_VOICE_ADDR, COMMAND_SET_VOICE_ADDR_PROBE, EVENT_APPLIED, EVENT_R2O_VOICE_PROOF,
        R2oVoiceProofEvent, R2oVoiceProofKind, SHAPE_VOICE,
    };
    use std::net::{Ipv4Addr, SocketAddr};

    const MARK: u32 = 291;
    if !can_set_socket_mark(MARK)
        || r2o_datapath::raw::RawSocket::open(libc::AF_INET, MARK, None).is_err()
    {
        eprintln!("skipping Discovery candidate flow: SO_MARK or CAP_NET_RAW is unavailable");
        return;
    }

    let work = temporary_directory();
    fs::create_dir(&work).unwrap();
    // WSL DrvFS cannot host AF_UNIX sockets; keep only the ephemeral socket in tmpfs.
    let socket_root = PathBuf::from("/dev/shm").join(work.file_name().unwrap());
    fs::create_dir(&socket_root).unwrap();
    let socket_path = socket_root.join("control.sock");
    let catalog_path = work.join("catalog.json");
    fs::write(&catalog_path, br#"{"boxes":[]}"#).unwrap();

    let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let server_port = udp.local_addr().unwrap().port();
    let (discovery_done_sender, discovery_done_receiver) = std::sync::mpsc::channel();
    let discovery = thread::spawn(move || -> Result<(usize, usize), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut direct = std::collections::HashMap::<SocketAddr, (usize, Instant)>::new();
        let mut candidates = std::collections::HashSet::<SocketAddr>::new();
        let mut request = [0; 2048];
        loop {
            if discovery_done_receiver.try_recv().is_ok() {
                return Ok((direct.len(), candidates.len()));
            }
            if Instant::now() >= deadline {
                return Err("controller did not install a Discovery candidate".into());
            }
            let (length, peer) = match udp.recv_from(&mut request) {
                Ok(packet) => packet,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(format!("UDP receive failed: {error}")),
            };
            if length == 20 && r2k_core::stun::is_binding_request(&request[..length]) {
                candidates.insert(peer);
                continue;
            }
            let candidate_request = length == 74 && request[8..72].iter().any(|byte| *byte != 0);
            if candidate_request {
                candidates.insert(peer);
            }
            if length != 74
                || (!r2k_core::stun::is_discord_ip_discovery_request(&request[..length])
                    && !candidate_request
                    && !candidates.contains(&peer))
            {
                return Err(format!(
                    "unexpected Discord Discovery request length {length}"
                ));
            }

            let answer = if candidates.contains(&peer) {
                true
            } else {
                let entry = direct.entry(peer).or_insert((0, Instant::now()));
                if entry.1.elapsed() >= Duration::from_millis(500) {
                    entry.0 = 0;
                }
                entry.1 = Instant::now();
                if entry.0 < 24 {
                    entry.0 += 1;
                    true
                } else {
                    false
                }
            };
            if answer {
                let mut response = [0; 74];
                response[..4].copy_from_slice(&[0, 2, 0, 70]);
                response[4..8].copy_from_slice(&request[4..8]);
                let address = b"203.0.113.7";
                response[8..8 + address.len()].copy_from_slice(address);
                response[72..74].copy_from_slice(&50_000_u16.to_be_bytes());
                udp.send_to(&response, peer)
                    .map_err(|error| format!("UDP response failed: {error}"))?;
            }
        }
    });

    let listener = UnixListener::bind(&socket_path).unwrap();
    let mut flow_key = [0; KEY_LEN];
    flow_key[0] = 4;
    flow_key[1..5].copy_from_slice(&[127, 0, 0, 1]);
    flow_key[17..21].copy_from_slice(&[192, 0, 2, 1]);
    flow_key[33..35].copy_from_slice(&server_port.to_be_bytes());
    flow_key[35..37].copy_from_slice(&50_000_u16.to_be_bytes());
    flow_key[37] = 17;
    let server = thread::spawn(move || -> Result<[u8; 16], String> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|error| format!("control accept failed: {error}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .map_err(|error| format!("set control timeout failed: {error}"))?;
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream
            .write_all(&frame(0x000a, &greeting))
            .map_err(|error| format!("write datapath greeting failed: {error}"))?;
        let event = r2k_core::control::R2oVoiceSuspectEvent {
            key: flow_key,
            client_is_low: false,
        };
        stream
            .write_all(&frame(
                r2k_core::control::EVENT_R2O_VOICE_SUSPECT,
                &event.event_body().unwrap(),
            ))
            .map_err(|error| format!("write voice event failed: {error}"))?;

        let (kind, body) = read_frame_io(&mut stream)
            .map_err(|error| format!("wait for Discovery candidate command: {error}"))?;
        if kind != COMMAND_SET_VOICE_ADDR_PROBE || body.len() < 30 {
            return Err(format!("expected voice trial command, got {kind:#06x}"));
        }
        if body[..4] != [192, 0, 2, 1]
            || body[4..8] != [127, 0, 0, 1]
            || u16::from_be_bytes([body[8], body[9]]) != server_port
        {
            return Err("voice trial command changed its Discovery target".into());
        }
        let plan_records = &body[14..body.len() - 16];
        let plan = r2k_core::plan::Plan::parse(plan_records)
            .map_err(|error| format!("invalid voice trial plan: {error}"))?;
        if plan.transport != 17 || plan.proto != r2k_core::plan::PROTO_VOICE {
            return Err("Discovery candidate was not installed as a UDP voice plan".into());
        }
        let trial_id: [u8; 16] = body[body.len() - 16..]
            .try_into()
            .map_err(|_| "invalid trial ID")?;
        discovery_done_sender
            .send(())
            .map_err(|error| format!("stop Discovery fixture: {error}"))?;

        let applied = AppliedEvent {
            key: flow_key,
            plan_id: plan.id,
            trial_id,
            execution_id: 1,
            binding: BindingContext {
                generation: 1,
                kind: 2,
                family: 4,
                shape: SHAPE_VOICE,
                temporary: true,
                epoch: [1; 16],
            },
        };
        stream
            .write_all(&frame(EVENT_APPLIED, &applied.event_body().unwrap()))
            .map_err(|error| format!("write exact APPLIED event failed: {error}"))?;
        let proof = R2oVoiceProofEvent {
            key: flow_key,
            trial_id,
            proof: R2oVoiceProofKind::DiscordDiscovery {
                mapped_ip: Ipv4Addr::new(203, 0, 113, 7),
                mapped_port: 50_000,
            },
        };
        stream
            .write_all(&frame(EVENT_R2O_VOICE_PROOF, &proof.event_body().unwrap()))
            .map_err(|error| format!("write Discovery proof event failed: {error}"))?;

        let (kind, body) = read_frame(&mut stream);
        if kind != COMMAND_SET_VOICE_ADDR || body[..4] != [127, 0, 0, 1] {
            return Err(format!("expected permanent voice command, got {kind:#06x}"));
        }
        let permanent_plan = r2k_core::plan::Plan::parse(&body[4..])
            .map_err(|error| format!("invalid permanent voice plan: {error}"))?;
        if permanent_plan.id != plan.id {
            return Err("permanent plan ID differs from the tested candidate".into());
        }
        stream
            .write_all(&r2k_core::control::encode_ack(COMMAND_SET_VOICE_ADDR, true, 0).unwrap())
            .map_err(|error| format!("ack permanent voice plan failed: {error}"))?;

        let (kind, body) = read_frame(&mut stream);
        if kind != COMMAND_DEL_VOICE_ADDR_PROBE || body.len() < 26 {
            return Err(format!("expected trial removal command, got {kind:#06x}"));
        }
        if body[4..8] != [127, 0, 0, 1] || body[8..10] != server_port.to_be_bytes() {
            return Err("trial removal command changed its target".into());
        }
        stream
            .write_all(
                &r2k_core::control::encode_ack_for_trial(
                    COMMAND_DEL_VOICE_ADDR_PROBE,
                    true,
                    0,
                    Some(trial_id),
                )
                .unwrap(),
            )
            .map_err(|error| format!("ack trial removal failed: {error}"))?;
        Ok(plan.id)
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--serve",
            socket_path.to_str().unwrap(),
            catalog_path.to_str().unwrap(),
            "--discover",
            "--mark",
            "291",
        ])
        .output()
        .unwrap();
    let server_result = server.join().unwrap();
    let discovery_result = discovery.join().unwrap();
    assert!(
        output.status.success(),
        "r2o-controller voice Discovery failed; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let applied_plan_id = server_result.unwrap_or_else(|error| {
        panic!(
            "Discovery control fixture failed: {error}; stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let (direct_flows, candidate_flows) = discovery_result.unwrap_or_else(|error| {
        panic!(
            "Discovery UDP fixture failed: {error}; stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(direct_flows, 3, "all three direct cutoffs must be measured");
    assert_eq!(
        candidate_flows, 3,
        "all three candidate repeats must be sent"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Ответ Discord Discovery подтверждён"),
        "controller did not report confirmation: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let persisted = fs::read_to_string(&catalog_path).unwrap();
    let plan_id_hex: String = applied_plan_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(persisted.contains(&plan_id_hex));
    assert!(persisted.contains("127.0.0.1"));

    let reapply_socket = socket_root.join("reapply.sock");
    let reapply_listener = UnixListener::bind(&reapply_socket).unwrap();
    let reapply_server = thread::spawn(move || {
        let (mut stream, _) = reapply_listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut greeting = vec![0; KEY_LEN];
        greeting[0] = 4;
        greeting.extend_from_slice(&PROTO_VERSION.to_be_bytes());
        greeting.extend_from_slice(&65_535_u32.to_be_bytes());
        greeting.extend_from_slice(&[3, b'd', b'e', b'v']);
        stream.write_all(&frame(0x000a, &greeting)).unwrap();
        let (kind, body) = read_frame(&mut stream);
        assert_eq!(kind, COMMAND_SET_ADDR);
        assert_eq!(body[0], 4);
        assert_eq!(body[1..5], [127, 0, 0, 1]);
        assert_eq!(body[17], SHAPE_VOICE);
        let plan = r2k_core::plan::Plan::parse(&body[18..]).unwrap();
        assert_eq!(plan.id, applied_plan_id);
        stream
            .write_all(&r2k_core::control::encode_ack(COMMAND_SET_ADDR, true, 0).unwrap())
            .unwrap();
    });
    let reapply = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--apply-catalog",
            reapply_socket.to_str().unwrap(),
            catalog_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        reapply.status.success(),
        "r2o-controller catalog reapply failed: {}",
        String::from_utf8_lossy(&reapply.stderr)
    );
    reapply_server.join().unwrap();
    fs::remove_dir_all(socket_root).unwrap();
    fs::remove_dir_all(work).unwrap();
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
fn apply_catalog_compiles_and_sends_tcp_and_discord_voice_name_bindings() {
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
    assert!(String::from_utf8_lossy(&output.stdout).contains("отправлено 2"));
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
        let bypass_area_id = body[body.len() - 16..].to_vec();
        expected.extend_from_slice(&bypass_area_id);
        assert_eq!(body, expected);
        let mut ack = vec![0; KEY_LEN];
        ack[0] = 4;
        ack.extend_from_slice(&[0x00, 0x8e, 1, 0]);
        ack.extend_from_slice(&bypass_area_id);
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
        let suffix_area_id = body[body.len() - 16..].to_vec();
        expected.extend_from_slice(&suffix_area_id);
        assert_eq!(body, expected);
        let mut ack = vec![0; KEY_LEN];
        ack[0] = 4;
        ack.extend_from_slice(&[0x00, 0x8c, 1, 0]);
        ack.extend_from_slice(&suffix_area_id);
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
    assert!(String::from_utf8_lossy(&output.stdout).contains("отправлено 2"));
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
    assert!(String::from_utf8_lossy(&output.stdout).contains("отправлено 0"));
}

#[test]
fn apply_catalog_sends_name_bindings_without_waiting_for_acknowledgements() {
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

        let (kind, rejected) = read_frame(&mut stream);
        assert_eq!(kind, 0x0081);
        assert!(
            rejected
                .windows(b"rejected.example.test".len())
                .any(|part| part == b"rejected.example.test")
        );

        let (kind, accepted) = read_frame(&mut stream);
        assert_eq!(kind, 0x0081);
        assert!(
            accepted
                .windows(b"accepted.example.test".len())
                .any(|part| part == b"accepted.example.test")
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
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("каталог обработан: отправлено 2"));
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

fn read_frame_io(stream: &mut UnixStream) -> std::io::Result<(u16, Vec<u8>)> {
    let mut header = [0; 6];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
    if !(2..=65_536).contains(&length) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid control frame length",
        ));
    }
    let kind = u16::from_be_bytes(header[4..6].try_into().unwrap());
    let mut body = vec![0; length - 2];
    stream.read_exact(&mut body)?;
    Ok((kind, body))
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
