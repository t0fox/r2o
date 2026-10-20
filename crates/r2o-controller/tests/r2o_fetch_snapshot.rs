#[cfg(unix)]
#[test]
fn r2o_fetch_snapshot_берёт_длину_именно_для_запрошенного_sni() {
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let work = std::env::temp_dir().join(format!("r2o-fetch-snapshot-{nonce}"));
    std::fs::create_dir(&work).unwrap();
    let control_socket = work.join("datapath.sock");
    let snapshot_socket = r2k_core::control::r2k_snapshot_socket_path(&control_socket);
    let listener = UnixListener::bind(&snapshot_socket).unwrap();
    let datapath = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .write_all(&r2k_core::control::encode_greeting(4096).unwrap())
            .unwrap();
        for (host, shape, length) in [
            ("other.test", r2k_core::control::SHAPE_MODERN, Some(900_u16)),
            ("example.test", r2k_core::control::SHAPE_HTTP, None),
            (
                "example.test",
                r2k_core::control::SHAPE_MODERN,
                Some(1275_u16),
            ),
        ] {
            let mut body = vec![0; r2k_core::control::KEY_LEN];
            body[0] = 4;
            body[37] = 6;
            body.push(host.len() as u8);
            body.extend_from_slice(host.as_bytes());
            body.push(shape);
            if let Some(length) = length {
                body.extend_from_slice(&length.to_be_bytes());
            }
            stream
                .write_all(
                    &r2k_core::control::encode_frame(r2k_core::control::EVENT_HELLO, &body)
                        .unwrap(),
                )
                .unwrap();
        }
    });

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-fetch"))
        .args([
            "--name",
            "example.test",
            "--port",
            "0",
            "--wire",
            "2000",
            "--snapshot=1000",
        ])
        .arg("--control")
        .arg(&control_socket)
        .output()
        .expect("запустить r2o-fetch");
    let error = String::from_utf8_lossy(&output.stderr);

    assert!(
        error.contains("снято приветствие браузера: 1275 байт"),
        "r2o-fetch не выбрал точную длину ClientHello: {error}"
    );
    assert!(
        error.contains("порт должен быть"),
        "ожидалась ошибка порта: {error}"
    );
    datapath.join().unwrap();
    std::fs::remove_dir_all(work).unwrap();
}
