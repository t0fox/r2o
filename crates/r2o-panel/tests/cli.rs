use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(10_000);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "r2o-panel-cli-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn get(address: std::net::SocketAddr, path: &str) -> std::io::Result<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(100))?;
    stream.set_read_timeout(Some(Duration::from_millis(300)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        address.port()
    )?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = std::str::from_utf8(&response[..split])
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    Ok((status, response[split + 4..].to_vec()))
}

fn stop(child: &mut Child) {
    #[cfg(unix)]
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    panic!("r2o-panel did not exit after SIGTERM");
}

#[test]
fn cli_starts_http_panel_writes_health_and_stops_cleanly() {
    let temp = TempDir::new();
    let health = temp.file("panel.health");
    let port_probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = port_probe.local_addr().unwrap();
    drop(port_probe);
    let mut child = Command::new(env!("CARGO_BIN_EXE_r2o-panel"))
        .args(["serve", "--listen", &address.to_string(), "--health-file"])
        .arg(&health)
        .arg("--state-dir")
        .arg(temp.file("state"))
        .arg("--service")
        .arg(temp.file("missing-service"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(4);
    let status = loop {
        if child.try_wait().unwrap().is_some() {
            panic!("r2o-panel exited before binding the HTTP socket");
        }
        if let Ok((200, body)) = get(address, "/api/status") {
            break serde_json::from_slice::<Value>(&body).unwrap();
        }
        assert!(Instant::now() < deadline, "r2o-panel did not answer HTTP");
        thread::sleep(Duration::from_millis(40));
    };
    assert_eq!(status["snapshot"]["controls_enabled"], true);
    assert_eq!(status["snapshot"]["mode"], "observe");
    let heartbeat = fs::read_to_string(&health).unwrap();
    assert!(heartbeat.starts_with(&format!("R2OH1 {} ", child.id())));
    assert!(heartbeat.ends_with(" 20 - 0 1 1\n"));
    let (code, page) = get(address, "/").unwrap();
    assert_eq!(code, 200);
    assert!(String::from_utf8(page).unwrap().contains("id=\"app\""));
    stop(&mut child);
}

#[test]
fn cli_version_is_reported_without_starting_the_server() {
    let output = Command::new(env!("CARGO_BIN_EXE_r2o-panel"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("r2o-panel release="));
    assert!(stdout.contains("features=telegram-control update-control"));
}

#[test]
fn cli_rejects_zero_port_instead_of_binding_an_ephemeral_port() {
    let temp = TempDir::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_r2o-panel"))
        .args(["serve", "--listen", "127.0.0.1:0", "--config"])
        .arg(temp.file("missing-config"))
        .arg("--health-file")
        .arg(temp.file("health"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(300));
    let exited = child.try_wait().unwrap().is_some();
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert!(
        exited,
        "port 0 must fail validation instead of starting the panel"
    );
}
