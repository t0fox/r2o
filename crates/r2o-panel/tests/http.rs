use r2o_panel::server::{Config, handle_request, parse_config};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "r2o-panel-{}-{}",
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

fn request(config: &Config, raw: &str) -> (u16, String, String) {
    let response = handle_request(config, raw.as_bytes());
    (
        response.status,
        response.content_type,
        String::from_utf8(response.body).unwrap(),
    )
}

#[test]
fn status_without_live_file_returns_the_panel_contract() {
    let mut config = Config::default();
    config.live_path =
        std::env::temp_dir().join(format!("r2o-missing-live-{}", std::process::id()));
    let (status, content_type, body) = request(
        &config,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert!(content_type.starts_with("application/json"));
    let value: Value = serde_json::from_str(&body).unwrap();
    assert!(value["snapshot"].is_object());
    assert!(value["knowledge"].is_object());
    assert_eq!(value["knowledge"]["linked"], false);
    assert_eq!(value["knowledge"]["boxes"], serde_json::json!([]));
    assert_eq!(value["snapshot"]["controls_enabled"], false);
}

#[cfg(unix)]
#[test]
fn status_accepts_rust_telegram_stats_snapshot() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    let temp = TempDir::new();
    let socket_path = temp.file("telegram-stats.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let stats = serde_json::json!({
        "process_started_at": 1_800_000_000_u64,
        "listener_ready": true,
        "active_connections": 1,
        "active_sessions": [{
            "id": 1,
            "dc": 2,
            "is_media": false,
            "stage": "upstream_ready",
            "direct_state": "connected",
            "direct_transport": "direct_wss",
            "fallback_state": "idle",
            "fallback_transport": null,
            "selected_transport": "direct_wss",
            "telegram_response_seen": true,
            "events": []
        }],
        "route_sessions_truncated": false,
        "max_connections": 128,
        "accepted_connections": 7,
        "wss_established": 5,
        "mtproto_success": 4,
        "mtproto_failure": 1,
        "last_mtproto_response_at": 1_800_000_001_u64,
        "dc_map": {"generation": 1, "fetched_at": 1, "freshness_seconds": 5},
        "cf_domain_pool": {"domains": [], "fetched_at": 1, "freshness_seconds": 5},
        "workers": {},
        "sessions_by_dc_transport": {"dc2:direct-wss": 4},
        "failures": {"tls": 1},
        "ttfb": {},
        "rss_kib": 1024,
        "rss_hwm_kib": 2048
    });
    let encoded = serde_json::to_vec(&stats).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 32];
        let _ = stream.read(&mut request).unwrap();
        stream.write_all(&encoded).unwrap();
    });
    let mut config = Config::default();
    config.telegram_stats_path = socket_path;
    let (_, _, body) = request(
        &config,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    server.join().unwrap();
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["snapshot"]["telegram_stats"]["mtproto_success"], 4);
    assert_eq!(
        value["snapshot"]["telegram_stats"]["ttfb"],
        serde_json::json!({})
    );
}

#[test]
fn control_requires_same_origin() {
    let mut config = Config::default();
    config.control_enabled = true;
    let (status, _, _) = request(
        &config,
        "POST /api/control/start HTTP/1.1\r\nHost: router.local\r\nOrigin: http://attacker.local\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(status, 403);
}

#[test]
fn telegram_start_failure_is_exposed_when_listener_is_not_running() {
    let temp = TempDir::new();
    let config_path = temp.file("config");
    fs::write(&config_path, "TG_ENABLED=1\nTG_MODE=local\n").unwrap();
    let telegram_status_path = temp.file("telegram.status");
    fs::write(&telegram_status_path, "error\n").unwrap();
    let mut config = Config::default();
    config.config_path = config_path;
    config.telegram_status_path = telegram_status_path;
    config.telegram_pid_path = temp.file("missing-telegram.pid");

    let (status, _, body) = request(
        &config,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 200);
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["snapshot"]["telegram_running"], false);
    assert_eq!(value["snapshot"]["telegram_status"], "error");
}

#[test]
fn control_routes_reject_get() {
    let (status, _, _) = request(
        &Config::default(),
        "GET /api/control/start HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 405);
}

#[test]
fn root_serves_existing_panel_html() {
    let (status, content_type, body) = request(
        &Config::default(),
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert!(content_type.starts_with("text/html"));
    assert!(body.contains("<!doctype html") || body.contains("<!DOCTYPE html"));
}

#[test]
fn updater_absence_is_reported_as_json() {
    let mut config = Config::default();
    config.updater_path =
        std::env::temp_dir().join(format!("r2o-no-updater-{}", std::process::id()));
    let (status, content_type, body) = request(
        &config,
        "GET /api/update HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert!(content_type.starts_with("application/json"));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["absent"],
        true
    );
}

#[cfg(unix)]
#[test]
fn installed_manager_exposes_update_state_and_drives_update_actions() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let manager = temp.file("r2o-manager");
    let arguments = temp.file("manager-arguments");
    fs::write(
        &manager,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
            arguments.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.file("install-root");
    let service_arguments = temp.file("service-arguments");
    let service = temp.file("S99r2o");
    fs::write(
        &service,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\n",
            service_arguments.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&service, fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = Config::default();
    config.manager_path = manager;
    config.manager_root = root.clone();
    config.update_state_path = root.join("state/update.json");
    config.service_path = service.clone();
    config.control_enabled = true;

    let (status, _, body) = request(
        &config,
        "GET /api/update HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["never"], true);

    let (status, _, body) = request(
        &config,
        "POST /api/control/update-check HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(status, 202);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["ok"], true);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !arguments.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read_to_string(arguments).unwrap(),
        format!("update-check\n--root\n{}\n", root.display())
    );

    for action in ["update-auto-on", "update-auto-off"] {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (status, _, body) = request(
                &config,
                &format!(
                    "POST /api/control/{action} HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n"
                ),
            );
            if status == 202 {
                break;
            }
            assert_eq!(status, 409, "{body}");
            assert!(Instant::now() < deadline, "service action stayed busy");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while !fs::read_to_string(&service_arguments)
        .is_ok_and(|args| args.contains("update-auto-on\n") && args.contains("update-auto-off\n"))
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    let service_log = fs::read_to_string(&service_arguments).unwrap();
    assert!(service_log.contains("update-auto-on\n"));
    assert!(service_log.contains("update-auto-off\n"));

    let mut install_config = Config::default();
    install_config.manager_path = config.manager_path.clone();
    install_config.manager_root = root;
    install_config.service_path = service;
    install_config.control_enabled = true;
    let (status, _, _) = request(
        &install_config,
        "POST /api/control/update-install HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(status, 202);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !fs::read_to_string(&service_arguments)
        .is_ok_and(|arguments| arguments.ends_with("update-install\n"))
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        fs::read_to_string(service_arguments)
            .unwrap()
            .ends_with("update-install\n")
    );
}

#[cfg(unix)]
#[test]
fn router_actions_use_service_when_manager_is_installed() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let manager = temp.file("r2o-manager");
    fs::write(&manager, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();
    let service_arguments = temp.file("service-arguments");
    let service = temp.file("S99r2o");
    fs::write(
        &service,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\n",
            service_arguments.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&service, fs::Permissions::from_mode(0o700)).unwrap();

    for (enabled, action) in [
        ("0", "telegram-enable"),
        ("1", "telegram-disable"),
        ("0", "clear-found"),
    ] {
        let config_name = format!("config-{enabled}");
        let config_path = temp.file(&config_name);
        fs::write(
            &config_path,
            format!("TG_ENABLED={enabled}\nTG_MODE=local\n"),
        )
        .unwrap();
        let mut config = Config::default();
        config.manager_path = manager.clone();
        config.service_path = service.clone();
        config.config_path = config_path;
        config.control_enabled = true;

        let (status, _, body) = request(
            &config,
            &format!(
                "POST /api/control/{action} HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n"
            ),
        );
        assert_eq!(status, 202, "{body}");
        let expected = format!("{action}\n");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if fs::read_to_string(&service_arguments).is_ok_and(|args| args.ends_with(&expected)) {
                break;
            }
            assert!(Instant::now() < deadline, "router service was not called");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn live_catalog_revision_reuses_only_catalog_arrays() {
    let temp = TempDir::new();
    let live = temp.file("live.json");
    let engine_pid = temp.file("engine.pid");
    let controller_pid = temp.file("controller.pid");
    fs::write(&engine_pid, format!("{}\n", std::process::id())).unwrap();
    fs::write(&controller_pid, format!("{}\n", std::process::id())).unwrap();
    let source = "{ \"linked\":true, \"catalog_at\":\"now\", \"boxes\":[{\"id\": \"one\"}], \"groups\":[{\"suffix\":\"example.test\"}], \"searches\":[], \"probes_used\":7 }";
    fs::write(&live, source).unwrap();
    let mut config = Config::default();
    config.live_path = live;
    config.engine_pid_path = engine_pid;
    config.controller_pid_path = controller_pid;

    let (_, _, full_body) = request(
        &config,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    let full: Value = serde_json::from_str(&full_body).unwrap();
    let revision = full["catalog_revision"].as_str().unwrap();
    assert_eq!(full["snapshot"]["live_fresh"], true);
    assert_eq!(full["knowledge"]["linked"], true);
    assert_eq!(full["knowledge"]["probes_used"], 7);

    let (_, _, slim_body) = request(
        &config,
        &format!("GET /api/status?catalog_revision={revision} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    );
    let slim: Value = serde_json::from_str(&slim_body).unwrap();
    assert_eq!(slim["catalog_unchanged"], true);
    assert_eq!(slim["knowledge"]["boxes"], Value::Null);
    assert_eq!(slim["knowledge"]["groups"], Value::Null);
    assert_eq!(slim["knowledge"]["probes_used"], 7);
}

#[test]
fn static_assets_use_etag_and_return_not_modified() {
    let config = Config::default();
    let first = handle_request(
        &config,
        b"GET /assets/panel.js HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(first.status, 200);
    let etag = first
        .headers
        .iter()
        .find(|(name, _)| name == "ETag")
        .unwrap()
        .1
        .clone();
    assert_eq!(
        first
            .headers
            .iter()
            .find(|(name, _)| name == "Cache-Control")
            .unwrap()
            .1,
        "no-cache"
    );
    let raw = format!(
        "GET /assets/panel.js HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: {etag}\r\n\r\n"
    );
    let unchanged = handle_request(&config, raw.as_bytes());
    assert_eq!(unchanged.status, 304);
    assert!(unchanged.body.is_empty());
}

#[test]
fn worker_domains_are_normalized_and_saved_without_losing_other_config() {
    let temp = TempDir::new();
    let config_path = temp.file("config");
    let service_path = temp.file("service.sh");
    fs::write(
        &config_path,
        "MODE=apply\nKEEP_ME=yes\nTG_CF_WORKER_DOMAIN=https://Example.COM/path,media.example.net\n",
    )
    .unwrap();
    fs::write(&service_path, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&service_path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = Config::default();
    config.config_path = config_path.clone();
    config.service_path = service_path;
    config.control_enabled = true;
    let (status, _, body) = request(
        &config,
        "GET /api/telegram/workers HTTP/1.1\r\nHost: router.local\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["domains"],
        serde_json::json!(["example.com", "media.example.net"])
    );

    let body = r#"{"domains":["New.Workers.Dev","new.workers.dev"]}"#;
    let raw = format!(
        "POST /api/telegram/workers HTTP/1.1\r\nHost: router.local\r\nOrigin: http://router.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let response = handle_request(&config, raw.as_bytes());
    assert_eq!(response.status, 202);
    let saved = fs::read_to_string(config_path).unwrap();
    assert!(saved.contains("KEEP_ME=yes"));
    assert_eq!(saved.matches("TG_CF_WORKER_DOMAIN=").count(), 1);
    assert!(saved.contains("TG_CF_WORKER_DOMAIN=new.workers.dev\n"));
}

#[cfg(unix)]
#[test]
fn r2o_служебная_команда_панели_остаётся_асинхронной() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new();
    let service = temp.file("service.sh");
    let r2o_started_marker = temp.file("r2o-started");
    let r2o_release_marker = temp.file("r2o-release");
    fs::write(
        &service,
        "#!/bin/sh\nr2o_base=${0%/*}\nprintf started >\"$r2o_base/r2o-started\"\nr2o_count=0\nwhile [ ! -e \"$r2o_base/r2o-release\" ] && [ \"$r2o_count\" -lt 300 ]; do\n sleep 0.01\n r2o_count=$((r2o_count + 1))\ndone\nexit 7\n",
    )
    .unwrap();
    fs::set_permissions(&service, fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = Config::default();
    config.service_path = service;
    config.control_enabled = true;
    let raw = b"POST /api/control/stop HTTP/1.1\r\nHost: router.local\r\nOrigin: http://router.local\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(handle_request(&config, raw).status, 202);
    let started_deadline = Instant::now() + Duration::from_secs(2);
    while !r2o_started_marker.exists() {
        assert!(
            Instant::now() < started_deadline,
            "команда службы не запустилась"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let (_, _, running) = request(
        &config,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(
        serde_json::from_str::<Value>(&running).unwrap()["snapshot"]["control_state"],
        "running"
    );
    fs::write(r2o_release_marker, "готово").unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let (_, _, finished) = request(
            &config,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        let state = serde_json::from_str::<Value>(&finished).unwrap()["snapshot"]["control_state"]
            .as_str()
            .unwrap()
            .to_owned();
        if state == "failed" {
            break;
        }
        assert_eq!(state, "running");
        assert!(
            Instant::now() < deadline,
            "slow service action did not finish"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn config_parser_honors_overrides_and_keeps_unknown_keys_visible() {
    let temp = TempDir::new();
    let path = temp.file("config");
    fs::write(
        &path,
        "MODE=apply\nQUEUE_NUM=1234\nR2O_PPE_DEOFFLOAD=1\nFUTURE_KEY='not parsed'\n",
    )
    .unwrap();
    let mut config = Config::default();
    parse_config(&path, &mut config, &["mode"]).unwrap();
    assert_eq!(config.mode, "observe");
    assert_eq!(config.queue_num, 1234);
    assert_eq!(config.unknown_keys, ["FUTURE_KEY"]);
    fs::write(&path, "MODE=broken\n").unwrap();
    assert!(parse_config(&path, &mut config, &["mode"]).is_err());
    fs::write(&path, "SCHEMA=+1\n").unwrap();
    assert!(parse_config(&path, &mut config, &[]).is_err());
    fs::write(&path, "QUEUE_NUM=+2000\n").unwrap();
    assert!(parse_config(&path, &mut config, &[]).is_err());
    fs::write(&path, format!("FUTURE_KEY={}\n", "x".repeat(2040))).unwrap();
    assert!(parse_config(&path, &mut config, &[]).is_err());
}
