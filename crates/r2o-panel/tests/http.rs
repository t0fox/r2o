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
fn panel_default_bind_matches_d2o_config_and_server_fallback() {
    let d2o_default = include_str!("fixtures/d2o-panel-listen-default.txt")
        .lines()
        .find_map(|line| line.strip_prefix("PANEL_LISTEN="))
        .unwrap();
    assert_eq!(Config::default().panel_listen, d2o_default);
}

#[cfg(unix)]
#[test]
fn diagnostics_api_matches_d2o_opt_in_download_and_same_origin_contract() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let state = temp.file("state");
    fs::create_dir(&state).unwrap();
    let mut config = Config::default();
    config.state_dir = state.clone();
    config.control_enabled = true;

    let disabled = handle_request(
        &config,
        b"GET /api/diagnostics?report HTTP/1.1\r\nHost: router.local\r\n\r\n",
    );
    assert_eq!(disabled.status, 200);
    assert_eq!(disabled.body, br#"{"enabled":false}"#);
    assert!(
        disabled
            .headers
            .iter()
            .any(|(name, value)| name == "Cache-Control" && value == "no-store")
    );

    let forged = handle_request(
        &config,
        b"POST /api/diagnostics?enable HTTP/1.1\r\nHost: router.local\r\nOrigin: http://attacker.local\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(forged.status, 403);

    let enabled = handle_request(
        &config,
        b"POST /api/diagnostics?enable HTTP/1.1\r\nHost: router.local\r\nOrigin: http://router.local\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(enabled.status, 200);
    let dir = state.join("diagnostics");
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(dir.join("enabled"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let pending = handle_request(
        &config,
        b"GET /api/diagnostics?report HTTP/1.1\r\nHost: router.local\r\n\r\n",
    );
    assert_eq!(pending.status, 503);
    assert_eq!(pending.body, br#"{"enabled":true,"pending":true}"#);
    fs::write(
        dir.join("report.json"),
        br#"{"schema":1,"events":[],"samples":[]}"#,
    )
    .unwrap();
    let download = handle_request(
        &config,
        b"GET /api/diagnostics?download HTTP/1.1\r\nHost: router.local\r\n\r\n",
    );
    assert_eq!(download.status, 200);
    assert!(download.headers.iter().any(
        |(name, value)| name == "Content-Disposition" && value.contains("r2o-diagnostics.json")
    ));
    assert!(
        download
            .headers
            .iter()
            .any(|(name, value)| name == "Cache-Control" && value == "no-store")
    );

    let disabled = handle_request(
        &config,
        b"POST /api/diagnostics?disable HTTP/1.1\r\nHost: router.local\r\nOrigin: http://router.local\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(disabled.status, 200);
    assert!(!dir.join("enabled").exists());
    assert!(!dir.join("report.json").exists());
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
    for counter in ["targets", "confirms", "probes_used", "client_unfit"] {
        assert_eq!(
            value["knowledge"][counter],
            Value::Null,
            "{counter} is unknown without a live snapshot"
        );
    }
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
fn root_serves_panel_layout_without_non_d2o_settings_controls() {
    let (status, content_type, body) = request(
        &Config::default(),
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert!(content_type.starts_with("text/html"));
    assert!(body.contains("<!doctype html") || body.contains("<!DOCTYPE html"));
    assert!(body.contains(r#"<main id="app">"#));
    assert!(body.contains("id=\"diagnostics\""));
    assert!(!body.contains("href=\"#r2o-settings\""));
    assert!(!body.contains("id=\"r2o-settings\""));
    assert!(!body.contains("id=\"r2o-settings-form\""));
    let (status, _, _) = request(
        &Config::default(),
        "GET /api/config HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(
        status, 404,
        "панель не должна предоставлять API управления настройками"
    );
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
#[ignore = "run through scripts/test-panel-control-response-differential.sh"]
fn d2o_control_action_response_trace() {
    let service = std::env::var_os("R2O_PANEL_CONTROL_SERVICE")
        .expect("test helper provides a fake service")
        .into();
    let mut config = Config::default();
    config.service_path = service;
    config.control_enabled = true;

    let success = request(
        &config,
        "POST /api/control/stop HTTP/1.1\r\nHost: localhost:8090\r\nOrigin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n",
    );
    let busy = request(
        &config,
        "POST /api/control/stop HTTP/1.1\r\nHost: localhost:8090\r\nOrigin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n",
    );
    config.service_path.clear();
    let start_error = request(
        &config,
        "POST /api/control/stop HTTP/1.1\r\nHost: localhost:8090\r\nOrigin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n",
    );
    let trace = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        success.0, success.2, busy.0, busy.2, start_error.0, start_error.2
    );
    println!("{trace}");
    let parse_trace = |trace: &str| {
        let lines = trace.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 6, "control response trace has six lines");
        lines
            .chunks_exact(2)
            .map(|pair| {
                (
                    pair[0].parse::<u16>().unwrap(),
                    serde_json::from_str::<Value>(pair[1]).unwrap(),
                )
            })
            .collect::<Vec<_>>()
    };
    if let Some(path) = std::env::var_os("R2O_PANEL_CONTROL_TRACE_OUTPUT") {
        fs::write(path, &trace).unwrap();
    }
    let c_path = std::env::var_os("R2O_PANEL_CONTROL_C_TRACE")
        .expect("test helper provides the D2O C trace");
    let c_trace = fs::read_to_string(c_path).unwrap();
    assert_eq!(parse_trace(&c_trace), parse_trace(&trace));
    assert_eq!(success.0, 202);
    assert_eq!(busy.0, 409);
    assert_eq!(start_error.0, 500);
}

#[cfg(unix)]
#[test]
#[ignore = "run through scripts/test-panel-workers-busy-differential.sh"]
fn d2o_worker_busy_response_does_not_persist_new_domains() {
    let service = std::env::var_os("R2O_PANEL_WORKER_SERVICE")
        .expect("test helper provides a fake service")
        .into();
    let config_path = std::env::var_os("R2O_PANEL_WORKER_CONFIG")
        .expect("test helper provides a config file")
        .into();
    let mut config = Config::default();
    config.service_path = service;
    config.config_path = config_path;
    config.control_enabled = true;

    let stop = request(
        &config,
        "POST /api/control/stop HTTP/1.1\r\nHost: localhost:8090\r\nOrigin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n",
    );
    let body = r#"{"domains":["new.example"]}"#;
    let worker_request = format!(
        "POST /api/telegram/workers HTTP/1.1\r\nHost: localhost:8090\r\nOrigin: http://localhost:8090\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let workers = request(&config, &worker_request);
    let current_config = fs::read_to_string(&config.config_path).unwrap();
    let normalized_config = current_config.replace('\n', "|");
    let trace = format!(
        "{}\n{}\n{}\n{}\nconfig:{}\n",
        stop.0, stop.2, workers.0, workers.2, normalized_config
    );
    println!("{trace}");
    if let Some(path) = std::env::var_os("R2O_PANEL_WORKER_TRACE_OUTPUT") {
        fs::write(path, &trace).unwrap();
    }
    let c_trace = fs::read_to_string(
        std::env::var_os("R2O_PANEL_WORKER_C_TRACE").expect("test helper provides the D2O C trace"),
    )
    .unwrap();
    let parse_trace = |trace: &str| {
        let lines = trace.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 5, "worker busy trace has five lines");
        let responses = lines[..4]
            .chunks_exact(2)
            .map(|pair| {
                (
                    pair[0].parse::<u16>().unwrap(),
                    serde_json::from_str::<Value>(pair[1]).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        (responses, lines[4].to_owned())
    };
    assert_eq!(parse_trace(&c_trace), parse_trace(&trace));
    assert_eq!(stop.0, 202);
    assert_eq!(workers.0, 409);
    assert_eq!(
        current_config,
        "MODE=apply\nTG_CF_WORKER_DOMAIN=old.example\n"
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
fn status_merges_independent_controller_live_snapshots() {
    let temp = TempDir::new();
    let live4 = temp.file("live4.json");
    let live6 = temp.file("live6.json");
    let engine_pid = temp.file("engine.pid");
    let controller_pid = temp.file("controller.pid");
    fs::write(&engine_pid, format!("{}\n", std::process::id())).unwrap();
    fs::write(&controller_pid, format!("{}\n", std::process::id())).unwrap();
    fs::write(
        &live4,
        r#"{"linked":true,"catalog_at":"catalog.json","boxes":[],"groups":[],"searches":[{"target":"v4.example","family":4,"transport":6,"ip":"192.0.2.4","port":443,"phase":"проверка"}],"measurements":{"active":2,"queued":1,"limit":4,"cores":2,"free_pct":90},"autopick":{"datapath_events":12,"suspect_events":3,"target":"v4.example"},"targets":0,"confirms":0,"probes_used":7,"client_unfit":1}"#,
    )
    .unwrap();
    fs::write(
        &live6,
        r#"{"linked":true,"catalog_at":"catalog.json","boxes":[{"id":"box6"}],"groups":[{"suffix":"ipv6.example"}],"searches":[{"target":"v6.example","family":6,"transport":6,"ip":"2001:db8::6","port":443,"phase":"кандидат"}],"measurements":{"active":1,"queued":0,"limit":2,"cores":2,"free_pct":88},"autopick":{"datapath_events":8,"suspect_events":2,"target":"v6.example"},"targets":1,"confirms":1,"probes_used":5,"client_unfit":2}"#,
    )
    .unwrap();
    let mut config = Config::default();
    config.live_path = live4;
    config.live_extra_paths = vec![live6];
    config.engine_pid_path = engine_pid;
    config.controller_pid_path = controller_pid;

    let (status, _, body) = request(
        &config,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 200);
    let value: Value = serde_json::from_str(&body).unwrap();
    let knowledge = &value["knowledge"];
    assert_eq!(knowledge["searches"].as_array().unwrap().len(), 2);
    assert_eq!(knowledge["measurements"]["active"], 3);
    assert_eq!(knowledge["measurements"]["queued"], 1);
    assert_eq!(knowledge["measurements"]["limit"], 6);
    assert_eq!(knowledge["probes_used"], 12);
    assert_eq!(knowledge["client_unfit"], 3);
    assert_eq!(knowledge["autopick"]["datapath_events"], 20);
    assert_eq!(knowledge["boxes"][0]["id"], "box6");
    let revision = value["catalog_revision"].as_str().unwrap();
    let (_, _, cached_body) = request(
        &config,
        &format!("GET /api/status?catalog_revision={revision} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    );
    let cached: Value = serde_json::from_str(&cached_body).unwrap();
    assert_eq!(cached["catalog_unchanged"], true);
    assert_eq!(cached["knowledge"]["boxes"], Value::Null);
    assert_eq!(cached["knowledge"]["searches"].as_array().unwrap().len(), 2);
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

#[test]
fn status_accepts_only_complete_telegram_diagnostics() {
    let temp = TempDir::new();
    let state = temp.file("state");
    fs::create_dir(&state).unwrap();
    let report_path = state.join("telegram-diagnostics.json");
    let report = serde_json::json!({
        "checked_at": 1_800_000_000_u64,
        "state": "partial",
        "data_centers": [
            {"dc":1,"state":"healthy","routes":[{"transport":"direct-wss","state":"healthy"}]},
            {"dc":2,"state":"blocked","routes":[]},
            {"dc":3,"state":"unavailable","routes":[]},
            {"dc":4,"state":"unverified","routes":[]},
            {"dc":5,"state":"healthy","routes":[]}
        ]
    });
    fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
    let mut config = Config::default();
    config.state_dir = state;

    let (_, _, body) = request(
        &config,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["snapshot"]["telegram_diagnostics"], report);

    fs::write(
        &report_path,
        br#"{"checked_at":1800000000,"state":"healthy","data_centers":[]}"#,
    )
    .unwrap();
    let (_, _, body) = request(
        &config,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["snapshot"]["telegram_diagnostics"]["state"], "never");
}

#[cfg(unix)]
#[test]
fn telegram_check_runs_as_an_authenticated_async_service_action() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let config_path = temp.file("config");
    let service = temp.file("service.sh");
    let started = temp.file("started");
    let release = temp.file("release");
    fs::write(&config_path, "TG_ENABLED=0\nTG_MODE=local\n").unwrap();
    fs::write(
        &service,
        format!(
            "#!/bin/sh\n[ \"$1\" = telegram-check ] || exit 8\nprintf started > '{}'\nwhile [ ! -e '{}' ]; do sleep 0.01; done\n",
            started.display(),
            release.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&service, fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = Config::default();
    config.config_path = config_path;
    config.service_path = service;
    config.state_dir = temp.file("state");
    config.control_enabled = true;

    let raw = b"POST /api/control/telegram-check HTTP/1.1\r\nHost: router.local\r\nOrigin: http://other.local\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(handle_request(&config, raw).status, 403);
    let raw = b"POST /api/control/telegram-check HTTP/1.1\r\nHost: router.local\r\nOrigin: http://router.local\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(handle_request(&config, raw).status, 202);

    let deadline = Instant::now() + Duration::from_secs(10);
    while !started.exists() {
        assert!(
            Instant::now() < deadline,
            "проверка Telegram не запустилась"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let (_, _, body) = request(
        &config,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        value["snapshot"]["telegram_diagnostics"]["state"],
        "running"
    );
    fs::write(&release, "done").unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (_, _, body) = request(
            &config,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        let value: Value = serde_json::from_str(&body).unwrap();
        if value["snapshot"]["control_state"] == "done" {
            assert_eq!(value["snapshot"]["telegram_diagnostics"]["state"], "never");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "проверка Telegram не завершилась"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
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
    // The service starts on a background thread; allow a loaded CI worker to schedule it.
    let started_deadline = Instant::now() + Duration::from_secs(30);
    while !r2o_started_marker.exists() {
        let (_, _, current) = request(
            &config,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        let state = serde_json::from_str::<Value>(&current).unwrap()["snapshot"]["control_state"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            state, "running",
            "service action stopped before its start marker"
        );
        assert!(
            Instant::now() < started_deadline,
            "команда службы не запустилась"
        );
        std::thread::sleep(Duration::from_millis(10));
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
    let deadline = Instant::now() + Duration::from_secs(10);
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
