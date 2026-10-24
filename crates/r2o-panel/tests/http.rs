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
fn root_serves_panel_layout_with_settings_screen() {
    let (status, content_type, body) = request(
        &Config::default(),
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert!(content_type.starts_with("text/html"));
    assert!(body.contains("<!doctype html") || body.contains("<!DOCTYPE html"));
    assert!(body.contains(r#"<main id="app">"#));
    assert!(body.contains("id=\"diagnostics\""));
    assert!(body.contains("href=\"#r2o-settings\""));
    assert!(body.contains("id=\"r2o-settings\""));
    assert!(body.contains("id=\"r2o-settings-form\""));
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

#[cfg(unix)]
#[test]
fn r2o_settings_are_read_saved_and_restart_services() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let config_path = temp.file("config");
    let service_path = temp.file("S99r2o");
    let service_log = temp.file("service-arguments");
    fs::write(
        &config_path,
        "# Основные настройки\nMODE=observe # режим R2O\nQUEUE_NUM=2000 # очередь IPv4\nQUEUE_NUM6=2001\nR2O_FLOW_CAPACITY=2048\nIPV6_ENABLED=1\nMARK=45\nPROBE_MARK=0\nONLY_MARK=\nFW_BACKEND=auto\nPORTS=0:65535\nCONNBYTES=0:8\nVOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344\nVOICE_CONNBYTES=0:4\nHTTP_KEEPALIVE_PORTS=80\nDNS_PORTS=53,853\nTG_PORT=1445\nR2O_PPE_DEOFFLOAD=1\nLOGMAX=2097152\nLOGKEEP=1048576\nLOG_EVERY=60\nKEEP_ME=yes\n",
    )
    .unwrap();
    fs::write(
        &service_path,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
            service_log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&service_path, fs::Permissions::from_mode(0o700)).unwrap();

    let mut config = Config::default();
    config.config_path = config_path.clone();
    config.service_path = service_path;
    config.control_enabled = true;

    let (r2o_status, _, r2o_body) = request(
        &config,
        "GET /api/config HTTP/1.1\r\nHost: router.local\r\n\r\n",
    );
    assert_eq!(r2o_status, 200);
    let r2o_settings: Value = serde_json::from_str(&r2o_body).unwrap();
    assert_eq!(r2o_settings["mode"], "observe");
    assert_eq!(r2o_settings["queue_num"], 2000);
    assert_eq!(r2o_settings["queue_num6"], 2001);
    assert_eq!(r2o_settings["flow_capacity"], 2048);
    assert_eq!(r2o_settings["ipv6_enabled"], true);
    assert_eq!(r2o_settings["mark"], "45");
    assert_eq!(r2o_settings["probe_mark"], "0");
    assert_eq!(r2o_settings["only_mark"], "");
    assert_eq!(r2o_settings["firewall_backend"], "auto");
    assert_eq!(r2o_settings["ports"], "0:65535");
    assert_eq!(r2o_settings["connbytes"], "0:8");
    assert_eq!(
        r2o_settings["voice_ports"],
        "50000:50099,1400,3478:3481,5349,19294:19344"
    );
    assert_eq!(r2o_settings["voice_connbytes"], "0:4");
    assert_eq!(r2o_settings["http_keepalive_ports"], "80");
    assert_eq!(r2o_settings["dns_ports"], "53,853");
    assert_eq!(r2o_settings["tg_port"], 1445);
    assert_eq!(r2o_settings["ppe_deoffload"], true);
    assert_eq!(r2o_settings["log_max"], 2097152);
    assert_eq!(r2o_settings["log_keep"], 1048576);
    assert_eq!(r2o_settings["log_every"], 60);
    assert_eq!(r2o_settings["editable"], true);

    let r2o_body = r#"{"mode":"apply","queue_num":321,"queue_num6":322,"flow_capacity":4096,"ipv6_enabled":false,"mark":"0x2d","probe_mark":"7","only_mark":"9/255","firewall_backend":"nft","ports":"80,443","connbytes":"0:12","voice_ports":"3478:3481","voice_connbytes":"0:6","http_keepalive_ports":"8080","dns_ports":"53,853,5353","tg_port":1444,"ppe_deoffload":false,"log_max":4194304,"log_keep":2097152,"log_every":120}"#;
    let r2o_raw = format!(
        "POST /api/config HTTP/1.1\r\nHost: router.local\r\nOrigin: http://router.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{r2o_body}",
        r2o_body.len()
    );
    let r2o_response = handle_request(&config, r2o_raw.as_bytes());
    assert_eq!(r2o_response.status, 202);

    let r2o_saved = fs::read_to_string(&config_path).unwrap();
    assert!(r2o_saved.contains("# Основные настройки\n"));
    assert!(r2o_saved.contains("KEEP_ME=yes\n"));
    assert_eq!(r2o_saved.matches("MODE=").count(), 1);
    assert_eq!(r2o_saved.matches("QUEUE_NUM=").count(), 1);
    assert!(r2o_saved.contains("MODE=apply # режим R2O\n"));
    assert!(r2o_saved.contains("QUEUE_NUM=321 # очередь IPv4\n"));
    assert!(r2o_saved.contains("QUEUE_NUM6=322\n"));
    assert!(r2o_saved.contains("R2O_FLOW_CAPACITY=4096\n"));
    assert!(r2o_saved.contains("IPV6_ENABLED=0\n"));
    assert!(r2o_saved.contains("MARK=0x2d\n"));
    assert!(r2o_saved.contains("PROBE_MARK=7\n"));
    assert!(r2o_saved.contains("ONLY_MARK=9/255\n"));
    assert!(r2o_saved.contains("FW_BACKEND=nft\n"));
    assert!(r2o_saved.contains("PORTS=80,443\n"));
    assert!(r2o_saved.contains("CONNBYTES=0:12\n"));
    assert!(r2o_saved.contains("VOICE_PORTS=3478:3481\n"));
    assert!(r2o_saved.contains("VOICE_CONNBYTES=0:6\n"));
    assert!(r2o_saved.contains("HTTP_KEEPALIVE_PORTS=8080\n"));
    assert!(r2o_saved.contains("DNS_PORTS=53,853,5353\n"));
    assert!(r2o_saved.contains("TG_PORT=1444\n"));
    assert!(r2o_saved.contains("R2O_PPE_DEOFFLOAD=0\n"));
    assert!(r2o_saved.contains("LOGMAX=4194304\n"));
    assert!(r2o_saved.contains("LOGKEEP=2097152\n"));
    assert!(r2o_saved.contains("LOG_EVERY=120\n"));

    let r2o_deadline = Instant::now() + Duration::from_secs(2);
    let mut r2o_arguments = String::new();
    while Instant::now() < r2o_deadline {
        if let Ok(arguments) = fs::read_to_string(&service_log) {
            if arguments == "settings-restart\n" {
                r2o_arguments = arguments;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(r2o_arguments, "settings-restart\n");
    let (r2o_disabled_status, _, r2o_disabled_body) = request(
        &config,
        "GET /api/config HTTP/1.1\r\nHost: router.local\r\n\r\n",
    );
    assert_eq!(r2o_disabled_status, 200);
    let r2o_disabled_settings: Value = serde_json::from_str(&r2o_disabled_body).unwrap();
    assert_eq!(r2o_disabled_settings["ppe_deoffload"], false);

    let mut r2o_off_settings: Value = serde_json::from_str(r2o_body).unwrap();
    r2o_off_settings["mode"] = Value::String("off".into());
    r2o_off_settings["ppe_deoffload"] = Value::Bool(true);
    let r2o_off_body = r2o_off_settings.to_string();
    let r2o_off_raw = format!(
        "POST /api/config HTTP/1.1\r\nHost: router.local\r\nOrigin: http://router.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{r2o_off_body}",
        r2o_off_body.len()
    );
    let r2o_off_deadline = Instant::now() + Duration::from_secs(2);
    let mut r2o_off_status = 409;
    while Instant::now() < r2o_off_deadline {
        r2o_off_status = handle_request(&config, r2o_off_raw.as_bytes()).status;
        if r2o_off_status != 409 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(r2o_off_status, 202);
    let r2o_stop_deadline = Instant::now() + Duration::from_secs(2);
    let mut r2o_stop_arguments = String::new();
    while Instant::now() < r2o_stop_deadline {
        if let Ok(arguments) = fs::read_to_string(&service_log) {
            if arguments == "settings-restart\n" {
                r2o_stop_arguments = arguments;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(r2o_stop_arguments, "settings-restart\n");
    assert!(
        fs::read_to_string(config_path)
            .unwrap()
            .contains("R2O_PPE_DEOFFLOAD=1\n")
    );
    let (r2o_enabled_status, _, r2o_enabled_body) = request(
        &config,
        "GET /api/config HTTP/1.1\r\nHost: router.local\r\n\r\n",
    );
    assert_eq!(r2o_enabled_status, 200);
    let r2o_enabled_settings: Value = serde_json::from_str(&r2o_enabled_body).unwrap();
    assert_eq!(r2o_enabled_settings["ppe_deoffload"], true);
}

#[test]
fn r2o_settings_reject_invalid_firewall_port_lists_and_connbytes_windows() {
    let temp = TempDir::new();
    let config_path = temp.file("config");
    fs::write(&config_path, "MODE=observe\nQUEUE_NUM=2000\nKEEP_ME=yes\n").unwrap();
    let mut config = Config::default();
    config.config_path = config_path.clone();
    config.control_enabled = true;
    let before = fs::read_to_string(&config_path).unwrap();
    let valid = serde_json::json!({
        "mode":"apply", "queue_num":321, "queue_num6":322, "flow_capacity":2048,
        "ipv6_enabled":true, "mark":"1", "probe_mark":"0", "only_mark":"",
        "firewall_backend":"auto", "ports":"0:65535", "connbytes":"0:8",
        "voice_ports":"50000:50099,1400,3478:3481,5349,19294:19344",
        "voice_connbytes":"0:4", "http_keepalive_ports":"80", "dns_ports":"53,853",
        "tg_port":1443, "ppe_deoffload":true,
        "log_max":2097152, "log_keep":1048576, "log_every":60
    });
    for (key, value) in [
        ("ports", "80:80"),
        ("ports", "443;$(touch /tmp/r2o-injected)"),
        ("ports", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"),
        ("connbytes", "0:8:9"),
        ("voice_ports", "0:65536"),
        ("voice_connbytes", "8:4"),
        ("http_keepalive_ports", "80,,443"),
        ("dns_ports", "53, 853"),
        ("tg_port", "0"),
        ("tg_port", "65536"),
    ] {
        let mut body = valid.clone();
        body[key] = Value::String(value.into());
        let body = body.to_string();
        let raw = format!(
            "POST /api/config HTTP/1.1\r\nHost: router.local\r\nOrigin: http://router.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(
            handle_request(&config, raw.as_bytes()).status,
            400,
            "{key}={value}"
        );
    }
    let mut invalid_ppe = valid.clone();
    invalid_ppe["ppe_deoffload"] = Value::String("false".into());
    let invalid_ppe = invalid_ppe.to_string();
    let invalid_ppe_raw = format!(
        "POST /api/config HTTP/1.1\r\nHost: router.local\r\nOrigin: http://router.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{invalid_ppe}",
        invalid_ppe.len()
    );
    assert_eq!(
        handle_request(&config, invalid_ppe_raw.as_bytes()).status,
        400
    );
    assert_eq!(fs::read_to_string(config_path).unwrap(), before);
}

#[test]
fn r2o_settings_reject_invalid_values_and_cross_origin_writes() {
    let temp = TempDir::new();
    let config_path = temp.file("config");
    fs::write(&config_path, "MODE=observe\nQUEUE_NUM=2000\nKEEP_ME=yes\n").unwrap();
    let mut config = Config::default();
    config.config_path = config_path.clone();
    config.control_enabled = true;

    let r2o_before = fs::read_to_string(&config_path).unwrap();
    for r2o_body in [
        r#"{"mode":"apply\nTG_ENABLED=0","queue_num":321}"#,
        r#"{"mode":"apply","queue_num":65536}"#,
        r#"{"mode":"apply","queue_num":321,"state_dir":"/tmp"}"#,
        r#"{"mode":"apply","queue_num":321,"queue_num6":321,"flow_capacity":2048,"ipv6_enabled":true,"mark":"1","probe_mark":"0","only_mark":"","firewall_backend":"auto","ports":"0:65535","connbytes":"0:8","voice_ports":"50000:50099,1400,3478:3481,5349,19294:19344","voice_connbytes":"0:4","http_keepalive_ports":"80","dns_ports":"53,853","log_max":2097152,"log_keep":1048576,"log_every":60}"#,
        r#"{"mode":"apply","queue_num":321,"queue_num6":321,"flow_capacity":2048,"ipv6_enabled":true,"mark":"1","probe_mark":"0","only_mark":"","firewall_backend":"auto","ports":"0:65535","connbytes":"0:8","voice_ports":"50000:50099,1400,3478:3481,5349,19294:19344","voice_connbytes":"0:4","http_keepalive_ports":"80","dns_ports":"53,853","tg_port":1443,"log_max":2097152,"log_keep":1048576,"log_every":60}"#,
        r#"{"mode":"apply","queue_num":321,"queue_num6":322,"flow_capacity":2048,"ipv6_enabled":true,"mark":"0x2d","probe_mark":"45","only_mark":"","firewall_backend":"auto","ports":"0:65535","connbytes":"0:8","voice_ports":"50000:50099,1400,3478:3481,5349,19294:19344","voice_connbytes":"0:4","http_keepalive_ports":"80","dns_ports":"53,853","tg_port":1443,"log_max":2097152,"log_keep":1048576,"log_every":60}"#,
        r#"{"mode":"apply","queue_num":321,"queue_num6":322,"flow_capacity":0,"ipv6_enabled":true,"mark":"1","probe_mark":"0","only_mark":"","firewall_backend":"auto","ports":"0:65535","connbytes":"0:8","voice_ports":"50000:50099,1400,3478:3481,5349,19294:19344","voice_connbytes":"0:4","http_keepalive_ports":"80","dns_ports":"53,853","tg_port":1443,"log_max":2097152,"log_keep":1048576,"log_every":60}"#,
        r#"{"mode":"apply","queue_num":321,"queue_num6":322,"flow_capacity":2048,"ipv6_enabled":true,"mark":"1","probe_mark":"4294967296","only_mark":"","firewall_backend":"auto","ports":"0:65535","connbytes":"0:8","voice_ports":"50000:50099,1400,3478:3481,5349,19294:19344","voice_connbytes":"0:4","http_keepalive_ports":"80","dns_ports":"53,853","tg_port":1443,"log_max":2097152,"log_keep":1048576,"log_every":60}"#,
        r#"{"mode":"apply","queue_num":321,"queue_num6":322,"flow_capacity":2048,"ipv6_enabled":true,"mark":"1","probe_mark":"0","only_mark":"8/0","firewall_backend":"auto","ports":"0:65535","connbytes":"0:8","voice_ports":"50000:50099,1400,3478:3481,5349,19294:19344","voice_connbytes":"0:4","http_keepalive_ports":"80","dns_ports":"53,853","tg_port":1443,"log_max":2097152,"log_keep":1048576,"log_every":0}"#,
    ] {
        let r2o_raw = format!(
            "POST /api/config HTTP/1.1\r\nHost: router.local\r\nOrigin: http://router.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{r2o_body}",
            r2o_body.len()
        );
        assert_eq!(handle_request(&config, r2o_raw.as_bytes()).status, 400);
    }
    let r2o_body = r#"{"mode":"apply","queue_num":321}"#;
    let r2o_raw = format!(
        "POST /api/config HTTP/1.1\r\nHost: router.local\r\nOrigin: http://attacker.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{r2o_body}",
        r2o_body.len()
    );
    assert_eq!(handle_request(&config, r2o_raw.as_bytes()).status, 403);
    assert_eq!(fs::read_to_string(config_path).unwrap(), r2o_before);
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
