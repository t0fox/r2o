use r2o_panel::server::{Config, handle_request};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[test]
#[ignore = "run through scripts/test-panel-config-mode-differential.sh"]
fn d2o_worker_config_write_preserves_mode_ignoring_umask() {
    let config_path = PathBuf::from(
        std::env::var_os("R2O_PANEL_MODE_CONFIG").expect("test helper provides config path"),
    );
    let service = PathBuf::from(
        std::env::var_os("R2O_PANEL_MODE_SERVICE").expect("test helper provides service path"),
    );
    let c_trace = fs::read_to_string(
        std::env::var_os("R2O_PANEL_MODE_C_TRACE").expect("test helper provides D2O trace"),
    )
    .unwrap();

    let mut config = Config::default();
    config.config_path = config_path.clone();
    config.service_path = service;
    config.control_enabled = true;

    let body = r#"{"domains":["New.Example"]}"#;
    let raw = format!(
        "POST /api/telegram/workers HTTP/1.1\r\nHost: localhost:8090\r\nOrigin: http://localhost:8090\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let old_umask = unsafe { libc::umask(0o077) };
    let response = handle_request(&config, raw.as_bytes());
    unsafe { libc::umask(old_umask) };
    assert_eq!(response.status, 202);

    let metadata = fs::metadata(&config_path).unwrap();
    let saved = fs::read(&config_path).unwrap();
    let config_hex = saved
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let trace = format!(
        "mode={:04o}\nconfig={config_hex}\n",
        metadata.permissions().mode() & 0o777
    );
    assert_eq!(trace, c_trace);
}
