use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const REQUEST_MAX: usize = 16 * 1024;
const BODY_MAX: usize = 4 * 1024 * 1024;
const WORKER_BODY_MAX: usize = 4096;
const WORKER_MAX: usize = 8;
const TELEGRAM_DIAGNOSTICS_MAX: usize = 256 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
const UPDATE_CHECK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const UPDATE_INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static LAST_HEARTBEAT: Mutex<u64> = Mutex::new(0);

#[derive(Clone, Debug)]
pub struct Config {
    pub live_path: PathBuf,
    pub live_extra_paths: Vec<PathBuf>,
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
    pub asset_dir: PathBuf,
    pub health_path: PathBuf,
    pub service_path: PathBuf,
    pub update_state_path: PathBuf,
    pub updater_path: PathBuf,
    pub manager_path: PathBuf,
    pub manager_root: PathBuf,
    pub engine_pid_path: PathBuf,
    pub controller_pid_path: PathBuf,
    pub telegram_pid_path: PathBuf,
    pub telegram_status_path: PathBuf,
    pub telegram_stats_path: PathBuf,
    pub mode: String,
    pub panel_listen: String,
    pub version: String,
    pub commit: String,
    pub built: String,
    pub queue_num: u16,
    pub queue_num6: u16,
    pub flow_capacity: u32,
    pub ipv6_enabled: bool,
    pub mark: String,
    pub probe_mark: String,
    pub only_mark: String,
    pub firewall_backend: String,
    pub ports: String,
    pub connbytes: String,
    pub voice_ports: String,
    pub voice_connbytes: String,
    pub http_keepalive_ports: String,
    pub dns_ports: String,
    pub tg_port: u16,
    pub ppe_deoffload: bool,
    pub log_max: u32,
    pub log_keep: u32,
    pub log_every: u16,
    pub config_exists: bool,
    pub dirty: bool,
    pub control_enabled: bool,
    pub started_epoch: i64,
    pub unknown_keys: Vec<String>,
    telegram_check_running: Arc<AtomicBool>,
    action: Arc<Mutex<String>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            live_path: "/opt/r2o/state/live.json".into(),
            live_extra_paths: Vec::new(),
            config_path: "/opt/r2o/config".into(),
            state_dir: "/opt/r2o/state".into(),
            asset_dir: "/opt/r2o/panel".into(),
            health_path: "/tmp/r2o/r2o-panel.health".into(),
            service_path: "/opt/etc/init.d/S99r2o".into(),
            update_state_path: "/opt/r2o/state/update.json".into(),
            updater_path: "/opt/r2o/r2o-update.sh".into(),
            manager_path: "/opt/r2o/r2o-manager".into(),
            manager_root: "/opt/r2o".into(),
            engine_pid_path: "/opt/r2o/run/r2o-datapath.pid".into(),
            controller_pid_path: "/opt/r2o/run/r2o.pid".into(),
            telegram_pid_path: "/opt/r2o/run/r2o-telegram.pid".into(),
            telegram_status_path: "/opt/r2o/state/telegram.status".into(),
            telegram_stats_path: "/opt/r2o/state/telegram.stats.sock".into(),
            mode: "observe".into(),
            panel_listen: "127.0.0.1:8090".into(),
            version: "dev".into(),
            commit: String::new(),
            built: String::new(),
            queue_num: 2000,
            queue_num6: 2001,
            flow_capacity: 2048,
            ipv6_enabled: true,
            mark: "45".into(),
            probe_mark: "0".into(),
            only_mark: String::new(),
            firewall_backend: "auto".into(),
            ports: "0:65535".into(),
            connbytes: "0:8".into(),
            voice_ports: "50000:50099,1400,3478:3481,5349,19294:19344".into(),
            voice_connbytes: "0:4".into(),
            http_keepalive_ports: "80".into(),
            dns_ports: "53,853".into(),
            tg_port: 1443,
            ppe_deoffload: true,
            log_max: 2_097_152,
            log_keep: 1_048_576,
            log_every: 60,
            config_exists: false,
            dirty: false,
            control_enabled: false,
            started_epoch: 0,
            unknown_keys: Vec::new(),
            telegram_check_running: Arc::new(AtomicBool::new(false)),
            action: Arc::new(Mutex::new("idle".into())),
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl Response {
    fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            body: body.into(),
            headers: Vec::new(),
        }
    }

    fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn send(self, stream: &mut TcpStream) -> std::io::Result<()> {
        let reason = match self.status {
            200 => "OK",
            202 => "Accepted",
            304 => "Not Modified",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            415 => "Unsupported Media Type",
            431 => "Request Header Fields Too Large",
            409 => "Conflict",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Error",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Security-Policy: default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n",
            self.status,
            reason,
            self.content_type,
            self.body.len()
        )?;
        for (name, value) in self.headers {
            write!(stream, "{name}: {value}\r\n")?;
        }
        stream.write_all(b"\r\n")?;
        stream.write_all(&self.body)
    }
}

#[derive(Debug)]
struct Request<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    body: &'a [u8],
}

impl<'a> Request<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self, u16> {
        let end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or(400u16)?;
        if end > REQUEST_MAX {
            return Err(431);
        }
        let head = std::str::from_utf8(&raw[..end]).map_err(|_| 400u16)?;
        let mut lines = head.split("\r\n");
        let mut first = lines.next().ok_or(400u16)?.split_ascii_whitespace();
        let method = first.next().ok_or(400u16)?;
        let target = first.next().ok_or(400u16)?;
        let version = first.next().ok_or(400u16)?;
        if first.next().is_some()
            || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
            || !target.starts_with('/')
            || target.len() > 255
        {
            return Err(400);
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':').ok_or(400u16)?;
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(400);
            }
            headers.push((name, value.trim_matches([' ', '\t'])));
        }
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        Ok(Self {
            method,
            path,
            query,
            headers,
            body: &raw[end + 4..],
        })
    }

    fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    }
}

pub fn handle_request(config: &Config, raw: &[u8]) -> Response {
    let request = match Request::parse(raw) {
        Ok(request) => request,
        Err(431) => return text_response(431, "request too large\n"),
        Err(_) => return text_response(400, "bad request\n"),
    };
    if request.path == "/api/telegram/workers" {
        if !matches!(request.method, "GET" | "POST") {
            return text_response(405, "method not allowed\n");
        }
        return api_workers(config, &request);
    }
    if request.path == "/api/update" {
        if request.method != "GET" {
            return text_response(405, "method not allowed\n");
        }
        return api_update(config);
    }
    if request.path == "/api/diagnostics" {
        if !matches!(request.method, "GET" | "POST") {
            return Response::new(405, "text/plain; charset=utf-8", Vec::new())
                .header("Cache-Control", "no-store");
        }
        return api_diagnostics(config, &request);
    }
    if request.path.starts_with("/api/control/") {
        if request.method != "POST" {
            return text_response(405, "method not allowed\n");
        }
        return api_control(config, &request);
    }
    if request.method != "GET" {
        return text_response(405, "method not allowed\n");
    }
    if request.path == "/api/status" {
        return api_status(config, request.query);
    }
    if request.path == "/" {
        return static_asset(config, &request, "index.html", "text/html; charset=utf-8");
    }
    for (route, file, content_type) in [
        ("/assets/favicon.svg", "favicon.svg", "image/svg+xml"),
        (
            "/assets/refresh-mask.svg",
            "refresh-mask.svg",
            "image/svg+xml",
        ),
        ("/assets/panel.css", "panel.css", "text/css; charset=utf-8"),
        (
            "/assets/panel.js",
            "panel.js",
            "application/javascript; charset=utf-8",
        ),
        (
            "/assets/diagnostics.js",
            "diagnostics.js",
            "application/javascript; charset=utf-8",
        ),
        (
            "/assets/telegram-flow.js",
            "telegram-flow.js",
            "application/javascript; charset=utf-8",
        ),
        (
            "/assets/telegram-flow-prototype.js",
            "telegram-flow-prototype.js",
            "application/javascript; charset=utf-8",
        ),
        (
            "/assets/gsap.js",
            "gsap.js",
            "application/javascript; charset=utf-8",
        ),
        (
            "/assets/panel-motion.js",
            "panel-motion.js",
            "application/javascript; charset=utf-8",
        ),
        (
            "/assets/panel-lava.js",
            "panel-lava.js",
            "application/javascript; charset=utf-8",
        ),
        ("/assets/onest.woff2", "fonts/onest.woff2", "font/woff2"),
        ("/assets/jbmono.woff2", "fonts/jbmono.woff2", "font/woff2"),
        (
            "/assets/nunito-cyrillic.woff2",
            "fonts/nunito-cyrillic.woff2",
            "font/woff2",
        ),
        (
            "/assets/nunito-latin.woff2",
            "fonts/nunito-latin.woff2",
            "font/woff2",
        ),
        (
            "/assets/jetbrains-mono-lava.woff2",
            "fonts/jetbrains-mono-lava.woff2",
            "font/woff2",
        ),
    ] {
        if request.path == route {
            return static_asset(config, &request, file, content_type);
        }
    }
    text_response(404, "not found\n")
}

pub fn serve(listener: TcpListener, config: Config) -> std::io::Result<()> {
    STOP_REQUESTED.store(false, Ordering::Release);
    #[cfg(unix)]
    unsafe {
        let handler = stop_signal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
    listener.set_nonblocking(true)?;
    while !STOP_REQUESTED.load(Ordering::Acquire) {
        let _ = runtime_heartbeat(&config.health_path);
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let request = read_request(&mut stream)?;
        let response = match request {
            Ok(raw) => handle_request(&config, &raw),
            Err(status) => text_response(
                status,
                if status == 408 {
                    "request timeout\n"
                } else if status == 431 {
                    "request too large\n"
                } else {
                    "bad request\n"
                },
            ),
        };
        let _ = response.send(&mut stream);
    }
    Ok(())
}

#[cfg(unix)]
extern "C" fn stop_signal(_: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::Release);
}

#[cfg(unix)]
fn runtime_heartbeat(path: &Path) -> std::io::Result<()> {
    let now = monotonic_ms();
    let mut last = LAST_HEARTBEAT.lock().expect("heartbeat clock lock");
    if *last != 0 && now >= *last && now - *last < 1000 {
        return Ok(());
    }
    let pid = std::process::id();
    let start_ticks = fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|stat| {
            let close = stat.rfind(')')?;
            stat[close + 1..]
                .split_whitespace()
                .nth(19)?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0);
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local".into());
    let release = option_env!("R2O_RELEASE_ID").unwrap_or("dev");
    let body = format!("R2OH1 {pid} {start_ticks} {now} {boot} {release} 20 - 0 1 1\n");
    let temp = PathBuf::from(format!("{}.tmp.{pid}", path.display()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
    let mut file = options.open(&temp)?;
    if let Err(error) = file
        .write_all(body.as_bytes())
        .and_then(|_| file.sync_all())
    {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    drop(file);
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    *last = now;
    Ok(())
}

#[cfg(not(unix))]
fn runtime_heartbeat(_: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn monotonic_ms() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return 0;
    }
    (time.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add((time.tv_nsec as u64) / 1_000_000)
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Result<Vec<u8>, u16>> {
    let mut raw = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let header_end;
    loop {
        if raw.len() >= REQUEST_MAX {
            return Ok(Err(431));
        }
        let available = chunk.len().min(REQUEST_MAX + 1 - raw.len());
        match stream.read(&mut chunk[..available]) {
            Ok(0) => return Ok(Err(400)),
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(Err(408));
            }
            Err(e) => return Err(e),
        }
        if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = end + 4;
            break;
        }
    }
    let header = String::from_utf8_lossy(&raw[..header_end]);
    let is_workers_post = header
        .lines()
        .next()
        .is_some_and(|l| l.starts_with("POST /api/telegram/workers "));
    if !is_workers_post {
        return Ok(Ok(raw));
    }
    let length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if length > WORKER_BODY_MAX {
        return Ok(Err(400));
    }
    let expected = header_end.saturating_add(length);
    while raw.len() < expected {
        let available = (expected - raw.len()).min(chunk.len());
        match stream.read(&mut chunk[..available]) {
            Ok(0) => return Ok(Err(400)),
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(Err(408));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(Ok(raw))
}

fn text_response(status: u16, body: &str) -> Response {
    Response::new(
        status,
        "text/plain; charset=utf-8",
        body.as_bytes().to_vec(),
    )
}
fn json_response(status: u16, value: &Value) -> Response {
    Response::new(
        status,
        "application/json; charset=utf-8",
        serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
    )
}

const DIAGNOSTICS_REPORT_MAX: u64 = 256 * 1024;

fn diagnostic_response(status: u16, body: impl Into<Vec<u8>>) -> Response {
    Response::new(status, "application/json; charset=utf-8", body)
        .header("Cache-Control", "no-store")
}

fn api_diagnostics(config: &Config, request: &Request<'_>) -> Response {
    let dir = config.state_dir.join("diagnostics");
    if request.method == "POST" {
        if !config.control_enabled || !same_origin(request) {
            return diagnostic_response(
                403,
                "{\"error\":\"требуется запрос с того же источника\"}"
                    .as_bytes()
                    .to_vec(),
            );
        }
        if !matches!(request.query, "enable" | "disable") {
            return diagnostic_response(400, b"{}".to_vec());
        }
        if diagnostics_toggle(&dir, request.query == "enable").is_err() {
            return diagnostic_response(
                500,
                "{\"error\":\"не удалось изменить состояние диагностики\"}"
                    .as_bytes()
                    .to_vec(),
            );
        }
        return diagnostic_response(
            200,
            if diagnostics_enabled(&dir) {
                b"{\"enabled\":true}".to_vec()
            } else {
                b"{\"enabled\":false}".to_vec()
            },
        );
    }
    if !diagnostics_enabled(&dir) {
        return diagnostic_response(200, b"{\"enabled\":false}".to_vec());
    }
    if request.query == "status" {
        return diagnostic_response(200, b"{\"enabled\":true}".to_vec());
    }
    let path = dir.join("report.json");
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return diagnostic_response(503, b"{\"enabled\":true,\"pending\":true}".to_vec());
            }
            Err(_) => {
                return Response::new(500, "text/plain; charset=utf-8", Vec::new())
                    .header("Cache-Control", "no-store");
            }
        }
    };
    #[cfg(not(unix))]
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return diagnostic_response(503, b"{\"enabled\":true,\"pending\":true}".to_vec());
        }
        Err(_) => {
            return Response::new(500, "text/plain; charset=utf-8", Vec::new())
                .header("Cache-Control", "no-store");
        }
    };
    let Ok(metadata) = file.metadata() else {
        return Response::new(500, "text/plain; charset=utf-8", Vec::new())
            .header("Cache-Control", "no-store");
    };
    if !metadata.is_file() || metadata.len() > DIAGNOSTICS_REPORT_MAX {
        return Response::new(500, "text/plain; charset=utf-8", Vec::new())
            .header("Cache-Control", "no-store");
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    if file
        .take(DIAGNOSTICS_REPORT_MAX + 1)
        .read_to_end(&mut body)
        .is_err()
        || body.len() as u64 > DIAGNOSTICS_REPORT_MAX
    {
        return Response::new(503, "text/plain; charset=utf-8", Vec::new())
            .header("Cache-Control", "no-store");
    }
    let response = Response::new(200, "application/json; charset=utf-8", body)
        .header("Cache-Control", "no-store");
    if request.query == "download" {
        response.header(
            "Content-Disposition",
            "attachment; filename=\"r2o-diagnostics.json\"",
        )
    } else {
        response
    }
}

fn diagnostics_dir_valid(dir: &Path, create: bool) -> bool {
    if create {
        match fs::create_dir(dir) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).is_err() {
                        return false;
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return false,
        }
    }
    let Ok(metadata) = fs::symlink_metadata(dir) else {
        return false;
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        metadata.uid() == unsafe { libc::geteuid() } && metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn diagnostics_enabled(dir: &Path) -> bool {
    if !diagnostics_dir_valid(dir, false) {
        return false;
    }
    let Ok(metadata) = fs::symlink_metadata(dir.join("enabled")) else {
        return false;
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        metadata.uid() == unsafe { libc::geteuid() } && metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn diagnostics_toggle(dir: &Path, enabled: bool) -> std::io::Result<()> {
    if !diagnostics_dir_valid(dir, true) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "каталог диагностики небезопасен",
        ));
    }
    let marker = dir.join("enabled");
    if enabled {
        if diagnostics_enabled(dir) {
            return Ok(());
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(marker)?.sync_all()
    } else {
        for name in ["enabled", "report.json", "report.new"] {
            match fs::remove_file(dir.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

fn api_status(config: &Config, query: &str) -> Response {
    let mut live = read_json_object(&config.live_path, BODY_MAX);
    let engine_pid = pid_path_running(&config.engine_pid_path);
    let controller_running = pid_path_running(&config.controller_pid_path).is_some();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    for path in &config.live_extra_paths {
        let Some(extra) = read_json_object(path, BODY_MAX) else {
            continue;
        };
        let extra_mtime = fs::metadata(path)
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map(|modified| modified.as_secs());
        let extra_fresh = extra_mtime.is_some_and(|modified| {
            let within_window = if modified > now {
                modified - now <= 5
            } else {
                now - modified <= 15
            };
            let after_engine = engine_pid.is_none_or(|(_, started)| modified >= started);
            within_window && after_engine
        });
        if extra_fresh && extra.get("linked").and_then(Value::as_bool) == Some(true) {
            if let Some(live) = &mut live {
                merge_live_snapshot(live, &extra);
            }
        }
    }
    let live_mtime = live
        .as_ref()
        .and_then(|_| fs::metadata(&config.live_path).ok())
        .and_then(|m| m.modified().ok())
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|modified| modified.as_secs());
    let live_fresh = live_mtime.is_some_and(|modified| {
        let within_window = if modified > now {
            modified - now <= 5
        } else {
            now - modified <= 15
        };
        let after_engine = engine_pid.is_none_or(|(_, started)| modified >= started);
        within_window && after_engine
    });
    let have_catalog = live
        .as_ref()
        .and_then(|v| v.get("catalog_at"))
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    let linked = live
        .as_ref()
        .and_then(|v| v.get("linked"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && live_fresh
        && engine_pid.is_some()
        && controller_running;
    let (knowledge, revision, unchanged) = match live {
        Some(mut value) => {
            let revision = catalog_revision(&value);
            let unchanged = revision
                .as_ref()
                .is_some_and(|r| query.strip_prefix("catalog_revision=") == Some(r.as_str()));
            if let Some(object) = value.as_object_mut() {
                if object.contains_key("linked") {
                    object.insert("linked".into(), Value::Bool(linked));
                }
                if unchanged {
                    for key in ["boxes", "groups"] {
                        if object.contains_key(key) {
                            object.insert(key.into(), Value::Null);
                        }
                    }
                }
                (value, revision, unchanged)
            } else {
                unavailable_knowledge()
            }
        }
        None => unavailable_knowledge(),
    };
    let snapshot = snapshot(
        config,
        linked,
        have_catalog,
        live_fresh,
        engine_pid.is_some(),
        controller_running,
    );
    let mut result = json!({"snapshot": snapshot, "knowledge": knowledge});
    if let Some(revision) = revision {
        result["catalog_revision"] = Value::String(revision);
        result["catalog_unchanged"] = Value::Bool(unchanged);
    }
    json_response(200, &result)
}

fn merge_live_snapshot(primary: &mut Value, extra: &Value) {
    let primary_has_searches = primary
        .get("searches")
        .and_then(Value::as_array)
        .is_some_and(|searches| !searches.is_empty());
    let extra_searches = extra.get("searches").and_then(Value::as_array);
    let extra_has_searches = extra_searches.is_some_and(|searches| !searches.is_empty());
    let primary_events = primary["autopick"]["datapath_events"].as_u64().unwrap_or(0);
    let extra_events = extra["autopick"]["datapath_events"].as_u64().unwrap_or(0);
    let primary_suspects = primary["autopick"]["suspect_events"].as_u64().unwrap_or(0);
    let extra_suspects = extra["autopick"]["suspect_events"].as_u64().unwrap_or(0);
    let take_extra_autopick = extra_has_searches && !primary_has_searches
        || (extra_has_searches == primary_has_searches && extra_events > primary_events);

    let mut seen = HashSet::new();
    if let Some(searches) = primary.get("searches").and_then(Value::as_array) {
        for search in searches {
            seen.insert(live_search_key(search));
        }
    }
    if let Some(searches) = primary.get_mut("searches").and_then(Value::as_array_mut) {
        if let Some(extra_searches) = extra_searches {
            for search in extra_searches {
                if seen.insert(live_search_key(search)) {
                    searches.push(search.clone());
                }
            }
        }
    }

    for key in ["probes_used", "client_unfit"] {
        add_live_counter(primary, extra, key);
    }
    if let Some(primary_autopick) = primary.get_mut("autopick").and_then(Value::as_object_mut) {
        for key in ["datapath_events", "suspect_events"] {
            let sum = primary_autopick
                .get(key)
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .saturating_add(extra["autopick"][key].as_u64().unwrap_or(0));
            primary_autopick.insert(key.into(), Value::from(sum));
        }
    }
    if take_extra_autopick && let Some(autopick) = extra.get("autopick") {
        primary["autopick"] = autopick.clone();
        if let Some(primary_autopick) = primary.get_mut("autopick").and_then(Value::as_object_mut) {
            primary_autopick.insert(
                "datapath_events".into(),
                Value::from(primary_events.saturating_add(extra_events)),
            );
            primary_autopick.insert(
                "suspect_events".into(),
                Value::from(primary_suspects.saturating_add(extra_suspects)),
            );
        }
    }

    if let Some(primary_measurements) = primary
        .get_mut("measurements")
        .and_then(Value::as_object_mut)
    {
        for key in ["active", "queued", "limit"] {
            let sum = primary_measurements
                .get(key)
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .saturating_add(extra["measurements"][key].as_u64().unwrap_or(0));
            primary_measurements.insert(key.into(), Value::from(sum));
        }
        merge_live_min(primary_measurements, extra, "free_pct");
        merge_live_min(primary_measurements, extra, "mem_avail_mb");
        merge_live_max(primary_measurements, extra, "cores");
        merge_live_max(primary_measurements, extra, "mem_total_mb");
        merge_live_max(primary_measurements, extra, "conntrack_pct");
        if primary_measurements
            .get("limited_by")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            && let Some(value) = extra["measurements"].get("limited_by")
        {
            primary_measurements.insert("limited_by".into(), value.clone());
        }
    }

    let primary_confirms = primary["confirms"].as_u64().unwrap_or(0);
    let extra_confirms = extra["confirms"].as_u64().unwrap_or(0);
    let primary_targets = primary["targets"].as_u64().unwrap_or(0);
    let extra_targets = extra["targets"].as_u64().unwrap_or(0);
    if extra_confirms > primary_confirms || extra_targets > primary_targets {
        for key in ["boxes", "groups", "targets", "confirms"] {
            if let Some(value) = extra.get(key) {
                primary[key] = value.clone();
            }
        }
    }
}

fn live_search_key(search: &Value) -> String {
    let identity = ["target", "family", "transport", "ip", "port"]
        .map(|field| search.get(field).cloned().unwrap_or(Value::Null));
    serde_json::to_string(&identity).unwrap_or_default()
}

fn add_live_counter(primary: &mut Value, extra: &Value, key: &str) {
    let sum = primary[key]
        .as_u64()
        .unwrap_or(0)
        .saturating_add(extra[key].as_u64().unwrap_or(0));
    primary[key] = Value::from(sum);
}

fn merge_live_min(primary: &mut serde_json::Map<String, Value>, extra: &Value, key: &str) {
    if let Some(value) = extra["measurements"][key].as_u64() {
        let current = primary.get(key).and_then(Value::as_u64).unwrap_or(value);
        primary.insert(key.into(), Value::from(current.min(value)));
    }
}

fn merge_live_max(primary: &mut serde_json::Map<String, Value>, extra: &Value, key: &str) {
    if let Some(value) = extra["measurements"][key].as_u64() {
        let current = primary.get(key).and_then(Value::as_u64).unwrap_or(value);
        primary.insert(key.into(), Value::from(current.max(value)));
    }
}

fn unavailable_knowledge() -> (Value, Option<String>, bool) {
    (
        json!({"linked":false,"link_note":"движок не отдаёт состояние","catalog_at":"","boxes":[],"searches":[],"targets":null,"confirms":null,"probes_used":null,"client_unfit":null}),
        None,
        false,
    )
}

fn snapshot(
    config: &Config,
    linked: bool,
    have_catalog: bool,
    live_fresh: bool,
    engine_running: bool,
    controller_running: bool,
) -> Value {
    let now = OffsetDateTime::now_utc();
    let taken = now
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
    let started = if config.started_epoch > 0 {
        OffsetDateTime::from_unix_timestamp(config.started_epoch)
            .ok()
            .and_then(|v| v.format(&Rfc3339).ok())
            .unwrap_or_else(|| "0001-01-01T00:00:00Z".into())
    } else {
        "0001-01-01T00:00:00Z".into()
    };
    let uptime = if config.started_epoch > 0 {
        now.unix_timestamp()
            .saturating_sub(config.started_epoch)
            .max(0) as u64
    } else {
        0
    };
    let (tg_enabled, tg_configured) = telegram_config_flags(&config.config_path);
    let tg_running = pid_path_running(&config.telegram_pid_path).is_some();
    let tg_status = telegram_status(config, tg_enabled, tg_configured, tg_running);
    let action = config
        .action
        .lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| "failed".into());
    let stages = vec![
        stage(
            "config",
            "Конфигурация",
            true,
            if config.config_exists {
                "Прочитана из конфигурационного файла."
            } else {
                "Файла конфигурации нет, действуют умолчания."
            },
        ),
        stage(
            "capture",
            "Чтение пакетов",
            linked,
            if linked {
                "Очередь ядра открыта, пакеты читаются: контроллер получает события датапата."
            } else {
                "Контроллер не подключён к датапату — сказать, читаются ли пакеты, нечем."
            },
        ),
        stage(
            "flow",
            "Состояние потоков",
            linked,
            if linked {
                "Датапат ведёт учёт соединений и сообщает о подозрениях."
            } else {
                "Контроллер не подключён к датапату."
            },
        ),
        stage(
            "plan",
            "Исполнение планов",
            linked,
            if linked {
                "Планы ставятся датапату и исполняются на живых соединениях."
            } else {
                "Контроллер не подключён к датапату: применяется ли обход, отсюда не видно."
            },
        ),
        stage(
            "boxes",
            "Каталог коробок",
            have_catalog,
            if have_catalog {
                "Каталог открыт: изученные коробки и цели доступны."
            } else {
                "Каталог не открыт."
            },
        ),
        stage("panel", "Панель", true, "Показывает этот снимок."),
    ];
    let mut absent = vec![stage(
        "outages",
        "Здоровье наблюдения",
        false,
        "Нечем: сколько пакетов не дошло до очереди, снаружи не измеряется.",
    )];
    if !linked {
        absent.push(stage("traffic", "Наблюдаемый трафик", false, "Нечем: контроллер не подключён к датапату. Это не «ноль соединений», а отсутствие измерения."));
    }
    json!({
        "taken":taken,"version":config.version,"commit":config.commit,"built":config.built,"dirty":config.dirty,
        "config_path":config.config_path,"config_exists":config.config_exists,"mode":config.mode,"panel_listen":config.panel_listen,
        "controls_enabled":config.control_enabled,"control_state":action,"catalog_available":have_catalog,"live_fresh":live_fresh,
        "engine_running":engine_running,"controller_running":controller_running,"telegram_enabled":tg_enabled,
        "telegram_configured":tg_configured,"telegram_running":tg_running,"telegram_status":tg_status,"telegram_stats":read_telegram_stats(&config.telegram_stats_path),"telegram_diagnostics":telegram_diagnostics_snapshot(config),
        "state_dir":config.state_dir,"state_dir_note":state_dir_note(&config.state_dir),"queue_num":config.queue_num,
        "unknown_keys":config.unknown_keys,"started_at":started,"uptime_seconds":uptime,"stages":stages,"absent":absent
    })
}

fn stage(key: &str, title: &str, built: bool, detail: &str) -> Value {
    json!({"key":key,"title":title,"built":built,"detail":detail})
}
fn state_dir_note(path: &Path) -> &'static str {
    match fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "не создан",
        Err(_) => "недоступен",
        Ok(m) if !m.is_dir() => "существует, но это не каталог",
        Ok(_) => "есть",
    }
}

fn api_update(config: &Config) -> Response {
    let updater_present = is_executable_file(&config.updater_path);
    let manager_present = is_executable_file(&config.manager_path);
    if !updater_present && !manager_present {
        return json_response(200, &json!({"absent":true}));
    }
    match read_json_object(&config.update_state_path, 16 * 1024) {
        Some(value) => json_response(200, &value),
        None => json_response(200, &json!({"never":true})),
    }
}

fn api_control(config: &Config, request: &Request<'_>) -> Response {
    let actions = [
        ("/api/control/start", "engine-start", "Запуск движка"),
        ("/api/control/stop", "engine-stop", "Остановка движка"),
        (
            "/api/control/restart",
            "engine-restart",
            "Перезапуск движка",
        ),
        ("/api/control/reapply", "reapply", "Восстановление правил"),
        (
            "/api/control/clear-found",
            "clear-found",
            "Очистка подобранного",
        ),
        (
            "/api/control/telegram-enable",
            "telegram-enable",
            "Включение Telegram-туннеля",
        ),
        (
            "/api/control/telegram-disable",
            "telegram-disable",
            "Отключение Telegram-туннеля",
        ),
        (
            "/api/control/telegram-check",
            "telegram-check",
            "Проверка Telegram-туннеля",
        ),
        (
            "/api/control/update-check",
            "update-check",
            "Проверка обновлений",
        ),
        (
            "/api/control/update-install",
            "update-install",
            "Установка обновления",
        ),
        (
            "/api/control/update-auto-on",
            "update-auto-on",
            "Включение автообновления",
        ),
        (
            "/api/control/update-auto-off",
            "update-auto-off",
            "Выключение автообновления",
        ),
    ];
    let Some((_, command, label)) = actions.iter().find(|(path, _, _)| *path == request.path)
    else {
        return json_response(404, &json!({"ok":false,"message":"Неизвестная операция"}));
    };
    if !config.control_enabled || !same_origin(request) {
        return json_response(
            403,
            &json!({"ok":false,"message":"Управление разрешено только с этой панели"}),
        );
    }
    if matches!(*command, "engine-start" | "engine-restart") && config.mode == "off" {
        return json_response(
            409,
            &json!({"ok":false,"message":"В config задан MODE=off; сначала измените режим движка"}),
        );
    }
    if matches!(*command, "telegram-enable" | "telegram-check")
        && !telegram_config_flags(&config.config_path).1
    {
        return json_response(
            409,
            &json!({"ok":false,"message":"Укажите TG_MODE=local в конфигурации Telegram"}),
        );
    }
    if request.header("Transfer-Encoding").is_some()
        || request.header("Content-Length").is_some_and(|v| v != "0")
    {
        return json_response(400, &json!({"ok":false,"message":"Тело запроса запрещено"}));
    }
    let manager_present = is_executable_file(&config.manager_path);
    let result = if *command == "telegram-check" {
        start_telegram_check(config)
    } else if manager_present && *command == "update-check" {
        start_manager_update(config, command)
    } else if manager_present && *command == "update-install" {
        if is_executable_file(&config.service_path) {
            start_service_action(config, command)
        } else {
            return json_response(
                409,
                &json!({"ok":false,"message":"Для установки обновления требуется запущенный router adapter"}),
            );
        }
    } else {
        start_service_action(config, command)
    };
    match result {
        Ok(()) => json_response(
            202,
            &json!({"ok":true,"action":label,"message":"Команда запущена"}),
        ),
        Err(ActionError::Busy) => json_response(
            409,
            &json!({"ok":false,"message":"Предыдущая команда ещё выполняется"}),
        ),
        Err(ActionError::Start) => json_response(
            500,
            &json!({"ok":false,"message":"Команда службы завершилась ошибкой"}),
        ),
        Err(ActionError::ConfigWrite) => json_response(
            500,
            &json!({"ok":false,"message":"Команда службы завершилась ошибкой"}),
        ),
    }
}

fn same_origin(request: &Request<'_>) -> bool {
    let (Some(host), Some(origin)) = (request.header("Host"), request.header("Origin")) else {
        return false;
    };
    origin
        .strip_prefix("http://")
        .is_some_and(|authority| !authority.is_empty() && authority == host)
}

#[derive(Debug)]
enum ActionError {
    Busy,
    Start,
    ConfigWrite,
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn start_service_action(config: &Config, command: &str) -> Result<(), ActionError> {
    if config.service_path.as_os_str().is_empty() {
        return Err(ActionError::Start);
    }
    let mut child_command = Command::new(config.service_path.clone());
    child_command.arg(command);
    start_action_command(config, child_command, CONTROL_TIMEOUT)
}

fn start_telegram_check(config: &Config) -> Result<(), ActionError> {
    if config.service_path.as_os_str().is_empty() {
        return Err(ActionError::Start);
    }
    if config
        .telegram_check_running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(ActionError::Busy);
    }
    let running = Arc::clone(&config.telegram_check_running);
    let mut command = Command::new(config.service_path.clone());
    command.arg("telegram-check");
    let result =
        start_action_command_with_completion(config, command, CONTROL_TIMEOUT, move || {
            running.store(false, Ordering::Release)
        });
    if result.is_err() {
        config
            .telegram_check_running
            .store(false, Ordering::Release);
    }
    result
}

fn start_manager_update(config: &Config, command: &str) -> Result<(), ActionError> {
    if !is_executable_file(&config.manager_path) {
        return Err(ActionError::Start);
    }
    let mut child_command = Command::new(config.manager_path.clone());
    child_command
        .arg(command)
        .arg("--root")
        .arg(config.manager_root.as_os_str());
    let timeout = if command == "update-install" {
        UPDATE_INSTALL_TIMEOUT
    } else {
        UPDATE_CHECK_TIMEOUT
    };
    start_action_command(config, child_command, timeout)
}

fn start_action_command(
    config: &Config,
    child_command: Command,
    timeout: Duration,
) -> Result<(), ActionError> {
    start_action_command_with_completion(config, child_command, timeout, || {})
}

fn start_action_command_with_completion<F>(
    config: &Config,
    child_command: Command,
    timeout: Duration,
    on_complete: F,
) -> Result<(), ActionError>
where
    F: FnOnce() + Send + 'static,
{
    start_action_command_with_setup(config, child_command, timeout, || Ok(()), on_complete)
}

fn start_action_command_with_setup<F, S>(
    config: &Config,
    mut child_command: Command,
    timeout: Duration,
    setup: S,
    on_complete: F,
) -> Result<(), ActionError>
where
    F: FnOnce() + Send + 'static,
    S: FnOnce() -> Result<(), ActionError>,
{
    let mut state = config.action.lock().map_err(|_| ActionError::Start)?;
    if *state == "running" {
        return Err(ActionError::Busy);
    }
    let previous_state = state.clone();
    *state = "running".into();
    if let Err(error) = setup() {
        *state = previous_state;
        return Err(error);
    }
    let shared = Arc::clone(&config.action);
    std::thread::Builder::new()
        .name("r2o-panel-action".into())
        .spawn(move || {
            child_command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                child_command.process_group(0);
            }
            let outcome = child_command
                .spawn()
                .ok()
                .and_then(|mut child| {
                    let start = std::time::Instant::now();
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                return Some(if status.success() { "done" } else { "failed" });
                            }
                            Ok(None) if start.elapsed() < timeout => {
                                std::thread::sleep(Duration::from_millis(20))
                            }
                            Ok(None) => {
                                #[cfg(unix)]
                                unsafe {
                                    libc::kill(-(child.id() as i32), libc::SIGTERM);
                                }
                                #[cfg(not(unix))]
                                {
                                    let _ = child.kill();
                                }
                                std::thread::sleep(Duration::from_secs(1));
                                #[cfg(unix)]
                                unsafe {
                                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                                }
                                #[cfg(not(unix))]
                                {
                                    let _ = child.kill();
                                }
                                let _ = child.wait();
                                return Some("timeout");
                            }
                            Err(_) => return Some("failed"),
                        }
                    }
                })
                .unwrap_or("failed");
            if let Ok(mut state) = shared.lock() {
                *state = outcome.into();
            }
            on_complete();
        })
        .map_err(|_| {
            *state = "failed".into();
            ActionError::Start
        })?;
    Ok(())
}

fn api_workers(config: &Config, request: &Request<'_>) -> Response {
    if request.method == "GET" {
        return match worker_domains_from_config(&config.config_path) {
            Ok(domains) => json_response(200, &json!({"domains":domains})),
            Err(_) => json_response(
                500,
                &json!({"ok":false,"message":"Не удалось прочитать настройки Workers"}),
            ),
        };
    }
    if !config.control_enabled || !same_origin(request) {
        return json_response(
            403,
            &json!({"ok":false,"message":"Изменять настройки можно только с этой панели"}),
        );
    }
    if !request.header("Content-Type").is_some_and(|s| {
        s.get(..16)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/json"))
    }) {
        return json_response(
            415,
            &json!({"ok":false,"message":"Ожидается JSON со списком доменов"}),
        );
    }
    if request.header("Transfer-Encoding").is_some() {
        return json_response(
            400,
            &json!({"ok":false,"message":"Проверьте домены: до 8 имён без URL и пути"}),
        );
    }
    let length = request.header("Content-Length").and_then(|s| {
        (!s.is_empty() && s.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| s.parse::<usize>().ok())
            .flatten()
    });
    if length.is_none_or(|n| n == 0 || n > WORKER_BODY_MAX) || length != Some(request.body.len()) {
        return json_response(
            400,
            &json!({"ok":false,"message":"Проверьте домены: до 8 имён без URL и пути"}),
        );
    }
    let domains = match worker_domains_from_json(request.body) {
        Ok(domains) => domains,
        Err(_) => {
            return json_response(
                400,
                &json!({"ok":false,"message":"Проверьте домены: до 8 имён без URL и пути"}),
            );
        }
    };
    let config_path = config.config_path.clone();
    let service_missing = config.service_path.as_os_str().is_empty();
    let mut command = Command::new(config.service_path.clone());
    command.arg("telegram-restart");
    match start_action_command_with_setup(
        config,
        command,
        CONTROL_TIMEOUT,
        || {
            write_worker_config(&config_path, &domains).map_err(|_| ActionError::ConfigWrite)?;
            if service_missing {
                return Err(ActionError::Start);
            }
            Ok(())
        },
        || {},
    ) {
        Ok(()) => json_response(
            202,
            &json!({"ok":true,"message":"Настройки сохранены, C11 перезапускается"}),
        ),
        Err(ActionError::Busy) => json_response(
            409,
            &json!({"ok":false,"message":"Дождитесь завершения текущей команды"}),
        ),
        Err(ActionError::Start) => json_response(
            500,
            &json!({"ok":false,"message":"Настройки сохранены, но C11 не удалось перезапустить"}),
        ),
        Err(ActionError::ConfigWrite) => json_response(
            500,
            &json!({"ok":false,"message":"Не удалось сохранить настройки Workers"}),
        ),
    }
}

fn worker_domains_from_json(body: &[u8]) -> Result<Vec<String>, ()> {
    if body.len() > WORKER_BODY_MAX {
        return Err(());
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    if !value.is_object() {
        return Err(());
    }
    let list = top_level_raw_value(body, "domains").ok_or(())?;
    let mut domains = Vec::new();
    let mut at = skip_ws(list, 0);
    if list.get(at) != Some(&b'[') {
        return Err(());
    }
    at = skip_ws(list, at + 1);
    if list.get(at) == Some(&b']') {
        return Ok(domains);
    }
    loop {
        if list.get(at) != Some(&b'"') {
            return Err(());
        }
        let start = at + 1;
        at = start;
        while at < list.len() && list[at] != b'"' {
            if list[at] == b'\\' || !list[at].is_ascii() {
                return Err(());
            }
            at += 1;
        }
        if at >= list.len() {
            return Err(());
        }
        let raw = std::str::from_utf8(&list[start..at]).map_err(|_| ())?;
        if raw.contains(['/', '?', '#']) {
            return Err(());
        }
        add_domain(&mut domains, raw, false)?;
        at = skip_ws(list, at + 1);
        match list.get(at) {
            Some(b',') => at = skip_ws(list, at + 1),
            Some(b']') if skip_ws(list, at + 1) == list.len() => return Ok(domains),
            _ => return Err(()),
        }
    }
}

fn worker_domains_from_config(path: &Path) -> Result<Vec<String>, ()> {
    let raw = read_regular_file(path, BODY_MAX).map_err(|_| ())?;
    let text = String::from_utf8_lossy(&raw);
    let mut domains = Vec::new();
    for line in text.lines() {
        let line = line.trim_start_matches([' ', '\t']);
        if worker_line(line) {
            let value = line.split_once('=').ok_or(())?.1.trim();
            let value = strip_config_quotes(value)?;
            let mut found = Vec::new();
            for item in value.split(',').filter(|s| !s.is_empty()) {
                add_domain(&mut found, item, true)?;
            }
            domains = found;
        }
    }
    Ok(domains)
}

fn worker_line(line: &str) -> bool {
    worker_line_bytes(line.as_bytes())
}

fn worker_line_bytes(line: &[u8]) -> bool {
    let mut start = 0;
    while line
        .get(start)
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        start += 1;
    }
    if start == line.len() || line[start] == b'#' {
        return false;
    }
    let Some(equal) = line[start..].iter().position(|byte| *byte == b'=') else {
        return false;
    };
    let mut end = start + equal;
    while end > start && matches!(line[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    &line[start..end] == b"TG_CF_WORKER_DOMAIN"
}

fn strip_config_quotes(value: &str) -> Result<&str, ()> {
    let value = value.trim();
    if value.starts_with('"') || value.starts_with('\'') {
        let quote = value.as_bytes()[0] as char;
        let close = value[1..].find(quote).map(|i| i + 1).ok_or(())?;
        if value
            .as_bytes()
            .get(close + 1)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            return Err(());
        }
        let tail = value[close + 1..].trim();
        if !tail.is_empty() && !tail.starts_with('#') {
            return Err(());
        }
        Ok(&value[1..close])
    } else {
        let cut = value.char_indices().find_map(|(i, c)| {
            (c == '#' && (i == 0 || value.as_bytes()[i - 1].is_ascii_whitespace())).then_some(i)
        });
        let plain = cut.map_or(value, |i| &value[..i]).trim();
        if plain.ends_with(['\'', '"']) {
            return Err(());
        }
        Ok(plain)
    }
}

fn add_domain(domains: &mut Vec<String>, input: &str, allow_url: bool) -> Result<(), ()> {
    let mut value = input.trim();
    if allow_url {
        if value
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
        {
            value = &value[7..];
        } else if value
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
        {
            value = &value[8..];
        }
        value = value.split(['/', '?', '#']).next().unwrap_or("");
    }
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err(());
    }
    let labels: Vec<_> = value.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(());
    }
    let tld = labels[labels.len() - 1];
    if tld.len() < 2 || !tld.bytes().any(|b| b.is_ascii_alphabetic()) {
        return Err(());
    }
    let normalized = value.to_ascii_lowercase();
    if domains.iter().any(|domain| domain == &normalized) {
        return Ok(());
    }
    if domains.len() == WORKER_MAX {
        return Err(());
    }
    domains.push(normalized);
    Ok(())
}

fn write_worker_config(path: &Path, domains: &[String]) -> std::io::Result<()> {
    let (source, metadata) = read_regular_file_with_metadata(path, BODY_MAX)?;
    if source.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "nul byte in config",
        ));
    }
    let mut output = Vec::with_capacity(source.len().saturating_add(64));
    let mut offset = 0;
    while offset < source.len() {
        let end = source[offset..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(source.len(), |length| offset + length);
        let mut line_end = end;
        if line_end > offset && source[line_end - 1] == b'\r' {
            line_end -= 1;
        }
        if !worker_line_bytes(&source[offset..line_end]) {
            let copy_end = if end < source.len() { end + 1 } else { end };
            output.extend_from_slice(&source[offset..copy_end]);
        }
        offset = if end < source.len() {
            end + 1
        } else {
            source.len()
        };
    }
    if !domains.is_empty() {
        if !output.is_empty() && !output.ends_with(b"\n") {
            output.push(b'\n');
        }
        output.extend_from_slice(b"TG_CF_WORKER_DOMAIN=");
        for (index, domain) in domains.iter().enumerate() {
            if index != 0 {
                output.push(b',');
            }
            output.extend_from_slice(domain.as_bytes());
        }
        output.push(b'\n');
    }
    r2o_write_config_atomically(path, &output, &metadata, "workers")
}

fn r2o_write_config_atomically(
    path: &Path,
    output: &[u8],
    metadata: &fs::Metadata,
    suffix: &str,
) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "config filename"))?;
    for attempt in 0..8 {
        let temporary = parent.join(format!(
            ".{name}.{suffix}.{}.{}",
            std::process::id(),
            attempt
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            options.mode(metadata.permissions().mode() & 0o777);
        }
        match options.open(&temporary) {
            Ok(mut file) => {
                let result = (|| {
                    file.write_all(output)?;
                    file.sync_all()?;
                    fs::rename(&temporary, path)?;
                    File::open(parent)?.sync_all()?;
                    Ok(())
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&temporary);
                }
                return result;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "temporary config collision",
    ))
}

fn static_asset(
    config: &Config,
    request: &Request<'_>,
    name: &str,
    content_type: &str,
) -> Response {
    let bytes = match read_asset(config, name) {
        Ok(data) => data,
        Err(_) => return text_response(404, "not found\n"),
    };
    let hash = bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    });
    let etag = format!("\"{:x}-{:x}\"", bytes.len(), hash);
    let mut response = Response::new(200, content_type, bytes);
    response = response
        .header("Cache-Control", "no-cache")
        .header("ETag", etag.clone());
    if request.header("If-None-Match") == Some(etag.as_str()) {
        response.status = 304;
        response.body.clear();
    }
    response
}

fn read_asset(config: &Config, name: &str) -> std::io::Result<Vec<u8>> {
    let root_safe = fs::symlink_metadata(&config.asset_dir)
        .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink());
    if !root_safe {
        return embedded_asset(name)
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "asset root unavailable")
            });
    }
    if name.starts_with("fonts/")
        && fs::symlink_metadata(config.asset_dir.join("fonts"))
            .is_ok_and(|m| !m.is_dir() || m.file_type().is_symlink())
    {
        return embedded_asset(name)
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "asset directory unsafe")
            });
    }
    let path = config.asset_dir.join(name);
    match read_regular_file(&path, BODY_MAX) {
        Ok(bytes) => Ok(bytes),
        Err(_) => embedded_asset(name)
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "asset missing")),
    }
}

fn embedded_asset(name: &str) -> Option<&'static [u8]> {
    Some(match name {
        "index.html" => include_bytes!("../assets/index.html"),
        "favicon.svg" => include_bytes!("../assets/favicon.svg"),
        "refresh-mask.svg" => include_bytes!("../assets/refresh-mask.svg"),
        "panel.css" => include_bytes!("../assets/panel.css"),
        "panel.js" => include_bytes!("../assets/panel.js"),
        "telegram-flow.js" => include_bytes!("../assets/telegram-flow.js"),
        "telegram-flow-prototype.js" => include_bytes!("../assets/telegram-flow-prototype.js"),
        "gsap.js" => include_bytes!("../assets/gsap.js"),
        "panel-motion.js" => include_bytes!("../assets/panel-motion.js"),
        "panel-lava.js" => include_bytes!("../assets/panel-lava.js"),
        "fonts/onest.woff2" => include_bytes!("../assets/fonts/onest.woff2"),
        "fonts/jbmono.woff2" => include_bytes!("../assets/fonts/jbmono.woff2"),
        "fonts/nunito-cyrillic.woff2" => include_bytes!("../assets/fonts/nunito-cyrillic.woff2"),
        "fonts/nunito-latin.woff2" => include_bytes!("../assets/fonts/nunito-latin.woff2"),
        "fonts/jetbrains-mono-lava.woff2" => {
            include_bytes!("../assets/fonts/jetbrains-mono-lava.woff2")
        }
        _ => return None,
    })
}

fn read_json_object(path: &Path, limit: usize) -> Option<Value> {
    let bytes = read_regular_file(path, limit).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.is_object().then_some(value)
}

fn read_regular_file(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    read_regular_file_with_metadata(path, limit).map(|(bytes, _)| bytes)
}

fn read_regular_file_with_metadata(
    path: &Path,
    limit: usize,
) -> std::io::Result<(Vec<u8>, fs::Metadata)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() as usize > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file too large",
        ));
    }
    Ok((bytes, metadata))
}

fn catalog_revision(value: &Value) -> Option<String> {
    let mut hash = 14_695_981_039_346_656_037u64;
    let mut found = false;
    for (index, key) in ["boxes", "groups"].iter().enumerate() {
        let raw_value = value.get(key).map(serde_json::to_vec).transpose().ok()?;
        hash ^= (index + 1) as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
        hash ^= raw_value.as_ref().map_or(0, Vec::len) as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
        if let Some(value) = raw_value {
            found = true;
            for byte in &value {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(1_099_511_628_211);
            }
        }
    }
    found.then(|| format!("{hash:016x}"))
}

fn top_level_raw_value<'a>(raw: &'a [u8], wanted: &str) -> Option<&'a [u8]> {
    let mut at = skip_ws(raw, 0);
    if raw.get(at)? != &b'{' {
        return None;
    }
    at += 1;
    loop {
        at = skip_ws(raw, at);
        if raw.get(at)? == &b'}' {
            return None;
        }
        let key_start = at;
        at = scan_string(raw, at)?;
        let key: String = serde_json::from_slice(&raw[key_start..at]).ok()?;
        at = skip_ws(raw, at);
        if raw.get(at)? != &b':' {
            return None;
        }
        at = skip_ws(raw, at + 1);
        let value_start = at;
        at = scan_json_value(raw, at)?;
        if key == wanted {
            return Some(&raw[value_start..at]);
        }
        at = skip_ws(raw, at);
        match raw.get(at)? {
            b',' => at += 1,
            b'}' => return None,
            _ => return None,
        }
    }
}

fn skip_ws(raw: &[u8], mut at: usize) -> usize {
    while raw.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}
fn scan_string(raw: &[u8], start: usize) -> Option<usize> {
    if raw.get(start)? != &b'"' {
        return None;
    }
    let mut at = start + 1;
    while at < raw.len() {
        match raw[at] {
            b'\\' => at += 2,
            b'"' => return Some(at + 1),
            _ => at += 1,
        }
    }
    None
}
fn scan_json_value(raw: &[u8], start: usize) -> Option<usize> {
    match *raw.get(start)? {
        b'"' => scan_string(raw, start),
        b'{' | b'[' => {
            let mut at = start;
            let mut depth = 0usize;
            let mut in_string = false;
            while at < raw.len() {
                let byte = raw[at];
                if in_string {
                    if byte == b'\\' {
                        at += 2;
                        continue;
                    }
                    if byte == b'"' {
                        in_string = false;
                    }
                } else {
                    match byte {
                        b'"' => in_string = true,
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(at + 1);
                            }
                        }
                        _ => {}
                    }
                }
                at += 1;
            }
            None
        }
        _ => {
            let mut at = start;
            while at < raw.len()
                && !matches!(raw[at], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
            {
                at += 1;
            }
            (at > start).then_some(at)
        }
    }
}

fn pid_path_running(path: &Path) -> Option<(u32, u64)> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    let started = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    let raw = read_regular_file(path, 32).ok()?;
    let text = std::str::from_utf8(&raw).ok()?.trim();
    let pid: u32 = text.parse().ok()?;
    if pid <= 1 || pid > 4_194_304 {
        return None;
    }
    #[cfg(unix)]
    {
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
            return Some((pid, started));
        }
    }
    None
}

fn telegram_config_flags(path: &Path) -> (bool, bool) {
    let Ok(raw) = read_regular_file(path, BODY_MAX) else {
        return (false, false);
    };
    let mut enabled = false;
    let mut mode_seen = false;
    let mut configured = true;
    let mut local = false;
    for line in raw.split(|byte| *byte == b'\n') {
        let line_end = line
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(line.len());
        let mut line = &line[..line_end];
        while line
            .first()
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            line = &line[1..];
        }
        if line.first() == Some(&b'#') {
            continue;
        }
        let Some(equal) = line.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let mut key = &line[..equal];
        while key
            .last()
            .is_some_and(|byte| matches!(*byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            key = &key[..key.len() - 1];
        }
        let mut value = &line[equal + 1..];
        while value
            .first()
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            value = &value[1..];
        }
        while value
            .last()
            .is_some_and(|byte| matches!(*byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            value = &value[..value.len() - 1];
        }
        if let Some(&quote) = value.first() {
            if quote == b'\'' || quote == b'"' {
                if value.len() < 2 || value.last() != Some(&quote) {
                    return (false, false);
                }
                value = &value[1..value.len() - 1];
                if value.contains(&quote) {
                    return (false, false);
                }
            }
        }
        match key {
            b"TG_ENABLED" => enabled = value == b"1" || value == b"yes",
            b"TG_MODE" => {
                if mode_seen {
                    configured = false;
                }
                mode_seen = true;
                local = value == b"local";
                if !local {
                    configured = false;
                }
            }
            _ => {}
        }
    }
    (enabled, configured && mode_seen && local)
}

fn telegram_status(
    config: &Config,
    enabled: bool,
    configured: bool,
    running: bool,
) -> &'static str {
    if !configured {
        return "not_configured";
    }
    if !enabled {
        return "stopped";
    }
    let stored = read_regular_file(&config.telegram_status_path, 64)
        .ok()
        .and_then(|raw| {
            std::str::from_utf8(&raw)
                .ok()
                .map(|value| value.trim().to_owned())
        });
    if !running {
        return match stored.as_deref() {
            Some("error") => "error",
            Some("not_configured") => "not_configured",
            _ => "stopped",
        };
    }
    match stored.as_deref().unwrap_or("") {
        "connected" => "connected",
        "connecting" => "connecting",
        "local" => "local",
        "stopped" => "stopped",
        "not_configured" => "not_configured",
        _ => "connecting",
    }
}

fn read_telegram_stats(path: &Path) -> Option<Value> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(path).ok()?;
        let timeout = Some(Duration::from_millis(1250));
        let _ = stream.set_read_timeout(timeout);
        let _ = stream.set_write_timeout(timeout);
        stream.write_all(b"snapshot\n").ok()?;
        let mut raw = Vec::with_capacity(2048);
        stream.take(8192).read_to_end(&mut raw).ok()?;
        let stats: Value = serde_json::from_slice(&raw).ok()?;
        if !valid_telegram_stats(&stats) {
            return None;
        }
        Some(stats)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod differential_tests {
    use super::*;
    use std::process::Command;
    use std::time::Instant;

    #[test]
    #[ignore = "run through scripts/test-panel-control-timeout-differential.sh"]
    fn d2o_control_timeout_state_trace() {
        let service = PathBuf::from(
            std::env::var_os("R2O_PANEL_TIMEOUT_SERVICE")
                .expect("test helper provides a slow service"),
        );
        let config = Config::default();
        let mut command = Command::new(service);
        command.arg("engine-stop");
        start_action_command(&config, command, Duration::from_millis(40)).unwrap();

        let deadline = Instant::now() + Duration::from_secs(4);
        let state = loop {
            let response = handle_request(
                &config,
                b"GET /api/status HTTP/1.1\r\nHost: localhost:8090\r\n\r\n",
            );
            let value: Value = serde_json::from_slice(&response.body).unwrap();
            let state = value["snapshot"]["control_state"].as_str().unwrap();
            if state != "running" || Instant::now() >= deadline {
                break state.to_owned();
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        println!("{state}");
        if let Some(path) = std::env::var_os("R2O_PANEL_TIMEOUT_TRACE_OUTPUT") {
            fs::write(path, format!("{state}\n")).unwrap();
        }
        let c_state = fs::read_to_string(
            std::env::var_os("R2O_PANEL_TIMEOUT_C_TRACE")
                .expect("test helper provides the D2O C trace"),
        )
        .unwrap();
        assert_eq!(state.trim(), c_state.trim());
        assert_eq!(state, "timeout");
    }
}

fn telegram_diagnostics_snapshot(config: &Config) -> Value {
    if config.telegram_check_running.load(Ordering::Acquire) {
        return json!({"state":"running"});
    }
    read_telegram_diagnostics(&config.state_dir.join("telegram-diagnostics.json"))
        .unwrap_or_else(|| json!({"state":"never"}))
}

fn read_telegram_diagnostics(path: &Path) -> Option<Value> {
    let report = read_json_object(path, TELEGRAM_DIAGNOSTICS_MAX)?;
    valid_telegram_diagnostics(&report).then_some(report)
}

fn valid_telegram_diagnostics(report: &Value) -> bool {
    match report.get("state").and_then(Value::as_str) {
        Some("error") => report.get("message").and_then(Value::as_str).is_some(),
        Some("healthy" | "partial" | "unavailable" | "unverified") => {
            report.get("checked_at").and_then(Value::as_u64).is_some()
                && report
                    .get("data_centers")
                    .and_then(Value::as_array)
                    .is_some_and(|centers| {
                        centers.len() == 5
                            && centers.iter().enumerate().all(|(index, center)| {
                                center.get("dc").and_then(Value::as_u64) == Some(index as u64 + 1)
                                    && center.get("state").and_then(Value::as_str).is_some_and(
                                        |state| {
                                            matches!(
                                                state,
                                                "healthy"
                                                    | "blocked"
                                                    | "unavailable"
                                                    | "unverified"
                                            )
                                        },
                                    )
                                    && center.get("routes").and_then(Value::as_array).is_some()
                            })
                    })
        }
        _ => false,
    }
}

fn valid_telegram_stats(stats: &Value) -> bool {
    let Some(object) = stats.as_object() else {
        return false;
    };
    let required_numbers = [
        "active_connections",
        "max_connections",
        "accepted_connections",
        "process_started_at",
    ];
    if required_numbers
        .iter()
        .any(|key| object.get(*key).and_then(Value::as_u64).is_none())
        || !object.get("active_sessions").is_some_and(Value::is_array)
        || !object
            .get("route_sessions_truncated")
            .is_some_and(Value::is_boolean)
    {
        return false;
    }

    let is_rust_snapshot =
        object.contains_key("mtproto_success") || object.contains_key("wss_established");
    if is_rust_snapshot {
        let required_rust_numbers = [
            "wss_established",
            "mtproto_success",
            "mtproto_failure",
            "last_mtproto_response_at",
        ];
        let required_objects = [
            "dc_map",
            "cf_domain_pool",
            "workers",
            "sessions_by_dc_transport",
            "failures",
            "ttfb",
        ];
        return object.get("listener_ready").is_some_and(Value::is_boolean)
            && required_rust_numbers
                .iter()
                .all(|key| object.get(*key).and_then(Value::as_u64).is_some())
            && required_objects
                .iter()
                .all(|key| object.get(*key).is_some_and(Value::is_object));
    }

    let required_legacy_numbers = [
        "connections_started",
        "bytes_from_clients",
        "bytes_from_upstreams",
        "wss_attempts",
        "wss_failures",
        "wss_responses",
        "cf_wss_responses",
    ];
    let optional_legacy_numbers = [
        "last_success_dc",
        "last_success_route",
        "last_success_latency_ms",
        "last_success_age_ms",
        "last_failure_dc",
        "last_failure_route",
        "last_failure_stage",
        "last_failure_age_ms",
    ];
    required_legacy_numbers
        .iter()
        .all(|key| object.get(*key).and_then(Value::as_u64).is_some())
        && !optional_legacy_numbers.iter().any(|key| {
            object
                .get(*key)
                .is_some_and(|value| value.as_u64().is_none())
        })
}

pub fn parse_config(
    path: &Path,
    config: &mut Config,
    cli_overrides: &[&str],
) -> std::io::Result<()> {
    let raw = match read_regular_file(path, BODY_MAX) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            config.config_exists = false;
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    config.config_exists = true;
    let text = std::str::from_utf8(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let known = [
        "SCHEMA",
        "MODE",
        "PANEL_LISTEN",
        "STATE_DIR",
        "QUEUE_NUM",
        "QUEUE_NUM6",
        "R2O_FLOW_CAPACITY",
        "IPV6_ENABLED",
        "CONTROL_SOCKET",
        "DECOY_SNI",
        "MARK",
        "PROBE_MARK",
        "ONLY_MARK",
        "FLOWS",
        "STATS_SEC",
        "HEAL_EVERY",
        "LOGMAX",
        "LOGKEEP",
        "LOG_EVERY",
        "FW_BACKEND",
        "R2O_RUNTIME_DIR",
        "PORTS",
        "CONNBYTES",
        "VOICE_PORTS",
        "VOICE_CONNBYTES",
        "TG_ENABLED",
        "TG_MODE",
        "TG_DC_MAP_PATH",
        "TG_IDENTITY",
        "TG_CA_BUNDLE",
        "TG_STATUS",
        "TG_STATS_SOCKET",
        "TG_PORT",
        "TG_DIAGNOSTIC_DIRECT_TCP",
        "TG_CF_WORKER_DOMAIN",
        "R2O_PPE_DEOFFLOAD",
    ];
    for line in text.lines() {
        if line.len() >= 2047 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "configuration line exceeds 2046 bytes",
            ));
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !known.contains(&key) {
            if config.unknown_keys.len() < 64
                && key.len() < 128
                && !config.unknown_keys.iter().any(|k| k == key)
            {
                config.unknown_keys.push(key.into());
            }
            continue;
        }
        let value = strip_shell_value(raw_value.trim()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid config value for {key}"),
            )
        })?;
        match key {
            "SCHEMA" => {
                if value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || value.parse::<u8>().map_or(true, |schema| schema > 1)
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid SCHEMA",
                    ));
                }
            }
            "MODE" => {
                if !matches!(value, "off" | "observe" | "apply") {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid MODE",
                    ));
                }
                if !cli_overrides.contains(&"mode") {
                    config.mode = value.into();
                }
            }
            "PANEL_LISTEN" if !cli_overrides.contains(&"listen") => {
                config.panel_listen = value.into()
            }
            "STATE_DIR" if !cli_overrides.contains(&"state-dir") => {
                if !value.is_empty() && !value.starts_with('/') {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "STATE_DIR must be absolute",
                    ));
                }
                config.state_dir = value.into();
            }
            "QUEUE_NUM" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid QUEUE_NUM",
                    ));
                }
                let n: u16 = value
                    .parse()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                if !cli_overrides.contains(&"queue") {
                    config.queue_num = n;
                }
            }
            "QUEUE_NUM6" => {
                config.queue_num6 = r2o_config_number(key, value)?;
            }
            "R2O_FLOW_CAPACITY" => {
                let capacity: u32 = r2o_config_number(key, value)?;
                if capacity == 0 {
                    return Err(r2o_invalid_config(key));
                }
                config.flow_capacity = capacity;
            }
            "IPV6_ENABLED" => {
                config.ipv6_enabled = match value {
                    "0" => false,
                    "1" => true,
                    _ => return Err(r2o_invalid_config(key)),
                };
            }
            "MARK" => {
                if !valid_mark(value) {
                    return Err(r2o_invalid_config(key));
                }
                config.mark = value.into();
            }
            "PROBE_MARK" => {
                if !valid_mark(value) {
                    return Err(r2o_invalid_config(key));
                }
                config.probe_mark = value.into();
            }
            "ONLY_MARK" => {
                if !valid_only_mark(value) {
                    return Err(r2o_invalid_config(key));
                }
                config.only_mark = value.into();
            }
            "FW_BACKEND" => {
                if !matches!(value, "auto" | "iptables" | "nft") {
                    return Err(r2o_invalid_config(key));
                }
                config.firewall_backend = value.into();
            }
            "PORTS" => {
                if !valid_port_list(value) {
                    return Err(r2o_invalid_config(key));
                }
                config.ports = value.into();
            }
            "CONNBYTES" => {
                if !valid_connbytes_window(value) {
                    return Err(r2o_invalid_config(key));
                }
                config.connbytes = value.into();
            }
            "VOICE_PORTS" => {
                if !valid_port_list(value) {
                    return Err(r2o_invalid_config(key));
                }
                config.voice_ports = value.into();
            }
            "VOICE_CONNBYTES" => {
                if !valid_connbytes_window(value) {
                    return Err(r2o_invalid_config(key));
                }
                config.voice_connbytes = value.into();
            }
            "HTTP_KEEPALIVE_PORTS" => {
                if !valid_port_list(value) {
                    return Err(r2o_invalid_config(key));
                }
                config.http_keepalive_ports = value.into();
            }
            "DNS_PORTS" => {
                if !valid_port_list(value) {
                    return Err(r2o_invalid_config(key));
                }
                config.dns_ports = value.into();
            }
            "TG_PORT" => {
                let port: u16 = r2o_config_number(key, value)?;
                if port == 0 {
                    return Err(r2o_invalid_config(key));
                }
                config.tg_port = port;
            }
            "R2O_PPE_DEOFFLOAD" => {
                config.ppe_deoffload = match value {
                    "0" => false,
                    "1" => true,
                    _ => return Err(r2o_invalid_config(key)),
                };
            }
            "LOGMAX" => {
                config.log_max = r2o_config_log_size(key, value)?;
            }
            "LOGKEEP" => {
                config.log_keep = r2o_config_log_size(key, value)?;
            }
            "LOG_EVERY" => {
                let seconds: u16 = r2o_config_number(key, value)?;
                if !(1..=3600).contains(&seconds) {
                    return Err(r2o_invalid_config(key));
                }
                config.log_every = seconds;
            }
            _ => {}
        }
    }
    if config.queue_num == config.queue_num6
        || parse_mark(&config.probe_mark).is_some_and(|probe| {
            probe != 0 && parse_mark(&config.mark).is_some_and(|route| route == probe)
        })
    {
        return Err(r2o_invalid_config(
            "QUEUE_NUM/QUEUE_NUM6 or PROBE_MARK/MARK",
        ));
    }
    Ok(())
}

fn r2o_invalid_config(key: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("invalid config value for {key}"),
    )
}

fn r2o_config_number<T: std::str::FromStr>(key: &str, value: &str) -> std::io::Result<T> {
    value.parse().map_err(|_| r2o_invalid_config(key))
}

fn r2o_config_log_size(key: &str, value: &str) -> std::io::Result<u32> {
    let bytes: u32 = r2o_config_number(key, value)?;
    if !(1024..=67_108_864).contains(&bytes) {
        return Err(r2o_invalid_config(key));
    }
    Ok(bytes)
}

fn valid_port_list(value: &str) -> bool {
    let mut slots = 0;
    for item in value.split(',') {
        let (start, end) = match item.split_once(':') {
            Some((start, end)) if !end.contains(':') => (start, end),
            Some(_) => return false,
            None => (item, item),
        };
        let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>()) else {
            return false;
        };
        if start > end || (item.contains(':') && start == end) {
            return false;
        }
        slots += if item.contains(':') { 2 } else { 1 };
        if slots > 15 {
            return false;
        }
    }
    slots > 0
}

fn valid_connbytes_window(value: &str) -> bool {
    let Some((start, end)) = value.split_once(':') else {
        return false;
    };
    if end.contains(':') {
        return false;
    }
    let (Ok(start), Ok(end)) = (start.parse::<u64>(), end.parse::<u64>()) else {
        return false;
    };
    start < end
}

fn parse_mark(value: &str) -> Option<u32> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.is_empty() || hex.len() > 8 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u32>().ok()
    }
}

fn valid_mark(value: &str) -> bool {
    parse_mark(value).is_some()
}

fn valid_only_mark(value: &str) -> bool {
    if value.is_empty() || value == "none" {
        return true;
    }
    if let Some((mark, mask)) = value.split_once('/') {
        !mask.contains('/') && valid_mark(mark) && parse_mark(mask).is_some_and(|mask| mask != 0)
    } else {
        valid_mark(value)
    }
}

fn strip_shell_value(raw: &str) -> Option<&str> {
    if raw.starts_with('"') || raw.starts_with('\'') {
        let quote = raw.as_bytes()[0] as char;
        let end = raw[1..].find(quote)? + 1;
        if raw[end + 1..]
            .trim()
            .trim_start_matches('#')
            .trim()
            .is_empty()
        {
            Some(&raw[1..end])
        } else {
            None
        }
    } else {
        Some(raw.split_once(" #").map_or(raw, |(v, _)| v).trim())
    }
}
