use serde_json::{Value, json};
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
const CONFIG_BODY_MAX: usize = 4096;
const WORKER_BODY_MAX: usize = 4096;
const WORKER_MAX: usize = 8;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
const UPDATE_CHECK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const UPDATE_INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static LAST_HEARTBEAT: Mutex<u64> = Mutex::new(0);

#[derive(Clone, Debug)]
pub struct Config {
    pub live_path: PathBuf,
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
    pub log_max: u32,
    pub log_keep: u32,
    pub log_every: u16,
    pub config_exists: bool,
    pub dirty: bool,
    pub control_enabled: bool,
    pub started_epoch: i64,
    pub unknown_keys: Vec<String>,
    action: Arc<Mutex<String>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            live_path: "/opt/r2o/state/live.json".into(),
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
            log_max: 2_097_152,
            log_keep: 1_048_576,
            log_every: 60,
            config_exists: false,
            dirty: false,
            control_enabled: false,
            started_epoch: 0,
            unknown_keys: Vec::new(),
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
    if request.path == "/api/config" {
        if !matches!(request.method, "GET" | "POST") {
            return text_response(405, "method not allowed\n");
        }
        return r2o_api_config(config, &request);
    }
    if request.path == "/api/update" {
        if request.method != "GET" {
            return text_response(405, "method not allowed\n");
        }
        return api_update(config);
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

fn api_status(config: &Config, query: &str) -> Response {
    let live = read_json_object(&config.live_path, BODY_MAX);
    let engine_pid = pid_path_running(&config.engine_pid_path);
    let controller_running = pid_path_running(&config.controller_pid_path).is_some();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
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
            if let Some(object) = value.as_object_mut() {
                if object.contains_key("linked") {
                    object.insert("linked".into(), Value::Bool(linked));
                }
                let revision = catalog_revision(&config.live_path);
                let unchanged = revision
                    .as_ref()
                    .is_some_and(|r| query.strip_prefix("catalog_revision=") == Some(r.as_str()));
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
        "telegram_configured":tg_configured,"telegram_running":tg_running,"telegram_status":tg_status,"telegram_stats":read_telegram_stats(&config.telegram_stats_path),
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
        ("/api/control/start", "engine-start"),
        ("/api/control/stop", "engine-stop"),
        ("/api/control/restart", "engine-restart"),
        ("/api/control/reapply", "reapply"),
        ("/api/control/clear-found", "clear-found"),
        ("/api/control/telegram-enable", "telegram-enable"),
        ("/api/control/telegram-disable", "telegram-disable"),
        ("/api/control/update-check", "update-check"),
        ("/api/control/update-install", "update-install"),
        ("/api/control/update-auto-on", "update-auto-on"),
        ("/api/control/update-auto-off", "update-auto-off"),
    ];
    let Some((_, command)) = actions.iter().find(|(path, _)| *path == request.path) else {
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
    if *command == "telegram-enable" && !telegram_config_flags(&config.config_path).1 {
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
    let result = if manager_present && *command == "update-check" {
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
            &json!({"ok":true,"message":"Команда службы выполняется"}),
        ),
        Err(ActionError::Busy) => json_response(
            409,
            &json!({"ok":false,"message":"Дождитесь завершения текущей команды"}),
        ),
        Err(ActionError::Start) => json_response(
            500,
            &json!({"ok":false,"message":"Не удалось запустить команду службы"}),
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
    mut child_command: Command,
    timeout: Duration,
) -> Result<(), ActionError> {
    let mut state = config.action.lock().map_err(|_| ActionError::Start)?;
    if *state == "running" {
        return Err(ActionError::Busy);
    }
    *state = "running".into();
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
            let result = child_command
                .spawn()
                .ok()
                .and_then(|mut child| {
                    let start = std::time::Instant::now();
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => return Some(status.success()),
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
                                return Some(false);
                            }
                            Err(_) => return Some(false),
                        }
                    }
                })
                .unwrap_or(false);
            if let Ok(mut state) = shared.lock() {
                *state = if result { "done" } else { "failed" }.into();
            }
        })
        .map_err(|_| {
            *state = "failed".into();
            ActionError::Start
        })?;
    Ok(())
}

fn r2o_api_config(config: &Config, request: &Request<'_>) -> Response {
    if request.method == "GET" {
        let mut settings = Config::default();
        if parse_config(&config.config_path, &mut settings, &[]).is_err() {
            return json_response(
                500,
                &json!({"ok":false,"message":"Не удалось прочитать настройки R2O"}),
            );
        }
        return json_response(
            200,
            &json!({
                "mode":settings.mode,
                "queue_num":settings.queue_num,
                "queue_num6":settings.queue_num6,
                "flow_capacity":settings.flow_capacity,
                "ipv6_enabled":settings.ipv6_enabled,
                "mark":settings.mark,
                "probe_mark":settings.probe_mark,
                "only_mark":settings.only_mark,
                "firewall_backend":settings.firewall_backend,
                "ports":settings.ports,
                "connbytes":settings.connbytes,
                "voice_ports":settings.voice_ports,
                "voice_connbytes":settings.voice_connbytes,
                "http_keepalive_ports":settings.http_keepalive_ports,
                "dns_ports":settings.dns_ports,
                "tg_port":settings.tg_port,
                "log_max":settings.log_max,
                "log_keep":settings.log_keep,
                "log_every":settings.log_every,
                "editable":settings.config_exists && config.control_enabled
            }),
        );
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
            &json!({"ok":false,"message":"Ожидаются настройки в формате JSON"}),
        );
    }
    if request.header("Transfer-Encoding").is_some() {
        return json_response(
            400,
            &json!({"ok":false,"message":"Проверьте режим и номер очереди NFQUEUE"}),
        );
    }
    let length = request.header("Content-Length").and_then(|s| {
        (!s.is_empty() && s.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| s.parse::<usize>().ok())
            .flatten()
    });
    if length.is_none_or(|n| n == 0 || n > CONFIG_BODY_MAX) || length != Some(request.body.len()) {
        return json_response(
            400,
            &json!({"ok":false,"message":"Проверьте режим и номер очереди NFQUEUE"}),
        );
    }
    let settings = match r2o_config_from_json(request.body) {
        Ok(settings) => settings,
        Err(()) => {
            return json_response(
                400,
                &json!({"ok":false,"message":"Проверьте режим, очереди и параметры datapath"}),
            );
        }
    };
    let action = "settings-restart";
    if r2o_write_settings_config(&config.config_path, &settings).is_err() {
        return json_response(
            500,
            &json!({"ok":false,"message":"Не удалось сохранить настройки R2O"}),
        );
    }
    match start_service_action(config, action) {
        Ok(()) => json_response(
            202,
            &json!({"ok":true,"message":if action == "engine-stop" {"Настройки сохранены, движок останавливается"} else {"Настройки сохранены, службы R2O перезапускаются"}}),
        ),
        Err(ActionError::Busy) => json_response(
            409,
            &json!({"ok":false,"message":"Настройки сохранены, дождитесь завершения текущей команды"}),
        ),
        Err(ActionError::Start) => json_response(
            500,
            &json!({"ok":false,"message":"Настройки сохранены, но службы R2O не удалось перезапустить"}),
        ),
    }
}

#[derive(Clone, Debug)]
struct EditableSettings {
    mode: String,
    queue_num: u16,
    queue_num6: u16,
    flow_capacity: u32,
    ipv6_enabled: bool,
    mark: String,
    probe_mark: String,
    only_mark: String,
    firewall_backend: String,
    ports: String,
    connbytes: String,
    voice_ports: String,
    voice_connbytes: String,
    http_keepalive_ports: String,
    dns_ports: String,
    tg_port: u16,
    log_max: u32,
    log_keep: u32,
    log_every: u16,
}

fn r2o_config_from_json(body: &[u8]) -> Result<EditableSettings, ()> {
    if body.len() > CONFIG_BODY_MAX {
        return Err(());
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    const KEYS: [&str; 19] = [
        "mode",
        "queue_num",
        "queue_num6",
        "flow_capacity",
        "ipv6_enabled",
        "mark",
        "probe_mark",
        "only_mark",
        "firewall_backend",
        "ports",
        "connbytes",
        "voice_ports",
        "voice_connbytes",
        "http_keepalive_ports",
        "dns_ports",
        "tg_port",
        "log_max",
        "log_keep",
        "log_every",
    ];
    if object.len() != KEYS.len() || object.keys().any(|key| !KEYS.contains(&key.as_str())) {
        return Err(());
    }
    let mode = object.get("mode").and_then(Value::as_str).ok_or(())?;
    if !matches!(mode, "off" | "observe" | "apply") {
        return Err(());
    }
    let queue_num = r2o_json_u16(object, "queue_num")?;
    let queue_num6 = r2o_json_u16(object, "queue_num6")?;
    if queue_num == queue_num6 {
        return Err(());
    }
    let flow_capacity = object
        .get("flow_capacity")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(())?;
    let ipv6_enabled = object
        .get("ipv6_enabled")
        .and_then(Value::as_bool)
        .ok_or(())?;
    let mark = r2o_json_mark(object, "mark", valid_mark)?;
    let probe_mark = r2o_json_mark(object, "probe_mark", valid_mark)?;
    if parse_mark(&probe_mark)
        .is_some_and(|probe| probe != 0 && parse_mark(&mark).is_some_and(|route| route == probe))
    {
        return Err(());
    }
    let only_mark = r2o_json_mark(object, "only_mark", valid_only_mark)?;
    let firewall_backend = object
        .get("firewall_backend")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "auto" | "iptables" | "nft"))
        .ok_or(())?
        .to_owned();
    let ports = r2o_json_firewall_value(object, "ports", valid_port_list)?;
    let connbytes = r2o_json_firewall_value(object, "connbytes", valid_connbytes_window)?;
    let voice_ports = r2o_json_firewall_value(object, "voice_ports", valid_port_list)?;
    let voice_connbytes =
        r2o_json_firewall_value(object, "voice_connbytes", valid_connbytes_window)?;
    let http_keepalive_ports =
        r2o_json_firewall_value(object, "http_keepalive_ports", valid_port_list)?;
    let dns_ports = r2o_json_firewall_value(object, "dns_ports", valid_port_list)?;
    let tg_port = r2o_json_u16(object, "tg_port")?;
    if tg_port == 0 {
        return Err(());
    }
    let log_max = r2o_json_u32(object, "log_max")?;
    let log_keep = r2o_json_u32(object, "log_keep")?;
    let log_every = r2o_json_u16(object, "log_every")?;
    if !(1024..=67_108_864).contains(&log_max)
        || !(1024..=67_108_864).contains(&log_keep)
        || !(1..=3600).contains(&log_every)
    {
        return Err(());
    }
    Ok(EditableSettings {
        mode: mode.into(),
        queue_num,
        queue_num6,
        flow_capacity,
        ipv6_enabled,
        mark,
        probe_mark,
        only_mark,
        firewall_backend,
        ports,
        connbytes,
        voice_ports,
        voice_connbytes,
        http_keepalive_ports,
        dns_ports,
        tg_port,
        log_max,
        log_keep,
        log_every,
    })
}

fn r2o_json_firewall_value(
    object: &serde_json::Map<String, Value>,
    key: &str,
    valid: fn(&str) -> bool,
) -> Result<String, ()> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| valid(value))
        .map(str::to_owned)
        .ok_or(())
}

fn r2o_json_u16(object: &serde_json::Map<String, Value>, key: &str) -> Result<u16, ()> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(())
}

fn r2o_json_u32(object: &serde_json::Map<String, Value>, key: &str) -> Result<u32, ()> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(())
}

fn r2o_json_mark(
    object: &serde_json::Map<String, Value>,
    key: &str,
    valid: fn(&str) -> bool,
) -> Result<String, ()> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| valid(value))
        .map(str::to_owned)
        .ok_or(())
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
    if write_worker_config(&config.config_path, &domains).is_err() {
        return json_response(
            500,
            &json!({"ok":false,"message":"Не удалось сохранить настройки Workers"}),
        );
    }
    match start_service_action(config, "telegram-restart") {
        Ok(()) => json_response(
            202,
            &json!({"ok":true,"message":"Настройки сохранены, C11 перезапускается"}),
        ),
        Err(ActionError::Busy) => json_response(
            409,
            &json!({"ok":false,"message":"Настройки сохранены, дождитесь завершения текущей команды"}),
        ),
        Err(ActionError::Start) => json_response(
            500,
            &json!({"ok":false,"message":"Настройки сохранены, но C11 не удалось перезапустить"}),
        ),
    }
}

fn worker_domains_from_json(body: &[u8]) -> Result<Vec<String>, ()> {
    if body.len() > WORKER_BODY_MAX || !body.is_ascii() {
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
    if !raw.is_ascii() {
        return Err(());
    }
    let text = std::str::from_utf8(&raw).map_err(|_| ())?;
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
    let line = line.trim_start_matches([' ', '\t']);
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    let Some((key, _)) = line.split_once('=') else {
        return false;
    };
    key.trim_end_matches([' ', '\t']) == "TG_CF_WORKER_DOMAIN"
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
    let text = String::from_utf8(source)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut output = String::new();
    for line in text.split_inclusive('\n') {
        if !worker_line(line.trim_end_matches(['\r', '\n'])) {
            output.push_str(line);
        }
    }
    if !domains.is_empty() {
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str("TG_CF_WORKER_DOMAIN=");
        output.push_str(&domains.join(","));
        output.push('\n');
    }
    r2o_write_config_atomically(path, &output, &metadata, "workers")
}

fn r2o_write_settings_config(path: &Path, settings: &EditableSettings) -> std::io::Result<()> {
    let (source, metadata) = read_regular_file_with_metadata(path, BODY_MAX)?;
    if source.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "нулевой байт в конфигурации",
        ));
    }
    let text = String::from_utf8(source)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let settings_pairs = [
        ("MODE", settings.mode.clone()),
        ("QUEUE_NUM", settings.queue_num.to_string()),
        ("QUEUE_NUM6", settings.queue_num6.to_string()),
        ("R2O_FLOW_CAPACITY", settings.flow_capacity.to_string()),
        (
            "IPV6_ENABLED",
            if settings.ipv6_enabled { "1" } else { "0" }.into(),
        ),
        ("MARK", settings.mark.clone()),
        ("PROBE_MARK", settings.probe_mark.clone()),
        ("ONLY_MARK", settings.only_mark.clone()),
        ("FW_BACKEND", settings.firewall_backend.clone()),
        ("PORTS", settings.ports.clone()),
        ("CONNBYTES", settings.connbytes.clone()),
        ("VOICE_PORTS", settings.voice_ports.clone()),
        ("VOICE_CONNBYTES", settings.voice_connbytes.clone()),
        (
            "HTTP_KEEPALIVE_PORTS",
            settings.http_keepalive_ports.clone(),
        ),
        ("DNS_PORTS", settings.dns_ports.clone()),
        ("TG_PORT", settings.tg_port.to_string()),
        ("LOGMAX", settings.log_max.to_string()),
        ("LOGKEEP", settings.log_keep.to_string()),
        ("LOG_EVERY", settings.log_every.to_string()),
    ];
    let mut output = String::with_capacity(text.len().saturating_add(256));
    let mut comments: Vec<(&str, String)> = Vec::new();
    for r2o_original_line in text.split_inclusive('\n') {
        let line = r2o_original_line.trim_end_matches(['\r', '\n']);
        let key = r2o_config_line_key(line);
        if let Some(key) = key.filter(|key| settings_pairs.iter().any(|(name, _)| name == key)) {
            let value = line
                .split_once('=')
                .map(|(_, value)| value)
                .unwrap_or_default();
            if let Some(at) = value.find(" #") {
                comments.push((key, value[at..].into()));
            }
            continue;
        }
        output.push_str(r2o_original_line);
    }
    let mut r2o_settings = String::with_capacity(256);
    for (key, value) in &settings_pairs {
        r2o_settings.push_str(key);
        r2o_settings.push('=');
        r2o_settings.push_str(value);
        if let Some((_, comment)) = comments.iter().find(|(comment_key, _)| comment_key == key) {
            r2o_settings.push_str(comment);
        }
        r2o_settings.push('\n');
    }
    let r2o_separator_len = usize::from(!output.is_empty() && !output.ends_with('\n'));
    if output
        .len()
        .saturating_add(r2o_separator_len)
        .saturating_add(r2o_settings.len())
        > BODY_MAX
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "конфигурация слишком велика",
        ));
    }
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    output.push_str(&r2o_settings);
    r2o_write_config_atomically(path, &output, &metadata, "settings")
}

fn r2o_config_line_key(line: &str) -> Option<&str> {
    let line = line.trim_start_matches([' ', '\t']);
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    line.split_once('=').map(|(key, _)| key.trim())
}

fn r2o_write_config_atomically(
    path: &Path,
    output: &str,
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
                    file.write_all(output.as_bytes())?;
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

fn catalog_revision(path: &Path) -> Option<String> {
    let raw = read_regular_file(path, BODY_MAX).ok()?;
    let _ = serde_json::from_slice::<Value>(&raw).ok()?;
    let mut hash = 14_695_981_039_346_656_037u64;
    let mut found = false;
    for (index, key) in ["boxes", "groups"].iter().enumerate() {
        let raw_value = top_level_raw_value(&raw, key);
        hash ^= (index + 1) as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
        hash ^= raw_value.map_or(0, |v| v.len()) as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
        if let Some(value) = raw_value {
            found = true;
            for byte in value {
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
    let Ok(text) = std::str::from_utf8(&raw) else {
        return (false, false);
    };
    let mut enabled = false;
    let mut mode_seen = false;
    let mut configured = true;
    let mut local = false;
    for line in text.lines() {
        let line = line.trim_start_matches([' ', '\t']);
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = match strip_config_quotes(value) {
            Ok(v) => v,
            Err(()) => {
                if key.trim() == "TG_MODE" {
                    return (false, false);
                } else {
                    continue;
                }
            }
        };
        match key.trim() {
            "TG_ENABLED" => enabled = matches!(value, "1" | "yes"),
            "TG_MODE" => {
                if mode_seen {
                    configured = false;
                }
                mode_seen = true;
                local = value == "local";
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
