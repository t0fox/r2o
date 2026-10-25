use r2k_core::control::PROTOCOL_VERSION;
use r2o_panel::server::{Config, parse_config, serve};
use std::error::Error;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const RELEASE: &str = match option_env!("R2O_RELEASE_ID") {
    Some(value) => value,
    None => "dev",
};

fn main() {
    if let Err(error) = run() {
        eprintln!("r2o-panel: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        usage();
        return Ok(());
    }
    if args.len() == 1 && (args[0] == "--version" || args[0] == "-V") {
        println!(
            "r2o-panel release={RELEASE} wire={PROTOCOL_VERSION} features=telegram-control update-control"
        );
        return Ok(());
    }
    if args.first().is_none_or(|arg| arg != "serve") {
        usage();
        return Err("используйте `r2o-panel serve`".into());
    }

    let mut config = Config::default();
    let mut log_path = None;
    let mut cli_overrides = Vec::new();
    let mut explicit_live = false;
    let mut i = 1;
    while i < args.len() {
        let option = args[i].to_str().ok_or("имя аргумента должно быть UTF-8")?;
        i += 1;
        if i >= args.len() {
            return Err(format!("для {option} требуется значение").into());
        }
        let value = args[i]
            .to_str()
            .ok_or("значение аргумента должно быть UTF-8")?;
        i += 1;
        match option {
            "--config" => config.config_path = PathBuf::from(value),
            "--live" => {
                config.live_path = PathBuf::from(value);
                explicit_live = true;
            }
            "--live-extra" => config.live_extra_paths.push(PathBuf::from(value)),
            "--assets" => config.asset_dir = PathBuf::from(value),
            "--health-file" => config.health_path = PathBuf::from(value),
            "--listen" => {
                config.panel_listen = value.into();
                cli_overrides.push("listen");
            }
            "--mode" => {
                config.mode = value.into();
                cli_overrides.push("mode");
            }
            "--state-dir" => {
                config.state_dir = PathBuf::from(value);
                cli_overrides.push("state-dir");
            }
            "--queue" => {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err("QUEUE_NUM должен содержать цифры от 0 до 65535".into());
                }
                config.queue_num = value.parse()?;
                cli_overrides.push("queue");
            }
            "--service" => config.service_path = PathBuf::from(value),
            "--manager" => config.manager_path = PathBuf::from(value),
            "--manager-root" => config.manager_root = PathBuf::from(value),
            "--engine-pid" => config.engine_pid_path = PathBuf::from(value),
            "--controller-pid" => config.controller_pid_path = PathBuf::from(value),
            "--telegram-pid" => config.telegram_pid_path = PathBuf::from(value),
            "--telegram-status" => config.telegram_status_path = PathBuf::from(value),
            "--telegram-stats" => config.telegram_stats_path = PathBuf::from(value),
            "--log" => log_path = Some(PathBuf::from(value)),
            _ => return Err(format!("неизвестный параметр: {option}").into()),
        }
    }
    let config_path = config.config_path.clone();
    parse_config(&config_path, &mut config, &cli_overrides)?;
    if !explicit_live {
        config.live_path = config.state_dir.join("live.json");
    }
    config.update_state_path = config.manager_root.join("state/update.json");
    if !args.windows(2).any(|w| w[0] == "--telegram-status") {
        config.telegram_status_path = config.state_dir.join("telegram.status");
    }
    if !args.windows(2).any(|w| w[0] == "--telegram-stats") {
        config.telegram_stats_path = config.state_dir.join("telegram.stats.sock");
    }
    if !matches!(config.mode.as_str(), "off" | "observe" | "apply") {
        return Err(format!("недопустимый MODE: {}", config.mode).into());
    }
    if config.panel_listen.is_empty() {
        eprintln!("PANEL_LISTEN пуст — панель выключена");
        return Ok(());
    }
    let (listen_host, listen_port) = split_listen(&config.panel_listen)?;
    if let Some(path) = log_path {
        redirect_logs(&path)?;
    }
    let listener = TcpListener::bind((listen_host, listen_port))?;
    eprintln!("внимание: у панели нет аутентификации");
    config.started_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    config.control_enabled = true;
    println!(
        "r2o-panel {}\nhttp://{}/",
        config.version, config.panel_listen
    );
    serve(listener, config)?;
    Ok(())
}

fn split_listen(listen: &str) -> Result<(&str, u16), Box<dyn Error>> {
    let (host, port) = if let Some(rest) = listen.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']').ok_or("неверный PANEL_LISTEN")?;
        let port = suffix.strip_prefix(':').ok_or("неверный PANEL_LISTEN")?;
        (host, port)
    } else {
        listen.rsplit_once(':').ok_or("неверный PANEL_LISTEN")?
    };
    if host.is_empty()
        || host.len() >= 256
        || port.is_empty()
        || port.len() >= 16
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || !matches!(port.parse::<u32>(), Ok(1..=65535))
    {
        return Err("неверный PANEL_LISTEN".into());
    }
    Ok((host, port.parse()?))
}

fn redirect_logs(path: &std::path::Path) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = file.as_raw_fd();
        if unsafe { libc::dup2(fd, libc::STDOUT_FILENO) } < 0
            || unsafe { libc::dup2(fd, libc::STDERR_FILENO) } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn usage() {
    println!(
        "r2o-panel --version | serve [--config FILE] [--live FILE] [--live-extra FILE] [--assets DIR] [--listen HOST:PORT] [--state-dir DIR] [--mode MODE] [--queue N] [--service FILE] [--manager FILE] [--manager-root DIR] [--engine-pid FILE] [--controller-pid FILE] [--telegram-stats PATH] [--log FILE]"
    );
}
