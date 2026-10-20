//! r2o-telegram — прозрачный мост Telegram MTProto через WebSocket.
//!
//! Принимает соединения MTProto и передаёт их по WebSocket к узлам Telegram,
//! обходя сети, которые блокируют прямой TCP-трафик Telegram.
//!
//! # Схема соединения
//!
//! ```
//! Telegram Desktop → MTProto (TCP 1443) → r2o-telegram → WebSocket (TLS 443) → узел Telegram
//! ```
//!
//! Обработка соединений находится в [`r2o_telegram::transparent_proxy`],
//! а обфускация MTProto — в [`r2o_telegram::crypto`].

use std::io::IsTerminal as _;
use std::net::Ipv4Addr;
use std::path::Path;

use r2o_telegram::config::Config;
use r2o_telegram::server;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("не удалось установить CryptoProvider rustls ring");

    let args: Vec<_> = std::env::args().collect();
    if let [_, command, host, address, ca_bundle] = args.as_slice()
        && command == "--check-instagram-ip"
    {
        let address = match address.parse::<Ipv4Addr>() {
            Ok(address) if r2o_telegram::meta_edge::certificate_name(host).is_some() => address,
            _ => {
                eprintln!("ожидаются точное имя Meta и IPv4-адрес");
                std::process::exit(2);
            }
        };
        return match r2o_telegram::meta_edge::check_meta_edge(host, address, Path::new(ca_bundle))
            .await
        {
            Ok(()) => {
                println!(
                    "Meta edge доступен, сертификат проверен; обход блокировки не подтверждён"
                );
            }
            Err(error) => {
                eprintln!("ошибка TLS-проверки Meta edge: {error}");
                std::process::exit(1);
            }
        };
    }

    let config = Config::from_args();
    init_logging(&config);

    if config.initialize_identity {
        let identity = match r2o_telegram::identity::Identity::load_or_mint(&config.identity_file) {
            Ok(identity) => identity,
            Err(error) => {
                eprintln!("ошибка идентичности установки: {error}");
                std::process::exit(1);
            }
        };
        println!(
            "Локальная идентичность готова: {}",
            identity.install_id_hex()
        );
        return;
    }

    if config.resolve_meta {
        match r2o_telegram::meta_dns::resolve_meta_direct().await {
            Ok(results) => println!("{}", serde_json::to_string(&results).unwrap()),
            Err(error) => {
                eprintln!("ошибка DNS-запроса Meta: {error}");
                std::process::exit(1);
            }
        }
        return;
    }

    if config.refresh_meta_dns {
        if let Err(error) = r2o_telegram::meta_dns::refresh_from_env().await {
            eprintln!("ошибка обновления Meta DNS: {error}");
            std::process::exit(1);
        }
        return;
    }

    if config.remove_meta_dns {
        if let Err(error) = r2o_telegram::meta_dns::remove_from_env() {
            eprintln!("ошибка удаления Meta DNS: {error}");
            std::process::exit(1);
        }
        return;
    }

    if config.meta_dns_scheduler {
        tokio::select! {
            _ = shutdown_signal() => {},
            result = r2o_telegram::meta_dns::run_scheduler() => {
                if let Err(error) = result {
                    eprintln!("ошибка планировщика Meta DNS: {error}");
                    std::process::exit(1);
                }
            }
        }
        return;
    }

    if config.stats {
        match r2o_telegram::stats::read_socket(&config.stats_socket_path).await {
            Ok(snapshot) => print!("{}", String::from_utf8_lossy(&snapshot)),
            Err(error) => {
                eprintln!("не удалось получить статистику Telegram: {error}");
                std::process::exit(1);
            }
        }
        return;
    }

    if config.check {
        match r2o_telegram::diagnostics::run(&config).await {
            Ok(report) => {
                println!(
                    "{}",
                    serde_json::to_string(&report).expect("JSON диагностики")
                );
                if !report.has_healthy_route() {
                    std::process::exit(2);
                }
            }
            Err(error) => {
                eprintln!("ошибка диагностики Telegram: {error}");
                std::process::exit(1);
            }
        }
        return;
    }

    match server::run(config, shutdown_signal()).await {
        Ok(()) => {}
        // Bind и InvalidListenAddress означают обычную ошибку пользователя.
        // «Порт уже занят» не должно приводить к panic с предложением
        // включить RUST_BACKTRACE.
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).expect("не удалось подписаться на SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn init_logging(config: &Config) {
    let log_level = if config.quiet {
        "off"
    } else if config.verbose {
        "debug"
    } else {
        "info"
    };

    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| log_level.into());

    if let Some(ref path) = config.log_file {
        // Для файла отключить ANSI-цвета в журнале.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| panic!("не удалось открыть файл журнала '{}': {}", path, e));
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .with_writer(file)
            .init();
    } else {
        // В консоли отключить ANSI-цвета, если Windows не поддерживает режим
        // виртуального терминала. Отключать их также при перенаправлении stderr,
        // например в канал или файл.
        let use_ansi = std::io::stderr().is_terminal() && !cfg!(windows);
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(use_ansi)
            .init();
    }
}
