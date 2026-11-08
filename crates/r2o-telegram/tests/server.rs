use std::time::Duration;

use r2o_telegram::config::Config;
use r2o_telegram::server;

#[tokio::test]
async fn writes_d2o_health_file_before_listener_is_ready() {
    let temp = std::env::temp_dir().join(format!(
        "r2o-tg-health-server-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp).unwrap();
    let health_path = temp.join("d2ktg.health");
    let stats_path = temp.join("stats.sock");
    let config = Config::try_from_cli_line(&format!(
        "--host 127.0.0.1 --port 0 --quiet --health-file {} --stats-socket-path {}",
        health_path.display(),
        stats_path.display()
    ))
    .unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (listen_tx, listen_rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        server::run_with_listen(
            config,
            async move {
                let _ = shutdown_rx.await;
            },
            move |info| {
                let _ = listen_tx.send(info.addr);
            },
        )
        .await
    });

    let address = tokio::time::timeout(Duration::from_secs(5), listen_rx)
        .await
        .expect("listener не начал принимать подключения")
        .expect("callback прослушивания завершился без адреса");
    assert_ne!(address.port(), 0);

    // Файл обязан существовать уже к моменту готовности listener: иначе
    // watchdog с коротким интервалом успеет перезапустить живой процесс.
    let line = std::fs::read_to_string(&health_path).expect("heartbeat-файл не создан");
    let fields: Vec<&str> = line.trim_end().split(' ').collect();
    assert_eq!(fields.len(), 11, "{line:?}");
    assert_eq!(fields[0], "D2KH1");
    assert_eq!(fields[1], std::process::id().to_string());
    assert!(fields[2].parse::<u64>().unwrap() > 0);
    assert!(fields[3].parse::<u64>().unwrap() > 0);
    assert!(!fields[4].is_empty());
    assert_eq!(fields[7], "-");
    assert_eq!(fields[9], "1", "ready должен быть 1");
    assert_eq!(fields[10], "0", "external у local-режима всегда 0");

    shutdown_tx.send(()).unwrap();
    task.await
        .expect("задача сервера завершилась аварийно")
        .expect("сервер вернул ошибку при остановке");
    std::fs::remove_dir_all(&temp).unwrap();
}

#[tokio::test]
async fn implicit_transparent_listener_binds_then_stops_cleanly() {
    let config = Config::try_from_cli_line("--host 127.0.0.1 --port 0 --quiet").unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (listen_tx, listen_rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        server::run_with_listen(
            config,
            async move {
                let _ = shutdown_rx.await;
            },
            move |info| {
                let _ = listen_tx.send(info.addr);
            },
        )
        .await
    });

    let address = tokio::time::timeout(Duration::from_secs(5), listen_rx)
        .await
        .expect("listener не начал принимать подключения")
        .expect("callback прослушивания завершился без адреса");
    assert_ne!(address.port(), 0);
    tokio::net::TcpStream::connect(address)
        .await
        .expect("listener должен принимать TCP подключения");

    shutdown_tx.send(()).unwrap();
    task.await
        .expect("задача сервера завершилась аварийно")
        .expect("сервер вернул ошибку при остановке");

    tokio::net::TcpListener::bind(address)
        .await
        .expect("порт должен освободиться после остановки");
}
