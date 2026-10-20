use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use r2o_controller::fetch::{
    FetchOptions, R2oFetchVolumeTxVerdict, fetch, r2o_fetch_measure_rx_volume,
    r2o_fetch_measure_tx_volume, r2o_fetch_quic_with_budget, r2o_fetch_snapshot_wire_len,
};
use r2o_controller::r2o_quic_http3::R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS;

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("r2o-fetch: {error}");
            2
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32, String> {
    let mut name = None;
    let mut ip = None;
    let mut port = 443_u16;
    let mut path = "/".to_owned();
    let mut deadline = Duration::from_millis(15_000);
    let mut tls12 = false;
    let mut wire_len = None;
    let mut r2o_quic = false;
    let mut r2o_quic_budget_packets = R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS;
    let mut r2o_quic_budget_set = false;
    let mut r2o_ladder = false;
    let mut mark = None;
    let mut r2o_snapshot = None;
    let mut r2o_control_path = std::env::var_os("R2O_CONTROL_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("R2O_DIR").unwrap_or_else(|| "/opt/r2o".into()))
                .join("run/r2o-datapath4.sock")
        });
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();

    if arguments.len() == 1 && matches!(arguments[0].to_str(), Some("--help" | "-h")) {
        print_help();
        return Ok(0);
    }
    if arguments.len() == 1 && matches!(arguments[0].to_str(), Some("--version" | "-V")) {
        println!("r2o-fetch {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }

    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| "параметры командной строки должны быть в UTF-8".to_owned())?;
        match option {
            "--name" => {
                index += 1;
                name = Some(argument(&arguments, index, "--name")?.to_owned());
            }
            "--ip" => {
                index += 1;
                ip = Some(
                    argument(&arguments, index, "--ip")?
                        .parse::<IpAddr>()
                        .map_err(|error| format!("неверный IP-адрес: {error}"))?,
                );
            }
            "--port" => {
                index += 1;
                port = argument(&arguments, index, "--port")?
                    .parse::<u16>()
                    .map_err(|error| format!("неверный порт: {error}"))?;
            }
            "--path" => {
                index += 1;
                path = argument(&arguments, index, "--path")?.to_owned();
            }
            "--deadline" => {
                index += 1;
                let milliseconds = argument(&arguments, index, "--deadline")?
                    .parse::<u64>()
                    .map_err(|error| format!("неверный срок ожидания: {error}"))?;
                deadline = Duration::from_millis(milliseconds);
            }
            "--wire" => {
                index += 1;
                let value = argument(&arguments, index, "--wire")?
                    .parse::<usize>()
                    .map_err(|error| format!("неверная длина ClientHello: {error}"))?;
                wire_len = (value != 0).then_some(value);
            }
            "--snapshot" => r2o_snapshot = Some(Duration::from_millis(60_000)),
            _ if option.starts_with("--snapshot=") => {
                let value = option["--snapshot=".len()..]
                    .parse::<u64>()
                    .map_err(|error| format!("неверный срок снимка: {error}"))?;
                r2o_snapshot = Some(Duration::from_millis(value));
            }
            "--control" => {
                index += 1;
                r2o_control_path = PathBuf::from(argument(&arguments, index, "--control")?);
            }
            "--mark" => {
                index += 1;
                let value = argument(&arguments, index, "--mark")?;
                let (value, radix) = value
                    .strip_prefix("0x")
                    .map_or((value, 10), |hex| (hex, 16));
                mark = Some(
                    u32::from_str_radix(value, radix)
                        .map_err(|error| format!("неверная метка SO_MARK: {error}"))?,
                );
            }
            "--tls12" => tls12 = true,
            "--quic" => r2o_quic = true,
            "--quic-budget" => {
                index += 1;
                r2o_quic_budget_packets = argument(&arguments, index, "--quic-budget")?
                    .parse::<u32>()
                    .map_err(|error| format!("неверный QUIC-бюджет: {error}"))?;
                r2o_quic_budget_set = true;
            }
            "--ladder" => r2o_ladder = true,
            _ => return Err(format!("неизвестный параметр {option}; используйте --help")),
        }
        index += 1;
    }

    if r2o_quic_budget_set && !r2o_quic {
        return Err("параметр --quic-budget требует --quic".into());
    }

    let name = name.ok_or_else(|| "обязателен параметр --name".to_owned())?;
    if let Some(r2o_wait) = r2o_snapshot.filter(|wait| !wait.is_zero()) {
        wire_len = Some(r2o_fetch_snapshot_wire_len(
            &name,
            &r2o_control_path,
            r2o_wait,
        )?);
        if r2o_quic {
            wire_len = Some(
                wire_len
                    .and_then(|length| length.checked_sub(5))
                    .filter(|length| *length != 0)
                    .ok_or_else(|| "TCP-снимок короче заголовка TLS-записи".to_owned())?,
            );
        }
    }
    let options = FetchOptions {
        name,
        ip,
        port,
        path,
        deadline,
        tls12,
        wire_len,
        mark,
    };
    options.validate()?;
    if r2o_ladder {
        let r2o_started = std::time::Instant::now();
        let r2o_tx = r2o_fetch_measure_tx_volume(&options)?;
        let r2o_rx = r2o_fetch_measure_rx_volume(&options);
        println!(
            "цель:        {} ({}:{}), путь {}",
            options.name,
            r2o_tx.address.ip(),
            options.port,
            options.path
        );
        println!(
            "приветствие: {}, {}, метка {}",
            options
                .wire_len
                .map(|length| format!("ClientHello {length} байт"))
                .unwrap_or_else(|| "профиль rustls, длина не задана".into()),
            if options.tls12 { "TLS 1.2" } else { "TLS 1.3" },
            options
                .mark
                .map(|value| format!("0x{value:x}"))
                .unwrap_or_else(|| "0x0".into())
        );
        println!(
            "лестница:    {}{}",
            r2o_tx.verdict.r2o_label(),
            if r2o_tx.verdict == R2oFetchVolumeTxVerdict::Cut {
                ""
            } else {
                " (обрыва нет)"
            }
        );
        if r2o_tx.at_kb != 0 {
            println!("оборвалась:  около {} КБ", r2o_tx.at_kb);
        }
        if let Some(evidence) = &r2o_rx.evidence {
            println!(
                "вход:        обрыв {} около {} КБ{}",
                match evidence.domain {
                    r2o_controller::r2o_volume::R2oVolumeRxDomain::HttpBody => "HTTP-тела",
                    r2o_controller::r2o_volume::R2oVolumeRxDomain::TlsWire => "TLS-потока",
                },
                evidence.cut_kb,
                if evidence.cut_packets == 0 {
                    String::new()
                } else {
                    format!(", {} пакетов с данными", evidence.cut_packets)
                }
            );
        } else {
            println!("вход:        {}", r2o_rx.reason);
        }
        println!("время:       {} мс", r2o_started.elapsed().as_millis());
        if r2o_tx.verdict != R2oFetchVolumeTxVerdict::Passed {
            println!("причина:     {}", r2o_tx.reason);
        }
        for failure in &r2o_rx.failures {
            println!("ошибка RX:   {failure}");
        }
        let mut r2o_failed =
            r2o_tx.verdict == R2oFetchVolumeTxVerdict::Cut || r2o_rx.evidence.is_some();
        if r2o_quic {
            r2o_failed |= !r2o_run_quic(&options, r2o_quic_budget_packets)?;
        }
        return Ok(i32::from(r2o_failed));
    }
    if r2o_quic {
        return Ok(i32::from(!r2o_run_quic(&options, r2o_quic_budget_packets)?));
    }
    let result = match fetch(&options) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("r2o-fetch: {error}");
            return Ok(1);
        }
    };
    println!(
        "цель:        {} ({}), путь {}",
        options.name, result.address, options.path
    );
    println!(
        "приветствие: {}, {}",
        options
            .wire_len
            .map(|length| format!("ClientHello {length} байт"))
            .unwrap_or_else(|| "профиль rustls, длина не задана".into()),
        if options.tls12 {
            "TLS 1.2"
        } else {
            "TLS 1.2/1.3"
        }
    );
    println!(
        "маршрут:     {}",
        options
            .mark
            .map(|value| format!("SO_MARK 0x{value:x}"))
            .unwrap_or_else(|| "без метки, через планы datapath".into())
    );
    println!("TLS:         {}", result.tls.unwrap_or("рукопожатия нет"));
    println!("HTTP:        {}", result.status);
    if let Some(expected) = result.body_expected {
        println!("тело:        {} из {} байт", result.body_bytes, expected);
    } else if result.chunked {
        println!("тело:        {} байт (chunked)", result.body_bytes);
    } else if result.body_bytes != 0 {
        println!("тело:        {} байт", result.body_bytes);
    }
    if result.gzip {
        println!("кодировка:   gzip");
    }
    println!(
        "итог:        {}",
        if result.complete {
            "ОТВЕТ ПОЛУЧЕН ЦЕЛИКОМ"
        } else if result.status != 0 {
            "ОБРЫВ: ответ начался и не доехал"
        } else {
            "ОБРЫВ: ответа нет"
        }
    );
    println!(
        "время:       {} мс, местный порт {}",
        result.elapsed.as_millis(),
        result.local_port
    );
    if let Some(reason) = result.reason {
        println!("причина:     {reason}");
    }
    Ok(i32::from(!result.complete))
}

fn r2o_run_quic(options: &FetchOptions, budget_packets: u32) -> Result<bool, String> {
    let result = r2o_fetch_quic_with_budget(options, budget_packets)?;
    r2o_print_quic_result(options, &result, budget_packets);
    Ok(result.data.complete || result.data.budget_passed)
}

fn r2o_print_quic_result(
    options: &FetchOptions,
    result: &r2o_controller::fetch::R2oQuicFetchResult,
    budget_packets: u32,
) {
    println!(
        "цель:        {} ({}), путь {}",
        options.name, result.address, options.path
    );
    println!("режим:       HTTP/3 GET с повторами, бюджетом и PING-контролем");
    if let Some(length) = options.wire_len {
        println!("приветствие: ClientHello {length} байт");
    }
    println!(
        "маршрут:     {}",
        options
            .mark
            .map(|value| format!("SO_MARK 0x{value:x}"))
            .unwrap_or_else(|| "без метки, через планы datapath".into())
    );
    println!(
        "TLS:         {}",
        if result.data.handshake_confirmed {
            "1.3"
        } else {
            "рукопожатия нет"
        }
    );
    println!("HTTP:        {}", result.data.status);
    println!("тело:        {} байт", result.data.body_bytes);
    println!("запросы:     {}", result.data.requests);
    println!("датаграммы:  {}", result.data.datagrams);
    if result.data.budget_required {
        let r2o_required_datagrams = budget_packets.saturating_mul(2);
        println!(
            "бюджет:      {} из {} датаграмм — {}",
            result.data.datagrams,
            r2o_required_datagrams,
            if result.data.budget_passed {
                "пройден"
            } else {
                "не пройден"
            }
        );
    } else {
        println!("бюджет:      отключён, проверен один ответ");
    }
    println!(
        "PING:        подтверждено {}/{}",
        result.data.r2o_ping_acks, result.data.r2o_ping_probes
    );
    if result.data.r2o_quic_stalled {
        println!(
            "QUIC-поток:  {}",
            if result.data.r2o_quic_one_way {
                "сервер передаёт, но не подтверждает наши пакеты"
            } else {
                "остановлен"
            }
        );
    }
    println!(
        "итог:        {}",
        if result.data.complete {
            "ОТВЕТ ПОЛУЧЕН ЦЕЛИКОМ"
        } else if result.data.budget_required && result.data.budget_passed {
            "БЮДЖЕТ ПРОЙДЕН, ПОВТОРНЫЕ ОТВЕТЫ ПОЛУЧЕНЫ"
        } else {
            "HTTP/3-передача не подтверждена"
        }
    );
    println!("местный UDP-порт: {}", result.local_port);
    println!("время:       {} мс", result.elapsed.as_millis());
    if let Some(reason) = result.data.error.as_deref() {
        println!("причина:     {reason}");
    }
}

fn argument<'a>(
    arguments: &'a [std::ffi::OsString],
    index: usize,
    option: &str,
) -> Result<&'a str, String> {
    arguments
        .get(index)
        .ok_or_else(|| format!("после {option} требуется значение"))?
        .to_str()
        .ok_or_else(|| format!("значение {option} должно быть в UTF-8"))
}

fn print_help() {
    println!(
        "r2o-fetch — HTTPS-проверка с измерением полноты ответа\n\n\
         Использование:\n\
         r2o-fetch --name ИМЯ [--ip АДРЕС] [--port N] [--path /путь]\n\
                    [--tls12 | --quic] [--quic-budget N] [--ladder]\n\
                    [--wire БАЙТЫ] [--snapshot[=МС]]\n\
                    [--control СОКЕТ] [--deadline МС] [--mark 0xN]\n\n\
         --name      имя SNI и заголовка Host (обязательно)\n\
         --ip        адрес цели; без него имя разрешается системой\n\
         --port      порт, по умолчанию 443\n\
         --path      путь запроса, по умолчанию /\n\
         --tls12     ограничить рукопожатие TLS 1.2\n\
         --quic      выполнить QUIC/HTTP/3 GET (TLS 1.3) с PING-контролем тишины\n\
         --quic-budget N  требовать 2 × N датаграмм; по умолчанию N=25, 0 отключает бюджет\n\
         --ladder    выполнить десять HEAD-шагов и отдельную RX-проверку identity/gzip\n\
         --wire      задать длину ClientHello; 0 выбирает длину профиля rustls\n\
         --snapshot  дождаться живого ClientHello с тем же именем; по умолчанию 60000 мс\n\
         --control   основной сокет datapath; используется соседний путь .snapshot\n\
                     по умолчанию R2O_CONTROL_SOCKET или /opt/r2o/run/r2o-datapath4.sock\n\
         --deadline  срок ожидания, по умолчанию 15000 мс\n\
         --mark      установить SO_MARK до подключения; без метки действуют планы datapath\n\n\
         Для TCP длина включает пять байт заголовка TLS-записи; для QUIC — только handshake-сообщение.\n\
         Снимок выполняется до запроса и заменяет значение --wire.\n\
         --ladder измеряет TCP/TLS даже при наличии --quic."
    );
}
