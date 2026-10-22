use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use r2o_controller::fetch::{
    FetchOptions, R2oFetchVolumeTxVerdict, r2o_fetch_detailed, r2o_fetch_measure_rx_volume,
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
    let mut ip_raw = None;
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
    let r2o_json = arguments
        .iter()
        .any(|argument| argument.to_str() == Some("--json"));

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
                ip_raw = Some(argument(&arguments, index, "--ip")?.to_owned());
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
                mark = Some(parse_mark(value)?);
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
            "--json" => {}
            _ => return Err(format!("неизвестный параметр {option}; используйте --help")),
        }
        index += 1;
    }

    if r2o_quic_budget_set && !r2o_quic {
        return Err("параметр --quic-budget требует --quic".into());
    }

    let name = name.ok_or_else(|| "обязателен параметр --name".to_owned())?;
    if !r2o_quic && wire_len.is_none() {
        wire_len = Some(
            if tls12 {
                r2o_controller::hello::legacy_client_hello(&name)
            } else {
                r2o_controller::hello::modern_client_hello(&name)
            }
            .map_err(|error| format!("не удалось собрать профиль ClientHello: {error}"))?
            .len(),
        );
    }
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
    let ip = match ip_raw {
        Some(value) => match value.parse::<IpAddr>() {
            Ok(address) => Some(address),
            Err(_) if value.is_empty() => {
                if r2o_json {
                    r2o_print_dns_failed(&name);
                } else {
                    eprintln!("имя {} не разрешилось", name);
                }
                return Ok(2);
            }
            Err(error) => return Err(format!("неверный IP-адрес: {error}")),
        },
        None => None,
    };
    let ip = match ip {
        Some(ip) => ip,
        None => match (name.as_str(), port).to_socket_addrs() {
            Ok(mut addresses) => match addresses.next() {
                Some(address) => address.ip(),
                None => {
                    if r2o_json {
                        r2o_print_dns_failed(&name);
                    } else {
                        eprintln!("имя {} не разрешилось", name);
                    }
                    return Ok(2);
                }
            },
            Err(error) => {
                if r2o_json {
                    r2o_print_dns_failed(&name);
                } else {
                    eprintln!("имя {} не разрешилось: {error}", name);
                }
                return Ok(2);
            }
        },
    };
    let options = FetchOptions {
        name,
        ip: Some(ip),
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
        let r2o_rx = if options.port == 80 || r2o_tx.reason.starts_with("нет TCP к ") {
            Default::default()
        } else {
            r2o_fetch_measure_rx_volume(&options)
        };
        if r2o_json {
            let r2o_verdict = match r2o_tx.verdict {
                R2oFetchVolumeTxVerdict::Unreachable => "unreachable",
                R2oFetchVolumeTxVerdict::Short => "short",
                R2oFetchVolumeTxVerdict::Cut => "cut",
                R2oFetchVolumeTxVerdict::Passed => "passed",
            };
            let r2o_verdict_human = match r2o_tx.verdict {
                R2oFetchVolumeTxVerdict::Unreachable => "мишень не ответила",
                R2oFetchVolumeTxVerdict::Short => "объём не набран — вердикта нет",
                R2oFetchVolumeTxVerdict::Cut => "обрыв по объёму",
                R2oFetchVolumeTxVerdict::Passed => "объём прошёл",
            };
            let r2o_rx_cut = r2o_rx.evidence.is_some();
            let r2o_reason = r2o_tx
                .reason
                .strip_prefix(&format!("нет TCP к {}: ", r2o_tx.address))
                .map(|reason| {
                    format!(
                        "нет TCP: {}",
                        reason.split(" (os error ").next().unwrap_or(reason)
                    )
                })
                .unwrap_or_else(|| r2o_tx.reason.clone());
            println!(
                "{}",
                serde_json::json!({
                    "schema": 2,
                    "shape": "ladder",
                    "mode": "ladder",
                    "name": options.name,
                    "ip": r2o_tx.address.ip().to_string(),
                    "port": options.port,
                    "verdict": r2o_verdict,
                    "verdict_human": r2o_verdict_human,
                    "tx_passed": r2o_tx.verdict == R2oFetchVolumeTxVerdict::Passed,
                    "at_kb": r2o_tx.at_kb,
                    "rx_cut": r2o_rx_cut,
                    "rx_at_kb": r2o_rx.evidence.as_ref().map_or(0, |evidence| evidence.cut_kb),
                    "elapsed_ms": r2o_started.elapsed().as_millis(),
                    "reason": r2o_reason,
                    "rx_short": r2o_rx.short_bytes.is_some(),
                    "rx_unmeasured": r2o_rx.rx_unmeasured,
                    "rx_direct_complete": r2o_rx.direct_complete,
                    "rx_tls_unavailable": r2o_rx.rx_tls_unavailable,
                    "measured_path": r2o_rx.measured_path.as_deref().unwrap_or(""),
                    "rx_reason": r2o_rx.reason,
                })
            );
            return Ok(
                if r2o_tx.verdict == R2oFetchVolumeTxVerdict::Cut || r2o_rx_cut {
                    1
                } else if r2o_tx.verdict == R2oFetchVolumeTxVerdict::Passed {
                    0
                } else {
                    2
                },
            );
        }
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
        } else if !r2o_rx.reason.is_empty() {
            println!("вход:        {}", r2o_rx.reason);
        }
        println!("время:       {} мс", r2o_started.elapsed().as_millis());
        if r2o_tx.verdict != R2oFetchVolumeTxVerdict::Passed {
            println!("причина:     {}", r2o_tx.reason);
        }
        for failure in &r2o_rx.failures {
            println!("ошибка RX:   {failure}");
        }
        return Ok(
            if r2o_tx.verdict == R2oFetchVolumeTxVerdict::Cut || r2o_rx.evidence.is_some() {
                1
            } else if r2o_tx.verdict == R2oFetchVolumeTxVerdict::Passed {
                0
            } else {
                2
            },
        );
    }
    if r2o_quic {
        let r2o_result = r2o_fetch_quic_with_budget(&options, r2o_quic_budget_packets)?;
        if r2o_json {
            let r2o_status = r2o_result.data.status;
            let r2o_handshake = r2o_result.data.handshake_confirmed;
            println!(
                "{}",
                serde_json::json!({
                    "schema": 2,
                    "client": "d2k-own-profile",
                    "name": options.name,
                    "shape": "quic",
                    "ip": r2o_result.address.ip().to_string(),
                    "port": options.port,
                    "path": options.path,
                    "protocol": "quic",
                    "body_bytes": null,
                    "quic_stream_bytes": r2o_result.data.body_bytes,
                    "body_expected": null,
                    "body_has_length": null,
                    "headers_inspected": false,
                    "location": null,
                    "cloudflare_challenge": null,
                    "wire_requested": options.wire_len.unwrap_or(0),
                    "mark": options.mark.unwrap_or(0),
                    "elapsed_ms": r2o_result.elapsed.as_millis(),
                    "local_port": if r2o_handshake { r2o_result.local_port } else { 0 },
                    "negotiated_tls": if r2o_handshake { 0x0304 } else { 0 },
                    "http_status": r2o_status,
                    "response_complete": r2o_result.data.complete,
                    "level": if r2o_result.data.local_refusal { 0 } else if r2o_status > 0 { 3 } else if r2o_handshake { 2 } else { 0 },
                    "local_refusal": r2o_result.data.local_refusal,
                    "measured": !r2o_result.data.local_refusal,
                    "name_ok": if r2o_handshake { 1 } else { -1 },
                    "reason": r2o_result.data.error.as_deref().unwrap_or(""),
                })
            );
            return Ok(if r2o_result.data.local_refusal {
                2
            } else {
                i32::from(!(r2o_result.data.complete || r2o_result.data.budget_passed))
            });
        }
        r2o_print_quic_result(&options, &r2o_result, r2o_quic_budget_packets);
        return Ok(if r2o_result.data.local_refusal {
            2
        } else {
            i32::from(!(r2o_result.data.complete || r2o_result.data.budget_passed))
        });
    }
    let r2o_fetch_started = std::time::Instant::now();
    let result = match r2o_fetch_detailed(&options) {
        Ok(result) => result,
        Err(error) => {
            if r2o_json {
                let r2o_no_tcp =
                    !error.local_refusal && error.message.starts_with("не удалось подключиться к ");
                println!(
                    "{}",
                    serde_json::json!({
                        "schema": 2,
                        "client": "d2k-own-profile",
                        "name": options.name,
                        "shape": "tcp",
                        "ip": ip.to_string(),
                        "port": options.port,
                        "path": options.path,
                        "protocol": if options.tls12 { "tls12" } else { "tls13" },
                        "body_bytes": 0,
                        "body_expected": 0,
                        "body_has_length": false,
                        "headers_inspected": true,
                        "cloudflare_challenge": false,
                        "location": "",
                        "wire_requested": options.wire_len.unwrap_or(0),
                        "mark": options.mark.unwrap_or(0),
                        "elapsed_ms": r2o_fetch_started.elapsed().as_millis(),
                        "local_port": 0,
                        "negotiated_tls": 0,
                        "http_status": 0,
                        "response_complete": false,
                        "level": if error.local_refusal || r2o_no_tcp { 0 } else { 1 },
                        "local_refusal": error.local_refusal,
                        "measured": !error.local_refusal,
                        "name_ok": -1,
                        "reason": if error.local_refusal { &error.message } else if r2o_no_tcp { "нет TCP" } else { &error.message },
                    })
                );
                return Ok(if error.local_refusal { 2 } else { 1 });
            }
            if error.local_refusal {
                eprintln!("r2o-fetch: НЕ ИЗМЕРЕНО: локальный отказ: {}", error.message);
                return Ok(2);
            }
            eprintln!("r2o-fetch: {}", error.message);
            return Ok(1);
        }
    };
    if r2o_json {
        let r2o_level = if result.cloudflare_challenge {
            4
        } else if result.status > 0 {
            3
        } else if result.tls.is_some() {
            2
        } else {
            1
        };
        println!(
            "{}",
            serde_json::json!({
                "schema": 2,
                "client": "d2k-own-profile",
                "name": options.name,
                "shape": "tcp",
                "ip": result.address.ip().to_string(),
                "port": options.port,
                "path": options.path,
                "protocol": if options.tls12 { "tls12" } else { "tls13" },
                "body_bytes": result.body_bytes,
                "body_expected": result.body_expected.unwrap_or(0),
                "body_has_length": result.body_has_length,
                "headers_inspected": true,
                "cloudflare_challenge": result.cloudflare_challenge,
                "location": result.location,
                "wire_requested": options.wire_len.unwrap_or(0),
                "mark": options.mark.unwrap_or(0),
                "elapsed_ms": result.elapsed.as_millis(),
                "local_port": result.local_port,
                "negotiated_tls": match result.tls { Some("1.3") => 0x0304, Some("1.2") => 0x0303, _ => 0 },
                "http_status": result.status,
                "response_complete": result.complete,
                "level": r2o_level,
                "local_refusal": false,
                "measured": true,
                "name_ok": if result.tls.is_some() { 1 } else { -1 },
                "reason": result.reason.as_deref().unwrap_or(""),
            })
        );
        return Ok(i32::from(!result.complete));
    }
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

fn r2o_print_dns_failed(name: &str) {
    println!(
        "{}",
        serde_json::json!({
            "schema": 2,
            "shape": "dns_failed",
            "measured": false,
            "name": name,
            "ip": null,
            "reason": "адрес не разрешился"
        })
    );
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
        if result.data.local_refusal {
            "НЕ ИЗМЕРЕНО: локальный отказ"
        } else if result.data.complete {
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

fn parse_mark(value: &str) -> Result<u32, String> {
    let (digits, radix) = if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (digits, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    u32::from_str_radix(digits, radix).map_err(|error| format!("неверная метка SO_MARK: {error}"))
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
         --json      вывести результат в машиночитаемой схеме JSON\n\
         Для TCP длина включает пять байт заголовка TLS-записи; для QUIC — только handshake-сообщение.\n\
         Снимок выполняется до запроса и заменяет значение --wire.\n\
         --ladder измеряет TCP/TLS даже при наличии --quic."
    );
}

#[cfg(test)]
mod tests {
    use super::parse_mark;

    #[test]
    fn mark_parser_matches_c_decimal_hex_and_octal_forms() {
        assert_eq!(parse_mark("45").unwrap(), 45);
        assert_eq!(parse_mark("0x2d").unwrap(), 45);
        assert_eq!(parse_mark("0X2D").unwrap(), 45);
        assert_eq!(parse_mark("055").unwrap(), 45);
        assert_eq!(parse_mark("0").unwrap(), 0);
    }

    #[test]
    fn mark_parser_rejects_invalid_and_negative_values() {
        assert!(parse_mark("08").is_err());
        assert!(parse_mark("-1").is_err());
        assert!(parse_mark("0x").is_err());
    }
}
