use r2k_core::control::{
    self, ADDR_PROBE_LEASE_MAX_MS, COMMAND_CLEAR, COMMAND_DEL_ADDR, COMMAND_DEL_ADDR_PROBE,
    COMMAND_DEL_VOICE_ADDR_PROBE, COMMAND_SET_ADDR, COMMAND_SET_ADDR_PROBE, COMMAND_SET_HTTPS,
    COMMAND_SET_NAME, COMMAND_SET_VOICE_ADDR, COMMAND_SET_VOICE_ADDR_PROBE, EVENT_APPLIED,
    EVENT_HELLO, EVENT_HTTP_PORTAL, EVENT_HTTP_RESPONSE, EVENT_R2O_JOURNAL_END,
    EVENT_R2O_JOURNAL_ENTRY, EVENT_R2O_QUIC_STALL, EVENT_R2O_QUIC_SUSPECT, EVENT_R2O_TCP_FIN_RETRY,
    EVENT_R2O_TCP_RST_AFTER_APP, EVENT_R2O_TCP_SILENT, EVENT_R2O_TCP_STALL, EVENT_R2O_VOICE_PROOF,
    EVENT_R2O_VOICE_SUSPECT, Frame, PROTOCOL_VERSION, RELEASE_ID, SHAPE_ECH_TCP, SHAPE_HTTP,
    SHAPE_LEGACY, SHAPE_MODERN, SHAPE_QUIC, SHAPE_VOICE, VOICE_ADDR_PROBE_LEASE_MAX_MS, decode_ack,
    decode_applied, decode_greeting, decode_hello, decode_http_portal, decode_http_response,
    decode_r2o_quic_stall, decode_r2o_quic_suspect, decode_r2o_tcp_fin_retry,
    decode_r2o_tcp_rst_after_app, decode_r2o_tcp_silence, decode_r2o_tcp_stall,
    decode_r2o_voice_proof, decode_r2o_voice_suspect, encode_delete_addr, encode_delete_addr_probe,
    encode_delete_name, encode_delete_name_probe, encode_delete_voice_addr_probe, encode_frame,
    encode_set_addr, encode_set_addr_probe, encode_set_bypass, encode_set_https, encode_set_name,
    encode_set_name_probe, encode_set_suffix, encode_set_voice_addr, encode_set_voice_addr_probe,
    read_frame,
};
use r2k_core::plan::{PROTO_HTTP, PROTO_VOICE, Plan};
use r2o_controller::catalog::{Catalog, DomainObservation, GroupKey};
use r2o_controller::classify::{Accept, ClassifyOptions, Trigger, Verdict, run as classify_run};
use r2o_controller::domain::normalize;
use r2o_controller::http_search::{
    candidate_key_from_plan_text, candidate_keys, candidate_program, candidate_text,
    measured_poison_keys, stable_id,
};
use r2o_controller::https_probe::{HttpsProbeWorker, target_from_portal};
use r2o_controller::plan_text::compile_text;
#[cfg(unix)]
use r2o_controller::r2o_late_rx::{R2oLateRxCache, R2oLateRxInput};
use r2o_controller::response::{ResponseOptions, ResponseVerdict, probe_response};
use std::error::Error;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::collections::{HashMap, HashSet, VecDeque};

#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};

#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use std::thread::JoinHandle;

#[cfg(unix)]
const MAX_PENDING_EVENTS: usize = 512;

#[cfg(unix)]
const HTTP_SEARCH_RETRY: std::time::Duration = std::time::Duration::from_secs(60 * 60);
const HTTP_SEARCH_INCONCLUSIVE: std::time::Duration = std::time::Duration::from_secs(5 * 60);
const HTTP_SEARCH_RECHECK: std::time::Duration = std::time::Duration::from_secs(10 * 60);
const HTTP_SEARCH_CHALLENGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);
#[cfg(unix)]
const HTTP_SEARCH_TASK_CAPACITY: usize = 20;
#[cfg(unix)]
const R2O_LATE_RX_TASK_CAPACITY: usize = 16;
#[cfg(unix)]
const R2O_LATE_RX_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10 * 60);
#[cfg(unix)]
const R2O_AUTOMATED_MEASUREMENT_SLOTS: usize = 5;
#[cfg(unix)]
const R2O_QUIC_TRIAL_QUEUE_CAPACITY: usize = 8;

#[cfg(unix)]
const CONTROL_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, Eq, PartialEq)]
struct ClassifyCliOptions {
    repeats: usize,
    allow_loopback: bool,
    mark: Option<u32>,
    save_plan_path: Option<PathBuf>,
    arm_socket_path: Option<PathBuf>,
    modern: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ServeCliOptions {
    discover: bool,
    mark: Option<u32>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("r2o-controller: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
        print_help();
        return Ok(());
    }
    if arguments.len() == 1 && (arguments[0] == "--version" || arguments[0] == "-V") {
        println!("r2o-controller release={RELEASE_ID} wire={PROTOCOL_VERSION}");
        return Ok(());
    }
    if arguments.len() == 1 && arguments[0] == "--http-candidates" {
        print_http_candidates();
        return Ok(());
    }
    if arguments.len() == 2 && arguments[0] == "--watch" {
        #[cfg(unix)]
        return watch(PathBuf::from(&arguments[1]));
        #[cfg(not(unix))]
        return Err("управляющий AF_UNIX сокет поддерживается только на Unix".into());
    }
    if arguments.len() == 2 && arguments[0] == "--journal" {
        #[cfg(unix)]
        return print_flow_journal(PathBuf::from(&arguments[1]));
        #[cfg(not(unix))]
        return Err("управляющий AF_UNIX сокет поддерживается только на Unix".into());
    }
    if arguments.len() == 6 && arguments[0] == "--set-name" {
        #[cfg(unix)]
        return set_name(
            PathBuf::from(&arguments[1]),
            arguments[2].to_str().ok_or("HOST должен быть в UTF-8")?,
            arguments[3].to_str().ok_or("FAMILY должен быть в UTF-8")?,
            arguments[4].to_str().ok_or("SHAPE должен быть в UTF-8")?,
            PathBuf::from(&arguments[5]),
        );
        #[cfg(not(unix))]
        return Err("управляющий AF_UNIX сокет поддерживается только на Unix".into());
    }
    if arguments.len() == 5 && arguments[0] == "--set-addr" {
        #[cfg(unix)]
        return set_addr(
            PathBuf::from(&arguments[1]),
            arguments[2].to_str().ok_or("IP должен быть в UTF-8")?,
            arguments[3].to_str().ok_or("SHAPE должен быть в UTF-8")?,
            PathBuf::from(&arguments[4]),
        );
        #[cfg(not(unix))]
        return Err("управляющий AF_UNIX сокет поддерживается только на Unix".into());
    }
    if arguments.len() == 4 && arguments[0] == "--del-addr" {
        #[cfg(unix)]
        return delete_addr(
            PathBuf::from(&arguments[1]),
            arguments[2].to_str().ok_or("IP должен быть в UTF-8")?,
            arguments[3].to_str().ok_or("SHAPE должен быть в UTF-8")?,
        );
        #[cfg(not(unix))]
        return Err("управляющий AF_UNIX сокет поддерживается только на Unix".into());
    }
    if arguments.len() == 3 && arguments[0] == "--apply-catalog" {
        #[cfg(unix)]
        return apply_catalog(PathBuf::from(&arguments[1]), PathBuf::from(&arguments[2]));
        #[cfg(not(unix))]
        return Err("управляющий AF_UNIX сокет поддерживается только на Unix".into());
    }
    if arguments.len() == 2 && arguments[0] == "--clear-catalog" {
        #[cfg(unix)]
        return clear_catalog(PathBuf::from(&arguments[1]));
        #[cfg(not(unix))]
        return Err("очистка каталога поддерживается только на Unix".into());
    }
    if (3..=6).contains(&arguments.len()) && arguments[0] == "--serve" {
        #[cfg(unix)]
        {
            let options = parse_serve_options(&arguments[3..])?;
            return serve_catalog(
                PathBuf::from(&arguments[1]),
                PathBuf::from(&arguments[2]),
                options.discover,
                options.mark,
            );
        }
        #[cfg(not(unix))]
        return Err("управляющий AF_UNIX сокет поддерживается только на Unix".into());
    }
    if arguments.len() == 2 && arguments[0] == "--check-catalog" {
        let path = PathBuf::from(&arguments[1]);
        let catalog = Catalog::load(&path)?;
        let enabled_bindings = catalog
            .boxes
            .iter()
            .flat_map(|box_record| &box_record.bindings)
            .filter(|binding| binding.enabled)
            .count();
        println!(
            "каталог исправен: {} коробок, {} активных привязок",
            catalog.boxes.len(),
            enabled_bindings
        );
        return Ok(());
    }
    if arguments.len() == 3 && arguments[0] == "--import-donor-catalog" {
        let source = PathBuf::from(&arguments[1]);
        let destination = PathBuf::from(&arguments[2]);
        let updated = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        if Catalog::import_donor_file(&source, &destination, updated)? {
            println!("каталог донора перенесён в {}", destination.display());
        } else {
            println!(
                "целевой каталог {} уже существует; он оставлен без изменений",
                destination.display()
            );
        }
        return Ok(());
    }
    if arguments.len() >= 4 && arguments[0] == "--classify" {
        let host = arguments[1].to_str().ok_or("HOST должен быть в UTF-8")?;
        let port = arguments[2]
            .to_str()
            .ok_or("PORT должен быть в UTF-8")?
            .parse::<u16>()?;
        let sni = arguments[3].to_str().ok_or("SNI должен быть в UTF-8")?;
        let ClassifyCliOptions {
            repeats,
            allow_loopback,
            mark,
            save_plan_path,
            arm_socket_path,
            modern,
        } = parse_classify_options(&arguments[4..])?;
        let target = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let trigger = if modern {
            Trigger::tls13(sni)
        } else {
            Trigger::tls(sni)
        }
        .map_err(|error| format!("TLS-зонд: {error}"))?;
        let control = Trigger {
            accept: Accept::TlsRecord,
            ..Trigger::tls("disk.rzd.ru").map_err(|error| format!("TLS-контроль: {error}"))?
        };
        let result = classify_run(
            &target,
            &trigger,
            ClassifyOptions {
                repeats,
                allow_loopback,
                mark,
                control: Some(control),
                ..ClassifyOptions::default()
            },
        );
        if let Some(path) = save_plan_path {
            let hit = result
                .hit
                .as_ref()
                .ok_or("классификатор не нашёл применимый poison-план")?;
            save_plan_file(&path, &hit.plan)?;
            println!("план R2OP сохранён: {}", path.display());
        }
        if let Some(socket_path) = arm_socket_path {
            let hit = result
                .hit
                .as_ref()
                .ok_or("классификатор не нашёл применимый poison-план")?;
            #[cfg(unix)]
            set_name_bytes(
                socket_path,
                sni,
                if host.contains(':') { 6 } else { 4 },
                if modern { SHAPE_MODERN } else { SHAPE_LEGACY },
                &hit.plan,
            )?;
            #[cfg(not(unix))]
            return Err(
                "установка в r2o-datapath через Unix-сокет поддерживается только на Unix".into(),
            );
        }
        println!(
            "цель: {}\nвердикт: {}\nпричина: {}\nзонды: {}\nвремя: {} мс",
            result.target,
            result.verdict.as_str(),
            result.reason,
            result.probes,
            result.duration.as_millis()
        );
        if let Some(boundary) = result.boundary {
            println!("граница: {boundary}");
        }
        if let Some(reassembles) = result.reassembles {
            println!("пересборка: {reassembles}");
        }
        if let Some(strategy) = result.strategy {
            println!("стратегия: {strategy}");
        }
        if let Some(response) = result.response {
            let verdict = match response.verdict {
                ResponseVerdict::NotApplicable => "неприменимо",
                ResponseVerdict::Clear => "чисто",
                ResponseVerdict::Blocked => "режут ответ",
                ResponseVerdict::Flaky => "нестабильно",
            };
            println!(
                "ответное направление: {verdict}; цель={} контроль={}; {}",
                response.target, response.control, response.reason
            );
        }
        for observation in result.trace {
            println!(
                "зонд: {} cuts={:?} пауза={} мс прошло={} не прошло={} {}",
                observation.probe,
                observation.cuts,
                observation.delay.as_millis(),
                observation.pass,
                observation.fail,
                observation.error.unwrap_or_default()
            );
        }
        if result.stopped {
            println!("замер прерван; результат неполный");
        }
        if result.verdict == Verdict::Opaque && !result.raw_usable {
            println!("сырые зонды недоступны: poison-поиск не выполнялся");
        }
        return Ok(());
    }
    if (4..=5).contains(&arguments.len()) && arguments[0] == "--probe-response" {
        let host = arguments[1].to_str().ok_or("HOST должен быть в UTF-8")?;
        let port = arguments[2]
            .to_str()
            .ok_or("PORT должен быть в UTF-8")?
            .parse::<u16>()?;
        let sni = arguments[3].to_str().ok_or("SNI должен быть в UTF-8")?;
        let repeats = if arguments.len() == 5 {
            arguments[4]
                .to_str()
                .ok_or("REPEATS должен быть в UTF-8")?
                .parse::<usize>()?
        } else {
            3
        };
        let result = probe_response(
            host,
            port,
            sni,
            ResponseOptions {
                repeats,
                ..ResponseOptions::default()
            },
        );
        let verdict = match result.verdict {
            ResponseVerdict::NotApplicable => "неприменимо",
            ResponseVerdict::Clear => "чисто",
            ResponseVerdict::Blocked => "режут ответ",
            ResponseVerdict::Flaky => "нестабильно",
        };
        println!(
            "вердикт: {verdict}\nцель: {}\nконтроль: {}\nпричина: {}",
            result.target, result.control, result.reason
        );
        return Ok(());
    }
    Err("используйте `r2o-controller --help`".into())
}

fn print_http_candidates() {
    for key in candidate_keys() {
        let id = stable_id(key);
        let plan = candidate_text(key, Some(&id)).expect("built-in HTTP candidate is valid");
        println!("кандидат: {key}");
        print!("{plan}");
    }
}

fn parse_classify_options(arguments: &[std::ffi::OsString]) -> Result<ClassifyCliOptions, String> {
    let mut repeats = None;
    let mut allow_loopback = false;
    let mut mark = None;
    let mut save_plan_path = None;
    let mut arm_socket_path = None;
    let mut modern = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--allow-loopback") if !allow_loopback => allow_loopback = true,
            Some("--mark") if mark.is_none() => {
                index += 1;
                let value = arguments
                    .get(index)
                    .and_then(|value| value.to_str())
                    .ok_or("--mark требует числовую метку")?;
                mark = Some(parse_mark(value)?);
            }
            Some("--save-plan") if save_plan_path.is_none() => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or("--save-plan требует путь к файлу")?;
                save_plan_path = Some(PathBuf::from(path));
            }
            Some("--arm") if arm_socket_path.is_none() => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or("--arm требует Unix-сокет r2o-datapath")?;
                arm_socket_path = Some(PathBuf::from(path));
            }
            Some("--modern") if !modern => modern = true,
            Some(option) if option.starts_with("--") => {
                return Err(format!("неизвестный параметр classify: {option}"));
            }
            Some(value) if repeats.is_none() => {
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| "REPEATS должен быть целым числом".to_owned())?;
                if parsed == 0 {
                    return Err("REPEATS должен быть больше нуля".into());
                }
                repeats = Some(parsed);
            }
            Some(_) => return Err("повторный или лишний аргумент classify".into()),
            None => return Err("параметр classify должен быть UTF-8".into()),
        }
        index += 1;
    }
    Ok(ClassifyCliOptions {
        repeats: repeats.unwrap_or(3),
        allow_loopback,
        mark,
        save_plan_path,
        arm_socket_path,
        modern,
    })
}

fn parse_serve_options(arguments: &[std::ffi::OsString]) -> Result<ServeCliOptions, String> {
    let mut options = ServeCliOptions {
        discover: false,
        mark: None,
    };
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--discover") if !options.discover => options.discover = true,
            Some("--mark") if options.mark.is_none() => {
                index += 1;
                let value = arguments
                    .get(index)
                    .and_then(|value| value.to_str())
                    .ok_or("--mark требует числовую метку")?;
                options.mark = Some(parse_mark(value)?);
            }
            Some(option) if option.starts_with("--") => {
                return Err(format!("неизвестный параметр serve: {option}"));
            }
            Some(_) => return Err("лишний аргумент serve".into()),
            None => return Err("параметр serve должен быть UTF-8".into()),
        }
        index += 1;
    }
    Ok(options)
}

fn parse_mark(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| "--mark должен быть числом от 0 до 4294967295".to_owned())
}

fn save_plan_file(path: &std::path::Path, plan: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(plan)
}

fn print_help() {
    println!(
        "r2o-controller — каталог и контроллер r2o\n\nИспользование:\n  r2o-controller --check-catalog ФАЙЛ\n  r2o-controller --clear-catalog ФАЙЛ\n  r2o-controller --classify HOST PORT SNI [REPEATS] [--modern] [--allow-loopback] [--mark N] [--save-plan ФАЙЛ] [--arm СОКЕТ]\n  r2o-controller --probe-response HOST PORT SNI [REPEATS]\n  r2o-controller --set-name СОКЕТ HOST FAMILY SHAPE ПЛАН.r2op\n  r2o-controller --set-addr СОКЕТ IP SHAPE ПЛАН.r2op\n  r2o-controller --del-addr СОКЕТ IP SHAPE\n  r2o-controller --apply-catalog СОКЕТ КАТАЛОГ.json\n  r2o-controller --serve СОКЕТ КАТАЛОГ.json [--discover] [--mark N]\n  r2o-controller --watch СОКЕТ\n  r2o-controller --journal СОКЕТ\n  r2o-controller --http-candidates\n  r2o-controller --version\n  r2o-controller --help\n\nFAMILY: ipv4 или ipv6. SHAPE: modern, legacy, ech, http, quic или voice; voice использует HOST @discord-voice. Адресная привязка принимает modern, legacy, ech, quic или voice. QUIC поддерживает планы quicsplit, quicdeny, четыре формы IP-фрагментации после контрольной пробы, удлинение UDP, нулевую 16-байтовую фальшивку и пару фальшивых quic5 с TTL 3 после подтверждённого рукопожатия и зависания; --modern использует сохранённый TLS 1.3 ClientHello; --discover ставит новые TCP SNI в ограниченную очередь классификации и ищет обход HTTP-портала, а для Discord voice запускает ограниченный IP Discovery поиск, требующий --mark; --mark задаёт SO_MARK управляющим зондам и raw-пакетам; --save-plan создаёт новый файл и не перезаписывает существующий; --arm передаёт найденный план работающему r2o-datapath для соответствующей формы."
    );
    println!("  r2o-controller --import-donor-catalog ФАЙЛ КАТАЛОГА");
}

fn normalize_plan_target(target: &str, shape: u8) -> Result<String, String> {
    if shape == SHAPE_VOICE {
        if target.eq_ignore_ascii_case("@discord-voice") {
            Ok("@discord-voice".to_owned())
        } else {
            Err("voice-план должен использовать HOST @discord-voice".to_owned())
        }
    } else {
        normalize(target).map_err(|error| error.to_string())
    }
}

fn shape_matches_plan(shape: u8, plan: &Plan) -> bool {
    match shape {
        SHAPE_HTTP => plan.transport == 6 && plan.proto == PROTO_HTTP,
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.transport == 6 && plan.proto == 1,
        SHAPE_QUIC => plan.r2k_is_quic_address_plan(),
        SHAPE_VOICE => plan.transport == 17 && plan.proto == PROTO_VOICE,
        _ => false,
    }
}

fn binding_shape_transport(shape: u8, transport: u8) -> bool {
    match shape {
        SHAPE_HTTP | SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => transport == 6,
        SHAPE_QUIC | SHAPE_VOICE => transport == 17,
        _ => false,
    }
}

#[cfg(unix)]
fn set_name(
    socket_path: PathBuf,
    host: &str,
    family: &str,
    shape: &str,
    plan_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let family = match family {
        "ipv4" | "4" => 4,
        "ipv6" | "6" => 6,
        _ => return Err("FAMILY принимает ipv4 или ipv6".into()),
    };
    let shape = match shape {
        "modern" => SHAPE_MODERN,
        "legacy" => SHAPE_LEGACY,
        "ech" => SHAPE_ECH_TCP,
        "http" => SHAPE_HTTP,
        "voice" => SHAPE_VOICE,
        "quic" => SHAPE_QUIC,
        _ => return Err("неизвестная SHAPE".into()),
    };
    let host = normalize_plan_target(host, shape).map_err(|error| format!("HOST: {error}"))?;
    let bytes = std::fs::read(&plan_path)?;
    set_name_bytes(socket_path, &host, family, shape, &bytes)
}

#[cfg(unix)]
fn set_addr(
    socket_path: PathBuf,
    address: &str,
    shape: &str,
    plan_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let address = address
        .parse::<std::net::IpAddr>()
        .map_err(|error| format!("IP: {error}"))?;
    let shape = match shape {
        "modern" => SHAPE_MODERN,
        "legacy" => SHAPE_LEGACY,
        "ech" => SHAPE_ECH_TCP,
        "quic" => SHAPE_QUIC,
        "voice" => SHAPE_VOICE,
        _ => return Err("неизвестная SHAPE адресной привязки".into()),
    };
    let bytes = std::fs::read(&plan_path)?;
    let plan = Plan::parse(&bytes)?;
    if !shape_matches_plan(shape, &plan) {
        return Err("SHAPE не соответствует transport/proto плана".into());
    }
    r2o_datapath::engine::validate_runtime_plan(&plan)
        .map_err(|error| format!("план не подходит runtime r2o-datapath: {error}"))?;
    let command =
        encode_set_addr(address, shape, &bytes).map_err(|error| format!("SET_ADDR: {error}"))?;
    let mut client = ControlClient::connect(socket_path)?;
    client.send_command(&command, COMMAND_SET_ADDR)?;
    println!("план установлен для адреса {address} ({shape})");
    Ok(())
}

#[cfg(unix)]
fn delete_addr(socket_path: PathBuf, address: &str, shape: &str) -> Result<(), Box<dyn Error>> {
    let address = address
        .parse::<std::net::IpAddr>()
        .map_err(|error| format!("IP: {error}"))?;
    let shape = match shape {
        "modern" => SHAPE_MODERN,
        "legacy" => SHAPE_LEGACY,
        "ech" => SHAPE_ECH_TCP,
        "quic" => SHAPE_QUIC,
        "voice" => SHAPE_VOICE,
        _ => return Err("неизвестная SHAPE адресной привязки".into()),
    };
    let command =
        encode_delete_addr(address, shape).map_err(|error| format!("DEL_ADDR: {error}"))?;
    let mut client = ControlClient::connect(socket_path)?;
    client.send_command(&command, COMMAND_DEL_ADDR)?;
    println!("план удалён для адреса {address} ({shape})");
    Ok(())
}

#[cfg(unix)]
fn set_name_bytes(
    socket_path: PathBuf,
    host: &str,
    family: u8,
    shape: u8,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let host = normalize_plan_target(host, shape).map_err(|error| format!("HOST: {error}"))?;
    let plan = Plan::parse(bytes)?;
    if !shape_matches_plan(shape, &plan) {
        return Err("SHAPE не соответствует transport/proto плана".into());
    }
    r2o_datapath::engine::validate_runtime_plan(&plan)
        .map_err(|error| format!("план не подходит runtime r2o-datapath: {error}"))?;
    let command = encode_set_name(&host, shape, family, bytes)
        .map_err(|error| format!("SET_NAME: {error}"))?;

    let mut client = ControlClient::connect(socket_path)?;
    client.send_set_name(&command)?;
    println!("план установлен: {host} ({shape})");
    Ok(())
}

#[cfg(unix)]
fn apply_catalog(socket_path: PathBuf, catalog_path: PathBuf) -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::load(&catalog_path)?;
    let compiled = catalog_commands(&catalog)?;
    let mut client = ControlClient::connect(socket_path)?;
    install_catalog(&mut client, &compiled.commands)?;
    println!(
        "каталог обработан: установлено {}, пропущено неподдерживаемых {skipped}",
        compiled.commands.len(),
        skipped = compiled.skipped
    );
    Ok(())
}

#[cfg(unix)]
fn serve_catalog(
    socket_path: PathBuf,
    catalog_path: PathBuf,
    discover: bool,
    mark: Option<u32>,
) -> Result<(), Box<dyn Error>> {
    use std::io::Write;

    let catalog = Catalog::load(&catalog_path)?;
    let compiled = catalog_commands(&catalog)?;
    let mut client = ControlClient::connect(socket_path)?;
    install_catalog(&mut client, &compiled.commands)?;
    println!(
        "каталог обработан: установлено {}, пропущено неподдерживаемых {}; {}",
        compiled.commands.len(),
        compiled.skipped,
        if discover {
            "наблюдение и автопоиск активны"
        } else {
            "наблюдение активно"
        }
    );
    std::io::stdout().flush()?;
    let https_cache_path = catalog_path.with_file_name("https-cache.json");
    client.watch_events(
        discover.then_some((catalog, catalog_path, mark)),
        Some(https_cache_path),
        mark,
    )
}

#[cfg(unix)]
struct CatalogLock(std::fs::File);

#[cfg(unix)]
impl CatalogLock {
    fn acquire(path: &Path) -> Result<Self, Box<dyn Error>> {
        use std::fs::OpenOptions;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let mut lock_name = path
            .file_name()
            .ok_or("в пути каталога отсутствует имя файла")?
            .to_os_string();
        lock_name.push(".lock");
        let lock_path = path.with_file_name(lock_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(lock_path)?;
        if !file.metadata()?.is_file() {
            return Err("файл блокировки каталога имеет неверный тип".into());
        }
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(Self(file));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }
}

#[cfg(unix)]
impl Drop for CatalogLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(unix)]
fn locked_catalog(
    path: &Path,
    fallback: &Catalog,
) -> Result<(CatalogLock, Catalog), Box<dyn Error>> {
    let lock = CatalogLock::acquire(path)?;
    let catalog = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            Catalog::load(path)?
        }
        Ok(_) => return Err("путь каталога указывает не на обычный файл".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fallback.clone(),
        Err(error) => return Err(error.into()),
    };
    Ok((lock, catalog))
}

#[cfg(unix)]
fn clear_catalog(path: PathBuf) -> Result<(), Box<dyn Error>> {
    let (_lock, _current) = locked_catalog(&path, &Catalog::default())?;
    let updated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    Catalog::default().save_atomic(&path, updated)?;
    println!("каталог очищен атомарно: {}", path.display());
    Ok(())
}

#[cfg(unix)]
struct CompiledCatalog {
    commands: Vec<(String, Vec<u8>)>,
    skipped: usize,
}

#[cfg(unix)]
const DOMAIN_DIRECT_CLEAR: u8 = 2;
#[cfg(unix)]
const DOMAIN_PLAN_FAILED: u8 = 4;

#[cfg(unix)]
fn catalog_commands(catalog: &Catalog) -> Result<CompiledCatalog, Box<dyn Error>> {
    let mut commands = Vec::new();
    let mut skipped = 0_usize;
    for box_record in &catalog.boxes {
        for binding in &box_record.bindings {
            if !binding.enabled {
                continue;
            }
            if binding.kind == "addr"
                && binding.transport == 17
                && binding.shape == SHAPE_QUIC
                && binding.verified_by == 6
                && binding.input == 1
            {
                let address = binding.target.parse::<std::net::IpAddr>().map_err(|_| {
                    format!("QUIC-привязка содержит неверный IP: {}", binding.target)
                })?;
                let family = if address.is_ipv4() { 4 } else { 6 };
                if binding.family != family {
                    return Err(format!(
                        "QUIC-привязка {} не совпадает с семейством адреса",
                        binding.target
                    )
                    .into());
                }
                let saved_plan = box_record
                    .plans
                    .iter()
                    .find(|plan| plan.id == binding.plan_id && plan.enabled)
                    .ok_or_else(|| {
                        format!(
                            "QUIC-привязка {} ссылается на отсутствующий план {}",
                            binding.target, binding.plan_id
                        )
                    })?;
                let bytes = compile_text(&saved_plan.text)
                    .map_err(|error| format!("QUIC-план {}: {error}", saved_plan.id))?;
                let plan = Plan::parse(&bytes)?;
                if saved_plan.proto != "quic" || !plan.r2k_is_quic_address_plan() {
                    return Err(format!(
                        "адресная QUIC-привязка {} не содержит проверенный план подбора",
                        binding.target
                    )
                    .into());
                }
                r2o_datapath::engine::validate_runtime_plan(&plan)
                    .map_err(|error| format!("QUIC-план {}: {error}", saved_plan.id))?;
                let command = encode_set_addr(address, SHAPE_QUIC, &bytes)
                    .map_err(|error| format!("SET_ADDR для QUIC {}: {error}", binding.target))?;
                commands.push((binding.target.clone(), command));
                continue;
            }
            if binding.kind == "addr"
                && binding.transport == 17
                && binding.family == 4
                && binding.shape == SHAPE_VOICE
                && binding.verified_by == 4
            {
                let server = binding.target.parse::<std::net::Ipv4Addr>().map_err(|_| {
                    format!("адресная голосовая привязка неверна: {}", binding.target)
                })?;
                let saved_plan = box_record
                    .plans
                    .iter()
                    .find(|plan| plan.id == binding.plan_id && plan.enabled)
                    .ok_or_else(|| {
                        format!(
                            "голосовая привязка {} ссылается на отсутствующий план {}",
                            binding.target, binding.plan_id
                        )
                    })?;
                let bytes = compile_text(&saved_plan.text)
                    .map_err(|error| format!("voice-план {}: {error}", saved_plan.id))?;
                let plan = Plan::parse(&bytes)?;
                if plan.transport != 17
                    || plan.proto != PROTO_VOICE
                    || r2o_controller::voice_discovery::r2o_voice_discovery_prefix_from_plan_text(
                        &saved_plan.text,
                    )
                    .is_none()
                {
                    return Err(format!(
                        "адресная голосовая привязка {} не содержит точный Discovery-план",
                        binding.target
                    )
                    .into());
                }
                let command = encode_set_voice_addr(server, &bytes)
                    .map_err(|error| format!("SET_VOICE_ADDR для {}: {error}", binding.target))?;
                commands.push((binding.target.clone(), command));
                continue;
            }
            if binding.kind != "name" {
                skipped += 1;
                continue;
            }
            let family = match binding.family {
                0 | 4 => 4,
                6 => 6,
                _ => {
                    skipped += 1;
                    continue;
                }
            };
            let shape = binding.shape;
            if !binding_shape_transport(shape, binding.transport) {
                skipped += 1;
                continue;
            }
            let host = normalize_plan_target(&binding.target, shape)
                .map_err(|error| format!("привязка {}: HOST: {error}", binding.target))?;
            let saved_plan = box_record
                .plans
                .iter()
                .find(|plan| plan.id == binding.plan_id && plan.enabled)
                .ok_or_else(|| {
                    format!(
                        "привязка {} ссылается на отсутствующий или отключённый план {}",
                        binding.target, binding.plan_id
                    )
                })?;
            let bytes = compile_text(&saved_plan.text)
                .map_err(|error| format!("план {}: {error}", saved_plan.id))?;
            let plan = Plan::parse(&bytes)?;
            if !shape_matches_plan(shape, &plan) {
                return Err(format!(
                    "форма {} привязки {} не соответствует транспорту или протоколу плана",
                    shape, binding.target
                )
                .into());
            }
            let command = encode_set_name(&host, shape, family, &bytes)
                .map_err(|error| format!("SET_NAME для {}: {error}", binding.target))?;
            commands.push((binding.target.clone(), command));
        }
    }
    if let Some(domain_state) = &catalog.domain_state {
        let mut plans_by_wire_key: HashMap<(String, u8, u8, u8), HashSet<String>> = HashMap::new();
        for group in &domain_state.groups {
            plans_by_wire_key
                .entry((
                    group.suffix.clone(),
                    group.key.transport,
                    group.key.family,
                    group.key.shape,
                ))
                .or_default()
                .insert(group.plan_id.clone());
        }

        let mut active_groups = Vec::new();
        let mut seen_suffixes = HashSet::new();
        let mut suffix_commands = Vec::new();
        for group in &domain_state.groups {
            let wire_key = (
                group.suffix.clone(),
                group.key.transport,
                group.key.family,
                group.key.shape,
            );
            if plans_by_wire_key
                .get(&wire_key)
                .is_none_or(|plan_ids| plan_ids.len() != 1)
            {
                skipped += 1;
                continue;
            }
            let Some(saved_plan) = catalog
                .boxes
                .iter()
                .flat_map(|box_record| &box_record.plans)
                .find(|plan| plan.id == group.plan_id && plan.enabled)
            else {
                skipped += 1;
                continue;
            };
            let bytes = compile_text(&saved_plan.text)
                .map_err(|error| format!("план области {}: {error}", group.suffix))?;
            let plan = Plan::parse(&bytes)?;
            if !binding_shape_transport(group.key.shape, group.key.transport)
                || !shape_matches_plan(group.key.shape, &plan)
                || r2o_datapath::engine::validate_runtime_plan(&plan).is_err()
            {
                skipped += 1;
                continue;
            }
            active_groups.push(group);
            if !seen_suffixes.insert(wire_key) {
                continue;
            }
            let command =
                encode_set_suffix(&group.suffix, group.key.shape, group.key.family, &bytes)
                    .map_err(|error| format!("SET_SUFFIX для {}: {error}", group.suffix))?;
            suffix_commands.push((format!("суффикс {}", group.suffix), command));
        }

        let mut seen_bypasses = HashSet::new();
        let mut bypass_commands = Vec::new();
        for observation in &domain_state.observations {
            let direct_clear = observation.evidence & DOMAIN_DIRECT_CLEAR != 0;
            let failed_group_plan = observation.evidence & DOMAIN_PLAN_FAILED != 0
                && active_groups.iter().any(|group| {
                    group.key == observation.key
                        && group.plan_id == observation.plan_id
                        && domain_member(&observation.name, &group.suffix)
                })
                && !has_confirmed_exact_binding(catalog, observation);
            if !direct_clear && !failed_group_plan {
                continue;
            }
            let wire_key = (
                observation.name.clone(),
                observation.key.transport,
                observation.key.shape,
                observation.key.family,
            );
            if !seen_bypasses.insert(wire_key) {
                continue;
            }
            let command = encode_set_bypass(
                &observation.name,
                observation.key.transport,
                observation.key.shape,
                observation.key.family,
            )
            .map_err(|error| format!("SET_BYPASS для {}: {error}", observation.name))?;
            bypass_commands.push((format!("исключение {}", observation.name), command));
        }
        commands.extend(bypass_commands);
        commands.extend(suffix_commands);
    }
    Ok(CompiledCatalog { commands, skipped })
}

#[cfg(unix)]
fn has_confirmed_exact_binding(catalog: &Catalog, observation: &DomainObservation) -> bool {
    catalog.boxes.iter().any(|box_record| {
        box_record.bindings.iter().any(|binding| {
            binding.enabled
                && binding.level >= 3
                && binding.recheck_since.is_none()
                && binding.kind == "name"
                && normalize(&binding.target).is_ok_and(|name| name == observation.name)
                && (binding.transport == observation.key.transport
                    || binding.transport == 0 && observation.key.transport == 6)
                && (binding.family == observation.key.family
                    || binding.family == 0 && observation.key.family == 4)
                && group_shape_fits(binding.shape, observation.key.shape)
                && group_path(binding.transport, &binding.probe_path)
                    == group_path(observation.key.transport, &observation.key.probe_path)
                && binding.ech_origin == observation.key.ech_origin
        })
    })
}

#[cfg(unix)]
fn group_shape_fits(saved: u8, observed: u8) -> bool {
    saved == 0 || saved == observed || saved == SHAPE_MODERN && observed == SHAPE_ECH_TCP
}

#[cfg(unix)]
fn group_path(transport: u8, path: &str) -> &str {
    if transport == 17 || path.is_empty() {
        "/"
    } else {
        path
    }
}

#[cfg(unix)]
fn domain_member(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(unix)]
fn matching_domain_group<'a>(
    catalog: &'a Catalog,
    target: &r2o_controller::discovery::DiscoveryTarget,
) -> Option<&'a r2o_controller::catalog::DomainGroup> {
    let key = GroupKey {
        transport: 6,
        family: target.family,
        shape: target.shape,
        ..GroupKey::default()
    };
    let domain_state = catalog.domain_state.as_ref()?;
    let group = domain_state.match_domain(&target.host, &key)?;
    let groups = &domain_state.groups;
    if groups.iter().any(|other| {
        other.suffix == group.suffix
            && other.key.transport == group.key.transport
            && other.key.family == group.key.family
            && other.key.shape == group.key.shape
            && other.plan_id != group.plan_id
    }) {
        return None;
    }
    let saved_plan = catalog
        .boxes
        .iter()
        .flat_map(|box_record| &box_record.plans)
        .find(|plan| plan.id == group.plan_id && plan.enabled)?;
    let bytes = compile_text(&saved_plan.text).ok()?;
    let plan = Plan::parse(&bytes).ok()?;
    if !shape_matches_plan(group.key.shape, &plan)
        || r2o_datapath::engine::validate_runtime_plan(&plan).is_err()
    {
        return None;
    }
    Some(group)
}

#[cfg(unix)]
fn install_catalog(
    client: &mut ControlClient,
    commands: &[(String, Vec<u8>)],
) -> Result<(), Box<dyn Error>> {
    client.send_clear()?;
    for (installed, (host, command)) in commands.iter().enumerate() {
        let expected = command
            .get(4..6)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .ok_or("собранная команда каталога обрезана")?;
        if let Err(error) = client.send_command(command, expected) {
            return match client.send_clear() {
                Ok(()) => Err(format!(
                    "установка каталога остановлена после {installed} привязок; частичная таблица очищена; {host}: {error}"
                )
                .into()),
                Err(clear_error) => Err(format!(
                    "установка каталога остановлена после {installed} привязок; не удалось очистить частичную таблицу; {host}: {error}; очистка при откате завершилась ошибкой: {clear_error}"
                )
                .into()),
            };
        }
    }
    Ok(())
}

#[cfg(unix)]
fn saved_http_candidate_keys(
    catalog: &Catalog,
    target: &r2o_controller::discovery::DiscoveryTarget,
) -> Vec<String> {
    let mut saved = Vec::new();
    for box_record in &catalog.boxes {
        for binding in &box_record.bindings {
            let same_name = binding.target.eq_ignore_ascii_case(&target.host);
            let same_context = same_name
                && binding.family == target.family
                && binding.shape == SHAPE_HTTP
                && binding.transport == 6;
            if binding.kind != "name"
                || binding.shape != SHAPE_HTTP
                || binding.transport != 6
                || (!binding.enabled && !(same_context && binding.recheck_since.is_some()))
            {
                continue;
            }
            let Some(plan) = box_record.plans.iter().find(|plan| {
                plan.enabled
                    && plan.proto == "http"
                    && plan.id.eq_ignore_ascii_case(&binding.plan_id)
            }) else {
                continue;
            };
            let Some(key) = candidate_key_from_plan_text(&plan.text) else {
                continue;
            };
            saved.push((same_context, binding.confirmed, key));
        }
    }
    saved.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    let mut keys = Vec::new();
    for (_, _, key) in saved {
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

#[cfg(unix)]
#[derive(Clone, Debug, Default)]
struct HttpLiveFailures {
    programs: Vec<Vec<u8>>,
    evidence_lost: bool,
}

#[cfg(unix)]
fn measured_http_candidate_keys(catalog: &Catalog) -> Vec<String> {
    const MAX_MEASURED_CANDIDATES: usize = 8;

    let mut measured = Vec::new();
    for box_record in &catalog.boxes {
        for plan in &box_record.plans {
            if plan.proto != "tls" || !plan.enabled || plan.successes <= 0 {
                continue;
            }
            for key in measured_poison_keys(&plan.text) {
                measured.push((plan.successes, key));
            }
        }
    }
    measured.sort_by_key(|entry| std::cmp::Reverse(entry.0));

    let mut keys = Vec::new();
    for (_, key) in measured {
        if !keys.contains(&key) {
            keys.push(key);
            if keys.len() == MAX_MEASURED_CANDIDATES {
                break;
            }
        }
    }
    keys
}

#[cfg(unix)]
fn failed_http_programs(
    catalog: &Catalog,
    target: &r2o_controller::discovery::DiscoveryTarget,
) -> HttpLiveFailures {
    let mut failures = HttpLiveFailures::default();
    for box_record in &catalog.boxes {
        for binding in &box_record.bindings {
            if binding.kind != "name"
                || !binding.target.eq_ignore_ascii_case(&target.host)
                || binding.enabled
                || binding.recheck_since.is_none()
                || binding.transport != 6
                || binding.family != target.family
                || binding.shape != SHAPE_HTTP
                || binding.verified_by != 1
                || binding.input != 2
            {
                continue;
            }
            let Some(plan) = box_record
                .plans
                .iter()
                .find(|plan| plan.id.eq_ignore_ascii_case(&binding.plan_id))
            else {
                failures.evidence_lost = true;
                continue;
            };
            let Some(key) = candidate_key_from_plan_text(&plan.text) else {
                failures.evidence_lost = true;
                continue;
            };
            let Some(program) = candidate_program(&key) else {
                failures.evidence_lost = true;
                continue;
            };
            if !failures.programs.contains(&program) {
                failures.programs.push(program);
            }
        }
    }
    failures
}

#[cfg(unix)]
fn http_search_candidates(
    catalog: &Catalog,
    target: &r2o_controller::discovery::DiscoveryTarget,
) -> Vec<String> {
    let measured = measured_http_candidate_keys(catalog);
    let mut candidates = saved_http_candidate_keys(catalog, target);
    for key in candidate_keys() {
        if !measured.is_empty() && *key == "fake-seqshift" {
            continue;
        }
        if !candidates.iter().any(|saved| saved == key) {
            candidates.push((*key).to_owned());
        }
    }
    for key in measured {
        if !candidates.contains(&key) {
            candidates.push(key);
        }
    }
    candidates
}

#[cfg(unix)]
struct HttpSearchTask {
    target: r2o_controller::discovery::DiscoveryTarget,
    request_path: Vec<u8>,
    expected_baseline: r2o_controller::http_search::Answer,
    candidates: Vec<String>,
    live_failures: HttpLiveFailures,
    mark: Option<u32>,
}

#[cfg(unix)]
enum HttpSearchCommand {
    InstallProbe {
        host: String,
        family: u8,
        port: u16,
        command: Vec<u8>,
        trial_id: [u8; 16],
        reply: SyncSender<Result<r2k_core::control::Ack, String>>,
    },
    DeleteProbe {
        host: String,
        family: u8,
        port: u16,
        reply: SyncSender<Result<(), String>>,
    },
    CollectApplied {
        trial_id: [u8; 16],
        timeout: std::time::Duration,
        reply: SyncSender<Result<Vec<r2k_core::control::AppliedEvent>, String>>,
    },
    R2oInstallQuicProbe {
        command: Vec<u8>,
        delete: Vec<u8>,
        trial_id: [u8; 16],
        reply: SyncSender<Result<r2k_core::control::Ack, String>>,
    },
    R2oDeleteQuicProbe {
        command: Vec<u8>,
        reply: SyncSender<Result<(), String>>,
    },
    InstallCandidate {
        target: r2o_controller::discovery::DiscoveryTarget,
        key: String,
        reply: SyncSender<Result<(), String>>,
    },
}

#[cfg(unix)]
struct HttpSearchOutcome {
    target: r2o_controller::discovery::DiscoveryTarget,
    result: Result<(), String>,
    disposition: HttpSearchDisposition,
}

#[cfg(unix)]
struct R2oQuicDiscoveryTask {
    server: std::net::SocketAddr,
    snapshot: Vec<u8>,
    permit: r2o_controller::r2o_resource_limit::R2oMeasurementPermit,
}

#[cfg(unix)]
struct R2oQuicDiscoveryOutcome {
    server: std::net::SocketAddr,
    result: Result<Option<(String, String)>, String>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpSearchDisposition {
    Retry,
    Inconclusive,
    Recheck,
    Challenge,
}

#[cfg(unix)]
impl HttpSearchDisposition {
    fn cooldown(self) -> std::time::Duration {
        match self {
            Self::Retry => HTTP_SEARCH_RETRY,
            Self::Inconclusive => HTTP_SEARCH_INCONCLUSIVE,
            Self::Recheck => HTTP_SEARCH_RECHECK,
            Self::Challenge => HTTP_SEARCH_CHALLENGE,
        }
    }
}

#[cfg(unix)]
fn r2o_http_failed_disposition(
    r2o_skipped_conflicts: usize,
    r2o_any_complete_server_trial: bool,
) -> HttpSearchDisposition {
    if r2o_skipped_conflicts > 0 {
        HttpSearchDisposition::Retry
    } else if r2o_any_complete_server_trial {
        HttpSearchDisposition::Inconclusive
    } else {
        HttpSearchDisposition::Retry
    }
}

#[cfg(unix)]
fn r2o_http_live_cut_recheck(response_code: u8, live: bool) -> bool {
    response_code == 4 && live
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct HttpSearchWindow {
    started: std::time::Instant,
    cooldown: std::time::Duration,
    active: bool,
}

#[cfg(unix)]
impl HttpSearchWindow {
    fn active(now: std::time::Instant) -> Self {
        Self {
            started: now,
            cooldown: HTTP_SEARCH_INCONCLUSIVE,
            active: true,
        }
    }
}

#[cfg(unix)]
fn http_search_key(target: &r2o_controller::discovery::DiscoveryTarget) -> (String, u8, String) {
    (target.host.clone(), target.family, target.endpoint.clone())
}

#[cfg(unix)]
struct R2oLateRxOutcome {
    input: R2oLateRxInput,
    result: r2o_controller::fetch::R2oFetchVolumeRxResult,
}

#[cfg(unix)]
struct R2oLateRxWorker {
    jobs: Option<SyncSender<R2oLateRxInput>>,
    outcomes: Receiver<R2oLateRxOutcome>,
    cancel: Arc<AtomicBool>,
    cooldowns: HashMap<String, std::time::Instant>,
    thread: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl R2oLateRxWorker {
    fn new(measurement_gate: r2o_controller::r2o_resource_limit::R2oMeasurementGate) -> Self {
        let (jobs, job_receiver) =
            mpsc::sync_channel::<R2oLateRxInput>(R2O_LATE_RX_TASK_CAPACITY - 1);
        let (outcome_sender, outcomes) = mpsc::sync_channel(R2O_LATE_RX_TASK_CAPACITY);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_gate = measurement_gate.clone();
        let thread = std::thread::spawn(move || {
            while let Ok(input) = job_receiver.recv() {
                if worker_cancel.load(Ordering::Relaxed) {
                    break;
                }
                let result = {
                    let Some(_permit) = worker_gate.r2o_acquire(&worker_cancel) else {
                        break;
                    };
                    r2o_controller::fetch::r2o_fetch_measure_rx_volume(&input.options)
                };
                if outcome_sender
                    .send(R2oLateRxOutcome { input, result })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            jobs: Some(jobs),
            outcomes,
            cancel,
            cooldowns: HashMap::new(),
            thread: Some(thread),
        }
    }

    fn queue(&mut self, input: R2oLateRxInput, now: std::time::Instant) -> bool {
        self.cooldowns
            .retain(|_, started| now.saturating_duration_since(*started) < R2O_LATE_RX_COOLDOWN);
        let host = input.options.name.clone();
        if self.cooldowns.contains_key(&host) {
            return false;
        }
        let Some(jobs) = self.jobs.as_ref() else {
            return false;
        };
        if jobs.try_send(input).is_err() {
            return false;
        }
        if self.cooldowns.len() >= 128
            && let Some(oldest) = self
                .cooldowns
                .iter()
                .min_by_key(|(_, started)| *started)
                .map(|(host, _)| host.clone())
        {
            self.cooldowns.remove(&oldest);
        }
        self.cooldowns.insert(host, now);
        true
    }

    fn try_outcome(&self) -> Option<R2oLateRxOutcome> {
        self.outcomes.try_recv().ok()
    }
}

#[cfg(unix)]
impl Drop for R2oLateRxWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
struct HttpSearchWorker {
    jobs: Option<SyncSender<HttpSearchTask>>,
    commands: Option<Receiver<HttpSearchCommand>>,
    outcomes: Option<Receiver<HttpSearchOutcome>>,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl HttpSearchWorker {
    fn new(measurement_gate: r2o_controller::r2o_resource_limit::R2oMeasurementGate) -> Self {
        // Одна задача выполняется, остальные 19 остаются в очереди.
        let (job_sender, job_receiver) =
            mpsc::sync_channel::<HttpSearchTask>(HTTP_SEARCH_TASK_CAPACITY - 1);
        let (command_sender, commands) = mpsc::sync_channel::<HttpSearchCommand>(16);
        let (outcome_sender, outcomes) = mpsc::sync_channel::<HttpSearchOutcome>(16);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_gate = measurement_gate.clone();
        let thread = std::thread::spawn(move || {
            while let Ok(task) = job_receiver.recv() {
                if worker_cancel.load(Ordering::Relaxed) {
                    break;
                }
                let target = task.target.clone();
                let (result, disposition) = {
                    let Some(_permit) = worker_gate.r2o_acquire(&worker_cancel) else {
                        break;
                    };
                    match run_http_search_task(task, &command_sender, &worker_cancel) {
                        Ok(disposition) => (Ok(()), disposition),
                        Err(error) => (Err(error), HttpSearchDisposition::Inconclusive),
                    }
                };
                if outcome_sender
                    .send(HttpSearchOutcome {
                        target,
                        result,
                        disposition,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            jobs: Some(job_sender),
            commands: Some(commands),
            outcomes: Some(outcomes),
            cancel,
            thread: Some(thread),
        }
    }

    fn queue(&self, task: HttpSearchTask) -> bool {
        let Some(jobs) = self.jobs.as_ref() else {
            return false;
        };
        matches!(jobs.try_send(task), Ok(()))
    }

    fn try_command(&self) -> Option<HttpSearchCommand> {
        self.commands.as_ref()?.try_recv().ok()
    }

    fn try_outcome(&self) -> Option<HttpSearchOutcome> {
        self.outcomes.as_ref()?.try_recv().ok()
    }
}

#[cfg(unix)]
impl Drop for HttpSearchWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs.take();
        self.commands.take();
        self.outcomes.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
const R2O_QUIC_DISCOVERY_WORKER_COUNT: usize = 2;

#[cfg(unix)]
type R2oQuicDiscoveryRunner = dyn Fn(
        R2oQuicDiscoveryTask,
        SyncSender<HttpSearchCommand>,
        Arc<AtomicBool>,
    ) -> Result<Option<(String, String)>, String>
    + Send
    + Sync;

#[cfg(unix)]
struct R2oQuicDiscoveryWorker {
    jobs: Option<SyncSender<R2oQuicDiscoveryTask>>,
    commands: Option<Receiver<HttpSearchCommand>>,
    outcomes: Receiver<R2oQuicDiscoveryOutcome>,
    cancel: Arc<AtomicBool>,
    active: std::collections::HashSet<std::net::SocketAddr>,
    threads: Vec<JoinHandle<()>>,
}

#[cfg(unix)]
impl R2oQuicDiscoveryWorker {
    fn new() -> Self {
        Self::r2o_new_with_runner(Arc::new(|mut task, commands, cancel| {
            ControlClient::r2o_run_quic_discovery_trial(
                task.server,
                &task.snapshot,
                &commands,
                &cancel,
                &mut task.permit,
            )
            .map_err(|error| error.to_string())
        }))
    }

    fn r2o_new_with_runner(runner: Arc<R2oQuicDiscoveryRunner>) -> Self {
        let (jobs, job_receiver) =
            mpsc::sync_channel::<R2oQuicDiscoveryTask>(R2O_QUIC_DISCOVERY_WORKER_COUNT);
        let job_receiver = Arc::new(std::sync::Mutex::new(job_receiver));
        let (command_sender, commands) = mpsc::sync_channel::<HttpSearchCommand>(16);
        let (outcome_sender, outcomes) =
            mpsc::sync_channel::<R2oQuicDiscoveryOutcome>(R2O_QUIC_DISCOVERY_WORKER_COUNT);
        let cancel = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::with_capacity(R2O_QUIC_DISCOVERY_WORKER_COUNT);
        for _ in 0..R2O_QUIC_DISCOVERY_WORKER_COUNT {
            let worker_jobs = Arc::clone(&job_receiver);
            let worker_commands = command_sender.clone();
            let worker_outcomes = outcome_sender.clone();
            let worker_cancel = Arc::clone(&cancel);
            let worker_runner = Arc::clone(&runner);
            threads.push(std::thread::spawn(move || {
                loop {
                    let task = worker_jobs
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv();
                    let Ok(task) = task else {
                        break;
                    };
                    if worker_cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let server = task.server;
                    let result =
                        worker_runner(task, worker_commands.clone(), Arc::clone(&worker_cancel));
                    if worker_outcomes
                        .send(R2oQuicDiscoveryOutcome { server, result })
                        .is_err()
                    {
                        break;
                    }
                }
            }));
        }
        Self {
            jobs: Some(jobs),
            commands: Some(commands),
            outcomes,
            cancel,
            active: std::collections::HashSet::new(),
            threads,
        }
    }

    fn queue(&mut self, task: R2oQuicDiscoveryTask) -> bool {
        let server = task.server;
        if self.active.contains(&server) {
            return false;
        }
        let Some(jobs) = self.jobs.as_ref() else {
            return false;
        };
        if jobs.try_send(task).is_err() {
            return false;
        }
        self.active.insert(server);
        true
    }

    fn has_capacity(&self) -> bool {
        self.active.len() < R2O_QUIC_DISCOVERY_WORKER_COUNT
    }

    fn try_command(&self) -> Option<HttpSearchCommand> {
        self.commands.as_ref()?.try_recv().ok()
    }

    fn try_outcome(&mut self) -> Option<R2oQuicDiscoveryOutcome> {
        let outcome = self.outcomes.try_recv().ok()?;
        self.active.remove(&outcome.server);
        Some(outcome)
    }
}

#[cfg(unix)]
impl Drop for R2oQuicDiscoveryWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs.take();
        self.commands.take();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
fn watch(socket_path: PathBuf) -> Result<(), Box<dyn Error>> {
    ControlClient::connect(socket_path)?.watch_events(None, None, None)
}

#[cfg(unix)]
fn print_flow_journal(socket_path: PathBuf) -> Result<(), Box<dyn Error>> {
    let mut client = ControlClient::connect(socket_path)?;
    let deadline = std::time::Instant::now() + CONTROL_ACK_TIMEOUT;
    let mut received = 0_u32;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() || !wait_for_control_frame(&client.socket, remaining)? {
            return Err("датапат не завершил снимок журнала за 3 секунды".into());
        }
        let Some(frame) = read_optional_frame(&mut client.socket)? else {
            return Err("датапат закрыл соединение до завершения снимка журнала".into());
        };
        if frame.kind == EVENT_R2O_JOURNAL_ENTRY {
            let entry = r2o_datapath::flow_journal::R2oFlowJournalEntry::from_event_frame(&frame)
                .map_err(|error| format!("событие журнала: {error}"))?;
            println!("{}", format_flow_journal_entry(&entry));
            received = received.saturating_add(1);
        } else if frame.kind == EVENT_R2O_JOURNAL_END {
            let summary =
                r2o_datapath::flow_journal::R2oFlowJournalSummary::from_event_frame(&frame)
                    .map_err(|error| format!("завершение снимка журнала: {error}"))?;
            if received != summary.count {
                return Err(format!(
                    "снимок журнала неполон: получено {received} из {} записей",
                    summary.count
                )
                .into());
            }
            println!(
                "снимок журнала: {received} записей, всего {}, вытеснено {}",
                summary.added, summary.dropped
            );
            return Ok(());
        }
    }
}

#[cfg(unix)]
fn format_flow_journal_key(key: &[u8; r2k_core::control::KEY_LEN]) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let client_port = u16::from_be_bytes([key[33], key[34]]);
    let server_port = u16::from_be_bytes([key[35], key[36]]);
    if key[0] == 6 {
        let client = Ipv6Addr::from(<[u8; 16]>::try_from(&key[1..17]).unwrap());
        let server = Ipv6Addr::from(<[u8; 16]>::try_from(&key[17..33]).unwrap());
        format!("[{client}]:{client_port} → [{server}]:{server_port}")
    } else {
        let client = Ipv4Addr::from(<[u8; 4]>::try_from(&key[1..5]).unwrap());
        let server = Ipv4Addr::from(<[u8; 4]>::try_from(&key[17..21]).unwrap());
        format!("{client}:{client_port} → {server}:{server_port}")
    }
}

#[cfg(unix)]
fn format_flow_journal_entry(entry: &r2o_datapath::flow_journal::R2oFlowJournalEntry) -> String {
    let name = String::from_utf8_lossy(&entry.name[..usize::from(entry.name_len)]);
    let direction = match entry.client_is_low {
        Some(true) => "клиент ниже сервера",
        Some(false) => "клиент выше сервера",
        None => "направление неизвестно",
    };
    let binding = entry
        .binding
        .map_or_else(|| "нет".to_owned(), |value| format!("{value:?}"));
    format!(
        "[{} нс] {} {} имя={:?} код={} число={} TTL={}/{} TOS={} серверный_hello={} план={} форма={} направление={} длительность={}мс IP_ID={} mapped={}:{} план_ID={:02x?} попытка_ID={:02x?} исполнение={} привязка={}",
        entry.at_ns,
        entry.kind.russian_name(),
        format_flow_journal_key(&entry.key),
        name,
        entry.code,
        entry.num,
        entry.ttl,
        entry.reference_ttl,
        entry.tos,
        entry.server_hello,
        entry.planned,
        entry.client_shape,
        direction,
        entry.elapsed_ms,
        entry.ip_id,
        std::net::Ipv4Addr::from(entry.mapped_ip),
        entry.mapped_port,
        entry.plan_id,
        entry.trial_id,
        entry.execution_id,
        binding
    )
}

#[cfg(unix)]
struct DiscoveryOutcome {
    target: r2o_controller::discovery::DiscoveryTarget,
    plan_text: Option<String>,
    detail: String,
    queue_expired: bool,
}

#[cfg(unix)]
const R2O_DISCOVERY_QUEUE_CAPACITY: usize = 64;
#[cfg(unix)]
const R2O_DISCOVERY_TASK_LIFETIME: std::time::Duration = std::time::Duration::from_secs(10 * 60);

#[cfg(unix)]
#[derive(Default)]
struct R2oDiscoveryQueue {
    entries: Vec<R2oDiscoveryQueueEntry>,
    event_sequence: u64,
    #[cfg(test)]
    waiting_for_slot: bool,
}

#[cfg(unix)]
struct R2oDiscoveryQueueEntry {
    target: r2o_controller::discovery::DiscoveryTarget,
    queued_at: std::time::Instant,
    queued_event: u64,
    hot_event: u64,
}

#[cfg(unix)]
impl R2oDiscoveryQueue {
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn enqueue(
        &mut self,
        target: r2o_controller::discovery::DiscoveryTarget,
        queued_at: std::time::Instant,
    ) -> bool {
        if self.promote(&target) {
            return true;
        }
        if self.entries.len() >= R2O_DISCOVERY_QUEUE_CAPACITY {
            return false;
        }
        self.event_sequence = self.event_sequence.wrapping_add(1);
        self.entries.push(R2oDiscoveryQueueEntry {
            target,
            queued_at,
            queued_event: self.event_sequence,
            hot_event: 0,
        });
        true
    }

    fn r2o_expire(
        &mut self,
        now: std::time::Instant,
    ) -> Vec<r2o_controller::discovery::DiscoveryTarget> {
        let mut expired = Vec::new();
        self.entries.retain(|entry| {
            if now.saturating_duration_since(entry.queued_at) > R2O_DISCOVERY_TASK_LIFETIME {
                expired.push(entry.target.clone());
                false
            } else {
                true
            }
        });
        expired
    }

    fn promote(&mut self, target: &r2o_controller::discovery::DiscoveryTarget) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| &entry.target == target)
        else {
            return false;
        };
        self.event_sequence = self.event_sequence.wrapping_add(1);
        entry.hot_event = self.event_sequence;
        true
    }

    fn pop(
        &mut self,
        now: std::time::Instant,
    ) -> (
        Vec<r2o_controller::discovery::DiscoveryTarget>,
        Option<r2o_controller::discovery::DiscoveryTarget>,
    ) {
        let expired = self.r2o_expire(now);
        let selected = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| (std::cmp::Reverse(entry.hot_event), entry.queued_event))
            .map(|(index, _)| index);
        let Some(selected) = selected else {
            return (expired, None);
        };
        (expired, Some(self.entries.remove(selected).target))
    }
}

#[cfg(unix)]
struct R2oPendingQuicDiscovery {
    server: std::net::SocketAddr,
    snapshot: Vec<u8>,
    captured: std::time::Instant,
    permit: Option<r2o_controller::r2o_resource_limit::R2oMeasurementPermit>,
}

#[cfg(unix)]
fn r2o_enqueue_quic_discovery(
    pending: &mut VecDeque<R2oPendingQuicDiscovery>,
    server: std::net::SocketAddr,
    snapshot: Vec<u8>,
    captured: std::time::Instant,
    gate: &r2o_controller::r2o_resource_limit::R2oMeasurementGate,
) -> usize {
    pending.push_back(R2oPendingQuicDiscovery {
        server,
        snapshot,
        captured,
        permit: gate.r2o_try_acquire(),
    });
    pending.len()
}

#[cfg(unix)]
fn r2o_take_ready_quic_discovery(
    pending: &mut VecDeque<R2oPendingQuicDiscovery>,
    gate: &r2o_controller::r2o_resource_limit::R2oMeasurementGate,
) -> Option<(
    R2oPendingQuicDiscovery,
    r2o_controller::r2o_resource_limit::R2oMeasurementPermit,
)> {
    let permit = pending
        .front_mut()?
        .permit
        .take()
        .or_else(|| gate.r2o_try_acquire())?;
    let entry = pending.pop_front()?;
    Some((entry, permit))
}

#[cfg(unix)]
struct DiscoveryWorker {
    jobs: Arc<(std::sync::Mutex<R2oDiscoveryQueue>, std::sync::Condvar)>,
    outcomes: Receiver<DiscoveryOutcome>,
    cancel: Arc<AtomicBool>,
    seen: HashSet<r2o_controller::discovery::DiscoveryTarget>,
    seen_order: VecDeque<r2o_controller::discovery::DiscoveryTarget>,
    failed_at: HashMap<r2o_controller::discovery::DiscoveryTarget, std::time::Instant>,
    active: HashSet<r2o_controller::discovery::DiscoveryTarget>,
    thread: Option<JoinHandle<()>>,
}

#[cfg(unix)]
fn r2o_discovery_failure_retry_due(failed_at: std::time::Instant, now: std::time::Instant) -> bool {
    now.saturating_duration_since(failed_at) >= std::time::Duration::from_secs(120)
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct R2oVoiceDiscoveryJob {
    target: r2o_controller::voice_discovery::R2oVoiceTarget,
    known_prefix: Option<[u8; 20]>,
}

#[cfg(unix)]
#[derive(Default)]
struct R2oVoiceLatestQueue {
    current: Option<R2oVoiceDiscoveryJob>,
    pending: Option<R2oVoiceDiscoveryJob>,
}

#[cfg(unix)]
impl R2oVoiceLatestQueue {
    fn offer(
        &mut self,
        job: R2oVoiceDiscoveryJob,
        can_start: bool,
    ) -> Option<R2oVoiceDiscoveryJob> {
        if self
            .current
            .as_ref()
            .is_some_and(|current| current.target == job.target)
            || self
                .pending
                .as_ref()
                .is_some_and(|pending| pending.target == job.target)
        {
            return None;
        }
        if self.current.is_some() || !can_start {
            self.pending = Some(job);
            return None;
        }
        self.pending = None;
        self.current = Some(job.clone());
        Some(job)
    }

    fn complete(&mut self, target: &r2o_controller::voice_discovery::R2oVoiceTarget) -> bool {
        if self
            .current
            .as_ref()
            .is_some_and(|current| &current.target == target)
        {
            self.current = None;
            true
        } else {
            false
        }
    }

    fn take_pending_if_idle(&mut self, can_start: bool) -> Option<R2oVoiceDiscoveryJob> {
        if !can_start || self.current.is_some() {
            return None;
        }
        let job = self.pending.take()?;
        self.current = Some(job.clone());
        Some(job)
    }
}

#[cfg(unix)]
struct R2oVoiceDiscoveryOutcome {
    target: r2o_controller::voice_discovery::R2oVoiceTarget,
    result: r2o_controller::voice_discovery::R2oDiscoverySearchResult,
}

#[cfg(unix)]
const R2O_VOICE_DISCOVERY_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(120);

#[cfg(unix)]
const R2O_VOICE_DISCOVERY_SEEN_LIMIT: usize = 128;

#[cfg(unix)]
#[derive(Default)]
struct R2oVoiceDiscoverySeen {
    r2o_targets: HashMap<r2o_controller::voice_discovery::R2oVoiceTarget, std::time::Instant>,
    r2o_order: VecDeque<(
        r2o_controller::voice_discovery::R2oVoiceTarget,
        std::time::Instant,
    )>,
}

#[cfg(unix)]
impl R2oVoiceDiscoverySeen {
    fn r2o_prune(&mut self, now: std::time::Instant) {
        while let Some((target, observed_at)) = self.r2o_order.front().copied() {
            if now.saturating_duration_since(observed_at) < R2O_VOICE_DISCOVERY_COOLDOWN {
                break;
            }
            self.r2o_order.pop_front();
            if self.r2o_targets.get(&target) == Some(&observed_at) {
                self.r2o_targets.remove(&target);
            }
        }
    }

    fn r2o_contains(
        &mut self,
        target: &r2o_controller::voice_discovery::R2oVoiceTarget,
        now: std::time::Instant,
    ) -> bool {
        self.r2o_prune(now);
        self.r2o_targets.contains_key(target)
    }

    fn r2o_insert(
        &mut self,
        target: r2o_controller::voice_discovery::R2oVoiceTarget,
        now: std::time::Instant,
    ) {
        self.r2o_prune(now);
        if self.r2o_targets.contains_key(&target) {
            return;
        }
        while self.r2o_targets.len() >= R2O_VOICE_DISCOVERY_SEEN_LIMIT {
            let Some((expired, observed_at)) = self.r2o_order.pop_front() else {
                break;
            };
            if self.r2o_targets.get(&expired) == Some(&observed_at) {
                self.r2o_targets.remove(&expired);
            }
        }
        self.r2o_targets.insert(target, now);
        self.r2o_order.push_back((target, now));
    }
}

#[cfg(unix)]
#[derive(Clone)]
struct R2oVoiceTrialContext {
    target: r2o_controller::voice_discovery::R2oVoiceTarget,
    trial_id: [u8; 16],
    plan_text: String,
    expires_at: std::time::Instant,
}

#[cfg(unix)]
struct R2oVoiceDiscoveryWorker {
    jobs: Option<SyncSender<R2oVoiceDiscoveryJob>>,
    outcomes: Receiver<R2oVoiceDiscoveryOutcome>,
    cancel: Arc<AtomicBool>,
    r2o_seen: R2oVoiceDiscoverySeen,
    schedule: R2oVoiceLatestQueue,
    thread: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl R2oVoiceDiscoveryWorker {
    fn new(
        mark: Option<u32>,
        measurement_gate: r2o_controller::r2o_resource_limit::R2oMeasurementGate,
    ) -> Self {
        let (r2o_job_sender, r2o_job_receiver) = mpsc::sync_channel::<R2oVoiceDiscoveryJob>(1);
        let (r2o_outcome_sender, r2o_outcomes) = mpsc::sync_channel(8);
        let r2o_cancel = Arc::new(AtomicBool::new(false));
        let r2o_worker_cancel = Arc::clone(&r2o_cancel);
        let r2o_worker_gate = measurement_gate.clone();
        let r2o_thread = std::thread::spawn(move || {
            while let Ok(r2o_job) = r2o_job_receiver.recv() {
                if r2o_worker_cancel.load(Ordering::Relaxed) {
                    break;
                }
                let r2o_result = {
                    let Some(_permit) = r2o_worker_gate.r2o_acquire(&r2o_worker_cancel) else {
                        break;
                    };
                    r2o_controller::voice_discovery::r2o_search_discovery_endpoint(
                        r2o_job.target.server,
                        r2o_job.known_prefix,
                        std::time::Duration::from_secs(3),
                        mark,
                    )
                };
                if r2o_outcome_sender
                    .send(R2oVoiceDiscoveryOutcome {
                        target: r2o_job.target,
                        result: r2o_result,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            jobs: Some(r2o_job_sender),
            outcomes: r2o_outcomes,
            cancel: r2o_cancel,
            r2o_seen: R2oVoiceDiscoverySeen::default(),
            schedule: R2oVoiceLatestQueue::default(),
            thread: Some(r2o_thread),
        }
    }

    fn queue(
        &mut self,
        target: r2o_controller::voice_discovery::R2oVoiceTarget,
        known_prefix: Option<[u8; 20]>,
        can_start: bool,
    ) -> bool {
        if self
            .r2o_seen
            .r2o_contains(&target, std::time::Instant::now())
            || self
                .schedule
                .current
                .as_ref()
                .is_some_and(|current| current.target == target)
            || self
                .schedule
                .pending
                .as_ref()
                .is_some_and(|pending| pending.target == target)
        {
            return false;
        }
        let r2o_job = R2oVoiceDiscoveryJob {
            target,
            known_prefix,
        };
        let Some(r2o_dispatch) = self.schedule.offer(r2o_job, can_start) else {
            return self
                .schedule
                .pending
                .as_ref()
                .is_some_and(|pending| pending.target == target);
        };
        self.r2o_dispatch_voice_job(r2o_dispatch)
    }

    fn r2o_dispatch_voice_job(&mut self, r2o_job: R2oVoiceDiscoveryJob) -> bool {
        match self
            .jobs
            .as_ref()
            .expect("живой поток поиска Discord Discovery")
            .try_send(r2o_job)
        {
            Ok(()) => true,
            Err(TrySendError::Full(r2o_job)) => {
                self.schedule.complete(&r2o_job.target);
                self.schedule.pending = Some(r2o_job);
                false
            }
            Err(TrySendError::Disconnected(r2o_job)) => {
                self.schedule.complete(&r2o_job.target);
                false
            }
        }
    }

    fn release_pending(&mut self, can_start: bool) -> bool {
        let Some(r2o_job) = self.schedule.take_pending_if_idle(can_start) else {
            return false;
        };
        if self
            .r2o_seen
            .r2o_contains(&r2o_job.target, std::time::Instant::now())
        {
            self.schedule.complete(&r2o_job.target);
            return false;
        }
        self.r2o_dispatch_voice_job(r2o_job)
    }

    fn try_outcome(&mut self) -> Option<R2oVoiceDiscoveryOutcome> {
        let r2o_outcome = self.outcomes.try_recv().ok()?;
        self.schedule.complete(&r2o_outcome.target);
        self.r2o_seen
            .r2o_insert(r2o_outcome.target, std::time::Instant::now());
        Some(r2o_outcome)
    }
}

#[cfg(unix)]
fn r2o_take_expired_voice_trials(
    trials: &mut HashMap<[u8; 16], R2oVoiceTrialContext>,
    now: std::time::Instant,
) -> Vec<R2oVoiceTrialContext> {
    let expired_ids: Vec<_> = trials
        .iter()
        .filter(|(_, trial)| trial.expires_at <= now)
        .map(|(trial_id, _)| *trial_id)
        .collect();
    expired_ids
        .into_iter()
        .filter_map(|trial_id| trials.remove(&trial_id))
        .collect()
}

#[cfg(unix)]
impl Drop for R2oVoiceDiscoveryWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs.take();
        if let Some(r2o_thread) = self.thread.take() {
            let _ = r2o_thread.join();
        }
    }
}

#[cfg(unix)]
fn r2o_known_voice_discovery_prefix(
    catalog: &Catalog,
    server: std::net::Ipv4Addr,
) -> Option<[u8; 20]> {
    let server = server.to_string();
    catalog.boxes.iter().find_map(|box_record| {
        box_record.bindings.iter().find_map(|binding| {
            if !binding.enabled
                || binding.confirmed == 0
                || binding.recheck_since.is_some()
                || binding.level < 3
                || binding.kind != "addr"
                || binding.target != server
                || binding.transport != 17
                || binding.family != 4
                || binding.shape != SHAPE_VOICE
                || binding.verified_by != 4
            {
                return None;
            }
            let r2o_plan = box_record
                .plans
                .iter()
                .find(|plan| plan.enabled && plan.id.eq_ignore_ascii_case(&binding.plan_id))?;
            r2o_controller::voice_discovery::r2o_voice_discovery_prefix_from_plan_text(
                &r2o_plan.text,
            )
        })
    })
}

#[cfg(unix)]
fn r2o_voice_proof_matches_target(
    proof: &r2k_core::control::R2oVoiceProofEvent,
    target: r2o_controller::voice_discovery::R2oVoiceTarget,
) -> bool {
    let key = &proof.key;
    if key[0] != 4 || key[37] != 17 {
        return false;
    }
    let low_ip = std::net::Ipv4Addr::new(key[1], key[2], key[3], key[4]);
    let high_ip = std::net::Ipv4Addr::new(key[17], key[18], key[19], key[20]);
    let low_port = u16::from_be_bytes([key[33], key[34]]);
    let high_port = u16::from_be_bytes([key[35], key[36]]);
    if low_port == 0 || high_port == 0 {
        return false;
    }
    (low_ip == *target.server.ip() && low_port == target.server.port() && high_ip == target.client)
        || (high_ip == *target.server.ip()
            && high_port == target.server.port()
            && low_ip == target.client)
}

fn flow_socket_addresses(
    key: &[u8; r2k_core::control::KEY_LEN],
    client_is_low: bool,
) -> (std::net::SocketAddr, std::net::SocketAddr) {
    let (low_ip, high_ip) = if key[0] == 4 {
        (
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(&key[1..5]).expect("проверен адрес IPv4"),
            )),
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(&key[17..21]).expect("проверен адрес IPv4"),
            )),
        )
    } else {
        (
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&key[1..17]).expect("проверен адрес IPv6"),
            )),
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&key[17..33]).expect("проверен адрес IPv6"),
            )),
        )
    };
    let low = std::net::SocketAddr::new(low_ip, u16::from_be_bytes([key[33], key[34]]));
    let high = std::net::SocketAddr::new(high_ip, u16::from_be_bytes([key[35], key[36]]));
    if client_is_low {
        (low, high)
    } else {
        (high, low)
    }
}

#[cfg(unix)]
fn applied_quic_trial_matches(
    event: &r2k_core::control::AppliedEvent,
    trial_id: [u8; 16],
    plan_id: [u8; 16],
    local: std::net::SocketAddr,
    server: std::net::SocketAddr,
) -> bool {
    let key = &event.key;
    if event.trial_id != trial_id
        || event.plan_id != plan_id
        || event.execution_id == 0
        || !event.binding.is_known()
        || event.binding.kind != 2
        || event.binding.family != if server.is_ipv4() { 4 } else { 6 }
        || event.binding.shape != SHAPE_QUIC
        || !event.binding.temporary
        || key[37] != 17
        || key[0] != if server.is_ipv4() { 4 } else { 6 }
    {
        return false;
    }
    let first_port = u16::from_be_bytes([key[33], key[34]]);
    let second_port = u16::from_be_bytes([key[35], key[36]]);
    let pair_matches = match key[0] {
        4 => {
            let first = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(&key[1..5]).expect("проверен ключ IPv4"),
                )),
                first_port,
            );
            let second = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(&key[17..21]).expect("проверен ключ IPv4"),
                )),
                second_port,
            );
            (first == local && second == server) || (first == server && second == local)
        }
        6 => {
            let first = std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&key[1..17]).expect("проверен ключ IPv6"),
                )),
                first_port,
            );
            let second = std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&key[17..33]).expect("проверен ключ IPv6"),
                )),
                second_port,
            );
            (first == local && second == server) || (first == server && second == local)
        }
        _ => false,
    };
    pair_matches
}

#[cfg(unix)]
impl DiscoveryWorker {
    fn new(
        mark: Option<u32>,
        measurement_gate: r2o_controller::r2o_resource_limit::R2oMeasurementGate,
    ) -> Self {
        let jobs = Arc::new((
            std::sync::Mutex::new(R2oDiscoveryQueue::default()),
            std::sync::Condvar::new(),
        ));
        let (outcome_sender, outcomes) = mpsc::sync_channel(8);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_gate = measurement_gate.clone();
        let worker_jobs = Arc::clone(&jobs);
        let thread = std::thread::spawn(move || {
            loop {
                let has_jobs = {
                    let (queue, wake) = &*worker_jobs;
                    let mut queue = queue
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    loop {
                        if worker_cancel.load(Ordering::Relaxed) {
                            break false;
                        }
                        if !queue.is_empty() {
                            #[cfg(test)]
                            {
                                queue.waiting_for_slot = true;
                            }
                            break true;
                        }
                        queue = wake
                            .wait(queue)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                };
                if !has_jobs {
                    break;
                }
                let outcome = {
                    let Some(_permit) = worker_gate.r2o_acquire(&worker_cancel) else {
                        break;
                    };
                    let (expired, target) = {
                        let (queue, _) = &*worker_jobs;
                        let mut queue = queue
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        #[cfg(test)]
                        {
                            queue.waiting_for_slot = false;
                        }
                        if worker_cancel.load(Ordering::Relaxed) {
                            (Vec::new(), None)
                        } else {
                            queue.pop(std::time::Instant::now())
                        }
                    };
                    for target in expired {
                        if outcome_sender
                            .send(DiscoveryOutcome {
                                target,
                                plan_text: None,
                                detail: "подозрение устарело в очереди".into(),
                                queue_expired: true,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    let Some(target) = target else {
                        continue;
                    };
                    classify_discovery_target(target, Arc::clone(&worker_cancel), mark)
                };
                if outcome_sender.send(outcome).is_err() {
                    break;
                }
            }
        });
        Self {
            jobs,
            outcomes,
            cancel,
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            failed_at: HashMap::new(),
            active: HashSet::new(),
            thread: Some(thread),
        }
    }

    fn queue(&mut self, target: r2o_controller::discovery::DiscoveryTarget) -> bool {
        if self.active.contains(&target) {
            let (queue, wake) = &*self.jobs;
            let promoted = queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .promote(&target);
            if promoted {
                wake.notify_one();
            }
            return promoted;
        }
        if self.seen.contains(&target) {
            let now = std::time::Instant::now();
            if !self
                .failed_at
                .get(&target)
                .is_some_and(|failed_at| r2o_discovery_failure_retry_due(*failed_at, now))
            {
                return false;
            }
            self.seen.remove(&target);
            self.seen_order.retain(|seen| seen != &target);
            self.failed_at.remove(&target);
        }
        if self.seen_order.len() == 256
            && let Some(expired) = self.seen_order.pop_front()
        {
            self.seen.remove(&expired);
            self.failed_at.remove(&expired);
        }
        self.seen.insert(target.clone());
        self.seen_order.push_back(target.clone());
        let (queue, wake) = &*self.jobs;
        let enqueued = queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .enqueue(target.clone(), std::time::Instant::now());
        if enqueued {
            self.active.insert(target);
            wake.notify_one();
            true
        } else {
            self.seen.remove(&target);
            self.seen_order.retain(|seen| seen != &target);
            self.failed_at.remove(&target);
            false
        }
    }

    fn queue_after_rx_cut(&mut self, target: r2o_controller::discovery::DiscoveryTarget) -> bool {
        if self.active.contains(&target) {
            return self.queue(target);
        }
        self.seen.remove(&target);
        self.seen_order.retain(|seen| seen != &target);
        self.failed_at.remove(&target);
        self.queue(target)
    }

    fn is_active(&self, target: &r2o_controller::discovery::DiscoveryTarget) -> bool {
        self.active.contains(target)
    }

    fn r2o_expire_queued(
        &mut self,
        now: std::time::Instant,
    ) -> Vec<r2o_controller::discovery::DiscoveryTarget> {
        let expired = self
            .jobs
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .r2o_expire(now);
        for target in &expired {
            self.active.remove(target);
            self.seen.remove(target);
            self.seen_order.retain(|seen| seen != target);
            self.failed_at.remove(target);
        }
        expired
    }

    fn try_outcome(&mut self) -> Option<DiscoveryOutcome> {
        let outcome = self.outcomes.try_recv().ok()?;
        if outcome.queue_expired {
            self.active.remove(&outcome.target);
            self.seen.remove(&outcome.target);
            self.seen_order.retain(|seen| seen != &outcome.target);
            self.failed_at.remove(&outcome.target);
        } else if outcome.plan_text.is_none() && self.seen.contains(&outcome.target) {
            self.active.remove(&outcome.target);
            self.failed_at
                .insert(outcome.target.clone(), std::time::Instant::now());
        } else {
            self.active.remove(&outcome.target);
            self.failed_at.remove(&outcome.target);
        }
        Some(outcome)
    }
}

#[cfg(unix)]
impl Drop for DiscoveryWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs.1.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
fn classify_discovery_target(
    target: r2o_controller::discovery::DiscoveryTarget,
    cancel: Arc<AtomicBool>,
    mark: Option<u32>,
) -> DiscoveryOutcome {
    let trigger = match target.shape {
        SHAPE_MODERN => Trigger::tls13(&target.host),
        SHAPE_LEGACY => Trigger::tls(&target.host),
        _ => Err("форма TLS не поддерживается"),
    };
    let Ok(trigger) = trigger else {
        return DiscoveryOutcome {
            target,
            plan_text: None,
            detail: "не удалось собрать профиль целевого TLS".into(),
            queue_expired: false,
        };
    };
    let control = match Trigger::tls("disk.rzd.ru") {
        Ok(control) => Trigger {
            accept: Accept::TlsRecord,
            ..control
        },
        Err(error) => {
            return DiscoveryOutcome {
                target,
                plan_text: None,
                detail: format!("не удалось собрать контрольный TLS: {error}"),
                queue_expired: false,
            };
        }
    };
    let result = classify_run(
        &target.endpoint,
        &trigger,
        ClassifyOptions {
            mark,
            control: Some(control),
            cancel: Some(cancel),
            ..ClassifyOptions::default()
        },
    );
    let plan_text = result.hit.map(|hit| hit.plan_text);
    DiscoveryOutcome {
        target,
        plan_text,
        detail: result.reason,
        queue_expired: false,
    }
}

#[cfg(unix)]
fn read_optional_frame(stream: &mut impl std::io::Read) -> std::io::Result<Option<Frame>> {
    use std::io::{Error, ErrorKind};

    let mut prefix = [0; 4];
    loop {
        match stream.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break,
            Ok(_) => unreachable!("single-byte read exceeded its buffer"),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    stream.read_exact(&mut prefix[1..])?;
    let length = u32::from_be_bytes(prefix) as usize;
    if !(2..=control::FRAME_MAX).contains(&length) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "длина управляющего кадра вне допустимого диапазона",
        ));
    }
    let mut content = vec![0; length];
    stream.read_exact(&mut content)?;
    Ok(Some(Frame {
        kind: u16::from_be_bytes([content[0], content[1]]),
        body: content[2..].to_vec(),
    }))
}

#[cfg(unix)]
fn wait_for_control_frame(
    socket: &std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;

    let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut descriptor = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result > 0 {
            return Ok(descriptor.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn r2o_read_control_batch(
    socket: &mut std::os::unix::net::UnixStream,
    first: Frame,
    limit: usize,
) -> std::io::Result<VecDeque<Frame>> {
    let limit = limit.clamp(1, 256);
    let mut frames = VecDeque::with_capacity(limit);
    frames.push_back(first);
    while frames.len() < limit && wait_for_control_frame(socket, std::time::Duration::ZERO)? {
        let Some(frame) = read_optional_frame(socket)? else {
            break;
        };
        frames.push_back(frame);
    }
    Ok(frames)
}

#[cfg(unix)]
struct ControlClient {
    socket: std::os::unix::net::UnixStream,
    pending_events: VecDeque<Frame>,
    pending_applied_events: VecDeque<r2k_core::control::AppliedEvent>,
    http_search_started: HashMap<(String, u8, String), HttpSearchWindow>,
    http_challenge_cooldowns: HashMap<(String, u8), std::time::Instant>,
}

#[cfg(unix)]
struct QuicDiscoveryTrialOutcome {
    plan_text: String,
    data: Option<r2o_controller::r2o_quic_http3::R2oQuicHttp3Result>,
    filter: r2o_controller::quic_replay::R2oQuicFilterResult,
    decision: r2o_controller::quic_replay::R2oQuicFilterDecision,
    applied: bool,
}

#[cfg(unix)]
impl ControlClient {
    fn connect(path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let mut socket = std::os::unix::net::UnixStream::connect(path)?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        socket.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
        let greeting = decode_greeting(&read_frame(&mut socket)?)
            .map_err(|error| format!("приветствие датапата: {error}"))?;
        if greeting.version != PROTOCOL_VERSION || greeting.release_id != RELEASE_ID {
            return Err(format!(
                "несовместимый r2o-datapath: wire={}, release={}, нужен wire={PROTOCOL_VERSION}, release={RELEASE_ID}",
                greeting.version, greeting.release_id
            )
            .into());
        }
        Ok(Self {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        })
    }

    fn send_set_name(&mut self, command: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_command(command, COMMAND_SET_NAME)
    }

    fn send_clear(&mut self) -> Result<(), Box<dyn Error>> {
        let command =
            encode_frame(COMMAND_CLEAR, &[]).map_err(|error| format!("CLEAR: {error}"))?;
        self.send_command(&command, COMMAND_CLEAR)
    }

    fn install_r2o_voice_trial(
        &mut self,
        target: r2o_controller::voice_discovery::R2oVoiceTarget,
        prefix: [u8; 20],
    ) -> Result<R2oVoiceTrialContext, Box<dyn Error>> {
        use std::io::Read;

        let plan_text = r2o_controller::voice_discovery::r2o_voice_arm_plan_text(&prefix);
        let plan_records = compile_text(&plan_text)?;
        let plan = Plan::parse(&plan_records)?;
        r2o_datapath::engine::validate_runtime_plan(&plan)
            .map_err(|error| format!("исполнитель r2o-datapath отверг voice-план: {error}"))?;
        let mut trial_id = [0; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut trial_id)?;
        if trial_id.iter().all(|byte| *byte == 0) {
            trial_id[15] = 1;
        }
        let command = encode_set_voice_addr_probe(
            target.client,
            target.server,
            VOICE_ADDR_PROBE_LEASE_MAX_MS,
            &plan_records,
            trial_id,
        )?;
        self.send_command(&command, COMMAND_SET_VOICE_ADDR_PROBE)?;
        Ok(R2oVoiceTrialContext {
            target,
            trial_id,
            plan_text,
            expires_at: std::time::Instant::now()
                + std::time::Duration::from_millis(u64::from(VOICE_ADDR_PROBE_LEASE_MAX_MS)),
        })
    }

    fn retire_r2o_voice_trial(
        &mut self,
        trial: &R2oVoiceTrialContext,
    ) -> Result<(), Box<dyn Error>> {
        let delete = encode_delete_voice_addr_probe(
            trial.target.client,
            trial.target.server,
            trial.trial_id,
        )?;
        self.send_command(&delete, COMMAND_DEL_VOICE_ADDR_PROBE)
    }

    fn confirm_r2o_voice_trial(
        &mut self,
        trial: R2oVoiceTrialContext,
        proof: &r2k_core::control::R2oVoiceProofEvent,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        if proof.trial_id != trial.trial_id || !r2o_voice_proof_matches_target(proof, trial.target)
        {
            return Err("Discovery-подтверждение не совпало с временным голосовым опытом".into());
        }
        let (_lock, previous) = locked_catalog(catalog_path, catalog)?;
        let mut updated = previous.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let plan_id = r2o_controller::voice_discovery::r2o_save_confirmed_voice_binding(
            &mut updated,
            *trial.target.server.ip(),
            &trial.plan_text,
            now,
        )
        .map_err(|error| format!("не удалось сохранить Discovery-привязку: {error}"))?;
        let plan_records = compile_text(&trial.plan_text)?;
        let command = encode_set_voice_addr(*trial.target.server.ip(), &plan_records)?;
        updated.save_atomic(catalog_path, now)?;
        if let Err(install_error) = self.send_command(&command, COMMAND_SET_VOICE_ADDR) {
            return match previous.save_atomic(catalog_path, now) {
                Ok(()) => Err(format!(
                    "датапат не подтвердил постоянный voice-план; каталог восстановлен: {install_error}"
                )
                .into()),
                Err(rollback_error) => Err(format!(
                    "датапат не подтвердил постоянный voice-план ({install_error}); каталог не удалось восстановить ({rollback_error})"
                )
                .into()),
            };
        }
        *catalog = updated;
        if let Err(error) = self.retire_r2o_voice_trial(&trial) {
            eprintln!("временный voice-план доживёт до конца аренды: {error}");
        }
        println!(
            "Discord Discovery подтверждён: адресный план {plan_id} сохранён для {}; передачу аудио отдельно не измеряли (ответ {}:{})",
            trial.target.server.ip(),
            proof.mapped_ip,
            proof.mapped_port
        );
        Ok(())
    }

    fn watch_events(
        &mut self,
        discovery: Option<(Catalog, PathBuf, Option<u32>)>,
        https_cache_path: Option<PathBuf>,
        https_probe_mark: Option<u32>,
    ) -> Result<(), Box<dyn Error>> {
        use std::io::Write;

        self.socket.set_read_timeout(None)?;
        let measurement_gate =
            r2o_controller::r2o_resource_limit::R2oMeasurementGate::r2o_with_start_gap(
                R2O_AUTOMATED_MEASUREMENT_SLOTS,
            );
        let mut voice_discovery = discovery
            .as_ref()
            .map(|(_, _, mark)| R2oVoiceDiscoveryWorker::new(*mark, measurement_gate.clone()));
        let mut discovery = discovery.map(|(catalog, path, mark)| {
            (
                DiscoveryWorker::new(mark, measurement_gate.clone()),
                catalog,
                path,
                mark,
            )
        });
        let http_search = discovery
            .as_ref()
            .map(|_| HttpSearchWorker::new(measurement_gate.clone()));
        let mut quic_discovery = discovery.as_ref().map(|_| R2oQuicDiscoveryWorker::new());
        let mut r2o_late_rx = discovery
            .as_ref()
            .map(|_| R2oLateRxWorker::new(measurement_gate.clone()));
        let mut r2o_late_rx_hellos = R2oLateRxCache::default();
        let mut https_probe = HttpsProbeWorker::new(https_probe_mark);
        let mut r2o_voice_trials = HashMap::<[u8; 16], R2oVoiceTrialContext>::new();
        let mut quic_snapshots =
            HashMap::<[u8; r2k_core::control::KEY_LEN], (Vec<u8>, std::time::Instant)>::new();
        let mut quic_trial_cooldowns = HashMap::<std::net::IpAddr, std::time::Instant>::new();
        let mut r2o_pending_quic_discovery = VecDeque::<R2oPendingQuicDiscovery>::new();
        if let Some(path) = &https_cache_path {
            let wall_now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            match HttpsProbeWorker::load_cache(path, wall_now) {
                Ok(entries) => {
                    let now = std::time::Instant::now();
                    for (host, state, ttl) in entries {
                        if !https_probe.restore_cached(&host, state, ttl, now) {
                            continue;
                        }
                        if state.should_redirect() {
                            let command = encode_set_https(&host, ttl)
                                .map_err(|error| format!("команда проверки HTTPS: {error}"))?;
                            self.send_command(&command, COMMAND_SET_HTTPS)?;
                        }
                        println!(
                            "кэш HTTPS восстановлен: {} — {}, ещё {} с",
                            host,
                            state.description(),
                            ttl
                        );
                    }
                }
                Err(error) => eprintln!(
                    "кэш HTTPS не прочитан из {}: {}; зонд продолжает с пустым кэшем",
                    path.display(),
                    error
                ),
            }
        }
        let mut r2o_scheduler_tick_pending = false;
        let mut r2o_quic_command_first = false;
        loop {
            if r2o_scheduler_tick_pending && self.pending_events.is_empty() {
                if wait_for_control_frame(&self.socket, std::time::Duration::ZERO)? {
                    let Some(frame) = read_optional_frame(&mut self.socket)? else {
                        return Ok(());
                    };
                    self.pending_events.extend(r2o_read_control_batch(
                        &mut self.socket,
                        frame,
                        256,
                    )?);
                } else {
                    measurement_gate.r2o_scheduler_tick();
                    r2o_scheduler_tick_pending = false;
                }
            }
            let r2o_now = std::time::Instant::now();
            if let Some((worker, _, _, _)) = &mut discovery {
                for target in worker.r2o_expire_queued(r2o_now) {
                    println!(
                        "подозрение {} устарело в очереди Discovery; сетевой замер не запускался",
                        target.host
                    );
                }
            }
            for r2o_trial in r2o_take_expired_voice_trials(&mut r2o_voice_trials, r2o_now) {
                if let Err(error) = self.retire_r2o_voice_trial(&r2o_trial) {
                    eprintln!(
                        "временный Discord-план истёк и удалится по аренде; досрочное снятие не удалось: {error}"
                    );
                }
            }
            if let Some(r2o_worker) = voice_discovery.as_mut() {
                r2o_worker.release_pending(r2o_voice_trials.is_empty());
            }
            let mut https_cache_changed = false;
            while let Some(result) = https_probe.try_result() {
                let command = encode_set_https(&result.host, result.ttl_seconds)
                    .map_err(|error| format!("команда проверки HTTPS: {error}"))?;
                self.send_command(&command, COMMAND_SET_HTTPS)?;
                println!(
                    "проверка HTTPS {}: {}",
                    result.host,
                    result.state.description()
                );
                https_cache_changed = true;
            }
            if https_cache_changed && let Some(path) = &https_cache_path {
                let wall_now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if let Err(error) =
                    https_probe.save_cache(path, wall_now, std::time::Instant::now())
                {
                    eprintln!("кэш HTTPS не сохранён: {error}");
                }
            }
            if let Some((worker, catalog, path, _)) = &mut discovery
                && let Some(outcome) = worker.try_outcome()
            {
                if outcome.queue_expired {
                    println!(
                        "подозрение {} устарело в очереди Discovery; сетевой замер не запускался",
                        outcome.target.host
                    );
                } else {
                    self.apply_discovery_outcome(outcome, catalog, path)?;
                }
                std::io::stdout().flush()?;
                continue;
            }
            if let Some(r2o_outcome) = voice_discovery
                .as_mut()
                .and_then(R2oVoiceDiscoveryWorker::try_outcome)
            {
                let r2o_target = r2o_outcome.target;
                if let r2o_controller::voice_discovery::R2oDiscoveryVerdict::Blocked {
                    prefix,
                    cutoff,
                } = r2o_outcome.result.verdict
                {
                    if r2o_voice_trials
                        .values()
                        .any(|r2o_trial| r2o_trial.target == r2o_target)
                    {
                        println!(
                            "поиск Discord Discovery {} -> {}:{}: временный план для этой цели уже ждёт доказательство",
                            r2o_target.client,
                            r2o_target.server.ip(),
                            r2o_target.server.port()
                        );
                    } else if discovery
                        .as_ref()
                        .is_some_and(|(_, _, _, mark)| mark.is_some_and(|mark| mark != 0))
                    {
                        let r2o_trial = self.install_r2o_voice_trial(r2o_target, prefix)?;
                        let r2o_trial_id = r2o_trial.trial_id;
                        r2o_voice_trials.insert(r2o_trial_id, r2o_trial);
                        println!(
                            "Discord Discovery повторяемо обрывался после {cutoff} ответов; временный адресный план поставлен для следующего потока {} -> {}:{}",
                            r2o_target.client,
                            r2o_target.server.ip(),
                            r2o_target.server.port()
                        );
                    } else {
                        println!(
                            "поиск Discord Discovery {} -> {}:{}: план-кандидат измерен, но временная установка требует включённого поиска с ненулевой меткой",
                            r2o_target.client,
                            r2o_target.server.ip(),
                            r2o_target.server.port()
                        );
                    }
                    std::io::stdout().flush()?;
                    continue;
                }
                let r2o_detail = match &r2o_outcome.result.verdict {
                    r2o_controller::voice_discovery::R2oDiscoveryVerdict::Continue => {
                        "прямой Discovery пока не показал повторяемого обрыва".to_owned()
                    }
                    r2o_controller::voice_discovery::R2oDiscoveryVerdict::Clear => {
                        "Discovery отвечает без кандидата на исправление".to_owned()
                    }
                    r2o_controller::voice_discovery::R2oDiscoveryVerdict::Flaky => {
                        "граница обрыва не повторилась".to_owned()
                    }
                    r2o_controller::voice_discovery::R2oDiscoveryVerdict::Unmeasured => r2o_outcome
                        .result
                        .error
                        .clone()
                        .unwrap_or_else(|| "зонд не дал измеримого результата".to_owned()),
                    r2o_controller::voice_discovery::R2oDiscoveryVerdict::Blocked { .. } => {
                        "кандидат прошёл Discovery-проверку".to_owned()
                    }
                };
                println!(
                    "поиск Discord Discovery {} -> {}:{}: {}",
                    r2o_target.client,
                    r2o_target.server.ip(),
                    r2o_target.server.port(),
                    r2o_detail
                );
                std::io::stdout().flush()?;
                continue;
            }
            if let Some(outcome) = http_search.as_ref().and_then(HttpSearchWorker::try_outcome) {
                self.complete_http_search(
                    &outcome.target,
                    outcome.disposition,
                    std::time::Instant::now(),
                );
                if let Err(error) = outcome.result {
                    eprintln!(
                        "HTTP {}: поиск завершился с ошибкой: {error}",
                        outcome.target.host
                    );
                }
                continue;
            }
            if let Some(outcome) = quic_discovery
                .as_mut()
                .and_then(R2oQuicDiscoveryWorker::try_outcome)
            {
                match outcome.result {
                    Ok(Some((plan_text, candidate_name))) => {
                        if let Some((_, catalog, path, _)) = &mut discovery {
                            self.r2o_install_quic_candidate(
                                outcome.server,
                                &plan_text,
                                &candidate_name,
                                catalog,
                                path,
                            )?;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => eprintln!("QUIC-испытание не завершено: {error}"),
                }
                std::io::stdout().flush()?;
                continue;
            }
            if let Some(outcome) = r2o_late_rx.as_ref().and_then(R2oLateRxWorker::try_outcome) {
                let host = outcome.input.options.name.clone();
                let discovery_target = outcome.input.discovery_target;
                if let Some(evidence) = outcome.result.evidence {
                    println!(
                        "парная RX-проверка {host}: обрыв подтверждён по identity/gzip, граница около {} КБ из {} КБ; событие не устанавливает план само по себе",
                        evidence.cut_kb, evidence.expected_kb
                    );
                    if let Some(target) = discovery_target
                        && let Some((worker, _, _, _)) = &mut discovery
                    {
                        if worker.is_active(&target) {
                            println!(
                                "классификация {} уже выполняется; повторную задачу не создаю",
                                target.host
                            );
                        } else if worker.queue_after_rx_cut(target.clone()) {
                            println!(
                                "подтверждённый RX-обрыв поставил классификацию {} в очередь",
                                target.host
                            );
                        } else {
                            println!(
                                "классификация {} не поставлена: очередь занята",
                                target.host
                            );
                        }
                    }
                } else {
                    println!(
                        "парная RX-проверка {host}: обрыв не подтверждён — {}",
                        outcome.result.reason
                    );
                }
                std::io::stdout().flush()?;
                continue;
            }
            let frame = if let Some(frame) = self.pending_events.pop_front() {
                frame
            } else {
                let command = if r2o_quic_command_first {
                    quic_discovery
                        .as_ref()
                        .and_then(R2oQuicDiscoveryWorker::try_command)
                        .or_else(|| http_search.as_ref().and_then(HttpSearchWorker::try_command))
                } else {
                    http_search
                        .as_ref()
                        .and_then(HttpSearchWorker::try_command)
                        .or_else(|| {
                            quic_discovery
                                .as_ref()
                                .and_then(R2oQuicDiscoveryWorker::try_command)
                        })
                };
                r2o_quic_command_first = !r2o_quic_command_first;
                if let Some(command) = command
                    && let Some((_, catalog, path, _)) = &mut discovery
                {
                    self.service_http_search_command(command, catalog, path)?;
                    continue;
                }
                if discovery.is_some()
                    && let Some((pending_server, pending_captured)) = r2o_pending_quic_discovery
                        .front()
                        .map(|pending| (pending.server, pending.captured))
                {
                    let now = std::time::Instant::now();
                    if now.saturating_duration_since(pending_captured)
                        > std::time::Duration::from_secs(60)
                    {
                        let expired = r2o_pending_quic_discovery
                            .pop_front()
                            .expect("проверенная очередь QUIC");
                        quic_trial_cooldowns.remove(&expired.server.ip());
                        println!(
                            "QUIC-проба {} пропущена: снимок Initial устарел в очереди",
                            pending_server
                        );
                        continue;
                    }
                    if let Some(worker) = quic_discovery.as_mut()
                        && worker.has_capacity()
                        && let Some((pending, permit)) = r2o_take_ready_quic_discovery(
                            &mut r2o_pending_quic_discovery,
                            &measurement_gate,
                        )
                    {
                        if !worker.queue(R2oQuicDiscoveryTask {
                            server: pending.server,
                            snapshot: pending.snapshot,
                            permit,
                        }) {
                            eprintln!(
                                "QUIC-испытание {} не попало в очередь worker",
                                pending.server
                            );
                        }
                        std::io::stdout().flush()?;
                        continue;
                    }
                }
                if !wait_for_control_frame(&self.socket, std::time::Duration::from_millis(100))? {
                    measurement_gate.r2o_scheduler_tick();
                    continue;
                }
                let Some(frame) = read_optional_frame(&mut self.socket)? else {
                    return Ok(());
                };
                self.pending_events
                    .extend(r2o_read_control_batch(&mut self.socket, frame, 256)?);
                r2o_scheduler_tick_pending = true;
                self.pending_events
                    .pop_front()
                    .expect("добавленное событие управляющего канала")
            };
            if frame.kind == EVENT_R2O_JOURNAL_ENTRY {
                let entry =
                    r2o_datapath::flow_journal::R2oFlowJournalEntry::from_event_frame(&frame)
                        .map_err(|error| format!("событие журнала: {error}"))?;
                println!("{}", format_flow_journal_entry(&entry));
                std::io::stdout().flush()?;
                continue;
            }
            if frame.kind == EVENT_R2O_JOURNAL_END {
                let summary =
                    r2o_datapath::flow_journal::R2oFlowJournalSummary::from_event_frame(&frame)
                        .map_err(|error| format!("завершение снимка журнала: {error}"))?;
                println!(
                    "снимок журнала: {} записей, всего {}, вытеснено {}",
                    summary.count, summary.added, summary.dropped
                );
                std::io::stdout().flush()?;
                continue;
            }
            if frame.kind == EVENT_HTTP_PORTAL {
                let portal = decode_http_portal(&frame)
                    .map_err(|error| format!("событие HTTP portal: {error}"))?;
                println!(
                    "наблюдение HTTP-портала: IPv{}, форма=ответ HTTP-портала, Host={:?}",
                    portal.key[0],
                    String::from_utf8_lossy(&portal.host),
                );
                std::io::stdout().flush()?;
                if let Some((host, address)) = target_from_portal(&portal) {
                    https_probe.submit(&host, address, std::time::Instant::now());
                }
                if !portal.answered
                    && let Some((_, catalog, _, mark)) = &mut discovery
                    && let Some(target) =
                        r2o_controller::discovery::DiscoveryTarget::from_http_portal(&portal)
                {
                    let queued = http_search.as_ref().is_some_and(|worker| {
                        self.enqueue_http_search(
                            worker,
                            &target,
                            b"/",
                            r2o_controller::http_search::Answer::Injected,
                            catalog,
                            *mark,
                            false,
                        )
                    });
                    if !queued {
                        println!(
                            "HTTP {}: цель уже проверялась или очередь занята",
                            target.host
                        );
                    }
                }
                continue;
            }
            if frame.kind == EVENT_R2O_VOICE_PROOF {
                let proof = decode_r2o_voice_proof(&frame)
                    .map_err(|error| format!("подтверждение Discord Discovery: {error}"))?;
                let Some(trial) = r2o_voice_trials.get(&proof.trial_id).cloned() else {
                    println!("Discovery-ответ не относится к активному временному voice-плану");
                    std::io::stdout().flush()?;
                    continue;
                };
                if trial.expires_at <= std::time::Instant::now() {
                    r2o_voice_trials.remove(&proof.trial_id);
                    if let Err(error) = self.retire_r2o_voice_trial(&trial) {
                        eprintln!(
                            "истёкший Discord-план удалится по аренде; досрочное снятие не удалось: {error}"
                        );
                    }
                    println!("Discovery-ответ пришёл после истечения временного voice-плана");
                    std::io::stdout().flush()?;
                    continue;
                }
                if !r2o_voice_proof_matches_target(&proof, trial.target) {
                    println!("Discovery-ответ пришёл по другому клиентскому или серверному адресу");
                    std::io::stdout().flush()?;
                    continue;
                }
                if let Some((_, catalog, path, _)) = &mut discovery {
                    r2o_voice_trials.remove(&proof.trial_id);
                    if let Err(error) =
                        self.confirm_r2o_voice_trial(trial.clone(), &proof, catalog, path)
                    {
                        r2o_voice_trials.insert(trial.trial_id, trial);
                        eprintln!("voice-план не подтверждён: {error}");
                    }
                } else {
                    println!("Discovery-ответ получен без активного каталога автопоиска");
                }
                std::io::stdout().flush()?;
                continue;
            }
            if frame.kind == EVENT_R2O_VOICE_SUSPECT {
                let event = decode_r2o_voice_suspect(&frame)
                    .map_err(|error| format!("событие голосового потока: {error}"))?;
                let Some(r2o_target) =
                    r2o_controller::voice_discovery::r2o_voice_target_from_event(&event)
                else {
                    println!("подозрение Discord voice содержит неполный адрес потока");
                    std::io::stdout().flush()?;
                    continue;
                };
                let r2o_queued = if let (Some(r2o_worker), Some((_, catalog, _, _))) =
                    (&mut voice_discovery, &discovery)
                {
                    let r2o_known_prefix =
                        r2o_known_voice_discovery_prefix(catalog, *r2o_target.server.ip());
                    r2o_worker.queue(r2o_target, r2o_known_prefix, r2o_voice_trials.is_empty())
                } else {
                    false
                };
                println!(
                    "обнаружен Discord voice {} -> {}:{}; {}",
                    r2o_target.client,
                    r2o_target.server.ip(),
                    r2o_target.server.port(),
                    if r2o_queued {
                        "зонд поставлен в ограниченную очередь"
                    } else if voice_discovery.is_none() {
                        "автопоиск отключён"
                    } else {
                        "цель уже проверялась или очередь занята"
                    }
                );
                std::io::stdout().flush()?;
                continue;
            }
            if matches!(frame.kind, EVENT_R2O_QUIC_SUSPECT | EVENT_R2O_QUIC_STALL) {
                let quic_stalled = frame.kind == EVENT_R2O_QUIC_STALL;
                let event = if quic_stalled {
                    decode_r2o_quic_stall(&frame)
                } else {
                    decode_r2o_quic_suspect(&frame)
                }
                .map_err(|error| format!("событие наблюдения QUIC: {error}"))?;
                let (client, server) = flow_socket_addresses(&event.key, event.client_is_low);
                if quic_stalled {
                    println!(
                        "наблюдение QUIC: после видимого ответа серверные пакеты не доходят, клиент продолжает передачу: {client} -> {server}; это не подтверждает блокировку"
                    );
                } else {
                    println!(
                        "наблюдение QUIC: после повтора Initial ответ не виден минимум 2 с: {client} -> {server}; это не подтверждает блокировку"
                    );
                }
                let Some((_, catalog, _, _)) = &mut discovery else {
                    std::io::stdout().flush()?;
                    continue;
                };
                if server.port() != 443 {
                    println!("QUIC-проба пропущена: временный план поддерживает только UDP/443");
                    std::io::stdout().flush()?;
                    continue;
                }
                if r2o_controller::discovery::has_usable_quic_address_binding(catalog, server.ip())
                {
                    println!("QUIC-проба пропущена: для адреса уже сохранён проверенный план");
                    std::io::stdout().flush()?;
                    continue;
                }
                let now = std::time::Instant::now();
                quic_trial_cooldowns.retain(|_, until| *until > now);
                if quic_trial_cooldowns
                    .get(&server.ip())
                    .is_some_and(|until| *until > now)
                {
                    println!("QUIC-проба пропущена: для адреса действует часовой интервал повтора");
                    std::io::stdout().flush()?;
                    continue;
                }
                let Some(captured) = quic_snapshots
                    .get(&event.key)
                    .map(|(_, captured)| *captured)
                else {
                    println!("QUIC-проба пропущена: для потока нет снимка Initial");
                    std::io::stdout().flush()?;
                    continue;
                };
                if now.saturating_duration_since(captured) > std::time::Duration::from_secs(60) {
                    quic_snapshots.remove(&event.key);
                    println!("QUIC-проба пропущена: снимок Initial устарел");
                    std::io::stdout().flush()?;
                    continue;
                }
                if r2o_pending_quic_discovery.len() >= R2O_QUIC_TRIAL_QUEUE_CAPACITY {
                    println!(
                        "QUIC-проба {} не поставлена: общая очередь замеров заполнена",
                        server
                    );
                    std::io::stdout().flush()?;
                    continue;
                }
                let Some((snapshot, captured)) = quic_snapshots.remove(&event.key) else {
                    println!("QUIC-проба пропущена: снимок Initial уже удалён");
                    std::io::stdout().flush()?;
                    continue;
                };
                quic_trial_cooldowns
                    .insert(server.ip(), now + std::time::Duration::from_secs(60 * 60));
                let queued = r2o_enqueue_quic_discovery(
                    &mut r2o_pending_quic_discovery,
                    server,
                    snapshot,
                    captured,
                    &measurement_gate,
                );
                println!(
                    "QUIC-проба {} поставлена в общую очередь замеров ({}/{})",
                    server, queued, R2O_QUIC_TRIAL_QUEUE_CAPACITY
                );
                std::io::stdout().flush()?;
                continue;
            }
            if frame.kind == EVENT_R2O_TCP_SILENT {
                let event = decode_r2o_tcp_silence(&frame)
                    .map_err(|error| format!("событие молчания TCP: {error}"))?;
                let (client, server) = flow_socket_addresses(&event.key, event.client_is_low);
                println!(
                    "наблюдение TCP: после ClientHello нет видимого ответа {client} -> {server} за {} мс; это не подтверждает блокировку",
                    event.elapsed_ms
                );
                std::io::stdout().flush()?;
                continue;
            }
            if frame.kind == EVENT_R2O_TCP_STALL {
                let event = decode_r2o_tcp_stall(&frame)
                    .map_err(|error| format!("событие зависания TCP: {error}"))?;
                let (client, server) = flow_socket_addresses(&event.key, event.client_is_low);
                println!(
                    "наблюдение TCP: поток {client} -> {server} замер на оценке {} пакетов; ответ не виден {} мс; это не подтверждает блокировку",
                    event.estimated_packets, event.elapsed_ms
                );
                std::io::stdout().flush()?;
                continue;
            }
            if frame.kind == EVENT_R2O_TCP_FIN_RETRY {
                let event = decode_r2o_tcp_fin_retry(&frame)
                    .map_err(|error| format!("событие повтора FIN TCP: {error}"))?;
                let (client, server) = flow_socket_addresses(&event.key, event.client_is_low);
                println!(
                    "наблюдение TCP: клиент {client} повторил FIN после видимого ответа {server}; это не подтверждает блокировку"
                );
                std::io::stdout().flush()?;
                continue;
            }
            if frame.kind == EVENT_R2O_TCP_RST_AFTER_APP {
                let event = decode_r2o_tcp_rst_after_app(&frame)
                    .map_err(|error| format!("событие позднего RST TCP: {error}"))?;
                let (client, server) = flow_socket_addresses(&event.key, event.client_is_low);
                println!(
                    "наблюдение TCP: сброс после TLS app-data в потоке {client} -> {server}; событие требует парной проверки объёма и само по себе не подтверждает блокировку"
                );
                if let Some(worker) = &mut r2o_late_rx {
                    let now = std::time::Instant::now();
                    let mark = discovery.as_ref().and_then(|(_, _, _, mark)| *mark);
                    match r2o_late_rx_hellos.take_for_rst(&event, mark, now) {
                        Some(input) => {
                            if worker.queue(input, now) {
                                println!(
                                    "поставлена в очередь парная identity/gzip RX-проверка для {} -> {}",
                                    client, server
                                );
                            } else {
                                println!(
                                    "парная RX-проверка для {client} -> {server} пропущена: очередь занята или действует десятиминутный предел для имени"
                                );
                            }
                        }
                        None => println!(
                            "парная RX-проверка для {client} -> {server} не запущена: нет свежего полного ClientHello с SNI"
                        ),
                    }
                }
                std::io::stdout().flush()?;
                continue;
            }
            if frame.kind == EVENT_HTTP_RESPONSE {
                let response = decode_http_response(&frame)
                    .map_err(|error| format!("событие HTTP_RESPONSE: {error}"))?;
                let outcome = match response.code {
                    1 => "полный ответ",
                    2 => "результат неизвестен",
                    3 => "обнаружен портал",
                    4 => "обрыв ответа",
                    _ => unreachable!("декодер отвергает неизвестный исход HTTP_RESPONSE"),
                };
                println!(
                    "наблюдение HTTP-ответа: IPv{}, Host={:?}, исход={}, статус={}, тело={} байт, путь={:?}, номер запроса={}, исполнение={}, привязка известна={}",
                    response.key[0],
                    String::from_utf8_lossy(&response.host),
                    outcome,
                    response.status,
                    response.body_bytes,
                    String::from_utf8_lossy(&response.path),
                    response.request_no,
                    response.execution_id,
                    response.binding.is_known(),
                );
                std::io::stdout().flush()?;
                if let Some((_, catalog, path, mark)) = &mut discovery {
                    let live = response.binding.is_known()
                        && !response.binding.temporary
                        && response.binding.kind == 1
                        && response.binding.family == response.key[0]
                        && response.binding.shape == SHAPE_HTTP
                        && response.execution_id != 0
                        && response.request_ms != 0
                        && response.trial_id.iter().all(|byte| *byte == 0);
                    let mut target = None;
                    let mut expected = None;
                    if live && response.code == 3 {
                        let candidate =
                            r2o_controller::discovery::DiscoveryTarget::from_http_response(
                                &response,
                            );
                        if let Some(candidate) = candidate
                            && self.revoke_http_binding(&response, &candidate, catalog, path)?
                        {
                            self.http_search_started
                                .remove(&http_search_key(&candidate));
                            target = Some(candidate);
                            expected = Some(r2o_controller::http_search::Answer::Injected);
                        }
                    } else if response.code == 4 {
                        target = r2o_controller::discovery::DiscoveryTarget::from_http_response(
                            &response,
                        );
                        expected = Some(r2o_controller::http_search::Answer::Cut);
                    }
                    if let (Some(target), Some(expected)) = (target, expected) {
                        let queued = http_search.as_ref().is_some_and(|worker| {
                            self.enqueue_http_search(
                                worker,
                                &target,
                                &response.path,
                                expected,
                                catalog,
                                *mark,
                                r2o_http_live_cut_recheck(response.code, live),
                            )
                        });
                        if !queued {
                            println!(
                                "HTTP {}: цель уже проверялась или очередь занята",
                                target.host
                            );
                        }
                    }
                }
                continue;
            }
            if frame.kind == EVENT_APPLIED {
                let applied =
                    decode_applied(&frame).map_err(|error| format!("событие APPLIED: {error}"))?;
                self.remember_applied_event(applied.clone());
                println!(
                    "исполнение подтверждено: plan={:02x?}, trial={:02x?}, execution={}, привязка известна={}",
                    applied.plan_id,
                    applied.trial_id,
                    applied.execution_id,
                    applied.binding.is_known(),
                );
                std::io::stdout().flush()?;
                continue;
            }
            if frame.kind != EVENT_HELLO {
                continue;
            }
            let hello =
                decode_hello(&frame).map_err(|error| format!("событие датапата: {error}"))?;
            if r2o_late_rx.is_some() {
                r2o_late_rx_hellos.capture(&hello, std::time::Instant::now());
            }
            if hello.key[37] == 17
                && hello.shape == Some(SHAPE_QUIC)
                && let Some(snapshot) = hello.quic_snapshot.as_ref()
            {
                let now = std::time::Instant::now();
                quic_snapshots.retain(|_, (_, captured)| {
                    now.duration_since(*captured) < std::time::Duration::from_secs(60)
                });
                if quic_snapshots.len() >= 128 && !quic_snapshots.contains_key(&hello.key) {
                    if let Some(oldest) = quic_snapshots
                        .iter()
                        .min_by_key(|(_, (_, captured))| *captured)
                        .map(|(key, _)| *key)
                    {
                        quic_snapshots.remove(&oldest);
                    }
                }
                quic_snapshots.insert(hello.key, (snapshot.clone(), now));
            }
            let family = hello.key[0];
            let protocol_name = match (hello.key[37], hello.shape) {
                (17, _) => "QUIC",
                (6, Some(SHAPE_HTTP)) => "HTTP",
                _ => "TLS",
            };
            let shape_name = hello.shape.map_or("неизвестна", |shape| match shape {
                SHAPE_MODERN => "TLS 1.3",
                SHAPE_LEGACY => "TLS 1.2",
                SHAPE_ECH_TCP => "ECH/TLS 1.3",
                SHAPE_QUIC => "QUIC",
                SHAPE_HTTP => "HTTP-запрос",
                _ => "неизвестна",
            });
            let name_kind = if hello.shape == Some(SHAPE_HTTP) {
                "Host"
            } else {
                "SNI"
            };
            if let Some(ref host) = hello.host {
                println!(
                    "наблюдение {protocol_name}: IPv{family}, форма={shape_name}, {name_kind}={:?}",
                    String::from_utf8_lossy(host),
                );
            } else {
                println!(
                    "наблюдение {protocol_name}: IPv{family}, форма={shape_name}, SNI отсутствует",
                );
            }
            if let Some((worker, catalog, _, _)) = &mut discovery
                && let Some(target) = r2o_controller::discovery::DiscoveryTarget::from_event(&hello)
            {
                if r2o_controller::discovery::has_usable_binding(catalog, &target) {
                    println!("план каталога уже покрывает {} ({shape_name})", target.host);
                } else if let Some(group) = matching_domain_group(catalog, &target) {
                    println!(
                        "область {} уже применяет план {} к {} ({shape_name}); новый поиск не запускаю",
                        group.suffix, group.plan_id, target.host
                    );
                } else if worker.queue(target.clone()) {
                    println!(
                        "поставлен в очередь классификации: {} {}",
                        target.endpoint, target.host
                    );
                } else {
                    println!(
                        "классификация уже в очереди или очередь заполнена: {}",
                        target.host
                    );
                }
            }
            std::io::stdout().flush()?;
        }
    }

    fn begin_http_search(
        &mut self,
        target: &r2o_controller::discovery::DiscoveryTarget,
        live_bound_cut: bool,
    ) -> bool {
        let now = std::time::Instant::now();
        self.http_challenge_cooldowns
            .retain(|_, until| *until > now);
        let challenge_key = (target.host.to_ascii_lowercase(), target.family);
        if self
            .http_challenge_cooldowns
            .get(&challenge_key)
            .is_some_and(|until| now < *until)
        {
            return false;
        }
        let key = http_search_key(target);
        if live_bound_cut
            && self
                .http_search_started
                .get(&key)
                .is_some_and(|window| !window.active)
        {
            self.http_search_started.remove(&key);
        }
        if self.http_search_started.get(&key).is_some_and(|window| {
            window.active || now.duration_since(window.started) < window.cooldown
        }) {
            return false;
        }
        self.http_search_started.retain(|_, window| {
            window.active || now.duration_since(window.started) < window.cooldown
        });
        self.http_search_started
            .insert(key, HttpSearchWindow::active(now));
        true
    }

    fn complete_http_search(
        &mut self,
        target: &r2o_controller::discovery::DiscoveryTarget,
        disposition: HttpSearchDisposition,
        now: std::time::Instant,
    ) {
        if let Some(window) = self.http_search_started.get_mut(&http_search_key(target)) {
            window.started = now;
            window.cooldown = disposition.cooldown();
            window.active = false;
        }
        if disposition != HttpSearchDisposition::Challenge {
            return;
        }
        self.http_challenge_cooldowns
            .retain(|_, until| *until > now);
        let key = (target.host.to_ascii_lowercase(), target.family);
        if self.http_challenge_cooldowns.len() >= 128
            && !self.http_challenge_cooldowns.contains_key(&key)
            && let Some(oldest) = self
                .http_challenge_cooldowns
                .iter()
                .min_by_key(|(_, until)| *until)
                .map(|(key, _)| key.clone())
        {
            self.http_challenge_cooldowns.remove(&oldest);
        }
        self.http_challenge_cooldowns
            .insert(key, now + HTTP_SEARCH_CHALLENGE);
    }

    fn enqueue_http_search(
        &mut self,
        worker: &HttpSearchWorker,
        target: &r2o_controller::discovery::DiscoveryTarget,
        request_path: &[u8],
        expected_baseline: r2o_controller::http_search::Answer,
        catalog: &Catalog,
        mark: Option<u32>,
        live_bound_cut: bool,
    ) -> bool {
        if !self.begin_http_search(target, live_bound_cut) {
            return false;
        }
        let candidates = http_search_candidates(catalog, target);
        let live_failures = failed_http_programs(catalog, target);
        if worker.queue(HttpSearchTask {
            target: target.clone(),
            request_path: request_path.to_vec(),
            expected_baseline,
            candidates,
            live_failures,
            mark,
        }) {
            true
        } else {
            self.http_search_started.remove(&http_search_key(target));
            false
        }
    }

    fn service_http_search_command(
        &mut self,
        command: HttpSearchCommand,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        match command {
            HttpSearchCommand::InstallProbe {
                host,
                family,
                port,
                command,
                trial_id,
                reply,
            } => {
                let ack = match self.exchange_command(&command, control::COMMAND_SET_NAME_PROBE) {
                    Ok(ack) => ack,
                    Err(error) => {
                        match self.delete_http_probe(&host, family, port) {
                            Ok(()) => {
                                let _ = reply.send(Err(format!(
                                    "установка HTTP-пробы не подтверждена; временная привязка удалена: {error}"
                                )));
                            }
                            Err(cleanup_error) => {
                                let message = format!(
                                    "установка HTTP-пробы не подтверждена ({error}); удалить временную привязку не удалось ({cleanup_error})"
                                );
                                let _ = reply.send(Err(message.clone()));
                                return Err(message.into());
                            }
                        }
                        return Ok(());
                    }
                };
                if ack.trial_id != Some(trial_id) {
                    match self.delete_http_probe(&host, family, port) {
                        Ok(()) => {
                            let _ = reply.send(Err(
                                "подтверждение HTTP-пробы содержит чужой trial ID; временная привязка удалена"
                                    .to_owned(),
                            ));
                        }
                        Err(cleanup_error) => {
                            let message = format!(
                                "подтверждение HTTP-пробы содержит чужой trial ID; удалить временную привязку не удалось: {cleanup_error}"
                            );
                            let _ = reply.send(Err(message.clone()));
                            return Err(message.into());
                        }
                    }
                    return Ok(());
                }
                let _ = reply.send(Ok(ack));
            }
            HttpSearchCommand::DeleteProbe {
                host,
                family,
                port,
                reply,
            } => {
                let result = self
                    .delete_http_probe(&host, family, port)
                    .map_err(|error| error.to_string());
                if let Err(error) = result {
                    let _ = reply.send(Err(error.clone()));
                    return Err(error.into());
                }
                let _ = reply.send(Ok(()));
            }
            HttpSearchCommand::CollectApplied {
                trial_id,
                timeout,
                reply,
            } => {
                let result = self
                    .collect_applied_events(trial_id, timeout)
                    .map_err(|error| error.to_string());
                if let Err(error) = &result {
                    let _ = reply.send(Err(error.clone()));
                    return Err(error.clone().into());
                }
                let _ = reply.send(result);
            }
            HttpSearchCommand::R2oInstallQuicProbe {
                command,
                delete,
                trial_id,
                reply,
            } => {
                let ack = match self.exchange_command(&command, COMMAND_SET_ADDR_PROBE) {
                    Ok(ack) => ack,
                    Err(error) => {
                        match self.send_command(&delete, COMMAND_DEL_ADDR_PROBE) {
                            Ok(()) => {
                                let _ = reply.send(Err(format!(
                                    "установка QUIC-пробы не подтверждена; временная привязка удалена: {error}"
                                )));
                            }
                            Err(cleanup_error) => {
                                let message = format!(
                                    "установка QUIC-пробы не подтверждена ({error}); удалить временную привязку не удалось ({cleanup_error})"
                                );
                                let _ = reply.send(Err(message.clone()));
                                return Err(message.into());
                            }
                        }
                        return Ok(());
                    }
                };
                if ack.trial_id != Some(trial_id) || !ack.ok {
                    match self.send_command(&delete, COMMAND_DEL_ADDR_PROBE) {
                        Ok(()) => {
                            let _ = reply.send(Err(
                                "датапат не подтвердил QUIC-пробу с ожидаемым trial ID; временная привязка удалена"
                                    .to_owned(),
                            ));
                        }
                        Err(cleanup_error) => {
                            let message = format!(
                                "датапат не подтвердил QUIC-пробу; удалить временную привязку не удалось: {cleanup_error}"
                            );
                            let _ = reply.send(Err(message.clone()));
                            return Err(message.into());
                        }
                    }
                    return Ok(());
                }
                let _ = reply.send(Ok(ack));
            }
            HttpSearchCommand::R2oDeleteQuicProbe { command, reply } => {
                let result = self
                    .send_command(&command, COMMAND_DEL_ADDR_PROBE)
                    .map_err(|error| error.to_string());
                if let Err(error) = result {
                    let _ = reply.send(Err(error.clone()));
                    return Err(error.into());
                }
                let _ = reply.send(Ok(()));
            }
            HttpSearchCommand::InstallCandidate { target, key, reply } => {
                let result = self
                    .install_http_candidate(&target, &key, catalog, catalog_path)
                    .map_err(|error| error.to_string());
                if let Err(error) = &result {
                    let _ = reply.send(Err(error.clone()));
                    return Err(error.clone().into());
                }
                let _ = reply.send(Ok(()));
            }
        }
        Ok(())
    }

    fn delete_http_probe(&mut self, host: &str, family: u8, port: u16) -> Result<(), String> {
        let command = encode_delete_name_probe(host, SHAPE_HTTP, family, port)
            .map_err(|error| error.to_owned())?;
        self.send_command(&command, control::COMMAND_DEL_NAME_PROBE)
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn collect_applied_events(
        &mut self,
        trial_id: [u8; 16],
        timeout: std::time::Duration,
    ) -> Result<Vec<r2k_core::control::AppliedEvent>, Box<dyn Error>> {
        let deadline = std::time::Instant::now() + timeout;
        let mut events = Vec::new();
        let pending = std::mem::take(&mut self.pending_applied_events);
        for event in pending {
            if event.trial_id == trial_id {
                events.push(event);
            } else {
                self.remember_applied_event(event);
            }
        }
        loop {
            let queued = self.pending_events.len();
            for _ in 0..queued {
                let Some(frame) = self.pending_events.pop_front() else {
                    break;
                };
                if frame.kind == EVENT_APPLIED {
                    if let Ok(event) = decode_applied(&frame) {
                        if event.trial_id == trial_id {
                            events.push(event);
                        } else {
                            self.remember_applied_event(event);
                        }
                    }
                } else {
                    self.pending_events.push_back(frame);
                }
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(events);
            }
            let wait = remaining.min(std::time::Duration::from_millis(100));
            if !wait_for_control_frame(&self.socket, wait)? {
                continue;
            }
            let Some(frame) = read_optional_frame(&mut self.socket)? else {
                return Err("соединение с датапатом закрыто во время проверки APPLIED".into());
            };
            if frame.kind == EVENT_APPLIED {
                if let Ok(event) = decode_applied(&frame) {
                    if event.trial_id == trial_id {
                        events.push(event);
                    } else {
                        self.remember_applied_event(event);
                    }
                }
            } else {
                self.queue_async_frame(frame)?;
            }
        }
    }

    fn remember_applied_event(&mut self, event: r2k_core::control::AppliedEvent) {
        const APPLIED_EVENT_LIMIT: usize = 256;
        if self.pending_applied_events.len() == APPLIED_EVENT_LIMIT {
            self.pending_applied_events.pop_front();
        }
        self.pending_applied_events.push_back(event);
    }

    fn run_quic_discovery_candidate(
        commands: &SyncSender<HttpSearchCommand>,
        cancel: &AtomicBool,
        server: std::net::SocketAddr,
        local: std::net::SocketAddr,
        probe: &mut r2o_controller::quic_replay::QuicReplayProbe,
        candidate: &r2o_controller::quic_replay::R2oQuicDiscoveryCandidate,
        sni: &str,
        runtime: &tokio::runtime::Runtime,
        request_timeout: std::time::Duration,
        roots: &rustls::RootCertStore,
        retry_strategy: bool,
        measurement_permit: &mut r2o_controller::r2o_resource_limit::R2oMeasurementPermit,
    ) -> Result<Option<QuicDiscoveryTrialOutcome>, Box<dyn Error>> {
        use r2o_controller::quic_replay::{
            R2oQuicCandidateKind, R2oQuicFilterDecision, R2oQuicFilterResult,
            r2o_quic_strategy_attempt_decision,
        };

        let trial_id = random_id()?;
        let plan_id = trial_id;
        let plan_id_text = plan_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let plan_text = format!(
            "r2o-plan 1 10\nid {plan_id_text}\nproto udp quic\n{}",
            candidate.directives
        );
        let plan_records = compile_text(&plan_text)?;
        let plan = Plan::parse(&plan_records)?;
        r2o_datapath::engine::validate_runtime_plan(&plan).map_err(|error| {
            format!(
                "исполнитель r2o-datapath отверг QUIC-кандидат «{}»: {error}",
                candidate.name
            )
        })?;
        let set = encode_set_addr_probe(
            local,
            server,
            ADDR_PROBE_LEASE_MAX_MS,
            &plan_records,
            trial_id,
        )?;
        let delete = encode_delete_addr_probe(local, server, trial_id)?;
        let ack = ask_http_controller(commands, |reply| HttpSearchCommand::R2oInstallQuicProbe {
            command: set.clone(),
            delete: delete.clone(),
            trial_id,
            reply,
        })?;
        if !ack.ok || ack.trial_id != Some(trial_id) {
            println!(
                "QUIC-кандидат «{}» не установлен: datapath не подтвердил его trial ID",
                candidate.name
            );
            return Ok(None);
        }

        let is_fragment_control = candidate.kind == R2oQuicCandidateKind::FragmentControl;
        let attempts = if retry_strategy { 2 } else { 1 };
        let trial_result = (|| {
            let mut applied = false;
            let mut outcome = QuicDiscoveryTrialOutcome {
                plan_text: plan_text.clone(),
                data: None,
                filter: R2oQuicFilterResult {
                    decision: R2oQuicFilterDecision::Unknown,
                    answered: 0,
                    measured: 0,
                },
                decision: R2oQuicFilterDecision::Unknown,
                applied: false,
            };
            for attempt in 0..attempts {
                if !measurement_permit.r2o_yield_if_contended_with_cancel(cancel) {
                    return Err("QUIC-испытание отменено во время ожидания слота".into());
                }
                let filter = probe.r2o_quic_probe_filter(request_timeout, attempt);
                let events = r2o_collect_controller_applied_events(
                    commands,
                    trial_id,
                    std::time::Duration::from_millis(400),
                )?;
                applied |= events.iter().any(|event| {
                    applied_quic_trial_matches(event, trial_id, plan_id, local, server)
                });
                outcome.filter = filter;
                outcome.applied = applied;
                if filter.decision != R2oQuicFilterDecision::Pass {
                    outcome.decision = r2o_quic_strategy_attempt_decision(
                        filter.decision,
                        None,
                        if retry_strategy { attempt } else { 1 },
                    );
                    if outcome.decision == R2oQuicFilterDecision::Retry && attempt + 1 < attempts {
                        continue;
                    }
                    return Ok::<_, Box<dyn Error>>(outcome);
                }
                if is_fragment_control {
                    outcome.decision = R2oQuicFilterDecision::Pass;
                    return Ok(outcome);
                }

                let data =
                    runtime.block_on(r2o_controller::r2o_quic_http3::r2o_quic_http3_measure(
                        probe.try_clone_socket()?,
                        server,
                        sni,
                        "/",
                        request_timeout,
                        roots.clone(),
                        r2o_controller::r2o_quic_http3::R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS,
                    ));
                let events = r2o_collect_controller_applied_events(
                    commands,
                    trial_id,
                    std::time::Duration::from_millis(400),
                )?;
                applied |= events.iter().any(|event| {
                    applied_quic_trial_matches(event, trial_id, plan_id, local, server)
                });
                let data_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&data);
                outcome.data = Some(data);
                outcome.applied = applied;
                outcome.decision = r2o_quic_strategy_attempt_decision(
                    filter.decision,
                    Some(data_verdict),
                    if retry_strategy { attempt } else { 1 },
                );
                if outcome.decision == R2oQuicFilterDecision::Retry && attempt + 1 < attempts {
                    continue;
                }
                return Ok(outcome);
            }
            Ok(outcome)
        })();

        ask_http_controller(commands, |reply| HttpSearchCommand::R2oDeleteQuicProbe {
            command: delete,
            reply,
        })?;
        match trial_result {
            Ok(outcome) => Ok(Some(outcome)),
            Err(error) => Err(error),
        }
    }

    fn r2o_run_quic_discovery_trial(
        server: std::net::SocketAddr,
        snapshot: &[u8],
        commands: &SyncSender<HttpSearchCommand>,
        cancel: &AtomicBool,
        measurement_permit: &mut r2o_controller::r2o_resource_limit::R2oMeasurementPermit,
    ) -> Result<Option<(String, String)>, Box<dyn Error>> {
        use r2o_controller::quic_replay::QuicReplayProbe;

        let mut probe = match QuicReplayProbe::prepare(server, snapshot, None) {
            Ok(probe) => probe,
            Err(error) => {
                eprintln!("QUIC replay не подготовлен: {error}");
                return Ok(None);
            }
        };
        let parsed_snapshot = match r2k_core::quic_snapshot::r2k_quic_snapshot_parse(snapshot) {
            Some(parsed) => parsed,
            None => {
                eprintln!("QUIC HTTP/3-проба пропущена: снимок Initial повреждён");
                return Ok(None);
            }
        };
        let server_name = match r2k_core::quic::r2k_quic_initial_sni_result_from_datagrams(
            parsed_snapshot.datagrams(),
        ) {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(server_name) => server_name,
                Err(_) => {
                    eprintln!("QUIC HTTP/3-проба пропущена: SNI не является UTF-8");
                    return Ok(None);
                }
            },
            Ok(None) => {
                let server_name = server.ip().to_string();
                eprintln!("в ClientHello нет SNI; QUIC проверяется по IP {server_name}");
                server_name
            }
            Err(error) => {
                eprintln!("QUIC HTTP/3-проба пропущена: ClientHello повреждён: {error}");
                return Ok(None);
            }
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Для снимка RTT ещё не измерен, поэтому используем нижнюю границу донора.
        #[cfg(test)]
        let request_timeout = std::time::Duration::from_millis(20);
        #[cfg(not(test))]
        let request_timeout = std::time::Duration::from_millis(u64::from(
            r2k_core::quic::r2k_quic_dynamic_wait_ms(0),
        ));
        let baseline = runtime.block_on(r2o_controller::r2o_quic_http3::r2o_quic_http3_get(
            probe.try_clone_socket()?,
            server,
            &server_name,
            "/",
            request_timeout,
            roots.clone(),
        ));
        let baseline_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(&baseline);
        if baseline_verdict == r2k_core::quic::R2kQuicDataVerdict::Pass {
            println!("исходный HTTP/3 GET уже проходит; QUIC-план не устанавливаю");
            return Ok(None);
        }

        let local = probe.local_endpoint();
        let split_applicable = parsed_snapshot
            .datagrams()
            .iter()
            .any(|datagram| r2k_core::quic::initial_split_crypto(datagram).is_ok());
        let mut selected_plan = None;
        let mut fragment_control_passed = false;
        let mut benign_asked = false;
        let mut ttl_three_answered_no = false;
        let mut clearance_decision = r2o_controller::quic_replay::R2oQuicFilterDecision::Unknown;
        let mut split_decision = r2o_controller::quic_replay::R2oQuicFilterDecision::Unknown;
        let mut strategy_candidates =
            r2o_controller::quic_replay::r2o_quic_discovery_candidates(&baseline, split_applicable);
        for candidate in strategy_candidates.drain(..) {
            if cancel.load(Ordering::Relaxed) {
                return Err("QUIC-испытание отменено".into());
            }
            let outcome = match Self::run_quic_discovery_candidate(
                commands,
                cancel,
                server,
                local,
                &mut probe,
                &candidate,
                &server_name,
                &runtime,
                request_timeout,
                &roots,
                true,
                measurement_permit,
            ) {
                Ok(Some(outcome)) => outcome,
                Ok(None) => continue,
                Err(error) => {
                    eprintln!(
                        "испытание QUIC-кандидата «{}» не завершено: {error}",
                        candidate.name
                    );
                    continue;
                }
            };
            let decision = if outcome.applied {
                outcome.decision
            } else {
                r2o_controller::quic_replay::R2oQuicFilterDecision::Unknown
            };
            match candidate.kind {
                r2o_controller::quic_replay::R2oQuicCandidateKind::TtlStrategy => {
                    ttl_three_answered_no =
                        decision == r2o_controller::quic_replay::R2oQuicFilterDecision::No;
                }
                r2o_controller::quic_replay::R2oQuicCandidateKind::Clearance => {
                    benign_asked = true;
                    clearance_decision = decision;
                }
                r2o_controller::quic_replay::R2oQuicCandidateKind::SplitCrypto => {
                    split_decision = decision;
                }
                _ => {}
            }
            if decision != r2o_controller::quic_replay::R2oQuicFilterDecision::Pass {
                println!(
                    "QUIC-кандидат «{}» не подтверждён: исход={decision:?}, ответов фильтра={}/{}, точный APPLIED={}; временный план удалён",
                    candidate.name,
                    outcome.filter.answered,
                    outcome.filter.measured,
                    outcome.applied,
                );
                continue;
            }
            let Some(data) = outcome.data.as_ref() else {
                println!("QUIC-кандидат «{}» не вернул замер HTTP/3", candidate.name);
                continue;
            };
            let data_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(data);
            if data.r2o_quic_stalled
                || !r2o_controller::quic_replay::r2o_quic_data_proof_confirmed(
                    data.handshake_confirmed,
                    outcome.applied,
                    data_verdict,
                )
            {
                println!(
                    "QUIC-кандидат «{}» не подтверждён: рукопожатие={}, HTTP={}, байт тела={}, зависание={}, HTTP/3={data_verdict:?}, точный APPLIED={}",
                    candidate.name,
                    data.handshake_confirmed,
                    data.status,
                    data.body_bytes,
                    data.r2o_quic_stalled,
                    outcome.applied,
                );
                continue;
            }
            selected_plan = Some((outcome.plan_text, candidate.name));
            break;
        }

        let fragment_questions_used = clearance_decision
            == r2o_controller::quic_replay::R2oQuicFilterDecision::No
            && (split_decision == r2o_controller::quic_replay::R2oQuicFilterDecision::No
                || !split_applicable);
        if selected_plan.is_none() && fragment_questions_used {
            for candidate in r2o_controller::quic_replay::r2o_quic_fragment_candidates() {
                if matches!(
                    candidate.kind,
                    r2o_controller::quic_replay::R2oQuicCandidateKind::FragmentShape(_)
                ) && !fragment_control_passed
                {
                    continue;
                }
                if cancel.load(Ordering::Relaxed) {
                    return Err("QUIC-испытание отменено".into());
                }
                let outcome = match Self::run_quic_discovery_candidate(
                    commands,
                    cancel,
                    server,
                    local,
                    &mut probe,
                    &candidate,
                    &server_name,
                    &runtime,
                    request_timeout,
                    &roots,
                    false,
                    measurement_permit,
                ) {
                    Ok(Some(outcome)) => outcome,
                    Ok(None) => continue,
                    Err(error) => {
                        eprintln!(
                            "испытание QUIC-кандидата «{}» не завершено: {error}",
                            candidate.name
                        );
                        continue;
                    }
                };
                if candidate.kind
                    == r2o_controller::quic_replay::R2oQuicCandidateKind::FragmentControl
                {
                    fragment_control_passed =
                        r2o_controller::quic_replay::r2o_quic_fragment_control_succeeded(
                            outcome.decision,
                            outcome.applied,
                        );
                    if fragment_control_passed {
                        println!("контроль IP-фрагментов прошёл 3/3 и подтверждён точным APPLIED");
                    } else {
                        println!("контроль IP-фрагментов не пройден; формы 1–4 пропускаются");
                    }
                    continue;
                }
                let decision = if outcome.applied {
                    outcome.decision
                } else {
                    r2o_controller::quic_replay::R2oQuicFilterDecision::Unknown
                };
                let Some(data) = outcome.data.as_ref() else {
                    continue;
                };
                let data_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(data);
                if decision == r2o_controller::quic_replay::R2oQuicFilterDecision::Pass
                    && !data.r2o_quic_stalled
                    && r2o_controller::quic_replay::r2o_quic_data_proof_confirmed(
                        data.handshake_confirmed,
                        outcome.applied,
                        data_verdict,
                    )
                {
                    selected_plan = Some((outcome.plan_text, candidate.name));
                    break;
                }
            }
        }

        if selected_plan.is_none() {
            let mut fallback = std::collections::VecDeque::from(
                r2o_controller::quic_replay::r2o_quic_original_fallback_candidates(
                    benign_asked,
                    ttl_three_answered_no,
                    fragment_questions_used,
                ),
            );
            while let Some(candidate) = fallback.pop_front() {
                if matches!(
                    candidate.kind,
                    r2o_controller::quic_replay::R2oQuicCandidateKind::FragmentShape(_)
                ) && !fragment_control_passed
                {
                    continue;
                }
                if cancel.load(Ordering::Relaxed) {
                    return Err("QUIC-испытание отменено".into());
                }
                let outcome = match Self::run_quic_discovery_candidate(
                    commands,
                    cancel,
                    server,
                    local,
                    &mut probe,
                    &candidate,
                    &server_name,
                    &runtime,
                    request_timeout,
                    &roots,
                    false,
                    measurement_permit,
                ) {
                    Ok(Some(outcome)) => outcome,
                    Ok(None) => continue,
                    Err(error) => {
                        eprintln!(
                            "испытание QUIC-кандидата «{}» не завершено: {error}",
                            candidate.name
                        );
                        continue;
                    }
                };
                if candidate.kind
                    == r2o_controller::quic_replay::R2oQuicCandidateKind::FragmentControl
                {
                    fragment_control_passed =
                        r2o_controller::quic_replay::r2o_quic_fragment_control_succeeded(
                            outcome.decision,
                            outcome.applied,
                        );
                    if fragment_control_passed {
                        println!("контроль IP-фрагментов прошёл 3/3 и подтверждён точным APPLIED");
                    } else {
                        println!("контроль IP-фрагментов не пройден; формы 1–4 пропускаются");
                    }
                    continue;
                }
                if candidate.kind
                    == (r2o_controller::quic_replay::R2oQuicCandidateKind::OriginalRepeats {
                        blob: 3,
                        copies: 11,
                    })
                {
                    let data_verdict = outcome
                        .data
                        .as_ref()
                        .map(r2o_controller::quic_replay::r2o_quic_trial_data_verdict);
                    if r2o_controller::quic_replay::r2o_quic_adaptive_split_eligible(
                        split_decision,
                        split_applicable,
                        outcome.filter.answered,
                        outcome.filter.measured,
                        data_verdict,
                    ) {
                        fallback.push_front(
                            r2o_controller::quic_replay::r2o_quic_adaptive_split_candidate(),
                        );
                    }
                }
                let decision = if outcome.applied {
                    outcome.decision
                } else {
                    r2o_controller::quic_replay::R2oQuicFilterDecision::Unknown
                };
                let Some(data) = outcome.data.as_ref() else {
                    continue;
                };
                let data_verdict = r2o_controller::quic_replay::r2o_quic_trial_data_verdict(data);
                if decision == r2o_controller::quic_replay::R2oQuicFilterDecision::Pass
                    && !data.r2o_quic_stalled
                    && r2o_controller::quic_replay::r2o_quic_data_proof_confirmed(
                        data.handshake_confirmed,
                        outcome.applied,
                        data_verdict,
                    )
                {
                    selected_plan = Some((outcome.plan_text, candidate.name));
                    break;
                }
                println!(
                    "QUIC-кандидат «{}» не дал двух доказательств: исход={decision:?}, HTTP/3={data_verdict:?}, точный APPLIED={}; временный план удалён",
                    candidate.name, outcome.applied,
                );
            }
        }
        let Some((plan_text, candidate_name)) = selected_plan else {
            println!("QUIC-подбор исчерпал доступные кандидаты без двух подтверждений");
            return Ok(None);
        };
        Ok(Some((plan_text, candidate_name)))
    }

    fn r2o_install_quic_candidate(
        &mut self,
        server: std::net::SocketAddr,
        plan_text: &str,
        candidate_name: &str,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        let (_lock, previous) = locked_catalog(catalog_path, catalog)?;
        if r2o_controller::discovery::has_usable_quic_address_binding(&previous, server.ip()) {
            *catalog = previous;
            println!("QUIC-план не заменён: другой процесс уже сохранил адресную привязку");
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let mut updated = previous.clone();
        let saved_plan_id = r2o_controller::discovery::add_confirmed_quic_address_binding(
            &mut updated,
            server.ip(),
            &plan_text,
            now,
        )
        .map_err(|error| format!("не удалось подготовить подтверждённую QUIC-привязку: {error}"))?;
        let saved_plan = updated
            .boxes
            .iter()
            .flat_map(|record| &record.plans)
            .find(|saved| saved.id == saved_plan_id && saved.enabled)
            .ok_or("сохранённый QUIC-план исчез из каталога")?;
        let saved_records = compile_text(&saved_plan.text)?;
        let command = encode_set_addr(server.ip(), SHAPE_QUIC, &saved_records)?;
        updated.save_atomic(catalog_path, now)?;
        if let Err(install_error) = self.send_command(&command, COMMAND_SET_ADDR) {
            return match previous.save_atomic(catalog_path, now) {
                Ok(()) => Err(format!(
                    "datapath не подтвердил постоянный QUIC-план; каталог восстановлен: {install_error}"
                )
                .into()),
                Err(rollback_error) => Err(format!(
                    "datapath не подтвердил постоянный QUIC-план ({install_error}); откат каталога не удался ({rollback_error})"
                )
                .into()),
            };
        }
        *catalog = updated;
        println!(
            "HTTP/3 и точный APPLIED подтверждены кандидатом «{candidate_name}»; адресный план {saved_plan_id} сохранён для {}",
            server.ip(),
        );
        Ok(())
    }

    fn revoke_http_binding(
        &mut self,
        response: &r2k_core::control::HttpResponseEvent,
        target: &r2o_controller::discovery::DiscoveryTarget,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<bool, Box<dyn Error>> {
        let (_lock, previous) = locked_catalog(catalog_path, catalog)?;
        let mut updated = previous.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        if !r2o_controller::discovery::revoke_http_response_binding(
            &mut updated,
            response,
            target,
            now,
        ) {
            return Ok(false);
        }
        updated.save_atomic(catalog_path, now)?;
        *catalog = updated;
        let command = encode_delete_name(&target.host, 6, SHAPE_HTTP, target.family)?;
        self.send_command(&command, control::COMMAND_DEL_NAME)?;
        println!(
            "HTTP {}: подтверждённая привязка отозвана после живого портала; запускаю повторную проверку",
            target.host
        );
        Ok(true)
    }

    fn install_http_candidate(
        &mut self,
        target: &r2o_controller::discovery::DiscoveryTarget,
        key: &str,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        let stable = stable_id(key);
        let text = candidate_text(key, Some(&stable))
            .ok_or_else(|| format!("неизвестный HTTP-кандидат: {key}"))?;
        let (_lock, previous) = locked_catalog(catalog_path, catalog)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let mut updated = previous.clone();
        let plan_id =
            r2o_controller::discovery::add_measured_binding(&mut updated, target, &text, now)
                .map_err(|error| format!("не удалось подготовить HTTP-план: {error}"))?;
        let saved = updated
            .boxes
            .iter()
            .flat_map(|record| &record.plans)
            .find(|plan| plan.id == plan_id && plan.enabled)
            .ok_or("HTTP-план не найден после добавления в каталог")?;
        let bytes = compile_text(&saved.text)?;
        let runtime_plan = Plan::parse(&bytes)?;
        r2o_datapath::engine::validate_runtime_plan(&runtime_plan)
            .map_err(|error| format!("план HTTP не принят runtime r2o-datapath: {error}"))?;
        let command = encode_set_name(&target.host, SHAPE_HTTP, target.family, &bytes)?;
        updated.save_atomic(catalog_path, now)?;
        if let Err(install_error) = self.send_set_name(&command) {
            return match previous.save_atomic(catalog_path, now) {
                Ok(()) => Err(format!(
                    "r2o-datapath не подтвердил HTTP-план; каталог восстановлен: {install_error}"
                )
                .into()),
                Err(rollback_error) => Err(format!(
                    "r2o-datapath не подтвердил HTTP-план ({install_error}); откат каталога не удался ({rollback_error})"
                )
                .into()),
            };
        }
        *catalog = updated;
        println!("HTTP обход найден: «{key}»; план {plan_id} установлен и сохранён");
        Ok(())
    }

    fn apply_discovery_outcome(
        &mut self,
        outcome: DiscoveryOutcome,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        let Some(source_text) = outcome.plan_text else {
            println!(
                "автопоиск не дал применимого плана для {}: {}",
                outcome.target.host, outcome.detail
            );
            return Ok(());
        };
        if r2o_controller::discovery::has_usable_binding(catalog, &outcome.target) {
            println!(
                "автопоиск пропущен: каталог уже покрывает {}",
                outcome.target.host
            );
            return Ok(());
        }

        let (_lock, previous) = locked_catalog(catalog_path, catalog)?;
        if r2o_controller::discovery::has_usable_binding(&previous, &outcome.target) {
            *catalog = previous;
            println!(
                "автопоиск пропущен: другой контроллер уже сохранил план для {}",
                outcome.target.host
            );
            return Ok(());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let mut updated = previous.clone();
        let plan_id = r2o_controller::discovery::add_measured_binding(
            &mut updated,
            &outcome.target,
            &source_text,
            now,
        )
        .map_err(|error| format!("не удалось сохранить результат классификации: {error}"))?;
        let plan_text = updated
            .boxes
            .iter()
            .flat_map(|box_record| &box_record.plans)
            .find(|plan| plan.id == plan_id && plan.enabled)
            .ok_or("сохранённый план исчез из каталога")?;
        let bytes = compile_text(&plan_text.text)?;
        let runtime_plan = Plan::parse(&bytes)?;
        r2o_datapath::engine::validate_runtime_plan(&runtime_plan)
            .map_err(|error| format!("исполнитель r2o-datapath отверг план: {error}"))?;
        let compiled = catalog_commands(&updated)?;

        if let Err(error) = updated.save_atomic(catalog_path, now) {
            println!("каталог не записан; план не установлен: {error}");
            return Ok(());
        }
        if let Err(install_error) = install_catalog(self, &compiled.commands) {
            let file_rollback = previous.save_atomic(catalog_path, now);
            let runtime_rollback = catalog_commands(&previous)
                .and_then(|previous_compiled| install_catalog(self, &previous_compiled.commands));
            return Err(match (file_rollback, runtime_rollback) {
                (Ok(()), Ok(())) => format!(
                    "r2o-datapath не подтвердил обновлённый каталог; восстановлены прежние каталог и планы: {install_error}"
                ),
                (file_result, runtime_result) => format!(
                    "r2o-datapath не подтвердил обновлённый каталог ({install_error}); откат файла: {}; откат datapath: {}",
                    file_result.err().map_or_else(|| "успешно".to_owned(), |error| error.to_string()),
                    runtime_result.err().map_or_else(|| "успешно".to_owned(), |error| error.to_string()),
                ),
            }
            .into());
        }
        *catalog = updated;
        println!(
            "автопоиск установил и сохранил план {} для {} ({shape})",
            plan_id,
            outcome.target.host,
            shape = if outcome.target.shape == SHAPE_MODERN {
                "TLS 1.3"
            } else {
                "TLS 1.2"
            }
        );
        Ok(())
    }

    fn send_command(&mut self, command: &[u8], expected: u16) -> Result<(), Box<dyn Error>> {
        let ack = self.exchange_command(command, expected)?;
        if ack.ok {
            return Ok(());
        }
        let reason = match ack.reason {
            control::ACK_BAD_PLAN => "план не подходит runtime",
            control::ACK_NO_ROOM => "таблица планов заполнена",
            control::ACK_BAD_ARGS => "датапат отверг аргументы",
            _ => "неизвестная причина",
        };
        let command_name = match expected {
            COMMAND_CLEAR => "CLEAR",
            COMMAND_SET_ADDR => "SET_ADDR",
            COMMAND_DEL_ADDR => "DEL_ADDR",
            control::COMMAND_SET_SUFFIX => "SET_SUFFIX",
            control::COMMAND_DEL_SUFFIX => "DEL_SUFFIX",
            control::COMMAND_SET_BYPASS => "SET_BYPASS",
            control::COMMAND_DEL_BYPASS => "DEL_BYPASS",
            control::COMMAND_DEL_NAME => "DEL_NAME",
            control::COMMAND_DEL_NAME_PROBE => "DEL_NAME_PROBE",
            COMMAND_DEL_VOICE_ADDR_PROBE => "DEL_VOICE_ADDR_PROBE",
            COMMAND_DEL_ADDR_PROBE => "команда удаления временной QUIC-пробы",
            control::COMMAND_SET_NAME_PROBE => "SET_NAME_PROBE",
            COMMAND_SET_VOICE_ADDR => "SET_VOICE_ADDR",
            COMMAND_SET_VOICE_ADDR_PROBE => "SET_VOICE_ADDR_PROBE",
            COMMAND_SET_ADDR_PROBE => "команда установки временной QUIC-пробы",
            COMMAND_SET_HTTPS => "SET_HTTPS",
            _ => "SET_NAME",
        };
        Err(format!("{command_name} не выполнена: {reason}").into())
    }

    fn exchange_command(
        &mut self,
        command: &[u8],
        expected: u16,
    ) -> Result<r2k_core::control::Ack, Box<dyn Error>> {
        use std::io::Write;
        self.socket.write_all(command)?;
        let deadline = std::time::Instant::now() + CONTROL_ACK_TIMEOUT;
        let ack_frame = loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() || !wait_for_control_frame(&self.socket, remaining)? {
                return Err("датапат не подтвердил управляющую команду за 3 секунды".into());
            }
            let frame = read_optional_frame(&mut self.socket)?
                .ok_or("соединение с датапатом закрыто до подтверждения команды")?;
            if frame.kind == control::EVENT_ACK {
                break frame;
            }
            self.queue_async_frame(frame)?;
        };
        let ack =
            decode_ack(&ack_frame).map_err(|error| format!("подтверждение датапата: {error}"))?;
        if ack.command != expected {
            return Err(format!("датапат подтвердил чужую команду 0x{:04x}", ack.command).into());
        }
        Ok(ack)
    }

    fn queue_async_frame(&mut self, frame: Frame) -> Result<(), Box<dyn Error>> {
        if !matches!(
            frame.kind,
            EVENT_HELLO
                | EVENT_APPLIED
                | EVENT_HTTP_PORTAL
                | EVENT_HTTP_RESPONSE
                | EVENT_R2O_QUIC_STALL
                | EVENT_R2O_QUIC_SUSPECT
                | EVENT_R2O_TCP_SILENT
                | EVENT_R2O_TCP_STALL
                | EVENT_R2O_TCP_FIN_RETRY
                | EVENT_R2O_TCP_RST_AFTER_APP
                | EVENT_R2O_VOICE_SUSPECT
                | EVENT_R2O_JOURNAL_ENTRY
                | EVENT_R2O_JOURNAL_END
        ) {
            return Ok(());
        }
        if self.pending_events.len() == MAX_PENDING_EVENTS {
            return Err("очередь событий контроллера заполнена".into());
        }
        self.pending_events.push_back(frame);
        Ok(())
    }
}

#[cfg(unix)]
struct BoundTcpProbe {
    socket: std::os::fd::OwnedFd,
    local_port: u16,
}

#[cfg(unix)]
impl BoundTcpProbe {
    fn open(family: u8, mark: Option<u32>) -> std::io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd};

        if !matches!(family, 4 | 6) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "семейство адресов HTTP-зонда не поддерживается",
            ));
        }
        let domain = if family == 4 {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let raw = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let socket = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        let fd = socket.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let mark = mark.unwrap_or(0x2d);
        #[cfg(target_os = "linux")]
        if mark != 0 {
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&mark as *const u32).cast(),
                    std::mem::size_of_val(&mark) as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = mark;

        let bound = if family == 4 {
            let address = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd,
                    (&address as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            }
        } else {
            let address = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
                sin6_scope_id: 0,
            };
            unsafe {
                libc::bind(
                    fd,
                    (&address as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            }
        };
        if bound != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut local: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&local) as libc::socklen_t;
        if unsafe {
            libc::getsockname(
                fd,
                (&mut local as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let local_port = unsafe {
            if family == 4 {
                u16::from_be((*(&local as *const _ as *const libc::sockaddr_in)).sin_port)
            } else {
                u16::from_be((*(&local as *const _ as *const libc::sockaddr_in6)).sin6_port)
            }
        };
        if local_port == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "ядро не назначило порт HTTP-зонду",
            ));
        }
        Ok(Self { socket, local_port })
    }

    fn connect(
        self,
        destination: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> std::io::Result<(std::net::TcpStream, std::net::IpAddr, u16, i64)> {
        use std::os::fd::AsRawFd;

        let fd = self.socket.as_raw_fd();
        let start = std::time::Instant::now();
        let result = match destination {
            std::net::SocketAddr::V4(address) => {
                let raw = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: address.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(address.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    libc::connect(
                        fd,
                        (&raw as *const libc::sockaddr_in).cast(),
                        std::mem::size_of_val(&raw) as libc::socklen_t,
                    )
                }
            }
            std::net::SocketAddr::V6(address) => {
                let raw = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: address.port().to_be(),
                    sin6_flowinfo: address.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: address.ip().octets(),
                    },
                    sin6_scope_id: address.scope_id(),
                };
                unsafe {
                    libc::connect(
                        fd,
                        (&raw as *const libc::sockaddr_in6).cast(),
                        std::mem::size_of_val(&raw) as libc::socklen_t,
                    )
                }
            }
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EINPROGRESS | libc::EALREADY | libc::EINTR)
            ) {
                return Err(error);
            }
            let millis = timeout.as_millis().saturating_add(1).min(i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let ready = loop {
                let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
                if ready >= 0 {
                    break ready;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            };
            if ready == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "истёк срок соединения HTTP-зонда",
                ));
            }
            let mut socket_error: libc::c_int = 0;
            let mut length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut socket_error as *mut libc::c_int).cast(),
                    &mut length,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if socket_error != 0 {
                return Err(std::io::Error::from_raw_os_error(socket_error));
            }
        }
        let stream = std::net::TcpStream::from(self.socket);
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let local = stream.local_addr()?;
        Ok((
            stream,
            local.ip(),
            local.port(),
            start.elapsed().as_micros() as i64,
        ))
    }
}

#[cfg(unix)]
struct HttpTrialSocketResult {
    answer: r2o_controller::http_search::Answer,
    requests_sent: usize,
    complete_responses: usize,
    client: std::net::IpAddr,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpCandidateProgress {
    Repeat,
    Next,
    Confirmed,
}

#[cfg(unix)]
#[derive(Default)]
struct HttpCandidateHistory {
    confirmations: u8,
    had_complete_server_trial: bool,
    retried_cut: bool,
}

#[cfg(unix)]
fn advance_http_candidate(
    history: &mut HttpCandidateHistory,
    answer: Option<r2o_controller::http_search::Answer>,
    complete_responses: usize,
    execution_confirmed: bool,
) -> HttpCandidateProgress {
    use r2o_controller::http_search::Answer;

    if !execution_confirmed {
        return HttpCandidateProgress::Next;
    }
    match answer {
        Some(Answer::Real) if complete_responses >= 2 => {
            history.had_complete_server_trial = true;
            history.confirmations += 1;
            if history.confirmations >= 2 {
                HttpCandidateProgress::Confirmed
            } else {
                HttpCandidateProgress::Repeat
            }
        }
        Some(Answer::Cut) if history.had_complete_server_trial && !history.retried_cut => {
            history.retried_cut = true;
            history.confirmations = 0;
            HttpCandidateProgress::Repeat
        }
        _ => HttpCandidateProgress::Next,
    }
}

#[cfg(unix)]
struct HttpTrialResult {
    answer: Option<r2o_controller::http_search::Answer>,
    requests_sent: usize,
    complete_responses: usize,
    execution_confirmed: bool,
}

#[cfg(unix)]
enum HttpBaselineError {
    Connect(std::io::Error),
    Send(std::io::Error),
    Response(std::io::Error),
    InvalidPath,
}

#[cfg(unix)]
fn baseline_silence_starts_search(
    expected: r2o_controller::http_search::Answer,
    kind: std::io::ErrorKind,
) -> bool {
    expected == r2o_controller::http_search::Answer::Injected
        && matches!(
            kind,
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        )
}

#[cfg(unix)]
impl std::fmt::Display for HttpBaselineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(error) => write!(formatter, "соединение: {error}"),
            Self::Send(error) => write!(formatter, "отправка запроса: {error}"),
            Self::Response(error) => write!(formatter, "чтение ответа: {error}"),
            Self::InvalidPath => formatter.write_str("HTTP-путь нельзя повторить"),
        }
    }
}

#[cfg(unix)]
fn run_http_search_task(
    task: HttpSearchTask,
    commands: &SyncSender<HttpSearchCommand>,
    cancel: &AtomicBool,
) -> Result<HttpSearchDisposition, String> {
    if cancel.load(Ordering::Relaxed) {
        return Ok(HttpSearchDisposition::Inconclusive);
    }
    let HttpSearchTask {
        target,
        request_path,
        expected_baseline,
        candidates,
        live_failures,
        mark,
    } = task;
    if live_failures.evidence_lost {
        println!(
            "HTTP {}: история живого отказа неполна; поиск остановлен без установки кандидатов",
            target.host
        );
        return Ok(HttpSearchDisposition::Inconclusive);
    }
    let destination = target
        .endpoint
        .parse::<std::net::SocketAddr>()
        .map_err(|error| error.to_string())?;
    println!("HTTP {}: проверяю воспроизводимость ответа", target.host);
    let baseline = match run_http_baseline(
        &target.host,
        destination,
        target.family,
        mark,
        &request_path,
    ) {
        Ok(response) => Some(response),
        Err(HttpBaselineError::Response(error))
            if baseline_silence_starts_search(expected_baseline, error.kind()) =>
        {
            println!(
                "HTTP {}: клиент получил заглушку, а базовый запрос роутера молчит; начинаю поиск кандидатов",
                target.host
            );
            None
        }
        Err(error) => {
            println!("HTTP {}: базовый зонд не завершился: {error}", target.host);
            return Ok(HttpSearchDisposition::Recheck);
        }
    };
    if baseline
        .as_ref()
        .is_some_and(|response| response.answer == r2o_controller::http_search::Answer::Challenge)
    {
        println!(
            "HTTP {}: получен cf-mitigated: challenge — поиск остановлен, пауза цели 60 мин",
            target.host
        );
        return Ok(HttpSearchDisposition::Challenge);
    }
    if baseline
        .as_ref()
        .is_some_and(|response| response.answer != expected_baseline)
    {
        println!(
            "HTTP {}: исходный ответ не воспроизвёлся на том же пути; поиск не начат",
            target.host
        );
        return Ok(HttpSearchDisposition::Recheck);
    }

    let mut skipped_conflicts = 0;
    let mut any_complete_server_trial = false;
    for key in candidates {
        if cancel.load(Ordering::Relaxed) {
            return Ok(HttpSearchDisposition::Inconclusive);
        }
        let program = candidate_program(&key)
            .ok_or_else(|| format!("HTTP-кандидат не компилируется: {key}"))?;
        if live_failures.programs.contains(&program) {
            skipped_conflicts += 1;
            println!(
                "HTTP {}: кандидат «{key}» пропущен — его TLV совпадает с ранее отвергнутой живым ответом программой",
                target.host
            );
            continue;
        }
        let mut history = HttpCandidateHistory::default();
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Ok(HttpSearchDisposition::Inconclusive);
            }
            let trial =
                run_http_trial_task(&target, destination, &key, mark, &request_path, commands)?;
            use r2o_controller::http_search::Answer;
            if trial.answer == Some(Answer::Challenge) {
                println!(
                    "HTTP {}: получен cf-mitigated: challenge — поиск остановлен, пауза цели 60 мин",
                    target.host
                );
                return Ok(HttpSearchDisposition::Challenge);
            }
            if trial.execution_confirmed
                && trial.answer == Some(Answer::Real)
                && trial.complete_responses >= 2
            {
                any_complete_server_trial = true;
            }
            let progress = advance_http_candidate(
                &mut history,
                trial.answer,
                trial.complete_responses,
                trial.execution_confirmed,
            );
            match progress {
                HttpCandidateProgress::Confirmed => {
                    ask_http_controller(commands, |reply| HttpSearchCommand::InstallCandidate {
                        target: target.clone(),
                        key: key.clone(),
                        reply,
                    })?;
                    return Ok(HttpSearchDisposition::Recheck);
                }
                HttpCandidateProgress::Repeat => {
                    if trial.answer == Some(Answer::Cut) {
                        println!(
                            "HTTP {}: «{key}» — обрыв тела после ответа сервера (запросов {}, полных ответов {}), диагностический повтор",
                            target.host, trial.requests_sent, trial.complete_responses
                        );
                    }
                }
                HttpCandidateProgress::Next => {
                    if trial.answer == Some(Answer::Cut) {
                        println!(
                            "HTTP {}: «{key}» — обрыв тела после ответа сервера (запросов {}, полных ответов {}); кандидат не подтверждён, проверяю следующий",
                            target.host, trial.requests_sent, trial.complete_responses
                        );
                    } else {
                        println!(
                            "HTTP {}: кандидат «{key}» не подтвердил два полных ответа сервера; проверяю следующий",
                            target.host
                        );
                    }
                    break;
                }
            }
        }
    }
    let disposition = r2o_http_failed_disposition(skipped_conflicts, any_complete_server_trial);
    if skipped_conflicts > 0 {
        println!(
            "HTTP {}: поиск завершён без принятого плана: {skipped_conflicts} кандидат(а) совпали с живыми отказами в области привязки имени; воспроизведение не объясняет живой поток",
            target.host,
        );
    } else if any_complete_server_trial {
        println!(
            "HTTP {}: поиск завершён без подтверждения — ответ сервера был получен, но устойчивость не подтверждена; следующая попытка не раньше чем через 5 мин",
            target.host,
        );
    } else {
        println!(
            "HTTP {}: обход не найден — ни один кандидат не дал полного ответа сервера; следующая попытка не раньше чем через 60 мин",
            target.host,
        );
    }
    Ok(disposition)
}

#[cfg(unix)]
fn run_http_trial_task(
    target: &r2o_controller::discovery::DiscoveryTarget,
    destination: std::net::SocketAddr,
    key: &str,
    mark: Option<u32>,
    request_path: &[u8],
    commands: &SyncSender<HttpSearchCommand>,
) -> Result<HttpTrialResult, String> {
    let bound = match BoundTcpProbe::open(target.family, mark) {
        Ok(bound) => bound,
        Err(error) => {
            println!(
                "HTTP {}: не удалось открыть сокет зонда: {error}",
                target.host
            );
            return Ok(HttpTrialResult {
                answer: None,
                requests_sent: 0,
                complete_responses: 0,
                execution_confirmed: false,
            });
        }
    };
    let port = bound.local_port;
    let plan_id = random_id().map_err(|error| error.to_string())?;
    let trial_id = random_id().map_err(|error| error.to_string())?;
    let plan_text = candidate_text(key, Some(&plan_id))
        .ok_or_else(|| format!("неизвестный HTTP-кандидат: {key}"))?;
    let records = compile_text(&plan_text).map_err(|error| error.to_string())?;
    let command = encode_set_name_probe(
        &target.host,
        SHAPE_HTTP,
        target.family,
        port,
        &records,
        trial_id,
    )
    .map_err(|error| error.to_string())?;
    let ack = ask_http_controller(commands, |reply| HttpSearchCommand::InstallProbe {
        host: target.host.clone(),
        family: target.family,
        port,
        command,
        trial_id,
        reply,
    })?;
    if ack.trial_id != Some(trial_id) {
        return Err("подтверждение HTTP-пробы содержит чужой trial ID".into());
    }
    if !ack.ok {
        println!(
            "HTTP {}: датапат отверг временный план «{key}»",
            target.host
        );
        return Ok(HttpTrialResult {
            answer: None,
            requests_sent: 0,
            complete_responses: 0,
            execution_confirmed: false,
        });
    }

    let result = run_http_trial_socket(bound, destination, &target.host, request_path);
    ask_http_controller(commands, |reply| HttpSearchCommand::DeleteProbe {
        host: target.host.clone(),
        family: target.family,
        port,
        reply,
    })?;
    let events = r2o_collect_controller_applied_events(
        commands,
        trial_id,
        std::time::Duration::from_millis(500),
    )?;
    let result = match result {
        Ok(result) => Some(result),
        Err(error) => {
            println!(
                "HTTP {}: зонд «{key}» завершился без полного результата: {error}",
                target.host
            );
            None
        }
    };
    let Some(result) = result else {
        return Ok(HttpTrialResult {
            answer: None,
            requests_sent: 0,
            complete_responses: 0,
            execution_confirmed: false,
        });
    };
    let identity = r2o_controller::http_search::ProbeIdentity {
        plan_id,
        trial_id,
        family: target.family,
        client: result.client,
        server: destination.ip(),
        local_port: port,
    };
    let proof =
        r2o_controller::http_search::confirmed_applied(&events, &identity, result.requests_sent);
    Ok(HttpTrialResult {
        answer: Some(result.answer),
        requests_sent: result.requests_sent,
        complete_responses: result.complete_responses,
        execution_confirmed: proof.is_some(),
    })
}

#[cfg(unix)]
fn ask_http_controller<T: Send + 'static>(
    commands: &SyncSender<HttpSearchCommand>,
    build: impl FnOnce(SyncSender<Result<T, String>>) -> HttpSearchCommand,
) -> Result<T, String> {
    let (reply, response) = mpsc::sync_channel(1);
    commands
        .send(build(reply))
        .map_err(|_| "управляющий цикл HTTP-поиска остановлен".to_owned())?;
    response
        .recv()
        .map_err(|_| "управляющий цикл HTTP-поиска закрыл ответ".to_owned())?
}

#[cfg(unix)]
fn r2o_collect_controller_applied_events(
    commands: &SyncSender<HttpSearchCommand>,
    trial_id: [u8; 16],
    timeout: std::time::Duration,
) -> Result<Vec<r2k_core::control::AppliedEvent>, String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut events = Vec::new();
    loop {
        events.extend(ask_http_controller(commands, |reply| {
            HttpSearchCommand::CollectApplied {
                trial_id,
                timeout: std::time::Duration::ZERO,
                reply,
            }
        })?);
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok(events);
        }
        std::thread::sleep(remaining.min(std::time::Duration::from_millis(20)));
    }
}

#[cfg(unix)]
fn run_http_baseline(
    host: &str,
    destination: std::net::SocketAddr,
    family: u8,
    mark: Option<u32>,
    request_path: &[u8],
) -> Result<r2o_controller::http_search::HttpProbeResponse, HttpBaselineError> {
    use std::io::Write;

    let bound = BoundTcpProbe::open(family, mark).map_err(HttpBaselineError::Connect)?;
    let (mut stream, _, _, rtt_us) = bound
        .connect(destination, std::time::Duration::from_secs(6))
        .map_err(HttpBaselineError::Connect)?;
    let request =
        build_http_get_request(host, request_path).ok_or(HttpBaselineError::InvalidPath)?;
    let sent = std::time::Instant::now();
    stream
        .write_all(&request)
        .map_err(HttpBaselineError::Send)?;
    r2o_controller::http_search::read_probe_response(
        &mut stream,
        Some(host.as_bytes()),
        rtt_us,
        sent,
    )
    .map_err(HttpBaselineError::Response)
}

#[cfg(unix)]
fn run_http_trial_socket(
    bound: BoundTcpProbe,
    destination: std::net::SocketAddr,
    host: &str,
    request_path: &[u8],
) -> Result<HttpTrialSocketResult, String> {
    use std::io::Write;

    let (mut stream, client, _, rtt_us) = bound
        .connect(destination, std::time::Duration::from_secs(6))
        .map_err(|error| error.to_string())?;
    let request = build_http_get_request(host, request_path)
        .ok_or_else(|| "HTTP-путь нельзя повторить".to_owned())?;
    let mut result = HttpTrialSocketResult {
        answer: r2o_controller::http_search::Answer::Real,
        requests_sent: 0,
        complete_responses: 0,
        client,
    };
    for _ in 0..2 {
        let sent = std::time::Instant::now();
        stream
            .write_all(&request)
            .map_err(|error| error.to_string())?;
        result.requests_sent += 1;
        let response = r2o_controller::http_search::read_probe_response(
            &mut stream,
            Some(host.as_bytes()),
            rtt_us,
            sent,
        )
        .map_err(|error| error.to_string())?;
        result.answer = response.answer;
        if response.answer != r2o_controller::http_search::Answer::Real || !response.complete {
            break;
        }
        result.complete_responses += 1;
        if response.connection_close {
            break;
        }
        if response.connection_close {
            break;
        }
    }
    Ok(result)
}

#[cfg(unix)]
fn build_http_get_request(host: &str, request_path: &[u8]) -> Option<Vec<u8>> {
    if r2k_core::control::encode_set_https(host, 1).is_err()
        || !r2o_controller::http_search::repeatable_path(request_path)
    {
        return None;
    }
    let mut request = Vec::with_capacity(host.len() + request_path.len() + 96);
    request.extend_from_slice(b"GET ");
    request.extend_from_slice(request_path);
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(
        b"\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
    );
    Some(request)
}

#[cfg(unix)]
fn random_id() -> std::io::Result<[u8; 16]> {
    use std::io::Read;

    let mut id = [0; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut id)?;
    if id.iter().all(|byte| *byte == 0) {
        id[0] = 1;
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::locked_catalog;
    #[cfg(unix)]
    use super::saved_http_candidate_keys;
    use super::{
        ClassifyCliOptions, ControlClient, DiscoveryOutcome, HttpCandidateHistory,
        HttpCandidateProgress, HttpLiveFailures, HttpSearchCommand, HttpSearchDisposition,
        HttpSearchTask, HttpSearchWindow, HttpSearchWorker, R2oVoiceTrialContext, ServeCliOptions,
        advance_http_candidate, applied_quic_trial_matches, baseline_silence_starts_search,
        binding_shape_transport, catalog_commands, failed_http_programs, flow_socket_addresses,
        http_search_candidates, http_search_key, matching_domain_group,
        measured_http_candidate_keys, normalize_plan_target, parse_classify_options,
        parse_serve_options, print_flow_journal, r2o_discovery_failure_retry_due,
        r2o_http_failed_disposition, r2o_http_live_cut_recheck, r2o_voice_proof_matches_target,
        save_plan_file, shape_matches_plan,
    };
    use r2k_core::control::{
        COMMAND_DEL_NAME_PROBE, COMMAND_DEL_VOICE_ADDR_PROBE, COMMAND_SET_NAME,
        COMMAND_SET_NAME_PROBE, COMMAND_SET_VOICE_ADDR, EVENT_APPLIED, EVENT_R2O_TCP_SILENT,
        EVENT_R2O_TCP_STALL, Frame, KEY_LEN, SHAPE_MODERN, SHAPE_QUIC, SHAPE_VOICE, encode_ack,
        encode_ack_for_trial, encode_frame, encode_greeting, read_frame,
    };
    use r2k_core::plan::{PLAN_MAGIC, Plan};
    use r2o_controller::catalog::{Binding, BoxRecord, Catalog};
    use std::{collections::VecDeque, ffi::OsString, io::Write, path::PathBuf};

    #[cfg(unix)]
    #[test]
    fn r2o_начальная_quic_очередь_сохраняет_допуск_через_первый_тик() {
        use r2o_controller::r2o_resource_limit::R2oMeasurementGate;

        let gate = R2oMeasurementGate::r2o_with_start_gap(2);
        let mut pending = VecDeque::new();
        assert_eq!(
            super::r2o_enqueue_quic_discovery(
                &mut pending,
                "127.0.0.1:443".parse().unwrap(),
                vec![1, 2, 3],
                std::time::Instant::now(),
                &gate,
            ),
            1
        );
        gate.r2o_scheduler_tick();
        let (entry, permit) = super::r2o_take_ready_quic_discovery(&mut pending, &gate).unwrap();
        assert_eq!(entry.snapshot, [1, 2, 3]);
        drop(permit);
        assert!(gate.r2o_try_acquire().is_none());

        let full_gate = R2oMeasurementGate::r2o_with_start_gap(1);
        let held = full_gate.r2o_try_acquire().unwrap();
        let mut queued = VecDeque::new();
        assert_eq!(
            super::r2o_enqueue_quic_discovery(
                &mut queued,
                "127.0.0.1:443".parse().unwrap(),
                vec![4, 5, 6],
                std::time::Instant::now(),
                &full_gate,
            ),
            1
        );
        full_gate.r2o_scheduler_tick();
        drop(held);
        assert!(super::r2o_take_ready_quic_discovery(&mut queued, &full_gate).is_none());
        assert_eq!(queued.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_событийная_пачка_считывает_все_готовые_кадры() {
        use std::os::unix::net::UnixStream;

        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        writer
            .write_all(&encode_frame(1, &[0x11]).unwrap())
            .unwrap();
        writer
            .write_all(&encode_frame(2, &[0x22]).unwrap())
            .unwrap();
        let first = super::read_optional_frame(&mut reader).unwrap().unwrap();

        let batch = super::r2o_read_control_batch(&mut reader, first, 256).unwrap();

        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].kind, 1);
        assert_eq!(batch[1].kind, 2);
        assert_eq!(batch[1].body, [0x22]);
    }

    #[cfg(unix)]
    #[test]
    fn http_candidate_retries_one_cut_after_a_complete_server_trial() {
        use r2o_controller::http_search::Answer;

        let mut history = HttpCandidateHistory::default();
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Real), 2, true),
            HttpCandidateProgress::Repeat
        );
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Cut), 1, true),
            HttpCandidateProgress::Repeat
        );
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Real), 2, true),
            HttpCandidateProgress::Repeat
        );
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Real), 2, true),
            HttpCandidateProgress::Confirmed
        );
    }

    #[cfg(unix)]
    #[test]
    fn http_candidate_accepts_more_than_two_complete_responses() {
        use r2o_controller::http_search::Answer;

        let mut history = HttpCandidateHistory::default();
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Real), 3, true),
            HttpCandidateProgress::Repeat
        );
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Real), 3, true),
            HttpCandidateProgress::Confirmed
        );
    }

    #[cfg(unix)]
    #[test]
    fn http_candidate_does_not_retry_unconfirmed_or_repeated_cuts() {
        use r2o_controller::http_search::Answer;

        let mut history = HttpCandidateHistory::default();
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Cut), 0, true),
            HttpCandidateProgress::Next
        );
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Real), 2, false),
            HttpCandidateProgress::Next
        );

        let mut history = HttpCandidateHistory::default();
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Real), 2, true),
            HttpCandidateProgress::Repeat
        );
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Cut), 0, true),
            HttpCandidateProgress::Repeat
        );
        assert_eq!(
            advance_http_candidate(&mut history, Some(Answer::Cut), 0, true),
            HttpCandidateProgress::Next
        );
    }

    #[cfg(unix)]
    #[test]
    fn http_search_dispositions_keep_retry_windows_distinct() {
        use std::time::Duration;

        assert_eq!(
            HttpSearchDisposition::Retry.cooldown(),
            Duration::from_secs(60 * 60)
        );
        assert_eq!(
            HttpSearchDisposition::Inconclusive.cooldown(),
            Duration::from_secs(5 * 60)
        );
        assert_eq!(
            HttpSearchDisposition::Recheck.cooldown(),
            Duration::from_secs(10 * 60)
        );
        assert_eq!(
            HttpSearchDisposition::Challenge.cooldown(),
            Duration::from_secs(60 * 60)
        );
    }

    #[cfg(unix)]
    #[test]
    fn http_challenge_pauses_the_name_and_address_family_across_endpoints() {
        use r2o_controller::discovery::DiscoveryTarget;
        use std::time::Instant;

        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "192.0.2.1:80".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_HTTP,
        };
        client.complete_http_search(&target, HttpSearchDisposition::Challenge, Instant::now());

        assert!(!client.begin_http_search(&target, false));

        let mut other_endpoint = target.clone();
        other_endpoint.endpoint = "192.0.2.2:80".into();
        assert!(!client.begin_http_search(&other_endpoint, false));

        let mut other_family = target.clone();
        other_family.endpoint = "[2001:db8::1]:80".into();
        other_family.family = 6;
        assert!(client.begin_http_search(&other_family, false));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_http_без_ответа_оставляет_часовую_паузу() {
        assert_eq!(
            r2o_http_failed_disposition(0, false),
            HttpSearchDisposition::Retry
        );
        assert_eq!(
            r2o_http_failed_disposition(0, true),
            HttpSearchDisposition::Inconclusive
        );
        assert_eq!(
            r2o_http_failed_disposition(1, true),
            HttpSearchDisposition::Retry
        );
    }

    #[cfg(unix)]
    #[test]
    fn http_search_window_blocks_active_work_and_uses_its_result_delay() {
        use r2o_controller::discovery::DiscoveryTarget;
        use std::time::{Duration, Instant};

        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "192.0.2.1:80".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_HTTP,
        };
        let key = http_search_key(&target);
        let now = Instant::now();
        client.http_search_started.insert(
            key.clone(),
            HttpSearchWindow {
                started: now - Duration::from_secs(4 * 60 + 59),
                cooldown: HttpSearchDisposition::Inconclusive.cooldown(),
                active: false,
            },
        );
        assert!(!client.begin_http_search(&target, false));

        client.http_search_started.insert(
            key.clone(),
            HttpSearchWindow {
                started: now - Duration::from_secs(5 * 60 + 1),
                cooldown: HttpSearchDisposition::Inconclusive.cooldown(),
                active: false,
            },
        );
        assert!(client.begin_http_search(&target, false));
        assert!(!client.begin_http_search(&target, false));

        client.http_search_started.insert(
            key,
            HttpSearchWindow {
                started: now - Duration::from_secs(59 * 60),
                cooldown: HttpSearchDisposition::Retry.cooldown(),
                active: false,
            },
        );
        assert!(!client.begin_http_search(&target, false));

        let mut other_endpoint = target.clone();
        other_endpoint.endpoint = "192.0.2.2:80".into();
        assert!(client.begin_http_search(&other_endpoint, false));
        assert!(!client.begin_http_search(&target, false));
    }

    #[cfg(unix)]
    #[test]
    fn живой_http_обрыв_снимает_только_завершённое_окно_повтора() {
        use r2o_controller::discovery::DiscoveryTarget;
        use std::time::Instant;

        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "192.0.2.1:80".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_HTTP,
        };
        let key = http_search_key(&target);
        let now = Instant::now();
        client.http_search_started.insert(
            key.clone(),
            HttpSearchWindow {
                started: now,
                cooldown: HttpSearchDisposition::Recheck.cooldown(),
                active: false,
            },
        );

        assert!(!client.begin_http_search(&target, false));
        assert!(client.begin_http_search(&target, true));

        client.http_search_started.insert(
            key,
            HttpSearchWindow {
                started: now,
                cooldown: HttpSearchDisposition::Recheck.cooldown(),
                active: true,
            },
        );
        assert!(!client.begin_http_search(&target, true));
    }

    #[cfg(unix)]
    #[test]
    fn немедленная_перепроверка_разрешена_только_для_живого_http_обрыва() {
        assert!(r2o_http_live_cut_recheck(4, true));
        assert!(!r2o_http_live_cut_recheck(4, false));
        assert!(!r2o_http_live_cut_recheck(3, true));
    }

    #[cfg(unix)]
    #[test]
    fn silent_baseline_after_a_portal_starts_candidate_search() {
        use r2o_controller::http_search::Answer;
        use std::io::ErrorKind;

        assert!(baseline_silence_starts_search(
            Answer::Injected,
            ErrorKind::TimedOut
        ));
        assert!(baseline_silence_starts_search(
            Answer::Injected,
            ErrorKind::WouldBlock
        ));
        assert!(!baseline_silence_starts_search(
            Answer::Cut,
            ErrorKind::TimedOut
        ));
        assert!(!baseline_silence_starts_search(
            Answer::Injected,
            ErrorKind::ConnectionReset
        ));
    }

    #[cfg(unix)]
    #[test]
    fn controller_queues_applied_events_for_later_processing() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        let applied = Frame {
            kind: EVENT_APPLIED,
            body: vec![0x5a; 12],
        };

        client.queue_async_frame(applied.clone()).unwrap();

        assert_eq!(client.pending_events, VecDeque::from([applied]));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_controller_queues_tcp_silence_events_for_later_processing() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        let event = Frame {
            kind: EVENT_R2O_TCP_SILENT,
            body: vec![0; KEY_LEN + 5],
        };

        client.queue_async_frame(event.clone()).unwrap();

        assert_eq!(client.pending_events, VecDeque::from([event]));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_controller_queues_tcp_stall_events_for_later_processing() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        let event = Frame {
            kind: EVENT_R2O_TCP_STALL,
            body: vec![0; KEY_LEN + 9],
        };

        client.queue_async_frame(event.clone()).unwrap();

        assert_eq!(client.pending_events, VecDeque::from([event]));
    }

    #[cfg(unix)]
    #[test]
    fn controller_queues_journal_entries_and_snapshot_end() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        let mut journal_entry = r2o_datapath::flow_journal::R2oFlowJournalEntry::default();
        journal_entry.key[0] = 4;
        journal_entry.key[37] = 6;
        let entry = journal_entry.to_event_frame().unwrap();
        let end = r2o_datapath::flow_journal::R2oFlowJournalSummary {
            added: 0,
            dropped: 0,
            count: 0,
        }
        .to_event_frame();

        client.queue_async_frame(entry.clone()).unwrap();
        client.queue_async_frame(end.clone()).unwrap();

        assert_eq!(client.pending_events, VecDeque::from([entry, end]));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_cli_читает_полный_снимок_журнала_из_сокета() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_path = std::env::temp_dir().join(format!("r2o-cli-journal-{nonce}.sock"));
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.write_all(&encode_greeting(u16::MAX as u32).unwrap())
                .unwrap();
            let mut entry = r2o_datapath::flow_journal::R2oFlowJournalEntry::default();
            entry.key[0] = 4;
            entry.key[37] = 6;
            entry.set_name(b"example.test");
            let event = entry.to_event_frame().unwrap();
            peer.write_all(&encode_frame(event.kind, &event.body).unwrap())
                .unwrap();
            let summary = r2o_datapath::flow_journal::R2oFlowJournalSummary {
                added: 1,
                dropped: 0,
                count: 1,
            }
            .to_event_frame();
            peer.write_all(&encode_frame(summary.kind, &summary.body).unwrap())
                .unwrap();
        });

        let result = print_flow_journal(socket_path.clone());

        server.join().unwrap();
        std::fs::remove_file(socket_path).unwrap();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn r2o_flow_socket_addresses_preserve_ipv4_ipv6_direction() {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 20]);
        key[33..35].copy_from_slice(&41000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 6;
        assert_eq!(
            flow_socket_addresses(&key, true),
            (
                "192.0.2.10:41000".parse().unwrap(),
                "198.51.100.20:443".parse().unwrap(),
            )
        );
        assert_eq!(
            flow_socket_addresses(&key, false),
            (
                "198.51.100.20:443".parse().unwrap(),
                "192.0.2.10:41000".parse().unwrap(),
            )
        );

        key = [0; KEY_LEN];
        key[0] = 6;
        key[1..17].copy_from_slice(
            &"2001:db8::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        key[17..33].copy_from_slice(
            &"2001:db8::20"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        key[33..35].copy_from_slice(&41000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 6;
        assert_eq!(
            flow_socket_addresses(&key, false),
            (
                "[2001:db8::20]:443".parse().unwrap(),
                "[2001:db8::10]:41000".parse().unwrap(),
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn applied_quic_trial_requires_exact_temporary_binding_and_flow() {
        let local: std::net::SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let server: std::net::SocketAddr = "198.51.100.20:443".parse().unwrap();
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 20]);
        key[33..35].copy_from_slice(&41000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 17;
        let mut event = r2k_core::control::AppliedEvent {
            key,
            plan_id: [0x22; 16],
            trial_id: [0x11; 16],
            execution_id: 1,
            binding: r2k_core::control::BindingContext {
                generation: 3,
                kind: 2,
                family: 4,
                shape: SHAPE_QUIC,
                temporary: true,
                epoch: [0x33; 16],
            },
        };
        let matches = |event: &r2k_core::control::AppliedEvent| {
            applied_quic_trial_matches(event, [0x11; 16], [0x22; 16], local, server)
        };

        assert!(matches(&event));
        event.trial_id = [0x44; 16];
        assert!(!matches(&event));
        event.trial_id = [0x11; 16];
        event.plan_id = [0x44; 16];
        assert!(!matches(&event));
        event.plan_id = [0x22; 16];
        event.binding.temporary = false;
        assert!(!matches(&event));
        event.binding.temporary = true;
        event.key[35..37].copy_from_slice(&444_u16.to_be_bytes());
        assert!(!matches(&event));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_quic_подбор_удаляет_все_пробы_без_двух_доказательств() {
        use super::{R2oQuicDiscoveryTask, R2oQuicDiscoveryWorker};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let work = std::env::temp_dir().join(format!(
            "r2o-quic-trial-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&work).unwrap();
        let udp_server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp_server
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .unwrap();
        let endpoint = udp_server.local_addr().unwrap();
        let (candidate_done_tx, candidate_done_rx) = std::sync::mpsc::channel();
        let control_done = Arc::new(AtomicBool::new(false));
        let control_done_sender = Arc::clone(&control_done);
        let udp_thread = std::thread::spawn(move || {
            let mut peers = Vec::new();
            loop {
                let mut packet = [0; 1500];
                match udp_server.recv_from(&mut packet) {
                    Ok((length, peer)) => {
                        if r2k_core::quic::r2k_quic_initial_flight_id(&packet[..length]).is_some() {
                            peers.push(peer);
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        if candidate_done_rx.try_recv().is_ok() {
                            break;
                        }
                    }
                    Err(error) => panic!("ошибка приёмника UDP: {error}"),
                }
            }
            peers
        });
        let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let control_thread = std::thread::spawn(move || {
            for candidate_index in 0..16 {
                let set = read_frame(&mut peer).unwrap();
                assert_eq!(set.kind, super::COMMAND_SET_ADDR_PROBE);
                let trial_id: [u8; 16] = set.body[KEY_LEN..KEY_LEN + 16].try_into().unwrap();
                let plan = Plan::parse(&set.body[KEY_LEN + 20..]).unwrap();
                match candidate_index {
                    0 => {
                        assert_eq!(plan.fakes.len(), 1);
                        assert_eq!(plan.fakes[0].repeats, 1);
                        assert_eq!(plan.payloads[0].bytes, [0; 16]);
                    }
                    1 => assert_eq!(plan.qsplit, 1),
                    2 => assert_eq!(plan.udplen, 100),
                    3 => assert_eq!(plan.payloads[0].bytes.len(), 1200),
                    4 => assert_eq!(
                        plan.payloads[0].bytes,
                        include_bytes!("../../r2k-core/src/quic/quic_google.bin")
                    ),
                    5 => assert_eq!(
                        plan.payloads[0].bytes,
                        include_bytes!("../../r2k-core/src/quic/quic_rutracker.bin")
                    ),
                    6 => assert_eq!(
                        plan.payloads[0].bytes,
                        include_bytes!("../../r2k-core/src/quic/quic_default.bin")
                    ),
                    7 => assert_eq!(plan.fakes[0].repeats, 6),
                    8 => assert_eq!(plan.fakes[0].repeats, 11),
                    9 => {
                        assert_eq!(plan.payloads[0].bytes.len(), 620);
                        assert_eq!(plan.fakes[0].repeats, 6);
                    }
                    10 => assert_eq!(plan.fakes[0].repeats, 11),
                    11..=14 => {
                        assert_eq!(plan.fakes[0].repeats, 2);
                        assert_eq!(plan.poisons[0].ttl, [3, 5, 8, 12][candidate_index - 11]);
                    }
                    15 => assert_eq!(plan.ipfrag, 1),
                    _ => unreachable!(),
                }
                if candidate_index == 0 {
                    let mut key = [0; KEY_LEN];
                    key[0] = 4;
                    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
                    key[17..21].copy_from_slice(&[198, 51, 100, 20]);
                    key[33..35].copy_from_slice(&41000_u16.to_be_bytes());
                    key[35..37].copy_from_slice(&443_u16.to_be_bytes());
                    key[37] = 6;
                    let event = r2k_core::control::R2oTcpSilenceEvent {
                        key,
                        client_is_low: true,
                        elapsed_ms: 1000,
                    };
                    peer.write_all(
                        &encode_frame(EVENT_R2O_TCP_SILENT, &event.event_body().unwrap()).unwrap(),
                    )
                    .unwrap();
                }
                peer.write_all(
                    &encode_ack_for_trial(super::COMMAND_SET_ADDR_PROBE, true, 0, Some(trial_id))
                        .unwrap(),
                )
                .unwrap();

                let delete = read_frame(&mut peer).unwrap();
                assert_eq!(delete.kind, super::COMMAND_DEL_ADDR_PROBE);
                peer.write_all(&encode_ack(delete.kind, true, 0).unwrap())
                    .unwrap();
            }
            control_done_sender.store(true, Ordering::Relaxed);
            candidate_done_tx.send(()).unwrap();
        });
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let permit = gate
            .r2o_acquire(&std::sync::atomic::AtomicBool::new(false))
            .unwrap();
        let snapshot = r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[&include_bytes!(
            "../../r2k-core/tests/fixtures/quic_v1_initial.bin"
        )[..]])
        .unwrap();
        let mut worker = R2oQuicDiscoveryWorker::new();
        assert!(worker.queue(R2oQuicDiscoveryTask {
            server: endpoint,
            snapshot,
            permit,
        }));
        let mut saw_tcp_while_quic_active = false;
        let mut catalog = Catalog::default();
        let outcome = loop {
            if let Some(frame) = client.pending_events.pop_front() {
                if frame.kind == EVENT_R2O_TCP_SILENT {
                    let _ = r2k_core::control::decode_r2o_tcp_silence(&frame).unwrap();
                    assert!(!control_done.load(Ordering::Relaxed));
                    saw_tcp_while_quic_active = true;
                }
                continue;
            }
            if let Some(command) = worker.try_command() {
                client
                    .service_http_search_command(command, &mut catalog, &work.join("каталог.json"))
                    .unwrap();
                continue;
            }
            if let Some(outcome) = worker.try_outcome() {
                break outcome;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        };

        let peers = udp_thread.join().unwrap();
        control_thread.join().unwrap();
        drop(worker);
        assert!(peers.len() >= 48);
        assert!(peers.iter().all(|peer| *peer == peers[0]));
        assert!(saw_tcp_while_quic_active);
        assert!(matches!(outcome.result, Ok(None)));
        assert!(!work.join("каталог.json").exists());
        std::fs::remove_dir_all(work).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn r2o_quic_worker_одновременно_изолирует_два_адресных_опыта() {
        use super::{R2oQuicDiscoveryTask, R2oQuicDiscoveryWorker};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Condvar, Mutex};

        let состояние = Arc::new((Mutex::new(0_usize), Condvar::new(), AtomicUsize::new(0)));
        let состояние_работника = Arc::clone(&состояние);
        let mut worker = R2oQuicDiscoveryWorker::r2o_new_with_runner(Arc::new(
            move |_task, _commands, _cancel| {
                let (активные, сигнал, максимум) = &*состояние_работника;
                let mut активные = активные
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *активные += 1;
                максимум.fetch_max(*активные, Ordering::Relaxed);
                сигнал.notify_all();
                let (mut активные, _) = сигнал
                    .wait_timeout_while(
                        активные,
                        std::time::Duration::from_secs(1),
                        |активные| *активные < 2,
                    )
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let параллельно = максимум.load(Ordering::Relaxed) == 2;
                *активные -= 1;
                сигнал.notify_all();
                if параллельно {
                    Ok(None)
                } else {
                    Err("второй адресный опыт не стартовал параллельно".into())
                }
            },
        ));
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(2);
        let first = R2oQuicDiscoveryTask {
            server: "198.51.100.10:443".parse().unwrap(),
            snapshot: Vec::new(),
            permit: gate.r2o_try_acquire().unwrap(),
        };
        let second = R2oQuicDiscoveryTask {
            server: "198.51.100.20:443".parse().unwrap(),
            snapshot: Vec::new(),
            permit: gate.r2o_try_acquire().unwrap(),
        };

        assert!(worker.queue(first));
        assert!(worker.queue(second));
        assert!(!worker.has_capacity());

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut completed = std::collections::HashSet::new();
        while completed.len() < 2 {
            if let Some(outcome) = worker.try_outcome() {
                assert!(outcome.result.is_ok());
                assert!(completed.insert(outcome.server));
            } else {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        assert_eq!(состояние.2.load(Ordering::Relaxed), 2);
        assert!(worker.has_capacity());
    }

    #[cfg(unix)]
    #[test]
    fn r2o_quic_подтверждение_из_worker_сохраняет_и_устанавливает_план() {
        let work = std::env::temp_dir().join(format!(
            "r2o-quic-install-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&work).unwrap();
        let path = work.join("каталог.json");
        let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let control_thread = std::thread::spawn(move || {
            let install = read_frame(&mut peer).unwrap();
            assert_eq!(install.kind, super::COMMAND_SET_ADDR);
            assert_eq!(install.body[0], 4);
            assert_eq!(&install.body[1..5], &[198, 51, 100, 90]);
            let plan = Plan::parse(&install.body[18..]).unwrap();
            assert!(plan.r2k_is_quic_address_plan());
            peer.write_all(&encode_ack(install.kind, true, 0).unwrap())
                .unwrap();
        });
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        let mut catalog = Catalog::default();
        client
            .r2o_install_quic_candidate(
                "198.51.100.90:443".parse().unwrap(),
                "r2o-plan 1 10\nid 00000000000000000000000000000000\nproto udp quic\nquicsplit 1\n",
                "разрез ClientHello по CRYPTO",
                &mut catalog,
                &path,
            )
            .unwrap();

        control_thread.join().unwrap();
        assert!(path.is_file());
        assert!(r2o_controller::discovery::has_usable_quic_address_binding(
            &catalog,
            "198.51.100.90".parse().unwrap(),
        ));
        std::fs::remove_dir_all(work).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn r2o_каталог_восстанавливает_подтверждённую_quic_адресную_привязку() {
        let mut catalog = Catalog::default();
        r2o_controller::discovery::add_confirmed_quic_address_binding(
            &mut catalog,
            "198.51.100.20".parse().unwrap(),
            "r2o-plan 1 10\nid 00000000000000000000000000000000\nproto udp quic\nquicsplit 1\n",
            1_800_000_001,
        )
        .unwrap();

        let compiled = catalog_commands(&catalog).unwrap();
        assert_eq!(compiled.skipped, 0);
        assert_eq!(compiled.commands.len(), 1);
        let command = read_frame(&mut std::io::Cursor::new(&compiled.commands[0].1)).unwrap();
        assert_eq!(command.kind, super::COMMAND_SET_ADDR);
        assert_eq!(command.body[0], 4);
        assert_eq!(&command.body[1..5], &[198, 51, 100, 20]);
        assert_eq!(command.body[17], SHAPE_QUIC);
        let plan = Plan::parse(&command.body[18..]).unwrap();
        assert_eq!(plan.transport, 17);
        assert_eq!(plan.proto, 2);
        assert_eq!(plan.qsplit, 1);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_каталог_восстанавливает_quic_привязки_clearance_и_udplen() {
        let plans = [
            "r2o-plan 1 10\nid 00000000000000000000000000000000\nproto udp quic\npayload 1 00000000000000000000000000000000\nfake payload=1 poison=0 repeats=1 gap_us=0 place=before\n",
            "r2o-plan 1 9\nid 00000000000000000000000000000000\nproto udp quic\nudplen 100\n",
        ];
        for (index, text) in plans.into_iter().enumerate() {
            let address =
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 30 + index as u8));
            let mut catalog = Catalog::default();
            r2o_controller::discovery::add_confirmed_quic_address_binding(
                &mut catalog,
                address,
                text,
                1_800_000_002,
            )
            .unwrap();
            let compiled = catalog_commands(&catalog).unwrap();
            assert_eq!(compiled.skipped, 0);
            assert_eq!(compiled.commands.len(), 1);
            let command = read_frame(&mut std::io::Cursor::new(&compiled.commands[0].1)).unwrap();
            assert_eq!(command.kind, super::COMMAND_SET_ADDR);
            let plan = Plan::parse(&command.body[18..]).unwrap();
            assert!(plan.r2k_is_quic_address_plan());
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejected_http_probe_ack_cleans_up_its_temporary_binding() {
        use std::sync::mpsc;

        let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let probe = read_frame(&mut peer).unwrap();
            assert_eq!(probe.kind, COMMAND_SET_NAME_PROBE);
            peer.write_all(
                &encode_ack_for_trial(COMMAND_SET_NAME_PROBE, true, 0, Some([2; 16])).unwrap(),
            )
            .unwrap();

            let delete = read_frame(&mut peer).unwrap();
            assert_eq!(delete.kind, COMMAND_DEL_NAME_PROBE);
            assert_eq!(&delete.body[1..], b"example.test\x07\x04\xa8\xc1");
            peer.write_all(&encode_ack(COMMAND_DEL_NAME_PROBE, true, 0).unwrap())
                .unwrap();
        });
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        let (reply, response) = mpsc::sync_channel(1);
        let mut catalog = Catalog::default();
        let result = client.service_http_search_command(
            HttpSearchCommand::InstallProbe {
                host: "example.test".to_owned(),
                family: 4,
                port: 0xa8c1,
                command: encode_frame(COMMAND_SET_NAME_PROBE, &[]).unwrap(),
                trial_id: [1; 16],
                reply,
            },
            &mut catalog,
            std::path::Path::new("unused"),
        );

        assert!(result.is_ok());
        assert!(response.recv().unwrap().is_err());
        peer_thread.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn applied_event_backlog_keeps_only_the_newest_256_entries() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        for execution_id in 1..=257 {
            client.remember_applied_event(r2k_core::control::AppliedEvent {
                key: [0; r2k_core::control::KEY_LEN],
                plan_id: [0; 16],
                trial_id: [0; 16],
                execution_id,
                binding: r2k_core::control::BindingContext {
                    generation: 0,
                    kind: 0,
                    family: 0,
                    shape: 0,
                    temporary: false,
                    epoch: [0; 16],
                },
            });
        }

        assert_eq!(client.pending_applied_events.len(), 256);
        assert_eq!(
            client.pending_applied_events.front().unwrap().execution_id,
            2
        );
        assert_eq!(
            client.pending_applied_events.back().unwrap().execution_id,
            257
        );
    }

    #[cfg(unix)]
    #[test]
    fn r2o_quic_applied_collection_keeps_events_for_other_trials() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
        };
        for (trial_id, execution_id) in [([1; 16], 1), ([2; 16], 2)] {
            client.remember_applied_event(r2k_core::control::AppliedEvent {
                key: [0; KEY_LEN],
                plan_id: [0; 16],
                trial_id,
                execution_id,
                binding: r2k_core::control::BindingContext {
                    generation: 0,
                    kind: 0,
                    family: 0,
                    shape: 0,
                    temporary: false,
                    epoch: [0; 16],
                },
            });
        }

        let events = client
            .collect_applied_events([2; 16], std::time::Duration::ZERO)
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].trial_id, [2; 16]);
        assert_eq!(client.pending_applied_events.len(), 1);
        assert_eq!(client.pending_applied_events[0].trial_id, [1; 16]);
    }

    #[cfg(unix)]
    #[test]
    fn http_probe_reuses_a_bound_socket_for_two_complete_responses() {
        use super::{BoundTcpProbe, run_http_trial_socket};
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for _ in 0..2 {
                let mut request = Vec::new();
                let mut byte = [0; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
                std::thread::sleep(std::time::Duration::from_millis(5));
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
            }
        });

        let result = run_http_trial_socket(
            BoundTcpProbe::open(4, Some(0)).unwrap(),
            destination,
            "example.com",
            b"/",
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(result.requests_sent, 2);
        assert_eq!(result.complete_responses, 2);
        assert_eq!(
            result.client,
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_http_candidates_put_the_same_name_first_then_newest_other_names() {
        use r2k_core::control::SHAPE_HTTP;
        use r2o_controller::catalog::Plan as SavedPlan;
        use r2o_controller::discovery::DiscoveryTarget;

        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.20:80".into(),
            family: 4,
            shape: SHAPE_HTTP,
        };
        let rows = [
            ("same-name", "fake:ttl=5+badsum", 100, false, Some(120)),
            ("newer-other", "disorder", 300, true, None),
            ("older-other", "split", 200, true, None),
            ("disabled-other", "fake-seqshift", 400, false, None),
        ];
        let mut plans = Vec::new();
        let mut bindings = Vec::new();
        for (index, (host, key, confirmed, enabled, recheck_since)) in rows.into_iter().enumerate()
        {
            let id = format!("{:02x}", index + 1).repeat(16);
            plans.push(SavedPlan {
                id: id.clone(),
                proto: "http".into(),
                text: r2o_controller::http_search::candidate_text(
                    key,
                    Some(&[index as u8 + 1; 16]),
                )
                .unwrap(),
                enabled: true,
                ..SavedPlan::default()
            });
            bindings.push(Binding {
                kind: "name".into(),
                target: if host == "same-name" {
                    "example.com"
                } else {
                    host
                }
                .into(),
                plan_id: id,
                enabled,
                transport: 6,
                family: 4,
                shape: SHAPE_HTTP,
                verified_by: 1,
                input: 2,
                confirmed,
                recheck_since,
                ..Binding::default()
            });
        }
        let catalog = Catalog {
            boxes: vec![BoxRecord {
                plans,
                bindings,
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };

        assert_eq!(
            saved_http_candidate_keys(&catalog, &target),
            ["fake:ttl=5+badsum", "disorder", "split"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn measured_http_candidates_use_success_rank_and_stop_at_eight() {
        use r2o_controller::catalog::Plan as SavedPlan;

        let plans = (1..=9)
            .map(|ttl| SavedPlan {
                proto: "tls".into(),
                text: format!(
                    "r2o-plan 1 11\nid {}\nproto tcp tls\npoison 1 ttl={ttl} badsum\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\n",
                    format!("{ttl:02x}").repeat(16)
                ),
                enabled: true,
                successes: 10 - ttl,
                ..SavedPlan::default()
            })
            .collect();
        let catalog = Catalog {
            boxes: vec![BoxRecord {
                plans,
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };

        let candidates = measured_http_candidate_keys(&catalog);

        assert_eq!(candidates.len(), 8);
        assert_eq!(candidates[0], "fake:ttl=1+badsum");
        assert!(!candidates.contains(&"fake:ttl=9+badsum".to_owned()));
    }

    #[cfg(unix)]
    #[test]
    fn measured_http_candidates_replace_only_the_generic_sequence_fallback() {
        use r2k_core::control::SHAPE_HTTP;
        use r2o_controller::catalog::Plan as SavedPlan;
        use r2o_controller::discovery::DiscoveryTarget;

        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.20:80".into(),
            family: 4,
            shape: SHAPE_HTTP,
        };
        let catalog = Catalog {
            boxes: vec![BoxRecord {
                plans: vec![SavedPlan {
                    proto: "tls".into(),
                    text: "r2o-plan 1 11\nid 01010101010101010101010101010101\nproto tcp tls\npoison 1 ttl=64 badsum\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\n".into(),
                    enabled: true,
                    successes: 3,
                    ..SavedPlan::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };

        let candidates = http_search_candidates(&catalog, &target);

        assert!(candidates.contains(&"fake:ttl=64+badsum".to_owned()));
        assert!(!candidates.contains(&"fake-seqshift".to_owned()));
        assert!(candidates.contains(&"fake-badsum".to_owned()));
    }

    #[cfg(unix)]
    #[test]
    fn live_http_failures_match_plan_programs_and_fail_closed_when_missing() {
        use r2k_core::control::SHAPE_HTTP;
        use r2o_controller::catalog::Plan as SavedPlan;
        use r2o_controller::discovery::DiscoveryTarget;
        use r2o_controller::http_search::candidate_program;

        let target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.20:80".into(),
            family: 4,
            shape: SHAPE_HTTP,
        };
        let plan_id = "07".repeat(16);
        let plan_text =
            r2o_controller::http_search::candidate_text("fake:badsum", Some(&[7; 16])).unwrap();
        let failed_binding = Binding {
            kind: "name".into(),
            target: target.host.clone(),
            plan_id: plan_id.clone(),
            enabled: false,
            transport: 6,
            family: 4,
            shape: SHAPE_HTTP,
            verified_by: 1,
            input: 2,
            recheck_since: Some(100),
            ..Binding::default()
        };
        let catalog = Catalog {
            boxes: vec![BoxRecord {
                plans: vec![SavedPlan {
                    id: plan_id,
                    proto: "http".into(),
                    text: plan_text,
                    enabled: true,
                    ..SavedPlan::default()
                }],
                bindings: vec![failed_binding.clone()],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };

        let failures = failed_http_programs(&catalog, &target);
        assert!(!failures.evidence_lost);
        assert_eq!(failures.programs.len(), 1);
        assert_eq!(
            failures.programs[0],
            candidate_program("fake-badsum").unwrap()
        );

        let missing_plan = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![failed_binding],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        assert!(failed_http_programs(&missing_plan, &target).evidence_lost);
        assert_eq!(HttpLiveFailures::default().programs.len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn http_search_worker_runs_queued_jobs_outside_the_control_loop() {
        let worker = HttpSearchWorker::new(
            r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(4),
        );
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "invalid-endpoint".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_HTTP,
        };
        assert!(worker.queue(HttpSearchTask {
            target: target.clone(),
            request_path: b"/".to_vec(),
            expected_baseline: r2o_controller::http_search::Answer::Injected,
            candidates: Vec::new(),
            live_failures: HttpLiveFailures::default(),
            mark: None,
        }));

        let outcome = worker
            .outcomes
            .as_ref()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(outcome.target, target);
        assert!(outcome.result.is_err());
    }

    #[test]
    fn classify_options_accept_save_plan_with_existing_arguments() {
        let args = ["4", "--allow-loopback", "--save-plan", "out.r2op"].map(OsString::from);
        assert_eq!(
            parse_classify_options(&args).unwrap(),
            ClassifyCliOptions {
                repeats: 4,
                allow_loopback: true,
                mark: None,
                save_plan_path: Some(PathBuf::from("out.r2op")),
                arm_socket_path: None,
                modern: false,
            }
        );
    }

    #[test]
    fn classify_options_accept_direct_arm_socket() {
        let args =
            ["--arm", "/run/r2o-datapath.sock", "--save-plan", "out.r2op"].map(OsString::from);
        assert_eq!(
            parse_classify_options(&args).unwrap(),
            ClassifyCliOptions {
                repeats: 3,
                allow_loopback: false,
                mark: None,
                save_plan_path: Some(PathBuf::from("out.r2op")),
                arm_socket_path: Some(PathBuf::from("/run/r2o-datapath.sock")),
                modern: false,
            }
        );
    }

    #[test]
    fn classify_options_accept_modern_profile() {
        let args = ["--modern"].map(OsString::from);
        assert!(parse_classify_options(&args).unwrap().modern);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_queue_promotes_repeated_suspicions_and_keeps_fifo() {
        fn target(host: &str) -> r2o_controller::discovery::DiscoveryTarget {
            r2o_controller::discovery::DiscoveryTarget {
                host: host.into(),
                endpoint: "127.0.0.1:443".into(),
                family: 4,
                shape: SHAPE_MODERN,
            }
        }

        let first = target("first.example");
        let second = target("second.example");
        let third = target("third.example");
        let mut queue = super::R2oDiscoveryQueue::default();
        let now = std::time::Instant::now();

        assert!(queue.enqueue(first.clone(), now));
        assert!(queue.enqueue(second.clone(), now));
        assert!(queue.enqueue(third.clone(), now));
        assert!(queue.promote(&first));
        assert!(queue.promote(&third));

        assert_eq!(queue.pop(now), (Vec::new(), Some(third)));
        assert_eq!(queue.pop(now), (Vec::new(), Some(first.clone())));
        assert!(!queue.promote(&first));
        assert_eq!(queue.pop(now), (Vec::new(), Some(second)));
        assert_eq!(queue.pop(now), (Vec::new(), None));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_queue_matches_donor_capacity() {
        let mut queue = super::R2oDiscoveryQueue::default();
        let now = std::time::Instant::now();
        for index in 0..super::R2O_DISCOVERY_QUEUE_CAPACITY {
            let target = r2o_controller::discovery::DiscoveryTarget {
                host: format!("target-{index}.example"),
                endpoint: "127.0.0.1:443".into(),
                family: 4,
                shape: SHAPE_MODERN,
            };
            assert!(queue.enqueue(target, now));
        }
        let extra = r2o_controller::discovery::DiscoveryTarget {
            host: "overflow.example".into(),
            endpoint: "127.0.0.1:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };

        assert!(!queue.enqueue(extra, now));
        assert_eq!(queue.entries.len(), 64);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_queued_target_expires_only_after_ten_minutes() {
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "expired.example".into(),
            endpoint: "127.0.0.1:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let queued_at = std::time::Instant::now();
        let mut queue = super::R2oDiscoveryQueue::default();

        assert!(queue.enqueue(target.clone(), queued_at));
        assert!(queue.promote(&target));
        assert!(
            queue
                .r2o_expire(queued_at + std::time::Duration::from_secs(600))
                .is_empty()
        );
        assert_eq!(
            queue.r2o_expire(
                queued_at
                    + std::time::Duration::from_secs(600)
                    + std::time::Duration::from_nanos(1)
            ),
            vec![target]
        );
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_expiration_releases_target_and_keeps_worker_alive() {
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let permit = gate.r2o_try_acquire().unwrap();
        let mut worker = super::DiscoveryWorker::new(None, gate);
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "expired.example".into(),
            endpoint: "invalid-endpoint".into(),
            family: 4,
            shape: 0,
        };
        let expired_after = std::time::Instant::now() + std::time::Duration::from_secs(601);
        assert!(worker.queue(target.clone()));

        let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let waiting = worker
                .jobs
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .waiting_for_slot;
            if waiting {
                break;
            }
            assert!(std::time::Instant::now() < wait_deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        assert_eq!(
            worker.r2o_expire_queued(expired_after),
            vec![target.clone()]
        );
        assert!(!worker.is_active(&target));
        drop(permit);

        let idle_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let waiting = worker
                .jobs
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .waiting_for_slot;
            if !waiting {
                assert!(!worker.thread.as_ref().unwrap().is_finished());
                break;
            }
            assert!(std::time::Instant::now() < idle_deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        assert!(worker.queue(target.clone()));
        let outcome = worker
            .outcomes
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(outcome.target, target);
    }

    #[cfg(unix)]
    #[test]
    fn discovery_worker_tracks_accepted_target_as_active() {
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "127.0.0.1:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let mut worker = super::DiscoveryWorker::new(
            None,
            r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(4),
        );

        assert!(worker.queue(target.clone()));
        assert!(worker.is_active(&target));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_worker_keeps_waiting_targets_promotable() {
        fn target(host: &str) -> r2o_controller::discovery::DiscoveryTarget {
            r2o_controller::discovery::DiscoveryTarget {
                host: host.into(),
                endpoint: "invalid-endpoint".into(),
                family: 4,
                shape: 0,
            }
        }

        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(2);
        let first_permit = gate.r2o_try_acquire().unwrap();
        let second_permit = gate.r2o_try_acquire().unwrap();
        let mut worker = super::DiscoveryWorker::new(None, gate);
        let first = target("first.example");
        let second = target("second.example");
        let third = target("third.example");

        assert!(worker.queue(first.clone()));
        assert!(worker.queue(second));
        assert!(worker.queue(third.clone()));
        let waiting_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let waiting = worker
                .jobs
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .waiting_for_slot;
            if waiting {
                break;
            }
            assert!(std::time::Instant::now() < waiting_deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        assert!(worker.queue(first.clone()));
        assert!(worker.queue(third.clone()));
        drop(first_permit);
        drop(second_permit);

        let outcome_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let outcome = loop {
            if let Some(outcome) = worker.try_outcome() {
                break outcome;
            }
            assert!(std::time::Instant::now() < outcome_deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        assert_eq!(outcome.target, third);
    }

    #[cfg(unix)]
    #[test]
    fn failed_discovery_becomes_eligible_after_the_donor_rest_period() {
        let failed_at = std::time::Instant::now();

        assert!(!r2o_discovery_failure_retry_due(
            failed_at,
            failed_at + std::time::Duration::from_secs(119)
        ));
        assert!(r2o_discovery_failure_retry_due(
            failed_at,
            failed_at + std::time::Duration::from_secs(120)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn discovery_persists_only_after_datapath_ack_and_rolls_back_on_rejection() {
        fn run_case(accept: bool) -> (bool, Catalog, Vec<u8>) {
            let work = std::env::temp_dir().join(format!(
                "r2o-discovery-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&work).unwrap();
            let socket_path = work.join("control.sock");
            let catalog_path = work.join("catalog.json");
            let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream.write_all(&encode_greeting(65_535).unwrap()).unwrap();
                let clear = read_frame(&mut stream).unwrap();
                assert_eq!(clear.kind, super::COMMAND_CLEAR);
                assert!(clear.body.is_empty());
                stream
                    .write_all(&encode_ack(clear.kind, true, 0).unwrap())
                    .unwrap();

                let command = read_frame(&mut stream).unwrap();
                assert_eq!(command.kind, COMMAND_SET_NAME);
                let ack = encode_ack(command.kind, accept, if accept { 0 } else { 1 }).unwrap();
                stream.write_all(&ack).unwrap();
                if !accept {
                    for _ in 0..2 {
                        let clear = read_frame(&mut stream).unwrap();
                        assert_eq!(clear.kind, super::COMMAND_CLEAR);
                        assert!(clear.body.is_empty());
                        stream
                            .write_all(&encode_ack(clear.kind, true, 0).unwrap())
                            .unwrap();
                    }
                }
                (command.kind, command.body)
            });

            let mut client = super::ControlClient::connect(socket_path).unwrap();
            let target = r2o_controller::discovery::DiscoveryTarget {
                host: "example.com".into(),
                endpoint: "127.0.0.1:443".into(),
                family: 4,
                shape: SHAPE_MODERN,
            };
            let trigger = r2o_controller::classify::Trigger::tls13("example.com").unwrap();
            let poison = r2o_controller::classify::Poison {
                name: "badsum".into(),
                badsum: true,
                ..r2o_controller::classify::Poison::default()
            };
            let plan_text =
                r2o_controller::classify::plan_text_for_poison(&poison, &trigger, None, 0).unwrap();
            let mut catalog = Catalog::default();
            let outcome = DiscoveryOutcome {
                target: target.clone(),
                plan_text: Some(plan_text),
                detail: "test".into(),
                queue_expired: false,
            };
            let result = client.apply_discovery_outcome(outcome, &mut catalog, &catalog_path);
            let (kind, body) = server.join().unwrap();
            assert_eq!(kind, COMMAND_SET_NAME);
            let persisted = Catalog::load(&catalog_path).unwrap();
            std::fs::remove_dir_all(work).unwrap();
            (result.is_ok(), persisted, body)
        }

        let (accepted, saved, body) = run_case(true);
        assert!(accepted);
        assert!(r2o_controller::discovery::has_usable_binding(
            &saved,
            &r2o_controller::discovery::DiscoveryTarget {
                host: "example.com".into(),
                endpoint: "127.0.0.1:443".into(),
                family: 4,
                shape: SHAPE_MODERN,
            }
        ));
        let name_len = usize::from(body[0]);
        assert_eq!(&body[1..1 + name_len], b"example.com");
        assert_eq!(body[1 + name_len], SHAPE_MODERN);
        assert_eq!(Plan::parse(&body[3 + name_len..]).unwrap().proto, 1);

        let (accepted, saved, _) = run_case(false);
        assert!(!accepted);
        assert!(saved.boxes.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_family_controllers_merge_catalog_updates_under_lock() {
        let work = std::env::temp_dir().join(format!(
            "r2o-catalog-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&work).unwrap();
        let path = work.join("catalog.json");
        Catalog::default().save_atomic(&path, 0).unwrap();

        let workers = ["ipv4", "ipv6"].map(|id| {
            let path = path.clone();
            std::thread::spawn(move || {
                let fallback = Catalog::default();
                let (_lock, mut current) = locked_catalog(&path, &fallback).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(20));
                current.boxes.push(BoxRecord {
                    id: id.into(),
                    ..BoxRecord::default()
                });
                current.save_atomic(&path, 0).unwrap();
            })
        });
        for worker in workers {
            worker.join().unwrap();
        }

        let saved = Catalog::load(&path).unwrap();
        assert_eq!(
            saved
                .boxes
                .iter()
                .map(|record| record.id.as_str())
                .collect::<std::collections::HashSet<_>>(),
            std::collections::HashSet::from(["ipv4", "ipv6"])
        );
        std::fs::remove_dir_all(work).unwrap();
    }

    #[test]
    fn classify_options_reject_zero_repeats_and_missing_plan_path() {
        assert!(parse_classify_options(&[OsString::from("0")]).is_err());
        assert!(parse_classify_options(&[OsString::from("--save-plan")]).is_err());
        assert!(parse_classify_options(&[OsString::from("--arm")]).is_err());
    }

    #[test]
    fn classify_and_serve_accept_the_datapath_bypass_mark() {
        let classify = parse_classify_options(&[
            OsString::from("--mark"),
            OsString::from("77"),
            OsString::from("--modern"),
        ])
        .unwrap();
        assert_eq!(classify.mark, Some(77));

        let serve = parse_serve_options(&[
            OsString::from("--discover"),
            OsString::from("--mark"),
            OsString::from("77"),
        ])
        .unwrap();
        assert_eq!(
            serve,
            ServeCliOptions {
                discover: true,
                mark: Some(77)
            }
        );
    }

    #[test]
    fn saved_plan_file_is_created_without_overwriting_existing_data() {
        let path = std::env::temp_dir().join(format!(
            "r2o-classify-{}-{}.r2op",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        save_plan_file(&path, b"R2OP-test").unwrap();
        assert!(save_plan_file(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"R2OP-test");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn discord_voice_class_binding_accepts_only_udp_voice_plans() {
        let voice = parse_plan(&[17, 3]);
        let tcp = parse_plan(&[6, 1]);
        assert!(shape_matches_plan(SHAPE_VOICE, &voice));
        assert!(!shape_matches_plan(SHAPE_VOICE, &tcp));
        assert!(!shape_matches_plan(SHAPE_MODERN, &voice));
    }

    #[test]
    fn r2o_quic_форма_принимает_только_поддерживаемые_планы() {
        let qsplit = Plan::parse(
            &r2o_controller::plan_text::compile_text(
                "r2o-plan 1 10\nproto udp quic\nquicsplit 1\n",
            )
            .unwrap(),
        )
        .unwrap();
        let qdeny = Plan::parse(
            &r2o_controller::plan_text::compile_text("r2o-plan 1 11\nproto udp quic\nquicdeny 1\n")
                .unwrap(),
        )
        .unwrap();
        let clearance = Plan::parse(
            &r2o_controller::plan_text::compile_text(
                "r2o-plan 1 10\nproto udp quic\npayload 1 00000000000000000000000000000000\nfake payload=1 poison=0 repeats=1 gap_us=0 place=before\n",
            )
            .unwrap(),
        )
        .unwrap();
        let udp_length = Plan::parse(
            &r2o_controller::plan_text::compile_text("r2o-plan 1 9\nproto udp quic\nudplen 100\n")
                .unwrap(),
        )
        .unwrap();
        let ttl_payload = r2k_core::plan::R2K_QUIC_TTL_PROBE_PAYLOAD
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let ttl_probe = Plan::parse(
            &r2o_controller::plan_text::compile_text(&format!(
                "r2o-plan 1 10\nproto udp quic\npayload 1 {ttl_payload}\npoison 1 ttl=3\nfake payload=1 poison=1 repeats=2 gap_us=0 place=before\n"
            ))
            .unwrap(),
        )
        .unwrap();
        let voice = parse_plan(&[17, 3]);

        assert!(shape_matches_plan(SHAPE_QUIC, &qsplit));
        assert!(shape_matches_plan(SHAPE_QUIC, &qdeny));
        assert!(shape_matches_plan(SHAPE_QUIC, &clearance));
        assert!(shape_matches_plan(SHAPE_QUIC, &udp_length));
        assert!(shape_matches_plan(SHAPE_QUIC, &ttl_probe));
        assert!(r2o_datapath::engine::validate_runtime_plan(&clearance).is_ok());
        assert!(r2o_datapath::engine::validate_runtime_plan(&udp_length).is_ok());
        assert!(r2o_datapath::engine::validate_runtime_plan(&ttl_probe).is_ok());
        assert!(!shape_matches_plan(SHAPE_QUIC, &voice));
        assert!(binding_shape_transport(SHAPE_QUIC, 17));
        assert!(!binding_shape_transport(SHAPE_QUIC, 6));
    }

    #[cfg(unix)]
    #[test]
    fn новое_имя_с_планом_обученной_группы_не_ставится_в_очередь_поиска() {
        let catalog = Catalog::parse(
            br#"{"boxes":[{"id":"box-1","created":"2026-10-18T00:00:00Z","updated":"2026-10-18T00:00:00Z","plans":[{"id":"plan-1","proto":"tls","text":"r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +0\n","added":"2026-10-18T00:00:00Z","successes":3,"enabled":true}],"bindings":[]}],"domain_observations":[{"name":"a.googlevideo.com","plan_id":"plan-1","transport":6,"family":4,"shape":1,"evidence":1,"at":"2026-10-18T00:00:00Z"},{"name":"b.googlevideo.com","plan_id":"plan-1","transport":6,"family":4,"shape":1,"evidence":1,"at":"2026-10-18T00:01:00Z"},{"name":"c.googlevideo.com","plan_id":"plan-1","transport":6,"family":4,"shape":1,"evidence":1,"at":"2026-10-18T00:02:00Z"}]}"#,
        )
        .unwrap();
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "new.googlevideo.com".into(),
            endpoint: "203.0.113.1:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };

        let group = matching_domain_group(&catalog, &target).unwrap();
        assert_eq!(group.suffix, "googlevideo.com");
        assert_eq!(group.plan_id, "plan-1");
        assert!(
            matching_domain_group(
                &catalog,
                &r2o_controller::discovery::DiscoveryTarget {
                    host: "evilgooglevideo.com".into(),
                    ..target
                }
            )
            .is_none()
        );
    }

    #[test]
    fn discord_voice_class_name_is_reserved_to_voice_shape() {
        assert_eq!(
            normalize_plan_target("@discord-voice", SHAPE_VOICE).unwrap(),
            "@discord-voice"
        );
        assert!(normalize_plan_target("@discord-voice", SHAPE_MODERN).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn подтверждение_voice_игнорирует_клиентский_порт_но_сверяет_серверную_точку() {
        let target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: "192.0.2.10".parse().unwrap(),
            server: "198.51.100.20:50004".parse().unwrap(),
        };
        let mut key = [0; r2k_core::control::KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 20]);
        key[33..35].copy_from_slice(&51_234_u16.to_be_bytes());
        key[35..37].copy_from_slice(&50_004_u16.to_be_bytes());
        key[37] = 17;
        let mut proof = r2k_core::control::R2oVoiceProofEvent {
            key,
            trial_id: [0x44; 16],
            mapped_ip: "203.0.113.9".parse().unwrap(),
            mapped_port: 52_321,
        };
        assert!(r2o_voice_proof_matches_target(&proof, target));

        proof.key[35..37].copy_from_slice(&50_005_u16.to_be_bytes());
        assert!(!r2o_voice_proof_matches_target(&proof, target));
    }

    #[cfg(unix)]
    #[test]
    fn каталог_собирает_подтверждённую_адресную_voice_привязку() {
        let prefix = r2k_core::stun::binding_request([0x35; 12]);
        let text = r2o_controller::voice_discovery::r2o_voice_arm_plan_text(&prefix);
        let mut catalog = Catalog::default();
        r2o_controller::voice_discovery::r2o_save_confirmed_voice_binding(
            &mut catalog,
            "198.51.100.21".parse().unwrap(),
            &text,
            1_800_000_001,
        )
        .unwrap();

        let compiled = catalog_commands(&catalog).unwrap();
        assert_eq!(compiled.skipped, 0);
        assert_eq!(compiled.commands.len(), 1);
        let command = read_frame(&mut std::io::Cursor::new(&compiled.commands[0].1)).unwrap();
        assert_eq!(command.kind, COMMAND_SET_VOICE_ADDR);
        assert_eq!(&command.body[..4], &[198, 51, 100, 21]);
        let plan = Plan::parse(&command.body[4..]).unwrap();
        assert_eq!(plan.transport, 17);
        assert_eq!(plan.proto, r2k_core::plan::PROTO_VOICE);
    }

    #[cfg(unix)]
    #[test]
    fn временный_voice_опыт_становится_постоянным_только_после_ack_датапата() {
        use std::io::Write;

        let directory = std::env::temp_dir().join(format!(
            "r2o-voice-proof-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let socket_path = directory.join("control.sock");
        let catalog_path = directory.join("catalog.json");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        Catalog::default().save_atomic(&catalog_path, now).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let trial_id = [0x69; 16];
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .write_all(&encode_greeting(u16::MAX as u32).unwrap())
                .unwrap();
            let permanent = read_frame(&mut stream).unwrap();
            stream
                .write_all(&encode_ack(permanent.kind, true, 0).unwrap())
                .unwrap();
            let remove = read_frame(&mut stream).unwrap();
            stream
                .write_all(&encode_ack_for_trial(remove.kind, true, 0, Some(trial_id)).unwrap())
                .unwrap();
            (permanent.kind, permanent.body, remove.kind, remove.body)
        });

        let target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: "192.0.2.10".parse().unwrap(),
            server: "198.51.100.20:50004".parse().unwrap(),
        };
        let prefix = r2k_core::stun::binding_request([0x36; 12]);
        let trial = R2oVoiceTrialContext {
            target,
            trial_id,
            plan_text: r2o_controller::voice_discovery::r2o_voice_arm_plan_text(&prefix),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(120),
        };
        let mut key = [0; r2k_core::control::KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 20]);
        key[33..35].copy_from_slice(&51_234_u16.to_be_bytes());
        key[35..37].copy_from_slice(&50_004_u16.to_be_bytes());
        key[37] = 17;
        let proof = r2k_core::control::R2oVoiceProofEvent {
            key,
            trial_id,
            mapped_ip: "203.0.113.10".parse().unwrap(),
            mapped_port: 52_322,
        };
        let mut client = ControlClient::connect(socket_path).unwrap();
        let mut catalog = Catalog::load(&catalog_path).unwrap();
        client
            .confirm_r2o_voice_trial(trial, &proof, &mut catalog, &catalog_path)
            .unwrap();

        let (permanent_kind, permanent_body, remove_kind, remove_body) = server.join().unwrap();
        assert_eq!(permanent_kind, COMMAND_SET_VOICE_ADDR);
        assert_eq!(&permanent_body[..4], &[198, 51, 100, 20]);
        assert_eq!(remove_kind, COMMAND_DEL_VOICE_ADDR_PROBE);
        assert_eq!(&remove_body[..4], &[192, 0, 2, 10]);
        assert_eq!(&remove_body[4..8], &[198, 51, 100, 20]);
        assert_eq!(&remove_body[8..10], &50_004_u16.to_be_bytes());
        assert_eq!(&remove_body[10..], &trial_id);
        let saved = Catalog::load(&catalog_path).unwrap();
        assert_eq!(saved.boxes[0].bindings[0].verified_by, 4);
        assert_eq!(saved.boxes[0].bindings[0].target, "198.51.100.20");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn повторный_discovery_endpoint_допускается_после_двухминутного_отдыха() {
        use super::R2oVoiceDiscoverySeen;
        use std::net::{Ipv4Addr, SocketAddrV4};
        use std::time::{Duration, Instant};

        let r2o_target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: Ipv4Addr::new(192, 0, 2, 10),
            server: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 50_004),
        };
        let r2o_now = Instant::now();
        let mut r2o_seen = R2oVoiceDiscoverySeen::default();

        r2o_seen.r2o_insert(r2o_target, r2o_now);

        assert!(r2o_seen.r2o_contains(&r2o_target, r2o_now + Duration::from_secs(119)));
        assert!(!r2o_seen.r2o_contains(&r2o_target, r2o_now + Duration::from_secs(120)));
    }

    #[cfg(unix)]
    #[test]
    fn очередь_voice_оставляет_последний_endpoint_и_ждёт_исхода_опыта() {
        use super::{R2oVoiceDiscoveryJob, R2oVoiceLatestQueue};
        use std::net::{Ipv4Addr, SocketAddrV4};

        let r2o_client = Ipv4Addr::new(192, 0, 2, 10);
        let r2o_first = R2oVoiceDiscoveryJob {
            target: r2o_controller::voice_discovery::R2oVoiceTarget {
                client: r2o_client,
                server: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 50_004),
            },
            known_prefix: Some([1; 20]),
        };
        let r2o_middle = R2oVoiceDiscoveryJob {
            target: r2o_controller::voice_discovery::R2oVoiceTarget {
                client: r2o_client,
                server: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 21), 50_005),
            },
            known_prefix: None,
        };
        let r2o_latest = R2oVoiceDiscoveryJob {
            target: r2o_controller::voice_discovery::R2oVoiceTarget {
                client: r2o_client,
                server: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 22), 50_006),
            },
            known_prefix: Some([2; 20]),
        };
        let mut r2o_queue = R2oVoiceLatestQueue::default();

        assert_eq!(
            r2o_queue.offer(r2o_first.clone(), true),
            Some(r2o_first.clone())
        );
        assert_eq!(r2o_queue.offer(r2o_middle, true), None);
        assert_eq!(r2o_queue.offer(r2o_latest.clone(), true), None);
        assert_eq!(r2o_queue.take_pending_if_idle(true), None);
        assert!(r2o_queue.complete(&r2o_first.target));
        assert_eq!(r2o_queue.take_pending_if_idle(false), None);
        assert_eq!(
            r2o_queue.take_pending_if_idle(true),
            Some(r2o_latest.clone())
        );
        assert_eq!(r2o_queue.current.as_ref(), Some(&r2o_latest));
    }

    #[cfg(unix)]
    #[test]
    fn истёкшие_voice_пробы_отделяются_от_действующих() {
        use super::{R2oVoiceTrialContext, r2o_take_expired_voice_trials};
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

        let r2o_now = Instant::now();
        let r2o_target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: "192.0.2.10".parse().unwrap(),
            server: "198.51.100.20:50004".parse().unwrap(),
        };
        let mut r2o_trials = HashMap::from([
            (
                [1; 16],
                R2oVoiceTrialContext {
                    target: r2o_target,
                    trial_id: [1; 16],
                    plan_text: String::new(),
                    expires_at: r2o_now - Duration::from_secs(1),
                },
            ),
            (
                [2; 16],
                R2oVoiceTrialContext {
                    target: r2o_target,
                    trial_id: [2; 16],
                    plan_text: String::new(),
                    expires_at: r2o_now + Duration::from_secs(1),
                },
            ),
        ]);

        let r2o_expired = r2o_take_expired_voice_trials(&mut r2o_trials, r2o_now);

        assert_eq!(r2o_expired.len(), 1);
        assert_eq!(r2o_expired[0].trial_id, [1; 16]);
        assert_eq!(
            r2o_trials.keys().copied().collect::<Vec<_>>(),
            vec![[2; 16]]
        );
    }

    fn parse_plan(proto: &[u8; 2]) -> Plan {
        let mut bytes = PLAN_MAGIC.to_vec();
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]);
        bytes.extend_from_slice(&[0, 2, 0, 2]);
        bytes.extend_from_slice(proto);
        Plan::parse(&bytes).unwrap()
    }
}
