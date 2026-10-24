use r2k_core::control::{
    self, ADDR_PROBE_LEASE_MAX_MS, COMMAND_ARM_SHAPE, COMMAND_CLEAR, COMMAND_DEL_ADDR,
    COMMAND_DEL_ADDR_PROBE, COMMAND_DEL_NAME, COMMAND_DEL_VOICE_ADDR_PROBE, COMMAND_SET_ADDR,
    COMMAND_SET_ADDR_PROBE, COMMAND_SET_HTTPS, COMMAND_SET_NAME, COMMAND_SET_TCP_STALL_BUDGETS,
    COMMAND_SET_VOICE_ADDR, COMMAND_SET_VOICE_ADDR_PROBE, EVENT_APPLIED, EVENT_CLIENT_SHAPE,
    EVENT_HELLO, EVENT_HTTP_PORTAL, EVENT_HTTP_RESPONSE, EVENT_PROTOCOL, EVENT_R2O_JOURNAL_END,
    EVENT_R2O_JOURNAL_ENTRY, EVENT_R2O_QUIC_STALL, EVENT_R2O_QUIC_SUSPECT,
    EVENT_R2O_TCP_CLEAN_HANDSHAKE, EVENT_R2O_TCP_EARLY_RST, EVENT_R2O_TCP_EXCHANGE,
    EVENT_R2O_TCP_FIN_RETRY, EVENT_R2O_TCP_REPEAT, EVENT_R2O_TCP_RST_AFTER_APP,
    EVENT_R2O_TCP_RST_CUT, EVENT_R2O_TCP_SILENT, EVENT_R2O_TCP_STALL, EVENT_R2O_VOICE_PROOF,
    EVENT_R2O_VOICE_RTP_PROOF, EVENT_R2O_VOICE_STUN_PROOF, EVENT_R2O_VOICE_SUSPECT, EVENT_REFUSED,
    Frame, HelloEvent, PROTOCOL_VERSION, RELEASE_ID, SHAPE_ECH_TCP, SHAPE_HTTP, SHAPE_LEGACY,
    SHAPE_MODERN, SHAPE_QUIC, SHAPE_VOICE, VOICE_ADDR_PROBE_LEASE_MAX_MS, decode_ack,
    decode_applied, decode_client_shape, decode_greeting, decode_hello, decode_http_portal,
    decode_http_response, decode_r2o_quic_stall, decode_r2o_quic_suspect,
    decode_r2o_tcp_clean_handshake, decode_r2o_tcp_early_rst, decode_r2o_tcp_exchange,
    decode_r2o_tcp_fin_retry, decode_r2o_tcp_repeat, decode_r2o_tcp_rst_after_app,
    decode_r2o_tcp_rst_cut_signal, decode_r2o_tcp_silence, decode_r2o_tcp_stall,
    decode_r2o_voice_proof, decode_r2o_voice_suspect, decode_refused, encode_arm_shape,
    encode_delete_addr, encode_delete_addr_probe, encode_delete_name, encode_delete_name_probe,
    encode_delete_voice_addr_probe, encode_frame, encode_set_addr, encode_set_addr_probe,
    encode_set_bypass, encode_set_https, encode_set_name, encode_set_name_probe, encode_set_suffix,
    encode_set_tcp_stall_budgets, encode_set_voice_addr, encode_set_voice_addr_probe, read_frame,
};
use r2k_core::plan::{PROTO_HTTP, PROTO_VOICE, Plan};
use r2o_controller::ask::{
    ASK_WAIT, AskCliOptions, AskControlInput, AskQuestion, AskSnapshotInput, compose_plan_texts,
    hello_shape, hello_sni, parse_ask_options, question_plan, read_hex_file,
    record_question_passed, validate_hello,
};
use r2o_controller::catalog::{Catalog, DomainObservation, GroupKey};
use r2o_controller::classify::{Accept, ClassifyOptions, Trigger, Verdict, run as classify_run};
use r2o_controller::domain::normalize;
use r2o_controller::http_search::{
    candidate_key_from_plan_text, candidate_keys, candidate_program, candidate_text,
    measured_poison_keys, stable_id,
};
use r2o_controller::https_probe::{
    HttpsProbeWorker, target_from_http_response, target_from_portal,
};
use r2o_controller::plan_text::compile_text;
#[cfg(unix)]
use r2o_controller::r2o_late_rx::{R2oLateRxCache, R2oLateRxInput};
#[cfg(unix)]
use r2o_controller::r2o_quic_deny::R2oQuicDenyCache;
use r2o_controller::response::{ResponseOptions, ResponseVerdict, probe_response};
#[cfg(unix)]
use r2o_controller::voice_measure::{
    R2oVoiceMeasurement, R2oVoiceOptions, R2oVoiceVerdict, r2o_measure_voice_for_flow,
};
use r2o_controller::voice_measure::{
    r2o_format_voice_measurement, r2o_measure_voice, r2o_parse_voice_options,
};
use r2o_controller::voice_targets::{r2o_format_voice_targets, r2o_read_voice_targets};
use std::error::Error;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::collections::{HashMap, HashSet, VecDeque};

#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
const HTTP_SEARCH_BASE_RETRIES: u8 = 1;
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
const R2O_QUIC_DISCOVERY_FOUND_COOLDOWN: std::time::Duration =
    std::time::Duration::from_secs(60 * 60);
#[cfg(unix)]
const R2O_QUIC_DISCOVERY_INCONCLUSIVE_COOLDOWN: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);
#[cfg(unix)]
const R2O_QUIC_DISCOVERY_FAILURE_COOLDOWN: std::time::Duration =
    std::time::Duration::from_secs(2 * 60);

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
    let r2o_arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if let Some(r2o_code) = r2o_ask_command(&r2o_arguments) {
        if r2o_code != 0 {
            std::process::exit(r2o_code);
        }
        return;
    }
    if let Some(r2o_code) = r2o_voice_check_command(&r2o_arguments) {
        if r2o_code != 0 {
            std::process::exit(r2o_code);
        }
        return;
    }
    if let Some(r2o_code) = r2o_voice_list_command(&r2o_arguments) {
        if r2o_code != 0 {
            std::process::exit(r2o_code);
        }
        return;
    }
    if let Err(error) = run(r2o_arguments) {
        eprintln!("r2o-controller: {error}");
        std::process::exit(1);
    }
}

fn r2o_ask_command(arguments: &[std::ffi::OsString]) -> Option<i32> {
    if arguments.first().is_none_or(|argument| argument != "--ask") {
        return None;
    }
    if matches!(arguments, [command, help] if command == "--ask" && (help == "--help" || help == "-h"))
    {
        println!("{}", r2o_controller::ask::ask_help());
        return Some(0);
    }
    let options = match parse_ask_options(&arguments[1..]) {
        Ok(options) => options,
        Err(error) => {
            eprintln!(
                "r2o-controller: {error}\n{}",
                r2o_controller::ask::ask_help()
            );
            return Some(2);
        }
    };
    #[cfg(unix)]
    {
        match run_r2o_ask(options) {
            Ok(code) => Some(code),
            Err(error) => {
                eprintln!("r2o-controller --ask: {error}");
                Some(1)
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = options;
        eprintln!("r2o-controller --ask поддерживается только на Unix");
        Some(1)
    }
}

#[cfg(unix)]
fn run_r2o_ask(options: AskCliOptions) -> Result<i32, Box<dyn Error>> {
    use std::io::Write;

    let mut trigger_bytes = match &options.trigger {
        AskSnapshotInput::File(path) => Some(
            read_hex_file(path)
                .map_err(|error| format!("--hello-hex {}: {error}", path.display()))?,
        ),
        AskSnapshotInput::Capture => None,
    };
    if let Some(bytes) = &trigger_bytes {
        validate_hello(bytes, &options.sni)
            .map_err(|error| format!("ClientHello цели: {error}"))?;
    }

    let mut control_bytes = match &options.control {
        Some(AskControlInput::File(path)) => Some(
            read_hex_file(path)
                .map_err(|error| format!("--control-hex {}: {error}", path.display()))?,
        ),
        _ => None,
    };
    if let Some(bytes) = &control_bytes {
        let control_sni =
            hello_sni(bytes).map_err(|error| format!("control ClientHello: {error}"))?;
        validate_hello(bytes, &control_sni)
            .map_err(|error| format!("control ClientHello: {error}"))?;
    }

    let family = if options.target_ip.is_ipv4() { 4 } else { 6 };
    let destination = std::net::SocketAddr::new(options.target_ip, options.port);
    let mut client = ControlClient::connect(options.control_path.clone())?;
    let mut trigger_timed_out = false;
    if trigger_bytes.is_none() {
        client.arm_client_shape(&options.sni, family)?;
        trigger_bytes = client
            .wait_for_client_shape(&options.sni, family, options.arm_wait.unwrap_or(ASK_WAIT))?
            .map(|event| event.client_hello);
        trigger_timed_out = trigger_bytes.is_none();
    }

    let mut control_timed_out = false;
    if let Some(AskControlInput::Capture(control_sni)) = &options.control {
        client.arm_client_shape(control_sni, family)?;
        control_bytes = client
            .wait_for_client_shape(control_sni, family, options.arm_wait.unwrap_or(ASK_WAIT))?
            .map(|event| event.client_hello);
        control_timed_out = control_bytes.is_none();
    }

    if let Some(bytes) = &trigger_bytes {
        validate_hello(bytes, &options.sni)
            .map_err(|error| format!("снимок ClientHello цели: {error}"))?;
        if let Some(path) = &options.save_trigger {
            save_ask_snapshot(path, "триггера", &options.sni, bytes);
        }
    }
    if let Some(bytes) = &control_bytes {
        let control_sni = match &options.control {
            Some(AskControlInput::Capture(name)) => name.clone(),
            _ => hello_sni(bytes).map_err(|error| format!("control ClientHello: {error}"))?,
        };
        validate_hello(bytes, &control_sni)
            .map_err(|error| format!("control ClientHello: {error}"))?;
        if let Some(path) = &options.save_control {
            save_ask_snapshot(path, "control", &control_sni, bytes);
        }
    }

    println!("цель: {}:{}", options.target_ip, options.port);
    println!("имя (--sni): {}", options.sni);
    println!("управляющий сокет: {}", options.control_path.display());
    println!(
        "метка (--mark): 0x{:x}; зонд отправляется без метки",
        options.mark
    );
    match &trigger_bytes {
        Some(bytes) => println!(
            "снимок триггера: {} байт, SNI {}",
            bytes.len(),
            hello_sni(bytes).unwrap_or_else(|_| "не найден".into())
        ),
        None if trigger_timed_out => println!(
            "снимок триггера: не получен за {} мс",
            options.arm_wait.unwrap_or(ASK_WAIT).as_millis()
        ),
        None => println!("снимок триггера: не получен"),
    }
    match (&options.control, &control_bytes) {
        (None, _) => println!("снимок control: не запрошен"),
        (_, Some(bytes)) => println!(
            "снимок control: {} байт, SNI {}",
            bytes.len(),
            hello_sni(bytes).unwrap_or_else(|_| "не найден".into())
        ),
        (_, None) if control_timed_out => println!(
            "снимок control: не получен за {} мс",
            options.arm_wait.unwrap_or(ASK_WAIT).as_millis()
        ),
        (_, None) => println!("снимок control: не получен"),
    }

    let Some(trigger_bytes) = trigger_bytes else {
        println!("опрос не выполнен: нет полного ClientHello цели");
        for (index, question) in AskQuestion::ALL.iter().enumerate() {
            println!(
                "[{}/5] {} — не задан: снимок триггера не получен",
                index + 1,
                question.label()
            );
        }
        return Ok(0);
    };
    let trigger = validate_hello(&trigger_bytes, &options.sni)
        .map_err(|error| format!("ClientHello цели: {error}"))?;
    let control_trigger = control_bytes
        .as_deref()
        .map(|bytes| {
            let control_sni = hello_sni(bytes)?;
            validate_hello(bytes, &control_sni)
        })
        .transpose()?;
    let shape = hello_shape(&trigger_bytes)?;
    let mut properties = r2o_controller::classify::DpiProps::default();
    let mut passed_question = None;

    for (index, question) in AskQuestion::ALL.iter().copied().enumerate() {
        if question == AskQuestion::ProtocolParse && control_trigger.is_none() {
            println!(
                "[{}/5] {} — не задан: нет control ClientHello",
                index + 1,
                question.label()
            );
            continue;
        }
        let plan_id = random_id()?;
        let trial_id = random_id()?;
        let (plan_text, plan) = match question_plan(
            question,
            &trigger,
            control_trigger
                .as_ref()
                .map(|value| value.payload.as_slice()),
            plan_id,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                println!(
                    "[{}/5] {} — не задан: план не собран ({error})",
                    index + 1,
                    question.label()
                );
                continue;
            }
        };
        let plan_records = compile_text(&plan_text)?;
        let plan_len = plan_records.len();
        if plan.id != plan_id {
            return Err("план вопроса потерял случайный идентификатор".into());
        }
        let bound = match BoundTcpProbe::open(family, Some(0)) {
            Ok(bound) => bound,
            Err(error) => {
                r2o_print_ask_trace(
                    plan_len,
                    "не отправлен",
                    None,
                    None,
                    "не удалось занять порт вопроса",
                );
                println!(
                    "[{}/5] {} — не задан: не удалось занять порт вопроса ({error})",
                    index + 1,
                    question.label()
                );
                continue;
            }
        };
        let source_port = bound.local_port;
        let command = encode_set_name_probe(
            &options.sni,
            shape,
            family,
            source_port,
            &plan_records,
            trial_id,
        )?;
        let ack = match client.exchange_command_with_timeout(
            &command,
            control::COMMAND_SET_NAME_PROBE,
            ASK_WAIT,
        ) {
            Ok(ack) => ack,
            Err(error) => {
                if let Err(cleanup_error) =
                    client.delete_name_probe(&options.sni, shape, family, source_port)
                {
                    return Err(format!(
                        "подтверждение вопроса {} не получено ({error}); временный план не снят: {cleanup_error}",
                        question.label()
                    )
                    .into());
                }
                r2o_print_ask_trace(
                    plan_len,
                    "SET_NAME_PROBE не подтверждён",
                    None,
                    None,
                    "SET_NAME_PROBE не подтверждён",
                );
                println!(
                    "[{}/5] {} — не измерено: нет подтверждения плана ({error}); временный план снят",
                    index + 1,
                    question.label()
                );
                continue;
            }
        };
        if ack.trial_id != Some(trial_id) {
            client.delete_name_probe(&options.sni, shape, family, source_port)?;
            r2o_print_ask_trace(
                plan_len,
                "получено чужое подтверждение",
                None,
                None,
                "trial ID подтверждения не совпал",
            );
            println!(
                "[{}/5] {} — не измерено: подтверждение пришло с чужим trial ID; временный план снят",
                index + 1,
                question.label()
            );
            continue;
        }
        if !ack.ok {
            r2o_print_ask_trace(
                plan_len,
                &format!("датапат отверг — {}", r2o_ask_ack_reason(ack.reason)),
                None,
                None,
                "датапат отверг план",
            );
            println!(
                "[{}/5] {} — план не принят датапатом (код {})",
                index + 1,
                question.label(),
                ack.reason
            );
            continue;
        }

        let connection = bound.connect(destination, ASK_WAIT);
        let (mut stream, local_ip, local_port, _) = match connection {
            Ok(connection) => connection,
            Err(error) => {
                let cleanup = client.delete_name_probe(&options.sni, shape, family, source_port);
                if let Err(cleanup_error) = cleanup {
                    return Err(format!(
                        "вопрос {} не подключился ({error}); временный план не снят: {cleanup_error}",
                        question.label()
                    )
                    .into());
                }
                r2o_print_ask_trace(
                    plan_len,
                    "датапат принял",
                    None,
                    None,
                    "обращение к цели не состоялось",
                );
                println!(
                    "[{}/5] {} — не измерено: соединение не установлено ({error}); временный план снят",
                    index + 1,
                    question.label()
                );
                continue;
            }
        };
        if local_port != source_port {
            client.delete_name_probe(&options.sni, shape, family, source_port)?;
            drop(stream);
            r2o_print_ask_trace(
                plan_len,
                "датапат принял",
                Some(local_port),
                None,
                "локальный порт сокета изменился",
            );
            println!(
                "[{}/5] {} — не измерено: локальный порт изменился; временный план снят",
                index + 1,
                question.label()
            );
            continue;
        }
        let expected_key = r2o_ask_flow_key(local_ip, local_port, destination);
        if let Err(error) = stream.write_all(&trigger_bytes) {
            drop(stream);
            client.delete_name_probe(&options.sni, shape, family, source_port)?;
            r2o_print_ask_trace(
                plan_len,
                "датапат принял",
                Some(local_port),
                None,
                "снимок ClientHello не отправился полностью",
            );
            println!(
                "[{}/5] {} — не измерено: снимок ClientHello не отправился ({error}); временный план снят",
                index + 1,
                question.label()
            );
            continue;
        }
        let proof =
            client.wait_for_ask_proof(trial_id, plan_id, expected_key, family, shape, ASK_WAIT);
        let proof = match proof {
            Ok(proof) => proof,
            Err(error) => {
                let cleanup = client.delete_name_probe(&options.sni, shape, family, source_port);
                if let Err(cleanup_error) = cleanup {
                    return Err(format!(
                        "вопрос {} завершился ({error}); временный план не снят: {cleanup_error}",
                        question.label()
                    )
                    .into());
                }
                drop(stream);
                r2o_print_ask_trace(
                    plan_len,
                    "датапат принял",
                    Some(local_port),
                    None,
                    "сбор события обмена прервался",
                );
                println!(
                    "[{}/5] {} — не измерено: сбор события обмена прервался ({error}); временный план снят",
                    index + 1,
                    question.label()
                );
                continue;
            }
        };

        if proof.applied && proof.exchange_seen && proof.server_hello {
            drop(stream);
            record_question_passed(&mut properties, question);
            r2o_print_ask_trace(
                plan_len,
                "датапат принял",
                Some(local_port),
                Some(&proof),
                "вопрос прошёл",
            );
            println!(
                "[{}/5] {} — пройден: план применён и получен ServerHello",
                index + 1,
                question.label()
            );
            println!("план вопроса, подтверждённый этим измерением:\n{plan_text}");
            passed_question = Some(index);
            break;
        }

        if let Some(code) = proof.unsent_code {
            client.delete_name_probe(&options.sni, shape, family, source_port)?;
            drop(stream);
            r2o_print_ask_trace(
                plan_len,
                "датапат принял",
                Some(local_port),
                Some(&proof),
                "посылка плана не покинула машину",
            );
            println!(
                "[{}/5] {} — не измерено: план не был полностью отправлен (код отказа {code}); временный план снят",
                index + 1,
                question.label()
            );
            continue;
        }

        client.delete_name_probe(&options.sni, shape, family, source_port)?;
        drop(stream);
        r2o_print_ask_trace(
            plan_len,
            "датапат принял",
            Some(local_port),
            Some(&proof),
            "вопрос не получил полного доказательства",
        );
        let missing = if !proof.applied {
            "план к потоку не применён"
        } else if !proof.exchange_seen {
            "событие TCP-обмена не получено"
        } else {
            "ServerHello не подтверждён"
        };
        println!(
            "[{}/5] {} — не измерено: {missing}; временный план снят",
            index + 1,
            question.label()
        );
    }

    if let Some(passed_index) = passed_question {
        for (index, question) in AskQuestion::ALL.iter().enumerate().skip(passed_index + 1) {
            println!(
                "[{}/5] {} — не задан: предыдущий вопрос уже дал ответ, опрос остановлен",
                index + 1,
                question.label()
            );
        }
    }

    println!("итоговые свойства инспектора:");
    println!(
        "  tolerates_left_overlap = {}",
        r2o_tri_state(properties.tolerates_left_overlap)
    );
    println!(
        "  tolerates_reorder      = {}",
        r2o_tri_state(properties.tolerates_reorder)
    );
    println!(
        "  validates_checksum     = {}",
        r2o_tri_state(properties.validates_checksum)
    );
    println!(
        "  parses_l7              = {}",
        r2o_tri_state(properties.parses_l7)
    );
    println!(
        "  counts_duplicates      = {}",
        r2o_tri_state(properties.counts_duplicates)
    );
    let decoy_sni = control_bytes
        .as_deref()
        .and_then(|bytes| hello_sni(bytes).ok());
    let composed = compose_plan_texts(&properties, &trigger, shape, decoy_sni.as_deref(), 0)?;
    if composed.is_empty() {
        println!("выведенные планы: нет (не хватает имени control-приманки)");
    } else {
        println!("выведенные планы:");
        for (index, plan) in composed.iter().enumerate() {
            println!("\nплан {}/{}:\n{}", index + 1, composed.len(), plan);
        }
    }
    Ok(0)
}

#[cfg(unix)]
fn save_ask_snapshot(path: &std::path::Path, kind: &str, sni: &str, bytes: &[u8]) {
    let mut contents = format!(
        "# снимок {kind}, имя {sni}, {} байт — снят r2o-controller с живого датапата\n",
        bytes.len()
    );
    for (index, byte) in bytes.iter().enumerate() {
        contents.push_str(&format!("{byte:02x}"));
        if (index + 1) % 32 == 0 {
            contents.push('\n');
        }
    }
    if !bytes.len().is_multiple_of(32) {
        contents.push('\n');
    }
    match std::fs::write(path, contents) {
        Ok(()) => println!(
            "снимок {kind} сохранён: {} ({} байт)",
            path.display(),
            bytes.len()
        ),
        Err(error) => eprintln!(
            "r2o-controller: снимок {kind} не сохранён в {}: {error}",
            path.display()
        ),
    }
}

#[cfg(unix)]
fn r2o_tri_state(value: r2o_controller::classify::TriState) -> &'static str {
    match value {
        r2o_controller::classify::TriState::Unset => "не измерено",
        r2o_controller::classify::TriState::False => "нет",
        r2o_controller::classify::TriState::True => "да",
    }
}

fn r2o_voice_check_command(r2o_arguments: &[std::ffi::OsString]) -> Option<i32> {
    if r2o_arguments
        .first()
        .is_none_or(|r2o_argument| r2o_argument != "--voice-check")
    {
        return None;
    }
    let r2o_options = match r2o_parse_voice_options(&r2o_arguments[1..]) {
        Ok(r2o_options) => r2o_options,
        Err(r2o_error) => {
            eprintln!("r2o-controller: {r2o_error}");
            eprintln!(
                "использование: r2o-controller --voice-check [--addr IPv4:ПОРТ] [--control ХОСТ:ПОРТ] [--conntrack ФАЙЛ] [--wait МС] [--mark 0xN] [--discovery]"
            );
            return Some(2);
        }
    };
    let r2o_result = r2o_measure_voice(&r2o_options);
    print!("{}", r2o_format_voice_measurement(&r2o_result));
    Some(i32::from(
        r2o_result.verdict != r2o_controller::voice_measure::R2oVoiceVerdict::Clear,
    ))
}

fn r2o_voice_list_command(r2o_arguments: &[std::ffi::OsString]) -> Option<i32> {
    if r2o_arguments
        .first()
        .is_none_or(|r2o_argument| r2o_argument != "--voice-list")
    {
        return None;
    }

    let r2o_path = match r2o_arguments {
        [r2o_command] if r2o_command == "--voice-list" => None,
        [r2o_command, r2o_option, r2o_path]
            if r2o_command == "--voice-list" && r2o_option == "--conntrack" =>
        {
            Some(PathBuf::from(r2o_path))
        }
        _ => {
            eprintln!("использование: r2o-controller --voice-list [--conntrack ФАЙЛ]");
            return Some(2);
        }
    };

    let r2o_targets = r2o_read_voice_targets(r2o_path.as_deref());
    print!("{}", r2o_format_voice_targets(&r2o_targets));
    Some(i32::from(r2o_targets.is_empty()))
}

fn run(arguments: Vec<std::ffi::OsString>) -> Result<(), Box<dyn Error>> {
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
    println!(
        "  r2o-controller --ask --control СОКЕТ --ip IP --sni ИМЯ (--hello-hex ФАЙЛ | --arm-wait-ms МС)"
    );
    println!("  r2o-controller --import-donor-catalog ФАЙЛ КАТАЛОГА");
    println!("  r2o-controller --voice-list [--conntrack ФАЙЛ]");
    println!(
        "  r2o-controller --voice-check [--addr IPv4:ПОРТ] [--control ХОСТ:ПОРТ] [--conntrack ФАЙЛ] [--wait МС] [--mark 0xN] [--discovery]"
    );
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
    let installed = install_catalog_best_effort(&mut client, &compiled)?;
    report_catalog_refusals(&installed);
    println!(
        "каталог обработан: установлено {}, пропущено неподдерживаемых {skipped}",
        installed.installed,
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
    let installed = install_catalog_best_effort(&mut client, &compiled)?;
    report_catalog_refusals(&installed);
    println!(
        "каталог обработан: установлено {}, пропущено неподдерживаемых {}; {}",
        installed.installed,
        compiled.skipped,
        if discover {
            "наблюдение и автопоиск активны"
        } else {
            "наблюдение активно"
        }
    );
    std::io::stdout().flush()?;
    let https_cache_path = catalog_path.with_file_name("https-cache.json");
    let active_groups = installed.installed_groups.into_iter().collect();
    let live_catalog = Some((catalog.clone(), catalog_path.clone()));
    client.watch_events(
        discover.then_some((catalog, catalog_path.clone(), mark)),
        Some(https_cache_path),
        mark,
        live_catalog,
        active_groups,
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
fn r2o_discovery_record_network_whitelist(
    path: &Path,
    fallback: &Catalog,
    discovered_name: Option<&str>,
) -> Result<(), String> {
    let (_lock, mut catalog) = locked_catalog(path, fallback).map_err(|error| error.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs() as i64;
    let network = catalog
        .network_whitelist
        .get_or_insert_with(r2o_controller::catalog::NetworkWhitelist::default);
    if let Some(name) = discovered_name {
        if !network.name.is_empty() && network.name != name {
            return Ok(());
        }
        network.name = name.to_owned();
        network.searched = true;
        network.confirmed_at = Some(now.max(1));
    } else if network.name.is_empty() {
        network.searched = true;
    }
    catalog
        .save_atomic(path, now.max(1))
        .map_err(|error| format!("не удалось сохранить белое имя сети: {error}"))
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
    group_commands: Vec<(usize, r2o_controller::live::LiveGroupKey)>,
    skipped: usize,
    tcp_stall_budgets: Vec<u16>,
}

#[cfg(unix)]
const R2O_TCP_STALL_FIELD_BUDGET: u16 = 25;
#[cfg(unix)]
const R2O_TCP_STALL_BUDGETS_MAX: usize = 8;
#[cfg(unix)]
const R2O_TCP_STALL_BUDGET_SLACK: u32 = 3;

#[cfg(unix)]
fn r2o_box_tcp_stall_budget(box_record: &r2o_controller::catalog::BoxRecord) -> Option<u16> {
    box_record.fingerprint.signals.iter().find_map(|signal| {
        if !matches!(signal.kind.as_str(), "rx-volume" | "rx-volume-wire")
            || !(1..=i32::from(u16::MAX)).contains(&signal.packets)
        {
            return None;
        }
        u16::try_from(signal.packets).ok()
    })
}

#[cfg(unix)]
fn r2o_tcp_stall_budgets(catalog: &Catalog) -> Vec<u16> {
    let mut budgets = Vec::new();
    for budget in catalog.boxes.iter().filter_map(r2o_box_tcp_stall_budget) {
        if budgets.is_empty() {
            budgets.push(R2O_TCP_STALL_FIELD_BUDGET);
        }
        if budgets.len() >= R2O_TCP_STALL_BUDGETS_MAX {
            break;
        }
        if !budgets.contains(&budget) {
            budgets.push(budget);
        }
    }
    budgets
}

#[cfg(unix)]
fn r2o_tcp_stall_budgets_for_name(catalog: &Catalog, host: &str) -> Vec<u16> {
    let mut budgets = Vec::new();
    for box_record in &catalog.boxes {
        let Some(budget) = r2o_box_tcp_stall_budget(box_record) else {
            continue;
        };
        let bound_to_tcp_name = box_record.bindings.iter().any(|binding| {
            binding.enabled
                && binding.kind == "name"
                && binding.target == host
                && (binding.transport == 0 || binding.transport == 6)
        });
        if bound_to_tcp_name && !budgets.contains(&budget) {
            budgets.push(budget);
            if budgets.len() == R2O_TCP_STALL_BUDGETS_MAX {
                break;
            }
        }
    }
    budgets
}

#[cfg(unix)]
fn r2o_tcp_stall_in_name_band(catalog: &Catalog, host: &str, packets: u32) -> bool {
    let budgets = r2o_tcp_stall_budgets_for_name(catalog, host);
    budgets.is_empty()
        || budgets.iter().any(|budget| {
            packets.saturating_add(R2O_TCP_STALL_BUDGET_SLACK) >= u32::from(*budget)
                && packets <= u32::from(*budget) + R2O_TCP_STALL_BUDGET_SLACK
        })
}

#[cfg(unix)]
const DOMAIN_DIRECT_CLEAR: u8 = 2;
#[cfg(unix)]
const DOMAIN_PLAN_FAILED: u8 = 4;

#[cfg(unix)]
fn catalog_commands(catalog: &Catalog) -> Result<CompiledCatalog, Box<dyn Error>> {
    let mut commands = Vec::new();
    let mut group_commands = Vec::new();
    let mut skipped = 0_usize;
    for box_record in &catalog.boxes {
        for binding in &box_record.bindings {
            if !binding.enabled || binding.recheck_since.is_some() {
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
                && binding.verified_by == 5
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
                        "адресная голосовая привязка {} не содержит точный STUN/Discovery-план",
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
            suffix_commands.push((
                format!("суффикс {}", group.suffix),
                command,
                r2o_controller::live::LiveGroupKey::from(group),
            ));
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
        for (host, command, key) in suffix_commands {
            group_commands.push((commands.len(), key));
            commands.push((host, command));
        }
    }
    Ok(CompiledCatalog {
        commands,
        group_commands,
        skipped,
        tcp_stall_budgets: r2o_tcp_stall_budgets(catalog),
    })
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
fn r2o_public_resource_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            let [first, second, _, _] = address.octets();
            first != 0
                && first != 10
                && first != 127
                && first < 224
                && !(first == 169 && second == 254)
                && !(first == 192 && second == 168)
                && !(first == 172 && (16..=31).contains(&second))
                && !(first == 100 && (64..=127).contains(&second))
        }
        std::net::IpAddr::V6(address) => address.octets()[0] & 0xe0 == 0x20,
    }
}

#[cfg(unix)]
fn r2o_target_confirmed_probe_path(
    catalog: &Catalog,
    target: &r2o_controller::discovery::DiscoveryTarget,
) -> Option<String> {
    let Ok(endpoint) = target.endpoint.parse::<std::net::SocketAddr>() else {
        return None;
    };
    if endpoint.port() != 443
        || target.host.parse::<std::net::IpAddr>().is_ok()
        || !r2o_public_resource_ip(endpoint.ip())
        || !matches!(target.family, 4 | 6)
        || endpoint.is_ipv4() != (target.family == 4)
    {
        return None;
    }
    let (transport, shape) = match target.shape {
        SHAPE_ECH_TCP => (6, SHAPE_MODERN),
        SHAPE_QUIC => (17, SHAPE_QUIC),
        shape => (6, shape),
    };
    catalog
        .boxes
        .iter()
        .flat_map(|box_record| &box_record.bindings)
        .filter(|binding| {
            binding.enabled
                && binding.level >= 3
                && binding.kind == "name"
                && binding.target == target.host
                && binding.transport == transport
                && (if binding.family == 0 {
                    4
                } else {
                    binding.family
                }) == target.family
                && binding.shape == shape
                && r2o_controller::r2o_resource::r2o_resource_path_ok(&binding.probe_path)
        })
        .reduce(|best, binding| {
            if binding.confirmed > best.confirmed {
                binding
            } else {
                best
            }
        })
        .map(|binding| binding.probe_path.clone())
}

#[cfg(unix)]
fn r2o_discovery_resource_probe_paths(
    target: &r2o_controller::discovery::DiscoveryTarget,
    catalog: Option<&Catalog>,
    memory: &std::sync::Mutex<r2o_controller::r2o_resource::R2oResourceMemory>,
) -> (String, Option<String>) {
    let Ok(endpoint) = target.endpoint.parse::<std::net::SocketAddr>() else {
        return ("/".into(), None);
    };
    if endpoint.port() != 443
        || target.host.parse::<std::net::IpAddr>().is_ok()
        || !r2o_public_resource_ip(endpoint.ip())
        || !matches!(target.family, 4 | 6)
        || endpoint.is_ipv4() != (target.family == 4)
    {
        return ("/".into(), None);
    }
    let confirmed = catalog.and_then(|catalog| r2o_target_confirmed_probe_path(catalog, target));
    let (proven, hint) = memory
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .paths_for_host(&target.host, std::time::Instant::now());
    let primary = confirmed
        .or_else(|| proven.clone())
        .or_else(|| hint.clone())
        .unwrap_or_else(|| "/".into());
    let alternate = proven
        .filter(|path| path != &primary)
        .or_else(|| hint.filter(|path| path != &primary));
    (primary, alternate)
}

#[cfg(unix)]
fn r2o_quic_discovery_probe_path(
    snapshot: &[u8],
    server: std::net::SocketAddr,
    catalog: &Catalog,
    resource_memory: &std::sync::Mutex<r2o_controller::r2o_resource::R2oResourceMemory>,
) -> String {
    let host =
        r2o_quic_snapshot_server_name(snapshot, server).unwrap_or_else(|| server.ip().to_string());
    let target = r2o_controller::discovery::DiscoveryTarget {
        host,
        endpoint: server.to_string(),
        family: if server.is_ipv4() { 4 } else { 6 },
        shape: SHAPE_QUIC,
    };
    r2o_discovery_resource_probe_paths(&target, Some(catalog), resource_memory).0
}

#[cfg(unix)]
fn r2o_discovery_volume_wire_len(
    target: &r2o_controller::discovery::DiscoveryTarget,
    client_hello: Option<&[u8]>,
) -> Option<usize> {
    client_hello
        .map(<[u8]>::len)
        .or_else(|| match target.shape {
            SHAPE_MODERN => Trigger::tls13(&target.host)
                .ok()
                .map(|trigger| trigger.payload.len()),
            SHAPE_LEGACY => Trigger::tls(&target.host)
                .ok()
                .map(|trigger| trigger.payload.len()),
            _ => None,
        })
}

#[cfg(unix)]
fn r2o_discovery_volume_fetch_options(
    target: &r2o_controller::discovery::DiscoveryTarget,
    path: &str,
    mark: Option<u32>,
    wire_len: Option<usize>,
) -> Result<r2o_controller::fetch::FetchOptions, String> {
    let endpoint = target
        .endpoint
        .parse::<std::net::SocketAddr>()
        .map_err(|error| format!("адрес объёмной пробы недопустим: {error}"))?;
    let options = r2o_controller::fetch::FetchOptions {
        name: target.host.clone(),
        ip: Some(endpoint.ip()),
        port: endpoint.port(),
        path: path.into(),
        deadline: std::time::Duration::from_secs(8),
        tls12: target.shape == SHAPE_LEGACY,
        wire_len,
        mark,
    };
    options.validate()?;
    Ok(options)
}

#[cfg(unix)]
fn r2o_discovery_measure_volume(
    options: &r2o_controller::fetch::FetchOptions,
    alternate_path: Option<&str>,
) -> (
    Result<r2o_controller::fetch::R2oFetchVolumeTxResult, String>,
    r2o_controller::fetch::R2oFetchVolumeRxResult,
) {
    let tx = r2o_controller::fetch::r2o_fetch_measure_tx_volume(options);
    let rx = if options.port == 80
        || tx
            .as_ref()
            .is_ok_and(|result| result.reason.starts_with("нет TCP к "))
    {
        r2o_controller::fetch::R2oFetchVolumeRxResult::default()
    } else {
        r2o_controller::fetch::r2o_fetch_measure_rx_volume_with_fallback_path(
            options,
            alternate_path,
        )
    };
    (tx, rx)
}

#[cfg(unix)]
fn r2o_discovery_volume_cut(
    tx: &Result<r2o_controller::fetch::R2oFetchVolumeTxResult, String>,
    rx: &r2o_controller::fetch::R2oFetchVolumeRxResult,
) -> bool {
    tx.as_ref()
        .is_ok_and(|result| result.verdict == r2o_controller::fetch::R2oFetchVolumeTxVerdict::Cut)
        || rx.evidence.is_some()
}

#[cfg(unix)]
fn r2o_discovery_volume_ladder_eligible(
    tx: &Result<r2o_controller::fetch::R2oFetchVolumeTxResult, String>,
    rx: &r2o_controller::fetch::R2oFetchVolumeRxResult,
) -> bool {
    r2o_discovery_volume_cut(tx, rx)
}

#[cfg(unix)]
fn r2o_discovery_volume_ladder_decision(
    result: &Result<r2o_controller::fetch::FetchResult, String>,
    applied: bool,
    packet_budget_required: bool,
) -> R2oFamilyRecoveryDecision {
    if packet_budget_required
        && !result.as_ref().is_ok_and(|fetch| {
            fetch.r2o_volume_observation.packet_budget
                == r2o_controller::r2o_volume::R2oVolumePacketBudget::Passed
        })
    {
        return R2oFamilyRecoveryDecision::Reclassify;
    }
    r2o_family_recovery_decision(result, applied)
}

#[cfg(unix)]
fn r2o_discovery_partial_rx_inconclusive_reason(
    observation: &r2o_controller::r2o_volume::R2oVolumeObservation,
) -> Option<String> {
    if !r2o_controller::r2o_volume::r2o_volume_rx_partial(observation) {
        return None;
    }
    let wire_partial = observation.status == 0 && observation.rx_tls_record_missing;
    let (domain, bytes) = if wire_partial {
        ("TLS wire", observation.rx_tls_wire_bytes)
    } else {
        ("HTTP body", observation.body_bytes)
    };
    Some(format!(
        "RX {domain} оборвался после {bytes} байт; повторный объёмный замер не завершён"
    ))
}

#[cfg(unix)]
fn r2o_discovery_mark_partial_rx_inconclusive(
    outcome: &mut DiscoveryOutcome,
    observation: &r2o_controller::r2o_volume::R2oVolumeObservation,
    volume_proven: bool,
) -> bool {
    if volume_proven {
        return false;
    }
    let Some(reason) = r2o_discovery_partial_rx_inconclusive_reason(observation) else {
        return false;
    };
    outcome.direct_clear = false;
    outcome.retry_after = Some(R2O_DISCOVERY_INCOMPLETE_RETRY);
    outcome.detail.push_str(&format!("; {reason}"));
    true
}

#[cfg(unix)]
fn r2o_discovery_volume_fingerprint(
    tx: &Result<r2o_controller::fetch::R2oFetchVolumeTxResult, String>,
    rx: &r2o_controller::fetch::R2oFetchVolumeRxResult,
) -> r2o_controller::catalog::Fingerprint {
    let mut signals = Vec::with_capacity(2);
    if let Ok(result) = tx
        && result.verdict == r2o_controller::fetch::R2oFetchVolumeTxVerdict::Cut
    {
        signals.push(r2o_controller::catalog::Signal {
            kind: "volume".into(),
            volume: i32::try_from(result.at_kb).unwrap_or(i32::MAX),
            seen: 1,
            ..r2o_controller::catalog::Signal::default()
        });
    }
    if let Some(evidence) = &rx.evidence {
        signals.push(r2o_controller::catalog::Signal {
            kind: match evidence.domain {
                r2o_controller::r2o_volume::R2oVolumeRxDomain::TlsWire => "rx-volume-wire",
                r2o_controller::r2o_volume::R2oVolumeRxDomain::HttpBody => "rx-volume",
            }
            .into(),
            volume: i32::try_from(evidence.cut_kb).unwrap_or(i32::MAX),
            seen: 1,
            packets: i32::try_from(evidence.cut_packets).unwrap_or(i32::MAX),
            ..r2o_controller::catalog::Signal::default()
        });
    }
    r2o_controller::catalog::Fingerprint { method: 2, signals }
}

#[cfg(unix)]
fn r2o_discovery_volume_bucket(volume_kb: i32) -> i32 {
    if volume_kb <= 0 {
        return 0;
    }
    (i32::BITS - volume_kb.leading_zeros()) as i32
}

#[cfg(unix)]
fn r2o_discovery_volume_known_plans(
    catalog: Option<&Catalog>,
    target: &r2o_controller::discovery::DiscoveryTarget,
    observed: &r2o_controller::catalog::Fingerprint,
) -> Vec<(String, String)> {
    let Some(catalog) = catalog else {
        return Vec::new();
    };
    if !matches!(target.shape, SHAPE_MODERN | SHAPE_LEGACY) {
        return Vec::new();
    }
    let observed_buckets: Vec<(&str, i32)> = observed
        .signals
        .iter()
        .filter(|signal| {
            matches!(
                signal.kind.as_str(),
                "volume" | "rx-volume" | "rx-volume-wire"
            )
        })
        .map(|signal| {
            (
                signal.kind.as_str(),
                r2o_discovery_volume_bucket(signal.volume),
            )
        })
        .collect();
    let mut candidates = Vec::new();
    for box_record in &catalog.boxes {
        if !box_record.fingerprint.is_compatible_with(observed) {
            continue;
        }
        let same_bucket = box_record.fingerprint.signals.iter().any(|saved| {
            observed_buckets.iter().any(|(kind, bucket)| {
                *kind == saved.kind
                    && *bucket > 0
                    && *bucket == r2o_discovery_volume_bucket(saved.volume)
            })
        });
        for plan in &box_record.plans {
            if !plan.enabled || plan.proto != "tls" || plan.text.len() >= 4096 {
                continue;
            }
            let Ok(bytes) = compile_text(&plan.text) else {
                continue;
            };
            let Ok(runtime_plan) = Plan::parse(&bytes) else {
                continue;
            };
            if runtime_plan.transport != 6
                || runtime_plan.proto != 1
                || r2o_datapath::engine::validate_runtime_plan(&runtime_plan).is_err()
            {
                continue;
            }
            candidates.push((
                same_bucket,
                plan.successes,
                plan.text.clone(),
                box_record.id.clone(),
            ));
        }
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
    let mut plans: Vec<(String, String)> = Vec::new();
    for (_, _, text, box_id) in candidates {
        if !plans.iter().any(|(_, known_text)| known_text == &text) {
            plans.push((box_id, text));
        }
    }
    plans
}

#[cfg(unix)]
fn r2o_discovery_existing_binding_blocks_outcome(
    catalog: &Catalog,
    target: &r2o_controller::discovery::DiscoveryTarget,
    input: u8,
    volume_recovery: bool,
) -> bool {
    r2o_controller::discovery::has_usable_binding(catalog, target)
        && !(input == 1 && r2o_controller::discovery::has_usable_profile_binding(catalog, target))
        && !volume_recovery
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
    if target.shape == SHAPE_QUIC {
        return None;
    }
    let selected_path = r2o_target_confirmed_probe_path(catalog, target).unwrap_or_default();
    let key = GroupKey {
        transport: 6,
        family: target.family,
        shape: if target.shape == SHAPE_ECH_TCP {
            SHAPE_MODERN
        } else {
            target.shape
        },
        probe_path: if selected_path == "/" {
            String::new()
        } else {
            selected_path
        },
        ..GroupKey::default()
    };
    let domain_state = catalog.domain_state.as_ref()?;
    let group = domain_state.match_domain(&target.host, &key)?;
    let probe_path = group_path(group.key.transport, &group.key.probe_path);
    if probe_path != "/" && !r2o_controller::r2o_resource::r2o_resource_path_ok(probe_path) {
        return None;
    }
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
fn matching_domain_recovery_candidates(
    catalog: &Catalog,
    target: &r2o_controller::discovery::DiscoveryTarget,
) -> Vec<R2oFamilyRecoveryCandidate> {
    const MAX_CANDIDATES: usize = 8;

    let Some(group) = matching_domain_group(catalog, target) else {
        return Vec::new();
    };
    let Some(state) = catalog.domain_state.as_ref() else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for group_pass in [true, false] {
        for observation in &state.observations {
            if observation.evidence & 1 == 0
                || observation.evidence & (2 | 4) != 0
                || observation.key != group.key
                || !domain_member(&observation.name, &group.suffix)
                || (observation.plan_id == group.plan_id) != group_pass
            {
                continue;
            }
            for box_record in &catalog.boxes {
                let Some(saved_plan) = box_record
                    .plans
                    .iter()
                    .find(|plan| plan.id == observation.plan_id && plan.enabled)
                else {
                    continue;
                };
                if saved_plan.proto != "tls" || saved_plan.text.len() >= 4096 {
                    continue;
                }
                let confirmed = box_record.bindings.iter().any(|binding| {
                    binding.enabled
                        && binding.level >= 3
                        && binding.recheck_since.is_none()
                        && binding.kind == "name"
                        && normalize(&binding.target).is_ok_and(|name| name == observation.name)
                        && binding.plan_id == observation.plan_id
                        && (binding.transport == observation.key.transport
                            || binding.transport == 0 && observation.key.transport == 6)
                        && (binding.family == observation.key.family
                            || binding.family == 0 && observation.key.family == 4)
                        && group_shape_fits(binding.shape, observation.key.shape)
                        && group_path(binding.transport, &binding.probe_path)
                            == group_path(observation.key.transport, &observation.key.probe_path)
                        && binding.ech_origin == observation.key.ech_origin
                });
                if !confirmed {
                    continue;
                }
                let Ok(bytes) = compile_text(&saved_plan.text) else {
                    continue;
                };
                let Ok(plan) = Plan::parse(&bytes) else {
                    continue;
                };
                if !shape_matches_plan(target.shape, &plan)
                    || r2o_datapath::engine::validate_runtime_plan(&plan).is_err()
                    || candidates
                        .iter()
                        .any(|candidate: &R2oFamilyRecoveryCandidate| {
                            candidate.plan_text == saved_plan.text
                        })
                {
                    continue;
                }
                candidates.push(R2oFamilyRecoveryCandidate {
                    plan_id: plan.id,
                    plan_text: saved_plan.text.clone(),
                    group_plan: group_pass,
                    probe_path: group_path(group.key.transport, &group.key.probe_path).into(),
                });
                break;
            }
            if candidates.len() == MAX_CANDIDATES {
                return candidates;
            }
        }
    }
    candidates
}

#[cfg(unix)]
#[derive(Debug, Default, Eq, PartialEq)]
struct CatalogInstallSummary {
    installed: usize,
    refused: usize,
    last_refusal: Option<&'static str>,
    installed_groups: Vec<r2o_controller::live::LiveGroupKey>,
}

#[cfg(unix)]
fn install_catalog(
    client: &mut ControlClient,
    compiled: &CompiledCatalog,
) -> Result<CatalogInstallSummary, Box<dyn Error>> {
    install_catalog_with_policy(client, compiled, false)
}

#[cfg(unix)]
fn install_catalog_best_effort(
    client: &mut ControlClient,
    compiled: &CompiledCatalog,
) -> Result<CatalogInstallSummary, Box<dyn Error>> {
    install_catalog_with_policy(client, compiled, true)
}

#[cfg(unix)]
fn install_catalog_with_policy(
    client: &mut ControlClient,
    compiled: &CompiledCatalog,
    continue_plan_refusals: bool,
) -> Result<CatalogInstallSummary, Box<dyn Error>> {
    client.send_clear()?;
    let mut summary = CatalogInstallSummary::default();
    for (command_index, (host, command)) in compiled.commands.iter().enumerate() {
        let expected = command
            .get(4..6)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .ok_or("собранная команда каталога обрезана")?;
        if continue_plan_refusals
            && matches!(
                expected,
                COMMAND_SET_NAME | COMMAND_SET_ADDR | control::COMMAND_SET_SUFFIX
            )
        {
            let ack = match client.exchange_command(command, expected) {
                Ok(ack) => ack,
                Err(error) => {
                    return Err(rollback_catalog_install(
                        client,
                        command_index,
                        format!("{host}: {error}"),
                    ));
                }
            };
            if !ack.ok {
                summary.refused += 1;
                summary.last_refusal = Some(ack_reason_text(ack.reason));
                continue;
            }
        } else if let Err(error) = client.send_command(command, expected) {
            return Err(rollback_catalog_install(
                client,
                command_index,
                format!("{host}: {error}"),
            ));
        }
        if let Some((_, key)) = compiled
            .group_commands
            .iter()
            .find(|(index, _)| *index == command_index)
        {
            summary.installed_groups.push(key.clone());
        }
        summary.installed += 1;
    }
    if !compiled.tcp_stall_budgets.is_empty() {
        let command = encode_set_tcp_stall_budgets(&compiled.tcp_stall_budgets)
            .map_err(|error| format!("SET_TCP_STALL_BUDGETS: {error}"))?;
        if let Err(error) = client.send_command(&command, COMMAND_SET_TCP_STALL_BUDGETS) {
            return Err(rollback_catalog_install(
                client,
                summary.installed + summary.refused,
                format!("бюджеты потока TCP: {error}"),
            ));
        }
    }
    Ok(summary)
}

#[cfg(unix)]
fn rollback_catalog_install(
    client: &mut ControlClient,
    installed: usize,
    error: impl std::fmt::Display,
) -> Box<dyn Error> {
    match client.send_clear() {
        Ok(()) => format!(
            "установка каталога остановлена после {installed} привязок; частичная таблица очищена; {error}"
        )
        .into(),
        Err(clear_error) => format!(
            "установка каталога остановлена после {installed} привязок; не удалось очистить частичную таблицу; {error}; очистка при откате завершилась ошибкой: {clear_error}"
        )
        .into(),
    }
}

#[cfg(unix)]
fn ack_reason_text(reason: u8) -> &'static str {
    match reason {
        control::ACK_BAD_PLAN => "план не подходит runtime",
        control::ACK_NO_ROOM => "таблица планов заполнена",
        control::ACK_BAD_ARGS => "датапат отверг аргументы",
        _ => "неизвестная причина",
    }
}

#[cfg(unix)]
fn report_catalog_refusals(summary: &CatalogInstallSummary) {
    if summary.refused > 0 {
        println!(
            "каталог: датапат отверг планов с прошлой сводки: {} ({}) — обход по этим целям не исполняется, причина в журнале датапата",
            summary.refused,
            summary.last_refusal.unwrap_or("неизвестная причина")
        );
    }
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
        shape: u8,
        family: u8,
        port: u16,
        command: Vec<u8>,
        trial_id: [u8; 16],
        reply: SyncSender<Result<r2k_core::control::Ack, String>>,
    },
    DeleteProbe {
        host: String,
        shape: u8,
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
    probe_path: String,
    r2o_mark: Option<u32>,
    permit: r2o_controller::r2o_resource_limit::R2oMeasurementPermit,
    started_at: std::time::Instant,
    deny_recheck: bool,
    stall_cut: bool,
}

#[cfg(unix)]
struct R2oQuicDiscoveryOutcome {
    server: std::net::SocketAddr,
    snapshot: Vec<u8>,
    host: String,
    probe_path: String,
    deny_recheck: bool,
    stall_cut: bool,
    result: Result<Option<(String, String)>, String>,
}

#[cfg(unix)]
fn r2o_quic_snapshot_server_name(snapshot: &[u8], server: std::net::SocketAddr) -> Option<String> {
    let parsed = r2k_core::quic_snapshot::r2k_quic_snapshot_parse(snapshot)?;
    match r2k_core::quic::r2k_quic_initial_sni_result_from_datagrams(parsed.datagrams()).ok()? {
        Some(host) => {
            let host = String::from_utf8(host).ok()?;
            r2o_controller::domain::normalize(&host).ok()
        }
        None => Some(server.ip().to_string()),
    }
}

#[cfg(unix)]
fn r2o_quic_snapshot_has_ech(snapshot: &[u8]) -> bool {
    let Some(parsed) = r2k_core::quic_snapshot::r2k_quic_snapshot_parse(snapshot) else {
        return false;
    };
    let Some(client_hello) =
        r2k_core::quic::r2k_quic_initial_client_hello_from_datagrams(parsed.datagrams())
    else {
        return false;
    };
    let Ok(record_length) = u16::try_from(client_hello.len()) else {
        return false;
    };
    let mut record = Vec::with_capacity(5 + client_hello.len());
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&record_length.to_be_bytes());
    record.extend_from_slice(&client_hello);
    r2k_core::tls::parse(&record).ech_offer
}

#[cfg(unix)]
fn r2o_quic_discovery_cooldown(
    result: &Result<Option<(String, String)>, String>,
) -> std::time::Duration {
    match result {
        Ok(Some(_)) => R2O_QUIC_DISCOVERY_FOUND_COOLDOWN,
        Ok(None) => R2O_QUIC_DISCOVERY_INCONCLUSIVE_COOLDOWN,
        Err(_) => R2O_QUIC_DISCOVERY_FAILURE_COOLDOWN,
    }
}

#[cfg(unix)]
fn r2o_quic_data_cut(result: &r2o_controller::r2o_quic_http3::R2oQuicHttp3Result) -> bool {
    result.handshake_confirmed
        && r2o_controller::quic_replay::r2o_quic_trial_data_verdict(result)
            == r2k_core::quic::R2kQuicDataVerdict::Cut
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
fn r2o_http_search_from_response(
    response: &r2k_core::control::HttpResponseEvent,
) -> Option<(
    r2o_controller::discovery::DiscoveryTarget,
    &[u8],
    r2o_controller::http_search::Answer,
)> {
    let target = r2o_controller::discovery::DiscoveryTarget::from_http_response(response)?;
    let expected = match response.code {
        3 => r2o_controller::http_search::Answer::Injected,
        4 => r2o_controller::http_search::Answer::Cut,
        _ => return None,
    };
    Some((target, &response.path, expected))
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
fn http_search_key(target: &r2o_controller::discovery::DiscoveryTarget) -> (String, u8) {
    (target.host.clone(), target.family)
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
fn r2o_late_rx_is_covered_by_catalog(
    input: &R2oLateRxInput,
    planned: bool,
    catalog: Option<&Catalog>,
) -> bool {
    !planned
        && input.discovery_target.as_ref().is_some_and(|target| {
            catalog.is_some_and(|catalog| {
                r2o_controller::discovery::has_covering_binding(catalog, target)
            })
        })
}

#[cfg(unix)]
struct R2oFamilyRecoveryTask {
    target: r2o_controller::discovery::DiscoveryTarget,
    candidates: Vec<R2oFamilyRecoveryCandidate>,
    mark: Option<u32>,
}

#[cfg(unix)]
#[derive(Clone)]
struct R2oFamilyRecoveryCandidate {
    plan_id: [u8; 16],
    plan_text: String,
    group_plan: bool,
    probe_path: String,
}

#[cfg(unix)]
struct R2oFamilyRecoveryOutcome {
    target: r2o_controller::discovery::DiscoveryTarget,
    plan_id: [u8; 16],
    result: Result<r2o_controller::fetch::FetchResult, String>,
    applied: bool,
}

#[cfg(unix)]
struct R2oFamilyRecoveryWorker {
    jobs: Option<SyncSender<R2oFamilyRecoveryTask>>,
    outcomes: Receiver<R2oFamilyRecoveryOutcome>,
    cancel: Arc<AtomicBool>,
    active: HashSet<r2o_controller::discovery::DiscoveryTarget>,
    thread: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl R2oFamilyRecoveryWorker {
    fn new(
        measurement_gate: r2o_controller::r2o_resource_limit::R2oMeasurementGate,
        trial_commands: SyncSender<HttpSearchCommand>,
    ) -> Self {
        let (jobs, job_receiver) = mpsc::sync_channel::<R2oFamilyRecoveryTask>(8);
        let (outcome_sender, outcomes) = mpsc::sync_channel(8);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_gate = measurement_gate.clone();
        let worker_commands = trial_commands;
        let thread = std::thread::spawn(move || {
            while let Ok(task) = job_receiver.recv() {
                if worker_cancel.load(Ordering::Relaxed) {
                    break;
                }
                let outcome = {
                    let Some(_permit) = worker_gate.r2o_acquire(&worker_cancel) else {
                        break;
                    };
                    r2o_family_recovery_run(task, &worker_commands, &worker_cancel)
                };
                if outcome_sender.send(outcome).is_err() {
                    break;
                }
            }
        });
        Self {
            jobs: Some(jobs),
            outcomes,
            cancel,
            active: HashSet::new(),
            thread: Some(thread),
        }
    }

    fn queue(
        &mut self,
        target: r2o_controller::discovery::DiscoveryTarget,
        candidates: Vec<R2oFamilyRecoveryCandidate>,
        mark: Option<u32>,
    ) -> bool {
        if candidates.is_empty() || !self.active.insert(target.clone()) {
            return false;
        }
        let Some(jobs) = self.jobs.as_ref() else {
            self.active.remove(&target);
            return false;
        };
        if jobs
            .try_send(R2oFamilyRecoveryTask {
                target: target.clone(),
                candidates,
                mark,
            })
            .is_err()
        {
            self.active.remove(&target);
            return false;
        }
        true
    }

    fn try_outcome(&self) -> Option<R2oFamilyRecoveryOutcome> {
        self.outcomes.try_recv().ok()
    }

    fn complete(&mut self, target: &r2o_controller::discovery::DiscoveryTarget) {
        self.active.remove(target);
    }

    fn r2o_begin_shutdown(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs.take();
    }

    fn r2o_all_finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
    }

    fn r2o_join(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
impl Drop for R2oFamilyRecoveryWorker {
    fn drop(&mut self) {
        self.r2o_begin_shutdown();
        self.r2o_join();
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum R2oFamilyRecoveryDecision {
    Verified,
    Reclassify,
}

#[cfg(unix)]
fn r2o_family_recovery_decision(
    result: &Result<r2o_controller::fetch::FetchResult, String>,
    applied: bool,
) -> R2oFamilyRecoveryDecision {
    let response_complete = result.as_ref().is_ok_and(|fetch| {
        fetch.tls.is_some()
            && fetch.complete
            && fetch.application_verified
            && (200..600).contains(&fetch.status)
            && !fetch.cloudflare_challenge
            && !matches!(
                fetch.http_outcome,
                r2o_controller::fetch::R2oFetchHttpOutcome::Blocked
                    | r2o_controller::fetch::R2oFetchHttpOutcome::LegalDenial
            )
    });
    if response_complete && applied {
        R2oFamilyRecoveryDecision::Verified
    } else {
        R2oFamilyRecoveryDecision::Reclassify
    }
}

#[cfg(unix)]
fn r2o_confirm_discovery_outcome(
    mut outcome: DiscoveryOutcome,
    result: Result<r2o_controller::fetch::FetchResult, String>,
    applied: bool,
) -> DiscoveryOutcome {
    if outcome.plan_text.is_none()
        || r2o_family_recovery_decision(&result, applied) == R2oFamilyRecoveryDecision::Verified
    {
        return outcome;
    }
    outcome.plan_text = None;
    outcome.retry_after = Some(R2O_DISCOVERY_FAILURE_RETRY);
    if result
        .as_ref()
        .is_ok_and(|fetch| fetch.cloudflare_challenge)
    {
        outcome.detail.push_str(
            "; сервер вернул Cloudflare challenge: это не подтверждает обход и кандидат не сохранён",
        );
    } else {
        outcome.detail.push_str(
            "; кандидат не сохранён: временная проба не получила полный HTTPS-ответ и точное APPLIED",
        );
    }
    outcome
}

#[cfg(unix)]
fn r2o_family_recovery_fetch(
    target: &r2o_controller::discovery::DiscoveryTarget,
    mark: Option<u32>,
    probe_path: &str,
) -> Result<r2o_controller::fetch::FetchResult, String> {
    let endpoint = target
        .endpoint
        .parse::<std::net::SocketAddr>()
        .map_err(|error| format!("адрес семейной пробы недопустим: {error}"))?;
    r2o_controller::fetch::fetch(&r2o_controller::fetch::FetchOptions {
        name: target.host.clone(),
        ip: Some(endpoint.ip()),
        port: endpoint.port(),
        path: probe_path.into(),
        deadline: std::time::Duration::from_secs(8),
        tls12: target.shape == SHAPE_LEGACY,
        wire_len: None,
        mark,
    })
    .map_err(|error| format!("проверка известного семейного плана не завершилась: {error}"))
}

#[cfg(unix)]
fn r2o_family_recovery_run(
    task: R2oFamilyRecoveryTask,
    commands: &SyncSender<HttpSearchCommand>,
    cancel: &AtomicBool,
) -> R2oFamilyRecoveryOutcome {
    let mut outcome = R2oFamilyRecoveryOutcome {
        target: task.target.clone(),
        plan_id: task.candidates[0].plan_id,
        result: Err("не найден подходящий план семейного восстановления".to_owned()),
        applied: false,
    };
    let destination = match task.target.endpoint.parse::<std::net::SocketAddr>() {
        Ok(destination) => destination,
        Err(error) => {
            outcome.result = Err(format!("адрес семейной пробы недопустим: {error}"));
            return outcome;
        }
    };

    for candidate in task.candidates {
        if cancel.load(Ordering::Relaxed) {
            outcome.result = Err("проверка семейного плана отменена".to_owned());
            return outcome;
        }
        outcome.plan_id = candidate.plan_id;
        let trial = if candidate.group_plan {
            let result = r2o_family_recovery_fetch(&task.target, task.mark, &candidate.probe_path);
            let applied = r2o_collect_controller_applied_events(
                commands,
                [0; 16],
                std::time::Duration::from_millis(500),
            )
            .map(|events| {
                events.iter().any(|event| {
                    r2o_family_applied_flow_matches(
                        event,
                        &task.target,
                        result.as_ref().map_or(0, |fetch| fetch.local_port),
                        candidate.plan_id,
                        [0; 16],
                        false,
                    )
                })
            });
            match applied {
                Ok(applied) => (result, applied),
                Err(error) => (Err(error), false),
            }
        } else {
            r2o_family_recovery_sibling_trial(
                &task.target,
                destination,
                &candidate,
                task.mark,
                commands,
            )
        };
        outcome.result = trial.0;
        outcome.applied = trial.1;
        if r2o_family_recovery_decision(&outcome.result, outcome.applied)
            == R2oFamilyRecoveryDecision::Verified
        {
            return outcome;
        }
    }
    outcome
}

#[cfg(unix)]
fn r2o_family_recovery_sibling_trial(
    target: &r2o_controller::discovery::DiscoveryTarget,
    destination: std::net::SocketAddr,
    candidate: &R2oFamilyRecoveryCandidate,
    mark: Option<u32>,
    commands: &SyncSender<HttpSearchCommand>,
) -> (Result<r2o_controller::fetch::FetchResult, String>, bool) {
    r2o_family_recovery_sibling_trial_with_ech(target, destination, candidate, mark, commands, None)
}

#[cfg(unix)]
fn r2o_family_recovery_sibling_trial_with_ech(
    target: &r2o_controller::discovery::DiscoveryTarget,
    destination: std::net::SocketAddr,
    candidate: &R2oFamilyRecoveryCandidate,
    mark: Option<u32>,
    commands: &SyncSender<HttpSearchCommand>,
    ech: Option<&r2o_controller::ech::R2oEchConfig>,
) -> (Result<r2o_controller::fetch::FetchResult, String>, bool) {
    let (result, applied, _) = r2o_family_recovery_sibling_trial_with_ech_state(
        target,
        destination,
        candidate,
        mark,
        commands,
        ech,
        None,
    );
    (result, applied)
}

#[cfg(unix)]
fn r2o_family_recovery_sibling_trial_with_ech_state(
    target: &r2o_controller::discovery::DiscoveryTarget,
    destination: std::net::SocketAddr,
    candidate: &R2oFamilyRecoveryCandidate,
    mark: Option<u32>,
    commands: &SyncSender<HttpSearchCommand>,
    ech: Option<&r2o_controller::ech::R2oEchConfig>,
    packet_budget: Option<u32>,
) -> (
    Result<r2o_controller::fetch::FetchResult, String>,
    bool,
    bool,
) {
    let result = (|| {
        let bound = BoundTcpProbe::open(target.family, mark)
            .map_err(|error| format!("не удалось открыть сокет семейной пробы: {error}"))?;
        let local_port = bound.local_port;
        let trial_id = random_id().map_err(|error| error.to_string())?;
        let records = compile_text(&candidate.plan_text).map_err(|error| error.to_string())?;
        let command = encode_set_name_probe(
            &target.host,
            target.shape,
            target.family,
            local_port,
            &records,
            trial_id,
        )
        .map_err(|error| error.to_string())?;
        let ack = ask_http_controller(commands, |reply| HttpSearchCommand::InstallProbe {
            host: target.host.clone(),
            shape: target.shape,
            family: target.family,
            port: local_port,
            command,
            trial_id,
            reply,
        })?;
        if ack.trial_id != Some(trial_id) {
            return Err("подтверждение семейной пробы содержит чужой trial ID".into());
        }
        if !ack.ok {
            ask_http_controller(commands, |reply| HttpSearchCommand::DeleteProbe {
                host: target.host.clone(),
                shape: target.shape,
                family: target.family,
                port: local_port,
                reply,
            })?;
            return Err("датапат отверг временный план семейной пробы".into());
        }

        let connected = bound
            .connect(destination, std::time::Duration::from_secs(8))
            .map_err(|error| format!("не удалось подключить семейную пробу: {error}"));
        let mut transport_established = false;
        let fetch_result = match connected {
            Ok((stream, _, connected_port, _)) if connected_port == local_port => {
                transport_established = true;
                let options = r2o_controller::fetch::FetchOptions {
                    name: ech
                        .map(|config| config.origin_name.clone())
                        .unwrap_or_else(|| target.host.clone()),
                    ip: Some(destination.ip()),
                    port: destination.port(),
                    path: candidate.probe_path.clone(),
                    deadline: std::time::Duration::from_secs(8),
                    tls12: target.shape == SHAPE_LEGACY,
                    wire_len: None,
                    mark,
                };
                if let Some(ech) = ech {
                    let config = r2o_controller::ech::r2o_ech_tls_config(ech)?;
                    r2o_controller::fetch::r2o_fetch_ech_connected_stream(&options, stream, &config)
                } else if packet_budget.is_some() {
                    r2o_controller::fetch::r2o_fetch_connected_stream_with_packet_budget(
                        &options,
                        stream,
                        packet_budget,
                    )
                } else {
                    r2o_controller::fetch::r2o_fetch_connected_stream(&options, stream)
                }
            }
            Ok((_stream, _, _, _)) => Err("TCP-зонд получил неожиданный локальный порт".into()),
            Err(error) => Err(error),
        };
        ask_http_controller(commands, |reply| HttpSearchCommand::DeleteProbe {
            host: target.host.clone(),
            shape: target.shape,
            family: target.family,
            port: local_port,
            reply,
        })?;
        let events = r2o_collect_controller_applied_events(
            commands,
            trial_id,
            std::time::Duration::from_millis(500),
        )?;
        let applied = events.iter().any(|event| {
            r2o_family_applied_flow_matches(
                event,
                target,
                local_port,
                candidate.plan_id,
                trial_id,
                true,
            )
        });
        Ok((fetch_result, applied, transport_established))
    })();
    match result {
        Ok((fetch, applied, transport_established)) => (fetch, applied, transport_established),
        Err(error) => (Err(error), false, false),
    }
}

#[cfg(unix)]
fn r2o_run_discovery_candidate_trial(
    target: &r2o_controller::discovery::DiscoveryTarget,
    source_text: &str,
    probe_path: &str,
    mark: Option<u32>,
    commands: &SyncSender<HttpSearchCommand>,
    client_hello: Option<&[u8]>,
    ech_config: Option<&r2o_controller::ech::R2oEchConfig>,
    resource_memory: &std::sync::Mutex<r2o_controller::r2o_resource::R2oResourceMemory>,
    packet_budget: Option<u32>,
) -> (
    Result<r2o_controller::fetch::FetchResult, String>,
    bool,
    usize,
) {
    let (result, applied, attempts) = r2o_run_discovery_candidate_trial_with_retries(
        target,
        source_text,
        probe_path,
        mark,
        commands,
        client_hello,
        ech_config,
        resource_memory,
        1 + usize::from(client_hello.is_some()),
        packet_budget,
        || false,
    );
    (result, applied, attempts)
}

#[cfg(unix)]
fn r2o_run_discovery_candidate_trial_with_retries(
    target: &r2o_controller::discovery::DiscoveryTarget,
    source_text: &str,
    probe_path: &str,
    mark: Option<u32>,
    commands: &SyncSender<HttpSearchCommand>,
    client_hello: Option<&[u8]>,
    ech_config: Option<&r2o_controller::ech::R2oEchConfig>,
    resource_memory: &std::sync::Mutex<r2o_controller::r2o_resource::R2oResourceMemory>,
    probe_budget_remaining: usize,
    packet_budget: Option<u32>,
    mut retry_budget_available: impl FnMut() -> bool,
) -> (
    Result<r2o_controller::fetch::FetchResult, String>,
    bool,
    usize,
) {
    if probe_budget_remaining == 0 {
        return (
            Err("бюджет зондов Discovery исчерпан до проверки кандидата".into()),
            false,
            0,
        );
    }
    let proof_probe_reserve = usize::from(client_hello.is_some());
    let Some(max_retries) = r2o_discovery_candidate_retry_count(
        probe_budget_remaining.saturating_sub(proof_probe_reserve),
    ) else {
        return (
            Err(
                "бюджета зондов Discovery недостаточно для проверки и подтверждения кандидата"
                    .into(),
            ),
            false,
            0,
        );
    };
    let plan_id = match random_id() {
        Ok(id) => id,
        Err(error) => return (Err(error.to_string()), false, 0),
    };
    let plan_text = match r2o_controller::discovery::plan_text_for_trial(source_text, plan_id) {
        Ok(text) => text,
        Err(error) => return (Err(error), false, 0),
    };
    let destination = match target.endpoint.parse::<std::net::SocketAddr>() {
        Ok(destination) => destination,
        Err(error) => {
            return (
                Err(format!("адрес Discovery-пробы недопустим: {error}")),
                false,
                0,
            );
        }
    };
    let candidate = R2oFamilyRecoveryCandidate {
        plan_id,
        plan_text,
        group_plan: false,
        probe_path: probe_path.into(),
    };
    if target.shape == SHAPE_ECH_TCP && ech_config.is_none() {
        return (
            Err("кандидат ECH нельзя подтвердить без совместимой TLS-конфигурации".into()),
            false,
            0,
        );
    }
    let mut attempts = 0;
    let (result, applied, _) = r2o_repeat_candidate_trials(
        max_retries,
        || {
            attempts += 1;
            let trial = r2o_family_recovery_sibling_trial_with_ech_state(
                target,
                destination,
                &candidate,
                mark,
                commands,
                ech_config,
                packet_budget,
            );
            if let Ok(fetch) = &trial.0
                && r2o_controller::fetch::r2o_fetch_result_can_remember_resources(fetch)
            {
                resource_memory
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remember_hints(&fetch.r2o_resources, std::time::Instant::now());
            }
            trial
        },
        |(result, applied, transport_established)| {
            retry_budget_available()
                && r2o_family_recovery_decision(result, *applied)
                    != R2oFamilyRecoveryDecision::Verified
                && r2o_discovery_candidate_retryable(result, *applied, *transport_established)
        },
    );
    if r2o_family_recovery_decision(&result, applied) == R2oFamilyRecoveryDecision::Verified
        && let Some(client_hello) = client_hello
    {
        let snapshot_applied = r2o_discovery_client_shape_trial(
            target,
            &candidate.plan_text,
            client_hello,
            mark,
            commands,
        )
        .unwrap_or(false);
        attempts += 1;
        return (result, applied && snapshot_applied, attempts);
    }
    (result, applied, attempts)
}

#[cfg(unix)]
fn r2o_discovery_candidate_retry_count(probe_budget_remaining: usize) -> Option<u8> {
    (probe_budget_remaining > 0).then(|| {
        R2O_DISCOVERY_CANDIDATE_VERIFY_RETRIES.min(
            probe_budget_remaining
                .saturating_sub(1)
                .min(u8::MAX as usize) as u8,
        )
    })
}

#[cfg(unix)]
fn r2o_repeat_candidate_trials<T>(
    max_retries: u8,
    mut trial: impl FnMut() -> T,
    mut should_retry: impl FnMut(&T) -> bool,
) -> T {
    for attempt in 0..=max_retries {
        let result = trial();
        if attempt == max_retries || !should_retry(&result) {
            return result;
        }
    }
    unreachable!("цикл повторов кандидата всегда возвращает исход")
}

#[cfg(unix)]
fn r2o_discovery_candidate_retryable(
    result: &Result<r2o_controller::fetch::FetchResult, String>,
    applied: bool,
    transport_established: bool,
) -> bool {
    if !applied {
        return false;
    }
    let Ok(fetch) = result else {
        return transport_established;
    };
    transport_established
        && !fetch.r2o_volume_observation.local_limit
        && !fetch.cloudflare_challenge
        && !matches!(
            fetch.http_outcome,
            r2o_controller::fetch::R2oFetchHttpOutcome::Blocked
                | r2o_controller::fetch::R2oFetchHttpOutcome::LegalDenial
        )
}

#[cfg(unix)]
fn r2o_discovery_client_shape_trial(
    target: &r2o_controller::discovery::DiscoveryTarget,
    source_text: &str,
    client_hello: &[u8],
    mark: Option<u32>,
    commands: &SyncSender<HttpSearchCommand>,
) -> Result<bool, String> {
    let destination = target
        .endpoint
        .parse::<std::net::SocketAddr>()
        .map_err(|error| format!("адрес снимка ClientHello недопустим: {error}"))?;
    let bound = BoundTcpProbe::open(target.family, mark)
        .map_err(|error| format!("не удалось открыть сокет снимка ClientHello: {error}"))?;
    let local_port = bound.local_port;
    let trial_id = random_id().map_err(|error| error.to_string())?;
    let records = compile_text(source_text).map_err(|error| error.to_string())?;
    let plan = Plan::parse(&records).map_err(|error| error.to_string())?;
    let command = encode_set_name_probe(
        &target.host,
        target.shape,
        target.family,
        local_port,
        &records,
        trial_id,
    )
    .map_err(|error| error.to_string())?;
    let ack = ask_http_controller(commands, |reply| HttpSearchCommand::InstallProbe {
        host: target.host.clone(),
        shape: target.shape,
        family: target.family,
        port: local_port,
        command,
        trial_id,
        reply,
    })?;
    if ack.trial_id != Some(trial_id) {
        let _ = ask_http_controller(commands, |reply| HttpSearchCommand::DeleteProbe {
            host: target.host.clone(),
            shape: target.shape,
            family: target.family,
            port: local_port,
            reply,
        });
        return Err("подтверждение пробы снимка содержит чужой trial ID".into());
    }
    if !ack.ok {
        ask_http_controller(commands, |reply| HttpSearchCommand::DeleteProbe {
            host: target.host.clone(),
            shape: target.shape,
            family: target.family,
            port: local_port,
            reply,
        })?;
        return Err("датапат отверг временный план снимка ClientHello".into());
    }

    let send_result = match bound.connect(destination, std::time::Duration::from_secs(8)) {
        Ok((mut stream, _, connected_port, _)) if connected_port == local_port => {
            std::io::Write::write_all(&mut stream, client_hello)
                .map_err(|error| format!("не удалось отправить снимок ClientHello: {error}"))
        }
        Ok((_stream, _, _, _)) => Err("сокет снимка получил неожиданный локальный порт".into()),
        Err(error) => Err(format!("не удалось подключить снимок ClientHello: {error}")),
    };
    let delete_result = ask_http_controller(commands, |reply| HttpSearchCommand::DeleteProbe {
        host: target.host.clone(),
        shape: target.shape,
        family: target.family,
        port: local_port,
        reply,
    });
    let events = r2o_collect_controller_applied_events(
        commands,
        trial_id,
        std::time::Duration::from_millis(500),
    );
    send_result?;
    delete_result?;
    let events = events?;
    Ok(events.iter().any(|event| {
        r2o_family_applied_flow_matches(event, target, local_port, plan.id, trial_id, true)
    }))
}

#[cfg(unix)]
fn r2o_family_applied_flow_matches(
    event: &r2k_core::control::AppliedEvent,
    target: &r2o_controller::discovery::DiscoveryTarget,
    local_port: u16,
    plan_id: [u8; 16],
    trial_id: [u8; 16],
    temporary: bool,
) -> bool {
    let Ok(endpoint) = target.endpoint.parse::<std::net::SocketAddr>() else {
        return false;
    };
    if event.key[0] != target.family
        || event.key[37] != 6
        || event.trial_id != trial_id
        || event.execution_id == 0
        || event.plan_id != plan_id
        || !event.binding.is_known()
        || event.binding.kind != 1
        || event.binding.family != target.family
        || event.binding.shape != target.shape
        || event.binding.temporary != temporary
    {
        return false;
    }
    let low_port = u16::from_be_bytes([event.key[33], event.key[34]]);
    let high_port = u16::from_be_bytes([event.key[35], event.key[36]]);
    let server_bytes = if low_port == local_port && high_port == endpoint.port() {
        &event.key[17..33]
    } else if high_port == local_port && low_port == endpoint.port() {
        &event.key[1..17]
    } else {
        return false;
    };
    match endpoint.ip() {
        std::net::IpAddr::V4(ip) => server_bytes[..4] == ip.octets(),
        std::net::IpAddr::V6(ip) => server_bytes == ip.octets(),
    }
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
                    r2o_controller::fetch::r2o_fetch_measure_rx_volume_with_fallback_path(
                        &input.options,
                        input.alternate_path.as_deref(),
                    )
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
    command_sender: SyncSender<HttpSearchCommand>,
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
        let worker_command_sender = command_sender.clone();
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
                    match run_http_search_task(task, &worker_command_sender, &worker_cancel) {
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
            command_sender,
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

    fn command_sender(&self) -> SyncSender<HttpSearchCommand> {
        self.command_sender.clone()
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
        &mut R2oQuicDiscoveryTask,
        SyncSender<HttpSearchCommand>,
        Arc<AtomicBool>,
    ) -> Result<Option<(String, String)>, String>
    + Send
    + Sync;

#[cfg(unix)]
struct R2oQuicDiscoveryJob {
    task: R2oQuicDiscoveryTask,
    remeasured: Arc<AtomicBool>,
}

#[cfg(unix)]
struct R2oQuicActiveSnapshot {
    host: String,
    remeasured: Arc<AtomicBool>,
}

#[cfg(unix)]
struct R2oQuicDiscoveryWorker {
    jobs: Option<SyncSender<R2oQuicDiscoveryJob>>,
    commands: Option<Receiver<HttpSearchCommand>>,
    outcomes: Receiver<R2oQuicDiscoveryOutcome>,
    cancel: Arc<AtomicBool>,
    active: HashMap<std::net::SocketAddr, R2oQuicActiveSnapshot>,
    pending_snapshots: Arc<std::sync::Mutex<HashMap<std::net::SocketAddr, (Vec<u8>, String)>>>,
    threads: Vec<JoinHandle<()>>,
}

#[cfg(unix)]
impl R2oQuicDiscoveryWorker {
    fn new() -> Self {
        Self::r2o_new_with_runner(Arc::new(|task, commands, cancel| {
            ControlClient::r2o_run_quic_discovery_trial(
                task.server,
                &task.snapshot,
                &task.probe_path,
                &commands,
                &cancel,
                task.started_at,
                &mut task.permit,
                task.r2o_mark,
                task.deny_recheck,
                &mut task.stall_cut,
            )
            .map_err(|error| error.to_string())
        }))
    }

    fn r2o_new_with_runner(runner: Arc<R2oQuicDiscoveryRunner>) -> Self {
        let (jobs, job_receiver) =
            mpsc::sync_channel::<R2oQuicDiscoveryJob>(R2O_QUIC_DISCOVERY_WORKER_COUNT);
        let job_receiver = Arc::new(std::sync::Mutex::new(job_receiver));
        let (command_sender, commands) = mpsc::sync_channel::<HttpSearchCommand>(16);
        let (outcome_sender, outcomes) =
            mpsc::sync_channel::<R2oQuicDiscoveryOutcome>(R2O_QUIC_DISCOVERY_WORKER_COUNT);
        let cancel = Arc::new(AtomicBool::new(false));
        let pending_snapshots = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut threads = Vec::with_capacity(R2O_QUIC_DISCOVERY_WORKER_COUNT);
        for _ in 0..R2O_QUIC_DISCOVERY_WORKER_COUNT {
            let worker_jobs = Arc::clone(&job_receiver);
            let worker_commands = command_sender.clone();
            let worker_outcomes = outcome_sender.clone();
            let worker_cancel = Arc::clone(&cancel);
            let worker_snapshots = Arc::clone(&pending_snapshots);
            let worker_runner = Arc::clone(&runner);
            threads.push(std::thread::spawn(move || {
                loop {
                    let job = worker_jobs
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv();
                    let Ok(mut job) = job else {
                        break;
                    };
                    if worker_cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let server = job.task.server;
                    let deny_recheck = job.task.deny_recheck;
                    let mut result = worker_runner(
                        &mut job.task,
                        worker_commands.clone(),
                        Arc::clone(&worker_cancel),
                    );
                    let replacement = {
                        let mut snapshots = worker_snapshots
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let replacement = if !worker_cancel.load(Ordering::Relaxed)
                            && !job.remeasured.load(Ordering::Relaxed)
                        {
                            snapshots.remove(&server)
                        } else {
                            snapshots.remove(&server);
                            None
                        };
                        job.remeasured.store(true, Ordering::Relaxed);
                        replacement
                    };
                    if let Some((snapshot, probe_path)) = replacement {
                        job.task.snapshot = snapshot;
                        job.task.probe_path = probe_path;
                        job.task.stall_cut = false;
                        result = worker_runner(
                            &mut job.task,
                            worker_commands.clone(),
                            Arc::clone(&worker_cancel),
                        );
                    }
                    worker_snapshots
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&server);
                    if worker_outcomes
                        .send(R2oQuicDiscoveryOutcome {
                            server,
                            snapshot: job.task.snapshot.clone(),
                            host: r2o_quic_snapshot_server_name(&job.task.snapshot, server)
                                .unwrap_or_else(|| server.ip().to_string()),
                            probe_path: job.task.probe_path.clone(),
                            deny_recheck,
                            stall_cut: job.task.stall_cut,
                            result,
                        })
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
            active: HashMap::new(),
            pending_snapshots,
            threads,
        }
    }

    fn queue(&mut self, task: R2oQuicDiscoveryTask) -> bool {
        let server = task.server;
        if self.active.contains_key(&server) {
            return false;
        }
        let Some(host) = r2o_quic_snapshot_server_name(&task.snapshot, server) else {
            return false;
        };
        let Some(jobs) = self.jobs.as_ref() else {
            return false;
        };
        let remeasured = Arc::new(AtomicBool::new(false));
        if jobs
            .try_send(R2oQuicDiscoveryJob {
                task,
                remeasured: Arc::clone(&remeasured),
            })
            .is_err()
        {
            return false;
        }
        self.active
            .insert(server, R2oQuicActiveSnapshot { host, remeasured });
        true
    }

    fn queue_client_snapshot(
        &self,
        hello: &r2k_core::control::HelloEvent,
        catalog: &Catalog,
        resource_memory: &std::sync::Mutex<r2o_controller::r2o_resource::R2oResourceMemory>,
    ) -> bool {
        if hello.key[37] != 17 || hello.shape != Some(SHAPE_QUIC) {
            return false;
        }
        let Some(snapshot) = hello.quic_snapshot.as_ref() else {
            return false;
        };
        let (low, high) = flow_socket_addresses(&hello.key, true);
        let event_host = match hello.host.as_deref() {
            Some(host) => match std::str::from_utf8(host) {
                Ok(host) => Some(host),
                Err(_) => return false,
            },
            None => None,
        };
        for (server, active) in &self.active {
            if *server != low && *server != high {
                continue;
            }
            if active.remeasured.load(Ordering::Relaxed) {
                return false;
            }
            let matches_host = event_host.map_or_else(
                || active.host == server.ip().to_string(),
                |host| active.host == host,
            );
            if !matches_host {
                return false;
            }
            let mut snapshots = self
                .pending_snapshots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if active.remeasured.load(Ordering::Relaxed) {
                return false;
            }
            let probe_path =
                r2o_quic_discovery_probe_path(snapshot, *server, catalog, resource_memory);
            snapshots.insert(*server, (snapshot.clone(), probe_path));
            return true;
        }
        false
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
        self.pending_snapshots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&outcome.server);
        Some(outcome)
    }

    fn r2o_begin_shutdown(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs.take();
        self.pending_snapshots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    fn r2o_all_finished(&self) -> bool {
        self.threads.iter().all(JoinHandle::is_finished)
    }

    fn r2o_join(&mut self) {
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        self.commands.take();
    }
}

#[cfg(unix)]
impl Drop for R2oQuicDiscoveryWorker {
    fn drop(&mut self) {
        self.r2o_begin_shutdown();
        self.commands.take();
        self.r2o_join();
    }
}

#[cfg(unix)]
fn watch(socket_path: PathBuf) -> Result<(), Box<dyn Error>> {
    ControlClient::connect(socket_path)?.watch_events(None, None, None, None, HashSet::new())
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
    direct_clear: bool,
    volume_recovery: bool,
    volume_fingerprint: Option<r2o_controller::catalog::Fingerprint>,
    volume_box_id: Option<String>,
    retry_after: Option<std::time::Duration>,
}

#[cfg(unix)]
struct R2oDiscoveryWorkOutcome {
    outcome: DiscoveryOutcome,
    catalog_generation: u64,
}

#[cfg(unix)]
impl std::ops::Deref for R2oDiscoveryWorkOutcome {
    type Target = DiscoveryOutcome;

    fn deref(&self) -> &Self::Target {
        &self.outcome
    }
}

#[cfg(unix)]
type R2oDiscoveryRunner = dyn Fn(r2o_controller::discovery::DiscoveryTarget, Arc<AtomicBool>) -> DiscoveryOutcome
    + Send
    + Sync;

#[cfg(unix)]
const R2O_DISCOVERY_TASK_CAPACITY: usize = 64;
// Matches SCHED_REST_MS: failed and direct-clear tasks keep a scheduler slot for two minutes.
const R2O_DISCOVERY_TASK_REST: std::time::Duration = std::time::Duration::from_secs(120);
#[cfg(unix)]
const R2O_DISCOVERY_WORKER_COUNT: usize = R2O_AUTOMATED_MEASUREMENT_SLOTS;
#[cfg(unix)]
const R2O_DISCOVERY_TASK_LIFETIME: std::time::Duration = std::time::Duration::from_secs(10 * 60);
#[cfg(unix)]
fn r2o_quic_trial_remaining_at(
    started: std::time::Instant,
    yielded: std::time::Duration,
    now: std::time::Instant,
) -> std::time::Duration {
    R2O_DISCOVERY_TASK_LIFETIME.saturating_sub(
        now.saturating_duration_since(started)
            .saturating_sub(yielded),
    )
}
#[cfg(unix)]
fn r2o_quic_trial_remaining(
    started: std::time::Instant,
    permit: &r2o_controller::r2o_resource_limit::R2oMeasurementPermit,
) -> std::time::Duration {
    r2o_quic_trial_remaining_at(
        started,
        permit.r2o_yielded_duration(),
        std::time::Instant::now(),
    )
}
#[cfg(unix)]
const R2O_DISCOVERY_ECH_INPUT_CAPACITY: usize = 8;
#[cfg(unix)]
const R2O_DISCOVERY_ECH_RR_CAPACITY: usize = 256;
#[cfg(unix)]
const R2O_DISCOVERY_ECH_RR_POSITIVE_TTL: std::time::Duration =
    std::time::Duration::from_secs(6 * 60 * 60);
#[cfg(unix)]
const R2O_DISCOVERY_ECH_RR_NEGATIVE_TTL: std::time::Duration =
    std::time::Duration::from_secs(30 * 60);
#[cfg(unix)]
const R2O_ECH_RX_LADDER_BATCH: usize = 32;
#[cfg(unix)]
const R2O_DISCOVERY_FAILURE_RETRY: std::time::Duration = std::time::Duration::from_secs(120);
#[cfg(unix)]
const R2O_DISCOVERY_CHALLENGE_RETRY: std::time::Duration = std::time::Duration::from_secs(60 * 60);
#[cfg(unix)]
const R2O_VOLUME_LADDER_BATCH: usize = 32;
const R2O_VOLUME_TX_LADDER_PACKET_BUDGET: u32 = 50;
#[cfg(unix)]
const R2O_VOLUME_SEARCH_CACHE_CAPACITY: usize = 256;
#[cfg(unix)]
const R2O_DISCOVERY_CHALLENGE_COOLDOWN_CAPACITY: usize = 128;
#[cfg(unix)]
const R2O_DISCOVERY_CLEAR_RETRY_FIRST: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);
#[cfg(unix)]
const R2O_DISCOVERY_CLEAR_RETRY_SECOND: std::time::Duration =
    std::time::Duration::from_secs(30 * 60);
#[cfg(unix)]
const R2O_DISCOVERY_CLEAR_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(60 * 60);
#[cfg(unix)]
const R2O_DISCOVERY_INCOMPLETE_RETRY: std::time::Duration = std::time::Duration::from_secs(10 * 60);
#[cfg(unix)]
const R2O_DISCOVERY_CANDIDATE_VERIFY_RETRIES: u8 = 2;
// 5 property questions + 8 queued plans + 5 RX variants + 49 fallback arms.
#[cfg(unix)]
const R2O_DISCOVERY_PROBE_CAP: usize = 67;

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct R2oDiscoveryVolumeSearchKey {
    wire_len: Option<usize>,
    send_cap: usize,
    probe_path: String,
    alternate_path: Option<String>,
    network_probe: bool,
    white_name: String,
}

#[cfg(unix)]
#[derive(Clone)]
struct R2oDiscoveryVolumeSearch {
    key: R2oDiscoveryVolumeSearchKey,
    measured_at: std::time::Instant,
    tx: Result<r2o_controller::fetch::R2oFetchVolumeTxResult, String>,
    rx: r2o_controller::fetch::R2oFetchVolumeRxResult,
    next_candidate: usize,
    tried_plans: Vec<String>,
}

#[cfg(unix)]
#[derive(Default)]
struct R2oDiscoveryVolumeSearchCache {
    entries: VecDeque<(
        r2o_controller::discovery::DiscoveryTarget,
        R2oDiscoveryVolumeSearch,
    )>,
}

#[cfg(unix)]
impl R2oDiscoveryVolumeSearchCache {
    fn get(
        &mut self,
        target: &r2o_controller::discovery::DiscoveryTarget,
        key: &R2oDiscoveryVolumeSearchKey,
        now: std::time::Instant,
    ) -> Option<R2oDiscoveryVolumeSearch> {
        self.entries.retain(|(_, search)| {
            now.saturating_duration_since(search.measured_at) < R2O_DISCOVERY_TASK_LIFETIME
        });
        let index = self
            .entries
            .iter()
            .position(|(candidate, _)| candidate == target)?;
        if self.entries[index].1.key != *key {
            self.entries.remove(index);
            return None;
        }
        let entry = self.entries.remove(index)?;
        let search = entry.1.clone();
        self.entries.push_back(entry);
        Some(search)
    }

    fn insert(
        &mut self,
        target: r2o_controller::discovery::DiscoveryTarget,
        search: R2oDiscoveryVolumeSearch,
    ) {
        self.entries.retain(|(candidate, _)| candidate != &target);
        self.entries.push_back((target, search));
        while self.entries.len() > R2O_VOLUME_SEARCH_CACHE_CAPACITY {
            self.entries.pop_front();
        }
    }

    fn remove(&mut self, target: &r2o_controller::discovery::DiscoveryTarget) {
        self.entries.retain(|(candidate, _)| candidate != target);
    }
}

#[cfg(unix)]
const R2O_CLEAN_HANDSHAKE_CAPACITY: usize = 16;
#[cfg(unix)]
const R2O_CLEAN_HANDSHAKE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
#[cfg(unix)]
const R2O_TCP_HELLO_CAPACITY: usize = 128;
#[cfg(unix)]
const R2O_RECENT_TCP_NAME_CAPACITY: usize = 512;
#[cfg(unix)]
const R2O_RECENT_TCP_NAME_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

#[cfg(unix)]
struct R2oEchWitnessResolution {
    name: String,
    config: Option<r2o_controller::ech::R2oEchConfig>,
    checked_at: std::time::Instant,
}

#[cfg(unix)]
struct R2oEchWitnessResolutionCache {
    entries: Vec<Option<R2oEchWitnessResolution>>,
    next: usize,
}

#[cfg(unix)]
impl Default for R2oEchWitnessResolutionCache {
    fn default() -> Self {
        Self {
            entries: std::iter::repeat_with(|| None)
                .take(R2O_DISCOVERY_ECH_RR_CAPACITY)
                .collect(),
            next: 0,
        }
    }
}

#[cfg(unix)]
impl R2oEchWitnessResolutionCache {
    fn lookup(
        &self,
        name: &str,
        now: std::time::Instant,
    ) -> Option<Option<r2o_controller::ech::R2oEchConfig>> {
        let entry = self
            .entries
            .iter()
            .flatten()
            .find(|entry| entry.name == name)?;
        let ttl = if entry.config.is_some() {
            R2O_DISCOVERY_ECH_RR_POSITIVE_TTL
        } else {
            R2O_DISCOVERY_ECH_RR_NEGATIVE_TTL
        };
        (now.saturating_duration_since(entry.checked_at) <= ttl).then(|| entry.config.clone())
    }

    fn cached_witness_names(&self, public_name: &str, now: std::time::Instant) -> Vec<String> {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| {
                now.saturating_duration_since(entry.checked_at) <= R2O_DISCOVERY_ECH_RR_POSITIVE_TTL
                    && entry
                        .config
                        .as_ref()
                        .is_some_and(|config| config.public_name == public_name)
            })
            .take(r2o_controller::discovery::R2O_ECH_WITNESS_LIMIT)
            .map(|entry| entry.name.clone())
            .collect()
    }

    fn store(
        &mut self,
        name: &str,
        config: Option<r2o_controller::ech::R2oEchConfig>,
        now: std::time::Instant,
    ) {
        let slot = if let Some(slot) = self
            .entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.name == name))
        {
            slot
        } else {
            let slot = self.next;
            self.next = (self.next + 1) % R2O_DISCOVERY_ECH_RR_CAPACITY;
            slot
        };
        self.entries[slot] = Some(R2oEchWitnessResolution {
            name: name.to_owned(),
            config,
            checked_at: now,
        });
    }
}

#[cfg(unix)]
fn r2o_merge_ech_witness_candidates(
    public_name: &str,
    cached: &[String],
    discovered: &[String],
) -> Vec<String> {
    let mut candidates = Vec::with_capacity(r2o_controller::discovery::R2O_ECH_WITNESS_LIMIT);
    for name in cached.iter().chain(discovered) {
        if name.is_empty()
            || name == public_name
            || candidates.len() >= r2o_controller::discovery::R2O_ECH_WITNESS_LIMIT
            || candidates.iter().any(|candidate| candidate == name)
        {
            continue;
        }
        candidates.push(name.clone());
    }
    candidates
}

#[cfg(unix)]
#[derive(Default)]
struct R2oCleanHandshakeCache {
    entries: VecDeque<(String, u8, std::time::Instant)>,
}

#[cfg(unix)]
impl R2oCleanHandshakeCache {
    fn note(&mut self, name: &str, family: u8, now: std::time::Instant) {
        self.entries
            .retain(|(_, _, seen)| now.saturating_duration_since(*seen) <= R2O_CLEAN_HANDSHAKE_TTL);
        if let Some((_, _, seen)) = self
            .entries
            .iter_mut()
            .find(|(entry_name, entry_family, _)| entry_name == name && *entry_family == family)
        {
            *seen = now;
            return;
        }
        if self.entries.len() == R2O_CLEAN_HANDSHAKE_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back((name.to_owned(), family, now));
    }

    fn r2o_recent(&self, name: &str, family: u8, now: std::time::Instant) -> bool {
        self.entries.iter().any(|(entry_name, entry_family, seen)| {
            entry_name == name
                && *entry_family == family
                && now.saturating_duration_since(*seen) <= R2O_CLEAN_HANDSHAKE_TTL
        })
    }

    fn suppresses_unplanned_tcp_suspicion(
        &self,
        name: &str,
        family: u8,
        planned: bool,
        now: std::time::Instant,
    ) -> bool {
        !planned && self.r2o_recent(name, family, now)
    }
}

#[cfg(unix)]
#[derive(Default)]
struct R2oTcpHelloCache {
    entries: HashMap<[u8; r2k_core::control::KEY_LEN], (HelloEvent, std::time::Instant)>,
}

#[cfg(unix)]
impl R2oTcpHelloCache {
    fn note(&mut self, hello: HelloEvent, now: std::time::Instant) {
        self.entries
            .retain(|_, (_, seen)| now.saturating_duration_since(*seen) <= R2O_CLEAN_HANDSHAKE_TTL);
        if self.entries.len() >= R2O_TCP_HELLO_CAPACITY
            && !self.entries.contains_key(&hello.key)
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(key, _)| *key)
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(hello.key, (hello, now));
    }

    fn clean_handshake_name(
        &self,
        key: &[u8; r2k_core::control::KEY_LEN],
        now: std::time::Instant,
    ) -> Option<String> {
        let (hello, seen) = self.entries.get(key)?;
        if now.saturating_duration_since(*seen) > R2O_CLEAN_HANDSHAKE_TTL {
            return None;
        }
        hello
            .host
            .as_deref()
            .and_then(|host| std::str::from_utf8(host).ok())
            .filter(|host| !host.is_empty())
            .and_then(|host| r2o_controller::domain::normalize(host).ok())
    }

    fn target_for_tcp_flow(
        &self,
        key: &[u8; r2k_core::control::KEY_LEN],
        now: std::time::Instant,
    ) -> Option<r2o_controller::discovery::DiscoveryTarget> {
        let (hello, seen) = self.entries.get(key)?;
        if now.saturating_duration_since(*seen) > R2O_CLEAN_HANDSHAKE_TTL {
            return None;
        }
        r2o_controller::discovery::DiscoveryTarget::from_event(hello)
    }
}

#[cfg(unix)]
#[derive(Default)]
struct R2oRecentTcpNameCache {
    entries: Vec<Option<([u8; r2k_core::control::KEY_LEN], String, std::time::Instant)>>,
    next: usize,
}

#[cfg(unix)]
impl R2oRecentTcpNameCache {
    fn note(&mut self, hello: &HelloEvent, now: std::time::Instant) {
        if hello.key[37] != 6 {
            return;
        }
        let Some(name) = hello
            .host
            .as_deref()
            .and_then(|host| std::str::from_utf8(host).ok())
            .and_then(|host| r2o_controller::domain::normalize(host).ok())
        else {
            return;
        };

        if let Some((_, seen_name, seen_at)) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|(key, _, _)| key == &hello.key)
        {
            *seen_name = name;
            *seen_at = now;
            return;
        }

        let entry = Some((hello.key, name, now));
        if self.entries.len() < R2O_RECENT_TCP_NAME_CAPACITY {
            self.entries.push(entry);
        } else {
            self.entries[self.next] = entry;
            self.next = (self.next + 1) % R2O_RECENT_TCP_NAME_CAPACITY;
        }
    }

    fn ech_witness_names(
        &self,
        target: &r2o_controller::discovery::DiscoveryTarget,
        now: std::time::Instant,
    ) -> Vec<(String, bool)> {
        let Ok(endpoint) = target.endpoint.parse::<std::net::SocketAddr>() else {
            return Vec::new();
        };
        self.entries
            .iter()
            .flatten()
            .filter_map(|(key, name, seen_at)| {
                if now.saturating_duration_since(*seen_at) > R2O_RECENT_TCP_NAME_TTL
                    || key[0] != target.family
                {
                    return None;
                }
                let same_address = match (target.family, endpoint.ip()) {
                    (4, std::net::IpAddr::V4(address)) => {
                        key[1..5] == address.octets() || key[17..21] == address.octets()
                    }
                    (6, std::net::IpAddr::V6(address)) => {
                        key[1..17] == address.octets() || key[17..33] == address.octets()
                    }
                    _ => false,
                };
                Some((name.clone(), same_address))
            })
            .collect()
    }
}

#[cfg(unix)]
#[derive(Default)]
struct R2oDiscoveryQueue {
    entries: Vec<R2oDiscoveryQueueEntry>,
    event_sequence: u64,
    catalog_generation: u64,
    #[cfg(test)]
    waiting_for_slot: usize,
}

#[cfg(unix)]
struct R2oDiscoveryQueueEntry {
    target: r2o_controller::discovery::DiscoveryTarget,
    queued_at: std::time::Instant,
    queued_event: u64,
    hot_event: u64,
}

#[cfg(unix)]
type R2oDiscoveryTaskKey = (String, u8, u8);

#[cfg(unix)]
type R2oDiscoveryFailureKey = (String, u8, u8, String);

#[cfg(unix)]
fn r2o_discovery_transport(target: &r2o_controller::discovery::DiscoveryTarget) -> u8 {
    if target.shape == SHAPE_QUIC { 17 } else { 6 }
}

#[cfg(unix)]
fn r2o_discovery_task_key(
    target: &r2o_controller::discovery::DiscoveryTarget,
) -> R2oDiscoveryTaskKey {
    (
        target.host.clone(),
        r2o_discovery_transport(target),
        target.family,
    )
}

#[cfg(unix)]
fn r2o_live_timestamp(seen: std::time::Instant, now: std::time::Instant) -> Option<String> {
    let elapsed = now.saturating_duration_since(seen).as_secs();
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .saturating_sub(elapsed);
    time::OffsetDateTime::from_unix_timestamp(i64::try_from(unix).ok()?)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

#[cfg(unix)]
#[derive(Default)]
struct R2oRecentClientShapeCache {
    entries: [Option<R2oCachedClientShape>; 2],
}

#[cfg(unix)]
struct R2oCachedClientShape {
    host: String,
    shape: u8,
    client_hello: Vec<u8>,
}

#[cfg(unix)]
impl R2oRecentClientShapeCache {
    fn note(&mut self, target: &r2o_controller::discovery::DiscoveryTarget, client_hello: &[u8]) {
        let Some(index) = r2o_client_shape_family_slot(target.family) else {
            return;
        };
        self.entries[index] = Some(R2oCachedClientShape {
            host: target.host.clone(),
            shape: target.shape,
            client_hello: client_hello.to_vec(),
        });
    }

    fn get(&self, target: &r2o_controller::discovery::DiscoveryTarget) -> Option<&[u8]> {
        let index = r2o_client_shape_family_slot(target.family)?;
        let entry = self.entries[index].as_ref()?;
        (entry.host == target.host && entry.shape == target.shape)
            .then_some(entry.client_hello.as_slice())
    }
}

#[cfg(unix)]
fn r2o_client_shape_family_slot(family: u8) -> Option<usize> {
    match family {
        4 => Some(0),
        6 => Some(1),
        _ => None,
    }
}

#[cfg(unix)]
fn r2o_discovery_failure_key(
    target: &r2o_controller::discovery::DiscoveryTarget,
) -> R2oDiscoveryFailureKey {
    (
        target.host.clone(),
        r2o_discovery_transport(target),
        target.family,
        target.endpoint.clone(),
    )
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
        if self.entries.len() >= R2O_DISCOVERY_TASK_CAPACITY {
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
            .find(|entry| r2o_discovery_task_key(&entry.target) == r2o_discovery_task_key(target))
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
    r2o_mark: Option<u32>,
    permit: Option<r2o_controller::r2o_resource_limit::R2oMeasurementPermit>,
    deny_recheck: bool,
}

#[cfg(unix)]
fn r2o_enqueue_quic_discovery(
    pending: &mut VecDeque<R2oPendingQuicDiscovery>,
    server: std::net::SocketAddr,
    snapshot: Vec<u8>,
    captured: std::time::Instant,
    r2o_mark: Option<u32>,
    gate: &r2o_controller::r2o_resource_limit::R2oMeasurementGate,
    deny_recheck: bool,
) -> usize {
    let pending_entry = R2oPendingQuicDiscovery {
        server,
        snapshot,
        captured,
        r2o_mark,
        permit: gate.r2o_try_acquire(),
        deny_recheck,
    };
    if deny_recheck {
        pending.push_front(pending_entry);
    } else {
        pending.push_back(pending_entry);
    }
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
        .or_else(|| gate.r2o_try_acquire_queued())?;
    let entry = pending.pop_front()?;
    Some((entry, permit))
}

#[cfg(unix)]
struct DiscoveryWorker {
    jobs: Arc<(std::sync::Mutex<R2oDiscoveryQueue>, std::sync::Condvar)>,
    client_hellos: Arc<std::sync::Mutex<HashMap<R2oDiscoveryTaskKey, Vec<u8>>>>,
    recent_client_shapes: R2oRecentClientShapeCache,
    resource_memory: Arc<std::sync::Mutex<r2o_controller::r2o_resource::R2oResourceMemory>>,
    active_cancels: Arc<std::sync::Mutex<HashMap<R2oDiscoveryTaskKey, Arc<AtomicBool>>>>,
    catalog_refreshes: Arc<std::sync::Mutex<HashSet<R2oDiscoveryTaskKey>>>,
    outcomes: Receiver<R2oDiscoveryWorkOutcome>,
    cancel: Arc<AtomicBool>,
    seen: HashSet<r2o_controller::discovery::DiscoveryTarget>,
    seen_order: VecDeque<r2o_controller::discovery::DiscoveryTarget>,
    failed_at: HashMap<R2oDiscoveryFailureKey, std::time::Instant>,
    failed_retry_after: HashMap<R2oDiscoveryFailureKey, std::time::Duration>,
    challenge_cooldowns: HashMap<(String, u8), std::time::Instant>,
    ech_input_clearable_failures: HashSet<R2oDiscoveryFailureKey>,
    ech_input_names: VecDeque<(String, u8)>,
    clear_streaks: HashMap<R2oDiscoveryFailureKey, u8>,
    client_snapshot_targets: HashSet<r2o_controller::discovery::DiscoveryTarget>,
    pending_rechecks:
        HashMap<R2oDiscoveryTaskKey, (r2o_controller::discovery::DiscoveryTarget, Option<Vec<u8>>)>,
    active: HashMap<R2oDiscoveryTaskKey, r2o_controller::discovery::DiscoveryTarget>,
    completed: HashSet<R2oDiscoveryTaskKey>,
    threads: Vec<JoinHandle<()>>,
}

#[cfg(unix)]
#[cfg(test)]
fn r2o_discovery_failure_retry_due(failed_at: std::time::Instant, now: std::time::Instant) -> bool {
    r2o_discovery_failure_retry_due_after(failed_at, now, R2O_DISCOVERY_FAILURE_RETRY)
}

#[cfg(unix)]
fn r2o_discovery_failure_retry_due_after(
    failed_at: std::time::Instant,
    now: std::time::Instant,
    retry_after: std::time::Duration,
) -> bool {
    now.saturating_duration_since(failed_at) >= retry_after
}

#[cfg(unix)]
fn r2o_run_with_deadline<T>(
    worker_cancel: Arc<AtomicBool>,
    lifetime: std::time::Duration,
    run: impl FnOnce(Arc<AtomicBool>) -> T,
) -> (T, bool) {
    let r2o_deadline = std::time::Instant::now() + lifetime;
    let r2o_task_cancel = Arc::new(AtomicBool::new(false));
    let r2o_watch_cancel = Arc::clone(&r2o_task_cancel);
    let r2o_worker_cancel = Arc::clone(&worker_cancel);
    let (r2o_stop_sender, r2o_stop_receiver) = std::sync::mpsc::channel();
    let r2o_watch = std::thread::spawn(move || {
        loop {
            if r2o_worker_cancel.load(Ordering::Relaxed) {
                r2o_watch_cancel.store(true, Ordering::Relaxed);
                break;
            }
            let r2o_now = std::time::Instant::now();
            if r2o_now > r2o_deadline {
                r2o_watch_cancel.store(true, Ordering::Relaxed);
                break;
            }
            let r2o_remaining = r2o_deadline.saturating_duration_since(r2o_now);
            match r2o_stop_receiver
                .recv_timeout(r2o_remaining.min(std::time::Duration::from_millis(50)))
            {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    });

    let r2o_result = run(Arc::clone(&r2o_task_cancel));
    let r2o_timed_out =
        std::time::Instant::now() > r2o_deadline && !worker_cancel.load(Ordering::Relaxed);
    let _ = r2o_stop_sender.send(());
    let _ = r2o_watch.join();
    (r2o_result, r2o_timed_out)
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct R2oVoiceDiscoveryJob {
    target: r2o_controller::voice_discovery::R2oVoiceTarget,
    flow: Option<r2o_controller::voice_targets::R2oVoiceTarget>,
    known_prefix: Option<[u8; 20]>,
    started_at: std::time::Instant,
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
    started_at: std::time::Instant,
    result: r2o_controller::voice_discovery::R2oDiscoverySearchResult,
    fallback: Option<R2oVoiceMeasurement>,
}

#[cfg(unix)]
fn r2o_voice_fallback_after_discovery<F>(
    r2o_result: &r2o_controller::voice_discovery::R2oDiscoverySearchResult,
    r2o_flow: Option<r2o_controller::voice_targets::R2oVoiceTarget>,
    r2o_fallback: F,
) -> Option<R2oVoiceMeasurement>
where
    F: FnOnce(r2o_controller::voice_targets::R2oVoiceTarget) -> R2oVoiceMeasurement,
{
    if !matches!(
        r2o_result.verdict,
        r2o_controller::voice_discovery::R2oDiscoveryVerdict::Continue
    ) {
        return None;
    }
    Some(r2o_fallback(r2o_flow?))
}

#[cfg(unix)]
const R2O_VOICE_DISCOVERY_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(120);

#[cfg(unix)]
const R2O_VOICE_DISCOVERY_SEEN_LIMIT: usize = 128;

#[cfg(unix)]
const R2O_VOICE_TRIAL_TASK_LIFETIME: std::time::Duration = std::time::Duration::from_secs(600);

#[cfg(unix)]
const R2O_VOICE_PENDING_GRACE: std::time::Duration = std::time::Duration::from_secs(120);

#[cfg(unix)]
const R2O_VOICE_TRIAL_RENEW_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(VOICE_ADDR_PROBE_LEASE_MAX_MS as u64 / 2);

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

    fn r2o_remove(&mut self, target: &r2o_controller::voice_discovery::R2oVoiceTarget) {
        self.r2o_targets.remove(target);
        self.r2o_order.retain(|(queued, _)| queued != target);
    }
}

#[cfg(unix)]
#[derive(Clone)]
struct R2oVoiceTrialContext {
    target: r2o_controller::voice_discovery::R2oVoiceTarget,
    trial_id: [u8; 16],
    plan_text: String,
    voice_flow_key: Option<[u8; r2k_core::control::KEY_LEN]>,
    started_at: std::time::Instant,
    renew_at: std::time::Instant,
    expires_at: std::time::Instant,
    response_confirmed: bool,
}

#[cfg(unix)]
fn r2o_hold_voice_trial_until_expiry(trial: &mut R2oVoiceTrialContext) {
    trial.voice_flow_key = None;
    trial.renew_at = trial.expires_at;
}

#[cfg(unix)]
enum R2oVoiceTrialInstallOutcome {
    Installed(R2oVoiceTrialContext),
    LocalRefusal,
    NotInstalled,
}

#[cfg(unix)]
impl R2oVoiceDiscoverySeen {
    fn r2o_after_trial_install(
        &mut self,
        target: &r2o_controller::voice_discovery::R2oVoiceTarget,
        outcome: &R2oVoiceTrialInstallOutcome,
    ) {
        // Совпавший NAK — местный отказ runtime, а не провал цели.
        if matches!(outcome, R2oVoiceTrialInstallOutcome::LocalRefusal) {
            self.r2o_remove(target);
        }
    }
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
                let (r2o_result, r2o_fallback) = {
                    let Some(_permit) = r2o_worker_gate.r2o_acquire(&r2o_worker_cancel) else {
                        break;
                    };
                    let r2o_result = r2o_controller::voice_discovery::r2o_search_discovery_endpoint(
                        r2o_job.target.server,
                        r2o_job.known_prefix,
                        std::time::Duration::from_secs(3),
                        mark,
                    );
                    let r2o_fallback =
                        r2o_voice_fallback_after_discovery(&r2o_result, r2o_job.flow, |r2o_flow| {
                            let r2o_options = R2oVoiceOptions {
                                address: Some(std::net::SocketAddrV4::new(
                                    r2o_flow.server_ip,
                                    r2o_flow.server_port,
                                )),
                                control: r2o_controller::voice_measure::R2O_VOICE_DEFAULT_CONTROL
                                    .into(),
                                conntrack_path: None,
                                wait: std::time::Duration::from_secs(3),
                                mark,
                                discovery: false,
                            };
                            r2o_measure_voice_for_flow(&r2o_options, r2o_flow)
                        });
                    (r2o_result, r2o_fallback)
                };
                let r2o_started_at = r2o_job.started_at;
                if r2o_outcome_sender
                    .send(R2oVoiceDiscoveryOutcome {
                        target: r2o_job.target,
                        started_at: r2o_started_at,
                        result: r2o_result,
                        fallback: r2o_fallback,
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

    fn queue_with_flow(
        &mut self,
        target: r2o_controller::voice_discovery::R2oVoiceTarget,
        known_prefix: Option<[u8; 20]>,
        flow: Option<r2o_controller::voice_targets::R2oVoiceTarget>,
        can_start: bool,
    ) -> bool {
        let r2o_now = std::time::Instant::now();
        if self.r2o_seen.r2o_contains(&target, r2o_now)
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
            flow,
            known_prefix,
            started_at: r2o_now,
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

    fn queue_after_new_session_with_flow(
        &mut self,
        target: r2o_controller::voice_discovery::R2oVoiceTarget,
        known_prefix: Option<[u8; 20]>,
        flow: Option<r2o_controller::voice_targets::R2oVoiceTarget>,
        can_start: bool,
    ) -> bool {
        self.r2o_seen.r2o_remove(&target);
        self.queue_with_flow(target, known_prefix, flow, can_start)
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
fn r2o_take_stale_pending_voice_trials(
    trials: &mut HashMap<[u8; 16], R2oVoiceTrialContext>,
    now: std::time::Instant,
    has_pending_target: bool,
) -> Vec<R2oVoiceTrialContext> {
    if !has_pending_target {
        return Vec::new();
    }
    let stale_ids: Vec<_> = trials
        .iter()
        .filter(|(_, trial)| {
            trial.expires_at > now
                && now.saturating_duration_since(trial.started_at) >= R2O_VOICE_PENDING_GRACE
        })
        .map(|(trial_id, _)| *trial_id)
        .collect();
    stale_ids
        .into_iter()
        .filter_map(|trial_id| trials.remove(&trial_id))
        .collect()
}

#[cfg(unix)]
fn r2o_take_due_voice_trial_renewals(
    trials: &mut HashMap<[u8; 16], R2oVoiceTrialContext>,
    now: std::time::Instant,
) -> Vec<R2oVoiceTrialContext> {
    let due_ids: Vec<_> = trials
        .iter()
        .filter(|(_, trial)| trial.renew_at <= now && trial.expires_at > now)
        .map(|(trial_id, _)| *trial_id)
        .collect();
    due_ids
        .into_iter()
        .filter_map(|trial_id| {
            let trial = trials.get_mut(&trial_id)?;
            trial.renew_at = now + R2O_VOICE_TRIAL_RENEW_INTERVAL;
            Some(trial.clone())
        })
        .collect()
}

#[cfg(unix)]
fn r2o_voice_target_has_active_trial(
    trials: &HashMap<[u8; 16], R2oVoiceTrialContext>,
    target: &r2o_controller::voice_discovery::R2oVoiceTarget,
) -> bool {
    trials.values().any(|trial| &trial.target == target)
}

#[cfg(unix)]
fn r2o_voice_applied_flow_matches(
    trial: &R2oVoiceTrialContext,
    event: &r2k_core::control::AppliedEvent,
) -> bool {
    let key = &event.key;
    if event.trial_id != trial.trial_id
        || event.execution_id == 0
        || !event.binding.is_known()
        || event.binding.kind != 2
        || event.binding.family != 4
        || event.binding.shape != SHAPE_VOICE
        || !event.binding.temporary
        || key[0] != 4
        || key[37] != 17
    {
        return false;
    }
    let Ok(plan_bytes) = compile_text(&trial.plan_text) else {
        return false;
    };
    let Ok(plan) = Plan::parse(&plan_bytes) else {
        return false;
    };
    if plan.transport != 17 || plan.proto != PROTO_VOICE || event.plan_id != plan.id {
        return false;
    }

    let first = std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::new(key[1], key[2], key[3], key[4]),
        u16::from_be_bytes([key[33], key[34]]),
    );
    let second = std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::new(key[17], key[18], key[19], key[20]),
        u16::from_be_bytes([key[35], key[36]]),
    );
    let server = trial.target.server;
    (first.ip() == &trial.target.client && second == server && first.port() != 0)
        || (second.ip() == &trial.target.client && first == server && second.port() != 0)
}

#[cfg(unix)]
fn r2o_take_silent_voice_trial(
    trials: &mut HashMap<[u8; 16], R2oVoiceTrialContext>,
    key: &[u8; r2k_core::control::KEY_LEN],
    target: &r2o_controller::voice_discovery::R2oVoiceTarget,
) -> Option<R2oVoiceTrialContext> {
    let trial_id = trials
        .iter()
        .find(|(_, trial)| &trial.target == target && trial.voice_flow_key.as_ref() == Some(key))
        .map(|(trial_id, _)| *trial_id)?;
    trials.remove(&trial_id)
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
                || !matches!(binding.verified_by, 4 | 5)
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
    #[cfg(test)]
    fn new(
        mark: Option<u32>,
        measurement_gate: r2o_controller::r2o_resource_limit::R2oMeasurementGate,
    ) -> Self {
        let runner: Arc<R2oDiscoveryRunner> =
            Arc::new(move |target, cancel| classify_discovery_target(target, cancel, mark));
        Self::r2o_new_with_runner(measurement_gate, runner)
    }

    fn new_with_confirmation(
        mark: Option<u32>,
        send_cap: Arc<AtomicUsize>,
        measurement_gate: r2o_controller::r2o_resource_limit::R2oMeasurementGate,
        commands: SyncSender<HttpSearchCommand>,
        catalog_path: PathBuf,
        recent_tcp_names: Arc<std::sync::Mutex<R2oRecentTcpNameCache>>,
    ) -> Self {
        let client_hellos = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let runner_client_hellos = Arc::clone(&client_hellos);
        let ech_challenges = Arc::new(std::sync::Mutex::new(
            HashMap::<String, std::time::Instant>::new(),
        ));
        let runner_ech_challenges = Arc::clone(&ech_challenges);
        let runner_recent_tcp_names = Arc::clone(&recent_tcp_names);
        let runner_send_cap = Arc::clone(&send_cap);
        let ech_witness_resolutions = Arc::new(std::sync::Mutex::new(
            R2oEchWitnessResolutionCache::default(),
        ));
        let runner_ech_witness_resolutions = Arc::clone(&ech_witness_resolutions);
        let ech_rx_cursor = Arc::new(std::sync::Mutex::new(HashMap::<
            r2o_controller::discovery::DiscoveryTarget,
            usize,
        >::new()));
        let runner_ech_rx_cursor = Arc::clone(&ech_rx_cursor);
        let resource_memory = Arc::new(std::sync::Mutex::new(
            r2o_controller::r2o_resource::R2oResourceMemory::default(),
        ));
        let runner_resource_memory = Arc::clone(&resource_memory);
        let volume_searches = Arc::new(std::sync::Mutex::new(
            R2oDiscoveryVolumeSearchCache::default(),
        ));
        let runner_volume_searches = Arc::clone(&volume_searches);
        let runner: Arc<R2oDiscoveryRunner> = Arc::new(move |target, cancel| {
            let runner_started = std::time::Instant::now();
            let client_hello = runner_client_hellos
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&r2o_discovery_task_key(&target))
                .cloned();
            let candidate_catalog = match Catalog::load(&catalog_path) {
                Ok(catalog) => Some(catalog),
                Err(error) => {
                    if target.shape == SHAPE_ECH_TCP {
                        eprintln!("ECH-свидетели не прочитаны из каталога: {error}");
                    }
                    None
                }
            };
            let discovered_witness_candidates = if target.shape == SHAPE_ECH_TCP {
                candidate_catalog
                    .as_ref()
                    .map(|catalog| {
                        let recent_names = runner_recent_tcp_names
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .ech_witness_names(&target, std::time::Instant::now());
                        r2o_controller::discovery::r2o_ech_witness_candidates(
                            catalog,
                            &target,
                            &recent_names,
                        )
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let now = std::time::Instant::now();
            let cached_witness_candidates = if target.shape == SHAPE_ECH_TCP {
                runner_ech_witness_resolutions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .cached_witness_names(&target.host, now)
            } else {
                Vec::new()
            };
            let mut ech_witness_candidates = r2o_merge_ech_witness_candidates(
                &target.host,
                &cached_witness_candidates,
                &discovered_witness_candidates,
            );
            let challenged = {
                let mut cache = runner_ech_challenges
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                cache.retain(|_, expires| *expires > now);
                cache.keys().cloned().collect::<HashSet<_>>()
            };
            ech_witness_candidates.retain(|witness| !challenged.contains(witness));
            let known_ech_origin = candidate_catalog.as_ref().and_then(|catalog| {
                catalog
                    .boxes
                    .iter()
                    .flat_map(|box_record| &box_record.bindings)
                    .find(|binding| {
                        binding.enabled
                            && binding.level >= 3
                            && binding.kind == "name"
                            && binding.target == target.host
                            && matches!(binding.transport, 0 | 6)
                            && (binding.family == target.family
                                || binding.family == 0 && target.family == 4)
                            && !binding.ech_origin.is_empty()
                    })
                    .map(|binding| binding.ech_origin.clone())
            });
            let known_origin_config = known_ech_origin.as_deref().and_then(|witness| {
                r2o_discovery_ech_witness_config(
                    &target,
                    witness,
                    mark,
                    &runner_ech_witness_resolutions,
                )
                .ok()
                .flatten()
            });
            let direct_ech_config = known_origin_config
                .is_none()
                .then(|| r2o_discovery_ech_config(&target, mark).ok().flatten())
                .flatten();
            let ech_configuration_proven =
                direct_ech_config.is_some() || known_origin_config.is_some();
            let witness_search = if ech_configuration_proven {
                ech_witness_candidates.as_slice()
            } else {
                &ech_witness_candidates[..ech_witness_candidates.len().min(4)]
            };
            let (witness_config, next_witness) = r2o_discovery_first_ech_witness(
                &target,
                witness_search,
                0,
                mark,
                &runner_ech_witness_resolutions,
            )
            .map_or((None, witness_search.len()), |(config, next)| {
                (Some(config), next)
            });
            let ech_config = witness_config.or(known_origin_config).or(direct_ech_config);
            let mut target = target;
            let ech_grease =
                ech_config.is_none() && r2o_controller::discovery::regrade_ech_grease(&mut target);
            let white_name = candidate_catalog
                .as_ref()
                .and_then(|catalog| catalog.network_whitelist.as_ref())
                .map(|network| network.name.as_str())
                .filter(|name| !name.is_empty())
                .unwrap_or("hcaptcha.com");
            let (outcome, classify_probes) =
                r2o_classify_discovery_target_with_client_hello_and_ech(
                    target.clone(),
                    client_hello.as_deref(),
                    Arc::clone(&cancel),
                    mark,
                    ech_config.as_ref(),
                    white_name,
                );
            let mut outcome = outcome;
            if ech_grease {
                outcome.detail.push_str(
                    "; ECH-конфигурация имени не подтверждена — веду ClientHello как TLS 1.3 GREASE",
                );
            }
            if cancel.load(Ordering::Relaxed) {
                return outcome;
            }
            if r2o_discovery_volume_recovery(
                &mut outcome,
                &target,
                client_hello.as_deref(),
                mark,
                &commands,
                &catalog_path,
                candidate_catalog.as_ref(),
                white_name,
                &runner_send_cap,
                &runner_resource_memory,
                &runner_volume_searches,
                &cancel,
                runner_started,
                classify_probes,
            ) {
                return outcome;
            }
            let Some(plan_text) = outcome.plan_text.as_deref() else {
                return outcome;
            };
            let (probe_path, _) = r2o_discovery_resource_probe_paths(
                &target,
                candidate_catalog.as_ref(),
                &runner_resource_memory,
            );
            let network_probe = candidate_catalog.as_ref().is_some_and(|catalog| {
                catalog
                    .network_whitelist
                    .as_ref()
                    .is_none_or(|network| network.name.is_empty() && !network.searched)
            });
            let probe_cap = R2O_DISCOVERY_PROBE_CAP.saturating_add(if network_probe {
                r2o_controller::r2o_rx_volume::r2o_rx_volume_name_count()
            } else {
                0
            });
            let (result, applied, candidate_attempts) =
                r2o_run_discovery_candidate_trial_with_retries(
                    &target,
                    plan_text,
                    &probe_path,
                    mark,
                    &commands,
                    client_hello.as_deref(),
                    ech_config.as_ref(),
                    &runner_resource_memory,
                    probe_cap.saturating_sub(classify_probes),
                    None,
                    || {
                        !cancel.load(Ordering::Relaxed)
                            && R2O_DISCOVERY_TASK_LIFETIME.saturating_sub(runner_started.elapsed())
                                >= std::time::Duration::from_secs(9)
                    },
                );
            let mut probes_used = classify_probes.saturating_add(candidate_attempts);
            let Some(primary_config) = ech_config.clone() else {
                return r2o_confirm_discovery_outcome(outcome, result, applied);
            };
            let primary_origin = primary_config.origin_name.clone();
            let (selected_config, (mut result, mut applied), mut rejected_witnesses) =
                r2o_ech_retry_challenged_witness(
                    &target.host,
                    plan_text,
                    &ech_witness_candidates,
                    next_witness,
                    primary_config,
                    (result, applied),
                    |config, (result, _)| {
                        result.as_ref().is_ok_and(|fetch| {
                            r2o_ech_witness_transport_proof(&target, config, fetch)
                        })
                    },
                    |witness| {
                        r2o_discovery_ech_witness_config(
                            &target,
                            witness,
                            mark,
                            &runner_ech_witness_resolutions,
                        )
                        .ok()
                        .flatten()
                    },
                    |config, retry_plan| {
                        let proof_probe_reserve = usize::from(client_hello.is_some());
                        if probe_cap.saturating_sub(probes_used) < 1 + proof_probe_reserve {
                            return (
                                Err(
                                    "бюджет зондов Discovery исчерпан при проверке ECH-свидетеля"
                                        .into(),
                                ),
                                false,
                            );
                        }
                        let (result, applied, attempts) = r2o_run_discovery_candidate_trial(
                            &target,
                            retry_plan,
                            &probe_path,
                            mark,
                            &commands,
                            client_hello.as_deref(),
                            Some(config),
                            &runner_resource_memory,
                            None,
                        );
                        probes_used = probes_used.saturating_add(attempts);
                        (result, applied)
                    },
                );
            let mut rx_ladder_plan = None;
            if applied
                && result.as_ref().is_ok_and(|fetch| {
                    r2o_ech_witness_rx_cut(&target, &selected_config, true, false, fetch)
                })
            {
                let mut discovered_network_name = None;
                let mut next_index = *runner_ech_rx_cursor
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&target)
                    .unwrap_or(&0);
                let candidate_count = r2o_ech_rx_ladder_candidate_count(network_probe);
                for _ in 0..R2O_ECH_RX_LADDER_BATCH {
                    if cancel.load(Ordering::Relaxed)
                        || probe_cap.saturating_sub(probes_used)
                            < 1 + usize::from(client_hello.is_some())
                        || R2O_DISCOVERY_TASK_LIFETIME.saturating_sub(runner_started.elapsed())
                            < std::time::Duration::from_secs(9)
                        || next_index >= candidate_count
                    {
                        break;
                    }
                    let index = next_index;
                    let (candidate, discovered_name) = match r2o_ech_rx_ladder_candidate(
                        index,
                        network_probe,
                        white_name,
                        runner_send_cap.load(Ordering::Relaxed),
                    ) {
                        Ok(Some(candidate)) => candidate,
                        Ok(None) => break,
                        Err(error) => {
                            eprintln!("RX-лестница ECH пропустила план {index}: {error}");
                            next_index = index + 1;
                            runner_ech_rx_cursor
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .insert(target.clone(), next_index);
                            continue;
                        }
                    };
                    let trial = r2o_run_discovery_candidate_trial(
                        &target,
                        &candidate,
                        &probe_path,
                        mark,
                        &commands,
                        client_hello.as_deref(),
                        Some(&selected_config),
                        &runner_resource_memory,
                        None,
                    );
                    probes_used = probes_used.saturating_add(trial.2);
                    result = trial.0;
                    applied = trial.1;
                    if r2o_family_recovery_decision(&result, applied)
                        == R2oFamilyRecoveryDecision::Verified
                    {
                        rx_ladder_plan = Some(candidate);
                        discovered_network_name = discovered_name;
                        runner_ech_rx_cursor
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .remove(&target);
                        break;
                    }
                    let Some(fetch) = result.as_ref().ok() else {
                        break;
                    };
                    if !applied {
                        break;
                    }
                    if fetch.cloudflare_challenge {
                        if !rejected_witnesses.contains(&selected_config.origin_name) {
                            rejected_witnesses.push(selected_config.origin_name.clone());
                        }
                        break;
                    }
                    next_index = index + 1;
                    runner_ech_rx_cursor
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(target.clone(), next_index);
                }
                if let Some(name) = discovered_network_name.as_deref() {
                    if let Some(catalog) = candidate_catalog.as_ref() {
                        if let Err(error) = r2o_discovery_record_network_whitelist(
                            &catalog_path,
                            catalog,
                            Some(name),
                        ) {
                            eprintln!("не удалось сохранить найденное белое имя сети: {error}");
                        }
                    }
                } else if network_probe && next_index >= candidate_count {
                    runner_ech_rx_cursor
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&target);
                    if let Some(catalog) = candidate_catalog.as_ref() {
                        if let Err(error) =
                            r2o_discovery_record_network_whitelist(&catalog_path, catalog, None)
                        {
                            eprintln!(
                                "не удалось сохранить исчерпание поиска белого имени: {error}"
                            );
                        }
                    }
                } else if next_index >= candidate_count {
                    runner_ech_rx_cursor
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&target);
                }
            }
            if !rejected_witnesses.is_empty() {
                let expires = std::time::Instant::now() + std::time::Duration::from_secs(30 * 60);
                let mut cache = runner_ech_challenges
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for witness in &rejected_witnesses {
                    cache.insert(witness.clone(), expires);
                }
            }
            let mut outcome = r2o_confirm_discovery_outcome(outcome, result, applied);
            if let Some(plan) = rx_ladder_plan {
                outcome.plan_text = Some(plan);
                outcome
                    .detail
                    .push_str("; измеренный ECH RX-обрыв снят планом лестницы белого SNI");
            } else if runner_ech_rx_cursor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&target)
            {
                outcome
                    .detail
                    .push_str("; ECH RX-лестница продолжится со следующего белого SNI");
            }
            if selected_config.origin_name != primary_origin {
                outcome.detail.push_str(&format!(
                    "; тот же кандидат повторно проверен после challenge через ECH-свидетеля {}",
                    selected_config.origin_name
                ));
            }
            if !rejected_witnesses.is_empty() && outcome.plan_text.is_none() {
                outcome
                    .detail
                    .push_str("; ECH-свидетели с challenge временно исключены на 30 минут");
            }
            outcome
        });
        Self::r2o_new_with_runner_and_client_hellos(
            measurement_gate,
            runner,
            client_hellos,
            resource_memory,
        )
    }

    #[cfg(test)]
    fn r2o_new_with_runner(
        measurement_gate: r2o_controller::r2o_resource_limit::R2oMeasurementGate,
        runner: Arc<R2oDiscoveryRunner>,
    ) -> Self {
        Self::r2o_new_with_runner_and_client_hellos(
            measurement_gate,
            runner,
            Arc::new(std::sync::Mutex::new(HashMap::new())),
            Arc::new(std::sync::Mutex::new(
                r2o_controller::r2o_resource::R2oResourceMemory::default(),
            )),
        )
    }

    fn r2o_new_with_runner_and_client_hellos(
        measurement_gate: r2o_controller::r2o_resource_limit::R2oMeasurementGate,
        runner: Arc<R2oDiscoveryRunner>,
        client_hellos: Arc<std::sync::Mutex<HashMap<R2oDiscoveryTaskKey, Vec<u8>>>>,
        resource_memory: Arc<std::sync::Mutex<r2o_controller::r2o_resource::R2oResourceMemory>>,
    ) -> Self {
        let jobs = Arc::new((
            std::sync::Mutex::new(R2oDiscoveryQueue::default()),
            std::sync::Condvar::new(),
        ));
        let (outcome_sender, outcomes) = mpsc::sync_channel(8);
        let cancel = Arc::new(AtomicBool::new(false));
        let active_cancels = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let catalog_refreshes = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let mut threads = Vec::with_capacity(R2O_DISCOVERY_WORKER_COUNT);
        for _ in 0..R2O_DISCOVERY_WORKER_COUNT {
            let worker_cancel = Arc::clone(&cancel);
            let worker_gate = measurement_gate.clone();
            let worker_jobs = Arc::clone(&jobs);
            let task_cancels = Arc::clone(&active_cancels);
            let worker_catalog_refreshes = Arc::clone(&catalog_refreshes);
            let worker_outcomes = outcome_sender.clone();
            let worker_runner = Arc::clone(&runner);
            threads.push(std::thread::spawn(move || {
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
                                    queue.waiting_for_slot += 1;
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
                        let permit = worker_gate.r2o_acquire(&worker_cancel);
                        let (expired, target, generation) = {
                            let (queue, _) = &*worker_jobs;
                            let mut queue = queue
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            #[cfg(test)]
                            {
                                queue.waiting_for_slot = queue.waiting_for_slot.saturating_sub(1);
                            }
                            if worker_cancel.load(Ordering::Relaxed) || permit.is_none() {
                                (Vec::new(), None, queue.catalog_generation)
                            } else {
                                let (expired, target) = queue.pop(std::time::Instant::now());
                                (expired, target, queue.catalog_generation)
                            }
                        };
                        let Some(_permit) = permit else {
                            break;
                        };
                        for target in expired {
                            if worker_outcomes
                                .send(R2oDiscoveryWorkOutcome {
                                    outcome: DiscoveryOutcome {
                                        target,
                                        plan_text: None,
                                        detail: "подозрение устарело в очереди".into(),
                                        queue_expired: true,
                                        direct_clear: false,
                                        volume_recovery: false,
                                        volume_fingerprint: None,
                                        volume_box_id: None,
                                        retry_after: None,
                                    },
                                    catalog_generation: generation,
                                })
                                .is_err()
                            {
                                return;
                            }
                        }
                        let Some(target) = target else {
                            continue;
                        };
                        let task_key = r2o_discovery_task_key(&target);
                        let task_cancel = task_cancels
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .get(&task_key)
                            .cloned()
                            .unwrap_or_else(|| {
                                Arc::new(AtomicBool::new(worker_cancel.load(Ordering::Relaxed)))
                            });
                        let mut run_generation = generation;
                        let outcome = loop {
                            let outcome = if task_cancel.load(Ordering::Relaxed) {
                                DiscoveryOutcome {
                                    target: target.clone(),
                                    plan_text: None,
                                    detail: "задача заменена свежим ClientHello".into(),
                                    queue_expired: false,
                                    direct_clear: false,
                                    volume_recovery: false,
                                    volume_fingerprint: None,
                                    volume_box_id: None,
                                    retry_after: None,
                                }
                            } else {
                                worker_runner(target.clone(), Arc::clone(&task_cancel))
                            };
                            let latest_generation = worker_jobs
                                .0
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .catalog_generation;
                            if latest_generation != run_generation
                                && worker_catalog_refreshes
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .remove(&task_key)
                                && !worker_cancel.load(Ordering::Relaxed)
                            {
                                task_cancel.store(false, Ordering::Relaxed);
                                run_generation = latest_generation;
                                continue;
                            }
                            if latest_generation == run_generation
                                || task_cancel.load(Ordering::Relaxed)
                                || worker_cancel.load(Ordering::Relaxed)
                            {
                                break R2oDiscoveryWorkOutcome {
                                    outcome,
                                    catalog_generation: run_generation,
                                };
                            }
                            run_generation = latest_generation;
                        };
                        worker_catalog_refreshes
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .remove(&task_key);
                        task_cancels
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .remove(&task_key);
                        outcome
                    };
                    if worker_outcomes.send(outcome).is_err() {
                        break;
                    }
                }
            }));
        }
        Self {
            jobs,
            client_hellos,
            recent_client_shapes: R2oRecentClientShapeCache::default(),
            resource_memory,
            active_cancels,
            catalog_refreshes,
            outcomes,
            cancel,
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            failed_at: HashMap::new(),
            failed_retry_after: HashMap::new(),
            challenge_cooldowns: HashMap::new(),
            ech_input_clearable_failures: HashSet::new(),
            ech_input_names: VecDeque::new(),
            clear_streaks: HashMap::new(),
            client_snapshot_targets: HashSet::new(),
            pending_rechecks: HashMap::new(),
            active: HashMap::new(),
            completed: HashSet::new(),
            threads,
        }
    }

    fn r2o_live_searches(&self, now: std::time::Instant) -> Vec<serde_json::Value> {
        let queue = self
            .jobs
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.active
            .values()
            .map(|target| {
                let queued_at = queue
                    .entries
                    .iter()
                    .find(|entry| {
                        r2o_discovery_task_key(&entry.target) == r2o_discovery_task_key(target)
                    })
                    .map(|entry| entry.queued_at);
                let (ip, port) = target
                    .endpoint
                    .parse::<std::net::SocketAddr>()
                    .map(|endpoint| (endpoint.ip().to_string(), endpoint.port()))
                    .unwrap_or_default();
                let mut search = serde_json::json!({
                    "target": target.host,
                    "family": target.family,
                    "transport": 6,
                    "shape": target.shape,
                    "ip": ip,
                    "port": port,
                    "phase": if queued_at.is_some() {
                        "ожидает безопасного слота замера"
                    } else {
                        "выполняется замер"
                    },
                });
                if let Some(queued_at) = queued_at
                    && let Some(since) = r2o_live_timestamp(queued_at, now)
                {
                    search["since"] = serde_json::Value::String(since);
                }
                search
            })
            .collect()
    }

    fn remember_proven_resource(&self, host: &str, path: &str, now: std::time::Instant) -> bool {
        self.resource_memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remember_proven_path(host, path, now)
    }

    fn prepare_late_rx_resource_paths(&self, input: &mut R2oLateRxInput, catalog: &Catalog) {
        let Some(target) = input.discovery_target.as_ref() else {
            return;
        };
        let (path, alternate_path) =
            r2o_discovery_resource_probe_paths(target, Some(catalog), &self.resource_memory);
        input.options.path = path;
        input.alternate_path = alternate_path;
    }

    fn r2o_discovery_challenge_active(
        &mut self,
        target: &r2o_controller::discovery::DiscoveryTarget,
        now: std::time::Instant,
    ) -> bool {
        self.challenge_cooldowns.retain(|_, until| *until > now);
        self.challenge_cooldowns
            .get(&(target.host.clone(), target.family))
            .is_some_and(|until| *until > now)
    }

    fn r2o_record_discovery_challenge(
        &mut self,
        target: &r2o_controller::discovery::DiscoveryTarget,
        now: std::time::Instant,
    ) {
        self.challenge_cooldowns.retain(|_, until| *until > now);
        let key = (target.host.clone(), target.family);
        if !self.challenge_cooldowns.contains_key(&key)
            && self.challenge_cooldowns.len() >= R2O_DISCOVERY_CHALLENGE_COOLDOWN_CAPACITY
            && let Some(oldest) = self
                .challenge_cooldowns
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(key, _)| key.clone())
        {
            self.challenge_cooldowns.remove(&oldest);
        }
        self.challenge_cooldowns
            .insert(key, now + R2O_DISCOVERY_CHALLENGE_RETRY);
    }

    fn r2o_outstanding_task_count(&self, now: std::time::Instant) -> usize {
        // A canceled task may keep a deferred recheck until its outcome arrives.
        let mut task_keys = self
            .active
            .keys()
            .chain(self.pending_rechecks.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for (failure_key, failed_at) in &self.failed_at {
            if now.saturating_duration_since(*failed_at) < R2O_DISCOVERY_TASK_REST {
                task_keys.insert((failure_key.0.clone(), failure_key.1, failure_key.2));
            }
        }
        task_keys.len()
    }

    fn queue(&mut self, target: r2o_controller::discovery::DiscoveryTarget) -> bool {
        let now = std::time::Instant::now();
        if self.r2o_discovery_challenge_active(&target, now) {
            return false;
        }
        let task_key = r2o_discovery_task_key(&target);
        if let Some(active_target) = self.active.get(&task_key).cloned() {
            let (queue, wake) = &*self.jobs;
            let promoted = queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .promote(&active_target);
            if promoted {
                wake.notify_one();
            }
            return promoted;
        }
        if self.completed.contains(&task_key) {
            return false;
        }
        let failure_key = r2o_discovery_failure_key(&target);
        if let Some(failed_at) = self.failed_at.get(&failure_key).copied() {
            let retry_after = self
                .failed_retry_after
                .get(&failure_key)
                .copied()
                .unwrap_or(R2O_DISCOVERY_FAILURE_RETRY);
            if !r2o_discovery_failure_retry_due_after(failed_at, now, retry_after) {
                return false;
            }
            self.r2o_clear_failed_endpoint(&failure_key);
        }
        // A new endpoint replaces the donor's resting task for this name,
        // so its occupied slot remains reusable when the table is full.
        let replaces_resting_task = self.failed_at.iter().any(|(failed_key, failed_at)| {
            failed_key.0 == task_key.0
                && failed_key.1 == task_key.1
                && failed_key.2 == task_key.2
                && now.saturating_duration_since(*failed_at) < R2O_DISCOVERY_TASK_REST
        });
        // The donor's fixed task table contains both queued and running jobs.
        if self.r2o_outstanding_task_count(now) >= R2O_DISCOVERY_TASK_CAPACITY
            && !replaces_resting_task
        {
            return false;
        }
        if self.seen.contains(&target) {
            return false;
        }
        if self.seen_order.len() == 256
            && let Some(expired) = self.seen_order.pop_front()
        {
            self.seen.remove(&expired);
            let expired_task_key = r2o_discovery_task_key(&expired);
            if !self
                .seen_order
                .iter()
                .any(|seen| r2o_discovery_task_key(seen) == expired_task_key)
            {
                self.completed.remove(&expired_task_key);
            }
            let expired_key = r2o_discovery_failure_key(&expired);
            if !self
                .seen_order
                .iter()
                .any(|seen| r2o_discovery_failure_key(seen) == expired_key)
            {
                self.failed_at.remove(&expired_key);
                self.failed_retry_after.remove(&expired_key);
                self.ech_input_clearable_failures.remove(&expired_key);
                self.clear_streaks.remove(&expired_key);
            }
        }
        self.seen.insert(target.clone());
        self.seen_order.push_back(target.clone());
        let (queue, wake) = &*self.jobs;
        let mut queue = queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cached_client_hello = self
            .recent_client_shapes
            .get(&target)
            .map(|snapshot| snapshot.to_vec());
        if let Some(client_hello) = cached_client_hello.as_ref() {
            self.client_hellos
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(task_key.clone(), client_hello.clone());
        }
        let enqueued = queue.enqueue(target.clone(), now);
        if enqueued {
            self.active_cancels
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(task_key.clone(), Arc::new(AtomicBool::new(false)));
            self.active.insert(task_key, target);
            drop(queue);
            wake.notify_one();
            true
        } else {
            drop(queue);
            if cached_client_hello.is_some() {
                self.client_hellos
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&task_key);
            }
            self.seen.remove(&target);
            self.seen_order.retain(|seen| seen != &target);
            self.failed_at.remove(&failure_key);
            self.failed_retry_after.remove(&failure_key);
            self.ech_input_clearable_failures.remove(&failure_key);
            false
        }
    }

    fn queue_client_snapshot(
        &mut self,
        target: r2o_controller::discovery::DiscoveryTarget,
        client_hello: Vec<u8>,
    ) -> bool {
        if self.r2o_discovery_challenge_active(&target, std::time::Instant::now()) {
            return false;
        }
        if !self.remember_client_snapshot(&target, &client_hello) {
            return false;
        }
        if target.shape == SHAPE_ECH_TCP && self.r2o_record_ech_input(&target) {
            self.r2o_clear_ech_profile_failures(&target.host, target.family);
        }
        let task_key = r2o_discovery_task_key(&target);
        self.completed.remove(&task_key);
        if self.active.contains_key(&task_key) {
            self.catalog_refreshes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&task_key);
            self.pending_rechecks
                .insert(task_key.clone(), (target, Some(client_hello)));
            if let Some(cancel) = self
                .active_cancels
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&task_key)
            {
                cancel.store(true, Ordering::Relaxed);
            }
            return true;
        }
        self.seen.remove(&target);
        self.seen_order.retain(|seen| seen != &target);
        self.client_hellos
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(task_key, client_hello);
        if !self.queue(target.clone()) {
            self.client_hellos
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&r2o_discovery_task_key(&target));
            return false;
        }
        self.client_snapshot_targets.insert(target);
        true
    }

    fn remember_client_snapshot(
        &mut self,
        target: &r2o_controller::discovery::DiscoveryTarget,
        client_hello: &[u8],
    ) -> bool {
        let shape = r2k_core::tls::parse(client_hello);
        let observed_shape = if shape.ech_offer {
            SHAPE_ECH_TCP
        } else if shape.is_tls13 {
            SHAPE_MODERN
        } else {
            SHAPE_LEGACY
        };
        if !matches!(target.shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP)
            || observed_shape != target.shape
            || Trigger::tls_client_hello(&target.host, client_hello).is_err()
        {
            return false;
        }
        self.recent_client_shapes.note(target, client_hello);
        true
    }

    fn r2o_record_ech_input(
        &mut self,
        target: &r2o_controller::discovery::DiscoveryTarget,
    ) -> bool {
        if self
            .ech_input_names
            .iter()
            .any(|(name, family)| name == &target.host && *family == target.family)
        {
            return false;
        }
        if self.ech_input_names.len() == R2O_DISCOVERY_ECH_INPUT_CAPACITY {
            self.ech_input_names.pop_front();
        }
        self.ech_input_names
            .push_back((target.host.clone(), target.family));
        true
    }

    fn r2o_clear_ech_profile_failures(&mut self, host: &str, family: u8) {
        let failures = self
            .ech_input_clearable_failures
            .iter()
            .filter(|(failed_host, _, failed_family, _)| {
                failed_host == host && *failed_family == family
            })
            .cloned()
            .collect::<Vec<_>>();
        for failure in failures {
            self.r2o_clear_failed_endpoint(&failure);
        }
    }

    fn take_client_snapshot_provenance(
        &mut self,
        target: &r2o_controller::discovery::DiscoveryTarget,
    ) -> bool {
        self.client_snapshot_targets.remove(target)
    }

    fn queue_after_confirmed_failure(
        &mut self,
        target: r2o_controller::discovery::DiscoveryTarget,
    ) -> bool {
        if self.active.contains_key(&r2o_discovery_task_key(&target)) {
            return self.queue(target);
        }
        self.seen.remove(&target);
        self.seen_order.retain(|seen| seen != &target);
        self.completed.remove(&r2o_discovery_task_key(&target));
        let failure_key = r2o_discovery_failure_key(&target);
        self.failed_at.remove(&failure_key);
        self.failed_retry_after.remove(&failure_key);
        self.ech_input_clearable_failures.remove(&failure_key);
        self.queue(target)
    }

    fn queue_after_fresh_suspect(
        &mut self,
        target: r2o_controller::discovery::DiscoveryTarget,
    ) -> bool {
        if self.active.contains_key(&r2o_discovery_task_key(&target)) {
            return self.queue(target);
        }
        self.seen.remove(&target);
        self.seen_order.retain(|seen| seen != &target);
        self.completed.remove(&r2o_discovery_task_key(&target));
        self.queue(target)
    }

    fn r2o_clear_failed_endpoint(&mut self, failure_key: &R2oDiscoveryFailureKey) {
        let matching: Vec<_> = self
            .seen_order
            .iter()
            .filter(|seen| &r2o_discovery_failure_key(seen) == failure_key)
            .cloned()
            .collect();
        for target in matching {
            self.seen.remove(&target);
        }
        self.seen_order
            .retain(|seen| &r2o_discovery_failure_key(seen) != failure_key);
        self.failed_at.remove(failure_key);
        self.failed_retry_after.remove(failure_key);
        self.ech_input_clearable_failures.remove(failure_key);
    }

    fn is_active(&self, target: &r2o_controller::discovery::DiscoveryTarget) -> bool {
        self.active.contains_key(&r2o_discovery_task_key(target))
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
            let task_key = r2o_discovery_task_key(target);
            self.active_cancels
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&task_key);
            if self.active.get(&task_key) == Some(target) {
                self.active.remove(&task_key);
            }
            self.seen.remove(target);
            self.seen_order.retain(|seen| seen != target);
            let failure_key = r2o_discovery_failure_key(target);
            self.failed_at.remove(&failure_key);
            self.failed_retry_after.remove(&failure_key);
            self.ech_input_clearable_failures.remove(&failure_key);
        }
        expired
    }

    fn catalog_changed(&mut self) {
        {
            let (queue, _) = &*self.jobs;
            let mut queue = queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            queue.catalog_generation = queue.catalog_generation.wrapping_add(1);
        }
        let pending = self
            .pending_rechecks
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        let cancels = self
            .active_cancels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut refreshes = self
            .catalog_refreshes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (task_key, cancel) in cancels.iter() {
            if !pending.contains(task_key) {
                refreshes.insert(task_key.clone());
                cancel.store(true, Ordering::Relaxed);
            }
        }
    }

    fn try_outcome(&mut self) -> Option<DiscoveryOutcome> {
        self.r2o_schedule_pending_rechecks();
        let work = self.outcomes.try_recv().ok()?;
        let catalog_generation = work.catalog_generation;
        let outcome = work.outcome;
        let task_key = r2o_discovery_task_key(&outcome.target);
        if self.pending_rechecks.contains_key(&task_key) {
            if r2o_discovery_volume_challenge_outcome(&outcome) {
                self.r2o_record_discovery_challenge(&outcome.target, std::time::Instant::now());
            }
            if self.active.get(&task_key) == Some(&outcome.target) {
                self.active.remove(&task_key);
            }
            self.seen.remove(&outcome.target);
            self.seen_order.retain(|seen| seen != &outcome.target);
            let failure_key = r2o_discovery_failure_key(&self.pending_rechecks.get(&task_key)?.0);
            self.failed_at.remove(&failure_key);
            self.failed_retry_after.remove(&failure_key);
            self.ech_input_clearable_failures.remove(&failure_key);
            self.r2o_schedule_pending_rechecks();
            return None;
        }
        let current_generation = self
            .jobs
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .catalog_generation;
        if catalog_generation != current_generation
            && !outcome.queue_expired
            && !outcome.direct_clear
            && !r2o_discovery_volume_challenge_outcome(&outcome)
        {
            if self.active.get(&task_key) == Some(&outcome.target) {
                self.active.remove(&task_key);
            }
            self.seen.remove(&outcome.target);
            self.seen_order.retain(|seen| seen != &outcome.target);
            let failure_key = r2o_discovery_failure_key(&outcome.target);
            self.failed_at.remove(&failure_key);
            self.failed_retry_after.remove(&failure_key);
            self.ech_input_clearable_failures.remove(&failure_key);
            let client_hello = self
                .client_hellos
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&r2o_discovery_task_key(&outcome.target))
                .cloned();
            self.pending_rechecks
                .insert(task_key, (outcome.target, client_hello));
            self.r2o_schedule_pending_rechecks();
            return None;
        }
        Some(self.r2o_complete_outcome(outcome))
    }

    fn r2o_schedule_pending_rechecks(&mut self) {
        let ready = self
            .pending_rechecks
            .keys()
            .filter(|task_key| !self.active.contains_key(*task_key))
            .cloned()
            .collect::<Vec<_>>();
        for task_key in ready {
            let Some((target, client_hello)) = self.pending_rechecks.remove(&task_key) else {
                continue;
            };
            let client_hello_key = r2o_discovery_task_key(&target);
            self.completed.remove(&task_key);
            if self.r2o_discovery_challenge_active(&target, std::time::Instant::now()) {
                self.client_hellos
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&client_hello_key);
                self.client_snapshot_targets.remove(&target);
                continue;
            }
            self.seen.remove(&target);
            self.seen_order.retain(|seen| seen != &target);
            let failure_key = r2o_discovery_failure_key(&target);
            self.failed_at.remove(&failure_key);
            self.failed_retry_after.remove(&failure_key);
            self.ech_input_clearable_failures.remove(&failure_key);
            if let Some(client_hello) = client_hello.as_ref() {
                self.client_hellos
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(client_hello_key.clone(), client_hello.clone());
            } else {
                self.client_hellos
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&client_hello_key);
                self.client_snapshot_targets.remove(&target);
            }
            if self.queue(target.clone()) {
                if client_hello.is_some() {
                    self.client_snapshot_targets.insert(target);
                }
            } else {
                if client_hello.is_none() {
                    self.client_hellos
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&client_hello_key);
                }
                self.pending_rechecks
                    .insert(task_key, (target, client_hello));
            }
        }
    }

    fn r2o_complete_outcome(&mut self, mut outcome: DiscoveryOutcome) -> DiscoveryOutcome {
        if r2o_discovery_volume_challenge_outcome(&outcome) {
            self.r2o_record_discovery_challenge(&outcome.target, std::time::Instant::now());
        }
        let task_key = r2o_discovery_task_key(&outcome.target);
        let failure_key = r2o_discovery_failure_key(&outcome.target);
        let ech_input_clearable = !outcome.queue_expired
            && outcome.plan_text.is_none()
            && !outcome.direct_clear
            && outcome.target.shape != SHAPE_ECH_TCP
            && outcome.retry_after == Some(R2O_DISCOVERY_INCOMPLETE_RETRY);
        self.ech_input_clearable_failures.remove(&failure_key);
        if ech_input_clearable {
            self.ech_input_clearable_failures
                .insert(failure_key.clone());
        }
        self.client_hellos
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&task_key);
        if self.active.get(&task_key) == Some(&outcome.target) {
            self.active.remove(&task_key);
        }
        if outcome.direct_clear {
            let streak = self.clear_streaks.entry(failure_key.clone()).or_default();
            *streak = streak.saturating_add(1);
            outcome.retry_after = Some(r2o_discovery_clear_retry_after(*streak));
        } else if !outcome.queue_expired {
            self.clear_streaks.remove(&failure_key);
        }
        if outcome.queue_expired {
            self.completed.remove(&task_key);
            self.seen.remove(&outcome.target);
            self.seen_order.retain(|seen| seen != &outcome.target);
            self.failed_at.remove(&failure_key);
            self.failed_retry_after.remove(&failure_key);
            self.ech_input_clearable_failures.remove(&failure_key);
        } else if outcome.plan_text.is_none() && self.seen.contains(&outcome.target) {
            self.completed.remove(&task_key);
            self.failed_at
                .insert(failure_key.clone(), std::time::Instant::now());
            if let Some(retry_after) = outcome.retry_after {
                self.failed_retry_after.insert(failure_key, retry_after);
            } else {
                self.failed_retry_after.remove(&failure_key);
            }
        } else {
            if outcome.plan_text.is_some() {
                self.completed.insert(task_key);
            }
            self.failed_at.remove(&failure_key);
            self.failed_retry_after.remove(&failure_key);
            self.ech_input_clearable_failures.remove(&failure_key);
        }
        outcome
    }
}

#[cfg(unix)]
impl Drop for DiscoveryWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        for cancel in self
            .active_cancels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
        {
            cancel.store(true, Ordering::Relaxed);
        }
        self.jobs.1.notify_all();
        for thread in self.threads.drain(..) {
            while !thread.is_finished() {
                while self.outcomes.try_recv().is_ok() {}
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            while self.outcomes.try_recv().is_ok() {}
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
fn r2o_discovery_retry_after(
    timed_out: bool,
    verdict: Verdict,
    reason: &str,
) -> Option<std::time::Duration> {
    if timed_out {
        Some(R2O_DISCOVERY_TASK_LIFETIME)
    } else if verdict == Verdict::Clear {
        Some(R2O_DISCOVERY_CLEAR_RETRY_FIRST)
    } else if verdict == Verdict::Flaky && reason.contains("замер не состоялся") {
        Some(std::time::Duration::ZERO)
    } else if matches!(
        verdict,
        Verdict::Inconclusive | Verdict::Flaky | Verdict::Unreachable
    ) {
        Some(R2O_DISCOVERY_INCOMPLETE_RETRY)
    } else {
        None
    }
}

#[cfg(unix)]
fn r2o_discovery_clear_retry_after(streak: u8) -> std::time::Duration {
    match streak {
        0 | 1 => R2O_DISCOVERY_CLEAR_RETRY_FIRST,
        2 => R2O_DISCOVERY_CLEAR_RETRY_SECOND,
        _ => R2O_DISCOVERY_CLEAR_RETRY_MAX,
    }
}

#[cfg(unix)]
#[cfg(test)]
fn classify_discovery_target(
    target: r2o_controller::discovery::DiscoveryTarget,
    cancel: Arc<AtomicBool>,
    mark: Option<u32>,
) -> DiscoveryOutcome {
    classify_discovery_target_with_client_hello(target, None, cancel, mark)
}

#[cfg(unix)]
#[cfg(test)]
fn classify_discovery_target_with_client_hello(
    target: r2o_controller::discovery::DiscoveryTarget,
    client_hello: Option<&[u8]>,
    cancel: Arc<AtomicBool>,
    mark: Option<u32>,
) -> DiscoveryOutcome {
    r2o_classify_discovery_target_with_client_hello_and_ech(
        target,
        client_hello,
        cancel,
        mark,
        None,
        "hcaptcha.com",
    )
    .0
}

#[cfg(unix)]
fn r2o_discovery_ech_config(
    target: &r2o_controller::discovery::DiscoveryTarget,
    mark: Option<u32>,
) -> Result<Option<r2o_controller::ech::R2oEchConfig>, String> {
    if target.shape != SHAPE_ECH_TCP {
        return Ok(None);
    }
    let config = r2o_controller::ech::resolve_ech_config(&target.host, mark)?;
    if config.public_name != target.host {
        return Err(format!(
            "ECH public_name {} не совпадает с внешним именем {}",
            config.public_name, target.host
        ));
    }
    Ok(Some(config))
}

#[cfg(unix)]
fn r2o_discovery_ech_witness_config(
    target: &r2o_controller::discovery::DiscoveryTarget,
    witness: &str,
    mark: Option<u32>,
    cache: &std::sync::Mutex<R2oEchWitnessResolutionCache>,
) -> Result<Option<r2o_controller::ech::R2oEchConfig>, String> {
    if target.shape != SHAPE_ECH_TCP || witness == target.host {
        return Ok(None);
    }
    r2o_discovery_resolve_ech_witness_cached(cache, witness, &target.host, || {
        r2o_controller::ech::resolve_ech_config(witness, mark)
    })
}

#[cfg(unix)]
fn r2o_discovery_resolve_ech_witness_cached(
    cache: &std::sync::Mutex<R2oEchWitnessResolutionCache>,
    witness: &str,
    public_name: &str,
    resolve: impl FnOnce() -> Result<r2o_controller::ech::R2oEchConfig, String>,
) -> Result<Option<r2o_controller::ech::R2oEchConfig>, String> {
    let now = std::time::Instant::now();
    let cached = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .lookup(witness, now);
    let result = if let Some(cached) = cached {
        Ok(cached)
    } else {
        let result = resolve();
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .store(
                witness,
                result.as_ref().ok().cloned(),
                std::time::Instant::now(),
            );
        result.map(Some)
    };
    match result {
        Ok(Some(config)) if config.public_name == public_name => Ok(Some(config)),
        Ok(_) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn r2o_discovery_first_ech_witness(
    target: &r2o_controller::discovery::DiscoveryTarget,
    candidates: &[String],
    start: usize,
    mark: Option<u32>,
    cache: &std::sync::Mutex<R2oEchWitnessResolutionCache>,
) -> Option<(r2o_controller::ech::R2oEchConfig, usize)> {
    for (index, witness) in candidates.iter().enumerate().skip(start) {
        if let Ok(Some(config)) = r2o_discovery_ech_witness_config(target, witness, mark, cache) {
            return Some((config, index + 1));
        }
    }
    None
}

#[cfg(unix)]
fn r2o_ech_witness_transport_proof(
    target: &r2o_controller::discovery::DiscoveryTarget,
    config: &r2o_controller::ech::R2oEchConfig,
    fetch: &r2o_controller::fetch::FetchResult,
) -> bool {
    target.shape == SHAPE_ECH_TCP
        && config.origin_name != target.host
        && fetch.tls.is_some()
        && fetch.cloudflare_challenge
        && fetch.complete
        && (100..=599).contains(&fetch.status)
}

#[cfg(unix)]
fn r2o_ech_witness_rx_cut(
    target: &r2o_controller::discovery::DiscoveryTarget,
    config: &r2o_controller::ech::R2oEchConfig,
    ech_accepted: bool,
    replay: bool,
    fetch: &r2o_controller::fetch::FetchResult,
) -> bool {
    target.shape == SHAPE_ECH_TCP
        && ech_accepted
        && !replay
        && !config.origin_name.is_empty()
        && config.origin_name != target.host
        && fetch.tls.is_some()
        && (200..400).contains(&fetch.status)
        && !matches!(
            fetch.http_outcome,
            r2o_controller::fetch::R2oFetchHttpOutcome::Blocked
                | r2o_controller::fetch::R2oFetchHttpOutcome::LegalDenial
        )
        && !fetch.complete
        && fetch.r2o_volume_observation.body_framing_valid
        && fetch.body_bytes >= 8192
}

#[cfg(unix)]
fn r2o_ech_rx_ladder_candidate_count(network_probe: bool) -> usize {
    if network_probe {
        r2o_controller::r2o_rx_volume::r2o_rx_volume_name_count()
    } else {
        r2o_controller::r2o_rx_volume::r2o_rx_volume_plan_count()
    }
}

#[cfg(unix)]
fn r2o_ech_rx_ladder_candidate(
    index: usize,
    network_probe: bool,
    white_name: &str,
    send_cap: usize,
) -> Result<Option<(String, Option<String>)>, String> {
    if network_probe {
        let Some(name) = r2o_controller::r2o_rx_volume::r2o_rx_volume_name(index) else {
            return Ok(None);
        };
        let plan = r2o_controller::r2o_rx_volume::r2o_rx_volume_plan(0, name, send_cap)?;
        Ok(Some((plan, Some(name.to_owned()))))
    } else if index < r2o_controller::r2o_rx_volume::r2o_rx_volume_plan_count() {
        r2o_controller::r2o_rx_volume::r2o_rx_volume_plan(index, white_name, send_cap)
            .map(|plan| Some((plan, None)))
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
fn r2o_discovery_volume_recovery(
    outcome: &mut DiscoveryOutcome,
    target: &r2o_controller::discovery::DiscoveryTarget,
    client_hello: Option<&[u8]>,
    mark: Option<u32>,
    commands: &SyncSender<HttpSearchCommand>,
    catalog_path: &Path,
    candidate_catalog: Option<&Catalog>,
    white_name: &str,
    send_cap: &AtomicUsize,
    resource_memory: &std::sync::Mutex<r2o_controller::r2o_resource::R2oResourceMemory>,
    searches: &std::sync::Mutex<R2oDiscoveryVolumeSearchCache>,
    cancel: &AtomicBool,
    started: std::time::Instant,
    classify_probes: usize,
) -> bool {
    if !r2o_discovery_volume_recovery_eligible(outcome) {
        return false;
    }

    let (probe_path, alternate_path) =
        r2o_discovery_resource_probe_paths(target, candidate_catalog, resource_memory);
    let network_probe = candidate_catalog.is_some_and(|catalog| {
        catalog
            .network_whitelist
            .as_ref()
            .is_none_or(|network| network.name.is_empty() && !network.searched)
    });
    let probe_cap = R2O_DISCOVERY_PROBE_CAP.saturating_add(if network_probe {
        r2o_controller::r2o_rx_volume::r2o_rx_volume_name_count()
    } else {
        0
    });
    let mut probes_used = classify_probes;
    let key = R2oDiscoveryVolumeSearchKey {
        wire_len: r2o_discovery_volume_wire_len(target, client_hello),
        send_cap: send_cap.load(Ordering::Relaxed),
        probe_path,
        alternate_path,
        network_probe,
        white_name: white_name.to_owned(),
    };
    let cached = searches
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(target, &key, std::time::Instant::now());
    let mut search = if let Some(cached) = cached {
        cached
    } else {
        let options =
            match r2o_discovery_volume_fetch_options(target, &key.probe_path, mark, key.wire_len) {
                Ok(options) => options,
                Err(error) => {
                    outcome
                        .detail
                        .push_str(&format!("; объёмная проба пропущена: {error}"));
                    return false;
                }
            };
        let (tx, rx) = r2o_discovery_measure_volume(&options, key.alternate_path.as_deref());
        for fetch in [&rx.first, &rx.second, &rx.third, &rx.gzip]
            .into_iter()
            .flatten()
        {
            if r2o_controller::fetch::r2o_fetch_result_can_remember_resources(fetch) {
                resource_memory
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remember_hints(&fetch.r2o_resources, std::time::Instant::now());
            }
        }
        if rx.evidence.is_some()
            && let Some(path) = rx.measured_path.as_deref()
        {
            resource_memory
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remember_proven_path(&target.host, path, std::time::Instant::now());
        }
        let search = R2oDiscoveryVolumeSearch {
            key,
            measured_at: std::time::Instant::now(),
            tx,
            rx,
            next_candidate: 0,
            tried_plans: Vec::new(),
        };
        searches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target.clone(), search.clone());
        search
    };

    if !r2o_discovery_volume_cut(&search.tx, &search.rx) {
        if search.rx.evidence.is_none()
            && let Some(first) = search.rx.first.as_ref()
        {
            r2o_discovery_mark_partial_rx_inconclusive(
                outcome,
                &first.r2o_volume_observation,
                false,
            );
        }
        return false;
    }

    outcome.direct_clear = false;
    outcome.volume_recovery = true;
    let measured_candidate = outcome.plan_text.take();
    let tx_reason = search
        .tx
        .as_ref()
        .map_or_else(|error| error.as_str(), |result| result.reason.as_str());
    let rx_reason = if search.rx.evidence.is_some() {
        search.rx.reason.as_str()
    } else {
        "обрыв входящего ответа не подтверждён"
    };
    outcome.detail.push_str(&format!(
        "; подтверждён объёмный обрыв: TX {tx_reason}; RX {rx_reason}"
    ));

    let observed_fingerprint = r2o_discovery_volume_fingerprint(&search.tx, &search.rx);
    let candidate_probe_path = search
        .rx
        .measured_path
        .as_deref()
        .unwrap_or(&search.key.probe_path)
        .to_owned();
    let known_plans =
        r2o_discovery_volume_known_plans(candidate_catalog, target, &observed_fingerprint);
    let pending_known_plans: Vec<(String, String)> = known_plans
        .iter()
        .filter(|(_, candidate)| !search.tried_plans.contains(candidate))
        .take(8)
        .cloned()
        .collect();
    let mut known_probe_incomplete = false;
    for (box_id, candidate) in &pending_known_plans {
        if cancel.load(Ordering::Relaxed)
            || probes_used >= probe_cap
            || R2O_DISCOVERY_TASK_LIFETIME.saturating_sub(started.elapsed())
                < std::time::Duration::from_secs(9)
        {
            break;
        }
        let (result, applied, attempts) = r2o_run_discovery_candidate_trial(
            target,
            candidate,
            &candidate_probe_path,
            mark,
            commands,
            client_hello,
            None,
            resource_memory,
            None,
        );
        probes_used = probes_used.saturating_add(attempts);
        if r2o_family_recovery_decision(&result, applied) == R2oFamilyRecoveryDecision::Verified {
            searches
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(target);
            outcome.plan_text = Some(candidate.clone());
            outcome.volume_recovery = true;
            outcome.volume_fingerprint = Some(observed_fingerprint);
            outcome.volume_box_id = Some(box_id.clone());
            outcome.retry_after = None;
            outcome.detail.push_str(
                "; совместимый сохранённый TLS-план подтверждён точным APPLIED и полным HTTPS-ответом",
            );
            return true;
        }
        let Some(fetch) = result.as_ref().ok() else {
            known_probe_incomplete = true;
            outcome.detail.push_str(
                "; проба сохранённого объёмно-совместимого плана не завершилась, повторю её",
            );
            break;
        };
        if fetch.cloudflare_challenge {
            r2o_discovery_stop_volume_search_for_challenge(outcome, target, searches);
            return true;
        }
        search.tried_plans.push(candidate.clone());
        if !applied {
            outcome
                .detail
                .push_str("; сохранённый объёмно-совместимый план не получил точное применение");
        }
    }
    let known_plans_remain = known_plans
        .iter()
        .any(|(_, candidate)| !search.tried_plans.contains(candidate));
    if known_probe_incomplete || known_plans_remain {
        searches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target.clone(), search);
        outcome.retry_after = Some(if known_probe_incomplete {
            R2O_DISCOVERY_FAILURE_RETRY
        } else {
            std::time::Duration::ZERO
        });
        if known_plans_remain {
            outcome
                .detail
                .push_str("; оставшиеся планы коробок продолжатся следующей задачей");
        }
        return true;
    }

    if let Some(candidate) = measured_candidate
        .as_deref()
        .filter(|candidate| !search.tried_plans.iter().any(|tried| tried == candidate))
    {
        let (result, applied, attempts) = r2o_run_discovery_candidate_trial_with_retries(
            target,
            candidate,
            &candidate_probe_path,
            mark,
            commands,
            client_hello,
            None,
            resource_memory,
            probe_cap.saturating_sub(probes_used),
            None,
            || {
                !cancel.load(Ordering::Relaxed)
                    && R2O_DISCOVERY_TASK_LIFETIME.saturating_sub(started.elapsed())
                        >= std::time::Duration::from_secs(9)
            },
        );
        probes_used = probes_used.saturating_add(attempts);
        if r2o_family_recovery_decision(&result, applied) == R2oFamilyRecoveryDecision::Verified {
            searches
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(target);
            outcome.plan_text = Some(candidate.to_owned());
            outcome.volume_fingerprint = Some(observed_fingerprint.clone());
            outcome.retry_after = None;
            outcome.detail.push_str(
                "; собственный измеренный план подтверждён после сохранённых планов коробок",
            );
            return true;
        }
        if result
            .as_ref()
            .is_ok_and(|fetch| fetch.cloudflare_challenge)
        {
            r2o_discovery_stop_volume_search_for_challenge(outcome, target, searches);
            return true;
        }
        search.tried_plans.push(candidate.to_owned());
        if !applied {
            outcome
                .detail
                .push_str("; собственный измеренный план не получил точное применение");
        }
        if result.is_err() {
            outcome.detail.push_str(
                "; собственный измеренный план исчерпал ограниченные повторы без полного ответа",
            );
        }
    }

    if !r2o_discovery_volume_ladder_eligible(&search.tx, &search.rx) {
        searches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(target);
        outcome.plan_text = None;
        outcome.retry_after = Some(R2O_DISCOVERY_INCOMPLETE_RETRY);
        outcome
            .detail
            .push_str("; объёмный обрыв не подтверждён — fake-SNI-лестница не запускается");
        return true;
    }

    if search.rx.evidence.is_none()
        && search.tx.as_ref().is_ok_and(|result| {
            result.verdict == r2o_controller::fetch::R2oFetchVolumeTxVerdict::Cut
        })
    {
        outcome
            .detail
            .push_str("; исходящий TX-обрыв подтверждён — запускаю fake-SNI/split-лестницу");
    }

    if target.shape != SHAPE_MODERN {
        searches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(target);
        outcome.plan_text = None;
        outcome.retry_after = Some(R2O_DISCOVERY_INCOMPLETE_RETRY);
        outcome.detail.push_str(
            "; TLS 1.2 не поддерживает fake-SNI/RX-лестницу, сохранённые совместимые планы исчерпаны",
        );
        return true;
    }

    let candidate_count = r2o_ech_rx_ladder_candidate_count(network_probe);
    let tx_ladder_requires_packet_budget = search.rx.evidence.is_none()
        && search.tx.as_ref().is_ok_and(|result| {
            result.verdict == r2o_controller::fetch::R2oFetchVolumeTxVerdict::Cut
        });
    let mut next_candidate = search.next_candidate;
    let first_candidate = next_candidate;
    let mut attempted = 0_usize;
    while attempted < R2O_VOLUME_LADDER_BATCH
        && probes_used < probe_cap
        && !cancel.load(Ordering::Relaxed)
        && R2O_DISCOVERY_TASK_LIFETIME.saturating_sub(started.elapsed())
            >= std::time::Duration::from_secs(9)
        && next_candidate < candidate_count
    {
        let index = next_candidate;
        let (candidate, discovered_name) = match r2o_ech_rx_ladder_candidate(
            index,
            network_probe,
            white_name,
            send_cap.load(Ordering::Relaxed),
        ) {
            Ok(Some(candidate)) => candidate,
            Ok(None) => break,
            Err(error) => {
                eprintln!("объёмная лестница пропустила план {index}: {error}");
                next_candidate = index + 1;
                attempted += 1;
                continue;
            }
        };
        if search.tried_plans.iter().any(|tried| tried == &candidate) {
            next_candidate = index + 1;
            continue;
        }
        attempted += 1;
        let (result, applied, attempts) = r2o_run_discovery_candidate_trial(
            target,
            &candidate,
            &candidate_probe_path,
            mark,
            commands,
            client_hello,
            None,
            resource_memory,
            tx_ladder_requires_packet_budget.then_some(R2O_VOLUME_TX_LADDER_PACKET_BUDGET),
        );
        probes_used = probes_used.saturating_add(attempts);
        if r2o_discovery_volume_ladder_decision(&result, applied, tx_ladder_requires_packet_budget)
            == R2oFamilyRecoveryDecision::Verified
        {
            if network_probe
                && let (Some(catalog), Some(name)) = (candidate_catalog, discovered_name.as_deref())
                && let Err(error) =
                    r2o_discovery_record_network_whitelist(catalog_path, catalog, Some(name))
            {
                eprintln!("не удалось сохранить найденное белое имя сети: {error}");
            }
            searches
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(target);
            outcome.plan_text = Some(candidate);
            outcome.volume_recovery = true;
            outcome.volume_fingerprint = Some(observed_fingerprint.clone());
            outcome.retry_after = None;
            outcome.detail.push_str(&format!(
                "; объёмная лестница подтвердила план {index} точным APPLIED и полным HTTPS-ответом"
            ));
            return true;
        }
        let Some(fetch) = result.as_ref().ok() else {
            outcome.detail.push_str(&format!(
                "; проба объёмного плана {index} не завершилась и будет повторена"
            ));
            break;
        };
        if fetch.cloudflare_challenge {
            r2o_discovery_stop_volume_search_for_challenge(outcome, target, searches);
            return true;
        }
        if !applied {
            outcome.detail.push_str(&format!(
                "; проба объёмного плана {index} не получила точное применение; повторю её"
            ));
            break;
        }
        if tx_ladder_requires_packet_budget
            && matches!(
                fetch.r2o_volume_observation.packet_budget,
                r2o_controller::r2o_volume::R2oVolumePacketBudget::NotMeasured
                    | r2o_controller::r2o_volume::R2oVolumePacketBudget::NotApplicable
            )
        {
            searches
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(target);
            outcome.plan_text = None;
            outcome.retry_after = Some(R2O_DISCOVERY_INCOMPLETE_RETRY);
            outcome.detail.push_str(
                "; TCP_INFO не подтвердил бюджет потока для исходящей лестницы — белое имя не сохраняю",
            );
            return true;
        }
        next_candidate = index + 1;
    }

    search.next_candidate = next_candidate;
    outcome.plan_text = None;
    if network_probe && next_candidate >= candidate_count {
        if let Some(catalog) = candidate_catalog
            && let Err(error) = r2o_discovery_record_network_whitelist(catalog_path, catalog, None)
        {
            eprintln!("не удалось сохранить исчерпание поиска белого имени: {error}");
        }
        search.key.network_probe = false;
        search.key.white_name = "hcaptcha.com".into();
        search.next_candidate = 0;
        outcome.retry_after = Some(std::time::Duration::ZERO);
        outcome.detail.push_str(
            "; перебор белых имён исчерпан, следующая задача начнёт пять разрезов hcaptcha.com",
        );
        searches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target.clone(), search);
    } else if next_candidate >= candidate_count {
        searches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(target);
        outcome.retry_after = Some(R2O_DISCOVERY_INCOMPLETE_RETRY);
        outcome
            .detail
            .push_str("; варианты объёмной лестницы исчерпаны без подтверждённого обхода");
    } else {
        searches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target.clone(), search);
        outcome.retry_after = Some(if next_candidate == first_candidate {
            R2O_DISCOVERY_FAILURE_RETRY
        } else {
            std::time::Duration::ZERO
        });
        outcome.detail.push_str(&format!(
            "; объёмная лестница продолжится с плана {next_candidate}"
        ));
    }
    true
}

#[cfg(unix)]
fn r2o_discovery_volume_recovery_eligible(outcome: &DiscoveryOutcome) -> bool {
    // The C worker runs the ordinary volume probe only after a CLEAR verdict.
    !outcome.queue_expired
        && outcome.direct_clear
        && matches!(outcome.target.shape, SHAPE_MODERN | SHAPE_LEGACY)
}

#[cfg(unix)]
fn r2o_discovery_volume_challenge_outcome(outcome: &DiscoveryOutcome) -> bool {
    outcome.volume_recovery
        && !outcome.direct_clear
        && outcome.plan_text.is_none()
        && outcome.retry_after == Some(R2O_DISCOVERY_CHALLENGE_RETRY)
}

#[cfg(unix)]
fn r2o_discovery_stop_volume_search_for_challenge(
    outcome: &mut DiscoveryOutcome,
    target: &r2o_controller::discovery::DiscoveryTarget,
    searches: &std::sync::Mutex<R2oDiscoveryVolumeSearchCache>,
) {
    searches
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(target);
    outcome.direct_clear = false;
    outcome.plan_text = None;
    outcome.volume_recovery = true;
    outcome.volume_fingerprint = None;
    outcome.volume_box_id = None;
    outcome.retry_after = Some(R2O_DISCOVERY_CHALLENGE_RETRY);
    outcome.detail.push_str(
        "; получен Cloudflare challenge — объёмный перебор остановлен, цель отдыхает 60 минут",
    );
}

#[cfg(unix)]
fn r2o_ech_retry_challenged_witness<T>(
    target_name: &str,
    plan_text: &str,
    candidates: &[String],
    next_candidate: usize,
    primary_config: r2o_controller::ech::R2oEchConfig,
    first_result: T,
    mut is_transport_challenge: impl FnMut(&r2o_controller::ech::R2oEchConfig, &T) -> bool,
    mut resolve: impl FnMut(&str) -> Option<r2o_controller::ech::R2oEchConfig>,
    mut trial: impl FnMut(&r2o_controller::ech::R2oEchConfig, &str) -> T,
) -> (r2o_controller::ech::R2oEchConfig, T, Vec<String>) {
    let mut selected_config = primary_config;
    let mut result = first_result;
    if selected_config.origin_name == target_name
        || !is_transport_challenge(&selected_config, &result)
    {
        return (selected_config, result, Vec::new());
    }

    let mut challenged = vec![selected_config.origin_name.clone()];
    for witness in candidates.iter().skip(next_candidate) {
        if witness == target_name || witness == &selected_config.origin_name {
            continue;
        }
        let Some(config) = resolve(witness) else {
            continue;
        };
        if config.public_name != target_name || config.origin_name != *witness {
            continue;
        }
        let next_result = trial(&config, plan_text);
        selected_config = config;
        result = next_result;
        if selected_config.origin_name != target_name
            && is_transport_challenge(&selected_config, &result)
        {
            challenged.push(selected_config.origin_name.clone());
            continue;
        }
        return (selected_config, result, challenged);
    }
    (selected_config, result, challenged)
}

#[cfg(unix)]
fn r2o_classify_discovery_target_with_client_hello_and_ech(
    target: r2o_controller::discovery::DiscoveryTarget,
    client_hello: Option<&[u8]>,
    cancel: Arc<AtomicBool>,
    mark: Option<u32>,
    ech_config: Option<&r2o_controller::ech::R2oEchConfig>,
    white_name: &str,
) -> (DiscoveryOutcome, usize) {
    let trigger: Result<Trigger, String> = if let Some(client_hello) = client_hello {
        Trigger::tls_client_hello(&target.host, client_hello).map_err(str::to_owned)
    } else {
        match target.shape {
            SHAPE_MODERN => Trigger::tls13(&target.host).map_err(str::to_owned),
            SHAPE_LEGACY => Trigger::tls(&target.host).map_err(str::to_owned),
            SHAPE_ECH_TCP => match ech_config {
                Some(config) => {
                    let origin_name = config.origin_name.clone();
                    r2o_controller::ech::r2o_ech_tls_config(config)
                        .and_then(|ech| {
                            r2o_controller::r2o_tls::r2o_tls_ech_client_hello(&origin_name, ech)
                        })
                        .and_then(|hello| {
                            Trigger::tls_client_hello(&target.host, &hello).map_err(str::to_owned)
                        })
                }
                None => Err("для ECH нет совместимой HTTPS RR-конфигурации".into()),
            },
            _ => Err("форма TLS не поддерживается".into()),
        }
    };
    let Ok(trigger) = trigger else {
        return (
            DiscoveryOutcome {
                target,
                plan_text: None,
                detail: "не удалось собрать профиль целевого TLS".into(),
                queue_expired: false,
                direct_clear: false,
                volume_recovery: false,
                volume_fingerprint: None,
                volume_box_id: None,
                retry_after: None,
            },
            0,
        );
    };
    let control = match Trigger::tls("disk.rzd.ru") {
        Ok(control) => Trigger {
            accept: Accept::TlsRecord,
            ..control
        },
        Err(error) => {
            return (
                DiscoveryOutcome {
                    target,
                    plan_text: None,
                    detail: format!("не удалось собрать контрольный TLS: {error}"),
                    queue_expired: false,
                    direct_clear: false,
                    volume_recovery: false,
                    volume_fingerprint: None,
                    volume_box_id: None,
                    retry_after: None,
                },
                0,
            );
        }
    };
    let white = r2o_discovery_white_trigger(white_name);
    let (result, timed_out) =
        r2o_run_with_deadline(cancel, R2O_DISCOVERY_TASK_LIFETIME, |task_cancel| {
            classify_run(
                &target.endpoint,
                &trigger,
                ClassifyOptions {
                    mark,
                    control: Some(control),
                    white,
                    cancel: Some(task_cancel),
                    ..ClassifyOptions::default()
                },
            )
        });
    let retry_after = r2o_discovery_retry_after(timed_out, result.verdict, &result.reason);
    let probes = result.probes;
    let plan_text = if timed_out {
        None
    } else {
        result.hit.map(|hit| hit.plan_text)
    };
    let detail = if timed_out {
        "активный поиск превысил срок жизни 10 минут; частичный результат отброшен".into()
    } else {
        result.reason
    };
    (
        DiscoveryOutcome {
            target,
            plan_text,
            detail,
            queue_expired: false,
            direct_clear: !timed_out && result.verdict == Verdict::Clear,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after,
        },
        probes,
    )
}

#[cfg(unix)]
fn r2o_discovery_white_trigger(name: &str) -> Option<Trigger> {
    r2o_controller::hello::r2o_rx_fake_client_hello(name)
        .ok()
        .map(|payload| Trigger {
            name: "white".into(),
            payload,
            accept: Accept::TlsRecord,
        })
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
    send_maxlen: u32,
    send_cap: Arc<AtomicUsize>,
    pending_events: VecDeque<Frame>,
    pending_applied_events: VecDeque<r2k_core::control::AppliedEvent>,
    http_search_started: HashMap<(String, u8), HttpSearchWindow>,
    http_challenge_cooldowns: HashMap<(String, u8), std::time::Instant>,
    http_acknowledged_bindings:
        HashMap<(String, u8), ([u8; 16], r2k_core::control::BindingContext)>,
}

#[cfg(unix)]
#[derive(Default)]
struct R2oAskProof {
    applied: bool,
    exchange_seen: bool,
    server_hello: bool,
    unsent_code: Option<u8>,
    exchange: Option<r2k_core::control::R2oTcpExchangeEvent>,
}

#[cfg(unix)]
impl R2oAskProof {
    fn observe_applied(
        &mut self,
        event: &r2k_core::control::AppliedEvent,
        expected_key: &[u8; r2k_core::control::KEY_LEN],
        plan_id: [u8; 16],
        trial_id: [u8; 16],
        family: u8,
        shape: u8,
    ) -> bool {
        if event.trial_id != trial_id {
            return false;
        }
        self.applied |=
            r2o_ask_applied_matches(event, expected_key, plan_id, trial_id, family, shape);
        true
    }

    fn observe_exchange(
        &mut self,
        event: &r2k_core::control::R2oTcpExchangeEvent,
        expected_key: &[u8; r2k_core::control::KEY_LEN],
    ) -> bool {
        if event.key != *expected_key {
            return false;
        }
        self.exchange_seen = true;
        self.server_hello |= event.server_hello;
        self.exchange = Some(*event);
        true
    }

    fn passed(&self) -> bool {
        self.applied && self.exchange_seen && self.server_hello
    }

    fn finished(&self) -> bool {
        self.passed() || self.unsent_code.is_some()
    }

    fn observe_refused(
        &mut self,
        event: &r2k_core::control::RefusedEvent,
        expected_key: &[u8; r2k_core::control::KEY_LEN],
        plan_id: [u8; 16],
        trial_id: [u8; 16],
    ) -> bool {
        if event.key != *expected_key || event.plan_id != plan_id || event.trial_id != trial_id {
            return false;
        }
        if event.code != 0 {
            self.unsent_code = Some(event.code);
        }
        true
    }
}

#[cfg(unix)]
fn r2o_ask_ack_reason(code: u8) -> &'static str {
    match code {
        r2k_core::control::ACK_BAD_PLAN => "план не разобрался",
        r2k_core::control::ACK_BAD_ARGS => "аргументы команды не разобрались",
        r2k_core::control::ACK_NO_ROOM => "нет места в таблице планов",
        _ => "неизвестная причина",
    }
}

#[cfg(unix)]
fn r2o_ask_print_seen_types(mask: u8) -> String {
    let types = [
        (20, "20 смена шифра"),
        (21, "21 тревога"),
        (22, "22 рукопожатие"),
        (23, "23 прикладные данные"),
    ];
    let seen = types
        .into_iter()
        .filter_map(|(record_type, label)| (mask & (1 << (record_type - 20)) != 0).then_some(label))
        .collect::<Vec<_>>();
    if seen.is_empty() {
        "ни одной".into()
    } else {
        seen.join(", ")
    }
}

#[cfg(unix)]
fn r2o_print_ask_trace(
    plan_len: usize,
    plan_status: &str,
    local_port: Option<u16>,
    proof: Option<&R2oAskProof>,
    stop_reason: &str,
) {
    println!("  план: {plan_len} байт, {plan_status}");
    match local_port {
        Some(port) => match proof.and_then(|proof| proof.exchange) {
            Some(exchange) => println!(
                "  обмен: с местного порта {port}, {} байт, первая запись типа {}, встречены типы: {}",
                exchange.bytes_after_client_hello,
                exchange.first_record_type,
                r2o_ask_print_seen_types(exchange.record_types)
            ),
            None => {
                println!("  обмен: обращение с местного порта {port}, события обмена не пришло")
            }
        },
        None => println!("  обмен: до обращения к цели дело не дошло"),
    }
    if let Some(code) = proof.and_then(|proof| proof.unsent_code) {
        println!("  отказ отправки плана: код {code}");
    }
    println!("  причина остановки: {stop_reason}");
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
            send_maxlen: greeting.send_maxlen,
            send_cap: Arc::new(AtomicUsize::new(greeting.send_maxlen as usize)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        })
    }

    fn acknowledged_http_binding_for(
        &self,
        response: &r2k_core::control::HttpResponseEvent,
    ) -> Option<r2k_core::control::BindingContext> {
        let host = std::str::from_utf8(&response.host).ok()?;
        let host = normalize(host).ok()?;
        let (plan_id, binding) = self
            .http_acknowledged_bindings
            .get(&(host, response.key[0]))?;
        (*plan_id == response.plan_id && *binding == response.binding).then_some(*binding)
    }

    fn record_http_binding_acknowledgement(
        &mut self,
        command: &[u8],
        expected: u16,
        ack: r2k_core::control::Ack,
    ) {
        let Ok(frame) = read_frame(&mut std::io::Cursor::new(command)) else {
            return;
        };
        if frame.kind != expected {
            return;
        }
        match expected {
            COMMAND_CLEAR if ack.ok => self.http_acknowledged_bindings.clear(),
            COMMAND_SET_NAME if ack.ok => {
                let body = &frame.body;
                let Some(name_len) = body.first().copied().map(usize::from) else {
                    return;
                };
                let Some(fields_end) = 3_usize.checked_add(name_len) else {
                    return;
                };
                if name_len == 0 || body.len() <= fields_end {
                    return;
                }
                let shape = body[1 + name_len];
                if shape != SHAPE_HTTP {
                    return;
                }
                let family = body[2 + name_len];
                let Ok(host) = std::str::from_utf8(&body[1..1 + name_len]) else {
                    return;
                };
                let Ok(host) = normalize(host) else {
                    return;
                };
                let key = (host, family);
                let Some(binding) = ack.binding_context.filter(|binding| {
                    binding.is_known()
                        && !binding.temporary
                        && binding.kind == 1
                        && binding.family == family
                        && binding.shape == SHAPE_HTTP
                }) else {
                    self.http_acknowledged_bindings.remove(&key);
                    return;
                };
                let Ok(plan) = Plan::parse(&body[fields_end..]) else {
                    self.http_acknowledged_bindings.remove(&key);
                    return;
                };
                self.http_acknowledged_bindings
                    .insert(key, (plan.id, binding));
            }
            COMMAND_DEL_NAME if ack.ok => {
                let body = &frame.body;
                let Some(name_len) = body.first().copied().map(usize::from) else {
                    return;
                };
                let Some(fields_end) = 1_usize
                    .checked_add(name_len)
                    .and_then(|length| length.checked_add(3))
                else {
                    return;
                };
                if name_len == 0 || body.len() != fields_end {
                    return;
                }
                let transport = body[1 + name_len];
                let shape = body[2 + name_len];
                let family = body[3 + name_len];
                if transport != 6 || shape != SHAPE_HTTP {
                    return;
                }
                if let Ok(host) = std::str::from_utf8(&body[1..1 + name_len])
                    && let Ok(host) = normalize(host)
                {
                    self.http_acknowledged_bindings.remove(&(host, family));
                }
            }
            _ => {}
        }
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
        plan_text: String,
        started_at: std::time::Instant,
    ) -> Result<R2oVoiceTrialInstallOutcome, Box<dyn Error>> {
        use std::io::Read;

        let now = std::time::Instant::now();
        let expires_at = started_at + R2O_VOICE_TRIAL_TASK_LIFETIME;
        if expires_at <= now {
            eprintln!("голосовая задача Discovery истекла до установки временного плана");
            return Ok(R2oVoiceTrialInstallOutcome::NotInstalled);
        }
        let mut trial_id = [0; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut trial_id)?;
        if trial_id.iter().all(|byte| *byte == 0) {
            trial_id[15] = 1;
        }
        let trial = R2oVoiceTrialContext {
            target,
            trial_id,
            plan_text,
            voice_flow_key: None,
            started_at,
            renew_at: now + R2O_VOICE_TRIAL_RENEW_INTERVAL,
            expires_at,
            response_confirmed: false,
        };
        let ack = self.set_r2o_voice_trial(&trial)?;
        if ack.trial_id != Some(trial_id) || !ack.ok {
            let local_refusal = ack.trial_id == Some(trial_id) && !ack.ok;
            let reason = if ack.trial_id != Some(trial_id) {
                "подтверждение пришло с чужим trial ID".to_owned()
            } else {
                match ack.reason {
                    control::ACK_BAD_PLAN => "план не подходит runtime".to_owned(),
                    control::ACK_NO_ROOM => "таблица временных планов заполнена".to_owned(),
                    control::ACK_BAD_ARGS => "датапат отверг аргументы".to_owned(),
                    _ => "неизвестная причина отказа".to_owned(),
                }
            };
            if let Err(error) = self.retire_r2o_voice_trial(&trial) {
                eprintln!("не удалось удалить отклонённый временный voice-план: {error}");
            }
            eprintln!("SET_VOICE_ADDR_PROBE не принят: {reason}");
            return Ok(if local_refusal {
                R2oVoiceTrialInstallOutcome::LocalRefusal
            } else {
                R2oVoiceTrialInstallOutcome::NotInstalled
            });
        }
        Ok(R2oVoiceTrialInstallOutcome::Installed(trial))
    }

    fn set_r2o_voice_trial(
        &mut self,
        trial: &R2oVoiceTrialContext,
    ) -> Result<r2k_core::control::Ack, Box<dyn Error>> {
        let plan_records = compile_text(&trial.plan_text)?;
        let plan = Plan::parse(&plan_records)?;
        r2o_datapath::engine::validate_runtime_plan(&plan)
            .map_err(|error| format!("исполнитель r2o-datapath отверг voice-план: {error}"))?;
        let command = encode_set_voice_addr_probe(
            trial.target.client,
            trial.target.server,
            VOICE_ADDR_PROBE_LEASE_MAX_MS,
            &plan_records,
            trial.trial_id,
        )?;
        self.exchange_command(&command, COMMAND_SET_VOICE_ADDR_PROBE)
    }

    fn renew_r2o_voice_trial(
        &mut self,
        trial: &R2oVoiceTrialContext,
    ) -> Result<Option<u8>, Box<dyn Error>> {
        let ack = self.set_r2o_voice_trial(trial)?;
        if ack.trial_id != Some(trial.trial_id) {
            return Err("SET_VOICE_ADDR_PROBE продления получил чужой trial ID".into());
        }
        Ok((!ack.ok).then_some(ack.reason))
    }

    fn renew_due_r2o_voice_trials(
        &mut self,
        trials: &mut HashMap<[u8; 16], R2oVoiceTrialContext>,
        now: std::time::Instant,
    ) {
        for trial in r2o_take_due_voice_trial_renewals(trials, now) {
            match self.renew_r2o_voice_trial(&trial) {
                Ok(None) => {}
                Ok(Some(reason)) => {
                    if let Some(retired) = trials.remove(&trial.trial_id) {
                        if let Err(error) = self.retire_r2o_voice_trial(&retired) {
                            eprintln!(
                                "датапат отклонил продление Discord-плана (причина {reason}); временное правило истечёт по аренде, досрочное снятие не удалось: {error}"
                            );
                        }
                        eprintln!(
                            "датапат отклонил продление Discord-плана (причина {reason}); опыт снят, цель не признана и ожидающая цель может продолжить"
                        );
                    }
                }
                Err(error) => eprintln!(
                    "Discord-план не продлён; повторю через {} с, если цель ещё активна: {error}",
                    R2O_VOICE_TRIAL_RENEW_INTERVAL.as_secs()
                ),
            }
        }
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
        let ack = self.exchange_command(&delete, COMMAND_DEL_VOICE_ADDR_PROBE)?;
        if ack.trial_id != Some(trial.trial_id) {
            return Err("DEL_VOICE_ADDR_PROBE получил подтверждение с чужим trial ID".into());
        }
        if !ack.ok {
            return Err(format!(
                "DEL_VOICE_ADDR_PROBE не выполнена: {}",
                match ack.reason {
                    control::ACK_BAD_PLAN => "план не подходит runtime",
                    control::ACK_NO_ROOM => "таблица временных планов заполнена",
                    control::ACK_BAD_ARGS => "датапат отверг аргументы",
                    _ => "неизвестная причина",
                }
            )
            .into());
        }
        Ok(())
    }

    fn confirm_r2o_voice_trial(
        &mut self,
        trial: R2oVoiceTrialContext,
        proof: &r2k_core::control::R2oVoiceProofEvent,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        if !trial.response_confirmed {
            return Err("RTP не подтверждает voice-план без Discovery/STUN-ответа".into());
        }
        if proof.trial_id != trial.trial_id || !r2o_voice_proof_matches_target(proof, trial.target)
        {
            return Err("голосовое подтверждение не совпало с временным опытом".into());
        }
        let (outbound_packets, inbound_packets) = match proof.proof {
            r2k_core::control::R2oVoiceProofKind::RtpMedia {
                outbound_packets,
                inbound_packets,
            } if outbound_packets >= r2k_core::control::VOICE_RTP_PROOF_MIN_PACKETS
                && inbound_packets >= r2k_core::control::VOICE_RTP_PROOF_MIN_PACKETS =>
            {
                (outbound_packets, inbound_packets)
            }
            _ => {
                return Err(
                    "постоянную voice-привязку подтверждает только двусторонний RTP".into(),
                );
            }
        };
        let verified_by = 5;
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
            verified_by,
        )
        .map_err(|error| format!("не удалось сохранить голосовую привязку: {error}"))?;
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
            "Двусторонний RTP подтверждён: адресный план {plan_id} сохранён для {}; принято RTP-пакетов исход/вход={outbound_packets}/{inbound_packets}; качество и слышимость аудио отдельно не измерялись",
            trial.target.server.ip(),
        );
        Ok(())
    }

    fn watch_events(
        &mut self,
        discovery: Option<(Catalog, PathBuf, Option<u32>)>,
        https_cache_path: Option<PathBuf>,
        https_probe_mark: Option<u32>,
        live_catalog: Option<(Catalog, PathBuf)>,
        mut active_groups: HashSet<r2o_controller::live::LiveGroupKey>,
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
        let http_search = discovery
            .as_ref()
            .map(|_| HttpSearchWorker::new(measurement_gate.clone()));
        let tcp_witness_names = Arc::new(std::sync::Mutex::new(R2oRecentTcpNameCache::default()));
        let mut discovery = discovery.map(|(catalog, path, mark)| {
            (
                DiscoveryWorker::new_with_confirmation(
                    mark,
                    Arc::clone(&self.send_cap),
                    measurement_gate.clone(),
                    http_search
                        .as_ref()
                        .expect("HTTP worker существует при активном Discovery")
                        .command_sender(),
                    path.clone(),
                    Arc::clone(&tcp_witness_names),
                ),
                catalog,
                path,
                mark,
            )
        });
        let mut family_recovery = discovery.as_ref().map(|_| {
            R2oFamilyRecoveryWorker::new(
                measurement_gate.clone(),
                http_search
                    .as_ref()
                    .expect("HTTP worker существует при активном Discovery")
                    .command_sender(),
            )
        });
        let mut quic_discovery = discovery.as_ref().map(|_| R2oQuicDiscoveryWorker::new());
        let mut r2o_late_rx = discovery
            .as_ref()
            .map(|_| R2oLateRxWorker::new(measurement_gate.clone()));
        let mut r2o_late_rx_hellos = R2oLateRxCache::default();
        let mut https_probe = HttpsProbeWorker::new(https_probe_mark);
        let mut r2o_voice_trials = HashMap::<[u8; 16], R2oVoiceTrialContext>::new();
        let mut quic_snapshots =
            HashMap::<[u8; r2k_core::control::KEY_LEN], (Vec<u8>, std::time::Instant)>::new();
        let mut quic_hello_names =
            HashMap::<[u8; r2k_core::control::KEY_LEN], (Option<String>, std::time::Instant)>::new(
            );
        let mut tcp_hello_names = R2oTcpHelloCache::default();
        let mut clean_handshakes = R2oCleanHandshakeCache::default();
        let mut quic_trial_cooldowns = HashMap::<std::net::IpAddr, std::time::Instant>::new();
        let mut quic_deny = R2oQuicDenyCache::default();
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
        let live_path = live_catalog
            .as_ref()
            .map(|(_, path)| path.with_file_name("live.json"));
        let mut live_written_at = None;
        let run_result = (|| -> Result<(), Box<dyn Error>> {
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
                if live_written_at.is_none_or(|last: std::time::Instant| {
                    r2o_now.saturating_duration_since(last) >= std::time::Duration::from_secs(5)
                }) {
                    let catalog_snapshot = discovery
                        .as_ref()
                        .map(|(_, catalog, _, _)| catalog)
                        .or_else(|| live_catalog.as_ref().map(|(catalog, _)| catalog));
                    if let (Some(catalog), Some(path)) = (catalog_snapshot, live_path.as_deref()) {
                        let searches = discovery
                            .as_ref()
                            .map(|(worker, _, _, _)| worker.r2o_live_searches(r2o_now))
                            .unwrap_or_default();
                        let status = measurement_gate.r2o_live_snapshot();
                        let measurements = serde_json::json!({
                            "active": status.active,
                            "limit": status.limit,
                            "queued": status.queued,
                            "cores": status.cores,
                            "free_pct": status.free_pct,
                            "mem_avail_mb": status.mem_avail_mb,
                            "mem_total_mb": status.mem_total_mb,
                            "conntrack_pct": status.conntrack_pct,
                            "limited_by": status.limited_by,
                        });
                        if let Some((_, catalog_path)) = &live_catalog {
                            match r2o_controller::live::snapshot(
                                catalog,
                                catalog_path,
                                &active_groups,
                                searches,
                                measurements,
                            )
                            .and_then(|value| r2o_controller::live::write_snapshot(path, &value))
                            {
                                Ok(()) => live_written_at = Some(r2o_now),
                                Err(error) => {
                                    eprintln!("живое состояние панели не записано: {error}");
                                    live_written_at = Some(r2o_now);
                                }
                            }
                        }
                    }
                }
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
                let r2o_has_pending_voice_target = voice_discovery
                    .as_ref()
                    .is_some_and(|worker| worker.schedule.pending.is_some());
                for r2o_trial in r2o_take_stale_pending_voice_trials(
                    &mut r2o_voice_trials,
                    r2o_now,
                    r2o_has_pending_voice_target,
                ) {
                    if let Err(error) = self.retire_r2o_voice_trial(&r2o_trial) {
                        eprintln!(
                            "Discord-проба не получила решения за две минуты; ожидающая цель продолжит после истечения аренды: {error}"
                        );
                    }
                }
                self.renew_due_r2o_voice_trials(&mut r2o_voice_trials, r2o_now);
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
                    let client_input = worker.take_client_snapshot_provenance(&outcome.target)
                        && outcome.plan_text.is_some();
                    if outcome.queue_expired {
                        println!(
                            "подозрение {} устарело в очереди Discovery; сетевой замер не запускался",
                            outcome.target.host
                        );
                    } else {
                        let catalog_changed = outcome.plan_text.is_some() || outcome.direct_clear;
                        if let Some(installed_groups) = self.apply_discovery_outcome_with_input(
                            outcome,
                            catalog,
                            path,
                            if client_input { 1 } else { 2 },
                        )? {
                            active_groups = installed_groups.into_iter().collect();
                        }
                        if catalog_changed {
                            worker.catalog_changed();
                        }
                    }
                    std::io::stdout().flush()?;
                    continue;
                }
                if let Some(outcome) = family_recovery
                    .as_ref()
                    .and_then(R2oFamilyRecoveryWorker::try_outcome)
                {
                    let decision = r2o_family_recovery_decision(&outcome.result, outcome.applied);
                    match decision {
                        R2oFamilyRecoveryDecision::Verified => {
                            if let Some(worker) = &mut family_recovery {
                                worker.complete(&outcome.target);
                            }
                            println!(
                                "план семейного восстановления {:02x?} прошёл HTTPS и получил точный APPLIED для {}; полный поиск не потребовался",
                                outcome.plan_id, outcome.target.host
                            );
                            std::io::stdout().flush()?;
                            continue;
                        }
                        R2oFamilyRecoveryDecision::Reclassify => {
                            if let Some(worker) = &mut family_recovery {
                                worker.complete(&outcome.target);
                            }
                            let queued = discovery.as_mut().is_some_and(|(worker, _, _, _)| {
                                worker.queue_after_confirmed_failure(outcome.target.clone())
                            });
                            println!(
                                "сохранённые планы семейного восстановления не подтвердились для {}: {}; {}",
                                outcome.target.host,
                                outcome
                                    .result
                                    .as_ref()
                                    .err()
                                    .map(String::as_str)
                                    .unwrap_or("HTTPS/APPLIED не прошли проверку"),
                                if queued {
                                    "запускаю полную классификацию"
                                } else {
                                    "полная классификация уже выполняется или очередь занята"
                                }
                            );
                            std::io::stdout().flush()?;
                            continue;
                        }
                    }
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
                            let r2o_install = self.install_r2o_voice_trial(
                                r2o_target,
                                r2o_controller::voice_discovery::r2o_voice_arm_plan_text(&prefix),
                                r2o_outcome.started_at,
                            )?;
                            if let Some(worker) = voice_discovery.as_mut() {
                                worker
                                    .r2o_seen
                                    .r2o_after_trial_install(&r2o_target, &r2o_install);
                            }
                            match r2o_install {
                                R2oVoiceTrialInstallOutcome::Installed(r2o_trial) => {
                                    let r2o_trial_id = r2o_trial.trial_id;
                                    r2o_voice_trials.insert(r2o_trial_id, r2o_trial);
                                    println!(
                                        "Discord Discovery повторяемо обрывался после {cutoff} ответов; временный адресный план поставлен для следующего потока {} -> {}:{}",
                                        r2o_target.client,
                                        r2o_target.server.ip(),
                                        r2o_target.server.port()
                                    );
                                }
                                R2oVoiceTrialInstallOutcome::LocalRefusal => eprintln!(
                                    "Discord Discovery {} -> {}:{}: датапат локально отверг временный план; цель не подтверждена, следующий поток сможет повторить поиск",
                                    r2o_target.client,
                                    r2o_target.server.ip(),
                                    r2o_target.server.port()
                                ),
                                R2oVoiceTrialInstallOutcome::NotInstalled => eprintln!(
                                    "Discord Discovery {} -> {}:{}: датапат не подтвердил временный план с его trial ID; цель не подтверждена",
                                    r2o_target.client,
                                    r2o_target.server.ip(),
                                    r2o_target.server.port()
                                ),
                            }
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
                    if matches!(
                        r2o_outcome.result.verdict,
                        r2o_controller::voice_discovery::R2oDiscoveryVerdict::Continue
                    ) {
                        if let Some(r2o_fallback) = r2o_outcome.fallback.as_ref() {
                            if r2o_fallback.verdict == R2oVoiceVerdict::Blocked {
                                if let Some(r2o_arm) = r2o_fallback.arm {
                                    if r2o_voice_trials
                                        .values()
                                        .any(|r2o_trial| r2o_trial.target == r2o_target)
                                    {
                                        println!(
                                            "голосовой STUN fallback {} -> {}:{}: временный план для этой цели уже ждёт доказательство",
                                            r2o_target.client,
                                            r2o_target.server.ip(),
                                            r2o_target.server.port()
                                        );
                                    } else if discovery.as_ref().is_some_and(|(_, _, _, mark)| {
                                        mark.is_some_and(|mark| mark != 0)
                                    }) {
                                        let r2o_plan_text =
                                            r2o_controller::voice_measure::r2o_measured_voice_arm_plan_text(
                                                r2o_arm,
                                            )
                                            .map_err(|error| {
                                                format!("не удалось собрать измеренный voice-plan: {error}")
                                            })?;
                                        let r2o_install = self.install_r2o_voice_trial(
                                            r2o_target,
                                            r2o_plan_text,
                                            r2o_outcome.started_at,
                                        )?;
                                        if let Some(worker) = voice_discovery.as_mut() {
                                            worker
                                                .r2o_seen
                                                .r2o_after_trial_install(&r2o_target, &r2o_install);
                                        }
                                        match r2o_install {
                                            R2oVoiceTrialInstallOutcome::Installed(r2o_trial) => {
                                                r2o_voice_trials
                                                    .insert(r2o_trial.trial_id, r2o_trial);
                                                println!(
                                                    "Discord live-flow fallback подтвердил выбор arm {} ×{}; временный план поставлен для следующего потока {} -> {}:{}",
                                                    r2o_arm.name,
                                                    r2o_arm.copies,
                                                    r2o_target.client,
                                                    r2o_target.server.ip(),
                                                    r2o_target.server.port()
                                                );
                                            }
                                            R2oVoiceTrialInstallOutcome::LocalRefusal => eprintln!(
                                                "Discord live-flow fallback {} -> {}:{}: датапат локально отверг временный план; цель не подтверждена",
                                                r2o_target.client,
                                                r2o_target.server.ip(),
                                                r2o_target.server.port()
                                            ),
                                            R2oVoiceTrialInstallOutcome::NotInstalled => eprintln!(
                                                "Discord live-flow fallback {} -> {}:{}: датапат не подтвердил временный план с его trial ID",
                                                r2o_target.client,
                                                r2o_target.server.ip(),
                                                r2o_target.server.port()
                                            ),
                                        }
                                    } else {
                                        println!(
                                            "Discord live-flow fallback нашёл arm {}, но временная установка требует ненулевую метку",
                                            r2o_arm.name
                                        );
                                    }
                                } else {
                                    println!(
                                        "Discord live-flow fallback: поток заблокирован, но ни один arm не получил полную серию STUN-ответов"
                                    );
                                }
                            } else {
                                println!(
                                    "Discord live-flow fallback {} -> {}:{}: {}",
                                    r2o_target.client,
                                    r2o_target.server.ip(),
                                    r2o_target.server.port(),
                                    r2o_fallback.reason
                                );
                            }
                        } else {
                            println!(
                                "Discord Discovery {} -> {}:{}: прямой зонд не дал блокировки, точный conntrack-поток уже завершился или не найден",
                                r2o_target.client,
                                r2o_target.server.ip(),
                                r2o_target.server.port()
                            );
                        }
                        std::io::stdout().flush()?;
                        continue;
                    }
                    let r2o_detail =
                        match &r2o_outcome.result.verdict {
                            r2o_controller::voice_discovery::R2oDiscoveryVerdict::Continue => {
                                "прямой Discovery пока не показал повторяемого обрыва".to_owned()
                            }
                            r2o_controller::voice_discovery::R2oDiscoveryVerdict::Clear => {
                                "Discovery отвечает без кандидата на исправление".to_owned()
                            }
                            r2o_controller::voice_discovery::R2oDiscoveryVerdict::Flaky => {
                                "граница обрыва не повторилась".to_owned()
                            }
                            r2o_controller::voice_discovery::R2oDiscoveryVerdict::Unmeasured => {
                                r2o_outcome.result.error.clone().unwrap_or_else(|| {
                                    "зонд не дал измеримого результата".to_owned()
                                })
                            }
                            r2o_controller::voice_discovery::R2oDiscoveryVerdict::Blocked {
                                ..
                            } => "кандидат прошёл Discovery-проверку".to_owned(),
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
                if let Some(outcome) = http_search.as_ref().and_then(HttpSearchWorker::try_outcome)
                {
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
                    let now = std::time::Instant::now();
                    if !outcome.deny_recheck {
                        quic_trial_cooldowns.insert(
                            outcome.server.ip(),
                            now + r2o_quic_discovery_cooldown(&outcome.result),
                        );
                    }
                    let family = if outcome.server.is_ipv4() { 4 } else { 6 };
                    if outcome.deny_recheck {
                        if outcome.stall_cut {
                            if let Some((_, catalog, path, _)) = &mut discovery {
                                match self.r2o_install_quic_deny(
                                    &outcome.host,
                                    family,
                                    outcome.server,
                                    &outcome.snapshot,
                                    catalog,
                                    path,
                                    &mut quic_deny,
                                ) {
                                    Ok(Some(_)) => {}
                                    Ok(None) => quic_deny.r2o_recheck_retry(&outcome.host, family),
                                    Err(error) => {
                                        quic_deny.r2o_recheck_retry(&outcome.host, family);
                                        eprintln!(
                                            "повторное продление запрета QUIC не удалось: {error}"
                                        );
                                    }
                                }
                            } else {
                                quic_deny.r2o_recheck_retry(&outcome.host, family);
                            }
                        } else if quic_deny.r2o_recheck_clear(&outcome.host, family) {
                            println!(
                                "по {} (QUIC) собственная HTTP/3-перепроверка не воспроизвела обрыв; снимаю временный запрет",
                                outcome.host
                            );
                        }
                    } else {
                        match outcome.result {
                            Ok(Some((plan_text, candidate_name))) => {
                                if let Some((_, catalog, path, _)) = &mut discovery {
                                    self.r2o_install_quic_candidate(
                                        outcome.server,
                                        &outcome.host,
                                        &outcome.snapshot,
                                        &outcome.probe_path,
                                        &plan_text,
                                        &candidate_name,
                                        catalog,
                                        path,
                                    )?;
                                }
                            }
                            Ok(None) if outcome.stall_cut => {
                                if outcome.host.parse::<std::net::IpAddr>().is_ok() {
                                    println!(
                                        "QUIC-обрыв подтверждён по IP; временный запрет по имени не применяется без SNI"
                                    );
                                } else if let Some((_, catalog, path, _)) = &mut discovery {
                                    if let Err(error) = self.r2o_install_quic_deny(
                                        &outcome.host,
                                        family,
                                        outcome.server,
                                        &outcome.snapshot,
                                        catalog,
                                        path,
                                        &mut quic_deny,
                                    ) {
                                        eprintln!("временный запрет QUIC не установлен: {error}");
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(error) => eprintln!("QUIC-испытание не завершено: {error}"),
                        }
                    }
                    std::io::stdout().flush()?;
                    continue;
                }
                if let Some(outcome) = r2o_late_rx.as_ref().and_then(R2oLateRxWorker::try_outcome) {
                    let host = outcome.input.options.name.clone();
                    let discovery_target = outcome.input.discovery_target;
                    let measured_path = outcome.result.measured_path.clone();
                    if let Some(evidence) = outcome.result.evidence {
                        println!(
                            "парная RX-проверка {host}: обрыв подтверждён по identity/gzip, граница около {} КБ из {} КБ; событие не устанавливает план само по себе",
                            evidence.cut_kb, evidence.expected_kb
                        );
                        if let (Some(path), Some((worker, _, _, _))) =
                            (measured_path.as_deref(), &mut discovery)
                        {
                            worker.remember_proven_resource(&host, path, std::time::Instant::now());
                        }
                        if let Some(target) = discovery_target
                            && let Some((worker, _, _, _)) = &mut discovery
                        {
                            if worker.is_active(&target) {
                                println!(
                                    "классификация {} уже выполняется; повторную задачу не создаю",
                                    target.host
                                );
                            } else if worker.queue_after_confirmed_failure(target.clone()) {
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
                            .or_else(|| {
                                http_search.as_ref().and_then(HttpSearchWorker::try_command)
                            })
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
                    let now = std::time::Instant::now();
                    if let Some((host, family)) =
                        quic_deny.r2o_pending_removals(now).into_iter().next()
                    {
                        let removed = if discovery.is_some() {
                            match self.r2o_remove_quic_deny(&host, family) {
                                Ok(()) => {
                                    println!("по {host} (QUIC) временный запрет снят");
                                    true
                                }
                                Err(error) => {
                                    eprintln!(
                                        "по {host} (QUIC) не удалось снять временный запрет: {error}"
                                    );
                                    false
                                }
                            }
                        } else {
                            false
                        };
                        quic_deny.r2o_finish_removal(&host, family, removed, now);
                        continue;
                    }
                    if let Some((_, _, _, mark)) = discovery.as_ref()
                        && r2o_pending_quic_discovery.len() < R2O_QUIC_TRIAL_QUEUE_CAPACITY
                        && let Some(entry) = quic_deny.r2o_due_rechecks(now).into_iter().next()
                    {
                        if quic_deny.r2o_start_recheck(&entry.name, entry.family, now) {
                            r2o_enqueue_quic_discovery(
                                &mut r2o_pending_quic_discovery,
                                entry.server,
                                entry.snapshot,
                                now,
                                *mark,
                                &measurement_gate,
                                true,
                            );
                            println!(
                                "по {} (QUIC) срок запрета вышел; собственная прямая HTTP/3-перепроверка поставлена в очередь",
                                entry.name
                            );
                        }
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
                            if expired.deny_recheck {
                                if let Some(host) =
                                    r2o_quic_snapshot_server_name(&expired.snapshot, expired.server)
                                {
                                    quic_deny.r2o_recheck_retry(
                                        &host,
                                        if expired.server.is_ipv4() { 4 } else { 6 },
                                    );
                                }
                            }
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
                            let pending_host =
                                r2o_quic_snapshot_server_name(&pending.snapshot, pending.server);
                            let pending_family = if pending.server.is_ipv4() { 4 } else { 6 };
                            let probe_path = discovery
                                .as_ref()
                                .map(|(worker, catalog, _, _)| {
                                    r2o_quic_discovery_probe_path(
                                        &pending.snapshot,
                                        pending.server,
                                        catalog,
                                        &worker.resource_memory,
                                    )
                                })
                                .unwrap_or_else(|| "/".into());
                            if !worker.queue(R2oQuicDiscoveryTask {
                                server: pending.server,
                                snapshot: pending.snapshot,
                                probe_path,
                                r2o_mark: pending.r2o_mark,
                                permit,
                                started_at: std::time::Instant::now(),
                                deny_recheck: pending.deny_recheck,
                                stall_cut: false,
                            }) {
                                quic_trial_cooldowns.remove(&pending.server.ip());
                                if pending.deny_recheck {
                                    if let Some(host) = pending_host {
                                        quic_deny.r2o_recheck_retry(&host, pending_family);
                                    }
                                }
                                eprintln!(
                                    "QUIC-испытание {} не попало в очередь worker",
                                    pending.server
                                );
                            }
                            std::io::stdout().flush()?;
                            continue;
                        }
                    }
                    if !wait_for_control_frame(&self.socket, std::time::Duration::from_millis(100))?
                    {
                        measurement_gate.r2o_scheduler_tick();
                        continue;
                    }
                    let Some(frame) = read_optional_frame(&mut self.socket)? else {
                        return Ok(());
                    };
                    self.pending_events.extend(r2o_read_control_batch(
                        &mut self.socket,
                        frame,
                        256,
                    )?);
                    r2o_scheduler_tick_pending = true;
                    self.pending_events
                        .pop_front()
                        .expect("добавленное событие управляющего канала")
                };
                if frame.kind == EVENT_PROTOCOL {
                    self.r2o_update_send_cap(&frame)?;
                    continue;
                }
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
                    continue;
                }
                if matches!(
                    frame.kind,
                    EVENT_R2O_VOICE_PROOF | EVENT_R2O_VOICE_STUN_PROOF | EVENT_R2O_VOICE_RTP_PROOF
                ) {
                    let proof = decode_r2o_voice_proof(&frame)
                        .map_err(|error| format!("подтверждение голосового потока: {error}"))?;
                    let proof_name = match proof.proof {
                        r2k_core::control::R2oVoiceProofKind::DiscordDiscovery { .. } => {
                            "Discord Discovery"
                        }
                        r2k_core::control::R2oVoiceProofKind::StunBinding => "STUN",
                        r2k_core::control::R2oVoiceProofKind::RtpMedia { .. } => "RTP",
                    };
                    let Some(trial) = r2o_voice_trials.get(&proof.trial_id).cloned() else {
                        println!(
                            "{proof_name}-ответ не относится к активному временному voice-плану"
                        );
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
                        println!(
                            "{proof_name}-ответ пришёл после истечения временного voice-плана"
                        );
                        std::io::stdout().flush()?;
                        continue;
                    }
                    if !r2o_voice_proof_matches_target(&proof, trial.target) {
                        println!(
                            "{proof_name}-доказательство пришло по другому клиентскому или серверному адресу"
                        );
                        std::io::stdout().flush()?;
                        continue;
                    }
                    match proof.proof {
                        r2k_core::control::R2oVoiceProofKind::DiscordDiscovery { .. }
                        | r2k_core::control::R2oVoiceProofKind::StunBinding => {
                            if let Some(active_trial) = r2o_voice_trials.get_mut(&proof.trial_id) {
                                active_trial.response_confirmed = true;
                            }
                            println!(
                                "{proof_name}-ответ временного плана подтверждён для {}; ожидаются минимум {} принятых RTP-пакета в каждом направлении",
                                trial.target.server,
                                r2k_core::control::VOICE_RTP_PROOF_MIN_PACKETS
                            );
                        }
                        r2k_core::control::R2oVoiceProofKind::RtpMedia { .. } => {
                            if !trial.response_confirmed {
                                println!(
                                    "RTP-доказательство проигнорировано: нет подтверждённого Discovery/STUN-ответа для попытки"
                                );
                            } else if let Some((_, catalog, path, _)) = &mut discovery {
                                r2o_voice_trials.remove(&proof.trial_id);
                                if let Err(error) = self.confirm_r2o_voice_trial(
                                    trial.clone(),
                                    &proof,
                                    catalog,
                                    path,
                                ) {
                                    r2o_voice_trials.insert(trial.trial_id, trial);
                                    eprintln!("voice-план не подтверждён: {error}");
                                }
                            } else {
                                println!(
                                    "RTP-доказательство получено без активного каталога автопоиска"
                                );
                            }
                        }
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
                    if let Some(r2o_trial) =
                        r2o_take_silent_voice_trial(&mut r2o_voice_trials, &event.key, &r2o_target)
                    {
                        let r2o_retired = match self.retire_r2o_voice_trial(&r2o_trial) {
                            Ok(()) => true,
                            Err(error) => {
                                eprintln!(
                                    "голосовой приём не пробил; временное правило истечёт по аренде, досрочное снятие не удалось: {error}"
                                );
                                let mut r2o_trial = r2o_trial;
                                r2o_hold_voice_trial_until_expiry(&mut r2o_trial);
                                r2o_voice_trials.insert(r2o_trial.trial_id, r2o_trial);
                                false
                            }
                        };
                        let r2o_queued = if r2o_retired {
                            if let (Some(r2o_worker), Some((_, catalog, _, _))) =
                                (&mut voice_discovery, &discovery)
                            {
                                let r2o_known_prefix = r2o_known_voice_discovery_prefix(
                                    catalog,
                                    *r2o_target.server.ip(),
                                );
                                let r2o_flow =
                                    r2o_controller::voice_discovery::r2o_voice_observed_flow_from_event(
                                        &event,
                                    );
                                r2o_worker.queue_after_new_session_with_flow(
                                    r2o_target,
                                    r2o_known_prefix,
                                    r2o_flow,
                                    r2o_voice_trials.is_empty(),
                                )
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        println!(
                            "голосовой приём не пробил поток {} -> {}:{}; {}",
                            r2o_target.client,
                            r2o_target.server.ip(),
                            r2o_target.server.port(),
                            if r2o_queued {
                                "проверка для новой сессии поставлена в ограниченную очередь"
                            } else if r2o_retired {
                                "предыдущая проба снята; новая проверка ждёт свободного слота"
                            } else {
                                "предыдущее правило не снято и останется до срока аренды"
                            }
                        );
                        std::io::stdout().flush()?;
                        continue;
                    }
                    let r2o_queued = if let (Some(r2o_worker), Some((_, catalog, _, _))) =
                        (&mut voice_discovery, &discovery)
                    {
                        if r2o_voice_target_has_active_trial(&r2o_voice_trials, &r2o_target) {
                            false
                        } else {
                            let r2o_known_prefix =
                                r2o_known_voice_discovery_prefix(catalog, *r2o_target.server.ip());
                            let r2o_flow =
                                r2o_controller::voice_discovery::r2o_voice_observed_flow_from_event(
                                    &event,
                                );
                            r2o_worker.queue_after_new_session_with_flow(
                                r2o_target,
                                r2o_known_prefix,
                                r2o_flow,
                                r2o_voice_trials.is_empty(),
                            )
                        }
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
                            "наблюдение QUIC: после видимого ответа серверные пакеты не доходят, клиент продолжает передачу: {client} -> {server}; план применялся={}; это не подтверждает блокировку",
                            event.planned
                        );
                    } else {
                        println!(
                            "наблюдение QUIC: после повтора Initial ответ не виден минимум 2 с: {client} -> {server}; план применялся={}; это не подтверждает блокировку",
                            event.planned
                        );
                    }
                    let Some((_, catalog, _, r2o_mark)) = &mut discovery else {
                        std::io::stdout().flush()?;
                        continue;
                    };
                    if server.port() != 443 {
                        println!(
                            "QUIC-проба пропущена: временный план поддерживает только UDP/443"
                        );
                        std::io::stdout().flush()?;
                        continue;
                    }
                    let has_quic_binding =
                        r2o_controller::discovery::has_usable_quic_address_binding(
                            catalog,
                            server.ip(),
                        );
                    if r2o_quic_binding_blocks_retry(has_quic_binding, event.planned) {
                        println!("QUIC-проба пропущена: для адреса уже сохранён проверенный план");
                        std::io::stdout().flush()?;
                        continue;
                    }
                    if has_quic_binding && event.planned {
                        println!(
                            "QUIC-план на этом потоке уже применялся; адрес будет проверен повторно"
                        );
                    }
                    let now = std::time::Instant::now();
                    quic_trial_cooldowns.retain(|_, until| *until > now);
                    if quic_trial_cooldowns
                        .get(&server.ip())
                        .is_some_and(|until| *until > now)
                    {
                        println!(
                            "QUIC-проба пропущена: для адреса действует часовой интервал повтора"
                        );
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
                    let (snapshot, captured) = match quic_snapshots.remove(&event.key) {
                        Some((snapshot, captured))
                            if now.saturating_duration_since(captured)
                                <= std::time::Duration::from_secs(60) =>
                        {
                            (snapshot, captured)
                        }
                        _ => {
                            let server_name = quic_hello_names
                                .get(&event.key)
                                .filter(|(_, seen)| {
                                    now.saturating_duration_since(*seen)
                                        <= std::time::Duration::from_secs(60)
                                })
                                .and_then(|(name, _)| name.as_deref());
                            let Some(snapshot) =
                                r2o_controller::quic_replay::r2o_quic_profile_snapshot(server_name)
                            else {
                                println!(
                                    "QUIC-проба пропущена: не удалось собрать профиль Initial"
                                );
                                std::io::stdout().flush()?;
                                continue;
                            };
                            println!(
                                "QUIC Discovery использует свежий профиль {}",
                                server_name.unwrap_or("без SNI")
                            );
                            (snapshot, now)
                        }
                    };
                    quic_trial_cooldowns
                        .insert(server.ip(), now + std::time::Duration::from_secs(60 * 60));
                    let queued = r2o_enqueue_quic_discovery(
                        &mut r2o_pending_quic_discovery,
                        server,
                        snapshot,
                        captured,
                        *r2o_mark,
                        &measurement_gate,
                        false,
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
                    if event.planned {
                        println!(
                            "наблюдение TCP: под применённым планом после ClientHello нет видимого ответа {client} -> {server} за {} мс",
                            event.elapsed_ms
                        );
                        let target = r2o_late_rx_hellos
                            .discovery_target_for_tcp_silence(&event, std::time::Instant::now());
                        if let Some(target) = target {
                            let family_candidates = discovery
                                .as_ref()
                                .map(|(_, catalog, _, _)| {
                                    matching_domain_recovery_candidates(catalog, &target)
                                })
                                .unwrap_or_default();
                            let has_family_candidates = !family_candidates.is_empty();
                            let family_queued = has_family_candidates && {
                                let mark = discovery.as_ref().and_then(|(_, _, _, mark)| *mark);
                                family_recovery.as_mut().is_some_and(|worker| {
                                    worker.queue(target.clone(), family_candidates, mark)
                                })
                            };
                            if family_queued {
                                println!(
                                    "плановый отказ {} сначала проверит сохранённый план семейства через HTTPS",
                                    target.host
                                );
                            } else if has_family_candidates
                                && family_recovery
                                    .as_ref()
                                    .is_some_and(|worker| worker.active.contains(&target))
                            {
                                println!(
                                    "проверка семейного плана для {} уже выполняется",
                                    target.host
                                );
                            } else if let Some((worker, _, _, _)) = &mut discovery {
                                let queued = worker.queue_after_confirmed_failure(target.clone());
                                println!(
                                    "плановый отказ {}: {}",
                                    target.host,
                                    if queued {
                                        "сохранённый план недоступен или очередь проверки занята; запущена полная классификация"
                                    } else {
                                        "полная классификация уже выполняется или очередь занята"
                                    }
                                );
                            } else {
                                println!(
                                    "повторная классификация {} пропущена: Discovery не подключён",
                                    target.host
                                );
                            }
                        } else {
                            println!(
                                "повторная классификация не запущена: нет свежего полного ClientHello с SNI того же потока"
                            );
                        }
                    } else {
                        println!(
                            "наблюдение TCP: после ClientHello нет видимого ответа {client} -> {server} за {} мс без применённого плана; это не подтверждает блокировку",
                            event.elapsed_ms
                        );
                        let now = std::time::Instant::now();
                        let target = tcp_hello_names.target_for_tcp_flow(&event.key, now);
                        if let Some(target) = target {
                            if clean_handshakes.suppresses_unplanned_tcp_suspicion(
                                &target.host,
                                target.family,
                                event.planned,
                                now,
                            ) {
                                println!(
                                    "классификация {} пропущена: IPv{} недавно завершил TCP-рукопожатие без плана",
                                    target.host, target.family
                                );
                            } else if let Some((worker, catalog, _, _)) = &mut discovery {
                                if r2o_controller::discovery::has_usable_binding(catalog, &target)
                                    || r2o_controller::discovery::has_covering_binding(
                                        catalog, &target,
                                    )
                                    || matching_domain_group(catalog, &target).is_some()
                                {
                                    println!(
                                        "молчание без плана для {} не создаёт повторную задачу: каталог уже содержит применимое решение",
                                        target.host
                                    );
                                } else if worker.queue(target.clone()) {
                                    println!(
                                        "молчание TCP без чистого рукопожатия поставило {} в очередь классификации",
                                        target.host
                                    );
                                } else {
                                    println!(
                                        "классификация {} после молчания пропущена: задача уже выполняется, повтор запрещён или очередь занята",
                                        target.host
                                    );
                                }
                            }
                        }
                    }
                    std::io::stdout().flush()?;
                    continue;
                }
                if frame.kind == EVENT_R2O_TCP_RST_CUT {
                    let event = decode_r2o_tcp_rst_cut_signal(&frame)
                        .map_err(|error| format!("событие защитно снятого TCP RST: {error}"))?;
                    let (client, server) = flow_socket_addresses(&event.key, event.client_is_low);
                    println!(
                        "наблюдение TCP: защита сняла чужой RST до ответа {client} -> {server}; это сильный сигнал для повторной классификации"
                    );
                    let now = std::time::Instant::now();
                    if let Some(target) = tcp_hello_names.target_for_tcp_flow(&event.key, now) {
                        if let Some((worker, _, _, _)) = &mut discovery {
                            let queued = worker.queue_after_fresh_suspect(target.clone());
                            println!(
                                "снятый защитой RST поставил {} в очередь классификации: {}",
                                target.host,
                                if queued {
                                    "задача поставлена"
                                } else {
                                    "задача уже выполняется, повтор ожидает cooldown или очередь занята"
                                }
                            );
                        } else {
                            println!(
                                "классификация {} после снятого RST пропущена: Discovery не подключён",
                                target.host
                            );
                        }
                    } else {
                        println!(
                            "классификация после снятого RST не запущена: нет свежего ClientHello с SNI того же потока"
                        );
                    }
                    std::io::stdout().flush()?;
                    continue;
                }
                if frame.kind == EVENT_R2O_TCP_EARLY_RST {
                    let event = decode_r2o_tcp_early_rst(&frame)
                        .map_err(|error| format!("событие раннего TCP RST: {error}"))?;
                    let (client, server) = flow_socket_addresses(&event.key, event.client_is_low);
                    println!(
                        "наблюдение TCP: ранний RST от сервера {client} -> {server}, план применён={}; событие само по себе не подтверждает блокировку",
                        event.planned
                    );
                    let now = std::time::Instant::now();
                    if let Some(target) = tcp_hello_names.target_for_tcp_flow(&event.key, now) {
                        if clean_handshakes.suppresses_unplanned_tcp_suspicion(
                            &target.host,
                            target.family,
                            event.planned,
                            now,
                        ) {
                            println!(
                                "классификация {} пропущена: IPv{} недавно завершил TCP-рукопожатие без плана",
                                target.host, target.family
                            );
                        } else if let Some((worker, catalog, _, _)) = &mut discovery {
                            let has_solution =
                                r2o_controller::discovery::has_usable_binding(catalog, &target)
                                    || r2o_controller::discovery::has_covering_binding(
                                        catalog, &target,
                                    )
                                    || matching_domain_group(catalog, &target).is_some();
                            if event.planned {
                                let queued = if has_solution {
                                    worker.queue_after_confirmed_failure(target.clone())
                                } else {
                                    worker.queue(target.clone())
                                };
                                println!(
                                    "ранний TCP RST поставил {} на повторную проверку плана: {}",
                                    target.host,
                                    if queued {
                                        "задача поставлена"
                                    } else {
                                        "задача уже выполняется или очередь занята"
                                    }
                                );
                            } else if has_solution {
                                println!(
                                    "RST без плана для {} не создаёт задачу: каталог уже содержит применимое решение",
                                    target.host
                                );
                            } else if worker.queue(target.clone()) {
                                println!(
                                    "ранний TCP RST без чистого рукопожатия поставил {} в очередь классификации",
                                    target.host
                                );
                            } else {
                                println!(
                                    "классификация {} после раннего RST пропущена: задача уже выполняется или очередь занята",
                                    target.host
                                );
                            }
                        }
                    } else {
                        println!(
                            "классификация после раннего RST не запущена: нет свежего ClientHello с SNI того же потока"
                        );
                    }
                    std::io::stdout().flush()?;
                    continue;
                }
                if frame.kind == EVENT_R2O_TCP_REPEAT {
                    let event = decode_r2o_tcp_repeat(&frame)
                        .map_err(|error| format!("событие повторного ClientHello TCP: {error}"))?;
                    let (client, server) = flow_socket_addresses(&event.key, event.client_is_low);
                    println!(
                        "наблюдение TCP: ClientHello повторён без TLS-ответа {client} -> {server}, план применён={}; повтор сам по себе не подтверждает блокировку",
                        event.planned
                    );
                    let now = std::time::Instant::now();
                    if let Some(target) = tcp_hello_names.target_for_tcp_flow(&event.key, now) {
                        if clean_handshakes.suppresses_unplanned_tcp_suspicion(
                            &target.host,
                            target.family,
                            event.planned,
                            now,
                        ) {
                            println!(
                                "классификация {} пропущена: IPv{} недавно завершил TCP-рукопожатие без плана",
                                target.host, target.family
                            );
                        } else if let Some((worker, catalog, _, _)) = &mut discovery {
                            let has_solution =
                                r2o_controller::discovery::has_usable_binding(catalog, &target)
                                    || r2o_controller::discovery::has_covering_binding(
                                        catalog, &target,
                                    )
                                    || matching_domain_group(catalog, &target).is_some();
                            if event.planned {
                                let queued = if has_solution {
                                    worker.queue_after_confirmed_failure(target.clone())
                                } else {
                                    worker.queue(target.clone())
                                };
                                println!(
                                    "повтор ClientHello под планом поставил {} на проверку: {}",
                                    target.host,
                                    if queued {
                                        "задача поставлена"
                                    } else {
                                        "задача уже выполняется или очередь занята"
                                    }
                                );
                            } else if has_solution {
                                println!(
                                    "повтор ClientHello без плана для {} не создаёт задачу: каталог уже содержит применимое решение",
                                    target.host
                                );
                            } else if worker.queue(target.clone()) {
                                println!(
                                    "повтор ClientHello без плана поставил {} в очередь классификации",
                                    target.host
                                );
                            } else {
                                println!(
                                    "классификация {} после повтора ClientHello пропущена: задача уже выполняется или очередь занята",
                                    target.host
                                );
                            }
                        }
                    } else {
                        println!(
                            "классификация после повтора ClientHello не запущена: нет свежего ClientHello с SNI того же потока"
                        );
                    }
                    std::io::stdout().flush()?;
                    continue;
                }
                if frame.kind == EVENT_R2O_TCP_STALL {
                    let event = decode_r2o_tcp_stall(&frame)
                        .map_err(|error| format!("событие зависания TCP: {error}"))?;
                    let (client, server) = flow_socket_addresses(&event.key, event.client_is_low);
                    println!(
                        "наблюдение TCP: поток {client} -> {server} замер на оценке {} пакетов; ответ не виден {} мс; план применялся={}; это не подтверждает блокировку",
                        event.estimated_packets, event.elapsed_ms, event.planned
                    );
                    if let Some(worker) = &mut r2o_late_rx {
                        let now = std::time::Instant::now();
                        let mark = discovery.as_ref().and_then(|(_, _, _, mark)| *mark);
                        match r2o_late_rx_hellos.take_for_tcp_stall(&event, mark, now) {
                            Some(input)
                                if r2o_late_rx_is_covered_by_catalog(
                                    &input,
                                    event.planned,
                                    discovery.as_ref().map(|(_, catalog, _, _)| catalog),
                                ) =>
                            {
                                println!(
                                    "парная RX-проверка {} пропущена: подтверждённая привязка покрывает форму потока без применённого плана",
                                    input.options.name
                                );
                            }
                            Some(mut input) => {
                                if let Some((discovery_worker, catalog, _, _)) = discovery.as_ref()
                                {
                                    discovery_worker
                                        .prepare_late_rx_resource_paths(&mut input, catalog);
                                }
                                let host = input.options.name.clone();
                                let in_band =
                                    discovery.as_ref().is_none_or(|(_, catalog, _, _)| {
                                        r2o_tcp_stall_in_name_band(
                                            catalog,
                                            &host,
                                            event.estimated_packets,
                                        )
                                    });
                                if !in_band {
                                    println!(
                                        "парная RX-проверка {host} не запущена: оценка {} пакетов вне измеренного бюджета коробки",
                                        event.estimated_packets
                                    );
                                } else if worker.queue(input, now) {
                                    println!(
                                        "зависание TCP поставило парную identity/gzip RX-проверку для {host}"
                                    );
                                } else {
                                    println!(
                                        "парная RX-проверка {host} пропущена: очередь занята или действует десятиминутный предел"
                                    );
                                }
                            }
                            None => println!(
                                "парная RX-проверка не запущена: нет свежего полного ClientHello с SNI для потока {client} -> {server}"
                            ),
                        }
                    }
                    std::io::stdout().flush()?;
                    continue;
                }
                if frame.kind == EVENT_R2O_TCP_FIN_RETRY {
                    let event = decode_r2o_tcp_fin_retry(&frame)
                        .map_err(|error| format!("событие повтора FIN TCP: {error}"))?;
                    let (client, server) = flow_socket_addresses(&event.key, event.client_is_low);
                    if event.planned {
                        println!(
                            "наблюдение TCP: поток {client} -> {server} повторил FIN под применённым планом; запускаю контрольную RX-проверку"
                        );
                    } else {
                        println!(
                            "наблюдение TCP: поток {client} -> {server} повторил FIN без применённого плана; запускаю парную проверку объёма ответа"
                        );
                    }
                    if let Some(worker) = &mut r2o_late_rx {
                        let now = std::time::Instant::now();
                        let mark = discovery.as_ref().and_then(|(_, _, _, mark)| *mark);
                        match r2o_late_rx_hellos.take_for_fin_retry(&event, mark, now) {
                            Some(input)
                                if r2o_late_rx_is_covered_by_catalog(
                                    &input,
                                    event.planned,
                                    discovery.as_ref().map(|(_, catalog, _, _)| catalog),
                                ) =>
                            {
                                println!(
                                    "парная RX-проверка для {client} -> {server} пропущена: подтверждённая привязка покрывает форму потока без применённого плана"
                                );
                            }
                            Some(mut input) => {
                                if let Some((discovery_worker, catalog, _, _)) = discovery.as_ref()
                                {
                                    discovery_worker
                                        .prepare_late_rx_resource_paths(&mut input, catalog);
                                }
                                if worker.queue(input, now) {
                                    println!(
                                        "повтор FIN поставил парную identity/gzip RX-проверку для {client} -> {server}"
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
                    } else {
                        println!(
                            "парная RX-проверка для {client} -> {server} не запущена: измеритель не подключён"
                        );
                    }
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
                            Some(input)
                                if r2o_late_rx_is_covered_by_catalog(
                                    &input,
                                    event.planned,
                                    discovery.as_ref().map(|(_, catalog, _, _)| catalog),
                                ) =>
                            {
                                println!(
                                    "парная RX-проверка для {client} -> {server} пропущена: подтверждённая привязка покрывает форму потока без применённого плана"
                                );
                            }
                            Some(mut input) => {
                                if let Some((discovery_worker, catalog, _, _)) = discovery.as_ref()
                                {
                                    discovery_worker
                                        .prepare_late_rx_resource_paths(&mut input, catalog);
                                }
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
                    let acked_binding = self.acknowledged_http_binding_for(&response);
                    let live_owner = acked_binding.is_some_and(|binding| {
                        discovery.as_ref().is_some_and(|(_, catalog, _, _)| {
                            r2o_controller::discovery::matches_confirmed_http_catalog_owner(
                                catalog, &response, binding,
                            )
                        })
                    });
                    if live_owner {
                        let outcome = if response.code == 1 {
                            "response-complete"
                        } else {
                            "unknown"
                        };
                        let plan_id: String = response
                            .plan_id
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect();
                        println!(
                            "HTTP live target={} IPv{} request={} execution={} plan={} generation={} outcome={} status={} body={}; scope=request, connection=pending",
                            String::from_utf8_lossy(&response.host),
                            response.key[0],
                            response.request_no,
                            response.execution_id,
                            plan_id,
                            response.binding.generation,
                            outcome,
                            response.status,
                            response.body_bytes,
                        );
                    } else {
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
                    }
                    std::io::stdout().flush()?;
                    if let Some((host, address)) = target_from_http_response(&response) {
                        https_probe.submit(&host, address, std::time::Instant::now());
                    }
                    if let Some((_, catalog, path, mark)) = &mut discovery {
                        let live = response.binding.is_known()
                            && !response.binding.temporary
                            && response.binding.kind == 1
                            && response.binding.family == response.key[0]
                            && response.binding.shape == SHAPE_HTTP
                            && response.execution_id != 0
                            && response.request_ms != 0
                            && response.trial_id.iter().all(|byte| *byte == 0);
                        if let Some((target, request_path, expected)) =
                            r2o_http_search_from_response(&response)
                            && (response.code != 3
                                || !live
                                || self.revoke_http_binding(&response, &target, catalog, path)?)
                        {
                            if live && response.code == 3 {
                                self.http_search_started.remove(&http_search_key(&target));
                            }
                            let queued = http_search.as_ref().is_some_and(|worker| {
                                self.enqueue_http_search(
                                    worker,
                                    &target,
                                    request_path,
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
                    let applied = decode_applied(&frame)
                        .map_err(|error| format!("событие APPLIED: {error}"))?;
                    if let Some(r2o_trial) = r2o_voice_trials.get_mut(&applied.trial_id)
                        && r2o_trial.expires_at > std::time::Instant::now()
                        && r2o_voice_applied_flow_matches(r2o_trial, &applied)
                    {
                        r2o_trial.voice_flow_key = Some(applied.key);
                    }
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
                if frame.kind == EVENT_R2O_TCP_CLEAN_HANDSHAKE {
                    let event = decode_r2o_tcp_clean_handshake(&frame)
                        .map_err(|error| format!("чистое TCP-рукопожатие: {error}"))?;
                    let now = std::time::Instant::now();
                    if let Some(name) = tcp_hello_names.clean_handshake_name(&event.key, now) {
                        clean_handshakes.note(&name, event.key[0], now);
                    }
                    continue;
                }
                if frame.kind == EVENT_CLIENT_SHAPE {
                    let shape = decode_client_shape(&frame)
                        .map_err(|error| format!("снимок ClientHello: {error}"))?;
                    if let Some((worker, catalog, _, _)) = &mut discovery
                        && let Some(target) =
                            r2o_controller::discovery::DiscoveryTarget::from_client_shape(&shape)
                    {
                        worker.remember_client_snapshot(&target, &shape.client_hello);
                        if r2o_controller::discovery::has_usable_profile_binding(catalog, &target)
                            || !r2o_controller::discovery::has_usable_binding(catalog, &target)
                                && !r2o_controller::discovery::has_covering_binding(
                                    catalog, &target,
                                )
                        {
                            let profile_only =
                                r2o_controller::discovery::has_usable_profile_binding(
                                    catalog, &target,
                                );
                            if worker
                                .queue_client_snapshot(target.clone(), shape.client_hello.clone())
                            {
                                if profile_only {
                                    println!(
                                        "привязка {} повторно измеряется по полному ClientHello клиента",
                                        target.host
                                    );
                                } else {
                                    println!(
                                        "автоклассификация {} запущена по полному ClientHello клиента",
                                        target.host
                                    );
                                }
                            } else {
                                println!(
                                    "снимок {} пропущен: проверка уже запущена или очередь занята",
                                    target.host
                                );
                            }
                        }
                    }
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
                if hello.key[37] == 6 {
                    let now = std::time::Instant::now();
                    tcp_hello_names.note(hello.clone(), now);
                    tcp_witness_names
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .note(&hello, now);
                }
                if hello.key[37] == 17 {
                    let now = std::time::Instant::now();
                    quic_hello_names.retain(|_, (_, seen)| {
                        now.saturating_duration_since(*seen) < std::time::Duration::from_secs(60)
                    });
                    if quic_hello_names.len() >= 128 && !quic_hello_names.contains_key(&hello.key) {
                        if let Some(oldest) = quic_hello_names
                            .iter()
                            .min_by_key(|(_, (_, seen))| *seen)
                            .map(|(key, _)| *key)
                        {
                            quic_hello_names.remove(&oldest);
                        }
                    }
                    let name = hello
                        .host
                        .as_deref()
                        .and_then(|host| std::str::from_utf8(host).ok())
                        .filter(|host| !host.is_empty())
                        .map(str::to_owned);
                    quic_hello_names.insert(hello.key, (name, now));
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
                if let Some((discovery_worker, catalog, _, _)) = discovery.as_ref()
                    && quic_discovery.as_ref().is_some_and(|worker| {
                        worker.queue_client_snapshot(
                            &hello,
                            catalog,
                            &discovery_worker.resource_memory,
                        )
                    })
                {
                    println!(
                        "во время QUIC Discovery сохранён новейший Initial для одного повтора"
                    );
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
                    && let Some(target) =
                        r2o_controller::discovery::DiscoveryTarget::from_event(&hello)
                {
                    if r2o_controller::discovery::has_usable_profile_binding(catalog, &target) {
                        println!(
                            "каталог покрывает {}, но привязка измерена профилем; жду полный снимок ClientHello",
                            target.host
                        );
                    } else if r2o_controller::discovery::has_usable_binding(catalog, &target)
                        || r2o_controller::discovery::has_covering_binding(catalog, &target)
                    {
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
        })();
        let family_shutdown_result = if let (Some(worker), Some((_, catalog, path, _))) =
            (family_recovery.as_mut(), discovery.as_mut())
        {
            self.r2o_stop_family_recovery(
                worker,
                http_search.as_ref(),
                quic_discovery.as_ref(),
                catalog,
                path,
            )
        } else {
            Ok(())
        };
        let shutdown_result = if let (Some(worker), Some((_, catalog, path, _))) =
            (quic_discovery.as_mut(), discovery.as_mut())
        {
            self.r2o_stop_quic_discovery(worker, catalog, path)
        } else {
            Ok(())
        };
        match (run_result, family_shutdown_result, shutdown_result) {
            (Ok(()), Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(()), Ok(()))
            | (Ok(()), Err(error), Ok(()))
            | (Ok(()), Ok(()), Err(error)) => Err(error),
            (run_result, family_result, quic_result) => Err(format!(
                "цикл событий: {}; семейное восстановление: {}; QUIC Discovery: {}",
                run_result.map_or_else(|error| error.to_string(), |_| "завершён".into()),
                family_result.map_or_else(|error| error.to_string(), |_| "завершено".into()),
                quic_result.map_or_else(|error| error.to_string(), |_| "завершён".into()),
            )
            .into()),
        }
    }

    fn r2o_stop_family_recovery(
        &mut self,
        worker: &mut R2oFamilyRecoveryWorker,
        http_worker: Option<&HttpSearchWorker>,
        quic_worker: Option<&R2oQuicDiscoveryWorker>,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        worker.r2o_begin_shutdown();
        let mut cleanup_error = None;
        while !worker.r2o_all_finished() {
            let command = http_worker
                .and_then(HttpSearchWorker::try_command)
                .or_else(|| quic_worker.and_then(R2oQuicDiscoveryWorker::try_command));
            if let Some(command) = command
                && let Err(error) = self.service_http_search_command(command, catalog, catalog_path)
            {
                cleanup_error.get_or_insert_with(|| error.to_string());
            }
            while worker.try_outcome().is_some() {}
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        while worker.try_outcome().is_some() {}
        worker.r2o_join();
        if let Some(error) = cleanup_error {
            Err(format!("не удалось завершить семейное восстановление: {error}").into())
        } else {
            Ok(())
        }
    }

    fn r2o_stop_quic_discovery(
        &mut self,
        worker: &mut R2oQuicDiscoveryWorker,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        worker.r2o_begin_shutdown();
        let mut cleanup_error = None;
        while !worker.r2o_all_finished() {
            while let Some(command) = worker.try_command() {
                if let Err(error) = self.service_http_search_command(command, catalog, catalog_path)
                {
                    cleanup_error.get_or_insert_with(|| error.to_string());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        while let Some(command) = worker.try_command() {
            if let Err(error) = self.service_http_search_command(command, catalog, catalog_path) {
                cleanup_error.get_or_insert_with(|| error.to_string());
            }
        }
        worker.r2o_join();
        if let Some(error) = cleanup_error {
            Err(format!("не удалось завершить QUIC Discovery: {error}").into())
        } else {
            Ok(())
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
                shape,
                family,
                port,
                command,
                trial_id,
                reply,
            } => {
                let ack = match self.exchange_command(&command, control::COMMAND_SET_NAME_PROBE) {
                    Ok(ack) => ack,
                    Err(error) => {
                        match self.delete_name_probe(&host, shape, family, port) {
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
                    match self.delete_name_probe(&host, shape, family, port) {
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
                shape,
                family,
                port,
                reply,
            } => {
                let result = self
                    .delete_name_probe(&host, shape, family, port)
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

    fn delete_name_probe(
        &mut self,
        host: &str,
        shape: u8,
        family: u8,
        port: u16,
    ) -> Result<(), String> {
        let command = encode_delete_name_probe(host, shape, family, port)
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

    fn wait_for_client_shape(
        &mut self,
        host: &str,
        family: u8,
        timeout: std::time::Duration,
    ) -> Result<Option<r2k_core::control::ClientShapeEvent>, Box<dyn Error>> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or("срок захвата ClientHello слишком велик")?;
        loop {
            let queued = self.pending_events.len();
            for _ in 0..queued {
                let Some(frame) = self.pending_events.pop_front() else {
                    break;
                };
                if frame.kind == EVENT_CLIENT_SHAPE {
                    let event = decode_client_shape(&frame)
                        .map_err(|error| format!("снимок ClientHello: {error}"))?;
                    if event.key[0] == family && event.host.eq_ignore_ascii_case(host.as_bytes()) {
                        return Ok(Some(event));
                    }
                } else {
                    self.pending_events.push_back(frame);
                }
            }

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            if !wait_for_control_frame(
                &self.socket,
                remaining.min(std::time::Duration::from_millis(100)),
            )? {
                continue;
            }
            let Some(frame) = read_optional_frame(&mut self.socket)? else {
                return Err("соединение с датапатом закрыто во время захвата ClientHello".into());
            };
            if frame.kind == EVENT_CLIENT_SHAPE {
                let event = decode_client_shape(&frame)
                    .map_err(|error| format!("снимок ClientHello: {error}"))?;
                if event.key[0] == family && event.host.eq_ignore_ascii_case(host.as_bytes()) {
                    return Ok(Some(event));
                }
            } else {
                self.queue_async_frame(frame)?;
            }
        }
    }

    fn arm_client_shape(&mut self, host: &str, family: u8) -> Result<(), Box<dyn Error>> {
        let command =
            encode_arm_shape(host, 6, family).map_err(|error| format!("ARM_SHAPE: {error}"))?;
        let ack = self.exchange_command(&command, COMMAND_ARM_SHAPE)?;
        if ack.ok {
            Ok(())
        } else {
            Err(format!("датапат отверг ARM_SHAPE для {host} (код {})", ack.reason).into())
        }
    }

    fn wait_for_ask_proof(
        &mut self,
        trial_id: [u8; 16],
        plan_id: [u8; 16],
        expected_key: [u8; r2k_core::control::KEY_LEN],
        family: u8,
        shape: u8,
        timeout: std::time::Duration,
    ) -> Result<R2oAskProof, Box<dyn Error>> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or("срок проверки TCP-обмена слишком велик")?;
        let mut proof = R2oAskProof::default();

        let pending_applied = std::mem::take(&mut self.pending_applied_events);
        for event in pending_applied {
            if event.trial_id == trial_id {
                proof.applied |= r2o_ask_applied_matches(
                    &event,
                    &expected_key,
                    plan_id,
                    trial_id,
                    family,
                    shape,
                );
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
                if !self.observe_ask_proof_frame(
                    &frame,
                    &mut proof,
                    &expected_key,
                    plan_id,
                    trial_id,
                    family,
                    shape,
                )? {
                    self.pending_events.push_back(frame);
                }
            }
            if proof.finished() {
                return Ok(proof);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(proof);
            }
            let wait = remaining.min(std::time::Duration::from_millis(100));
            if !wait_for_control_frame(&self.socket, wait)? {
                continue;
            }
            let Some(frame) = read_optional_frame(&mut self.socket)? else {
                return Err("соединение с датапатом закрыто во время проверки TCP-обмена".into());
            };
            if !self.observe_ask_proof_frame(
                &frame,
                &mut proof,
                &expected_key,
                plan_id,
                trial_id,
                family,
                shape,
            )? {
                self.queue_async_frame(frame)?;
            }
            if proof.finished() {
                return Ok(proof);
            }
        }
    }

    fn observe_ask_proof_frame(
        &mut self,
        frame: &Frame,
        proof: &mut R2oAskProof,
        expected_key: &[u8; r2k_core::control::KEY_LEN],
        plan_id: [u8; 16],
        trial_id: [u8; 16],
        family: u8,
        shape: u8,
    ) -> Result<bool, Box<dyn Error>> {
        if frame.kind == EVENT_APPLIED {
            let event =
                decode_applied(frame).map_err(|error| format!("событие APPLIED: {error}"))?;
            if !proof.observe_applied(&event, expected_key, plan_id, trial_id, family, shape) {
                self.remember_applied_event(event);
            }
            return Ok(true);
        }
        if frame.kind == EVENT_REFUSED {
            let event =
                decode_refused(frame).map_err(|error| format!("событие REFUSED: {error}"))?;
            return Ok(proof.observe_refused(&event, expected_key, plan_id, trial_id));
        }
        if frame.kind == EVENT_R2O_TCP_EXCHANGE {
            let event = decode_r2o_tcp_exchange(frame)
                .map_err(|error| format!("событие TCP-обмена: {error}"))?;
            if !proof.observe_exchange(&event, expected_key) {
                return Ok(false);
            }
            return Ok(true);
        }
        Ok(false)
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
        probe_path: &str,
        runtime: &tokio::runtime::Runtime,
        request_timeout: std::time::Duration,
        roots: &rustls::RootCertStore,
        retry_strategy: bool,
        started_at: std::time::Instant,
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
                if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                    return Err("истёк срок QUIC-испытания".into());
                }
                if !measurement_permit.r2o_yield_if_contended_with_cancel(cancel) {
                    return Err("QUIC-испытание отменено во время ожидания слота".into());
                }
                if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                    return Err("истёк срок QUIC-испытания".into());
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
                if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                    return Err("истёк срок QUIC-испытания".into());
                }
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

                let data = runtime.block_on(
                    r2o_controller::r2o_quic_http3::r2o_quic_http3_measure_with_max_duration(
                        probe.try_clone_socket()?,
                        server,
                        sni,
                        probe_path,
                        request_timeout,
                        roots.clone(),
                        r2o_controller::r2o_quic_http3::R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS,
                        r2o_quic_trial_remaining(started_at, measurement_permit),
                    ),
                );
                if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                    return Err("истёк срок QUIC-испытания".into());
                }
                let events = r2o_collect_controller_applied_events(
                    commands,
                    trial_id,
                    std::time::Duration::from_millis(400),
                )?;
                applied |= events.iter().any(|event| {
                    applied_quic_trial_matches(event, trial_id, plan_id, local, server)
                });
                if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                    return Err("истёк срок QUIC-испытания".into());
                }
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
            if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                return Err("истёк срок QUIC-испытания".into());
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
        probe_path: &str,
        commands: &SyncSender<HttpSearchCommand>,
        cancel: &AtomicBool,
        started_at: std::time::Instant,
        measurement_permit: &mut r2o_controller::r2o_resource_limit::R2oMeasurementPermit,
        r2o_mark: Option<u32>,
        deny_recheck: bool,
        stall_cut: &mut bool,
    ) -> Result<Option<(String, String)>, Box<dyn Error>> {
        use r2o_controller::quic_replay::QuicReplayProbe;

        if deny_recheck {
            if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                return Ok(None);
            }
            if !measurement_permit.r2o_yield_if_contended_with_cancel(cancel) {
                return Err("перепроверка запрета QUIC отменена".into());
            }
            if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                return Ok(None);
            }
            let Some(server_name) = r2o_quic_snapshot_server_name(snapshot, server) else {
                return Ok(None);
            };
            if server_name.parse::<std::net::IpAddr>().is_ok() {
                return Ok(None);
            }
            let mut probe = match QuicReplayProbe::prepare(server, snapshot, r2o_mark) {
                Ok(probe) => probe,
                Err(error) => {
                    eprintln!("прямая перепроверка запрета QUIC не подготовлена: {error}");
                    return Ok(None);
                }
            };
            #[cfg(test)]
            let request_timeout = std::time::Duration::from_millis(20);
            #[cfg(not(test))]
            let request_timeout = std::time::Duration::from_millis(u64::from(
                r2k_core::quic::r2k_quic_dynamic_wait_ms(0),
            ));
            if probe.r2o_quic_probe_filter(request_timeout, 0).decision
                != r2o_controller::quic_replay::R2oQuicFilterDecision::Pass
            {
                return Ok(None);
            }
            if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                return Ok(None);
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let result = runtime.block_on(
                r2o_controller::r2o_quic_http3::r2o_quic_http3_get_with_max_duration(
                    probe.try_clone_socket()?,
                    server,
                    &server_name,
                    probe_path,
                    request_timeout,
                    roots,
                    r2o_quic_trial_remaining(started_at, measurement_permit),
                ),
            );
            *stall_cut = r2o_quic_data_cut(&result);
            return Ok(None);
        }

        let mut probe = match QuicReplayProbe::prepare(server, snapshot, r2o_mark) {
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
        let remaining = r2o_quic_trial_remaining(started_at, measurement_permit);
        if remaining.is_zero() {
            return Ok(None);
        }
        let baseline = runtime.block_on(
            r2o_controller::r2o_quic_http3::r2o_quic_http3_get_with_max_duration(
                probe.try_clone_socket()?,
                server,
                &server_name,
                probe_path,
                request_timeout,
                roots.clone(),
                remaining,
            ),
        );
        if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
            println!("истёк срок QUIC-испытания во время исходного HTTP/3 GET");
            return Ok(None);
        }
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
            if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                println!("истёк срок QUIC-испытания; оставшиеся кандидаты пропущены");
                return Ok(None);
            }
            let outcome = match Self::run_quic_discovery_candidate(
                commands,
                cancel,
                server,
                local,
                &mut probe,
                &candidate,
                &server_name,
                probe_path,
                &runtime,
                request_timeout,
                &roots,
                true,
                started_at,
                measurement_permit,
            ) {
                Ok(Some(outcome)) => outcome,
                Ok(None) => continue,
                Err(error) => {
                    eprintln!(
                        "испытание QUIC-кандидата «{}» не завершено: {error}",
                        candidate.name
                    );
                    if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                        return Ok(None);
                    }
                    continue;
                }
            };
            *stall_cut |= outcome.applied && outcome.data.as_ref().is_some_and(r2o_quic_data_cut);
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
                if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                    println!("истёк срок QUIC-испытания; оставшиеся кандидаты пропущены");
                    return Ok(None);
                }
                let outcome = match Self::run_quic_discovery_candidate(
                    commands,
                    cancel,
                    server,
                    local,
                    &mut probe,
                    &candidate,
                    &server_name,
                    probe_path,
                    &runtime,
                    request_timeout,
                    &roots,
                    false,
                    started_at,
                    measurement_permit,
                ) {
                    Ok(Some(outcome)) => outcome,
                    Ok(None) => continue,
                    Err(error) => {
                        eprintln!(
                            "испытание QUIC-кандидата «{}» не завершено: {error}",
                            candidate.name
                        );
                        if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                            return Ok(None);
                        }
                        continue;
                    }
                };
                *stall_cut |=
                    outcome.applied && outcome.data.as_ref().is_some_and(r2o_quic_data_cut);
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
                if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                    println!("истёк срок QUIC-испытания; оставшиеся кандидаты пропущены");
                    return Ok(None);
                }
                let outcome = match Self::run_quic_discovery_candidate(
                    commands,
                    cancel,
                    server,
                    local,
                    &mut probe,
                    &candidate,
                    &server_name,
                    probe_path,
                    &runtime,
                    request_timeout,
                    &roots,
                    false,
                    started_at,
                    measurement_permit,
                ) {
                    Ok(Some(outcome)) => outcome,
                    Ok(None) => continue,
                    Err(error) => {
                        eprintln!(
                            "испытание QUIC-кандидата «{}» не завершено: {error}",
                            candidate.name
                        );
                        if r2o_quic_trial_remaining(started_at, measurement_permit).is_zero() {
                            return Ok(None);
                        }
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

    fn r2o_install_quic_deny(
        &mut self,
        host: &str,
        family: u8,
        server: std::net::SocketAddr,
        snapshot: &[u8],
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
        cache: &mut R2oQuicDenyCache,
    ) -> Result<Option<std::time::Duration>, Box<dyn Error>> {
        let Some(delay) = cache.r2o_next_delay(host, family) else {
            println!("по {host} (QUIC) запрет не установлен: кольцо из 16 записей занято");
            return Ok(None);
        };
        let (_lock, previous) = locked_catalog(catalog_path, catalog)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let mut updated = previous.clone();
        let mut marked = 0;
        for record in &mut updated.boxes {
            for binding in &mut record.bindings {
                let transport = if binding.transport == 0 {
                    6
                } else {
                    binding.transport
                };
                let binding_family = if binding.family == 0 {
                    4
                } else {
                    binding.family
                };
                if binding.enabled
                    && binding.kind == "name"
                    && binding.target == host
                    && transport == 17
                    && binding_family == family
                    && binding.recheck_since.is_none()
                {
                    binding.recheck_since = Some(now.max(1));
                    binding.recheck_mono = Some(std::time::Instant::now());
                    record.updated = now.max(1);
                    marked += 1;
                }
            }
        }
        let plan_id = random_id()?;
        let plan_id = plan_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let plan_text =
            format!("r2o-plan 1 11\nid {plan_id}\nproto udp quic\nquicdeny 1\norder forward\n");
        let records = compile_text(&plan_text)?;
        let plan = Plan::parse(&records)?;
        r2o_datapath::engine::validate_runtime_plan(&plan)
            .map_err(|error| format!("datapath отверг запрет QUIC: {error}"))?;
        let command = encode_set_name(host, SHAPE_QUIC, family, &records)?;
        self.send_command(&command, COMMAND_SET_NAME)?;
        if marked > 0
            && let Err(save_error) = updated.save_atomic(catalog_path, now)
        {
            let delete = encode_delete_name(host, 17, SHAPE_QUIC, family)?;
            return match self.send_command(&delete, control::COMMAND_DEL_NAME) {
                Ok(()) => Err(format!(
                    "каталог не сохранил отметку QUIC-перепроверки; временный запрет снят: {save_error}"
                )
                .into()),
                Err(delete_error) => {
                    let retry_delay = cache.r2o_record_cut(
                        host,
                        family,
                        server,
                        snapshot,
                        std::time::Instant::now(),
                    );
                    *catalog = updated;
                    Err(format!(
                        "каталог не сохранил отметку QUIC-перепроверки ({save_error}); не удалось снять временный запрет ({delete_error}); запрет оставлен в памяти для перепроверки через {} мин",
                        retry_delay.unwrap_or(delay).as_secs() / 60
                    )
                    .into())
                }
            };
        }
        let Some(actual_delay) =
            cache.r2o_record_cut(host, family, server, snapshot, std::time::Instant::now())
        else {
            let delete = encode_delete_name(host, 17, SHAPE_QUIC, family)?;
            self.send_command(&delete, control::COMMAND_DEL_NAME)?;
            return Err("кольцо временных запретов QUIC изменилось во время установки".into());
        };
        *catalog = updated;
        println!(
            "по {host} (QUIC) прямой HTTP/3-запрос подтвердил обрыв после рукопожатия; QUIC закрыт на {} мин, собственная перепроверка начнётся после срока{}",
            actual_delay.as_secs() / 60,
            if marked > 0 {
                "; подтверждённая привязка помечена на повторную проверку"
            } else {
                ""
            }
        );
        Ok(Some(delay))
    }

    fn r2o_remove_quic_deny(&mut self, host: &str, family: u8) -> Result<(), Box<dyn Error>> {
        let command = encode_delete_name(host, 17, SHAPE_QUIC, family)?;
        self.send_command(&command, control::COMMAND_DEL_NAME)
    }

    fn r2o_install_quic_candidate(
        &mut self,
        server: std::net::SocketAddr,
        host: &str,
        snapshot: &[u8],
        probe_path: &str,
        plan_text: &str,
        candidate_name: &str,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        let address_binding =
            host.parse::<std::net::IpAddr>().is_ok() || r2o_quic_snapshot_has_ech(snapshot);
        let (_lock, previous) = locked_catalog(catalog_path, catalog)?;
        if address_binding
            && r2o_controller::discovery::has_usable_quic_address_binding(&previous, server.ip())
        {
            *catalog = previous;
            println!("QUIC-план не заменён: другой процесс уже сохранил адресную привязку");
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let mut updated = previous.clone();
        let family = if server.is_ipv4() { 4 } else { 6 };
        let saved_probe_path = if probe_path == "/" { "" } else { probe_path };
        let saved_plan_id = if address_binding {
            r2o_controller::discovery::add_confirmed_quic_address_binding(
                &mut updated,
                server.ip(),
                plan_text,
                now,
            )
        } else {
            r2o_controller::discovery::add_confirmed_quic_name_binding(
                &mut updated,
                host,
                family,
                saved_probe_path,
                plan_text,
                now,
            )
        }
        .map_err(|error| format!("не удалось подготовить подтверждённую QUIC-привязку: {error}"))?;
        let saved_plan = updated
            .boxes
            .iter()
            .flat_map(|record| &record.plans)
            .find(|saved| saved.id == saved_plan_id && saved.enabled)
            .ok_or("сохранённый QUIC-план исчез из каталога")?;
        let saved_records = compile_text(&saved_plan.text)?;
        let (command, command_kind) = if address_binding {
            (
                encode_set_addr(server.ip(), SHAPE_QUIC, &saved_records)?,
                COMMAND_SET_ADDR,
            )
        } else {
            (
                encode_set_name(host, SHAPE_QUIC, family, &saved_records)?,
                COMMAND_SET_NAME,
            )
        };
        updated.save_atomic(catalog_path, now)?;
        if let Err(install_error) = self.send_command(&command, command_kind) {
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
            "HTTP/3 и точный APPLIED подтверждены кандидатом «{candidate_name}»; QUIC-план {saved_plan_id} сохранён для {}{}",
            if address_binding {
                server.ip().to_string()
            } else {
                host.to_owned()
            },
            if address_binding {
                " (адресная привязка)"
            } else {
                " (именная привязка)"
            },
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

    #[cfg(test)]
    fn apply_discovery_outcome(
        &mut self,
        outcome: DiscoveryOutcome,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        self.apply_discovery_outcome_with_input(outcome, catalog, catalog_path, 2)
            .map(|_| ())
    }

    fn apply_discovery_outcome_with_input(
        &mut self,
        outcome: DiscoveryOutcome,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
        input: u8,
    ) -> Result<Option<Vec<r2o_controller::live::LiveGroupKey>>, Box<dyn Error>> {
        if outcome.direct_clear {
            self.apply_discovery_direct_clear(&outcome.target, catalog, catalog_path)?;
            return Ok(None);
        }
        let Some(source_text) = outcome.plan_text else {
            println!(
                "автопоиск не дал применимого плана для {}: {}",
                outcome.target.host, outcome.detail
            );
            return Ok(None);
        };
        if r2o_discovery_existing_binding_blocks_outcome(
            catalog,
            &outcome.target,
            input,
            outcome.volume_recovery,
        ) {
            println!(
                "автопоиск пропущен: каталог уже покрывает {}",
                outcome.target.host
            );
            return Ok(None);
        }

        let (_lock, previous) = locked_catalog(catalog_path, catalog)?;
        if r2o_discovery_existing_binding_blocks_outcome(
            &previous,
            &outcome.target,
            input,
            outcome.volume_recovery,
        ) {
            *catalog = previous;
            println!(
                "автопоиск пропущен: другой контроллер уже сохранил план для {}",
                outcome.target.host
            );
            return Ok(None);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let mut updated = previous.clone();
        let plan_id = r2o_controller::discovery::add_measured_binding_with_fingerprint_in_box(
            &mut updated,
            &outcome.target,
            &source_text,
            now,
            input,
            outcome.volume_fingerprint.as_ref(),
            outcome.volume_box_id.as_deref(),
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
            return Ok(None);
        }
        let installed = match install_catalog(self, &compiled) {
            Ok(installed) => installed,
            Err(install_error) => {
                let file_rollback = previous.save_atomic(catalog_path, now);
                let runtime_rollback = catalog_commands(&previous)
                    .and_then(|previous_compiled| install_catalog(self, &previous_compiled));
                return Err(match (file_rollback, runtime_rollback) {
                    (Ok(()), Ok(_)) => format!(
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
        };
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
        Ok(Some(installed.installed_groups))
    }

    fn apply_discovery_direct_clear(
        &mut self,
        target: &r2o_controller::discovery::DiscoveryTarget,
        catalog: &mut Catalog,
        catalog_path: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        let (_lock, previous) = locked_catalog(catalog_path, catalog)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let mut updated = previous.clone();
        let result = r2o_controller::discovery::update_direct_clear_bindings(
            &mut updated,
            target,
            now,
            std::time::Instant::now(),
        );
        if result.marked == 0 && result.removed == 0 {
            *catalog = previous;
            if result.waiting != 0 {
                println!(
                    "{} напрямую проходит; привязка ждёт отдельной перепроверки",
                    target.host
                );
            } else {
                println!(
                    "{} напрямую проходит; точной TLS-привязки в каталоге нет",
                    target.host
                );
            }
            return Ok(());
        }

        updated.save_atomic(catalog_path, now)?;
        if result.delete_runtime {
            let command = encode_delete_name(&target.host, 6, target.shape, target.family)?;
            if let Err(delete_error) = self.send_command(&command, control::COMMAND_DEL_NAME) {
                *catalog = updated;
                return Err(format!(
                    "прямая проверка {} сохранила пометку перепроверки, но runtime не подтвердил снятие привязки; каталог не восстановлен, чтобы не установить эту привязку повторно: {delete_error}",
                    target.host
                )
                .into());
            }
        }
        *catalog = updated;

        if result.marked != 0 {
            println!(
                "{} напрямую проходит; точная привязка формы {} снята с runtime и сохранена для независимой перепроверки",
                target.host, target.shape
            );
        }
        if result.removed != 0 {
            println!(
                "{} повторно напрямую проходит; устаревшая точная привязка удалена из каталога",
                target.host
            );
        }
        if result.waiting != 0 {
            println!(
                "{} напрямую проходит; текущий замер слишком близок к предыдущей перепроверке",
                target.host
            );
        }
        Ok(())
    }

    fn send_command(&mut self, command: &[u8], expected: u16) -> Result<(), Box<dyn Error>> {
        let ack = self.exchange_command(command, expected)?;
        if ack.ok {
            return Ok(());
        }
        let reason = ack_reason_text(ack.reason);
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
        self.exchange_command_with_timeout(command, expected, CONTROL_ACK_TIMEOUT)
    }

    fn exchange_command_with_timeout(
        &mut self,
        command: &[u8],
        expected: u16,
        timeout: std::time::Duration,
    ) -> Result<r2k_core::control::Ack, Box<dyn Error>> {
        use std::io::Write;
        self.socket.write_all(command)?;
        let deadline = std::time::Instant::now() + timeout;
        let ack_frame = loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() || !wait_for_control_frame(&self.socket, remaining)? {
                let timeout_label = if timeout == CONTROL_ACK_TIMEOUT {
                    "3 секунды".to_owned()
                } else {
                    format!("{} мс", timeout.as_millis())
                };
                return Err(format!(
                    "датапат не подтвердил управляющую команду за {timeout_label}"
                )
                .into());
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
        self.record_http_binding_acknowledgement(command, expected, ack);
        Ok(ack)
    }

    fn queue_async_frame(&mut self, frame: Frame) -> Result<(), Box<dyn Error>> {
        if frame.kind == EVENT_PROTOCOL {
            self.r2o_update_send_cap(&frame)?;
        }
        if !matches!(
            frame.kind,
            EVENT_PROTOCOL
                | EVENT_HELLO
                | EVENT_APPLIED
                | EVENT_REFUSED
                | EVENT_CLIENT_SHAPE
                | EVENT_HTTP_PORTAL
                | EVENT_HTTP_RESPONSE
                | EVENT_R2O_QUIC_STALL
                | EVENT_R2O_QUIC_SUSPECT
                | EVENT_R2O_TCP_SILENT
                | EVENT_R2O_TCP_STALL
                | EVENT_R2O_TCP_FIN_RETRY
                | EVENT_R2O_TCP_RST_AFTER_APP
                | EVENT_R2O_TCP_CLEAN_HANDSHAKE
                | EVENT_R2O_TCP_EARLY_RST
                | EVENT_R2O_TCP_REPEAT
                | EVENT_R2O_TCP_RST_CUT
                | EVENT_R2O_TCP_EXCHANGE
                | EVENT_R2O_VOICE_SUSPECT
                | EVENT_R2O_VOICE_PROOF
                | EVENT_R2O_VOICE_RTP_PROOF
                | EVENT_R2O_VOICE_STUN_PROOF
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

    fn r2o_update_send_cap(&mut self, frame: &Frame) -> Result<(), Box<dyn Error>> {
        let greeting = decode_greeting(frame)
            .map_err(|error| format!("обновлённое приветствие датапата: {error}"))?;
        if greeting.version != PROTOCOL_VERSION || greeting.release_id != RELEASE_ID {
            return Err(format!(
                "несовместимое обновлённое приветствие датапата: wire={}, release={}, нужен wire={PROTOCOL_VERSION}, release={RELEASE_ID}",
                greeting.version, greeting.release_id
            )
            .into());
        }
        self.send_maxlen = greeting.send_maxlen;
        self.send_cap
            .store(greeting.send_maxlen as usize, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(unix)]
fn r2o_ask_applied_matches(
    event: &r2k_core::control::AppliedEvent,
    key: &[u8; r2k_core::control::KEY_LEN],
    plan_id: [u8; 16],
    trial_id: [u8; 16],
    family: u8,
    shape: u8,
) -> bool {
    event.key == *key
        && event.plan_id == plan_id
        && event.trial_id == trial_id
        && event.execution_id != 0
        && event.binding.is_known()
        && event.binding.kind == 1
        && event.binding.family == family
        && event.binding.shape == shape
        && event.binding.temporary
}

#[cfg(unix)]
fn r2o_ask_flow_key(
    client_ip: std::net::IpAddr,
    client_port: u16,
    server: std::net::SocketAddr,
) -> [u8; r2k_core::control::KEY_LEN] {
    let client = r2k_core::addr::Address::new(client_ip);
    let server_address = r2k_core::addr::Address::new(server.ip());
    let client_order = (client.family(), client.bytes(), client_port);
    let server_order = (
        server_address.family(),
        server_address.bytes(),
        server.port(),
    );
    let (low, high) = if client_order <= server_order {
        ((client, client_port), (server_address, server.port()))
    } else {
        ((server_address, server.port()), (client, client_port))
    };
    let mut key = [0; r2k_core::control::KEY_LEN];
    key[0] = low.0.family();
    key[1..17].copy_from_slice(&low.0.bytes());
    key[17..33].copy_from_slice(&high.0.bytes());
    key[33..35].copy_from_slice(&low.1.to_be_bytes());
    key[35..37].copy_from_slice(&high.1.to_be_bytes());
    key[37] = 6;
    key
}

#[cfg(all(test, unix))]
mod r2o_ask_proof_tests {
    use super::{ASK_WAIT, ControlClient, R2oAskProof, encode_frame, read_frame};
    use r2k_core::control::{
        AppliedEvent, BindingContext, KEY_LEN, R2oTcpExchangeEvent, RefusedEvent, SHAPE_LEGACY,
    };
    use r2k_core::control::{COMMAND_SET_NAME_PROBE, encode_ack};

    fn flow_key() -> [u8; KEY_LEN] {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 1]);
        key[17..21].copy_from_slice(&[198, 51, 100, 2]);
        key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 6;
        key
    }

    #[test]
    fn pass_waits_for_matching_applied_and_server_hello_events() {
        let key = flow_key();
        let plan_id = [7; 16];
        let trial_id = [8; 16];
        let mut proof = R2oAskProof::default();
        assert!(proof.observe_exchange(
            &R2oTcpExchangeEvent {
                key,
                first_record_type: 22,
                bytes_after_client_hello: 1_380,
                record_types: 0x04,
                server_hello: false,
                planned: false,
            },
            &key,
        ));
        assert!(!proof.passed());

        assert!(proof.observe_applied(
            &AppliedEvent {
                key,
                plan_id,
                trial_id,
                execution_id: 1,
                binding: BindingContext {
                    generation: 1,
                    kind: 1,
                    family: 4,
                    shape: SHAPE_LEGACY,
                    temporary: true,
                    epoch: [1; 16],
                },
            },
            &key,
            plan_id,
            trial_id,
            4,
            SHAPE_LEGACY,
        ));
        assert!(!proof.passed());

        assert!(proof.observe_exchange(
            &R2oTcpExchangeEvent {
                key,
                first_record_type: 22,
                bytes_after_client_hello: 1_500,
                record_types: 0x04,
                server_hello: true,
                planned: false,
            },
            &key,
        ));
        assert!(proof.passed());
    }

    #[test]
    fn matching_unsent_refusal_finishes_question_without_a_box_verdict() {
        let key = flow_key();
        let plan_id = [7; 16];
        let trial_id = [8; 16];
        let mut proof = R2oAskProof::default();
        let refusal = RefusedEvent {
            key,
            code: 4,
            plan_id,
            trial_id,
            client_shape: Some(SHAPE_LEGACY),
            execution_id: None,
            binding: None,
        };

        assert!(proof.observe_refused(&refusal, &key, plan_id, trial_id));
        assert_eq!(proof.unsent_code, Some(4));
        assert!(proof.finished());
        assert!(!proof.passed());
    }

    #[test]
    fn unrelated_refusal_does_not_finish_an_ask_question() {
        let key = flow_key();
        let mut proof = R2oAskProof::default();
        let refusal = RefusedEvent {
            key,
            code: 4,
            plan_id: [9; 16],
            trial_id: [8; 16],
            client_shape: Some(SHAPE_LEGACY),
            execution_id: None,
            binding: None,
        };

        assert!(!proof.observe_refused(&refusal, &key, [7; 16], [8; 16]));
        assert!(!proof.finished());
    }

    #[test]
    fn ask_accepts_a_plan_ack_that_arrives_after_the_generic_three_second_deadline() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        use std::time::Duration;

        let (socket, mut peer) = UnixStream::pair().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let command = read_frame(&mut peer).unwrap();
            std::thread::sleep(Duration::from_millis(3_200));
            peer.write_all(&encode_ack(command.kind, true, 0).unwrap())
                .unwrap();
        });
        let mut client = ControlClient {
            socket,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: Default::default(),
            pending_applied_events: Default::default(),
            http_search_started: Default::default(),
            http_challenge_cooldowns: Default::default(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let command = encode_frame(COMMAND_SET_NAME_PROBE, &[]).unwrap();

        let ack = client
            .exchange_command_with_timeout(&command, COMMAND_SET_NAME_PROBE, ASK_WAIT)
            .unwrap();

        assert!(ack.ok);
        peer_thread.join().unwrap();
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpBaselineFailureAction {
    Retry,
    Search,
    Inconclusive,
    Recheck,
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
fn http_baseline_failure_action(
    expected: r2o_controller::http_search::Answer,
    attempts: u8,
    error: &HttpBaselineError,
) -> HttpBaselineFailureAction {
    use r2o_controller::http_search::Answer;
    use std::io::ErrorKind;

    match error {
        HttpBaselineError::Connect(_) if attempts <= HTTP_SEARCH_BASE_RETRIES => {
            HttpBaselineFailureAction::Retry
        }
        HttpBaselineError::Connect(_) => HttpBaselineFailureAction::Inconclusive,
        HttpBaselineError::Response(error)
            if expected == Answer::Cut
                && matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
                && attempts <= HTTP_SEARCH_BASE_RETRIES =>
        {
            HttpBaselineFailureAction::Retry
        }
        HttpBaselineError::Response(error)
            if baseline_silence_starts_search(expected, error.kind()) =>
        {
            HttpBaselineFailureAction::Search
        }
        HttpBaselineError::Response(error)
            if expected == Answer::Cut
                && matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
        {
            HttpBaselineFailureAction::Search
        }
        _ => HttpBaselineFailureAction::Recheck,
    }
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
    let mut baseline_attempts = 0;
    let baseline = loop {
        baseline_attempts += 1;
        match run_http_baseline(
            &target.host,
            destination,
            target.family,
            mark,
            &request_path,
        ) {
            Ok(response) => break Some(response),
            Err(error) => {
                match http_baseline_failure_action(expected_baseline, baseline_attempts, &error) {
                    HttpBaselineFailureAction::Retry => {
                        println!(
                            "HTTP {}: базовый зонд не завершился ({error}); повторяю базу, попытка {} из {}",
                            target.host,
                            baseline_attempts + 1,
                            HTTP_SEARCH_BASE_RETRIES + 1
                        );
                    }
                    HttpBaselineFailureAction::Search => {
                        if expected_baseline == r2o_controller::http_search::Answer::Cut {
                            println!(
                                "HTTP {}: базовый запрос молчит после {} попыток при живом обрыве; начинаю поиск кандидатов",
                                target.host, baseline_attempts
                            );
                        } else {
                            println!(
                                "HTTP {}: клиент получил заглушку, а базовый запрос роутера молчит; начинаю поиск кандидатов",
                                target.host
                            );
                        }
                        break None;
                    }
                    HttpBaselineFailureAction::Inconclusive => {
                        println!(
                            "HTTP {}: базовый запрос не измерен — локальное соединение не установилось {} раза подряд; повтор не раньше чем через 5 мин",
                            target.host, baseline_attempts
                        );
                        return Ok(HttpSearchDisposition::Inconclusive);
                    }
                    HttpBaselineFailureAction::Recheck => {
                        println!("HTTP {}: базовый зонд не завершился: {error}", target.host);
                        return Ok(HttpSearchDisposition::Recheck);
                    }
                }
            }
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
        shape: SHAPE_HTTP,
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
        shape: SHAPE_HTTP,
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
    let (stream, client, _, rtt_us) = bound
        .connect(destination, std::time::Duration::from_secs(6))
        .map_err(|error| error.to_string())?;
    r2o_run_http_trial_stream(stream, client, rtt_us, host, request_path)
}

#[cfg(unix)]
fn r2o_run_http_trial_stream(
    mut stream: std::net::TcpStream,
    client: std::net::IpAddr,
    rtt_us: i64,
    host: &str,
    request_path: &[u8],
) -> Result<HttpTrialSocketResult, String> {
    use std::io::Write;

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

fn r2o_quic_binding_blocks_retry(binding_exists: bool, planned: bool) -> bool {
    binding_exists && !planned
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::locked_catalog;
    #[cfg(unix)]
    use super::saved_http_candidate_keys;
    use super::{
        CatalogInstallSummary, ClassifyCliOptions, CompiledCatalog, ControlClient,
        DiscoveryOutcome, HttpBaselineError, HttpBaselineFailureAction, HttpCandidateHistory,
        HttpCandidateProgress, HttpLiveFailures, HttpSearchCommand, HttpSearchDisposition,
        HttpSearchTask, HttpSearchWindow, HttpSearchWorker, R2oFamilyRecoveryDecision,
        R2oVoiceTrialContext, ServeCliOptions, advance_http_candidate, applied_quic_trial_matches,
        baseline_silence_starts_search, binding_shape_transport, candidate_text, catalog_commands,
        compile_text, encode_set_name, failed_http_programs, flow_socket_addresses,
        http_baseline_failure_action, http_search_candidates, http_search_key,
        install_catalog_best_effort, matching_domain_group, matching_domain_recovery_candidates,
        measured_http_candidate_keys, normalize_plan_target, parse_classify_options,
        parse_serve_options, print_flow_journal, r2o_discovery_failure_retry_due,
        r2o_family_applied_flow_matches, r2o_family_recovery_decision, r2o_http_failed_disposition,
        r2o_http_live_cut_recheck, r2o_quic_binding_blocks_retry, r2o_tcp_stall_budgets,
        r2o_tcp_stall_budgets_for_name, r2o_tcp_stall_in_name_band, r2o_voice_proof_matches_target,
        save_plan_file, shape_matches_plan,
    };
    use r2k_core::control::{
        BindingContext, COMMAND_DEL_NAME_PROBE, COMMAND_DEL_VOICE_ADDR_PROBE, COMMAND_SET_NAME,
        COMMAND_SET_NAME_PROBE, COMMAND_SET_TCP_STALL_BUDGETS, COMMAND_SET_VOICE_ADDR,
        EVENT_APPLIED, EVENT_R2O_TCP_SILENT, EVENT_R2O_TCP_STALL, Frame, HelloEvent,
        HttpResponseEvent, KEY_LEN, SHAPE_ECH_TCP, SHAPE_HTTP, SHAPE_MODERN, SHAPE_QUIC,
        SHAPE_VOICE, encode_ack, encode_ack_for_trial, encode_frame, encode_greeting, read_frame,
    };
    use r2k_core::plan::{PLAN_MAGIC, Plan};
    use r2o_controller::catalog::{Binding, BoxRecord, Catalog, Fingerprint, Signal};
    use r2o_controller::discovery::DiscoveryTarget;
    #[cfg(unix)]
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[cfg(unix)]
    #[test]
    fn http_live_owner_requires_the_latest_acknowledged_runtime_generation() {
        use super::encode_delete_name;
        use std::os::unix::net::UnixStream;

        let (socket, _peer) = UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: Default::default(),
            pending_applied_events: Default::default(),
            http_search_started: Default::default(),
            http_challenge_cooldowns: Default::default(),
            http_acknowledged_bindings: Default::default(),
        };
        let plan_id = [0x41; 16];
        let plan_text = candidate_text("split", Some(&plan_id)).unwrap();
        let plan_records = compile_text(&plan_text).unwrap();
        let set = encode_set_name("example.com", SHAPE_HTTP, 4, &plan_records).unwrap();
        let first_binding = BindingContext {
            generation: 7,
            kind: 1,
            family: 4,
            shape: SHAPE_HTTP,
            temporary: false,
            epoch: [3; 16],
        };
        client.record_http_binding_acknowledgement(
            &set,
            COMMAND_SET_NAME,
            r2k_core::control::Ack {
                command: COMMAND_SET_NAME,
                ok: true,
                reason: r2k_core::control::ACK_OK,
                trial_id: None,
                binding_context: Some(first_binding),
            },
        );

        let mut response = r2o_http_response(1, b"/");
        response.execution_id = 9;
        response.plan_id = plan_id;
        response.request_ms = 10;
        response.binding = first_binding;
        assert_eq!(
            client.acknowledged_http_binding_for(&response),
            Some(first_binding)
        );

        let second_binding = BindingContext {
            generation: 8,
            ..first_binding
        };
        client.record_http_binding_acknowledgement(
            &set,
            COMMAND_SET_NAME,
            r2k_core::control::Ack {
                command: COMMAND_SET_NAME,
                ok: true,
                reason: r2k_core::control::ACK_OK,
                trial_id: None,
                binding_context: Some(second_binding),
            },
        );
        assert_eq!(client.acknowledged_http_binding_for(&response), None);
        response.binding = second_binding;
        assert_eq!(
            client.acknowledged_http_binding_for(&response),
            Some(second_binding)
        );

        let delete = encode_delete_name("example.com", 6, SHAPE_HTTP, 4).unwrap();
        client.record_http_binding_acknowledgement(
            &delete,
            r2k_core::control::COMMAND_DEL_NAME,
            r2k_core::control::Ack {
                command: r2k_core::control::COMMAND_DEL_NAME,
                ok: true,
                reason: r2k_core::control::ACK_OK,
                trial_id: None,
                binding_context: None,
            },
        );
        assert_eq!(client.acknowledged_http_binding_for(&response), None);
    }

    #[cfg(unix)]
    #[test]
    fn sync_catalog_counts_refusals_and_keeps_installing_remaining_plans() {
        use std::io::Write;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_path = std::env::temp_dir().join(format!("r2o-catalog-refusal-{nonce}.sock"));
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.write_all(&encode_greeting(u16::MAX as u32).unwrap())
                .unwrap();
            let clear = read_frame(&mut peer).unwrap();
            assert_eq!(clear.kind, super::COMMAND_CLEAR);
            peer.write_all(&encode_ack(clear.kind, true, 0).unwrap())
                .unwrap();

            for (ok, reason) in [
                (false, r2k_core::control::ACK_BAD_PLAN),
                (true, r2k_core::control::ACK_OK),
                (false, r2k_core::control::ACK_NO_ROOM),
            ] {
                let command = read_frame(&mut peer).unwrap();
                assert_eq!(command.kind, r2k_core::control::COMMAND_SET_SUFFIX);
                peer.write_all(&encode_ack(command.kind, ok, reason).unwrap())
                    .unwrap();
            }
        });

        let plan = super::compile_text(
            "r2o-plan 1 11\nid 00000000000000000000000000000000\nproto tcp tls\nsplit sni_middle +0\n",
        )
        .unwrap();
        let command =
            |suffix: &str| super::encode_set_suffix(suffix, SHAPE_MODERN, 4, &plan).unwrap();
        let group = r2o_controller::live::LiveGroupKey {
            suffix: "installed.example".into(),
            plan_id: "plan-1".into(),
            transport: 6,
            family: 4,
            shape: SHAPE_MODERN,
            probe_path: "/".into(),
            ech_origin: String::new(),
        };
        let compiled = CompiledCatalog {
            commands: vec![
                ("bad-plan.example".into(), command("bad-plan.example")),
                ("installed.example".into(), command("installed.example")),
                ("full-table.example".into(), command("full-table.example")),
            ],
            group_commands: vec![(1, group.clone())],
            skipped: 0,
            tcp_stall_budgets: Vec::new(),
        };
        let mut client = ControlClient::connect(socket_path.clone()).unwrap();
        let summary = install_catalog_best_effort(&mut client, &compiled).unwrap();

        server.join().unwrap();
        std::fs::remove_file(socket_path).unwrap();
        assert_eq!(
            summary,
            CatalogInstallSummary {
                installed: 1,
                refused: 2,
                last_refusal: Some("таблица планов заполнена"),
                installed_groups: vec![group],
            }
        );
    }
    use r2o_controller::fetch::FetchResult;
    use std::{collections::VecDeque, ffi::OsString, io::Write, path::PathBuf};

    #[test]
    fn подтверждённый_quic_план_разрешает_повторную_проверку_адреса() {
        assert!(r2o_quic_binding_blocks_retry(true, false));
        assert!(!r2o_quic_binding_blocks_retry(true, true));
        assert!(!r2o_quic_binding_blocks_retry(false, false));
    }

    fn r2o_test_quic_initial_snapshot() -> Vec<u8> {
        r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[&include_bytes!(
            "../../r2k-core/tests/fixtures/quic_v1_initial.bin"
        )[..]])
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn запрет_quic_требует_рукопожатия_и_обрыва_данных() {
        let cut = r2o_controller::r2o_quic_http3::R2oQuicHttp3Result {
            handshake_confirmed: true,
            status: 200,
            r2o_quic_stalled: true,
            ..Default::default()
        };
        assert!(super::r2o_quic_data_cut(&cut));
        assert!(!super::r2o_quic_data_cut(
            &r2o_controller::r2o_quic_http3::R2oQuicHttp3Result {
                r2o_quic_stalled: true,
                ..Default::default()
            }
        ));
        assert!(!super::r2o_quic_data_cut(
            &r2o_controller::r2o_quic_http3::R2oQuicHttp3Result {
                handshake_confirmed: true,
                status: 200,
                complete: true,
                ..Default::default()
            }
        ));
    }

    fn r2o_test_tls_ech_client_hello() -> Vec<u8> {
        let mut handshake = include_bytes!("../tests/fixtures/r2o_tls13_client_hello.bin").to_vec();
        let mut offset = 4 + 2 + 32;
        offset += 1 + usize::from(handshake[offset]);
        let cipher_suites = usize::from(u16::from_be_bytes([
            handshake[offset],
            handshake[offset + 1],
        ]));
        offset += 2 + cipher_suites;
        offset += 1 + usize::from(handshake[offset]);
        let extensions_length_offset = offset;
        let extensions_length = usize::from(u16::from_be_bytes([
            handshake[offset],
            handshake[offset + 1],
        ]));
        let insert_at = offset + 2 + extensions_length;
        let ech_extension = [0xfe, 0x0d, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xaa, 0xbb];
        handshake.splice(insert_at..insert_at, ech_extension);
        handshake[extensions_length_offset..extensions_length_offset + 2]
            .copy_from_slice(&((extensions_length + ech_extension.len()) as u16).to_be_bytes());
        let handshake_length = (handshake.len() - 4) as u32;
        handshake[1] = (handshake_length >> 16) as u8;
        handshake[2] = (handshake_length >> 8) as u8;
        handshake[3] = handshake_length as u8;

        let mut record = vec![
            0x16,
            0x03,
            0x01,
            (handshake.len() >> 8) as u8,
            handshake.len() as u8,
        ];
        record.extend_from_slice(&handshake);
        assert!(r2k_core::tls::parse(&record).ech_offer);
        assert!(super::Trigger::tls_client_hello("example.com", &record).is_ok());
        record
    }

    fn r2o_test_quic_ech_snapshot() -> Vec<u8> {
        let profile =
            r2o_controller::quic_replay::r2o_quic_profile_snapshot(Some("media.example.net"))
                .unwrap();
        let parsed = r2k_core::quic_snapshot::r2k_quic_snapshot_parse(&profile).unwrap();
        let mut client_hello =
            r2k_core::quic::r2k_quic_initial_client_hello_from_datagrams(parsed.datagrams())
                .unwrap();
        let mut offset = 4 + 2 + 32;
        offset += 1 + usize::from(client_hello[offset]);
        let cipher_suites = usize::from(u16::from_be_bytes([
            client_hello[offset],
            client_hello[offset + 1],
        ]));
        offset += 2 + cipher_suites;
        offset += 1 + usize::from(client_hello[offset]);
        let extensions_length_offset = offset;
        let extensions_length = usize::from(u16::from_be_bytes([
            client_hello[offset],
            client_hello[offset + 1],
        ]));
        let insert_at = offset + 2 + extensions_length;
        let ech_extension = [0xfe, 0x0d, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xaa, 0xbb];
        client_hello.splice(insert_at..insert_at, ech_extension);
        client_hello[extensions_length_offset..extensions_length_offset + 2]
            .copy_from_slice(&((extensions_length + ech_extension.len()) as u16).to_be_bytes());
        let handshake_length = (client_hello.len() - 4) as u32;
        client_hello[1] = (handshake_length >> 16) as u8;
        client_hello[2] = (handshake_length >> 8) as u8;
        client_hello[3] = handshake_length as u8;

        let initial = r2k_core::quic::r2k_quic_initial_build(&client_hello, &[7; 8], 1200).unwrap();
        r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[&initial]).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn r2o_quic_snapshot_recognizes_ech_in_raw_client_hello() {
        let snapshot = r2o_test_quic_ech_snapshot();
        assert!(super::r2o_quic_snapshot_has_ech(&snapshot));
    }

    fn r2o_test_discovery_worker_without_threads() -> super::DiscoveryWorker {
        let (_sender, outcomes) = std::sync::mpsc::sync_channel(8);
        super::DiscoveryWorker {
            jobs: std::sync::Arc::new((
                std::sync::Mutex::new(super::R2oDiscoveryQueue::default()),
                std::sync::Condvar::new(),
            )),
            client_hellos: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            recent_client_shapes: super::R2oRecentClientShapeCache::default(),
            resource_memory: std::sync::Arc::new(std::sync::Mutex::new(
                r2o_controller::r2o_resource::R2oResourceMemory::default(),
            )),
            active_cancels: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            catalog_refreshes: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
            outcomes,
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            seen: std::collections::HashSet::new(),
            seen_order: std::collections::VecDeque::new(),
            failed_at: std::collections::HashMap::new(),
            failed_retry_after: std::collections::HashMap::new(),
            challenge_cooldowns: std::collections::HashMap::new(),
            ech_input_clearable_failures: std::collections::HashSet::new(),
            ech_input_names: std::collections::VecDeque::new(),
            clear_streaks: std::collections::HashMap::new(),
            client_snapshot_targets: std::collections::HashSet::new(),
            pending_rechecks: std::collections::HashMap::new(),
            active: std::collections::HashMap::new(),
            completed: std::collections::HashSet::new(),
            threads: Vec::new(),
        }
    }

    fn r2o_test_record_failed_discovery(
        worker: &mut super::DiscoveryWorker,
        target: DiscoveryTarget,
        retry_after: std::time::Duration,
        direct_clear: bool,
    ) {
        worker.seen.insert(target.clone());
        worker.seen_order.push_back(target.clone());
        worker.r2o_complete_outcome(DiscoveryOutcome {
            target,
            plan_text: None,
            detail: "измерение завершено без классификации".into(),
            queue_expired: false,
            direct_clear,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: Some(retry_after),
        });
    }

    #[cfg(unix)]
    #[test]
    fn новый_ech_clienthello_снимает_один_старый_профильный_отказ() {
        let mut worker = r2o_test_discovery_worker_without_threads();
        let profile = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.10:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let failure_key = super::r2o_discovery_failure_key(&profile);
        r2o_test_record_failed_discovery(
            &mut worker,
            profile,
            super::R2O_DISCOVERY_INCOMPLETE_RETRY,
            false,
        );

        let mut ech_target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.10:443".into(),
            family: 4,
            shape: SHAPE_ECH_TCP,
        };
        let hello = r2o_test_tls_ech_client_hello();
        assert!(worker.queue_client_snapshot(ech_target.clone(), hello.clone()));
        assert!(!worker.failed_at.contains_key(&failure_key));

        worker.jobs.0.lock().unwrap().entries.clear();
        worker
            .active
            .remove(&super::r2o_discovery_task_key(&ech_target));
        worker.seen.remove(&ech_target);
        worker.seen_order.retain(|seen| seen != &ech_target);
        ech_target.shape = SHAPE_MODERN;
        r2o_test_record_failed_discovery(
            &mut worker,
            ech_target,
            super::R2O_DISCOVERY_INCOMPLETE_RETRY,
            false,
        );

        let ech_target = DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.10:443".into(),
            family: 4,
            shape: SHAPE_ECH_TCP,
        };
        assert!(!worker.queue_client_snapshot(ech_target, hello));
        assert!(worker.failed_at.contains_key(&failure_key));
    }

    #[cfg(unix)]
    #[test]
    fn новый_ech_clienthello_сохраняет_паузы_challenge_ech_и_clear() {
        let hello = r2o_test_tls_ech_client_hello();
        let cases = [
            (
                SHAPE_MODERN,
                std::time::Duration::from_secs(120),
                false,
                "антибот-проверка",
            ),
            (
                SHAPE_ECH_TCP,
                super::R2O_DISCOVERY_INCOMPLETE_RETRY,
                false,
                "ECH",
            ),
            (
                SHAPE_MODERN,
                super::R2O_DISCOVERY_CLEAR_RETRY_FIRST,
                true,
                "прямой CLEAR",
            ),
        ];
        for (shape, retry_after, direct_clear, reason) in cases {
            let mut worker = r2o_test_discovery_worker_without_threads();
            let failed = DiscoveryTarget {
                host: "example.com".into(),
                endpoint: "198.51.100.10:443".into(),
                family: 4,
                shape,
            };
            let failure_key = super::r2o_discovery_failure_key(&failed);
            r2o_test_record_failed_discovery(&mut worker, failed, retry_after, direct_clear);

            let ech_target = DiscoveryTarget {
                host: "example.com".into(),
                endpoint: "198.51.100.10:443".into(),
                family: 4,
                shape: SHAPE_ECH_TCP,
            };
            assert!(
                !worker.queue_client_snapshot(ech_target, hello.clone()),
                "ECH-вход не должен снимать паузу {reason}"
            );
            assert!(worker.failed_at.contains_key(&failure_key));
        }
    }

    #[test]
    fn кэш_чистого_tcp_рукопожатия_сверяет_имя_семейство_срок_и_ёмкость() {
        let now = std::time::Instant::now();
        let mut cache = super::R2oCleanHandshakeCache::default();
        cache.note("clean.example", 4, now);

        assert!(cache.r2o_recent("clean.example", 4, now));
        assert!(cache.suppresses_unplanned_tcp_suspicion("clean.example", 4, false, now));
        assert!(!cache.suppresses_unplanned_tcp_suspicion("clean.example", 4, true, now));
        assert!(!cache.r2o_recent("other.example", 4, now));
        assert!(!cache.r2o_recent("clean.example", 6, now));
        assert!(!cache.suppresses_unplanned_tcp_suspicion("clean.example", 6, false, now));
        assert!(cache.r2o_recent("clean.example", 4, now + std::time::Duration::from_secs(60),));
        assert!(!cache.r2o_recent("clean.example", 4, now + std::time::Duration::from_secs(61),));

        for index in 0..16 {
            cache.note(&format!("other-{index}.example"), 4, now);
        }
        assert!(!cache.r2o_recent("clean.example", 4, now));
    }

    #[test]
    fn кэш_tcp_приветствий_связывает_имя_цель_и_подозрение_с_точным_потоком() {
        let now = std::time::Instant::now();
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 80]);
        key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 6;
        let hello = HelloEvent {
            key,
            host: Some(b"CLEAN.Example.COM.".to_vec()),
            shape: Some(SHAPE_MODERN),
            r2o_wire_len: Some(812),
            quic_snapshot: None,
        };
        let mut cache = super::R2oTcpHelloCache::default();
        cache.note(hello, now);

        assert_eq!(
            cache.clean_handshake_name(&key, now).as_deref(),
            Some("clean.example.com")
        );
        let target = cache.target_for_tcp_flow(&key, now).unwrap();
        assert_eq!(target.host, "clean.example.com");
        assert_eq!(target.family, 4);

        let mut foreign = key;
        foreign[4] = 11;
        assert!(cache.clean_handshake_name(&foreign, now).is_none());
        assert!(cache.target_for_tcp_flow(&foreign, now).is_none());
        assert!(
            cache
                .clean_handshake_name(&key, now + std::time::Duration::from_secs(61))
                .is_none()
        );
        assert!(
            cache
                .target_for_tcp_flow(&key, now + std::time::Duration::from_secs(61))
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn кэш_недавних_tcp_имён_даёт_свидетелей_с_адресом_и_сроком_жизни() {
        let now = std::time::Instant::now();
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "cloudflare-ech.com".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_ECH_TCP,
        };
        let hello = |name: &[u8], server: [u8; 4], port: u16| {
            let mut key = [0; KEY_LEN];
            key[0] = 4;
            key[1..5].copy_from_slice(&[192, 0, 2, 10]);
            key[17..21].copy_from_slice(&server);
            key[33..35].copy_from_slice(&port.to_be_bytes());
            key[35..37].copy_from_slice(&443_u16.to_be_bytes());
            key[37] = 6;
            HelloEvent {
                key,
                host: Some(name.to_vec()),
                shape: Some(SHAPE_MODERN),
                r2o_wire_len: None,
                quic_snapshot: None,
            }
        };
        let mut cache = super::R2oRecentTcpNameCache::default();
        cache.note(&hello(b"SAME.Example.", [198, 51, 100, 80], 41_001), now);
        cache.note(
            &hello(b"stale.example", [203, 0, 113, 5], 41_002),
            now - std::time::Duration::from_secs(601),
        );
        cache.note(&hello(b"cross.example", [203, 0, 113, 5], 41_003), now);

        assert_eq!(
            cache.ech_witness_names(&target, now),
            [
                ("same.example".into(), true),
                ("cross.example".into(), false),
            ]
        );
        assert_eq!(
            cache.ech_witness_names(&target, now + std::time::Duration::from_secs(601)),
            []
        );
    }

    #[cfg(unix)]
    #[test]
    fn ech_rr_сохраняет_положительный_и_отрицательный_ответ_до_срока() {
        let now = std::time::Instant::now();
        let mut cache = super::R2oEchWitnessResolutionCache::default();
        let config = r2o_controller::ech::R2oEchConfig {
            public_name: "public.example".into(),
            origin_name: "witness.example".into(),
            config_list: vec![1, 2, 3],
        };

        cache.store("positive.example", Some(config.clone()), now);
        cache.store("negative.example", None, now);

        assert_eq!(
            cache.lookup(
                "positive.example",
                now + std::time::Duration::from_secs(6 * 60 * 60)
            ),
            Some(Some(config))
        );
        assert!(
            cache
                .lookup(
                    "positive.example",
                    now + std::time::Duration::from_secs(6 * 60 * 60)
                        + std::time::Duration::from_nanos(1)
                )
                .is_none()
        );
        assert_eq!(
            cache.lookup(
                "negative.example",
                now + std::time::Duration::from_secs(11 * 60)
            ),
            Some(None)
        );
        assert!(
            cache
                .lookup(
                    "negative.example",
                    now + std::time::Duration::from_secs(30 * 60)
                        + std::time::Duration::from_nanos(1)
                )
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn ech_rr_свежие_положительные_свидетели_получают_приоритет() {
        let now = std::time::Instant::now();
        let mut cache = super::R2oEchWitnessResolutionCache::default();
        let config = |public_name: &str| r2o_controller::ech::R2oEchConfig {
            public_name: public_name.into(),
            origin_name: "witness.example".into(),
            config_list: vec![1],
        };
        cache.store("known-one.example", Some(config("public.example")), now);
        cache.store("known-two.example", Some(config("public.example")), now);
        cache.store("wrong.example", Some(config("other.example")), now);
        cache.store("negative.example", None, now);
        cache.store(
            "expired.example",
            Some(config("public.example")),
            now - super::R2O_DISCOVERY_ECH_RR_POSITIVE_TTL - std::time::Duration::from_nanos(1),
        );

        let cached = cache.cached_witness_names("public.example", now);
        let mut discovered = vec!["known-one.example".into(), "public.example".into()];
        discovered.extend((0..40).map(|index| format!("catalog-{index}.example")));
        let candidates =
            super::r2o_merge_ech_witness_candidates("public.example", &cached, &discovered);

        assert_eq!(
            &candidates[..3],
            [
                "known-one.example",
                "known-two.example",
                "catalog-0.example"
            ]
        );
        assert_eq!(
            candidates.len(),
            r2o_controller::discovery::R2O_ECH_WITNESS_LIMIT
        );
        assert!(!candidates.iter().any(|name| {
            matches!(
                name.as_str(),
                "public.example" | "wrong.example" | "negative.example" | "expired.example"
            )
        }));
    }

    #[cfg(unix)]
    #[test]
    fn ech_rr_переиспользует_разрешение_и_сверяет_public_name() {
        let cache = std::sync::Mutex::new(super::R2oEchWitnessResolutionCache::default());
        let calls = std::cell::Cell::new(0);
        let config = r2o_controller::ech::R2oEchConfig {
            public_name: "public.example".into(),
            origin_name: "witness.example".into(),
            config_list: vec![1, 2, 3],
        };
        let mut resolve = || {
            calls.set(calls.get() + 1);
            Ok(config.clone())
        };

        assert_eq!(
            super::r2o_discovery_resolve_ech_witness_cached(
                &cache,
                "witness.example",
                "public.example",
                &mut resolve,
            ),
            Ok(Some(config.clone()))
        );
        assert_eq!(
            super::r2o_discovery_resolve_ech_witness_cached(
                &cache,
                "witness.example",
                "other-public.example",
                || panic!("свежую HTTPS RR-запись не запрашиваем повторно"),
            ),
            Ok(None)
        );
        assert_eq!(
            super::r2o_discovery_resolve_ech_witness_cached(
                &cache,
                "witness.example",
                "public.example",
                || panic!("положительный HTTPS RR уже кэширован"),
            ),
            Ok(Some(config))
        );
        assert_eq!(calls.get(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn ech_rr_отрицательное_разрешение_не_повторяет_dns_запрос() {
        let cache = std::sync::Mutex::new(super::R2oEchWitnessResolutionCache::default());
        let calls = std::cell::Cell::new(0);
        let mut resolve = || {
            calls.set(calls.get() + 1);
            Err("HTTPS RR не содержит подходящей ECH-конфигурации".to_owned())
        };

        assert_eq!(
            super::r2o_discovery_resolve_ech_witness_cached(
                &cache,
                "negative.example",
                "public.example",
                &mut resolve,
            ),
            Err("HTTPS RR не содержит подходящей ECH-конфигурации".into())
        );
        assert_eq!(
            super::r2o_discovery_resolve_ech_witness_cached(
                &cache,
                "negative.example",
                "public.example",
                || panic!("отрицательный HTTPS RR уже кэширован"),
            ),
            Ok(None)
        );
        assert_eq!(calls.get(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn ech_rr_кэш_ограничен_256_именами_и_обновление_не_двигает_кольцо() {
        let now = std::time::Instant::now();
        let mut cache = super::R2oEchWitnessResolutionCache::default();
        let config = || r2o_controller::ech::R2oEchConfig {
            public_name: "public.example".into(),
            origin_name: "witness.example".into(),
            config_list: vec![1],
        };

        for index in 0..256 {
            cache.store(&format!("witness-{index}.example"), Some(config()), now);
        }
        cache.store("witness-256.example", Some(config()), now);
        cache.store("witness-256.example", None, now);
        cache.store("witness-new.example", Some(config()), now);

        assert!(cache.lookup("witness-0.example", now).is_none());
        assert!(cache.lookup("witness-1.example", now).is_none());
        assert_eq!(cache.lookup("witness-256.example", now), Some(None));
        assert!(cache.lookup("witness-new.example", now).is_some());
    }

    #[cfg(unix)]
    fn r2o_http_response(code: u8, path: &[u8]) -> HttpResponseEvent {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 80]);
        key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&80_u16.to_be_bytes());
        key[37] = 6;
        HttpResponseEvent {
            key,
            code,
            host: b"Example.com".to_vec(),
            execution_id: 0,
            plan_id: [0; 16],
            trial_id: [0; 16],
            request_ms: 0,
            path: path.to_vec(),
            binding: BindingContext {
                generation: 0,
                kind: 0,
                family: 0,
                shape: 0,
                temporary: false,
                epoch: [0; 16],
            },
            status: 200,
            body_bytes: 1024,
            request_no: 1,
        }
    }

    #[cfg(unix)]
    #[test]
    fn r2o_http_search_сохраняет_путь_повторяемого_запроса() {
        let portal = r2o_http_response(3, b"/account/view");
        let (target, path, expected) = super::r2o_http_search_from_response(&portal).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(path, b"/account/view");
        assert!(matches!(
            expected,
            r2o_controller::http_search::Answer::Injected
        ));

        let cut = r2o_http_response(4, b"/watch/42");
        let (_, path, expected) = super::r2o_http_search_from_response(&cut).unwrap();
        assert_eq!(path, b"/watch/42");
        assert!(matches!(expected, r2o_controller::http_search::Answer::Cut));
        assert!(
            super::r2o_http_search_from_response(&r2o_http_response(3, b"//host/admin")).is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn семейный_план_требует_https_и_applied_точного_потока_включая_trial_и_temporary() {
        let target = DiscoveryTarget {
            host: "media.example.com".into(),
            endpoint: "198.51.100.20:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let plan_id = [0x55; 16];
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 20]);
        key[33..35].copy_from_slice(&41_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 6;
        let event = r2k_core::control::AppliedEvent {
            key,
            plan_id,
            trial_id: [0; 16],
            execution_id: 7,
            binding: r2k_core::control::BindingContext {
                generation: 1,
                kind: 1,
                family: 4,
                shape: SHAPE_MODERN,
                temporary: false,
                epoch: [1; 16],
            },
        };
        assert!(r2o_family_applied_flow_matches(
            &event, &target, 41_000, plan_id, [0; 16], false
        ));
        assert!(!r2o_family_applied_flow_matches(
            &event, &target, 41_001, plan_id, [0; 16], false
        ));
        assert!(!r2o_family_applied_flow_matches(
            &event, &target, 41_000, [0x56; 16], [0; 16], false
        ));

        let trial_id = [0x44; 16];
        let mut temporary = event.clone();
        temporary.trial_id = trial_id;
        temporary.binding.temporary = true;
        assert!(r2o_family_applied_flow_matches(
            &temporary, &target, 41_000, plan_id, trial_id, true
        ));
        assert!(!r2o_family_applied_flow_matches(
            &temporary, &target, 41_000, plan_id, [0x45; 16], true
        ));
        assert!(!r2o_family_applied_flow_matches(
            &temporary, &target, 41_000, plan_id, trial_id, false
        ));

        let fetch = FetchResult {
            address: "198.51.100.20:443".parse().unwrap(),
            local_port: 41_000,
            tls: Some("1.3"),
            status: 200,
            http_outcome: r2o_controller::fetch::R2oFetchHttpOutcome::Positive,
            cloudflare_challenge: false,
            body_bytes: 64,
            body_expected: Some(64),
            body_has_length: true,
            location: String::new(),
            chunked: false,
            gzip: false,
            complete: true,
            application_verified: true,
            elapsed: std::time::Duration::from_millis(30),
            reason: None,
            r2o_volume_observation: Default::default(),
            r2o_resources: Vec::new(),
        };
        assert_eq!(
            r2o_family_recovery_decision(&Ok(fetch.clone()), false),
            R2oFamilyRecoveryDecision::Reclassify
        );
        assert_eq!(
            r2o_family_recovery_decision(&Ok(fetch.clone()), true),
            R2oFamilyRecoveryDecision::Verified
        );
        let mut unresolved_redirect = fetch.clone();
        unresolved_redirect.status = 302;
        unresolved_redirect.location = "/landing".into();
        unresolved_redirect.application_verified = false;
        assert_eq!(
            r2o_family_recovery_decision(&Ok(unresolved_redirect), true),
            R2oFamilyRecoveryDecision::Reclassify
        );
        let mut blocked_page = fetch.clone();
        blocked_page.status = 403;
        blocked_page.http_outcome = r2o_controller::fetch::R2oFetchHttpOutcome::Blocked;
        blocked_page.application_verified = false;
        assert_eq!(
            r2o_family_recovery_decision(&Ok(blocked_page), true),
            R2oFamilyRecoveryDecision::Reclassify
        );
        let mut legal_denial = fetch.clone();
        legal_denial.status = 451;
        legal_denial.http_outcome = r2o_controller::fetch::R2oFetchHttpOutcome::LegalDenial;
        legal_denial.application_verified = false;
        assert_eq!(
            r2o_family_recovery_decision(&Ok(legal_denial), true),
            R2oFamilyRecoveryDecision::Reclassify
        );
        let mut incomplete = fetch;
        incomplete.complete = false;
        assert_eq!(
            r2o_family_recovery_decision(&Ok(incomplete), true),
            R2oFamilyRecoveryDecision::Reclassify
        );
        assert_eq!(
            r2o_family_recovery_decision(&Ok(r2o_test_fetch_result()), false),
            R2oFamilyRecoveryDecision::Reclassify
        );
    }

    #[cfg(unix)]
    #[test]
    fn measured_candidate_retry_needs_exact_application_and_has_two_retries() {
        assert_eq!(super::r2o_discovery_candidate_retry_count(0), None);
        assert_eq!(super::r2o_discovery_candidate_retry_count(1), Some(0));
        assert_eq!(super::r2o_discovery_candidate_retry_count(2), Some(1));
        assert_eq!(super::r2o_discovery_candidate_retry_count(3), Some(2));
        assert_eq!(super::r2o_discovery_candidate_retry_count(100), Some(2));

        let mut incomplete = r2o_test_fetch_result();
        incomplete.complete = false;
        incomplete.application_verified = false;
        assert!(super::r2o_discovery_candidate_retryable(
            &Ok(incomplete.clone()),
            true,
            true
        ));
        assert!(!super::r2o_discovery_candidate_retryable(
            &Ok(incomplete.clone()),
            false,
            true
        ));
        assert!(super::r2o_discovery_candidate_retryable(
            &Err("network timeout".into()),
            true,
            true
        ));
        assert!(!super::r2o_discovery_candidate_retryable(
            &Err("connect failed".into()),
            true,
            false
        ));
        let mut no_tls = incomplete.clone();
        no_tls.tls = None;
        assert!(super::r2o_discovery_candidate_retryable(
            &Ok(no_tls.clone()),
            true,
            true
        ));
        assert!(!super::r2o_discovery_candidate_retryable(
            &Ok(no_tls.clone()),
            true,
            false
        ));

        incomplete.r2o_volume_observation.local_limit = true;
        assert!(!super::r2o_discovery_candidate_retryable(
            &Ok(incomplete.clone()),
            true,
            true
        ));
        incomplete.r2o_volume_observation.local_limit = false;
        incomplete.cloudflare_challenge = true;
        assert!(!super::r2o_discovery_candidate_retryable(
            &Ok(incomplete),
            true,
            true
        ));
        let mut blocked = r2o_test_fetch_result();
        blocked.http_outcome = r2o_controller::fetch::R2oFetchHttpOutcome::Blocked;
        assert!(!super::r2o_discovery_candidate_retryable(
            &Ok(blocked),
            true,
            true
        ));
        let mut legal_denial = r2o_test_fetch_result();
        legal_denial.http_outcome = r2o_controller::fetch::R2oFetchHttpOutcome::LegalDenial;
        assert!(!super::r2o_discovery_candidate_retryable(
            &Ok(legal_denial),
            true,
            true
        ));

        let mut attempts = 0;
        let verified = super::r2o_repeat_candidate_trials(
            2,
            || {
                attempts += 1;
                let mut fetch = r2o_test_fetch_result();
                if attempts < 3 {
                    fetch.complete = false;
                    fetch.application_verified = false;
                }
                (Ok(fetch), true, true)
            },
            |(result, applied, transport_established)| {
                super::r2o_family_recovery_decision(result, *applied)
                    != R2oFamilyRecoveryDecision::Verified
                    && super::r2o_discovery_candidate_retryable(
                        result,
                        *applied,
                        *transport_established,
                    )
            },
        );
        assert_eq!(
            super::r2o_family_recovery_decision(&verified.0, verified.1),
            R2oFamilyRecoveryDecision::Verified
        );
        assert_eq!(attempts, 3);

        let mut unbound_attempts = 0;
        let not_retried = super::r2o_repeat_candidate_trials(
            2,
            || {
                unbound_attempts += 1;
                (Err("connect failed".into()), true, false)
            },
            |(result, applied, transport_established)| {
                super::r2o_discovery_candidate_retryable(result, *applied, *transport_established)
            },
        );
        assert!(not_retried.0.is_err());
        assert_eq!(unbound_attempts, 1);
    }

    #[cfg(unix)]
    #[test]
    fn автоклассификатор_не_сохраняет_кандидат_без_полного_https_и_applied() {
        let outcome = || DiscoveryOutcome {
            target: DiscoveryTarget {
                host: "example.com".into(),
                endpoint: "198.51.100.20:443".into(),
                family: 4,
                shape: SHAPE_MODERN,
            },
            plan_text: Some("проверенный сырой пробой кандидат".into()),
            detail: "кандидат найден".into(),
            queue_expired: false,
            direct_clear: false,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: None,
        };

        let без_applied =
            super::r2o_confirm_discovery_outcome(outcome(), Ok(r2o_test_fetch_result()), false);
        assert!(без_applied.plan_text.is_none());

        let mut неполный = r2o_test_fetch_result();
        неполный.complete = false;
        let без_полного_https = super::r2o_confirm_discovery_outcome(outcome(), Ok(неполный), true);
        assert!(без_полного_https.plan_text.is_none());

        let подтверждённый =
            super::r2o_confirm_discovery_outcome(outcome(), Ok(r2o_test_fetch_result()), true);
        assert!(подтверждённый.plan_text.is_some());

        let mut challenge = r2o_test_fetch_result();
        challenge.status = 403;
        challenge.cloudflare_challenge = true;
        assert_eq!(
            super::r2o_family_recovery_decision(&Ok(challenge.clone()), true),
            super::R2oFamilyRecoveryDecision::Reclassify
        );
        let rejected = super::r2o_confirm_discovery_outcome(outcome(), Ok(challenge), true);
        assert!(rejected.plan_text.is_none());
        assert!(rejected.detail.contains("Cloudflare challenge"));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_ech_challenge_повторяет_тот_же_кандидат_через_другого_свидетеля() {
        let primary = r2o_controller::ech::R2oEchConfig {
            public_name: "cloudflare-ech.com".into(),
            origin_name: "romfea.gr".into(),
            config_list: vec![1],
        };
        let next = r2o_controller::ech::R2oEchConfig {
            public_name: "cloudflare-ech.com".into(),
            origin_name: "kinozal.me".into(),
            config_list: vec![2],
        };
        let plan = "tcp split pos=1";
        let mut attempts = Vec::new();
        let (selected, result, challenged) = super::r2o_ech_retry_challenged_witness(
            "cloudflare-ech.com",
            plan,
            &["kinozal.me".into()],
            0,
            primary,
            "challenge".to_owned(),
            |config, result| config.origin_name != "cloudflare-ech.com" && result == "challenge",
            |name| (name == "kinozal.me").then(|| next.clone()),
            |config, received_plan| {
                attempts.push((config.origin_name.clone(), received_plan.to_owned()));
                "clear".to_owned()
            },
        );

        assert_eq!(selected.origin_name, "kinozal.me");
        assert_eq!(result, "clear");
        assert_eq!(challenged, ["romfea.gr"]);
        assert_eq!(attempts, [("kinozal.me".into(), plan.into())]);
    }

    #[cfg(unix)]
    fn r2o_test_fetch_result() -> FetchResult {
        FetchResult {
            address: "198.51.100.20:443".parse().unwrap(),
            local_port: 41_000,
            tls: Some("1.3"),
            status: 200,
            http_outcome: r2o_controller::fetch::R2oFetchHttpOutcome::Positive,
            cloudflare_challenge: false,
            body_bytes: 64,
            body_expected: Some(64),
            body_has_length: true,
            location: String::new(),
            chunked: false,
            gzip: false,
            complete: true,
            application_verified: true,
            elapsed: std::time::Duration::from_millis(30),
            reason: None,
            r2o_volume_observation: Default::default(),
            r2o_resources: Vec::new(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn ech_rx_обрыв_требует_всех_подтверждённых_признаков() {
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "cloudflare-ech.com".into(),
            endpoint: "198.51.100.20:443".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_ECH_TCP,
        };
        let config = r2o_controller::ech::R2oEchConfig {
            public_name: target.host.clone(),
            origin_name: "kinozal.me".into(),
            config_list: Vec::new(),
        };
        let mut fetch = r2o_test_fetch_result();
        fetch.status = 200;
        fetch.complete = false;
        fetch.body_bytes = 8192;
        fetch.r2o_volume_observation.body_framing_valid = true;
        assert!(super::r2o_ech_witness_rx_cut(
            &target, &config, true, false, &fetch
        ));

        assert!(!super::r2o_ech_witness_rx_cut(
            &target, &config, false, false, &fetch
        ));
        assert!(!super::r2o_ech_witness_rx_cut(
            &target, &config, true, true, &fetch
        ));
        let mut not_cut = fetch.clone();
        not_cut.body_bytes = 8191;
        assert!(!super::r2o_ech_witness_rx_cut(
            &target, &config, true, false, &not_cut
        ));
        not_cut = fetch.clone();
        not_cut.complete = true;
        assert!(!super::r2o_ech_witness_rx_cut(
            &target, &config, true, false, &not_cut
        ));
        not_cut = fetch.clone();
        not_cut.r2o_volume_observation.body_framing_valid = false;
        assert!(!super::r2o_ech_witness_rx_cut(
            &target, &config, true, false, &not_cut
        ));
        not_cut = fetch.clone();
        not_cut.status = 400;
        assert!(!super::r2o_ech_witness_rx_cut(
            &target, &config, true, false, &not_cut
        ));
        not_cut = fetch.clone();
        not_cut.http_outcome = r2o_controller::fetch::R2oFetchHttpOutcome::Blocked;
        assert!(!super::r2o_ech_witness_rx_cut(
            &target, &config, true, false, &not_cut
        ));
        not_cut.http_outcome = r2o_controller::fetch::R2oFetchHttpOutcome::LegalDenial;
        assert!(!super::r2o_ech_witness_rx_cut(
            &target, &config, true, false, &not_cut
        ));
    }

    #[cfg(unix)]
    #[test]
    fn ech_rx_лестница_выбирает_имена_или_пять_разрезов_из_состояния_каталога() {
        assert_eq!(super::r2o_ech_rx_ladder_candidate_count(true), 266);
        assert_eq!(
            super::r2o_ech_rx_ladder_candidate_count(false),
            r2o_controller::r2o_rx_volume::r2o_rx_volume_plan_count()
        );

        let (candidate, discovered_name) =
            super::r2o_ech_rx_ladder_candidate(0, true, "hcaptcha.com", 1492)
                .unwrap()
                .unwrap();
        assert_eq!(discovered_name.as_deref(), Some("9gag.com"));
        assert_eq!(
            candidate,
            r2o_controller::r2o_rx_volume::r2o_rx_volume_plan(0, "9gag.com", 1492).unwrap()
        );
        assert!(
            super::r2o_ech_rx_ladder_candidate(266, true, "hcaptcha.com", 1492)
                .unwrap()
                .is_none()
        );

        let (candidate, discovered_name) =
            super::r2o_ech_rx_ladder_candidate(0, false, "media.example", 1492)
                .unwrap()
                .unwrap();
        assert_eq!(discovered_name, None);
        assert_eq!(
            candidate,
            r2o_controller::r2o_rx_volume::r2o_rx_volume_plan(0, "media.example", 1492).unwrap()
        );
        assert!(
            super::r2o_ech_rx_ladder_candidate(5, false, "media.example", 1492)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn ech_rx_лестница_сохраняет_найденное_имя_и_исчерпание_поиска() {
        let work = std::env::temp_dir().join(format!(
            "r2o-network-whitelist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&work).unwrap();
        let path = work.join("catalog.json");
        let fallback = Catalog::default();

        super::r2o_discovery_record_network_whitelist(&path, &fallback, None).unwrap();
        let searched = Catalog::load(&path).unwrap();
        let network = searched.network_whitelist.as_ref().unwrap();
        assert!(network.searched);
        assert!(network.name.is_empty());
        assert_eq!(network.confirmed_at, None);

        super::r2o_discovery_record_network_whitelist(&path, &fallback, Some("9gag.com")).unwrap();
        let confirmed = Catalog::load(&path).unwrap();
        let network = confirmed.network_whitelist.as_ref().unwrap();
        assert!(network.searched);
        assert_eq!(network.name, "9gag.com");
        assert!(network.confirmed_at.is_some());

        super::r2o_discovery_record_network_whitelist(&path, &fallback, Some("zoho.com")).unwrap();
        assert_eq!(
            Catalog::load(&path)
                .unwrap()
                .network_whitelist
                .unwrap()
                .name,
            "9gag.com"
        );

        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(work.join("catalog.json.lock")).unwrap();
        std::fs::remove_dir(work).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn volume_поиск_сохраняет_замер_и_курсоры_только_для_того_же_входа() {
        use r2o_controller::fetch::{R2oFetchVolumeTxResult, R2oFetchVolumeTxVerdict};

        let target = DiscoveryTarget {
            host: "media.example".into(),
            endpoint: "192.0.2.31:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let now = std::time::Instant::now();
        let key = super::R2oDiscoveryVolumeSearchKey {
            wire_len: Some(812),
            send_cap: 1492,
            probe_path: "/asset.css".into(),
            alternate_path: Some("/image.webp".into()),
            network_probe: false,
            white_name: "hcaptcha.com".into(),
        };
        let search = super::R2oDiscoveryVolumeSearch {
            key: key.clone(),
            measured_at: now,
            tx: Ok(R2oFetchVolumeTxResult {
                address: "192.0.2.31:443".parse().unwrap(),
                verdict: R2oFetchVolumeTxVerdict::Cut,
                at_kb: 16,
                elapsed: std::time::Duration::from_secs(1),
                reason: "обрыв на 16 КБ".into(),
            }),
            rx: Default::default(),
            next_candidate: 7,
            tried_plans: Vec::new(),
        };
        let mut cache = super::R2oDiscoveryVolumeSearchCache::default();
        cache.insert(target.clone(), search);

        let cached = cache.get(&target, &key, now).unwrap();
        assert_eq!(cached.next_candidate, 7);
        assert_eq!(cached.key.wire_len, Some(812));
        assert!(
            cache
                .get(
                    &target,
                    &super::R2oDiscoveryVolumeSearchKey {
                        probe_path: "/".into(),
                        ..key.clone()
                    },
                    now,
                )
                .is_none()
        );
        assert!(cache.entries.is_empty());

        cache.insert(
            target.clone(),
            super::R2oDiscoveryVolumeSearch {
                key: key.clone(),
                measured_at: now,
                tx: Ok(R2oFetchVolumeTxResult {
                    address: "192.0.2.31:443".parse().unwrap(),
                    verdict: R2oFetchVolumeTxVerdict::Passed,
                    at_kb: 64,
                    elapsed: std::time::Duration::ZERO,
                    reason: "лестница пройдена".into(),
                }),
                rx: Default::default(),
                next_candidate: 0,
                tried_plans: Vec::new(),
            },
        );
        assert!(
            cache
                .get(
                    &target,
                    &key,
                    now + super::R2O_DISCOVERY_TASK_LIFETIME + std::time::Duration::from_secs(1),
                )
                .is_none()
        );
        assert!(cache.entries.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn volume_проба_сохраняет_форму_профиля_и_распознаёт_оба_направления_обрыва() {
        use r2o_controller::fetch::{
            R2oFetchVolumeRxResult, R2oFetchVolumeTxResult, R2oFetchVolumeTxVerdict,
        };
        use r2o_controller::r2o_volume::{R2oVolumeRxDomain, R2oVolumeRxEvidence};

        let mut target = DiscoveryTarget {
            host: "media.example".into(),
            endpoint: "[2001:db8::31]:443".into(),
            family: 6,
            shape: SHAPE_MODERN,
        };
        let client_hello = [1, 2, 3, 4, 5];
        let options = super::r2o_discovery_volume_fetch_options(
            &target,
            "/asset.css",
            Some(17),
            super::r2o_discovery_volume_wire_len(&target, Some(&client_hello)),
        )
        .unwrap();
        assert_eq!(options.ip.unwrap().to_string(), "2001:db8::31");
        assert_eq!(options.port, 443);
        assert_eq!(options.path, "/asset.css");
        assert_eq!(options.wire_len, Some(5));
        assert!(!options.tls12);
        assert_eq!(options.mark, Some(17));

        target.shape = r2k_core::control::SHAPE_LEGACY;
        let options = super::r2o_discovery_volume_fetch_options(
            &target,
            "/",
            None,
            super::r2o_discovery_volume_wire_len(&target, None),
        )
        .unwrap();
        assert!(options.tls12);
        assert!(options.wire_len.is_some());

        let tx_passed = Ok(R2oFetchVolumeTxResult {
            address: "192.0.2.31:443".parse().unwrap(),
            verdict: R2oFetchVolumeTxVerdict::Passed,
            at_kb: 64,
            elapsed: std::time::Duration::ZERO,
            reason: String::new(),
        });
        assert!(!super::r2o_discovery_volume_cut(
            &tx_passed,
            &R2oFetchVolumeRxResult::default(),
        ));
        let rx_cut = R2oFetchVolumeRxResult {
            evidence: Some(R2oVolumeRxEvidence {
                domain: R2oVolumeRxDomain::HttpBody,
                cut_kb: 16,
                expected_kb: 32,
                cut_packets: 18,
                compressed_complete: true,
                reason: "парный RX-обрыв".into(),
            }),
            ..Default::default()
        };
        assert!(super::r2o_discovery_volume_cut(&tx_passed, &rx_cut));
    }

    #[cfg(unix)]
    #[test]
    fn volume_fingerprint_preserves_both_cut_domains_and_the_rx_packet_budget() {
        use r2o_controller::fetch::{
            R2oFetchVolumeRxResult, R2oFetchVolumeTxResult, R2oFetchVolumeTxVerdict,
        };
        use r2o_controller::r2o_volume::{R2oVolumeRxDomain, R2oVolumeRxEvidence};

        let tx = Ok(R2oFetchVolumeTxResult {
            address: "192.0.2.31:443".parse().unwrap(),
            verdict: R2oFetchVolumeTxVerdict::Cut,
            at_kb: 19,
            elapsed: std::time::Duration::ZERO,
            reason: "TX cut".into(),
        });
        let rx = R2oFetchVolumeRxResult {
            evidence: Some(R2oVolumeRxEvidence {
                domain: R2oVolumeRxDomain::TlsWire,
                cut_kb: 64,
                expected_kb: 96,
                cut_packets: 27,
                compressed_complete: true,
                reason: "RX cut".into(),
            }),
            ..Default::default()
        };
        let fingerprint = super::r2o_discovery_volume_fingerprint(&tx, &rx);

        assert_eq!(fingerprint.method, 2);
        assert_eq!(fingerprint.signals.len(), 2);
        assert_eq!(fingerprint.signals[0].kind, "volume");
        assert_eq!(fingerprint.signals[0].volume, 19);
        assert_eq!(fingerprint.signals[1].kind, "rx-volume-wire");
        assert_eq!(fingerprint.signals[1].volume, 64);
        assert_eq!(fingerprint.signals[1].packets, 27);
    }

    #[cfg(unix)]
    #[test]
    fn volume_recovery_runs_only_after_clear_classification() {
        let target = DiscoveryTarget {
            host: "media.example".into(),
            endpoint: "192.0.2.31:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let outcome = DiscoveryOutcome {
            target: target.clone(),
            plan_text: Some("measured plan".into()),
            detail: String::new(),
            queue_expired: false,
            direct_clear: false,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: None,
        };

        assert!(!super::r2o_discovery_volume_recovery_eligible(&outcome));
        let clear = DiscoveryOutcome {
            direct_clear: true,
            ..outcome
        };
        assert!(super::r2o_discovery_volume_recovery_eligible(&clear));
        let expired = DiscoveryOutcome {
            queue_expired: true,
            ..clear
        };
        assert!(!super::r2o_discovery_volume_recovery_eligible(&expired));
    }

    #[cfg(unix)]
    #[test]
    fn unpaired_partial_rx_downgrades_clear_and_uses_incomplete_retry() {
        use r2o_controller::r2o_volume::{
            R2oVolumeObservation, R2oVolumeProbeStage, R2oVolumeRxEncoding,
        };

        let target = DiscoveryTarget {
            host: "media.example".into(),
            endpoint: "192.0.2.31:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let mut outcome = DiscoveryOutcome {
            target: target.clone(),
            plan_text: None,
            detail: "прямой замер завершился".into(),
            queue_expired: false,
            direct_clear: true,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: None,
        };
        let body_partial = R2oVolumeObservation {
            status: 206,
            body_encoding: R2oVolumeRxEncoding::Identity,
            body_framing_valid: true,
            body_has_length: true,
            body_expected: 24_000,
            body_bytes: 23_900,
            ..Default::default()
        };
        assert!(super::r2o_discovery_mark_partial_rx_inconclusive(
            &mut outcome,
            &body_partial,
            false,
        ));
        assert!(!outcome.direct_clear);
        assert_eq!(
            outcome.retry_after,
            Some(super::R2O_DISCOVERY_INCOMPLETE_RETRY)
        );
        assert!(
            outcome
                .detail
                .contains("RX HTTP body оборвался после 23900 байт")
        );

        let tls_wire_partial = R2oVolumeObservation {
            stage: R2oVolumeProbeStage::Handshake,
            name_valid: true,
            negotiated_tls: Some(0x0303),
            rx_tls_wire_bytes: 14_005,
            rx_tls_record_missing: true,
            ..Default::default()
        };
        let mut tls_outcome = DiscoveryOutcome {
            direct_clear: true,
            ..outcome
        };
        assert!(!super::r2o_discovery_mark_partial_rx_inconclusive(
            &mut tls_outcome,
            &tls_wire_partial,
            true,
        ));
        assert!(tls_outcome.direct_clear);
        assert!(super::r2o_discovery_mark_partial_rx_inconclusive(
            &mut tls_outcome,
            &tls_wire_partial,
            false,
        ));
        assert!(!tls_outcome.direct_clear);
        assert!(
            tls_outcome
                .detail
                .contains("RX TLS wire оборвался после 14005 байт")
        );
    }

    #[cfg(unix)]
    #[test]
    fn tx_volume_cut_enables_the_fake_sni_ladder() {
        use r2o_controller::fetch::{R2oFetchVolumeTxResult, R2oFetchVolumeTxVerdict};

        let tx_cut = Ok(R2oFetchVolumeTxResult {
            address: "192.0.2.31:443".parse().unwrap(),
            verdict: R2oFetchVolumeTxVerdict::Cut,
            at_kb: 19,
            elapsed: std::time::Duration::ZERO,
            reason: "TX cut".into(),
        });
        let no_rx_cut = r2o_controller::fetch::R2oFetchVolumeRxResult::default();
        assert!(super::r2o_discovery_volume_ladder_eligible(
            &tx_cut, &no_rx_cut
        ));

        let tx_passed = Ok(R2oFetchVolumeTxResult {
            verdict: R2oFetchVolumeTxVerdict::Passed,
            address: "192.0.2.31:443".parse().unwrap(),
            at_kb: 64,
            elapsed: std::time::Duration::ZERO,
            reason: String::new(),
        });
        assert!(!super::r2o_discovery_volume_ladder_eligible(
            &tx_passed, &no_rx_cut
        ));

        let rx_cut = r2o_controller::fetch::R2oFetchVolumeRxResult {
            evidence: Some(r2o_controller::r2o_volume::R2oVolumeRxEvidence {
                domain: r2o_controller::r2o_volume::R2oVolumeRxDomain::HttpBody,
                cut_kb: 16,
                expected_kb: 32,
                cut_packets: 16,
                compressed_complete: true,
                reason: "body cut".into(),
            }),
            ..Default::default()
        };
        assert!(super::r2o_discovery_volume_ladder_eligible(
            &tx_passed, &rx_cut
        ));
    }

    #[cfg(unix)]
    #[test]
    fn исходящая_fake_sni_лестница_требует_полного_бюджета_потока() {
        let mut response = r2o_test_fetch_result();
        response.status = 403;
        response.http_outcome = r2o_controller::fetch::R2oFetchHttpOutcome::Neutral;
        let without_budget = Ok(response.clone());
        assert_eq!(
            super::r2o_discovery_volume_ladder_decision(&without_budget, true, true),
            super::R2oFamilyRecoveryDecision::Reclassify
        );

        response.r2o_volume_observation.packet_budget =
            r2o_controller::r2o_volume::R2oVolumePacketBudget::Passed;
        let with_budget = Ok(response);
        assert_eq!(
            super::r2o_discovery_volume_ladder_decision(&with_budget, true, true),
            super::R2oFamilyRecoveryDecision::Verified
        );
        assert_eq!(
            super::r2o_discovery_volume_ladder_decision(&with_budget, false, true),
            super::R2oFamilyRecoveryDecision::Reclassify
        );
        assert_eq!(
            super::r2o_discovery_volume_ladder_decision(&without_budget, true, false),
            super::R2oFamilyRecoveryDecision::Verified
        );
    }

    #[cfg(unix)]
    #[test]
    fn volume_cloudflare_challenge_stops_search_and_cools_down_the_name() {
        let target = DiscoveryTarget {
            host: "media.example".into(),
            endpoint: "192.0.2.31:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let now = std::time::Instant::now();
        let mut searches = super::R2oDiscoveryVolumeSearchCache::default();
        searches.insert(
            target.clone(),
            super::R2oDiscoveryVolumeSearch {
                key: super::R2oDiscoveryVolumeSearchKey {
                    wire_len: None,
                    send_cap: 1200,
                    probe_path: "/".into(),
                    alternate_path: None,
                    network_probe: false,
                    white_name: "hcaptcha.com".into(),
                },
                measured_at: now,
                tx: Err("fixture".into()),
                rx: Default::default(),
                next_candidate: 4,
                tried_plans: vec!["known plan".into()],
            },
        );
        let mut outcome = DiscoveryOutcome {
            target: target.clone(),
            plan_text: Some("candidate".into()),
            detail: String::new(),
            queue_expired: false,
            direct_clear: true,
            volume_recovery: false,
            volume_fingerprint: Some(Default::default()),
            volume_box_id: Some("box".into()),
            retry_after: None,
        };

        let searches = std::sync::Mutex::new(searches);
        super::r2o_discovery_stop_volume_search_for_challenge(&mut outcome, &target, &searches);
        assert!(super::r2o_discovery_volume_challenge_outcome(&outcome));
        assert!(searches.lock().unwrap().entries.is_empty());
        assert!(outcome.plan_text.is_none());
        assert!(outcome.volume_fingerprint.is_none());
        assert!(outcome.volume_box_id.is_none());
        assert_eq!(
            outcome.retry_after,
            Some(super::R2O_DISCOVERY_CHALLENGE_RETRY)
        );

        let mut worker = r2o_test_discovery_worker_without_threads();
        worker.r2o_complete_outcome(outcome);
        let other_address = DiscoveryTarget {
            endpoint: "192.0.2.32:443".into(),
            ..target.clone()
        };
        assert!(!worker.queue(other_address.clone()));

        worker.challenge_cooldowns.insert(
            (target.host, target.family),
            std::time::Instant::now() - std::time::Duration::from_secs(1),
        );
        assert!(worker.queue(other_address));
    }

    #[cfg(unix)]
    #[test]
    fn volume_known_plans_use_compatible_boxes_and_prioritize_the_same_bucket() {
        fn saved_plan(id: u8, successes: i32, split: i32) -> r2o_controller::catalog::Plan {
            let id = format!("{id:02x}").repeat(16);
            r2o_controller::catalog::Plan {
                id: id.clone(),
                proto: "tls".into(),
                text: format!("r2o-plan 1 11\nid {id}\nproto tcp tls\nsplit sni_middle +{split}\n"),
                successes,
                enabled: true,
                ..Default::default()
            }
        }
        fn volume_box(id: &str, volume: i32, plan: r2o_controller::catalog::Plan) -> BoxRecord {
            BoxRecord {
                id: id.into(),
                fingerprint: Fingerprint {
                    method: 2,
                    signals: vec![Signal {
                        kind: "volume".into(),
                        volume,
                        seen: 1,
                        ..Signal::default()
                    }],
                },
                plans: vec![plan],
                ..Default::default()
            }
        }

        let same_bucket = saved_plan(1, 1, 8);
        let near_bucket = saved_plan(2, 100, 9);
        let catalog = Catalog {
            boxes: vec![
                volume_box("near", 15, near_bucket.clone()),
                volume_box("same", 20, same_bucket.clone()),
                volume_box("outside-slack", 24, saved_plan(3, 1000, 10)),
                {
                    let mut record = volume_box("wrong-method", 20, saved_plan(4, 1000, 11));
                    record.fingerprint.method = 1;
                    record
                },
            ],
            ..Catalog::default()
        };
        let target = DiscoveryTarget {
            host: "media.example".into(),
            endpoint: "192.0.2.31:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let observed = Fingerprint {
            method: 2,
            signals: vec![Signal {
                kind: "volume".into(),
                volume: 19,
                seen: 1,
                ..Signal::default()
            }],
        };

        assert_eq!(
            super::r2o_discovery_volume_known_plans(Some(&catalog), &target, &observed),
            [
                ("same".into(), same_bucket.text),
                ("near".into(), near_bucket.text)
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn подтверждённый_volume_план_заменяет_уже_пригодную_привязку() {
        let target = DiscoveryTarget {
            host: "media.example".into(),
            endpoint: "192.0.2.31:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let plan_id = "ab".repeat(16);
        let mut catalog = Catalog::default();
        catalog.boxes.push(BoxRecord {
            id: "volume-source".into(),
            fingerprint: Fingerprint::default(),
            plans: vec![r2o_controller::catalog::Plan {
                id: plan_id.clone(),
                proto: "tls".into(),
                text: r2o_controller::r2o_rx_volume::r2o_rx_volume_plan(0, "hcaptcha.com", 1492)
                    .unwrap(),
                added: 100,
                enabled: true,
                ..Default::default()
            }],
            bindings: vec![Binding {
                kind: "name".into(),
                target: target.host.clone(),
                plan_id,
                level: 3,
                confirmed: 100,
                enabled: true,
                transport: 6,
                family: 4,
                shape: SHAPE_MODERN,
                verified_by: 1,
                input: 2,
                ..Binding::default()
            }],
            ..BoxRecord::default()
        });
        assert!(r2o_controller::discovery::has_usable_binding(
            &catalog, &target
        ));
        assert!(super::r2o_discovery_existing_binding_blocks_outcome(
            &catalog, &target, 2, false
        ));
        assert!(!super::r2o_discovery_existing_binding_blocks_outcome(
            &catalog, &target, 2, true
        ));
    }

    #[cfg(unix)]
    #[test]
    fn семейное_восстановление_ставит_план_группы_первым_и_отбрасывает_recheck() {
        use r2o_controller::catalog::{DomainObservation, DomainState, Plan as SavedPlan};

        fn saved_tls_plan(id: u8, ttl: u8) -> SavedPlan {
            let id_hex = format!("{id:02x}").repeat(16);
            SavedPlan {
                id: id_hex.clone(),
                proto: "tls".into(),
                text: format!(
                    "r2o-plan 1 11\nid {id_hex}\nproto tcp tls\nsplit sni_middle +{ttl}\n"
                ),
                enabled: true,
                ..SavedPlan::default()
            }
        }

        fn binding(name: &str, plan: &SavedPlan, recheck_since: Option<i64>) -> Binding {
            Binding {
                kind: "name".into(),
                target: name.into(),
                plan_id: plan.id.clone(),
                level: 3,
                enabled: true,
                transport: 6,
                family: 4,
                shape: SHAPE_MODERN,
                probe_path: "/css/site.css".into(),
                recheck_since,
                ..Binding::default()
            }
        }

        fn observation(name: &str, plan: &SavedPlan) -> r2o_controller::catalog::DomainObservation {
            DomainObservation {
                name: name.into(),
                plan_id: plan.id.clone(),
                key: r2o_controller::catalog::GroupKey {
                    transport: 6,
                    family: 4,
                    shape: SHAPE_MODERN,
                    probe_path: "/css/site.css".into(),
                    ..Default::default()
                },
                evidence: 1,
                at: 10,
            }
        }

        let group_plan = saved_tls_plan(1, 1);
        let sibling_a = saved_tls_plan(2, 2);
        let sibling_b = saved_tls_plan(3, 3);
        let recheck_plan = saved_tls_plan(4, 4);
        let domain_state = DomainState {
            observations: vec![
                observation("a.example.net", &group_plan),
                observation("b.example.net", &group_plan),
                observation("c.example.net", &group_plan),
                observation("d.example.net", &sibling_a),
                observation("e.example.net", &sibling_b),
                observation("f.example.net", &recheck_plan),
            ],
            ..DomainState::default()
        };
        let mut catalog = Catalog {
            boxes: vec![
                BoxRecord {
                    plans: vec![group_plan.clone()],
                    bindings: vec![
                        binding("a.example.net", &group_plan, None),
                        binding("b.example.net", &group_plan, None),
                        binding("c.example.net", &group_plan, None),
                    ],
                    ..BoxRecord::default()
                },
                BoxRecord {
                    plans: vec![sibling_a.clone()],
                    bindings: vec![binding("d.example.net", &sibling_a, None)],
                    ..BoxRecord::default()
                },
                BoxRecord {
                    plans: vec![sibling_b.clone()],
                    bindings: vec![binding("e.example.net", &sibling_b, None)],
                    ..BoxRecord::default()
                },
                BoxRecord {
                    plans: vec![recheck_plan.clone()],
                    bindings: vec![binding("f.example.net", &recheck_plan, Some(9))],
                    ..BoxRecord::default()
                },
                BoxRecord {
                    plans: vec![group_plan.clone()],
                    bindings: vec![binding("media.example.net", &group_plan, None)],
                    ..BoxRecord::default()
                },
            ],
            domain_state: Some(domain_state),
            ..Catalog::default()
        };
        catalog.domain_state.as_mut().unwrap().restore().unwrap();
        let target = DiscoveryTarget {
            host: "media.example.net".into(),
            endpoint: "198.51.100.20:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        assert_eq!(
            catalog
                .domain_state
                .as_ref()
                .unwrap()
                .groups
                .first()
                .map(|group| group.plan_id.as_str()),
            Some(group_plan.id.as_str())
        );

        let candidates = matching_domain_recovery_candidates(&catalog, &target);

        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].plan_id, [1; 16]);
        assert!(candidates[0].group_plan);
        assert_eq!(candidates[1].plan_id, [2; 16]);
        assert!(!candidates[1].group_plan);
        assert_eq!(candidates[2].plan_id, [3; 16]);
        assert!(!candidates[2].group_plan);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.probe_path == "/css/site.css")
        );
    }

    #[cfg(unix)]
    #[test]
    fn обычный_discovery_выбирает_подтверждение_перед_измерением_и_упоминанием() {
        use r2o_controller::catalog::{Binding, BoxRecord, Catalog};
        use r2o_controller::discovery::DiscoveryTarget;
        use r2o_controller::r2o_resource::{R2oResourceHint, R2oResourceMemory};

        let now = std::time::Instant::now();
        let memory = std::sync::Mutex::new(R2oResourceMemory::default());
        memory.lock().unwrap().remember_hints(
            &[R2oResourceHint {
                host: "media.example.net".into(),
                path: "/css/mentioned.css".into(),
            }],
            now,
        );
        assert_eq!(
            super::r2o_discovery_resource_probe_paths(
                &DiscoveryTarget {
                    host: "media.example.net".into(),
                    endpoint: "198.51.100.20:443".into(),
                    family: 4,
                    shape: SHAPE_MODERN,
                },
                None,
                &memory,
            ),
            ("/css/mentioned.css".into(), None)
        );

        memory.lock().unwrap().remember_proven_path(
            "media.example.net",
            "/css/proven.css",
            now + std::time::Duration::from_secs(1),
        );
        let target = DiscoveryTarget {
            host: "media.example.net".into(),
            endpoint: "198.51.100.20:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        assert_eq!(
            super::r2o_discovery_resource_probe_paths(&target, None, &memory),
            ("/css/proven.css".into(), None)
        );

        let catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: "media.example.net".into(),
                    level: 3,
                    confirmed: 10,
                    enabled: true,
                    transport: 6,
                    family: 0,
                    shape: SHAPE_MODERN,
                    probe_path: "/css/confirmed.css".into(),
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        assert_eq!(
            super::r2o_discovery_resource_probe_paths(&target, Some(&catalog), &memory),
            ("/css/confirmed.css".into(), Some("/css/proven.css".into()))
        );
        assert_eq!(
            super::r2o_discovery_resource_probe_paths(
                &DiscoveryTarget {
                    shape: SHAPE_ECH_TCP,
                    ..target.clone()
                },
                Some(&catalog),
                &memory,
            ),
            ("/css/confirmed.css".into(), Some("/css/proven.css".into()))
        );
        let quic_catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: "media.example.net".into(),
                    level: 3,
                    confirmed: 10,
                    enabled: true,
                    transport: 17,
                    family: 4,
                    shape: SHAPE_QUIC,
                    probe_path: "/css/quic.css".into(),
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        assert_eq!(
            super::r2o_discovery_resource_probe_paths(
                &DiscoveryTarget {
                    shape: SHAPE_QUIC,
                    ..target.clone()
                },
                Some(&quic_catalog),
                &memory,
            ),
            ("/css/quic.css".into(), Some("/css/proven.css".into()),)
        );
        assert_eq!(
            super::r2o_discovery_resource_probe_paths(
                &DiscoveryTarget {
                    endpoint: "10.0.0.20:443".into(),
                    ..target
                },
                Some(&catalog),
                &memory,
            ),
            ("/".into(), None)
        );
    }

    #[cfg(unix)]
    #[test]
    fn подтверждённый_путь_при_равной_отметке_сохраняет_первую_привязку() {
        use r2o_controller::catalog::{Binding, BoxRecord, Catalog};
        use r2o_controller::discovery::DiscoveryTarget;

        let binding = |probe_path: &str| Binding {
            kind: "name".into(),
            target: "media.example.net".into(),
            level: 3,
            confirmed: 10,
            enabled: true,
            transport: 6,
            family: 4,
            shape: SHAPE_MODERN,
            probe_path: probe_path.into(),
            ..Binding::default()
        };
        let catalog = Catalog {
            boxes: vec![
                BoxRecord {
                    bindings: vec![binding("/first.css")],
                    ..BoxRecord::default()
                },
                BoxRecord {
                    bindings: vec![binding("/second.css")],
                    ..BoxRecord::default()
                },
            ],
            ..Catalog::default()
        };
        let target = DiscoveryTarget {
            host: "media.example.net".into(),
            endpoint: "198.51.100.20:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };

        assert_eq!(
            super::r2o_target_confirmed_probe_path(&catalog, &target),
            Some("/first.css".into())
        );
    }

    #[cfg(unix)]
    #[test]
    fn сохранённый_quic_путь_имени_используется_следующим_discovery() {
        use r2o_controller::catalog::Catalog;
        use r2o_controller::discovery::DiscoveryTarget;

        let mut catalog = Catalog::default();
        r2o_controller::discovery::add_confirmed_quic_name_binding(
            &mut catalog,
            "media.example.net",
            4,
            "/static/app.css",
            "r2o-plan 1 10\nid 00000000000000000000000000000000\nproto udp quic\nquicsplit 1\n",
            125,
        )
        .unwrap();
        let snapshot =
            r2o_controller::quic_replay::r2o_quic_profile_snapshot(Some("media.example.net"))
                .unwrap();
        let resource_memory =
            std::sync::Mutex::new(r2o_controller::r2o_resource::R2oResourceMemory::default());
        assert_eq!(
            super::r2o_quic_discovery_probe_path(
                &snapshot,
                "198.51.100.20:443".parse().unwrap(),
                &catalog,
                &resource_memory,
            ),
            "/static/app.css"
        );
        let target = DiscoveryTarget {
            host: "media.example.net".into(),
            endpoint: "198.51.100.20:443".into(),
            family: 4,
            shape: SHAPE_QUIC,
        };

        assert_eq!(
            super::r2o_target_confirmed_probe_path(&catalog, &target),
            Some("/static/app.css".into())
        );
    }

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
                Some(77),
                &gate,
                false,
            ),
            1
        );
        gate.r2o_scheduler_tick();
        let (entry, permit) = super::r2o_take_ready_quic_discovery(&mut pending, &gate).unwrap();
        assert_eq!(entry.snapshot, [1, 2, 3]);
        assert_eq!(entry.r2o_mark, Some(77));
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
                None,
                &full_gate,
                false,
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
    fn r2o_quic_срок_задачи_не_считает_уступку_слота() {
        let started = std::time::Instant::now();
        assert_eq!(
            super::r2o_quic_trial_remaining_at(
                started,
                std::time::Duration::from_secs(120),
                started + std::time::Duration::from_secs(9 * 60),
            ),
            std::time::Duration::from_secs(3 * 60)
        );
        assert_eq!(
            super::r2o_quic_trial_remaining_at(
                started,
                std::time::Duration::from_secs(120),
                started + std::time::Duration::from_secs(12 * 60),
            ),
            std::time::Duration::ZERO
        );
    }

    #[cfg(unix)]
    #[test]
    fn r2o_quic_discovery_задаёт_повтор_по_исходу_испытания() {
        assert_eq!(
            super::r2o_quic_discovery_cooldown(&Ok(Some((
                "план".to_owned(),
                "кандидат".to_owned(),
            )))),
            std::time::Duration::from_secs(60 * 60)
        );
        assert_eq!(
            super::r2o_quic_discovery_cooldown(&Ok(None)),
            std::time::Duration::from_secs(10 * 60)
        );
        assert_eq!(
            super::r2o_quic_discovery_cooldown(&Err("сбой".to_owned())),
            std::time::Duration::from_secs(2 * 60)
        );
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
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
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
    fn http_search_window_shares_active_and_cooldown_state_across_endpoints() {
        use r2o_controller::discovery::DiscoveryTarget;
        use std::time::{Duration, Instant};

        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
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
        let mut other_endpoint = target.clone();
        other_endpoint.endpoint = "192.0.2.2:80".into();
        assert!(!client.begin_http_search(&other_endpoint, false));

        client.http_search_started.insert(
            key,
            HttpSearchWindow {
                started: now - Duration::from_secs(59 * 60),
                cooldown: HttpSearchDisposition::Retry.cooldown(),
                active: false,
            },
        );
        assert!(!client.begin_http_search(&target, false));

        assert!(!client.begin_http_search(&other_endpoint, false));
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
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
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
    fn baseline_local_failure_and_cut_silence_follow_donor_retry_rules() {
        use r2o_controller::http_search::Answer;
        use std::io::{Error, ErrorKind};

        let connect = || HttpBaselineError::Connect(Error::from(ErrorKind::ConnectionRefused));
        assert_eq!(
            http_baseline_failure_action(Answer::Cut, 1, &connect()),
            HttpBaselineFailureAction::Retry
        );
        assert_eq!(
            http_baseline_failure_action(Answer::Injected, 1, &connect()),
            HttpBaselineFailureAction::Retry
        );
        assert_eq!(
            http_baseline_failure_action(Answer::Cut, 2, &connect()),
            HttpBaselineFailureAction::Inconclusive
        );

        let silence = || HttpBaselineError::Response(Error::from(ErrorKind::TimedOut));
        assert_eq!(
            http_baseline_failure_action(Answer::Cut, 1, &silence()),
            HttpBaselineFailureAction::Retry
        );
        assert_eq!(
            http_baseline_failure_action(Answer::Cut, 2, &silence()),
            HttpBaselineFailureAction::Search
        );
        assert_eq!(
            http_baseline_failure_action(Answer::Injected, 1, &silence()),
            HttpBaselineFailureAction::Search
        );

        let reset = HttpBaselineError::Response(Error::from(ErrorKind::ConnectionReset));
        assert_eq!(
            http_baseline_failure_action(Answer::Cut, 1, &reset),
            HttpBaselineFailureAction::Recheck
        );
    }

    #[cfg(unix)]
    #[test]
    fn controller_queues_applied_events_for_later_processing() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
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
    fn controller_applies_a_dynamic_datapath_send_limit_before_queueing_the_event() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let send_cap = Arc::new(AtomicUsize::new(1200));
        let mut client = ControlClient {
            socket,
            send_maxlen: 1200,
            send_cap: Arc::clone(&send_cap),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let bytes = r2k_core::control::encode_greeting(1500).unwrap();
        let mut encoded = std::io::Cursor::new(bytes);
        let greeting = read_frame(&mut encoded).unwrap();

        client.queue_async_frame(greeting.clone()).unwrap();

        assert_eq!(client.send_maxlen, 1500);
        assert_eq!(send_cap.load(Ordering::Relaxed), 1500);
        assert_eq!(client.pending_events, VecDeque::from([greeting]));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_controller_queues_tcp_silence_events_for_later_processing() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let event = Frame {
            kind: EVENT_R2O_TCP_SILENT,
            body: vec![0; KEY_LEN + 6],
        };

        client.queue_async_frame(event.clone()).unwrap();

        assert_eq!(client.pending_events, VecDeque::from([event]));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_controller_queues_tcp_repeat_events_for_later_processing() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let event = Frame {
            kind: r2k_core::control::EVENT_R2O_TCP_REPEAT,
            body: vec![0; KEY_LEN + 2],
        };

        client.queue_async_frame(event.clone()).unwrap();

        assert_eq!(client.pending_events, VecDeque::from([event]));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_controller_queues_tcp_rst_cut_events_for_later_processing() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut client = ControlClient {
            socket,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let event = Frame {
            kind: r2k_core::control::EVENT_R2O_TCP_RST_CUT,
            body: vec![0; KEY_LEN + 1],
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
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let event = Frame {
            kind: EVENT_R2O_TCP_STALL,
            body: vec![0; KEY_LEN + 10],
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
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
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
                        planned: false,
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
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
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
            probe_path: "/".into(),
            r2o_mark: None,
            permit,
            started_at: std::time::Instant::now(),
            deny_recheck: false,
            stall_cut: false,
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
    fn r2o_quic_discovery_повторяет_один_раз_с_последним_clienthello() {
        use super::{R2oQuicDiscoveryTask, R2oQuicDiscoveryWorker};
        use std::sync::{Arc, Condvar, Mutex};

        let server: std::net::SocketAddr = "198.51.100.20:443".parse().unwrap();
        let client: std::net::SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let first = r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[&include_bytes!(
            "../../r2k-core/tests/fixtures/quic_v1_initial.bin"
        )[..]])
        .unwrap();
        let second = r2k_core::quic_snapshot::r2k_quic_snapshot_reseal(&first).unwrap();
        let latest = r2k_core::quic_snapshot::r2k_quic_snapshot_reseal(&second).unwrap();
        let ignored = r2k_core::quic_snapshot::r2k_quic_snapshot_reseal(&latest).unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let runner_observed = Arc::clone(&observed);
        let expected_latest = latest.clone();
        let runner_state = Arc::new((Mutex::new((0usize, 0usize)), Condvar::new()));
        let runner_wait = Arc::clone(&runner_state);
        let mut worker =
            R2oQuicDiscoveryWorker::r2o_new_with_runner(Arc::new(move |task, _, _| {
                runner_observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(task.snapshot.clone());
                let (state_lock, changed) = &*runner_wait;
                let mut state = state_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.0 += 1;
                let run = state.0;
                changed.notify_all();
                while state.1 < run {
                    state = changed
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                let name = if task.snapshot == expected_latest {
                    "свежий"
                } else {
                    "устаревший"
                };
                Ok(Some((name.to_owned(), name.to_owned())))
            }));
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let permit = gate
            .r2o_acquire(&std::sync::atomic::AtomicBool::new(false))
            .unwrap();
        assert!(worker.queue(R2oQuicDiscoveryTask {
            server,
            snapshot: first.clone(),
            probe_path: "/".into(),
            r2o_mark: None,
            permit,
            started_at: std::time::Instant::now(),
            deny_recheck: false,
            stall_cut: false,
        }));

        let mut key = [0; r2k_core::control::KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(
            &client
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .unwrap()
                .octets(),
        );
        key[17..21].copy_from_slice(
            &server
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .unwrap()
                .octets(),
        );
        key[33..35].copy_from_slice(&client.port().to_be_bytes());
        key[35..37].copy_from_slice(&server.port().to_be_bytes());
        key[37] = 17;
        let hello = |snapshot: Vec<u8>| r2k_core::control::HelloEvent {
            key,
            host: Some(b"example.com".to_vec()),
            shape: Some(r2k_core::control::SHAPE_QUIC),
            r2o_wire_len: None,
            quic_snapshot: Some(snapshot),
        };
        let wait_for_run = |run| {
            let (state_lock, changed) = &*runner_state;
            let state = state_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (state, timeout) = changed
                .wait_timeout_while(state, std::time::Duration::from_secs(2), |state| {
                    state.0 < run
                })
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                !timeout.timed_out(),
                "QUIC worker не начал ожидаемый повтор"
            );
            drop(state);
        };
        let release_run = |run| {
            let (state_lock, changed) = &*runner_state;
            state_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .1 = run;
            changed.notify_all();
        };

        let catalog = Catalog::default();
        let resource_memory =
            std::sync::Mutex::new(r2o_controller::r2o_resource::R2oResourceMemory::default());
        wait_for_run(1);
        assert!(worker.queue_client_snapshot(&hello(second.clone()), &catalog, &resource_memory));
        assert!(worker.queue_client_snapshot(&hello(latest.clone()), &catalog, &resource_memory));
        assert_eq!(observed.lock().unwrap()[0], first);
        release_run(1);
        wait_for_run(2);
        assert!(!worker.queue_client_snapshot(&hello(ignored), &catalog, &resource_memory));
        assert_eq!(observed.lock().unwrap()[1], latest);
        release_run(2);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let outcome = loop {
            if let Some(outcome) = worker.try_outcome() {
                break outcome;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "QUIC worker не вернул исход"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        assert_eq!(
            outcome.result.unwrap(),
            Some(("свежий".into(), "свежий".into()))
        );
        assert_eq!(observed.lock().unwrap().len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_quic_параллельные_адресные_пробы_сохраняют_поколения_и_снимаются_точно() {
        use super::{HttpSearchCommand, R2oQuicDiscoveryTask, R2oQuicDiscoveryWorker};
        use std::collections::HashSet;
        use std::os::unix::net::UnixStream;
        use std::sync::{Arc, Barrier};

        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(2);
        let plan_records = Arc::new(
            super::compile_text(
                "r2o-plan 1 10\nid 11111111111111111111111111111111\nproto udp quic\nquicsplit 1\n",
            )
            .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(2));
        let runner_barrier = Arc::clone(&barrier);
        let runner_plan = Arc::clone(&plan_records);
        let mut worker = R2oQuicDiscoveryWorker::r2o_new_with_runner(Arc::new(
            move |task, commands, _cancel| {
                let server = task.server;
                let trial_byte = match server.ip() {
                    std::net::IpAddr::V4(address) => address.octets()[3],
                    std::net::IpAddr::V6(_) => return Err("ожидался IPv4-адрес".into()),
                };
                let local = std::net::SocketAddr::new(
                    "192.0.2.10".parse().unwrap(),
                    41000 + u16::from(trial_byte),
                );
                let trial_id = [trial_byte; 16];
                let set = super::encode_set_addr_probe(
                    local,
                    server,
                    super::ADDR_PROBE_LEASE_MAX_MS,
                    &runner_plan,
                    trial_id,
                )
                .map_err(str::to_owned)?;
                let delete = super::encode_delete_addr_probe(local, server, trial_id)
                    .map_err(str::to_owned)?;
                let ack = super::ask_http_controller(&commands, |reply| {
                    HttpSearchCommand::R2oInstallQuicProbe {
                        command: set,
                        delete: delete.clone(),
                        trial_id,
                        reply,
                    }
                })?;
                if !ack.ok || ack.trial_id != Some(trial_id) {
                    return Err("точная QUIC-проба не получила подтверждение".into());
                }
                runner_barrier.wait();
                super::ask_http_controller(&commands, |reply| {
                    HttpSearchCommand::R2oDeleteQuicProbe {
                        command: delete,
                        reply,
                    }
                })?;
                Ok(None)
            },
        ));

        let (socket, mut peer) = UnixStream::pair().unwrap();
        let control_thread = std::thread::spawn(move || {
            let mut active = HashSet::new();
            let mut probes = Vec::new();
            let mut maximum_active = 0;
            for _ in 0..4 {
                let frame = read_frame(&mut peer).unwrap();
                match frame.kind {
                    super::COMMAND_SET_ADDR_PROBE => {
                        let key: [u8; KEY_LEN] = frame.body[..KEY_LEN].try_into().unwrap();
                        let trial_id: [u8; 16] =
                            frame.body[KEY_LEN..KEY_LEN + 16].try_into().unwrap();
                        assert_eq!(key[0], 4);
                        assert_eq!(key[37], 17);
                        assert_eq!(&key[1..5], &[192, 0, 2, 10]);
                        assert_eq!(u16::from_be_bytes([key[35], key[36]]), 443);
                        assert_eq!(trial_id, [key[20]; 16]);
                        assert!(active.insert((key, trial_id)));
                        maximum_active = maximum_active.max(active.len());
                        probes.push((key, trial_id));
                        peer.write_all(
                            &encode_ack_for_trial(
                                super::COMMAND_SET_ADDR_PROBE,
                                true,
                                0,
                                Some(trial_id),
                            )
                            .unwrap(),
                        )
                        .unwrap();
                    }
                    super::COMMAND_DEL_ADDR_PROBE => {
                        let key: [u8; KEY_LEN] = frame.body[..KEY_LEN].try_into().unwrap();
                        let trial_id: [u8; 16] =
                            frame.body[KEY_LEN..KEY_LEN + 16].try_into().unwrap();
                        assert!(active.remove(&(key, trial_id)));
                        peer.write_all(
                            &encode_ack(super::COMMAND_DEL_ADDR_PROBE, true, 0).unwrap(),
                        )
                        .unwrap();
                    }
                    other => panic!("неожиданная команда QUIC-пробы: {other}"),
                }
            }
            assert_eq!(maximum_active, 2);
            assert_eq!(probes.len(), 2);
            assert!(active.is_empty());
            let mut destinations = probes
                .iter()
                .map(|(key, _)| {
                    std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&key[17..21]).unwrap())
                })
                .collect::<Vec<_>>();
            destinations.sort_unstable();
            assert_eq!(
                destinations,
                [
                    std::net::Ipv4Addr::new(198, 51, 100, 10),
                    std::net::Ipv4Addr::new(198, 51, 100, 20)
                ]
            );
            assert_ne!(probes[0].1, probes[1].1);
            assert_ne!(
                [probes[0].0[33], probes[0].0[34]],
                [probes[1].0[33], probes[1].0[34]]
            );
        });

        let mut client = ControlClient {
            socket,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let mut catalog = Catalog::default();
        let first = R2oQuicDiscoveryTask {
            server: "198.51.100.10:443".parse().unwrap(),
            snapshot: r2o_test_quic_initial_snapshot(),
            probe_path: "/".into(),
            r2o_mark: None,
            permit: gate.r2o_try_acquire().unwrap(),
            started_at: std::time::Instant::now(),
            deny_recheck: false,
            stall_cut: false,
        };
        let second = R2oQuicDiscoveryTask {
            server: "198.51.100.20:443".parse().unwrap(),
            snapshot: r2o_test_quic_initial_snapshot(),
            probe_path: "/".into(),
            r2o_mark: None,
            permit: gate.r2o_try_acquire().unwrap(),
            started_at: std::time::Instant::now(),
            deny_recheck: false,
            stall_cut: false,
        };
        assert!(worker.queue(first));
        assert!(worker.queue(second));
        assert!(!worker.has_capacity());

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut completed = HashSet::new();
        while completed.len() < 2 {
            if let Some(command) = worker.try_command() {
                client
                    .service_http_search_command(
                        command,
                        &mut catalog,
                        std::path::Path::new("параллельные-адресные-пробы.json"),
                    )
                    .unwrap();
                continue;
            }
            if let Some(outcome) = worker.try_outcome() {
                assert!(matches!(outcome.result, Ok(None)));
                assert!(completed.insert(outcome.server));
            } else {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        control_thread.join().unwrap();
        assert!(catalog.boxes.is_empty());
        assert!(worker.has_capacity());
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
            snapshot: r2o_test_quic_initial_snapshot(),
            probe_path: "/".into(),
            r2o_mark: None,
            permit: gate.r2o_try_acquire().unwrap(),
            started_at: std::time::Instant::now(),
            deny_recheck: false,
            stall_cut: false,
        };
        let second = R2oQuicDiscoveryTask {
            server: "198.51.100.20:443".parse().unwrap(),
            snapshot: r2o_test_quic_initial_snapshot(),
            probe_path: "/".into(),
            r2o_mark: None,
            permit: gate.r2o_try_acquire().unwrap(),
            started_at: std::time::Instant::now(),
            deny_recheck: false,
            stall_cut: false,
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
    fn r2o_quic_worker_передает_метку_в_исполнитель() {
        use super::{R2oQuicDiscoveryTask, R2oQuicDiscoveryWorker};
        use std::sync::{Arc, mpsc};

        let (метка_sender, метка_receiver) = mpsc::channel();
        let mut worker =
            R2oQuicDiscoveryWorker::r2o_new_with_runner(Arc::new(move |task, _, _| {
                метка_sender
                    .send(task.r2o_mark)
                    .map_err(|error| error.to_string())?;
                Ok(None)
            }));
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        assert!(worker.queue(R2oQuicDiscoveryTask {
            server: "198.51.100.77:443".parse().unwrap(),
            snapshot: r2o_test_quic_initial_snapshot(),
            probe_path: "/".into(),
            r2o_mark: Some(77),
            permit: gate.r2o_try_acquire().unwrap(),
            started_at: std::time::Instant::now(),
            deny_recheck: false,
            stall_cut: false,
        }));

        assert_eq!(
            метка_receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap(),
            Some(77)
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Some(outcome) = worker.try_outcome() {
                assert_eq!(outcome.server, "198.51.100.77:443".parse().unwrap());
                assert!(matches!(outcome.result, Ok(None)));
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(worker.has_capacity());
    }

    #[cfg(unix)]
    #[test]
    fn r2o_quic_worker_передает_выбранный_путь_в_исполнитель() {
        use super::{R2oQuicDiscoveryTask, R2oQuicDiscoveryWorker};
        use std::sync::{Arc, mpsc};

        let (path_sender, path_receiver) = mpsc::channel();
        let mut worker =
            R2oQuicDiscoveryWorker::r2o_new_with_runner(Arc::new(move |task, _, _| {
                path_sender
                    .send(task.probe_path.clone())
                    .map_err(|error| error.to_string())?;
                Ok(None)
            }));
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        assert!(worker.queue(R2oQuicDiscoveryTask {
            server: "198.51.100.77:443".parse().unwrap(),
            snapshot: r2o_test_quic_initial_snapshot(),
            probe_path: "/static/app.css".into(),
            r2o_mark: None,
            permit: gate.r2o_try_acquire().unwrap(),
            started_at: std::time::Instant::now(),
            deny_recheck: false,
            stall_cut: false,
        }));

        assert_eq!(
            path_receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap(),
            "/static/app.css"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if worker.try_outcome().is_some() {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(worker.has_capacity());
    }

    #[cfg(unix)]
    #[test]
    fn r2o_остановка_quic_worker_обслуживает_удаление_временной_пробы() {
        use super::{HttpSearchCommand, R2oQuicDiscoveryTask, R2oQuicDiscoveryWorker};
        use std::sync::mpsc;
        use std::sync::{Arc, atomic::Ordering};

        let server = "198.51.100.10:443".parse().unwrap();
        let local = "192.0.2.10:41000".parse().unwrap();
        let trial_id = [0x41; 16];
        let (started_sender, started_receiver) = mpsc::channel();
        let mut worker = R2oQuicDiscoveryWorker::r2o_new_with_runner(Arc::new(
            move |_task, commands, cancel| {
                started_sender.send(()).unwrap();
                while !cancel.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                let (reply, result) = mpsc::sync_channel(1);
                commands
                    .send(HttpSearchCommand::R2oDeleteQuicProbe {
                        command: super::encode_delete_addr_probe(local, server, trial_id).unwrap(),
                        reply,
                    })
                    .map_err(|error| error.to_string())?;
                result
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .map_err(|error| error.to_string())??;
                Ok(None)
            },
        ));
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        assert!(worker.queue(R2oQuicDiscoveryTask {
            server,
            snapshot: r2o_test_quic_initial_snapshot(),
            probe_path: "/".into(),
            r2o_mark: None,
            permit: gate.r2o_try_acquire().unwrap(),
            started_at: std::time::Instant::now(),
            deny_recheck: false,
            stall_cut: false,
        }));
        started_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();

        let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let control_thread = std::thread::spawn(move || {
            let delete = read_frame(&mut peer).unwrap();
            assert_eq!(delete.kind, super::COMMAND_DEL_ADDR_PROBE);
            peer.write_all(&encode_ack(delete.kind, true, 0).unwrap())
                .unwrap();
        });
        let mut client = super::ControlClient {
            socket,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let mut catalog = Catalog::default();

        client
            .r2o_stop_quic_discovery(
                &mut worker,
                &mut catalog,
                std::path::Path::new("каталог.json"),
            )
            .unwrap();
        control_thread.join().unwrap();
        assert!(worker.r2o_all_finished());
    }

    #[cfg(unix)]
    #[test]
    fn r2o_quic_ech_подтверждение_сохраняет_адресную_привязку() {
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
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let mut catalog = Catalog::default();
        client
            .r2o_install_quic_candidate(
                "198.51.100.90:443".parse().unwrap(),
                "media.example.net",
                &r2o_test_quic_ech_snapshot(),
                "/static/app.css",
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
        let binding = &catalog.boxes[0].bindings[0];
        assert_eq!(binding.kind, "addr");
        assert_eq!(binding.target, "198.51.100.90");
        assert!(binding.probe_path.is_empty());
        std::fs::remove_dir_all(work).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn каталожные_tcp_бюджеты_учитывают_только_rx_сигналы_и_своё_имя() {
        let measured = |kind: &str, packets: i32| Signal {
            kind: kind.to_owned(),
            packets,
            ..Signal::default()
        };
        let bound = |transport: u8, enabled: bool| Binding {
            kind: "name".to_owned(),
            target: "example.com".to_owned(),
            transport,
            enabled,
            ..Binding::default()
        };
        let catalog = Catalog {
            boxes: vec![
                BoxRecord {
                    fingerprint: Fingerprint {
                        signals: vec![
                            measured("volume", 19),
                            measured("rx-volume", 0),
                            measured("rx-volume", 32),
                            measured("rx-volume-wire", 44),
                        ],
                        ..Fingerprint::default()
                    },
                    bindings: vec![bound(6, true)],
                    ..BoxRecord::default()
                },
                BoxRecord {
                    fingerprint: Fingerprint {
                        signals: vec![measured("rx-volume-wire", 64)],
                        ..Fingerprint::default()
                    },
                    bindings: vec![bound(17, true)],
                    ..BoxRecord::default()
                },
                BoxRecord {
                    fingerprint: Fingerprint {
                        signals: vec![measured("rx-volume", 48)],
                        ..Fingerprint::default()
                    },
                    bindings: vec![bound(6, false)],
                    ..BoxRecord::default()
                },
            ],
            ..Catalog::default()
        };

        assert_eq!(r2o_tcp_stall_budgets(&catalog), [25, 32, 64, 48]);
        assert!(r2o_tcp_stall_budgets(&Catalog::default()).is_empty());
        assert_eq!(
            r2o_tcp_stall_budgets_for_name(&catalog, "example.com"),
            [32]
        );
        assert!(r2o_tcp_stall_in_name_band(&catalog, "example.com", 29));
        assert!(!r2o_tcp_stall_in_name_band(&catalog, "example.com", 28));
        assert!(r2o_tcp_stall_in_name_band(&catalog, "other.example", 7));
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
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let (reply, response) = mpsc::sync_channel(1);
        let mut catalog = Catalog::default();
        let result = client.service_http_search_command(
            HttpSearchCommand::InstallProbe {
                host: "example.test".to_owned(),
                shape: SHAPE_HTTP,
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
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
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
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: std::collections::HashMap::new(),
            http_challenge_cooldowns: std::collections::HashMap::new(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
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
        use super::{BoundTcpProbe, r2o_run_http_trial_stream};
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

        let (stream, client, _, _) = BoundTcpProbe::open(4, Some(0))
            .unwrap()
            .connect(destination, std::time::Duration::from_secs(6))
            .unwrap();
        let result = r2o_run_http_trial_stream(stream, client, 0, "example.com", b"/").unwrap();
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
    fn discovery_classification_supplies_the_c_white_clienthello() {
        let white = super::r2o_discovery_white_trigger("hcaptcha.com").unwrap();
        assert_eq!(white.name, "white");
        assert_eq!(white.accept, super::Accept::TlsRecord);
        assert_eq!(
            white.payload,
            include_bytes!("../tests/fixtures/r2o-rx-fake-hcaptcha-c.bin")
        );
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
    fn r2o_discovery_keeps_tcp_and_quic_tasks_for_the_same_name_separate() {
        let mut worker = r2o_test_discovery_worker_without_threads();
        let tcp = DiscoveryTarget {
            host: "same.example".into(),
            endpoint: "198.51.100.10:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let quic = DiscoveryTarget {
            host: tcp.host.clone(),
            endpoint: tcp.endpoint.clone(),
            family: tcp.family,
            shape: SHAPE_QUIC,
        };

        assert!(worker.queue(tcp));
        assert!(worker.queue(quic));
        assert_eq!(worker.active.len(), 2);
        assert_eq!(worker.jobs.0.lock().unwrap().entries.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_success_suppresses_other_endpoints_for_same_name_and_transport() {
        let mut worker = r2o_test_discovery_worker_without_threads();
        let first = DiscoveryTarget {
            host: "same.example".into(),
            endpoint: "198.51.100.10:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let second = DiscoveryTarget {
            endpoint: "198.51.100.11:443".into(),
            shape: r2k_core::control::SHAPE_LEGACY,
            ..first.clone()
        };

        assert!(worker.queue(first.clone()));
        worker.jobs.0.lock().unwrap().pop(std::time::Instant::now());
        worker.r2o_complete_outcome(DiscoveryOutcome {
            target: first,
            plan_text: Some("r2o-plan 1 1\\n".into()),
            detail: "план подтверждён".into(),
            queue_expired: false,
            direct_clear: false,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: None,
        });

        assert!(!worker.queue(second.clone()));
        assert_eq!(worker.active.len(), 0);
        assert!(worker.jobs.0.lock().unwrap().entries.is_empty());
        assert!(worker.queue_after_confirmed_failure(second));
        assert_eq!(worker.active.len(), 1);
        assert_eq!(worker.jobs.0.lock().unwrap().entries.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_new_endpoint_reuses_resting_task_slot_at_capacity() {
        let mut worker = r2o_test_discovery_worker_without_threads();
        let now = std::time::Instant::now();
        for index in 0..super::R2O_DISCOVERY_TASK_CAPACITY {
            let failure_key = (
                format!("resting-{index}.example"),
                6,
                4,
                format!("198.51.100.{}:443", index + 1),
            );
            worker.failed_at.insert(failure_key.clone(), now);
            worker
                .failed_retry_after
                .insert(failure_key, super::R2O_DISCOVERY_FAILURE_RETRY);
        }

        let retry = DiscoveryTarget {
            host: "resting-0.example".into(),
            endpoint: "198.51.100.200:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };

        assert!(worker.queue(retry.clone()));
        assert_eq!(
            worker.active.get(&super::r2o_discovery_task_key(&retry)),
            Some(&retry)
        );
        assert_eq!(
            worker.r2o_outstanding_task_count(now),
            super::R2O_DISCOVERY_TASK_CAPACITY
        );
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_queue_matches_donor_capacity() {
        let mut queue = super::R2oDiscoveryQueue::default();
        let now = std::time::Instant::now();
        for index in 0..super::R2O_DISCOVERY_TASK_CAPACITY {
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
        assert_eq!(queue.entries.len(), super::R2O_DISCOVERY_TASK_CAPACITY);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_capacity_includes_running_and_queued_tasks() {
        fn target(host: String) -> DiscoveryTarget {
            DiscoveryTarget {
                host,
                endpoint: "127.0.0.1:443".into(),
                family: 4,
                shape: SHAPE_MODERN,
            }
        }

        let mut worker = r2o_test_discovery_worker_without_threads();
        for index in 0..4 {
            let target = target(format!("running-{index}.example"));
            worker
                .active
                .insert(super::r2o_discovery_task_key(&target), target);
        }
        for index in 0..60 {
            assert!(worker.queue(target(format!("queued-{index}.example"))));
        }
        assert_eq!(worker.active.len(), 64);
        assert_eq!(
            worker
                .jobs
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entries
                .len(),
            60
        );

        assert!(!worker.queue(target("overflow.example".into())));
        assert_eq!(worker.active.len(), 64);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_capacity_includes_deferred_rechecks() {
        fn target(host: String) -> DiscoveryTarget {
            DiscoveryTarget {
                host,
                endpoint: "127.0.0.1:443".into(),
                family: 4,
                shape: SHAPE_MODERN,
            }
        }

        let mut worker = r2o_test_discovery_worker_without_threads();
        for index in 0..63 {
            let target = target(format!("running-{index}.example"));
            worker
                .active
                .insert(super::r2o_discovery_task_key(&target), target);
        }
        let deferred = target("deferred.example".into());
        worker
            .pending_rechecks
            .insert(super::r2o_discovery_task_key(&deferred), (deferred, None));

        assert!(!worker.queue(target("overflow.example".into())));
        assert_eq!(worker.active.len(), 63);
        assert_eq!(worker.pending_rechecks.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_capacity_respects_two_minute_task_rest() {
        fn target(host: String) -> DiscoveryTarget {
            DiscoveryTarget {
                host,
                endpoint: "127.0.0.1:443".into(),
                family: 4,
                shape: SHAPE_MODERN,
            }
        }

        let mut worker = r2o_test_discovery_worker_without_threads();
        for index in 0..63 {
            let target = target(format!("running-{index}.example"));
            worker
                .active
                .insert(super::r2o_discovery_task_key(&target), target);
        }
        let failed = target("resting.example".into());
        let failure_key = super::r2o_discovery_failure_key(&failed);
        r2o_test_record_failed_discovery(
            &mut worker,
            failed,
            std::time::Duration::from_secs(10 * 60),
            true,
        );

        let overflow = target("overflow.example".into());
        assert!(!worker.queue(overflow.clone()));
        worker.failed_at.insert(
            failure_key,
            std::time::Instant::now() - super::R2O_DISCOVERY_TASK_REST,
        );
        assert!(worker.queue(overflow));
        assert_eq!(worker.active.len(), 64);
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
            if waiting > 0 {
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
            if waiting == 0 {
                assert!(worker.threads.iter().all(|thread| !thread.is_finished()));
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
    fn r2o_активный_discovery_перезапускается_по_новому_clienthello() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::sync::{Arc, Mutex, mpsc};
        use std::time::{Duration, Instant};

        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let snapshots = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let runner_snapshots = Arc::clone(&snapshots);
        let attempts = Arc::new(AtomicUsize::new(0));
        let runner_attempts = Arc::clone(&attempts);
        let (started_sender, started_receiver) = mpsc::channel();
        let runner = Arc::new(
            move |target: r2o_controller::discovery::DiscoveryTarget, cancel: Arc<AtomicBool>| {
                let key = super::r2o_discovery_task_key(&target);
                let hello = runner_snapshots.lock().unwrap().remove(&key).unwrap();
                started_sender
                    .send((target.clone(), hello, Arc::clone(&cancel)))
                    .unwrap();
                let attempt = runner_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if attempt == 0 {
                    while !cancel.load(std::sync::atomic::Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                super::DiscoveryOutcome {
                    target,
                    plan_text: Some(
                        if attempt == 0 {
                            "устаревший"
                        } else {
                            "новый"
                        }
                        .into(),
                    ),
                    detail: "проверка завершена".into(),
                    queue_expired: false,
                    direct_clear: false,
                    volume_recovery: false,
                    volume_fingerprint: None,
                    volume_box_id: None,
                    retry_after: None,
                }
            },
        );
        let mut worker = super::DiscoveryWorker::r2o_new_with_runner_and_client_hellos(
            gate,
            runner,
            Arc::clone(&snapshots),
            Arc::new(std::sync::Mutex::new(
                r2o_controller::r2o_resource::R2oResourceMemory::default(),
            )),
        );
        let first_target = r2o_controller::discovery::DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.2:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let latest_target = r2o_controller::discovery::DiscoveryTarget {
            endpoint: "198.51.100.3:443".into(),
            ..first_target.clone()
        };
        let first_hello = r2o_controller::hello::modern_client_hello("example.com").unwrap();
        let mut latest_hello = first_hello.clone();
        latest_hello[11] ^= 1;

        assert!(worker.queue_client_snapshot(first_target.clone(), first_hello.clone()));
        let (started_target, started_hello, cancel) = started_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(started_target, first_target);
        assert_eq!(started_hello, first_hello);
        assert!(worker.queue_client_snapshot(latest_target.clone(), latest_hello.clone()));

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut latest_start = None;
        let mut completed = None;
        while Instant::now() < deadline {
            if let Some(outcome) = worker.try_outcome() {
                completed = Some(outcome);
                break;
            }
            if latest_start.is_none()
                && let Ok(start) = started_receiver.try_recv()
            {
                latest_start = Some(start);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if latest_start.is_none() {
            latest_start = started_receiver.recv_timeout(Duration::from_secs(1)).ok();
        }

        assert!(cancel.load(std::sync::atomic::Ordering::Relaxed));
        let (target, hello, _) = latest_start.expect("перезапуск должен получить свежий снимок");
        assert_eq!(target, latest_target);
        assert_eq!(hello, latest_hello);
        let outcome = completed.expect("перезапуск должен завершиться");
        assert_eq!(outcome.target, latest_target);
        assert_eq!(outcome.plan_text.as_deref(), Some("новый"));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_перезапускает_активный_поиск_после_обновления_каталога() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex, mpsc};
        use std::time::{Duration, Instant};

        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.2:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let client_hello = r2o_controller::hello::modern_client_hello(&target.host).unwrap();
        let key = super::r2o_discovery_task_key(&target);
        let snapshots = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let runner_snapshots = Arc::clone(&snapshots);
        let attempts = Arc::new(AtomicUsize::new(0));
        let runner_attempts = Arc::clone(&attempts);
        let (first_started_sender, first_started_receiver) = mpsc::channel();
        let (second_started_sender, second_started_receiver) = mpsc::channel();
        let runner = Arc::new(
            move |target: r2o_controller::discovery::DiscoveryTarget, cancel: Arc<AtomicBool>| {
                let attempt = runner_attempts.fetch_add(1, Ordering::Relaxed);
                let captured = runner_snapshots.lock().unwrap().get(&key).cloned();
                if attempt == 0 {
                    first_started_sender.send(captured).unwrap();
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while !cancel.load(Ordering::Relaxed) && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    assert!(cancel.load(Ordering::Relaxed));
                } else {
                    second_started_sender
                        .send((captured, cancel.load(Ordering::Relaxed)))
                        .unwrap();
                }
                super::DiscoveryOutcome {
                    target,
                    plan_text: (attempt != 0).then(|| "совместимый план".into()),
                    detail: "проверка завершена".into(),
                    queue_expired: false,
                    direct_clear: false,
                    volume_recovery: false,
                    volume_fingerprint: None,
                    volume_box_id: None,
                    retry_after: None,
                }
            },
        );
        let mut worker = super::DiscoveryWorker::r2o_new_with_runner_and_client_hellos(
            r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1),
            runner,
            snapshots,
            Arc::new(Mutex::new(
                r2o_controller::r2o_resource::R2oResourceMemory::default(),
            )),
        );

        assert!(worker.queue_client_snapshot(target.clone(), client_hello.clone()));
        assert_eq!(
            first_started_receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            Some(client_hello.clone())
        );
        worker.catalog_changed();
        let (refreshed_hello, cancelled) = second_started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("поиск должен перезапуститься с новым поколением каталога");
        assert_eq!(refreshed_hello, Some(client_hello));
        assert!(
            !cancelled,
            "перед повтором отмена каталога должна сбрасываться"
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        let outcome = loop {
            if let Some(outcome) = worker.try_outcome() {
                break outcome;
            }
            assert!(
                Instant::now() < deadline,
                "повторный поиск должен вернуть исход"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(outcome.target, target);
        assert_eq!(outcome.plan_text.as_deref(), Some("совместимый план"));
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_очередь_сохраняет_снятый_clienthello_до_старта_задачи() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let held = gate.r2o_try_acquire().unwrap();
        let runner = Arc::new(
            |target: r2o_controller::discovery::DiscoveryTarget, _cancel: Arc<AtomicBool>| {
                super::DiscoveryOutcome {
                    target,
                    plan_text: None,
                    detail: "проверка завершена".into(),
                    queue_expired: false,
                    direct_clear: false,
                    volume_recovery: false,
                    volume_fingerprint: None,
                    volume_box_id: None,
                    retry_after: None,
                }
            },
        );
        let mut worker = super::DiscoveryWorker::r2o_new_with_runner(gate, runner);
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.2:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let captured = r2o_controller::hello::modern_client_hello("example.com").unwrap();

        assert!(worker.queue_client_snapshot(target.clone(), captured.clone()));
        assert_eq!(
            worker
                .client_hellos
                .lock()
                .unwrap()
                .get(&super::r2o_discovery_task_key(&target)),
            Some(&captured)
        );
        assert!(worker.take_client_snapshot_provenance(&target));
        drop(held);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_повторная_задача_использует_свежий_полный_clienthello() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let held = gate.r2o_try_acquire().unwrap();
        let snapshots = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let runner = Arc::new(
            |target: r2o_controller::discovery::DiscoveryTarget, _cancel: Arc<AtomicBool>| {
                super::DiscoveryOutcome {
                    target,
                    plan_text: None,
                    detail: "проверка завершена".into(),
                    queue_expired: false,
                    direct_clear: false,
                    volume_recovery: false,
                    volume_fingerprint: None,
                    volume_box_id: None,
                    retry_after: None,
                }
            },
        );
        let mut worker = super::DiscoveryWorker::r2o_new_with_runner_and_client_hellos(
            gate,
            runner,
            Arc::clone(&snapshots),
            Arc::new(std::sync::Mutex::new(
                r2o_controller::r2o_resource::R2oResourceMemory::default(),
            )),
        );
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.2:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let captured = r2o_controller::hello::modern_client_hello("example.com").unwrap();

        assert!(worker.remember_client_snapshot(&target, &captured));
        assert!(worker.queue(target.clone()));
        assert_eq!(
            snapshots
                .lock()
                .unwrap()
                .get(&super::r2o_discovery_task_key(&target)),
            Some(&captured)
        );
        drop(held);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_снимок_clienthello_соблюдает_паузы_повтора_discovery() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let held = gate.r2o_try_acquire().unwrap();
        let runner = Arc::new(
            |target: r2o_controller::discovery::DiscoveryTarget, _cancel: Arc<AtomicBool>| {
                super::DiscoveryOutcome {
                    target,
                    plan_text: None,
                    detail: "проверка завершена".into(),
                    queue_expired: false,
                    direct_clear: false,
                    volume_recovery: false,
                    volume_fingerprint: None,
                    volume_box_id: None,
                    retry_after: None,
                }
            },
        );
        let mut worker = super::DiscoveryWorker::r2o_new_with_runner(gate, runner);
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.2:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let failure_key = super::r2o_discovery_failure_key(&target);
        let failed_at = std::time::Instant::now();
        worker.failed_at.insert(failure_key.clone(), failed_at);
        worker
            .failed_retry_after
            .insert(failure_key.clone(), super::R2O_DISCOVERY_FAILURE_RETRY);
        let captured = r2o_controller::hello::modern_client_hello("example.com").unwrap();

        assert!(!worker.queue_client_snapshot(target, captured));
        assert!(worker.client_hellos.lock().unwrap().is_empty());
        assert_eq!(worker.failed_at.get(&failure_key), Some(&failed_at));
        assert_eq!(
            worker.failed_retry_after.get(&failure_key),
            Some(&super::R2O_DISCOVERY_FAILURE_RETRY)
        );
        drop(held);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_запускает_параллельные_задачи_в_пределах_общих_слотов() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Mutex, mpsc};
        use std::time::Duration;

        let (started_sender, started_receiver) = mpsc::channel();
        let runner_release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let worker_release = Arc::clone(&runner_release);
        let runner = Arc::new(
            move |target: r2o_controller::discovery::DiscoveryTarget, _cancel: Arc<AtomicBool>| {
                started_sender.send(target.host.clone()).unwrap();
                let (released, wake) = &*worker_release;
                let released = released
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = wake
                    .wait_timeout_while(released, Duration::from_secs(2), |released| !*released)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                super::DiscoveryOutcome {
                    target,
                    plan_text: Some("план".into()),
                    detail: "завершено".into(),
                    queue_expired: false,
                    direct_clear: false,
                    volume_recovery: false,
                    volume_fingerprint: None,
                    volume_box_id: None,
                    retry_after: None,
                }
            },
        );
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(2);
        let mut worker = super::DiscoveryWorker::r2o_new_with_runner(gate, runner);
        let first = r2o_controller::discovery::DiscoveryTarget {
            host: "first.example".into(),
            endpoint: "127.0.0.1:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let second = r2o_controller::discovery::DiscoveryTarget {
            host: "second.example".into(),
            endpoint: "127.0.0.1:444".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let third = r2o_controller::discovery::DiscoveryTarget {
            host: "third.example".into(),
            endpoint: "127.0.0.1:445".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };

        assert!(worker.queue(first));
        assert!(worker.queue(second));
        assert!(worker.queue(third));
        let first_started = started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("первая задача должна начаться");
        let second_started = match started_receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(host) => host,
            Err(error) => {
                *runner_release
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                runner_release.1.notify_all();
                panic!("вторая задача не стартовала одновременно: {error}");
            }
        };
        assert_ne!(first_started, second_started);
        assert!(
            started_receiver
                .recv_timeout(Duration::from_millis(50))
                .is_err()
        );
        *runner_release
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        runner_release.1.notify_all();
        assert_eq!(
            started_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("очередь должна продолжить работу после освобождения слота"),
            "third.example"
        );
        let mut outcomes = Vec::new();
        for _ in 0..3 {
            outcomes.push(
                worker
                    .outcomes
                    .recv_timeout(Duration::from_secs(2))
                    .expect("обе задачи должны вернуть результат")
                    .target
                    .host
                    .clone(),
            );
        }
        outcomes.sort();
        assert_eq!(
            outcomes,
            ["first.example", "second.example", "third.example"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_ожидающая_задача_не_обходит_первый_тик() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Mutex, mpsc};
        use std::time::{Duration, Instant};

        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel::<()>();
        let release_receiver = Arc::new(Mutex::new(release_receiver));
        let runner_release = Arc::clone(&release_receiver);
        let runner = Arc::new(
            move |target: r2o_controller::discovery::DiscoveryTarget, _cancel: Arc<AtomicBool>| {
                started_sender.send(target.host.clone()).unwrap();
                runner_release
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv()
                    .unwrap();
                super::DiscoveryOutcome {
                    target,
                    plan_text: Some("план".into()),
                    detail: "завершено".into(),
                    queue_expired: false,
                    direct_clear: false,
                    volume_recovery: false,
                    volume_fingerprint: None,
                    volume_box_id: None,
                    retry_after: None,
                }
            },
        );
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::r2o_with_start_gap(2);
        let mut worker = super::DiscoveryWorker::r2o_new_with_runner(gate.clone(), runner);
        let target = |host: &str, port| r2o_controller::discovery::DiscoveryTarget {
            host: host.into(),
            endpoint: format!("127.0.0.1:{port}"),
            family: 4,
            shape: SHAPE_MODERN,
        };

        assert!(worker.queue(target("first.example", 443)));
        assert!(worker.queue(target("second.example", 444)));
        assert!(worker.queue(target("third.example", 445)));
        let mut started = [
            started_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("первая начальная задача должна начаться"),
            started_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("вторая начальная задача должна начаться"),
        ];
        started.sort();
        assert_eq!(started, ["first.example", "second.example"]);

        release_sender.send(()).unwrap();
        release_sender.send(()).unwrap();
        let outcome_deadline = Instant::now() + Duration::from_secs(2);
        let mut completed = 0;
        while completed < 2 {
            if worker.try_outcome().is_some() {
                completed += 1;
            } else {
                assert!(
                    Instant::now() < outcome_deadline,
                    "обе начальные задачи должны завершиться"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        let before_tick = started_receiver.recv_timeout(Duration::from_millis(100));
        if before_tick.is_ok() {
            release_sender.send(()).unwrap();
        }
        assert!(
            matches!(before_tick, Err(mpsc::RecvTimeoutError::Timeout)),
            "уже ожидающая задача не должна стартовать до первого тика"
        );

        let tick_started = Instant::now();
        gate.r2o_scheduler_tick();
        let third_started = started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("ожидающая задача должна продолжиться после первого тика");
        assert_eq!(third_started, "third.example");
        assert!(
            tick_started.elapsed() >= Duration::from_millis(250),
            "после первого тика между выпусками должна пройти пауза 250 мс"
        );
        release_sender.send(()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_свежее_подозрение_соблюдает_паузу_при_занятом_замере() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Mutex, mpsc};
        use std::time::{Duration, Instant};

        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel::<()>();
        let release_receiver = Arc::new(Mutex::new(release_receiver));
        let runner_release = Arc::clone(&release_receiver);
        let runner = Arc::new(
            move |target: r2o_controller::discovery::DiscoveryTarget, _cancel: Arc<AtomicBool>| {
                started_sender
                    .send((target.host.clone(), Instant::now()))
                    .unwrap();
                runner_release
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv()
                    .unwrap();
                super::DiscoveryOutcome {
                    target,
                    plan_text: Some("план".into()),
                    detail: "завершено".into(),
                    queue_expired: false,
                    direct_clear: false,
                    volume_recovery: false,
                    volume_fingerprint: None,
                    volume_box_id: None,
                    retry_after: None,
                }
            },
        );
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::r2o_with_start_gap(2);
        gate.r2o_scheduler_tick();
        let mut worker = super::DiscoveryWorker::r2o_new_with_runner(gate, runner);
        let target = |host: &str, port| r2o_controller::discovery::DiscoveryTarget {
            host: host.into(),
            endpoint: format!("127.0.0.1:{port}"),
            family: 4,
            shape: SHAPE_MODERN,
        };

        assert!(worker.queue(target("running.example", 443)));
        let (started, first_started_at) = started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("первый замер должен начаться");
        assert_eq!(started, "running.example");
        assert!(worker.queue(target("fresh.example", 444)));

        let second_started = started_receiver.recv_timeout(Duration::from_secs(2));
        let _ = release_sender.send(());
        let _ = release_sender.send(());
        let (started, second_started_at) =
            second_started.expect("свежее подозрение должно начать замер после паузы");
        assert_eq!(started, "fresh.example");
        let start_gap = second_started_at.duration_since(first_started_at);
        assert!(
            start_gap >= Duration::from_millis(250),
            "между стартами Discovery должно пройти не менее 250 мс, прошло {} мс",
            start_gap.as_millis()
        );
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_worker_keeps_waiting_targets_promotable() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, mpsc};

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
        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let release_receiver = Arc::new(std::sync::Mutex::new(release_receiver));
        let (finished_sender, finished_receiver) = mpsc::channel();
        let runner_release = Arc::clone(&release_receiver);
        let runner = Arc::new(
            move |target: r2o_controller::discovery::DiscoveryTarget, _cancel: Arc<AtomicBool>| {
                let host = target.host.clone();
                started_sender.send(host.clone()).unwrap();
                runner_release
                    .lock()
                    .unwrap()
                    .recv()
                    .expect("тест должен отпустить Discovery runner");
                finished_sender.send(host).unwrap();
                super::DiscoveryOutcome {
                    target,
                    plan_text: Some("план".into()),
                    detail: "завершено".into(),
                    queue_expired: false,
                    direct_clear: false,
                    volume_recovery: false,
                    volume_fingerprint: None,
                    volume_box_id: None,
                    retry_after: None,
                }
            },
        );
        let mut worker = super::DiscoveryWorker::r2o_new_with_runner(gate, runner);
        let first = target("first.example");
        let second = target("second.example");
        let third = target("third.example");

        assert!(worker.queue(first.clone()));
        assert!(worker.queue(second.clone()));
        assert!(worker.queue(third.clone()));
        let waiting_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let waiting = worker
                .jobs
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .waiting_for_slot;
            if waiting >= 2 {
                break;
            }
            assert!(std::time::Instant::now() < waiting_deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        assert!(worker.queue(first.clone()));
        assert!(worker.queue(third.clone()));
        drop(first_permit);

        assert_eq!(
            started_receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("повышенная цель должна запуститься первой"),
            third.host
        );
        release_sender.send(()).unwrap();
        assert_eq!(
            finished_receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("горячая цель должна освободить worker"),
            third.host
        );

        assert_eq!(
            started_receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("первая старая цель должна запуститься после горячей"),
            first.host
        );
        release_sender.send(()).unwrap();
        assert_eq!(
            finished_receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("первая старая цель должна освободить worker"),
            first.host
        );

        assert_eq!(
            started_receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("последняя цель должна сохранить порядок FIFO"),
            second.host
        );
        release_sender.send(()).unwrap();
        assert_eq!(
            finished_receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("последняя цель должна освободить worker"),
            second.host
        );
        drop(second_permit);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_сливает_endpoint_до_исхода_задачи_имени() {
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let permit = gate.r2o_try_acquire().unwrap();
        let mut worker = super::DiscoveryWorker::new(None, gate);
        let first = r2o_controller::discovery::DiscoveryTarget {
            host: "same.example".into(),
            endpoint: "198.51.100.10:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let mut later_endpoint_and_shape = first.clone();
        later_endpoint_and_shape.endpoint = "198.51.100.11:443".into();
        later_endpoint_and_shape.shape = r2k_core::control::SHAPE_LEGACY;
        assert!(worker.queue(first.clone()));
        let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let waiting = worker
                .jobs
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .waiting_for_slot;
            if waiting > 0 {
                break;
            }
            assert!(std::time::Instant::now() < wait_deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let before_promotion = {
            let queue = worker
                .jobs
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = &queue.entries[0];
            (entry.queued_at, entry.queued_event, entry.hot_event)
        };

        assert!(worker.queue(later_endpoint_and_shape.clone()));
        {
            let (queue, _) = &*worker.jobs;
            let queue = queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(queue.entries.len(), 1);
            assert_eq!(queue.entries[0].target, first);
            assert_eq!(queue.entries[0].target.endpoint, "198.51.100.10:443");
            assert_eq!(queue.entries[0].target.shape, SHAPE_MODERN);
            assert_eq!(queue.entries[0].queued_at, before_promotion.0);
            assert_eq!(queue.entries[0].queued_event, before_promotion.1);
            assert!(queue.entries[0].hot_event > before_promotion.2);
        }

        let selected = worker
            .jobs
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop(std::time::Instant::now())
            .1;
        assert_eq!(selected, Some(first.clone()));
        assert!(!worker.queue(later_endpoint_and_shape.clone()));
        assert!(worker.jobs.0.lock().unwrap().is_empty());

        let completed = super::DiscoveryOutcome {
            target: first.clone(),
            plan_text: None,
            detail: "целевая проверка завершена".into(),
            queue_expired: false,
            direct_clear: false,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: None,
        };
        worker.r2o_complete_outcome(completed);
        assert!(
            worker
                .failed_at
                .contains_key(&super::r2o_discovery_failure_key(&first))
        );
        assert!(worker.queue(later_endpoint_and_shape.clone()));
        let queue = worker
            .jobs
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(queue.entries.len(), 1);
        assert_eq!(queue.entries[0].target, later_endpoint_and_shape);
        drop(queue);
        drop(worker);
        drop(permit);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_discovery_failure_cooldown_ключует_endpoint_без_shape() {
        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let permit = gate.r2o_try_acquire().unwrap();
        let mut worker = super::DiscoveryWorker::new(None, gate);
        let first = r2o_controller::discovery::DiscoveryTarget {
            host: "same.example".into(),
            endpoint: "198.51.100.10:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        worker.seen.insert(first.clone());
        worker.seen_order.push_back(first.clone());
        worker.r2o_complete_outcome(super::DiscoveryOutcome {
            target: first.clone(),
            plan_text: None,
            detail: "ошибка поиска".into(),
            queue_expired: false,
            direct_clear: false,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: None,
        });
        assert!(
            worker
                .failed_at
                .contains_key(&super::r2o_discovery_failure_key(&first))
        );

        let mut same_endpoint_other_shape = first.clone();
        same_endpoint_other_shape.shape = r2k_core::control::SHAPE_LEGACY;
        assert!(!worker.queue(same_endpoint_other_shape));

        let mut another_endpoint = first;
        another_endpoint.endpoint = "198.51.100.11:443".into();
        assert!(worker.queue(another_endpoint));
        drop(worker);
        drop(permit);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_снятый_защитой_rst_снимает_дедупликацию_но_соблюдает_cooldown() {
        use std::time::{Duration, Instant};

        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let permit = gate.r2o_try_acquire().unwrap();
        let mut worker = super::DiscoveryWorker::new(None, gate);
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "rst-cut.example".into(),
            endpoint: "198.51.100.10:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let failure_key = super::r2o_discovery_failure_key(&target);
        let now = Instant::now();
        worker.seen.insert(target.clone());
        worker.seen_order.push_back(target.clone());
        worker.failed_at.insert(failure_key.clone(), now);
        worker
            .failed_retry_after
            .insert(failure_key.clone(), Duration::from_secs(600));

        assert!(!worker.queue_after_fresh_suspect(target.clone()));
        assert!(!worker.seen.contains(&target));
        assert!(worker.failed_at.contains_key(&failure_key));

        worker
            .failed_at
            .insert(failure_key, now - Duration::from_secs(601));
        assert!(worker.queue_after_fresh_suspect(target));
        drop(worker);
        drop(permit);
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
    fn r2o_неубедительный_замер_ждёт_десять_минут_до_повтора() {
        use r2o_controller::classify::Verdict;
        use std::time::Duration;

        let retry_after =
            super::r2o_discovery_retry_after(false, Verdict::Inconclusive, "частичный ответ")
                .expect("неубедительный результат должен задать отдельную паузу");
        assert_eq!(retry_after, Duration::from_secs(10 * 60));
        assert_eq!(
            super::r2o_discovery_retry_after(false, Verdict::Flaky, "база не воспроизводится"),
            Some(Duration::from_secs(10 * 60))
        );
        assert_eq!(
            super::r2o_discovery_retry_after(
                false,
                Verdict::Flaky,
                "замер не состоялся: истёк срок подключения"
            ),
            Some(Duration::ZERO)
        );
        let immediate = std::time::Instant::now();
        assert!(super::r2o_discovery_failure_retry_due_after(
            immediate,
            immediate,
            Duration::ZERO
        ));
        assert_eq!(
            super::r2o_discovery_retry_after(false, Verdict::Unreachable, "нет TCP до цели"),
            Some(Duration::from_secs(10 * 60))
        );
        assert_eq!(
            super::r2o_discovery_retry_after(true, Verdict::Inconclusive, "частичный ответ"),
            Some(super::R2O_DISCOVERY_TASK_LIFETIME)
        );

        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let permit = gate.r2o_try_acquire().unwrap();
        let mut worker = super::DiscoveryWorker::new(None, gate);
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "inconclusive.example".into(),
            endpoint: "198.51.100.10:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        worker.seen.insert(target.clone());
        worker.seen_order.push_back(target.clone());
        worker
            .active
            .insert(super::r2o_discovery_task_key(&target), target.clone());
        worker.r2o_complete_outcome(super::DiscoveryOutcome {
            target: target.clone(),
            plan_text: None,
            detail: "неубедительный прямой замер".into(),
            queue_expired: false,
            direct_clear: false,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: Some(retry_after),
        });
        assert!(!worker.queue(target.clone()));

        let failure_key = super::r2o_discovery_failure_key(&target);
        worker.failed_at.insert(
            failure_key.clone(),
            std::time::Instant::now() - Duration::from_secs(599),
        );
        assert!(!worker.queue(target.clone()));
        worker
            .failed_at
            .insert(failure_key, std::time::Instant::now() - retry_after);
        assert!(worker.queue(target.clone()));
        drop(worker);
        drop(permit);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_прямой_clear_увеличивает_отсрочку_десять_тридцать_шестьдесят_минут() {
        use std::time::Duration;

        let gate = r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1);
        let permit = gate.r2o_try_acquire().unwrap();
        let mut worker = super::DiscoveryWorker::new(None, gate);
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "clear-backoff.example".into(),
            endpoint: "198.51.100.10:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        worker.seen.insert(target.clone());
        worker.seen_order.push_back(target.clone());

        for (streak, minutes) in [(1, 10), (2, 30), (3, 60)] {
            let outcome = worker.r2o_complete_outcome(super::DiscoveryOutcome {
                target: target.clone(),
                plan_text: None,
                detail: "прямой CLEAR".into(),
                queue_expired: false,
                direct_clear: true,
                volume_recovery: false,
                volume_fingerprint: None,
                volume_box_id: None,
                retry_after: Some(Duration::from_secs(10 * 60)),
            });
            let expected = Duration::from_secs(minutes * 60);
            assert_eq!(outcome.retry_after, Some(expected));
            assert_eq!(
                worker
                    .clear_streaks
                    .get(&super::r2o_discovery_failure_key(&target)),
                Some(&streak)
            );
            assert_eq!(
                worker
                    .failed_retry_after
                    .get(&super::r2o_discovery_failure_key(&target)),
                Some(&expected)
            );
        }

        drop(worker);
        drop(permit);
    }

    #[cfg(unix)]
    #[test]
    fn r2o_таймаут_активного_поиска_освобождает_цель_для_нового_поколения() {
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "retry.example".into(),
            endpoint: "invalid-endpoint".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let mut worker = super::DiscoveryWorker::new(
            None,
            r2o_controller::r2o_resource_limit::R2oMeasurementGate::new(1),
        );
        worker.seen.insert(target.clone());
        worker.seen_order.push_back(target.clone());
        worker
            .active
            .insert(super::r2o_discovery_task_key(&target), target.clone());
        let outcome = super::DiscoveryOutcome {
            target: target.clone(),
            plan_text: None,
            detail: "активный поиск превысил срок жизни".into(),
            queue_expired: false,
            direct_clear: false,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: Some(super::R2O_DISCOVERY_TASK_LIFETIME),
        };

        let finished = worker.r2o_complete_outcome(outcome);

        assert!(finished.plan_text.is_none());
        assert!(!worker.is_active(&target));
        assert!(worker.seen.contains(&target));
        assert!(!worker.queue(target.clone()));
        let failure_key = super::r2o_discovery_failure_key(&target);
        assert_eq!(
            worker.failed_retry_after.get(&failure_key),
            Some(&super::R2O_DISCOVERY_TASK_LIFETIME)
        );
        let now = std::time::Instant::now();
        worker.failed_at.insert(
            failure_key.clone(),
            now - std::time::Duration::from_secs(599),
        );
        assert!(!worker.queue(target.clone()));
        worker.failed_at.insert(
            failure_key,
            std::time::Instant::now() - std::time::Duration::from_secs(600),
        );
        assert!(worker.queue(target.clone()));
        assert!(worker.is_active(&target));
    }

    #[cfg(unix)]
    #[test]
    fn r2o_активный_поиск_отменяется_по_сроку_жизни() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        let worker_cancel = std::sync::Arc::new(AtomicBool::new(false));
        let (cancelled, expired) = super::r2o_run_with_deadline(
            std::sync::Arc::clone(&worker_cancel),
            Duration::from_millis(20),
            |task_cancel| {
                let limit = Instant::now() + Duration::from_secs(1);
                while !task_cancel.load(Ordering::Relaxed) && Instant::now() < limit {
                    std::thread::sleep(Duration::from_millis(1));
                }
                task_cancel.load(Ordering::Relaxed)
            },
        );

        assert!(cancelled);
        assert!(expired);
    }

    #[cfg(unix)]
    #[test]
    fn остановка_контроллера_прерывает_поиск_без_метки_таймаута() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        let worker_cancel = std::sync::Arc::new(AtomicBool::new(false));
        let cancel_signal = std::sync::Arc::clone(&worker_cancel);
        let cancel_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            cancel_signal.store(true, Ordering::Relaxed);
        });
        let (cancelled, expired) = super::r2o_run_with_deadline(
            std::sync::Arc::clone(&worker_cancel),
            Duration::from_secs(1),
            |task_cancel| {
                let limit = Instant::now() + Duration::from_secs(2);
                while !task_cancel.load(Ordering::Relaxed) && Instant::now() < limit {
                    std::thread::sleep(Duration::from_millis(1));
                }
                task_cancel.load(Ordering::Relaxed)
            },
        );
        cancel_thread.join().unwrap();

        assert!(cancelled);
        assert!(!expired);
    }

    #[cfg(unix)]
    #[test]
    fn прямой_clear_сохраняет_пометку_и_удаляет_только_свою_форму_из_runtime() {
        let work = std::env::temp_dir().join(format!(
            "r2o-direct-clear-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&work).unwrap();
        let catalog_path = work.join("catalog.json");
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "clear.example".into(),
            endpoint: "198.51.100.80:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                created: 100,
                updated: 100,
                bindings: vec![
                    Binding {
                        kind: "name".into(),
                        target: target.host.clone(),
                        plan_id: "11".repeat(16),
                        enabled: true,
                        transport: 6,
                        family: 4,
                        shape: SHAPE_MODERN,
                        ..Binding::default()
                    },
                    Binding {
                        kind: "name".into(),
                        target: target.host.clone(),
                        plan_id: "22".repeat(16),
                        enabled: false,
                        transport: 6,
                        family: 4,
                        shape: r2k_core::control::SHAPE_LEGACY,
                        ..Binding::default()
                    },
                ],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        catalog.save_atomic(&catalog_path, 100).unwrap();

        let (client_stream, mut server_stream) = std::os::unix::net::UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let command = read_frame(&mut server_stream).unwrap();
            server_stream
                .write_all(&encode_ack(command.kind, true, 0).unwrap())
                .unwrap();
            command
        });
        let mut client = ControlClient {
            socket: client_stream,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: Default::default(),
            http_challenge_cooldowns: Default::default(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let outcome = DiscoveryOutcome {
            target: target.clone(),
            plan_text: None,
            detail: "цель напрямую проходит".into(),
            queue_expired: false,
            direct_clear: true,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: None,
        };

        client
            .apply_discovery_outcome(outcome, &mut catalog, &catalog_path)
            .unwrap();

        let deleted = server.join().unwrap();
        assert_eq!(deleted.kind, r2k_core::control::COMMAND_DEL_NAME);
        assert_eq!(
            deleted.body,
            super::encode_delete_name(&target.host, 6, SHAPE_MODERN, 4).unwrap()[6..]
        );
        assert!(catalog.boxes[0].bindings[0].recheck_since.is_some());
        assert!(catalog.boxes[0].bindings[0].recheck_mono.is_some());
        assert!(catalog.boxes[0].bindings[1].recheck_since.is_none());
        assert!(catalog_commands(&catalog).unwrap().commands.is_empty());
        let saved = std::fs::read_to_string(&catalog_path).unwrap();
        assert!(saved.contains("recheck_since"));
        assert!(!saved.contains("recheck_mono"));

        std::fs::remove_dir_all(work).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn прямой_clear_оставляет_пометку_если_runtime_не_подтвердил_удаление() {
        let work = std::env::temp_dir().join(format!(
            "r2o-direct-clear-rejected-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&work).unwrap();
        let catalog_path = work.join("catalog.json");
        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "clear-rejected.example".into(),
            endpoint: "198.51.100.81:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let mut catalog = Catalog {
            boxes: vec![BoxRecord {
                bindings: vec![Binding {
                    kind: "name".into(),
                    target: target.host.clone(),
                    plan_id: "33".repeat(16),
                    enabled: true,
                    transport: 6,
                    family: 4,
                    shape: SHAPE_MODERN,
                    ..Binding::default()
                }],
                ..BoxRecord::default()
            }],
            ..Catalog::default()
        };
        catalog.save_atomic(&catalog_path, 100).unwrap();

        let (client_stream, mut server_stream) = std::os::unix::net::UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let command = read_frame(&mut server_stream).unwrap();
            server_stream
                .write_all(&encode_ack(command.kind, false, 1).unwrap())
                .unwrap();
            command
        });
        let mut client = ControlClient {
            socket: client_stream,
            send_maxlen: 0,
            send_cap: Arc::new(AtomicUsize::new(0)),
            pending_events: VecDeque::new(),
            pending_applied_events: VecDeque::new(),
            http_search_started: Default::default(),
            http_challenge_cooldowns: Default::default(),
            http_acknowledged_bindings: std::collections::HashMap::new(),
        };
        let outcome = DiscoveryOutcome {
            target: target.clone(),
            plan_text: None,
            detail: "цель напрямую проходит".into(),
            queue_expired: false,
            direct_clear: true,
            volume_recovery: false,
            volume_fingerprint: None,
            volume_box_id: None,
            retry_after: None,
        };

        assert!(
            client
                .apply_discovery_outcome(outcome, &mut catalog, &catalog_path)
                .is_err()
        );
        assert_eq!(
            server.join().unwrap().kind,
            r2k_core::control::COMMAND_DEL_NAME
        );
        assert!(catalog.boxes[0].bindings[0].recheck_since.is_some());
        assert!(catalog_commands(&catalog).unwrap().commands.is_empty());
        assert!(
            Catalog::load(&catalog_path).unwrap().boxes[0].bindings[0]
                .recheck_since
                .is_some()
        );

        std::fs::remove_dir_all(work).unwrap();
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
                if accept {
                    let budgets = read_frame(&mut stream).unwrap();
                    assert_eq!(budgets.kind, COMMAND_SET_TCP_STALL_BUDGETS);
                    assert_eq!(budgets.body, [2, 0, 25, 0, 32]);
                    stream
                        .write_all(&encode_ack(budgets.kind, true, 0).unwrap())
                        .unwrap();
                }
                if !accept {
                    for _ in 0..2 {
                        let clear = read_frame(&mut stream).unwrap();
                        assert_eq!(clear.kind, super::COMMAND_CLEAR);
                        assert!(clear.body.is_empty());
                        stream
                            .write_all(&encode_ack(clear.kind, true, 0).unwrap())
                            .unwrap();
                    }
                    let budgets = read_frame(&mut stream).unwrap();
                    assert_eq!(budgets.kind, COMMAND_SET_TCP_STALL_BUDGETS);
                    assert_eq!(budgets.body, [2, 0, 25, 0, 32]);
                    stream
                        .write_all(&encode_ack(budgets.kind, true, 0).unwrap())
                        .unwrap();
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
            let mut catalog = Catalog {
                boxes: vec![BoxRecord {
                    fingerprint: Fingerprint {
                        signals: vec![Signal {
                            kind: "rx-volume".into(),
                            packets: 32,
                            ..Signal::default()
                        }],
                        ..Fingerprint::default()
                    },
                    ..BoxRecord::default()
                }],
                ..Catalog::default()
            };
            let outcome = DiscoveryOutcome {
                target: target.clone(),
                plan_text: Some(plan_text),
                detail: "test".into(),
                queue_expired: false,
                direct_clear: false,
                volume_recovery: false,
                volume_fingerprint: None,
                volume_box_id: None,
                retry_after: None,
            };
            let outcome =
                super::r2o_confirm_discovery_outcome(outcome, Ok(r2o_test_fetch_result()), true);
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
        assert_eq!(
            saved
                .boxes
                .iter()
                .flat_map(|box_record| &box_record.bindings)
                .find(|binding| binding.kind == "name" && binding.target == "example.com")
                .unwrap()
                .level,
            3
        );
        let name_len = usize::from(body[0]);
        assert_eq!(&body[1..1 + name_len], b"example.com");
        assert_eq!(body[1 + name_len], SHAPE_MODERN);
        assert_eq!(Plan::parse(&body[3 + name_len..]).unwrap().proto, 1);

        let (accepted, saved, _) = run_case(false);
        assert!(!accepted);
        assert_eq!(saved.boxes.len(), 1);
        assert_eq!(saved.boxes[0].fingerprint.signals[0].packets, 32);
        assert!(!r2o_controller::discovery::has_usable_binding(
            &saved,
            &r2o_controller::discovery::DiscoveryTarget {
                host: "example.com".into(),
                endpoint: "127.0.0.1:443".into(),
                family: 4,
                shape: SHAPE_MODERN,
            }
        ));
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
            proof: r2k_core::control::R2oVoiceProofKind::DiscordDiscovery {
                mapped_ip: "203.0.113.9".parse().unwrap(),
                mapped_port: 52_321,
            },
        };
        assert!(r2o_voice_proof_matches_target(&proof, target));

        proof.key[35..37].copy_from_slice(&50_005_u16.to_be_bytes());
        assert!(!r2o_voice_proof_matches_target(&proof, target));
    }

    #[cfg(unix)]
    #[test]
    fn discord_voice_после_continue_запускает_live_flow_fallback() {
        use r2o_controller::voice_discovery::{
            R2oDiscoverySearchResult, R2oDiscoveryTrace, R2oDiscoveryVerdict,
        };
        use std::net::Ipv4Addr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let flow = r2o_controller::voice_targets::R2oVoiceTarget {
            server_ip: Ipv4Addr::new(198, 51, 100, 20),
            server_port: 50_004,
            client_ip: Ipv4Addr::new(192, 0, 2, 10),
            client_port: 51_234,
            packets: 12,
            replied: false,
        };
        let mut discovery = R2oDiscoverySearchResult {
            trace: R2oDiscoveryTrace {
                known_prefix: None,
                known_prefix_probe: None,
                direct_probes: Vec::new(),
                candidate_prefix: None,
                candidate_probes: Vec::new(),
            },
            verdict: R2oDiscoveryVerdict::Continue,
            error: None,
        };
        let calls = AtomicUsize::new(0);
        let fallback = super::r2o_voice_fallback_after_discovery(&discovery, Some(flow), |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            r2o_controller::voice_measure::R2oVoiceMeasurement {
                verdict: r2o_controller::voice_measure::R2oVoiceVerdict::Blocked,
                reason: "target STUN silent; public control answers".into(),
                address: Some("198.51.100.20:50004".parse().unwrap()),
                probes: 6,
                marked: true,
                discovery_verified: false,
                arm: None,
            }
        });
        assert_eq!(
            fallback.map(|result| result.verdict),
            Some(r2o_controller::voice_measure::R2oVoiceVerdict::Blocked)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        discovery.verdict = R2oDiscoveryVerdict::Clear;
        assert!(
            super::r2o_voice_fallback_after_discovery(&discovery, Some(flow), |_| {
                calls.fetch_add(1, Ordering::Relaxed);
                unreachable!("CLEAR уже завершает измерение")
            })
            .is_none()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
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
            5,
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
    fn каталог_не_устанавливает_старые_voice_привязки_без_rtp() {
        let prefix = r2k_core::stun::binding_request([0x94; 12]);
        let text = r2o_controller::voice_discovery::r2o_voice_arm_plan_text(&prefix);

        for verified_by in [3, 4] {
            let mut catalog = Catalog::default();
            r2o_controller::voice_discovery::r2o_save_confirmed_voice_binding(
                &mut catalog,
                "198.51.100.21".parse().unwrap(),
                &text,
                1_800_000_001,
                5,
            )
            .unwrap();
            catalog.boxes[0].bindings[0].verified_by = verified_by;

            let compiled = catalog_commands(&catalog).unwrap();
            assert!(compiled.commands.is_empty());
            assert_eq!(compiled.skipped, 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn r2o_установка_voice_опыта_проверяет_ack_и_trial_id() {
        use std::os::unix::net::UnixStream;

        let install = |ack_ok, ack_reason, mismatched_trial_id| {
            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                let command = read_frame(&mut server_stream).unwrap();
                assert_eq!(command.kind, super::COMMAND_SET_VOICE_ADDR_PROBE);
                let trial_id: [u8; 16] =
                    command.body[command.body.len() - 16..].try_into().unwrap();
                let mut ack_trial_id = trial_id;
                if mismatched_trial_id {
                    ack_trial_id[0] ^= 1;
                }
                server_stream
                    .write_all(
                        &encode_ack_for_trial(command.kind, ack_ok, ack_reason, Some(ack_trial_id))
                            .unwrap(),
                    )
                    .unwrap();
                if !ack_ok || mismatched_trial_id {
                    let delete = read_frame(&mut server_stream).unwrap();
                    assert_eq!(delete.kind, COMMAND_DEL_VOICE_ADDR_PROBE);
                    assert_eq!(&delete.body[delete.body.len() - 16..], &trial_id);
                    server_stream
                        .write_all(
                            &encode_ack_for_trial(delete.kind, true, 0, Some(trial_id)).unwrap(),
                        )
                        .unwrap();
                }
            });
            let mut client = ControlClient {
                socket: client_stream,
                send_maxlen: 0,
                send_cap: Arc::new(AtomicUsize::new(0)),
                pending_events: VecDeque::new(),
                pending_applied_events: VecDeque::new(),
                http_search_started: Default::default(),
                http_challenge_cooldowns: Default::default(),
                http_acknowledged_bindings: std::collections::HashMap::new(),
            };
            let target = r2o_controller::voice_discovery::R2oVoiceTarget {
                client: "192.0.2.10".parse().unwrap(),
                server: "198.51.100.20:50004".parse().unwrap(),
            };
            let prefix = r2k_core::stun::binding_request([0x36; 12]);
            let plan_text = r2o_controller::voice_discovery::r2o_voice_arm_plan_text(&prefix);
            let result =
                client.install_r2o_voice_trial(target, plan_text, std::time::Instant::now());
            server.join().unwrap();
            result
        };

        assert!(
            matches!(
                install(true, 0, true).unwrap(),
                super::R2oVoiceTrialInstallOutcome::NotInstalled
            ),
            "чужой trial ID принят за подтверждение опыта"
        );
        assert!(
            matches!(
                install(false, r2k_core::control::ACK_NO_ROOM, false).unwrap(),
                super::R2oVoiceTrialInstallOutcome::LocalRefusal
            ),
            "локальный отказ датапата превратился в установленный опыт"
        );
        assert!(
            matches!(
                install(true, 0, false).unwrap(),
                super::R2oVoiceTrialInstallOutcome::Installed(_)
            ),
            "точное успешное подтверждение отклонено"
        );

        for (ack_ok, matching_trial_id) in [(true, false), (false, true)] {
            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                let delete = read_frame(&mut server_stream).unwrap();
                assert_eq!(delete.kind, COMMAND_DEL_VOICE_ADDR_PROBE);
                let trial_id: [u8; 16] = delete.body[delete.body.len() - 16..].try_into().unwrap();
                let mut ack_trial_id = trial_id;
                if !matching_trial_id {
                    ack_trial_id[0] ^= 1;
                }
                server_stream
                    .write_all(
                        &encode_ack_for_trial(delete.kind, ack_ok, 0, Some(ack_trial_id)).unwrap(),
                    )
                    .unwrap();
            });
            let mut client = ControlClient {
                socket: client_stream,
                send_maxlen: 0,
                send_cap: Arc::new(AtomicUsize::new(0)),
                pending_events: VecDeque::new(),
                pending_applied_events: VecDeque::new(),
                http_search_started: Default::default(),
                http_challenge_cooldowns: Default::default(),
                http_acknowledged_bindings: std::collections::HashMap::new(),
            };
            let trial = R2oVoiceTrialContext {
                target: r2o_controller::voice_discovery::R2oVoiceTarget {
                    client: "192.0.2.10".parse().unwrap(),
                    server: "198.51.100.20:50004".parse().unwrap(),
                },
                trial_id: [0x42; 16],
                plan_text: String::new(),
                voice_flow_key: None,
                started_at: std::time::Instant::now() - std::time::Duration::from_secs(599),
                renew_at: std::time::Instant::now() + std::time::Duration::from_secs(60),
                expires_at: std::time::Instant::now() + std::time::Duration::from_secs(1),
                response_confirmed: false,
            };
            let result = client.retire_r2o_voice_trial(&trial);
            server.join().unwrap();
            assert_eq!(
                result.is_ok(),
                ack_ok && matching_trial_id,
                "удаление должно требовать успешный ACK с точным trial ID"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn r2o_voice_discovery_снимает_пробу_при_точном_nak_продления() {
        use super::{
            R2O_VOICE_TRIAL_RENEW_INTERVAL, R2O_VOICE_TRIAL_TASK_LIFETIME, R2oVoiceTrialContext,
            r2o_take_due_voice_trial_renewals, r2o_take_expired_voice_trials,
        };
        use std::collections::HashMap;
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        use std::time::Instant;

        let r2o_started_at = Instant::now();
        let r2o_trial_id = [0x42; 16];
        let r2o_target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: "192.0.2.10".parse().unwrap(),
            server: "198.51.100.20:50004".parse().unwrap(),
        };
        let r2o_prefix = r2k_core::stun::binding_request([0x36; 12]);
        let r2o_plan_text = r2o_controller::voice_discovery::r2o_voice_arm_plan_text(&r2o_prefix);
        let r2o_trial = R2oVoiceTrialContext {
            target: r2o_target,
            trial_id: r2o_trial_id,
            plan_text: r2o_plan_text.clone(),
            voice_flow_key: None,
            started_at: r2o_started_at,
            renew_at: r2o_started_at + R2O_VOICE_TRIAL_RENEW_INTERVAL,
            expires_at: r2o_started_at + R2O_VOICE_TRIAL_TASK_LIFETIME,
            response_confirmed: false,
        };
        assert!(super::r2o_voice_target_has_active_trial(
            &HashMap::from([(r2o_trial_id, r2o_trial.clone())]),
            &r2o_target
        ));
        let r2o_other_target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: "192.0.2.11".parse().unwrap(),
            server: "198.51.100.20:50004".parse().unwrap(),
        };
        assert!(!super::r2o_voice_target_has_active_trial(
            &HashMap::from([(r2o_trial_id, r2o_trial.clone())]),
            &r2o_other_target
        ));
        let mut r2o_trials = HashMap::from([(r2o_trial_id, r2o_trial)]);

        assert!(
            r2o_take_due_voice_trial_renewals(
                &mut r2o_trials,
                r2o_started_at + std::time::Duration::from_secs(59),
            )
            .is_empty()
        );
        let r2o_due = r2o_take_due_voice_trial_renewals(
            &mut r2o_trials,
            r2o_started_at + R2O_VOICE_TRIAL_RENEW_INTERVAL,
        );
        assert_eq!(r2o_due.len(), 1);
        assert_eq!(r2o_due[0].trial_id, r2o_trial_id);
        assert_eq!(
            r2o_trials[&r2o_trial_id].renew_at,
            r2o_started_at + R2O_VOICE_TRIAL_RENEW_INTERVAL * 2
        );
        assert!(
            r2o_take_due_voice_trial_renewals(
                &mut r2o_trials,
                r2o_started_at + R2O_VOICE_TRIAL_RENEW_INTERVAL * 2
                    - std::time::Duration::from_secs(1),
            )
            .is_empty()
        );
        assert_eq!(
            r2o_take_due_voice_trial_renewals(
                &mut r2o_trials,
                r2o_started_at + R2O_VOICE_TRIAL_RENEW_INTERVAL * 2,
            )
            .len(),
            1
        );
        assert_eq!(
            r2o_take_expired_voice_trials(
                &mut r2o_trials,
                r2o_started_at + R2O_VOICE_TRIAL_TASK_LIFETIME,
            )
            .len(),
            1
        );

        let renew = |ack_ok: bool, matching_trial_id: bool| {
            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let plan_records = super::compile_text(&r2o_plan_text).unwrap();
            let expected = super::encode_set_voice_addr_probe(
                r2o_target.client,
                r2o_target.server,
                super::VOICE_ADDR_PROBE_LEASE_MAX_MS,
                &plan_records,
                r2o_trial_id,
            )
            .unwrap();
            let expected = read_frame(&mut std::io::Cursor::new(expected.as_slice())).unwrap();
            let expected_delete = super::encode_delete_voice_addr_probe(
                r2o_target.client,
                r2o_target.server,
                r2o_trial_id,
            )
            .unwrap();
            let expected_delete =
                read_frame(&mut std::io::Cursor::new(expected_delete.as_slice())).unwrap();
            let server = std::thread::spawn(move || {
                let command = read_frame(&mut server_stream).unwrap();
                assert_eq!(command.kind, super::COMMAND_SET_VOICE_ADDR_PROBE);
                assert_eq!(command.body, expected.body);
                let mut ack_trial_id = r2o_trial_id;
                if !matching_trial_id {
                    ack_trial_id[0] ^= 1;
                }
                server_stream
                    .write_all(
                        &encode_ack_for_trial(
                            command.kind,
                            ack_ok,
                            r2k_core::control::ACK_NO_ROOM,
                            Some(ack_trial_id),
                        )
                        .unwrap(),
                    )
                    .unwrap();
                if !ack_ok && matching_trial_id {
                    server_stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                        .unwrap();
                    let delete = read_frame(&mut server_stream).unwrap();
                    assert_eq!(delete.kind, super::COMMAND_DEL_VOICE_ADDR_PROBE);
                    assert_eq!(delete.body, expected_delete.body);
                    server_stream
                        .write_all(
                            &encode_ack_for_trial(delete.kind, true, 0, Some(r2o_trial_id))
                                .unwrap(),
                        )
                        .unwrap();
                } else {
                    server_stream
                        .set_read_timeout(Some(std::time::Duration::from_millis(50)))
                        .unwrap();
                    let mut unexpected_command = [0; 1];
                    assert!(matches!(
                        server_stream.read(&mut unexpected_command),
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            )
                    ));
                }
            });
            let mut client = ControlClient {
                socket: client_stream,
                send_maxlen: 0,
                send_cap: Arc::new(AtomicUsize::new(0)),
                pending_events: VecDeque::new(),
                pending_applied_events: VecDeque::new(),
                http_search_started: Default::default(),
                http_challenge_cooldowns: Default::default(),
                http_acknowledged_bindings: std::collections::HashMap::new(),
            };
            let r2o_now = r2o_started_at + R2O_VOICE_TRIAL_RENEW_INTERVAL;
            let mut trials = HashMap::from([
                (
                    r2o_trial_id,
                    R2oVoiceTrialContext {
                        target: r2o_target,
                        trial_id: r2o_trial_id,
                        plan_text: r2o_plan_text.clone(),
                        voice_flow_key: None,
                        started_at: r2o_started_at,
                        renew_at: r2o_started_at,
                        expires_at: r2o_started_at + R2O_VOICE_TRIAL_TASK_LIFETIME,
                        response_confirmed: false,
                    },
                ),
                (
                    [0x43; 16],
                    R2oVoiceTrialContext {
                        target: r2o_other_target,
                        trial_id: [0x43; 16],
                        plan_text: r2o_plan_text.clone(),
                        voice_flow_key: None,
                        started_at: r2o_started_at,
                        renew_at: r2o_started_at + R2O_VOICE_TRIAL_RENEW_INTERVAL * 2,
                        expires_at: r2o_started_at + R2O_VOICE_TRIAL_TASK_LIFETIME,
                        response_confirmed: false,
                    },
                ),
            ]);

            client.renew_due_r2o_voice_trials(&mut trials, r2o_now);
            server.join().unwrap();
            (trials, r2o_now)
        };

        for (ack_ok, matching_trial_id, retained) in [
            (true, true, true),
            (false, true, false),
            (true, false, true),
        ] {
            let (trials, r2o_now) = renew(ack_ok, matching_trial_id);
            assert_eq!(trials.contains_key(&r2o_trial_id), retained);
            assert!(trials.contains_key(&[0x43; 16]), "соседняя проба сохранена");
            assert_eq!(
                super::r2o_voice_target_has_active_trial(&trials, &r2o_target),
                retained
            );
            if retained {
                assert_eq!(
                    trials[&r2o_trial_id].renew_at,
                    r2o_now + R2O_VOICE_TRIAL_RENEW_INTERVAL
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn неснятая_voice_проба_остаётся_учтённой_до_арендного_срока_без_продления() {
        use super::{
            R2O_VOICE_TRIAL_TASK_LIFETIME, R2oVoiceTrialContext, r2o_hold_voice_trial_until_expiry,
            r2o_take_due_voice_trial_renewals, r2o_take_expired_voice_trials,
            r2o_voice_target_has_active_trial,
        };
        use r2k_core::control::KEY_LEN;
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

        let now = Instant::now();
        let trial_id = [0x42; 16];
        let target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: "192.0.2.10".parse().unwrap(),
            server: "198.51.100.20:50004".parse().unwrap(),
        };
        let mut trial = R2oVoiceTrialContext {
            target,
            trial_id,
            plan_text: String::new(),
            voice_flow_key: Some([0x55; KEY_LEN]),
            started_at: now,
            renew_at: now + Duration::from_secs(60),
            expires_at: now + R2O_VOICE_TRIAL_TASK_LIFETIME,
            response_confirmed: false,
        };
        r2o_hold_voice_trial_until_expiry(&mut trial);
        let expires_at = trial.expires_at;
        let mut trials = HashMap::from([(trial_id, trial)]);

        assert!(r2o_voice_target_has_active_trial(&trials, &target));
        assert!(trials[&trial_id].voice_flow_key.is_none());
        assert!(
            r2o_take_due_voice_trial_renewals(&mut trials, expires_at - Duration::from_nanos(1),)
                .is_empty()
        );
        assert_eq!(
            r2o_take_expired_voice_trials(&mut trials, expires_at).len(),
            1
        );
        assert!(trials.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn r2o_voice_watch_связывает_applied_с_точным_потоком_пробы() {
        use super::{
            R2oVoiceTrialContext, r2o_take_silent_voice_trial, r2o_voice_applied_flow_matches,
        };
        use r2k_core::control::{AppliedEvent, BindingContext, KEY_LEN, SHAPE_VOICE};
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

        let target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: "192.0.2.10".parse().unwrap(),
            server: "198.51.100.20:50004".parse().unwrap(),
        };
        let trial_id = [0x42; 16];
        let prefix = r2k_core::stun::binding_request([0x36; 12]);
        let plan_text = r2o_controller::voice_discovery::r2o_voice_arm_plan_text(&prefix);
        let plan_id = r2o_controller::voice_discovery::r2o_voice_arm_plan(&prefix)
            .unwrap()
            .id;
        let now = Instant::now();
        let trial = R2oVoiceTrialContext {
            target,
            trial_id,
            plan_text,
            voice_flow_key: None,
            started_at: now,
            renew_at: now + Duration::from_secs(60),
            expires_at: now + Duration::from_secs(600),
            response_confirmed: false,
        };
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 20]);
        key[33..35].copy_from_slice(&51_234_u16.to_be_bytes());
        key[35..37].copy_from_slice(&50_004_u16.to_be_bytes());
        key[37] = 17;
        let applied = AppliedEvent {
            key,
            plan_id,
            trial_id,
            execution_id: 7,
            binding: BindingContext {
                generation: 1,
                kind: 2,
                family: 4,
                shape: SHAPE_VOICE,
                temporary: true,
                epoch: [1; 16],
            },
        };

        assert!(r2o_voice_applied_flow_matches(&trial, &applied));
        let mut wrong_plan = applied.clone();
        wrong_plan.plan_id[0] ^= 1;
        assert!(!r2o_voice_applied_flow_matches(&trial, &wrong_plan));
        let mut wrong_server = applied.clone();
        wrong_server.key[35..37].copy_from_slice(&50_005_u16.to_be_bytes());
        assert!(!r2o_voice_applied_flow_matches(&trial, &wrong_server));
        let mut permanent = applied.clone();
        permanent.binding.temporary = false;
        assert!(!r2o_voice_applied_flow_matches(&trial, &permanent));

        let trial = R2oVoiceTrialContext {
            voice_flow_key: Some(applied.key),
            ..trial
        };
        let mut trials = HashMap::from([(trial_id, trial)]);
        let mut other_flow = applied.key;
        other_flow[33..35].copy_from_slice(&51_235_u16.to_be_bytes());
        assert!(r2o_take_silent_voice_trial(&mut trials, &other_flow, &target).is_none());
        assert!(trials.contains_key(&trial_id));
        let other_target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: "192.0.2.11".parse().unwrap(),
            server: target.server,
        };
        assert!(r2o_take_silent_voice_trial(&mut trials, &applied.key, &other_target).is_none());
        assert!(trials.contains_key(&trial_id));
        assert_eq!(
            r2o_take_silent_voice_trial(&mut trials, &applied.key, &target)
                .unwrap()
                .trial_id,
            trial_id
        );
        assert!(trials.is_empty());
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
            voice_flow_key: None,
            started_at: std::time::Instant::now(),
            renew_at: std::time::Instant::now() + std::time::Duration::from_secs(60),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(600),
            response_confirmed: true,
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
            proof: r2k_core::control::R2oVoiceProofKind::RtpMedia {
                outbound_packets: 3,
                inbound_packets: 3,
            },
        };
        let mut client = ControlClient::connect(socket_path).unwrap();
        let mut catalog = Catalog::load(&catalog_path).unwrap();
        let mut unconfirmed_trial = trial.clone();
        unconfirmed_trial.response_confirmed = false;
        assert!(
            client
                .confirm_r2o_voice_trial(unconfirmed_trial, &proof, &mut catalog, &catalog_path,)
                .is_err()
        );
        assert!(catalog.boxes.is_empty());
        assert!(Catalog::load(&catalog_path).unwrap().boxes.is_empty());

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
        assert_eq!(saved.boxes[0].bindings[0].verified_by, 5);
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
        let r2o_failure_at = r2o_now + Duration::from_secs(30);
        r2o_seen.r2o_remove(&r2o_target);
        r2o_seen.r2o_insert(r2o_target, r2o_failure_at);
        assert!(r2o_seen.r2o_contains(&r2o_target, r2o_failure_at + Duration::from_secs(119)));
        assert!(!r2o_seen.r2o_contains(&r2o_target, r2o_failure_at + Duration::from_secs(120)));
    }

    #[cfg(unix)]
    #[test]
    fn местный_voice_nak_не_блокирует_повтор_по_следующему_потоку() {
        use super::{R2oVoiceDiscoverySeen, R2oVoiceTrialInstallOutcome};
        use std::net::{Ipv4Addr, SocketAddrV4};
        use std::time::Instant;

        let target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: Ipv4Addr::new(192, 0, 2, 10),
            server: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 50_004),
        };
        let now = Instant::now();
        let mut seen = R2oVoiceDiscoverySeen::default();
        seen.r2o_insert(target, now);
        seen.r2o_after_trial_install(&target, &R2oVoiceTrialInstallOutcome::LocalRefusal);
        assert!(
            !seen.r2o_contains(&target, now),
            "локальный NAK не должен ставить цель на отдых: новый поток может повторить поиск"
        );

        seen.r2o_insert(target, now);
        seen.r2o_after_trial_install(&target, &R2oVoiceTrialInstallOutcome::NotInstalled);
        assert!(
            seen.r2o_contains(&target, now),
            "отличный от NAK исход не должен снимать ограничение повтора"
        );
    }

    #[cfg(unix)]
    #[test]
    fn новая_voice_сессия_снимает_cooldown_и_ставится_за_текущей_проверкой() {
        use super::{R2oVoiceDiscoveryOutcome, R2oVoiceDiscoveryWorker, R2oVoiceLatestQueue};
        use std::net::{Ipv4Addr, SocketAddrV4};
        use std::sync::mpsc;
        use std::time::Instant;

        let target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: Ipv4Addr::new(192, 0, 2, 10),
            server: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 50_004),
        };
        let (_outcome_sender, outcomes) = mpsc::sync_channel::<R2oVoiceDiscoveryOutcome>(1);
        let mut worker = R2oVoiceDiscoveryWorker {
            jobs: None,
            outcomes,
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            r2o_seen: super::R2oVoiceDiscoverySeen::default(),
            schedule: R2oVoiceLatestQueue::default(),
            thread: None,
        };
        let now = Instant::now();
        worker.r2o_seen.r2o_insert(target, now);

        assert!(worker.queue_after_new_session_with_flow(target, None, None, false));
        assert!(
            worker
                .schedule
                .pending
                .as_ref()
                .is_some_and(|job| job.target == target)
        );
        assert!(
            !worker.r2o_seen.r2o_contains(&target, now),
            "fresh voice session may retry before the old 120-second cooldown ends"
        );
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
            flow: None,
            known_prefix: Some([1; 20]),
            started_at: std::time::Instant::now(),
        };
        let r2o_middle = R2oVoiceDiscoveryJob {
            target: r2o_controller::voice_discovery::R2oVoiceTarget {
                client: r2o_client,
                server: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 21), 50_005),
            },
            flow: None,
            known_prefix: None,
            started_at: std::time::Instant::now(),
        };
        let r2o_latest = R2oVoiceDiscoveryJob {
            target: r2o_controller::voice_discovery::R2oVoiceTarget {
                client: r2o_client,
                server: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 22), 50_006),
            },
            flow: None,
            known_prefix: Some([2; 20]),
            started_at: std::time::Instant::now(),
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
                    voice_flow_key: None,
                    started_at: r2o_now - Duration::from_secs(601),
                    renew_at: r2o_now - Duration::from_secs(30),
                    expires_at: r2o_now - Duration::from_secs(1),
                    response_confirmed: false,
                },
            ),
            (
                [2; 16],
                R2oVoiceTrialContext {
                    target: r2o_target,
                    trial_id: [2; 16],
                    plan_text: String::new(),
                    voice_flow_key: None,
                    started_at: r2o_now - Duration::from_secs(599),
                    renew_at: r2o_now + Duration::from_secs(30),
                    expires_at: r2o_now + Duration::from_secs(1),
                    response_confirmed: false,
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

    #[cfg(unix)]
    #[test]
    fn ожидающая_voice_цель_освобождается_через_две_минуты() {
        use super::{
            R2O_VOICE_PENDING_GRACE, R2oVoiceTrialContext, r2o_take_stale_pending_voice_trials,
        };
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

        let r2o_started_at = Instant::now();
        let r2o_trial_id = [0x73; 16];
        let r2o_target = r2o_controller::voice_discovery::R2oVoiceTarget {
            client: "192.0.2.10".parse().unwrap(),
            server: "198.51.100.20:50004".parse().unwrap(),
        };
        let mut r2o_trials = HashMap::from([(
            r2o_trial_id,
            R2oVoiceTrialContext {
                target: r2o_target,
                trial_id: r2o_trial_id,
                plan_text: String::new(),
                voice_flow_key: None,
                renew_at: r2o_started_at + Duration::from_secs(60),
                expires_at: r2o_started_at + Duration::from_secs(600),
                started_at: r2o_started_at,
                response_confirmed: false,
            },
        )]);

        assert!(
            r2o_take_stale_pending_voice_trials(
                &mut r2o_trials,
                r2o_started_at + R2O_VOICE_PENDING_GRACE - Duration::from_nanos(1),
                true,
            )
            .is_empty()
        );
        assert!(r2o_trials.contains_key(&r2o_trial_id));
        assert!(
            r2o_take_stale_pending_voice_trials(
                &mut r2o_trials,
                r2o_started_at + R2O_VOICE_PENDING_GRACE,
                false,
            )
            .is_empty()
        );
        assert!(r2o_trials.contains_key(&r2o_trial_id));

        let r2o_retired = r2o_take_stale_pending_voice_trials(
            &mut r2o_trials,
            r2o_started_at + R2O_VOICE_PENDING_GRACE,
            true,
        );
        assert_eq!(r2o_retired.len(), 1);
        assert_eq!(r2o_retired[0].trial_id, r2o_trial_id);
        assert!(r2o_trials.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn подтверждённый_отказ_повторно_ставит_цель_без_учёта_старого_охлаждения() {
        use std::sync::{Arc, Condvar, Mutex, atomic::AtomicBool, mpsc};

        let target = r2o_controller::discovery::DiscoveryTarget {
            host: "example.com".into(),
            endpoint: "198.51.100.9:443".into(),
            family: 4,
            shape: SHAPE_MODERN,
        };
        let failure_key = super::r2o_discovery_failure_key(&target);
        let (outcome_sender, outcomes) = mpsc::sync_channel(1);
        drop(outcome_sender);
        let mut worker = super::DiscoveryWorker {
            jobs: Arc::new((
                Mutex::new(super::R2oDiscoveryQueue::default()),
                Condvar::new(),
            )),
            client_hellos: Arc::new(Mutex::new(std::collections::HashMap::new())),
            recent_client_shapes: super::R2oRecentClientShapeCache::default(),
            resource_memory: Arc::new(Mutex::new(
                r2o_controller::r2o_resource::R2oResourceMemory::default(),
            )),
            active_cancels: Arc::new(Mutex::new(std::collections::HashMap::new())),
            catalog_refreshes: Arc::new(Mutex::new(std::collections::HashSet::new())),
            client_snapshot_targets: std::collections::HashSet::new(),
            pending_rechecks: std::collections::HashMap::new(),
            outcomes,
            cancel: Arc::new(AtomicBool::new(false)),
            seen: std::collections::HashSet::from([target.clone()]),
            seen_order: VecDeque::from([target.clone()]),
            failed_at: std::collections::HashMap::from([(
                failure_key.clone(),
                std::time::Instant::now(),
            )]),
            failed_retry_after: std::collections::HashMap::new(),
            challenge_cooldowns: std::collections::HashMap::new(),
            ech_input_clearable_failures: std::collections::HashSet::new(),
            ech_input_names: std::collections::VecDeque::new(),
            clear_streaks: std::collections::HashMap::new(),
            completed: std::collections::HashSet::new(),
            active: std::collections::HashMap::new(),
            threads: Vec::new(),
        };

        assert!(worker.queue_after_confirmed_failure(target.clone()));
        assert!(worker.seen.contains(&target));
        assert!(
            worker
                .active
                .contains_key(&super::r2o_discovery_task_key(&target))
        );
        assert!(!worker.failed_at.contains_key(&failure_key));
        assert_eq!(worker.jobs.0.lock().unwrap().entries.len(), 1);
    }

    fn parse_plan(proto: &[u8; 2]) -> Plan {
        let mut bytes = PLAN_MAGIC.to_vec();
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]);
        bytes.extend_from_slice(&[0, 2, 0, 2]);
        bytes.extend_from_slice(proto);
        Plan::parse(&bytes).unwrap()
    }
}
