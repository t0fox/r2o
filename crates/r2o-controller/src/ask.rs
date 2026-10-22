//! Измерение базовых свойств TCP-инспектора короткими потоковыми пробами.

use crate::classify::{DpiProps, Poison, Trigger, plan_text_for_poison};
use r2k_core::plan::Plan;
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

pub const ASK_HELLO_MAX: usize = 2048;
pub const ASK_WAIT: Duration = Duration::from_secs(5);
const ASK_USAGE: &str = "использование: r2o-controller --ask --control <сокет> --ip <адрес> --sni <имя> (--hello-hex <файл> | --arm-wait-ms <мс>) [--port 443] [--control-sni <имя> | --control-hex <файл>] [--mark 0x2d] [--save-trigger <файл>] [--save-control <файл>]";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AskSnapshotInput {
    File(PathBuf),
    Capture,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AskControlInput {
    File(PathBuf),
    Capture(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AskCliOptions {
    pub control_path: PathBuf,
    pub target_ip: IpAddr,
    pub port: u16,
    pub sni: String,
    pub trigger: AskSnapshotInput,
    pub arm_wait: Option<Duration>,
    pub control: Option<AskControlInput>,
    pub mark: u32,
    pub save_trigger: Option<PathBuf>,
    pub save_control: Option<PathBuf>,
}

pub fn ask_help() -> &'static str {
    ASK_USAGE
}

pub fn parse_ask_options(arguments: &[OsString]) -> Result<AskCliOptions, String> {
    let mut control_path = None;
    let mut ip = None;
    let mut port = None;
    let mut sni = None;
    let mut control_sni = None;
    let mut control_hex = None;
    let mut hello_hex = None;
    let mut arm_wait_raw = None;
    let mut mark_raw = None;
    let mut save_trigger = None;
    let mut save_control = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or("флаг --ask должен быть UTF-8")?;
        let value = match flag {
            "--control" | "--ip" | "--port" | "--sni" | "--control-sni" | "--control-hex"
            | "--hello-hex" | "--arm-wait-ms" | "--mark" | "--save-trigger" | "--save-control" => {
                index += 1;
                arguments
                    .get(index)
                    .ok_or_else(|| format!("{flag} требует значения"))?
                    .clone()
            }
            unknown => return Err(format!("неизвестный аргумент: {unknown}")),
        };
        let one = |slot: &mut Option<OsString>| -> Result<(), String> {
            if slot.replace(value.clone()).is_some() {
                Err(format!("{flag} указан больше одного раза"))
            } else {
                Ok(())
            }
        };
        match flag {
            "--control" => one(&mut control_path)?,
            "--ip" => one(&mut ip)?,
            "--port" => one(&mut port)?,
            "--sni" => one(&mut sni)?,
            "--control-sni" => one(&mut control_sni)?,
            "--control-hex" => one(&mut control_hex)?,
            "--hello-hex" => one(&mut hello_hex)?,
            "--arm-wait-ms" => one(&mut arm_wait_raw)?,
            "--mark" => one(&mut mark_raw)?,
            "--save-trigger" => one(&mut save_trigger)?,
            "--save-control" => one(&mut save_control)?,
            _ => unreachable!(),
        }
        index += 1;
    }

    let control_path = control_path.ok_or("обязателен --control <путь к сокету>")?;
    let target_ip = ip
        .ok_or("обязателен --ip <IPv4 или IPv6>")?
        .to_str()
        .ok_or("--ip должен быть UTF-8")?
        .parse::<IpAddr>()
        .map_err(|error| format!("неверный IP-адрес цели: {error}"))?;
    let sni = sni
        .ok_or("обязателен --sni <имя>")?
        .into_string()
        .map_err(|_| "--sni должен быть UTF-8")?;
    if sni.is_empty() || sni.len() > r2k_core::control::MAX_DNS_NAME_LEN {
        return Err("--sni должен занимать от 1 до 253 байт".into());
    }

    if hello_hex.is_some() == arm_wait_raw.is_some() {
        return Err("задайте ровно один из --hello-hex и --arm-wait-ms".into());
    }
    if control_hex.is_some() && control_sni.is_some() {
        return Err("--control-hex и --control-sni взаимоисключающие".into());
    }
    if control_sni.is_some() && arm_wait_raw.is_none() {
        return Err("--control-sni требует --arm-wait-ms".into());
    }

    let arm_wait = arm_wait_raw
        .map(|value| parse_positive_ms(&value, "--arm-wait-ms"))
        .transpose()?;
    let trigger = if let Some(path) = hello_hex {
        AskSnapshotInput::File(PathBuf::from(path))
    } else {
        AskSnapshotInput::Capture
    };
    let control = if let Some(path) = control_hex {
        Some(AskControlInput::File(PathBuf::from(path)))
    } else {
        control_sni
            .map(|name| {
                name.into_string()
                    .map(AskControlInput::Capture)
                    .map_err(|_| "--control-sni должен быть UTF-8".to_owned())
            })
            .transpose()?
    };
    let mark = mark_raw
        .map(|value| parse_mark(&value))
        .transpose()?
        .unwrap_or(0);
    let port = port
        .map(|value| parse_positive_port(&value))
        .transpose()?
        .unwrap_or(443);
    Ok(AskCliOptions {
        control_path: PathBuf::from(control_path),
        target_ip,
        port,
        sni,
        trigger,
        arm_wait,
        control,
        mark,
        save_trigger: save_trigger.map(PathBuf::from),
        save_control: save_control.map(PathBuf::from),
    })
}

fn argument_text<'a>(value: &'a OsString, flag: &str) -> Result<&'a str, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{flag} должен быть UTF-8"))
}

fn parse_positive_port(value: &OsString) -> Result<u16, String> {
    let text = argument_text(value, "--port")?;
    let port = text
        .parse::<u16>()
        .map_err(|_| format!("--port не число 1..65535: {text}"))?;
    if port == 0 {
        return Err(format!("--port не число 1..65535: {text}"));
    }
    Ok(port)
}

fn parse_positive_ms(value: &OsString, flag: &str) -> Result<Duration, String> {
    let text = argument_text(value, flag)?;
    let milliseconds = text
        .parse::<u64>()
        .map_err(|_| format!("{flag} не положительное целое (мс): {text}"))?;
    if milliseconds == 0 {
        return Err(format!("{flag} не положительное целое (мс): {text}"));
    }
    Ok(Duration::from_millis(milliseconds))
}

fn parse_mark(value: &OsString) -> Result<u32, String> {
    let text = argument_text(value, "--mark")?;
    if text.starts_with('-') || text.is_empty() {
        return Err(format!("--mark не число: {text}"));
    }
    let (digits, radix) =
        if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (digits, 16)
        } else if text.len() > 1 && text.starts_with('0') {
            if text[1..].is_empty() {
                return Ok(0);
            }
            (&text[1..], 8)
        } else {
            (text, 10)
        };
    u32::from_str_radix(digits, radix).map_err(|_| format!("--mark не число: {text}"))
}

pub fn read_hex_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let contents = std::fs::read(path).map_err(|error| format!("открыть не удалось: {error}"))?;
    decode_hex(&contents)
}

fn decode_hex(contents: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut high = None;
    let mut digits = 0usize;
    for line in contents.split(|byte| *byte == b'\n') {
        let start = line
            .iter()
            .position(|byte| !matches!(byte, b' ' | b'\t'))
            .unwrap_or(line.len());
        if line.get(start) == Some(&b'#') {
            continue;
        }
        for byte in &line[start..] {
            if matches!(byte, b'\n' | b'\r' | b' ' | b'\t') {
                continue;
            }
            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => {
                    return Err(format!(
                        "недопустимый символ '{}' (не шестнадцатеричная цифра)",
                        char::from(*byte)
                    ));
                }
            };
            digits += 1;
            if let Some(high) = high.take() {
                if output.len() == ASK_HELLO_MAX {
                    return Err(format!(
                        "снимок больше потолка формы приветствия ({ASK_HELLO_MAX} байт)"
                    ));
                }
                output.push((high << 4) | nibble);
            } else {
                high = Some(nibble);
            }
        }
    }
    if digits % 2 != 0 {
        return Err(format!("нечётное число шестнадцатеричных цифр ({digits})"));
    }
    if output.is_empty() {
        return Err("файл пуст (0 байт)".into());
    }
    Ok(output)
}

pub fn hello_sni(bytes: &[u8]) -> Result<String, String> {
    let tls = r2k_core::tls::parse(bytes);
    if !tls.is_client_hello || tls.extensions_truncated || tls.record_end != Some(bytes.len()) {
        return Err("снимок неполон или не является TLS ClientHello".into());
    }
    let sni = tls
        .sni_range
        .as_ref()
        .and_then(|range| bytes.get(range.clone()))
        .ok_or("в ClientHello не найден SNI")?;
    std::str::from_utf8(sni)
        .map(str::to_owned)
        .map_err(|_| "SNI в ClientHello не является UTF-8".into())
}

pub fn validate_hello(bytes: &[u8], expected_sni: &str) -> Result<Trigger, String> {
    Trigger::tls_client_hello(expected_sni, bytes).map_err(str::to_owned)
}

pub fn hello_shape(bytes: &[u8]) -> Result<u8, String> {
    let tls = r2k_core::tls::parse(bytes);
    if !tls.is_client_hello || tls.record_end != Some(bytes.len()) {
        return Err("снимок неполон или не является TLS ClientHello".into());
    }
    Ok(if tls.ech_offer {
        r2k_core::control::SHAPE_ECH_TCP
    } else if tls.is_tls13 {
        r2k_core::control::SHAPE_MODERN
    } else {
        r2k_core::control::SHAPE_LEGACY
    })
}

/// Build the candidate plan list from the measured three-valued properties.
/// The order follows the donor's `d2k_compose`; every returned text is accepted
/// by the same plan compiler and runtime validator used for installation.
pub fn compose_plan_texts(
    properties: &DpiProps,
    trigger: &Trigger,
    target_shape: u8,
    decoy_sni: Option<&str>,
    send_cap: usize,
) -> Result<Vec<String>, String> {
    use crate::classify::TriState;

    let mut plans = Vec::new();
    let decoy_hello = decoy_sni
        .map(|name| {
            if target_shape == r2k_core::control::SHAPE_MODERN {
                crate::hello::modern_client_hello(name)
            } else {
                crate::hello::legacy_client_hello(name)
            }
            .map_err(str::to_owned)
        })
        .transpose()?;

    if properties.tolerates_left_overlap == TriState::False {
        plans.push(question_plan(AskQuestion::LeftOverlap, trigger, None, [0; 16])?.0);
    }
    if properties.tolerates_reorder == TriState::False {
        plans.push(question_plan(AskQuestion::Reorder, trigger, None, [0; 16])?.0);
    }
    if properties.counts_duplicates == TriState::True {
        if let Some(decoy) = &decoy_hello {
            plans.push(compose_badsum_fake_plan(decoy, 2, 20_000)?);
        }
    }
    if properties.validates_checksum == TriState::False && properties.parses_l7 != TriState::True {
        plans.push(compose_badsum_fake_plan(&[0x0f; 64], 1, 0)?);
    }
    if properties.parses_l7 == TriState::True {
        if let Some(decoy) = &decoy_hello {
            plans.push(compose_badsum_fake_plan(decoy, 1, 0)?);
        }
    }
    if plans.is_empty() {
        if let Some(decoy) = &decoy_hello {
            let room = if send_cap > 120 { send_cap - 120 } else { 0 };
            let decoy_len = if room > 0 {
                decoy.len().min(room)
            } else {
                decoy.len()
            };
            let plan = format!(
                "r2o-plan 1 10\nid 00000000000000000000000000000000\nproto tcp tls\npayload 1 {}\npayload 2 0f\npoison 1 badsum\nsplit payload_start +1\nsplit sni_middle +0\nfake payload=1 poison=1 repeats=2 gap_us=20000 place=before\nseqovl payload=2 poison=0\norder reverse\n",
                hex(&decoy[..decoy_len])
            );
            plans.push(plan);
        }
    }

    for text in &plans {
        let records = crate::plan_text::compile_text(text)?;
        let plan = Plan::parse(&records).map_err(|error| error.to_string())?;
        r2o_datapath::engine::validate_runtime_plan(&plan)
            .map_err(|error| format!("составленный план не подходит runtime: {error}"))?;
    }
    Ok(plans)
}

fn compose_badsum_fake_plan(payload: &[u8], repeats: u8, gap_us: u32) -> Result<String, String> {
    if payload.is_empty() {
        return Err("фальшивка плана не может быть пустой".into());
    }
    Ok(format!(
        "r2o-plan 1 10\nid 00000000000000000000000000000000\nproto tcp tls\npayload 1 {}\npoison 1 badsum\nfake payload=1 poison=1 repeats={repeats} gap_us={gap_us} place=before\norder forward\npace 15000\n",
        hex(payload)
    ))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub const ASK_QUESTION_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AskQuestion {
    LeftOverlap,
    Reorder,
    Checksum,
    ProtocolParse,
    Duplicates,
}

impl AskQuestion {
    pub const ALL: [Self; ASK_QUESTION_COUNT] = [
        Self::LeftOverlap,
        Self::Reorder,
        Self::Checksum,
        Self::ProtocolParse,
        Self::Duplicates,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::LeftOverlap => "перекрытие слева",
            Self::Reorder => "порядок сегментов",
            Self::Checksum => "контрольная сумма",
            Self::ProtocolParse => "разбор протокола",
            Self::Duplicates => "счёт дубликатов",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::LeftOverlap => "держит ли сегмент, начинающийся левее данных",
            Self::Reorder => "держит ли сегменты не по порядку прихода",
            Self::Checksum => "сверяет ли контрольную сумму TCP",
            Self::ProtocolParse => "разбирает ли TLS, а не просто смотрит байты",
            Self::Duplicates => "считает ли разнесённые копии за одно",
        }
    }
}

/// Собрать точный R2OP-вопрос и проверить его тем же парсером, что datapath.
/// Порядок вопросов и параметры воздействий повторяют `d2k_props_ask`.
pub fn question_plan(
    question: AskQuestion,
    trigger: &Trigger,
    control: Option<&[u8]>,
    plan_id: [u8; 16],
) -> Result<(String, Plan), String> {
    let poison = match question {
        AskQuestion::LeftOverlap => Poison {
            name: "ask-left-overlap".into(),
            seqovl: 1,
            ..Poison::default()
        },
        AskQuestion::Reorder => Poison {
            name: "ask-reorder".into(),
            disorder: true,
            ..Poison::default()
        },
        AskQuestion::Checksum => Poison {
            name: "ask-checksum".into(),
            badsum: true,
            ..Poison::default()
        },
        AskQuestion::ProtocolParse => Poison {
            name: "ask-protocol-parse".into(),
            badsum: true,
            decoy_hello: true,
            ..Poison::default()
        },
        AskQuestion::Duplicates => Poison {
            name: "ask-duplicates".into(),
            badsum: true,
            repeats: 2,
            gap_ms: 20,
            ..Poison::default()
        },
    };
    let decoy = if question == AskQuestion::ProtocolParse {
        let control = control.ok_or("вопрос разбора протокола требует control ClientHello")?;
        let max = trigger.payload.len().saturating_mul(2);
        Some(&control[..control.len().min(max)])
    } else {
        None
    };
    let mut text = plan_text_for_poison(&poison, trigger, decoy, 0)?;
    let plan_id_hex = plan_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let id_line = format!("id {plan_id_hex}");
    text = text.replacen("id 00000000000000000000000000000000", &id_line, 1);
    let bytes = crate::plan_text::compile_text(&text)?;
    let plan = Plan::parse(&bytes).map_err(|error| error.to_string())?;
    if plan.id != plan_id {
        return Err("собранный вопрос содержит чужой идентификатор плана".into());
    }
    r2o_datapath::engine::validate_runtime_plan(&plan)
        .map_err(|error| format!("вопрос не подходит runtime r2o-datapath: {error}"))?;
    Ok((text, plan))
}

pub fn record_question_passed(properties: &mut DpiProps, question: AskQuestion) {
    use crate::classify::TriState;

    match question {
        AskQuestion::LeftOverlap => properties.tolerates_left_overlap = TriState::False,
        AskQuestion::Reorder => properties.tolerates_reorder = TriState::False,
        AskQuestion::Checksum => properties.validates_checksum = TriState::False,
        AskQuestion::ProtocolParse => {
            properties.parses_l7 = TriState::True;
            properties.validates_checksum = TriState::False;
        }
        AskQuestion::Duplicates => properties.counts_duplicates = TriState::True,
    }
}

#[cfg(test)]
mod tests {
    use super::{AskQuestion, question_plan, record_question_passed};
    use crate::classify::{DpiProps, TriState, Trigger};
    use r2k_core::plan::{POISON_BADSUM, Plan};
    use std::ffi::OsString;
    use std::net::IpAddr;
    use std::time::Duration;

    fn trigger() -> Trigger {
        Trigger::tls("ask.example").unwrap()
    }

    #[test]
    fn question_order_and_plan_parameters_match_the_five_donor_probes() {
        let trigger = trigger();
        let control = Trigger::tls("control.example").unwrap();

        let (overlap_text, overlap) =
            question_plan(AskQuestion::LeftOverlap, &trigger, None, [1; 16]).unwrap();
        assert!(overlap_text.contains("seqovl payload=2 poison=0"));
        assert_eq!(overlap.seq_overlays.len(), 1);
        assert_eq!(overlap.payloads[0].bytes, [0x0f]);

        let (_, reorder) = question_plan(AskQuestion::Reorder, &trigger, None, [2; 16]).unwrap();
        assert_eq!(reorder.order, 1);
        assert_eq!(reorder.pace_us, 12_000);
        assert_eq!(reorder.splits.len(), 2);

        let (_, checksum) = question_plan(AskQuestion::Checksum, &trigger, None, [3; 16]).unwrap();
        assert_eq!(checksum.poisons[0].flags, POISON_BADSUM);
        assert_eq!(checksum.payloads[0].bytes.len(), trigger.payload.len() * 2);
        assert!(checksum.payloads[0].bytes.iter().all(|byte| *byte == 0x0f));

        let (_, parse) = question_plan(
            AskQuestion::ProtocolParse,
            &trigger,
            Some(&control.payload),
            [4; 16],
        )
        .unwrap();
        assert_eq!(parse.payloads[0].bytes.len(), trigger.payload.len() * 2);
        assert!(parse.payloads[0].bytes.starts_with(&control.payload));
        assert!(
            parse.payloads[0].bytes[control.payload.len()..]
                .iter()
                .all(|byte| *byte == 0x0f)
        );

        let (_, duplicates) =
            question_plan(AskQuestion::Duplicates, &trigger, None, [5; 16]).unwrap();
        assert_eq!(duplicates.fakes[0].repeats, 2);
        assert_eq!(duplicates.fakes[0].gap_us, 20_000);
    }

    #[test]
    fn protocol_parse_requires_control_and_success_updates_only_its_proven_fields() {
        let trigger = trigger();
        assert!(question_plan(AskQuestion::ProtocolParse, &trigger, None, [4; 16]).is_err());

        let mut properties = DpiProps::default();
        record_question_passed(&mut properties, AskQuestion::ProtocolParse);
        assert_eq!(properties.parses_l7, TriState::True);
        assert_eq!(properties.validates_checksum, TriState::False);
        assert_eq!(properties.counts_duplicates, TriState::Unset);
        assert_eq!(properties.tolerates_reorder, TriState::Unset);
        assert_eq!(properties.tolerates_left_overlap, TriState::Unset);
    }

    #[test]
    fn built_question_plan_is_accepted_by_runtime_parser() {
        let trigger = trigger();
        let (_, plan) = question_plan(AskQuestion::Duplicates, &trigger, None, [0x6a; 16]).unwrap();
        assert_eq!(plan.id, [0x6a; 16]);
        let bytes = crate::plan_text::compile_text(
            &super::question_plan(AskQuestion::Duplicates, &trigger, None, [0x6a; 16])
                .unwrap()
                .0,
        )
        .unwrap();
        assert_eq!(Plan::parse(&bytes).unwrap(), plan);
    }

    #[test]
    fn ask_options_keep_capture_inputs_and_c_defaults() {
        let args = [
            "--control",
            "/run/r2o.sock",
            "--ip",
            "2001:db8::1",
            "--sni",
            "target.example",
            "--arm-wait-ms",
            "7500",
            "--control-sni",
            "control.example",
            "--mark",
            "0x2d",
        ]
        .map(OsString::from);
        let options = super::parse_ask_options(&args).unwrap();
        assert_eq!(options.port, 443);
        assert_eq!(options.mark, 0x2d);
        assert_eq!(options.arm_wait, Some(Duration::from_millis(7500)));
        assert_eq!(options.trigger, super::AskSnapshotInput::Capture);
        assert_eq!(
            options.control,
            Some(super::AskControlInput::Capture("control.example".into()))
        );
        assert_eq!(options.target_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ask_options_reject_ambiguous_snapshot_sources_and_bad_marks() {
        let base = [
            "--control",
            "/run/r2o.sock",
            "--ip",
            "192.0.2.1",
            "--sni",
            "target.example",
        ];
        let with = |tail: &[&str]| {
            base.iter()
                .chain(tail)
                .map(OsString::from)
                .collect::<Vec<_>>()
        };
        assert!(super::parse_ask_options(&with(&["--hello-hex", "trigger.hex"])).is_ok());
        assert!(
            super::parse_ask_options(&with(&[
                "--arm-wait-ms",
                "20",
                "--hello-hex",
                "trigger.hex"
            ]))
            .is_err()
        );
        assert!(
            super::parse_ask_options(&with(&[
                "--hello-hex",
                "trigger.hex",
                "--control-sni",
                "control.example"
            ]))
            .is_err()
        );
        assert!(
            super::parse_ask_options(&with(&["--hello-hex", "trigger.hex", "--mark", "-1"]))
                .is_err()
        );
    }

    #[test]
    fn saved_hex_reader_accepts_comments_and_rejects_non_hex_data() {
        assert_eq!(
            super::decode_hex(b"  # comment\n  16 03\t03\r\n0x16"),
            Err("недопустимый символ 'x' (не шестнадцатеричная цифра)".into())
        );
        assert_eq!(
            super::decode_hex(b"# hello\n16030"),
            Err("нечётное число шестнадцатеричных цифр (5)".into())
        );
        assert_eq!(
            super::decode_hex(b"# profile\n16 03 03"),
            Ok(vec![0x16, 0x03, 0x03])
        );
    }

    #[test]
    fn clienthello_shape_and_name_are_taken_from_exact_saved_bytes() {
        let bytes = crate::hello::modern_client_hello("ask.example").unwrap();
        assert_eq!(super::hello_sni(&bytes).unwrap(), "ask.example");
        assert_eq!(
            super::hello_shape(&bytes),
            Ok(r2k_core::control::SHAPE_MODERN)
        );
        assert!(super::validate_hello(&bytes, "other.example").is_err());
        assert!(super::validate_hello(&bytes, "ask.example").is_ok());
    }

    #[test]
    fn compose_builds_donor_ordered_plans_and_the_all_unknown_fallback() {
        let trigger = Trigger::tls("target.example").unwrap();
        let mut properties = DpiProps::default();
        let plans = super::compose_plan_texts(
            &properties,
            &trigger,
            r2k_core::control::SHAPE_LEGACY,
            Some("control.example"),
            0,
        )
        .unwrap();
        assert_eq!(plans.len(), 1);
        let fallback = Plan::parse(&crate::plan_text::compile_text(&plans[0]).unwrap()).unwrap();
        assert_eq!(fallback.payloads.len(), 2);
        assert_eq!(fallback.poisons[0].flags, POISON_BADSUM);
        assert_eq!(fallback.fakes[0].repeats, 2);
        assert_eq!(fallback.splits.len(), 2);
        assert_eq!(fallback.seq_overlays.len(), 1);
        assert_eq!(fallback.order, 1);

        properties.tolerates_left_overlap = TriState::False;
        properties.tolerates_reorder = TriState::False;
        properties.counts_duplicates = TriState::True;
        properties.validates_checksum = TriState::False;
        properties.parses_l7 = TriState::True;
        let plans = super::compose_plan_texts(
            &properties,
            &trigger,
            r2k_core::control::SHAPE_LEGACY,
            Some("control.example"),
            0,
        )
        .unwrap();
        assert_eq!(plans.len(), 4);
        let parsed = plans
            .iter()
            .map(|text| Plan::parse(&crate::plan_text::compile_text(text).unwrap()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(parsed[0].seq_overlays.len(), 1);
        assert_eq!(parsed[1].order, 1);
        assert_eq!(parsed[2].fakes[0].repeats, 2);
        assert_eq!(parsed[3].fakes[0].repeats, 1);
    }

    #[test]
    fn compose_omits_checksum_when_parse_success_already_explains_it() {
        let trigger = Trigger::tls("target.example").unwrap();
        let mut properties = DpiProps::default();
        properties.validates_checksum = TriState::False;
        properties.parses_l7 = TriState::True;
        let plans = super::compose_plan_texts(
            &properties,
            &trigger,
            r2k_core::control::SHAPE_LEGACY,
            Some("control.example"),
            0,
        )
        .unwrap();
        assert_eq!(plans.len(), 1);
        let parsed = Plan::parse(&crate::plan_text::compile_text(&plans[0]).unwrap()).unwrap();
        assert_eq!(parsed.fakes[0].repeats, 1);
        assert!(
            parsed.payloads[0]
                .bytes
                .starts_with(&crate::hello::legacy_client_hello("control.example").unwrap())
        );
    }
}
