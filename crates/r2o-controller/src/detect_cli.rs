//! Detect-совместимый CLI `d2k-detect classify` (`detect/main.c` донора a378).
//!
//! Здесь перенесены точные тексты `print_json`/`print_human`, разбор флагов
//! и коды возврата C-инструмента. Контроллер `main.rs` не используется:
//! отдельный бинарник `r2o-detect` можно сверять с C построчно.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use crate::classify::{
    Accept, ClassifyOptions, ClassifyResult, TcpProbeBackend, TriState, Trigger,
    run_with_backend_progress,
};

/// C `D2K_BYPASS_MARK` (`detect/include/d2k_detect.h:34`).
const D2K_BYPASS_MARK: u32 = 0x4000_0000;
const D2K_SKIP_MAX: usize = 32;

struct DetectOptions {
    repeats: usize,
    timeout: Duration,
    write_gap: Duration,
    long_gap: Duration,
    only_poison: Option<String>,
    skip_poisons: Vec<String>,
    white: Option<Trigger>,
    control: Option<Trigger>,
    control_vouched: bool,
    no_raw: bool,
    mark: u32,
    allow_loopback: bool,
    json: bool,
    dump_trigger: bool,
    progress: bool,
}

impl Default for DetectOptions {
    fn default() -> Self {
        Self {
            repeats: 3,
            timeout: Duration::from_millis(6000),
            write_gap: Duration::from_millis(60),
            long_gap: Duration::from_millis(700),
            only_poison: None,
            skip_poisons: Vec::new(),
            white: None,
            control: None,
            control_vouched: false,
            no_raw: false,
            mark: D2K_BYPASS_MARK,
            allow_loopback: false,
            json: false,
            dump_trigger: false,
            progress: false,
        }
    }
}

/// Ошибка разбора CLI с кодом возврата C-инструмента: 2 — ошибка
/// командной строки, 1 — не собрался триггер.
struct DetectError {
    code: i32,
    message: String,
    show_usage: bool,
}

impl DetectError {
    /// Ошибка флага/аргумента: C печатает сообщение и usage, код 2.
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
            show_usage: true,
        }
    }

    /// Смысловая ошибка CLI: C печатает только сообщение, код 2.
    fn cli(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
            show_usage: false,
        }
    }

    /// Триггер не собрался: код 1, без usage.
    fn trigger(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
            show_usage: false,
        }
    }
}

fn usage(out: &mut String) {
    out.push_str(
        "d2k-detect classify <host:port> [флаги]\n\n  --sni ИМЯ          собрать триггер как ClientHello с этим именем\n  --raw HEX          триггер шестнадцатеричной строкой (для не-TLS протоколов)\n  --repeats N        повторов на зонд; вердикт только при единогласии (3)\n  --timeout MS       сколько ждать ответа (6000)\n  --only ИМЯ         прогнать только эту гипотезу (для отладки зондов)\n  --skip ИМЯ         не пробовать эту гипотезу (можно повторять)\n  --control-sni ИМЯ  имя для контрольного зонда; сервер обязан его обслуживать\n  --white ИМЯ        ECH-приманка вопроса «приветствие под меткой» — то же\n                     белое имя, что даёт планировщик (net.name или hcaptcha.com)\n  --control-raw HEX  байты контрольного зонда шестнадцатеричной строкой.\n                     Нужен сверке: контроль — такой же ВХОД замера, как триггер,\n                     и гипотезы с приманкой берут длину перекрытия равной его длине\n  --hello modern|legacy   какое приветствие TLS мерить\n  --no-raw           выключить сырые зонды\n  --mark HEX         метка SO_MARK для всех зондов (умолчание 0x40000000 — z2k).\n                     У d2k метка своя, её задаёт --mark датапату: с чужой зонд\n                     пойдёт ЧЕРЕЗ наш обход и замерит его, а не коробку\n  --allow-loopback   снять защиту от цели на localhost (для стенда)\n  --json             выдать результат как JSON\n  --progress         печатать каждый зонд по мере готовности.\n                     Трасса печатается в конце, а поиск на трудной цели идёт\n                     десятки минут: без этого «идёт» не отличить от «висит»\n  --dump-trigger     напечатать байты триггера hex и выйти\n                     (тем же hex кормится эталон: z2k-detect classify -raw ...,\n                      только так сверка меряет АЛГОРИТМ, а не разные приветствия)\n",
    );
}

fn print_json_str(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

fn print_tri(out: &mut String, key: &str, state: TriState) {
    if state == TriState::Unset {
        return;
    }
    let _ = write!(
        out,
        ",\n    \"{key}\": {}",
        if state == TriState::True {
            "true"
        } else {
            "false"
        }
    );
}

/// Точный перенос C `print_json` (`detect/main.c:75-205`).
pub fn format_json(result: &ClassifyResult, trigger_len: usize) -> String {
    let mut out = String::new();
    out.push_str("{\n  \"target\": ");
    print_json_str(&mut out, &result.target);
    out.push_str(",\n  \"verdict\": ");
    print_json_str(&mut out, result.verdict.as_str());
    out.push_str(",\n  \"reason\": ");
    print_json_str(&mut out, &result.reason);
    let _ = write!(
        out,
        ",\n  \"repeats\": {},\n  \"probes\": {},\n  \"duration\": ",
        result.repeats, result.probes
    );
    print_json_str(&mut out, &format!("{}ms", result.duration.as_millis()));
    let _ = write!(out, ",\n  \"trigger_len\": {trigger_len}");
    if let Some(boundary) = result.boundary.filter(|boundary| *boundary > 0) {
        let _ = write!(out, ",\n  \"boundary\": {boundary}");
    }
    if let Some(split_pos) = result.split_pos.filter(|split_pos| *split_pos > 0) {
        let _ = write!(out, ",\n  \"split_pos\": {split_pos}");
    }
    if let Some(reassembles) = result.reassembles {
        let _ = write!(
            out,
            ",\n  \"reassembles\": {}",
            if reassembles { "true" } else { "false" }
        );
    }
    if let Some(strategy) = result.strategy.as_deref().filter(|value| !value.is_empty()) {
        out.push_str(",\n  \"strategy\": ");
        print_json_str(&mut out, strategy);
    }
    if !result.notes.is_empty() {
        out.push_str(",\n  \"notes\": [");
        for (index, note) in result.notes.iter().enumerate() {
            out.push_str(if index == 0 { "\n    " } else { ",\n    " });
            print_json_str(&mut out, note);
        }
        out.push_str("\n  ]");
    }
    if let Some(response) = &result.response {
        out.push_str(",\n  \"response\": {\n    \"verdict\": ");
        print_json_str(&mut out, response.verdict.as_str());
        out.push_str(",\n    \"reason\": ");
        print_json_str(&mut out, &response.reason);
        let _ = write!(
            out,
            ",\n    \"target\": {},\n    \"control\": {}\n  }}",
            response.target, response.control
        );
    }
    if result.covers_tls12 != TriState::Unset {
        let _ = write!(
            out,
            ",\n  \"covers_tls12\": {}",
            if result.covers_tls12 == TriState::True {
                "true"
            } else {
                "false"
            }
        );
    }
    out.push_str(",\n  \"props\": {");
    let mut first = true;
    let fields = [
        ("reassembles", result.props.reassembles),
        ("parses_l7", result.props.parses_l7),
        ("validates_checksum", result.props.validates_checksum),
        ("tolerates_reorder", result.props.tolerates_reorder),
        (
            "tolerates_left_overlap",
            result.props.tolerates_left_overlap,
        ),
        ("counts_duplicates", result.props.counts_duplicates),
        ("inspects_syn", result.props.inspects_syn),
    ];
    for (key, state) in fields {
        if state == TriState::Unset {
            continue;
        }
        let value = if state == TriState::True {
            "true"
        } else {
            "false"
        };
        if first {
            let _ = write!(out, "\n    \"{key}\": {value}");
            first = false;
        } else {
            print_tri(&mut out, key, state);
        }
    }
    if result.props.hop_ttl.is_some_and(|ttl| ttl > 0) {
        let ttl = result.props.hop_ttl.unwrap_or_default();
        let _ = write!(
            out,
            "{}\n    \"hop_ttl\": {ttl}",
            if first { "" } else { "," }
        );
        first = false;
    }
    out.push_str(if first { "}" } else { "\n  }" });
    if let Some(path) = result.path.as_deref().filter(|value| !value.is_empty()) {
        out.push_str(",\n  \"path\": ");
        print_json_str(&mut out, path);
    }
    let _ = write!(
        out,
        ",\n  \"composed\": {},\n  \"raw_usable\": {},\n  \"trace\": [",
        if result.composed { "true" } else { "false" },
        if result.raw_usable { "true" } else { "false" }
    );
    for (index, observation) in result.trace.iter().enumerate() {
        out.push_str(if index == 0 {
            "\n    {\n      \"probe\": "
        } else {
            ",\n    {\n      \"probe\": "
        });
        print_json_str(&mut out, &observation.probe);
        if !observation.cuts.is_empty() {
            out.push_str(",\n      \"cuts\": [");
            for (cut_index, cut) in observation.cuts.iter().enumerate() {
                if cut_index != 0 {
                    out.push(',');
                }
                let _ = write!(out, "{cut}");
            }
            out.push(']');
        }
        let delay_ms = observation.delay.as_millis();
        if delay_ms > 0 {
            let _ = write!(out, ",\n      \"delay_ms\": {delay_ms}");
        }
        let _ = write!(
            out,
            ",\n      \"pass\": {},\n      \"fail\": {}",
            observation.pass, observation.fail
        );
        if let Some(error) = observation
            .error
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            out.push_str(",\n      \"err\": ");
            print_json_str(&mut out, error);
        }
        out.push_str("\n    }");
    }
    out.push_str("\n  ]\n}\n");
    out
}

fn tri_word(state: TriState) -> &'static str {
    match state {
        TriState::Unset => "не измерено",
        TriState::True => "да",
        TriState::False => "нет",
    }
}

/// Точный перенос C `print_human` (`detect/main.c:207-275`).
pub fn format_human(result: &ClassifyResult, trigger: &Trigger, trigger_len: usize) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Цель:     {}", result.target);
    let _ = writeln!(out, "Триггер:  {} ({trigger_len} байт)", trigger.name);
    let _ = writeln!(
        out,
        "Вердикт:  {} — {}",
        result.verdict.as_str(),
        result.reason
    );
    let _ = writeln!(
        out,
        "Зондов:   {} за {}ms (по {} повтора)",
        result.probes,
        result.duration.as_millis(),
        result.repeats
    );
    if let Some(boundary) = result.boundary.filter(|boundary| *boundary > 0) {
        let _ = writeln!(out, "Граница:  сигнатура кончается на байте {boundary}");
    }
    if let Some(reassembles) = result.reassembles {
        out.push_str(if reassembles {
            "Пересборка: ЕСТЬ — при паузе блок возвращается\n"
        } else {
            "Пересборка: нет\n"
        });
    }
    if let Some(strategy) = result.strategy.as_deref().filter(|value| !value.is_empty()) {
        let mut how = "путь не отмечен";
        match result.path.as_deref() {
            Some("свойство") => how = "ответила фаза свойств — 6 вопросов о коробке",
            Some("собрано") => how = "СОБРАНА из вектора свойств",
            Some("перебор") => how = "вектор не помог, найдена запасным перебором",
            _ => {}
        }
        let _ = writeln!(out, "Стратегия: {strategy}");
        let _ = writeln!(out, "           ({how})");
    }
    if let Some(response) = &result.response {
        let _ = writeln!(
            out,
            "Ответ:    {} — {} (цель {}, контроль {})",
            response.verdict.as_str(),
            response.reason,
            response.target,
            response.control
        );
    }
    for note in &result.notes {
        let _ = writeln!(out, "Оговорка:  {note}");
    }
    if result.verdict == crate::classify::Verdict::Opaque && !result.raw_usable {
        out.push_str(
            "ВНИМАНИЕ: сырые зонды не отработали — отрицательный вывод про отравление НЕ значим\n",
        );
    }
    if result.props.reassembles != TriState::Unset
        || result.props.parses_l7 != TriState::Unset
        || result.props.validates_checksum != TriState::Unset
        || result.props.tolerates_reorder != TriState::Unset
        || result.props.tolerates_left_overlap != TriState::Unset
        || result.props.hop_ttl.is_some_and(|ttl| ttl > 0)
    {
        out.push_str("Свойства коробки:\n");
        let _ = writeln!(
            out,
            "  пересобирает поток:        {}",
            tri_word(result.props.reassembles)
        );
        let _ = writeln!(
            out,
            "  разбирает протокол:        {}",
            tri_word(result.props.parses_l7)
        );
        let _ = writeln!(
            out,
            "  проверяет контр. сумму:    {}",
            tri_word(result.props.validates_checksum)
        );
        let _ = writeln!(
            out,
            "  держит переупорядочивание: {}",
            tri_word(result.props.tolerates_reorder)
        );
        let _ = writeln!(
            out,
            "  держит перекрытие слева:   {}",
            tri_word(result.props.tolerates_left_overlap)
        );
        if let Some(ttl) = result.props.hop_ttl.filter(|ttl| *ttl > 0) {
            let _ = writeln!(out, "  расстояние до неё:         {ttl} хопов");
        }
    }
    out.push_str("Трасса:\n");
    for observation in &result.trace {
        let cuts = if observation.cuts.is_empty() {
            "-".to_owned()
        } else {
            format!(
                "[{}]",
                observation
                    .cuts
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        };
        let _ = writeln!(
            out,
            "  {:<11} cuts={:<8} пауза={}мс  прошло={} не прошло={} {}",
            observation.probe,
            cuts,
            observation.delay.as_millis(),
            observation.pass,
            observation.fail,
            observation.error.as_deref().unwrap_or("")
        );
    }
    out
}

fn atoi(value: &str) -> i64 {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    let mut sign = 1_i64;
    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        if bytes[index] == b'-' {
            sign = -1;
        }
        index += 1;
    }
    let mut value = 0_i64;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add(i64::from(bytes[index] - b'0'));
        index += 1;
    }
    value.saturating_mul(sign)
}

/// C `strtoul(value, NULL, 0)` в объёме, нужном detect CLI.
fn strtoul(value: &str) -> u32 {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    let mut negative = false;
    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        negative = bytes[index] == b'-';
        index += 1;
    }
    let (radix, prefix) = if bytes[index..].starts_with(b"0x") || bytes[index..].starts_with(b"0X")
    {
        (16, 2)
    } else if index < bytes.len() && bytes[index] == b'0' {
        (8, 1)
    } else {
        (10, 0)
    };
    index += prefix;
    let mut parsed = 0_u64;
    let mut any = false;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => u64::from(bytes[index] - b'0'),
            b'a'..=b'f' => u64::from(bytes[index] - b'a') + 10,
            b'A'..=b'F' => u64::from(bytes[index] - b'A') + 10,
            _ => break,
        };
        if digit >= u64::from(radix as u32) {
            break;
        }
        parsed = parsed
            .saturating_mul(u64::from(radix as u32))
            .saturating_add(digit);
        any = true;
        index += 1;
    }
    if !any {
        return 0;
    }
    let parsed = if negative {
        parsed.wrapping_neg()
    } else {
        parsed
    };
    parsed as u32
}

fn parse_duration_ms(value: &str) -> Duration {
    let millis = atoi(value);
    if millis <= 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(millis as u64)
    }
}

fn target_name(address: &str) -> &str {
    // C `main.c`: имя до последнего двоеточия, без отдельной разборки
    // IPv6-скобок.
    address.rsplit_once(':').map_or(address, |(host, _)| host)
}

fn target_trigger(
    sni: Option<&str>,
    raw: Option<&str>,
    address: &str,
    modern: bool,
) -> Result<Trigger, DetectError> {
    if let Some(hex) = raw {
        return Trigger::raw_hex(hex).map_err(|error| DetectError::trigger(format!("{error}")));
    }
    let name = sni.unwrap_or_else(|| target_name(address));
    if name.is_empty() {
        return Err(DetectError::trigger("classify: пустой SNI"));
    }
    let hello = if modern {
        Trigger::tls13(name)
    } else {
        Trigger::tls(name)
    };
    hello.map_err(|_| {
        DetectError::trigger(format!("classify: приветствие для «{name}» не собралось"))
    })
}

fn control_trigger(
    control_sni: Option<&str>,
    control_raw: Option<&str>,
    target_sni: Option<&str>,
) -> Result<(Option<Trigger>, bool), DetectError> {
    if let Some(hex) = control_raw {
        let mut trigger =
            Trigger::raw_hex(hex).map_err(|error| DetectError::trigger(format!("{error}")))?;
        trigger.name = "control".into();
        trigger.accept = Accept::TlsRecord;
        return Ok((Some(trigger), false));
    }
    let Some(name) = control_sni else {
        let mut trigger = Trigger::tls13("probe-d2k.invalid-control.example")
            .map_err(|error| DetectError::trigger(format!("{error}")))?;
        trigger.name = "control".into();
        trigger.accept = Accept::TlsRecord;
        return Ok((Some(trigger), false));
    };
    if target_sni == Some(name) {
        return Err(DetectError::cli(
            "classify: --control-sni совпадает с --sni; контролем должно быть ДРУГОЕ имя, заведомо не блокируемое",
        ));
    }
    match Trigger::tls13(name) {
        Ok(mut trigger) => {
            trigger.name = format!("control:{name}");
            // C `main.c:419-423` не меняет accept для `--control-sni`:
            // остаётся строгий ServerHello из `d2k_trigger_tls`; мягкий
            // TlsRecord — только у безымянного default control.
            Ok((Some(trigger), true))
        }
        // C `main.c:419-423`: ошибка сборки контрольного имени не отменяет
        // замер, а просто оставляет control пустым.
        Err(_) => Ok((None, false)),
    }
}

fn parse_options(
    arguments: &[OsString],
    address: &str,
) -> Result<(DetectOptions, Trigger), DetectError> {
    let mut options = DetectOptions {
        // C `d2k_opts_defaults`: нули заменяются значениями по умолчанию.
        repeats: 0,
        timeout: Duration::ZERO,
        write_gap: Duration::ZERO,
        long_gap: Duration::ZERO,
        mark: 0,
        ..DetectOptions::default()
    };
    let mut sni: Option<String> = None;
    let mut raw: Option<String> = None;
    let mut control_sni: Option<String> = None;
    let mut control_raw: Option<String> = None;
    let mut white_name: Option<String> = None;
    let mut modern = true;
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].to_str() else {
            return Err(DetectError::usage("classify: параметр должен быть UTF-8"));
        };
        let next = |index: usize| {
            arguments
                .get(index + 1)
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    // C `main.c`: флаг без значения не совпал ни с одной
                    // ветвью и попал в «неизвестный флаг».
                    DetectError::usage(format!("classify: неизвестный флаг {argument}"))
                })
        };
        match argument {
            "--sni" => {
                sni = Some(next(index)?.to_owned());
                index += 2;
            }
            "--raw" => {
                raw = Some(next(index)?.to_owned());
                index += 2;
            }
            "--repeats" => {
                options.repeats = atoi(next(index)?).max(0) as usize;
                index += 2;
            }
            "--timeout" => {
                options.timeout = parse_duration_ms(next(index)?);
                index += 2;
            }
            "--write-gap" => {
                options.write_gap = parse_duration_ms(next(index)?);
                index += 2;
            }
            "--long-gap" => {
                options.long_gap = parse_duration_ms(next(index)?);
                index += 2;
            }
            "--only" => {
                let value = next(index)?.to_owned();
                // C `only[0] == '\0'` означает «без фильтра».
                options.only_poison = (!value.is_empty()).then_some(value);
                index += 2;
            }
            "--skip" => {
                let value = next(index)?.to_owned();
                if options.skip_poisons.len() < D2K_SKIP_MAX {
                    options.skip_poisons.push(value);
                }
                index += 2;
            }
            "--control-sni" => {
                control_sni = Some(next(index)?.to_owned());
                index += 2;
            }
            "--white" => {
                white_name = Some(next(index)?.to_owned());
                index += 2;
            }
            "--control-raw" => {
                control_raw = Some(next(index)?.to_owned());
                index += 2;
            }
            "--hello" => {
                match next(index)? {
                    "modern" => modern = true,
                    "legacy" => modern = false,
                    value => {
                        return Err(DetectError::cli(format!(
                            "classify: --hello может быть modern или legacy, а не «{value}»"
                        )));
                    }
                }
                index += 2;
            }
            "--no-raw" => {
                options.no_raw = true;
                index += 1;
            }
            "--mark" => {
                options.mark = strtoul(next(index)?);
                index += 2;
            }
            "--allow-loopback" => {
                options.allow_loopback = true;
                index += 1;
            }
            "--json" => {
                options.json = true;
                index += 1;
            }
            "--dump-trigger" => {
                options.dump_trigger = true;
                index += 1;
            }
            "--progress" => {
                options.progress = true;
                index += 1;
            }
            _ => {
                return Err(DetectError::usage(format!(
                    "classify: неизвестный флаг {argument}"
                )));
            }
        }
    }
    if raw.is_some() && sni.is_some() {
        return Err(DetectError::cli(
            "classify: --sni и --raw взаимоисключающие",
        ));
    }
    if let Some(name) = sni.as_deref() {
        if name.len() >= 254 {
            return Err(DetectError::cli("classify: SNI длиннее 253 байт"));
        }
    } else if raw.is_none() && target_name(address).len() >= 254 {
        return Err(DetectError::cli("classify: имя узла длиннее 253 байт"));
    }
    let trigger = target_trigger(sni.as_deref(), raw.as_deref(), address, modern)?;
    if options.dump_trigger {
        return Ok((options, trigger));
    }
    if control_raw.is_some() && control_sni.is_some() {
        return Err(DetectError::cli(
            "classify: --control-raw и --control-sni взаимоисключающие",
        ));
    }
    let (control, vouched) = control_trigger(
        control_sni.as_deref(),
        control_raw.as_deref(),
        sni.as_deref(),
    )?;
    options.control = control;
    options.control_vouched = vouched;
    if let Some(name) = white_name {
        let payload = crate::hello::r2o_rx_fake_client_hello(&name).map_err(|_| {
            DetectError::cli(format!(
                "classify: --white {name}: приветствие не собралось"
            ))
        })?;
        options.white = Some(Trigger {
            name: "white".into(),
            payload,
            accept: Accept::TlsRecord,
        });
    }
    Ok((options, trigger))
}

/// C `main`: `d2k-detect classify <host:port> [флаги]`.
pub fn run(
    arguments: &[OsString],
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
) -> i32 {
    if arguments.len() < 2 || arguments[0] != "classify" {
        let mut text = String::new();
        usage(&mut text);
        let _ = stderr.write_all(text.as_bytes());
        return 2;
    }
    let address = arguments[1].to_string_lossy().into_owned();
    let (mut options, trigger) = match parse_options(&arguments[2..], &address) {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = writeln!(stderr, "{}", error.message);
            if error.show_usage {
                let mut text = String::new();
                usage(&mut text);
                let _ = stderr.write_all(text.as_bytes());
            }
            return error.code;
        }
    };
    if options.dump_trigger {
        for byte in &trigger.payload {
            let _ = write!(stdout, "{byte:02x}");
        }
        let _ = writeln!(stdout);
        return 0;
    }
    if options.repeats == 0 {
        options.repeats = 3;
    }
    if options.timeout.is_zero() {
        options.timeout = Duration::from_millis(6000);
    }
    if options.write_gap.is_zero() {
        options.write_gap = Duration::from_millis(60);
    }
    if options.long_gap.is_zero() {
        options.long_gap = Duration::from_millis(700);
    }
    if options.mark == 0 {
        options.mark = D2K_BYPASS_MARK;
    }
    let started = Instant::now();
    let progress_enabled = options.progress;
    let repeats = options.repeats;
    let mut progress = |probe: &str, _probes: usize, passed: usize, failed: usize| {
        let completed = passed.saturating_add(failed);
        let observation_complete = completed >= repeats
            || (probe == "control" || probe == "neutral-ack") && passed > 0
            || probe.starts_with("transport:");
        if progress_enabled && completed > 0 && observation_complete {
            let _ = writeln!(
                stderr,
                "  [{:4} с] {:<28} прошло={} не прошло={}",
                started.elapsed().as_secs(),
                probe,
                passed,
                failed
            );
        }
    };
    let classify_options = ClassifyOptions {
        repeats: options.repeats,
        timeout: options.timeout,
        write_gap: options.write_gap,
        long_gap: options.long_gap,
        allow_loopback: options.allow_loopback,
        no_raw: options.no_raw,
        full_detect_semantics: true,
        confirm_clear: false,
        only_poison: options.only_poison,
        skip_poisons: options.skip_poisons,
        control: options.control,
        white: options.white,
        control_vouched: options.control_vouched,
        trigger_snapped: false,
        client_tcp_has_timestamps: None,
        mark: Some(options.mark),
        cancel: None,
        seed_whole: None,
        cross_check_tls12: false,
    };
    let result = run_with_backend_progress(
        &address,
        &trigger,
        classify_options,
        &mut TcpProbeBackend,
        &mut progress,
    );
    if options.json {
        let _ = stdout.write_all(format_json(&result, trigger.payload.len()).as_bytes());
        let _ = stdout.flush();
    } else {
        let _ = stdout.write_all(format_human(&result, &trigger, trigger.payload.len()).as_bytes());
        let _ = stdout.flush();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Observation, PoisonHit, Verdict};

    fn sample() -> ClassifyResult {
        let mut result = ClassifyResult::new("example.com:443", 3);
        result.verdict = Verdict::Prefix;
        result.reason = "префиксный матчер".into();
        result.probes = 9;
        result.duration = Duration::from_millis(42);
        result.boundary = Some(7);
        result.split_pos = Some(1);
        result.reassembles = Some(false);
        result.strategy = Some("--lua-desync=multisplit".into());
        result.props = crate::classify::DpiProps {
            reassembles: TriState::False,
            parses_l7: TriState::True,
            ..Default::default()
        };
        result.path = Some("перебор".into());
        result.hit = Some(PoisonHit {
            name: "seqovl-1".into(),
            strategy: "s".into(),
            plan_text: String::new(),
            plan: Vec::new(),
            gap_ms: 0,
        });
        result.raw_usable = true;
        result.trace = vec![Observation {
            probe: "whole".into(),
            cuts: vec![1, 2],
            delay: Duration::from_millis(60),
            pass: 3,
            fail: 0,
            error: None,
        }];
        result.notes = vec!["оговорка".into()];
        result
    }

    #[test]
    fn json_shape_matches_c_field_order() {
        let text = format_json(&sample(), 41);
        assert!(text.starts_with("{\n  \"target\": \"example.com:443\""));
        assert!(text.contains(",\n  \"verdict\": \"prefix\""));
        assert!(text.contains(",\n  \"duration\": \"42ms\""));
        assert!(text.contains(",\n  \"boundary\": 7"));
        assert!(text.contains(",\n  \"props\": {\n    \"reassembles\": false"));
        assert!(text.contains(",\n    \"parses_l7\": true\n  }"));
        assert!(text.contains(",\n  \"trace\": ["));
        assert!(text.ends_with("\n  ]\n}\n"));
    }

    #[test]
    fn human_shape_matches_c_labels() {
        let trigger = Trigger::raw_hex("5741").unwrap();
        let text = format_human(&sample(), &trigger, 2);
        assert!(text.contains("Цель:     example.com:443\n"));
        assert!(text.contains("Триггер:  raw:2B (2 байт)\n"));
        assert!(text.contains("Вердикт:  prefix — префиксный матчер\n"));
        assert!(text.contains("Граница:  сигнатура кончается на байте 7\n"));
        assert!(text.contains("Стратегия: --lua-desync=multisplit\n"));
        assert!(text.contains("Трасса:\n  whole       cuts=[1 2]"));
    }

    #[test]
    fn c_strtoul_and_atoi_accept_detect_forms() {
        assert_eq!(strtoul("0x40000000"), 0x4000_0000);
        assert_eq!(strtoul("010"), 8);
        assert_eq!(strtoul("42"), 42);
        assert_eq!(strtoul("not-a-number"), 0);
        assert_eq!(atoi("  -12ms"), -12);
        assert_eq!(atoi("7"), 7);
    }
}
