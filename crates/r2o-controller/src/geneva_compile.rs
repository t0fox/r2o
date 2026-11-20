//! Консервативный компилятор поддерживаемого подмножества Geneva в R2OP.
//!
//! Это продолжение `docs/geneva-c-adoption.md`: Geneva-стратегия не
//! исполняется вторым движком, а переводится в существующий план r2o.
//! Компилятор намеренно узкий: он принимает только те деревья, для которых
//! R2OP умеет выразить **тот же набор пакетов**.
//!
//! Сейчас поддержана форма `[TCP:flags:...]-duplicate(,tamper{...})`:
//! Geneva отправляет оригинал, затем изменённую копию; R2OP выражает это
//! как `fake ... place=after` (P2.2). Всё остальное отвергается с явной
//! причиной, без «похожей» аппроксимации.

use std::fmt;

use crate::geneva::{
    GenevaAction, GenevaActionKind, GenevaLayer, GenevaStrategy, GenevaTamper, GenevaTamperKind,
    GenevaValue, tcp_flags_parse,
};

/// Ошибка компиляции Geneva-стратегии.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenevaCompileError(String);

impl GenevaCompileError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// Текст ошибки для отчёта/журнала.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GenevaCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for GenevaCompileError {}

/// Скомпилировать стратегию в текст R2OP для указанной нагрузки.
///
/// `payload` — транспортная нагрузка первого пакета потока (обычно
/// ClientHello). `plan_id` — 16 байт идентификатора плана.
pub fn compile_text(
    strategy: &GenevaStrategy,
    payload: &[u8],
    plan_id: [u8; 16],
) -> Result<String, GenevaCompileError> {
    if payload.is_empty() {
        return Err(GenevaCompileError::new(
            "для duplicate нужна непустая нагрузка оригинала",
        ));
    }
    if !strategy.inbound.is_empty() {
        return Err(GenevaCompileError::new(
            "входящий лес Geneva не выражается TCP-планом R2OP",
        ));
    }
    if strategy.out.len() != 1 {
        return Err(GenevaCompileError::new(format!(
            "R2OP-план выражает одно дерево, а в стратегии {}",
            strategy.out.len()
        )));
    }
    let tree = &strategy.out[0];
    if tree.trigger.layer != GenevaLayer::Tcp
        || tree.trigger.field != "flags"
        || tree.trigger.wildcard
        || tree.trigger.gas.is_some()
    {
        return Err(GenevaCompileError::new(
            "поддержан только простой триггер [TCP:flags:...]",
        ));
    }
    let Some(action) = tree.action.as_ref() else {
        return Err(GenevaCompileError::new("пустое дерево не даёт плана"));
    };
    if !matches!(&action.kind, GenevaActionKind::Duplicate) {
        return Err(GenevaCompileError::new(format!(
            "корневое действие {} не выражается: нужен duplicate",
            action_name(&action.kind)
        )));
    }
    if action.left.is_some() {
        return Err(GenevaCompileError::new(
            "duplicate(tamper{...},) меняет оригинал; R2OP меняет только фальшивку",
        ));
    }
    let mut tampers = Vec::new();
    collect_tamper_chain(action.right.as_deref(), &mut tampers)?;
    if tampers.is_empty() {
        return Err(GenevaCompileError::new(
            "duplicate без изменённой правой ветви нечего отправлять",
        ));
    }

    let fields = plan_poison_fields(&tampers)?;
    let mut text = String::new();
    text.push_str("r2o-plan 1 14\n");
    text.push_str(&format!("id {}\n", hex(&plan_id)));
    text.push_str("proto tcp tls\n");
    if fields.iter().any(|field| field == "md5") {
        text.push_str("wire detect-tcp-v1\n");
    }
    text.push_str(&format!("payload 1 {}\n", hex(payload)));
    text.push_str(&format!("poison 1 {}\n", fields.join(" ")));
    text.push_str("fake payload=1 poison=1 repeats=1 gap_us=0 place=after\n");
    text.push_str("order forward\n");
    Ok(text)
}

/// Скомпилировать стратегию сразу в проверенные байты R2OP.
pub fn compile_plan(
    strategy: &GenevaStrategy,
    payload: &[u8],
    plan_id: [u8; 16],
) -> Result<Vec<u8>, GenevaCompileError> {
    let text = compile_text(strategy, payload, plan_id)?;
    let bytes = crate::plan_text::compile_text(&text)
        .map_err(|error| GenevaCompileError::new(format!("R2OP: {error}")))?;
    let plan = r2k_core::plan::Plan::parse(&bytes)
        .map_err(|error| GenevaCompileError::new(format!("R2OP: {error}")))?;
    r2o_datapath::engine::validate_runtime_plan(&plan)
        .map_err(|error| GenevaCompileError::new(format!("runtime: {error}")))?;
    Ok(bytes)
}

fn action_name(kind: &GenevaActionKind) -> &'static str {
    match kind {
        GenevaActionKind::Tamper(_) => "tamper",
        GenevaActionKind::Duplicate => "duplicate",
        GenevaActionKind::Fragment { .. } => "fragment",
        GenevaActionKind::Drop => "drop",
        GenevaActionKind::Sleep { .. } => "sleep",
        GenevaActionKind::Trace { .. } => "trace",
    }
}

fn collect_tamper_chain<'a>(
    action: Option<&'a GenevaAction>,
    tampers: &mut Vec<&'a GenevaTamper>,
) -> Result<(), GenevaCompileError> {
    let mut current = action;
    while let Some(action) = current {
        match &action.kind {
            GenevaActionKind::Tamper(tamper) => {
                if action.right.is_some() {
                    return Err(GenevaCompileError::new("у tamper не бывает правой ветви"));
                }
                tampers.push(tamper);
                current = action.left.as_deref();
            }
            other => {
                return Err(GenevaCompileError::new(format!(
                    "действие {} внутри duplicate не выражается R2OP",
                    action_name(other)
                )));
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct PoisonFields {
    badsum: bool,
    md5: bool,
    ttl: Option<u8>,
    dataofs: Option<u8>,
    tcp_flags: Option<u16>,
    ack_corrupt: bool,
    ip_len: Option<u16>,
    tcp_window: Option<u16>,
    seq_shift: Option<i32>,
}

fn plan_poison_fields(tampers: &[&GenevaTamper]) -> Result<Vec<String>, GenevaCompileError> {
    let mut fields = PoisonFields::default();
    for tamper in tampers {
        let value = tamper.value.as_ref();
        match (tamper.layer, tamper.field.as_str(), tamper.kind) {
            (GenevaLayer::Tcp, "chksum", GenevaTamperKind::Corrupt) => fields.badsum = true,
            (GenevaLayer::Tcp, "options-md5header", GenevaTamperKind::Corrupt) => {
                fields.md5 = true;
            }
            (GenevaLayer::Tcp, "dataofs", GenevaTamperKind::Replace) => {
                fields.dataofs = Some(int_value(value, 1, 15, "TCP:dataofs")? as u8);
            }
            (GenevaLayer::Tcp, "flags", GenevaTamperKind::Replace) => {
                let text = match value {
                    Some(GenevaValue::Text(text)) => text.clone(),
                    Some(GenevaValue::Int(number)) => number.to_string(),
                    None => {
                        return Err(GenevaCompileError::new("TCP:flags:replace без значения"));
                    }
                };
                fields.tcp_flags = Some(tcp_flags_parse(&text).ok_or_else(|| {
                    GenevaCompileError::new("TCP:flags:replace: неизвестные флаги")
                })?);
            }
            (GenevaLayer::Tcp, "ack", GenevaTamperKind::Corrupt) => fields.ack_corrupt = true,
            (GenevaLayer::Tcp, "window", GenevaTamperKind::Replace) => {
                fields.tcp_window = Some(int_value(value, 0, 65_535, "TCP:window")? as u16);
            }
            (GenevaLayer::Tcp, "seq", GenevaTamperKind::Add) => {
                fields.seq_shift =
                    Some(int_value(value, i32::MIN as i64, i32::MAX as i64, "TCP:seq:add")? as i32);
            }
            (GenevaLayer::Ip, "ttl", GenevaTamperKind::Replace) => {
                fields.ttl = Some(int_value(value, 1, 255, "IP:ttl")? as u8);
            }
            (GenevaLayer::Ip, "len", GenevaTamperKind::Replace) => {
                fields.ip_len = Some(int_value(value, 0, 65_535, "IP:len")? as u16);
            }
            _ => {
                return Err(GenevaCompileError::new(format!(
                    "tamper {}:{}:{:?} не выражается R2OP",
                    tamper.proto, tamper.field, tamper.kind
                )));
            }
        }
    }

    let mut out = Vec::new();
    if fields.badsum {
        out.push("badsum".to_owned());
    }
    if fields.md5 {
        out.push("md5".to_owned());
    }
    if let Some(ttl) = fields.ttl {
        out.push(format!("ttl={ttl}"));
    }
    if let Some(dataofs) = fields.dataofs {
        out.push(format!("dataofs={dataofs}"));
    }
    if let Some(flags) = fields.tcp_flags {
        out.push(format!("tcp_flags={flags}"));
    }
    if fields.ack_corrupt {
        out.push("ack=corrupt".to_owned());
    }
    if let Some(len) = fields.ip_len {
        out.push(format!("ip_len={len}"));
    }
    if let Some(window) = fields.tcp_window {
        out.push(format!("window={window}"));
    }
    if let Some(shift) = fields.seq_shift {
        out.push(format!("seqshift={shift}"));
    }
    if out.is_empty() {
        return Err(GenevaCompileError::new(
            "ни одного поддерживаемого tamper-поля",
        ));
    }
    Ok(out)
}

fn int_value(
    value: Option<&GenevaValue>,
    minimum: i64,
    maximum: i64,
    name: &str,
) -> Result<i64, GenevaCompileError> {
    let Some(GenevaValue::Int(number)) = value else {
        return Err(GenevaCompileError::new(format!(
            "{name}: нужно целое значение"
        )));
    };
    if *number < minimum || *number > maximum {
        return Err(GenevaCompileError::new(format!(
            "{name}: значение {number} вне {minimum}..{maximum}"
        )));
    }
    Ok(*number)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{compile_plan, compile_text};
    use crate::geneva::parse_strategy;
    use crate::geneva_library::GENEVA_LIBRARY;
    use r2k_core::plan::Plan;

    const CLIENT_HELLO: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];

    fn compile(strategy: &str) -> Result<Vec<u8>, String> {
        let parsed = parse_strategy(strategy).map_err(|error| error.to_string())?;
        compile_plan(&parsed, CLIENT_HELLO, [0x42; 16]).map_err(|error| error.to_string())
    }

    #[test]
    fn duplicate_right_tamper_becomes_after_fake() {
        let bytes = compile(
            "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-",
        )
        .expect("compile");
        let plan = Plan::parse(&bytes).expect("parse");
        assert_eq!(plan.fakes.len(), 1);
        assert_eq!(plan.fakes[0].placement, 2, "place=after");
        assert_eq!(plan.fakes[0].payload_id, 1);
        assert_eq!(plan.poisons[0].tcp_flags, Some(0x04));
        assert_eq!(plan.poisons[0].flags, 1, "badsum");
        assert_eq!(plan.payloads[0].bytes, CLIENT_HELLO);
    }

    #[test]
    fn duplicate_with_ttl_and_ack_corrupt_combines_in_one_poison() {
        let bytes = compile(
            "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10}(tamper{TCP:ack:corrupt},),))-",
        )
        .expect("compile");
        let plan = Plan::parse(&bytes).expect("parse");
        assert_eq!(plan.poisons[0].tcp_flags, Some(0x14));
        assert_eq!(plan.poisons[0].ttl, 10);
        assert!(plan.poisons[0].ack_corrupt);
    }

    #[test]
    fn md5_option_tamper_selects_detect_tcp_wire_profile() {
        let bytes = compile(
            "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUN}(tamper{TCP:options-md5header:corrupt},))-",
        )
        .expect("compile");
        let plan = Plan::parse(&bytes).expect("parse");
        assert_eq!(
            plan.poisons[0].flags & r2k_core::plan::POISON_MD5,
            r2k_core::plan::POISON_MD5
        );
        assert_eq!(plan.wire_profile, r2k_core::plan::WIRE_DETECT_TCP);
    }

    #[test]
    fn duplicate_with_dataofs_and_window_is_supported() {
        let bytes = compile(
            "[TCP:flags:PA]-duplicate(,tamper{TCP:dataofs:replace:10}(tamper{TCP:window:replace:1024},))-",
        )
        .expect("compile");
        let plan = Plan::parse(&bytes).expect("parse");
        assert_eq!(plan.poisons[0].dataofs, Some(10));
        assert_eq!(plan.poisons[0].tcp_window, Some(1024));
    }

    #[test]
    fn tampered_original_and_other_actions_are_rejected_explicitly() {
        for strategy in [
            "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R},)-",
            "[TCP:flags:A]-drop-",
            "[TCP:flags:PA]-fragment{tcp:8:True}-",
            "[TCP:flags:A]-duplicate(,tamper{TCP:chksum:replace:1})-",
            "[TCP:flags:A]-duplicate(,tamper{TCP:options-wscale:corrupt})-",
            "[TCP:flags:A]-duplicate(,tamper{TCP:dataofs:replace:0})-",
            "[TCP:flags:A]-duplicate(,tamper{IP:ttl:replace:0})-",
        ] {
            assert!(
                compile(strategy).is_err(),
                "должна быть отвергнута: {strategy}"
            );
        }
    }

    #[test]
    fn inbound_forest_is_rejected() {
        let strategy = parse_strategy(
            "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-| \\/ [TCP:flags:A]-drop-|",
        )
        .unwrap();
        assert!(compile_plan(&strategy, CLIENT_HELLO, [1; 16]).is_err());
    }

    #[test]
    fn library_has_compilable_subset_and_every_entry_is_classified() {
        let mut compiled = 0;
        let mut rejected = 0;
        for entry in GENEVA_LIBRARY {
            let Ok(strategy) = parse_strategy(entry.strategy) else {
                rejected += 1;
                continue;
            };
            match compile_plan(&strategy, CLIENT_HELLO, [7; 16]) {
                Ok(_) => compiled += 1,
                Err(error) => {
                    assert!(!error.message().is_empty());
                    rejected += 1;
                }
            }
        }
        println!("geneva library: compiled={compiled} rejected={rejected}");
        assert!(
            compiled > 0,
            "подмножество библиотеки должно компилироваться"
        );
        assert!(
            rejected > 0,
            "неподдерживаемые стратегии должны быть явно отвергнуты"
        );
        assert_eq!(compiled + rejected, GENEVA_LIBRARY.len());
    }

    #[test]
    fn compile_text_returns_r2op_text_without_panic() {
        let strategy =
            parse_strategy("[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R})-").unwrap();
        let text = compile_text(&strategy, CLIENT_HELLO, [3; 16]).unwrap();
        assert!(text.starts_with("r2o-plan 1 14\n"));
        assert!(text.contains("place=after"));
        assert!(text.contains("tcp_flags=4"));
    }
}
