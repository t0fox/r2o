//! Консервативный компилятор поддерживаемого подмножества Geneva в R2OP.
//!
//! Компилятор принимает только те деревья, для которых существующий
//! формат R2OP может выразить тот же набор пакетов.
//!
//! Для сравнения пакетов на ПК поддерживаются `duplicate(,tamper{...})`
//! и `fragment{tcp:...}` на одном ClientHello с точными флагами PA.
//! R2OP сохраняет условие на исходный TCP-пакет.

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

fn compile_text(
    strategy: &GenevaStrategy,
    payload: &[u8],
    flags: u16,
    plan_id: [u8; 16],
) -> Result<String, GenevaCompileError> {
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
            "поддержан только точный триггер [TCP:flags:PA]",
        ));
    }
    // Geneva сравнивает каноническую строку из заголовка. AP и числовое
    // значение 24 в исходной стратегии не совпадают с PA даже при той же маске.
    if !matches!(&tree.trigger.value, GenevaValue::Text(value) if value == "PA") {
        return Err(GenevaCompileError::new(
            "TCP-стратегия R2OP поддерживает только триггер PA на ClientHello",
        ));
    }
    if flags != 0x18 {
        return Err(GenevaCompileError::new(
            "TCP-флаги пакета не совпали с триггером PA",
        ));
    }
    let Some(action) = tree.action.as_ref() else {
        return Err(GenevaCompileError::new("пустое дерево не даёт плана"));
    };
    match &action.kind {
        GenevaActionKind::Duplicate => compile_duplicate(action, payload, plan_id),
        GenevaActionKind::Fragment {
            segment,
            fragsize,
            overlap,
            in_order,
        } => compile_fragment(
            action, *segment, *fragsize, *overlap, *in_order, payload, plan_id,
        ),
        _ => Err(GenevaCompileError::new(format!(
            "корневое действие {} не выражается: нужен duplicate или fragment{{tcp:...}}",
            action_name(&action.kind)
        ))),
    }
}

fn compile_duplicate(
    action: &GenevaAction,
    payload: &[u8],
    plan_id: [u8; 16],
) -> Result<String, GenevaCompileError> {
    if payload.is_empty() {
        return Err(GenevaCompileError::new(
            "для duplicate нужна непустая нагрузка оригинала",
        ));
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
    text.push_str("r2o-plan 1 15\n");
    text.push_str(&format!("id {}\n", hex(&plan_id)));
    text.push_str("proto tcp tls\n");
    text.push_str("input tcp-flags PA\n");
    if fields.iter().any(|field| field == "md5") {
        text.push_str("wire detect-tcp-v1\n");
    }
    text.push_str(&format!("payload 1 {}\n", hex(payload)));
    text.push_str(&format!("poison 1 {}\n", fields.join(" ")));
    text.push_str("fake payload=1 poison=1 repeats=1 gap_us=0 place=after\n");
    text.push_str("order forward\n");
    Ok(text)
}

/// Geneva `fragment{tcp:N:True|False}`: два TCP-сегмента с общей
/// последовательностью. R2OP выражает это `split` без фальшивок.
fn compile_fragment(
    action: &GenevaAction,
    segment: bool,
    fragsize: i32,
    overlap: i32,
    in_order: bool,
    payload: &[u8],
    plan_id: [u8; 16],
) -> Result<String, GenevaCompileError> {
    if !segment {
        return Err(GenevaCompileError::new(
            "fragment{ip:...} не выражается TCP-разрезом R2OP",
        ));
    }
    if action.left.is_some() || action.right.is_some() {
        return Err(GenevaCompileError::new(
            "fragment с правками кусков не выражается: R2OP не даёт отдельный poison на кусок",
        ));
    }
    if overlap != 0 {
        return Err(GenevaCompileError::new(
            "fragment с перекрытием не выражается: нужен seqovl, а не split",
        ));
    }
    if payload.len() < 2 {
        return Err(GenevaCompileError::new(
            "для разреза нужны минимум два байта нагрузки",
        ));
    }
    let split = if fragsize == -1 || fragsize > 0 && fragsize as usize >= payload.len() {
        "hello_middle +0".to_owned()
    } else if fragsize > 0 {
        format!("payload_start +{fragsize}")
    } else {
        return Err(GenevaCompileError::new(
            "fragment{tcp:...} требует положительный размер или -1",
        ));
    };
    Ok(fragment_plan(&split, in_order, plan_id))
}

fn fragment_plan(split: &str, in_order: bool, plan_id: [u8; 16]) -> String {
    let order = if in_order { "forward" } else { "reverse" };
    format!(
        "r2o-plan 1 15\nid {}\nproto tcp tls\ninput tcp-flags PA\nsplit {split}\norder {order}\n",
        hex(&plan_id)
    )
}

/// Один проверенный разрез для короткого именного TLS 1.2 ClientHello.
pub fn discovery_midpoint_candidate(client_hello: &[u8], send_cap: usize) -> Option<String> {
    // Первый штатный кусочный план режет на 178 байтах и для такого
    // приветствия оставляет пакет целым.
    if !(5..=178).contains(&client_hello.len())
        || (send_cap != 0 && client_hello.len().div_ceil(2) + 100 > send_cap)
    {
        return None;
    }
    let tls = r2k_core::tls::parse(client_hello);
    (tls.is_client_hello
        && !tls.is_tls13
        && !tls.ech_offer
        && !tls.extensions_truncated
        && tls.sni_range.is_some()
        && tls.record_end == Some(client_hello.len()))
    .then(|| fragment_plan("hello_middle +0", true, [0; 16]))
}

/// Скомпилировать R2OP для офлайн-проверки конкретного IP-пакета с ClientHello.
pub fn compile_plan_for_packet(
    strategy: &GenevaStrategy,
    packet: &[u8],
    plan_id: [u8; 16],
) -> Result<Vec<u8>, GenevaCompileError> {
    let view = r2k_core::packet::PacketView::parse(packet)
        .ok_or_else(|| GenevaCompileError::new("неверный IP-пакет"))?;
    if view.fragment & 0x3fff != 0 {
        return Err(GenevaCompileError::new(
            "фрагментированный IP-пакет не поддержан",
        ));
    }
    let tcp = view
        .tcp_segment(packet)
        .ok_or_else(|| GenevaCompileError::new("Geneva требуется TCP-пакет"))?;
    let payload = &packet[tcp.payload];
    let tls = r2k_core::tls::parse(payload);
    if !tls.is_client_hello || tls.extensions_truncated || tls.record_end != Some(payload.len()) {
        return Err(GenevaCompileError::new(
            "требуется полный ClientHello в одном TCP-пакете",
        ));
    }
    compile_strategy(strategy, payload, tcp.wire_flags, plan_id)
}

fn compile_strategy(
    strategy: &GenevaStrategy,
    payload: &[u8],
    flags: u16,
    plan_id: [u8; 16],
) -> Result<Vec<u8>, GenevaCompileError> {
    let text = compile_text(strategy, payload, flags, plan_id)?;
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
    use super::{compile_strategy, compile_text};
    use crate::geneva::parse_strategy;
    use crate::geneva_library::GENEVA_LIBRARY;
    use r2k_core::plan::Plan;

    const CLIENT_HELLO: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];

    fn compile(strategy: &str) -> Result<Vec<u8>, String> {
        let parsed = parse_strategy(strategy).map_err(|error| error.to_string())?;
        compile_strategy(&parsed, CLIENT_HELLO, 0x18, [0x42; 16]).map_err(|error| error.to_string())
    }

    #[test]
    fn duplicate_right_tamper_becomes_after_fake() {
        let bytes = compile(
            "[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-",
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
            "[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10}(tamper{TCP:ack:corrupt},),))-",
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
            "[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:FRAPUN}(tamper{TCP:options-md5header:corrupt},))-",
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
    fn tcp_fragment_becomes_split_with_matching_order() {
        let bytes = compile("[TCP:flags:PA]-fragment{tcp:8:True}-").expect("fragment in order");
        let plan = Plan::parse(&bytes).expect("parse");
        assert_eq!(plan.splits.len(), 1);
        assert_eq!(plan.splits[0].anchor, 0, "payload_start");
        assert_eq!(plan.splits[0].offset, 8);
        assert_eq!(plan.order, 0, "forward");

        let bytes = compile("[TCP:flags:PA]-fragment{tcp:-1:False}-").expect("fragment reverse");
        let plan = Plan::parse(&bytes).expect("parse");
        assert_eq!(plan.splits[0].anchor, 3, "hello_middle");
        assert_eq!(plan.splits[0].offset, 0);
        assert_eq!(plan.order, 1, "reverse");
    }

    #[test]
    fn fragment_with_children_or_ip_mode_is_rejected() {
        for strategy in [
            "[TCP:flags:PA]-fragment{tcp:8:True}(tamper{TCP:chksum:corrupt},)-",
            "[TCP:flags:PA]-fragment{ip:8:True}-",
            "[TCP:flags:PA]-fragment{tcp:0:True}-",
        ] {
            assert!(
                compile(strategy).is_err(),
                "должна быть отвергнута: {strategy}"
            );
        }
    }

    #[test]
    fn tampered_original_and_other_actions_are_rejected_explicitly() {
        for strategy in [
            "[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:R},)-",
            "[TCP:flags:PA]-drop-",
            "[TCP:flags:PA]-duplicate(,tamper{TCP:chksum:replace:1})-",
            "[TCP:flags:PA]-duplicate(,tamper{TCP:options-wscale:corrupt})-",
            "[TCP:flags:PA]-duplicate(,tamper{TCP:dataofs:replace:0})-",
            "[TCP:flags:PA]-duplicate(,tamper{IP:ttl:replace:0})-",
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
            "[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-| \\/ [TCP:flags:PA]-drop-|",
        )
        .unwrap();
        assert!(compile_strategy(&strategy, CLIENT_HELLO, 0x18, [1; 16]).is_err());
    }

    #[test]
    fn library_has_compilable_subset_and_every_entry_is_classified() {
        let mut unique_plans = std::collections::BTreeSet::new();
        let mut compiled = 0;
        let mut rejected = 0;
        for entry in GENEVA_LIBRARY {
            let Ok(strategy) = parse_strategy(entry) else {
                rejected += 1;
                continue;
            };
            match compile_strategy(&strategy, CLIENT_HELLO, 0x18, [7; 16]) {
                Ok(bytes) => {
                    compiled += 1;
                    unique_plans.insert(bytes);
                }
                Err(error) => {
                    assert!(!error.message().is_empty());
                    rejected += 1;
                }
            }
        }
        println!("geneva library: compiled={compiled} rejected={rejected}");
        assert_eq!(compiled, 2);
        assert_eq!(unique_plans.len(), 1, "остается один разрез PA");
        assert_eq!(rejected, 56);
        assert_eq!(compiled + rejected, GENEVA_LIBRARY.len());
    }

    #[test]
    fn compile_text_returns_r2op_text_without_panic() {
        let strategy =
            parse_strategy("[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:R})-").unwrap();
        let text = compile_text(&strategy, CLIENT_HELLO, 0x18, [3; 16]).unwrap();
        assert!(text.starts_with("r2o-plan 1 15\n"));
        assert!(text.contains("place=after"));
        assert!(text.contains("tcp_flags=4"));
    }
}
