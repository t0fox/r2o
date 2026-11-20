//! Разбор, каноническая печать и библиотека стратегий Geneva.
//!
//! Это P1 из `docs/geneva-c-adoption.md`: перенос корпуса и парсера
//! `strategy.c` без второго исполнителя стратегий. Модуль не участвует в
//! production-datapath; его задача — проверяемый импорт Geneva-стратегий,
//! фикстуры и будущая компиляция поддерживаемого подмножества в R2OP.
//!
//! Поведение и тексты канонической печати сверены с geneva_c
//! (`strategy_parse` + `strategy_print`) на 145 записях
//! `tests/geneva_strategies.h` и 58 записях `src/library_data.h`.

use crate::geneva_library::{GENEVA_LIBRARY, GenevaLibraryEntry, GenevaLibraryFilter};

/// Предел вложенности деревьев действий, как `MAX_DEPTH` в geneva_c.
const MAX_DEPTH: usize = 200;

/// Направление леса: исходящий или входящий.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenevaDirection {
    Out,
    In,
}

/// Слой пакета, к которому обращается триггер или tamper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenevaLayer {
    Ip,
    Tcp,
    Udp,
    Dns,
    DnsQr,
    Ipv6,
}

impl GenevaLayer {
    /// `layer_by_name`: регистронезависимые имена и два псевдонима.
    fn parse(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("ip") {
            Some(Self::Ip)
        } else if name.eq_ignore_ascii_case("tcp") {
            Some(Self::Tcp)
        } else if name.eq_ignore_ascii_case("udp") {
            Some(Self::Udp)
        } else if name.eq_ignore_ascii_case("dns") {
            Some(Self::Dns)
        } else if name.eq_ignore_ascii_case("dnsqr")
            || name.eq_ignore_ascii_case("dns question record")
        {
            Some(Self::DnsQr)
        } else if name.eq_ignore_ascii_case("ipv6") || name.eq_ignore_ascii_case("ip6") {
            Some(Self::Ipv6)
        } else {
            None
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Ip => "IP",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Dns => "DNS",
            Self::DnsQr => "DNSQR",
            Self::Ipv6 => "IPv6",
        }
    }

    /// Имена полей из `pkt_fields.c`; сравнение точное, как `layer_has_field`.
    fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Ip => &[
                "version", "ihl", "tos", "len", "id", "flags", "frag", "ttl", "proto", "chksum",
                "src", "dst", "load",
            ],
            Self::Tcp => &[
                "sport",
                "dport",
                "seq",
                "ack",
                "dataofs",
                "reserved",
                "flags",
                "window",
                "chksum",
                "urgptr",
                "load",
                "options-eol",
                "options-nop",
                "options-mss",
                "options-wscale",
                "options-sackok",
                "options-sack",
                "options-timestamp",
                "options-altchksum",
                "options-altchksumopt",
                "options-md5header",
                "options-uto",
            ],
            Self::Udp => &["sport", "dport", "chksum", "len", "load"],
            Self::Dns => &[
                "id", "qr", "opcode", "aa", "tc", "rd", "ra", "z", "ad", "cd", "qd", "rcode",
                "qdcount", "ancount", "nscount", "arcount",
            ],
            Self::DnsQr => &["qname", "qtype", "qclass"],
            Self::Ipv6 => &[
                "version", "tc", "fl", "plen", "nh", "hlim", "src", "dst", "load",
            ],
        }
    }

    fn has_field(self, field: &str) -> bool {
        self.fields().contains(&field)
    }
}

/// Значение параметра Geneva: целое или строка.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenevaValue {
    Int(i64),
    Text(String),
}

impl GenevaValue {
    fn print(&self) -> String {
        match self {
            Self::Int(value) => value.to_string(),
            Self::Text(value) => value.clone(),
        }
    }
}

/// Примитив tamper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenevaTamperKind {
    Replace,
    Corrupt,
    Add,
    Compress,
}

impl GenevaTamperKind {
    fn name(self) -> &'static str {
        match self {
            Self::Replace => "replace",
            Self::Corrupt => "corrupt",
            Self::Add => "add",
            Self::Compress => "compress",
        }
    }
}

/// Разобранный tamper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenevaTamper {
    pub proto: String,
    pub layer: GenevaLayer,
    pub field: String,
    pub kind: GenevaTamperKind,
    pub value: Option<GenevaValue>,
}

/// Триггер дерева.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenevaTrigger {
    /// Протокол в том виде, в каком он написан в стратегии.
    pub proto: String,
    pub layer: GenevaLayer,
    pub field: String,
    pub value: GenevaValue,
    pub wildcard: bool,
    /// `None` — газа нет; отрицательное значение — bomb-триггер.
    pub gas: Option<i64>,
}

/// Действие дерева.
#[derive(Clone, Debug, PartialEq)]
pub enum GenevaActionKind {
    Tamper(GenevaTamper),
    Duplicate,
    Fragment {
        segment: bool,
        fragsize: i32,
        overlap: i32,
        in_order: bool,
    },
    Drop,
    Sleep {
        time: f64,
    },
    Trace {
        start: u8,
        end: u8,
    },
}

impl GenevaActionKind {
    /// Число поддеревьев: 2 — ветвление, 0 — терминальное, 1 — одно.
    fn children(&self) -> usize {
        match self {
            Self::Duplicate | Self::Fragment { .. } => 2,
            Self::Drop | Self::Trace { .. } => 0,
            Self::Tamper(_) | Self::Sleep { .. } => 1,
        }
    }

    fn is_branching(&self) -> bool {
        self.children() == 2
    }

    fn is_terminal(&self) -> bool {
        self.children() == 0
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Tamper(_) => "tamper",
            Self::Duplicate => "duplicate",
            Self::Fragment { .. } => "fragment",
            Self::Drop => "drop",
            Self::Sleep { .. } => "sleep",
            Self::Trace { .. } => "trace",
        }
    }
}

/// Узел дерева действий.
#[derive(Clone, Debug, PartialEq)]
pub struct GenevaAction {
    pub kind: GenevaActionKind,
    pub left: Option<Box<GenevaAction>>,
    pub right: Option<Box<GenevaAction>>,
}

/// Одно дерево стратегии: триггер, действие и направление.
#[derive(Clone, Debug, PartialEq)]
pub struct GenevaTree {
    pub direction: GenevaDirection,
    pub trigger: GenevaTrigger,
    pub action: Option<GenevaAction>,
}

/// Разобранная стратегия Geneva.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GenevaStrategy {
    pub out: Vec<GenevaTree>,
    pub inbound: Vec<GenevaTree>,
}

impl GenevaStrategy {
    /// `strategy_print`: исходящий лес, ` \/ `, входящий лес.
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        for (i, tree) in self.out.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(&tree.print());
        }
        if !self.out.is_empty() {
            out.push(' ');
        }
        out.push_str("\\/");
        for tree in &self.inbound {
            out.push(' ');
            out.push_str(&tree.print());
        }
        out
    }
}

impl GenevaTree {
    fn print(&self) -> String {
        let mut out = format!("[{}]-", self.trigger.print());
        if let Some(action) = &self.action {
            action.print_repr(&mut out);
        }
        // C проверяет последний символ всего вывода, а не наличие действия:
        // значение, оканчивающееся на '-', не получает второй дефис.
        if !out.ends_with('-') {
            out.push('-');
        }
        out.push('|');
        out
    }
}

impl GenevaTrigger {
    fn print(&self) -> String {
        let mut out = format!("{}:{}:{}", self.proto, self.field, self.value.print());
        if self.wildcard {
            out.push('*');
        }
        if let Some(gas) = self.gas {
            out.push(':');
            out.push_str(&gas.to_string());
        }
        out
    }
}

impl GenevaAction {
    fn print_repr(&self, out: &mut String) {
        out.push_str(&self.kind.print());
        if self.left.is_some() || self.right.is_some() {
            out.push('(');
            if let Some(left) = &self.left {
                left.print_repr(out);
            }
            out.push(',');
            if let Some(right) = &self.right {
                right.print_repr(out);
            }
            out.push(')');
        }
    }
}

impl GenevaActionKind {
    fn print(&self) -> String {
        match self {
            Self::Tamper(tamper) => {
                if tamper.kind == GenevaTamperKind::Compress {
                    "tamper{DNS:qd:compress}".to_string()
                } else if tamper.kind == GenevaTamperKind::Corrupt {
                    format!("tamper{{{}:{}:corrupt}}", tamper.proto, tamper.field)
                } else {
                    format!(
                        "tamper{{{}:{}:{}:{}}}",
                        tamper.proto,
                        tamper.field,
                        tamper.kind.name(),
                        tamper
                            .value
                            .as_ref()
                            .map_or_else(String::new, GenevaValue::print)
                    )
                }
            }
            Self::Duplicate => "duplicate".to_string(),
            Self::Fragment {
                segment,
                fragsize,
                overlap,
                in_order,
            } => {
                let mut out = format!(
                    "fragment{{{}:{}:{}}}",
                    if *segment { "tcp" } else { "ip" },
                    fragsize,
                    if *in_order { "True" } else { "False" }
                );
                if *overlap != 0 {
                    out.pop();
                    out.push_str(&format!(":{overlap}}}"));
                }
                out
            }
            Self::Drop => "drop".to_string(),
            Self::Sleep { time } => format!("sleep{{{}}}", format_general(*time)),
            Self::Trace { start, end } => format!("trace{{{start}:{end}}}"),
        }
    }
}

/// Разбирает стратегию; ошибка содержит объяснение, как в geneva_c.
pub fn parse_strategy(text: &str) -> Result<GenevaStrategy, String> {
    let trimmed = strip_dup(text);
    let mut body = trimmed;
    // Geneva снимает одну висящую кавычку с каждой стороны.
    if let Some(rest) = body.strip_prefix('"') {
        body = rest;
    }
    if let Some(rest) = body.strip_suffix('"') {
        body = rest;
    }

    let mut strategy = GenevaStrategy::default();
    let mut direction = GenevaDirection::Out;
    let mut part = body;
    loop {
        let (forest, rest) = match part.find("\\/") {
            Some(index) => (&part[..index], Some(&part[index + 2..])),
            None => (part, None),
        };
        parse_forest(forest, direction, &mut strategy)?;
        match rest {
            Some(rest) => {
                part = rest;
                // Всё после первого `\/` — входящий лес.
                direction = GenevaDirection::In;
            }
            None => break,
        }
    }
    Ok(strategy)
}

/// Удобная обёртка: разобрать и сразу напечатать каноническую форму.
pub fn canonical_strategy(text: &str) -> Result<String, String> {
    parse_strategy(text).map(|strategy| strategy.canonical())
}

fn parse_forest(
    forest: &str,
    direction: GenevaDirection,
    strategy: &mut GenevaStrategy,
) -> Result<(), String> {
    for token in forest.split('|') {
        let token = strip_dup(token);
        if token.is_empty() {
            continue;
        }
        // C запрещает пробелы внутри дерева; пробелы между деревьями уже срезаны.
        if token.as_bytes().iter().any(|&byte| is_c_space(byte)) {
            return Err(format!("strategy includes a space in \"{token}\""));
        }
        let with_bar = format!("{token}|");
        let tree = parse_tree(&with_bar, direction)?;
        match direction {
            GenevaDirection::Out => strategy.out.push(tree),
            GenevaDirection::In => strategy.inbound.push(tree),
        }
    }
    Ok(())
}

fn parse_tree(text: &str, direction: GenevaDirection) -> Result<GenevaTree, String> {
    let s = strip_dup(text);
    if !s.ends_with('|') {
        return Err(format!("tree \"{s}\" does not end with |"));
    }
    // C ищет последнее `]-`, если дерево начинается с `[`.
    let separator = if s.starts_with('[') {
        s.rfind("]-")
    } else {
        None
    };
    let Some(separator) = separator else {
        return Err(format!("could not identify the trigger in \"{s}\""));
    };
    let trigger_text = &s[1..separator];
    let mut body = s[separator + 2..].to_string();
    // C удаляет все `-|`, затем все `|`, если строка всё ещё кончается на `|`.
    if body.len() >= 2 && body.ends_with("-|") {
        body = body.replace("-|", "");
    }
    if body.ends_with('|') {
        body = body.replace('|', "");
    }
    let trigger = parse_trigger(trigger_text)?;
    let action = parse_action_tree(&body, direction, 0)?;
    Ok(GenevaTree {
        direction,
        trigger,
        action,
    })
}

fn parse_action_tree(
    text: &str,
    direction: GenevaDirection,
    depth: usize,
) -> Result<Option<GenevaAction>, String> {
    if is_blank(text) {
        return Ok(None);
    }
    if depth > MAX_DEPTH {
        return Err("action tree is nested too deeply".to_string());
    }

    let (action_text, left_text, right_text) = match text.find('(') {
        None => (text, None, None),
        Some(paren) => {
            let rest = &text[paren..];
            let mut opened = 0i32;
            let mut commas = 0i32;
            let mut split = None;
            for (index, byte) in rest.bytes().enumerate() {
                if byte == b'(' {
                    opened += 1;
                }
                if byte == b',' {
                    commas += 1;
                }
                if commas == opened && opened > 0 {
                    split = Some(index);
                    break;
                }
            }
            let Some(comma) = split else {
                return Err(format!("malformed action tree \"{text}\""));
            };
            let left = &rest[1..comma];
            // C отбрасывает последний символ rest (закрывающую скобку).
            let right = if comma + 1 < rest.len() {
                &rest[comma + 1..rest.len() - 1]
            } else {
                ""
            };
            (&text[..paren], Some(left), Some(right))
        }
    };

    let mut action = parse_action(action_text, direction)?;
    if !action.kind.is_branching() && right_text.is_some_and(|right| !right.is_empty()) {
        return Err(format!(
            "{} cannot have a right subtree",
            action.kind.name()
        ));
    }
    if action.kind.is_terminal()
        && (left_text.is_some_and(|left| !left.is_empty())
            || right_text.is_some_and(|right| !right.is_empty()))
    {
        return Err(format!(
            "terminal action {} cannot have children",
            action.kind.name()
        ));
    }
    if let Some(left) = left_text.filter(|left| !left.is_empty()) {
        action.left = parse_action_tree(left, direction, depth + 1)?.map(Box::new);
    }
    if let Some(right) = right_text.filter(|right| !right.is_empty()) {
        action.right = parse_action_tree(right, direction, depth + 1)?.map(Box::new);
    }
    Ok(Some(action))
}

fn parse_action(text: &str, direction: GenevaDirection) -> Result<GenevaAction, String> {
    let brace = text.find('{');
    let name = match brace {
        Some(index) => &text[..index],
        None => text,
    };
    let is_tamper = name.eq_ignore_ascii_case("tamper");
    let is_duplicate = name.eq_ignore_ascii_case("duplicate");
    let is_fragment = name.eq_ignore_ascii_case("fragment");
    let is_drop = name.eq_ignore_ascii_case("drop");
    let is_sleep = name.eq_ignore_ascii_case("sleep");
    let is_trace = name.eq_ignore_ascii_case("trace");
    if !(is_tamper || is_duplicate || is_fragment || is_drop || is_sleep || is_trace) {
        return Err(format!("unknown action \"{name}\""));
    }
    if direction == GenevaDirection::In && !(is_tamper || is_drop) {
        return Err(format!(
            "action {} cannot be used in the inbound forest",
            name.to_ascii_lowercase()
        ));
    }

    // C удаляет все `}` из параметров и отвергает вторую `{`.
    let data = match brace {
        Some(index) => {
            let tail = &text[index + 1..];
            if tail.contains('{') {
                return Err(format!("malformed action parameters \"{text}\""));
            }
            Some(tail.replace('}', ""))
        }
        None => None,
    };
    let data = data.as_deref().filter(|data| !data.is_empty());

    let kind = if is_tamper {
        let data = data
            .ok_or_else(|| "tamper needs parameters {proto:field:primitive[:value]}".to_string())?;
        GenevaActionKind::Tamper(parse_tamper(data)?)
    } else if is_duplicate {
        if data.is_some() {
            return Err("action duplicate takes no parameters".to_string());
        }
        GenevaActionKind::Duplicate
    } else if is_fragment {
        let fields = parse_fragment(data)?;
        GenevaActionKind::Fragment {
            segment: fields.segment,
            fragsize: fields.fragsize,
            overlap: fields.overlap,
            in_order: fields.in_order,
        }
    } else if is_drop {
        if data.is_some() {
            return Err("action drop takes no parameters".to_string());
        }
        GenevaActionKind::Drop
    } else if is_sleep {
        GenevaActionKind::Sleep {
            time: parse_sleep(data)?,
        }
    } else {
        let (start, end) = parse_trace(data)?;
        GenevaActionKind::Trace { start, end }
    };
    Ok(GenevaAction {
        kind,
        left: None,
        right: None,
    })
}

fn parse_trigger(text: &str) -> Result<GenevaTrigger, String> {
    let mut s = strip_dup(text);
    if s.ends_with(']') {
        s = &s[..s.len() - 1];
    }
    let body = s.strip_prefix('[').unwrap_or(s);
    let parts: Vec<&str> = body.split(':').collect();
    if parts.len() != 3 && parts.len() != 4 {
        return Err(format!(
            "malformed trigger \"{text}\" (expected proto:field:value[:gas])"
        ));
    }
    let layer = GenevaLayer::parse(parts[0])
        .ok_or_else(|| format!("unknown protocol \"{}\" in trigger", parts[0]))?;
    if !layer.has_field(parts[1]) {
        return Err(format!(
            "unknown field \"{}\" for {} in trigger",
            parts[1],
            layer.name()
        ));
    }
    let mut value = python_value(parts[2]);
    let mut wildcard = false;
    if let GenevaValue::Text(text) = &mut value {
        if text.ends_with('*') {
            text.pop();
            wildcard = true;
        }
    }
    let gas = if parts.len() == 4 {
        Some(python_int(parts[3]).ok_or_else(|| format!("bad trigger gas \"{}\"", parts[3]))?)
    } else {
        None
    };
    Ok(GenevaTrigger {
        proto: parts[0].to_string(),
        layer,
        field: parts[1].to_string(),
        value,
        wildcard,
        gas,
    })
}

fn parse_tamper(data: &str) -> Result<GenevaTamper, String> {
    let parts: Vec<&str> = data.split(':').collect();
    if parts.len() != 3 && parts.len() != 4 {
        return Err(format!("cannot parse tamper action {{{data}}}"));
    }
    let kind = if parts[2] == "replace" {
        GenevaTamperKind::Replace
    } else if parts[2] == "corrupt" {
        GenevaTamperKind::Corrupt
    } else if parts[2] == "add" {
        GenevaTamperKind::Add
    } else if parts[2] == "compress" {
        GenevaTamperKind::Compress
    } else {
        return Err(format!("unknown tamper primitive \"{}\"", parts[2]));
    };
    if kind == GenevaTamperKind::Compress {
        // Geneva всегда печатает и исполняет это как DNS:qd:compress.
        return Ok(GenevaTamper {
            proto: "DNS".to_string(),
            layer: GenevaLayer::Dns,
            field: "qd".to_string(),
            kind,
            value: None,
        });
    }
    let layer = GenevaLayer::parse(parts[0])
        .ok_or_else(|| format!("unknown protocol \"{}\" in tamper", parts[0]))?;
    if !layer.has_field(parts[1]) {
        return Err(format!(
            "unknown field \"{}\" for {} in tamper",
            parts[1],
            layer.name()
        ));
    }
    let mut value = None;
    if kind != GenevaTamperKind::Corrupt {
        if parts.len() != 4 {
            return Err(format!("tamper {} needs a value", parts[2]));
        }
        // TamperAction.parse(): int() кроме полей load.
        let parsed = if parts[1].contains("load") {
            GenevaValue::Text(parts[3].to_string())
        } else {
            python_value(parts[3])
        };
        if kind == GenevaTamperKind::Add {
            if python_int(parts[3]).is_none() {
                return Err(format!("tamper add needs an integer, got \"{}\"", parts[3]));
            }
        } else {
            // field_parse: значение, которое поле не может принять, — ошибка,
            // а не молчаливый no-op.
            let printed = parsed.print();
            field_parse(layer, parts[1], &printed).ok_or_else(|| {
                format!(
                    "bad value \"{}\" for {}:{}",
                    parts[3],
                    layer.name(),
                    parts[1]
                )
            })?;
        }
        value = Some(parsed);
    }
    Ok(GenevaTamper {
        proto: parts[0].to_string(),
        layer,
        field: parts[1].to_string(),
        kind,
        value,
    })
}

fn parse_fragment(data: Option<&str>) -> Result<FragmentFields, String> {
    let Some(data) = data else {
        // C выбирает порядок случайно; для каноникализатора фиксируем False.
        return Ok(FragmentFields {
            segment: true,
            fragsize: -1,
            overlap: 0,
            in_order: false,
        });
    };
    let parts: Vec<&str> = data.split(':').collect();
    if parts.len() != 3 && parts.len() != 4 {
        return Err(format!("cannot parse fragment action {{{data}}}"));
    }
    let fragsize =
        python_int(parts[1]).ok_or_else(|| format!("cannot parse fragment action {{{data}}}"))?;
    let overlap = if parts.len() == 4 {
        python_int(parts[3]).ok_or_else(|| format!("cannot parse fragment action {{{data}}}"))?
    } else {
        0
    };
    if !(-65535..=65535).contains(&fragsize) || !(-65535..=65535).contains(&overlap) {
        return Err(format!("cannot parse fragment action {{{data}}}"));
    }
    Ok(FragmentFields {
        segment: parts[0].contains("tcp"),
        fragsize: fragsize as i32,
        overlap: overlap as i32,
        in_order: parts[2].starts_with("True"),
    })
}

/// Поля варианта `Fragment`, пока действие ещё не собрано.
#[derive(Clone, Copy, Debug)]
struct FragmentFields {
    segment: bool,
    fragsize: i32,
    overlap: i32,
    in_order: bool,
}

fn parse_sleep(data: Option<&str>) -> Result<f64, String> {
    let Some(data) = data else {
        return Ok(1.0);
    };
    let value = parse_double_c(data)
        .filter(|value| value.is_finite() && (0.0..=3600.0).contains(value))
        .ok_or_else(|| format!("bad sleep time \"{data}\""))?;
    Ok(value)
}

fn parse_trace(data: Option<&str>) -> Result<(u8, u8), String> {
    let Some(data) = data else {
        return Ok((1, 64));
    };
    let parts: Vec<&str> = data.split(':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "bad trace range {{{data}}} (expected start_ttl:end_ttl, start <= end)"
        ));
    }
    let start = python_int(parts[0])
        .filter(|value| (0..=255).contains(value))
        .ok_or_else(|| {
            format!("bad trace range {{{data}}} (expected start_ttl:end_ttl, start <= end)")
        })?;
    let end = python_int(parts[1])
        .filter(|value| (0..=255).contains(value))
        .ok_or_else(|| {
            format!("bad trace range {{{data}}} (expected start_ttl:end_ttl, start <= end)")
        })?;
    if start > end {
        return Err(format!(
            "bad trace range {{{data}}} (expected start_ttl:end_ttl, start <= end)"
        ));
    }
    Ok((start as u8, end as u8))
}

/// `field_parse` из `pkt_fields.c`: пригодно ли значение для replace.
fn field_parse(layer: GenevaLayer, field: &str, text: &str) -> Option<GenevaValue> {
    if !layer.has_field(field) {
        return None;
    }
    if field == "load" {
        return Some(GenevaValue::Text(text.to_string()));
    }
    if let Some(is_int) = tcp_option_is_int(field) {
        if !is_int {
            if !hex_decode_ok(text) {
                return None;
            }
            return Some(GenevaValue::Text(text.to_string()));
        }
        if text.is_empty() {
            return Some(GenevaValue::Text(String::new()));
        }
        let value = parse_i64_c(text).filter(|value| *value >= 0)?;
        return Some(GenevaValue::Int(value));
    }
    if let Some(value) = parse_i64_c(text) {
        return Some(GenevaValue::Int(value));
    }
    if !is_string_field(layer, field) {
        return None;
    }
    if field == "flags" {
        match layer {
            GenevaLayer::Tcp => {
                tcp_flags_parse(text)?;
            }
            GenevaLayer::Ip => {
                ip_flags_parse(text)?;
            }
            _ => {}
        }
    }
    Some(GenevaValue::Text(text.to_string()))
}

fn is_string_field(layer: GenevaLayer, field: &str) -> bool {
    if matches!(field, "load" | "src" | "dst") {
        return true;
    }
    if matches!(layer, GenevaLayer::Ip | GenevaLayer::Tcp) && field == "flags" {
        return true;
    }
    if layer == GenevaLayer::DnsQr && field == "qname" {
        return true;
    }
    layer == GenevaLayer::Dns && field == "qd"
}

/// `tcp_opt_table`: (имя после `options-`, целочисленное ли значение).
const TCP_OPTIONS: &[(&str, bool)] = &[
    ("eol", false),
    ("nop", false),
    ("mss", true),
    ("wscale", true),
    ("sackok", false),
    ("sack", false),
    ("timestamp", true),
    ("altchksum", true),
    ("altchksumopt", false),
    ("md5header", false),
    ("uto", true),
];

fn tcp_option_is_int(field: &str) -> Option<bool> {
    let suffix = field.strip_prefix("options-")?;
    TCP_OPTIONS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(suffix))
        .map(|(_, is_int)| *is_int)
}

fn hex_decode_ok(text: &str) -> bool {
    text.len() % 2 == 0 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn tcp_flags_parse(text: &str) -> Option<u16> {
    if let Some(value) = parse_i64_c(text) {
        if !(0..=0x1ff).contains(&value) {
            return None;
        }
        return Some(value as u16);
    }
    const LETTERS: &str = "FSRPAUECN";
    let mut flags = 0u16;
    for byte in text.bytes() {
        let index = LETTERS.bytes().position(|letter| letter == byte)?;
        flags |= 1 << index;
    }
    Some(flags)
}

fn ip_flags_parse(text: &str) -> Option<u8> {
    if let Some(value) = parse_i64_c(text) {
        if !(0..=7).contains(&value) {
            return None;
        }
        return Some(value as u8);
    }
    const NAMES: &[&str] = &["MF", "DF", "evil"];
    let mut flags = 0u8;
    let mut rest = text;
    while !rest.is_empty() {
        let (part, tail) = match rest.find('+') {
            Some(index) => (&rest[..index], Some(&rest[index + 1..])),
            None => (rest, None),
        };
        let index = NAMES
            .iter()
            .position(|name| name.eq_ignore_ascii_case(part))?;
        flags |= 1 << index;
        match tail {
            Some(tail) => rest = tail,
            None => rest = "",
        }
    }
    Some(flags)
}

/// `py_int`: int(str) из Python с подчёркиваниями, но без пробелов внутри.
fn python_int(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() && is_c_space(bytes[index]) {
        index += 1;
    }
    let mut buffer = String::new();
    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        buffer.push(bytes[index] as char);
        index += 1;
    }
    let mut digits = 0usize;
    while index < bytes.len() && !is_c_space(bytes[index]) {
        if bytes[index] == b'_' {
            if digits == 0 || index + 1 >= bytes.len() || !bytes[index + 1].is_ascii_digit() {
                return None;
            }
            index += 1;
            continue;
        }
        if !bytes[index].is_ascii_digit() || buffer.len() >= 31 {
            return None;
        }
        buffer.push(bytes[index] as char);
        index += 1;
        digits += 1;
    }
    while index < bytes.len() && is_c_space(bytes[index]) {
        index += 1;
    }
    if index != bytes.len() || digits == 0 {
        return None;
    }
    buffer.parse::<i64>().ok()
}

/// `py_value`: int(), иначе исходная строка.
fn python_value(text: &str) -> GenevaValue {
    python_int(text).map_or_else(|| GenevaValue::Text(text.to_string()), GenevaValue::Int)
}

/// `parse_i64`: strtoll с обязательным концом строки.
fn parse_i64_c(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() && is_c_space(bytes[index]) {
        index += 1;
    }
    let start = index;
    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        index += 1;
    }
    let digits = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index == digits || index != bytes.len() {
        return None;
    }
    text[start..].parse::<i64>().ok()
}

/// `parse_double` из geneva_c: ведущие пробелы допустимы, хвост — нет.
fn parse_double_c(text: &str) -> Option<f64> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() && is_c_space(bytes[index]) {
        index += 1;
    }
    if index == bytes.len() {
        return None;
    }
    text[index..].parse::<f64>().ok()
}

/// `%g` из C: 6 значащих цифр, экспонента при exp < -4 или exp >= 6.
fn format_general(value: f64) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() { "-0" } else { "0" }.to_string();
    }
    let exponent = value.abs().log10().floor() as i32;
    if exponent < -4 || exponent >= 6 {
        let raw = format!("{value:.5e}");
        let (mantissa, exponent) = raw.split_once('e').unwrap_or((&raw, "0"));
        let mut mantissa = mantissa.to_string();
        while mantissa.ends_with('0') {
            mantissa.pop();
        }
        if mantissa.ends_with('.') {
            mantissa.pop();
        }
        let exponent: i32 = exponent.parse().unwrap_or(0);
        format!("{mantissa}e{exponent:+03}")
    } else {
        let precision = (5 - exponent).max(0) as usize;
        let mut out = format!("{value:.precision$}", precision = precision);
        while out.ends_with('0') {
            out.pop();
        }
        if out.ends_with('.') {
            out.pop();
        }
        out
    }
}

fn is_c_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn is_blank(text: &str) -> bool {
    text.as_bytes().iter().all(|&byte| is_c_space(byte))
}

fn strip_dup(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut start = 0;
    while start < bytes.len() && is_c_space(bytes[start]) {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && is_c_space(bytes[end - 1]) {
        end -= 1;
    }
    &text[start..end]
}

/// Возвращает библиотеку Geneva и проверяет, что все записи разбираются.
pub fn library() -> &'static [GenevaLibraryEntry] {
    GENEVA_LIBRARY
}

/// Фильтрует библиотеку по правилам `library.c`.
pub fn library_filtered(filter: &GenevaLibraryFilter<'_>) -> Vec<&'static GenevaLibraryEntry> {
    GENEVA_LIBRARY
        .iter()
        .filter(|entry| filter.matches(entry))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geneva_corpus::{CORPUS, LIBRARY_CANONICAL};
    use crate::geneva_library::{GENEVA_LIBRARY, GenevaLibraryFilter};

    #[test]
    fn корпус_geneva_совпадает_с_c() {
        assert_eq!(CORPUS.len(), 145);
        for (index, entry) in CORPUS.iter().enumerate() {
            let parsed = parse_strategy(entry.text);
            assert_eq!(
                parsed.is_ok(),
                entry.ok,
                "запись {index}: {}: {parsed:?}",
                entry.text
            );
            match parsed {
                Ok(strategy) => assert_eq!(
                    strategy.canonical(),
                    entry.canonical,
                    "запись {index}: {}",
                    entry.text
                ),
                Err(error) => assert!(!error.is_empty(), "запись {index} без объяснения"),
            }
        }
    }

    #[test]
    fn библиотека_geneva_совпадает_с_c() {
        assert_eq!(GENEVA_LIBRARY.len(), 58);
        assert_eq!(GENEVA_LIBRARY.len(), LIBRARY_CANONICAL.len());
        for (entry, expected) in GENEVA_LIBRARY.iter().zip(LIBRARY_CANONICAL) {
            let strategy = parse_strategy(entry.strategy)
                .unwrap_or_else(|error| panic!("{}: {error}", entry.strategy));
            assert_eq!(&strategy.canonical(), expected, "{}", entry.strategy);
        }
    }

    #[test]
    fn каноникализация_идемпотентна() {
        for entry in CORPUS.iter().filter(|entry| entry.ok) {
            let first = parse_strategy(entry.text).expect(entry.text).canonical();
            let second = parse_strategy(&first)
                .unwrap_or_else(|error| panic!("{first}: {error}"))
                .canonical();
            assert_eq!(first, second);
        }
        for entry in GENEVA_LIBRARY {
            let first = parse_strategy(entry.strategy)
                .expect(entry.strategy)
                .canonical();
            let second = parse_strategy(&first)
                .unwrap_or_else(|error| panic!("{first}: {error}"))
                .canonical();
            assert_eq!(first, second);
        }
    }

    #[test]
    fn фильтр_библиотеки_повторяет_c() {
        // Без страны lab-записи скрыты, если не запрошены явно.
        let all = library_filtered(&GenevaLibraryFilter::default());
        assert_eq!(all.len(), 48);
        assert!(all.iter().all(|entry| entry.country != "lab"));

        let lab = library_filtered(&GenevaLibraryFilter {
            country: Some("lab"),
            ..Default::default()
        });
        assert_eq!(lab.len(), 10);
        assert!(lab.iter().all(|entry| entry.country == "lab"));

        let china = library_filtered(&GenevaLibraryFilter {
            country: Some("china"),
            ..Default::default()
        });
        assert_eq!(china.len(), 38);
        assert!(china.iter().all(|entry| entry.country == "china"));

        let india = library_filtered(&GenevaLibraryFilter {
            country: Some("india"),
            ..Default::default()
        });
        assert_eq!(india.len(), 6);

        let kazakhstan = library_filtered(&GenevaLibraryFilter {
            country: Some("kazakhstan"),
            ..Default::default()
        });
        assert_eq!(kazakhstan.len(), 4);

        let clients = library_filtered(&GenevaLibraryFilter {
            side: 1,
            ..Default::default()
        });
        assert!(clients.iter().all(|entry| !entry.server_side));

        let servers = library_filtered(&GenevaLibraryFilter {
            side: 2,
            ..Default::default()
        });
        assert!(servers.iter().all(|entry| entry.server_side));
        assert_eq!(servers.len(), 2);

        let rate = library_filtered(&GenevaLibraryFilter {
            min_rate: 100,
            ..Default::default()
        });
        assert!(rate.iter().all(|entry| entry.rate == 100));

        // Префикс `censor` отбрасывается; список цензоров — через пробел.
        let by_censor = library_filtered(&GenevaLibraryFilter {
            censor: Some("8"),
            ..Default::default()
        });
        let by_prefixed = library_filtered(&GenevaLibraryFilter {
            censor: Some("censor8"),
            ..Default::default()
        });
        assert_eq!(by_censor.len(), by_prefixed.len());
        assert!(!by_censor.is_empty());
        assert!(by_censor.iter().all(|entry| {
            entry
                .censors
                .is_some_and(|list| list.split(' ').any(|w| w == "8"))
        }));

        let with_lab = library_filtered(&GenevaLibraryFilter {
            with_lab: true,
            ..Default::default()
        });
        assert_eq!(with_lab.len(), 58);
    }

    #[test]
    fn крайние_случаи_печати_совпадают_с_geneva() {
        // test_strategy.c::test_print_exact, массив same.
        let same = [
            "[TCP:flags:A]-| \\/",
            "\\/ [TCP:flags:A]-|",
            "[TCP:flags:A]-duplicate(duplicate(duplicate(duplicate,),),)-| \\/",
            "[IP:version:4]-| \\/",
            "[TCP:flags:A]-duplicate(tamper{TCP:flags:corrupt}(duplicate(duplicate,),),)-| \\/",
            "[TCP:flags:A]-tamper{TCP:flags:replace:S}(duplicate,)-| \\/",
            "[IP:frag:0]-fragment{tcp:-1:False}(drop,tamper{TCP:options-altchksum:replace:})-| \\/",
            "[IP:ihl:0]-fragment{tcp:-1:True}(duplicate,tamper{IP:load:replace:074})-| \\/",
            "[TCP:flags:0]-tamper{TCP:flags:replace:S}(duplicate(,drop),)-| \\/",
            "[TCP:flags:SA:1]-drop-| [UDP:dport:53:-2]-sleep{0.25}-| \\/ [TCP:flags:R]-drop-|",
            "[TCP:load:GET*]-trace{2:10}-| \\/",
            "[UDP:dport:53]-tamper{DNS:qd:compress}-| \\/",
            "[TCP:flags:PA]-fragment{ip:2:True:4}-| \\/",
            "[IPv6:hlim:64]-tamper{IP:ttl:add:-3}-| \\/",
            "\\/",
        ];
        for text in same {
            assert_eq!(canonical_strategy(text).expect(text), text);
        }
    }

    #[test]
    fn нормализация_совпадает_с_geneva() {
        // test_strategy.c::test_print_exact, массив norm.
        let norm = [
            ("", "\\/"),
            ("\"\\/\"", "\\/"),
            ("\"\\/ [TCP:flags:A]-drop-|\"", "\\/ [TCP:flags:A]-drop-|"),
            ("[TCP:flags:0]--|", "[TCP:flags:0]-| \\/"),
            ("[TCP:flags:A]-drop|", "[TCP:flags:A]-drop-| \\/"),
            ("[[TCP:flags:A]]-drop-|", "[TCP:flags:A]-drop-| \\/"),
            (
                "[TCP:dport:080]-tamper{TCP:window:replace:+1_000}-|",
                "[TCP:dport:80]-tamper{TCP:window:replace:1000}-| \\/",
            ),
            (
                "[TCP:flags:PA]-tamper{TCP:load:replace:007}-|",
                "[TCP:flags:PA]-tamper{TCP:load:replace:007}-| \\/",
            ),
            (
                "[TCP:flags:A]-tamper{TCP:seq:corrupt:5}-|",
                "[TCP:flags:A]-tamper{TCP:seq:corrupt}-| \\/",
            ),
            (
                "[UDP:dport:53]-tamper{UDP:sport:compress}-|",
                "[UDP:dport:53]-tamper{DNS:qd:compress}-| \\/",
            ),
            (
                "[TCP:flags:PA]-fragment{tcp:8:true:0}-|",
                "[TCP:flags:PA]-fragment{tcp:8:False}-| \\/",
            ),
            (
                "[TCP:flags:PA]-fragment{xx:8:True}-|",
                "[TCP:flags:PA]-fragment{ip:8:True}-| \\/",
            ),
            (
                "[TCP:flags:PA]-sleep{1.50}-|",
                "[TCP:flags:PA]-sleep{1.5}-| \\/",
            ),
            ("[TCP:flags:PA]-sleep-|", "[TCP:flags:PA]-sleep{1}-| \\/"),
            ("[TCP:flags:PA]-trace-|", "[TCP:flags:PA]-trace{1:64}-| \\/"),
            (
                "[TCP:flags:PA]-DUPLICATE-|",
                "[TCP:flags:PA]-duplicate-| \\/",
            ),
            (
                "[TCP:flags:S]-drop-| \\/ [TCP:flags:R]-drop-| \\/ [TCP:flags:F]-drop-|",
                "[TCP:flags:S]-drop-| \\/ [TCP:flags:R]-drop-| [TCP:flags:F]-drop-|",
            ),
        ];
        for (input, expected) in norm {
            assert_eq!(canonical_strategy(input).expect(input), expected);
        }
    }

    #[test]
    fn ошибки_разбора_совпадают_с_geneva() {
        // test_strategy.c::test_parse_errors.
        let bad = [
            "asdfasdf",
            "[TCP:flags:0]-duplicate{x}-|",
            "[TCP:flags:0]-tamper-|",
            "[TCP:flags:0]-tamper{TCP:flags:replace}-|",
            "[TCP:flags:0]-tamper{TCP:flags:frob:1}-|",
            "[TCP:flags:0]-tamper{TCP:nosuch:replace:1}-|",
            "[TCP:flags:0]-tamper{XYZ:ttl:replace:1}-|",
            "[TCP:flags:0]-tamper{IP:ttl:add:x}-|",
            "[TCP:flags:0]-tamper{TCP:flags:replace:XYZ}-|",
            "[TCP:flags:0]-tamper{IP:flags:replace:QQ}-|",
            "[TCP:flags:0]-tamper{TCP:window:replace:abc}-|",
            "[TCP:flags:0]-tamper{TCP:options-md5header:replace:zz}-|",
            "[TCP:flags:0]-tamper{IP:ttl:replace:1:2}-|",
            "[TCP:flags:0]-tamper{{IP:ttl:replace:1}-|",
            "[TCP:flags:0]-fragment{tcp:x:True}-|",
            "[TCP:flags:0]-fragment{tcp}-|",
            "[TCP:flags:0]-sleep{-1}-|",
            "[TCP:flags:0]-sleep{nan}-|",
            "[TCP:flags:0]-sleep{abc}-|",
            "[TCP:flags:0]-trace{5:1}-|",
            "[TCP:flags:0]-trace{5}-|",
            "[TCP:flags:0:x]-drop-|",
            "[TCP:flags]-drop-|",
            "[TCP:flags:0:1:2]-drop-|",
            "[FOO:flags:0]-drop-|",
            "\\/ [TCP:flags:R]-duplicate-|",
            "\\/ [TCP:flags:R]-fragment{tcp:-1:True}-|",
            "\\/ [TCP:flags:R]-trace{1:2}-|",
            "[TCP:flags:A]-drop-| x",
        ];
        for text in bad {
            assert!(parse_strategy(text).is_err(), "принято: {text}");
        }

        let mut deep = String::from("[TCP:flags:A]-");
        for _ in 0..1000 {
            deep.push_str("duplicate(");
        }
        deep.push_str(",)-|");
        assert!(parse_strategy(&deep).is_err());
    }

    #[test]
    fn значения_печатаются_как_python_int() {
        assert_eq!(
            canonical_strategy("[TCP:dport:080]-tamper{TCP:window:replace:+1_000}-|").unwrap(),
            "[TCP:dport:80]-tamper{TCP:window:replace:1000}-| \\/"
        );
        // В триггере py_int может не сработать: тогда значение остаётся строкой.
        assert_eq!(
            canonical_strategy("[TCP:dport:1__0]-drop-|").unwrap(),
            "[TCP:dport:1__0]-drop-| \\/"
        );
        assert_eq!(
            canonical_strategy("[TCP:dport:_1]-drop-|").unwrap(),
            "[TCP:dport:_1]-drop-| \\/"
        );
        // А в replace значение обязано приводиться к типу поля.
        assert!(parse_strategy("[TCP:flags:A]-tamper{TCP:window:replace:_1}-|").is_err());
        assert!(parse_strategy("[TCP:flags:A]-tamper{TCP:window:replace:1_}-|").is_err());
        assert_eq!(
            canonical_strategy("[TCP:load:GET*]-drop-|").unwrap(),
            "[TCP:load:GET*]-drop-| \\/"
        );
        assert_eq!(
            canonical_strategy("[TCP:flags:PA]-sleep{0.25}-|").unwrap(),
            "[TCP:flags:PA]-sleep{0.25}-| \\/"
        );
        assert_eq!(
            canonical_strategy("[TCP:flags:PA]-sleep{0.00001}-|").unwrap(),
            "[TCP:flags:PA]-sleep{1e-05}-| \\/"
        );
        assert_eq!(
            canonical_strategy("[TCP:flags:PA]-sleep{0.0001}-|").unwrap(),
            "[TCP:flags:PA]-sleep{0.0001}-| \\/"
        );
    }
}
