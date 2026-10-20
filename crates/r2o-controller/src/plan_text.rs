use r2k_core::plan::{PLAN_MAGIC, Plan};

const REC_ID: u16 = 0x0001;
const REC_PROTO: u16 = 0x0002;
const REC_PAYLOAD: u16 = 0x0010;
const REC_POISON: u16 = 0x0011;
const REC_SPLIT: u16 = 0x0100;
const REC_FAKE: u16 = 0x0101;
const REC_SEQOVL: u16 = 0x0102;
const REC_ORDER: u16 = 0x0103;
const REC_GUARD: u16 = 0x0104;
const REC_PACE: u16 = 0x0105;
const REC_INPUT: u16 = 0x0106;
const REC_SETTLE: u16 = 0x0107;
const REC_SEGMENT: u16 = 0x0108;
const REC_WIRE: u16 = 0x0109;
const REC_INPUT_TLS: u16 = 0x010a;
const REC_DELAY: u16 = 0x010b;
const REC_IPFRAG: u16 = 0x010c;
const REC_OOB: u16 = 0x010d;
const REC_UDPLEN: u16 = 0x010e;
const REC_QSPLIT: u16 = 0x010f;
const REC_QDENY: u16 = 0x0110;

const MAX_DIRECTIVES: usize = 8;
const MAX_PLAN_BYTES: usize = 65_000;
const MAX_PAYLOADS: usize = 8;
const MAX_POISONS: usize = 8;
const MAX_SPLITS: usize = 8;
const MAX_FAKES: usize = 8;
const MAX_SEQOVLS: usize = 4;

#[derive(Default)]
struct ParsedPlan {
    header_seen: bool,
    schema: u16,
    minexec: u16,
    id: [u8; 16],
    transport: u8,
    proto: u8,
    payloads: Vec<(u16, Vec<u8>)>,
    poisons: Vec<Vec<u8>>,
    splits: Vec<Vec<u8>>,
    fakes: Vec<Vec<u8>>,
    seqovls: Vec<Vec<u8>>,
    order: u8,
    guards: u8,
    pace_us: u32,
    input: Option<Vec<u8>>,
    input_tls: bool,
    settle_us: u32,
    segment_size: u32,
    wire_profile: u8,
    delay_us: u32,
    ipfrag: u8,
    oob: Option<Vec<u8>>,
    udplen: u16,
    qsplit: u8,
    qdeny: u8,
}

/// Скомпилировать текст `r2o-plan` в канонический формат R2OP для передачи.
/// Неизвестные директивы отклоняются; полученные байты повторно проверяются
/// тем же парсером R2OP, который использует datapath.
pub fn compile_text(text: &str) -> Result<Vec<u8>, String> {
    if text.as_bytes().contains(&0) {
        return Err("plan text contains NUL".into());
    }
    let mut plan = ParsedPlan::default();
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        if raw_line.len() >= 8192 {
            return Err(format!("line {line_number} exceeds 8191 bytes"));
        }
        let line = raw_line.trim_matches([' ', '\t', '\r']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line
            .split([' ', '\t'])
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() > MAX_DIRECTIVES {
            return Err(format!("line {line_number}: more than 8 fields"));
        }
        let parse_error = |message: &str| format!("line {line_number}: {message}");
        match fields[0] {
            "r2o-plan" => {
                require_fields(
                    &fields,
                    3,
                    line_number,
                    "r2o-plan expects schema and minexec",
                )?;
                plan.schema = number(fields[1], u16::MAX as u64)
                    .map_err(|_| parse_error("invalid schema"))?
                    as u16;
                plan.minexec = number(fields[2], u16::MAX as u64)
                    .map_err(|_| parse_error("invalid minexec"))?
                    as u16;
                plan.header_seen = true;
            }
            "id" => {
                require_fields(&fields, 2, line_number, "id expects one hex word")?;
                let bytes =
                    hex(fields[1]).map_err(|_| parse_error("id must be 16 bytes of hex"))?;
                if bytes.len() != 16 {
                    return Err(parse_error("id must be 16 bytes of hex"));
                }
                plan.id.copy_from_slice(&bytes);
            }
            "proto" => {
                require_fields(
                    &fields,
                    3,
                    line_number,
                    "proto expects transport and protocol",
                )?;
                plan.transport = match fields[1] {
                    "tcp" => 6,
                    "udp" => 17,
                    _ => return Err(parse_error("unknown transport")),
                };
                plan.proto = match fields[2] {
                    "unknown" => 0,
                    "tls" => 1,
                    "quic" => 2,
                    "voice" => 3,
                    "http" => 4,
                    _ => return Err(parse_error("unknown protocol")),
                };
            }
            "payload" => {
                if !(2..=3).contains(&fields.len()) || plan.payloads.len() >= MAX_PAYLOADS {
                    return Err(parse_error("payload expects id and optional hex bytes"));
                }
                let id = number(fields[1], u16::MAX as u64)
                    .map_err(|_| parse_error("payload id is out of range"))?
                    as u16;
                let bytes = hex(fields.get(2).copied().unwrap_or(""))
                    .map_err(|_| parse_error("invalid payload hex"))?;
                plan.payloads.push((id, bytes));
            }
            "payload-pad" | "payload-pad64" => {
                if !(4..=5).contains(&fields.len()) || plan.payloads.len() >= MAX_PAYLOADS {
                    return Err(parse_error(
                        "payload-pad expects id, length, fill, and optional prefix",
                    ));
                }
                let id = number(fields[1], u16::MAX as u64)
                    .map_err(|_| parse_error("invalid payload-pad id"))?
                    as u16;
                let length = number(fields[2], 65_533)
                    .map_err(|_| parse_error("invalid payload-pad length"))?
                    as usize;
                let fill = number(fields[3], u8::MAX as u64)
                    .map_err(|_| parse_error("invalid payload-pad fill"))?
                    as u8;
                if id == 0 || length == 0 {
                    return Err(parse_error("payload-pad id and length must be positive"));
                }
                let prefix_text = fields.get(4).copied().unwrap_or("");
                let prefix = if fields[0] == "payload-pad64" {
                    base64(prefix_text).map_err(|_| parse_error("invalid payload-pad64 prefix"))?
                } else {
                    hex(prefix_text).map_err(|_| parse_error("invalid payload-pad prefix"))?
                };
                if prefix.len() > length {
                    return Err(parse_error("payload-pad prefix exceeds output length"));
                }
                let mut bytes = vec![fill; length];
                bytes[..prefix.len()].copy_from_slice(&prefix);
                plan.payloads.push((id, bytes));
            }
            "payload-slice" => {
                require_fields(
                    &fields,
                    5,
                    line_number,
                    "payload-slice expects id source offset length",
                )?;
                if plan.payloads.len() >= MAX_PAYLOADS {
                    return Err(parse_error("too many payloads"));
                }
                let id = number(fields[1], u16::MAX as u64)
                    .map_err(|_| parse_error("invalid payload-slice id"))?
                    as u16;
                let source = number(fields[2], u16::MAX as u64)
                    .map_err(|_| parse_error("invalid payload-slice source"))?
                    as u16;
                let offset = number(fields[3], u32::MAX as u64)
                    .map_err(|_| parse_error("invalid payload-slice offset"))?
                    as usize;
                let length = number(fields[4], 65_533)
                    .map_err(|_| parse_error("invalid payload-slice length"))?
                    as usize;
                if id == 0 || length == 0 {
                    return Err(parse_error("payload-slice id and length must be positive"));
                }
                let source_bytes = plan
                    .payloads
                    .iter()
                    .find(|(payload_id, _)| *payload_id == source)
                    .map(|(_, bytes)| bytes)
                    .ok_or_else(|| parse_error("payload-slice source does not exist yet"))?;
                let end = offset
                    .checked_add(length)
                    .filter(|end| *end <= source_bytes.len())
                    .ok_or_else(|| parse_error("payload-slice exceeds its source"))?;
                plan.payloads.push((id, source_bytes[offset..end].to_vec()));
            }
            "wire" => {
                require_fields(&fields, 2, line_number, "wire expects one profile")?;
                plan.wire_profile = match fields[1] {
                    "detect-tcp-v1" => 1,
                    "tcp-template-v1" => 2,
                    _ => return Err(parse_error("unknown wire profile")),
                };
                if plan.wire_profile == 2 && plan.minexec < 8 {
                    return Err(parse_error("tcp-template-v1 requires minexec=8"));
                }
            }
            "input" => {
                if fields.len() == 2 && fields[1] == "tls-sni" {
                    plan.input_tls = true;
                } else {
                    require_fields(
                        &fields,
                        4,
                        line_number,
                        "input expects length, SNI offset, and SNI length",
                    )?;
                    let length = number(fields[1], u16::MAX as u64)
                        .map_err(|_| parse_error("invalid input length"))?
                        as u32;
                    let sni_off = number(fields[2], u32::MAX as u64)
                        .map_err(|_| parse_error("invalid input SNI offset"))?
                        as u32;
                    let sni_len = number(fields[3], u32::MAX as u64)
                        .map_err(|_| parse_error("invalid input SNI length"))?
                        as u32;
                    if length == 0 || sni_off > length || sni_len > length - sni_off {
                        return Err(parse_error("input SNI range is invalid"));
                    }
                    let mut value = Vec::with_capacity(12);
                    push_u32(&mut value, length);
                    push_u32(&mut value, sni_off);
                    push_u32(&mut value, sni_len);
                    plan.input = Some(value);
                }
            }
            "settle" | "segment" => {
                require_fields(
                    &fields,
                    2,
                    line_number,
                    "settle/segment expects one positive number",
                )?;
                let value = number(fields[1], u32::MAX as u64)
                    .map_err(|_| parse_error("invalid settle/segment value"))?
                    as u32;
                if value == 0 || (fields[0] == "segment" && value > u16::MAX as u32) {
                    return Err(parse_error("settle/segment value is out of range"));
                }
                if fields[0] == "settle" {
                    plan.settle_us = value;
                } else {
                    plan.segment_size = value;
                }
            }
            "poison" => {
                if fields.len() < 2 || plan.poisons.len() >= MAX_POISONS {
                    return Err(parse_error("poison expects an id and optional flags"));
                }
                let id = number(fields[1], u16::MAX as u64)
                    .map_err(|_| parse_error("poison id is out of range"))?
                    as u16;
                let mut ttl = 0_u8;
                let mut flags = 0_u8;
                let mut seq_shift = 0_i32;
                for field in &fields[2..] {
                    if *field == "badsum" {
                        flags |= 1;
                    } else if *field == "tcpts" {
                        flags |= 2;
                    } else if *field == "ipidzero" {
                        flags |= 4;
                    } else if *field == "md5" {
                        flags |= 8;
                    } else if let Some(value) = field.strip_prefix("ttl=") {
                        ttl = number(value, u8::MAX as u64)
                            .map_err(|_| parse_error("ttl is out of range"))?
                            as u8;
                    } else if let Some(value) = field.strip_prefix("seqshift=") {
                        seq_shift = value
                            .parse::<i32>()
                            .map_err(|_| parse_error("seqshift is outside int32"))?;
                    } else {
                        return Err(parse_error("unknown poison flag"));
                    }
                }
                let mut value = Vec::with_capacity(8);
                push_u16(&mut value, id);
                value.push(ttl);
                value.push(flags);
                push_u32(&mut value, seq_shift as u32);
                plan.poisons.push(value);
            }
            "split" => {
                require_fields(
                    &fields,
                    3,
                    line_number,
                    "split expects an anchor and offset",
                )?;
                if plan.splits.len() >= MAX_SPLITS {
                    return Err(parse_error("too many splits"));
                }
                let anchor =
                    anchor(fields[1]).ok_or_else(|| parse_error("unknown split anchor"))?;
                let offset = fields[2]
                    .parse::<i16>()
                    .map_err(|_| parse_error("split offset is outside int16"))?;
                let mut value = Vec::with_capacity(4);
                push_u16(&mut value, anchor);
                push_u16(&mut value, offset as u16);
                plan.splits.push(value);
            }
            "oob" => {
                require_fields(
                    &fields,
                    3,
                    line_number,
                    "oob expects an anchor and one byte",
                )?;
                if plan.oob.is_some() {
                    return Err(parse_error("duplicate oob directive"));
                }
                let anchor = anchor(fields[1]).ok_or_else(|| parse_error("unknown oob anchor"))?;
                let byte = hex(fields[2]).map_err(|_| parse_error("oob requires one hex byte"))?;
                if byte.len() != 1 {
                    return Err(parse_error("oob requires one hex byte"));
                }
                let mut value = Vec::with_capacity(3);
                push_u16(&mut value, anchor);
                value.push(byte[0]);
                plan.oob = Some(value);
            }
            "fake" => {
                if !(6..=7).contains(&fields.len()) || plan.fakes.len() >= MAX_FAKES {
                    return Err(parse_error(
                        "fake expects payload, poison, repeats, gap_us and place",
                    ));
                }
                let payload = kv_number(fields[1], "payload", u16::MAX as u64)
                    .map_err(|_| parse_error("fake requires payload="))?
                    as u16;
                let poison = kv_number(fields[2], "poison", u16::MAX as u64)
                    .map_err(|_| parse_error("fake requires poison="))?
                    as u16;
                let repeats = kv_number(fields[3], "repeats", u8::MAX as u64)
                    .map_err(|_| parse_error("fake requires repeats="))?
                    as u8;
                let gap = kv_number(fields[4], "gap_us", u32::MAX as u64)
                    .map_err(|_| parse_error("fake requires gap_us="))?
                    as u32;
                let placement = match fields[5] {
                    "place=before" => 0,
                    "place=between" => 1,
                    _ => return Err(parse_error("unknown fake placement")),
                };
                let tls_mod = if fields.len() == 7 {
                    if plan.minexec < 8 {
                        return Err(parse_error("tlsmod requires minexec=8"));
                    }
                    match fields[6] {
                        "tlsmod=rnd,dupsid" => 3,
                        "tlsmod=rnd" => 1,
                        "tlsmod=dupsid" => 2,
                        _ => return Err(parse_error("unknown tlsmod")),
                    }
                } else {
                    0
                };
                let mut value = Vec::with_capacity(11);
                push_u16(&mut value, payload);
                push_u16(&mut value, poison);
                value.push(repeats);
                value.push(placement);
                push_u32(&mut value, gap);
                if tls_mod != 0 {
                    value.push(tls_mod);
                }
                plan.fakes.push(value);
            }
            "seqovl" => {
                require_fields(
                    &fields,
                    3,
                    line_number,
                    "seqovl expects payload= and poison=",
                )?;
                if plan.seqovls.len() >= MAX_SEQOVLS {
                    return Err(parse_error("too many sequence overlays"));
                }
                let payload = kv_number(fields[1], "payload", u16::MAX as u64)
                    .map_err(|_| parse_error("seqovl requires payload="))?
                    as u16;
                let poison = kv_number(fields[2], "poison", u16::MAX as u64)
                    .map_err(|_| parse_error("seqovl requires poison="))?
                    as u16;
                let mut value = Vec::with_capacity(4);
                push_u16(&mut value, payload);
                push_u16(&mut value, poison);
                plan.seqovls.push(value);
            }
            "order" => {
                require_fields(&fields, 2, line_number, "order expects one value")?;
                plan.order = match fields[1] {
                    "forward" => 0,
                    "reverse" => 1,
                    _ => return Err(parse_error("unknown order")),
                };
            }
            "pace" | "delay" => {
                require_fields(
                    &fields,
                    2,
                    line_number,
                    "pace/delay expects one positive number",
                )?;
                let value = number(fields[1], u32::MAX as u64)
                    .map_err(|_| parse_error("invalid pace/delay value"))?
                    as u32;
                if value == 0 {
                    return Err(parse_error("pace/delay must be positive"));
                }
                if fields[0] == "pace" {
                    plan.pace_us = value;
                } else {
                    plan.delay_us = value;
                }
            }
            "ipfrag" | "quicsplit" | "quicdeny" => {
                require_fields(
                    &fields,
                    2,
                    line_number,
                    "directive expects one numeric form",
                )?;
                match fields[0] {
                    "ipfrag" => {
                        let value = number(fields[1], 4)
                            .map_err(|_| parse_error("ipfrag form must be 1..4"))?
                            as u8;
                        if value == 0 || plan.ipfrag != 0 {
                            return Err(parse_error("ipfrag form must be 1..4 and unique"));
                        }
                        plan.ipfrag = value;
                    }
                    "quicsplit" => {
                        if fields[1] != "1" || plan.qsplit != 0 {
                            return Err(parse_error("quicsplit form must be 1 and unique"));
                        }
                        plan.qsplit = 1;
                    }
                    _ => {
                        if fields[1] != "1" || plan.qdeny != 0 {
                            return Err(parse_error("quicdeny form must be 1 and unique"));
                        }
                        plan.qdeny = 1;
                    }
                }
            }
            "udplen" => {
                require_fields(
                    &fields,
                    2,
                    line_number,
                    "udplen expects one positive number",
                )?;
                let value = number(fields[1], u16::MAX as u64)
                    .map_err(|_| parse_error("udplen must be 1..65535"))?
                    as u16;
                if value == 0 || plan.udplen != 0 {
                    return Err(parse_error("udplen must be 1..65535 and unique"));
                }
                plan.udplen = value;
            }
            "guard" => {
                require_fields(&fields, 2, line_number, "guard expects one value")?;
                if fields[1] != "rst_alien" {
                    return Err(parse_error("unknown guard"));
                }
                plan.guards |= 1;
            }
            _ => return Err(parse_error(&format!("unknown directive {}", fields[0]))),
        }
    }

    if !plan.header_seen {
        return Err("missing r2o-plan header".into());
    }
    let mut records = Vec::<(u16, Vec<u8>)>::new();
    records.push((REC_ID, plan.id.to_vec()));
    records.push((REC_PROTO, vec![plan.transport, plan.proto]));
    records.extend(plan.payloads.into_iter().map(|(id, bytes)| {
        let mut value = Vec::with_capacity(bytes.len() + 2);
        push_u16(&mut value, id);
        value.extend_from_slice(&bytes);
        (REC_PAYLOAD, value)
    }));
    records.extend(plan.poisons.into_iter().map(|value| (REC_POISON, value)));
    records.extend(plan.splits.into_iter().map(|value| (REC_SPLIT, value)));
    records.extend(plan.fakes.into_iter().map(|value| (REC_FAKE, value)));
    records.extend(plan.seqovls.into_iter().map(|value| (REC_SEQOVL, value)));
    records.push((REC_ORDER, vec![plan.order]));
    if plan.pace_us != 0 {
        records.push((REC_PACE, plan.pace_us.to_be_bytes().to_vec()));
    }
    if let Some(input) = plan.input {
        records.push((REC_INPUT, input));
    }
    if plan.settle_us != 0 {
        records.push((REC_SETTLE, plan.settle_us.to_be_bytes().to_vec()));
    }
    if plan.segment_size != 0 {
        records.push((REC_SEGMENT, plan.segment_size.to_be_bytes().to_vec()));
    }
    if plan.input_tls {
        records.push((REC_INPUT_TLS, Vec::new()));
    }
    if plan.delay_us != 0 {
        records.push((REC_DELAY, plan.delay_us.to_be_bytes().to_vec()));
    }
    if plan.wire_profile != 0 {
        records.push((REC_WIRE, vec![plan.wire_profile]));
    }
    if plan.ipfrag != 0 {
        records.push((REC_IPFRAG, vec![plan.ipfrag]));
    }
    if plan.udplen != 0 {
        records.push((REC_UDPLEN, plan.udplen.to_be_bytes().to_vec()));
    }
    if plan.qsplit != 0 {
        records.push((REC_QSPLIT, vec![plan.qsplit]));
    }
    if plan.qdeny != 0 {
        records.push((REC_QDENY, vec![plan.qdeny]));
    }
    if let Some(oob) = plan.oob {
        records.push((REC_OOB, oob));
    }
    if plan.guards != 0 {
        records.push((REC_GUARD, vec![plan.guards]));
    }

    let record_count = u16::try_from(records.len()).map_err(|_| "too many plan records")?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&PLAN_MAGIC);
    push_u16(&mut bytes, plan.schema);
    push_u16(&mut bytes, plan.minexec);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, record_count);
    for (kind, value) in records {
        let value_len =
            u16::try_from(value.len()).map_err(|_| "plan record exceeds 65535 bytes")?;
        push_u16(&mut bytes, kind);
        push_u16(&mut bytes, value_len);
        bytes.extend_from_slice(&value);
    }
    if bytes.len() > MAX_PLAN_BYTES {
        return Err(format!("compiled plan exceeds {MAX_PLAN_BYTES} bytes"));
    }
    Plan::parse(&bytes).map_err(|error| format!("compiled R2OP plan rejected: {error}"))?;
    Ok(bytes)
}

fn require_fields(
    fields: &[&str],
    expected: usize,
    line: usize,
    message: &str,
) -> Result<(), String> {
    if fields.len() == expected {
        Ok(())
    } else {
        Err(format!("line {line}: {message}"))
    }
}

fn number(value: &str, maximum: u64) -> Result<u64, ()> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let parsed = value.parse::<u64>().map_err(|_| ())?;
    (parsed <= maximum).then_some(parsed).ok_or(())
}

fn kv_number(value: &str, key: &str, maximum: u64) -> Result<u64, ()> {
    let (actual_key, actual_value) = value.split_once('=').ok_or(())?;
    if actual_key != key {
        return Err(());
    }
    number(actual_value, maximum)
}

fn hex(value: &str) -> Result<Vec<u8>, ()> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    let mut output = Vec::with_capacity(bytes.len() / 2);
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(());
    }
    for pair in pairs {
        let high = hex_nibble(pair[0]).ok_or(())?;
        let low = hex_nibble(pair[1]).ok_or(())?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn base64(value: &str) -> Result<Vec<u8>, ()> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(());
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    let (chunks, remainder) = bytes.as_chunks::<4>();
    if !remainder.is_empty() {
        return Err(());
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let final_chunk = index + 1 == bytes.len() / 4;
        let a = base64_value(chunk[0]).ok_or(())?;
        let b = base64_value(chunk[1]).ok_or(())?;
        output.push((a << 2) | (b >> 4));
        if chunk[2] == b'=' {
            if !final_chunk || chunk[3] != b'=' || b & 15 != 0 {
                return Err(());
            }
            continue;
        }
        let c = base64_value(chunk[2]).ok_or(())?;
        output.push((b << 4) | (c >> 2));
        if chunk[3] == b'=' {
            if !final_chunk || c & 3 != 0 {
                return Err(());
            }
            continue;
        }
        let d = base64_value(chunk[3]).ok_or(())?;
        output.push((c << 6) | d);
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn anchor(value: &str) -> Option<u16> {
    match value {
        "payload_start" => Some(0),
        "sni_start" => Some(1),
        "sni_end" => Some(2),
        "hello_middle" => Some(3),
        "record_end" => Some(4),
        "sni_middle" => Some(5),
        _ => None,
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}
