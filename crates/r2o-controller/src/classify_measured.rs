//! Преобразование измеренной гипотезы искажения в программу R2OP для r2o-datapath.

use std::fmt::Write as _;

use r2k_core::plan::Plan;

use crate::classify::{Poison, Trigger, poison_has_fake};

const MAX_TRIGGER: usize = 16_384;
const MAX_DECOY: usize = 2_048;
const MAX_TEXT: usize = 8_192;
const SEGMENT_SIZE: usize = 1_400;

/// Собрать и проверить точные байты плана R2OP для измеренного искажения.
///
/// `decoy` — последовательность байтов, отправленная при raw-замере. Передача
/// этих байтов не позволяет стратегии подменить фактически проверенный профиль
/// сгенерированным TLS-профилем.
pub fn plan_bytes_for_poison(
    poison: &Poison,
    trigger: &Trigger,
    decoy: Option<&[u8]>,
    send_cap: usize,
) -> Result<Vec<u8>, String> {
    let text = plan_text_for_poison(poison, trigger, decoy, send_cap)?;
    crate::plan_text::compile_text(&text)
}

/// Собрать совместимый с каталогом текст измеренного плана искажения.
pub fn plan_text_for_poison(
    poison: &Poison,
    trigger: &Trigger,
    decoy: Option<&[u8]>,
    send_cap: usize,
) -> Result<String, String> {
    measured_plan_text(poison, trigger, decoy, send_cap)
}

/// Собрать неизменяемый план, который будет выполнять парсер datapath.
pub fn plan_for_poison(
    poison: &Poison,
    trigger: &Trigger,
    decoy: Option<&[u8]>,
    send_cap: usize,
) -> Result<Plan, String> {
    let bytes = plan_bytes_for_poison(poison, trigger, decoy, send_cap)?;
    Plan::parse(&bytes).map_err(|error| format!("compiled R2OP plan rejected: {error}"))
}

fn measured_plan_text(
    poison: &Poison,
    trigger: &Trigger,
    decoy: Option<&[u8]>,
    send_cap: usize,
) -> Result<String, String> {
    let n = trigger.payload.len();
    if !(2..=MAX_TRIGGER).contains(&n) {
        return Err("measured trigger length is outside 2..=16384".into());
    }
    let (sni_off, sni_len) = crate::hello::sni_bounds(&trigger.payload).unwrap_or((0, 0));
    let named = sni_off > 0 && sni_len > 1;
    if poison.syn_data {
        return Err("данные в SYN языком плана не выражаются".into());
    }
    if poison.seq_shift != 0 && poison.seq_shift != -66_000 {
        return Err(format!(
            "сдвиг TCP seq {} не выражается флагом seq_out",
            poison.seq_shift
        ));
    }
    let between = poison.fake_between;
    let decoy = if !between && (poison.decoy_hello || poison.seqovl_exact) {
        let measured = decoy.unwrap_or_default();
        if measured.is_empty() {
            return Err("приём с приветствием требует сохранённую измеренную приманку".into());
        }
        measured
    } else {
        &[]
    };
    if decoy.len() > MAX_DECOY {
        return Err("measured decoy exceeds 2048 bytes".into());
    }
    if poison.repeats > u8::MAX as i32 {
        return Err("measured repeat count exceeds 255".into());
    }
    if poison.ttl > u8::MAX as i32 {
        return Err("measured TTL exceeds 255".into());
    }
    if poison.gap_ms > (u32::MAX / 1000) as i32 {
        return Err("measured gap exceeds the plan range".into());
    }
    let repeats = if poison.repeats > 0 {
        poison.repeats as u32
    } else if poison_has_fake(poison) {
        1
    } else {
        0
    };
    let gap_us = if poison.gap_ms > 0 {
        poison.gap_ms as u32 * 1000
    } else {
        0
    };
    let ttl = poison.ttl.max(0) as u32;
    let mut overlap = if poison.seqovl_exact {
        decoy.len()
    } else {
        poison.seqovl.max(0) as usize
    };
    if overlap > MAX_DECOY {
        return Err("measured overlap exceeds 2048 bytes".into());
    }

    if between {
        overlap = 0;
    }
    let fake = !between
        && (poison.badsum || poison.md5 || ttl > 0 || poison.seq_shift != 0 || poison.tcp_ts);
    let disorder = !between && poison.disorder;
    let disorder_pos = poison.disorder_pos.max(0) as usize;
    let split_pos = poison.split_pos.max(0) as usize;

    if split_pos != 0
        && !poison.badsum
        && !poison.md5
        && repeats == 0
        && ttl == 0
        && poison.seq_shift == 0
        && !poison.decoy_hello
        && !poison.tcp_ts
        && !poison.ip_id_zero
        && !poison.disorder
        && disorder_pos == 0
        && !between
        && overlap == 0
        && !poison.oob
    {
        if split_pos >= n {
            return Err("measured split is outside the trigger".into());
        }
        return checked_text(format!(
            "r2o-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsegment {SEGMENT_SIZE}\nsplit payload_start +{split_pos}\norder forward\npace {gap_us}\n"
        ));
    }

    if poison.tcp_ts
        && poison.decoy_hello
        && repeats == 8
        && split_pos == 2
        && !poison.badsum
        && !poison.md5
        && ttl == 0
        && poison.seq_shift == 0
        && gap_us == 0
        && !poison.disorder
        && disorder_pos == 0
        && !between
        && overlap == 0
        && !poison.ip_id_zero
        && !poison.oob
    {
        if !named || decoy.is_empty() {
            return Err("composite timestamp plan requires a measured named hello".into());
        }
        if send_cap > 0 && (decoy.len() > send_cap || send_cap - decoy.len() < 132) {
            return Err("composite measured hello exceeds the send cap".into());
        }
        let mut text = format!(
            "r2o-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\ninput tls-sni\nsegment {SEGMENT_SIZE}\npayload 1 {}\npoison 1 tcpts\nfake payload=1 poison=1 repeats=8 gap_us=0 place=before tlsmod=rnd,dupsid\nsplit payload_start +2\norder forward\n",
            hex(decoy)
        );
        return checked_text(std::mem::take(&mut text));
    }

    if disorder_pos != 0 {
        if !poison.disorder
            || disorder_pos >= n
            || overlap != 0
            || poison.seqovl_exact
            || poison.badsum
            || poison.md5
            || repeats != 0
            || gap_us != 0
            || between
            || ttl != 0
            || poison.seq_shift != 0
            || poison.decoy_hello
            || poison.tcp_ts
            || poison.ip_id_zero
            || poison.oob
            || split_pos != 0
        {
            return Err(
                "measured disorder position cannot be represented with these fields".into(),
            );
        }
        let input = if named {
            "input tls-sni".to_owned()
        } else {
            format!("input {n} {sni_off} {sni_len}")
        };
        return checked_text(format!(
            "r2o-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\n{input}\nsegment {SEGMENT_SIZE}\nsplit payload_start +{disorder_pos}\norder reverse\n"
        ));
    }

    if poison.oob {
        if overlap != 0
            || poison.seqovl_exact
            || poison.badsum
            || poison.md5
            || repeats != 0
            || gap_us != 0
            || poison.disorder
            || between
            || ttl != 0
            || poison.seq_shift != 0
            || poison.decoy_hello
            || poison.tcp_ts
            || poison.ip_id_zero
            || split_pos != 0
            || !named
        {
            return Err("measured urgent-byte plan requires a named TLS input only".into());
        }
        return checked_text(format!(
            "r2o-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\ninput tls-sni\nsegment {SEGMENT_SIZE}\noob sni_middle 0f\norder forward\n"
        ));
    }

    if disorder && !fake && named {
        let mut text = format!(
            "r2o-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\ninput tls-sni\nsegment {SEGMENT_SIZE}\n"
        );
        if overlap != 0 {
            append_measured_payload(&mut text, 2, overlap, decoy)?;
            text.push_str("seqovl payload=2 poison=0\n");
        }
        text.push_str("split payload_start +1\nsplit sni_middle +0\norder reverse\npace 12000\n");
        return checked_text(text);
    }

    let parameterized = !between && named;
    let minexec = if poison.md5 {
        12
    } else if parameterized {
        5
    } else {
        4
    };
    let mut text = if parameterized {
        format!(
            "r2o-plan 1 {minexec}\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\ninput tls-sni\nsegment {SEGMENT_SIZE}\n"
        )
    } else {
        format!(
            "r2o-plan 1 {minexec}\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\ninput {n} {sni_off} {sni_len}\nsegment {SEGMENT_SIZE}\n"
        )
    };
    let mid = if between { 1 } else { n / 2 };
    let mut mid = if named {
        sni_off + if between { 0 } else { sni_len / 2 }
    } else {
        mid
    };
    if between {
        if mid >= n {
            mid = 1;
        }
    } else {
        mid = mid.max(2).min(n - 1);
    }
    let fake_len = if between {
        n - mid
    } else {
        n.saturating_mul(2)
    };

    if (fake || between) && fake_len == 0 {
        return Err("measured fake payload is empty".into());
    }
    if fake || between {
        append_measured_payload(&mut text, 1, fake_len, if between { &[] } else { decoy })?;
        text.push_str("poison 1");
        if poison.badsum {
            text.push_str(" badsum");
        }
        if ttl > 0 {
            write!(text, " ttl={ttl}").expect("writing to String");
        }
        if !between {
            if poison.md5 {
                text.push_str(" md5");
            }
            if poison.tcp_ts {
                text.push_str(" tcpts");
            }
            if poison.ip_id_zero {
                text.push_str(" ipidzero");
            }
            if poison.seq_shift != 0 {
                text.push_str(" seqshift=-66000");
            }
        }
        text.push('\n');
    }

    if overlap != 0 {
        if fake && overlap <= fake_len {
            writeln!(text, "payload-slice 2 1 0 {overlap}").expect("writing to String");
        } else {
            append_measured_payload(&mut text, 2, overlap, decoy)?;
        }
        text.push_str("seqovl payload=2 poison=0\n");
    }

    if disorder {
        text.push_str("split payload_start +1\n");
    }
    if disorder && parameterized {
        text.push_str("split sni_middle +0\n");
    } else if disorder || between {
        writeln!(text, "split payload_start +{mid}").expect("writing to String");
    }
    if split_pos != 0 {
        if between || disorder || split_pos >= n {
            return Err("measured split is incompatible with disorder or fake-between".into());
        }
        writeln!(text, "split payload_start +{split_pos}").expect("writing to String");
    }
    if fake || between {
        writeln!(
            text,
            "fake payload=1 poison=1 repeats={} gap_us={} place={}",
            repeats.max(1),
            if between { 0 } else { gap_us },
            if between { "between" } else { "before" }
        )
        .expect("writing to String");
    }
    writeln!(
        text,
        "order {}",
        if disorder { "reverse" } else { "forward" }
    )
    .expect("writing to String");
    if disorder || between {
        text.push_str("pace 12000\n");
    }
    if fake {
        text.push_str("settle 15000\n");
    }

    if send_cap > 0 {
        let mut body = if fake || between {
            if between {
                n - mid
            } else {
                n.saturating_mul(2)
            }
        } else {
            0
        };
        body = body.max(overlap).min(SEGMENT_SIZE);
        let header = 40
            + if fake && poison.md5 {
                20
            } else if fake && poison.tcp_ts {
                12
            } else {
                0
            };
        if body > 0 && header + body > send_cap {
            return Err("measured packet exceeds the send cap".into());
        }
    }
    checked_text(text)
}

fn append_measured_payload(
    text: &mut String,
    id: u16,
    length: usize,
    prefix: &[u8],
) -> Result<(), String> {
    if length == 0 {
        return Err("measured payload cannot be empty".into());
    }
    let prefix = &prefix[..prefix.len().min(length)];
    write!(text, "payload-pad64 {id} {length} 15").expect("writing to String");
    if !prefix.is_empty() {
        write!(text, " {}", base64(prefix)).expect("writing to String");
    }
    text.push('\n');
    Ok(())
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(first >> 2) as usize] as char);
        out.push(TABLE[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(third & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to String");
    }
    out
}

fn checked_text(text: String) -> Result<String, String> {
    if text.len() >= MAX_TEXT {
        return Err("measured plan exceeds the 8191-byte text limit".into());
    }
    Ok(text)
}
