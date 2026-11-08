//! Чистый Rust-порт текстовых builder'ов `core/compose.c` (`d2k-plan`).
//!
//! Runtime R2O продолжает использовать `r2o-plan`; этот модуль нужен для
//! C/Rust differential контракта compose и повторяет формат D2O байт в байт.

use crate::hello::{legacy_client_hello, modern_client_hello};

pub const D2K_P_UNKNOWN: u8 = 0;
pub const D2K_P_YES: u8 = 1;
pub const D2K_P_NO: u8 = 2;

const D2K_OVERLAP_FILLER: u8 = 0x0f;
const D2K_PACE_PIECE_US: u32 = 12_000;
const D2K_PACE_SETTLE_US: u32 = 15_000;
const D2K_COMPOSE_HELLO_MAX: usize = 1_800;
const D2K_HEAD_ROOM: usize = 120;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D2oComposeProps {
    pub tolerates_left_overlap: u8,
    pub tolerates_reorder: u8,
    pub validates_checksum: u8,
    pub parses_l7: u8,
    pub counts_duplicates: u8,
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn header() -> String {
    format!("d2k-plan 1 1\nid {}\nproto tcp tls\n", "0".repeat(32))
}

fn overlap_plan_text() -> String {
    format!(
        "{}payload 1 {D2K_OVERLAP_FILLER:02x}\nseqovl payload=1 poison=0\norder forward\n",
        header()
    )
}

fn reorder_plan_text() -> String {
    format!(
        "{}split payload_start +1\nsplit sni_middle +0\norder reverse\npace {D2K_PACE_PIECE_US}\n",
        header()
    )
}

fn badsum_fake_plan_text(payload: &[u8], repeats: u32, gap_us: u32) -> String {
    format!(
        "{}payload 1 {}\npoison 1 badsum\nfake payload=1 poison=1 repeats={repeats} gap_us={gap_us} place=before\norder forward\npace {D2K_PACE_SETTLE_US}\n",
        header(),
        hex(payload)
    )
}

/// `build_decoy_hello`: MODERN только для modern shape, иначе LEGACY.
fn decoy_hello(shape: u8, decoy: Option<&str>) -> Option<Vec<u8>> {
    let decoy = decoy?;
    if decoy.is_empty() {
        return None;
    }
    let hello = if shape == r2k_core::control::SHAPE_MODERN {
        modern_client_hello(decoy)
    } else {
        legacy_client_hello(decoy)
    }
    .ok()?;
    (hello.len() <= D2K_COMPOSE_HELLO_MAX).then_some(hello)
}

fn duplicates_plan_text(shape: u8, decoy: Option<&str>) -> Option<String> {
    let hello = decoy_hello(shape, decoy)?;
    Some(badsum_fake_plan_text(&hello, 2, 20_000))
}

fn parse_protocol_plan_text(shape: u8, decoy: Option<&str>) -> Option<String> {
    let hello = decoy_hello(shape, decoy)?;
    Some(badsum_fake_plan_text(&hello, 1, 0))
}

fn everything_plan_text(shape: u8, decoy: Option<&str>, send_cap: usize) -> Option<String> {
    let mut hello = decoy_hello(shape, decoy)?;
    let room = send_cap.saturating_sub(D2K_HEAD_ROOM);
    if room > 0 && hello.len() > room {
        hello.truncate(room);
    }
    Some(format!(
        "{}payload 1 {}\npayload 2 {D2K_OVERLAP_FILLER:02x}\npoison 1 badsum\nsplit payload_start +1\nsplit sni_middle +0\nfake payload=1 poison=1 repeats=2 gap_us=20000 place=before\nseqovl payload=2 poison=0\norder reverse\n",
        header(),
        hex(&hello)
    ))
}

/// Побайтный перенос `d2k_compose`; `cap` — максимум планов (C `cap`).
pub fn compose_plan_texts(
    properties: &D2oComposeProps,
    target_shape: u8,
    decoy: Option<&str>,
    send_cap: usize,
    cap: usize,
) -> Vec<String> {
    let mut plans = Vec::new();
    if cap == 0 {
        return plans;
    }
    if properties.tolerates_left_overlap == D2K_P_NO && plans.len() < cap {
        plans.push(overlap_plan_text());
    }
    if properties.tolerates_reorder == D2K_P_NO && plans.len() < cap {
        plans.push(reorder_plan_text());
    }
    if properties.counts_duplicates == D2K_P_YES
        && plans.len() < cap
        && let Some(plan) = duplicates_plan_text(target_shape, decoy)
    {
        plans.push(plan);
    }
    if properties.validates_checksum == D2K_P_NO
        && properties.parses_l7 != D2K_P_YES
        && plans.len() < cap
    {
        plans.push(badsum_fake_plan_text(&[D2K_OVERLAP_FILLER; 64], 1, 0));
    }
    if properties.parses_l7 == D2K_P_YES
        && plans.len() < cap
        && let Some(plan) = parse_protocol_plan_text(target_shape, decoy)
    {
        plans.push(plan);
    }
    if plans.is_empty()
        && cap > 0
        && let Some(plan) = everything_plan_text(target_shape, decoy, send_cap)
    {
        plans.push(plan);
    }
    plans
}

#[cfg(test)]
mod tests {
    use super::{D2oComposeProps, compose_plan_texts};

    #[test]
    fn overlap_plan_matches_d2o_text() {
        let props = D2oComposeProps {
            tolerates_left_overlap: 2,
            ..D2oComposeProps::default()
        };
        let plans = compose_plan_texts(&props, 0, Some("disk.rzd.ru"), 0, 8);
        assert_eq!(plans.len(), 1);
        assert!(plans[0].starts_with("d2k-plan 1 1\nid "));
        assert!(plans[0].contains("payload 1 0f\n"));
        assert!(plans[0].contains("seqovl payload=1 poison=0\n"));
    }

    #[test]
    fn empty_vector_requires_decoy_for_fallback() {
        let props = D2oComposeProps::default();
        assert!(compose_plan_texts(&props, 0, None, 0, 8).is_empty());
        assert_eq!(
            compose_plan_texts(&props, 0, Some("disk.rzd.ru"), 0, 8).len(),
            1
        );
    }
}
