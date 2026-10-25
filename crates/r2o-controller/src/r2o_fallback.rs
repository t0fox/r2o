//! Запасной список core/compose.c актуального d2o.

use crate::classify::Poison;
use std::collections::VecDeque;
use std::fmt::Write as _;

pub struct MeasuredArmFailure {
    pub transport: u8,
    pub search_owned: bool,
    pub owned_fallback: bool,
    pub own_first: u8,
    pub after_cached: bool,
    pub arm_matches: bool,
    pub applied: bool,
    pub local_limit: bool,
    pub dropped_before: u32,
    pub dropped_after: u32,
    pub transport_established: bool,
}

impl MeasuredArmFailure {
    pub fn fallback_enabled(&self) -> bool {
        self.owned_fallback
            || self.transport == 6
                && self.search_owned
                && self.own_first != 2
                && self.after_cached
                && self.arm_matches
                && self.applied
                && !self.local_limit
                && self.dropped_before == self.dropped_after
                && self.transport_established
    }
}

pub struct ProbeCounts {
    pub raw: usize,
    pub candidates: usize,
}

impl ProbeCounts {
    pub fn remaining(&self, cap: usize) -> usize {
        cap.saturating_sub(self.candidates)
    }

    pub fn total(&self) -> usize {
        self.raw.saturating_add(self.candidates)
    }
}

/// The scheduler stores the low 32 bits of its original FNV-1a text hash.
pub fn tried_key(text: &str) -> u32 {
    let text = text.replacen("r2o-plan", "d2k-plan", 1);
    text.bytes()
        .fold(1_469_598_103_934_665_603_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(1_099_511_628_211)
        }) as u32
}

pub struct FallbackQueue {
    next: usize,
    tried: Vec<u32>,
    pending: VecDeque<String>,
}

impl FallbackQueue {
    pub fn new(measured: &str) -> Self {
        Self {
            next: 0,
            tried: vec![tried_key(measured)],
            pending: VecDeque::new(),
        }
    }

    pub fn new_owned_search() -> Self {
        Self {
            next: 0,
            tried: Vec::new(),
            pending: VecDeque::new(),
        }
    }

    pub fn next(&mut self, shape: u8, send_cap: usize) -> Option<String> {
        // refill_from_fallback snapshots send_cap for each SCHED_MAX_PLANS batch.
        if self.pending.is_empty() {
            while self.pending.len() < 8 && self.next < 49 {
                let index = self.next;
                self.next += 1;
                let Some(text) = plan(index, shape, send_cap) else {
                    continue;
                };
                let key = tried_key(&text);
                if self.tried.contains(&key) {
                    continue;
                }
                self.tried.push(key);
                self.pending.push_back(text);
            }
        }
        self.pending.pop_front()
    }
}

fn arm(index: usize) -> Option<Poison> {
    let mut a = Poison::default();
    match index {
        0 => a.seqovl = 1,
        1..=3 => {
            a.badsum = true;
            a.repeats = if index == 3 { 7 } else { 2 };
            a.gap_ms = [20, 80, 0][index - 1];
        }
        4 => a.disorder = true,
        5 => {
            a.disorder = true;
            a.disorder_pos = 2;
        }
        6 => {
            a.badsum = true;
            a.repeats = 1;
        }
        7 => {
            a.repeats = 1;
            a.seq_shift = -66_000;
        }
        8..=9 => {
            a.badsum = true;
            a.fake_between = true;
            a.repeats = if index == 8 { 1 } else { 7 };
        }
        10..=11 => {
            a.seqovl_exact = true;
            a.disorder = index == 11;
        }
        12 => a.oob = true,
        13..=18 => {
            a.badsum = true;
            a.repeats = [7, 4, 2][(index - 13) % 3];
            a.seqovl_exact = true;
            a.decoy_hello = true;
            a.ttl = if index >= 16 { 62 } else { 0 };
        }
        19..=32 => {
            a.seqovl = [2, 4, 8, 16, 64, 336, 681][(index - 19) / 2];
            a.decoy_hello = (index - 19) % 2 != 0;
        }
        33..=48 => {
            a.badsum = true;
            a.repeats = [2, 3, 4, 7][(index - 33) % 4];
            a.gap_ms = [0, 20, 80, 300][(index - 33) / 4];
        }
        _ => return None,
    }
    Some(a)
}

/// Дословные порядок и сборка d2k_fallback_plan/fb_arm_at/d2k_arm_plan.
pub fn plan(index: usize, shape: u8, send_cap: usize) -> Option<String> {
    let a = arm(index)?;
    let segment = if send_cap == 0 {
        1400
    } else {
        send_cap.checked_sub(72)?.min(1400)
    };
    if segment == 0 {
        return None;
    }
    let header = |version| {
        format!("r2o-plan 1 {version}\nid 00000000000000000000000000000000\nproto tcp tls\n")
    };
    if a.disorder_pos != 0 {
        return Some(format!(
            "{}wire detect-tcp-v1\ninput tls-sni\nsegment {segment}\nsplit payload_start +2\norder reverse\n",
            header(5)
        ));
    }
    if a.oob {
        return Some(format!(
            "{}wire detect-tcp-v1\ninput tls-sni\nsegment {segment}\noob sni_middle 0f\norder forward\n",
            header(8)
        ));
    }
    let hello = if a.seqovl_exact || a.decoy_hello || a.badsum || a.repeats > 0 || a.fake_between {
        if shape == 1 {
            crate::hello::modern_client_hello("disk.rzd.ru").ok()?
        } else {
            crate::hello::legacy_client_hello("disk.rzd.ru").ok()?
        }
    } else {
        Vec::new()
    };
    let room = send_cap.saturating_sub(120);
    if a.seqovl_exact && room > 0 && hello.len() + 1 > room {
        return None;
    }
    let payload = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut text = header(1);
    let have_fake = a.badsum || a.repeats > 0 || a.fake_between;
    if have_fake {
        let bytes = if a.decoy_hello {
            &hello[..if room > 0 {
                hello.len().min(room)
            } else {
                hello.len()
            }]
        } else {
            &[]
        };
        let value = if a.decoy_hello {
            payload(bytes)
        } else {
            "0f".repeat(if room > 0 { 64.min(room) } else { 64 })
        };
        writeln!(text, "payload 1 {value}").unwrap();
    }
    if a.seqovl_exact {
        writeln!(text, "payload 2 {}", payload(&hello)).unwrap();
    } else if a.seqovl > 0 {
        writeln!(text, "payload 2 {}", "0f".repeat(a.seqovl as usize)).unwrap();
    }
    if have_fake || a.seq_shift != 0 {
        text.push_str("poison 1");
        if a.badsum {
            text.push_str(" badsum");
        }
        if a.ttl != 0 {
            write!(text, " ttl={}", a.ttl).unwrap();
        }
        if a.seq_shift != 0 {
            text.push_str(" seqshift=-66000");
        }
        text.push('\n');
    }
    if a.seqovl > 0 || a.seqovl_exact || a.disorder || a.fake_between {
        text.push_str("split payload_start +1\n");
    }
    if a.disorder || a.fake_between {
        text.push_str("split sni_middle +0\n");
    }
    if have_fake {
        writeln!(
            text,
            "fake payload=1 poison=1 repeats={} gap_us={} place={}",
            a.repeats.max(1),
            a.gap_ms * 1000,
            if a.fake_between { "between" } else { "before" }
        )
        .unwrap();
    }
    if a.seqovl_exact || a.seqovl > 0 {
        text.push_str("seqovl payload=2 poison=0\n");
    }
    writeln!(
        text,
        "order {}",
        if a.disorder { "reverse" } else { "forward" }
    )
    .unwrap();
    if a.disorder {
        text.push_str("pace 12000\n");
    } else if have_fake {
        text.push_str("pace 15000\n");
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    #[test]
    fn fallback_queue_batches_and_tried_hashes_match_donor() {
        let mut output = String::new();
        for shape in [1, 2] {
            let measured = super::plan(12, shape, 1492).unwrap();
            let mut queue = super::FallbackQueue::new(&measured);
            let mut emitted = 0;
            loop {
                let cap = if emitted < 3 {
                    1492
                } else if emitted < 13 {
                    1200
                } else {
                    100
                };
                let Some(text) = queue.next(shape, cap) else {
                    break;
                };
                output.push_str(&format!("{shape} {emitted} {}\n", super::tried_key(&text)));
                output.push_str(&text.replace("r2o-plan", "d2k-plan"));
                emitted += 1;
            }
            assert!(emitted > 30);
        }
        if let Ok(path) = std::env::var("R2O_FALLBACK_QUEUE_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn measured_failure_fallback_gate_matches_donor() {
        let mut output = String::new();
        for mode in 0..12 {
            let failure = super::MeasuredArmFailure {
                transport: if mode == 1 { 17 } else { 6 },
                search_owned: mode != 2,
                owned_fallback: mode == 3,
                own_first: if mode == 4 { 2 } else { 0 },
                after_cached: mode != 5,
                arm_matches: !matches!(mode, 6 | 7),
                applied: mode != 8,
                local_limit: mode == 9,
                dropped_before: 7,
                dropped_after: if mode == 10 { 8 } else { 7 },
                transport_established: mode != 11,
            };
            let enabled = failure.fallback_enabled();
            assert_eq!(enabled, matches!(mode, 0 | 3), "mode={mode}");
            output.push_str(&format!("{mode} {}\n", u8::from(enabled)));
        }
        if let Ok(path) = std::env::var("R2O_FALLBACK_GATE_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn raw_measurements_do_not_consume_candidate_budget() {
        let mut output = String::new();
        for raw in [0, 5, 67, 100] {
            for candidates in [0, 1, 66, 67] {
                let counts = super::ProbeCounts { raw, candidates };
                let remaining = counts.remaining(67);
                assert_eq!(
                    remaining,
                    67 - candidates,
                    "raw={raw}, candidates={candidates}"
                );
                output.push_str(&format!("{raw} {candidates} {remaining}\n"));
            }
        }
        if let Ok(path) = std::env::var("R2O_RAW_BUDGET_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn fallback_plans_match_donor() {
        assert!(
            super::plan(0, 1, 1492).is_some(),
            "donor's first fallback arm is missing"
        );
        let mut output = String::new();
        for shape in [1, 2] {
            for cap in [0, 1492, 1200, 100, 60] {
                for index in 0..=49 {
                    let plan = super::plan(index, shape, cap);
                    output.push_str(&format!(
                        "{shape} {cap} {index} {}\n",
                        if plan.is_some() { "plan" } else { "skip" }
                    ));
                    if let Some(text) = plan {
                        let records = crate::plan_text::compile_text(&text).unwrap();
                        r2k_core::plan::Plan::parse(&records).unwrap();
                        output.push_str(&text.replace("r2o-plan", "d2k-plan"));
                    }
                }
            }
        }
        if let Ok(path) = std::env::var("R2O_FALLBACK_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }

    #[test]
    fn opaque_owned_search_starts_with_donor_fallback_queue() {
        let mut queue = super::FallbackQueue::new_owned_search();
        let mut output = String::new();
        for _ in 0..8 {
            let text = queue
                .next(1, 1492)
                .expect("donor fallback batch has eight arms");
            output.push_str(&text.replace("r2o-plan", "d2k-plan"));
        }
        if let Ok(path) = std::env::var("R2O_OWNED_FALLBACK_DIFF_OUTPUT") {
            std::fs::write(path, output).unwrap();
        }
    }
}
