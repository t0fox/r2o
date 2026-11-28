use super::{Value, VecDeque, fs, json};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

const WINDOW: usize = 10;

#[derive(Clone, Copy)]
pub(super) struct Measurement {
    pid: u64,
    start_ticks: u64,
    mono_ms: u64,
    rss_kib: u64,
    anon_kib: Option<u64>,
    live_bytes: Option<u64>,
    peak_bytes: Option<u64>,
}

impl Measurement {
    pub(super) fn from_report(process: &Value, detail: &Value, mono_ms: u64) -> Option<Self> {
        let heap = &detail["build"]["heap"];
        Some(Self {
            pid: process["pid"].as_u64()?,
            start_ticks: detail["start_ticks"].as_u64()?,
            mono_ms,
            rss_kib: process["rss_kib"].as_u64()?,
            anon_kib: process["anon_kib"].as_u64(),
            live_bytes: heap["live_bytes"].as_u64(),
            peak_bytes: heap["peak_bytes"].as_u64(),
        })
    }
}

#[derive(Default)]
pub(super) struct Growth {
    window: VecDeque<Measurement>,
    last_report_ms: Option<u64>,
}

impl Growth {
    pub(super) fn reset_window(&mut self) {
        self.window.clear();
    }

    pub(super) fn record(
        &mut self,
        point: Option<Measurement>,
        name: &str,
        at: u64,
    ) -> Option<Value> {
        let Some(point) = point else {
            self.reset_window();
            return None;
        };
        if self
            .window
            .back()
            .is_none_or(|old| (old.pid, old.start_ticks) != (point.pid, point.start_ticks))
        {
            self.reset_window();
            self.last_report_ms = None;
        }
        if self.window.len() == WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(point);
        let first = self.window.front()?;
        let rss_delta = point.rss_kib.saturating_sub(first.rss_kib);
        let rising = self
            .window
            .iter()
            .zip(self.window.iter().skip(1))
            .filter(|(before, after)| after.rss_kib > before.rss_kib)
            .count();
        if self.window.len() != WINDOW
            || point.mono_ms.saturating_sub(first.mono_ms) < 540_000
            || rising < 7
            || rss_delta < 1024
            || self
                .last_report_ms
                .is_some_and(|last| point.mono_ms.saturating_sub(last) < 1_800_000)
        {
            return None;
        }
        let anon_delta = point.anon_kib.zip(first.anon_kib).map(|(now, before)| {
            i64::try_from(now).unwrap_or(i64::MAX) - i64::try_from(before).unwrap_or(i64::MAX)
        });
        let live_delta = point.live_bytes.zip(first.live_bytes).map(|(now, before)| {
            i64::try_from(now).unwrap_or(i64::MAX) - i64::try_from(before).unwrap_or(i64::MAX)
        });
        let relevant = i64::try_from(rss_delta.saturating_mul(256)).unwrap_or(i64::MAX);
        let cause = if live_delta.is_some_and(|delta| delta >= relevant) {
            "live-allocations"
        } else if live_delta.is_some_and(|delta| delta.abs_diff(0) < relevant as u64)
            && anon_delta.is_some_and(|delta| delta >= (rss_delta / 2) as i64)
            && point
                .peak_bytes
                .zip(first.peak_bytes)
                .is_some_and(|(now, before)| {
                    now.saturating_sub(before) >= relevant as u64
                        && point
                            .live_bytes
                            .is_some_and(|live| now.saturating_sub(live) >= relevant as u64)
                })
        {
            "possible-allocator-retention"
        } else {
            "unattributed"
        };
        self.last_report_ms = Some(point.mono_ms);
        Some(json!({
            "kind": "process-rss-growth",
            "process": name,
            "pid": point.pid,
            "start_ticks": point.start_ticks,
            "at": at,
            "cause": cause,
            "rss_delta_kib": rss_delta,
            "anon_delta_kib": anon_delta,
            "live_delta_bytes": live_delta,
            "window_samples": WINDOW,
        }))
    }
}

pub(super) fn start_ticks(base: &Path) -> Option<u64> {
    let stat = fs::read_to_string(base.join("stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

pub(super) fn anonymous(
    process: &Value,
    detail: &Value,
    base: &Path,
) -> (Option<u64>, &'static str) {
    if let Some(value) = process["anon_kib"].as_u64() {
        return (Some(value), "status");
    }
    if let Some(value) = detail["smaps_rollup"]["anonymous_kib"].as_u64() {
        return (Some(value), "smaps_rollup");
    }
    let value = fs::File::open(base.join("smaps"))
        .ok()
        .and_then(smaps_anonymous);
    value.map_or((None, "unavailable"), |value| (Some(value), "smaps"))
}

fn smaps_anonymous(input: impl Read) -> Option<u64> {
    const MAX: u64 = 1024 * 1024;
    let mut reader = BufReader::new(input.take(MAX + 1));
    let mut line = Vec::new();
    let mut sum = None::<u64>;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).ok()? == 0 {
            break;
        }
        if let Some(field) = line.strip_prefix(b"Anonymous:") {
            let value = std::str::from_utf8(field)
                .ok()?
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            sum = Some(sum.unwrap_or(0).checked_add(value)?);
        }
    }
    (reader.get_ref().limit() != 0).then_some(sum).flatten()
}

fn heap_payload(bytes: u64, objects: u64, peak_bytes: u64) -> Value {
    json!({
        "coverage": "rust-system-requests-since-start",
        "live_bytes": bytes,
        "live_objects": objects,
        "peak_bytes": peak_bytes,
    })
}

pub(super) fn local_build() -> Value {
    use r2k_core::memory_diagnostics::{BUILD, heap, linked_allocator};

    json!({
        "target": BUILD.target,
        "rustc": BUILD.rustc,
        "toolchain": BUILD.toolchain,
        "allocator": linked_allocator(),
        "heap": heap().map(|heap| heap_payload(heap.bytes as u64, heap.objects as u64, heap.peak_bytes as u64)),
    })
}

pub(super) fn read_build(path: &Path, pid: u64, ticks: u64) -> Option<Value> {
    let file = fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.modified().ok()?.elapsed().ok()?.as_secs() > 20 {
        return None;
    }
    let mut contents = String::new();
    file.take(2049).read_to_string(&mut contents).ok()?;
    if contents.len() > 2048 {
        return None;
    }
    let mut lines = contents.lines();
    let mut identity = lines.next()?.split_whitespace();
    if identity.next()?.parse::<u64>().ok()? != pid
        || identity.next()?.parse::<u64>().ok()? != ticks
    {
        return None;
    }
    let target = lines.next()?;
    let rustc = lines.next()?.trim();
    let toolchain = lines.next()?.trim();
    let allocator = lines.next()?.trim();
    let heap = lines.next().and_then(|line| {
        let mut fields = line.split_whitespace();
        Some(heap_payload(
            fields.next()?.parse().ok()?,
            fields.next()?.parse().ok()?,
            fields.next()?.parse().ok()?,
        ))
    });
    Some(json!({
        "target": target,
        "rustc": (!rustc.is_empty()).then_some(rustc),
        "toolchain": (!toolchain.is_empty()).then_some(toolchain),
        "allocator": (!allocator.is_empty()).then_some(allocator),
        "heap": heap,
    }))
}

pub(super) fn platform(proc_dir: &Path) -> Value {
    let kernel = fs::read_to_string(proc_dir.join("sys/kernel/osrelease")).ok();
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    json!({
        "kernel": kernel.as_deref().map(str::trim),
        "page_size": (page_size > 0).then_some(page_size),
        "architecture": std::env::consts::ARCH,
    })
}

pub(super) fn linkage(path: &Path) -> Option<&'static str> {
    let mut file = fs::File::open(path).ok()?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header).ok()?;
    if header.get(..4)? != b"\x7fELF" {
        return None;
    }
    let little = match header[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    fn read_int(bytes: &[u8], little: bool) -> u64 {
        let mut field = [0_u8; 8];
        if little {
            field[..bytes.len()].copy_from_slice(bytes);
            u64::from_le_bytes(field)
        } else {
            field[8 - bytes.len()..].copy_from_slice(bytes);
            u64::from_be_bytes(field)
        }
    }
    let (offset, size, count) = match header[4] {
        1 => (&header[28..32], &header[42..44], &header[44..46]),
        2 => (&header[32..40], &header[54..56], &header[56..58]),
        _ => return None,
    };
    let offset = read_int(offset, little);
    let size = read_int(size, little);
    let count = read_int(count, little);
    if offset == 0 || size < 4 || !(1..=128).contains(&count) {
        return None;
    }
    for index in 0..count {
        let mut tag = [0_u8; 4];
        file.seek(SeekFrom::Start(offset.checked_add(index * size)?))
            .ok()?;
        file.read_exact(&mut tag).ok()?;
        if read_int(&tag, little) == 3 {
            return Some("dynamic");
        }
    }
    Some("static")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(index: u64) -> Measurement {
        Measurement {
            pid: 50,
            start_ticks: 10,
            mono_ms: index * 60_000,
            rss_kib: 5000 + index * 200,
            anon_kib: Some(4000 + index * 200),
            live_bytes: None,
            peak_bytes: None,
        }
    }

    #[test]
    fn reports_datapath_growth_once_without_guessing_allocator_retention() {
        let mut growth = Growth::default();
        for i in 0..9 {
            assert!(
                growth
                    .record(Some(point(i)), "r2o-datapath", i * 60)
                    .is_none()
            );
        }
        let alert = growth.record(Some(point(9)), "r2o-datapath", 540).unwrap();
        assert_eq!(alert["process"], "r2o-datapath");
        assert_eq!(alert["cause"], "unattributed");
        assert!(
            growth
                .record(Some(point(10)), "r2o-datapath", 600)
                .is_none()
        );
        let mut replacement = point(11);
        replacement.start_ticks += 1;
        assert!(
            growth
                .record(Some(replacement), "r2o-datapath", 660)
                .is_none()
        );
        assert_eq!(growth.window.len(), 1);
    }

    #[test]
    fn compares_live_objects_and_allocator_high_water_separately() {
        let mut live = Growth::default();
        let mut retained = Growth::default();
        for i in 0..10 {
            let mut current = point(i);
            current.live_bytes = Some(100_000 + i * 100_000);
            current.peak_bytes = current.live_bytes;
            let live_result = live.record(Some(current), "live", i);
            current.live_bytes = Some(100_000);
            let retained_result = retained.record(Some(current), "retained", i);
            if i == 9 {
                assert_eq!(live_result.unwrap()["cause"], "live-allocations");
                assert_eq!(
                    retained_result.unwrap()["cause"],
                    "possible-allocator-retention"
                );
            }
        }
    }

    #[test]
    fn older_smaps_counts_anonymous_pages_and_preserves_missing_fields() {
        assert_eq!(
            smaps_anonymous("Rss: 24 kB\nAnonymous: 0 kB\n".as_bytes()),
            Some(0)
        );
        assert_eq!(
            smaps_anonymous("Anonymous: 8 kB\nAnonymous: 16 kB\n".as_bytes()),
            Some(24)
        );
        assert_eq!(smaps_anonymous("Rss: 24 kB\n".as_bytes()), None);
        assert_eq!(
            smaps_anonymous("Anonymous: 8 kB\nAnonymous: ?\n".as_bytes()),
            None
        );
    }
}
