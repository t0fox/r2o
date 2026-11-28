//! Сериализация снимка без копирования колец и полного буфера JSON.

use super::{
    MEMORY_HISTORY_CAPACITY, MEMORY_HISTORY_FIELDS, REPORT_MAX, Recorder, SAMPLE_INTERVAL,
};
use serde::Serialize;
use serde::ser::{SerializeSeq, SerializeTuple};
use serde_json::Value;
use std::fs::File;
use std::io::{BufWriter, Seek, Write};

#[derive(Clone)]
pub(super) struct MemoryRow {
    pub(super) at: u64,
    pub(super) mono_s: u64,
    pub(super) rss_kib: Option<i32>,
    pub(super) vm_data_kib: Option<i32>,
    pub(super) vm_swap_kib: Option<i32>,
    pub(super) rollup_status: u8,
    pub(super) rollup_errno: Option<i32>,
    pub(super) rollup: Option<[Option<i32>; 5]>,
    pub(super) rss_anon_kib: Option<i32>,
    pub(super) bytes: [Option<i32>; 6],
    pub(super) counts: [u8; 4],
    pub(super) epoch: u64,
}

struct RelativeRow<'a>(&'a MemoryRow, (u64, u64));

impl Serialize for RelativeRow<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (row, (at, mono_s)) = (self.0, self.1);
        let mut fields = serializer.serialize_tuple(MEMORY_HISTORY_FIELDS.len())?;
        fields.serialize_element(&row.at.saturating_sub(at))?;
        fields.serialize_element(&row.mono_s.saturating_sub(mono_s))?;
        fields.serialize_element(&row.rss_kib)?;
        fields.serialize_element(&row.vm_data_kib)?;
        fields.serialize_element(&row.vm_swap_kib)?;
        fields.serialize_element(&row.rollup_status)?;
        fields.serialize_element(&row.rollup_errno)?;
        fields.serialize_element(&row.rollup)?;
        fields.serialize_element(&row.rss_anon_kib)?;
        for n in &row.bytes {
            fields.serialize_element(n)?;
        }
        for n in &row.counts {
            fields.serialize_element(n)?;
        }
        fields.serialize_element(&row.epoch)?;
        fields.end()
    }
}

struct Rows<'a> {
    recorder: &'a Recorder,
    skip: usize,
    base: (u64, u64),
}

impl Serialize for Rows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq =
            serializer.serialize_seq(Some(self.recorder.memory_history.len() - self.skip))?;
        for row in self.recorder.memory_history.iter().skip(self.skip) {
            seq.serialize_element(&RelativeRow(row, self.base))?;
        }
        seq.end()
    }
}

#[derive(Serialize)]
struct History<'a> {
    capacity: usize,
    sample_interval_ms: u128,
    time_base: [Option<u64>; 2],
    smaps_rollup_status_codes: [&'static str; 5],
    fields: [&'static str; 20],
    samples: Rows<'a>,
}

#[derive(Serialize)]
struct ReportView<'a> {
    #[serde(flatten)]
    current: &'a Value,
    anomalies: &'a std::collections::VecDeque<Value>,
    events: &'a std::collections::VecDeque<Value>,
    limit_transitions: &'a std::collections::VecDeque<Value>,
    samples: &'a std::collections::VecDeque<Box<serde_json::value::RawValue>>,
    memory_history: History<'a>,
    memory_history_overwritten: u64,
}

pub(super) struct Report<'a> {
    recorder: &'a Recorder,
    current: Value,
}

impl<'a> Report<'a> {
    pub(super) fn new(recorder: &'a Recorder, current: Value) -> Self {
        Self { recorder, current }
    }
}

pub(super) trait SerializeReport {
    fn write_to(&self, writer: impl Write, skip: usize) -> serde_json::Result<()>;
}

impl SerializeReport for Report<'_> {
    fn write_to(&self, writer: impl Write, skip: usize) -> serde_json::Result<()> {
        let recorder = self.recorder;
        let base = recorder
            .memory_history
            .front()
            .map(|row| (row.at, row.mono_s));
        serde_json::to_writer(
            writer,
            &ReportView {
                current: &self.current,
                anomalies: &recorder.anomalies,
                events: &recorder.events,
                limit_transitions: &recorder.limits,
                samples: &recorder.samples,
                memory_history: History {
                    capacity: MEMORY_HISTORY_CAPACITY,
                    sample_interval_ms: SAMPLE_INTERVAL.as_millis(),
                    time_base: base.map_or([None; 2], |(at, mono_s)| [Some(at), Some(mono_s)]),
                    smaps_rollup_status_codes: [
                        "not-read",
                        "unavailable",
                        "ok",
                        "parse-error",
                        "unsupported",
                    ],
                    fields: MEMORY_HISTORY_FIELDS,
                    samples: Rows {
                        recorder,
                        skip,
                        base: base.unwrap_or_default(),
                    },
                },
                memory_history_overwritten: recorder
                    .memory_total
                    .saturating_sub((recorder.memory_history.len() - skip) as u64),
            },
        )
    }
}

#[cfg(test)]
impl SerializeReport for Value {
    fn write_to(&self, writer: impl Write, _skip: usize) -> serde_json::Result<()> {
        serde_json::to_writer(writer, self)
    }
}

/// Учитывает точный размер, пишет на диск максимум REPORT_MAX байт.
struct BoundedWriter<W> {
    writer: W,
    size: usize,
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = REPORT_MAX.saturating_sub(self.size);
        self.writer
            .write_all(&bytes[..bytes.len().min(remaining)])?;
        self.size += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

pub(super) fn write_bounded(
    file: &mut File,
    report: &impl SerializeReport,
    memory_rows: usize,
) -> Result<(), (&'static str, i32)> {
    let io_error = |err: std::io::Error| ("flush-close", err.raw_os_error().unwrap_or(0));
    let mut writer = BoundedWriter {
        writer: BufWriter::with_capacity(16 * 1024, file),
        size: 0,
    };
    let mut skip = 0;
    loop {
        report
            .write_to(&mut writer, skip)
            .map_err(|err| match err.io_error_kind() {
                Some(_) => (
                    "flush-close",
                    std::io::Error::from(err).raw_os_error().unwrap_or(0),
                ),
                None => ("serialize", 0),
            })?;
        if writer.size <= REPORT_MAX {
            writer.flush().map_err(io_error)?;
            if skip != 0 {
                writer
                    .writer
                    .get_mut()
                    .set_len(writer.size as u64)
                    .map_err(io_error)?;
            }
            return Ok(());
        }
        // Сохраняем прежний порядок вытеснения и базу времени опубликованных строк.
        let trim = ((writer.size - REPORT_MAX) / 96 + 1).min(memory_rows.saturating_sub(skip + 1));
        if trim == 0 {
            return Err(("size-limit", libc::EFBIG));
        }
        skip += trim;
        writer.writer.rewind().map_err(io_error)?;
        writer.size = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs::{self, OpenOptions};

    #[test]
    fn bounded_report_never_writes_past_limit_and_preserves_time_base() {
        let name = std::env::temp_dir().join(format!("r2o-diag-bound-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&name)
            .unwrap();
        let mut recorder = Recorder::new(name.clone(), name.clone());
        for index in 0..512 {
            recorder.memory_history.push_back(MemoryRow {
                at: 9_000 + 60 * index,
                mono_s: 60 * index,
                rss_kib: Some(8192),
                vm_data_kib: None,
                vm_swap_kib: None,
                rollup_status: 4,
                rollup_errno: None,
                rollup: None,
                rss_anon_kib: None,
                bytes: [None; 6],
                counts: [0; 4],
                epoch: 1,
            });
        }
        recorder.memory_total = 520;
        let report = Report::new(
            &recorder,
            json!({
                "schema": 1, "other": "x".repeat(REPORT_MAX - 4000),
            }),
        );
        write_bounded(&mut file, &report, recorder.memory_history.len()).unwrap();
        let bytes = fs::read(&name).unwrap();
        assert!(bytes.len() <= REPORT_MAX);
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        let rows = report["memory_history"]["samples"].as_array().unwrap();
        assert!((1..512).contains(&rows.len()));
        assert_eq!(report["memory_history"]["time_base"], json!([9000, 0]));
        assert_eq!(rows[0][0], (512 - rows.len()) * 60);
        assert_eq!(rows.last().unwrap()[1], 511 * 60);
        assert_eq!(report["memory_history_overwritten"], 520 - rows.len());
        assert_eq!(report["other"].as_str().unwrap().len(), REPORT_MAX - 4000);
        drop(file);
        fs::remove_file(name).unwrap();
    }
}
