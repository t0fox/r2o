//! D2O-совместимый heartbeat-файл Telegram watchdog.
//!
//! C `d2k_runtime_heartbeat` пишет строку `D2KH1`, а
//! `files/d2k-tg-watchdog.sh` проверяет её поля, свежесть по `/proc/uptime`
//! и совпадение pid/start_ticks/boot_id. R2O сохраняет тот же формат, чтобы
//! сторож не зависел от статистического сокета и мог отличить живой процесс
//! от переиспользованного pid.

use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

pub const HEALTH_MAGIC: &str = "D2KH1";

pub struct HealthWriter {
    path: PathBuf,
    start_ticks: u64,
    boot_id: String,
}

impl HealthWriter {
    pub fn new(path: PathBuf) -> io::Result<Self> {
        Ok(Self {
            path,
            start_ticks: self_start_ticks()?,
            boot_id: boot_id()?,
        })
    }

    /// Записать heartbeat атомарной заменой, как C `rename`.
    pub fn write(&self, connected: bool, ready: bool, external: bool) -> io::Result<()> {
        let heartbeat_ms = uptime_ms()?;
        let body = format!(
            "{HEALTH_MAGIC} {} {} {} {} {} {} - {} {} {}\n",
            std::process::id(),
            self.start_ticks,
            heartbeat_ms,
            self.boot_id,
            r2k_core::control::RELEASE_ID,
            r2k_core::control::PROTOCOL_VERSION,
            u8::from(connected),
            u8::from(ready),
            u8::from(external),
        );
        let temporary = PathBuf::from(format!(
            "{}.tmp.{}",
            self.path.display(),
            std::process::id()
        ));
        let _ = std::fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, body.as_bytes())?;
        drop(file);
        match std::fs::rename(&temporary, &self.path) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                Err(error)
            }
        }
    }
}

/// Поле 22 `/proc/<pid>/stat` — время старта процесса в тиках.
fn self_start_ticks() -> io::Result<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    stat_start_ticks(&stat).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat"))
}

fn stat_start_ticks(stat: &str) -> Option<u64> {
    let tail = stat.rsplit_once(')')?.1;
    let ticks = tail.split_whitespace().nth(19)?;
    ticks.parse().ok()
}

fn boot_id() -> io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}

fn uptime_ms() -> io::Result<u64> {
    let uptime = std::fs::read_to_string("/proc/uptime")?;
    let seconds: f64 = uptime
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "uptime"))?;
    Ok((seconds * 1000.0).round() as u64)
}

#[cfg(test)]
mod tests {
    use super::{HEALTH_MAGIC, HealthWriter, stat_start_ticks};

    #[test]
    fn parses_start_ticks_after_process_name_with_spaces_and_parentheses() {
        let mut fields = vec!["S".to_owned()];
        for index in 4..=22 {
            fields.push(index.to_string());
        }
        let stat = format!("42 (r2o (tg)) {}", fields.join(" "));
        assert_eq!(stat_start_ticks(&stat), Some(22));
        assert_eq!(stat_start_ticks("42 (tg) S"), None);
    }

    #[test]
    fn writes_d2o_heartbeat_line_with_expected_field_count() {
        let path = std::env::temp_dir().join(format!(
            "r2o-tg-health-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let writer = HealthWriter::new(path.clone()).unwrap();
        writer.write(true, true, false).unwrap();
        let line = std::fs::read_to_string(&path).unwrap();
        let fields: Vec<&str> = line.trim_end().split(' ').collect();
        assert_eq!(fields.len(), 11);
        assert_eq!(fields[0], HEALTH_MAGIC);
        assert_eq!(fields[1], std::process::id().to_string());
        assert!(fields[2].parse::<u64>().is_ok());
        assert!(fields[3].parse::<u64>().is_ok());
        assert!(!fields[4].is_empty());
        assert_eq!(fields[7], "-");
        assert_eq!(fields[8], "1");
        assert_eq!(fields[9], "1");
        assert_eq!(fields[10], "0");
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_file(&path).unwrap();
    }
}
