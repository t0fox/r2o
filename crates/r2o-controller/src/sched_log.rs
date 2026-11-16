//! C `sched_say` (`core/d2kc.c:150-157`): журнал планировщика печатается в
//! stdout с локальным временем `ЧЧ:ММ:СС` и немедленным `fflush`, чтобы
//! строка была видна сразу при перенаправлении в файл.
//!
//! C `d2k_sched_set_say(s, sched_say, NULL)` направляет в эту функцию и
//! `say_quiet` (`core/sched.c:1615-1632`), поэтому подтверждённые строки
//! планировщика в d2kc имеют тот же префикс времени.

#[cfg(unix)]
pub fn r2o_sched_say_at(epoch_seconds: i64, line: &str) -> String {
    let moment = epoch_seconds as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let converted = unsafe { libc::localtime_r(&moment, &mut tm) };
    if converted.is_null() {
        // C оставил бы tm неинициализированным (UB); детерминированный
        // ноль лучше повторения неопределённого поведения.
        return format!("00:00:00 {line}");
    }
    format!("{:02}:{:02}:{:02} {line}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

#[cfg(unix)]
pub fn r2o_sched_say(line: &str) {
    use std::io::Write as _;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    println!("{}", r2o_sched_say_at(now, line));
    let _ = std::io::stdout().flush();
}

#[cfg(all(test, unix))]
mod tests {
    use super::r2o_sched_say_at;

    /// C/Rust differential: C-стенд вызывает production `sched_say` из
    /// d2kc.c и печатает окно `time(NULL)` до/после. Скрипт передаёт epoch,
    /// в котором окно не пересекло границу секунды, и сравнивает строку.
    #[test]
    fn sched_say_matches_c() {
        let Some(path) = std::env::var_os("R2O_SCHED_SAY_DIFF_OUTPUT") else {
            return;
        };
        let epoch: i64 = std::env::var("R2O_SCHED_SAY_EPOCH")
            .expect("R2O_SCHED_SAY_EPOCH")
            .parse()
            .expect("epoch");
        let line = r2o_sched_say_at(epoch, "планировщик: строка журнала");
        std::fs::write(path, format!("{line}\n")).unwrap();
        print!("{line}\n");
    }
}
