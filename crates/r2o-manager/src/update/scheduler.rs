use super::*;
use std::process::{Child, Command, Stdio};

#[cfg(unix)]
fn local_window() -> Option<u32> {
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    if now < 0 {
        return None;
    }
    let mut time = std::mem::MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::localtime_r(&now, time.as_mut_ptr()) }.is_null() {
        return None;
    }
    let time = unsafe { time.assume_init() };
    window(
        time.tm_year + 1900,
        time.tm_mon + 1,
        time.tm_mday,
        time.tm_hour,
    )
}

#[cfg(any(unix, test))]
fn window(year: i32, month: i32, day: i32, hour: i32) -> Option<u32> {
    (3..5)
        .contains(&hour)
        .then(|| (year * 10_000 + month * 100 + day) as u32)
}

#[cfg(not(unix))]
fn local_window() -> Option<u32> {
    None
}

fn claim_day(root: &Path, day: u32) -> Result<bool, UpdateError> {
    let _lock = UpdateLock::named(root, "update-schedule.lock", true)?;
    let marker = root.join("state/update-night.json");
    let previous = read_bounded(&marker, 128)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    if previous.is_some_and(|p| p["date"] == day) {
        return Ok(false);
    }
    write_json(root, "update-night.json", &json!({"date":day}))?;
    Ok(true)
}

pub fn run_update_schedule(
    root: &Path,
    adapter: &Path,
    default_auto: bool,
) -> Result<(), UpdateError> {
    set_auto_update(root, default_auto)?;
    let log_path = root.join("log/update-scheduler.log");
    let mut children: Vec<Child> = Vec::new();
    loop {
        children.retain_mut(|child| child.try_wait().is_ok_and(|status| status.is_none()));
        if let Some(day) = local_window() {
            match claim_day(root, day) {
                Ok(true) => {
                    if let Ok(path) = crate::active_component_path(root, "r2o-telegram") {
                        let mut refresh = Command::new(path);
                        refresh
                            .arg("--refresh-lists")
                            .env("R2O_LISTS_EXCLUDE_META", "1");
                        if let Ok(child) = spawn_logged(refresh, &log_path) {
                            children.push(child);
                        }
                    }
                    let state = read_state(root)?;
                    let auto = state["auto"].as_bool().unwrap_or(default_auto);
                    let mut update = Command::new(root.join("r2o-manager"));
                    update
                        .args([
                            if auto {
                                "update-install-auto"
                            } else {
                                "update-check"
                            },
                            "--root",
                        ])
                        .arg(root);
                    if auto {
                        update.arg("--service").arg(adapter);
                    }
                    if let Ok(child) = spawn_logged(update, &log_path) {
                        children.push(child);
                    }
                }
                Ok(false) => (),
                Err(error) => eprintln!("r2o-manager: расписание обновлений: {error}"),
            }
        }
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn spawn_logged(mut command: Command, log: &Path) -> io::Result<Child> {
    let file = OpenOptions::new().create(true).append(true).open(log)?;
    command
        .stdin(Stdio::null())
        .stdout(file.try_clone()?)
        .stderr(file);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_uses_nightly_window() {
        assert_eq!(window(2026, 11, 22, 2), None);
        assert_eq!(window(2026, 11, 22, 3), Some(20261122));
        assert_eq!(window(2026, 11, 22, 4), Some(20261122));
        assert_eq!(window(2026, 11, 22, 5), None);
    }

    #[test]
    fn scheduler_claims_the_date_only_once() {
        let tmp = super::super::tests::TestDir::new();
        assert!(claim_day(&tmp.0, 20261122).unwrap());
        assert!(!claim_day(&tmp.0, 20261122).unwrap());
        assert!(claim_day(&tmp.0, 20261123).unwrap());
    }
}
