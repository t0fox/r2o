use super::*;
use std::io::{Seek, SeekFrom};
use std::process::{Command, Stdio};

const JOURNAL: &str = "update-pending.json";
const STARTUP_LOGS: [&str; 6] = [
    "r2o-datapath.log",
    "r2o-datapath4.log",
    "r2o-datapath6.log",
    "r2o-controller.log",
    "r2o-controller4.log",
    "r2o-controller6.log",
];
const STARTUP_LOG_LIMIT: u64 = 8 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    version: u32,
    old: String,
    #[serde(default)]
    old_previous: Option<String>,
    target: String,
    #[serde(default)]
    committed: bool,
}

fn pending(root: &Path) -> Result<Option<Transaction>, UpdateError> {
    let path = root.join("state").join(JOURNAL);
    let bytes = match read_bounded(&path, 1024) {
        Ok(bytes) => bytes,
        Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let tx: Transaction = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if tx.version != 1 {
        return Err(io::Error::other("неподдерживаемая версия журнала обновления").into());
    }
    Ok(Some(tx))
}

fn clear(root: &Path) -> Result<(), UpdateError> {
    let state = root.join("state");
    fs::remove_file(state.join(JOURNAL))?;
    File::open(state)?.sync_all()?;
    Ok(())
}

/// Вызов адаптера ограничен, даже если дочерняя служба зависла.
fn service(root: &Path, adapter: &Path, action: &str) -> Result<(), UpdateError> {
    let mut command = Command::new(adapter);
    command.arg(action).stdin(Stdio::null());
    // Встроенные пути определяет адаптер запускаемого слота, включая старые выпуски.
    let releases = root.join("releases");
    for (variable, relative) in [
        ("R2O_FIREWALL", "router/r2o-firewall.sh"),
        ("R2O_PPE_ADAPTER", "router/r2o-ppe-deoffload.sh"),
    ] {
        if std::env::var_os(variable).is_some_and(|value| {
            let path = Path::new(&value);
            path.starts_with(&releases) && path.ends_with(relative)
        }) {
            command.env_remove(variable);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        #[cfg(target_os = "linux")]
        {
            let owner = std::process::id();
            // Адаптер не должен продолжить фазу остановки после гибели владельца журнала.
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() as u32 != owner {
                        return Err(io::Error::from_raw_os_error(libc::ECHILD));
                    }
                    Ok(())
                });
            }
        }
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("{action}: {status}")).into())
            };
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            #[cfg(not(unix))]
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(io::ErrorKind::TimedOut, action.to_owned()).into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn health(root: &Path, adapter: &Path, target: &str) -> Result<(), UpdateError> {
    let deadline = Instant::now() + Duration::from_secs(35);
    let mut consecutive = 0;
    loop {
        let current = read_install_slots(root)?.ok_or(crate::InstallError::NoActiveRelease)?;
        if current.current != target {
            return Err(io::Error::other("активный слот изменился во время проверки").into());
        }
        if service(root, adapter, "update-health").is_ok() {
            consecutive += 1;
            if consecutive == 3 {
                return Ok(());
            }
        } else {
            consecutive = 0;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("службы не прошли проверку готовности").into());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn startup_log_size(path: &Path) -> Option<u64> {
    let metadata = fs::symlink_metadata(path).ok()?;
    metadata.is_file().then(|| metadata.len())
}

fn report_failed_start(root: &Path, offsets: [u64; STARTUP_LOGS.len()]) {
    let log_dir = root.join("log");
    let mut stderr = io::stderr().lock();
    for (name, offset) in STARTUP_LOGS.into_iter().zip(offsets) {
        let path = log_dir.join(name);
        let Some(size) = startup_log_size(&path) else {
            continue;
        };
        // При ротации новый файл может начинаться с нулевого смещения.
        let start = if size < offset { 0 } else { offset };
        let start = start.max(size.saturating_sub(STARTUP_LOG_LIMIT));
        if size == start {
            continue;
        }
        let mut bytes = Vec::new();
        let result = File::open(path).and_then(|mut file| {
            file.seek(SeekFrom::Start(start))?;
            file.take(size - start).read_to_end(&mut bytes)
        });
        if result.is_ok() && !bytes.is_empty() {
            let _ = writeln!(
                stderr,
                "r2o: {name}, ошибка запуска до отката:\n{}",
                String::from_utf8_lossy(&bytes).trim_end()
            );
        }
    }
}

fn recover(root: &Path, tx: &Transaction, reason: &str) -> Result<(), UpdateError> {
    let _lock = UpdateLock::acquire(root)?;
    let slots = read_install_slots(root)?.ok_or(crate::InstallError::NoActiveRelease)?;
    if tx.committed {
        return finalize(root, tx);
    }
    let switched = slots.current == tx.target && slots.previous.as_deref() == Some(tx.old.as_str());
    if switched {
        write_json(
            root,
            &rejected_file(&tx.target)?,
            &json!({"utc":now_epoch()}),
        )?;
        crate::install::restore_update_slots(
            root,
            &tx.target,
            &InstallSlots {
                current: tx.old.clone(),
                previous: tx.old_previous.clone(),
            },
        )?;
    } else if slots.current != tx.old {
        return Err(io::Error::other("активный слот не совпадает с журналом обновления").into());
    }
    let mut state = read_state(root)?;
    state["busy"] = json!("");
    state["current"] = json!(tx.old);
    state["previous"] = json!(read_install_slots(root)?.and_then(|slots| slots.previous));
    state["last_utc"] = json!(now_epoch());
    state["last_ok"] = json!(false);
    state["last_release"] = json!(tx.target);
    state["last_message"] = json!(short_error(reason));
    record(&mut state, &tx.target, false, reason);
    if release_rejected(root, &tx.target)? {
        state["bad_release"] = json!(tx.target);
    }
    write_state(root, &state)?;
    clear_staged(root);
    let _ = fs::remove_file(root.join("state/update-transfer.json"));
    clear(root)
}

pub(super) fn record(state: &mut Value, release: &str, healthy: bool, message: &str) {
    if !state["history"].is_array() {
        state["history"] = json!([]);
    }
    let history = state["history"].as_array_mut().expect("массив истории");
    if history.len() >= 8 {
        history.drain(..history.len() - 7);
    }
    history.push(json!({
        "release_id": release, "healthy": healthy, "utc": now_epoch(), "message": message.chars().take(160).collect::<String>(),
    }));
}

fn recover_idle(root: &Path) -> Result<(), UpdateError> {
    let _lock = UpdateLock::named(root, "update.lock", true)?;
    let mut state = read_state(root)?;
    if state["busy"].as_str().is_some_and(|busy| !busy.is_empty())
        || state["install_stage"] == 2 && state["last_ok"] == true
        || staged_file(root).try_exists()?
    {
        state["busy"] = json!("");
        state["last_utc"] = json!(now_epoch());
        state["last_ok"] = json!(false);
        state["last_message"] = json!("Операция обновления прервана");
        clear_staged(root);
        crate::install::recover_interrupted_extraction(root)?;
        let _ = fs::remove_file(root.join("state/update-transfer.json"));
        write_state(root, &state)?;
    }
    Ok(())
}

pub fn recover_router_update(root: &Path) -> Result<(), UpdateError> {
    let _guard = UpdateLock::named(root, "update-router.lock", true)?;
    match pending(root)? {
        Some(tx) => recover(
            root,
            &tx,
            "Прерванная установка отменена, рабочий выпуск восстановлен",
        ),
        None => recover_idle(root),
    }
}

pub fn compact_install_rollback(root: &Path) -> Result<(), UpdateError> {
    let _guard = UpdateLock::named(root, "update-router.lock", true)?;
    if pending(root)?.is_some() {
        return Err(crate::InstallError::Busy.into());
    }
    Ok(crate::install::cleanup_releases(root)?)
}

pub fn watch_router_update(root: &Path, adapter: &Path) -> Result<(), UpdateError> {
    let _guard = UpdateLock::named(root, "update-router.lock", false)?;
    let Some(tx) = pending(root)? else {
        return recover_idle(root);
    };
    recover_running(
        root,
        adapter,
        &tx,
        "Процесс обновления прерван, рабочий выпуск восстановлен",
    )
}

fn recover_running(
    root: &Path,
    adapter: &Path,
    tx: &Transaction,
    reason: &str,
) -> Result<(), UpdateError> {
    if !tx.committed
        && read_install_slots(root)?.is_some_and(|slots| slots.current == tx.target)
        && let Err(error) = service(root, adapter, "update-stop")
    {
        // Ошибка остановки кандидата не должна оставлять его активным.
        eprintln!("r2o-manager: остановка при восстановлении: {error}");
    }
    recover(root, tx, reason)?;
    service(root, adapter, "update-start")
}

fn watch_command(root: &Path, adapter: &Path) -> Result<std::process::Child, UpdateError> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("update-watch")
        .arg(root)
        .arg(adapter)
        .stdin(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    Ok(cmd.spawn()?)
}

/// Транзакция работает в самостоятельном процессе и переживает перезапуск панели.
pub fn run_router_update(
    root: &Path,
    adapter: &Path,
    architecture: &str,
    automatic: bool,
    release: Option<&str>,
    source: Option<&str>,
    previous: bool,
) -> Result<Value, UpdateError> {
    let _guard = UpdateLock::named(root, "update-router.lock", true)?;
    if let Some(tx) = pending(root)? {
        recover_running(root, adapter, &tx, "Прерванная установка отменена")?;
    }
    let preflight = (|| {
        let old = read_install_slots(root)?.ok_or(crate::InstallError::NoActiveRelease)?;
        check_compatible_slot(root, &old.current)?;
        if read_install_architecture(root)?.as_deref() != Some(architecture) {
            return Err(UpdateError::InvalidArchitecture);
        }
        check_catalog_schema(root)?;
        Ok((old, watch_command(root, adapter)?))
    })();
    let (old, _watch) = report_preflight(root, release, preflight)?;
    {
        let _gate = UpdateLock::named(root, "update-cancel.lock", false)?;
        reset_cancel(root)?;
    }
    let result = if previous {
        report_preflight(
            root,
            old.previous.as_deref(),
            stage_previous(root, architecture, &old),
        )?
    } else {
        stage_update_with_policy(root, architecture, automatic, release, source)?
    };
    if result["staged"] != true {
        return Ok(result);
    }
    let target = result["release_id"]
        .as_str()
        .ok_or(UpdateError::NoStagedRelease)?;
    let mut tx = Transaction {
        version: 1,
        old: old.current,
        old_previous: old.previous,
        target: target.to_owned(),
        committed: false,
    };
    {
        let _gate = UpdateLock::named(root, "update-cancel.lock", false)?;
        let _lock = UpdateLock::acquire(root)?;
        if read_cancel(root)? {
            clear_staged(root);
            let mut state = read_state(root)?;
            state["busy"] = json!("");
            state["last_utc"] = json!(now_epoch());
            state["last_ok"] = json!(false);
            state["last_message"] = json!(cancelled().to_string());
            write_state(root, &state)?;
            return Err(cancelled());
        }
        if read_install_slots(root)?.is_none_or(|slots| slots.current != tx.old) {
            return Err(io::Error::other("исходный слот изменился при подготовке выпуска").into());
        }
        save(root, &tx)?;
    }

    let mut startup_log_offsets = None;
    let outcome: Result<Value, UpdateError> = (|| {
        {
            let _lock = UpdateLock::acquire(root)?;
            let mut state = read_state(root)?;
            state["busy"] = json!("activating");
            state["phase"] = json!("activate");
            write_state(root, &state)?;
        }
        service(root, adapter, "update-stop")?;
        let activated = activate_staged_update(root)?;
        let log_dir = root.join("log");
        startup_log_offsets = Some(
            STARTUP_LOGS.map(|name| startup_log_size(&log_dir.join(name)).unwrap_or_default()),
        );
        service(root, adapter, "update-start")?;
        health(root, adapter, &tx.target)?;
        let _lock = UpdateLock::acquire(root)?;
        tx.committed = true;
        save(root, &tx)?;
        finalize(root, &tx)?;
        Ok(activated)
    })();
    match outcome {
        Ok(result) => Ok(result),
        Err(error) if pending(root)?.is_some_and(|tx| !tx.committed) => {
            if let Some(offsets) = startup_log_offsets {
                report_failed_start(root, offsets);
            }
            recover_running(root, adapter, &tx, &error.to_string())?;
            health(root, adapter, &tx.old)?;
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn report_preflight<T>(
    root: &Path,
    release: Option<&str>,
    result: Result<T, UpdateError>,
) -> Result<T, UpdateError> {
    if let Err(error) = &result {
        let persisted = (|| {
            let _lock = UpdateLock::acquire(root)?;
            let mut state = read_state(root)?;
            state["busy"] = json!("");
            state["phase"] = json!("check");
            state["install_stage"] = json!(0);
            state["last_utc"] = json!(now_epoch());
            state["last_ok"] = json!(false);
            state["last_release"] = json!(release);
            state["last_message"] = json!(short_error(&error.to_string()));
            write_state(root, &state)
        })();
        if let Err(write_error) = persisted {
            eprintln!("r2o-manager: {write_error}");
        }
    }
    result
}

fn save(root: &Path, tx: &Transaction) -> Result<(), UpdateError> {
    write_json(
        root,
        JOURNAL,
        &serde_json::to_value(tx).map_err(io::Error::other)?,
    )
}

fn finalize(root: &Path, tx: &Transaction) -> Result<(), UpdateError> {
    if read_install_slots(root)?.is_none_or(|slots| slots.current != tx.target) {
        return Err(
            io::Error::other("активный слот не совпадает с зафиксированным выпуском").into(),
        );
    }
    let mut state = read_state(root)?;
    state["busy"] = json!("");
    state["phase"] = json!("commit");
    state["install_stage"] = json!(4);
    state["previous"] = json!(&tx.old);
    state["last_utc"] = json!(now_epoch());
    state["last_ok"] = json!(true);
    state["last_message"] = json!("Выпуск установлен, обязательные службы готовы");
    if let Some(blocked) = state["bad_releases"].as_object_mut() {
        blocked.remove(&tx.target);
    }
    if state["bad_release"] == tx.target {
        state["bad_release"] = json!("");
    }
    if state["history"]
        .as_array()
        .and_then(|history| history.last())
        .is_none_or(|last| last["release_id"] != tx.target || last["healthy"] != true)
    {
        record(&mut state, &tx.target, true, "Проверка служб пройдена");
    }
    write_state(root, &state)?;
    clear_rejected(root, &tx.target)?;
    clear(root)?;
    if let Err(error) =
        crate::install::refresh_launcher(root).and_then(|()| crate::install::cleanup_releases(root))
    {
        eprintln!("r2o-manager: очистка после установки: {error}");
    }
    Ok(())
}

fn rejected_file(release: &str) -> Result<String, UpdateError> {
    crate::validate_token(release, "release_id", 128)?;
    Ok(format!("update-rejected-{release}.json"))
}

pub(super) fn release_rejected(root: &Path, release: &str) -> Result<bool, UpdateError> {
    Ok(root
        .join("state")
        .join(rejected_file(release)?)
        .try_exists()?)
}

pub(super) fn prune_rejected<'a>(
    root: &Path,
    catalog_ids: impl IntoIterator<Item = &'a str>,
) -> Result<(), UpdateError> {
    if pending(root)?.is_some() {
        return Ok(());
    }
    let published: std::collections::HashSet<_> = catalog_ids.into_iter().collect();
    let state_dir = root.join("state");
    let mut removed = false;
    for entry in fs::read_dir(&state_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(release) = name
            .to_str()
            .and_then(|name| name.strip_prefix("update-rejected-"))
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        if !published.contains(release)
            && rejected_file(release).is_ok()
            && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        crate::install::sync_directory(&state_dir)?;
    }
    Ok(())
}

fn clear_rejected(root: &Path, release: &str) -> Result<(), UpdateError> {
    let state_dir = root.join("state");
    match fs::remove_file(state_dir.join(rejected_file(release)?)) {
        Ok(()) => Ok(crate::install::sync_directory(&state_dir)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn check_catalog_schema(root: &Path) -> Result<(), UpdateError> {
    #[derive(serde::Deserialize)]
    struct Schema {
        schema: Option<u32>,
    }
    let path = root.join("state/catalog.json");
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
        return Err(io::Error::other("небезопасный обученный каталог").into());
    }
    let schema: Schema = serde_json::from_reader(BufReader::new(file.take(64 * 1024 * 1024 + 1)))
        .map_err(io::Error::other)?;
    if schema.schema.is_some_and(|version| version != 1) {
        return Err(io::Error::other("версия обученного каталога не поддерживается").into());
    }
    Ok(())
}

fn stage_previous(
    root: &Path,
    architecture: &str,
    slots: &InstallSlots,
) -> Result<Value, UpdateError> {
    let _lock = UpdateLock::acquire(root)?;
    clear_staged(root);
    let previous = slots
        .previous
        .as_deref()
        .ok_or(crate::InstallError::NoPreviousRelease)?;
    check_compatible_slot(root, previous)?;
    crate::install::prepare_previous_builds(root, previous)?;
    write_staged(
        root,
        &json!({"release_id":previous,"architecture":architecture,"kind":"previous"}),
    )?;
    Ok(json!({"staged":true,"release_id":previous}))
}
