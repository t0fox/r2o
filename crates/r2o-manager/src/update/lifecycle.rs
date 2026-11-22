use super::*;
use std::process::{Command, Stdio};

const JOURNAL: &str = "update-pending.json";

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
fn service(adapter: &Path, action: &str) -> Result<(), UpdateError> {
    let mut command = Command::new(adapter);
    command.arg(action).stdin(Stdio::null());
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
        if service(adapter, "update-health").is_ok() {
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
    {
        state["busy"] = json!("");
        state["last_utc"] = json!(now_epoch());
        state["last_ok"] = json!(false);
        state["last_message"] = json!("Операция обновления прервана");
        clear_staged(root);
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

pub fn watch_router_update(root: &Path, adapter: &Path) -> Result<(), UpdateError> {
    let _guard = UpdateLock::named(root, "update-router.lock", false)?;
    let Some(tx) = pending(root)? else {
        return recover_idle(root);
    };
    if !tx.committed && read_install_slots(root)?.is_some_and(|slots| slots.current == tx.target) {
        service(adapter, "update-stop")?;
    }
    recover(
        root,
        &tx,
        "Процесс обновления прерван, рабочий выпуск восстановлен",
    )?;
    service(adapter, "update-start")
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
        service(adapter, "update-stop")?;
        recover(root, &tx, "Прерванная установка отменена")?;
        service(adapter, "update-start")?;
    }
    let old = read_install_slots(root)?.ok_or(crate::InstallError::NoActiveRelease)?;
    check_compatible_slot(root, &old.current)?;
    if read_install_architecture(root)?.as_deref() != Some(architecture) {
        return Err(UpdateError::InvalidArchitecture);
    }
    check_catalog_schema(root)?;
    let _watch = watch_command(root, adapter)?;
    {
        let _gate = UpdateLock::named(root, "update-cancel.lock", false)?;
        reset_cancel(root)?;
    }
    let result = if previous {
        stage_previous(root, architecture, &old)?
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

    let outcome: Result<Value, UpdateError> = (|| {
        {
            let _lock = UpdateLock::acquire(root)?;
            let mut state = read_state(root)?;
            state["busy"] = json!("activating");
            state["phase"] = json!("activate");
            write_state(root, &state)?;
        }
        service(adapter, "update-stop")?;
        let activated = activate_staged_update(root)?;
        service(adapter, "update-start")?;
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
            if read_install_slots(root)?.is_some_and(|slots| slots.current == tx.target) {
                service(adapter, "update-stop")?;
            }
            recover(root, &tx, &error.to_string())?;
            service(adapter, "update-start")?;
            health(root, adapter, &tx.old)?;
            Err(error)
        }
        Err(error) => Err(error),
    }
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
    write_staged(
        root,
        &json!({"release_id":previous,"architecture":architecture,"kind":"previous"}),
    )?;
    Ok(json!({"staged":true,"release_id":previous}))
}
