mod catalog;
mod lifecycle;
mod mirrors;
mod scheduler;
pub use lifecycle::{recover_router_update, run_router_update, watch_router_update};
pub use scheduler::run_update_schedule;

use crate::install::activate_previous_release;
use crate::{
    InstallSlots, PreparedRelease, VerifyError, activate_prepared, decode_public_key,
    read_install_architecture, read_install_slots, verify_manifest,
};
use r2k_core::dns::{DNS_RESOLVERS, build_a_query, parse_a_reply};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PUBLIC_KEY: &[u8] = include_bytes!("../release-public.pem");
const DOWNLOAD_URL: &str = "https://github.com/t0fox/r2o/releases/download";
const SIGNATURE_MAX_BYTES: u64 = 64;
const MANIFEST_MAX_BYTES: u64 = 64 * 1024;
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);
static NEXT_DNS_ID: AtomicU16 = AtomicU16::new(1);

const GITHUB_DOWNLOAD_HOSTS: [&str; 4] = [
    "github.com",
    "api.github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];
const DOWNLOAD_DNS_TIMEOUT: Duration = Duration::from_millis(600);
const DOWNLOAD_DNS_PACKET_LIMIT: usize = 4096;

#[derive(Debug)]
pub enum UpdateError {
    Io(io::Error),
    Verify(VerifyError),
    Install(crate::InstallError),
    Download(String),
    InvalidArchitecture,
    PreviouslyFailedRelease(String),
    NoStagedRelease,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "ошибка ввода-вывода: {error}"),
            Self::Verify(error) => write!(f, "не удалось проверить выпуск: {error}"),
            Self::Install(error) => write!(f, "не удалось установить выпуск: {error}"),
            Self::Download(error) => write!(f, "не удалось скачать выпуск: {error}"),
            Self::InvalidArchitecture => write!(f, "недопустимое обозначение архитектуры"),
            Self::PreviouslyFailedRelease(release) => {
                write!(
                    f,
                    "автоматический повтор выпуска {release} пропущен после отказа runtime-проверки"
                )
            }
            Self::NoStagedRelease => {
                write!(f, "нет подготовленного выпуска для активации")
            }
        }
    }
}

impl std::error::Error for UpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Verify(error) => Some(error),
            Self::Install(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for UpdateError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<VerifyError> for UpdateError {
    fn from(value: VerifyError) -> Self {
        Self::Verify(value)
    }
}

impl From<crate::InstallError> for UpdateError {
    fn from(value: crate::InstallError) -> Self {
        Self::Install(value)
    }
}

/// Загрузить и проверить подписанные метаданные последнего выпуска проекта.
pub fn check_update(root: &Path, architecture: &str) -> Result<Value, UpdateError> {
    validate_architecture(architecture)?;
    let _router = UpdateLock::named(root, "update-router.lock", true)?;
    let _lock = UpdateLock::acquire(root)?;
    fs::create_dir_all(root)?;
    let mut state = read_state(root)?;
    state["auto"] = json!(auto_update_enabled(&state));
    state["busy"] = json!("checking");
    write_state(root, &state)?;

    let result = (|| {
        let work = create_work_dir(root)?;
        let result = check_update_in(&work, root, architecture);
        let _ = fs::remove_dir_all(work);
        result
    })();

    match result {
        Ok((manifest, slots)) => {
            let current = slots
                .as_ref()
                .map(|value| value.current.as_str())
                .unwrap_or("");
            let available = manifest.release_id != current;
            let auto_retry_blocked = bad_release_matches(&state, &manifest.release_id)
                || lifecycle::release_rejected(root, &manifest.release_id)?;
            let latest = catalog::describe(&manifest, architecture);
            state["previous"] = json!(slots.as_ref().and_then(|slots| slots.previous.as_deref()));
            let now = now_epoch();
            state["busy"] = json!("");
            state["current"] = json!(current);
            state["arch"] = json!(architecture);
            state["checked_utc"] = json!(now);
            state["check_ok"] = json!(true);
            state["check_error"] = json!("");
            state["latest"] = latest.clone();
            state["last_utc"] = state.get("last_utc").cloned().unwrap_or(json!(0));
            state["last_ok"] = state.get("last_ok").cloned().unwrap_or(json!(false));
            state["last_release"] = state.get("last_release").cloned().unwrap_or(json!(""));
            state["last_message"] = state.get("last_message").cloned().unwrap_or(json!(""));
            state["bad_release"] = state.get("bad_release").cloned().unwrap_or(json!(""));
            if let Some(object) = state.as_object_mut() {
                object.remove("never");
            }
            write_state(root, &state)?;
            Ok(
                json!({"checked":true,"update_available":available,"auto_retry_blocked":auto_retry_blocked,"current":current,"architecture":architecture,"latest":latest}),
            )
        }
        Err(error) => {
            state["busy"] = json!("");
            state["checked_utc"] = json!(now_epoch());
            state["check_ok"] = json!(false);
            state["check_error"] = json!(short_error(&error.to_string()));
            if let Some(object) = state.as_object_mut() {
                object.remove("never");
            }
            write_state(root, &state)?;
            Err(error)
        }
    }
}

fn staged_file(root: &Path) -> PathBuf {
    root.join("state/update-stage.json")
}

fn read_staged(root: &Path) -> Option<Value> {
    let bytes = fs::read(staged_file(root)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_staged(root: &Path, value: &Value) -> Result<(), UpdateError> {
    write_json(root, "update-stage.json", value)
}

/// Удалить маркер подготовки и приватный распакованный каталог, если он был.
fn clear_staged(root: &Path) {
    if let Some(staged) = read_staged(root) {
        if let Some(work) = staged_work(root, &staged) {
            let _ = fs::remove_dir_all(work);
        }
    }
    let _ = fs::remove_file(staged_file(root));
}

fn staged_work(root: &Path, staged: &Value) -> Option<PathBuf> {
    let name = staged["work"].as_str()?;
    let (pid, sequence) = name.strip_prefix(".install-")?.split_once('-')?;
    pid.parse::<u32>().ok()?;
    sequence.parse::<usize>().ok()?;
    let path = root.join(name);
    fs::symlink_metadata(&path).ok()?.is_dir().then_some(path)
}

enum StagedOutcome {
    AlreadyCurrent(crate::ReleaseManifest, InstallSlots),
    Staged(crate::ReleaseManifest),
}

fn stage_update_with_policy(
    root: &Path,
    architecture: &str,
    automatic: bool,
    release: Option<&str>,
    source: Option<&str>,
) -> Result<Value, UpdateError> {
    validate_architecture(architecture)?;
    let _lock = UpdateLock::acquire(root)?;
    fs::create_dir_all(root)?;
    clear_staged(root);
    let mut state = read_state(root)?;
    state["auto"] = json!(auto_update_enabled(&state));
    state["busy"] = json!("staging");
    state["phase"] = json!("check");
    state["last_release"] = json!("");
    state["transfer"] = Value::Null;
    state["install_stage"] = json!(0);
    write_state(root, &state)?;

    let result = (|| {
        let work = create_work_dir(root)?;
        let result = stage_update_in(
            &work,
            root,
            architecture,
            automatic,
            &mut state,
            release,
            source,
        );
        let _ = fs::remove_dir_all(work);
        result
    })();

    let _ = fs::remove_file(root.join("state/update-transfer.json"));
    match result {
        Ok(StagedOutcome::AlreadyCurrent(manifest, slots)) => {
            state["busy"] = json!("");
            state["current"] = json!(slots.current);
            state["arch"] = json!(architecture);
            state["checked_utc"] = json!(now_epoch());
            state["check_ok"] = json!(true);
            state["check_error"] = json!("");

            state["last_utc"] = json!(now_epoch());
            state["last_ok"] = json!(true);
            state["last_release"] = json!(manifest.release_id);
            state["last_message"] = json!("Выбранный выпуск уже установлен");
            if let Some(object) = state.as_object_mut() {
                object.remove("install_stage");
            }
            state["bad_release"] = json!("");
            if let Some(object) = state.as_object_mut() {
                object.remove("never");
            }
            write_state(root, &state)?;
            Ok(json!({
                "staged": false,
                "already_current": true,
                "current": slots.current,
                "previous": slots.previous,
                "architecture": architecture
            }))
        }
        Ok(StagedOutcome::Staged(manifest)) => {
            state["busy"] = json!("");
            state["arch"] = json!(architecture);
            state["checked_utc"] = json!(now_epoch());
            state["check_ok"] = json!(true);
            state["check_error"] = json!("");

            state["last_utc"] = json!(now_epoch());
            state["last_ok"] = json!(true);
            state["last_release"] = json!(manifest.release_id);
            state["last_message"] = json!("Релиз подготовлен; runtime ещё не изменён");
            state["phase"] = json!("migrate");
            state["install_stage"] = json!(2);
            if let Some(object) = state.as_object_mut() {
                object.remove("never");
            }
            write_state(root, &state)?;
            Ok(json!({
                "staged": true,
                "already_current": false,
                "release_id": manifest.release_id,
                "architecture": architecture
            }))
        }
        Err(error) => {
            state["busy"] = json!("");
            state["transfer"] = Value::Null;
            state["last_utc"] = json!(now_epoch());
            state["last_ok"] = json!(false);
            state["last_message"] = json!(short_error(&error.to_string()));
            let release = state["last_release"].as_str().unwrap_or("").to_owned();
            if !release.is_empty() && !matches!(error, UpdateError::PreviouslyFailedRelease(_)) {
                lifecycle::record(&mut state, &release, false, &error.to_string());
            }
            if let Some(object) = state.as_object_mut() {
                object.remove("never");
            }
            write_state(root, &state)?;
            Err(error)
        }
    }
}

fn stage_update_in(
    work: &Path,
    root: &Path,
    architecture: &str,
    automatic: bool,
    state: &mut Value,
    release: Option<&str>,
    source: Option<&str>,
) -> Result<StagedOutcome, UpdateError> {
    let slots = read_install_slots(root)?;
    if let Some(slots) = &slots {
        check_compatible_slot(root, &slots.current)?;
        state["current"] = json!(slots.current);
        state["previous"] = json!(slots.previous);
    }
    let catalog = catalog::fetch(work, root, architecture)?;
    state["latest"] = catalog::describe(&catalog.releases[0], architecture);
    let target = match release {
        Some(id) => catalog
            .releases
            .iter()
            .find(|manifest| manifest.release_id == id)
            .ok_or_else(|| catalog::invalid("версия отсутствует в опубликованном каталоге"))?,
        None => &catalog.releases[0],
    };
    if read_cancel(root)? {
        return Err(cancelled());
    }
    let url = format!("{DOWNLOAD_URL}/{}/latest.json", target.release_id);
    let manifest_path = work.join("latest.json");
    let signature_path = work.join("latest.json.sig");
    state["last_release"] = json!(target.release_id);
    let routes = mirrors::routes(target, source)?;
    let (manifest_bytes, signature) =
        mirrors::metadata(&routes, &url, &manifest_path, &signature_path, target)?;
    let public_key = decode_public_key(PUBLIC_KEY)?;
    let manifest = verify_manifest(&manifest_bytes, &signature, &public_key)?;
    if &manifest != target {
        return Err(catalog::invalid(
            "манифест отличается от подписанного каталога",
        ));
    }
    if slots
        .as_ref()
        .is_some_and(|installed| installed.current == manifest.release_id)
    {
        return Ok(StagedOutcome::AlreadyCurrent(
            manifest,
            slots.expect("current release was checked"),
        ));
    }
    if should_skip_failed_release(automatic, &read_state(root)?, &manifest.release_id)
        || automatic && lifecycle::release_rejected(root, &manifest.release_id)?
    {
        return Err(UpdateError::PreviouslyFailedRelease(manifest.release_id).into());
    }
    if slots.as_ref().is_some_and(|installed| {
        installed.previous.as_deref() == Some(manifest.release_id.as_str())
    }) {
        check_compatible_slot(root, &manifest.release_id)?;
        crate::install::prepare_previous_builds(root, &manifest.release_id)?;
        write_staged(
            root,
            &json!({
                "release_id": manifest.release_id,
                "architecture": architecture,
                "kind": "previous"
            }),
        )?;
        return Ok(StagedOutcome::Staged(manifest));
    }
    let url = format!(
        "{DOWNLOAD_URL}/{}/r2o-{architecture}.tar.gz",
        manifest.release_id
    );
    let archive_path = mirrors::cache_path(root, &target.assets[architecture].sha256)?;
    state["phase"] = json!("download");
    write_state(root, state)?;
    mirrors::archive(
        &routes,
        &url,
        &archive_path,
        &target.assets[architecture],
        root,
        state,
        source,
    )?;
    let _ = fs::remove_file(root.join("state/update-transfer.json"));
    state["phase"] = json!("verify");
    state["install_stage"] = json!(1);
    write_state(root, state)?;
    let prepared = crate::install::prepare_download(
        root,
        &archive_path,
        &manifest_bytes,
        &signature,
        &public_key,
        architecture,
    )?;
    let _ = fs::remove_file(&archive_path);
    state["phase"] = json!("stage");
    write_state(root, state)?;
    let layout = (|| {
        check_compatible_bundle(&prepared.bundle)?;
        let path = prepared.bundle.join("router/update-sequence");
        let sequence = read_bounded(&path, 32)?;
        if sequence.strip_suffix(b"\n") != Some(manifest.sequence().to_string().as_bytes()) {
            return Err(catalog::invalid(
                "порядковый номер пакета отличается от манифеста",
            ));
        }
        Ok::<(), UpdateError>(())
    })();
    if let Err(error) = layout {
        prepared.discard();
        return Err(error);
    }
    let relative_work = prepared
        .work
        .strip_prefix(root)
        .map_err(|_| UpdateError::Io(io::Error::other("prepared release is outside root")))?;
    if let Err(error) = write_staged(
        root,
        &json!({
            "release_id": prepared.release_id,
            "architecture": architecture,
            "kind": "download",
            "work": relative_work
        }),
    ) {
        prepared.discard();
        return Err(error);
    }
    Ok(StagedOutcome::Staged(manifest))
}

/// Активировать подготовленный выпуск после остановки runtime.
fn activate_staged_update(root: &Path) -> Result<Value, UpdateError> {
    let _lock = UpdateLock::acquire(root)?;
    let staged = read_staged(root).ok_or(UpdateError::NoStagedRelease)?;
    let release_id = staged
        .get("release_id")
        .and_then(Value::as_str)
        .ok_or(UpdateError::NoStagedRelease)?
        .to_owned();
    let architecture = staged
        .get("architecture")
        .and_then(Value::as_str)
        .ok_or(UpdateError::NoStagedRelease)?
        .to_owned();
    validate_architecture(&architecture)?;
    let kind = staged
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(UpdateError::NoStagedRelease)?;
    let result = (|| {
        if kind == "previous" {
            activate_previous_release(root, &release_id, &architecture)?
                .ok_or(UpdateError::NoStagedRelease)
        } else if kind == "archive" || kind == "download" {
            let work = staged_work(root, &staged).ok_or(UpdateError::NoStagedRelease)?;
            let prepared = PreparedRelease {
                release_id: release_id.clone(),
                architecture: architecture.clone(),
                bundle: work.join("bundle"),
                work,
            };
            let activation = if kind == "download" {
                crate::install::activate_download(root, &prepared)
            } else {
                activate_prepared(root, &prepared)
            };
            let slots = match activation {
                Ok(slots) => slots,
                Err(error) => {
                    prepared.discard();
                    return Err(error.into());
                }
            };
            prepared.discard();
            Ok(slots)
        } else {
            Err(UpdateError::NoStagedRelease)
        }
    })();
    let _ = fs::remove_file(staged_file(root));
    let slots = result?;

    let mut state = read_state(root)?;
    state["busy"] = if root.join("state/update-pending.json").exists() {
        json!("health")
    } else {
        json!("")
    };
    state["current"] = json!(slots.current);
    state["arch"] = json!(architecture);
    state["checked_utc"] = json!(now_epoch());
    state["check_ok"] = json!(true);
    state["check_error"] = json!("");
    state["last_utc"] = json!(now_epoch());
    state["last_ok"] = json!(true);
    state["last_release"] = json!(release_id);
    state["phase"] = json!("health");
    state["install_stage"] = json!(3);
    state["last_message"] =
        json!("Релиз активирован; для проверки и перезапуска вызовите адаптер роутера");
    state["bad_release"] = json!("");
    if let Some(object) = state.as_object_mut() {
        object.remove("never");
    }
    write_state(root, &state)?;
    Ok(json!({
        "activated": true,
        "already_current": false,
        "current": slots.current,
        "previous": slots.previous,
        "architecture": architecture
    }))
}

/// Записать провалившийся текущий релиз после успешного возврата на previous slot.
pub fn mark_bad_previous_release(root: &Path) -> Result<Value, UpdateError> {
    let _lock = UpdateLock::acquire(root)?;
    let slots = read_install_slots(root)?.ok_or(crate::InstallError::NoPreviousRelease)?;
    let bad_release = slots
        .previous
        .clone()
        .ok_or(crate::InstallError::NoPreviousRelease)?;
    let architecture = read_install_architecture(root)?.unwrap_or_default();
    let mut state = read_state(root)?;
    state["busy"] = json!("");
    state["current"] = json!(slots.current);
    state["arch"] = json!(architecture);
    state["bad_release"] = json!(bad_release);
    state["last_utc"] = json!(now_epoch());
    state["last_ok"] = json!(false);
    state["install_stage"] = json!(3);
    state["last_release"] = json!(bad_release);
    state["last_message"] = json!("Релиз не прошёл проверку служб; предыдущий слот снова активен");
    write_state(root, &state)?;
    Ok(json!({"current":slots.current,"bad_release":bad_release}))
}

/// Результат перезапуска записывает адаптер после runtime-проверки.
pub fn finish_router_update(root: &Path, healthy: bool) -> Result<(), UpdateError> {
    let _lock = UpdateLock::acquire(root)?;
    let mut state = read_state(root)?;
    let stage = state["install_stage"].as_u64();
    if healthy && (stage != Some(3) || state["last_ok"].as_bool() != Some(true)) {
        return Ok(());
    }
    if !healthy && !matches!(stage, Some(2 | 3)) {
        return Ok(());
    }
    state["last_utc"] = json!(now_epoch());
    state["last_ok"] = json!(healthy);
    if healthy {
        state["install_stage"] = json!(4);
    }
    state["last_message"] = json!(if healthy {
        "Обновление запущено и прошло проверку служб"
    } else {
        "Адаптер не завершил установку обновления"
    });
    write_state(root, &state)
}
/// Сохранить настройку автоустановки роутера, не сбрасывая историю обновлений.
pub fn set_auto_update(root: &Path, enabled: bool) -> Result<Value, UpdateError> {
    let _lock = UpdateLock::acquire(root)?;
    let mut state = read_state(root)?;
    state["auto"] = json!(enabled);
    if let Some(slots) = read_install_slots(root)? {
        state["current"] = json!(slots.current);
        state["previous"] = json!(slots.previous);
        state["arch"] = json!(read_install_architecture(root)?);
    }
    if state.get("checked_utc").is_none() {
        state["never"] = json!(true);
    }
    write_state(root, &state)?;
    Ok(json!({"auto":enabled}))
}

fn auto_update_enabled(state: &Value) -> bool {
    state.get("auto").and_then(Value::as_bool).unwrap_or(true)
}

fn bad_release_matches(state: &Value, release_id: &str) -> bool {
    state.get("bad_release").and_then(Value::as_str) == Some(release_id)
        || state["bad_releases"][release_id] == true
}

fn should_skip_failed_release(automatic: bool, state: &Value, release_id: &str) -> bool {
    automatic && bad_release_matches(state, release_id)
}

struct UpdateLock(File);

impl UpdateLock {
    fn acquire(root: &Path) -> Result<Self, UpdateError> {
        Self::named(root, "update.lock", false)
    }

    fn named(root: &Path, name: &str, nonblocking: bool) -> Result<Self, UpdateError> {
        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir)?;
        let path: PathBuf = state_dir.join(name);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(
                io::Error::other("файл блокировки обновления не является обычным файлом").into(),
            );
        }
        #[cfg(unix)]
        loop {
            use std::os::fd::AsRawFd;
            if unsafe {
                libc::flock(
                    file.as_raw_fd(),
                    libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 },
                )
            } == 0
            {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        if name == "update.lock" {
            cleanup_stale_update_work_dirs(root);
        }
        Ok(Self(file))
    }
}

/// Убрать рабочие каталоги `.update-*`, оставшиеся после SIGKILL/сбоя
/// питания. Вызывается только под UpdateLock.
fn cleanup_stale_update_work_dirs(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(".update-") {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_symlink() && metadata.is_dir() {
            let _ = fs::remove_dir_all(&path);
        }
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn check_update_in(
    work: &Path,
    root: &Path,
    architecture: &str,
) -> Result<(crate::ReleaseManifest, Option<InstallSlots>), UpdateError> {
    let slots = read_install_slots(root)?;
    if let Some(slots) = &slots {
        check_compatible_slot(root, &slots.current)?;
    }
    let catalog = catalog::fetch(work, root, architecture)?;
    Ok((
        catalog
            .releases
            .into_iter()
            .next()
            .expect("каталог проверен"),
        slots,
    ))
}

fn validate_architecture(architecture: &str) -> Result<(), UpdateError> {
    if architecture.is_empty()
        || architecture.len() > 32
        || !architecture.as_bytes()[0].is_ascii_alphanumeric()
        || !architecture
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(UpdateError::InvalidArchitecture);
    }
    Ok(())
}

fn download(
    url: &str,
    destination: &Path,
    max_bytes: u64,
    timeout: &str,
) -> Result<(), UpdateError> {
    validate_download_url(url)?;
    download_rust(
        url,
        destination,
        max_bytes,
        timeout,
        &[],
        RequestKind::Metadata,
    )
    .map(|_| ())
}

const HTTP_MAX_REDIRECTS: usize = 5;
const HTTP_HEADER_MAX_BYTES: usize = 64 * 1024;
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(30);

struct HttpHead {
    status: u16,
    location: Option<String>,
    chunked: bool,
    content_length: Option<u64>,
    content_range: Option<String>,
    encoding: Option<String>,
}

#[derive(Clone, Copy)]
enum RequestKind<'a> {
    Metadata,
    Redirect,
    Probe(u64),
    Archive {
        total: u64,
        root: &'a Path,
        source: &'a str,
    },
}

fn download_rust(
    url: &str,
    destination: &Path,
    max_bytes: u64,
    timeout: &str,
    overrides: &[(String, Vec<Ipv4Addr>)],
    kind: RequestKind<'_>,
) -> Result<Option<String>, UpdateError> {
    let timeout_seconds = timeout.parse::<u64>().unwrap_or(600).clamp(1, 3600);
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
    let initial_host = download_url_host(url)
        .ok_or_else(|| UpdateError::Download("недопустимый HTTPS-адрес загрузки".into()))?;
    let override_map = overrides
        .iter()
        .map(|(host, addresses)| (host.as_str(), addresses.as_slice()))
        .collect::<HashMap<_, _>>();
    let mut current = url.to_owned();

    for redirect in 0..=HTTP_MAX_REDIRECTS {
        let (host, path) = parse_https_url(&current)?;
        if redirect > 0 && host != initial_host && !GITHUB_DOWNLOAD_HOSTS.contains(&host.as_str()) {
            return Err(UpdateError::Download(format!(
                "перенаправление на недопустимый хост {host}"
            )));
        }
        let addresses = if let Some(addresses) = override_map.get(host.as_str()) {
            (*addresses).to_vec()
        } else {
            resolve_download_host(&host)?
        };
        let mut last_error = None;
        let mut next_url = None;
        for address in addresses.into_iter().take(4) {
            match fetch_https(
                &host,
                &path,
                address,
                destination,
                max_bytes,
                deadline,
                kind,
            ) {
                Ok(Some(location)) => {
                    next_url = Some(resolve_redirect(&current, &host, &location, &initial_host)?);
                    break;
                }
                Ok(None) => return Ok(None),
                Err(error) => last_error = Some(error),
            }
        }
        if let Some(next) = next_url {
            if matches!(kind, RequestKind::Redirect) {
                return Ok(Some(next));
            }
            current = next;
            continue;
        }
        return Err(last_error
            .unwrap_or_else(|| UpdateError::Download(format!("не удалось скачать {current}"))));
    }
    Err(UpdateError::Download(
        "слишком много перенаправлений при загрузке".into(),
    ))
}

fn parse_https_url(url: &str) -> Result<(String, String), UpdateError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| UpdateError::Download("разрешён только https".into()))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, "443")) => (host, 443),
        Some((_, _)) => {
            return Err(UpdateError::Download(
                "разрешён только HTTPS-порт 443".into(),
            ));
        }
        None => (authority, 443),
    };
    let host = host.to_ascii_lowercase();
    let normalized = if port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    };
    if download_url_host(&normalized).as_deref() != Some(host.as_str()) {
        return Err(UpdateError::Download(format!(
            "недопустимый HTTPS-хост {host}"
        )));
    }
    if path.is_empty() || path.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(UpdateError::Download("недопустимый путь загрузки".into()));
    }
    Ok((host, path.to_owned()))
}

fn resolve_redirect(
    base_url: &str,
    base_host: &str,
    location: &str,
    initial_host: &str,
) -> Result<String, UpdateError> {
    let location = location.trim();
    if location.is_empty() {
        return Err(UpdateError::Download("перенаправление без Location".into()));
    }
    let next = if location.starts_with("https://") {
        location.to_owned()
    } else if location.starts_with("//") {
        return Err(UpdateError::Download(
            "протокол-относительное перенаправление запрещено".into(),
        ));
    } else if location.starts_with('/') {
        format!("https://{base_host}{location}")
    } else if location.starts_with('?') {
        let (_, path) = parse_https_url(base_url)?;
        format!("https://{base_host}{path}{location}")
    } else {
        let (_, path) = parse_https_url(base_url)?;
        let directory = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
        format!("https://{base_host}{directory}/{location}")
    };
    validate_download_url(&next)?;
    let host = download_url_host(&next)
        .ok_or_else(|| UpdateError::Download("недопустимый адрес перенаправления".into()))?;
    if host != initial_host && !GITHUB_DOWNLOAD_HOSTS.contains(&host.as_str()) {
        return Err(UpdateError::Download(format!(
            "перенаправление на недопустимый хост {host}"
        )));
    }
    Ok(next)
}

fn fetch_https(
    host: &str,
    path: &str,
    address: Ipv4Addr,
    destination: &Path,
    max_bytes: u64,
    deadline: Instant,
    kind: RequestKind<'_>,
) -> Result<Option<String>, UpdateError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(UpdateError::Download("истёк тайм-аут загрузки".into()));
    }
    let tcp = TcpStream::connect_timeout(
        &SocketAddr::from((address, 443)),
        remaining.min(HTTP_CONNECT_TIMEOUT),
    )
    .map_err(|error| UpdateError::Download(format!("TCP {address}: {error}")))?;
    tcp.set_read_timeout(Some(remaining.min(HTTP_READ_TIMEOUT)))
        .map_err(|error| UpdateError::Download(format!("тайм-аут чтения: {error}")))?;
    tcp.set_write_timeout(Some(remaining.min(HTTP_READ_TIMEOUT)))
        .map_err(|error| UpdateError::Download(format!("тайм-аут записи: {error}")))?;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|error| UpdateError::Download(format!("неверное TLS-имя {host}: {error}")))?;
    let connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|error| UpdateError::Download(format!("TLS {host}: {error}")))?;
    let mut stream = BufReader::new(StreamOwned::new(connection, tcp));

    let offset = match kind {
        RequestKind::Archive { root, .. } => {
            if read_cancel(root)? {
                return Err(cancelled());
            }
            fs::metadata(destination).map_or(0, |m| m.len())
        }
        _ => 0,
    };
    let range = match kind {
        RequestKind::Archive { .. } if offset > 0 => format!("Range: bytes={offset}-\r\n"),
        RequestKind::Probe(total) => format!("Range: bytes=0-{}\r\n", total.min(16 * 1024) - 1),
        _ => String::new(),
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: r2o-manager/{}\r\nAccept: */*\r\nAccept-Encoding: identity\r\n{range}Connection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    stream
        .get_mut()
        .write_all(request.as_bytes())
        .map_err(|error| UpdateError::Download(format!("отправка запроса: {error}")))?;
    stream
        .get_mut()
        .flush()
        .map_err(|error| UpdateError::Download(format!("отправка запроса: {error}")))?;

    receive_response(
        &mut stream,
        destination,
        max_bytes,
        deadline,
        kind,
        offset,
        &format!("{host}{path}"),
    )
}

fn receive_response(
    stream: &mut impl BufRead,
    destination: &Path,
    max_bytes: u64,
    deadline: Instant,
    kind: RequestKind<'_>,
    offset: u64,
    url: &str,
) -> Result<Option<String>, UpdateError> {
    let head = read_http_head(stream)?;
    let parsed = parse_http_head(&head)?;
    if matches!(parsed.status, 301 | 302 | 303 | 307 | 308) {
        return Ok(Some(parsed.location.ok_or_else(|| {
            UpdateError::Download("перенаправление без Location".into())
        })?));
    }
    if parsed
        .encoding
        .as_deref()
        .is_some_and(|encoding| !encoding.eq_ignore_ascii_case("identity"))
    {
        return Err(io::Error::other("сервер изменил кодирование файла").into());
    }
    let limit = match kind {
        RequestKind::Metadata if parsed.status == 200 => max_bytes,
        RequestKind::Archive { total, .. } if parsed.status == 200 => total,
        RequestKind::Archive { total, .. }
            if offset > 0 && offset < total && range_matches(&parsed, offset, total - 1, total) =>
        {
            total - offset
        }
        RequestKind::Probe(total) => {
            let probe = total.min(16 * 1024);
            if range_matches(&parsed, 0, probe - 1, total)
                || parsed.status == 200 && parsed.content_length == Some(total) && !parsed.chunked
            {
                copy_exact(stream, &mut io::sink(), probe, probe, deadline)?;
                return Ok(None);
            }
            return Err(
                io::Error::other("источник вернул неверный ответ на пробный диапазон").into(),
            );
        }
        _ => {
            return Err(UpdateError::Download(format!(
                "HTTP {} при загрузке {url}",
                parsed.status
            )));
        }
    };
    if parsed.content_length.is_some_and(|length| length > limit) {
        return Err(io::Error::other("HTTP-ответ больше ожидаемого размера").into());
    }
    let mut options = OpenOptions::new();
    let append = matches!(kind, RequestKind::Archive { .. }) && parsed.status == 206;
    if matches!(kind, RequestKind::Archive { .. }) {
        options
            .write(true)
            .create(true)
            .append(append)
            .truncate(!append);
    } else {
        options.write(true).create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let output = options.open(destination).map_err(|error| {
        UpdateError::Download(format!(
            "не удалось создать {}: {error}",
            destination.display()
        ))
    })?;
    let mut output = mirrors::Progress::new(output, kind, if append { offset } else { 0 });
    let copied = if parsed.chunked {
        copy_chunked(stream, &mut output, limit, deadline)
    } else if let Some(length) = parsed.content_length {
        copy_exact(stream, &mut output, length, limit, deadline)
    } else {
        copy_until_eof(stream, &mut output, limit, deadline)
    };
    if !matches!(kind, RequestKind::Archive { .. }) && !matches!(&copied, Ok(bytes) if *bytes > 0) {
        drop(output);
        let _ = fs::remove_file(destination);
        return Err(copied
            .err()
            .unwrap_or_else(|| io::Error::other("загрузка пуста").into()));
    }
    let bytes = copied?;
    if matches!(kind, RequestKind::Archive { .. }) && bytes != limit {
        return Err(io::Error::other("загружена только часть архива").into());
    }
    output.file.sync_all()?;
    Ok(None)
}

fn range_matches(head: &HttpHead, start: u64, end: u64, total: u64) -> bool {
    head.status == 206
        && !head.chunked
        && head.content_length == Some(end - start + 1)
        && head.content_range.as_deref() == Some(format!("bytes {start}-{end}/{total}").as_str())
}

fn read_http_head(reader: &mut impl BufRead) -> Result<Vec<u8>, UpdateError> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let read = (&mut *reader)
            .take((HTTP_HEADER_MAX_BYTES + 1 - head.len()) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|error| UpdateError::Download(format!("чтение заголовков: {error}")))?;
        if read == 0 {
            return Err(UpdateError::Download(
                "соединение закрылось до HTTP-заголовков".into(),
            ));
        }
        head.extend_from_slice(&line);
        if head.len() > HTTP_HEADER_MAX_BYTES {
            return Err(UpdateError::Download(
                "HTTP-заголовки больше предела".into(),
            ));
        }
        if line == b"\r\n" || line == b"\n" {
            return Ok(head);
        }
    }
}

fn parse_http_head(head: &[u8]) -> Result<HttpHead, UpdateError> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| UpdateError::Download("пустой HTTP-ответ".into()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| UpdateError::Download("некорректный HTTP-статус".into()))?;
    let mut location = None;
    let mut chunked = false;
    let mut content_length = None;
    let mut content_range = None;
    let mut encoding = None;
    for line in lines {
        let line = line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("location") {
            location = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"));
        } else if name.eq_ignore_ascii_case("content-range")
            && content_range.replace(value.to_owned()).is_some()
            || name.eq_ignore_ascii_case("content-encoding")
                && encoding.replace(value.to_owned()).is_some()
        {
            return Err(io::Error::other("повтор заголовка HTTP").into());
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(io::Error::other("повтор Content-Length").into());
            }
            content_length = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| UpdateError::Download("некорректный Content-Length".into()))?,
            );
        }
    }
    Ok(HttpHead {
        status,
        location,
        chunked,
        content_length,
        content_range,
        encoding,
    })
}

fn check_deadline(deadline: Instant) -> Result<(), UpdateError> {
    if Instant::now() > deadline {
        return Err(UpdateError::Download("истёк тайм-аут загрузки".into()));
    }
    Ok(())
}

fn write_body_chunk(
    output: &mut impl Write,
    chunk: &[u8],
    total: &mut u64,
    max_bytes: u64,
) -> Result<(), UpdateError> {
    *total = total.saturating_add(chunk.len() as u64);
    if *total > max_bytes {
        return Err(UpdateError::Download(format!(
            "размер загрузки превышает {max_bytes} байт"
        )));
    }
    output
        .write_all(chunk)
        .map_err(|error| UpdateError::Download(format!("запись загрузки: {error}")))
}

fn copy_exact(
    reader: &mut impl Read,
    output: &mut impl Write,
    length: u64,
    max_bytes: u64,
    deadline: Instant,
) -> Result<u64, UpdateError> {
    let mut left = length;
    let mut total = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    while left > 0 {
        check_deadline(deadline)?;
        let want = left.min(buffer.len() as u64) as usize;
        let read = reader
            .read(&mut buffer[..want])
            .map_err(|error| UpdateError::Download(format!("чтение загрузки: {error}")))?;
        if read == 0 {
            return Err(UpdateError::Download(
                "соединение закрылось до конца тела ответа".into(),
            ));
        }
        write_body_chunk(output, &buffer[..read], &mut total, max_bytes)?;
        left -= read as u64;
    }
    Ok(total)
}

fn copy_until_eof(
    reader: &mut impl Read,
    output: &mut impl Write,
    max_bytes: u64,
    deadline: Instant,
) -> Result<u64, UpdateError> {
    let mut total = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        check_deadline(deadline)?;
        let read = reader
            .read(&mut buffer)
            .map_err(|error| UpdateError::Download(format!("чтение загрузки: {error}")))?;
        if read == 0 {
            return Ok(total);
        }
        write_body_chunk(output, &buffer[..read], &mut total, max_bytes)?;
    }
}

fn copy_chunked(
    reader: &mut impl BufRead,
    output: &mut impl Write,
    max_bytes: u64,
    deadline: Instant,
) -> Result<u64, UpdateError> {
    let mut total = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        check_deadline(deadline)?;
        let line = bounded_chunk_line(reader, deadline)?;
        let size = line
            .trim()
            .split(';')
            .next()
            .and_then(|value| usize::from_str_radix(value.trim(), 16).ok())
            .ok_or_else(|| UpdateError::Download("некорректный chunk size".into()))?;
        if size == 0 {
            let mut trailer_bytes = 0;
            loop {
                let trailer = bounded_chunk_line(reader, deadline)?;
                trailer_bytes += trailer.len();
                if trailer_bytes > HTTP_HEADER_MAX_BYTES {
                    return Err(io::Error::other("слишком длинный trailer HTTP").into());
                }
                if trailer == "\r\n" || trailer == "\n" {
                    return Ok(total);
                }
            }
        }
        let mut left = size;
        while left > 0 {
            check_deadline(deadline)?;
            let want = left.min(buffer.len());
            let read = reader
                .read(&mut buffer[..want])
                .map_err(|error| UpdateError::Download(format!("чтение chunk: {error}")))?;
            if read == 0 {
                return Err(UpdateError::Download(
                    "соединение закрылось внутри chunk".into(),
                ));
            }
            write_body_chunk(output, &buffer[..read], &mut total, max_bytes)?;
            left -= read;
        }
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|error| UpdateError::Download(format!("чтение CRLF: {error}")))?;
        if &crlf != b"\r\n" {
            return Err(UpdateError::Download("некорректный chunk CRLF".into()));
        }
    }
}

fn bounded_chunk_line(reader: &mut impl BufRead, deadline: Instant) -> Result<String, UpdateError> {
    check_deadline(deadline)?;
    let mut line = String::new();
    if reader.take(4096).read_line(&mut line)? == 0 || !line.ends_with('\n') {
        return Err(io::Error::other("неполная строка chunked HTTP").into());
    }
    Ok(line)
}

#[cfg(test)]
fn download_with(
    curl: &str,
    url: &str,
    destination: &Path,
    max_bytes: u64,
    timeout: &str,
) -> Result<(), UpdateError> {
    validate_download_url(url)?;
    let overrides = resolve_download_overrides(url)?;
    download_with_overrides(curl, url, destination, max_bytes, timeout, &overrides)
}

#[cfg(test)]
fn download_with_overrides(
    curl: &str,
    url: &str,
    destination: &Path,
    max_bytes: u64,
    timeout: &str,
    overrides: &[(String, Vec<Ipv4Addr>)],
) -> Result<(), UpdateError> {
    validate_download_url(url)?;
    let mut command = Command::new(curl);
    let arguments = download_curl_args(url, timeout, overrides);
    command.args(&arguments[..arguments.len() - 1]);
    let mut child = command
        .arg(url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| UpdateError::Download(format!("не удалось запустить curl: {error}")))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| UpdateError::Download("curl не открыл поток загрузки".into()))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = match options.open(destination) {
        Ok(file) => file,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
    };
    let transfer = (|| {
        let mut bytes = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = stdout.read(&mut buffer)?;
            if count == 0 {
                return Ok((bytes, false));
            }
            bytes = bytes.saturating_add(count as u64);
            if bytes > max_bytes {
                return Ok((bytes, true));
            }
            output.write_all(&buffer[..count])?;
        }
    })();
    let (bytes, too_large) = match transfer {
        Ok(result) => result,
        Err(error) => {
            let _ = child.kill();
            drop(stdout);
            let _ = child.wait();
            let _ = fs::remove_file(destination);
            return Err(UpdateError::Io(error));
        }
    };
    if too_large {
        let _ = child.kill();
    }
    if let Err(error) = output.sync_all() {
        drop(output);
        let _ = child.kill();
        drop(stdout);
        let _ = child.wait();
        let _ = fs::remove_file(destination);
        return Err(UpdateError::Io(error));
    }
    drop(output);
    drop(stdout);
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            let _ = fs::remove_file(destination);
            return Err(UpdateError::Io(error));
        }
    };
    let mut stderr = Vec::new();
    if let Some(stream) = child.stderr.take() {
        let _ = stream.take(4096).read_to_end(&mut stderr);
    }
    if too_large {
        let _ = fs::remove_file(destination);
        return Err(UpdateError::Download(format!(
            "размер загрузки превышает {max_bytes} байт"
        )));
    }
    if !status.success() {
        let _ = fs::remove_file(destination);
        return Err(UpdateError::Download(
            String::from_utf8_lossy(&stderr).trim().to_owned(),
        ));
    }
    if bytes == 0 {
        let _ = fs::remove_file(destination);
        return Err(UpdateError::Download("загрузки не содержат данных".into()));
    }
    Ok(())
}

fn validate_download_url(url: &str) -> Result<(), UpdateError> {
    if download_url_host(url).is_none() {
        return Err(UpdateError::Download(
            "разрешены только корректные HTTPS-адреса на порту 443".into(),
        ));
    }
    Ok(())
}

fn download_url_host(url: &str) -> Option<String> {
    let authority = url
        .strip_prefix("https://")?
        .split(['/', '?', '#'])
        .next()?;
    if authority.is_empty() || authority.contains('@') || authority.contains(['\n', '\r', '\0']) {
        return None;
    }
    let host = match authority.rsplit_once(':') {
        Some((host, "443")) => host,
        Some(_) => return None,
        None => authority,
    };
    if host.len() > 253 || host.is_empty() || !host.is_ascii() {
        return None;
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

#[cfg(test)]
fn release_download_hosts(url: &str) -> &'static [&'static str] {
    if download_url_host(url).as_deref() == Some("github.com") {
        &GITHUB_DOWNLOAD_HOSTS
    } else {
        &[]
    }
}

#[cfg(test)]
fn download_curl_args(
    url: &str,
    timeout: &str,
    overrides: &[(String, Vec<Ipv4Addr>)],
) -> Vec<String> {
    let mut arguments = [
        "--noproxy",
        "*",
        "--fail",
        "--location",
        "--max-redirs",
        "5",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
        "8",
        "--max-time",
        timeout,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    for (host, addresses) in overrides {
        if addresses.is_empty() {
            continue;
        }
        arguments.push("--resolve".to_owned());
        arguments.push(format!(
            "{host}:443:{}",
            addresses
                .iter()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    arguments.push(url.to_owned());
    arguments
}

#[cfg(test)]
fn resolve_download_overrides(url: &str) -> Result<Vec<(String, Vec<Ipv4Addr>)>, UpdateError> {
    let requested_host = download_url_host(url)
        .ok_or_else(|| UpdateError::Download("недопустимый HTTPS-адрес загрузки".into()))?;
    let hosts = release_download_hosts(url);
    let hosts = if hosts.is_empty() {
        vec![requested_host.as_str()]
    } else {
        hosts.to_vec()
    };
    hosts
        .into_iter()
        .map(|host| resolve_download_host(host).map(|addresses| (host.to_owned(), addresses)))
        .collect()
}

fn resolve_download_host(host: &str) -> Result<Vec<Ipv4Addr>, UpdateError> {
    let mut addresses = Vec::new();
    for resolver in DNS_RESOLVERS {
        let id = NEXT_DNS_ID.fetch_add(1, Ordering::Relaxed);
        let Ok(query) = build_a_query(id, host) else {
            continue;
        };
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            continue;
        };
        if socket.set_read_timeout(Some(DOWNLOAD_DNS_TIMEOUT)).is_err()
            || socket
                .set_write_timeout(Some(DOWNLOAD_DNS_TIMEOUT))
                .is_err()
            || socket
                .connect(SocketAddr::from((resolver.address, 53)))
                .is_err()
            || socket.send(&query).is_err()
        {
            continue;
        }
        let mut response = [0_u8; DOWNLOAD_DNS_PACKET_LIMIT];
        let Ok(length) = socket.recv(&mut response) else {
            continue;
        };
        if let Ok(answer) = parse_a_reply(&response[..length], &query, host) {
            for address in answer {
                if !addresses.contains(&address) && addresses.len() < 8 {
                    addresses.push(address);
                }
            }
        }
    }
    if addresses.is_empty() {
        return Err(UpdateError::Download(format!(
            "выбранные DNS не вернули IPv4-адрес для {host}"
        )));
    }
    Ok(addresses)
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, UpdateError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        return Err(UpdateError::Download(format!(
            "{} не является обычным файлом или превышает ограничение размера",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(UpdateError::Download(format!(
            "{} превышает ограничение размера",
            path.display()
        )));
    }
    Ok(bytes)
}

fn create_work_dir(root: &Path) -> Result<PathBuf, UpdateError> {
    for _ in 0..16 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!(".update-{}-{sequence}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                }
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "не удалось создать временный каталог обновления",
    )
    .into())
}

fn read_state(root: &Path) -> Result<Value, UpdateError> {
    let bytes = match read_bounded(&root.join("state/update.json"), 16 * 1024) {
        Ok(bytes) => bytes,
        Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(json!({"format":1}));
        }
        Err(error) => return Err(error),
    };
    let mut state: Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let map = state
        .as_object_mut()
        .ok_or_else(|| io::Error::other("состояние обновления должно быть объектом"))?;
    match map.get("format").and_then(Value::as_u64) {
        Some(1) => (),
        None if !map.contains_key("format") => {
            // Выпуски с общей схемой данных могут хранить начальную телеметрию без номера формата.
            if let Some(release) = map
                .get("bad_release")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                crate::validate_token(release, "release_id", 128)?;
                map.insert("bad_releases".to_owned(), json!({ (release): true }));
            }
            map.insert("format".to_owned(), json!(1));
        }
        _ => return Err(io::Error::other("неподдерживаемый формат состояния обновления").into()),
    }
    Ok(state)
}

fn write_state(root: &Path, state: &Value) -> Result<(), UpdateError> {
    let mut state = state.clone();
    state["format"] = json!(1);
    write_json(root, "update.json", &state)
}

fn write_json(root: &Path, name: &str, state: &Value) -> Result<(), UpdateError> {
    let path = root.join("state").join(name);
    let parent = path.parent().expect("update state has parent");
    fs::create_dir_all(parent)?;
    let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".update-{}-{sequence}.json", std::process::id()));
    let bytes = serde_json::to_vec(state).map_err(|error| io::Error::other(error.to_string()))?;
    if name == "update.json" && bytes.len() >= 16 * 1024 - 1 {
        return Err(io::Error::other("состояние обновления превышает 16 КиБ").into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        crate::install::sync_directory(parent)?;
        Ok::<(), io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result?;
    Ok(())
}

fn read_cancel(root: &Path) -> Result<bool, UpdateError> {
    Ok(root.join("state/update-cancel").try_exists()?)
}

fn cancelled() -> UpdateError {
    io::Error::new(io::ErrorKind::Interrupted, "Обновление отменено").into()
}

pub fn cancel_router_update(root: &Path) -> Result<(), UpdateError> {
    let _gate = UpdateLock::named(root, "update-cancel.lock", false)?;
    match UpdateLock::named(root, "update-router.lock", true) {
        Ok(_) => return Err(io::Error::other("Установка не запущена").into()),
        Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error),
    }
    if root.join("state/update-pending.json").try_exists()? {
        return Err(io::Error::other("Отмена возможна только до активации").into());
    }
    let path = root.join("state/update-cancel");
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    Ok(())
}

fn reset_cancel(root: &Path) -> Result<(), UpdateError> {
    match fs::remove_file(root.join("state/update-cancel")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn check_compatible_slot(root: &Path, release_id: &str) -> Result<(), UpdateError> {
    crate::validate_token(release_id, "release_id", 128)?;
    check_compatible_bundle(&root.join("releases").join(release_id))
}

fn check_compatible_bundle(bundle: &Path) -> Result<(), UpdateError> {
    if read_bounded(&bundle.join("router/update-schema"), 32)? != b"R2O-STATE-1\n" {
        return Err(io::Error::other("несовместимые форматы конфигурации и состояния").into());
    }
    Ok(())
}

fn short_error(message: &str) -> String {
    message[..message.floor_char_boundary(320)].to_owned()
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_TEMP: AtomicUsize = AtomicUsize::new(0);

    pub(super) struct TestDir(pub(super) PathBuf);

    impl TestDir {
        pub(super) fn new() -> Self {
            let id = TEST_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("r2o-update-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn fake_curl(path: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = path.join("curl");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nhave_proto=0\nhave_redir=0\nwhile [ \"$#\" -gt 0 ]; do\ncase \"$1\" in\n--proto) [ \"$2\" = \"=https\" ] && have_proto=1; shift 2 ;;\n--proto-redir) [ \"$2\" = \"=https\" ] && have_redir=1; shift 2 ;;\n*) shift ;;\nesac\ndone\n[ \"$have_proto\" = 1 ] && [ \"$have_redir\" = 1 ] || exit 9\nprintf '%s' '{}'\n",
                body
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        script
    }

    #[cfg(unix)]
    #[test]
    fn resume_validates_range_and_restarts_if_source_ignores_it() {
        let temp = TestDir::new();
        let path = temp.0.join("archive");
        let deadline = Instant::now() + Duration::from_secs(2);
        let kind = RequestKind::Archive {
            total: 6,
            root: &temp.0,
            source: "test",
        };
        let mut interrupted = &b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc"[..];
        assert!(receive_response(&mut interrupted, &path, 6, deadline, kind, 0, "test").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"abc");

        let mut wrong =
            &b"HTTP/1.1 206 Partial\r\nContent-Range: bytes 2-4/6\r\nContent-Length: 3\r\n\r\ncde"
                [..];
        assert!(receive_response(&mut wrong, &path, 6, deadline, kind, 3, "test").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"abc");

        let mut valid =
            &b"HTTP/1.1 206 Partial\r\nContent-Range: bytes 3-5/6\r\nContent-Length: 3\r\n\r\ndef"
                [..];
        receive_response(&mut valid, &path, 6, deadline, kind, 3, "test").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"abcdef");

        let mut restart = &b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef"[..];
        fs::write(&path, b"bad").unwrap();
        receive_response(&mut restart, &path, 6, deadline, kind, 3, "test").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"abcdef");
    }

    #[test]
    fn stale_update_work_dirs_are_removed_under_lock() {
        let temp = TestDir::new();
        let root = temp.0.join("root");
        fs::create_dir_all(root.join(".update-999-0")).unwrap();
        fs::create_dir_all(root.join(".update-999-1")).unwrap();
        fs::write(root.join(".update-file"), "not a directory").unwrap();

        let lock = UpdateLock::acquire(&root).unwrap();
        assert!(!root.join(".update-999-0").exists());
        assert!(!root.join(".update-999-1").exists());
        assert!(root.join(".update-file").exists());
        drop(lock);
    }

    #[cfg(unix)]
    #[test]
    fn downloader_requires_https_and_enforces_a_streaming_size_limit() {
        let temp = TestDir::new();
        let script = fake_curl(&temp.0, "123456");
        let output = temp.0.join("payload");
        assert!(matches!(
            download_with(script.to_str().unwrap(), "http://example.test/file", &output, 20, "1"),
            Err(UpdateError::Download(message)) if message.contains("HTTPS")
        ));
        assert!(matches!(
            download_with_overrides(
                script.to_str().unwrap(),
                "https://example.test/file",
                &output,
                5,
                "1",
                &[],
            ),
            Err(UpdateError::Download(message)) if message.contains("превышает 5")
        ));
        assert!(!output.exists());

        let script = fake_curl(&temp.0, "ok");
        download_with_overrides(
            script.to_str().unwrap(),
            "https://example.test/file",
            &output,
            5,
            "1",
            &[],
        )
        .unwrap();
        assert_eq!(fs::read_to_string(output).unwrap(), "ok");
    }

    #[test]
    fn release_download_uses_direct_dns_pins_for_github_redirect_hosts() {
        let overrides = vec![
            (
                "github.com".to_string(),
                vec![
                    "140.82.114.4".parse().unwrap(),
                    "140.82.112.4".parse().unwrap(),
                ],
            ),
            (
                "release-assets.githubusercontent.com".to_string(),
                vec!["185.199.108.133".parse().unwrap()],
            ),
        ];
        let args = download_curl_args(
            "https://github.com/t0fox/r2o/releases/download/r2o-1/update.tar.gz",
            "60",
            &overrides,
        );

        assert!(args.windows(2).any(|pair| pair == ["--noproxy", "*"]));
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--resolve", "github.com:443:140.82.114.4,140.82.112.4"] })
        );
        assert!(args.windows(2).any(|pair| {
            pair == [
                "--resolve",
                "release-assets.githubusercontent.com:443:185.199.108.133",
            ]
        }));
    }

    #[test]
    fn release_download_host_list_covers_manifest_and_asset_redirects() {
        assert_eq!(
            release_download_hosts(
                "https://github.com/t0fox/r2o/releases/latest/download/latest.json"
            ),
            [
                "github.com",
                "api.github.com",
                "release-assets.githubusercontent.com",
                "objects.githubusercontent.com",
            ]
        );
    }

    #[test]
    fn update_state_is_atomically_readable_json() {
        let temp = TestDir::new();
        let state = json!({"busy":"","check_ok":true,"latest":{"release_id":"r2o-1"}});
        write_state(&temp.0, &state).unwrap();
        assert_eq!(read_state(&temp.0).unwrap()["auto"], state["auto"]);
    }

    #[test]
    fn automatic_retry_is_blocked_only_for_the_recorded_bad_release() {
        let state = json!({"bad_release":"r2o-bad"});
        assert!(should_skip_failed_release(true, &state, "r2o-bad"));
        assert!(!should_skip_failed_release(false, &state, "r2o-bad"));
        assert!(!should_skip_failed_release(true, &state, "r2o-new"));
        assert!(!should_skip_failed_release(
            true,
            &json!({"bad_release":""}),
            "r2o-bad"
        ));
    }

    #[test]
    fn recording_bad_previous_release_updates_runtime_failure_state() {
        let temp = TestDir::new();
        let root = &temp.0;
        for release in ["r2o-good", "r2o-bad"] {
            let dir = root.join("releases").join(release);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("release-architecture"), "mipsel").unwrap();
        }
        fs::write(
            root.join("release-slots"),
            "R2O-RELEASE-SLOTS-1\nr2o-good\nr2o-bad\n",
        )
        .unwrap();

        let result = mark_bad_previous_release(root).unwrap();
        assert_eq!(result["current"], "r2o-good");
        assert_eq!(result["bad_release"], "r2o-bad");
        let state = read_state(root).unwrap();
        assert_eq!(state["current"], "r2o-good");
        assert_eq!(state["bad_release"], "r2o-bad");
        assert_eq!(state["last_ok"], false);
        assert_eq!(state["last_release"], "r2o-bad");
    }

    #[test]
    fn embedded_release_key_is_a_valid_ed25519_public_key() {
        assert_eq!(decode_public_key(PUBLIC_KEY).unwrap().len(), 32);
    }

    #[cfg(unix)]
    #[test]
    fn staged_archive_activates_only_on_explicit_request() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TestDir::new();
        let root = &temp.0;
        let work_relative = ".install-1-1";
        let work = root.join(work_relative);
        let builds = work.join("bundle/builds");
        fs::create_dir_all(&builds).unwrap();
        for component in [
            "r2o-datapath",
            "r2o-controller",
            "r2o-panel",
            "r2o-telegram",
            "r2o-manager",
            "r2o-fetch",
        ] {
            let path = builds.join(format!("{component}-linux-mipsel"));
            fs::write(&path, "release payload").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        write_staged(
            root,
            &json!({
                "release_id": "r2o-stage-1",
                "architecture": "mipsel",
                "kind": "archive",
                "work": work_relative
            }),
        )
        .unwrap();

        assert_eq!(read_install_slots(root).unwrap(), None);
        assert!(staged_file(root).exists());

        let result = activate_staged_update(root).unwrap();
        assert_eq!(result["activated"], true);
        assert_eq!(result["current"], "r2o-stage-1");
        assert_eq!(
            read_install_slots(root).unwrap().unwrap().current,
            "r2o-stage-1"
        );
        assert!(!staged_file(root).exists());
        assert!(!work.exists());
        assert_eq!(read_state(root).unwrap()["current"], "r2o-stage-1");
        assert_eq!(read_state(root).unwrap()["install_stage"], 3);
        finish_router_update(root, true).unwrap();
        assert_eq!(read_state(root).unwrap()["install_stage"], 4);
        assert_eq!(read_state(root).unwrap()["last_ok"], true);
    }

    #[test]
    fn activation_without_a_staged_release_fails() {
        let temp = TestDir::new();
        assert!(matches!(
            activate_staged_update(&temp.0),
            Err(UpdateError::NoStagedRelease)
        ));
    }

    #[test]
    fn https_url_parser_requires_port_443_and_clean_path() {
        assert_eq!(
            parse_https_url("https://github.com/t0fox/r2o/releases/download/x.tar.gz").unwrap(),
            (
                "github.com".to_string(),
                "/t0fox/r2o/releases/download/x.tar.gz".to_string()
            )
        );
        assert!(parse_https_url("http://github.com/x").is_err());
        assert!(parse_https_url("https://github.com:444/x").is_err());
        assert!(parse_https_url("https://github.com/x\r\nInjected: 1").is_err());
    }

    #[test]
    fn redirect_resolution_allows_only_release_hosts() {
        assert_eq!(
            resolve_redirect(
                "https://github.com/t0fox/r2o/releases/download/x.tar.gz",
                "github.com",
                "/t0fox/r2o/releases/download/y.tar.gz",
                "github.com",
            )
            .unwrap(),
            "https://github.com/t0fox/r2o/releases/download/y.tar.gz"
        );
        assert_eq!(
            resolve_redirect(
                "https://github.com/t0fox/r2o/releases/download/x.tar.gz",
                "github.com",
                "https://objects.githubusercontent.com/blob",
                "github.com",
            )
            .unwrap(),
            "https://objects.githubusercontent.com/blob"
        );
        assert!(
            resolve_redirect(
                "https://github.com/t0fox/r2o/releases/download/x.tar.gz",
                "github.com",
                "https://evil.example/blob",
                "github.com",
            )
            .is_err()
        );
    }

    #[test]
    fn http_head_parser_reads_status_location_and_length() {
        let head = b"HTTP/1.1 302 Found\r\nLocation: https://objects.githubusercontent.com/x\r\nContent-Length: 0\r\n\r\n";
        let parsed = parse_http_head(head).unwrap();
        assert_eq!(parsed.status, 302);
        assert_eq!(
            parsed.location.as_deref(),
            Some("https://objects.githubusercontent.com/x")
        );
        assert!(!parsed.chunked);
        assert_eq!(parsed.content_length, Some(0));

        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let parsed = parse_http_head(head).unwrap();
        assert_eq!(parsed.status, 200);
        assert!(parsed.chunked);
    }

    #[test]
    fn chunked_body_is_decoded_and_size_limited() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let input = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let mut reader = std::io::Cursor::new(input);
        let mut output = Vec::new();
        let total = copy_chunked(&mut reader, &mut output, 100, deadline).unwrap();
        assert_eq!(total, 9);
        assert_eq!(output, b"Wikipedia");

        let mut reader = std::io::Cursor::new(input);
        let mut output = Vec::new();
        assert!(matches!(
            copy_chunked(&mut reader, &mut output, 5, deadline),
            Err(UpdateError::Download(message)) if message.contains("превышает")
        ));
    }
}
