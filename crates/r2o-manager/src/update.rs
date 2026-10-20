use crate::{
    InstallSlots, VerifyError, decode_public_key, install_archive, read_install_slots,
    verify_manifest,
};
use r2k_core::dns::{DNS_RESOLVERS, build_a_query, parse_a_reply};
use serde_json::{Value, json};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PUBLIC_KEY: &[u8] = include_bytes!("../release-public.pem");
const LATEST_URL: &str = "https://github.com/t0fox/r2o/releases/latest/download/latest.json";
const DOWNLOAD_URL: &str = "https://github.com/t0fox/r2o/releases/download";
const SIGNATURE_MAX_BYTES: u64 = 64;
const ARCHIVE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const MANIFEST_MAX_BYTES: u64 = 64 * 1024;
const DOWNLOAD_TIMEOUT_SECONDS: &str = "600";
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
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "ошибка ввода-вывода: {error}"),
            Self::Verify(error) => write!(f, "не удалось проверить выпуск: {error}"),
            Self::Install(error) => write!(f, "не удалось установить выпуск: {error}"),
            Self::Download(error) => write!(f, "не удалось скачать выпуск: {error}"),
            Self::InvalidArchitecture => write!(f, "недопустимое обозначение архитектуры"),
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
    let _lock = UpdateLock::acquire(root)?;
    fs::create_dir_all(root)?;
    let mut state = read_state(root);
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
            let latest = json!({
                "release_id": manifest.release_id,
                "version": manifest.version,
                "notes": manifest.notes,
            });
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
                json!({"checked":true,"update_available":available,"current":current,"architecture":architecture,"latest":latest}),
            )
        }
        Err(error) => {
            state["busy"] = json!("");
            state["checked_utc"] = json!(now_epoch());
            state["check_ok"] = json!(false);
            state["check_error"] = json!(error.to_string());
            if let Some(object) = state.as_object_mut() {
                object.remove("never");
            }
            write_state(root, &state)?;
            Err(error)
        }
    }
}

/// Скачать проверенный выпуск и активировать его транзакционно.
pub fn install_update(root: &Path, architecture: &str) -> Result<Value, UpdateError> {
    validate_architecture(architecture)?;
    let _lock = UpdateLock::acquire(root)?;
    fs::create_dir_all(root)?;
    let mut state = read_state(root);
    state["auto"] = json!(auto_update_enabled(&state));
    state["busy"] = json!("installing");
    write_state(root, &state)?;

    let result = (|| {
        let work = create_work_dir(root)?;
        let result = install_update_in(&work, root, architecture);
        let _ = fs::remove_dir_all(work);
        result
    })();

    match result {
        Ok((manifest, slots, changed)) => {
            let now = now_epoch();
            state["busy"] = json!("");
            state["current"] = json!(slots.current);
            state["arch"] = json!(architecture);
            state["checked_utc"] = json!(now);
            state["check_ok"] = json!(true);
            state["check_error"] = json!("");
            state["latest"] = json!({"release_id":manifest.release_id,"version":manifest.version,"notes":manifest.notes});
            state["last_utc"] = json!(now);
            state["last_ok"] = json!(true);
            state["last_release"] = json!(manifest.release_id);
            state["last_message"] = json!(if changed {
                "Релиз активирован; для проверки и перезапуска вызовите адаптер роутера"
            } else {
                "Уже установлен последний релиз"
            });
            state["bad_release"] = json!("");
            if let Some(object) = state.as_object_mut() {
                object.remove("never");
            }
            write_state(root, &state)?;
            Ok(
                json!({"activated":changed,"already_current":!changed,"current":slots.current,"previous":slots.previous,"architecture":architecture}),
            )
        }
        Err(error) => {
            state["busy"] = json!("");
            state["last_utc"] = json!(now_epoch());
            state["last_ok"] = json!(false);
            state["last_message"] = json!(error.to_string());
            if let Some(object) = state.as_object_mut() {
                object.remove("never");
            }
            write_state(root, &state)?;
            Err(error)
        }
    }
}

/// Сохранить настройку автоустановки роутера, не сбрасывая историю обновлений.
pub fn set_auto_update(root: &Path, enabled: bool) -> Result<Value, UpdateError> {
    let _lock = UpdateLock::acquire(root)?;
    let mut state = read_state(root);
    state["auto"] = json!(enabled);
    if state.get("checked_utc").is_none() {
        state["never"] = json!(true);
    }
    write_state(root, &state)?;
    Ok(json!({"auto":enabled}))
}

fn auto_update_enabled(state: &Value) -> bool {
    state.get("auto").and_then(Value::as_bool).unwrap_or(true)
}

struct UpdateLock(File);

impl UpdateLock {
    fn acquire(root: &Path) -> Result<Self, UpdateError> {
        use std::fs::OpenOptions;
        use std::path::PathBuf;

        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir)?;
        let path: PathBuf = state_dir.join("update.lock");
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
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        Ok(Self(file))
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
    let manifest_path = work.join("latest.json");
    let signature_path = work.join("latest.json.sig");
    download(LATEST_URL, &manifest_path, MANIFEST_MAX_BYTES, "60")?;
    download(
        &format!("{LATEST_URL}.sig"),
        &signature_path,
        SIGNATURE_MAX_BYTES,
        "60",
    )?;
    let manifest_bytes = read_bounded(&manifest_path, MANIFEST_MAX_BYTES)?;
    let signature = read_bounded(&signature_path, SIGNATURE_MAX_BYTES)?;
    let public_key = decode_public_key(PUBLIC_KEY)?;
    let manifest = verify_manifest(&manifest_bytes, &signature, &public_key)?;
    let _ = manifest
        .assets
        .get(architecture)
        .ok_or_else(|| VerifyError::UnknownArchitecture(architecture.to_owned()))?;
    let slots = read_install_slots(root)?;
    Ok((manifest, slots))
}

fn install_update_in(
    work: &Path,
    root: &Path,
    architecture: &str,
) -> Result<(crate::ReleaseManifest, InstallSlots, bool), UpdateError> {
    let manifest_path = work.join("latest.json");
    let signature_path = work.join("latest.json.sig");
    let archive_path = work.join("release.tar.gz");
    download(LATEST_URL, &manifest_path, MANIFEST_MAX_BYTES, "60")?;
    download(
        &format!("{LATEST_URL}.sig"),
        &signature_path,
        SIGNATURE_MAX_BYTES,
        "60",
    )?;
    let manifest_bytes = read_bounded(&manifest_path, MANIFEST_MAX_BYTES)?;
    let signature = read_bounded(&signature_path, SIGNATURE_MAX_BYTES)?;
    let public_key = decode_public_key(PUBLIC_KEY)?;
    let manifest = verify_manifest(&manifest_bytes, &signature, &public_key)?;
    if !manifest.assets.contains_key(architecture) {
        return Err(VerifyError::UnknownArchitecture(architecture.to_owned()).into());
    }
    let slots = read_install_slots(root)?;
    if slots
        .as_ref()
        .is_some_and(|installed| installed.current == manifest.release_id)
    {
        return Ok((manifest, slots.expect("current release was checked"), false));
    }
    let url = format!(
        "{DOWNLOAD_URL}/{}/r2o-{architecture}.tar.gz",
        manifest.release_id
    );
    download(
        &url,
        &archive_path,
        ARCHIVE_MAX_BYTES,
        DOWNLOAD_TIMEOUT_SECONDS,
    )?;
    let slots = install_archive(
        root,
        &archive_path,
        &manifest_bytes,
        &signature,
        &public_key,
        architecture,
    )?;
    Ok((manifest, slots, true))
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
    download_with("curl", url, destination, max_bytes, timeout)
}

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

fn release_download_hosts(url: &str) -> &'static [&'static str] {
    if download_url_host(url).as_deref() == Some("github.com") {
        &GITHUB_DOWNLOAD_HOSTS
    } else {
        &[]
    }
}

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

fn read_state(root: &Path) -> Value {
    fs::read(root.join("state/update.json"))
        .ok()
        .filter(|bytes| bytes.len() <= 16 * 1024)
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn write_state(root: &Path, state: &Value) -> Result<(), UpdateError> {
    let path = root.join("state/update.json");
    let parent = path.parent().expect("update state has parent");
    fs::create_dir_all(parent)?;
    let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".update-{}-{sequence}.json", std::process::id()));
    let bytes = serde_json::to_vec(state).map_err(|error| io::Error::other(error.to_string()))?;
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
        Ok::<(), io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result?;
    Ok(())
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

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
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
        assert_eq!(read_state(&temp.0), state);
    }

    #[test]
    fn embedded_release_key_is_a_valid_ed25519_public_key() {
        assert_eq!(decode_public_key(PUBLIC_KEY).unwrap().len(), 32);
    }
}
