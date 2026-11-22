mod abi;
mod rollback_archive;

use super::{VerifyError, validate_token, verify_release_archive};
use flate2::read::GzDecoder;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use tar::Archive;

const SLOT_FILE: &str = "release-slots";
const MANAGER_COMPONENTS: [&str; 6] = [
    "r2o-datapath",
    "r2o-controller",
    "r2o-panel",
    "r2o-telegram",
    "r2o-manager",
    "r2o-fetch",
];
/// Необязательный диагностический CLI. Новый менеджер не требует его от
/// старых выпусков, но активирует и отдаёт, если файл есть в архиве.
const AUXILIARY_COMPONENTS: [&str; 1] = ["r2o-detect"];
const ARCHIVE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const ARCHIVE_MAX_ENTRIES: usize = 4096;
const ARCHIVE_MAX_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
const ARCHIVE_MAX_ENTRY_BYTES: u64 = 128 * 1024 * 1024;
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallSlots {
    pub current: String,
    pub previous: Option<String>,
}

#[derive(Debug)]
pub enum InstallError {
    Io(io::Error),
    InvalidReleaseId,
    InvalidArchitecture,
    InvalidBundle,
    MissingComponent(String),
    UnsafeBundleEntry(PathBuf),
    ReleaseAlreadyExists(String),
    InvalidSlotFile,
    NoActiveRelease,
    InvalidComponent,
    NoPreviousRelease,
    Busy,
    Verification(VerifyError),
    InvalidArchive(String),
    ArchiveTooLarge,
    ArchiveEntryLimit,
    ArchiveExpandedTooLarge,
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::InvalidReleaseId => write!(f, "release ID must be a safe alphanumeric token"),
            Self::InvalidArchitecture => {
                write!(f, "architecture must be a safe alphanumeric token")
            }
            Self::InvalidBundle => write!(f, "bundle must be a regular directory"),
            Self::MissingComponent(name) => write!(f, "bundle is missing executable {name}"),
            Self::UnsafeBundleEntry(path) => write!(
                f,
                "bundle contains an unsupported entry: {}",
                path.display()
            ),
            Self::ReleaseAlreadyExists(id) => write!(f, "release {id} already exists"),
            Self::InvalidSlotFile => write!(f, "release slot state is malformed"),
            Self::NoActiveRelease => write!(f, "there is no active release"),
            Self::InvalidComponent => write!(f, "component is not managed by this release"),
            Self::NoPreviousRelease => write!(f, "there is no previous release to roll back to"),
            Self::Busy => write!(f, "another install or rollback is already running"),
            Self::Verification(error) => write!(f, "release verification failed: {error}"),
            Self::InvalidArchive(reason) => write!(f, "invalid release archive: {reason}"),
            Self::ArchiveTooLarge => write!(f, "release archive exceeds {ARCHIVE_MAX_BYTES} bytes"),
            Self::ArchiveEntryLimit => write!(f, "release archive contains too many entries"),
            Self::ArchiveExpandedTooLarge => {
                write!(f, "expanded release archive exceeds the size limit")
            }
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Verification(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for InstallError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<VerifyError> for InstallError {
    fn from(value: VerifyError) -> Self {
        Self::Verification(value)
    }
}

/// Скопировать полный выпуск в неизменяемый каталог версии и атомарно
/// переключить единый файл слотов. Конфигурация и состояние вне каталога
/// выпуска не затрагиваются.
pub fn activate_bundle(
    root: &Path,
    bundle: &Path,
    release_id: &str,
    architecture: &str,
) -> Result<InstallSlots, InstallError> {
    fs::create_dir_all(root)?;
    let _lock = ManagerLock::acquire(root)?;
    if root.join("state/update-pending.json").try_exists()? {
        return Err(InstallError::Busy);
    }
    cleanup_stale_install_artifacts(root);
    activate_bundle_locked(root, bundle, release_id, architecture)
}

/// Проверенный и уже распакованный выпуск, который ещё не переключил слоты.
/// Нужен, чтобы скачивание/проверка/распаковка происходили до остановки
/// runtime, как в D2O `install.sh`, а замена файлов — после неё.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRelease {
    pub release_id: String,
    pub architecture: String,
    pub bundle: PathBuf,
    pub work: PathBuf,
}

impl PreparedRelease {
    /// Удалить приватный рабочий каталог подготовленного выпуска.
    pub fn discard(&self) {
        let _ = fs::remove_dir_all(&self.work);
    }
}

/// Проверить подписанный архив и распаковать его, не активируя. Вызывающий
/// позже подтверждает выпуск через [`activate_prepared`].
pub fn prepare_archive(
    root: &Path,
    archive_path: &Path,
    manifest_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
    architecture: &str,
) -> Result<PreparedRelease, InstallError> {
    if manifest_bytes.len() > super::MANIFEST_MAX_BYTES {
        return Err(VerifyError::ManifestTooLarge.into());
    }
    validate_token(architecture, "architecture", 32)
        .map_err(|_| InstallError::InvalidArchitecture)?;
    fs::create_dir_all(root)?;
    let _lock = ManagerLock::acquire(root)?;
    prepare_archive_locked(
        root,
        archive_path,
        manifest_bytes,
        signature,
        public_key,
        architecture,
    )
}

fn prepare_archive_locked(
    root: &Path,
    archive_path: &Path,
    manifest_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
    architecture: &str,
) -> Result<PreparedRelease, InstallError> {
    prepare_archive_inner(
        root,
        archive_path,
        manifest_bytes,
        signature,
        public_key,
        architecture,
        true,
    )
}

pub(crate) fn prepare_download(
    root: &Path,
    path: &Path,
    manifest: &[u8],
    signature: &[u8],
    key: &[u8],
    architecture: &str,
) -> Result<PreparedRelease, InstallError> {
    let _lock = ManagerLock::acquire(root)?;
    prepare_archive_inner(root, path, manifest, signature, key, architecture, false)
}

fn prepare_archive_inner(
    root: &Path,
    archive_path: &Path,
    manifest_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
    architecture: &str,
    copy: bool,
) -> Result<PreparedRelease, InstallError> {
    cleanup_stale_install_artifacts(root);
    let work = create_work_dir(root)?;
    let result = (|| {
        let local_archive = work.join("release.tar.gz");
        let archive_path = if copy {
            copy_archive(archive_path, &local_archive)?;
            local_archive.as_path()
        } else {
            archive_path
        };
        let mut archive_file = File::open(archive_path)?;
        let (manifest, _) = verify_release_archive(
            manifest_bytes,
            signature,
            public_key,
            architecture,
            &mut archive_file,
        )?;
        let max_expanded = manifest.assets[architecture]
            .expanded
            .unwrap_or(ARCHIVE_MAX_EXPANDED_BYTES);
        archive_file.seek(SeekFrom::Start(0))?;
        let bundle = work.join("bundle");
        fs::create_dir(&bundle)?;
        extract_bundle(GzDecoder::new(&mut archive_file), &bundle, max_expanded)?;
        validate_bundle(&bundle, architecture)?;
        if manifest.metadata.is_some() {
            abi::validate_bundle_abi(&bundle, architecture)?;
        }
        if !copy {
            link_controller_applets(&bundle, architecture)?;
            write_synced(&bundle.join("release-id"), manifest.release_id.as_bytes())?;
            write_synced(
                &bundle.join("release-architecture"),
                architecture.as_bytes(),
            )?;
            sync_bundle(&bundle)?;
            sync_directory(&work)?;
            sync_directory(root)?;
        }
        Ok(PreparedRelease {
            release_id: manifest.release_id,
            architecture: architecture.to_owned(),
            bundle,
            work: work.clone(),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&work);
    }
    result
}

fn sync_bundle(bundle: &Path) -> Result<(), InstallError> {
    for entry in fs::read_dir(bundle)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_bundle(&entry.path())?;
        } else {
            File::open(entry.path())?.sync_all()?;
        }
    }
    sync_directory(bundle)?;
    Ok(())
}

pub(crate) fn activate_download(
    root: &Path,
    prepared: &PreparedRelease,
) -> Result<InstallSlots, InstallError> {
    let _lock = ManagerLock::acquire(root)?;
    let current = read_install_slots(root)?.ok_or(InstallError::NoActiveRelease)?;
    let slots = InstallSlots {
        current: prepared.release_id.clone(),
        previous: Some(current.current),
    };
    let releases = root.join("releases");
    let target = releases.join(&slots.current);
    validate_bundle(&prepared.bundle, &prepared.architecture)?;
    if fs::symlink_metadata(&target).is_ok() {
        if slots.previous.as_deref() == Some(slots.current.as_str())
            || current.previous.as_deref() == Some(slots.current.as_str())
        {
            return Err(InstallError::ReleaseAlreadyExists(slots.current));
        }
        ensure_release_dir(root, &slots.current)?;
        fs::remove_dir_all(&target)?;
    }
    fs::rename(&prepared.bundle, &target)?;
    sync_directory(&releases)?;
    sync_directory(&prepared.work)?;
    write_slots_atomically(root, &slots)?;
    Ok(slots)
}

pub(crate) fn refresh_launcher(root: &Path) -> Result<(), InstallError> {
    let _lock = ManagerLock::acquire(root)?;
    let current = read_install_slots(root)?
        .ok_or(InstallError::NoActiveRelease)?
        .current;
    let arch = read_release_architecture(root, &current)?;
    install_manager_launcher(root, &root.join("releases").join(current), &arch)
}

pub fn link_active_applets(root: &Path) -> Result<(), InstallError> {
    let _lock = ManagerLock::acquire(root)?;
    let current = read_install_slots(root)?
        .ok_or(InstallError::NoActiveRelease)?
        .current;
    let architecture = read_release_architecture(root, &current)?;
    let release = root.join("releases").join(current);
    link_controller_applets(&release, &architecture)?;
    if !root.join("state/update-pending.json").try_exists()? {
        install_manager_launcher(root, &release, &architecture)?;
    }
    Ok(())
}

/// Активировать ранее подготовленный выпуск, не перепроверяя архив.
pub fn activate_prepared(
    root: &Path,
    prepared: &PreparedRelease,
) -> Result<InstallSlots, InstallError> {
    fs::create_dir_all(root)?;
    let _lock = ManagerLock::acquire(root)?;
    activate_bundle_locked(
        root,
        &prepared.bundle,
        &prepared.release_id,
        &prepared.architecture,
    )
}

/// Проверить подписанный выпуск и активировать архив, не раскрывая
/// непроверенные файлы. Сжатый архив сначала копируется в закрытый временный
/// каталог, поэтому проверка и распаковка читают одни и те же байты.
pub fn install_archive(
    root: &Path,
    archive_path: &Path,
    manifest_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
    architecture: &str,
) -> Result<InstallSlots, InstallError> {
    if manifest_bytes.len() > super::MANIFEST_MAX_BYTES {
        return Err(VerifyError::ManifestTooLarge.into());
    }
    validate_token(architecture, "architecture", 32)
        .map_err(|_| InstallError::InvalidArchitecture)?;
    fs::create_dir_all(root)?;
    let _lock = ManagerLock::acquire(root)?;
    if root.join("state/update-pending.json").try_exists()? {
        return Err(InstallError::Busy);
    }
    let prepared = prepare_archive_locked(
        root,
        archive_path,
        manifest_bytes,
        signature,
        public_key,
        architecture,
    )?;
    let result = activate_bundle_locked(
        root,
        &prepared.bundle,
        &prepared.release_id,
        &prepared.architecture,
    );
    prepared.discard();
    result
}

fn activate_bundle_locked(
    root: &Path,
    bundle: &Path,
    release_id: &str,
    architecture: &str,
) -> Result<InstallSlots, InstallError> {
    validate_token(release_id, "release_id", 128).map_err(|_| InstallError::InvalidReleaseId)?;
    validate_token(architecture, "architecture", 32)
        .map_err(|_| InstallError::InvalidArchitecture)?;
    validate_bundle(bundle, architecture)?;
    let releases = root.join("releases");
    fs::create_dir_all(&releases)?;
    let destination = releases.join(release_id);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(InstallError::ReleaseAlreadyExists(release_id.to_owned()));
    }

    let staging = create_staging_dir(&releases, release_id)?;
    let copy_result = copy_tree(bundle, &staging).and_then(|()| {
        link_controller_applets(&staging, architecture)?;
        write_synced(&staging.join("release-id"), release_id.as_bytes())?;
        write_synced(
            &staging.join("release-architecture"),
            architecture.as_bytes(),
        )?;
        sync_directory(&staging)?;
        Ok(())
    });
    if let Err(error) = copy_result {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    if let Err(error) = fs::rename(&staging, &destination) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error.into());
    }
    sync_directory(&releases)?;
    install_manager_launcher(root, &destination, architecture)?;

    let slots = match read_install_slots(root)? {
        Some(previous) => InstallSlots {
            current: release_id.to_owned(),
            previous: Some(previous.current),
        },
        None => InstallSlots {
            current: release_id.to_owned(),
            previous: None,
        },
    };
    write_slots_atomically(root, &slots)?;
    if !root.join("state/update-pending.json").try_exists()? {
        prune_obsolete_releases(root, &slots);
    }
    Ok(slots)
}

/// Удалить выпуски, на которые больше не ссылаются слоты current/previous.
/// Каталог `releases` принадлежит установщику; чужие или недописанные
/// каталоги без совпадающего `release-id` не трогаем.
pub(crate) fn cleanup_releases(root: &Path) -> Result<(), InstallError> {
    let _lock = ManagerLock::acquire(root)?;
    if let Some(slots) = read_install_slots(root)? {
        prune_obsolete_releases(root, &slots);
        if let Some(previous) = &slots.previous
            && rollback_archive::supported_by(root, &slots.current)
        {
            rollback_archive::compact(root, previous)?;
        }
    }
    Ok(())
}

fn prune_obsolete_releases(root: &Path, slots: &InstallSlots) {
    let releases = root.join("releases");
    let Ok(entries) = fs::read_dir(&releases) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !valid_release_id(name)
            || name == slots.current
            || slots.previous.as_deref() == Some(name)
        {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let marker = fs::read(path.join("release-id")).ok();
        if marker.as_deref() != Some(name.as_bytes()) {
            continue;
        }
        // Уборка не должна отменять уже состоявшуюся активацию: если старый
        // выпуск занят или права не позволяют, установка всё равно успешна.
        let _ = fs::remove_dir_all(&path);
    }
}

/// Убрать оставшиеся после SIGKILL/сбоя питания временные каталоги и
/// недописанные слоты. Вызывается только под ManagerLock.
fn cleanup_stale_install_artifacts(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let stale_directory = name.starts_with(".install-");
        let stale_file = name.starts_with(".release-slots.") || name.starts_with(".r2o-manager-");
        if !stale_directory && !stale_file {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if stale_directory && metadata.is_dir() {
            let _ = fs::remove_dir_all(&path);
        } else if stale_file && metadata.is_file() {
            let _ = fs::remove_file(&path);
        }
    }

    let releases = root.join("releases");
    let Ok(entries) = fs::read_dir(&releases) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(".staging-") {
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

pub(crate) fn recover_interrupted_extraction(root: &Path) -> Result<(), InstallError> {
    let _lock = ManagerLock::acquire(root)?;
    cleanup_stale_install_artifacts(root);
    Ok(())
}

fn create_work_dir(root: &Path) -> Result<PathBuf, InstallError> {
    for _ in 0..16 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let work = root.join(format!(".install-{}-{sequence}", std::process::id()));
        match fs::create_dir(&work) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&work, fs::Permissions::from_mode(0o700))?;
                }
                return Ok(work);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot allocate release work directory",
    )
    .into())
}

fn copy_archive(source: &Path, destination: &Path) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(InstallError::InvalidArchive(
            "archive source must be a regular file".into(),
        ));
    }
    if metadata.len() > ARCHIVE_MAX_BYTES {
        return Err(InstallError::ArchiveTooLarge);
    }
    let mut input = File::open(source)?;
    let mut output_options = OpenOptions::new();
    output_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        output_options.mode(0o600);
    }
    let mut output = output_options.open(destination)?;
    let mut buffer = [0u8; 32 * 1024];
    let mut copied = 0u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(count as u64)
            .ok_or(InstallError::ArchiveTooLarge)?;
        if copied > ARCHIVE_MAX_BYTES {
            return Err(InstallError::ArchiveTooLarge);
        }
        output.write_all(&buffer[..count])?;
    }
    output.sync_all()?;
    Ok(())
}

fn extract_bundle<R: Read>(
    reader: R,
    destination: &Path,
    max_expanded: u64,
) -> Result<R, InstallError> {
    let mut archive = Archive::new(reader);
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    let mut seen = std::collections::HashSet::new();
    let mut entry_count = 0usize;
    let mut expanded = 0u64;
    let entries = archive
        .entries()
        .map_err(|error| InstallError::InvalidArchive(error.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| InstallError::InvalidArchive(error.to_string()))?;
        entry_count += 1;
        if entry_count > ARCHIVE_MAX_ENTRIES {
            return Err(InstallError::ArchiveEntryLimit);
        }
        let path = entry
            .path()
            .map_err(|error| InstallError::InvalidArchive(error.to_string()))?
            .into_owned();
        let path = validate_archive_path(&path)?;
        if !seen.insert(path.clone()) {
            return Err(InstallError::InvalidArchive(format!(
                "duplicate path {}",
                path.display()
            )));
        }
        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() && !entry_type.is_dir() {
            return Err(InstallError::InvalidArchive(format!(
                "unsupported entry type at {}",
                path.display()
            )));
        }
        let size = entry
            .header()
            .size()
            .map_err(|error| InstallError::InvalidArchive(error.to_string()))?;
        if entry_type.is_dir() && size != 0 {
            return Err(InstallError::InvalidArchive(format!(
                "directory has data at {}",
                path.display()
            )));
        }
        if size > ARCHIVE_MAX_ENTRY_BYTES {
            return Err(InstallError::ArchiveExpandedTooLarge);
        }
        expanded = expanded
            .checked_add(size)
            .ok_or(InstallError::ArchiveExpandedTooLarge)?;
        if expanded > max_expanded {
            return Err(InstallError::ArchiveExpandedTooLarge);
        }
        entry.set_mask(0o7022);
        if !entry
            .unpack_in(destination)
            .map_err(|error| InstallError::InvalidArchive(error.to_string()))?
        {
            return Err(InstallError::InvalidArchive(format!(
                "path escapes bundle root: {}",
                path.display()
            )));
        }
    }
    Ok(archive.into_inner())
}

fn validate_archive_path(path: &Path) -> Result<PathBuf, InstallError> {
    if path.as_os_str().is_empty()
        || path.as_os_str().len() > 4096
        || path.is_absolute()
        || path.to_string_lossy().contains('\\')
    {
        return Err(InstallError::InvalidArchive("unsafe or empty path".into()));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => normalized.push(part),
            _ => {
                return Err(InstallError::InvalidArchive(format!(
                    "unsafe path {}",
                    path.display()
                )));
            }
        }
    }
    Ok(normalized)
}

/// Атомарно поменять местами идентификаторы текущего и предыдущего выпусков
/// в одном файле состояния.
pub fn rollback(root: &Path) -> Result<InstallSlots, InstallError> {
    fs::create_dir_all(root)?;
    let _lock = ManagerLock::acquire(root)?;
    if root.join("state/update-pending.json").try_exists()? {
        return Err(InstallError::Busy);
    }
    rollback_locked(root)
}

pub(crate) fn restore_update_slots(
    root: &Path,
    active_trial: &str,
    slots: &InstallSlots,
) -> Result<(), InstallError> {
    let _lock = ManagerLock::acquire(root)?;
    let active = read_install_slots(root)?.ok_or(InstallError::NoActiveRelease)?;
    if active.current != active_trial || active.previous.as_deref() != Some(slots.current.as_str())
    {
        return Err(InstallError::InvalidSlotFile);
    }
    ensure_release_dir(root, &slots.current)?;
    if let Some(previous) = &slots.previous {
        ensure_release_dir(root, previous)?;
    }
    write_slots_atomically(root, slots)
}

fn rollback_locked(root: &Path) -> Result<InstallSlots, InstallError> {
    let current = read_install_slots(root)?.ok_or(InstallError::NoPreviousRelease)?;
    let previous = current.previous.ok_or(InstallError::NoPreviousRelease)?;
    ensure_release_dir(root, &previous)?;
    ensure_release_dir(root, &current.current)?;
    rollback_archive::restore(root, &previous)?;
    let slots = InstallSlots {
        current: previous,
        previous: Some(current.current),
    };
    write_slots_atomically(root, &slots)?;
    Ok(slots)
}

pub(crate) fn prepare_previous_builds(root: &Path, release_id: &str) -> Result<(), InstallError> {
    let _lock = ManagerLock::acquire(root)?;
    let slots = read_install_slots(root)?.ok_or(InstallError::NoActiveRelease)?;
    if slots.previous.as_deref() != Some(release_id) {
        return Err(InstallError::NoPreviousRelease);
    }
    rollback_archive::restore(root, release_id)
}

pub(crate) fn activate_previous_release(
    root: &Path,
    release_id: &str,
    architecture: &str,
) -> Result<Option<InstallSlots>, InstallError> {
    fs::create_dir_all(root)?;
    let _lock = ManagerLock::acquire(root)?;
    cleanup_stale_install_artifacts(root);
    let Some(current) = read_install_slots(root)? else {
        return Ok(None);
    };
    if current.previous.as_deref() != Some(release_id) {
        return Ok(None);
    }
    if read_release_architecture(root, release_id)? != architecture {
        return Err(InstallError::InvalidArchitecture);
    }
    rollback_archive::restore(root, release_id)?;
    let slots = InstallSlots {
        current: release_id.to_owned(),
        previous: Some(current.current),
    };
    write_slots_atomically(root, &slots)?;
    if !root.join("state/update-pending.json").try_exists()? {
        prune_obsolete_releases(root, &slots);
    }
    Ok(Some(slots))
}

pub fn read_install_slots(root: &Path) -> Result<Option<InstallSlots>, InstallError> {
    let path = root.join(SLOT_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 512 {
        return Err(InstallError::InvalidSlotFile);
    }
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(513).read_to_end(&mut bytes)?;
    if bytes.len() > 512 {
        return Err(InstallError::InvalidSlotFile);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| InstallError::InvalidSlotFile)?;
    let mut lines = text.lines();
    if lines.next() != Some("R2O-RELEASE-SLOTS-1") {
        return Err(InstallError::InvalidSlotFile);
    }
    let current = lines.next().ok_or(InstallError::InvalidSlotFile)?;
    let previous = lines.next().ok_or(InstallError::InvalidSlotFile)?;
    if lines.next().is_some() || !valid_release_id(current) {
        return Err(InstallError::InvalidSlotFile);
    }
    let previous = if previous == "-" {
        None
    } else if valid_release_id(previous) && previous != current {
        Some(previous.to_owned())
    } else {
        return Err(InstallError::InvalidSlotFile);
    };
    let slots = InstallSlots {
        current: current.to_owned(),
        previous,
    };
    ensure_release_dir(root, &slots.current)?;
    if let Some(previous) = &slots.previous {
        ensure_release_dir(root, previous)?;
    }
    Ok(Some(slots))
}

/// Прочитать архитектуру, записанную для текущего неизменяемого выпуска.
pub fn read_install_architecture(root: &Path) -> Result<Option<String>, InstallError> {
    let Some(slots) = read_install_slots(root)? else {
        return Ok(None);
    };
    read_release_architecture(root, &slots.current).map(Some)
}

/// Найти компонент только внутри текущего неизменяемого выпуска.
pub fn active_component_path(root: &Path, component: &str) -> Result<PathBuf, InstallError> {
    if !MANAGER_COMPONENTS.contains(&component) && !AUXILIARY_COMPONENTS.contains(&component) {
        return Err(InstallError::InvalidComponent);
    }
    let slots = read_install_slots(root)?.ok_or(InstallError::NoActiveRelease)?;
    let architecture = read_release_architecture(root, &slots.current)?;
    let name = format!("{component}-linux-{architecture}");
    let path = root
        .join("releases")
        .join(slots.current)
        .join("builds")
        .join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => InstallError::MissingComponent(component.to_owned()),
        _ => InstallError::Io(error),
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
        return Err(InstallError::MissingComponent(component.to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(InstallError::MissingComponent(component.to_owned()));
        }
    }
    Ok(path)
}

fn read_release_architecture(root: &Path, release_id: &str) -> Result<String, InstallError> {
    let path = root
        .join("releases")
        .join(release_id)
        .join("release-architecture");
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 32 {
        return Err(InstallError::InvalidArchitecture);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.take(33).read_to_end(&mut bytes)?;
    if bytes.len() > 32 {
        return Err(InstallError::InvalidArchitecture);
    }
    let architecture = std::str::from_utf8(&bytes)
        .map_err(|_| InstallError::InvalidArchitecture)?
        .to_owned();
    validate_token(&architecture, "architecture", 32)
        .map_err(|_| InstallError::InvalidArchitecture)?;
    Ok(architecture)
}

fn link_controller_applets(staging: &Path, architecture: &str) -> io::Result<()> {
    const FORMAT: &[u8] = b"R2O-CONTROLLER-APPLETS-5\n";
    let marker = staging.join("router/controller-applets");
    let file = match File::open(marker) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::with_capacity(FORMAT.len());
    file.take(FORMAT.len() as u64 + 1).read_to_end(&mut bytes)?;
    let applets: &[&str] = match bytes.as_slice() {
        b"R2O-CONTROLLER-APPLETS-1\n" => &["r2o-fetch", "r2o-detect"],
        b"R2O-CONTROLLER-APPLETS-2\n" => &["r2o-fetch", "r2o-detect", "r2o-telegram"],
        b"R2O-CONTROLLER-APPLETS-3\n" => &["r2o-fetch", "r2o-detect", "r2o-telegram", "r2o-panel"],
        b"R2O-CONTROLLER-APPLETS-4\n" => &[
            "r2o-fetch",
            "r2o-detect",
            "r2o-telegram",
            "r2o-panel",
            "r2o-datapath",
        ],
        FORMAT => &[
            "r2o-fetch",
            "r2o-detect",
            "r2o-telegram",
            "r2o-panel",
            "r2o-manager",
        ],
        _ => return Ok(()),
    };

    let builds = staging.join("builds");
    let controller = builds.join(format!("r2o-controller-linux-{architecture}"));
    let controller_metadata = fs::metadata(&controller)?;
    let mut changed = false;
    for applet in applets {
        if *applet == "r2o-datapath" && !matches!(architecture, "mipsel" | "mipsel-openwrt-musl") {
            continue;
        }
        let installed = builds.join(format!("{applet}-linux-{architecture}"));
        let temporary = builds.join(format!(".{applet}.link"));
        let Ok(metadata) = fs::metadata(&installed) else {
            continue;
        };
        if !metadata.is_file() || rollback_archive::same_file(&metadata, &controller_metadata) {
            continue;
        }
        // На ФС без жёстких ссылок оставляем отдельный проверенный ELF из архива.
        if fs::hard_link(&controller, &temporary).is_ok()
            || fs::symlink_metadata(&temporary)
                .is_ok_and(|link| rollback_archive::same_file(&link, &controller_metadata))
        {
            fs::rename(temporary, installed)?;
            changed = true;
        }
    }
    if changed {
        sync_directory(&builds)?;
    }
    Ok(())
}

fn install_manager_launcher(
    root: &Path,
    release: &Path,
    architecture: &str,
) -> Result<(), InstallError> {
    let source = release
        .join("builds")
        .join(format!("r2o-manager-linux-{architecture}"));
    let source_metadata = fs::symlink_metadata(&source)?;
    if !source_metadata.is_file() || source_metadata.file_type().is_symlink() {
        return Err(InstallError::MissingComponent(format!(
            "r2o-manager-linux-{architecture}"
        )));
    }
    let launcher = root.join("r2o-manager");
    for _ in 0..16 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary = root.join(format!(".r2o-manager-{}-{sequence}", std::process::id()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Ссылка экономит копию ELF. Если ФС или режим файла мешают, сохраняем копирование.
            if source_metadata.permissions().mode() & 0o7777 == 0o755 {
                if let Ok(metadata) = fs::symlink_metadata(&launcher)
                    && rollback_archive::same_file(&source_metadata, &metadata)
                {
                    return Ok(());
                }
                match fs::hard_link(&source, &temporary) {
                    Ok(()) => {
                        let result = fs::rename(&temporary, &launcher);
                        let _ = fs::remove_file(&temporary);
                        return result
                            .and_then(|()| sync_directory(root))
                            .map_err(InstallError::Io);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(_) => {}
                }
            }
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        let mut destination = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        let result = (|| {
            let mut source = File::open(&source)?;
            io::copy(&mut source, &mut destination)?;
            destination.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))?;
            }
            destination.sync_all()?;
            fs::rename(&temporary, &launcher)?;
            sync_directory(root)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result.map_err(InstallError::Io);
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot allocate manager launcher",
    )
    .into())
}

fn validate_bundle(bundle: &Path, architecture: &str) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(bundle).map_err(InstallError::Io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(InstallError::InvalidBundle);
    }
    let reserved = bundle.join(rollback_archive::ARCHIVE);
    match fs::symlink_metadata(&reserved) {
        Ok(_) => return Err(InstallError::UnsafeBundleEntry(reserved)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for component in MANAGER_COMPONENTS {
        let name = format!("{component}-linux-{architecture}");
        let path = bundle.join("builds").join(&name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(InstallError::MissingComponent(name));
            }
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
            return Err(InstallError::MissingComponent(name));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(InstallError::MissingComponent(name));
            }
        }
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), InstallError> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            return Err(InstallError::UnsafeBundleEntry(source_path));
        }
        if metadata.is_dir() {
            fs::create_dir(&destination_path)?;
            copy_tree(&source_path, &destination_path)?;
            sync_directory(&destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &destination_path,
                    fs::Permissions::from_mode(metadata.permissions().mode() & 0o755),
                )?;
            }
            File::open(&destination_path)?.sync_all()?;
        } else {
            return Err(InstallError::UnsafeBundleEntry(source_path));
        }
    }
    Ok(())
}

fn create_staging_dir(releases: &Path, release_id: &str) -> Result<PathBuf, InstallError> {
    for _ in 0..16 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let staging = releases.join(format!(
            ".staging-{release_id}-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&staging) {
            Ok(()) => return Ok(staging),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot allocate release staging directory",
    )
    .into())
}

fn write_slots_atomically(root: &Path, slots: &InstallSlots) -> Result<(), InstallError> {
    let previous = slots.previous.as_deref().unwrap_or("-");
    let bytes = format!("R2O-RELEASE-SLOTS-1\n{}\n{}\n", slots.current, previous);
    for _ in 0..16 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary = root.join(format!(".{SLOT_FILE}.{}-{sequence}", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(mut file) => {
                let result = (|| {
                    file.write_all(bytes.as_bytes())?;
                    file.sync_all()?;
                    fs::rename(&temporary, root.join(SLOT_FILE))?;
                    sync_directory(root)
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&temporary);
                }
                return result.map_err(InstallError::Io);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot allocate release state file",
    )
    .into())
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn ensure_release_dir(root: &Path, release_id: &str) -> Result<(), InstallError> {
    if !valid_release_id(release_id) {
        return Err(InstallError::InvalidSlotFile);
    }
    let path = root.join("releases").join(release_id);
    let metadata = fs::symlink_metadata(path).map_err(InstallError::Io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(InstallError::InvalidSlotFile);
    }
    Ok(())
}

fn valid_release_id(value: &str) -> bool {
    validate_token(value, "release_id", 128).is_ok()
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(all(test, unix))]
fn log_test_manager_debug_line(line: &str) {
    let _ = unsafe { libc::write(libc::STDERR_FILENO, line.as_ptr().cast(), line.len()) };
}

#[cfg(all(test, unix))]
fn log_test_manager_lock(status: &str, root: &Path, file: &File) {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().ok();
    let inode = metadata.as_ref().map_or(0, MetadataExt::ino);
    let device = metadata.as_ref().map_or(0, MetadataExt::dev);
    let lock_table = fs::read_to_string("/proc/locks").unwrap_or_default();
    let locks = lock_table
        .lines()
        .filter(|line| line.contains(&format!(" {inode} ")))
        .collect::<Vec<_>>();
    log_test_manager_debug_line(&format!(
        "manager-lock-test status={status} pid={} thread={} root={} dev={device:x} ino={inode} locks={locks:?}\n",
        std::process::id(),
        std::thread::current().name().unwrap_or("?"),
        root.display()
    ));
}

#[cfg(unix)]
struct ManagerLock {
    _file: File,
}

#[cfg(unix)]
impl ManagerLock {
    fn acquire(root: &Path) -> Result<Self, InstallError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(".manager.lock"))?;
        // `flock` удерживает блокировку установки, пока открыт этот файл.
        // На некоторых ФС (и под высокой параллельностью тестов) ядро
        // отдаёт EAGAIN ещё короткое время после close предыдущего
        // владельца. Ждём до 100 мс: настоящий параллельный менеджер всё
        // равно получит Busy, а ложный отказ установки исчезает.
        let mut attempts = 0;
        loop {
            if unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&file),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            } == 0
            {
                break;
            }
            let error = io::Error::last_os_error();
            if error
                .raw_os_error()
                .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
            {
                attempts += 1;
                if attempts >= 50 {
                    #[cfg(test)]
                    log_test_manager_lock("busy", root, &file);
                    return Err(InstallError::Busy);
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            return Err(error.into());
        }
        #[cfg(test)]
        log_test_manager_lock("acquired", root, &file);
        Ok(Self { _file: file })
    }
}

#[cfg(not(unix))]
struct ManagerLock;

#[cfg(not(unix))]
impl ManagerLock {
    fn acquire(_root: &Path) -> Result<Self, InstallError> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "release activation requires a Unix file lock",
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::read::GzDecoder;
    use flate2::write::GzEncoder;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEST: AtomicUsize = AtomicUsize::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            loop {
                let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "r2o-manager-install-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        #[cfg(unix)]
                        super::log_test_manager_debug_line(&format!(
                            "manager-test-dir pid={} thread={} path={}\n",
                            std::process::id(),
                            std::thread::current().name().unwrap_or("?"),
                            path.display()
                        ));
                        return Self(path);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        panic!("cannot create test directory {}: {error}", path.display())
                    }
                }
            }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn bundle(parent: &Path, id: &str, arch: &str) -> PathBuf {
        let root = parent.join(format!("bundle-{id}"));
        let builds = root.join("builds");
        fs::create_dir_all(&builds).unwrap();
        for component in MANAGER_COMPONENTS {
            let path = builds.join(format!("{component}-linux-{arch}"));
            fs::write(&path, format!("{id}:{component}")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        fs::write(root.join("preserved.txt"), "release payload").unwrap();
        root
    }

    fn signed_archive() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for component in MANAGER_COMPONENTS {
            let path = format!("builds/{component}-linux-mipsel");
            let content = format!("fixture:{component}");
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(content.len() as u64);
            header.set_mode(0o4755);
            header.set_cksum();
            builder
                .append_data(&mut header, path, content.as_bytes())
                .unwrap();
        }
        builder.finish().unwrap();
        let archive = builder.into_inner().unwrap().finish().unwrap();

        sign_archive(archive)
    }

    fn sign_archive(archive: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let digest = crate::to_hex(&Sha256::digest(&archive));
        let manifest = format!(
            r#"{{"release_id":"r2o-archive-1","version":"0.1.0","notes":"test","assets":{{"mipsel":{{"sha256":"{digest}"}}}}}}"#
        )
        .into_bytes();
        let signature = key_pair.sign(&manifest).as_ref().to_vec();
        let public_key = key_pair.public_key().as_ref().to_vec();
        (archive, manifest, signature, public_key)
    }

    fn replace_first_archive_path(archive: &[u8], path: &str) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        GzDecoder::new(Cursor::new(archive))
            .read_to_end(&mut tar_bytes)
            .unwrap();
        let header = &mut tar_bytes[..512];
        header[..100].fill(0);
        header[..path.len()].copy_from_slice(path.as_bytes());
        header[148..156].fill(b' ');
        let checksum: usize = header.iter().map(|byte| *byte as usize).sum();
        let checksum = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn downloaded_release_shares_controller_applets_after_activation() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new();
        let root = temp.0.join("install");
        let legacy = bundle(&temp.0, "legacy", "mipsel");
        activate_bundle(&root, &legacy, "r2o-legacy", "mipsel").unwrap();
        let incoming = bundle(&temp.0, "incoming", "mipsel");
        fs::create_dir(incoming.join("router")).unwrap();
        fs::write(
            incoming.join("router/controller-applets"),
            "R2O-CONTROLLER-APPLETS-5\n",
        )
        .unwrap();
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        tar.append_dir_all("builds", incoming.join("builds"))
            .unwrap();
        tar.append_dir_all("router", incoming.join("router"))
            .unwrap();
        let (archive, manifest, signature, key) =
            sign_archive(tar.into_inner().unwrap().finish().unwrap());
        let download = temp.0.join("download.tar.gz");
        fs::write(&download, archive).unwrap();
        let prepared =
            prepare_download(&root, &download, &manifest, &signature, &key, "mipsel").unwrap();
        activate_download(&root, &prepared).unwrap();
        let controller =
            fs::metadata(active_component_path(&root, "r2o-controller").unwrap()).unwrap();
        for name in ["r2o-fetch", "r2o-telegram", "r2o-panel", "r2o-manager"] {
            let applet = fs::metadata(active_component_path(&root, name).unwrap()).unwrap();
            assert_eq!(
                (applet.dev(), applet.ino()),
                (controller.dev(), controller.ino())
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn installation_shares_controller_applets_and_keeps_old_release() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = TestDir::new();
        let root = temp.0.join("install");
        let legacy = bundle(&temp.0, "legacy", "mipsel");
        let modern = bundle(&temp.0, "modern", "mipsel");
        fs::create_dir(modern.join("router")).unwrap();
        fs::write(
            modern.join("router/controller-applets"),
            "R2O-CONTROLLER-APPLETS-1\n",
        )
        .unwrap();
        let detect = modern.join("builds/r2o-detect-linux-mipsel");
        fs::write(&detect, "detect").unwrap();
        fs::set_permissions(&detect, fs::Permissions::from_mode(0o755)).unwrap();

        activate_bundle(&root, &legacy, "r2o-legacy", "mipsel").unwrap();
        activate_bundle(&root, &modern, "r2o-modern", "mipsel").unwrap();
        let controller = active_component_path(&root, "r2o-controller").unwrap();
        let controller = fs::metadata(controller).unwrap();
        for applet in ["r2o-fetch", "r2o-detect"] {
            let path = active_component_path(&root, applet).unwrap();
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(
                (metadata.dev(), metadata.ino()),
                (controller.dev(), controller.ino())
            );
        }

        rollback(&root).unwrap();
        let fetch = active_component_path(&root, "r2o-fetch").unwrap();
        assert_eq!(fs::read_to_string(fetch).unwrap(), "legacy:r2o-fetch");
        assert!(active_component_path(&root, "r2o-detect").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn startup_links_applets_extracted_by_an_older_manager() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new();
        let root = temp.0.join("install");
        let incoming = bundle(&temp.0, "incoming", "mipsel");
        activate_bundle(&root, &incoming, "r2o-current", "mipsel").unwrap();
        let release = root.join("releases/r2o-current");
        fs::create_dir(release.join("router")).unwrap();
        fs::write(
            release.join("router/controller-applets"),
            "R2O-CONTROLLER-APPLETS-5\n",
        )
        .unwrap();

        let builds = release.join("builds");
        fs::hard_link(
            builds.join("r2o-controller-linux-mipsel"),
            builds.join(".r2o-manager.link"),
        )
        .unwrap();
        for _ in 0..2 {
            link_active_applets(&root).unwrap();
            let controller = active_component_path(&root, "r2o-controller").unwrap();
            let controller = fs::metadata(controller).unwrap();
            for name in ["r2o-telegram", "r2o-manager"] {
                let file = active_component_path(&root, name).unwrap();
                assert_eq!(fs::metadata(file).unwrap().ino(), controller.ino());
                assert!(!builds.join(format!(".{name}.link")).exists());
            }
            let datapath = active_component_path(&root, "r2o-datapath").unwrap();
            assert_ne!(fs::metadata(datapath).unwrap().ino(), controller.ino());
            assert_eq!(
                fs::metadata(root.join("r2o-manager")).unwrap().ino(),
                controller.ino()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn compacted_rollback_preserves_bytes_and_never_activates_a_corrupt_archive() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = TestDir::new();
        let root = temp.0.join("install");
        let previous = bundle(&temp.0, "previous", "mipsel");
        let current = bundle(&temp.0, "current", "mipsel");
        let old_controller = previous.join("builds/r2o-controller-linux-mipsel");
        let controller_bytes = b"previous-controller".repeat(8192);
        fs::write(&old_controller, &controller_bytes).unwrap();
        fs::create_dir(previous.join("router")).unwrap();
        fs::write(
            previous.join("router/controller-applets"),
            "R2O-CONTROLLER-APPLETS-5\n",
        )
        .unwrap();
        let detect = previous.join("builds/r2o-detect-linux-mipsel");
        fs::write(&detect, "detect").unwrap();
        fs::set_permissions(&detect, fs::Permissions::from_mode(0o755)).unwrap();

        activate_bundle(&root, &previous, "r2o-previous", "mipsel").unwrap();
        let slots = activate_bundle(&root, &current, "r2o-current", "mipsel").unwrap();
        cleanup_releases(&root).unwrap();
        let old = root.join("releases/r2o-previous");
        let archive = old.join(rollback_archive::ARCHIVE);
        assert!(old.join("builds").is_dir());
        assert!(!archive.exists());
        let router = root.join("releases/r2o-current/router");
        fs::create_dir(&router).unwrap();
        fs::write(router.join("rollback-xz"), rollback_archive::FORMAT).unwrap();
        crate::compact_install_rollback(&root).unwrap();
        assert!(!old.join("builds").exists());
        assert!(old.join("router/controller-applets").is_file());
        let packed = fs::read(&archive).unwrap();
        assert!(packed.len() < controller_bytes.len());

        fs::write(&archive, &packed[..packed.len() - 1]).unwrap();
        assert!(prepare_previous_builds(&root, "r2o-previous").is_err());
        assert!(rollback(&root).is_err());
        assert_eq!(read_install_slots(&root).unwrap(), Some(slots));
        assert!(!old.join("builds").exists());

        fs::write(&archive, packed).unwrap();
        prepare_previous_builds(&root, "r2o-previous").unwrap();
        assert_eq!(rollback(&root).unwrap().current, "r2o-previous");
        assert!(!archive.exists());
        let controller = active_component_path(&root, "r2o-controller").unwrap();
        assert_eq!(fs::read(&controller).unwrap(), controller_bytes);
        let inode = fs::metadata(&controller).unwrap().ino();
        for name in [
            "r2o-fetch",
            "r2o-detect",
            "r2o-telegram",
            "r2o-panel",
            "r2o-manager",
        ] {
            assert_eq!(
                fs::metadata(active_component_path(&root, name).unwrap())
                    .unwrap()
                    .ino(),
                inode
            );
        }
    }

    #[test]
    fn activation_prunes_old_releases_and_stale_install_artifacts() {
        let temp = TestDir::new();
        let root = temp.0.join("install");
        fs::create_dir_all(root.join("releases")).unwrap();
        fs::create_dir_all(root.join(".install-999-0")).unwrap();
        fs::create_dir_all(root.join("releases/.staging-dead-999-0")).unwrap();
        fs::write(root.join(".release-slots.999-0"), "junk").unwrap();
        // Чужой каталог без release-id не принадлежит установщику.
        fs::create_dir_all(root.join("releases/foreign")).unwrap();
        // Старый выпуск с корректной меткой обязан быть вычищен.
        fs::create_dir_all(root.join("releases/r2o-old")).unwrap();
        fs::write(root.join("releases/r2o-old/release-id"), "r2o-old").unwrap();

        let one = bundle(&temp.0, "one", "mipsel");
        let two = bundle(&temp.0, "two", "mipsel");
        let three = bundle(&temp.0, "three", "mipsel");
        activate_bundle(&root, &one, "r2o-1", "mipsel").unwrap();
        assert!(!root.join(".install-999-0").exists());
        assert!(!root.join("releases/.staging-dead-999-0").exists());
        assert!(!root.join(".release-slots.999-0").exists());
        assert!(!root.join("releases/r2o-old").exists());
        assert!(root.join("releases/foreign").exists());

        activate_bundle(&root, &two, "r2o-2", "mipsel").unwrap();
        activate_bundle(&root, &three, "r2o-3", "mipsel").unwrap();
        assert!(!root.join("releases/r2o-1").exists());
        assert!(root.join("releases/r2o-2").exists());
        assert!(root.join("releases/r2o-3").exists());

        let rolled = rollback(&root).unwrap();
        assert_eq!(rolled.current, "r2o-2");
        assert_eq!(rolled.previous.as_deref(), Some("r2o-3"));
        assert!(root.join("releases/r2o-3").exists());
        assert!(root.join("releases/foreign").exists());
    }

    #[test]
    fn failed_trial_restores_both_previously_healthy_slots() {
        let temp = TestDir::new();
        let root = temp.0.join("install");
        let first = bundle(&temp.0, "first", "mipsel");
        let second = bundle(&temp.0, "second", "mipsel");
        let trial = bundle(&temp.0, "trial", "mipsel");
        activate_bundle(&root, &first, "r2o-first", "mipsel").unwrap();
        let before = activate_bundle(&root, &second, "r2o-second", "mipsel").unwrap();
        fs::create_dir_all(root.join("state")).unwrap();
        fs::write(root.join("state/update-pending.json"), "{}").unwrap();
        activate_prepared(
            &root,
            &PreparedRelease {
                release_id: "r2o-trial".to_owned(),
                architecture: "mipsel".to_owned(),
                bundle: trial,
                work: root.join("prepared"),
            },
        )
        .unwrap();
        assert!(root.join("releases/r2o-first").exists());

        restore_update_slots(&root, "r2o-trial", &before).unwrap();
        assert_eq!(read_install_slots(&root).unwrap(), Some(before));
        cleanup_releases(&root).unwrap();
        assert!(root.join("releases/r2o-first").exists());
        assert!(root.join("releases/r2o-second").exists());
        assert!(!root.join("releases/r2o-trial").exists());
    }

    #[test]
    fn activation_keeps_two_releases_and_rollback_swaps_them() {
        let temp = TestDir::new();
        let bundle_one = bundle(&temp.0, "one", "mipsel");
        let bundle_two = bundle(&temp.0, "two", "mipsel");
        let root = temp.0.join("install");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("config"), "operator config\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                bundle_one.join("preserved.txt"),
                fs::Permissions::from_mode(0o4755),
            )
            .unwrap();
        }

        let first = activate_bundle(&root, &bundle_one, "r2o-1", "mipsel").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let launcher = fs::metadata(root.join("r2o-manager")).unwrap();
            let component =
                fs::metadata(root.join("releases/r2o-1/builds/r2o-manager-linux-mipsel")).unwrap();
            assert_eq!(
                (launcher.dev(), launcher.ino()),
                (component.dev(), component.ino())
            );
        }
        assert_eq!(
            read_install_architecture(&root).unwrap().as_deref(),
            Some("mipsel")
        );
        assert_eq!(
            fs::read_to_string(root.join("r2o-manager")).unwrap(),
            "one:r2o-manager"
        );
        assert_eq!(
            fs::read_to_string(active_component_path(&root, "r2o-datapath").unwrap()).unwrap(),
            "one:r2o-datapath"
        );
        assert!(matches!(
            active_component_path(&root, "../r2o-datapath"),
            Err(InstallError::InvalidComponent)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                fs::metadata(root.join("r2o-manager"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
        assert_eq!(
            first,
            InstallSlots {
                current: "r2o-1".into(),
                previous: None
            }
        );
        let second = activate_bundle(&root, &bundle_two, "r2o-2", "mipsel").unwrap();
        assert_eq!(
            fs::read_to_string(root.join("r2o-manager")).unwrap(),
            "two:r2o-manager"
        );
        assert_eq!(
            second,
            InstallSlots {
                current: "r2o-2".into(),
                previous: Some("r2o-1".into())
            }
        );
        let rolled = rollback(&root).unwrap();
        assert_eq!(
            read_install_architecture(&root).unwrap().as_deref(),
            Some("mipsel")
        );
        assert_eq!(
            rolled,
            InstallSlots {
                current: "r2o-1".into(),
                previous: Some("r2o-2".into())
            }
        );
        assert_eq!(
            fs::read_to_string(root.join("config")).unwrap(),
            "operator config\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("releases/r2o-2/preserved.txt")).unwrap(),
            "release payload"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(root.join("releases/r2o-1/preserved.txt"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, 0o755);
        }
    }

    #[test]
    fn auxiliary_detect_component_is_optional_and_available_when_present() {
        let temp = TestDir::new();
        let root = temp.0.join("install");
        let with_detect = bundle(&temp.0, "with-detect", "mipsel");
        let detect = with_detect.join("builds/r2o-detect-linux-mipsel");
        fs::write(&detect, b"detect-binary").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&detect, fs::Permissions::from_mode(0o755)).unwrap();
        }
        activate_bundle(&root, &with_detect, "r2o-with-detect", "mipsel").unwrap();
        assert_eq!(
            fs::read_to_string(active_component_path(&root, "r2o-detect").unwrap()).unwrap(),
            "detect-binary"
        );

        // Старый выпуск без r2o-detect обязан активироваться без изменений.
        let legacy = bundle(&temp.0, "legacy", "mipsel");
        activate_bundle(&root, &legacy, "r2o-legacy", "mipsel").unwrap();
        assert!(matches!(
            active_component_path(&root, "r2o-detect"),
            Err(InstallError::MissingComponent(name)) if name == "r2o-detect"
        ));
    }

    #[test]
    fn concurrent_manager_lock_still_returns_busy_after_retry_window() {
        let temp = TestDir::new();
        let root = temp.0.join("install");
        fs::create_dir_all(&root).unwrap();
        let _held = ManagerLock::acquire(&root).unwrap();
        let started = std::time::Instant::now();
        assert!(matches!(
            ManagerLock::acquire(&root),
            Err(InstallError::Busy)
        ));
        // 50 попыток с паузой 2 мс: ложный EAGAIN успевает исчезнуть, а
        // настоящий параллельный владелец всё равно получает Busy.
        assert!(started.elapsed() >= std::time::Duration::from_millis(90));
    }

    #[test]
    fn update_reactivates_an_installed_latest_release_after_rollback() {
        let temp = TestDir::new();
        let bundle_one = bundle(&temp.0, "one", "mipsel");
        let bundle_two = bundle(&temp.0, "two", "mipsel");
        let root = temp.0.join("install");
        activate_bundle(&root, &bundle_one, "r2o-1", "mipsel").unwrap();
        activate_bundle(&root, &bundle_two, "r2o-2", "mipsel").unwrap();
        rollback(&root).unwrap();

        assert!(
            activate_previous_release(&root, "r2o-3", "mipsel")
                .unwrap()
                .is_none()
        );
        assert_eq!(read_install_slots(&root).unwrap().unwrap().current, "r2o-1");
        assert_eq!(
            activate_previous_release(&root, "r2o-2", "mipsel").unwrap(),
            Some(InstallSlots {
                current: "r2o-2".into(),
                previous: Some("r2o-1".into()),
            })
        );
    }

    #[test]
    fn incomplete_bundle_does_not_change_active_release() {
        let temp = TestDir::new();
        let root = temp.0.join("install");
        let good = bundle(&temp.0, "good", "mipsel");
        let bad = temp.0.join("bundle-bad");
        fs::create_dir_all(bad.join("builds")).unwrap();
        for component in MANAGER_COMPONENTS
            .into_iter()
            .filter(|name| *name != "r2o-manager")
        {
            let path = bad.join("builds").join(format!("{component}-linux-mipsel"));
            fs::write(&path, b"binary").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        activate_bundle(&root, &good, "r2o-good", "mipsel").unwrap();
        assert!(matches!(
            activate_bundle(&root, &bad, "r2o-bad", "mipsel"),
            Err(InstallError::MissingComponent(name)) if name == "r2o-manager-linux-mipsel"
        ));
        assert_eq!(
            read_install_slots(&root).unwrap().unwrap().current,
            "r2o-good"
        );
        assert!(!root.join("releases/r2o-bad").exists());
    }

    #[test]
    fn rejects_unsafe_release_ids_and_bundle_symlinks() {
        let temp = TestDir::new();
        let root = temp.0.join("install");
        let valid = bundle(&temp.0, "valid", "mipsel");
        assert!(matches!(
            activate_bundle(&root, &valid, "../escape", "mipsel"),
            Err(InstallError::InvalidReleaseId)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(
                valid.join("builds/r2o-datapath-linux-mipsel"),
                valid.join("linked-file"),
            )
            .unwrap();
            assert!(matches!(
                activate_bundle(&root, &valid, "r2o-symlink", "mipsel"),
                Err(InstallError::UnsafeBundleEntry(_))
            ));
        }
    }

    #[test]
    fn rejects_rollback_when_no_previous_slot_exists() {
        let temp = TestDir::new();
        let root = temp.0.join("empty");
        assert!(matches!(
            rollback(&root),
            Err(InstallError::NoPreviousRelease)
        ));
    }

    #[test]
    fn prepared_archive_does_not_change_slots_until_activated() {
        let temp = TestDir::new();
        let root = temp.0.join("install");
        let archive_path = temp.0.join("release.tar.gz");
        let (archive, manifest, signature, public_key) = signed_archive();
        fs::write(&archive_path, archive).unwrap();

        let prepared = prepare_archive(
            &root,
            &archive_path,
            &manifest,
            &signature,
            &public_key,
            "mipsel",
        )
        .unwrap();
        assert_eq!(prepared.release_id, "r2o-archive-1");
        assert_eq!(read_install_slots(&root).unwrap(), None);
        assert!(
            prepared
                .bundle
                .join("builds/r2o-datapath-linux-mipsel")
                .is_file()
        );

        let slots = activate_prepared(&root, &prepared).unwrap();
        assert_eq!(slots.current, "r2o-archive-1");
        assert_eq!(slots.previous, None);
        assert_eq!(
            read_install_slots(&root).unwrap().unwrap().current,
            "r2o-archive-1"
        );
        prepared.discard();
        assert!(!prepared.work.exists());
    }

    #[test]
    fn signed_archive_is_verified_extracted_and_activated() {
        let temp = TestDir::new();
        let root = temp.0.join("install");
        let archive_path = temp.0.join("release.tar.gz");
        let (archive, manifest, signature, public_key) = signed_archive();
        fs::write(&archive_path, archive).unwrap();

        let slots = install_archive(
            &root,
            &archive_path,
            &manifest,
            &signature,
            &public_key,
            "mipsel",
        )
        .unwrap();
        assert_eq!(slots.current, "r2o-archive-1");
        assert_eq!(slots.previous, None);
        assert_eq!(
            fs::read_to_string(
                root.join("releases/r2o-archive-1/builds/r2o-datapath-linux-mipsel")
            )
            .unwrap(),
            "fixture:r2o-datapath"
        );
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".install-")
        }));
    }

    #[test]
    fn archive_hash_mismatch_never_changes_active_release() {
        let temp = TestDir::new();
        let root = temp.0.join("install");
        let archive_path = temp.0.join("release.tar.gz");
        let (mut archive, manifest, signature, public_key) = signed_archive();
        archive[0] ^= 1;
        fs::write(&archive_path, archive).unwrap();

        assert!(matches!(
            install_archive(
                &root,
                &archive_path,
                &manifest,
                &signature,
                &public_key,
                "mipsel"
            ),
            Err(InstallError::Verification(
                VerifyError::ArchiveDigestMismatch { .. }
            ))
        ));
        assert!(read_install_slots(&root).unwrap().is_none());
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".install-")
        }));
    }

    #[test]
    fn signed_traversal_entry_is_rejected_before_activation() {
        let temp = TestDir::new();
        let root = temp.0.join("install");
        let archive_path = temp.0.join("release.tar.gz");
        let (archive, _, _, _) = signed_archive();
        let archive = replace_first_archive_path(&archive, "../escaped");
        let (archive, manifest, signature, public_key) = sign_archive(archive);
        fs::write(&archive_path, archive).unwrap();

        assert!(matches!(
            install_archive(
                &root,
                &archive_path,
                &manifest,
                &signature,
                &public_key,
                "mipsel"
            ),
            Err(InstallError::InvalidArchive(_))
        ));
        assert!(!temp.0.join("escaped").exists());
        assert!(read_install_slots(&root).unwrap().is_none());
    }
}
