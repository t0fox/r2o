use super::{
    ARCHIVE_MAX_BYTES, ARCHIVE_MAX_ENTRIES, ARCHIVE_MAX_ENTRY_BYTES, ARCHIVE_MAX_EXPANDED_BYTES,
    InstallError, create_staging_dir, extract_bundle, read_release_architecture, sync_directory,
    validate_archive_path, validate_bundle,
};
use lzma_rust2::{XzOptions, XzReader, XzWriter};
use std::fs::{self, File, Metadata};
use std::io::{self, BufReader, BufWriter, Read};
use std::path::Path;

pub(super) const ARCHIVE: &str = ".rollback-builds.tar.xz";
const DICTIONARY_BYTES: u32 = 2 * 1024 * 1024;
const DECODE_LIMIT_KIB: u32 = DICTIONARY_BYTES / 1024 + 128;

pub(super) fn compact(root: &Path, id: &str) -> Result<(), InstallError> {
    let releases = root.join("releases");
    let release = releases.join(id);
    let builds = release.join("builds");
    match fs::symlink_metadata(&builds) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(InstallError::UnsafeBundleEntry(builds)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let architecture = read_release_architecture(root, id)?;
    let controller = fs::metadata(builds.join(format!("r2o-controller-linux-{architecture}")))?;
    let options = compression_options(&architecture)?;
    let stage = create_staging_dir(&releases, id)?;
    let result = (|| {
        let temporary = stage.join(ARCHIVE);
        let encoder = XzWriter::new(BufWriter::new(File::create(&temporary)?), options)?;
        let mut tar = tar::Builder::new(encoder);
        let mut raw_bytes = 0u64;
        for (index, entry) in fs::read_dir(&builds)?.enumerate() {
            let entry = entry?;
            let meta = entry.metadata()?;
            let name = entry.file_name();
            let path = Path::new("builds").join(&name);
            if index >= ARCHIVE_MAX_ENTRIES
                || !meta.is_file()
                || meta.len() == 0
                || meta.len() > ARCHIVE_MAX_ENTRY_BYTES
                || validate_archive_path(&path).is_err()
            {
                return Ok(());
            }
            if is_applet(&name, &architecture) && same_file(&meta, &controller) {
                // Пустая запись сохраняет имя ссылки без второй копии ELF.
                let mut header = tar::Header::new_gnu();
                header.set_mode(0o755);
                header.set_size(0);
                tar.append_data(&mut header, path, io::empty())?;
            } else {
                raw_bytes = raw_bytes.saturating_add(meta.len());
                if raw_bytes > ARCHIVE_MAX_EXPANDED_BYTES {
                    return Ok(());
                }
                tar.append_path_with_name(entry.path(), path)?;
            }
        }
        let packed = tar
            .into_inner()?
            .finish()?
            .into_inner()
            .map_err(|error| error.into_error())?;
        if packed.metadata()?.len() >= raw_bytes {
            return Ok(());
        }
        packed.sync_all()?;
        fs::rename(temporary, release.join(ARCHIVE))?;
        sync_directory(&release)?;
        // После сбоя доступна либо вся исходная папка, либо уже записанный архив.
        fs::rename(&builds, stage.join("builds"))?;
        sync_directory(&release)?;
        Ok(())
    })();
    let _ = fs::remove_dir_all(stage);
    result
}

fn compression_options(architecture: &str) -> io::Result<XzOptions> {
    let mut options = XzOptions::with_preset(4);
    options.lzma_options.dict_size = DICTIONARY_BYTES;
    #[cfg(target_os = "linux")]
    if let Some(available_kib) = fs::read_to_string("/proc/meminfo")
        .ok()
        .as_deref()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("MemAvailable:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u32>()
                    .ok()
            })
        })
    {
        // Оставляем работающим службам запас сверх памяти кодировщика.
        let budget = available_kib.saturating_sub(8192);
        if options.lzma_options.get_memory_usage() > budget {
            options = XzOptions::with_preset(1);
        }
        if options.lzma_options.get_memory_usage() > budget {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "недостаточно RAM для сжатия резервного слота",
            ));
        }
    }
    if architecture == "aarch64-openwrt-musl" {
        options.prepend_pre_filter(lzma_rust2::FilterType::BcjArm64, 0);
    }
    Ok(options)
}

pub(super) fn restore(root: &Path, id: &str) -> Result<(), InstallError> {
    let releases = root.join("releases");
    let release = releases.join(id);
    let builds = release.join("builds");
    let packed = release.join(ARCHIVE);
    match fs::symlink_metadata(&builds) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => return Err(InstallError::UnsafeBundleEntry(builds)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(&packed)?;
    if !metadata.is_file() || metadata.len() > ARCHIVE_MAX_BYTES {
        return Err(InstallError::InvalidArchive(
            "некорректный архив отката".into(),
        ));
    }
    let architecture = read_release_architecture(root, id)?;
    let stage = create_staging_dir(&releases, id)?;
    let result = (|| {
        let decoder = XzReader::new_mem_limit(
            BufReader::new(File::open(&packed)?),
            false,
            DECODE_LIMIT_KIB,
        );
        let decoder = extract_bundle(decoder, &stage, ARCHIVE_MAX_EXPANDED_BYTES)?;
        // Дочитываем XZ для проверки контрольной суммы и ограничиваем хвост tar.
        if io::copy(&mut decoder.take(16 * 1024), &mut io::sink())? == 16 * 1024 {
            return Err(InstallError::InvalidArchive(
                "слишком длинное заполнение в архиве отката".into(),
            ));
        }
        let staged_builds = stage.join("builds");
        let controller = staged_builds.join(format!("r2o-controller-linux-{architecture}"));
        for entry in fs::read_dir(&staged_builds)? {
            let entry = entry?;
            let path = entry.path();
            if entry.metadata()?.len() == 0 && is_applet(&entry.file_name(), &architecture) {
                fs::remove_file(&path)?;
                if fs::hard_link(&controller, &path).is_err() {
                    fs::copy(&controller, &path)?;
                }
            }
            File::open(path)?.sync_all()?;
        }
        validate_bundle(&stage, &architecture)?;
        sync_directory(&staged_builds)?;
        fs::rename(staged_builds, builds)?;
        sync_directory(&release)?;
        fs::remove_file(packed)?;
        sync_directory(&release)?;
        Ok(())
    })();
    let _ = fs::remove_dir_all(stage);
    result
}

fn is_applet(name: &std::ffi::OsStr, architecture: &str) -> bool {
    ["r2o-fetch", "r2o-detect", "r2o-telegram"]
        .iter()
        .any(|applet| name == std::ffi::OsStr::new(&format!("{applet}-linux-{architecture}")))
}

#[cfg(unix)]
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (a.dev(), a.ino()) == (b.dev(), b.ino())
}

#[cfg(not(unix))]
fn same_file(_a: &Metadata, _b: &Metadata) -> bool {
    false
}
