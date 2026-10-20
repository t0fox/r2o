//! Постоянная локальная идентичность установки без сетевой регистрации.

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const FILE_SIZE: usize = 88;
const MAGIC: &[u8; 8] = b"R2OTGID1";

/// Локальная идентичность установки.
pub struct Identity {
    install_id: [u8; 16],
    private_seed: [u8; 32],
    public_key: [u8; 32],
}

impl Identity {
    pub fn load_or_mint(path: &Path) -> Result<Self, String> {
        match Self::load(path) {
            Ok(identity) => Ok(identity),
            Err(LoadError::Missing) => Self::mint(path),
            Err(LoadError::Invalid(message)) => Err(message),
        }
    }

    pub fn install_id_hex(&self) -> String {
        hex::encode(self.install_id)
    }

    fn load(path: &Path) -> Result<Self, LoadError> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(LoadError::Missing);
            }
            Err(error) => {
                return Err(LoadError::Invalid(format!(
                    "не удалось открыть файл идентичности {}: {error}",
                    path.display()
                )));
            }
        };
        let metadata = file.metadata().map_err(|error| {
            LoadError::Invalid(format!(
                "не удалось проверить файл идентичности {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(invalid_file(path, "ожидается обычный файл"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // `geteuid` предоставляется libc на поддерживаемых Unix-маршрутизаторах.
            let owner = unsafe { libc::geteuid() };
            if metadata.mode() & 0o077 != 0 || metadata.uid() != owner {
                return Err(invalid_file(
                    path,
                    "небезопасные права доступа или неверный владелец",
                ));
            }
        }
        if metadata.len() != FILE_SIZE as u64 {
            return Err(invalid_file(path, "неверный размер файла идентичности"));
        }

        let mut raw = [0_u8; FILE_SIZE];
        file.read_exact(&mut raw).map_err(|error| {
            LoadError::Invalid(format!(
                "не удалось прочитать файл идентичности {}: {error}",
                path.display()
            ))
        })?;
        if &raw[..8] != MAGIC {
            raw.zeroize();
            return Err(invalid_file(path, "неверная сигнатура файла идентичности"));
        }
        let mut install_id = [0_u8; 16];
        install_id.copy_from_slice(&raw[8..24]);
        let mut private_seed = [0_u8; 32];
        private_seed.copy_from_slice(&raw[24..56]);
        let mut public_key = [0_u8; 32];
        public_key.copy_from_slice(&raw[56..88]);
        raw.zeroize();

        let key = Ed25519KeyPair::from_seed_unchecked(&private_seed)
            .map_err(|_| invalid_file(path, "неверный закрытый ключ Ed25519"))?;
        if key.public_key().as_ref() != public_key {
            private_seed.zeroize();
            return Err(invalid_file(path, "закрытый и открытый ключи не совпадают"));
        }
        Ok(Self {
            install_id,
            private_seed,
            public_key,
        })
    }

    fn mint(path: &Path) -> Result<Self, String> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "не удалось создать каталог идентичности {}: {error}",
                parent.display()
            )
        })?;
        let random = SystemRandom::new();
        let mut install_id = [0_u8; 16];
        let mut private_seed = [0_u8; 32];
        random
            .fill(&mut install_id)
            .and_then(|()| random.fill(&mut private_seed))
            .map_err(|_| "защищённый генератор случайных чисел недоступен".to_string())?;
        let key = Ed25519KeyPair::from_seed_unchecked(&private_seed)
            .map_err(|_| "не удалось создать ключ идентичности Ed25519".to_string())?;
        let mut public_key = [0_u8; 32];
        public_key.copy_from_slice(key.public_key().as_ref());
        let identity = Self {
            install_id,
            private_seed,
            public_key,
        };

        let mut raw = [0_u8; FILE_SIZE];
        raw[..8].copy_from_slice(MAGIC);
        raw[8..24].copy_from_slice(&identity.install_id);
        raw[24..56].copy_from_slice(&identity.private_seed);
        raw[56..88].copy_from_slice(&identity.public_key);
        let result = save_no_replace(path, parent, &raw);
        raw.zeroize();
        match result {
            Ok(()) => Ok(identity),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                // При параллельном первом запуске сохраняем ключ процесса-победителя.
                Self::load(path).map_err(|error| match error {
                    LoadError::Missing => {
                        format!("файл идентичности исчез: {}", path.display())
                    }
                    LoadError::Invalid(message) => message,
                })
            }
            Err(error) => Err(format!(
                "не удалось сохранить файл идентичности {}: {error}",
                path.display()
            )),
        }
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.private_seed.zeroize();
    }
}

enum LoadError {
    Missing,
    Invalid(String),
}

fn invalid_file(path: &Path, reason: &str) -> LoadError {
    LoadError::Invalid(format!(
        "{}: {reason}; restore the file or remove it to create a new identity",
        path.display()
    ))
}

fn save_no_replace(path: &Path, parent: &Path, raw: &[u8; FILE_SIZE]) -> io::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "в пути идентичности нет имени файла",
        )
    })?;
    let mut temporary = PathBuf::new();
    let mut file = None;
    for _ in 0..16 {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        temporary = parent.join(format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            id
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        match options.open(&temporary) {
            Ok(opened) => {
                file = Some(opened);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let mut file = file.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "не удалось создать временный файл идентичности",
        )
    })?;
    let write_result = file.write_all(raw).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    fs::remove_file(&temporary)?;
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_path() -> PathBuf {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("r2o-identity-{}-{id}", std::process::id()))
    }

    #[test]
    fn identity_is_stable_and_private_file_is_protected() {
        let path = temp_path();
        let identity = Identity::load_or_mint(&path).unwrap();
        let reloaded = Identity::load_or_mint(&path).unwrap();
        assert_eq!(identity.install_id_hex(), reloaded.install_id_hex());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn invalid_existing_identity_is_preserved() {
        let path = temp_path();
        fs::write(&path, b"not an identity").unwrap();
        let before = fs::read(&path).unwrap();
        assert!(Identity::load_or_mint(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        let _ = fs::remove_file(path);
    }
}
