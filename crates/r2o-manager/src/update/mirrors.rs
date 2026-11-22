use super::*;

pub(super) fn cache_path(root: &Path, digest: &str) -> Result<PathBuf, UpdateError> {
    let directory = root.join("state/update-download");
    match fs::create_dir(&directory) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
            }
            crate::install::sync_directory(&directory)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(&directory)?.is_dir() {
                return Err(io::Error::other("небезопасный каталог загрузки").into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    let archive = directory.join(digest);
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.path() != archive && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    if let Ok(meta) = fs::symlink_metadata(&archive) {
        if !meta.is_file() {
            return Err(io::Error::other("небезопасный файл загрузки").into());
        }
    }
    Ok(archive)
}

pub(super) struct Route {
    name: &'static str,
    prefix: String,
    r2: bool,
}

impl Route {
    fn url(&self, github: &str) -> String {
        if self.r2 {
            format!(
                "{}/{}",
                self.prefix,
                github
                    .strip_prefix(DOWNLOAD_URL)
                    .expect("адрес ресурса")
                    .trim_start_matches('/')
            )
        } else {
            format!("{}{github}", self.prefix)
        }
    }
}

pub(super) fn routes(
    manifest: &crate::ReleaseManifest,
    preferred: Option<&str>,
) -> Result<Vec<Route>, UpdateError> {
    let mut routes = vec![Route {
        name: "github",
        prefix: String::new(),
        r2: false,
    }];
    if let Some(url) = manifest
        .metadata
        .as_ref()
        .and_then(|meta| meta.r2_url.as_ref())
    {
        let url = url.trim_end_matches('/');
        let (_, path) = parse_https_url(url)?;
        if path.contains(['?', '#', '%']) || path.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(catalog::invalid("недопустимый URL зеркала R2"));
        }
        routes.push(Route {
            name: "r2",
            prefix: url.to_owned(),
            r2: true,
        });
    }
    for (name, prefix) in [
        ("gh-proxy", "https://gh-proxy.com/"),
        ("ghproxy", "https://ghproxy.net/"),
        ("ghfast", "https://ghfast.top/"),
    ] {
        routes.push(Route {
            name,
            prefix: prefix.to_owned(),
            r2: false,
        });
    }
    if let Some(source) = preferred.filter(|source| *source != "auto") {
        let index = routes
            .iter()
            .position(|route| route.name == source)
            .ok_or_else(|| io::Error::other("неизвестный источник загрузки"))?;
        routes.swap(0, index);
    }
    Ok(routes)
}

pub(super) fn metadata(
    routes: &[Route],
    url: &str,
    body: &Path,
    signature: &Path,
    expected: &crate::ReleaseManifest,
) -> Result<(Vec<u8>, Vec<u8>), UpdateError> {
    let mut last = catalog::invalid("манифест недоступен");
    for route in routes {
        let result = (|| {
            download(&route.url(url), body, MANIFEST_MAX_BYTES, "10")?;
            download(
                &route.url(&format!("{url}.sig")),
                signature,
                SIGNATURE_MAX_BYTES,
                "10",
            )?;
            let bytes = read_bounded(body, MANIFEST_MAX_BYTES)?;
            let sig = read_bounded(signature, SIGNATURE_MAX_BYTES)?;
            if verify_manifest(&bytes, &sig, PUBLIC_KEY)? != *expected {
                return Err(catalog::invalid(
                    "манифест отличается от подписанного каталога",
                ));
            }
            Ok((bytes, sig))
        })();
        let _ = fs::remove_file(body);
        let _ = fs::remove_file(signature);
        match result {
            Ok(pair) => return Ok(pair),
            Err(error) => last = error,
        }
    }
    Err(last)
}

pub(super) fn archive(
    routes: &[Route],
    url: &str,
    destination: &Path,
    asset: &crate::ReleaseAsset,
    root: &Path,
    state: &mut Value,
    preferred: Option<&str>,
) -> Result<(), UpdateError> {
    let total = asset
        .bytes
        .ok_or_else(|| catalog::invalid("размер архива не подписан"))?;
    let expanded = asset
        .expanded
        .ok_or_else(|| catalog::invalid("размер распаковки не подписан"))?;
    let mut existing = fs::metadata(destination).map_or(0, |meta| meta.len());
    if existing >= total {
        if existing == total
            && crate::verify_archive(&mut File::open(destination)?, &asset.sha256).is_ok()
        {
            require_space(root, expanded + 1024 * 1024)?;
            return Ok(());
        }
        fs::remove_file(destination)?;
        existing = 0;
    }
    require_space(root, total - existing + expanded + 1024 * 1024)?;
    let mut order = std::thread::scope(|scope| {
        let attempts: Vec<_> = routes
            .iter()
            .map(|route| {
                let request = route.url(url);
                let result = scope.spawn(move || {
                    let start = Instant::now();
                    let available = download_rust(
                        &request,
                        destination,
                        total,
                        "7",
                        &[],
                        RequestKind::Probe(total),
                    )
                    .is_ok();
                    (!available, start.elapsed(), route)
                });
                result
            })
            .collect();
        attempts
            .into_iter()
            .map(|handle| handle.join().expect("проба источника"))
            .collect::<Vec<_>>()
    });
    order.sort_by_key(|(failed, elapsed, route)| {
        (
            preferred.is_none_or(|source| source != route.name),
            *failed,
            *elapsed,
        )
    });
    let mut attempts = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(600);
    for (_, _, route) in order {
        for _ in 0..2 {
            if read_cancel(root)? {
                return Err(cancelled());
            }
            state["transfer"] = transfer(
                route.name,
                total,
                fs::metadata(destination).map_or(0, |m| m.len()),
                0,
            );
            write_state(root, state)?;
            let remaining = deadline.saturating_duration_since(Instant::now()).as_secs();
            if remaining == 0 {
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "истёк срок загрузки архива").into(),
                );
            }
            let result = download_rust(
                &route.url(url),
                destination,
                total,
                &remaining.min(90).to_string(),
                &[],
                RequestKind::Archive {
                    total,
                    root,
                    source: route.name,
                },
            );
            if fs::metadata(destination).is_ok_and(|m| m.len() == total) {
                if result.is_ok()
                    && crate::verify_archive(&mut File::open(destination)?, &asset.sha256).is_ok()
                {
                    state["transfer"] = transfer(route.name, total, total, 0);
                    return Ok(());
                }
                fs::remove_file(destination)?;
            }
            let cause = result.err().map_or_else(
                || "SHA-256 не совпадает".to_owned(),
                |error| error.to_string(),
            );
            attempts.push(format!("{}: {cause}", route.name));
        }
    }
    Err(UpdateError::Download(attempts.join("; ")))
}

#[cfg(unix)]
pub(super) fn require_space(root: &Path, required: u64) -> Result<(), UpdateError> {
    use std::os::fd::AsRawFd;
    let directory = File::open(root)?;
    let mut data = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let data = unsafe { data.assume_init() };
    let free = u128::from(data.f_bavail) * u128::from(data.f_frsize);
    if free < u128::from(required) {
        return Err(io::Error::other(format!(
            "мало места: нужно {required} байт, доступно {free}"
        ))
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_space(_root: &Path, _required: u64) -> Result<(), UpdateError> {
    Err(io::Error::other("обновление поддерживается на Unix").into())
}

fn transfer(source: &str, total: u64, done: u64, speed: u64) -> Value {
    json!({"source":source,"bytes":done,"total":total,"speed":speed,
        "eta":total.saturating_sub(done).checked_div(speed)})
}

pub(super) struct Progress<'a> {
    pub(super) file: File,
    kind: RequestKind<'a>,
    offset: u64,
    last_offset: u64,
    updated: Instant,
}

impl<'a> Progress<'a> {
    pub(super) fn new(file: File, kind: RequestKind<'a>, offset: u64) -> Self {
        Self {
            file,
            kind,
            offset,
            last_offset: offset,
            updated: Instant::now(),
        }
    }
}

impl Write for Progress<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let RequestKind::Archive {
            total,
            root,
            source,
        } = self.kind
        {
            let elapsed = self.updated.elapsed().as_secs();
            if elapsed > 0 {
                if read_cancel(root).map_err(io::Error::other)? {
                    return Err(io::Error::other("Обновление отменено"));
                }
                let speed = (self.offset - self.last_offset) / elapsed;
                write_json(
                    root,
                    "update-transfer.json",
                    &transfer(source, total, self.offset, speed),
                )
                .map_err(io::Error::other)?;
                self.last_offset = self.offset;
                self.updated = Instant::now();
            }
        }
        let count = self.file.write(bytes)?;
        self.offset += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn disk_preflight_refuses_an_impossible_reservation() {
        let tmp = super::super::tests::TestDir::new();
        assert!(require_space(&tmp.0, 0).is_ok());
        assert!(require_space(&tmp.0, u64::MAX).is_err());
    }
}
