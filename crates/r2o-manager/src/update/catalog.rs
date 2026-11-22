use super::*;

const API_LATEST: &str = "https://api.github.com/repos/t0fox/r2o/releases/latest";
const LATEST_CATALOG: &str = "https://github.com/t0fox/r2o/releases/latest/download/catalog.json";
pub(super) const CATALOG_MAX: u64 = 1024 * 1024;

pub(super) struct Catalog {
    pub(super) releases: Vec<crate::ReleaseManifest>,
}

pub(super) fn fetch(work: &Path, root: &Path, architecture: &str) -> Result<Catalog, UpdateError> {
    let mirror = read_install_slots(root)?.and_then(|slots| {
        let file = root
            .join("releases")
            .join(slots.current)
            .join("router/update-r2");
        let bytes = read_bounded(&file, 512).ok()?;
        let url = String::from_utf8(bytes)
            .ok()?
            .trim()
            .trim_end_matches('/')
            .to_owned();
        (!url.is_empty() && parse_https_url(&url).is_ok()).then_some(url)
    });
    let published = github_latest(work);
    let tag = match (&published, &mirror) {
        (Ok(tag), _) => tag.clone(),
        (Err(_), Some(mirror)) => {
            let path = work.join("mirror-head");
            download(&format!("{mirror}/latest"), &path, 256, "12")?;
            String::from_utf8(read_bounded(&path, 256)?)
                .map_err(io::Error::other)?
                .trim()
                .to_owned()
        }
        (Err(error), None) => return Err(io::Error::other(error.to_string()).into()),
    };
    crate::validate_token(&tag, "release_id", 128)?;
    let github = format!("{DOWNLOAD_URL}/{tag}/catalog.json");
    let mirrors = [
        published.is_ok().then(|| github.clone()),
        mirror
            .as_ref()
            .map(|base| format!("{base}/{tag}/catalog.json")),
        published
            .is_ok()
            .then(|| format!("https://gh-proxy.com/{github}")),
        published
            .is_ok()
            .then(|| format!("https://ghproxy.net/{github}")),
        published
            .is_ok()
            .then(|| format!("https://ghfast.top/{github}")),
    ];
    let body = work.join("catalog.json");
    let signature = work.join("catalog.json.sig");
    let mut verified = Err(invalid("подписанный каталог не загружен"));
    for url in mirrors.iter().flatten() {
        verified = (|| {
            download(url, &body, CATALOG_MAX, "15")?;
            download(&format!("{url}.sig"), &signature, SIGNATURE_MAX_BYTES, "15")?;
            let bytes = read_bounded(&body, CATALOG_MAX)?;
            let sig = read_bounded(&signature, SIGNATURE_MAX_BYTES)?;
            decode(&bytes, &sig, PUBLIC_KEY, &tag)
        })();
        if verified.is_ok() {
            break;
        }
        let _ = fs::remove_file(&body);
        let _ = fs::remove_file(&signature);
    }
    let result = verified?;
    let latest = result
        .releases
        .first()
        .expect("проверенный каталог содержит последнее издание");
    let sequence = latest.sequence();
    let marker = read_bounded(&root.join("state/update-catalog-head.json"), 1024);
    let state: Value = match marker {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other)?,
        Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => json!({}),
        Err(error) => return Err(error),
    };
    let high = state["catalog_sequence"].as_u64().unwrap_or(0);
    if let Some(slots) = read_install_slots(root)? {
        let seq_path = root
            .join("releases")
            .join(&slots.current)
            .join("router/update-sequence");
        let sequence_min = std::str::from_utf8(&read_bounded(&seq_path, 32)?)
            .map_err(io::Error::other)?
            .trim()
            .parse::<u64>()
            .map_err(io::Error::other)?;
        if sequence < sequence_min {
            return Err(invalid("каталог старше установленного выпуска"));
        }
    }
    if sequence < high || sequence == high && state["catalog_tag"] != tag {
        return Err(invalid(
            "опубликованный каталог старше последнего проверенного",
        ));
    }
    write_json(
        root,
        "update-catalog-head.json",
        &json!({"catalog_sequence":sequence,"catalog_tag":tag}),
    )?;
    let releases: Vec<_> = result
        .releases
        .into_iter()
        .filter(|manifest| manifest.assets.contains_key(architecture))
        .collect();
    if releases.is_empty() {
        return Err(VerifyError::UnknownArchitecture(architecture.to_owned()).into());
    }
    let public: Vec<_> = releases
        .iter()
        .map(|manifest| describe(manifest, architecture))
        .collect();
    write_json(root, "update-catalog.json", &json!({"releases":public}))?;
    Ok(Catalog { releases })
}

fn github_latest(work: &Path) -> Result<String, UpdateError> {
    github_latest_from_api(work).or_else(|api_error| {
        // GitHub привязывает latest/download к тегу стабильного выпуска до выдачи файла.
        let tag = download_rust(
            LATEST_CATALOG,
            &work.join("github-redirect"),
            0,
            "10",
            &[],
            RequestKind::Redirect,
        )
        .and_then(|location| {
            let location = location.ok_or_else(|| invalid("GitHub не перенаправил на каталог"))?;
            tag_from_catalog_redirect(&location)
        });
        tag.map_err(|redirect_error| {
            UpdateError::Download(format!(
                "GitHub API: {api_error}; GitHub Releases: {redirect_error}"
            ))
        })
    })
}

fn github_latest_from_api(work: &Path) -> Result<String, UpdateError> {
    let reply = work.join("github.json");
    download(API_LATEST, &reply, CATALOG_MAX, "13")?;
    let github: Value =
        serde_json::from_slice(&read_bounded(&reply, CATALOG_MAX)?).map_err(io::Error::other)?;
    let tag = github["tag_name"]
        .as_str()
        .ok_or_else(|| invalid("GitHub не вернул тег выпуска"))?;
    if github["draft"] != false || github["prerelease"] != false {
        return Err(invalid("GitHub вернул черновик или предрелиз"));
    }
    crate::validate_token(tag, "release_id", 128)?;
    Ok(tag.to_owned())
}

fn tag_from_catalog_redirect(location: &str) -> Result<String, UpdateError> {
    let tag = location
        .strip_prefix(DOWNLOAD_URL)
        .and_then(|path| path.strip_prefix('/'))
        .and_then(|path| path.strip_suffix("/catalog.json"))
        .ok_or_else(|| invalid("GitHub не перенаправил на каталог R2O"))?;
    crate::validate_token(tag, "release_id", 128)?;
    Ok(tag.to_owned())
}

fn decode(bytes: &[u8], sig: &[u8], key: &[u8], tag: &str) -> Result<Catalog, UpdateError> {
    crate::verify_signature(bytes, sig, key)?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Raw {
        format: u32,
        releases: Vec<crate::RawManifest>,
    }
    let raw: Raw = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    if raw.format != 1 || raw.releases.is_empty() {
        return Err(invalid("формат каталога не поддерживается"));
    }
    let mut releases = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut previous = u64::MAX;
    for item in raw.releases {
        let manifest = crate::validate_manifest(item)?;
        if manifest.sequence() == 0
            || manifest.sequence() >= previous
            || !seen.insert(manifest.release_id.clone())
        {
            return Err(invalid("повтор или неверный порядок версий в каталоге"));
        }
        previous = manifest.sequence();
        releases.push(manifest);
    }
    if releases[0].release_id != tag {
        return Err(invalid("подпись каталога относится к другому тегу"));
    }
    Ok(Catalog { releases })
}

pub(super) fn describe(manifest: &crate::ReleaseManifest, arch: &str) -> Value {
    let meta = manifest.metadata.as_ref();
    json!({
        "release_id": manifest.release_id, "version": manifest.version, "notes": manifest.notes,
        "title": meta.map(|m| &m.title), "commit": meta.map(|m| &m.commit),
        "created_utc": meta.map(|m| m.created_utc), "sequence": manifest.sequence(),
        "size": manifest.assets.get(arch).and_then(|asset| asset.bytes), "architecture": arch,
        "state_format": meta.map(|m| m.state_format), "config_format": meta.map(|m| m.config_format),
        "sources": if meta.and_then(|m| m.r2_url.as_ref()).is_some() {
            vec!["github","r2","gh-proxy","ghproxy","ghfast"]
        } else { vec!["github","gh-proxy","ghproxy","ghfast"] },
    })
}

pub(super) fn invalid(message: &str) -> UpdateError {
    VerifyError::InvalidManifest(message.to_owned()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn item(id: &str, sequence: u64) -> Value {
        json!({
            "release_id":id,"version":id,"notes":"",
            "metadata":{"format":2,"state_format":1,"config_format":1,"commit":"1".repeat(40),
                "title":id,"sequence":sequence,"created_utc":100,"r2_url":null},
            "assets":{"mipsel":{"sha256":"b".repeat(64),"bytes":3,"expanded":9}},
        })
    }

    #[test]
    fn signed_catalog_binds_head_and_orders_unique_supported_releases() {
        let pair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pair.as_ref()).unwrap();
        let key = pair.public_key().as_ref();
        let verify = |releases: Value, tag| {
            let bytes = serde_json::to_vec(&json!({"format":1,"releases":releases})).unwrap();
            let signature = pair.sign(&bytes);
            decode(&bytes, signature.as_ref(), key, tag)
        };
        let a = item("r2o-a", 1);
        let b = item("r2o-b", 2);
        assert_eq!(verify(json!([b, a]), "r2o-b").unwrap().releases.len(), 2);
        assert!(verify(json!([b, a]), "r2o-a").is_err());
        assert!(verify(json!([a, b]), "r2o-a").is_err());
        assert!(verify(json!([b, b]), "r2o-b").is_err());
        let mut legacy = a.clone();
        legacy.as_object_mut().unwrap().remove("metadata");
        assert!(verify(json!([b, legacy]), "r2o-b").is_err());
        assert!(decode(b"{}", &[0; 64], key, "r2o-b").is_err());
    }

    #[test]
    fn github_catalog_redirect_requires_the_exact_repo_tag_and_asset() {
        assert_eq!(
            tag_from_catalog_redirect(&format!("{DOWNLOAD_URL}/r2o-v1/catalog.json")).unwrap(),
            "r2o-v1"
        );
        for bad in [
            "https://github.com/other/r2o/releases/download/r2o-v1/catalog.json",
            "https://release-assets.githubusercontent.com/r2o-v1/catalog.json",
            "https://github.com/t0fox/r2o/releases/download//catalog.json",
            "https://github.com/t0fox/r2o/releases/download/r2o-v1/other/catalog.json",
            "https://github.com/t0fox/r2o/releases/download/r2o-v1/catalog.json?next=2",
            "https://github.com/t0fox/r2o/releases/download/r2o-v1/latest.json",
        ] {
            assert!(tag_from_catalog_redirect(bad).is_err(), "{bad}");
        }
    }
}
