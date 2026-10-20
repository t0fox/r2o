use r2o_manager::{
    activate_bundle, active_component_path, check_update, config::initialize_config,
    decode_public_key, install_archive, install_update, read_install_architecture, rollback,
    set_auto_update, verify_release_archive,
};
use serde_json::json;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

const MANIFEST_MAX: u64 = 64 * 1024;
const SIGNATURE_MAX: u64 = 64;
const KEY_MAX: u64 = 4096;

fn main() {
    if let Err(error) = run() {
        eprintln!("r2o-manager: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let command = args.next().ok_or_else(usage_error)?;
    if command == "--help" || command == "-h" {
        usage();
        return Ok(());
    }
    if command == "--version" || command == "-V" {
        println!("r2o-manager {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    match command.to_str() {
        Some("verify-release") => verify_release_command(args),
        Some("install-archive") => install_archive_command(args),
        Some("update-check") => update_command(args, false),
        Some("update-install") => update_command(args, true),
        Some("update-auto") => update_auto_command(args),
        Some("exec") => exec_command(args),
        Some("install-local") => install_local_command(args),
        Some("config-init") => config_init_command(args),
        Some("rollback") => rollback_command(args),
        _ => Err(usage_error()),
    }
}

fn exec_command(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<(), Box<dyn Error>> {
    let mut root = None;
    let mut component: Option<String> = None;
    let mut passthrough = Vec::new();
    while let Some(option) = args.next() {
        if option == "--" {
            passthrough.extend(args);
            break;
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {}", option.to_string_lossy()))?;
        match option.to_str() {
            Some("--root") => set_once(&mut root, PathBuf::from(value), "--root")?,
            Some("--component") => set_once(
                &mut component,
                value.into_string().map_err(|_| "component must be UTF-8")?,
                "--component",
            )?,
            _ => return Err(format!("unknown option: {}", option.to_string_lossy()).into()),
        }
    }
    let root = required(root, "--root")?;
    let component = component.ok_or("missing required option --component")?;
    let path = active_component_path(&root, &component)?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = std::process::Command::new(path).args(passthrough).exec();
        Err(error.into())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, passthrough);
        Err("active component exec is supported only on Unix".into())
    }
}

fn update_command(
    mut args: impl Iterator<Item = std::ffi::OsString>,
    install: bool,
) -> Result<(), Box<dyn Error>> {
    let mut root = None;
    let mut architecture: Option<String> = None;
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {}", option.to_string_lossy()))?;
        match option.to_str() {
            Some("--root") => set_once(&mut root, PathBuf::from(value), "--root")?,
            Some("--architecture") => set_once(
                &mut architecture,
                value
                    .into_string()
                    .map_err(|_| "architecture must be UTF-8")?,
                "--architecture",
            )?,
            _ => return Err(format!("unknown option: {}", option.to_string_lossy()).into()),
        }
    }
    let root = required(root, "--root")?;
    let architecture = match architecture {
        Some(value) => value,
        None => read_install_architecture(&root)?
            .ok_or("missing --architecture and no active release records one")?,
    };
    let result = if install {
        install_update(&root, &architecture)?
    } else {
        check_update(&root, &architecture)?
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn update_auto_command(
    mut args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn Error>> {
    let mut root = None;
    let mut enabled = None;
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {}", option.to_string_lossy()))?;
        match option.to_str() {
            Some("--root") => set_once(&mut root, PathBuf::from(value), "--root")?,
            Some("--enabled") => {
                let text = value.into_string().map_err(|_| "enabled must be UTF-8")?;
                let parsed = match text.as_str() {
                    "1" | "true" => true,
                    "0" | "false" => false,
                    _ => return Err("--enabled must be 0, 1, false or true".into()),
                };
                set_once(&mut enabled, parsed, "--enabled")?;
            }
            _ => return Err(format!("unknown option: {}", option.to_string_lossy()).into()),
        }
    }
    let root = required(root, "--root")?;
    let enabled = enabled.ok_or("missing required option --enabled")?;
    let result = set_auto_update(&root, enabled)?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn install_archive_command(
    mut args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn Error>> {
    let mut root = None;
    let mut archive = None;
    let mut manifest = None;
    let mut signature = None;
    let mut key = None;
    let mut architecture: Option<String> = None;
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {}", option.to_string_lossy()))?;
        match option.to_str() {
            Some("--root") => set_once(&mut root, PathBuf::from(value), "--root")?,
            Some("--archive") => set_once(&mut archive, PathBuf::from(value), "--archive")?,
            Some("--manifest") => set_once(&mut manifest, PathBuf::from(value), "--manifest")?,
            Some("--signature") => set_once(&mut signature, PathBuf::from(value), "--signature")?,
            Some("--public-key") => set_once(&mut key, PathBuf::from(value), "--public-key")?,
            Some("--architecture") => set_once(
                &mut architecture,
                value
                    .into_string()
                    .map_err(|_| "architecture must be UTF-8")?,
                "--architecture",
            )?,
            _ => return Err(format!("unknown option: {}", option.to_string_lossy()).into()),
        }
    }
    let root = required(root, "--root")?;
    let archive_path = required(archive, "--archive")?;
    let manifest_path = required(manifest, "--manifest")?;
    let signature_path = required(signature, "--signature")?;
    let key_path = required(key, "--public-key")?;
    let architecture = architecture.ok_or("missing required option --architecture")?;
    let manifest = read_bounded(&manifest_path, MANIFEST_MAX)?;
    let signature = read_bounded(&signature_path, SIGNATURE_MAX)?;
    let key_file = read_bounded(&key_path, KEY_MAX)?;
    let key = decode_public_key(&key_file)?;
    let slots = install_archive(
        &root,
        &archive_path,
        &manifest,
        &signature,
        &key,
        &architecture,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "installed": true,
            "current": slots.current,
            "previous": slots.previous,
            "architecture": architecture,
        }))?
    );
    Ok(())
}

fn verify_release_command(
    mut args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn Error>> {
    let mut manifest = None;
    let mut signature = None;
    let mut key = None;
    let mut architecture: Option<String> = None;
    let mut archive = None;
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {}", option.to_string_lossy()))?;
        let value = PathBuf::from(value);
        match option.to_str() {
            Some("--manifest") => set_once(&mut manifest, value, "--manifest")?,
            Some("--signature") => set_once(&mut signature, value, "--signature")?,
            Some("--public-key") => set_once(&mut key, value, "--public-key")?,
            Some("--architecture") => {
                let value = value
                    .into_os_string()
                    .into_string()
                    .map_err(|_| "architecture must be UTF-8")?;
                set_once(&mut architecture, value, "--architecture")?;
            }
            Some("--archive") => set_once(&mut archive, value, "--archive")?,
            _ => return Err(format!("unknown option: {}", option.to_string_lossy()).into()),
        }
    }

    let manifest_path = required(manifest, "--manifest")?;
    let signature_path = required(signature, "--signature")?;
    let key_path = required(key, "--public-key")?;
    let architecture = architecture.ok_or("missing required option --architecture")?;
    let archive_path = required(archive, "--archive")?;

    let manifest = read_bounded(&manifest_path, MANIFEST_MAX)?;
    let signature = read_bounded(&signature_path, SIGNATURE_MAX)?;
    let key_file = read_bounded(&key_path, KEY_MAX)?;
    let key = decode_public_key(&key_file)?;
    let mut archive = File::open(archive_path)?;
    let (manifest, sha256) =
        verify_release_archive(&manifest, &signature, &key, &architecture, &mut archive)?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "verified": true,
            "release_id": manifest.release_id,
            "version": manifest.version,
            "architecture": architecture,
            "sha256": sha256,
        }))?
    );
    Ok(())
}

fn install_local_command(
    args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn Error>> {
    let mut root = None;
    let mut bundle = None;
    let mut release_id: Option<String> = None;
    let mut architecture: Option<String> = None;
    let mut args = args;
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {}", option.to_string_lossy()))?;
        match option.to_str() {
            Some("--root") => set_once(&mut root, PathBuf::from(value), "--root")?,
            Some("--bundle") => set_once(&mut bundle, PathBuf::from(value), "--bundle")?,
            Some("--release-id") => set_once(
                &mut release_id,
                value
                    .into_string()
                    .map_err(|_| "release ID must be UTF-8")?,
                "--release-id",
            )?,
            Some("--architecture") => set_once(
                &mut architecture,
                value
                    .into_string()
                    .map_err(|_| "architecture must be UTF-8")?,
                "--architecture",
            )?,
            _ => return Err(format!("unknown option: {}", option.to_string_lossy()).into()),
        }
    }
    let root = required(root, "--root")?;
    let bundle = required(bundle, "--bundle")?;
    let release_id = release_id.ok_or("missing required option --release-id")?;
    let architecture = architecture.ok_or("missing required option --architecture")?;
    let slots = activate_bundle(&root, &bundle, &release_id, &architecture)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "activated": true,
            "current": slots.current,
            "previous": slots.previous,
            "architecture": architecture,
        }))?
    );
    Ok(())
}

fn config_init_command(
    mut args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn Error>> {
    let mut root = None;
    let mut defaults = None;
    let mut donor_config = None;
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("для {} не задан путь", option.to_string_lossy()))?;
        match option.to_str() {
            Some("--root") => set_once(&mut root, PathBuf::from(value), "--root")?,
            Some("--defaults") => set_once(&mut defaults, PathBuf::from(value), "--defaults")?,
            Some("--donor-config") => {
                set_once(&mut donor_config, PathBuf::from(value), "--donor-config")?
            }
            _ => return Err(format!("неизвестный параметр: {}", option.to_string_lossy()).into()),
        }
    }
    let root = required(root, "--root")?;
    let defaults = required(defaults, "--defaults")?;
    let result = initialize_config(&root, &defaults, donor_config.as_deref())?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn rollback_command(args: impl Iterator<Item = std::ffi::OsString>) -> Result<(), Box<dyn Error>> {
    let mut root = None;
    let mut args = args;
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {}", option.to_string_lossy()))?;
        match option.to_str() {
            Some("--root") => set_once(&mut root, PathBuf::from(value), "--root")?,
            _ => return Err(format!("unknown option: {}", option.to_string_lossy()).into()),
        }
    }
    let root = required(root, "--root")?;
    let slots = rollback(&root)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "rolled_back": true,
            "current": slots.current,
            "previous": slots.previous,
        }))?
    );
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), Box<dyn Error>> {
    if slot.replace(value).is_some() {
        return Err(format!("параметр {option} можно указать только один раз").into());
    }
    Ok(())
}

fn required(value: Option<PathBuf>, option: &str) -> Result<PathBuf, Box<dyn Error>> {
    value.ok_or_else(|| format!("не задан обязательный параметр {option}").into())
}

fn read_bounded(path: &std::path::Path, max: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    if size > max {
        return Err(format!("{} exceeds the {} byte limit", path.display(), max).into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size)?);
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(format!("{} exceeds the {} byte limit", path.display(), max).into());
    }
    Ok(bytes)
}

fn usage_error() -> Box<dyn Error> {
    "неверная команда; запустите `r2o-manager --help`".into()
}

fn usage() {
    println!("r2o-manager {} |", env!("CARGO_PKG_VERSION"));
    println!(
        "  verify-release --manifest FILE --signature FILE --public-key FILE --architecture ARCH --archive FILE"
    );
    println!(
        "  install-archive --root DIR --archive FILE --manifest FILE --signature FILE --public-key FILE --architecture ARCH"
    );
    println!("  update-check --root DIR [--architecture ARCH]");
    println!("  update-install --root DIR [--architecture ARCH]");
    println!("  update-auto --root DIR --enabled 0|1");
    println!("  exec --root DIR --component NAME [-- ARGS...]");
    println!("  install-local --root DIR --bundle DIR --release-id ID --architecture ARCH");
    println!("  config-init --root КАТАЛОГ --defaults ФАЙЛ [--donor-config ФАЙЛ]");
    println!("  rollback --root DIR");
}
