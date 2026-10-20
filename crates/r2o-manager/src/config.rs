//! Безопасная первичная настройка выпуска r2o и перенос совместимых параметров донора.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const CONFIG_MAX_BYTES: u64 = 64 * 1024;
const CONFIG_LINE_MAX_BYTES: usize = 2046;
const IMPORTABLE_KEYS: &[&str] = &[
    "SCHEMA",
    "MODE",
    "STATE_DIR",
    "QUEUE_NUM",
    "QUEUE_NUM6",
    "R2O_FLOW_CAPACITY",
    "IPV6_ENABLED",
    "MARK",
    "AUTOUPDATE",
    "FW_BACKEND",
    "PANEL_LISTEN",
    "TG_ENABLED",
    "TG_MODE",
    "TG_PORT",
];
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfigInitResult {
    pub created: bool,
    pub state_dir: Option<String>,
    pub donor_state_dir: Option<String>,
    pub imported: Vec<String>,
    pub unsupported: Vec<String>,
}

/// Создать конфигурацию выпуска один раз, сохранив существующий файл без изменений.
/// Файл донора читается как данные: оболочка его не запускает.
pub fn initialize_config(
    root: &Path,
    defaults_path: &Path,
    donor_config_path: Option<&Path>,
) -> io::Result<ConfigInitResult> {
    let target = root.join("config");
    match fs::symlink_metadata(&target) {
        Ok(_) => {
            let state_dir = read_config_text(&target)
                .ok()
                .and_then(|text| state_dir_from_text(&text, false));
            let donor_state_dir = donor_config_path
                .and_then(|path| read_config_text(path).ok())
                .and_then(|text| state_dir_from_text(&text, true));
            return Ok(ConfigInitResult {
                created: false,
                state_dir,
                donor_state_dir,
                imported: Vec::new(),
                unsupported: Vec::new(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let defaults = read_config_text(defaults_path)?;
    let default_keys = parse_defaults(&defaults)?;
    let mut imported_values = BTreeMap::new();
    let mut unsupported = BTreeSet::new();
    let mut donor_state_dir = None;
    if let Some(path) = donor_config_path {
        let donor = read_config_text(path)?;
        donor_state_dir = state_dir_from_text(&donor, true);
        import_donor_values(
            &donor,
            &default_keys,
            &mut imported_values,
            &mut unsupported,
        )?;
    }

    let mut content = String::with_capacity(defaults.len() + 128);
    let mut remaining = imported_values.clone();
    for line in defaults.lines() {
        let trimmed = line.trim();
        if let Some((key, _)) = assignment_parts(trimmed)? {
            if let Some(value) = remaining.remove(key) {
                content.push_str(key);
                content.push('=');
                content.push_str(&value);
                content.push('\n');
                continue;
            }
        }
        content.push_str(line);
        content.push('\n');
    }
    for (key, value) in remaining {
        content.push_str(&key);
        content.push('=');
        content.push_str(&value);
        content.push('\n');
    }
    if content.len() as u64 > CONFIG_MAX_BYTES {
        return Err(invalid_config("итоговый файл конфигурации слишком велик"));
    }

    fs::create_dir_all(root)?;
    let temporary = temporary_path(root);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        match fs::hard_link(&temporary, &target) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    })();
    let _ = fs::remove_file(&temporary);
    let created = write_result?;

    Ok(ConfigInitResult {
        created,
        state_dir: state_dir_from_text(&content, false),
        donor_state_dir,
        imported: if created {
            imported_values.keys().cloned().collect()
        } else {
            Vec::new()
        },
        unsupported: unsupported.into_iter().collect(),
    })
}

fn state_dir_from_text(config: &str, donor: bool) -> Option<String> {
    let mut state_dir = None;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Ok(Some((key, raw_value))) = assignment_parts(trimmed) else {
            return None;
        };
        if key != "STATE_DIR" {
            continue;
        }
        let Ok(value) = strip_literal(raw_value) else {
            return None;
        };
        if validate_value("STATE_DIR", &value, donor).is_err() || state_dir.is_some() {
            return None;
        }
        state_dir = Some(value);
    }
    state_dir
}

fn temporary_path(root: &Path) -> PathBuf {
    let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    root.join(format!(".config.new.{}.{}", std::process::id(), sequence))
}

fn read_config_text(path: &Path) -> io::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid_config(
            "файл конфигурации должен быть обычным файлом",
        ));
    }
    if metadata.len() > CONFIG_MAX_BYTES {
        return Err(invalid_config("файл конфигурации превышает предел размера"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(CONFIG_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > CONFIG_MAX_BYTES {
        return Err(invalid_config("файл конфигурации превышает предел размера"));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn parse_defaults(defaults: &str) -> io::Result<BTreeSet<String>> {
    let mut keys = BTreeSet::new();
    for line in defaults.lines() {
        if line.len() > CONFIG_LINE_MAX_BYTES {
            return Err(invalid_config("строка конфигурации превышает предел длины"));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = assignment_parts(trimmed)? else {
            return Err(invalid_config(
                "в файле значений по умолчанию есть неверная строка",
            ));
        };
        if !IMPORTABLE_KEYS.contains(&key) || !keys.insert(key.to_owned()) {
            return Err(invalid_config(
                "в файле значений по умолчанию есть лишний или повторный ключ",
            ));
        }
        let value = strip_literal(raw_value)?;
        validate_value(key, &value, false)?;
    }
    if keys.is_empty() {
        return Err(invalid_config("файл значений по умолчанию пуст"));
    }
    Ok(keys)
}

fn import_donor_values(
    donor: &str,
    default_keys: &BTreeSet<String>,
    imported: &mut BTreeMap<String, String>,
    unsupported: &mut BTreeSet<String>,
) -> io::Result<()> {
    for line in donor.lines() {
        if line.len() > CONFIG_LINE_MAX_BYTES {
            return Err(invalid_config(
                "строка конфигурации донора превышает предел длины",
            ));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = assignment_parts(trimmed)? else {
            return Err(invalid_config("в конфигурации донора есть неверная строка"));
        };
        let target_key = match key {
            "FLOWS" => "R2O_FLOW_CAPACITY",
            "D2K_PPE_DEOFFLOAD" | "CONTROL_SOCKET" | "DECOY_SNI" => {
                unsupported.insert(key.to_owned());
                continue;
            }
            _ if !IMPORTABLE_KEYS.contains(&key) => {
                unsupported.insert(key.to_owned());
                continue;
            }
            _ => key,
        };
        if !default_keys.contains(target_key) && target_key != "TG_PORT" {
            unsupported.insert(key.to_owned());
            continue;
        }
        let mut value = strip_literal(raw_value)?;
        if target_key == "TG_MODE" && value == "relay" {
            value = "local".to_owned();
        }
        validate_value(target_key, &value, true)?;
        if target_key == "STATE_DIR" {
            value = migrate_state_path(value)?;
        }
        imported.insert(target_key.to_owned(), value);
    }
    Ok(())
}

fn assignment_parts(line: &str) -> io::Result<Option<(&str, &str)>> {
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let Some((raw_key, raw_value)) = line.split_once('=') else {
        return Ok(None);
    };
    let key = raw_key.trim();
    let mut bytes = key.bytes();
    if key.len() > 128
        || !matches!(bytes.next(), Some(b'A'..=b'Z'))
        || !bytes.all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
    {
        return Err(invalid_config(
            "имя параметра конфигурации имеет неверный формат",
        ));
    }
    Ok(Some((key, raw_value.trim())))
}

fn strip_literal(raw: &str) -> io::Result<String> {
    let value = if let Some(rest) = raw.strip_prefix('\'') {
        rest.strip_suffix('\'')
            .ok_or_else(|| invalid_config("одинарная кавычка не закрыта"))?
    } else if let Some(rest) = raw.strip_prefix('"') {
        rest.strip_suffix('"')
            .ok_or_else(|| invalid_config("двойная кавычка не закрыта"))?
    } else {
        raw
    };
    if value.contains(['\'', '"']) {
        return Err(invalid_config("в значении есть кавычка внутри строки"));
    }
    Ok(value.to_owned())
}

fn validate_value(key: &str, value: &str, donor: bool) -> io::Result<()> {
    let valid = match key {
        "SCHEMA" => value == "1",
        "MODE" => matches!(value, "off" | "observe" | "apply"),
        "STATE_DIR" => {
            value.starts_with('/')
                && !value.split('/').any(|part| part == "." || part == "..")
                && safe_chars(value, |byte| {
                    byte.is_ascii_alphanumeric() || b"/._-".contains(&byte)
                })
        }
        "QUEUE_NUM" | "QUEUE_NUM6" | "TG_PORT" => value.parse::<u16>().is_ok(),
        "R2O_FLOW_CAPACITY" => value.parse::<u32>().is_ok_and(|capacity| capacity > 0),
        "IPV6_ENABLED" | "AUTOUPDATE" | "TG_ENABLED" => matches!(value, "0" | "1"),
        "MARK" => valid_mark(value),
        "FW_BACKEND" => matches!(value, "auto" | "iptables" | "nft"),
        "PANEL_LISTEN" => valid_panel_listen(value),
        "TG_MODE" => value == "local" || (donor && value == "relay"),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_config(
            "значение параметра конфигурации недопустимо",
        ))
    }
}

fn valid_mark(value: &str) -> bool {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        !hex.is_empty() && hex.len() <= 8 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    } else {
        value.parse::<u32>().is_ok()
    }
}

fn valid_panel_listen(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if host.is_empty()
        || host.len() >= 256
        || port.len() >= 16
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || !matches!(port.parse::<u32>(), Ok(1..=65535))
    {
        return false;
    }
    safe_chars(value, |byte| {
        byte.is_ascii_alphanumeric() || b"._:%[]-".contains(&byte)
    })
}

fn safe_chars(value: &str, allowed: impl Fn(u8) -> bool) -> bool {
    value.bytes().all(allowed)
}

fn migrate_state_path(mut value: String) -> io::Result<String> {
    for donor_root in ["/opt/d2k", "/opt/d2o"] {
        if value == donor_root {
            value = "/opt/r2o".to_owned();
            break;
        }
        if let Some(suffix) = value.strip_prefix(&format!("{donor_root}/")) {
            value = format!("/opt/r2o/{suffix}");
            break;
        }
    }
    let lowercase = value.to_ascii_lowercase();
    if lowercase.contains("d2k") || lowercase.contains("d2o") {
        return Err(invalid_config(
            "путь состояния содержит имя донора вне переносимого корня",
        ));
    }
    Ok(value)
}

fn invalid_config(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
