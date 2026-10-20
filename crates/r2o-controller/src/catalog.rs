use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::error::Error as StdError;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

const MAX_JSON_DEPTH: usize = 64;
const MAX_CATALOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CATALOG_PATH_BYTES: usize = 255;
const MAX_SIGNALS: usize = 8;
const MAX_DOMAIN_GROUPS: usize = 64;
const MAX_DOMAIN_OBSERVATIONS: usize = 256;
const TTL_SLACK: u8 = 2;
const VOLUME_SLACK: i64 = 4;
static NEXT_DONOR_IMPORT: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, Default)]
pub struct Catalog {
    pub boxes: Vec<BoxRecord>,
    pub domain_state: Option<DomainState>,
    pub network_whitelist: Option<NetworkWhitelist>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct BoxRecord {
    pub id: String,
    #[serde(with = "timestamp")]
    pub created: i64,
    #[serde(with = "timestamp")]
    pub updated: i64,
    pub fingerprint: Fingerprint,
    #[serde(deserialize_with = "null_to_default")]
    pub plans: Vec<Plan>,
    #[serde(rename = "bindings", deserialize_with = "null_to_default")]
    pub bindings: Vec<Binding>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Fingerprint {
    pub method: i32,
    #[serde(deserialize_with = "null_to_default")]
    pub signals: Vec<Signal>,
}

impl Fingerprint {
    /// Сравнить новое наблюдение с сохранённым отпечатком.
    ///
    /// По контракту источника сохранённые данные идут первыми, поэтому сравнение
    /// направленное: отсутствие сохранённых типов сигналов не противоречит
    /// неполному наблюдению, но известные типы должны совпадать.
    pub fn is_compatible_with(&self, observed: &Self) -> bool {
        if self.method != observed.method {
            return false;
        }
        let mut any_agreement = false;
        for new_signal in &observed.signals {
            let mut kind_seen = false;
            let mut signal_agrees = false;
            for old_signal in self
                .signals
                .iter()
                .filter(|old_signal| old_signal.kind == new_signal.kind)
            {
                kind_seen = true;
                if same_signal(old_signal, new_signal) {
                    signal_agrees = true;
                }
            }
            if kind_seen && !signal_agrees {
                return false;
            }
            any_agreement |= signal_agrees;
        }
        any_agreement
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Signal {
    pub kind: String,
    pub ttl: u8,
    pub ttl_delta: i32,
    pub tos: u8,
    pub ipid: u16,
    pub volume: i32,
    pub seen: i32,
    #[serde(skip_serializing_if = "is_zero")]
    pub packets: i32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Plan {
    pub id: String,
    pub proto: String,
    pub text: String,
    #[serde(with = "timestamp")]
    pub added: i64,
    pub successes: i32,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Binding {
    pub kind: String,
    pub target: String,
    pub plan_id: String,
    pub level: i32,
    #[serde(with = "timestamp")]
    pub confirmed: i64,
    pub successes: i32,
    pub enabled: bool,
    pub transport: u8,
    #[serde(serialize_with = "serialize_family")]
    pub family: u8,
    pub shape: u8,
    pub verified_by: u8,
    pub input: u8,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub probe_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ech_origin: String,
    #[serde(
        default,
        with = "optional_timestamp",
        skip_serializing_if = "option_is_zero"
    )]
    pub recheck_since: Option<i64>,
    /// Монотонная отметка текущего процесса, не попадающая в файл каталога.
    #[serde(skip)]
    pub recheck_mono: Option<std::time::Instant>,
    #[serde(skip_serializing_if = "is_zero")]
    pub budget: u8,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct GroupKey {
    pub transport: u8,
    pub family: u8,
    pub shape: u8,
    pub probe_path: String,
    pub ech_origin: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DomainObservation {
    pub name: String,
    pub plan_id: String,
    #[serde(flatten)]
    pub key: GroupKey,
    pub evidence: u8,
    #[serde(with = "timestamp")]
    pub at: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DomainGroup {
    pub suffix: String,
    pub plan_id: String,
    #[serde(flatten)]
    pub key: GroupKey,
    pub evidence_count: u32,
    #[serde(skip)]
    pub at: i64,
}

#[derive(Clone, Debug, Default)]
pub struct DomainState {
    /// Производный кеш; источником истины остаётся `domain_observations`.
    pub groups: Vec<DomainGroup>,
    pub observations: Vec<DomainObservation>,
    pub frozen: bool,
    pub disabled: bool,
    pub disabled_at: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct NetworkWhitelist {
    pub name: String,
    pub searched: bool,
    #[serde(
        rename = "confirmed_utc",
        default,
        with = "optional_timestamp",
        skip_serializing_if = "option_is_zero"
    )]
    pub confirmed_at: Option<i64>,
}

#[derive(Debug)]
pub struct CatalogError(String);

impl CatalogError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl StdError for CatalogError {}

impl DomainState {
    /// Проверить сохранённые наблюдения и заново собрать рабочий кеш.
    /// Сохранённым `domain_groups` намеренно не доверяем.
    pub fn restore(&mut self) -> Result<(), CatalogError> {
        crate::groups::restore(self)
    }

    /// Найти самую точную активную группу, охватывающую имя узла.
    pub fn match_domain(&self, name: &str, key: &GroupKey) -> Option<&DomainGroup> {
        crate::groups::match_domain(self, name, key)
    }

    /// Сохранить измеренное наблюдение и обновить производный рабочий кеш.
    pub fn learn(&mut self, observation: DomainObservation) -> Result<bool, CatalogError> {
        crate::groups::learn(self, observation)
    }

    /// Забыть неудачные планы для недоступной точки и обновить кеш.
    pub fn forget_failures(&mut self, name: &str, transport: u8, family: u8) -> usize {
        crate::groups::forget_failures(self, name, transport, family)
    }

    /// Удалить устаревшие записи неудачных планов. Подтверждённые успехи не стареют.
    pub fn expire_failures(&mut self, now: i64, max_age: i64) -> usize {
        crate::groups::expire_failures(self, now, max_age)
    }
}

impl Catalog {
    pub fn parse(input: &[u8]) -> Result<Self, CatalogError> {
        if input.len() as u64 > MAX_CATALOG_BYTES {
            return Err(CatalogError::new("catalog file exceeds 64 MiB"));
        }
        check_json_depth(input)?;
        let decoded: CatalogInput = serde_json::from_slice(input)
            .map_err(|error| CatalogError::new(format!("invalid catalog JSON: {error}")))?;
        if decoded.schema.is_some_and(|schema| schema != 1) {
            return Err(CatalogError::new("unsupported catalog schema"));
        }
        if decoded
            .domain_observations
            .as_ref()
            .is_some_and(|observations| observations.len() > MAX_DOMAIN_OBSERVATIONS)
        {
            return Err(CatalogError::new("too many domain observations"));
        }

        let domain_state = if decoded.domain_observations.is_some()
            || decoded.domain_groups_frozen.is_some()
            || decoded.domain_groups_disabled.is_some()
            || decoded.domain_groups_disabled_at.is_some()
        {
            Some(DomainState {
                groups: Vec::new(),
                observations: decoded.domain_observations.unwrap_or_default(),
                frozen: decoded.domain_groups_frozen.unwrap_or_default(),
                disabled: decoded.domain_groups_disabled.unwrap_or_default(),
                disabled_at: decoded.domain_groups_disabled_at,
            })
        } else {
            None
        };
        let mut catalog = Self {
            boxes: decoded.boxes,
            domain_state,
            network_whitelist: decoded.network_whitelist,
        };
        catalog.validate()?;
        if let Some(state) = &mut catalog.domain_state {
            state.restore()?;
        }
        Ok(catalog)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, CatalogError> {
        let path = path.as_ref();
        let metadata = fs::metadata(path)
            .map_err(|error| CatalogError::new(format!("{}: {error}", path.display())))?;
        if metadata.len() > MAX_CATALOG_BYTES {
            return Err(CatalogError::new("catalog file exceeds 64 MiB"));
        }
        let bytes = fs::read(path)
            .map_err(|error| CatalogError::new(format!("{}: {error}", path.display())))?;
        Self::parse(&bytes)
    }

    /// Импортировать каталог донора, переименовав заголовки планов и не заменяя цель.
    pub fn import_donor_file(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        updated: i64,
    ) -> Result<bool, CatalogError> {
        let source = source.as_ref();
        let destination = destination.as_ref();
        if destination_exists(destination)? {
            return Ok(false);
        }
        let metadata = fs::symlink_metadata(source)
            .map_err(|error| CatalogError::new(format!("не открыть каталог донора: {error}")))?;
        if !metadata.file_type().is_file() {
            return Err(CatalogError::new(
                "каталог донора должен быть обычным файлом",
            ));
        }
        let mut catalog = Self::load(source)?;
        for record in &mut catalog.boxes {
            for plan in &mut record.plans {
                rename_donor_plan_header(&mut plan.text).map_err(|error| {
                    CatalogError::new(format!(
                        "план {} нельзя безопасно перенести: {error}",
                        plan.id
                    ))
                })?;
                crate::plan_text::compile_text(&plan.text).map_err(|error| {
                    CatalogError::new(format!(
                        "план {} не проходит проверку R2O: {error}",
                        plan.id
                    ))
                })?;
            }
        }
        let content = catalog.to_json_at(updated)?;
        if content.len() as u64 > MAX_CATALOG_BYTES {
            return Err(CatalogError::new(
                "импортированный каталог превышает предел 64 МиБ",
            ));
        }
        write_new_catalog(destination, content.as_bytes())
    }

    pub fn to_json_at(&self, updated: i64) -> Result<String, CatalogError> {
        self.validate()?;
        format_timestamp(updated)?;
        let mut rebuilt_domain_state = self.domain_state.clone();
        if let Some(state) = &mut rebuilt_domain_state {
            state.restore()?;
        }
        let domain_groups = rebuilt_domain_state
            .as_ref()
            .map(|state| state.groups.as_slice());
        let domain_observations = self
            .domain_state
            .as_ref()
            .map(|state| state.observations.as_slice());
        let domain_groups_frozen = self.domain_state.as_ref().map(|state| state.frozen);
        let domain_groups_disabled = self.domain_state.as_ref().map(|state| state.disabled);
        let domain_groups_disabled_at = self
            .domain_state
            .as_ref()
            .and_then(|state| state.disabled_at.filter(|at| *at != 0));
        let network_whitelist = self
            .network_whitelist
            .as_ref()
            .filter(|network| network.searched || !network.name.is_empty());
        let output = CatalogOutput {
            schema: 1,
            updated,
            boxes: &self.boxes,
            domain_groups,
            domain_observations,
            domain_groups_frozen,
            domain_groups_disabled,
            domain_groups_disabled_at,
            network_whitelist,
        };
        let mut text = serde_json::to_string_pretty(&output)
            .map_err(|error| CatalogError::new(format!("serialize catalog: {error}")))?;
        text.push('\n');
        Ok(text)
    }

    /// Сохранить полный снимок и синхронизировать файл и каталог до и после переименования.
    pub fn save_atomic(&self, path: impl AsRef<Path>, updated: i64) -> Result<(), CatalogError> {
        let path = path.as_ref();
        let path_bytes = path.to_string_lossy().len();
        if path_bytes > MAX_CATALOG_PATH_BYTES {
            return Err(CatalogError::new("catalog path exceeds 255 bytes"));
        }
        let file_name = path
            .file_name()
            .ok_or_else(|| CatalogError::new("catalog path has no file name"))?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| CatalogError::new(format!("system clock: {error}")))?
            .as_nanos();
        let mut temporary_name = file_name.to_os_string();
        temporary_name.push(format!(".new.{}.{}", std::process::id(), nonce));
        let temporary_path: PathBuf = path.with_file_name(temporary_name);
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));

        let result = (|| {
            let content = self.to_json_at(updated)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary_path)
                .map_err(|error| {
                    CatalogError::new(format!("{}: {error}", temporary_path.display()))
                })?;
            file.write_all(content.as_bytes())
                .map_err(|error| CatalogError::new(format!("write catalog: {error}")))?;
            file.sync_all()
                .map_err(|error| CatalogError::new(format!("sync catalog: {error}")))?;
            drop(file);
            fs::rename(&temporary_path, path)
                .map_err(|error| CatalogError::new(format!("replace catalog: {error}")))?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| CatalogError::new(format!("sync catalog directory: {error}")))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    pub fn match_fingerprint(&self, observed: &Fingerprint) -> Option<usize> {
        self.boxes
            .iter()
            .position(|box_record| box_record.fingerprint.is_compatible_with(observed))
    }

    fn validate(&self) -> Result<(), CatalogError> {
        for (box_index, box_record) in self.boxes.iter().enumerate() {
            validate_string(&box_record.id, 39, "box.id")?;
            if box_record.fingerprint.signals.len() > MAX_SIGNALS {
                return Err(CatalogError::new(format!(
                    "box {box_index}: fingerprint has more than {MAX_SIGNALS} signals"
                )));
            }
            format_timestamp(box_record.created)?;
            format_timestamp(box_record.updated)?;
            for signal in &box_record.fingerprint.signals {
                validate_string(&signal.kind, 23, "signal.kind")?;
            }
            for plan in &box_record.plans {
                validate_string(&plan.id, 39, "plan.id")?;
                validate_string(&plan.proto, 7, "plan.proto")?;
                validate_string(&plan.text, usize::MAX, "plan.text")?;
                format_timestamp(plan.added)?;
            }
            for binding in &box_record.bindings {
                validate_string(&binding.kind, 7, "binding.kind")?;
                validate_string(&binding.target, 255, "binding.target")?;
                validate_string(&binding.plan_id, 39, "binding.plan_id")?;
                validate_string(&binding.probe_path, 511, "binding.probe_path")?;
                validate_string(&binding.ech_origin, 255, "binding.ech_origin")?;
                format_timestamp(binding.confirmed)?;
                if let Some(recheck_since) = binding.recheck_since {
                    format_timestamp(recheck_since)?;
                }
            }
        }
        if let Some(groups) = &self.domain_state {
            if groups.groups.len() > MAX_DOMAIN_GROUPS {
                return Err(CatalogError::new("too many domain groups"));
            }
            if groups.observations.len() > MAX_DOMAIN_OBSERVATIONS {
                return Err(CatalogError::new("too many domain observations"));
            }
            for group in &groups.groups {
                validate_string(&group.suffix, 255, "domain_group.suffix")?;
                validate_string(&group.plan_id, 39, "domain_group.plan_id")?;
                validate_group_key(&group.key)?;
            }
            for observation in &groups.observations {
                validate_string(&observation.name, 255, "domain_observation.name")?;
                validate_string(&observation.plan_id, 39, "domain_observation.plan_id")?;
                validate_group_key(&observation.key)?;
                format_timestamp(observation.at)?;
            }
            if let Some(disabled_at) = groups.disabled_at {
                format_timestamp(disabled_at)?;
            }
        }
        if let Some(network) = &self.network_whitelist {
            validate_string(&network.name, 255, "network_whitelist.name")?;
            if let Some(confirmed_at) = network.confirmed_at {
                format_timestamp(confirmed_at)?;
            }
        }
        Ok(())
    }
}

fn rename_donor_plan_header(text: &mut String) -> Result<(), String> {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let content = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = content.trim_matches([' ', '\t', '\r']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += line.len();
            continue;
        }
        let leading = content.len() - content.trim_start_matches([' ', '\t']).len();
        let start = offset + leading;
        if let Some(rest) = trimmed.strip_prefix("d2k-plan") {
            if rest.is_empty() || rest.starts_with([' ', '\t']) {
                text.replace_range(start..start + "d2k-plan".len(), "r2o-plan");
                return Ok(());
            }
        }
        if trimmed.starts_with("r2o-plan ") {
            return Ok(());
        }
        return Err("первая директива должна задавать заголовок плана".into());
    }
    Err("текст плана пуст".into())
}

fn destination_exists(path: &Path) -> Result<bool, CatalogError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(CatalogError::new(format!(
            "не проверить целевой каталог: {error}"
        ))),
    }
}

fn write_new_catalog(path: &Path, content: &[u8]) -> Result<bool, CatalogError> {
    if path.to_string_lossy().len() > MAX_CATALOG_PATH_BYTES {
        return Err(CatalogError::new("путь целевого каталога длиннее 255 байт"));
    }
    if destination_exists(path)? {
        return Ok(false);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| CatalogError::new(format!("не создать каталог состояния: {error}")))?;
    let sequence = NEXT_DONOR_IMPORT.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .ok_or_else(|| CatalogError::new("у целевого каталога нет имени файла"))?;
    let mut temporary_name = file_name.to_os_string();
    temporary_name.push(format!(".import.{}.{}", std::process::id(), sequence));
    let temporary = path.with_file_name(temporary_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|error| CatalogError::new(format!("не создать временный каталог: {error}")))?;
        file.write_all(content)
            .map_err(|error| CatalogError::new(format!("не записать каталог: {error}")))?;
        file.sync_all()
            .map_err(|error| CatalogError::new(format!("не синхронизировать каталог: {error}")))?;
        drop(file);
        match fs::hard_link(&temporary, path) {
            Ok(()) => {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| {
                        CatalogError::new(format!("не закрепить каталог состояния: {error}"))
                    })?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(CatalogError::new(format!(
                "не опубликовать импортированный каталог: {error}"
            ))),
        }
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn same_signal(saved: &Signal, observed: &Signal) -> bool {
    match saved.kind.as_str() {
        "volume" | "rx-volume" | "rx-volume-wire" => {
            (i64::from(saved.volume) - i64::from(observed.volume)).abs() <= VOLUME_SLACK
        }
        _ => {
            saved.ttl.abs_diff(observed.ttl) <= TTL_SLACK
                && saved.tos == observed.tos
                && saved.ipid == observed.ipid
        }
    }
}

fn validate_group_key(key: &GroupKey) -> Result<(), CatalogError> {
    validate_string(&key.probe_path, 255, "domain.probe_path")?;
    validate_string(&key.ech_origin, 255, "domain.ech_origin")
}

fn validate_string(value: &str, max_bytes: usize, field: &str) -> Result<(), CatalogError> {
    if value.as_bytes().contains(&0) {
        return Err(CatalogError::new(format!("{field} contains NUL")));
    }
    if value.len() > max_bytes {
        return Err(CatalogError::new(format!(
            "{field} exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn is_zero<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

fn serialize_family<S>(family: &u8, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u8(if *family == 0 { 4 } else { *family })
}

fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn check_json_depth(input: &[u8]) -> Result<(), CatalogError> {
    let (mut depth, mut in_string, mut escaped) = (0_usize, false, false);
    for byte in input {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(CatalogError::new(format!(
                        "JSON nesting exceeds {MAX_JSON_DEPTH} levels"
                    )));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<i64, String> {
    if !value.ends_with('Z') {
        return Err("timestamp must be UTC RFC3339 with a Z suffix".into());
    }
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|error| error.to_string())?;
    if parsed.offset() != UtcOffset::UTC {
        return Err("timestamp must use UTC".into());
    }
    Ok(parsed.unix_timestamp())
}

fn format_timestamp(value: i64) -> Result<String, CatalogError> {
    let date = OffsetDateTime::from_unix_timestamp(value)
        .map_err(|error| CatalogError::new(format!("invalid Unix timestamp {value}: {error}")))?;
    date.format(&Rfc3339)
        .map_err(|error| CatalogError::new(format!("format Unix timestamp {value}: {error}")))
}

mod timestamp {
    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<i64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_timestamp(&value).map_err(serde::de::Error::custom)
    }

    pub fn serialize<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = format_timestamp(*value).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&value)
    }
}

mod optional_timestamp {
    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|value| parse_timestamp(&value).map_err(serde::de::Error::custom))
            .transpose()
    }

    pub fn serialize<S>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => {
                let value = format_timestamp(*value).map_err(serde::ser::Error::custom)?;
                serializer.serialize_some(&value)
            }
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct CatalogInput {
    schema: Option<u32>,
    #[serde(deserialize_with = "null_to_default")]
    boxes: Vec<BoxRecord>,
    domain_observations: Option<Vec<DomainObservation>>,
    domain_groups_frozen: Option<bool>,
    domain_groups_disabled: Option<bool>,
    #[serde(with = "optional_timestamp")]
    domain_groups_disabled_at: Option<i64>,
    network_whitelist: Option<NetworkWhitelist>,
}

#[derive(Serialize)]
struct CatalogOutput<'a> {
    schema: u8,
    #[serde(serialize_with = "timestamp::serialize")]
    updated: i64,
    boxes: &'a [BoxRecord],
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_groups: Option<&'a [DomainGroup]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_observations: Option<&'a [DomainObservation]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_groups_frozen: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_groups_disabled: Option<bool>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "optional_timestamp_ref::serialize"
    )]
    domain_groups_disabled_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_whitelist: Option<&'a NetworkWhitelist>,
}

mod optional_timestamp_ref {
    use super::*;

    pub fn serialize<S>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        optional_timestamp::serialize(value, serializer)
    }
}

fn option_is_zero(value: &Option<i64>) -> bool {
    value.is_none_or(|timestamp| timestamp == 0)
}
