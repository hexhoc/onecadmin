use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fs4::FileExt;
use noyalib::{DuplicateKeyPolicy, ErrorKind, ParserConfig, Value};
use serde::Serialize;
use tempfile::NamedTempFile;
use uuid::Uuid;

use super::{
    AclError, ClusterConfig, Config, ConfigError, InfobaseAuthOverride, SafeYamlError,
    resolve_config_path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AclProtection {
    Applied,
    NotConfigured,
}

pub trait AclProtector: Send + Sync {
    fn protect_current_user(&self, path: &Path) -> Result<AclProtection, AclError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopAclProtector;

impl AclProtector for NoopAclProtector {
    fn protect_current_user(&self, _path: &Path) -> Result<AclProtection, AclError> {
        Ok(AclProtection::NotConfigured)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigSnapshot {
    path: PathBuf,
    config: Config,
}

impl ConfigSnapshot {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn into_config(self) -> Config {
        self.config
    }
}

impl Deref for ConfigSnapshot {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ConfigDocument {
    snapshot: ConfigSnapshot,
    source: String,
}

impl ConfigDocument {
    pub fn snapshot(&self) -> &ConfigSnapshot {
        &self.snapshot
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn into_parts(self) -> (ConfigSnapshot, String) {
        (self.snapshot, self.source)
    }
}

impl fmt::Debug for ConfigDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigDocument")
            .field("snapshot", &self.snapshot)
            .field("source", &"[REDACTED YAML]")
            .field("source_len", &self.source.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatPreservation {
    Canonical,
    TargetedCst,
    CanonicalFallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteOutcome {
    pub snapshot: ConfigSnapshot,
    pub format_preservation: FormatPreservation,
    pub acl_protection: AclProtection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverrideSelector {
    pub infobase_uuid: Option<Uuid>,
    pub infobase: String,
}

impl OverrideSelector {
    pub fn new(infobase_uuid: Option<Uuid>, infobase: impl Into<String>) -> Self {
        Self {
            infobase_uuid,
            infobase: infobase.into(),
        }
    }

    pub fn by_uuid(uuid: Uuid) -> Self {
        Self::new(Some(uuid), String::new())
    }

    pub fn by_name(infobase: impl Into<String>) -> Self {
        Self::new(None, infobase)
    }

    fn find_in(&self, overrides: &[InfobaseAuthOverride]) -> Option<usize> {
        let by_uuid = self.infobase_uuid.and_then(|uuid| {
            overrides
                .iter()
                .position(|entry| entry.infobase_uuid() == Some(uuid))
        });
        by_uuid.or_else(|| {
            if self.infobase.is_empty() {
                return None;
            }
            let folded = self.infobase.to_lowercase();
            overrides
                .iter()
                .position(|entry| entry.infobase().to_lowercase() == folded)
        })
    }

    fn label(&self) -> String {
        self.infobase_uuid
            .map(|uuid| uuid.to_string())
            .unwrap_or_else(|| self.infobase.clone())
    }
}

pub struct ConfigStore {
    path: PathBuf,
    lock_path: PathBuf,
    acl: Arc<dyn AclProtector>,
}

impl fmt::Debug for ConfigStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigStore")
            .field("path", &self.path)
            .field("lock_path", &self.lock_path)
            .finish_non_exhaustive()
    }
}

impl ConfigStore {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyConfigPath);
        }
        let file_name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(ConfigError::EmptyConfigPath)?;
        let mut lock_name = OsString::from(file_name);
        lock_name.push(".lock");
        let lock_path = path.with_file_name(lock_name);
        Ok(Self {
            path,
            lock_path,
            acl: Arc::new(NoopAclProtector),
        })
    }

    pub fn from_sources(cli_path: Option<PathBuf>) -> Result<Self, ConfigError> {
        Self::new(resolve_config_path(cli_path)?)
    }

    pub fn with_acl_protector<P>(mut self, protector: P) -> Self
    where
        P: AclProtector + 'static,
    {
        self.acl = Arc::new(protector);
        self
    }

    pub fn with_shared_acl_protector(mut self, protector: Arc<dyn AclProtector>) -> Self {
        self.acl = protector;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub fn load(&self) -> Result<ConfigSnapshot, ConfigError> {
        Ok(self.load_document()?.snapshot)
    }

    pub fn load_document(&self) -> Result<ConfigDocument, ConfigError> {
        if !self.parent_dir().exists() {
            return Err(ConfigError::NotFound {
                path: self.path.clone(),
            });
        }
        let _lock = self.acquire_lock(false, false)?;
        self.read_document_unlocked()
    }

    pub fn create_default(&self) -> Result<WriteOutcome, ConfigError> {
        self.create(Config::default())
    }

    pub fn create(&self, config: Config) -> Result<WriteOutcome, ConfigError> {
        let _lock = self.acquire_lock(true, true)?;
        match fs::metadata(&self.path) {
            Ok(_) => {
                return Err(ConfigError::AlreadyExists {
                    path: self.path.clone(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ConfigError::Io {
                    action: "inspect",
                    path: self.path.clone(),
                    source,
                });
            }
        }

        config.validate()?;
        let yaml = serialize_config(&config)?;
        ensure_roundtrip(&self.path, &yaml, &config)?;
        let acl_protection = self.write_atomic(&yaml)?;
        Ok(WriteOutcome {
            snapshot: self.snapshot(config),
            format_preservation: FormatPreservation::Canonical,
            acl_protection,
        })
    }

    pub fn add_cluster(
        &self,
        alias: impl Into<String>,
        cluster: ClusterConfig,
    ) -> Result<WriteOutcome, ConfigError> {
        let alias = alias.into();
        self.transact(move |config| {
            if let Some(existing) = find_cluster_key(config, &alias) {
                return Err(ConfigError::ClusterAlreadyExists {
                    requested: alias,
                    existing: existing.to_owned(),
                });
            }
            config.clusters.insert(alias.clone(), cluster);
            Ok(CstEdit::AddCluster { alias })
        })
    }

    pub fn remove_cluster(&self, alias: &str) -> Result<WriteOutcome, ConfigError> {
        let requested = alias.to_owned();
        self.transact(move |config| {
            let exact = find_cluster_key(config, &requested)
                .map(str::to_owned)
                .ok_or_else(|| ConfigError::ClusterNotFound {
                    alias: requested.clone(),
                })?;
            config.clusters.shift_remove(&exact);
            Ok(CstEdit::RemoveCluster { alias: exact })
        })
    }

    pub fn add_override(
        &self,
        cluster_alias: &str,
        entry: InfobaseAuthOverride,
    ) -> Result<WriteOutcome, ConfigError> {
        let requested = cluster_alias.to_owned();
        self.transact(move |config| {
            let exact = find_cluster_key(config, &requested)
                .map(str::to_owned)
                .ok_or_else(|| ConfigError::ClusterNotFound {
                    alias: requested.clone(),
                })?;
            let cluster = config.clusters.get_mut(&exact).expect("key was found");
            cluster.infobase_auth.overrides.push(entry);
            let index = cluster.infobase_auth.overrides.len() - 1;
            Ok(CstEdit::AddOverride {
                cluster: exact,
                index,
            })
        })
    }

    pub fn remove_override(
        &self,
        cluster_alias: &str,
        selector: OverrideSelector,
    ) -> Result<WriteOutcome, ConfigError> {
        let requested = cluster_alias.to_owned();
        self.transact(move |config| {
            let exact = find_cluster_key(config, &requested)
                .map(str::to_owned)
                .ok_or_else(|| ConfigError::ClusterNotFound {
                    alias: requested.clone(),
                })?;
            let cluster = config.clusters.get_mut(&exact).expect("key was found");
            let index = selector
                .find_in(&cluster.infobase_auth.overrides)
                .ok_or_else(|| ConfigError::OverrideNotFound {
                    cluster: exact.clone(),
                    target: selector.label(),
                })?;
            cluster.infobase_auth.overrides.remove(index);
            Ok(CstEdit::RemoveOverride {
                cluster: exact,
                index,
            })
        })
    }

    fn transact<F>(&self, mutation: F) -> Result<WriteOutcome, ConfigError>
    where
        F: FnOnce(&mut Config) -> Result<CstEdit, ConfigError>,
    {
        let _lock = self.acquire_lock(true, true)?;
        let current = self.read_document_unlocked()?;
        let mut desired = current.snapshot.config.clone();
        let edit = mutation(&mut desired)?;
        desired.validate()?;

        let (yaml, format_preservation) = render_update(&current.source, &desired, &edit)
            .unwrap_or_else(|| {
                serialize_config(&desired).map(|yaml| (yaml, FormatPreservation::CanonicalFallback))
            })?;
        ensure_roundtrip(&self.path, &yaml, &desired)?;
        let acl_protection = self.write_atomic(&yaml)?;
        Ok(WriteOutcome {
            snapshot: self.snapshot(desired),
            format_preservation,
            acl_protection,
        })
    }

    fn read_document_unlocked(&self) -> Result<ConfigDocument, ConfigError> {
        let source = match fs::read_to_string(&self.path) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ConfigError::NotFound {
                    path: self.path.clone(),
                });
            }
            Err(source) => {
                return Err(ConfigError::Io {
                    action: "read",
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let config = parse_config(&self.path, &source)?;
        Ok(ConfigDocument {
            snapshot: self.snapshot(config),
            source,
        })
    }

    fn snapshot(&self, config: Config) -> ConfigSnapshot {
        ConfigSnapshot {
            path: self.path.clone(),
            config,
        }
    }

    fn acquire_lock(&self, exclusive: bool, create_parent: bool) -> Result<File, ConfigError> {
        if create_parent {
            fs::create_dir_all(self.parent_dir()).map_err(|source| ConfigError::Io {
                action: "create configuration directory",
                path: self.parent_dir().to_path_buf(),
                source,
            })?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)
            .map_err(|source| ConfigError::Io {
                action: "open sidecar lock",
                path: self.lock_path.clone(),
                source,
            })?;
        let result = if exclusive {
            FileExt::lock(&lock)
        } else {
            FileExt::lock_shared(&lock)
        };
        result.map_err(|source| ConfigError::Lock {
            mode: if exclusive { "exclusive" } else { "shared" },
            path: self.lock_path.clone(),
            source,
        })?;
        Ok(lock)
    }

    fn write_atomic(&self, yaml: &str) -> Result<AclProtection, ConfigError> {
        let parent = self.parent_dir();
        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| ConfigError::Io {
            action: "create temporary configuration",
            path: parent.to_path_buf(),
            source,
        })?;
        temporary
            .write_all(yaml.as_bytes())
            .map_err(|source| ConfigError::Io {
                action: "write temporary configuration",
                path: temporary.path().to_path_buf(),
                source,
            })?;
        temporary.flush().map_err(|source| ConfigError::Io {
            action: "flush temporary configuration",
            path: temporary.path().to_path_buf(),
            source,
        })?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|source| ConfigError::Io {
                action: "sync temporary configuration",
                path: temporary.path().to_path_buf(),
                source,
            })?;

        let temporary = temporary.into_temp_path();
        let acl_protection =
            self.acl
                .protect_current_user(temporary.as_ref())
                .map_err(|source| ConfigError::Acl {
                    path: temporary.to_path_buf(),
                    source,
                })?;
        match temporary.persist(&self.path) {
            Ok(()) => Ok(acl_protection),
            Err(error) => Err(ConfigError::AtomicReplace {
                path: self.path.clone(),
                source: error.error,
            }),
        }
    }

    fn parent_dir(&self) -> &Path {
        self.path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }
}

enum CstEdit {
    AddCluster { alias: String },
    RemoveCluster { alias: String },
    AddOverride { cluster: String, index: usize },
    RemoveOverride { cluster: String, index: usize },
}

fn find_cluster_key<'a>(config: &'a Config, alias: &str) -> Option<&'a str> {
    config
        .clusters
        .keys()
        .find(|candidate| candidate.eq_ignore_ascii_case(alias))
        .map(String::as_str)
}

fn parse_config(path: &Path, source: &str) -> Result<Config, ConfigError> {
    let parser = ParserConfig::strict().duplicate_key_policy(DuplicateKeyPolicy::Error);
    noyalib::from_str_with_config::<Value>(source, &parser)
        .map_err(|error| yaml_error(path, &error))?;
    let config: Config =
        noyalib::from_str_strict(source).map_err(|error| yaml_error(path, &error))?;
    config.validate()?;
    Ok(config)
}

fn yaml_error(path: &Path, error: &noyalib::Error) -> ConfigError {
    let location = error
        .location()
        .map(|location| (location.line(), location.column()));
    let detail = match error {
        noyalib::Error::UnknownField(field) => format!("unknown field `{field}`"),
        noyalib::Error::MissingField(field) => format!("required field `{field}` is missing"),
        noyalib::Error::DuplicateKey(key) => format!("duplicate YAML key `{key}`"),
        noyalib::Error::KeyCollision(key) => {
            format!("YAML keys collide after conversion at `{key}`")
        }
        noyalib::Error::TypeMismatch { expected, found } => {
            format!("expected {expected}, found {found}")
        }
        noyalib::Error::MoreThanOneDocument => {
            "the configuration must contain exactly one YAML document".to_owned()
        }
        _ => match error.kind() {
            ErrorKind::Syntax => "invalid YAML syntax".to_owned(),
            ErrorKind::DuplicateKey => "duplicate YAML key".to_owned(),
            ErrorKind::KeyCollision => "colliding YAML keys".to_owned(),
            ErrorKind::Budget => "YAML security limit exceeded".to_owned(),
            ErrorKind::Policy => "YAML construct is not allowed".to_owned(),
            ErrorKind::Data => "YAML value does not match the configuration schema".to_owned(),
            ErrorKind::EndOfStream => "unexpected end of YAML input".to_owned(),
            ErrorKind::Io => "YAML input/output error".to_owned(),
            ErrorKind::Other => "invalid YAML configuration value".to_owned(),
            _ => "invalid YAML configuration".to_owned(),
        },
    };
    ConfigError::Yaml {
        path: path.to_path_buf(),
        diagnostic: SafeYamlError::new(detail, location),
    }
}

fn serialize_config(config: &Config) -> Result<String, ConfigError> {
    noyalib::to_string(config).map_err(|_| ConfigError::Serialization)
}

fn ensure_roundtrip(path: &Path, yaml: &str, expected: &Config) -> Result<(), ConfigError> {
    let parsed = parse_config(path, yaml)?;
    if &parsed == expected {
        Ok(())
    } else {
        Err(ConfigError::SerializationInvariant)
    }
}

fn render_update(
    source: &str,
    desired: &Config,
    edit: &CstEdit,
) -> Option<Result<(String, FormatPreservation), ConfigError>> {
    let rendered = try_render_cst(source, desired, edit)?;
    Some(Ok((rendered, FormatPreservation::TargetedCst)))
}

fn try_render_cst(source: &str, desired: &Config, edit: &CstEdit) -> Option<String> {
    let mut document = noyalib::cst::parse_document(source).ok()?;
    let direct = apply_direct_cst_edit(&mut document, desired, edit);
    if !direct {
        document = noyalib::cst::parse_document(source).ok()?;
        if !apply_collection_cst_fallback(&mut document, desired, edit) {
            return None;
        }
    }
    document.validate().ok()?;
    let rendered = document.source().to_owned();
    let parsed = parse_config(Path::new("<CST>"), &rendered).ok()?;
    (parsed == *desired).then_some(rendered)
}

fn apply_direct_cst_edit(
    document: &mut noyalib::cst::Document,
    desired: &Config,
    edit: &CstEdit,
) -> bool {
    match edit {
        CstEdit::AddCluster { alias } => desired
            .clusters
            .get(alias)
            .and_then(yaml_fragment)
            .is_some_and(|fragment| document.insert_entry("clusters", alias, &fragment).is_ok()),
        CstEdit::RemoveCluster { alias } => {
            cst_path_key_safe(alias) && document.remove(&format!("clusters.{alias}")).is_ok()
        }
        CstEdit::AddOverride { cluster, index } => {
            if !cst_path_key_safe(cluster) {
                return false;
            }
            desired
                .clusters
                .get(cluster)
                .and_then(|cluster| cluster.infobase_auth.overrides.get(*index))
                .and_then(yaml_fragment)
                .is_some_and(|fragment| {
                    document
                        .push_back(
                            &format!("clusters.{cluster}.infobase_auth.overrides"),
                            &fragment,
                        )
                        .is_ok()
                })
        }
        CstEdit::RemoveOverride { cluster, index } => {
            cst_path_key_safe(cluster)
                && document
                    .remove(&format!(
                        "clusters.{cluster}.infobase_auth.overrides[{index}]"
                    ))
                    .is_ok()
        }
    }
}

fn apply_collection_cst_fallback(
    document: &mut noyalib::cst::Document,
    desired: &Config,
    edit: &CstEdit,
) -> bool {
    match edit {
        CstEdit::AddCluster { .. } | CstEdit::RemoveCluster { .. } => {
            set_collection(document, "clusters", &desired.clusters, "{}")
        }
        CstEdit::AddOverride { cluster, .. } | CstEdit::RemoveOverride { cluster, .. }
            if cst_path_key_safe(cluster) =>
        {
            desired.clusters.get(cluster).is_some_and(|value| {
                set_collection(
                    document,
                    &format!("clusters.{cluster}.infobase_auth.overrides"),
                    &value.infobase_auth.overrides,
                    "[]",
                )
            })
        }
        CstEdit::AddOverride { .. } | CstEdit::RemoveOverride { .. } => {
            set_collection(document, "clusters", &desired.clusters, "{}")
        }
    }
}

fn set_collection<T>(
    document: &mut noyalib::cst::Document,
    path: &str,
    value: &T,
    empty_fragment: &str,
) -> bool
where
    T: Serialize + CollectionState,
{
    if value.is_empty() {
        return document.set(path, empty_fragment).is_ok();
    }
    let Some(fragment) = yaml_fragment(value) else {
        return false;
    };
    let Some(replacement) = collection_replacement(document, path, &fragment) else {
        return false;
    };
    document.set(path, &replacement).is_ok()
}

trait CollectionState {
    fn is_empty(&self) -> bool;
}

impl<K, V> CollectionState for indexmap::IndexMap<K, V> {
    fn is_empty(&self) -> bool {
        indexmap::IndexMap::is_empty(self)
    }
}

impl<T> CollectionState for Vec<T> {
    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
    }
}

fn collection_replacement(
    document: &noyalib::cst::Document,
    path: &str,
    fragment: &str,
) -> Option<String> {
    let (start, _) = document.span_at(path)?;
    let source = document.source();
    let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
    let before_value = &source[line_start..start];

    if before_value
        .chars()
        .all(|character| matches!(character, ' ' | '\t'))
    {
        let mut lines = fragment.lines();
        let first = lines.next()?;
        let mut replacement = first.to_owned();
        for line in lines {
            replacement.push('\n');
            replacement.push_str(before_value);
            replacement.push_str(line);
        }
        Some(replacement)
    } else {
        let key_indent = before_value
            .bytes()
            .take_while(|byte| *byte == b' ')
            .count();
        let child_indent = " ".repeat(key_indent + document.indent_unit());
        let mut replacement = String::new();
        for line in fragment.lines() {
            replacement.push('\n');
            replacement.push_str(&child_indent);
            replacement.push_str(line);
        }
        Some(replacement)
    }
}

fn yaml_fragment<T>(value: &T) -> Option<String>
where
    T: Serialize + ?Sized,
{
    noyalib::to_string(value)
        .ok()
        .map(|yaml| yaml.trim_end_matches(&['\r', '\n'][..]).to_owned())
}

fn cst_path_key_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::config::{
        AuthConfig, DiscoveredCluster, InfobaseAuthConfig, Password, RacConfig, RasConfig,
    };

    fn cluster() -> ClusterConfig {
        ClusterConfig {
            ras: RasConfig {
                host: "ras.example.test".to_owned(),
                port: 1545,
            },
            discovered_cluster: DiscoveredCluster {
                uuid: Uuid::new_v4(),
                name: "Development".to_owned(),
                host: "cluster.example.test".to_owned(),
                port: 1541,
            },
            rac: RacConfig::default(),
            cluster_auth: AuthConfig::password("admin", Password::new("top-secret")),
            infobase_auth: InfobaseAuthConfig::default(),
        }
    }

    #[test]
    fn strict_schema_rejects_unknown_and_cross_mode_fields_without_leaking_password() {
        let yaml = r#"
schema_version: 1
settings:
  timeout_seconds: 30
  rac_path: null
  log_level: INFO
clusters:
  dev:
    ras:
      host: ras.example.test
      port: 1545
    discovered_cluster:
      uuid: 00000000-0000-0000-0000-000000000000
      name: Development
      host: cluster.example.test
      port: 1541
    rac:
      path: null
      version: auto
    cluster_auth:
      mode: os
      user: admin
      password: should-never-appear
    infobase_auth:
      default:
        mode: none
      overrides: []
"#;
        let error = parse_config(Path::new("config.yaml"), yaml).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("should-never-appear"));
        assert!(rendered.contains("password"));
    }

    #[test]
    fn password_mode_requires_user_and_password_fields() {
        let yaml = r#"
schema_version: 1
settings:
  timeout_seconds: 30
  rac_path: null
  log_level: INFO
clusters:
  dev:
    ras: { host: ras.example.test, port: 1545 }
    discovered_cluster:
      uuid: 00000000-0000-0000-0000-000000000000
      name: Development
      host: cluster.example.test
      port: 1541
    rac: { path: null, version: auto }
    cluster_auth: { mode: password, user: admin }
    infobase_auth:
      default: { mode: none }
      overrides: []
"#;
        let error = parse_config(Path::new("config.yaml"), yaml).unwrap_err();
        assert!(format!("{error}").contains("password"));
    }

    #[test]
    fn atomic_updates_roundtrip_and_keep_untouched_comments() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let store = ConfigStore::new(path.clone()).unwrap();
        store.create_default().unwrap();

        let source = fs::read_to_string(&path).unwrap();
        fs::write(&path, format!("# keep this comment\n{source}")).unwrap();

        let outcome = store.add_cluster("dev", cluster()).unwrap();
        assert_eq!(outcome.snapshot.clusters.len(), 1);
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("# keep this comment")
        );
        assert_eq!(store.load().unwrap().clusters.len(), 1);

        store
            .add_override(
                "DEV",
                InfobaseAuthOverride::none("zup_corp", Some(Uuid::new_v4())),
            )
            .unwrap();
        assert_eq!(
            store.load().unwrap().clusters["dev"]
                .infobase_auth
                .overrides
                .len(),
            1
        );
        store
            .remove_override("dev", OverrideSelector::by_name("ZUP_CORP"))
            .unwrap();
        store.remove_cluster("DEV").unwrap();
        assert!(store.load().unwrap().clusters.is_empty());
    }

    struct RejectAcl;

    impl AclProtector for RejectAcl {
        fn protect_current_user(&self, _path: &Path) -> Result<AclProtection, AclError> {
            Err(AclError::new("test ACL rejection"))
        }
    }

    #[test]
    fn failed_pre_replace_step_leaves_original_file_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        ConfigStore::new(path.clone())
            .unwrap()
            .create_default()
            .unwrap();
        let before = fs::read(&path).unwrap();

        let store = ConfigStore::new(path.clone())
            .unwrap()
            .with_acl_protector(RejectAcl);
        assert!(matches!(
            store.add_cluster("dev", cluster()),
            Err(ConfigError::Acl { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(store.load().unwrap().clusters.is_empty());
    }
}
