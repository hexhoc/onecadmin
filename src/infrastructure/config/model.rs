use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::ValidationError;

pub const CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Password(String);

impl Password {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password([REDACTED])")
    }
}

impl fmt::Display for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Serialize for Password {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Unsupported(String),
}

impl LogLevel {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Unsupported(value) => value,
        }
    }

    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported(_))
    }

    fn from_yaml(value: String) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "TRACE" => Self::Trace,
            "DEBUG" => Self::Debug,
            "INFO" => Self::Info,
            "WARN" | "WARNING" => Self::Warn,
            "ERROR" => Self::Error,
            _ => Self::Unsupported(value),
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let level = Self::from_yaml(value.to_owned());
        level
            .is_supported()
            .then_some(level)
            .ok_or("unsupported log level")
    }
}

impl Serialize for LogLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LogLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from_yaml)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RacVersion {
    #[default]
    Auto,
    Exact(String),
}

impl RacVersion {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Auto => "auto",
            Self::Exact(version) => version,
        }
    }
}

impl Serialize for RacVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RacVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = String::deserialize(deserializer)?;
        if version.eq_ignore_ascii_case("auto") {
            Ok(Self::Auto)
        } else {
            Ok(Self::Exact(version))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub settings: Settings,
    pub clusters: IndexMap<String, ClusterConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            settings: Settings::default(),
            clusters: IndexMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub timeout_seconds: u64,
    pub rac_path: Option<PathBuf>,
    pub log_level: LogLevel,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            rac_path: None,
            log_level: LogLevel::Info,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfig {
    pub ras: RasConfig,
    pub discovered_cluster: DiscoveredCluster,
    pub rac: RacConfig,
    pub cluster_auth: AuthConfig,
    pub infobase_auth: InfobaseAuthConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RasConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredCluster {
    pub uuid: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RacConfig {
    pub path: Option<PathBuf>,
    pub version: RacVersion,
}

impl Default for RacConfig {
    fn default() -> Self {
        Self {
            path: None,
            version: RacVersion::Auto,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    Password,
    Os,
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum AuthConfig {
    Password(PasswordAuth),
    Os(OsAuth),
    None(NoAuth),
}

impl AuthConfig {
    pub fn password(user: impl Into<String>, password: impl Into<Password>) -> Self {
        Self::Password(PasswordAuth {
            user: user.into(),
            password: password.into(),
        })
    }

    pub fn os(user: impl Into<String>, os_user: Option<String>) -> Self {
        Self::Os(OsAuth {
            user: user.into(),
            os_user,
        })
    }

    pub fn none() -> Self {
        Self::None(NoAuth {})
    }

    pub fn mode(&self) -> AuthMode {
        match self {
            Self::Password(_) => AuthMode::Password,
            Self::Os(_) => AuthMode::Os,
            Self::None(_) => AuthMode::None,
        }
    }

    pub fn as_ref(&self) -> AuthRef<'_> {
        match self {
            Self::Password(auth) => AuthRef::Password {
                user: &auth.user,
                password: &auth.password,
            },
            Self::Os(auth) => AuthRef::Os {
                user: &auth.user,
                os_user: auth.os_user.as_deref(),
            },
            Self::None(_) => AuthRef::None,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self::none()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasswordAuth {
    pub user: String,
    pub password: Password,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OsAuth {
    pub user: String,
    pub os_user: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NoAuth {}

#[derive(Clone, Copy, Debug)]
pub enum AuthRef<'a> {
    Password {
        user: &'a str,
        password: &'a Password,
    },
    Os {
        user: &'a str,
        os_user: Option<&'a str>,
    },
    None,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InfobaseAuthConfig {
    pub default: AuthConfig,
    pub overrides: Vec<InfobaseAuthOverride>,
}

impl InfobaseAuthConfig {
    pub fn find_override(
        &self,
        infobase_uuid: Option<Uuid>,
        infobase: &str,
    ) -> Option<&InfobaseAuthOverride> {
        infobase_uuid
            .and_then(|uuid| {
                self.overrides
                    .iter()
                    .find(|entry| entry.infobase_uuid() == Some(uuid))
            })
            .or_else(|| {
                self.overrides
                    .iter()
                    .find(|entry| unicode_case_eq(entry.infobase(), infobase))
            })
    }

    pub fn resolve(&self, infobase_uuid: Option<Uuid>, infobase: &str) -> AuthRef<'_> {
        self.find_override(infobase_uuid, infobase)
            .map(InfobaseAuthOverride::as_ref)
            .unwrap_or_else(|| self.default.as_ref())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum InfobaseAuthOverride {
    Password(PasswordInfobaseAuthOverride),
    Os(OsInfobaseAuthOverride),
    None(NoneInfobaseAuthOverride),
}

impl InfobaseAuthOverride {
    pub fn password(
        infobase: impl Into<String>,
        infobase_uuid: Option<Uuid>,
        user: impl Into<String>,
        password: impl Into<Password>,
    ) -> Self {
        Self::Password(PasswordInfobaseAuthOverride {
            infobase: infobase.into(),
            infobase_uuid,
            user: user.into(),
            password: password.into(),
        })
    }

    pub fn os(
        infobase: impl Into<String>,
        infobase_uuid: Option<Uuid>,
        user: impl Into<String>,
        os_user: Option<String>,
    ) -> Self {
        Self::Os(OsInfobaseAuthOverride {
            infobase: infobase.into(),
            infobase_uuid,
            user: user.into(),
            os_user,
        })
    }

    pub fn none(infobase: impl Into<String>, infobase_uuid: Option<Uuid>) -> Self {
        Self::None(NoneInfobaseAuthOverride {
            infobase: infobase.into(),
            infobase_uuid,
        })
    }

    pub fn infobase(&self) -> &str {
        match self {
            Self::Password(entry) => &entry.infobase,
            Self::Os(entry) => &entry.infobase,
            Self::None(entry) => &entry.infobase,
        }
    }

    pub fn infobase_uuid(&self) -> Option<Uuid> {
        match self {
            Self::Password(entry) => entry.infobase_uuid,
            Self::Os(entry) => entry.infobase_uuid,
            Self::None(entry) => entry.infobase_uuid,
        }
    }

    pub fn mode(&self) -> AuthMode {
        match self {
            Self::Password(_) => AuthMode::Password,
            Self::Os(_) => AuthMode::Os,
            Self::None(_) => AuthMode::None,
        }
    }

    pub fn as_ref(&self) -> AuthRef<'_> {
        match self {
            Self::Password(entry) => AuthRef::Password {
                user: &entry.user,
                password: &entry.password,
            },
            Self::Os(entry) => AuthRef::Os {
                user: &entry.user,
                os_user: entry.os_user.as_deref(),
            },
            Self::None(_) => AuthRef::None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasswordInfobaseAuthOverride {
    pub infobase: String,
    pub infobase_uuid: Option<Uuid>,
    pub user: String,
    pub password: Password,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OsInfobaseAuthOverride {
    pub infobase: String,
    pub infobase_uuid: Option<Uuid>,
    pub user: String,
    pub os_user: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NoneInfobaseAuthOverride {
    pub infobase: String,
    pub infobase_uuid: Option<Uuid>,
}

impl Config {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchemaVersion {
                expected: CONFIG_SCHEMA_VERSION,
                found: self.schema_version,
            });
        }
        if self.settings.timeout_seconds == 0 {
            return Err(ValidationError::InvalidTimeout);
        }
        if let LogLevel::Unsupported(value) = &self.settings.log_level {
            return Err(ValidationError::InvalidLogLevel {
                value: value.clone(),
            });
        }
        validate_optional_path(&self.settings.rac_path, "settings.rac_path")?;

        let mut aliases = HashMap::<String, &str>::new();
        for (alias, cluster) in &self.clusters {
            validate_alias(alias)?;
            let folded = alias.to_ascii_lowercase();
            if let Some(first) = aliases.insert(folded, alias) {
                return Err(ValidationError::DuplicateAlias {
                    first: first.to_owned(),
                    second: alias.clone(),
                });
            }
            validate_cluster(alias, cluster)?;
        }
        Ok(())
    }
}

fn validate_alias(alias: &str) -> Result<(), ValidationError> {
    if alias.is_empty()
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(ValidationError::InvalidAlias {
            alias: alias.to_owned(),
        });
    }
    Ok(())
}

fn validate_cluster(alias: &str, cluster: &ClusterConfig) -> Result<(), ValidationError> {
    validate_non_empty(&cluster.ras.host, format!("clusters.{alias}.ras.host"))?;
    validate_port(cluster.ras.port, format!("clusters.{alias}.ras.port"))?;
    validate_non_empty(
        &cluster.discovered_cluster.host,
        format!("clusters.{alias}.discovered_cluster.host"),
    )?;
    validate_port(
        cluster.discovered_cluster.port,
        format!("clusters.{alias}.discovered_cluster.port"),
    )?;
    validate_optional_path(&cluster.rac.path, &format!("clusters.{alias}.rac.path"))?;
    if let RacVersion::Exact(version) = &cluster.rac.version
        && !is_supported_rac_version(version)
    {
        return Err(ValidationError::InvalidRacVersion {
            field: format!("clusters.{alias}.rac.version"),
            value: version.clone(),
        });
    }
    validate_auth(
        &cluster.cluster_auth,
        &format!("clusters.{alias}.cluster_auth"),
    )?;
    validate_auth(
        &cluster.infobase_auth.default,
        &format!("clusters.{alias}.infobase_auth.default"),
    )?;
    validate_overrides(alias, &cluster.infobase_auth.overrides)
}

fn validate_auth(auth: &AuthConfig, path: &str) -> Result<(), ValidationError> {
    match auth {
        AuthConfig::Password(auth) => {
            validate_non_empty(&auth.user, format!("{path}.user"))?;
            validate_non_empty(auth.password.expose_secret(), format!("{path}.password"))
        }
        AuthConfig::Os(auth) => {
            validate_non_empty(&auth.user, format!("{path}.user"))?;
            if let Some(os_user) = &auth.os_user {
                validate_non_empty(os_user, format!("{path}.os_user"))?;
            }
            Ok(())
        }
        AuthConfig::None(_) => Ok(()),
    }
}

fn validate_overrides(
    alias: &str,
    overrides: &[InfobaseAuthOverride],
) -> Result<(), ValidationError> {
    let mut names = HashMap::<String, usize>::new();
    let mut uuids = HashMap::<Uuid, usize>::new();
    for (index, entry) in overrides.iter().enumerate() {
        validate_non_empty(
            entry.infobase(),
            format!("clusters.{alias}.infobase_auth.overrides[{index}].infobase"),
        )?;
        match entry {
            InfobaseAuthOverride::Password(entry) => {
                validate_non_empty(
                    &entry.user,
                    format!("clusters.{alias}.infobase_auth.overrides[{index}].user"),
                )?;
                validate_non_empty(
                    entry.password.expose_secret(),
                    format!("clusters.{alias}.infobase_auth.overrides[{index}].password"),
                )?;
            }
            InfobaseAuthOverride::Os(entry) => {
                validate_non_empty(
                    &entry.user,
                    format!("clusters.{alias}.infobase_auth.overrides[{index}].user"),
                )?;
                if let Some(os_user) = &entry.os_user {
                    validate_non_empty(
                        os_user,
                        format!("clusters.{alias}.infobase_auth.overrides[{index}].os_user"),
                    )?;
                }
            }
            InfobaseAuthOverride::None(_) => {}
        }

        let folded = entry.infobase().to_lowercase();
        if let Some(first) = names.insert(folded, index) {
            return Err(ValidationError::DuplicateOverrideName {
                cluster: alias.to_owned(),
                infobase: entry.infobase().to_owned(),
                first,
                second: index,
            });
        }
        if let Some(uuid) = entry.infobase_uuid()
            && let Some(first) = uuids.insert(uuid, index)
        {
            return Err(ValidationError::DuplicateOverrideUuid {
                cluster: alias.to_owned(),
                uuid,
                first,
                second: index,
            });
        }
    }
    Ok(())
}

fn validate_non_empty(value: &str, field: String) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        Err(ValidationError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn validate_port(port: u16, field: String) -> Result<(), ValidationError> {
    if port == 0 {
        Err(ValidationError::InvalidPort { field })
    } else {
        Ok(())
    }
}

fn validate_optional_path(path: &Option<PathBuf>, field: &str) -> Result<(), ValidationError> {
    if path
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        Err(ValidationError::EmptyPath {
            field: field.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn is_supported_rac_version(value: &str) -> bool {
    let components = value
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>();
    let Ok(components) = components else {
        return false;
    };
    matches!(components.as_slice(), [8, 3, patch, _] if *patch >= 20)
}

fn unicode_case_eq(left: &str, right: &str) -> bool {
    left.to_lowercase() == right.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster() -> ClusterConfig {
        ClusterConfig {
            ras: RasConfig {
                host: "ras.example.test".to_owned(),
                port: 1545,
            },
            discovered_cluster: DiscoveredCluster {
                uuid: Uuid::nil(),
                name: "Development".to_owned(),
                host: "cluster.example.test".to_owned(),
                port: 1541,
            },
            rac: RacConfig::default(),
            cluster_auth: AuthConfig::password("admin", Password::new("secret")),
            infobase_auth: InfobaseAuthConfig::default(),
        }
    }

    #[test]
    fn validates_aliases_case_insensitively() {
        let mut config = Config::default();
        config.clusters.insert("Dev".to_owned(), cluster());
        config.clusters.insert("dev".to_owned(), cluster());
        assert!(matches!(
            config.validate(),
            Err(ValidationError::DuplicateAlias { .. })
        ));

        let mut config = Config::default();
        config.clusters.insert("bad alias".to_owned(), cluster());
        assert!(matches!(
            config.validate(),
            Err(ValidationError::InvalidAlias { .. })
        ));
    }

    #[test]
    fn validates_timeout_ports_schema_and_log_level() {
        let mut config = Config::default();
        config.settings.timeout_seconds = 0;
        assert_eq!(config.validate(), Err(ValidationError::InvalidTimeout));

        let config = Config {
            schema_version: 2,
            ..Config::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ValidationError::UnsupportedSchemaVersion { .. })
        ));

        let mut config = Config::default();
        config.settings.log_level = LogLevel::Unsupported("VERBOSE".to_owned());
        assert!(matches!(
            config.validate(),
            Err(ValidationError::InvalidLogLevel { .. })
        ));

        let mut invalid_cluster = cluster();
        invalid_cluster.ras.port = 0;
        let mut config = Config::default();
        config.clusters.insert("dev".to_owned(), invalid_cluster);
        assert!(matches!(
            config.validate(),
            Err(ValidationError::InvalidPort { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_override_names_and_uuids() {
        let uuid = Uuid::new_v4();
        let mut value = cluster();
        value.infobase_auth.overrides = vec![
            InfobaseAuthOverride::none("ZUP", Some(uuid)),
            InfobaseAuthOverride::none("zup", None),
        ];
        let mut config = Config::default();
        config.clusters.insert("dev".to_owned(), value);
        assert!(matches!(
            config.validate(),
            Err(ValidationError::DuplicateOverrideName { .. })
        ));

        let mut value = cluster();
        value.infobase_auth.overrides = vec![
            InfobaseAuthOverride::none("first", Some(uuid)),
            InfobaseAuthOverride::none("second", Some(uuid)),
        ];
        let mut config = Config::default();
        config.clusters.insert("dev".to_owned(), value);
        assert!(matches!(
            config.validate(),
            Err(ValidationError::DuplicateOverrideUuid { .. })
        ));
    }

    #[test]
    fn password_debug_is_redacted() {
        let password = Password::new("do-not-print-me");
        let debug = format!("{password:?}");
        assert!(!debug.contains(password.expose_secret()));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn override_resolution_prefers_uuid_then_unicode_casefolded_name() {
        let uuid = Uuid::new_v4();
        let auth = InfobaseAuthConfig {
            default: AuthConfig::none(),
            overrides: vec![
                InfobaseAuthOverride::password(
                    "Baza",
                    Some(uuid),
                    "uuid-user",
                    Password::new("one"),
                ),
                InfobaseAuthOverride::os(
                    "Production",
                    None,
                    "name-user",
                    Some("DOMAIN\\user".to_owned()),
                ),
            ],
        };

        assert_eq!(
            auth.find_override(Some(uuid), "Production")
                .unwrap()
                .infobase(),
            "Baza"
        );
        assert_eq!(
            auth.find_override(None, "production").unwrap().infobase(),
            "Production"
        );
    }
}
