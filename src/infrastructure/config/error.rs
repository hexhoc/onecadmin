use std::io;
use std::path::PathBuf;

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("unsupported schema_version {found}; expected {expected}")]
    UnsupportedSchemaVersion { expected: u32, found: u32 },

    #[error("settings.timeout_seconds must be greater than zero")]
    InvalidTimeout,

    #[error("unsupported settings.log_level `{value}`; use TRACE, DEBUG, INFO, WARN, or ERROR")]
    InvalidLogLevel { value: String },

    #[error(
        "invalid cluster alias `{alias}`; allowed characters are ASCII letters, digits, '.', '_', '-', and ':'"
    )]
    InvalidAlias { alias: String },

    #[error("cluster aliases `{first}` and `{second}` are equal ignoring ASCII case")]
    DuplicateAlias { first: String, second: String },

    #[error("{field} must be in the range 1..=65535")]
    InvalidPort { field: String },

    #[error("{field} must not be empty")]
    EmptyField { field: String },

    #[error("{field} must not be an empty path")]
    EmptyPath { field: String },

    #[error("invalid RAC version `{value}` in {field}; expected `auto` or 8.3.20+")]
    InvalidRacVersion { field: String, value: String },

    #[error(
        "duplicate infobase override name `{infobase}` in cluster `{cluster}` at indexes {first} and {second}"
    )]
    DuplicateOverrideName {
        cluster: String,
        infobase: String,
        first: usize,
        second: usize,
    },

    #[error(
        "duplicate infobase override UUID `{uuid}` in cluster `{cluster}` at indexes {first} and {second}"
    )]
    DuplicateOverrideUuid {
        cluster: String,
        uuid: Uuid,
        first: usize,
        second: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeYamlError {
    detail: String,
    line: Option<usize>,
    column: Option<usize>,
}

impl SafeYamlError {
    pub fn new(detail: impl Into<String>, location: Option<(usize, usize)>) -> Self {
        let (line, column) = location
            .map(|(line, column)| (Some(line), Some(column)))
            .unwrap_or((None, None));
        Self {
            detail: detail.into(),
            line,
            column,
        }
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub fn line(&self) -> Option<usize> {
        self.line
    }

    pub fn column(&self) -> Option<usize> {
        self.column
    }
}

impl std::fmt::Display for SafeYamlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.line, self.column) {
            (Some(line), Some(column)) => {
                write!(formatter, "{} at line {line}, column {column}", self.detail)
            }
            _ => formatter.write_str(&self.detail),
        }
    }
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct AclError {
    message: String,
}

impl AclError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration path is empty")]
    EmptyConfigPath,

    #[error("APPDATA is not set; pass --config or set ONECADMIN_CONFIG")]
    AppDataUnavailable,

    #[error("configuration file does not exist: {path:?}")]
    NotFound { path: PathBuf },

    #[error("configuration file already exists: {path:?}")]
    AlreadyExists { path: PathBuf },

    #[error("cannot {action} {path:?}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("cannot acquire {mode} configuration lock {path:?}: {source}")]
    Lock {
        mode: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid YAML configuration {path:?}: {diagnostic}")]
    Yaml {
        path: PathBuf,
        diagnostic: SafeYamlError,
    },

    #[error(transparent)]
    Validation(#[from] ValidationError),

    #[error("cluster `{requested}` already exists as `{existing}`")]
    ClusterAlreadyExists { requested: String, existing: String },

    #[error("cluster `{alias}` was not found")]
    ClusterNotFound { alias: String },

    #[error("infobase override `{target}` was not found in cluster `{cluster}`")]
    OverrideNotFound { cluster: String, target: String },

    #[error("cannot serialize validated configuration")]
    Serialization,

    #[error("serialized configuration did not pass its own schema validation")]
    SerializationInvariant,

    #[error("cannot protect temporary configuration {path:?} for the current user: {source}")]
    Acl {
        path: PathBuf,
        #[source]
        source: AclError,
    },

    #[error("cannot atomically replace configuration {path:?}: {source}")]
    AtomicReplace {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}
