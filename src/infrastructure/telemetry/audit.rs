use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs4::FileExt;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::infrastructure::windows::{
    IdentityError, WindowsIdentityProvider, WindowsPathError, WindowsPaths,
};

use super::{REDACTED, SecretRedactor};

pub mod audit_actions {
    pub const SESSION_KILL: &str = "session_kill";
    pub const CONNECTION_KILL: &str = "connection_kill";
    pub const CLUSTER_ADD: &str = "cluster_add";
    pub const CLUSTER_REMOVE: &str = "cluster_remove";
    pub const CREDENTIAL_OVERRIDE_CHANGE: &str = "credential_override_change";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Failure,
    Partial,
    Cancelled,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct AuditContext {
    pub cluster_alias: Option<String>,
    pub cluster_uuid: Option<Uuid>,
    pub infobase_name: Option<String>,
    pub infobase_uuid: Option<Uuid>,
    pub session_uuid: Option<Uuid>,
    pub connection_uuid: Option<Uuid>,
    pub numeric_id: Option<u64>,
    pub message: Option<String>,
    pub reason: Option<String>,
}

impl fmt::Debug for AuditContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditContext")
            .field("cluster_alias", &self.cluster_alias)
            .field("cluster_uuid", &self.cluster_uuid)
            .field("infobase_name", &self.infobase_name)
            .field("infobase_uuid", &self.infobase_uuid)
            .field("session_uuid", &self.session_uuid)
            .field("connection_uuid", &self.connection_uuid)
            .field("numeric_id", &self.numeric_id)
            .field("message", &self.message.as_ref().map(|_| REDACTED))
            .field("reason", &self.reason.as_ref().map(|_| REDACTED))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub windows_user: String,
    pub action: String,
    pub context: AuditContext,
    pub result: AuditResult,
    pub error_code: Option<String>,
    pub error: Option<String>,
}

impl AuditEvent {
    pub fn new(
        windows_user: impl Into<String>,
        action: impl Into<String>,
        result: AuditResult,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            windows_user: windows_user.into(),
            action: action.into(),
            context: AuditContext::default(),
            result,
            error_code: None,
            error: None,
        }
    }

    pub fn for_current_user<P>(
        identity_provider: &P,
        action: impl Into<String>,
        result: AuditResult,
    ) -> Result<Self, IdentityError>
    where
        P: WindowsIdentityProvider + ?Sized,
    {
        let identity = identity_provider.current_identity()?;
        Ok(Self::new(identity.to_string_lossy(), action, result))
    }

    pub fn with_context(mut self, context: AuditContext) -> Self {
        self.context = context;
        self
    }

    pub fn with_error(mut self, code: impl Into<String>, error: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self.error = Some(error.into());
        self
    }
}

impl fmt::Debug for AuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditEvent")
            .field("timestamp", &self.timestamp)
            .field("windows_user", &self.windows_user)
            .field("action", &self.action)
            .field("context", &self.context)
            .field("result", &self.result)
            .field("error_code", &self.error_code)
            .field("error", &self.error.as_ref().map(|_| REDACTED))
            .finish()
    }
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditWriteError>;
}

#[derive(Clone)]
pub struct JsonlAuditSink {
    path: PathBuf,
    redactor: SecretRedactor,
}

impl JsonlAuditSink {
    pub fn new(path: impl Into<PathBuf>, redactor: SecretRedactor) -> Self {
        Self {
            path: path.into(),
            redactor,
        }
    }

    pub fn at_default_path(redactor: SecretRedactor) -> Result<Self, AuditWriteError> {
        let paths = WindowsPaths::discover()?;
        Ok(Self::new(paths.audit_file(), redactor))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn redactor(&self) -> &SecretRedactor {
        &self.redactor
    }

    pub fn record(&self, event: &AuditEvent) -> Result<(), AuditWriteError> {
        <Self as AuditSink>::record(self, event)
    }
}

impl fmt::Debug for JsonlAuditSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonlAuditSink")
            .field("path", &self.path)
            .field("redactor", &self.redactor)
            .finish()
    }
}

impl AuditSink for JsonlAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditWriteError> {
        let serialized = SanitizedAuditEvent::from_event(event, &self.redactor);
        let mut line = serde_json::to_vec(&serialized).map_err(AuditWriteError::Serialize)?;
        line.push(b'\n');

        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| AuditWriteError::InvalidPath(self.path.clone()))?;
        fs::create_dir_all(parent).map_err(|source| self.io_error("создать каталог", source))?;

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| self.io_error("открыть", source))?;

        FileExt::lock(&file).map_err(|source| self.io_error("заблокировать", source))?;
        let write_result = self.write_locked(&mut file, &line);
        let unlock_result =
            FileExt::unlock(&file).map_err(|source| self.io_error("снять блокировку с", source));

        match (write_result, unlock_result) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl JsonlAuditSink {
    fn write_locked(&self, file: &mut File, line: &[u8]) -> Result<(), AuditWriteError> {
        let original_length = file
            .metadata()
            .map_err(|source| self.io_error("прочитать метаданные", source))?
            .len();

        let result = (|| {
            file.write_all(line)
                .map_err(|source| self.io_error("записать", source))?;
            file.flush()
                .map_err(|source| self.io_error("сбросить буфер", source))?;
            file.sync_data()
                .map_err(|source| self.io_error("синхронизировать", source))?;
            Ok(())
        })();

        if result.is_err() {
            // Keep the JSONL invariant after a partial write. Rollback is
            // best-effort; the original I/O error remains the useful cause.
            let _ = file.set_len(original_length);
            let _ = file.sync_data();
        }
        result
    }

    fn io_error(&self, operation: &'static str, source: io::Error) -> AuditWriteError {
        AuditWriteError::Io {
            operation,
            path: self.path.clone(),
            source,
        }
    }
}

#[derive(Debug, Error)]
pub enum AuditWriteError {
    #[error("не удалось определить путь аудита: {0}")]
    WindowsPath(#[from] WindowsPathError),
    #[error("путь файла аудита не содержит каталога: {0:?}")]
    InvalidPath(PathBuf),
    #[error("не удалось сериализовать событие аудита: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("не удалось {operation} файл аудита {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Serialize)]
struct SanitizedAuditEvent {
    timestamp: DateTime<Utc>,
    windows_user: String,
    action: String,
    cluster_alias: Option<String>,
    cluster_uuid: Option<Uuid>,
    infobase_name: Option<String>,
    infobase_uuid: Option<Uuid>,
    session_uuid: Option<Uuid>,
    connection_uuid: Option<Uuid>,
    numeric_id: Option<u64>,
    message: Option<String>,
    reason: Option<String>,
    result: AuditResult,
    error_code: Option<String>,
    error: Option<String>,
}

impl SanitizedAuditEvent {
    fn from_event(event: &AuditEvent, redactor: &SecretRedactor) -> Self {
        let redact_option =
            |value: &Option<String>| value.as_deref().map(|value| redactor.redact(value));

        Self {
            timestamp: event.timestamp,
            windows_user: redactor.redact(&event.windows_user),
            action: redactor.redact(&event.action),
            cluster_alias: redact_option(&event.context.cluster_alias),
            cluster_uuid: event.context.cluster_uuid,
            infobase_name: redact_option(&event.context.infobase_name),
            infobase_uuid: event.context.infobase_uuid,
            session_uuid: event.context.session_uuid,
            connection_uuid: event.context.connection_uuid,
            numeric_id: event.context.numeric_id,
            message: redact_option(&event.context.message),
            reason: redact_option(&event.context.reason),
            result: event.result,
            error_code: redact_option(&event.error_code),
            error: redact_option(&event.error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_one_complete_utf8_json_line_without_passwords() {
        let directory = tempfile::tempdir().unwrap();
        let audit_path = directory.path().join("logs").join("audit.jsonl");
        let redactor = SecretRedactor::with_secrets(["plain-text-password"]);
        let sink = JsonlAuditSink::new(&audit_path, redactor);

        let cluster_uuid = Uuid::new_v4();
        let infobase_uuid = Uuid::new_v4();
        let session_uuid = Uuid::new_v4();
        let mut event = AuditEvent::new(
            r"DOMAIN\Иванов",
            audit_actions::SESSION_KILL,
            AuditResult::Failure,
        )
        .with_context(AuditContext {
            cluster_alias: Some("prod".to_owned()),
            cluster_uuid: Some(cluster_uuid),
            infobase_name: Some("Зарплата".to_owned()),
            infobase_uuid: Some(infobase_uuid),
            session_uuid: Some(session_uuid),
            connection_uuid: None,
            numeric_id: Some(42),
            message: Some("Причина с переводом\nстроки --password plain-text-password".to_owned()),
            reason: Some("password: plain-text-password".to_owned()),
        })
        .with_error(
            "rac_failed",
            "rac --cluster-pwd=plain-text-password завершился с ошибкой",
        );
        event.timestamp = DateTime::parse_from_rfc3339("2026-08-11T10:11:12Z")
            .unwrap()
            .with_timezone(&Utc);

        sink.record(&event).unwrap();

        let bytes = fs::read(&audit_path).unwrap();
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(bytes.last(), Some(&b'\n'));
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("plain-text-password"));
        assert!(text.contains("[REDACTED]"));

        let value: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(value["timestamp"], "2026-08-11T10:11:12Z");
        assert_eq!(value["windows_user"], r"DOMAIN\Иванов");
        assert_eq!(value["action"], audit_actions::SESSION_KILL);
        assert_eq!(value["cluster_alias"], "prod");
        assert_eq!(value["cluster_uuid"], cluster_uuid.to_string());
        assert_eq!(value["infobase_name"], "Зарплата");
        assert_eq!(value["infobase_uuid"], infobase_uuid.to_string());
        assert_eq!(value["session_uuid"], session_uuid.to_string());
        assert_eq!(value["numeric_id"], 42);
        assert_eq!(value["result"], "failure");
        assert_eq!(value["error_code"], "rac_failed");
        assert!(value.get("connection_uuid").is_some());
        assert!(value.get("reason").is_some());
        assert!(value.get("error").is_some());
    }

    #[test]
    fn debug_output_omits_free_form_message_reason_and_error() {
        let mut event = AuditEvent::new("user", "action", AuditResult::Failure);
        event.context.message = Some("--password secret-one".to_owned());
        event.context.reason = Some("password: secret-two".to_owned());
        event.error = Some("secret-three".to_owned());

        let debug = format!("{event:?}");
        assert!(!debug.contains("secret-one"));
        assert!(!debug.contains("secret-two"));
        assert!(!debug.contains("secret-three"));
    }
}
