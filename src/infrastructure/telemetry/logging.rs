use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use file_rotate::compression::Compression;
use file_rotate::suffix::AppendCount;
use file_rotate::{ContentLimit, FileRotate};
use thiserror::Error;
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::EnvFilter;

use crate::infrastructure::windows::{TECHNICAL_LOG_FILE_NAME, WindowsPathError, WindowsPaths};

use super::SecretRedactor;

pub const LOG_FILE_SIZE_BYTES: usize = 10 * 1024 * 1024;
/// Includes the active file; suffixes `.1` through `.4` are retained.
pub const LOG_FILE_COUNT: usize = 5;

#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("не удалось определить каталог технического лога: {0}")]
    WindowsPath(#[from] WindowsPathError),
    #[error("не удалось создать каталог технического лога {path:?}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("не удалось открыть технический лог {path:?}: {source}")]
    OpenLog {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("некорректный фильтр уровня технического лога {filter:?}: {details}")]
    InvalidFilter { filter: String, details: String },
    #[error("не удалось установить глобальный tracing subscriber: {details}")]
    InstallSubscriber { details: String },
}

/// Must remain alive until process shutdown so the non-blocking writer drains
/// and flushes all queued tracing events.
#[must_use = "LoggingGuard должен храниться до завершения процесса"]
pub struct LoggingGuard {
    _worker_guard: WorkerGuard,
    redactor: SecretRedactor,
    log_path: PathBuf,
}

impl LoggingGuard {
    pub fn redactor(&self) -> &SecretRedactor {
        &self.redactor
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }
}

impl std::fmt::Debug for LoggingGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoggingGuard")
            .field("log_path", &self.log_path)
            .field("redactor", &self.redactor)
            .finish_non_exhaustive()
    }
}

pub fn init_default_logging(log_filter: &str) -> Result<LoggingGuard, LoggingError> {
    let paths = WindowsPaths::discover()?;
    init_logging(paths.logs_directory(), log_filter)
}

pub fn init_logging(
    logs_directory: impl AsRef<Path>,
    log_filter: &str,
) -> Result<LoggingGuard, LoggingError> {
    init_logging_with_redactor(logs_directory, log_filter, SecretRedactor::new())
}

pub fn init_logging_with_redactor(
    logs_directory: impl AsRef<Path>,
    log_filter: &str,
    redactor: SecretRedactor,
) -> Result<LoggingGuard, LoggingError> {
    let logs_directory = logs_directory.as_ref();
    fs::create_dir_all(logs_directory).map_err(|source| LoggingError::CreateDirectory {
        path: logs_directory.to_path_buf(),
        source,
    })?;

    let log_path = logs_directory.join(TECHNICAL_LOG_FILE_NAME);
    // FileRotate opens lazily. Preflight here so bootstrap gets a clear error
    // instead of silently losing the first background log event.
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|source| LoggingError::OpenLog {
            path: log_path.clone(),
            source,
        })?;

    let filter = EnvFilter::try_new(log_filter).map_err(|error| LoggingError::InvalidFilter {
        filter: log_filter.to_owned(),
        details: error.to_string(),
    })?;

    let rotating_file = FileRotate::new(
        &log_path,
        AppendCount::new(LOG_FILE_COUNT - 1),
        // Rotate only between complete tracing lines so every file remains
        // valid UTF-8 even when a Russian character crosses the size boundary.
        ContentLimit::BytesSurpassed(LOG_FILE_SIZE_BYTES),
        Compression::None,
        None,
    );
    let redacting_writer = RedactingWriter::new(rotating_file, redactor.clone());
    let (non_blocking, worker_guard) = NonBlockingBuilder::default()
        .lossy(false)
        .thread_name("onecadmin-log-writer")
        .finish(redacting_writer);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .log_internal_errors(false)
        .try_init()
        .map_err(|error| LoggingError::InstallSubscriber {
            details: error.to_string(),
        })?;

    Ok(LoggingGuard {
        _worker_guard: worker_guard,
        redactor,
        log_path,
    })
}

struct RedactingWriter<W: Write> {
    inner: W,
    redactor: SecretRedactor,
    pending: Vec<u8>,
}

impl<W: Write> RedactingWriter<W> {
    fn new(inner: W, redactor: SecretRedactor) -> Self {
        Self {
            inner,
            redactor,
            pending: Vec::new(),
        }
    }

    fn write_complete_lines(&mut self) -> io::Result<()> {
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=newline).collect();
            self.write_redacted(&line)?;
        }
        Ok(())
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            self.write_redacted(&pending)?;
        }
        Ok(())
    }

    fn write_redacted(&mut self, bytes: &[u8]) -> io::Result<()> {
        let has_newline = bytes.last() == Some(&b'\n');
        let content = if has_newline {
            &bytes[..bytes.len() - 1]
        } else {
            bytes
        };
        let text = String::from_utf8_lossy(content);
        let redacted = self.redactor.redact(&text);
        let mut output = Vec::with_capacity(redacted.len() + usize::from(has_newline));
        output.extend_from_slice(redacted.as_bytes());
        if has_newline {
            output.push(b'\n');
        }
        self.inner.write_all(&output)
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buffer);
        self.write_complete_lines()?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_pending()?;
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::telemetry::REDACTED;

    #[test]
    fn writer_preserves_utf8_and_redacts_across_write_chunks() {
        let mut output = Vec::new();
        let redactor = SecretRedactor::with_secrets(["секрет"]);
        {
            let mut writer = RedactingWriter::new(&mut output, redactor);
            writer
                .write_all("Русский текст --password ".as_bytes())
                .unwrap();
            writer
                .write_all("секрет\nСледующая строка".as_bytes())
                .unwrap();
            writer.flush().unwrap();
        }

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Русский текст"));
        assert!(output.contains("Следующая строка"));
        assert!(output.contains(REDACTED));
        assert!(!output.contains("секрет"));
    }

    #[test]
    fn rotation_configuration_is_five_ten_mebibyte_files() {
        assert_eq!(LOG_FILE_COUNT, 5);
        assert_eq!(LOG_FILE_SIZE_BYTES, 10 * 1024 * 1024);
    }
}
