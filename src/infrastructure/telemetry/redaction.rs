use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use regex::{Captures, Regex};
use zeroize::Zeroize;

pub const REDACTED: &str = "[REDACTED]";

struct SecretValue(String);

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct RedactionPatterns {
    command_flag: Regex,
    named_value: Regex,
}

impl RedactionPatterns {
    fn new() -> Self {
        Self {
            command_flag: Regex::new(
                r#"(?i)(?P<key>--[a-z0-9_-]*(?:password|passwd|pwd))(?P<sep>\s*=\s*|\s+)(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;)\]}]+)"#,
            )
            .expect("password flag regex is valid"),
            named_value: Regex::new(
                r#"(?i)(?P<key>[\"']?(?:password|passwd|pwd)[\"']?)(?P<sep>\s*[:=]\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;)\]}]+)"#,
            )
            .expect("password field regex is valid"),
        }
    }
}

/// Shared redaction service for technical logs, argv diagnostics, errors and
/// audit records. Registered secrets are zeroized when the last clone drops.
#[derive(Clone)]
pub struct SecretRedactor {
    secrets: Arc<RwLock<Vec<SecretValue>>>,
    patterns: Arc<RedactionPatterns>,
}

impl SecretRedactor {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(Vec::new())),
            patterns: Arc::new(RedactionPatterns::new()),
        }
    }

    pub fn with_secrets<I, S>(secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let redactor = Self::new();
        for secret in secrets {
            redactor.register_secret(secret);
        }
        redactor
    }

    /// Returns true when a new non-empty secret was registered.
    pub fn register_secret(&self, secret: impl Into<String>) -> bool {
        let secret = secret.into();
        if secret.is_empty() {
            return false;
        }

        let mut secrets = self.write_secrets();
        if secrets.iter().any(|known| known.0 == secret) {
            return false;
        }
        secrets.push(SecretValue(secret));
        // Longer values must be removed first when one secret is a prefix of
        // another one.
        secrets.sort_by_key(|value| std::cmp::Reverse(value.0.len()));
        true
    }

    pub fn clear_secrets(&self) {
        self.write_secrets().clear();
    }

    pub fn redact(&self, value: &str) -> String {
        let mut redacted = value.to_owned();
        for secret in self.read_secrets().iter() {
            redacted = redacted.replace(&secret.0, REDACTED);
        }

        redacted = redact_matches(&self.patterns.command_flag, &redacted);
        redact_matches(&self.patterns.named_value, &redacted)
    }

    pub fn redact_string(&self, value: &str) -> String {
        self.redact(value)
    }

    pub fn redact_error(&self, error: &dyn Error) -> String {
        self.redact(&error.to_string())
    }

    pub fn redact_display(&self, value: &impl fmt::Display) -> String {
        self.redact(&value.to_string())
    }

    pub fn redact_debug(&self, value: &impl fmt::Debug) -> String {
        self.redact(&format!("{value:?}"))
    }

    /// Preserves non-Unicode arguments byte-for-byte/wide-unit-for-wide-unit,
    /// except for a password value which is intentionally replaced wholesale.
    pub fn redact_argv<I, S>(&self, arguments: I) -> Vec<OsString>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut redact_next = false;
        let mut result = Vec::new();

        for argument in arguments {
            let argument = argument.as_ref();
            if redact_next {
                result.push(OsString::from(REDACTED));
                redact_next = false;
                continue;
            }

            if let Some(text) = argument.to_str() {
                if let Some((flag, _value)) = text.split_once('=')
                    && is_password_flag(flag)
                {
                    result.push(OsString::from(format!("{flag}={REDACTED}")));
                    continue;
                }
                if is_password_flag(text) {
                    result.push(argument.to_os_string());
                    redact_next = true;
                    continue;
                }

                let redacted = self.redact(text);
                if redacted != text {
                    result.push(OsString::from(redacted));
                    continue;
                }
            }

            result.push(argument.to_os_string());
        }

        result
    }

    pub fn redact_argv_lossy<I, S>(&self, arguments: I) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.redact_argv(arguments)
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    fn read_secrets(&self) -> RwLockReadGuard<'_, Vec<SecretValue>> {
        self.secrets
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_secrets(&self) -> RwLockWriteGuard<'_, Vec<SecretValue>> {
        self.secrets
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for SecretRedactor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecretRedactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRedactor")
            .field("registered_secret_count", &self.read_secrets().len())
            .finish_non_exhaustive()
    }
}

fn redact_matches(pattern: &Regex, value: &str) -> String {
    pattern
        .replace_all(value, |captures: &Captures<'_>| {
            let original_value = &captures["value"];
            let replacement = match original_value.as_bytes().first() {
                Some(b'\"') => format!("\"{REDACTED}\""),
                Some(b'\'') => format!("'{REDACTED}'"),
                _ => REDACTED.to_owned(),
            };
            format!("{}{}{}", &captures["key"], &captures["sep"], replacement)
        })
        .into_owned()
}

fn is_password_flag(flag: &str) -> bool {
    let normalized = flag
        .trim_start_matches(['-', '/'])
        .replace('_', "-")
        .to_ascii_lowercase();

    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "cluster-password"
            | "cluster-pwd"
            | "infobase-password"
            | "infobase-pwd"
            | "db-password"
            | "db-pwd"
    ) || normalized.ends_with("-password")
        || normalized.ends_with("-passwd")
        || normalized.ends_with("-pwd")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_password_flags_and_named_values() {
        let redactor = SecretRedactor::new();
        let input = concat!(
            "rac --cluster-pwd hunter2 --infobase-password=secret ",
            "password: yaml-secret, JSON=ok, \"password\":\"json-secret\""
        );

        let output = redactor.redact(input);
        assert!(!output.contains("hunter2"));
        assert!(!output.contains("secret"));
        assert!(!output.contains("yaml-secret"));
        assert!(!output.contains("json-secret"));
        assert!(output.contains(REDACTED));
    }

    #[test]
    fn redacts_separate_and_inline_argv_passwords() {
        let redactor = SecretRedactor::new();
        let argv = [
            OsString::from("rac.exe"),
            OsString::from("--cluster-pwd"),
            OsString::from("very-secret"),
            OsString::from("--infobase-password=also-secret"),
            OsString::from("--port"),
            OsString::from("1545"),
        ];

        let redacted = redactor.redact_argv_lossy(&argv);
        assert_eq!(redacted[2], REDACTED);
        assert_eq!(redacted[3], format!("--infobase-password={REDACTED}"));
        assert_eq!(redacted[4], "--port");
        assert_eq!(redacted[5], "1545");
        assert!(!format!("{redacted:?}").contains("very-secret"));
        assert!(!format!("{redacted:?}").contains("also-secret"));
    }

    #[test]
    fn registered_secrets_are_removed_from_errors_and_debug_output() {
        let redactor = SecretRedactor::with_secrets(["swordfish"]);
        let error = std::io::Error::other("ошибка входа для swordfish");

        assert_eq!(
            redactor.redact_error(&error),
            format!("ошибка входа для {REDACTED}")
        );
        assert!(!format!("{redactor:?}").contains("swordfish"));
    }

    #[test]
    fn keeps_non_secret_russian_text() {
        let redactor = SecretRedactor::new();
        assert_eq!(
            redactor.redact("Сеанс завершен администратором"),
            "Сеанс завершен администратором"
        );
    }
}
