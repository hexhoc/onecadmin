use std::{fmt, io};

use super::{RacProcessError, RedactedInvocation};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RacErrorKind {
    ProtocolIncompatible,
    NotFound,
    UnsupportedVersion,
    Dns,
    ConnectionRefused,
    Timeout,
    Auth,
    CommandSyntax,
    Parse,
    Cancelled,
    Unknown,
}

impl RacErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProtocolIncompatible => "protocol_incompatible",
            Self::NotFound => "not_found",
            Self::UnsupportedVersion => "unsupported_version",
            Self::Dns => "dns",
            Self::ConnectionRefused => "connection_refused",
            Self::Timeout => "timeout",
            Self::Auth => "auth",
            Self::CommandSyntax => "command_syntax",
            Self::Parse => "parse",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }

    pub const fn allows_version_fallback(self) -> bool {
        matches!(self, Self::ProtocolIncompatible)
    }

    pub const fn user_message(self) -> &'static str {
        match self {
            Self::ProtocolIncompatible => "версия RAC несовместима с протоколом RAS",
            Self::NotFound => "исполняемый файл rac.exe не найден",
            Self::UnsupportedVersion => "версия RAC не поддерживается",
            Self::Dns => "не удалось разрешить имя сервера RAS",
            Self::ConnectionRefused => "сервер RAS отклонил подключение",
            Self::Timeout => "превышено время ожидания ответа RAC",
            Self::Auth => "ошибка аутентификации RAC",
            Self::CommandSyntax => "RAC отклонил синтаксис команды",
            Self::Parse => "не удалось разобрать ответ RAC",
            Self::Cancelled => "операция RAC отменена",
            Self::Unknown => "неизвестная ошибка RAC",
        }
    }
}

impl fmt::Display for RacErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

#[derive(Clone, Debug)]
pub struct RacError {
    kind: RacErrorKind,
    invocation: Option<RedactedInvocation>,
    exit_code: Option<i32>,
}

impl RacError {
    pub const fn new(kind: RacErrorKind) -> Self {
        Self {
            kind,
            invocation: None,
            exit_code: None,
        }
    }

    pub const fn kind(&self) -> RacErrorKind {
        self.kind
    }

    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub fn invocation(&self) -> Option<&RedactedInvocation> {
        self.invocation.as_ref()
    }

    pub const fn allows_version_fallback(&self) -> bool {
        self.kind.allows_version_fallback()
    }

    pub(crate) fn with_invocation(kind: RacErrorKind, invocation: RedactedInvocation) -> Self {
        Self {
            kind,
            invocation: Some(invocation),
            exit_code: None,
        }
    }

    pub(crate) fn command_failed(
        kind: RacErrorKind,
        exit_code: Option<i32>,
        invocation: RedactedInvocation,
    ) -> Self {
        Self {
            kind,
            invocation: Some(invocation),
            exit_code,
        }
    }

    pub(crate) fn from_process(error: RacProcessError) -> Self {
        let kind = match &error {
            RacProcessError::Timeout { .. } => RacErrorKind::Timeout,
            RacProcessError::Cancelled { .. } => RacErrorKind::Cancelled,
            RacProcessError::Io { error_kind, .. } if *error_kind == io::ErrorKind::NotFound => {
                RacErrorKind::NotFound
            }
            RacProcessError::Io { .. } => RacErrorKind::Unknown,
        };
        Self::with_invocation(kind, error.invocation().clone())
    }
}

impl fmt::Display for RacError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}",
            self.kind.code(),
            self.kind.user_message()
        )?;
        if let Some(exit_code) = self.exit_code {
            write!(formatter, " (код RAC: {exit_code})")?;
        }
        if let Some(invocation) = &self.invocation {
            write!(formatter, ": {invocation}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RacError {}

pub fn classify_diagnostic(diagnostic: &str) -> RacErrorKind {
    let diagnostic = diagnostic.to_lowercase().replace('ё', "е");

    if contains_any(
        &diagnostic,
        &[
            "incompatible protocol",
            "protocol version mismatch",
            "unsupported protocol version",
            "server protocol version is not supported",
            "administration server version is not supported",
            "version of administration server is not supported",
            "protocol is incompatible",
            "несовместимая версия протокола",
            "несовместим с протоколом",
            "версия протокола не поддерживается",
            "версия сервера администрирования не поддерживается",
            "несовместимые версии rac и ras",
            "ошибка протокола взаимодействия",
        ],
    ) {
        return RacErrorKind::ProtocolIncompatible;
    }

    if contains_any(
        &diagnostic,
        &[
            "timed out",
            "timeout",
            "time-out",
            "operation has timed out",
            "истекло время ожидания",
            "превышено время ожидания",
            "тайм-аут",
            "таймаут",
        ],
    ) {
        return RacErrorKind::Timeout;
    }

    if contains_any(
        &diagnostic,
        &[
            "no such host is known",
            "name or service not known",
            "temporary failure in name resolution",
            "getaddrinfo failed",
            "host not found",
            "could not resolve host",
            "неизвестен такой узел",
            "не удается разрешить имя",
            "не удалось разрешить имя",
            "узел не найден",
            "хост не найден",
        ],
    ) {
        return RacErrorKind::Dns;
    }

    if contains_any(
        &diagnostic,
        &[
            "connection refused",
            "actively refused",
            "target machine refused",
            "could not connect because the target machine actively refused",
            "подключение не установлено, т.к. конечный компьютер отверг",
            "целевой компьютер активно отверг",
            "соединение отклонено",
            "отказано в подключении",
        ],
    ) {
        return RacErrorKind::ConnectionRefused;
    }

    if contains_any(
        &diagnostic,
        &[
            "authentication failed",
            "authorization failed",
            "invalid user or password",
            "invalid username or password",
            "wrong password",
            "access denied",
            "administrator is not authenticated",
            "ошибка аутентификации",
            "ошибка авторизации",
            "неверный пароль",
            "неверное имя пользователя",
            "пользователь не аутентифицирован",
            "администратор не аутентифицирован",
            "доступ запрещен",
            "недостаточно прав",
        ],
    ) {
        return RacErrorKind::Auth;
    }

    if contains_any(
        &diagnostic,
        &[
            "unknown command",
            "unknown option",
            "unknown argument",
            "unrecognized option",
            "invalid command",
            "invalid option",
            "error parsing parameter",
            "parameter parsing error",
            "usage:",
            "неизвестная команда",
            "неизвестный параметр",
            "неверный параметр",
            "недопустимый параметр",
            "ошибка синтаксиса команды",
            "ошибка разбора параметра",
        ],
    ) {
        return RacErrorKind::CommandSyntax;
    }

    if contains_any(
        &diagnostic,
        &[
            "unsupported rac version",
            "rac version is not supported",
            "version is too old",
            "версия rac не поддерживается",
            "устаревшая версия rac",
            "версия rac слишком старая",
        ],
    ) {
        return RacErrorKind::UnsupportedVersion;
    }

    if contains_any(
        &diagnostic,
        &[
            "rac.exe is not recognized",
            "rac.exe: not found",
            "the system cannot find the file",
            "системе не удается найти указанный файл",
            "rac.exe не найден",
        ],
    ) {
        return RacErrorKind::NotFound;
    }

    RacErrorKind::Unknown
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_russian_and_english_diagnostics() {
        let cases = [
            (
                "The administration server version is not supported by this client",
                RacErrorKind::ProtocolIncompatible,
            ),
            (
                "Ошибка аутентификации: неверный пароль администратора",
                RacErrorKind::Auth,
            ),
            (
                "No such host is known (getaddrinfo failed)",
                RacErrorKind::Dns,
            ),
            (
                "Подключение не установлено, т.к. конечный компьютер отверг запрос",
                RacErrorKind::ConnectionRefused,
            ),
            ("Unknown option --future", RacErrorKind::CommandSyntax),
            ("Истекло время ожидания операции", RacErrorKind::Timeout),
        ];

        for (diagnostic, expected) in cases {
            assert_eq!(classify_diagnostic(diagnostic), expected, "{diagnostic}");
        }
    }

    #[test]
    fn fallback_is_only_allowed_for_protocol_mismatch() {
        for kind in [
            RacErrorKind::Dns,
            RacErrorKind::ConnectionRefused,
            RacErrorKind::Timeout,
            RacErrorKind::Auth,
            RacErrorKind::CommandSyntax,
            RacErrorKind::Unknown,
        ] {
            assert!(!kind.allows_version_fallback());
        }
        assert!(RacErrorKind::ProtocolIncompatible.allows_version_fallback());
    }
}
