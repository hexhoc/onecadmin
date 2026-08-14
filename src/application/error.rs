use std::fmt;
use std::process::ExitCode;

use crate::domain::{ClusterAlias, DomainError, RasEndpoint, TargetError, TargetErrorKind};
use crate::infrastructure::rac::{RacError, RacErrorKind};

/// Stable process exit codes defined by the application contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AppExitCode {
    Success = 0,
    Internal = 1,
    InvalidInput = 2,
    RacNotFound = 3,
    AllTargetsFailed = 4,
    PartialSuccess = 5,
    Cancelled = 6,
    NoObjects = 7,
    Interrupted = 130,
}

impl AppExitCode {
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }
}

impl From<AppExitCode> for ExitCode {
    fn from(value: AppExitCode) -> Self {
        Self::from(value.value())
    }
}

/// Centralized conversion of application results into a process exit code.
pub trait ExitCodePolicy {
    fn app_exit_code(&self) -> AppExitCode;

    fn exit_code(&self) -> ExitCode {
        self.app_exit_code().into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppErrorCategory {
    Internal,
    InvalidInput,
    RacNotFound,
    AllTargetsFailed,
    Cancelled,
    NoObjects,
    Interrupted,
}

impl AppErrorCategory {
    #[must_use]
    pub const fn exit_code(self) -> AppExitCode {
        match self {
            Self::Internal => AppExitCode::Internal,
            Self::InvalidInput => AppExitCode::InvalidInput,
            Self::RacNotFound => AppExitCode::RacNotFound,
            Self::AllTargetsFailed => AppExitCode::AllTargetsFailed,
            Self::Cancelled => AppExitCode::Cancelled,
            Self::NoObjects => AppExitCode::NoObjects,
            Self::Interrupted => AppExitCode::Interrupted,
        }
    }
}

/// User-facing application error with a stable machine code and Russian text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppError {
    category: AppErrorCategory,
    code: &'static str,
    message: String,
    target_errors: Vec<TargetError>,
}

impl AppError {
    #[must_use]
    pub fn new(category: AppErrorCategory, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            category,
            code,
            message: message.into(),
            target_errors: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_domain(error: DomainError) -> Self {
        Self::new(
            AppErrorCategory::InvalidInput,
            error.code(),
            error.to_string(),
        )
    }

    #[must_use]
    pub fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(AppErrorCategory::InvalidInput, code, message)
    }

    #[must_use]
    pub fn config(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(AppErrorCategory::InvalidInput, code, message)
    }

    #[must_use]
    pub fn internal(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(AppErrorCategory::Internal, code, message)
    }

    #[must_use]
    pub fn target_operation(error: RacError) -> Self {
        let category = match error.kind() {
            RacErrorKind::NotFound | RacErrorKind::UnsupportedVersion => {
                AppErrorCategory::RacNotFound
            }
            RacErrorKind::Cancelled => AppErrorCategory::Cancelled,
            _ => AppErrorCategory::AllTargetsFailed,
        };
        let code = match category {
            AppErrorCategory::RacNotFound => "rac_not_found",
            AppErrorCategory::Cancelled => "cancelled",
            _ => error.code(),
        };
        Self::new(category, code, error.to_string())
    }

    #[must_use]
    pub fn all_targets_failed(target_errors: Vec<TargetError>) -> Self {
        let all_rac_missing = !target_errors.is_empty()
            && target_errors
                .iter()
                .all(|error| error.kind == TargetErrorKind::RacNotFound);
        let all_cancelled = !target_errors.is_empty()
            && target_errors
                .iter()
                .all(|error| error.kind == TargetErrorKind::Cancelled);
        let (category, code, message) = if all_cancelled {
            (
                AppErrorCategory::Cancelled,
                "cancelled",
                "Операция отменена".to_owned(),
            )
        } else if all_rac_missing {
            (
                AppErrorCategory::RacNotFound,
                "rac_not_found",
                "Не найден совместимый исполняемый файл rac.exe ни для одной цели".to_owned(),
            )
        } else {
            (
                AppErrorCategory::AllTargetsFailed,
                "all_targets_failed",
                "Операция завершилась ошибкой для всех выбранных кластеров".to_owned(),
            )
        };
        Self::new(category, code, message).with_target_errors(target_errors)
    }

    #[must_use]
    pub fn cancelled() -> Self {
        Self::new(
            AppErrorCategory::Cancelled,
            "cancelled",
            "Операция отменена",
        )
    }

    #[must_use]
    pub fn confirmation_required() -> Self {
        Self::new(
            AppErrorCategory::Cancelled,
            "confirmation_required",
            "Для разрушающей операции требуется подтверждение или признак force",
        )
    }

    #[must_use]
    pub fn no_objects(entity: &'static str) -> Self {
        let message = match entity {
            "session" => "Не найдено сеансов для завершения",
            "connection" => "Не найдено соединений для разрыва",
            "cluster" => "Не найдено подключений к кластеру для удаления",
            _ => "Разрушающая операция не нашла объектов",
        };
        Self::new(AppErrorCategory::NoObjects, "no_objects", message)
    }

    #[must_use]
    pub fn interrupted() -> Self {
        Self::new(
            AppErrorCategory::Interrupted,
            "interrupted",
            "Операция прервана пользователем",
        )
    }

    #[must_use]
    pub fn with_target_errors(mut self, target_errors: Vec<TargetError>) -> Self {
        self.target_errors = target_errors;
        self
    }

    #[must_use]
    pub const fn category(&self) -> AppErrorCategory {
        self.category
    }

    #[must_use]
    pub const fn app_exit_code(&self) -> AppExitCode {
        self.category.exit_code()
    }

    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        self.app_exit_code().into()
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn target_errors(&self) -> &[TargetError] {
        &self.target_errors
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AppError {}

impl ExitCodePolicy for AppError {
    fn app_exit_code(&self) -> AppExitCode {
        AppError::app_exit_code(self)
    }
}

impl<T> ExitCodePolicy for Result<T, AppError>
where
    T: ExitCodePolicy,
{
    fn app_exit_code(&self) -> AppExitCode {
        match self {
            Ok(outcome) => outcome.app_exit_code(),
            Err(error) => error.app_exit_code(),
        }
    }
}

#[must_use]
pub(crate) fn target_error_from_rac(
    cluster: ClusterAlias,
    ras_address: RasEndpoint,
    error: RacError,
) -> TargetError {
    TargetError::new(
        cluster,
        ras_address,
        target_kind_from_rac(error.kind()),
        error.to_string(),
    )
}

#[must_use]
pub(crate) const fn target_kind_from_rac(kind: RacErrorKind) -> TargetErrorKind {
    match kind {
        RacErrorKind::Dns | RacErrorKind::ConnectionRefused => TargetErrorKind::Unavailable,
        RacErrorKind::Timeout => TargetErrorKind::Timeout,
        RacErrorKind::Auth => TargetErrorKind::Authentication,
        RacErrorKind::ProtocolIncompatible | RacErrorKind::CommandSyntax => {
            TargetErrorKind::Protocol
        }
        RacErrorKind::Parse => TargetErrorKind::InvalidResponse,
        RacErrorKind::NotFound | RacErrorKind::UnsupportedVersion => TargetErrorKind::RacNotFound,
        RacErrorKind::Cancelled => TargetErrorKind::Cancelled,
        RacErrorKind::Unknown => TargetErrorKind::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_the_public_contract() {
        assert_eq!(
            AppError::invalid("bad", "Ошибка").app_exit_code().value(),
            2
        );
        assert_eq!(AppError::cancelled().app_exit_code().value(), 6);
        assert_eq!(AppError::no_objects("session").app_exit_code().value(), 7);
        assert_eq!(AppError::interrupted().app_exit_code().value(), 130);
    }
}
