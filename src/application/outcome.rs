use crate::domain::{
    ConnectionKillPlan, ConnectionKillTarget, ConnectionRecord, QueryOutcome, SessionKillPlan,
    SessionKillTarget, SessionRecord, TargetError,
};

use super::{AppError, AppExitCode, ExitCodePolicy, RacOptions};

/// Proof that confirmation was handled by an adapter before execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Approval {
    Confirmed,
    Forced,
}

impl Approval {
    pub fn from_flags(confirmed: bool, force: bool) -> Result<Self, AppError> {
        if force {
            Ok(Self::Forced)
        } else if confirmed {
            Ok(Self::Confirmed)
        } else {
            Err(AppError::confirmation_required())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionError {
    pub code: String,
    pub message: String,
}

impl ActionError {
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionStatus {
    Success,
    Failed,
    Cancelled,
}

impl ActionStatus {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionItemOutcome<T> {
    pub target: T,
    pub status: ActionStatus,
    pub error: Option<ActionError>,
    /// The action status describes the RAC effect. Audit failure is kept
    /// separately so callers can report that the effect may already exist.
    pub audit_error: Option<ActionError>,
}

impl<T> ActionItemOutcome<T> {
    #[must_use]
    pub fn success(target: T) -> Self {
        Self {
            target,
            status: ActionStatus::Success,
            error: None,
            audit_error: None,
        }
    }

    #[must_use]
    pub fn failed(target: T, error: ActionError) -> Self {
        Self {
            target,
            status: ActionStatus::Failed,
            error: Some(error),
            audit_error: None,
        }
    }

    #[must_use]
    pub fn cancelled(target: T) -> Self {
        Self {
            target,
            status: ActionStatus::Cancelled,
            error: Some(ActionError::new("cancelled", "Операция отменена")),
            audit_error: None,
        }
    }

    #[must_use]
    pub fn with_audit_error(mut self, error: ActionError) -> Self {
        self.audit_error = Some(error);
        self
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActionMeta {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub cancelled: usize,
    pub audit_failed: usize,
    pub partial: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionOutcome<T> {
    pub items: Vec<ActionItemOutcome<T>>,
    pub meta: ActionMeta,
}

impl<T> ActionOutcome<T> {
    #[must_use]
    pub fn new(items: Vec<ActionItemOutcome<T>>) -> Self {
        let succeeded = items
            .iter()
            .filter(|item| item.status == ActionStatus::Success)
            .count();
        let failed = items
            .iter()
            .filter(|item| item.status == ActionStatus::Failed)
            .count();
        let cancelled = items
            .iter()
            .filter(|item| item.status == ActionStatus::Cancelled)
            .count();
        let audit_failed = items
            .iter()
            .filter(|item| item.audit_error.is_some())
            .count();
        let attempted = items.len();
        let partial = succeeded > 0 && failed + cancelled > 0;
        Self {
            items,
            meta: ActionMeta {
                attempted,
                succeeded,
                failed,
                cancelled,
                audit_failed,
                partial,
            },
        }
    }
}

impl<T> ExitCodePolicy for ActionOutcome<T> {
    fn app_exit_code(&self) -> AppExitCode {
        if self.meta.cancelled > 0 {
            AppExitCode::Cancelled
        } else if self.meta.audit_failed > 0 {
            AppExitCode::Internal
        } else if self.meta.attempted == 0 {
            AppExitCode::NoObjects
        } else if self.meta.succeeded > 0 && self.meta.failed > 0 {
            AppExitCode::PartialSuccess
        } else if self.meta.failed > 0 {
            AppExitCode::AllTargetsFailed
        } else {
            AppExitCode::Success
        }
    }
}

impl<T> ExitCodePolicy for QueryOutcome<T> {
    fn app_exit_code(&self) -> AppExitCode {
        if self.meta.partial {
            AppExitCode::PartialSuccess
        } else if self.is_all_failed() {
            AppExitCode::AllTargetsFailed
        } else {
            AppExitCode::Success
        }
    }
}

#[derive(Clone, Debug)]
pub struct PreparedSessionKill {
    pub plan: SessionKillPlan,
    pub records: Vec<SessionRecord>,
    pub target_errors: Vec<TargetError>,
    pub rac_options: RacOptions,
}

impl PreparedSessionKill {
    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.target_errors.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct PreparedConnectionKill {
    pub plan: ConnectionKillPlan,
    pub records: Vec<ConnectionRecord>,
    pub target_errors: Vec<TargetError>,
    pub rac_options: RacOptions,
}

impl PreparedConnectionKill {
    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.target_errors.is_empty()
    }
}

pub type SessionKillOutcome = ActionOutcome<SessionKillTarget>;
pub type ConnectionKillOutcome = ActionOutcome<ConnectionKillTarget>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_never_prompts_inside_application() {
        assert_eq!(Approval::from_flags(false, true), Ok(Approval::Forced));
        assert_eq!(Approval::from_flags(true, false), Ok(Approval::Confirmed));
        assert_eq!(
            Approval::from_flags(false, false)
                .err()
                .map(|error| error.code()),
            Some("confirmation_required")
        );
    }
}
