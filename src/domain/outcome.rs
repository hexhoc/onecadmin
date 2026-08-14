use serde::Serialize;

use super::{ClusterAlias, RasEndpoint};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetErrorKind {
    Unavailable,
    Timeout,
    Authentication,
    Protocol,
    InvalidResponse,
    RacNotFound,
    Cancelled,
    Internal,
}

impl TargetErrorKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "target_unavailable",
            Self::Timeout => "timeout",
            Self::Authentication => "authentication_failed",
            Self::Protocol => "protocol_error",
            Self::InvalidResponse => "invalid_response",
            Self::RacNotFound => "rac_not_found",
            Self::Cancelled => "cancelled",
            Self::Internal => "internal_error",
        }
    }
}

impl Serialize for TargetErrorKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.code())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TargetError {
    pub cluster: ClusterAlias,
    pub ras_address: RasEndpoint,
    #[serde(rename = "code")]
    pub kind: TargetErrorKind,
    pub message: String,
}

impl TargetError {
    #[must_use]
    pub fn new(
        cluster: ClusterAlias,
        ras_address: RasEndpoint,
        kind: TargetErrorKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            cluster,
            ras_address,
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct QueryMeta {
    pub matched: usize,
    pub returned: usize,
    pub partial: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryOutcome<T> {
    pub data: Vec<T>,
    pub errors: Vec<TargetError>,
    pub meta: QueryMeta,
}

impl<T> QueryOutcome<T> {
    #[must_use]
    pub fn new(
        data: Vec<T>,
        errors: Vec<TargetError>,
        matched: usize,
        successful_targets: usize,
    ) -> Self {
        let returned = data.len();
        let partial = !errors.is_empty() && successful_targets > 0;
        Self {
            data,
            errors,
            meta: QueryMeta {
                matched,
                returned,
                partial,
            },
        }
    }

    #[must_use]
    pub fn is_all_failed(&self) -> bool {
        !self.errors.is_empty() && !self.meta.partial && self.data.is_empty()
    }

    #[must_use]
    pub fn is_empty_success(&self) -> bool {
        self.data.is_empty() && self.errors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error() -> TargetError {
        TargetError::new(
            ClusterAlias::new("dev").unwrap_or_else(|error| panic!("{error}")),
            "ras.local:1545"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            TargetErrorKind::Timeout,
            "timeout",
        )
    }

    #[test]
    fn partial_requires_at_least_one_successful_target() {
        let partial = QueryOutcome::new(vec![1], vec![error()], 1, 1);
        let failed = QueryOutcome::<i32>::new(Vec::new(), vec![error()], 0, 0);

        assert!(partial.meta.partial);
        assert!(!failed.meta.partial);
        assert!(failed.is_all_failed());
    }

    #[test]
    fn empty_success_is_not_an_error() {
        let outcome = QueryOutcome::<i32>::new(Vec::new(), Vec::new(), 0, 2);

        assert!(outcome.is_empty_success());
        assert!(!outcome.is_all_failed());
    }
}
