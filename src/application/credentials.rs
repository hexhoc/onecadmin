use std::path::PathBuf;

use tokio_util::sync::CancellationToken;

use crate::domain::{ClusterAlias, ClusterTarget, InfobaseAuthOverride, InfobaseUuid};
use crate::infrastructure::config::OverrideSelector;
use crate::infrastructure::telemetry::{AuditContext, AuditEvent, AuditResult, audit_actions};

use super::conversion::domain_override_to_config;
use super::{
    AppError, AppErrorCategory, AppServices, config_port_error, convert_config_snapshot,
    ensure_not_cancelled,
};

#[derive(Clone, Debug)]
pub struct CredentialOverrideAddRequest {
    pub cluster: ClusterAlias,
    pub entry: InfobaseAuthOverride,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialOverrideSelector {
    Uuid(InfobaseUuid),
    Name(String),
}

impl CredentialOverrideSelector {
    pub fn by_name(name: impl Into<String>) -> Result<Self, AppError> {
        let name = name.into();
        if name.is_empty() {
            return Err(AppError::invalid(
                "invalid_override_selector",
                "Имя информационной базы для удаления переопределения учетных данных не может быть пустым",
            ));
        }
        Ok(Self::Name(name))
    }

    #[must_use]
    pub const fn by_uuid(uuid: InfobaseUuid) -> Self {
        Self::Uuid(uuid)
    }

    fn infrastructure_selector(&self) -> OverrideSelector {
        match self {
            Self::Uuid(uuid) => OverrideSelector::by_uuid(uuid.into_uuid()),
            Self::Name(name) => OverrideSelector::by_name(name),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CredentialOverrideRemoveRequest {
    pub cluster: ClusterAlias,
    pub selector: CredentialOverrideSelector,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialMutation {
    Added,
    Removed,
}

#[derive(Clone, Debug)]
pub struct CredentialWriteOutcome {
    pub cluster: ClusterTarget,
    pub entry: InfobaseAuthOverride,
    pub mutation: CredentialMutation,
    pub config_path: PathBuf,
}

impl AppServices {
    pub async fn credential_overrides(
        &self,
        cluster: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<InfobaseAuthOverride>, AppError> {
        let alias = ClusterAlias::new(cluster).map_err(AppError::from_domain)?;
        let snapshot = self.load_config_snapshot(cancellation).await?;
        let target = snapshot.target(&alias).ok_or_else(|| {
            AppError::invalid(
                "cluster_not_found",
                format!("Кластер с alias `{alias}` не найден"),
            )
        })?;
        Ok(target.target.infobase_auth.overrides().to_vec())
    }

    pub async fn add_credential_override(
        &self,
        request: CredentialOverrideAddRequest,
        cancellation: &CancellationToken,
    ) -> Result<CredentialWriteOutcome, AppError> {
        let persisted = domain_override_to_config(&request.entry)?;
        let windows_user = self.audit_user().await?;
        let result = async {
            ensure_not_cancelled(cancellation)?;
            let snapshot = self.load_config_snapshot(cancellation).await?;
            if snapshot.target(&request.cluster).is_none() {
                return Err(AppError::invalid(
                    "cluster_not_found",
                    format!("Кластер с alias `{}` не найден", request.cluster),
                ));
            }
            ensure_not_cancelled(cancellation)?;
            let written = self
                .config
                .add_override(request.cluster.to_string(), persisted)
                .await
                .map_err(config_port_error)?;
            let converted = convert_config_snapshot(written)?;
            let target = converted
                .target(&request.cluster)
                .map(|target| target.target.clone())
                .ok_or_else(|| {
                    AppError::internal(
                        "config_write_invariant",
                        "Кластер отсутствует после записи переопределения учетных данных",
                    )
                })?;
            Ok(CredentialWriteOutcome {
                cluster: target,
                entry: request.entry.clone(),
                mutation: CredentialMutation::Added,
                config_path: converted.path,
            })
        }
        .await;
        self.complete_credential_audit(
            result,
            &request.cluster,
            &request.entry,
            CredentialMutation::Added,
            windows_user,
        )
        .await
    }

    pub async fn remove_credential_override(
        &self,
        request: CredentialOverrideRemoveRequest,
        cancellation: &CancellationToken,
    ) -> Result<CredentialWriteOutcome, AppError> {
        let windows_user = self.audit_user().await?;
        let result = async {
            ensure_not_cancelled(cancellation)?;
            let snapshot = self.load_config_snapshot(cancellation).await?;
            let target = snapshot.target(&request.cluster).ok_or_else(|| {
                AppError::invalid(
                    "cluster_not_found",
                    format!("Кластер с alias `{}` не найден", request.cluster),
                )
            })?;
            let entry = find_override(target.target.infobase_auth.overrides(), &request.selector)
                .cloned()
                .ok_or_else(|| {
                    AppError::invalid(
                        "credential_override_not_found",
                        "Переопределение учетных данных не найдено",
                    )
                })?;
            ensure_not_cancelled(cancellation)?;
            let written = self
                .config
                .remove_override(
                    request.cluster.to_string(),
                    request.selector.infrastructure_selector(),
                )
                .await
                .map_err(config_port_error)?;
            let converted = convert_config_snapshot(written)?;
            let target = converted
                .target(&request.cluster)
                .map(|target| target.target.clone())
                .ok_or_else(|| {
                    AppError::internal(
                        "config_write_invariant",
                        "Кластер отсутствует после удаления переопределения учетных данных",
                    )
                })?;
            Ok(CredentialWriteOutcome {
                cluster: target,
                entry,
                mutation: CredentialMutation::Removed,
                config_path: converted.path,
            })
        }
        .await;

        let audit_entry = match &result {
            Ok(outcome) => outcome.entry.clone(),
            Err(_) => placeholder_entry(&request.selector)?,
        };
        self.complete_credential_audit(
            result,
            &request.cluster,
            &audit_entry,
            CredentialMutation::Removed,
            windows_user,
        )
        .await
    }

    async fn complete_credential_audit(
        &self,
        result: Result<CredentialWriteOutcome, AppError>,
        cluster: &ClusterAlias,
        entry: &InfobaseAuthOverride,
        mutation: CredentialMutation,
        windows_user: String,
    ) -> Result<CredentialWriteOutcome, AppError> {
        let context = AuditContext {
            cluster_alias: Some(cluster.to_string()),
            cluster_uuid: result
                .as_ref()
                .ok()
                .map(|outcome| outcome.cluster.discovered_cluster.uuid.into_uuid()),
            infobase_name: entry.infobase().map(str::to_owned),
            infobase_uuid: entry.infobase_uuid().map(InfobaseUuid::into_uuid),
            reason: Some(match mutation {
                CredentialMutation::Added => "add".to_owned(),
                CredentialMutation::Removed => "remove".to_owned(),
            }),
            ..AuditContext::default()
        };
        let event = match &result {
            Ok(_) => AuditEvent::new(
                windows_user,
                audit_actions::CREDENTIAL_OVERRIDE_CHANGE,
                AuditResult::Success,
            )
            .with_context(context),
            Err(error) => AuditEvent::new(
                windows_user,
                audit_actions::CREDENTIAL_OVERRIDE_CHANGE,
                if error.category() == AppErrorCategory::Cancelled {
                    AuditResult::Cancelled
                } else {
                    AuditResult::Failure
                },
            )
            .with_context(context)
            .with_error(error.code(), error.message()),
        };
        let audit_result = self.audit.record(event).await;
        match (result, audit_result) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Ok(_), Err(error)) => Err(AppError::internal(
                "audit_write_failed",
                format!(
                    "Переопределение учетных данных изменено, но событие аудита не записано: {}",
                    error.message
                ),
            )),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(audit_error)) => Err(error.with_audit_error(audit_error.message)),
        }
    }
}

fn find_override<'a>(
    overrides: &'a [InfobaseAuthOverride],
    selector: &CredentialOverrideSelector,
) -> Option<&'a InfobaseAuthOverride> {
    match selector {
        CredentialOverrideSelector::Uuid(uuid) => overrides
            .iter()
            .find(|entry| entry.infobase_uuid() == Some(*uuid)),
        CredentialOverrideSelector::Name(name) => overrides.iter().find(|entry| {
            entry
                .infobase()
                .is_some_and(|candidate| candidate.to_lowercase() == name.to_lowercase())
        }),
    }
}

fn placeholder_entry(
    selector: &CredentialOverrideSelector,
) -> Result<InfobaseAuthOverride, AppError> {
    let (name, uuid) = match selector {
        CredentialOverrideSelector::Uuid(uuid) => (None, Some(*uuid)),
        CredentialOverrideSelector::Name(name) => (Some(name.clone()), None),
    };
    InfobaseAuthOverride::new(name, uuid, crate::domain::AuthConfig::none())
        .map_err(AppError::from_domain)
}
