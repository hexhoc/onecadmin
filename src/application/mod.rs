//! Application services shared by CLI and TUI.

mod clusters;
mod connections;
mod conversion;
mod credentials;
mod diagnostics;
mod error;
mod infobases;
mod normalize;
mod outcome;
mod ports;
#[cfg(test)]
mod service_tests;
mod sessions;

use std::fmt;
use std::sync::Arc;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::domain::{
    AuthConfig, ClusterSource, DiscoveredCluster, FieldRegistry, QuerySpec, RecordKind, SqlMask,
    TargetError, TargetErrorKind,
};
use crate::infrastructure::config::ConfigStore;
use crate::infrastructure::rac::RacGateway;
use crate::infrastructure::telemetry::AuditSink;
use crate::infrastructure::windows::WindowsIdentityProvider;

pub use clusters::{ClusterAddOutcome, ClusterAddRequest, ClusterRemoveOutcome, ClusterRemovePlan};
pub use connections::{ConnectionKillRequest, ConnectionListRequest};
pub use conversion::{
    ApplicationConfigSnapshot, ConfiguredTarget, RacOptions, auth_to_rac_credentials,
    convert_config_snapshot,
};
pub use credentials::{
    CredentialMutation, CredentialOverrideAddRequest, CredentialOverrideRemoveRequest,
    CredentialOverrideSelector, CredentialWriteOutcome,
};
pub use diagnostics::{DiagnosticsSnapshot, SelectedRac};
pub use error::{AppError, AppErrorCategory, AppExitCode, ExitCodePolicy};
pub use infobases::InfobaseSearchRequest;
pub use normalize::{
    NormalizationError, RacNormalizer, normalize_cluster, normalize_connection, normalize_infobase,
    normalize_session,
};
pub use outcome::{
    ActionError, ActionItemOutcome, ActionMeta, ActionOutcome, ActionStatus, Approval,
    ConnectionKillOutcome, PreparedConnectionKill, PreparedSessionKill, SessionKillOutcome,
};
pub use ports::{
    AuditPort, AuditSinkAdapter, ConfigRepository, ConfigStoreAdapter, IdentityPort, PortError,
    PortErrorKind, RacPort, RawConfigSnapshot, WindowsIdentityAdapter,
};
pub use sessions::{SessionKillRequest, SessionListRequest};

#[derive(Clone, Debug)]
pub struct ClusterSelector {
    source: Option<String>,
    mask: Option<SqlMask>,
}

impl ClusterSelector {
    #[must_use]
    pub const fn all() -> Self {
        Self {
            source: None,
            mask: None,
        }
    }

    pub fn parse(value: Option<&str>) -> Result<Self, AppError> {
        match value {
            None => Ok(Self::all()),
            Some("") => Err(AppError::invalid(
                "invalid_cluster_selector",
                "Маска или alias кластера не может быть пустой",
            )),
            Some(value) => Ok(Self {
                source: Some(value.to_owned()),
                mask: Some(SqlMask::parse(value).map_err(AppError::from_domain)?),
            }),
        }
    }

    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    #[must_use]
    pub const fn is_all(&self) -> bool {
        self.source.is_none()
    }
}

impl Default for ClusterSelector {
    fn default() -> Self {
        Self::all()
    }
}

#[derive(Clone)]
pub struct AppServices {
    pub(crate) config: Arc<dyn ConfigRepository>,
    pub(crate) rac: Arc<dyn RacPort>,
    pub(crate) audit: Arc<dyn AuditPort>,
    pub(crate) identity: Arc<dyn IdentityPort>,
    pub(crate) fields: FieldRegistry,
    pub(crate) diagnostics: Arc<RwLock<DiagnosticsSnapshot>>,
}

impl AppServices {
    #[must_use]
    pub fn new<C, R, A, I>(config: C, rac: R, audit: A, identity: I) -> Self
    where
        C: ConfigRepository + 'static,
        R: RacPort + 'static,
        A: AuditPort + 'static,
        I: IdentityPort + 'static,
    {
        Self::from_ports(
            Arc::new(config),
            Arc::new(rac),
            Arc::new(audit),
            Arc::new(identity),
        )
    }

    #[must_use]
    pub fn from_ports(
        config: Arc<dyn ConfigRepository>,
        rac: Arc<dyn RacPort>,
        audit: Arc<dyn AuditPort>,
        identity: Arc<dyn IdentityPort>,
    ) -> Self {
        Self {
            config,
            rac,
            audit,
            identity,
            fields: FieldRegistry::new(),
            diagnostics: Arc::new(RwLock::new(DiagnosticsSnapshot::default())),
        }
    }

    #[must_use]
    pub fn from_infrastructure<A, I>(
        config: ConfigStore,
        rac: RacGateway,
        audit: A,
        identity: I,
    ) -> Self
    where
        A: AuditSink + 'static,
        I: WindowsIdentityProvider + 'static,
    {
        Self::new(
            ConfigStoreAdapter::new(config),
            rac,
            AuditSinkAdapter::new(audit),
            WindowsIdentityAdapter::new(identity),
        )
    }

    #[must_use]
    pub fn from_shared_infrastructure(
        config: Arc<ConfigStore>,
        rac: Arc<RacGateway>,
        audit: Arc<dyn AuditSink>,
        identity: Arc<dyn WindowsIdentityProvider>,
    ) -> Self {
        Self::from_ports(
            Arc::new(ConfigStoreAdapter::from_shared(config)),
            rac,
            Arc::new(AuditSinkAdapter::from_shared(audit)),
            Arc::new(WindowsIdentityAdapter::from_shared(identity)),
        )
    }

    #[must_use]
    pub const fn field_registry(&self) -> &FieldRegistry {
        &self.fields
    }

    pub async fn load_config_snapshot(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<ApplicationConfigSnapshot, AppError> {
        ensure_not_cancelled(cancellation)?;
        let raw = self.config.load().await.map_err(config_port_error)?;
        ensure_not_cancelled(cancellation)?;
        convert_config_snapshot(raw)
    }

    pub async fn load_config(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<ApplicationConfigSnapshot, AppError> {
        self.load_config_snapshot(cancellation).await
    }

    pub async fn configured_clusters(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Vec<crate::domain::ClusterTarget>, AppError> {
        self.load_config_snapshot(cancellation)
            .await
            .map(|snapshot| snapshot.cluster_targets())
    }

    pub async fn select_targets(
        &self,
        selector: &ClusterSelector,
        cancellation: &CancellationToken,
    ) -> Result<Vec<ConfiguredTarget>, AppError> {
        let snapshot = self.load_config_snapshot(cancellation).await?;
        select_configured_targets(&snapshot, selector)
    }

    pub(crate) async fn live_cluster(
        &self,
        configured: &ConfiguredTarget,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Result<LiveCluster, TargetError> {
        if cancellation.is_cancelled() {
            return Err(TargetError::new(
                configured.target.alias.clone(),
                configured.target.ras.clone(),
                TargetErrorKind::Cancelled,
                "Операция отменена",
            ));
        }
        let policy = configured.effective_search_policy(options);
        let records = self
            .rac
            .cluster_list(configured.target.ras.as_str(), &policy, cancellation)
            .await
            .map_err(|error| {
                error::target_error_from_rac(
                    configured.target.alias.clone(),
                    configured.target.ras.clone(),
                    error,
                )
            })?;
        if records.len() != 1 {
            return Err(TargetError::new(
                configured.target.alias.clone(),
                configured.target.ras.clone(),
                TargetErrorKind::InvalidResponse,
                format!(
                    "RAS должен вернуть ровно один кластер, получено: {}",
                    records.len()
                ),
            ));
        }
        let Some(record) = records.first() else {
            return Err(TargetError::new(
                configured.target.alias.clone(),
                configured.target.ras.clone(),
                TargetErrorKind::InvalidResponse,
                "RAS не вернул сведения о кластере",
            ));
        };
        let cluster = normalize_cluster(record).map_err(|error| {
            TargetError::new(
                configured.target.alias.clone(),
                configured.target.ras.clone(),
                TargetErrorKind::InvalidResponse,
                error.to_string(),
            )
        })?;
        if cluster.uuid != configured.target.discovered_cluster.uuid {
            return Err(TargetError::new(
                configured.target.alias.clone(),
                configured.target.ras.clone(),
                TargetErrorKind::InvalidResponse,
                format!(
                    "RAS вернул другой кластер: ожидался UUID {}, получен {}",
                    configured.target.discovered_cluster.uuid, cluster.uuid
                ),
            ));
        }
        self.verify_auth_identity(&configured.target.cluster_auth)
            .await
            .map_err(|error| target_error_from_port(configured, error))?;
        let source = ClusterSource::new(
            configured.target.alias.clone(),
            cluster.uuid,
            cluster.name.clone(),
            configured.target.ras.clone(),
        );
        Ok(LiveCluster {
            cluster,
            source,
            search_policy: policy,
        })
    }

    pub(crate) async fn verify_auth_identity(&self, auth: &AuthConfig) -> Result<(), PortError> {
        if let Some(expected) = auth.expected_os_user() {
            self.identity
                .verify_expected(expected.to_owned())
                .await
                .map(|_| ())
        } else {
            Ok(())
        }
    }

    pub(crate) async fn audit_user(&self) -> Result<String, AppError> {
        self.identity.current_identity().await.map_err(|error| {
            AppError::internal(
                error.code,
                format!(
                    "Не удалось определить текущего пользователя Windows для аудита: {}",
                    error.message
                ),
            )
        })
    }
}

impl fmt::Debug for AppServices {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServices")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LiveCluster {
    pub cluster: DiscoveredCluster,
    pub source: ClusterSource,
    pub search_policy: crate::infrastructure::rac::SearchPolicy,
}

pub(crate) fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<(), AppError> {
    if cancellation.is_cancelled() {
        Err(AppError::cancelled())
    } else {
        Ok(())
    }
}

pub(crate) fn select_configured_targets(
    snapshot: &ApplicationConfigSnapshot,
    selector: &ClusterSelector,
) -> Result<Vec<ConfiguredTarget>, AppError> {
    let Some(source) = selector.source() else {
        return Ok(snapshot.targets.clone());
    };

    // An existing alias wins over `_` mask semantics because `_` is also a
    // valid literal alias character.
    if let Some(exact) = snapshot
        .targets
        .iter()
        .find(|target| target.target.alias.as_str().eq_ignore_ascii_case(source))
    {
        return Ok(vec![exact.clone()]);
    }

    let Some(mask) = &selector.mask else {
        return Ok(snapshot.targets.clone());
    };
    let selected = snapshot
        .targets
        .iter()
        .filter(|target| mask.matches(target.target.alias.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if selected.is_empty() {
        let message = if mask.has_wildcards() {
            format!("Маска кластера `{source}` не выбрала ни одной цели")
        } else {
            format!("Кластер с alias `{source}` не найден")
        };
        Err(AppError::invalid("cluster_not_found", message))
    } else {
        Ok(selected)
    }
}

pub(crate) fn resolved_query_spec(
    kind: RecordKind,
    query: &Option<QuerySpec>,
    registry: &FieldRegistry,
) -> Result<QuerySpec, AppError> {
    let spec = match query {
        Some(spec) => spec.clone(),
        None => QuerySpec::new(kind, registry).map_err(AppError::from_domain)?,
    };
    if spec.kind() != kind {
        return Err(AppError::invalid(
            "query_kind_mismatch",
            format!(
                "Запрос типа `{}` нельзя применить к записям типа `{}`",
                spec.kind().as_str(),
                kind.as_str()
            ),
        ));
    }
    Ok(spec)
}

pub(crate) fn config_port_error(error: PortError) -> AppError {
    match error.kind {
        PortErrorKind::Conflict | PortErrorKind::NotFound | PortErrorKind::Configuration => {
            AppError::config(error.code, error.message)
        }
        _ => AppError::internal(error.code, error.message),
    }
}

pub(crate) fn target_error_from_port(target: &ConfiguredTarget, error: PortError) -> TargetError {
    let kind = match error.kind {
        PortErrorKind::IdentityMismatch => TargetErrorKind::Authentication,
        PortErrorKind::IdentityUnavailable => TargetErrorKind::Internal,
        _ => TargetErrorKind::Internal,
    };
    TargetError::new(
        target.target.alias.clone(),
        target.target.ras.clone(),
        kind,
        error.message,
    )
}

pub(crate) fn finish_target_results<T>(
    cancellation: &CancellationToken,
    data: Vec<T>,
    errors: Vec<TargetError>,
    successful_targets: usize,
) -> Result<(Vec<T>, Vec<TargetError>, usize), AppError> {
    if cancellation.is_cancelled() {
        return Err(AppError::cancelled().with_target_errors(errors));
    }
    if successful_targets == 0 && !errors.is_empty() {
        Err(AppError::all_targets_failed(errors))
    } else {
        Ok((data, errors, successful_targets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AuthConfig, ClusterAlias, ClusterTarget, ClusterUuid, DiscoveredCluster,
        InfobaseAuthPolicy, RacPolicy, RasEndpoint,
    };
    use crate::infrastructure::rac::{RacCredentials, SearchPolicy};
    use uuid::Uuid;

    fn target(alias: &str) -> ConfiguredTarget {
        let alias = ClusterAlias::new(alias).unwrap_or_else(|error| panic!("{error}"));
        let ras = "ras.local:1545"
            .parse::<RasEndpoint>()
            .unwrap_or_else(|error| panic!("{error}"));
        let cluster = DiscoveredCluster::new(
            ClusterUuid::new(Uuid::new_v4()),
            "cluster",
            "cluster.local",
            1541,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        ConfiguredTarget {
            target: ClusterTarget::new(
                alias,
                ras,
                cluster,
                RacPolicy::Auto,
                AuthConfig::none(),
                InfobaseAuthPolicy::default(),
            ),
            search_policy: SearchPolicy::isolated(),
            cluster_credentials: RacCredentials::none(),
        }
    }

    #[test]
    fn selector_prefers_exact_alias_with_underscore_then_uses_mask() {
        let snapshot = ApplicationConfigSnapshot {
            path: "config.yaml".into(),
            timeout: std::time::Duration::from_secs(30),
            global_rac_path: None,
            targets: vec![target("prod_1"), target("prodX1")],
        };
        let exact =
            ClusterSelector::parse(Some("prod_1")).unwrap_or_else(|error| panic!("{error}"));
        let selected =
            select_configured_targets(&snapshot, &exact).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].target.alias.as_str(), "prod_1");

        let mask = ClusterSelector::parse(Some("prod%")).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            select_configured_targets(&snapshot, &mask)
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            2
        );
    }
}
