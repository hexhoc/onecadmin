use std::path::PathBuf;

use futures::future::join_all;
use tokio_util::sync::CancellationToken;

use crate::domain::{
    AuthConfig, ClusterAlias, ClusterTarget, InfobaseAuthPolicy, RacPolicy, RasEndpoint,
    TargetError,
};
use crate::infrastructure::config;

use super::conversion::{
    domain_auth_to_config, domain_infobase_auth_to_config, domain_rac_to_config,
    search_policy_for_new_cluster,
};
use super::{
    AppError, AppErrorCategory, AppServices, Approval, ConfiguredTarget, RacOptions, SelectedRac,
    auth_to_rac_credentials, config_port_error, convert_config_snapshot, ensure_not_cancelled,
    normalize_cluster,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClusterStatus {
    Ok,
    Error(TargetError),
}

#[derive(Clone, Debug)]
pub struct ClusterStatusEntry {
    pub target: ClusterTarget,
    pub status: ClusterStatus,
}

#[derive(Clone, Debug)]
pub struct ClusterAddRequest {
    pub alias: ClusterAlias,
    pub ras: RasEndpoint,
    pub cluster_auth: AuthConfig,
    pub infobase_auth: InfobaseAuthPolicy,
    pub rac_policy: RacPolicy,
    pub rac_options: RacOptions,
}

impl ClusterAddRequest {
    #[must_use]
    pub fn new(alias: ClusterAlias, ras: RasEndpoint, cluster_auth: AuthConfig) -> Self {
        Self {
            alias,
            ras,
            cluster_auth,
            infobase_auth: InfobaseAuthPolicy::default(),
            rac_policy: RacPolicy::Auto,
            rac_options: RacOptions::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClusterAddOutcome {
    pub target: ClusterTarget,
    pub config_path: PathBuf,
    pub selected_rac: Option<SelectedRac>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterRemovePlan {
    pub target: ClusterTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterRemoveOutcome {
    pub removed: ClusterTarget,
    pub config_path: PathBuf,
}

impl AppServices {
    pub async fn add_cluster(
        &self,
        request: ClusterAddRequest,
        cancellation: &CancellationToken,
    ) -> Result<ClusterAddOutcome, AppError> {
        self.add_cluster_inner(&request, cancellation).await
    }

    async fn add_cluster_inner(
        &self,
        request: &ClusterAddRequest,
        cancellation: &CancellationToken,
    ) -> Result<ClusterAddOutcome, AppError> {
        ensure_not_cancelled(cancellation)?;

        // Convert every value that will be persisted before any network call.
        let persisted_cluster_auth = domain_auth_to_config(&request.cluster_auth)?;
        let persisted_infobase_auth = domain_infobase_auth_to_config(&request.infobase_auth)?;
        let credentials = auth_to_rac_credentials(&request.cluster_auth)?;

        let snapshot = self.load_config_snapshot(cancellation).await?;
        if snapshot.targets.iter().any(|target| {
            target
                .target
                .alias
                .as_str()
                .eq_ignore_ascii_case(request.alias.as_str())
        }) {
            return Err(AppError::invalid(
                "cluster_already_exists",
                format!("Подключение с alias `{}` уже существует", request.alias),
            ));
        }

        let search_policy = search_policy_for_new_cluster(
            snapshot.global_rac_path.clone(),
            &request.rac_policy,
            &request.rac_options,
        );
        let records = self
            .rac
            .cluster_list(request.ras.as_str(), &search_policy, cancellation)
            .await
            .map_err(AppError::target_operation)?;
        if records.len() != 1 {
            return Err(AppError::new(
                AppErrorCategory::AllTargetsFailed,
                "invalid_cluster_count",
                format!(
                    "RAS `{}` должен вернуть ровно один кластер, получено: {}",
                    request.ras,
                    records.len()
                ),
            ));
        }
        let Some(record) = records.first() else {
            return Err(AppError::new(
                AppErrorCategory::AllTargetsFailed,
                "invalid_cluster_count",
                "RAS не вернул кластер",
            ));
        };
        let discovered = normalize_cluster(record).map_err(|error| {
            AppError::new(
                AppErrorCategory::AllTargetsFailed,
                error.code(),
                error.message(),
            )
        })?;

        // A successful authenticated command is mandatory; no offline path is
        // available and nothing is persisted before this point.
        self.rac
            .infobase_list(
                request.ras.as_str(),
                discovered.uuid.into_uuid(),
                &credentials,
                &search_policy,
                cancellation,
            )
            .await
            .map_err(AppError::target_operation)?;
        ensure_not_cancelled(cancellation)?;

        let persisted = config::ClusterConfig {
            ras: config::RasConfig {
                host: request.ras.host().to_owned(),
                port: request.ras.port(),
            },
            discovered_cluster: config::DiscoveredCluster {
                uuid: discovered.uuid.into_uuid(),
                name: discovered.name.clone(),
                host: discovered.host.clone(),
                port: discovered.port,
            },
            rac: domain_rac_to_config(&request.rac_policy),
            cluster_auth: persisted_cluster_auth,
            infobase_auth: persisted_infobase_auth,
        };
        let written = self
            .config
            .add_cluster(request.alias.to_string(), persisted)
            .await
            .map_err(config_port_error)?;
        let converted = convert_config_snapshot(written)?;
        let configured = converted
            .targets
            .iter()
            .find(|target| target.target.alias == request.alias)
            .cloned()
            .ok_or_else(|| {
                AppError::internal(
                    "config_write_invariant",
                    "Добавленный кластер отсутствует в записанном снимке конфигурации",
                )
            })?;
        self.update_diagnostics(std::slice::from_ref(&configured), &[])
            .await;
        let selected_rac = self
            .diagnostics()
            .await
            .selected_rac
            .into_iter()
            .find(|selected| selected.cluster == request.alias);
        Ok(ClusterAddOutcome {
            target: configured.target,
            config_path: converted.path,
            selected_rac,
        })
    }

    pub async fn cluster_statuses(
        &self,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Result<Vec<ClusterStatusEntry>, AppError> {
        let snapshot = self.load_config_snapshot(cancellation).await?;
        let entries = join_all(snapshot.targets.iter().map(|target| async {
            let status = match self.probe_cluster(target, options, cancellation).await {
                Ok(()) => ClusterStatus::Ok,
                Err(error) => ClusterStatus::Error(error),
            };
            ClusterStatusEntry {
                target: target.target.clone(),
                status,
            }
        }))
        .await;
        Ok(entries)
    }

    async fn probe_cluster(
        &self,
        target: &ConfiguredTarget,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Result<(), TargetError> {
        self.live_cluster(target, options, cancellation)
            .await
            .map(|_| ())
    }

    pub async fn prepare_cluster_remove(
        &self,
        alias: &str,
        cancellation: &CancellationToken,
    ) -> Result<ClusterRemovePlan, AppError> {
        let alias = ClusterAlias::new(alias).map_err(AppError::from_domain)?;
        let snapshot = self.load_config_snapshot(cancellation).await?;
        let target = snapshot
            .target(&alias)
            .ok_or_else(|| AppError::no_objects("cluster"))?;
        Ok(ClusterRemovePlan {
            target: target.target.clone(),
        })
    }

    pub async fn execute_cluster_remove(
        &self,
        plan: &ClusterRemovePlan,
        _approval: Approval,
        cancellation: &CancellationToken,
    ) -> Result<ClusterRemoveOutcome, AppError> {
        self.remove_cluster_inner(plan, cancellation).await
    }

    pub async fn remove_cluster(
        &self,
        plan: &ClusterRemovePlan,
        approval: Approval,
        cancellation: &CancellationToken,
    ) -> Result<ClusterRemoveOutcome, AppError> {
        self.execute_cluster_remove(plan, approval, cancellation)
            .await
    }

    async fn remove_cluster_inner(
        &self,
        plan: &ClusterRemovePlan,
        cancellation: &CancellationToken,
    ) -> Result<ClusterRemoveOutcome, AppError> {
        ensure_not_cancelled(cancellation)?;
        let snapshot = self.load_config_snapshot(cancellation).await?;
        let current = snapshot
            .target(&plan.target.alias)
            .ok_or_else(|| AppError::no_objects("cluster"))?;
        if current.target.discovered_cluster.uuid != plan.target.discovered_cluster.uuid {
            return Err(AppError::invalid(
                "cluster_changed",
                "Подключение изменилось после подготовки удаления; создайте новый план",
            ));
        }
        ensure_not_cancelled(cancellation)?;
        let written = self
            .config
            .remove_cluster(plan.target.alias.to_string())
            .await
            .map_err(config_port_error)?;
        Ok(ClusterRemoveOutcome {
            removed: plan.target.clone(),
            config_path: written.path,
        })
    }
}
