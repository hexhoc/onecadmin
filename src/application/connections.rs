use std::collections::{BTreeMap, HashMap, HashSet};

use futures::future::join_all;
use tokio_util::sync::CancellationToken;

use crate::domain::{
    ConnectionKillPlan, ConnectionKillTarget, ConnectionRecord, ConnectionUuid, FieldValue, Filter,
    FilterOperator, ProcessUuid, QueryEngine, QueryOutcome, QuerySpec, RecordKind, SnapshotId,
    SqlMask, TargetError, TargetErrorKind,
};
use crate::infrastructure::rac::RacErrorKind;

use super::{
    ActionError, ActionItemOutcome, ActionOutcome, AppError, AppServices, Approval,
    ClusterSelector, ConfiguredTarget, ConnectionKillOutcome, PreparedConnectionKill, RacOptions,
    auth_to_rac_credentials, finish_target_results, normalize_connection, resolved_query_spec,
    select_configured_targets,
};

#[derive(Clone, Debug, Default)]
pub struct ConnectionListRequest {
    pub clusters: ClusterSelector,
    pub infobase: Option<SqlMask>,
    pub id: Option<ConnectionUuid>,
    pub number: Option<i64>,
    pub host: Option<SqlMask>,
    pub application: Option<SqlMask>,
    pub process: Option<ProcessUuid>,
    pub query: Option<QuerySpec>,
    pub rac_options: RacOptions,
}

impl ConnectionListRequest {
    #[must_use]
    pub fn has_destructive_selector(&self) -> bool {
        self.infobase.is_some()
            || self.id.is_some()
            || self.number.is_some()
            || self.host.is_some()
            || self.application.is_some()
            || self.process.is_some()
            || self
                .query
                .as_ref()
                .is_some_and(|query| !query.filters().is_empty() || query.text_query().is_some())
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConnectionKillRequest {
    pub selection: ConnectionListRequest,
}

impl AppServices {
    pub async fn list_connections(
        &self,
        request: &ConnectionListRequest,
        cancellation: &CancellationToken,
    ) -> Result<QueryOutcome<ConnectionRecord>, AppError> {
        let query = self.connection_query(request)?;
        let snapshot = self.load_config_snapshot(cancellation).await?;
        let targets = select_configured_targets(&snapshot, &request.clusters)?;
        let results =
            join_all(targets.iter().map(|target| {
                self.connections_for_target(target, &request.rac_options, cancellation)
            }))
            .await;

        let mut data = Vec::new();
        let mut errors = Vec::new();
        let mut successful_targets = 0_usize;
        for result in results {
            match result {
                Ok(mut records) => {
                    successful_targets += 1;
                    data.append(&mut records);
                }
                Err(error) => errors.push(error),
            }
        }
        self.update_diagnostics(&targets, &errors).await;
        let (data, errors, successful_targets) =
            finish_target_results(cancellation, data, errors, successful_targets)?;
        QueryEngine::new()
            .execute(data, errors, successful_targets, &query)
            .map_err(AppError::from_domain)
    }

    pub async fn connection_list(
        &self,
        request: &ConnectionListRequest,
        cancellation: &CancellationToken,
    ) -> Result<QueryOutcome<ConnectionRecord>, AppError> {
        self.list_connections(request, cancellation).await
    }

    fn connection_query(&self, request: &ConnectionListRequest) -> Result<QuerySpec, AppError> {
        let mut query = resolved_query_spec(RecordKind::Connection, &request.query, &self.fields)?;
        if let Some(value) = request.id {
            push_filter(
                &mut query,
                "connection",
                FilterOperator::Eq,
                FieldValue::Uuid(value.into_uuid()),
                self,
            )?;
        }
        if let Some(value) = request.number {
            push_filter(
                &mut query,
                "conn_id",
                FilterOperator::Eq,
                FieldValue::Int(value),
                self,
            )?;
        }
        if let Some(value) = request.process {
            push_filter(
                &mut query,
                "process",
                FilterOperator::Eq,
                FieldValue::Uuid(value.into_uuid()),
                self,
            )?;
        }
        for (field, mask) in [
            ("infobase", request.infobase.as_ref()),
            ("host", request.host.as_ref()),
            ("application", request.application.as_ref()),
        ] {
            if let Some(mask) = mask {
                push_filter(
                    &mut query,
                    field,
                    FilterOperator::Like,
                    FieldValue::Str(mask.source().to_owned()),
                    self,
                )?;
            }
        }
        Ok(query)
    }

    async fn connections_for_target(
        &self,
        target: &ConfiguredTarget,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Result<Vec<ConnectionRecord>, TargetError> {
        let live = self.live_cluster(target, options, cancellation).await?;
        let infobases = self.infobases_for_live(target, &live, cancellation).await?;
        let names = infobases
            .into_iter()
            .map(|infobase| (infobase.infobase_uuid, infobase.infobase))
            .collect::<HashMap<_, _>>();
        let records = self
            .rac
            .connection_list(
                target.target.ras.as_str(),
                live.cluster.uuid.into_uuid(),
                &target.cluster_credentials,
                &live.search_policy,
                cancellation,
            )
            .await
            .map_err(|error| {
                super::error::target_error_from_rac(
                    target.target.alias.clone(),
                    target.target.ras.clone(),
                    error,
                )
            })?;
        let mut seen = HashSet::with_capacity(records.len());
        let mut normalized = Vec::with_capacity(records.len());
        for record in &records {
            let mut item = normalize_connection(record, live.source.clone()).map_err(|error| {
                TargetError::new(
                    target.target.alias.clone(),
                    target.target.ras.clone(),
                    TargetErrorKind::InvalidResponse,
                    error.to_string(),
                )
            })?;
            if !seen.insert(item.connection) {
                return Err(TargetError::new(
                    target.target.alias.clone(),
                    target.target.ras.clone(),
                    TargetErrorKind::InvalidResponse,
                    format!(
                        "RAC вернул повторяющийся UUID соединения {}",
                        item.connection
                    ),
                ));
            }
            if let Some(uuid) = item.infobase_uuid {
                item.infobase = names.get(&uuid).cloned();
            }
            normalized.push(item);
        }
        Ok(normalized)
    }

    pub async fn prepare_connection_kill(
        &self,
        request: &ConnectionKillRequest,
        cancellation: &CancellationToken,
    ) -> Result<PreparedConnectionKill, AppError> {
        if !request.selection.has_destructive_selector() {
            return Err(AppError::invalid(
                "selector_required",
                "Разрыв соединений без предметного селектора запрещен; одного кластера недостаточно",
            ));
        }
        let outcome = self
            .list_connections(&request.selection, cancellation)
            .await?;
        if outcome.data.is_empty() {
            return Err(AppError::no_objects("connection"));
        }
        let plan = ConnectionKillPlan::from_records(SnapshotId::random(), &outcome.data)
            .map_err(AppError::from_domain)?;
        Ok(PreparedConnectionKill {
            plan,
            records: outcome.data,
            target_errors: outcome.errors,
            rac_options: request.selection.rac_options.clone(),
        })
    }

    pub async fn execute_prepared_connection_kill(
        &self,
        prepared: &PreparedConnectionKill,
        approval: Approval,
        cancellation: &CancellationToken,
    ) -> Result<ConnectionKillOutcome, AppError> {
        self.execute_connection_kill(
            &prepared.plan,
            approval,
            &prepared.rac_options,
            cancellation,
        )
        .await
    }

    pub async fn execute_connection_kill(
        &self,
        plan: &ConnectionKillPlan,
        _approval: Approval,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Result<ConnectionKillOutcome, AppError> {
        let snapshot = self.load_config_snapshot(cancellation).await?;
        let mut groups = BTreeMap::new();
        for (index, target) in plan.targets().iter().cloned().enumerate() {
            groups
                .entry((target.cluster.clone(), target.cluster_uuid))
                .or_insert_with(Vec::new)
                .push((index, target));
        }
        let grouped = join_all(groups.into_values().map(|targets| {
            self.execute_connection_group(&snapshot.targets, targets, options, cancellation)
        }))
        .await;
        let mut indexed = grouped.into_iter().flatten().collect::<Vec<_>>();
        indexed.sort_by_key(|(index, _)| *index);
        Ok(ActionOutcome::new(
            indexed.into_iter().map(|(_, item)| item).collect(),
        ))
    }

    async fn execute_connection_group(
        &self,
        configured: &[ConfiguredTarget],
        targets: Vec<(usize, ConnectionKillTarget)>,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Vec<(usize, ActionItemOutcome<ConnectionKillTarget>)> {
        let Some(first) = targets.first().map(|(_, target)| target) else {
            return Vec::new();
        };
        let configured = configured.iter().find(|configured| {
            configured.target.alias == first.cluster
                && configured.target.discovered_cluster.uuid == first.cluster_uuid
        });
        let Some(configured) = configured else {
            return self
                .fail_connection_group(
                    targets,
                    ActionError::new(
                        "cluster_snapshot_mismatch",
                        "Кластер отсутствует или изменился после создания снимка",
                    ),
                )
                .await;
        };
        let live = match self.live_cluster(configured, options, cancellation).await {
            Ok(live) => live,
            Err(error) => {
                return self
                    .fail_connection_group(targets, ActionError::new(error.code(), error.message))
                    .await;
            }
        };

        let mut outcomes = Vec::with_capacity(targets.len());
        for (index, target) in targets {
            let outcome = if cancellation.is_cancelled() {
                ActionItemOutcome::cancelled(target)
            } else {
                let auth = configured
                    .target
                    .infobase_auth
                    .resolve(
                        Some(target.infobase_uuid),
                        target.infobase.as_deref().unwrap_or(""),
                    )
                    .clone();
                match auth_to_rac_credentials(&auth) {
                    Err(error) => ActionItemOutcome::failed(
                        target,
                        ActionError::new(error.code(), error.message()),
                    ),
                    Ok(infobase_credentials) => match self
                        .rac
                        .connection_disconnect(
                            configured.target.ras.as_str(),
                            live.cluster.uuid.into_uuid(),
                            target.process_id.into_uuid(),
                            target.connection_id.into_uuid(),
                            &configured.cluster_credentials,
                            &infobase_credentials,
                            &live.search_policy,
                            cancellation,
                        )
                        .await
                    {
                        Ok(_) => ActionItemOutcome::success(target),
                        Err(error) if error.kind() == RacErrorKind::Cancelled => {
                            ActionItemOutcome::cancelled(target)
                        }
                        Err(error) => ActionItemOutcome::failed(
                            target,
                            ActionError::new(error.code(), error.to_string()),
                        ),
                    },
                }
            };
            outcomes.push((index, outcome));
        }
        outcomes
    }

    async fn fail_connection_group(
        &self,
        targets: Vec<(usize, ConnectionKillTarget)>,
        error: ActionError,
    ) -> Vec<(usize, ActionItemOutcome<ConnectionKillTarget>)> {
        targets
            .into_iter()
            .map(|(index, target)| (index, ActionItemOutcome::failed(target, error.clone())))
            .collect()
    }
}

fn push_filter(
    query: &mut QuerySpec,
    field: &str,
    operator: FilterOperator,
    value: FieldValue,
    services: &AppServices,
) -> Result<(), AppError> {
    let filter = Filter::from_value(
        RecordKind::Connection,
        field,
        operator,
        value,
        &services.fields,
    )
    .map_err(AppError::from_domain)?;
    query.push_filter(filter).map_err(AppError::from_domain)
}
