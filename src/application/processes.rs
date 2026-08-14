use std::collections::{BTreeMap, HashSet};

use futures::future::join_all;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::domain::{
    FieldValue, Filter, FilterOperator, ProcessKillPlan, ProcessKillTarget, ProcessRecord,
    ProcessUuid, QueryEngine, QueryOutcome, QuerySpec, RecordKind, SnapshotId, TargetError,
    TargetErrorKind,
};
use crate::infrastructure::rac::RacErrorKind;

use super::{
    ActionError, ActionItemOutcome, ActionOutcome, AppError, AppServices, Approval,
    ClusterSelector, ConfiguredTarget, PreparedProcessKill, ProcessKillOutcome, RacOptions,
    finish_target_results, normalize_process, resolved_query_spec, select_configured_targets,
};

#[derive(Clone, Debug, Default)]
pub struct ProcessListRequest {
    pub clusters: ClusterSelector,
    pub id: Option<ProcessUuid>,
    pub pid: Option<i64>,
    pub server: Option<Uuid>,
    pub query: Option<QuerySpec>,
    pub rac_options: RacOptions,
}

impl ProcessListRequest {
    #[must_use]
    pub fn has_destructive_selector(&self) -> bool {
        self.id.is_some()
            || self.pid.is_some()
            || self.server.is_some()
            || self
                .query
                .as_ref()
                .is_some_and(|query| !query.filters().is_empty() || query.text_query().is_some())
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcessKillRequest {
    pub selection: ProcessListRequest,
}

impl AppServices {
    pub async fn list_processes(
        &self,
        request: &ProcessListRequest,
        cancellation: &CancellationToken,
    ) -> Result<QueryOutcome<ProcessRecord>, AppError> {
        let query = self.process_query(request)?;
        let snapshot = self.load_config_snapshot(cancellation).await?;
        let targets = select_configured_targets(&snapshot, &request.clusters)?;
        let results =
            join_all(targets.iter().map(|target| {
                self.processes_for_target(target, &request.rac_options, cancellation)
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

    pub async fn process_list(
        &self,
        request: &ProcessListRequest,
        cancellation: &CancellationToken,
    ) -> Result<QueryOutcome<ProcessRecord>, AppError> {
        self.list_processes(request, cancellation).await
    }

    fn process_query(&self, request: &ProcessListRequest) -> Result<QuerySpec, AppError> {
        let mut query = resolved_query_spec(RecordKind::Process, &request.query, &self.fields)?;
        if let Some(value) = request.id {
            push_filter(
                &mut query,
                "process",
                FilterOperator::Eq,
                FieldValue::Uuid(value.into_uuid()),
                self,
            )?;
        }
        if let Some(value) = request.pid {
            push_filter(
                &mut query,
                "pid",
                FilterOperator::Eq,
                FieldValue::Int(value),
                self,
            )?;
        }
        if let Some(value) = request.server {
            push_filter(
                &mut query,
                "server",
                FilterOperator::Eq,
                FieldValue::Uuid(value),
                self,
            )?;
        }
        Ok(query)
    }

    async fn processes_for_target(
        &self,
        target: &ConfiguredTarget,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Result<Vec<ProcessRecord>, TargetError> {
        let live = self.live_cluster(target, options, cancellation).await?;
        let records = self
            .rac
            .process_list(
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
            let item = normalize_process(record, live.source.clone()).map_err(|error| {
                TargetError::new(
                    target.target.alias.clone(),
                    target.target.ras.clone(),
                    TargetErrorKind::InvalidResponse,
                    error.to_string(),
                )
            })?;
            if !seen.insert(item.process) {
                return Err(TargetError::new(
                    target.target.alias.clone(),
                    target.target.ras.clone(),
                    TargetErrorKind::InvalidResponse,
                    format!(
                        "RAC вернул повторяющийся UUID рабочего процесса {}",
                        item.process
                    ),
                ));
            }
            normalized.push(item);
        }
        Ok(normalized)
    }

    pub async fn prepare_process_kill(
        &self,
        request: &ProcessKillRequest,
        cancellation: &CancellationToken,
    ) -> Result<PreparedProcessKill, AppError> {
        if !request.selection.has_destructive_selector() {
            return Err(AppError::invalid(
                "selector_required",
                "Выключение рабочих процессов без предметного селектора запрещено; одного кластера недостаточно",
            ));
        }
        let outcome = self
            .list_processes(&request.selection, cancellation)
            .await?;
        if outcome.data.is_empty() {
            return Err(AppError::no_objects("process"));
        }
        let plan = ProcessKillPlan::from_records(SnapshotId::random(), &outcome.data)
            .map_err(AppError::from_domain)?;
        Ok(PreparedProcessKill {
            plan,
            records: outcome.data,
            target_errors: outcome.errors,
            rac_options: request.selection.rac_options.clone(),
        })
    }

    pub async fn execute_prepared_process_kill(
        &self,
        prepared: &PreparedProcessKill,
        approval: Approval,
        cancellation: &CancellationToken,
    ) -> Result<ProcessKillOutcome, AppError> {
        self.execute_process_kill(
            &prepared.plan,
            approval,
            &prepared.rac_options,
            cancellation,
        )
        .await
    }

    pub async fn execute_process_kill(
        &self,
        plan: &ProcessKillPlan,
        _approval: Approval,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Result<ProcessKillOutcome, AppError> {
        let snapshot = self.load_config_snapshot(cancellation).await?;
        let mut groups = BTreeMap::new();
        for (index, target) in plan.targets().iter().cloned().enumerate() {
            groups
                .entry((target.cluster.clone(), target.cluster_uuid))
                .or_insert_with(Vec::new)
                .push((index, target));
        }
        let grouped = join_all(groups.into_values().map(|targets| {
            self.execute_process_group(&snapshot.targets, targets, options, cancellation)
        }))
        .await;
        let mut indexed = grouped.into_iter().flatten().collect::<Vec<_>>();
        indexed.sort_by_key(|(index, _)| *index);
        Ok(ActionOutcome::new(
            indexed.into_iter().map(|(_, item)| item).collect(),
        ))
    }

    async fn execute_process_group(
        &self,
        configured: &[ConfiguredTarget],
        targets: Vec<(usize, ProcessKillTarget)>,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Vec<(usize, ActionItemOutcome<ProcessKillTarget>)> {
        let Some(first) = targets.first().map(|(_, target)| target) else {
            return Vec::new();
        };
        let configured = configured.iter().find(|configured| {
            configured.target.alias == first.cluster
                && configured.target.discovered_cluster.uuid == first.cluster_uuid
        });
        let Some(configured) = configured else {
            return targets
                .into_iter()
                .map(|(index, target)| {
                    (
                        index,
                        ActionItemOutcome::failed(
                            target,
                            ActionError::new(
                                "cluster_snapshot_mismatch",
                                "Кластер отсутствует или изменился после создания снимка",
                            ),
                        ),
                    )
                })
                .collect();
        };
        let live = match self.live_cluster(configured, options, cancellation).await {
            Ok(live) => live,
            Err(error) => {
                return targets
                    .into_iter()
                    .map(|(index, target)| {
                        (
                            index,
                            ActionItemOutcome::failed(
                                target,
                                ActionError::new(error.code(), error.message.clone()),
                            ),
                        )
                    })
                    .collect();
            }
        };

        let mut outcomes = Vec::with_capacity(targets.len());
        for (index, target) in targets {
            let outcome = if cancellation.is_cancelled() {
                ActionItemOutcome::cancelled(target)
            } else {
                match self
                    .rac
                    .process_turn_off(
                        configured.target.ras.as_str(),
                        live.cluster.uuid.into_uuid(),
                        target.process_id.into_uuid(),
                        &configured.cluster_credentials,
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
                }
            };
            outcomes.push((index, outcome));
        }
        outcomes
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
        RecordKind::Process,
        field,
        operator,
        value,
        &services.fields,
    )
    .map_err(AppError::from_domain)?;
    query.push_filter(filter).map_err(AppError::from_domain)
}
