use std::collections::{BTreeMap, HashMap, HashSet};

use futures::future::join_all;
use tokio_util::sync::CancellationToken;

use crate::domain::{
    FieldValue, Filter, FilterOperator, QueryEngine, QueryOutcome, QuerySpec, RecordKind,
    SessionKillPlan, SessionKillTarget, SessionRecord, SessionUuid, SnapshotId, SqlMask,
    TargetError, TargetErrorKind,
};
use crate::infrastructure::rac::RacErrorKind;
use crate::infrastructure::telemetry::{AuditContext, AuditEvent, AuditResult, audit_actions};

use super::{
    ActionError, ActionItemOutcome, ActionOutcome, ActionStatus, AppError, AppServices, Approval,
    ClusterSelector, ConfiguredTarget, PreparedSessionKill, RacOptions, SessionKillOutcome,
    finish_target_results, normalize_session, resolved_query_spec, select_configured_targets,
};

#[derive(Clone, Debug, Default)]
pub struct SessionListRequest {
    pub clusters: ClusterSelector,
    pub infobase: Option<SqlMask>,
    pub id: Option<SessionUuid>,
    pub number: Option<i64>,
    pub user: Option<SqlMask>,
    pub host: Option<SqlMask>,
    pub app: Option<SqlMask>,
    pub query: Option<QuerySpec>,
    pub rac_options: RacOptions,
}

impl SessionListRequest {
    #[must_use]
    pub fn has_destructive_selector(&self) -> bool {
        self.infobase.is_some()
            || self.id.is_some()
            || self.number.is_some()
            || self.user.is_some()
            || self.host.is_some()
            || self.app.is_some()
            || self
                .query
                .as_ref()
                .is_some_and(|query| !query.filters().is_empty() || query.text_query().is_some())
    }
}

#[derive(Clone, Debug, Default)]
pub struct SessionKillRequest {
    pub selection: SessionListRequest,
    pub message: Option<String>,
}

impl AppServices {
    pub async fn list_sessions(
        &self,
        request: &SessionListRequest,
        cancellation: &CancellationToken,
    ) -> Result<QueryOutcome<SessionRecord>, AppError> {
        let query = self.session_query(request)?;
        let snapshot = self.load_config_snapshot(cancellation).await?;
        let targets = select_configured_targets(&snapshot, &request.clusters)?;
        let results =
            join_all(targets.iter().map(|target| {
                self.sessions_for_target(target, &request.rac_options, cancellation)
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

    pub async fn session_list(
        &self,
        request: &SessionListRequest,
        cancellation: &CancellationToken,
    ) -> Result<QueryOutcome<SessionRecord>, AppError> {
        self.list_sessions(request, cancellation).await
    }

    fn session_query(&self, request: &SessionListRequest) -> Result<QuerySpec, AppError> {
        let mut query = resolved_query_spec(RecordKind::Session, &request.query, &self.fields)?;
        if let Some(value) = request.id {
            push_filter(
                &mut query,
                "session",
                FilterOperator::Eq,
                FieldValue::Uuid(value.into_uuid()),
                self,
            )?;
        }
        if let Some(value) = request.number {
            push_filter(
                &mut query,
                "session_id",
                FilterOperator::Eq,
                FieldValue::Int(value),
                self,
            )?;
        }
        for (field, mask) in [
            ("infobase", request.infobase.as_ref()),
            ("user_name", request.user.as_ref()),
            ("host", request.host.as_ref()),
            ("app_id", request.app.as_ref()),
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

    async fn sessions_for_target(
        &self,
        target: &ConfiguredTarget,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SessionRecord>, TargetError> {
        let live = self.live_cluster(target, options, cancellation).await?;
        let infobases = self.infobases_for_live(target, &live, cancellation).await?;
        let names = infobases
            .into_iter()
            .map(|infobase| (infobase.infobase_uuid, infobase.infobase))
            .collect::<HashMap<_, _>>();
        let records = self
            .rac
            .session_list(
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
            let mut item = normalize_session(record, live.source.clone()).map_err(|error| {
                TargetError::new(
                    target.target.alias.clone(),
                    target.target.ras.clone(),
                    TargetErrorKind::InvalidResponse,
                    error.to_string(),
                )
            })?;
            if !seen.insert(item.session) {
                return Err(TargetError::new(
                    target.target.alias.clone(),
                    target.target.ras.clone(),
                    TargetErrorKind::InvalidResponse,
                    format!("RAC вернул повторяющийся UUID сеанса {}", item.session),
                ));
            }
            if let Some(uuid) = item.infobase_uuid {
                item.infobase = names.get(&uuid).cloned();
            }
            normalized.push(item);
        }
        Ok(normalized)
    }

    pub async fn prepare_session_kill(
        &self,
        request: &SessionKillRequest,
        cancellation: &CancellationToken,
    ) -> Result<PreparedSessionKill, AppError> {
        if !request.selection.has_destructive_selector() {
            return Err(AppError::invalid(
                "selector_required",
                "Завершение сеансов без предметного селектора запрещено; одного кластера недостаточно",
            ));
        }
        let outcome = self.list_sessions(&request.selection, cancellation).await?;
        if outcome.data.is_empty() {
            return Err(AppError::no_objects("session"));
        }
        let plan = SessionKillPlan::from_records(
            SnapshotId::random(),
            &outcome.data,
            request.message.clone(),
        )
        .map_err(AppError::from_domain)?;
        Ok(PreparedSessionKill {
            plan,
            records: outcome.data,
            target_errors: outcome.errors,
            rac_options: request.selection.rac_options.clone(),
        })
    }

    pub async fn execute_prepared_session_kill(
        &self,
        prepared: &PreparedSessionKill,
        approval: Approval,
        cancellation: &CancellationToken,
    ) -> Result<SessionKillOutcome, AppError> {
        self.execute_session_kill(
            &prepared.plan,
            approval,
            &prepared.rac_options,
            cancellation,
        )
        .await
    }

    pub async fn execute_session_kill(
        &self,
        plan: &SessionKillPlan,
        _approval: Approval,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Result<SessionKillOutcome, AppError> {
        let windows_user = self.audit_user().await?;
        let snapshot = self.load_config_snapshot(cancellation).await?;
        let mut groups = BTreeMap::new();
        for (index, target) in plan.targets().iter().cloned().enumerate() {
            groups
                .entry((target.cluster.clone(), target.cluster_uuid))
                .or_insert_with(Vec::new)
                .push((index, target));
        }
        let grouped = join_all(groups.into_values().map(|targets| {
            self.execute_session_group(
                &snapshot.targets,
                targets,
                plan.message(),
                options,
                &windows_user,
                cancellation,
            )
        }))
        .await;
        let mut indexed = grouped.into_iter().flatten().collect::<Vec<_>>();
        indexed.sort_by_key(|(index, _)| *index);
        Ok(ActionOutcome::new(
            indexed.into_iter().map(|(_, item)| item).collect(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_session_group(
        &self,
        configured: &[ConfiguredTarget],
        targets: Vec<(usize, SessionKillTarget)>,
        message: &str,
        options: &RacOptions,
        windows_user: &str,
        cancellation: &CancellationToken,
    ) -> Vec<(usize, ActionItemOutcome<SessionKillTarget>)> {
        let Some(first) = targets.first().map(|(_, target)| target) else {
            return Vec::new();
        };
        let configured = configured.iter().find(|configured| {
            configured.target.alias == first.cluster
                && configured.target.discovered_cluster.uuid == first.cluster_uuid
        });
        let Some(configured) = configured else {
            return self
                .fail_session_group(
                    targets,
                    ActionError::new(
                        "cluster_snapshot_mismatch",
                        "Кластер отсутствует или изменился после создания снимка",
                    ),
                    message,
                    windows_user,
                )
                .await;
        };
        let live = match self.live_cluster(configured, options, cancellation).await {
            Ok(live) => live,
            Err(error) => {
                return self
                    .fail_session_group(
                        targets,
                        ActionError::new(error.code(), error.message),
                        message,
                        windows_user,
                    )
                    .await;
            }
        };

        let mut outcomes = Vec::with_capacity(targets.len());
        for (index, target) in targets {
            let mut outcome = if cancellation.is_cancelled() {
                ActionItemOutcome::cancelled(target)
            } else {
                match self
                    .rac
                    .session_terminate(
                        configured.target.ras.as_str(),
                        live.cluster.uuid.into_uuid(),
                        target.session_id.into_uuid(),
                        Some(message),
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
            self.audit_session_outcome(windows_user, message, &mut outcome)
                .await;
            outcomes.push((index, outcome));
        }
        outcomes
    }

    async fn fail_session_group(
        &self,
        targets: Vec<(usize, SessionKillTarget)>,
        error: ActionError,
        message: &str,
        windows_user: &str,
    ) -> Vec<(usize, ActionItemOutcome<SessionKillTarget>)> {
        let mut outcomes = Vec::with_capacity(targets.len());
        for (index, target) in targets {
            let mut outcome = ActionItemOutcome::failed(target, error.clone());
            self.audit_session_outcome(windows_user, message, &mut outcome)
                .await;
            outcomes.push((index, outcome));
        }
        outcomes
    }

    async fn audit_session_outcome(
        &self,
        windows_user: &str,
        message: &str,
        outcome: &mut ActionItemOutcome<SessionKillTarget>,
    ) {
        let context = AuditContext {
            cluster_alias: Some(outcome.target.cluster.to_string()),
            cluster_uuid: Some(outcome.target.cluster_uuid.into_uuid()),
            infobase_name: outcome.target.infobase.clone(),
            infobase_uuid: outcome.target.infobase_uuid.map(|uuid| uuid.into_uuid()),
            session_uuid: Some(outcome.target.session_id.into_uuid()),
            connection_uuid: None,
            numeric_id: outcome
                .target
                .session_number
                .and_then(|number| u64::try_from(number).ok()),
            message: Some(message.to_owned()),
            reason: None,
        };
        let result = match outcome.status {
            ActionStatus::Success => AuditResult::Success,
            ActionStatus::Failed => AuditResult::Failure,
            ActionStatus::Cancelled => AuditResult::Cancelled,
        };
        let mut event = AuditEvent::new(windows_user, audit_actions::SESSION_KILL, result)
            .with_context(context);
        if let Some(error) = &outcome.error {
            event = event.with_error(error.code.clone(), error.message.clone());
        }
        if let Err(error) = self.audit.record(event).await {
            outcome.audit_error = Some(ActionError::new(error.code, error.message));
        }
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
        RecordKind::Session,
        field,
        operator,
        value,
        &services.fields,
    )
    .map_err(AppError::from_domain)?;
    query.push_filter(filter).map_err(AppError::from_domain)
}
