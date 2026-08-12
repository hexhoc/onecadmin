use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::application::{
    AppServices, Approval, ClusterSelector, ConnectionKillRequest, ConnectionListRequest,
    InfobaseSearchRequest, SessionKillRequest, SessionListRequest,
};
use crate::domain::AuthMode;

use super::state::{
    ActionReport, BackgroundMessage, BackgroundPayload, ConnectionSelection, CredentialRow, Job,
    JobKind, OperationRequest, OperationResult, RefreshWork, SessionSelection, TaskFailure,
};

pub(crate) fn spawn_job(
    services: AppServices,
    job: Job,
    cancellation: CancellationToken,
    sender: mpsc::UnboundedSender<BackgroundMessage>,
) {
    tokio::spawn(async move {
        let payload = match job.kind {
            JobKind::Refresh(work) => {
                run_refresh(&services, work, &job.rac_options, &cancellation).await
            }
            JobKind::Operation(request) => BackgroundPayload::Operation(Box::new(
                run_operation(&services, request, &job.rac_options, &cancellation).await,
            )),
        };
        let _ = sender.send(BackgroundMessage {
            request_id: job.meta.request_id,
            generation: job.meta.generation,
            screen: job.meta.screen,
            payload,
        });
    });
}

async fn run_refresh(
    services: &AppServices,
    work: RefreshWork,
    rac_options: &crate::application::RacOptions,
    cancellation: &CancellationToken,
) -> BackgroundPayload {
    match work {
        RefreshWork::Clusters { query } => BackgroundPayload::Clusters(
            services
                .configured_clusters(cancellation)
                .await
                .map(|mut records| {
                    filter_clusters(&mut records, &query);
                    records
                })
                .map_err(TaskFailure::from),
        ),
        RefreshWork::Credentials { query } => {
            BackgroundPayload::Credentials(load_credentials(services, &query, cancellation).await)
        }
        RefreshWork::Infobases { query } => {
            let result = InfobaseSearchRequest::new("%").map(|mut request| {
                request.query = Some(query);
                request.rac_options = rac_options.clone();
                request
            });
            BackgroundPayload::Infobases(match result {
                Ok(request) => services
                    .search_infobases(&request, cancellation)
                    .await
                    .map_err(TaskFailure::from),
                Err(error) => Err(TaskFailure::from(error)),
            })
        }
        RefreshWork::Sessions { query } => {
            let request = SessionListRequest {
                query: Some(query),
                rac_options: rac_options.clone(),
                ..SessionListRequest::default()
            };
            BackgroundPayload::Sessions(
                services
                    .list_sessions(&request, cancellation)
                    .await
                    .map_err(TaskFailure::from),
            )
        }
        RefreshWork::Connections { query } => {
            let request = ConnectionListRequest {
                query: Some(query),
                rac_options: rac_options.clone(),
                ..ConnectionListRequest::default()
            };
            BackgroundPayload::Connections(
                services
                    .list_connections(&request, cancellation)
                    .await
                    .map_err(TaskFailure::from),
            )
        }
        RefreshWork::Diagnostics => {
            if cancellation.is_cancelled() {
                BackgroundPayload::Diagnostics(Err(cancelled()))
            } else {
                BackgroundPayload::Diagnostics(Ok(services.diagnostics().await))
            }
        }
    }
}

async fn load_credentials(
    services: &AppServices,
    query: &str,
    cancellation: &CancellationToken,
) -> Result<Vec<CredentialRow>, TaskFailure> {
    let clusters = services
        .configured_clusters(cancellation)
        .await
        .map_err(TaskFailure::from)?;
    let mut rows = Vec::new();
    for cluster in clusters {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let entries = services
            .credential_overrides(cluster.alias.as_str(), cancellation)
            .await
            .map_err(TaskFailure::from)?;
        rows.extend(entries.into_iter().map(|entry| CredentialRow {
            cluster: cluster.alias.clone(),
            cluster_uuid: cluster.discovered_cluster.uuid,
            entry,
        }));
    }
    rows.sort_by(|left, right| {
        left.cluster.cmp(&right.cluster).then_with(|| {
            left.entry
                .infobase()
                .unwrap_or_default()
                .to_lowercase()
                .cmp(&right.entry.infobase().unwrap_or_default().to_lowercase())
        })
    });
    filter_credentials(&mut rows, query);
    Ok(rows)
}

fn filter_clusters(records: &mut Vec<crate::domain::ClusterTarget>, query: &str) {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return;
    }
    records.retain(|record| {
        [
            record.alias.as_str(),
            record.ras.as_str(),
            &record.discovered_cluster.name,
            &record.discovered_cluster.host,
        ]
        .iter()
        .any(|value| value.to_lowercase().contains(&query))
    });
}

fn filter_credentials(records: &mut Vec<CredentialRow>, query: &str) {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return;
    }
    records.retain(|record| {
        let mode = auth_mode(record.entry.auth().mode());
        [
            record.cluster.as_str(),
            record.entry.infobase().unwrap_or_default(),
            record.entry.auth().user().unwrap_or_default(),
            record.entry.auth().expected_os_user().unwrap_or_default(),
            mode,
        ]
        .iter()
        .any(|value| value.to_lowercase().contains(&query))
            || record
                .entry
                .infobase_uuid()
                .is_some_and(|uuid| uuid.to_string().to_lowercase().contains(&query))
    });
}

const fn auth_mode(mode: AuthMode) -> &'static str {
    match mode {
        AuthMode::None => "none",
        AuthMode::Password => "password",
        AuthMode::Os => "os",
    }
}

async fn run_operation(
    services: &AppServices,
    request: OperationRequest,
    rac_options: &crate::application::RacOptions,
    cancellation: &CancellationToken,
) -> Result<OperationResult, TaskFailure> {
    if cancellation.is_cancelled() {
        return Err(cancelled());
    }
    match request {
        OperationRequest::AddCluster(request) => services
            .add_cluster(request, cancellation)
            .await
            .map(|outcome| OperationResult::ClusterAdded(outcome.target.alias.to_string()))
            .map_err(TaskFailure::from),
        OperationRequest::PrepareClusterRemove(alias) => services
            .prepare_cluster_remove(&alias, cancellation)
            .await
            .map(|plan| OperationResult::ClusterRemovePrepared(Box::new(plan)))
            .map_err(TaskFailure::from),
        OperationRequest::RemoveCluster(plan) => services
            .execute_cluster_remove(&plan, Approval::Confirmed, cancellation)
            .await
            .map(|outcome| OperationResult::ClusterRemoved(outcome.removed.alias.to_string()))
            .map_err(TaskFailure::from),
        OperationRequest::AddCredential(request) => services
            .add_credential_override(request, cancellation)
            .await
            .map(|outcome| {
                OperationResult::CredentialAdded(
                    outcome.entry.infobase().unwrap_or_default().to_owned(),
                )
            })
            .map_err(TaskFailure::from),
        OperationRequest::RemoveCredential(request) => services
            .remove_credential_override(request, cancellation)
            .await
            .map(|outcome| {
                OperationResult::CredentialRemoved(
                    outcome.entry.infobase().unwrap_or_default().to_owned(),
                )
            })
            .map_err(TaskFailure::from),
        OperationRequest::PrepareSessionKill(selections) => {
            prepare_sessions(services, selections, rac_options, cancellation)
                .await
                .map(OperationResult::SessionKillPrepared)
        }
        OperationRequest::KillSessions(prepared) => {
            execute_sessions(services, prepared, cancellation)
                .await
                .map(OperationResult::SessionsKilled)
        }
        OperationRequest::PrepareConnectionKill(selections) => {
            prepare_connections(services, selections, rac_options, cancellation)
                .await
                .map(OperationResult::ConnectionKillPrepared)
        }
        OperationRequest::KillConnections(prepared) => {
            execute_connections(services, prepared, cancellation)
                .await
                .map(OperationResult::ConnectionsKilled)
        }
    }
}

async fn prepare_sessions(
    services: &AppServices,
    selections: Vec<SessionSelection>,
    rac_options: &crate::application::RacOptions,
    cancellation: &CancellationToken,
) -> Result<Vec<crate::application::PreparedSessionKill>, TaskFailure> {
    if selections.is_empty() {
        return Err(TaskFailure::new(
            "selector_required",
            "Не выбран ни один точный UUID сеанса",
        ));
    }
    let mut prepared_items = Vec::with_capacity(selections.len());
    for selected in selections {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let mut selection = SessionListRequest {
            clusters: ClusterSelector::parse(Some(&selected.cluster)).map_err(TaskFailure::from)?,
            id: Some(selected.session),
            ..SessionListRequest::default()
        };
        // The exact UUID is the destructive selector. No broad query or empty
        // filter can reach the application prepare method from this path.
        selection.rac_options = rac_options.clone();
        let request = SessionKillRequest {
            selection,
            message: None,
        };
        let prepared = services
            .prepare_session_kill(&request, cancellation)
            .await
            .map_err(TaskFailure::from)?;
        let valid = matches!(prepared.records.as_slice(), [record]
            if record.source.cluster_uuid == selected.cluster_uuid
                && record.session == selected.session)
            && prepared.plan.len() == 1;
        if !valid {
            return Err(TaskFailure::new(
                "selection_changed",
                format!(
                    "Подготовленный план не соответствует выбранному сеансу {} в кластере {}",
                    selected.session, selected.cluster
                ),
            ));
        }
        prepared_items.push(prepared);
    }
    Ok(prepared_items)
}

async fn prepare_connections(
    services: &AppServices,
    selections: Vec<ConnectionSelection>,
    rac_options: &crate::application::RacOptions,
    cancellation: &CancellationToken,
) -> Result<Vec<crate::application::PreparedConnectionKill>, TaskFailure> {
    if selections.is_empty() {
        return Err(TaskFailure::new(
            "selector_required",
            "Не выбран ни один точный UUID соединения",
        ));
    }
    let mut prepared_items = Vec::with_capacity(selections.len());
    for selected in selections {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let selection = ConnectionListRequest {
            clusters: ClusterSelector::parse(Some(&selected.cluster)).map_err(TaskFailure::from)?,
            id: Some(selected.connection),
            rac_options: rac_options.clone(),
            ..ConnectionListRequest::default()
        };
        let request = ConnectionKillRequest { selection };
        let prepared = services
            .prepare_connection_kill(&request, cancellation)
            .await
            .map_err(TaskFailure::from)?;
        let valid = matches!(prepared.records.as_slice(), [record]
            if record.source.cluster_uuid == selected.cluster_uuid
                && record.connection == selected.connection)
            && prepared.plan.len() == 1;
        if !valid {
            return Err(TaskFailure::new(
                "selection_changed",
                format!(
                    "Подготовленный план не соответствует выбранному соединению {} в кластере {}",
                    selected.connection, selected.cluster
                ),
            ));
        }
        prepared_items.push(prepared);
    }
    Ok(prepared_items)
}

async fn execute_sessions(
    services: &AppServices,
    prepared: Vec<crate::application::PreparedSessionKill>,
    cancellation: &CancellationToken,
) -> Result<ActionReport, TaskFailure> {
    if prepared.is_empty() {
        return Err(TaskFailure::new(
            "empty_kill_plan",
            "Нет подготовленных планов завершения сеансов",
        ));
    }
    let mut report = ActionReport::default();
    for item in prepared {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let outcome = services
            .execute_prepared_session_kill(&item, Approval::Confirmed, cancellation)
            .await
            .map_err(TaskFailure::from)?;
        report.attempted += outcome.meta.attempted;
        report.succeeded += outcome.meta.succeeded;
        report.failed += outcome.meta.failed;
        report.cancelled += outcome.meta.cancelled;
        report.audit_failed += outcome.meta.audit_failed;
        for result in outcome.items {
            if let Some(error) = result.error {
                report.errors.push(format!(
                    "{} session={} {}: {}",
                    result.target.cluster, result.target.session_id, error.code, error.message
                ));
            }
            if let Some(error) = result.audit_error {
                report.errors.push(format!(
                    "{} session={} audit {}: {}",
                    result.target.cluster, result.target.session_id, error.code, error.message
                ));
            }
        }
    }
    Ok(report)
}

async fn execute_connections(
    services: &AppServices,
    prepared: Vec<crate::application::PreparedConnectionKill>,
    cancellation: &CancellationToken,
) -> Result<ActionReport, TaskFailure> {
    if prepared.is_empty() {
        return Err(TaskFailure::new(
            "empty_kill_plan",
            "Нет подготовленных планов разрыва соединений",
        ));
    }
    let mut report = ActionReport::default();
    for item in prepared {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let outcome = services
            .execute_prepared_connection_kill(&item, Approval::Confirmed, cancellation)
            .await
            .map_err(TaskFailure::from)?;
        report.attempted += outcome.meta.attempted;
        report.succeeded += outcome.meta.succeeded;
        report.failed += outcome.meta.failed;
        report.cancelled += outcome.meta.cancelled;
        report.audit_failed += outcome.meta.audit_failed;
        for result in outcome.items {
            if let Some(error) = result.error {
                report.errors.push(format!(
                    "{} connection={} {}: {}",
                    result.target.cluster, result.target.connection_id, error.code, error.message
                ));
            }
            if let Some(error) = result.audit_error {
                report.errors.push(format!(
                    "{} connection={} audit {}: {}",
                    result.target.cluster, result.target.connection_id, error.code, error.message
                ));
            }
        }
    }
    Ok(report)
}

fn cancelled() -> TaskFailure {
    TaskFailure::new("cancelled", "Операция отменена")
}
