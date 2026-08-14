use std::io;
use std::path::Path;

use comfy_table::{ContentArrangement, Table, presets};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

pub use crate::application::AppExitCode;
use crate::application::{
    ActionOutcome, ActionStatus, AppError, AppErrorCategory, AppServices, Approval,
    ClusterAddRequest, ClusterSelector, ConnectionKillOutcome, ConnectionKillRequest,
    ConnectionListRequest, ExitCodePolicy, InfobaseSearchRequest, RacOptions, SessionKillOutcome,
    SessionKillRequest, SessionListRequest,
};
use crate::domain::{
    ConnectionKillTarget, FieldAccess, FieldRegistry, InfobaseAuthPolicy, Projection, QueryOutcome,
    QuerySpec, RecordKind, SessionKillTarget, SqlMask, TargetError,
};
use crate::infrastructure::telemetry::SecretRedactor;

use super::args::{
    Cli, CliCommand, ClusterAddArgs, ClusterCommand, ClusterRemoveArgs, ConnectionCommand,
    ConnectionKillArgs, ConnectionListArgs, InfobaseCommand, InfobaseSearchArgs, OutputFormat,
    QueryOptions, SessionCommand, SessionKillArgs, SessionListArgs,
};
use super::confirm::{Confirmation, confirm};
use super::output::{OutputError, OutputRenderer, RenderedOutput};

const SESSION_PREVIEW_COLUMNS: &str = "cluster,infobase,session,session_id,user_name,host,app_id";
const CONNECTION_PREVIEW_COLUMNS: &str =
    "cluster,infobase,connection,conn_id,host,application,process";

/// Complete process-facing result of one CLI command.
///
/// Dispatch never writes command data to stdout itself. The binary boundary is
/// responsible for writing these byte buffers and converting `exit_code` to a
/// process exit code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliRunResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: AppExitCode,
}

impl CliRunResult {
    #[must_use]
    pub fn new(output: RenderedOutput, exit_code: AppExitCode) -> Self {
        Self {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code,
        }
    }

    #[must_use]
    pub fn rendered_output(&self) -> RenderedOutput {
        RenderedOutput {
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
        }
    }

    #[must_use]
    pub fn into_rendered_output(self) -> RenderedOutput {
        RenderedOutput {
            stdout: self.stdout,
            stderr: self.stderr,
        }
    }

    fn prepend_stderr(&mut self, mut prefix: Vec<u8>) {
        if prefix.is_empty() {
            return;
        }
        if !prefix.ends_with(b"\n") && !self.stderr.is_empty() {
            prefix.push(b'\n');
        }
        prefix.append(&mut self.stderr);
        self.stderr = prefix;
    }
}

impl ExitCodePolicy for CliRunResult {
    fn app_exit_code(&self) -> AppExitCode {
        self.exit_code
    }
}

#[derive(Debug)]
struct DispatchFailure {
    error: AppError,
    stderr_prefix: Vec<u8>,
}

impl DispatchFailure {
    fn with_stderr(error: AppError, stderr_prefix: Vec<u8>) -> Self {
        Self {
            error,
            stderr_prefix,
        }
    }

    fn output(error: OutputError, stderr_prefix: Vec<u8>) -> Self {
        Self::with_stderr(
            AppError::internal("output_error", error.to_string()),
            stderr_prefix,
        )
    }
}

impl From<AppError> for DispatchFailure {
    fn from(error: AppError) -> Self {
        Self::with_stderr(error, Vec::new())
    }
}

impl From<OutputError> for DispatchFailure {
    fn from(error: OutputError) -> Self {
        Self::output(error, Vec::new())
    }
}

/// Executes a parsed CLI command using the production terminal confirmation.
///
/// Confirmation preview and prompt are emitted by `confirm` to stderr because
/// they must be visible before stdin is read. All non-interactive command
/// output is returned in `CliRunResult`.
pub async fn dispatch(
    cli: &Cli,
    services: &AppServices,
    cancellation: &CancellationToken,
) -> CliRunResult {
    dispatch_with_confirmation(cli, services, cancellation, confirm).await
}

/// Testable and embeddable dispatcher variant.
///
/// The callback owns the interactive boundary: it receives a prompt and the
/// complete preview intended for stderr. A production callback must display
/// the preview before asking for input. It must never write either value to
/// stdout.
pub async fn dispatch_with_confirmation<F>(
    cli: &Cli,
    services: &AppServices,
    cancellation: &CancellationToken,
    mut request_confirmation: F,
) -> CliRunResult
where
    F: FnMut(&str, &str) -> io::Result<Confirmation>,
{
    let redactor = redactor_for_cli(cli);
    if cancellation.is_cancelled() {
        return render_app_error(
            cli.format,
            &AppError::interrupted(),
            &redactor,
            AppExitCode::Interrupted,
        );
    }

    if let Err(error) = cli.validate() {
        let error = AppError::invalid(error.code(), error.message());
        return render_app_error(cli.format, &error, &redactor, AppExitCode::InvalidInput);
    }

    match run_command(
        cli,
        services,
        cancellation,
        &redactor,
        &mut request_confirmation,
    )
    .await
    {
        Ok(mut result) => {
            if result.exit_code == AppExitCode::Cancelled && cancellation.is_cancelled() {
                result.exit_code = AppExitCode::Interrupted;
            }
            result
        }
        Err(failure) => {
            let interrupted = failure.error.app_exit_code() == AppExitCode::Cancelled
                && cancellation.is_cancelled();
            let mut result = if interrupted {
                render_app_error(
                    cli.format,
                    &AppError::interrupted(),
                    &redactor,
                    AppExitCode::Interrupted,
                )
            } else {
                let exit_code = failure.error.app_exit_code();
                render_app_error(cli.format, &failure.error, &redactor, exit_code)
            };
            result.prepend_stderr(failure.stderr_prefix);
            result
        }
    }
}

async fn run_command<F>(
    cli: &Cli,
    services: &AppServices,
    cancellation: &CancellationToken,
    redactor: &SecretRedactor,
    request_confirmation: &mut F,
) -> Result<CliRunResult, DispatchFailure>
where
    F: FnMut(&str, &str) -> io::Result<Confirmation>,
{
    match cli.command.as_ref() {
        None => Err(AppError::invalid(
            "command_required",
            "CLI dispatcher требует явную подкоманду",
        )
        .into()),
        Some(CliCommand::Cluster { command }) => match command {
            ClusterCommand::Add(args) => run_cluster_add(cli, services, cancellation, args).await,
            ClusterCommand::Remove(args) => {
                run_cluster_remove(cli, services, cancellation, args, request_confirmation).await
            }
        },
        Some(CliCommand::Infobase { command }) => match command {
            InfobaseCommand::Search(args) => {
                run_infobase_search(cli, services, cancellation, redactor, args).await
            }
        },
        Some(CliCommand::Session { command }) => match command {
            SessionCommand::List(args) => {
                run_session_list(cli, services, cancellation, redactor, args).await
            }
            SessionCommand::Kill(args) => {
                run_session_kill(
                    cli,
                    services,
                    cancellation,
                    redactor,
                    args,
                    request_confirmation,
                )
                .await
            }
        },
        Some(CliCommand::Connection { command }) => match command {
            ConnectionCommand::List(args) => {
                run_connection_list(cli, services, cancellation, redactor, args).await
            }
            ConnectionCommand::Kill(args) => {
                run_connection_kill(
                    cli,
                    services,
                    cancellation,
                    redactor,
                    args,
                    request_confirmation,
                )
                .await
            }
        },
    }
}

async fn run_cluster_add(
    cli: &Cli,
    services: &AppServices,
    cancellation: &CancellationToken,
    args: &ClusterAddArgs,
) -> Result<CliRunResult, DispatchFailure> {
    let cluster_auth = args
        .cluster_auth()
        .map_err(|error| AppError::invalid(error.code(), error.message()))?;
    let default_infobase_auth = args
        .infobase_auth()
        .map_err(|error| AppError::invalid(error.code(), error.message()))?;
    let infobase_auth = InfobaseAuthPolicy::new(default_infobase_auth, Vec::new())
        .map_err(AppError::from_domain)?;

    let mut request = ClusterAddRequest::new(args.name.clone(), args.ras.clone(), cluster_auth);
    request.infobase_auth = infobase_auth;
    request.rac_options = rac_options(cli);

    let outcome = services.add_cluster(request, cancellation).await?;
    render_cluster_mutation("added", &outcome.target, &outcome.config_path, cli.format)
        .map_err(DispatchFailure::from)
}

async fn run_cluster_remove<F>(
    cli: &Cli,
    services: &AppServices,
    cancellation: &CancellationToken,
    args: &ClusterRemoveArgs,
    request_confirmation: &mut F,
) -> Result<CliRunResult, DispatchFailure>
where
    F: FnMut(&str, &str) -> io::Result<Confirmation>,
{
    let plan = services
        .prepare_cluster_remove(args.name.as_str(), cancellation)
        .await?;
    let preview = format!(
        "Будет удалено подключение: cluster={}, cluster_uuid={}, ras_address={}\n",
        plan.target.alias, plan.target.discovered_cluster.uuid, plan.target.ras
    )
    .into_bytes();
    let prompt = format!("Удалить подключение к кластеру `{}`?", plan.target.alias);
    let (approval, retain_preview) =
        request_approval(args.force, &prompt, &preview, request_confirmation)?;
    let stderr_prefix = if retain_preview { preview } else { Vec::new() };

    let outcome = match services
        .execute_cluster_remove(&plan, approval, cancellation)
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => return Err(DispatchFailure::with_stderr(error, stderr_prefix)),
    };
    let mut result = match render_cluster_mutation(
        "removed",
        &outcome.removed,
        &outcome.config_path,
        cli.format,
    ) {
        Ok(result) => result,
        Err(error) => return Err(DispatchFailure::output(error, stderr_prefix)),
    };
    result.prepend_stderr(stderr_prefix);
    Ok(result)
}

async fn run_infobase_search(
    cli: &Cli,
    services: &AppServices,
    cancellation: &CancellationToken,
    redactor: &SecretRedactor,
    args: &InfobaseSearchArgs,
) -> Result<CliRunResult, DispatchFailure> {
    let (request, projection) = build_infobase_request(cli, services, args)?;
    let mut outcome = services.search_infobases(&request, cancellation).await?;
    sanitize_target_errors(&mut outcome.errors, redactor);
    render_query(cli, RecordKind::Infobase, &outcome, &projection).map_err(DispatchFailure::from)
}

async fn run_session_list(
    cli: &Cli,
    services: &AppServices,
    cancellation: &CancellationToken,
    redactor: &SecretRedactor,
    args: &SessionListArgs,
) -> Result<CliRunResult, DispatchFailure> {
    let (request, projection) = build_session_list_request(cli, services, args)?;
    let mut outcome = services.list_sessions(&request, cancellation).await?;
    sanitize_target_errors(&mut outcome.errors, redactor);
    render_query(cli, RecordKind::Session, &outcome, &projection).map_err(DispatchFailure::from)
}

async fn run_connection_list(
    cli: &Cli,
    services: &AppServices,
    cancellation: &CancellationToken,
    redactor: &SecretRedactor,
    args: &ConnectionListArgs,
) -> Result<CliRunResult, DispatchFailure> {
    let (request, projection) = build_connection_list_request(cli, services, args)?;
    let mut outcome = services.list_connections(&request, cancellation).await?;
    sanitize_target_errors(&mut outcome.errors, redactor);
    render_query(cli, RecordKind::Connection, &outcome, &projection).map_err(DispatchFailure::from)
}

async fn run_session_kill<F>(
    cli: &Cli,
    services: &AppServices,
    cancellation: &CancellationToken,
    redactor: &SecretRedactor,
    args: &SessionKillArgs,
    request_confirmation: &mut F,
) -> Result<CliRunResult, DispatchFailure>
where
    F: FnMut(&str, &str) -> io::Result<Confirmation>,
{
    let list_args = SessionListArgs {
        selectors: args.selectors.clone(),
        query: args.query.clone(),
    };
    let (selection, _) = build_session_list_request(cli, services, &list_args)?;
    let request = SessionKillRequest {
        selection,
        message: args.message.clone(),
    };
    let mut prepared = services
        .prepare_session_kill(&request, cancellation)
        .await?;
    sanitize_target_errors(&mut prepared.target_errors, redactor);

    let projection = Projection::parse(
        Some(SESSION_PREVIEW_COLUMNS),
        RecordKind::Session,
        services.field_registry(),
    )
    .map_err(|error| {
        AppError::internal(
            "preview_projection_error",
            format!("Не удалось построить проекцию предпросмотра сеансов: {error}"),
        )
    })?;
    let preview = render_preview(
        cli,
        RecordKind::Session,
        &prepared.records,
        &prepared.target_errors,
        &projection,
        "Выбрано сеансов",
    )?;
    let prompt = format!("Завершить выбранные сеансы ({})?", prepared.plan.len());
    let (approval, retain_preview) =
        request_approval(args.force, &prompt, &preview, request_confirmation)?;
    let stderr_prefix = if retain_preview { preview } else { Vec::new() };

    let mut outcome = match services
        .execute_prepared_session_kill(&prepared, approval, cancellation)
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => return Err(DispatchFailure::with_stderr(error, stderr_prefix)),
    };
    sanitize_action_outcome(&mut outcome, redactor);
    let exit_code = action_exit_code(&outcome, &prepared.target_errors);
    let mut result = match render_session_action(
        cli.format,
        &outcome,
        &prepared.target_errors,
        exit_code,
        redactor,
    ) {
        Ok(result) => result,
        Err(error) => return Err(DispatchFailure::output(error, stderr_prefix)),
    };
    result.prepend_stderr(stderr_prefix);
    Ok(result)
}

async fn run_connection_kill<F>(
    cli: &Cli,
    services: &AppServices,
    cancellation: &CancellationToken,
    redactor: &SecretRedactor,
    args: &ConnectionKillArgs,
    request_confirmation: &mut F,
) -> Result<CliRunResult, DispatchFailure>
where
    F: FnMut(&str, &str) -> io::Result<Confirmation>,
{
    let list_args = ConnectionListArgs {
        selectors: args.selectors.clone(),
        query: args.query.clone(),
    };
    let (selection, _) = build_connection_list_request(cli, services, &list_args)?;
    let request = ConnectionKillRequest { selection };
    let mut prepared = services
        .prepare_connection_kill(&request, cancellation)
        .await?;
    sanitize_target_errors(&mut prepared.target_errors, redactor);

    let projection = Projection::parse(
        Some(CONNECTION_PREVIEW_COLUMNS),
        RecordKind::Connection,
        services.field_registry(),
    )
    .map_err(|error| {
        AppError::internal(
            "preview_projection_error",
            format!("Не удалось построить проекцию предпросмотра соединений: {error}"),
        )
    })?;
    let preview = render_preview(
        cli,
        RecordKind::Connection,
        &prepared.records,
        &prepared.target_errors,
        &projection,
        "Выбрано соединений",
    )?;
    let prompt = format!("Разорвать выбранные соединения ({})?", prepared.plan.len());
    let (approval, retain_preview) =
        request_approval(args.force, &prompt, &preview, request_confirmation)?;
    let stderr_prefix = if retain_preview { preview } else { Vec::new() };

    let mut outcome = match services
        .execute_prepared_connection_kill(&prepared, approval, cancellation)
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => return Err(DispatchFailure::with_stderr(error, stderr_prefix)),
    };
    sanitize_action_outcome(&mut outcome, redactor);
    let exit_code = action_exit_code(&outcome, &prepared.target_errors);
    let mut result = match render_connection_action(
        cli.format,
        &outcome,
        &prepared.target_errors,
        exit_code,
        redactor,
    ) {
        Ok(result) => result,
        Err(error) => return Err(DispatchFailure::output(error, stderr_prefix)),
    };
    result.prepend_stderr(stderr_prefix);
    Ok(result)
}

fn build_infobase_request(
    cli: &Cli,
    services: &AppServices,
    args: &InfobaseSearchArgs,
) -> Result<(InfobaseSearchRequest, Projection), AppError> {
    let query = QuerySpec::parse(
        RecordKind::Infobase,
        std::iter::empty::<&str>(),
        None,
        std::iter::empty::<&str>(),
        None,
        args.columns.as_deref(),
        services.field_registry(),
    )
    .map_err(AppError::from_domain)?;
    let projection = query.projection().clone();
    let mut request = InfobaseSearchRequest::new(&args.pattern)?;
    request.clusters = ClusterSelector::parse(args.cluster.as_deref())?;
    request.query = Some(query);
    request.rac_options = rac_options(cli);
    Ok((request, projection))
}

fn build_session_list_request(
    cli: &Cli,
    services: &AppServices,
    args: &SessionListArgs,
) -> Result<(SessionListRequest, Projection), AppError> {
    let query = base_query_spec(
        RecordKind::Session,
        &args.query,
        args.selectors.query.as_deref(),
        services.field_registry(),
    )?;
    let projection = query.projection().clone();
    let request = SessionListRequest {
        clusters: ClusterSelector::parse(args.selectors.cluster.as_deref())?,
        infobase: optional_mask(args.selectors.infobase.as_deref())?,
        id: args.selectors.id,
        number: args.selectors.number,
        user: optional_mask(args.selectors.user.as_deref())?,
        host: optional_mask(args.selectors.host.as_deref())?,
        app: optional_mask(args.selectors.app.as_deref())?,
        query: Some(query),
        rac_options: rac_options(cli),
    };
    Ok((request, projection))
}

fn build_connection_list_request(
    cli: &Cli,
    services: &AppServices,
    args: &ConnectionListArgs,
) -> Result<(ConnectionListRequest, Projection), AppError> {
    let query = base_query_spec(
        RecordKind::Connection,
        &args.query,
        args.selectors.query.as_deref(),
        services.field_registry(),
    )?;
    let projection = query.projection().clone();
    let request = ConnectionListRequest {
        clusters: ClusterSelector::parse(args.selectors.cluster.as_deref())?,
        infobase: optional_mask(args.selectors.infobase.as_deref())?,
        id: args.selectors.id,
        number: args.selectors.number,
        host: optional_mask(args.selectors.host.as_deref())?,
        application: optional_mask(args.selectors.application.as_deref())?,
        process: args.selectors.process,
        query: Some(query),
        rac_options: rac_options(cli),
    };
    Ok((request, projection))
}

fn base_query_spec(
    kind: RecordKind,
    options: &QueryOptions,
    text_query: Option<&str>,
    registry: &FieldRegistry,
) -> Result<QuerySpec, AppError> {
    let top = options.top.map(|value| value.get().to_string());
    QuerySpec::parse(
        kind,
        options.filter.iter().map(String::as_str),
        text_query,
        options.sort.iter().map(String::as_str),
        top.as_deref(),
        options.columns.as_deref(),
        registry,
    )
    .map_err(AppError::from_domain)
}

fn optional_mask(value: Option<&str>) -> Result<Option<SqlMask>, AppError> {
    value
        .map(SqlMask::parse)
        .transpose()
        .map_err(AppError::from_domain)
}

fn rac_options(cli: &Cli) -> RacOptions {
    RacOptions {
        explicit_path: cli.rac_path.clone(),
    }
}

fn request_approval<F>(
    force: bool,
    prompt: &str,
    preview: &[u8],
    request_confirmation: &mut F,
) -> Result<(Approval, bool), AppError>
where
    F: FnMut(&str, &str) -> io::Result<Confirmation>,
{
    if force {
        return Ok((Approval::Forced, true));
    }

    let preview = String::from_utf8_lossy(preview);
    match request_confirmation(prompt, &preview).map_err(|error| {
        AppError::internal(
            "confirmation_io",
            format!("Не удалось запросить подтверждение: {error}"),
        )
    })? {
        Confirmation::Confirmed => Ok((Approval::Confirmed, false)),
        Confirmation::Declined => Err(AppError::new(
            AppErrorCategory::Cancelled,
            "confirmation_declined",
            "Операция отменена пользователем",
        )),
        Confirmation::NonInteractive => Err(AppError::confirmation_required()),
    }
}

fn render_query<R: FieldAccess>(
    cli: &Cli,
    kind: RecordKind,
    outcome: &QueryOutcome<R>,
    projection: &Projection,
) -> Result<CliRunResult, OutputError> {
    let exit_code = outcome.app_exit_code();
    let output = OutputRenderer::new(cli.format, cli.no_color).render(kind, outcome, projection)?;
    Ok(CliRunResult::new(output, exit_code))
}

fn render_preview<R: FieldAccess + Clone>(
    cli: &Cli,
    kind: RecordKind,
    records: &[R],
    errors: &[TargetError],
    projection: &Projection,
    table_label: &str,
) -> Result<Vec<u8>, OutputError> {
    let outcome = QueryOutcome::new(
        records.to_vec(),
        errors.to_vec(),
        records.len(),
        usize::from(!records.is_empty()),
    );
    let output =
        OutputRenderer::new(cli.format, cli.no_color).render(kind, &outcome, projection)?;
    let mut preview = if cli.format == OutputFormat::Table {
        format!("{table_label}: {}\n", records.len()).into_bytes()
    } else {
        Vec::new()
    };
    preview.extend(output.stdout);
    preview.extend(output.stderr);
    Ok(preview)
}

fn render_cluster_mutation(
    action: &'static str,
    target: &crate::domain::ClusterTarget,
    config_path: &Path,
    format: OutputFormat,
) -> Result<CliRunResult, OutputError> {
    let config_path = config_path.to_string_lossy().into_owned();
    let headers = [
        "action",
        "cluster",
        "cluster_uuid",
        "ras_address",
        "config_path",
    ];
    let rows = vec![vec![
        action.to_owned(),
        target.alias.to_string(),
        target.discovered_cluster.uuid.to_string(),
        target.ras.to_string(),
        config_path.clone(),
    ]];
    let data = json!({
        "action": action,
        "cluster": target.alias,
        "cluster_uuid": target.discovered_cluster.uuid,
        "ras_address": target.ras,
        "config_path": config_path,
    });
    let output = match format {
        OutputFormat::Json => RenderedOutput {
            stdout: json_bytes(&json!({
                "data": [data],
                "errors": [],
                "meta": { "succeeded": 1, "partial": false },
            }))?,
            stderr: Vec::new(),
        },
        OutputFormat::Table | OutputFormat::Csv => RenderedOutput {
            stdout: render_grid(format, &headers, &rows)?,
            stderr: Vec::new(),
        },
    };
    Ok(CliRunResult::new(output, AppExitCode::Success))
}

fn action_exit_code<T>(outcome: &ActionOutcome<T>, target_errors: &[TargetError]) -> AppExitCode {
    let exit_code = outcome.app_exit_code();
    if exit_code == AppExitCode::Success && !target_errors.is_empty() {
        AppExitCode::PartialSuccess
    } else {
        exit_code
    }
}

fn render_session_action(
    format: OutputFormat,
    outcome: &SessionKillOutcome,
    target_errors: &[TargetError],
    exit_code: AppExitCode,
    redactor: &SecretRedactor,
) -> Result<CliRunResult, OutputError> {
    let data_headers = [
        "cluster",
        "ras_address",
        "infobase",
        "session",
        "session_id",
        "status",
    ];
    let error_headers = [
        "cluster",
        "ras_address",
        "infobase",
        "session",
        "session_id",
        "stage",
        "code",
        "message",
    ];
    let mut data_rows = Vec::with_capacity(outcome.items.len());
    let mut data_json = Vec::with_capacity(outcome.items.len());
    let mut error_rows = Vec::new();
    let mut error_json = Vec::new();

    for item in &outcome.items {
        let target = &item.target;
        data_rows.push(vec![
            target.cluster.to_string(),
            target.ras_address.to_string(),
            target.infobase.clone().unwrap_or_default(),
            target.session_id.to_string(),
            optional_i64(target.session_number),
            item.status.code().to_owned(),
        ]);
        data_json.push(json!({
            "cluster": target.cluster,
            "ras_address": target.ras_address,
            "infobase": target.infobase,
            "session": target.session_id,
            "session_id": target.session_number,
            "status": item.status.code(),
        }));

        if let Some(error) = &item.error {
            push_session_action_error(
                target,
                "action",
                &error.code,
                &error.message,
                redactor,
                &mut error_rows,
                &mut error_json,
            );
        } else if item.status != ActionStatus::Success {
            push_session_action_error(
                target,
                "action",
                "action_failed",
                "Действие завершилось без диагностического сообщения",
                redactor,
                &mut error_rows,
                &mut error_json,
            );
        }
    }

    for error in target_errors {
        let message = redactor.redact(&error.message);
        error_rows.push(vec![
            error.cluster.to_string(),
            error.ras_address.to_string(),
            String::new(),
            String::new(),
            String::new(),
            "selection".to_owned(),
            error.code().to_owned(),
            message.clone(),
        ]);
        error_json.push(json!({
            "cluster": error.cluster,
            "ras_address": error.ras_address,
            "infobase": null,
            "session": null,
            "session_id": null,
            "stage": "selection",
            "code": error.code(),
            "message": message,
        }));
    }

    let partial = outcome.meta.partial || (!target_errors.is_empty() && outcome.meta.succeeded > 0);
    render_action_output(
        format,
        &data_headers,
        &data_rows,
        data_json,
        &error_headers,
        &error_rows,
        error_json,
        json!({
            "attempted": outcome.meta.attempted,
            "succeeded": outcome.meta.succeeded,
            "failed": outcome.meta.failed,
            "cancelled": outcome.meta.cancelled,
            "selection_failed": target_errors.len(),
            "partial": partial,
        }),
        exit_code,
    )
}

fn push_session_action_error(
    target: &SessionKillTarget,
    stage: &'static str,
    code: &str,
    message: &str,
    redactor: &SecretRedactor,
    rows: &mut Vec<Vec<String>>,
    values: &mut Vec<Value>,
) {
    let message = redactor.redact(message);
    rows.push(vec![
        target.cluster.to_string(),
        target.ras_address.to_string(),
        target.infobase.clone().unwrap_or_default(),
        target.session_id.to_string(),
        optional_i64(target.session_number),
        stage.to_owned(),
        code.to_owned(),
        message.clone(),
    ]);
    values.push(json!({
        "cluster": target.cluster,
        "ras_address": target.ras_address,
        "infobase": target.infobase,
        "session": target.session_id,
        "session_id": target.session_number,
        "stage": stage,
        "code": code,
        "message": message,
    }));
}

fn render_connection_action(
    format: OutputFormat,
    outcome: &ConnectionKillOutcome,
    target_errors: &[TargetError],
    exit_code: AppExitCode,
    redactor: &SecretRedactor,
) -> Result<CliRunResult, OutputError> {
    let data_headers = [
        "cluster",
        "ras_address",
        "infobase",
        "connection",
        "conn_id",
        "process",
        "status",
    ];
    let error_headers = [
        "cluster",
        "ras_address",
        "infobase",
        "connection",
        "conn_id",
        "process",
        "stage",
        "code",
        "message",
    ];
    let mut data_rows = Vec::with_capacity(outcome.items.len());
    let mut data_json = Vec::with_capacity(outcome.items.len());
    let mut error_rows = Vec::new();
    let mut error_json = Vec::new();

    for item in &outcome.items {
        let target = &item.target;
        data_rows.push(vec![
            target.cluster.to_string(),
            target.ras_address.to_string(),
            target.infobase.clone().unwrap_or_default(),
            target.connection_id.to_string(),
            optional_i64(target.connection_number),
            target.process_id.to_string(),
            item.status.code().to_owned(),
        ]);
        data_json.push(json!({
            "cluster": target.cluster,
            "ras_address": target.ras_address,
            "infobase": target.infobase,
            "connection": target.connection_id,
            "conn_id": target.connection_number,
            "process": target.process_id,
            "status": item.status.code(),
        }));

        if let Some(error) = &item.error {
            push_connection_action_error(
                target,
                "action",
                &error.code,
                &error.message,
                redactor,
                &mut error_rows,
                &mut error_json,
            );
        } else if item.status != ActionStatus::Success {
            push_connection_action_error(
                target,
                "action",
                "action_failed",
                "Действие завершилось без диагностического сообщения",
                redactor,
                &mut error_rows,
                &mut error_json,
            );
        }
    }

    for error in target_errors {
        let message = redactor.redact(&error.message);
        error_rows.push(vec![
            error.cluster.to_string(),
            error.ras_address.to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "selection".to_owned(),
            error.code().to_owned(),
            message.clone(),
        ]);
        error_json.push(json!({
            "cluster": error.cluster,
            "ras_address": error.ras_address,
            "infobase": null,
            "connection": null,
            "conn_id": null,
            "process": null,
            "stage": "selection",
            "code": error.code(),
            "message": message,
        }));
    }

    let partial = outcome.meta.partial || (!target_errors.is_empty() && outcome.meta.succeeded > 0);
    render_action_output(
        format,
        &data_headers,
        &data_rows,
        data_json,
        &error_headers,
        &error_rows,
        error_json,
        json!({
            "attempted": outcome.meta.attempted,
            "succeeded": outcome.meta.succeeded,
            "failed": outcome.meta.failed,
            "cancelled": outcome.meta.cancelled,
            "selection_failed": target_errors.len(),
            "partial": partial,
        }),
        exit_code,
    )
}

fn push_connection_action_error(
    target: &ConnectionKillTarget,
    stage: &'static str,
    code: &str,
    message: &str,
    redactor: &SecretRedactor,
    rows: &mut Vec<Vec<String>>,
    values: &mut Vec<Value>,
) {
    let message = redactor.redact(message);
    rows.push(vec![
        target.cluster.to_string(),
        target.ras_address.to_string(),
        target.infobase.clone().unwrap_or_default(),
        target.connection_id.to_string(),
        optional_i64(target.connection_number),
        target.process_id.to_string(),
        stage.to_owned(),
        code.to_owned(),
        message.clone(),
    ]);
    values.push(json!({
        "cluster": target.cluster,
        "ras_address": target.ras_address,
        "infobase": target.infobase,
        "connection": target.connection_id,
        "conn_id": target.connection_number,
        "process": target.process_id,
        "stage": stage,
        "code": code,
        "message": message,
    }));
}

#[allow(clippy::too_many_arguments)]
fn render_action_output(
    format: OutputFormat,
    data_headers: &[&str],
    data_rows: &[Vec<String>],
    data_json: Vec<Value>,
    error_headers: &[&str],
    error_rows: &[Vec<String>],
    error_json: Vec<Value>,
    meta: Value,
    exit_code: AppExitCode,
) -> Result<CliRunResult, OutputError> {
    let output = match format {
        OutputFormat::Json => RenderedOutput {
            stdout: json_bytes(&json!({
                "data": data_json,
                "errors": error_json,
                "meta": meta,
            }))?,
            stderr: Vec::new(),
        },
        OutputFormat::Table | OutputFormat::Csv => RenderedOutput {
            stdout: render_grid(format, data_headers, data_rows)?,
            stderr: if error_rows.is_empty() {
                Vec::new()
            } else {
                render_grid(format, error_headers, error_rows)?
            },
        },
    };
    Ok(CliRunResult::new(output, exit_code))
}

fn render_app_error(
    format: OutputFormat,
    error: &AppError,
    redactor: &SecretRedactor,
    exit_code: AppExitCode,
) -> CliRunResult {
    match render_app_error_output(format, error, redactor) {
        Ok(output) => CliRunResult::new(output, exit_code),
        Err(output_error) => {
            let message = redactor.redact(&output_error.to_string());
            CliRunResult {
                stdout: Vec::new(),
                stderr: format!("output_error: {message}\n").into_bytes(),
                exit_code: AppExitCode::Internal,
            }
        }
    }
}

fn render_app_error_output(
    format: OutputFormat,
    error: &AppError,
    redactor: &SecretRedactor,
) -> Result<RenderedOutput, OutputError> {
    let headers = ["scope", "cluster", "ras_address", "code", "message"];
    let message = redactor.redact(error.message());
    let mut rows = vec![vec![
        "command".to_owned(),
        String::new(),
        String::new(),
        error.code().to_owned(),
        message.clone(),
    ]];
    let mut errors = vec![json!({
        "scope": "command",
        "cluster": null,
        "ras_address": null,
        "code": error.code(),
        "message": message,
    })];

    for target_error in error.target_errors() {
        let message = redactor.redact(&target_error.message);
        rows.push(vec![
            "target".to_owned(),
            target_error.cluster.to_string(),
            target_error.ras_address.to_string(),
            target_error.code().to_owned(),
            message.clone(),
        ]);
        errors.push(json!({
            "scope": "target",
            "cluster": target_error.cluster,
            "ras_address": target_error.ras_address,
            "code": target_error.code(),
            "message": message,
        }));
    }

    match format {
        OutputFormat::Json => Ok(RenderedOutput {
            stdout: json_bytes(&json!({
                "data": [],
                "errors": errors,
                "meta": {
                    "matched": 0,
                    "returned": 0,
                    "partial": false,
                },
            }))?,
            stderr: Vec::new(),
        }),
        OutputFormat::Table | OutputFormat::Csv => Ok(RenderedOutput {
            stdout: Vec::new(),
            stderr: render_grid(format, &headers, &rows)?,
        }),
    }
}

fn sanitize_target_errors(errors: &mut [TargetError], redactor: &SecretRedactor) {
    for error in errors {
        error.message = redactor.redact(&error.message);
    }
}

fn sanitize_action_outcome<T>(outcome: &mut ActionOutcome<T>, redactor: &SecretRedactor) {
    for item in &mut outcome.items {
        if let Some(error) = &mut item.error {
            error.message = redactor.redact(&error.message);
        }
    }
}

fn redactor_for_cli(cli: &Cli) -> SecretRedactor {
    let redactor = SecretRedactor::new();
    if let Some(CliCommand::Cluster {
        command: ClusterCommand::Add(args),
    }) = cli.command.as_ref()
    {
        if let Some(password) = &args.password {
            redactor.register_secret(password.expose_secret().to_owned());
        }
        if let Some(password) = &args.infobase_password {
            redactor.register_secret(password.expose_secret().to_owned());
        }
    }
    redactor
}

fn render_grid(
    format: OutputFormat,
    headers: &[&str],
    rows: &[Vec<String>],
) -> Result<Vec<u8>, OutputError> {
    match format {
        OutputFormat::Csv => render_grid_csv(headers, rows),
        OutputFormat::Table => Ok(render_grid_table(headers, rows)),
        OutputFormat::Json => Ok(Vec::new()),
    }
}

fn render_grid_csv(headers: &[&str], rows: &[Vec<String>]) -> Result<Vec<u8>, OutputError> {
    let mut output = Vec::new();
    {
        let mut writer = csv::WriterBuilder::new()
            .terminator(csv::Terminator::CRLF)
            .from_writer(&mut output);
        writer.write_record(headers)?;
        for row in rows {
            writer.write_record(row)?;
        }
        writer.flush()?;
    }
    Ok(output)
}

fn render_grid_table(headers: &[&str], rows: &[Vec<String>]) -> Vec<u8> {
    let width = crossterm::terminal::size()
        .ok()
        .map_or(120, |(width, _)| width)
        .max(20);
    let mut table = Table::new();
    table.load_preset(presets::UTF8_FULL_CONDENSED);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_width(width);
    table.set_header(headers.iter().copied());
    for row in rows {
        table.add_row(row.iter().map(String::as_str));
    }
    let mut output = table.to_string().into_bytes();
    output.push(b'\n');
    output
}

fn json_bytes(value: &Value) -> Result<Vec<u8>, OutputError> {
    let mut output = serde_json::to_vec_pretty(value)?;
    output.push(b'\n');
    Ok(output)
}

fn optional_i64(value: Option<i64>) -> String {
    value.map_or_else(String::new, |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::application::{ActionError, ActionItemOutcome};
    use crate::domain::{
        ClusterAlias, ClusterSource, ClusterUuid, RasEndpoint, SessionRecord, SessionUuid,
        TargetErrorKind,
    };

    fn source() -> ClusterSource {
        ClusterSource::new(
            ClusterAlias::new("dev").unwrap_or_else(|error| panic!("{error}")),
            ClusterUuid::new(Uuid::from_u128(1)),
            "Development",
            "ras.local:1545"
                .parse::<RasEndpoint>()
                .unwrap_or_else(|error| panic!("{error}")),
        )
    }

    fn json_output(result: &CliRunResult) -> Value {
        serde_json::from_slice(&result.stdout).unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn cli_result_exposes_application_exit_code_and_both_streams() {
        let result = CliRunResult::new(
            RenderedOutput {
                stdout: b"data".to_vec(),
                stderr: b"warning".to_vec(),
            },
            AppExitCode::PartialSuccess,
        );

        assert_eq!(result.stdout, b"data");
        assert_eq!(result.stderr, b"warning");
        assert_eq!(result.app_exit_code(), AppExitCode::PartialSuccess);
    }

    #[test]
    fn session_request_keeps_uuid_in_session_and_number_in_session_id() {
        let cli = Cli::try_parse_validated_from([
            "onecadmin",
            "session",
            "list",
            "--id",
            "00000000-0000-0000-0000-000000000002",
            "--number",
            "42",
            "--columns",
            "cluster,session,session_id",
        ])
        .unwrap_or_else(|error| panic!("{error}"));
        let Some(CliCommand::Session {
            command: SessionCommand::List(args),
        }) = cli.command.as_ref()
        else {
            panic!("ожидалась команда session list");
        };
        let registry = crate::domain::FieldRegistry::new();
        let query = args
            .query_spec(&registry)
            .unwrap_or_else(|error| panic!("{error}"));
        let fields = query
            .filters()
            .iter()
            .map(|filter| filter.field())
            .collect::<Vec<_>>();

        assert!(fields.contains(&"session"));
        assert!(fields.contains(&"session_id"));
        assert_eq!(args.selectors.number, Some(42));
        assert_eq!(
            args.selectors.id.map(|value| value.into_uuid()),
            Some(Uuid::from_u128(2))
        );
        assert_eq!(
            query.projection().columns(),
            ["cluster", "session", "session_id"]
        );
    }

    #[test]
    fn cluster_scope_is_not_promoted_to_a_destructive_query_filter() {
        let cli =
            Cli::try_parse_validated_from(["onecadmin", "session", "list", "--cluster", "dev"])
                .unwrap_or_else(|error| panic!("{error}"));
        let Some(CliCommand::Session {
            command: SessionCommand::List(args),
        }) = cli.command.as_ref()
        else {
            panic!("ожидалась команда session list");
        };
        let query = base_query_spec(
            RecordKind::Session,
            &args.query,
            args.selectors.query.as_deref(),
            &crate::domain::FieldRegistry::new(),
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert!(query.filters().is_empty());
        assert!(query.text_query().is_none());
        assert_eq!(args.selectors.cluster.as_deref(), Some("dev"));
    }

    #[test]
    fn read_rendering_maps_partial_to_five_and_empty_success_to_zero() {
        let cli = Cli::try_parse_validated_from([
            "onecadmin",
            "session",
            "list",
            "--columns",
            "session,session_id",
            "--format",
            "json",
        ])
        .unwrap_or_else(|error| panic!("{error}"));
        let Some(CliCommand::Session {
            command: SessionCommand::List(args),
        }) = cli.command.as_ref()
        else {
            panic!("ожидалась команда session list");
        };
        let query = args
            .query_spec(&crate::domain::FieldRegistry::new())
            .unwrap_or_else(|error| panic!("{error}"));
        let mut record = SessionRecord::new(source(), SessionUuid::new(Uuid::from_u128(2)));
        record.session_id = Some(17);
        let target_error = TargetError::new(
            ClusterAlias::new("prod").unwrap_or_else(|error| panic!("{error}")),
            "prod.local:1545"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            TargetErrorKind::Timeout,
            "Истек тайм-аут",
        );
        let partial = QueryOutcome::new(vec![record], vec![target_error], 1, 1);
        let result = render_query(&cli, RecordKind::Session, &partial, query.projection())
            .unwrap_or_else(|error| panic!("{error}"));
        let value = json_output(&result);

        assert_eq!(result.exit_code, AppExitCode::PartialSuccess);
        assert_eq!(value["data"][0]["session"], Uuid::from_u128(2).to_string());
        assert_eq!(value["data"][0]["session_id"], 17);

        let empty = QueryOutcome::<SessionRecord>::new(Vec::new(), Vec::new(), 0, 1);
        let result = render_query(&cli, RecordKind::Session, &empty, query.projection())
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(result.exit_code, AppExitCode::Success);
    }

    #[test]
    fn session_action_summary_uses_canonical_identity_and_reports_each_failure() {
        let target = |uuid, number| SessionKillTarget {
            cluster: source().cluster,
            cluster_uuid: ClusterUuid::new(Uuid::from_u128(1)),
            ras_address: "ras.local:1545"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            infobase: Some("Accounting".to_owned()),
            infobase_uuid: None,
            session_id: SessionUuid::new(Uuid::from_u128(uuid)),
            session_number: Some(number),
        };
        let outcome = ActionOutcome::new(vec![
            ActionItemOutcome::success(target(2, 17)),
            ActionItemOutcome::failed(
                target(3, 18),
                ActionError::new("authentication_failed", "Нет доступа"),
            ),
        ]);
        let exit_code = action_exit_code(&outcome, &[]);
        let result = render_session_action(
            OutputFormat::Json,
            &outcome,
            &[],
            exit_code,
            &SecretRedactor::new(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let value = json_output(&result);

        assert_eq!(result.exit_code, AppExitCode::PartialSuccess);
        assert_eq!(value["data"][0]["session"], Uuid::from_u128(2).to_string());
        assert_eq!(value["data"][0]["session_id"], 17);
        assert_eq!(value["data"][1]["status"], "failed");
        assert_eq!(
            value["errors"][0]["session"],
            Uuid::from_u128(3).to_string()
        );
        assert_eq!(value["errors"][0]["session_id"], 18);
        assert_eq!(value["errors"][0]["code"], "authentication_failed");
    }

    #[test]
    fn json_command_errors_have_stable_shape_and_redact_cli_passwords() {
        let cli = Cli::try_parse_validated_from([
            "onecadmin",
            "cluster",
            "add",
            "--name",
            "dev",
            "--ras",
            "ras.local:1545",
            "--auth",
            "password",
            "--user",
            "admin",
            "--password",
            "hunter2",
            "--format",
            "json",
        ])
        .unwrap_or_else(|error| panic!("{error}"));
        let error = AppError::new(
            AppErrorCategory::AllTargetsFailed,
            "rac_failed",
            "rac failed: password=hunter2",
        );
        let result = render_app_error(
            OutputFormat::Json,
            &error,
            &redactor_for_cli(&cli),
            error.app_exit_code(),
        );
        let rendered =
            String::from_utf8(result.stdout.clone()).unwrap_or_else(|error| panic!("{error}"));
        let value = json_output(&result);

        assert!(!rendered.contains("hunter2"));
        assert_eq!(value["data"], json!([]));
        assert_eq!(value["errors"][0]["scope"], "command");
        assert_eq!(value["errors"][0]["code"], "rac_failed");
        assert_eq!(value["meta"]["partial"], false);
    }

    #[test]
    fn non_interactive_and_declined_confirmation_map_to_six() {
        let mut non_interactive = |_: &str, _: &str| Ok(Confirmation::NonInteractive);
        let error = request_approval(false, "Продолжить?", b"preview", &mut non_interactive)
            .err()
            .unwrap_or_else(|| panic!("ожидалась ошибка подтверждения"));
        assert_eq!(error.app_exit_code(), AppExitCode::Cancelled);
        assert_eq!(error.code(), "confirmation_required");

        let mut declined = |_: &str, _: &str| Ok(Confirmation::Declined);
        let error = request_approval(false, "Продолжить?", b"preview", &mut declined)
            .err()
            .unwrap_or_else(|| panic!("ожидался отказ"));
        assert_eq!(error.app_exit_code().value(), 6);
        assert_eq!(error.code(), "confirmation_declined");
    }
}
