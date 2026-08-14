use std::collections::HashSet;
use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::time::Instant;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::application::{
    AppError, ClusterAddRequest, ClusterRemovePlan, ClusterStatus, CredentialOverrideAddRequest,
    CredentialOverrideRemoveRequest, CredentialOverrideSelector, DiagnosticsSnapshot,
    PreparedConnectionKill, PreparedSessionKill, RacOptions,
};
use crate::domain::{
    AuthConfig, AuthMode, ClusterAlias, ClusterTarget, ClusterUuid, ConnectionRecord,
    ConnectionUuid, FieldAccess, FieldRegistry, FieldValueRef, InfobaseAuthOverride,
    InfobaseRecord, InfobaseUuid, QueryOutcome, QuerySpec, RacPolicy, RasEndpoint, RecordKind,
    SecretString, SessionRecord, SessionUuid, TargetError, TargetErrorKind,
};

use super::{REFRESH_INTERVAL_PRESETS, TuiOptions, validate_refresh_interval};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Screen {
    Clusters,
    Credentials,
    Infobases,
    Sessions,
    Connections,
    Diagnostics,
}

impl Screen {
    pub(crate) const ALL: [Self; 6] = [
        Self::Clusters,
        Self::Credentials,
        Self::Infobases,
        Self::Sessions,
        Self::Connections,
        Self::Diagnostics,
    ];

    pub(crate) const fn title(self) -> &'static str {
        match self {
            Self::Clusters => "Кластеры",
            Self::Credentials => "Доступы к БД",
            Self::Infobases => "Информационные базы",
            Self::Sessions => "Сеансы",
            Self::Connections => "Соединения",
            Self::Diagnostics => "Диагностика",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Clusters => 0,
            Self::Credentials => 1,
            Self::Infobases => 2,
            Self::Sessions => 3,
            Self::Connections => 4,
            Self::Diagnostics => 5,
        }
    }

    fn wrapping_add(self, offset: isize) -> Self {
        let len = Self::ALL.len() as isize;
        let index = (self.index() as isize + offset).rem_euclid(len) as usize;
        Self::ALL[index]
    }

    pub(crate) const fn record_kind(self) -> Option<RecordKind> {
        match self {
            Self::Infobases => Some(RecordKind::Infobase),
            Self::Sessions => Some(RecordKind::Session),
            Self::Connections => Some(RecordKind::Connection),
            Self::Clusters | Self::Credentials | Self::Diagnostics => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RequestId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RefreshMeta {
    pub request_id: RequestId,
    pub generation: u64,
    pub screen: Screen,
}

#[derive(Clone, Debug)]
pub(crate) enum LoadState<T> {
    Loading,
    Data(T),
    Error(TaskFailure),
}

#[derive(Clone, Copy, Debug, Default)]
struct RefreshTracker {
    generation: u64,
    active: Option<RequestId>,
}

impl RefreshTracker {
    fn begin(&mut self, request_id: RequestId) -> Option<u64> {
        if self.active.is_some() {
            return None;
        }
        self.generation = self.generation.wrapping_add(1).max(1);
        self.active = Some(request_id);
        Some(self.generation)
    }

    fn finish(&mut self, request_id: RequestId, generation: u64) -> bool {
        if self.active == Some(request_id) && self.generation == generation {
            self.active = None;
            true
        } else {
            false
        }
    }

    const fn is_active(self) -> bool {
        self.active.is_some()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Resource<T> {
    pub state: LoadState<T>,
    tracker: RefreshTracker,
}

impl<T> Resource<T> {
    fn new() -> Self {
        Self {
            state: LoadState::Loading,
            tracker: RefreshTracker::default(),
        }
    }

    fn begin(&mut self, request_id: RequestId) -> Option<u64> {
        let generation = self.tracker.begin(request_id)?;
        if !matches!(self.state, LoadState::Data(_)) {
            self.state = LoadState::Loading;
        }
        Some(generation)
    }

    fn finish(&mut self, meta: RefreshMeta) -> bool {
        self.tracker.finish(meta.request_id, meta.generation)
    }

    pub(crate) const fn is_active(&self) -> bool {
        self.tracker.is_active()
    }

    fn needs_initial_load(&self) -> bool {
        matches!(self.state, LoadState::Loading) && !self.is_active()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct QuerySettings {
    pub query: String,
    pub filter: String,
    pub sort: String,
    pub columns: String,
    pub cluster_filter: Option<String>,
}

impl QuerySettings {
    pub(crate) fn build(
        &self,
        kind: RecordKind,
        registry: &FieldRegistry,
    ) -> Result<QuerySpec, String> {
        let filters = split_non_empty(&self.filter, ';');
        let sort = split_non_empty(&self.sort, ',');
        QuerySpec::parse(
            kind,
            filters.iter().copied(),
            non_empty(&self.query),
            sort.iter().copied(),
            None,
            non_empty(&self.columns),
            registry,
        )
        .map_err(|error| error.to_string())
    }
}

fn split_non_empty(value: &str, separator: char) -> Vec<&str> {
    value
        .split(separator)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect()
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialRow {
    pub cluster: ClusterAlias,
    pub cluster_uuid: ClusterUuid,
    pub entry: InfobaseAuthOverride,
}

#[derive(Clone, Debug)]
pub(crate) struct ClusterRow {
    pub target: ClusterTarget,
    pub status: ClusterStatus,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum RowKey {
    Cluster(Uuid),
    Credential {
        cluster: Uuid,
        infobase: Option<Uuid>,
        name: String,
    },
    Infobase(Uuid, Uuid),
    Session(Uuid, Uuid),
    Connection(Uuid, Uuid),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TableNav {
    pub selected: Option<usize>,
    pub offset: usize,
    pub viewport_height: usize,
    pub marked: HashSet<RowKey>,
    anchor: Option<RowKey>,
}

impl TableNav {
    fn preserve(&mut self, old_keys: &[RowKey], new_keys: &[RowKey]) {
        let old_index = self.selected;
        let selected_key = old_index
            .and_then(|index| old_keys.get(index))
            .or(self.anchor.as_ref());
        self.selected = selected_key
            .and_then(|key| new_keys.iter().position(|candidate| candidate == key))
            .or_else(|| {
                (!new_keys.is_empty()).then_some(
                    old_index
                        .unwrap_or_default()
                        .min(new_keys.len().saturating_sub(1)),
                )
            });
        self.marked
            .retain(|key| new_keys.iter().any(|candidate| candidate == key));
        self.ensure_visible(new_keys.len());
        self.anchor = self.selected.and_then(|index| new_keys.get(index)).cloned();
    }

    fn remember(&mut self, keys: &[RowKey]) {
        self.anchor = self.selected.and_then(|index| keys.get(index)).cloned();
    }

    fn move_by(&mut self, delta: isize, len: usize) {
        if len == 0 {
            self.selected = None;
            self.offset = 0;
            return;
        }
        let current = self.selected.unwrap_or_default() as isize;
        self.selected = Some((current + delta).clamp(0, len.saturating_sub(1) as isize) as usize);
        self.ensure_visible(len);
    }

    fn home(&mut self, len: usize) {
        self.selected = (len > 0).then_some(0);
        self.ensure_visible(len);
    }

    fn end(&mut self, len: usize) {
        self.selected = (len > 0).then_some(len - 1);
        self.ensure_visible(len);
    }

    pub(crate) fn set_viewport_height(&mut self, height: usize, len: usize) {
        self.viewport_height = height.max(1);
        self.ensure_visible(len);
    }

    fn ensure_visible(&mut self, len: usize) {
        if len == 0 {
            self.selected = None;
            self.offset = 0;
            return;
        }
        let selected = self.selected.get_or_insert(0);
        *selected = (*selected).min(len - 1);
        let height = self.viewport_height.max(1);
        if *selected < self.offset {
            self.offset = *selected;
        } else if *selected >= self.offset.saturating_add(height) {
            self.offset = selected.saturating_add(1).saturating_sub(height);
        }
        self.offset = self.offset.min(len.saturating_sub(1));
    }

    fn toggle(&mut self, key: RowKey) {
        if !self.marked.remove(&key) {
            self.marked.insert(key);
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TableScreen<T> {
    pub resource: Resource<T>,
    pub nav: TableNav,
    pub settings: QuerySettings,
}

impl<T> TableScreen<T> {
    fn new() -> Self {
        Self {
            resource: Resource::new(),
            nav: TableNav::default(),
            settings: QuerySettings::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DiagnosticsScreen {
    pub resource: Resource<DiagnosticsSnapshot>,
    pub scroll: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct AutoRefresh {
    pub enabled: bool,
    pub interval: Duration,
    preset_index: Option<usize>,
    next_due: Instant,
}

impl AutoRefresh {
    fn new(interval: Duration) -> Self {
        let preset_index = REFRESH_INTERVAL_PRESETS
            .iter()
            .position(|candidate| *candidate == interval);
        Self {
            enabled: false,
            interval,
            preset_index,
            next_due: Instant::now() + interval,
        }
    }

    fn toggle(&mut self, now: Instant) {
        self.enabled = !self.enabled;
        self.next_due = now + self.interval;
    }

    fn set_interval(&mut self, interval: Duration, now: Instant) -> Result<(), String> {
        validate_refresh_interval(interval).map_err(|error| error.to_string())?;
        self.interval = interval;
        self.preset_index = REFRESH_INTERVAL_PRESETS
            .iter()
            .position(|candidate| *candidate == interval);
        self.next_due = now + interval;
        Ok(())
    }

    fn cycle_preset(&mut self, direction: isize, now: Instant) {
        let current = self.preset_index.unwrap_or_else(|| {
            REFRESH_INTERVAL_PRESETS
                .iter()
                .position(|candidate| *candidate >= self.interval)
                .unwrap_or(REFRESH_INTERVAL_PRESETS.len() - 1)
        });
        let len = REFRESH_INTERVAL_PRESETS.len() as isize;
        let next = (current as isize + direction).rem_euclid(len) as usize;
        self.interval = REFRESH_INTERVAL_PRESETS[next];
        self.preset_index = Some(next);
        self.next_due = now + self.interval;
    }

    fn due(&mut self, now: Instant) -> bool {
        if !self.enabled || now < self.next_due {
            return false;
        }
        self.next_due = now + self.interval;
        true
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TaskFailure {
    pub code: String,
    pub message: String,
    pub target_errors: Vec<TargetError>,
}

impl TaskFailure {
    pub(crate) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            target_errors: Vec::new(),
        }
    }

    pub(crate) fn display(&self) -> String {
        format!("{}: {}", self.code, self.message)
    }
}

impl From<AppError> for TaskFailure {
    fn from(error: AppError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.message().to_owned(),
            target_errors: error.target_errors().to_vec(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SessionSelection {
    pub cluster: String,
    pub cluster_uuid: ClusterUuid,
    pub session: SessionUuid,
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectionSelection {
    pub cluster: String,
    pub cluster_uuid: ClusterUuid,
    pub connection: ConnectionUuid,
}

#[derive(Clone, Debug)]
pub(crate) enum ConfirmAction {
    RemoveCluster(Box<ClusterRemovePlan>),
    RemoveCredential(CredentialOverrideRemoveRequest),
    KillSessions(Vec<PreparedSessionKill>),
    KillConnections(Vec<PreparedConnectionKill>),
}

#[derive(Clone, Debug)]
pub(crate) enum OperationRequest {
    AddCluster(ClusterAddRequest),
    PrepareClusterRemove(String),
    RemoveCluster(ClusterRemovePlan),
    AddCredential(CredentialOverrideAddRequest),
    RemoveCredential(CredentialOverrideRemoveRequest),
    PrepareSessionKill(Vec<SessionSelection>),
    KillSessions(Vec<PreparedSessionKill>),
    PrepareConnectionKill(Vec<ConnectionSelection>),
    KillConnections(Vec<PreparedConnectionKill>),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ActionReport {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub cancelled: usize,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum OperationResult {
    ClusterRemovePrepared(Box<ClusterRemovePlan>),
    SessionKillPrepared(Vec<PreparedSessionKill>),
    ConnectionKillPrepared(Vec<PreparedConnectionKill>),
    ClusterAdded(String),
    ClusterRemoved(String),
    CredentialAdded(String),
    CredentialRemoved(String),
    SessionsKilled(ActionReport),
    ConnectionsKilled(ActionReport),
}

#[derive(Clone, Debug)]
pub(crate) enum RefreshWork {
    Clusters {
        query: String,
    },
    Credentials {
        query: String,
    },
    Infobases {
        query: QuerySpec,
        cluster: Option<String>,
    },
    Sessions {
        query: QuerySpec,
        cluster: Option<String>,
    },
    Connections {
        query: QuerySpec,
        cluster: Option<String>,
    },
    Diagnostics,
}

#[derive(Clone, Debug)]
pub(crate) enum JobKind {
    Refresh(RefreshWork),
    Operation(OperationRequest),
}

#[derive(Clone, Debug)]
pub(crate) struct Job {
    pub meta: RefreshMeta,
    pub kind: JobKind,
    pub rac_options: RacOptions,
}

impl Job {
    pub(crate) const fn request_id(&self) -> RequestId {
        self.meta.request_id
    }
}

#[derive(Clone, Debug)]
pub(crate) enum BackgroundPayload {
    Clusters(Result<Vec<ClusterRow>, TaskFailure>),
    Credentials(Result<Vec<CredentialRow>, TaskFailure>),
    Infobases(Result<QueryOutcome<InfobaseRecord>, TaskFailure>),
    Sessions(Result<QueryOutcome<SessionRecord>, TaskFailure>),
    Connections(Result<QueryOutcome<ConnectionRecord>, TaskFailure>),
    Diagnostics(Result<DiagnosticsSnapshot, TaskFailure>),
    Operation(Box<Result<OperationResult, TaskFailure>>),
}

#[derive(Clone, Debug)]
pub(crate) struct BackgroundMessage {
    pub request_id: RequestId,
    pub generation: u64,
    pub screen: Screen,
    pub payload: BackgroundPayload,
}

impl BackgroundMessage {
    pub(crate) const fn meta(&self) -> RefreshMeta {
        RefreshMeta {
            request_id: self.request_id,
            generation: self.generation,
            screen: self.screen,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Intent {
    Quit,
    Refresh(Screen),
    Spawn(Box<Job>),
    Cancel(RequestId),
}

#[derive(Clone, Debug)]
pub(crate) struct DetailsModal {
    pub title: String,
    pub lines: Vec<String>,
    pub scroll: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct ConfirmModal {
    pub title: String,
    pub lines: Vec<String>,
    pub action: ConfirmAction,
    pub scroll: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct ClusterPicker {
    pub options: Vec<String>,
    pub selected: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EditKind {
    Query,
    Filter,
    Sort,
    Columns,
    Interval,
}

impl EditKind {
    pub(crate) const fn title(self) -> &'static str {
        match self {
            Self::Query => "Строка query (маски %, _)",
            Self::Filter => "Фильтры field:operator:value (через ;)",
            Self::Sort => "Сортировка field:asc|desc (через ,)",
            Self::Columns => "Колонки (через , или *)",
            Self::Interval => "Интервал автообновления, секунд (минимум 2)",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EditModal {
    pub kind: EditKind,
    pub value: String,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FormAuthMode {
    None,
    Password,
}

impl FormAuthMode {
    fn next(self, direction: isize) -> Self {
        let modes = [Self::None, Self::Password];
        let current = match self {
            Self::None => 0,
            Self::Password => 1,
        };
        modes[(current as isize + direction).rem_euclid(modes.len() as isize) as usize]
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Password => "password",
        }
    }
}

#[derive(Clone)]
pub(crate) struct ClusterForm {
    pub field: usize,
    pub alias: String,
    pub ras: String,
    pub auth_mode: FormAuthMode,
    pub user: String,
    pub password: String,
    pub error: Option<String>,
}

impl ClusterForm {
    fn new() -> Self {
        Self {
            field: 0,
            alias: String::new(),
            ras: String::new(),
            auth_mode: FormAuthMode::None,
            user: String::new(),
            password: String::new(),
            error: None,
        }
    }

    fn build(&self, rac_options: RacOptions) -> Result<ClusterAddRequest, String> {
        let alias = ClusterAlias::new(self.alias.trim()).map_err(|error| error.to_string())?;
        let ras = self
            .ras
            .trim()
            .parse::<RasEndpoint>()
            .map_err(|error| error.to_string())?;
        let auth = build_auth(self.auth_mode, &self.user, &self.password)?;
        let mut request = ClusterAddRequest::new(alias, ras, auth);
        request.rac_options = rac_options;
        Ok(request)
    }

    pub(crate) fn fields(&self) -> [(&'static str, String, bool); 5] {
        [
            ("alias", self.alias.clone(), false),
            ("ras_address", self.ras.clone(), false),
            ("auth_mode", self.auth_mode.label().to_owned(), false),
            ("user", self.user.clone(), false),
            ("password", "*".repeat(self.password.chars().count()), true),
        ]
    }

    fn edit_value(&mut self) -> Option<&mut String> {
        match self.field {
            0 => Some(&mut self.alias),
            1 => Some(&mut self.ras),
            3 => Some(&mut self.user),
            4 => Some(&mut self.password),
            _ => None,
        }
    }
}

impl Drop for ClusterForm {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Clone)]
pub(crate) struct CredentialForm {
    pub field: usize,
    pub cluster: String,
    pub infobase: String,
    pub infobase_uuid: String,
    pub auth_mode: FormAuthMode,
    pub user: String,
    pub password: String,
    pub error: Option<String>,
}

impl CredentialForm {
    fn new(cluster: String) -> Self {
        Self {
            field: 0,
            cluster,
            infobase: String::new(),
            infobase_uuid: String::new(),
            auth_mode: FormAuthMode::None,
            user: String::new(),
            password: String::new(),
            error: None,
        }
    }

    fn build(&self) -> Result<CredentialOverrideAddRequest, String> {
        let cluster = ClusterAlias::new(self.cluster.trim()).map_err(|error| error.to_string())?;
        let infobase = self.infobase.trim();
        if infobase.is_empty() {
            return Err("Требуется точное имя информационной базы".to_owned());
        }
        let infobase_uuid = non_empty(&self.infobase_uuid)
            .map(str::parse::<InfobaseUuid>)
            .transpose()
            .map_err(|error| error.to_string())?;
        let auth = build_auth(self.auth_mode, &self.user, &self.password)?;
        let entry = InfobaseAuthOverride::new(Some(infobase.to_owned()), infobase_uuid, auth)
            .map_err(|error| error.to_string())?;
        Ok(CredentialOverrideAddRequest { cluster, entry })
    }

    pub(crate) fn fields(&self) -> [(&'static str, String, bool); 6] {
        [
            ("cluster", self.cluster.clone(), false),
            ("infobase", self.infobase.clone(), false),
            ("infobase_uuid", self.infobase_uuid.clone(), false),
            ("auth_mode", self.auth_mode.label().to_owned(), false),
            ("user", self.user.clone(), false),
            ("password", "*".repeat(self.password.chars().count()), true),
        ]
    }

    fn edit_value(&mut self) -> Option<&mut String> {
        match self.field {
            0 => Some(&mut self.cluster),
            1 => Some(&mut self.infobase),
            2 => Some(&mut self.infobase_uuid),
            4 => Some(&mut self.user),
            5 => Some(&mut self.password),
            _ => None,
        }
    }
}

impl Drop for CredentialForm {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

fn build_auth(mode: FormAuthMode, user: &str, password: &str) -> Result<AuthConfig, String> {
    match mode {
        FormAuthMode::None => Ok(AuthConfig::none()),
        FormAuthMode::Password => AuthConfig::password(user.trim(), SecretString::new(password))
            .map_err(|e| e.to_string()),
    }
}

#[derive(Clone)]
pub(crate) enum Modal {
    Details(DetailsModal),
    Confirm(Box<ConfirmModal>),
    Edit(EditModal),
    ClusterPicker(ClusterPicker),
    ClusterForm(ClusterForm),
    CredentialForm(CredentialForm),
    Progress {
        title: String,
        request_id: RequestId,
    },
}

pub(crate) struct App {
    pub screen: Screen,
    pub clusters: TableScreen<Vec<ClusterRow>>,
    pub credentials: TableScreen<Vec<CredentialRow>>,
    pub infobases: TableScreen<QueryOutcome<InfobaseRecord>>,
    pub sessions: TableScreen<QueryOutcome<SessionRecord>>,
    pub connections: TableScreen<QueryOutcome<ConnectionRecord>>,
    pub diagnostics: DiagnosticsScreen,
    pub auto_refresh: AutoRefresh,
    pub modal: Option<Modal>,
    pub status: String,
    pub status_is_error: bool,
    pub local_errors: Vec<String>,
    pub registry: FieldRegistry,
    rac_options: RacOptions,
    next_request_id: u64,
    operation: Option<RequestId>,
    pending_refresh: HashSet<Screen>,
}

impl App {
    pub(crate) fn new(options: &TuiOptions) -> Self {
        Self {
            screen: Screen::Clusters,
            clusters: TableScreen::new(),
            credentials: TableScreen::new(),
            infobases: TableScreen::new(),
            sessions: TableScreen::new(),
            connections: TableScreen::new(),
            diagnostics: DiagnosticsScreen {
                resource: Resource::new(),
                scroll: 0,
            },
            auto_refresh: AutoRefresh::new(options.refresh_interval()),
            modal: None,
            status: "Инициализация".to_owned(),
            status_is_error: false,
            local_errors: Vec::new(),
            registry: FieldRegistry::new(),
            rac_options: options.rac_options().clone(),
            next_request_id: 0,
            operation: None,
            pending_refresh: HashSet::new(),
        }
    }

    fn allocate_request_id(&mut self) -> RequestId {
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        RequestId(self.next_request_id)
    }

    pub(crate) fn begin_refresh(&mut self, screen: Screen) -> Result<Option<Job>, String> {
        if self.refresh_active(screen) {
            self.pending_refresh.insert(screen);
            if screen == self.screen {
                self.status =
                    "Обновление уже выполняется; повторный запрос поставлен в очередь".to_owned();
                self.status_is_error = false;
            }
            return Ok(None);
        }
        let work = match screen {
            Screen::Clusters => RefreshWork::Clusters {
                query: self.clusters.settings.query.clone(),
            },
            Screen::Credentials => RefreshWork::Credentials {
                query: self.credentials.settings.query.clone(),
            },
            Screen::Infobases => RefreshWork::Infobases {
                query: self
                    .infobases
                    .settings
                    .build(RecordKind::Infobase, &self.registry)?,
                cluster: self.infobases.settings.cluster_filter.clone(),
            },
            Screen::Sessions => RefreshWork::Sessions {
                query: self
                    .sessions
                    .settings
                    .build(RecordKind::Session, &self.registry)?,
                cluster: self.sessions.settings.cluster_filter.clone(),
            },
            Screen::Connections => RefreshWork::Connections {
                query: self
                    .connections
                    .settings
                    .build(RecordKind::Connection, &self.registry)?,
                cluster: self.connections.settings.cluster_filter.clone(),
            },
            Screen::Diagnostics => RefreshWork::Diagnostics,
        };
        let request_id = self.allocate_request_id();
        let generation = match screen {
            Screen::Clusters => self.clusters.resource.begin(request_id),
            Screen::Credentials => self.credentials.resource.begin(request_id),
            Screen::Infobases => self.infobases.resource.begin(request_id),
            Screen::Sessions => self.sessions.resource.begin(request_id),
            Screen::Connections => self.connections.resource.begin(request_id),
            Screen::Diagnostics => self.diagnostics.resource.begin(request_id),
        };
        let Some(generation) = generation else {
            return Ok(None);
        };
        if screen == self.screen {
            self.status = format!("Обновление раздела «{}»...", screen.title());
            self.status_is_error = false;
        }
        Ok(Some(Job {
            meta: RefreshMeta {
                request_id,
                generation,
                screen,
            },
            kind: JobKind::Refresh(work),
            rac_options: self.rac_options.clone(),
        }))
    }

    fn begin_operation(
        &mut self,
        title: impl Into<String>,
        request: OperationRequest,
    ) -> Vec<Intent> {
        if self.operation.is_some() {
            self.set_status_error("Другая операция уже выполняется".to_owned());
            return Vec::new();
        }
        let request_id = self.allocate_request_id();
        let title = title.into();
        self.operation = Some(request_id);
        self.modal = Some(Modal::Progress {
            title: title.clone(),
            request_id,
        });
        self.status = title;
        self.status_is_error = false;
        vec![Intent::Spawn(Box::new(Job {
            meta: RefreshMeta {
                request_id,
                generation: 0,
                screen: self.screen,
            },
            kind: JobKind::Operation(request),
            rac_options: self.rac_options.clone(),
        }))]
    }

    pub(crate) fn set_status_error(&mut self, message: String) {
        self.status = message.clone();
        self.status_is_error = true;
        self.push_local_error(message);
    }

    fn push_local_error(&mut self, message: String) {
        if self.local_errors.last() != Some(&message) {
            self.local_errors.push(message);
            if self.local_errors.len() > 200 {
                let excess = self.local_errors.len() - 200;
                self.local_errors.drain(..excess);
            }
        }
    }

    fn record_failure(&mut self, failure: &TaskFailure) {
        self.push_local_error(failure.display());
        for error in &failure.target_errors {
            self.push_local_error(format!(
                "{} {} {}: {}",
                error.cluster,
                error.ras_address,
                error.code(),
                error.message
            ));
        }
    }

    pub(crate) fn apply_background(&mut self, message: BackgroundMessage) -> Vec<Intent> {
        let meta = message.meta();
        match message.payload {
            BackgroundPayload::Clusters(result) => self.apply_clusters(meta, result),
            BackgroundPayload::Credentials(result) => self.apply_credentials(meta, result),
            BackgroundPayload::Infobases(result) => self.apply_infobases(meta, result),
            BackgroundPayload::Sessions(result) => self.apply_sessions(meta, result),
            BackgroundPayload::Connections(result) => self.apply_connections(meta, result),
            BackgroundPayload::Diagnostics(result) => self.apply_diagnostics(meta, result),
            BackgroundPayload::Operation(result) => {
                self.apply_operation(message.request_id, *result)
            }
        }
    }

    fn apply_clusters(
        &mut self,
        meta: RefreshMeta,
        result: Result<Vec<ClusterRow>, TaskFailure>,
    ) -> Vec<Intent> {
        if meta.screen != Screen::Clusters || !self.clusters.resource.finish(meta) {
            return Vec::new();
        }
        match result {
            Ok(data) => {
                let old = cluster_keys_from_state(&self.clusters.resource.state);
                let new = data.iter().map(cluster_key).collect::<Vec<_>>();
                self.clusters.nav.preserve(&old, &new);
                let count = data.len();
                self.clusters.resource.state = LoadState::Data(data);
                self.set_loaded_status_for(Screen::Clusters, count, 0);
            }
            Err(failure) => self.apply_refresh_failure(Screen::Clusters, failure),
        }
        self.finished_refresh_intents(Screen::Clusters, false)
    }

    fn apply_credentials(
        &mut self,
        meta: RefreshMeta,
        result: Result<Vec<CredentialRow>, TaskFailure>,
    ) -> Vec<Intent> {
        if meta.screen != Screen::Credentials || !self.credentials.resource.finish(meta) {
            return Vec::new();
        }
        match result {
            Ok(data) => {
                let old = credential_keys_from_state(&self.credentials.resource.state);
                let new = data.iter().map(credential_key).collect::<Vec<_>>();
                self.credentials.nav.preserve(&old, &new);
                let count = data.len();
                self.credentials.resource.state = LoadState::Data(data);
                self.set_loaded_status_for(Screen::Credentials, count, 0);
            }
            Err(failure) => self.apply_refresh_failure(Screen::Credentials, failure),
        }
        self.finished_refresh_intents(Screen::Credentials, false)
    }

    fn apply_infobases(
        &mut self,
        meta: RefreshMeta,
        result: Result<QueryOutcome<InfobaseRecord>, TaskFailure>,
    ) -> Vec<Intent> {
        if meta.screen != Screen::Infobases || !self.infobases.resource.finish(meta) {
            return Vec::new();
        }
        match result {
            Ok(data) => {
                let old = infobase_keys_from_state(&self.infobases.resource.state);
                let new = data.data.iter().map(infobase_key).collect::<Vec<_>>();
                self.infobases.nav.preserve(&old, &new);
                let count = data.data.len();
                let errors = data.errors.len();
                self.infobases.resource.state = LoadState::Data(data);
                self.set_loaded_status_for(Screen::Infobases, count, errors);
            }
            Err(failure) => self.apply_refresh_failure(Screen::Infobases, failure),
        }
        self.finished_refresh_intents(Screen::Infobases, true)
    }

    fn apply_sessions(
        &mut self,
        meta: RefreshMeta,
        result: Result<QueryOutcome<SessionRecord>, TaskFailure>,
    ) -> Vec<Intent> {
        if meta.screen != Screen::Sessions || !self.sessions.resource.finish(meta) {
            return Vec::new();
        }
        match result {
            Ok(data) => {
                let old = session_keys_from_state(&self.sessions.resource.state);
                let new = data.data.iter().map(session_key).collect::<Vec<_>>();
                self.sessions.nav.preserve(&old, &new);
                let count = data.data.len();
                let errors = data.errors.len();
                self.sessions.resource.state = LoadState::Data(data);
                self.set_loaded_status_for(Screen::Sessions, count, errors);
            }
            Err(failure) => self.apply_refresh_failure(Screen::Sessions, failure),
        }
        self.finished_refresh_intents(Screen::Sessions, true)
    }

    fn apply_connections(
        &mut self,
        meta: RefreshMeta,
        result: Result<QueryOutcome<ConnectionRecord>, TaskFailure>,
    ) -> Vec<Intent> {
        if meta.screen != Screen::Connections || !self.connections.resource.finish(meta) {
            return Vec::new();
        }
        match result {
            Ok(data) => {
                let old = connection_keys_from_state(&self.connections.resource.state);
                let new = data.data.iter().map(connection_key).collect::<Vec<_>>();
                self.connections.nav.preserve(&old, &new);
                let count = data.data.len();
                let errors = data.errors.len();
                self.connections.resource.state = LoadState::Data(data);
                self.set_loaded_status_for(Screen::Connections, count, errors);
            }
            Err(failure) => self.apply_refresh_failure(Screen::Connections, failure),
        }
        self.finished_refresh_intents(Screen::Connections, true)
    }

    fn apply_diagnostics(
        &mut self,
        meta: RefreshMeta,
        result: Result<DiagnosticsSnapshot, TaskFailure>,
    ) -> Vec<Intent> {
        if meta.screen != Screen::Diagnostics || !self.diagnostics.resource.finish(meta) {
            return Vec::new();
        }
        match result {
            Ok(data) => {
                let count = data.selected_rac.len() + data.target_errors.len();
                self.diagnostics.resource.state = LoadState::Data(data);
                self.set_loaded_status_for(Screen::Diagnostics, count, self.local_errors.len());
            }
            Err(failure) => self.apply_refresh_failure(Screen::Diagnostics, failure),
        }
        self.finished_refresh_intents(Screen::Diagnostics, false)
    }

    fn finished_refresh_intents(
        &mut self,
        screen: Screen,
        refresh_diagnostics: bool,
    ) -> Vec<Intent> {
        let mut intents = Vec::new();
        if self.pending_refresh.remove(&screen) {
            intents.push(Intent::Refresh(screen));
        }
        if refresh_diagnostics && screen != Screen::Diagnostics {
            intents.push(Intent::Refresh(Screen::Diagnostics));
        }
        intents
    }

    fn apply_refresh_failure(&mut self, screen: Screen, failure: TaskFailure) {
        self.record_failure(&failure);
        self.status = failure.display();
        self.status_is_error = true;
        match screen {
            Screen::Clusters => {
                self.clusters
                    .nav
                    .remember(&cluster_keys_from_state(&self.clusters.resource.state));
                self.clusters.resource.state = LoadState::Error(failure);
            }
            Screen::Credentials => {
                self.credentials.nav.remember(&credential_keys_from_state(
                    &self.credentials.resource.state,
                ));
                self.credentials.resource.state = LoadState::Error(failure);
            }
            Screen::Infobases => {
                self.infobases
                    .nav
                    .remember(&infobase_keys_from_state(&self.infobases.resource.state));
                self.infobases.resource.state = LoadState::Error(failure);
            }
            Screen::Sessions => {
                self.sessions
                    .nav
                    .remember(&session_keys_from_state(&self.sessions.resource.state));
                self.sessions.resource.state = LoadState::Error(failure);
            }
            Screen::Connections => {
                self.connections.nav.remember(&connection_keys_from_state(
                    &self.connections.resource.state,
                ));
                self.connections.resource.state = LoadState::Error(failure);
            }
            Screen::Diagnostics => self.diagnostics.resource.state = LoadState::Error(failure),
        }
    }

    fn set_loaded_status_for(&mut self, screen: Screen, count: usize, errors: usize) {
        if self.screen != screen {
            return;
        }
        self.status = if errors == 0 {
            format!("Загружено записей: {count}")
        } else {
            format!("Загружено записей: {count}; ошибок целей: {errors}")
        };
        self.status_is_error = errors > 0;
    }

    fn apply_operation(
        &mut self,
        request_id: RequestId,
        result: Result<OperationResult, TaskFailure>,
    ) -> Vec<Intent> {
        if self.operation != Some(request_id) {
            return Vec::new();
        }
        self.operation = None;
        match result {
            Err(failure) => {
                self.record_failure(&failure);
                self.status = failure.display();
                self.status_is_error = true;
                self.modal = Some(Modal::Details(DetailsModal {
                    title: "Ошибка операции".to_owned(),
                    lines: failure_lines(&failure),
                    scroll: 0,
                }));
                Vec::new()
            }
            Ok(OperationResult::ClusterRemovePrepared(plan)) => {
                let lines = vec![
                    format!("alias: {}", plan.target.alias),
                    format!("cluster_uuid: {}", plan.target.discovered_cluster.uuid),
                    format!("ras_address: {}", plan.target.ras),
                    format!("cluster_name: {}", plan.target.discovered_cluster.name),
                ];
                self.modal = Some(Modal::Confirm(Box::new(ConfirmModal {
                    title: "Удалить подключение к кластеру?".to_owned(),
                    lines,
                    action: ConfirmAction::RemoveCluster(plan),
                    scroll: 0,
                })));
                self.status = "План удаления подготовлен; требуется подтверждение".to_owned();
                self.status_is_error = false;
                Vec::new()
            }
            Ok(OperationResult::SessionKillPrepared(prepared)) => {
                let mut lines = vec![format!("Точных планов: {}", prepared.len())];
                for item in &prepared {
                    lines.push(format!("snapshot_id: {}", item.plan.snapshot_id()));
                    for record in &item.records {
                        lines.push(format!(
                            "{} | {} | session={} | session_id={} | user_name={} | host={}",
                            record.source.cluster,
                            record.infobase.as_deref().unwrap_or(""),
                            record.session,
                            option_i64(record.session_id),
                            record.user_name.as_deref().unwrap_or(""),
                            record.host.as_deref().unwrap_or("")
                        ));
                    }
                }
                self.modal = Some(Modal::Confirm(Box::new(ConfirmModal {
                    title: "Завершить выбранные сеансы?".to_owned(),
                    lines,
                    action: ConfirmAction::KillSessions(prepared),
                    scroll: 0,
                })));
                self.status = "Точные планы завершения подготовлены".to_owned();
                self.status_is_error = false;
                Vec::new()
            }
            Ok(OperationResult::ConnectionKillPrepared(prepared)) => {
                let mut lines = vec![format!("Точных планов: {}", prepared.len())];
                for item in &prepared {
                    lines.push(format!("snapshot_id: {}", item.plan.snapshot_id()));
                    for record in &item.records {
                        lines.push(format!(
                            "{} | {} | connection={} | conn_id={} | process={} | host={}",
                            record.source.cluster,
                            record.infobase.as_deref().unwrap_or(""),
                            record.connection,
                            option_i64(record.conn_id),
                            record.process,
                            record.host.as_deref().unwrap_or("")
                        ));
                    }
                }
                self.modal = Some(Modal::Confirm(Box::new(ConfirmModal {
                    title: "Разорвать выбранные соединения?".to_owned(),
                    lines,
                    action: ConfirmAction::KillConnections(prepared),
                    scroll: 0,
                })));
                self.status = "Точные планы разрыва подготовлены".to_owned();
                self.status_is_error = false;
                Vec::new()
            }
            Ok(OperationResult::ClusterAdded(alias)) => {
                self.finish_mutation(format!("Кластер `{alias}` добавлен"));
                vec![
                    Intent::Refresh(Screen::Clusters),
                    Intent::Refresh(Screen::Diagnostics),
                ]
            }
            Ok(OperationResult::ClusterRemoved(alias)) => {
                self.finish_mutation(format!("Кластер `{alias}` удален"));
                vec![
                    Intent::Refresh(Screen::Clusters),
                    Intent::Refresh(Screen::Credentials),
                    Intent::Refresh(Screen::Diagnostics),
                ]
            }
            Ok(OperationResult::CredentialAdded(name)) => {
                self.finish_mutation(format!("Override для `{name}` добавлен"));
                vec![Intent::Refresh(Screen::Credentials)]
            }
            Ok(OperationResult::CredentialRemoved(name)) => {
                self.finish_mutation(format!("Override для `{name}` удален"));
                vec![Intent::Refresh(Screen::Credentials)]
            }
            Ok(OperationResult::SessionsKilled(report)) => {
                self.finish_action_report("Завершение сеансов", &report);
                vec![
                    Intent::Refresh(Screen::Sessions),
                    Intent::Refresh(Screen::Diagnostics),
                ]
            }
            Ok(OperationResult::ConnectionsKilled(report)) => {
                self.finish_action_report("Разрыв соединений", &report);
                vec![
                    Intent::Refresh(Screen::Connections),
                    Intent::Refresh(Screen::Diagnostics),
                ]
            }
        }
    }

    fn finish_mutation(&mut self, message: String) {
        self.status = message.clone();
        self.status_is_error = false;
        self.modal = Some(Modal::Details(DetailsModal {
            title: "Операция завершена".to_owned(),
            lines: vec![message],
            scroll: 0,
        }));
    }

    fn finish_action_report(&mut self, title: &str, report: &ActionReport) {
        let mut lines = vec![
            format!("attempted: {}", report.attempted),
            format!("succeeded: {}", report.succeeded),
            format!("failed: {}", report.failed),
            format!("cancelled: {}", report.cancelled),
        ];
        lines.extend(report.errors.iter().cloned());
        for error in &report.errors {
            self.push_local_error(error.clone());
        }
        self.status = format!(
            "{title}: успешно {}, ошибок {}, отменено {}",
            report.succeeded, report.failed, report.cancelled
        );
        self.status_is_error = report.failed + report.cancelled > 0;
        self.modal = Some(Modal::Details(DetailsModal {
            title: title.to_owned(),
            lines,
            scroll: 0,
        }));
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Vec<Intent> {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return vec![Intent::Quit];
        }
        if self.modal.is_some() {
            return self.handle_modal_key(key);
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => vec![Intent::Quit],
            KeyCode::Tab | KeyCode::Right => self.change_screen(1),
            KeyCode::BackTab | KeyCode::Left => self.change_screen(-1),
            KeyCode::F(5) => vec![Intent::Refresh(self.screen)],
            KeyCode::Char('a') | KeyCode::Char('A') => {
                self.auto_refresh.toggle(Instant::now());
                self.status = if self.auto_refresh.enabled {
                    format!(
                        "Автообновление включено: {} с",
                        self.auto_refresh.interval.as_secs()
                    )
                } else {
                    "Автообновление выключено".to_owned()
                };
                self.status_is_error = false;
                Vec::new()
            }
            KeyCode::Char('[') => {
                self.auto_refresh.cycle_preset(-1, Instant::now());
                self.interval_status();
                Vec::new()
            }
            KeyCode::Char(']') => {
                self.auto_refresh.cycle_preset(1, Instant::now());
                self.interval_status();
                Vec::new()
            }
            KeyCode::Char('i') | KeyCode::Char('I') => {
                self.modal = Some(Modal::Edit(EditModal {
                    kind: EditKind::Interval,
                    value: self.auto_refresh.interval.as_secs().to_string(),
                    error: None,
                }));
                Vec::new()
            }
            KeyCode::Up => {
                self.navigate(-1, false);
                Vec::new()
            }
            KeyCode::Down => {
                self.navigate(1, false);
                Vec::new()
            }
            KeyCode::PageUp => {
                self.navigate(-1, true);
                Vec::new()
            }
            KeyCode::PageDown => {
                self.navigate(1, true);
                Vec::new()
            }
            KeyCode::Home => {
                self.navigate_home();
                Vec::new()
            }
            KeyCode::End => {
                self.navigate_end();
                Vec::new()
            }
            KeyCode::Enter => {
                self.open_details();
                Vec::new()
            }
            KeyCode::Char(' ') => {
                self.toggle_mark();
                Vec::new()
            }
            KeyCode::Char('/') => {
                self.open_edit(EditKind::Query);
                Vec::new()
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                self.open_edit(EditKind::Filter);
                Vec::new()
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.open_edit(EditKind::Sort);
                Vec::new()
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                self.open_edit(EditKind::Columns);
                Vec::new()
            }
            KeyCode::Char('g') | KeyCode::Char('G') => {
                self.open_cluster_picker();
                Vec::new()
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                self.open_add_form();
                Vec::new()
            }
            KeyCode::Delete | KeyCode::Char('x') | KeyCode::Char('X') => {
                self.start_remove_selected()
            }
            KeyCode::Char('k') | KeyCode::Char('K') => self.start_kill_selected(),
            KeyCode::Char('?') => {
                self.modal = Some(Modal::Details(DetailsModal {
                    title: "Справка".to_owned(),
                    lines: help_lines(),
                    scroll: 0,
                }));
                Vec::new()
            }
            KeyCode::Char(value @ '1'..='6') => {
                let index = value as usize - '1' as usize;
                self.screen = Screen::ALL[index];
                self.initial_refresh_intent()
            }
            _ => Vec::new(),
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) -> Vec<Intent> {
        let Some(modal) = self.modal.take() else {
            return Vec::new();
        };
        match modal {
            Modal::Details(mut details) => match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => Vec::new(),
                KeyCode::Up => {
                    details.scroll = details.scroll.saturating_sub(1);
                    self.modal = Some(Modal::Details(details));
                    Vec::new()
                }
                KeyCode::Down => {
                    details.scroll = details.scroll.saturating_add(1);
                    self.modal = Some(Modal::Details(details));
                    Vec::new()
                }
                KeyCode::PageUp => {
                    details.scroll = details.scroll.saturating_sub(10);
                    self.modal = Some(Modal::Details(details));
                    Vec::new()
                }
                KeyCode::PageDown => {
                    details.scroll = details.scroll.saturating_add(10);
                    self.modal = Some(Modal::Details(details));
                    Vec::new()
                }
                _ => {
                    self.modal = Some(Modal::Details(details));
                    Vec::new()
                }
            },
            Modal::Confirm(mut confirm) => match key.code {
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => Vec::new(),
                KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let (title, request) = match confirm.action {
                        ConfirmAction::RemoveCluster(plan) => (
                            "Удаление подключения...".to_owned(),
                            OperationRequest::RemoveCluster(*plan),
                        ),
                        ConfirmAction::RemoveCredential(request) => (
                            "Удаление override...".to_owned(),
                            OperationRequest::RemoveCredential(request),
                        ),
                        ConfirmAction::KillSessions(prepared) => (
                            "Завершение выбранных сеансов...".to_owned(),
                            OperationRequest::KillSessions(prepared),
                        ),
                        ConfirmAction::KillConnections(prepared) => (
                            "Разрыв выбранных соединений...".to_owned(),
                            OperationRequest::KillConnections(prepared),
                        ),
                    };
                    self.begin_operation(title, request)
                }
                KeyCode::Up => {
                    confirm.scroll = confirm.scroll.saturating_sub(1);
                    self.modal = Some(Modal::Confirm(confirm));
                    Vec::new()
                }
                KeyCode::Down => {
                    confirm.scroll = confirm.scroll.saturating_add(1);
                    self.modal = Some(Modal::Confirm(confirm));
                    Vec::new()
                }
                KeyCode::PageUp => {
                    confirm.scroll = confirm.scroll.saturating_sub(10);
                    self.modal = Some(Modal::Confirm(confirm));
                    Vec::new()
                }
                KeyCode::PageDown => {
                    confirm.scroll = confirm.scroll.saturating_add(10);
                    self.modal = Some(Modal::Confirm(confirm));
                    Vec::new()
                }
                _ => {
                    self.modal = Some(Modal::Confirm(confirm));
                    Vec::new()
                }
            },
            Modal::Edit(mut edit) => match key.code {
                KeyCode::Esc => Vec::new(),
                KeyCode::Enter => match self.apply_edit(&edit) {
                    Ok(intents) => intents,
                    Err(error) => {
                        edit.error = Some(error);
                        self.modal = Some(Modal::Edit(edit));
                        Vec::new()
                    }
                },
                KeyCode::Backspace => {
                    edit.value.pop();
                    edit.error = None;
                    self.modal = Some(Modal::Edit(edit));
                    Vec::new()
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    edit.value.clear();
                    edit.error = None;
                    self.modal = Some(Modal::Edit(edit));
                    Vec::new()
                }
                KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    edit.value.push(character);
                    edit.error = None;
                    self.modal = Some(Modal::Edit(edit));
                    Vec::new()
                }
                _ => {
                    self.modal = Some(Modal::Edit(edit));
                    Vec::new()
                }
            },
            Modal::ClusterPicker(mut picker) => match key.code {
                KeyCode::Esc => Vec::new(),
                KeyCode::Up => {
                    picker.selected = picker.selected.saturating_sub(1);
                    self.modal = Some(Modal::ClusterPicker(picker));
                    Vec::new()
                }
                KeyCode::Down => {
                    picker.selected = (picker.selected + 1).min(picker.options.len() - 1);
                    self.modal = Some(Modal::ClusterPicker(picker));
                    Vec::new()
                }
                KeyCode::Home => {
                    picker.selected = 0;
                    self.modal = Some(Modal::ClusterPicker(picker));
                    Vec::new()
                }
                KeyCode::End => {
                    picker.selected = picker.options.len() - 1;
                    self.modal = Some(Modal::ClusterPicker(picker));
                    Vec::new()
                }
                KeyCode::Enter => {
                    let alias = if picker.selected == 0 {
                        None
                    } else {
                        picker.options.get(picker.selected).cloned()
                    };
                    self.current_settings_mut().cluster_filter = alias;
                    self.status = match self.current_settings().cluster_filter.as_deref() {
                        Some(alias) => format!("Фильтр по кластеру: {alias}"),
                        None => "Фильтр по кластеру: все кластеры".to_owned(),
                    };
                    self.status_is_error = false;
                    vec![Intent::Refresh(self.screen)]
                }
                _ => {
                    self.modal = Some(Modal::ClusterPicker(picker));
                    Vec::new()
                }
            },
            Modal::ClusterForm(mut form) => match key.code {
                KeyCode::Esc => Vec::new(),
                KeyCode::Enter => match form.build(self.rac_options.clone()) {
                    Ok(request) => self.begin_operation(
                        "Проверка и добавление кластера...",
                        OperationRequest::AddCluster(request),
                    ),
                    Err(error) => {
                        form.error = Some(error);
                        self.modal = Some(Modal::ClusterForm(form));
                        Vec::new()
                    }
                },
                _ => {
                    handle_cluster_form_input(&mut form, key);
                    self.modal = Some(Modal::ClusterForm(form));
                    Vec::new()
                }
            },
            Modal::CredentialForm(mut form) => match key.code {
                KeyCode::Esc => Vec::new(),
                KeyCode::Enter => match form.build() {
                    Ok(request) => self.begin_operation(
                        "Добавление credential override...",
                        OperationRequest::AddCredential(request),
                    ),
                    Err(error) => {
                        form.error = Some(error);
                        self.modal = Some(Modal::CredentialForm(form));
                        Vec::new()
                    }
                },
                _ => {
                    handle_credential_form_input(&mut form, key);
                    self.modal = Some(Modal::CredentialForm(form));
                    Vec::new()
                }
            },
            Modal::Progress { title, request_id } => {
                if key.code == KeyCode::Esc {
                    self.operation = None;
                    self.status = "Операция отменяется...".to_owned();
                    self.status_is_error = false;
                    vec![Intent::Cancel(request_id)]
                } else {
                    self.modal = Some(Modal::Progress { title, request_id });
                    Vec::new()
                }
            }
        }
    }

    fn apply_edit(&mut self, edit: &EditModal) -> Result<Vec<Intent>, String> {
        if edit.kind == EditKind::Interval {
            let seconds = edit
                .value
                .trim()
                .parse::<u64>()
                .map_err(|_| "Интервал должен быть целым числом секунд".to_owned())?;
            self.auto_refresh
                .set_interval(Duration::from_secs(seconds), Instant::now())?;
            self.interval_status();
            return Ok(Vec::new());
        }

        let mut settings = self.current_settings().clone();
        match edit.kind {
            EditKind::Query => settings.query = edit.value.clone(),
            EditKind::Filter => settings.filter = edit.value.clone(),
            EditKind::Sort => settings.sort = edit.value.clone(),
            EditKind::Columns => settings.columns = edit.value.clone(),
            EditKind::Interval => unreachable!(),
        }
        if let Some(kind) = self.screen.record_kind() {
            settings.build(kind, &self.registry)?;
        } else if !matches!(edit.kind, EditKind::Query) {
            return Err("Для этого раздела доступна только строка поиска `/`".to_owned());
        }
        *self.current_settings_mut() = settings;
        Ok(vec![Intent::Refresh(self.screen)])
    }

    fn current_settings(&self) -> &QuerySettings {
        match self.screen {
            Screen::Clusters => &self.clusters.settings,
            Screen::Credentials => &self.credentials.settings,
            Screen::Infobases => &self.infobases.settings,
            Screen::Sessions => &self.sessions.settings,
            Screen::Connections => &self.connections.settings,
            Screen::Diagnostics => &self.clusters.settings,
        }
    }

    fn current_settings_mut(&mut self) -> &mut QuerySettings {
        match self.screen {
            Screen::Clusters => &mut self.clusters.settings,
            Screen::Credentials => &mut self.credentials.settings,
            Screen::Infobases => &mut self.infobases.settings,
            Screen::Sessions => &mut self.sessions.settings,
            Screen::Connections => &mut self.connections.settings,
            Screen::Diagnostics => &mut self.clusters.settings,
        }
    }

    fn open_edit(&mut self, kind: EditKind) {
        if self.screen == Screen::Diagnostics {
            self.set_status_error("В разделе диагностики фильтры не применяются".to_owned());
            return;
        }
        if self.screen.record_kind().is_none() && kind != EditKind::Query {
            self.set_status_error("Для этого раздела доступна только строка поиска `/`".to_owned());
            return;
        }
        let settings = self.current_settings();
        let value = match kind {
            EditKind::Query => settings.query.clone(),
            EditKind::Filter => settings.filter.clone(),
            EditKind::Sort => settings.sort.clone(),
            EditKind::Columns => settings.columns.clone(),
            EditKind::Interval => String::new(),
        };
        self.modal = Some(Modal::Edit(EditModal {
            kind,
            value,
            error: None,
        }));
    }

    fn open_cluster_picker(&mut self) {
        if self.screen.record_kind().is_none() || self.screen == Screen::Diagnostics {
            self.set_status_error(
                "Фильтр по кластеру доступен в разделах баз, сеансов и соединений".to_owned(),
            );
            return;
        }
        let aliases = self.cluster_aliases();
        let mut options = Vec::with_capacity(aliases.len() + 1);
        options.push("Все кластеры".to_owned());
        options.extend(aliases);
        let selected = self
            .current_settings()
            .cluster_filter
            .as_deref()
            .and_then(|alias| options.iter().position(|option| option == alias))
            .unwrap_or(0);
        self.modal = Some(Modal::ClusterPicker(ClusterPicker { options, selected }));
    }

    fn cluster_aliases(&self) -> Vec<String> {
        let LoadState::Data(rows) = &self.clusters.resource.state else {
            return Vec::new();
        };
        let mut aliases = rows
            .iter()
            .map(|row| row.target.alias.to_string())
            .collect::<Vec<_>>();
        aliases.sort();
        aliases.dedup();
        aliases
    }

    fn change_screen(&mut self, direction: isize) -> Vec<Intent> {
        self.screen = self.screen.wrapping_add(direction);
        self.status = format!("Раздел: {}", self.screen.title());
        self.status_is_error = false;
        self.initial_refresh_intent()
    }

    fn initial_refresh_intent(&self) -> Vec<Intent> {
        let needed = match self.screen {
            Screen::Clusters => self.clusters.resource.needs_initial_load(),
            Screen::Credentials => self.credentials.resource.needs_initial_load(),
            Screen::Infobases => self.infobases.resource.needs_initial_load(),
            Screen::Sessions => self.sessions.resource.needs_initial_load(),
            Screen::Connections => self.connections.resource.needs_initial_load(),
            Screen::Diagnostics => self.diagnostics.resource.needs_initial_load(),
        };
        if needed {
            vec![Intent::Refresh(self.screen)]
        } else {
            Vec::new()
        }
    }

    pub(crate) fn on_tick(&mut self, now: Instant) -> Vec<Intent> {
        if !self.auto_refresh.due(now) {
            return Vec::new();
        }
        if self.current_refresh_active() {
            self.status = "Тик автообновления пропущен: refresh еще выполняется".to_owned();
            self.status_is_error = false;
            Vec::new()
        } else {
            vec![Intent::Refresh(self.screen)]
        }
    }

    pub(crate) fn current_refresh_active(&self) -> bool {
        self.refresh_active(self.screen)
    }

    fn refresh_active(&self, screen: Screen) -> bool {
        match screen {
            Screen::Clusters => self.clusters.resource.is_active(),
            Screen::Credentials => self.credentials.resource.is_active(),
            Screen::Infobases => self.infobases.resource.is_active(),
            Screen::Sessions => self.sessions.resource.is_active(),
            Screen::Connections => self.connections.resource.is_active(),
            Screen::Diagnostics => self.diagnostics.resource.is_active(),
        }
    }

    fn interval_status(&mut self) {
        self.status = format!(
            "Интервал автообновления: {} с (авто: {})",
            self.auto_refresh.interval.as_secs(),
            if self.auto_refresh.enabled {
                "вкл"
            } else {
                "выкл"
            }
        );
        self.status_is_error = false;
    }

    fn current_len(&self) -> usize {
        match self.screen {
            Screen::Clusters => data_len(&self.clusters.resource.state),
            Screen::Credentials => data_len(&self.credentials.resource.state),
            Screen::Infobases => outcome_len(&self.infobases.resource.state),
            Screen::Sessions => outcome_len(&self.sessions.resource.state),
            Screen::Connections => outcome_len(&self.connections.resource.state),
            Screen::Diagnostics => 0,
        }
    }

    fn navigate(&mut self, direction: isize, page: bool) {
        if self.screen == Screen::Diagnostics {
            let delta = if page { 10 } else { 1 };
            if direction < 0 {
                self.diagnostics.scroll = self.diagnostics.scroll.saturating_sub(delta);
            } else {
                self.diagnostics.scroll = self.diagnostics.scroll.saturating_add(delta);
            }
            return;
        }
        let len = self.current_len();
        let nav = self.current_nav_mut();
        let step = if page {
            nav.viewport_height.max(1) as isize
        } else {
            1
        };
        nav.move_by(direction * step, len);
    }

    fn navigate_home(&mut self) {
        if self.screen == Screen::Diagnostics {
            self.diagnostics.scroll = 0;
            return;
        }
        let len = self.current_len();
        self.current_nav_mut().home(len);
    }

    fn navigate_end(&mut self) {
        if self.screen == Screen::Diagnostics {
            self.diagnostics.scroll = usize::MAX / 2;
            return;
        }
        let len = self.current_len();
        self.current_nav_mut().end(len);
    }

    fn current_nav_mut(&mut self) -> &mut TableNav {
        match self.screen {
            Screen::Clusters => &mut self.clusters.nav,
            Screen::Credentials => &mut self.credentials.nav,
            Screen::Infobases => &mut self.infobases.nav,
            Screen::Sessions => &mut self.sessions.nav,
            Screen::Connections => &mut self.connections.nav,
            Screen::Diagnostics => &mut self.clusters.nav,
        }
    }

    fn toggle_mark(&mut self) {
        let key = match self.screen {
            Screen::Sessions => selected_session(&self.sessions).map(session_key),
            Screen::Connections => selected_connection(&self.connections).map(connection_key),
            _ => None,
        };
        let Some(key) = key else {
            self.status = "Множественный выбор доступен для сеансов и соединений".to_owned();
            self.status_is_error = false;
            return;
        };
        self.current_nav_mut().toggle(key);
        self.status = format!("Отмечено объектов: {}", self.current_nav_mut().marked.len());
        self.status_is_error = false;
    }

    fn open_details(&mut self) {
        let details = match self.screen {
            Screen::Clusters => selected_cluster(&self.clusters).map(cluster_details),
            Screen::Credentials => selected_credential(&self.credentials).map(credential_details),
            Screen::Infobases => selected_infobase(&self.infobases)
                .map(|record| record_details(record, RecordKind::Infobase, &self.registry)),
            Screen::Sessions => selected_session(&self.sessions)
                .map(|record| record_details(record, RecordKind::Session, &self.registry)),
            Screen::Connections => selected_connection(&self.connections)
                .map(|record| record_details(record, RecordKind::Connection, &self.registry)),
            Screen::Diagnostics => None,
        };
        if let Some(lines) = details {
            self.modal = Some(Modal::Details(DetailsModal {
                title: format!("Детали: {}", self.screen.title()),
                lines,
                scroll: 0,
            }));
        }
    }

    fn open_add_form(&mut self) {
        match self.screen {
            Screen::Clusters => self.modal = Some(Modal::ClusterForm(ClusterForm::new())),
            Screen::Credentials => {
                let cluster = selected_credential(&self.credentials)
                    .map(|row| row.cluster.to_string())
                    .or_else(|| {
                        selected_cluster(&self.clusters).map(|row| row.target.alias.to_string())
                    })
                    .unwrap_or_default();
                self.modal = Some(Modal::CredentialForm(CredentialForm::new(cluster)));
            }
            _ => self.set_status_error(
                "Добавление доступно только в разделах «Кластеры» и «Credentials»".to_owned(),
            ),
        }
    }

    fn start_remove_selected(&mut self) -> Vec<Intent> {
        match self.screen {
            Screen::Clusters => {
                let Some(cluster) = selected_cluster(&self.clusters) else {
                    self.set_status_error("Не выбран кластер".to_owned());
                    return Vec::new();
                };
                self.begin_operation(
                    "Подготовка плана удаления кластера...",
                    OperationRequest::PrepareClusterRemove(cluster.target.alias.to_string()),
                )
            }
            Screen::Credentials => {
                let Some(row) = selected_credential(&self.credentials) else {
                    self.set_status_error("Не выбран credential override".to_owned());
                    return Vec::new();
                };
                let selector = row.entry.infobase_uuid().map_or_else(
                    || {
                        CredentialOverrideSelector::by_name(
                            row.entry.infobase().unwrap_or_default().to_owned(),
                        )
                    },
                    |uuid| Ok(CredentialOverrideSelector::by_uuid(uuid)),
                );
                let Ok(selector) = selector else {
                    self.set_status_error(
                        "У выбранного override нет точного идентификатора".to_owned(),
                    );
                    return Vec::new();
                };
                let request = CredentialOverrideRemoveRequest {
                    cluster: row.cluster.clone(),
                    selector,
                };
                self.modal = Some(Modal::Confirm(Box::new(ConfirmModal {
                    title: "Удалить credential override?".to_owned(),
                    lines: credential_details(row),
                    action: ConfirmAction::RemoveCredential(request),
                    scroll: 0,
                })));
                Vec::new()
            }
            _ => {
                self.set_status_error(
                    "Удаление доступно только для кластеров и credential overrides".to_owned(),
                );
                Vec::new()
            }
        }
    }

    fn start_kill_selected(&mut self) -> Vec<Intent> {
        match self.screen {
            Screen::Sessions => {
                let selections = selected_session_identities(&self.sessions);
                if selections.is_empty() {
                    self.set_status_error("Не выбран ни один сеанс".to_owned());
                    return Vec::new();
                }
                self.begin_operation(
                    "Подготовка точных планов завершения...",
                    OperationRequest::PrepareSessionKill(selections),
                )
            }
            Screen::Connections => {
                let selections = selected_connection_identities(&self.connections);
                if selections.is_empty() {
                    self.set_status_error("Не выбрано ни одно соединение".to_owned());
                    return Vec::new();
                }
                self.begin_operation(
                    "Подготовка точных планов разрыва...",
                    OperationRequest::PrepareConnectionKill(selections),
                )
            }
            _ => {
                self.set_status_error(
                    "Опасное действие доступно только для сеансов и соединений".to_owned(),
                );
                Vec::new()
            }
        }
    }

    pub(crate) fn current_settings_summary(&self) -> String {
        if self.screen == Screen::Diagnostics {
            return "Последние ошибки application/RAC и выбранные версии rac.exe".to_owned();
        }
        let settings = self.current_settings();
        let mut parts = Vec::new();
        if let Some(cluster) = settings.cluster_filter.as_deref() {
            parts.push(format!("cluster={cluster}"));
        }
        if !settings.query.is_empty() {
            parts.push(format!("query={}", settings.query));
        }
        if !settings.filter.is_empty() {
            parts.push(format!("filter={}", settings.filter));
        }
        if !settings.sort.is_empty() {
            parts.push(format!("sort={}", settings.sort));
        }
        if !settings.columns.is_empty() {
            parts.push(format!("columns={}", settings.columns));
        }
        if parts.is_empty() {
            "Фильтры: нет; сортировка/колонки: по умолчанию".to_owned()
        } else {
            parts.join(" | ")
        }
    }

    pub(crate) fn selected_count(&self) -> usize {
        match self.screen {
            Screen::Sessions => self.sessions.nav.marked.len(),
            Screen::Connections => self.connections.nav.marked.len(),
            _ => 0,
        }
    }
}

fn handle_cluster_form_input(form: &mut ClusterForm, key: KeyEvent) {
    form.error = None;
    match key.code {
        KeyCode::Tab | KeyCode::Down => form.field = (form.field + 1) % 5,
        KeyCode::BackTab | KeyCode::Up => form.field = (form.field + 4) % 5,
        KeyCode::F(2) => form.auth_mode = form.auth_mode.next(1),
        KeyCode::Left if form.field == 2 => form.auth_mode = form.auth_mode.next(-1),
        KeyCode::Right | KeyCode::Char(' ') if form.field == 2 => {
            form.auth_mode = form.auth_mode.next(1);
        }
        KeyCode::Backspace => {
            if let Some(value) = form.edit_value() {
                value.pop();
            }
        }
        KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(value) = form.edit_value() {
                value.push(character);
            }
        }
        _ => {}
    }
}

fn handle_credential_form_input(form: &mut CredentialForm, key: KeyEvent) {
    form.error = None;
    match key.code {
        KeyCode::Tab | KeyCode::Down => form.field = (form.field + 1) % 6,
        KeyCode::BackTab | KeyCode::Up => form.field = (form.field + 5) % 6,
        KeyCode::F(2) => form.auth_mode = form.auth_mode.next(1),
        KeyCode::Left if form.field == 3 => form.auth_mode = form.auth_mode.next(-1),
        KeyCode::Right | KeyCode::Char(' ') if form.field == 3 => {
            form.auth_mode = form.auth_mode.next(1);
        }
        KeyCode::Backspace => {
            if let Some(value) = form.edit_value() {
                value.pop();
            }
        }
        KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(value) = form.edit_value() {
                value.push(character);
            }
        }
        _ => {}
    }
}

fn data_len<T>(state: &LoadState<Vec<T>>) -> usize {
    match state {
        LoadState::Data(data) => data.len(),
        LoadState::Loading | LoadState::Error(_) => 0,
    }
}

fn outcome_len<T>(state: &LoadState<QueryOutcome<T>>) -> usize {
    match state {
        LoadState::Data(data) => data.data.len(),
        LoadState::Loading | LoadState::Error(_) => 0,
    }
}

pub(crate) fn cluster_key(record: &ClusterRow) -> RowKey {
    RowKey::Cluster(record.target.discovered_cluster.uuid.into_uuid())
}

pub(crate) fn credential_key(record: &CredentialRow) -> RowKey {
    RowKey::Credential {
        cluster: record.cluster_uuid.into_uuid(),
        infobase: record.entry.infobase_uuid().map(InfobaseUuid::into_uuid),
        name: record.entry.infobase().unwrap_or_default().to_lowercase(),
    }
}

pub(crate) fn infobase_key(record: &InfobaseRecord) -> RowKey {
    RowKey::Infobase(
        record.source.cluster_uuid.into_uuid(),
        record.infobase_uuid.into_uuid(),
    )
}

pub(crate) fn session_key(record: &SessionRecord) -> RowKey {
    RowKey::Session(
        record.source.cluster_uuid.into_uuid(),
        record.session.into_uuid(),
    )
}

pub(crate) fn connection_key(record: &ConnectionRecord) -> RowKey {
    RowKey::Connection(
        record.source.cluster_uuid.into_uuid(),
        record.connection.into_uuid(),
    )
}

fn cluster_keys_from_state(state: &LoadState<Vec<ClusterRow>>) -> Vec<RowKey> {
    match state {
        LoadState::Data(data) => data.iter().map(cluster_key).collect(),
        LoadState::Loading | LoadState::Error(_) => Vec::new(),
    }
}

fn credential_keys_from_state(state: &LoadState<Vec<CredentialRow>>) -> Vec<RowKey> {
    match state {
        LoadState::Data(data) => data.iter().map(credential_key).collect(),
        LoadState::Loading | LoadState::Error(_) => Vec::new(),
    }
}

fn infobase_keys_from_state(state: &LoadState<QueryOutcome<InfobaseRecord>>) -> Vec<RowKey> {
    match state {
        LoadState::Data(data) => data.data.iter().map(infobase_key).collect(),
        LoadState::Loading | LoadState::Error(_) => Vec::new(),
    }
}

fn session_keys_from_state(state: &LoadState<QueryOutcome<SessionRecord>>) -> Vec<RowKey> {
    match state {
        LoadState::Data(data) => data.data.iter().map(session_key).collect(),
        LoadState::Loading | LoadState::Error(_) => Vec::new(),
    }
}

fn connection_keys_from_state(state: &LoadState<QueryOutcome<ConnectionRecord>>) -> Vec<RowKey> {
    match state {
        LoadState::Data(data) => data.data.iter().map(connection_key).collect(),
        LoadState::Loading | LoadState::Error(_) => Vec::new(),
    }
}

fn selected_cluster(screen: &TableScreen<Vec<ClusterRow>>) -> Option<&ClusterRow> {
    match &screen.resource.state {
        LoadState::Data(data) => screen.selected_index().and_then(|index| data.get(index)),
        LoadState::Loading | LoadState::Error(_) => None,
    }
}

fn selected_credential(screen: &TableScreen<Vec<CredentialRow>>) -> Option<&CredentialRow> {
    match &screen.resource.state {
        LoadState::Data(data) => screen.selected_index().and_then(|index| data.get(index)),
        LoadState::Loading | LoadState::Error(_) => None,
    }
}

fn selected_infobase(
    screen: &TableScreen<QueryOutcome<InfobaseRecord>>,
) -> Option<&InfobaseRecord> {
    match &screen.resource.state {
        LoadState::Data(data) => screen
            .selected_index()
            .and_then(|index| data.data.get(index)),
        LoadState::Loading | LoadState::Error(_) => None,
    }
}

fn selected_session(screen: &TableScreen<QueryOutcome<SessionRecord>>) -> Option<&SessionRecord> {
    match &screen.resource.state {
        LoadState::Data(data) => screen
            .selected_index()
            .and_then(|index| data.data.get(index)),
        LoadState::Loading | LoadState::Error(_) => None,
    }
}

fn selected_connection(
    screen: &TableScreen<QueryOutcome<ConnectionRecord>>,
) -> Option<&ConnectionRecord> {
    match &screen.resource.state {
        LoadState::Data(data) => screen
            .selected_index()
            .and_then(|index| data.data.get(index)),
        LoadState::Loading | LoadState::Error(_) => None,
    }
}

impl<T> TableScreen<T> {
    fn selected_index(&self) -> Option<usize> {
        self.nav.selected
    }
}

fn selected_session_identities(
    screen: &TableScreen<QueryOutcome<SessionRecord>>,
) -> Vec<SessionSelection> {
    let LoadState::Data(outcome) = &screen.resource.state else {
        return Vec::new();
    };
    outcome
        .data
        .iter()
        .enumerate()
        .filter(|(index, record)| {
            if screen.nav.marked.is_empty() {
                screen.nav.selected == Some(*index)
            } else {
                screen.nav.marked.contains(&session_key(record))
            }
        })
        .map(|(_, record)| SessionSelection {
            cluster: record.source.cluster.to_string(),
            cluster_uuid: record.source.cluster_uuid,
            session: record.session,
        })
        .collect()
}

fn selected_connection_identities(
    screen: &TableScreen<QueryOutcome<ConnectionRecord>>,
) -> Vec<ConnectionSelection> {
    let LoadState::Data(outcome) = &screen.resource.state else {
        return Vec::new();
    };
    outcome
        .data
        .iter()
        .enumerate()
        .filter(|(index, record)| {
            if screen.nav.marked.is_empty() {
                screen.nav.selected == Some(*index)
            } else {
                screen.nav.marked.contains(&connection_key(record))
            }
        })
        .map(|(_, record)| ConnectionSelection {
            cluster: record.source.cluster.to_string(),
            cluster_uuid: record.source.cluster_uuid,
            connection: record.connection,
        })
        .collect()
}

fn cluster_details(row: &ClusterRow) -> Vec<String> {
    let record = &row.target;
    let mut lines = vec![
        format!("alias: {}", record.alias),
        format!("ras_address: {}", record.ras),
        format!("cluster_uuid: {}", record.discovered_cluster.uuid),
        format!("cluster_name: {}", record.discovered_cluster.name),
        format!("cluster_host: {}", record.discovered_cluster.host),
        format!("cluster_port: {}", record.discovered_cluster.port),
        format!("status: {}", cluster_status_text(&row.status)),
        format!("rac_policy: {}", rac_policy(&record.rac_policy)),
        format!(
            "cluster_auth_mode: {}",
            auth_mode(record.cluster_auth.mode())
        ),
        format!(
            "cluster_auth_user: {}",
            record.cluster_auth.user().unwrap_or("")
        ),
        format!(
            "infobase_default_auth_mode: {}",
            auth_mode(record.infobase_auth.default_auth().mode())
        ),
        format!(
            "infobase_default_auth_user: {}",
            record.infobase_auth.default_auth().user().unwrap_or("")
        ),
        format!(
            "credential_overrides: {}",
            record.infobase_auth.overrides().len()
        ),
    ];
    for (name, value) in &record.discovered_cluster.extra {
        lines.push(format!("extra.{name}: {}", field_value(value.as_ref())));
    }
    lines
}

fn credential_details(record: &CredentialRow) -> Vec<String> {
    vec![
        format!("cluster: {}", record.cluster),
        format!("cluster_uuid: {}", record.cluster_uuid),
        format!("infobase: {}", record.entry.infobase().unwrap_or("")),
        format!(
            "infobase_uuid: {}",
            record
                .entry
                .infobase_uuid()
                .map_or_else(String::new, |uuid| uuid.to_string())
        ),
        format!("auth_mode: {}", auth_mode(record.entry.auth().mode())),
        format!("user: {}", record.entry.auth().user().unwrap_or("")),
    ]
}

fn record_details<R: FieldAccess>(
    record: &R,
    kind: RecordKind,
    registry: &FieldRegistry,
) -> Vec<String> {
    let definitions = registry.definitions(kind);
    let mut lines = Vec::with_capacity(definitions.len() + record.extra_fields().len());
    let mut known = HashSet::new();
    for definition in definitions {
        if known.insert(definition.name) {
            let value = record.field(definition.name).unwrap_or(FieldValueRef::Null);
            lines.push(format!("{}: {}", definition.name, field_value(value)));
        }
    }
    for (name, value) in record.extra_fields() {
        if !known.contains(name.as_str()) {
            lines.push(format!("extra.{name}: {}", field_value(value.as_ref())));
        }
    }
    lines
}

fn field_value(value: FieldValueRef<'_>) -> String {
    match value {
        FieldValueRef::Uuid(value) => value.to_string(),
        FieldValueRef::Int(value) => value.to_string(),
        FieldValueRef::Bool(value) => value.to_string(),
        FieldValueRef::DateTime(value) => value.to_rfc3339(),
        FieldValueRef::Str(value) => value.to_owned(),
        FieldValueRef::Null => "—".to_owned(),
    }
}

fn auth_mode(mode: AuthMode) -> &'static str {
    match mode {
        AuthMode::None => "none",
        AuthMode::Password => "password",
    }
}

fn rac_policy(policy: &RacPolicy) -> String {
    match policy {
        RacPolicy::Auto => "auto".to_owned(),
        RacPolicy::Version(version) => format!("version:{version}"),
        RacPolicy::ExplicitPath(path) => format!("path:{}", path.display()),
    }
}

pub(crate) fn cluster_status_text(status: &ClusterStatus) -> String {
    match status {
        ClusterStatus::Ok => "ok".to_owned(),
        ClusterStatus::Error(error) => format!("error ({})", short_error(error)),
    }
}

fn short_error(error: &TargetError) -> &'static str {
    match error.kind {
        TargetErrorKind::Unavailable => "недоступен",
        TargetErrorKind::Timeout => "тайм-аут",
        TargetErrorKind::Authentication => "ошибка доступа",
        TargetErrorKind::Protocol => "ошибка протокола",
        TargetErrorKind::InvalidResponse => "некорректный ответ",
        TargetErrorKind::RacNotFound => "rac.exe не найден",
        TargetErrorKind::Cancelled => "отменено",
        TargetErrorKind::Internal => "внутренняя ошибка",
    }
}

fn failure_lines(failure: &TaskFailure) -> Vec<String> {
    let mut lines = vec![
        format!("code: {}", failure.code),
        format!("message: {}", failure.message),
    ];
    for error in &failure.target_errors {
        lines.push(format!(
            "{} | {} | {} | {}",
            error.cluster,
            error.ras_address,
            error.code(),
            error.message
        ));
    }
    lines
}

fn option_i64(value: Option<i64>) -> String {
    value.map_or_else(String::new, |value| value.to_string())
}

fn help_lines() -> Vec<String> {
    [
        "Tab / Shift+Tab / ← →: сменить раздел",
        "1..6: открыть раздел",
        "↑ ↓ PgUp PgDn Home End: навигация",
        "Enter: все известные canonical fields и extra",
        "F5: ручное обновление (overlap не допускается)",
        "a: автообновление; [ ]: интервалы 5/10/30/60 с; i: свой интервал",
        "/: query; f: filter; s: sort; c: columns",
        "g: фильтр по кластеру (выпадающий список)",
        "Space: отметить несколько сеансов/соединений",
        "k: подготовить точные планы и запросить подтверждение kill",
        "n: добавить кластер/credential override; Delete/x: удалить",
        "F2 или ← → на auth_mode: none/password",
        "Esc: закрыть окно/отменить задачу; на основном экране выйти",
        "q или Ctrl+C: выйти",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DiscoveredCluster, InfobaseAuthPolicy};

    fn options() -> TuiOptions {
        TuiOptions::new()
    }

    fn cluster_row(alias: &str) -> ClusterRow {
        let alias = ClusterAlias::new(alias).unwrap_or_else(|error| panic!("{error}"));
        let ras: RasEndpoint = "ras.local:1545"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));
        let cluster = DiscoveredCluster::new(
            ClusterUuid::new(Uuid::new_v4()),
            "cluster",
            "cluster.local",
            1541,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        ClusterRow {
            target: ClusterTarget::new(
                alias,
                ras,
                cluster,
                RacPolicy::Auto,
                AuthConfig::none(),
                InfobaseAuthPolicy::default(),
            ),
            status: ClusterStatus::Ok,
        }
    }

    #[test]
    fn reducer_changes_tabs_and_requests_initial_load() {
        let mut app = App::new(&options());
        let intents = app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));

        assert_eq!(app.screen, Screen::Credentials);
        assert!(matches!(
            intents.as_slice(),
            [Intent::Refresh(Screen::Credentials)]
        ));
    }

    #[test]
    fn refresh_tracker_rejects_overlap_and_stale_completion() {
        let mut tracker = RefreshTracker::default();
        let first = RequestId(1);
        let second = RequestId(2);
        let generation = tracker.begin(first).unwrap_or_default();

        assert!(tracker.begin(second).is_none());
        assert!(!tracker.finish(second, generation));
        assert!(tracker.is_active());
        assert!(tracker.finish(first, generation));
        assert!(!tracker.is_active());
    }

    #[test]
    fn manual_refresh_during_active_request_is_queued_without_overlap() {
        let mut app = App::new(&options());
        let first = app
            .begin_refresh(Screen::Clusters)
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("first refresh was not started"));

        assert!(
            app.begin_refresh(Screen::Clusters)
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
        let intents = app.apply_background(BackgroundMessage {
            request_id: first.meta.request_id,
            generation: first.meta.generation,
            screen: Screen::Clusters,
            payload: BackgroundPayload::Clusters(Ok(Vec::new())),
        });

        assert!(matches!(
            intents.as_slice(),
            [Intent::Refresh(Screen::Clusters)]
        ));
    }

    #[test]
    fn selection_and_marks_are_preserved_by_composite_uuid() {
        let cluster = Uuid::from_u128(1);
        let first = RowKey::Session(cluster, Uuid::from_u128(10));
        let second = RowKey::Session(cluster, Uuid::from_u128(20));
        let third = RowKey::Session(cluster, Uuid::from_u128(30));
        let mut nav = TableNav {
            selected: Some(1),
            marked: HashSet::from([second.clone(), third.clone()]),
            viewport_height: 5,
            ..TableNav::default()
        };

        nav.preserve(
            &[first.clone(), second.clone(), third],
            &[second.clone(), first],
        );

        assert_eq!(nav.selected, Some(0));
        assert_eq!(nav.marked, HashSet::from([second]));
    }

    #[test]
    fn auto_refresh_skips_due_tick_while_current_refresh_is_active() {
        let mut app = App::new(&options());
        app.auto_refresh.enabled = true;
        app.auto_refresh.next_due = Instant::now();
        let request = app.begin_refresh(Screen::Clusters);
        assert!(matches!(request, Ok(Some(_))));

        let intents = app.on_tick(Instant::now() + Duration::from_secs(1));

        assert!(intents.is_empty());
        assert!(app.status.contains("пропущен"));
    }

    #[test]
    fn custom_interval_rejects_values_below_contract_minimum() {
        let mut auto = AutoRefresh::new(Duration::from_secs(10));
        assert!(
            auto.set_interval(Duration::from_secs(1), Instant::now())
                .is_err()
        );
        assert!(
            auto.set_interval(super::super::MIN_REFRESH_INTERVAL, Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn cluster_picker_lists_aliases_and_filters_refresh() {
        let mut app = App::new(&options());
        app.screen = Screen::Sessions;
        app.clusters.resource.state =
            LoadState::Data(vec![cluster_row("dev"), cluster_row("prod")]);

        app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        let Modal::ClusterPicker(picker) = app.modal.as_ref().unwrap_or_else(|| panic!("no modal"))
        else {
            panic!("ожидался выбор кластера");
        };
        assert_eq!(picker.options, vec!["Все кластеры", "dev", "prod"]);

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        let intents = app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert_eq!(app.sessions.settings.cluster_filter.as_deref(), Some("dev"));
        assert!(matches!(
            intents.as_slice(),
            [Intent::Refresh(Screen::Sessions)]
        ));
    }
}
