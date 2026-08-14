use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use uuid::Uuid;

use crate::domain::{
    AuthConfig, ClusterAlias, ConnectionUuid, DomainError, FieldRegistry, FieldValue, Filter,
    FilterOperator, ProcessUuid, QuerySpec, RasEndpoint, RecordKind, SecretString, SessionUuid,
};

const HELP_TEMPLATE: &str = "{name} {version}\n{about-with-newline}\nИспользование: {usage}\n\nКоманды:\n{subcommands}\nПараметры:\n{options}";
const GROUP_HELP_TEMPLATE: &str = "{name}\n{about-with-newline}\nИспользование: {usage}\n\nКоманды:\n{subcommands}\nПараметры:\n{options}";
const COMMAND_HELP_TEMPLATE: &str =
    "{name}\n{about-with-newline}\nИспользование: {usage}\n\n{positionals}\nПараметры:\n{options}";

/// Machine-readable output format selected for a CLI command.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Csv,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Table => "table",
            Self::Json => "json",
            Self::Csv => "csv",
        })
    }
}

/// Authentication mode accepted by `cluster add`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AuthModeArg {
    None,
    Password,
}

/// Root command. An absent subcommand means that the TUI should be started.
#[derive(Clone, Debug, Parser)]
#[command(
    name = "onecadmin",
    version,
    about = "Администрирование кластеров 1С:Предприятия через RAS/RAC",
    long_about = None,
    help_template = HELP_TEMPLATE,
    subcommand_help_heading = "Команды",
    subcommand_value_name = "КОМАНДА",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Explicit configuration path. It takes precedence over all other sources.
    #[arg(
        long,
        global = true,
        env = "ONECADMIN_CONFIG",
        value_name = "PATH",
        help = "Путь к YAML-файлу конфигурации"
    )]
    pub config: Option<PathBuf>,

    /// Explicit `rac.exe` path.
    #[arg(
        long,
        global = true,
        env = "ONECADMIN_RAC_PATH",
        value_name = "PATH",
        help = "Явный путь к rac.exe"
    )]
    pub rac_path: Option<PathBuf>,

    /// RAC operation timeout in seconds.
    #[arg(
        long,
        global = true,
        value_name = "SECONDS",
        value_parser = parse_timeout,
        help = "Тайм-аут операции RAC в секундах (положительное целое число)"
    )]
    pub timeout: Option<NonZeroU64>,

    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t,
        value_name = "FORMAT",
        help = "Формат вывода: table, json или csv"
    )]
    pub format: OutputFormat,

    #[arg(
        long,
        global = true,
        action = ArgAction::SetTrue,
        help = "Отключить цветной вывод"
    )]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Option<CliCommand>,
}

impl Cli {
    #[must_use]
    pub const fn is_tui_mode(&self) -> bool {
        self.command.is_none()
    }

    /// Validates all rules that must be checked before configuration or network I/O.
    pub fn validate(&self) -> Result<(), CliValidationError> {
        let registry = FieldRegistry::new();
        match &self.command {
            None => Ok(()),
            Some(CliCommand::Cluster { command }) => match command {
                ClusterCommand::Add(args) => args.validate(),
                ClusterCommand::Remove(_) => Ok(()),
            },
            Some(CliCommand::Infobase { command }) => match command {
                InfobaseCommand::Search(args) => args
                    .query_spec(&registry)
                    .map(|_| ())
                    .map_err(CliValidationError::from),
            },
            Some(CliCommand::Session { command }) => match command {
                SessionCommand::List(args) => args
                    .query_spec(&registry)
                    .map(|_| ())
                    .map_err(CliValidationError::from),
                SessionCommand::Kill(args) => args.validate(&registry),
            },
            Some(CliCommand::Connection { command }) => match command {
                ConnectionCommand::List(args) => args
                    .query_spec(&registry)
                    .map(|_| ())
                    .map_err(CliValidationError::from),
                ConnectionCommand::Kill(args) => args.validate(&registry),
            },
            Some(CliCommand::Process { command }) => match command {
                ProcessCommand::List(args) => args
                    .query_spec(&registry)
                    .map(|_| ())
                    .map_err(CliValidationError::from),
                ProcessCommand::Kill(args) => args.validate(&registry),
            },
        }
    }

    /// Parses and performs pre-I/O validation while preserving clap's error type.
    pub fn try_parse_validated_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let cli = <Self as Parser>::try_parse_from(args)?;
        cli.validate().map_err(|error| error.as_clap_error())?;
        Ok(cli)
    }
}

#[derive(Clone, Debug, Subcommand)]
pub enum CliCommand {
    #[command(
        about = "Управление настроенными подключениями к кластерам",
        help_template = GROUP_HELP_TEMPLATE
    )]
    Cluster {
        #[command(subcommand)]
        command: ClusterCommand,
    },
    #[command(
        about = "Поиск информационных баз",
        help_template = GROUP_HELP_TEMPLATE
    )]
    Infobase {
        #[command(subcommand)]
        command: InfobaseCommand,
    },
    #[command(
        about = "Просмотр и завершение сеансов",
        help_template = GROUP_HELP_TEMPLATE
    )]
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    #[command(
        about = "Просмотр и разрыв соединений",
        help_template = GROUP_HELP_TEMPLATE
    )]
    Connection {
        #[command(subcommand)]
        command: ConnectionCommand,
    },
    #[command(
        about = "Просмотр и выключение рабочих процессов",
        help_template = GROUP_HELP_TEMPLATE
    )]
    Process {
        #[command(subcommand)]
        command: ProcessCommand,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum ClusterCommand {
    #[command(
        about = "Проверить и добавить подключение к кластеру",
        help_template = COMMAND_HELP_TEMPLATE
    )]
    Add(ClusterAddArgs),
    #[command(
        about = "Удалить настроенное подключение к кластеру",
        help_template = COMMAND_HELP_TEMPLATE
    )]
    Remove(ClusterRemoveArgs),
}

#[derive(Clone, Debug, Args)]
pub struct ClusterAddArgs {
    #[arg(long, value_name = "ALIAS", help = "Уникальный alias кластера")]
    pub name: ClusterAlias,

    #[arg(long, value_name = "HOST:PORT", help = "Адрес службы RAS")]
    pub ras: RasEndpoint,

    #[arg(
        long,
        value_enum,
        value_name = "MODE",
        help = "Аутентификация кластера: none или password"
    )]
    pub auth: AuthModeArg,

    #[arg(long, value_name = "USER", help = "Имя администратора кластера")]
    pub user: Option<String>,

    #[arg(
        long,
        visible_alias = "pwd",
        value_name = "PASSWORD",
        value_parser = parse_secret,
        help = "Пароль администратора кластера (хранится в YAML открытым текстом)"
    )]
    pub password: Option<SecretString>,

    #[arg(
        long,
        value_enum,
        value_name = "MODE",
        help = "Общая аутентификация информационных баз: none или password"
    )]
    pub infobase_auth: Option<AuthModeArg>,

    #[arg(
        long,
        value_name = "USER",
        help = "Общее имя администратора информационных баз"
    )]
    pub infobase_user: Option<String>,

    #[arg(
        long,
        value_name = "PASSWORD",
        value_parser = parse_secret,
        help = "Общий пароль информационных баз (хранится в YAML открытым текстом)"
    )]
    pub infobase_password: Option<SecretString>,
}

impl ClusterAddArgs {
    pub fn validate(&self) -> Result<(), CliValidationError> {
        let _ = self.cluster_auth()?;
        let _ = self.infobase_auth()?;
        Ok(())
    }

    pub fn cluster_auth(&self) -> Result<AuthConfig, CliValidationError> {
        match self.auth {
            AuthModeArg::None => {
                reject_present("--user", self.user.is_some(), "none")?;
                reject_present("--password", self.password.is_some(), "none")?;
                Ok(AuthConfig::none())
            }
            AuthModeArg::Password => {
                let user = required("--user", self.user.as_deref(), "password", "кластера")?;
                let password = self
                    .password
                    .clone()
                    .ok_or_else(|| missing_auth_option("--password", "password", "кластера"))?;
                AuthConfig::password(user, password).map_err(CliValidationError::from)
            }
        }
    }

    pub fn infobase_auth(&self) -> Result<AuthConfig, CliValidationError> {
        match self.infobase_auth.unwrap_or(AuthModeArg::None) {
            AuthModeArg::None => {
                reject_present("--infobase-user", self.infobase_user.is_some(), "none")?;
                reject_present(
                    "--infobase-password",
                    self.infobase_password.is_some(),
                    "none",
                )?;
                Ok(AuthConfig::none())
            }
            AuthModeArg::Password => {
                let user = required(
                    "--infobase-user",
                    self.infobase_user.as_deref(),
                    "password",
                    "информационных баз",
                )?;
                let password = self.infobase_password.clone().ok_or_else(|| {
                    missing_auth_option("--infobase-password", "password", "информационных баз")
                })?;
                AuthConfig::password(user, password).map_err(CliValidationError::from)
            }
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct ClusterRemoveArgs {
    #[arg(long, value_name = "ALIAS", help = "Alias удаляемого кластера")]
    pub name: ClusterAlias,

    #[arg(long, action = ArgAction::SetTrue, help = "Не запрашивать подтверждение")]
    pub force: bool,
}

#[derive(Clone, Debug, Subcommand)]
pub enum InfobaseCommand {
    #[command(
        about = "Найти информационные базы по имени или маске",
        help_template = COMMAND_HELP_TEMPLATE
    )]
    Search(InfobaseSearchArgs),
}

#[derive(Clone, Debug, Args)]
pub struct InfobaseSearchArgs {
    #[arg(value_name = "PATTERN", help = "Имя или SQL-подобная маска имени базы")]
    pub pattern: String,

    #[arg(long, value_name = "PATTERN", help = "Alias или маска alias кластера")]
    pub cluster: Option<String>,

    #[arg(
        long,
        value_name = "FIELDS",
        help = "Канонические поля через запятую или *"
    )]
    pub columns: Option<String>,
}

impl InfobaseSearchArgs {
    pub fn query_spec(&self, registry: &FieldRegistry) -> Result<QuerySpec, DomainError> {
        let mut spec = QuerySpec::parse(
            RecordKind::Infobase,
            std::iter::empty::<&str>(),
            Some(&self.pattern),
            std::iter::empty::<&str>(),
            None,
            self.columns.as_deref(),
            registry,
        )?;
        push_mask(
            &mut spec,
            RecordKind::Infobase,
            "cluster",
            self.cluster.as_deref(),
            registry,
        )?;
        Ok(spec)
    }
}

#[derive(Clone, Debug, Subcommand)]
pub enum SessionCommand {
    #[command(
        about = "Получить список сеансов",
        help_template = COMMAND_HELP_TEMPLATE
    )]
    List(SessionListArgs),
    #[command(
        about = "Принудительно завершить выбранные сеансы",
        help_template = COMMAND_HELP_TEMPLATE
    )]
    Kill(SessionKillArgs),
}

#[derive(Clone, Debug, Args)]
pub struct SessionSelectors {
    #[arg(long, value_name = "PATTERN", help = "Alias или маска alias кластера")]
    pub cluster: Option<String>,
    #[arg(
        long,
        value_name = "PATTERN",
        help = "Имя или маска информационной базы"
    )]
    pub infobase: Option<String>,
    #[arg(long, value_name = "PATTERN", help = "Маска user_name или host")]
    pub query: Option<String>,
    #[arg(long, value_name = "UUID", help = "UUID сеанса")]
    pub id: Option<SessionUuid>,
    #[arg(long, value_name = "NUMBER", help = "Номер сеанса")]
    pub number: Option<i64>,
    #[arg(long, value_name = "PATTERN", help = "Имя или маска пользователя")]
    pub user: Option<String>,
    #[arg(long, value_name = "PATTERN", help = "Имя или маска хоста")]
    pub host: Option<String>,
    #[arg(long, value_name = "PATTERN", help = "app_id или его маска")]
    pub app: Option<String>,
}

impl SessionSelectors {
    /// `--cluster` deliberately does not count as a destructive selector.
    #[must_use]
    pub fn has_selector(&self) -> bool {
        self.infobase.is_some()
            || self.query.is_some()
            || self.id.is_some()
            || self.number.is_some()
            || self.user.is_some()
            || self.host.is_some()
            || self.app.is_some()
    }

    fn apply(&self, spec: &mut QuerySpec, registry: &FieldRegistry) -> Result<(), DomainError> {
        push_mask(
            spec,
            RecordKind::Session,
            "cluster",
            self.cluster.as_deref(),
            registry,
        )?;
        push_mask(
            spec,
            RecordKind::Session,
            "infobase",
            self.infobase.as_deref(),
            registry,
        )?;
        push_scalar(
            spec,
            RecordKind::Session,
            "session",
            self.id.map(|value| FieldValue::Uuid(value.into_uuid())),
            registry,
        )?;
        push_scalar(
            spec,
            RecordKind::Session,
            "session_id",
            self.number.map(FieldValue::Int),
            registry,
        )?;
        push_mask(
            spec,
            RecordKind::Session,
            "user_name",
            self.user.as_deref(),
            registry,
        )?;
        push_mask(
            spec,
            RecordKind::Session,
            "host",
            self.host.as_deref(),
            registry,
        )?;
        push_mask(
            spec,
            RecordKind::Session,
            "app_id",
            self.app.as_deref(),
            registry,
        )
    }
}

#[derive(Clone, Debug, Args)]
pub struct QueryOptions {
    #[arg(
        long,
        value_name = "FIELD:OPERATOR:VALUE",
        action = ArgAction::Append,
        help = "Типизированный фильтр; параметр можно повторять"
    )]
    pub filter: Vec<String>,

    #[arg(
        long,
        value_name = "FIELD:DIRECTION",
        action = ArgAction::Append,
        help = "Сортировка field:asc|desc; параметр можно повторять"
    )]
    pub sort: Vec<String>,

    #[arg(
        long,
        value_name = "N",
        value_parser = parse_top,
        help = "Вернуть первые N строк после глобальной сортировки"
    )]
    pub top: Option<NonZeroUsize>,

    #[arg(
        long,
        value_name = "FIELDS",
        help = "Канонические поля через запятую или *"
    )]
    pub columns: Option<String>,
}

impl QueryOptions {
    fn query_spec(
        &self,
        kind: RecordKind,
        query: Option<&str>,
        registry: &FieldRegistry,
    ) -> Result<QuerySpec, DomainError> {
        let top = self.top.map(|value| value.get().to_string());
        QuerySpec::parse(
            kind,
            self.filter.iter().map(String::as_str),
            query,
            self.sort.iter().map(String::as_str),
            top.as_deref(),
            self.columns.as_deref(),
            registry,
        )
    }
}

#[derive(Clone, Debug, Args)]
pub struct SessionListArgs {
    #[command(flatten)]
    pub selectors: SessionSelectors,
    #[command(flatten)]
    pub query: QueryOptions,
}

impl SessionListArgs {
    pub fn query_spec(&self, registry: &FieldRegistry) -> Result<QuerySpec, DomainError> {
        let mut spec = self.query.query_spec(
            RecordKind::Session,
            self.selectors.query.as_deref(),
            registry,
        )?;
        self.selectors.apply(&mut spec, registry)?;
        Ok(spec)
    }
}

#[derive(Clone, Debug, Args)]
pub struct SessionKillArgs {
    #[command(flatten)]
    pub selectors: SessionSelectors,
    #[command(flatten)]
    pub query: QueryOptions,

    #[arg(long, value_name = "TEXT", help = "Сообщение завершенному сеансу")]
    pub message: Option<String>,

    #[arg(long, action = ArgAction::SetTrue, help = "Не запрашивать подтверждение")]
    pub force: bool,
}

impl SessionKillArgs {
    #[must_use]
    pub fn has_selector(&self) -> bool {
        self.selectors.has_selector() || !self.query.filter.is_empty()
    }

    pub fn query_spec(&self, registry: &FieldRegistry) -> Result<QuerySpec, DomainError> {
        let list = SessionListArgs {
            selectors: self.selectors.clone(),
            query: self.query.clone(),
        };
        list.query_spec(registry)
    }

    pub fn validate(&self, registry: &FieldRegistry) -> Result<(), CliValidationError> {
        if !self.has_selector() {
            return Err(CliValidationError::new(
                "selector_required",
                "Для завершения сеансов требуется хотя бы один предметный селектор; одного `--cluster` недостаточно",
            ));
        }
        self.query_spec(registry)
            .map(|_| ())
            .map_err(CliValidationError::from)
    }
}

#[derive(Clone, Debug, Subcommand)]
pub enum ConnectionCommand {
    #[command(
        about = "Получить список соединений",
        help_template = COMMAND_HELP_TEMPLATE
    )]
    List(ConnectionListArgs),
    #[command(
        about = "Разорвать выбранные соединения",
        help_template = COMMAND_HELP_TEMPLATE
    )]
    Kill(ConnectionKillArgs),
}

#[derive(Clone, Debug, Args)]
pub struct ConnectionSelectors {
    #[arg(long, value_name = "PATTERN", help = "Alias или маска alias кластера")]
    pub cluster: Option<String>,
    #[arg(
        long,
        value_name = "PATTERN",
        help = "Имя или маска информационной базы"
    )]
    pub infobase: Option<String>,
    #[arg(long, value_name = "PATTERN", help = "Маска host или application")]
    pub query: Option<String>,
    #[arg(long, value_name = "UUID", help = "UUID соединения")]
    pub id: Option<ConnectionUuid>,
    #[arg(long, value_name = "NUMBER", help = "Числовой conn_id")]
    pub number: Option<i64>,
    #[arg(long, value_name = "PATTERN", help = "Имя или маска хоста")]
    pub host: Option<String>,
    #[arg(long, value_name = "PATTERN", help = "Имя или маска приложения")]
    pub application: Option<String>,
    #[arg(long, value_name = "UUID", help = "UUID рабочего процесса")]
    pub process: Option<ProcessUuid>,
}

impl ConnectionSelectors {
    /// `--cluster` deliberately does not count as a destructive selector.
    #[must_use]
    pub fn has_selector(&self) -> bool {
        self.infobase.is_some()
            || self.query.is_some()
            || self.id.is_some()
            || self.number.is_some()
            || self.host.is_some()
            || self.application.is_some()
            || self.process.is_some()
    }

    fn apply(&self, spec: &mut QuerySpec, registry: &FieldRegistry) -> Result<(), DomainError> {
        push_mask(
            spec,
            RecordKind::Connection,
            "cluster",
            self.cluster.as_deref(),
            registry,
        )?;
        push_mask(
            spec,
            RecordKind::Connection,
            "infobase",
            self.infobase.as_deref(),
            registry,
        )?;
        push_scalar(
            spec,
            RecordKind::Connection,
            "connection",
            self.id.map(|value| FieldValue::Uuid(value.into_uuid())),
            registry,
        )?;
        push_scalar(
            spec,
            RecordKind::Connection,
            "conn_id",
            self.number.map(FieldValue::Int),
            registry,
        )?;
        push_mask(
            spec,
            RecordKind::Connection,
            "host",
            self.host.as_deref(),
            registry,
        )?;
        push_mask(
            spec,
            RecordKind::Connection,
            "application",
            self.application.as_deref(),
            registry,
        )?;
        push_scalar(
            spec,
            RecordKind::Connection,
            "process",
            self.process
                .map(|value| FieldValue::Uuid(value.into_uuid())),
            registry,
        )
    }
}

#[derive(Clone, Debug, Args)]
pub struct ConnectionListArgs {
    #[command(flatten)]
    pub selectors: ConnectionSelectors,
    #[command(flatten)]
    pub query: QueryOptions,
}

impl ConnectionListArgs {
    pub fn query_spec(&self, registry: &FieldRegistry) -> Result<QuerySpec, DomainError> {
        let mut spec = self.query.query_spec(
            RecordKind::Connection,
            self.selectors.query.as_deref(),
            registry,
        )?;
        self.selectors.apply(&mut spec, registry)?;
        Ok(spec)
    }
}

#[derive(Clone, Debug, Args)]
pub struct ConnectionKillArgs {
    #[command(flatten)]
    pub selectors: ConnectionSelectors,
    #[command(flatten)]
    pub query: QueryOptions,

    #[arg(long, action = ArgAction::SetTrue, help = "Не запрашивать подтверждение")]
    pub force: bool,
}

impl ConnectionKillArgs {
    #[must_use]
    pub fn has_selector(&self) -> bool {
        self.selectors.has_selector() || !self.query.filter.is_empty()
    }

    pub fn query_spec(&self, registry: &FieldRegistry) -> Result<QuerySpec, DomainError> {
        let list = ConnectionListArgs {
            selectors: self.selectors.clone(),
            query: self.query.clone(),
        };
        list.query_spec(registry)
    }

    pub fn validate(&self, registry: &FieldRegistry) -> Result<(), CliValidationError> {
        if !self.has_selector() {
            return Err(CliValidationError::new(
                "selector_required",
                "Для разрыва соединений требуется хотя бы один предметный селектор; одного `--cluster` недостаточно",
            ));
        }
        self.query_spec(registry)
            .map(|_| ())
            .map_err(CliValidationError::from)
    }
}

#[derive(Clone, Debug, Subcommand)]
pub enum ProcessCommand {
    #[command(
        about = "Получить список рабочих процессов",
        help_template = COMMAND_HELP_TEMPLATE
    )]
    List(ProcessListArgs),
    #[command(
        about = "Выключить выбранные рабочие процессы",
        help_template = COMMAND_HELP_TEMPLATE
    )]
    Kill(ProcessKillArgs),
}

#[derive(Clone, Debug, Args)]
pub struct ProcessSelectors {
    #[arg(long, value_name = "PATTERN", help = "Alias или маска alias кластера")]
    pub cluster: Option<String>,
    #[arg(long, value_name = "UUID", help = "UUID рабочего процесса")]
    pub id: Option<ProcessUuid>,
    #[arg(long, value_name = "NUMBER", help = "Идентификатор процесса (pid)")]
    pub pid: Option<i64>,
    #[arg(long, value_name = "UUID", help = "UUID рабочего сервера")]
    pub server: Option<Uuid>,
}

impl ProcessSelectors {
    #[must_use]
    pub fn has_selector(&self) -> bool {
        self.id.is_some() || self.pid.is_some() || self.server.is_some()
    }

    fn apply(&self, spec: &mut QuerySpec, registry: &FieldRegistry) -> Result<(), DomainError> {
        push_mask(
            spec,
            RecordKind::Process,
            "cluster",
            self.cluster.as_deref(),
            registry,
        )?;
        push_scalar(
            spec,
            RecordKind::Process,
            "process",
            self.id.map(|value| FieldValue::Uuid(value.into_uuid())),
            registry,
        )?;
        push_scalar(
            spec,
            RecordKind::Process,
            "pid",
            self.pid.map(FieldValue::Int),
            registry,
        )?;
        push_scalar(
            spec,
            RecordKind::Process,
            "server",
            self.server.map(FieldValue::Uuid),
            registry,
        )
    }
}

#[derive(Clone, Debug, Args)]
pub struct ProcessListArgs {
    #[command(flatten)]
    pub selectors: ProcessSelectors,
    #[command(flatten)]
    pub query: QueryOptions,
}

impl ProcessListArgs {
    pub fn query_spec(&self, registry: &FieldRegistry) -> Result<QuerySpec, DomainError> {
        let mut spec = self.query.query_spec(RecordKind::Process, None, registry)?;
        self.selectors.apply(&mut spec, registry)?;
        Ok(spec)
    }
}

#[derive(Clone, Debug, Args)]
pub struct ProcessKillArgs {
    #[command(flatten)]
    pub selectors: ProcessSelectors,
    #[command(flatten)]
    pub query: QueryOptions,

    #[arg(long, action = ArgAction::SetTrue, help = "Не запрашивать подтверждение")]
    pub force: bool,
}

impl ProcessKillArgs {
    #[must_use]
    pub fn has_selector(&self) -> bool {
        self.selectors.has_selector() || !self.query.filter.is_empty()
    }

    pub fn query_spec(&self, registry: &FieldRegistry) -> Result<QuerySpec, DomainError> {
        let list = ProcessListArgs {
            selectors: self.selectors.clone(),
            query: self.query.clone(),
        };
        list.query_spec(registry)
    }

    pub fn validate(&self, registry: &FieldRegistry) -> Result<(), CliValidationError> {
        if !self.has_selector() {
            return Err(CliValidationError::new(
                "selector_required",
                "Для выключения процессов требуется хотя бы один предметный селектор; одного `--cluster` недостаточно",
            ));
        }
        self.query_spec(registry)
            .map(|_| ())
            .map_err(CliValidationError::from)
    }
}

/// A safe, secret-free error produced by pre-I/O CLI validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliValidationError {
    code: &'static str,
    message: String,
}

impl CliValidationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn as_clap_error(&self) -> clap::Error {
        let mut command = Cli::command();
        command.error(ErrorKind::ValueValidation, self.to_string())
    }
}

impl fmt::Display for CliValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CliValidationError {}

impl From<DomainError> for CliValidationError {
    fn from(error: DomainError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

/// Renders clap diagnostics with Russian fixed labels while retaining its usage context.
#[must_use]
pub fn render_parse_error(error: &clap::Error) -> String {
    error
        .to_string()
        .replace("error:", "ошибка:")
        .replace("Usage:", "Использование:")
        .replace("unexpected argument", "неожиданный аргумент")
        .replace(
            "the following required arguments were not provided:",
            "не указаны обязательные аргументы:",
        )
        .replace("invalid value", "некорректное значение")
        .replace("unrecognized subcommand", "неизвестная команда")
        .replace(
            "For more information, try '--help'.",
            "Для дополнительной информации используйте '--help'.",
        )
}

fn required<'a>(
    option: &str,
    value: Option<&'a str>,
    mode: &str,
    scope: &str,
) -> Result<&'a str, CliValidationError> {
    value.ok_or_else(|| missing_auth_option(option, mode, scope))
}

fn missing_auth_option(option: &str, mode: &str, scope: &str) -> CliValidationError {
    CliValidationError::new(
        "invalid_auth",
        format!("Для {mode}-аутентификации {scope} требуется `{option}`"),
    )
}

fn reject_present(option: &str, present: bool, mode: &str) -> Result<(), CliValidationError> {
    if present {
        Err(CliValidationError::new(
            "invalid_auth",
            format!("Параметр `{option}` недопустим при режиме аутентификации `{mode}`"),
        ))
    } else {
        Ok(())
    }
}

fn push_mask(
    spec: &mut QuerySpec,
    kind: RecordKind,
    field: &str,
    value: Option<&str>,
    registry: &FieldRegistry,
) -> Result<(), DomainError> {
    if let Some(value) = value {
        spec.push_filter(Filter::from_value(
            kind,
            field,
            FilterOperator::Like,
            FieldValue::Str(value.to_owned()),
            registry,
        )?)?;
    }
    Ok(())
}

fn push_scalar(
    spec: &mut QuerySpec,
    kind: RecordKind,
    field: &str,
    value: Option<FieldValue>,
    registry: &FieldRegistry,
) -> Result<(), DomainError> {
    if let Some(value) = value {
        spec.push_filter(Filter::from_value(
            kind,
            field,
            FilterOperator::Eq,
            value,
            registry,
        )?)?;
    }
    Ok(())
}

fn parse_secret(value: &str) -> Result<SecretString, String> {
    Ok(SecretString::new(value))
}

fn parse_timeout(value: &str) -> Result<NonZeroU64, String> {
    value
        .parse::<u64>()
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or_else(|| "ожидается положительное целое число секунд".to_owned())
}

fn parse_top(value: &str) -> Result<NonZeroUsize, String> {
    value
        .parse::<usize>()
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| "ожидается положительное целое число".to_owned())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    const SESSION_UUID: &str = "00000000-0000-0000-0000-000000000001";
    const PROCESS_UUID: &str = "00000000-0000-0000-0000-000000000002";

    #[test]
    fn no_subcommand_selects_tui_and_root_options_are_typed() {
        let cli = Cli::try_parse_from([
            "onecadmin",
            "--config",
            "custom.yaml",
            "--rac-path",
            "rac.exe",
            "--timeout",
            "15",
            "--format",
            "json",
            "--no-color",
        ])
        .unwrap_or_else(|error| panic!("{error}"));

        assert!(cli.is_tui_mode());
        assert_eq!(cli.timeout.map(NonZeroU64::get), Some(15));
        assert_eq!(cli.format, OutputFormat::Json);
        assert!(cli.no_color);
    }

    #[test]
    fn cluster_add_accepts_pwd_alias_and_validates_conditionally() {
        let cli = Cli::try_parse_validated_from([
            "onecadmin",
            "cluster",
            "add",
            "--name",
            "dev",
            "--ras",
            "RV-DEV-1C01:1545",
            "--auth",
            "password",
            "--user",
            "administrator",
            "--pwd",
            "secret",
            "--infobase-auth",
            "password",
            "--infobase-user",
            "ib-admin",
            "--infobase-password",
            "ib-secret",
        ])
        .unwrap_or_else(|error| panic!("{error}"));

        let Some(CliCommand::Cluster {
            command: ClusterCommand::Add(args),
        }) = cli.command
        else {
            panic!("ожидалась команда cluster add");
        };
        assert_eq!(args.name.as_str(), "dev");
        assert_eq!(
            args.password.as_ref().map(SecretString::expose_secret),
            Some("secret")
        );
    }

    #[test]
    fn auth_requirements_are_checked_by_validate_not_clap_relations() {
        let cli = Cli::try_parse_from([
            "onecadmin",
            "cluster",
            "add",
            "--name",
            "dev",
            "--ras",
            "host:1545",
            "--auth",
            "password",
        ])
        .unwrap_or_else(|error| panic!("{error}"));

        let error = cli.validate().expect_err("password credentials must fail");
        assert_eq!(error.code(), "invalid_auth");
        assert!(error.to_string().contains("--user"));
    }

    #[test]
    fn infobase_search_contract_has_positional_pattern_and_cluster_scope() {
        let cli = Cli::try_parse_validated_from([
            "onecadmin",
            "infobase",
            "search",
            "zup_%",
            "--cluster",
            "prod%",
            "--columns",
            "cluster,infobase",
            "--format",
            "csv",
        ])
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(cli.format, OutputFormat::Csv);
        let Some(CliCommand::Infobase {
            command: InfobaseCommand::Search(args),
        }) = cli.command
        else {
            panic!("ожидалась команда infobase search");
        };
        assert_eq!(args.pattern, "zup_%");
        assert_eq!(args.cluster.as_deref(), Some("prod%"));
    }

    #[test]
    fn session_list_accepts_all_query_controls_and_inherited_format() {
        let cli = Cli::try_parse_validated_from([
            "onecadmin",
            "session",
            "list",
            "--id",
            SESSION_UUID,
            "--number",
            "12",
            "--infobase",
            "zup%",
            "--query",
            r"DOMAIN\\user",
            "--user",
            "admin%",
            "--host",
            "PC-%",
            "--app",
            "1CV8%",
            "--filter",
            "cpu_time_total:gt:1",
            "--filter",
            "memory_current:ge:2",
            "--sort",
            "cpu_time_total:desc",
            "--sort",
            "started_at:asc",
            "--top",
            "10",
            "--columns",
            "cluster,session_id,cpu_time_total",
            "--format",
            "json",
        ])
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(cli.format, OutputFormat::Json);
        let Some(CliCommand::Session {
            command: SessionCommand::List(args),
        }) = cli.command
        else {
            panic!("ожидалась команда session list");
        };
        assert_eq!(args.query.filter.len(), 2);
        assert_eq!(args.query.sort.len(), 2);
        assert_eq!(args.query.top.map(NonZeroUsize::get), Some(10));
    }

    #[test]
    fn destructive_selector_guard_excludes_cluster_but_includes_filter() {
        let cluster_only = Cli::try_parse_from([
            "onecadmin",
            "session",
            "kill",
            "--cluster",
            "dev",
            "--force",
        ])
        .unwrap_or_else(|error| panic!("{error}"));
        let Some(CliCommand::Session {
            command: SessionCommand::Kill(args),
        }) = &cluster_only.command
        else {
            panic!("ожидалась команда session kill");
        };
        assert!(!args.has_selector());
        assert_eq!(
            cluster_only.validate().map_err(|error| error.code()),
            Err("selector_required")
        );

        let filtered = Cli::try_parse_validated_from([
            "onecadmin",
            "session",
            "kill",
            "--cluster",
            "dev",
            "--filter",
            "user_name:eq:test",
            "--message",
            "Завершено администратором",
            "--force",
        ])
        .unwrap_or_else(|error| panic!("{error}"));
        let Some(CliCommand::Session {
            command: SessionCommand::Kill(args),
        }) = filtered.command
        else {
            panic!("ожидалась команда session kill");
        };
        assert!(args.has_selector());
    }

    #[test]
    fn connection_kill_has_all_selectors_and_same_guard() {
        let cli = Cli::try_parse_validated_from([
            "onecadmin",
            "connection",
            "kill",
            "--id",
            SESSION_UUID,
            "--number",
            "154",
            "--host",
            "APP-%",
            "--application",
            "1CV8%",
            "--process",
            PROCESS_UUID,
            "--sort",
            "connected_at:desc",
            "--top",
            "3",
            "--columns",
            "cluster,connection,process",
            "--force",
        ])
        .unwrap_or_else(|error| panic!("{error}"));

        let Some(CliCommand::Connection {
            command: ConnectionCommand::Kill(args),
        }) = cli.command
        else {
            panic!("ожидалась команда connection kill");
        };
        assert!(args.has_selector());
        assert_eq!(args.selectors.number, Some(154));
        assert!(args.selectors.process.is_some());
    }

    #[test]
    fn invalid_columns_fail_before_io_and_error_can_be_rendered_in_russian() {
        let error = Cli::try_parse_validated_from([
            "onecadmin",
            "session",
            "list",
            "--columns",
            "cpu_time",
        ])
        .expect_err("unknown column must fail");
        let rendered = render_parse_error(&error);

        assert!(rendered.contains("ошибка:"));
        assert!(rendered.contains("Неизвестное каноническое поле"));
        assert!(rendered.contains("Использование:"));
    }

    #[test]
    fn version_is_handled_by_clap_without_selecting_a_runtime_mode() {
        let error = Cli::try_parse_from(["onecadmin", "--version"])
            .expect_err("version must be rendered as an early clap response");

        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
        assert!(error.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn nested_help_keeps_russian_descriptions() {
        let error = Cli::try_parse_from(["onecadmin", "session", "list", "--help"])
            .expect_err("help must be rendered as an early clap response");
        let help = error.to_string();

        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        assert!(help.contains("Получить список сеансов"));
        assert!(help.contains("Канонические поля"));
        assert!(help.contains("Использование:"));
    }
}
