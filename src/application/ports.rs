use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::infrastructure::config::{
    ClusterConfig, Config, ConfigError, ConfigStore, InfobaseAuthOverride, OverrideSelector,
};
use crate::infrastructure::rac::{
    RacCandidate, RacCredentials, RacError, RacGateway, RacRecord, SearchPolicy,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortErrorKind {
    Configuration,
    Conflict,
    NotFound,
    Internal,
}

impl PortErrorKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Configuration => "configuration_error",
            Self::Conflict => "conflict",
            Self::NotFound => "not_found",
            Self::Internal => "internal_port_error",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortError {
    pub kind: PortErrorKind,
    pub code: &'static str,
    pub message: String,
}

impl PortError {
    #[must_use]
    pub fn new(kind: PortErrorKind, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for PortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PortError {}

/// Raw, typed infrastructure configuration returned across the application port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawConfigSnapshot {
    pub path: std::path::PathBuf,
    pub config: Config,
}

#[async_trait]
pub trait ConfigRepository: Send + Sync {
    async fn load(&self) -> Result<RawConfigSnapshot, PortError>;

    async fn add_cluster(
        &self,
        alias: String,
        cluster: ClusterConfig,
    ) -> Result<RawConfigSnapshot, PortError>;

    async fn remove_cluster(&self, alias: String) -> Result<RawConfigSnapshot, PortError>;

    async fn add_override(
        &self,
        cluster_alias: String,
        entry: InfobaseAuthOverride,
    ) -> Result<RawConfigSnapshot, PortError>;

    async fn remove_override(
        &self,
        cluster_alias: String,
        selector: OverrideSelector,
    ) -> Result<RawConfigSnapshot, PortError>;
}

#[derive(Clone)]
pub struct ConfigStoreAdapter {
    store: Arc<ConfigStore>,
}

impl ConfigStoreAdapter {
    #[must_use]
    pub fn new(store: ConfigStore) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    #[must_use]
    pub fn from_shared(store: Arc<ConfigStore>) -> Self {
        Self { store }
    }

    #[must_use]
    pub fn store(&self) -> &Arc<ConfigStore> {
        &self.store
    }
}

impl fmt::Debug for ConfigStoreAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigStoreAdapter")
            .field("store", &self.store)
            .finish()
    }
}

#[async_trait]
impl ConfigRepository for ConfigStoreAdapter {
    async fn load(&self) -> Result<RawConfigSnapshot, PortError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.load())
            .await
            .map_err(join_error)?
            .map(snapshot_from_config)
            .map_err(config_error)
    }

    async fn add_cluster(
        &self,
        alias: String,
        cluster: ClusterConfig,
    ) -> Result<RawConfigSnapshot, PortError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.add_cluster(alias, cluster))
            .await
            .map_err(join_error)?
            .map(|outcome| snapshot_from_config(outcome.snapshot))
            .map_err(config_error)
    }

    async fn remove_cluster(&self, alias: String) -> Result<RawConfigSnapshot, PortError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.remove_cluster(&alias))
            .await
            .map_err(join_error)?
            .map(|outcome| snapshot_from_config(outcome.snapshot))
            .map_err(config_error)
    }

    async fn add_override(
        &self,
        cluster_alias: String,
        entry: InfobaseAuthOverride,
    ) -> Result<RawConfigSnapshot, PortError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.add_override(&cluster_alias, entry))
            .await
            .map_err(join_error)?
            .map(|outcome| snapshot_from_config(outcome.snapshot))
            .map_err(config_error)
    }

    async fn remove_override(
        &self,
        cluster_alias: String,
        selector: OverrideSelector,
    ) -> Result<RawConfigSnapshot, PortError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.remove_override(&cluster_alias, selector))
            .await
            .map_err(join_error)?
            .map(|outcome| snapshot_from_config(outcome.snapshot))
            .map_err(config_error)
    }
}

fn snapshot_from_config(
    snapshot: crate::infrastructure::config::ConfigSnapshot,
) -> RawConfigSnapshot {
    RawConfigSnapshot {
        path: snapshot.path().to_path_buf(),
        config: snapshot.into_config(),
    }
}

fn join_error(error: tokio::task::JoinError) -> PortError {
    PortError::new(
        PortErrorKind::Internal,
        "blocking_task_failed",
        format!("Внутренняя задача ввода-вывода завершилась ошибкой: {error}"),
    )
}

fn config_error(error: ConfigError) -> PortError {
    let (kind, code, prefix) = match &error {
        ConfigError::ClusterAlreadyExists { .. } => (
            PortErrorKind::Conflict,
            "cluster_already_exists",
            "Подключение с таким alias уже существует",
        ),
        ConfigError::ClusterNotFound { .. } => (
            PortErrorKind::NotFound,
            "cluster_not_found",
            "Подключение к кластеру не найдено",
        ),
        ConfigError::OverrideNotFound { .. } => (
            PortErrorKind::NotFound,
            "credential_override_not_found",
            "Переопределение учетных данных не найдено",
        ),
        ConfigError::NotFound { .. } => (
            PortErrorKind::Configuration,
            "config_not_found",
            "Файл конфигурации не найден",
        ),
        ConfigError::Validation(_) | ConfigError::Yaml { .. } => (
            PortErrorKind::Configuration,
            "invalid_config",
            "Файл конфигурации не прошел проверку",
        ),
        _ => (
            PortErrorKind::Configuration,
            "config_io_failed",
            "Не удалось прочитать или атомарно изменить конфигурацию",
        ),
    };
    PortError::new(kind, code, format!("{prefix}: {error}"))
}

#[async_trait]
pub trait RacPort: Send + Sync {
    async fn cluster_list(
        &self,
        ras_address: &str,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError>;

    async fn cluster_info(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError>;

    async fn infobase_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError>;

    async fn session_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError>;

    #[allow(clippy::too_many_arguments)]
    async fn session_terminate(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        session_id: Uuid,
        message: Option<&str>,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError>;

    async fn connection_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError>;

    #[allow(clippy::too_many_arguments)]
    async fn connection_disconnect(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        process_id: Uuid,
        connection_id: Uuid,
        cluster_credentials: &RacCredentials,
        infobase_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError>;

    async fn chosen_candidate(&self, ras_address: &str) -> Option<RacCandidate>;
}

#[async_trait]
impl RacPort for RacGateway {
    async fn cluster_list(
        &self,
        ras_address: &str,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        RacGateway::cluster_list(self, ras_address, search_policy, cancellation).await
    }

    async fn cluster_info(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        RacGateway::cluster_info(
            self,
            ras_address,
            cluster_id,
            cluster_credentials,
            search_policy,
            cancellation,
        )
        .await
    }

    async fn infobase_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        RacGateway::infobase_list(
            self,
            ras_address,
            cluster_id,
            cluster_credentials,
            search_policy,
            cancellation,
        )
        .await
    }

    async fn session_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        RacGateway::session_list(
            self,
            ras_address,
            cluster_id,
            cluster_credentials,
            search_policy,
            cancellation,
        )
        .await
    }

    async fn session_terminate(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        session_id: Uuid,
        message: Option<&str>,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        RacGateway::session_terminate(
            self,
            ras_address,
            cluster_id,
            session_id,
            message,
            cluster_credentials,
            search_policy,
            cancellation,
        )
        .await
    }

    async fn connection_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        RacGateway::connection_list(
            self,
            ras_address,
            cluster_id,
            cluster_credentials,
            search_policy,
            cancellation,
        )
        .await
    }

    async fn connection_disconnect(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        process_id: Uuid,
        connection_id: Uuid,
        cluster_credentials: &RacCredentials,
        infobase_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        RacGateway::connection_disconnect(
            self,
            ras_address,
            cluster_id,
            process_id,
            connection_id,
            cluster_credentials,
            infobase_credentials,
            search_policy,
            cancellation,
        )
        .await
    }

    async fn chosen_candidate(&self, ras_address: &str) -> Option<RacCandidate> {
        RacGateway::chosen_candidate(self, ras_address).await
    }
}
