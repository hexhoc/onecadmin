use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Duration;

use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

use crate::application::{AppExitCode, AppServices, RacOptions};
use crate::cli::{Cli, dispatch};
use crate::infrastructure::config::{
    AuthConfig as ConfigAuth, Config, ConfigError, ConfigStore, InfobaseAuthOverride,
};
use crate::infrastructure::rac::RacGateway;
use crate::infrastructure::telemetry::{SecretRedactor, init_logging_with_redactor};
use crate::infrastructure::windows::WindowsPaths;
use crate::tui::{TuiOptions, run as run_tui};

pub fn main_entry() -> ExitCode {
    let cli = match Cli::try_parse_validated_from(std::env::args_os()) {
        Ok(cli) => cli,
        Err(error) => {
            let exit_code =
                u8::try_from(error.exit_code()).unwrap_or(AppExitCode::InvalidInput.value());
            let _ = error.print();
            return ExitCode::from(exit_code);
        }
    };

    let runtime = match Builder::new_multi_thread()
        .enable_all()
        .thread_name("onecadmin-runtime")
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            write_stderr(format!("Не удалось создать async runtime: {error}\n").as_bytes());
            return AppExitCode::Internal.into();
        }
    };

    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> ExitCode {
    let paths = match WindowsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            write_stderr(
                format!("Не удалось определить пользовательские пути: {error}\n").as_bytes(),
            );
            return AppExitCode::InvalidInput.into();
        }
    };
    let config_path = match crate::infrastructure::config::resolve_config_path(cli.config.clone()) {
        Ok(path) => path,
        Err(error) => {
            write_stderr(format!("Не удалось определить путь конфигурации: {error}\n").as_bytes());
            return AppExitCode::InvalidInput.into();
        }
    };

    let store = match ConfigStore::new(config_path) {
        Ok(store) => store,
        Err(error) => {
            write_config_error(&error);
            return AppExitCode::InvalidInput.into();
        }
    };

    let config = match load_or_create_config(&store) {
        Ok(config) => config,
        Err(error) => {
            write_config_error(&error);
            return AppExitCode::InvalidInput.into();
        }
    };

    let redactor = redactor_from_config(&config);
    let log_filter = config.settings.log_level.as_str().to_ascii_lowercase();
    let _logging_guard =
        match init_logging_with_redactor(paths.logs_directory(), &log_filter, redactor) {
            Ok(guard) => guard,
            Err(error) => {
                write_stderr(
                    format!("Не удалось инициализировать технический лог: {error}\n").as_bytes(),
                );
                return AppExitCode::Internal.into();
            }
        };

    let timeout = cli
        .timeout
        .map(|value| Duration::from_secs(value.get()))
        .unwrap_or_else(|| Duration::from_secs(config.settings.timeout_seconds));
    let services = AppServices::from_infrastructure(store, RacGateway::new(timeout));

    let cancellation = CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancellation.cancel();
        }
    });

    let result = if cli.is_tui_mode() {
        let options = TuiOptions::new().with_rac_options(RacOptions {
            explicit_path: cli.rac_path.clone(),
        });
        match run_tui(&services, options, &cancellation).await {
            Ok(()) if cancellation.is_cancelled() => AppExitCode::Interrupted.into(),
            Ok(()) => AppExitCode::Success.into(),
            Err(error) => {
                write_stderr(format!("TUI завершился с ошибкой: {error}\n").as_bytes());
                AppExitCode::Internal.into()
            }
        }
    } else {
        let command_result = dispatch(&cli, &services, &cancellation).await;
        write_stdout(&command_result.stdout);
        write_stderr(&command_result.stderr);
        command_result.exit_code.into()
    };

    signal_task.abort();
    let _ = signal_task.await;
    result
}

fn load_or_create_config(store: &ConfigStore) -> Result<Config, ConfigError> {
    match store.load() {
        Ok(snapshot) => Ok(snapshot.into_config()),
        Err(ConfigError::NotFound { .. }) => store
            .create_default()
            .map(|outcome| outcome.snapshot.into_config()),
        Err(error) => Err(error),
    }
}

fn redactor_from_config(config: &Config) -> SecretRedactor {
    let redactor = SecretRedactor::new();
    for cluster in config.clusters.values() {
        register_auth_secret(&redactor, &cluster.cluster_auth);
        register_auth_secret(&redactor, &cluster.infobase_auth.default);
        for entry in &cluster.infobase_auth.overrides {
            if let InfobaseAuthOverride::Password(password) = entry {
                redactor.register_secret(password.password.expose_secret());
            }
        }
    }
    redactor
}

fn register_auth_secret(redactor: &SecretRedactor, auth: &ConfigAuth) {
    if let ConfigAuth::Password(password) = auth {
        redactor.register_secret(password.password.expose_secret());
    }
}

fn write_config_error(error: &ConfigError) {
    write_stderr(format!("Ошибка конфигурации: {error}\n").as_bytes());
}

fn write_stdout(bytes: &[u8]) {
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(bytes);
    let _ = stdout.flush();
}

fn write_stderr(bytes: &[u8]) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(bytes);
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::config::{
        ClusterConfig, DiscoveredCluster, InfobaseAuthConfig, Password, RacConfig, RasConfig,
        Settings,
    };
    use indexmap::IndexMap;
    use std::fs;
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn every_configured_password_is_registered_before_logging() {
        let mut clusters = IndexMap::new();
        clusters.insert(
            "dev".to_owned(),
            ClusterConfig {
                ras: RasConfig {
                    host: "ras.local".to_owned(),
                    port: 1545,
                },
                discovered_cluster: DiscoveredCluster {
                    uuid: Uuid::from_u128(1),
                    name: "cluster".to_owned(),
                    host: "cluster.local".to_owned(),
                    port: 1541,
                },
                rac: RacConfig::default(),
                cluster_auth: ConfigAuth::password("admin", Password::new("cluster-secret")),
                infobase_auth: InfobaseAuthConfig {
                    default: ConfigAuth::password("admin", Password::new("base-secret")),
                    overrides: vec![InfobaseAuthOverride::password(
                        "Accounting",
                        None,
                        "admin",
                        Password::new("override-secret"),
                    )],
                },
            },
        );
        let config = Config {
            schema_version: 1,
            settings: Settings::default(),
            clusters,
        };

        let redactor = redactor_from_config(&config);
        let rendered = redactor.redact("cluster-secret base-secret override-secret обычный-текст");
        assert!(!rendered.contains("cluster-secret"));
        assert!(!rendered.contains("base-secret"));
        assert!(!rendered.contains("override-secret"));
        assert!(rendered.contains("обычный-текст"));
    }

    #[test]
    fn create_default_is_idempotent_for_bootstrap() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = directory.path().join("config.yaml");
        let store = ConfigStore::new(&path).unwrap_or_else(|error| panic!("{error}"));

        let first = load_or_create_config(&store).unwrap_or_else(|error| panic!("{error}"));
        let second = load_or_create_config(&store).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(first, second);
        assert!(Path::new(&path).exists());
        assert!(fs::read_to_string(path).is_ok());
    }
}
