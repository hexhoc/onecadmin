use std::path::PathBuf;
use std::time::Duration;

use crate::domain::{
    AuthConfig, ClusterAlias, ClusterTarget, ClusterUuid, DiscoveredCluster, InfobaseAuthOverride,
    InfobaseAuthPolicy, InfobaseUuid, PlatformVersion, RacPolicy, RasEndpoint, SecretString,
};
use crate::infrastructure::config;
use crate::infrastructure::rac::{
    PlatformVersion as RacPlatformVersion, RacCredentials, RacVersionSelection, SearchPolicy,
};

use super::{AppError, RawConfigSnapshot};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RacOptions {
    pub explicit_path: Option<PathBuf>,
}

impl RacOptions {
    #[must_use]
    pub fn with_explicit_path(path: impl Into<PathBuf>) -> Self {
        Self {
            explicit_path: Some(path.into()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConfiguredTarget {
    pub target: ClusterTarget,
    pub search_policy: SearchPolicy,
    pub cluster_credentials: RacCredentials,
}

impl ConfiguredTarget {
    #[must_use]
    pub fn effective_search_policy(&self, options: &RacOptions) -> SearchPolicy {
        let mut policy = self.search_policy.clone();
        policy.explicit_path = options.explicit_path.clone();
        policy
    }
}

#[derive(Clone, Debug)]
pub struct ApplicationConfigSnapshot {
    pub path: PathBuf,
    pub timeout: Duration,
    pub global_rac_path: Option<PathBuf>,
    pub targets: Vec<ConfiguredTarget>,
}

impl ApplicationConfigSnapshot {
    #[must_use]
    pub fn target(&self, alias: &ClusterAlias) -> Option<&ConfiguredTarget> {
        self.targets
            .iter()
            .find(|target| target.target.alias == *alias)
    }

    #[must_use]
    pub fn cluster_targets(&self) -> Vec<ClusterTarget> {
        self.targets
            .iter()
            .map(|configured| configured.target.clone())
            .collect()
    }
}

pub fn convert_config_snapshot(
    snapshot: RawConfigSnapshot,
) -> Result<ApplicationConfigSnapshot, AppError> {
    snapshot.config.validate().map_err(|error| {
        AppError::config(
            "invalid_config",
            format!("Некорректная конфигурация: {error}"),
        )
    })?;
    let global_rac_path = snapshot.config.settings.rac_path.clone();
    let timeout = Duration::from_secs(snapshot.config.settings.timeout_seconds);
    let mut targets = snapshot
        .config
        .clusters
        .iter()
        .map(|(alias, cluster)| convert_cluster(alias, cluster, global_rac_path.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    targets.sort_by(|left, right| left.target.alias.cmp(&right.target.alias));

    Ok(ApplicationConfigSnapshot {
        path: snapshot.path,
        timeout,
        global_rac_path,
        targets,
    })
}

fn convert_cluster(
    alias: &str,
    cluster: &config::ClusterConfig,
    global_rac_path: Option<PathBuf>,
) -> Result<ConfiguredTarget, AppError> {
    let alias = ClusterAlias::new(alias).map_err(AppError::from_domain)?;
    let ras = RasEndpoint::new(cluster.ras.host.clone(), cluster.ras.port)
        .map_err(AppError::from_domain)?;
    let discovered_cluster = DiscoveredCluster::new(
        ClusterUuid::new(cluster.discovered_cluster.uuid),
        cluster.discovered_cluster.name.clone(),
        cluster.discovered_cluster.host.clone(),
        cluster.discovered_cluster.port,
    )
    .map_err(AppError::from_domain)?;
    let cluster_auth = config_auth_to_domain(&cluster.cluster_auth)?;
    let infobase_auth = config_infobase_auth_to_domain(&cluster.infobase_auth)?;

    let parsed_version = match &cluster.rac.version {
        config::RacVersion::Auto => None,
        config::RacVersion::Exact(value) => Some(value.parse::<PlatformVersion>().map_err(|_| {
            AppError::config(
                "invalid_rac_version",
                format!(
                    "Некорректная версия RAC для кластера `{alias}`: ожидаются четыре числовых компонента"
                ),
            )
        })?),
    };
    let rac_policy = if let Some(path) = &cluster.rac.path {
        RacPolicy::ExplicitPath(path.clone())
    } else if let Some(version) = parsed_version {
        RacPolicy::Version(version)
    } else {
        RacPolicy::Auto
    };
    let target = ClusterTarget::new(
        alias,
        ras,
        discovered_cluster,
        rac_policy,
        cluster_auth,
        infobase_auth,
    );

    let search_policy = SearchPolicy {
        cluster_path: cluster.rac.path.clone(),
        global_path: global_rac_path,
        version: parsed_version.map_or(RacVersionSelection::Auto, |version| {
            RacVersionSelection::Exact(domain_version_to_rac(version))
        }),
        ..SearchPolicy::default()
    };
    let cluster_credentials = auth_to_rac_credentials(&target.cluster_auth)?;

    Ok(ConfiguredTarget {
        target,
        search_policy,
        cluster_credentials,
    })
}

pub(crate) fn search_policy_for_new_cluster(
    global_rac_path: Option<PathBuf>,
    policy: &RacPolicy,
    options: &RacOptions,
) -> SearchPolicy {
    let (cluster_path, version) = match policy {
        RacPolicy::Auto => (None, RacVersionSelection::Auto),
        RacPolicy::Version(version) => (
            None,
            RacVersionSelection::Exact(domain_version_to_rac(*version)),
        ),
        RacPolicy::ExplicitPath(path) => (Some(path.clone()), RacVersionSelection::Auto),
    };
    SearchPolicy {
        explicit_path: options.explicit_path.clone(),
        cluster_path,
        global_path: global_rac_path,
        version,
        ..SearchPolicy::default()
    }
}

pub(crate) fn config_auth_to_domain(auth: &config::AuthConfig) -> Result<AuthConfig, AppError> {
    match auth.as_ref() {
        config::AuthRef::Password { user, password } => {
            AuthConfig::password(user, SecretString::new(password.expose_secret()))
                .map_err(AppError::from_domain)
        }
        config::AuthRef::Os { user, os_user } => {
            AuthConfig::os(Some(user.to_owned()), os_user.map(str::to_owned))
                .map_err(AppError::from_domain)
        }
        config::AuthRef::None => Ok(AuthConfig::none()),
    }
}

fn config_infobase_auth_to_domain(
    policy: &config::InfobaseAuthConfig,
) -> Result<InfobaseAuthPolicy, AppError> {
    let default = config_auth_to_domain(&policy.default)?;
    let overrides = policy
        .overrides
        .iter()
        .map(|item| {
            let auth = match item.as_ref() {
                config::AuthRef::Password { user, password } => {
                    AuthConfig::password(user, SecretString::new(password.expose_secret()))
                        .map_err(AppError::from_domain)?
                }
                config::AuthRef::Os { user, os_user } => {
                    AuthConfig::os(Some(user.to_owned()), os_user.map(str::to_owned))
                        .map_err(AppError::from_domain)?
                }
                config::AuthRef::None => AuthConfig::none(),
            };
            InfobaseAuthOverride::new(
                Some(item.infobase().to_owned()),
                item.infobase_uuid().map(InfobaseUuid::new),
                auth,
            )
            .map_err(AppError::from_domain)
        })
        .collect::<Result<Vec<_>, _>>()?;
    InfobaseAuthPolicy::new(default, overrides).map_err(AppError::from_domain)
}

pub fn auth_to_rac_credentials(auth: &AuthConfig) -> Result<RacCredentials, AppError> {
    match auth {
        AuthConfig::None => Ok(RacCredentials::none()),
        AuthConfig::Password(_) => {
            let user = auth.user().ok_or_else(|| {
                AppError::config(
                    "missing_auth_user",
                    "В учетных данных password-режима отсутствует имя пользователя",
                )
            })?;
            let password = auth.password_secret().ok_or_else(|| {
                AppError::config(
                    "missing_auth_password",
                    "В учетных данных password-режима отсутствует пароль",
                )
            })?;
            Ok(RacCredentials::password(user, password.expose_secret()))
        }
        AuthConfig::Os(_) => {
            let user = auth.user().filter(|user| !user.is_empty()).ok_or_else(|| {
                AppError::config(
                    "missing_auth_user",
                    "В учетных данных OS-режима отсутствует имя администратора 1С",
                )
            })?;
            Ok(RacCredentials::os(user))
        }
    }
}

pub(crate) fn domain_auth_to_config(auth: &AuthConfig) -> Result<config::AuthConfig, AppError> {
    match auth {
        AuthConfig::None => Ok(config::AuthConfig::none()),
        AuthConfig::Password(_) => {
            let user = auth.user().ok_or_else(|| {
                AppError::invalid(
                    "missing_auth_user",
                    "Для password-аутентификации требуется имя пользователя",
                )
            })?;
            let password = auth.password_secret().ok_or_else(|| {
                AppError::invalid(
                    "missing_auth_password",
                    "Для password-аутентификации требуется пароль",
                )
            })?;
            Ok(config::AuthConfig::password(
                user,
                config::Password::new(password.expose_secret()),
            ))
        }
        AuthConfig::Os(_) => {
            let user = auth.user().filter(|user| !user.is_empty()).ok_or_else(|| {
                AppError::invalid(
                    "missing_auth_user",
                    "Для OS-аутентификации требуется имя администратора 1С",
                )
            })?;
            Ok(config::AuthConfig::os(
                user,
                auth.expected_os_user().map(str::to_owned),
            ))
        }
    }
}

pub(crate) fn domain_infobase_auth_to_config(
    policy: &InfobaseAuthPolicy,
) -> Result<config::InfobaseAuthConfig, AppError> {
    let default = domain_auth_to_config(policy.default_auth())?;
    let overrides = policy
        .overrides()
        .iter()
        .map(domain_override_to_config)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(config::InfobaseAuthConfig { default, overrides })
}

pub(crate) fn domain_override_to_config(
    item: &InfobaseAuthOverride,
) -> Result<config::InfobaseAuthOverride, AppError> {
    let name = item
        .infobase()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            AppError::invalid(
                "missing_infobase_name",
                "Для переопределения учетных данных требуется точное имя информационной базы",
            )
        })?;
    let uuid = item.infobase_uuid().map(InfobaseUuid::into_uuid);
    match item.auth() {
        AuthConfig::None => Ok(config::InfobaseAuthOverride::none(name, uuid)),
        AuthConfig::Password(_) => {
            let auth = domain_auth_to_config(item.auth())?;
            let config::AuthConfig::Password(auth) = auth else {
                return Err(AppError::internal(
                    "auth_conversion_failed",
                    "Не удалось преобразовать учетные данные password-режима",
                ));
            };
            Ok(config::InfobaseAuthOverride::password(
                name,
                uuid,
                auth.user,
                auth.password,
            ))
        }
        AuthConfig::Os(_) => {
            let auth = domain_auth_to_config(item.auth())?;
            let config::AuthConfig::Os(auth) = auth else {
                return Err(AppError::internal(
                    "auth_conversion_failed",
                    "Не удалось преобразовать учетные данные OS-режима",
                ));
            };
            Ok(config::InfobaseAuthOverride::os(
                name,
                uuid,
                auth.user,
                auth.os_user,
            ))
        }
    }
}

pub(crate) fn domain_rac_to_config(policy: &RacPolicy) -> config::RacConfig {
    match policy {
        RacPolicy::Auto => config::RacConfig::default(),
        RacPolicy::Version(version) => config::RacConfig {
            path: None,
            version: config::RacVersion::Exact(version.to_string()),
        },
        RacPolicy::ExplicitPath(path) => config::RacConfig {
            path: Some(path.clone()),
            version: config::RacVersion::Auto,
        },
    }
}

fn domain_version_to_rac(version: PlatformVersion) -> RacPlatformVersion {
    let [major, minor, patch, build] = version.components();
    RacPlatformVersion::new(major, minor, patch, build)
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn config_is_converted_and_sorted_by_case_insensitive_alias() {
        let cluster = |name: &str| config::ClusterConfig {
            ras: config::RasConfig {
                host: "ras.local".to_owned(),
                port: 1545,
            },
            discovered_cluster: config::DiscoveredCluster {
                uuid: Uuid::new_v4(),
                name: name.to_owned(),
                host: "cluster.local".to_owned(),
                port: 1541,
            },
            rac: config::RacConfig::default(),
            cluster_auth: config::AuthConfig::none(),
            infobase_auth: config::InfobaseAuthConfig::default(),
        };
        let mut clusters = IndexMap::new();
        clusters.insert("zeta".to_owned(), cluster("z"));
        clusters.insert("Alpha".to_owned(), cluster("a"));
        let snapshot = RawConfigSnapshot {
            path: "config.yaml".into(),
            config: config::Config {
                schema_version: config::CONFIG_SCHEMA_VERSION,
                settings: config::Settings::default(),
                clusters,
            },
        };

        let converted = convert_config_snapshot(snapshot).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(converted.targets[0].target.alias.as_str(), "Alpha");
        assert_eq!(converted.targets[1].target.alias.as_str(), "zeta");
    }
}
