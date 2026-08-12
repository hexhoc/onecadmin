use std::ffi::OsString;
use std::path::PathBuf;

use super::ConfigError;

pub const CONFIG_ENV: &str = "ONECADMIN_CONFIG";

pub fn resolve_config_path(cli_path: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
    select_config_path(
        cli_path,
        std::env::var_os(CONFIG_ENV),
        std::env::var_os("APPDATA"),
    )
}

pub fn default_config_path(appdata: Option<OsString>) -> Result<PathBuf, ConfigError> {
    let appdata = non_empty(appdata).ok_or(ConfigError::AppDataUnavailable)?;
    Ok(PathBuf::from(appdata).join("onecadmin").join("config.yaml"))
}

pub fn select_config_path(
    cli_path: Option<PathBuf>,
    env_path: Option<OsString>,
    appdata: Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    if let Some(path) = cli_path {
        if path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyConfigPath);
        }
        return Ok(path);
    }

    if let Some(path) = non_empty(env_path) {
        return Ok(PathBuf::from(path));
    }

    default_config_path(appdata)
}

fn non_empty(value: Option<OsString>) -> Option<OsString> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_priority_is_cli_then_environment_then_appdata() {
        let cli = PathBuf::from("cli.yaml");
        let selected = select_config_path(
            Some(cli.clone()),
            Some(OsString::from("env.yaml")),
            Some(OsString::from("appdata")),
        )
        .unwrap();
        assert_eq!(selected, cli);

        let selected = select_config_path(
            None,
            Some(OsString::from("env.yaml")),
            Some(OsString::from("appdata")),
        )
        .unwrap();
        assert_eq!(selected, PathBuf::from("env.yaml"));

        let selected = select_config_path(None, None, Some(OsString::from("appdata"))).unwrap();
        assert_eq!(
            selected,
            PathBuf::from("appdata")
                .join("onecadmin")
                .join("config.yaml")
        );
    }

    #[test]
    fn empty_environment_value_falls_back_to_appdata() {
        let selected =
            select_config_path(None, Some(OsString::new()), Some(OsString::from("appdata")))
                .unwrap();
        assert_eq!(
            selected,
            PathBuf::from("appdata")
                .join("onecadmin")
                .join("config.yaml")
        );
    }
}
