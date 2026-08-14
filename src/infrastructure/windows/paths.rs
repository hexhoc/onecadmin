use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub const APPDATA_ENV: &str = "APPDATA";
pub const LOCALAPPDATA_ENV: &str = "LOCALAPPDATA";
pub const APP_DIRECTORY_NAME: &str = "onecadmin";
pub const LOG_DIRECTORY_NAME: &str = "logs";
pub const CONFIG_FILE_NAME: &str = "config.yaml";
pub const TECHNICAL_LOG_FILE_NAME: &str = "onecadmin.log";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WindowsPathError {
    #[error("переменная окружения Windows {variable} не задана")]
    MissingEnvironmentVariable { variable: &'static str },
    #[error("переменная окружения Windows {variable} содержит пустой путь")]
    EmptyEnvironmentVariable { variable: &'static str },
}

/// Default per-user paths. Paths stay as `PathBuf` so non-Unicode Windows
/// environment values are never converted through UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPaths {
    config_file: PathBuf,
    logs_directory: PathBuf,
}

impl WindowsPaths {
    pub fn discover() -> Result<Self, WindowsPathError> {
        Self::from_environment_values(env::var_os(APPDATA_ENV), env::var_os(LOCALAPPDATA_ENV))
    }

    pub fn from_environment_values(
        app_data: Option<OsString>,
        local_app_data: Option<OsString>,
    ) -> Result<Self, WindowsPathError> {
        let app_data = required_root(app_data, APPDATA_ENV)?;
        let local_app_data = required_root(local_app_data, LOCALAPPDATA_ENV)?;
        Ok(Self::from_roots(app_data, local_app_data))
    }

    pub fn from_roots(app_data: impl Into<PathBuf>, local_app_data: impl Into<PathBuf>) -> Self {
        let config_file = app_data
            .into()
            .join(APP_DIRECTORY_NAME)
            .join(CONFIG_FILE_NAME);
        let logs_directory = local_app_data
            .into()
            .join(APP_DIRECTORY_NAME)
            .join(LOG_DIRECTORY_NAME);

        Self {
            config_file,
            logs_directory,
        }
    }

    pub fn config_file(&self) -> &Path {
        &self.config_file
    }

    pub fn logs_directory(&self) -> &Path {
        &self.logs_directory
    }

    pub fn technical_log_file(&self) -> PathBuf {
        self.logs_directory.join(TECHNICAL_LOG_FILE_NAME)
    }
}

pub fn default_config_path() -> Result<PathBuf, WindowsPathError> {
    WindowsPaths::discover().map(|paths| paths.config_file)
}

pub fn default_logs_directory() -> Result<PathBuf, WindowsPathError> {
    WindowsPaths::discover().map(|paths| paths.logs_directory)
}

fn required_root(
    value: Option<OsString>,
    variable: &'static str,
) -> Result<PathBuf, WindowsPathError> {
    let value = value.ok_or(WindowsPathError::MissingEnvironmentVariable { variable })?;
    if value.is_empty() {
        return Err(WindowsPathError::EmptyEnvironmentVariable { variable });
    }
    Ok(PathBuf::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_specified_default_paths() {
        let roaming = PathBuf::from("profile").join("roaming");
        let local = PathBuf::from("profile").join("local");
        let paths = WindowsPaths::from_roots(&roaming, &local);

        assert_eq!(
            paths.config_file(),
            roaming.join(APP_DIRECTORY_NAME).join(CONFIG_FILE_NAME)
        );
        assert_eq!(
            paths.logs_directory(),
            local.join(APP_DIRECTORY_NAME).join(LOG_DIRECTORY_NAME)
        );
        assert_eq!(
            paths.technical_log_file(),
            local
                .join(APP_DIRECTORY_NAME)
                .join(LOG_DIRECTORY_NAME)
                .join(TECHNICAL_LOG_FILE_NAME)
        );
    }

    #[test]
    fn reports_missing_and_empty_environment_roots() {
        assert_eq!(
            WindowsPaths::from_environment_values(None, Some(OsString::from("local"))),
            Err(WindowsPathError::MissingEnvironmentVariable {
                variable: APPDATA_ENV
            })
        );
        assert_eq!(
            WindowsPaths::from_environment_values(
                Some(OsString::from("roaming")),
                Some(OsString::new())
            ),
            Err(WindowsPathError::EmptyEnvironmentVariable {
                variable: LOCALAPPDATA_ENV
            })
        );
    }

    #[cfg(windows)]
    #[test]
    fn preserves_non_unicode_windows_roots() {
        use std::os::windows::ffi::OsStringExt;

        let mut roaming_wide: Vec<u16> = r"C:\Users\".encode_utf16().collect();
        roaming_wide.push(0xd800);
        let roaming = OsString::from_wide(&roaming_wide);

        let paths = WindowsPaths::from_roots(roaming.clone(), OsString::from(r"D:\Local"));
        assert_eq!(
            paths.config_file(),
            PathBuf::from(roaming)
                .join(APP_DIRECTORY_NAME)
                .join(CONFIG_FILE_NAME)
        );
    }
}
