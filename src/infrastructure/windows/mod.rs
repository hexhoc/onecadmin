mod paths;

pub use paths::{
    APP_DIRECTORY_NAME, APPDATA_ENV, CONFIG_FILE_NAME, LOCALAPPDATA_ENV, LOG_DIRECTORY_NAME,
    TECHNICAL_LOG_FILE_NAME, WindowsPathError, WindowsPaths, default_config_path,
    default_logs_directory,
};
