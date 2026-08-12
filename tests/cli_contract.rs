use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn command(environment: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("onecadmin").expect("test binary must exist");
    command
        .env("APPDATA", environment.path().join("roaming"))
        .env("LOCALAPPDATA", environment.path().join("local"))
        .env_remove("ONECADMIN_CONFIG")
        .env_remove("ONECADMIN_RAC_PATH");
    command
}

#[test]
fn help_does_not_initialize_config_logging_or_tui() {
    let environment = tempfile::tempdir().expect("temporary directory must be created");
    let config = environment.path().join("must-not-exist.yaml");

    command(&environment)
        .arg("--config")
        .arg(&config)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Администрирование кластеров"));

    assert!(!config.exists());
    assert!(!environment.path().join("local/onecadmin/logs").exists());
}

#[test]
fn version_does_not_initialize_runtime_resources() {
    let environment = tempfile::tempdir().expect("temporary directory must be created");
    let config = environment.path().join("must-not-exist.yaml");

    command(&environment)
        .arg("--config")
        .arg(&config)
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("onecadmin "));

    assert!(!config.exists());
}

#[test]
fn invalid_filter_is_rejected_before_config_io() {
    let environment = tempfile::tempdir().expect("temporary directory must be created");
    let config = environment.path().join("must-not-exist.yaml");

    command(&environment)
        .arg("--config")
        .arg(&config)
        .args(["session", "list", "--filter", "cpu_time:eq:1"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cpu_time"));

    assert!(!config.exists());
}

#[test]
fn empty_configuration_produces_valid_empty_json_envelope() {
    let environment = tempfile::tempdir().expect("temporary directory must be created");
    let config = environment.path().join("config.yaml");

    let output = command(&environment)
        .arg("--config")
        .arg(&config)
        .args(["--format", "json", "infobase", "search", "%"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("stdout must be JSON");
    assert_eq!(json["data"], Value::Array(Vec::new()));
    assert_eq!(json["errors"], Value::Array(Vec::new()));
    assert_eq!(json["meta"]["matched"], 0);
    assert_eq!(json["meta"]["returned"], 0);
    assert!(config.exists());
    let source = fs::read_to_string(config).expect("created config must be UTF-8");
    assert!(source.contains("schema_version: 1"));
}
