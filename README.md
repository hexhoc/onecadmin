# onecadmin

`onecadmin` is a Windows terminal application for administering 1C:Enterprise clusters through an already running RAS service and the installed `rac.exe` utility.

The user interface and messages are in Russian. CLI commands, options, output fields, JSON keys and CSV columns are in English.

## Requirements

- Windows 10 or Windows 11 x64.
- 1C:Enterprise 8.3.20 or newer.
- An already running RAS service with exactly one cluster.
- `rac.exe` from an installed compatible 1C platform version.

`onecadmin` does not install or start RAS and does not include `rac.exe`.

## Build

Install stable Rust and Visual Studio Build Tools with the C++ workload, then run:

```powershell
cargo build --release --locked
```

The result is `target\release\onecadmin.exe`. The release profile and `.cargo\config.toml` produce a portable executable with a statically linked CRT. System Windows DLLs and the external `rac.exe` remain runtime requirements.

## Configuration

The default path is:

```text
%APPDATA%\onecadmin\config.yaml
```

The path priority is `--config`, `ONECADMIN_CONFIG`, then the default path. The application creates an empty version 1 configuration when the selected file does not exist.

## Password Warning

Passwords are stored in plain text in `config.yaml`. This is not encryption.

Passwords passed to `onecadmin` and forwarded to `rac.exe` can be visible in PowerShell history and in the process list. Technical logs and JSON errors redact configured passwords, but operators must still protect the Windows account and configuration file.

## Usage

Running without a command opens the full-screen TUI:

```powershell
onecadmin
```

Add and remove a connection:

```powershell
onecadmin cluster add --name dev --ras RV-DEV-1C01:1545 --auth password --user admin --password secret
onecadmin cluster remove --name dev
```

Search and inspect:

```powershell
onecadmin infobase search 'zup%'
onecadmin session list --infobase zup_corp --sort cpu_time_total:desc --top 10
onecadmin connection list --query 'APP-%' --format json
```

Destructive commands require a selector and confirmation. `--cluster` alone is not a selector. Use `--force` only in controlled non-interactive automation:

```powershell
onecadmin session kill --user 'test%' --infobase zup_corp
onecadmin connection kill --host 'APP-%' --force
```

## Runtime Files

```text
%LOCALAPPDATA%\onecadmin\logs\onecadmin.log
```

The technical log rotates at 10 MiB and keeps five files.

## Verification

```powershell
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo audit
cargo deny check
cargo llvm-cov --locked --all-features --workspace --all-targets
```

The last three commands require `cargo-audit`, `cargo-deny` and `cargo-llvm-cov`. GitHub Actions runs the same dependency policy and coverage checks on every push and pull request, together with stable and Rust 1.88 Windows builds.
