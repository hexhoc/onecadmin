use std::{
    ffi::{OsStr, OsString},
    fmt, io,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    task::JoinHandle,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const REDACTED: &str = "<redacted>";
const MAX_CAPTURED_OUTPUT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct RacArguments {
    raw: Vec<OsString>,
    redacted: Vec<OsString>,
}

impl RacArguments {
    pub fn plain<I, S>(arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let raw: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
        let redacted = redact_arguments(&raw);
        Self { raw, redacted }
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn len(&self) -> usize {
        self.raw.len()
    }

    pub fn redacted(&self) -> &[OsString] {
        &self.redacted
    }

    pub(crate) fn empty() -> Self {
        Self {
            raw: Vec::new(),
            redacted: Vec::new(),
        }
    }

    pub(crate) fn raw(&self) -> &[OsString] {
        &self.raw
    }

    pub(crate) fn push_public(&mut self, argument: impl Into<OsString>) {
        let argument = argument.into();
        self.redacted.push(argument.clone());
        self.raw.push(argument);
    }

    pub(crate) fn push_secret(&mut self, argument: OsString, option: &str) {
        self.raw.push(argument);
        self.redacted
            .push(OsString::from(format!("{option}={REDACTED}")));
    }
}

impl fmt::Debug for RacArguments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RacArguments")
            .field(&self.redacted)
            .finish()
    }
}

fn redact_arguments(arguments: &[OsString]) -> Vec<OsString> {
    let mut result = Vec::with_capacity(arguments.len());
    let mut redact_next = false;

    for argument in arguments {
        if redact_next {
            result.push(OsString::from(REDACTED));
            redact_next = false;
            continue;
        }

        let rendered = argument.to_string_lossy();
        if let Some((option, _)) = rendered.split_once('=')
            && is_secret_option(option)
        {
            result.push(OsString::from(format!("{option}={REDACTED}")));
            continue;
        }

        if is_secret_option(&rendered) {
            redact_next = true;
        }
        result.push(argument.clone());
    }

    result
}

fn is_secret_option(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "--cluster-pwd"
            | "--cluster-password"
            | "--infobase-pwd"
            | "--infobase-password"
            | "--password"
            | "--pwd"
    )
}

#[derive(Clone, Eq, PartialEq)]
pub struct RedactedInvocation {
    executable: PathBuf,
    arguments: Vec<OsString>,
}

impl RedactedInvocation {
    pub fn new(executable: impl Into<PathBuf>, arguments: &RacArguments) -> Self {
        Self {
            executable: executable.into(),
            arguments: arguments.redacted.clone(),
        }
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
}

impl fmt::Debug for RedactedInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedInvocation")
            .field("executable", &self.executable)
            .field("arguments", &self.arguments)
            .finish()
    }
}

impl fmt::Display for RedactedInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}",
            quote_for_diagnostics(self.executable.as_os_str())
        )?;
        for argument in &self.arguments {
            write!(formatter, " {}", quote_for_diagnostics(argument))?;
        }
        Ok(())
    }
}

fn quote_for_diagnostics(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if value.is_empty() || value.chars().any(char::is_whitespace) || value.contains('"') {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.into_owned()
    }
}

pub struct RacProcessOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    invocation: RedactedInvocation,
}

impl RacProcessOutput {
    pub fn status(&self) -> ExitStatus {
        self.status
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn invocation(&self) -> &RedactedInvocation {
        &self.invocation
    }
}

impl fmt::Debug for RacProcessOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RacProcessOutput")
            .field("status", &self.status)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("invocation", &self.invocation)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessIoStage {
    Spawn,
    CapturePipes,
    Wait,
    ReadStdout,
    ReadStderr,
}

#[derive(Clone, Debug)]
pub enum RacProcessError {
    Io {
        stage: ProcessIoStage,
        error_kind: io::ErrorKind,
        raw_os_error: Option<i32>,
        invocation: RedactedInvocation,
    },
    Timeout {
        invocation: RedactedInvocation,
    },
    Cancelled {
        invocation: RedactedInvocation,
    },
}

impl RacProcessError {
    pub fn invocation(&self) -> &RedactedInvocation {
        match self {
            Self::Io { invocation, .. }
            | Self::Timeout { invocation }
            | Self::Cancelled { invocation } => invocation,
        }
    }

    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io { error_kind, .. } => Some(*error_kind),
            Self::Timeout { .. } | Self::Cancelled { .. } => None,
        }
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }

    fn io(stage: ProcessIoStage, error: &io::Error, invocation: RedactedInvocation) -> Self {
        Self::Io {
            stage,
            error_kind: error.kind(),
            raw_os_error: error.raw_os_error(),
            invocation,
        }
    }
}

impl fmt::Display for RacProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                stage,
                error_kind,
                raw_os_error,
                invocation,
            } => write!(
                formatter,
                "ошибка запуска RAC ({stage:?}, {error_kind:?}, OS {raw_os_error:?}): {invocation}"
            ),
            Self::Timeout { invocation } => {
                write!(formatter, "превышено время ожидания RAC: {invocation}")
            }
            Self::Cancelled { invocation } => {
                write!(formatter, "вызов RAC отменен: {invocation}")
            }
        }
    }
}

impl std::error::Error for RacProcessError {}

#[derive(Clone, Debug)]
pub struct RacProcessRunner {
    timeout: Duration,
}

impl RacProcessRunner {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn run(
        &self,
        executable: impl AsRef<Path>,
        arguments: &RacArguments,
        cancellation: &CancellationToken,
    ) -> Result<RacProcessOutput, RacProcessError> {
        let executable = executable.as_ref().to_path_buf();
        let invocation = RedactedInvocation::new(executable.clone(), arguments);
        let mut command = Command::new(&executable);
        command
            .args(arguments.raw())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|error| {
            RacProcessError::io(ProcessIoStage::Spawn, &error, invocation.clone())
        })?;

        let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take())
        else {
            terminate_and_wait(&mut child).await;
            return Err(RacProcessError::Io {
                stage: ProcessIoStage::CapturePipes,
                error_kind: io::ErrorKind::Other,
                raw_os_error: None,
                invocation,
            });
        };

        let mut stdout_task = tokio::spawn(async move { read_pipe(&mut stdout).await });
        let mut stderr_task = tokio::spawn(async move { read_pipe(&mut stderr).await });

        let deadline = Instant::now() + self.timeout;
        let timeout = tokio::time::sleep_until(deadline);
        tokio::pin!(timeout);
        let completion = tokio::select! {
            biased;
            _ = cancellation.cancelled() => ProcessCompletion::Cancelled,
            _ = &mut timeout => ProcessCompletion::Timeout,
            status = child.wait() => ProcessCompletion::Exited(status),
        };

        match completion {
            ProcessCompletion::Timeout => {
                terminate_and_wait(&mut child).await;
                abort_pipe_tasks(stdout_task, stderr_task).await;
                Err(RacProcessError::Timeout { invocation })
            }
            ProcessCompletion::Cancelled => {
                terminate_and_wait(&mut child).await;
                abort_pipe_tasks(stdout_task, stderr_task).await;
                Err(RacProcessError::Cancelled { invocation })
            }
            ProcessCompletion::Exited(Err(error)) => {
                terminate_and_wait(&mut child).await;
                abort_pipe_tasks(stdout_task, stderr_task).await;
                Err(RacProcessError::io(
                    ProcessIoStage::Wait,
                    &error,
                    invocation,
                ))
            }
            ProcessCompletion::Exited(Ok(status)) => {
                let pipes = tokio::time::timeout_at(deadline, async {
                    let stdout =
                        collect_pipe(&mut stdout_task, ProcessIoStage::ReadStdout, &invocation)
                            .await?;
                    let stderr =
                        collect_pipe(&mut stderr_task, ProcessIoStage::ReadStderr, &invocation)
                            .await?;
                    Ok::<_, RacProcessError>((stdout, stderr))
                })
                .await;
                match pipes {
                    Ok(Ok((stdout, stderr))) => Ok(RacProcessOutput {
                        status,
                        stdout,
                        stderr,
                        invocation,
                    }),
                    Ok(Err(error)) => Err(error),
                    Err(_) => {
                        abort_pipe_tasks(stdout_task, stderr_task).await;
                        Err(RacProcessError::Timeout { invocation })
                    }
                }
            }
        }
    }
}

impl Default for RacProcessRunner {
    fn default() -> Self {
        Self::new(Self::DEFAULT_TIMEOUT)
    }
}

enum ProcessCompletion {
    Exited(io::Result<ExitStatus>),
    Timeout,
    Cancelled,
}

async fn terminate_and_wait(child: &mut Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

async fn collect_pipe(
    task: &mut JoinHandle<io::Result<Vec<u8>>>,
    stage: ProcessIoStage,
    invocation: &RedactedInvocation,
) -> Result<Vec<u8>, RacProcessError> {
    match task.await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => Err(RacProcessError::io(stage, &error, invocation.clone())),
        Err(_) => Err(RacProcessError::Io {
            stage,
            error_kind: io::ErrorKind::Other,
            raw_os_error: None,
            invocation: invocation.clone(),
        }),
    }
}

async fn abort_pipe_tasks(
    stdout: JoinHandle<io::Result<Vec<u8>>>,
    stderr: JoinHandle<io::Result<Vec<u8>>>,
) {
    stdout.abort();
    stderr.abort();
    let _ = tokio::join!(stdout, stderr);
}

async fn read_pipe<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    reader
        .take(MAX_CAPTURED_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_CAPTURED_OUTPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "вывод RAC превысил допустимый размер",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_arguments_redact_both_option_forms() {
        let arguments = RacArguments::plain([
            "session",
            "list",
            "--cluster-pwd=first-secret",
            "--infobase-pwd",
            "second-secret",
        ]);
        let debug = format!("{arguments:?}");

        assert!(!debug.contains("first-secret"));
        assert!(!debug.contains("second-secret"));
        assert!(debug.matches(REDACTED).count() >= 2);
    }

    #[test]
    #[ignore = "helper process for the timeout test"]
    fn child_that_sleeps() {
        std::thread::sleep(Duration::from_secs(2));
    }

    #[tokio::test]
    async fn timeout_kills_and_waits_for_child() {
        let executable = std::env::current_exe().unwrap();
        let arguments = RacArguments::plain(["--ignored", "child_that_sleeps", "--test-threads=1"]);
        let runner = RacProcessRunner::new(Duration::from_millis(50));
        let cancellation = CancellationToken::new();

        let error = runner
            .run(executable, &arguments, &cancellation)
            .await
            .unwrap_err();

        assert!(error.is_timeout());
    }
}
