//! Command-line adapter foundations.

pub mod args;
pub mod confirm;
pub mod dispatch;
pub mod output;

pub use args::{
    AuthModeArg, Cli, CliCommand, CliValidationError, ClusterAddArgs, ClusterCommand,
    ClusterRemoveArgs, ConnectionCommand, ConnectionKillArgs, ConnectionListArgs,
    ConnectionSelectors, InfobaseCommand, InfobaseSearchArgs, OutputFormat, QueryOptions,
    SessionCommand, SessionKillArgs, SessionListArgs, SessionSelectors, render_parse_error,
};
pub use confirm::{Confirmation, confirm, confirm_with_io};
pub use dispatch::{AppExitCode, CliRunResult, dispatch, dispatch_with_confirmation};
pub use output::{
    OutputEnvelope, OutputError, OutputRenderer, ProjectedRow, RenderedOutput,
    render_errors_for_stderr,
};
