use std::{ffi::OsString, fmt};

use uuid::Uuid;
use zeroize::Zeroizing;

use super::process::RacArguments;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RacAuthMode {
    None,
    Password,
}

pub struct RacSecret(Zeroizing<String>);

impl RacSecret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Exposes the secret only for serialization or child-process argv construction.
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl Clone for RacSecret {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret())
    }
}

impl fmt::Debug for RacSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RacSecret(<redacted>)")
    }
}

impl From<String> for RacSecret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for RacSecret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Default)]
pub enum RacCredentials {
    #[default]
    None,
    Password {
        username: String,
        password: RacSecret,
    },
}

impl RacCredentials {
    pub fn none() -> Self {
        Self::None
    }

    pub fn password(username: impl Into<String>, password: impl Into<RacSecret>) -> Self {
        Self::Password {
            username: username.into(),
            password: password.into(),
        }
    }

    pub const fn mode(&self) -> RacAuthMode {
        match self {
            Self::None => RacAuthMode::None,
            Self::Password { .. } => RacAuthMode::Password,
        }
    }

    pub fn username(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Password { username, .. } => Some(username),
        }
    }
}

impl fmt::Debug for RacCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("RacCredentials::None"),
            Self::Password { username, .. } => formatter
                .debug_struct("RacCredentials::Password")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RacArgumentBuilder;

impl RacArgumentBuilder {
    pub const fn new() -> Self {
        Self
    }

    pub fn version(&self) -> RacArguments {
        RacArguments::plain(["--version"])
    }

    pub fn cluster_list(&self, ras_address: &str) -> RacArguments {
        command(["cluster", "list"], ras_address)
    }

    pub fn cluster_info(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        _cluster_credentials: &RacCredentials,
    ) -> RacArguments {
        let mut arguments = command_prefix(["cluster", "info"]);
        push_public_option(&mut arguments, "--cluster", cluster_id);
        arguments.push_public(ras_address);
        arguments
    }

    /// RAC calls this operation `infobase summary list`.
    pub fn infobase_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
    ) -> RacArguments {
        let mut arguments = command_prefix(["infobase", "summary", "list"]);
        push_public_option(&mut arguments, "--cluster", cluster_id);
        push_credentials(
            &mut arguments,
            CredentialScope::Cluster,
            cluster_credentials,
        );
        arguments.push_public(ras_address);
        arguments
    }

    pub fn session_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
    ) -> RacArguments {
        let mut arguments = command_prefix(["session", "list"]);
        push_public_option(&mut arguments, "--cluster", cluster_id);
        push_credentials(
            &mut arguments,
            CredentialScope::Cluster,
            cluster_credentials,
        );
        arguments.push_public(ras_address);
        arguments
    }

    pub fn session_terminate(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        session_id: Uuid,
        message: Option<&str>,
        cluster_credentials: &RacCredentials,
    ) -> RacArguments {
        let mut arguments = command_prefix(["session", "terminate"]);
        push_public_option(&mut arguments, "--cluster", cluster_id);
        push_public_option(&mut arguments, "--session", session_id);
        if let Some(message) = message {
            push_public_option(&mut arguments, "--error-message", message);
        }
        push_credentials(
            &mut arguments,
            CredentialScope::Cluster,
            cluster_credentials,
        );
        arguments.push_public(ras_address);
        arguments
    }

    pub fn connection_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
    ) -> RacArguments {
        let mut arguments = command_prefix(["connection", "list"]);
        push_public_option(&mut arguments, "--cluster", cluster_id);
        push_credentials(
            &mut arguments,
            CredentialScope::Cluster,
            cluster_credentials,
        );
        arguments.push_public(ras_address);
        arguments
    }

    pub fn connection_disconnect(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        process_id: Uuid,
        connection_id: Uuid,
        cluster_credentials: &RacCredentials,
        infobase_credentials: &RacCredentials,
    ) -> RacArguments {
        let mut arguments = command_prefix(["connection", "disconnect"]);
        push_public_option(&mut arguments, "--cluster", cluster_id);
        push_public_option(&mut arguments, "--process", process_id);
        push_public_option(&mut arguments, "--connection", connection_id);
        push_credentials(
            &mut arguments,
            CredentialScope::Cluster,
            cluster_credentials,
        );
        push_credentials(
            &mut arguments,
            CredentialScope::Infobase,
            infobase_credentials,
        );
        arguments.push_public(ras_address);
        arguments
    }

    pub fn process_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
    ) -> RacArguments {
        let mut arguments = command_prefix(["process", "list"]);
        push_public_option(&mut arguments, "--cluster", cluster_id);
        push_credentials(
            &mut arguments,
            CredentialScope::Cluster,
            cluster_credentials,
        );
        arguments.push_public(ras_address);
        arguments
    }

    pub fn process_turn_off(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        process_id: Uuid,
        cluster_credentials: &RacCredentials,
    ) -> RacArguments {
        let mut arguments = command_prefix(["process", "turn-off"]);
        push_public_option(&mut arguments, "--cluster", cluster_id);
        push_public_option(&mut arguments, "--process", process_id);
        push_credentials(
            &mut arguments,
            CredentialScope::Cluster,
            cluster_credentials,
        );
        arguments.push_public(ras_address);
        arguments
    }
}

fn command<const N: usize>(parts: [&str; N], ras_address: &str) -> RacArguments {
    let mut arguments = command_prefix(parts);
    arguments.push_public(ras_address);
    arguments
}

fn command_prefix<const N: usize>(parts: [&str; N]) -> RacArguments {
    let mut arguments = RacArguments::empty();
    for part in parts {
        arguments.push_public(part);
    }
    arguments
}

fn push_public_option(arguments: &mut RacArguments, option: &str, value: impl fmt::Display) {
    arguments.push_public(format!("{option}={value}"));
}

#[derive(Clone, Copy)]
enum CredentialScope {
    Cluster,
    Infobase,
}

impl CredentialScope {
    const fn user_option(self) -> &'static str {
        match self {
            Self::Cluster => "--cluster-user",
            Self::Infobase => "--infobase-user",
        }
    }

    const fn password_option(self) -> &'static str {
        match self {
            Self::Cluster => "--cluster-pwd",
            Self::Infobase => "--infobase-pwd",
        }
    }
}

fn push_credentials(
    arguments: &mut RacArguments,
    scope: CredentialScope,
    credentials: &RacCredentials,
) {
    match credentials {
        RacCredentials::None => {}
        RacCredentials::Password { username, password } => {
            push_public_option(arguments, scope.user_option(), username);
            push_secret_option(arguments, scope.password_option(), password);
        }
    }
}

fn push_secret_option(arguments: &mut RacArguments, option: &str, value: &RacSecret) {
    let mut raw = OsString::from(option);
    raw.push("=");
    raw.push(value.expose_secret());
    arguments.push_secret(raw, option);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_cluster_list_as_separate_arguments() {
        let arguments = RacArgumentBuilder::new().cluster_list("server.example:1545");

        assert_eq!(
            arguments.raw(),
            ["cluster", "list", "server.example:1545"].map(OsString::from)
        );
    }

    #[test]
    fn redacts_password_in_arguments_credentials_and_invocation() {
        let secret = "do-not-log-this";
        let credentials = RacCredentials::password("administrator", secret);
        let arguments =
            RacArgumentBuilder::new().session_list("server:1545", Uuid::nil(), &credentials);
        let invocation = super::super::RedactedInvocation::new("rac.exe", &arguments);

        assert!(
            arguments
                .raw()
                .iter()
                .any(|value| value.to_string_lossy().contains(secret))
        );
        assert!(!format!("{arguments:?}").contains(secret));
        assert!(!format!("{credentials:?}").contains(secret));
        assert!(!format!("{invocation:?}").contains(secret));
        assert!(!invocation.to_string().contains(secret));
    }

    #[test]
    fn disconnect_uses_process_and_connection_from_same_snapshot() {
        let process_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let arguments = RacArgumentBuilder::new().connection_disconnect(
            "server:1545",
            Uuid::nil(),
            process_id,
            connection_id,
            &RacCredentials::None,
            &RacCredentials::None,
        );
        let rendered: Vec<_> = arguments
            .raw()
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();

        assert!(rendered.contains(&format!("--process={process_id}")));
        assert!(rendered.contains(&format!("--connection={connection_id}")));
    }
}
