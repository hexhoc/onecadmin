#[cfg(windows)]
use std::env;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;
use std::sync::Arc;

use super::{SystemWindowsIdentityProvider, WindowsIdentityProvider};
use crate::infrastructure::config::{AclError, AclProtection, AclProtector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclRestriction {
    Applied,
    NotApplied { reason: String },
}

impl AclRestriction {
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied)
    }
}

/// Boundary used by the config adapter after creating or atomically replacing
/// a config file. Failure is reported but deliberately does not invalidate a
/// successful config write.
pub trait ConfigFileAcl: Send + Sync {
    fn restrict_to_current_user(&self, path: &Path) -> AclRestriction;
}

#[derive(Clone)]
pub struct WindowsConfigFileAcl {
    identity_provider: Arc<dyn WindowsIdentityProvider>,
}

impl WindowsConfigFileAcl {
    pub fn new(identity_provider: Arc<dyn WindowsIdentityProvider>) -> Self {
        Self { identity_provider }
    }
}

impl Default for WindowsConfigFileAcl {
    fn default() -> Self {
        Self::new(Arc::new(SystemWindowsIdentityProvider))
    }
}

impl std::fmt::Debug for WindowsConfigFileAcl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsConfigFileAcl")
            .finish_non_exhaustive()
    }
}

impl ConfigFileAcl for WindowsConfigFileAcl {
    fn restrict_to_current_user(&self, path: &Path) -> AclRestriction {
        if path.as_os_str().is_empty() {
            return not_applied("не указан путь к файлу конфигурации");
        }

        #[cfg(not(windows))]
        {
            let _ = path;
            let _ = &self.identity_provider;
            return not_applied("ограничение ACL поддерживается только в Windows");
        }

        #[cfg(windows)]
        {
            let identity = match self.identity_provider.current_identity() {
                Ok(identity) => identity,
                Err(error) => {
                    return not_applied(format!(
                        "не удалось определить пользователя для ACL: {error}"
                    ));
                }
            };

            let Some(icacls) = icacls_path() else {
                return not_applied(
                    "переменная SystemRoot не задана; безопасный путь к icacls.exe неизвестен",
                );
            };

            let mut grant = identity.into_os_string();
            grant.push(":(F)");

            // Arguments are passed directly, without cmd.exe/PowerShell, so a
            // path or account name cannot be interpreted as shell syntax.
            let output = Command::new(&icacls)
                .arg(path)
                .arg("/inheritance:r")
                .arg("/grant:r")
                .arg(grant)
                .output();

            match output {
                Ok(output) if output.status.success() => AclRestriction::Applied,
                Ok(output) => not_applied(match output.status.code() {
                    Some(code) => format!("icacls.exe завершился с кодом {code}"),
                    None => "icacls.exe был завершен без кода возврата".to_owned(),
                }),
                Err(error) => not_applied(format!(
                    "не удалось запустить {}: {error}",
                    icacls.display()
                )),
            }
        }
    }
}

impl AclProtector for WindowsConfigFileAcl {
    fn protect_current_user(&self, path: &Path) -> Result<AclProtection, AclError> {
        match self.restrict_to_current_user(path) {
            AclRestriction::Applied => Ok(AclProtection::Applied),
            AclRestriction::NotApplied { reason } => Err(AclError::new(reason)),
        }
    }
}

fn not_applied(reason: impl Into<String>) -> AclRestriction {
    AclRestriction::NotApplied {
        reason: reason.into(),
    }
}

#[cfg(windows)]
fn icacls_path() -> Option<PathBuf> {
    let system_root = env::var_os("SystemRoot").filter(|value| !value.is_empty())?;
    Some(
        PathBuf::from(system_root)
            .join("System32")
            .join("icacls.exe"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_is_a_best_effort_failure() {
        let result = WindowsConfigFileAcl::default().restrict_to_current_user(Path::new(""));
        assert!(!result.is_applied());
        assert!(matches!(result, AclRestriction::NotApplied { .. }));
    }
}
