use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::DomainError;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMode {
    None,
    Password,
    Os,
}

#[derive(Clone, Eq, PartialEq, Zeroize)]
pub struct PasswordAuth {
    user: String,
    password: SecretString,
}

impl PasswordAuth {
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    #[must_use]
    pub const fn password(&self) -> &SecretString {
        &self.password
    }
}

impl fmt::Debug for PasswordAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordAuth")
            .field("user", &self.user)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
pub struct OsAuth {
    user: Option<String>,
    expected_os_user: Option<String>,
}

impl OsAuth {
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    #[must_use]
    pub fn expected_os_user(&self) -> Option<&str> {
        self.expected_os_user.as_deref()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum AuthConfig {
    None,
    Password(PasswordAuth),
    Os(OsAuth),
}

impl AuthConfig {
    #[must_use]
    pub const fn none() -> Self {
        Self::None
    }

    pub fn password(user: impl Into<String>, password: SecretString) -> Result<Self, DomainError> {
        let user = user.into();
        if user.is_empty() {
            return Err(DomainError::InvalidAuth {
                reason: "в password-режиме требуется непустой user",
            });
        }
        if password.is_empty() {
            return Err(DomainError::InvalidAuth {
                reason: "в password-режиме требуется непустой password",
            });
        }
        Ok(Self::Password(PasswordAuth { user, password }))
    }

    pub fn os(user: Option<String>, expected_os_user: Option<String>) -> Result<Self, DomainError> {
        if user.as_deref().is_some_and(str::is_empty) {
            return Err(DomainError::InvalidAuth {
                reason: "user в OS-режиме не может быть пустым",
            });
        }
        if expected_os_user.as_deref().is_some_and(str::is_empty) {
            return Err(DomainError::InvalidAuth {
                reason: "os_user в OS-режиме не может быть пустым",
            });
        }
        Ok(Self::Os(OsAuth {
            user,
            expected_os_user,
        }))
    }

    #[must_use]
    pub const fn mode(&self) -> AuthMode {
        match self {
            Self::None => AuthMode::None,
            Self::Password(_) => AuthMode::Password,
            Self::Os(_) => AuthMode::Os,
        }
    }

    #[must_use]
    pub fn user(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Password(auth) => Some(auth.user()),
            Self::Os(auth) => auth.user(),
        }
    }

    #[must_use]
    pub fn password_secret(&self) -> Option<&SecretString> {
        match self {
            Self::Password(auth) => Some(auth.password()),
            Self::None | Self::Os(_) => None,
        }
    }

    #[must_use]
    pub fn expected_os_user(&self) -> Option<&str> {
        match self {
            Self::Os(auth) => auth.expected_os_user(),
            Self::None | Self::Password(_) => None,
        }
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("AuthConfig::None"),
            Self::Password(auth) => formatter
                .debug_tuple("AuthConfig::Password")
                .field(auth)
                .finish(),
            Self::Os(auth) => formatter.debug_tuple("AuthConfig::Os").field(auth).finish(),
        }
    }
}

impl Zeroize for AuthConfig {
    fn zeroize(&mut self) {
        match self {
            Self::None => {}
            Self::Password(auth) => auth.zeroize(),
            Self::Os(auth) => auth.zeroize(),
        }
    }
}

impl Drop for AuthConfig {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

    use super::*;

    #[test]
    fn debug_never_contains_password() {
        let auth = AuthConfig::password("administrator", SecretString::new("top-secret"))
            .unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{auth:?}");

        assert!(!debug.contains("top-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn explicit_zeroize_clears_credentials() {
        let mut auth = AuthConfig::password("administrator", SecretString::new("top-secret"))
            .unwrap_or_else(|error| panic!("{error}"));

        auth.zeroize();

        assert_eq!(auth.user(), Some(""));
        assert_eq!(
            auth.password_secret().map(SecretString::expose_secret),
            Some("")
        );
    }

    #[test]
    fn auth_modes_do_not_fall_back_to_empty_passwords() {
        let os = AuthConfig::os(None, Some("DOMAIN\\user".to_owned()))
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(os.mode(), AuthMode::Os);
        assert!(os.password_secret().is_none());
        assert!(AuthConfig::password("user", SecretString::new("")).is_err());
    }
}
