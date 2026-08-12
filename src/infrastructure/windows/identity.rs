use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    Environment,
    WindowsApi,
}

#[derive(Clone, PartialEq, Eq)]
pub struct WindowsIdentity {
    account_name: OsString,
    source: IdentitySource,
}

impl WindowsIdentity {
    pub fn new(account_name: impl Into<OsString>, source: IdentitySource) -> Self {
        Self {
            account_name: account_name.into(),
            source,
        }
    }

    pub fn as_os_str(&self) -> &OsStr {
        &self.account_name
    }

    pub fn into_os_string(self) -> OsString {
        self.account_name
    }

    pub fn source(&self) -> IdentitySource {
        self.source
    }

    /// JSON is UTF-8, while Windows strings may contain unpaired UTF-16
    /// surrogates. This conversion is intended only for display and audit.
    pub fn to_string_lossy(&self) -> String {
        self.account_name.to_string_lossy().into_owned()
    }
}

impl fmt::Debug for WindowsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsIdentity")
            .field("account_name", &self.account_name)
            .field("source", &self.source)
            .finish()
    }
}

impl fmt::Display for WindowsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.account_name.to_string_lossy().fmt(formatter)
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("ожидаемая учетная запись Windows (os_user) не может быть пустой")]
    EmptyExpectedIdentity,
    #[error(
        "текущая учетная запись Windows не совпадает с ожидаемой: ожидалась {expected}, процесс запущен от {actual}"
    )]
    IdentityMismatch { expected: String, actual: String },
    #[error(
        "не удалось определить текущую учетную запись Windows: USERDOMAIN/USERNAME отсутствуют или неполны; {details}"
    )]
    IdentityUnavailable { details: String },
}

pub trait WindowsIdentityProvider: Send + Sync {
    fn current_identity(&self) -> Result<WindowsIdentity, IdentityError>;

    fn verify_expected(&self, expected: &str) -> Result<WindowsIdentity, IdentityError> {
        if expected.is_empty() {
            return Err(IdentityError::EmptyExpectedIdentity);
        }

        let current = self.current_identity()?;
        if identities_equal(current.as_os_str(), OsStr::new(expected)) {
            return Ok(current);
        }

        Err(IdentityError::IdentityMismatch {
            expected: expected.to_owned(),
            actual: identity_for_error(current.as_os_str()),
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemWindowsIdentityProvider;

impl SystemWindowsIdentityProvider {
    pub fn current_identity(&self) -> Result<WindowsIdentity, IdentityError> {
        <Self as WindowsIdentityProvider>::current_identity(self)
    }

    pub fn verify_expected(&self, expected: &str) -> Result<WindowsIdentity, IdentityError> {
        <Self as WindowsIdentityProvider>::verify_expected(self, expected)
    }
}

impl WindowsIdentityProvider for SystemWindowsIdentityProvider {
    fn current_identity(&self) -> Result<WindowsIdentity, IdentityError> {
        if let Ok(account_name) = current_identity_from_windows_api() {
            return Ok(WindowsIdentity::new(
                account_name,
                IdentitySource::WindowsApi,
            ));
        }

        let domain = non_empty_environment_value("USERDOMAIN");
        let username = non_empty_environment_value("USERNAME");

        if let (Some(domain), Some(username)) = (domain.as_ref(), username.as_ref()) {
            let mut account_name = domain.clone();
            account_name.push("\\");
            account_name.push(username);
            return Ok(WindowsIdentity::new(
                account_name,
                IdentitySource::Environment,
            ));
        }

        if let Some(username) = username {
            return Ok(WindowsIdentity::new(username, IdentitySource::Environment));
        }

        Err(IdentityError::IdentityUnavailable {
            details: "Windows API и переменные окружения не вернули имя пользователя".to_owned(),
        })
    }
}

pub fn identities_equal(actual: &OsStr, expected: &OsStr) -> bool {
    platform::identities_equal(actual, expected)
}

fn non_empty_environment_value(name: &str) -> Option<OsString> {
    env::var_os(name).filter(|value| !value.is_empty())
}

fn current_identity_from_windows_api() -> io::Result<OsString> {
    platform::current_identity_from_windows_api()
}

fn identity_for_error(identity: &OsStr) -> String {
    identity
        .to_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{identity:?}"))
}

#[cfg(windows)]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    const NAME_SAM_COMPATIBLE: u32 = 2;
    const ERROR_MORE_DATA: i32 = 234;
    const CSTR_EQUAL: i32 = 2;
    const INITIAL_NAME_CAPACITY: usize = 256;
    const MAX_NAME_CAPACITY: usize = 32 * 1024;

    #[link(name = "Secur32")]
    unsafe extern "system" {
        fn GetUserNameExW(name_format: u32, name_buffer: *mut u16, size: *mut u32) -> u8;
    }

    #[link(name = "Advapi32")]
    unsafe extern "system" {
        fn GetUserNameW(name_buffer: *mut u16, size: *mut u32) -> i32;
    }

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn CompareStringOrdinal(
            string1: *const u16,
            string1_length: i32,
            string2: *const u16,
            string2_length: i32,
            ignore_case: i32,
        ) -> i32;
    }

    pub(super) fn current_identity_from_windows_api() -> io::Result<OsString> {
        match sam_compatible_name() {
            Ok(name) => Ok(name),
            Err(sam_error) => basic_user_name().map_err(|basic_error| {
                io::Error::new(
                    basic_error.kind(),
                    format!(
                        "GetUserNameExW завершился ошибкой ({sam_error}); GetUserNameW завершился ошибкой ({basic_error})"
                    ),
                )
            }),
        }
    }

    pub(super) fn identities_equal(actual: &OsStr, expected: &OsStr) -> bool {
        let actual: Vec<u16> = actual.encode_wide().collect();
        let expected: Vec<u16> = expected.encode_wide().collect();
        let Ok(actual_length) = i32::try_from(actual.len()) else {
            return false;
        };
        let Ok(expected_length) = i32::try_from(expected.len()) else {
            return false;
        };

        // SAFETY: pointers reference live UTF-16 vectors for the exact lengths
        // passed to CompareStringOrdinal; the API only reads those buffers.
        let comparison = unsafe {
            CompareStringOrdinal(
                actual.as_ptr(),
                actual_length,
                expected.as_ptr(),
                expected_length,
                1,
            )
        };
        comparison == CSTR_EQUAL
    }

    fn sam_compatible_name() -> io::Result<OsString> {
        let mut buffer = vec![0_u16; INITIAL_NAME_CAPACITY];

        loop {
            let mut size = u32::try_from(buffer.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "слишком длинное имя Windows")
            })?;

            // SAFETY: buffer is writable for `size` u16 values and `size`
            // remains alive for the duration of the Windows API call.
            let succeeded =
                unsafe { GetUserNameExW(NAME_SAM_COMPATIBLE, buffer.as_mut_ptr(), &mut size) };
            if succeeded != 0 {
                let length = usize::try_from(size).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "некорректная длина имени Windows",
                    )
                })?;
                if length > buffer.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Windows API вернул длину имени за пределами буфера",
                    ));
                }
                buffer.truncate(length);
                return Ok(OsString::from_wide(&buffer));
            }

            let error = io::Error::last_os_error();
            let required = usize::try_from(size).unwrap_or(MAX_NAME_CAPACITY + 1);
            if error.raw_os_error() == Some(ERROR_MORE_DATA)
                && required > buffer.len()
                && required <= MAX_NAME_CAPACITY
            {
                buffer.resize(required, 0);
                continue;
            }
            return Err(error);
        }
    }

    fn basic_user_name() -> io::Result<OsString> {
        let mut buffer = vec![0_u16; INITIAL_NAME_CAPACITY];

        loop {
            let mut size = u32::try_from(buffer.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "слишком длинное имя Windows")
            })?;

            // SAFETY: buffer is writable for `size` u16 values and `size`
            // remains alive for the duration of the Windows API call.
            let succeeded = unsafe { GetUserNameW(buffer.as_mut_ptr(), &mut size) };
            if succeeded != 0 {
                let mut length = usize::try_from(size).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "некорректная длина имени Windows",
                    )
                })?;
                if length > buffer.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Windows API вернул длину имени за пределами буфера",
                    ));
                }
                if length > 0 && buffer[length - 1] == 0 {
                    length -= 1;
                }
                buffer.truncate(length);
                return Ok(OsString::from_wide(&buffer));
            }

            let error = io::Error::last_os_error();
            let required = usize::try_from(size).unwrap_or(MAX_NAME_CAPACITY + 1);
            if error.raw_os_error() == Some(ERROR_MORE_DATA)
                && required > buffer.len()
                && required <= MAX_NAME_CAPACITY
            {
                buffer.resize(required, 0);
                continue;
            }
            return Err(error);
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::io;

    pub(super) fn current_identity_from_windows_api() -> io::Result<OsString> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows API недоступен на этой платформе",
        ))
    }

    pub(super) fn identities_equal(actual: &OsStr, expected: &OsStr) -> bool {
        actual.to_string_lossy().to_lowercase() == expected.to_string_lossy().to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedIdentityProvider(WindowsIdentity);

    impl WindowsIdentityProvider for FixedIdentityProvider {
        fn current_identity(&self) -> Result<WindowsIdentity, IdentityError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn expected_identity_is_case_insensitive() {
        let provider = FixedIdentityProvider(WindowsIdentity::new(
            r"DOMAIN\Ivanov",
            IdentitySource::Environment,
        ));

        let identity = provider.verify_expected(r"domain\IVANOV").unwrap();
        assert_eq!(identity.as_os_str(), OsStr::new(r"DOMAIN\Ivanov"));
    }

    #[test]
    fn mismatch_error_names_expected_and_actual_accounts() {
        let provider = FixedIdentityProvider(WindowsIdentity::new(
            r"DOMAIN\actual",
            IdentitySource::Environment,
        ));

        let error = provider.verify_expected(r"DOMAIN\expected").unwrap_err();
        let message = error.to_string();
        assert!(message.contains(r"DOMAIN\expected"));
        assert!(message.contains(r"DOMAIN\actual"));
    }
}
