use std::{fmt, path::Path, str::FromStr};

use tokio_util::sync::CancellationToken;

use super::{
    RacArguments, RacError, RacErrorKind, RacOutputDecoder, RacProcessRunner, classify_diagnostic,
};

/// A four-component 1C platform version. This is deliberately not SemVer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlatformVersion {
    major: u32,
    minor: u32,
    patch: u32,
    build: u32,
}

impl PlatformVersion {
    pub const MIN_SUPPORTED: Self = Self::new(8, 3, 20, 0);

    pub const fn new(major: u32, minor: u32, patch: u32, build: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            build,
        }
    }

    pub const fn major(self) -> u32 {
        self.major
    }

    pub const fn minor(self) -> u32 {
        self.minor
    }

    pub const fn patch(self) -> u32 {
        self.patch
    }

    pub const fn build(self) -> u32 {
        self.build
    }

    pub const fn components(self) -> [u32; 4] {
        [self.major, self.minor, self.patch, self.build]
    }

    /// Extracts a four-component platform version from `rac --version` output.
    pub fn from_rac_output(output: &str) -> Result<Self, PlatformVersionParseError> {
        output
            .split(|character: char| !(character.is_ascii_digit() || character == '.'))
            .find_map(|token| token.parse().ok())
            .ok_or(PlatformVersionParseError)
    }

    pub const fn is_supported(self) -> bool {
        self.major > 8
            || (self.major == 8 && (self.minor > 3 || (self.minor == 3 && self.patch >= 20)))
    }
}

impl fmt::Display for PlatformVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}.{}.{}.{}",
            self.major, self.minor, self.patch, self.build
        )
    }
}

impl FromStr for PlatformVersion {
    type Err = PlatformVersionParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut components = value.trim().split('.');
        let major = parse_component(components.next())?;
        let minor = parse_component(components.next())?;
        let patch = parse_component(components.next())?;
        let build = parse_component(components.next())?;

        if components.next().is_some() {
            return Err(PlatformVersionParseError);
        }

        Ok(Self::new(major, minor, patch, build))
    }
}

fn parse_component(component: Option<&str>) -> Result<u32, PlatformVersionParseError> {
    let component = component.ok_or(PlatformVersionParseError)?;
    if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PlatformVersionParseError);
    }
    component.parse().map_err(|_| PlatformVersionParseError)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformVersionParseError;

impl fmt::Display for PlatformVersionParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ожидалась версия платформы из четырех числовых компонентов")
    }
}

impl std::error::Error for PlatformVersionParseError {}

#[derive(Clone, Debug)]
pub struct RacVersionProbe {
    runner: RacProcessRunner,
}

impl RacVersionProbe {
    pub fn new(runner: RacProcessRunner) -> Self {
        Self { runner }
    }

    pub fn runner(&self) -> &RacProcessRunner {
        &self.runner
    }

    pub async fn probe(
        &self,
        executable: &Path,
        cancellation: &CancellationToken,
    ) -> Result<PlatformVersion, RacError> {
        let arguments = RacArguments::plain(["--version"]);
        let output = self
            .runner
            .run(executable, &arguments, cancellation)
            .await
            .map_err(RacError::from_process)?;

        if !output.status().success() {
            let stderr = RacOutputDecoder::decode(output.stderr());
            let kind = classify_diagnostic(stderr.text());
            return Err(RacError::command_failed(
                kind,
                output.status().code(),
                output.invocation().clone(),
            ));
        }

        let stdout = RacOutputDecoder::decode(output.stdout());
        let stderr = RacOutputDecoder::decode(output.stderr());
        PlatformVersion::from_rac_output(stdout.text())
            .or_else(|_| PlatformVersion::from_rac_output(stderr.text()))
            .map_err(|_| {
                RacError::with_invocation(
                    RacErrorKind::UnsupportedVersion,
                    output.invocation().clone(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_all_four_components() {
        let version: PlatformVersion = "8.3.20.1710".parse().unwrap();

        assert_eq!(version.components(), [8, 3, 20, 1710]);
        assert_eq!(version.build(), 1710);
        assert_eq!(version.to_string(), "8.3.20.1710");
    }

    #[test]
    fn extracts_version_from_rac_banner() {
        let version = PlatformVersion::from_rac_output(
            "1C:Enterprise 8.3 Remote Administration Client (8.3.25.1501)\r\n",
        )
        .unwrap();

        assert_eq!(version, PlatformVersion::new(8, 3, 25, 1501));
    }

    #[test]
    fn rejects_semver_and_incomplete_versions() {
        assert!("8.3.20".parse::<PlatformVersion>().is_err());
        assert!("8.3.20.1-beta".parse::<PlatformVersion>().is_err());
        assert!("8.3.20.1.2".parse::<PlatformVersion>().is_err());
    }

    #[test]
    fn versions_have_platform_ordering() {
        assert!(PlatformVersion::new(8, 3, 24, 100) > PlatformVersion::new(8, 3, 23, u32::MAX));
        assert!(!PlatformVersion::new(8, 3, 19, 9999).is_supported());
        assert!(PlatformVersion::new(8, 3, 20, 1).is_supported());
    }
}
