use std::{
    cmp::Ordering,
    collections::HashSet,
    env,
    ffi::OsString,
    fmt,
    path::{Path, PathBuf},
};

use tokio_util::sync::CancellationToken;

use super::{
    PlatformVersion, RacArguments, RacError, RacErrorKind, RacOutputDecoder, RacVersionProbe,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RacOrigin {
    ExplicitArgument,
    Environment,
    ClusterConfig,
    GlobalConfig,
    Path,
    Registry,
    ProgramFiles,
    ProgramFilesX86,
}

impl RacOrigin {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExplicitArgument => "explicit_argument",
            Self::Environment => "environment",
            Self::ClusterConfig => "cluster_config",
            Self::GlobalConfig => "global_config",
            Self::Path => "path",
            Self::Registry => "registry",
            Self::ProgramFiles => "program_files",
            Self::ProgramFilesX86 => "program_files_x86",
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::ExplicitArgument => 0,
            Self::Environment => 1,
            Self::ClusterConfig => 2,
            Self::GlobalConfig => 3,
            Self::Path => 4,
            Self::Registry => 5,
            Self::ProgramFiles => 6,
            Self::ProgramFilesX86 => 7,
        }
    }
}

impl fmt::Display for RacOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RacCandidate {
    pub path: PathBuf,
    pub version: PlatformVersion,
    pub origin: RacOrigin,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RacVersionSelection {
    #[default]
    Auto,
    Exact(PlatformVersion),
}

#[derive(Clone, Debug)]
pub struct SearchEnvironment {
    pub rac_path: Option<PathBuf>,
    pub path_entries: Vec<PathBuf>,
    pub program_files: Option<PathBuf>,
    pub program_files_x86: Option<PathBuf>,
}

impl SearchEnvironment {
    pub fn current() -> Self {
        Self {
            rac_path: env::var_os("ONECADMIN_RAC_PATH").map(PathBuf::from),
            path_entries: env::var_os("PATH")
                .map(|value| env::split_paths(&value).collect())
                .unwrap_or_default(),
            program_files: env::var_os("ProgramFiles").map(PathBuf::from),
            program_files_x86: env::var_os("ProgramFiles(x86)").map(PathBuf::from),
        }
    }

    pub const fn empty() -> Self {
        Self {
            rac_path: None,
            path_entries: Vec::new(),
            program_files: None,
            program_files_x86: None,
        }
    }
}

impl Default for SearchEnvironment {
    fn default() -> Self {
        Self::current()
    }
}

#[derive(Clone, Debug)]
pub struct SearchPolicy {
    pub explicit_path: Option<PathBuf>,
    pub cluster_path: Option<PathBuf>,
    pub global_path: Option<PathBuf>,
    pub version: RacVersionSelection,
    pub minimum_version: PlatformVersion,
    pub environment: SearchEnvironment,
    pub search_registry: bool,
    /// Additional pre-discovered registry paths, primarily useful for adapters and tests.
    pub registry_paths: Vec<PathBuf>,
    pub search_program_files: bool,
}

impl SearchPolicy {
    pub fn isolated() -> Self {
        Self {
            explicit_path: None,
            cluster_path: None,
            global_path: None,
            version: RacVersionSelection::Auto,
            minimum_version: PlatformVersion::MIN_SUPPORTED,
            environment: SearchEnvironment::empty(),
            search_registry: false,
            registry_paths: Vec::new(),
            search_program_files: false,
        }
    }

    pub fn with_explicit_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.explicit_path = Some(path.into());
        self
    }

    pub fn with_cluster_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.cluster_path = Some(path.into());
        self
    }

    pub fn with_global_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.global_path = Some(path.into());
        self
    }

    pub fn effective_minimum(&self) -> PlatformVersion {
        if self.minimum_version < PlatformVersion::MIN_SUPPORTED {
            PlatformVersion::MIN_SUPPORTED
        } else {
            self.minimum_version
        }
    }

    pub(crate) fn accepts_version(&self, version: PlatformVersion) -> bool {
        if version < self.effective_minimum() {
            return false;
        }
        match self.version {
            RacVersionSelection::Auto => true,
            RacVersionSelection::Exact(expected) => version == expected,
        }
    }

    pub(crate) fn accepts_cached(&self, candidate: &RacCandidate) -> bool {
        if !self.accepts_version(candidate.version) {
            return false;
        }
        match &self.explicit_path {
            Some(explicit) => canonical_path_key(explicit) == canonical_path_key(&candidate.path),
            None => true,
        }
    }
}

impl Default for SearchPolicy {
    fn default() -> Self {
        Self {
            explicit_path: None,
            cluster_path: None,
            global_path: None,
            version: RacVersionSelection::Auto,
            minimum_version: PlatformVersion::MIN_SUPPORTED,
            environment: SearchEnvironment::current(),
            search_registry: cfg!(windows),
            registry_paths: Vec::new(),
            search_program_files: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RacLocator {
    probe: RacVersionProbe,
}

impl RacLocator {
    pub fn new(probe: RacVersionProbe) -> Self {
        Self { probe }
    }

    pub fn probe(&self) -> &RacVersionProbe {
        &self.probe
    }

    pub async fn find_candidates(
        &self,
        policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacCandidate>, RacError> {
        if let Some(explicit_path) = &policy.explicit_path {
            let candidate = self
                .validate_explicit(explicit_path, policy, cancellation)
                .await?;
            return Ok(vec![candidate]);
        }

        let discovered = self.discover_paths(policy, cancellation).await?;
        let discovered = canonical_deduplicate(discovered).await;
        let mut candidates = Vec::new();
        let mut unsupported_version_seen = false;

        for (path, origin) in discovered {
            if cancellation.is_cancelled() {
                return Err(RacError::new(RacErrorKind::Cancelled));
            }

            match self.probe.probe(&path, cancellation).await {
                Ok(version) if policy.accepts_version(version) => candidates.push(RacCandidate {
                    path,
                    version,
                    origin,
                }),
                Ok(_) => unsupported_version_seen = true,
                Err(error) if error.kind() == RacErrorKind::Cancelled => return Err(error),
                Err(error) if error.kind() == RacErrorKind::UnsupportedVersion => {
                    unsupported_version_seen = true;
                }
                Err(_) => {}
            }
        }

        candidates.sort_by(compare_candidates);
        if !candidates.is_empty() {
            return Ok(candidates);
        }

        if unsupported_version_seen {
            Err(RacError::new(RacErrorKind::UnsupportedVersion))
        } else {
            Err(RacError::new(RacErrorKind::NotFound))
        }
    }

    async fn validate_explicit(
        &self,
        path: &Path,
        policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<RacCandidate, RacError> {
        let path = tokio::fs::canonicalize(path)
            .await
            .map_err(|_| RacError::new(RacErrorKind::NotFound))?;
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|_| RacError::new(RacErrorKind::NotFound))?;
        if !metadata.is_file() {
            return Err(RacError::new(RacErrorKind::NotFound));
        }

        let version = self.probe.probe(&path, cancellation).await?;
        if !policy.accepts_version(version) {
            return Err(RacError::new(RacErrorKind::UnsupportedVersion));
        }

        Ok(RacCandidate {
            path,
            version,
            origin: RacOrigin::ExplicitArgument,
        })
    }

    async fn discover_paths(
        &self,
        policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(PathBuf, RacOrigin)>, RacError> {
        let mut paths = Vec::new();

        if let Some(path) = &policy.environment.rac_path {
            paths.push((path.clone(), RacOrigin::Environment));
        }
        if let Some(path) = &policy.cluster_path {
            paths.push((path.clone(), RacOrigin::ClusterConfig));
        }
        if let Some(path) = &policy.global_path {
            paths.push((path.clone(), RacOrigin::GlobalConfig));
        }
        paths.extend(
            policy
                .environment
                .path_entries
                .iter()
                .map(|directory| (directory.join("rac.exe"), RacOrigin::Path)),
        );
        paths.extend(
            policy
                .registry_paths
                .iter()
                .cloned()
                .map(|path| (path, RacOrigin::Registry)),
        );

        if policy.search_registry {
            paths.extend(
                self.discover_registry(cancellation)
                    .await?
                    .into_iter()
                    .map(|path| (path, RacOrigin::Registry)),
            );
        }

        if policy.search_program_files {
            if let Some(root) = &policy.environment.program_files {
                paths.extend(
                    scan_program_files(root)
                        .await
                        .into_iter()
                        .map(|path| (path, RacOrigin::ProgramFiles)),
                );
            }
            if let Some(root) = &policy.environment.program_files_x86 {
                paths.extend(
                    scan_program_files(root)
                        .await
                        .into_iter()
                        .map(|path| (path, RacOrigin::ProgramFilesX86)),
                );
            }
        }

        Ok(paths)
    }

    #[cfg(windows)]
    async fn discover_registry(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Vec<PathBuf>, RacError> {
        const ROOTS: [&str; 3] = [
            r"HKLM\SOFTWARE\1C\1Cv8",
            r"HKLM\SOFTWARE\WOW6432Node\1C\1Cv8",
            r"HKCU\SOFTWARE\1C\1Cv8",
        ];
        const VALUE_NAMES: [&str; 3] = ["InstallLocation", "InstallDir", "Path"];

        let mut result = Vec::new();
        for root in ROOTS {
            for value_name in VALUE_NAMES {
                let arguments = RacArguments::plain([
                    OsString::from("query"),
                    OsString::from(root),
                    OsString::from("/s"),
                    OsString::from("/v"),
                    OsString::from(value_name),
                ]);
                match self
                    .probe
                    .runner()
                    .run("reg.exe", &arguments, cancellation)
                    .await
                {
                    Ok(output) if output.status().success() => {
                        let decoded = RacOutputDecoder::decode(output.stdout());
                        result.extend(extract_registry_candidates(decoded.text()));
                    }
                    Err(error) if error.is_cancelled() => {
                        return Err(RacError::from_process(error));
                    }
                    Ok(_) | Err(_) => {}
                }
            }
        }
        Ok(result)
    }

    #[cfg(not(windows))]
    async fn discover_registry(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Vec<PathBuf>, RacError> {
        if cancellation.is_cancelled() {
            Err(RacError::new(RacErrorKind::Cancelled))
        } else {
            Ok(Vec::new())
        }
    }
}

fn compare_candidates(left: &RacCandidate, right: &RacCandidate) -> Ordering {
    right
        .version
        .cmp(&left.version)
        .then_with(|| left.origin.priority().cmp(&right.origin.priority()))
        .then_with(|| canonical_path_key(&left.path).cmp(&canonical_path_key(&right.path)))
}

async fn canonical_deduplicate(discovered: Vec<(PathBuf, RacOrigin)>) -> Vec<(PathBuf, RacOrigin)> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for (path, origin) in discovered {
        let Ok(metadata) = tokio::fs::metadata(&path).await else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let Ok(canonical) = tokio::fs::canonicalize(&path).await else {
            continue;
        };
        if seen.insert(canonical_path_key(&canonical)) {
            result.push((canonical, origin));
        }
    }

    result
}

pub(crate) fn canonical_path_key(path: &Path) -> String {
    let rendered = path.to_string_lossy().replace('/', "\\");
    rendered
        .strip_prefix(r"\\?\")
        .unwrap_or(&rendered)
        .to_lowercase()
}

async fn scan_program_files(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let Ok(mut versions) = tokio::fs::read_dir(root.join("1cv8")).await else {
        return result;
    };

    loop {
        match versions.next_entry().await {
            Ok(Some(entry)) => result.push(entry.path().join("bin").join("rac.exe")),
            Ok(None) | Err(_) => return result,
        }
    }
}

#[cfg(windows)]
fn extract_registry_candidates(output: &str) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for line in output.lines() {
        let Some(data) = registry_value_data(line) else {
            continue;
        };
        let expanded = expand_windows_environment(data.trim().trim_matches('"'));
        if expanded.is_empty() {
            continue;
        }
        let location = PathBuf::from(expanded.trim_end_matches(",0"));
        let file_name = location
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        if file_name.eq_ignore_ascii_case("rac.exe") {
            result.push(location);
        } else if file_name.eq_ignore_ascii_case("bin") {
            result.push(location.join("rac.exe"));
        } else if location
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        {
            if let Some(parent) = location.parent() {
                result.push(parent.join("rac.exe"));
            }
        } else {
            result.push(location.join("bin").join("rac.exe"));
        }
    }
    result
}

#[cfg(windows)]
fn registry_value_data(line: &str) -> Option<&str> {
    ["REG_EXPAND_SZ", "REG_SZ"]
        .into_iter()
        .find_map(|marker| line.find(marker).map(|index| &line[index + marker.len()..]))
}

#[cfg(windows)]
fn expand_windows_environment(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        result.push_str(&rest[..start]);
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('%') else {
            result.push_str(&rest[start..]);
            return result;
        };
        let name = &after_start[..end];
        match env::var_os(name) {
            Some(replacement) => result.push_str(&replacement.to_string_lossy()),
            None => {
                result.push('%');
                result.push_str(name);
                result.push('%');
            }
        }
        rest = &after_start[end + 1..];
    }
    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_candidates_sort_newest_first_then_by_origin() {
        let mut candidates = [
            RacCandidate {
                path: PathBuf::from(r"C:\old\rac.exe"),
                version: PlatformVersion::new(8, 3, 20, 1),
                origin: RacOrigin::Path,
            },
            RacCandidate {
                path: PathBuf::from(r"C:\new-b\rac.exe"),
                version: PlatformVersion::new(8, 3, 25, 1),
                origin: RacOrigin::Registry,
            },
            RacCandidate {
                path: PathBuf::from(r"C:\new-a\rac.exe"),
                version: PlatformVersion::new(8, 3, 25, 1),
                origin: RacOrigin::Path,
            },
        ];

        candidates.sort_by(compare_candidates);

        assert_eq!(candidates[0].origin, RacOrigin::Path);
        assert_eq!(candidates[1].origin, RacOrigin::Registry);
        assert_eq!(candidates[2].version, PlatformVersion::new(8, 3, 20, 1));
    }

    #[test]
    fn canonical_key_is_case_insensitive_and_separator_independent() {
        assert_eq!(
            canonical_path_key(Path::new(r"C:\Program Files\1cv8\rac.exe")),
            canonical_path_key(Path::new("c:/program files/1CV8/RAC.EXE"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn derives_rac_path_from_registry_install_directory() {
        let output = concat!(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\1C\\1Cv8\\8.3.25.1\r\n",
            "    InstallDir    REG_SZ    C:\\Program Files\\1cv8\\8.3.25.1\r\n",
        );

        assert_eq!(
            extract_registry_candidates(output),
            vec![PathBuf::from(r"C:\Program Files\1cv8\8.3.25.1\bin\rac.exe")]
        );
    }
}
