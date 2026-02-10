use chrono::{DateTime, Utc};

/// Source type for a driver
#[derive(Debug, Clone)]
pub enum DriverSource {
    GitHub { owner: String, repo: String },
    PyPI { package: String },
}

/// Configuration for a single driver
#[derive(Debug, Clone)]
pub struct DriverConfig {
    pub name: String,
    pub source: DriverSource,
    pub version_req: Option<semver::VersionReq>,
    pub artifact_filter: Option<String>,
}

impl DriverConfig {
    /// Check if an artifact filename matches the filter pattern
    /// Returns true if no filter is set, or if the artifact matches the pattern
    pub fn matches_artifact(&self, filename: &str) -> bool {
        match &self.artifact_filter {
            None => true,
            Some(pattern) => {
                // Support glob-style patterns
                if pattern.contains('*') || pattern.contains('?') {
                    // Use glob matching
                    if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
                        return glob_pattern.matches(filename);
                    }
                    // If pattern compilation fails, fall through to prefix matching
                }

                // Simple prefix/suffix/contains matching
                if pattern.starts_with('*') && pattern.ends_with('*') {
                    // *text* - contains
                    let text = &pattern[1..pattern.len()-1];
                    filename.contains(text)
                } else if pattern.starts_with('*') {
                    // *suffix - ends with
                    let suffix = &pattern[1..];
                    filename.ends_with(suffix)
                } else if pattern.ends_with('*') {
                    // prefix* - starts with
                    let prefix = &pattern[..pattern.len()-1];
                    filename.starts_with(prefix)
                } else {
                    // Exact match
                    filename == pattern
                }
            }
        }
    }
}

/// A release record - one row per driver release
#[derive(Debug, Clone)]
pub struct ReleaseRecord {
    pub name: String,
    pub release_tag: String,
    pub version: Option<String>,
    pub published_date: DateTime<Utc>,
    pub release_url: String,
    pub os: Vec<String>,
    pub arch: Vec<String>,
}

/// A library record - one row per shared library
#[derive(Debug, Clone)]
pub struct LibraryRecord {
    pub name: String,
    pub release_tag: String,
    pub version: Option<String>,
    pub published_date: DateTime<Utc>,
    pub os: String,
    pub arch: String,
    pub library_name: String,
    pub library_size_bytes: i64,
    pub library_sha256: String,
    pub artifact_name: String,
    pub artifact_url: String,
}

/// A driver record - one row per driver
#[derive(Debug, Clone)]
pub struct DriverRecord {
    pub name: String,
    pub repo_owner: String,
    pub repo_name: String,
    pub release_count: i64,
    pub library_count: i64,
    pub first_release_date: DateTime<Utc>,
    pub first_release_version: Option<String>,
    pub latest_release_date: DateTime<Utc>,
    pub latest_release_version: Option<String>,
}

/// A symbol record - one row per exported symbol
#[derive(Debug, Clone)]
pub struct SymbolRecord {
    pub name: String,
    pub release_tag: String,
    pub version: Option<String>,
    pub os: String,
    pub arch: String,
    pub library_name: String,
    pub symbol: String,
    pub symbol_index: i64,
    pub is_stub: bool,
    pub constant_return: Option<i32>,
    pub return_status: Option<String>,
}

impl ReleaseRecord {
    /// Parse version from tag (handles complex tags like "go/v0.2.0")
    /// Returns version in format "0.1.2" (without 'v' prefix)
    pub fn parse_version(tag: &str) -> Option<String> {
        let tag = tag.trim();

        // Split by '/' and find the last component that looks like a version
        let parts: Vec<&str> = tag.split('/').collect();

        for part in parts.iter().rev() {
            let part = part.trim();

            // Try with 'v' prefix
            if part.starts_with('v') || part.starts_with('V') {
                let version = &part[1..];
                if is_valid_version(version) {
                    return Some(version.to_string());
                }
            }

            // Try without 'v' prefix
            if part.chars().next()?.is_ascii_digit() && is_valid_version(part) {
                return Some(part.to_string());
            }
        }

        None
    }

    /// Sanitize release tag for use in file paths
    /// Strips path prefixes like "go/" and 'v' from "go/v0.2.0" -> "0.2.0"
    /// Falls back to replacing '/' with '_' if no version is found
    pub fn sanitize_tag_for_path(tag: &str) -> String {
        let tag = tag.trim();

        // Split by '/' and find the component that looks like a version
        let parts: Vec<&str> = tag.split('/').collect();

        // Look for a version-like component (starting from the end)
        for part in parts.iter().rev() {
            let part = part.trim();

            // Check if this part looks like a version with 'v' prefix
            if (part.starts_with('v') || part.starts_with('V')) && is_valid_version(&part[1..]) {
                return part[1..].to_string(); // Strip the 'v'
            }

            // Check if this part looks like a version without 'v' prefix
            if part.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
                && is_valid_version(part) {
                return part.to_string();
            }
        }

        // No version found, fall back to replacing '/' with '_'
        tag.replace('/', "_")
    }
}

/// Check if string looks like a valid semantic version
fn is_valid_version(s: &str) -> bool {
    // Must start with a digit
    if !s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return false;
    }

    // Must contain at least one dot
    if !s.contains('.') {
        return false;
    }

    // Check format: digits separated by dots, optionally with dash for pre-release
    let parts: Vec<&str> = s.split(&['.', '-'][..]).collect();
    if parts.is_empty() {
        return false;
    }

    // First parts (major.minor.patch) should be numeric
    for (i, part) in parts.iter().enumerate() {
        if i < 3 {
            // Major, minor, patch should be all digits
            if !part.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
        }
        // After that, we allow alphanumeric for pre-release/build metadata
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_version() {
        assert_eq!(ReleaseRecord::parse_version("v0.2.0"), Some("0.2.0".to_string()));
        assert_eq!(ReleaseRecord::parse_version("v1.0.0"), Some("1.0.0".to_string()));
        assert_eq!(ReleaseRecord::parse_version("0.1.2"), Some("0.1.2".to_string()));
    }

    #[test]
    fn test_parse_complex_tag() {
        assert_eq!(ReleaseRecord::parse_version("go/v0.2.0"), Some("0.2.0".to_string()));
        assert_eq!(ReleaseRecord::parse_version("python/v1.0.0"), Some("1.0.0".to_string()));
        assert_eq!(ReleaseRecord::parse_version("java/driver/v2.3.4"), Some("2.3.4".to_string()));
    }

    #[test]
    fn test_parse_prerelease() {
        assert_eq!(ReleaseRecord::parse_version("v1.0.0-beta"), Some("1.0.0-beta".to_string()));
        assert_eq!(ReleaseRecord::parse_version("v1.0.0-rc.1"), Some("1.0.0-rc.1".to_string()));
    }

    #[test]
    fn test_sanitize_tag() {
        assert_eq!(ReleaseRecord::sanitize_tag_for_path("v0.2.0"), "0.2.0");
        assert_eq!(ReleaseRecord::sanitize_tag_for_path("go/v0.2.0"), "0.2.0");
        assert_eq!(ReleaseRecord::sanitize_tag_for_path("a/b/c/v1.0.0"), "1.0.0");
        assert_eq!(ReleaseRecord::sanitize_tag_for_path("0.1.2"), "0.1.2");
        assert_eq!(ReleaseRecord::sanitize_tag_for_path("python/1.5.0"), "1.5.0");
    }

    #[test]
    fn test_invalid_versions() {
        assert_eq!(ReleaseRecord::parse_version("go"), None);
        assert_eq!(ReleaseRecord::parse_version("latest"), None);
        assert_eq!(ReleaseRecord::parse_version("main"), None);
    }

    #[test]
    fn test_artifact_filter_prefix() {
        let config = DriverConfig {
            name: "test".to_string(),
            source: DriverSource::GitHub {
                owner: "test".to_string(),
                repo: "test".to_string(),
            },
            version_req: None,
            artifact_filter: Some("lib*".to_string()),
        };

        assert!(config.matches_artifact("libduckdb.so"));
        assert!(config.matches_artifact("libduckdb-osx-universal.zip"));
        assert!(!config.matches_artifact("duckdb_cli-osx-universal.zip"));
        assert!(!config.matches_artifact("duckdb_jdbc.jar"));
    }

    #[test]
    fn test_artifact_filter_suffix() {
        let config = DriverConfig {
            name: "test".to_string(),
            source: DriverSource::GitHub {
                owner: "test".to_string(),
                repo: "test".to_string(),
            },
            version_req: None,
            artifact_filter: Some("*.zip".to_string()),
        };

        assert!(config.matches_artifact("libduckdb-osx-universal.zip"));
        assert!(config.matches_artifact("duckdb_cli.zip"));
        assert!(!config.matches_artifact("libduckdb.so"));
        assert!(!config.matches_artifact("duckdb_jdbc.jar"));
    }

    #[test]
    fn test_artifact_filter_contains() {
        let config = DriverConfig {
            name: "test".to_string(),
            source: DriverSource::GitHub {
                owner: "test".to_string(),
                repo: "test".to_string(),
            },
            version_req: None,
            artifact_filter: Some("*linux*".to_string()),
        };

        assert!(config.matches_artifact("libduckdb-linux-amd64.zip"));
        assert!(config.matches_artifact("linux-binary.tar.gz"));
        assert!(!config.matches_artifact("libduckdb-osx-universal.zip"));
        assert!(!config.matches_artifact("windows-binary.zip"));
    }

    #[test]
    fn test_artifact_filter_glob() {
        let config = DriverConfig {
            name: "test".to_string(),
            source: DriverSource::GitHub {
                owner: "test".to_string(),
                repo: "test".to_string(),
            },
            version_req: None,
            artifact_filter: Some("libduckdb-*.zip".to_string()),
        };

        assert!(config.matches_artifact("libduckdb-osx-universal.zip"));
        assert!(config.matches_artifact("libduckdb-linux-amd64.zip"));
        assert!(!config.matches_artifact("libduckdb-osx-universal.tar.gz"));
        assert!(!config.matches_artifact("duckdb_cli-linux.zip"));
    }

    #[test]
    fn test_artifact_filter_none() {
        let config = DriverConfig {
            name: "test".to_string(),
            source: DriverSource::GitHub {
                owner: "test".to_string(),
                repo: "test".to_string(),
            },
            version_req: None,
            artifact_filter: None,
        };

        // No filter means everything matches
        assert!(config.matches_artifact("anything.zip"));
        assert!(config.matches_artifact("libduckdb.so"));
        assert!(config.matches_artifact("random_file.txt"));
    }
}
