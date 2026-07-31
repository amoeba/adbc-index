use crate::error::{AdbcIndexError, Result};
use crate::models::{DriverConfig, DriverSource};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Deserialize)]
#[serde(untagged)]
enum DriverValue {
    Simple(String),
    Detailed(DetailedDriverConfig),
}

#[derive(Deserialize)]
struct DetailedDriverConfig {
    urls: Vec<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    artifact_filter: Option<String>,
    #[serde(default)]
    language: Option<String>,
}

#[derive(Deserialize)]
struct ConfigFile {
    drivers: HashMap<String, DriverValue>,
}

/// Top-level configuration returned by load_config.
pub struct Config {
    pub drivers: Vec<DriverConfig>,
}

/// Parse drivers.toml configuration file
pub fn load_config(path: &Path) -> Result<Config> {
    let content = fs::read_to_string(path)?;
    let config: ConfigFile = toml::from_str(&content)?;

    let mut configs = Vec::new();

    for (name, driver_value) in config.drivers {
        let (urls, version_req, artifact_filter, language) = match driver_value {
            DriverValue::Simple(url) => (vec![url], None, None, None),
            DriverValue::Detailed(detailed) => {
                let version_req = if let Some(version_str) = &detailed.version {
                    Some(semver::VersionReq::parse(version_str).map_err(|e| {
                        AdbcIndexError::Config(format!(
                            "Invalid version requirement '{}' for driver '{}': {}",
                            version_str, name, e
                        ))
                    })?)
                } else {
                    None
                };

                if detailed.urls.is_empty() {
                    return Err(AdbcIndexError::Config(format!(
                        "Driver '{}' must have at least one URL in 'urls' field",
                        name
                    )));
                }

                (
                    detailed.urls,
                    version_req,
                    detailed.artifact_filter,
                    detailed.language,
                )
            }
        };

        // Parse all URLs into sources
        let mut sources = Vec::new();
        for url in urls {
            let source = parse_driver_url(&url)?;
            sources.push(source);
        }

        configs.push(DriverConfig {
            name,
            sources,
            version_req,
            artifact_filter,
            language,
        });
    }

    Ok(Config {
        drivers: configs,
    })
}

/// Parse driver URL and determine source type
/// Supports GitHub and PyPI URLs
fn parse_driver_url(url: &str) -> Result<DriverSource> {
    let url = url.trim_end_matches('/');

    if url.contains("github.com") {
        let (owner, repo) = parse_github_url(url)?;
        Ok(DriverSource::GitHub { owner, repo })
    } else if url.contains("pypi.org") {
        let package = parse_pypi_url(url)?;
        Ok(DriverSource::PyPI { package })
    } else {
        Err(AdbcIndexError::InvalidUrl(format!(
            "URL must be from github.com or pypi.org: {}",
            url
        )))
    }
}

/// Parse GitHub URL to extract owner and repo
/// Expected format: https://github.com/{owner}/{repo}
fn parse_github_url(url: &str) -> Result<(String, String)> {
    if !url.starts_with("https://github.com/") {
        return Err(AdbcIndexError::InvalidUrl(format!(
            "GitHub URL must start with https://github.com/: {}",
            url
        )));
    }

    let path = &url["https://github.com/".len()..];
    let parts: Vec<&str> = path.split('/').collect();

    if parts.len() < 2 {
        return Err(AdbcIndexError::InvalidUrl(format!(
            "GitHub URL must contain owner and repo: {}",
            url
        )));
    }

    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Parse PyPI URL to extract package name
/// Expected format: https://pypi.org/project/{package}/
fn parse_pypi_url(url: &str) -> Result<String> {
    if !url.starts_with("https://pypi.org/project/") {
        return Err(AdbcIndexError::InvalidUrl(format!(
            "PyPI URL must start with https://pypi.org/project/: {}",
            url
        )));
    }

    let path = &url["https://pypi.org/project/".len()..];
    let parts: Vec<&str> = path.split('/').collect();

    if parts.is_empty() || parts[0].is_empty() {
        return Err(AdbcIndexError::InvalidUrl(format!(
            "PyPI URL must contain package name: {}",
            url
        )));
    }

    Ok(parts[0].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_url() {
        let (owner, repo) = parse_github_url("https://github.com/apache/arrow-adbc").unwrap();
        assert_eq!(owner, "apache");
        assert_eq!(repo, "arrow-adbc");

        let (owner, repo) = parse_github_url("https://github.com/apache/arrow-adbc/").unwrap();
        assert_eq!(owner, "apache");
        assert_eq!(repo, "arrow-adbc");
    }

    #[test]
    fn test_parse_pypi_url() {
        let package = parse_pypi_url("https://pypi.org/project/adbc-driver-sqlite/").unwrap();
        assert_eq!(package, "adbc-driver-sqlite");

        let package = parse_pypi_url("https://pypi.org/project/adbc-driver-postgresql/").unwrap();
        assert_eq!(package, "adbc-driver-postgresql");
    }

    #[test]
    fn test_parse_driver_url_github() {
        let source = parse_driver_url("https://github.com/apache/arrow-adbc").unwrap();
        match source {
            DriverSource::GitHub { owner, repo } => {
                assert_eq!(owner, "apache");
                assert_eq!(repo, "arrow-adbc");
            }
            _ => panic!("Expected GitHub source"),
        }
    }

    #[test]
    fn test_parse_driver_url_pypi() {
        let source = parse_driver_url("https://pypi.org/project/adbc-driver-sqlite/").unwrap();
        match source {
            DriverSource::PyPI { package } => {
                assert_eq!(package, "adbc-driver-sqlite");
            }
            _ => panic!("Expected PyPI source"),
        }
    }

    #[test]
    fn test_source_id() {
        let github_source = DriverSource::GitHub {
            owner: "apache".to_string(),
            repo: "arrow-adbc".to_string(),
        };
        assert_eq!(github_source.source_id(), "github_apache_arrow-adbc");

        let pypi_source = DriverSource::PyPI {
            package: "adbc-driver-sqlite".to_string(),
        };
        assert_eq!(pypi_source.source_id(), "pypi_adbc-driver-sqlite");
    }

    #[test]
    fn test_version_requirement_parsing() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Test simple format (backward compatibility)
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[drivers]
sqlite = "https://pypi.org/project/adbc-driver-sqlite/"
"#
        )
        .unwrap();
        let cfg = load_config(file.path()).unwrap();
        let configs = cfg.drivers;
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "sqlite");
        assert_eq!(configs[0].sources.len(), 1);
        assert!(configs[0].version_req.is_none());
        assert!(configs[0].artifact_filter.is_none());

        // Test detailed format with version
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[drivers.duckdb]
urls = ["https://github.com/duckdb/duckdb"]
version = ">=0.8.0"
"#
        )
        .unwrap();
        let cfg = load_config(file.path()).unwrap();
        let configs = cfg.drivers;
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "duckdb");
        assert_eq!(configs[0].sources.len(), 1);
        assert!(configs[0].version_req.is_some());
        assert!(configs[0].artifact_filter.is_none());
        let version_req = configs[0].version_req.as_ref().unwrap();
        assert!(version_req.matches(&semver::Version::parse("0.8.0").unwrap()));
        assert!(version_req.matches(&semver::Version::parse("1.0.0").unwrap()));
        assert!(!version_req.matches(&semver::Version::parse("0.7.0").unwrap()));

        // Test detailed format with version and artifact filter
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[drivers.duckdb]
urls = ["https://github.com/duckdb/duckdb"]
version = ">=0.8.0"
artifact_filter = "libduckdb-*"
"#
        )
        .unwrap();
        let cfg = load_config(file.path()).unwrap();
        let configs = cfg.drivers;
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "duckdb");
        assert_eq!(configs[0].sources.len(), 1);
        assert!(configs[0].version_req.is_some());
        assert!(configs[0].artifact_filter.is_some());
        assert_eq!(configs[0].artifact_filter.as_ref().unwrap(), "libduckdb-*");

        // Test artifact matching
        assert!(configs[0].matches_artifact("libduckdb-osx-universal.zip"));
        assert!(!configs[0].matches_artifact("duckdb_cli-linux.zip"));

        // Test multiple URLs format
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[drivers.bigquery]
urls = ["https://pypi.org/project/adbc-driver-bigquery/", "https://github.com/adbc-drivers/bigquery"]
language = "go"
"#
        )
        .unwrap();
        let cfg = load_config(file.path()).unwrap();
        let configs = cfg.drivers;
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "bigquery");
        assert_eq!(configs[0].sources.len(), 2);
        assert_eq!(configs[0].language.as_ref().unwrap(), "go");

        // Test empty URLs array should error
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[drivers.empty]
urls = []
"#
        )
        .unwrap();
        let result = load_config(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_url() {
        assert!(parse_github_url("https://gitlab.com/owner/repo").is_err());
        assert!(parse_github_url("https://github.com/owner").is_err());
        assert!(parse_pypi_url("https://pypi.org/simple/package/").is_err());
        assert!(parse_driver_url("https://example.com/package").is_err());
    }
}
