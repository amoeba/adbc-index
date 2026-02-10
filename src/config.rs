use crate::error::{AdbcIndexError, Result};
use crate::models::{DriverConfig, DriverSource};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Deserialize)]
struct ConfigFile {
    drivers: HashMap<String, String>,
}

/// Parse drivers.toml configuration file
pub fn load_config(path: &Path) -> Result<Vec<DriverConfig>> {
    let content = fs::read_to_string(path)?;
    let config: ConfigFile = toml::from_str(&content)?;

    let mut configs = Vec::new();

    for (name, url) in config.drivers {
        let source = parse_driver_url(&url)?;
        configs.push(DriverConfig { name, source });
    }

    Ok(configs)
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
    fn test_parse_invalid_url() {
        assert!(parse_github_url("https://gitlab.com/owner/repo").is_err());
        assert!(parse_github_url("https://github.com/owner").is_err());
        assert!(parse_pypi_url("https://pypi.org/simple/package/").is_err());
        assert!(parse_driver_url("https://example.com/package").is_err());
    }
}
