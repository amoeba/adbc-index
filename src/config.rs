use crate::error::{DashError, Result};
use crate::models::DriverConfig;
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
        let (owner, repo) = parse_github_url(&url)?;
        configs.push(DriverConfig { name, owner, repo });
    }

    Ok(configs)
}

/// Parse GitHub URL to extract owner and repo
/// Expected format: https://github.com/{owner}/{repo}
fn parse_github_url(url: &str) -> Result<(String, String)> {
    let url = url.trim_end_matches('/');

    if !url.starts_with("https://github.com/") {
        return Err(DashError::InvalidUrl(format!(
            "URL must start with https://github.com/: {}",
            url
        )));
    }

    let path = &url["https://github.com/".len()..];
    let parts: Vec<&str> = path.split('/').collect();

    if parts.len() < 2 {
        return Err(DashError::InvalidUrl(format!(
            "URL must contain owner and repo: {}",
            url
        )));
    }

    Ok((parts[0].to_string(), parts[1].to_string()))
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
    fn test_parse_invalid_url() {
        assert!(parse_github_url("https://gitlab.com/owner/repo").is_err());
        assert!(parse_github_url("https://github.com/owner").is_err());
    }
}
