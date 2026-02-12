use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub name: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub html_url: String,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub url: Option<String>, // API URL that works for tags with slashes
    pub size: i64,
    #[serde(default)]
    pub download_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubError {
    pub message: String,
    pub documentation_url: Option<String>,
}
