use thiserror::Error;

#[derive(Error, Debug)]
pub enum AdbcIndexError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP request failed: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Parquet error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),

    #[error("Arrow error: {0}")]
    Arrow(#[from] arrow::error::ArrowError),

    #[error("Binary parsing error: {0}")]
    Goblin(#[from] goblin::error::Error),

    #[error("Invalid GitHub URL: {0}")]
    InvalidUrl(String),

    #[error("GitHub API error: {status} - {message}")]
    GitHubApi { status: u16, message: String },

    #[error("Missing GitHub token. Set GITHUB_TOKEN environment variable")]
    MissingToken,

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Download failed for {url}: {reason}")]
    Download { url: String, reason: String },
}

pub type Result<T> = std::result::Result<T, AdbcIndexError>;
