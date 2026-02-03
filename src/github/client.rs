use crate::error::{AdbcIndexError, Result};
use crate::github::types::{GitHubError, Release};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};

const GITHUB_API_BASE: &str = "https://api.github.com";
const PER_PAGE: u32 = 100;

pub struct GitHubClient {
    client: reqwest::Client,
    token: Option<String>,
}

impl GitHubClient {
    pub fn new(token: Option<String>) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("adbc-index"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github.v3+json"),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;

        Ok(Self { client, token })
    }

    /// Fetch all releases for a repository
    pub async fn fetch_releases(&self, owner: &str, repo: &str) -> Result<Vec<Release>> {
        let mut all_releases = Vec::new();
        let mut page = 1;

        loop {
            let url = format!(
                "{}/repos/{}/{}/releases?per_page={}&page={}",
                GITHUB_API_BASE, owner, repo, PER_PAGE, page
            );

            let mut request = self.client.get(&url);

            if let Some(token) = &self.token {
                request = request.header(AUTHORIZATION, format!("Bearer {}", token));
            }

            let response = request.send().await?;

            let status = response.status();

            if !status.is_success() {
                let error_body = response.text().await?;
                let error_msg = match serde_json::from_str::<GitHubError>(&error_body) {
                    Ok(gh_err) => gh_err.message,
                    Err(_) => error_body,
                };

                return Err(AdbcIndexError::GitHubApi {
                    status: status.as_u16(),
                    message: error_msg,
                });
            }

            let releases: Vec<Release> = response.json().await?;

            if releases.is_empty() {
                break;
            }

            all_releases.extend(releases);
            page += 1;

            // GitHub API has a max of 100 pages
            if page > 100 {
                break;
            }
        }

        Ok(all_releases)
    }

    /// Check rate limit status
    pub async fn check_rate_limit(&self) -> Result<RateLimit> {
        let url = format!("{}/rate_limit", GITHUB_API_BASE);

        let mut request = self.client.get(&url);

        if let Some(token) = &self.token {
            request = request.header(AUTHORIZATION, format!("Bearer {}", token));
        }

        let response = request.send().await?;

        let data: serde_json::Value = response.json().await?;
        let core = &data["resources"]["core"];

        Ok(RateLimit {
            limit: core["limit"].as_u64().unwrap_or(0),
            remaining: core["remaining"].as_u64().unwrap_or(0),
            reset: core["reset"].as_u64().unwrap_or(0),
        })
    }
}

#[derive(Debug)]
pub struct RateLimit {
    pub limit: u64,
    pub remaining: u64,
    pub reset: u64,
}
