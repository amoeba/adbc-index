use crate::error::{AdbcIndexError, Result};
use crate::pypi::types::{PyPIAsset, PyPIPackage, PyPIRelease};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};

const PYPI_API_BASE: &str = "https://pypi.org/pypi";

#[derive(Clone)]
pub struct PyPIClient {
    client: reqwest::Client,
}

impl PyPIClient {
    pub fn new() -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("adbc-index"));

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;

        Ok(Self { client })
    }

    /// Fetch all releases for a PyPI package
    pub async fn fetch_releases(&self, package: &str) -> Result<Vec<PyPIRelease>> {
        let url = format!("{}/{}/json", PYPI_API_BASE, package);

        let response = self.client.get(&url).send().await?;

        let status = response.status();

        if !status.is_success() {
            let error_body = response.text().await?;
            return Err(AdbcIndexError::PyPIApi {
                status: status.as_u16(),
                message: error_body,
            });
        }

        let pkg_data: PyPIPackage = response.json().await?;

        // Convert releases to our internal format
        let mut releases = Vec::new();

        for (version, files) in pkg_data.releases {
            // Filter for wheel files only
            let wheels: Vec<PyPIAsset> = files
                .into_iter()
                .filter(|f| f.packagetype == "bdist_wheel" && f.filename.ends_with(".whl"))
                .map(|f| PyPIAsset {
                    filename: f.filename,
                    url: f.url,
                    sha256: f.digests.sha256,
                    upload_time: f.upload_time,
                    size: f.size,
                })
                .collect();

            // Only include versions that have wheel files
            if !wheels.is_empty() {
                releases.push(PyPIRelease { version, wheels });
            }
        }

        // Sort by version (most recent first based on upload time of first wheel)
        releases.sort_by(|a, b| {
            let a_time = a.wheels.first().map(|w| w.upload_time).unwrap_or_default();
            let b_time = b.wheels.first().map(|w| w.upload_time).unwrap_or_default();
            b_time.cmp(&a_time)
        });

        Ok(releases)
    }
}
