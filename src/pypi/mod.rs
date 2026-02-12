mod client;
mod types;

pub use client::PyPIClient;
pub use types::PyPIRelease;

use crate::github::types::{Asset, Release};

/// Convert PyPI releases to GitHub Release format for compatibility
pub fn pypi_to_github_releases(pypi_releases: Vec<PyPIRelease>, package: &str) -> Vec<Release> {
    pypi_releases
        .into_iter()
        .map(|pr| {
            let version = pr.version.clone();

            // Use the earliest upload time as the published_at time
            let published_at = pr.wheels.iter().map(|w| w.upload_time).min();

            // Convert wheels to assets
            let assets = pr
                .wheels
                .into_iter()
                .map(|wheel| Asset {
                    name: wheel.filename.clone(),
                    browser_download_url: wheel.url.clone(),
                    url: Some(wheel.url), // PyPI URLs don't have the slash issue
                    size: wheel.size,
                    download_count: 0,
                })
                .collect();

            Release {
                tag_name: version.clone(),
                name: Some(format!("{} {}", package, version)),
                published_at,
                html_url: format!("https://pypi.org/project/{}/{}/", package, version),
                assets,
            }
        })
        .collect()
}
