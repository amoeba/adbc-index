use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PyPI package metadata response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyPIPackage {
    pub info: PackageInfo,
    pub releases: HashMap<String, Vec<ReleaseFile>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
}

/// A single file in a PyPI release
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseFile {
    pub filename: String,
    pub url: String,
    pub digests: Digests,
    #[serde(rename = "upload_time_iso_8601")]
    pub upload_time: DateTime<Utc>,
    pub size: i64,
    pub packagetype: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digests {
    pub sha256: String,
}

/// Parsed release information (normalized for our use)
#[derive(Debug, Clone)]
pub struct PyPIRelease {
    pub version: String,
    pub wheels: Vec<PyPIAsset>,
}

#[derive(Debug, Clone)]
pub struct PyPIAsset {
    pub filename: String,
    pub url: String,
    #[allow(dead_code)]
    pub sha256: String,
    pub upload_time: DateTime<Utc>,
    pub size: i64,
}
