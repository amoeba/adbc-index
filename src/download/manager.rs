use crate::error::{AdbcIndexError, Result};
use flate2::read::GzDecoder;
use futures::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tar::Archive;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use std::sync::Arc;

pub struct DownloadManager {
    client: reqwest::Client,
    cache_dir: PathBuf,
    semaphore: Arc<Semaphore>,
    multi_progress: MultiProgress,
}

#[derive(Debug, Clone)]
pub struct DownloadTask {
    pub url: String,
    pub driver_name: String,
    pub release_tag: String,
    pub artifact_name: String,
    pub expected_size: i64,
}

#[derive(Debug)]
pub struct DownloadResult {
    pub task: DownloadTask,
    pub sha256: String,
    pub path: PathBuf,
}

impl DownloadManager {
    pub fn new(cache_dir: PathBuf, max_concurrent: usize) -> Result<Self> {
        let client = reqwest::Client::builder()
            .build()?;

        Ok(Self {
            client,
            cache_dir,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            multi_progress: MultiProgress::new(),
        })
    }

    pub fn with_progress(cache_dir: PathBuf, max_concurrent: usize, multi_progress: Arc<MultiProgress>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .build()?;

        Ok(Self {
            client,
            cache_dir,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            multi_progress: (*multi_progress).clone(),
        })
    }

    /// Download all tasks concurrently with rate limiting
    pub async fn download_all(&self, tasks: Vec<DownloadTask>) -> Vec<Result<DownloadResult>> {
        let mut handles = Vec::new();

        for task in tasks {
            let manager = self.clone_for_task();
            let handle = tokio::spawn(async move {
                manager.download_task(task).await
            });
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(AdbcIndexError::Download {
                    url: "unknown".to_string(),
                    reason: e.to_string(),
                })),
            }
        }

        results
    }

    fn clone_for_task(&self) -> Self {
        Self {
            client: self.client.clone(),
            cache_dir: self.cache_dir.clone(),
            semaphore: self.semaphore.clone(),
            multi_progress: self.multi_progress.clone(),
        }
    }

    async fn download_task(&self, task: DownloadTask) -> Result<DownloadResult> {
        let _permit = self.semaphore.acquire().await.unwrap();

        let cache_path = self.get_cache_path(&task);
        let sha256_path = get_sha256_path(&cache_path);

        // Check if file already exists and has valid SHA256
        if cache_path.exists() && sha256_path.exists() {
            // Read stored SHA256
            if let Ok(stored_sha256) = fs::read_to_string(&sha256_path).await {
                let stored_sha256 = stored_sha256.trim();

                // Verify file integrity by computing SHA256
                if let Ok(computed_sha256) = compute_file_sha256(&cache_path).await {
                    if computed_sha256 == stored_sha256 {
                        // File exists and integrity verified
                        // Extract .tar.gz if not already extracted
                        if task.artifact_name.ends_with(".tar.gz") {
                            let _ = extract_tar_gz(&cache_path).await;
                        }

                        return Ok(DownloadResult {
                            task,
                            sha256: computed_sha256,
                            path: cache_path,
                        });
                    }
                }
            }
        }

        // Create parent directory
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Download file
        let response = self.client.get(&task.url).send().await?;

        if !response.status().is_success() {
            return Err(AdbcIndexError::Download {
                url: task.url.clone(),
                reason: format!("HTTP {}", response.status()),
            });
        }

        // Create progress bar
        let pb = self.multi_progress.add(ProgressBar::new(task.expected_size as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  ├─ {msg} [{bar:30}] {bytes}/{total_bytes}")
                .unwrap()
                .progress_chars("█▓░"),
        );
        pb.set_message(format!("{}/{}", task.driver_name, task.artifact_name));

        // Stream download and compute SHA256
        let mut file = File::create(&cache_path).await?;
        let mut hasher = Sha256::new();
        let mut stream = response.bytes_stream();
        let mut downloaded = 0u64;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| AdbcIndexError::Download {
                url: task.url.clone(),
                reason: e.to_string(),
            })?;

            file.write_all(&chunk).await?;
            hasher.update(&chunk);
            downloaded += chunk.len() as u64;
            pb.set_position(downloaded);
        }

        file.flush().await?;
        pb.finish_and_clear();

        let sha256 = format!("{:x}", hasher.finalize());

        // Write SHA256 to sidecar file
        let sha256_path = get_sha256_path(&cache_path);
        let _ = fs::write(&sha256_path, &sha256).await;

        // Extract .tar.gz files after download
        if task.artifact_name.ends_with(".tar.gz") {
            let _ = extract_tar_gz(&cache_path).await;
        }

        Ok(DownloadResult {
            task,
            sha256,
            path: cache_path,
        })
    }

    fn get_cache_path(&self, task: &DownloadTask) -> PathBuf {
        use crate::models::ReleaseRecord;
        let sanitized_tag = ReleaseRecord::sanitize_tag_for_path(&task.release_tag);
        self.cache_dir
            .join(&task.driver_name)
            .join(&sanitized_tag)
            .join(&task.artifact_name)
    }
}

/// Compute SHA256 hash of an existing file
async fn compute_file_sha256(path: &Path) -> Result<String> {
    let content = fs::read(path).await?;
    let hash = Sha256::digest(&content);
    Ok(format!("{:x}", hash))
}

/// Extract a .tar.gz file to the same directory
async fn extract_tar_gz(archive_path: &Path) -> Result<()> {
    let archive_path = archive_path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        // Get the directory where the archive is located
        let extract_dir = archive_path.parent().ok_or_else(|| {
            AdbcIndexError::Download {
                url: "".to_string(),
                reason: "Invalid archive path".to_string(),
            }
        })?;

        // Open and extract the archive
        let file = std::fs::File::open(&archive_path)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        archive.unpack(extract_dir)?;

        Ok::<(), AdbcIndexError>(())
    })
    .await
    .map_err(|e| AdbcIndexError::Download {
        url: "".to_string(),
        reason: format!("Extraction task failed: {}", e),
    })?
}

/// Get the path for the SHA256 sidecar file
fn get_sha256_path(file_path: &Path) -> PathBuf {
    let mut path = file_path.to_path_buf();
    let filename = path.file_name().unwrap().to_string_lossy().to_string();
    path.set_file_name(format!("{}.sha256", filename));
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_sha256_path() {
        let file_path = Path::new("/cache/mysql/0.2.0/mysql_linux_amd64.tar.gz");
        let sha256_path = get_sha256_path(file_path);
        assert_eq!(
            sha256_path,
            Path::new("/cache/mysql/0.2.0/mysql_linux_amd64.tar.gz.sha256")
        );

        let file_path = Path::new("artifact.zip");
        let sha256_path = get_sha256_path(file_path);
        assert_eq!(sha256_path, Path::new("artifact.zip.sha256"));
    }
}
