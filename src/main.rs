mod artifact_parser;
mod config;
mod download;
mod error;
mod github;
mod models;
mod parquet;

use clap::{Parser, Subcommand};
use error::Result;
use models::ReleaseRecord;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "dash")]
#[command(about = "ADBC Driver Release Artifact Downloader and Statistics Handler", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Sync cache directory with remote GitHub releases
    Sync,
    /// Analyze cache directory and create parquet reports
    Report,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sync => sync().await,
        Commands::Report => report().await,
    }
}

async fn sync() -> Result<()> {
    // Hardcoded configuration
    let config = PathBuf::from("drivers.toml");
    let cache_dir = PathBuf::from("cache");
    let concurrent_downloads = 5;

    // Get GitHub token (optional)
    let github_token = std::env::var("GITHUB_TOKEN").ok();

    println!("🚀 dash sync - Syncing with GitHub releases");
    println!();

    // Load configuration
    println!("📋 Loading configuration from {:?}", config);
    let drivers = config::load_config(&config)?;
    println!("   Found {} drivers", drivers.len());
    println!();

    // Create GitHub client
    let gh_client = if let Some(ref token) = github_token {
        println!("🔑 Using GitHub token for authentication");
        println!();
        github::GitHubClient::new(Some(token.clone()))?
    } else {
        println!("⚠️  No GitHub token found - using unauthenticated requests (lower rate limits)");
        println!();
        github::GitHubClient::new(None)?
    };

    // Check rate limit
    let rate_limit = gh_client.check_rate_limit().await?;
    println!(
        "⚡ GitHub API Rate Limit: {}/{}",
        rate_limit.remaining, rate_limit.limit
    );
    println!();

    // Fetch releases for all drivers
    let mut download_tasks = Vec::new();
    let mut cached_count = 0;
    let mut driver_fetch_errors = 0;

    for driver in &drivers {
        println!("📦 Fetching releases for {}", driver.name);
        println!("   Repository: {}/{}", driver.owner, driver.repo);

        match gh_client.fetch_releases(&driver.owner, &driver.repo).await {
            Ok(releases) => {
                println!("   Found {} releases", releases.len());

                let mut driver_new = 0;
                let mut driver_cached = 0;

                for release in &releases {
                    let tag = release.tag_name.clone();
                    let sanitized_tag = ReleaseRecord::sanitize_tag_for_path(&tag);

                    // Save release JSON to cache directory
                    let release_dir = cache_dir.join(&driver.name).join(&sanitized_tag);
                    if let Err(e) = std::fs::create_dir_all(&release_dir) {
                        eprintln!("⚠️  Failed to create release directory: {}", e);
                    } else {
                        let release_json_path = release_dir.join("release.json");
                        match serde_json::to_string_pretty(&release) {
                            Ok(json) => {
                                if let Err(e) = std::fs::write(&release_json_path, json) {
                                    eprintln!("⚠️  Failed to write release.json: {}", e);
                                }
                            }
                            Err(e) => {
                                eprintln!("⚠️  Failed to serialize release JSON: {}", e);
                            }
                        }
                    }

                    for asset in &release.assets {
                        // Check if artifact already exists in cache with valid SHA256
                        let cache_path = cache_dir
                            .join(&driver.name)
                            .join(&sanitized_tag)
                            .join(&asset.name);

                        // Get SHA256 sidecar path
                        let sha256_filename = format!("{}.sha256", asset.name);
                        let sha256_path = cache_path.parent().unwrap().join(&sha256_filename);

                        // Consider it cached if both the file and its SHA256 sidecar exist
                        let already_cached = cache_path.exists() && sha256_path.exists();

                        if already_cached {
                            cached_count += 1;
                            driver_cached += 1;
                        } else {
                            download_tasks.push(download::DownloadTask {
                                url: asset.browser_download_url.clone(),
                                driver_name: driver.name.clone(),
                                release_tag: tag.clone(),
                                artifact_name: asset.name.clone(),
                                expected_size: asset.size,
                            });
                            driver_new += 1;
                        }
                    }
                }

                println!("   Artifacts: {} new, {} cached", driver_new, driver_cached);
            }
            Err(e) => {
                eprintln!("   ⚠️  Error fetching releases: {}", e);
                eprintln!("   Continuing with other drivers...");
                driver_fetch_errors += 1;
            }
        }

        println!();
    }

    // Fail if any driver failed to fetch
    if driver_fetch_errors > 0 {
        return Err(error::DashError::Config(
            format!("Failed to fetch releases from {} driver(s). Sync aborted.", driver_fetch_errors)
        ));
    }

    println!("📊 Sync summary:");
    println!("   {} artifacts already cached", cached_count);
    println!("   {} artifacts to download", download_tasks.len());
    println!();

    // Download artifacts
    if !download_tasks.is_empty() {
        println!("⬇️  Downloading {} artifacts...", download_tasks.len());
        println!();

        let download_manager =
            download::DownloadManager::new(cache_dir.clone(), concurrent_downloads)?;

        let results = download_manager.download_all(download_tasks).await;

        let mut success_count = 0;
        let mut error_count = 0;

        for result in results {
            match result {
                Ok(_) => {
                    success_count += 1;
                }
                Err(e) => {
                    eprintln!("   ⚠️  Download error: {}", e);
                    error_count += 1;
                }
            }
        }

        println!();
        println!(
            "✅ Sync complete: {} artifacts downloaded ({} errors)",
            success_count, error_count
        );
        println!("Cache directory: {:?}", cache_dir);

        if error_count > 0 {
            return Err(error::DashError::Download {
                url: "multiple".to_string(),
                reason: format!("{} artifact(s) failed to download", error_count),
            });
        }
    } else {
        println!("✅ No new artifacts to download");
    }

    Ok(())
}

async fn report() -> Result<()> {
    // Run sync first - if it fails, report fails
    println!("🔄 Running sync before generating report...");
    println!();
    sync().await?;
    println!();

    let config = PathBuf::from("drivers.toml");
    let cache_dir = PathBuf::from("cache");

    // Get GitHub token (optional)
    let github_token = std::env::var("GITHUB_TOKEN").ok();

    println!("📊 dash report - Generating parquet reports");
    println!();

    // Load configuration
    println!("📋 Loading configuration from {:?}", config);
    let drivers = config::load_config(&config)?;
    println!("   Found {} drivers", drivers.len());
    println!();

    // Create GitHub client
    let gh_client = if let Some(ref token) = github_token {
        println!("🔑 Using GitHub token for authentication");
        println!();
        github::GitHubClient::new(Some(token.clone()))?
    } else {
        println!("⚠️  No GitHub token found - using unauthenticated requests (lower rate limits)");
        println!();
        github::GitHubClient::new(None)?
    };

    // Check rate limit
    let rate_limit = gh_client.check_rate_limit().await?;
    println!(
        "⚡ GitHub API Rate Limit: {}/{}",
        rate_limit.remaining, rate_limit.limit
    );
    println!();

    use std::collections::{HashMap, HashSet};
    use models::LibraryRecord;

    // Track releases and libraries separately
    let mut library_records = Vec::new();
    let mut release_data: HashMap<(String, String), (Option<String>, chrono::DateTime<chrono::Utc>, String, HashSet<String>, HashSet<String>)> = HashMap::new();

    for driver in &drivers {
        println!("📦 Fetching releases for {}", driver.name);
        println!("   Repository: {}/{}", driver.owner, driver.repo);

        match gh_client.fetch_releases(&driver.owner, &driver.repo).await {
            Ok(releases) => {
                println!("   Found {} releases", releases.len());

                for release in &releases {
                    let release_url = release.html_url.clone();
                    let tag = release.tag_name.clone();
                    let version = models::ReleaseRecord::parse_version(&tag);
                    let published_date = release
                        .published_at
                        .unwrap_or_else(|| chrono::Utc::now());

                    for asset in &release.assets {
                        // Parse artifact metadata
                        let artifact_meta = artifact_parser::parse_artifact(&asset.name);

                        // Skip non-driver artifacts (docs, configs, etc.)
                        if !is_driver_artifact(&artifact_meta.file_format) {
                            continue;
                        }

                        // Extract archive and find shared library
                        let library_info = extract_and_find_library(
                            &cache_dir,
                            &driver.name,
                            &tag,
                            &asset.name,
                        );

                        // Only process if we found a library
                        if let Some(lib_info) = library_info {
                            if let (Some(os), Some(arch)) = (&artifact_meta.os, &artifact_meta.arch) {
                                // Add to library records
                                library_records.push(LibraryRecord {
                                    name: driver.name.clone(),
                                    release_tag: tag.clone(),
                                    version: version.clone(),
                                    published_date,
                                    os: os.clone(),
                                    arch: arch.clone(),
                                    library_name: lib_info.name,
                                    library_size_bytes: lib_info.size,
                                    library_sha256: lib_info.sha256.unwrap_or_default(),
                                    artifact_name: asset.name.clone(),
                                    artifact_url: asset.browser_download_url.clone(),
                                });

                                // Aggregate release data
                                let key = (driver.name.clone(), tag.clone());
                                release_data.entry(key)
                                    .or_insert_with(|| (version.clone(), published_date, release_url.clone(), HashSet::new(), HashSet::new()))
                                    .3.insert(os.clone());
                                release_data.get_mut(&(driver.name.clone(), tag.clone())).unwrap()
                                    .4.insert(arch.clone());
                            }
                        }
                    }
                }

                let total_artifacts: usize = releases.iter().map(|r| r.assets.len()).sum();
                println!("   Total artifacts: {}", total_artifacts);
            }
            Err(e) => {
                eprintln!("   ⚠️  Error fetching releases: {}", e);
                eprintln!("   Continuing with other drivers...");
            }
        }

        println!();
    }

    println!("📊 Total library records: {}", library_records.len());
    println!("📊 Total releases: {}", release_data.len());
    println!();

    // Convert release_data to ReleaseRecords
    let mut release_records: Vec<models::ReleaseRecord> = release_data
        .into_iter()
        .map(|((name, release_tag), (version, published_date, release_url, os_set, arch_set))| {
            let mut os: Vec<String> = os_set.into_iter().collect();
            let mut arch: Vec<String> = arch_set.into_iter().collect();
            os.sort();
            arch.sort();

            models::ReleaseRecord {
                name,
                release_tag,
                version,
                published_date,
                release_url,
                os,
                arch,
            }
        })
        .collect();

    // Sort by name, then by release_tag
    release_records.sort_by(|a, b| {
        a.name.cmp(&b.name).then_with(|| a.release_tag.cmp(&b.release_tag))
    });

    // Write releases.parquet
    let releases_output = PathBuf::from("releases.parquet");
    println!("💾 Writing to {:?}", releases_output);
    let mut releases_writer = parquet::ReleasesWriter::new(&releases_output)?;
    for record in release_records {
        releases_writer.add_record(record)?;
    }
    releases_writer.close()?;
    println!("   ✓ Written {} releases", library_records.len());

    // Write libraries.parquet
    let libraries_output = PathBuf::from("libraries.parquet");
    println!("💾 Writing to {:?}", libraries_output);
    let mut libraries_writer = parquet::LibrariesWriter::new(&libraries_output)?;
    for record in library_records {
        libraries_writer.add_record(record)?;
    }
    libraries_writer.close()?;

    println!();
    println!("✨ Done!");
    println!();
    println!("Output files:");
    println!("  - {:?}", releases_output);
    println!("  - {:?}", libraries_output);

    Ok(())
}

/// Information about an extracted shared library
#[derive(Debug, Clone)]
struct LibraryInfo {
    name: String,
    size: i64,
    sha256: Option<String>,
}

/// Extract archive and find the shared library inside
fn extract_and_find_library(
    cache_dir: &PathBuf,
    driver_name: &str,
    release_tag: &str,
    artifact_name: &str,
) -> Option<LibraryInfo> {
    use flate2::read::GzDecoder;
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::Read;
    use tar::Archive;
    use zip::ZipArchive;

    let sanitized_tag = ReleaseRecord::sanitize_tag_for_path(release_tag);
    let artifact_path = cache_dir
        .join(driver_name)
        .join(&sanitized_tag)
        .join(artifact_name);

    if !artifact_path.exists() {
        return None;
    }

    // Determine archive type and extract
    if artifact_name.ends_with(".tar.gz") || artifact_name.ends_with(".tgz") {
        // Extract tar.gz
        let file = File::open(&artifact_path).ok()?;
        let gz = GzDecoder::new(file);
        let mut archive = Archive::new(gz);

        for entry in archive.entries().ok()? {
            let mut entry = entry.ok()?;
            let path = entry.path().ok()?;
            let filename = path.file_name()?.to_str()?.to_string();

            // Check if this is a shared library
            if filename.ends_with(".so") || filename.ends_with(".dylib") || filename.ends_with(".dll") {
                let size = entry.size() as i64;

                // Compute SHA256
                let mut hasher = Sha256::new();
                let mut buffer = vec![0; 8192];
                loop {
                    let n = entry.read(&mut buffer).ok()?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                let sha256 = format!("{:x}", hasher.finalize());

                return Some(LibraryInfo {
                    name: filename,
                    size,
                    sha256: Some(sha256),
                });
            }
        }
    } else if artifact_name.ends_with(".zip") {
        // Extract zip
        let file = File::open(&artifact_path).ok()?;
        let mut archive = ZipArchive::new(file).ok()?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).ok()?;
            let filename = file.name().split('/').last()?.to_string();

            // Check if this is a shared library
            if filename.ends_with(".so") || filename.ends_with(".dylib") || filename.ends_with(".dll") {
                let size = file.size() as i64;

                // Compute SHA256
                let mut hasher = Sha256::new();
                let mut buffer = vec![0; 8192];
                loop {
                    let n = file.read(&mut buffer).ok()?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                let sha256 = format!("{:x}", hasher.finalize());

                return Some(LibraryInfo {
                    name: filename,
                    size,
                    sha256: Some(sha256),
                });
            }
        }
    }

    None
}

/// Check if an artifact is a driver build (vs documentation, config, etc.)
fn is_driver_artifact(file_format: &Option<String>) -> bool {
    match file_format.as_deref() {
        // Archive formats
        Some("tar.gz") | Some("tar.bz2") | Some("tar.xz") | Some("tgz") => true,
        Some("zip") | Some("gz") | Some("bz2") | Some("xz") => true,
        // Binary formats
        Some("so") | Some("dylib") | Some("dll") => true,
        Some("a") | Some("lib") => true,
        // Executable formats
        Some("exe") | Some("bin") => true,
        // Package formats
        Some("deb") | Some("rpm") | Some("apk") | Some("pkg") => true,
        Some("msi") | Some("dmg") => true,
        // Wheel/egg for Python
        Some("whl") | Some("egg") => true,
        // JAR for Java
        Some("jar") => true,
        // Reject documentation and config files
        Some("md") | Some("txt") | Some("yaml") | Some("yml") => false,
        Some("json") | Some("toml") | Some("xml") => false,
        Some("rst") | Some("adoc") | Some("pdf") => false,
        Some("asc") | Some("sig") => false, // signatures
        // Unknown or no extension - reject to be safe
        None => false,
        Some(_) => false,
    }
}

