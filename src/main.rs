mod artifact_parser;
mod config;
mod download;
mod error;
mod github;
mod models;
mod parquet;
mod progress;
mod pypi;
mod stub_detector;
mod symbols;

use clap::{Parser, Subcommand};
use error::Result;
use models::ReleaseRecord;
use std::path::PathBuf;
use tera::{Tera, Context};

#[derive(Parser, Debug)]
#[command(name = "adbc-index")]
#[command(about = "ADBC Index - Index and analyze ADBC driver releases and libraries", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Download cache directory with remote GitHub releases
    Download {
        /// Optional driver name to download (downloads all drivers if not specified)
        driver: Option<String>,
    },
    /// Download releases, analyze cache, and generate HTML dashboard
    Build,
    /// Generate HTML dashboard from existing parquet files
    Html,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Download { driver } => download(driver).await,
        Commands::Build => build().await,
        Commands::Html => html().await,
    }
}

async fn download(driver_filter: Option<String>) -> Result<()> {
    // Hardcoded configuration
    let config = PathBuf::from("drivers.toml");
    let cache_dir = PathBuf::from("cache");
    let concurrent_downloads = 5;

    // Require GitHub token
    let github_token = std::env::var("GITHUB_TOKEN").map_err(|_| {
        error::AdbcIndexError::Config(
            "GITHUB_TOKEN environment variable is not set. Please set it with: export GITHUB_TOKEN=your_token_here".to_string()
        )
    })?;

    // Verify GitHub token works
    let gh_client = github::GitHubClient::new(Some(github_token.clone()))?;
    match gh_client.check_rate_limit().await {
        Ok(rate_limit) => {
            eprintln!("✓ GitHub token verified. Rate limit: {}/{}", rate_limit.remaining, rate_limit.limit);
        }
        Err(e) => {
            eprintln!("⚠️  Warning: GitHub token may be invalid: {}", e);
            eprintln!("   Make sure your GITHUB_TOKEN has 'public_repo' or 'repo' scope");
        }
    }

    // Load configuration
    let mut drivers = config::load_config(&config)?;

    // Filter to specific driver if requested
    if let Some(ref driver_name) = driver_filter {
        drivers.retain(|d| d.name == *driver_name);
        if drivers.is_empty() {
            return Err(error::AdbcIndexError::Config(
                format!("Driver '{}' not found in configuration", driver_name)
            ));
        }
    }

    // Create GitHub client
    let gh_client = github::GitHubClient::new(Some(github_token.clone()))?;

    // Create PyPI client
    let pypi_client = pypi::PyPIClient::new()?;

    // Check rate limit for GitHub only
    let _rate_limit = gh_client.check_rate_limit().await?;

    // Create progress tracker
    let progress = progress::ProgressTracker::new(drivers.len() as u64, "Download");
    progress.set_message("Fetching releases");

    // Fetch releases for all drivers
    let mut download_tasks = Vec::new();
    let mut cached_count = 0;
    let mut driver_fetch_errors = 0;

    for (idx, driver) in drivers.iter().enumerate() {
        let driver_progress = progress.add_spinner(&driver.name, "Fetching releases");

        if std::env::var("DEBUG").is_ok() {
            eprintln!("DEBUG: Fetching releases for driver: {}", driver.name);
        }

        // Fetch releases based on source type
        let releases_result = match &driver.source {
            models::DriverSource::GitHub { owner, repo } => {
                if std::env::var("DEBUG").is_ok() {
                    eprintln!("DEBUG: Fetching from GitHub: {}/{}", owner, repo);
                }
                gh_client.fetch_releases(owner, repo).await
            }
            models::DriverSource::PyPI { package } => {
                pypi_client.fetch_releases(package).await
                    .map(|pypi_releases| pypi::pypi_to_github_releases(pypi_releases, package))
            }
        };

        if std::env::var("DEBUG").is_ok() {
            eprintln!("DEBUG: Processing releases_result...");
        }

        match releases_result {
            Ok(mut releases) => {
                if std::env::var("DEBUG").is_ok() {
                    eprintln!("DEBUG: Got {} releases, filtering...", releases.len());
                }

                // Filter releases by version requirement if specified
                if let Some(ref version_req) = driver.version_req {
                    releases.retain(|release| {
                        if let Some(version_str) = ReleaseRecord::parse_version(&release.tag_name) {
                            if let Ok(version) = semver::Version::parse(&version_str) {
                                return version_req.matches(&version);
                            }
                        }
                        true
                    });
                }

                let mut driver_new = 0;
                let mut driver_cached = 0;

                if std::env::var("DEBUG").is_ok() {
                    eprintln!("DEBUG: Processing {} releases...", releases.len());
                }

                for release in &releases {
                    let tag = release.tag_name.clone();

                    if std::env::var("DEBUG").is_ok() {
                        eprintln!("DEBUG: Processing release: {}", tag);
                    }

                    let sanitized_tag = ReleaseRecord::sanitize_tag_for_path(&tag);

                    // Save release JSON to cache directory
                    let release_dir = cache_dir.join(&driver.name).join(&sanitized_tag);
                    if std::fs::create_dir_all(&release_dir).is_ok() {
                        let release_json_path = release_dir.join("release.json");
                        if let Ok(json) = serde_json::to_string_pretty(&release) {
                            let _ = std::fs::write(&release_json_path, json);
                        }
                    }

                    for asset in &release.assets {
                        if std::env::var("DEBUG").is_ok() {
                            eprintln!("DEBUG:   Asset: {}", asset.name);
                        }

                        // Skip artifacts that don't match the filter pattern
                        if !driver.matches_artifact(&asset.name) {
                            if std::env::var("DEBUG").is_ok() {
                                eprintln!("DEBUG:   Skipping (doesn't match filter)");
                            }
                            continue;
                        }

                        // Check if artifact already exists in cache with valid SHA256
                        let cache_path = cache_dir
                            .join(&driver.name)
                            .join(&sanitized_tag)
                            .join(&asset.name);

                        let sha256_filename = format!("{}.sha256", asset.name);
                        let sha256_path = cache_path.parent().unwrap().join(&sha256_filename);

                        let already_cached = cache_path.exists() && sha256_path.exists();

                        if std::env::var("DEBUG").is_ok() {
                            eprintln!("DEBUG:   Cached: {}", already_cached);
                        }

                        if already_cached {
                            cached_count += 1;
                            driver_cached += 1;
                        } else {
                            if std::env::var("DEBUG").is_ok() {
                                eprintln!("DEBUG:   Adding to download queue");
                            }

                            // Use API URL instead of browser_download_url for tags with slashes
                            // GitHub has a bug where browser_download_url doesn't work for tags with /
                            // The API url works: needs Accept: application/octet-stream header
                            let (download_url, url_type) = if tag.contains('/') {
                                (asset.url.clone(), "API")
                            } else {
                                (asset.browser_download_url.clone(), "direct")
                            };

                            if std::env::var("DEBUG").is_ok() {
                                eprintln!("DEBUG:   URL type: {} for {}", url_type, asset.name);
                            }

                            download_tasks.push(download::DownloadTask {
                                url: download_url,
                                driver_name: driver.name.clone(),
                                release_tag: tag.clone(),
                                artifact_name: asset.name.clone(),
                                expected_size: asset.size,
                            });
                            driver_new += 1;
                        }
                    }
                }

                if std::env::var("DEBUG").is_ok() {
                    eprintln!("DEBUG: Finishing driver progress: {} new, {} cached", driver_new, driver_cached);
                }
                driver_progress.finish_with_message(format!("{} new, {} cached", driver_new, driver_cached));
            }
            Err(e) => {
                    eprintln!("  ⚠️  Download error: {}", e);
                driver_progress.finish_with_message(format!("Error: {}", e));
                driver_fetch_errors += 1;
            }
        }

        if std::env::var("DEBUG").is_ok() {
            eprintln!("DEBUG: Setting progress position to {}", idx + 1);
        }
        progress.set_position((idx + 1) as u64);
    }

    if std::env::var("DEBUG").is_ok() {
        eprintln!("DEBUG: Done processing all drivers");
    }

    // Fail if any driver failed to fetch
    if driver_fetch_errors > 0 {
        progress.finish_with_message("Failed");
        return Err(error::AdbcIndexError::Config(
            format!("Failed to fetch releases from {} driver(s)", driver_fetch_errors)
        ));
    }

    if std::env::var("DEBUG").is_ok() {
        eprintln!("DEBUG: Finishing main progress: {} cached, {} to download", cached_count, download_tasks.len());
    }

    progress.finish_with_message(&format!("{} cached, {} to download", cached_count, download_tasks.len()));

    if std::env::var("DEBUG").is_ok() {
        eprintln!("DEBUG: Progress finished");
    }

    // Download artifacts
    if !download_tasks.is_empty() {
        let download_progress = progress::ProgressTracker::new(download_tasks.len() as u64, "Download");
        download_progress.set_message("Downloading artifacts");

        let download_manager =
            download::DownloadManager::with_progress(
                cache_dir.clone(),
                concurrent_downloads,
                download_progress.multi(),
                Some(github_token.clone())
            )?;

        let results = download_manager.download_all(download_tasks).await;

        let mut success_count = 0;
        let mut error_count = 0;

        for result in results {
            match result {
                Ok(_) => {
                    success_count += 1;
                    download_progress.inc(1);
                }
                Err(e) => {
                    eprintln!("  ⚠️  Download error: {}", e);
                    error_count += 1;
                    download_progress.inc(1);
                }
            }
        }

        if error_count > 0 {
            download_progress.finish_with_message(&format!("{} downloaded, {} errors", success_count, error_count));
            return Err(error::AdbcIndexError::Download {
                url: "multiple".to_string(),
                reason: format!("{} artifact(s) failed", error_count),
            });
        } else {
            download_progress.finish_with_message(&format!("{} artifacts downloaded", success_count));
        }
    }

    Ok(())
}

async fn build() -> Result<()> {
    let build_progress = progress::ProgressTracker::new(3, "Build");

    // Step 1: Download releases
    build_progress.set_message("Step 1/3: Downloading releases");
    download(None).await?;
    build_progress.inc(1);

    // Step 2: Generate parquet reports
    build_progress.set_message("Step 2/3: Analyzing and generating reports");
    report().await?;
    build_progress.inc(1);

    // Step 3: Generate HTML dashboard
    build_progress.set_message("Step 3/3: Generating HTML dashboard");
    html().await?;
    build_progress.inc(1);

    build_progress.finish_with_message("Build complete");

    Ok(())
}

/// Load cached releases from disk for a driver
fn load_cached_releases(cache_dir: &PathBuf, driver_name: &str) -> Result<Vec<github::types::Release>> {
    let driver_cache = cache_dir.join(driver_name);
    if !driver_cache.exists() {
        return Ok(Vec::new());
    }

    let mut releases = Vec::new();

    // Iterate through each tag directory
    for entry in std::fs::read_dir(&driver_cache)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let release_json_path = entry.path().join("release.json");
        if !release_json_path.exists() {
            continue;
        }

        // Read and deserialize release.json
        let json_content = std::fs::read_to_string(&release_json_path)?;
        match serde_json::from_str::<github::types::Release>(&json_content) {
            Ok(release) => releases.push(release),
            Err(e) => {
                    eprintln!("  ⚠️  Download error: {}", e);
                eprintln!("⚠️  Failed to parse {}: {}", release_json_path.display(), e);
            }
        }
    }

    Ok(releases)
}

/// Result of processing a single driver
struct DriverProcessResult {
    library_records: Vec<models::LibraryRecord>,
    symbol_records: Vec<models::SymbolRecord>,
    release_data: Vec<((String, String), (Option<String>, chrono::DateTime<chrono::Utc>, String, std::collections::HashSet<String>, std::collections::HashSet<String>))>,
    driver_name: String,
    repo_owner: String,
    repo_name: String,
    library_count: usize,
}

/// Process a single driver and return its results
async fn process_driver(
    driver: models::DriverConfig,
    cache_dir: PathBuf,
    symbol_filter: symbols::SymbolFilter,
) -> Result<DriverProcessResult> {
    use std::collections::HashSet;
    use models::{LibraryRecord, SymbolRecord};

    let mut library_records = Vec::new();
    let mut symbol_records = Vec::new();
    let mut release_data_vec: Vec<((String, String), (Option<String>, chrono::DateTime<chrono::Utc>, String, HashSet<String>, HashSet<String>))> = Vec::new();
    let mut library_count = 0;

    let mut releases = load_cached_releases(&cache_dir, &driver.name)?;

    // Filter releases by version requirement if specified
    if let Some(ref version_req) = driver.version_req {
        releases.retain(|release| {
            if let Some(version_str) = models::ReleaseRecord::parse_version(&release.tag_name) {
                if let Ok(version) = semver::Version::parse(&version_str) {
                    return version_req.matches(&version);
                }
            }
            true
        });
    }

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
                        library_name: lib_info.name.clone(),
                        library_size_bytes: lib_info.size,
                        library_sha256: lib_info.sha256.clone().unwrap_or_default(),
                        artifact_name: asset.name.clone(),
                        artifact_url: asset.browser_download_url.clone(),
                    });

                    // Extract symbols and analyze stubs in a single pass
                    if let Some(ref lib_path) = lib_info.path {
                        match symbols::extract_symbols_and_stubs(lib_path, &symbol_filter) {
                            Ok((syms, stub_analyses)) => {
                                // Build map of symbol -> stub analysis
                                let stub_map: std::collections::HashMap<String, stub_detector::StubAnalysis> =
                                    stub_analyses.into_iter()
                                        .map(|a| (a.symbol_name.clone(), a))
                                        .collect();

                                for (idx, symbol) in syms.into_iter().enumerate() {
                                    let stub_info = stub_map.get(&symbol);

                                    symbol_records.push(SymbolRecord {
                                        name: driver.name.clone(),
                                        release_tag: tag.clone(),
                                        version: version.clone(),
                                        os: os.clone(),
                                        arch: arch.clone(),
                                        library_name: lib_info.name.clone(),
                                        symbol: symbol.clone(),
                                        symbol_index: idx as i64,
                                        is_stub: stub_info.map(|s| s.is_stub).unwrap_or(false),
                                        constant_return: stub_info.and_then(|s| s.constant_return),
                                        return_status: stub_info.and_then(|s| s.status_code.map(|c| c.name().to_string())),
                                    });
                                }
                            }
                            Err(_e) => {
                                // Silently skip symbol extraction errors
                            }
                        }
                    }

                    // Track library count
                    library_count += 1;

                    // Aggregate release data
                    let key = (driver.name.clone(), tag.clone());

                    // Find existing entry or create new one
                    if let Some(entry) = release_data_vec.iter_mut().find(|(k, _)| k == &key) {
                        entry.1.3.insert(os.clone());
                        entry.1.4.insert(arch.clone());
                    } else {
                        let mut os_set = HashSet::new();
                        let mut arch_set = HashSet::new();
                        os_set.insert(os.clone());
                        arch_set.insert(arch.clone());
                        release_data_vec.push((key, (version.clone(), published_date, release_url.clone(), os_set, arch_set)));
                    }
                }
            }
        }
    }

    // Extract repo owner and name based on source type
    let (repo_owner, repo_name) = match &driver.source {
        models::DriverSource::GitHub { owner, repo } => (owner.clone(), repo.clone()),
        models::DriverSource::PyPI { package } => ("pypi".to_string(), package.clone()),
    };

    Ok(DriverProcessResult {
        library_records,
        symbol_records,
        release_data: release_data_vec,
        driver_name: driver.name,
        repo_owner,
        repo_name,
        library_count,
    })
}

async fn report() -> Result<()> {
    let config = PathBuf::from("drivers.toml");
    let cache_dir = PathBuf::from("cache");

    // Load configuration
    let drivers = config::load_config(&config)?;

    use std::collections::{HashMap, HashSet};
    use models::DriverRecord;

    // Configure symbol filter - only extract symbols starting with "Adbc"
    let symbol_filter = symbols::SymbolFilter::default();

    // Create progress tracker
    let analyze_progress = progress::ProgressTracker::new(drivers.len() as u64, "Analyze");
    analyze_progress.set_message("Processing drivers");

    // Process all drivers in parallel
    let mut tasks = Vec::new();
    for driver in drivers {
        let cache_dir_clone = cache_dir.clone();
        let symbol_filter_clone = symbol_filter.clone();

        let task = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(
                process_driver(driver, cache_dir_clone, symbol_filter_clone)
            )
        });

        tasks.push(task);
    }

    // Collect results from all tasks
    let mut library_records = Vec::new();
    let mut symbol_records = Vec::new();
    let mut release_data: HashMap<(String, String), (Option<String>, chrono::DateTime<chrono::Utc>, String, HashSet<String>, HashSet<String>)> = HashMap::new();
    let mut driver_stats: HashMap<String, (String, String, usize)> = HashMap::new();

    for task in tasks {
        match task.await {
            Ok(Ok(result)) => {
                let driver_name = result.driver_name.clone();

                // Merge results
                library_records.extend(result.library_records);
                symbol_records.extend(result.symbol_records);

                // Merge release data
                for (key, value) in result.release_data {
                    release_data.insert(key, value);
                }

                // Store driver stats
                driver_stats.insert(
                    result.driver_name,
                    (result.repo_owner, result.repo_name, result.library_count)
                );

                analyze_progress.inc(1);
            }
            Ok(Err(e)) => {
                analyze_progress.inc(1);
            }
            Err(e) => {
                    eprintln!("  ⚠️  Download error: {}", e);
                analyze_progress.inc(1);
            }
        }
    }

    analyze_progress.finish_with_message(&format!(
        "{} drivers, {} libraries, {} symbols",
        driver_stats.len(),
        library_records.len(),
        symbol_records.len()
    ));

    // Calculate first and latest release for each driver
    let mut driver_first_latest: HashMap<String, (chrono::DateTime<chrono::Utc>, Option<String>, chrono::DateTime<chrono::Utc>, Option<String>)> = HashMap::new();

    for ((name, _), (version, published_date, _, _, _)) in &release_data {
        driver_first_latest
            .entry(name.clone())
            .and_modify(|(first_date, first_ver, latest_date, latest_ver)| {
                if published_date < first_date {
                    *first_date = *published_date;
                    *first_ver = version.clone();
                }
                if published_date > latest_date {
                    *latest_date = *published_date;
                    *latest_ver = version.clone();
                }
            })
            .or_insert((*published_date, version.clone(), *published_date, version.clone()));
    }

    // Create driver records
    let mut driver_records: Vec<DriverRecord> = driver_stats
        .iter()
        .map(|(name, (owner, repo, lib_count))| {
            // Count releases for this driver
            let release_count = release_data
                .keys()
                .filter(|(driver_name, _)| driver_name == name)
                .count() as i64;

            // Get first and latest release info
            let (first_release_date, first_release_version, latest_release_date, latest_release_version) =
                driver_first_latest.get(name).cloned().unwrap_or_else(|| {
                    let now = chrono::Utc::now();
                    (now, None, now, None)
                });

            DriverRecord {
                name: name.clone(),
                repo_owner: owner.clone(),
                repo_name: repo.clone(),
                release_count,
                library_count: *lib_count as i64,
                first_release_date,
                first_release_version,
                latest_release_date,
                latest_release_version,
            }
        })
        .collect();

    // Sort by name
    driver_records.sort_by(|a, b| a.name.cmp(&b.name));

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

    // Create dist directory for output
    let dist_dir = PathBuf::from("dist");
    std::fs::create_dir_all(&dist_dir)?;

    let write_progress = progress::ProgressTracker::new(4, "Write");
    write_progress.set_message("Writing parquet files");

    // Write drivers.parquet
    let drivers_output = dist_dir.join("drivers.parquet");
    let mut drivers_writer = parquet::DriversWriter::new(&drivers_output)?;
    for record in driver_records {
        drivers_writer.add_record(record)?;
    }
    drivers_writer.close()?;
    write_progress.inc(1);

    // Write releases.parquet
    let releases_output = dist_dir.join("releases.parquet");
    let mut releases_writer = parquet::ReleasesWriter::new(&releases_output)?;
    for record in release_records {
        releases_writer.add_record(record)?;
    }
    releases_writer.close()?;
    write_progress.inc(1);

    // Write libraries.parquet
    let libraries_output = dist_dir.join("libraries.parquet");
    let mut libraries_writer = parquet::LibrariesWriter::new(&libraries_output)?;
    for record in library_records {
        libraries_writer.add_record(record)?;
    }
    libraries_writer.close()?;
    write_progress.inc(1);

    // Write symbols.parquet
    let symbols_output = dist_dir.join("symbols.parquet");
    let mut symbols_writer = parquet::SymbolsWriter::new(&symbols_output)?;
    for record in symbol_records {
        symbols_writer.add_record(record)?;
    }
    symbols_writer.close()?;
    write_progress.inc(1);

    write_progress.finish_with_message("Parquet files written");

    Ok(())
}

/// Information about an extracted shared library
#[derive(Debug, Clone)]
struct LibraryInfo {
    name: String,
    size: i64,
    sha256: Option<String>,
    path: Option<std::path::PathBuf>,
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
    use std::io::{Read, Write};
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

    // Create temp directory for extracted libraries
    let extract_dir = cache_dir
        .join(driver_name)
        .join(&sanitized_tag)
        .join("extracted");
    std::fs::create_dir_all(&extract_dir).ok()?;

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

                // Extract library to temp directory
                let lib_path = extract_dir.join(&filename);
                let mut out_file = File::create(&lib_path).ok()?;
                let mut hasher = Sha256::new();
                let mut buffer = vec![0; 8192];

                // Read, hash, and write simultaneously
                loop {
                    let n = entry.read(&mut buffer).ok()?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                    out_file.write_all(&buffer[..n]).ok()?;
                }
                let sha256 = format!("{:x}", hasher.finalize());

                return Some(LibraryInfo {
                    name: filename,
                    size,
                    sha256: Some(sha256),
                    path: Some(lib_path),
                });
            }
        }
    } else if artifact_name.ends_with(".zip") || artifact_name.ends_with(".whl") {
        // Extract zip
        let file = File::open(&artifact_path).ok()?;
        let mut archive = ZipArchive::new(file).ok()?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).ok()?;
            let filename = file.name().split('/').last()?.to_string();

            // Check if this is a shared library
            if filename.ends_with(".so") || filename.ends_with(".dylib") || filename.ends_with(".dll") {
                let size = file.size() as i64;

                // Extract library to temp directory
                let lib_path = extract_dir.join(&filename);
                let mut out_file = File::create(&lib_path).ok()?;
                let mut hasher = Sha256::new();
                let mut buffer = vec![0; 8192];

                // Read, hash, and write simultaneously
                loop {
                    let n = file.read(&mut buffer).ok()?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                    out_file.write_all(&buffer[..n]).ok()?;
                }
                let sha256 = format!("{:x}", hasher.finalize());

                return Some(LibraryInfo {
                    name: filename,
                    size,
                    sha256: Some(sha256),
                    path: Some(lib_path),
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

/// Generate an SVG plot showing cumulative driver releases over time
fn generate_driver_timeline_svg(timeline_csv: &str) -> String {
    use chrono::NaiveDateTime;

    // Parse CSV to extract dates and driver names
    let mut data_points: Vec<(chrono::DateTime<chrono::Utc>, String)> = Vec::new();

    for (idx, line) in timeline_csv.lines().enumerate() {
        if idx == 0 {
            continue; // Skip header
        }

        let cells = parse_csv_line(line);
        if cells.len() >= 2 {
            let _name = &cells[0];
            let date_str = &cells[1];

            // Parse the timestamp (format: "2024-01-15 12:34:56.123" or "2024-01-15 12:34:56")
            // Try with microseconds first, then without
            let dt_result = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S%.f")
                .or_else(|_| NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S"));

            if let Ok(naive_dt) = dt_result {
                let dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive_dt, chrono::Utc);
                data_points.push((dt, _name.clone()));
            }
        }
    }

    if data_points.is_empty() {
        return String::from("<p>No driver release data available</p>");
    }

    // Already sorted by date from SQL query
    // Calculate cumulative counts, grouping by date
    let mut plot_points: Vec<(chrono::DateTime<chrono::Utc>, i32)> = Vec::new();
    let mut current_date: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut count = 0;

    for (date, _) in data_points {
        let date_only = date.date_naive();

        match current_date {
            None => {
                // First point
                count = 1;
                current_date = Some(date);
                plot_points.push((date, count));
            }
            Some(prev_date) => {
                let prev_date_only = prev_date.date_naive();
                if date_only == prev_date_only {
                    // Same day - increment and update the last point
                    count += 1;
                    if let Some(last) = plot_points.last_mut() {
                        last.1 = count;
                    }
                } else {
                    // New day
                    count += 1;
                    plot_points.push((date, count));
                    current_date = Some(date);
                }
            }
        }
    }

    if plot_points.is_empty() {
        return String::from("<p>No driver release data available</p>");
    }

    // SVG dimensions (Tufte-style: smaller, minimal)
    let width = 600.0;
    let height = 300.0;
    let margin_left = 40.0;
    let margin_right = 20.0;
    let margin_top = 40.0;
    let margin_bottom = 50.0;
    let plot_width = width - margin_left - margin_right;
    let plot_height = height - margin_top - margin_bottom;

    // Calculate scales
    let min_date = plot_points.first().unwrap().0;
    let max_date = plot_points.last().unwrap().0;
    let date_range = (max_date - min_date).num_seconds() as f64;
    let max_count = plot_points.last().unwrap().1;

    // Generate SVG with dark theme
    let mut svg = String::new();
    svg.push_str(&format!("<svg width=\"{}\" height=\"{}\" xmlns=\"http://www.w3.org/2000/svg\" style=\"background: transparent;\">", width, height));
    svg.push_str("\n");

    // Axes
    svg.push_str(&format!(
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#1e3a5f\" stroke-width=\"1\"/>",
        margin_left, margin_top + plot_height, margin_left + plot_width, margin_top + plot_height
    ));
    svg.push_str("\n");
    svg.push_str(&format!(
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#1e3a5f\" stroke-width=\"1\"/>",
        margin_left, margin_top, margin_left, margin_top + plot_height
    ));
    svg.push_str("\n");

    // Y-axis ticks and grid
    let y_tick_count = 5;
    for i in 0..=y_tick_count {
        let tick_value = (max_count as f64 / y_tick_count as f64 * i as f64).round() as i32;
        let y = margin_top + plot_height - (tick_value as f64 / max_count as f64 * plot_height);

        // Grid line
        if i > 0 && i < y_tick_count {
            svg.push_str(&format!(
                "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#1a2332\" stroke-width=\"0.5\" stroke-dasharray=\"2,2\"/>",
                margin_left, y, margin_left + plot_width, y
            ));
            svg.push_str("\n");
        }

        // Tick label
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" fill=\"#90caf9\" text-anchor=\"end\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">{}</text>",
            margin_left - 8.0, y, tick_value
        ));
        svg.push_str("\n");
    }

    // X-axis ticks
    let x_tick_count = 5;
    for i in 0..=x_tick_count {
        let date_offset = date_range * i as f64 / x_tick_count as f64;
        let tick_date = min_date + chrono::Duration::seconds(date_offset as i64);
        let x = margin_left + (plot_width * i as f64 / x_tick_count as f64);

        // Tick label
        let date_label = tick_date.format("%Y-%m").to_string();
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" text-anchor=\"end\" transform=\"rotate(-45, {}, {})\" font-family=\"JetBrains Mono, monospace\">{}</text>",
            x, margin_top + plot_height + 10.0, x, margin_top + plot_height + 10.0, date_label
        ));
        svg.push_str("\n");
    }

    // Plot area fill
    let mut area_points = format!("{},{} ", margin_left, margin_top + plot_height);
    for (date, count) in &plot_points {
        let x = margin_left + ((date.signed_duration_since(min_date).num_seconds() as f64 / date_range) * plot_width);
        let y = margin_top + plot_height - ((*count as f64 / max_count as f64) * plot_height);
        area_points.push_str(&format!("{},{} ", x, y));
    }
    area_points.push_str(&format!("{},{}", margin_left + plot_width, margin_top + plot_height));

    svg.push_str(&format!(
        "<polygon points=\"{}\" fill=\"rgba(0, 212, 255, 0.1)\" stroke=\"none\"/>",
        area_points.trim()
    ));
    svg.push_str("\n");

    // Plot line
    let mut polyline_points = String::new();
    for (date, count) in &plot_points {
        let x = margin_left + ((date.signed_duration_since(min_date).num_seconds() as f64 / date_range) * plot_width);
        let y = margin_top + plot_height - ((*count as f64 / max_count as f64) * plot_height);
        polyline_points.push_str(&format!("{},{} ", x, y));
    }

    svg.push_str(&format!(
        "<polyline points=\"{}\" fill=\"none\" stroke=\"#00d4ff\" stroke-width=\"2\"/>",
        polyline_points.trim()
    ));
    svg.push_str("\n");

    // Plot points
    for (date, count) in &plot_points {
        let x = margin_left + ((date.signed_duration_since(min_date).num_seconds() as f64 / date_range) * plot_width);
        let y = margin_top + plot_height - ((*count as f64 / max_count as f64) * plot_height);
        svg.push_str(&format!(
            "<circle cx=\"{}\" cy=\"{}\" r=\"2.5\" fill=\"#00d4ff\"/>",
            x, y
        ));
        svg.push_str("\n");
    }

    svg.push_str("</svg>\n");
    svg
}

/// Generate a Tufte-style horizontal bar chart
fn generate_bar_chart(csv: &str, title: &str) -> String {
    // Parse CSV to extract names and values
    let mut data: Vec<(String, f64)> = Vec::new();

    for (idx, line) in csv.lines().enumerate() {
        if idx == 0 {
            continue; // Skip header
        }

        let cells = parse_csv_line(line);
        if cells.len() >= 2 {
            let name = &cells[0];
            if let Ok(value) = cells[1].parse::<f64>() {
                data.push((name.clone(), value));
            }
        }
    }

    if data.is_empty() {
        return String::from("<p>No data available</p>");
    }

    // SVG dimensions (Tufte-style: compact)
    let width = 500.0;
    let bar_height = 20.0;
    let bar_spacing = 5.0;
    let margin_left = 100.0;
    let margin_right = 80.0;
    let margin_top = 30.0;
    let margin_bottom = 10.0;
    let plot_width = width - margin_left - margin_right;

    let total_bars = data.len() as f64;
    let height = margin_top + margin_bottom + (total_bars * (bar_height + bar_spacing));

    // Find max value for scaling
    let max_value = data.iter().map(|(_, v)| *v).fold(0.0, f64::max);

    // Determine if we should convert to MB (for library sizes)
    let is_bytes = title.contains("MB");
    let divisor = if is_bytes { 1_048_576.0 } else { 1.0 };
    let scaled_max = max_value / divisor;

    // Generate SVG with dark theme
    let mut svg = String::new();
    svg.push_str(&format!("<svg width=\"{}\" height=\"{}\" xmlns=\"http://www.w3.org/2000/svg\" style=\"background: transparent;\">", width, height));
    svg.push_str("\n");

    // Draw bars
    for (i, (name, value)) in data.iter().enumerate() {
        let y = margin_top + (i as f64 * (bar_height + bar_spacing));
        let scaled_value = value / divisor;
        let bar_width = (scaled_value / scaled_max) * plot_width;

        // Bar background
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"#1a2332\" opacity=\"0.3\"/>",
            margin_left, y, plot_width, bar_height
        ));
        svg.push_str("\n");

        // Bar
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"url(#barGradient)\"/>",
            margin_left, y, bar_width, bar_height
        ));
        svg.push_str("\n");

        // Bar border
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"none\" stroke=\"#00d4ff\" stroke-width=\"1\"/>",
            margin_left, y, bar_width, bar_height
        ));
        svg.push_str("\n");

        // Label (name)
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" fill=\"#e3f2fd\" text-anchor=\"end\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\" font-weight=\"500\">{}</text>",
            margin_left - 8.0, y + bar_height / 2.0, name
        ));
        svg.push_str("\n");

        // Value
        let value_text = if is_bytes {
            format!("{:.1}", scaled_value)
        } else {
            format!("{:.0}", scaled_value)
        };
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">{}</text>",
            margin_left + bar_width + 8.0, y + bar_height / 2.0, value_text
        ));
        svg.push_str("\n");
    }

    // Add gradient definition
    svg.insert_str(svg.find("<rect").unwrap(), &format!(
        "<defs><linearGradient id=\"barGradient\" x1=\"0%\" y1=\"0%\" x2=\"100%\" y2=\"0%\">\
         <stop offset=\"0%\" style=\"stop-color:#0099cc;stop-opacity:1\" />\
         <stop offset=\"100%\" style=\"stop-color:#00d4ff;stop-opacity:1\" />\
         </linearGradient></defs>"
    ));

    svg.push_str("</svg>\n");
    svg
}

async fn html() -> Result<()> {
    use std::process::Command;

    let output_dir = PathBuf::from("dist");
    let drivers_path = output_dir.join("drivers.parquet");
    let releases_path = output_dir.join("releases.parquet");
    let libraries_path = output_dir.join("libraries.parquet");
    let symbols_path = output_dir.join("symbols.parquet");
    let output_file = output_dir.join("index.html");

    // Check if parquet files exist
    if !drivers_path.exists() || !releases_path.exists() || !libraries_path.exists() || !symbols_path.exists() {
        return Err(error::AdbcIndexError::Config(
            "Parquet files not found. Run 'adbc-index build' first.".to_string(),
        ));
    }

    std::fs::create_dir_all(&output_dir)?;

    // Query driver timeline data (name and first release date)
    let timeline_output = Command::new("duckdb")
        .arg("-csv")
        .arg("-c")
        .arg("SELECT name, timezone('UTC', first_release_date) as first_release_date FROM read_parquet('dist/drivers.parquet') ORDER BY first_release_date")
        .output()?;

    if !timeline_output.status.success() {
        return Err(error::AdbcIndexError::Config(
            format!("DuckDB error reading timeline: {}", String::from_utf8_lossy(&timeline_output.stderr))
        ));
    }

    let timeline_csv = String::from_utf8_lossy(&timeline_output.stdout);

    // Query releases per driver
    let releases_chart_output = Command::new("duckdb")
        .arg("-csv")
        .arg("-c")
        .arg("SELECT name, COUNT(*) as count FROM read_parquet('dist/releases.parquet') GROUP BY name ORDER BY count DESC")
        .output()?;

    if !releases_chart_output.status.success() {
        return Err(error::AdbcIndexError::Config(
            format!("DuckDB error reading releases chart: {}", String::from_utf8_lossy(&releases_chart_output.stderr))
        ));
    }
    let releases_chart_csv = String::from_utf8_lossy(&releases_chart_output.stdout);

    // Query average library size per driver
    let libraries_chart_output = Command::new("duckdb")
        .arg("-csv")
        .arg("-c")
        .arg("SELECT name, AVG(library_size_bytes) as avg_size FROM read_parquet('dist/libraries.parquet') GROUP BY name ORDER BY avg_size DESC")
        .output()?;

    if !libraries_chart_output.status.success() {
        return Err(error::AdbcIndexError::Config(
            format!("DuckDB error reading libraries chart: {}", String::from_utf8_lossy(&libraries_chart_output.stderr))
        ));
    }
    let libraries_chart_csv = String::from_utf8_lossy(&libraries_chart_output.stdout);

    // Query symbol count per driver
    let symbols_chart_output = Command::new("duckdb")
        .arg("-csv")
        .arg("-c")
        .arg("SELECT name, COUNT(DISTINCT symbol) as symbol_count FROM read_parquet('dist/symbols.parquet') GROUP BY name ORDER BY symbol_count DESC")
        .output()?;

    if !symbols_chart_output.status.success() {
        return Err(error::AdbcIndexError::Config(
            format!("DuckDB error reading symbols chart: {}", String::from_utf8_lossy(&symbols_chart_output.stderr))
        ));
    }
    let symbols_chart_csv = String::from_utf8_lossy(&symbols_chart_output.stdout);

    println!("🔨 Generating HTML...");

    // Generate charts
    let timeline_svg = generate_driver_timeline_svg(&timeline_csv);
    let releases_chart_svg = generate_bar_chart(&releases_chart_csv, "Releases per Driver");
    let libraries_chart_svg = generate_bar_chart(&libraries_chart_csv, "Average Library Size by Driver (MB)");
    let symbols_chart_svg = generate_bar_chart(&symbols_chart_csv, "Unique Symbols per Driver");

    // Get file sizes for download links
    fn format_file_size(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }

    let drivers_size = format_file_size(std::fs::metadata(&drivers_path)?.len());
    let releases_size = format_file_size(std::fs::metadata(&releases_path)?.len());
    let libraries_size = format_file_size(std::fs::metadata(&libraries_path)?.len());
    let symbols_size = format_file_size(std::fs::metadata(&symbols_path)?.len());

    // Initialize Tera template engine
    let tera = match Tera::new("templates/**/*.tera") {
        Ok(t) => t,
        Err(e) => {
                    eprintln!("  ⚠️  Download error: {}", e);
            return Err(error::AdbcIndexError::Config(
                format!("Template parsing error: {}", e)
            ));
        }
    };

    // Create template context
    let mut context = Context::new();
    context.insert("timeline_svg", &timeline_svg);
    context.insert("releases_chart_svg", &releases_chart_svg);
    context.insert("libraries_chart_svg", &libraries_chart_svg);
    context.insert("symbols_chart_svg", &symbols_chart_svg);
    context.insert("drivers_size", &drivers_size);
    context.insert("releases_size", &releases_size);
    context.insert("libraries_size", &libraries_size);
    context.insert("symbols_size", &symbols_size);

    // Render template
    let html = match tera.render("index.html.tera", &context) {
        Ok(html) => html,
        Err(e) => {
                    eprintln!("  ⚠️  Download error: {}", e);
            return Err(error::AdbcIndexError::Config(
                format!("Template rendering error: {}", e)
            ));
        }
    };

    // Write HTML file
    std::fs::write(&output_file, html)?;

    println!("✨ Done!");
    println!();
    println!("Output file: {:?}", output_file);

    Ok(())
}

fn generate_interactive_html(
    timeline_svg: &str,
    releases_chart_svg: &str,
    libraries_chart_svg: &str,
    symbols_chart_svg: &str,
    drivers_size: &str,
    releases_size: &str,
    libraries_size: &str,
    symbols_size: &str,
) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ADBC Driver Index</title>
<script src="https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.32.0/+esm" type="module"></script>
<script src="https://cdn.jsdelivr.net/npm/ag-grid-community@31.0.0/dist/ag-grid-community.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/ag-grid-community@31.0.0/styles/ag-grid.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/ag-grid-community@31.0.0/styles/ag-theme-alpine-dark.min.css">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg-primary: #0a1929;
    --bg-secondary: #0f2137;
    --bg-tertiary: #162a42;
    --accent-primary: #00d4ff;
    --accent-secondary: #0099cc;
    --text-primary: #e3f2fd;
    --text-secondary: #90caf9;
    --text-muted: #546e7a;
    --border-color: #1e3a5f;
    --border-bright: #00d4ff;
    --success: #4caf50;
    --warning: #ffa726;
    --error: #ef5350;
    --grid-pattern: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 19px,
      var(--border-color) 19px,
      var(--border-color) 20px
    ),
    repeating-linear-gradient(
      90deg,
      transparent,
      transparent 19px,
      var(--border-color) 19px,
      var(--border-color) 20px
    );
  }}

  * {{
    box-sizing: border-box;
  }}

  body {{
    font-family: 'JetBrains Mono', 'SF Mono', 'Consolas', 'Monaco', monospace;
    margin: 0;
    padding: 0;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 13px;
    line-height: 1.6;
    background-image: var(--grid-pattern);
    background-size: 20px 20px;
  }}

  .container {{
    max-width: 1600px;
    margin: 0 auto;
    padding: 0 24px;
  }}

  header {{
    background: var(--bg-secondary);
    border-bottom: 2px solid var(--border-bright);
    padding: 32px 0;
    margin-bottom: 40px;
    box-shadow: 0 4px 20px rgba(0, 212, 255, 0.1);
    position: relative;
  }}

  .github-link {{
    position: absolute;
    top: 32px;
    right: 24px;
    width: 32px;
    height: 32px;
    transition: all 0.3s ease;
    opacity: 0.8;
  }}

  .github-link:hover {{
    opacity: 1;
    transform: scale(1.1);
  }}

  .github-link svg {{
    width: 100%;
    height: 100%;
    fill: var(--accent-primary);
    filter: drop-shadow(0 0 8px rgba(0, 212, 255, 0.3));
  }}

  .github-link:hover svg {{
    filter: drop-shadow(0 0 12px rgba(0, 212, 255, 0.6));
  }}

  h1 {{
    margin: 0;
    font-size: 32px;
    font-weight: 700;
    letter-spacing: -0.5px;
    text-transform: uppercase;
    color: var(--accent-primary);
    text-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
  }}

  .subtitle {{
    margin: 8px 0 0 0;
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 2px;
    font-weight: 300;
  }}

  h2 {{
    color: var(--accent-primary);
    font-size: 18px;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin: 0 0 24px 0;
    font-weight: 500;
    border-left: 3px solid var(--accent-primary);
    padding-left: 12px;
  }}

  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 16px;
    margin-bottom: 48px;
  }}

  .stat-card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    padding: 24px;
    position: relative;
    overflow: hidden;
    transition: all 0.3s ease;
  }}

  .stat-card::before {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent-primary), transparent);
  }}

  .stat-card:hover {{
    border-color: var(--accent-primary);
    transform: translateY(-2px);
    box-shadow: 0 4px 16px rgba(0, 212, 255, 0.2);
  }}

  .stat-label {{
    font-size: 10px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    font-weight: 500;
    margin-bottom: 12px;
  }}

  .stat-value {{
    font-size: 56px;
    font-weight: 700;
    color: var(--accent-primary);
    line-height: 1;
    font-variant-numeric: tabular-nums;
  }}

  .tabs {{
    display: flex;
    gap: 0;
    margin: 48px 0 32px;
    border-bottom: 1px solid var(--border-color);
    flex-wrap: wrap;
  }}

  .tab-button {{
    padding: 16px 24px;
    background: rgba(0, 212, 255, 0.03);
    border: none;
    cursor: pointer;
    font-size: 11px;
    font-weight: 500;
    color: var(--text-secondary);
    transition: all 0.2s ease;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    position: relative;
    font-family: 'JetBrains Mono', monospace;
  }}

  .tab-button::after {{
    content: '';
    position: absolute;
    bottom: -1px;
    left: 0;
    right: 0;
    height: 2px;
    background: var(--accent-primary);
    transform: scaleX(0);
    transition: transform 0.3s ease;
  }}

  .tab-button:hover {{
    color: var(--text-primary);
    background: rgba(0, 212, 255, 0.08);
  }}

  .tab-button.active {{
    color: var(--accent-primary);
    background: rgba(0, 212, 255, 0.06);
  }}

  .tab-button.active::after {{
    transform: scaleX(1);
  }}

  .status-indicator {{
    font-size: 11px;
    margin-left: 8px;
    font-weight: 400;
  }}

  .status-indicator.loading {{ color: var(--text-muted); }}
  .status-indicator.success {{ color: var(--success); }}
  .status-indicator.error {{ color: var(--error); }}

  .tab-content {{
    display: none;
    animation: fadeIn 0.3s ease;
  }}

  .tab-content.active {{
    display: block;
  }}

  @keyframes fadeIn {{
    from {{ opacity: 0; transform: translateY(8px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}

  .charts-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
    gap: 24px;
    margin-bottom: 48px;
  }}

  .chart-container {{
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    padding: 24px;
    position: relative;
    overflow: hidden;
  }}

  .chart-container::before {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent-primary), transparent);
  }}

  .chart-container h3 {{
    margin: 0 0 20px 0;
    color: var(--text-secondary);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    font-weight: 500;
  }}

  .chart-container svg {{
    filter: brightness(1.1);
  }}

  .table-container {{
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    padding: 24px;
    margin-bottom: 48px;
  }}

  .sql-query-box {{
    margin-bottom: 16px;
    padding: 16px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
  }}

  .sql-query-label {{
    display: block;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
  }}

  .sql-query-box textarea {{
    width: 100%;
    min-height: 80px;
    padding: 12px 16px;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    font-size: 12px;
    font-family: 'JetBrains Mono', monospace;
    transition: all 0.2s ease;
    resize: vertical;
  }}

  .sql-query-box textarea:focus {{
    outline: none;
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
  }}

  .sql-query-box textarea::placeholder {{
    color: var(--text-muted);
  }}

  .sql-query-buttons {{
    margin-top: 8px;
    display: flex;
    gap: 8px;
  }}

  .sql-query-button {{
    padding: 8px 16px;
    background: var(--accent-primary);
    border: none;
    color: var(--bg-primary);
    font-size: 11px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 1px;
    cursor: pointer;
    transition: all 0.2s ease;
    font-family: 'JetBrains Mono', monospace;
  }}

  .sql-query-button:hover {{
    background: var(--accent-secondary);
    box-shadow: 0 0 8px rgba(0, 212, 255, 0.4);
  }}

  .sql-query-button:active {{
    transform: translateY(1px);
  }}

  .ag-theme-alpine-dark {{
    --ag-background-color: var(--bg-tertiary);
    --ag-foreground-color: var(--text-primary);
    --ag-border-color: var(--border-color);
    --ag-header-background-color: var(--bg-secondary);
    --ag-odd-row-background-color: rgba(0, 212, 255, 0.02);
    --ag-row-hover-color: rgba(0, 212, 255, 0.08);
    --ag-selected-row-background-color: rgba(0, 212, 255, 0.15);
    height: 600px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
  }}

  .download-inline {{
    font-size: 12px;
    color: var(--text-secondary);
    margin-bottom: 16px;
    padding: 12px 16px;
    background: var(--bg-tertiary);
    border-left: 2px solid var(--accent-primary);
  }}

  .download-prefix {{
    color: var(--text-muted);
    margin-right: 8px;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-size: 10px;
  }}

  .download-link {{
    color: var(--accent-primary);
    text-decoration: none;
    font-weight: 500;
    transition: all 0.2s ease;
  }}

  .download-link:hover {{
    color: var(--accent-secondary);
    text-shadow: 0 0 8px rgba(0, 212, 255, 0.4);
  }}

  .loading {{
    text-align: center;
    padding: 60px 20px;
    color: var(--text-secondary);
    font-size: 14px;
  }}

  .loading.hidden {{
    display: none;
  }}

  .loading-step {{
    padding: 8px 0;
    color: var(--text-muted);
    font-size: 12px;
  }}

  .loading-step.active {{
    color: var(--accent-primary);
    font-weight: 500;
  }}

  .loading-step.success {{ color: var(--success); }}
  .loading-step.error {{ color: var(--error); }}

  .error-details {{
    background: rgba(239, 83, 80, 0.1);
    border: 1px solid var(--error);
    padding: 20px;
    margin: 24px 0;
  }}

  .error-details h3 {{
    color: var(--error);
    margin-top: 0;
    font-size: 14px;
    text-transform: uppercase;
  }}

  .error-details pre {{
    background: var(--bg-primary);
    padding: 16px;
    overflow-x: auto;
    font-size: 11px;
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
  }}

  footer {{
    margin-top: 80px;
    padding: 32px 0;
    border-top: 1px solid var(--border-color);
    text-align: center;
    color: var(--text-muted);
    font-size: 11px;
  }}

  @media (max-width: 768px) {{
    .stats-grid {{
      grid-template-columns: repeat(2, 1fr);
    }}
    .charts-grid {{
      grid-template-columns: 1fr;
    }}
    .stat-value {{
      font-size: 40px;
    }}
  }}
</style>
</head>
<body>

<header>
  <div class="container">
    <h1>ADBC Driver Index</h1>
    <div class="subtitle">Arrow Database Connectivity · Binary Analysis</div>
  </div>
  <a href="https://github.com/amoeba/adbc-dindex" target="_blank" rel="noopener noreferrer" class="github-link" aria-label="View on GitHub">
    <svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
    </svg>
  </a>
</header>

<div class="container">

<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-label">Total Drivers</div>
    <div class="stat-value" id="stat-drivers">—</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Total Releases</div>
    <div class="stat-value" id="stat-releases">—</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Total Libraries</div>
    <div class="stat-value" id="stat-libraries">—</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Total Symbols</div>
    <div class="stat-value" id="stat-symbols">—</div>
  </div>
</div>

<div class="tabs">
  <button class="tab-button active" data-tab="overview">
    Overview<span class="status-indicator" id="overviewStatus"></span>
  </button>
  <button class="tab-button" data-tab="drivers">
    Drivers<span class="status-indicator" id="driversStatus"></span>
  </button>
  <button class="tab-button" data-tab="releases">
    Releases<span class="status-indicator" id="releasesStatus"></span>
  </button>
  <button class="tab-button" data-tab="libraries">
    Libraries<span class="status-indicator" id="librariesStatus"></span>
  </button>
  <button class="tab-button" data-tab="symbols">
    Symbols<span class="status-indicator" id="symbolsStatus"></span>
  </button>
</div>

<div class="tab-content active" id="tab-overview">
<h2>Overview</h2>

<div class="charts-grid">
  <div class="chart-container">
    <h3>Drivers Released Over Time</h3>
    {timeline_svg}
  </div>
  <div class="chart-container">
    <h3>Releases per Driver</h3>
    {releases_chart_svg}
  </div>
  <div class="chart-container">
    <h3>Average Library Size by Driver</h3>
    {libraries_chart_svg}
  </div>
  <div class="chart-container">
    <h3>Unique Symbols per Driver</h3>
    {symbols_chart_svg}
  </div>
</div>
</div>

<div class="tab-content" id="tab-drivers">
<h2>Drivers</h2>
<div class="download-inline">
  <span class="download-prefix">Download</span>
  <a href="drivers.parquet" class="download-link" download>drivers.parquet ({drivers_size})</a>
</div>

<div class="table-container">
  <div class="sql-query-box">
    <label class="sql-query-label">SQL Query</label>
    <textarea id="driversQuery" placeholder="SELECT * FROM read_parquet('drivers.parquet')">SELECT * FROM read_parquet('drivers.parquet')</textarea>
    <div class="sql-query-buttons">
      <button class="sql-query-button" onclick="runDriversQuery()">Run Query ⏎</button>
    </div>
  </div>
  <div id="driversGrid" class="ag-theme-alpine-dark"></div>
</div>
</div>

<div class="tab-content" id="tab-releases">
<h2>Releases</h2>
<div class="download-inline">
  <span class="download-prefix">Download</span>
  <a href="releases.parquet" class="download-link" download>releases.parquet ({releases_size})</a>
</div>

<div class="table-container">
  <div class="sql-query-box">
    <label class="sql-query-label">SQL Query</label>
    <textarea id="releasesQuery" placeholder="SELECT * FROM read_parquet('releases.parquet')">SELECT * FROM read_parquet('releases.parquet')</textarea>
    <div class="sql-query-buttons">
      <button class="sql-query-button" onclick="runReleasesQuery()">Run Query ⏎</button>
    </div>
  </div>
  <div id="releasesGrid" class="ag-theme-alpine-dark"></div>
</div>
</div>

<div class="tab-content" id="tab-libraries">
<h2>Libraries</h2>
<div class="download-inline">
  <span class="download-prefix">Download</span>
  <a href="libraries.parquet" class="download-link" download>libraries.parquet ({libraries_size})</a>
</div>

<div class="table-container">
  <div class="sql-query-box">
    <label class="sql-query-label">SQL Query</label>
    <textarea id="librariesQuery" placeholder="SELECT * FROM read_parquet('libraries.parquet')">SELECT * FROM read_parquet('libraries.parquet')</textarea>
    <div class="sql-query-buttons">
      <button class="sql-query-button" onclick="runLibrariesQuery()">Run Query ⏎</button>
    </div>
  </div>
  <div id="librariesGrid" class="ag-theme-alpine-dark"></div>
</div>
</div>

<div class="tab-content" id="tab-symbols">
<h2>Symbols</h2>
<div class="download-inline">
  <span class="download-prefix">Download</span>
  <a href="symbols.parquet" class="download-link" download>symbols.parquet ({symbols_size})</a>
</div>

<div class="table-container">
  <div class="sql-query-box">
    <label class="sql-query-label">SQL Query</label>
    <textarea id="symbolsQuery" placeholder="SELECT * FROM read_parquet('symbols.parquet')">SELECT * FROM read_parquet('symbols.parquet')</textarea>
    <div class="sql-query-buttons">
      <button class="sql-query-button" onclick="runSymbolsQuery()">Run Query ⏎</button>
    </div>
  </div>
  <div id="symbolsGrid" class="ag-theme-alpine-dark"></div>
</div>
</div>

<div class="loading" id="globalLoading">
  <div id="loadingSteps"></div>
</div>

</div>

<footer>
  <div class="container">
    Generated by ADBC Index · Data stored in Parquet format · Powered by DuckDB WASM
  </div>
</footer>

<script type="module">
let db;
let loadingSteps = {{}};

function updateLoadingStep(id, status, message) {{
  if (!loadingSteps[id]) {{
    const stepDiv = document.createElement('div');
    stepDiv.id = `step-${{id}}`;
    stepDiv.className = 'loading-step';
    document.getElementById('loadingSteps').appendChild(stepDiv);
    loadingSteps[id] = stepDiv;
  }}

  const stepDiv = loadingSteps[id];
  stepDiv.className = `loading-step ${{status}}`;

  const icon = status === 'active' ? '⏳' : status === 'success' ? '✓' : status === 'error' ? '✗' : '';
  stepDiv.textContent = `${{icon}} ${{message}}`;
}}

function setTableStatus(tableId, status, message) {{
  const statusEl = document.getElementById(`${{tableId}}Status`);
  if (statusEl) {{
    statusEl.className = `status-indicator ${{status}}`;
    const icon = status === 'loading' ? '⏳' : status === 'success' ? '✓' : status === 'error' ? '✗' : '';
    statusEl.textContent = message ? `${{icon}} ${{message}}` : icon;
  }}
}}

function showError(title, message, details) {{
  const errorDiv = document.createElement('div');
  errorDiv.className = 'error-details';
  errorDiv.innerHTML = `
    <h3>${{title}}</h3>
    <p>${{message}}</p>
    ${{details ? `<pre>${{details}}</pre>` : ''}}
  `;
  document.getElementById('globalLoading').insertAdjacentElement('afterend', errorDiv);
}}

async function initDuckDB() {{
  updateLoadingStep('import', 'active', 'Loading DuckDB WASM module...');

  let duckdb;
  try {{
    duckdb = await import('https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.32.0/+esm');
    updateLoadingStep('import', 'success', 'DuckDB WASM module loaded');
  }} catch (err) {{
    updateLoadingStep('import', 'error', 'Failed to load DuckDB WASM module');
    throw new Error(`Failed to import DuckDB WASM: ${{err.message}}`);
  }}

  updateLoadingStep('init', 'active', 'Initializing DuckDB...');

  try {{
    const JSDELIVR_BUNDLES = duckdb.getJsDelivrBundles();
    const bundle = await duckdb.selectBundle(JSDELIVR_BUNDLES);

    const worker_url = URL.createObjectURL(
      new Blob([`importScripts("${{bundle.mainWorker}}");`], {{type: "text/javascript"}})
    );

    const worker = new Worker(worker_url);
    const logger = new duckdb.ConsoleLogger();
    db = new duckdb.AsyncDuckDB(logger, worker);
    await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
    URL.revokeObjectURL(worker_url);

    updateLoadingStep('init', 'success', 'DuckDB initialized');
  }} catch (err) {{
    updateLoadingStep('init', 'error', 'Failed to initialize DuckDB');
    throw new Error(`Failed to initialize DuckDB: ${{err.message}}`);
  }}

  // Register parquet files in DuckDB's file system
  const files = [
    {{ name: 'drivers.parquet', id: 'drivers' }},
    {{ name: 'releases.parquet', id: 'releases' }},
    {{ name: 'libraries.parquet', id: 'libraries' }},
    {{ name: 'symbols.parquet', id: 'symbols' }}
  ];

  for (const file of files) {{
    updateLoadingStep(`fetch-${{file.name}}`, 'active', `Fetching ${{file.name}}...`);
    try {{
      const response = await fetch(file.name);
      if (!response.ok) {{
        throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
      }}
      const buffer = await response.arrayBuffer();
      await db.registerFileBuffer(file.name, new Uint8Array(buffer));

      const sizeKB = (buffer.byteLength / 1024).toFixed(1);
      updateLoadingStep(`fetch-${{file.name}}`, 'success', `${{file.name}} loaded (${{sizeKB}} KB)`);

      // Update download link with file size
      const sizeEl = document.getElementById(`size-${{file.id}}`);
      if (sizeEl) {{
        sizeEl.textContent = `${{sizeKB}} KB`;
      }}
    }} catch (err) {{
      updateLoadingStep(`fetch-${{file.name}}`, 'error', `Failed to load ${{file.name}}`);

      // Update download link with error
      const sizeEl = document.getElementById(`size-${{file.id}}`);
      if (sizeEl) {{
        sizeEl.textContent = 'Error loading';
        sizeEl.style.color = '#dc3545';
      }}

      throw new Error(`Failed to fetch ${{file.name}}: ${{err.message}}`);
    }}
  }}
}}

function convertBigIntsToNumbers(obj) {{
  const result = {{}};
  for (const [key, value] of Object.entries(obj)) {{
    if (typeof value === 'bigint') {{
      // Convert BigInt to Number for JavaScript compatibility
      result[key] = Number(value);
    }} else {{
      result[key] = value;
    }}
  }}
  return result;
}}

async function queryDuckDB(sql, context) {{
  let conn;
  try {{
    conn = await db.connect();
    const result = await conn.query(sql);
    const data = result.toArray().map(row => convertBigIntsToNumbers(Object.fromEntries(Object.entries(row))));
    return data;
  }} catch (err) {{
    console.error(`Query failed [${{context}}]:`, err);
    throw new Error(`Query failed: ${{err.message}}`);
  }} finally {{
    if (conn) {{
      try {{
        await conn.close();
      }} catch (e) {{
        console.warn('Failed to close connection:', e);
      }}
    }}
  }}
}}

let driversGrid = null;

async function loadDriversTable(customSQL) {{
  console.log('loadDriversTable called with customSQL:', customSQL);
  setTableStatus('drivers', 'loading', 'Loading...');

  try {{
    const sql = customSQL || document.getElementById('driversQuery').value;
    console.log('Executing SQL:', sql);
    const data = await queryDuckDB(sql, 'drivers');
    console.log('Query returned', data?.length, 'rows');

    if (!data || data.length === 0) {{
      setTableStatus('drivers', 'error', 'No data');
      if (driversGrid) {{
        driversGrid.destroy();
        driversGrid = null;
      }}
      return;
    }}

    // Dynamically create column definitions from the data
    const columnDefs = Object.keys(data[0]).map(key => ({{
      field: key,
      headerName: key,
      filter: true,
      sortable: true,
      width: 150
    }}));

    const gridOptions = {{
      columnDefs: columnDefs,
      rowData: data,
      defaultColDef: {{
        resizable: true,
        sortable: true,
        filter: true
      }},
      pagination: true,
      paginationPageSize: 20
    }};

    // Destroy existing grid before creating new one
    if (driversGrid) {{
      driversGrid.destroy();
    }}

    driversGrid = agGrid.createGrid(document.getElementById('driversGrid'), gridOptions);

    setTableStatus('drivers', 'success', `${{data.length}} rows`);

    // Update stats card
    const statEl = document.getElementById('stat-drivers');
    if (statEl) {{
      statEl.textContent = data.length;
    }}
  }} catch (err) {{
    console.error('Failed to load drivers table:', err);
    setTableStatus('drivers', 'error', err.message);
    if (driversGrid) {{
      driversGrid.destroy();
      driversGrid = null;
    }}
  }}
}}

async function runDriversQuery() {{
  console.log('Running drivers query...');
  const queryText = document.getElementById('driversQuery').value;
  console.log('Query:', queryText);
  try {{
    await loadDriversTable();
  }} catch (err) {{
    console.error('Query execution failed:', err);
    alert('Query failed: ' + err.message);
  }}
}}

let releasesGrid = null;

async function loadReleasesTable(customSQL) {{
  setTableStatus('releases', 'loading', 'Loading...');

  try {{
    const sql = customSQL || document.getElementById('releasesQuery').value;
    const data = await queryDuckDB(sql, 'releases');

    if (!data || data.length === 0) {{
      setTableStatus('releases', 'error', 'No data');
      if (releasesGrid) {{
        releasesGrid.destroy();
        releasesGrid = null;
      }}
      return;
    }}

    // Dynamically create column definitions from the data
    const columnDefs = Object.keys(data[0]).map(key => ({{
      field: key,
      headerName: key,
      filter: true,
      sortable: true,
      width: 150,
      cellRenderer: (params) => {{
        // Auto-link URL fields
        if (key.includes('url') && params.value && typeof params.value === 'string' && params.value.startsWith('http')) {{
          return `<a href="${{params.value}}" target="_blank">${{params.value}}</a>`;
        }}
        // Format array fields
        if (Array.isArray(params.value)) {{
          return params.value.join(', ');
        }}
        return params.value;
      }}
    }}));

    const gridOptions = {{
      columnDefs: columnDefs,
      rowData: data,
      defaultColDef: {{
        resizable: true,
        sortable: true,
        filter: true
      }},
      pagination: true,
      paginationPageSize: 50
    }};

    // Destroy existing grid before creating new one
    if (releasesGrid) {{
      releasesGrid.destroy();
    }}

    releasesGrid = agGrid.createGrid(document.getElementById('releasesGrid'), gridOptions);

    setTableStatus('releases', 'success', `${{data.length}} rows`);

    // Update stats card
    const statEl = document.getElementById('stat-releases');
    if (statEl) {{
      statEl.textContent = data.length;
    }}
  }} catch (err) {{
    console.error('Failed to load releases table:', err);
    setTableStatus('releases', 'error', err.message);
    if (releasesGrid) {{
      releasesGrid.destroy();
      releasesGrid = null;
    }}
  }}
}}

async function runReleasesQuery() {{
  console.log('Running releases query...');
  const queryText = document.getElementById('releasesQuery').value;
  console.log('Query:', queryText);
  try {{
    await loadReleasesTable();
  }} catch (err) {{
    console.error('Query execution failed:', err);
    alert('Query failed: ' + err.message);
  }}
}}

let librariesGrid = null;

async function loadLibrariesTable(customSQL) {{
  setTableStatus('libraries', 'loading', 'Loading...');

  try {{
    const sql = customSQL || document.getElementById('librariesQuery').value;
    const data = await queryDuckDB(sql, 'libraries');

    if (!data || data.length === 0) {{
      setTableStatus('libraries', 'error', 'No data');
      if (librariesGrid) {{
        librariesGrid.destroy();
        librariesGrid = null;
      }}
      return;
    }}

    // Dynamically create column definitions from the data
    const columnDefs = Object.keys(data[0]).map(key => ({{
      field: key,
      headerName: key,
      filter: true,
      sortable: true,
      width: 150,
      cellRenderer: (params) => {{
        // Auto-link URL fields
        if (key.includes('url') && params.value && typeof params.value === 'string' && params.value.startsWith('http')) {{
          return `<a href="${{params.value}}" target="_blank">${{params.value}}</a>`;
        }}
        return params.value;
      }}
    }}));

    const gridOptions = {{
      columnDefs: columnDefs,
      rowData: data,
      defaultColDef: {{
        resizable: true,
        sortable: true,
        filter: true
      }},
      pagination: true,
      paginationPageSize: 50
    }};

    // Destroy existing grid before creating new one
    if (librariesGrid) {{
      librariesGrid.destroy();
    }}

    librariesGrid = agGrid.createGrid(document.getElementById('librariesGrid'), gridOptions);

    setTableStatus('libraries', 'success', `${{data.length}} rows`);

    // Update stats card
    const statEl = document.getElementById('stat-libraries');
    if (statEl) {{
      statEl.textContent = data.length;
    }}
  }} catch (err) {{
    console.error('Failed to load libraries table:', err);
    setTableStatus('libraries', 'error', err.message);
    if (librariesGrid) {{
      librariesGrid.destroy();
      librariesGrid = null;
    }}
  }}
}}

async function runLibrariesQuery() {{
  console.log('Running libraries query...');
  const queryText = document.getElementById('librariesQuery').value;
  console.log('Query:', queryText);
  try {{
    await loadLibrariesTable();
  }} catch (err) {{
    console.error('Query execution failed:', err);
    alert('Query failed: ' + err.message);
  }}
}}

let symbolsGrid = null;

async function loadSymbolsTable(customSQL) {{
  setTableStatus('symbols', 'loading', 'Loading...');

  try {{
    const sql = customSQL || document.getElementById('symbolsQuery').value;
    const data = await queryDuckDB(sql, 'symbols');

    if (!data || data.length === 0) {{
      setTableStatus('symbols', 'error', 'No data');
      if (symbolsGrid) {{
        symbolsGrid.destroy();
        symbolsGrid = null;
      }}
      return;
    }}

    // Dynamically create column definitions from the data
    const columnDefs = Object.keys(data[0]).map(key => ({{
      field: key,
      headerName: key,
      filter: true,
      sortable: true,
      width: 150,
      cellRenderer: (params) => {{
        // Special rendering for boolean is_stub field
        if (key === 'is_stub' && typeof params.value === 'boolean') {{
          return params.value ? '✓' : '✗';
        }}
        return params.value;
      }}
    }}));

    const gridOptions = {{
      columnDefs: columnDefs,
      rowData: data,
      defaultColDef: {{
        resizable: true,
        sortable: true,
        filter: true
      }},
      pagination: true,
      paginationPageSize: 100
    }};

    // Destroy existing grid before creating new one
    if (symbolsGrid) {{
      symbolsGrid.destroy();
    }}

    symbolsGrid = agGrid.createGrid(document.getElementById('symbolsGrid'), gridOptions);

    setTableStatus('symbols', 'success', `${{data.length}} rows`);

    // Update stats card
    const statEl = document.getElementById('stat-symbols');
    if (statEl) {{
      statEl.textContent = data.length;
    }}
  }} catch (err) {{
    console.error('Failed to load symbols table:', err);
    setTableStatus('symbols', 'error', err.message);
    if (symbolsGrid) {{
      symbolsGrid.destroy();
      symbolsGrid = null;
    }}
  }}
}}

async function runSymbolsQuery() {{
  console.log('Running symbols query...');
  const queryText = document.getElementById('symbolsQuery').value;
  console.log('Query:', queryText);
  try {{
    await loadSymbolsTable();
  }} catch (err) {{
    console.error('Query execution failed:', err);
    alert('Query failed: ' + err.message);
  }}
}}

// Expose query functions to global scope for inline onclick handlers
window.runDriversQuery = runDriversQuery;
window.runReleasesQuery = runReleasesQuery;
window.runLibrariesQuery = runLibrariesQuery;
window.runSymbolsQuery = runSymbolsQuery;

async function init() {{
  const globalLoadingEl = document.getElementById('globalLoading');

  try {{
    // Check if AG Grid is loaded
    if (typeof agGrid === 'undefined') {{
      throw new Error('AG Grid library failed to load. Check your internet connection or try refreshing the page.');
    }}

    // Initialize DuckDB
    await initDuckDB();

    // Load all tables
    updateLoadingStep('tables', 'active', 'Loading tables...');

    const results = await Promise.allSettled([
      loadDriversTable(),
      loadReleasesTable(),
      loadLibrariesTable(),
      loadSymbolsTable()
    ]);

    // Check for any failures
    const failures = results.filter(r => r.status === 'rejected');
    if (failures.length > 0) {{
      updateLoadingStep('tables', 'error', `${{failures.length}} table(s) failed to load`);

      // Show detailed error for first failure
      const firstError = failures[0].reason;
      showError(
        'Failed to Load Tables',
        `${{failures.length}} of 4 tables failed to load.`,
        firstError.message
      );
    }} else {{
      updateLoadingStep('tables', 'success', 'All tables loaded successfully');
    }}

    // Hide global loading indicator
    globalLoadingEl.classList.add('hidden');

    // Add keyboard shortcuts for query execution (Enter to run, Shift+Enter for newline)
    document.getElementById('driversQuery').addEventListener('keydown', (e) => {{
      if (e.key === 'Enter' && !e.shiftKey) {{
        e.preventDefault();
        runDriversQuery();
      }}
    }});

    document.getElementById('releasesQuery').addEventListener('keydown', (e) => {{
      if (e.key === 'Enter' && !e.shiftKey) {{
        e.preventDefault();
        runReleasesQuery();
      }}
    }});

    document.getElementById('librariesQuery').addEventListener('keydown', (e) => {{
      if (e.key === 'Enter' && !e.shiftKey) {{
        e.preventDefault();
        runLibrariesQuery();
      }}
    }});

    document.getElementById('symbolsQuery').addEventListener('keydown', (e) => {{
      if (e.key === 'Enter' && !e.shiftKey) {{
        e.preventDefault();
        runSymbolsQuery();
      }}
    }});

  }} catch (err) {{
    console.error('Critical error during initialization:', err);
    updateLoadingStep('init-error', 'error', 'Initialization failed');

    showError(
      'Failed to Initialize Dashboard',
      'The dashboard could not be loaded. Please check the console for details.',
      err.message
    );

    // Keep loading indicator visible but update text
    const stepsDiv = document.getElementById('loadingSteps');
    stepsDiv.style.marginBottom = '20px';
  }}
}}

// Tab switching functionality
function switchTab(tabName) {{
  // Hide all tab contents
  document.querySelectorAll('.tab-content').forEach(content => {{
    content.classList.remove('active');
  }});

  // Deactivate all tab buttons
  document.querySelectorAll('.tab-button').forEach(button => {{
    button.classList.remove('active');
  }});

  // Show selected tab content
  const tabContent = document.getElementById(`tab-${{tabName}}`);
  if (tabContent) {{
    tabContent.classList.add('active');
  }}

  // Activate selected tab button
  const tabButton = document.querySelector(`[data-tab="${{tabName}}"]`);
  if (tabButton) {{
    tabButton.classList.add('active');
  }}
}}

// Setup tab click handlers
document.addEventListener('DOMContentLoaded', () => {{
  document.querySelectorAll('.tab-button').forEach(button => {{
    button.addEventListener('click', () => {{
      const tabName = button.getAttribute('data-tab');
      switchTab(tabName);
    }});
  }});
}});

// Global error handler for unhandled errors
window.addEventListener('error', (event) => {{
  console.error('Unhandled error:', event.error);
  showError(
    'Unexpected Error',
    'An unexpected error occurred while loading the dashboard.',
    event.error ? event.error.message : event.message
  );
}});

// Global handler for unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {{
  console.error('Unhandled promise rejection:', event.reason);
  showError(
    'Unexpected Error',
    'An unexpected error occurred while loading the dashboard.',
    event.reason ? event.reason.message : String(event.reason)
  );
}});

// Start initialization
init();</script>

</body>
</html>"#,
    timeline_svg = timeline_svg,
    releases_chart_svg = releases_chart_svg,
    libraries_chart_svg = libraries_chart_svg,
    symbols_chart_svg = symbols_chart_svg,
    drivers_size = drivers_size,
    releases_size = releases_size,
    libraries_size = libraries_size,
    symbols_size = symbols_size
    )
}

fn csv_to_html_table(csv: &str) -> String {
    let mut html = String::new();
    html.push_str("<table border=\"1\">\n");

    let mut lines = csv.lines();

    // Header row
    if let Some(header) = lines.next() {
        html.push_str("<tr>\n");
        for cell in parse_csv_line(header) {
            html.push_str(&format!("<th>{}</th>\n", cell));
        }
        html.push_str("</tr>\n");
    }

    // Data rows
    for line in lines {
        html.push_str("<tr>\n");
        for cell in parse_csv_line(line) {
            html.push_str(&format!("<td>{}</td>\n", cell));
        }
        html.push_str("</tr>\n");
    }

    html.push_str("</table>\n");
    html
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut current_cell = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                // Check if this is an escaped quote
                if in_quotes && chars.peek() == Some(&'"') {
                    current_cell.push('"');
                    chars.next(); // Skip the second quote
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                cells.push(current_cell.clone());
                current_cell.clear();
            }
            _ => {
                current_cell.push(c);
            }
        }
    }

    // Push the last cell
    if !current_cell.is_empty() || !cells.is_empty() {
        cells.push(current_cell);
    }

    cells
}

