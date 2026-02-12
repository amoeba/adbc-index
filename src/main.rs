mod artifact_parser;
mod config;
mod csv_utils;
mod download;
mod error;
mod github;
mod info_codes;
mod models;
mod parquet;
mod progress;
mod pypi;
mod stub_detector;
mod svg;
mod symbols;

use clap::{Parser, Subcommand};
use error::Result;
use models::ReleaseRecord;
use std::path::PathBuf;
use std::sync::Arc;
use tera::{Tera, Context};

/// Context holding clients for accessing GitHub and PyPI APIs
struct ClientContext {
    gh_client: github::GitHubClient,
    pypi_client: pypi::PyPIClient,
}

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
                            let (download_url, url_type) = if tag.contains('/') && asset.url.is_some() {
                                (asset.url.clone().unwrap(), "API")
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


/// Result of processing a single driver
struct DriverProcessResult {
    library_records: Vec<models::LibraryRecord>,
    symbol_records: Vec<models::SymbolRecord>,
    info_code_records: Vec<models::InfoCodeRecord>,
    release_data: Vec<((String, String), (Option<String>, chrono::DateTime<chrono::Utc>, String, std::collections::HashSet<String>, std::collections::HashSet<String>))>,
    driver_name: String,
    repo_owner: String,
    repo_name: String,
    library_count: usize,
}

/// Process a single driver and return its results
async fn process_driver(
    ctx: Arc<ClientContext>,
    driver: models::DriverConfig,
    cache_dir: PathBuf,
    symbol_filter: symbols::SymbolFilter,
) -> Result<DriverProcessResult> {
    use std::collections::HashSet;
    use models::{LibraryRecord, SymbolRecord};

    let mut library_records = Vec::new();
    let mut symbol_records = Vec::new();
    let mut info_code_records = Vec::new();
    let mut release_data_vec: Vec<((String, String), (Option<String>, chrono::DateTime<chrono::Utc>, String, HashSet<String>, HashSet<String>))> = Vec::new();
    let mut library_count = 0;

    // Fetch releases based on source type
    let mut releases = match &driver.source {
        models::DriverSource::GitHub { owner, repo } => {
            ctx.gh_client.fetch_releases(owner, repo).await?
        }
        models::DriverSource::PyPI { package } => {
            let pypi_releases = ctx.pypi_client.fetch_releases(package).await?;
            pypi::pypi_to_github_releases(pypi_releases, package)
        }
    };

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

        // Track whether we found a macOS arm64 library for this release
        let mut found_macos_arm64 = false;

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

                        // Extract info codes for macOS arm64 builds only
                        // TEMPORARILY DISABLED: This loads and executes drivers, which can cause segfaults
                        // for drivers with missing dependencies (e.g., Oracle requiring Oracle client libs)
                        if os == "darwin" && arch == "arm64" {
                            found_macos_arm64 = true;

                            // Temporarily skip actual info code extraction
                            info_code_records.push(models::InfoCodeRecord {
                                name: driver.name.clone(),
                                release_tag: tag.clone(),
                                version: version.clone(),
                                os: os.clone(),
                                arch: arch.clone(),
                                library_name: lib_info.name.clone(),
                                success: false,
                                error_message: Some("Info code extraction temporarily disabled".to_string()),
                                info_codes: None,
                            });
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

        // If no macOS arm64 library was found for this release, create a failure record
        if !found_macos_arm64 {
            info_code_records.push(models::InfoCodeRecord {
                name: driver.name.clone(),
                release_tag: tag.clone(),
                version: version.clone(),
                os: "darwin".to_string(),
                arch: "arm64".to_string(),
                library_name: String::new(),
                success: false,
                error_message: Some("No macOS arm64 library found for this release".to_string()),
                info_codes: None,
            });
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
        info_code_records,
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

    // Create GitHub and PyPI clients
    let github_token = std::env::var("GITHUB_TOKEN").ok();
    let ctx = Arc::new(ClientContext {
        gh_client: github::GitHubClient::new(github_token)?,
        pypi_client: pypi::PyPIClient::new()?,
    });

    // Configure symbol filter - only extract symbols starting with "Adbc"
    let symbol_filter = symbols::SymbolFilter::default();

    // Create progress tracker
    let analyze_progress = progress::ProgressTracker::new(drivers.len() as u64, "Analyze");
    analyze_progress.set_message("Processing drivers");

    // Process all drivers in parallel
    let mut tasks = Vec::new();
    for driver in drivers {
        let ctx = Arc::clone(&ctx);
        let cache_dir_clone = cache_dir.clone();
        let symbol_filter_clone = symbol_filter.clone();

        let task = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(
                process_driver(ctx, driver, cache_dir_clone, symbol_filter_clone)
            )
        });

        tasks.push(task);
    }

    // Collect results from all tasks
    let mut library_records = Vec::new();
    let mut symbol_records = Vec::new();
    let mut info_code_records = Vec::new();
    let mut release_data: HashMap<(String, String), (Option<String>, chrono::DateTime<chrono::Utc>, String, HashSet<String>, HashSet<String>)> = HashMap::new();
    let mut driver_stats: HashMap<String, (String, String, usize)> = HashMap::new();

    for task in tasks {
        match task.await {
            Ok(Ok(result)) => {
                let _driver_name = result.driver_name.clone();

                // Merge results
                library_records.extend(result.library_records);
                symbol_records.extend(result.symbol_records);
                info_code_records.extend(result.info_code_records);

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
            Ok(Err(_e)) => {
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

    let write_progress = progress::ProgressTracker::new(5, "Write");
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

    // Write info_codes.parquet
    let info_codes_output = dist_dir.join("info_codes.parquet");
    let mut info_codes_writer = parquet::InfoCodesWriter::new(&info_codes_output)?;
    for record in info_code_records {
        info_codes_writer.add_record(record)?;
    }
    info_codes_writer.close()?;
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

async fn html() -> Result<()> {
    use std::process::Command;

    fn query_duckdb(sql: &str) -> Result<String> {
        let output = Command::new("duckdb")
            .arg("-csv")
            .arg("-c")
            .arg(sql)
            .output()?;

        if !output.status.success() {
            return Err(error::AdbcIndexError::Config(
                format!("DuckDB query failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    let output_dir = PathBuf::from("dist");
    let drivers_path = output_dir.join("drivers.parquet");
    let releases_path = output_dir.join("releases.parquet");
    let libraries_path = output_dir.join("libraries.parquet");
    let symbols_path = output_dir.join("symbols.parquet");
    let info_codes_path = output_dir.join("info_codes.parquet");
    let output_file = output_dir.join("index.html");

    // Check if parquet files exist
    if !drivers_path.exists() || !releases_path.exists() || !libraries_path.exists() || !symbols_path.exists() || !info_codes_path.exists() {
        return Err(error::AdbcIndexError::Config(
            "Parquet files not found. Run 'adbc-index build' first.".to_string(),
        ));
    }

    std::fs::create_dir_all(&output_dir)?;

    // Query driver timeline data
    let timeline_csv = query_duckdb(
        "SELECT name, timezone('UTC', first_release_date) as first_release_date FROM read_parquet('dist/drivers.parquet') ORDER BY first_release_date"
    )?;

    // Query releases per driver
    let releases_chart_csv = query_duckdb(
        "SELECT name, COUNT(*) as count FROM read_parquet('dist/releases.parquet') GROUP BY name ORDER BY count DESC"
    )?;

    // Query average library size per driver
    let libraries_chart_csv = query_duckdb(
        "SELECT name, AVG(library_size_bytes) as avg_size FROM read_parquet('dist/libraries.parquet') GROUP BY name ORDER BY avg_size DESC"
    )?;

    // Query symbol count per driver
    let symbols_chart_csv = query_duckdb(
        "SELECT name, COUNT(DISTINCT symbol) as symbol_count FROM read_parquet('dist/symbols.parquet') GROUP BY name ORDER BY symbol_count DESC"
    )?;

    // Query info code success rate per driver
    let info_codes_chart_csv = query_duckdb(
        "SELECT name, SUM(CASE WHEN success THEN 1 ELSE 0 END) as success_count, COUNT(*) as total_count FROM read_parquet('dist/info_codes.parquet') GROUP BY name ORDER BY success_count DESC"
    )?;

    println!("🔨 Generating HTML...");

    // Generate charts
    let timeline_svg = svg::generate_driver_timeline_svg(&timeline_csv);
    let releases_chart_svg = svg::generate_bar_chart(&releases_chart_csv, "Releases per Driver");
    let libraries_chart_svg = svg::generate_bar_chart(&libraries_chart_csv, "Average Library Size by Driver (MB)");
    let symbols_chart_svg = svg::generate_bar_chart(&symbols_chart_csv, "Unique Symbols per Driver");
    let info_codes_chart_svg = svg::generate_bar_chart(&info_codes_chart_csv, "GetInfo Success Rate per Driver");

    // Get file sizes for download links
    let drivers_size = csv_utils::format_file_size(std::fs::metadata(&drivers_path)?.len());
    let releases_size = csv_utils::format_file_size(std::fs::metadata(&releases_path)?.len());
    let libraries_size = csv_utils::format_file_size(std::fs::metadata(&libraries_path)?.len());
    let symbols_size = csv_utils::format_file_size(std::fs::metadata(&symbols_path)?.len());
    let info_codes_size = csv_utils::format_file_size(std::fs::metadata(&info_codes_path)?.len());

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
    context.insert("info_codes_chart_svg", &info_codes_chart_svg);
    context.insert("drivers_size", &drivers_size);
    context.insert("releases_size", &releases_size);
    context.insert("libraries_size", &libraries_size);
    context.insert("symbols_size", &symbols_size);
    context.insert("info_codes_size", &info_codes_size);

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


