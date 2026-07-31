mod artifact_parser;
mod config;
mod csv_utils;
mod dependencies;
mod download;
mod error;
mod github;
mod language_detector;
mod models;
mod parquet;
mod progress;
mod pypi;
mod stub_detector;
mod svg;
mod symbols;

use clap::{Parser, Subcommand};
use error::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::ProgressBar;
use models::ReleaseRecord;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tera::{Context, Tera};

// Type aliases for complex types
type ReleaseDataValue = (
    Option<String>,              // version
    chrono::DateTime<chrono::Utc>, // published_date
    String,                      // release_url
    HashSet<String>,             // os_set
    HashSet<String>,             // arch_set
    bool,                        // has_universal_binary
    Option<HashSet<String>>,     // universal_binary_archs (architectures from universal binaries)
);
type ReleaseDataMap = HashMap<(String, String), ReleaseDataValue>;
type ReleaseDataVec = Vec<((String, String), ReleaseDataValue)>;
type DriverFirstLatest = HashMap<
    String,
    (
        chrono::DateTime<chrono::Utc>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        Option<String>,
    ),
>;

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
    /// Analyze downloaded artifacts and generate parquet reports
    Analyze,
    /// Generate HTML dashboard from existing parquet files
    Html,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Locate the project root (the directory containing drivers.toml) and
    // change into it so all relative paths (cache/, dist/, templates/) work
    // regardless of which directory the user invokes the binary from.
    let project_root = std::env::current_dir()
        .ok()
        .and_then(|cwd| {
            let mut dir = cwd.as_path();
            loop {
                if dir.join("drivers.toml").exists() {
                    return Some(dir.to_path_buf());
                }
                match dir.parent() {
                    Some(parent) => dir = parent,
                    None => return None,
                }
            }
        });

    match project_root {
        Some(root) => {
            if let Err(e) = std::env::set_current_dir(&root) {
                eprintln!("Warning: could not change to project root {}: {}", root.display(), e);
            }
        }
        None => {
            eprintln!(
                "Error: could not find drivers.toml in the current directory or any parent.\n\
                 Run adbc-index from the project root."
            );
            std::process::exit(1);
        }
    }

    match cli.command {
        Commands::Download { driver } => download(driver).await,
        Commands::Analyze => analyze().await,
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
            eprintln!(
                "✓ GitHub token verified. Rate limit: {}/{}",
                rate_limit.remaining, rate_limit.limit
            );
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
            return Err(error::AdbcIndexError::Config(format!(
                "Driver '{}' not found in configuration",
                driver_name
            )));
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

        let mut driver_new = 0;
        let mut driver_cached = 0;
        let mut source_errors = 0;

        // Process each source for this driver
        for source in &driver.sources {
            let source_id = source.source_id();

            if std::env::var("DEBUG").is_ok() {
                eprintln!("DEBUG: Processing source: {}", source_id);
            }

            // Fetch releases based on source type
            let releases_result = match source {
                models::DriverSource::GitHub { owner, repo } => {
                    if std::env::var("DEBUG").is_ok() {
                        eprintln!("DEBUG: Fetching from GitHub: {}/{}", owner, repo);
                    }
                    gh_client.fetch_releases(owner, repo).await
                }
                models::DriverSource::PyPI { package } => pypi_client
                    .fetch_releases(package)
                    .await
                    .map(|pypi_releases| pypi::pypi_to_github_releases(pypi_releases, package)),
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
                            if let Some(version_str) =
                                ReleaseRecord::parse_version(&release.tag_name)
                            {
                                if let Ok(version) = semver::Version::parse(&version_str) {
                                    return version_req.matches(&version);
                                }
                            }
                            true
                        });
                    }

                    if std::env::var("DEBUG").is_ok() {
                        eprintln!("DEBUG: Processing {} releases...", releases.len());
                    }

                    for release in &releases {
                        let tag = release.tag_name.clone();

                        if std::env::var("DEBUG").is_ok() {
                            eprintln!("DEBUG: Processing release: {}", tag);
                        }

                        let sanitized_tag = ReleaseRecord::sanitize_tag_for_path(&tag);

                        // Save release metadata for analyze command to use
                        let release_dir = cache_dir
                            .join(&driver.name)
                            .join(&source_id)
                            .join(&sanitized_tag);
                        std::fs::create_dir_all(&release_dir).ok();
                        let metadata_path = release_dir.join(".release_metadata.json");
                        if !metadata_path.exists() {
                            let metadata = serde_json::json!({
                                "tag_name": tag,
                                "published_at": release.published_at,
                                "html_url": release.html_url,
                            });
                            let _ = std::fs::write(
                                &metadata_path,
                                serde_json::to_string_pretty(&metadata).unwrap(),
                            );
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
                                .join(&source_id)
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
                                let (download_url, url_type) =
                                    if tag.contains('/') && asset.url.is_some() {
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
                                    source_id: source_id.clone(),
                                    release_tag: tag.clone(),
                                    artifact_name: asset.name.clone(),
                                    expected_size: asset.size,
                                });
                                driver_new += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  ⚠️  Source error ({}): {}", source_id, e);
                    source_errors += 1;
                }
            }
        }

        if std::env::var("DEBUG").is_ok() {
            eprintln!(
                "DEBUG: Finishing driver progress: {} new, {} cached, {} source errors",
                driver_new, driver_cached, source_errors
            );
        }

        if source_errors == driver.sources.len() {
            // All sources failed
            driver_progress.finish_with_message("Error: all sources failed".to_string());
            driver_fetch_errors += 1;
        } else {
            driver_progress.finish_with_message(format!(
                "{} new, {} cached{}",
                driver_new,
                driver_cached,
                if source_errors > 0 {
                    format!(", {} source errors", source_errors)
                } else {
                    String::new()
                }
            ));
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
        return Err(error::AdbcIndexError::Config(format!(
            "Failed to fetch releases from {} driver(s)",
            driver_fetch_errors
        )));
    }

    if std::env::var("DEBUG").is_ok() {
        eprintln!(
            "DEBUG: Finishing main progress: {} cached, {} to download",
            cached_count,
            download_tasks.len()
        );
    }

    progress.finish_with_message(&format!(
        "{} cached, {} to download",
        cached_count,
        download_tasks.len()
    ));

    if std::env::var("DEBUG").is_ok() {
        eprintln!("DEBUG: Progress finished");
    }

    // Download artifacts
    if !download_tasks.is_empty() {
        let download_progress =
            progress::ProgressTracker::new(download_tasks.len() as u64, "Download");
        download_progress.set_message("Downloading artifacts");

        let download_manager = download::DownloadManager::with_progress(
            cache_dir.clone(),
            concurrent_downloads,
            download_progress.multi(),
            Some(github_token.clone()),
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
            download_progress.finish_with_message(&format!(
                "{} downloaded, {} errors",
                success_count, error_count
            ));
            return Err(error::AdbcIndexError::Download {
                url: "multiple".to_string(),
                reason: format!("{} artifact(s) failed", error_count),
            });
        } else {
            download_progress
                .finish_with_message(&format!("{} artifacts downloaded", success_count));
        }
    }

    Ok(())
}

async fn analyze() -> Result<()> {
    let config = PathBuf::from("drivers.toml");
    let cache_dir = PathBuf::from("cache");

    // Load configuration
    let drivers = config::load_config(&config)?;

    use models::DriverRecord;

    // Configure symbol filter - only extract symbols starting with "Adbc"
    let symbol_filter = symbols::SymbolFilter::default();

    // Create progress tracker
    let analyze_progress = progress::ProgressTracker::new(drivers.len() as u64, "Analyze");
    analyze_progress.set_message("Processing drivers");

    // Process all drivers in parallel
    let mut tasks = FuturesUnordered::new();
    for driver in drivers {
        let cache_dir_clone = cache_dir.clone();
        let symbol_filter_clone = symbol_filter.clone();
        let progress_multi = analyze_progress.multi();

        let task = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(process_driver(
                driver,
                cache_dir_clone,
                symbol_filter_clone,
                progress_multi,
            ))
        });

        tasks.push(task);
    }

    // Collect results from all tasks
    let mut library_records = Vec::new();
    let mut symbol_records = Vec::new();
    let mut dependency_records = Vec::new();
    let mut release_data: ReleaseDataMap = HashMap::new();
    let mut driver_stats: HashMap<String, (String, String, usize)> = HashMap::new();

    while let Some(task_result) = tasks.next().await {
        match task_result {
            Ok(Ok(result)) => {
                let _driver_name = result.driver_name.clone();

                // Merge results
                library_records.extend(result.library_records);
                symbol_records.extend(result.symbol_records);
                dependency_records.extend(result.dependency_records);

                // Merge release data
                for (key, value) in result.release_data {
                    release_data.insert(key, value);
                }

                // Store driver stats
                driver_stats.insert(
                    result.driver_name,
                    (result.repo_owner, result.repo_name, result.library_count),
                );

                analyze_progress.inc(1);
            }
            Ok(Err(e)) => {
                eprintln!("  ⚠️  Processing error: {}", e);
                analyze_progress.inc(1);
            }
            Err(e) => {
                eprintln!("  ⚠️  Download error: {}", e);
                analyze_progress.inc(1);
            }
        }
    }

    analyze_progress.finish_with_message(&format!(
        "{} drivers, {} libraries, {} symbols, {} dependencies",
        driver_stats.len(),
        library_records.len(),
        symbol_records.len(),
        dependency_records.len()
    ));

    // Calculate first and latest release for each driver
    let mut driver_first_latest: DriverFirstLatest = HashMap::new();

    for ((name, _), (version, published_date, _, _, _, _, _)) in &release_data {
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
            .or_insert((
                *published_date,
                version.clone(),
                *published_date,
                version.clone(),
            ));
    }

    // Determine the latest release_tag per driver (by published_date)
    let mut latest_tag_per_driver: HashMap<String, (String, chrono::DateTime<chrono::Utc>)> =
        HashMap::new();
    for ((name, tag), (_, published_date, _, _, _, _, _)) in &release_data {
        latest_tag_per_driver
            .entry(name.clone())
            .and_modify(|(existing_tag, existing_date)| {
                if published_date > existing_date {
                    *existing_tag = tag.clone();
                    *existing_date = *published_date;
                }
            })
            .or_insert((tag.clone(), *published_date));
    }
    let latest_tag_per_driver: HashMap<String, String> = latest_tag_per_driver
        .into_iter()
        .map(|(name, (tag, _))| (name, tag))
        .collect();

    // Stamp is_latest on library, symbol, and dependency records
    for record in &mut library_records {
        record.is_latest = latest_tag_per_driver
            .get(&record.name)
            .map(|t| t == &record.release_tag)
            .unwrap_or(false);
    }
    for record in &mut symbol_records {
        record.is_latest = latest_tag_per_driver
            .get(&record.name)
            .map(|t| t == &record.release_tag)
            .unwrap_or(false);
    }
    for record in &mut dependency_records {
        record.is_latest = latest_tag_per_driver
            .get(&record.name)
            .map(|t| t == &record.release_tag)
            .unwrap_or(false);
    }

    // Aggregate languages from library records to determine primary language for each driver
    let mut driver_languages: HashMap<String, HashMap<String, usize>> = HashMap::new();
    for lib in &library_records {
        if let Some(ref lang) = lib.language {
            driver_languages
                .entry(lib.name.clone())
                .or_insert_with(HashMap::new)
                .entry(lang.clone())
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
    }

    // Determine primary language (most common) for each driver
    let primary_languages: HashMap<String, String> = driver_languages
        .into_iter()
        .map(|(driver, lang_counts)| {
            let primary = lang_counts
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(lang, _)| lang)
                .unwrap_or_else(|| "unknown".to_string());
            (driver, primary)
        })
        .collect();

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
            let (
                first_release_date,
                first_release_version,
                latest_release_date,
                latest_release_version,
            ) = driver_first_latest.get(name).cloned().unwrap_or_else(|| {
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
                language: primary_languages.get(name).cloned(),
            }
        })
        .collect();

    // Sort by name
    driver_records.sort_by(|a, b| a.name.cmp(&b.name));

    // Convert release_data to ReleaseRecords
    let mut release_records: Vec<models::ReleaseRecord> = release_data
        .into_iter()
        .map(
            |((name, release_tag), (version, published_date, release_url, os_set, arch_set, has_universal_binary, universal_binary_archs_opt))| {
                let mut os: Vec<String> = os_set.into_iter().collect();
                let mut arch: Vec<String> = arch_set.into_iter().collect();
                os.sort();
                arch.sort();

                let universal_binary_archs = if let Some(archs_set) = universal_binary_archs_opt {
                    let mut archs: Vec<String> = archs_set.into_iter().collect();
                    archs.sort();
                    Some(archs)
                } else {
                    None
                };

                models::ReleaseRecord {
                    name: name.clone(),
                    release_tag: release_tag.clone(),
                    version,
                    published_date,
                    release_url,
                    os,
                    arch,
                    has_universal_binary,
                    universal_binary_archs,
                    is_latest: latest_tag_per_driver
                        .get(&name)
                        .map(|t| t == &release_tag)
                        .unwrap_or(false),
                }
            },
        )
        .collect();

    // Sort by name, then by release_tag
    release_records.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.release_tag.cmp(&b.release_tag))
    });

    // Create dist directory for output
    let dist_dir = PathBuf::from("dist");
    std::fs::create_dir_all(&dist_dir)?;

    // Collect driver names for validation before moving driver_records
    let actual_driver_names: HashSet<String> = driver_records
        .iter()
        .map(|d| d.name.clone())
        .collect();

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

    // Write dependencies.parquet
    let dependencies_output = dist_dir.join("dependencies.parquet");
    let mut dependencies_writer = parquet::DependenciesWriter::new(&dependencies_output)?;
    for record in dependency_records {
        dependencies_writer.add_record(record)?;
    }
    dependencies_writer.close()?;
    write_progress.inc(1);

    write_progress.finish_with_message("Parquet files written");

    // Validate that all drivers from config are present in output
    println!("\n🔍 Validating output...");
    let config_drivers = config::load_config(&config)?;
    let expected_drivers: HashSet<String> = config_drivers
        .iter()
        .map(|d| d.name.clone())
        .collect();

    let missing_drivers: Vec<String> = expected_drivers
        .difference(&actual_driver_names)
        .cloned()
        .collect();

    if !missing_drivers.is_empty() {
        eprintln!("\n⚠️  Warning: The following drivers from drivers.toml are missing from the output:");
        for driver in &missing_drivers {
            eprintln!("  - {}", driver);
        }
        eprintln!("\nThis usually means:");
        eprintln!("  1. No cached artifacts exist (run 'adbc-index download' first)");
        eprintln!("  2. An error occurred during processing (check logs above)");
        return Err(error::AdbcIndexError::Config(format!(
            "Missing {} driver(s) in output: {}",
            missing_drivers.len(),
            missing_drivers.join(", ")
        )));
    }

    println!("✓ All {} drivers from drivers.toml are present in output", config_drivers.len());

    Ok(())
}

/// Result of processing a single driver
struct DriverProcessResult {
    library_records: Vec<models::LibraryRecord>,
    symbol_records: Vec<models::SymbolRecord>,
    dependency_records: Vec<models::DependencyRecord>,
    release_data: ReleaseDataVec,
    driver_name: String,
    repo_owner: String,
    repo_name: String,
    library_count: usize,
}

/// Read releases from cache directory instead of fetching from API
/// This allows analyze to work offline without GitHub/PyPI access
fn read_releases_from_cache(
    cache_dir: &Path,
    driver_name: &str,
) -> Result<Vec<github::types::Release>> {
    use std::collections::HashMap;
    use std::fs;

    let driver_cache_dir = cache_dir.join(driver_name);

    if !driver_cache_dir.exists() {
        return Ok(Vec::new());
    }

    // Map from tag_name to release data
    // This allows merging assets from multiple sources for the same tag
    let mut releases_map: HashMap<String, github::types::Release> = HashMap::new();

    // Collect all tag directories to process.
    // Handles two cache layouts:
    //   Old (flat):   cache/{driver}/{version}/artifacts...
    //   New (nested): cache/{driver}/{source}/{version}/artifacts...
    // We distinguish them by checking if the first-level directory contains
    // a .release_metadata.json (old style version dir) or only subdirectories (new style source dir).
    let mut tag_dirs: Vec<std::path::PathBuf> = Vec::new();

    let top_entries = fs::read_dir(&driver_cache_dir)?;
    for top_entry in top_entries {
        let top_entry = top_entry?;
        let top_path = top_entry.path();

        // Skip non-directories and hidden files
        if !top_path.is_dir() || top_entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }

        // Detect old-style flat layout: version dir contains .release_metadata.json or artifact files directly
        let has_metadata = top_path.join(".release_metadata.json").exists();
        let has_artifact_files = if !has_metadata {
            // Check if directory contains any regular files (not just subdirectories)
            fs::read_dir(&top_path)?
                .filter_map(|e| e.ok())
                .any(|e| e.path().is_file() && !e.file_name().to_string_lossy().starts_with('.'))
        } else {
            false
        };

        if has_metadata || has_artifact_files {
            // Old-style: this IS a version/tag directory
            tag_dirs.push(top_path);
        } else {
            // New-style: this is a source directory containing version subdirectories
            let sub_entries = fs::read_dir(&top_path)?;
            for sub_entry in sub_entries {
                let sub_entry = sub_entry?;
                let sub_path = sub_entry.path();
                if !sub_path.is_dir() || sub_entry.file_name().to_string_lossy().starts_with('.') {
                    continue;
                }
                tag_dirs.push(sub_path);
            }
        }
    }

    // Process each tag directory
    for tag_path in tag_dirs {
        let tag_name = tag_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Read release metadata if available
        let metadata_path = tag_path.join(".release_metadata.json");
        let (published_at, html_url) = if metadata_path.exists() {
            if let Ok(metadata_content) = fs::read_to_string(&metadata_path) {
                if let Ok(metadata) =
                    serde_json::from_str::<serde_json::Value>(&metadata_content)
                {
                    let published_at = metadata
                        .get("published_at")
                        .and_then(|v| v.as_str())
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&chrono::Utc));
                    let html_url = metadata
                        .get("html_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    (published_at, html_url)
                } else {
                    (None, String::new())
                }
            } else {
                (None, String::new())
            }
        } else {
            (None, String::new())
        };

        // Read artifacts in this tag directory
        let mut assets = Vec::new();
        let asset_entries = fs::read_dir(&tag_path)?;
        for asset_entry in asset_entries {
            let asset_entry = asset_entry?;
            let asset_path = asset_entry.path();

            // Skip .sha256 files and hidden files
            let filename = asset_entry.file_name().to_string_lossy().to_string();
            if filename.ends_with(".sha256")
                || filename.ends_with(".analysis.json")
                || filename.starts_with('.')
            {
                continue;
            }

            // Skip non-files
            if !asset_path.is_file() {
                continue;
            }

            let size = fs::metadata(&asset_path)?.len() as i64;

            assets.push(github::types::Asset {
                name: filename,
                browser_download_url: String::new(), // Not needed for cache-based processing
                url: None,
                size,
                download_count: 0,
            });
        }

        // Merge assets with existing release or create new release
        if !assets.is_empty() {
            releases_map
                .entry(tag_name.clone())
                .and_modify(|existing_release| {
                    // Merge assets from this source with existing assets
                    existing_release.assets.extend(assets.clone());
                })
                .or_insert_with(|| github::types::Release {
                    tag_name: tag_name.clone(),
                    name: Some(tag_name.clone()),
                    published_at,
                    html_url,
                    assets,
                    draft: false,
                    prerelease: false,
                });
        }
    }

    let releases: Vec<github::types::Release> = releases_map.into_values().collect();

    Ok(releases)
}

/// Process a single driver and return its results
async fn process_driver(
    driver: models::DriverConfig,
    cache_dir: PathBuf,
    symbol_filter: symbols::SymbolFilter,
    progress_multi: Arc<indicatif::MultiProgress>,
) -> Result<DriverProcessResult> {
    use models::{DependencyRecord, LibraryRecord, SymbolRecord};
    use std::collections::HashSet;

    let mut library_records = Vec::new();
    let mut symbol_records = Vec::new();
    let mut dependency_records = Vec::new();
    let mut release_data_vec: ReleaseDataVec = Vec::new();
    let mut library_count = 0;

    // Create spinner for this driver
    let driver_spinner = progress_multi.add(ProgressBar::new_spinner());
    driver_spinner.set_style(
        indicatif::ProgressStyle::default_spinner()
            .template(&format!("  ├─ {{spinner}} {} {{msg}}", driver.name))
            .unwrap(),
    );
    driver_spinner.enable_steady_tick(std::time::Duration::from_millis(100));
    driver_spinner.set_message("Reading releases from cache");

    // Read releases from cache instead of fetching from API
    // This allows analyze to work offline without GitHub/PyPI access
    let mut releases = read_releases_from_cache(&cache_dir, &driver.name)?;

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

    driver_spinner.set_message(format!("Processing {} releases", releases.len()));

    for (release_idx, release) in releases.iter().enumerate() {
        let release_url = release.html_url.clone();
        let tag = release.tag_name.clone();
        let version = models::ReleaseRecord::parse_version(&tag);
        let published_date = release.published_at.unwrap_or_else(chrono::Utc::now);

        driver_spinner.set_message(format!(
            "Processing release {}/{}: {}",
            release_idx + 1,
            releases.len(),
            tag
        ));

        for asset in &release.assets {
            // Parse artifact metadata
            let artifact_meta = artifact_parser::parse_artifact(&asset.name);

            // Skip non-driver artifacts (docs, configs, etc.)
            if !is_driver_artifact(&artifact_meta.file_format) {
                continue;
            }

            // ── Analysis cache check ──────────────────────────────────────
            // Locate the artifact in the cache directory so we can read the
            // sidecar files (.sha256, .analysis.json) without extracting.
            let artifact_path =
                find_artifact_path(&cache_dir, &driver.name, &tag, &asset.name);

            if let Some(ref apath) = artifact_path {
                if let Some(cached) = load_analysis_cache(apath) {
                    // Cache hit: push the pre-computed records and skip all
                    // extraction / parsing work.
                    if let Some(lib_rec) = cached.library_record {
                        let os = lib_rec.os.clone();
                        let arch = lib_rec.arch.clone();
                        let is_universal = arch.len() > 1;

                        library_records.push(lib_rec);
                        symbol_records.extend(cached.symbol_records);
                        dependency_records.extend(cached.dependency_records);
                        library_count += 1;

                        // Aggregate release data (identical logic to the miss path below)
                        let key = (driver.name.clone(), tag.clone());
                        if let Some(entry) = release_data_vec.iter_mut().find(|(k, _)| k == &key) {
                            entry.1 .3.insert(os.clone());
                            for av in arch.iter() { entry.1 .4.insert(av.clone()); }
                            if is_universal {
                                entry.1 .5 = true;
                                let ua = entry.1 .6.get_or_insert_with(std::collections::HashSet::new);
                                for av in arch.iter() { ua.insert(av.clone()); }
                            }
                        } else {
                            let mut os_set = std::collections::HashSet::new();
                            let mut arch_set = std::collections::HashSet::new();
                            os_set.insert(os.clone());
                            for av in arch.iter() { arch_set.insert(av.clone()); }
                            let uba = if is_universal {
                                let mut s = std::collections::HashSet::new();
                                for av in arch.iter() { s.insert(av.clone()); }
                                Some(s)
                            } else { None };
                            release_data_vec.push((
                                key,
                                (version.clone(), published_date, release_url.clone(),
                                 os_set, arch_set, is_universal, uba),
                            ));
                        }
                    }
                    continue; // ← skip extraction entirely
                }
            }
            // ── End cache check ───────────────────────────────────────────

            // Record slice offsets so we can snapshot the new records after
            // analysis and write them to the cache sidecar.
            let lib_idx_before  = library_records.len();
            let sym_idx_before  = symbol_records.len();
            let dep_idx_before  = dependency_records.len();

            // Extract archive and find shared library
            let library_info =
                extract_and_find_library(&cache_dir, &driver.name, &tag, &asset.name);

            // Only process if we found a library
            if let Some(lib_info) = library_info {
                if let (Some(os), Some(arch)) = (&artifact_meta.os, &artifact_meta.arch) {
                    // Skip if arch list is empty (invalid metadata)
                    if arch.is_empty() {
                        if std::env::var("DEBUG").is_ok() {
                            eprintln!(
                                "⚠️  Skipping asset {} - empty architecture list (invalid metadata)",
                                asset.name
                            );
                        }
                        continue;
                    }

                    // Add to library records (language will be added later)
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
                        language: None,
                        is_latest: false, // set after all releases are collected
                    });

                    // Extract symbols and analyze stubs in a single pass
                    if let Some(ref lib_path) = lib_info.path {
                        // Use explicit language from config if provided, otherwise detect
                        let language = if let Some(ref explicit_lang) = driver.language {
                            Some(explicit_lang.clone())
                        } else {
                            // Detect language from binary strings (works for stripped binaries)
                            // This extracts printable strings from the binary's data sections
                            symbols::extract_binary_strings(lib_path)
                                .ok()
                                .and_then(|strings| language_detector::detect_language(&strings))
                        };

                        // Update the last library record with language
                        if let Some(last_record) = library_records.last_mut() {
                            last_record.language = language;
                        }

                        match symbols::extract_symbols_and_stubs(lib_path, &symbol_filter) {
                            Ok((syms, stub_analyses)) => {
                                // Build map of symbol -> stub analysis
                                let stub_map: std::collections::HashMap<
                                    String,
                                    stub_detector::StubAnalysis,
                                > = stub_analyses
                                    .into_iter()
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
                                        return_status: stub_info.and_then(|s| {
                                            s.status_code.map(|c| c.name().to_string())
                                        }),
                                        is_latest: false, // set after all releases are collected
                                    });
                                }
                            }
                            Err(_e) => {
                                // Silently skip symbol extraction errors
                            }
                        }

                        // Extract dynamic library dependencies
                        match dependencies::extract_dependencies(lib_path) {
                            Ok(deps) => {
                                for (idx, dep) in deps.iter().enumerate() {
                                    dependency_records.push(DependencyRecord {
                                        name: driver.name.clone(),
                                        release_tag: tag.clone(),
                                        version: version.clone(),
                                        os: os.clone(),
                                        arch: arch.clone(),
                                        library_name: lib_info.name.clone(),
                                        dependency: dep.clone(),
                                        dependency_basename: dependencies::dependency_basename(dep),
                                        dependency_index: idx as i64,
                                        is_system: dependencies::is_system_dependency(dep, os),
                                        is_latest: false, // set after all releases are collected
                                    });
                                }
                            }
                            Err(e) => {
                                return Err(e);
                            }
                        }

                        // Clean up temp file after symbol extraction
                        let _ = std::fs::remove_file(lib_path);
                        // Also try to clean up the temp directory (will succeed if empty)
                        if let Some(parent) = lib_path.parent() {
                            let _ = std::fs::remove_dir(parent);
                        }
                    }

                    // Track library count
                    library_count += 1;

                    // ── Save analysis cache sidecar ───────────────────────────
                    if let Some(ref apath) = artifact_path {
                        if let Some(sha256) = read_artifact_sha256(apath) {
                            let cached_lib = library_records.get(lib_idx_before).cloned();
                            let cached_syms = symbol_records[sym_idx_before..].to_vec();
                            let cached_deps = dependency_records[dep_idx_before..].to_vec();
                            save_analysis_cache(apath, &ArtifactAnalysis {
                                cache_version: ANALYSIS_CACHE_VERSION,
                                artifact_sha256: sha256,
                                library_record: cached_lib,
                                symbol_records: cached_syms,
                                dependency_records: cached_deps,
                            });
                        }
                    }

                    // Aggregate release data
                    let key = (driver.name.clone(), tag.clone());

                    // Determine if this is a universal binary (multiple architectures in a single library)
                    let is_universal = arch.len() > 1;

                    // Find existing entry or create new one
                    if let Some(entry) = release_data_vec.iter_mut().find(|(k, _)| k == &key) {
                        entry.1 .3.insert(os.clone());
                        // arch is now Vec<String>, so extend the set with all architectures
                        for arch_val in arch.iter() {
                            entry.1 .4.insert(arch_val.clone());
                        }
                        // Track universal binary information
                        if is_universal {
                            entry.1 .5 = true; // has_universal_binary
                            let universal_archs = entry.1 .6.get_or_insert_with(HashSet::new);
                            for arch_val in arch.iter() {
                                universal_archs.insert(arch_val.clone());
                            }
                        }
                    } else {
                        let mut os_set = HashSet::new();
                        let mut arch_set = HashSet::new();
                        os_set.insert(os.clone());
                        // arch is now Vec<String>, so insert all architectures
                        for arch_val in arch.iter() {
                            arch_set.insert(arch_val.clone());
                        }

                        let has_universal_binary = is_universal;
                        let universal_binary_archs = if is_universal {
                            let mut archs = HashSet::new();
                            for arch_val in arch.iter() {
                                archs.insert(arch_val.clone());
                            }
                            Some(archs)
                        } else {
                            None
                        };

                        release_data_vec.push((
                            key,
                            (
                                version.clone(),
                                published_date,
                                release_url.clone(),
                                os_set,
                                arch_set,
                                has_universal_binary,
                                universal_binary_archs,
                            ),
                        ));
                    }
                }
            }
        }
    }

    // Extract repo owner and name from first source
    // For multi-source drivers, we use the first source for display purposes
    let (repo_owner, repo_name) = if let Some(first_source) = driver.sources.first() {
        match first_source {
            models::DriverSource::GitHub { owner, repo } => (owner.clone(), repo.clone()),
            models::DriverSource::PyPI { package } => ("pypi".to_string(), package.clone()),
        }
    } else {
        ("unknown".to_string(), "unknown".to_string())
    };

    driver_spinner.finish_with_message(format!(
        "{} libraries, {} symbols",
        library_count,
        symbol_records.len()
    ));

    Ok(DriverProcessResult {
        library_records,
        symbol_records,
        dependency_records,
        release_data: release_data_vec,
        driver_name: driver.name,
        repo_owner,
        repo_name,
        library_count,
    })
}

// ── Analysis cache ────────────────────────────────────────────────────────────
//
// After analysing an artifact we write a JSON sidecar next to it:
//   cache/{driver}/{source}/{tag}/artifact.tar.gz.analysis.json
//
// On the next `analyze` run we load the sidecar if the artifact SHA256 still
// matches and the cache-format version is current, skipping the expensive
// extract / goblin / capstone work entirely.

/// Bump this whenever the analysis logic changes in a way that would produce
/// different results for the same binary.
const ANALYSIS_CACHE_VERSION: u32 = 1;

#[derive(serde::Serialize, serde::Deserialize)]
struct ArtifactAnalysis {
    cache_version: u32,
    /// SHA256 of the artifact archive (matches the .sha256 sidecar).
    artifact_sha256: String,
    library_record: Option<models::LibraryRecord>,
    symbol_records: Vec<models::SymbolRecord>,
    dependency_records: Vec<models::DependencyRecord>,
}

/// Return the path of the artifact file in the cache, searching across all
/// source sub-directories.
fn find_artifact_path(
    cache_dir: &Path,
    driver_name: &str,
    release_tag: &str,
    artifact_name: &str,
) -> Option<std::path::PathBuf> {
    let sanitized_tag = ReleaseRecord::sanitize_tag_for_path(release_tag);
    let driver_cache_dir = cache_dir.join(driver_name);
    if !driver_cache_dir.exists() {
        return None;
    }
    if let Ok(entries) = std::fs::read_dir(&driver_cache_dir) {
        for entry in entries.flatten() {
            let source_path = entry.path();
            if !source_path.is_dir() || entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let candidate = source_path.join(&sanitized_tag).join(artifact_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Read the hex SHA256 stored in the .sha256 sidecar file.
fn read_artifact_sha256(artifact_path: &Path) -> Option<String> {
    let sidecar = format!("{}.sha256", artifact_path.display());
    std::fs::read_to_string(sidecar).ok().map(|s| s.trim().to_string())
}

/// Load a valid analysis cache for the given artifact, or `None` on any miss.
fn load_analysis_cache(artifact_path: &Path) -> Option<ArtifactAnalysis> {
    let cache_path = format!("{}.analysis.json", artifact_path.display());
    let content = std::fs::read_to_string(&cache_path).ok()?;
    let cached: ArtifactAnalysis = serde_json::from_str(&content).ok()?;
    if cached.cache_version != ANALYSIS_CACHE_VERSION {
        return None;
    }
    if let Some(expected) = read_artifact_sha256(artifact_path) {
        if cached.artifact_sha256 != expected {
            return None;
        }
    }
    Some(cached)
}

/// Persist an analysis result as a JSON sidecar next to the artifact.
fn save_analysis_cache(artifact_path: &Path, analysis: &ArtifactAnalysis) {
    let cache_path = format!("{}.analysis.json", artifact_path.display());
    if let Ok(json) = serde_json::to_string(analysis) {
        let _ = std::fs::write(cache_path, json);
    }
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
    cache_dir: &Path,
    driver_name: &str,
    release_tag: &str,
    artifact_name: &str,
) -> Option<LibraryInfo> {
    use flate2::read::GzDecoder;
    use sha2::{Digest, Sha256};
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use tar::Archive;
    use zip::ZipArchive;

    let sanitized_tag = ReleaseRecord::sanitize_tag_for_path(release_tag);

    // Search for the artifact across all source directories
    // The cache structure is: cache_dir/driver_name/source_id/sanitized_tag/artifact_name
    let driver_cache_dir = cache_dir.join(driver_name);

    let artifact_path = if driver_cache_dir.exists() {
        let mut found_path = None;

        // Try to read source directories
        if let Ok(source_entries) = fs::read_dir(&driver_cache_dir) {
            for source_entry in source_entries {
                if let Ok(source_entry) = source_entry {
                    let source_path = source_entry.path();

                    // Skip non-directories and hidden files
                    if !source_path.is_dir() || source_entry.file_name().to_string_lossy().starts_with('.') {
                        continue;
                    }

                    // Check if artifact exists in this source directory
                    let candidate_path = source_path.join(&sanitized_tag).join(artifact_name);
                    if candidate_path.exists() {
                        found_path = Some(candidate_path);
                        break;
                    }
                }
            }
        }

        found_path
    } else {
        None
    };

    let artifact_path = artifact_path?;

    // Create unique temp directory for extracted libraries
    let temp_base = std::env::temp_dir();
    let unique_id = format!(
        "adbc-{}-{}-{}",
        driver_name,
        sanitized_tag,
        std::process::id()
    );
    let extract_dir = temp_base.join(unique_id);
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
            if filename.ends_with(".so")
                || filename.ends_with(".dylib")
                || filename.ends_with(".dll")
            {
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
            let filename = file.name().split('/').next_back()?.to_string();

            // Check if this is a shared library
            if filename.ends_with(".so")
                || filename.ends_with(".dylib")
                || filename.ends_with(".dll")
            {
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
            return Err(error::AdbcIndexError::Config(format!(
                "DuckDB query failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    let output_dir = PathBuf::from("dist");
    let drivers_path = output_dir.join("drivers.parquet");
    let releases_path = output_dir.join("releases.parquet");
    let libraries_path = output_dir.join("libraries.parquet");
    let symbols_path = output_dir.join("symbols.parquet");
    let dependencies_path = output_dir.join("dependencies.parquet");
    let output_file = output_dir.join("index.html");

    // Check if parquet files exist
    if !drivers_path.exists()
        || !releases_path.exists()
        || !libraries_path.exists()
        || !symbols_path.exists()
        || !dependencies_path.exists()
    {
        return Err(error::AdbcIndexError::Config(
            "Parquet files not found. Run 'adbc-index analyze' first.".to_string(),
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

    // Query library size statistics per driver (for box plot)
    let libraries_chart_csv = query_duckdb(
        "WITH latest_tag AS ( \
           SELECT name, release_tag \
           FROM read_parquet('dist/libraries.parquet') \
           QUALIFY ROW_NUMBER() OVER (PARTITION BY name ORDER BY published_date DESC) = 1 \
         ), \
         stats AS ( \
           SELECT name, \
           MIN(library_size_bytes) as min_size, \
           PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY library_size_bytes) as q1, \
           PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY library_size_bytes) as median, \
           PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY library_size_bytes) as q3, \
           MAX(library_size_bytes) as max_size \
           FROM read_parquet('dist/libraries.parquet') \
           GROUP BY name \
         ), \
         latest AS ( \
           SELECT l.name, \
           MIN(l.library_size_bytes) as latest_min, \
           MAX(l.library_size_bytes) as latest_max \
           FROM read_parquet('dist/libraries.parquet') l \
           JOIN latest_tag lt ON l.name = lt.name AND l.release_tag = lt.release_tag \
           GROUP BY l.name \
         ) \
         SELECT s.name, s.min_size, s.q1, s.median, s.q3, s.max_size, l.latest_min, l.latest_max \
         FROM stats s \
         JOIN latest l ON s.name = l.name \
         ORDER BY s.median DESC"
    )?;

    // Query symbol count per driver
    let symbols_chart_csv = query_duckdb(
        "SELECT name, COUNT(DISTINCT symbol) as symbol_count FROM read_parquet('dist/symbols.parquet') GROUP BY name ORDER BY symbol_count DESC"
    )?;

    // Query drivers by language
    let language_chart_csv = query_duckdb(
        "SELECT language, COUNT(*) as driver_count FROM read_parquet('dist/drivers.parquet') GROUP BY language ORDER BY driver_count DESC, language"
    )?;

    let dependencies_chart_csv = query_duckdb(
        "SELECT name, COUNT(*) as dep_count FROM read_parquet('dist/dependencies.parquet') WHERE is_latest = true AND is_system = false GROUP BY name ORDER BY dep_count DESC"
    )?;

    println!("🔨 Generating HTML...");

    // Generate charts
    // Build driver → language JSON for the in-browser brush system.
    // Queries the same drivers.parquet so no extra parquet file needed.
    let driver_lang_csv = query_duckdb(
        "SELECT name, COALESCE(language, '') as language FROM read_parquet('dist/drivers.parquet')"
    )?;
    let mut driver_languages_json = String::from("{\n");
    let mut first_entry = true;
    for line in driver_lang_csv.lines().skip(1) {
        if line.trim().is_empty() { continue; }
        let cells = csv_utils::parse_csv_line(line);
        if cells.len() >= 2 {
            if !first_entry { driver_languages_json.push_str(",\n"); }
            let name_j = cells[0].replace('\\', "\\\\").replace('"', "\\\"");
            let lang_j = cells[1].replace('\\', "\\\\").replace('"', "\\\"");
            driver_languages_json.push_str(&format!("  \"{}\":\"{}\"", name_j, lang_j));
            first_entry = false;
        }
    }
    driver_languages_json.push_str("\n}");

    let timeline_svg = svg::generate_driver_timeline_svg(&timeline_csv);
    let releases_chart_svg = svg::generate_bar_chart(&releases_chart_csv, "Releases per Driver", "driver");
    let libraries_chart_svg =
        svg::generate_box_plot(&libraries_chart_csv, "Library Size by Driver (MB)");
    let symbols_chart_svg =
        svg::generate_bar_chart(&symbols_chart_csv, "Unique Symbols per Driver", "driver");
    let language_chart_svg =
        svg::generate_bar_chart(&language_chart_csv, "Drivers by Language", "language");
    let dependencies_chart_svg =
        svg::generate_bar_chart(&dependencies_chart_csv, "Non-System Dependencies per Driver", "driver");

    // Get file sizes for download links
    let drivers_meta = std::fs::metadata(&drivers_path)?;
    let releases_meta = std::fs::metadata(&releases_path)?;
    let libraries_meta = std::fs::metadata(&libraries_path)?;
    let symbols_meta = std::fs::metadata(&symbols_path)?;
    let dependencies_meta = std::fs::metadata(&dependencies_path)?;

    let drivers_size = csv_utils::format_file_size(drivers_meta.len());
    let releases_size = csv_utils::format_file_size(releases_meta.len());
    let libraries_size = csv_utils::format_file_size(libraries_meta.len());
    let symbols_size = csv_utils::format_file_size(symbols_meta.len());
    let dependencies_size = csv_utils::format_file_size(dependencies_meta.len());

    // Find the most recent modification time across all parquet files
    let newest_mtime = [&drivers_meta, &releases_meta, &libraries_meta, &symbols_meta, &dependencies_meta]
        .iter()
        .filter_map(|m| m.modified().ok())
        .max()
        .unwrap_or(std::time::SystemTime::now());
    let last_updated: chrono::DateTime<chrono::Utc> = newest_mtime.into();
    let last_updated_str = last_updated.format("%Y-%m-%d %H:%M UTC").to_string();

    // Initialize Tera template engine
    let tera = match Tera::new("templates/**/*.tera") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("  ⚠️  Download error: {}", e);
            return Err(error::AdbcIndexError::Config(format!(
                "Template parsing error: {}",
                e
            )));
        }
    };

    // Create template context
    let mut context = Context::new();
    context.insert("timeline_svg", &timeline_svg);
    context.insert("releases_chart_svg", &releases_chart_svg);
    context.insert("libraries_chart_svg", &libraries_chart_svg);
    context.insert("symbols_chart_svg", &symbols_chart_svg);
    context.insert("language_chart_svg", &language_chart_svg);
    context.insert("dependencies_chart_svg", &dependencies_chart_svg);
    context.insert("drivers_size", &drivers_size);
    context.insert("releases_size", &releases_size);
    context.insert("libraries_size", &libraries_size);
    context.insert("symbols_size", &symbols_size);
    context.insert("dependencies_size", &dependencies_size);
    context.insert("driver_languages_json", &driver_languages_json);
    context.insert("last_updated", &last_updated_str);

    // Render template
    let html = match tera.render("index.html.tera", &context) {
        Ok(html) => html,
        Err(e) => {
            eprintln!("  ⚠️  Download error: {}", e);
            return Err(error::AdbcIndexError::Config(format!(
                "Template rendering error: {}",
                e
            )));
        }
    };

    // Write HTML file
    std::fs::write(&output_file, html)?;

    println!("✨ Done!");
    println!();
    println!("Output file: {:?}", output_file);

    Ok(())
}
