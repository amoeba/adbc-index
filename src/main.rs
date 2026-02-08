mod artifact_parser;
mod config;
mod download;
mod error;
mod github;
mod models;
mod parquet;
mod symbols;

use clap::{Parser, Subcommand};
use error::Result;
use models::ReleaseRecord;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "adbc-index")]
#[command(about = "ADBC Index - Index and analyze ADBC driver releases and libraries", long_about = None)]
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
    /// Generate HTML dashboard from parquet files
    Html,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sync => sync().await,
        Commands::Report => report().await,
        Commands::Html => html().await,
    }
}

async fn sync() -> Result<()> {
    // Hardcoded configuration
    let config = PathBuf::from("drivers.toml");
    let cache_dir = PathBuf::from("cache");
    let concurrent_downloads = 5;

    // Get GitHub token (optional)
    let github_token = std::env::var("GITHUB_TOKEN").ok();

    println!("🚀 adbc-index sync - Syncing with GitHub releases");
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
        return Err(error::AdbcIndexError::Config(
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
            return Err(error::AdbcIndexError::Download {
                url: "multiple".to_string(),
                reason: format!("{} artifact(s) failed to download", error_count),
            });
        }
    } else {
        println!("✅ No new artifacts to download");
    }

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
                eprintln!("⚠️  Failed to parse {}: {}", release_json_path.display(), e);
            }
        }
    }

    Ok(releases)
}

async fn report() -> Result<()> {
    // Run sync first - if it fails, report fails
    println!("🔄 Running sync before generating report...");
    println!();
    sync().await?;
    println!();

    let config = PathBuf::from("drivers.toml");
    let cache_dir = PathBuf::from("cache");

    println!("📊 adbc-index report - Generating parquet reports");
    println!();

    // Load configuration
    println!("📋 Loading configuration from {:?}", config);
    let drivers = config::load_config(&config)?;
    println!("   Found {} drivers", drivers.len());
    println!();

    use std::collections::{HashMap, HashSet};
    use models::{LibraryRecord, DriverRecord, SymbolRecord};

    // Track releases, libraries, drivers, and symbols separately
    let mut library_records = Vec::new();
    let mut symbol_records = Vec::new();
    let mut release_data: HashMap<(String, String), (Option<String>, chrono::DateTime<chrono::Utc>, String, HashSet<String>, HashSet<String>)> = HashMap::new();
    let mut driver_stats: HashMap<String, (String, String, usize)> = HashMap::new();

    // Configure symbol filter - only extract symbols starting with "Adbc"
    let symbol_filter = symbols::SymbolFilter::default();

    for driver in &drivers {
        driver_stats.insert(
            driver.name.clone(),
            (driver.owner.clone(), driver.repo.clone(), 0)
        );
        println!("📦 Loading cached releases for {}", driver.name);

        match load_cached_releases(&cache_dir, &driver.name) {
            Ok(releases) => {
                println!("   Found {} releases in cache", releases.len());

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

                                // Extract symbols from the library if we have a path
                                if let Some(ref lib_path) = lib_info.path {
                                    match symbols::extract_symbols(lib_path, &symbol_filter) {
                                        Ok(syms) => {
                                            for (idx, symbol) in syms.into_iter().enumerate() {
                                                symbol_records.push(SymbolRecord {
                                                    name: driver.name.clone(),
                                                    release_tag: tag.clone(),
                                                    version: version.clone(),
                                                    os: os.clone(),
                                                    arch: arch.clone(),
                                                    library_name: lib_info.name.clone(),
                                                    symbol,
                                                    symbol_index: idx as i64,
                                                });
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("   ⚠️  Failed to extract symbols from {}: {}", lib_info.name, e);
                                        }
                                    }
                                }

                                // Track library count for driver
                                if let Some(stats) = driver_stats.get_mut(&driver.name) {
                                    stats.2 += 1;
                                }

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
                eprintln!("   ⚠️  Error loading cached releases: {}", e);
                eprintln!("   Continuing with other drivers...");
            }
        }

        println!();
    }

    println!("📊 Total library records: {}", library_records.len());
    println!("📊 Total symbol records: {}", symbol_records.len());
    println!("📊 Total releases: {}", release_data.len());
    println!("📊 Total drivers: {}", driver_stats.len());
    println!();

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

    // Write drivers.parquet
    let drivers_output = PathBuf::from("drivers.parquet");
    println!("💾 Writing to {:?}", drivers_output);
    let mut drivers_writer = parquet::DriversWriter::new(&drivers_output)?;
    for record in driver_records {
        drivers_writer.add_record(record)?;
    }
    drivers_writer.close()?;
    println!("   ✓ Written {} drivers", driver_stats.len());

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

    // Write symbols.parquet
    let symbols_output = PathBuf::from("symbols.parquet");
    println!("💾 Writing to {:?}", symbols_output);
    let mut symbols_writer = parquet::SymbolsWriter::new(&symbols_output)?;
    for record in symbol_records {
        symbols_writer.add_record(record)?;
    }
    symbols_writer.close()?;

    println!();
    println!("✨ Done!");
    println!();
    println!("Output files:");
    println!("  - {:?}", drivers_output);
    println!("  - {:?}", releases_output);
    println!("  - {:?}", libraries_output);
    println!("  - {:?}", symbols_output);

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

    println!("🌐 adbc-index html - Generating HTML dashboard");
    println!();

    let drivers_path = PathBuf::from("drivers.parquet");
    let releases_path = PathBuf::from("releases.parquet");
    let libraries_path = PathBuf::from("libraries.parquet");
    let symbols_path = PathBuf::from("symbols.parquet");
    let output_dir = PathBuf::from("dist");
    let output_file = output_dir.join("index.html");

    // Check if parquet files exist
    if !drivers_path.exists() {
        return Err(error::AdbcIndexError::Config(
            "drivers.parquet not found. Run 'adbc-index report' first.".to_string(),
        ));
    }
    if !releases_path.exists() {
        return Err(error::AdbcIndexError::Config(
            "releases.parquet not found. Run 'adbc-index report' first.".to_string(),
        ));
    }
    if !libraries_path.exists() {
        return Err(error::AdbcIndexError::Config(
            "libraries.parquet not found. Run 'adbc-index report' first.".to_string(),
        ));
    }
    if !symbols_path.exists() {
        return Err(error::AdbcIndexError::Config(
            "symbols.parquet not found. Run 'adbc-index report' first.".to_string(),
        ));
    }

    // Create output directory
    std::fs::create_dir_all(&output_dir)?;

    println!("📖 Reading parquet files with DuckDB...");

    // Use DuckDB to convert parquet to CSV
    let drivers_csv_output = Command::new("duckdb")
        .arg("-csv")
        .arg("-c")
        .arg("SELECT * FROM read_parquet('drivers.parquet')")
        .output()?;

    let releases_csv_output = Command::new("duckdb")
        .arg("-csv")
        .arg("-c")
        .arg("SELECT * FROM read_parquet('releases.parquet')")
        .output()?;

    let libraries_csv_output = Command::new("duckdb")
        .arg("-csv")
        .arg("-c")
        .arg("SELECT * FROM read_parquet('libraries.parquet')")
        .output()?;

    let symbols_csv_output = Command::new("duckdb")
        .arg("-csv")
        .arg("-c")
        .arg("SELECT * FROM read_parquet('symbols.parquet')")
        .output()?;

    if !drivers_csv_output.status.success() {
        return Err(error::AdbcIndexError::Config(
            format!("DuckDB error reading drivers: {}", String::from_utf8_lossy(&drivers_csv_output.stderr))
        ));
    }

    if !releases_csv_output.status.success() {
        return Err(error::AdbcIndexError::Config(
            format!("DuckDB error reading releases: {}", String::from_utf8_lossy(&releases_csv_output.stderr))
        ));
    }

    if !libraries_csv_output.status.success() {
        return Err(error::AdbcIndexError::Config(
            format!("DuckDB error reading libraries: {}", String::from_utf8_lossy(&libraries_csv_output.stderr))
        ));
    }

    if !symbols_csv_output.status.success() {
        return Err(error::AdbcIndexError::Config(
            format!("DuckDB error reading symbols: {}", String::from_utf8_lossy(&symbols_csv_output.stderr))
        ));
    }

    let drivers_csv = String::from_utf8_lossy(&drivers_csv_output.stdout);
    let releases_csv = String::from_utf8_lossy(&releases_csv_output.stdout);
    let libraries_csv = String::from_utf8_lossy(&libraries_csv_output.stdout);
    let symbols_csv = String::from_utf8_lossy(&symbols_csv_output.stdout);

    println!("🔨 Generating HTML...");

    // Generate HTML
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n");
    html.push_str("<html>\n");
    html.push_str("<head>\n");
    html.push_str("<title>ADBC Driver Dashboard</title>\n");
    html.push_str("</head>\n");
    html.push_str("<body>\n");
    html.push_str("<h1>ADBC Driver Dashboard</h1>\n\n");

    // Drivers table
    html.push_str("<h2>Drivers</h2>\n");
    html.push_str(&csv_to_html_table(&drivers_csv));
    html.push_str("\n");

    // Releases table
    html.push_str("<h2>Releases</h2>\n");
    html.push_str(&csv_to_html_table(&releases_csv));
    html.push_str("\n");

    // Libraries table
    html.push_str("<h2>Libraries</h2>\n");
    html.push_str(&csv_to_html_table(&libraries_csv));
    html.push_str("\n");

    // Symbols table
    html.push_str("<h2>Symbols</h2>\n");
    html.push_str(&csv_to_html_table(&symbols_csv));
    html.push_str("\n");

    html.push_str("</body>\n");
    html.push_str("</html>\n");

    // Write HTML file
    std::fs::write(&output_file, html)?;

    println!("✨ Done!");
    println!();
    println!("Output file: {:?}", output_file);

    Ok(())
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

