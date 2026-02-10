# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust CLI tool that indexes ADBC (Arrow Database Connectivity) drivers. It downloads driver releases from GitHub and PyPI, analyzes shared libraries to extract exported symbols, detects stub implementations, and generates Parquet files and HTML dashboards for visualization.

## Common Commands

### Build and Test
```bash
# Build the project
cargo build --release

# Run tests
cargo test

# Run a specific test
cargo test test_name

# Run integration tests
cargo test --test symbol_stub_integration_test
```

### Running the Tool
```bash
# Set required environment variable
export GITHUB_TOKEN=your_token_here

# Download all driver releases
cargo run --release -- download

# Download specific driver
cargo run --release -- download mysql

# Full build: download + analyze + generate HTML
cargo run --release -- build
```

### External Dependencies
- **DuckDB CLI**: Required for HTML generation (`adbc-index build` command). Install with `brew install duckdb` on macOS.
- **GITHUB_TOKEN**: Required environment variable for GitHub API access.

## Architecture

### Core Data Flow
1. **Config Loading** (`src/config.rs`): Loads `drivers.toml` which defines driver sources (GitHub repos or PyPI packages), version requirements, and artifact filters.

2. **Release Fetching** (`src/github/`, `src/pypi/`): Queries GitHub/PyPI APIs to get release information and asset URLs.

3. **Download** (`src/download/`): Concurrent download of artifacts (tar.gz, zip, whl files) to `cache/` directory with SHA256 verification.

4. **Artifact Parsing** (`src/artifact_parser.rs`): Extracts metadata (OS, architecture, version) from artifact filenames using multiple parsing strategies (wheel format, underscore-separated, dash-separated, etc.).

5. **Library Extraction** (`src/main.rs:extract_and_find_library`): Extracts archives and locates shared libraries (.so, .dylib, .dll) inside them.

6. **Symbol Analysis** (`src/symbols.rs`): Uses `goblin` to parse binary formats (ELF/PE/Mach-O) and extract exported symbols. Filters symbols by prefix (default: "Adbc").

7. **Stub Detection** (`src/stub_detector.rs`): Uses `capstone` for disassembly to detect stub implementations that return constant values (especially ADBC_STATUS_NOT_IMPLEMENTED).

8. **Parquet Generation** (`src/parquet/`): Writes structured data to Parquet files:
   - `dist/drivers.parquet`: Driver-level summary
   - `dist/releases.parquet`: Release information per driver
   - `dist/libraries.parquet`: Library metadata per release/platform
   - `dist/symbols.parquet`: Exported symbols with stub detection results

9. **HTML Dashboard** (`src/main.rs:html`): Uses DuckDB to query Parquet files and generates an HTML dashboard with SVG charts.

### Key Modules

- **`models.rs`**: Core data structures (DriverConfig, ReleaseRecord, LibraryRecord, SymbolRecord)
- **`stub_detector.rs`**: Binary analysis to detect stub functions, includes AdbcStatusCode enum matching ADBC spec
- **`symbols.rs`**: Symbol extraction with SymbolFilter for prefix-based filtering
- **`artifact_parser.rs`**: Multi-strategy filename parsing to extract platform metadata
- **`parquet/`**: Schema definitions and writers for each output file type

### Important Patterns

1. **Symbol Filtering**: By default, only symbols starting with "Adbc" are extracted. This is configurable via `SymbolFilter` but hardcoded to default in main.rs:518.

2. **Version Filtering**: The `drivers.toml` supports semver version requirements (e.g., ">=0.8.0") to filter which releases are processed.

3. **Artifact Filtering**: Supports glob patterns in `drivers.toml` to filter which artifacts are downloaded (e.g., "libduckdb-*" for DuckDB).

4. **Concurrent Processing**: Uses tokio for async I/O and parallel processing of drivers (spawn_blocking for CPU-bound work in src/main.rs:521-534).

5. **Cache Management**: Downloaded artifacts are cached in `cache/{driver}/{tag}/` with SHA256 sidecar files for verification.

## Configuration

### drivers.toml Format
```toml
[drivers]
# Simple GitHub source
mysql = "https://github.com/adbc-drivers/mysql"

# PyPI source
bigquery = "https://pypi.org/project/adbc-driver-bigquery/"

# Advanced configuration with version filter and artifact filter
[drivers.duckdb]
url = "https://github.com/duckdb/duckdb"
version = ">=0.8.0"
artifact_filter = "libduckdb-*"
```

## Testing

Tests use the `test_artifacts/` directory for fixtures. Integration tests analyze real shared libraries to verify symbol extraction and stub detection work correctly across platforms (ELF/PE/Mach-O).

Key test files:
- `tests/test_config_load.rs`: Configuration parsing
- `tests/symbol_stub_integration_test.rs`: End-to-end symbol extraction and stub detection
- `tests/test_stub_detection_comprehensive.rs`: Detailed stub detection scenarios

## Output Files

The tool generates files in the `dist/` directory:
- `drivers.parquet`, `releases.parquet`, `libraries.parquet`, `symbols.parquet`: Structured data
- `index.html`: Dashboard with tables and SVG visualizations
- Deployable to Cloudflare Workers via `wrangler.toml`
