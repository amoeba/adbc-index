# Language Assignment Validation

## Summary

All 14 ADBC drivers have been validated for correct language assignment using multiple sources:

1. ✅ Binary string analysis (automatic detection)
2. ✅ GitHub repository analysis
3. ✅ Known implementation details from ADBC project documentation

## Validation Results

| Driver     | Assigned | GitHub Repo Top Lang | Binary Detection | Status |
|------------|----------|---------------------|------------------|---------|
| bigquery   | Go       | C# (apache/arrow-adbc*) | Go | ✅ Correct |
| clickhouse | Rust     | Python (adbc-drivers/clickhouse*) | Rust | ✅ Correct |
| databricks | Go       | C# (apache/arrow-adbc*) | Go | ✅ Correct |
| duckdb     | C++      | C++ (duckdb/duckdb) | C++ | ✅ Correct |
| flightsql  | Go       | C# (apache/arrow-adbc*) | Go | ✅ Correct |
| mssql      | Go       | C# (apache/arrow-adbc*) | Go | ✅ Correct |
| mysql      | Go       | C# (apache/arrow-adbc*) | Go | ✅ Correct |
| oracle     | Go       | C# (apache/arrow-adbc*) | Go | ✅ Correct |
| postgresql | C        | C# (apache/arrow-adbc*) | C  | ✅ Correct |
| redshift   | Go       | C# (apache/arrow-adbc*) | Go | ✅ Correct |
| snowflake  | Go       | C# (apache/arrow-adbc*) | Go | ✅ Correct |
| sqlite     | C        | C# (apache/arrow-adbc*) | C  | ✅ Correct |
| teradata   | Rust     | N/A (adbc-drivers/teradata) | Rust | ✅ Correct |
| trino      | Go       | C# (apache/arrow-adbc*) | Go | ✅ Correct |

\* Note: Many drivers live in the apache/arrow-adbc monorepo which contains implementations in multiple languages (C#, C++, Go, Java, Rust). The GitHub API reports C# as the top language for the entire repo, but individual drivers within it are implemented in different languages.

## Distribution

- **Go**: 9 drivers (64%)
- **Rust**: 2 drivers (14%)
- **C**: 2 drivers (14%)
- **C++**: 1 driver (7%)

## Why GitHub API Alone Is Insufficient

### Apache Arrow ADBC Monorepo

The `apache/arrow-adbc` repository contains multiple driver implementations:
- **C drivers**: postgresql, sqlite (uses libpq and SQLite C libraries)
- **Go drivers**: bigquery, databricks, flightsql, mssql, mysql, oracle, redshift, snowflake, trino
- **C# bindings**: AdoNet provider
- **C++ driver manager**: Core ADBC functionality
- **Java bindings**: JDBC compatibility layer
- **Rust experimental drivers**: Some experimental implementations

GitHub's language API shows:
```
C#: 4,158,738 bytes (largest due to AdoNet implementation)
C++: 1,955,423 bytes (driver manager)
Go: 1,069,672 bytes (multiple Go drivers)
Java: 527,444 bytes (JDBC layer)
Rust: 488,529 bytes (experimental drivers)
```

### Driver-Specific Repos

**clickhouse** (`adbc-drivers/clickhouse`):
- GitHub shows: Python (16,985 bytes), Shell (3,427 bytes)
- These are CI/build scripts and wrappers
- Actual driver implementation: Rust (verified via binary analysis)
- Driver binaries contain Rust runtime strings and panic handlers

**teradata** (`adbc-drivers/teradata`):
- GitHub repo: Not publicly accessible
- Binary analysis: Clearly shows Rust implementation
- Contains `/rustc/` build paths and Rust stdlib symbols

## Validation Method

The most reliable validation method for ADBC drivers is **binary string analysis**:

1. Extract printable strings from compiled shared libraries (.so, .dylib, .dll)
2. Analyze for language-specific patterns:
   - **Go**: `go.`, `runtime.`, goroutine error messages
   - **Rust**: `/rustc/`, `panicked at`, Rust stdlib references
   - **C++**: `std::`, vtable/RTTI symbols, C++ exception handling
   - **C**: Standard library function names, simple unmangled symbols

This method:
- Works on stripped production binaries
- Reflects the actual compiled implementation
- Is independent of repository structure
- Doesn't depend on GitHub API or repository access

## Conclusion

All 14 language assignments in `drivers.toml` have been verified as correct:
- ✅ Matches binary analysis (100% accuracy)
- ✅ Matches known ADBC implementation details
- ✅ Validated against production library artifacts

The hybrid approach (explicit config + binary detection fallback) ensures accuracy while maintaining flexibility for edge cases where GitHub's language API may be misleading due to monorepo structures or non-public repositories.
