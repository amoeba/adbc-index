use adbc_index::config;
use std::path::PathBuf;

#[test]
fn test_load_drivers_toml() {
    let config_path = PathBuf::from("drivers.toml");
    let drivers = config::load_config(&config_path).expect("Failed to load config");

    println!("\nLoaded {} drivers:", drivers.len());
    for driver in &drivers {
        println!("  - {}: {:?}", driver.name, driver.source);
        if let Some(ref version_req) = driver.version_req {
            println!("    Version requirement: {}", version_req);
        }
    }

    // Find duckdb driver and verify it has version requirement
    let duckdb = drivers.iter().find(|d| d.name == "duckdb");
    assert!(duckdb.is_some(), "DuckDB driver not found");

    let duckdb = duckdb.unwrap();
    assert!(
        duckdb.version_req.is_some(),
        "DuckDB should have version requirement"
    );
    assert!(
        duckdb.artifact_filter.is_some(),
        "DuckDB should have artifact filter"
    );

    let version_req = duckdb.version_req.as_ref().unwrap();
    println!("\nDuckDB version requirement: {}", version_req);

    // Test that it matches expected versions
    assert!(
        version_req.matches(&semver::Version::parse("0.8.0").unwrap()),
        "Should match 0.8.0"
    );
    assert!(
        version_req.matches(&semver::Version::parse("1.4.0").unwrap()),
        "Should match 1.4.0"
    );
    assert!(
        !version_req.matches(&semver::Version::parse("0.7.1").unwrap()),
        "Should not match 0.7.1"
    );

    println!("✓ DuckDB version filtering configured correctly!");

    // Test artifact filter
    let artifact_filter = duckdb.artifact_filter.as_ref().unwrap();
    println!("DuckDB artifact filter: {}", artifact_filter);

    assert!(
        duckdb.matches_artifact("libduckdb-osx-universal.zip"),
        "Should match libduckdb"
    );
    assert!(
        duckdb.matches_artifact("libduckdb-linux-amd64.zip"),
        "Should match libduckdb"
    );
    assert!(
        !duckdb.matches_artifact("duckdb_cli-osx-universal.zip"),
        "Should not match CLI"
    );
    assert!(
        !duckdb.matches_artifact("duckdb_jdbc.jar"),
        "Should not match JDBC"
    );

    println!("✓ DuckDB artifact filtering configured correctly!");
}
