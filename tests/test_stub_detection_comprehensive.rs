use adbc_index::stub_detector::{analyze_stubs, AdbcStatusCode};

#[test]
fn test_stub_detection_comprehensive() {
    let binaries = vec![
        ("Linux ELF", "test_artifacts/tiniest-adbc-driver/tiny-driver-ubuntu-latest/libtiny.so"),
        ("Windows PE", "test_artifacts/tiniest-adbc-driver/tiny-driver-windows-latest/tiny.dll"),
        ("macOS Mach-O", "test_artifacts/tiniest-adbc-driver/tiny-driver-macos-latest/libtiny.dylib"),
    ];

    // Expected stubs (return ADBC_STATUS_NOT_IMPLEMENTED = 2)
    let expected_stubs = vec![
        "AdbcConnectionSetOption",
        "AdbcDatabaseRelease",
        "AdbcDatabaseSetOption",
        "AdbcDriverRelease",
        "AdbcStatementExecuteQuery",
        "AdbcStatementRelease",
        "AdbcStatementSetSqlQuery",
    ];

    // Expected non-stubs that return OK (= 0)
    let expected_non_stubs = vec![
        "AdbcConnectionInit",
        "AdbcDatabaseInit",
        "AdbcDatabaseNew",
        "AdbcStatementNew",
    ];

    for (name, path) in binaries {
        println!("\n=== {} ===", name);
        println!("Path: {}\n", path);

        let analyses = analyze_stubs(path)
            .unwrap_or_else(|e| panic!("{} stub analysis failed: {}", name, e));

        println!("Found {} analyses", analyses.len());

        // Count stubs and non-stubs
        let mut detected_stubs = Vec::new();
        let mut detected_non_stubs = Vec::new();

        for analysis in &analyses {
            println!("  {} - is_stub: {}, constant_return: {:?}, status: {:?}",
                     analysis.symbol_name,
                     analysis.is_stub,
                     analysis.constant_return,
                     analysis.status_code.map(|s| s.name()));

            if analysis.is_stub {
                detected_stubs.push(analysis.symbol_name.clone());
            } else if analysis.constant_return == Some(0) && analysis.status_code == Some(AdbcStatusCode::Ok) {
                detected_non_stubs.push(analysis.symbol_name.clone());
            }
        }

        println!("\nStubs (returning NOT_IMPLEMENTED): {}", detected_stubs.len());
        for stub in &detected_stubs {
            println!("  - {}", stub);
        }

        println!("\nNon-stubs (returning OK): {}", detected_non_stubs.len());
        for non_stub in &detected_non_stubs {
            println!("  - {}", non_stub);
        }

        // Verify all expected stubs were detected
        for expected_stub in &expected_stubs {
            assert!(
                detected_stubs.contains(&expected_stub.to_string()),
                "{}: Expected stub '{}' was not detected as a stub",
                name,
                expected_stub
            );
        }

        // Verify all expected non-stubs were detected
        for expected_non_stub in &expected_non_stubs {
            assert!(
                detected_non_stubs.contains(&expected_non_stub.to_string()),
                "{}: Expected non-stub '{}' was not detected correctly",
                name,
                expected_non_stub
            );
        }

        println!("\n{}: ✓ All stub detection working correctly!", name);
    }
}
