use adbc_index::stub_detector::{analyze_stubs, AdbcStatusCode};
use adbc_index::symbols::{extract_symbols, extract_symbols_and_stubs, SymbolFilter};

/// Expected symbols present in all test binaries
const COMMON_SYMBOLS: &[&str] = &[
    "AdbcConnectionInit",
    "AdbcConnectionNew",
    "AdbcConnectionRelease",
    "AdbcConnectionSetOption",
    "AdbcDatabaseInit",
    "AdbcDatabaseNew",
    "AdbcDatabaseRelease",
    "AdbcDatabaseSetOption",
    "AdbcDriverInit",
    "AdbcDriverRelease",
    "AdbcStatementExecuteQuery",
    "AdbcStatementNew",
    "AdbcStatementRelease",
    "AdbcStatementSetSqlQuery",
];

/// Expected stub functions (return ADBC_STATUS_NOT_IMPLEMENTED) on macOS
const MACOS_EXPECTED_STUBS: &[&str] = &[
    "AdbcConnectionSetOption",
    "AdbcDatabaseRelease",
    "AdbcDatabaseSetOption",
    "AdbcDriverRelease",
    "AdbcStatementExecuteQuery",
    "AdbcStatementRelease",
    "AdbcStatementSetSqlQuery",
];

/// Expected non-stub functions (return ADBC_STATUS_OK) on macOS
const MACOS_EXPECTED_NON_STUBS: &[&str] = &[
    "AdbcConnectionInit",
    "AdbcDatabaseInit",
    "AdbcDatabaseNew",
    "AdbcStatementNew",
];

fn test_binary_paths() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "Linux",
            "test_artifacts/tiniest-adbc-driver/tiny-driver-ubuntu-latest/libtiny.so",
        ),
        (
            "macOS",
            "test_artifacts/tiniest-adbc-driver/tiny-driver-macos-latest/libtiny.dylib",
        ),
        (
            "Windows",
            "test_artifacts/tiniest-adbc-driver/tiny-driver-windows-latest/tiny.dll",
        ),
    ]
}

#[test]
fn test_extract_symbols_all_platforms() {
    let filter = SymbolFilter::default(); // Only "Adbc" prefix

    for (platform, path) in test_binary_paths() {
        let symbols = extract_symbols(path, &filter)
            .unwrap_or_else(|e| panic!("{} binary extraction failed: {}", platform, e));

        // All platforms should now export 14 symbols
        let expected_count = 14;

        assert_eq!(
            symbols.len(),
            expected_count,
            "{}: Expected {} symbols, got {}",
            platform,
            expected_count,
            symbols.len()
        );

        // Verify all common symbols are present
        for &expected in COMMON_SYMBOLS {
            assert!(
                symbols.contains(&expected.to_string()),
                "{}: Missing common symbol: {}",
                platform,
                expected
            );
        }

        // Verify symbols are sorted
        let mut sorted = symbols.clone();
        sorted.sort();
        assert_eq!(symbols, sorted, "{}: Symbols should be sorted", platform);
    }
}

#[test]
fn test_stub_detection_macos() {
    // Note: Stub detection currently only works reliably on macOS ARM64
    let path = "test_artifacts/tiniest-adbc-driver/tiny-driver-macos-latest/libtiny.dylib";

    let analyses = analyze_stubs(path).expect("macOS stub analysis failed");

    // Should analyze exactly 14 functions
    assert_eq!(
        analyses.len(),
        14,
        "Expected 14 analyses, got {}",
        analyses.len()
    );

    // Count stubs
    let stubs: Vec<_> = analyses.iter().filter(|a| a.is_stub).collect();
    assert_eq!(stubs.len(), 7, "Expected 7 stubs, got {}", stubs.len());

    // Verify expected stub functions
    for &expected_stub in MACOS_EXPECTED_STUBS {
        let analysis = analyses.iter().find(|a| a.symbol_name == expected_stub);
        assert!(
            analysis.is_some(),
            "Missing analysis for stub: {}",
            expected_stub
        );

        let analysis = analysis.unwrap();
        assert!(
            analysis.is_stub,
            "{} should be detected as stub",
            expected_stub
        );
        assert_eq!(
            analysis.constant_return,
            Some(2),
            "{} should return 2",
            expected_stub
        );
        assert_eq!(
            analysis.status_code,
            Some(AdbcStatusCode::NotImplemented),
            "{} should have NotImplemented status",
            expected_stub
        );
    }

    // Verify expected non-stub functions that have constant returns
    for &expected_non_stub in MACOS_EXPECTED_NON_STUBS {
        let analysis = analyses.iter().find(|a| a.symbol_name == expected_non_stub);
        assert!(
            analysis.is_some(),
            "Missing analysis for non-stub: {}",
            expected_non_stub
        );

        let analysis = analysis.unwrap();
        assert!(
            !analysis.is_stub,
            "{} should not be detected as stub",
            expected_non_stub
        );
        assert_eq!(
            analysis.constant_return,
            Some(0),
            "{} should return 0",
            expected_non_stub
        );
        assert_eq!(
            analysis.status_code,
            Some(AdbcStatusCode::Ok),
            "{} should have Ok status",
            expected_non_stub
        );
    }
}

#[test]
fn test_stub_detection_all_platforms() {
    // Test that stub analysis runs without errors on all platforms
    for (platform, path) in test_binary_paths() {
        let analyses = analyze_stubs(path)
            .unwrap_or_else(|e| panic!("{} stub analysis failed: {}", platform, e));

        // All platforms should now have 14 analyses
        let expected_count = 14;

        assert_eq!(
            analyses.len(),
            expected_count,
            "{}: Expected {} analyses, got {}",
            platform,
            expected_count,
            analyses.len()
        );

        // All analyses should have valid symbol names
        for analysis in &analyses {
            assert!(
                analysis.symbol_name.starts_with("Adbc"),
                "{}: Invalid symbol name: {}",
                platform,
                analysis.symbol_name
            );
        }
    }
}

#[test]
fn test_combined_extraction_all_platforms() {
    let filter = SymbolFilter::default();

    for (platform, path) in test_binary_paths() {
        let (symbols, analyses) = extract_symbols_and_stubs(path, &filter)
            .unwrap_or_else(|e| panic!("{} combined extraction failed: {}", platform, e));

        // All platforms should now have 14 symbols and analyses
        let expected_count = 14;

        assert_eq!(
            symbols.len(),
            expected_count,
            "{}: Expected {} symbols, got {}",
            platform,
            expected_count,
            symbols.len()
        );
        assert_eq!(
            analyses.len(),
            expected_count,
            "{}: Expected {} analyses, got {}",
            platform,
            expected_count,
            analyses.len()
        );

        // All symbols should have corresponding analyses
        for symbol in &symbols {
            assert!(
                analyses.iter().any(|a| &a.symbol_name == symbol),
                "{}: Symbol {} has no analysis",
                platform,
                symbol
            );
        }
    }
}

#[test]
fn test_symbol_filtering_disabled() {
    // With empty filter, should extract all exported symbols
    let filter = SymbolFilter::new(vec![]);

    for (platform, path) in test_binary_paths() {
        let symbols = extract_symbols(path, &filter)
            .unwrap_or_else(|e| panic!("{} extraction failed: {}", platform, e));

        // Expected counts vary by platform
        let min_expected = match platform {
            "Linux" => 17,   // Includes __cxa_finalize, free, malloc
            "macOS" => 14,   // Only ADBC functions exported
            "Windows" => 14, // Only ADBC functions exported (fixed)
            _ => 14,
        };

        assert!(
            symbols.len() >= min_expected,
            "{}: With disabled filter, expected >= {} symbols, got {}",
            platform,
            min_expected,
            symbols.len()
        );

        // Should still include all common ADBC symbols
        for &expected in COMMON_SYMBOLS {
            assert!(
                symbols.contains(&expected.to_string()),
                "{}: Missing ADBC symbol: {}",
                platform,
                expected
            );
        }
    }
}

#[test]
fn test_symbol_filtering_custom_prefix() {
    // Filter to only "AdbcDatabase" functions (should get 4)
    let filter = SymbolFilter::new(vec!["AdbcDatabase".to_string()]);

    for (platform, path) in test_binary_paths() {
        let symbols = extract_symbols(path, &filter)
            .unwrap_or_else(|e| panic!("{} extraction failed: {}", platform, e));

        // Should extract exactly 4 AdbcDatabase* functions
        assert_eq!(
            symbols.len(),
            4,
            "{}: Expected 4 AdbcDatabase symbols, got {}",
            platform,
            symbols.len()
        );

        // Verify all extracted symbols start with "AdbcDatabase"
        for symbol in &symbols {
            assert!(
                symbol.starts_with("AdbcDatabase"),
                "{}: Symbol {} should start with AdbcDatabase",
                platform,
                symbol
            );
        }

        // Should include these specific functions
        let expected_database = [
            "AdbcDatabaseInit",
            "AdbcDatabaseNew",
            "AdbcDatabaseRelease",
            "AdbcDatabaseSetOption",
        ];
        for &expected in &expected_database {
            assert!(
                symbols.contains(&expected.to_string()),
                "{}: Missing {}",
                platform,
                expected
            );
        }
    }
}

#[test]
fn test_extract_symbols_missing_file() {
    let filter = SymbolFilter::default();
    let result = extract_symbols("nonexistent/path/file.so", &filter);

    assert!(result.is_err(), "Should return error for missing file");
}

#[test]
fn test_extract_symbols_invalid_binary() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let filter = SymbolFilter::default();

    // Create a temporary file with invalid binary data
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    temp_file
        .write_all(b"This is not a valid binary file")
        .expect("Failed to write to temp file");

    let result = extract_symbols(temp_file.path(), &filter);

    assert!(result.is_err(), "Should return error for invalid binary");
}

#[test]
fn test_macos_symbol_underscore_stripping() {
    // Verify macOS symbols have leading underscore removed
    let filter = SymbolFilter::default();
    let path = "test_artifacts/tiniest-adbc-driver/tiny-driver-macos-latest/libtiny.dylib";

    let symbols = extract_symbols(path, &filter).expect("macOS symbol extraction failed");

    // None of the symbols should start with underscore
    for symbol in &symbols {
        assert!(
            !symbol.starts_with('_'),
            "macOS symbol should not start with underscore: {}",
            symbol
        );

        // All should start with "Adbc" (after underscore removal)
        assert!(
            symbol.starts_with("Adbc"),
            "Symbol should start with Adbc: {}",
            symbol
        );
    }
}

#[test]
fn test_macos_functions_have_valid_status_codes() {
    // Verify macOS functions that have constant returns have valid ADBC status codes
    let path = "test_artifacts/tiniest-adbc-driver/tiny-driver-macos-latest/libtiny.dylib";

    let analyses = analyze_stubs(path).expect("macOS stub analysis failed");

    for analysis in &analyses {
        if let Some(constant) = analysis.constant_return {
            // If we detected a constant return, it should map to a valid status code
            let expected_code = AdbcStatusCode::from_i32(constant);
            assert_eq!(
                analysis.status_code, expected_code,
                "Function {} constant {} should map to status code {:?}",
                analysis.symbol_name, constant, expected_code
            );
        }
    }
}
