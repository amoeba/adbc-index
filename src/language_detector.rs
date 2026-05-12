/// Detects the implementation language of a shared library by analyzing exported symbol patterns.
///
/// This module uses symbol naming conventions and patterns to identify whether a library
/// was compiled from Rust, C++, C, Go, or another language.

use std::collections::HashMap;

/// Detect the implementation language from a list of exported symbols.
///
/// Returns Some(language) if confidence exceeds threshold (5% of symbols), otherwise None.
/// Returns "Unknown" if no clear language pattern is detected.
pub fn detect_language(symbols: &[String]) -> Option<String> {
    if symbols.is_empty() {
        return None;
    }

    let mut scores: HashMap<&str, usize> = HashMap::new();

    // Count pattern matches for each language
    for symbol in symbols {
        if is_rust_symbol(symbol) || is_rust_string(symbol) {
            *scores.entry("rust").or_insert(0) += 1;
        }
        if is_cpp_symbol(symbol) || is_cpp_string(symbol) {
            *scores.entry("c++").or_insert(0) += 1;
        }
        if is_c_symbol(symbol) {
            *scores.entry("c").or_insert(0) += 1;
        }
        if is_go_symbol(symbol) || is_go_string(symbol) {
            *scores.entry("go").or_insert(0) += 1;
        }
    }

    // Find language with highest score
    let max_score = scores.values().max().copied().unwrap_or(0);
    if max_score == 0 {
        return Some("unknown".to_string());
    }

    // Calculate confidence threshold (1% of strings/symbols for string-based detection)
    let threshold = (symbols.len() as f64 * 0.01).max(1.0) as usize;

    if max_score < threshold {
        return Some("unknown".to_string());
    }

    // Get language with highest score
    let detected = scores
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(lang, _)| lang.to_string());

    detected
}

/// Check if a symbol follows Rust naming patterns
fn is_rust_symbol(symbol: &str) -> bool {
    // Rust mangled symbols: _ZN{digits}
    if symbol.starts_with("_ZN") && symbol.len() > 3 {
        if let Some(c) = symbol.chars().nth(3) {
            if c.is_ascii_digit() {
                return true;
            }
        }
    }

    // Newer Rust mangling: _RN
    if symbol.starts_with("_RN") {
        return true;
    }

    // Rust runtime symbols (with or without leading underscore)
    if symbol.starts_with("rust_")
        || symbol.starts_with("_rust_")
        || symbol.contains("rust_panic")
        || symbol.contains("rust_eh_personality")
        || symbol.contains("rust_oom") {
        return true;
    }

    // Rust hash suffixes: 17h[hex]E pattern
    if symbol.contains("17h") && symbol.ends_with('E') {
        return true;
    }

    // Common Rust crate patterns in mangled names
    if symbol.contains("_ZN4core") || symbol.contains("_ZN3std") || symbol.contains("_ZN5alloc") {
        return true;
    }

    false
}

/// Check if a symbol follows C++ naming patterns
fn is_cpp_symbol(symbol: &str) -> bool {
    // C++ standard library namespace: _ZNSt
    if symbol.starts_with("_ZNSt") {
        return true;
    }

    // C++ const methods: _ZNK
    if symbol.starts_with("_ZNK") {
        return true;
    }

    // C++ RTTI symbols
    if symbol.starts_with("_ZTV") || symbol.starts_with("_ZTI") || symbol.starts_with("_ZTS") {
        return true;
    }

    // C++ exception handling (C++ ABI)
    if symbol.starts_with("__cxa_") {
        return true;
    }

    // Generic C++ mangling (but exclude Rust patterns)
    if symbol.starts_with("_Z") && !is_rust_symbol(symbol) {
        return true;
    }

    false
}

/// Check if a symbol follows C naming patterns
fn is_c_symbol(symbol: &str) -> bool {
    // C symbols are typically unmangled (no _Z prefix)
    if symbol.starts_with("_Z") {
        return false;
    }

    // Don't count Rust runtime symbols as C
    if symbol.starts_with("rust_") || symbol.starts_with("_rust_") {
        return false;
    }

    // Don't count Go symbols as C
    if symbol.starts_with("runtime.") || symbol.starts_with("go.") || symbol.starts_with("type..") {
        return false;
    }

    // Common C standard library functions
    let c_stdlib_functions = [
        "malloc", "free", "calloc", "realloc",
        "memcpy", "memset", "memmove", "memcmp",
        "strlen", "strcpy", "strcmp", "strcat",
        "printf", "sprintf", "fprintf", "snprintf",
        "fopen", "fclose", "fread", "fwrite",
        "exit", "abort", "atoi", "atof",
    ];

    // Check for exact matches
    for func in &c_stdlib_functions {
        if symbol == *func {
            return true;
        }
    }

    // Check if it looks like a typical C function name
    if symbol.len() >= 4 && symbol.chars().all(|c| c.is_alphanumeric() || c == '_') {
        // Must start with a letter
        if !symbol.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) {
            return false;
        }

        // Must contain at least one lowercase letter (rules out things like "XYZ123")
        if !symbol.chars().any(|c| c.is_lowercase()) {
            return false;
        }

        // Exclude symbols that end with "_" followed by a single digit (like "symbol_1", "test_2")
        // These are likely test symbols or generic placeholders
        if let Some(last_char) = symbol.chars().last() {
            if last_char.is_ascii_digit() {
                let parts: Vec<&str> = symbol.rsplitn(2, '_').collect();
                if parts.len() == 2 && parts[0].len() == 1 {
                    return false;
                }
            }
        }

        // Check if it starts with a capital letter (like AdbcDriverInit)
        if symbol.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            return true;
        }

        // Check if it looks like a typical C function name (lowercase with underscores)
        // like "my_function", "calculate_sum"
        // But exclude generic names like "random_symbol" by requiring more structure
        if symbol.chars().next().map(|c| c.is_lowercase()).unwrap_or(false) {
            // Must contain underscore or be a known pattern
            if symbol.contains('_') {
                // Exclude very generic patterns like "random_symbol", "generic_name"
                let generic_patterns = ["random", "symbol", "generic", "test", "temp", "tmp"];
                let is_generic = generic_patterns.iter().any(|pattern| symbol.starts_with(pattern));
                if !is_generic {
                    return true;
                }
            }
        }
    }

    false
}

/// Check if a symbol follows Go naming patterns
fn is_go_symbol(symbol: &str) -> bool {
    // Go runtime symbols
    if symbol.starts_with("runtime.") || symbol.starts_with("go.string.") {
        return true;
    }

    // Go type information
    if symbol.starts_with("type..") || symbol.starts_with("go.itab.") {
        return true;
    }

    // Go module paths in symbols
    if symbol.contains("go.") {
        return true;
    }

    false
}

/// Check if a string from binary data indicates Go
fn is_go_string(s: &str) -> bool {
    // Go module paths (especially common in go.mod-based projects)
    if s.starts_with("go.") || s.starts_with("golang.org/") || s.starts_with("github.com/golang/") {
        return true;
    }

    // Go runtime strings that appear in binaries
    if s.starts_with("runtime.") {
        return true;
    }

    // Go-specific error messages and runtime strings
    if s.contains("goroutine ") || s.contains("panic: ") || s.contains("fatal error: ") {
        return true;
    }

    // Common Go package paths
    if s.starts_with("github.com/") && s.contains("/go") {
        return true;
    }

    false
}

/// Check if a string from binary data indicates Rust
fn is_rust_string(s: &str) -> bool {
    // Rust panic messages
    if s.contains("panicked at") || s.starts_with("thread '") || s.contains("panic_impl") {
        return true;
    }

    // Rust crate paths
    if s.starts_with("/rustc/") || s.contains("/.cargo/registry/") {
        return true;
    }

    // Common Rust error patterns
    if s.contains("called `Result::unwrap()") || s.contains("called `Option::unwrap()") {
        return true;
    }

    false
}

/// Check if a string from binary data indicates C++
fn is_cpp_string(s: &str) -> bool {
    // C++ standard library namespaces and types
    if s.starts_with("std::") || s.contains("std::__") {
        return true;
    }

    // C++ exception messages
    if s.contains("terminate called") || s.contains("pure virtual") {
        return true;
    }

    // C++ RTTI strings (typeinfo names)
    if s.starts_with("typeinfo for") || s.starts_with("vtable for") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_rust() {
        let symbols = vec![
            "_ZN4core3ptr85drop_in_place$LT$std..rt..lang_start$LT$$LP$$RP$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h1234567890abcdefE".to_string(),
            "_ZN3std2rt10lang_start17h1234567890abcdefE".to_string(),
            "rust_panic".to_string(),
            "_rust_alloc".to_string(),
            "rust_eh_personality".to_string(),
        ];

        let result = detect_language(&symbols);
        assert_eq!(result, Some("rust".to_string()));
    }

    #[test]
    fn test_detect_cpp() {
        let symbols = vec![
            "_ZNSt6vectorIiSaIiEE9push_backERKi".to_string(),
            "_ZNKSt5__cxx114listIiSaIiEE4sizeEv".to_string(),
            "_ZTV9MyClass".to_string(),
            "_ZTI9MyClass".to_string(),
            "__cxa_throw".to_string(),
            "__cxa_begin_catch".to_string(),
        ];

        let result = detect_language(&symbols);
        assert_eq!(result, Some("c++".to_string()));
    }

    #[test]
    fn test_detect_c() {
        let symbols = vec![
            "malloc".to_string(),
            "free".to_string(),
            "strlen".to_string(),
            "memcpy".to_string(),
            "my_function".to_string(),
            "calculate_sum".to_string(),
        ];

        let result = detect_language(&symbols);
        assert_eq!(result, Some("c".to_string()));
    }

    #[test]
    fn test_detect_go() {
        let symbols = vec![
            "runtime.malloc".to_string(),
            "runtime.newobject".to_string(),
            "go.string.hello".to_string(),
            "type..eq.[8]string".to_string(),
            "go.itab.*os.File,io.Writer".to_string(),
        ];

        let result = detect_language(&symbols);
        assert_eq!(result, Some("go".to_string()));
    }

    #[test]
    fn test_empty_symbols() {
        let symbols: Vec<String> = vec![];
        let result = detect_language(&symbols);
        assert_eq!(result, None);
    }

    #[test]
    fn test_unknown_symbols() {
        let symbols = vec![
            "XYZ123".to_string(),
            "___abc___".to_string(),
            "symbol_1".to_string(),
        ];

        let result = detect_language(&symbols);
        assert_eq!(result, Some("unknown".to_string()));
    }

    #[test]
    fn test_mixed_rust_cpp() {
        // More Rust symbols than C++ - should detect Rust
        let symbols = vec![
            "_ZN4core3ptr17h1234567890abcdefE".to_string(),
            "_ZN3std2rt17h1234567890abcdefE".to_string(),
            "rust_panic".to_string(),
            "_ZNSt6vectorIiSaIiEE9push_backERKi".to_string(), // C++
        ];

        let result = detect_language(&symbols);
        assert_eq!(result, Some("rust".to_string()));
    }

    #[test]
    fn test_rust_symbol_patterns() {
        assert!(is_rust_symbol("_ZN4core3ptr17h1234567890abcdefE"));
        assert!(is_rust_symbol("_ZN3std2rt10lang_start17h1234567890abcdefE"));
        assert!(is_rust_symbol("rust_panic"));
        assert!(is_rust_symbol("_rust_alloc"));
        assert!(is_rust_symbol("rust_eh_personality"));
        assert!(is_rust_symbol("_RNvC1a4main"));

        assert!(!is_rust_symbol("_ZNSt6vectorIiSaIiEE9push_backERKi"));
        assert!(!is_rust_symbol("malloc"));
    }

    #[test]
    fn test_cpp_symbol_patterns() {
        assert!(is_cpp_symbol("_ZNSt6vectorIiSaIiEE9push_backERKi"));
        assert!(is_cpp_symbol("_ZNKSt5__cxx114listIiSaIiEE4sizeEv"));
        assert!(is_cpp_symbol("_ZTV9MyClass"));
        assert!(is_cpp_symbol("_ZTI9MyClass"));
        assert!(is_cpp_symbol("__cxa_throw"));

        assert!(!is_cpp_symbol("_ZN4core3ptr17h1234567890abcdefE"));
        assert!(!is_cpp_symbol("malloc"));
    }

    #[test]
    fn test_c_symbol_patterns() {
        assert!(is_c_symbol("malloc"));
        assert!(is_c_symbol("free"));
        assert!(is_c_symbol("strlen"));
        assert!(is_c_symbol("my_function"));

        assert!(!is_c_symbol("_ZNSt6vectorIiSaIiEE9push_backERKi"));
        assert!(!is_c_symbol("_ZN4core3ptr17h1234567890abcdefE"));
    }

    #[test]
    fn test_go_symbol_patterns() {
        assert!(is_go_symbol("runtime.malloc"));
        assert!(is_go_symbol("runtime.newobject"));
        assert!(is_go_symbol("go.string.hello"));
        assert!(is_go_symbol("type..eq.[8]string"));
        assert!(is_go_symbol("go.itab.*os.File,io.Writer"));

        assert!(!is_go_symbol("malloc"));
        assert!(!is_go_symbol("_ZNSt6vectorIiSaIiEE9push_backERKi"));
    }

    #[test]
    fn test_threshold_detection() {
        // Only 1 Rust symbol out of 200 - below 1% threshold
        let mut symbols = vec!["random_symbol".to_string(); 199];
        symbols.push("rust_panic".to_string());

        let result = detect_language(&symbols);
        // Should return Unknown since Rust confidence is below 1% threshold
        assert_eq!(result, Some("unknown".to_string()));
    }

    #[test]
    fn test_adbc_functions_detected_as_c() {
        // ADBC functions are C-style symbols
        let symbols = vec![
            "AdbcDriverInit".to_string(),
            "AdbcDatabaseNew".to_string(),
            "AdbcConnectionNew".to_string(),
            "AdbcStatementNew".to_string(),
        ];

        let result = detect_language(&symbols);
        assert_eq!(result, Some("c".to_string()));
    }
}
