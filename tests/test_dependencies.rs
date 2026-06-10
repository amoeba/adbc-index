use adbc_index::dependencies::{dependency_basename, extract_dependencies, is_system_dependency};

#[test]
fn test_extract_dependencies_linux() {
    let path = "test_artifacts/tiniest-adbc-driver/tiny-driver-ubuntu-latest/libtiny.so";
    let deps = extract_dependencies(path).unwrap();

    // Linux ELF libraries should at minimum depend on libc
    assert!(!deps.is_empty(), "Linux library should have dependencies");

    // Check that libc is present (virtually all shared libraries depend on it)
    let has_libc = deps.iter().any(|d| d.starts_with("libc.so"));
    assert!(has_libc, "Linux library should depend on libc.so, got: {:?}", deps);

    // All libc/system deps should be classified as system
    for dep in &deps {
        if dep.starts_with("libc.so") || dep.starts_with("ld-linux") {
            assert!(
                is_system_dependency(dep, "linux"),
                "{} should be classified as system on linux",
                dep
            );
        }
    }
}

#[test]
fn test_extract_dependencies_macos() {
    let path = "test_artifacts/tiniest-adbc-driver/tiny-driver-macos-latest/libtiny.dylib";
    let deps = extract_dependencies(path).unwrap();

    // macOS dylibs should at minimum depend on libSystem
    assert!(!deps.is_empty(), "macOS library should have dependencies");

    // Check that libSystem.B.dylib is present
    let has_libsystem = deps.iter().any(|d| d.contains("libSystem"));
    assert!(
        has_libsystem,
        "macOS library should depend on libSystem, got: {:?}",
        deps
    );

    // All /usr/lib/* deps should be classified as system
    for dep in &deps {
        if dep.starts_with("/usr/lib/") {
            assert!(
                is_system_dependency(dep, "macos"),
                "{} should be classified as system on macos",
                dep
            );
        }
    }

    // Verify basename extraction works for macOS paths
    for dep in &deps {
        let basename = dependency_basename(dep);
        assert!(!basename.is_empty());
        assert!(!basename.contains('/'), "basename should not contain path separators: {}", basename);
    }
}

#[test]
fn test_extract_dependencies_windows() {
    let path = "test_artifacts/tiniest-adbc-driver/tiny-driver-windows-latest/tiny.dll";
    let deps = extract_dependencies(path).unwrap();

    // Windows DLLs should depend on KERNEL32 at minimum
    assert!(!deps.is_empty(), "Windows DLL should have dependencies");

    // Check that KERNEL32.dll is present (case-insensitive check)
    let has_kernel32 = deps
        .iter()
        .any(|d| d.to_lowercase().contains("kernel32"));
    assert!(
        has_kernel32,
        "Windows DLL should depend on KERNEL32.dll, got: {:?}",
        deps
    );

    // All known system DLLs should be classified as system
    for dep in &deps {
        let dep_lower = dep.to_lowercase();
        if dep_lower == "kernel32.dll" || dep_lower == "ntdll.dll" || dep_lower == "msvcrt.dll" {
            assert!(
                is_system_dependency(dep, "windows"),
                "{} should be classified as system on windows",
                dep
            );
        }
    }
}

#[test]
fn test_extract_dependencies_all_platforms_have_deps() {
    let test_cases = vec![
        ("test_artifacts/tiniest-adbc-driver/tiny-driver-ubuntu-latest/libtiny.so", "linux"),
        ("test_artifacts/tiniest-adbc-driver/tiny-driver-macos-latest/libtiny.dylib", "macos"),
        ("test_artifacts/tiniest-adbc-driver/tiny-driver-windows-latest/tiny.dll", "windows"),
    ];

    for (path, os) in test_cases {
        let deps = extract_dependencies(path).unwrap();
        assert!(
            !deps.is_empty(),
            "Library at {} ({}) should have at least one dependency",
            path,
            os
        );

        // Every dependency should have a non-empty basename
        for dep in &deps {
            let basename = dependency_basename(dep);
            assert!(
                !basename.is_empty(),
                "Dependency {} should have a non-empty basename",
                dep
            );
        }
    }
}

#[test]
fn test_dependency_classification_non_system() {
    // These should NOT be classified as system
    assert!(!is_system_dependency("libssl.so.1.1", "linux"));
    assert!(!is_system_dependency("libz.so.1", "linux"));
    assert!(!is_system_dependency("libcurl.so.4", "linux"));
    assert!(!is_system_dependency("@rpath/libsomething.dylib", "macos"));
    assert!(!is_system_dependency("/opt/homebrew/lib/libssl.3.dylib", "macos"));
    assert!(!is_system_dependency("oci.dll", "windows"));
    assert!(!is_system_dependency("arrow.dll", "windows"));
}
