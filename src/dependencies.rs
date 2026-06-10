use std::fs::File;
use std::io::Read;
use std::path::Path;

use goblin::mach::Mach;
use goblin::Object;

use crate::error::Result;

/// Extract dynamic library dependencies from a shared library.
/// Returns the list of dependency strings as recorded in the binary.
///
/// - ELF (Linux): DT_NEEDED entries (filenames like "libc.so.6")
/// - PE (Windows): Imported DLL names (like "KERNEL32.dll")
/// - Mach-O (macOS): LC_LOAD_DYLIB paths (like "/usr/lib/libSystem.B.dylib")
///
/// For Fat/Universal Mach-O binaries, extracts dependencies from the first
/// architecture slice and verifies all other slices have identical dependencies.
/// Returns an error if slices differ.
pub fn extract_dependencies<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let deps = match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            elf.libraries.iter().map(|s| s.to_string()).collect()
        }
        Object::PE(pe) => {
            pe.libraries.iter().map(|s| s.to_string()).collect()
        }
        Object::Mach(mach) => extract_mach_dependencies(&mach, &buffer, path)?,
        _ => {
            return Err(crate::error::AdbcIndexError::Config(format!(
                "Unsupported binary format: {}",
                path.display()
            )));
        }
    };

    Ok(deps)
}

/// Extract dependencies from Mach-O, handling Fat binaries.
fn extract_mach_dependencies(mach: &Mach, buffer: &[u8], path: &Path) -> Result<Vec<String>> {
    match mach {
        Mach::Binary(macho) => {
            // Single architecture: skip "self" which is always the first entry
            Ok(macho
                .libs
                .iter()
                .skip(1) // first entry is always "self"
                .map(|s| s.to_string())
                .collect())
        }
        Mach::Fat(fat) => {
            // Universal binary: extract from first arch, verify others match
            let mut first_deps: Option<Vec<String>> = None;

            for (i, arch_result) in fat.iter_arches().enumerate() {
                let arch = arch_result.map_err(|e| {
                    crate::error::AdbcIndexError::Config(format!(
                        "Failed to parse fat arch {}: {}",
                        i, e
                    ))
                })?;

                let start = arch.offset as usize;
                let end = (arch.offset + arch.size) as usize;
                if end > buffer.len() {
                    return Err(crate::error::AdbcIndexError::Config(format!(
                        "Fat binary arch {} extends beyond buffer in {}",
                        i,
                        path.display()
                    )));
                }

                let arch_slice = &buffer[start..end];
                let arch_mach = Mach::parse(arch_slice).map_err(|e| {
                    crate::error::AdbcIndexError::Config(format!(
                        "Failed to parse fat arch {} in {}: {}",
                        i,
                        path.display(),
                        e
                    ))
                })?;

                let deps: Vec<String> = match &arch_mach {
                    Mach::Binary(macho) => macho
                        .libs
                        .iter()
                        .skip(1) // first entry is always "self"
                        .map(|s| s.to_string())
                        .collect(),
                    _ => {
                        return Err(crate::error::AdbcIndexError::Config(format!(
                            "Unexpected nested fat binary in {}",
                            path.display()
                        )));
                    }
                };

                match &first_deps {
                    None => {
                        first_deps = Some(deps);
                    }
                    Some(first) => {
                        if first != &deps {
                            return Err(crate::error::AdbcIndexError::Config(format!(
                                "Fat binary architecture slices have different dependencies in {}. \
                                 Arch 0: {:?}, Arch {}: {:?}",
                                path.display(),
                                first,
                                i,
                                deps
                            )));
                        }
                    }
                }
            }

            first_deps.ok_or_else(|| {
                crate::error::AdbcIndexError::Config(format!(
                    "Fat binary has no architecture slices: {}",
                    path.display()
                ))
            })
        }
    }
}

/// Determine if a dependency is a system library.
///
/// Uses conservative allowlists per platform:
/// - Linux: glibc, kernel vDSO, GCC/C++ runtimes
/// - macOS: /usr/lib/*, /System/Library/*
/// - Windows: core Windows DLLs, CRT, api-ms-win-*
///
/// Everything else (libssl, libz, libcurl, etc.) is considered non-system.
pub fn is_system_dependency(dependency: &str, os: &str) -> bool {
    match os {
        "linux" => is_system_linux(dependency),
        "macos" | "darwin" => is_system_macos(dependency),
        "windows" => is_system_windows(dependency),
        _ => false,
    }
}

/// Conservative list of Linux system library prefixes.
/// Only glibc, kernel, and compiler runtimes.
fn is_system_linux(dep: &str) -> bool {
    // These are the basename (ELF only stores filenames)
    const SYSTEM_PREFIXES: &[&str] = &[
        "libc.so",
        "libc.musl-",
        "libm.so",
        "libpthread.so",
        "libdl.so",
        "librt.so",
        "libresolv.so",
        "libnsl.so",
        "libutil.so",
        "libcrypt.so",
        "libmvec.so",
        "ld-linux-",
        "ld-linux.",
        "ld-musl-",
        "linux-vdso.so",
        "linux-gate.so",
        "libgcc_s.so",
        "libstdc++.so",
    ];

    SYSTEM_PREFIXES.iter().any(|prefix| dep.starts_with(prefix))
}

/// macOS system libraries are identified by path prefix.
fn is_system_macos(dep: &str) -> bool {
    dep.starts_with("/usr/lib/")
        || dep.starts_with("/System/Library/")
}

/// Conservative list of Windows system DLLs (case-insensitive).
fn is_system_windows(dep: &str) -> bool {
    let dep_lower = dep.to_lowercase();

    // api-ms-win-* pattern (Windows API sets)
    if dep_lower.starts_with("api-ms-win-") {
        return true;
    }

    // ext-ms-* pattern (Windows extension API sets)
    if dep_lower.starts_with("ext-ms-") {
        return true;
    }

    // Known system DLLs (stored lowercase for comparison)
    const SYSTEM_DLLS: &[&str] = &[
        "kernel32.dll",
        "kernelbase.dll",
        "ntdll.dll",
        "user32.dll",
        "gdi32.dll",
        "advapi32.dll",
        "shell32.dll",
        "ole32.dll",
        "oleaut32.dll",
        "comctl32.dll",
        "comdlg32.dll",
        "combase.dll",
        "ws2_32.dll",
        "wsock32.dll",
        "winmm.dll",
        "winspool.drv",
        "imm32.dll",
        "msvcrt.dll",
        "ucrtbase.dll",
        "crypt32.dll",
        "secur32.dll",
        "bcrypt.dll",
        "bcryptprimitives.dll",
        "ncrypt.dll",
        "rpcrt4.dll",
        "shlwapi.dll",
        "version.dll",
        "iphlpapi.dll",
        "userenv.dll",
        "netapi32.dll",
        "setupapi.dll",
        "wintrust.dll",
        "cabinet.dll",
        "msi.dll",
        "psapi.dll",
        "dbghelp.dll",
        "powrprof.dll",
        "winhttp.dll",
        "wininet.dll",
        "urlmon.dll",
        "dnsapi.dll",
        "mswsock.dll",
        "normaliz.dll",
        "credui.dll",
        "sechost.dll",
        "cfgmgr32.dll",
        "nsi.dll",
        "wldap32.dll",
        "rstrtmgr.dll",
    ];

    if SYSTEM_DLLS.contains(&dep_lower.as_str()) {
        return true;
    }

    // Visual C++ runtime DLLs (vcruntime*.dll, msvcp*.dll, vcomp*.dll, concrt*.dll)
    if dep_lower.starts_with("vcruntime") && dep_lower.ends_with(".dll") {
        return true;
    }
    if dep_lower.starts_with("msvcp") && dep_lower.ends_with(".dll") {
        return true;
    }
    if dep_lower.starts_with("vcomp") && dep_lower.ends_with(".dll") {
        return true;
    }
    if dep_lower.starts_with("concrt") && dep_lower.ends_with(".dll") {
        return true;
    }

    // GCC/MinGW runtime DLLs
    if dep_lower.starts_with("libgcc_s") && dep_lower.ends_with(".dll") {
        return true;
    }
    if dep_lower.starts_with("libstdc++") && dep_lower.ends_with(".dll") {
        return true;
    }
    if dep_lower.starts_with("libwinpthread") && dep_lower.ends_with(".dll") {
        return true;
    }

    false
}

/// Extract the basename from a dependency path.
/// For macOS paths like "/usr/lib/libSystem.B.dylib", returns "libSystem.B.dylib".
/// For ELF/PE entries that are already basenames, returns as-is.
pub fn dependency_basename(dependency: &str) -> String {
    Path::new(dependency)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| dependency.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_system_linux() {
        assert!(is_system_linux("libc.so.6"));
        assert!(is_system_linux("libc.musl-x86_64.so.1"));
        assert!(is_system_linux("libc.musl-aarch64.so.1"));
        assert!(is_system_linux("libm.so.6"));
        assert!(is_system_linux("libpthread.so.0"));
        assert!(is_system_linux("libdl.so.2"));
        assert!(is_system_linux("librt.so.1"));
        assert!(is_system_linux("ld-linux-x86-64.so.2"));
        assert!(is_system_linux("ld-musl-x86_64.so.1"));
        assert!(is_system_linux("linux-vdso.so.1"));
        assert!(is_system_linux("libgcc_s.so.1"));
        assert!(is_system_linux("libstdc++.so.6"));

        // Non-system
        assert!(!is_system_linux("libssl.so.1.1"));
        assert!(!is_system_linux("libz.so.1"));
        assert!(!is_system_linux("libcurl.so.4"));
        assert!(!is_system_linux("liboci.so"));
        assert!(!is_system_linux("libarrow.so.1200"));
    }

    #[test]
    fn test_is_system_macos() {
        assert!(is_system_macos("/usr/lib/libSystem.B.dylib"));
        assert!(is_system_macos("/usr/lib/libc++.1.dylib"));
        assert!(is_system_macos("/usr/lib/libobjc.A.dylib"));
        assert!(is_system_macos(
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
        ));
        assert!(is_system_macos(
            "/System/Library/Frameworks/Security.framework/Versions/A/Security"
        ));

        // Non-system
        assert!(!is_system_macos("@rpath/libsomething.dylib"));
        assert!(!is_system_macos("@loader_path/../lib/libfoo.dylib"));
        assert!(!is_system_macos("/opt/homebrew/lib/libssl.3.dylib"));
    }

    #[test]
    fn test_is_system_dependency_darwin_os() {
        // The artifact parser normalizes macOS to "darwin", so is_system_dependency
        // must accept both "macos" and "darwin".
        assert!(is_system_dependency("/usr/lib/libSystem.B.dylib", "darwin"));
        assert!(is_system_dependency(
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
            "darwin"
        ));
        assert!(is_system_dependency("/usr/lib/libiconv.2.dylib", "darwin"));
        assert!(!is_system_dependency("libcliv2.dylib", "darwin"));

        // Also works with "macos"
        assert!(is_system_dependency("/usr/lib/libSystem.B.dylib", "macos"));
    }

    #[test]
    fn test_is_system_windows() {
        assert!(is_system_windows("KERNEL32.dll"));
        assert!(is_system_windows("kernel32.dll"));
        assert!(is_system_windows("ntdll.dll"));
        assert!(is_system_windows("USER32.dll"));
        assert!(is_system_windows("WS2_32.dll"));
        assert!(is_system_windows("VCRUNTIME140.dll"));
        assert!(is_system_windows("vcruntime140_1.dll"));
        assert!(is_system_windows("ucrtbase.dll"));
        assert!(is_system_windows("api-ms-win-crt-runtime-l1-1-0.dll"));
        assert!(is_system_windows("MSVCP140.dll"));
        assert!(is_system_windows("bcryptprimitives.dll"));
        assert!(is_system_windows("combase.dll"));
        assert!(is_system_windows("WLDAP32.dll"));
        assert!(is_system_windows("RstrtMgr.DLL"));
        assert!(is_system_windows("libgcc_s_seh-1.dll"));
        assert!(is_system_windows("libstdc++-6.dll"));
        assert!(is_system_windows("libwinpthread-1.dll"));

        // Non-system
        assert!(!is_system_windows("oci.dll"));
        assert!(!is_system_windows("libssl-3-x64.dll"));
        assert!(!is_system_windows("arrow.dll"));
    }

    #[test]
    fn test_dependency_basename() {
        assert_eq!(
            dependency_basename("/usr/lib/libSystem.B.dylib"),
            "libSystem.B.dylib"
        );
        assert_eq!(
            dependency_basename("/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"),
            "CoreFoundation"
        );
        assert_eq!(dependency_basename("libc.so.6"), "libc.so.6");
        assert_eq!(dependency_basename("KERNEL32.dll"), "KERNEL32.dll");
        assert_eq!(
            dependency_basename("@rpath/libfoo.dylib"),
            "libfoo.dylib"
        );
    }
}
