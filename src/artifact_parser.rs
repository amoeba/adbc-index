/// Parsed artifact metadata
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactMetadata {
    pub os: Option<String>,
    pub arch: Option<Vec<String>>,
    pub version: Option<String>,
    pub file_format: Option<String>,
}

/// Parse artifact filename using multiple strategies
pub fn parse_artifact(filename: &str) -> ArtifactMetadata {
    // If it's a wheel file, use wheel-specific parsing
    if filename.ends_with(".whl") {
        if let Some(metadata) = strategy_wheel(filename) {
            if metadata.is_valid() {
                return metadata;
            }
        }
    }

    // Try each strategy in order
    let strategies: Vec<fn(&str) -> Option<ArtifactMetadata>> = vec![
        strategy_underscore_separated,
        strategy_dash_separated,
        strategy_without_prefix,
        strategy_platform_in_name,
        strategy_best_effort,
    ];

    for strategy in strategies {
        if let Some(metadata) = strategy(filename) {
            if metadata.is_valid() {
                return metadata;
            }
        }
    }

    // Fallback: at least extract file format
    ArtifactMetadata {
        os: None,
        arch: None,
        version: None,
        file_format: extract_file_format(filename),
    }
}

impl ArtifactMetadata {
    fn is_valid(&self) -> bool {
        // At least one field must be populated
        let has_data = self.os.is_some() || self.arch.is_some() || self.version.is_some();

        // Additionally, if arch is present, it must not be empty
        let arch_valid = if let Some(ref arch) = self.arch {
            !arch.is_empty()
        } else {
            true // None is valid (means unknown arch)
        };

        has_data && arch_valid
    }
}

/// Strategy 0: Python wheel files
/// Example: adbc_driver_sqlite-0.1.0-py3-none-macosx_10_9_x86_64.whl
/// Format: {package}-{version}-{python}-{abi}-{platform}.whl
fn strategy_wheel(filename: &str) -> Option<ArtifactMetadata> {
    if !filename.ends_with(".whl") {
        return None;
    }

    let base = filename.trim_end_matches(".whl");
    let parts: Vec<&str> = base.split('-').collect();

    // Wheel format requires at least 5 parts: package, version, python, abi, platform
    if parts.len() < 5 {
        return None;
    }

    // Version is the second part
    let version = extract_version(parts[1]);

    // Platform is everything after the abi tag (may contain multiple dashes)
    // Join the last parts to handle platforms like "macosx_10_9_x86_64"
    let platform = parts[4..].join("-");

    // Parse the wheel platform tag
    let (os, arch) = parse_wheel_platform(&platform);

    Some(ArtifactMetadata {
        os,
        arch,
        version,
        file_format: Some("whl".to_string()),
    })
}

/// Parse wheel platform tag to OS and architecture
/// Examples:
/// - linux_x86_64 -> (linux, [amd64])
/// - macosx_10_9_x86_64 -> (darwin, [amd64])
/// - win_amd64 -> (windows, [amd64])
fn parse_wheel_platform(platform: &str) -> (Option<String>, Option<Vec<String>>) {
    let lower = platform.to_lowercase();

    // Determine OS
    let os = if lower.starts_with("linux") {
        Some("linux".to_string())
    } else if lower.starts_with("macosx") {
        Some("darwin".to_string())
    } else if lower.starts_with("win") {
        Some("windows".to_string())
    } else if lower == "any" {
        // Platform-independent wheel (no native code)
        None
    } else {
        None
    };

    // Determine architecture from the platform tag
    let arch = if lower.contains("x86_64") || lower.contains("amd64") {
        Some(vec!["amd64".to_string()])
    } else if lower.contains("aarch64") || lower.contains("arm64") {
        Some(vec!["arm64".to_string()])
    } else if lower.contains("i686") || lower.contains("win32") {
        Some(vec!["386".to_string()])
    } else if lower.contains("armv7") {
        Some(vec!["arm".to_string()])
    } else if lower == "any" {
        // Platform-independent
        None
    } else {
        None
    };

    (os, arch)
}

/// Strategy 1: driver_os_arch_version.ext
/// Example: mysql_linux_amd64_v0.2.0.tar.gz
fn strategy_underscore_separated(filename: &str) -> Option<ArtifactMetadata> {
    let (base, format) = split_extension(filename);
    let parts: Vec<&str> = base.split('_').collect();

    if parts.len() >= 4 {
        // Skip first part (driver name), parse rest
        let os = recognize_os(parts[1]);
        let arch = recognize_arch(parts[2]);
        let version = extract_version(parts[3..].join("_").as_str());

        if os.is_some() || arch.is_some() {
            return Some(ArtifactMetadata {
                os,
                arch,
                version,
                file_format: format,
            });
        }
    }

    None
}

/// Strategy 2: driver-os-arch-version.ext
/// Example: mysql-linux-amd64-v0.2.0.tar.gz
fn strategy_dash_separated(filename: &str) -> Option<ArtifactMetadata> {
    let (base, format) = split_extension(filename);
    let parts: Vec<&str> = base.split('-').collect();

    if parts.len() >= 4 {
        // Skip first part (driver name), parse rest
        let os = recognize_os(parts[1]);
        let arch = recognize_arch(parts[2]);
        let version = extract_version(parts[3..].join("-").as_str());

        if os.is_some() || arch.is_some() {
            return Some(ArtifactMetadata {
                os,
                arch,
                version,
                file_format: format,
            });
        }
    }

    None
}

/// Strategy 3: os_arch_version.ext (without driver prefix)
/// Example: linux_amd64_v0.2.0.tar.gz
fn strategy_without_prefix(filename: &str) -> Option<ArtifactMetadata> {
    let (base, format) = split_extension(filename);
    let parts: Vec<&str> = base.split('_').collect();

    if parts.len() >= 3 {
        let os = recognize_os(parts[0]);
        let arch = recognize_arch(parts[1]);
        let version = extract_version(parts[2..].join("_").as_str());

        if os.is_some() && arch.is_some() {
            return Some(ArtifactMetadata {
                os,
                arch,
                version,
                file_format: format,
            });
        }
    }

    None
}

/// Strategy 4: Look for platform keywords anywhere in name
/// Example: adbc-driver-postgresql-macos-arm64-1.0.0.tar.gz
fn strategy_platform_in_name(filename: &str) -> Option<ArtifactMetadata> {
    let (base, format) = split_extension(filename);
    let lower = base.to_lowercase();

    // Extract OS
    let os = if lower.contains("linux") {
        Some("linux".to_string())
    } else if lower.contains("darwin") || lower.contains("macos") || lower.contains("osx") {
        Some("darwin".to_string())
    } else if lower.contains("windows") || lower.contains("win") {
        Some("windows".to_string())
    } else {
        None
    };

    // Extract architecture - check for universal first
    let arch = if lower.contains("universal") {
        Some(vec!["amd64".to_string(), "arm64".to_string()])
    } else if lower.contains("amd64") || lower.contains("x86_64") || lower.contains("x64") {
        Some(vec!["amd64".to_string()])
    } else if lower.contains("arm64") || lower.contains("aarch64") {
        Some(vec!["arm64".to_string()])
    } else if lower.contains("386") || lower.contains("x86") {
        Some(vec!["386".to_string()])
    } else if lower.contains("arm") {
        Some(vec!["arm".to_string()])
    } else {
        None
    };

    // Try to extract version from any part
    let version = base.split(&['_', '-'][..]).find_map(extract_version);

    if os.is_some() || arch.is_some() {
        return Some(ArtifactMetadata {
            os,
            arch,
            version,
            file_format: format,
        });
    }

    None
}

/// Strategy 5: Best effort - extract whatever we can find
fn strategy_best_effort(filename: &str) -> Option<ArtifactMetadata> {
    let (base, format) = split_extension(filename);

    // Try to find any recognizable components
    let parts: Vec<&str> = base.split(&['_', '-', '.'][..]).collect();

    let mut os = None;
    let mut arch = None;
    let mut version = None;

    for part in &parts {
        if os.is_none() {
            os = recognize_os(part);
        }
        if arch.is_none() {
            arch = recognize_arch(part);
        }
        if version.is_none() {
            version = extract_version(part);
        }
    }

    Some(ArtifactMetadata {
        os,
        arch,
        version,
        file_format: format,
    })
}

/// Recognize OS from string
fn recognize_os(s: &str) -> Option<String> {
    let lower = s.to_lowercase();
    match lower.as_str() {
        "linux" => Some("linux".to_string()),
        "darwin" | "macos" | "osx" => Some("darwin".to_string()),
        "windows" | "win" => Some("windows".to_string()),
        "freebsd" => Some("freebsd".to_string()),
        "netbsd" => Some("netbsd".to_string()),
        "openbsd" => Some("openbsd".to_string()),
        _ => None,
    }
}

/// Recognize architecture from string
fn recognize_arch(s: &str) -> Option<Vec<String>> {
    let lower = s.to_lowercase();
    match lower.as_str() {
        "universal" => Some(vec!["amd64".to_string(), "arm64".to_string()]),
        "amd64" | "x86_64" | "x64" => Some(vec!["amd64".to_string()]),
        "arm64" | "aarch64" => Some(vec!["arm64".to_string()]),
        "386" | "i386" | "x86" => Some(vec!["386".to_string()]),
        "arm" | "armv7" => Some(vec!["arm".to_string()]),
        "ppc64le" => Some(vec!["ppc64le".to_string()]),
        "s390x" => Some(vec!["s390x".to_string()]),
        _ => None,
    }
}

/// Extract version from string
fn extract_version(s: &str) -> Option<String> {
    let s = s.trim();

    // Match patterns like v0.2.0, 1.0.0, etc.
    if s.starts_with('v') || s.starts_with('V') {
        let rest = &s[1..];
        if is_version_like(rest) {
            return Some(rest.to_string());
        }
    }

    if is_version_like(s) {
        return Some(s.to_string());
    }

    None
}

/// Check if string looks like a version number
fn is_version_like(s: &str) -> bool {
    // Must start with a digit
    if !s
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        return false;
    }

    // Must contain at least one dot
    if !s.contains('.') {
        return false;
    }

    // All characters should be digits, dots, or hyphens
    s.chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
}

/// Split filename into base and extension
fn split_extension(filename: &str) -> (String, Option<String>) {
    // Handle compound extensions like .tar.gz
    if filename.ends_with(".tar.gz") {
        let base = filename.trim_end_matches(".tar.gz");
        return (base.to_string(), Some("tar.gz".to_string()));
    }
    if filename.ends_with(".tar.bz2") {
        let base = filename.trim_end_matches(".tar.bz2");
        return (base.to_string(), Some("tar.bz2".to_string()));
    }
    if filename.ends_with(".tar.xz") {
        let base = filename.trim_end_matches(".tar.xz");
        return (base.to_string(), Some("tar.xz".to_string()));
    }

    // Single extension
    if let Some(dot_pos) = filename.rfind('.') {
        let base = filename[..dot_pos].to_string();
        let ext = filename[dot_pos + 1..].to_string();
        (base, Some(ext))
    } else {
        (filename.to_string(), None)
    }
}

/// Extract file format from filename
fn extract_file_format(filename: &str) -> Option<String> {
    let (_, format) = split_extension(filename);
    format
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_underscore_separated() {
        let meta = parse_artifact("mysql_linux_amd64_v0.2.0.tar.gz");
        assert_eq!(meta.os, Some("linux".to_string()));
        assert_eq!(meta.arch, Some(vec!["amd64".to_string()]));
        assert_eq!(meta.version, Some("0.2.0".to_string()));
        assert_eq!(meta.file_format, Some("tar.gz".to_string()));
    }

    #[test]
    fn test_dash_separated() {
        let meta = parse_artifact("mysql-darwin-arm64-1.0.0.zip");
        assert_eq!(meta.os, Some("darwin".to_string()));
        assert_eq!(meta.arch, Some(vec!["arm64".to_string()]));
        assert_eq!(meta.version, Some("1.0.0".to_string()));
        assert_eq!(meta.file_format, Some("zip".to_string()));
    }

    #[test]
    fn test_platform_in_name() {
        let meta = parse_artifact("adbc-driver-postgresql-macos-arm64-1.0.0.tar.gz");
        assert_eq!(meta.os, Some("darwin".to_string()));
        assert_eq!(meta.arch, Some(vec!["arm64".to_string()]));
        assert_eq!(meta.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_windows() {
        let meta = parse_artifact("driver_windows_amd64_v1.2.3.zip");
        assert_eq!(meta.os, Some("windows".to_string()));
        assert_eq!(meta.arch, Some(vec!["amd64".to_string()]));
        assert_eq!(meta.version, Some("1.2.3".to_string()));
    }

    #[test]
    fn test_wheel_linux() {
        let meta = parse_artifact("adbc_driver_sqlite-0.1.0-py3-none-linux_x86_64.whl");
        assert_eq!(meta.os, Some("linux".to_string()));
        assert_eq!(meta.arch, Some(vec!["amd64".to_string()]));
        assert_eq!(meta.version, Some("0.1.0".to_string()));
        assert_eq!(meta.file_format, Some("whl".to_string()));
    }

    #[test]
    fn test_wheel_macos_intel() {
        let meta = parse_artifact("adbc_driver_sqlite-0.2.0-py3-none-macosx_10_9_x86_64.whl");
        assert_eq!(meta.os, Some("darwin".to_string()));
        assert_eq!(meta.arch, Some(vec!["amd64".to_string()]));
        assert_eq!(meta.version, Some("0.2.0".to_string()));
    }

    #[test]
    fn test_wheel_macos_arm() {
        let meta = parse_artifact("adbc_driver_postgresql-1.0.0-py3-none-macosx_11_0_arm64.whl");
        assert_eq!(meta.os, Some("darwin".to_string()));
        assert_eq!(meta.arch, Some(vec!["arm64".to_string()]));
        assert_eq!(meta.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_wheel_windows() {
        let meta = parse_artifact("adbc_driver_flightsql-0.5.0-py3-none-win_amd64.whl");
        assert_eq!(meta.os, Some("windows".to_string()));
        assert_eq!(meta.arch, Some(vec!["amd64".to_string()]));
        assert_eq!(meta.version, Some("0.5.0".to_string()));
    }

    #[test]
    fn test_universal_binary() {
        let meta = parse_artifact("libduckdb-osx-universal.zip");
        assert_eq!(meta.os, Some("darwin".to_string()));
        assert_eq!(
            meta.arch,
            Some(vec!["amd64".to_string(), "arm64".to_string()])
        );
    }
}
