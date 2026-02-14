use std::fs::File;
use std::io::Read;
use std::path::Path;

use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::pe::PE;
use goblin::Object;

use crate::error::Result;
use crate::stub_detector::StubAnalysis;

/// Configuration for symbol filtering
#[derive(Debug, Clone)]
pub struct SymbolFilter {
    /// Prefixes to match (e.g., ["Adbc", "adbc"])
    pub prefixes: Vec<String>,
    /// If true, only include symbols matching prefixes. If false, include all.
    pub enabled: bool,
}

impl SymbolFilter {
    pub fn new(prefixes: Vec<String>) -> Self {
        Self {
            enabled: !prefixes.is_empty(),
            prefixes,
        }
    }

    pub fn matches(&self, symbol: &str) -> bool {
        if !self.enabled {
            return true;
        }

        self.prefixes
            .iter()
            .any(|prefix| symbol.starts_with(prefix))
    }
}

impl Default for SymbolFilter {
    fn default() -> Self {
        // By default, only include symbols starting with "Adbc"
        Self::new(vec!["Adbc".to_string()])
    }
}

/// Extract exported symbols from a shared library
#[allow(dead_code)]
pub fn extract_symbols<P: AsRef<Path>>(path: P, filter: &SymbolFilter) -> Result<Vec<String>> {
    use std::panic;

    let path = path.as_ref();

    // Catch panics from goblin parsing
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| -> Result<Vec<String>> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // Limit buffer size to prevent memory issues (100MB max)
        if buffer.len() > 100 * 1024 * 1024 {
            return Err(crate::error::AdbcIndexError::Config(format!(
                "Binary file too large: {} ({} bytes)",
                path.display(),
                buffer.len()
            )));
        }

        let symbols = match Object::parse(&buffer)? {
            Object::Elf(elf) => extract_elf_symbols(&elf, filter),
            Object::PE(pe) => extract_pe_symbols(&pe, filter),
            Object::Mach(mach) => extract_mach_symbols(&mach, filter),
            _ => {
                return Err(crate::error::AdbcIndexError::Config(format!(
                    "Unsupported binary format: {}",
                    path.display()
                )));
            }
        };

        Ok(symbols)
    }));

    // If panic occurred, return error
    match result {
        Ok(Ok(symbols)) => Ok(symbols),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(crate::error::AdbcIndexError::Config(format!(
            "Panic occurred while parsing binary: {}",
            path.display()
        ))),
    }
}

/// Extract symbols from ELF binary (Linux .so)
fn extract_elf_symbols(elf: &Elf, filter: &SymbolFilter) -> Vec<String> {
    let mut symbols = Vec::new();

    // Extract dynamic symbols (exported functions)
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            // Only include function symbols (STT_FUNC) and global/weak binding
            if sym.st_type() == goblin::elf::sym::STT_FUNC
                && (sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                    || sym.st_bind() == goblin::elf::sym::STB_WEAK)
                && filter.matches(name)
            {
                symbols.push(name.to_string());
            }
        }
    }

    symbols.sort();
    symbols.dedup();
    symbols
}

/// Extract symbols from PE binary (Windows .dll)
fn extract_pe_symbols(pe: &PE, filter: &SymbolFilter) -> Vec<String> {
    let mut symbols = Vec::new();

    // Extract exported functions
    for export in &pe.exports {
        if let Some(name) = export.name {
            if filter.matches(name) {
                symbols.push(name.to_string());
            }
        }
    }

    symbols.sort();
    symbols.dedup();
    symbols
}

/// Extract symbols from Mach-O binary (macOS .dylib)
fn extract_mach_symbols(mach: &Mach, filter: &SymbolFilter) -> Vec<String> {
    let mut symbols = Vec::new();

    match mach {
        Mach::Binary(macho) => {
            // Single architecture - extract normally
            for (name, nlist) in macho.symbols().flatten() {
                if nlist.is_global() && !nlist.is_undefined() {
                    let name = name.trim_start_matches('_');
                    if filter.matches(name) {
                        symbols.push(name.to_string());
                    }
                }
            }
        }
        Mach::Fat(_fat) => {
            // Universal binary - symbols should be identical across architectures
            // For now, we skip Fat binaries in this function since we don't have buffer access
            // They will be handled by extract_symbols_and_stubs which has buffer access
        }
    }

    symbols.sort();
    symbols.dedup();
    symbols
}

/// Combined extraction: get symbols and stub analyses in a single pass
/// This is more efficient than calling extract_symbols and analyze_stubs separately
pub fn extract_symbols_and_stubs<P: AsRef<Path>>(
    path: P,
    filter: &SymbolFilter,
) -> Result<(Vec<String>, Vec<StubAnalysis>)> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let object = Object::parse(&buffer)?;

    let (symbols, stubs) = match object {
        Object::Elf(elf) => {
            let symbols = extract_elf_symbols(&elf, filter);
            let stubs = crate::stub_detector::analyze_elf_stubs_with_buffer(&elf, &buffer)?;
            (symbols, stubs)
        }
        Object::PE(pe) => {
            let symbols = extract_pe_symbols(&pe, filter);
            let stubs = crate::stub_detector::analyze_pe_stubs_with_buffer(&pe, &buffer)?;
            (symbols, stubs)
        }
        Object::Mach(mach) => {
            // For Fat binaries, parse the first architecture
            let (symbols, stubs) = match &mach {
                Mach::Binary(_) => {
                    let symbols = extract_mach_symbols(&mach, filter);
                    let stubs = crate::stub_detector::analyze_mach_stubs_with_buffer(&mach, &buffer)?;
                    (symbols, stubs)
                }
                Mach::Fat(fat) => {
                    // Parse all architectures from Fat binary and merge symbols
                    let mut all_symbols = Vec::new();
                    let mut all_stubs = Vec::new();

                    for arch_result in fat.iter_arches() {
                        if let Ok(arch) = arch_result {
                            let start = arch.offset as usize;
                            let end = (arch.offset + arch.size) as usize;
                            if end <= buffer.len() {
                                let arch_slice = &buffer[start..end];
                                if let Ok(arch_mach) = Mach::parse(arch_slice) {
                                    // Extract symbols and stubs from this architecture
                                    let arch_symbols = extract_mach_symbols(&arch_mach, filter);
                                    let arch_stubs = crate::stub_detector::analyze_mach_stubs_with_buffer(
                                        &arch_mach,
                                        arch_slice,
                                    )?;

                                    // Merge symbols (union)
                                    all_symbols.extend(arch_symbols);

                                    // Merge stubs - keep all stubs from all architectures
                                    // Note: if a symbol appears in multiple archs with different stub status,
                                    // we keep all entries and let the caller decide how to handle it
                                    all_stubs.extend(arch_stubs);
                                }
                            }
                        }
                    }

                    // Deduplicate symbols while preserving order
                    all_symbols.sort();
                    all_symbols.dedup();

                    (all_symbols, all_stubs)
                }
            };
            (symbols, stubs)
        }
        _ => {
            return Err(crate::error::AdbcIndexError::Config(format!(
                "Unsupported binary format: {}",
                path.display()
            )));
        }
    };

    Ok((symbols, stubs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_filter_default() {
        let filter = SymbolFilter::default();

        assert!(filter.enabled);
        assert_eq!(filter.prefixes, vec!["Adbc"]);

        // Should match symbols starting with "Adbc"
        assert!(filter.matches("AdbcDriverInit"));
        assert!(filter.matches("AdbcConnectionNew"));

        // Should not match other symbols
        assert!(!filter.matches("adbc_driver_init")); // lowercase
        assert!(!filter.matches("MyAdbcFunction")); // prefix not at start
        assert!(!filter.matches("sqlite3_open")); // different function
    }

    #[test]
    fn test_symbol_filter_custom_prefixes() {
        let filter = SymbolFilter::new(vec!["Adbc".to_string(), "sqlite3_".to_string()]);

        assert!(filter.enabled);

        // Should match both prefixes
        assert!(filter.matches("AdbcDriverInit"));
        assert!(filter.matches("sqlite3_open"));
        assert!(filter.matches("sqlite3_close"));

        // Should not match other symbols
        assert!(!filter.matches("postgres_connect"));
        assert!(!filter.matches("my_function"));
    }

    #[test]
    fn test_symbol_filter_disabled() {
        let filter = SymbolFilter::new(vec![]);

        assert!(!filter.enabled);
        assert!(filter.prefixes.is_empty());

        // Should match everything when disabled
        assert!(filter.matches("AdbcDriverInit"));
        assert!(filter.matches("sqlite3_open"));
        assert!(filter.matches("anything"));
        assert!(filter.matches(""));
    }

    #[test]
    fn test_symbol_filter_case_sensitive() {
        let filter = SymbolFilter::new(vec!["Adbc".to_string()]);

        // Case-sensitive matching
        assert!(filter.matches("AdbcDriverInit"));
        assert!(filter.matches("Adbc"));

        // Should not match different case
        assert!(!filter.matches("adbc_driver_init"));
        assert!(!filter.matches("ADBC_DRIVER_INIT"));
        assert!(!filter.matches("adbcDriverInit"));
    }
}
