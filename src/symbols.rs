use std::fs::File;
use std::io::Read;
use std::path::Path;

use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::pe::PE;
use goblin::Object;

use crate::error::Result;

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

        self.prefixes.iter().any(|prefix| symbol.starts_with(prefix))
    }
}

impl Default for SymbolFilter {
    fn default() -> Self {
        // By default, only include symbols starting with "Adbc"
        Self::new(vec!["Adbc".to_string()])
    }
}

/// Extract exported symbols from a shared library
pub fn extract_symbols<P: AsRef<Path>>(
    path: P,
    filter: &SymbolFilter,
) -> Result<Vec<String>> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let symbols = match Object::parse(&buffer)? {
        Object::Elf(elf) => extract_elf_symbols(&elf, filter),
        Object::PE(pe) => extract_pe_symbols(&pe, filter),
        Object::Mach(mach) => extract_mach_symbols(&mach, filter),
        _ => {
            return Err(crate::error::AdbcIndexError::Config(
                format!("Unsupported binary format: {}", path.display())
            ));
        }
    };

    Ok(symbols)
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
            {
                if filter.matches(name) {
                    symbols.push(name.to_string());
                }
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
            // Extract exported symbols from dynamic symbol table
            for sym in macho.symbols() {
                if let Ok((name, nlist)) = sym {
                    // Check if it's an exported symbol (external linkage)
                    if nlist.is_global() && !nlist.is_undefined() {
                        let name = name.trim_start_matches('_'); // Remove leading underscore
                        if filter.matches(name) {
                            symbols.push(name.to_string());
                        }
                    }
                }
            }
        }
        Mach::Fat(_) => {
            // Fat binaries are more complex - skip for now
            // They contain multiple architectures, would need to iterate and parse each
        }
    }

    symbols.sort();
    symbols.dedup();
    symbols
}
