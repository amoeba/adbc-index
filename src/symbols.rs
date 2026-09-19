use std::fs::File;
use std::io::Read;
use std::path::Path;

use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::pe::PE;
use goblin::Object;

use crate::error::Result;
use crate::stub_detector::StubAnalysis;

/// Extract strings from binary data sections (for language detection)
/// This is useful for stripped binaries where symbols are removed but strings remain
pub fn extract_binary_strings<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Extract printable strings from the binary (min length 4 characters)
    let mut strings = Vec::new();
    let mut current_string = String::new();

    for &byte in &buffer {
        if byte.is_ascii_graphic() || byte == b' ' {
            current_string.push(byte as char);
        } else if byte == 0 || !byte.is_ascii() {
            if current_string.len() >= 4 {
                strings.push(current_string.clone());
            }
            current_string.clear();
        }
    }

    // Add the last string if it's long enough
    if current_string.len() >= 4 {
        strings.push(current_string);
    }

    Ok(strings)
}

/// Extract exported symbols from a shared library
#[allow(dead_code)]
pub fn extract_symbols<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    use std::panic;

    let path = path.as_ref();

    // Catch panics from goblin parsing
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| -> Result<Vec<String>> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let symbols = match Object::parse(&buffer)? {
            Object::Elf(elf) => extract_elf_symbols(&elf),
            Object::PE(pe) => extract_pe_symbols(&pe),
            Object::Mach(mach) => extract_mach_symbols(&mach),
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
fn extract_elf_symbols(elf: &Elf) -> Vec<String> {
    let mut symbols = Vec::new();

    // Extract dynamic symbols (exported functions)
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            // Only include function symbols (STT_FUNC) and global/weak binding
            if sym.st_type() == goblin::elf::sym::STT_FUNC
                && (sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                    || sym.st_bind() == goblin::elf::sym::STB_WEAK)
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
fn extract_pe_symbols(pe: &PE) -> Vec<String> {
    let mut symbols = Vec::new();

    // Extract exported functions
    for export in &pe.exports {
        if let Some(name) = export.name {
            symbols.push(name.to_string());
        }
    }

    symbols.sort();
    symbols.dedup();
    symbols
}

/// Extract symbols from Mach-O binary (macOS .dylib)
fn extract_mach_symbols(mach: &Mach) -> Vec<String> {
    let mut symbols = Vec::new();

    match mach {
        Mach::Binary(macho) => {
            // Single architecture - extract normally
            for (name, nlist) in macho.symbols().flatten() {
                if nlist.is_global() && !nlist.is_undefined() {
                    let name = name.trim_start_matches('_');
                    symbols.push(name.to_string());
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
) -> Result<(Vec<String>, Vec<StubAnalysis>)> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let object = Object::parse(&buffer)?;

    let (symbols, stubs) = match object {
        Object::Elf(elf) => {
            let symbols = extract_elf_symbols(&elf);
            let stubs = crate::stub_detector::analyze_elf_stubs_with_buffer(&elf, &buffer)?;
            (symbols, stubs)
        }
        Object::PE(pe) => {
            let symbols = extract_pe_symbols(&pe);
            let stubs = crate::stub_detector::analyze_pe_stubs_with_buffer(&pe, &buffer)?;
            (symbols, stubs)
        }
        Object::Mach(mach) => {
            // For Fat binaries, parse the first architecture
            let (symbols, stubs) = match &mach {
                Mach::Binary(_) => {
                    let symbols = extract_mach_symbols(&mach);
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
                                    let arch_symbols = extract_mach_symbols(&arch_mach);
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


