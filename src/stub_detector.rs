use goblin::Object;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::Result;

/// ADBC status codes from adbc.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AdbcStatusCode {
    Ok = 0,
    Unknown = 1,
    NotImplemented = 2,
    NotFound = 3,
    AlreadyExists = 4,
    InvalidArgument = 5,
    InvalidState = 6,
    InvalidData = 7,
    Integrity = 8,
    Internal = 9,
    Io = 10,
    Cancelled = 11,
    Unauthorized = 12,
    Timeout = 13,
}

impl AdbcStatusCode {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::Unknown),
            2 => Some(Self::NotImplemented),
            3 => Some(Self::NotFound),
            4 => Some(Self::AlreadyExists),
            5 => Some(Self::InvalidArgument),
            6 => Some(Self::InvalidState),
            7 => Some(Self::InvalidData),
            8 => Some(Self::Integrity),
            9 => Some(Self::Internal),
            10 => Some(Self::Io),
            11 => Some(Self::Cancelled),
            12 => Some(Self::Unauthorized),
            13 => Some(Self::Timeout),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Ok => "ADBC_STATUS_OK",
            Self::Unknown => "ADBC_STATUS_UNKNOWN",
            Self::NotImplemented => "ADBC_STATUS_NOT_IMPLEMENTED",
            Self::NotFound => "ADBC_STATUS_NOT_FOUND",
            Self::AlreadyExists => "ADBC_STATUS_ALREADY_EXISTS",
            Self::InvalidArgument => "ADBC_STATUS_INVALID_ARGUMENT",
            Self::InvalidState => "ADBC_STATUS_INVALID_STATE",
            Self::InvalidData => "ADBC_STATUS_INVALID_DATA",
            Self::Integrity => "ADBC_STATUS_INTEGRITY",
            Self::Internal => "ADBC_STATUS_INTERNAL",
            Self::Io => "ADBC_STATUS_IO",
            Self::Cancelled => "ADBC_STATUS_CANCELLED",
            Self::Unauthorized => "ADBC_STATUS_UNAUTHORIZED",
            Self::Timeout => "ADBC_STATUS_TIMEOUT",
        }
    }
}

/// Result of analyzing a function
#[derive(Debug, Clone)]
pub struct StubAnalysis {
    pub symbol_name: String,
    pub is_stub: bool,
    pub constant_return: Option<i32>,
    pub status_code: Option<AdbcStatusCode>,
}

/// Detect stub implementations in a library
pub fn analyze_stubs<P: AsRef<Path>>(path: P) -> Result<Vec<StubAnalysis>> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let object = Object::parse(&buffer)?;

    let mut results = Vec::new();

    match object {
        Object::Elf(elf) => {
            results.extend(analyze_elf_stubs_with_buffer(&elf, &buffer)?);
        }
        Object::PE(pe) => {
            results.extend(analyze_pe_stubs_with_buffer(&pe, &buffer)?);
        }
        Object::Mach(mach) => {
            results.extend(analyze_mach_stubs_with_buffer(&mach, &buffer)?);
        }
        _ => {}
    }

    Ok(results)
}

/// Analyze ELF (Linux .so) for stub functions
pub fn analyze_elf_stubs_with_buffer(
    elf: &goblin::elf::Elf,
    buffer: &[u8],
) -> Result<Vec<StubAnalysis>> {
    let mut results = Vec::new();

    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            // Only analyze ADBC functions
            if !name.starts_with("Adbc") {
                continue;
            }

            // Check if it's a function symbol
            if sym.st_type() == goblin::elf::sym::STT_FUNC
                && (sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                    || sym.st_bind() == goblin::elf::sym::STB_WEAK)
            {
                let offset = sym.st_value as usize;
                let size = sym.st_size as usize;

                if size > 0 && offset + size <= buffer.len() {
                    let func_bytes = &buffer[offset..offset + size.min(50)];
                    let analysis = analyze_x86_function(name, func_bytes);
                    results.push(analysis);
                }
            }
        }
    }

    Ok(results)
}

/// Section information for RVA to file offset conversion
struct SectionInfo {
    virtual_address: u32,
    virtual_size: u32,
    pointer_to_raw_data: u32,
}

/// Convert RVA to file offset using section information
fn rva_to_file_offset(rva: u32, sections: &[SectionInfo]) -> Option<u32> {
    for section in sections {
        if rva >= section.virtual_address && rva < section.virtual_address + section.virtual_size {
            let offset_in_section = rva - section.virtual_address;
            return Some(section.pointer_to_raw_data + offset_in_section);
        }
    }
    None
}

/// Analyze PE (Windows .dll) for stub functions
pub fn analyze_pe_stubs_with_buffer(
    pe: &goblin::pe::PE,
    buffer: &[u8],
) -> Result<Vec<StubAnalysis>> {
    let mut results = Vec::new();

    // Build section information for efficient RVA to offset conversion
    let sections: Vec<SectionInfo> = pe.sections.iter().map(|section| {
        SectionInfo {
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size.min(section.size_of_raw_data),
            pointer_to_raw_data: section.pointer_to_raw_data,
        }
    }).collect();

    for export in &pe.exports {
        if let Some(name) = export.name {
            // Only analyze ADBC functions
            if !name.starts_with("Adbc") {
                continue;
            }

            let rva = export.rva as u32;
            if let Some(offset) = rva_to_file_offset(rva, &sections) {
                let offset = offset as usize;
                if offset < buffer.len() {
                    let func_bytes = &buffer[offset..buffer.len().min(offset + 50)];
                    let analysis = analyze_x86_function(name, func_bytes);
                    results.push(analysis);
                }
            }
        }
    }

    Ok(results)
}

/// Analyze Mach-O (macOS .dylib) for stub functions
pub fn analyze_mach_stubs_with_buffer(
    mach: &goblin::mach::Mach,
    buffer: &[u8],
) -> Result<Vec<StubAnalysis>> {
    let mut results = Vec::new();

    match mach {
        goblin::mach::Mach::Binary(macho) => {
            for sym in macho.symbols() {
                if let Ok((name, nlist)) = sym {
                    let name = name.trim_start_matches('_');

                    // Only analyze ADBC functions
                    if !name.starts_with("Adbc") {
                        continue;
                    }

                    if nlist.is_global() && !nlist.is_undefined() {
                        let offset = nlist.n_value as usize;
                        if offset < buffer.len() {
                            let func_bytes = &buffer[offset..buffer.len().min(offset + 50)];

                            // Detect architecture from mach-o header
                            let is_arm64 = macho.header.cputype() == goblin::mach::cputype::CPU_TYPE_ARM64;

                            let analysis = if is_arm64 {
                                analyze_arm64_function(name, func_bytes)
                            } else {
                                analyze_x86_function(name, func_bytes)
                            };
                            results.push(analysis);
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(results)
}

/// Analyze x86/x64 function to detect constant returns
fn analyze_x86_function(name: &str, bytes: &[u8]) -> StubAnalysis {
    if bytes.is_empty() {
        return StubAnalysis {
            symbol_name: name.to_string(),
            is_stub: false,
            constant_return: None,
            status_code: None,
        };
    }

    // Try to detect simple constant return patterns
    let constant = detect_x86_constant_return(bytes);

    let status_code = constant.and_then(|c| AdbcStatusCode::from_i32(c));
    let is_stub = status_code == Some(AdbcStatusCode::NotImplemented);

    StubAnalysis {
        symbol_name: name.to_string(),
        is_stub,
        constant_return: constant,
        status_code,
    }
}

/// Analyze ARM64 function to detect constant returns
fn analyze_arm64_function(name: &str, bytes: &[u8]) -> StubAnalysis {
    if bytes.len() < 8 {
        return StubAnalysis {
            symbol_name: name.to_string(),
            is_stub: false,
            constant_return: None,
            status_code: None,
        };
    }

    let constant = detect_arm64_constant_return(bytes);

    let status_code = constant.and_then(|c| AdbcStatusCode::from_i32(c));
    let is_stub = status_code == Some(AdbcStatusCode::NotImplemented);

    StubAnalysis {
        symbol_name: name.to_string(),
        is_stub,
        constant_return: constant,
        status_code,
    }
}

/// Detect simple constant return patterns in x86/x64
pub(crate) fn detect_x86_constant_return(bytes: &[u8]) -> Option<i32> {
    if bytes.len() < 2 {
        return None;
    }

    // Pattern 1: mov eax, imm32; ret
    // B8 xx xx xx xx C3
    if bytes.len() >= 6 && bytes[0] == 0xB8 && bytes[5] == 0xC3 {
        let value = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        return Some(value);
    }

    // Pattern 2: xor eax, eax; ret (returns 0)
    // 31 C0 C3 or 33 C0 C3
    if bytes.len() >= 3 && (bytes[0] == 0x31 || bytes[0] == 0x33) && bytes[1] == 0xC0 && bytes[2] == 0xC3 {
        return Some(0);
    }

    // Pattern 3: mov eax, small_imm; ret
    // B8+r (for registers) or small immediate moves
    if bytes.len() >= 2 && (bytes[0] >= 0xB8 && bytes[0] <= 0xBF) {
        // Single byte register encoding
        let reg = bytes[0] - 0xB8;
        if reg == 0 && bytes.len() >= 6 { // eax
            let value = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            if bytes.len() > 5 && bytes[5] == 0xC3 {
                return Some(value);
            }
        }
    }

    // Pattern 4: mov rax, imm; ret (64-bit with REX prefix)
    // 48 C7 C0 xx xx xx xx C3
    if bytes.len() >= 8 && bytes[0] == 0x48 && bytes[1] == 0xC7 && bytes[2] == 0xC0 && bytes[7] == 0xC3 {
        let value = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
        return Some(value);
    }

    // Pattern 5: Simple small constant in eax
    // B8 0X 00 00 00 C3 (values 0-15 are common)
    if bytes.len() >= 6
        && bytes[0] == 0xB8
        && bytes[2] == 0x00
        && bytes[3] == 0x00
        && bytes[4] == 0x00
        && bytes[5] == 0xC3
    {
        return Some(bytes[1] as i32);
    }

    None
}

/// Detect simple constant return patterns in ARM64
pub(crate) fn detect_arm64_constant_return(bytes: &[u8]) -> Option<i32> {
    if bytes.len() < 8 {
        return None;
    }

    // ARM64 instruction encoding is fixed 32-bit (4 bytes)
    let instr1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let instr2 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    // Pattern: mov w0, #imm; ret
    // MOV (immediate) to w0 (x0 lower 32 bits) followed by RET
    // RET is typically 0xD65F03C0
    if instr2 == 0xD65F03C0 {
        // Check if first instruction is MOV w0, #imm
        // MOV is encoded as ORR with zero register: ORR Wd, WZR, #imm
        // Or as MOVZ: 0x52800000 | (imm << 5) | 0 (w0)

        // MOVZ w0, #imm: 0101_0010_1xxx_xxxx_xxxx_xxxx_xxx0_0000
        if (instr1 & 0xFF80_001F) == 0x5280_0000 {
            let imm = ((instr1 >> 5) & 0xFFFF) as i32;
            return Some(imm);
        }

        // MOVN w0, #imm (move NOT): 0001_0010_1xxx_xxxx_xxxx_xxxx_xxx0_0000
        if (instr1 & 0xFF80_001F) == 0x1280_0000 {
            let imm = ((instr1 >> 5) & 0xFFFF) as i32;
            return Some(!imm); // MOVN stores the NOT of the immediate
        }

        // ORR w0, wzr, #imm (another way to encode MOV)
        // This is more complex to decode, skip for now
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_from_i32_valid() {
        // Test valid status codes
        assert_eq!(AdbcStatusCode::from_i32(0), Some(AdbcStatusCode::Ok));
        assert_eq!(AdbcStatusCode::from_i32(2), Some(AdbcStatusCode::NotImplemented));
        assert_eq!(AdbcStatusCode::from_i32(13), Some(AdbcStatusCode::Timeout));
    }

    #[test]
    fn test_status_code_from_i32_invalid() {
        // Test invalid status codes
        assert_eq!(AdbcStatusCode::from_i32(-1), None);
        assert_eq!(AdbcStatusCode::from_i32(14), None);
        assert_eq!(AdbcStatusCode::from_i32(999), None);
    }

    #[test]
    fn test_status_code_names() {
        // Test status code name strings
        assert_eq!(AdbcStatusCode::Ok.name(), "ADBC_STATUS_OK");
        assert_eq!(AdbcStatusCode::NotImplemented.name(), "ADBC_STATUS_NOT_IMPLEMENTED");
        assert_eq!(AdbcStatusCode::Unknown.name(), "ADBC_STATUS_UNKNOWN");
        assert_eq!(AdbcStatusCode::Timeout.name(), "ADBC_STATUS_TIMEOUT");
    }

    #[test]
    fn test_detect_x86_return_zero_xor() {
        // Test x86 pattern: xor eax, eax; ret (returns 0)
        // 31 C0 C3
        let bytes = vec![0x31, 0xC0, 0xC3];
        assert_eq!(detect_x86_constant_return(&bytes), Some(0));

        // Alternative encoding: 33 C0 C3
        let bytes = vec![0x33, 0xC0, 0xC3];
        assert_eq!(detect_x86_constant_return(&bytes), Some(0));
    }

    #[test]
    fn test_detect_x86_return_constant_mov() {
        // Test x86 pattern: mov eax, 2; ret
        // B8 02 00 00 00 C3
        let bytes = vec![0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3];
        assert_eq!(detect_x86_constant_return(&bytes), Some(2));

        // Test with different constant
        let bytes = vec![0xB8, 0x0D, 0x00, 0x00, 0x00, 0xC3];
        assert_eq!(detect_x86_constant_return(&bytes), Some(13));
    }

    #[test]
    fn test_detect_x86_no_constant_return() {
        // Test complex code that doesn't have a simple constant return
        // This should return None
        let bytes = vec![0x48, 0x89, 0x5C, 0x24, 0x08, 0x57];
        assert_eq!(detect_x86_constant_return(&bytes), None);

        // Empty bytes
        assert_eq!(detect_x86_constant_return(&[]), None);

        // Just a return without constant setup
        let bytes = vec![0xC3];
        assert_eq!(detect_x86_constant_return(&bytes), None);
    }

    #[test]
    fn test_detect_arm64_return_constant() {
        // Test ARM64 pattern: movz w0, #2; ret
        // MOVZ w0, #2: 0x52800040 (little-endian: 40 00 80 52)
        // RET: 0xD65F03C0 (little-endian: C0 03 5F D6)
        let bytes = vec![0x40, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];
        assert_eq!(detect_arm64_constant_return(&bytes), Some(2));

        // MOVZ w0, #0: 0x52800000
        let bytes = vec![0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];
        assert_eq!(detect_arm64_constant_return(&bytes), Some(0));
    }

    #[test]
    fn test_stub_analysis_is_stub() {
        // Create a StubAnalysis for a stub function (returns ADBC_STATUS_NOT_IMPLEMENTED)
        let analysis = StubAnalysis {
            symbol_name: "AdbcDatabaseSetOption".to_string(),
            is_stub: true,
            constant_return: Some(2),
            status_code: Some(AdbcStatusCode::NotImplemented),
        };

        assert_eq!(analysis.symbol_name, "AdbcDatabaseSetOption");
        assert!(analysis.is_stub);
        assert_eq!(analysis.constant_return, Some(2));
        assert_eq!(analysis.status_code, Some(AdbcStatusCode::NotImplemented));
    }

    #[test]
    fn test_stub_analysis_not_stub() {
        // Create a StubAnalysis for a non-stub function (returns ADBC_STATUS_OK)
        let analysis = StubAnalysis {
            symbol_name: "AdbcDriverInit".to_string(),
            is_stub: false,
            constant_return: Some(0),
            status_code: Some(AdbcStatusCode::Ok),
        };

        assert_eq!(analysis.symbol_name, "AdbcDriverInit");
        assert!(!analysis.is_stub);
        assert_eq!(analysis.constant_return, Some(0));
        assert_eq!(analysis.status_code, Some(AdbcStatusCode::Ok));
    }
}
