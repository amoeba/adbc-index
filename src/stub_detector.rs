use capstone::prelude::*;
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
                // Map virtual address (st_value) to file offset using section headers
                if let Some(file_offset) = elf_vaddr_to_file_offset(elf, sym.st_value) {
                    let offset = file_offset as usize;
                    let size = sym.st_size as usize;

                    if size > 0 && offset + size <= buffer.len() {
                        let func_bytes = &buffer[offset..offset + size.min(50)];
                        let analysis = analyze_x86_function(name, func_bytes);
                        results.push(analysis);
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Convert ELF virtual address to file offset using section headers
fn elf_vaddr_to_file_offset(elf: &goblin::elf::Elf, vaddr: u64) -> Option<u64> {
    for section in &elf.section_headers {
        // Only consider sections that are loaded into memory (ALLOC flag)
        if section.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0
            && vaddr >= section.sh_addr
            && vaddr < section.sh_addr + section.sh_size
        {
            let offset_in_section = vaddr - section.sh_addr;
            return Some(section.sh_offset + offset_in_section);
        }
    }
    None
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
    let sections: Vec<SectionInfo> = pe
        .sections
        .iter()
        .map(|section| SectionInfo {
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size.min(section.size_of_raw_data),
            pointer_to_raw_data: section.pointer_to_raw_data,
        })
        .collect();

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

    if let goblin::mach::Mach::Binary(macho) = mach {
        for (name, nlist) in macho.symbols().flatten() {
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

    Ok(results)
}

/// Analyze x86/x64 function to detect constant returns using Capstone
fn analyze_x86_function(name: &str, bytes: &[u8]) -> StubAnalysis {
    if bytes.is_empty() {
        return StubAnalysis {
            symbol_name: name.to_string(),
            is_stub: false,
            constant_return: None,
            status_code: None,
        };
    }

    // Try to detect simple constant return patterns using Capstone
    let constant = disassemble_x86_constant_return(bytes);

    let status_code = constant.and_then(AdbcStatusCode::from_i32);
    let is_stub = status_code == Some(AdbcStatusCode::NotImplemented);

    StubAnalysis {
        symbol_name: name.to_string(),
        is_stub,
        constant_return: constant,
        status_code,
    }
}

/// Analyze ARM64 function to detect constant returns using Capstone
fn analyze_arm64_function(name: &str, bytes: &[u8]) -> StubAnalysis {
    if bytes.len() < 8 {
        return StubAnalysis {
            symbol_name: name.to_string(),
            is_stub: false,
            constant_return: None,
            status_code: None,
        };
    }

    let constant = disassemble_arm64_constant_return(bytes);

    let status_code = constant.and_then(AdbcStatusCode::from_i32);
    let is_stub = status_code == Some(AdbcStatusCode::NotImplemented);

    StubAnalysis {
        symbol_name: name.to_string(),
        is_stub,
        constant_return: constant,
        status_code,
    }
}

/// Disassemble x86/x64 function to detect constant return values using Capstone
fn disassemble_x86_constant_return(bytes: &[u8]) -> Option<i32> {
    use std::panic;

    if bytes.is_empty() {
        return None;
    }

    // Catch panics from Capstone FFI calls
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        // Create Capstone disassembler for x86-64
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .ok()?;

        // Disassemble the function
        let insns = cs.disasm_all(bytes, 0x0).ok()?;

        // Look for pattern: mov to return register (eax/rax/al) followed by ret
        let mut last_mov_value: Option<i32> = None;

        for insn in insns.as_ref() {
            let mnemonic = insn.mnemonic().unwrap_or("");

            // Check for XOR eax, eax (returns 0)
            if mnemonic == "xor" {
                if let Ok(detail) = cs.insn_detail(insn) {
                    let arch_detail = detail.arch_detail();
                    let ops = arch_detail.operands();

                    // XOR of same register = 0
                    if ops.len() == 2 {
                        if let (Some(op1), Some(op2)) = (ops.first(), ops.get(1)) {
                            // Check if both operands are the same register (eax, rax, or al)
                            if is_same_x86_register(op1, op2) && is_return_register_x86(op1) {
                                last_mov_value = Some(0);
                            }
                        }
                    }
                }
            }

            // Check for MOV to return register with immediate
            if mnemonic == "mov" || mnemonic == "movzx" {
                if let Ok(detail) = cs.insn_detail(insn) {
                    let arch_detail = detail.arch_detail();
                    let ops = arch_detail.operands();

                    // MOV dst, imm
                    if ops.len() == 2 {
                        if let (Some(op1), Some(op2)) = (ops.first(), ops.get(1)) {
                            // First operand should be a return register (eax, rax, al)
                            if is_return_register_x86(op1) {
                                // Second operand should be an immediate
                                if let capstone::arch::ArchOperand::X86Operand(x86_op) = op2 {
                                    if let capstone::arch::x86::X86OperandType::Imm(imm_val) =
                                        x86_op.op_type
                                    {
                                        last_mov_value = Some(imm_val as i32);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check for RET instruction
            if mnemonic == "ret" {
                return last_mov_value;
            }
        }

        None
    }));

    // If panic occurred or error, return None
    result.ok().flatten()
}

/// Check if an x86 operand is a return register (eax, rax, or al)
fn is_return_register_x86(op: &capstone::arch::ArchOperand) -> bool {
    if let capstone::arch::ArchOperand::X86Operand(x86_op) = op {
        if let capstone::arch::x86::X86OperandType::Reg(reg_id) = x86_op.op_type {
            let reg = reg_id.0 as u32;
            // Check for AL, AX, EAX, RAX
            return reg == capstone::arch::x86::X86Reg::X86_REG_AL
                || reg == capstone::arch::x86::X86Reg::X86_REG_AX
                || reg == capstone::arch::x86::X86Reg::X86_REG_EAX
                || reg == capstone::arch::x86::X86Reg::X86_REG_RAX;
        }
    }
    false
}

/// Check if two x86 operands reference the same register
fn is_same_x86_register(
    op1: &capstone::arch::ArchOperand,
    op2: &capstone::arch::ArchOperand,
) -> bool {
    if let (
        capstone::arch::ArchOperand::X86Operand(x86_op1),
        capstone::arch::ArchOperand::X86Operand(x86_op2),
    ) = (op1, op2)
    {
        if let (
            capstone::arch::x86::X86OperandType::Reg(reg1),
            capstone::arch::x86::X86OperandType::Reg(reg2),
        ) = (&x86_op1.op_type, &x86_op2.op_type)
        {
            return reg1 == reg2;
        }
    }
    false
}

/// Disassemble ARM64 function to detect constant return values using Capstone
fn disassemble_arm64_constant_return(bytes: &[u8]) -> Option<i32> {
    use std::panic;

    if bytes.len() < 8 {
        return None;
    }

    // Catch panics from Capstone FFI calls
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        // Create Capstone disassembler for ARM64
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .ok()?;

        // Disassemble the function
        let insns = cs.disasm_all(bytes, 0x0).ok()?;

        // Look for pattern: mov to return register (w0/x0) followed by ret
        let mut last_mov_value: Option<i32> = None;

        for insn in insns.as_ref() {
            let mnemonic = insn.mnemonic().unwrap_or("");

            // Check for MOV to return register with immediate
            if mnemonic == "mov" || mnemonic == "movz" {
                if let Ok(detail) = cs.insn_detail(insn) {
                    let arch_detail = detail.arch_detail();
                    let ops = arch_detail.operands();

                    // MOV dst, imm
                    if ops.len() == 2 {
                        if let (Some(op1), Some(op2)) = (ops.first(), ops.get(1)) {
                            // First operand should be a return register (w0 or x0)
                            if is_return_register_arm64(op1) {
                                // Second operand should be an immediate
                                if let capstone::arch::ArchOperand::Arm64Operand(arm64_op) = op2 {
                                    if let capstone::arch::arm64::Arm64OperandType::Imm(imm_val) =
                                        arm64_op.op_type
                                    {
                                        last_mov_value = Some(imm_val as i32);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check for MOVN (move NOT) - result is bitwise NOT of immediate
            if mnemonic == "movn" {
                if let Ok(detail) = cs.insn_detail(insn) {
                    let arch_detail = detail.arch_detail();
                    let ops = arch_detail.operands();

                    if ops.len() == 2 {
                        if let (Some(op1), Some(op2)) = (ops.first(), ops.get(1)) {
                            if is_return_register_arm64(op1) {
                                if let capstone::arch::ArchOperand::Arm64Operand(arm64_op) = op2 {
                                    if let capstone::arch::arm64::Arm64OperandType::Imm(imm_val) =
                                        arm64_op.op_type
                                    {
                                        // MOVN stores the bitwise NOT of the immediate
                                        last_mov_value = Some(!imm_val as i32);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check for RET instruction
            if mnemonic == "ret" {
                return last_mov_value;
            }
        }

        None
    }));

    // If panic occurred or error, return None
    result.ok().flatten()
}

/// Check if an ARM64 operand is a return register (w0 or x0)
fn is_return_register_arm64(op: &capstone::arch::ArchOperand) -> bool {
    if let capstone::arch::ArchOperand::Arm64Operand(arm64_op) = op {
        if let capstone::arch::arm64::Arm64OperandType::Reg(reg_id) = arm64_op.op_type {
            let reg = reg_id.0 as u32;
            // Check for W0 or X0
            return reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_W0
                || reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_X0;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_from_i32_valid() {
        // Test valid status codes
        assert_eq!(AdbcStatusCode::from_i32(0), Some(AdbcStatusCode::Ok));
        assert_eq!(
            AdbcStatusCode::from_i32(2),
            Some(AdbcStatusCode::NotImplemented)
        );
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
        assert_eq!(
            AdbcStatusCode::NotImplemented.name(),
            "ADBC_STATUS_NOT_IMPLEMENTED"
        );
        assert_eq!(AdbcStatusCode::Unknown.name(), "ADBC_STATUS_UNKNOWN");
        assert_eq!(AdbcStatusCode::Timeout.name(), "ADBC_STATUS_TIMEOUT");
    }

    #[test]
    fn test_disassemble_x86_return_zero_xor() {
        // Test x86 pattern: xor eax, eax; ret (returns 0)
        // 31 C0 C3
        let bytes = vec![0x31, 0xC0, 0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), Some(0));

        // Alternative encoding: 33 C0 C3
        let bytes = vec![0x33, 0xC0, 0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), Some(0));
    }

    #[test]
    fn test_disassemble_x86_return_constant_mov() {
        // Test x86 pattern: mov eax, 2; ret
        // B8 02 00 00 00 C3
        let bytes = vec![0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), Some(2));

        // Test with different constant
        let bytes = vec![0xB8, 0x0D, 0x00, 0x00, 0x00, 0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), Some(13));
    }

    #[test]
    fn test_disassemble_x86_no_constant_return() {
        // Test complex code that doesn't have a simple constant return
        // This should return None
        let bytes = vec![0x48, 0x89, 0x5C, 0x24, 0x08, 0x57];
        assert_eq!(disassemble_x86_constant_return(&bytes), None);

        // Empty bytes
        assert_eq!(disassemble_x86_constant_return(&[]), None);

        // Just a return without constant setup
        let bytes = vec![0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), None);
    }

    #[test]
    fn test_disassemble_x86_with_endbr64_prefix() {
        // Test Linux pattern with ENDBR64 prefix: endbr64; mov eax, 2; ret
        // F3 0F 1E FA B8 02 00 00 00 C3
        let bytes = vec![0xF3, 0x0F, 0x1E, 0xFA, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), Some(2));

        // Test Linux pattern with ENDBR64 prefix: endbr64; xor eax, eax; ret
        // F3 0F 1E FA 31 C0 C3
        let bytes = vec![0xF3, 0x0F, 0x1E, 0xFA, 0x31, 0xC0, 0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), Some(0));
    }

    #[test]
    fn test_disassemble_x86_8bit_register() {
        // Test Windows pattern: mov al, 2; ret (8-bit register)
        // B0 02 C3
        let bytes = vec![0xB0, 0x02, 0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), Some(2));

        // Test Windows pattern: xor al, al; ret
        // 32 C0 C3
        let bytes = vec![0x32, 0xC0, 0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), Some(0));

        // Test with different constants
        let bytes = vec![0xB0, 0x00, 0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), Some(0));

        let bytes = vec![0xB0, 0x0D, 0xC3];
        assert_eq!(disassemble_x86_constant_return(&bytes), Some(13));
    }

    #[test]
    fn test_disassemble_arm64_return_constant() {
        // Test ARM64 pattern: movz w0, #2; ret
        // MOVZ w0, #2: 0x52800040 (little-endian: 40 00 80 52)
        // RET: 0xD65F03C0 (little-endian: C0 03 5F D6)
        let bytes = vec![0x40, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];
        assert_eq!(disassemble_arm64_constant_return(&bytes), Some(2));

        // MOVZ w0, #0: 0x52800000
        let bytes = vec![0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];
        assert_eq!(disassemble_arm64_constant_return(&bytes), Some(0));
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
