//! Parser PE (Portable Executable) — Windows.
//!
//! Soporta PE32 y PE32+, imports/exports, secciones y recursos.

use crate::error::{BitwiseError, Result};
use crate::{
    Architecture, BinaryFormat, BinaryInfo, Endianness, Permissions, Platform, Section, Symbol,
    SymbolBinding, SymbolKind,
};
use std::path::Path;

// --- DOS Header ---
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"

// --- PE Signature ---
const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

// --- Machine types ---
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;

// --- Section flags ---
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

// --- Data directories ---
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

// --- Symbol types ---
const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
const IMAGE_SYM_CLASS_STATIC: u8 = 3;
const IMAGE_SYM_CLASS_FUNCTION: u8 = 101;

fn machine_to_arch(machine: u16) -> Architecture {
    match machine {
        IMAGE_FILE_MACHINE_I386 => Architecture::X86,
        IMAGE_FILE_MACHINE_AMD64 => Architecture::X86_64,
        IMAGE_FILE_MACHINE_ARM | IMAGE_FILE_MACHINE_ARMNT => Architecture::ARM,
        IMAGE_FILE_MACHINE_ARM64 => Architecture::AArch64,
        other => Architecture::Unknown(other),
    }
}

fn section_flags_to_perms(characteristics: u32) -> Permissions {
    Permissions {
        read: (characteristics & IMAGE_SCN_MEM_READ) != 0,
        write: (characteristics & IMAGE_SCN_MEM_WRITE) != 0,
        execute: (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0,
    }
}

pub fn parse_pe(data: &[u8], path: &Path) -> Result<BinaryInfo> {
    if data.len() < 64 {
        return Err(BitwiseError::InvalidPE("archivo muy pequeño".into()));
    }

    // Validar DOS signature
    let dos_sig = u16::from_le_bytes([data[0], data[1]]);
    if dos_sig != IMAGE_DOS_SIGNATURE {
        return Err(BitwiseError::InvalidPE("signature MZ inválida".into()));
    }

    // e_lfanew (offset al PE header) está en offset 0x3C
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_offset + 4 > data.len() {
        return Err(BitwiseError::InvalidPE("e_lfanew fuera de rango".into()));
    }

    // PE Signature
    let pe_sig = u32::from_le_bytes([
        data[pe_offset],
        data[pe_offset + 1],
        data[pe_offset + 2],
        data[pe_offset + 3],
    ]);
    if pe_sig != IMAGE_NT_SIGNATURE {
        return Err(BitwiseError::InvalidPE("signature PE inválida".into()));
    }

    let coff_offset = pe_offset + 4;
    let opt_offset = coff_offset + 20;

    // COFF Header
    let machine = u16::from_le_bytes([data[coff_offset], data[coff_offset + 1]]);
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]);
    let size_opt_header = u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]);

    let arch = machine_to_arch(machine);
    let is_64 = machine == IMAGE_FILE_MACHINE_AMD64 || machine == IMAGE_FILE_MACHINE_ARM64;

    // Optional Header
    let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    let is_pe32plus = magic == 0x20b;

    let entry_point = if is_pe32plus {
        u32::from_le_bytes([
            data[opt_offset + 16],
            data[opt_offset + 17],
            data[opt_offset + 18],
            data[opt_offset + 19],
        ]) as u64
    } else {
        u32::from_le_bytes([
            data[opt_offset + 16],
            data[opt_offset + 17],
            data[opt_offset + 18],
            data[opt_offset + 19],
        ]) as u64
    };

    let image_base = if is_pe32plus {
        u64::from_le_bytes([
            data[opt_offset + 24],
            data[opt_offset + 25],
            data[opt_offset + 26],
            data[opt_offset + 27],
            data[opt_offset + 28],
            data[opt_offset + 29],
            data[opt_offset + 30],
            data[opt_offset + 31],
        ])
    } else {
        u32::from_le_bytes([
            data[opt_offset + 28],
            data[opt_offset + 29],
            data[opt_offset + 30],
            data[opt_offset + 31],
        ]) as u64
    };

    // Data directories
    let data_dir_offset = opt_offset + if is_pe32plus { 112 } else { 96 };
    let num_data_dirs = u32::from_le_bytes([
        data[data_dir_offset - 4],
        data[data_dir_offset - 3],
        data[data_dir_offset - 2],
        data[data_dir_offset - 1],
    ]) as usize;

    let mut export_rva: u32 = 0;
    let mut export_size: u32 = 0;
    let mut import_rva: u32 = 0;
    let mut _import_size: u32 = 0;

    if IMAGE_DIRECTORY_ENTRY_EXPORT < num_data_dirs {
        let ed = data_dir_offset + IMAGE_DIRECTORY_ENTRY_EXPORT * 8;
        export_rva = u32::from_le_bytes([data[ed], data[ed + 1], data[ed + 2], data[ed + 3]]);
        export_size = u32::from_le_bytes([data[ed + 4], data[ed + 5], data[ed + 6], data[ed + 7]]);
    }
    if IMAGE_DIRECTORY_ENTRY_IMPORT < num_data_dirs {
        let id = data_dir_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
        import_rva = u32::from_le_bytes([data[id], data[id + 1], data[id + 2], data[id + 3]]);
        _import_size = u32::from_le_bytes([data[id + 4], data[id + 5], data[id + 6], data[id + 7]]);
    }

    // --- Secciones ---
    let section_offset = opt_offset + size_opt_header as usize;
    let mut sections: Vec<Section> = Vec::new();

    for i in 0..num_sections as usize {
        let sec_off = section_offset + i * 40;
        if sec_off + 40 > data.len() {
            break;
        }

        let name_bytes = &data[sec_off..sec_off + 8];
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_len]).to_string();

        let virtual_size = u32::from_le_bytes([
            data[sec_off + 8],
            data[sec_off + 9],
            data[sec_off + 10],
            data[sec_off + 11],
        ]);
        let virtual_address = u32::from_le_bytes([
            data[sec_off + 12],
            data[sec_off + 13],
            data[sec_off + 14],
            data[sec_off + 15],
        ]);
        let size_raw_data = u32::from_le_bytes([
            data[sec_off + 16],
            data[sec_off + 17],
            data[sec_off + 18],
            data[sec_off + 19],
        ]);
        let ptr_raw_data = u32::from_le_bytes([
            data[sec_off + 20],
            data[sec_off + 21],
            data[sec_off + 22],
            data[sec_off + 23],
        ]);
        let characteristics = u32::from_le_bytes([
            data[sec_off + 36],
            data[sec_off + 37],
            data[sec_off + 38],
            data[sec_off + 39],
        ]);

        if ptr_raw_data > 0 {
            sections.push(Section {
                name,
                virtual_address: image_base + virtual_address as u64,
                virtual_size: virtual_size as u64,
                raw_offset: ptr_raw_data as u64,
                raw_size: size_raw_data as u64,
                permissions: section_flags_to_perms(characteristics),
                data: None,
            });
        }
    }

    // --- Símbolos: exports ---
    let mut symbols: Vec<Symbol> = Vec::new();

    if export_rva > 0 && export_size > 0 {
        if let Some(export_names) = parse_exports(data, export_rva, image_base) {
            symbols.extend(export_names);
        }
    }

    // --- Símbolos: imports ---
    if import_rva > 0 {
        if let Some(import_names) = parse_imports(data, import_rva, image_base, is_64) {
            symbols.extend(import_names);
        }
    }

    Ok(BinaryInfo {
        path: path.display().to_string(),
        format: BinaryFormat::PE,
        architecture: arch,
        endianness: Endianness::Little,
        platform: Platform::Windows,
        entry_point: if entry_point > 0 {
            Some(image_base + entry_point)
        } else {
            None
        },
        sections,
        symbols,
        file_size: data.len() as u64,
    })
}

/// Convierte un RVA a offset en archivo usando las secciones ya parseadas.
fn rva_to_offset(data: &[u8], rva: u32, image_base: u64) -> Option<usize> {
    // Simplificado: buscar en los section headers raw
    // Versión completa necesitaría re-parser secciones; aquí usamos búsqueda directa
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let coff_offset = pe_offset + 4;
    let opt_offset = coff_offset + 20;
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]);
    let size_opt_header = u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]);
    let section_offset = opt_offset + size_opt_header as usize;

    for i in 0..num_sections as usize {
        let sec_off = section_offset + i * 40;
        if sec_off + 40 > data.len() {
            break;
        }
        let sec_va = u32::from_le_bytes([
            data[sec_off + 12],
            data[sec_off + 13],
            data[sec_off + 14],
            data[sec_off + 15],
        ]);
        let sec_raw = u32::from_le_bytes([
            data[sec_off + 20],
            data[sec_off + 21],
            data[sec_off + 22],
            data[sec_off + 23],
        ]);
        let sec_size = u32::from_le_bytes([
            data[sec_off + 16],
            data[sec_off + 17],
            data[sec_off + 18],
            data[sec_off + 19],
        ]);

        if rva >= sec_va && rva < sec_va + sec_size {
            return Some((sec_raw + (rva - sec_va)) as usize);
        }
    }
    None
}

fn parse_exports(data: &[u8], export_rva: u32, image_base: u64) -> Option<Vec<Symbol>> {
    let offset = rva_to_offset(data, export_rva, image_base)?;
    if offset + 40 > data.len() {
        return None;
    }

    let _flags = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    let name_rva = u32::from_le_bytes([
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    ]);
    let ordinal_base = u32::from_le_bytes([
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    ]);
    let num_functions = u32::from_le_bytes([
        data[offset + 20],
        data[offset + 21],
        data[offset + 22],
        data[offset + 23],
    ]);
    let num_names = u32::from_le_bytes([
        data[offset + 24],
        data[offset + 25],
        data[offset + 26],
        data[offset + 27],
    ]);
    let addr_rva = u32::from_le_bytes([
        data[offset + 28],
        data[offset + 29],
        data[offset + 30],
        data[offset + 31],
    ]);
    let name_ptr_rva = u32::from_le_bytes([
        data[offset + 32],
        data[offset + 33],
        data[offset + 34],
        data[offset + 35],
    ]);
    let ordinal_rva = u32::from_le_bytes([
        data[offset + 36],
        data[offset + 37],
        data[offset + 38],
        data[offset + 39],
    ]);

    let name_ptr_off = rva_to_offset(data, name_ptr_rva, image_base)?;
    let ordinal_off = rva_to_offset(data, ordinal_rva, image_base)?;
    let addr_off = rva_to_offset(data, addr_rva, image_base)?;

    let dll_name = if name_rva > 0 {
        rva_to_offset(data, name_rva, image_base)
            .and_then(|o| read_cstr(data, o))
            .unwrap_or_default()
    } else {
        String::new()
    };

    let mut symbols = Vec::new();

    for i in 0..num_names as usize {
        let name_ptr_pos = name_ptr_off + i * 4;
        let ord_pos = ordinal_off + i * 2;
        if name_ptr_pos + 4 > data.len() || ord_pos + 2 > data.len() {
            break;
        }

        let sym_name_rva = u32::from_le_bytes([
            data[name_ptr_pos],
            data[name_ptr_pos + 1],
            data[name_ptr_pos + 2],
            data[name_ptr_pos + 3],
        ]);
        let ordinal_idx = u16::from_le_bytes([data[ord_pos], data[ord_pos + 1]]) as usize;
        let addr_pos = addr_off + ordinal_idx * 4;
        if addr_pos + 4 > data.len() {
            continue;
        }

        let func_rva = u32::from_le_bytes([
            data[addr_pos],
            data[addr_pos + 1],
            data[addr_pos + 2],
            data[addr_pos + 3],
        ]);

        if let Some(sym_name) =
            rva_to_offset(data, sym_name_rva, image_base).and_then(|o| read_cstr(data, o))
        {
            let full_name = if dll_name.is_empty() {
                sym_name
            } else {
                format!("{}!{}", dll_name, sym_name)
            };
            symbols.push(Symbol {
                name: full_name,
                address: image_base + func_rva as u64,
                size: 0,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
            });
        }
    }

    Some(symbols)
}

fn parse_imports(
    data: &[u8],
    import_rva: u32,
    image_base: u64,
    is_64: bool,
) -> Option<Vec<Symbol>> {
    let offset = rva_to_offset(data, import_rva, image_base)?;
    let mut symbols = Vec::new();
    let mut pos = offset;

    // Tamaño de IMAGE_IMPORT_DESCRIPTOR: 20 bytes
    loop {
        if pos + 20 > data.len() {
            break;
        }

        let name_rva = u32::from_le_bytes([
            data[pos + 12],
            data[pos + 13],
            data[pos + 14],
            data[pos + 15],
        ]);
        if name_rva == 0 {
            break;
        } // terminador

        let iat_rva = u32::from_le_bytes([
            data[pos + 16],
            data[pos + 17],
            data[pos + 18],
            data[pos + 19],
        ]);

        let dll_name = rva_to_offset(data, name_rva, image_base)
            .and_then(|o| read_cstr(data, o))
            .unwrap_or_default();

        // Leer thunks (IAT)
        if let Some(iat_off) = rva_to_offset(data, iat_rva, image_base) {
            let mut thunk_pos = iat_off;
            let entry_size = if is_64 { 8 } else { 4 };
            loop {
                if thunk_pos + entry_size > data.len() {
                    break;
                }
                let thunk_val = if is_64 {
                    u64::from_le_bytes([
                        data[thunk_pos],
                        data[thunk_pos + 1],
                        data[thunk_pos + 2],
                        data[thunk_pos + 3],
                        data[thunk_pos + 4],
                        data[thunk_pos + 5],
                        data[thunk_pos + 6],
                        data[thunk_pos + 7],
                    ])
                } else {
                    u32::from_le_bytes([
                        data[thunk_pos],
                        data[thunk_pos + 1],
                        data[thunk_pos + 2],
                        data[thunk_pos + 3],
                    ]) as u64
                };

                if thunk_val == 0 {
                    break;
                }

                // Bit alto indica import por ordinal
                let is_ordinal = if is_64 {
                    (thunk_val >> 63) != 0
                } else {
                    (thunk_val >> 31) != 0
                };

                if !is_ordinal {
                    let hint_name_rva = (thunk_val & 0x7FFFFFFF) as u32;
                    if let Some(hint_off) = rva_to_offset(data, hint_name_rva, image_base) {
                        // Skip hint (2 bytes), read name
                        if let Some(name) = read_cstr(data, hint_off + 2) {
                            let full_name = format!("{}!{}", dll_name, name);
                            symbols.push(Symbol {
                                name: full_name,
                                address: 0, // imports no tienen dirección fija
                                size: 0,
                                kind: SymbolKind::Function,
                                binding: SymbolBinding::Global,
                            });
                        }
                    }
                }

                thunk_pos += entry_size;
            }
        }

        pos += 20;
    }

    Some(symbols)
}

fn read_cstr(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..].iter().position(|&b| b == 0)?;
    String::from_utf8(data[offset..offset + end].to_vec()).ok()
}
