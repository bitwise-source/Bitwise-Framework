//! Parser Mach-O — macOS / Darwin.
//!
//! Soporta Mach-O 32/64-bit, FAT binaries, LC_SEGMENT/LC_SYMTAB,
//! y extracción de símbolos exports.

use crate::error::{BitwiseError, Result};
use crate::{
    Architecture, BinaryFormat, BinaryInfo, Endianness, Permissions, Platform, Section, Symbol,
    SymbolBinding, SymbolKind,
};
use std::path::Path;

// --- Magic ---
const MH_MAGIC: u32 = 0xfeedface;
const MH_CIGAM: u32 = 0xcefaedfe;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM_64: u32 = 0xcffaedfe;
const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_CIGAM: u32 = 0xbebafeca;

// --- CPU types ---
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100000c;

// --- File types ---
const MH_EXECUTE: u32 = 2;
const MH_DYLIB: u32 = 6;

// --- Load commands ---
const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_MAIN: u32 = 0x80000028;

// --- Section flags ---
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x80000000;

// --- nlist ---
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x0;

fn cpu_to_arch(cpu_type: u32) -> Architecture {
    match cpu_type {
        CPU_TYPE_X86 => Architecture::X86,
        CPU_TYPE_X86_64 => Architecture::X86_64,
        CPU_TYPE_ARM => Architecture::ARM,
        CPU_TYPE_ARM64 => Architecture::AArch64,
        other => Architecture::Unknown(other as u16),
    }
}

pub fn parse_macho(data: &[u8], path: &Path) -> Result<BinaryInfo> {
    if data.len() < 28 {
        return Err(BitwiseError::InvalidMachO("archivo muy pequeño".into()));
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    // Detectar FAT binary
    if magic == FAT_MAGIC || magic == FAT_CIGAM {
        return parse_fat(data, path);
    }

    let is_le = magic == MH_MAGIC || magic == MH_MAGIC_64;
    let is_64 = magic == MH_MAGIC_64 || magic == MH_CIGAM_64;

    if !is_le && magic != MH_CIGAM && magic != MH_CIGAM_64 {
        return Err(BitwiseError::InvalidMachO(format!(
            "magic desconocido: 0x{:08x}",
            magic
        )));
    }

    parse_thin(data, path, is_le, is_64)
}

fn parse_fat(data: &[u8], path: &Path) -> Result<BinaryInfo> {
    if data.len() < 8 {
        return Err(BitwiseError::InvalidMachO("FAT muy pequeño".into()));
    }

    let nfat_arch = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    // Buscar FAT entry para x86_64 o arm64 (preferimos la nativa)
    for i in 0..nfat_arch.min(16) as usize {
        let entry_off = 8 + i * 20;
        if entry_off + 20 > data.len() {
            break;
        }

        let cpu_type = u32::from_be_bytes([
            data[entry_off],
            data[entry_off + 1],
            data[entry_off + 2],
            data[entry_off + 3],
        ]);
        let offset = u32::from_be_bytes([
            data[entry_off + 8],
            data[entry_off + 9],
            data[entry_off + 10],
            data[entry_off + 11],
        ]) as usize;
        let _size = u32::from_be_bytes([
            data[entry_off + 12],
            data[entry_off + 13],
            data[entry_off + 14],
            data[entry_off + 15],
        ]) as usize;

        match cpu_type {
            CPU_TYPE_X86_64 | CPU_TYPE_ARM64 | CPU_TYPE_ARM => {
                if offset + 28 <= data.len() {
                    let slice = &data[offset..];
                    let magic = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
                    let is_le = magic == MH_MAGIC_64 || magic == MH_MAGIC;
                    let is_64 = magic == MH_MAGIC_64 || magic == MH_CIGAM_64;

                    let mut info = parse_thin(slice, path, is_le, is_64)?;
                    info.path = format!("{} [FAT slice {}]", path.display(), i);
                    return Ok(info);
                }
            }
            _ => {}
        }
    }

    // Fallback: primer slice
    let entry_off = 8;
    let offset = u32::from_be_bytes([
        data[entry_off + 8],
        data[entry_off + 9],
        data[entry_off + 10],
        data[entry_off + 11],
    ]) as usize;
    if offset + 28 <= data.len() {
        let slice = &data[offset..];
        let magic = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
        let is_le = magic == MH_MAGIC_64 || magic == MH_MAGIC;
        let is_64 = magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
        return parse_thin(slice, path, is_le, is_64);
    }

    Err(BitwiseError::InvalidMachO("FAT sin slices válidos".into()))
}

fn parse_thin(data: &[u8], path: &Path, is_le: bool, is_64: bool) -> Result<BinaryInfo> {
    let read_u32 = |off: usize| -> u32 {
        let bytes = [data[off], data[off + 1], data[off + 2], data[off + 3]];
        if is_le {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    let read_u64 = |off: usize| -> u64 {
        let bytes = [
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ];
        if is_le {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        }
    };

    let cpu_type = read_u32(4);
    let _cpu_subtype = read_u32(8);
    let filetype = read_u32(12);
    let ncmds = read_u32(16);
    let sizeofcmds = read_u32(20);

    let arch = cpu_to_arch(cpu_type);

    let platform = match filetype {
        MH_EXECUTE | MH_DYLIB => Platform::MacOS,
        _ => Platform::Unknown,
    };

    let mut entry_point: Option<u64> = None;
    let mut sections: Vec<Section> = Vec::new();
    let mut symbols: Vec<Symbol> = Vec::new();

    let mut symtab_off: u32 = 0;
    let mut symtab_nsyms: u32 = 0;
    let mut strtab_off: u32 = 0;
    let mut strtab_size: u32 = 0;

    let hdr_size = if is_64 { 32 } else { 28 };
    let mut cmd_off = hdr_size;

    for _ in 0..ncmds {
        if cmd_off + 8 > data.len() {
            break;
        }

        let cmd = read_u32(cmd_off);
        let cmdsize = read_u32(cmd_off + 4) as usize;
        if cmdsize < 8 || cmd_off + cmdsize > data.len() {
            break;
        }

        match cmd {
            LC_MAIN => {
                let ep_off = read_u64(cmd_off + 8);
                entry_point = Some(ep_off);
            }
            LC_SEGMENT | LC_SEGMENT_64 => {
                let segname = String::from_utf8_lossy(&data[cmd_off + 8..cmd_off + 24])
                    .trim_end_matches('\0')
                    .to_string();

                let (vmaddr, vmsize, fileoff, filesize, nsects) = if cmd == LC_SEGMENT_64 {
                    let vmaddr = read_u64(cmd_off + 24);
                    let vmsize = read_u64(cmd_off + 32);
                    let fileoff = read_u64(cmd_off + 40);
                    let filesize = read_u64(cmd_off + 48);
                    let nsects = read_u32(cmd_off + 64);
                    (vmaddr, vmsize, fileoff, filesize, nsects)
                } else {
                    let vmaddr = read_u32(cmd_off + 24) as u64;
                    let vmsize = read_u32(cmd_off + 28) as u64;
                    let fileoff = read_u32(cmd_off + 32) as u64;
                    let filesize = read_u32(cmd_off + 36) as u64;
                    let nsects = read_u32(cmd_off + 48);
                    (vmaddr, vmsize, fileoff, filesize, nsects)
                };

                let sec_hdr_size = if cmd == LC_SEGMENT_64 { 80 } else { 68 };
                let mut sec_off = cmd_off + if cmd == LC_SEGMENT_64 { 72 } else { 56 };

                for _ in 0..nsects {
                    if sec_off + sec_hdr_size > data.len() {
                        break;
                    }

                    let secname = String::from_utf8_lossy(&data[sec_off..sec_off + 16])
                        .trim_end_matches('\0')
                        .to_string();

                    let (sec_addr, sec_size, sec_offset) = if cmd == LC_SEGMENT_64 {
                        let addr = read_u64(sec_off + 32);
                        let size = read_u64(sec_off + 40);
                        let offset = read_u32(sec_off + 48) as u64;
                        (addr, size, offset)
                    } else {
                        let addr = read_u32(sec_off + 32) as u64;
                        let size = read_u32(sec_off + 36) as u64;
                        let offset = read_u32(sec_off + 40) as u64;
                        (addr, size, offset)
                    };

                    let flags = read_u32(sec_off + if cmd == LC_SEGMENT_64 { 56 } else { 44 });

                    let is_exec = (flags & S_ATTR_PURE_INSTRUCTIONS) != 0;

                    if sec_size > 0 && sec_offset > 0 {
                        sections.push(Section {
                            name: format!("{}.{}", segname, secname),
                            virtual_address: sec_addr,
                            virtual_size: sec_size,
                            raw_offset: sec_offset,
                            raw_size: sec_size,
                            permissions: Permissions {
                                read: true,
                                write: false,
                                execute: is_exec,
                            },
                            data: None,
                        });
                    }

                    sec_off += sec_hdr_size;
                }
            }
            LC_SYMTAB => {
                symtab_off = read_u32(cmd_off + 8);
                symtab_nsyms = read_u32(cmd_off + 12);
                strtab_off = read_u32(cmd_off + 16);
                strtab_size = read_u32(cmd_off + 20);
            }
            _ => {}
        }

        cmd_off += cmdsize;
    }

    // Parsear tabla de símbolos (nlist)
    if symtab_off > 0 && symtab_nsyms > 0 && strtab_off > 0 {
        let nlist_size = if is_64 { 16 } else { 12 };
        for i in 0..symtab_nsyms as usize {
            let sym_off = symtab_off as usize + i * nlist_size;
            if sym_off + nlist_size > data.len() {
                break;
            }

            let n_strx = read_u32(sym_off);
            let n_type = data[sym_off + 4];
            let _n_sect = data[sym_off + 5];
            let _n_desc = u16::from_le_bytes([data[sym_off + 6], data[sym_off + 7]]);
            let n_value = if is_64 {
                read_u64(sym_off + 8)
            } else {
                read_u32(sym_off + 8) as u64
            };

            // Skip stabs y símbolos undefined
            if (n_type & N_STAB) != 0 {
                continue;
            }
            if (n_type & N_TYPE) == N_UNDF {
                continue;
            }

            let is_global = (n_type & N_EXT) != 0;

            // Leer nombre
            let name = if n_strx > 0 {
                let str_start = strtab_off as usize + n_strx as usize;
                if str_start < data.len() {
                    read_cstr(data, str_start).unwrap_or_default()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            if name.is_empty() || n_value == 0 {
                continue;
            }

            let is_func = name.starts_with('_');

            symbols.push(Symbol {
                name,
                address: n_value,
                size: 0,
                kind: if is_func {
                    SymbolKind::Function
                } else {
                    SymbolKind::Object
                },
                binding: if is_global {
                    SymbolBinding::Global
                } else {
                    SymbolBinding::Local
                },
            });
        }
    }

    Ok(BinaryInfo {
        path: path.display().to_string(),
        format: BinaryFormat::MachO,
        architecture: arch,
        endianness: if is_le {
            Endianness::Little
        } else {
            Endianness::Big
        },
        platform,
        entry_point,
        sections,
        symbols,
        file_size: data.len() as u64,
    })
}

fn read_cstr(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..].iter().position(|&b| b == 0)?;
    String::from_utf8(data[offset..offset + end].to_vec()).ok()
}
