//! Parser de ELF (Executable and Linkable Format).
//!
//! Soporta ELF32 y ELF64, little/big endian, con tablas de
//! secciones, símbolos, y detección de arquitectura vía e_machine.

use crate::error::{BitwiseError, Result};
use crate::{
    Architecture, BinaryFormat, BinaryInfo, Endianness, Permissions, Platform, Section, Symbol,
    SymbolBinding, SymbolKind,
};
use std::path::Path;

// --- Constantes ELF ---

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

// e_type
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

// e_machine → Architecture
const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_ARM: u16 = 40;
const EM_AARCH64: u16 = 183;
const EM_MIPS: u16 = 8;
const EM_PPC: u16 = 20;
const EM_PPC64: u16 = 21;
const EM_RISCV: u16 = 243;

// p_type
const PT_LOAD: u32 = 1;

// sh_type
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;

// st_info binding
const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

// st_info type
const STT_FUNC: u8 = 2;
const STT_OBJECT: u8 = 1;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;

// sh_flags
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

/// Estructura base para leer números con endianness variable.
struct EndianReader<'a> {
    data: &'a [u8],
    pos: usize,
    is_le: bool,
    is_64: bool,
}

impl<'a> EndianReader<'a> {
    fn new(data: &'a [u8], is_le: bool, is_64: bool) -> Self {
        Self {
            data,
            pos: 0,
            is_le,
            is_64,
        }
    }

    fn seek(&mut self, offset: usize) {
        self.pos = offset;
    }

    fn skip(&mut self, n: usize) {
        self.pos += n;
    }

    fn read_u8(&mut self) -> u8 {
        let v = self.data[self.pos];
        self.pos += 1;
        v
    }

    fn read_u16(&mut self) -> u16 {
        let bytes = [self.data[self.pos], self.data[self.pos + 1]];
        self.pos += 2;
        if self.is_le {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    }

    fn read_u32(&mut self) -> u32 {
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ];
        self.pos += 4;
        if self.is_le {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    }

    fn read_u64(&mut self) -> u64 {
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ];
        self.pos += 8;
        if self.is_le {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        }
    }

    fn read_addr(&mut self) -> u64 {
        if self.is_64 {
            self.read_u64()
        } else {
            self.read_u32() as u64
        }
    }

    fn read_off(&mut self) -> u64 {
        if self.is_64 {
            self.read_u64()
        } else {
            self.read_u32() as u64
        }
    }
}

fn machine_to_arch(machine: u16) -> Architecture {
    match machine {
        EM_386 => Architecture::X86,
        EM_X86_64 => Architecture::X86_64,
        EM_ARM => Architecture::ARM,
        EM_AARCH64 => Architecture::AArch64,
        EM_MIPS => Architecture::Mips,
        EM_PPC => Architecture::PowerPc,
        EM_PPC64 => Architecture::PowerPc64,
        EM_RISCV => Architecture::RiscV32, // podría ser RV64; se refina con la clase
        other => Architecture::Unknown(other),
    }
}

fn sh_flags_to_perms(flags: u64) -> Permissions {
    Permissions {
        read: true, // SHF_ALLOC no es necesario para lectura en análisis
        write: (flags & SHF_WRITE) != 0,
        execute: (flags & SHF_EXECINSTR) != 0,
    }
}

pub fn parse_elf(data: &[u8], path: &Path) -> Result<BinaryInfo> {
    if data.len() < 64 || data[0..4] != ELF_MAGIC {
        return Err(BitwiseError::InvalidElf("magic inválido".into()));
    }

    let class = data[4]; // EI_CLASS
    let data_enc = data[5]; // EI_DATA
    let is_64 = class == ELFCLASS64;
    let is_le = data_enc == ELFDATA2LSB;

    if !is_le && data_enc != ELFDATA2MSB {
        return Err(BitwiseError::InvalidElf("endianness desconocido".into()));
    }

    let mut r = EndianReader::new(data, is_le, is_64);

    // --- ELF Header ---
    r.seek(16);
    let e_type = r.read_u16();
    let e_machine = r.read_u16();
    let _e_version = r.read_u32();
    let e_entry = r.read_addr();
    let e_phoff = r.read_off();
    let e_shoff = r.read_off();
    let _e_flags = r.read_u32();
    let _e_ehsize = r.read_u16();
    let e_phentsize = r.read_u16();
    let e_phnum = r.read_u16();
    let e_shentsize = r.read_u16();
    let e_shnum = r.read_u16();
    let e_shstrndx = r.read_u16();

    let platform = match e_type {
        ET_EXEC | ET_DYN => Platform::Linux,
        _ => Platform::Unknown,
    };

    let mut arch = machine_to_arch(e_machine);
    // Refinar RISC-V: RV32 vs RV64
    if arch == Architecture::RiscV32 && is_64 {
        arch = Architecture::RiscV64;
    }

    // --- Program Headers (segmentos) ---
    let mut sections: Vec<Section> = Vec::new();

    for i in 0..e_phnum as usize {
        let offset = e_phoff as usize + i * e_phentsize as usize;
        if offset + 32 > data.len() {
            break;
        }
        r.seek(offset);

        let p_type = r.read_u32();
        if is_64 {
            let _p_flags = r.read_u32(); // en ELF64 los flags están antes del offset
        }
        let p_offset = r.read_off();
        let p_vaddr = r.read_addr();
        let _p_paddr = r.read_addr();
        let p_filesz = r.read_off();
        let p_memsz = r.read_off();
        let p_flags = if !is_64 { r.read_u32() as u64 } else { 0 };

        if p_type == PT_LOAD && p_filesz > 0 {
            sections.push(Section {
                name: format!("segment_{}", i),
                virtual_address: p_vaddr,
                virtual_size: p_memsz,
                raw_offset: p_offset,
                raw_size: p_filesz,
                permissions: Permissions {
                    read: (p_flags & 4) != 0,
                    write: (p_flags & 2) != 0,
                    execute: (p_flags & 1) != 0,
                },
                data: None, // lazy
            });
        }
    }

    // --- Section Headers ---
    let mut strtab_offset: usize = 0;
    let mut strtab_size: usize = 0;

    // Leer la string table de secciones primero
    if e_shstrndx != 0 && (e_shstrndx as usize) < e_shnum as usize {
        let shdr_size = e_shentsize as usize;
        let strtab_idx = e_shstrndx as usize;
        let sh_offset = e_shoff as usize + strtab_idx * shdr_size;
        if sh_offset + shdr_size <= data.len() {
            r.seek(sh_offset + if is_64 { 24 } else { 16 }); // sh_offset
            strtab_offset = r.read_off() as usize;
            r.seek(sh_offset + if is_64 { 32 } else { 20 }); // sh_size
            strtab_size = r.read_off() as usize;
        }
    }

    // --- Símbolos ---
    let mut symbols: Vec<Symbol> = Vec::new();

    // Leer todas las secciones
    for i in 0..e_shnum as usize {
        let shdr_size = e_shentsize as usize;
        let sh_offset = e_shoff as usize + i * shdr_size;
        if sh_offset + shdr_size > data.len() {
            break;
        }
        r.seek(sh_offset);

        let sh_name_idx = r.read_u32();
        let sh_type = r.read_u32();
        let sh_flags = r.read_off();
        let sh_addr = r.read_addr();
        let sh_offset_data = r.read_off();
        let sh_size = r.read_off();
        let sh_link = r.read_u32();
        let sh_entsize = if is_64 {
            r.read_u64()
        } else {
            r.read_u32() as u64
        };

        // Nombre de sección
        let sec_name = if sh_name_idx > 0 && strtab_offset > 0 {
            read_strtab(data, strtab_offset, strtab_size, sh_name_idx as usize)
                .unwrap_or_else(|| format!("section_{}", i))
        } else {
            format!("section_{}", i)
        };

        // Secciones con datos
        if sh_addr != 0 && sh_size > 0 && sh_offset_data > 0 {
            sections.push(Section {
                name: sec_name.clone(),
                virtual_address: sh_addr,
                virtual_size: sh_size,
                raw_offset: sh_offset_data,
                raw_size: sh_size,
                permissions: sh_flags_to_perms(sh_flags),
                data: None,
            });
        }

        // Símbolos
        if (sh_type == SHT_SYMTAB || sh_type == SHT_DYNSYM) && sh_entsize > 0 {
            let symtab_data_offset = sh_offset_data as usize;
            let sym_count = sh_size as usize / sh_entsize as usize;
            let linked_strtab = sh_link as usize;

            // Leer string table ligada
            let linked_sh_offset = e_shoff as usize + linked_strtab * shdr_size;
            let (linked_str_off, linked_str_size) = if linked_sh_offset + shdr_size <= data.len() {
                r.seek(linked_sh_offset + if is_64 { 24 } else { 16 });
                let lo = r.read_off() as usize;
                r.seek(linked_sh_offset + if is_64 { 32 } else { 20 });
                let ls = r.read_off() as usize;
                (lo, ls)
            } else {
                (0, 0)
            };

            for si in 0..sym_count {
                let sym_off = symtab_data_offset + si * sh_entsize as usize;
                if sym_off + (if is_64 { 24 } else { 16 }) > data.len() {
                    break;
                }
                r.seek(sym_off);

                let st_name = r.read_u32();
                let st_info = if is_64 {
                    r.read_u8()
                } else {
                    let v = r.read_u16() as u8;
                    r.seek(sym_off + 12);
                    v
                };
                let _st_other = r.read_u8();
                let _st_shndx = r.read_u16();
                let st_value = r.read_addr();
                let st_size = if is_64 {
                    r.read_u64()
                } else {
                    r.read_u32() as u64
                };

                let sym_name = read_strtab(data, linked_str_off, linked_str_size, st_name as usize)
                    .unwrap_or_default();

                if st_value == 0 || sym_name.is_empty() {
                    continue;
                }

                let bind = st_info >> 4;
                let stype = st_info & 0xf;

                symbols.push(Symbol {
                    name: sym_name,
                    address: st_value,
                    size: st_size,
                    kind: match stype {
                        STT_FUNC => SymbolKind::Function,
                        STT_OBJECT => SymbolKind::Object,
                        STT_SECTION => SymbolKind::Section,
                        STT_FILE => SymbolKind::File,
                        _ => SymbolKind::Unknown,
                    },
                    binding: match bind {
                        STB_LOCAL => SymbolBinding::Local,
                        STB_WEAK => SymbolBinding::Weak,
                        _ => SymbolBinding::Global,
                    },
                });
            }
        }
    }

    Ok(BinaryInfo {
        path: path.display().to_string(),
        format: BinaryFormat::ELF,
        architecture: arch,
        endianness: if is_le {
            Endianness::Little
        } else {
            Endianness::Big
        },
        platform,
        entry_point: if e_entry != 0 { Some(e_entry) } else { None },
        sections,
        symbols,
        file_size: data.len() as u64,
    })
}

fn read_strtab(data: &[u8], base: usize, size: usize, idx: usize) -> Option<String> {
    if idx >= size {
        return None;
    }
    let start = base + idx;
    if start >= data.len() {
        return None;
    }
    let end = data[start..].iter().position(|&b| b == 0)?;
    let slice = data.get(start..start + end)?;
    String::from_utf8(slice.to_vec()).ok()
}
