//! Parsers de formatos binarios: ELF, PE, Mach-O, y detección automática.

pub mod elf;
pub mod macho;
pub mod pe;

use crate::error::Result;
use crate::{Architecture, BinaryFormat, BinaryInfo, Endianness, Platform};
use std::path::Path;

/// Detecta el formato de un archivo por sus bytes mágicos.
pub fn detect_format(data: &[u8]) -> Option<BinaryFormat> {
    if data.len() < 4 {
        return None;
    }
    match &data[0..4] {
        [0x7f, b'E', b'L', b'F'] => Some(BinaryFormat::ELF),
        [b'M', b'Z', _, _] => Some(BinaryFormat::PE),
        [0xcf, 0xfa, 0xed, 0xfe] => Some(BinaryFormat::MachO), // 64-bit LE
        [0xfe, 0xed, 0xfa, 0xcf] => Some(BinaryFormat::MachO), // 64-bit BE
        [0xce, 0xfa, 0xed, 0xfe] => Some(BinaryFormat::MachO), // 32-bit LE
        [0xfe, 0xed, 0xfa, 0xce] => Some(BinaryFormat::MachO), // 32-bit BE
        _ => None,
    }
}

/// Carga y analiza un binario, detectando automáticamente el formato.
pub fn load_binary(path: &Path) -> Result<BinaryInfo> {
    let data = std::fs::read(path)?;
    let format = detect_format(&data).unwrap_or(BinaryFormat::Raw);

    match format {
        BinaryFormat::ELF => elf::parse_elf(&data, path),
        BinaryFormat::PE => pe::parse_pe(&data, path),
        BinaryFormat::MachO => macho::parse_macho(&data, path),
        BinaryFormat::Raw => parse_raw(&data, path),
    }
}

/// Carga un archivo como binario raw (sin formato conocido).
fn parse_raw(data: &[u8], path: &Path) -> Result<BinaryInfo> {
    Ok(BinaryInfo {
        path: path.display().to_string(),
        format: BinaryFormat::Raw,
        architecture: Architecture::Unknown(0),
        endianness: Endianness::Little,
        platform: Platform::Unknown,
        entry_point: Some(0),
        sections: vec![],
        symbols: vec![],
        file_size: data.len() as u64,
    })
}
