//! # Bitwise Core
//!
//! Tipos fundamentales, parsers de formatos binarios y análisis estructural.
//! Soporta ELF (Linux), PE (Windows) y Mach-O (macOS).

pub mod analysis;
pub mod arch;
pub mod binary;
pub mod error;

use serde::{Deserialize, Serialize};

/// Arquitectura de CPU soportada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    X86,
    X86_64,
    ARM,
    AArch64,
    Mips,
    Mips64,
    PowerPc,
    PowerPc64,
    RiscV32,
    RiscV64,
    Unknown(u16),
}

impl Architecture {
    /// Tamaño de palabra en bytes (4 = 32-bit, 8 = 64-bit).
    pub fn pointer_width(&self) -> u8 {
        match self {
            Self::X86 | Self::ARM | Self::Mips | Self::PowerPc | Self::RiscV32 => 4,
            _ => 8,
        }
    }

    /// Nombre de la ISA para el desensamblador.
    pub fn isa_name(&self) -> &str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86-64",
            Self::ARM => "arm",
            Self::AArch64 => "aarch64",
            Self::Mips | Self::Mips64 => "mips",
            Self::PowerPc | Self::PowerPc64 => "ppc",
            Self::RiscV32 | Self::RiscV64 => "riscv",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// Endianness del binario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

/// Sistema operativo target del binario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Linux,
    Windows,
    MacOS,
    FreeBSD,
    Unknown,
}

/// Sección o segmento de un binario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub permissions: Permissions,
    /// Datos crudos de la sección (perezoso: cargado bajo demanda).
    #[serde(skip)]
    pub data: Option<Vec<u8>>,
}

/// Símbolo (función, variable, etc.) extraído del binario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolKind,
    pub binding: SymbolBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Object,
    Section,
    File,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
}

/// Permisos de memoria: R | W | X.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Permissions {
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    pub const RWX: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
}

/// Resultado del análisis de un binario cargado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub path: String,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub endianness: Endianness,
    pub platform: Platform,
    pub entry_point: Option<u64>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub file_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    ELF,
    PE,
    MachO,
    Raw,
}
