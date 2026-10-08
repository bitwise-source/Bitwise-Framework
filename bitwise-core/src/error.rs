use thiserror::Error;

#[derive(Error, Debug)]
pub enum BitwiseError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Formato no soportado: {0}")]
    UnsupportedFormat(String),

    #[error("Arquitectura no soportada: {0}")]
    UnsupportedArchitecture(String),

    #[error("ELF inválido: {0}")]
    InvalidElf(String),

    #[error("PE inválido: {0}")]
    InvalidPE(String),

    #[error("Mach-O inválido: {0}")]
    InvalidMachO(String),

    #[error("Sección no encontrada: {0}")]
    SectionNotFound(String),

    #[error("Símbolo no encontrado: {0}")]
    SymbolNotFound(String),

    #[error("Dirección fuera de rango: 0x{0:x}")]
    AddressOutOfRange(u64),
}

pub type Result<T> = std::result::Result<T, BitwiseError>;
