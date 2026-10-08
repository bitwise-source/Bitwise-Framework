//! # Bitwise Disassembler
//!
//! Motor de desensamblado multi-arquitectura basado en Capstone.
//! Soporta x86, x86-64, ARM, ARM64, MIPS, PowerPC y RISC-V.

use bitwise_core::arch::Instruction;
use bitwise_core::{Architecture, BinaryInfo};
use capstone::prelude::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DisasmError {
    #[error("Capstone error: {0}")]
    Capstone(#[from] capstone::Error),

    #[error("Arquitectura no soportada: {0:?}")]
    UnsupportedArchitecture(Architecture),
}

pub type Result<T> = std::result::Result<T, DisasmError>;

/// Constructor de desensamblador con configuración de arquitectura.
pub struct Disassembler {
    cs: Capstone,
    architecture: Architecture,
}

impl Disassembler {
    /// Crea un desensamblador para una arquitectura dada.
    pub fn new(arch: Architecture) -> Result<Self> {
        let cs = match arch {
            Architecture::X86 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()?,
            Architecture::X86_64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()?,
            Architecture::ARM => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build()?,
            Architecture::AArch64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()?,
            Architecture::Mips | Architecture::Mips64 => Capstone::new()
                .mips()
                .mode(if matches!(arch, Architecture::Mips64) {
                    arch::mips::ArchMode::Mips64
                } else {
                    arch::mips::ArchMode::Mips32
                })
                .endian(capstone::Endian::Little)
                .detail(true)
                .build()?,
            Architecture::PowerPc | Architecture::PowerPc64 => Capstone::new()
                .ppc()
                .mode(if matches!(arch, Architecture::PowerPc64) {
                    arch::ppc::ArchMode::Mode64
                } else {
                    arch::ppc::ArchMode::Mode32
                })
                .endian(capstone::Endian::Big)
                .detail(true)
                .build()?,
            Architecture::RiscV32 | Architecture::RiscV64 => Capstone::new()
                .riscv()
                .mode(if matches!(arch, Architecture::RiscV64) {
                    arch::riscv::ArchMode::RiscV64
                } else {
                    arch::riscv::ArchMode::RiscV32
                })
                .detail(true)
                .build()?,
            _ => {
                return Err(DisasmError::UnsupportedArchitecture(arch));
            }
        };

        Ok(Self {
            cs,
            architecture: arch,
        })
    }

    /// Crea un desensamblador a partir de la info extraída de un binario.
    pub fn from_binary(info: &BinaryInfo) -> Result<Self> {
        Self::new(info.architecture)
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// Desensambla un rango de bytes.
    pub fn disassemble(&self, code: &[u8], base_address: u64) -> Result<Vec<Instruction>> {
        let insns = self.cs.disasm_all(code, base_address)?;

        Ok(insns
            .iter()
            .map(|insn| Instruction {
                address: insn.address(),
                size: insn.bytes().len() as u8,
                mnemonic: insn.mnemonic().unwrap_or("???").to_string(),
                operands: insn.op_str().unwrap_or("").to_string(),
                bytes: insn.bytes().to_vec(),
            })
            .collect())
    }

    /// Desensambla todas las secciones ejecutables de un binario.
    pub fn disassemble_binary(&self, info: &BinaryInfo) -> Result<Vec<Instruction>> {
        let mut all_insns = Vec::new();

        let raw_data = std::fs::read(&info.path).ok();

        for section in &info.sections {
            // Solo desensamblar secciones ejecutables con datos
            if !section.permissions.execute {
                continue;
            }

            let code = if let Some(data) = raw_data.as_ref() {
                let start = section.raw_offset as usize;
                let end = (start + section.raw_size as usize).min(data.len());
                if start < data.len() {
                    &data[start..end]
                } else {
                    continue;
                }
            } else {
                continue;
            };

            if code.is_empty() {
                continue;
            }

            match self.disassemble(code, section.virtual_address) {
                Ok(insns) => all_insns.extend(insns),
                Err(_) => continue, // skip secciones con datos no válidos como código
            }
        }

        Ok(all_insns)
    }

    /// Desensambla una sola sección por nombre.
    pub fn disassemble_section(
        &self,
        info: &BinaryInfo,
        section_name: &str,
    ) -> Result<Vec<Instruction>> {
        let section = info
            .sections
            .iter()
            .find(|s| s.name == section_name)
            .ok_or_else(|| {
                // Convertir a capstone error (no es ideal, pero mantiene compatibilidad)
                capstone::Error::CustomError("sección no encontrada")
            })?;

        let raw_data = std::fs::read(&info.path)
            .map_err(|_e| capstone::Error::CustomError("I/O error"))?;

        let start = section.raw_offset as usize;
        let end = (start + section.raw_size as usize).min(raw_data.len());
        let code = &raw_data[start..end];

        self.disassemble(code, section.virtual_address)
    }
}

/// Imprime instrucciones desensambladas en formato legible.
pub fn format_instructions(instructions: &[Instruction], show_bytes: bool) -> String {
    let mut output = String::new();
    for insn in instructions {
        if show_bytes {
            let bytes_str: Vec<String> = insn.bytes.iter().map(|b| format!("{:02x}", b)).collect();
            output.push_str(&format!(
                "  {:#018x}  {:20}  {:8}  {}\n",
                insn.address,
                bytes_str.join(" "),
                insn.mnemonic,
                insn.operands,
            ));
        } else {
            output.push_str(&format!(
                "  {:#018x}  {:8}  {}\n",
                insn.address, insn.mnemonic, insn.operands,
            ));
        }
    }
    output
}
