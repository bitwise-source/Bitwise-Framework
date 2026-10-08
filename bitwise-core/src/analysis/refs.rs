//! Extracción de strings y referencias cruzadas (xrefs).

use crate::arch::Instruction;
use std::collections::BTreeMap;

/// Un string encontrado en el binario.
#[derive(Debug, Clone)]
pub struct FoundString {
    pub address: u64,
    pub length: usize,
    pub value: String,
    /// Sección donde se encontró
    pub section: String,
}

/// Extrae strings ASCII imprimibles de longitud mínima `min_len`.
pub fn extract_strings(data: &[u8], base_address: u64, section: &str, min_len: usize) -> Vec<FoundString> {
    let mut results = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&b);
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else {
            if let Some(s) = start.take() {
                if i - s >= min_len {
                    let value = String::from_utf8_lossy(&data[s..i]).to_string();
                    results.push(FoundString {
                        address: base_address + s as u64,
                        length: i - s,
                        value,
                        section: section.to_string(),
                    });
                }
            }
        }
    }
    // string al final del buffer
    if let Some(s) = start {
        if data.len() - s >= min_len {
            let value = String::from_utf8_lossy(&data[s..]).to_string();
            results.push(FoundString {
                address: base_address + s as u64,
                length: data.len() - s,
                value,
                section: section.to_string(),
            });
        }
    }

    results
}

/// Extrae strings de todas las secciones con datos de un binario.
pub fn extract_strings_from_binary(
    info: &crate::BinaryInfo,
    min_len: usize,
) -> std::io::Result<Vec<FoundString>> {
    let raw = std::fs::read(&info.path)?;
    let mut all = Vec::new();

    for sec in &info.sections {
        let start = sec.raw_offset as usize;
        let end = (start + sec.raw_size as usize).min(raw.len());
        if start >= raw.len() {
            continue;
        }
        all.extend(extract_strings(&raw[start..end], sec.virtual_address, &sec.name, min_len));
    }

    Ok(all)
}

/// Referencia a una dirección.
#[derive(Debug, Clone)]
pub struct Xref {
    pub from_address: u64,
    pub to_address: u64,
    pub kind: XrefKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    Jump,
    Data,
}

impl std::fmt::Display for XrefKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XrefKind::Call => write!(f, "CALL"),
            XrefKind::Jump => write!(f, "JUMP"),
            XrefKind::Data => write!(f, "DATA"),
        }
    }
}

/// Construye la tabla de xrefs escaneando instrucciones con operandos de dirección.
pub fn build_xrefs(instructions: &[Instruction]) -> BTreeMap<u64, Vec<Xref>> {
    let mut table: BTreeMap<u64, Vec<Xref>> = BTreeMap::new();

    for insn in instructions {
        let kind = if insn.mnemonic == "call" {
            Some(XrefKind::Call)
        } else if insn.mnemonic.starts_with('j') || insn.mnemonic == "b" || insn.mnemonic.starts_with("b.")
        {
            Some(XrefKind::Jump)
        } else if insn.operands.contains("0x") {
            Some(XrefKind::Data)
        } else {
            None
        };

        let Some(kind) = kind else { continue };

        // extraer direcciones hex de los operandos
        for part in insn.operands.split(|c: char| c == ',' || c == ' ') {
            if let Some(hex) = part.trim().strip_prefix("0x") {
                if let Ok(addr) = u64::from_str_radix(hex, 16) {
                    // filtrar inmediatos pequeños (no direcciones)
                    if addr >= 0x1000 {
                        table.entry(addr).or_default().push(Xref {
                            from_address: insn.address,
                            to_address: addr,
                            kind,
                        });
                    }
                }
            }
        }
    }

    table
}

/// Devuelve todas las referencias QUE APUNTAN a `addr`.
pub fn xrefs_to(table: &BTreeMap<u64, Vec<Xref>>, addr: u64) -> Vec<&Xref> {
    table.get(&addr).map(|v| v.iter().collect()).unwrap_or_default()
}
