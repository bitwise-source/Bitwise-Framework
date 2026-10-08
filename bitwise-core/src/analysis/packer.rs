//! # Detección de packers y ofuscación
//!
//! Identifica binarios empaquetados (UPX, ASPack, MPRESS, etc.) por:
//!  - Firmas de strings ("UPX!", "ASPack", "MPRESS")
//!  - Entropía de Shannon (packers comprimen → entropía ~7.9)
//!  - Sección con `VirtualSize >> RawSize` (UPX expande in-place)
//!
//! Output:
//!   - Score 0..1 (probabilidad de packing)
//!   - Lista de matches con nombre del packer y offset

use crate::BinaryInfo;
use std::collections::HashSet;

const SIGNATURES: &[(&str, &[u8])] = &[
    ("UPX", b"UPX!"),
    ("UPX", b"$Info: This file is packed with the UPX executable packer"),
    ("UPX", b"$Id: UPX"),
    ("ASPack", b"ASPACK"),
    ("ASPack", b".aspack"),
    ("MPRESS", b"MPRESS"),
    ("MPRESS", b".MPRESS1"),
    ("PEtite", b"petite"),
    ("UPack", b"UPack"),
    ("NsPack", b"NsPack"),
    ("Kkrunchy", b"kkrunchy"),
    ("Themida", b"Themida"),
];

/// Score de entropía de Shannon (0..8). Más alto = más comprimido/cifrado.
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f32;
    let mut h = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f32 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Resultado de un análisis de packing.
#[derive(Debug, Clone)]
pub struct PackerMatch {
    pub name: String,
    pub offset: usize,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct PackerReport {
    pub is_likely_packed: bool,
    pub score: f32, // 0..1
    pub entropy: f32,
    pub anomaly_vs_raw: bool,
    pub matches: Vec<PackerMatch>,
}

pub fn analyze(info: &BinaryInfo) -> PackerReport {
    let raw = match std::fs::read(&info.path) {
        Ok(r) => r,
        Err(_) => {
            return PackerReport {
                is_likely_packed: false,
                score: 0.0,
                entropy: 0.0,
                anomaly_vs_raw: false,
                matches: vec![],
            }
        }
    };

    // firmas
    let mut matches = Vec::new();
    for (name, sig) in SIGNATURES {
        let mut start = 0;
        while let Some(p) = find_subslice(&raw[start..], sig) {
            matches.push(PackerMatch {
                name: name.to_string(),
                offset: start + p,
                signature: String::from_utf8_lossy(sig).to_string(),
            });
            start += p + sig.len();
            if matches.len() > 32 {
                break;
            }
        }
    }

    // entropía global
    let entropy = shannon_entropy(&raw);

    // heurística: VS > RS en alguna sección ejecutable
    let mut anomaly_vs_raw = false;
    for sec in &info.sections {
        if sec.permissions.execute && sec.virtual_size > 0 && sec.raw_size > 0 {
            if sec.virtual_size > sec.raw_size * 2 {
                anomaly_vs_raw = true;
            }
        }
    }

    // score combinado
    let has_sig = !matches.is_empty();
    let high_entropy = entropy > 7.5;
    let anom = anomaly_vs_raw;
    let mut score = 0.0;
    if has_sig {
        score += 0.7;
    }
    if high_entropy {
        score += 0.25;
    }
    if anom {
        score += 0.15;
    }
    if score > 1.0 {
        score = 1.0;
    }

    PackerReport {
        is_likely_packed: score >= 0.5,
        score,
        entropy,
        anomaly_vs_raw,
        matches,
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let mut seen: HashSet<u8> = HashSet::new();
    for &b in needle {
        seen.insert(b);
    }
    for i in 0..=(hay.len() - needle.len()) {
        let window = &hay[i..i + needle.len()];
        if window.iter().all(|&b| seen.contains(&b)) && window == needle {
            return Some(i);
        }
    }
    None
}

/// Reescribe bytes del binario en disco. Crea backup .bak si `backup` es true.
pub fn patch_bytes(
    info: &BinaryInfo,
    patches: &[(u64, Vec<u8>)],
    backup: bool,
) -> std::io::Result<()> {
    if backup {
        let backup_path = format!("{}.bak", info.path);
        std::fs::copy(&info.path, &backup_path)?;
    }

    let mut data = std::fs::read(&info.path)?;
    for (offset, bytes) in patches {
        let off = *offset as usize;
        if off + bytes.len() > data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "patch offset {:#x}+{} exceeds file size {}",
                    off,
                    bytes.len(),
                    data.len()
                ),
            ));
        }
        data[off..off + bytes.len()].copy_from_slice(bytes);
    }
    std::fs::write(&info.path, &data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_zero_for_uniform() {
        let data = vec![0u8; 1000];
        assert!(shannon_entropy(&data) < 0.01);
    }

    #[test]
    fn entropy_max_for_random() {
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let h = shannon_entropy(&data);
        assert!(h > 7.9);
    }

    #[test]
    fn find_substr() {
        assert_eq!(find_subslice(b"hello world", b"world"), Some(6));
        assert_eq!(find_subslice(b"hello", b"bye"), None);
    }
}
