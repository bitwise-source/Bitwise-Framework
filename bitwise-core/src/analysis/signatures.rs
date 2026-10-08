//! # Firmas de funciones (style FLIRT)
//!
//! Motor de matching de funciones por patrón de bytes con wildcards.
//! Similar al Function ID de Ghidra pero simplificado: en vez de árboles
//! de decisión sobre bytes normalizados, usa patrones directos con
//! `??` como byte ignorado.
//!
//! Formato de firma (JSON o built-in):
//! ```json
//! {
//!   "name": "strlen",
//!   "pattern": "554889e5488b07 80 38 00 74 ?? 48ffc0 ebf?"
//! }
//! ```
//! Espacios separan bytes; `??` es wildcard.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub name: String,
    /// patrón en texto hex, `??` = wildcard, espacios/`_` ignorados
    pub pattern: String,
    /// longitud mínima del patrón (sin wildcards) para aceptar el match
    #[serde(default = "default_min_solid")]
    pub min_solid: usize,
}

fn default_min_solid() -> usize {
    6
}

impl Signature {
    /// Compila el patrón a bytes: `(Some(byte), is_wildcard)`.
    pub fn compile(pattern: &str) -> Vec<(Option<u8>, bool)> {
        let cleaned: String = pattern
            .chars()
            .filter(|c| c.is_ascii_hexdigit() || *c == '?')
            .collect();

        let mut out = Vec::new();
        let mut i = 0;
        let bytes = cleaned.as_bytes();
        while i < bytes.len() {
            if bytes[i] == b'?' {
                // wildcard: ?? (dos '?')
                if i + 1 < bytes.len() && bytes[i + 1] == b'?' {
                    out.push((None, true));
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            // byte hex
            if i + 1 < bytes.len() {
                let hex = &cleaned[i..i + 2];
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push((Some(b), false));
                    i += 2;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        out
    }

    /// Fuerza el match contra un slice de bytes (debe empezar en 0).
    pub fn matches(&self, data: &[u8]) -> bool {
        let pat = Self::compile(&self.pattern);
        if pat.is_empty() || data.len() < pat.len() {
            return false;
        }
        let solid = pat.iter().filter(|(b, _)| b.is_some()).count();
        if solid < self.min_solid {
            return false;
        }
        pat.iter().enumerate().all(|(i, (byte, wild))| {
            if *wild {
                true
            } else {
                data[i] == byte.expect("pattern byte")
            }
        })
    }
}

/// Base de datos de firmas.
#[derive(Debug, Clone, Default)]
pub struct SignatureDb {
    pub signatures: Vec<Signature>,
}

impl SignatureDb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Añade una firma.
    pub fn add(&mut self, name: &str, pattern: &str) {
        self.signatures.push(Signature {
            name: name.to_string(),
            pattern: pattern.to_string(),
            min_solid: default_min_solid(),
        });
    }

    /// Carga firmas desde JSON.
    pub fn load_json(text: &str) -> std::result::Result<Self, serde_json::Error> {
        let sigs: Vec<Signature> = serde_json::from_str(text)?;
        Ok(Self { signatures: sigs })
    }

    /// Escanea un buffer binario y devuelve addr (offset) → nombre.
    pub fn scan(&self, data: &[u8]) -> BTreeMap<usize, String> {
        let mut hits = BTreeMap::new();
        for sig in &self.signatures {
            let pat = Signature::compile(&sig.pattern);
            if pat.is_empty() {
                continue;
            }
            let solid = pat.iter().filter(|(b, _)| b.is_some()).count();
            if solid < sig.min_solid {
                continue;
            }
            let mut i = 0;
            while i + pat.len() <= data.len() {
                let matched = pat.iter().enumerate().all(|(j, (byte, wild))| {
                    *wild || data[i + j] == byte.expect("pattern byte")
                });
                if matched {
                    hits.entry(i).or_insert_with(|| sig.name.clone());
                    i += 1;
                } else {
                    i += 1;
                }
            }
        }
        hits
    }
}

/// Base de datos de firmas built-in (libc x86-64, prologo + primeras
/// instrucciones representativas). Los patrones usan wildcards para
/// absorver diferencias de compilador/optimizacion.
pub fn builtin_libc_db() -> SignatureDb {
    let mut db = SignatureDb::new();

    // Prologos canónicos x86-64 System V: push rbp; mov rbp,rsp; ...
    // strlen: 48 89 f8 / cmp byte [rdi],0 ...
    db.add("strlen", "48 89 f8 80 3f 00 74 ?? 48 ff c7 eb f?");
    // memcpy: 48 89 f8 48 89 d1 ... (diferencias cambian; solo el prologo + rep movsb)
    db.add("memcpy", "48 89 f8 48 89 d6 48 89 d1 ?? ?? ?? ?? f3 a4");
    // memset
    db.add("memset", "48 89 f8 48 89 f1 f3 aa c3");
    // strcmp (rep cmpsb)
    db.add("strcmp", "48 89 f8 48 89 f1 f3 a6 0f 9? c0");
    // strcpy
    db.add("strcpy", "48 89 f8 48 89 f1 f3 a4 c3");

    db
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_pattern() {
        let pat = Signature::compile("55 48 89 ?? e5");
        // 5 bytes: 55, 48, 89, wildcard(??), e5
        assert_eq!(pat.len(), 5);
        assert_eq!(pat[0], (Some(0x55), false));
        assert_eq!(pat[2], (Some(0x89), false));
        assert_eq!(pat[3], (None, true));
        assert_eq!(pat[4], (Some(0xe5), false));
    }

    #[test]
    fn compile_ignores_spaces_and_underscores() {
        let pat = Signature::compile("55_48 89");
        assert_eq!(pat.len(), 3);
        assert_eq!(pat[0].0, Some(0x55));
        assert_eq!(pat[1].0, Some(0x48));
    }

    #[test]
    fn match_with_wildcard() {
        let sig = Signature {
            name: "t".into(),
            pattern: "55 48 ?? e5".into(),
            min_solid: 3,
        };
        assert!(sig.matches(&[0x55, 0x48, 0x89, 0xe5]));
        assert!(sig.matches(&[0x55, 0x48, 0xAA, 0xe5]));
        assert!(!sig.matches(&[0x55, 0x48, 0x89, 0x00]));
    }

    #[test]
    fn db_scan_finds_hit() {
        let mut db = SignatureDb::new();
        db.add("strlen", "80 3f 00 74 ?? 48 ff c7");
        let data = vec![0x00, 0x00, 0x80, 0x3f, 0x00, 0x74, 0x05, 0x48, 0xff, 0xc7];
        let hits = db.scan(&data);
        assert!(hits.values().any(|n| n == "strlen"));
    }
}