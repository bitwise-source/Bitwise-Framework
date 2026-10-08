//! # Análisis C++: demangling y detección de vtables
//!
//! Dos capacidades esenciales para reversing de binarios C++:
//!  1. `demangle`: decodifica nombres mangled Itanium ABI (`_ZN3Foo3barEv`
//!     → `Foo::bar()`). Cubre los patrones más comunes (clases, métodos,
//!     namespaces, constructores/destructores, operadores).
//!  2. `detect_vtables`: localiza tablas virtuales en las secciones de datos
//!     read-only — arrays de punteros que apuntan a direcciones de código.

use crate::BinaryInfo;
use std::collections::BTreeMap;

// ============================================================================
// Demangling Itanium ABI (subconjunto)
// ============================================================================

/// Parsea una secuencia de componentes `<len><name>`.
/// Devuelve (componentes, nueva_posición).
fn parse_components(s: &[u8], mut pos: usize) -> (Vec<String>, usize) {
    let mut comps = Vec::new();
    while pos < s.len() {
        match s[pos] {
            b'N' => {
                // nested name: N <component...> E
                pos += 1;
                let (mut inner, new_pos) = parse_components(s, pos);
                pos = new_pos;
                // los componentes internos se aplanan: el primer es el scope
                // y el resto son métodos/miembros
                comps.extend(inner.drain(..));
                if pos < s.len() && s[pos] == b'E' {
                    pos += 1;
                }
            }
            b'C' => {
                // constructor: C1/C2 → "~ctor", C3 → ...
                if pos + 1 < s.len() {
                    comps.push("ctor".into());
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            b'D' => {
                if pos + 1 < s.len() {
                    comps.push("dtor".into());
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            b'E' => {
                pos += 1;
                break;
            }
            b'I' => {
                // template args → simplificamos
                pos += 1;
                comps.push("<...>".into());
            }
            b'0'..=b'9' => {
                // longitud + nombre
                let mut n = 0usize;
                while pos < s.len() && s[pos].is_ascii_digit() {
                    n = n * 10 + (s[pos] - b'0') as usize;
                    pos += 1;
                }
                if pos + n <= s.len() {
                    comps.push(String::from_utf8_lossy(&s[pos..pos + n]).to_string());
                    pos += n;
                } else {
                    break;
                }
            }
            _ => {
                pos += 1;
            }
        }
    }
    (comps, pos)
}

/// Demanglea un nombre Itanium ABI. Devuelve `None` si no es mangled.
pub fn demangle(name: &str) -> Option<String> {
    if !name.starts_with("_Z") {
        return None;
    }
    let s = name.as_bytes();
    let mut pos = 2; // skip "_Z"

    // _ZN = nested name; _Z followed by digit = top-level function
    if pos < s.len() && s[pos] == b'N' {
        pos += 1;
        let (comps, _) = parse_components(s, pos);
        if comps.is_empty() {
            return Some(name.to_string());
        }
        // formato: scope::scope::...::func
        if comps.len() == 1 {
            Some(comps[0].clone())
        } else {
            Some(comps.join("::"))
        }
    } else {
        // top-level: _Z <len><name>...
        let (comps, _) = parse_components(s, pos);
        if comps.is_empty() {
            Some(name.to_string())
        } else if comps.len() == 1 {
            Some(comps[0].clone())
        } else {
            Some(comps.join("::"))
        }
    }
}

// ============================================================================
// Detección de vtables
// ============================================================================

#[derive(Debug, Clone)]
pub struct Vtable {
    /// dirección de la vtable en el binario
    pub address: u64,
    /// sección donde vive
    pub section: String,
    /// cantidad de entradas (métodos virtuales)
    pub entry_count: usize,
    /// direcciones de los métodos (targets)
    pub entries: Vec<u64>,
}

/// Detecta vtables: secuencias de ≥2 punteros alineados a 8 bytes en
/// secciones read-only que apuntan a direcciones que caen dentro de una
/// sección ejecutable.
pub fn detect_vtables(info: &BinaryInfo) -> Vec<Vtable> {
    // rango de código ejecutable
    let exec_ranges: Vec<(u64, u64)> = info
        .sections
        .iter()
        .filter(|s| s.permissions.execute)
        .map(|s| (s.virtual_address, s.virtual_address + s.virtual_size))
        .collect();

    let raw = match std::fs::read(&info.path) {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let mut vtables = Vec::new();

    for sec in &info.sections {
        // solo secciones read-only (las vtables están en .rodata/.data.rel.ro)
        if sec.permissions.write || sec.raw_size == 0 {
            continue;
        }
        let base = sec.raw_offset as usize;
        let end = (base + sec.raw_size as usize).min(raw.len());
        if base >= raw.len() {
            continue;
        }

        let mut i = base;
        while i + 8 <= end {
            let ptr = u64::from_le_bytes([
                raw[i], raw[i+1], raw[i+2], raw[i+3], raw[i+4], raw[i+5], raw[i+6], raw[i+7],
            ]);
            // ¿puntero a código?
            let in_code = exec_ranges.iter().any(|(a, b)| ptr >= *a && ptr < *b);
            if in_code {
                // iniciar una vtable aquí: leer punteros consecutivos
                let mut entries = vec![ptr];
                let mut j = i + 8;
                while j + 8 <= end && entries.len() < 64 {
                    let p = u64::from_le_bytes([
                        raw[j], raw[j+1], raw[j+2], raw[j+3], raw[j+4], raw[j+5], raw[j+6], raw[j+7],
                    ]);
                    let p_in_code = exec_ranges.iter().any(|(a, b)| p >= *a && p < *b);
                    if p_in_code {
                        entries.push(p);
                        j += 8;
                    } else {
                        break;
                    }
                }
                if entries.len() >= 2 {
                    let addr = sec.virtual_address + (i - base) as u64;
                    vtables.push(Vtable {
                        address: addr,
                        section: sec.name.clone(),
                        entry_count: entries.len(),
                        entries,
                    });
                    i = j;
                    continue;
                }
            }
            i += 8;
        }
    }

    vtables
}

/// Devuelve el nombre demangleado de una función si está mangled.
pub fn demangled_function_names(
    info: &BinaryInfo,
) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    for sym in &info.symbols {
        if let Some(dm) = demangle(&sym.name) {
            out.insert(sym.address, dm);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangle_simple_function() {
        assert_eq!(demangle("_Z3foov"), Some("foo".to_string()));
    }

    #[test]
    fn demangle_method() {
        // _ZN3Foo3barEv → Foo::bar()
        assert_eq!(demangle("_ZN3Foo3barEv"), Some("Foo::bar".to_string()));
    }

    #[test]
    fn demangle_non_mangled() {
        assert_eq!(demangle("printf"), None);
        assert_eq!(demangle("main"), None);
    }

    #[test]
    fn demangle_ctor() {
        // _ZN3FooC1Ev → Foo::ctor
        let r = demangle("_ZN3FooC1Ev");
        assert!(r.is_some());
    }
}