//! # JS deobfuscator / beautifier
//!
//! Herramientas para analizar JavaScript ofuscado o minificado:
//!  - `beautify`: re-indenta y agrega saltos de línea legibles
//!  - `deobfuscate`: beautify + renombrado de identificadores basura
//!    (_0x1a2b → var_1) + decodificación de strings hex/unicode escape
//!  - `stats`: métricas del archivo (tamaño, funciones, strings)

use std::collections::HashSet;

/// Métricas básicas de un archivo JS.
#[derive(Debug, Clone, Default)]
pub struct JsStats {
    pub bytes: usize,
    pub lines: usize,
    pub functions: usize,
    pub strings: usize,
    pub hex_idents: usize, // identificadores estilo _0x4f2a (ofuscación)
    pub eval_calls: usize,
    pub atob_calls: usize,
    pub fromcharcode_calls: usize,
}

/// Analiza un JS y devuelve métricas + score de ofuscación (0..1).
pub fn analyze_js(js: &str) -> (JsStats, f32) {
    let mut s = JsStats {
        bytes: js.len(),
        lines: js.lines().count(),
        ..Default::default()
    };

    let mut idents: HashSet<String> = HashSet::new();
    let mut in_ident = false;
    let mut cur = String::new();
    for c in js.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
            if !in_ident {
                in_ident = true;
                cur.clear();
            }
            cur.push(c);
        } else {
            if in_ident && cur.len() > 2 {
                idents.insert(cur.clone());
            }
            in_ident = false;
        }
    }

    for ident in &idents {
        // patrón _0x + hex = ofuscación javascript-obfuscator / obfuscator.io
        if ident.starts_with("_0x") && ident.len() >= 6 {
            s.hex_idents += 1;
        }
    }

    let lower = js.to_lowercase();
    s.functions = js.matches("function").count();
    s.eval_calls = lower.matches("eval(").count();
    s.atob_calls = lower.matches("atob(").count();
    s.fromcharcode_calls = lower.matches("fromcharcode").count();
    s.strings = js.matches('"').count() / 2 + js.matches('\'').count() / 2;

    // score de ofuscación
    let mut score = 0.0f32;
    if s.hex_idents > 10 {
        score += 0.5;
    } else if s.hex_idents > 0 {
        score += 0.2;
    }
    if s.eval_calls > 0 {
        score += 0.2;
    }
    if s.atob_calls + s.fromcharcode_calls > 0 {
        score += 0.15;
    }
    // densidad: pocas líneas para mucho código = minificado
    if s.bytes > 1000 && s.lines < (s.bytes / 200) {
        score += 0.15;
    }
    (s, score.min(1.0))
}

/// Beautify: re-indenta JS minificado con heurística de llaves/paréntesis.
/// No es un parser completo — es "buen enough" para lectura manual.
pub fn beautify(js: &str) -> String {
    let mut out = String::with_capacity(js.len() * 2);
    let mut indent = 0usize;
    let mut in_string: Option<char> = None;
    let mut in_comment: Option<u8> = None; // 1 = //, 2 = /* */

    let chars: Vec<char> = js.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];

        // manejo de comentarios
        if in_comment.is_none() && in_string.is_none() && c == '/' && i + 1 < chars.len() {
            if chars[i + 1] == '/' {
                in_comment = Some(1);
            } else if chars[i + 1] == '*' {
                in_comment = Some(2);
            }
        }
        if let Some(k) = in_comment {
            out.push(c);
            if k == 1 && c == '\n' {
                in_comment = None;
            } else if k == 2 && c == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                out.push('/');
                i += 2;
                in_comment = None;
                continue;
            }
            i += 1;
            continue;
        }

        // manejo de strings
        if let Some(q) = in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == q {
                in_string = None;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            in_string = Some(c);
            out.push(c);
            i += 1;
            continue;
        }

        match c {
            '{' | '[' | '(' => {
                indent += 1;
                out.push(c);
                // salto después de abrir bloque (no en arrays/args cortos)
                if c == '{' {
                    out.push('\n');
                    push_indent(&mut out, indent);
                }
            }
            '}' | ']' | ')' => {
                indent = indent.saturating_sub(1);
                if c == '}' {
                    out.push('\n');
                    push_indent(&mut out, indent);
                }
                out.push(c);
            }
            ';' => {
                out.push(c);
                out.push('\n');
                push_indent(&mut out, indent);
                // saltar espacios siguientes
                while i + 1 < chars.len() && chars[i + 1] == ' ' {
                    i += 1;
                }
            }
            '\n' | '\r' => {
                // colapsar saltos existentes
            }
            _ => out.push(c),
        }
        i += 1;
    }

    // colapsar múltiples líneas vacías
    let mut collapsed = String::with_capacity(out.len());
    let mut empty_count = 0;
    for line in out.lines() {
        if line.trim().is_empty() {
            empty_count += 1;
            if empty_count <= 1 {
                collapsed.push('\n');
            }
        } else {
            empty_count = 0;
            collapsed.push_str(line);
            collapsed.push('\n');
        }
    }
    collapsed
}

fn push_indent(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push_str("  ");
    }
}

/// Deobfuscate: beautify + renombra identificadores _0x... + decodifica escapes.
pub fn deobfuscate(js: &str) -> String {
    // 1) renombrar identificadores hex
    let mut mapping: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut counter = 0u32;

    // recolectar identificadores _0x...
    let hex_idents: Vec<String> = collect_hex_idents(js);
    for ident in hex_idents {
        counter += 1;
        mapping.insert(ident, format!("v{}", counter));
    }

    // 2) reemplazo seguro (fuera de strings)
    let mut out = String::with_capacity(js.len() * 2);
    let mut in_string: Option<char> = None;
    let chars: Vec<char> = js.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == q {
                in_string = None;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            in_string = Some(c);
            out.push(c);
            i += 1;
            continue;
        }
        // ¿inicio de identificador?
        if c == '_' || c.is_ascii_alphabetic() || c == '$' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '$')
            {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            if let Some(renamed) = mapping.get(&ident) {
                out.push_str(renamed);
            } else {
                out.push_str(&ident);
            }
            continue;
        }
        out.push(c);
        i += 1;
    }

    // 3) decodificar strings con escapes \x41 → 'A' y \u0041 → 'A'
    let decoded = decode_escapes(&out);

    // 4) beautify final
    beautify(&decoded)
}

fn collect_hex_idents(js: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_string: Option<char> = None;
    let chars: Vec<char> = js.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = in_string {
            if c != '\\' && c == q {
                in_string = None;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            in_string = Some(c);
            i += 1;
            continue;
        }
        if c == '_' && i + 3 < chars.len() && chars[i + 1] == '0' && chars[i + 2] == 'x' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '$')
            {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            if ident.len() >= 6 {
                out.push(ident);
            }
            continue;
        }
        i += 1;
    }
    out
}

/// Decodifica \xNN y \uNNNN dentro de strings.
fn decode_escapes(js: &str) -> String {
    let mut out = String::with_capacity(js.len());
    let chars: Vec<char> = js.chars().collect();
    let mut i = 0usize;
    let mut in_string: Option<char> = None;

    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = in_string {
            if c == '\\' && i + 1 < chars.len() {
                let n = chars[i + 1];
                if n == 'x' && i + 3 < chars.len() {
                    // \xNN
                    if let Ok(v) = u8::from_str_radix(&format!("{}{}", chars[i + 2], chars[i + 3]), 16) {
                        if v.is_ascii_graphic() || v == b' ' {
                            out.push(v as char);
                            i += 4;
                            continue;
                        }
                    }
                } else if n == 'u' && i + 5 < chars.len() {
                    // \uNNNN
                    let hex: String = chars[i + 2..i + 6].iter().collect();
                    if let Ok(v) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(v) {
                            if ch.is_ascii_graphic() || ch == ' ' {
                                out.push(ch);
                                i += 6;
                                continue;
                            }
                        }
                    }
                }
                out.push(c);
                out.push(n);
                i += 2;
                continue;
            }
            if c == q {
                in_string = None;
            }
            out.push(c);
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            in_string = Some(c);
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beautify_formats() {
        let min = "function a(){if(x){return 1;}else{return 2;}}";
        let out = beautify(min);
        assert!(out.contains("function a(){\n"));
        assert!(out.contains("return 1;\n"));
    }

    #[test]
    fn beautify_respects_strings() {
        // el ; dentro del string NO debe generar salto
        let min = "var s='a;b';";
        let out = beautify(min);
        assert!(out.contains("'a;b'"));
    }

    #[test]
    fn hex_ident_detection() {
        let js = "var _0x4f2a = 1; _0x4f2ab(2);";
        let (stats, score) = analyze_js(js);
        assert!(stats.hex_idents >= 2);
        assert!(score > 0.1);
    }

    #[test]
    fn deobfuscate_renames() {
        let js = "var _0xabc1=_0xabc2;";
        let out = deobfuscate(js);
        assert!(!out.contains("_0xabc1"), "debe renombrar: {}", out);
        assert!(out.contains("v1"));
        assert!(out.contains("v2"));
    }

    #[test]
    fn decode_hex_escapes() {
        let js = "var s='\\x41\\x42';";
        let out = decode_escapes(js);
        assert!(out.contains("'AB'"), "salida: {}", out);
    }

    #[test]
    fn obfuscation_score_clean_js() {
        let js = "function hello(name) { return name; }";
        let (_, score) = analyze_js(js);
        assert!(score < 0.2);
    }
}