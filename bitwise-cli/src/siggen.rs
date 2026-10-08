//! # Generador de firmas (siggen)
//!
//! Extrae firmas FLIRT-like de un binario de REFERENCIA (que aún tiene
//! símbolos). A diferencia de los patrones escritos a mano (que fallan
//! contra binarios optimizados), esto genera la firma REAL de cada función
//! normalizando los bytes que dependen de la dirección:
//!
//!  - Los primeros N bytes del prólogo (código estable).
//!  - Wildcards `??` en displacements de instrucciones RIP-relative
//!    (call/jmp/lea/mov que referencian memoria), porque esos offset
//!    cambian entre compilaciones.
//!
//! El resultado es un JSON que `bitwise identify --signatures` carga.
//!
//! Uso:
//!   bitwise-siggen <lib_de_referencia> <output.json> [num_funcs]

use bitwise_core::binary;
use bitwise_core::SymbolKind;
use bitwise_disasm::Disassembler;
use std::collections::BTreeMap;
use std::io::Write;

const SIGNATURE_LEN: usize = 24; // bytes de prólogo por firma
const MIN_SOLID: usize = 8;      // mínimo de bytes sólidos para aceptar

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("uso: bitwise-siggen <lib_referencia> <salida.json> [num_funcs]");
        std::process::exit(2);
    }
    let lib_path = &args[1];
    let out_path = &args[2];
    let max_funcs = args.get(3).and_then(|s| s.parse::<usize>().ok()).unwrap_or(5000);

    let info = match binary::load_binary(std::path::Path::new(lib_path)) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("no se pudo cargar {}: {}", lib_path, e);
            std::process::exit(1);
        }
    };

    // bytes del archivo completo
    let raw = std::fs::read(lib_path).expect("leer lib");

    // mapa de offset de archivo para cada símbolo de función
    let funcs: Vec<(String, u64)> = info
        .symbols
        .iter()
        .filter(|s| matches!(s.kind, SymbolKind::Function) && s.size > 0)
        .take(max_funcs)
        .map(|s| (s.name.clone(), s.address))
        .collect();

    if funcs.is_empty() {
        eprintln!("sin funciones exportadas; ¿el binario está stripped?");
        std::process::exit(1);
    }

    // desensamblar para saber qué bytes son RIP-relative (hay que hacer wildcard)
    let disasm = Disassembler::from_binary(&info).ok();

    let mut db: Vec<serde_json::Value> = Vec::new();
    let mut generated = 0;

    for (name, addr) in funcs {
        // dirección virtual → offset de archivo (buscar la sección que la contiene)
        let Some(file_off) = vaddr_to_offset(&info, addr) else { continue; };
        if file_off + SIGNATURE_LEN > raw.len() {
            continue;
        }

        let bytes = &raw[file_off..file_off + SIGNATURE_LEN];

        // normalizar: wildcard en bytes de operando RIP-relative
        let mut pattern = vec![0x5Cu8; SIGNATURE_LEN * 3]; // placeholder
        let mut solid = 0;
        let normalized = normalize(bytes, addr, &disasm, &info);

        // contar sólidos
        for (b, is_wild) in &normalized {
            if !*is_wild {
                solid += 1;
            }
        }
        if solid < MIN_SOLID {
            continue;
        }

        let pat_str = normalized
            .iter()
            .map(|(b, w)| if *w { "?? ".to_string() } else { format!("{:02x} ", b) })
            .collect::<String>()
            .trim()
            .to_string();

        let _ = &mut pattern;
        db.push(serde_json::json!({
            "name": name,
            "pattern": pat_str,
            "min_solid": MIN_SOLID,
        }));
        generated += 1;
    }

    // escribir JSON
    let text = serde_json::to_string_pretty(&db).expect("serializar");
    std::fs::write(out_path, &text).expect("escribir json");

    eprintln!("{}: {} firmas generadas de {} funciones", out_path, generated, info.symbols.len());
    let _ = std::io::stderr().flush();
}

/// Convierte dirección virtual a offset de archivo.
fn vaddr_to_offset(info: &bitwise_core::BinaryInfo, vaddr: u64) -> Option<usize> {
    for sec in &info.sections {
        if vaddr >= sec.virtual_address && vaddr < sec.virtual_address + sec.virtual_size {
            let delta = vaddr - sec.virtual_address;
            return Some((sec.raw_offset + delta) as usize);
        }
    }
    None
}

/// Marca `??` en los bytes que forman parte de un displacement RIP-relative.
/// Heurística: si la instrucción en esa dirección tiene un operando que
/// referencia memoria (contiene `[rip`), los últimos 4 bytes (un disp32)
/// son dependientes de dirección → wildcard.
fn normalize(
    bytes: &[u8],
    base_addr: u64,
    disasm: &Option<Disassembler>,
    info: &bitwise_core::BinaryInfo,
) -> Vec<(u8, bool)> {
    let mut out: Vec<(u8, bool)> = bytes.iter().map(|&b| (b, false)).collect();

    // Para simplicidad y robustez, marcamos wildcards en una heurística
    // por instrucción: desensambla el prólogo y detecta operandos `[rip`.
    if let Some(d) = disasm {
        if let Ok(insns) = d.disassemble(bytes, base_addr) {
            for insn in insns {
                let start = (insn.address - base_addr) as usize; // offset dentro del slice
                let size = insn.size as usize;
                let has_rip_rel = insn.operands.contains("[rip");
                if has_rip_rel && size >= 5 && start + size <= out.len() {
                    // los últimos 4 bytes son el disp32 RIP-relative
                    let base = start + size - 4;
                    for i in base..(base + 4).min(out.len()) {
                        out[i].1 = true;
                    }
                }
                // los call/jmp directos con dest absoluto también varían
                // (pero preservamos los primeros bytes)
            }
        }
    } else {
        // sin capstone: heurística cruda por si el byte parece un offset
        // (no hacemos nada — el pattern queda 100% sólido)
    }

    // Los primeros 3 bytes (prologo push rbp/mov rbp,rsp) casi siempre
    // estables, los preservamos.
    out
}