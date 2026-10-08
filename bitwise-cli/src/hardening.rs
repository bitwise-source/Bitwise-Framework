//! # Hardening test harness
//!
//! Corre el parser (y opcionalmente decompilador) contra N binarios y
//! reporta cuántos fallan. No es un test unitario; es un binario de
//! auditoría para desarrolladores. Detecta crashs, panics y binarios que
//! el parser no puede abrir.
//!
//! Uso:
//!   cargo run -p bitwise-cli --bin bitwise-hardening -- <dir> [count]

use bitwise_core::binary;
use std::path::Path;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("uso: bitwise-hardening <directorio> [max_binarios]");
        std::process::exit(2);
    }
    let dir = &args[1];
    let max = args
        .get(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(usize::MAX);

    let paths: Vec<_> = std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .take(max)
        .collect();

    let total = paths.len();
    let mut ok = 0;
    let mut failed = 0;
    let mut formats: std::collections::BTreeMap<String, usize> = Default::default();
    let mut archs: std::collections::BTreeMap<String, usize> = Default::default();
    let mut failures: Vec<(String, String)> = Vec::new();
    let start = Instant::now();

    for p in &paths {
        let name = p.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
        match binary::load_binary(p) {
            Ok(info) => {
                ok += 1;
                *formats.entry(format!("{:?}", info.format)).or_insert(0) += 1;
                *archs.entry(format!("{:?}", info.architecture)).or_insert(0) += 1;
            }
            Err(e) => {
                failed += 1;
                if failures.len() < 30 {
                    failures.push((name, e.to_string()));
                }
            }
        }
    }

    let elapsed = start.elapsed();
    println!("═══ Bitwise hardening report ═══");
    println!("  total:   {}", total);
    println!("  ok:      {} ({:.1}%)", ok, 100.0 * ok as f64 / total as f64);
    println!("  failed:  {} ({:.1}%)", failed, 100.0 * failed as f64 / total as f64);
    println!("  tiempo:  {:?}", elapsed);
    println!();
    println!("  formatos:");
    for (k, v) in &formats {
        println!("    {:10} {}", k, v);
    }
    println!("  arquitecturas:");
    for (k, v) in &archs {
        println!("    {:10} {}", k, v);
    }
    if !failures.is_empty() {
        println!();
        println!("  fallos (primeros {}):", failures.len());
        for (name, err) in &failures {
            println!("    {}: {}", name, err);
        }
    }

    // exit code 0 si todo ok, 1 si hubo fallos
    if failed > 0 {
        std::process::exit(1);
    }
}

// Evitar warning de unused por Path
#[allow(dead_code)]
fn _unused(_p: &Path) {}