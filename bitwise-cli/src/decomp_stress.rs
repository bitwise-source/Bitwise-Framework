//! # Decompiler stress test
//! Corre el pipeline completo (disasm → lift → optimize → decompile) contra
//! N binarios y detecta panics/crashs. Separa lo que falla por etapa.

use bitwise_core::binary;
use bitwise_core::analysis;
use bitwise_disasm::Disassembler;
use bitwise_decomp::Decompiler;
use bitwise_lift::Lifter;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("uso: bitwise-decomp-stress <directorio> [max_binarios] [max_funcs]");
        std::process::exit(2);
    }
    let dir = &args[1];
    let max_bins = args.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(usize::MAX);
    let max_funcs = args.get(3).and_then(|s| s.parse::<usize>().ok()).unwrap_or(5);

    let paths: Vec<_> = std::fs::read_dir(dir)
        .ok().into_iter().flatten().flatten()
        .map(|e| e.path()).filter(|p| p.is_file()).take(max_bins).collect();

    let start = Instant::now();
    let mut bins = 0;
    let mut funcs_total = 0;
    let mut disasm_fail = 0;
    let mut decomp_fail = 0;
    let mut lift_fail = 0;
    let mut fails: Vec<(String, String)> = Vec::new();

    for p in &paths {
        let info = match binary::load_binary(p) {
            Ok(i) => i,
            Err(_) => continue, // raw/no-ELF ya cubierto por hardening
        };
        if !matches!(info.format, bitwise_core::BinaryFormat::ELF) {
            continue;
        }
        bins += 1;

        let disasm = match Disassembler::from_binary(&info) {
            Ok(d) => d,
            Err(e) => { disasm_fail += 1; if fails.len() < 20 { fails.push((p.display().to_string(), format!("disasm: {}", e))); } continue; }
        };

        let instructions = match disasm.disassemble_binary(&info) {
            Ok(i) => i,
            Err(e) => { disasm_fail += 1; if fails.len() < 20 { fails.push((p.display().to_string(), format!("disasm_bin: {}", e))); } continue; }
        };

        if instructions.is_empty() { continue; }

        let functions = analysis::detect_functions(&instructions, &info.symbols);
        let funcs: Vec<u64> = functions.iter().take(max_funcs).copied().collect();

        let mut sorted = instructions.clone();
        sorted.sort_by_key(|i| i.address);

        let mut decompiler = Decompiler::new();

        for target in funcs {
            funcs_total += 1;
            let next = functions.iter().filter(|&&a| a > target).min().copied().unwrap_or(u64::MAX);
            let func_insns: Vec<_> = sorted.iter().filter(|i| i.address >= target && i.address < next).cloned().collect();
            if func_insns.is_empty() { continue; }

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut lifter = Lifter::new(bitwise_lift::RegisterMap::x86_64());
                let raw = lifter.lift_all(&func_insns);
                let pcode = bitwise_decomp::optimize(&raw);
                let blocks = Lifter::build_blocks(&pcode);
                let mut f = bitwise_ir::IrFunction::new(&format!("f_{:x}", target), target);
                f.blocks = blocks;
                decompiler.decompile(&f)
            }));

            match result {
                Ok(_) => {}
                Err(_) => {
                    decomp_fail += 1;
                    if fails.len() < 20 {
                        fails.push((p.display().to_string(), format!("decompile panic @ {:#x}", target)));
                    }
                }
            }
        }
    }

    let elapsed = start.elapsed();
    println!("═══ Bitwise decompiler stress ═══");
    println!("  binarios ELF:     {}", bins);
    println!("  funciones:        {}", funcs_total);
    println!("  disasm fallos:    {}", disasm_fail);
    println!("  decomp fallos:    {}", decomp_fail);
    println!("  tiempo:           {:?}", elapsed);
    if !fails.is_empty() {
        println!();
        println!("  fallos:");
        for (n, e) in &fails { println!("    {}: {}", n, e); }
    }
    std::process::exit(if decomp_fail > 0 { 1 } else { 0 });
}