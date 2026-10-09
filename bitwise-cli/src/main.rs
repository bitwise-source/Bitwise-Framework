//! # Bitwise CLI
//!
//! Herramienta de línea de comandos para análisis de binarios.
//! Comandos: info, disasm, symbols, sections, analyze, ir, decompile,
//! strings, xrefs, hexdump, tui, debug, script, diff.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use colored::*;

use bitwise_core::analysis;
use bitwise_core::binary;
use bitwise_disasm::{format_instructions, Disassembler};

/// Bitwise — Framework de ingeniería inversa multi-plataforma.
#[derive(Parser)]
#[command(name = "bitwise", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Muestra información general del binario
    Info {
        file: PathBuf,
        #[arg(short, long)]
        json: bool,
    },
    /// Desensambla secciones ejecutables
    Disasm {
        file: PathBuf,
        #[arg(short, long)]
        section: Option<String>,
        #[arg(short = 'b', long)]
        show_bytes: bool,
        #[arg(short = 'a', long, default_value = "0")]
        base_address: u64,
        #[arg(short = 'n', long)]
        max_instructions: Option<usize>,
    },
    /// Lista símbolos (funciones, variables)
    Symbols {
        file: PathBuf,
        #[arg(short, long, default_value = "all")]
        filter: String,
        #[arg(short, long)]
        json: bool,
    },
    /// Lista secciones del binario
    Sections {
        file: PathBuf,
        #[arg(short, long)]
        json: bool,
    },
    /// Análisis completo: detección de funciones y CFG
    Analyze {
        file: PathBuf,
        #[arg(short, long)]
        blocks: bool,
    },
    /// Muestra el IR (P-Code) de una sección
    Ir {
        file: PathBuf,
        #[arg(short, long)]
        section: Option<String>,
        #[arg(short = 'n', long)]
        max_instructions: Option<usize>,
    },
    /// Decompila funciones a pseudo-C
    Decompile {
        file: PathBuf,
        /// Dirección de la función (hex, ej 0x4da4)
        #[arg(short = 'f', long)]
        function: Option<String>,
        /// Decompilar las primeras N funciones (default 5)
        #[arg(short = 'n', long)]
        max_functions: Option<usize>,
    },
    /// Extrae strings del binario
    Strings {
        file: PathBuf,
        #[arg(short = 'n', long, default_value = "4")]
        min_length: usize,
        #[arg(short, long)]
        grep: Option<String>,
    },
    /// Referencias cruzadas hacia una dirección
    Xrefs {
        file: PathBuf,
        /// Dirección objetivo (hex)
        address: String,
    },
    /// Hex dump del archivo o una sección
    Hexdump {
        file: PathBuf,
        #[arg(short = 'n', long, default_value = "32")]
        lines: usize,
        #[arg(short, long)]
        section: Option<String>,
    },
    /// Interfaz interactiva de terminal
    Tui {
        file: PathBuf,
    },
    /// Debugger: corre el binario con breakpoints
    Debug {
        file: PathBuf,
        /// Breakpoint inicial (dirección hex)
        #[arg(short = 'b', long)]
        breakpoint: Option<String>,
        /// Argumentos para el programa
        args: Vec<String>,
    },
    /// Ejecuta un script .bws
    Script {
        script_file: PathBuf,
    },
    /// Compara dos binarios (secciones + símbolos)
    Diff {
        file_a: PathBuf,
        file_b: PathBuf,
    },
    /// Exporta el CFG a Graphviz (.dot) para visualizar con `dot -Tpng`
    CfgDot {
        file: PathBuf,
        /// Dirección de función (hex). Si se omite, exporta las primeras N
        #[arg(short = 'f', long)]
        function: Option<String>,
        /// Cantidad de funciones a exportar (default 3)
        #[arg(short = 'n', long, default_value = "3")]
        max_funcs: usize,
    },
    /// Detecta packers y ofuscación (UPX, ASPack, MPRESS, entropía)
    Packer {
        file: PathBuf,
    },
    /// Reescribe bytes del binario en disco (parcheo manual)
    Patch {
        file: PathBuf,
        /// Parches a aplicar: cada flag es offset+hex_bytes, ej --at 0x1000 --with 9090
        #[arg(long, value_parser = parse_u64)]
        at: Vec<u64>,
        #[arg(long, value_parser = parse_hex)]
        with: Vec<String>,
        /// Crear backup .bak antes de modificar
        #[arg(long)]
        backup: bool,
    },
    /// Emula ejecución de una función (interpreter x86-64)
    Emu {
        file: PathBuf,
        /// Dirección de entrada (hex). Por defecto, entry point.
        #[arg(short = 'f', long)]
        entry: Option<String>,
        /// Máximo de instrucciones (default 1000)
        #[arg(short = 'n', long, default_value = "1000")]
        max_instructions: u64,
        /// Dirección de memoria a volcar al final (hex), ej 0x2000
        #[arg(long, value_parser = parse_u64, num_args = 1..)]
        dump_mem: Vec<u64>,
        /// Tamaño del volcado en bytes (default 64)
        #[arg(long, default_value = "64")]
        dump_size: usize,
        /// Dirección donde detenerse antes de tiempo (hex)
        #[arg(long, value_parser = parse_u64, num_args = 1..)]
        stop_at: Vec<u64>,
    },
    /// Renombra funciones/variables y guarda en proyecto .bitwise.json
        Annotate {
            file: PathBuf,
            /// Renombra función: --funcs 0x4da4 main
            #[arg(long, value_names = ["ADDR", "NAME"], num_args = 2)]
            funcs: Vec<String>,
            /// Renombra variable/temp: --vars t1000 filename
            #[arg(long, value_names = ["TEMP", "NAME"], num_args = 2)]
            vars: Vec<String>,
            /// Comentario: --comments 0x4da4 "descifra el string"
            #[arg(long, value_names = ["ADDR", "TEXT"], num_args = 2)]
            comments: Vec<String>,
            /// Mostrar el proyecto actual
            #[arg(short, long)]
            show: bool,
        },
        /// Demanglea nombres C++ (símbolos, o un nombre suelto)
            Demangle {
                file: PathBuf,
                /// Mostrar solo vtables detectadas
                #[arg(short, long)]
                vtables: bool,
            },
            /// Identifica funciones conocidas (firmas FLIRT-like)
            Identify {
                file: PathBuf,
                /// Archivo JSON de firmas personalizadas (si no, builtin libc)
                #[arg(short, long)]
                signatures: Option<PathBuf>,
            },
            /// Ingeniería inversa de páginas web (recon estático)
            Web {
                /// URL a analizar (https://...)
                url: String,
                /// Descargar y analizar también los scripts externos
                #[arg(short, long)]
                deep: bool,
            },
            /// Deobfuscador/beautifier de JavaScript
            Js {
                /// Archivo .js local o URL del script
                input: String,
                /// Solo mostrar stats/score de ofuscación
                #[arg(short, long)]
                stats: bool,
                /// Solo beautify (sin renombrar)
                #[arg(short = 'B', long)]
                beautify_only: bool,
                /// Buscar y descargar sourcemaps (si input es URL)
                #[arg(short = 'm', long)]
                sourcemaps: bool,
            },
            /// Análisis dinámico web (navegador headless vía CDP)
            WebDyn {
                /// URL a renderizar con navegador real
                url: String,
                /// Tiempo de espera tras la carga (ms, default 3000)
                #[arg(short = 'w', long, default_value = "3000")]
                wait_ms: u64,
                /// Ejecutar JS arbitrario en la página renderizada (imprime el resultado)
                #[arg(short = 'j', long)]
                js: Option<String>,
                /// Guardar screenshot PNG de la página renderizada
                #[arg(short = 's', long)]
                screenshot: Option<String>,
            },
            }

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("{} {}", "error:".red().bold(), e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Info { file, json } => cmd_info(&file, json),
        Commands::Disasm {
            file,
            section,
            show_bytes,
            base_address,
            max_instructions,
        } => cmd_disasm(
            &file,
            section.as_deref(),
            show_bytes,
            base_address,
            max_instructions,
        ),
        Commands::Symbols { file, filter, json } => cmd_symbols(&file, &filter, json),
        Commands::Sections { file, json } => cmd_sections(&file, json),
        Commands::Analyze { file, blocks } => cmd_analyze(&file, blocks),
        Commands::Ir { file, section, max_instructions } => {
            cmd_ir(&file, section.as_deref(), max_instructions)
        }
        Commands::Decompile { file, function, max_functions } => {
            cmd_decompile(&file, function.as_deref(), max_functions)
        }
        Commands::Strings { file, min_length, grep } => {
            cmd_strings(&file, min_length, grep.as_deref())
        }
        Commands::Xrefs { file, address } => cmd_xrefs(&file, &address),
        Commands::Hexdump { file, lines, section } => cmd_hexdump(&file, lines, section.as_deref()),
        Commands::Tui { file } => cmd_tui(&file),
        Commands::Debug { file, breakpoint, args } => cmd_debug(&file, breakpoint.as_deref(), &args),
        Commands::Script { script_file } => cmd_script(&script_file),
        Commands::Diff { file_a, file_b } => cmd_diff(&file_a, &file_b),
        Commands::CfgDot { file, function, max_funcs } => {
            cmd_cfg_dot(&file, function.as_deref(), max_funcs)
        }
        Commands::Packer { file } => cmd_packer(&file),
        Commands::Patch { file, at, with, backup } => {
            cmd_patch(&file, &at, &with, backup)
        }
        Commands::Emu {
            file,
            entry,
            max_instructions,
            dump_mem,
            dump_size,
            stop_at,
        } => cmd_emu(&file, entry.as_deref(), max_instructions, &dump_mem, dump_size, &stop_at),
        Commands::Annotate {
            file,
            funcs,
            vars,
            comments,
            show,
        } => cmd_annotate(&file, &funcs, &vars, &comments, show),
        Commands::Demangle { file, vtables } => cmd_demangle(&file, vtables),
        Commands::Identify { file, signatures } => cmd_identify(&file, signatures.as_deref()),
        Commands::Web { url, deep } => cmd_web(&url, deep),
        Commands::Js { input, stats, beautify_only, sourcemaps } => {
            cmd_js(&input, stats, beautify_only, sourcemaps)
        }
        Commands::WebDyn { url, wait_ms, js, screenshot } => cmd_webdyn(&url, wait_ms, js.as_deref(), screenshot.as_deref()),
    }
}

fn parse_u64(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim_start_matches("0x");
    u64::from_str_radix(s, 16).map_err(|e| format!("offset inválido '{}': {}", s, e))
}

fn parse_hex(s: &str) -> std::result::Result<String, String> {
    let s = s.replace(' ', "").replace(',', "");
    if s.len() % 2 != 0 {
        return Err(format!("hex string de longitud impar: '{}'", s));
    }
    Ok(s)
}

fn cmd_info(file: &PathBuf, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("{}", "═══ Bitwise Binary Info ═══".cyan().bold());
        println!("  {} {}", "File:".bold(), info.path);
        println!("  {} {}", "Format:".bold(), format!("{:?}", info.format).yellow());
        println!("  {} {}", "Arch:".bold(), format!("{:?}", info.architecture).green());
        println!("  {} {}", "Endianness:".bold(), format!("{:?}", info.endianness));
        println!("  {} {:?}", "Platform:".bold(), info.platform);
        println!("  {} {}", "Size:".bold(), format_size(info.file_size));
        if let Some(ep) = info.entry_point {
            println!("  {} {:#018x}", "Entry Point:".bold(), ep);
        }
        println!("  {} {}", "Sections:".bold(), info.sections.len());
        println!("  {} {}", "Symbols:".bold(), info.symbols.len());
    }

    Ok(())
}

fn cmd_disasm(
    file: &PathBuf,
    section: Option<&str>,
    show_bytes: bool,
    base_address: u64,
    max_instructions: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;
    let disasm = Disassembler::from_binary(&info)?;

    let instructions = if let Some(sec_name) = section {
        disasm.disassemble_section(&info, sec_name)?
    } else {
        disasm.disassemble_binary(&info)?
    };

    let instructions: Vec<_> = if let Some(max) = max_instructions {
        instructions.into_iter().take(max).collect()
    } else {
        instructions
    };

    let _ = base_address;

    println!(
        "{} {} instructions",
        "Disassembled".green().bold(),
        instructions.len()
    );
    println!();

    if show_bytes {
        println!(
            "  {:18}  {:24}  {:8}  {}",
            "Address", "Bytes", "Mnemonic", "Operands"
        );
    } else {
        println!("  {:18}  {:8}  {}", "Address", "Mnemonic", "Operands");
    }

    print!("{}", format_instructions(&instructions, show_bytes));

    Ok(())
}

fn cmd_symbols(file: &PathBuf, filter: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;

    let filtered: Vec<_> = info
        .symbols
        .iter()
        .filter(|s| match filter {
            "func" => matches!(s.kind, bitwise_core::SymbolKind::Function),
            "obj" => matches!(s.kind, bitwise_core::SymbolKind::Object),
            _ => true,
        })
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
    } else {
        println!(
            "{} {} symbols ({})",
            "Symbols:".green().bold(),
            filtered.len(),
            filter
        );
        for sym in filtered.iter().take(100) {
            let kind_str = match sym.kind {
                bitwise_core::SymbolKind::Function => "FUNC".cyan(),
                bitwise_core::SymbolKind::Object => "OBJ".yellow(),
                _ => "?".into(),
            };
            println!("  {:#018x}  {:6}  {:8}  {}", sym.address, sym.size, kind_str, sym.name);
        }
        if filtered.len() > 100 {
            println!("  ... {} more", filtered.len() - 100);
        }
    }

    Ok(())
}

fn cmd_sections(file: &PathBuf, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&info.sections)?);
    } else {
        println!(
            "{} {} sections",
            "Sections:".green().bold(),
            info.sections.len()
        );
        for sec in &info.sections {
            let perms = format!(
                "{}{}{}",
                if sec.permissions.read { "r" } else { "-" },
                if sec.permissions.write { "w" } else { "-" },
                if sec.permissions.execute { "x" } else { "-" }
            );
            println!(
                "  {:24}  {:#018x}  {:10}  {}",
                sec.name, sec.virtual_address, sec.virtual_size, perms
            );
        }
    }

    Ok(())
}

fn cmd_analyze(file: &PathBuf, show_blocks: bool) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;
    let disasm = Disassembler::from_binary(&info)?;
    let instructions = disasm.disassemble_binary(&info)?;

    if instructions.is_empty() {
        println!("{}", "No executable code found.".yellow());
        return Ok(());
    }

    let functions = analysis::detect_functions(&instructions, &info.symbols);
    println!("{} {} functions detected", "Analysis:".green().bold(), functions.len());

    for func_addr in functions.iter().take(50) {
        println!("  {} {:#018x}", "func".cyan(), func_addr);
    }
    if functions.len() > 50 {
        println!("  ... {} more", functions.len() - 50);
    }

    if show_blocks {
        let blocks = analysis::build_basic_blocks(&instructions, &functions);
        println!("\n{} {} basic blocks", "Basic Blocks:".yellow().bold(), blocks.len());
        for block in blocks.iter().take(30) {
            let succ: Vec<String> = block.successors.iter().map(|a| format!("{:#x}", a)).collect();
            println!(
                "  {:#018x} → {} ({} bytes)",
                block.start_address,
                if succ.is_empty() { "∅".to_string() } else { succ.join(", ") },
                block.end_address - block.start_address
            );
        }
        if blocks.len() > 30 {
            println!("  ... {} more", blocks.len() - 30);
        }
    }

    Ok(())
}

fn cmd_ir(
    file: &PathBuf,
    section: Option<&str>,
    max_instructions: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    use bitwise_ir::PcodeInst;

    let info = binary::load_binary(file)?;
    let disasm = Disassembler::from_binary(&info)?;

    let instructions = if let Some(sec) = section {
        disasm.disassemble_section(&info, sec)?
    } else {
        disasm.disassemble_binary(&info)?
    };

    let instructions: Vec<_> = if let Some(max) = max_instructions {
        instructions.into_iter().take(max).collect()
    } else {
        instructions
    };

    let mut lifter = bitwise_lift::Lifter::new(bitwise_lift::RegisterMap::x86_64());
    let pcode_raw = lifter.lift_all(&instructions);
    let pcode = bitwise_decomp::optimize(&pcode_raw);

    println!("{} {} pcode ops", "IR:".green().bold(), pcode.len());
    println!();
    for inst in &pcode {
        println!("{}", inst);
    }

    Ok(())
}

fn cmd_decompile(
    file: &PathBuf,
    function: Option<&str>,
    max_functions: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;
    let disasm = Disassembler::from_binary(&info)?;
    let instructions = disasm.disassemble_binary(&info)?;

    if instructions.is_empty() {
        println!("{}", "No executable code found.".yellow());
        return Ok(());
    }

    let functions = analysis::detect_functions(&instructions, &info.symbols);

    // Cargar el proyecto de annotations para aplicar renombres
    let proj = bitwise_core::analysis::annotations::Project::load_for(
        std::path::Path::new(file),
    );

    let targets: Vec<u64> = if let Some(f) = function {
        let addr = u64::from_str_radix(f.trim_start_matches("0x"), 16)?;
        vec![addr]
    } else {
        let n = max_functions.unwrap_or(5).min(functions.len());
        functions[..n].to_vec()
    };

    // slicing de funciones por rango de direcciones
    let mut sorted = instructions.clone();
    sorted.sort_by_key(|i| i.address);

    let mut decompiler = bitwise_decomp::Decompiler::new();

    for target in targets {
        let next_start = functions
            .iter()
            .filter(|&&a| a > target)
            .min()
            .copied()
            .unwrap_or(u64::MAX);

        let func_insns: Vec<_> = sorted
            .iter()
            .filter(|i| i.address >= target && i.address < next_start)
            .cloned()
            .collect();

        if func_insns.is_empty() {
            println!("{}", format!("// sin instrucciones en 0x{:x}", target).yellow());
            continue;
        }

        let mut lifter = bitwise_lift::Lifter::new(bitwise_lift::RegisterMap::x86_64());
        let pcode_raw = lifter.lift_all(&func_insns);
        let pcode = bitwise_decomp::optimize(&pcode_raw);
        let blocks = bitwise_lift::Lifter::build_blocks(&pcode);

        // Usar el nombre del proyecto si existe, si no el default
        let func_display_name = proj
            .function_name(target)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("func_{:x}", target));

        let mut ir_func = bitwise_ir::IrFunction::new(&func_display_name, target);
        ir_func.blocks = blocks;

        let code = decompiler.decompile(&ir_func);

        // Aplicar renombres de variables (tN → nombre) al texto de salida
        let mut out = code;
        for (key, name) in &proj.variables {
            if let Some(temp_id) = key.strip_prefix('t').and_then(|s| s.parse::<u64>().ok()) {
                // el decompilador genera nombres como u0_qword; mapeamos t{id}
                // (el id interno) → nombre. Usamos un marker textual: t{id}
                let marker = format!("t{}", temp_id);
                // solo reintentar si aparece el id literal
                if out.contains(&marker) || out.contains(&format!("u{}", temp_id)) {
                    out = out.replace(&marker, name);
                }
            }
        }

        println!("{}", out);
        println!();
    }

    Ok(())
}

fn cmd_strings(
    file: &PathBuf,
    min_length: usize,
    grep: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;
    let strings = analysis::refs::extract_strings_from_binary(&info, min_length)?;

    let filtered: Vec<_> = if let Some(g) = grep {
        strings.into_iter().filter(|s| s.value.contains(g)).collect()
    } else {
        strings
    };

    println!(
        "{} {} strings (min_len={})",
        "Strings:".green().bold(),
        filtered.len(),
        min_length
    );
    for s in filtered.iter().take(200) {
        println!("  {:#018x}  [{}]  {}", s.address, s.section, s.value);
    }
    if filtered.len() > 200 {
        println!("  ... {} more", filtered.len() - 200);
    }

    Ok(())
}

fn cmd_xrefs(file: &PathBuf, address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let target = u64::from_str_radix(address.trim_start_matches("0x"), 16)?;

    let info = binary::load_binary(file)?;
    let disasm = Disassembler::from_binary(&info)?;
    let instructions = disasm.disassemble_binary(&info)?;

    let table = analysis::refs::build_xrefs(&instructions);
    let refs = analysis::refs::xrefs_to(&table, target);

    println!("{} {} xrefs to {:#018x}", "Xrefs:".green().bold(), refs.len(), target);
    for x in refs.iter().take(100) {
        let kind = match x.kind {
            analysis::refs::XrefKind::Call => "CALL".cyan(),
            analysis::refs::XrefKind::Jump => "JUMP".yellow(),
            analysis::refs::XrefKind::Data => "DATA".white(),
        };
        println!("  {:#018x}  {} → {:#018x}", x.from_address, kind, x.to_address);
    }
    if refs.is_empty() {
        println!("{}", "  (no references found)".yellow());
    }

    Ok(())
}

fn cmd_hexdump(
    file: &PathBuf,
    lines: usize,
    section: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;
    let raw = std::fs::read(file)?;

    let (data, base) = if let Some(sec_name) = section {
        let sec = info
            .sections
            .iter()
            .find(|s| s.name.contains(sec_name))
            .ok_or_else(|| format!("sección no encontrada: {}", sec_name))?;
        let start = sec.raw_offset as usize;
        let end = (start + sec.raw_size as usize).min(raw.len());
        (&raw[start.min(raw.len())..end], sec.virtual_address)
    } else {
        (&raw[..], 0u64)
    };

    print!("{}", bitwise_tui::hexdump::hexdump_limited(data, base, lines));

    Ok(())
}

fn cmd_tui(file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = bitwise_tui::TuiSession::load(file)?;
    bitwise_tui::run(&mut session)?;
    Ok(())
}

fn cmd_debug(
    file: &PathBuf,
    breakpoint: Option<&str>,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut dbg = bitwise_debug::Debugger::new();

    println!("{} {}", "Spawning:".cyan().bold(), file.display());
    let pid = dbg.spawn(file.to_str().unwrap(), args)?;
    println!("  pid={}", pid);

    // Para PIE: obtener la base de carga real desde /proc/<pid>/maps
    let load_base = std::fs::read_to_string(format!("/proc/{}/maps", pid))
        .ok()
        .and_then(|maps| {
            maps.lines()
                .next()
                .and_then(|first| first.split('-').next().map(|h| u64::from_str_radix(h, 16).unwrap_or(0)))
        })
        .unwrap_or(0);
    if load_base > 0 {
        println!("  load base = {:#018x} (PIE)", load_base);
    }

    let info = binary::load_binary(file)?;
    let disasm = Disassembler::from_binary(&info)?;

    let bp_addr = if let Some(bp) = breakpoint {
        u64::from_str_radix(bp.trim_start_matches("0x"), 16)? + load_base
    } else {
        info.entry_point.unwrap_or(0) + load_base
    };

    if bp_addr > 0 {
        println!("{} breakpoint at {:#018x}", "Set:".cyan().bold(), bp_addr);
        dbg.set_breakpoint(bp_addr)?;
    }

    println!("{} running...", "→".cyan());
    let event = dbg.cont()?;

    match event {
        bitwise_debug::StopEvent::Trap => {
            println!("{}", "Stopped (SIGTRAP)".green().bold());
            if let Some(hit) = dbg.breakpoints().first() {
                println!("  breakpoint hit at {:#018x}", hit.address);
            }
            let regs = dbg.registers()?;
            println!(
                "  rip={:#018x} rsp={:#018x} rbp={:#018x}",
                regs.get("rip").copied().unwrap_or(0),
                regs.get("rsp").copied().unwrap_or(0),
                regs.get("rbp").copied().unwrap_or(0),
            );
            match dbg.disasm_at_rip(&disasm, 8) {
                Ok(insns) => {
                    println!("{}", "  code at rip:".bold());
                    print!("{}", format_instructions(&insns, true));
                }
                Err(e) => println!("  (disasm failed: {})", e),
            }
        }
        bitwise_debug::StopEvent::Exited(code) => {
            println!("{} exit code {}", "Process exited:".yellow().bold(), code);
        }
        other => println!("{} {:?}", "Event:".yellow(), other),
    }

    dbg.kill()?;
    println!("{}", "Process killed.".dimmed());

    Ok(())
}

fn cmd_script(script_file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let source = std::fs::read_to_string(script_file)?;
    let mut interp = bitwise_script::Interpreter::new();
    let result = interp.run(&source)?;
    println!("{}", result);
    Ok(())
}

fn cmd_diff(file_a: &PathBuf, file_b: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let info_a = binary::load_binary(file_a)?;
    let info_b = binary::load_binary(file_b)?;

    println!("{}", "═══ Bitwise Diff ═══".cyan().bold());
    println!("  A: {}", info_a.path);
    println!("  B: {}", info_b.path);
    println!();

    if info_a.architecture != info_b.architecture {
        println!(
            "  {} {:?} → {:?}",
            "arch changed:".yellow(),
            info_a.architecture,
            info_b.architecture
        );
    }
    if info_a.entry_point != info_b.entry_point {
        println!(
            "  {} {:#x} → {:#x}",
            "entry changed:".yellow(),
            info_a.entry_point.unwrap_or(0),
            info_b.entry_point.unwrap_or(0)
        );
    }

    use std::collections::BTreeSet;
    let secs_a: BTreeSet<String> = info_a.sections.iter().map(|s| s.name.clone()).collect();
    let secs_b: BTreeSet<String> = info_b.sections.iter().map(|s| s.name.clone()).collect();

    let added: Vec<_> = secs_b.difference(&secs_a).collect();
    let removed: Vec<_> = secs_a.difference(&secs_b).collect();

    if !added.is_empty() {
        println!("  {} +{}", "sections added:".green(), added.len());
        for s in added.iter().take(10) {
            println!("    + {}", s);
        }
    }
    if !removed.is_empty() {
        println!("  {} -{}", "sections removed:".red(), removed.len());
        for s in removed.iter().take(10) {
            println!("    - {}", s);
        }
    }

    let syms_a: BTreeSet<String> = info_a.symbols.iter().map(|s| s.name.clone()).collect();
    let syms_b: BTreeSet<String> = info_b.symbols.iter().map(|s| s.name.clone()).collect();

    let sym_added = syms_b.difference(&syms_a).count();
    let sym_removed = syms_a.difference(&syms_b).count();

    println!(
        "  {} {} total, +{}/-{}",
        "symbols:".bold(),
        syms_b.len(),
        sym_added,
        sym_removed
    );

    let mut moved = 0;
    for sa in &info_a.symbols {
        if let Some(sb) = info_b.symbols.iter().find(|s| s.name == sa.name) {
            if sa.address != sb.address {
                moved += 1;
            }
        }
    }
    println!("  {} {} símbolos compartidos cambiaron de dirección", "moved:".bold(), moved);

    Ok(())
}

fn cmd_cfg_dot(file: &PathBuf, function: Option<&str>, max_funcs: usize) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;
    let func = function.map(|f| {
        let s = f.trim_start_matches("0x");
        u64::from_str_radix(s, 16).unwrap_or(0)
    });
    let dot = bitwise_tui::cfg_dot::bin_to_dot(&info, func, max_funcs);
    println!("{}", dot);
    eprintln!("{} guarda esto a un archivo .dot y abrí con `dot -Tpng file.dot -o file.png`", "tip:".cyan());
    Ok(())
}

fn cmd_packer(file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;
    let report = bitwise_core::analysis::packer::analyze(&info);

    if report.matches.is_empty() && !report.is_likely_packed {
        println!("{}", "no se detectaron packers conocidos".green());
    }

    println!("{} score: {:.2} ({} packed)",
        if report.is_likely_packed { "Packer:".red().bold() } else { "Packer:".green().bold() },
        report.score,
        if report.is_likely_packed { "LIKELY" } else { "no" }
    );
    println!("  entropy: {:.2} bits/byte", report.entropy);
    println!("  VS >> RS anomaly: {}", report.anomaly_vs_raw);

    if !report.matches.is_empty() {
        println!("\n  matches:");
        for m in &report.matches {
            println!("    {} @ {:#x}  (sig: {:?})", m.name.yellow(), m.offset, m.signature);
        }
    }
    Ok(())
}

fn cmd_patch(
    file: &PathBuf,
    at: &[u64],
    with: &[String],
    backup: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if at.len() != with.len() {
        return Err(format!(
            "--at y --with deben tener la misma cantidad de elementos ({} vs {})",
            at.len(), with.len()
        ).into());
    }
    let info = binary::load_binary(file)?;

    let mut patches: Vec<(u64, Vec<u8>)> = Vec::new();
    for (off, hex) in at.iter().zip(with.iter()) {
        let bytes = hex_to_bytes(hex)?;
        patches.push((*off, bytes));
    }

    bitwise_core::analysis::packer::patch_bytes(&info, &patches, backup)?;
    println!("{} parcheado {} bytes en {} ubicación(es){}",
        "OK".green().bold(),
        patches.iter().map(|(_, b)| b.len()).sum::<usize>(),
        patches.len(),
        if backup { " (backup .bak guardado)" } else { "" }
    );
    Ok(())
}

fn hex_to_bytes(s: &str) -> std::result::Result<Vec<u8>, String> {
    let s = s.replace(' ', "").replace(',', "");
    if s.len() % 2 != 0 {
        return Err(format!("hex string de longitud impar: '{}'", s));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("hex inválido: {}", e)))
        .collect()
}

fn cmd_emu(
    file: &PathBuf,
    entry: Option<&str>,
    max_instructions: u64,
    dump_mem: &[u64],
    dump_size: usize,
    stop_at: &[u64],
) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;

    let entry_addr = entry.map(|f| {
        let s = f.trim_start_matches("0x");
        u64::from_str_radix(s, 16).unwrap_or(0)
    });

    let dump: Vec<(u64, usize)> = dump_mem.iter().map(|&a| (a, dump_size)).collect();

    let cfg = bitwise_emu::EmuConfig {
        entry: entry_addr.unwrap_or(0),
        max_instructions,
        stop_addresses: stop_at.to_vec(),
        dump_registers: vec![],
        dump_memory: dump,
    };

    println!("{} {:?} from {:#x} (max {} insns)",
        "Emulating".cyan().bold(),
        info.architecture,
        if entry_addr.unwrap_or(0) == 0 { info.entry_point.unwrap_or(0) } else { entry_addr.unwrap_or(0) },
        max_instructions
    );

    let result = bitwise_emu::emulate(&info, &cfg);
    print!("{}", bitwise_emu::format_result(&result));
    Ok(())
}

fn cmd_annotate(
    file: &PathBuf,
    funcs: &[String],
    vars: &[String],
    comments: &[String],
    show: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use bitwise_core::analysis::annotations::Project;

    let path = std::path::Path::new(file);
    let mut proj = Project::load_for(path);

    for pair in funcs.chunks(2) {
        if pair.len() != 2 {
            continue;
        }
        let addr = u64::from_str_radix(pair[0].trim_start_matches("0x"), 16)?;
        proj.rename_function(addr, &pair[1]);
    }

    for pair in vars.chunks(2) {
        if pair.len() != 2 {
            continue;
        }
        let temp_id = pair[0].trim_start_matches('t').parse::<u64>()?;
        proj.rename_variable(temp_id, &pair[1]);
    }

    for pair in comments.chunks(2) {
        if pair.len() != 2 {
            continue;
        }
        let addr = u64::from_str_radix(pair[0].trim_start_matches("0x"), 16)?;
        proj.add_comment(addr, &pair[1]);
    }

    proj.save_for(path)?;

    if show || (funcs.is_empty() && vars.is_empty() && comments.is_empty()) {
        println!("{}", serde_json::to_string_pretty(&proj)?);
    } else {
        println!(
            "{} proyecto guardado en {}.bitwise.json",
            "OK".green().bold(),
            file.display()
        );
    }

    Ok(())
}

fn cmd_demangle(
    file: &PathBuf,
    vtables_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = binary::load_binary(file)?;

    if vtables_only {
        let vtables = bitwise_core::analysis::cpp::detect_vtables(&info);
        println!("{} {} vtables detected", "Vtables:".green().bold(), vtables.len());
        for v in vtables.iter().take(100) {
            println!(
                "  {} @ {:#018x} ({} methods)",
                v.section.yellow(),
                v.address,
                v.entry_count
            );
            for (i, e) in v.entries.iter().take(8).enumerate() {
                println!("    [{:2}] {:#018x}", i, e);
            }
            if v.entry_count > 8 {
                println!("    ... +{} more", v.entry_count - 8);
            }
        }
        return Ok(());
    }

    let demangled = bitwise_core::analysis::cpp::demangled_function_names(&info);
    println!("{} {} símbolos C++ demangleados", "C++:".green().bold(), demangled.len());
    for (addr, name) in demangled.iter().take(200) {
        println!("  {:#018x}  {}", addr, name);
    }
    if demangled.len() > 200 {
        println!("  ... {} more", demangled.len() - 200);
    }

    Ok(())
}

fn cmd_identify(
    file: &PathBuf,
    signatures: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    use bitwise_core::analysis::signatures::{builtin_libc_db, SignatureDb};

    let db = if let Some(path) = signatures {
        let text = std::fs::read_to_string(path)?;
        SignatureDb::load_json(&text)?
    } else {
        builtin_libc_db()
    };

    let raw = std::fs::read(file)?;
    let hits = db.scan(&raw);

    println!("{} {} firmas matched", "Identify:".green().bold(), hits.len());
    for (offset, name) in hits.iter().take(100) {
        println!("  {:#010x}  {}", offset, name.yellow());
    }
    if hits.len() > 100 {
        println!("  ... {} more", hits.len() - 100);
    }

    Ok(())
}

fn cmd_web(url: &str, deep: bool) -> Result<(), Box<dyn std::error::Error>> {
    use bitwise_core::analysis::web::WebClient;

    println!("{} {}", "Analizando:".cyan().bold(), url);
    if deep {
        println!("{}", "  (modo deep: descargando scripts externos)".dimmed());
    }

    let client = WebClient::new();
    let report = client
        .analyze(url, deep)
        .map_err(|e| format!("no se pudo analizar: {}", e))?;

    print!("{}", bitwise_core::analysis::web::format_report(&report));
    Ok(())
}

fn cmd_js(
    input: &str,
    stats_only: bool,
    beautify_only: bool,
    with_sourcemaps: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use bitwise_core::analysis::js_deobf;

    // cargar desde URL o archivo local
    let js = if input.starts_with("http://") || input.starts_with("https://") {
        let resp = ureq::get(input).call().map_err(|e| e.to_string())?;
        let mut body = String::new();
        use std::io::Read;
        resp.into_reader()
            .take(10_000_000)
            .read_to_string(&mut body)
            .map_err(|e| e.to_string())?;
        body
    } else {
        std::fs::read_to_string(input)?
    };

    // stats + score siempre
    let (stats, score) = js_deobf::analyze_js(&js);
    eprintln!("── stats ──────────────────────");
    eprintln!("  bytes: {}  líneas: {}", stats.bytes, stats.lines);
    eprintln!("  funciones: {}  strings: ~{}", stats.functions, stats.strings);
    eprintln!("  idents hex (_0x..): {}  eval: {}  atob: {}", stats.hex_idents, stats.eval_calls, stats.atob_calls);
    eprintln!("  score de ofuscación: {:.2} {}", score, if score > 0.5 { "⚠ OFUSCADO" } else { "ok" });
    eprintln!("───────────────────────────────");

    // sourcemaps
    if with_sourcemaps {
        let maps = bitwise_core::analysis::web::find_sourcemaps(&js);
        if maps.is_empty() {
            eprintln!("sourcemaps: ninguno declarado");
        } else {
            eprintln!("sourcemaps declarados: {}", maps.join(", "));
            // intentar descargar el primero si es URL de entrada
            if input.starts_with("http") {
                for m in &maps {
                    let map_url = bitwise_core::analysis::web::resolve_url(m, input);
                    if let Ok(resp) = ureq::get(&map_url).call() {
                        let mut body = String::new();
                        use std::io::Read;
                        resp.into_reader().take(5_000_000).read_to_string(&mut body).ok();
                        if let Ok(sources) = bitwise_core::analysis::web::parse_sourcemap(&body) {
                            eprintln!("  ↳ {}: {} archivos fuente:", m, sources.len());
                            for s in sources.iter().take(30) {
                                eprintln!("      {}", s);
                            }
                        }
                    }
                }
            }
        }
    }

    // stats-only termina acá
    if stats_only {
        return Ok(());
    }

    // beautify o deobfuscate
    let out = if beautify_only {
        js_deobf::beautify(&js)
    } else {
        js_deobf::deobfuscate(&js)
    };
    print!("{}", out);
    Ok(())
}

fn cmd_webdyn(
    url: &str,
    wait_ms: u64,
    js: Option<&str>,
    screenshot: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use bitwise_core::analysis::web_dynamic::HeadlessBrowser;

    println!("{} {} (navegador headless)", "Renderizando:".cyan().bold(), url);

    let mut browser = HeadlessBrowser::launch().map_err(|e| {
        format!(
            "no se pudo lanzar el navegador: {}\n  (instalá chromium: apt install chromium-browser, o google-chrome)",
            e
        )
    })?;

    let report = browser.analyze(url, wait_ms).map_err(|e| e.to_string())?;
    print!("{}", bitwise_core::analysis::web_dynamic::format_dynamic_report(&report));

    if let Some(expr) = js {
        let result = browser.evaluate(expr).map_err(|e| e.to_string())?;
        println!("\n{} JS> {}\n  => {}", "Evaluando:".cyan().bold(), expr, result);
    }

    if let Some(path) = screenshot {
        let png = browser.screenshot().map_err(|e| e.to_string())?;
        std::fs::write(path, &png)?;
        println!("{} {} ({} bytes)", "Screenshot:".cyan().bold(), path, png.len());
    }

    Ok(())
}

fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    format!("{:.1} {}", size, UNITS[unit_idx])
}
