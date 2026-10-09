//! Manejo de requests MCP: initialize, tools/list, tools/call.

use bitwise_core::analysis;
use bitwise_core::binary;
use bitwise_core::BinaryInfo;
use bitwise_disasm::Disassembler;
use std::path::PathBuf;

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "bitwise";
const SERVER_VERSION: &str = "0.1.0";

/// Dispatcher principal.
pub fn handle_request(req: &serde_json::Value) -> serde_json::Value {
    let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    let result = match method {
        "initialize" => Ok(handle_initialize()),
        "notifications/initialized" | "initialized" => {
            // notificación: no responder
            return serde_json::Value::Null;
        }
        "ping" => Ok(serde_json::json!({})),
        "tools/list" => Ok(handle_tools_list()),
        "tools/call" => handle_tools_call(req.get("params")),
        other => Err((serde_json::Value::from(-32601), format!("method not found: {}", other))),
    };

    match result {
        Ok(r) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": r
        }),
        Err((code, msg)) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": msg}
        }),
    }
}

fn handle_initialize() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION
        }
    })
}

fn tool_def(name: &str, desc: &str, params: serde_json::Value) -> serde_json::Value {
    tool_def_req(name, desc, params, &["file"])
}

fn tool_def_req(name: &str, desc: &str, params: serde_json::Value, required: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "description": desc,
        "inputSchema": {
            "type": "object",
            "properties": params,
            "required": required
        }
    })
}

fn handle_tools_list() -> serde_json::Value {
    let tools = vec![
        tool_def(
            "bitwise_info",
            "Información general de un binario: formato (ELF/PE/Mach-O), arquitectura, endianness, entry point, cantidad de secciones y símbolos",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"}
            }),
        ),
        tool_def(
            "bitwise_sections",
            "Lista secciones del binario con direcciones virtuales, tamaños y permisos rwx",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "exec_only": {"type": "boolean", "description": "Solo secciones ejecutables (default false)"}
            }),
        ),
        tool_def(
            "bitwise_symbols",
            "Lista símbolos del binario (funciones, objetos)",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "funcs_only": {"type": "boolean", "description": "Solo funciones (default false)"},
                "filter": {"type": "string", "description": "Substring a buscar en el nombre"}
            }),
        ),
        tool_def(
            "bitwise_disasm",
            "Desensambla instrucciones nativas de una sección ejecutable",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "section": {"type": "string", "description": "Sección (default .text)"},
                "count": {"type": "integer", "description": "Máximo de instrucciones (default 50)"}
            }),
        ),
        tool_def(
            "bitwise_strings",
            "Extrae strings ASCII del binario",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "min_length": {"type": "integer", "description": "Longitud mínima (default 5)"},
                "grep": {"type": "string", "description": "Substring a buscar"}
            }),
        ),
        tool_def(
            "bitwise_xrefs",
            "Referencias cruzadas (calls/jumps/datos) que apuntan a una dirección",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "address": {"type": "string", "description": "Dirección objetivo en hex (ej 0x4970)"}
            }),
        ),
        tool_def(
            "bitwise_decompile",
            "Decompila funciones a pseudo-C legible",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "function": {"type": "string", "description": "Dirección de función en hex (ej 0x4da4). Si se omite, decompila las primeras N"},
                "max_functions": {"type": "integer", "description": "Cantidad de funciones (default 1)"}
            }),
        ),
        tool_def(
            "bitwise_analyze",
            "Análisis completo: detecta funciones y bloques básicos",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"}
            }),
        ),
        tool_def_req(
            "bitwise_web",
            "Recon estático de una página web: endpoints, secretos filtrados (API keys, tokens), stack tecnológico y formularios",
            serde_json::json!({
                "url": {"type": "string", "description": "URL a analizar"},
                "deep": {"type": "boolean", "description": "Descargar y analizar también los JS externos (default false)"}
            }),
            &["url"],
        ),
        tool_def_req(
            "bitwise_webdyn",
            "Análisis dinámico web con navegador headless vía CDP: captura requests XHR/Fetch invisibles al análisis estático, el DOM post-JS, ejecuta JS arbitrario y saca screenshots",
            serde_json::json!({
                "url": {"type": "string", "description": "URL a renderizar"},
                "wait_ms": {"type": "integer", "description": "Espera tras la carga en ms (default 3000)"},
                "js": {"type": "string", "description": "JavaScript a evaluar en la página renderizada; imprime el resultado"},
                "screenshot": {"type": "string", "description": "Ruta donde guardar el screenshot PNG de la página renderizada"}
            }),
            &["url"],
        ),
        tool_def_req(
            "bitwise_js",
            "Deobfuscador JavaScript: beautify, renombra variables ofuscadas (_0x4f2a → v5), decodifica escapes \\xNN y busca sourcemaps",
            serde_json::json!({
                "input": {"type": "string", "description": "Ruta al .js o URL"},
                "stats": {"type": "boolean", "description": "Solo métricas y score de ofuscación (default false)"},
                "beautify_only": {"type": "boolean", "description": "Solo beautify sin renombrar (default false)"}
            }),
            &["input"],
        ),
    ];

    serde_json::json!({ "tools": tools })
}

fn text_content(s: String) -> serde_json::Value {
    serde_json::json!({
        "content": [{"type": "text", "text": s}],
        "isError": false
    })
}

fn error_content(msg: String) -> serde_json::Value {
    serde_json::json!({
        "content": [{"type": "text", "text": msg}],
        "isError": true
    })
}

fn handle_tools_call(params: Option<&serde_json::Value>) -> Result<serde_json::Value, (serde_json::Value, String)> {
    let params = params.ok_or((serde_json::Value::from(-32602), "missing params".into()))?;
    let name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or((serde_json::Value::from(-32602), "missing tool name".into()))?
        .to_string();
    let args = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));

    // Herramientas web: no requieren "file"
    let out = match name.as_str() {
        "bitwise_web" => {
            let url = req_str(&args, "url")?;
            return Ok(match cmd_web(&url, args.get("deep").and_then(|v| v.as_bool()).unwrap_or(false)) {
                Ok(s) => text_content(s),
                Err(e) => error_content(e),
            });
        }
        "bitwise_webdyn" => {
            let url = req_str(&args, "url")?;
            let wait_ms = args.get("wait_ms").and_then(|v| v.as_u64()).unwrap_or(3000);
            let js = args.get("js").and_then(|v| v.as_str()).map(|s| s.to_string());
            let screenshot = args.get("screenshot").and_then(|v| v.as_str()).map(|s| s.to_string());
            return Ok(match cmd_webdyn(&url, wait_ms, js.as_deref(), screenshot.as_deref()) {
                Ok(s) => text_content(s),
                Err(e) => error_content(e),
            });
        }
        "bitwise_js" => {
            let input = req_str(&args, "input")?;
            return Ok(match cmd_js(&input, args.get("stats").and_then(|v| v.as_bool()).unwrap_or(false), args.get("beautify_only").and_then(|v| v.as_bool()).unwrap_or(false)) {
                Ok(s) => text_content(s),
                Err(e) => error_content(e),
            });
        }
        _ => {
            // herramientas de binario: requieren "file"
            let file = args
                .get("file")
                .and_then(|f| f.as_str())
                .ok_or((serde_json::Value::from(-32602), "missing required argument: file".into()))?
                .to_string();
            handle_binary_tool(&name, &file, &args)?
        }
    };

    match out {
        Ok(s) => Ok(text_content(s)),
        Err(e) => Ok(error_content(e)),
    }
}

fn req_str(args: &serde_json::Value, key: &str) -> Result<String, (serde_json::Value, String)> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or((serde_json::Value::from(-32602), format!("missing required argument: {}", key)))
}

fn handle_binary_tool(
    name: &str,
    file: &str,
    args: &serde_json::Value,
) -> Result<Result<String, String>, (serde_json::Value, String)> {
    let out = match name {
        "bitwise_info" => cmd_info(&file),
        "bitwise_sections" => cmd_sections(&file, args.get("exec_only").and_then(|v| v.as_bool()).unwrap_or(false)),
        "bitwise_symbols" => cmd_symbols(
            &file,
            args.get("funcs_only").and_then(|v| v.as_bool()).unwrap_or(false),
            args.get("filter").and_then(|v| v.as_str()),
        ),
        "bitwise_disasm" => cmd_disasm(
            &file,
            args.get("section").and_then(|v| v.as_str()).unwrap_or(".text"),
            args.get("count").and_then(|v| v.as_u64()).unwrap_or(50) as usize,
        ),
        "bitwise_strings" => cmd_strings(
            &file,
            args.get("min_length").and_then(|v| v.as_u64()).unwrap_or(5) as usize,
            args.get("grep").and_then(|v| v.as_str()),
        ),
        "bitwise_xrefs" => cmd_xrefs(
            &file,
            args.get("address").and_then(|v| v.as_str()).unwrap_or("0"),
        ),
        "bitwise_decompile" => cmd_decompile(
            &file,
            args.get("function").and_then(|v| v.as_str()),
            args.get("max_functions").and_then(|v| v.as_u64()).unwrap_or(1) as usize,
        ),
        "bitwise_analyze" => cmd_analyze(&file),
        other => Err(format!("unknown tool: {}", other)),
    };

    Ok(out)
}

// ============================================================================
// Herramientas web
// ============================================================================

fn cmd_web(url: &str, deep: bool) -> Result<String, String> {
    let client = analysis::web::WebClient::new();
    let report = client.analyze(url, deep).map_err(|e| e.to_string())?;
    Ok(analysis::web::format_report(&report))
}

fn cmd_webdyn(
    url: &str,
    wait_ms: u64,
    js: Option<&str>,
    screenshot: Option<&str>,
) -> Result<String, String> {
    let mut browser = analysis::web_dynamic::HeadlessBrowser::launch().map_err(|e| e.to_string())?;
    let report = browser.analyze(url, wait_ms).map_err(|e| e.to_string())?;
    let mut out = analysis::web_dynamic::format_dynamic_report(&report);

    if let Some(expr) = js {
        let result = browser.evaluate(expr).map_err(|e| e.to_string())?;
        out.push_str(&format!("\nJS> {}\n  => {}\n", expr, result));
    }

    if let Some(path) = screenshot {
        let png = browser.screenshot().map_err(|e| e.to_string())?;
        std::fs::write(path, &png).map_err(|e| format!("escribir {}: {}", path, e))?;
        out.push_str(&format!("\nscreenshot guardado: {} ({} bytes)\n", path, png.len()));
    }

    Ok(out)
}

fn cmd_js(input: &str, stats: bool, beautify_only: bool) -> Result<String, String> {
    let source = std::fs::read_to_string(input)
        .map_err(|e| format!("leer {} (en MCP el input es ruta local; para URL usá bitwise_web/webdyn): {}", input, e))?;

    let (st, score) = analysis::js_deobf::analyze_js(&source);
    let mut out = String::new();

    if stats {
        out.push_str(&format!(
            "bytes: {}  líneas: {}\nscore de ofuscación: {:.2}/10\n",
            st.bytes, st.lines, score
        ));
        return Ok(out);
    }

    out.push_str(&format!("// score de ofuscación: {:.2}/10\n", score));
    if beautify_only {
        out.push_str(&analysis::js_deobf::beautify(&source));
    } else {
        out.push_str(&analysis::js_deobf::deobfuscate(&source));
    }
    Ok(out)
}

// ============================================================================
// Implementaciones de herramientas
// ============================================================================

fn load(file: &str) -> Result<BinaryInfo, String> {
    binary::load_binary(&PathBuf::from(file)).map_err(|e| e.to_string())
}

fn cmd_info(file: &str) -> Result<String, String> {
    let info = load(file)?;
    Ok(format!(
        "file: {}\nformat: {:?}\narch: {:?}\nendianness: {:?}\nplatform: {:?}\nentry_point: {:#x}\nsections: {}\nsymbols: {}\nsize: {} bytes",
        info.path,
        info.format,
        info.architecture,
        info.endianness,
        info.platform,
        info.entry_point.unwrap_or(0),
        info.sections.len(),
        info.symbols.len(),
        info.file_size
    ))
}

fn cmd_sections(file: &str, exec_only: bool) -> Result<String, String> {
    let info = load(file)?;
    let mut out = String::new();
    for sec in &info.sections {
        if exec_only && !sec.permissions.execute {
            continue;
        }
        let perms = format!(
            "{}{}{}",
            if sec.permissions.read { "r" } else { "-" },
            if sec.permissions.write { "w" } else { "-" },
            if sec.permissions.execute { "x" } else { "-" }
        );
        out.push_str(&format!(
            "{:#018x}  {:10}  {}  {}\n",
            sec.virtual_address, sec.virtual_size, perms, sec.name
        ));
    }
    Ok(out)
}

fn cmd_symbols(file: &str, funcs_only: bool, filter: Option<&str>) -> Result<String, String> {
    let info = load(file)?;
    let mut out = String::new();
    let mut count = 0;
    for s in &info.symbols {
        if funcs_only && !matches!(s.kind, bitwise_core::SymbolKind::Function) {
            continue;
        }
        if let Some(f) = filter {
            if !s.name.contains(f) {
                continue;
            }
        }
        out.push_str(&format!("{:#018x}  {}  {}\n", s.address, s.size, s.name));
        count += 1;
        if count >= 200 {
            out.push_str("...(truncated at 200)\n");
            break;
        }
    }
    if count == 0 {
        out.push_str("(no symbols)");
    }
    Ok(out)
}

fn cmd_disasm(file: &str, section: &str, count: usize) -> Result<String, String> {
    let info = load(file)?;
    let disasm = Disassembler::from_binary(&info).map_err(|e| e.to_string())?;
    let insns = disasm
        .disassemble_section(&info, section)
        .map_err(|e| e.to_string())?;

    let mut out = String::new();
    for insn in insns.iter().take(count) {
        let bytes: Vec<String> = insn.bytes.iter().map(|b| format!("{:02x}", b)).collect();
        out.push_str(&format!(
            "{:#018x}  {:24}  {:8} {}\n",
            insn.address,
            bytes.join(" "),
            insn.mnemonic,
            insn.operands
        ));
    }
    Ok(out)
}

fn cmd_strings(file: &str, min_length: usize, grep: Option<&str>) -> Result<String, String> {
    let info = load(file)?;
    let strings = analysis::refs::extract_strings_from_binary(&info, min_length)
        .map_err(|e| e.to_string())?;

    let mut out = String::new();
    let mut count = 0;
    for s in strings {
        if let Some(g) = grep {
            if !s.value.contains(g) {
                continue;
            }
        }
        out.push_str(&format!("{:#018x}  [{}]  {}\n", s.address, s.section, s.value));
        count += 1;
        if count >= 200 {
            out.push_str("...(truncated at 200)\n");
            break;
        }
    }
    if count == 0 {
        out.push_str("(no strings found)");
    }
    Ok(out)
}

fn cmd_xrefs(file: &str, address: &str) -> Result<String, String> {
    let target = u64::from_str_radix(address.trim_start_matches("0x"), 16)
        .map_err(|e| format!("dirección inválida '{}': {}", address, e))?;

    let info = load(file)?;
    let disasm = Disassembler::from_binary(&info).map_err(|e| e.to_string())?;
    let instructions = disasm.disassemble_binary(&info).map_err(|e| e.to_string())?;

    let table = analysis::refs::build_xrefs(&instructions);
    let refs = analysis::refs::xrefs_to(&table, target);

    let mut out = format!("xrefs to {:#x}: {}\n", target, refs.len());
    for x in refs.iter().take(100) {
        let kind = match x.kind {
            analysis::refs::XrefKind::Call => "CALL",
            analysis::refs::XrefKind::Jump => "JUMP",
            analysis::refs::XrefKind::Data => "DATA",
        };
        out.push_str(&format!("{:#018x}  {}\n", x.from_address, kind));
    }
    Ok(out)
}

fn cmd_decompile(file: &str, function: Option<&str>, max_functions: usize) -> Result<String, String> {
    let info = load(file)?;
    let disasm = Disassembler::from_binary(&info).map_err(|e| e.to_string())?;
    let instructions = disasm.disassemble_binary(&info).map_err(|e| e.to_string())?;

    if instructions.is_empty() {
        return Ok("(no executable code)".into());
    }

    let functions = analysis::detect_functions(&instructions, &info.symbols);

    let targets: Vec<u64> = if let Some(f) = function {
        let addr = u64::from_str_radix(f.trim_start_matches("0x"), 16)
            .map_err(|e| format!("dirección inválida '{}': {}", f, e))?;
        vec![addr]
    } else {
        let n = max_functions.min(functions.len());
        functions[..n].to_vec()
    };

    let mut sorted = instructions.clone();
    sorted.sort_by_key(|i| i.address);

    let mut decompiler = bitwise_decomp::Decompiler::new();
    let mut out = String::new();

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
            out.push_str(&format!("// sin instrucciones en {:#x}\n\n", target));
            continue;
        }

        let mut lifter = bitwise_lift::Lifter::new(bitwise_lift::RegisterMap::x86_64());
        let pcode = lifter.lift_all(&func_insns);
        let blocks = bitwise_lift::Lifter::build_blocks(&pcode);

        let mut ir_func = bitwise_ir::IrFunction::new(&format!("func_{:x}", target), target);
        ir_func.blocks = blocks;

        out.push_str(&decompiler.decompile(&ir_func));
        out.push('\n');
    }

    Ok(out)
}

fn cmd_analyze(file: &str) -> Result<String, String> {
    let info = load(file)?;
    let disasm = Disassembler::from_binary(&info).map_err(|e| e.to_string())?;
    let instructions = disasm.disassemble_binary(&info).map_err(|e| e.to_string())?;

    if instructions.is_empty() {
        return Ok("(no executable code)".into());
    }

    let functions = analysis::detect_functions(&instructions, &info.symbols);
    let blocks = analysis::build_basic_blocks(&instructions, &functions);

    Ok(format!(
        "functions detected: {}\nbasic blocks: {}\ninstructions: {}\n\nfirst functions:\n{}",
        functions.len(),
        blocks.len(),
        instructions.len(),
        functions
            .iter()
            .take(20)
            .map(|f| format!("  {:#018x}\n", f))
            .collect::<String>()
    ))
}
