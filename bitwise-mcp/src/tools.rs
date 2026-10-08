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
    serde_json::json!({
        "name": name,
        "description": desc,
        "inputSchema": {
            "type": "object",
            "properties": params,
            "required": ["file"]
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
        .ok_or((serde_json::Value::from(-32602), "missing tool name".into()))?;
    let args = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));

    let file = args
        .get("file")
        .and_then(|f| f.as_str())
        .ok_or((serde_json::Value::from(-32602), "missing required argument: file".into()))?
        .to_string();

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
        other => return Ok(error_content(format!("unknown tool: {}", other))),
    };

    match out {
        Ok(s) => Ok(text_content(s)),
        Err(e) => Ok(error_content(e)),
    }
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
