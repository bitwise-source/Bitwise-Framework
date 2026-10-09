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
        tool_def_req(
            "bitwise_mirror",
            "Clona un sitio (HTML + assets: bundles React/Vue, CSS, imágenes), le hace ingeniería inversa (endpoints, secrets por bundle) y devuelve el reporte. No abre túnel ni servidor — para eso usá la CLI 'bitwise mirror'",
            serde_json::json!({
                "url": {"type": "string", "description": "URL a clonar"},
                "out": {"type": "string", "description": "Directorio de salida (default: ./mirror-<host>)"}
            }),
            &["url"],
        ),
        tool_def(
            "bitwise_hexdump",
            "Hex dump del archivo completo o de una sección",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "lines": {"type": "integer", "description": "Cantidad de líneas (default 40)"},
                "section": {"type": "string", "description": "Sección a dumpear (default: archivo completo)"}
            }),
        ),
        tool_def(
            "bitwise_packer",
            "Detecta packers y ofuscación: UPX, ASPack, MPRESS, entropía de Shannon por sección",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"}
            }),
        ),
        tool_def(
            "bitwise_identify",
            "Identifica funciones conocidas contra firmas FLIRT-like (libc builtin u archivo de firmas custom)",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "signatures": {"type": "string", "description": "Ruta a archivo de firmas JSON (default: libc builtin)"}
            }),
        ),
        tool_def(
            "bitwise_demangle",
            "Demanglea símbolos C++ del binario y detecta vtables",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "vtables_only": {"type": "boolean", "description": "Solo detectar vtables (default false)"}
            }),
        ),
        tool_def(
            "bitwise_emu",
            "Emula la ejecución de una función (interpreter x86-64 puro, sin ejecutar el binario real)",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "entry": {"type": "string", "description": "Dirección de entrada en hex (default: entry point)"},
                "max_instructions": {"type": "integer", "description": "Máximo de instrucciones (default 1000)"}
            }),
        ),
        tool_def(
            "bitwise_diff",
            "Compara dos binarios: secciones y símbolos agregados/eliminados/cambiados",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario A"},
                "file_b": {"type": "string", "description": "Ruta al binario B"},
                "section": {"type": "string", "description": "Solo comparar una sección"}
            }),
        ),
        tool_def(
            "bitwise_annotate",
            "Renombra funciones/variables y agrega comentarios; persiste en <bin>.bitwise.json (compartido CLI/TUI/MCP)",
            serde_json::json!({
                "file": {"type": "string", "description": "Ruta al binario"},
                "renames": {"type": "array", "items": {"type": "string"}, "description": "Renombres 'old=new' (ej 'func_4da4=parse_header')"},
                "comments": {"type": "array", "items": {"type": "string"}, "description": "Comentarios 'addr=texto' (ej '0x4da4=valida el header')"},
                "show": {"type": "boolean", "description": "Solo mostrar el proyecto actual (default false)"}
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
        "bitwise_mirror" => {
            let url = req_str(&args, "url")?;
            let out = args.get("out").and_then(|v| v.as_str()).map(|s| s.to_string());
            return Ok(match cmd_mirror(&url, out.as_deref()) {
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
        "bitwise_hexdump" => cmd_hexdump(
            &file,
            args.get("lines").and_then(|v| v.as_u64()).unwrap_or(40) as usize,
            args.get("section").and_then(|v| v.as_str()),
        ),
        "bitwise_packer" => cmd_packer(&file),
        "bitwise_identify" => cmd_identify(&file, args.get("signatures").and_then(|v| v.as_str())),
        "bitwise_demangle" => cmd_demangle(&file, args.get("vtables_only").and_then(|v| v.as_bool()).unwrap_or(false)),
        "bitwise_emu" => cmd_emu(
            &file,
            args.get("entry").and_then(|v| v.as_str()),
            args.get("max_instructions").and_then(|v| v.as_u64()).unwrap_or(1000),
        ),
        "bitwise_diff" => {
            let file_b = args
                .get("file_b")
                .and_then(|v| v.as_str())
                .ok_or((serde_json::Value::from(-32602), "missing required argument: file_b".to_string()))?
                .to_string();
            cmd_diff(&file, &file_b, args.get("section").and_then(|v| v.as_str()))
        }
        "bitwise_annotate" => cmd_annotate(
            &file,
            args.get("renames").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
            args.get("comments").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
            args.get("show").and_then(|v| v.as_bool()).unwrap_or(false),
        ),
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

fn cmd_mirror(url: &str, out: Option<&str>) -> Result<String, String> {
    use bitwise_core::analysis::mirror;

    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("site");
    let out_dir = std::path::PathBuf::from(out.unwrap_or(&format!("mirror-{}", host)));

    let stats = mirror::mirror(url, &out_dir).map_err(|e| e.to_string())?;

    let mut out = format!(
        "dir: {}\npáginas: {}\nassets: {} ({} KB)\nbundles JS: {}\nendpoints: {}\n",
        out_dir.display(),
        stats.pages,
        stats.assets,
        stats.bytes / 1024,
        stats.js_bundles,
        stats.endpoints_found
    );

    for (file, eps) in stats.endpoints.iter().take(10) {
        out.push_str(&format!("  {}:\n", file));
        for e in eps.iter().take(10) {
            out.push_str(&format!("    {}\n", e));
        }
    }
    if !stats.secrets.is_empty() {
        out.push_str(&format!("secrets: {}\n", stats.secrets.len()));
        for s in stats.secrets.iter().take(10) {
            out.push_str(&format!("  {}\n", s));
        }
    }

    // persistir el reporte junto al mirror
    let report_path = out_dir.join("bitwise-report.json");
    if let Ok(json) = serde_json::to_string_pretty(&stats) {
        let _ = std::fs::write(&report_path, json);
        out.push_str(&format!("reporte: {}\n", report_path.display()));
    }
    Ok(out)
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
// Herramientas de binario extra (hexdump/packer/identify/demangle/emu/diff/annotate)
// ============================================================================

fn cmd_hexdump(file: &str, lines: usize, section: Option<&str>) -> Result<String, String> {
    let info = load(file)?;
    let raw = std::fs::read(file).map_err(|e| e.to_string())?;

    let (data, base): (Vec<u8>, u64) = if let Some(sec_name) = section {
        let sec = info
            .sections
            .iter()
            .find(|s| s.name == sec_name)
            .ok_or_else(|| format!("sección '{}' no encontrada", sec_name))?;
        let off = sec.raw_offset as usize;
        raw.get(off..off + sec.raw_size as usize)
            .map(|d| (d.to_vec(), sec.virtual_address))
            .ok_or_else(|| "sección fuera de rango".to_string())?
    } else {
        (raw.clone(), 0)
    };

    let mut out = String::new();
    for (i, chunk) in data.chunks(16).take(lines).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        out.push_str(&format!("{:#018x}  {:48}  {}\n", base + (i * 16) as u64, hex.join(" "), ascii));
    }
    Ok(out)
}

fn cmd_packer(file: &str) -> Result<String, String> {
    let info = load(file)?;
    let report = analysis::packer::analyze(&info);
    let mut out = format!(
        "likely packed: {}\nscore: {:.2}\nentropía global: {:.2}\nanomalía vs raw: {}\n",
        report.is_likely_packed, report.score, report.entropy, report.anomaly_vs_raw
    );
    if !report.matches.is_empty() {
        out.push_str("matches:\n");
        for m in &report.matches {
            out.push_str(&format!("  {} @ {:#x} ({})\n", m.name, m.offset, m.signature));
        }
    }
    Ok(out)
}

fn cmd_identify(file: &str, signatures: Option<&str>) -> Result<String, String> {
    use bitwise_core::analysis::signatures::{builtin_libc_db, SignatureDb};

    let db = if let Some(path) = signatures {
        let text = std::fs::read_to_string(path).map_err(|e| format!("leer {}: {}", path, e))?;
        SignatureDb::load_json(&text).map_err(|e| e.to_string())?
    } else {
        builtin_libc_db()
    };

    let info = load(file)?;
    let raw = std::fs::read(file).map_err(|e| e.to_string())?;
    let hits = db.scan(&raw);

    let mut out = format!("funciones identificadas: {}\n", hits.len());
    for (off, name) in hits.iter().take(100) {
        out.push_str(&format!("  {:#010x}  {}\n", off, name));
    }
    Ok(out)
}

fn cmd_demangle(file: &str, vtables_only: bool) -> Result<String, String> {
    let info = load(file)?;
    let mut out = String::new();

    if vtables_only {
        let vtables = bitwise_core::analysis::cpp::detect_vtables(&info);
        out.push_str(&format!("vtables: {}\n", vtables.len()));
        for v in vtables.iter().take(100) {
            out.push_str(&format!("  {:#018x}  {} entradas [{}]\n", v.address, v.entry_count, v.section));
        }
        return Ok(out);
    }

    let mut count = 0;
    for s in &info.symbols {
        if let Some(d) = bitwise_core::analysis::cpp::demangle(&s.name) {
            out.push_str(&format!("{}  →  {}\n", s.name, d));
            count += 1;
            if count >= 200 {
                out.push_str("...(truncated at 200)\n");
                break;
            }
        }
    }
    if count == 0 {
        out.push_str("(sin símbolos C++ demangleables)");
    }
    Ok(out)
}

fn cmd_emu(file: &str, entry: Option<&str>, max_instructions: u64) -> Result<String, String> {
    let info = load(file)?;

    let entry_addr = entry
        .map(|f| u64::from_str_radix(f.trim_start_matches("0x"), 16).unwrap_or(0))
        .or(info.entry_point)
        .unwrap_or(0);

    let cfg = bitwise_emu::EmuConfig {
        entry: entry_addr,
        max_instructions,
        ..Default::default()
    };
    let result = bitwise_emu::emulate(&info, &cfg);
    Ok(bitwise_emu::format_result(&result))
}

fn cmd_diff(file_a: &str, file_b: &str, _section: Option<&str>) -> Result<String, String> {
    let a = load(file_a)?;
    let b = load(file_b)?;

    let mut out = format!("A: {}\nB: {}\n\n", a.path, b.path);

    if a.architecture != b.architecture {
        out.push_str(&format!("arch changed: {:?} → {:?}\n", a.architecture, b.architecture));
    }
    if a.entry_point != b.entry_point {
        out.push_str(&format!(
            "entry changed: {:#x} → {:#x}\n",
            a.entry_point.unwrap_or(0),
            b.entry_point.unwrap_or(0)
        ));
    }

    use std::collections::BTreeSet;
    let secs_a: BTreeSet<String> = a.sections.iter().map(|s| s.name.clone()).collect();
    let secs_b: BTreeSet<String> = b.sections.iter().map(|s| s.name.clone()).collect();

    let added: Vec<_> = secs_b.difference(&secs_a).collect();
    let removed: Vec<_> = secs_a.difference(&secs_b).collect();
    if !added.is_empty() {
        out.push_str(&format!("secciones agregadas: {}\n", added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    if !removed.is_empty() {
        out.push_str(&format!("secciones eliminadas: {}\n", removed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }

    let sym_a: BTreeSet<String> = a.symbols.iter().map(|s| s.name.clone()).collect();
    let sym_b: BTreeSet<String> = b.symbols.iter().map(|s| s.name.clone()).collect();
    let sym_added = sym_b.difference(&sym_a).count();
    let sym_removed = sym_a.difference(&sym_b).count();
    if sym_added > 0 {
        out.push_str(&format!("símbolos agregados: {}\n", sym_added));
        for s in sym_b.difference(&sym_a).take(50) {
            out.push_str(&format!("  + {}\n", s));
        }
    }
    if sym_removed > 0 {
        out.push_str(&format!("símbolos eliminados: {}\n", sym_removed));
        for s in sym_a.difference(&sym_b).take(50) {
            out.push_str(&format!("  - {}\n", s));
        }
    }
    if sym_added == 0 && sym_removed == 0 && added.is_empty() && removed.is_empty() {
        out.push_str("(sin diferencias de secciones/símbolos)");
    }
    Ok(out)
}

fn cmd_annotate(file: &str, renames: Vec<String>, comments: Vec<String>, show: bool) -> Result<String, String> {
    use bitwise_core::analysis::annotations::Project;

    let path = std::path::Path::new(file);
    let mut proj = Project::load_for(path);
    let mut out = String::new();

    for r in &renames {
        // formato "addr=nombre"
        if let Some((addr_s, name)) = r.split_once('=') {
            let addr = u64::from_str_radix(addr_s.trim().trim_start_matches("0x"), 16)
                .map_err(|_| format!("renombre inválido '{}': la dirección debe ser hex", r))?;
            proj.rename_function(addr, name.trim());
            out.push_str(&format!("renombrado {:#x} → {}\n", addr, name.trim()));
        } else {
            return Err(format!("renombre inválido '{}': se espera 'addr=nombre'", r));
        }
    }

    for c in &comments {
        if let Some((addr_s, text)) = c.split_once('=') {
            let addr = u64::from_str_radix(addr_s.trim().trim_start_matches("0x"), 16)
                .map_err(|_| format!("comentario inválido '{}': la dirección debe ser hex", c))?;
            proj.add_comment(addr, text.trim());
            out.push_str(&format!("comentario en {:#x}: {}\n", addr, text.trim()));
        } else {
            return Err(format!("comentario inválido '{}': se espera 'addr=texto'", c));
        }
    }

    if show || (!renames.is_empty() || !comments.is_empty()) {
        proj.save_for(path).map_err(|e| format!("guardar proyecto: {}", e))?;
    }

    if show || (renames.is_empty() && comments.is_empty()) {
        out.push_str(&format!("\nfunciones: {}\n", proj.functions.len()));
        for (addr, name) in proj.functions.iter().take(100) {
            out.push_str(&format!("  {}  {}\n", addr, name));
        }
        out.push_str(&format!("comentarios: {}\n", proj.comments.len()));
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
