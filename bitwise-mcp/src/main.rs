//! # Bitwise MCP Server
//!
//! Expone el framework Bitwise vía Model Context Protocol (JSON-RPC sobre stdio).
//! Permite que agentes de IA (Claude, Cursor, etc.) analicen binarios con
//! herramientas estructuradas: info, sections, symbols, disasm, strings,
//! xrefs, decompile.
//!
//! Protocolo: MCP sobre stdio, línea-JSON (newline-delimited JSON-RPC 2.0).

use bitwise_core::binary;
use std::io::{self, BufRead, Write};

mod tools;

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();

    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let request: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let _ = write_response(
                    &mut out,
                    &serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {"code": -32700, "message": format!("parse error: {}", e)}
                    }),
                );
                continue;
            }
        };

        let response = tools::handle_request(&request);
        let _ = write_response(&mut out, &response);
    }
}

fn write_response(out: &mut io::StdoutLock, value: &serde_json::Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    out.write_all(b"\n")?;
    out.flush()
}
