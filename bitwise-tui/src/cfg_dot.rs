//! # Exportador de CFG a Graphviz (.dot)
//!
//! Produce un archivo `.dot` que se puede pasar a `dot -Tpng cfg.dot -o cfg.png`
//! para visualizar el grafo de control de flujo. Cada bloque es un nodo,
//! cada sucesor es una arista etiquetada con el tipo de transición.

use bitwise_core::arch::Instruction;
use bitwise_core::BinaryInfo;
use bitwise_disasm::Disassembler;
use bitwise_ir::EdgeType;
use std::collections::BTreeMap;
use std::fmt::Write;

/// Bloque propio del CFG-dot (operamos sobre instrucciones nativas, no P-Code).
#[derive(Debug, Clone)]
pub struct DotBlock {
    pub id: usize,
    pub start_address: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<(usize, EdgeType)>,
}

/// Construye el CFG de una función a partir de instrucciones nativas.
pub fn build_cfg(func_addr: u64, instructions: &[Instruction]) -> Vec<DotBlock> {
    let mut blocks: Vec<DotBlock> = Vec::new();
    if instructions.is_empty() {
        return blocks;
    }

    let mut addr_to_id: BTreeMap<u64, usize> = BTreeMap::new();
    let mut current_instructions: Vec<Instruction> = Vec::new();
    let mut current_start = instructions[0].address;
    let mut current_id = 0;
    addr_to_id.insert(current_start, 0);

    for insn in instructions {
        if addr_to_id.get(&insn.address).is_some() && !current_instructions.is_empty() {
            blocks.push(DotBlock {
                id: current_id,
                start_address: current_start,
                instructions: std::mem::take(&mut current_instructions),
                successors: Vec::new(),
            });
            current_start = insn.address;
            current_id = blocks.len();
        }
        current_instructions.push(insn.clone());

        if is_control_flow(&insn.mnemonic) {
            if let Some(target) = extract_target(&insn.operands) {
                addr_to_id.entry(target).or_insert_with(|| blocks.len() + 1);
            }
            let succ = successors_for(insn, &addr_to_id);
            blocks.push(DotBlock {
                id: current_id,
                start_address: current_start,
                instructions: std::mem::take(&mut current_instructions),
                successors: succ,
            });
            current_start = insn.address + insn.size as u64;
            current_id = blocks.len();
            addr_to_id.entry(current_start).or_insert(current_id);
        }
    }
    if !current_instructions.is_empty() {
        blocks.push(DotBlock {
            id: current_id,
            start_address: current_start,
            instructions: current_instructions,
            successors: vec![],
        });
    }
    blocks
}

fn is_control_flow(m: &str) -> bool {
    matches!(m, "jmp" | "je" | "jne" | "jl" | "jle" | "jg" | "jge" | "jb" | "jbe" | "ja" | "jae" | "call" | "ret" | "retn" | "jmpq" | "b" | "bl" | "b.")
}

fn extract_target(operands: &str) -> Option<u64> {
    for part in operands.split(|c: char| c == ',' || c == ' ') {
        if let Some(hex) = part.trim().strip_prefix("0x") {
            if let Ok(addr) = u64::from_str_radix(hex, 16) {
                return Some(addr);
            }
        }
    }
    None
}

fn successors_for(insn: &Instruction, addr_to_id: &BTreeMap<u64, usize>) -> Vec<(usize, EdgeType)> {
    let mut out = Vec::new();
    let target = extract_target(&insn.operands);
    let m = insn.mnemonic.as_str();
    if m == "call" {
        if let Some(addr) = target {
            if let Some(&id) = addr_to_id.get(&addr) {
                out.push((id, EdgeType::Call));
            }
        }
    } else if m == "ret" || m == "retn" {
        out.push((usize::MAX, EdgeType::Return)); // sentinel
    } else if m.starts_with('j') || m == "b" || m == "bl" {
        if let Some(addr) = target {
            if let Some(&id) = addr_to_id.get(&addr) {
                out.push((id, EdgeType::Jump));
            }
        }
        // fall-through
        let next = insn.address + insn.size as u64;
        if let Some(&id) = addr_to_id.get(&next) {
            out.push((id, EdgeType::Fallthrough));
        }
    }
    out
}

/// Serializa un CFG (lista de DotBlock) a Graphviz (.dot).
pub fn to_dot(name: &str, blocks: &[DotBlock]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "digraph cfg_{} {{", sanitize(name));
    out.push_str("  rankdir=TB;\n");
    out.push_str("  node [shape=box, fontname=\"monospace\", fontsize=10];\n");
    out.push_str("  edge [fontname=\"monospace\", fontsize=9];\n\n");

    for block in blocks {
        let label = make_label(&block.instructions, block.id, block.start_address);
        out.push_str(&format!(
            "  block_{} [label=\"{}\"];\n",
            block.id,
            label.replace('"', "\\\"").replace('\n', "\\l")
        ));
    }

    out.push('\n');
    for block in blocks {
        for (target, edge) in &block.successors {
            let style = match edge {
                EdgeType::Fallthrough => "[color=gray]",
                EdgeType::Call => "[color=blue, style=dashed]",
                EdgeType::Return => "[color=red, style=dotted]",
                _ => "[color=black]",
            };
            if *target == usize::MAX {
                out.push_str(&format!(
                    "  block_{} -> RET {}\n",
                    block.id, style
                ));
            } else {
                out.push_str(&format!(
                    "  block_{} -> block_{} {}\n",
                    block.id, target, style
                ));
            }
        }
    }
    out.push_str("}\n");
    out
}

fn make_label(instructions: &[Instruction], id: usize, start: u64) -> String {
    let mut s = format!("B{}\\n{:#x}:\\n", id, start);
    for insn in instructions.iter().take(6) {
        s.push_str(&format!("  {:#x}: {}\\n", insn.address, insn_text(insn)));
    }
    if instructions.len() > 6 {
        s.push_str(&format!("  ... +{} more\n", instructions.len() - 6));
    }
    s
}

fn insn_text(insn: &Instruction) -> String {
    if insn.operands.is_empty() {
        insn.mnemonic.clone()
    } else {
        format!("{} {}", insn.mnemonic, insn.operands)
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

/// Pipeline: archivo + dirección → texto `.dot`.
pub fn bin_to_dot(info: &BinaryInfo, function: Option<u64>, max_funcs: usize) -> String {
    let disasm = match Disassembler::from_binary(info) {
        Ok(d) => d,
        Err(_) => return "".into(),
    };
    let instructions = match disasm.disassemble_binary(info) {
        Ok(i) => i,
        Err(_) => return "".into(),
    };

    if instructions.is_empty() {
        return "digraph cfg { }\n".into();
    }

    let mut sorted = instructions.clone();
    sorted.sort_by_key(|i| i.address);

    let addrs: Vec<u64> = if let Some(addr) = function {
        vec![addr]
    } else {
        sorted.iter().take(max_funcs).map(|i| i.address).collect()
    };

    let mut all_dot = String::new();
    for (i, func_addr) in addrs.iter().enumerate() {
        if i > 0 {
            all_dot.push('\n');
        }
        let func_insns: Vec<_> = sorted
            .iter()
            .filter(|insn| insn.address >= *func_addr)
            .take(200)
            .cloned()
            .collect();
        let blocks = build_cfg(*func_addr, &func_insns);
        all_dot.push_str(&to_dot(&format!("func_{:x}", func_addr), &blocks));
    }
    all_dot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_has_graph_header() {
        let blocks: Vec<DotBlock> = vec![];
        let s = to_dot("test", &blocks);
        assert!(s.starts_with("digraph"));
        assert!(s.trim_end().ends_with('}'));
    }

    #[test]
    fn sanitize_replaces_special_chars() {
        assert_eq!(sanitize("main.foo"), "main_foo");
    }
}
