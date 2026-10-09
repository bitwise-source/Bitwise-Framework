//! Análisis estructural: Control Flow Graph y detección de funciones.

pub mod refs;
pub mod packer;
pub mod annotations;
pub mod cpp;
pub mod signatures;
pub mod dwarf;
pub mod web;
pub mod js_deobf;

use crate::arch::Instruction;
use std::collections::{BTreeMap, BTreeSet};

/// Nodo en el CFG.
#[derive(Debug, Clone)]
pub struct CfgNode {
    pub id: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<Instruction>,
    pub is_entry: bool,
}

/// Control Flow Graph de una función.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub name: String,
    pub entry_address: u64,
    pub nodes: Vec<CfgNode>,
    /// edges: (from_node_id, to_node_id, edge_type)
    pub edges: Vec<(usize, usize, EdgeType)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeType {
    Fallthrough,
    Jump,
    ConditionalTrue,
    ConditionalFalse,
    Call,
    Return,
}

impl ControlFlowGraph {
    pub fn new(name: &str, entry: u64) -> Self {
        Self {
            name: name.to_string(),
            entry_address: entry,
            nodes: vec![CfgNode {
                id: 0,
                start_address: entry,
                end_address: entry,
                instructions: vec![],
                is_entry: true,
            }],
            edges: vec![],
        }
    }

    /// Agrega un nodo al CFG.
    pub fn add_node(&mut self, start: u64, end: u64, instructions: Vec<Instruction>) -> usize {
        let id = self.nodes.len();
        self.nodes.push(CfgNode {
            id,
            start_address: start,
            end_address: end,
            instructions,
            is_entry: false,
        });
        id
    }

    /// Agrega un edge entre dos nodos.
    pub fn add_edge(&mut self, from: usize, to: usize, edge_type: EdgeType) {
        self.edges.push((from, to, edge_type));
    }
}

/// Bloque básico identificado en el binario.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_address: u64,
    pub end_address: u64,
    pub instruction_count: usize,
    pub successors: Vec<u64>,
    pub is_function_start: bool,
}

/// Detecta funciones por heurística (símbolos + prólogos + call-graph).
pub fn detect_functions(instructions: &[Instruction], symbols: &[crate::Symbol]) -> Vec<u64> {
    let mut function_starts: BTreeSet<u64> = BTreeSet::new();

    // Símbolos de función conocidos
    for sym in symbols {
        if matches!(sym.kind, crate::SymbolKind::Function) && sym.address > 0 {
            function_starts.insert(sym.address);
        }
    }

    // Heurísticas de prólogo
    // x86-64: push rbp; mov rbp, rsp
    // ARM64: stp x29, x30, [sp, #...]
    for window in instructions.windows(2) {
        let i0 = &window[0].mnemonic;
        let i1 = &window[1].mnemonic;

        let is_x86_prologue = (i0 == "push" && window[0].operands.contains("rbp"))
            && (i1 == "mov"
                && window[1].operands.contains("rbp")
                && window[1].operands.contains("rsp"));

        let is_arm64_prologue =
            i0 == "stp" && window[0].operands.contains("x29") && window[0].operands.contains("x30");

        if is_x86_prologue || is_arm64_prologue {
            function_starts.insert(window[0].address);
        }
    }

    // Call-graph: todo target directo de un call es inicio de función.
    // Es la técnica estándar (Ghidra/Rizin) y cubre binarios stripped.
    for addr in functions_from_calls(instructions) {
        function_starts.insert(addr);
    }

    // Si no hay funciones detectadas, la dirección más baja es entry
    if function_starts.is_empty() {
        if let Some(first) = instructions.first() {
            function_starts.insert(first.address);
        }
    }

    function_starts.into_iter().collect()
}

/// Extrae los targets de todos los `call` directos (inmediato) del binario.
/// Cada uno es un candidato a inicio de función — funciona sin símbolos.
pub fn functions_from_calls(instructions: &[Instruction]) -> Vec<u64> {
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    for insn in instructions {
        if insn.mnemonic == "call" || insn.mnemonic == "bl" {
            // target directo: primer operando hex
            for part in insn.operands.split(|c: char| c == ',' || c == ' ') {
                let part = part.trim();
                if let Some(hex) = part.strip_prefix("0x") {
                    if let Ok(addr) = u64::from_str_radix(hex, 16) {
                        // filtrar calls a PLT-stubs muy bajos o basura (0)
                        if addr > 0 {
                            targets.insert(addr);
                        }
                        break;
                    }
                }
            }
        }
    }
    targets.into_iter().collect()
}

/// Construye bloques básicos desde instrucciones y puntos de entrada de función.
pub fn build_basic_blocks(
    instructions: &[Instruction],
    function_starts: &[u64],
) -> Vec<BasicBlock> {
    if instructions.is_empty() {
        return vec![];
    }

    let func_set: BTreeSet<u64> = function_starts.iter().copied().collect();
    let mut blocks = Vec::new();
    let mut current_start = instructions[0].address;

    for window in instructions.windows(2) {
        let current = &window[0];
        let next = &window[1];

        let is_terminator = is_control_flow(&current.mnemonic);
        let is_next_func_start = func_set.contains(&next.address);

        if is_terminator || is_next_func_start {
            blocks.push(BasicBlock {
                start_address: current_start,
                end_address: current.address + current.size as u64,
                instruction_count: 0, // se llena después
                successors: if is_terminator {
                    extract_targets(current)
                } else {
                    vec![next.address]
                },
                is_function_start: func_set.contains(&current_start),
            });
            current_start = next.address;
        }
    }

    // Último bloque
    if let Some(last) = instructions.last() {
        blocks.push(BasicBlock {
            start_address: current_start,
            end_address: last.address + last.size as u64,
            instruction_count: 0,
            successors: vec![],
            is_function_start: func_set.contains(&current_start),
        });
    }

    blocks
}

fn is_control_flow(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "ret"
            | "retn"
            | "jmp"
            | "ja"
            | "jae"
            | "jb"
            | "jbe"
            | "jc"
            | "jcxz"
            | "je"
            | "jg"
            | "jge"
            | "jl"
            | "jle"
            | "jna"
            | "jnae"
            | "jnb"
            | "jnbe"
            | "jnc"
            | "jne"
            | "jng"
            | "jnge"
            | "jnl"
            | "jnle"
            | "jno"
            | "jnp"
            | "jns"
            | "jnz"
            | "jo"
            | "jp"
            | "jpe"
            | "jpo"
            | "js"
            | "jz"
            | "call"
            | "b"
            | "b."
            | "bl"
            | "blr"
            | "br"
            | "b.eq"
            | "b.ne"
            | "cbz"
            | "cbnz"
            | "tbz"
            | "tbnz"
            | "ret"
            | "b.ret"
    )
}

fn extract_targets(inst: &Instruction) -> Vec<u64> {
    // Simplificado: intenta parsear dirección hex de los operandos
    let mut targets = Vec::new();
    if inst.mnemonic == "call" || inst.mnemonic.starts_with('j') || inst.mnemonic == "b" {
        for part in inst.operands.split(',') {
            let part = part.trim();
            if let Some(hex) = part.strip_prefix("0x") {
                if let Ok(addr) = u64::from_str_radix(hex, 16) {
                    targets.push(addr);
                }
            }
        }
    }
    targets
}
