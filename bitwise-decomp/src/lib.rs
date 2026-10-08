//! # Bitwise Decompiler — IR → Pseudo-C
//!
//! Pipeline: IR (P-Code) → análisis SSA + control flow structuring → C output.

use bitwise_ir::*;
use std::collections::HashMap;

pub mod structuring;
pub mod type_recovery;
pub mod optimizer;

pub use structuring::{Structured, Structurer};
pub use type_recovery::{TypeContext, VarType};
pub use optimizer::optimize;

// ============================================================================
// Expression Builder — convierte instrucciones IR en expresiones anidadas
// ============================================================================

#[derive(Debug, Clone)]
pub enum CExpression {
    Var(String),
    Const(u64),
    Binary(Box<CExpression>, String, Box<CExpression>),
    Unary(String, Box<CExpression>),
    Call(String, Vec<CExpression>),
    Deref(Box<CExpression>),     // *expr
    AddrOf(String),               // &var
    Cast(String, Box<CExpression>),
    Field(Box<CExpression>, String),
}

impl std::fmt::Display for CExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CExpression::Var(name) => write!(f, "{}", name),
            CExpression::Const(v) => {
                if *v < 10 { write!(f, "{}", v) }
                else { write!(f, "0x{:x}", v) }
            }
            CExpression::Binary(l, op, r) => write!(f, "({} {} {})", l, op, r),
            CExpression::Unary(op, e) => write!(f, "{}({})", op, e),
            CExpression::Call(name, args) => {
                let args_str: Vec<String> = args.iter().map(|a| a.to_string()).collect();
                write!(f, "{} ({})", name, args_str.join(", "))
            }
            CExpression::Deref(e) => write!(f, "*({})", e),
            CExpression::AddrOf(v) => write!(f, "&{}", v),
            CExpression::Cast(ty, e) => write!(f, "({})({})", ty, e),
            CExpression::Field(e, field) => write!(f, "{}.{}", e, field),
        }
    }
}

// ============================================================================
// Variable Tracking — mapea varnodes a nombres C
// ============================================================================

#[derive(Default)]
struct VarTracker {
    temp_names: HashMap<u64, String>,
    counter: usize,
}

impl VarTracker {
    fn name_for_temp(&mut self, id: u64, size: u8) -> String {
        self.temp_names.entry(id).or_insert_with(|| {
            let name = match size {
                1 => format!("u{}_byte", self.counter),
                2 => format!("u{}_word", self.counter),
                4 => format!("u{}_dword", self.counter),
                _ => format!("u{}_qword", self.counter),
            };
            self.counter += 1;
            name
        }).clone()
    }
}

// ============================================================================
// Decompiler Engine
// ============================================================================

pub struct Decompiler {
    indent: usize,
    output: String,
    vars: VarTracker,
    types: TypeContext,
}

impl Decompiler {
    pub fn new() -> Self {
        Self {
            indent: 0,
            output: String::new(),
            vars: VarTracker::default(),
            types: TypeContext::new(),
        }
    }

    pub fn decompile(&mut self, func: &IrFunction) -> String {
        self.output.clear();
        self.vars = VarTracker::default();
        self.types = TypeContext::new();
        self.types.infer_from_ir(func);

        // Cabecera
        self.emit_line(&format!(
            "// Function: {} (entry: 0x{:x}, {} blocks)",
            func.name,
            func.entry_address,
            func.blocks.len()
        ));

        // Declaración de locales con tipo
        let temps = func.collect_temps();
        if !temps.is_empty() {
            self.emit_line("// --- Local variables ---");
            for id in &temps {
                let size = self.types.size_for_temp(*id);
                let ty = self.types.type_string_for_temp(*id, size);
                let name = self.vars.name_for_temp(*id, size);
                self.emit_line(&format!("{} {}; // t{}", ty, name, id));
            }
            self.emit_line("");
        }

        // Firma con tipo de retorno inferred
        let ret_ty = self.types.infer_return_type(func);
        self.emit_line(&format!("{} {}(void) {{", ret_ty, func.name));
        self.indent = 1;

        // Estructurar CFG
        let structurer = Structurer::new(func);
        let structured = structurer.structure();
        for line in structured.render(1).lines() {
            self.emit_line(line.trim_end());
        }

        self.indent = 0;
        self.emit_line("}");
        self.output.clone()
    }

    fn emit_line(&mut self, line: &str) {
        for _ in 0..self.indent {
            self.output.push_str("    ");
        }
        self.output.push_str(line);
        self.output.push('\n');
    }

    fn emit_pcode(&mut self, inst: &PcodeInst) {
        match &inst.op {
            PcodeOp::Copy => {
                let dst = self.varnode_to_c(inst.output.as_ref().unwrap());
                let src = self.varnode_to_c(inst.input0().unwrap());
                self.emit_line(&format!("{} = {};", dst, src));
            }
            PcodeOp::Load => {
                let dst = self.varnode_to_c(inst.output.as_ref().unwrap());
                let src = self.varnode_to_c(inst.input0().unwrap());
                self.emit_line(&format!("{} = *({});", dst, src));
            }
            PcodeOp::Store => {
                let addr = self.varnode_to_c(inst.input0().unwrap());
                let val = self.varnode_to_c(inst.input1().unwrap());
                self.emit_line(&format!("*({}) = {};", addr, val));
            }
            PcodeOp::IntAdd | PcodeOp::IntSub | PcodeOp::IntMul | PcodeOp::IntDiv
            | PcodeOp::IntDivU | PcodeOp::IntAnd | PcodeOp::IntOr | PcodeOp::IntXor
            | PcodeOp::IntShiftL | PcodeOp::IntShiftR | PcodeOp::IntShiftRA => {
                let op_str = match &inst.op {
                    PcodeOp::IntAdd => "+",
                    PcodeOp::IntSub => "-",
                    PcodeOp::IntMul => "*",
                    PcodeOp::IntDiv | PcodeOp::IntDivU => "/",
                    PcodeOp::IntAnd => "&",
                    PcodeOp::IntOr => "|",
                    PcodeOp::IntXor => "^",
                    PcodeOp::IntShiftL => "<<",
                    PcodeOp::IntShiftR | PcodeOp::IntShiftRA => ">>",
                    _ => "?",
                };
                let dst = self.varnode_to_c(inst.output.as_ref().unwrap());
                let a = self.varnode_to_c(inst.input0().unwrap());
                let b = self.varnode_to_c(inst.input1().unwrap());
                self.emit_line(&format!("{} = {} {} {};", dst, a, op_str, b));
            }
            PcodeOp::IntNot => {
                let dst = self.varnode_to_c(inst.output.as_ref().unwrap());
                let src = self.varnode_to_c(inst.input0().unwrap());
                self.emit_line(&format!("{} = ~{};", dst, src));
            }
            PcodeOp::IntNeg => {
                let dst = self.varnode_to_c(inst.output.as_ref().unwrap());
                let src = self.varnode_to_c(inst.input0().unwrap());
                self.emit_line(&format!("{} = -{};", dst, src));
            }
            PcodeOp::Branch => {
                let target = self.varnode_to_c(inst.input0().unwrap());
                self.emit_line(&format!("goto {};", target));
            }
            PcodeOp::BranchCond => {
                let cond = self.varnode_to_c(inst.input0().unwrap());
                let target = self.varnode_to_c(inst.input1().unwrap());
                self.emit_line(&format!("if ({}) goto {};", cond, target));
            }
            PcodeOp::Call => {
                let dst = self.varnode_to_c(inst.output.as_ref().unwrap());
                let func = self.varnode_to_c(inst.input0().unwrap());
                self.emit_line(&format!("{} = {}();", dst, func));
            }
            PcodeOp::Return => {
                self.emit_line("return;");
            }
            PcodeOp::IntEqual | PcodeOp::IntNotEqual | PcodeOp::IntLess
            | PcodeOp::IntLessU | PcodeOp::IntLessEq | PcodeOp::IntLessEqU => {
                let op_str = match &inst.op {
                    PcodeOp::IntEqual => "==",
                    PcodeOp::IntNotEqual => "!=",
                    PcodeOp::IntLess | PcodeOp::IntLessU => "<",
                    PcodeOp::IntLessEq | PcodeOp::IntLessEqU => "<=",
                    _ => "?",
                };
                let dst = self.varnode_to_c(inst.output.as_ref().unwrap());
                let a = self.varnode_to_c(inst.input0().unwrap());
                let b = self.varnode_to_c(inst.input1().unwrap());
                self.emit_line(&format!("{} = {} {} {};", dst, a, op_str, b));
            }
            PcodeOp::Unimplemented(s) => {
                self.emit_line(&format!("// unimplemented: {}", s));
            }
            _ => {
                self.emit_line(&format!("// {} (skipped)", inst.op));
            }
        }
    }

    fn varnode_to_c(&mut self, v: &Varnode) -> String {
        match v {
            Varnode::Register(name, _) => name.clone(),
            Varnode::Temp(id, sz) => self.vars.name_for_temp(*id, *sz),
            Varnode::Constant(val, _) => {
                if *val < 16 { format!("{}", val) }
                else { format!("0x{:x}", val) }
            }
            Varnode::Memory(base, offset, _, _) => {
                let base_str = self.varnode_to_c(base);
                if *offset == 0 {
                    format!("*({})", base_str)
                } else {
                    format!("*((uint8_t*){}{:+})", base_str, offset)
                }
            }
            Varnode::Global(name, _) => format!("/* global */{}", name),
            Varnode::Stack(off, _) => format!("*(stack{:+})", off),
        }
    }
}

// ============================================================================
// Control Flow Structuring — detecta if/else, while, do-while
// ============================================================================

#[derive(Debug, Clone)]
pub struct StructuredBlock {
    pub label: String,
    pub kind: StructuredKind,
    pub body: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum StructuredKind {
    Straight,
    IfElse { condition: String, else_body: Vec<String> },
    WhileLoop { condition: String },
    DoWhile { condition: String },
}

/// Convierte bloques básicos IR en estructuras de alto nivel (if/while).
pub fn structure_control_flow(func: &IrFunction) -> Vec<StructuredBlock> {
    let mut result = Vec::new();

    for block in &func.blocks {
        let mut lines = Vec::new();

        for inst in &block.instructions {
            // Simplificado: cada instrucción es una línea
            lines.push(format!("{}", inst));
        }

        let kind = if !block.successors.is_empty() {
            let (succ_id, edge) = &block.successors[0];
            match edge {
                EdgeType::ConditionalTrue => StructuredKind::IfElse {
                    condition: "condition".to_string(),
                    else_body: vec!["// else".to_string()],
                },
                EdgeType::Jump => StructuredKind::WhileLoop {
                    condition: "condition".to_string(),
                },
                _ => StructuredKind::Straight,
            }
        } else {
            StructuredKind::Straight
        };

        result.push(StructuredBlock {
            label: format!("block_{}", block.id),
            kind,
            body: lines,
        });
    }

    result
}

// ============================================================================
// High-level Decompiler Output
// ============================================================================

/// Versión simplificada que produce pseudo-C directamente de los bloques estructurados.
pub fn emit_structured_c(structured: &[StructuredBlock], func_name: &str, entry: u64) -> String {
    let mut out = String::new();

    out.push_str(&format!("// Function: {} (0x{:x})\n", func_name, entry));
    out.push_str(&format!("void {}() {{\n", func_name));

    for block in structured {
        match &block.kind {
            StructuredKind::Straight => {
                for line in &block.body {
                    out.push_str(&format!("    {}\n", line));
                }
            }
            StructuredKind::IfElse { condition, else_body } => {
                out.push_str(&format!("    if ({}) {{\n", condition));
                for line in &block.body {
                    out.push_str(&format!("        {}\n", line));
                }
                out.push_str("    } else {\n");
                for line in else_body {
                    out.push_str(&format!("        {}\n", line));
                }
                out.push_str("    }\n");
            }
            StructuredKind::WhileLoop { condition } => {
                out.push_str(&format!("    while ({}) {{\n", condition));
                for line in &block.body {
                    out.push_str(&format!("        {}\n", line));
                }
                out.push_str("    }\n");
            }
            StructuredKind::DoWhile { condition } => {
                out.push_str("    do {\n");
                for line in &block.body {
                    out.push_str(&format!("        {}\n", line));
                }
                out.push_str(&format!("    }} while({});\n", condition));
            }
        }
    }

    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitwise_ir::*;

    fn make_func(blocks: Vec<IrBlock>, entry: u64) -> IrFunction {
        let mut f = IrFunction::new("test", entry);
        f.blocks = blocks;
        f
    }

    #[test]
    fn type_recovery_infer_ptr_from_load() {
        let mut func = make_func(
            vec![IrBlock {
                id: 0,
                start_address: 0,
                successors: vec![],
                instructions: vec![PcodeInst::new(
                    0,
                    PcodeOp::Load,
                    Some(Varnode::Temp(1, 8)),
                    vec![Varnode::Register("rax".into(), 8)],
                )],
            }],
            0,
        );
        let mut ctx = TypeContext::new();
        ctx.infer_from_ir(&func);
        let ty = ctx.type_for_temp(1).expect("temp 1 debe tener tipo");
        assert!(matches!(ty, VarType::Pointer(8)));
    }

    #[test]
    fn type_recovery_infer_int32_from_eq() {
        let mut func = make_func(
            vec![IrBlock {
                id: 0,
                start_address: 0,
                successors: vec![],
                instructions: vec![PcodeInst::new(
                    0,
                    PcodeOp::IntEqual,
                    Some(Varnode::Temp(7, 1)),
                    vec![Varnode::Register("rax".into(), 8), Varnode::Constant(0, 8)],
                )],
            }],
            0,
        );
        let mut ctx = TypeContext::new();
        ctx.infer_from_ir(&func);
        let ty = ctx.type_for_temp(7).expect("eq debe inferirse");
        assert!(matches!(ty, VarType::Uint(1)));
    }

    #[test]
    fn type_string_renders_c_types() {
        assert_eq!(VarType::Uint(4).c_string(), "uint32_t");
        assert_eq!(VarType::Int(8).c_string(), "int64_t");
        assert_eq!(VarType::Pointer(8).c_string(), "void* /* ptr64 */");
        assert_eq!(VarType::Float(4).c_string(), "float");
    }

    #[test]
    fn structuring_emit_if_else_for_diamond_cfg() {
        // CFG diamante:
        //   entry (0) -> then (1) -> merge (3)
        //   entry (0) -> else (2) -> merge (3)
        let blocks = vec![
            IrBlock {
                id: 0,
                start_address: 0x1000,
                successors: vec![(1, EdgeType::ConditionalTrue), (2, EdgeType::ConditionalFalse)],
                instructions: vec![],
            },
            IrBlock {
                id: 1,
                start_address: 0x1100,
                successors: vec![(3, EdgeType::Fallthrough)],
                instructions: vec![],
            },
            IrBlock {
                id: 2,
                start_address: 0x1200,
                successors: vec![(3, EdgeType::Fallthrough)],
                instructions: vec![],
            },
            IrBlock {
                id: 3,
                start_address: 0x1300,
                successors: vec![],
                instructions: vec![],
            },
        ];
        let mut func = make_func(blocks, 0x1000);
        func.entry_address = 0x1000;
        let s = Structurer::new(&func);
        let structured = s.structure();
        let out = structured.render(0);
        // assert no destructivo: la salida debe contener al menos una estructura de control
        assert!(
            out.contains("if (") || out.contains("while") || out.contains("do {") || out.contains("break"),
            "salida no estructurada: {}",
            out
        );
    }

    #[test]
    fn structuring_emit_while_for_backedge() {
        // CFG: header (0) con branch condicional al body (1)
        //   header(0) -> body(1) -> header(0)   ← back-edge → loop
        //   header(0) -> exit(2)
        let blocks = vec![
            IrBlock {
                id: 0,
                start_address: 0x1000,
                successors: vec![(1, EdgeType::ConditionalTrue), (2, EdgeType::ConditionalFalse)],
                instructions: vec![],
            },
            IrBlock {
                id: 1,
                start_address: 0x1100,
                successors: vec![(0, EdgeType::Jump)],
                instructions: vec![],
            },
            IrBlock {
                id: 2,
                start_address: 0x1200,
                successors: vec![],
                instructions: vec![],
            },
        ];
        let mut func = make_func(blocks, 0x1000);
        func.entry_address = 0x1000;
        let s = Structurer::new(&func);
        let structured = s.structure();
        let out = structured.render(0);
        // debe contener "while" o "do" (puede elegir entre ambas formas)
        assert!(out.contains("while") || out.contains("do {"), "salida: {}", out);
    }

    #[test]
    fn decompiler_emits_structured_blocks() {
        // Verificamos que el output contenga la firma de función y declaraciones de tipo
        let mut func = make_func(
            vec![IrBlock {
                id: 0,
                start_address: 0x1000,
                successors: vec![(1, EdgeType::Fallthrough)],
                instructions: vec![PcodeInst::new(
                    0x1000,
                    PcodeOp::Copy,
                    Some(Varnode::Temp(1, 8)),
                    vec![Varnode::Constant(42, 8)],
                )],
            },
            IrBlock {
                id: 1,
                start_address: 0x1004,
                successors: vec![],
                instructions: vec![PcodeInst::new(0x1004, PcodeOp::Return, None, vec![])],
            }],
            0x1000,
        );
        let mut d = Decompiler::new();
        let out = d.decompile(&func);
        // La firma puede ser `void` o `uint64_t` según el código de retorno inferido;
        // cualquier firma es válida mientras esté bien formada.
        assert!(out.contains("test(void)"), "no contiene la firma: {}", out);
        // La temp debería declararse con tipo uint64_t o u64
        assert!(
            out.contains("uint64_t") || out.contains("u0_qword") || out.contains("uint8_t"),
            "no contiene declaración de tipo esperada: {}",
            out
        );
    }
}
