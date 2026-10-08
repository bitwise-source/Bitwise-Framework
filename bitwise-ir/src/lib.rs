//! # Bitwise IR — Intermediate Representation
//!
//! Un lenguaje intermedio de tres direcciones inspirado en P-Code/Ghidra SLEIGH.
//! Capa de abstracción entre el desensamblador y el decompilador.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// Varnodes
// ============================================================================

/// Un varnode es una ubicación de datos: registro, temporal, constante, o memoria.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Varnode {
    /// Registro nativo (nombre como "rax", "rsp", "x0")
    Register(String, u8), // nombre, tamaño en bytes
    /// Variable temporal generada por el lifter (id único, tamaño)
    Temp(u64, u8),
    /// Constante inmediata (valor, tamaño en bytes)
    Constant(u64, u8),
    /// Acceso a memoria: base + offset * scale (base, offset, scale, size)
    Memory(Box<Varnode>, i64, u8, u8),
    /// Variable global con nombre
    Global(String, u64), // nombre, dirección
    /// Stack variable: offset desde frame pointer
    Stack(i64, u8),
}

impl Varnode {
    pub fn size(&self) -> u8 {
        match self {
            Varnode::Register(_, sz) | Varnode::Temp(_, sz) | Varnode::Constant(_, sz) => *sz,
            Varnode::Memory(_, _, _, sz) | Varnode::Stack(_, sz) => *sz,
            Varnode::Global(_, _) => 8,
        }
    }

    pub fn reg(name: &str, size: u8) -> Self {
        Varnode::Register(name.to_string(), size)
    }
    pub fn temp(id: u64, size: u8) -> Self {
        Varnode::Temp(id, size)
    }
    pub fn const_(val: u64, size: u8) -> Self {
        Varnode::Constant(val, size)
    }
    pub fn mem(base: Varnode, offset: i64, size: u8) -> Self {
        Varnode::Memory(Box::new(base), offset, 1, size)
    }
    pub fn stack(offset: i64, size: u8) -> Self {
        Varnode::Stack(offset, size)
    }
}

impl std::fmt::Display for Varnode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Varnode::Register(name, _) => write!(f, "{}", name),
            Varnode::Temp(id, _) => write!(f, "t{}", id),
            Varnode::Constant(v, _) => write!(f, "0x{:x}", v),
            Varnode::Memory(base, offset, _, _) => {
                let sign = if *offset >= 0 { "+" } else { "-" };
                write!(f, "[{}{}{}]", base, sign, offset.abs())
            }
            Varnode::Global(name, _) => write!(f, "&{}", name),
            Varnode::Stack(off, _) => write!(f, "stack[{}]", off),
        }
    }
}

// ============================================================================
// P-Code Operations
// ============================================================================

/// Operación en el lenguaje intermedio.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcodeOp {
    /// COPY: dst = src
    Copy,
    /// LOAD: dst = *src (cargar de memoria con tamaño implícito)
    Load,
    /// STORE: *dst = src (guardar en memoria)
    Store,

    // Aritméticas enteras
    IntAdd,
    IntSub,
    IntMul,
    IntDiv,    // signed
    IntDivU,   // unsigned
    IntMod,    // signed
    IntModU,   // unsigned
    IntNeg,
    IntAbs,

    // Bitwise
    IntAnd,
    IntOr,
    IntXor,
    IntNot,
    IntShiftL,
    IntShiftR, // logical
    IntShiftRA, // arithmetic

    // Comparaciones (producen bool: 0 o 1)
    IntEqual,
    IntNotEqual,
    IntLess,     // signed
    IntLessU,    // unsigned
    IntLessEq,   // signed
    IntLessEqU,  // unsigned

    // Zero-extend / sign-extend
    IntZext,     // zero-extend src to dst size
    IntSext,     // sign-extend src to dst size
    IntTrunc,    // truncate to smaller size

    // Control flow
    Branch,      // branch to target
    BranchCond,  // branch if src != 0, else fallthrough
    Call,        // call src, store return in dst
    Return,      // return src
    IndirectBranch, // jump through register

    // Special
    Nop,
    Unimplemented(String), // instrucción no soportada
}

impl PcodeOp {
    pub fn is_control_flow(&self) -> bool {
        matches!(self, PcodeOp::Branch | PcodeOp::BranchCond | PcodeOp::Call
            | PcodeOp::Return | PcodeOp::IndirectBranch)
    }

    pub fn is_binary(&self) -> bool {
        matches!(self,
            PcodeOp::IntAdd | PcodeOp::IntSub | PcodeOp::IntMul | PcodeOp::IntDiv
            | PcodeOp::IntDivU | PcodeOp::IntMod | PcodeOp::IntModU
            | PcodeOp::IntAnd | PcodeOp::IntOr | PcodeOp::IntXor
            | PcodeOp::IntShiftL | PcodeOp::IntShiftR | PcodeOp::IntShiftRA
            | PcodeOp::IntEqual | PcodeOp::IntNotEqual | PcodeOp::IntLess
            | PcodeOp::IntLessU | PcodeOp::IntLessEq | PcodeOp::IntLessEqU
        )
    }
}

impl std::fmt::Display for PcodeOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PcodeOp::Copy => "COPY",
            PcodeOp::Load => "LOAD",
            PcodeOp::Store => "STORE",
            PcodeOp::IntAdd => "ADD",
            PcodeOp::IntSub => "SUB",
            PcodeOp::IntMul => "MUL",
            PcodeOp::IntDiv => "SDIV",
            PcodeOp::IntDivU => "UDIV",
            PcodeOp::IntMod => "SMOD",
            PcodeOp::IntModU => "UMOD",
            PcodeOp::IntNeg => "NEG",
            PcodeOp::IntAbs => "ABS",
            PcodeOp::IntAnd => "AND",
            PcodeOp::IntOr => "OR",
            PcodeOp::IntXor => "XOR",
            PcodeOp::IntNot => "NOT",
            PcodeOp::IntShiftL => "SHL",
            PcodeOp::IntShiftR => "SHR",
            PcodeOp::IntShiftRA => "SAR",
            PcodeOp::IntEqual => "EQ",
            PcodeOp::IntNotEqual => "NEQ",
            PcodeOp::IntLess => "SLT",
            PcodeOp::IntLessU => "ULT",
            PcodeOp::IntLessEq => "SLE",
            PcodeOp::IntLessEqU => "ULE",
            PcodeOp::IntZext => "ZEXT",
            PcodeOp::IntSext => "SEXT",
            PcodeOp::IntTrunc => "TRUNC",
            PcodeOp::Branch => "BR",
            PcodeOp::BranchCond => "BRC",
            PcodeOp::Call => "CALL",
            PcodeOp::Return => "RET",
            PcodeOp::IndirectBranch => "IBR",
            PcodeOp::Nop => "NOP",
            PcodeOp::Unimplemented(s) => return write!(f, "???({})", s),
        };
        write!(f, "{}", s)
    }
}

// ============================================================================
// P-Code Instruction
// ============================================================================

/// Una instrucción P-Code: opcode + operandos.
/// Formato de tres direcciones con varnodes de entrada y salida.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcodeInst {
    pub address: u64,
    pub op: PcodeOp,
    /// Varnode de salida/destino (None para stores y branches)
    pub output: Option<Varnode>,
    /// Varnodes de entrada (0, 1, o 2)
    pub inputs: Vec<Varnode>,
}

impl PcodeInst {
    pub fn new(addr: u64, op: PcodeOp, output: Option<Varnode>, inputs: Vec<Varnode>) -> Self {
        Self { address: addr, op, output, inputs }
    }

    pub fn input0(&self) -> Option<&Varnode> { self.inputs.first() }
    pub fn input1(&self) -> Option<&Varnode> { self.inputs.get(1) }
}

impl std::fmt::Display for PcodeInst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "  {:016x}: ", self.address)?;
        if let Some(out) = &self.output {
            write!(f, "{} = ", out)?;
        }
        write!(f, "{}", self.op)?;
        for (i, inp) in self.inputs.iter().enumerate() {
            if i == 0 {
                write!(f, " {}", inp)?;
            } else {
                write!(f, ", {}", inp)?;
            }
        }
        Ok(())
    }
}

// ============================================================================
// IR Basic Block
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrBlock {
    pub id: usize,
    pub start_address: u64,
    pub instructions: Vec<PcodeInst>,
    pub successors: Vec<(usize, EdgeType)>, // (block_id, edge_type)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeType {
    Fallthrough,
    Jump,
    ConditionalTrue,
    ConditionalFalse,
    Call,
    Return,
}

// ============================================================================
// IR Function
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFunction {
    pub name: String,
    pub entry_address: u64,
    pub blocks: Vec<IrBlock>,
    /// Tabla de temporales → tipo sugerido
    pub temp_types: BTreeMap<u64, IrType>,
    /// Stack frame size
    pub frame_size: i64,
    /// Parámetros (nombre, offset desde base)
    pub parameters: Vec<(String, i64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrType {
    Unknown(u8),
    Int(u8),      // signed int de N bytes
    Uint(u8),     // unsigned int de N bytes
    Pointer(u8),  // puntero
    Float(u8),
    Void,
    Array(Box<IrType>, u64), // tipo base, count
    Struct(String, Vec<(String, IrType)>),
}

impl IrFunction {
    pub fn new(name: &str, entry: u64) -> Self {
        Self {
            name: name.to_string(),
            entry_address: entry,
            blocks: Vec::new(),
            temp_types: BTreeMap::new(),
            frame_size: 0,
            parameters: Vec::new(),
        }
    }

    /// Encuentra el bloque de entrada (el que contiene entry_address o el primero).
    pub fn entry_block(&self) -> Option<usize> {
        self.blocks.iter().position(|b| b.start_address == self.entry_address)
            .or_else(|| self.blocks.first().map(|b| b.id))
    }

    /// Recolecta todos los temporales usados.
    pub fn collect_temps(&self) -> Vec<u64> {
        let mut temps: Vec<u64> = Vec::new();
        for block in &self.blocks {
            for inst in &block.instructions {
                if let Some(Varnode::Temp(id, _)) = &inst.output {
                    temps.push(*id);
                }
                for inp in &inst.inputs {
                    if let Varnode::Temp(id, _) = inp {
                        temps.push(*id);
                    }
                }
            }
        }
        temps.sort();
        temps.dedup();
        temps
    }
}
