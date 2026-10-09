//! # Type Recovery
//!
//! Inferencia de tipos para temporales de IR: por tamaño, uso (load/store, aritmética, ptr),
//! y heurísticas (constantes que son tamaños comunes, patrones de XMM, etc).
//!
//! Es una primera versión: suficiente para que el decompilador emita declaraciones
//! con tipos significativos (uint32_t, void*, etc.) en vez de `u{}_qword` opaco.

use bitwise_ir::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarType {
    Unknown(u8),
    Int(u8),     // signed int
    Uint(u8),    // unsigned int
    Pointer(u8), // puntero
    Float(u8),
    Void,
    Array(Box<VarType>, u64), // tipo base, count
    Struct(String, Vec<(String, VarType)>),
}

impl VarType {
    pub fn c_string(&self) -> String {
        match self {
            VarType::Unknown(_) => "void".into(),
            VarType::Void => "void".into(),
            VarType::Int(sz) | VarType::Uint(sz) => {
                let prefix = if matches!(self, VarType::Uint(_)) { "u" } else { "" };
                let bits = sz * 8;
                if bits == 0 {
                    "void".into()
                } else {
                    format!("{}{}int{}_t", prefix, if bits >= 32 { "" } else { "" }, bits)
                }
            }
            VarType::Pointer(sz) => {
                format!("void* /* ptr{} */", sz * 8)
            }
            VarType::Float(sz) => match sz {
                4 => "float".into(),
                _ => "double".into(),
            },
            VarType::Array(inner, n) => format!("{}[{}]", inner.c_string(), n),
            VarType::Struct(name, _) => format!("struct {}", name),
        }
    }

    pub fn size_bytes(&self) -> u8 {
        match self {
            VarType::Unknown(s) | VarType::Int(s) | VarType::Uint(s) | VarType::Pointer(s) | VarType::Float(s) => *s,
            VarType::Void => 0,
            VarType::Array(_, _) => 0,
            VarType::Struct(_, _) => 0,
        }
    }
}

/// Contexto de inferencia de tipos.
#[derive(Default, Clone)]
pub struct TypeContext {
    /// temp id -> VarType
    types: BTreeMap<u64, VarType>,
    /// dirección de global -> VarType
    globals: BTreeMap<String, VarType>,
}

impl TypeContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn infer_from_ir(&mut self, func: &IrFunction) {
        for block in &func.blocks {
            for inst in &block.instructions {
                let size = inst
                    .output
                    .as_ref()
                    .map(|v| v.size())
                    .unwrap_or(0);
                if let Some(Varnode::Temp(id, _)) = &inst.output {
                    let ty = match &inst.op {
                        PcodeOp::IntZext => VarType::Uint(size),
                        PcodeOp::IntSext => VarType::Int(size),
                        PcodeOp::Load => {
                            // load desde ptr → si el size es 8, casi siempre es un puntero
                            if size == 8 {
                                VarType::Pointer(8)
                            } else {
                                VarType::Uint(size)
                            }
                        }
                        PcodeOp::Store | PcodeOp::IntAdd | PcodeOp::IntSub => VarType::Uint(size),
                        PcodeOp::IntMul | PcodeOp::IntDiv | PcodeOp::IntDivU => VarType::Uint(size),
                        PcodeOp::IntAnd | PcodeOp::IntOr | PcodeOp::IntXor => VarType::Uint(size),
                        PcodeOp::IntShiftL | PcodeOp::IntShiftR | PcodeOp::IntShiftRA => {
                            VarType::Uint(size)
                        }
                        PcodeOp::IntEqual
                        | PcodeOp::IntNotEqual
                        | PcodeOp::IntLess
                        | PcodeOp::IntLessU
                        | PcodeOp::IntLessEq
                        | PcodeOp::IntLessEqU => VarType::Uint(1),
                        PcodeOp::Copy => VarType::Unknown(size),
                        PcodeOp::Call => {
                            // convención x86-64: resultado va a rax, uint64_t
                            VarType::Uint(8)
                        }
                        _ => VarType::Unknown(size),
                    };
                    self.types.insert(*id, ty);
                }
            }
        }
    }

    pub fn type_for_temp(&self, id: u64) -> Option<&VarType> {
        self.types.get(&id)
    }

    pub fn type_string_for_temp(&self, id: u64, fallback_size: u8) -> String {
        self.types
            .get(&id)
            .map(|t| t.c_string())
            .unwrap_or_else(|| VarType::Unknown(fallback_size).c_string())
    }

    pub fn size_for_temp(&self, id: u64) -> u8 {
        self.types
            .get(&id)
            .map(|t| t.size_bytes())
            .filter(|s| *s > 0)
            .unwrap_or(8)
    }

    /// Fuerza un tipo manual para un temp (re-tipeo interactivo).
    /// Acepta un string C (`uint32_t`, `int64_t`, `void*`, `float`, ...).
    pub fn force_type_string(&mut self, id: u64, type_str: &str) {
        let ty = match type_str {
            "uint8_t" => Some(VarType::Uint(1)),
            "uint16_t" => Some(VarType::Uint(2)),
            "uint32_t" => Some(VarType::Uint(4)),
            "uint64_t" => Some(VarType::Uint(8)),
            "int8_t" => Some(VarType::Int(1)),
            "int16_t" => Some(VarType::Int(2)),
            "int32_t" => Some(VarType::Int(4)),
            "int64_t" => Some(VarType::Int(8)),
            "void*" | "void *" => Some(VarType::Pointer(8)),
            "float" => Some(VarType::Float(4)),
            "double" => Some(VarType::Float(8)),
            "char*" | "char *" | "string" => Some(VarType::Pointer(1)),
            "void" => Some(VarType::Void),
            _ => None,
        };
        if let Some(t) = ty {
            self.types.insert(id, t);
        }
    }

    /// Devuelve el tipo actual de un temp como string C (o fallback).
    pub fn current_type_string(&self, id: u64, fallback_size: u8) -> String {
        self.type_string_for_temp(id, fallback_size)
    }

    /// Heurística: tipo de retorno = el output de la última instrucción que escribe
    /// a un registro que parezca return value (rax en x86-64).
    pub fn infer_return_type(&self, func: &IrFunction) -> String {
        // Buscar copy/return hacia rax
        let mut ret_size = 0u8;
        for block in &func.blocks {
            for inst in &block.instructions {
                if matches!(inst.op, PcodeOp::Return) {
                    // buscar copy a rax justo antes
                    for p in &block.instructions {
                        if let (Some(Varnode::Register(name, sz)), PcodeOp::Copy) =
                            (&p.output, &p.op)
                        {
                            if name == "rax" {
                                ret_size = ret_size.max(*sz);
                            }
                        }
                    }
                }
            }
        }
        if ret_size == 0 {
            "void".into()
        } else {
            format!("u{}int{}_t", "", ret_size * 8)
        }
    }
}
