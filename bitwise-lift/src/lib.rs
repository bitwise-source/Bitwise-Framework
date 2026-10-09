//! # Bitwise Lifter — Native → IR
//!
//! Convierte instrucciones nativas (x86-64, ARM64) a P-Code IR usando
//! los detalles arquitecturales de Capstone.

use bitwise_core::arch::Instruction;
use bitwise_ir::*;
use capstone::prelude::*;
use std::collections::HashMap;

/// Configuración de registro para lifting.
pub struct RegisterMap {
    /// Mapa de nombre de registro Capstone → Varnode
    regs: HashMap<String, Varnode>,
    pointer_size: u8,
}

impl RegisterMap {
    pub fn x86_64() -> Self {
        let mut regs = HashMap::new();
        for (name, sz) in [
            ("rax", 8), ("rbx", 8), ("rcx", 8), ("rdx", 8),
            ("rsi", 8), ("rdi", 8), ("rbp", 8), ("rsp", 8),
            ("r8", 8), ("r9", 8), ("r10", 8), ("r11", 8),
            ("r12", 8), ("r13", 8), ("r14", 8), ("r15", 8),
            ("rip", 8),
            ("eax", 4), ("ebx", 4), ("ecx", 4), ("edx", 4),
            ("esi", 4), ("edi", 4), ("ebp", 4), ("esp", 4),
            ("r8d", 4), ("r9d", 4), ("r10d", 4), ("r11d", 4),
            ("r12d", 4), ("r13d", 4), ("r14d", 4), ("r15d", 4),
            ("ax", 2), ("bx", 2), ("cx", 2), ("dx", 2),
            ("si", 2), ("di", 2), ("bp", 2), ("sp", 2),
            ("al", 1), ("bl", 1), ("cl", 1), ("dl", 1),
            ("ah", 1), ("bh", 1), ("ch", 1), ("dh", 1),
            ("sil", 1), ("dil", 1), ("bpl", 1), ("spl", 1),
            ("eflags", 4), ("rflags", 8),
        ] {
            regs.insert(name.to_string(), Varnode::reg(name, sz));
        }
        Self { regs, pointer_size: 8 }
    }

    pub fn aarch64() -> Self {
        let mut regs = HashMap::new();
        for i in 0..31 {
            regs.insert(format!("x{}", i), Varnode::reg(&format!("x{}", i), 8));
            regs.insert(format!("w{}", i), Varnode::reg(&format!("w{}", i), 4));
        }
        regs.insert("sp".into(), Varnode::reg("sp", 8));
        regs.insert("pc".into(), Varnode::reg("pc", 8));
        regs.insert("nzcv".into(), Varnode::reg("nzcv", 4));
        Self { regs, pointer_size: 8 }
    }

    pub fn get(&self, name: &str) -> Option<Varnode> {
        self.regs.get(name).cloned()
    }

    pub fn get_size(&self, name: &str) -> u8 {
        self.regs.get(name).map(|v| v.size()).unwrap_or(self.pointer_size)
    }
}

/// Lifter: convierte instrucciones nativas a IR.
pub struct Lifter {
    regs: RegisterMap,
    temp_counter: u64,
    output: Vec<PcodeInst>,
    current_addr: u64,
    arch: ArchKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ArchKind {
    X86_64,
    AArch64,
}

impl Lifter {
    pub fn new(regs: RegisterMap) -> Self {
        let arch = if regs.get("rax").is_some() { ArchKind::X86_64 } else { ArchKind::AArch64 };
        Self { regs, temp_counter: 1000, output: Vec::new(), current_addr: 0, arch }
    }

    pub fn with_arch(regs: RegisterMap, arch: ArchKind) -> Self {
        Self { regs, temp_counter: 1000, output: Vec::new(), current_addr: 0, arch }
    }

    fn new_temp(&mut self, size: u8) -> Varnode {
        let id = self.temp_counter;
        self.temp_counter += 1;
        Varnode::temp(id, size)
    }

    fn emit(&mut self, op: PcodeOp, output: Option<Varnode>, inputs: Vec<Varnode>) {
        self.output.push(PcodeInst::new(self.current_addr, op, output, inputs));
    }

    /// Lift de una instrucción nativa completa.
    pub fn lift_instruction(&mut self, inst: &Instruction) {
        self.current_addr = inst.address;
        // Usamos un enfoque simplificado: parsear mnemónico y operandos
        let mnemonic = inst.mnemonic.as_str();
        let ops = &inst.operands;

        match mnemonic {
            "mov" | "movabs" => self.lift_mov(ops),
            "push" => self.lift_push(ops),
            "pop" => self.lift_pop(ops),
            "add" => self.lift_binary(PcodeOp::IntAdd, ops),
            "sub" => self.lift_binary(PcodeOp::IntSub, ops),
            "imul" | "mul" => self.lift_binary(PcodeOp::IntMul, ops),
            "idiv" | "div" => self.lift_binary(PcodeOp::IntDiv, ops),
            "sdiv" => self.lift_binary(PcodeOp::IntDiv, ops),
            "udiv" => self.lift_binary(PcodeOp::IntDivU, ops),
            "and" => self.lift_binary(PcodeOp::IntAnd, ops),
            "or" | "orr" => self.lift_binary(PcodeOp::IntOr, ops),
            "xor" | "eor" => self.lift_binary(PcodeOp::IntXor, ops),
            "mvn" => self.lift_unary(PcodeOp::IntNot, ops),
            "not" => self.lift_unary(PcodeOp::IntNot, ops),
            "neg" => self.lift_unary(PcodeOp::IntNeg, ops),
            "shl" | "sal" | "lsl" => self.lift_binary(PcodeOp::IntShiftL, ops),
            "shr" | "lsr" => self.lift_binary(PcodeOp::IntShiftR, ops),
            "sar" | "asr" => self.lift_binary(PcodeOp::IntShiftRA, ops),
            "ldr" => self.lift_arm64_ldr(ops),
            "str" => self.lift_arm64_str(ops),
            "ldrb" => self.lift_arm64_ldr_size(ops, 1),
            "strb" => self.lift_arm64_str_size(ops, 1),
            "ldrh" => self.lift_arm64_ldr_size(ops, 2),
            "strh" => self.lift_arm64_str_size(ops, 2),
            "ldrsb" => self.lift_arm64_ldr_size(ops, 1),
            "ldrsw" => self.lift_arm64_ldr_size(ops, 4),
            "br" => self.lift_arm64_br(ops),
            "blr" => self.lift_arm64_blr(ops),
            "svc" => self.lift_arm64_svc(),
            "cmp" => self.lift_cmp(ops),
            "test" | "tst" => self.lift_test(ops),
            "lea" => self.lift_lea(ops),
            "call" => self.lift_call(ops),
            "jmp" | "jmpq" => self.lift_jmp(ops),
            "ret" | "retn" => self.lift_ret(),
            "je" | "jz" => self.lift_cond_branch(ops, "eq"),
            "jne" | "jnz" => self.lift_cond_branch(ops, "ne"),
            "jl" | "jnge" => self.lift_cond_branch(ops, "slt"),
            "jle" | "jng" => self.lift_cond_branch(ops, "sle"),
            "jg" | "jnle" => self.lift_cond_branch(ops, "sgt"),
            "jge" | "jnl" => self.lift_cond_branch(ops, "sge"),
            "jb" | "jnae" | "jc" => self.lift_cond_branch(ops, "ult"),
            "jbe" | "jna" => self.lift_cond_branch(ops, "ule"),
            "ja" | "jnbe" => self.lift_cond_branch(ops, "ugt"),
            "jae" | "jnb" | "jnc" => self.lift_cond_branch(ops, "uge"),
            "nop" | "endbr64" | "endbr32" => {
                self.emit(PcodeOp::Nop, None, vec![]);
            }
            "leave" => {
                // leave = mov rsp, rbp; pop rbp
                let rsp = self.regs.get("rsp").unwrap();
                let rbp = self.regs.get("rbp").unwrap();
                let rsp8 = self.regs.get("rsp").unwrap();
                self.emit(PcodeOp::Copy, Some(rbp.clone()), vec![rsp.clone()]);
                self.emit(PcodeOp::Load, Some(rbp), vec![Varnode::mem(rsp8, 0, 8)]);
            }
            "stp" => self.lift_arm64_stp(ops),
            "ldp" => self.lift_arm64_ldp(ops),
            "adrp" | "adr" => self.lift_arm64_adrp(ops),
            "cbz" | "cbnz" => self.lift_arm64_cbz(ops, mnemonic == "cbnz"),
            "b.eq" | "b.ne" | "b.lt" | "b.le" | "b.gt" | "b.ge" | "b.hi" | "b.ls" | "b.cc" | "b.cs"
            | "b.eq" | "b.ne" | "b.mi" | "b.pl" | "b.vs" | "b.vc" => self.lift_arm64_bcond(ops),
            _ => {
                self.emit(PcodeOp::Unimplemented(mnemonic.to_string()), None, vec![]);
            }
        }
    }

    fn lift_mov(&mut self, ops: &str) {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 { return; }
        let dst = self.parse_operand(parts[0]);
        let src = self.parse_operand(parts[1]);
        let sz = dst.as_ref().map(|v| v.size()).unwrap_or(8);

        if let (Some(d), Some(s)) = (&dst, &src) {
            if matches!(s, Varnode::Memory(..)) {
                let t = self.new_temp(sz);
                self.emit(PcodeOp::Load, Some(t.clone()), vec![s.clone()]);
                self.emit(PcodeOp::Copy, Some(d.clone()), vec![t]);
            } else {
                self.emit(PcodeOp::Copy, Some(d.clone()), vec![s.clone()]);
            }
        }
    }

    fn lift_push(&mut self, ops: &str) {
        if let Some(src) = self.parse_operand(ops.trim()) {
            let sz = src.size().max(8); // push siempre es 8 bytes en x86-64
            let rsp = self.regs.get("rsp").unwrap();
            // rsp = rsp - sz
            let new_rsp = self.new_temp(8);
            self.emit(PcodeOp::IntSub, Some(new_rsp.clone()), vec![
                rsp.clone(), Varnode::const_(sz as u64, 8),
            ]);
            self.emit(PcodeOp::Copy, Some(rsp.clone()), vec![new_rsp]);
            // [rsp] = src
            let rsp2 = self.regs.get("rsp").unwrap();
            self.emit(PcodeOp::Store, None, vec![
                Varnode::mem(rsp2, 0, sz), src,
            ]);
        }
    }

    fn lift_pop(&mut self, ops: &str) {
        if let Some(dst) = self.parse_operand(ops.trim()) {
            let sz = dst.size().max(8);
            let rsp = self.regs.get("rsp").unwrap();
            // dst = [rsp]
            let t = self.new_temp(sz);
            self.emit(PcodeOp::Load, Some(t.clone()), vec![
                Varnode::mem(rsp.clone(), 0, sz)
            ]);
            self.emit(PcodeOp::Copy, Some(dst), vec![t]);
            // rsp = rsp + sz
            let new_rsp = self.new_temp(8);
            self.emit(PcodeOp::IntAdd, Some(new_rsp.clone()), vec![
                rsp.clone(), Varnode::const_(sz as u64, 8),
            ]);
            self.emit(PcodeOp::Copy, Some(rsp), vec![new_rsp]);
        }
    }

    fn lift_binary(&mut self, op: PcodeOp, ops: &str) {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 { return; }
        let dst = self.parse_operand(parts[0]);
        let src = self.parse_operand(parts[1]);
        if let (Some(d), Some(s)) = (&dst, &src) {
            let sz = d.size();
            let t = self.new_temp(sz);
            self.emit(op.clone(), Some(t.clone()), vec![d.clone(), s.clone()]);
            self.emit(PcodeOp::Copy, Some(d.clone()), vec![t]);
        }
    }

    fn lift_unary(&mut self, op: PcodeOp, ops: &str) {
        if let Some(dst) = self.parse_operand(ops.trim()) {
            let sz = dst.size();
            let t = self.new_temp(sz);
            self.emit(op, Some(t.clone()), vec![dst.clone()]);
            self.emit(PcodeOp::Copy, Some(dst), vec![t]);
        }
    }

    fn lift_cmp(&mut self, _ops: &str) {
        // cmp a, b → guarda resultado en flags
        // Se implementa como operación fantasma; el branch condicional leerá el flag virtual
        let fl = self.regs.get("eflags").unwrap_or(Varnode::temp(9999, 4));
        self.emit(PcodeOp::Nop, Some(fl), vec![]);
    }

    fn lift_test(&mut self, _ops: &str) {
        let fl = self.regs.get("eflags").unwrap_or(Varnode::temp(9999, 4));
        self.emit(PcodeOp::Nop, Some(fl), vec![]);
    }

    fn lift_lea(&mut self, ops: &str) {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 { return; }
        if let Some(dst) = self.parse_operand(parts[0]) {
            // LEA simplificado: parsear [base + index*scale + disp]
            let src = self.parse_operand(parts[1]);
            if let Some(s) = src {
                self.emit(PcodeOp::Copy, Some(dst), vec![s]);
            }
        }
    }

    fn lift_call(&mut self, ops: &str) {
        if let Some(target) = self.parse_operand(ops.trim()) {
            // El valor de retorno va a rax (simplificado)
            let rax = self.regs.get("rax").unwrap();
            let dummy_ret = self.new_temp(8);
            self.emit(PcodeOp::Call, Some(dummy_ret.clone()), vec![target]);
            // El return value real se asigna a rax como efecto secundario
            self.emit(PcodeOp::Copy, Some(rax), vec![dummy_ret]);
        }
    }

    fn lift_jmp(&mut self, ops: &str) {
        if let Some(target) = self.parse_operand(ops.trim()) {
            self.emit(PcodeOp::Branch, None, vec![target]);
        }
    }

    fn lift_ret(&mut self) {
        self.emit(PcodeOp::Return, None, vec![]);
    }

    fn lift_cond_branch(&mut self, ops: &str, _cond: &str) {
        if let Some(target) = self.parse_operand(ops.trim()) {
            // La condición ya fue seteada por cmp/test; usamos el flag virtual
            let fl = self.regs.get("eflags").unwrap_or(Varnode::temp(9999, 4));
            self.emit(PcodeOp::BranchCond, None, vec![fl, target]);
        }
    }

    /// Parsea un operando textual a Varnode.
    fn parse_operand(&self, op: &str) -> Option<Varnode> {
        let op = op.trim();

        // Constante inmediata
        if let Some(hex) = op.strip_prefix("0x") {
            let val = u64::from_str_radix(hex, 16).ok()?;
            return Some(Varnode::const_(val, 8));
        }
        if let Ok(val) = op.parse::<i64>() {
            return Some(Varnode::const_(val as u64, 8));
        }

        // Memory: [base + index*scale + disp] o [base + disp] o [reg]
        if op.starts_with('[') || op.starts_with("qword ptr [") || op.starts_with("dword ptr [")
            || op.starts_with("word ptr [") || op.starts_with("byte ptr [")
        {
            return self.parse_memory(op);
        }

        // Registro
        if let Some(reg) = self.regs.get(op) {
            return Some(reg);
        }

        // Puntero a registro: "ptr [reg]"
        if op.starts_with("ptr [") {
            let inner = &op[5..op.len()-1];
            return self.parse_memory(&format!("[{}]", inner));
        }

        None
    }

    fn parse_memory(&self, op: &str) -> Option<Varnode> {
        let inner = if let Some(start) = op.find('[') {
            let end = op.rfind(']')?;
            &op[start+1..end]
        } else {
            op
        };

        let inner = inner.trim();

        // [reg + reg*scale + disp] o [reg + disp] o [reg]
        let parts: Vec<&str> = inner.split('+').map(|s| s.trim()).collect();

        let mut base: Option<Varnode> = None;
        let mut disp: i64 = 0;
        let mut scale: u8 = 1;

        for part in &parts {
            let part = part.trim();
            if part.is_empty() { continue; }

            if let Some(reg) = self.regs.get(part) {
                base = Some(reg);
            } else if part.contains('*') {
                let scale_parts: Vec<&str> = part.split('*').map(|s| s.trim()).collect();
                if scale_parts.len() == 2 {
                    base = self.regs.get(scale_parts[0]);
                    scale = scale_parts[1].parse().unwrap_or(1);
                }
            } else if let Some(hex) = part.strip_prefix("0x") {
                disp = i64::from_str_radix(hex, 16).ok()?;
            } else if let Ok(val) = part.parse::<i64>() {
                disp = val;
            } else if part.starts_with('-') {
                // resta: manejar separado
                if let Ok(val) = part.parse::<i64>() {
                    disp = val; // ya es negativo
                }
            }
        }

        let base = base?;
        let sz = self.infer_mem_size(op);
        Some(Varnode::Memory(Box::new(base), disp, scale, sz))
    }

    fn infer_mem_size(&self, op: &str) -> u8 {
        if op.contains("qword") { 8 }
        else if op.contains("dword") { 4 }
        else if op.contains("word") { 2 }
        else if op.contains("byte") { 1 }
        else { 8 } // default
    }

    /// Lift completo de una secuencia de instrucciones.
    pub fn lift_all(&mut self, instructions: &[Instruction]) -> Vec<PcodeInst> {
        self.output.clear();
        for inst in instructions {
            self.lift_instruction(inst);
        }
        self.output.clone()
    }

    // ========================================================================
    // AArch64 lifters
    // ========================================================================

    /// stp x29, x30, [sp, #imm]!  → pre-index; store pair
    fn lift_arm64_stp(&mut self, ops: &str) {
        // formato típico: "x29, x30, [sp, #-16]!" o similar
        // simplificado: store cada reg individualmente
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() < 3 { return; }
        let r1 = self.parse_operand(parts[0]);
        let r2 = self.parse_operand(parts[1]);
        let addr_str = parts[2..].join(",");
        let addr = self.parse_operand(&addr_str);
        if let (Some(a), Some(b), Some(addr)) = (r1, r2, addr) {
            let sz = a.size().max(8);
            self.emit(PcodeOp::Store, None, vec![Varnode::mem(addr.clone(), 0, sz), a]);
            let next = Varnode::mem(addr, sz as i64, sz);
            self.emit(PcodeOp::Store, None, vec![next, b]);
        }
    }

    /// ldp x29, x30, [sp], #imm   → post-index; load pair
    fn lift_arm64_ldp(&mut self, ops: &str) {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() < 3 { return; }
        let r1 = self.parse_operand(parts[0]);
        let r2 = self.parse_operand(parts[1]);
        let addr = self.parse_operand(&parts[2..].join(","));
        if let (Some(a), Some(b), Some(addr)) = (r1, r2, addr) {
            let sz = 8;
            let t1 = self.new_temp(sz);
            self.emit(PcodeOp::Load, Some(t1.clone()), vec![Varnode::mem(addr.clone(), 0, sz)]);
            self.emit(PcodeOp::Copy, Some(a), vec![t1]);
            let t2 = self.new_temp(sz);
            self.emit(PcodeOp::Load, Some(t2.clone()), vec![Varnode::mem(addr, sz as i64, sz)]);
            self.emit(PcodeOp::Copy, Some(b), vec![t2]);
        }
    }

    /// adrp/adr: cargar dirección absoluta (reloj de página)
    fn lift_arm64_adrp(&mut self, ops: &str) {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 { return; }
        if let Some(dst) = self.parse_operand(parts[0]) {
            if let Some(addr) = self.parse_operand(parts[1]) {
                self.emit(PcodeOp::Copy, Some(dst), vec![addr]);
            }
        }
    }

    /// cbz/cbnz: branch if (non)zero
    fn lift_arm64_cbz(&mut self, ops: &str, nonzero: bool) {
        // formato: "xN, label"
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 { return; }
        if let (Some(reg), Some(target)) = (self.parse_operand(parts[0]), self.parse_operand(parts[1])) {
            // simplificado: emitimos un BranchCond; el sign flip es solo metadata
            self.emit(PcodeOp::BranchCond, None, vec![reg, target]);
            let _ = nonzero;
        }
    }

    /// b.eq, b.ne, etc: branch condicional sobre NZCV
    fn lift_arm64_bcond(&mut self, ops: &str) {
        if let Some(target) = self.parse_operand(ops.trim()) {
            let nzcv = self.regs.get("nzcv").unwrap_or(Varnode::temp(9999, 4));
            self.emit(PcodeOp::BranchCond, None, vec![nzcv, target]);
        }
    }

    /// ldr xN, [addr] — load de 8 bytes (default)
    fn lift_arm64_ldr(&mut self, ops: &str) {
        self.lift_arm64_ldr_size(ops, 8);
    }

    /// ldr (con tamaño): load de size bytes
    fn lift_arm64_ldr_size(&mut self, ops: &str, size: u8) {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() < 2 { return; }
        let Some(dst) = self.parse_operand(parts[0]) else { return; };
        // el operando de memoria es todo lo que sigue a la primera coma
        let addr = self.parse_operand(&parts[1..].join(","));
        if let Some(addr) = addr {
            let t = self.new_temp(size);
            self.emit(PcodeOp::Load, Some(t.clone()), vec![Varnode::mem(addr, 0, size)]);
            self.emit(PcodeOp::Copy, Some(dst), vec![t]);
        }
    }

    /// str xN, [addr] — store de 8 bytes (default)
    fn lift_arm64_str(&mut self, ops: &str) {
        self.lift_arm64_str_size(ops, 8);
    }

    /// str (con tamaño): store de size bytes
    fn lift_arm64_str_size(&mut self, ops: &str, size: u8) {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() < 2 { return; }
        let Some(src) = self.parse_operand(parts[0]) else { return; };
        let addr = self.parse_operand(&parts[1..].join(","));
        if let Some(addr) = addr {
            self.emit(PcodeOp::Store, None, vec![Varnode::mem(addr, 0, size), src]);
        }
    }

    /// br xN — branch indirecto (jump a registro)
    fn lift_arm64_br(&mut self, ops: &str) {
        if let Some(target) = self.parse_operand(ops.trim()) {
            self.emit(PcodeOp::Branch, None, vec![target]);
        }
    }

    /// blr xN — branch-and-link indirecto (call a registro)
    fn lift_arm64_blr(&mut self, ops: &str) {
        if let Some(target) = self.parse_operand(ops.trim()) {
            // x30 (lr) = return addr; luego jump al target
            let lr = self.regs.get("x30").unwrap_or(Varnode::reg("lr", 8));
            self.emit(PcodeOp::Copy, Some(lr), vec![Varnode::const_(self.current_addr + 4, 8)]);
            self.emit(PcodeOp::Branch, None, vec![target]);
        }
    }

    /// svc — syscall: detener la emulación/lifting (límite del análisis)
    fn lift_arm64_svc(&mut self) {
        self.emit(PcodeOp::Unimplemented("svc".into()), None, vec![]);
    }

    /// Construye bloques básicos IR desde instrucciones P-Code.
    pub fn build_blocks(instructions: &[PcodeInst]) -> Vec<IrBlock> {
        if instructions.is_empty() { return vec![]; }

        let mut blocks: Vec<IrBlock> = Vec::new();
        let mut current_block = IrBlock {
            id: 0,
            start_address: instructions[0].address,
            instructions: Vec::new(),
            successors: Vec::new(),
        };

        for inst in instructions {
            let is_terminator = inst.op.is_control_flow() && !matches!(inst.op, PcodeOp::Call);

            current_block.instructions.push(inst.clone());

            if is_terminator {
                let next_id = blocks.len() + 1;
                // Sucesor simplificado
                if matches!(inst.op, PcodeOp::Branch) || matches!(inst.op, PcodeOp::BranchCond) {
                    current_block.successors.push((next_id, EdgeType::Jump));
                }
                blocks.push(current_block);
                current_block = IrBlock {
                    id: next_id,
                    start_address: inst.address + 1,
                    instructions: Vec::new(),
                    successors: Vec::new(),
                };
            }
        }

        // Último bloque
        if !current_block.instructions.is_empty() {
            blocks.push(current_block);
        }

        blocks
    }
}
