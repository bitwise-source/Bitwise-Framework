//! # Bitwise Emu — emulación sin dependencias externas
//!
//! Emulador minimalista de x86-64 escrito en Rust puro. Sirve para:
//!  - descifrar strings en runtime (XOR, sumas, ROL)
//!  - ejecutar checks de licencia simples
//!  - resolver branch indirectos
//!  - inspeccionar registros/memoria finales

use bitwise_core::binary;
use bitwise_core::arch::Instruction;
use bitwise_core::BinaryInfo;
use bitwise_disasm::Disassembler;
use std::collections::BTreeMap;
use std::io::{self, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    Ret,
    MaxInstructions,
    Unimplemented(String),
    IllegalAddress,
    UserStop,
}

#[derive(Debug, Clone)]
pub struct EmuResult {
    pub instructions_executed: u64,
    pub end_address: u64,
    pub registers: BTreeMap<String, u64>,
    pub memory_dump: Vec<(u64, Vec<u8>)>,
    pub stopped_reason: StopReason,
}

pub struct EmuConfig {
    pub entry: u64,
    pub max_instructions: u64,
    pub stop_addresses: Vec<u64>,
    pub dump_registers: Vec<String>,
    pub dump_memory: Vec<(u64, usize)>,
}

impl Default for EmuConfig {
    fn default() -> Self {
        Self {
            entry: 0,
            max_instructions: 1000,
            stop_addresses: vec![],
            dump_registers: vec![],
            dump_memory: vec![],
        }
    }
}

const MEMORY_SIZE: usize = 0x10_0000;
const STACK_BASE: u64 = 0x7fff_0000_0000;

pub struct Emu {
    regs: [u64; 16],
    mem: Vec<u8>,
    rip: u64,
    count: u64,
    stopped: Option<StopReason>,
}

impl Emu {
    pub fn new() -> Self {
        Self {
            regs: [0u64; 16],
            mem: vec![0u8; MEMORY_SIZE],
            rip: 0,
            count: 0,
            stopped: None,
        }
    }

    fn reg_index(name: &str) -> Option<usize> {
        match name {
            "rax" => Some(0),
            "rcx" => Some(1),
            "rdx" => Some(2),
            "rbx" => Some(3),
            "rsp" => Some(4),
            "rbp" => Some(5),
            "rsi" => Some(6),
            "rdi" => Some(7),
            "r8" => Some(8),
            "r9" => Some(9),
            "r10" => Some(10),
            "r11" => Some(11),
            "r12" => Some(12),
            "r13" => Some(13),
            "r14" => Some(14),
            "r15" => Some(15),
            _ => None,
        }
    }

    fn set_reg(&mut self, name: &str, v: u64) -> bool {
        if let Some(i) = Self::reg_index(name) {
            self.regs[i] = v;
            true
        } else {
            false
        }
    }

    fn get_reg(&self, name: &str) -> Option<u64> {
        Self::reg_index(name).map(|i| self.regs[i])
    }

    fn read_mem(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        if addr == 0 {
            return None;
        }
        let a = addr as usize;
        if a + size > self.mem.len() {
            return None;
        }
        Some(self.mem[a..a + size].to_vec())
    }

    fn write_mem(&mut self, addr: u64, data: &[u8]) -> bool {
        if addr == 0 {
            return false;
        }
        let a = addr as usize;
        if a + data.len() > self.mem.len() {
            return false;
        }
        self.mem[a..a + data.len()].copy_from_slice(data);
        true
    }

    pub fn load(&mut self, info: &BinaryInfo) -> io::Result<()> {
        let raw = std::fs::read(&info.path)?;
        for sec in &info.sections {
            let base = sec.virtual_address;
            let size = sec.virtual_size as usize;
            if size == 0 {
                continue;
            }
            let file_off = sec.raw_offset as usize;
            let copy_len = (sec.raw_size as usize).min(size);
            if (base as usize) < self.mem.len() {
                let end = (base as usize + size).min(self.mem.len());
                let dst = &mut self.mem[base as usize..end];
                if file_off + copy_len <= raw.len() {
                    dst[..copy_len].copy_from_slice(&raw[file_off..file_off + copy_len]);
                }
            }
        }
        Ok(())
    }

    fn read_op(&self, op: &str) -> Option<u64> {
        let op = op.trim();
        if let Some(h) = op.strip_prefix("0x") {
            return u64::from_str_radix(h, 16).ok();
        }
        if let Ok(n) = op.parse::<i64>() {
            return Some(n as u64);
        }
        if let Some(v) = self.get_reg(op) {
            return Some(v);
        }
        None
    }

    fn resolve_mem(&self, op: &str) -> Option<u64> {
        let op = op.trim();
        let s = if op.starts_with("qword ptr [")
            || op.starts_with("dword ptr [")
            || op.starts_with("byte ptr [")
            || op.starts_with("word ptr [")
        {
            let start = op.find('[')? + 1;
            let end = op.rfind(']')?;
            &op[start..end]
        } else if op.starts_with('[') && op.ends_with(']') {
            &op[1..op.len() - 1]
        } else {
            return None;
        };
        let mut addr: u64 = 0;
        let mut found_base = false;
        for p in s.split('+') {
            let p = p.trim();
            if p.is_empty() { continue; }
            if p.contains('*') {
                let ps: Vec<&str> = p.split('*').map(|x| x.trim()).collect();
                if ps.len() == 2 {
                    let base = self.get_reg(ps[0]).unwrap_or(0);
                    let scale: u64 = ps[1].parse().unwrap_or(1);
                    addr += base * scale;
                    found_base = true;
                    continue;
                }
            }
            if let Some(v) = self.read_op(p) {
                addr += v;
                continue;
            }
            if let Some(v) = self.get_reg(p) {
                addr += v;
                found_base = true;
            }
        }
        if found_base || addr != 0 { Some(addr) } else { None }
    }

    pub fn step(&mut self, insn: &Instruction) -> bool {
        self.count += 1;
        let m = insn.mnemonic.as_str();
        let ops: Vec<&str> = insn.operands.split(',').map(|s| s.trim()).collect();

        match m {
            "mov" | "movabs" => {
                if ops.len() != 2 { return true; }
                let val = self.read_op(ops[1]);
                if let Some(addr) = self.resolve_mem(ops[0]) {
                    if let Some(v) = val {
                        self.write_mem(addr, &v.to_le_bytes());
                    }
                } else if let Some(v) = val {
                    let _ = self.set_reg(ops[0], v);
                }
            }
            "movzx" => {
                if ops.len() != 2 { return true; }
                if let Some(addr) = self.resolve_mem(ops[1]) {
                    if let Some(d) = self.read_mem(addr, 1) {
                        let v = d[0] as u64;
                        let _ = self.set_reg(ops[0], v);
                    }
                }
            }
            "movsx" => {
                if ops.len() != 2 { return true; }
                if let Some(addr) = self.resolve_mem(ops[1]) {
                    if let Some(d) = self.read_mem(addr, 1) {
                        let v = (d[0] as i8) as i64 as u64;
                        let _ = self.set_reg(ops[0], v);
                    }
                }
            }
            "lea" => {
                if ops.len() != 2 { return true; }
                if let Some(addr) = self.resolve_mem(ops[1]) {
                    let _ = self.set_reg(ops[0], addr);
                } else {
                    let inner = &ops[1];
                    let s = inner.find('[').map(|i| &inner[i+1..inner.len()-1]).unwrap_or(inner);
                    let mut v: u64 = 0;
                    for p in s.split('+') {
                        let p = p.trim();
                        if let Some(n) = self.read_op(p) {
                            v += n;
                        } else if let Some(r) = self.get_reg(p) {
                            v += r;
                        }
                    }
                    let _ = self.set_reg(ops[0], v);
                }
            }
            "xchg" => {
                if ops.len() == 2 {
                    if let (Some(a), Some(b)) = (self.get_reg(ops[0]), self.get_reg(ops[1])) {
                        let _ = self.set_reg(ops[0], b);
                        let _ = self.set_reg(ops[1], a);
                    }
                }
            }
            "add" => self.binop(ops, |a, b| a.wrapping_add(b)),
            "sub" => self.binop(ops, |a, b| a.wrapping_sub(b)),
            "imul" => self.binop(ops, |a, b| a.wrapping_mul(b)),
            "mul" => self.binop(ops, |a, b| a.wrapping_mul(b)),
            "xor" => self.binop(ops, |a, b| a ^ b),
            "or" => self.binop(ops, |a, b| a | b),
            "and" => self.binop(ops, |a, b| a & b),
            "shl" | "sal" => self.shift_op(ops, |a, n| a << (n & 63)),
            "shr" => self.shift_op(ops, |a, n| a >> (n & 63)),
            "sar" => self.shift_op(ops, |a, n| {
                let signed = a as i64;
                (signed >> (n & 63)) as u64
            }),
            "neg" => self.unop(ops, |a| a.wrapping_neg()),
            "not" => self.unop(ops, |a| !a),
            "inc" => self.unop(ops, |a| a.wrapping_add(1)),
            "dec" => self.unop(ops, |a| a.wrapping_sub(1)),
            "rol" => self.shift_op(ops, |a, n| a.rotate_left((n & 63) as u32)),
            "ror" => self.shift_op(ops, |a, n| a.rotate_right((n & 63) as u32)),
            "test" => {
                if ops.len() == 2 {
                    let a = self.read_op(ops[0]).unwrap_or(0);
                    let b = self.read_op(ops[1]).unwrap_or(0);
                    let _ = a & b;
                }
            }
            "cmp" => {
                if ops.len() == 2 {
                    let a = self.read_op(ops[0]).unwrap_or(0);
                    let b = self.read_op(ops[1]).unwrap_or(0);
                    let _ = a.wrapping_sub(b);
                }
            }
            "jmp" | "jmpq" => {
                if let Some(target) = self.parse_branch_target(ops.first().copied().unwrap_or("")) {
                    self.rip = target;
                }
                return false;
            }
            "call" => {
                if let Some(target) = self.parse_branch_target(ops.first().copied().unwrap_or("")) {
                    self.regs[4] -= 8;
                    self.write_mem(self.regs[4], &self.rip.to_le_bytes());
                    self.rip = target;
                }
                return false;
            }
            "ret" | "retn" => {
                if let Some(d) = self.read_mem(self.regs[4], 8) {
                    if d.len() == 8 {
                        if let Ok(arr) = d[..8].try_into() {
                            self.rip = u64::from_le_bytes(arr);
                        }
                    }
                }
                self.regs[4] += 8;
                self.stopped = Some(StopReason::Ret);
                return false;
            }
            "push" => {
                if let Some(v) = self.read_op(ops.first().copied().unwrap_or("")) {
                    self.regs[4] -= 8;
                    self.write_mem(self.regs[4], &v.to_le_bytes());
                }
            }
            "pop" => {
                if let Some(d) = self.read_mem(self.regs[4], 8) {
                    if d.len() == 8 {
                        if let Ok(arr) = d[..8].try_into() {
                            let v = u64::from_le_bytes(arr);
                            let _ = self.set_reg(ops.first().copied().unwrap_or(""), v);
                        }
                    }
                    self.regs[4] += 8;
                }
            }
            "nop" | "endbr64" | "endbr32" => {}
            "syscall" => {
                self.stopped = Some(StopReason::Unimplemented("syscall".into()));
                return false;
            }
            "movsd" | "movsq" | "movsb" => {
                let size = match m {
                    "movsb" => 1,
                    "movsd" => 4,
                    "movsq" => 8,
                    _ => 1,
                };
                let src = self.regs[6];
                let dst = self.regs[7];
                if let Some(d) = self.read_mem(src, size) {
                    self.write_mem(dst, &d);
                }
                if self.regs[9] & 1 == 0 {
                    self.regs[6] += size as u64;
                    self.regs[7] += size as u64;
                } else {
                    self.regs[6] -= size as u64;
                    self.regs[7] -= size as u64;
                }
                self.regs[1] = self.regs[1].wrapping_sub(1);
            }
            _ => {
                self.stopped = Some(StopReason::Unimplemented(m.to_string()));
                return false;
            }
        }

        self.rip += insn.size as u64;
        true
    }

    fn binop<F: Fn(u64, u64) -> u64>(&mut self, ops: Vec<&str>, f: F) {
        if ops.len() != 2 { return; }
        let b = self.read_op(ops[1]).unwrap_or(0);
        if let Some(addr) = self.resolve_mem(ops[0]) {
            if let Some(d) = self.read_mem(addr, 8) {
                if d.len() == 8 {
                    if let Ok(arr) = d[..8].try_into() {
                        let a = u64::from_le_bytes(arr);
                        let r = f(a, b);
                        self.write_mem(addr, &r.to_le_bytes());
                    }
                }
            }
        } else if let Some(a) = self.read_op(ops[0]) {
            let r = f(a, b);
            let _ = self.set_reg(ops[0], r);
        }
    }

    fn unop<F: Fn(u64) -> u64>(&mut self, ops: Vec<&str>, f: F) {
        if ops.is_empty() { return; }
        if let Some(a) = self.read_op(ops[0]) {
            let _ = self.set_reg(ops[0], f(a));
        }
    }

    fn shift_op<F: Fn(u64, u64) -> u64>(&mut self, ops: Vec<&str>, f: F) {
        if ops.len() != 2 { return; }
        let b = self.read_op(ops[1]).unwrap_or(0);
        if let Some(a) = self.read_op(ops[0]) {
            let r = f(a, b);
            let _ = self.set_reg(ops[0], r);
        }
    }

    fn parse_branch_target(&self, op: &str) -> Option<u64> {
        let op = op.trim();
        if let Some(v) = self.read_op(op) {
            return Some(v);
        }
        if let Some(addr) = self.resolve_mem(op) {
            if let Some(d) = self.read_mem(addr, 8) {
                if d.len() == 8 {
                    if let Ok(arr) = d[..8].try_into() {
                        return Some(u64::from_le_bytes(arr));
                    }
                }
            }
        }
        None
    }
}

pub fn emulate(info: &BinaryInfo, cfg: &EmuConfig) -> EmuResult {
    let mut emu = Emu::new();
    let _ = emu.load(info);

    let entry = if cfg.entry == 0 {
        info.entry_point.unwrap_or(0)
    } else {
        cfg.entry
    };
    emu.rip = entry;
    emu.set_reg("rsp", STACK_BASE + 0x8000);
    emu.set_reg("rbp", STACK_BASE + 0x8000);

    let disasm = Disassembler::from_binary(info);
    let mut addr_to_insn: BTreeMap<u64, Instruction> = BTreeMap::new();
    if let Ok(d) = disasm {
        for sec in &info.sections {
            if !sec.permissions.execute { continue; }
            if let Ok(insns) = d.disassemble_section(info, &sec.name) {
                for i in insns {
                    addr_to_insn.insert(i.address, i);
                }
            }
        }
    }

    let mut last_reason = StopReason::MaxInstructions;
    while emu.count < cfg.max_instructions {
        if emu.stopped.is_some() {
            last_reason = emu.stopped.clone().unwrap();
            break;
        }
        if cfg.stop_addresses.contains(&emu.rip) {
            last_reason = StopReason::UserStop;
            break;
        }
        let insn = match addr_to_insn.get(&emu.rip) {
            Some(i) => i.clone(),
            None => {
                last_reason = StopReason::IllegalAddress;
                break;
            }
        };
        if !emu.step(&insn) {
            last_reason = emu.stopped.clone().unwrap_or(StopReason::IllegalAddress);
            break;
        }
    }

    let mut registers = BTreeMap::new();
    let to_dump: Vec<String> = if cfg.dump_registers.is_empty() {
        vec![
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    } else {
        cfg.dump_registers.clone()
    };
    for r in &to_dump {
        if let Some(v) = emu.get_reg(r) {
            registers.insert(r.clone(), v);
        }
    }

    let mut memory_dump = Vec::new();
    for (addr, size) in &cfg.dump_memory {
        if let Some(data) = emu.read_mem(*addr, *size) {
            memory_dump.push((*addr, data));
        }
    }

    EmuResult {
        instructions_executed: emu.count,
        end_address: emu.rip,
        registers,
        memory_dump,
        stopped_reason: last_reason,
    }
}

pub fn format_result(r: &EmuResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Emulation: {} instructions, ended at {:#x} ({:?})\n",
        r.instructions_executed, r.end_address, r.stopped_reason
    ));
    out.push_str("\nRegisters:\n");
    for (k, v) in &r.registers {
        out.push_str(&format!("  {:>4} = {:#018x}\n", k, v));
    }
    if !r.memory_dump.is_empty() {
        out.push_str("\nMemory dumps:\n");
        for (addr, data) in &r.memory_dump {
            out.push_str(&format!("  @ {:#x} ({} bytes):\n", addr, data.len()));
            for (i, chunk) in data.chunks(16).enumerate() {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                    .collect();
                out.push_str(&format!(
                    "    {:#010x}  {:48}  |{}|\n",
                    addr + (i * 16) as u64,
                    hex.join(" "),
                    ascii
                ));
            }
        }
    }
    out
}

pub fn run_cli(
    file: &str,
    entry: Option<u64>,
    max_instr: u64,
    dump_mem: Vec<(u64, usize)>,
    stop_addr: Vec<u64>,
) -> io::Result<()> {
    let info = binary::load_binary(std::path::Path::new(file))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let cfg = EmuConfig {
        entry: entry.unwrap_or(0),
        max_instructions: max_instr,
        stop_addresses: stop_addr,
        dump_registers: vec![],
        dump_memory: dump_mem,
    };
    let result = emulate(&info, &cfg);
    print!("{}", format_result(&result));
    io::stdout().flush().ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_index_works() {
        let mut e = Emu::new();
        assert!(e.set_reg("rax", 42));
        assert_eq!(e.get_reg("rax"), Some(42));
        assert!(!e.set_reg("foo", 0));
    }

    #[test]
    fn read_op_decimal_and_hex() {
        let e = Emu::new();
        assert_eq!(e.read_op("42"), Some(42));
        assert_eq!(e.read_op("0xff"), Some(255));
    }

    #[test]
    fn mem_roundtrip() {
        let mut e = Emu::new();
        e.write_mem(0x1000, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let r = e.read_mem(0x1000, 8).unwrap();
        assert_eq!(r, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
