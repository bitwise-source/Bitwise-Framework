//! Definiciones de registros e instrucciones por arquitectura.

use crate::Architecture;

/// Registro de CPU.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Register {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub size_bits: u16,
    pub kind: RegisterKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterKind {
    GeneralPurpose,
    StackPointer,
    BasePointer,
    InstructionPointer,
    Flags,
    Segment,
    FloatingPoint,
    Vector,
}

/// Instrucción desensamblada.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub size: u8,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
}

/// Registros x86-64 canónicos.
pub fn x86_64_registers() -> Vec<Register> {
    use RegisterKind::*;
    vec![
        Register {
            name: "rax",
            aliases: &["eax", "ax", "al"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "rbx",
            aliases: &["ebx", "bx", "bl"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "rcx",
            aliases: &["ecx", "cx", "cl"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "rdx",
            aliases: &["edx", "dx", "dl"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "rsi",
            aliases: &["esi", "si", "sil"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "rdi",
            aliases: &["edi", "di", "dil"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "rbp",
            aliases: &["ebp", "bp", "bpl"],
            size_bits: 64,
            kind: BasePointer,
        },
        Register {
            name: "rsp",
            aliases: &["esp", "sp", "spl"],
            size_bits: 64,
            kind: StackPointer,
        },
        Register {
            name: "r8",
            aliases: &["r8d", "r8w", "r8b"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "r9",
            aliases: &["r9d", "r9w", "r9b"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "r10",
            aliases: &["r10d", "r10w", "r10b"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "r11",
            aliases: &["r11d", "r11w", "r11b"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "r12",
            aliases: &["r12d", "r12w", "r12b"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "r13",
            aliases: &["r13d", "r13w", "r13b"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "r14",
            aliases: &["r14d", "r14w", "r14b"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "r15",
            aliases: &["r15d", "r15w", "r15b"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "rip",
            aliases: &["eip", "ip"],
            size_bits: 64,
            kind: InstructionPointer,
        },
        Register {
            name: "rflags",
            aliases: &["eflags", "flags"],
            size_bits: 64,
            kind: Flags,
        },
        Register {
            name: "cs",
            aliases: &[],
            size_bits: 16,
            kind: Segment,
        },
        Register {
            name: "ds",
            aliases: &[],
            size_bits: 16,
            kind: Segment,
        },
        Register {
            name: "es",
            aliases: &[],
            size_bits: 16,
            kind: Segment,
        },
        Register {
            name: "fs",
            aliases: &[],
            size_bits: 16,
            kind: Segment,
        },
        Register {
            name: "gs",
            aliases: &[],
            size_bits: 16,
            kind: Segment,
        },
        Register {
            name: "ss",
            aliases: &[],
            size_bits: 16,
            kind: Segment,
        },
        Register {
            name: "xmm0",
            aliases: &[],
            size_bits: 128,
            kind: Vector,
        },
        Register {
            name: "xmm1",
            aliases: &[],
            size_bits: 128,
            kind: Vector,
        },
        Register {
            name: "ymm0",
            aliases: &[],
            size_bits: 256,
            kind: Vector,
        },
    ]
}

/// Registros ARM64 (AArch64) canónicos.
pub fn aarch64_registers() -> Vec<Register> {
    use RegisterKind::*;
    vec![
        Register {
            name: "x0",
            aliases: &["w0"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "x1",
            aliases: &["w1"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "x2",
            aliases: &["w2"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "x3",
            aliases: &["w3"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "x4",
            aliases: &["w4"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "x5",
            aliases: &["w5"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "x6",
            aliases: &["w6"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "x7",
            aliases: &["w7"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "x29",
            aliases: &["fp"],
            size_bits: 64,
            kind: BasePointer,
        },
        Register {
            name: "x30",
            aliases: &["lr"],
            size_bits: 64,
            kind: GeneralPurpose,
        },
        Register {
            name: "sp",
            aliases: &["wsp"],
            size_bits: 64,
            kind: StackPointer,
        },
        Register {
            name: "pc",
            aliases: &[],
            size_bits: 64,
            kind: InstructionPointer,
        },
        Register {
            name: "nzcv",
            aliases: &[],
            size_bits: 32,
            kind: Flags,
        },
        Register {
            name: "v0",
            aliases: &["q0", "d0", "s0"],
            size_bits: 128,
            kind: Vector,
        },
    ]
}

/// Obtiene registros para una arquitectura dada.
pub fn registers_for(arch: Architecture) -> Vec<Register> {
    match arch {
        Architecture::X86_64 => x86_64_registers(),
        Architecture::AArch64 => aarch64_registers(),
        _ => vec![],
    }
}
