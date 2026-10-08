//! # Optimizador de IR
//!
//! Pases de limpieza del P-Code antes del structuring:
//!   1. Temp fusion: `tN = OP a, b` seguido de `dst = COPY tN` → `dst = OP a, b`
//!      (elimina la mitad de las líneas del lifter)
//!   2. Copy propagation: `tN = COPY x` + usos de tN → reemplazo directo por x
//!   3. Constant folding: `tN = ADD a, 0` → `a`; `tN = MUL a, 1` → `a`
//!   4. Dead store elimination: stores a stack que nunca se leen
//!      (colapsa el ruido `rsp = rsp - 8; *(rsp) = rbp;` de los prologos)

use bitwise_ir::{PcodeInst, PcodeOp, Varnode};
use std::collections::{BTreeSet, HashMap};

/// Ejecuta todos los pases hasta punto fijo (máx 5 iteraciones).
pub fn optimize(insts: &[PcodeInst]) -> Vec<PcodeInst> {
    let mut cur: Vec<PcodeInst> = insts.to_vec();
    for _ in 0..5 {
        let before = cur.len();
        cur = fuse_temps(&cur);
        cur = propagate_copies(&cur);
        cur = fold_constants(&cur);
        cur = eliminate_dead_stores(&cur);
        if cur.len() == before {
            break;
        }
    }
    cur
}

/// ¿El varnode es un temporal de un solo uso que solo alimenta al COPY siguiente?
fn fuse_temps(insts: &[PcodeInst]) -> Vec<PcodeInst> {
    // contar usos de cada temp
    let mut uses: HashMap<u64, usize> = HashMap::new();
    for i in insts {
        for inp in &i.inputs {
            if let Varnode::Temp(id, _) = inp {
                *uses.entry(*id).or_insert(0) += 1;
            }
        }
    }

    let mut out: Vec<PcodeInst> = Vec::with_capacity(insts.len());
    // rastrear qué temps ya fueron "consumidas" por la fusión anterior
    let mut consumed: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for i in insts {
        // si es un COPY a X de una temp t ya consumida, omitirlo (era la carga)
        if i.op == PcodeOp::Copy {
            if let Some(Varnode::Temp(t, _)) = i.inputs.first() {
                if consumed.contains(t) {
                    continue;
                }
            }
        }
        // patrón: output = Temp(t), op != Copy, t tiene 1 uso
        if let Some(Varnode::Temp(t, _)) = &i.output {
            if uses.get(t).copied().unwrap_or(0) == 1 && i.op != PcodeOp::Copy && !i.op.is_control_flow() {
                // buscar el consumidor (siguiente COPY con t como input) en TODA la lista restante
                let pos = insts.iter().position(|p| {
                    if p.op != PcodeOp::Copy {
                        return false;
                    }
                    match p.inputs.first() {
                        Some(Varnode::Temp(u, _)) => u == t,
                        _ => false,
                    }
                });
                if let Some(pos) = pos {
                    // la posición en `out` no es trivial, así que mejor emitimos
                    // el consumidor (COPY dst = t) y luego esta instrucción
                    // como `dst = OP inputs...` y marcamos t como consumida
                    let consumer = insts[pos].clone();
                    if let Some(dst) = consumer.output.clone() {
                        out.push(PcodeInst::new(
                            i.address,
                            i.op.clone(),
                            Some(dst),
                            i.inputs.clone(),
                        ));
                        consumed.insert(*t);
                        continue;
                    }
                }
            }
        }
        out.push(i.clone());
    }
    out
}

/// Propaga `tN = COPY x` cuando x es registro o constante (no memoria).
fn propagate_copies(insts: &[PcodeInst]) -> Vec<PcodeInst> {
    // reemplazo: temp -> varnode origen (solo si el COPY es la única def)
    let mut replace: HashMap<u64, Varnode> = HashMap::new();
    for i in insts {
        if i.op == PcodeOp::Copy {
            if let (Some(Varnode::Temp(t, _)), Some(src)) = (&i.output, i.inputs.first()) {
                if matches!(src, Varnode::Register(_, _) | Varnode::Constant(_, _)) {
                    replace.insert(*t, src.clone());
                }
            }
        }
    }

    insts
        .iter()
        .map(|i| {
            let mut n = i.clone();
            n.inputs = n
                .inputs
                .iter()
                .map(|v| {
                    if let Varnode::Temp(t, _) = v {
                        replace.get(t).cloned().unwrap_or_else(|| v.clone())
                    } else {
                        v.clone()
                    }
                })
                .collect();
            n
        })
        .collect()
}

/// Fold de identidades aritméticas: x+0, x-0, x*1, x/1, x<<0, x>>0, x^0, x|0, x&~0.
fn fold_constants(insts: &[PcodeInst]) -> Vec<PcodeInst> {
    insts
        .iter()
        .filter_map(|i| {
            if i.inputs.len() != 2 {
                return Some(i.clone());
            }
            let a = &i.inputs[0];
            let b = &i.inputs[1];
            let is_zero = matches!(b, Varnode::Constant(0, _));
            let is_one = matches!(b, Varnode::Constant(1, _));

            match &i.op {
                PcodeOp::IntAdd | PcodeOp::IntSub | PcodeOp::IntOr | PcodeOp::IntXor
                    if is_zero =>
                {
                    // t = a OP 0 → t = a
                    Some(PcodeInst::new(i.address, PcodeOp::Copy, i.output.clone(), vec![a.clone()]))
                }
                PcodeOp::IntMul | PcodeOp::IntDiv | PcodeOp::IntDivU
                    if is_one =>
                {
                    Some(PcodeInst::new(i.address, PcodeOp::Copy, i.output.clone(), vec![a.clone()]))
                }
                PcodeOp::IntShiftL | PcodeOp::IntShiftR | PcodeOp::IntShiftRA
                    if is_zero =>
                {
                    Some(PcodeInst::new(i.address, PcodeOp::Copy, i.output.clone(), vec![a.clone()]))
                }
                _ => Some(i.clone()),
            }
        })
        .collect()
}

/// Elimina stores a `[rsp]`/`[rbp]` cuyo valor nunca se carga después
/// (el ruido de push/pop de registros callee-saved).
fn eliminate_dead_stores(insts: &[PcodeInst]) -> Vec<PcodeInst> {
    // marcar offsets de stack que sí se leen
    let mut read_keys: BTreeSet<(String, i64)> = BTreeSet::new();
    for i in insts {
        if i.op == PcodeOp::Load {
            if let Some(Varnode::Memory(base, off, _, _)) = i.inputs.first() {
                if let Varnode::Register(name, _) = base.as_ref() {
                    read_keys.insert((name.clone(), *off));
                }
            }
        }
    }

    insts
        .iter()
        .filter(|i| {
            if i.op != PcodeOp::Store {
                return true;
            }
            if let Some(Varnode::Memory(base, off, _, _)) = i.inputs.first() {
                if let Varnode::Register(name, _) = base.as_ref() {
                    // conservador: solo eliminamos stores a rsp que nadie lee
                    if name == "rsp" && !read_keys.contains(&(name.clone(), *off)) {
                        return false;
                    }
                }
            }
            true
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitwise_ir::PcodeInst;

    #[test]
    fn fuse_temp_copy_pair() {
        let insts = vec![
            PcodeInst::new(0, PcodeOp::IntSub, Some(Varnode::Temp(1, 8)),
                vec![Varnode::reg("rsp", 8), Varnode::const_(8, 8)]),
            PcodeInst::new(0, PcodeOp::Copy, Some(Varnode::reg("rsp", 8)),
                vec![Varnode::Temp(1, 8)]),
        ];
        let out = fuse_temps(&insts);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].op, PcodeOp::IntSub);
        assert_eq!(out[0].output, Some(Varnode::reg("rsp", 8)));
    }

    #[test]
    fn fold_add_zero() {
        let insts = vec![
            PcodeInst::new(0, PcodeOp::IntAdd, Some(Varnode::Temp(1, 8)),
                vec![Varnode::reg("rax", 8), Varnode::const_(0, 8)]),
        ];
        let out = fold_constants(&insts);
        assert_eq!(out[0].op, PcodeOp::Copy);
    }

    #[test]
    fn dead_rsp_store_removed() {
        let insts = vec![
            PcodeInst::new(0, PcodeOp::Store, None,
                vec![Varnode::mem(Varnode::reg("rsp", 8), 0, 8), Varnode::reg("rbp", 8)]),
            PcodeInst::new(4, PcodeOp::Copy, Some(Varnode::reg("rax", 8)),
                vec![Varnode::const_(1, 8)]),
        ];
        let out = eliminate_dead_stores(&insts);
        assert_eq!(out.len(), 1); // el store a [rsp] nunca leído desaparece
    }

    #[test]
    fn live_store_kept() {
        let insts = vec![
            PcodeInst::new(0, PcodeOp::Store, None,
                vec![Varnode::mem(Varnode::reg("rsp", 8), 0, 8), Varnode::reg("rbp", 8)]),
            PcodeInst::new(4, PcodeOp::Load, Some(Varnode::Temp(1, 8)),
                vec![Varnode::mem(Varnode::reg("rsp", 8), 0, 8)]),
        ];
        let out = eliminate_dead_stores(&insts);
        assert_eq!(out.len(), 2); // se lee después → se conserva
    }
}
