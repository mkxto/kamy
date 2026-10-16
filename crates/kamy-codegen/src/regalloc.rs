use std::collections::{HashMap, HashSet};

use kamy_core::RejectionReason;
use kamy_core::ir::{
    BlockId, Gpr, IrFunction, IrOp, IrTerminator, IrType, PhysReg, ValueId, XmmReg,
};

#[derive(Debug, Clone)]
pub struct RegCopy {
    pub point: usize,
    pub from: PhysReg,
    pub to: PhysReg,
    pub ty: IrType,
}

#[derive(Debug)]
pub struct RegAllocation {
    pub assignments: HashMap<ValueId, PhysReg>,
    pub copies: Vec<RegCopy>,
}

#[derive(Debug, Clone)]
struct LiveInterval {
    value: ValueId,
    ty: IrType,
    start: usize,
    end: usize,
    pinned: Option<PhysReg>,
    crosses_call: bool,
}

// Win64 volatile (caller-saved) GPRs. RSI/RDI are NON-volatile on Win64 and
// therefore excluded here (unlike the SysV ABI).
const VOLATILE_GPRS: [Gpr; 7] = [
    Gpr::Rax,
    Gpr::Rcx,
    Gpr::Rdx,
    Gpr::R8,
    Gpr::R9,
    Gpr::R10,
    Gpr::R11,
];

/// Win64 callee-saved GPR pool in canonical push order.
pub const CALLEE_SAVED_GPRS: [PhysReg; 8] = [
    PhysReg::Gpr(Gpr::Rbx),
    PhysReg::Gpr(Gpr::Rbp),
    PhysReg::Gpr(Gpr::Rsi),
    PhysReg::Gpr(Gpr::Rdi),
    PhysReg::Gpr(Gpr::R12),
    PhysReg::Gpr(Gpr::R13),
    PhysReg::Gpr(Gpr::R14),
    PhysReg::Gpr(Gpr::R15),
];

fn gpr_to_iced(gpr: Gpr) -> iced_x86::Register {
    match gpr {
        Gpr::Rax => iced_x86::Register::RAX,
        Gpr::Rcx => iced_x86::Register::RCX,
        Gpr::Rdx => iced_x86::Register::RDX,
        Gpr::Rbx => iced_x86::Register::RBX,
        Gpr::Rsp => iced_x86::Register::RSP,
        Gpr::Rbp => iced_x86::Register::RBP,
        Gpr::Rsi => iced_x86::Register::RSI,
        Gpr::Rdi => iced_x86::Register::RDI,
        Gpr::R8 => iced_x86::Register::R8,
        Gpr::R9 => iced_x86::Register::R9,
        Gpr::R10 => iced_x86::Register::R10,
        Gpr::R11 => iced_x86::Register::R11,
        Gpr::R12 => iced_x86::Register::R12,
        Gpr::R13 => iced_x86::Register::R13,
        Gpr::R14 => iced_x86::Register::R14,
        Gpr::R15 => iced_x86::Register::R15,
    }
}

/// Callee-saved GPRs actually used by `alloc`, in canonical pool order, mapped
/// to iced registers. Drives prologue push emission and UNWIND_INFO.
pub fn callee_saved_used(alloc: &RegAllocation) -> Vec<iced_x86::Register> {
    CALLEE_SAVED_GPRS
        .iter()
        .filter(|saved| alloc.assignments.values().any(|v| v == *saved))
        .filter_map(|saved| match saved {
            PhysReg::Gpr(g) => Some(gpr_to_iced(*g)),
            _ => None,
        })
        .collect()
}

const VOLATILE_XMMS: [XmmReg; 6] = [
    XmmReg::Xmm0,
    XmmReg::Xmm1,
    XmmReg::Xmm2,
    XmmReg::Xmm3,
    XmmReg::Xmm4,
    XmmReg::Xmm5,
];

fn is_callee_saved_gpr(g: Gpr) -> bool {
    CALLEE_SAVED_GPRS
        .iter()
        .any(|p| matches!(p, PhysReg::Gpr(x) if *x == g))
}

fn block_order(func: &IrFunction) -> Vec<BlockId> {
    let mut order = Vec::with_capacity(func.blocks.len());
    let mut visited = vec![false; func.blocks.len()];
    let mut stack = vec![func.entry];
    while let Some(bid) = stack.pop() {
        let idx = bid.0 as usize;
        if idx >= visited.len() || visited[idx] {
            continue;
        }
        visited[idx] = true;
        order.push(bid);
        let block = func.block(bid);
        match &block.term {
            IrTerminator::Jump(t) => stack.push(*t),
            IrTerminator::Branch {
                taken, not_taken, ..
            } => {
                stack.push(*not_taken);
                stack.push(*taken);
            }
            IrTerminator::Ret | IrTerminator::Unreachable => {}
        }
    }
    order
}

fn linear_point(block_index: usize, inst_index: usize) -> usize {
    block_index * 1024 + inst_index
}

fn compute_live_intervals(func: &IrFunction, order: &[BlockId]) -> Vec<LiveInterval> {
    let mut defs: HashMap<ValueId, (usize, IrType, Option<PhysReg>)> = HashMap::new();
    let mut last_use: HashMap<ValueId, usize> = HashMap::new();
    let mut call_points: Vec<usize> = Vec::new();

    for (bi, &bid) in order.iter().enumerate() {
        let block = func.block(bid);

        for (pi, phi) in block.phis.iter().enumerate() {
            let pt = linear_point(bi, pi);
            defs.entry(phi.dest).or_insert((pt, phi.ty, None));
        }

        let phi_offset = block.phis.len();

        for (ii, inst) in block.insts.iter().enumerate() {
            let pt = linear_point(bi, phi_offset + ii);
            if matches!(inst.op, IrOp::Call { .. }) {
                call_points.push(pt);
            }
            if let Some(dest) = inst.dest {
                let pinned = match &inst.op {
                    IrOp::NativeInline(native) => native.writes.first().copied(),
                    _ => None,
                };
                defs.entry(dest).or_insert((pt, inst.ty, pinned));
            }
            for arg in &inst.args {
                last_use.insert(*arg, pt);
            }
            if let IrOp::NativeInline(native) = &inst.op {
                for r in &native.reads {
                    for (&vid, &(_, _, pinned)) in &defs {
                        if pinned == Some(*r) {
                            last_use
                                .entry(vid)
                                .and_modify(|e| *e = (*e).max(pt))
                                .or_insert(pt);
                        }
                    }
                }
            }
        }

        let term_pt = linear_point(bi, phi_offset + block.insts.len());
        if let IrTerminator::Branch { cond, .. } = &block.term {
            last_use.insert(*cond, term_pt);
        }

        match &block.term {
            IrTerminator::Jump(t) | IrTerminator::Branch { taken: t, .. } => {
                let target = func.block(*t);
                for phi in &target.phis {
                    for (pred, val) in &phi.args {
                        if *pred == bid {
                            last_use
                                .entry(*val)
                                .and_modify(|e| *e = (*e).max(term_pt))
                                .or_insert(term_pt);
                        }
                    }
                }
            }
            _ => {}
        }
        if let IrTerminator::Branch { not_taken, .. } = &block.term {
            let target = func.block(*not_taken);
            for phi in &target.phis {
                for (pred, val) in &phi.args {
                    if *pred == bid {
                        last_use
                            .entry(*val)
                            .and_modify(|e| *e = (*e).max(term_pt))
                            .or_insert(term_pt);
                    }
                }
            }
        }
    }

    let mut intervals: Vec<LiveInterval> = defs
        .into_iter()
        .map(|(vid, (start, ty, pinned))| {
            let end = last_use.get(&vid).copied().unwrap_or(start);
            // A value defined before a call and used after must survive it; only
            // callee-saved registers (or RSP) are preserved across a CALL.
            let crosses_call = call_points.iter().any(|&c| start < c && c < end);
            LiveInterval {
                value: vid,
                ty,
                start,
                end,
                pinned,
                crosses_call,
            }
        })
        .collect();

    intervals.sort_by_key(|iv| iv.start);
    intervals
}

pub fn allocate_registers(
    func: &IrFunction,
    saved_regs: &[PhysReg],
    rsp_pinned: &HashSet<ValueId>,
    reg_pins: &HashMap<ValueId, PhysReg>,
) -> Result<RegAllocation, RejectionReason> {
    let order = block_order(func);
    let mut intervals = compute_live_intervals(func, &order);
    for iv in &mut intervals {
        if rsp_pinned.contains(&iv.value) {
            iv.pinned = Some(PhysReg::Gpr(Gpr::Rsp));
        } else if let Some(p) = reg_pins.get(&iv.value) {
            iv.pinned = Some(*p);
        }
    }

    let mut avail_gprs: Vec<Gpr> = VOLATILE_GPRS.to_vec();
    let mut avail_xmms: Vec<XmmReg> = VOLATILE_XMMS.to_vec();

    for reg in saved_regs {
        match reg {
            PhysReg::Gpr(g) => {
                if !avail_gprs.contains(g) {
                    avail_gprs.push(*g);
                }
            }
            PhysReg::Xmm(x) => {
                if !avail_xmms.contains(x) {
                    avail_xmms.push(*x);
                }
            }
            PhysReg::Flag(_) => {}
        }
    }

    let mut assignments: HashMap<ValueId, PhysReg> = HashMap::new();
    let mut copies: Vec<RegCopy> = Vec::new();
    let mut active: Vec<(LiveInterval, PhysReg)> = Vec::new();
    let mut free_gprs: Vec<Gpr> = avail_gprs.clone();
    let mut free_xmms: Vec<XmmReg> = avail_xmms.clone();

    for iv in &intervals {
        active.retain(|(a, reg)| {
            if a.end < iv.start {
                match reg {
                    PhysReg::Gpr(g) => {
                        if avail_gprs.contains(g) && !free_gprs.contains(g) {
                            free_gprs.push(*g);
                        }
                    }
                    PhysReg::Xmm(x) => {
                        if avail_xmms.contains(x) && !free_xmms.contains(x) {
                            free_xmms.push(*x);
                        }
                    }
                    PhysReg::Flag(_) => {}
                }
                false
            } else {
                true
            }
        });

        if iv.ty == IrType::I8 {
            if let Some(pinned) = iv.pinned {
                assignments.insert(iv.value, pinned);
            } else {
                assignments.insert(iv.value, PhysReg::Gpr(Gpr::Rax));
            }
            continue;
        }

        let needs_xmm = iv.ty == IrType::I128;

        if let Some(pinned) = iv.pinned {
            if pinned == PhysReg::Gpr(Gpr::Rsp) {
                // RSP is one physical register threaded as a sequence of in-place
                // updates (sub/add rsp); a chain value's input dies exactly as the
                // result is defined, so it is never a real conflict. Evicting it to
                // a GPR would compute rsp arithmetic in a scratch register and leave
                // the real stack pointer unchanged.
                assignments.insert(iv.value, pinned);
                active.push((iv.clone(), pinned));
                continue;
            }
            let occupied = active.iter().any(|(_, r)| *r == pinned);
            if occupied {
                let conf = active
                    .iter()
                    .find(|(_, r)| *r == pinned)
                    .map(|(a, _)| a.clone())
                    .unwrap();
                if conf.end <= iv.start {
                    // conf's last use coincides with iv's definition (in-place
                    // reuse, e.g. `mov rcx,[rcx]`); iv takes the register, conf dies.
                    active.retain(|(a, _)| a.value != conf.value);
                } else if conf.pinned.is_some() {
                    // Two values pinned to one register with overlapping ranges:
                    // this allocator cannot split them soundly. Reject so the
                    // function relocates verbatim instead of miscompiling.
                    return Err(RejectionReason::RegisterPressure);
                } else {
                    // Evict the non-pinned temp to a register no live interval holds.
                    let busy: HashSet<PhysReg> = active.iter().map(|(_, r)| *r).collect();
                    let alt = if needs_xmm {
                        free_xmms
                            .iter()
                            .position(|x| !busy.contains(&PhysReg::Xmm(*x)))
                            .map(|p| PhysReg::Xmm(free_xmms.remove(p)))
                    } else {
                        free_gprs
                            .iter()
                            .position(|g| !busy.contains(&PhysReg::Gpr(*g)))
                            .map(|p| PhysReg::Gpr(free_gprs.remove(p)))
                    };
                    match alt {
                        Some(alt_reg) => {
                            copies.push(RegCopy {
                                point: iv.start,
                                from: pinned,
                                to: alt_reg,
                                ty: conf.ty,
                            });
                            active.iter_mut().for_each(|(a, r)| {
                                if a.value == conf.value {
                                    *r = alt_reg;
                                }
                            });
                            *assignments.get_mut(&conf.value).unwrap() = alt_reg;
                        }
                        None => return Err(RejectionReason::RegisterPressure),
                    }
                }
            } else {
                match pinned {
                    PhysReg::Gpr(g) => free_gprs.retain(|x| *x != g),
                    PhysReg::Xmm(x) => free_xmms.retain(|v| *v != x),
                    PhysReg::Flag(_) => {}
                }
            }

            assignments.insert(iv.value, pinned);
            active.push((iv.clone(), pinned));
        } else {
            let reg = if needs_xmm {
                if iv.crosses_call {
                    // No callee-saved XMM pool: an XMM value cannot survive a call.
                    return Err(RejectionReason::RegisterPressure);
                }
                free_xmms
                    .pop()
                    .map(PhysReg::Xmm)
                    .ok_or(RejectionReason::RegisterPressure)?
            } else {
                let pos = if iv.crosses_call {
                    // Must survive the call → callee-saved GPR only.
                    free_gprs.iter().position(|g| is_callee_saved_gpr(*g))
                } else {
                    // Prefer a volatile so callee-saved stay free for crossers;
                    // fall back to callee-saved when no volatile is free.
                    free_gprs.iter().position(|g| !is_callee_saved_gpr(*g)).or(
                        if free_gprs.is_empty() {
                            None
                        } else {
                            Some(free_gprs.len() - 1)
                        },
                    )
                };
                match pos {
                    Some(p) => PhysReg::Gpr(free_gprs.remove(p)),
                    None => return Err(RejectionReason::RegisterPressure),
                }
            };

            assignments.insert(iv.value, reg);
            active.push((iv.clone(), reg));
        }
    }

    Ok(RegAllocation {
        assignments,
        copies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::ir::*;

    fn make_test_function() -> IrFunction {
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };

        let v0 = func.alloc_value(); // arg1
        let v1 = func.alloc_value(); // arg2
        let v2 = func.alloc_value(); // add result
        let v3 = func.alloc_value(); // arg3
        let v4 = func.alloc_value(); // add result 2
        let v5 = func.alloc_value(); // store addr (unused dest but needed as arg)

        let block = IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(v0),
                    op: IrOp::Const(10),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v1),
                    op: IrOp::Const(20),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v2),
                    op: IrOp::Add,
                    args: vec![v0, v1],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v3),
                    op: IrOp::Const(30),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v4),
                    op: IrOp::Add,
                    args: vec![v2, v3],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v5),
                    op: IrOp::Const(0x1000),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Store,
                    args: vec![v5, v4],
                    ty: IrType::I64,
                },
            ],
            term: IrTerminator::Ret,
        };

        func.blocks.push(block);
        func
    }

    #[test]
    fn allocate_simple_no_copies() {
        let func = make_test_function();
        let result = allocate_registers(&func, &[], &HashSet::new(), &HashMap::new()).unwrap();

        assert!(result.assignments.contains_key(&ValueId(0)));
        assert!(result.assignments.contains_key(&ValueId(1)));
        assert!(result.assignments.contains_key(&ValueId(2)));
        assert!(result.assignments.contains_key(&ValueId(3)));
        assert!(result.assignments.contains_key(&ValueId(4)));
        assert!(result.assignments.contains_key(&ValueId(5)));

        let r0 = result.assignments[&ValueId(2)];
        let r1 = result.assignments[&ValueId(4)];
        assert!(matches!(r0, PhysReg::Gpr(_)), "v2 should be in a GPR");
        assert!(matches!(r1, PhysReg::Gpr(_)), "v4 should be in a GPR");
    }

    #[test]
    fn callee_saved_used_canonical_order() {
        let mut assignments = HashMap::new();
        assignments.insert(ValueId(0), PhysReg::Gpr(Gpr::R13));
        assignments.insert(ValueId(1), PhysReg::Gpr(Gpr::Rbx));
        assignments.insert(ValueId(2), PhysReg::Gpr(Gpr::Rax));
        let alloc = RegAllocation {
            assignments,
            copies: vec![],
        };
        assert_eq!(
            callee_saved_used(&alloc),
            vec![iced_x86::Register::RBX, iced_x86::Register::R13]
        );
    }
}
