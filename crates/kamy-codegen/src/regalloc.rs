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
}

const VOLATILE_GPRS: [Gpr; 9] = [
    Gpr::Rax,
    Gpr::Rcx,
    Gpr::Rdx,
    Gpr::R8,
    Gpr::R9,
    Gpr::R10,
    Gpr::R11,
    Gpr::Rsi,
    Gpr::Rdi,
];

const VOLATILE_XMMS: [XmmReg; 6] = [
    XmmReg::Xmm0,
    XmmReg::Xmm1,
    XmmReg::Xmm2,
    XmmReg::Xmm3,
    XmmReg::Xmm4,
    XmmReg::Xmm5,
];

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

    for (bi, &bid) in order.iter().enumerate() {
        let block = func.block(bid);

        for (pi, phi) in block.phis.iter().enumerate() {
            let pt = linear_point(bi, pi);
            defs.entry(phi.dest).or_insert((pt, phi.ty, None));
        }

        let phi_offset = block.phis.len();

        for (ii, inst) in block.insts.iter().enumerate() {
            let pt = linear_point(bi, phi_offset + ii);
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
            LiveInterval {
                value: vid,
                ty,
                start,
                end,
                pinned,
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
) -> Result<RegAllocation, RejectionReason> {
    let order = block_order(func);
    let mut intervals = compute_live_intervals(func, &order);
    for iv in &mut intervals {
        if rsp_pinned.contains(&iv.value) {
            iv.pinned = Some(PhysReg::Gpr(Gpr::Rsp));
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
            let occupied = active.iter().any(|(_, r)| *r == pinned);
            if occupied {
                let conflicting = active
                    .iter()
                    .find(|(_, r)| *r == pinned)
                    .map(|(a, _)| a.clone());
                if let Some(conf) = conflicting {
                    let alt = if needs_xmm {
                        free_xmms.pop().map(PhysReg::Xmm)
                    } else {
                        free_gprs.pop().map(PhysReg::Gpr)
                    };
                    if let Some(alt_reg) = alt {
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
                    } else {
                        return Err(RejectionReason::RegisterPressure);
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
                free_xmms
                    .pop()
                    .map(PhysReg::Xmm)
                    .ok_or(RejectionReason::RegisterPressure)?
            } else {
                free_gprs
                    .pop()
                    .map(PhysReg::Gpr)
                    .ok_or(RejectionReason::RegisterPressure)?
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
        let result = allocate_registers(&func, &[], &HashSet::new()).unwrap();

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
}
