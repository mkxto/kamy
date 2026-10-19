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
    pub edge_copies: HashMap<(BlockId, BlockId), Vec<RegCopy>>,
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

/// Callee-saved XMMs actually used by `alloc`, in canonical pool order, as iced
/// registers. Drives the prologue movups save area and the UNWIND stack alloc.
pub fn callee_saved_xmms_used(alloc: &RegAllocation) -> Vec<iced_x86::Register> {
    CALLEE_SAVED_XMMS
        .iter()
        .filter(|saved| {
            alloc
                .assignments
                .values()
                .any(|v| matches!(v, PhysReg::Xmm(x) if x == *saved))
        })
        .map(|saved| xmm_to_iced(*saved))
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

/// Win64 callee-saved XMM pool (XMM6..XMM15). Saved with movups in the generated
/// prologue; drives epilogue restore and the UNWIND stack allocation.
const CALLEE_SAVED_XMMS: [XmmReg; 10] = [
    XmmReg::Xmm6,
    XmmReg::Xmm7,
    XmmReg::Xmm8,
    XmmReg::Xmm9,
    XmmReg::Xmm10,
    XmmReg::Xmm11,
    XmmReg::Xmm12,
    XmmReg::Xmm13,
    XmmReg::Xmm14,
    XmmReg::Xmm15,
];

fn is_callee_saved_xmm(x: XmmReg) -> bool {
    CALLEE_SAVED_XMMS.contains(&x)
}

fn xmm_to_iced(x: XmmReg) -> iced_x86::Register {
    use iced_x86::Register as R;
    match x {
        XmmReg::Xmm0 => R::XMM0,
        XmmReg::Xmm1 => R::XMM1,
        XmmReg::Xmm2 => R::XMM2,
        XmmReg::Xmm3 => R::XMM3,
        XmmReg::Xmm4 => R::XMM4,
        XmmReg::Xmm5 => R::XMM5,
        XmmReg::Xmm6 => R::XMM6,
        XmmReg::Xmm7 => R::XMM7,
        XmmReg::Xmm8 => R::XMM8,
        XmmReg::Xmm9 => R::XMM9,
        XmmReg::Xmm10 => R::XMM10,
        XmmReg::Xmm11 => R::XMM11,
        XmmReg::Xmm12 => R::XMM12,
        XmmReg::Xmm13 => R::XMM13,
        XmmReg::Xmm14 => R::XMM14,
        XmmReg::Xmm15 => R::XMM15,
    }
}

fn is_callee_saved_gpr(g: Gpr) -> bool {
    CALLEE_SAVED_GPRS
        .iter()
        .any(|p| matches!(p, PhysReg::Gpr(x) if *x == g))
}

fn is_volatile_phys(p: PhysReg) -> bool {
    match p {
        PhysReg::Gpr(g) => g.is_volatile_win64(),
        PhysReg::Xmm(x) => VOLATILE_XMMS.contains(&x),
        PhysReg::Flag(_) => false,
    }
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
            IrTerminator::Ret | IrTerminator::Tail { .. } | IrTerminator::Unreachable => {}
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
    // Each phi dest is written by an edge copy at every predecessor's terminator;
    // its register must be reserved across those points, back-edges included.
    let mut phi_dest_edges: HashMap<ValueId, Vec<usize>> = HashMap::new();

    for (bi, &bid) in order.iter().enumerate() {
        let block = func.block(bid);

        for (pi, phi) in block.phis.iter().enumerate() {
            let pt = linear_point(bi, pi);
            defs.entry(phi.dest).or_insert((pt, phi.ty, None));
        }

        let phi_offset = block.phis.len();

        for (ii, inst) in block.insts.iter().enumerate() {
            let pt = linear_point(bi, phi_offset + ii);
            if matches!(inst.op, IrOp::Call { .. } | IrOp::CallIndirect) {
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

        for succ in successors(&block.term) {
            let target = func.block(succ);
            for phi in &target.phis {
                phi_dest_edges.entry(phi.dest).or_default().push(term_pt);
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

    for (dest, pts) in &phi_dest_edges {
        let minp = *pts.iter().min().unwrap();
        let maxp = *pts.iter().max().unwrap();
        if let Some(d) = defs.get_mut(dest) {
            d.0 = d.0.min(minp);
        }
        last_use
            .entry(*dest)
            .and_modify(|e| *e = (*e).max(maxp))
            .or_insert(maxp);
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

    intervals.sort_by_key(|iv| (iv.start, iv.value.0));
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

    // Physical registers reserved by pinned intervals, with their ranges. A
    // non-pinned value must not occupy one while its own range overlaps: a later
    // pin would otherwise have to move it mid-life, which the single-assignment
    // lowering cannot express.
    let pins: Vec<(PhysReg, usize, usize)> = intervals
        .iter()
        .filter_map(|iv| iv.pinned.map(|p| (p, iv.start, iv.end)))
        .collect();

    let mut avail_gprs: Vec<Gpr> = VOLATILE_GPRS.to_vec();
    let mut avail_xmms: Vec<XmmReg> = VOLATILE_XMMS
        .iter()
        .chain(CALLEE_SAVED_XMMS.iter())
        .copied()
        .collect();

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
    let copies: Vec<RegCopy> = Vec::new();
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
            if iv.crosses_call && is_volatile_phys(pinned) {
                // A value pinned to a volatile register that outlives a call would
                // be clobbered by it, and the single-assignment lowering cannot
                // relocate a pinned value mid-life. reg→reg moves are modeled as a
                // Copy (a fresh value the allocator can place in a callee-saved
                // register), so a correct function never reaches here; reject rather
                // than miscompile if one does.
                return Err(RejectionReason::RegisterPressure);
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
                    // A non-pinned value never sits in a register pinned by an
                    // overlapping interval (enforced by the forbidden-set filter in
                    // the unpinned path), so moving it here would be unsound under
                    // the single-assignment lowering: reject instead.
                    return Err(RejectionReason::RegisterPressure);
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
            let forbidden: HashSet<PhysReg> = pins
                .iter()
                .filter(|(_, s, e)| *s < iv.end && iv.start < *e)
                .map(|(r, _, _)| *r)
                .collect();
            let reg = if needs_xmm {
                let pos = if iv.crosses_call {
                    // Must survive the call → callee-saved XMM (saved in our prologue).
                    free_xmms.iter().position(|x| {
                        is_callee_saved_xmm(*x) && !forbidden.contains(&PhysReg::Xmm(*x))
                    })
                } else {
                    // Prefer a volatile so callee-saved stay free for crossers; fall
                    // back to any free register the pins leave available.
                    free_xmms
                        .iter()
                        .position(|x| {
                            !is_callee_saved_xmm(*x) && !forbidden.contains(&PhysReg::Xmm(*x))
                        })
                        .or_else(|| {
                            free_xmms
                                .iter()
                                .position(|x| !forbidden.contains(&PhysReg::Xmm(*x)))
                        })
                };
                match pos {
                    Some(p) => PhysReg::Xmm(free_xmms.remove(p)),
                    None => return Err(RejectionReason::RegisterPressure),
                }
            } else {
                let pos = if iv.crosses_call {
                    // Must survive the call → callee-saved GPR only.
                    free_gprs.iter().position(|g| {
                        is_callee_saved_gpr(*g) && !forbidden.contains(&PhysReg::Gpr(*g))
                    })
                } else {
                    // Prefer a volatile so callee-saved stay free for crossers;
                    // fall back to any free register the pins leave available.
                    free_gprs
                        .iter()
                        .position(|g| {
                            !is_callee_saved_gpr(*g) && !forbidden.contains(&PhysReg::Gpr(*g))
                        })
                        .or_else(|| {
                            free_gprs
                                .iter()
                                .position(|g| !forbidden.contains(&PhysReg::Gpr(*g)))
                        })
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
    let edge_copies = compute_edge_copies(func, &order, &intervals, &assignments)?;

    Ok(RegAllocation {
        assignments,
        copies,
        edge_copies,
    })
}

fn successors(term: &IrTerminator) -> Vec<BlockId> {
    match term {
        IrTerminator::Jump(t) => vec![*t],
        IrTerminator::Branch {
            taken, not_taken, ..
        } => vec![*taken, *not_taken],
        IrTerminator::Ret | IrTerminator::Tail { .. } | IrTerminator::Unreachable => vec![],
    }
}

/// SSA destruction: for every edge `pred -> succ` whose successor carries phis,
/// build the parallel register copy (succ phi dest <- that pred's phi arg) and
/// sequentialize it. A residual copy cycle is broken with a volatile register
/// free at the predecessor's terminator; if none is free the function is
/// rejected (D5: never spill to the stack).
fn compute_edge_copies(
    func: &IrFunction,
    order: &[BlockId],
    intervals: &[LiveInterval],
    assignments: &HashMap<ValueId, PhysReg>,
) -> Result<HashMap<(BlockId, BlockId), Vec<RegCopy>>, RejectionReason> {
    let mut order_index: HashMap<BlockId, usize> = HashMap::new();
    for (i, &b) in order.iter().enumerate() {
        order_index.insert(b, i);
    }
    let mut result: HashMap<(BlockId, BlockId), Vec<RegCopy>> = HashMap::new();
    for &pb in order {
        let pred = func.block(pb);
        let pidx = order_index[&pb];
        let pterm = linear_point(pidx, pred.phis.len() + pred.insts.len());
        for sb in successors(&pred.term) {
            let succ = func.block(sb);
            if succ.phis.is_empty() {
                continue;
            }
            let mut pairs: Vec<(PhysReg, PhysReg, IrType)> = Vec::new();
            for phi in &succ.phis {
                let Some((_, src_val)) = phi.args.iter().find(|(pr, _)| *pr == pb) else {
                    continue;
                };
                let (Some(&dst), Some(&src)) =
                    (assignments.get(&phi.dest), assignments.get(src_val))
                else {
                    return Err(RejectionReason::RegisterPressure);
                };
                pairs.push((dst, src, phi.ty));
            }
            let busy: HashSet<PhysReg> = intervals
                .iter()
                .filter(|iv| iv.start <= pterm && pterm <= iv.end)
                .filter_map(|iv| assignments.get(&iv.value).copied())
                .collect();
            let edge_regs: HashSet<PhysReg> = pairs.iter().flat_map(|(d, s, _)| [*d, *s]).collect();
            let mut free_gpr: Vec<PhysReg> = VOLATILE_GPRS
                .iter()
                .map(|g| PhysReg::Gpr(*g))
                .filter(|r| !busy.contains(r) && !edge_regs.contains(r))
                .collect();
            let mut free_xmm: Vec<PhysReg> = VOLATILE_XMMS
                .iter()
                .map(|x| PhysReg::Xmm(*x))
                .filter(|r| !busy.contains(r) && !edge_regs.contains(r))
                .collect();
            let seq = sequence_copies(&pairs, &mut free_gpr, &mut free_xmm)
                .ok_or(RejectionReason::RegisterPressure)?;
            if !seq.is_empty() {
                result.insert((pb, sb), seq);
            }
        }
    }
    Ok(result)
}

/// Sequentialize a parallel register copy. Each destination is written once, so
/// the move graph is chains and simple cycles: emit a move whose destination no
/// pending move still reads, and break a residual cycle by parking one register
/// in a free scratch. Returns `None` when a cycle needs a scratch and none is
/// free.
fn sequence_copies(
    pairs: &[(PhysReg, PhysReg, IrType)],
    free_gpr: &mut Vec<PhysReg>,
    free_xmm: &mut Vec<PhysReg>,
) -> Option<Vec<RegCopy>> {
    let mut moves: Vec<(PhysReg, PhysReg, IrType)> =
        pairs.iter().copied().filter(|(d, s, _)| d != s).collect();
    let mut out: Vec<RegCopy> = Vec::new();
    while !moves.is_empty() {
        if let Some(i) = moves
            .iter()
            .position(|(d, _, _)| !moves.iter().any(|(_, s, _)| s == d))
        {
            let (to, from, ty) = moves.remove(i);
            out.push(RegCopy {
                point: 0,
                from,
                to,
                ty,
            });
        } else {
            let d = moves[0].0;
            let ty = moves[0].2;
            let scratch = match d {
                PhysReg::Xmm(_) => free_xmm.pop(),
                _ => free_gpr.pop(),
            }?;
            out.push(RegCopy {
                point: 0,
                from: d,
                to: scratch,
                ty,
            });
            for m in moves.iter_mut() {
                if m.1 == d {
                    m.1 = scratch;
                }
            }
        }
    }
    Some(out)
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
            edge_copies: HashMap::new(),
        };
        assert_eq!(
            callee_saved_used(&alloc),
            vec![iced_x86::Register::RBX, iced_x86::Register::R13]
        );
    }

    #[test]
    fn xmm_value_across_call_uses_callee_saved() {
        // An XMM value live across a call previously rejected (no callee-saved XMM
        // pool); with XMM6..XMM15 it must allocate and be reported as used.
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let addr = func.alloc_value();
        let xv = func.alloc_value();
        let callret = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(addr),
                    op: IrOp::Const(0x1000),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(xv),
                    op: IrOp::Load,
                    args: vec![addr],
                    ty: IrType::I128,
                },
                Inst {
                    dest: Some(callret),
                    op: IrOp::Call { target: 0x2000 },
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Store,
                    args: vec![addr, xv],
                    ty: IrType::I128,
                },
            ],
            term: IrTerminator::Ret,
        });

        let alloc = allocate_registers(&func, &CALLEE_SAVED_GPRS, &HashSet::new(), &HashMap::new())
            .expect("xmm-across-call must allocate with the callee-saved pool");
        let phys = alloc.assignments[&xv];
        assert!(
            matches!(phys, PhysReg::Xmm(x) if is_callee_saved_xmm(x)),
            "xmm value crossing a call must land in a callee-saved XMM, got {phys:?}"
        );
        assert_eq!(
            callee_saved_xmms_used(&alloc),
            vec![iced_x86::Register::XMM6]
        );
    }

    #[test]
    fn volatile_pinned_value_across_call_rejects() {
        // A value pinned to a volatile register (an incoming arg) that outlives a
        // call would be clobbered by it, and the single-assignment lowering cannot
        // relocate a pinned value mid-life, so the allocator rejects rather than
        // miscompile. Recovering these needs live-range splitting (see STATUS).
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let arg = func.alloc_value();
        let callret = func.alloc_value();
        let data = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(arg),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(callret),
                    op: IrOp::Call { target: 0x2000 },
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(data),
                    op: IrOp::Const(7),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Store,
                    args: vec![arg, data],
                    ty: IrType::I64,
                },
            ],
            term: IrTerminator::Ret,
        });
        let mut pins = HashMap::new();
        pins.insert(arg, PhysReg::Gpr(Gpr::Rcx));
        let r = allocate_registers(&func, &CALLEE_SAVED_GPRS, &HashSet::new(), &pins);
        assert!(
            matches!(r, Err(RejectionReason::RegisterPressure)),
            "a volatile-pinned value crossing a call must reject, got {r:?}"
        );
    }

    #[test]
    fn nonpinned_value_avoids_overlapping_pinned_register() {
        // v0 is live across the point where v1 is pinned to R9 (both feed v2).
        // v0 must not also take R9 — otherwise the later pin would force an
        // unsound mid-life register move.
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let v0 = func.alloc_value();
        let v1 = func.alloc_value();
        let v2 = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(v0),
                    op: IrOp::Const(1),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v1),
                    op: IrOp::Const(2),
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
                    dest: None,
                    op: IrOp::Use,
                    args: vec![v2],
                    ty: IrType::I64,
                },
            ],
            term: IrTerminator::Ret,
        });
        let mut pins = HashMap::new();
        pins.insert(v1, PhysReg::Gpr(Gpr::R9));
        let alloc = allocate_registers(&func, &CALLEE_SAVED_GPRS, &HashSet::new(), &pins).unwrap();
        assert_eq!(alloc.assignments[&v1], PhysReg::Gpr(Gpr::R9));
        assert_ne!(alloc.assignments[&v0], PhysReg::Gpr(Gpr::R9));
        assert!(
            alloc.copies.is_empty(),
            "no mid-life register move should be emitted"
        );
    }
}
