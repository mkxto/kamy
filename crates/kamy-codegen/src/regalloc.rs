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
    pub flag_scratch: Option<PhysReg>,
}

#[derive(Debug, Clone)]
struct LiveInterval {
    value: ValueId,
    ty: IrType,
    start: usize,
    end: usize,
    pinned: Option<PhysReg>,
    clobbers: u64,
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

fn register_mask(phys: PhysReg) -> u64 {
    let index = match phys {
        PhysReg::Gpr(g) => g.index(),
        PhysReg::Xmm(x) => 16 + x.index(),
        PhysReg::Flag(f) => 32 + f.index(),
    };
    1u64 << index
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
            IrTerminator::Ret
            | IrTerminator::NoReturn
            | IrTerminator::Tail { .. }
            | IrTerminator::Unreachable => {}
        }
    }
    order
}

fn linear_point(block_index: usize, inst_index: usize) -> usize {
    block_index * 1024 + inst_index
}

fn interval_bump(
    lo: &mut HashMap<ValueId, usize>,
    hi: &mut HashMap<ValueId, usize>,
    v: ValueId,
    pt: usize,
) {
    lo.entry(v).and_modify(|e| *e = (*e).min(pt)).or_insert(pt);
    hi.entry(v).and_modify(|e| *e = (*e).max(pt)).or_insert(pt);
}

/// Live intervals over the linearized `order`. Liveness is a real backward
/// SSA dataflow (to a fixpoint, so back edges are honored): a value live across
/// a loop — a loop-carried phi value or a loop-invariant value defined before
/// the loop and used inside it — stays live from the loop header through the
/// latch's back-edge terminator. Each interval is the convex hull (min start,
/// max end) of every linear point where the value is defined, used, or live,
/// which is sound for single-interval linear scan regardless of block order:
/// collapsing holes only over-reserves a register, never under-reserves it.
/// The earlier syntactic last-use heuristic truncated loop-crossing values at
/// their textually-last use, so a later-ordered in-loop block could reuse the
/// register mid-loop and clobber the live value (issue #24).
fn compute_live_intervals(
    func: &IrFunction,
    order: &[BlockId],
) -> (Vec<LiveInterval>, Vec<(PhysReg, usize, usize)>) {
    let n = order.len();
    let mut pos: HashMap<BlockId, usize> = HashMap::new();
    for (i, &b) in order.iter().enumerate() {
        pos.insert(b, i);
    }

    let mut def_pt: HashMap<ValueId, usize> = HashMap::new();
    let mut ty_of: HashMap<ValueId, IrType> = HashMap::new();
    let mut clobber_points: Vec<(usize, u64)> = Vec::new();
    // Reserve physical writes even when their separately modeled outputs die.
    let mut write_pins: Vec<(PhysReg, usize, usize)> = Vec::new();

    for (bi, &bid) in order.iter().enumerate() {
        let block = func.block(bid);
        for (pi, phi) in block.phis.iter().enumerate() {
            def_pt.entry(phi.dest).or_insert(linear_point(bi, pi));
            ty_of.entry(phi.dest).or_insert(phi.ty);
        }
        let phi_off = block.phis.len();
        for (ii, inst) in block.insts.iter().enumerate() {
            let pt = linear_point(bi, phi_off + ii);
            if let IrOp::Call { clobbers, .. } | IrOp::CallIndirect { clobbers } = &inst.op {
                let mask = clobbers
                    .iter()
                    .fold(0, |mask, &phys| mask | register_mask(phys));
                clobber_points.push((pt, mask));
            }
            if let IrOp::NativeInline(native) = &inst.op {
                let mask = native
                    .writes
                    .iter()
                    .fold(0, |mask, &phys| mask | register_mask(phys));
                clobber_points.push((pt, mask));
                for w in &native.writes {
                    write_pins.push((*w, pt, pt));
                }
            }
            if matches!(
                inst.op,
                IrOp::UDiv | IrOp::SDiv | IrOp::UMulHi | IrOp::SMulHi
            ) {
                let rax = PhysReg::Gpr(Gpr::Rax);
                let rdx = PhysReg::Gpr(Gpr::Rdx);
                clobber_points.push((pt, register_mask(rax) | register_mask(rdx)));
                write_pins.push((rax, pt, pt));
                write_pins.push((rdx, pt, pt));
            }
            let projection = match inst.op {
                IrOp::URem | IrOp::SRem if inst.args.len() == 1 => Some(Gpr::Rdx),
                IrOp::Mul if inst.args.len() == 1 => Some(Gpr::Rax),
                _ => None,
            };
            if let Some(register) = projection {
                if let Some(&producer) = def_pt.get(&inst.args[0]) {
                    // The secondary hardware result exists before its projection.
                    write_pins.push((PhysReg::Gpr(register), producer, pt));
                }
            }
            if let Some(dest) = inst.dest {
                def_pt.entry(dest).or_insert(pt);
                ty_of.entry(dest).or_insert(inst.ty);
            }
        }
    }

    // Per-block use/def for liveness. `use_set` holds upward-exposed uses (read
    // before any in-block def); phi destinations are defined at block entry and
    // phi arguments are consumed on the predecessor edge, not read in the block.
    let mut use_set: Vec<HashSet<ValueId>> = vec![HashSet::new(); n];
    let mut def_set: Vec<HashSet<ValueId>> = vec![HashSet::new(); n];
    let mut edge_use: Vec<HashSet<ValueId>> = vec![HashSet::new(); n];
    let succ_idx: Vec<Vec<usize>> = order
        .iter()
        .map(|&bid| {
            successors(&func.block(bid).term)
                .iter()
                .filter_map(|s| pos.get(s).copied())
                .collect()
        })
        .collect();

    for (bi, &bid) in order.iter().enumerate() {
        let block = func.block(bid);
        let mut defined: HashSet<ValueId> = HashSet::new();
        for phi in &block.phis {
            def_set[bi].insert(phi.dest);
            defined.insert(phi.dest);
        }
        for inst in &block.insts {
            for &v in &inst.args {
                if !defined.contains(&v) {
                    use_set[bi].insert(v);
                }
            }
            if let Some(d) = inst.dest {
                def_set[bi].insert(d);
                defined.insert(d);
            }
        }
        if let IrTerminator::Branch { cond, .. } = &block.term {
            if !defined.contains(cond) {
                use_set[bi].insert(*cond);
            }
        }
        for s in successors(&block.term) {
            for phi in &func.block(s).phis {
                for (pred, val) in &phi.args {
                    if *pred == bid {
                        edge_use[bi].insert(*val);
                    }
                }
            }
        }
    }

    let mut live_in: Vec<HashSet<ValueId>> = vec![HashSet::new(); n];
    let mut live_out: Vec<HashSet<ValueId>> = vec![HashSet::new(); n];
    let mut changed = true;
    while changed {
        changed = false;
        for bi in (0..n).rev() {
            let mut new_out = edge_use[bi].clone();
            for &s in &succ_idx[bi] {
                new_out.extend(live_in[s].iter().copied());
            }
            let mut new_in = use_set[bi].clone();
            for &v in &new_out {
                if !def_set[bi].contains(&v) {
                    new_in.insert(v);
                }
            }
            if new_out != live_out[bi] {
                live_out[bi] = new_out;
                changed = true;
            }
            if new_in != live_in[bi] {
                live_in[bi] = new_in;
                changed = true;
            }
        }
    }

    let mut lo: HashMap<ValueId, usize> = HashMap::new();
    let mut hi: HashMap<ValueId, usize> = HashMap::new();
    for (&v, &p) in &def_pt {
        interval_bump(&mut lo, &mut hi, v, p);
    }
    for (bi, &bid) in order.iter().enumerate() {
        let block = func.block(bid);
        let phi_off = block.phis.len();
        for (ii, inst) in block.insts.iter().enumerate() {
            let pt = linear_point(bi, phi_off + ii);
            for &v in &inst.args {
                interval_bump(&mut lo, &mut hi, v, pt);
            }
        }
        let term_pt = linear_point(bi, phi_off + block.insts.len());
        if let IrTerminator::Branch { cond, .. } = &block.term {
            interval_bump(&mut lo, &mut hi, *cond, term_pt);
        }
        for s in successors(&block.term) {
            for phi in &func.block(s).phis {
                for (pred, val) in &phi.args {
                    if *pred == bid {
                        interval_bump(&mut lo, &mut hi, *val, term_pt);
                    }
                }
            }
        }
        let start_pt = linear_point(bi, 0);
        for &v in &live_in[bi] {
            interval_bump(&mut lo, &mut hi, v, start_pt);
        }
        for &v in &live_out[bi] {
            interval_bump(&mut lo, &mut hi, v, term_pt);
        }
    }

    let mut intervals: Vec<LiveInterval> = def_pt
        .keys()
        .map(|&vid| {
            let start = lo[&vid];
            let end = hi[&vid];
            let clobbers = clobber_points
                .iter()
                .filter(|(point, _)| start < *point && *point < end)
                .fold(0, |mask, (_, effects)| mask | effects);
            LiveInterval {
                value: vid,
                ty: ty_of[&vid],
                start,
                end,
                pinned: None,
                clobbers,
            }
        })
        .collect();

    intervals.sort_by_key(|iv| (iv.start, iv.value.0));
    (intervals, write_pins)
}

/// True iff a *used* flag op can be re-established at its consumer by
/// re-executing the producing op into a scratch register: add flags
/// (`CarryAdd/OverflowAdd/AuxCarryAdd`), or shift flags
/// (`CarryShl/CarryShr/CarrySar`) whose count is a constant. Variable-count
/// shift flags are excluded (reproducing them needs CL, which is not modeled).
fn consumes_recomputable_flag(func: &IrFunction) -> bool {
    let mut used = HashSet::new();
    for b in &func.blocks {
        for i in &b.insts {
            used.extend(i.args.iter().copied());
        }
        for p in &b.phis {
            used.extend(p.args.iter().map(|(_, v)| *v));
        }
        if let IrTerminator::Branch { cond, .. } = &b.term {
            used.insert(*cond);
        }
    }
    let is_const = |vid: ValueId| -> bool {
        func.blocks.iter().any(|b| {
            b.insts
                .iter()
                .any(|i| i.dest == Some(vid) && matches!(i.op, IrOp::Const(_)))
        })
    };
    func.blocks.iter().any(|b| {
        b.insts.iter().any(|i| {
            i.dest.is_some_and(|d| used.contains(&d))
                && match i.op {
                    IrOp::CarryAdd | IrOp::OverflowAdd | IrOp::AuxCarryAdd => true,
                    IrOp::CarryShl | IrOp::CarryShr | IrOp::CarrySar => is_const(i.args[1]),
                    _ => false,
                }
        })
    })
}

fn validate_implicit_arithmetic(
    func: &IrFunction,
    reg_pins: &HashMap<ValueId, PhysReg>,
) -> Result<(), RejectionReason> {
    let rax = PhysReg::Gpr(Gpr::Rax);
    let rdx = PhysReg::Gpr(Gpr::Rdx);
    let pinned = |value: Option<ValueId>, phys| {
        value.is_some_and(|value| reg_pins.get(&value) == Some(&phys))
    };
    for block in &func.blocks {
        let mut division = None;
        let mut product = None;
        for inst in &block.insts {
            if (matches!(
                inst.op,
                IrOp::UDiv | IrOp::SDiv | IrOp::URem | IrOp::SRem | IrOp::UMulHi | IrOp::SMulHi
            ) || (matches!(inst.op, IrOp::Mul) && inst.args.len() == 1))
                && !matches!(
                    inst.ty,
                    IrType::I8 | IrType::I16 | IrType::I32 | IrType::I64
                )
            {
                return Err(RejectionReason::UnsupportedInstruction);
            }
            match &inst.op {
                IrOp::UDiv | IrOp::SDiv => {
                    if inst.args.len() != 3
                        || !pinned(inst.dest, rax)
                        || !pinned(inst.args.first().copied(), rdx)
                        || !pinned(inst.args.get(1).copied(), rax)
                        || inst.args.get(2).is_some_and(|value| {
                            matches!(reg_pins.get(value), Some(phys) if *phys == rax || *phys == rdx)
                        })
                    {
                        return Err(RejectionReason::UnsupportedInstruction);
                    }
                    division = Some((inst.dest.unwrap(), inst.ty, matches!(inst.op, IrOp::SDiv)));
                    product = None;
                }
                IrOp::UMulHi | IrOp::SMulHi => {
                    if inst.args.len() != 2
                        || !pinned(inst.dest, rdx)
                        || !pinned(inst.args.first().copied(), rax)
                    {
                        return Err(RejectionReason::UnsupportedInstruction);
                    }
                    division = None;
                    product = Some((inst.dest.unwrap(), inst.ty));
                }
                IrOp::URem | IrOp::SRem => {
                    if inst.args.len() != 1
                        || !pinned(inst.dest, rdx)
                        || division
                            != inst
                                .args
                                .first()
                                .map(|&quotient| (quotient, inst.ty, matches!(inst.op, IrOp::SRem)))
                    {
                        return Err(RejectionReason::UnsupportedInstruction);
                    }
                }
                IrOp::Mul if inst.args.len() != 2 => {
                    if inst.args.len() != 1
                        || !pinned(inst.dest, rax)
                        || product != inst.args.first().map(|&high| (high, inst.ty))
                    {
                        return Err(RejectionReason::UnsupportedInstruction);
                    }
                }
                _ => {
                    let writes = |phys| match &inst.op {
                        IrOp::Call { clobbers, .. } | IrOp::CallIndirect { clobbers } => {
                            clobbers.contains(&phys)
                        }
                        IrOp::NativeInline(native) => native.writes.contains(&phys),
                        _ => false,
                    };
                    if writes(rdx) || pinned(inst.dest, rdx) {
                        division = None;
                    }
                    if writes(rax) || pinned(inst.dest, rax) {
                        product = None;
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn allocate_registers(
    func: &IrFunction,
    saved_regs: &[PhysReg],
    rsp_pinned: &HashSet<ValueId>,
    reg_pins: &HashMap<ValueId, PhysReg>,
) -> Result<RegAllocation, RejectionReason> {
    validate_implicit_arithmetic(func, reg_pins)?;
    let order = block_order(func);
    let (mut intervals, write_pins) = compute_live_intervals(func, &order);
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
    // lowering cannot express. Physical native/implicit-arithmetic writes add
    // reservations even when their output values do not survive DCE.
    let mut pins: Vec<(PhysReg, usize, usize)> = intervals
        .iter()
        .filter_map(|iv| iv.pinned.map(|p| (p, iv.start, iv.end)))
        .collect();
    pins.extend(write_pins);

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

    // If a branch/setcc consumes an add- or constant-count-shift flag, the x86
    // flags are re-established at the consumer by re-executing the op into a
    // reserved scratch (R11). Reserve it here so no value is ever placed there.
    let flag_scratch: Option<PhysReg> = if consumes_recomputable_flag(func) {
        if intervals
            .iter()
            .any(|iv| iv.pinned == Some(PhysReg::Gpr(Gpr::R11)))
        {
            // R11 genuinely live; cannot reserve it as scratch. Reject soundly.
            return Err(RejectionReason::RegisterPressure);
        }
        avail_gprs.retain(|g| *g != Gpr::R11);
        free_gprs.retain(|g| *g != Gpr::R11);
        Some(PhysReg::Gpr(Gpr::R11))
    } else {
        None
    };

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
            if iv.clobbers & register_mask(pinned) != 0 {
                // Values consumed at the write or defined after it do not cross
                // the clobber; a pinned value live through it cannot move.
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
                    // Two overlapping pins cannot be split by this allocator.
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
                let pos = if iv.clobbers != 0 {
                    free_xmms.iter().position(|x| {
                        iv.clobbers & register_mask(PhysReg::Xmm(*x)) == 0
                            && !forbidden.contains(&PhysReg::Xmm(*x))
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
                let pos = if iv.clobbers != 0 {
                    free_gprs.iter().position(|g| {
                        iv.clobbers & register_mask(PhysReg::Gpr(*g)) == 0
                            && !forbidden.contains(&PhysReg::Gpr(*g))
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
        flag_scratch,
    })
}

fn successors(term: &IrTerminator) -> Vec<BlockId> {
    match term {
        IrTerminator::Jump(t) => vec![*t],
        IrTerminator::Branch {
            taken, not_taken, ..
        } => vec![*taken, *not_taken],
        IrTerminator::Ret
        | IrTerminator::NoReturn
        | IrTerminator::Tail { .. }
        | IrTerminator::Unreachable => vec![],
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
    fn branch_on_add_flag_reserves_r11_scratch() {
        // b0: a=Undef, b=Undef, r=Add(a,b), cf=CarryAdd(a,b); branch cf -> b1:b2
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let a = func.alloc_value();
        let b = func.alloc_value();
        let r = func.alloc_value();
        let cf = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(a),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(b),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(r),
                    op: IrOp::Add,
                    args: vec![a, b],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(cf),
                    op: IrOp::CarryAdd,
                    args: vec![a, b],
                    ty: IrType::I8,
                },
            ],
            term: IrTerminator::Branch {
                cond: cf,
                taken: BlockId(1),
                not_taken: BlockId(2),
            },
        });
        for id in [BlockId(1), BlockId(2)] {
            func.blocks.push(IrBlock {
                id,
                phis: vec![],
                insts: vec![],
                term: IrTerminator::Ret,
            });
        }
        let mut reg_pins = HashMap::new();
        reg_pins.insert(a, PhysReg::Gpr(Gpr::Rcx));
        reg_pins.insert(b, PhysReg::Gpr(Gpr::Rdx));
        let alloc =
            allocate_registers(&func, &CALLEE_SAVED_GPRS, &HashSet::new(), &reg_pins).unwrap();
        assert_eq!(alloc.flag_scratch, Some(PhysReg::Gpr(Gpr::R11)));
        assert!(
            !alloc
                .assignments
                .values()
                .any(|p| *p == PhysReg::Gpr(Gpr::R11)),
            "R11 is reserved as flag scratch and must not be assigned to any value"
        );
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
            flag_scratch: None,
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
                    op: IrOp::Call {
                        target: kamy_core::Reference {
                            source: kamy_core::SymbolId::Host {
                                rva: kamy_core::Rva::ZERO,
                            },
                            offset: 0,
                            expression: kamy_core::SymbolicExpression::symbol(
                                kamy_core::SymbolId::Host {
                                    rva: kamy_core::Rva::new(0x2000),
                                },
                            ),
                            field: kamy_core::LinkField::Relative32 { bias: 0 },
                            origin: kamy_core::ReferenceOrigin::HostAnalysis,
                        },
                        clobbers: kamy_core::ir::win64_volatiles(),
                    },
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
                    op: IrOp::Call {
                        target: kamy_core::Reference {
                            source: kamy_core::SymbolId::Host {
                                rva: kamy_core::Rva::ZERO,
                            },
                            offset: 0,
                            expression: kamy_core::SymbolicExpression::symbol(
                                kamy_core::SymbolId::Host {
                                    rva: kamy_core::Rva::new(0x2000),
                                },
                            ),
                            field: kamy_core::LinkField::Relative32 { bias: 0 },
                            origin: kamy_core::ReferenceOrigin::HostAnalysis,
                        },
                        clobbers: kamy_core::ir::win64_volatiles(),
                    },
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

    // A `NativeInline` re-emits raw bytes that read/write fixed physical
    // registers. The lifter pins the read values to the read regs and the
    // write-Undef to the write reg; regalloc must honor those pins and must not
    // park a value live across the native in the native's write register.
    #[test]
    fn native_inline_pins_reads_writes_and_spares_live_across() {
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let across = func.alloc_value(); // defined before, used after the native
        let rcx_v = func.alloc_value(); // read value pinned to RCX
        let rdx_v = func.alloc_value(); // read value pinned to RDX
        let nv = func.alloc_value(); // dead NativeInline dest
        let rax_v = func.alloc_value(); // write-Undef pinned to RAX
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(across),
                    op: IrOp::Const(10),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(rcx_v),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(rdx_v),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(nv),
                    op: IrOp::NativeInline(NativeInst {
                        bytes: vec![0x90],
                        references: vec![],
                        reads: vec![PhysReg::Gpr(Gpr::Rcx), PhysReg::Gpr(Gpr::Rdx)],
                        writes: vec![PhysReg::Gpr(Gpr::Rax)],
                    }),
                    args: vec![rcx_v, rdx_v],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(rax_v),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![across],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![rax_v],
                    ty: IrType::I64,
                },
            ],
            term: IrTerminator::Ret,
        });
        let mut pins = HashMap::new();
        pins.insert(rcx_v, PhysReg::Gpr(Gpr::Rcx));
        pins.insert(rdx_v, PhysReg::Gpr(Gpr::Rdx));
        pins.insert(rax_v, PhysReg::Gpr(Gpr::Rax));
        let alloc = allocate_registers(&func, &CALLEE_SAVED_GPRS, &HashSet::new(), &pins).unwrap();
        assert_eq!(alloc.assignments[&rcx_v], PhysReg::Gpr(Gpr::Rcx));
        assert_eq!(alloc.assignments[&rdx_v], PhysReg::Gpr(Gpr::Rdx));
        assert_eq!(alloc.assignments[&rax_v], PhysReg::Gpr(Gpr::Rax));
        // `across` is live over the native, so it must not land in the write reg
        // (RAX) the raw bytes clobber, nor in either read reg.
        assert_ne!(alloc.assignments[&across], PhysReg::Gpr(Gpr::Rax));
        assert_ne!(alloc.assignments[&across], PhysReg::Gpr(Gpr::Rcx));
        assert_ne!(alloc.assignments[&across], PhysReg::Gpr(Gpr::Rdx));
    }

    fn implicit_division_function(
        ty: IrType,
        signed: bool,
    ) -> (IrFunction, HashMap<ValueId, PhysReg>) {
        let insts = [
            (Some(ValueId(0)), IrOp::Const(0), vec![]),
            (Some(ValueId(1)), IrOp::Const(41), vec![]),
            (Some(ValueId(2)), IrOp::Const(3), vec![]),
            (
                Some(ValueId(3)),
                if signed { IrOp::SDiv } else { IrOp::UDiv },
                vec![ValueId(0), ValueId(1), ValueId(2)],
            ),
            (
                Some(ValueId(4)),
                if signed { IrOp::SRem } else { IrOp::URem },
                vec![ValueId(3)],
            ),
            (Some(ValueId(5)), IrOp::Copy, vec![ValueId(3)]),
            (Some(ValueId(6)), IrOp::Copy, vec![ValueId(4)]),
            (None, IrOp::Use, vec![ValueId(5), ValueId(6)]),
        ]
        .into_iter()
        .map(|(dest, op, args)| Inst { dest, op, args, ty })
        .collect();
        let func = IrFunction {
            entry: BlockId(0),
            next_value: 7,
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts,
                term: IrTerminator::Ret,
            }],
        };
        let pins = HashMap::from([
            (ValueId(0), PhysReg::Gpr(Gpr::Rdx)),
            (ValueId(1), PhysReg::Gpr(Gpr::Rax)),
            (ValueId(3), PhysReg::Gpr(Gpr::Rax)),
            (ValueId(4), PhysReg::Gpr(Gpr::Rdx)),
        ]);
        (func, pins)
    }

    #[test]
    fn implicit_arithmetic_allows_input_output_boundaries_and_spares_live_values() {
        for ty in [IrType::I8, IrType::I16, IrType::I32, IrType::I64] {
            for signed in [false, true] {
                let (mut func, pins) = implicit_division_function(ty, signed);
                let alloc = allocate_registers(&func, &[], &HashSet::new(), &pins).unwrap();
                assert_eq!(alloc.assignments[&ValueId(0)], PhysReg::Gpr(Gpr::Rdx));
                assert_eq!(alloc.assignments[&ValueId(1)], PhysReg::Gpr(Gpr::Rax));
                assert_eq!(alloc.assignments[&ValueId(3)], PhysReg::Gpr(Gpr::Rax));
                assert_eq!(alloc.assignments[&ValueId(4)], PhysReg::Gpr(Gpr::Rdx));
                assert_ne!(alloc.assignments[&ValueId(2)], PhysReg::Gpr(Gpr::Rax));
                assert_ne!(alloc.assignments[&ValueId(2)], PhysReg::Gpr(Gpr::Rdx));
                func.blocks[0].insts.push(Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![ValueId(1)],
                    ty,
                });
                assert!(matches!(
                    allocate_registers(&func, &[], &HashSet::new(), &pins),
                    Err(RejectionReason::RegisterPressure)
                ));

                let (mut func, mut pins) = implicit_division_function(ty, signed);
                func.blocks[0].insts[3].op = if signed { IrOp::SMulHi } else { IrOp::UMulHi };
                func.blocks[0].insts[3].args = vec![ValueId(1), ValueId(2)];
                func.blocks[0]
                    .insts
                    .retain(|inst| inst.dest != Some(ValueId(4)) && inst.dest != Some(ValueId(6)));
                func.blocks[0].insts.last_mut().unwrap().args = vec![ValueId(5)];
                pins.insert(ValueId(3), PhysReg::Gpr(Gpr::Rdx));
                pins.remove(&ValueId(4));
                let alloc = allocate_registers(&func, &[], &HashSet::new(), &pins).unwrap();
                assert_eq!(alloc.assignments[&ValueId(3)], PhysReg::Gpr(Gpr::Rdx));
                assert_ne!(alloc.assignments[&ValueId(2)], PhysReg::Gpr(Gpr::Rax));
                func.blocks[0].insts.push(Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![ValueId(1)],
                    ty,
                });
                assert!(matches!(
                    allocate_registers(&func, &[], &HashSet::new(), &pins),
                    Err(RejectionReason::RegisterPressure)
                ));
            }
        }
    }

    #[test]
    fn division_holds_rdx_until_the_remainder_projection() {
        let (mut func, pins) = implicit_division_function(IrType::I64, false);
        func.next_value = 8;
        func.blocks[0].insts.insert(
            4,
            Inst {
                dest: Some(ValueId(7)),
                op: IrOp::Const(99),
                args: vec![],
                ty: IrType::I64,
            },
        );
        func.blocks[0].insts.insert(
            5,
            Inst {
                dest: None,
                op: IrOp::Use,
                args: vec![ValueId(7)],
                ty: IrType::I64,
            },
        );
        let alloc = allocate_registers(&func, &[], &HashSet::new(), &pins).unwrap();
        assert_ne!(alloc.assignments[&ValueId(7)], PhysReg::Gpr(Gpr::Rdx));
        let (_, reservations) = compute_live_intervals(&func, &block_order(&func));
        assert!(reservations.contains(&(PhysReg::Gpr(Gpr::Rdx), 3, 6)));
    }

    fn implicit_multiplication_function(
        ty: IrType,
        signed: bool,
    ) -> (IrFunction, HashMap<ValueId, PhysReg>) {
        let (mut func, mut pins) = implicit_division_function(ty, signed);
        func.blocks[0].insts[3].op = if signed { IrOp::SMulHi } else { IrOp::UMulHi };
        func.blocks[0].insts[3].args = vec![ValueId(1), ValueId(2)];
        func.blocks[0].insts[4].op = IrOp::Mul;
        pins.insert(ValueId(3), PhysReg::Gpr(Gpr::Rdx));
        pins.insert(ValueId(4), PhysReg::Gpr(Gpr::Rax));
        (func, pins)
    }

    #[test]
    fn multiplication_projects_the_low_result_without_losing_rax() {
        for ty in [IrType::I8, IrType::I16, IrType::I32, IrType::I64] {
            for signed in [false, true] {
                let (mut func, pins) = implicit_multiplication_function(ty, signed);
                func.next_value = 8;
                func.blocks[0].insts.insert(
                    4,
                    Inst {
                        dest: Some(ValueId(7)),
                        op: IrOp::Const(99),
                        args: vec![],
                        ty,
                    },
                );
                func.blocks[0].insts.insert(
                    5,
                    Inst {
                        dest: None,
                        op: IrOp::Use,
                        args: vec![ValueId(7)],
                        ty,
                    },
                );
                let alloc = allocate_registers(&func, &[], &HashSet::new(), &pins).unwrap();
                assert_eq!(alloc.assignments[&ValueId(3)], PhysReg::Gpr(Gpr::Rdx));
                assert_eq!(alloc.assignments[&ValueId(4)], PhysReg::Gpr(Gpr::Rax));
                assert_ne!(alloc.assignments[&ValueId(2)], PhysReg::Gpr(Gpr::Rax));
                assert_ne!(alloc.assignments[&ValueId(7)], PhysReg::Gpr(Gpr::Rax));
                let (_, reservations) = compute_live_intervals(&func, &block_order(&func));
                assert!(reservations.contains(&(PhysReg::Gpr(Gpr::Rax), 3, 6)));
            }
        }
    }

    #[test]
    fn malformed_low_product_projections_fail_closed() {
        for invalid in 0..8 {
            let (mut func, mut pins) = implicit_multiplication_function(IrType::I64, false);
            match invalid {
                0 => {
                    pins.remove(&ValueId(4));
                }
                1 => {
                    func.blocks[0].insts[4].args = vec![ValueId(1)];
                }
                2 => {
                    func.blocks[0].insts[4].ty = IrType::I128;
                }
                3 => {
                    func.blocks[0].insts[3].ty = IrType::I32;
                }
                4 => {
                    func.blocks[0].insts.insert(
                        4,
                        Inst {
                            dest: None,
                            op: IrOp::NativeInline(NativeInst {
                                bytes: vec![0x0f, 0x31],
                                references: vec![],
                                reads: vec![],
                                writes: vec![PhysReg::Gpr(Gpr::Rax), PhysReg::Gpr(Gpr::Rdx)],
                            }),
                            args: vec![],
                            ty: IrType::I64,
                        },
                    );
                }
                5 => {
                    func.next_value = 8;
                    func.blocks[0].insts.insert(
                        4,
                        Inst {
                            dest: Some(ValueId(7)),
                            op: IrOp::Const(99),
                            args: vec![],
                            ty: IrType::I64,
                        },
                    );
                    pins.insert(ValueId(7), PhysReg::Gpr(Gpr::Rax));
                }
                6 => {
                    func.blocks[0].insts[4].args.clear();
                }
                _ => {
                    pins.remove(&ValueId(3));
                }
            }
            assert!(matches!(
                allocate_registers(&func, &[], &HashSet::new(), &pins),
                Err(RejectionReason::UnsupportedInstruction)
            ));
        }
    }

    #[test]
    fn malformed_implicit_arithmetic_contracts_fail_closed() {
        for invalid in 0..8 {
            let (mut func, mut pins) = implicit_division_function(IrType::I64, false);
            match invalid {
                0 => {
                    pins.remove(&ValueId(3));
                }
                1 => {
                    pins.insert(ValueId(0), PhysReg::Gpr(Gpr::Rcx));
                }
                2 => {
                    func.blocks[0].insts[4].op = IrOp::SRem;
                }
                3 => {
                    func.blocks[0].insts[3].ty = IrType::I128;
                }
                4 => {
                    func.blocks[0].insts[4].args = vec![ValueId(0)];
                }
                5 => {
                    func.blocks[0].insts.insert(
                        4,
                        Inst {
                            dest: None,
                            op: IrOp::NativeInline(NativeInst {
                                bytes: vec![0x0f, 0x31],
                                references: vec![],
                                reads: vec![],
                                writes: vec![PhysReg::Gpr(Gpr::Rax), PhysReg::Gpr(Gpr::Rdx)],
                            }),
                            args: vec![],
                            ty: IrType::I64,
                        },
                    );
                }
                6 => {
                    pins.insert(ValueId(2), PhysReg::Gpr(Gpr::Rdx));
                }
                _ => {
                    func.blocks[0].insts[3].args.pop();
                }
            }
            assert!(matches!(
                allocate_registers(&func, &[], &HashSet::new(), &pins),
                Err(RejectionReason::UnsupportedInstruction)
            ));
        }
    }

    #[test]
    fn native_writes_reject_crossing_pins_but_allow_read_modify_write_boundaries() {
        for (phys, ty, bytes) in [
            (PhysReg::Gpr(Gpr::Rax), IrType::I64, vec![0x48, 0x0f, 0xc8]),
            (
                PhysReg::Xmm(XmmReg::Xmm0),
                IrType::I128,
                vec![0x66, 0x0f, 0x70, 0xc0, 0],
            ),
        ] {
            let input = ValueId(0);
            let output = ValueId(1);
            let mut func = IrFunction {
                entry: BlockId(0),
                next_value: 2,
                blocks: vec![IrBlock {
                    id: BlockId(0),
                    phis: vec![],
                    insts: vec![
                        Inst {
                            dest: Some(input),
                            op: IrOp::Undef,
                            args: vec![],
                            ty,
                        },
                        Inst {
                            dest: None,
                            op: IrOp::NativeInline(NativeInst {
                                bytes,
                                references: vec![],
                                reads: vec![phys],
                                writes: vec![phys],
                            }),
                            args: vec![input],
                            ty,
                        },
                        Inst {
                            dest: Some(output),
                            op: IrOp::Undef,
                            args: vec![],
                            ty,
                        },
                        Inst {
                            dest: None,
                            op: IrOp::Use,
                            args: vec![output],
                            ty,
                        },
                    ],
                    term: IrTerminator::Ret,
                }],
            };
            let pins = HashMap::from([(input, phys), (output, phys)]);
            let alloc =
                allocate_registers(&func, &CALLEE_SAVED_GPRS, &HashSet::new(), &pins).unwrap();
            assert_eq!(alloc.assignments[&input], phys);
            assert_eq!(alloc.assignments[&output], phys);
            func.blocks[0].insts.push(Inst {
                dest: None,
                op: IrOp::Use,
                args: vec![input],
                ty,
            });
            assert!(matches!(
                allocate_registers(&func, &CALLEE_SAVED_GPRS, &HashSet::new(), &pins),
                Err(RejectionReason::RegisterPressure)
            ));
        }
    }

    // Issue #24: a value defined before a loop and used inside it is live across
    // the back-edge, so its interval must reach the latch's terminator. The old
    // syntactic last-use heuristic ended it at the in-body use, letting a later
    // block reuse the register mid-loop and clobber the live value.
    #[test]
    fn loop_invariant_value_lives_across_back_edge() {
        // b0: inv=Undef, seed=Undef -> b1
        // b1 header: cur=phi(seed, cur2); c=IsZero(cur); branch -> b3(exit):b2(body)
        // b2 body: t=Add(cur,inv); one=Const(1); cur2=Sub(cur,one); Use(t) -> b1
        // b3: ret
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let inv = func.alloc_value();
        let seed = func.alloc_value();
        let cur = func.alloc_value();
        let c = func.alloc_value();
        let t = func.alloc_value();
        let one = func.alloc_value();
        let cur2 = func.alloc_value();

        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(inv),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(seed),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I64,
                },
            ],
            term: IrTerminator::Jump(BlockId(1)),
        });
        func.blocks.push(IrBlock {
            id: BlockId(1),
            phis: vec![Phi {
                dest: cur,
                ty: IrType::I64,
                args: vec![(BlockId(0), seed), (BlockId(2), cur2)],
            }],
            insts: vec![Inst {
                dest: Some(c),
                op: IrOp::IsZero,
                args: vec![cur],
                ty: IrType::I8,
            }],
            term: IrTerminator::Branch {
                cond: c,
                taken: BlockId(3),
                not_taken: BlockId(2),
            },
        });
        func.blocks.push(IrBlock {
            id: BlockId(2),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(t),
                    op: IrOp::Add,
                    args: vec![cur, inv],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(one),
                    op: IrOp::Const(1),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(cur2),
                    op: IrOp::Sub,
                    args: vec![cur, one],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![t],
                    ty: IrType::I64,
                },
            ],
            term: IrTerminator::Jump(BlockId(1)),
        });
        func.blocks.push(IrBlock {
            id: BlockId(3),
            phis: vec![],
            insts: vec![],
            term: IrTerminator::Ret,
        });

        let order = block_order(&func);
        let (intervals, _) = compute_live_intervals(&func, &order);
        let inv_iv = intervals
            .iter()
            .find(|iv| iv.value == inv)
            .expect("inv has an interval");
        let b2 = func.block(BlockId(2));
        let b2_idx = order.iter().position(|&b| b == BlockId(2)).unwrap();
        let latch_term = linear_point(b2_idx, b2.phis.len() + b2.insts.len());
        assert!(
            inv_iv.end >= latch_term,
            "loop-invariant value must stay live through the back-edge: end={} latch_term={}",
            inv_iv.end,
            latch_term
        );
    }
}

#[cfg(test)]
mod symbolic_abi_tests {
    use super::*;
    use kamy_core::ir::{Inst, IrBlock};

    #[test]
    fn call_liveness_uses_contract_clobbers_not_win64_register_names() {
        let value = ValueId(0);
        let target = kamy_core::Reference {
            source: kamy_core::SymbolId::Host {
                rva: kamy_core::Rva::new(0x1000),
            },
            offset: 1,
            expression: kamy_core::SymbolicExpression::symbol(kamy_core::SymbolId::Generated {
                name: "helper".into(),
            }),
            field: kamy_core::LinkField::Relative32 { bias: 0 },
            origin: kamy_core::ReferenceOrigin::Generated,
        };
        let mut func = IrFunction {
            entry: BlockId(0),
            next_value: 1,
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![
                    Inst {
                        dest: Some(value),
                        op: IrOp::Const(7),
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: None,
                        op: IrOp::Call {
                            target,
                            clobbers: vec![PhysReg::Gpr(Gpr::Rax)],
                        },
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: None,
                        op: IrOp::Use,
                        args: vec![value],
                        ty: IrType::I64,
                    },
                ],
                term: IrTerminator::Ret,
            }],
        };
        let pins = HashMap::from([(value, PhysReg::Gpr(Gpr::Rcx))]);
        assert!(allocate_registers(&func, &CALLEE_SAVED_GPRS, &HashSet::new(), &pins).is_ok());
        if let IrOp::Call { clobbers, .. } = &mut func.blocks[0].insts[1].op {
            *clobbers = vec![PhysReg::Gpr(Gpr::Rcx)];
        }
        assert!(allocate_registers(&func, &CALLEE_SAVED_GPRS, &HashSet::new(), &pins).is_err());
    }
}
