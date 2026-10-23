use std::collections::{HashMap, HashSet, VecDeque};

use crate::RejectionReason;
use crate::ir::{
    BlockId, Gpr, Inst, IrFunction, IrOp, IrTerminator, IrType, Phi, PhysReg, ValueId,
};

mod bounds;
mod index;

pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueClass {
    Gpr,
    Xmm,
    Flag,
}

#[derive(Clone, Copy, Debug)]
pub struct FrameHome {
    pub offset: u32,
    pub ty: IrType,
    pub class: ValueClass,
}

#[derive(Clone, Copy, Debug)]
pub struct FrameSave {
    pub register: PhysReg,
    pub offset: u32,
}

/// Conservative entry-RSP intervals, not an enumeration of feasible starts.
/// Select/Phi definitions retain alternatives when gaps matter to access safety.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FramePointerBounds {
    pub negative: Option<(i64, i64)>,
    pub incoming: Option<(i64, i64)>,
}

impl FramePointerBounds {
    fn observe(&mut self, delta: i64) {
        let interval = if delta < 0 {
            &mut self.negative
        } else {
            &mut self.incoming
        };
        let (low, high) = interval.get_or_insert((delta, delta));
        *low = (*low).min(delta);
        *high = (*high).max(delta);
    }

    fn is_empty(self) -> bool {
        self.negative.is_none() && self.incoming.is_none()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FrameIndexedAddress {
    pub base: ValueId,
    pub index: ValueId,
    pub displacement: i64,
    pub subtract: bool,
    pub bounds: FramePointerBounds,
}

#[derive(Clone, Debug, Default)]
pub struct FrameAnalysis {
    pub offsets: HashMap<ValueId, i64>,
    pub constants: HashMap<ValueId, u64>,
    pub derived_offsets: HashMap<ValueId, (ValueId, i64)>,
    // Finite aliases retain original entry-RSP coordinates, not relocated home addresses.
    pub pointer_bounds: HashMap<ValueId, FramePointerBounds>,
    pub indexed_offsets: HashMap<ValueId, FrameIndexedAddress>,
    pub induction_bounds: HashMap<ValueId, FramePointerBounds>,
    pub original_size: u32,
    pub outgoing_size: u32,
    pub call_deltas: HashMap<(BlockId, usize), i64>,
}

#[derive(Clone, Debug, Default)]
pub struct ConcreteFrame {
    pub stack_size: u32,
    pub original_size: u32,
    pub outgoing_size: u32,
    pub copy_scratch: u32,
    pub saves: Vec<FrameSave>,
}

impl ConcreteFrame {
    pub fn address_offset(&self, delta: i64) -> i64 {
        if delta < 0 {
            i64::from(self.original_size) + delta
        } else {
            i64::from(self.stack_size) + delta
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fact {
    Unknown,
    Scalar(Option<u64>),
    Offset(i64),
    Variable,
    Conflict,
    Overflow,
}

impl Fact {
    fn merge(self, other: Self) -> Self {
        use Fact::*;
        match (self, other) {
            (Overflow, _) | (_, Overflow) => Overflow,
            (Conflict, _) | (_, Conflict) => Conflict,
            (Unknown, value) | (value, Unknown) => value,
            (Variable, _) | (_, Variable) => Variable,
            (Offset(a), Offset(b)) if a == b => Offset(a),
            (Offset(_), Offset(_)) => Conflict,
            (Scalar(a), Scalar(b)) if a == b => Scalar(a),
            (Scalar(_), Scalar(_)) => Scalar(None),
            _ => Variable,
        }
    }

    fn offset(self) -> Result<i64, RejectionReason> {
        match self {
            Self::Offset(delta) => Ok(delta),
            Self::Conflict => Err(RejectionReason::FrameConflict),
            Self::Overflow => Err(RejectionReason::FrameOverflow),
            _ => Err(RejectionReason::FrameDynamic),
        }
    }
}

#[derive(Clone, Copy)]
enum Definition<'a> {
    Phi(&'a Phi),
    Inst(&'a Inst),
}

fn same_scalar(
    left: ValueId,
    right: ValueId,
    definitions: &HashMap<ValueId, Definition<'_>>,
    depth: usize,
) -> bool {
    if left == right {
        return true;
    }
    if depth == 0 {
        return false;
    }
    let (Some(Definition::Inst(left)), Some(Definition::Inst(right))) =
        (definitions.get(&left), definitions.get(&right))
    else {
        return false;
    };
    left.ty == right.ty
        && left.args.len() == 1
        && right.args.len() == 1
        && matches!(
            (&left.op, &right.op),
            (IrOp::Copy, IrOp::Copy)
                | (IrOp::Trunc, IrOp::Trunc)
                | (IrOp::Zext, IrOp::Zext)
                | (IrOp::Sext, IrOp::Sext)
        )
        && same_scalar(left.args[0], right.args[0], definitions, depth - 1)
}

impl Definition<'_> {
    fn dest(self) -> Option<ValueId> {
        match self {
            Self::Phi(phi) => Some(phi.dest),
            Self::Inst(inst) => inst.dest,
        }
    }

    fn evaluate(
        self,
        facts: &HashMap<ValueId, Fact>,
        definitions: &HashMap<ValueId, Definition<'_>>,
        reachable: &HashSet<BlockId>,
    ) -> Fact {
        let get = |value: &ValueId| facts.get(value).copied().unwrap_or(Fact::Unknown);
        match self {
            Self::Phi(phi) => {
                let fact = phi
                    .args
                    .iter()
                    .filter(|(block, _)| reachable.contains(block))
                    .fold(Fact::Unknown, |fact, (_, value)| fact.merge(get(value)));
                match fact {
                    Fact::Offset(_) if phi.ty != IrType::I64 => Fact::Variable,
                    fact => fact,
                }
            }
            Self::Inst(inst) => {
                let mask = if inst.ty.bits() < 64 {
                    (1u64 << inst.ty.bits()) - 1
                } else {
                    u64::MAX
                };
                match &inst.op {
                    IrOp::Const(value) => Fact::Scalar(Some(*value & mask)),
                    IrOp::FrameAddress(delta) => Fact::Offset(*delta),
                    IrOp::FrameIndex { .. } => Fact::Conflict,
                    IrOp::FrameOffset(offset) if inst.args.len() == 1 => arithmetic(
                        get(&inst.args[0]),
                        Fact::Scalar(Some(*offset as u64)),
                        false,
                    ),
                    IrOp::Select if inst.args.len() == 3 => {
                        let fact = match get(&inst.args[0]) {
                            // An unevaluated condition is bottom, not a runtime choice.
                            Fact::Unknown => Fact::Unknown,
                            Fact::Scalar(Some(0)) => get(&inst.args[2]),
                            Fact::Scalar(Some(_)) => get(&inst.args[1]),
                            _ => get(&inst.args[1]).merge(get(&inst.args[2])),
                        };
                        match fact {
                            Fact::Offset(_) | Fact::Conflict if inst.ty != IrType::I64 => {
                                Fact::Variable
                            }
                            fact => fact,
                        }
                    }
                    IrOp::Copy | IrOp::Zext | IrOp::Trunc | IrOp::Sext if inst.args.len() == 1 => {
                        match get(&inst.args[0]) {
                            Fact::Scalar(Some(value)) => {
                                let value = if matches!(inst.op, IrOp::Sext) {
                                    let bits = match definitions.get(&inst.args[0]) {
                                        Some(Definition::Inst(source)) => source.ty.bits(),
                                        Some(Definition::Phi(source)) => source.ty.bits(),
                                        None => 64,
                                    }
                                    .min(64);
                                    let shift = 64 - bits;
                                    (((value << shift) as i64) >> shift) as u64
                                } else {
                                    value
                                };
                                Fact::Scalar(Some(value & mask))
                            }
                            fact if matches!(inst.op, IrOp::Copy) && inst.ty == IrType::I64 => fact,
                            Fact::Offset(_) | Fact::Conflict | Fact::Variable => Fact::Variable,
                            fact => fact,
                        }
                    }
                    IrOp::Add | IrOp::Sub if inst.args.len() == 2 => {
                        match arithmetic(
                            get(&inst.args[0]),
                            get(&inst.args[1]),
                            matches!(inst.op, IrOp::Sub),
                        ) {
                            Fact::Scalar(Some(value)) => Fact::Scalar(Some(value & mask)),
                            Fact::Offset(_) if inst.ty != IrType::I64 => Fact::Variable,
                            fact => fact,
                        }
                    }
                    IrOp::And | IrOp::Or | IrOp::Xor if inst.args.len() == 2 => {
                        match (get(&inst.args[0]), get(&inst.args[1])) {
                            _ if matches!(inst.op, IrOp::Xor)
                                && same_scalar(
                                    inst.args[0],
                                    inst.args[1],
                                    definitions,
                                    definitions.len(),
                                ) =>
                            {
                                Fact::Scalar(Some(0))
                            }
                            (Fact::Scalar(Some(left)), Fact::Scalar(Some(right))) => {
                                let value = match inst.op {
                                    IrOp::And => left & right,
                                    IrOp::Or => left | right,
                                    _ => left ^ right,
                                };
                                Fact::Scalar(Some(value & mask))
                            }
                            (Fact::Unknown, _) | (_, Fact::Unknown) => Fact::Unknown,
                            (Fact::Scalar(_), Fact::Scalar(_)) => Fact::Scalar(None),
                            _ => Fact::Variable,
                        }
                    }
                    IrOp::Shl if inst.args.len() == 2 => {
                        match (get(&inst.args[0]), get(&inst.args[1])) {
                            (Fact::Scalar(Some(value)), Fact::Scalar(Some(count))) => {
                                let count_mask = if inst.ty == IrType::I64 { 63 } else { 31 };
                                Fact::Scalar(Some(
                                    value.wrapping_shl((count & count_mask) as u32) & mask,
                                ))
                            }
                            (Fact::Unknown, _) | (_, Fact::Unknown) => Fact::Unknown,
                            (Fact::Scalar(_), Fact::Scalar(_)) => Fact::Scalar(None),
                            _ => Fact::Variable,
                        }
                    }
                    _ => Fact::Scalar(None),
                }
            }
        }
    }
}

fn arithmetic(left: Fact, right: Fact, subtract: bool) -> Fact {
    use Fact::*;
    match (left, right) {
        (Overflow, _) | (_, Overflow) => Overflow,
        (Offset(a), Offset(b)) if subtract => Scalar(Some(a.wrapping_sub(b) as u64)),
        (Offset(_) | Conflict, Offset(_) | Conflict) if subtract => Scalar(None),
        (Conflict, _) | (_, Conflict) => Conflict,
        (Unknown, _) | (_, Unknown) => Unknown,
        (Scalar(Some(a)), Scalar(Some(b))) => Scalar(Some(if subtract {
            a.wrapping_sub(b)
        } else {
            a.wrapping_add(b)
        })),
        (Offset(delta), Scalar(Some(constant))) => {
            let result = if subtract {
                delta.checked_sub(constant as i64)
            } else {
                delta.checked_add(constant as i64)
            };
            result.map_or(Overflow, Offset)
        }
        (Scalar(Some(constant)), Offset(delta)) if !subtract => {
            delta.checked_add(constant as i64).map_or(Overflow, Offset)
        }
        (Scalar(_), Scalar(_)) => Scalar(None),
        _ => Variable,
    }
}

fn relative_frame_offset(
    inst: &Inst,
    facts: &HashMap<ValueId, Fact>,
) -> Result<Option<(ValueId, i64)>, RejectionReason> {
    match (&inst.op, inst.args.as_slice()) {
        (IrOp::FrameOffset(offset), [source]) => Ok(Some((*source, *offset))),
        (IrOp::Add | IrOp::Sub, [left, right]) => match (facts.get(left), facts.get(right)) {
            (_, Some(Fact::Scalar(Some(constant)))) => {
                let offset = if matches!(inst.op, IrOp::Sub) {
                    (*constant as i64)
                        .checked_neg()
                        .ok_or(RejectionReason::FrameOverflow)?
                } else {
                    *constant as i64
                };
                Ok(Some((*left, offset)))
            }
            (Some(Fact::Scalar(Some(constant))), _) if matches!(inst.op, IrOp::Add) => {
                Ok(Some((*right, *constant as i64)))
            }
            _ => Ok(None),
        },
        _ => Ok(None),
    }
}

#[derive(Default)]
struct AccessScratch {
    pending: Vec<(ValueId, i64, bool)>,
    active: HashMap<ValueId, i64>,
    // Query-local completed traversals, not proofs reusable across roots or extents.
    completed: HashSet<(ValueId, i64)>,
    unknown: bool,
    bounds: FramePointerBounds,
    proven: HashMap<ValueId, FramePointerBounds>,
    #[cfg(test)]
    visits: usize,
}

fn check_access(
    value: ValueId,
    extent: i64,
    facts: &HashMap<ValueId, Fact>,
    definitions: &HashMap<ValueId, Definition<'_>>,
    reachable: &HashSet<BlockId>,
    scratch: &mut AccessScratch,
    minimum: &mut i64,
) -> Result<(), RejectionReason> {
    scratch.pending.clear();
    scratch.active.clear();
    scratch.completed.clear();
    #[cfg(test)]
    {
        scratch.visits = 0;
    }
    scratch.unknown = false;
    scratch.bounds = FramePointerBounds::default();
    scratch.pending.push((value, 0, false));
    while let Some((value, adjustment, exiting)) = scratch.pending.pop() {
        #[cfg(test)]
        {
            scratch.visits += 1;
        }
        if exiting {
            scratch.active.remove(&value);
            scratch.completed.insert((value, adjustment));
            continue;
        }
        if let Some(previous) = scratch.active.get(&value) {
            if *previous == adjustment {
                continue;
            }
            return Err(RejectionReason::FrameDynamic);
        }
        if scratch.completed.contains(&(value, adjustment)) {
            continue;
        }
        let fact = facts.get(&value).copied().unwrap_or(Fact::Unknown);
        let mut interval_conflict = false;
        if let Some(bounds) = scratch.proven.get(&value).copied() {
            if let Some(bounds) = index::access_bounds(bounds, adjustment, extent)? {
                for (low, high) in [bounds.negative, bounds.incoming].into_iter().flatten() {
                    *minimum = (*minimum).min(low);
                    scratch.bounds.observe(low);
                    scratch.bounds.observe(high);
                }
                scratch.completed.insert((value, adjustment));
                continue;
            }
            // No scratch state was committed by the failed certificate. The
            // original alternatives, not invented interval points, decide.
            interval_conflict = true;
        }
        if let Fact::Offset(delta) = fact {
            let start = delta
                .checked_add(adjustment)
                .ok_or(RejectionReason::FrameOverflow)?;
            let end = start
                .checked_add(extent)
                .ok_or(RejectionReason::FrameOverflow)?;
            i32::try_from(start).map_err(|_| RejectionReason::FrameOverflow)?;
            i32::try_from(end).map_err(|_| RejectionReason::FrameOverflow)?;
            if start < 0 && end >= 0 {
                return Err(RejectionReason::FrameConflict);
            }
            *minimum = (*minimum).min(start);
            scratch.bounds.observe(start);
            scratch.completed.insert((value, adjustment));
            continue;
        }
        match fact {
            Fact::Variable if !interval_conflict => return Err(RejectionReason::FrameDynamic),
            Fact::Overflow => return Err(RejectionReason::FrameOverflow),
            Fact::Conflict | Fact::Variable => {}
            _ => {
                scratch.unknown = true;
                scratch.completed.insert((value, adjustment));
                continue;
            }
        }
        let unsupported = if interval_conflict {
            RejectionReason::FrameConflict
        } else {
            RejectionReason::FrameDynamic
        };
        scratch.active.insert(value, adjustment);
        scratch.pending.push((value, adjustment, true));
        match definitions.get(&value).copied() {
            Some(Definition::Phi(phi)) if phi.ty == IrType::I64 => {
                scratch.pending.extend(
                    phi.args
                        .iter()
                        .filter(|(block, _)| reachable.contains(block))
                        .map(|(_, arg)| (*arg, adjustment, false)),
                );
            }
            Some(Definition::Inst(inst))
                if inst.ty == IrType::I64 && matches!(inst.op, IrOp::Copy) =>
            {
                let [source] = inst.args.as_slice() else {
                    return Err(RejectionReason::FrameDynamic);
                };
                scratch.pending.push((*source, adjustment, false));
            }
            Some(Definition::Inst(inst))
                if inst.ty == IrType::I64 && matches!(inst.op, IrOp::Select) =>
            {
                let [condition, yes, no] = inst.args.as_slice() else {
                    return Err(RejectionReason::FrameDynamic);
                };
                match facts.get(condition) {
                    None | Some(Fact::Unknown) => scratch.unknown = true,
                    Some(Fact::Scalar(Some(0))) => {
                        scratch.pending.push((*no, adjustment, false));
                    }
                    Some(Fact::Scalar(Some(_))) => {
                        scratch.pending.push((*yes, adjustment, false));
                    }
                    _ => {
                        scratch.pending.push((*yes, adjustment, false));
                        scratch.pending.push((*no, adjustment, false));
                    }
                }
            }
            Some(Definition::Inst(inst)) if inst.ty == IrType::I64 => {
                let (input, offset) = relative_frame_offset(inst, facts)?.ok_or(unsupported)?;
                let adjustment = adjustment
                    .checked_add(offset)
                    .ok_or(RejectionReason::FrameOverflow)?;
                scratch.pending.push((input, adjustment, false));
            }
            _ => return Err(unsupported),
        }
    }
    Ok(())
}

impl FrameAnalysis {
    pub fn analyze(
        func: &IrFunction,
        rsp_pinned: &HashSet<ValueId>,
        pins: &HashMap<ValueId, PhysReg>,
    ) -> Result<Self, RejectionReason> {
        let blocks: HashMap<_, _> = func.blocks.iter().map(|block| (block.id, block)).collect();
        let mut reachable = HashSet::new();
        let mut pending = vec![func.entry];
        while let Some(id) = pending.pop() {
            if !reachable.insert(id) {
                continue;
            }
            let block = blocks.get(&id).ok_or(RejectionReason::FrameConflict)?;
            match block.term {
                IrTerminator::Jump(target) => pending.push(target),
                IrTerminator::Branch {
                    taken, not_taken, ..
                } => {
                    pending.push(taken);
                    pending.push(not_taken);
                }
                _ => {}
            }
        }

        let mut actual_rsp = rsp_pinned.clone();
        actual_rsp.extend(pins.iter().filter_map(|(&value, &register)| {
            (register == PhysReg::Gpr(Gpr::Rsp)).then_some(value)
        }));
        let seed = blocks[&func.entry].insts.iter().find_map(|inst| {
            inst.dest
                .filter(|value| actual_rsp.contains(value) && matches!(inst.op, IrOp::Undef))
        });
        let mut definitions = Vec::new();
        let mut users: HashMap<ValueId, Vec<usize>> = HashMap::new();
        let mut defined = HashMap::new();
        for block in &func.blocks {
            if !reachable.contains(&block.id) {
                continue;
            }
            for phi in &block.phis {
                let index = definitions.len();
                definitions.push(Definition::Phi(phi));
                if defined.insert(phi.dest, Definition::Phi(phi)).is_some() {
                    return Err(RejectionReason::FrameConflict);
                }
                for (_, arg) in phi.args.iter().filter(|(id, _)| reachable.contains(id)) {
                    users.entry(*arg).or_default().push(index);
                }
            }
            for inst in &block.insts {
                let Some(dest) = inst.dest else {
                    continue;
                };
                let index = definitions.len();
                definitions.push(Definition::Inst(inst));
                if defined.insert(dest, Definition::Inst(inst)).is_some() {
                    return Err(RejectionReason::FrameConflict);
                }
                for arg in &inst.args {
                    users.entry(*arg).or_default().push(index);
                }
            }
        }
        let mut facts = HashMap::with_capacity(definitions.len());
        if let Some(value) = seed {
            facts.insert(value, Fact::Offset(0));
        }
        let mut work: VecDeque<_> = (0..definitions.len()).collect();
        let mut queued = vec![true; definitions.len()];
        while let Some(index) = work.pop_front() {
            queued[index] = false;
            let definition = definitions[index];
            let Some(dest) = definition.dest() else {
                continue;
            };
            if Some(dest) == seed {
                continue;
            }
            let old = facts.get(&dest).copied().unwrap_or(Fact::Unknown);
            let fact = old.merge(definition.evaluate(&facts, &defined, &reachable));
            if old == fact {
                continue;
            }
            facts.insert(dest, fact);
            for &user in users.get(&dest).into_iter().flatten() {
                if !queued[user] {
                    queued[user] = true;
                    work.push_back(user);
                }
            }
        }

        let mut analysis = Self::default();
        let mut minimum = 0i64;
        if facts.values().any(|fact| match fact {
            Fact::Overflow => true,
            Fact::Offset(delta) => i32::try_from(*delta).is_err(),
            _ => false,
        }) {
            return Err(RejectionReason::FrameOverflow);
        }
        for (&value, &fact) in &facts {
            match fact {
                Fact::Scalar(Some(constant)) => {
                    analysis.constants.insert(value, constant);
                }
                Fact::Offset(delta) => {
                    analysis.offsets.insert(value, delta);
                    minimum = minimum.min(delta);
                }
                _ => {}
            }
        }
        for block in &func.blocks {
            if !reachable.contains(&block.id) {
                continue;
            }
            for inst in &block.insts {
                if let IrOp::FrameIndex { bounds, .. } = inst.op {
                    index::validate(bounds)?;
                    let [_, _] = inst.args.as_slice() else {
                        return Err(RejectionReason::FrameDynamic);
                    };
                    let dest = inst.dest.ok_or(RejectionReason::FrameDynamic)?;
                    analysis.pointer_bounds.insert(dest, bounds);
                }
            }
        }
        let loop_bounds = bounds::loops(func, &facts, &defined, &reachable)?;
        analysis.induction_bounds = loop_bounds.pointers.clone();
        analysis.pointer_bounds.extend(loop_bounds.pointers);
        analysis.derived_offsets.extend(loop_bounds.advances);
        for &value in actual_rsp
            .iter()
            .filter(|value| defined.contains_key(*value))
        {
            if facts.get(&value) == Some(&Fact::Conflict) {
                return Err(RejectionReason::FrameConflict);
            }
        }
        for &value in actual_rsp
            .iter()
            .filter(|value| defined.contains_key(*value))
        {
            facts
                .get(&value)
                .copied()
                .unwrap_or(Fact::Unknown)
                .offset()?;
        }

        let mut access_scratch = AccessScratch {
            proven: analysis.pointer_bounds.clone(),
            ..AccessScratch::default()
        };
        for (&value, &fact) in &facts {
            if fact != Fact::Conflict
                || analysis.pointer_bounds.contains_key(&value)
                || !matches!(defined.get(&value), Some(Definition::Phi(_)))
            {
                continue;
            }
            let mut pointer_minimum = minimum;
            if check_access(
                value,
                0,
                &facts,
                &defined,
                &reachable,
                &mut access_scratch,
                &mut pointer_minimum,
            )
            .is_ok()
                && !access_scratch.unknown
                && !access_scratch.bounds.is_empty()
            {
                minimum = pointer_minimum;
                analysis.pointer_bounds.insert(value, access_scratch.bounds);
                access_scratch.proven.insert(value, access_scratch.bounds);
            }
        }
        let mut scalars = bounds::ScalarAnalysis::new(&facts, &defined, &loop_bounds.scalars);
        let mut pointer_work: VecDeque<_> = (0..definitions.len()).collect();
        queued.fill(true);
        while let Some(index) = pointer_work.pop_front() {
            queued[index] = false;
            let definition = definitions[index];
            let Some(dest) = definition.dest() else {
                continue;
            };
            if analysis.offsets.contains_key(&dest) || analysis.pointer_bounds.contains_key(&dest) {
                continue;
            }
            let proof = match definition {
                Definition::Phi(phi) => {
                    index::phi(phi, &facts, &analysis.pointer_bounds, &reachable).map(|bounds| {
                        index::PointerProof {
                            bounds,
                            indexed: None,
                            relative: None,
                        }
                    })
                }
                Definition::Inst(inst) if matches!(inst.op, IrOp::Select) => {
                    index::select(inst, &facts, &analysis.pointer_bounds).map(|bounds| {
                        index::PointerProof {
                            bounds,
                            indexed: None,
                            relative: None,
                        }
                    })
                }
                Definition::Inst(_) => index::prove(
                    dest,
                    &facts,
                    &defined,
                    &analysis.pointer_bounds,
                    &mut scalars,
                )?,
            };
            let Some(index::PointerProof {
                bounds,
                indexed,
                relative,
            }) = proof
            else {
                continue;
            };
            analysis.pointer_bounds.insert(dest, bounds);
            access_scratch.proven.insert(dest, bounds);
            if let Some(indexed) = indexed {
                analysis.indexed_offsets.insert(dest, indexed);
            }
            if let Some(relative) = relative {
                analysis.derived_offsets.insert(dest, relative);
            }
            for &user in users.get(&dest).into_iter().flatten() {
                if !queued[user] {
                    queued[user] = true;
                    pointer_work.push_back(user);
                }
            }
        }
        for bounds in analysis.pointer_bounds.values() {
            if let Some((low, _)) = bounds.negative {
                minimum = minimum.min(low);
            }
        }
        for block in &func.blocks {
            if !reachable.contains(&block.id) {
                continue;
            }
            for (index, inst) in block.insts.iter().enumerate() {
                if let Some(dest) = inst.dest.filter(|dest| {
                    inst.ty == IrType::I64
                        && (matches!(inst.op, IrOp::FrameOffset(_))
                            || facts.get(dest) == Some(&Fact::Conflict))
                }) {
                    if let Some((source, offset)) = relative_frame_offset(inst, &facts)? {
                        let mut derived_minimum = minimum;
                        match check_access(
                            dest,
                            0,
                            &facts,
                            &defined,
                            &reachable,
                            &mut access_scratch,
                            &mut derived_minimum,
                        ) {
                            Ok(())
                                if !access_scratch.unknown && !access_scratch.bounds.is_empty() =>
                            {
                                minimum = derived_minimum;
                                if !analysis.offsets.contains_key(&dest) {
                                    analysis.derived_offsets.insert(dest, (source, offset));
                                }
                            }
                            Err(reason)
                                if matches!(inst.op, IrOp::FrameOffset(_))
                                    || reason == RejectionReason::FrameOverflow =>
                            {
                                return Err(reason);
                            }
                            _ if matches!(inst.op, IrOp::FrameOffset(_)) => {
                                return Err(RejectionReason::FrameDynamic);
                            }
                            _ => {}
                        }
                    } else if matches!(inst.op, IrOp::FrameOffset(_)) {
                        return Err(RejectionReason::FrameDynamic);
                    }
                }
                match &inst.op {
                    IrOp::FrameIndex {
                        displacement,
                        subtract,
                        ..
                    } => {
                        let [base, index] = inst.args.as_slice() else {
                            return Err(RejectionReason::FrameDynamic);
                        };
                        let identity = *displacement == 0
                            && !*subtract
                            && matches!(facts.get(index), Some(Fact::Scalar(Some(0))));
                        if inst.ty != IrType::I64
                            || (!identity
                                && !analysis.offsets.contains_key(base)
                                && !analysis.pointer_bounds.contains_key(base))
                            || analysis.offsets.contains_key(index)
                            || analysis.pointer_bounds.contains_key(index)
                        {
                            return Err(RejectionReason::FrameDynamic);
                        }
                    }
                    IrOp::FrameLogical => {
                        let [source] = inst.args.as_slice() else {
                            return Err(RejectionReason::FrameDynamic);
                        };
                        if !analysis.offsets.contains_key(source)
                            && !analysis.pointer_bounds.contains_key(source)
                        {
                            return Err(RejectionReason::FrameDynamic);
                        }
                    }
                    IrOp::StackProbe => {
                        let [size, rsp] = inst.args.as_slice() else {
                            return Err(RejectionReason::FrameDynamic);
                        };
                        let Some(Fact::Scalar(Some(size))) = facts.get(size) else {
                            return Err(RejectionReason::FrameDynamic);
                        };
                        let size =
                            i64::try_from(*size).map_err(|_| RejectionReason::FrameOverflow)?;
                        let delta = facts.get(rsp).copied().unwrap_or(Fact::Unknown).offset()?;
                        let bottom = delta
                            .checked_sub(size)
                            .ok_or(RejectionReason::FrameOverflow)?;
                        i32::try_from(bottom).map_err(|_| RejectionReason::FrameOverflow)?;
                        minimum = minimum.min(bottom);
                    }
                    IrOp::Load | IrOp::Store => {
                        let value = *inst.args.first().ok_or(RejectionReason::FrameDynamic)?;
                        check_access(
                            value,
                            i64::from(inst.ty.bytes() - 1),
                            &facts,
                            &defined,
                            &reachable,
                            &mut access_scratch,
                            &mut minimum,
                        )?;
                    }
                    IrOp::Call { .. } | IrOp::CallIndirect { .. } => {
                        let logical_rsp =
                            inst.args.last().filter(|value| actual_rsp.contains(value));
                        let delta = match logical_rsp {
                            Some(value) => facts
                                .get(value)
                                .copied()
                                .unwrap_or(Fact::Unknown)
                                .offset()?,
                            None if actual_rsp.is_empty() => -40,
                            None => return Err(RejectionReason::FrameDynamic),
                        };
                        if delta > -32 || delta.rem_euclid(16) != 8 {
                            return Err(RejectionReason::FrameConflict);
                        }
                        minimum = minimum.min(delta);
                        analysis.outgoing_size = analysis.outgoing_size.max(32);
                        for (index, value) in inst.args.iter().enumerate() {
                            if Some(value) == logical_rsp
                                || pins.contains_key(value)
                                || (index == 0 && matches!(inst.op, IrOp::CallIndirect { .. }))
                            {
                                continue;
                            }
                            if let Some(endpoint) = analysis.offsets.get(value) {
                                if *endpoint < delta || *endpoint >= 0 {
                                    return Err(RejectionReason::FrameConflict);
                                }
                                let width = endpoint
                                    .checked_sub(delta)
                                    .and_then(|width| width.checked_add(1))
                                    .ok_or(RejectionReason::FrameOverflow)?;
                                let width = u32::try_from(width)
                                    .map_err(|_| RejectionReason::FrameOverflow)?;
                                analysis.outgoing_size = analysis.outgoing_size.max(width);
                            }
                        }
                        analysis.call_deltas.insert((block.id, index), delta);
                    }
                    IrOp::NativeInline(native) => {
                        if native.writes.contains(&PhysReg::Gpr(Gpr::Rsp)) {
                            return Err(RejectionReason::FrameDynamic);
                        }
                        for value in &inst.args {
                            match facts.get(value) {
                                Some(Fact::Variable)
                                    if !analysis.pointer_bounds.contains_key(value) =>
                                {
                                    return Err(RejectionReason::FrameDynamic);
                                }
                                Some(Fact::Conflict)
                                    if !analysis.pointer_bounds.contains_key(value) =>
                                {
                                    check_access(
                                        *value,
                                        0,
                                        &facts,
                                        &defined,
                                        &reachable,
                                        &mut access_scratch,
                                        &mut minimum,
                                    )?;
                                    if access_scratch.unknown || access_scratch.bounds.is_empty() {
                                        return Err(RejectionReason::FrameDynamic);
                                    }
                                    analysis
                                        .pointer_bounds
                                        .insert(*value, access_scratch.bounds);
                                }
                                _ => {}
                            }
                        }
                        if let Some(index) = native
                            .reads
                            .iter()
                            .position(|reg| *reg == PhysReg::Gpr(Gpr::Rsp))
                        {
                            let value =
                                inst.args.get(index).ok_or(RejectionReason::FrameDynamic)?;
                            let delta = facts
                                .get(value)
                                .copied()
                                .unwrap_or(Fact::Unknown)
                                .offset()?;
                            minimum = minimum.min(delta);
                        }
                    }
                    IrOp::Use
                        if index + 1 == block.insts.len()
                            && matches!(
                                block.term,
                                IrTerminator::Ret | IrTerminator::Tail { .. }
                            ) =>
                    {
                        for value in inst.args.iter().filter(|value| actual_rsp.contains(value)) {
                            if facts
                                .get(value)
                                .copied()
                                .unwrap_or(Fact::Unknown)
                                .offset()?
                                != 0
                            {
                                return Err(RejectionReason::FrameConflict);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        let required = u32::try_from(
            minimum
                .checked_neg()
                .ok_or(RejectionReason::FrameOverflow)?,
        )
        .map_err(|_| RejectionReason::FrameOverflow)?;
        if required != 0 {
            analysis.original_size = required
                .checked_add(7)
                .map(|value| value & !15)
                .and_then(|value| value.checked_add(8))
                .ok_or(RejectionReason::FrameOverflow)?;
        }
        if analysis.original_size > MAX_FRAME_SIZE {
            return Err(RejectionReason::FrameResourceLimit);
        }
        Ok(analysis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrBlock, NativeInst};

    fn inst(dest: u32, op: IrOp, args: &[u32]) -> Inst {
        Inst {
            dest: Some(ValueId(dest)),
            op,
            args: args.iter().map(|value| ValueId(*value)).collect(),
            ty: IrType::I64,
        }
    }

    fn function(insts: Vec<Inst>) -> IrFunction {
        IrFunction {
            entry: BlockId(0),
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts,
                term: IrTerminator::Ret,
            }],
            next_value: 32,
        }
    }

    fn analyze(func: &IrFunction, rsp: &[u32]) -> Result<FrameAnalysis, RejectionReason> {
        FrameAnalysis::analyze(
            func,
            &rsp.iter().map(|value| ValueId(*value)).collect(),
            &HashMap::new(),
        )
    }

    fn access_definitions(func: &IrFunction) -> HashMap<ValueId, Definition<'_>> {
        let mut definitions = HashMap::new();
        for block in &func.blocks {
            for phi in &block.phis {
                definitions.insert(phi.dest, Definition::Phi(phi));
            }
            for inst in &block.insts {
                if let Some(dest) = inst.dest {
                    definitions.insert(dest, Definition::Inst(inst));
                }
            }
        }
        definitions
    }

    #[test]
    fn aliases_preserve_negative_and_incoming_coordinates() {
        let func = function(vec![
            inst(0, IrOp::Undef, &[]),
            inst(1, IrOp::Const(72), &[]),
            inst(2, IrOp::Sub, &[0, 1]),
            inst(3, IrOp::Copy, &[2]),
            inst(4, IrOp::Const(112), &[]),
            inst(5, IrOp::Add, &[3, 4]),
            inst(6, IrOp::Add, &[2, 1]),
        ]);
        let analysis = analyze(&func, &[0, 2, 6]).unwrap();
        assert_eq!(analysis.original_size, 72);
        assert_eq!(analysis.offsets[&ValueId(3)], -72);
        assert_eq!(analysis.offsets[&ValueId(5)], 40);
        let frame = ConcreteFrame {
            original_size: analysis.original_size,
            stack_size: 232,
            ..ConcreteFrame::default()
        };
        assert_eq!(frame.address_offset(-72), 0);
        assert_eq!(frame.address_offset(-8), 64);
        assert_eq!(frame.address_offset(0), 232);
        assert_eq!(frame.address_offset(40), 272);
    }

    fn loop_frame(backedge_delta: u64) -> IrFunction {
        let mut func = function(vec![
            inst(0, IrOp::Undef, &[]),
            inst(1, IrOp::Const(40), &[]),
            inst(2, IrOp::Sub, &[0, 1]),
        ]);
        func.blocks[0].term = IrTerminator::Jump(BlockId(1));
        func.blocks.push(IrBlock {
            id: BlockId(1),
            phis: vec![Phi {
                dest: ValueId(3),
                ty: IrType::I64,
                args: vec![(BlockId(0), ValueId(2)), (BlockId(1), ValueId(5))],
            }],
            insts: vec![
                inst(4, IrOp::Const(backedge_delta), &[]),
                inst(5, IrOp::Add, &[3, 4]),
            ],
            term: IrTerminator::Jump(BlockId(1)),
        });
        func
    }

    #[test]
    fn seeded_equal_loop_phi_is_proven() {
        let analysis = analyze(&loop_frame(0), &[0, 2, 3, 5]).unwrap();
        assert_eq!(analysis.offsets[&ValueId(3)], -40);
        assert_eq!(analysis.offsets[&ValueId(5)], -40);
    }

    #[test]
    fn conflicting_loop_rsp_is_specific() {
        assert_eq!(
            analyze(&loop_frame(16), &[0, 2, 3, 5]).unwrap_err(),
            RejectionReason::FrameConflict,
        );
    }

    #[test]
    fn successor_undef_is_not_an_entry_rsp_seed() {
        let mut func = function(vec![inst(0, IrOp::Undef, &[])]);
        func.blocks[0].term = IrTerminator::Jump(BlockId(1));
        func.blocks.push(IrBlock {
            id: BlockId(1),
            phis: vec![],
            insts: vec![inst(1, IrOp::Undef, &[])],
            term: IrTerminator::Ret,
        });
        assert_eq!(
            analyze(&func, &[0, 1]).unwrap_err(),
            RejectionReason::FrameDynamic
        );
    }

    #[test]
    fn variable_alias_is_not_claimed_as_static_rsp() {
        let func = function(vec![
            inst(0, IrOp::Undef, &[]),
            inst(1, IrOp::Undef, &[]),
            inst(2, IrOp::Add, &[0, 1]),
        ]);
        let analysis = analyze(&func, &[0]).unwrap();
        assert!(!analysis.offsets.contains_key(&ValueId(2)));
        assert_eq!(
            analyze(&func, &[0, 2]).unwrap_err(),
            RejectionReason::FrameDynamic
        );
    }

    #[test]
    fn displacement_overflow_and_resource_limit_are_distinct() {
        for (amount, reason) in [
            (i32::MAX as u64 + 2, RejectionReason::FrameOverflow),
            (
                u64::from(MAX_FRAME_SIZE) + 8,
                RejectionReason::FrameResourceLimit,
            ),
            (i64::MAX as u64 + 1, RejectionReason::FrameOverflow),
        ] {
            let func = function(vec![
                inst(0, IrOp::Undef, &[]),
                inst(1, IrOp::Const(amount), &[]),
                inst(2, IrOp::Sub, &[0, 1]),
            ]);
            assert_eq!(analyze(&func, &[0, 2]).unwrap_err(), reason);
        }
    }

    #[test]
    fn native_rsp_write_is_dynamic() {
        let func = function(vec![
            inst(0, IrOp::Undef, &[]),
            inst(
                1,
                IrOp::NativeInline(NativeInst {
                    bytes: vec![0xc9],
                    references: vec![],
                    reads: vec![PhysReg::Gpr(Gpr::Rsp)],
                    writes: vec![PhysReg::Gpr(Gpr::Rsp)],
                }),
                &[0],
            ),
        ]);
        assert_eq!(
            analyze(&func, &[0]).unwrap_err(),
            RejectionReason::FrameDynamic
        );
    }

    #[test]
    fn call_alignment_and_shadow_space_are_proven() {
        for (amount, expected) in [
            (40, None),
            (24, Some(RejectionReason::FrameConflict)),
            (32, Some(RejectionReason::FrameConflict)),
        ] {
            let func = function(vec![
                inst(0, IrOp::Undef, &[]),
                inst(1, IrOp::Const(amount), &[]),
                inst(2, IrOp::Sub, &[0, 1]),
                inst(3, IrOp::Const(0x1000), &[]),
                inst(4, IrOp::CallIndirect { clobbers: vec![] }, &[3, 2]),
            ]);
            let result = analyze(&func, &[0, 2]);
            if let Some(reason) = expected {
                assert_eq!(result.unwrap_err(), reason);
            } else {
                let analysis = result.unwrap();
                assert_eq!(analysis.call_deltas[&(BlockId(0), 4)], -40);
                assert_eq!(analysis.original_size, 40);
                assert_eq!(analysis.outgoing_size, 32);
            }
        }
    }

    #[test]
    fn frameless_ir_calls_receive_one_mandatory_call_area() {
        let func = function(vec![
            inst(0, IrOp::Const(0x1000), &[]),
            inst(1, IrOp::CallIndirect { clobbers: vec![] }, &[0]),
        ]);
        let analysis = analyze(&func, &[]).unwrap();
        assert_eq!(analysis.original_size, 40);
        assert_eq!(analysis.outgoing_size, 32);
        assert_eq!(analysis.call_deltas[&(BlockId(0), 1)], -40);
    }

    #[test]
    fn known_outgoing_stack_args_extend_outgoing_without_crossing_split() {
        for (endpoint, expected) in [
            (-1, Ok(40u32)),
            (-8, Ok(33)),
            (-40, Ok(32)),
            (-41, Err(RejectionReason::FrameConflict)),
            (0, Err(RejectionReason::FrameConflict)),
        ] {
            let func = function(vec![
                inst(0, IrOp::Undef, &[]),
                inst(1, IrOp::Const(40), &[]),
                inst(2, IrOp::Sub, &[0, 1]),
                inst(3, IrOp::Const((endpoint + 40) as u64), &[]),
                inst(4, IrOp::Add, &[2, 3]),
                inst(5, IrOp::Const(0x1000), &[]),
                inst(6, IrOp::CallIndirect { clobbers: vec![] }, &[5, 4, 2]),
            ]);
            let result = analyze(&func, &[0, 2]);
            match expected {
                Ok(outgoing) => {
                    let analysis = result.unwrap();
                    assert_eq!(analysis.call_deltas[&(BlockId(0), 6)], -40);
                    assert_eq!(analysis.outgoing_size, outgoing);
                }
                Err(reason) => assert_eq!(result.unwrap_err(), reason),
            }
        }
    }

    #[test]
    fn accesses_cannot_straddle_reconstructed_and_incoming_zones() {
        for (offset, ty, expected) in [
            (-8, IrType::I64, None),
            (-8, IrType::I128, Some(RejectionReason::FrameConflict)),
            (0, IrType::I128, None),
        ] {
            let mut load = inst(1, IrOp::Load, &[0]);
            load.ty = ty;
            let func = function(vec![inst(0, IrOp::FrameAddress(offset), &[]), load]);
            let result = analyze(&func, &[]);
            if let Some(reason) = expected {
                assert_eq!(result.unwrap_err(), reason);
            } else {
                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn unbounded_frame_index_is_dynamic() {
        let func = function(vec![
            inst(0, IrOp::FrameAddress(-40), &[]),
            inst(1, IrOp::Undef, &[]),
            inst(2, IrOp::Add, &[0, 1]),
            inst(3, IrOp::Load, &[2]),
        ]);
        assert_eq!(
            analyze(&func, &[]).unwrap_err(),
            RejectionReason::FrameDynamic
        );
    }

    #[test]
    fn stack_probe_uses_static_extended_size_without_shadow_space() {
        let mut size = inst(1, IrOp::Const(0x5000), &[]);
        size.ty = IrType::I32;
        let func = function(vec![
            inst(0, IrOp::FrameAddress(0), &[]),
            size,
            inst(2, IrOp::Zext, &[1]),
            inst(3, IrOp::StackProbe, &[2, 0]),
        ]);
        let analysis = analyze(&func, &[0]).unwrap();
        assert_eq!(analysis.original_size, 0x5008);
        assert_eq!(analysis.outgoing_size, 0);
        assert!(analysis.call_deltas.is_empty());
    }

    #[test]
    fn dynamic_stack_probe_size_is_specific() {
        let func = function(vec![
            inst(0, IrOp::FrameAddress(0), &[]),
            inst(1, IrOp::Undef, &[]),
            inst(2, IrOp::StackProbe, &[1, 0]),
        ]);
        assert_eq!(
            analyze(&func, &[0]).unwrap_err(),
            RejectionReason::FrameDynamic
        );
    }

    fn pointer_phi(displacement: i64) -> IrFunction {
        let mut func = function(vec![
            inst(0, IrOp::FrameAddress(-8), &[]),
            inst(1, IrOp::FrameAddress(-16), &[]),
            inst(2, IrOp::Undef, &[]),
        ]);
        func.blocks[0].term = IrTerminator::Branch {
            cond: ValueId(2),
            taken: BlockId(1),
            not_taken: BlockId(2),
        };
        for id in [1, 2] {
            func.blocks.push(IrBlock {
                id: BlockId(id),
                phis: vec![],
                insts: vec![],
                term: IrTerminator::Jump(BlockId(3)),
            });
        }
        func.blocks.push(IrBlock {
            id: BlockId(3),
            phis: vec![Phi {
                dest: ValueId(3),
                ty: IrType::I64,
                args: vec![(BlockId(1), ValueId(0)), (BlockId(2), ValueId(1))],
            }],
            insts: vec![
                inst(4, IrOp::Copy, &[3]),
                inst(5, IrOp::Const(displacement as u64), &[]),
                inst(6, IrOp::Add, &[4, 5]),
                inst(7, IrOp::Load, &[6]),
            ],
            term: IrTerminator::Ret,
        });
        func
    }

    #[test]
    fn finite_pointer_phis_preserve_objects_without_claiming_one_offset() {
        for (displacement, expected_size) in [(0, 24), (-16, 40)] {
            let mut func = pointer_phi(displacement);
            let analysis = analyze(&func, &[]).unwrap();
            assert_eq!(analysis.original_size, expected_size);
            assert_eq!(
                analysis.derived_offsets[&ValueId(6)],
                (ValueId(4), displacement)
            );
            func.blocks[3].insts[2].op = IrOp::FrameOffset(displacement);
            func.blocks[3].insts[2].args = vec![ValueId(4)];
            assert_eq!(analyze(&func, &[]).unwrap().original_size, expected_size);
            for value in [3, 4, 6] {
                assert!(!analysis.offsets.contains_key(&ValueId(value)));
            }
        }
        assert_eq!(
            analyze(&pointer_phi(0), &[3]).unwrap_err(),
            RejectionReason::FrameConflict
        );
        assert_eq!(
            analyze(&pointer_phi(4), &[]).unwrap_err(),
            RejectionReason::FrameConflict
        );
        assert!(analyze(&pointer_phi(32), &[]).is_ok());
    }

    #[test]
    fn finite_pointer_rotation_cycle_proves_each_seed() {
        let mut func = function(vec![
            inst(0, IrOp::FrameAddress(-8), &[]),
            inst(1, IrOp::FrameAddress(-16), &[]),
        ]);
        func.blocks[0].term = IrTerminator::Jump(BlockId(1));
        func.blocks.push(IrBlock {
            id: BlockId(1),
            phis: vec![
                Phi {
                    dest: ValueId(2),
                    ty: IrType::I64,
                    args: vec![(BlockId(0), ValueId(0)), (BlockId(1), ValueId(3))],
                },
                Phi {
                    dest: ValueId(3),
                    ty: IrType::I64,
                    args: vec![(BlockId(0), ValueId(1)), (BlockId(1), ValueId(2))],
                },
            ],
            insts: vec![inst(4, IrOp::Load, &[2]), inst(5, IrOp::Load, &[3])],
            term: IrTerminator::Jump(BlockId(1)),
        });
        let analysis = analyze(&func, &[]).unwrap();
        assert_eq!(analysis.original_size, 24);
        assert!(!analysis.offsets.contains_key(&ValueId(2)));
        assert!(!analysis.offsets.contains_key(&ValueId(3)));
        func.blocks[1].insts[0] = inst(
            4,
            IrOp::NativeInline(NativeInst {
                bytes: vec![0x48, 0x8b, 0x01],
                references: vec![],
                reads: vec![PhysReg::Gpr(Gpr::Rcx)],
                writes: vec![PhysReg::Gpr(Gpr::Rax)],
            }),
            &[2],
        );
        let native = analyze(&func, &[]).unwrap();
        assert_eq!(
            native.pointer_bounds[&ValueId(2)],
            FramePointerBounds {
                negative: Some((-16, -8)),
                incoming: None,
            }
        );
    }

    #[test]
    fn pointer_cycle_with_nonzero_step_is_dynamic() {
        let mut func = function(vec![inst(0, IrOp::FrameAddress(-8), &[])]);
        func.blocks[0].term = IrTerminator::Jump(BlockId(1));
        func.blocks.push(IrBlock {
            id: BlockId(1),
            phis: vec![Phi {
                dest: ValueId(1),
                ty: IrType::I64,
                args: vec![(BlockId(0), ValueId(0)), (BlockId(1), ValueId(3))],
            }],
            insts: vec![
                inst(2, IrOp::Const(16), &[]),
                inst(3, IrOp::Add, &[1, 2]),
                inst(4, IrOp::Load, &[1]),
            ],
            term: IrTerminator::Jump(BlockId(1)),
        });
        assert_eq!(
            analyze(&func, &[]).unwrap_err(),
            RejectionReason::FrameDynamic
        );
    }

    #[test]
    fn native_pointer_phi_bounds_keep_coordinate_zones_separate() {
        for incoming in [false, true] {
            let mut func = pointer_phi(0);
            if incoming {
                func.blocks[0].insts[1].op = IrOp::FrameAddress(40);
            }
            func.blocks[3].insts[3] = inst(
                7,
                IrOp::NativeInline(NativeInst {
                    bytes: vec![0x48, 0x8b, 0x01],
                    references: vec![],
                    reads: vec![PhysReg::Gpr(Gpr::Rcx)],
                    writes: vec![PhysReg::Gpr(Gpr::Rax)],
                }),
                &[6],
            );
            let analysis = analyze(&func, &[]).unwrap();
            assert_eq!(
                analysis.pointer_bounds[&ValueId(6)],
                if incoming {
                    FramePointerBounds {
                        negative: Some((-8, -8)),
                        incoming: Some((40, 40)),
                    }
                } else {
                    FramePointerBounds {
                        negative: Some((-16, -8)),
                        incoming: None,
                    }
                }
            );
        }
    }

    #[test]
    fn select_copy_and_phi_arithmetic_preserve_final_frame_coordinates() {
        for displacement in [0, 56, -32] {
            let mut func = pointer_phi(displacement);
            func.blocks[3]
                .insts
                .insert(0, inst(8, IrOp::Select, &[2, 3, 1]));
            func.blocks[3].insts[1].args = vec![ValueId(8)];
            let analysis = analyze(&func, &[]).unwrap();
            let expected = index::from_interval(-16 + displacement, -8 + displacement).unwrap();
            assert_eq!(analysis.pointer_bounds[&ValueId(6)], expected);
            assert_eq!(
                analysis.pointer_bounds[&ValueId(8)].negative,
                Some((-16, -8))
            );
            assert_eq!(
                analysis.derived_offsets[&ValueId(6)],
                (ValueId(4), displacement)
            );
        }
    }

    #[test]
    fn nested_selects_shift_across_both_frame_zones() {
        let func = function(vec![
            inst(0, IrOp::FrameAddress(-16), &[]),
            inst(1, IrOp::FrameAddress(-8), &[]),
            inst(2, IrOp::Undef, &[]),
            inst(3, IrOp::Select, &[2, 1, 0]),
            inst(4, IrOp::Copy, &[3]),
            inst(5, IrOp::FrameOffset(56), &[4]),
            inst(6, IrOp::Select, &[2, 5, 4]),
            inst(7, IrOp::FrameOffset(-32), &[6]),
            inst(8, IrOp::Load, &[7]),
        ]);
        let analysis = analyze(&func, &[]).unwrap();
        assert_eq!(
            analysis.pointer_bounds[&ValueId(5)].incoming,
            Some((40, 48))
        );
        assert_eq!(
            analysis.pointer_bounds[&ValueId(7)],
            FramePointerBounds {
                negative: Some((-48, -40)),
                incoming: Some((8, 16)),
            }
        );
        assert_eq!(analysis.derived_offsets[&ValueId(7)], (ValueId(6), -32));
    }

    #[test]
    fn shared_select_dag_feeding_phi_has_linear_access_work() {
        const LAYERS: u32 = 64;
        let mut func = function(vec![
            inst(0, IrOp::FrameAddress(-8), &[]),
            inst(1, IrOp::FrameAddress(-16), &[]),
            inst(2, IrOp::Undef, &[]),
            inst(3, IrOp::Undef, &[]),
        ]);
        let mut facts = HashMap::from([
            (ValueId(0), Fact::Offset(-8)),
            (ValueId(1), Fact::Offset(-16)),
            (ValueId(2), Fact::Scalar(None)),
            (ValueId(3), Fact::Scalar(None)),
        ]);
        let mut previous = [0, 1];
        let mut next = 4;
        for _ in 0..LAYERS {
            let current = [next, next + 1];
            for (condition, dest) in [2, 3].into_iter().zip(current) {
                func.blocks[0].insts.push(inst(
                    dest,
                    IrOp::Select,
                    &[condition, previous[0], previous[1]],
                ));
                facts.insert(ValueId(dest), Fact::Conflict);
            }
            previous = current;
            next += 2;
        }
        let phi = ValueId(next);
        facts.insert(phi, Fact::Conflict);
        func.next_value = next + 2;
        func.blocks[0].term = IrTerminator::Branch {
            cond: ValueId(2),
            taken: BlockId(1),
            not_taken: BlockId(2),
        };
        for id in [1, 2] {
            func.blocks.push(IrBlock {
                id: BlockId(id),
                phis: vec![],
                insts: vec![],
                term: IrTerminator::Jump(BlockId(3)),
            });
        }
        func.blocks.push(IrBlock {
            id: BlockId(3),
            phis: vec![Phi {
                dest: phi,
                ty: IrType::I64,
                args: vec![
                    (BlockId(1), ValueId(previous[0])),
                    (BlockId(2), ValueId(previous[1])),
                ],
            }],
            insts: vec![inst(next + 1, IrOp::Load, &[next])],
            term: IrTerminator::Ret,
        });
        let definitions = access_definitions(&func);
        let reachable = func.blocks.iter().map(|block| block.id).collect();
        let mut scratch = AccessScratch::default();
        let mut minimum = 0;
        check_access(
            phi,
            7,
            &facts,
            &definitions,
            &reachable,
            &mut scratch,
            &mut minimum,
        )
        .unwrap();
        let expected = FramePointerBounds {
            negative: Some((-16, -8)),
            incoming: None,
        };
        assert_eq!(scratch.bounds, expected);
        assert_eq!(minimum, -16);
        assert!(!scratch.unknown);
        // Count every popped work item, including cache hits and exit markers.
        // Each layer contributes four input edges and two completion markers.
        assert_eq!(scratch.visits, 6 * LAYERS as usize + 4);

        let analysis = analyze(&func, &[]).unwrap();
        assert_eq!(analysis.pointer_bounds[&phi], expected);
        assert!(!analysis.offsets.contains_key(&phi));
        assert_eq!(analysis.original_size, 24);

        // The same shared DAG must remain linear when coarse bounds cannot
        // certify the shifted load, and therefore cannot short-circuit it.
        func.blocks[0].insts[0].op = IrOp::FrameAddress(-16);
        func.blocks[0].insts[1].op = IrOp::FrameAddress(-32);
        facts.insert(ValueId(0), Fact::Offset(-16));
        facts.insert(ValueId(1), Fact::Offset(-32));
        let shifted = ValueId(next + 2);
        func.blocks[3]
            .insts
            .insert(0, inst(next + 2, IrOp::FrameOffset(24), &[next]));
        func.blocks[3].insts[1].args = vec![shifted];
        func.next_value = next + 3;
        facts.insert(shifted, Fact::Conflict);
        let coarse = index::from_interval(-32, -16).unwrap();
        let shifted_coarse = index::from_interval(-8, 8).unwrap();
        scratch.proven = facts
            .iter()
            .filter_map(|(&value, &fact)| {
                (fact == Fact::Conflict).then_some((
                    value,
                    if value == shifted {
                        shifted_coarse
                    } else {
                        coarse
                    },
                ))
            })
            .collect();
        let definitions = access_definitions(&func);
        minimum = 0;
        check_access(
            shifted,
            7,
            &facts,
            &definitions,
            &reachable,
            &mut scratch,
            &mut minimum,
        )
        .unwrap();
        assert_eq!(
            scratch.bounds,
            FramePointerBounds {
                negative: Some((-8, -8)),
                incoming: Some((8, 8)),
            }
        );
        assert_eq!(minimum, -8);
        assert!(!scratch.unknown);
        assert_eq!(scratch.visits, 6 * LAYERS as usize + 6);
        let analysis = analyze(&func, &[]).unwrap();
        assert_eq!(analysis.pointer_bounds[&shifted], shifted_coarse);
        assert_eq!(analysis.original_size, 40);
    }

    #[test]
    fn completed_access_states_keep_adjustments_extents_and_unknowns_distinct() {
        let func = function(vec![
            inst(0, IrOp::FrameAddress(-16), &[]),
            inst(1, IrOp::FrameAddress(-8), &[]),
            inst(2, IrOp::Undef, &[]),
            inst(3, IrOp::Select, &[2, 0, 1]),
            inst(4, IrOp::FrameOffset(56), &[3]),
            inst(5, IrOp::Select, &[2, 4, 3]),
            inst(6, IrOp::FrameOffset(i64::MAX), &[5]),
            inst(7, IrOp::FrameOffset(1), &[6]),
        ]);
        let mut facts = HashMap::from([
            (ValueId(0), Fact::Offset(-16)),
            (ValueId(1), Fact::Offset(-8)),
            (ValueId(2), Fact::Scalar(None)),
        ]);
        facts.extend((3..=7).map(|value| (ValueId(value), Fact::Conflict)));
        let definitions = access_definitions(&func);
        let reachable = HashSet::from([BlockId(0)]);
        let mut scratch = AccessScratch::default();
        let mut minimum = 0;
        let expected = FramePointerBounds {
            negative: Some((-16, -8)),
            incoming: Some((40, 48)),
        };
        check_access(
            ValueId(5),
            7,
            &facts,
            &definitions,
            &reachable,
            &mut scratch,
            &mut minimum,
        )
        .unwrap();
        assert_eq!(scratch.bounds, expected);
        assert_eq!(minimum, -16);
        assert!(!scratch.unknown);
        assert_eq!(scratch.visits, 12);

        // A completed query cannot suppress a wider access or signed overflow.
        for (value, extent, reason) in [
            (5, 8, RejectionReason::FrameConflict),
            (7, 7, RejectionReason::FrameOverflow),
        ] {
            assert_eq!(
                check_access(
                    ValueId(value),
                    extent,
                    &facts,
                    &definitions,
                    &reachable,
                    &mut scratch,
                    &mut minimum,
                ),
                Err(reason),
            );
        }

        facts.remove(&ValueId(1));
        check_access(
            ValueId(5),
            7,
            &facts,
            &definitions,
            &reachable,
            &mut scratch,
            &mut minimum,
        )
        .unwrap();
        assert!(scratch.unknown);
        assert_eq!(
            scratch.bounds,
            FramePointerBounds {
                negative: Some((-16, -16)),
                incoming: Some((40, 40)),
            }
        );

        // Neither a failed nor an unknown query leaves reusable partial proofs.
        facts.insert(ValueId(1), Fact::Offset(-8));
        check_access(
            ValueId(5),
            7,
            &facts,
            &definitions,
            &reachable,
            &mut scratch,
            &mut minimum,
        )
        .unwrap();
        assert!(!scratch.unknown);
        assert_eq!(scratch.bounds, expected);
        assert_eq!(scratch.visits, 12);
    }

    #[test]
    fn completed_access_states_preserve_active_cycle_checks() {
        for step in [0, 8] {
            let mut func = function(vec![
                inst(0, IrOp::FrameAddress(-8), &[]),
                inst(1, IrOp::FrameAddress(-16), &[]),
                inst(2, IrOp::Undef, &[]),
            ]);
            func.blocks[0].term = IrTerminator::Jump(BlockId(1));
            func.blocks.push(IrBlock {
                id: BlockId(1),
                phis: vec![Phi {
                    dest: ValueId(3),
                    ty: IrType::I64,
                    args: vec![(BlockId(0), ValueId(0)), (BlockId(1), ValueId(5))],
                }],
                insts: vec![
                    inst(4, IrOp::Select, &[2, 3, 1]),
                    inst(5, IrOp::FrameOffset(step), &[4]),
                    inst(6, IrOp::Load, &[3]),
                ],
                term: IrTerminator::Jump(BlockId(1)),
            });
            let facts = HashMap::from([
                (ValueId(0), Fact::Offset(-8)),
                (ValueId(1), Fact::Offset(-16)),
                (ValueId(2), Fact::Scalar(None)),
                (ValueId(3), Fact::Conflict),
                (ValueId(4), Fact::Conflict),
                (ValueId(5), Fact::Conflict),
            ]);
            let definitions = access_definitions(&func);
            let reachable = HashSet::from([BlockId(0), BlockId(1)]);
            let mut scratch = AccessScratch::default();
            let mut minimum = 0;
            let result = check_access(
                ValueId(3),
                7,
                &facts,
                &definitions,
                &reachable,
                &mut scratch,
                &mut minimum,
            );
            if step != 0 {
                assert_eq!(result, Err(RejectionReason::FrameDynamic));
                continue;
            }
            result.unwrap();
            let expected = FramePointerBounds {
                negative: Some((-16, -8)),
                incoming: None,
            };
            assert_eq!(scratch.bounds, expected);
            assert!(!scratch.unknown);
            assert_eq!(minimum, -16);
            assert_eq!(scratch.visits, 9);

            // The select completed before its active phi; its own next query
            // must still traverse the phi and recover both concrete seeds.
            check_access(
                ValueId(4),
                7,
                &facts,
                &definitions,
                &reachable,
                &mut scratch,
                &mut minimum,
            )
            .unwrap();
            assert_eq!(scratch.bounds, expected);
            assert!(!scratch.unknown);
            assert_eq!(scratch.visits, 9);
        }
    }

    #[test]
    fn ambiguous_access_bounds_preserve_zero_and_nonzero_cycle_distinctions() {
        for step in [0, 8] {
            let mut func = function(vec![
                inst(0, IrOp::FrameAddress(-32), &[]),
                inst(1, IrOp::FrameAddress(-16), &[]),
                inst(2, IrOp::Undef, &[]),
            ]);
            func.blocks[0].term = IrTerminator::Jump(BlockId(1));
            func.blocks.push(IrBlock {
                id: BlockId(1),
                phis: vec![Phi {
                    dest: ValueId(3),
                    ty: IrType::I64,
                    args: vec![(BlockId(0), ValueId(0)), (BlockId(1), ValueId(5))],
                }],
                insts: vec![
                    inst(4, IrOp::Select, &[2, 3, 1]),
                    inst(5, IrOp::FrameOffset(step), &[4]),
                    inst(6, IrOp::FrameOffset(24), &[3]),
                    inst(7, IrOp::Load, &[6]),
                ],
                term: IrTerminator::Jump(BlockId(1)),
            });
            let facts = HashMap::from([
                (ValueId(0), Fact::Offset(-32)),
                (ValueId(1), Fact::Offset(-16)),
                (ValueId(2), Fact::Scalar(None)),
                (ValueId(3), Fact::Conflict),
                (ValueId(4), Fact::Conflict),
                (ValueId(5), Fact::Conflict),
                (ValueId(6), Fact::Conflict),
            ]);
            let definitions = access_definitions(&func);
            let mut scratch = AccessScratch {
                proven: HashMap::from([(ValueId(6), index::from_interval(-8, 8).unwrap())]),
                ..AccessScratch::default()
            };
            let mut minimum = 0;
            let result = check_access(
                ValueId(6),
                7,
                &facts,
                &definitions,
                &HashSet::from([BlockId(0), BlockId(1)]),
                &mut scratch,
                &mut minimum,
            );
            if step == 0 {
                result.unwrap();
                assert_eq!(
                    scratch.bounds,
                    FramePointerBounds {
                        negative: Some((-8, -8)),
                        incoming: Some((8, 8)),
                    }
                );
                assert_eq!(minimum, -8);
                assert!(!scratch.unknown);
                assert_eq!(scratch.visits, 11);
            } else {
                assert_eq!(result, Err(RejectionReason::FrameDynamic));
                assert!(scratch.visits <= 11);
            }
        }
    }

    #[test]
    fn unproved_select_frame_alternative_remains_dynamic() {
        let func = function(vec![
            inst(0, IrOp::FrameAddress(-16), &[]),
            inst(1, IrOp::Undef, &[]),
            inst(2, IrOp::Undef, &[]),
            inst(3, IrOp::Select, &[2, 0, 1]),
            inst(4, IrOp::Load, &[3]),
        ]);
        assert_eq!(
            analyze(&func, &[]).unwrap_err(),
            RejectionReason::FrameDynamic
        );
    }

    #[test]
    fn constant_select_condition_retains_only_the_selected_coordinate() {
        for (condition, expected) in [(0, 40), (1, -16)] {
            let func = function(vec![
                inst(0, IrOp::FrameAddress(-16), &[]),
                inst(1, IrOp::FrameAddress(40), &[]),
                inst(2, IrOp::Const(condition), &[]),
                inst(3, IrOp::Select, &[2, 0, 1]),
                inst(4, IrOp::Load, &[3]),
            ]);
            assert_eq!(analyze(&func, &[]).unwrap().offsets[&ValueId(3)], expected);
        }
    }

    #[test]
    fn delayed_select_condition_is_independent_of_block_order() {
        for condition in [0, 1] {
            for condition_id in [1, 2] {
                for consumer_first in [false, true] {
                    let consumer_id = 3 - condition_id;
                    let mut func = function(vec![
                        inst(0, IrOp::FrameAddress(-16), &[]),
                        inst(1, IrOp::Const(56), &[]),
                        inst(2, IrOp::Const(0), &[]),
                    ]);
                    func.blocks[0].term = IrTerminator::Jump(BlockId(condition_id));
                    let definition = IrBlock {
                        id: BlockId(condition_id),
                        phis: vec![],
                        insts: vec![inst(3, IrOp::Const(condition), &[])],
                        term: IrTerminator::Jump(BlockId(consumer_id)),
                    };
                    let consumer = IrBlock {
                        id: BlockId(consumer_id),
                        phis: vec![],
                        insts: vec![
                            inst(4, IrOp::Select, &[3, 1, 2]),
                            inst(5, IrOp::Add, &[0, 4]),
                            inst(6, IrOp::Load, &[5]),
                        ],
                        term: IrTerminator::Ret,
                    };
                    if consumer_first {
                        func.blocks.extend([consumer, definition]);
                    } else {
                        func.blocks.extend([definition, consumer]);
                    }
                    let analysis = analyze(&func, &[]).unwrap();
                    let scalar = if condition == 0 { 0 } else { 56 };
                    assert_eq!(analysis.constants[&ValueId(4)], scalar);
                    assert_eq!(analysis.offsets[&ValueId(5)], -16 + scalar as i64);
                    assert!(!analysis.pointer_bounds.contains_key(&ValueId(5)));
                }
            }
        }
    }

    #[test]
    fn unresolved_select_conditions_defer_scalar_and_pointer_proofs() {
        let select = inst(3, IrOp::Select, &[2, 0, 1]);
        let definitions = HashMap::from([(ValueId(3), Definition::Inst(&select))]);
        let reachable = HashSet::from([BlockId(0)]);
        for (yes, no) in [
            (Fact::Scalar(Some(56)), Fact::Scalar(Some(0))),
            (Fact::Offset(-32), Fact::Offset(-16)),
        ] {
            let mut facts = HashMap::from([(ValueId(0), yes), (ValueId(1), no)]);
            assert_eq!(
                Definition::Inst(&select).evaluate(&facts, &definitions, &reachable),
                Fact::Unknown,
            );
            assert!(index::select(&select, &facts, &HashMap::new()).is_none());
            facts.insert(ValueId(2), Fact::Scalar(None));
            assert_eq!(
                Definition::Inst(&select).evaluate(&facts, &definitions, &reachable),
                yes.merge(no),
            );
            for (condition, expected) in [(0, no), (1, yes)] {
                facts.insert(ValueId(2), Fact::Scalar(Some(condition)));
                assert_eq!(
                    Definition::Inst(&select).evaluate(&facts, &definitions, &reachable),
                    expected,
                );
            }
        }
    }

    #[test]
    fn scalar_select_cycles_still_widen_runtime_choices() {
        for ty in [IrType::I8, IrType::I32, IrType::I64] {
            for loop_first in [false, true] {
                let mut func = function(vec![
                    Inst {
                        ty,
                        ..inst(0, IrOp::Const(0x100), &[])
                    },
                    Inst {
                        ty,
                        ..inst(1, IrOp::Const(0x101), &[])
                    },
                ]);
                func.blocks[0].term = IrTerminator::Jump(BlockId(1));
                let loop_block = IrBlock {
                    id: BlockId(1),
                    phis: vec![Phi {
                        dest: ValueId(2),
                        ty,
                        args: vec![(BlockId(0), ValueId(1)), (BlockId(1), ValueId(3))],
                    }],
                    insts: vec![Inst {
                        ty,
                        ..inst(3, IrOp::Select, &[2, 0, 1])
                    }],
                    term: IrTerminator::Jump(BlockId(1)),
                };
                if loop_first {
                    func.blocks.insert(0, loop_block);
                } else {
                    func.blocks.push(loop_block);
                }
                let analysis = analyze(&func, &[]).unwrap();
                let mask = if ty == IrType::I8 { 0xff } else { u64::MAX };
                assert_eq!(analysis.constants[&ValueId(0)], 0x100 & mask);
                assert_eq!(analysis.constants[&ValueId(1)], 0x101 & mask);
                assert!(!analysis.constants.contains_key(&ValueId(2)));
                assert!(!analysis.constants.contains_key(&ValueId(3)));
            }
        }
    }

    #[test]
    fn split_select_accesses_expand_only_actual_offset_alternatives() {
        for reverse in [false, true] {
            for operation in [IrOp::FrameOffset(24), IrOp::Add, IrOp::Sub] {
                let subtract = matches!(operation, IrOp::Sub);
                let offset = if subtract { -24i64 } else { 24 };
                let args = if matches!(operation, IrOp::FrameOffset(_)) {
                    vec![4]
                } else {
                    vec![4, 5]
                };
                let arms = if reverse { [2, 1, 0] } else { [2, 0, 1] };
                let func = function(vec![
                    inst(0, IrOp::FrameAddress(-32), &[]),
                    inst(1, IrOp::FrameAddress(-16), &[]),
                    inst(2, IrOp::Undef, &[]),
                    inst(3, IrOp::Select, &arms),
                    inst(4, IrOp::Copy, &[3]),
                    inst(5, IrOp::Const(offset as u64), &[]),
                    inst(6, operation, &args),
                    inst(7, IrOp::Load, &[6]),
                ]);
                let analysis = analyze(&func, &[]).unwrap();
                assert_eq!(
                    analysis.pointer_bounds[&ValueId(6)],
                    index::from_interval(-8, 8).unwrap(),
                );
                assert_eq!(analysis.derived_offsets[&ValueId(6)], (ValueId(4), 24));
                let facts = HashMap::from([
                    (ValueId(0), Fact::Offset(-32)),
                    (ValueId(1), Fact::Offset(-16)),
                    (ValueId(2), Fact::Scalar(None)),
                    (ValueId(3), Fact::Conflict),
                    (ValueId(4), Fact::Conflict),
                    (ValueId(5), Fact::Scalar(Some(offset as u64))),
                    (ValueId(6), Fact::Conflict),
                ]);
                let definitions = access_definitions(&func);
                let mut scratch = AccessScratch {
                    proven: analysis.pointer_bounds.clone(),
                    ..AccessScratch::default()
                };
                let mut minimum = 0;
                check_access(
                    ValueId(6),
                    7,
                    &facts,
                    &definitions,
                    &HashSet::from([BlockId(0)]),
                    &mut scratch,
                    &mut minimum,
                )
                .unwrap();
                assert_eq!(
                    scratch.bounds,
                    FramePointerBounds {
                        negative: Some((-8, -8)),
                        incoming: Some((8, 8)),
                    }
                );
                assert_eq!(minimum, -8);
                assert!(!scratch.unknown);
            }
        }
    }

    #[test]
    fn split_select_accesses_reject_only_selected_true_crossings() {
        for reverse in [false, true] {
            for condition in [None, Some(0), Some(1)] {
                for (negative, ty) in [(-32, IrType::I64), (-31, IrType::I64), (-32, IrType::I128)]
                {
                    let arms = if reverse { [2, 1, 0] } else { [2, 0, 1] };
                    let func = function(vec![
                        inst(0, IrOp::FrameAddress(negative), &[]),
                        inst(1, IrOp::FrameAddress(-16), &[]),
                        inst(2, condition.map_or(IrOp::Undef, IrOp::Const), &[]),
                        inst(3, IrOp::Select, &arms),
                        inst(4, IrOp::FrameOffset(24), &[3]),
                        Inst {
                            ty,
                            ..inst(5, IrOp::Load, &[4])
                        },
                    ]);
                    let selects_negative =
                        condition.is_none_or(|condition| (condition != 0) != reverse);
                    let crosses = negative + 24 + i64::from(ty.bytes() - 1) >= 0;
                    let result = analyze(&func, &[]);
                    if selects_negative && crosses {
                        assert_eq!(result.unwrap_err(), RejectionReason::FrameConflict);
                    } else {
                        let analysis = result.unwrap();
                        if let Some(condition) = condition {
                            let expected = if (condition != 0) != reverse {
                                negative + 24
                            } else {
                                8
                            };
                            assert_eq!(analysis.offsets[&ValueId(4)], expected);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn split_select_failure_reasons_remain_specific() {
        for (negative, other, displacement, expected) in [
            (
                -32,
                IrOp::FrameAddress(-16),
                i64::MAX,
                RejectionReason::FrameOverflow,
            ),
            (
                -i64::from(MAX_FRAME_SIZE) - 8,
                IrOp::FrameAddress(-16),
                24,
                RejectionReason::FrameResourceLimit,
            ),
            (-32, IrOp::Undef, 24, RejectionReason::FrameDynamic),
        ] {
            let func = function(vec![
                inst(0, IrOp::FrameAddress(negative), &[]),
                inst(1, other, &[]),
                inst(2, IrOp::Undef, &[]),
                inst(3, IrOp::Select, &[2, 0, 1]),
                inst(4, IrOp::FrameOffset(displacement), &[3]),
                inst(5, IrOp::Load, &[4]),
            ]);
            assert_eq!(analyze(&func, &[]).unwrap_err(), expected);
        }
    }

    #[test]
    fn failed_coarse_access_certification_commits_no_partial_bounds() {
        let func = function(vec![
            inst(0, IrOp::FrameAddress(-32), &[]),
            inst(1, IrOp::FrameAddress(24), &[]),
            inst(2, IrOp::Undef, &[]),
            inst(3, IrOp::Select, &[2, 0, 1]),
            inst(4, IrOp::FrameOffset(-16), &[3]),
        ]);
        let mut facts = HashMap::from([
            (ValueId(0), Fact::Offset(-32)),
            (ValueId(1), Fact::Offset(24)),
            (ValueId(2), Fact::Scalar(None)),
            (ValueId(3), Fact::Conflict),
            (ValueId(4), Fact::Conflict),
        ]);
        let definitions = access_definitions(&func);
        let mut scratch = AccessScratch {
            proven: HashMap::from([(
                ValueId(3),
                FramePointerBounds {
                    negative: Some((-32, -16)),
                    incoming: Some((8, 24)),
                },
            )]),
            ..AccessScratch::default()
        };
        for unknown in [false, true, false] {
            if unknown {
                facts.remove(&ValueId(1));
            } else {
                facts.insert(ValueId(1), Fact::Offset(24));
            }
            let mut minimum = 0;
            check_access(
                ValueId(4),
                7,
                &facts,
                &definitions,
                &HashSet::from([BlockId(0)]),
                &mut scratch,
                &mut minimum,
            )
            .unwrap();
            assert_eq!(
                scratch.bounds,
                FramePointerBounds {
                    negative: Some((-48, -48)),
                    incoming: (!unknown).then_some((8, 8)),
                }
            );
            assert_eq!(minimum, -48);
            assert_eq!(scratch.unknown, unknown);
        }
    }

    #[test]
    fn opaque_frame_index_intervals_still_reject_possible_crossings() {
        for (negative, expected) in [
            ((-8, -8), None),
            ((-8, -1), Some(RejectionReason::FrameConflict)),
            ((-7, -7), Some(RejectionReason::FrameConflict)),
        ] {
            let func = function(vec![
                inst(0, IrOp::FrameAddress(-8), &[]),
                inst(1, IrOp::Const(0), &[]),
                inst(
                    2,
                    IrOp::FrameIndex {
                        displacement: 0,
                        subtract: false,
                        bounds: FramePointerBounds {
                            negative: Some(negative),
                            incoming: Some((8, 8)),
                        },
                    },
                    &[0, 1],
                ),
                inst(3, IrOp::Load, &[2]),
            ]);
            assert_eq!(analyze(&func, &[]).err(), expected);
        }
    }

    #[test]
    fn singleton_frame_offset_retains_exact_coordinate() {
        let func = function(vec![
            inst(0, IrOp::FrameAddress(-40), &[]),
            inst(1, IrOp::FrameOffset(8), &[0]),
        ]);
        let analysis = analyze(&func, &[]).unwrap();
        assert_eq!(analysis.offsets[&ValueId(1)], -32);
        assert!(!analysis.derived_offsets.contains_key(&ValueId(1)));
    }

    #[test]
    fn scalar_constants_preserve_widths_without_pointer_guesses() {
        let typed = |dest, op, args: &[u32], ty| Inst {
            ty,
            ..inst(dest, op, args)
        };
        let func = function(vec![
            typed(0, IrOp::Const(0x180), &[], IrType::I32),
            inst(1, IrOp::Zext, &[0]),
            inst(2, IrOp::Copy, &[1]),
            typed(3, IrOp::Trunc, &[2], IrType::I8),
            inst(4, IrOp::Sext, &[3]),
            inst(5, IrOp::FrameAddress(-8), &[]),
            typed(6, IrOp::Trunc, &[5], IrType::I32),
            typed(7, IrOp::Trunc, &[5], IrType::I32),
            typed(8, IrOp::Xor, &[6, 7], IrType::I32),
            inst(9, IrOp::Zext, &[8]),
        ]);
        let analysis = analyze(&func, &[]).unwrap();
        for (value, constant) in [
            (0, 0x180),
            (1, 0x180),
            (2, 0x180),
            (3, 0x80),
            (4, (-128i64) as u64),
            (8, 0),
            (9, 0),
        ] {
            assert_eq!(analysis.constants[&ValueId(value)], constant);
        }
        for value in [5, 6, 7] {
            assert!(!analysis.constants.contains_key(&ValueId(value)));
        }
    }
}
