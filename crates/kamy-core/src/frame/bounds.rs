use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ScalarBounds {
    pub low: u64,
    pub high: u64,
}

#[derive(Default)]
pub(super) struct LoopBounds {
    pub scalars: HashMap<ValueId, ScalarBounds>,
    pub pointers: HashMap<ValueId, FramePointerBounds>,
    pub advances: HashMap<ValueId, (ValueId, i64)>,
}

#[derive(Clone, Copy)]
struct Affine {
    delta: i64,
    minimum: i64,
    maximum: i64,
    bits: u32,
}

fn affine(
    value: ValueId,
    root: ValueId,
    facts: &HashMap<ValueId, Fact>,
    definitions: &HashMap<ValueId, Definition<'_>>,
    depth: usize,
) -> Option<Affine> {
    if value == root {
        return Some(Affine {
            delta: 0,
            minimum: 0,
            maximum: 0,
            bits: 64,
        });
    }
    if depth == 0 {
        return None;
    }
    let Definition::Inst(inst) = definitions.get(&value)? else {
        return None;
    };
    let constant = |value: &ValueId| match facts.get(value) {
        Some(Fact::Scalar(Some(value))) => Some(*value as i64),
        _ => None,
    };
    let (source, offset) = match (&inst.op, inst.args.as_slice()) {
        (IrOp::Copy | IrOp::Zext | IrOp::Trunc, [source]) => (*source, 0),
        (IrOp::FrameOffset(offset), [source]) => (*source, *offset),
        (IrOp::Add | IrOp::Sub, [left, right]) => {
            if let Some(offset) = constant(right) {
                (
                    *left,
                    if matches!(inst.op, IrOp::Sub) {
                        offset.checked_neg()?
                    } else {
                        offset
                    },
                )
            } else if matches!(inst.op, IrOp::Add) {
                (*right, constant(left)?)
            } else {
                return None;
            }
        }
        _ => return None,
    };
    let mut affine = affine(source, root, facts, definitions, depth - 1)?;
    affine.delta = affine.delta.checked_add(offset)?;
    affine.minimum = affine.minimum.min(affine.delta);
    affine.maximum = affine.maximum.max(affine.delta);
    affine.bits = affine.bits.min(inst.ty.bits());
    Some(affine)
}

fn equality_exit(
    mut condition: ValueId,
    mut continuation: bool,
    facts: &HashMap<ValueId, Fact>,
    definitions: &HashMap<ValueId, Definition<'_>>,
) -> Option<(ValueId, u64)> {
    for _ in 0..=definitions.len() {
        let Definition::Inst(inst) = definitions.get(&condition)? else {
            return None;
        };
        match (&inst.op, inst.args.as_slice()) {
            (IrOp::Copy | IrOp::Zext | IrOp::Trunc, [source]) => condition = *source,
            (IrOp::BoolNot, [source]) => {
                condition = *source;
                continuation = !continuation;
            }
            (IrOp::IsZero, [source]) if !continuation => {
                if let Some(Definition::Inst(compare)) = definitions.get(source) {
                    if let [left, right] = compare.args.as_slice() {
                        let constant = |value: &ValueId| match facts.get(value) {
                            Some(Fact::Scalar(Some(value))) => Some(*value),
                            _ => None,
                        };
                        if matches!(compare.op, IrOp::Sub | IrOp::Xor) {
                            if let Some(bound) = constant(right) {
                                return Some((*left, bound));
                            }
                            if let Some(bound) = constant(left) {
                                return Some((*right, bound));
                            }
                        }
                        if matches!(compare.op, IrOp::Add) {
                            if let Some(bound) = constant(right) {
                                return Some((*left, bound.wrapping_neg()));
                            }
                            if let Some(bound) = constant(left) {
                                return Some((*right, bound.wrapping_neg()));
                            }
                        }
                    }
                }
                return Some((*source, 0));
            }
            _ => return None,
        }
    }
    None
}

pub(super) fn loops(
    func: &IrFunction,
    facts: &HashMap<ValueId, Fact>,
    definitions: &HashMap<ValueId, Definition<'_>>,
    reachable: &HashSet<BlockId>,
) -> Result<LoopBounds, RejectionReason> {
    let blocks: HashMap<_, _> = func.blocks.iter().map(|block| (block.id, block)).collect();
    let mut predecessors: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    for block in &func.blocks {
        if !reachable.contains(&block.id) {
            continue;
        }
        let successors = match block.term {
            IrTerminator::Jump(target) => [Some(target), None],
            IrTerminator::Branch {
                taken, not_taken, ..
            } => [Some(taken), Some(not_taken)],
            _ => [None, None],
        };
        for successor in successors.into_iter().flatten() {
            predecessors.entry(successor).or_default().push(block.id);
        }
    }
    let mut dominators: HashMap<_, _> = reachable
        .iter()
        .map(|&block| {
            (
                block,
                if block == func.entry {
                    HashSet::from([block])
                } else {
                    reachable.clone()
                },
            )
        })
        .collect();
    loop {
        let mut changed = false;
        for block in &func.blocks {
            if block.id == func.entry || !reachable.contains(&block.id) {
                continue;
            }
            let mut parents = predecessors[&block.id].iter();
            let Some(first) = parents.next() else {
                continue;
            };
            let mut common = dominators[first].clone();
            for parent in parents {
                common.retain(|block| dominators[parent].contains(block));
            }
            common.insert(block.id);
            if common != dominators[&block.id] {
                dominators.insert(block.id, common);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut backedges: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    for (&target, parents) in &predecessors {
        for &parent in parents {
            if dominators[&parent].contains(&target) {
                backedges.entry(target).or_default().push(parent);
            }
        }
    }
    let mut result = LoopBounds::default();
    for (header, latches) in backedges {
        let [latch] = latches.as_slice() else {
            continue;
        };
        let IrTerminator::Branch {
            cond,
            taken,
            not_taken,
        } = blocks[latch].term
        else {
            continue;
        };
        let continuation = taken == header;
        if !continuation && not_taken != header {
            continue;
        }
        let Some((control, end)) = equality_exit(cond, continuation, facts, definitions) else {
            continue;
        };
        let mut members = HashSet::from([header]);
        let mut pending = vec![*latch];
        while let Some(block) = pending.pop() {
            if !members.insert(block) {
                continue;
            }
            pending.extend(predecessors.get(&block).into_iter().flatten().copied());
        }
        let exit = if continuation { not_taken } else { taken };
        if members.contains(&exit)
            || members
                .iter()
                .any(|block| !dominators[block].contains(&header))
        {
            continue;
        }
        let initial = |phi: &Phi| {
            let mut outside = phi
                .args
                .iter()
                .filter(|(block, _)| !members.contains(block));
            let (_, value) = outside.next()?;
            let fact = facts.get(value).copied()?;
            outside
                .all(|(_, value)| facts.get(value) == Some(&fact))
                .then_some(fact)
        };
        let update = |phi: &Phi| {
            let mut inside = phi.args.iter().filter(|(block, _)| members.contains(block));
            let (block, value) = inside.next()?;
            (*block == *latch && inside.next().is_none()).then_some(*value)
        };
        let mut trips = None;
        for phi in &blocks[&header].phis {
            let Some(Fact::Scalar(Some(start))) = initial(phi) else {
                continue;
            };
            let Some(next) = update(phi) else { continue };
            let Some(step) = affine(next, phi.dest, facts, definitions, definitions.len()) else {
                continue;
            };
            let Some(compared) = affine(control, phi.dest, facts, definitions, definitions.len())
            else {
                continue;
            };
            if step.delta == 0 {
                continue;
            }
            // The first equality at the latch fixes the header visits before any wrap.
            let distance = i128::from(end) - i128::from(start) - i128::from(compared.delta);
            let stride = i128::from(step.delta);
            if distance % stride != 0 || distance / stride < 0 {
                continue;
            }
            let count = distance / stride + 1;
            let last = i128::from(start) + stride * (count - 1);
            let low = i128::from(start).min(last);
            let high = i128::from(start).max(last);
            let limit = (1u128 << step.bits.min(compared.bits).min(phi.ty.bits())) - 1;
            if low + i128::from(step.minimum.min(compared.minimum)) < 0
                || high + i128::from(step.maximum.max(compared.maximum)) > limit as i128
            {
                continue;
            }
            let count = u64::try_from(count).map_err(|_| RejectionReason::FrameOverflow)?;
            trips = Some(count);
            break;
        }
        let Some(trips) = trips else { continue };
        for phi in &blocks[&header].phis {
            let Some(initial) = initial(phi) else {
                continue;
            };
            let Some(next) = update(phi) else { continue };
            let Some(step) = affine(next, phi.dest, facts, definitions, definitions.len()) else {
                continue;
            };
            let count = i128::from(trips - 1);
            match initial {
                Fact::Scalar(Some(start)) => {
                    let last = i128::from(start) + i128::from(step.delta) * count;
                    let low = i128::from(start).min(last);
                    let high = i128::from(start).max(last);
                    let limit = (1u128 << step.bits.min(phi.ty.bits())) - 1;
                    if low + i128::from(step.minimum) < 0
                        || high + i128::from(step.maximum) > limit as i128
                    {
                        continue;
                    }
                    result.scalars.insert(
                        phi.dest,
                        ScalarBounds {
                            low: low as u64,
                            high: high as u64,
                        },
                    );
                }
                Fact::Offset(start) => {
                    if phi.ty != IrType::I64 || step.bits != 64 {
                        continue;
                    }
                    let last = i128::from(start) + i128::from(step.delta) * count;
                    let low = i128::from(start).min(last);
                    let high = i128::from(start).max(last);
                    let minimum = low + i128::from(step.minimum);
                    let maximum = high + i128::from(step.maximum);
                    i32::try_from(minimum).map_err(|_| RejectionReason::FrameOverflow)?;
                    i32::try_from(maximum).map_err(|_| RejectionReason::FrameOverflow)?;
                    let low = i64::try_from(low).map_err(|_| RejectionReason::FrameOverflow)?;
                    let high = i64::try_from(high).map_err(|_| RejectionReason::FrameOverflow)?;
                    if (low < 0) != (high < 0) {
                        continue;
                    }
                    let mut bounds = FramePointerBounds::default();
                    bounds.observe(low);
                    bounds.observe(high);
                    result.pointers.insert(phi.dest, bounds);
                    result.advances.insert(next, (phi.dest, step.delta));
                }
                _ => {}
            }
        }
    }
    Ok(result)
}

#[derive(Clone, Copy)]
enum ScalarState {
    Active(usize),
    Complete(Option<ScalarBounds>),
}

struct ScalarPending {
    value: ValueId,
    next_argument: usize,
    cycle_start: usize,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct ScalarWork {
    evaluated_nodes: usize,
    dependency_edges: usize,
    peak_pending: usize,
}

/// A cache is valid only for these immutable facts, definitions and loop bounds.
pub(super) struct ScalarAnalysis<'facts, 'ir> {
    facts: &'facts HashMap<ValueId, Fact>,
    definitions: &'facts HashMap<ValueId, Definition<'ir>>,
    known: &'facts HashMap<ValueId, ScalarBounds>,
    states: HashMap<ValueId, ScalarState>,
    pending: Vec<ScalarPending>,
    #[cfg(test)]
    work: ScalarWork,
}

impl<'facts, 'ir> ScalarAnalysis<'facts, 'ir> {
    pub(super) fn new(
        facts: &'facts HashMap<ValueId, Fact>,
        definitions: &'facts HashMap<ValueId, Definition<'ir>>,
        known: &'facts HashMap<ValueId, ScalarBounds>,
    ) -> Self {
        Self {
            facts,
            definitions,
            known,
            states: HashMap::new(),
            pending: Vec::new(),
            #[cfg(test)]
            work: ScalarWork::default(),
        }
    }

    fn arguments(&self, value: ValueId) -> &[ValueId] {
        if self.known.contains_key(&value)
            || matches!(self.facts.get(&value), Some(Fact::Scalar(Some(_))))
        {
            return &[];
        }
        let Some(Definition::Inst(inst)) = self.definitions.get(&value) else {
            return &[];
        };
        if inst.ty.bits() > 64 {
            return &[];
        }
        let count = match inst.op {
            IrOp::Copy | IrOp::Zext | IrOp::Trunc => 1,
            IrOp::Add | IrOp::Sub | IrOp::Shl | IrOp::Shr | IrOp::And => 2,
            IrOp::Mul if inst.args.len() == 2 => 2,
            _ => 0,
        };
        &inst.args[..count.min(inst.args.len())]
    }

    fn begin(&mut self, value: ValueId, depth: usize) -> ScalarPending {
        self.states.insert(value, ScalarState::Active(depth));
        #[cfg(test)]
        {
            self.work.evaluated_nodes += 1;
            self.work.peak_pending = self.work.peak_pending.max(depth + 1);
        }
        ScalarPending {
            value,
            next_argument: 0,
            cycle_start: usize::MAX,
        }
    }

    pub(super) fn get(&mut self, value: ValueId) -> Option<ScalarBounds> {
        if let Some(ScalarState::Complete(result)) = self.states.get(&value) {
            return *result;
        }
        let mut pending = std::mem::take(&mut self.pending);
        pending.push(self.begin(value, 0));
        while let Some(current) = pending.last_mut() {
            if let Some(argument) = self
                .arguments(current.value)
                .get(current.next_argument)
                .copied()
            {
                current.next_argument += 1;
                #[cfg(test)]
                {
                    self.work.dependency_edges += 1;
                }
                match self.states.get(&argument).copied() {
                    Some(ScalarState::Active(depth)) => {
                        current.cycle_start = current.cycle_start.min(depth);
                    }
                    Some(ScalarState::Complete(_)) => {}
                    None => {
                        let next = self.begin(argument, pending.len());
                        pending.push(next);
                    }
                }
                continue;
            }
            let current = pending.pop().unwrap();
            let result = if current.cycle_start <= pending.len() {
                None
            } else {
                self.evaluate(current.value)
            };
            self.states
                .insert(current.value, ScalarState::Complete(result));
            if let Some(parent) = pending.last_mut() {
                parent.cycle_start = parent.cycle_start.min(current.cycle_start);
            }
        }
        self.pending = pending;
        match self.states[&value] {
            ScalarState::Complete(result) => result,
            ScalarState::Active(_) => unreachable!("scalar traversal left an active value"),
        }
    }

    fn evaluate(&self, value: ValueId) -> Option<ScalarBounds> {
        if let Some(&bounds) = self.known.get(&value) {
            return Some(bounds);
        }
        if let Some(Fact::Scalar(Some(value))) = self.facts.get(&value) {
            return Some(ScalarBounds {
                low: *value,
                high: *value,
            });
        }
        let Definition::Inst(inst) = self.definitions.get(&value)? else {
            return None;
        };
        if inst.ty.bits() > 64 {
            return None;
        }
        let arg = |index: usize| match self.states.get(inst.args.get(index)?)? {
            ScalarState::Complete(result) => *result,
            ScalarState::Active(_) => None,
        };
        let mask = if inst.ty.bits() == 64 {
            u64::MAX
        } else {
            (1u64 << inst.ty.bits()) - 1
        };
        let normalize = |low: u128, high: u128| {
            let bits = inst.ty.bits();
            (low >> bits == high >> bits).then_some(ScalarBounds {
                low: low as u64 & mask,
                high: high as u64 & mask,
            })
        };
        match inst.op {
            IrOp::Copy | IrOp::Zext => arg(0),
            IrOp::Trunc => {
                let value = arg(0)?;
                normalize(u128::from(value.low), u128::from(value.high))
            }
            IrOp::Add => {
                let (left, right) = (arg(0)?, arg(1)?);
                normalize(
                    u128::from(left.low) + u128::from(right.low),
                    u128::from(left.high) + u128::from(right.high),
                )
            }
            IrOp::Sub => {
                let (left, right) = (arg(0)?, arg(1)?);
                let modulus = 1u128 << inst.ty.bits();
                normalize(
                    u128::from(left.low)
                        .checked_add(modulus)?
                        .checked_sub(u128::from(right.high))?,
                    u128::from(left.high)
                        .checked_add(modulus)?
                        .checked_sub(u128::from(right.low))?,
                )
            }
            IrOp::Mul if inst.args.len() == 2 => {
                let (left, right) = (arg(0)?, arg(1)?);
                normalize(
                    u128::from(left.low) * u128::from(right.low),
                    u128::from(left.high) * u128::from(right.high),
                )
            }
            IrOp::Shl | IrOp::Shr => {
                let (value, count) = (arg(0)?, arg(1)?);
                if count.low != count.high {
                    return None;
                }
                let count = (count.low & if inst.ty == IrType::I64 { 63 } else { 31 }) as u32;
                if matches!(inst.op, IrOp::Shl) {
                    normalize(
                        u128::from(value.low) << count,
                        u128::from(value.high) << count,
                    )
                } else {
                    Some(ScalarBounds {
                        low: value.low >> count,
                        high: value.high >> count,
                    })
                }
            }
            IrOp::And => {
                let left = arg(0);
                let right = arg(1);
                match (left, right) {
                    (Some(left), Some(right)) => Some(ScalarBounds {
                        low: 0,
                        high: left.high.min(right.high),
                    }),
                    (Some(bound), None) | (None, Some(bound)) => Some(ScalarBounds {
                        low: 0,
                        high: bound.high,
                    }),
                    _ => None,
                }
            }
            IrOp::Undef | IrOp::Load if inst.ty.bits() < 64 => {
                Some(ScalarBounds { low: 0, high: mask })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
