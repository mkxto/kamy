use super::*;

#[derive(Clone, Copy)]
struct Expression {
    base: ValueId,
    index: Option<(ValueId, bool)>,
    displacement: i64,
}

pub(super) struct PointerProof {
    pub bounds: FramePointerBounds,
    pub indexed: Option<FrameIndexedAddress>,
    pub relative: Option<(ValueId, i64)>,
}

pub(super) fn from_interval(low: i64, high: i64) -> Result<FramePointerBounds, RejectionReason> {
    if low > high {
        return Err(RejectionReason::FrameConflict);
    }
    i32::try_from(low).map_err(|_| RejectionReason::FrameOverflow)?;
    i32::try_from(high).map_err(|_| RejectionReason::FrameOverflow)?;
    Ok(FramePointerBounds {
        negative: (low < 0).then_some((low, high.min(-1))),
        incoming: (high >= 0).then_some((low.max(0), high)),
    })
}

pub(super) fn validate(bounds: FramePointerBounds) -> Result<(), RejectionReason> {
    if bounds.is_empty() {
        return Err(RejectionReason::FrameDynamic);
    }
    for (negative, interval) in [(true, bounds.negative), (false, bounds.incoming)] {
        if let Some((low, high)) = interval {
            if low > high || (low < 0) != negative || (high < 0) != negative {
                return Err(RejectionReason::FrameConflict);
            }
            i32::try_from(low).map_err(|_| RejectionReason::FrameOverflow)?;
            i32::try_from(high).map_err(|_| RejectionReason::FrameOverflow)?;
        }
    }
    Ok(())
}

// Coarse intervals certify an access only when every represented start stays
// within one frame zone. Failure to certify is not proof that an actual
// Select/Phi alternative straddles the split; callers may expand its DAG.
pub(super) fn access_bounds(
    bounds: FramePointerBounds,
    adjustment: i64,
    extent: i64,
) -> Result<Option<FramePointerBounds>, RejectionReason> {
    let mut result = FramePointerBounds::default();
    for (low, high) in [bounds.negative, bounds.incoming].into_iter().flatten() {
        let start = low
            .checked_add(adjustment)
            .ok_or(RejectionReason::FrameOverflow)?;
        let last = high
            .checked_add(adjustment)
            .ok_or(RejectionReason::FrameOverflow)?;
        let end = last
            .checked_add(extent)
            .ok_or(RejectionReason::FrameOverflow)?;
        i32::try_from(start).map_err(|_| RejectionReason::FrameOverflow)?;
        i32::try_from(end).map_err(|_| RejectionReason::FrameOverflow)?;
        if start < 0 && end >= 0 {
            return Ok(None);
        }
        result.observe(start);
        result.observe(last);
    }
    Ok(Some(result))
}

fn merge(target: &mut FramePointerBounds, bounds: FramePointerBounds) {
    for (low, high) in [bounds.negative, bounds.incoming].into_iter().flatten() {
        target.observe(low);
        target.observe(high);
    }
}

pub(super) fn shifted(
    bounds: FramePointerBounds,
    low: i64,
    high: i64,
) -> Result<FramePointerBounds, RejectionReason> {
    let mut result = FramePointerBounds::default();
    for (start, end) in [bounds.negative, bounds.incoming].into_iter().flatten() {
        let start = start
            .checked_add(low)
            .ok_or(RejectionReason::FrameOverflow)?;
        let end = end
            .checked_add(high)
            .ok_or(RejectionReason::FrameOverflow)?;
        merge(&mut result, from_interval(start, end)?);
    }
    Ok(result)
}

fn pointer_bounds(
    value: ValueId,
    facts: &HashMap<ValueId, Fact>,
    known: &HashMap<ValueId, FramePointerBounds>,
) -> Option<FramePointerBounds> {
    if let Some(bounds) = known.get(&value) {
        return Some(*bounds);
    }
    if let Some(Fact::Offset(offset)) = facts.get(&value) {
        let mut bounds = FramePointerBounds::default();
        bounds.observe(*offset);
        return Some(bounds);
    }
    None
}

fn expression(
    value: ValueId,
    facts: &HashMap<ValueId, Fact>,
    definitions: &HashMap<ValueId, Definition<'_>>,
    known: &HashMap<ValueId, FramePointerBounds>,
    depth: usize,
) -> Option<Expression> {
    if pointer_bounds(value, facts, known).is_some() {
        return Some(Expression {
            base: value,
            index: None,
            displacement: 0,
        });
    }
    if matches!(facts.get(&value), Some(Fact::Scalar(_))) {
        return None;
    }
    if depth == 0 {
        return None;
    }
    let Definition::Inst(inst) = definitions.get(&value)? else {
        return None;
    };
    if inst.ty != IrType::I64 {
        return None;
    }
    let (mut expression, other, subtract) = match (&inst.op, inst.args.as_slice()) {
        (IrOp::Copy, [source]) => return expression(*source, facts, definitions, known, depth - 1),
        (IrOp::FrameOffset(offset), [source]) => {
            let mut expression = expression(*source, facts, definitions, known, depth - 1)?;
            expression.displacement = expression.displacement.checked_add(*offset)?;
            return Some(expression);
        }
        (IrOp::Add | IrOp::Sub, [left, right]) => {
            if let Some(expression) = expression(*left, facts, definitions, known, depth - 1) {
                (expression, *right, matches!(inst.op, IrOp::Sub))
            } else if matches!(inst.op, IrOp::Add) {
                (
                    expression(*right, facts, definitions, known, depth - 1)?,
                    *left,
                    false,
                )
            } else {
                return None;
            }
        }
        _ => return None,
    };
    if pointer_bounds(other, facts, known).is_some() {
        return None;
    }
    if let Some(Fact::Scalar(Some(constant))) = facts.get(&other) {
        let offset = if subtract {
            (*constant as i64).checked_neg()?
        } else {
            *constant as i64
        };
        expression.displacement = expression.displacement.checked_add(offset)?;
    } else if expression.index.is_none() {
        expression.index = Some((other, subtract));
    } else {
        return None;
    }
    Some(expression)
}

pub(super) fn prove(
    value: ValueId,
    facts: &HashMap<ValueId, Fact>,
    definitions: &HashMap<ValueId, Definition<'_>>,
    known: &HashMap<ValueId, FramePointerBounds>,
    scalars: &mut bounds::ScalarAnalysis<'_, '_>,
) -> Result<Option<PointerProof>, RejectionReason> {
    let Some(expression) = expression(value, facts, definitions, known, definitions.len()) else {
        return Ok(None);
    };
    if expression.base == value && expression.index.is_none() {
        return Ok(None);
    }
    let base =
        pointer_bounds(expression.base, facts, known).ok_or(RejectionReason::FrameDynamic)?;
    let Some((index, subtract)) = expression.index else {
        let bounds = shifted(base, expression.displacement, expression.displacement)?;
        return Ok(Some(PointerProof {
            bounds,
            indexed: None,
            relative: Some((expression.base, expression.displacement)),
        }));
    };
    let Some(range) = scalars.get(index) else {
        return Ok(None);
    };
    if range.low <= i64::MAX as u64 && range.high > i64::MAX as u64 {
        return Ok(None);
    }
    let (low, high) = if subtract {
        (
            (range.high as i64).checked_neg(),
            (range.low as i64).checked_neg(),
        )
    } else {
        (Some(range.low as i64), Some(range.high as i64))
    };
    let low = low
        .and_then(|low| low.checked_add(expression.displacement))
        .ok_or(RejectionReason::FrameOverflow)?;
    let high = high
        .and_then(|high| high.checked_add(expression.displacement))
        .ok_or(RejectionReason::FrameOverflow)?;
    let bounds = shifted(base, low, high)?;
    Ok(Some(PointerProof {
        bounds,
        indexed: Some(FrameIndexedAddress {
            base: expression.base,
            index,
            displacement: expression.displacement,
            subtract,
            bounds,
        }),
        relative: None,
    }))
}

pub(super) fn phi(
    phi: &Phi,
    facts: &HashMap<ValueId, Fact>,
    known: &HashMap<ValueId, FramePointerBounds>,
    reachable: &HashSet<BlockId>,
) -> Option<FramePointerBounds> {
    let mut result = FramePointerBounds::default();
    for (_, value) in phi
        .args
        .iter()
        .filter(|(block, _)| reachable.contains(block))
    {
        merge(&mut result, pointer_bounds(*value, facts, known)?);
    }
    (!result.is_empty()).then_some(result)
}

pub(super) fn select(
    inst: &Inst,
    facts: &HashMap<ValueId, Fact>,
    known: &HashMap<ValueId, FramePointerBounds>,
) -> Option<FramePointerBounds> {
    if inst.ty != IrType::I64 {
        return None;
    }
    let [condition, yes, no] = inst.args.as_slice() else {
        return None;
    };
    match facts.get(condition) {
        None | Some(Fact::Unknown) => None,
        Some(Fact::Scalar(Some(0))) => pointer_bounds(*no, facts, known),
        Some(Fact::Scalar(Some(_))) => pointer_bounds(*yes, facts, known),
        _ => {
            let mut bounds = pointer_bounds(*yes, facts, known)?;
            merge(&mut bounds, pointer_bounds(*no, facts, known)?);
            Some(bounds)
        }
    }
}
