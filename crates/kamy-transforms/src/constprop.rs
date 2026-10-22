use std::collections::HashMap;

use kamy_core::ir::{IrFunction, IrOp, IrType, ValueId};

use crate::Pass;

pub struct ConstProp;

fn type_mask(ty: IrType) -> u64 {
    match ty {
        IrType::I8 => 0xFF,
        IrType::I16 => 0xFFFF,
        IrType::I32 => 0xFFFF_FFFF,
        IrType::I64 => u64::MAX,
        IrType::I128 => u64::MAX,
    }
}

fn fold(op: &IrOp, vals: &[u64], ty: IrType, arg_ty: Option<IrType>) -> Option<u64> {
    if ty == IrType::I128 {
        return None;
    }
    let m = type_mask(ty);
    match op {
        IrOp::Copy => Some(vals[0] & m),
        IrOp::Add => Some(vals[0].wrapping_add(vals[1]) & m),
        IrOp::Sub => Some(vals[0].wrapping_sub(vals[1]) & m),
        IrOp::Neg => Some(0u64.wrapping_sub(vals[0]) & m),
        IrOp::And => Some(vals[0] & vals[1] & m),
        IrOp::Or => Some((vals[0] | vals[1]) & m),
        IrOp::Xor => Some((vals[0] ^ vals[1]) & m),
        IrOp::Not => Some((!vals[0]) & m),
        IrOp::BoolNot => Some((vals[0] == 0) as u64),
        IrOp::Shl => {
            let shift = vals[1] % ty.bits() as u64;
            Some((vals[0] << shift) & m)
        }
        IrOp::Shr => {
            let shift = vals[1] % ty.bits() as u64;
            Some((vals[0] & m) >> shift)
        }
        IrOp::Zext => {
            let at = arg_ty?;
            Some(vals[0] & type_mask(at))
        }
        IrOp::Sext => {
            let at = arg_ty?;
            let src_bits = at.bits();
            let val = vals[0] & type_mask(at);
            let sign_bit = 1u64 << (src_bits - 1);
            if val & sign_bit != 0 {
                Some((val | (u64::MAX << src_bits)) & m)
            } else {
                Some(val & m)
            }
        }
        IrOp::Trunc => Some(vals[0] & m),
        _ => None,
    }
}

impl Pass for ConstProp {
    fn name(&self) -> &'static str {
        "const-prop"
    }

    fn run(&self, func: &mut IrFunction) -> bool {
        let mut consts: HashMap<ValueId, u64> = HashMap::new();
        let mut types: HashMap<ValueId, IrType> = HashMap::new();

        for block in &func.blocks {
            for phi in &block.phis {
                types.insert(phi.dest, phi.ty);
            }
            for inst in &block.insts {
                if let Some(dest) = inst.dest {
                    types.insert(dest, inst.ty);
                    if let IrOp::Const(v) = &inst.op {
                        consts.insert(dest, *v & type_mask(inst.ty));
                    }
                }
            }
        }

        let mut folds: Vec<(usize, usize, ValueId, u64)> = Vec::new();

        for bi in 0..func.blocks.len() {
            for ii in 0..func.blocks[bi].insts.len() {
                let inst = &func.blocks[bi].insts[ii];
                let dest = match inst.dest {
                    Some(d) => d,
                    None => continue,
                };

                if matches!(inst.op, IrOp::Const(_)) {
                    continue;
                }

                let mut arg_vals = Vec::with_capacity(inst.args.len());
                let mut all_const = true;
                for &arg in &inst.args {
                    if let Some(&v) = consts.get(&arg) {
                        arg_vals.push(v);
                    } else {
                        all_const = false;
                        break;
                    }
                }

                if !all_const {
                    continue;
                }

                let arg_ty = if inst.args.len() == 1 {
                    types.get(&inst.args[0]).copied()
                } else {
                    None
                };

                if let Some(result) = fold(&inst.op, &arg_vals, inst.ty, arg_ty) {
                    folds.push((bi, ii, dest, result));
                    consts.insert(dest, result);
                }
            }
        }

        let changed = !folds.is_empty();
        for (bi, ii, _, result) in folds {
            func.blocks[bi].insts[ii].op = IrOp::Const(result);
            func.blocks[bi].insts[ii].args.clear();
        }

        changed
    }
}

#[derive(Clone, PartialEq, Eq)]
enum AddressFact {
    Pending,
    Constant(u64),
    Base(kamy_core::Reference),
    Unknown,
}

fn merge_fact(slot: &mut AddressFact, fact: AddressFact) -> bool {
    let same = match (&*slot, &fact) {
        (AddressFact::Base(left), AddressFact::Base(right)) => left.expression == right.expression,
        _ => *slot == fact,
    };
    if matches!(fact, AddressFact::Pending) || same || matches!(slot, AddressFact::Unknown) {
        return false;
    }
    *slot = if matches!(slot, AddressFact::Pending) {
        fact
    } else {
        AddressFact::Unknown
    };
    true
}

fn offset_base(reference: &kamy_core::Reference, offset: i64) -> AddressFact {
    match reference.expression.clone().with_addend(offset) {
        Some(expression) => {
            let mut reference = reference.clone();
            reference.expression = expression;
            reference.field = kamy_core::LinkField::Absolute64;
            AddressFact::Base(reference)
        }
        None => AddressFact::Unknown,
    }
}

/// Resolve arithmetic only when its base operand is the proven host ImageBase.
/// Returns whether an unresolved or escaping base-derived consumer remains.
pub fn resolve_image_base_uses(
    func: &mut IrFunction,
    mut classify: impl FnMut(i64) -> Option<kamy_core::SymbolicExpression>,
) -> bool {
    crate::Dce.run(func);
    let mut facts = vec![AddressFact::Pending; func.next_value as usize];
    loop {
        let mut changed = false;
        for block in &func.blocks {
            for phi in &block.phis {
                let mut fact = AddressFact::Pending;
                let mut pending = false;
                for &(_, value) in &phi.args {
                    if value == phi.dest {
                        continue;
                    }
                    if matches!(facts[value.0 as usize], AddressFact::Pending) {
                        pending = true;
                    }
                    merge_fact(&mut fact, facts[value.0 as usize].clone());
                }
                if !pending {
                    changed |= merge_fact(&mut facts[phi.dest.0 as usize], fact);
                }
            }
            for inst in &block.insts {
                let Some(dest) = inst.dest else {
                    continue;
                };
                let arg = |index: usize| inst.args.get(index).map(|value| &facts[value.0 as usize]);
                let fact = match &inst.op {
                    IrOp::Const(value) => AddressFact::Constant(*value),
                    IrOp::Address(reference)
                        if matches!(
                            reference.expression,
                            kamy_core::SymbolicExpression::Symbol {
                                symbol: kamy_core::SymbolId::HostImageBase,
                                ..
                            }
                        ) =>
                    {
                        AddressFact::Base(reference.clone())
                    }
                    IrOp::Copy => arg(0).cloned().unwrap_or(AddressFact::Unknown),
                    IrOp::Add | IrOp::Sub if inst.ty == IrType::I64 => match (arg(0), arg(1)) {
                        (Some(AddressFact::Base(base)), Some(AddressFact::Constant(offset))) => {
                            let offset = *offset as i64;
                            if matches!(inst.op, IrOp::Sub) {
                                offset.checked_neg().map_or(AddressFact::Unknown, |offset| {
                                    offset_base(base, offset)
                                })
                            } else {
                                offset_base(base, offset)
                            }
                        }
                        (Some(AddressFact::Constant(offset)), Some(AddressFact::Base(base)))
                            if matches!(inst.op, IrOp::Add) =>
                        {
                            offset_base(base, *offset as i64)
                        }
                        (Some(AddressFact::Constant(left)), Some(AddressFact::Constant(right))) => {
                            AddressFact::Constant(if matches!(inst.op, IrOp::Add) {
                                left.wrapping_add(*right)
                            } else {
                                left.wrapping_sub(*right)
                            })
                        }
                        (Some(AddressFact::Pending), _) | (_, Some(AddressFact::Pending)) => {
                            AddressFact::Pending
                        }
                        _ => AddressFact::Unknown,
                    },
                    _ => AddressFact::Unknown,
                };
                changed |= merge_fact(&mut facts[dest.0 as usize], fact);
            }
        }
        if !changed {
            break;
        }
    }
    for block in &mut func.blocks {
        for inst in &mut block.insts {
            if matches!(inst.op, IrOp::Address(_) | IrOp::Add | IrOp::Sub) {
                if let Some(AddressFact::Base(reference)) =
                    inst.dest.map(|value| &facts[value.0 as usize])
                {
                    let mut reference = reference.clone();
                    if let kamy_core::SymbolicExpression::Symbol { addend, .. } =
                        reference.expression
                    {
                        if let Some(expression) = classify(addend) {
                            reference.expression = expression;
                        }
                    }
                    inst.op = IrOp::Address(reference);
                    inst.args.clear();
                    continue;
                }
            }
        }
    }
    let mut derived = vec![false; func.next_value as usize];
    loop {
        let mut changed = false;
        for block in &func.blocks {
            for phi in &block.phis {
                if !derived[phi.dest.0 as usize]
                    && phi.args.iter().any(|(_, value)| derived[value.0 as usize])
                {
                    derived[phi.dest.0 as usize] = true;
                    changed = true;
                }
            }
            for inst in &block.insts {
                let Some(dest) = inst.dest else {
                    continue;
                };
                let tainted = match &inst.op {
                    IrOp::Address(reference) => matches!(
                        reference.expression,
                        kamy_core::SymbolicExpression::Symbol {
                            symbol: kamy_core::SymbolId::HostImageBase,
                            ..
                        }
                    ),
                    IrOp::Load | IrOp::CallResult { .. } | IrOp::Const(_) | IrOp::Undef => false,
                    _ => inst.args.iter().any(|value| derived[value.0 as usize]),
                };
                if tainted && !derived[dest.0 as usize] {
                    derived[dest.0 as usize] = true;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let mut unresolved = false;
    for block in &func.blocks {
        for inst in &block.insts {
            let consumes = inst.args.iter().any(|value| derived[value.0 as usize]);
            unresolved |= consumes
                && match inst.op {
                    IrOp::Copy | IrOp::Load => false,
                    IrOp::Store => inst
                        .args
                        .get(1)
                        .is_some_and(|value| derived[value.0 as usize]),
                    _ => true,
                };
        }
    }
    unresolved
}
