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
