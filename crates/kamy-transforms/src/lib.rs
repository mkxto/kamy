mod constprop;
mod dce;
mod instcombine;
pub mod mba;
mod prune_phis;

pub use constprop::ConstProp;
pub use dce::Dce;
pub use instcombine::InstCombine;
pub use mba::MbaPass;
pub use prune_phis::PrunePhis;

use kamy_core::ir::{IrFunction, IrTerminator, ValueId};

pub trait Pass {
    fn run(&self, func: &mut IrFunction) -> bool;
}

pub fn optimize(func: &mut IrFunction) {
    let passes: &[&dyn Pass] = &[&ConstProp, &InstCombine, &Dce, &PrunePhis];
    loop {
        let mut changed = false;
        for pass in passes {
            changed |= pass.run(func);
        }
        if !changed {
            break;
        }
    }
}

pub fn replace_uses(func: &mut IrFunction, old: ValueId, new: ValueId) {
    for block in &mut func.blocks {
        for phi in &mut block.phis {
            for (_, v) in &mut phi.args {
                if *v == old {
                    *v = new;
                }
            }
        }
        for inst in &mut block.insts {
            for arg in &mut inst.args {
                if *arg == old {
                    *arg = new;
                }
            }
        }
        if let IrTerminator::Branch { cond, .. } = &mut block.term {
            if *cond == old {
                *cond = new;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use kamy_core::ir::{BlockId, Inst, IrBlock, IrFunction, IrOp, IrTerminator, IrType, Phi};

    use super::*;

    fn one_block_func() -> IrFunction {
        IrFunction {
            entry: BlockId(0),
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![],
                term: IrTerminator::Ret,
            }],
            next_value: 0,
        }
    }

    #[test]
    fn constprop_folds_add() {
        let mut func = one_block_func();
        let v0 = func.alloc_value();
        let v1 = func.alloc_value();
        let v2 = func.alloc_value();
        func.blocks[0].insts = vec![
            Inst {
                dest: Some(v0),
                op: IrOp::Const(3),
                args: vec![],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v1),
                op: IrOp::Const(4),
                args: vec![],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v2),
                op: IrOp::Add,
                args: vec![v0, v1],
                ty: IrType::I32,
            },
        ];

        assert!(ConstProp.run(&mut func));
        assert!(matches!(func.blocks[0].insts[2].op, IrOp::Const(7)));
    }

    #[test]
    fn instcombine_add_zero() {
        let mut func = one_block_func();
        let v_addr = func.alloc_value();
        let v0 = func.alloc_value();
        let v_zero = func.alloc_value();
        let v_add = func.alloc_value();
        let v_store_addr = func.alloc_value();
        func.blocks[0].insts = vec![
            Inst {
                dest: Some(v_addr),
                op: IrOp::Const(0x1000),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(v0),
                op: IrOp::Load,
                args: vec![v_addr],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_zero),
                op: IrOp::Const(0),
                args: vec![],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_add),
                op: IrOp::Add,
                args: vec![v0, v_zero],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_store_addr),
                op: IrOp::Const(0x2000),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: None,
                op: IrOp::Store,
                args: vec![v_store_addr, v_add],
                ty: IrType::I32,
            },
        ];

        assert!(InstCombine.run(&mut func));
        assert_eq!(func.blocks[0].insts[5].args[1], v0);
    }

    #[test]
    fn dce_removes_unused_keeps_store() {
        let mut func = one_block_func();
        let v_addr = func.alloc_value();
        let v_load = func.alloc_value();
        let v_dead = func.alloc_value();
        let v_val = func.alloc_value();
        func.blocks[0].insts = vec![
            Inst {
                dest: Some(v_addr),
                op: IrOp::Const(0x1000),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(v_load),
                op: IrOp::Load,
                args: vec![v_addr],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_dead),
                op: IrOp::Add,
                args: vec![v_load, v_load],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_val),
                op: IrOp::Const(42),
                args: vec![],
                ty: IrType::I32,
            },
            Inst {
                dest: None,
                op: IrOp::Store,
                args: vec![v_addr, v_val],
                ty: IrType::I32,
            },
        ];

        assert!(Dce.run(&mut func));

        let has_store = func.blocks[0]
            .insts
            .iter()
            .any(|i| matches!(i.op, IrOp::Store));
        assert!(has_store);

        let has_dead_add = func.blocks[0].insts.iter().any(|i| i.dest == Some(v_dead));
        assert!(!has_dead_add);

        let has_dead_load = func.blocks[0].insts.iter().any(|i| i.dest == Some(v_load));
        assert!(!has_dead_load);
    }

    #[test]
    fn prune_phis_same_args() {
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let v0 = func.alloc_value();
        let v_phi = func.alloc_value();
        let v_store_addr = func.alloc_value();
        func.blocks = vec![
            IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![Inst {
                    dest: Some(v0),
                    op: IrOp::Const(42),
                    args: vec![],
                    ty: IrType::I32,
                }],
                term: IrTerminator::Jump(BlockId(1)),
            },
            IrBlock {
                id: BlockId(1),
                phis: vec![Phi {
                    dest: v_phi,
                    ty: IrType::I32,
                    args: vec![(BlockId(0), v0), (BlockId(1), v0)],
                }],
                insts: vec![
                    Inst {
                        dest: Some(v_store_addr),
                        op: IrOp::Const(0x1000),
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: None,
                        op: IrOp::Store,
                        args: vec![v_store_addr, v_phi],
                        ty: IrType::I32,
                    },
                ],
                term: IrTerminator::Ret,
            },
        ];

        assert!(PrunePhis.run(&mut func));
        assert!(func.blocks[1].phis.is_empty());
        assert_eq!(func.blocks[1].insts[1].args[1], v0);
    }

    #[test]
    fn convergence_instcombine_then_dce() {
        let mut func = one_block_func();
        let v_addr = func.alloc_value();
        let v0 = func.alloc_value();
        let v_zero = func.alloc_value();
        let v_add = func.alloc_value();
        func.blocks[0].insts = vec![
            Inst {
                dest: Some(v_addr),
                op: IrOp::Const(0x1000),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(v0),
                op: IrOp::Load,
                args: vec![v_addr],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_zero),
                op: IrOp::Const(0),
                args: vec![],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_add),
                op: IrOp::Add,
                args: vec![v0, v_zero],
                ty: IrType::I32,
            },
            Inst {
                dest: None,
                op: IrOp::Store,
                args: vec![v_addr, v_add],
                ty: IrType::I32,
            },
        ];

        optimize(&mut func);

        let has_add = func.blocks[0]
            .insts
            .iter()
            .any(|i| matches!(i.op, IrOp::Add));
        assert!(!has_add);

        let has_const_zero = func.blocks[0]
            .insts
            .iter()
            .any(|i| matches!(i.op, IrOp::Const(0)));
        assert!(!has_const_zero);

        let store = func.blocks[0]
            .insts
            .iter()
            .find(|i| matches!(i.op, IrOp::Store))
            .expect("Store must survive");
        assert_eq!(store.args[1], v0);
    }
}
