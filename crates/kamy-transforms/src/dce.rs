use std::collections::{HashMap, HashSet};

use kamy_core::ir::{IrFunction, IrOp, IrTerminator, ValueId};

use crate::Pass;

pub struct Dce;

impl Pass for Dce {
    fn run(&self, func: &mut IrFunction) -> bool {
        let mut def_args: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        for block in &func.blocks {
            for phi in &block.phis {
                def_args.insert(phi.dest, phi.args.iter().map(|(_, v)| *v).collect());
            }
            for inst in &block.insts {
                if let Some(dest) = inst.dest {
                    def_args.insert(dest, inst.args.clone());
                }
            }
        }

        let mut live: HashSet<ValueId> = HashSet::new();
        let mut worklist: Vec<ValueId> = Vec::new();

        for block in &func.blocks {
            for inst in &block.insts {
                let is_root = inst.dest.is_none()
                    || matches!(
                        inst.op,
                        IrOp::Store | IrOp::Call { .. } | IrOp::NativeInline(_)
                    );
                if is_root {
                    if let Some(dest) = inst.dest {
                        live.insert(dest);
                    }
                    for &arg in &inst.args {
                        if live.insert(arg) {
                            worklist.push(arg);
                        }
                    }
                }
            }
            if let IrTerminator::Branch { cond, .. } = &block.term {
                if live.insert(*cond) {
                    worklist.push(*cond);
                }
            }
        }

        while let Some(v) = worklist.pop() {
            if let Some(args) = def_args.get(&v) {
                for &arg in args {
                    if live.insert(arg) {
                        worklist.push(arg);
                    }
                }
            }
        }

        let mut changed = false;
        for block in &mut func.blocks {
            let phi_before = block.phis.len();
            block.phis.retain(|phi| live.contains(&phi.dest));
            if block.phis.len() != phi_before {
                changed = true;
            }

            let inst_before = block.insts.len();
            block.insts.retain(|inst| match inst.dest {
                Some(dest) => live.contains(&dest),
                None => true,
            });
            if block.insts.len() != inst_before {
                changed = true;
            }
        }

        changed
    }
}
