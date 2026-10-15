use std::collections::HashSet;

use kamy_core::ir::{IrFunction, ValueId};

use crate::{Pass, replace_uses};

pub struct PrunePhis;

impl Pass for PrunePhis {
    fn run(&self, func: &mut IrFunction) -> bool {
        let mut pruned: Vec<(ValueId, ValueId)> = Vec::new();

        for block in &func.blocks {
            for phi in &block.phis {
                let mut unique: Option<ValueId> = None;
                let mut all_same = true;
                for &(_, v) in &phi.args {
                    if v == phi.dest {
                        continue;
                    }
                    match unique {
                        None => unique = Some(v),
                        Some(u) => {
                            if u != v {
                                all_same = false;
                                break;
                            }
                        }
                    }
                }
                if all_same {
                    if let Some(u) = unique {
                        pruned.push((phi.dest, u));
                    }
                }
            }
        }

        if pruned.is_empty() {
            return false;
        }

        let pruned_set: HashSet<ValueId> = pruned.iter().map(|(d, _)| *d).collect();
        for (old, new) in &pruned {
            replace_uses(func, *old, *new);
        }
        for block in &mut func.blocks {
            block.phis.retain(|phi| !pruned_set.contains(&phi.dest));
        }

        true
    }
}
