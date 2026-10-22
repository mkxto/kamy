use std::collections::HashMap;

use kamy_core::ir::{IrFunction, IrTerminator, ValueId};

use crate::Pass;

#[derive(Clone, Copy)]
enum Alias {
    Pending(ValueId),
    Active,
    Resolved(ValueId),
}

fn resolve_alias(start: ValueId, aliases: &mut HashMap<ValueId, Alias>, path: &mut Vec<ValueId>) {
    if !matches!(aliases.get(&start), Some(Alias::Pending(_))) {
        return;
    }
    path.clear();
    let mut current = start;
    let replacement = loop {
        match aliases.get(&current).copied() {
            None => break current,
            Some(Alias::Resolved(value)) => break value,
            Some(Alias::Pending(next)) => {
                aliases.insert(current, Alias::Active);
                path.push(current);
                current = next;
            }
            Some(Alias::Active) => {
                // A phi-only cycle has no external definition to substitute.
                while let Some(value) = path.pop() {
                    aliases.insert(value, Alias::Resolved(value));
                    if value == current {
                        break;
                    }
                }
                break current;
            }
        }
    };
    for value in path.drain(..) {
        aliases.insert(value, Alias::Resolved(replacement));
    }
}

pub struct PrunePhis;

impl Pass for PrunePhis {
    fn name(&self) -> &'static str {
        "prune-phis"
    }

    fn run(&self, func: &mut IrFunction) -> bool {
        let mut aliases = HashMap::new();

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
                        aliases.insert(phi.dest, Alias::Pending(u));
                    }
                }
            }
        }

        if aliases.is_empty() {
            return false;
        }

        let mut path = Vec::new();
        for block in &func.blocks {
            for phi in &block.phis {
                resolve_alias(phi.dest, &mut aliases, &mut path);
            }
        }
        aliases.retain(|value, alias| match *alias {
            Alias::Resolved(replacement) => replacement != *value,
            _ => false,
        });
        if aliases.is_empty() {
            return false;
        }

        let replace = |value: &mut ValueId| {
            if let Some(Alias::Resolved(replacement)) = aliases.get(&*value) {
                *value = *replacement;
            }
        };
        for block in &mut func.blocks {
            block.phis.retain(|phi| !aliases.contains_key(&phi.dest));
            for phi in &mut block.phis {
                for (_, value) in &mut phi.args {
                    replace(value);
                }
            }
            for inst in &mut block.insts {
                for value in &mut inst.args {
                    replace(value);
                }
            }
            if let IrTerminator::Branch { cond, .. } = &mut block.term {
                replace(cond);
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::ir::{BlockId, Inst, IrBlock, IrOp, IrType, Phi};

    fn phi(dest: u32, args: &[(u32, u32)]) -> Phi {
        Phi {
            dest: ValueId(dest),
            ty: IrType::I8,
            args: args
                .iter()
                .map(|&(block, value)| (BlockId(block), ValueId(value)))
                .collect(),
        }
    }

    fn function(phis: Vec<Phi>, result: u32) -> IrFunction {
        IrFunction {
            entry: BlockId(0),
            next_value: 901,
            blocks: vec![
                IrBlock {
                    id: BlockId(0),
                    phis: vec![],
                    insts: vec![Inst {
                        dest: Some(ValueId(0)),
                        op: IrOp::Const(1),
                        args: vec![],
                        ty: IrType::I8,
                    }],
                    term: IrTerminator::Jump(BlockId(1)),
                },
                IrBlock {
                    id: BlockId(1),
                    phis,
                    insts: vec![
                        Inst {
                            dest: Some(ValueId(900)),
                            op: IrOp::Copy,
                            args: vec![ValueId(result)],
                            ty: IrType::I8,
                        },
                        Inst {
                            dest: None,
                            op: IrOp::Use,
                            args: vec![ValueId(900)],
                            ty: IrType::I8,
                        },
                    ],
                    term: IrTerminator::Branch {
                        cond: ValueId(result),
                        taken: BlockId(1),
                        not_taken: BlockId(2),
                    },
                },
                IrBlock {
                    id: BlockId(2),
                    phis: vec![],
                    insts: vec![],
                    term: IrTerminator::Ret,
                },
            ],
        }
    }

    #[test]
    fn transitive_aliases_rewrite_all_consumers_independent_of_block_order() {
        for reverse in [false, true] {
            let (first, second) = if reverse { (2, 1) } else { (1, 2) };
            let mut func = function(vec![], 20);
            let insts = std::mem::take(&mut func.blocks[1].insts);
            func.blocks[0].term = IrTerminator::Jump(BlockId(first));
            func.blocks[first as usize].phis = vec![phi(10, &[(0, 0), (first, 10)])];
            func.blocks[first as usize].term = IrTerminator::Branch {
                cond: ValueId(0),
                taken: BlockId(first),
                not_taken: BlockId(second),
            };
            func.blocks[second as usize].phis = vec![
                phi(20, &[(first, 10), (second, 20)]),
                phi(30, &[(first, 0), (second, 20)]),
            ];
            func.blocks[second as usize].insts = insts;
            func.blocks[second as usize].term = IrTerminator::Branch {
                cond: ValueId(20),
                taken: BlockId(second),
                not_taken: BlockId(3),
            };
            func.blocks.push(IrBlock {
                id: BlockId(3),
                phis: vec![],
                insts: vec![],
                term: IrTerminator::Ret,
            });
            assert!(PrunePhis.run(&mut func));
            let block = func.block(BlockId(second));
            assert_eq!(block.phis.len(), 1);
            assert_eq!(block.phis[0].dest, ValueId(30));
            assert!(
                block.phis[0]
                    .args
                    .iter()
                    .all(|(_, value)| *value == ValueId(0))
            );
            assert_eq!(block.insts[0].args, [ValueId(0)]);
            assert!(matches!(
                block.term,
                IrTerminator::Branch {
                    cond: ValueId(0),
                    ..
                }
            ));
        }
    }

    #[test]
    fn closed_cycles_keep_definitions_while_incoming_aliases_are_pruned() {
        for reverse in [false, true] {
            let mut phis = vec![
                phi(30, &[(1, 10)]),
                phi(10, &[(1, 20)]),
                phi(20, &[(1, 10)]),
                phi(40, &[(1, 40)]),
            ];
            if reverse {
                phis.reverse();
            }
            let mut func = function(phis, 30);
            func.blocks[0].term = IrTerminator::Ret;
            func.blocks[1].term = IrTerminator::Branch {
                cond: ValueId(30),
                taken: BlockId(1),
                not_taken: BlockId(1),
            };
            assert!(PrunePhis.run(&mut func));
            let block = &func.blocks[1];
            assert_eq!(block.phis.len(), 3);
            for (dest, source) in [(10, 20), (20, 10), (40, 40)] {
                let phi = block
                    .phis
                    .iter()
                    .find(|phi| phi.dest == ValueId(dest))
                    .unwrap();
                assert_eq!(phi.args, [(BlockId(1), ValueId(source))]);
            }
            assert_eq!(block.insts[0].args, [ValueId(10)]);
            assert!(matches!(
                block.term,
                IrTerminator::Branch {
                    cond: ValueId(10),
                    ..
                }
            ));
            assert!(!PrunePhis.run(&mut func));
        }
    }
}
