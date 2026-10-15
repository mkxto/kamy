use std::collections::HashMap;

use kamy_core::ir::{IrFunction, IrOp, ValueId};

use crate::{Pass, replace_uses};

pub struct InstCombine;

enum Pending {
    Replace {
        old: ValueId,
        new: ValueId,
    },
    Const {
        bi: usize,
        ii: usize,
        val: u64,
    },
    Rewrite {
        bi: usize,
        ii: usize,
        op: IrOp,
        args: Vec<ValueId>,
    },
}

impl Pass for InstCombine {
    fn run(&self, func: &mut IrFunction) -> bool {
        let mut consts: HashMap<ValueId, u64> = HashMap::new();
        let mut not_of: HashMap<ValueId, ValueId> = HashMap::new();
        let mut neg_of: HashMap<ValueId, ValueId> = HashMap::new();

        for block in &func.blocks {
            for inst in &block.insts {
                if let Some(dest) = inst.dest {
                    if let IrOp::Const(v) = &inst.op {
                        consts.insert(dest, *v);
                    }
                    if matches!(&inst.op, IrOp::Not) && inst.args.len() == 1 {
                        not_of.insert(dest, inst.args[0]);
                    }
                    if matches!(&inst.op, IrOp::Neg) && inst.args.len() == 1 {
                        neg_of.insert(dest, inst.args[0]);
                    }
                }
            }
        }

        let mut pending: Vec<Pending> = Vec::new();

        for bi in 0..func.blocks.len() {
            for ii in 0..func.blocks[bi].insts.len() {
                let inst = &func.blocks[bi].insts[ii];
                let dest = match inst.dest {
                    Some(d) => d,
                    None => continue,
                };

                let p = match &inst.op {
                    IrOp::Add if inst.args.len() == 2 => {
                        let a = inst.args[0];
                        let b = inst.args[1];
                        if consts.get(&b) == Some(&0) {
                            Some(Pending::Replace { old: dest, new: a })
                        } else if consts.get(&a) == Some(&0) {
                            Some(Pending::Replace { old: dest, new: b })
                        } else if let Some(&y) = neg_of.get(&b) {
                            Some(Pending::Rewrite {
                                bi,
                                ii,
                                op: IrOp::Sub,
                                args: vec![a, y],
                            })
                        } else if let Some(&y) = neg_of.get(&a) {
                            Some(Pending::Rewrite {
                                bi,
                                ii,
                                op: IrOp::Sub,
                                args: vec![b, y],
                            })
                        } else {
                            None
                        }
                    }

                    IrOp::Sub if inst.args.len() == 2 => {
                        let a = inst.args[0];
                        let b = inst.args[1];
                        if consts.get(&b) == Some(&0) {
                            Some(Pending::Replace { old: dest, new: a })
                        } else if a == b {
                            Some(Pending::Const { bi, ii, val: 0 })
                        } else {
                            None
                        }
                    }

                    IrOp::Mul if inst.args.len() == 2 => {
                        let a = inst.args[0];
                        let b = inst.args[1];
                        if consts.get(&b) == Some(&1) {
                            Some(Pending::Replace { old: dest, new: a })
                        } else if consts.get(&a) == Some(&1) {
                            Some(Pending::Replace { old: dest, new: b })
                        } else {
                            None
                        }
                    }

                    IrOp::And if inst.args.len() == 2 && inst.args[0] == inst.args[1] => {
                        Some(Pending::Replace {
                            old: dest,
                            new: inst.args[0],
                        })
                    }

                    IrOp::Or if inst.args.len() == 2 && inst.args[0] == inst.args[1] => {
                        Some(Pending::Replace {
                            old: dest,
                            new: inst.args[0],
                        })
                    }

                    IrOp::Xor if inst.args.len() == 2 && inst.args[0] == inst.args[1] => {
                        Some(Pending::Const { bi, ii, val: 0 })
                    }

                    IrOp::Shl | IrOp::Shr | IrOp::Sar
                        if inst.args.len() == 2 && consts.get(&inst.args[1]) == Some(&0) =>
                    {
                        Some(Pending::Replace {
                            old: dest,
                            new: inst.args[0],
                        })
                    }

                    IrOp::Not if inst.args.len() == 1 => {
                        not_of.get(&inst.args[0]).map(|&inner| Pending::Replace {
                            old: dest,
                            new: inner,
                        })
                    }

                    _ => None,
                };

                if let Some(p) = p {
                    pending.push(p);
                }
            }
        }

        let changed = !pending.is_empty();
        for p in pending {
            match p {
                Pending::Replace { old, new } => replace_uses(func, old, new),
                Pending::Const { bi, ii, val } => {
                    func.blocks[bi].insts[ii].op = IrOp::Const(val);
                    func.blocks[bi].insts[ii].args.clear();
                }
                Pending::Rewrite { bi, ii, op, args } => {
                    func.blocks[bi].insts[ii].op = op;
                    func.blocks[bi].insts[ii].args = args;
                }
            }
        }

        changed
    }
}
