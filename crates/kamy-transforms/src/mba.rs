use std::collections::HashSet;

use kamy_core::ir::{Inst, IrFunction, IrOp, IrType, ValueId};
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};

pub struct MbaPass {
    pub config: MbaConfig,
    pub seed: u64,
}

pub struct MbaConfig {
    pub iterations: u32,
    pub probability: u8,
    pub semantics: MbaSemantics,
    pub bitwidths: MbaBitwidths,
}

#[derive(Default)]
pub struct MbaSemantics {
    pub add: bool,
    pub sub: bool,
    pub xor: bool,
}

#[derive(Default)]
pub struct MbaBitwidths {
    pub bit8: bool,
    pub bit16: bool,
    pub bit32: bool,
    pub bit64: bool,
}

impl MbaBitwidths {
    fn matches(&self, ty: IrType) -> bool {
        match ty {
            IrType::I8 => self.bit8,
            IrType::I16 => self.bit16,
            IrType::I32 => self.bit32,
            IrType::I64 => self.bit64,
            IrType::I128 => false,
        }
    }
}

enum Expansion {
    Add,
    Sub,
    Xor,
}

impl super::Pass for MbaPass {
    fn run(&self, func: &mut IrFunction) -> bool {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let mut changed = false;
        let mut expanded: HashSet<ValueId> = HashSet::new();

        for _ in 0..self.config.iterations {
            for bi in 0..func.blocks.len() {
                let mut i = 0;
                while i < func.blocks[bi].insts.len() {
                    if let Some(d) = func.blocks[bi].insts[i].dest {
                        if expanded.contains(&d) {
                            i += 1;
                            continue;
                        }
                    }

                    let expansion = match func.blocks[bi].insts[i].op {
                        IrOp::Add if self.config.semantics.add => Expansion::Add,
                        IrOp::Sub if self.config.semantics.sub => Expansion::Sub,
                        IrOp::Xor if self.config.semantics.xor => Expansion::Xor,
                        _ => {
                            i += 1;
                            continue;
                        }
                    };

                    let ty = func.blocks[bi].insts[i].ty;
                    if !self.config.bitwidths.matches(ty) {
                        i += 1;
                        continue;
                    }

                    if rng.next_u32() % 100 >= self.config.probability as u32 {
                        i += 1;
                        continue;
                    }

                    let x = func.blocks[bi].insts[i].args[0];
                    let y = func.blocks[bi].insts[i].args[1];
                    let dest = func.blocks[bi].insts[i].dest.unwrap();

                    match expansion {
                        Expansion::Add => {
                            // x+y = (x^y) + 2*(x&y)
                            let v_xor = func.alloc_value();
                            let v_and = func.alloc_value();
                            let v_const = func.alloc_value();
                            let v_shl = func.alloc_value();

                            let prefix = vec![
                                Inst {
                                    dest: Some(v_xor),
                                    op: IrOp::Xor,
                                    args: vec![x, y],
                                    ty,
                                },
                                Inst {
                                    dest: Some(v_and),
                                    op: IrOp::And,
                                    args: vec![x, y],
                                    ty,
                                },
                                Inst {
                                    dest: Some(v_const),
                                    op: IrOp::Const(1),
                                    args: vec![],
                                    ty,
                                },
                                Inst {
                                    dest: Some(v_shl),
                                    op: IrOp::Shl,
                                    args: vec![v_and, v_const],
                                    ty,
                                },
                            ];
                            func.blocks[bi].insts[i].args = vec![v_xor, v_shl];
                            let n = prefix.len();
                            for (j, inst) in prefix.into_iter().enumerate() {
                                func.blocks[bi].insts.insert(i + j, inst);
                            }
                            i += n + 1;
                            changed = true;
                        }
                        Expansion::Sub => {
                            // x-y = x + (~y + 1)
                            let v_not = func.alloc_value();
                            let v_const = func.alloc_value();
                            let v_inner = func.alloc_value();

                            expanded.insert(v_inner);
                            expanded.insert(dest);

                            let prefix = vec![
                                Inst {
                                    dest: Some(v_not),
                                    op: IrOp::Not,
                                    args: vec![y],
                                    ty,
                                },
                                Inst {
                                    dest: Some(v_const),
                                    op: IrOp::Const(1),
                                    args: vec![],
                                    ty,
                                },
                                Inst {
                                    dest: Some(v_inner),
                                    op: IrOp::Add,
                                    args: vec![v_not, v_const],
                                    ty,
                                },
                            ];
                            func.blocks[bi].insts[i].op = IrOp::Add;
                            func.blocks[bi].insts[i].args = vec![x, v_inner];
                            let n = prefix.len();
                            for (j, inst) in prefix.into_iter().enumerate() {
                                func.blocks[bi].insts.insert(i + j, inst);
                            }
                            i += n + 1;
                            changed = true;
                        }
                        Expansion::Xor => {
                            // x^y = (x & ~y) | (~x & y)
                            let v_not_y = func.alloc_value();
                            let v_not_x = func.alloc_value();
                            let v_and1 = func.alloc_value();
                            let v_and2 = func.alloc_value();

                            let prefix = vec![
                                Inst {
                                    dest: Some(v_not_y),
                                    op: IrOp::Not,
                                    args: vec![y],
                                    ty,
                                },
                                Inst {
                                    dest: Some(v_not_x),
                                    op: IrOp::Not,
                                    args: vec![x],
                                    ty,
                                },
                                Inst {
                                    dest: Some(v_and1),
                                    op: IrOp::And,
                                    args: vec![x, v_not_y],
                                    ty,
                                },
                                Inst {
                                    dest: Some(v_and2),
                                    op: IrOp::And,
                                    args: vec![v_not_x, y],
                                    ty,
                                },
                            ];
                            func.blocks[bi].insts[i].op = IrOp::Or;
                            func.blocks[bi].insts[i].args = vec![v_and1, v_and2];
                            let n = prefix.len();
                            for (j, inst) in prefix.into_iter().enumerate() {
                                func.blocks[bi].insts.insert(i + j, inst);
                            }
                            i += n + 1;
                            changed = true;
                        }
                    }
                }
            }
        }

        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pass;
    use kamy_core::ir::{BlockId, IrBlock, IrTerminator};

    fn all_enabled() -> MbaConfig {
        MbaConfig {
            iterations: 1,
            probability: 100,
            semantics: MbaSemantics {
                add: true,
                sub: true,
                xor: true,
            },
            bitwidths: MbaBitwidths {
                bit8: true,
                bit16: true,
                bit32: true,
                bit64: true,
            },
        }
    }

    fn add_func() -> (IrFunction, ValueId, ValueId, ValueId) {
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![],
                term: IrTerminator::Ret,
            }],
            next_value: 0,
        };
        let v1 = func.alloc_value();
        let v2 = func.alloc_value();
        let v3 = func.alloc_value();
        func.blocks[0].insts.push(Inst {
            dest: Some(v1),
            op: IrOp::Const(10),
            args: vec![],
            ty: IrType::I32,
        });
        func.blocks[0].insts.push(Inst {
            dest: Some(v2),
            op: IrOp::Const(20),
            args: vec![],
            ty: IrType::I32,
        });
        func.blocks[0].insts.push(Inst {
            dest: Some(v3),
            op: IrOp::Add,
            args: vec![v1, v2],
            ty: IrType::I32,
        });
        (func, v1, v2, v3)
    }

    #[test]
    fn expands_add() {
        let (mut func, v1, v2, v3) = add_func();
        let pass = MbaPass {
            config: all_enabled(),
            seed: 0,
        };
        assert!(pass.run(&mut func));

        let insts = &func.blocks[0].insts;
        assert_eq!(insts.len(), 7);
        assert!(matches!(insts[0].op, IrOp::Const(10)));
        assert!(matches!(insts[1].op, IrOp::Const(20)));
        assert!(matches!(insts[2].op, IrOp::Xor));
        assert_eq!(insts[2].args, vec![v1, v2]);
        assert!(matches!(insts[3].op, IrOp::And));
        assert_eq!(insts[3].args, vec![v1, v2]);
        assert!(matches!(insts[4].op, IrOp::Const(1)));
        assert!(matches!(insts[5].op, IrOp::Shl));
        assert!(matches!(insts[6].op, IrOp::Add));
        assert_eq!(insts[6].dest, Some(v3));
    }

    #[test]
    fn probability_zero_no_change() {
        let (mut func, _, _, _) = add_func();
        let config = MbaConfig {
            probability: 0,
            ..all_enabled()
        };
        let pass = MbaPass { config, seed: 0 };
        assert!(!pass.run(&mut func));
        assert_eq!(func.blocks[0].insts.len(), 3);
    }
}
