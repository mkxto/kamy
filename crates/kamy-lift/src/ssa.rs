use kamy_core::ir::*;

use crate::LiftResult;

const NUM_REGS: usize = 38;

fn reg_type(r: usize) -> IrType {
    match r {
        0..=15 => IrType::I64,
        16..=31 => IrType::I128,
        32..=37 => IrType::I8,
        _ => unreachable!(),
    }
}

fn replace_in_block(block: &mut IrBlock, old: ValueId, new: ValueId) {
    for phi in &mut block.phis {
        for (_, v) in &mut phi.args {
            if *v == old {
                *v = new;
            }
        }
    }
    for inst in &mut block.insts {
        for v in &mut inst.args {
            if *v == old {
                *v = new;
            }
        }
    }
    if let IrTerminator::Branch { cond, .. } = &mut block.term {
        if *cond == old {
            *cond = new;
        }
    }
}

pub fn construct_ssa(result: &mut LiftResult) {
    let num_blocks = result.func.blocks.len();

    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); num_blocks];
    for (bi, block) in result.func.blocks.iter().enumerate() {
        match &block.term {
            IrTerminator::Jump(target) => {
                preds[target.0 as usize].push(bi);
            }
            IrTerminator::Branch {
                taken, not_taken, ..
            } => {
                preds[taken.0 as usize].push(bi);
                preds[not_taken.0 as usize].push(bi);
            }
            IrTerminator::Ret | IrTerminator::Unreachable => {}
        }
    }

    for (bi, block_preds) in preds.iter().enumerate().take(num_blocks) {
        let num_preds = block_preds.len();
        if num_preds == 0 {
            continue;
        }

        if num_preds == 1 {
            let pred_idx = block_preds[0];
            for r in 0..NUM_REGS {
                let old = result.block_entry[bi][r];
                let new = result.block_exit[pred_idx][r];
                if old != new {
                    replace_in_block(&mut result.func.blocks[bi], old, new);
                }
            }
        } else {
            for r in 0..NUM_REGS {
                let old = result.block_entry[bi][r];
                let first_val = result.block_exit[block_preds[0]][r];
                let all_same = block_preds
                    .iter()
                    .all(|&p| result.block_exit[p][r] == first_val);

                if all_same {
                    if old != first_val {
                        replace_in_block(&mut result.func.blocks[bi], old, first_val);
                    }
                } else {
                    let new_vid = result.func.alloc_value();
                    let ty = reg_type(r);
                    let phi_args: Vec<(BlockId, ValueId)> = block_preds
                        .iter()
                        .map(|&p| (result.func.blocks[p].id, result.block_exit[p][r]))
                        .collect();
                    result.func.blocks[bi].phis.push(Phi {
                        dest: new_vid,
                        ty,
                        args: phi_args,
                    });
                    if old != new_vid {
                        replace_in_block(&mut result.func.blocks[bi], old, new_vid);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn undef_inst(dest: ValueId, ty: IrType) -> Inst {
        Inst {
            dest: Some(dest),
            op: IrOp::Undef,
            args: vec![],
            ty,
        }
    }

    fn make_entry(regs: &[ValueId; 38]) -> [ValueId; 38] {
        *regs
    }

    #[test]
    fn single_predecessor_replaces_undef() {
        let entry_gpr0 = ValueId(0);
        let succ_entry_gpr0 = ValueId(1);
        let add_result = ValueId(2);
        let const5 = ValueId(3);

        let mut block_entry_0 = [ValueId(100); 38];
        block_entry_0[0] = entry_gpr0;

        let mut block_exit_0 = block_entry_0;
        block_exit_0[0] = add_result;

        let mut block_entry_1 = [ValueId(200); 38];
        block_entry_1[0] = succ_entry_gpr0;

        let block_exit_1 = block_entry_1;

        let blocks = vec![
            IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![
                    undef_inst(entry_gpr0, IrType::I64),
                    Inst {
                        dest: Some(const5),
                        op: IrOp::Const(5),
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: Some(add_result),
                        op: IrOp::Add,
                        args: vec![entry_gpr0, const5],
                        ty: IrType::I64,
                    },
                ],
                term: IrTerminator::Jump(BlockId(1)),
            },
            IrBlock {
                id: BlockId(1),
                phis: vec![],
                insts: vec![
                    undef_inst(succ_entry_gpr0, IrType::I64),
                    Inst {
                        dest: Some(ValueId(4)),
                        op: IrOp::Add,
                        args: vec![succ_entry_gpr0, succ_entry_gpr0],
                        ty: IrType::I64,
                    },
                ],
                term: IrTerminator::Ret,
            },
        ];

        let mut result = LiftResult {
            func: IrFunction {
                entry: BlockId(0),
                blocks,
                next_value: 5,
            },
            block_entry: vec![make_entry(&block_entry_0), make_entry(&block_entry_1)],
            block_exit: vec![block_exit_0, block_exit_1],
            rsp_chain: std::collections::HashSet::new(),
        };

        construct_ssa(&mut result);

        for inst in &result.func.blocks[1].insts {
            for arg in &inst.args {
                assert_ne!(
                    *arg, succ_entry_gpr0,
                    "Undef ValueId should have been replaced"
                );
            }
        }

        let add_inst = &result.func.blocks[1].insts[1];
        assert_eq!(add_inst.args[0], add_result);
        assert_eq!(add_inst.args[1], add_result);
    }

    #[test]
    fn diamond_inserts_phi_for_divergent_values() {
        let mut next_val = 0u32;
        let mut alloc = || {
            let v = ValueId(next_val);
            next_val += 1;
            v
        };

        let a_entry_gpr0 = alloc();
        let b_entry_gpr0 = alloc();
        let c_entry_gpr0 = alloc();
        let d_entry_gpr0 = alloc();
        let b_add_result = alloc();
        let c_sub_result = alloc();
        let const1 = alloc();
        let const2 = alloc();
        let branch_cond = alloc();

        let mut a_entry = [alloc(); 38];
        a_entry[0] = a_entry_gpr0;

        let mut a_exit = a_entry;
        a_exit[0] = a_entry_gpr0;

        let mut b_entry = [alloc(); 38];
        b_entry[0] = b_entry_gpr0;
        let mut b_exit = b_entry;
        b_exit[0] = b_add_result;

        let mut c_entry = [alloc(); 38];
        c_entry[0] = c_entry_gpr0;
        let mut c_exit = c_entry;
        c_exit[0] = c_sub_result;

        let mut d_entry = [alloc(); 38];
        d_entry[0] = d_entry_gpr0;
        let d_exit = d_entry;

        let blocks = vec![
            IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![
                    undef_inst(a_entry_gpr0, IrType::I64),
                    Inst {
                        dest: Some(branch_cond),
                        op: IrOp::Const(1),
                        args: vec![],
                        ty: IrType::I8,
                    },
                ],
                term: IrTerminator::Branch {
                    cond: branch_cond,
                    taken: BlockId(1),
                    not_taken: BlockId(2),
                },
            },
            IrBlock {
                id: BlockId(1),
                phis: vec![],
                insts: vec![
                    undef_inst(b_entry_gpr0, IrType::I64),
                    Inst {
                        dest: Some(const1),
                        op: IrOp::Const(1),
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: Some(b_add_result),
                        op: IrOp::Add,
                        args: vec![b_entry_gpr0, const1],
                        ty: IrType::I64,
                    },
                ],
                term: IrTerminator::Jump(BlockId(3)),
            },
            IrBlock {
                id: BlockId(2),
                phis: vec![],
                insts: vec![
                    undef_inst(c_entry_gpr0, IrType::I64),
                    Inst {
                        dest: Some(const2),
                        op: IrOp::Const(2),
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: Some(c_sub_result),
                        op: IrOp::Sub,
                        args: vec![c_entry_gpr0, const2],
                        ty: IrType::I64,
                    },
                ],
                term: IrTerminator::Jump(BlockId(3)),
            },
            IrBlock {
                id: BlockId(3),
                phis: vec![],
                insts: vec![
                    undef_inst(d_entry_gpr0, IrType::I64),
                    Inst {
                        dest: Some(alloc()),
                        op: IrOp::Add,
                        args: vec![d_entry_gpr0, d_entry_gpr0],
                        ty: IrType::I64,
                    },
                ],
                term: IrTerminator::Ret,
            },
        ];

        let mut result = LiftResult {
            func: IrFunction {
                entry: BlockId(0),
                blocks,
                next_value: next_val,
            },
            block_entry: vec![
                make_entry(&a_entry),
                make_entry(&b_entry),
                make_entry(&c_entry),
                make_entry(&d_entry),
            ],
            block_exit: vec![a_exit, b_exit, c_exit, d_exit],
            rsp_chain: std::collections::HashSet::new(),
        };

        construct_ssa(&mut result);

        let block_d = &result.func.blocks[3];

        let gpr0_phi = block_d.phis.iter().find(|phi| {
            phi.args.iter().any(|&(bid, vid)| {
                (bid == BlockId(1) && vid == b_add_result)
                    || (bid == BlockId(2) && vid == c_sub_result)
            })
        });
        assert!(
            gpr0_phi.is_some(),
            "Block D should have a phi for GPR[0] with B and C exit values"
        );

        let phi = gpr0_phi.unwrap();
        assert_eq!(phi.args.len(), 2);
        assert_eq!(phi.ty, IrType::I64);

        let phi_dest = phi.dest;
        let add_inst = &block_d.insts[1];
        assert_eq!(add_inst.args[0], phi_dest);
        assert_eq!(add_inst.args[1], phi_dest);

        for inst in &block_d.insts {
            for arg in &inst.args {
                assert_ne!(
                    *arg, d_entry_gpr0,
                    "Undef ValueId should have been replaced in block D"
                );
            }
        }
    }
}
