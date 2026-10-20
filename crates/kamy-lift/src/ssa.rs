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
            IrTerminator::Ret | IrTerminator::Tail { .. } | IrTerminator::Unreachable => {}
        }
    }

    let entry_idx = result
        .func
        .blocks
        .iter()
        .position(|b| b.id == result.func.entry)
        .unwrap_or(0);
    let order = reverse_post_order(&result.func, entry_idx, num_blocks);

    for bi in order {
        let block_preds = &preds[bi];
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
                    resolve_entry(&mut result.func, &mut result.reg_pins, bi, old, new);
                    propagate_exit(&mut result.block_exit[bi], old, new);
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
                        resolve_entry(&mut result.func, &mut result.reg_pins, bi, old, first_val);
                        propagate_exit(&mut result.block_exit[bi], old, first_val);
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
                    // The back-edge arg may reference `old`; threading it here turns
                    // a loop-carried pass-through into a proper self-referential phi.
                    resolve_entry(&mut result.func, &mut result.reg_pins, bi, old, new_vid);
                    propagate_exit(&mut result.block_exit[bi], old, new_vid);
                }
            }
        }
    }
}

/// After a block-entry value is resolved to its incoming definition, any register
/// that left the block unchanged (its exit still names the old entry undef) must
/// carry the resolved value forward so successor blocks wire phis to a live def.
fn propagate_exit(exit: &mut [ValueId; 38], old: ValueId, new: ValueId) {
    for e in exit.iter_mut() {
        if *e == old {
            *e = new;
        }
    }
}

/// Resolve a block-entry placeholder to its incoming definition. Besides rewriting
/// uses inside the resolving block, the placeholder may already survive as a
/// back-edge phi argument in an earlier-processed loop header: that header's phi
/// lives in a *different* block, so its argument must be rewritten here too. Entry
/// placeholders are unique per block/register, so a global phi-arg rewrite only
/// touches genuine references (issue #24).
///
/// A placeholder carries a `reg_pins` entry when a lift-time consumer required it
/// in a fixed register — a call argument bound to its ABI register, or a
/// NativeInline read. For a cross-block value that binding lives on the
/// placeholder, not on the incoming definition, so transfer it to `new` or the
/// pin is orphaned and the allocator is free to place the argument off its ABI
/// register (issue #23: `FlsFree(dwTlsIndex)` received `-1`). Keep any pin `new`
/// already has: a distinct required register for the same value is a real
/// conflict the allocator resolves (reject), never silently overwritten.
fn resolve_entry(
    func: &mut IrFunction,
    reg_pins: &mut std::collections::HashMap<ValueId, PhysReg>,
    bi: usize,
    old: ValueId,
    new: ValueId,
) {
    if let Some(&p) = reg_pins.get(&old) {
        reg_pins.entry(new).or_insert(p);
    }
    replace_in_block(&mut func.blocks[bi], old, new);
    for (j, block) in func.blocks.iter_mut().enumerate() {
        if j == bi {
            continue;
        }
        for phi in &mut block.phis {
            for (_, v) in &mut phi.args {
                if *v == old {
                    *v = new;
                }
            }
        }
    }
}

fn succ_indices(block: &IrBlock) -> Vec<usize> {
    match &block.term {
        IrTerminator::Jump(t) => vec![t.0 as usize],
        IrTerminator::Branch {
            taken, not_taken, ..
        } => vec![taken.0 as usize, not_taken.0 as usize],
        IrTerminator::Ret | IrTerminator::Tail { .. } | IrTerminator::Unreachable => vec![],
    }
}

/// Reverse post-order from the entry so a block's non-back-edge predecessors are
/// resolved before it; back edges are handled by self-referential phis. Unreachable
/// blocks are appended last.
fn reverse_post_order(func: &IrFunction, entry: usize, num_blocks: usize) -> Vec<usize> {
    let mut visited = vec![false; num_blocks];
    let mut succ_cursor = vec![0usize; num_blocks];
    let mut stack: Vec<usize> = Vec::new();
    let mut post: Vec<usize> = Vec::with_capacity(num_blocks);

    if entry < num_blocks {
        visited[entry] = true;
        stack.push(entry);
    }
    while let Some(&bi) = stack.last() {
        let succ = succ_indices(&func.blocks[bi]);
        if succ_cursor[bi] < succ.len() {
            let s = succ[succ_cursor[bi]];
            succ_cursor[bi] += 1;
            if s < num_blocks && !visited[s] {
                visited[s] = true;
                stack.push(s);
            }
        } else {
            post.push(bi);
            stack.pop();
        }
    }
    post.reverse();
    for (b, &seen) in visited.iter().enumerate() {
        if !seen {
            post.push(b);
        }
    }
    post
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
            reg_pins: std::collections::HashMap::new(),
            unsupported: false,
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
    fn cross_block_arg_pin_transfers_to_resolved_value() {
        // A call argument pinned to its ABI register in block 1 names that block's
        // RCX entry placeholder; SSA resolves the placeholder to the value defined
        // in block 0. The pin must follow to the resolved value, or the allocator
        // is free to place the argument off RCX (issue #23: FlsFree got -1).
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
                insts: vec![Inst {
                    dest: Some(ValueId(4)),
                    op: IrOp::Call { target: 0x1000 },
                    args: vec![succ_entry_gpr0],
                    ty: IrType::I64,
                }],
                term: IrTerminator::Ret,
            },
        ];

        let mut reg_pins = std::collections::HashMap::new();
        reg_pins.insert(succ_entry_gpr0, PhysReg::Gpr(Gpr::Rcx));
        let mut result = LiftResult {
            func: IrFunction {
                entry: BlockId(0),
                blocks,
                next_value: 5,
            },
            block_entry: vec![make_entry(&block_entry_0), make_entry(&block_entry_1)],
            block_exit: vec![block_exit_0, block_exit_1],
            rsp_chain: std::collections::HashSet::new(),
            reg_pins,
            unsupported: false,
        };

        construct_ssa(&mut result);

        assert_eq!(result.func.blocks[1].insts[0].args[0], add_result);
        assert_eq!(
            result.reg_pins.get(&add_result),
            Some(&PhysReg::Gpr(Gpr::Rcx)),
            "the ABI-register pin must transfer to the resolved cross-block value"
        );
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
            reg_pins: std::collections::HashMap::new(),
            unsupported: false,
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

    // Issue #24: a loop-invariant register carried through a separate body block
    // must not leave the body's entry placeholder (an Undef) as the header phi's
    // back-edge argument. Models the strnlen-shaped loop from the issue.
    #[test]
    fn loop_invariant_reg_threads_back_edge_phi() {
        let mut next_val = 0u32;
        let mut alloc = || {
            let v = ValueId(next_val);
            next_val += 1;
            v
        };

        let b0_ptr = alloc();
        let b1_ptr = alloc();
        let b2_ptr = alloc();
        let b3_ptr = alloc();
        let header_load = alloc();
        let header_cond = alloc();
        let body_load = alloc();

        let mut b0_entry = [alloc(); 38];
        b0_entry[0] = b0_ptr;
        let b0_exit = b0_entry;

        let mut b1_entry = [alloc(); 38];
        b1_entry[0] = b1_ptr;
        let b1_exit = b1_entry;

        let mut b2_entry = [alloc(); 38];
        b2_entry[0] = b2_ptr;
        let b2_exit = b2_entry;

        let mut b3_entry = [alloc(); 38];
        b3_entry[0] = b3_ptr;
        let b3_exit = b3_entry;

        let blocks = vec![
            IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![undef_inst(b0_ptr, IrType::I64)],
                term: IrTerminator::Jump(BlockId(1)),
            },
            IrBlock {
                id: BlockId(1),
                phis: vec![],
                insts: vec![
                    undef_inst(b1_ptr, IrType::I64),
                    Inst {
                        dest: Some(header_load),
                        op: IrOp::Add,
                        args: vec![b1_ptr, b1_ptr],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: Some(header_cond),
                        op: IrOp::Const(0),
                        args: vec![],
                        ty: IrType::I8,
                    },
                ],
                term: IrTerminator::Branch {
                    cond: header_cond,
                    taken: BlockId(2),
                    not_taken: BlockId(3),
                },
            },
            IrBlock {
                id: BlockId(2),
                phis: vec![],
                insts: vec![
                    undef_inst(b2_ptr, IrType::I64),
                    Inst {
                        dest: Some(body_load),
                        op: IrOp::Add,
                        args: vec![b2_ptr, b2_ptr],
                        ty: IrType::I64,
                    },
                ],
                term: IrTerminator::Jump(BlockId(1)),
            },
            IrBlock {
                id: BlockId(3),
                phis: vec![],
                insts: vec![undef_inst(b3_ptr, IrType::I64)],
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
                make_entry(&b0_entry),
                make_entry(&b1_entry),
                make_entry(&b2_entry),
                make_entry(&b3_entry),
            ],
            block_exit: vec![b0_exit, b1_exit, b2_exit, b3_exit],
            rsp_chain: std::collections::HashSet::new(),
            reg_pins: std::collections::HashMap::new(),
            unsupported: false,
        };

        construct_ssa(&mut result);

        for block in &result.func.blocks {
            for phi in &block.phis {
                for &(_, v) in &phi.args {
                    assert_ne!(
                        v, b2_ptr,
                        "body entry placeholder leaked into a phi back-edge arg"
                    );
                }
            }
        }

        let header_phi = result.func.blocks[1]
            .phis
            .iter()
            .find(|phi| {
                phi.args
                    .iter()
                    .any(|&(bid, v)| bid == BlockId(0) && v == b0_ptr)
            })
            .expect("header should carry a phi for the loop-invariant pointer");

        let back_arg = header_phi
            .args
            .iter()
            .find(|&&(bid, _)| bid == BlockId(2))
            .map(|&(_, v)| v)
            .expect("header phi must have a back-edge argument from the body");
        assert_eq!(
            back_arg, header_phi.dest,
            "loop-invariant back-edge arg must be the self-referential phi, not Undef"
        );
    }
}
