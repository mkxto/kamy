use kamy_core::ir::*;
use kamy_core::{FrameAnalysis, RejectionReason};

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

fn scalar_frame_operands(inst: &Inst, analysis: &FrameAnalysis) -> bool {
    // An unknown operand can alias a relocated frame object, so both sides must share coordinates.
    matches!(
        inst.op,
        IrOp::Sub | IrOp::BorrowSub | IrOp::OverflowSub | IrOp::AuxBorrowSub
    ) && inst.args.len() == 2
        && inst.args.iter().all(|value| {
            analysis.offsets.contains_key(value) || analysis.pointer_bounds.contains_key(value)
        })
}

pub fn construct_ssa(result: &mut LiftResult) -> Result<(), RejectionReason> {
    construct_graph(result)?;
    let analysis = FrameAnalysis::analyze(&result.func, &result.rsp_chain, &result.reg_pins)?;
    let mut next_value = result.func.next_value;
    for block in &mut result.func.blocks {
        for inst in &mut block.insts {
            if let Some(delta) = inst.dest.and_then(|value| analysis.offsets.get(&value)) {
                inst.op = IrOp::FrameAddress(*delta);
                inst.args.clear();
            } else if let Some(indexed) = inst
                .dest
                .and_then(|value| analysis.indexed_offsets.get(&value))
            {
                inst.op = IrOp::FrameIndex {
                    displacement: indexed.displacement,
                    subtract: indexed.subtract,
                    bounds: indexed.bounds,
                };
                inst.args.clear();
                inst.args.extend([indexed.base, indexed.index]);
            } else if let Some((source, offset)) = inst
                .dest
                .and_then(|value| analysis.derived_offsets.get(&value))
            {
                inst.op = IrOp::FrameOffset(*offset);
                inst.args.clear();
                inst.args.push(*source);
            }
        }
        let alias_count = block
            .phis
            .iter()
            .filter(|phi| analysis.offsets.contains_key(&phi.dest))
            .count();
        if alias_count != 0 {
            let mut insts = Vec::with_capacity(alias_count + block.insts.len());
            insts.extend(block.phis.iter().filter_map(|phi| {
                analysis.offsets.get(&phi.dest).map(|delta| Inst {
                    dest: Some(phi.dest),
                    op: IrOp::FrameAddress(*delta),
                    args: vec![],
                    ty: IrType::I64,
                })
            }));
            block
                .phis
                .retain(|phi| !analysis.offsets.contains_key(&phi.dest));
            insts.append(&mut block.insts);
            block.insts = insts;
        }
        let induction_count = block
            .phis
            .iter()
            .filter(|phi| analysis.induction_bounds.contains_key(&phi.dest))
            .count();
        if induction_count != 0 {
            let zero = ValueId(next_value);
            next_value = next_value
                .checked_add(1)
                .ok_or(RejectionReason::FrameOverflow)?;
            let mut insts = Vec::with_capacity(block.insts.len() + induction_count + 1);
            insts.push(Inst {
                dest: Some(zero),
                op: IrOp::Const(0),
                args: vec![],
                ty: IrType::I64,
            });
            for phi in &mut block.phis {
                let Some(&bounds) = analysis.induction_bounds.get(&phi.dest) else {
                    continue;
                };
                let dest = phi.dest;
                phi.dest = ValueId(next_value);
                next_value = next_value
                    .checked_add(1)
                    .ok_or(RejectionReason::FrameOverflow)?;
                insts.push(Inst {
                    dest: Some(dest),
                    op: IrOp::FrameIndex {
                        displacement: 0,
                        subtract: false,
                        bounds,
                    },
                    args: vec![phi.dest, zero],
                    ty: IrType::I64,
                });
            }
            insts.append(&mut block.insts);
            block.insts = insts;
        }
    }
    for block in &mut result.func.blocks {
        let extra = block
            .insts
            .iter()
            .filter(|inst| scalar_frame_operands(inst, &analysis))
            .flat_map(|inst| &inst.args)
            .count();
        if extra == 0 {
            continue;
        }
        let mut insts = Vec::with_capacity(block.insts.len() + extra);
        let mut logical_values = std::collections::HashMap::new();
        for mut inst in std::mem::take(&mut block.insts) {
            if scalar_frame_operands(&inst, &analysis) {
                for value in &mut inst.args {
                    let logical = if let Some(&logical) = logical_values.get(value) {
                        logical
                    } else {
                        let logical = ValueId(next_value);
                        next_value = next_value
                            .checked_add(1)
                            .ok_or(RejectionReason::FrameOverflow)?;
                        insts.push(Inst {
                            dest: Some(logical),
                            op: IrOp::FrameLogical,
                            args: vec![*value],
                            ty: IrType::I64,
                        });
                        logical_values.insert(*value, logical);
                        logical
                    };
                    *value = logical;
                }
            }
            insts.push(inst);
        }
        block.insts = insts;
    }
    result.func.next_value = next_value;
    if analysis.original_size != 0 {
        let delta = -i64::from(analysis.original_size);
        let entry = result.func.block(result.func.entry);
        let rooted = entry.insts.windows(2).any(|pair| {
            matches!(pair[0].op, IrOp::FrameAddress(offset) if offset == delta)
                && matches!(pair[1].op, IrOp::Use)
                && pair[1].args.as_slice() == pair[0].dest.as_slice()
        });
        if !rooted {
            result
                .func
                .next_value
                .checked_add(2)
                .ok_or(RejectionReason::FrameOverflow)?;
            let value = result.func.alloc_value();
            result.func.block_mut(result.func.entry).insts.splice(
                0..0,
                [
                    Inst {
                        dest: Some(value),
                        op: IrOp::FrameAddress(delta),
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: None,
                        op: IrOp::Use,
                        args: vec![value],
                        ty: IrType::I64,
                    },
                ],
            );
        }
    }
    Ok(())
}

fn construct_graph(result: &mut LiftResult) -> Result<(), RejectionReason> {
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
            IrTerminator::Ret
            | IrTerminator::NoReturn
            | IrTerminator::Tail { .. }
            | IrTerminator::Unreachable => {}
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
                    resolve_entry(result, bi, old, new);
                    result.block_entry[bi][r] = new;
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
                        resolve_entry(result, bi, old, first_val);
                        result.block_entry[bi][r] = first_val;
                        propagate_exit(&mut result.block_exit[bi], old, first_val);
                    }
                } else {
                    result
                        .func
                        .next_value
                        .checked_add(1)
                        .ok_or(RejectionReason::FrameOverflow)?;
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
                    resolve_entry(result, bi, old, new_vid);
                    result.block_entry[bi][r] = new_vid;
                    propagate_exit(&mut result.block_exit[bi], old, new_vid);
                }
            }
        }
    }
    Ok(())
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
/// Physical boundary constraints and logical RSP identity follow the resolved
/// definition; dead placeholders must not remain frame-analysis seeds.
fn resolve_entry(result: &mut LiftResult, bi: usize, old: ValueId, new: ValueId) {
    if let Some(p) = result.reg_pins.remove(&old) {
        result.reg_pins.entry(new).or_insert(p);
    }
    if result.rsp_chain.remove(&old) {
        result.rsp_chain.insert(new);
    }
    replace_in_block(&mut result.func.blocks[bi], old, new);
    for (j, block) in result.func.blocks.iter_mut().enumerate() {
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
        IrTerminator::Ret
        | IrTerminator::NoReturn
        | IrTerminator::Tail { .. }
        | IrTerminator::Unreachable => vec![],
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

        construct_graph(&mut result).unwrap();

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
                    op: IrOp::Call {
                        target: kamy_core::Reference {
                            source: kamy_core::SymbolId::Host {
                                rva: kamy_core::Rva::ZERO,
                            },
                            offset: 0,
                            expression: kamy_core::SymbolicExpression::symbol(
                                kamy_core::SymbolId::Host {
                                    rva: kamy_core::Rva::new(0x1000),
                                },
                            ),
                            field: kamy_core::LinkField::Relative32 { bias: 0 },
                            origin: kamy_core::ReferenceOrigin::HostAnalysis,
                        },
                        clobbers: kamy_core::ir::win64_volatiles(),
                    },
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

        construct_graph(&mut result).unwrap();

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

        construct_graph(&mut result).unwrap();

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

        construct_graph(&mut result).unwrap();

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

    #[test]
    fn logical_rsp_phi_is_canonical_and_extent_survives_dce() {
        let rsp = Gpr::Rsp.index();
        let mut entry = [ValueId(100); 38];
        entry[rsp] = ValueId(0);
        let mut entry_exit = entry;
        entry_exit[rsp] = ValueId(2);
        let mut header = [ValueId(200); 38];
        header[rsp] = ValueId(3);
        let mut header_exit = header;
        header_exit[rsp] = ValueId(5);
        let mut exit = [ValueId(300); 38];
        exit[rsp] = ValueId(7);
        let mut exit_exit = exit;
        exit_exit[rsp] = ValueId(8);
        let inst = |dest, op, args| Inst {
            dest: Some(ValueId(dest)),
            op,
            args,
            ty: IrType::I64,
        };
        let mut result = LiftResult {
            func: IrFunction {
                entry: BlockId(0),
                next_value: 400,
                blocks: vec![
                    IrBlock {
                        id: BlockId(0),
                        phis: vec![],
                        insts: vec![
                            undef_inst(ValueId(0), IrType::I64),
                            inst(1, IrOp::Const(40), vec![]),
                            inst(2, IrOp::Sub, vec![ValueId(0), ValueId(1)]),
                        ],
                        term: IrTerminator::Jump(BlockId(1)),
                    },
                    IrBlock {
                        id: BlockId(1),
                        phis: vec![],
                        insts: vec![
                            undef_inst(ValueId(3), IrType::I64),
                            inst(4, IrOp::Const(0), vec![]),
                            inst(5, IrOp::Add, vec![ValueId(3), ValueId(4)]),
                            inst(6, IrOp::Const(0), vec![]),
                        ],
                        term: IrTerminator::Branch {
                            cond: ValueId(6),
                            taken: BlockId(1),
                            not_taken: BlockId(2),
                        },
                    },
                    IrBlock {
                        id: BlockId(2),
                        phis: vec![],
                        insts: vec![
                            undef_inst(ValueId(7), IrType::I64),
                            inst(8, IrOp::Add, vec![ValueId(7), ValueId(1)]),
                            Inst {
                                dest: None,
                                op: IrOp::Use,
                                args: vec![ValueId(8)],
                                ty: IrType::I64,
                            },
                        ],
                        term: IrTerminator::Ret,
                    },
                ],
            },
            block_entry: vec![entry, header, exit],
            block_exit: vec![entry_exit, header_exit, exit_exit],
            rsp_chain: [0, 2, 3, 5, 7, 8].into_iter().map(ValueId).collect(),
            reg_pins: std::collections::HashMap::new(),
            unsupported: false,
        };
        construct_ssa(&mut result).unwrap();
        let header_rsp = result.block_entry[1][rsp];
        assert!(result.rsp_chain.contains(&header_rsp));
        assert!(!result.rsp_chain.contains(&ValueId(3)));
        assert!(!result.rsp_chain.contains(&ValueId(7)));
        assert!(result.func.blocks[1].insts.iter().any(|inst| {
            inst.dest == Some(header_rsp) && matches!(inst.op, IrOp::FrameAddress(-40))
        }));
        assert!(
            !result.func.blocks[1]
                .phis
                .iter()
                .any(|phi| phi.dest == header_rsp)
        );
        kamy_transforms::optimize(&mut result.func);
        let analysis =
            FrameAnalysis::analyze(&result.func, &result.rsp_chain, &result.reg_pins).unwrap();
        assert_eq!(analysis.original_size, 40);
    }

    #[test]
    fn synthetic_frame_extent_ids_are_checked() {
        for next_value in [u32::MAX - 1, u32::MAX] {
            let make = |extent| {
                let mut insts = vec![Inst {
                    dest: Some(ValueId(0)),
                    op: IrOp::FrameAddress(0),
                    args: vec![],
                    ty: IrType::I64,
                }];
                if extent {
                    insts.push(Inst {
                        dest: Some(ValueId(1)),
                        op: IrOp::FrameAddress(-8),
                        args: vec![],
                        ty: IrType::I64,
                    });
                }
                insts.push(Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![ValueId(0)],
                    ty: IrType::I64,
                });
                LiftResult {
                    func: IrFunction {
                        entry: BlockId(0),
                        next_value,
                        blocks: vec![IrBlock {
                            id: BlockId(0),
                            phis: vec![],
                            insts,
                            term: IrTerminator::Ret,
                        }],
                    },
                    block_entry: vec![[ValueId(0); 38]],
                    block_exit: vec![[ValueId(0); 38]],
                    rsp_chain: [ValueId(0)].into_iter().collect(),
                    reg_pins: std::collections::HashMap::new(),
                    unsupported: false,
                }
            };
            let mut framed = make(true);
            assert_eq!(
                construct_ssa(&mut framed),
                Err(RejectionReason::FrameOverflow)
            );
            let mut frameless = make(false);
            construct_ssa(&mut frameless).unwrap();
            assert_eq!(frameless.func.next_value, next_value);
        }
    }

    #[test]
    fn finite_frame_offsets_survive_mba_without_excluding_data_arithmetic() {
        use kamy_transforms::mba::{MbaBitwidths, MbaConfig, MbaSemantics};

        let inst = |dest, op, args| Inst {
            dest: Some(ValueId(dest)),
            op,
            args,
            ty: IrType::I64,
        };
        let mut result = LiftResult {
            func: IrFunction {
                entry: BlockId(0),
                next_value: 64,
                blocks: vec![
                    IrBlock {
                        id: BlockId(0),
                        phis: vec![],
                        insts: vec![
                            inst(20, IrOp::FrameAddress(0), vec![]),
                            inst(0, IrOp::FrameAddress(-8), vec![]),
                            inst(1, IrOp::FrameAddress(-16), vec![]),
                            inst(2, IrOp::Undef, vec![]),
                            inst(10, IrOp::Undef, vec![]),
                        ],
                        term: IrTerminator::Branch {
                            cond: ValueId(2),
                            taken: BlockId(1),
                            not_taken: BlockId(2),
                        },
                    },
                    IrBlock {
                        id: BlockId(1),
                        phis: vec![],
                        insts: vec![],
                        term: IrTerminator::Jump(BlockId(3)),
                    },
                    IrBlock {
                        id: BlockId(2),
                        phis: vec![],
                        insts: vec![],
                        term: IrTerminator::Jump(BlockId(3)),
                    },
                    IrBlock {
                        id: BlockId(3),
                        phis: vec![Phi {
                            dest: ValueId(3),
                            ty: IrType::I64,
                            args: vec![(BlockId(1), ValueId(0)), (BlockId(2), ValueId(1))],
                        }],
                        insts: vec![
                            inst(4, IrOp::Copy, vec![ValueId(3)]),
                            inst(5, IrOp::Const((-16i64) as u64), vec![]),
                            inst(6, IrOp::Add, vec![ValueId(4), ValueId(5)]),
                            inst(7, IrOp::Load, vec![ValueId(6)]),
                            inst(9, IrOp::Add, vec![ValueId(10), ValueId(5)]),
                            Inst {
                                dest: None,
                                op: IrOp::Use,
                                args: vec![ValueId(7), ValueId(9)],
                                ty: IrType::I64,
                            },
                            Inst {
                                dest: None,
                                op: IrOp::Use,
                                args: vec![ValueId(20)],
                                ty: IrType::I64,
                            },
                        ],
                        term: IrTerminator::Ret,
                    },
                ],
            },
            block_entry: vec![[ValueId(20); 38]; 4],
            block_exit: vec![[ValueId(20); 38]; 4],
            rsp_chain: [ValueId(20)].into_iter().collect(),
            reg_pins: std::collections::HashMap::new(),
            unsupported: false,
        };
        construct_ssa(&mut result).unwrap();
        let pass = kamy_transforms::MbaPass {
            seed: 7,
            config: MbaConfig {
                iterations: 2,
                probability: 100,
                semantics: MbaSemantics {
                    add: true,
                    sub: true,
                    xor: true,
                },
                bitwidths: MbaBitwidths {
                    bit64: true,
                    ..MbaBitwidths::default()
                },
            },
        };
        assert!(pass.run_with_intensity(&mut result.func, 1.0));
        let block = &result.func.blocks[3];
        let address = block
            .insts
            .iter()
            .find(|inst| inst.dest == Some(ValueId(6)))
            .unwrap();
        assert!(matches!(address.op, IrOp::FrameOffset(-16)));
        assert_eq!(address.args, [ValueId(4)]);
        let data = block
            .insts
            .iter()
            .find(|inst| inst.dest == Some(ValueId(9)))
            .unwrap();
        assert_ne!(data.args.as_slice(), &[ValueId(10), ValueId(5)]);
        let analysis =
            FrameAnalysis::analyze(&result.func, &result.rsp_chain, &result.reg_pins).unwrap();
        assert_eq!(analysis.original_size, 40);
        assert_eq!(analysis.derived_offsets[&ValueId(6)], (ValueId(4), -16));
    }

    #[test]
    fn scalar_coordinates_require_a_fully_proved_subtractive_pair() {
        use kamy_transforms::mba::{MbaBitwidths, MbaConfig, MbaSemantics};

        let inst = |dest, op, args| Inst {
            dest: Some(ValueId(dest)),
            ty: if matches!(
                op,
                IrOp::BorrowSub | IrOp::OverflowSub | IrOp::AuxBorrowSub | IrOp::IsZero
            ) {
                IrType::I8
            } else {
                IrType::I64
            },
            op,
            args,
        };
        let mut result = LiftResult {
            func: IrFunction {
                entry: BlockId(0),
                next_value: 32,
                blocks: vec![IrBlock {
                    id: BlockId(0),
                    phis: vec![],
                    insts: vec![
                        inst(0, IrOp::FrameAddress(0), vec![]),
                        inst(1, IrOp::FrameAddress(-8), vec![]),
                        inst(2, IrOp::FrameAddress(16), vec![]),
                        inst(3, IrOp::Undef, vec![]),
                        inst(4, IrOp::Const(8), vec![]),
                        inst(5, IrOp::Sub, vec![ValueId(3), ValueId(1)]),
                        inst(6, IrOp::Sub, vec![ValueId(1), ValueId(3)]),
                        inst(7, IrOp::Sub, vec![ValueId(2), ValueId(1)]),
                        inst(8, IrOp::BorrowSub, vec![ValueId(3), ValueId(1)]),
                        inst(9, IrOp::OverflowSub, vec![ValueId(1), ValueId(3)]),
                        inst(10, IrOp::AuxBorrowSub, vec![ValueId(3), ValueId(1)]),
                        inst(11, IrOp::BorrowSub, vec![ValueId(2), ValueId(1)]),
                        inst(12, IrOp::Sub, vec![ValueId(3), ValueId(4)]),
                        inst(13, IrOp::Sub, vec![ValueId(1), ValueId(4)]),
                        inst(14, IrOp::IsZero, vec![ValueId(1)]),
                        inst(15, IrOp::OverflowSub, vec![ValueId(2), ValueId(1)]),
                        inst(16, IrOp::AuxBorrowSub, vec![ValueId(2), ValueId(1)]),
                        Inst {
                            dest: None,
                            op: IrOp::Use,
                            args: (5..=16).map(ValueId).collect(),
                            ty: IrType::I64,
                        },
                    ],
                    term: IrTerminator::Ret,
                }],
            },
            block_entry: vec![[ValueId(0); 38]],
            block_exit: vec![[ValueId(0); 38]],
            rsp_chain: [ValueId(0)].into_iter().collect(),
            reg_pins: std::collections::HashMap::new(),
            unsupported: false,
        };
        construct_ssa(&mut result).unwrap();
        let block = &result.func.blocks[0];
        let find = |dest| {
            block
                .insts
                .iter()
                .find(|inst| inst.dest == Some(ValueId(dest)))
                .unwrap()
        };
        for (dest, args) in [
            (5, vec![ValueId(3), ValueId(1)]),
            (6, vec![ValueId(1), ValueId(3)]),
            (8, vec![ValueId(3), ValueId(1)]),
            (9, vec![ValueId(1), ValueId(3)]),
            (10, vec![ValueId(3), ValueId(1)]),
            (12, vec![ValueId(3), ValueId(4)]),
            (14, vec![ValueId(1)]),
        ] {
            assert_eq!(find(dest).args, args);
        }
        assert!(matches!(find(13).op, IrOp::FrameAddress(-16)));
        let logical: std::collections::HashMap<_, _> = block
            .insts
            .iter()
            .filter(|inst| matches!(inst.op, IrOp::FrameLogical))
            .map(|inst| (inst.args[0], inst.dest.unwrap()))
            .collect();
        assert_eq!(logical.len(), 2);
        for dest in [7, 11, 15, 16] {
            assert_eq!(
                find(dest).args,
                [logical[&ValueId(2)], logical[&ValueId(1)]]
            );
        }
        let pass = kamy_transforms::MbaPass {
            seed: 7,
            config: MbaConfig {
                iterations: 2,
                probability: 100,
                semantics: MbaSemantics {
                    add: true,
                    sub: true,
                    xor: true,
                },
                bitwidths: MbaBitwidths {
                    bit64: true,
                    ..MbaBitwidths::default()
                },
            },
        };
        assert!(pass.run_with_intensity(&mut result.func, 1.0));
        for (dest, args) in [
            (5, [ValueId(3), ValueId(1)]),
            (6, [ValueId(1), ValueId(3)]),
            (12, [ValueId(3), ValueId(4)]),
        ] {
            let transformed = result.func.blocks[0]
                .insts
                .iter()
                .find(|inst| inst.dest == Some(ValueId(dest)))
                .unwrap();
            assert_ne!(transformed.args, args);
        }
        assert!(
            result.func.blocks[0]
                .insts
                .iter()
                .any(|inst| matches!(inst.op, IrOp::FrameLogical))
        );
    }
}
