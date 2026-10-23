use super::*;
use crate::ir::IrBlock;

fn inst(dest: u32, op: IrOp, args: &[u32], ty: IrType) -> Inst {
    Inst {
        dest: Some(ValueId(dest)),
        op,
        args: args.iter().copied().map(ValueId).collect(),
        ty,
    }
}

fn definitions(insts: &[Inst]) -> HashMap<ValueId, Definition<'_>> {
    insts
        .iter()
        .map(|inst| (inst.dest.unwrap(), Definition::Inst(inst)))
        .collect()
}

#[test]
fn scalar_shared_success_and_failure_dags_evaluate_once() {
    for size in [256u32, 4096, 20_000] {
        for success in [true, false] {
            let mut insts = vec![inst(0, IrOp::Undef, &[], IrType::I64)];
            let mut facts = HashMap::new();
            let (first, base) = if success {
                insts.push(inst(1, IrOp::Const(1), &[], IrType::I64));
                insts.push(inst(2, IrOp::And, &[0, 1], IrType::I64));
                facts.insert(ValueId(1), Fact::Scalar(Some(1)));
                (3, 2)
            } else {
                (1, 0)
            };
            for offset in 0..size {
                let dest = first + offset;
                let source = if offset == 0 { base } else { dest - 1 };
                insts.push(inst(
                    dest,
                    if success { IrOp::And } else { IrOp::Add },
                    &[source, source],
                    IrType::I64,
                ));
            }
            let definitions = definitions(&insts);
            let known = HashMap::new();
            let mut analysis = ScalarAnalysis::new(&facts, &definitions, &known);
            let root = ValueId(first + size - 1);
            let expected = success.then_some(ScalarBounds { low: 0, high: 1 });
            assert_eq!(analysis.get(root), expected);
            assert_eq!(analysis.work.evaluated_nodes, insts.len());
            assert_eq!(analysis.states.len(), insts.len());
            let edges = 2 * (size as usize + usize::from(success));
            assert_eq!(analysis.work.dependency_edges, edges);
            let work = analysis.work.evaluated_nodes;
            for node in &insts {
                let _ = analysis.get(node.dest.unwrap());
            }
            assert_eq!(analysis.get(root), expected);
            assert_eq!(analysis.work.evaluated_nodes, work);
            assert_eq!(analysis.work.dependency_edges, edges);
            assert!(
                analysis
                    .states
                    .values()
                    .all(|state| matches!(state, ScalarState::Complete(_)))
            );
            let allocated = analysis.states.capacity() + analysis.pending.capacity();
            assert!(allocated <= 4 * insts.len());
            println!(
                "scalar-dag success={success} nodes={} edges={edges} evaluated={} cached={} allocated_entries={allocated} peak_pending={}",
                insts.len(),
                analysis.work.evaluated_nodes,
                analysis.states.len(),
                analysis.work.peak_pending,
            );
        }
    }
}

#[test]
fn scalar_cycles_fail_and_known_loop_bounds_break_dependencies() {
    let insts = vec![
        inst(0, IrOp::Copy, &[1], IrType::I64),
        inst(1, IrOp::And, &[0, 2], IrType::I64),
        inst(2, IrOp::Const(1), &[], IrType::I64),
        inst(3, IrOp::Copy, &[0], IrType::I64),
        inst(4, IrOp::Copy, &[4], IrType::I64),
    ];
    let definitions = definitions(&insts);
    let facts = HashMap::from([(ValueId(2), Fact::Scalar(Some(1)))]);
    let known = HashMap::new();
    let mut analysis = ScalarAnalysis::new(&facts, &definitions, &known);
    for value in [0, 1, 3, 4] {
        assert_eq!(analysis.get(ValueId(value)), None);
    }
    assert_eq!(analysis.work.evaluated_nodes, 5);
    assert_eq!(analysis.work.dependency_edges, 5);
    assert_eq!(analysis.states.len(), 5);
    assert!(
        analysis
            .states
            .values()
            .all(|state| matches!(state, ScalarState::Complete(_)))
    );
    println!(
        "scalar-cycle evaluated={} cached={} edges={}",
        analysis.work.evaluated_nodes,
        analysis.states.len(),
        analysis.work.dependency_edges
    );

    let known = HashMap::from([(ValueId(0), ScalarBounds { low: 4, high: 12 })]);
    let mut analysis = ScalarAnalysis::new(&facts, &definitions, &known);
    assert_eq!(
        analysis.get(ValueId(0)),
        Some(ScalarBounds { low: 4, high: 12 })
    );
    assert_eq!(
        analysis.get(ValueId(3)),
        Some(ScalarBounds { low: 4, high: 12 })
    );
    assert_eq!(analysis.work.evaluated_nodes, 2);
    assert_eq!(analysis.work.dependency_edges, 1);
}

fn scalar_operation(
    op: IrOp,
    ty: IrType,
    left: (u64, u64),
    right: (u64, u64),
) -> Option<ScalarBounds> {
    let insts = [inst(2, op, &[0, 1], ty)];
    let definitions = definitions(&insts);
    let facts = HashMap::new();
    let known = HashMap::from([
        (
            ValueId(0),
            ScalarBounds {
                low: left.0,
                high: left.1,
            },
        ),
        (
            ValueId(1),
            ScalarBounds {
                low: right.0,
                high: right.1,
            },
        ),
    ]);
    ScalarAnalysis::new(&facts, &definitions, &known).get(ValueId(2))
}

#[test]
fn scalar_width_wrap_and_overflow_boundaries_are_preserved() {
    for (op, ty, left, right, expected) in [
        (IrOp::Add, IrType::I8, (250, 252), (10, 10), Some((4, 6))),
        (IrOp::Add, IrType::I8, (250, 255), (1, 1), None),
        (IrOp::Sub, IrType::I8, (0, 1), (2, 2), Some((254, 255))),
        (IrOp::Sub, IrType::I8, (0, 2), (1, 1), None),
        (IrOp::Mul, IrType::I8, (254, 255), (2, 2), Some((252, 254))),
        (IrOp::Mul, IrType::I8, (127, 128), (2, 2), None),
        (IrOp::Trunc, IrType::I8, (256, 511), (0, 0), Some((0, 255))),
        (IrOp::Trunc, IrType::I8, (255, 256), (0, 0), None),
        (
            IrOp::Add,
            IrType::I64,
            (u64::MAX, u64::MAX),
            (1, 1),
            Some((0, 0)),
        ),
        (
            IrOp::Add,
            IrType::I64,
            (u64::MAX - 1, u64::MAX),
            (1, 1),
            None,
        ),
        (
            IrOp::Mul,
            IrType::I64,
            (u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX),
            Some((1, 1)),
        ),
        (IrOp::Shl, IrType::I64, (1, 1), (64, 64), Some((1, 1))),
        (IrOp::Shr, IrType::I32, (16, 32), (33, 33), Some((8, 16))),
    ] {
        let expected = expected.map(|(low, high)| ScalarBounds { low, high });
        assert_eq!(
            scalar_operation(op.clone(), ty, left, right),
            expected,
            "{op:?} {ty:?} {left:?} {right:?}"
        );
    }
}

#[test]
fn scalar_cache_is_recomputed_for_changed_facts() {
    let insts = [inst(1, IrOp::Copy, &[0], IrType::I64)];
    let definitions = definitions(&insts);
    let known = HashMap::new();
    let mut facts = HashMap::from([(ValueId(0), Fact::Scalar(Some(7)))]);
    assert_eq!(
        ScalarAnalysis::new(&facts, &definitions, &known).get(ValueId(1)),
        Some(ScalarBounds { low: 7, high: 7 })
    );
    facts.insert(ValueId(0), Fact::Scalar(Some(19)));
    assert_eq!(
        ScalarAnalysis::new(&facts, &definitions, &known).get(ValueId(1)),
        Some(ScalarBounds { low: 19, high: 19 })
    );
    facts.insert(ValueId(0), Fact::Scalar(None));
    assert_eq!(
        ScalarAnalysis::new(&facts, &definitions, &known).get(ValueId(1)),
        None
    );
}

#[test]
fn scalar_shared_index_consumer_preserves_resource_and_overflow_rejections() {
    for (depth, expected) in [
        (8, None),
        (24, Some(RejectionReason::FrameResourceLimit)),
        (31, Some(RejectionReason::FrameOverflow)),
        (40, Some(RejectionReason::FrameOverflow)),
        (64, Some(RejectionReason::FrameDynamic)),
    ] {
        let mut insts = vec![
            inst(0, IrOp::Undef, &[], IrType::I64),
            inst(1, IrOp::Const(1), &[], IrType::I64),
            inst(2, IrOp::And, &[0, 1], IrType::I64),
        ];
        for offset in 0..depth {
            let dest = offset + 3;
            insts.push(inst(dest, IrOp::Add, &[dest - 1, dest - 1], IrType::I64));
        }
        let index = depth + 2;
        insts.push(inst(index + 1, IrOp::FrameAddress(-8), &[], IrType::I64));
        insts.push(inst(index + 2, IrOp::Sub, &[index + 1, index], IrType::I64));
        insts.push(inst(index + 3, IrOp::Load, &[index + 2], IrType::I64));
        let func = IrFunction {
            entry: BlockId(0),
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts,
                term: IrTerminator::Ret,
            }],
            next_value: index + 4,
        };
        let result = FrameAnalysis::analyze(&func, &HashSet::new(), &HashMap::new());
        match expected {
            Some(reason) => assert_eq!(result.unwrap_err(), reason, "depth={depth}"),
            None => {
                let analysis = result.unwrap();
                assert_eq!(analysis.original_size, 264);
                assert_eq!(
                    analysis.indexed_offsets[&ValueId(index + 2)]
                        .bounds
                        .negative,
                    Some((-264, -8))
                );
            }
        }
    }
}

fn function_definitions(func: &IrFunction) -> HashMap<ValueId, Definition<'_>> {
    func.blocks
        .iter()
        .flat_map(|block| {
            block
                .phis
                .iter()
                .map(|phi| (phi.dest, Definition::Phi(phi)))
                .chain(
                    block
                        .insts
                        .iter()
                        .filter_map(|inst| inst.dest.map(|dest| (dest, Definition::Inst(inst)))),
                )
        })
        .collect()
}

fn predecessor_map(func: &IrFunction) -> HashMap<BlockId, Vec<BlockId>> {
    let mut predecessors: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    for block in &func.blocks {
        for successor in successors(block) {
            predecessors.entry(successor).or_default().push(block.id);
        }
    }
    predecessors
}

fn counted_loop(body_blocks: u32) -> (IrFunction, HashMap<ValueId, Fact>) {
    let latch = BlockId(body_blocks + 1);
    let exit = BlockId(body_blocks + 2);
    let mut blocks = vec![
        IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                inst(0, IrOp::Const(0), &[], IrType::I64),
                inst(1, IrOp::Const(1), &[], IrType::I64),
                inst(2, IrOp::Const(8), &[], IrType::I64),
                inst(3, IrOp::FrameAddress(-128), &[], IrType::I64),
            ],
            term: IrTerminator::Jump(BlockId(1)),
        },
        IrBlock {
            id: BlockId(1),
            phis: vec![
                Phi {
                    dest: ValueId(4),
                    ty: IrType::I64,
                    args: vec![(BlockId(0), ValueId(0)), (latch, ValueId(5))],
                },
                Phi {
                    dest: ValueId(6),
                    ty: IrType::I64,
                    args: vec![(BlockId(0), ValueId(3)), (latch, ValueId(7))],
                },
            ],
            insts: vec![],
            term: IrTerminator::Jump(BlockId(2)),
        },
    ];
    for block in 2..=latch.0 {
        blocks.push(IrBlock {
            id: BlockId(block),
            phis: vec![],
            insts: vec![],
            term: IrTerminator::Jump(BlockId(block + 1)),
        });
    }
    blocks[latch.0 as usize].insts = vec![
        inst(5, IrOp::Add, &[4, 1], IrType::I64),
        inst(7, IrOp::FrameOffset(8), &[6], IrType::I64),
        inst(8, IrOp::Sub, &[5, 2], IrType::I64),
        inst(9, IrOp::IsZero, &[8], IrType::I8),
    ];
    blocks[latch.0 as usize].term = IrTerminator::Branch {
        cond: ValueId(9),
        taken: exit,
        not_taken: BlockId(1),
    };
    blocks.push(IrBlock {
        id: exit,
        phis: vec![],
        insts: vec![],
        term: IrTerminator::Ret,
    });
    let facts = HashMap::from([
        (ValueId(0), Fact::Scalar(Some(0))),
        (ValueId(1), Fact::Scalar(Some(1))),
        (ValueId(2), Fact::Scalar(Some(8))),
        (ValueId(3), Fact::Offset(-128)),
    ]);
    (
        IrFunction {
            entry: BlockId(0),
            blocks,
            next_value: 10,
        },
        facts,
    )
}

#[test]
fn loop_candidate_free_large_acyclic_cfg_allocates_no_dominators() {
    for size in [256u32, 4096, 20_000] {
        let func = IrFunction {
            entry: BlockId(0),
            blocks: (0..size)
                .rev()
                .map(|id| IrBlock {
                    id: BlockId(id),
                    phis: vec![],
                    insts: vec![],
                    term: if id + 1 == size {
                        IrTerminator::Ret
                    } else {
                        IrTerminator::Jump(BlockId(id + 1))
                    },
                })
                .collect(),
            next_value: 0,
        };
        let reachable = func.blocks.iter().map(|block| block.id).collect();
        let result = loops(&func, &HashMap::new(), &HashMap::new(), &reachable).unwrap();
        assert!(
            result.scalars.is_empty() && result.pointers.is_empty() && result.advances.is_empty()
        );
        assert_eq!(result.work.candidate_blocks, size as usize);
        assert_eq!(result.work.dominators.graph_nodes, 0);
        assert_eq!(result.work.dominators.owned_allocated_entries, 0);
        println!(
            "loop-candidate-free nodes={size} candidate_scans={} dominator_nodes={} owned_allocated_entries={}",
            result.work.candidate_blocks,
            result.work.dominators.graph_nodes,
            result.work.dominators.owned_allocated_entries
        );
    }
}

#[test]
fn loop_reducible_headers_latches_have_linear_storage_and_measured_work() {
    for body_blocks in [0u32, 256, 4096, 20_000] {
        let (mut func, facts) = counted_loop(body_blocks);
        // Block-vector order is not a dominance or reachability ordering.
        func.blocks.reverse();
        let reachable = func.blocks.iter().map(|block| block.id).collect();
        let definitions = function_definitions(&func);
        let result = loops(&func, &facts, &definitions, &reachable).unwrap();
        assert_eq!(
            result.scalars[&ValueId(4)],
            ScalarBounds { low: 0, high: 7 }
        );
        assert_eq!(result.pointers[&ValueId(6)].negative, Some((-128, -72)));
        assert_eq!(result.advances[&ValueId(7)], (ValueId(6), 8));
        let nodes = func.blocks.len();
        let edges: usize = func
            .blocks
            .iter()
            .map(|block| successors(block).count())
            .sum();
        let work = &result.work.dominators;
        assert_eq!(work.graph_nodes, nodes);
        assert_eq!(work.graph_edges, edges);
        assert_eq!(work.immediate_dominator_entries, nodes - 1);
        assert_eq!(work.tree_nodes, nodes);
        assert_eq!(work.tree_edges, nodes - 1);
        assert!(work.owned_allocated_entries <= 10 * nodes + 2 * edges);
        println!(
            "loop-reducible nodes={nodes} edges={edges} idom_entries={} tree_nodes={} tree_edges={} owned_allocated_entries={} (petgraph fixed-point iterations not instrumented; documented O(V^2) worst-case time)",
            work.immediate_dominator_entries,
            work.tree_nodes,
            work.tree_edges,
            work.owned_allocated_entries
        );
    }
}

#[test]
fn loop_irreducible_entries_do_not_invent_induction_bounds() {
    for body_blocks in [1u32, 256, 4096, 20_000] {
        let (mut func, facts) = counted_loop(body_blocks);
        func.blocks[0]
            .insts
            .push(inst(12, IrOp::Undef, &[], IrType::I8));
        func.blocks[0].term = IrTerminator::Branch {
            cond: ValueId(12),
            taken: BlockId(1),
            not_taken: BlockId(2),
        };
        func.blocks[2].phis = vec![
            Phi {
                dest: ValueId(10),
                ty: IrType::I64,
                args: vec![(BlockId(0), ValueId(0)), (BlockId(1), ValueId(4))],
            },
            Phi {
                dest: ValueId(11),
                ty: IrType::I64,
                args: vec![(BlockId(0), ValueId(3)), (BlockId(1), ValueId(6))],
            },
        ];
        let latch = (body_blocks + 1) as usize;
        func.blocks[latch].insts[0].args[0] = ValueId(10);
        func.blocks[latch].insts[1].args[0] = ValueId(11);
        func.next_value = 13;
        let reachable = func.blocks.iter().map(|block| block.id).collect();
        let definitions = function_definitions(&func);
        let result = loops(&func, &facts, &definitions, &reachable).unwrap();
        assert!(
            result.scalars.is_empty() && result.pointers.is_empty() && result.advances.is_empty()
        );
        let nodes = func.blocks.len();
        let edges: usize = func
            .blocks
            .iter()
            .map(|block| successors(block).count())
            .sum();
        assert_eq!(result.work.dominators.graph_nodes, nodes);
        assert_eq!(result.work.dominators.tree_nodes, nodes);
        assert_eq!(result.work.dominators.tree_edges, nodes - 1);
        assert!(result.work.dominators.owned_allocated_entries <= 10 * nodes + 2 * edges);
        let blocks = func.blocks.iter().map(|block| (block.id, block)).collect();
        let dominators =
            LoopDominators::new(func.entry, &blocks, &predecessor_map(&func), &reachable);
        assert!(!dominators.dominates(BlockId(1), BlockId(2)));
        assert!(!dominators.dominates(BlockId(2), BlockId(1)));
        println!(
            "loop-irreducible nodes={nodes} edges={edges} {:?}",
            result.work.dominators
        );
    }
}

#[test]
fn loop_transform_recomputes_bounds_from_current_function() {
    let (mut func, mut facts) = counted_loop(1);
    let reachable = func.blocks.iter().map(|block| block.id).collect();
    for end in [8u64, 4] {
        func.blocks[0].insts[2].op = IrOp::Const(end);
        facts.insert(ValueId(2), Fact::Scalar(Some(end)));
        let definitions = function_definitions(&func);
        let result = loops(&func, &facts, &definitions, &reachable).unwrap();
        let expected = Some((-128, -128 + 8 * (end as i64 - 1)));
        assert_eq!(result.pointers[&ValueId(6)].negative, expected);
        let analysis = FrameAnalysis::analyze(&func, &HashSet::new(), &HashMap::new()).unwrap();
        assert_eq!(analysis.induction_bounds[&ValueId(6)].negative, expected);
    }
}

#[test]
fn loop_dominators_match_small_graph_fixed_point_oracle() {
    // The deliberately quadratic oracle is restricted to four nodes. The
    // production algorithm is checked against all 625 additional-edge choices,
    // including self edges, entry backedges, joins and irreducible cycles.
    let reachable: HashSet<_> = (0..4).map(BlockId).collect();
    let mut total_tree_nodes = 0;
    for mut choices in 0..625 {
        let mut blocks = Vec::new();
        for id in 0..4u32 {
            let extra = choices % 5;
            choices /= 5;
            let first = (id < 3).then_some(BlockId(id + 1));
            let second = (extra < 4).then_some(BlockId(extra));
            let term = match (first, second) {
                (Some(first), Some(second)) if first != second => IrTerminator::Branch {
                    cond: ValueId(0),
                    taken: first,
                    not_taken: second,
                },
                (Some(target), _) | (_, Some(target)) => IrTerminator::Jump(target),
                _ => IrTerminator::Ret,
            };
            blocks.push(IrBlock {
                id: BlockId(id),
                phis: vec![],
                insts: vec![],
                term,
            });
        }
        let func = IrFunction {
            entry: BlockId(0),
            blocks,
            next_value: 1,
        };
        let predecessors = predecessor_map(&func);
        let blocks = func.blocks.iter().map(|block| (block.id, block)).collect();
        let dominators = LoopDominators::new(func.entry, &blocks, &predecessors, &reachable);
        let mut expected: HashMap<_, _> = reachable
            .iter()
            .map(|&block| {
                (
                    block,
                    if block == func.entry {
                        HashSet::from([block])
                    } else {
                        reachable.clone()
                    },
                )
            })
            .collect();
        loop {
            let mut changed = false;
            for block in 1..4u32 {
                let block = BlockId(block);
                let mut parents = predecessors[&block].iter();
                let mut common = expected[parents.next().unwrap()].clone();
                for parent in parents {
                    common.retain(|dominator| expected[parent].contains(dominator));
                }
                common.insert(block);
                if common != expected[&block] {
                    expected.insert(block, common);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        for &dominator in &reachable {
            for &block in &reachable {
                assert_eq!(
                    dominators.dominates(dominator, block),
                    expected[&block].contains(&dominator),
                    "CFG={:?} dominator={dominator:?} block={block:?}",
                    func.blocks
                );
            }
        }
        total_tree_nodes += dominators.work.tree_nodes;
    }
    assert_eq!(total_tree_nodes, 2500);
    println!("loop-dominator-oracle graphs=625 nodes_per_graph=4 tree_nodes={total_tree_nodes}");
}
