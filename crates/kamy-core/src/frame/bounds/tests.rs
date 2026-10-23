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
