mod constprop;
mod dce;
mod instcombine;
pub mod mba;
mod prune_phis;

pub use constprop::{ConstProp, resolve_image_base_uses};
pub use dce::Dce;
pub use instcombine::InstCombine;
pub use mba::MbaPass;
pub use prune_phis::PrunePhis;

use kamy_core::ir::{IrFunction, IrTerminator, ValueId};

pub trait Pass {
    fn run(&self, func: &mut IrFunction) -> bool;
    fn name(&self) -> &'static str;
}

pub fn optimize(func: &mut IrFunction) {
    let _s = tracing::debug_span!("optimize").entered();
    let passes: &[&dyn Pass] = &[&ConstProp, &InstCombine, &Dce, &PrunePhis];
    let mut rounds = 0u32;
    loop {
        rounds += 1;
        let mut changed = false;
        for pass in passes {
            if pass.run(func) {
                changed = true;
                tracing::trace!(pass = pass.name(), round = rounds, "pass changed IR");
            }
        }
        if !changed {
            break;
        }
    }
    tracing::debug!(rounds, "optimizer converged");
}

pub fn replace_uses(func: &mut IrFunction, old: ValueId, new: ValueId) {
    for block in &mut func.blocks {
        for phi in &mut block.phis {
            for (_, v) in &mut phi.args {
                if *v == old {
                    *v = new;
                }
            }
        }
        for inst in &mut block.insts {
            for arg in &mut inst.args {
                if *arg == old {
                    *arg = new;
                }
            }
        }
        if let IrTerminator::Branch { cond, .. } = &mut block.term {
            if *cond == old {
                *cond = new;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use kamy_core::ir::{BlockId, Inst, IrBlock, IrFunction, IrOp, IrTerminator, IrType, Phi};

    use super::*;

    fn one_block_func() -> IrFunction {
        IrFunction {
            entry: BlockId(0),
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![],
                term: IrTerminator::Ret,
            }],
            next_value: 0,
        }
    }

    #[test]
    fn constprop_folds_add() {
        let mut func = one_block_func();
        let v0 = func.alloc_value();
        let v1 = func.alloc_value();
        let v2 = func.alloc_value();
        func.blocks[0].insts = vec![
            Inst {
                dest: Some(v0),
                op: IrOp::Const(3),
                args: vec![],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v1),
                op: IrOp::Const(4),
                args: vec![],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v2),
                op: IrOp::Add,
                args: vec![v0, v1],
                ty: IrType::I32,
            },
        ];

        assert!(ConstProp.run(&mut func));
        assert!(matches!(func.blocks[0].insts[2].op, IrOp::Const(7)));
    }

    #[test]
    fn instcombine_add_zero() {
        let mut func = one_block_func();
        let v_addr = func.alloc_value();
        let v0 = func.alloc_value();
        let v_zero = func.alloc_value();
        let v_add = func.alloc_value();
        let v_store_addr = func.alloc_value();
        func.blocks[0].insts = vec![
            Inst {
                dest: Some(v_addr),
                op: IrOp::Const(0x1000),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(v0),
                op: IrOp::Load,
                args: vec![v_addr],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_zero),
                op: IrOp::Const(0),
                args: vec![],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_add),
                op: IrOp::Add,
                args: vec![v0, v_zero],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_store_addr),
                op: IrOp::Const(0x2000),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: None,
                op: IrOp::Store,
                args: vec![v_store_addr, v_add],
                ty: IrType::I32,
            },
        ];

        assert!(InstCombine.run(&mut func));
        assert_eq!(func.blocks[0].insts[5].args[1], v0);
    }

    #[test]
    fn dce_removes_unused_keeps_store() {
        let mut func = one_block_func();
        let v_addr = func.alloc_value();
        let v_load = func.alloc_value();
        let v_dead = func.alloc_value();
        let v_val = func.alloc_value();
        func.blocks[0].insts = vec![
            Inst {
                dest: Some(v_addr),
                op: IrOp::Const(0x1000),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(v_load),
                op: IrOp::Load,
                args: vec![v_addr],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_dead),
                op: IrOp::Add,
                args: vec![v_load, v_load],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_val),
                op: IrOp::Const(42),
                args: vec![],
                ty: IrType::I32,
            },
            Inst {
                dest: None,
                op: IrOp::Store,
                args: vec![v_addr, v_val],
                ty: IrType::I32,
            },
        ];

        assert!(Dce.run(&mut func));

        let has_store = func.blocks[0]
            .insts
            .iter()
            .any(|i| matches!(i.op, IrOp::Store));
        assert!(has_store);

        let has_dead_add = func.blocks[0].insts.iter().any(|i| i.dest == Some(v_dead));
        assert!(!has_dead_add);

        let has_dead_load = func.blocks[0].insts.iter().any(|i| i.dest == Some(v_load));
        assert!(!has_dead_load);
    }

    #[test]
    fn dce_keeps_indirect_call() {
        let mut func = one_block_func();
        let v_target = func.alloc_value();
        let v_ret = func.alloc_value();
        func.blocks[0].insts = vec![
            Inst {
                dest: Some(v_target),
                op: IrOp::Const(0x1000),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(v_ret),
                op: IrOp::CallIndirect {
                    clobbers: kamy_core::ir::win64_volatiles(),
                },
                args: vec![v_target],
                ty: IrType::I64,
            },
        ];
        Dce.run(&mut func);
        assert!(
            func.blocks[0]
                .insts
                .iter()
                .any(|i| matches!(i.op, IrOp::CallIndirect { .. })),
            "an indirect call has side effects and must survive DCE"
        );
    }

    #[test]
    fn prune_phis_same_args() {
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let v0 = func.alloc_value();
        let v_phi = func.alloc_value();
        let v_store_addr = func.alloc_value();
        func.blocks = vec![
            IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![Inst {
                    dest: Some(v0),
                    op: IrOp::Const(42),
                    args: vec![],
                    ty: IrType::I32,
                }],
                term: IrTerminator::Jump(BlockId(1)),
            },
            IrBlock {
                id: BlockId(1),
                phis: vec![Phi {
                    dest: v_phi,
                    ty: IrType::I32,
                    args: vec![(BlockId(0), v0), (BlockId(1), v0)],
                }],
                insts: vec![
                    Inst {
                        dest: Some(v_store_addr),
                        op: IrOp::Const(0x1000),
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: None,
                        op: IrOp::Store,
                        args: vec![v_store_addr, v_phi],
                        ty: IrType::I32,
                    },
                ],
                term: IrTerminator::Ret,
            },
        ];

        assert!(PrunePhis.run(&mut func));
        assert!(func.blocks[1].phis.is_empty());
        assert_eq!(func.blocks[1].insts[1].args[1], v0);
    }

    #[test]
    fn convergence_instcombine_then_dce() {
        let mut func = one_block_func();
        let v_addr = func.alloc_value();
        let v0 = func.alloc_value();
        let v_zero = func.alloc_value();
        let v_add = func.alloc_value();
        func.blocks[0].insts = vec![
            Inst {
                dest: Some(v_addr),
                op: IrOp::Const(0x1000),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(v0),
                op: IrOp::Load,
                args: vec![v_addr],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_zero),
                op: IrOp::Const(0),
                args: vec![],
                ty: IrType::I32,
            },
            Inst {
                dest: Some(v_add),
                op: IrOp::Add,
                args: vec![v0, v_zero],
                ty: IrType::I32,
            },
            Inst {
                dest: None,
                op: IrOp::Store,
                args: vec![v_addr, v_add],
                ty: IrType::I32,
            },
        ];

        optimize(&mut func);

        let has_add = func.blocks[0]
            .insts
            .iter()
            .any(|i| matches!(i.op, IrOp::Add));
        assert!(!has_add);

        let has_const_zero = func.blocks[0]
            .insts
            .iter()
            .any(|i| matches!(i.op, IrOp::Const(0)));
        assert!(!has_const_zero);

        let store = func.blocks[0]
            .insts
            .iter()
            .find(|i| matches!(i.op, IrOp::Store))
            .expect("Store must survive");
        assert_eq!(store.args[1], v0);
    }

    fn reference(symbol: kamy_core::SymbolId) -> kamy_core::Reference {
        kamy_core::Reference {
            source: kamy_core::SymbolId::Authored {
                module: "source".into(),
                symbol: "object:0:symbol:1".into(),
            },
            offset: 2,
            expression: kamy_core::SymbolicExpression::symbol(symbol),
            field: kamy_core::LinkField::Absolute64,
            origin: kamy_core::ReferenceOrigin::Authored,
        }
    }

    #[test]
    fn address_leaves_remain_opaque_through_copies_phis_and_optimization() {
        let a = reference(kamy_core::SymbolId::Authored {
            module: "a".into(),
            symbol: "object:0:symbol:7".into(),
        });
        let b = reference(kamy_core::SymbolId::Authored {
            module: "b".into(),
            symbol: "object:0:symbol:7".into(),
        });
        let mut func = IrFunction {
            entry: BlockId(0),
            next_value: 7,
            blocks: vec![
                IrBlock {
                    id: BlockId(0),
                    phis: vec![],
                    insts: vec![
                        Inst {
                            dest: Some(ValueId(0)),
                            op: IrOp::Address(a.clone()),
                            args: vec![],
                            ty: IrType::I64,
                        },
                        Inst {
                            dest: Some(ValueId(1)),
                            op: IrOp::Address(b.clone()),
                            args: vec![],
                            ty: IrType::I64,
                        },
                        Inst {
                            dest: Some(ValueId(2)),
                            op: IrOp::Copy,
                            args: vec![ValueId(0)],
                            ty: IrType::I64,
                        },
                        Inst {
                            dest: Some(ValueId(3)),
                            op: IrOp::Copy,
                            args: vec![ValueId(1)],
                            ty: IrType::I64,
                        },
                        Inst {
                            dest: Some(ValueId(6)),
                            op: IrOp::Undef,
                            args: vec![],
                            ty: IrType::I8,
                        },
                    ],
                    term: IrTerminator::Jump(BlockId(1)),
                },
                IrBlock {
                    id: BlockId(1),
                    phis: vec![Phi {
                        dest: ValueId(4),
                        ty: IrType::I64,
                        args: vec![(BlockId(0), ValueId(2)), (BlockId(1), ValueId(3))],
                    }],
                    insts: vec![
                        Inst {
                            dest: Some(ValueId(5)),
                            op: IrOp::Const(0x140002000),
                            args: vec![],
                            ty: IrType::I64,
                        },
                        Inst {
                            dest: None,
                            op: IrOp::Use,
                            args: vec![ValueId(4), ValueId(5)],
                            ty: IrType::I64,
                        },
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
                    insts: vec![],
                    term: IrTerminator::Ret,
                },
            ],
        };
        optimize(&mut func);
        let addresses: Vec<_> = func
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|inst| {
                if let IrOp::Address(reference) = &inst.op {
                    Some(reference)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(addresses, vec![&a, &b]);
        assert_eq!(func.blocks[1].phis.len(), 1);
        assert!(
            func.blocks[1]
                .insts
                .iter()
                .any(|inst| matches!(inst.op, IrOp::Const(0x140002000)))
        );
    }

    #[test]
    fn decoded_movabs_pointer_and_literal_survive_ssa_merge_and_optimization() {
        use kamy_core::{
            BasicBlock, Function, Machine, Module, OperandReference, Rva, Section, SectionFlags,
            Symbol, SymbolId, SymbolKind, Terminator,
        };
        struct Cc(SymbolId);
        impl kamy_core::ir::CallingConvLookup for Cc {
            fn lookup(&self, _: u64) -> Option<kamy_core::ir::FnSignature> {
                None
            }
            fn lookup_symbol(&self, symbol: &SymbolId) -> Option<kamy_core::ir::FnSignature> {
                (*symbol == self.0).then(kamy_core::ir::Win64Default::default_signature)
            }
        }
        let literal = 0x140003008u64;
        let mut code = vec![0x85, 0xc9, 0x74, 0x0c, 0x48, 0xb8];
        code.extend_from_slice(&literal.to_le_bytes());
        code.extend_from_slice(&[0xeb, 0x0a, 0x48, 0xb8]);
        code.extend_from_slice(&literal.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0xc2, 0xc3]);
        let source = SymbolId::Authored {
            module: "module".into(),
            symbol: "object:0:symbol:1".into(),
        };
        let mut pointer = reference(SymbolId::Authored {
            module: "module".into(),
            symbol: "object:0:symbol:7".into(),
        });
        pointer.source = source.clone();
        pointer.offset = 6;
        pointer.expression = pointer.expression.with_addend(8).unwrap();
        let func = Function {
            entry: Rva::new(0x1000),
            blocks: vec![
                BasicBlock {
                    start: Rva::new(0x1000),
                    end: Rva::new(0x1004),
                    successors: vec![Rva::new(0x1010), Rva::new(0x1004)],
                    terminator: Terminator::Branch {
                        taken: Rva::new(0x1010),
                        not_taken: Rva::new(0x1004),
                    },
                },
                BasicBlock {
                    start: Rva::new(0x1004),
                    end: Rva::new(0x1010),
                    successors: vec![Rva::new(0x101a)],
                    terminator: Terminator::Jump(Rva::new(0x101a)),
                },
                BasicBlock {
                    start: Rva::new(0x1010),
                    end: Rva::new(0x101a),
                    successors: vec![Rva::new(0x101a)],
                    terminator: Terminator::Fallthrough(Rva::new(0x101a)),
                },
                BasicBlock {
                    start: Rva::new(0x101a),
                    end: Rva::new(0x101e),
                    successors: vec![],
                    terminator: Terminator::Return,
                },
            ],
        };
        let module = Module {
            image_base: 0x140000000,
            machine: Machine::X64,
            entry_point: None,
            sections: vec![Section {
                name: ".text".into(),
                rva: Rva::new(0x1000),
                virtual_size: code.len() as u32,
                data: code.clone(),
                flags: SectionFlags {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            symbols: vec![Symbol {
                id: source.clone(),
                name: "caller".into(),
                rva: func.entry,
                kind: SymbolKind::Function,
            }],
            relocations: vec![],
            functions: vec![func.clone()],
        };
        let annotations = [OperandReference {
            instruction: Rva::new(0x1004),
            operand: 1,
            reference: pointer.clone(),
        }];
        let mut lifted = kamy_lift::lift_function(&module, &func, &Cc(source), &annotations);
        assert!(!lifted.unsupported);
        kamy_lift::construct_ssa(&mut lifted);
        optimize(&mut lifted.func);
        assert!(
            lifted
                .func
                .blocks
                .iter()
                .any(|block| !block.phis.is_empty())
        );
        let instructions: Vec<_> = lifted
            .func
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .collect();
        assert!(
            instructions
                .iter()
                .any(|inst| matches!(&inst.op, IrOp::Address(actual) if actual == &pointer))
        );
        assert!(
            instructions
                .iter()
                .any(|inst| matches!(inst.op, IrOp::Const(value) if value == literal))
        );
        assert_eq!(module.sections[0].data, code);
    }

    #[test]
    fn proven_imagebase_object_arithmetic_is_symbolic_but_equal_literal_is_not() {
        let mut func = one_block_func();
        func.next_value = 6;
        let base = reference(kamy_core::SymbolId::HostImageBase);
        func.blocks[0].insts = vec![
            Inst {
                dest: Some(ValueId(0)),
                op: IrOp::Address(base.clone()),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(ValueId(1)),
                op: IrOp::Const(0x2010),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(ValueId(2)),
                op: IrOp::Add,
                args: vec![ValueId(0), ValueId(1)],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(ValueId(5)),
                op: IrOp::CarryAdd,
                args: vec![ValueId(0), ValueId(1)],
                ty: IrType::I8,
            },
            Inst {
                dest: Some(ValueId(3)),
                op: IrOp::Copy,
                args: vec![ValueId(2)],
                ty: IrType::I64,
            },
            Inst {
                dest: Some(ValueId(4)),
                op: IrOp::Const(0x140002010),
                args: vec![],
                ty: IrType::I64,
            },
            Inst {
                dest: None,
                op: IrOp::Use,
                args: vec![ValueId(3), ValueId(4)],
                ty: IrType::I64,
            },
        ];
        let expression = kamy_core::SymbolicExpression::Symbol {
            symbol: kamy_core::SymbolId::Host {
                rva: kamy_core::Rva::new(0x2000),
            },
            addend: 16,
        };
        assert!(!resolve_image_base_uses(&mut func, |offset| {
            if offset == 0x2010 {
                Some(expression.clone())
            } else {
                None
            }
        }));
        optimize(&mut func);
        assert!(func.blocks[0].insts.iter().any(|inst| matches!(&inst.op, IrOp::Address(actual) if actual.expression == expression && actual.origin == base.origin && actual.source == base.source)));
        assert!(
            func.blocks[0]
                .insts
                .iter()
                .any(|inst| matches!(inst.op, IrOp::Const(0x140002010)))
        );
    }

    #[test]
    fn header_offsets_stay_signed_and_unknown_base_arithmetic_constrains_movement() {
        for offset in [-16i64, 16] {
            let mut func = one_block_func();
            func.next_value = 4;
            func.blocks[0].insts = vec![
                Inst {
                    dest: Some(ValueId(0)),
                    op: IrOp::Address(reference(kamy_core::SymbolId::HostImageBase)),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(ValueId(1)),
                    op: IrOp::Const(offset as u64),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(ValueId(2)),
                    op: IrOp::Add,
                    args: vec![ValueId(0), ValueId(1)],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(ValueId(3)),
                    op: IrOp::Load,
                    args: vec![ValueId(2)],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![ValueId(3)],
                    ty: IrType::I64,
                },
            ];
            assert!(!resolve_image_base_uses(&mut func, |_| None));
            assert!(func.blocks[0].insts.iter().any(|inst| matches!(&inst.op, IrOp::Address(actual) if matches!(&actual.expression, kamy_core::SymbolicExpression::Symbol { symbol: kamy_core::SymbolId::HostImageBase, addend } if *addend == offset))));
            func.blocks[0].insts[1].op = IrOp::Undef;
            func.blocks[0].insts[2].op = IrOp::Add;
            func.blocks[0].insts[2].args = vec![ValueId(0), ValueId(1)];
            assert!(resolve_image_base_uses(&mut func, |_| None));
        }
    }
}
