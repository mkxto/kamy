use std::collections::{HashMap, HashSet};

use kamy_core::ir::{IrFunction, IrOp, IrTerminator, ValueId};

use crate::Pass;

pub struct Dce;

impl Pass for Dce {
    fn name(&self) -> &'static str {
        "dce"
    }

    fn run(&self, func: &mut IrFunction) -> bool {
        let mut def_args: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        for block in &func.blocks {
            for phi in &block.phis {
                def_args.insert(phi.dest, phi.args.iter().map(|(_, v)| *v).collect());
            }
            for inst in &block.insts {
                if let Some(dest) = inst.dest {
                    def_args.insert(dest, inst.args.clone());
                }
            }
        }

        let mut live: HashSet<ValueId> = HashSet::new();
        let mut worklist: Vec<ValueId> = Vec::new();

        for block in &func.blocks {
            for inst in &block.insts {
                let is_root = inst.dest.is_none()
                    || matches!(
                        inst.op,
                        IrOp::Store
                            | IrOp::Call { .. }
                            | IrOp::CallIndirect { .. }
                            | IrOp::NativeInline(_)
                            | IrOp::StackProbe
                            | IrOp::UDiv
                            | IrOp::SDiv
                    );
                if is_root {
                    if let Some(dest) = inst.dest {
                        live.insert(dest);
                    }
                    for &arg in &inst.args {
                        if live.insert(arg) {
                            worklist.push(arg);
                        }
                    }
                }
            }
            if let IrTerminator::Branch { cond, .. } = &block.term {
                if live.insert(*cond) {
                    worklist.push(*cond);
                }
            }
        }

        while let Some(v) = worklist.pop() {
            if let Some(args) = def_args.get(&v) {
                for &arg in args {
                    if live.insert(arg) {
                        worklist.push(arg);
                    }
                }
            }
        }

        let mut changed = false;
        for block in &mut func.blocks {
            let phi_before = block.phis.len();
            block.phis.retain(|phi| live.contains(&phi.dest));
            if block.phis.len() != phi_before {
                changed = true;
            }

            let inst_before = block.insts.len();
            block.insts.retain(|inst| match inst.dest {
                Some(dest) => live.contains(&dest),
                None => true,
            });
            if block.insts.len() != inst_before {
                changed = true;
            }
        }

        changed
    }
}

#[cfg(test)]
mod tests {
    use kamy_core::ir::{Gpr, IrType, PhysReg, Win64Default};
    use kamy_core::{
        BasicBlock, Function, Machine, Module, Rva, Section, SectionFlags, Terminator,
    };

    use super::*;

    fn lift(code: &[u8], blocks: Vec<BasicBlock>) -> kamy_lift::LiftResult {
        let function = Function {
            entry: Rva::new(0x1000),
            blocks,
        };
        let module = Module {
            image_base: 0x1_4000_0000,
            machine: Machine::X64,
            entry_point: Some(function.entry),
            sections: vec![Section {
                name: ".text".into(),
                rva: function.entry,
                virtual_size: code.len() as u32,
                data: code.to_vec(),
                flags: SectionFlags {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            symbols: vec![],
            relocations: vec![],
            functions: vec![],
        };
        let mut result = kamy_lift::lift_function(&module, &function, &Win64Default, &[]);
        assert!(!result.unsupported);
        kamy_lift::construct_ssa(&mut result).unwrap();
        Dce.run(&mut result.func);
        result
    }

    fn linear(code: &[u8]) -> kamy_lift::LiftResult {
        lift(
            code,
            vec![BasicBlock {
                start: Rva::new(0x1000),
                end: Rva::new(0x1000 + code.len() as u32),
                successors: vec![],
                terminator: Terminator::Return,
            }],
        )
    }

    fn value(function: &IrFunction, id: ValueId) -> u64 {
        let inst = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find(|inst| inst.dest == Some(id))
            .unwrap();
        let arg = |i: usize| value(function, inst.args[i]);
        let result = match inst.op {
            IrOp::Const(value) => value,
            IrOp::Copy | IrOp::Zext | IrOp::Trunc => arg(0),
            IrOp::And => arg(0) & arg(1),
            IrOp::Or => arg(0) | arg(1),
            IrOp::SetIf => u64::from(arg(0) != 0),
            ref unexpected => panic!("unexpected return dependency: {unexpected:?}"),
        };
        assert_ne!(inst.ty, IrType::I128);
        result & (u64::MAX >> (64 - inst.ty.bits()))
    }

    #[test]
    fn decoded_flag_overwrite_drops_comparison_but_inc_preserves_carry_use() {
        for preserve_carry in [false, true] {
            let mut code = vec![0xb8, 0, 0, 0, 0, 0x39, 0xd1];
            code.extend_from_slice(if preserve_carry {
                &[0x41, 0xff, 0xc0]
            } else {
                &[0x45, 0x85, 0xc0]
            });
            code.extend_from_slice(&[0x0f, 0x92, 0xc0, 0xc3]);
            let lifted = linear(&code);
            assert_eq!(
                lifted.func.blocks[0]
                    .insts
                    .iter()
                    .any(|inst| matches!(inst.op, IrOp::BorrowSub)),
                preserve_carry
            );
            if !preserve_carry {
                assert_eq!(
                    value(&lifted.func, lifted.block_exit[0][Gpr::Rax.index()]),
                    0
                );
            }
        }
    }

    #[test]
    fn decoded_partial_register_writes_retain_the_returned_upper_bits() {
        for (write, expected, retain_old) in [
            (&[0xb0, 0x55][..], 0x1122_3355, true),
            (&[0x66, 0xb8, 0x66, 0x55][..], 0x1122_5566, true),
            (&[0xb8, 0x88, 0x77, 0x66, 0x55][..], 0x5566_7788, false),
        ] {
            let mut code = vec![0xb8, 0x44, 0x33, 0x22, 0x11];
            code.extend_from_slice(write);
            code.push(0xc3);
            let lifted = linear(&code);
            assert_eq!(
                value(&lifted.func, lifted.block_exit[0][Gpr::Rax.index()]),
                expected
            );
            assert_eq!(
                lifted.func.blocks[0]
                    .insts
                    .iter()
                    .any(|inst| matches!(inst.op, IrOp::Const(0x1122_3344))),
                retain_old
            );
        }
    }

    #[test]
    fn decoded_native_partial_write_requires_incoming_register_but_full_write_does_not() {
        for (native, retain_old) in [
            (&[0x66, 0x0f, 0x38, 0xf0, 0x01][..], true),
            (&[0x0f, 0x38, 0xf0, 0x01][..], false),
        ] {
            let mut code = vec![0xb8, 0x44, 0x33, 0x22, 0x11];
            code.extend_from_slice(native);
            code.push(0xc3);
            let lifted = linear(&code);
            let inst = lifted.func.blocks[0]
                .insts
                .iter()
                .find(|inst| matches!(&inst.op, IrOp::NativeInline(raw) if raw.bytes == native))
                .unwrap();
            let IrOp::NativeInline(raw) = &inst.op else {
                unreachable!();
            };
            assert_eq!(raw.reads.contains(&PhysReg::Gpr(Gpr::Rax)), retain_old);
            assert_eq!(raw.writes, vec![PhysReg::Gpr(Gpr::Rax)]);
            if retain_old {
                let input = raw
                    .reads
                    .iter()
                    .position(|read| *read == PhysReg::Gpr(Gpr::Rax))
                    .unwrap();
                assert_eq!(value(&lifted.func, inst.args[input]), 0x1122_3344);
            }
            assert_eq!(
                lifted.func.blocks[0]
                    .insts
                    .iter()
                    .any(|inst| matches!(inst.op, IrOp::Const(0x1122_3344))),
                retain_old
            );
        }
    }

    #[test]
    fn decoded_native_memory_and_call_arguments_survive_dead_integer_return_and_flags() {
        let lifted = linear(&[
            0x48, 0x83, 0xec, 0x28, 0x39, 0xd1, 0xba, 17, 0, 0, 0, 0x41, 0x89, 0x10, 0x66, 0x0f,
            0xe7, 0x01, 0x41, 0xff, 0xd3, 0xb8, 9, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ]);
        let insts = &lifted.func.blocks[0].insts;
        assert!(insts.iter().any(|inst| matches!(inst.op, IrOp::Store)));
        assert!(insts.iter().any(|inst| {
            matches!(&inst.op, IrOp::NativeInline(raw) if raw.bytes == [0x66, 0x0f, 0xe7, 0x01])
        }));
        let call = insts
            .iter()
            .find(|inst| matches!(inst.op, IrOp::CallIndirect { .. }))
            .unwrap();
        assert_eq!(value(&lifted.func, call.args[2]), 17);
        assert!(!insts.iter().any(|inst| matches!(inst.op, IrOp::BorrowSub)));
        assert!(!insts.iter().any(|inst| {
            matches!(
                inst.op,
                IrOp::CallResult {
                    register: PhysReg::Gpr(Gpr::Rax)
                }
            )
        }));
        assert!(insts.iter().any(|inst| {
            matches!(
                inst.op,
                IrOp::CallResult {
                    register: PhysReg::Xmm(_)
                }
            )
        }));
        assert_eq!(
            value(&lifted.func, lifted.block_exit[0][Gpr::Rax.index()]),
            9
        );
    }

    #[test]
    fn decoded_register_use_on_either_successor_keeps_its_definition() {
        for used_by in [None, Some(1), Some(2)] {
            let mut code = vec![0x41, 0xba, 0x44, 0x33, 0x22, 0x11, 0x85, 0xc9, 0x74, 6];
            code.extend_from_slice(if used_by == Some(1) {
                &[0x44, 0x89, 0xd0, 0x90, 0x90, 0xc3]
            } else {
                &[0xb8, 7, 0, 0, 0, 0xc3]
            });
            code.extend_from_slice(if used_by == Some(2) {
                &[0x44, 0x89, 0xd0, 0x90, 0x90, 0xc3]
            } else {
                &[0xb8, 9, 0, 0, 0, 0xc3]
            });
            let lifted = lift(
                &code,
                vec![
                    BasicBlock {
                        start: Rva::new(0x1000),
                        end: Rva::new(0x100a),
                        successors: vec![Rva::new(0x1010), Rva::new(0x100a)],
                        terminator: Terminator::Branch {
                            taken: Rva::new(0x1010),
                            not_taken: Rva::new(0x100a),
                        },
                    },
                    BasicBlock {
                        start: Rva::new(0x100a),
                        end: Rva::new(0x1010),
                        successors: vec![],
                        terminator: Terminator::Return,
                    },
                    BasicBlock {
                        start: Rva::new(0x1010),
                        end: Rva::new(0x1000 + code.len() as u32),
                        successors: vec![],
                        terminator: Terminator::Return,
                    },
                ],
            );
            assert_eq!(
                lifted.func.blocks[0]
                    .insts
                    .iter()
                    .any(|inst| matches!(inst.op, IrOp::Const(0x1122_3344))),
                used_by.is_some()
            );
            assert_eq!(
                value(&lifted.func, lifted.block_exit[2][Gpr::Rax.index()]),
                if used_by == Some(2) { 0x1122_3344 } else { 9 }
            );
            assert_eq!(
                value(&lifted.func, lifted.block_exit[1][Gpr::Rax.index()]),
                if used_by == Some(1) { 0x1122_3344 } else { 7 }
            );
        }
    }

    #[test]
    fn unknown_call_keeps_loaded_float_argument_and_possible_float_return() {
        let lifted = linear(&[
            0x48, 0x83, 0xec, 0x28, 0xf2, 0x0f, 0x10, 0x01, 0x41, 0xff, 0xd3, 0x48, 0x83, 0xc4,
            0x28, 0xc3,
        ]);
        let insts = &lifted.func.blocks[0].insts;
        assert!(insts.iter().any(|inst| matches!(inst.op, IrOp::Load)));
        let call = insts
            .iter()
            .find(|inst| matches!(inst.op, IrOp::CallIndirect { .. }))
            .unwrap();
        assert_eq!(call.args.len(), 10);
        let float_return = lifted.block_exit[0][16];
        assert!(insts.iter().any(|inst| {
            inst.dest == Some(float_return)
                && matches!(
                    inst.op,
                    IrOp::CallResult {
                        register: PhysReg::Xmm(_)
                    }
                )
        }));
    }

    #[test]
    fn stack_probe_effect_retains_size_and_logical_frame_address() {
        use kamy_core::ir::{BlockId, Inst, IrBlock};

        let mut function = IrFunction {
            entry: BlockId(0),
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![
                    Inst {
                        dest: Some(ValueId(0)),
                        op: IrOp::Const(8192),
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: Some(ValueId(1)),
                        op: IrOp::FrameAddress(-40),
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: None,
                        op: IrOp::StackProbe,
                        args: vec![ValueId(0), ValueId(1)],
                        ty: IrType::I64,
                    },
                ],
                term: IrTerminator::Ret,
            }],
            next_value: 2,
        };
        crate::optimize(&mut function);
        let insts = &function.blocks[0].insts;
        assert_eq!(insts.len(), 3);
        assert!(matches!(insts[0].op, IrOp::Const(8192)));
        assert!(matches!(insts[1].op, IrOp::FrameAddress(-40)));
        assert!(matches!(insts[2].op, IrOp::StackProbe));
        assert_eq!(insts[2].args, vec![ValueId(0), ValueId(1)]);
    }
}
