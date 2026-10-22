use std::collections::HashSet;

use kamy_core::ir::{IrFunction, IrOp, IrTerminator, PhysReg, Win64Default, XmmReg};
use kamy_core::{
    BasicBlock, FrameAnalysis, Function, Machine, Module, RejectionReason, Rva, Section,
    SectionFlags, Symbol, SymbolId, SymbolKind, Terminator,
};
use kamy_lift::{LiftResult, construct_ssa, lift_function};
use kamy_transforms::mba::{MbaBitwidths, MbaConfig, MbaSemantics};

const BASE: u64 = 0x1_8000_0000;
const ENTRY: u32 = 0x1020;

fn compiler_array_loop() -> (Vec<u8>, Function) {
    let code = vec![
        0xb8, 0x00, 0x60, 0x00, 0x00, 0xe8, 0xe6, 0x02, 0x00, 0x00, 0x48, 0x29, 0xc4, 0x48, 0x8d,
        0x44, 0x24, 0x18, 0x31, 0xd2, 0x66, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x4c, 0x8d, 0x04, 0x11, 0x4c, 0x89, 0x40, 0xe8, 0x4c, 0x8d, 0x04, 0x11, 0x49,
        0x83, 0xc0, 0x07, 0x4c, 0x89, 0x40, 0xf0, 0x4c, 0x8d, 0x44, 0x11, 0x0e, 0x4c, 0x89, 0x40,
        0xf8, 0x4c, 0x8d, 0x04, 0x11, 0x49, 0x83, 0xc0, 0x15, 0x4c, 0x89, 0x00, 0x48, 0x83, 0xc0,
        0x20, 0x48, 0x83, 0xc2, 0x1c, 0x48, 0x81, 0xfa, 0x00, 0x54, 0x00, 0x00, 0x75, 0xc7, 0xb9,
        0x00, 0x0c, 0x00, 0x00, 0x31, 0xc0, 0x48, 0x03, 0x44, 0xcc, 0xf8, 0x48, 0x03, 0x44, 0xcc,
        0xf0, 0x48, 0x03, 0x44, 0xcc, 0xe8, 0x48, 0x03, 0x44, 0xcc, 0xe0, 0x48, 0x03, 0x44, 0xcc,
        0xd8, 0x48, 0x03, 0x44, 0xcc, 0xd0, 0x48, 0x03, 0x44, 0xcc, 0xc8, 0x48, 0x03, 0x44, 0xcc,
        0xc0, 0x48, 0x83, 0xc1, 0xf8, 0x75, 0xd2, 0x48, 0x81, 0xc4, 0x00, 0x60, 0x00, 0x00, 0xc3,
    ];
    let at = |offset| Rva::new(ENTRY + offset);
    let block = |start, end, terminator, successors| BasicBlock {
        start: at(start),
        end: at(end),
        successors,
        terminator,
    };
    let function = Function {
        entry: at(0),
        blocks: vec![
            block(0, 10, Terminator::Fallthrough(at(10)), vec![at(10)]),
            block(10, 32, Terminator::Fallthrough(at(32)), vec![at(32)]),
            block(
                32,
                89,
                Terminator::Branch {
                    taken: at(32),
                    not_taken: at(89),
                },
                vec![at(32), at(89)],
            ),
            block(89, 96, Terminator::Fallthrough(at(96)), vec![at(96)]),
            block(
                96,
                142,
                Terminator::Branch {
                    taken: at(96),
                    not_taken: at(142),
                },
                vec![at(96), at(142)],
            ),
            block(142, 150, Terminator::Return, vec![]),
        ],
    };
    (code, function)
}

fn lift(code: Vec<u8>, function: Function) -> LiftResult {
    let module = Module {
        image_base: BASE,
        machine: Machine::X64,
        entry_point: Some(function.entry),
        sections: vec![Section {
            name: ".text".into(),
            rva: function.entry,
            virtual_size: code.len() as u32,
            data: code,
            flags: SectionFlags {
                read: true,
                write: false,
                execute: true,
            },
        }],
        symbols: vec![Symbol {
            id: SymbolId::Host {
                rva: Rva::new(0x1310),
            },
            name: "__chkstk".into(),
            rva: Rva::new(0x1310),
            kind: SymbolKind::Function,
        }],
        relocations: vec![],
        functions: vec![function.clone()],
    };
    let lifted = lift_function(&module, &function, &Win64Default, &[]);
    assert!(!lifted.unsupported);
    lifted
}

fn assert_defined_uses(function: &IrFunction) {
    let definitions: HashSet<_> = function
        .blocks
        .iter()
        .flat_map(|block| {
            block
                .phis
                .iter()
                .map(|phi| phi.dest)
                .chain(block.insts.iter().filter_map(|inst| inst.dest))
        })
        .collect();
    for block in &function.blocks {
        for value in block
            .phis
            .iter()
            .flat_map(|phi| phi.args.iter().map(|(_, value)| value))
            .chain(block.insts.iter().flat_map(|inst| &inst.args))
        {
            assert!(
                definitions.contains(value),
                "undefined SSA operand {value:?}"
            );
        }
        if let IrTerminator::Branch { cond, .. } = block.term {
            assert!(definitions.contains(&cond));
        }
    }
}

#[test]
fn compiler_pointer_zeroing_and_unrolled_array_loops_lower_with_full_mba() {
    for mba in [false, true] {
        let (code, function) = compiler_array_loop();
        let mut lifted = lift(code, function);
        construct_ssa(&mut lifted).unwrap();
        kamy_transforms::optimize(&mut lifted.func);
        assert_defined_uses(&lifted.func);
        if mba {
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
                        bit8: true,
                        bit16: true,
                        bit32: true,
                        bit64: true,
                    },
                },
            };
            assert!(pass.run_with_intensity(&mut lifted.func, 1.0));
        }
        assert_defined_uses(&lifted.func);
        assert!(
            lifted
                .func
                .blocks
                .iter()
                .flat_map(|block| &block.insts)
                .any(|inst| matches!(inst.op, IrOp::FrameIndex { .. }))
        );
        assert_eq!(
            lifted
                .func
                .blocks
                .iter()
                .flat_map(|block| &block.insts)
                .filter(|inst| matches!(inst.op, IrOp::StackProbe))
                .count(),
            1
        );
        assert!(lifted.func.blocks.iter().any(|block| {
            matches!(block.term, IrTerminator::Ret)
                && block.insts.iter().any(|inst| {
                    matches!(inst.op, IrOp::Use)
                        && inst.args.iter().any(|value| {
                            lifted.reg_pins.get(value) == Some(&PhysReg::Xmm(XmmReg::Xmm0))
                        })
                })
        }));
        let analysis =
            FrameAnalysis::analyze(&lifted.func, &lifted.rsp_chain, &lifted.reg_pins).unwrap();
        assert_eq!(analysis.original_size, 24584);
        assert_eq!(analysis.outgoing_size, 0);
        let allocation =
            kamy_codegen::allocate_registers(&lifted.func, &lifted.rsp_chain, &lifted.reg_pins)
                .unwrap();
        let selected = kamy_codegen::select_instructions(&lifted.func, &allocation);
        assert!(
            !kamy_codegen::relocate(&selected.instructions, BASE + 0x4000)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn compiler_array_loop_rejects_unknown_nondivisible_and_wrapping_trips() {
    for case in 0..3 {
        let (mut code, function) = compiler_array_loop();
        match case {
            0 => code[18..20].copy_from_slice(&[0x89, 0xd2]),
            1 => code[83..87].copy_from_slice(&21505u32.to_le_bytes()),
            _ => code[90..94].copy_from_slice(&0u32.to_le_bytes()),
        }
        let mut lifted = lift(code, function);
        assert_eq!(
            construct_ssa(&mut lifted).unwrap_err(),
            RejectionReason::FrameDynamic
        );
    }
}
