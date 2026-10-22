use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, OpAccess, OpKind, Register,
};
use kamy_core::ir::{
    CallingConvLookup, FnSignature, Gpr, IrFunction, IrOp, IrTerminator, PhysReg, ValueId,
    Win64Default, XmmReg,
};
use kamy_core::{
    BasicBlock, Function, LinkField, Machine, Module, OperandReference, Reference, ReferenceOrigin,
    Rva, Section, SectionFlags, Symbol, SymbolId, SymbolKind, SymbolicExpression, Terminator,
};
use kamy_lift::{LiftResult, lift_function};

const BASE: u64 = 0x1_4000_0000;
const TEXT: u32 = 0x1000;
const LITERAL: u32 = 0x2000;

fn symbol(name: &str) -> SymbolId {
    SymbolId::Authored {
        module: "native-flags".into(),
        symbol: name.into(),
    }
}

struct AuthoredCc;

impl CallingConvLookup for AuthoredCc {
    fn lookup(&self, _: u64) -> Option<FnSignature> {
        None
    }

    fn lookup_symbol(&self, source: &SymbolId) -> Option<FnSignature> {
        (source == &symbol("function")).then(Win64Default::default_signature)
    }
}

fn append_rip(code: &mut Vec<u8>, opcode: &[u8], addend: u32, suffix: &[u8]) {
    let next = TEXT + (code.len() + opcode.len() + 4 + suffix.len()) as u32;
    let displacement = (i64::from(LITERAL + addend) - i64::from(next)) as i32;
    code.extend_from_slice(opcode);
    code.extend_from_slice(&displacement.to_le_bytes());
    code.extend_from_slice(suffix);
}

fn prologue(integer: u32) -> Vec<u8> {
    let mut code = vec![0xb8, 0, 0, 0, 0, 0xb9];
    code.extend_from_slice(&integer.to_le_bytes());
    append_rip(&mut code, &[0xf2, 0x0f, 0x10, 0x05], 0, &[]);
    append_rip(&mut code, &[0xf2, 0x0f, 0x10, 0x0d], 8, &[]);
    code.extend_from_slice(&[0x85, 0xc9]);
    code
}

fn lift_program(mut code: Vec<u8>, branch: bool) -> LiftResult {
    let at = |offset| Rva::new(TEXT + offset as u32);
    let blocks = if branch {
        code.extend_from_slice(&[0x74, 6]);
        let not_taken = code.len();
        code.extend_from_slice(&[0xb8, 13, 0, 0, 0, 0xc3]);
        let taken = code.len();
        code.extend_from_slice(&[0xb8, 29, 0, 0, 0, 0xc3]);
        vec![
            BasicBlock {
                start: at(0),
                end: at(not_taken),
                successors: vec![at(taken), at(not_taken)],
                terminator: Terminator::Branch {
                    taken: at(taken),
                    not_taken: at(not_taken),
                },
            },
            BasicBlock {
                start: at(not_taken),
                end: at(taken),
                successors: vec![],
                terminator: Terminator::Return,
            },
            BasicBlock {
                start: at(taken),
                end: at(code.len()),
                successors: vec![],
                terminator: Terminator::Return,
            },
        ]
    } else {
        code.extend_from_slice(&[0x0f, 0x94, 0xc0, 0xc3]);
        vec![BasicBlock {
            start: at(0),
            end: at(code.len()),
            successors: vec![],
            terminator: Terminator::Return,
        }]
    };
    lift_blocks(code, blocks)
}

fn lift_blocks(code: Vec<u8>, blocks: Vec<BasicBlock>) -> LiftResult {
    lift_blocks_with_cc(code, blocks, &AuthoredCc)
}

fn lift_blocks_with_cc(
    code: Vec<u8>,
    blocks: Vec<BasicBlock>,
    cc: &dyn CallingConvLookup,
) -> LiftResult {
    let at = |offset| Rva::new(TEXT + offset as u32);
    let mut references = Vec::new();
    let mut decoder = Decoder::with_ip(64, &code, BASE + u64::from(TEXT), DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.flow_control() == FlowControl::Call {
            let constants = decoder.get_constant_offsets(&instruction);
            let instruction_offset = (instruction.ip() - BASE - u64::from(TEXT)) as u32;
            references.push(OperandReference {
                instruction: at(instruction_offset as usize),
                operand: 0,
                reference: Reference {
                    source: symbol("function"),
                    offset: instruction_offset + constants.immediate_offset() as u32,
                    expression: SymbolicExpression::symbol(symbol("callee")),
                    field: LinkField::Relative32 { bias: 0 },
                    origin: ReferenceOrigin::Authored,
                },
            });
            continue;
        }
        if !instruction.is_ip_rel_memory_operand() {
            continue;
        }
        let constants = decoder.get_constant_offsets(&instruction);
        let instruction_offset = (instruction.ip() - BASE - u64::from(TEXT)) as u32;
        references.push(OperandReference {
            instruction: at(instruction_offset as usize),
            operand: (0..instruction.op_count())
                .find(|&operand| instruction.op_kind(operand) == OpKind::Memory)
                .unwrap(),
            reference: Reference {
                source: symbol("function"),
                offset: instruction_offset + constants.displacement_offset() as u32,
                expression: SymbolicExpression::Symbol {
                    symbol: symbol("literal"),
                    addend: (instruction.ip_rel_memory_address() - BASE - u64::from(LITERAL))
                        as i64,
                },
                field: LinkField::Relative32 {
                    bias: (instruction.len()
                        - constants.displacement_offset()
                        - constants.displacement_size()) as u8,
                },
                origin: ReferenceOrigin::Authored,
            },
        });
    }
    let function = Function {
        entry: at(0),
        blocks,
    };
    let flags = SectionFlags {
        read: true,
        write: false,
        execute: false,
    };
    let module = Module {
        image_base: BASE,
        machine: Machine::X64,
        entry_point: Some(at(0)),
        sections: vec![
            Section {
                name: ".text".into(),
                rva: at(0),
                virtual_size: code.len() as u32,
                data: code,
                flags: SectionFlags {
                    read: true,
                    write: false,
                    execute: true,
                },
            },
            Section {
                name: ".rdata".into(),
                rva: Rva::new(LITERAL),
                virtual_size: 16,
                data: [3.0f64.to_le_bytes(), 3.0f64.to_le_bytes()].concat(),
                flags,
            },
        ],
        symbols: vec![
            Symbol {
                id: symbol("function"),
                name: "function".into(),
                rva: at(0),
                kind: SymbolKind::Function,
            },
            Symbol {
                id: symbol("literal"),
                name: "literal".into(),
                rva: Rva::new(LITERAL),
                kind: SymbolKind::Data,
            },
        ],
        relocations: vec![],
        functions: vec![function.clone()],
    };
    lift_function(&module, &function, cc, &references)
}

fn integer_value(function: &IrFunction, value: ValueId) -> u64 {
    let instruction = function
        .blocks
        .iter()
        .flat_map(|block| &block.insts)
        .find(|instruction| instruction.dest == Some(value))
        .unwrap();
    let argument = |index: usize| integer_value(function, instruction.args[index]);
    let result = match instruction.op {
        IrOp::Const(value) => value,
        IrOp::Copy | IrOp::Trunc | IrOp::Zext => argument(0),
        IrOp::And => argument(0) & argument(1),
        IrOp::Or => argument(0) | argument(1),
        IrOp::Add => argument(0).wrapping_add(argument(1)),
        IrOp::Sub => argument(0).wrapping_sub(argument(1)),
        IrOp::IsZero => u64::from(argument(0) == 0),
        IrOp::SetIf => u64::from(argument(0) != 0),
        ref unexpected => panic!("unexpected return dependency: {unexpected:?}"),
    };
    let bits = instruction.ty.bits();
    assert!(bits <= 64);
    result & (u64::MAX >> (64 - bits))
}

fn return_value(lifted: &LiftResult) -> u64 {
    assert!(!lifted.unsupported);
    let mut block = lifted.func.entry;
    loop {
        match lifted.func.block(block).term {
            IrTerminator::Ret => {
                return integer_value(
                    &lifted.func,
                    lifted.block_exit[block.0 as usize][Gpr::Rax.index()],
                );
            }
            IrTerminator::Branch {
                cond,
                taken,
                not_taken,
            } => {
                block = if integer_value(&lifted.func, cond) != 0 {
                    taken
                } else {
                    not_taken
                };
            }
            ref unexpected => panic!("unexpected consumer terminator: {unexpected:?}"),
        }
    }
}

#[test]
fn rip_native_flag_writer_with_setcc_or_branch_is_unsupported() {
    for branch in [false, true] {
        let mut code = prologue(1);
        append_rip(&mut code, &[0x66, 0x0f, 0x2e, 0x05], 8, &[]);
        // Equal doubles set ZF, opposite to the preceding nonzero integer test.
        assert!(lift_program(code, branch).unsupported);
    }
}

#[test]
fn register_native_flag_writer_with_setcc_or_branch_is_unsupported() {
    for branch in [false, true] {
        let mut code = prologue(1);
        code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc1]);
        assert!(lift_program(code, branch).unsupported);
    }
}

#[test]
fn unchanged_flags_pic_preserves_setcc_and_branch_results() {
    let instructions: &[(&[u8], &[u8])] = &[
        (&[0x66, 0x0f, 0xd4, 0x05], &[]),
        (&[0x66, 0x0f, 0x70, 0x05], &[0x1b]),
        (&[0x66, 0x0f, 0x28, 0x05], &[]),
        (&[0xf3, 0x0f, 0x6f, 0x05], &[]),
    ];
    for &(opcode, suffix) in instructions {
        for integer in [0, 1] {
            for branch in [false, true] {
                let mut code = prologue(integer);
                append_rip(&mut code, opcode, 0, suffix);
                let lifted = lift_program(code, branch);
                let expected = if branch {
                    if integer == 0 { 29 } else { 13 }
                } else {
                    u64::from(integer == 0)
                };
                assert_eq!(return_value(&lifted), expected);
            }
        }
    }
}

#[test]
fn modeled_flag_writer_replaces_preceding_integer_flags() {
    for branch in [false, true] {
        let mut code = prologue(1);
        code.extend_from_slice(&[0x83, 0xf9, 1]);
        assert_eq!(
            return_value(&lift_program(code, branch)),
            if branch { 29 } else { 1 }
        );
    }
}

#[test]
fn overwritten_native_flags_preserve_the_actual_setcc_and_branch_consumers() {
    for branch in [false, true] {
        for integer in [0, 1] {
            let mut code = prologue(integer);
            code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc1, 0x85, 0xc9]);
            let lifted = lift_program(code, branch);
            assert_eq!(
                return_value(&lifted),
                if branch {
                    if integer == 0 { 29 } else { 13 }
                } else {
                    u64::from(integer == 0)
                }
            );
            assert!(lifted.func.blocks[0].insts.iter().any(|inst| {
                matches!(&inst.op, IrOp::NativeInline(native) if native.bytes == [0x66, 0x0f, 0x2e, 0xc1])
            }));
        }
    }
}

#[test]
fn partial_overwrite_does_not_hide_a_native_carry_dependency() {
    let mut code = prologue(1);
    code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc1, 0xff, 0xc1, 0x0f, 0x92, 0xc0]);
    assert!(lift_program(code, false).unsupported);
}

#[test]
fn native_flags_are_dead_only_when_every_successor_overwrites_them() {
    for preserve_carry in [false, true] {
        let mut code = prologue(1);
        code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc1, 0xff, 0xc1, 0x74, 6]);
        let split = code.len();
        code.extend_from_slice(&[0x85, 0xd2, 0x0f, 0x92, 0xc0, 0xc3]);
        let taken = code.len();
        code.extend_from_slice(if preserve_carry {
            &[0xff, 0xc2, 0x0f, 0x92, 0xc0, 0xc3]
        } else {
            &[0x85, 0xd2, 0x0f, 0x92, 0xc0, 0xc3]
        });
        let at = |offset| Rva::new(TEXT + offset as u32);
        let blocks = vec![
            BasicBlock {
                start: at(0),
                end: at(split),
                successors: vec![at(taken), at(split)],
                terminator: Terminator::Branch {
                    taken: at(taken),
                    not_taken: at(split),
                },
            },
            BasicBlock {
                start: at(split),
                end: at(taken),
                successors: vec![],
                terminator: Terminator::Return,
            },
            BasicBlock {
                start: at(taken),
                end: at(code.len()),
                successors: vec![],
                terminator: Terminator::Return,
            },
        ];
        let mut lifted = lift_blocks(code, blocks);
        assert_eq!(lifted.unsupported, preserve_carry);
        if !preserve_carry {
            kamy_lift::construct_ssa(&mut lifted).unwrap();
            assert_eq!(return_value(&lifted), 0);
        }
    }
}

#[test]
fn zero_count_shift_is_not_a_proven_flag_overwrite() {
    for shift in [&[0xd3, 0xe2][..], &[0xc1, 0xe2, 0][..]] {
        let mut code = prologue(1);
        code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc1]);
        code.extend_from_slice(shift);
        assert!(lift_program(code, false).unsupported);
    }
}

#[test]
fn unmodeled_native_flag_reads_remain_rejected_after_dead_writes() {
    let mut code = prologue(1);
    code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc1, 0x85, 0xc9, 0x83, 0xd2, 0]);
    assert!(lift_program(code, false).unsupported);
}

#[test]
fn back_edge_preserves_native_carry_until_a_real_overwrite() {
    for overwrite in [false, true] {
        let mut code = prologue(1);
        code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc1, 0xeb, 0]);
        let header = code.len();
        code.extend_from_slice(&[0xff, 0xc9, 0x75, 0xfc]);
        let exit = code.len();
        if overwrite {
            code.extend_from_slice(&[0x85, 0xd2]);
        }
        code.extend_from_slice(&[0x0f, 0x92, 0xc0, 0xc3]);
        let at = |offset| Rva::new(TEXT + offset as u32);
        let blocks = vec![
            BasicBlock {
                start: at(0),
                end: at(header),
                successors: vec![at(header)],
                terminator: Terminator::Jump(at(header)),
            },
            BasicBlock {
                start: at(header),
                end: at(exit),
                successors: vec![at(header), at(exit)],
                terminator: Terminator::Branch {
                    taken: at(header),
                    not_taken: at(exit),
                },
            },
            BasicBlock {
                start: at(exit),
                end: at(code.len()),
                successors: vec![],
                terminator: Terminator::Return,
            },
        ];
        assert_eq!(lift_blocks(code, blocks).unsupported, !overwrite);
    }
}

#[test]
fn calls_do_not_supply_an_unproven_native_flag_kill() {
    struct KnownCall;
    impl CallingConvLookup for KnownCall {
        fn lookup(&self, _: u64) -> Option<FnSignature> {
            None
        }

        fn lookup_symbol(&self, source: &SymbolId) -> Option<FnSignature> {
            (source == &symbol("function") || source == &symbol("callee"))
                .then(Win64Default::default_signature)
        }
    }

    for native_flag_writer in [false, true] {
        let mut code = prologue(1);
        code.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]);
        if native_flag_writer {
            code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc1]);
        }
        code.extend_from_slice(&[
            0xe8, 0, 0, 0, 0, 0x85, 0xc9, 0x0f, 0x94, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ]);
        let blocks = vec![BasicBlock {
            start: Rva::new(TEXT),
            end: Rva::new(TEXT + code.len() as u32),
            successors: vec![],
            terminator: Terminator::Return,
        }];
        let lifted = lift_blocks_with_cc(code, blocks, &KnownCall);
        assert!(lifted.func.blocks[0].insts.iter().any(|inst| {
            matches!(&inst.op, IrOp::Call { target, .. }
                if target.expression == SymbolicExpression::symbol(symbol("callee")))
        }));
        assert_eq!(lifted.unsupported, native_flag_writer);
    }
}

#[test]
fn authored_flag_preservation_is_a_real_return_boundary_use() {
    struct PreservingFlags;
    impl CallingConvLookup for PreservingFlags {
        fn lookup(&self, _: u64) -> Option<FnSignature> {
            None
        }

        fn lookup_symbol(&self, source: &SymbolId) -> Option<FnSignature> {
            (source == &symbol("function")).then(|| {
                let mut signature = Win64Default::default_signature();
                signature
                    .clobbers
                    .retain(|reg| !matches!(reg, PhysReg::Flag(_)));
                signature
            })
        }
    }

    let mut code = prologue(1);
    code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc1, 0xb8, 3, 0, 0, 0, 0xc3]);
    let blocks = vec![BasicBlock {
        start: Rva::new(TEXT),
        end: Rva::new(TEXT + code.len() as u32),
        successors: vec![],
        terminator: Terminator::Return,
    }];
    assert_eq!(return_value(&lift_blocks(code.clone(), blocks.clone())), 3);
    assert!(lift_blocks_with_cc(code, blocks, &PreservingFlags).unsupported);
}

#[test]
fn native_unmodeled_register_classes_are_not_silently_ignored() {
    for (bytes, expected_code, register, access) in [
        // VEX zeroing writes the full ZMM register without reading a YMM input.
        (
            &[0xc5, 0xfc, 0x57, 0xc0][..],
            Code::VEX_Vxorps_ymm_ymm_ymmm256,
            Register::ZMM0,
            OpAccess::Write,
        ),
        (
            &[0xc5, 0xfc, 0x57, 0xc1][..],
            Code::VEX_Vxorps_ymm_ymm_ymmm256,
            Register::YMM0,
            OpAccess::Read,
        ),
        (
            &[0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc1][..],
            Code::EVEX_Vaddps_zmm_k1z_zmm_zmmm512b32_er,
            Register::ZMM0,
            OpAccess::Write,
        ),
        (
            &[0x0f, 0xd4, 0xc1][..],
            Code::Paddq_mm_mmm64,
            Register::MM0,
            OpAccess::ReadWrite,
        ),
        (
            &[0xd8, 0xc1][..],
            Code::Fadd_st0_sti,
            Register::ST0,
            OpAccess::ReadWrite,
        ),
        (
            &[0xc5, 0xfc, 0x47, 0xc0][..],
            Code::VEX_Kxorw_kr_kr_kr,
            Register::K0,
            OpAccess::Write,
        ),
        (
            &[0x48, 0x0f, 0xb5, 0x01][..],
            Code::Lgs_r64_m1664,
            Register::GS,
            OpAccess::Write,
        ),
    ] {
        let mut decoder = Decoder::with_ip(64, bytes, BASE + u64::from(TEXT), DecoderOptions::NONE);
        let instruction = decoder.decode();
        assert!(!instruction.is_invalid(), "invalid witness: {bytes:02x?}");
        assert_eq!(instruction.len(), bytes.len());
        assert_eq!(instruction.code(), expected_code);
        let mut factory = InstructionInfoFactory::new();
        let info = factory.info(&instruction);
        assert!(
            info.used_registers()
                .iter()
                .any(|used| used.register() == register && used.access() == access),
            "{instruction:?}: {:?}",
            info.used_registers()
        );
        let mut code = prologue(1);
        code.extend_from_slice(bytes);
        code.extend_from_slice(&[0x85, 0xc9]);
        let lifted = lift_program(code, false);
        assert!(lifted.unsupported, "unmodeled register in {instruction:?}");
        assert!(!lifted.func.blocks[0].insts.iter().any(|inst| {
            matches!(&inst.op, IrOp::NativeInline(native) if native.bytes == bytes)
        }));
    }
}

#[test]
fn native_modeled_gpr_outputs_and_memory_inputs_remain_supported() {
    for (bytes, reads, writes) in [
        (
            &[0x0f, 0x31][..],
            vec![PhysReg::Gpr(Gpr::Rsp)],
            vec![PhysReg::Gpr(Gpr::Rax), PhysReg::Gpr(Gpr::Rdx)],
        ),
        (
            &[0x66, 0x0f, 0xe7, 0x01][..],
            vec![
                PhysReg::Gpr(Gpr::Rcx),
                PhysReg::Xmm(XmmReg::Xmm0),
                PhysReg::Gpr(Gpr::Rsp),
            ],
            vec![],
        ),
    ] {
        let mut code = prologue(1);
        code.extend_from_slice(bytes);
        let lifted = lift_program(code, false);
        assert!(!lifted.unsupported);
        let insts = &lifted.func.blocks[0].insts;
        let (position, inst) = insts
            .iter()
            .enumerate()
            .find(
                |(_, inst)| matches!(&inst.op, IrOp::NativeInline(native) if native.bytes == bytes),
            )
            .unwrap();
        let IrOp::NativeInline(native) = &inst.op else {
            unreachable!();
        };
        assert_eq!(native.reads.len(), reads.len());
        assert_eq!(native.writes.len(), writes.len());
        assert_eq!(inst.args.len(), reads.len());
        assert!(native.references.is_empty());
        for register in reads {
            let index = native
                .reads
                .iter()
                .position(|read| *read == register)
                .unwrap();
            if register != PhysReg::Gpr(Gpr::Rsp) {
                assert_eq!(lifted.reg_pins.get(&inst.args[index]), Some(&register));
            }
        }
        for register in writes {
            assert!(native.writes.contains(&register));
            assert!(insts[position + 1..].iter().any(|output| {
                matches!(output.op, IrOp::Undef)
                    && output
                        .dest
                        .is_some_and(|dest| lifted.reg_pins.get(&dest) == Some(&register))
            }));
        }
    }
}

#[test]
fn segment_relative_native_memory_remains_rejected() {
    let bytes = [0x65, 0x66, 0x0f, 0xe7, 0x01];
    let mut code = prologue(1);
    code.extend_from_slice(&bytes);
    let lifted = lift_program(code, false);
    assert!(lifted.unsupported);
    assert!(
        !lifted.func.blocks[0].insts.iter().any(|inst| {
            matches!(&inst.op, IrOp::NativeInline(native) if native.bytes == bytes)
        })
    );
}

#[test]
fn legacy_scalar_native_moves_read_both_complete_xmm_inputs() {
    use kamy_core::ir::{IrType, XmmReg};

    for bytes in [&[0xf2, 0x0f, 0x10, 0xc1][..], &[0xf3, 0x0f, 0x10, 0xc1][..]] {
        let mut code = prologue(1);
        code.extend_from_slice(bytes);
        let lifted = lift_program(code, false);
        assert!(!lifted.unsupported);
        let insts = &lifted.func.blocks[0].insts;
        let native = insts
            .iter()
            .find(|inst| matches!(&inst.op, IrOp::NativeInline(native) if native.bytes == bytes))
            .unwrap();
        let IrOp::NativeInline(raw) = &native.op else {
            unreachable!();
        };
        for register in [XmmReg::Xmm0, XmmReg::Xmm1] {
            let index = raw
                .reads
                .iter()
                .position(|read| *read == PhysReg::Xmm(register))
                .unwrap();
            let input = insts
                .iter()
                .find(|inst| inst.dest == Some(native.args[index]))
                .unwrap();
            assert_eq!(input.ty, IrType::I128);
            assert_eq!(
                lifted.reg_pins.get(&native.args[index]),
                Some(&PhysReg::Xmm(register))
            );
        }
        assert_eq!(raw.writes, vec![PhysReg::Xmm(XmmReg::Xmm0)]);
    }
}
