use iced_x86::{Decoder, DecoderOptions, OpKind};
use kamy_core::ir::{
    CallingConvLookup, FnSignature, Gpr, IrFunction, IrOp, IrTerminator, ValueId, Win64Default,
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
    let mut references = Vec::new();
    let mut decoder = Decoder::with_ip(64, &code, BASE + u64::from(TEXT), DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
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
    lift_function(&module, &function, &AuthoredCc, &references)
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
