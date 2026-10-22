use std::collections::{HashMap, HashSet};

use iced_x86::{Code, Instruction, MemoryOperand, Register};
use kamy_core::RejectionReason;
use kamy_core::ir::{
    BlockId, Gpr, Inst, IrBlock, IrFunction, IrOp, IrTerminator, IrType, NativeInst, Phi, PhysReg,
    ValueId, XmmReg,
};

const SOURCE: u64 = 0x1_4000_1000;

struct Witness {
    func: IrFunction,
    pins: HashMap<ValueId, PhysReg>,
}

impl Witness {
    fn new(blocks: u32) -> Self {
        Self {
            func: IrFunction {
                entry: BlockId(0),
                next_value: 0,
                blocks: (0..blocks)
                    .map(|id| IrBlock {
                        id: BlockId(id),
                        phis: Vec::new(),
                        insts: Vec::new(),
                        term: IrTerminator::Ret,
                    })
                    .collect(),
            },
            pins: HashMap::new(),
        }
    }

    fn value(&mut self, block: usize, op: IrOp, args: &[ValueId], ty: IrType) -> ValueId {
        let dest = self.func.alloc_value();
        self.func.blocks[block].insts.push(Inst {
            dest: Some(dest),
            op,
            args: args.to_vec(),
            ty,
        });
        dest
    }

    fn effect(&mut self, block: usize, op: IrOp, args: &[ValueId], ty: IrType) {
        self.func.blocks[block].insts.push(Inst {
            dest: None,
            op,
            args: args.to_vec(),
            ty,
        });
    }

    fn input(&mut self, reg: Gpr) -> ValueId {
        let value = self.value(0, IrOp::Undef, &[], IrType::I64);
        self.pins.insert(value, PhysReg::Gpr(reg));
        value
    }

    fn constant(&mut self, block: usize, value: u64) -> ValueId {
        self.value(block, IrOp::Const(value), &[], IrType::I64)
    }

    fn store_word(&mut self, delta: i64, word: u64) {
        let address = self.value(0, IrOp::FrameAddress(delta), &[], IrType::I64);
        let word = self.constant(0, word);
        self.effect(0, IrOp::Store, &[address, word], IrType::I64);
    }

    fn join(&mut self, selector: ValueId, left: ValueId, right: ValueId) -> ValueId {
        self.func.blocks[0].term = IrTerminator::Branch {
            cond: selector,
            taken: BlockId(1),
            not_taken: BlockId(2),
        };
        self.func.blocks[1].term = IrTerminator::Jump(BlockId(3));
        self.func.blocks[2].term = IrTerminator::Jump(BlockId(3));
        let dest = self.func.alloc_value();
        self.func.blocks[3].phis.push(Phi {
            dest,
            ty: IrType::I64,
            args: vec![(BlockId(1), left), (BlockId(2), right)],
        });
        dest
    }

    fn return_value(&mut self, block: usize, value: ValueId) {
        let result = self.value(block, IrOp::Copy, &[value], IrType::I64);
        self.pins.insert(result, PhysReg::Gpr(Gpr::Rax));
        self.effect(block, IrOp::Use, &[result], IrType::I64);
    }

    fn lower(&self, address: u64) -> Result<Vec<u8>, RejectionReason> {
        let allocation = kamy_codegen::allocate_registers(&self.func, &HashSet::new(), &self.pins)?;
        assert_eq!(
            (allocation.frame.stack_size - allocation.frame.original_size) % 16,
            0
        );
        let selected = kamy_codegen::select_instructions(&self.func, &allocation);
        Ok(kamy_codegen::relocate(&selected.instructions, address).unwrap())
    }
}

fn pointer_sub(witness: &mut Witness, left: ValueId, right: ValueId, expanded: bool) -> ValueId {
    if !expanded {
        return witness.value(3, IrOp::Sub, &[left, right], IrType::I64);
    }
    let left = witness.value(3, IrOp::FrameLogical, &[left], IrType::I64);
    let right = witness.value(3, IrOp::FrameLogical, &[right], IrType::I64);
    let complement = witness.value(3, IrOp::Not, &[right], IrType::I64);
    let one = witness.constant(3, 1);
    let inner_xor = witness.value(3, IrOp::Xor, &[complement, one], IrType::I64);
    let inner_and = witness.value(3, IrOp::And, &[complement, one], IrType::I64);
    let inner_shift = witness.value(3, IrOp::Shl, &[inner_and, one], IrType::I64);
    let negated = witness.value(3, IrOp::Add, &[inner_xor, inner_shift], IrType::I64);
    let outer_xor = witness.value(3, IrOp::Xor, &[left, negated], IrType::I64);
    let outer_and = witness.value(3, IrOp::And, &[left, negated], IrType::I64);
    let outer_shift = witness.value(3, IrOp::Shl, &[outer_and, one], IrType::I64);
    witness.value(3, IrOp::Add, &[outer_xor, outer_shift], IrType::I64)
}

fn comparison_witness(right_delta: i64, expanded: bool) -> Witness {
    let mut witness = Witness::new(4);
    let selector = witness.input(Gpr::Rcx);
    let output = witness.input(Gpr::Rdx);
    let anchor = witness.value(0, IrOp::FrameAddress(-72), &[], IrType::I64);
    let right = witness.value(0, IrOp::FrameAddress(right_delta), &[], IrType::I64);
    let incoming = witness.value(0, IrOp::FrameAddress(8), &[], IrType::I64);
    witness.store_word(-72, 0x1122_3344_5566_7788);
    witness.store_word(right_delta, 0x8877_6655_4433_2211);
    let pointer = witness.join(selector, anchor, right);
    let pointer = witness.value(3, IrOp::Copy, &[pointer], IrType::I64);
    let difference = pointer_sub(&mut witness, pointer, anchor, expanded);
    let borrow = witness.value(3, IrOp::BorrowSub, &[pointer, anchor], IrType::I8);
    let reverse = witness.value(3, IrOp::BorrowSub, &[anchor, pointer], IrType::I8);
    let cross_difference = pointer_sub(&mut witness, pointer, incoming, expanded);
    let loaded = witness.value(3, IrOp::Load, &[pointer], IrType::I64);
    let valid = witness.value(3, IrOp::BoolNot, &[borrow], IrType::I8);
    for (index, value) in [difference, borrow, reverse, cross_difference, loaded]
        .into_iter()
        .enumerate()
    {
        let wide = if index == 1 || index == 2 {
            witness.value(3, IrOp::Zext, &[value], IrType::I64)
        } else {
            value
        };
        let offset = witness.constant(3, index as u64 * 8);
        let address = witness.value(3, IrOp::Add, &[output, offset], IrType::I64);
        witness.effect(3, IrOp::Store, &[address, wide], IrType::I64);
    }
    let result = witness.value(3, IrOp::Zext, &[valid], IrType::I64);
    witness.return_value(3, result);
    witness
}

#[test]
fn finite_pointer_comparisons_and_differences_use_original_coordinates() {
    for (right_delta, expanded) in [(-64, false), (16, false), (-64, true), (16, true)] {
        let witness = comparison_witness(right_delta, expanded);
        witness.lower(SOURCE).unwrap();
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let executable = native::Executable::new(&witness);
            let function: unsafe extern "system" fn(u64, *mut u64) -> u64 =
                unsafe { core::mem::transmute(executable.address()) };
            for selector in [0, 1] {
                let mut output = [0; 5];
                assert_eq!(unsafe { function(selector, output.as_mut_ptr()) }, 1);
                let delta = if selector == 1 { -72 } else { right_delta };
                assert_eq!(
                    output,
                    [
                        (delta + 72) as u64,
                        0,
                        u64::from(selector == 0),
                        (delta - 8) as u64,
                        if selector == 1 {
                            0x1122_3344_5566_7788
                        } else {
                            0x8877_6655_4433_2211
                        },
                    ],
                    "right_delta={right_delta} expanded={expanded} selector={selector}"
                );
            }
        }
    }
}

fn native_vector_read(
    base: Register,
    index: Register,
    scale: u32,
    displacement: i64,
    aligned: bool,
) -> Vec<u8> {
    let memory = MemoryOperand::new(base, index, scale, displacement, 8, false, Register::None);
    let instruction = if aligned {
        Instruction::with3(
            Code::Pshufd_xmm_xmmm128_imm8,
            Register::XMM0,
            memory,
            0xe4u32,
        )
    } else {
        Instruction::with2(Code::Movdqu_xmm_xmmm128, Register::XMM0, memory)
    }
    .unwrap();
    kamy_codegen::relocate(&[instruction], SOURCE).unwrap()
}

fn native_read(
    witness: &mut Witness,
    block: usize,
    output: ValueId,
    address: (Option<ValueId>, Option<ValueId>, u32, i64),
    aligned: bool,
) {
    let (base, index, scale, displacement) = address;
    let mut reads = Vec::new();
    let mut args = Vec::new();
    for (value, register) in [(base, Gpr::Rcx), (index, Gpr::Rax)] {
        if let Some(value) = value {
            reads.push(PhysReg::Gpr(register));
            args.push(value);
        }
    }
    witness.effect(
        block,
        IrOp::NativeInline(NativeInst {
            bytes: native_vector_read(
                if base.is_some() {
                    Register::RCX
                } else {
                    Register::None
                },
                if index.is_some() {
                    Register::RAX
                } else {
                    Register::None
                },
                scale,
                displacement,
                aligned,
            ),
            references: Vec::new(),
            reads,
            writes: vec![PhysReg::Xmm(XmmReg::Xmm0)],
        }),
        &args,
        IrType::I128,
    );
    let result = witness.value(block, IrOp::Undef, &[], IrType::I128);
    witness.pins.insert(result, PhysReg::Xmm(XmmReg::Xmm0));
    witness.effect(block, IrOp::Store, &[output, result], IrType::I128);
    let one = witness.constant(block, 1);
    witness.return_value(block, one);
}

fn static_native_witness(
    pointer_delta: i64,
    scalar: i64,
    pointer_index: bool,
    scale: u32,
    displacement: i64,
    no_base: bool,
) -> Witness {
    let effective = pointer_delta
        + if no_base {
            0
        } else {
            scalar * if pointer_index { 1 } else { i64::from(scale) }
        }
        + displacement;
    let mut witness = Witness::new(1);
    let output = witness.input(Gpr::Rdx);
    let pointer = witness.value(0, IrOp::FrameAddress(pointer_delta), &[], IrType::I64);
    let scalar = witness.constant(0, scalar as u64);
    witness.store_word(effective, 0x0123_4567_89ab_cdef);
    witness.store_word(effective + 8, 0xfedc_ba98_7654_3210);
    let (base, index) = if no_base {
        (None, Some(pointer))
    } else if pointer_index {
        (Some(scalar), Some(pointer))
    } else {
        (Some(pointer), Some(scalar))
    };
    native_read(
        &mut witness,
        0,
        output,
        (base, index, scale, displacement),
        effective.rem_euclid(16) == 8,
    );
    witness
}

#[test]
fn static_native_sib_aliases_preserve_objects_across_coordinate_split() {
    for (pointer_delta, scalar, pointer_index, scale, displacement, no_base) in [
        (-40, 48, true, 1, 0, false),
        (-40, 48, false, 1, 0, false),
        (-40, 0, true, 1, 48, true),
        (8, -88, true, 1, 0, false),
        (8, -88, false, 1, 0, false),
        (-40, 24, false, 2, 0, false),
        (-40, 12, false, 4, 0, false),
        (-40, 6, false, 8, 0, false),
        (-40, 5, false, 8, 8, false),
        (-40, 24, true, 1, 0, false),
        (8, -80, true, 1, 0, false),
        (8, -80, false, 1, 0, false),
        (-40, -32, false, 1, 0, false),
        (8, 0, false, 1, 0, false),
        (-72, 0, true, 1, 0, true),
    ] {
        let witness = static_native_witness(
            pointer_delta,
            scalar,
            pointer_index,
            scale,
            displacement,
            no_base,
        );
        witness.lower(SOURCE).unwrap();
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let executable = native::Executable::new(&witness);
            let function: unsafe extern "system" fn(u64, *mut u64) -> u64 =
                unsafe { core::mem::transmute(executable.address()) };
            let mut output = [0; 2];
            assert_eq!(unsafe { function(0, output.as_mut_ptr()) }, 1);
            assert_eq!(
                output,
                [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210],
                "delta={pointer_delta} scalar={scalar} pointer_index={pointer_index} scale={scale} displacement={displacement} no_base={no_base}"
            );
        }
    }
}

#[test]
fn finite_native_index_aliases_rebase_each_selected_coordinate_zone() {
    for (left, right, adjustment) in [(-80, -64, 88), (8, 24, -88), (-80, 16, 8)] {
        for pointer_index in [false, true] {
            let mut witness = Witness::new(4);
            let selector = witness.input(Gpr::Rcx);
            let output = witness.input(Gpr::Rdx);
            let left_pointer = witness.value(0, IrOp::FrameAddress(left), &[], IrType::I64);
            let right_pointer = witness.value(0, IrOp::FrameAddress(right), &[], IrType::I64);
            let scalar = witness.constant(0, adjustment as u64);
            for (delta, first, second) in [
                (
                    left + adjustment,
                    0x1111_2222_3333_4444,
                    0x5555_6666_7777_8888,
                ),
                (
                    right + adjustment,
                    0x9999_aaaa_bbbb_cccc,
                    0xdddd_eeee_ffff_0000,
                ),
            ] {
                witness.store_word(delta, first);
                witness.store_word(delta + 8, second);
            }
            let pointer = witness.join(selector, left_pointer, right_pointer);
            let (base, index) = if pointer_index {
                (Some(scalar), Some(pointer))
            } else {
                (Some(pointer), Some(scalar))
            };
            native_read(&mut witness, 3, output, (base, index, 1, 0), false);
            witness.lower(SOURCE).unwrap();
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                let executable = native::Executable::new(&witness);
                let function: unsafe extern "system" fn(u64, *mut u64) -> u64 =
                    unsafe { core::mem::transmute(executable.address()) };
                for selector in [0, 1] {
                    let mut output = [0; 2];
                    assert_eq!(unsafe { function(selector, output.as_mut_ptr()) }, 1);
                    assert_eq!(
                        output,
                        if selector == 1 {
                            [0x1111_2222_3333_4444, 0x5555_6666_7777_8888]
                        } else {
                            [0x9999_aaaa_bbbb_cccc, 0xdddd_eeee_ffff_0000]
                        },
                        "left={left} right={right} adjustment={adjustment} pointer_index={pointer_index} selector={selector}"
                    );
                }
            }
        }
    }
}

#[test]
fn ordinary_native_scalar_indices_keep_runtime_data_addresses() {
    let mut witness = Witness::new(1);
    let input = witness.input(Gpr::Rcx);
    let output = witness.input(Gpr::Rdx);
    let index = witness.constant(0, 2);
    native_read(
        &mut witness,
        0,
        output,
        (Some(input), Some(index), 8, 0),
        false,
    );
    witness.lower(SOURCE).unwrap();
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let executable = native::Executable::new(&witness);
        let function: unsafe extern "system" fn(*const u64, *mut u64) -> u64 =
            unsafe { core::mem::transmute(executable.address()) };
        let input = [11, 22, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let mut output = [0; 2];
        assert_eq!(unsafe { function(input.as_ptr(), output.as_mut_ptr()) }, 1);
        assert_eq!(output, [input[2], input[3]]);
    }
}

#[test]
fn unprovable_native_sib_and_split_extent_fail_with_frame_causes() {
    for pointer_index in [false, true] {
        let crossing = static_native_witness(-40, 32, pointer_index, 1, 0, false);
        assert_eq!(
            crossing.lower(SOURCE).unwrap_err(),
            RejectionReason::FrameConflict
        );
    }
    for shape in 0..3 {
        let mut witness = Witness::new(1);
        let unknown = witness.input(Gpr::Rcx);
        let output = witness.input(Gpr::Rdx);
        let pointer = witness.value(0, IrOp::FrameAddress(-40), &[], IrType::I64);
        let constant = witness.constant(0, 48);
        let other = witness.value(0, IrOp::FrameAddress(8), &[], IrType::I64);
        let (base, index, scale) = match shape {
            0 => (Some(unknown), Some(pointer), 1),
            1 => (Some(constant), Some(pointer), 2),
            _ => (Some(other), Some(pointer), 1),
        };
        native_read(&mut witness, 0, output, (base, index, scale, 0), false);
        assert_eq!(
            witness.lower(SOURCE).unwrap_err(),
            RejectionReason::FrameDynamic
        );
    }
}

fn native_bits(
    witness: &mut Witness,
    block: usize,
    base: ValueId,
    index: ValueId,
    code: Code,
    locked: bool,
) {
    let index_register = match code {
        Code::Bt_rm16_r16 | Code::Bts_rm16_r16 | Code::Btr_rm16_r16 | Code::Btc_rm16_r16 => {
            Register::CX
        }
        Code::Bt_rm32_r32 | Code::Bts_rm32_r32 | Code::Btr_rm32_r32 | Code::Btc_rm32_r32 => {
            Register::ECX
        }
        _ => Register::RCX,
    };
    let mut instruction = Instruction::with2(
        code,
        MemoryOperand::with_base(Register::RAX),
        index_register,
    )
    .unwrap();
    instruction.set_has_lock_prefix(locked);
    witness.effect(
        block,
        IrOp::NativeInline(NativeInst {
            bytes: kamy_codegen::relocate(&[instruction], SOURCE).unwrap(),
            references: Vec::new(),
            reads: vec![PhysReg::Gpr(Gpr::Rax), PhysReg::Gpr(Gpr::Rcx)],
            writes: Vec::new(),
        }),
        &[base, index],
        IrType::I64,
    );
}

#[test]
fn native_bit_strings_do_not_target_generated_homes() {
    let mut witness = Witness::new(1);
    witness.store_word(8, 0);
    let base = witness.value(0, IrOp::FrameAddress(-40), &[], IrType::I64);
    let narrow = witness.value(0, IrOp::Const(384), &[], IrType::I32);
    let index = witness.value(0, IrOp::Zext, &[narrow], IrType::I64);
    native_bits(&mut witness, 0, base, index, Code::Bts_rm64_r64, false);
    let selected_word = witness.value(0, IrOp::FrameAddress(8), &[], IrType::I64);
    let result = witness.value(0, IrOp::Load, &[selected_word], IrType::I64);
    witness.return_value(0, result);
    witness.lower(SOURCE).unwrap();
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let executable = native::Executable::new(&witness);
        let function: unsafe extern "system" fn() -> u64 =
            unsafe { core::mem::transmute(executable.address()) };
        assert_eq!(unsafe { function() }, 1);
    }
}

#[test]
fn native_bit_strings_preserve_signed_word_offsets_widths_and_lock() {
    for (codes, width) in [
        (
            [
                Code::Bt_rm16_r16,
                Code::Bts_rm16_r16,
                Code::Btr_rm16_r16,
                Code::Btc_rm16_r16,
            ],
            16,
        ),
        (
            [
                Code::Bt_rm32_r32,
                Code::Bts_rm32_r32,
                Code::Btr_rm32_r32,
                Code::Btc_rm32_r32,
            ],
            32,
        ),
        (
            [
                Code::Bt_rm64_r64,
                Code::Bts_rm64_r64,
                Code::Btr_rm64_r64,
                Code::Btc_rm64_r64,
            ],
            64,
        ),
    ] {
        for (operation, code) in codes.into_iter().enumerate() {
            for locked in [false, true] {
                if operation == 0 && locked {
                    continue;
                }
                for (base_delta, index) in
                    [(-40, 384i64), (-40, 391), (8, -384), (8, -377), (24, -1)]
                {
                    let mut witness = Witness::new(1);
                    let output = witness.input(Gpr::Rdx);
                    let word_delta = base_delta + index.div_euclid(width) * (width / 8);
                    let bit = index.rem_euclid(width) as u32;
                    let mask = 1u64 << bit;
                    let initial = match operation {
                        1 => 0x9abc_def0_1234_5678 & !mask,
                        2 => 0x9abc_def0_1234_5678 | mask,
                        _ => 0x9abc_def0_1234_5678,
                    };
                    witness.store_word(word_delta, initial);
                    witness.store_word(word_delta + 8, 0xfedc_ba98_7654_3210);
                    let base = witness.value(0, IrOp::FrameAddress(base_delta), &[], IrType::I64);
                    let raw = match width {
                        16 => (index as u16 as u64) | 0x1234_5678_abcd_0000,
                        32 => (index as u32 as u64) | 0x1234_5678_0000_0000,
                        _ => index as u64,
                    };
                    let index = witness.constant(0, raw);
                    native_bits(&mut witness, 0, base, index, code, locked);
                    let selected_word =
                        witness.value(0, IrOp::FrameAddress(word_delta), &[], IrType::I64);
                    let result = witness.value(0, IrOp::Load, &[selected_word], IrType::I64);
                    let neighbor =
                        witness.value(0, IrOp::FrameAddress(word_delta + 8), &[], IrType::I64);
                    let neighbor = witness.value(0, IrOp::Load, &[neighbor], IrType::I64);
                    witness.effect(0, IrOp::Store, &[output, neighbor], IrType::I64);
                    witness.return_value(0, result);
                    let bytes = witness.lower(SOURCE).unwrap();
                    let mut decoder =
                        iced_x86::Decoder::new(64, &bytes, iced_x86::DecoderOptions::NONE);
                    let mut bit_instructions = 0;
                    while decoder.can_decode() {
                        let instruction = decoder.decode();
                        if matches!(
                            instruction.mnemonic(),
                            iced_x86::Mnemonic::Bt
                                | iced_x86::Mnemonic::Bts
                                | iced_x86::Mnemonic::Btr
                                | iced_x86::Mnemonic::Btc
                        ) {
                            bit_instructions += 1;
                            assert_eq!(instruction.op1_kind(), iced_x86::OpKind::Immediate8);
                            assert_eq!(instruction.immediate8(), bit as u8);
                            assert_eq!(instruction.memory_size().size(), width as usize / 8);
                            assert_eq!(instruction.has_lock_prefix(), locked);
                        }
                    }
                    assert_eq!(bit_instructions, 1);
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    {
                        let executable = native::Executable::new(&witness);
                        let function: unsafe extern "system" fn(u64, *mut u64) -> u64 =
                            unsafe { core::mem::transmute(executable.address()) };
                        let mut neighbor = 0;
                        let expected = match operation {
                            1 => initial | mask,
                            2 => initial & !mask,
                            3 => initial ^ mask,
                            _ => initial,
                        };
                        assert_eq!(
                            unsafe { function(0, &mut neighbor) },
                            expected,
                            "code={code:?} index={raw:#x} locked={locked}"
                        );
                        assert_eq!(neighbor, 0xfedc_ba98_7654_3210);
                    }
                }
            }
        }
    }
}

#[test]
fn finite_native_bit_strings_rebase_the_selected_word() {
    for (left, right, index) in [(-72, -56, 640i64), (8, 24, -640), (-16, 8, 64)] {
        let mut witness = Witness::new(4);
        let selector = witness.input(Gpr::Rcx);
        let left_pointer = witness.value(0, IrOp::FrameAddress(left), &[], IrType::I64);
        let right_pointer = witness.value(0, IrOp::FrameAddress(right), &[], IrType::I64);
        let word_offset = index.div_euclid(64) * 8;
        witness.store_word(left + word_offset, 0);
        witness.store_word(right + word_offset, 0);
        let pointer = witness.join(selector, left_pointer, right_pointer);
        let index = witness.constant(3, index as u64);
        native_bits(&mut witness, 3, pointer, index, Code::Bts_rm64_r64, true);
        let selected_word =
            witness.value(3, IrOp::FrameOffset(word_offset), &[pointer], IrType::I64);
        let result = witness.value(3, IrOp::Load, &[selected_word], IrType::I64);
        witness.return_value(3, result);
        witness.lower(SOURCE).unwrap();
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let executable = native::Executable::new(&witness);
            let function: unsafe extern "system" fn(u64) -> u64 =
                unsafe { core::mem::transmute(executable.address()) };
            for selector in [0, 1] {
                assert_eq!(
                    unsafe { function(selector) },
                    1,
                    "left={left} right={right} selector={selector}"
                );
            }
        }
    }
}

#[test]
fn unknown_native_bit_indices_reject_only_unproved_frame_extents() {
    for code in [Code::Bts_rm16_r16, Code::Bts_rm32_r32, Code::Bts_rm64_r64] {
        let mut crossing = Witness::new(1);
        let base = crossing.value(0, IrOp::FrameAddress(-49), &[], IrType::I64);
        let index = crossing.constant(0, 384);
        native_bits(&mut crossing, 0, base, index, code, true);
        assert_eq!(
            crossing.lower(SOURCE).unwrap_err(),
            RejectionReason::FrameConflict
        );
    }

    let mut frame = Witness::new(1);
    let index = frame.input(Gpr::Rcx);
    let base = frame.value(0, IrOp::FrameAddress(-40), &[], IrType::I64);
    native_bits(&mut frame, 0, base, index, Code::Bts_rm64_r64, true);
    assert_eq!(
        frame.lower(SOURCE).unwrap_err(),
        RejectionReason::FrameDynamic
    );

    let mut ordinary = Witness::new(1);
    let base = ordinary.input(Gpr::Rcx);
    let index = ordinary.input(Gpr::Rdx);
    native_bits(&mut ordinary, 0, base, index, Code::Bts_rm64_r64, true);
    let one = ordinary.constant(0, 1);
    ordinary.return_value(0, one);
    let bytes = ordinary.lower(SOURCE).unwrap();
    let mut decoder = iced_x86::Decoder::new(64, &bytes, iced_x86::DecoderOptions::NONE);
    let mut found = false;
    while decoder.can_decode() {
        found |= decoder.decode().code() == Code::Bts_rm64_r64;
    }
    assert!(found);
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let executable = native::Executable::new(&ordinary);
        let function: unsafe extern "system" fn(*mut u64, i64) -> u64 =
            unsafe { core::mem::transmute(executable.address()) };
        for index in [384i64, -384, -1, 391] {
            let mut words = [0u64; 24];
            assert_eq!(unsafe { function(words.as_mut_ptr().add(8), index) }, 1);
            let selected = (8 + index.div_euclid(64)) as usize;
            words[selected] ^= 1u64 << index.rem_euclid(64);
            assert_eq!(words, [0; 24]);
        }
    }
}

fn bounded_array_loop(count: u64, inverted: bool) -> Witness {
    let mut witness = Witness::new(5);
    let seed = witness.input(Gpr::Rcx);
    let entry = witness.value(0, IrOp::FrameAddress(0), &[], IrType::I64);
    let base = witness.value(0, IrOp::FrameAddress(-(count as i64) * 8), &[], IrType::I64);
    let initial_pointer = witness.value(0, IrOp::FrameOffset(24), &[base], IrType::I64);
    let zero = witness.constant(0, 0);
    let pointer = witness.func.alloc_value();
    let counter = witness.func.alloc_value();
    witness.func.blocks[0].term = IrTerminator::Jump(BlockId(1));
    for (displacement, increment) in [(-24, 0), (-16, 7), (-8, 14), (0, 21)] {
        let address = witness.value(1, IrOp::FrameOffset(displacement), &[pointer], IrType::I64);
        let increment = witness.constant(1, increment);
        let data = witness.value(1, IrOp::Add, &[seed, counter], IrType::I64);
        let data = witness.value(1, IrOp::Add, &[data, increment], IrType::I64);
        witness.effect(1, IrOp::Store, &[address, data], IrType::I64);
    }
    let next_pointer = witness.value(1, IrOp::FrameOffset(32), &[pointer], IrType::I64);
    let stride = witness.constant(1, 28);
    let next_counter = witness.value(1, IrOp::Add, &[counter, stride], IrType::I64);
    let limit = witness.constant(1, count / 4 * 28);
    let difference = witness.value(1, IrOp::Sub, &[next_counter, limit], IrType::I64);
    let finished = witness.value(1, IrOp::IsZero, &[difference], IrType::I8);
    let condition = if inverted {
        finished
    } else {
        witness.value(1, IrOp::BoolNot, &[finished], IrType::I8)
    };
    witness.func.blocks[1].term = IrTerminator::Branch {
        cond: condition,
        taken: BlockId(if inverted { 2 } else { 1 }),
        not_taken: BlockId(if inverted { 1 } else { 2 }),
    };
    witness.func.blocks[1].phis = vec![
        Phi {
            dest: pointer,
            ty: IrType::I64,
            args: vec![(BlockId(0), initial_pointer), (BlockId(1), next_pointer)],
        },
        Phi {
            dest: counter,
            ty: IrType::I64,
            args: vec![(BlockId(0), zero), (BlockId(1), next_counter)],
        },
    ];
    let initial_index = witness.constant(2, count);
    let index = witness.func.alloc_value();
    let sum = witness.func.alloc_value();
    witness.func.blocks[2].term = IrTerminator::Jump(BlockId(3));
    let scale = witness.constant(3, 3);
    let bytes = witness.value(3, IrOp::Shl, &[index, scale], IrType::I64);
    let unadjusted = witness.value(3, IrOp::Add, &[base, bytes], IrType::I64);
    let mut updated_sum = sum;
    for displacement in [-8, -16, -24, -32, -40, -48, -56, -64] {
        let address = witness.value(
            3,
            IrOp::FrameOffset(displacement),
            &[unadjusted],
            IrType::I64,
        );
        let data = witness.value(3, IrOp::Load, &[address], IrType::I64);
        updated_sum = witness.value(3, IrOp::Add, &[updated_sum, data], IrType::I64);
    }
    let stride = witness.constant(3, 8);
    let next_index = witness.value(3, IrOp::Sub, &[index, stride], IrType::I64);
    let finished = witness.value(3, IrOp::IsZero, &[next_index], IrType::I8);
    let condition = if inverted {
        finished
    } else {
        witness.value(3, IrOp::BoolNot, &[finished], IrType::I8)
    };
    witness.func.blocks[3].term = IrTerminator::Branch {
        cond: condition,
        taken: BlockId(if inverted { 4 } else { 3 }),
        not_taken: BlockId(if inverted { 3 } else { 4 }),
    };
    witness.func.blocks[3].phis = vec![
        Phi {
            dest: index,
            ty: IrType::I64,
            args: vec![(BlockId(2), initial_index), (BlockId(3), next_index)],
        },
        Phi {
            dest: sum,
            ty: IrType::I64,
            args: vec![(BlockId(2), zero), (BlockId(3), updated_sum)],
        },
    ];
    let final_pointer = witness.value(4, IrOp::FrameLogical, &[next_pointer], IrType::I64);
    let entry = witness.value(4, IrOp::FrameLogical, &[entry], IrType::I64);
    let distance = witness.value(4, IrOp::Sub, &[final_pointer, entry], IrType::I64);
    let weight = witness.constant(4, 1 << 48);
    let trace = witness.value(4, IrOp::Mul, &[distance, weight], IrType::I64);
    let result = witness.value(4, IrOp::Add, &[updated_sum, trace], IrType::I64);
    witness.return_value(4, result);
    witness
}

#[test]
fn bounded_pointer_and_scalar_inductions_preserve_indexed_local_objects() {
    for count in [8, 24, 3072] {
        for inverted in [false, true] {
            let witness = bounded_array_loop(count, inverted);
            witness.lower(SOURCE).unwrap();
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                let executable = native::Executable::new(&witness);
                let function: unsafe extern "system" fn(u64) -> u64 =
                    unsafe { core::mem::transmute(executable.address()) };
                for seed in [0, 1, 0x1234] {
                    let expected = seed * count + 7 * count * (count - 1) / 2 + (24 << 48);
                    assert_eq!(
                        unsafe { function(seed) },
                        expected,
                        "count={count} inverted={inverted} seed={seed}"
                    );
                }
            }
        }
    }
    for count in [0, 10] {
        assert_eq!(
            bounded_array_loop(count, false).lower(SOURCE).unwrap_err(),
            RejectionReason::FrameDynamic
        );
    }
}

#[test]
fn wrapping_induction_does_not_prove_bounded_frame_accesses() {
    let mut witness = Witness::new(3);
    let initial_pointer = witness.value(0, IrOp::FrameAddress(-64), &[], IrType::I64);
    let zero = witness.value(0, IrOp::Const(0), &[], IrType::I8);
    let pointer = witness.func.alloc_value();
    let counter = witness.func.alloc_value();
    witness.func.blocks[0].term = IrTerminator::Jump(BlockId(1));
    let loaded = witness.value(1, IrOp::Load, &[pointer], IrType::I64);
    let next_pointer = witness.value(1, IrOp::FrameOffset(32), &[pointer], IrType::I64);
    let stride = witness.value(1, IrOp::Const(28), &[], IrType::I8);
    let next_counter = witness.value(1, IrOp::Add, &[counter, stride], IrType::I8);
    let widened = witness.value(1, IrOp::Zext, &[next_counter], IrType::I64);
    let limit = witness.constant(1, 336);
    let difference = witness.value(1, IrOp::Sub, &[widened, limit], IrType::I64);
    let zero_flag = witness.value(1, IrOp::IsZero, &[difference], IrType::I8);
    let repeat = witness.value(1, IrOp::BoolNot, &[zero_flag], IrType::I8);
    witness.func.blocks[1].term = IrTerminator::Branch {
        cond: repeat,
        taken: BlockId(1),
        not_taken: BlockId(2),
    };
    witness.func.blocks[1].phis = vec![
        Phi {
            dest: pointer,
            ty: IrType::I64,
            args: vec![(BlockId(0), initial_pointer), (BlockId(1), next_pointer)],
        },
        Phi {
            dest: counter,
            ty: IrType::I8,
            args: vec![(BlockId(0), zero), (BlockId(1), next_counter)],
        },
    ];
    witness.return_value(2, loaded);
    assert_eq!(
        witness.lower(SOURCE).unwrap_err(),
        RejectionReason::FrameDynamic
    );
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod native {
    use super::Witness;
    use core::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualAlloc(
            address: *mut c_void,
            size: usize,
            kind: u32,
            protection: u32,
        ) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
        fn VirtualProtect(address: *mut c_void, size: usize, protection: u32, old: *mut u32)
        -> i32;
        fn FlushInstructionCache(process: *mut c_void, address: *const c_void, size: usize) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
    }

    pub(super) struct Executable(*mut c_void);

    impl Executable {
        pub(super) fn new(witness: &Witness) -> Self {
            let allocation = unsafe { VirtualAlloc(core::ptr::null_mut(), 65536, 0x3000, 4) };
            assert!(!allocation.is_null());
            let executable = Self(allocation);
            let code = witness.lower(allocation as u64).unwrap();
            assert!(code.len() <= 65536);
            unsafe {
                core::ptr::copy_nonoverlapping(code.as_ptr(), allocation.cast(), code.len());
                let mut old = 0;
                assert_ne!(VirtualProtect(allocation, 65536, 0x20, &mut old), 0);
                assert_ne!(
                    FlushInstructionCache(GetCurrentProcess(), allocation, code.len()),
                    0
                );
            }
            executable
        }

        pub(super) fn address(&self) -> *mut c_void {
            self.0
        }
    }

    impl Drop for Executable {
        fn drop(&mut self) {
            assert_ne!(unsafe { VirtualFree(self.0, 0, 0x8000) }, 0);
        }
    }
}
