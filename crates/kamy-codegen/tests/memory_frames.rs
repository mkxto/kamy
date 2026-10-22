use std::collections::{HashMap, HashSet};

use kamy_core::ir::{
    BlockId, Gpr, Inst, IrBlock, IrFunction, IrOp, IrTerminator, IrType, NativeInst, Phi, PhysReg,
    ValueId, XmmReg, win64_volatiles,
};
use kamy_core::{LinkField, Reference, ReferenceOrigin, SymbolId, SymbolicExpression};

const SOURCE_VA: u64 = 0x1_4000_1000;
const HELPER_OFFSET: usize = 0xf_f000;
#[cfg(all(windows, target_arch = "x86_64"))]
const ALLOCATION_SIZE: usize = 0x10_0000;
#[cfg(all(windows, target_arch = "x86_64"))]
const CLOBBERING_HELPER: &[u8] = &[
    0x48, 0x8d, 0x44, 0x49, 0x07, 0x31, 0xd2, 0x45, 0x31, 0xc0, 0x45, 0x31, 0xc9, 0x45, 0x31, 0xd2,
    0x45, 0x31, 0xdb, 0xb9, 0xad, 0xde, 0, 0, 0x66, 0x0f, 0xef, 0xc0, 0x66, 0x0f, 0xef, 0xc9, 0x66,
    0x0f, 0xef, 0xd2, 0x66, 0x0f, 0xef, 0xdb, 0x66, 0x0f, 0xef, 0xe4, 0x66, 0x0f, 0xef, 0xed, 0x66,
    0x48, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0x6c, 0xc0, 0xc3,
];

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

    fn pinned_copy(&mut self, block: usize, value: ValueId, reg: PhysReg, ty: IrType) -> ValueId {
        let copy = self.value(block, IrOp::Copy, &[value], ty);
        self.pins.insert(copy, reg);
        copy
    }

    fn phi(&mut self, ty: IrType) -> ValueId {
        let dest = self.func.alloc_value();
        self.func.blocks[1].phis.push(Phi {
            dest,
            ty,
            args: Vec::new(),
        });
        dest
    }

    fn call(&mut self, block: usize, arg: ValueId) -> ValueId {
        let argument = self.pinned_copy(block, arg, PhysReg::Gpr(Gpr::Rcx), IrType::I64);
        self.effect(
            block,
            IrOp::Call {
                target: Reference {
                    source: symbol("witness"),
                    offset: 0,
                    expression: SymbolicExpression::symbol(symbol("clobbering_helper")),
                    field: LinkField::Relative32 { bias: 0 },
                    origin: ReferenceOrigin::Authored,
                },
                clobbers: win64_volatiles(),
            },
            &[argument],
            IrType::I64,
        );
        let result = self.value(
            block,
            IrOp::CallResult {
                register: PhysReg::Gpr(Gpr::Rax),
            },
            &[],
            IrType::I64,
        );
        self.pins.insert(result, PhysReg::Gpr(Gpr::Rax));
        result
    }

    fn native(&mut self, block: usize, value: ValueId, vector: bool) -> ValueId {
        let (reg, ty, bytes) = if vector {
            (
                PhysReg::Xmm(XmmReg::Xmm0),
                IrType::I128,
                vec![0x66, 0x0f, 0x70, 0xc0, 0x1b],
            )
        } else {
            (PhysReg::Gpr(Gpr::R10), IrType::I64, vec![0x49, 0x0f, 0xca])
        };
        let input = self.pinned_copy(block, value, reg, ty);
        self.effect(
            block,
            IrOp::NativeInline(NativeInst {
                bytes,
                references: Vec::new(),
                reads: vec![reg],
                writes: vec![reg],
            }),
            &[input],
            ty,
        );
        let output = self.value(block, IrOp::Undef, &[], ty);
        self.pins.insert(output, reg);
        output
    }

    fn return_value(&mut self, block: usize, value: ValueId) {
        let result = self.pinned_copy(block, value, PhysReg::Gpr(Gpr::Rax), IrType::I64);
        self.effect(block, IrOp::Use, &[result], IrType::I64);
    }

    fn lower(&self, va: u64) -> Vec<u8> {
        let alloc = kamy_codegen::allocate_registers(&self.func, &HashSet::new(), &self.pins)
            .expect("supported pressure MUST lower without reducing the witness");
        let mut selected = kamy_codegen::select_instructions(&self.func, &alloc);
        kamy_codegen::bind_references(&mut selected, va, |target| {
            (target == &symbol("clobbering_helper")).then_some(va + HELPER_OFFSET as u64)
        })
        .unwrap();
        let code = kamy_codegen::relocate(&selected.instructions, va).unwrap();
        assert!(code.len() < HELPER_OFFSET);
        code
    }
}

fn symbol(name: &str) -> SymbolId {
    SymbolId::Authored {
        module: "memory_frames".into(),
        symbol: name.into(),
    }
}

fn pressure_witness(vector: bool, count: u64) -> Witness {
    let ty = if vector { IrType::I128 } else { IrType::I64 };
    let stride = if vector { 16 } else { 8 };
    let mut witness = Witness::new(5);
    let input = witness.input(Gpr::Rcx);
    let rounds = witness.input(Gpr::Rdx);
    let output = witness.input(Gpr::R8);
    let zero = witness.value(0, IrOp::Const(0), &[], IrType::I64);
    let one = witness.value(0, IrOp::Const(1), &[], IrType::I64);
    let mut initial = Vec::new();
    for index in 0..count {
        let offset = witness.value(0, IrOp::Const(index * stride), &[], IrType::I64);
        let address = witness.value(0, IrOp::Add, &[input, offset], IrType::I64);
        initial.push(witness.value(0, IrOp::Load, &[address], ty));
    }
    let counter = witness.phi(IrType::I64);
    let lanes: Vec<_> = (0..count).map(|_| witness.phi(ty)).collect();
    let condition = witness.value(1, IrOp::BorrowSub, &[counter, rounds], IrType::I8);
    witness.func.blocks[0].term = IrTerminator::Jump(BlockId(1));
    witness.func.blocks[1].term = IrTerminator::Branch {
        cond: condition,
        taken: BlockId(2),
        not_taken: BlockId(3),
    };
    let native = witness.native(2, lanes[0], vector);
    let first = witness.call(2, counter);
    let second = witness.call(2, one);
    let updated = if vector {
        native
    } else {
        let sum = witness.value(2, IrOp::Add, &[native, first], IrType::I64);
        witness.value(2, IrOp::Add, &[sum, second], IrType::I64)
    };
    let next = witness.value(2, IrOp::Add, &[counter, one], IrType::I64);
    witness.func.blocks[1].phis[0].args =
        vec![(BlockId(0), zero), (BlockId(2), next), (BlockId(4), next)];
    let alternate = if vector {
        witness.native(4, updated, true)
    } else {
        let adjustment = witness.value(4, IrOp::Const(23), &[], IrType::I64);
        witness.value(4, IrOp::Add, &[updated, adjustment], IrType::I64)
    };
    let count = count as usize;
    for index in 0..count {
        let source = if index == count - 3 {
            updated
        } else if index == count - 2 {
            lanes[count - 1]
        } else if index == count - 1 {
            lanes[count - 2]
        } else {
            lanes[index + 1]
        };
        let alternate_source = if index == count - 3 {
            alternate
        } else {
            source
        };
        witness.func.blocks[1].phis[index + 1].args = vec![
            (BlockId(0), initial[index]),
            (BlockId(2), source),
            (BlockId(4), alternate_source),
        ];
    }
    let odd = witness.value(2, IrOp::And, &[counter, one], IrType::I64);
    witness.func.blocks[2].term = IrTerminator::Branch {
        cond: odd,
        taken: BlockId(1),
        not_taken: BlockId(4),
    };
    witness.func.blocks[4].term = IrTerminator::Jump(BlockId(1));
    let mut checksum = zero;
    for (index, lane) in lanes.into_iter().enumerate() {
        let offset = witness.value(3, IrOp::Const(index as u64 * stride), &[], IrType::I64);
        let address = witness.value(3, IrOp::Add, &[output, offset], IrType::I64);
        witness.effect(3, IrOp::Store, &[address, lane], ty);
        if !vector {
            let weight = witness.value(3, IrOp::Const(index as u64 + 1), &[], IrType::I64);
            let product = witness.value(3, IrOp::Mul, &[lane, weight], IrType::I64);
            checksum = witness.value(3, IrOp::Add, &[checksum, product], IrType::I64);
        }
    }
    witness.return_value(3, checksum);
    witness
}

fn scalar_input() -> Vec<u64> {
    scalar_input_for(48)
}

fn scalar_input_for(count: u64) -> Vec<u64> {
    (0..count)
        .map(|index| index.wrapping_mul(0x1020_3040_5060_7081) ^ 0x9abc_def0_1234_5678)
        .collect()
}

fn scalar_oracle(input: &[u64], rounds: u64) -> (Vec<u64>, u64) {
    let mut lanes = input.to_vec();
    let rotating = lanes.len() - 2;
    for counter in 0..rounds {
        let updated = lanes[0]
            .swap_bytes()
            .wrapping_add(counter.wrapping_mul(3).wrapping_add(7))
            .wrapping_add(10)
            .wrapping_add(if counter & 1 == 0 { 23 } else { 0 });
        lanes[..rotating].rotate_left(1);
        lanes[rotating - 1] = updated;
        lanes.swap(rotating, rotating + 1);
    }
    let checksum = lanes.iter().enumerate().fold(0u64, |sum, (index, value)| {
        sum.wrapping_add(value.wrapping_mul(index as u64 + 1))
    });
    (lanes, checksum)
}

fn vector_input() -> Vec<u128> {
    (0..24u128)
        .map(|index| {
            0xfedc_ba98_7654_3210_0123_4567_89ab_cdefu128
                ^ index.wrapping_mul(0x1020_3040_5060_7081_1122_3344_5566_7789)
        })
        .collect()
}

fn vector_oracle(input: &[u128], rounds: u64) -> Vec<u128> {
    let mut lanes = input.to_vec();
    for counter in 0..rounds {
        let words = lanes[0].to_le_bytes();
        let mut reversed = [0; 16];
        for index in 0..4 {
            reversed[index * 4..index * 4 + 4]
                .copy_from_slice(&words[(3 - index) * 4..(4 - index) * 4]);
        }
        let updated = if counter & 1 == 0 {
            lanes[0]
        } else {
            u128::from_le_bytes(reversed)
        };
        lanes[..22].rotate_left(1);
        lanes[21] = updated;
        lanes.swap(22, 23);
    }
    lanes
}

#[test]
fn gpr_values_survive_calls_native_loop_and_parallel_copy_cycles() {
    let witness = pressure_witness(false, 48);
    witness.lower(SOURCE_VA);
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let executable = native::Executable::new(&witness);
        let function: unsafe extern "system" fn(*const u64, u64, *mut u64) -> u64 =
            unsafe { core::mem::transmute(executable.address()) };
        for rounds in [0, 1, 2, 17, 51, 97] {
            let input = scalar_input();
            let mut output = vec![0; input.len()];
            let expected = scalar_oracle(&input, rounds);
            let returned = unsafe { function(input.as_ptr(), rounds, output.as_mut_ptr()) };
            assert_eq!(output, expected.0, "rounds={rounds}");
            assert_eq!(returned, expected.1, "rounds={rounds}");
        }
    }
}

#[test]
fn large_generated_intermediate_frame_crosses_windows_guard_pages() {
    let witness = pressure_witness(false, 512);
    witness.lower(SOURCE_VA);
    let input = scalar_input_for(512);
    let expected = scalar_oracle(&input, 3);
    assert_eq!(expected.1, 0x3ab2_bf82_1c6b_f65d);
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let executable = native::Executable::new(&witness);
        let function: unsafe extern "system" fn(*const u64, u64, *mut u64) -> u64 =
            unsafe { core::mem::transmute(executable.address()) };
        let mut output = vec![0; input.len()];
        let returned = unsafe { function(input.as_ptr(), 3, output.as_mut_ptr()) };
        assert_eq!(output, expected.0);
        assert_eq!(returned, expected.1);
    }
}

#[test]
fn xmm_values_survive_calls_native_loop_and_parallel_copy_cycles() {
    let witness = pressure_witness(true, 24);
    witness.lower(SOURCE_VA);
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let executable = native::Executable::new(&witness);
        let function: unsafe extern "system" fn(*const u128, u64, *mut u128) -> u64 =
            unsafe { core::mem::transmute(executable.address()) };
        for rounds in [0, 1, 2, 17, 25, 53] {
            let input = vector_input();
            let mut output = vec![0; input.len()];
            let returned = unsafe { function(input.as_ptr(), rounds, output.as_mut_ptr()) };
            assert_eq!(output, vector_oracle(&input, rounds), "rounds={rounds}");
            assert_eq!(returned, 0);
        }
    }
}

#[test]
fn portable_witnesses_retain_exact_behavioral_goldens() {
    let (scalar, checksum) = scalar_oracle(&scalar_input(), 97);
    assert_eq!(scalar[0], 0xea1c_2fb1_83d6_65a7);
    assert_eq!(scalar[47], 0x7f74_757e_6360_6156);
    assert_eq!(checksum, 0xe630_779f_5b22_e234);
    let vectors = vector_oracle(&vector_input(), 53);
    assert_eq!(vectors[0], 0x6ffd_08da_a537_c699_9b10_8800_8931_fe3e);
    assert_eq!(vectors[13], 0xfedc_ba98_7654_3210_0123_4567_89ab_cdef);
    assert_eq!(vectors[23], 0x9c18_9f1e_9e1d_9907_79d3_22b8_df65_8829);
    assert_eq!(flags_oracle(u64::MAX, 1), 0x0000_6900_2224_222f);
    assert_eq!(flags_oracle(i64::MAX as u64, 1), 0x8000_7200_1113_109e);
    assert_eq!(flags_oracle(0, 0), 0x0000_2800_1111_1111);
}

fn flags_witness() -> Witness {
    let mut witness = Witness::new(4);
    let a = witness.input(Gpr::Rcx);
    let b = witness.input(Gpr::Rdx);
    let sum = witness.value(0, IrOp::Add, &[a, b], IrType::I64);
    let low_a = witness.value(0, IrOp::Trunc, &[a], IrType::I8);
    let low_b = witness.value(0, IrOp::Trunc, &[b], IrType::I16);
    let low_sum = witness.value(0, IrOp::Trunc, &[sum], IrType::I32);
    let carry = witness.value(0, IrOp::CarryAdd, &[a, b], IrType::I8);
    let overflow = witness.value(0, IrOp::OverflowAdd, &[a, b], IrType::I8);
    let borrow = witness.value(0, IrOp::BorrowSub, &[a, b], IrType::I8);
    let zero = witness.value(0, IrOp::IsZero, &[sum], IrType::I8);
    let nonzero = witness.value(0, IrOp::BoolNot, &[zero], IrType::I8);
    let parity = witness.value(0, IrOp::Parity, &[sum], IrType::I8);
    let negative = witness.value(0, IrOp::IsNeg, &[low_a], IrType::I8);
    let native = witness.native(0, a, false);
    let first = witness.call(0, a);
    let second = witness.call(0, b);
    witness.func.blocks[0].term = IrTerminator::Branch {
        cond: carry,
        taken: BlockId(1),
        not_taken: BlockId(2),
    };
    let carried = witness.value(1, IrOp::Const(0x2222_2222), &[], IrType::I64);
    let clear = witness.value(2, IrOp::Const(0x1111_1111), &[], IrType::I64);
    witness.func.blocks[1].term = IrTerminator::Jump(BlockId(3));
    witness.func.blocks[2].term = IrTerminator::Jump(BlockId(3));
    let joined = witness.func.alloc_value();
    witness.func.blocks[3].phis.push(Phi {
        dest: joined,
        ty: IrType::I64,
        args: vec![(BlockId(1), carried), (BlockId(2), clear)],
    });
    let mut result = witness.value(3, IrOp::Xor, &[first, second], IrType::I64);
    result = witness.value(3, IrOp::Add, &[result, native], IrType::I64);
    result = witness.value(3, IrOp::Add, &[result, joined], IrType::I64);
    for (value, weight) in [(low_a, 257), (low_b, 65537), (low_sum, 3)] {
        let wide = witness.value(3, IrOp::Zext, &[value], IrType::I64);
        let weight = witness.value(3, IrOp::Const(weight), &[], IrType::I64);
        let term = witness.value(3, IrOp::Mul, &[wide, weight], IrType::I64);
        result = witness.value(3, IrOp::Add, &[result, term], IrType::I64);
    }
    for (index, flag) in [carry, overflow, borrow, zero, nonzero, parity, negative]
        .into_iter()
        .enumerate()
    {
        let wide = witness.value(3, IrOp::Zext, &[flag], IrType::I64);
        let weight = witness.value(3, IrOp::Const(1u64 << (40 + index)), &[], IrType::I64);
        let term = witness.value(3, IrOp::Mul, &[wide, weight], IrType::I64);
        result = witness.value(3, IrOp::Add, &[result, term], IrType::I64);
    }
    witness.return_value(3, result);
    witness
}

fn flags_oracle(a: u64, b: u64) -> u64 {
    let (sum, carry) = a.overflowing_add(b);
    let overflow = ((!(a ^ b) & (a ^ sum)) >> 63) != 0;
    let flags = u64::from(carry)
        | (u64::from(overflow) << 1)
        | (u64::from(a < b) << 2)
        | (u64::from(sum == 0) << 3)
        | (u64::from(sum != 0) << 4)
        | (u64::from((sum as u8).count_ones() % 2 == 0) << 5)
        | (u64::from(a as u8 & 0x80 != 0) << 6);
    (a.wrapping_mul(3).wrapping_add(7) ^ b.wrapping_mul(3).wrapping_add(7))
        .wrapping_add(a.swap_bytes())
        .wrapping_add(u64::from(a as u8).wrapping_mul(257))
        .wrapping_add(u64::from(b as u16).wrapping_mul(65537))
        .wrapping_add(u64::from(sum as u32).wrapping_mul(3))
        .wrapping_add(flags << 40)
        .wrapping_add(if carry { 0x2222_2222 } else { 0x1111_1111 })
}

#[test]
fn flags_partial_widths_and_branch_phis_survive_native_and_two_calls() {
    let witness = flags_witness();
    witness.lower(SOURCE_VA);
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let executable = native::Executable::new(&witness);
        let function: unsafe extern "system" fn(u64, u64) -> u64 =
            unsafe { core::mem::transmute(executable.address()) };
        for (a, b) in [
            (0, 0),
            (u64::MAX, 1),
            (i64::MAX as u64, 1),
            (1 << 63, 1 << 63),
            (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            (0xffff_ffff_0000_0080, 0x1000_0000_0000_ffff),
        ] {
            assert_eq!(
                unsafe { function(a, b) },
                flags_oracle(a, b),
                "a={a:#x} b={b:#x}"
            );
        }
    }
}

#[test]
fn mixed_pinned_call_results_are_saved_after_definition_and_survive_later_calls() {
    let mut witness = Witness::new(1);
    let a = witness.input(Gpr::Rcx);
    let b = witness.input(Gpr::Rdx);
    let output = witness.input(Gpr::R8);
    let first = witness.call(0, a);
    let first_vector = witness.value(
        0,
        IrOp::CallResult {
            register: PhysReg::Xmm(XmmReg::Xmm0),
        },
        &[],
        IrType::I128,
    );
    witness
        .pins
        .insert(first_vector, PhysReg::Xmm(XmmReg::Xmm0));
    let second = witness.call(0, b);
    let second_vector = witness.value(
        0,
        IrOp::CallResult {
            register: PhysReg::Xmm(XmmReg::Xmm0),
        },
        &[],
        IrType::I128,
    );
    witness
        .pins
        .insert(second_vector, PhysReg::Xmm(XmmReg::Xmm0));
    witness.effect(0, IrOp::Store, &[output, first_vector], IrType::I128);
    let offset = witness.value(0, IrOp::Const(16), &[], IrType::I64);
    let address = witness.value(0, IrOp::Add, &[output, offset], IrType::I64);
    witness.effect(0, IrOp::Store, &[address, second_vector], IrType::I128);
    let weight = witness.value(0, IrOp::Const(13), &[], IrType::I64);
    let weighted = witness.value(0, IrOp::Mul, &[first, weight], IrType::I64);
    let result = witness.value(0, IrOp::Add, &[weighted, second], IrType::I64);
    witness.return_value(0, result);
    witness.lower(SOURCE_VA);
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let executable = native::Executable::new(&witness);
        let function: unsafe extern "system" fn(u64, u64, *mut u128) -> u64 =
            unsafe { core::mem::transmute(executable.address()) };
        for (a, b) in [
            (17u64, 23u64),
            (0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210),
        ] {
            let first = a.wrapping_mul(3).wrapping_add(7);
            let second = b.wrapping_mul(3).wrapping_add(7);
            let mut output = [0; 2];
            let returned = unsafe { function(a, b, output.as_mut_ptr()) };
            assert_eq!(
                output,
                [
                    u128::from(first) * 0x1_0000_0000_0000_0001,
                    u128::from(second) * 0x1_0000_0000_0000_0001
                ]
            );
            assert_eq!(returned, first.wrapping_mul(13).wrapping_add(second));
            if a == 17 {
                assert_eq!(returned, 830);
            }
        }
    }
}

#[test]
fn native_memory_reads_follow_phi_selected_original_stack_objects() {
    let mut witness = Witness::new(4);
    let selector = witness.input(Gpr::Rcx);
    let output = witness.input(Gpr::Rdx);
    let first_object = witness.value(0, IrOp::FrameAddress(-96), &[], IrType::I64);
    let second_object = witness.value(0, IrOp::FrameAddress(-64), &[], IrType::I64);
    for (object, first, second) in [(first_object, 17, 29), (second_object, 83, 101)] {
        let value = witness.value(0, IrOp::Const(first), &[], IrType::I64);
        witness.effect(0, IrOp::Store, &[object, value], IrType::I64);
        let offset = witness.value(0, IrOp::Const(8), &[], IrType::I64);
        let address = witness.value(0, IrOp::Add, &[object, offset], IrType::I64);
        let value = witness.value(0, IrOp::Const(second), &[], IrType::I64);
        witness.effect(0, IrOp::Store, &[address, value], IrType::I64);
    }
    let first_base = witness.value(0, IrOp::FrameAddress(-64), &[], IrType::I64);
    let second_base = witness.value(0, IrOp::FrameAddress(-32), &[], IrType::I64);
    let condition = witness.value(0, IrOp::IsZero, &[selector], IrType::I8);
    witness.func.blocks[0].term = IrTerminator::Branch {
        cond: condition,
        taken: BlockId(1),
        not_taken: BlockId(2),
    };
    witness.func.blocks[1].term = IrTerminator::Jump(BlockId(3));
    witness.func.blocks[2].term = IrTerminator::Jump(BlockId(3));
    let pointer = witness.func.alloc_value();
    witness.func.blocks[3].phis.push(Phi {
        dest: pointer,
        ty: IrType::I64,
        args: vec![(BlockId(1), first_base), (BlockId(2), second_base)],
    });
    let native_pointer = witness.pinned_copy(3, pointer, PhysReg::Gpr(Gpr::R10), IrType::I64);
    witness.effect(
        3,
        IrOp::NativeInline(NativeInst {
            bytes: vec![0x41, 0x0f, 0x10, 0x42, 0xe0],
            references: Vec::new(),
            reads: vec![PhysReg::Gpr(Gpr::R10)],
            writes: vec![PhysReg::Xmm(XmmReg::Xmm0)],
        }),
        &[native_pointer],
        IrType::I128,
    );
    let native_result = witness.value(3, IrOp::Undef, &[], IrType::I128);
    witness
        .pins
        .insert(native_result, PhysReg::Xmm(XmmReg::Xmm0));
    let produced = witness.call(3, selector);
    witness.effect(3, IrOp::Store, &[output, native_result], IrType::I128);
    let object = witness.value(3, IrOp::FrameOffset(-32), &[pointer], IrType::I64);
    let first = witness.value(3, IrOp::Load, &[object], IrType::I64);
    let offset = witness.value(3, IrOp::Const(8), &[], IrType::I64);
    let address = witness.value(3, IrOp::Add, &[object, offset], IrType::I64);
    let second = witness.value(3, IrOp::Load, &[address], IrType::I64);
    let weight = witness.value(3, IrOp::Const(7), &[], IrType::I64);
    let weighted = witness.value(3, IrOp::Mul, &[second, weight], IrType::I64);
    let sum = witness.value(3, IrOp::Add, &[first, weighted], IrType::I64);
    let result = witness.value(3, IrOp::Add, &[sum, produced], IrType::I64);
    witness.return_value(3, result);
    witness.lower(SOURCE_VA);
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let executable = native::Executable::new(&witness);
        let function: unsafe extern "system" fn(u64, *mut u128) -> u64 =
            unsafe { core::mem::transmute(executable.address()) };
        for (selector, words, expected) in [
            (0, [17u64, 29u64], 227),
            (1, [83, 101], 800),
            (7, [83, 101], 818),
        ] {
            let mut output = 0u128;
            let returned = unsafe { function(selector, &mut output) };
            assert_eq!(output, u128::from(words[0]) | (u128::from(words[1]) << 64));
            assert_eq!(returned, expected);
        }
    }
}

#[test]
fn concrete_frame_resource_and_signed_offset_overflow_are_specific() {
    let frame = |amount, repetitions| {
        let mut witness = Witness::new(1);
        let entry = witness.input(Gpr::Rsp);
        let amount = witness.value(0, IrOp::Const(amount), &[], IrType::I64);
        let mut rsp = entry;
        let mut chain = HashSet::from([entry]);
        for _ in 0..repetitions {
            rsp = witness.value(0, IrOp::Sub, &[rsp, amount], IrType::I64);
            witness.pins.insert(rsp, PhysReg::Gpr(Gpr::Rsp));
            chain.insert(rsp);
        }
        for _ in 0..repetitions {
            rsp = witness.value(0, IrOp::Add, &[rsp, amount], IrType::I64);
            witness.pins.insert(rsp, PhysReg::Gpr(Gpr::Rsp));
            chain.insert(rsp);
        }
        witness.effect(0, IrOp::Use, &[rsp], IrType::I64);
        (witness, chain)
    };
    let limit = u64::from(kamy_core::frame::MAX_FRAME_SIZE);
    let (accepted, chain) = frame(limit - 40, 1);
    let allocation = kamy_codegen::allocate_registers(&accepted.func, &chain, &accepted.pins)
        .expect("a restored frame below the resource bound MUST lower");
    assert_eq!(u64::from(allocation.frame.original_size), limit - 40);
    assert!(allocation.frame.stack_size > allocation.frame.original_size);
    assert!(u64::from(allocation.frame.stack_size) <= limit);
    accepted.lower(SOURCE_VA);

    for (amount, repetitions, expected) in [
        (limit - 24, 1, "FrameResourceLimit"),
        (limit, 1, "FrameResourceLimit"),
        (i64::MAX as u64, 2, "FrameOverflow"),
    ] {
        let (witness, chain) = frame(amount, repetitions);
        let rejected = kamy_codegen::allocate_registers(&witness.func, &chain, &witness.pins)
            .expect_err("unrepresentable frames MUST NOT emit a partial instruction stream");
        assert_eq!(rejected.tag(), expected);
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod native {
    use super::{ALLOCATION_SIZE, CLOBBERING_HELPER, HELPER_OFFSET, Witness};
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
            let allocation =
                unsafe { VirtualAlloc(core::ptr::null_mut(), ALLOCATION_SIZE, 0x3000, 4) };
            assert!(!allocation.is_null());
            let executable = Self(allocation);
            let code = witness.lower(allocation as u64);
            unsafe {
                let bytes = allocation.cast::<u8>();
                core::ptr::copy_nonoverlapping(code.as_ptr(), bytes, code.len());
                core::ptr::copy_nonoverlapping(
                    CLOBBERING_HELPER.as_ptr(),
                    bytes.add(HELPER_OFFSET),
                    CLOBBERING_HELPER.len(),
                );
                let mut old = 0;
                assert_ne!(
                    VirtualProtect(allocation, ALLOCATION_SIZE, 0x20, &mut old),
                    0
                );
                assert_ne!(
                    FlushInstructionCache(GetCurrentProcess(), allocation, ALLOCATION_SIZE),
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
