use std::collections::{HashMap, HashSet};

use kamy_core::ir::{
    BlockId, Gpr, Inst, IrBlock, IrFunction, IrOp, IrTerminator, IrType, NativeInst, Phi, PhysReg,
    ValueId, XmmReg, win64_volatiles,
};
use kamy_core::{LinkField, Reference, ReferenceOrigin, SymbolId, SymbolicExpression};

#[cfg(all(windows, target_arch = "x86_64"))]
#[path = "../../../tests/sdk-rebuild/src/native_probe.rs"]
mod native_probe;

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

#[derive(Clone, Copy, Debug)]
enum NonvolatileBoundary {
    ReadOnly,
    NativeRead,
    PartialWrite,
}

fn nonvolatile_boundary_witness(boundary: NonvolatileBoundary) -> Witness {
    let mut witness = Witness::new(1);
    let output = witness.input(Gpr::Rcx);
    let scalar = witness.input(Gpr::Rbx);
    let vector = witness.value(0, IrOp::Undef, &[], IrType::I128);
    witness.pins.insert(vector, PhysReg::Xmm(XmmReg::Xmm6));
    let (scalar, vector) = match boundary {
        NonvolatileBoundary::ReadOnly => (scalar, vector),
        NonvolatileBoundary::NativeRead => {
            let seven = witness.value(0, IrOp::Const(7), &[], IrType::I64);
            let sum = witness.value(0, IrOp::Add, &[scalar, seven], IrType::I64);
            let sum = witness.pinned_copy(0, sum, PhysReg::Gpr(Gpr::Rbx), IrType::I64);
            witness.effect(
                0,
                IrOp::NativeInline(NativeInst {
                    bytes: vec![0x48, 0x89, 0xd8], // mov rax,rbx only reads RBX
                    references: vec![],
                    reads: vec![PhysReg::Gpr(Gpr::Rbx)],
                    writes: vec![PhysReg::Gpr(Gpr::Rax)],
                }),
                &[sum],
                IrType::I64,
            );
            let result = witness.value(0, IrOp::Undef, &[], IrType::I64);
            witness.pins.insert(result, PhysReg::Gpr(Gpr::Rax));
            let zero = witness.value(0, IrOp::Const(0), &[], IrType::I128);
            let zero = witness.pinned_copy(0, zero, PhysReg::Xmm(XmmReg::Xmm6), IrType::I128);
            witness.effect(
                0,
                IrOp::NativeInline(NativeInst {
                    bytes: vec![0x0f, 0x50, 0xc6], // movmskps eax,xmm6 only reads XMM6
                    references: vec![],
                    reads: vec![PhysReg::Xmm(XmmReg::Xmm6)],
                    writes: vec![PhysReg::Gpr(Gpr::Rax)],
                }),
                &[zero],
                IrType::I32,
            );
            (result, zero)
        }
        NonvolatileBoundary::PartialWrite => {
            witness.effect(
                0,
                IrOp::NativeInline(NativeInst {
                    bytes: vec![0xb3, 0x5a], // mov bl,0x5a preserves the upper 56 bits
                    references: vec![],
                    reads: vec![PhysReg::Gpr(Gpr::Rbx)],
                    writes: vec![PhysReg::Gpr(Gpr::Rbx)],
                }),
                &[scalar],
                IrType::I8,
            );
            let result = witness.value(0, IrOp::Undef, &[], IrType::I64);
            witness.pins.insert(result, PhysReg::Gpr(Gpr::Rbx));
            let zero = witness.value(0, IrOp::Const(0), &[], IrType::I32);
            witness.pins.insert(zero, PhysReg::Xmm(XmmReg::Xmm0));
            witness.effect(
                0,
                IrOp::NativeInline(NativeInst {
                    bytes: vec![0xf3, 0x0f, 0x10, 0xf0], // movss xmm6,xmm0 preserves upper 96 bits
                    references: vec![],
                    reads: vec![PhysReg::Xmm(XmmReg::Xmm6), PhysReg::Xmm(XmmReg::Xmm0)],
                    writes: vec![PhysReg::Xmm(XmmReg::Xmm6)],
                }),
                &[vector, zero],
                IrType::I32,
            );
            let result_vector = witness.value(0, IrOp::Undef, &[], IrType::I128);
            witness
                .pins
                .insert(result_vector, PhysReg::Xmm(XmmReg::Xmm6));
            (result, result_vector)
        }
    };
    witness.effect(0, IrOp::Store, &[output, scalar], IrType::I64);
    let offset = witness.value(0, IrOp::Const(16), &[], IrType::I64);
    let address = witness.value(0, IrOp::Add, &[output, offset], IrType::I64);
    witness.effect(0, IrOp::Store, &[address, vector], IrType::I128);
    witness.return_value(0, scalar);
    witness
}

#[test]
fn nonvolatile_read_only_and_real_writes_preserve_results_and_caller_state() {
    let mut save_cases = Vec::new();
    for boundary in [
        NonvolatileBoundary::ReadOnly,
        NonvolatileBoundary::NativeRead,
        NonvolatileBoundary::PartialWrite,
    ] {
        let witness = nonvolatile_boundary_witness(boundary);
        let allocation =
            kamy_codegen::allocate_registers(&witness.func, &HashSet::new(), &witness.pins)
                .unwrap();
        let saved: Vec<_> = allocation
            .frame
            .saves
            .iter()
            .map(|save| save.register)
            .collect();
        let expected_saves = match boundary {
            NonvolatileBoundary::ReadOnly => vec![],
            _ => vec![PhysReg::Gpr(Gpr::Rbx), PhysReg::Xmm(XmmReg::Xmm6)],
        };
        let selected = kamy_codegen::select_instructions(&witness.func, &allocation);
        let prologue_end = selected
            .instructions
            .iter()
            .position(|inst| inst.ip() != 0)
            .unwrap();
        // This single-return fixture's epilogue restores its modeled saves,
        // reloads the nonconstant RAX output, releases its frame and returns.
        let epilogue_start = selected.instructions.len() - allocation.frame.saves.len() - 3;
        let code = kamy_codegen::relocate(&selected.instructions, SOURCE_VA).unwrap();
        let code_bytes = code.len();
        let unwind = kamy_seh::unwind_ranges(&code, SOURCE_VA)
            .expect("the exact nonvolatile fixture MUST have reconstructible native metadata");
        assert_eq!(unwind.first().unwrap().begin, 0, "{boundary:?}");
        assert_eq!(
            unwind.last().unwrap().end as usize,
            code_bytes,
            "{boundary:?}"
        );
        let prologue_bytes =
            kamy_codegen::relocate(&selected.instructions[..prologue_end], SOURCE_VA)
                .unwrap()
                .len();
        let epilogue_bytes =
            kamy_codegen::relocate(&selected.instructions[epilogue_start..], SOURCE_VA)
                .unwrap()
                .len();
        let save_bytes: u32 = allocation
            .frame
            .saves
            .iter()
            .map(|save| {
                if matches!(save.register, PhysReg::Xmm(_)) {
                    16
                } else {
                    8
                }
            })
            .sum();
        eprintln!(
            "nonvolatile {boundary:?}: frame={} saves={} save_bytes={} prologue={prologue_bytes} body={} epilogue={epilogue_bytes} code={code_bytes}",
            allocation.frame.stack_size,
            saved.len(),
            save_bytes,
            code_bytes - prologue_bytes - epilogue_bytes
        );
        save_cases.push((boundary, saved, expected_saves));
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let executable = native::Executable::with_nonvolatile_caller(&witness);
            let report = executable.check_unwind();
            assert!(report.body_pcs > 1, "interior body probes: {boundary:?}");
            assert!(report.epilogues >= 2, "epilogue probes: {boundary:?}");
            eprintln!(
                "nonvolatile {boundary:?}: native_unwind_pcs={} body_pcs={} epilogue_pcs={} anchor={} calls={} max_frame={} saved_gpr={} saved_xmm={}",
                report.pcs,
                report.body_pcs,
                report.epilogues,
                report.anchor,
                report.calls,
                report.max_frame,
                report.saved_gpr.count_ones(),
                report.saved_xmm.count_ones()
            );
            let function: unsafe extern "system" fn(
                *const [u128; 2],
                *mut [u128; 2],
                *mut [u128; 2],
            ) -> u64 = unsafe { core::mem::transmute(executable.caller_address()) };
            for (scalar, vector) in [
                (
                    0x1234_5678_9abc_def0u64,
                    0xfedc_ba98_7654_3210_0123_4567_89ab_cdefu128,
                ),
                (u64::MAX, 0x0011_2233_4455_6677_8899_aabb_ccdd_eeff),
            ] {
                let initial = [u128::from(scalar), vector];
                let mut output = [0; 2];
                let mut caller = [0; 2];
                let returned = unsafe { function(&initial, &mut output, &mut caller) };
                let expected = match boundary {
                    NonvolatileBoundary::ReadOnly => (scalar, vector),
                    NonvolatileBoundary::NativeRead => (scalar.wrapping_add(7), 0),
                    NonvolatileBoundary::PartialWrite => {
                        ((scalar & !0xff) | 0x5a, vector & !u128::from(u32::MAX))
                    }
                };
                assert_eq!(returned, expected.0, "{boundary:?}");
                assert_eq!(output, [u128::from(expected.0), expected.1], "{boundary:?}");
                assert_eq!(caller, initial, "full RBX/XMM6 caller state: {boundary:?}");
            }
        }
    }
    for (boundary, saved, expected) in save_cases {
        assert_eq!(saved, expected, "{boundary:?}");
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod native {
    use super::{ALLOCATION_SIZE, CLOBBERING_HELPER, HELPER_OFFSET, Witness};
    use core::ffi::c_void;
    use iced_x86::{Code, Instruction, MemoryOperand, Register};
    use windows::Win32::System::Diagnostics::Debug::{
        IMAGE_RUNTIME_FUNCTION_ENTRY, IMAGE_RUNTIME_FUNCTION_ENTRY_0, RtlAddFunctionTable,
        RtlDeleteFunctionTable,
    };

    const CALLER_OFFSET: usize = HELPER_OFFSET - 4096;

    fn nonvolatile_caller(entry: u64) -> Vec<u8> {
        use Register::*;
        let stack = |offset| MemoryOperand::with_base_displ(RSP, offset);
        let at = |base, offset| MemoryOperand::with_base_displ(base, offset);
        let instructions = vec![
            Instruction::with1(Code::Push_r64, RBX).unwrap(),
            Instruction::with2(Code::Sub_rm64_imm8, RSP, 64i32).unwrap(),
            Instruction::with2(Code::Movups_xmmm128_xmm, stack(48), XMM6).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, stack(32), R8).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, RBX, at(RCX, 0)).unwrap(),
            Instruction::with2(Code::Movups_xmm_xmmm128, XMM6, at(RCX, 16)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, RCX, RDX).unwrap(),
            Instruction::with_branch(Code::Call_rel32_64, entry).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, R10, stack(32)).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, at(R10, 0), RBX).unwrap(),
            Instruction::with2(Code::Movups_xmmm128_xmm, at(R10, 16), XMM6).unwrap(),
            Instruction::with2(Code::Movups_xmm_xmmm128, XMM6, stack(48)).unwrap(),
            Instruction::with2(Code::Add_rm64_imm8, RSP, 64i32).unwrap(),
            Instruction::with1(Code::Pop_r64, RBX).unwrap(),
            Instruction::with(Code::Retnq),
        ];
        kamy_codegen::relocate(&instructions, entry + CALLER_OFFSET as u64).unwrap()
    }

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

    pub(super) struct Executable {
        allocation: *mut c_void,
        code_len: u32,
        runtime_functions: Option<Box<[IMAGE_RUNTIME_FUNCTION_ENTRY]>>,
    }

    impl Executable {
        pub(super) fn new(witness: &Witness) -> Self {
            Self::build(witness, false)
        }

        pub(super) fn with_nonvolatile_caller(witness: &Witness) -> Self {
            Self::build(witness, true)
        }

        fn build(witness: &Witness, include_caller: bool) -> Self {
            let allocation =
                unsafe { VirtualAlloc(core::ptr::null_mut(), ALLOCATION_SIZE, 0x3000, 4) };
            assert!(!allocation.is_null(), "VirtualAlloc failed");
            let mut executable = Self {
                allocation,
                code_len: 0,
                runtime_functions: None,
            };
            let code = witness.lower(allocation as u64);
            executable.code_len = u32::try_from(code.len()).unwrap();
            let mut runtime_functions = Vec::new();
            unsafe {
                let bytes = allocation.cast::<u8>();
                core::ptr::copy_nonoverlapping(code.as_ptr(), bytes, code.len());
                core::ptr::copy_nonoverlapping(
                    CLOBBERING_HELPER.as_ptr(),
                    bytes.add(HELPER_OFFSET),
                    CLOBBERING_HELPER.len(),
                );
                if include_caller {
                    let ranges = kamy_seh::unwind_ranges(&code, allocation as u64)
                        .expect("exact generated bytes MUST have native unwind metadata");
                    let mut metadata_offset = (code.len() + 3) & !3;
                    let mut covered = 0;
                    for range in ranges {
                        assert_eq!(
                            range.begin, covered,
                            "runtime records MUST cover every fixture byte"
                        );
                        assert!(range.begin < range.end && range.end <= executable.code_len);
                        covered = range.end;
                        assert_eq!(metadata_offset % 4, 0);
                        let metadata_end = metadata_offset.checked_add(range.info.len()).unwrap();
                        assert!(
                            metadata_end <= CALLER_OFFSET,
                            "metadata overlaps the caller trampoline"
                        );
                        core::ptr::copy_nonoverlapping(
                            range.info.as_ptr(),
                            bytes.add(metadata_offset),
                            range.info.len(),
                        );
                        runtime_functions.push(IMAGE_RUNTIME_FUNCTION_ENTRY {
                            BeginAddress: range.begin,
                            EndAddress: range.end,
                            Anonymous: IMAGE_RUNTIME_FUNCTION_ENTRY_0 {
                                UnwindInfoAddress: u32::try_from(metadata_offset).unwrap(),
                            },
                        });
                        metadata_offset = (metadata_end + 3) & !3;
                    }
                    assert_eq!(covered, executable.code_len);
                    assert!(!runtime_functions.is_empty());
                    let caller = nonvolatile_caller(allocation as u64);
                    assert!(caller.len() <= HELPER_OFFSET - CALLER_OFFSET);
                    core::ptr::copy_nonoverlapping(
                        caller.as_ptr(),
                        bytes.add(CALLER_OFFSET),
                        caller.len(),
                    );
                }
                let mut old = 0;
                assert_ne!(
                    VirtualProtect(allocation, ALLOCATION_SIZE, 0x20, &mut old),
                    0,
                    "VirtualProtect failed"
                );
                assert_ne!(
                    FlushInstructionCache(GetCurrentProcess(), allocation, ALLOCATION_SIZE),
                    0,
                    "FlushInstructionCache failed"
                );
                if include_caller {
                    // The boxed table keeps the registered pointer stable until Drop,
                    // while all UNWIND_INFO RVAs refer to this exact executable allocation.
                    let table = runtime_functions.into_boxed_slice();
                    assert!(
                        RtlAddFunctionTable(&table, allocation as u64).as_bool(),
                        "RtlAddFunctionTable failed"
                    );
                    executable.runtime_functions = Some(table);
                }
            }
            executable
        }

        pub(super) fn address(&self) -> *mut c_void {
            self.allocation
        }

        pub(super) fn caller_address(&self) -> *mut c_void {
            unsafe { self.allocation.cast::<u8>().add(CALLER_OFFSET).cast() }
        }

        pub(super) fn check_unwind(&self) -> super::native_probe::windows_oracle::Report {
            assert!(
                self.runtime_functions.is_some(),
                "native unwind requires registered metadata"
            );
            unsafe {
                super::native_probe::windows_oracle::check_function(
                    self.allocation.cast(),
                    0,
                    self.code_len,
                )
            }
            .expect("registered exact nonvolatile fixture MUST unwind every reachable native PC")
        }
    }

    impl Drop for Executable {
        fn drop(&mut self) {
            if let Some(table) = &self.runtime_functions {
                assert!(
                    unsafe { RtlDeleteFunctionTable(table.as_ptr()) }.as_bool(),
                    "RtlDeleteFunctionTable failed"
                );
            }
            assert_ne!(
                unsafe { VirtualFree(self.allocation, 0, 0x8000) },
                0,
                "VirtualFree failed"
            );
        }
    }
}
