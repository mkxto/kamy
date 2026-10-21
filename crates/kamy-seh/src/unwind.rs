use std::collections::{BTreeMap, VecDeque};

use anyhow::{Context, Result, bail, ensure};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};

/// A half-open code range, relative to the supplied entry VA, and its UNWIND_INFO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindRange {
    pub begin: u32,
    pub end: u32,
    pub info: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Constant(u64),
    Stack(i64),
    OriginalGpr(u8),
    OriginalXmm(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    size: usize,
    value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    gprs: [Value; 16],
    xmms: [Value; 16],
    slots: BTreeMap<i64, Slot>,
}

const NONVOLATILE_GPRS: [usize; 8] = [3, 5, 6, 7, 12, 13, 14, 15];

impl State {
    fn entry() -> Self {
        let mut state = Self {
            gprs: std::array::from_fn(|i| Value::OriginalGpr(i as u8)),
            xmms: std::array::from_fn(|i| Value::OriginalXmm(i as u8)),
            slots: BTreeMap::new(),
        };
        state.gprs[4] = Value::Stack(0);
        state
    }

    fn rsp(&self) -> Result<i64> {
        match self.gprs[4] {
            Value::Stack(offset) => Ok(offset),
            _ => bail!("RSP is not a statically proved entry-stack offset"),
        }
    }

    fn set_rsp(&mut self, offset: i64) -> Result<()> {
        ensure!(offset <= 0, "RSP rises above the entry return address");
        ensure!(
            offset % 8 == 0,
            "RSP offset {offset} is not eight-byte aligned"
        );
        ensure!(
            offset >= -(u32::MAX as i64),
            "stack frame exceeds UNWIND_INFO limits"
        );
        self.gprs[4] = Value::Stack(offset);
        // Released stack storage cannot remain a source for subsequent unwinds.
        self.slots.retain(|address, _| *address >= offset);
        Ok(())
    }

    fn register(&self, reg: Register) -> Value {
        if let Some(index) = gpr_index(reg) {
            let value = self.gprs[index];
            if reg.is_gpr64() {
                value
            } else if let Value::Constant(value) = value {
                let shift = if matches!(
                    reg,
                    Register::AH | Register::CH | Register::DH | Register::BH
                ) {
                    8
                } else {
                    0
                };
                Value::Constant((value >> shift) & width_mask(reg.size()))
            } else {
                Value::Unknown
            }
        } else if let Some(index) = xmm_index(reg) {
            self.xmms[index]
        } else {
            Value::Unknown
        }
    }

    fn set_register(&mut self, reg: Register, value: Value) -> Result<()> {
        if let Some(index) = gpr_index(reg) {
            let value = if reg.is_gpr64() {
                value
            } else if reg.size() == 4 {
                match value {
                    Value::Constant(value) => Value::Constant(value & u32::MAX as u64),
                    _ => Value::Unknown,
                }
            } else {
                Value::Unknown
            };
            if index == 4 {
                let Value::Stack(offset) = value else {
                    bail!("instruction makes RSP dynamic or truncates a stack snapshot");
                };
                self.set_rsp(offset)?;
            } else {
                self.gprs[index] = value;
            }
        } else if let Some(index) = xmm_index(reg) {
            self.xmms[index] = value;
        }
        Ok(())
    }

    fn store(&mut self, address: i64, size: usize, value: Value) -> Result<()> {
        ensure!(size != 0, "stack store has an unknown width");
        let end = address
            .checked_add(size as i64)
            .context("stack store offset overflow")?;
        ensure!(
            end <= 0 || address >= 8,
            "stack store overwrites the entry return address"
        );
        ensure!(
            address >= self.rsp()?,
            "stack store uses unallocated storage below RSP"
        );
        self.slots.retain(|slot_address, slot| {
            *slot_address + slot.size as i64 <= address || *slot_address >= end
        });
        if value != Value::Unknown {
            self.slots.insert(address, Slot { size, value });
        }
        Ok(())
    }

    fn load(&self, address: i64, size: usize) -> Value {
        self.slots
            .get(&address)
            .filter(|slot| slot.size == size)
            .map_or(Value::Unknown, |slot| slot.value)
    }

    fn merge(&mut self, incoming: &Self) -> Result<bool> {
        ensure!(
            self.rsp()? == incoming.rsp()?,
            "control-flow join has incompatible RSP offsets"
        );
        let mut changed = false;
        for (current, other) in self.gprs.iter_mut().zip(incoming.gprs) {
            if *current != other && *current != Value::Unknown {
                *current = Value::Unknown;
                changed = true;
            }
        }
        for (current, other) in self.xmms.iter_mut().zip(incoming.xmms) {
            if *current != other && *current != Value::Unknown {
                *current = Value::Unknown;
                changed = true;
            }
        }
        self.slots.retain(|address, slot| {
            let keep = incoming.slots.get(address) == Some(slot);
            changed |= !keep;
            keep
        });
        self.plan()
            .context("control-flow join loses a nonvolatile save")?;
        Ok(changed)
    }

    fn plan(&self) -> Result<Plan> {
        let rsp = self.rsp()?;
        let mut saves = [None; 18];
        for (index, &reg) in NONVOLATILE_GPRS.iter().enumerate() {
            saves[index] =
                self.save_location(Value::OriginalGpr(reg as u8), 8, self.gprs[reg], rsp)?;
        }
        for reg in 6..16 {
            saves[reg + 2] =
                self.save_location(Value::OriginalXmm(reg as u8), 16, self.xmms[reg], rsp)?;
        }
        Ok(Plan {
            allocation: (-rsp) as u32,
            saves,
        })
    }

    fn save_location(
        &self,
        original: Value,
        size: usize,
        current: Value,
        rsp: i64,
    ) -> Result<Option<(Value, u32)>> {
        for (&address, slot) in &self.slots {
            if slot.size == size && slot.value == original && address >= rsp {
                let offset = address
                    .checked_sub(rsp)
                    .context("nonvolatile save offset overflow")?;
                let offset = u32::try_from(offset)
                    .context("nonvolatile save offset exceeds UNWIND_INFO limits")?;
                return Ok(Some((original, offset)));
            }
        }
        ensure!(
            current == original,
            "{original:?} is modified without a provable live stack save"
        );
        Ok(None)
    }

    fn returned(&self) -> Result<()> {
        ensure!(
            self.rsp()? == 0,
            "RET does not restore the entry stack pointer"
        );
        for &reg in &NONVOLATILE_GPRS {
            ensure!(
                self.gprs[reg] == Value::OriginalGpr(reg as u8),
                "RET does not restore nonvolatile GPR {reg}"
            );
        }
        for reg in 6..16 {
            ensure!(
                self.xmms[reg] == Value::OriginalXmm(reg as u8),
                "RET does not restore XMM{reg}"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Plan {
    allocation: u32,
    saves: [Option<(Value, u32)>; 18],
}

impl Plan {
    fn encode(&self) -> Result<Vec<u8>> {
        let slots = self
            .saves
            .iter()
            .flatten()
            .map(|&(register, offset)| {
                let scale = if matches!(register, Value::OriginalGpr(_)) {
                    8
                } else {
                    16
                };
                if offset % scale == 0 && offset / scale <= u16::MAX as u32 {
                    2
                } else {
                    3
                }
            })
            .sum::<usize>()
            + allocation_slots(self.allocation);
        let count = u8::try_from(slots).context("too many unwind code slots")?;
        let mut info = Vec::with_capacity(4 + slots.next_multiple_of(2).max(2) * 2);
        // Version 1 mistakes cross-fragment jumps for epilogues and ignores the state.
        // Version 2 without EPILOG descriptors applies the recorded state directly.
        // https://github.com/dotnet/runtime/blob/main/src/coreclr/unwinder/amd64/unwinder.cpp
        info.extend_from_slice(&[2, 0, count, 0]);
        for &(register, offset) in self.saves.iter().flatten() {
            encode_save(&mut info, register, offset);
        }
        encode_allocation(&mut info, self.allocation);
        if count == 0 {
            // Version 2 readers inspect the first slot even when CountOfCodes is zero.
            info.extend_from_slice(&[0, 0, 0, 0]);
        } else if count % 2 != 0 {
            info.extend_from_slice(&[0, 0]);
        }
        Ok(info)
    }
}

fn allocation_slots(size: u32) -> usize {
    match size {
        0 => 0,
        8..=128 => 1,
        size if size / 8 <= u16::MAX as u32 => 2,
        _ => 3,
    }
}

fn encode_allocation(info: &mut Vec<u8>, size: u32) {
    match size {
        0 => {}
        size @ 8..=128 => info.extend_from_slice(&[0, (((size - 8) / 8) as u8) << 4 | 2]),
        size if size / 8 <= u16::MAX as u32 => {
            info.extend_from_slice(&[0, 1]);
            info.extend_from_slice(&((size / 8) as u16).to_le_bytes());
        }
        size => {
            info.extend_from_slice(&[0, 0x11]);
            info.extend_from_slice(&size.to_le_bytes());
        }
    }
}

fn encode_save(info: &mut Vec<u8>, register: Value, offset: u32) {
    let (number, near, far, scale) = match register {
        Value::OriginalGpr(number) => (number, 4, 5, 8),
        Value::OriginalXmm(number) => (number, 8, 9, 16),
        _ => unreachable!(),
    };
    if offset % scale == 0 && offset / scale <= u16::MAX as u32 {
        info.extend_from_slice(&[0, (number << 4) | near]);
        info.extend_from_slice(&((offset / scale) as u16).to_le_bytes());
    } else {
        // FAR uses an unscaled byte offset, including unaligned MOVUPS save slots.
        // SAVE reads the fixed frame base, not the RSP advanced by ALLOC.
        // https://github.com/dotnet/runtime/blob/main/src/coreclr/unwinder/amd64/unwinder.cpp
        info.extend_from_slice(&[0, (number << 4) | far]);
        info.extend_from_slice(&offset.to_le_bytes());
    }
}

/// Reconstructs reachable Win64 unwind states from final encoded instructions.
/// Rejects dynamic frames, incompatible joins, and nonvolatile values that cannot
/// be recovered from their current register or a statically proved stack slot.
/// Handler-bearing source functions must be rejected before calling this API.
/// Unresolved indirect branches are terminal tails; callers must rule out opaque
/// in-function successors before supplying generated code.
pub fn unwind_ranges(code: &[u8], entry_va: u64) -> Result<Vec<UnwindRange>> {
    ensure!(!code.is_empty(), "cannot reconstruct unwind for empty code");
    let length = u32::try_from(code.len()).context("function exceeds RVA range")?;
    let end_va = entry_va
        .checked_add(code.len() as u64)
        .context("function VA overflow")?;
    let mut instructions = BTreeMap::<u32, Instruction>::new();
    let mut states = BTreeMap::from([(0u32, State::entry())]);
    let mut queue = VecDeque::from([0u32]);
    let mut factory = InstructionInfoFactory::new();
    while let Some(offset) = queue.pop_front() {
        let instruction = if let Some(instruction) = instructions.get(&offset) {
            *instruction
        } else {
            if let Some((&previous, instruction)) = instructions.range(..offset).next_back() {
                ensure!(
                    previous + instruction.len() as u32 <= offset,
                    "branch at +{offset:#x} enters an instruction"
                );
            }
            let mut decoder = Decoder::with_ip(
                64,
                &code[offset as usize..],
                entry_va + offset as u64,
                DecoderOptions::NONE,
            );
            let instruction = decoder.decode();
            ensure!(
                !instruction.is_invalid(),
                "invalid instruction at +{offset:#x}"
            );
            let next = offset + instruction.len() as u32;
            if let Some((&following, _)) = instructions.range((offset + 1)..).next() {
                ensure!(
                    next <= following,
                    "instruction at +{offset:#x} overlaps a branch target"
                );
            }
            instructions.insert(offset, instruction);
            instruction
        };
        let mut state = states[&offset].clone();
        state
            .plan()
            .with_context(|| format!("unwind state at +{offset:#x} ({:#x})", instruction.ip()))?;
        transfer(&instruction, &mut state, &mut factory).with_context(|| {
            format!(
                "unwind instruction at +{offset:#x} ({:#x}, {:?})",
                instruction.ip(),
                instruction.mnemonic()
            )
        })?;
        state
            .plan()
            .with_context(|| format!("unwind state after +{offset:#x}"))?;
        let next = offset + instruction.len() as u32;
        let mut successors = [None; 2];
        let internal_target = |target: u64| {
            (target >= entry_va && target < end_va).then(|| (target - entry_va) as u32)
        };
        match instruction.flow_control() {
            FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
                ensure!(
                    next < length,
                    "reachable fallthrough exits the code at +{next:#x}"
                );
                successors[0] = Some(next);
            }
            FlowControl::ConditionalBranch => {
                successors[0] = internal_target(instruction.near_branch_target());
                ensure!(
                    next < length,
                    "conditional fallthrough exits the code at +{next:#x}"
                );
                successors[1] = Some(next);
            }
            FlowControl::UnconditionalBranch => {
                ensure!(
                    matches!(instruction.op0_kind(), OpKind::NearBranch64),
                    "far branch at +{offset:#x} is unsupported"
                );
                successors[0] = internal_target(instruction.near_branch_target());
            }
            FlowControl::IndirectBranch => {
                if let Value::Constant(target) = operand(&instruction, 0, &state)? {
                    successors[0] = internal_target(target);
                } else if instruction.is_ip_rel_memory_operand() {
                    let address = instruction.ip_rel_memory_address();
                    if address >= entry_va
                        && address.checked_add(8).is_some_and(|end| end <= end_va)
                    {
                        let begin = (address - entry_va) as usize;
                        successors[0] = internal_target(u64::from_le_bytes(
                            code[begin..begin + 8].try_into().unwrap(),
                        ));
                    }
                }
            }
            FlowControl::Return => state
                .returned()
                .with_context(|| format!("return at +{offset:#x}"))?,
            FlowControl::Exception | FlowControl::Interrupt => {}
            other => bail!("unsupported control flow {other:?} at +{offset:#x}"),
        }
        for successor in successors.into_iter().flatten() {
            if let Some(current) = states.get_mut(&successor) {
                if current
                    .merge(&state)
                    .with_context(|| format!("join at +{successor:#x} from +{offset:#x}"))?
                {
                    queue.push_back(successor);
                }
            } else {
                states.insert(successor, state.clone());
                queue.push_back(successor);
            }
        }
    }
    let mut ranges = Vec::<UnwindRange>::new();
    let mut previous_plan = None;
    for (&offset, instruction) in &instructions {
        let plan = states[&offset].plan()?;
        let end = offset + instruction.len() as u32;
        if let Some(previous) = ranges
            .last_mut()
            .filter(|previous| previous.end == offset && previous_plan.as_ref() == Some(&plan))
        {
            previous.end = end;
        } else {
            let info = plan
                .encode()
                .with_context(|| format!("encoding unwind state at +{offset:#x}"))?;
            ranges.push(UnwindRange {
                begin: offset,
                end,
                info,
            });
        }
        previous_plan = Some(plan);
    }
    tracing::trace!(
        entry_va,
        instructions = instructions.len(),
        ranges = ranges.len(),
        "reconstructed unwind states"
    );
    Ok(ranges)
}

fn gpr_index(reg: Register) -> Option<usize> {
    reg.is_gpr().then(|| reg.full_register().number())
}

fn xmm_index(reg: Register) -> Option<usize> {
    (reg.is_xmm() || reg.is_ymm() || reg.is_zmm())
        .then(|| reg.number())
        .filter(|&number| number < 16)
}

fn width_mask(size: usize) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn address(instruction: &Instruction, state: &State) -> Result<Value> {
    if instruction.is_ip_rel_memory_operand() {
        return Ok(Value::Constant(instruction.ip_rel_memory_address()));
    }
    let base = instruction.memory_base();
    let index = instruction.memory_index();
    let mut value = if base == Register::None {
        Value::Constant(0)
    } else {
        state.register(base)
    };
    if index != Register::None {
        let index_value = state.register(index);
        if let Value::Constant(index_value) = index_value {
            value = add(
                value,
                index_value.wrapping_mul(instruction.memory_index_scale() as u64) as i64,
            )?;
        } else if let (Value::Constant(base), Value::Stack(offset)) = (value, index_value) {
            ensure!(
                instruction.memory_index_scale() == 1,
                "scaled stack snapshot cannot be proved"
            );
            value = add(Value::Stack(offset), base as i64)?;
        } else {
            ensure!(
                !matches!(value, Value::Stack(_)) && !matches!(index_value, Value::Stack(_)),
                "stack access has an unproved index"
            );
            return Ok(Value::Unknown);
        }
    }
    value = add(value, instruction.memory_displacement64() as i64)?;
    if matches!(value, Value::Stack(_)) {
        ensure!(
            !matches!(instruction.memory_segment(), Register::FS | Register::GS),
            "segmented stack address cannot be proved"
        );
    }
    Ok(value)
}

fn add(value: Value, increment: i64) -> Result<Value> {
    Ok(match value {
        Value::Stack(offset) => Value::Stack(
            offset
                .checked_add(increment)
                .context("stack address overflow")?,
        ),
        Value::Constant(value) => Value::Constant(value.wrapping_add(increment as u64)),
        _ => Value::Unknown,
    })
}

fn operand(instruction: &Instruction, index: u32, state: &State) -> Result<Value> {
    Ok(match instruction.op_kind(index) {
        OpKind::Register => state.register(instruction.op_register(index)),
        OpKind::Memory => match address(instruction, state)? {
            Value::Stack(address) => state.load(address, instruction.memory_size().size()),
            _ => Value::Unknown,
        },
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Value::Constant(instruction.immediate(index)),
        _ => Value::Unknown,
    })
}

fn arithmetic(instruction: &Instruction, state: &State) -> Result<Option<Value>> {
    use Mnemonic::*;
    let mnemonic = instruction.mnemonic();
    if !matches!(
        mnemonic,
        Add | Sub | And | Or | Xor | Shl | Shr | Sar | Inc | Dec | Neg | Not
    ) {
        return Ok(None);
    }
    let lhs = operand(instruction, 0, state)?;
    let rhs = if instruction.op_count() > 1 {
        operand(instruction, 1, state)?
    } else {
        Value::Constant(1)
    };
    if mnemonic == Xor
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Register
        && instruction.op0_register() == instruction.op1_register()
    {
        return Ok(Some(Value::Constant(0)));
    }
    if let (Add, Value::Constant(value), Value::Stack(offset)) = (mnemonic, lhs, rhs) {
        return Ok(Some(add(Value::Stack(offset), value as i64)?));
    }
    if let (Sub, Value::Stack(lhs), Value::Stack(rhs)) = (mnemonic, lhs, rhs) {
        return Ok(Some(Value::Constant(
            lhs.checked_sub(rhs)
                .context("stack snapshot difference overflow")? as u64,
        )));
    }
    if let Value::Stack(offset) = lhs {
        let result = match (mnemonic, rhs) {
            (Add | Inc, Value::Constant(value)) => add(lhs, value as i64)?,
            (Sub | Dec, Value::Constant(value)) => add(
                lhs,
                (value as i64)
                    .checked_neg()
                    .context("stack subtraction overflow")?,
            )?,
            (And, Value::Constant(mask)) => {
                let alignment = (!mask).wrapping_add(1);
                ensure!(
                    alignment.is_power_of_two() && alignment <= 16,
                    "stack alignment exceeds known Win64 entry alignment"
                );
                Value::Stack(offset - (offset + 8).rem_euclid(alignment as i64))
            }
            _ => Value::Unknown,
        };
        return Ok(Some(result));
    }
    let (Value::Constant(lhs), Value::Constant(rhs)) = (lhs, rhs) else {
        return Ok(Some(Value::Unknown));
    };
    let width = instruction.op0_register().size();
    let shift_mask = if width == 8 { 63 } else { 31 };
    let value = match mnemonic {
        Add | Inc => lhs.wrapping_add(rhs),
        Sub | Dec => lhs.wrapping_sub(rhs),
        And => lhs & rhs,
        Or => lhs | rhs,
        Xor => lhs ^ rhs,
        Shl => lhs.wrapping_shl((rhs & shift_mask) as u32),
        Shr => (lhs & width_mask(width)).wrapping_shr((rhs & shift_mask) as u32),
        Sar => {
            let bits = width * 8;
            let signed = ((lhs << (64 - bits)) as i64) >> (64 - bits);
            (signed >> (rhs & shift_mask)) as u64
        }
        Neg => lhs.wrapping_neg(),
        Not => !lhs,
        _ => unreachable!(),
    };
    Ok(Some(Value::Constant(value & width_mask(width))))
}

fn full_move(instruction: &Instruction) -> bool {
    matches!(
        instruction.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Movaps
            | Mnemonic::Movups
            | Mnemonic::Movdqa
            | Mnemonic::Movdqu
            | Mnemonic::Vmovaps
            | Mnemonic::Vmovups
            | Mnemonic::Vmovdqa
            | Mnemonic::Vmovdqu
    )
}

fn transfer(
    instruction: &Instruction,
    state: &mut State,
    factory: &mut InstructionInfoFactory,
) -> Result<()> {
    use Mnemonic::*;
    match instruction.mnemonic() {
        Push | Pushfq => {
            ensure!(
                instruction.stack_pointer_increment() == -8,
                "unsupported push width"
            );
            let value = if instruction.mnemonic() == Push {
                operand(instruction, 0, state)?
            } else {
                Value::Unknown
            };
            let rsp = state.rsp()?.checked_sub(8).context("push stack overflow")?;
            state.set_rsp(rsp)?;
            state.store(rsp, 8, value)?;
            return Ok(());
        }
        Pop | Popfq => {
            ensure!(
                instruction.stack_pointer_increment() == 8,
                "unsupported pop width"
            );
            let rsp = state.rsp()?;
            ensure!(rsp < 0, "pop consumes the entry return address");
            let value = state.load(rsp, 8);
            state.set_rsp(rsp + 8)?;
            if instruction.mnemonic() == Pop {
                ensure!(
                    instruction.op0_kind() == OpKind::Register,
                    "memory pop is unsupported"
                );
                state.set_register(instruction.op0_register(), value)?;
            }
            return Ok(());
        }
        Leave => {
            let Value::Stack(rsp) = state.register(Register::RBP) else {
                bail!("LEAVE frame pointer is not a proved stack snapshot");
            };
            state.set_rsp(rsp)?;
            let value = state.load(rsp, 8);
            ensure!(rsp < 0, "LEAVE consumes the entry return address");
            state.set_rsp(rsp + 8)?;
            state.set_register(Register::RBP, value)?;
            return Ok(());
        }
        Ret => {
            ensure!(
                instruction.op_count() == 0 || instruction.immediate16() == 0,
                "RET with argument cleanup is unsupported on Win64"
            );
            return Ok(());
        }
        Enter => bail!("ENTER frame construction is unsupported"),
        _ => {}
    }
    if matches!(
        instruction.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    ) {
        let rsp = state.rsp()?;
        state
            .slots
            .retain(|address, slot| *address + slot.size as i64 <= rsp || *address >= rsp + 32);
        for reg in [0, 1, 2, 8, 9, 10, 11] {
            state.gprs[reg] = Value::Unknown;
        }
        state.xmms[..6].fill(Value::Unknown);
        return Ok(());
    }
    let info = factory.info(instruction);
    let destination = (instruction.op_count() != 0
        && instruction.op0_kind() == OpKind::Register
        && writes(info.op0_access()))
    .then(|| instruction.op0_register());
    let result = if let Some(destination) = destination {
        if instruction.mnemonic() == Lea {
            Some(address(instruction, state)?)
        } else if full_move(instruction) {
            let value = operand(instruction, 1, state)?;
            let full_width = destination.is_gpr()
                || (destination.is_xmm()
                    && (instruction.op1_kind() != OpKind::Memory
                        || instruction.memory_size().size() == 16));
            Some(if full_width { value } else { Value::Unknown })
        } else {
            arithmetic(instruction, state)?
        }
    } else {
        None
    };
    let memory_address = if instruction.op_kinds().any(|kind| kind == OpKind::Memory) {
        Some(address(instruction, state)?)
    } else {
        None
    };
    let mut stack_write = None;
    for memory in info.used_memory() {
        if writes(memory.access()) {
            let location = memory_address.context("implicit memory write cannot be proved")?;
            if let Value::Stack(address) = location {
                ensure!(
                    stack_write.is_none(),
                    "multiple stack writes cannot be proved"
                );
                let size = memory.memory_size().size();
                let value = if full_move(instruction) && instruction.op0_kind() == OpKind::Memory {
                    match operand(instruction, 1, state)? {
                        Value::Constant(value) if size <= 8 => {
                            Value::Constant(value & width_mask(size))
                        }
                        value @ (Value::Stack(_) | Value::OriginalGpr(_)) if size == 8 => value,
                        value @ Value::OriginalXmm(_) if size == 16 => value,
                        _ => Value::Unknown,
                    }
                } else {
                    Value::Unknown
                };
                stack_write = Some((address, size, value));
            }
        }
    }
    for used in info.used_registers() {
        if writes(used.access()) {
            if gpr_index(used.register()) == Some(4) {
                ensure!(
                    destination == Some(Register::RSP) && result.is_some(),
                    "unmodeled instruction modifies RSP"
                );
            } else {
                state.set_register(used.register(), Value::Unknown)?;
            }
        }
    }
    if let Some((address, size, value)) = stack_write {
        state.store(address, size, value)?;
    }
    if let (Some(destination), Some(value)) = (destination, result) {
        state.set_register(destination, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: u64 = 0x140001000;

    fn info_at(ranges: &[UnwindRange], offset: u32) -> &[u8] {
        let mut matching = ranges
            .iter()
            .filter(|range| range.begin <= offset && offset < range.end);
        let range = matching
            .next()
            .expect("reachable instruction has unwind coverage");
        assert!(matching.next().is_none(), "unwind ranges do not overlap");
        &range.info
    }

    fn restore(
        info: &[u8],
        mut rsp: i64,
        gprs: &mut [u64; 16],
        xmms: &mut [u128; 16],
        stack: &BTreeMap<i64, u128>,
    ) -> i64 {
        assert!(matches!(info[0] & 7, 1 | 2));
        let frame_base = rsp;
        let mut slot = 0usize;
        let word =
            |slot: usize| u16::from_le_bytes(info[4 + slot * 2..6 + slot * 2].try_into().unwrap());
        let dword =
            |slot: usize| u32::from_le_bytes(info[4 + slot * 2..8 + slot * 2].try_into().unwrap());
        while slot < info[2] as usize {
            let code = info[5 + slot * 2];
            let register = (code >> 4) as usize;
            match code & 15 {
                1 if register == 0 => {
                    rsp += word(slot + 1) as i64 * 8;
                    slot += 2;
                }
                1 if register == 1 => {
                    rsp += dword(slot + 1) as i64;
                    slot += 3;
                }
                2 => {
                    rsp += register as i64 * 8 + 8;
                    slot += 1;
                }
                4 | 5 | 8 | 9 => {
                    let opcode = code & 15;
                    let offset = if opcode == 4 || opcode == 8 {
                        word(slot + 1) as i64 * if opcode == 4 { 8 } else { 16 }
                    } else {
                        dword(slot + 1) as i64
                    };
                    let value = stack[&(frame_base + offset)];
                    if opcode == 4 || opcode == 5 {
                        gprs[register] = value as u64;
                    } else {
                        xmms[register] = value;
                    }
                    slot += if opcode == 4 || opcode == 8 { 2 } else { 3 };
                }
                opcode => panic!("unexpected unwind operation {opcode}"),
            }
        }
        assert_eq!(slot, info[2] as usize);
        rsp + 8
    }

    #[test]
    fn body_allocation_and_unaligned_xmm_saves_restore_the_caller() {
        let code = [
            0x53, 0x48, 0x83, 0xec, 0x30, 0x0f, 0x11, 0x74, 0x24, 0x08, 0x48, 0x31, 0xdb, 0x0f,
            0x57, 0xf6, 0x48, 0x83, 0xec, 0x20, 0x90, 0x48, 0x83, 0xc4, 0x20, 0x0f, 0x10, 0x74,
            0x24, 0x08, 0x48, 0x83, 0xc4, 0x30, 0x5b, 0xc3,
        ];
        let ranges = unwind_ranges(&code, ENTRY).unwrap();
        let original_gprs = std::array::from_fn(|index| 0x1000 + index as u64);
        let original_xmms =
            std::array::from_fn(|index| (0x2000 + index as u128) << 64 | index as u128);
        let stack = BTreeMap::from([(-8, original_gprs[3] as u128), (-48, original_xmms[6])]);
        for (offset, rsp, dirty_rbx, dirty_xmm) in [
            (0, 0, false, false),
            (1, -8, false, false),
            (5, -56, false, false),
            (10, -56, false, false),
            (13, -56, true, false),
            (16, -56, true, true),
            (20, -88, true, true),
            (21, -88, true, true),
            (25, -56, true, true),
            (30, -56, true, false),
            (34, -8, true, false),
            (35, 0, false, false),
        ] {
            let mut gprs = original_gprs;
            let mut xmms = original_xmms;
            if dirty_rbx {
                gprs[3] = 0;
            }
            if dirty_xmm {
                xmms[6] = 0;
            }
            assert_eq!(
                restore(info_at(&ranges, offset), rsp, &mut gprs, &mut xmms, &stack),
                8
            );
            assert_eq!(gprs[3], original_gprs[3], "RBX at +{offset:#x}");
            assert_eq!(xmms[6], original_xmms[6], "XMM6 at +{offset:#x}");
        }
        assert_eq!(ranges.first().unwrap().begin, 0);
        assert_eq!(ranges.last().unwrap().end as usize, code.len());
    }

    #[test]
    fn translator_flag_and_volatile_pushes_are_stack_allocations() {
        let code = [
            0x9c, 0x50, 0x41, 0x52, 0x90, 0x41, 0x5a, 0x58, 0x9d, 0x41, 0xff, 0xe3,
        ];
        let ranges = unwind_ranges(&code, ENTRY).unwrap();
        for (offset, rsp) in [
            (0, 0),
            (1, -8),
            (2, -16),
            (4, -24),
            (5, -24),
            (7, -16),
            (8, -8),
            (9, 0),
        ] {
            assert_eq!(
                restore(
                    info_at(&ranges, offset),
                    rsp,
                    &mut [0; 16],
                    &mut [0; 16],
                    &BTreeMap::new()
                ),
                8
            );
        }
    }

    #[test]
    fn register_constant_stack_arithmetic_preserves_stack_snapshots() {
        let code = [
            0xb8, 0x40, 0x00, 0x00, 0x00, 0x48, 0x29, 0xc4, 0x49, 0x89, 0xe2, 0x48, 0x83, 0xec,
            0x20, 0x4c, 0x89, 0xd4, 0x48, 0x01, 0xc4, 0xc3,
        ];
        let ranges = unwind_ranges(&code, ENTRY).unwrap();
        for (offset, rsp) in [
            (0, 0),
            (5, 0),
            (8, -64),
            (11, -64),
            (15, -96),
            (18, -64),
            (21, 0),
        ] {
            assert_eq!(
                restore(
                    info_at(&ranges, offset),
                    rsp,
                    &mut [0; 16],
                    &mut [0; 16],
                    &BTreeMap::new()
                ),
                8
            );
        }
    }

    #[test]
    fn stack_stored_snapshot_can_restore_rsp() {
        let code = [
            0x49, 0x89, 0xe2, 0x48, 0x83, 0xec, 0x10, 0x4c, 0x89, 0x54, 0x24, 0x08, 0x48, 0x83,
            0xec, 0x20, 0x48, 0x8b, 0x64, 0x24, 0x28, 0xc3,
        ];
        let ranges = unwind_ranges(&code, ENTRY).unwrap();
        assert_eq!(
            restore(
                info_at(&ranges, 16),
                -48,
                &mut [0; 16],
                &mut [0; 16],
                &BTreeMap::new()
            ),
            8
        );
        assert_eq!(
            restore(
                info_at(&ranges, 21),
                0,
                &mut [0; 16],
                &mut [0; 16],
                &BTreeMap::new()
            ),
            8
        );
    }

    #[test]
    fn real_frame_pointer_and_alignment_have_truthful_epilogue_states() {
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x18, 0x48, 0x83, 0xe4, 0xf0, 0x90, 0xc9,
            0xc3,
        ];
        let ranges = unwind_ranges(&code, ENTRY).unwrap();
        let stack = BTreeMap::from([(-8, 0x1234)]);
        let mut gprs = [0; 16];
        assert_eq!(
            restore(info_at(&ranges, 12), -40, &mut gprs, &mut [0; 16], &stack),
            8
        );
        assert_eq!(gprs[5], 0x1234);
        assert_eq!(
            restore(info_at(&ranges, 14), 0, &mut gprs, &mut [0; 16], &stack),
            8
        );
    }

    #[test]
    fn compatible_branch_joins_and_constant_changing_loops_are_covered() {
        let branch = [
            0x48, 0x83, 0xec, 0x20, 0x85, 0xc9, 0x74, 0x07, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb,
            0x05, 0xb8, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x20, 0xc3,
        ];
        let ranges = unwind_ranges(&branch, ENTRY).unwrap();
        for offset in [4, 6, 8, 13, 15, 20] {
            assert_eq!(
                restore(
                    info_at(&ranges, offset),
                    -32,
                    &mut [0; 16],
                    &mut [0; 16],
                    &BTreeMap::new()
                ),
                8
            );
        }
        let loop_code = [
            0x48, 0x83, 0xec, 0x20, 0xb8, 0x03, 0x00, 0x00, 0x00, 0xff, 0xc8, 0x75, 0xfc, 0x48,
            0x83, 0xc4, 0x20, 0xc3,
        ];
        let ranges = unwind_ranges(&loop_code, ENTRY).unwrap();
        assert_eq!(
            restore(
                info_at(&ranges, 9),
                -32,
                &mut [0; 16],
                &mut [0; 16],
                &BTreeMap::new()
            ),
            8
        );
    }

    #[test]
    fn large_frames_and_far_gpr_saves_restore_the_caller() {
        let code = [
            0x48, 0x81, 0xec, 0x00, 0x00, 0x10, 0x00, 0x48, 0x89, 0x9c, 0x24, 0x00, 0x00, 0x08,
            0x00, 0x48, 0x31, 0xdb, 0x48, 0x8b, 0x9c, 0x24, 0x00, 0x00, 0x08, 0x00, 0x48, 0x81,
            0xc4, 0x00, 0x00, 0x10, 0x00, 0xc3,
        ];
        let ranges = unwind_ranges(&code, ENTRY).unwrap();
        let mut gprs = [0; 16];
        assert_eq!(
            restore(
                info_at(&ranges, 18),
                -0x100000,
                &mut gprs,
                &mut [0; 16],
                &BTreeMap::from([(-0x80000, 0x1234)])
            ),
            8
        );
        assert_eq!(gprs[3], 0x1234);
    }

    #[test]
    fn terminal_tail_keeps_its_real_frame_and_unreachable_data_is_not_code() {
        let code = [0x48, 0x83, 0xec, 0x28, 0xe9, 0x00, 0x10, 0x00, 0x00, 0x0f];
        let ranges = unwind_ranges(&code, ENTRY).unwrap();
        assert_eq!(ranges.last().unwrap().end, 9);
        assert_eq!(
            restore(
                info_at(&ranges, 4),
                -40,
                &mut [0; 16],
                &mut [0; 16],
                &BTreeMap::new()
            ),
            8
        );
    }

    #[test]
    fn unprovable_frames_saves_and_returns_are_rejected() {
        for code in [
            &[0x48, 0x29, 0xcc, 0xc3][..],
            &[0x48, 0x31, 0xdb, 0xc3][..],
            &[0x48, 0x83, 0xec, 0x20, 0xc3][..],
            &[0x53, 0x48, 0x31, 0xdb, 0xc3][..],
            &[
                0x48, 0x83, 0xec, 0x20, 0xf2, 0x0f, 0x11, 0x34, 0x24, 0x0f, 0x57, 0xf6, 0xc3,
            ][..],
            &[
                0x53, 0x48, 0x31, 0xdb, 0x48, 0xc7, 0x04, 0x24, 0, 0, 0, 0, 0x5b, 0xc3,
            ][..],
            &[
                0x85, 0xc9, 0x74, 0x06, 0x48, 0x83, 0xec, 0x08, 0xeb, 0x00, 0xc3,
            ][..],
            &[0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0x1c, 0x04, 0xc3][..],
            &[0xeb, 0xff][..],
            &[0x0f][..],
        ] {
            assert!(
                unwind_ranges(code, ENTRY).is_err(),
                "accepted unprovable bytes {code:02x?}"
            );
        }
    }

    #[test]
    fn calls_invalidate_volatile_snapshots_and_overwritten_shadow_saves() {
        let lost_snapshot = [
            0x49, 0x89, 0xe2, 0x48, 0x83, 0xec, 0x28, 0xe8, 0x00, 0x10, 0x00, 0x00, 0x4c, 0x89,
            0xd4, 0xc3,
        ];
        assert!(unwind_ranges(&lost_snapshot, ENTRY).is_err());
        let lost_save = [
            0x48, 0x83, 0xec, 0x28, 0x48, 0x89, 0x1c, 0x24, 0x48, 0x31, 0xdb, 0xe8, 0x00, 0x10,
            0x00, 0x00, 0xc3,
        ];
        assert!(unwind_ranges(&lost_save, ENTRY).is_err());
    }

    #[test]
    fn mixed_xmm_alignment_uses_real_save_addresses() {
        let code = [
            0x48, 0x83, 0xec, 0x30, 0x0f, 0x11, 0x34, 0x24, 0x0f, 0x11, 0x7c, 0x24, 0x18, 0x0f,
            0x57, 0xf6, 0x0f, 0x57, 0xff, 0x0f, 0x10, 0x34, 0x24, 0x0f, 0x10, 0x7c, 0x24, 0x18,
            0x48, 0x83, 0xc4, 0x30, 0xc3,
        ];
        let ranges = unwind_ranges(&code, ENTRY).unwrap();
        let mut xmms = [0; 16];
        let stack = BTreeMap::from([(-48, 0x1234), (-24, 0x5678)]);
        assert_eq!(
            restore(info_at(&ranges, 19), -48, &mut [0; 16], &mut xmms, &stack),
            8
        );
        assert_eq!(xmms[6], 0x1234);
        assert_eq!(xmms[7], 0x5678);
    }

    #[test]
    fn far_xmm_save_restores_the_full_register() {
        let code = [
            0x48, 0x81, 0xec, 0x20, 0x00, 0x10, 0x00, 0x0f, 0x11, 0xb4, 0x24, 0x00, 0x00, 0x10,
            0x00, 0x0f, 0x57, 0xf6, 0x0f, 0x10, 0xb4, 0x24, 0x00, 0x00, 0x10, 0x00, 0x48, 0x81,
            0xc4, 0x20, 0x00, 0x10, 0x00, 0xc3,
        ];
        let ranges = unwind_ranges(&code, ENTRY).unwrap();
        let mut xmms = [0; 16];
        let original = 0x123456789abcdef00123456789abcdef;
        let stack = BTreeMap::from([(-32, original)]);
        assert_eq!(
            restore(
                info_at(&ranges, 18),
                -0x100020,
                &mut [0; 16],
                &mut xmms,
                &stack
            ),
            8
        );
        assert_eq!(xmms[6], original);
    }

    #[test]
    fn call_preserves_nonvolatile_saves_outside_outgoing_shadow_space() {
        let code = [
            0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x31, 0xdb, 0xe8, 0x00, 0x10, 0x00, 0x00, 0x48,
            0x83, 0xc4, 0x20, 0x5b, 0xc3,
        ];
        let ranges = unwind_ranges(&code, ENTRY).unwrap();
        let mut gprs = [0; 16];
        assert_eq!(
            restore(
                info_at(&ranges, 13),
                -40,
                &mut gprs,
                &mut [0; 16],
                &BTreeMap::from([(-8, 0x1234)])
            ),
            8
        );
        assert_eq!(gprs[3], 0x1234);
    }
}
