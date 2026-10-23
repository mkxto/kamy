use anyhow::{Context, Result, bail, ensure};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use std::collections::BTreeMap;

const NONVOLATILE: [usize; 8] = [3, 5, 6, 7, 12, 13, 14, 15];
const RETURN_PC: u64 = 0x1234_5678_9abc_def0;
const STACK_MIN: i64 = -16 * 1024 * 1024;
const STACK_MAX: i64 = 8200;

fn gpr_sentinel(index: usize) -> u64 {
    0x1111_0000_0000_0000 + index as u64
}

fn xmm_sentinel(index: usize) -> u128 {
    0xaabb_ccdd_0011_2233_4455_6677_8899_0000 + index as u128
}

fn gpr(register: Register) -> Option<usize> {
    Some(match register.full_register() {
        Register::RAX => 0,
        Register::RCX => 1,
        Register::RDX => 2,
        Register::RBX => 3,
        Register::RSP => 4,
        Register::RBP => 5,
        Register::RSI => 6,
        Register::RDI => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        _ => return None,
    })
}

fn vector(register: Register) -> Option<usize> {
    register
        .is_xmm()
        .then(|| register as usize - Register::XMM0 as usize)
        .filter(|index| *index < 16)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Bits(u128),
    Stack(i64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    size: usize,
    value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Machine {
    registers: [Value; 16],
    vectors: [Value; 16],
    stack: BTreeMap<i64, Slot>,
    saved_gpr: u16,
    saved_xmm: u16,
}

fn stack_bounds(offset: i64, size: usize) -> Result<()> {
    ensure!(
        offset >= STACK_MIN
            && offset
                .checked_add(size as i64)
                .is_some_and(|end| end <= STACK_MAX),
        "independent unwind oracle accesses outside synthetic stack at {offset:+#x}, width {size}"
    );
    Ok(())
}

impl Machine {
    fn entry() -> Self {
        let mut machine = Self {
            registers: [Value::Unknown; 16],
            vectors: [Value::Unknown; 16],
            stack: BTreeMap::from([(
                0,
                Slot {
                    size: 8,
                    value: Value::Bits(RETURN_PC.into()),
                },
            )]),
            saved_gpr: 0,
            saved_xmm: 0,
        };
        machine.registers[4] = Value::Stack(0);
        for index in NONVOLATILE {
            machine.registers[index] = Value::Bits(gpr_sentinel(index).into());
        }
        for index in 6..16 {
            machine.vectors[index] = Value::Bits(xmm_sentinel(index));
        }
        machine
    }

    fn rsp(&self) -> Result<i64> {
        let Value::Stack(offset) = self.registers[4] else {
            bail!("independent unwind oracle lost the entry-relative RSP");
        };
        Ok(offset)
    }

    fn read_register(&self, register: Register) -> Value {
        if let Some(index) = gpr(register) {
            match self.registers[index] {
                value if register.is_gpr64() => value,
                Value::Bits(bits) => {
                    let shift = if register.is_gpr8()
                        && register >= Register::AH
                        && register <= Register::BH
                    {
                        8
                    } else {
                        0
                    };
                    let mask = (1u128 << (register.size() * 8)) - 1;
                    Value::Bits((bits >> shift) & mask)
                }
                _ => Value::Unknown,
            }
        } else if let Some(index) = vector(register) {
            self.vectors[index]
        } else {
            Value::Unknown
        }
    }

    fn write_register(&mut self, register: Register, value: Value) -> Result<()> {
        if let Some(index) = gpr(register) {
            let value = if register.is_gpr64() {
                value
            } else if let Value::Bits(bits) = value {
                let mask = (1u128 << (register.size() * 8)) - 1;
                if register.is_gpr32() {
                    Value::Bits(bits & mask)
                } else if let Value::Bits(previous) = self.registers[index] {
                    let shift = if register >= Register::AH && register <= Register::BH {
                        8
                    } else {
                        0
                    };
                    Value::Bits((previous & !(mask << shift)) | ((bits & mask) << shift))
                } else {
                    Value::Unknown
                }
            } else {
                Value::Unknown
            };
            if index == 4 {
                let Value::Stack(offset) = value else {
                    bail!("independent unwind oracle cannot simulate dynamic/truncated RSP");
                };
                ensure!(
                    offset <= 0 && offset % 8 == 0,
                    "invalid simulated RSP {offset}"
                );
                stack_bounds(offset, 8)?;
                self.stack.retain(|address, _| *address >= offset);
            }
            self.registers[index] = value;
        } else if let Some(index) = vector(register) {
            self.vectors[index] = value;
        } else {
            bail!("independent unwind oracle cannot write register {register:?}");
        }
        Ok(())
    }

    fn store(&mut self, offset: i64, size: usize, value: Value) -> Result<()> {
        ensure!(
            size != 0,
            "independent unwind oracle has unknown store width"
        );
        stack_bounds(offset, size)?;
        ensure!(
            offset >= self.rsp()?,
            "simulated store lies below allocated stack"
        );
        ensure!(
            offset + size as i64 <= 0 || offset >= 8,
            "simulated store overwrites caller return address"
        );
        self.stack.retain(|begin, slot| {
            *begin + slot.size as i64 <= offset || *begin >= offset + size as i64
        });
        if value != Value::Unknown {
            self.stack.insert(offset, Slot { size, value });
        }
        Ok(())
    }
}

fn stack_address(machine: &Machine, instruction: &Instruction) -> Result<Option<i64>> {
    if instruction.is_ip_rel_memory_operand() {
        return Ok(None);
    }
    let base = machine.read_register(instruction.memory_base());
    if let Value::Stack(offset) = base {
        let index = match instruction.memory_index() {
            Register::None => 0,
            _ => match machine.read_register(instruction.memory_index()) {
                Value::Bits(bits) => (bits as i64)
                    .checked_mul(i64::from(instruction.memory_index_scale()))
                    .context("simulated stack index overflow")?,
                _ => return Ok(None),
            },
        };
        return Ok(Some(
            offset
                .checked_add(index)
                .and_then(|offset| offset.checked_add(instruction.memory_displacement64() as i64))
                .context("simulated stack displacement overflow")?,
        ));
    }
    ensure!(
        instruction.memory_base() != Register::RSP,
        "independent unwind oracle lost stack memory base"
    );
    Ok(None)
}

fn is_move(instruction: &Instruction) -> bool {
    matches!(
        instruction.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Movaps
            | Mnemonic::Movups
            | Mnemonic::Movapd
            | Mnemonic::Movupd
            | Mnemonic::Movdqa
            | Mnemonic::Movdqu
            | Mnemonic::Vmovaps
            | Mnemonic::Vmovups
            | Mnemonic::Vmovapd
            | Mnemonic::Vmovupd
            | Mnemonic::Vmovdqa
            | Mnemonic::Vmovdqu
    )
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn advance_prologue(machine: &mut Machine, instruction: &Instruction) -> Result<bool> {
    match instruction.mnemonic() {
        Mnemonic::Endbr64 | Mnemonic::Nop => return Ok(true),
        Mnemonic::Push | Mnemonic::Pushfq => {
            ensure!(
                instruction.stack_pointer_increment() == -8
                    && (instruction.mnemonic() == Mnemonic::Pushfq
                        || instruction.op0_kind() == OpKind::Register),
                "independent unwind oracle cannot simulate this prologue PUSH"
            );
            let register = instruction.op0_register();
            let value = if instruction.mnemonic() == Mnemonic::Pushfq {
                Value::Bits(0x202)
            } else {
                machine.read_register(register)
            };
            let offset = machine
                .rsp()?
                .checked_sub(8)
                .context("prologue PUSH overflow")?;
            machine.write_register(Register::RSP, Value::Stack(offset))?;
            machine.store(offset, 8, value)?;
            if let Some(index) = gpr(register)
                && NONVOLATILE.contains(&index)
            {
                machine.saved_gpr |= 1 << index;
            }
            return Ok(true);
        }
        Mnemonic::Sub | Mnemonic::And if instruction.op0_register() == Register::RSP => {
            ensure!(
                matches!(
                    instruction.op1_kind(),
                    OpKind::Immediate8to64 | OpKind::Immediate32to64
                ),
                "independent unwind oracle cannot simulate dynamic prologue stack arithmetic"
            );
            let offset = machine.rsp()?;
            let immediate = instruction.immediate(1) as i64;
            let offset = if instruction.mnemonic() == Mnemonic::Sub {
                ensure!(immediate >= 0, "negative prologue stack allocation");
                offset
                    .checked_sub(immediate)
                    .context("prologue allocation overflow")?
            } else {
                let alignment = (!immediate as u64).wrapping_add(1);
                ensure!(
                    alignment.is_power_of_two() && alignment <= 16,
                    "independent unwind oracle cannot prove this prologue alignment"
                );
                offset - (offset + 8).rem_euclid(alignment as i64)
            };
            machine.write_register(Register::RSP, Value::Stack(offset))?;
            return Ok(true);
        }
        Mnemonic::Mov
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && matches!(
                    machine.read_register(instruction.op1_register()),
                    Value::Stack(_)
                ) =>
        {
            machine.write_register(
                instruction.op0_register(),
                machine.read_register(instruction.op1_register()),
            )?;
            return Ok(true);
        }
        Mnemonic::Lea if instruction.op0_register().is_gpr64() => {
            if let Some(offset) = stack_address(machine, instruction)? {
                machine.write_register(instruction.op0_register(), Value::Stack(offset))?;
                return Ok(true);
            }
        }
        _ => {}
    }
    if is_move(instruction)
        && instruction.op0_kind() == OpKind::Memory
        && let Some(offset) = stack_address(machine, instruction)?
    {
        let size = instruction.memory_size().size();
        let register = instruction.op1_register();
        if instruction.op1_kind() != OpKind::Register
            || !((size == 8 && register.is_gpr64()) || (size == 16 && vector(register).is_some()))
        {
            return Ok(false);
        }
        if matches!(
            instruction.mnemonic(),
            Mnemonic::Movaps
                | Mnemonic::Movapd
                | Mnemonic::Movdqa
                | Mnemonic::Vmovaps
                | Mnemonic::Vmovapd
                | Mnemonic::Vmovdqa
        ) {
            ensure!(
                (offset + 8).rem_euclid(16) == 0,
                "misaligned prologue vector save"
            );
        }
        machine.store(offset, size, machine.read_register(register))?;
        if let Some(index) = gpr(register)
            && NONVOLATILE.contains(&index)
        {
            machine.saved_gpr |= 1 << index;
        }
        if let Some(index) = vector(register)
            && index >= 6
        {
            machine.saved_xmm |= 1 << index;
        }
        return Ok(true);
    }
    Ok(false)
}

#[derive(Debug)]
pub(crate) struct Prologue {
    pub(crate) pc: u32,
}

pub(crate) fn decode_prologue(code: &[u8], begin: u32) -> Result<Prologue> {
    let mut machine = Machine::entry();
    let mut decoder = Decoder::with_ip(64, code, u64::from(begin), DecoderOptions::NONE);
    let mut factory = InstructionInfoFactory::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        ensure!(
            !instruction.is_invalid(),
            "invalid prologue instruction at {:#x}",
            instruction.ip()
        );
        if advance_prologue(&mut machine, &instruction).with_context(|| {
            format!("independent prologue simulation at {:#x}", instruction.ip())
        })? {
            continue;
        }
        if instruction.flow_control() == FlowControl::Next {
            ensure!(
                !factory
                    .info(&instruction)
                    .used_registers()
                    .iter()
                    .any(|used| gpr(used.register()) == Some(4) && writes(used.access())),
                "independent unwind oracle cannot simulate prologue stack instruction {:?} at {:#x}",
                instruction.mnemonic(),
                instruction.ip()
            );
        }
        return Ok(Prologue {
            pc: u32::try_from(instruction.ip())?,
        });
    }
    bail!("logical function has no instruction after its decoded prologue")
}

#[derive(Debug)]
struct Snapshot {
    pc: u32,
    machine: Machine,
    epilogue: bool,
}

fn operand(machine: &Machine, instruction: &Instruction, index: u32) -> Result<Value> {
    Ok(match instruction.op_kind(index) {
        OpKind::Register => machine.read_register(instruction.op_register(index)),
        OpKind::Memory => {
            if let Some(offset) = stack_address(machine, instruction)? {
                let size = instruction.memory_size().size();
                stack_bounds(offset, size)?;
                machine
                    .stack
                    .get(&offset)
                    .filter(|slot| slot.size == size)
                    .map_or(Value::Unknown, |slot| slot.value)
            } else {
                Value::Unknown
            }
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Value::Bits(instruction.immediate(index).into()),
        _ => Value::Unknown,
    })
}

fn advance_body(
    machine: &mut Machine,
    instruction: &Instruction,
    factory: &mut InstructionInfoFactory,
) -> Result<()> {
    if instruction.mnemonic() == Mnemonic::Pop || instruction.mnemonic() == Mnemonic::Popfq {
        ensure!(
            instruction.stack_pointer_increment() == 8,
            "unsupported POP width"
        );
        let offset = machine.rsp()?;
        let value = machine
            .stack
            .get(&offset)
            .filter(|slot| slot.size == 8)
            .map_or(Value::Unknown, |slot| slot.value);
        machine.write_register(Register::RSP, Value::Stack(offset + 8))?;
        if instruction.mnemonic() == Mnemonic::Pop {
            ensure!(
                instruction.op0_kind() == OpKind::Register,
                "unsupported POP destination"
            );
            machine.write_register(instruction.op0_register(), value)?;
        }
        return Ok(());
    }
    if instruction.mnemonic() == Mnemonic::Leave {
        machine.write_register(Register::RSP, machine.read_register(Register::RBP))?;
        let offset = machine.rsp()?;
        let value = machine
            .stack
            .get(&offset)
            .filter(|slot| slot.size == 8)
            .map_or(Value::Unknown, |slot| slot.value);
        machine.write_register(Register::RSP, Value::Stack(offset + 8))?;
        machine.write_register(Register::RBP, value)?;
        return Ok(());
    }
    if instruction.mnemonic() == Mnemonic::Add && instruction.op0_register() == Register::RSP {
        let Value::Bits(value) = operand(machine, instruction, 1)? else {
            bail!("independent unwind oracle cannot prove body stack deallocation");
        };
        let offset = machine
            .rsp()?
            .checked_add(i64::try_from(value)?)
            .context("body stack deallocation overflow")?;
        machine.write_register(Register::RSP, Value::Stack(offset))?;
        return Ok(());
    }
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Pxor
    ) && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Register
        && vector(instruction.op0_register()).is_some()
        && instruction.op0_register() == instruction.op1_register()
    {
        machine.write_register(instruction.op0_register(), Value::Bits(0))?;
        return Ok(());
    }
    if instruction.mnemonic() == Mnemonic::Movss {
        let source = operand(machine, instruction, 1)?;
        if instruction.op0_kind() == OpKind::Register {
            let value = match (machine.read_register(instruction.op0_register()), source) {
                (Value::Bits(previous), Value::Bits(bits))
                    if instruction.op1_kind() == OpKind::Register =>
                {
                    Value::Bits((previous & !u128::from(u32::MAX)) | (bits & u128::from(u32::MAX)))
                }
                (_, Value::Bits(bits)) if instruction.op1_kind() == OpKind::Memory => {
                    Value::Bits(bits & u128::from(u32::MAX))
                }
                _ => Value::Unknown,
            };
            machine.write_register(instruction.op0_register(), value)?;
        } else if let Some(offset) = stack_address(machine, instruction)? {
            let value = match source {
                Value::Bits(bits) => Value::Bits(bits & u128::from(u32::MAX)),
                _ => Value::Unknown,
            };
            machine.store(offset, 4, value)?;
        }
        return Ok(());
    }
    if is_move(instruction) {
        let value = operand(machine, instruction, 1)?;
        if instruction.op0_kind() == OpKind::Register {
            machine.write_register(instruction.op0_register(), value)?;
        } else if let Some(offset) = stack_address(machine, instruction)? {
            machine.store(offset, instruction.memory_size().size(), value)?;
            let register = instruction.op1_register();
            if let Some(index) = gpr(register)
                && NONVOLATILE.contains(&index)
                && value == Value::Bits(gpr_sentinel(index).into())
            {
                machine.saved_gpr |= 1 << index;
            }
            if let Some(index) = vector(register)
                && index >= 6
                && value == Value::Bits(xmm_sentinel(index))
            {
                machine.saved_xmm |= 1 << index;
            }
        }
        return Ok(());
    }
    if advance_prologue(machine, instruction)? {
        return Ok(());
    }
    if instruction.flow_control() == FlowControl::Call
        || instruction.flow_control() == FlowControl::IndirectCall
    {
        for index in [0, 1, 2, 8, 9, 10, 11] {
            machine.registers[index] = Value::Unknown;
        }
        machine.vectors[..6].fill(Value::Unknown);
        return Ok(());
    }
    let info = factory.info(instruction);
    if info
        .used_memory()
        .iter()
        .any(|memory| writes(memory.access()))
        && let Some(offset) = stack_address(machine, instruction)?
    {
        machine.store(offset, instruction.memory_size().size(), Value::Unknown)?;
    }
    for used in info
        .used_registers()
        .iter()
        .filter(|used| writes(used.access()))
    {
        if gpr(used.register()).is_some() || vector(used.register()).is_some() {
            machine.write_register(used.register(), Value::Unknown)?;
        }
    }
    Ok(())
}

fn machine_snapshots(code: &[u8], begin: u32) -> Result<Vec<Snapshot>> {
    let end = begin
        .checked_add(u32::try_from(code.len())?)
        .context("oracle code extent overflow")?;
    let mut instructions = BTreeMap::new();
    let mut decoder = Decoder::with_ip(64, code, u64::from(begin), DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        ensure!(
            !instruction.is_invalid(),
            "invalid machine instruction in unwind oracle"
        );
        instructions.insert(u32::try_from(instruction.ip())?, instruction);
    }
    let mut pending = vec![(begin, Machine::entry())];
    let mut states: BTreeMap<u32, Machine> = BTreeMap::new();
    let mut factory = InstructionInfoFactory::new();
    let mut snapshots = BTreeMap::new();
    while let Some((mut pc, mut machine)) = pending.pop() {
        loop {
            ensure!(
                states.len() <= 1_000_000,
                "independent unwind oracle instruction limit exceeded"
            );
            if let Some(previous) = states.get(&pc) {
                let mut merged = previous.clone();
                for (index, (old, current)) in merged
                    .registers
                    .iter_mut()
                    .zip(machine.registers)
                    .enumerate()
                {
                    if *old != current {
                        ensure!(
                            index != 4,
                            "independent unwind oracle has conflicting RSP at {pc:#x}"
                        );
                        *old = Value::Unknown;
                    }
                }
                for (old, current) in merged.vectors.iter_mut().zip(machine.vectors) {
                    if *old != current {
                        *old = Value::Unknown;
                    }
                }
                merged
                    .stack
                    .retain(|offset, slot| machine.stack.get(offset) == Some(slot));
                merged.saved_gpr |= machine.saved_gpr;
                merged.saved_xmm |= machine.saved_xmm;
                if &merged == previous {
                    break;
                }
                machine = merged;
            }
            states.insert(pc, machine.clone());
            let instruction = instructions
                .get(&pc)
                .context("unwind oracle branch is not an instruction boundary")?;
            let next = u32::try_from(instruction.next_ip())?;
            let epilogue = matches!(
                instruction.mnemonic(),
                Mnemonic::Pop | Mnemonic::Leave | Mnemonic::Ret
            ) || (instruction.mnemonic() == Mnemonic::Add
                && instruction.op0_register() == Register::RSP)
                || (is_move(instruction)
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Memory
                    && (instruction.op0_register().is_xmm()
                        || gpr(instruction.op0_register())
                            .is_some_and(|index| NONVOLATILE.contains(&index))));
            snapshots.insert(
                pc,
                Snapshot {
                    pc,
                    machine: machine.clone(),
                    epilogue,
                },
            );
            match instruction.flow_control() {
                FlowControl::Return | FlowControl::Exception | FlowControl::Interrupt => break,
                FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                    ensure!(
                        instruction.op0_kind() == OpKind::NearBranch64,
                        "unknown direct branch operand"
                    );
                    let target = u32::try_from(instruction.near_branch64())?;
                    if target >= begin && target < end {
                        pending.push((target, machine.clone()));
                    }
                    if instruction.flow_control() == FlowControl::UnconditionalBranch {
                        break;
                    }
                }
                FlowControl::IndirectBranch => break,
                _ => advance_body(&mut machine, instruction, &mut factory)
                    .with_context(|| format!("independent body simulation at {pc:#x}"))?,
            }
            if next >= end {
                break;
            }
            pc = next;
        }
    }
    Ok(snapshots.into_values().collect())
}

#[cfg(windows)]
pub(crate) mod windows_oracle {
    use super::*;
    use windows::Win32::System::Diagnostics::Debug::{
        CONTEXT, CONTEXT_ALL_AMD64, M128A, RtlLookupFunctionEntry, RtlVirtualUnwind,
    };

    fn concrete(value: Value, initial_sp: u64, poison: u64) -> u64 {
        match value {
            Value::Unknown => poison,
            Value::Bits(bits) => bits as u64,
            Value::Stack(offset) => initial_sp.wrapping_add_signed(offset),
        }
    }

    fn xmm(context: &CONTEXT, index: usize) -> u128 {
        let value = unsafe { context.Anonymous.FltSave.XmmRegisters[index] };
        u128::from(value.Low) | ((value.High as u128) << 64)
    }

    fn set_xmm(context: &mut CONTEXT, index: usize, value: u128) {
        unsafe {
            context.Anonymous.FltSave.XmmRegisters[index] = M128A {
                Low: value as u64,
                High: (value >> 64) as i64,
            };
        }
    }

    unsafe fn unwind_one(
        image: *const u8,
        begin: u32,
        snapshot: &Snapshot,
        stack: &mut Vec<u128>,
    ) -> Result<()> {
        let pc_rva = snapshot.pc;
        let machine = &snapshot.machine;
        let pc = image as u64 + u64::from(pc_rva);
        let mut image_base = 0;
        let entry = unsafe { RtlLookupFunctionEntry(pc, &mut image_base, None) };
        ensure!(
            !entry.is_null(),
            "native lookup has no runtime record at RVA {pc_rva:#x}"
        );
        ensure!(
            image_base == image as u64,
            "native lookup returned wrong image base"
        );
        let runtime = unsafe { &*entry };
        ensure!(
            runtime.BeginAddress <= pc_rva && pc_rva < runtime.EndAddress,
            "native lookup returned runtime record excluding exact probe PC"
        );
        let lowest = machine
            .stack
            .keys()
            .copied()
            .min()
            .unwrap_or(0)
            .min(machine.rsp()?);
        let below = usize::try_from(-lowest)?
            .checked_add(31)
            .context("synthetic stack size overflow")?
            / 16;
        stack.resize(below + (STACK_MAX as usize / 16) + 2, 0);
        stack.fill(0);
        let initial_sp = unsafe { stack.as_mut_ptr().add(below).cast::<u8>().add(8) } as u64;
        ensure!(
            initial_sp % 16 == 8,
            "synthetic Win64 entry stack is misaligned"
        );
        for (&offset, slot) in &machine.stack {
            stack_bounds(offset, slot.size)?;
            let destination = initial_sp.wrapping_add_signed(offset) as *mut u8;
            let value = match slot.value {
                Value::Bits(bits) => bits,
                value => u128::from(concrete(value, initial_sp, 0)),
            };
            ensure!(
                matches!(slot.size, 1 | 2 | 4 | 8 | 16),
                "unsupported synthetic stack width"
            );
            unsafe {
                core::ptr::copy_nonoverlapping(
                    value.to_le_bytes().as_ptr(),
                    destination,
                    slot.size,
                );
            }
        }
        let values: [u64; 16] = std::array::from_fn(|index| {
            let poison = 0xdead_beef_0000_0000 + index as u64;
            let value = machine.registers[index];
            concrete(value, initial_sp, poison)
        });
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_ALL_AMD64,
            Rax: values[0],
            Rcx: values[1],
            Rdx: values[2],
            Rbx: values[3],
            Rsp: values[4],
            Rbp: values[5],
            Rsi: values[6],
            Rdi: values[7],
            R8: values[8],
            R9: values[9],
            R10: values[10],
            R11: values[11],
            R12: values[12],
            R13: values[13],
            R14: values[14],
            R15: values[15],
            Rip: pc,
            EFlags: 0x202,
            ..Default::default()
        };
        for index in 0..16 {
            let value = match machine.vectors[index] {
                Value::Bits(value) => value,
                _ => 0xdead_0000 + index as u128,
            };
            set_xmm(&mut context, index, value);
        }
        let mut handler_data = core::ptr::null_mut();
        let mut establisher_frame = 0;
        unsafe {
            RtlVirtualUnwind(
                Default::default(),
                image_base,
                pc,
                entry,
                &mut context,
                &mut handler_data,
                &mut establisher_frame,
                None,
            );
        }
        ensure!(
            context.Rip == RETURN_PC && context.Rsp == initial_sp + 8,
            "native unwind disagrees with independently simulated function {begin:#x} at {pc_rva:#x}: rip={:#x}, rsp delta={}",
            context.Rip,
            context.Rsp.wrapping_sub(initial_sp)
        );
        let restored = [
            context.Rax,
            context.Rcx,
            context.Rdx,
            context.Rbx,
            context.Rsp,
            context.Rbp,
            context.Rsi,
            context.Rdi,
            context.R8,
            context.R9,
            context.R10,
            context.R11,
            context.R12,
            context.R13,
            context.R14,
            context.R15,
        ];
        for index in NONVOLATILE {
            ensure!(
                restored[index] == gpr_sentinel(index),
                "native unwind did not restore GPR {index} at RVA {pc_rva:#x}"
            );
        }
        for index in 6..16 {
            ensure!(
                xmm(&context, index) == xmm_sentinel(index),
                "native unwind did not restore XMM{index} at RVA {pc_rva:#x}"
            );
        }
        Ok(())
    }

    pub(crate) struct Report {
        pub(crate) anchor: u32,
        pub(crate) pcs: usize,
        pub(crate) body_pcs: usize,
        pub(crate) epilogues: usize,
        pub(crate) calls: usize,
        pub(crate) max_frame: i64,
        pub(crate) saved_gpr: u16,
        pub(crate) saved_xmm: u16,
    }

    /// Check every independently simulated instruction boundary against the
    /// operating system's registered metadata, not an allocation/frame model.
    /// The caller owns the mapped code and its live native runtime registration.
    pub(crate) unsafe fn check_function(image: *const u8, begin: u32, end: u32) -> Result<Report> {
        ensure!(begin < end, "native unwind function range is empty");
        let code = unsafe {
            core::slice::from_raw_parts(image.add(begin as usize), (end - begin) as usize)
        };
        let anchor = decode_prologue(code, begin)?.pc;
        let snapshots = machine_snapshots(code, begin)?;
        ensure!(
            snapshots.iter().any(|snapshot| snapshot.pc == anchor),
            "unwind anchor was not reached"
        );
        let mut report = Report {
            anchor,
            pcs: snapshots.len(),
            body_pcs: 0,
            epilogues: 0,
            calls: 0,
            max_frame: 0,
            saved_gpr: 0,
            saved_xmm: 0,
        };
        let mut stack = Vec::new();
        for snapshot in &snapshots {
            unsafe {
                unwind_one(image, begin, snapshot, &mut stack)?;
            }
            let offset = (snapshot.pc - begin) as usize;
            let instruction = Decoder::with_ip(
                64,
                &code[offset..],
                u64::from(snapshot.pc),
                DecoderOptions::NONE,
            )
            .decode();
            report.calls += usize::from(matches!(
                instruction.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            ));
            report.body_pcs += usize::from(snapshot.pc >= anchor && !snapshot.epilogue);
            report.epilogues += usize::from(snapshot.epilogue);
            report.max_frame = report.max_frame.max(-snapshot.machine.rsp()?);
            report.saved_gpr |= snapshot.machine.saved_gpr;
            report.saved_xmm |= snapshot.machine.saved_xmm;
        }
        Ok(report)
    }
}
