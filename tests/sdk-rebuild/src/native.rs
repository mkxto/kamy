use anyhow::{Context, Result, bail, ensure};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use std::collections::BTreeMap;

const NONVOLATILE: [usize; 8] = [3, 5, 6, 7, 12, 13, 14, 15];
const RETURN_PC: u64 = 0x1234_5678_9abc_def0;
const STACK_MIN: i64 = -8184;
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
            if register.is_gpr64() {
                self.registers[index]
            } else {
                Value::Unknown
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
    let index = machine.read_register(instruction.memory_index());
    ensure!(
        !matches!(index, Value::Stack(_)),
        "independent unwind oracle cannot simulate indexed stack addresses"
    );
    if let Value::Stack(offset) = base {
        ensure!(
            instruction.memory_index() == Register::None,
            "independent unwind oracle cannot simulate indexed stack addresses"
        );
        return Ok(Some(
            offset
                .checked_add(instruction.memory_displacement64() as i64)
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
        ensure!(
            instruction.op1_kind() == OpKind::Register,
            "independent unwind oracle cannot simulate this prologue save"
        );
        let size = instruction.memory_size().size();
        let register = instruction.op1_register();
        ensure!(
            (size == 8 && register.is_gpr64()) || (size == 16 && vector(register).is_some()),
            "independent unwind oracle cannot simulate partial/oversized prologue save"
        );
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
pub struct Prologue {
    pub pc: u32,
    machine: Machine,
}

pub fn decode_prologue(code: &[u8], begin: u32) -> Result<Prologue> {
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
            machine,
        });
    }
    bail!("logical function has no instruction after its decoded prologue")
}

#[cfg(windows)]
mod windows_oracle {
    use super::*;
    use windows::Win32::System::Diagnostics::Debug::{
        CONTEXT, CONTEXT_ALL_AMD64, M128A, RtlLookupFunctionEntry, RtlVirtualUnwind,
    };

    #[repr(align(16))]
    struct Stack([u64; 2048]);

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

    unsafe fn unwind_one(image: *const u8, begin: u32, pc_rva: u32, end: u32) -> Result<()> {
        let code = unsafe {
            core::slice::from_raw_parts(image.add(begin as usize), (end - begin) as usize)
        };
        let prologue = decode_prologue(code, begin)?;
        ensure!(
            prologue.pc == pc_rva,
            "unwind probe is not the independently decoded post-prologue PC"
        );
        let machine = prologue.machine;
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
        let mut stack = Stack([0; 2048]);
        let initial_sp = unsafe { stack.0.as_mut_ptr().add(1023) } as u64;
        ensure!(
            initial_sp % 16 == 8,
            "synthetic Win64 entry stack is misaligned"
        );
        for (&offset, slot) in &machine.stack {
            stack_bounds(offset, slot.size)?;
            let destination = initial_sp.wrapping_add_signed(offset) as *mut u8;
            match (slot.value, slot.size) {
                (value, 8) => unsafe {
                    destination
                        .cast::<u64>()
                        .write_unaligned(concrete(value, initial_sp, 0))
                },
                (Value::Bits(value), 16) => unsafe {
                    destination.cast::<u128>().write_unaligned(value)
                },
                _ => {
                    bail!("independent unwind oracle cannot materialize stack slot at {offset:+#x}")
                }
            }
        }
        let values: [u64; 16] = std::array::from_fn(|index| {
            let poison = 0xdead_beef_0000_0000 + index as u64;
            let value = machine.registers[index];
            if machine.saved_gpr & (1 << index) != 0 && !matches!(value, Value::Stack(_)) {
                poison
            } else {
                concrete(value, initial_sp, poison)
            }
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
            let value = if machine.saved_xmm & (1 << index) != 0 {
                0xdead_0000 + index as u128
            } else {
                match machine.vectors[index] {
                    Value::Bits(value) => value,
                    _ => 0xdead_0000 + index as u128,
                }
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
        println!(
            "native_unwind function={begin:#x} rva={pc_rva:#x} frame={} saved_gpr={} saved_xmm={}",
            -machine.rsp()?,
            (machine.saved_gpr & 0xf0e8).count_ones(),
            (machine.saved_xmm & 0xffc0).count_ones()
        );
        Ok(())
    }

    pub unsafe fn check_ranges(image: *const u8, image_size: u32, ranges: &str) -> Result<()> {
        let mut generated = 0;
        let mut authored = 0;
        for range in ranges.split(',').filter(|value| !value.is_empty()) {
            let (origin, coordinates) = range
                .split_once('@')
                .context("unwind probe MUST be origin@function-start:probe-pc:function-end")?;
            match origin {
                "generated" => generated += 1,
                "authored" => authored += 1,
                _ => bail!("invalid unwind origin {origin}"),
            }
            let mut coordinates = coordinates.split(':');
            let begin: u32 = coordinates
                .next()
                .context("unwind probe lacks logical start")?
                .parse()?;
            let pc: u32 = coordinates
                .next()
                .context("unwind probe lacks exact PC")?
                .parse()?;
            let end: u32 = coordinates
                .next()
                .context("unwind probe lacks logical end")?
                .parse()?;
            ensure!(
                coordinates.next().is_none(),
                "unwind probe has extra coordinates"
            );
            ensure!(
                begin <= pc && pc < end && end <= image_size,
                "unwind probe coordinates lie outside mapped image/function"
            );
            unsafe {
                unwind_one(image, begin, pc, end)?;
            }
        }
        ensure!(
            generated > 0 && authored > 0,
            "native unwind MUST exercise generated loader and authored module code"
        );
        println!("unwind_generated={generated} unwind_authored={authored}");
        Ok(())
    }
}

#[cfg(windows)]
pub use windows_oracle::check_ranges;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_frame_uses_logical_origin_after_endbr_and_nop() {
        let code = [
            0xf3, 0x0f, 0x1e, 0xfa, 0x90, 0x48, 0x83, 0xec, 0x48, 0x85, 0xc0, 0xc3,
        ];
        let prologue = decode_prologue(&code, 0x1000).unwrap();
        assert_eq!(prologue.pc, 0x1009);
        assert_eq!(prologue.machine.rsp().unwrap(), -72);
        assert_eq!(
            prologue.machine.stack[&0].value,
            Value::Bits(RETURN_PC.into())
        );
        assert_eq!(
            decode_prologue(&code[9..], 0x1009)
                .unwrap()
                .machine
                .rsp()
                .unwrap(),
            0
        );
    }

    #[test]
    fn prologue_records_actual_gpr_xmm_and_frame_pointer_values() {
        let code = [
            0x53, 0x55, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0xec, 0x0f, 0x29, 0x34, 0x24, 0x48,
            0x31, 0xdb, 0xc3,
        ];
        let prologue = decode_prologue(&code, 0x2000).unwrap();
        assert_eq!(prologue.pc, 0x200d);
        assert_eq!(prologue.machine.rsp().unwrap(), -56);
        assert_eq!(
            prologue.machine.stack[&-8].value,
            Value::Bits(gpr_sentinel(3).into())
        );
        assert_eq!(
            prologue.machine.stack[&-16].value,
            Value::Bits(gpr_sentinel(5).into())
        );
        assert_eq!(
            prologue.machine.stack[&-56].value,
            Value::Bits(xmm_sentinel(6))
        );
        assert_eq!(prologue.machine.registers[5], Value::Stack(-56));
        assert_eq!(prologue.machine.saved_gpr, (1 << 3) | (1 << 5));
        assert_eq!(prologue.machine.saved_xmm, 1 << 6);
    }

    #[test]
    fn unsupported_prologue_construction_fails_specifically() {
        let dynamic = [0x48, 0x29, 0xc4, 0xc3];
        assert!(
            format!("{:#}", decode_prologue(&dynamic, 0).unwrap_err())
                .contains("dynamic prologue stack arithmetic")
        );
        let enter = [0xc8, 0x20, 0x00, 0x00, 0xc3];
        assert!(
            format!("{:#}", decode_prologue(&enter, 0).unwrap_err())
                .contains("cannot simulate prologue stack instruction")
        );
    }
}
