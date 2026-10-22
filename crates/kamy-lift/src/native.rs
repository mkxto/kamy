use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, OpAccess, OpKind, Register};
use kamy_core::ir::{IrOp, IrType, NativeInst, PhysReg, ValueId};

use crate::builder::IrBuilder;
use crate::state::LiftState;
use crate::{iced_reg_to_gpr, iced_reg_to_xmm};

fn expand_reg(reg: Register) -> Vec<PhysReg> {
    if let Some(gpr) = iced_reg_to_gpr(reg) {
        return vec![PhysReg::Gpr(gpr)];
    }
    if let Some(xmm) = iced_reg_to_xmm(reg) {
        return vec![PhysReg::Xmm(xmm)];
    }
    vec![]
}

fn push_unique(list: &mut Vec<PhysReg>, regs: &[PhysReg]) {
    for r in regs {
        if !list.contains(r) {
            list.push(*r);
        }
    }
}

pub(crate) fn native_inline_fallback(
    insn: &Instruction,
    insn_bytes: &[u8],
    builder: &mut IrBuilder,
    state: &mut LiftState,
) {
    if insn.rflags_modified() != 0 {
        // NativeInline has no SSA flag outputs. Retaining the old values would
        // make later SETcc/Jcc consumers observe an earlier instruction's flags.
        state.unsupported = true;
        return;
    }
    let mut references = Vec::new();
    if insn.is_ip_rel_memory_operand() {
        let operand = (0..insn.op_count()).find(|&op| insn.op_kind(op) == OpKind::Memory);
        let reference = operand.and_then(|op| {
            let reference = state.address_reference(
                op,
                insn.ip_rel_memory_address(),
                kamy_core::LinkField::Relative32 { bias: 0 },
            )?;
            let offset = state
                .instruction
                .get()
                .checked_sub(state.source_start.get())?
                .checked_add(u32::from(state.operand_offsets[op as usize]))?;
            (insn.memory_base() == Register::RIP
                && insn.flow_control() == FlowControl::Next
                && reference.source == state.source
                && reference.offset == offset
                && matches!(reference.field, kamy_core::LinkField::Relative32 { .. }))
            .then_some(kamy_core::OperandReference {
                instruction: state.instruction,
                operand: op,
                reference,
            })
        });
        match reference {
            Some(reference) => references.push(reference),
            None => state.unsupported = true,
        }
    }
    if state.references.iter().any(|reference| {
        reference.instruction == state.instruction && !references.contains(reference)
    }) {
        state.unsupported = true;
    }
    if insn.rflags_read() != 0 {
        // The raw bytes consume an incoming rflags bit (adc/sbb/adcx/adox/rcl/…),
        // a dependency SSA does not thread for a NativeInline: the flag-producing
        // instruction is then DCE'd and the flag the bytes read is garbage
        // (issue #23: bmi1_tzcnt's `cmp rcx,1; adc rcx,0` guard was dropped, so
        // `tzcnt` saw 73 and returned 0). Preserve residency rather than losing
        // the incoming flag dependency (D22).
        state.unsupported = true;
    }
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(insn);

    let mut reads: Vec<PhysReg> = Vec::new();
    let mut writes: Vec<PhysReg> = Vec::new();

    for used in info.used_registers() {
        let expanded = expand_reg(used.register());
        if expanded.is_empty() {
            continue;
        }
        match used.access() {
            OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                push_unique(&mut reads, &expanded);
            }
            _ => {}
        }
        match used.access() {
            OpAccess::Write
            | OpAccess::CondWrite
            | OpAccess::ReadWrite
            | OpAccess::ReadCondWrite => {
                push_unique(&mut writes, &expanded);
            }
            _ => {}
        }
    }

    // Constrain the native read, not the incoming definition's entire lifetime.
    let mut read_vals: Vec<ValueId> = Vec::with_capacity(reads.len());
    for r in &reads {
        let v = match r {
            PhysReg::Gpr(g) => state.get_gpr(*g),
            PhysReg::Xmm(x) => state.get_xmm(*x),
            PhysReg::Flag(f) => state.get_flag(*f),
        };
        match state.reg_pins.get(&v).copied() {
            Some(p) if p == *r => read_vals.push(v),
            _ => {
                let ty = match r {
                    PhysReg::Xmm(_) => IrType::I128,
                    _ => IrType::I64,
                };
                let copy = builder.emit(IrOp::Copy, &[v], ty);
                state.reg_pins.insert(copy, *r);
                read_vals.push(copy);
            }
        }
    }

    let native = NativeInst {
        bytes: insn_bytes.to_vec(),
        references,
        reads,
        writes: writes.clone(),
    };

    tracing::trace!(mnemonic = ?insn.mnemonic(), "native passthrough");
    builder.emit(IrOp::NativeInline(native), &read_vals, IrType::I64);

    // The raw bytes write fixed physical registers. Each write value is a fresh
    // single-def Undef pinned to its write register, so a later op reading that
    // register reads it where the native actually wrote it. (The native point
    // itself is reserved against clobber in regalloc, independent of this pin,
    // since a write never read again is dead and gets DCE'd before regalloc.)
    for phys in &writes {
        match phys {
            PhysReg::Gpr(g) => {
                let v = builder.emit(IrOp::Undef, &[], IrType::I64);
                state.reg_pins.insert(v, *phys);
                state.set_gpr(*g, v);
            }
            PhysReg::Xmm(x) => {
                let v = builder.emit(IrOp::Undef, &[], IrType::I128);
                state.reg_pins.insert(v, *phys);
                state.set_xmm(*x, v);
            }
            PhysReg::Flag(f) => {
                let v = builder.emit(IrOp::Undef, &[], IrType::I8);
                state.reg_pins.insert(v, *phys);
                state.set_flag(*f, v);
            }
        }
    }
}
