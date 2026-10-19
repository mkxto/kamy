use iced_x86::{Instruction, InstructionInfoFactory, OpAccess, Register};
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
    if insn.is_ip_rel_memory_operand() {
        // A RIP-relative operand on an unmodeled instruction would be re-emitted
        // with its original displacement and resolve to the wrong VA once moved.
        tracing::warn!(
            ip = %insn.ip(),
            mnemonic = ?insn.mnemonic(),
            "rip-relative operand on unmodeled instruction; lifting unsupported"
        );
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

    let read_vals: Vec<ValueId> = reads
        .iter()
        .map(|r| match r {
            PhysReg::Gpr(g) => state.get_gpr(*g),
            PhysReg::Xmm(x) => state.get_xmm(*x),
            PhysReg::Flag(f) => state.get_flag(*f),
        })
        .collect();

    let native = NativeInst {
        bytes: insn_bytes.to_vec(),
        reads,
        writes: writes.clone(),
    };

    tracing::trace!(mnemonic = ?insn.mnemonic(), "native passthrough");
    builder.emit(IrOp::NativeInline(native), &read_vals, IrType::I64);

    for phys in &writes {
        match phys {
            PhysReg::Gpr(g) => {
                let v = builder.emit(IrOp::Undef, &[], IrType::I64);
                state.set_gpr(*g, v);
            }
            PhysReg::Xmm(x) => {
                let v = builder.emit(IrOp::Undef, &[], IrType::I128);
                state.set_xmm(*x, v);
            }
            PhysReg::Flag(f) => {
                let v = builder.emit(IrOp::Undef, &[], IrType::I8);
                state.set_flag(*f, v);
            }
        }
    }
}
