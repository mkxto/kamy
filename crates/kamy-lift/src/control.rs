use iced_x86::{Instruction, OpKind};
use kamy_core::ir::{CallingConvLookup, Gpr, IrOp, IrType, PhysReg, ValueId};

use crate::builder::IrBuilder;
use crate::cond::decode_condition;
use crate::state::LiftState;
use crate::{compute_mem_addr, iced_reg_to_gpr, iced_reg_to_xmm, read_operand, write_operand};

pub(crate) fn lift_push(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let val = match insn.op_kind(0) {
        OpKind::Register => {
            let reg = insn.op_register(0);
            if let Some(gpr) = iced_reg_to_gpr(reg) {
                s.get_gpr(gpr)
            } else {
                b.emit(IrOp::Undef, &[], IrType::I64)
            }
        }
        OpKind::Memory => {
            let addr = compute_mem_addr(insn, b, s);
            b.emit(IrOp::Load, &[addr], IrType::I64)
        }
        _ => match s.operand_reference(0) {
            Some(reference) => b.emit(IrOp::Address(reference), &[], IrType::I64),
            None => b.emit(IrOp::Const(crate::get_immediate(insn, 0)), &[], IrType::I64),
        },
    };

    let rsp = s.get_gpr(Gpr::Rsp);
    let eight = b.emit(IrOp::Const(8), &[], IrType::I64);
    let new_rsp = b.emit(IrOp::Sub, &[rsp, eight], IrType::I64);
    s.set_gpr(Gpr::Rsp, new_rsp);
    b.emit_void(IrOp::Store, &[new_rsp, val], IrType::I64);
}

pub(crate) fn lift_pop(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let rsp = s.get_gpr(Gpr::Rsp);
    let val = b.emit(IrOp::Load, &[rsp], IrType::I64);
    let eight = b.emit(IrOp::Const(8), &[], IrType::I64);
    let new_rsp = b.emit(IrOp::Add, &[rsp, eight], IrType::I64);
    s.set_gpr(Gpr::Rsp, new_rsp);
    write_operand(insn, 0, val, IrType::I64, b, s);
}

fn pin_argument(phys: PhysReg, b: &mut IrBuilder, s: &mut LiftState) -> ValueId {
    let value = match phys {
        PhysReg::Gpr(g) => s.get_gpr(g),
        PhysReg::Xmm(x) => s.get_xmm(x),
        PhysReg::Flag(f) => s.get_flag(f),
    };
    if s.reg_pins.get(&value) == Some(&phys) {
        return value;
    }
    let value = b.emit(IrOp::Copy, &[value], register_type(phys));
    s.reg_pins.insert(value, phys);
    value
}

fn register_type(phys: PhysReg) -> IrType {
    match phys {
        PhysReg::Gpr(_) => IrType::I64,
        PhysReg::Xmm(_) => IrType::I128,
        PhysReg::Flag(_) => IrType::I8,
    }
}

fn call_arguments(
    sig: &kamy_core::ir::FnSignature,
    b: &mut IrBuilder,
    s: &mut LiftState,
) -> Vec<ValueId> {
    let mut args = Vec::with_capacity(sig.args.len() + 1);
    for arg in &sig.args {
        match arg.location {
            kamy_core::ir::AbiLocation::Register(phys) => args.push(pin_argument(phys, b, s)),
            kamy_core::ir::AbiLocation::Stack { offset } => {
                let width = match arg.passing {
                    kamy_core::ir::AbiPassing::Direct => u32::from(arg.bits).div_ceil(8).max(8),
                    kamy_core::ir::AbiPassing::Indirect { .. }
                    | kamy_core::ir::AbiPassing::Sret { .. } => 8,
                };
                let endpoint = i64::from(offset)
                    .checked_sub(8)
                    .and_then(|offset| offset.checked_add(i64::from(width) - 1))
                    .expect("i32 ABI offset and u16 width fit i64");
                let displacement = b.emit(IrOp::Const(endpoint as u64), &[], IrType::I64);
                let address = b.emit(IrOp::Add, &[s.get_gpr(Gpr::Rsp), displacement], IrType::I64);
                args.push(address);
            }
        }
    }
    args.push(s.get_gpr(Gpr::Rsp));
    args
}

fn set_register(phys: PhysReg, value: ValueId, s: &mut LiftState) {
    match phys {
        PhysReg::Gpr(g) => s.set_gpr(g, value),
        PhysReg::Xmm(x) => s.set_xmm(x, value),
        PhysReg::Flag(f) => s.set_flag(f, value),
    }
}

fn call_results(sig: &kamy_core::ir::FnSignature, b: &mut IrBuilder, s: &mut LiftState) {
    if sig.noreturn {
        s.noreturn = true;
        return;
    }
    for &phys in &sig.clobbers {
        if sig
            .returns
            .iter()
            .any(|result| result.register_location() == Some(phys))
        {
            continue;
        }
        let value = b.emit(IrOp::Undef, &[], register_type(phys));
        set_register(phys, value, s);
    }
    for result in &sig.returns {
        let Some(phys) = result.register_location() else {
            s.unsupported = true;
            continue;
        };
        let value = b.emit(
            IrOp::CallResult { register: phys },
            &[],
            register_type(phys),
        );
        set_register(phys, value, s);
        s.reg_pins.insert(value, phys);
    }
}

fn call_signature(
    target: u64,
    reference: Option<&kamy_core::Reference>,
    cc: &dyn CallingConvLookup,
    s: &mut LiftState,
) -> Option<kamy_core::ir::FnSignature> {
    let sig = if s.authored() {
        reference.and_then(|reference| match &reference.expression {
            kamy_core::SymbolicExpression::Symbol { symbol, addend: 0 } => cc.lookup_symbol(symbol),
            _ => None,
        })
    } else {
        cc.lookup(target)
    };
    if sig.is_none() {
        s.unsupported = true;
    }
    sig
}

pub(crate) fn lift_call(
    _insn: &Instruction,
    target: u64,
    b: &mut IrBuilder,
    s: &mut LiftState,
    cc: &dyn CallingConvLookup,
) {
    let Some(reference) =
        s.address_reference(0, target, kamy_core::LinkField::Relative32 { bias: 0 })
    else {
        s.unsupported = true;
        return;
    };
    if let kamy_core::SymbolicExpression::Symbol { symbol, addend: 0 } = &reference.expression {
        if s.symbols
            .iter()
            .any(|candidate| candidate.id == *symbol && candidate.name == "__chkstk")
        {
            b.emit_void(
                IrOp::StackProbe,
                &[s.get_gpr(Gpr::Rax), s.get_gpr(Gpr::Rsp)],
                IrType::I64,
            );
            for register in [Gpr::R10, Gpr::R11] {
                let value = b.emit(IrOp::Undef, &[], IrType::I64);
                s.set_gpr(register, value);
            }
            for flag in kamy_core::ir::X86Flag::ALL {
                let value = b.emit(IrOp::Undef, &[], IrType::I8);
                s.set_flag(flag, value);
            }
            return;
        }
    }
    let Some(sig) = call_signature(target, Some(&reference), cc, s) else {
        return;
    };
    let args = call_arguments(&sig, b, s);
    b.emit_void(
        IrOp::Call {
            target: reference,
            clobbers: sig.clobbers.clone(),
        },
        &args,
        IrType::I64,
    );
    call_results(&sig, b, s);
}

pub(crate) fn lift_call_indirect(
    target_val: ValueId,
    slot_va: Option<u64>,
    b: &mut IrBuilder,
    s: &mut LiftState,
    cc: &dyn CallingConvLookup,
) {
    let reference = s.operand_reference(0);
    let Some(sig) = call_signature(slot_va.unwrap_or(0), reference.as_ref(), cc, s) else {
        return;
    };
    let args = call_arguments(&sig, b, s);
    let target = b.emit(IrOp::Copy, &[target_val], IrType::I64);
    s.reg_pins.insert(target, PhysReg::Gpr(Gpr::R11));
    let mut call_args = Vec::with_capacity(args.len() + 1);
    call_args.push(target);
    call_args.extend(args);
    b.emit_void(
        IrOp::CallIndirect {
            clobbers: sig.clobbers.clone(),
        },
        &call_args,
        IrType::I64,
    );
    call_results(&sig, b, s);
}

fn pin_live_out(phys: PhysReg, b: &mut IrBuilder, s: &mut LiftState) {
    let input = match phys {
        PhysReg::Gpr(g) => s.get_gpr(g),
        PhysReg::Xmm(x) => s.get_xmm(x),
        PhysReg::Flag(f) => s.get_flag(f),
    };
    let value = b.emit(IrOp::Copy, &[input], register_type(phys));
    s.reg_pins.insert(value, phys);
    b.emit_void(IrOp::Use, &[value], register_type(phys));
}

fn preserve_authored_registers(b: &mut IrBuilder, s: &mut LiftState, include_rax: bool) {
    if s.signature.is_none() {
        return;
    }
    for gpr in Gpr::ALL {
        if !gpr.is_volatile_win64() || (!include_rax && gpr == Gpr::Rax) {
            continue;
        }
        let phys = PhysReg::Gpr(gpr);
        if s.signature
            .is_some_and(|signature| !signature.clobbers.contains(&phys))
        {
            pin_live_out(phys, b, s);
        }
    }
    for xmm in kamy_core::ir::XmmReg::ALL.iter().take(6) {
        let phys = PhysReg::Xmm(*xmm);
        if s.signature
            .is_some_and(|signature| !signature.clobbers.contains(&phys))
        {
            pin_live_out(phys, b, s);
        }
    }
}

pub(crate) fn lift_ret(b: &mut IrBuilder, s: &mut LiftState) {
    let count = s.signature.as_ref().map_or(1, |sig| sig.returns.len());
    for index in 0..count {
        let phys = match s.signature.as_ref() {
            Some(sig) => sig.returns[index].register_location(),
            None => Some(PhysReg::Gpr(Gpr::Rax)),
        };
        let Some(phys) = phys else {
            s.unsupported = true;
            continue;
        };
        pin_live_out(phys, b, s);
    }
    if s.signature.is_none() {
        pin_live_out(PhysReg::Xmm(kamy_core::ir::XmmReg::Xmm0), b, s);
    }
    preserve_authored_registers(b, s, true);
    b.emit_void(IrOp::Use, &[s.get_gpr(Gpr::Rsp)], IrType::I64);
}

pub(crate) fn lift_tail_call(
    target: u64,
    b: &mut IrBuilder,
    s: &mut LiftState,
    cc: &dyn CallingConvLookup,
) {
    // A direct tail jmp: the callee reads its ABI argument registers and, on its
    // own RET, returns to our caller. Keep the argument values live in their ABI
    // registers across the jump (mirroring a call's pinning) and keep RSP live so
    // the frame teardown survives DCE.
    let Some(reference) =
        s.address_reference(0, target, kamy_core::LinkField::Relative32 { bias: 0 })
    else {
        s.unsupported = true;
        return;
    };
    if let Some(sig) = call_signature(target, Some(&reference), cc, s) {
        for value in &sig.args {
            let Some(phys) = value.register_location() else {
                continue;
            };
            let input = match phys {
                PhysReg::Gpr(g) => s.get_gpr(g),
                PhysReg::Xmm(x) => s.get_xmm(x),
                PhysReg::Flag(f) => s.get_flag(f),
            };
            // A merge-entry placeholder loses its pin during SSA construction.
            let copy = b.emit(IrOp::Copy, &[input], register_type(phys));
            s.reg_pins.insert(copy, phys);
            b.emit_void(IrOp::Use, &[copy], register_type(phys));
        }
    }
    // RAX carries a tail-forwarded value independent of the arg signature: the
    // Windows /guard:cf dispatch thunk (`jmp [__guard_dispatch_icall_fptr]`)
    // takes the indirect-call target in RAX, so a tail jmp through it must keep
    // the function's RAX live to the jump or the guard dispatches to garbage.
    pin_live_out(PhysReg::Gpr(Gpr::Rax), b, s);
    preserve_authored_registers(b, s, false);
    b.emit_void(IrOp::Use, &[s.get_gpr(Gpr::Rsp)], IrType::I64);
}

pub(crate) fn lift_cmovcc(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let cc = insn.condition_code();
    let cond = decode_condition(cc, b, s);
    let (src, ty) = read_operand(insn, 1, b, s);
    let (cur, _) = read_operand(insn, 0, b, s);
    let result = b.emit(IrOp::Select, &[cond, src, cur], ty);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_setcc(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let cc = insn.condition_code();
    let cond = decode_condition(cc, b, s);
    let result = b.emit(IrOp::SetIf, &[cond], IrType::I8);
    write_operand(insn, 0, result, IrType::I8, b, s);
}

pub(crate) fn lift_movaps(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (src, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Mov128, &[src], IrType::I128);
    write_operand(insn, 0, result, IrType::I128, b, s);
}

pub(crate) fn lift_movsd(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let src_kind = insn.op_kind(1);
    if src_kind == OpKind::Memory {
        let addr = compute_mem_addr(insn, b, s);
        let val = b.emit(IrOp::Load, &[addr], IrType::I64);
        if let Some(xmm) = iced_reg_to_xmm(insn.op_register(0)) {
            s.set_xmm(xmm, val);
        }
    } else if insn.op_kind(0) == OpKind::Memory {
        let src_reg = insn.op_register(1);
        let val = if let Some(xmm) = iced_reg_to_xmm(src_reg) {
            s.get_xmm(xmm)
        } else {
            b.emit(IrOp::Undef, &[], IrType::I64)
        };
        let addr = compute_mem_addr(insn, b, s);
        b.emit_void(IrOp::Store, &[addr, val], IrType::I64);
    } else {
        s.unsupported = true;
    }
}

pub(crate) fn lift_movss(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let src_kind = insn.op_kind(1);
    if src_kind == OpKind::Memory {
        let addr = compute_mem_addr(insn, b, s);
        let val = b.emit(IrOp::Load, &[addr], IrType::I32);
        if let Some(xmm) = iced_reg_to_xmm(insn.op_register(0)) {
            s.set_xmm(xmm, val);
        }
    } else if insn.op_kind(0) == OpKind::Memory {
        let src_reg = insn.op_register(1);
        let val = if let Some(xmm) = iced_reg_to_xmm(src_reg) {
            s.get_xmm(xmm)
        } else {
            b.emit(IrOp::Undef, &[], IrType::I32)
        };
        let addr = compute_mem_addr(insn, b, s);
        b.emit_void(IrOp::Store, &[addr, val], IrType::I32);
    } else {
        s.unsupported = true;
    }
}

pub(crate) fn lift_xorps(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let r0 = insn.op_register(0);
    let r1 = insn.op_register(1);
    if r0 == r1 {
        let zero = b.emit(IrOp::Const(0), &[], IrType::I128);
        if let Some(xmm) = iced_reg_to_xmm(r0) {
            s.set_xmm(xmm, zero);
        }
    } else {
        let (a, _) = read_operand(insn, 0, b, s);
        let (bv, _) = read_operand(insn, 1, b, s);
        let result = b.emit(IrOp::Xor, &[a, bv], IrType::I128);
        if let Some(xmm) = iced_reg_to_xmm(r0) {
            s.set_xmm(xmm, result);
        }
    }
}
