use iced_x86::{Instruction, OpKind};
use kamy_core::ir::{CallingConvLookup, Gpr, IrOp, IrType, PhysReg, X86Flag};

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
        _ => {
            let imm = crate::get_immediate(insn, 0);
            b.emit(IrOp::Const(imm), &[], IrType::I64)
        }
    };

    let rsp = s.get_gpr(Gpr::Rsp);
    let eight = b.emit(IrOp::Const(8), &[], IrType::I64);
    let new_rsp = b.emit(IrOp::Sub, &[rsp, eight], IrType::I64);
    s.set_gpr(Gpr::Rsp, new_rsp);
    b.emit_void(IrOp::Store, &[new_rsp, val]);
}

pub(crate) fn lift_pop(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let rsp = s.get_gpr(Gpr::Rsp);
    let val = b.emit(IrOp::Load, &[rsp], IrType::I64);
    let eight = b.emit(IrOp::Const(8), &[], IrType::I64);
    let new_rsp = b.emit(IrOp::Add, &[rsp, eight], IrType::I64);
    s.set_gpr(Gpr::Rsp, new_rsp);
    write_operand(insn, 0, val, IrType::I64, b, s);
}

pub(crate) fn lift_call(
    insn: &Instruction,
    target: u64,
    b: &mut IrBuilder,
    s: &mut LiftState,
    cc: &dyn CallingConvLookup,
) {
    let orig_rsp = s.get_gpr(Gpr::Rsp);

    let eight = b.emit(IrOp::Const(8), &[], IrType::I64);
    let push_rsp = b.emit(IrOp::Sub, &[orig_rsp, eight], IrType::I64);
    s.set_gpr(Gpr::Rsp, push_rsp);
    let ret_addr = b.emit(IrOp::Const(insn.next_ip()), &[], IrType::I64);
    b.emit_void(IrOp::Store, &[push_rsp, ret_addr]);

    let sig = cc.lookup(target);

    let mut arg_vals = Vec::new();
    if let Some(ref sig) = sig {
        for phys in &sig.args {
            arg_vals.push(match phys {
                PhysReg::Gpr(g) => s.get_gpr(*g),
                PhysReg::Xmm(x) => s.get_xmm(*x),
                PhysReg::Flag(f) => s.get_flag(*f),
            });
        }
    }

    let call_ret = b.emit(IrOp::Call { target }, &arg_vals, IrType::I64);

    s.set_gpr(Gpr::Rsp, orig_rsp);

    if let Some(ref sig) = sig {
        if let Some(ret_reg) = sig.ret {
            match ret_reg {
                PhysReg::Gpr(g) => s.set_gpr(g, call_ret),
                PhysReg::Xmm(x) => s.set_xmm(x, call_ret),
                PhysReg::Flag(_) => {}
            }
        }

        for phys in &sig.clobbers {
            let already_set = sig.ret == Some(*phys);
            if already_set {
                continue;
            }
            match phys {
                PhysReg::Gpr(g) => {
                    let v = b.emit(IrOp::Undef, &[], IrType::I64);
                    s.set_gpr(*g, v);
                }
                PhysReg::Xmm(x) => {
                    let v = b.emit(IrOp::Undef, &[], IrType::I128);
                    s.set_xmm(*x, v);
                }
                PhysReg::Flag(_) => {}
            }
        }
    }

    for f in X86Flag::ALL {
        let v = b.emit(IrOp::Undef, &[], IrType::I8);
        s.set_flag(f, v);
    }
}

pub(crate) fn lift_ret(b: &mut IrBuilder, s: &mut LiftState) {
    let rsp = s.get_gpr(Gpr::Rsp);
    let _ret_addr = b.emit(IrOp::Load, &[rsp], IrType::I64);
    let eight = b.emit(IrOp::Const(8), &[], IrType::I64);
    let new_rsp = b.emit(IrOp::Add, &[rsp, eight], IrType::I64);
    s.set_gpr(Gpr::Rsp, new_rsp);
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
        b.emit_void(IrOp::Store, &[addr, val]);
    } else {
        let (src, _) = read_operand(insn, 1, b, s);
        let copy = b.emit(IrOp::Copy, &[src], IrType::I64);
        if let Some(xmm) = iced_reg_to_xmm(insn.op_register(0)) {
            s.set_xmm(xmm, copy);
        }
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
        b.emit_void(IrOp::Store, &[addr, val]);
    } else {
        let (src, _) = read_operand(insn, 1, b, s);
        let copy = b.emit(IrOp::Copy, &[src], IrType::I32);
        if let Some(xmm) = iced_reg_to_xmm(insn.op_register(0)) {
            s.set_xmm(xmm, copy);
        }
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
