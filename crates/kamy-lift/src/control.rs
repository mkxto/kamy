use iced_x86::{Instruction, OpKind};
use kamy_core::ir::{CallingConvLookup, Gpr, IrOp, IrType, PhysReg, ValueId, X86Flag};

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

pub(crate) fn lift_call(
    _insn: &Instruction,
    target: u64,
    b: &mut IrBuilder,
    s: &mut LiftState,
    cc: &dyn CallingConvLookup,
) {
    let sig = cc.lookup(target);

    let mut arg_vals = Vec::new();
    if let Some(sig) = &sig {
        for phys in &sig.args {
            let v = match phys {
                PhysReg::Gpr(g) => s.get_gpr(*g),
                PhysReg::Xmm(x) => s.get_xmm(*x),
                PhysReg::Flag(f) => s.get_flag(*f),
            };
            // The value must sit in its ABI argument register at the call. Pin it
            // there, or copy first when it is already bound elsewhere (another arg
            // register, an RSP-chain value, or a prior pin).
            let arg = if matches!(phys, PhysReg::Flag(_)) || s.reg_pins.get(&v) == Some(phys) {
                v
            } else if s.reg_pins.contains_key(&v) || s.rsp_chain.contains(&v) {
                let ty = if matches!(phys, PhysReg::Xmm(_)) {
                    IrType::I128
                } else {
                    IrType::I64
                };
                let c = b.emit(IrOp::Copy, &[v], ty);
                s.reg_pins.insert(c, *phys);
                c
            } else {
                s.reg_pins.insert(v, *phys);
                v
            };
            arg_vals.push(arg);
        }
    }

    // A balanced CALL/RET leaves RSP unchanged: the hardware CALL pushes the
    // return address and the callee's RET pops it. Materializing that push made
    // the pre-call RSP a second chain value live across the call, which the
    // allocator cannot keep in RSP alongside the push slot (it spilled RSP to a
    // GPR, corrupting the frame).
    let call_ret = b.emit(IrOp::Call { target }, &arg_vals, IrType::I64);

    if let Some(sig) = &sig {
        if let Some(ret_reg) = sig.ret {
            match ret_reg {
                PhysReg::Gpr(g) => {
                    s.set_gpr(g, call_ret);
                    s.reg_pins.insert(call_ret, PhysReg::Gpr(g));
                }
                PhysReg::Xmm(x) => {
                    s.set_xmm(x, call_ret);
                    s.reg_pins.insert(call_ret, PhysReg::Xmm(x));
                }
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

pub(crate) fn lift_call_indirect(
    target_val: ValueId,
    b: &mut IrBuilder,
    s: &mut LiftState,
    cc: &dyn CallingConvLookup,
) {
    // Indirect calls carry no resolvable target address, so assume the Win64
    // default ABI; over-approximating the argument set is safe, never unsound.
    let sig = cc.lookup(0);

    let mut arg_vals = Vec::new();
    if let Some(sig) = &sig {
        for phys in &sig.args {
            let v = match phys {
                PhysReg::Gpr(g) => s.get_gpr(*g),
                PhysReg::Xmm(x) => s.get_xmm(*x),
                PhysReg::Flag(f) => s.get_flag(*f),
            };
            let arg = if matches!(phys, PhysReg::Flag(_)) || s.reg_pins.get(&v) == Some(phys) {
                v
            } else if s.reg_pins.contains_key(&v) || s.rsp_chain.contains(&v) {
                let ty = if matches!(phys, PhysReg::Xmm(_)) {
                    IrType::I128
                } else {
                    IrType::I64
                };
                let c = b.emit(IrOp::Copy, &[v], ty);
                s.reg_pins.insert(c, *phys);
                c
            } else {
                s.reg_pins.insert(v, *phys);
                v
            };
            arg_vals.push(arg);
        }
    }

    // The call reads the target after the argument setup, so park it in R11 —
    // volatile, never a Win64 argument register. Copy first if already bound.
    let target = if s.reg_pins.contains_key(&target_val) || s.rsp_chain.contains(&target_val) {
        let c = b.emit(IrOp::Copy, &[target_val], IrType::I64);
        s.reg_pins.insert(c, PhysReg::Gpr(Gpr::R11));
        c
    } else {
        s.reg_pins.insert(target_val, PhysReg::Gpr(Gpr::R11));
        target_val
    };

    let mut call_args = Vec::with_capacity(arg_vals.len() + 1);
    call_args.push(target);
    call_args.extend(arg_vals);
    let call_ret = b.emit(IrOp::CallIndirect, &call_args, IrType::I64);

    if let Some(sig) = &sig {
        if let Some(ret_reg) = sig.ret {
            match ret_reg {
                PhysReg::Gpr(g) => {
                    s.set_gpr(g, call_ret);
                    s.reg_pins.insert(call_ret, PhysReg::Gpr(g));
                }
                PhysReg::Xmm(x) => {
                    s.set_xmm(x, call_ret);
                    s.reg_pins.insert(call_ret, PhysReg::Xmm(x));
                }
                PhysReg::Flag(_) => {}
            }
        }
        for phys in &sig.clobbers {
            if sig.ret == Some(*phys) {
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
    // The hardware RET pops the return address and adds 8 to RSP; modeling that
    // here double-counts the adjustment and makes RET read past the saved
    // return address.
    //
    // Return value goes in RAX: pin it there, or copy first when it is already
    // bound to another physical register (e.g. an argument passed straight
    // through, or an RSP-chain value). RSP live-out keeps the frame teardown.
    let rax_value = s.get_gpr(Gpr::Rax);
    let ret_val = if s.reg_pins.contains_key(&rax_value) || s.rsp_chain.contains(&rax_value) {
        b.emit(IrOp::Copy, &[rax_value], IrType::I64)
    } else {
        rax_value
    };
    s.reg_pins.insert(ret_val, PhysReg::Gpr(Gpr::Rax));
    b.emit_void(IrOp::Use, &[ret_val], IrType::I64);
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
    if let Some(sig) = cc.lookup(target) {
        for phys in &sig.args {
            if matches!(phys, PhysReg::Flag(_)) {
                continue;
            }
            let v = match phys {
                PhysReg::Gpr(g) => s.get_gpr(*g),
                PhysReg::Xmm(x) => s.get_xmm(*x),
                PhysReg::Flag(f) => s.get_flag(*f),
            };
            let arg = if s.reg_pins.get(&v) == Some(phys) {
                v
            } else if s.reg_pins.contains_key(&v) || s.rsp_chain.contains(&v) {
                let ty = if matches!(phys, PhysReg::Xmm(_)) {
                    IrType::I128
                } else {
                    IrType::I64
                };
                let c = b.emit(IrOp::Copy, &[v], ty);
                s.reg_pins.insert(c, *phys);
                c
            } else {
                s.reg_pins.insert(v, *phys);
                v
            };
            b.emit_void(IrOp::Use, &[arg], IrType::I64);
        }
    }
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
        b.emit_void(IrOp::Store, &[addr, val], IrType::I32);
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
