use iced_x86::{Instruction, OpKind};
use kamy_core::ir::{Gpr, IrOp, IrType, PhysReg, ValueId, X86Flag};

use crate::builder::IrBuilder;
use crate::flags::{emit_arith_flags, emit_logic_flags, emit_shift_flags, preserve_zero_count};
use crate::state::LiftState;
use crate::{compute_mem_addr, read_operand, write_operand};

pub(crate) fn lift_add(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (bv, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Add, &[a, bv], ty);
    emit_arith_flags(b, s, result, a, bv, false);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_sub(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (bv, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Sub, &[a, bv], ty);
    emit_arith_flags(b, s, result, a, bv, true);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_cmp(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (bv, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Sub, &[a, bv], ty);
    emit_arith_flags(b, s, result, a, bv, true);
}

pub(crate) fn lift_inc(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let one = b.emit(IrOp::Const(1), &[], ty);
    let result = b.emit(IrOp::Add, &[a, one], ty);

    let cf = s.get_flag(X86Flag::Cf);

    emit_arith_flags(b, s, result, a, one, false);
    s.set_flag(X86Flag::Cf, cf);

    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_dec(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let one = b.emit(IrOp::Const(1), &[], ty);
    let result = b.emit(IrOp::Sub, &[a, one], ty);

    let cf = s.get_flag(X86Flag::Cf);

    emit_arith_flags(b, s, result, a, one, true);
    s.set_flag(X86Flag::Cf, cf);

    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_neg(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let zero = b.emit(IrOp::Const(0), &[], ty);
    let result = b.emit(IrOp::Sub, &[zero, a], ty);
    emit_arith_flags(b, s, result, zero, a, true);

    let is_zero = b.emit(IrOp::IsZero, &[a], IrType::I8);
    let cf_inv = b.emit(IrOp::BoolNot, &[is_zero], IrType::I8);
    s.set_flag(X86Flag::Cf, cf_inv);

    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_and(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (bv, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::And, &[a, bv], ty);
    emit_logic_flags(b, s, result);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_or(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (bv, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Or, &[a, bv], ty);
    emit_logic_flags(b, s, result);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_xor(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (bv, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Xor, &[a, bv], ty);
    emit_logic_flags(b, s, result);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_test(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (bv, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::And, &[a, bv], ty);
    emit_logic_flags(b, s, result);
}

pub(crate) fn lift_not(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let result = b.emit(IrOp::Not, &[a], ty);
    write_operand(insn, 0, result, ty, b, s);
}

fn zero_immediate_count(insn: &Instruction, ty: IrType) -> bool {
    let mask = if ty == IrType::I64 { 63 } else { 31 };
    crate::is_immediate(insn.op1_kind()) && crate::get_immediate(insn, 1) & mask == 0
}

pub(crate) fn lift_shl(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (count, count_ty) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Shl, &[a, count], ty);
    if !zero_immediate_count(insn, ty) {
        let prior = (insn.op1_kind() == OpKind::Register)
            .then(|| X86Flag::ALL.map(|flag| (flag, s.get_flag(flag))));
        emit_shift_flags(b, s, result, a, count, &IrOp::Shl);
        if let Some(prior) = prior {
            preserve_zero_count(b, s, (count, count_ty), ty, &prior);
        }
    }
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_shr(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (count, count_ty) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Shr, &[a, count], ty);
    if !zero_immediate_count(insn, ty) {
        let prior = (insn.op1_kind() == OpKind::Register)
            .then(|| X86Flag::ALL.map(|flag| (flag, s.get_flag(flag))));
        emit_shift_flags(b, s, result, a, count, &IrOp::Shr);
        if let Some(prior) = prior {
            preserve_zero_count(b, s, (count, count_ty), ty, &prior);
        }
    }
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_sar(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (count, count_ty) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Sar, &[a, count], ty);
    if !zero_immediate_count(insn, ty) {
        let prior = (insn.op1_kind() == OpKind::Register)
            .then(|| X86Flag::ALL.map(|flag| (flag, s.get_flag(flag))));
        emit_shift_flags(b, s, result, a, count, &IrOp::Sar);
        if let Some(prior) = prior {
            preserve_zero_count(b, s, (count, count_ty), ty, &prior);
        }
    }
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_rol(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (count, count_ty) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Rol, &[a, count], ty);

    if !zero_immediate_count(insn, ty) {
        let prior = (insn.op1_kind() == OpKind::Register)
            .then(|| [X86Flag::Cf, X86Flag::Of].map(|flag| (flag, s.get_flag(flag))));
        let cf = b.emit(IrOp::CarryShl, &[a, count], IrType::I8);
        s.set_flag(X86Flag::Cf, cf);
        let of = b.emit(IrOp::Undef, &[], IrType::I8);
        s.set_flag(X86Flag::Of, of);
        if let Some(prior) = prior {
            preserve_zero_count(b, s, (count, count_ty), ty, &prior);
        }
    }

    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_ror(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (count, count_ty) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Ror, &[a, count], ty);

    if !zero_immediate_count(insn, ty) {
        let prior = (insn.op1_kind() == OpKind::Register)
            .then(|| [X86Flag::Cf, X86Flag::Of].map(|flag| (flag, s.get_flag(flag))));
        let cf = b.emit(IrOp::CarryShr, &[a, count], IrType::I8);
        s.set_flag(X86Flag::Cf, cf);
        let of = b.emit(IrOp::Undef, &[], IrType::I8);
        s.set_flag(X86Flag::Of, of);
        if let Some(prior) = prior {
            preserve_zero_count(b, s, (count, count_ty), ty, &prior);
        }
    }

    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_mul(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    detach_implicit_gprs(b, s);
    let (src, ty) = read_operand(insn, 0, b, s);
    let rax = read_gpr_at_width(Gpr::Rax, ty, b, s);
    let (lo, hi) = emit_mul_pair(IrOp::UMulHi, rax, src, ty, b, s);
    write_implicit_pair(lo, hi, ty, b, s);

    let hi_nz = b.emit(IrOp::IsZero, &[hi], IrType::I8);
    let cf = b.emit(IrOp::BoolNot, &[hi_nz], IrType::I8);
    s.set_flag(X86Flag::Cf, cf);
    s.set_flag(X86Flag::Of, cf);
    undef_flags(b, s, &[X86Flag::Zf, X86Flag::Sf, X86Flag::Pf, X86Flag::Af]);
}

pub(crate) fn lift_imul(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let count = insn.op_count();
    if count == 1 {
        lift_imul_1op(insn, b, s);
    } else if count == 2 {
        lift_imul_2op(insn, b, s);
    } else {
        lift_imul_3op(insn, b, s);
    }
}

fn lift_imul_1op(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    detach_implicit_gprs(b, s);
    let (src, ty) = read_operand(insn, 0, b, s);
    let rax = read_gpr_at_width(Gpr::Rax, ty, b, s);
    let (lo, hi) = emit_mul_pair(IrOp::SMulHi, rax, src, ty, b, s);
    write_implicit_pair(lo, hi, ty, b, s);
    emit_signed_mul_flags(lo, hi, ty, b, s);
    undef_flags(b, s, &[X86Flag::Zf, X86Flag::Sf, X86Flag::Pf, X86Flag::Af]);
}

fn lift_imul_2op(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    detach_implicit_gprs(b, s);
    let (a, ty) = read_operand(insn, 0, b, s);
    let (bv, _) = read_operand(insn, 1, b, s);
    let (result, hi) = emit_mul_pair(IrOp::SMulHi, a, bv, ty, b, s);
    emit_signed_mul_flags(result, hi, ty, b, s);
    undef_flags(b, s, &[X86Flag::Zf, X86Flag::Sf, X86Flag::Pf, X86Flag::Af]);

    write_operand(insn, 0, result, ty, b, s);
}

fn lift_imul_3op(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    detach_implicit_gprs(b, s);
    let (_, ty) = read_operand(insn, 0, b, s);
    let (src, _) = read_operand(insn, 1, b, s);
    let imm = crate::get_immediate(insn, 2);
    let imm_val = b.emit(IrOp::Const(imm), &[], ty);
    let (result, hi) = emit_mul_pair(IrOp::SMulHi, src, imm_val, ty, b, s);
    emit_signed_mul_flags(result, hi, ty, b, s);
    undef_flags(b, s, &[X86Flag::Zf, X86Flag::Sf, X86Flag::Pf, X86Flag::Af]);

    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_div(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    lift_division(insn, false, b, s);
}

pub(crate) fn lift_idiv(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    lift_division(insn, true, b, s);
}

pub(crate) fn lift_mov(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (src, ty) = read_operand(insn, 1, b, s);
    write_operand(insn, 0, src, ty, b, s);
}

pub(crate) fn lift_lea(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let addr = compute_mem_addr(insn, b, s);
    let dest_reg = insn.op_register(0);
    let ty = crate::gpr_reg_type(dest_reg);
    if ty != IrType::I64 {
        let trunc = b.emit(IrOp::Trunc, &[addr], ty);
        write_operand(insn, 0, trunc, ty, b, s);
    } else {
        write_operand(insn, 0, addr, IrType::I64, b, s);
    }
}

pub(crate) fn lift_movzx(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (src, _) = read_operand(insn, 1, b, s);
    let dest_reg = insn.op_register(0);
    let dest_ty = crate::gpr_reg_type(dest_reg);
    let extended = b.emit(IrOp::Zext, &[src], dest_ty);
    write_operand(insn, 0, extended, dest_ty, b, s);
}

pub(crate) fn lift_movsx(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (src, _) = read_operand(insn, 1, b, s);
    let dest_reg = insn.op_register(0);
    let dest_ty = crate::gpr_reg_type(dest_reg);
    let extended = b.emit(IrOp::Sext, &[src], dest_ty);
    write_operand(insn, 0, extended, dest_ty, b, s);
}

pub(crate) fn lift_cdq(b: &mut IrBuilder, s: &mut LiftState) {
    let rax = s.get_gpr(Gpr::Rax);
    let eax = b.emit(IrOp::Trunc, &[rax], IrType::I32);
    let sign = b.emit(IrOp::Const(31), &[], IrType::I32);
    let hi = b.emit(IrOp::Sar, &[eax, sign], IrType::I32);
    let ext = b.emit(IrOp::Zext, &[hi], IrType::I64);
    s.set_gpr(Gpr::Rdx, ext);
}

pub(crate) fn lift_cqo(b: &mut IrBuilder, s: &mut LiftState) {
    let rax = s.get_gpr(Gpr::Rax);
    let sign = b.emit(IrOp::Const(63), &[], IrType::I64);
    let hi = b.emit(IrOp::Sar, &[rax, sign], IrType::I64);
    s.set_gpr(Gpr::Rdx, hi);
}

pub(crate) fn lift_cdqe(b: &mut IrBuilder, s: &mut LiftState) {
    let rax = s.get_gpr(Gpr::Rax);
    let eax = b.emit(IrOp::Trunc, &[rax], IrType::I32);
    let ext = b.emit(IrOp::Sext, &[eax], IrType::I64);
    s.set_gpr(Gpr::Rax, ext);
}

pub(crate) fn lift_xchg(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (bv, _) = read_operand(insn, 1, b, s);
    let copy_a = b.emit(IrOp::Copy, &[a], ty);
    let copy_b = b.emit(IrOp::Copy, &[bv], ty);
    write_operand(insn, 0, copy_b, ty, b, s);
    write_operand(insn, 1, copy_a, ty, b, s);
}

pub(crate) fn lift_bswap(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let result = b.emit(IrOp::Bswap, &[a], ty);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_bsf(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (src, ty) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Bsf, &[src], ty);
    let zf = b.emit(IrOp::IsZero, &[src], IrType::I8);
    s.set_flag(X86Flag::Zf, zf);
    undef_flags(
        b,
        s,
        &[
            X86Flag::Cf,
            X86Flag::Of,
            X86Flag::Sf,
            X86Flag::Pf,
            X86Flag::Af,
        ],
    );
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_bsr(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (src, ty) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Bsr, &[src], ty);
    let zf = b.emit(IrOp::IsZero, &[src], IrType::I8);
    s.set_flag(X86Flag::Zf, zf);
    undef_flags(
        b,
        s,
        &[
            X86Flag::Cf,
            X86Flag::Of,
            X86Flag::Sf,
            X86Flag::Pf,
            X86Flag::Af,
        ],
    );
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_popcnt(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (src, ty) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Popcnt, &[src], ty);
    let zf = b.emit(IrOp::IsZero, &[result], IrType::I8);
    s.set_flag(X86Flag::Zf, zf);
    let zero = b.emit(IrOp::Const(0), &[], IrType::I8);
    s.set_flag(X86Flag::Cf, zero);
    s.set_flag(X86Flag::Of, zero);
    s.set_flag(X86Flag::Sf, zero);
    s.set_flag(X86Flag::Pf, zero);
    s.set_flag(X86Flag::Af, zero);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_lzcnt(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (src, ty) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Lzcnt, &[src], ty);
    let cf = b.emit(IrOp::IsZero, &[src], IrType::I8);
    s.set_flag(X86Flag::Cf, cf);
    let zf = b.emit(IrOp::IsZero, &[result], IrType::I8);
    s.set_flag(X86Flag::Zf, zf);
    undef_flags(b, s, &[X86Flag::Of, X86Flag::Sf, X86Flag::Pf, X86Flag::Af]);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_tzcnt(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (src, ty) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Tzcnt, &[src], ty);
    let cf = b.emit(IrOp::IsZero, &[src], IrType::I8);
    s.set_flag(X86Flag::Cf, cf);
    let zf = b.emit(IrOp::IsZero, &[result], IrType::I8);
    s.set_flag(X86Flag::Zf, zf);
    undef_flags(b, s, &[X86Flag::Of, X86Flag::Sf, X86Flag::Pf, X86Flag::Af]);
    write_operand(insn, 0, result, ty, b, s);
}

fn detach_implicit_gprs(b: &mut IrBuilder, s: &mut LiftState) {
    for gpr in [Gpr::Rax, Gpr::Rdx] {
        let saved = b.emit(IrOp::Copy, &[s.get_gpr(gpr)], IrType::I64);
        s.set_gpr(gpr, saved);
    }
}

fn fixed_input(
    value: ValueId,
    gpr: Gpr,
    ty: IrType,
    b: &mut IrBuilder,
    s: &mut LiftState,
) -> ValueId {
    let fixed = b.emit(IrOp::Copy, &[value], ty);
    s.reg_pins.insert(fixed, PhysReg::Gpr(gpr));
    fixed
}

fn emit_mul_pair(
    op: IrOp,
    lhs: ValueId,
    rhs: ValueId,
    ty: IrType,
    b: &mut IrBuilder,
    s: &mut LiftState,
) -> (ValueId, ValueId) {
    let lhs = b.emit(IrOp::Copy, &[lhs], ty);
    let rhs = b.emit(IrOp::Copy, &[rhs], ty);
    let lhs = fixed_input(lhs, Gpr::Rax, ty, b, s);
    let high = b.emit(op, &[lhs, rhs], ty);
    s.reg_pins.insert(high, PhysReg::Gpr(Gpr::Rdx));
    let low = b.emit(IrOp::Mul, &[high], ty);
    s.reg_pins.insert(low, PhysReg::Gpr(Gpr::Rax));
    let low = b.emit(IrOp::Copy, &[low], ty);
    let high = b.emit(IrOp::Copy, &[high], ty);
    (low, high)
}

fn emit_signed_mul_flags(
    lo: ValueId,
    hi: ValueId,
    ty: IrType,
    b: &mut IrBuilder,
    s: &mut LiftState,
) {
    let shift = b.emit(IrOp::Const((ty.bits() - 1) as u64), &[], ty);
    let sign = b.emit(IrOp::Sar, &[lo, shift], ty);
    let diff = b.emit(IrOp::Xor, &[hi, sign], ty);
    let zero = b.emit(IrOp::IsZero, &[diff], IrType::I8);
    let overflow = b.emit(IrOp::BoolNot, &[zero], IrType::I8);
    s.set_flag(X86Flag::Cf, overflow);
    s.set_flag(X86Flag::Of, overflow);
}

fn write_implicit_pair(lo: ValueId, hi: ValueId, ty: IrType, b: &mut IrBuilder, s: &mut LiftState) {
    if ty == IrType::I8 {
        let lo = b.emit(IrOp::Zext, &[lo], IrType::I16);
        let hi = b.emit(IrOp::Zext, &[hi], IrType::I16);
        let eight = b.emit(IrOp::Const(8), &[], IrType::I16);
        let hi = b.emit(IrOp::Shl, &[hi, eight], IrType::I16);
        let ax = b.emit(IrOp::Or, &[lo, hi], IrType::I16);
        write_gpr_at_width(Gpr::Rax, ax, IrType::I16, b, s);
    } else {
        write_gpr_at_width(Gpr::Rax, lo, ty, b, s);
        write_gpr_at_width(Gpr::Rdx, hi, ty, b, s);
    }
}

fn lift_division(insn: &Instruction, signed: bool, b: &mut IrBuilder, s: &mut LiftState) {
    detach_implicit_gprs(b, s);
    let (divisor, ty) = read_operand(insn, 0, b, s);
    let low = read_gpr_at_width(Gpr::Rax, ty, b, s);
    let high = if ty == IrType::I8 {
        let eight = b.emit(IrOp::Const(8), &[], IrType::I64);
        let high = b.emit(IrOp::Shr, &[s.get_gpr(Gpr::Rax), eight], IrType::I64);
        b.emit(IrOp::Trunc, &[high], IrType::I8)
    } else {
        read_gpr_at_width(Gpr::Rdx, ty, b, s)
    };
    // Snapshot every source before writing either fixed input, including cycles.
    let high = b.emit(IrOp::Copy, &[high], ty);
    let low = b.emit(IrOp::Copy, &[low], ty);
    let divisor = b.emit(IrOp::Copy, &[divisor], ty);
    let high = fixed_input(high, Gpr::Rdx, ty, b, s);
    let low = fixed_input(low, Gpr::Rax, ty, b, s);
    let quotient = b.emit(
        if signed { IrOp::SDiv } else { IrOp::UDiv },
        &[high, low, divisor],
        ty,
    );
    s.reg_pins.insert(quotient, PhysReg::Gpr(Gpr::Rax));
    let remainder = b.emit(
        if signed { IrOp::SRem } else { IrOp::URem },
        &[quotient],
        ty,
    );
    s.reg_pins.insert(remainder, PhysReg::Gpr(Gpr::Rdx));
    let quotient = b.emit(IrOp::Copy, &[quotient], ty);
    let remainder = b.emit(IrOp::Copy, &[remainder], ty);
    write_implicit_pair(quotient, remainder, ty, b, s);
    undef_flags(
        b,
        s,
        &[
            X86Flag::Cf,
            X86Flag::Of,
            X86Flag::Zf,
            X86Flag::Sf,
            X86Flag::Pf,
            X86Flag::Af,
        ],
    );
}

fn read_gpr_at_width(gpr: Gpr, ty: IrType, b: &mut IrBuilder, s: &LiftState) -> ValueId {
    let val = s.get_gpr(gpr);
    if ty == IrType::I64 {
        val
    } else {
        b.emit(IrOp::Trunc, &[val], ty)
    }
}

fn write_gpr_at_width(gpr: Gpr, val: ValueId, ty: IrType, b: &mut IrBuilder, s: &mut LiftState) {
    if ty == IrType::I64 {
        s.set_gpr(gpr, val);
    } else {
        crate::write_gpr_sub64(gpr, val, ty, b, s);
    }
}

fn undef_flags(b: &mut IrBuilder, s: &mut LiftState, flags: &[X86Flag]) {
    for &f in flags {
        let v = b.emit(IrOp::Undef, &[], IrType::I8);
        s.set_flag(f, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::ir::{BlockId, IrBlock, IrFunction, IrTerminator};
    use std::collections::HashMap;

    #[test]
    fn immediate_zero_and_masked_zero_preserve_all_shift_flags() {
        for extension in [0xe0, 0xe8, 0xf8, 0xc0, 0xc8] {
            for (wide, count) in [(false, 0), (false, 32), (true, 0), (true, 64)] {
                let mut func = IrFunction {
                    entry: BlockId(0),
                    next_value: 0,
                    blocks: vec![IrBlock {
                        id: BlockId(0),
                        phis: vec![],
                        insts: vec![],
                        term: IrTerminator::Ret,
                    }],
                };
                let mut builder = IrBuilder::new(&mut func, BlockId(0));
                let mut state = LiftState::new_with_undefs(&mut builder, true);
                let before = X86Flag::ALL.map(|flag| state.get_flag(flag));
                let mut bytes = Vec::new();
                if wide {
                    bytes.push(0x48);
                }
                bytes.extend([0xc1, extension, count]);
                let instruction =
                    iced_x86::Decoder::new(64, &bytes, iced_x86::DecoderOptions::NONE).decode();
                match instruction.mnemonic() {
                    iced_x86::Mnemonic::Shl => lift_shl(&instruction, &mut builder, &mut state),
                    iced_x86::Mnemonic::Shr => lift_shr(&instruction, &mut builder, &mut state),
                    iced_x86::Mnemonic::Sar => lift_sar(&instruction, &mut builder, &mut state),
                    iced_x86::Mnemonic::Rol => lift_rol(&instruction, &mut builder, &mut state),
                    iced_x86::Mnemonic::Ror => lift_ror(&instruction, &mut builder, &mut state),
                    other => panic!("unexpected zero-count fixture: {other:?}"),
                }
                assert_eq!(X86Flag::ALL.map(|flag| state.get_flag(flag)), before);
            }
        }
    }

    #[test]
    fn runtime_count_guard_selects_prior_flags_only_for_effective_zero() {
        for ty in [IrType::I8, IrType::I16, IrType::I32, IrType::I64] {
            for count_ty in [IrType::I8, IrType::I64] {
                for count in [0, 1, 31, 32, 63, 64, 256] {
                    let mut func = IrFunction {
                        entry: BlockId(0),
                        next_value: 0,
                        blocks: vec![IrBlock {
                            id: BlockId(0),
                            phis: vec![],
                            insts: vec![],
                            term: IrTerminator::Ret,
                        }],
                    };
                    let outputs = {
                        let mut builder = IrBuilder::new(&mut func, BlockId(0));
                        let mut state = LiftState::new_with_undefs(&mut builder, true);
                        let prior = X86Flag::ALL.map(|flag| {
                            let previous = builder.emit(
                                IrOp::Const((flag.index() & 1) as u64),
                                &[],
                                IrType::I8,
                            );
                            let current = builder.emit(
                                IrOp::Const(((flag.index() & 1) ^ 1) as u64),
                                &[],
                                IrType::I8,
                            );
                            state.set_flag(flag, current);
                            (flag, previous)
                        });
                        let count_value = builder.emit(IrOp::Const(count), &[], count_ty);
                        preserve_zero_count(
                            &mut builder,
                            &mut state,
                            (count_value, count_ty),
                            ty,
                            &prior,
                        );
                        X86Flag::ALL.map(|flag| state.get_flag(flag))
                    };
                    let values = evaluate(&func);
                    let zero = count & if ty == IrType::I64 { 63 } else { 31 } == 0;
                    for flag in X86Flag::ALL {
                        let previous = (flag.index() & 1) as u64;
                        assert_eq!(
                            values[&outputs[flag.index()]],
                            if zero { previous } else { previous ^ 1 }
                        );
                    }
                }
            }
        }
    }

    fn lifted(
        code: &[u8],
        initial: [u64; 3],
    ) -> (IrFunction, HashMap<ValueId, PhysReg>, [ValueId; 4]) {
        let mut func = IrFunction {
            entry: BlockId(0),
            next_value: 0,
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![],
                term: IrTerminator::Ret,
            }],
        };
        let (pins, outputs) = {
            let mut builder = IrBuilder::new(&mut func, BlockId(0));
            let mut state = LiftState::new_with_undefs(&mut builder, true);
            for (gpr, value) in [Gpr::Rax, Gpr::Rdx, Gpr::Rcx].into_iter().zip(initial) {
                let value = builder.emit(IrOp::Const(value), &[], IrType::I64);
                state.set_gpr(gpr, value);
            }
            let instruction =
                iced_x86::Decoder::new(64, code, iced_x86::DecoderOptions::NONE).decode();
            match instruction.mnemonic() {
                iced_x86::Mnemonic::Div => lift_div(&instruction, &mut builder, &mut state),
                iced_x86::Mnemonic::Idiv => lift_idiv(&instruction, &mut builder, &mut state),
                iced_x86::Mnemonic::Mul => lift_mul(&instruction, &mut builder, &mut state),
                iced_x86::Mnemonic::Imul => lift_imul(&instruction, &mut builder, &mut state),
                _ => unreachable!(),
            }
            (
                state.reg_pins.clone(),
                [
                    state.get_gpr(Gpr::Rax),
                    state.get_gpr(Gpr::Rdx),
                    state.get_flag(X86Flag::Cf),
                    state.get_flag(X86Flag::Of),
                ],
            )
        };
        (func, pins, outputs)
    }

    fn evaluate(func: &IrFunction) -> HashMap<ValueId, u64> {
        let mut values: HashMap<ValueId, u64> = HashMap::new();
        let mut types: HashMap<ValueId, u32> = HashMap::new();
        let mut remainders: HashMap<ValueId, u64> = HashMap::new();
        let mut low_products: HashMap<ValueId, u64> = HashMap::new();
        for inst in &func.blocks[0].insts {
            let Some(dest) = inst.dest else { continue };
            let bits = inst.ty.bits().min(64);
            let mask = u64::MAX >> (64 - bits);
            let input = |index: usize| values[&inst.args[index]];
            let value = match inst.op {
                IrOp::Undef => 0,
                IrOp::Const(value) => value,
                IrOp::Copy | IrOp::Trunc => input(0),
                IrOp::Zext => input(0) & (u64::MAX >> (64 - types[&inst.args[0]].min(64))),
                IrOp::And => input(0) & input(1),
                IrOp::Or => input(0) | input(1),
                IrOp::Xor => input(0) ^ input(1),
                IrOp::Shl => input(0) << input(1),
                IrOp::Shr => input(0) >> input(1),
                IrOp::Sar => {
                    let signed = (i128::from(input(0)) << (128 - bits)) >> (128 - bits);
                    (signed >> input(1)) as u64
                }
                IrOp::Mul if inst.args.len() == 1 => low_products[&inst.args[0]],
                IrOp::Mul => input(0).wrapping_mul(input(1)),
                IrOp::UMulHi | IrOp::SMulHi => {
                    let signed = |value: u64| (i128::from(value) << (128 - bits)) >> (128 - bits);
                    let product = if matches!(inst.op, IrOp::SMulHi) {
                        (signed(input(0)) * signed(input(1))) as u128
                    } else {
                        u128::from(input(0)) * u128::from(input(1))
                    };
                    low_products.insert(dest, product as u64);
                    (product >> bits) as u64
                }
                IrOp::UDiv | IrOp::SDiv => {
                    let dividend = (u128::from(input(0)) << bits) | u128::from(input(1));
                    let (quotient, remainder) = if matches!(inst.op, IrOp::UDiv) {
                        (
                            dividend / u128::from(input(2)),
                            dividend % u128::from(input(2)),
                        )
                    } else {
                        let dividend = if bits == 64 {
                            dividend as i128
                        } else {
                            ((dividend << (128 - 2 * bits)) as i128) >> (128 - 2 * bits)
                        };
                        let divisor = (i128::from(input(2)) << (128 - bits)) >> (128 - bits);
                        ((dividend / divisor) as u128, (dividend % divisor) as u128)
                    };
                    remainders.insert(dest, remainder as u64);
                    quotient as u64
                }
                IrOp::URem | IrOp::SRem => remainders[&inst.args[0]],
                IrOp::IsZero => u64::from(input(0) == 0),
                IrOp::BoolNot => u64::from(input(0) == 0),
                IrOp::Select => {
                    if input(0) != 0 {
                        input(1)
                    } else {
                        input(2)
                    }
                }
                ref other => panic!("unexpected lifted arithmetic op {other:?}"),
            };
            values.insert(dest, value & mask);
            types.insert(dest, inst.ty.bits());
        }
        values
    }

    #[test]
    fn byte_division_uses_ax_and_preserves_rdx_and_upper_rax() {
        let (func, _, outputs) = lifted(
            &[0xf6, 0xf1],
            [0xabcd_1234_5678_0064, 0xfedc_ba98_7654_3210, 7],
        );
        let values = evaluate(&func);
        assert_eq!(values[&outputs[0]], 0xabcd_1234_5678_020e);
        assert_eq!(values[&outputs[1]], 0xfedc_ba98_7654_3210);
    }

    #[test]
    fn narrow_division_preserves_upper_halves_and_zero_extends_dword_results() {
        for (code, initial, expected) in [
            (
                &[0x66, 0xf7, 0xf1][..],
                [0xabcd_1234_5678_ffff, 0xfedc_ba98_7654_0000, 3],
                [0xabcd_1234_5678_5555, 0xfedc_ba98_7654_0000],
            ),
            (
                &[0xf7, 0xf1][..],
                [0xabcd_1234_ffff_ffff, 0xfedc_ba98_0000_0000, 3],
                [0x5555_5555, 0],
            ),
        ] {
            let (func, _, outputs) = lifted(code, initial);
            let values = evaluate(&func);
            assert_eq!([values[&outputs[0]], values[&outputs[1]]], expected);
        }
    }

    #[test]
    fn byte_high_product_and_signed_overflow_use_full_product_sign_extension() {
        for (code, initial, expected_ax, expected_overflow) in [
            (&[0xf6, 0xe9][..], 0xff, 0xfffe, 0),
            (&[0xf6, 0xe1][..], 0xff, 0x01fe, 1),
            (&[0xf6, 0xe9][..], 0x7f, 0x00fe, 1),
        ] {
            let (func, _, outputs) = lifted(
                code,
                [0xabcd_1234_5678_0000 | initial, 0xfedc_ba98_7654_3210, 2],
            );
            let values = evaluate(&func);
            assert_eq!(values[&outputs[0]], 0xabcd_1234_5678_0000 | expected_ax);
            assert_eq!(values[&outputs[1]], 0xfedc_ba98_7654_3210);
            assert_eq!(values[&outputs[2]], expected_overflow);
            assert_eq!(values[&outputs[3]], expected_overflow);
        }
    }

    #[test]
    fn byte_divisor_and_multiplier_can_read_ah() {
        for (code, initial, expected) in [
            (&[0xf6, 0xfc][..], 0xfffe, 2),
            (&[0xf6, 0xe4][..], 0x02ff, 0x01fe),
            (&[0xf6, 0xec][..], 0x02ff, 0xfffe),
        ] {
            let (func, _, outputs) = lifted(
                code,
                [0xabcd_1234_5678_0000 | initial, 0xfedc_ba98_7654_3210, 0],
            );
            let values = evaluate(&func);
            assert_eq!(values[&outputs[0]], 0xabcd_1234_5678_0000 | expected);
            assert_eq!(values[&outputs[1]], 0xfedc_ba98_7654_3210);
        }
    }

    #[test]
    fn optimized_low_and_high_product_consumers_share_one_multiply() {
        for prefix in [&[][..], &[0x66][..], &[0x48][..]] {
            for opcode in [0xe1, 0xe9] {
                for byte in [false, true] {
                    if byte && !prefix.is_empty() {
                        continue;
                    }
                    let mut code = prefix.to_vec();
                    code.extend([if byte { 0xf6 } else { 0xf7 }, opcode]);
                    let (mut func, pins, outputs) = lifted(&code, [u64::MAX, 0, 3]);
                    func.blocks[0].insts.push(kamy_core::ir::Inst {
                        dest: None,
                        op: IrOp::Use,
                        args: outputs.to_vec(),
                        ty: IrType::I64,
                    });
                    kamy_transforms::optimize(&mut func);
                    let high = func.blocks[0]
                        .insts
                        .iter()
                        .find(|inst| matches!(inst.op, IrOp::UMulHi | IrOp::SMulHi))
                        .unwrap();
                    let low = func.blocks[0]
                        .insts
                        .iter()
                        .find(|inst| matches!(inst.op, IrOp::Mul))
                        .unwrap();
                    assert_eq!(low.args, vec![high.dest.unwrap()]);
                    let alloc = kamy_codegen::allocate_registers(&func, &Default::default(), &pins)
                        .unwrap();
                    let selected = kamy_codegen::select_instructions(&func, &alloc);
                    assert_eq!(
                        selected
                            .instructions
                            .iter()
                            .filter(|inst| matches!(
                                inst.mnemonic(),
                                iced_x86::Mnemonic::Mul | iced_x86::Mnemonic::Imul
                            ))
                            .count(),
                        1
                    );
                }
            }
        }
    }

    #[test]
    fn optimized_remainder_only_and_dead_division_retain_single_faulting_operation() {
        for remainder_used in [false, true] {
            let (mut func, pins, outputs) = lifted(&[0x48, 0xf7, 0xf1], [u64::MAX, 0, 3]);
            if remainder_used {
                func.blocks[0].insts.push(kamy_core::ir::Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![outputs[1]],
                    ty: IrType::I64,
                });
            }
            kamy_transforms::optimize(&mut func);
            let division = func.blocks[0]
                .insts
                .iter()
                .filter(|inst| matches!(inst.op, IrOp::UDiv))
                .collect::<Vec<_>>();
            assert_eq!(division.len(), 1);
            if remainder_used {
                let remainder = func.blocks[0]
                    .insts
                    .iter()
                    .find(|inst| matches!(inst.op, IrOp::URem))
                    .unwrap();
                assert_eq!(remainder.args, vec![division[0].dest.unwrap()]);
            }
            let alloc =
                kamy_codegen::allocate_registers(&func, &Default::default(), &pins).unwrap();
            let selected = kamy_codegen::select_instructions(&func, &alloc);
            assert_eq!(
                selected
                    .instructions
                    .iter()
                    .filter(|inst| inst.mnemonic() == iced_x86::Mnemonic::Div)
                    .count(),
                1
            );
        }
    }
}
