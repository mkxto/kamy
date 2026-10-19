use iced_x86::Instruction;
use kamy_core::ir::{Gpr, IrOp, IrType, ValueId, X86Flag};

use crate::builder::IrBuilder;
use crate::flags::{emit_arith_flags, emit_logic_flags, emit_shift_flags};
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

pub(crate) fn lift_shl(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (count, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Shl, &[a, count], ty);
    emit_shift_flags(b, s, result, a, count, &IrOp::Shl);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_shr(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (count, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Shr, &[a, count], ty);
    emit_shift_flags(b, s, result, a, count, &IrOp::Shr);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_sar(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (count, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Sar, &[a, count], ty);
    emit_shift_flags(b, s, result, a, count, &IrOp::Sar);
    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_rol(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (count, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Rol, &[a, count], ty);

    let cf = b.emit(IrOp::CarryShl, &[a, count], IrType::I8);
    s.set_flag(X86Flag::Cf, cf);
    let of = b.emit(IrOp::Undef, &[], IrType::I8);
    s.set_flag(X86Flag::Of, of);

    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_ror(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (count, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Ror, &[a, count], ty);

    let cf = b.emit(IrOp::CarryShr, &[a, count], IrType::I8);
    s.set_flag(X86Flag::Cf, cf);
    let of = b.emit(IrOp::Undef, &[], IrType::I8);
    s.set_flag(X86Flag::Of, of);

    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_mul(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (src, ty) = read_operand(insn, 0, b, s);
    let rax = read_gpr_at_width(Gpr::Rax, ty, b, s);
    let lo = b.emit(IrOp::Mul, &[rax, src], ty);
    let hi = b.emit(IrOp::UMulHi, &[rax, src], ty);
    write_gpr_at_width(Gpr::Rax, lo, ty, b, s);
    write_gpr_at_width(Gpr::Rdx, hi, ty, b, s);

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
    let (src, ty) = read_operand(insn, 0, b, s);
    let rax = read_gpr_at_width(Gpr::Rax, ty, b, s);
    let lo = b.emit(IrOp::Mul, &[rax, src], ty);
    let hi = b.emit(IrOp::SMulHi, &[rax, src], ty);
    write_gpr_at_width(Gpr::Rax, lo, ty, b, s);
    write_gpr_at_width(Gpr::Rdx, hi, ty, b, s);

    let hi_nz = b.emit(IrOp::IsZero, &[hi], IrType::I8);
    let cf = b.emit(IrOp::BoolNot, &[hi_nz], IrType::I8);
    s.set_flag(X86Flag::Cf, cf);
    s.set_flag(X86Flag::Of, cf);
    undef_flags(b, s, &[X86Flag::Zf, X86Flag::Sf, X86Flag::Pf, X86Flag::Af]);
}

fn lift_imul_2op(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (a, ty) = read_operand(insn, 0, b, s);
    let (bv, _) = read_operand(insn, 1, b, s);
    let result = b.emit(IrOp::Mul, &[a, bv], ty);

    let hi = b.emit(IrOp::SMulHi, &[a, bv], ty);
    let bits_m1 = b.emit(IrOp::Const((ty.bits() - 1) as u64), &[], ty);
    let sign = b.emit(IrOp::Sar, &[result, bits_m1], ty);
    let diff = b.emit(IrOp::Xor, &[hi, sign], ty);
    let is_z = b.emit(IrOp::IsZero, &[diff], IrType::I8);
    let cf = b.emit(IrOp::BoolNot, &[is_z], IrType::I8);
    s.set_flag(X86Flag::Cf, cf);
    s.set_flag(X86Flag::Of, cf);
    undef_flags(b, s, &[X86Flag::Zf, X86Flag::Sf, X86Flag::Pf, X86Flag::Af]);

    write_operand(insn, 0, result, ty, b, s);
}

fn lift_imul_3op(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (_, ty) = read_operand(insn, 0, b, s);
    let (src, _) = read_operand(insn, 1, b, s);
    let imm = crate::get_immediate(insn, 2);
    let imm_val = b.emit(IrOp::Const(imm), &[], ty);
    let result = b.emit(IrOp::Mul, &[src, imm_val], ty);

    let hi = b.emit(IrOp::SMulHi, &[src, imm_val], ty);
    let bits_m1 = b.emit(IrOp::Const((ty.bits() - 1) as u64), &[], ty);
    let sign = b.emit(IrOp::Sar, &[result, bits_m1], ty);
    let diff = b.emit(IrOp::Xor, &[hi, sign], ty);
    let is_z = b.emit(IrOp::IsZero, &[diff], IrType::I8);
    let cf = b.emit(IrOp::BoolNot, &[is_z], IrType::I8);
    s.set_flag(X86Flag::Cf, cf);
    s.set_flag(X86Flag::Of, cf);
    undef_flags(b, s, &[X86Flag::Zf, X86Flag::Sf, X86Flag::Pf, X86Flag::Af]);

    write_operand(insn, 0, result, ty, b, s);
}

pub(crate) fn lift_div(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (divisor, ty) = read_operand(insn, 0, b, s);
    let rdx = read_gpr_at_width(Gpr::Rdx, ty, b, s);
    let rax = read_gpr_at_width(Gpr::Rax, ty, b, s);
    let quot = b.emit(IrOp::UDiv, &[rdx, rax, divisor], ty);
    let rem = b.emit(IrOp::URem, &[rdx, rax, divisor], ty);
    write_gpr_at_width(Gpr::Rax, quot, ty, b, s);
    write_gpr_at_width(Gpr::Rdx, rem, ty, b, s);
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

pub(crate) fn lift_idiv(insn: &Instruction, b: &mut IrBuilder, s: &mut LiftState) {
    let (divisor, ty) = read_operand(insn, 0, b, s);
    let rdx = read_gpr_at_width(Gpr::Rdx, ty, b, s);
    let rax = read_gpr_at_width(Gpr::Rax, ty, b, s);
    let quot = b.emit(IrOp::SDiv, &[rdx, rax, divisor], ty);
    let rem = b.emit(IrOp::SRem, &[rdx, rax, divisor], ty);
    write_gpr_at_width(Gpr::Rax, quot, ty, b, s);
    write_gpr_at_width(Gpr::Rdx, rem, ty, b, s);
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
        let ext = b.emit(IrOp::Zext, &[val], IrType::I64);
        s.set_gpr(gpr, ext);
    }
}

fn undef_flags(b: &mut IrBuilder, s: &mut LiftState, flags: &[X86Flag]) {
    for &f in flags {
        let v = b.emit(IrOp::Undef, &[], IrType::I8);
        s.set_flag(f, v);
    }
}
