use kamy_core::ir::{IrOp, IrType, ValueId, X86Flag};

use crate::builder::IrBuilder;
use crate::state::LiftState;

pub(crate) fn emit_arith_flags(
    b: &mut IrBuilder,
    s: &mut LiftState,
    result: ValueId,
    a: ValueId,
    b_val: ValueId,
    is_sub: bool,
) {
    let zf = b.emit(IrOp::IsZero, &[result], IrType::I8);
    s.set_flag(X86Flag::Zf, zf);

    let sf = b.emit(IrOp::IsNeg, &[result], IrType::I8);
    s.set_flag(X86Flag::Sf, sf);

    let pf = b.emit(IrOp::Parity, &[result], IrType::I8);
    s.set_flag(X86Flag::Pf, pf);

    if is_sub {
        let cf = b.emit(IrOp::BorrowSub, &[a, b_val], IrType::I8);
        s.set_flag(X86Flag::Cf, cf);

        let of = b.emit(IrOp::OverflowSub, &[a, b_val], IrType::I8);
        s.set_flag(X86Flag::Of, of);

        let af = b.emit(IrOp::AuxBorrowSub, &[a, b_val], IrType::I8);
        s.set_flag(X86Flag::Af, af);
    } else {
        let cf = b.emit(IrOp::CarryAdd, &[a, b_val], IrType::I8);
        s.set_flag(X86Flag::Cf, cf);

        let of = b.emit(IrOp::OverflowAdd, &[a, b_val], IrType::I8);
        s.set_flag(X86Flag::Of, of);

        let af = b.emit(IrOp::AuxCarryAdd, &[a, b_val], IrType::I8);
        s.set_flag(X86Flag::Af, af);
    }
}

pub(crate) fn emit_logic_flags(b: &mut IrBuilder, s: &mut LiftState, result: ValueId) {
    let zero = b.emit(IrOp::Const(0), &[], IrType::I8);
    s.set_flag(X86Flag::Cf, zero);
    s.set_flag(X86Flag::Of, zero);

    let zf = b.emit(IrOp::IsZero, &[result], IrType::I8);
    s.set_flag(X86Flag::Zf, zf);

    let sf = b.emit(IrOp::IsNeg, &[result], IrType::I8);
    s.set_flag(X86Flag::Sf, sf);

    let pf = b.emit(IrOp::Parity, &[result], IrType::I8);
    s.set_flag(X86Flag::Pf, pf);

    let af = b.emit(IrOp::Undef, &[], IrType::I8);
    s.set_flag(X86Flag::Af, af);
}

pub(crate) fn emit_shift_flags(
    b: &mut IrBuilder,
    s: &mut LiftState,
    result: ValueId,
    original: ValueId,
    count: ValueId,
    shift_kind: &IrOp,
) {
    let cf = match shift_kind {
        IrOp::Shl => b.emit(IrOp::CarryShl, &[original, count], IrType::I8),
        IrOp::Shr => b.emit(IrOp::CarryShr, &[original, count], IrType::I8),
        IrOp::Sar => b.emit(IrOp::CarrySar, &[original, count], IrType::I8),
        _ => b.emit(IrOp::Undef, &[], IrType::I8),
    };
    s.set_flag(X86Flag::Cf, cf);

    let zf = b.emit(IrOp::IsZero, &[result], IrType::I8);
    s.set_flag(X86Flag::Zf, zf);

    let sf = b.emit(IrOp::IsNeg, &[result], IrType::I8);
    s.set_flag(X86Flag::Sf, sf);

    let pf = b.emit(IrOp::Parity, &[result], IrType::I8);
    s.set_flag(X86Flag::Pf, pf);

    let of = b.emit(IrOp::Undef, &[], IrType::I8);
    s.set_flag(X86Flag::Of, of);

    let af = b.emit(IrOp::Undef, &[], IrType::I8);
    s.set_flag(X86Flag::Af, af);
}
