use iced_x86::ConditionCode;
use kamy_core::ir::{IrOp, IrType, ValueId, X86Flag};

use crate::builder::IrBuilder;
use crate::state::LiftState;

pub(crate) fn decode_condition(cc: ConditionCode, b: &mut IrBuilder, s: &LiftState) -> ValueId {
    match cc {
        ConditionCode::e => s.get_flag(X86Flag::Zf),
        ConditionCode::ne => {
            let zf = s.get_flag(X86Flag::Zf);
            b.emit(IrOp::BoolNot, &[zf], IrType::I8)
        }
        ConditionCode::b => s.get_flag(X86Flag::Cf),
        ConditionCode::ae => {
            let cf = s.get_flag(X86Flag::Cf);
            b.emit(IrOp::BoolNot, &[cf], IrType::I8)
        }
        ConditionCode::be => {
            let cf = s.get_flag(X86Flag::Cf);
            let zf = s.get_flag(X86Flag::Zf);
            b.emit(IrOp::Or, &[cf, zf], IrType::I8)
        }
        ConditionCode::a => {
            let cf = s.get_flag(X86Flag::Cf);
            let zf = s.get_flag(X86Flag::Zf);
            let or = b.emit(IrOp::Or, &[cf, zf], IrType::I8);
            b.emit(IrOp::BoolNot, &[or], IrType::I8)
        }
        ConditionCode::s => s.get_flag(X86Flag::Sf),
        ConditionCode::ns => {
            let sf = s.get_flag(X86Flag::Sf);
            b.emit(IrOp::BoolNot, &[sf], IrType::I8)
        }
        ConditionCode::o => s.get_flag(X86Flag::Of),
        ConditionCode::no => {
            let of = s.get_flag(X86Flag::Of);
            b.emit(IrOp::BoolNot, &[of], IrType::I8)
        }
        ConditionCode::l => {
            let sf = s.get_flag(X86Flag::Sf);
            let of = s.get_flag(X86Flag::Of);
            b.emit(IrOp::Xor, &[sf, of], IrType::I8)
        }
        ConditionCode::ge => {
            let sf = s.get_flag(X86Flag::Sf);
            let of = s.get_flag(X86Flag::Of);
            let xor = b.emit(IrOp::Xor, &[sf, of], IrType::I8);
            b.emit(IrOp::BoolNot, &[xor], IrType::I8)
        }
        ConditionCode::le => {
            let zf = s.get_flag(X86Flag::Zf);
            let sf = s.get_flag(X86Flag::Sf);
            let of = s.get_flag(X86Flag::Of);
            let xor = b.emit(IrOp::Xor, &[sf, of], IrType::I8);
            b.emit(IrOp::Or, &[zf, xor], IrType::I8)
        }
        ConditionCode::g => {
            let zf = s.get_flag(X86Flag::Zf);
            let sf = s.get_flag(X86Flag::Sf);
            let of = s.get_flag(X86Flag::Of);
            let xor = b.emit(IrOp::Xor, &[sf, of], IrType::I8);
            let or = b.emit(IrOp::Or, &[zf, xor], IrType::I8);
            b.emit(IrOp::BoolNot, &[or], IrType::I8)
        }
        ConditionCode::p => s.get_flag(X86Flag::Pf),
        ConditionCode::np => {
            let pf = s.get_flag(X86Flag::Pf);
            b.emit(IrOp::BoolNot, &[pf], IrType::I8)
        }
        _ => b.emit(IrOp::Undef, &[], IrType::I8),
    }
}
