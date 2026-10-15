use kamy_core::ir::{Gpr, IrType, ValueId, X86Flag, XmmReg};

use crate::IrOp;
use crate::builder::IrBuilder;

pub(crate) struct LiftState {
    gprs: [ValueId; 16],
    xmms: [ValueId; 16],
    flags: [ValueId; 6],
}

impl LiftState {
    pub(crate) fn new_with_undefs(builder: &mut IrBuilder) -> Self {
        let mut gprs = [ValueId(0); 16];
        let mut xmms = [ValueId(0); 16];
        let mut flags = [ValueId(0); 6];
        for g in &mut gprs {
            *g = builder.emit(IrOp::Undef, &[], IrType::I64);
        }
        for x in &mut xmms {
            *x = builder.emit(IrOp::Undef, &[], IrType::I128);
        }
        for f in &mut flags {
            *f = builder.emit(IrOp::Undef, &[], IrType::I8);
        }
        Self { gprs, xmms, flags }
    }

    pub(crate) fn get_gpr(&self, gpr: Gpr) -> ValueId {
        self.gprs[gpr.index()]
    }

    pub(crate) fn set_gpr(&mut self, gpr: Gpr, val: ValueId) {
        self.gprs[gpr.index()] = val;
    }

    pub(crate) fn get_xmm(&self, xmm: XmmReg) -> ValueId {
        self.xmms[xmm.index()]
    }

    pub(crate) fn set_xmm(&mut self, xmm: XmmReg, val: ValueId) {
        self.xmms[xmm.index()] = val;
    }

    pub(crate) fn get_flag(&self, flag: X86Flag) -> ValueId {
        self.flags[flag.index()]
    }

    pub(crate) fn set_flag(&mut self, flag: X86Flag, val: ValueId) {
        self.flags[flag.index()] = val;
    }

    pub(crate) fn snapshot(&self) -> [ValueId; 38] {
        let mut out = [ValueId(0); 38];
        out[..16].copy_from_slice(&self.gprs);
        out[16..32].copy_from_slice(&self.xmms);
        out[32..38].copy_from_slice(&self.flags);
        out
    }
}
