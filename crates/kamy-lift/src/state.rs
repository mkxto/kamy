use std::collections::{HashMap, HashSet};

use kamy_core::ir::{Gpr, IrType, PhysReg, ValueId, X86Flag, XmmReg};

use crate::IrOp;
use crate::builder::IrBuilder;

pub(crate) struct LiftState<'a> {
    gprs: [ValueId; 16],
    xmms: [ValueId; 16],
    flags: [ValueId; 6],
    pub(crate) rsp_chain: HashSet<ValueId>,
    pub(crate) reg_pins: HashMap<ValueId, PhysReg>,
    pub(crate) unsupported: bool,
    pub(crate) noreturn: bool,
    pub(crate) source: kamy_core::SymbolId,
    pub(crate) source_start: kamy_core::Rva,
    pub(crate) image_base: u64,
    pub(crate) instruction: kamy_core::Rva,
    pub(crate) operand_offsets: [u8; 5],
    pub(crate) operand_biases: [u8; 5],
    pub(crate) references: &'a [kamy_core::OperandReference],
    pub(crate) signature: Option<&'a kamy_core::ir::FnSignature>,
}

impl<'a> LiftState<'a> {
    pub(crate) fn new_with_undefs(builder: &mut IrBuilder, is_entry: bool) -> Self {
        let mut gprs = [ValueId(0); 16];
        let mut xmms = [ValueId(0); 16];
        let mut flags = [ValueId(0); 6];
        let mut rsp_chain = HashSet::new();
        let mut reg_pins = HashMap::new();
        for (i, g) in gprs.iter_mut().enumerate() {
            *g = builder.emit(IrOp::Undef, &[], IrType::I64);
            if i == Gpr::Rsp.index() {
                rsp_chain.insert(*g);
            } else if is_entry {
                // Only function-entry values have physical live-in locations;
                // successor placeholders are replaced by SSA definitions.
                reg_pins.insert(*g, PhysReg::Gpr(Gpr::ALL[i]));
            }
        }
        for (i, x) in xmms.iter_mut().enumerate() {
            *x = builder.emit(IrOp::Undef, &[], IrType::I128);
            if is_entry {
                reg_pins.insert(*x, PhysReg::Xmm(XmmReg::ALL[i]));
            }
        }
        for f in &mut flags {
            *f = builder.emit(IrOp::Undef, &[], IrType::I8);
        }
        Self {
            gprs,
            xmms,
            flags,
            rsp_chain,
            reg_pins,
            unsupported: false,
            noreturn: false,
            source: kamy_core::SymbolId::Host {
                rva: kamy_core::Rva::ZERO,
            },
            source_start: kamy_core::Rva::ZERO,
            image_base: 0,
            instruction: kamy_core::Rva::ZERO,
            operand_offsets: [0; 5],
            operand_biases: [0; 5],
            references: &[],
            signature: None,
        }
    }

    pub(crate) fn operand_reference(&self, operand: u32) -> Option<kamy_core::Reference> {
        self.references
            .iter()
            .find(|reference| {
                reference.instruction == self.instruction && reference.operand == operand
            })
            .map(|reference| reference.reference.clone())
    }

    pub(crate) fn address_reference(
        &self,
        operand: u32,
        target: u64,
        field: kamy_core::LinkField,
    ) -> Option<kamy_core::Reference> {
        if let Some(reference) = self.operand_reference(operand) {
            return Some(reference);
        }
        if self.authored() {
            return None;
        }
        let expression = match target
            .checked_sub(self.image_base)
            .and_then(|offset| u32::try_from(offset).ok())
        {
            Some(offset) => kamy_core::SymbolicExpression::symbol(kamy_core::SymbolId::Host {
                rva: kamy_core::Rva::new(offset),
            }),
            None => kamy_core::SymbolicExpression::Symbol {
                symbol: kamy_core::SymbolId::HostImageBase,
                addend: i64::try_from(i128::from(target) - i128::from(self.image_base)).ok()?,
            },
        };
        Some(kamy_core::Reference {
            source: self.source.clone(),
            offset: self
                .instruction
                .get()
                .checked_sub(self.source_start.get())?
                .checked_add(u32::from(*self.operand_offsets.get(operand as usize)?))?,
            expression,
            field: match field {
                kamy_core::LinkField::Relative32 { .. } => kamy_core::LinkField::Relative32 {
                    bias: *self.operand_biases.get(operand as usize)?,
                },
                other => other,
            },
            origin: kamy_core::ReferenceOrigin::HostAnalysis,
        })
    }

    pub(crate) fn authored(&self) -> bool {
        matches!(self.source, kamy_core::SymbolId::Authored { .. })
    }

    pub(crate) fn get_gpr(&self, gpr: Gpr) -> ValueId {
        self.gprs[gpr.index()]
    }

    pub(crate) fn set_gpr(&mut self, gpr: Gpr, val: ValueId) {
        self.gprs[gpr.index()] = val;
        if gpr == Gpr::Rsp {
            self.rsp_chain.insert(val);
        }
    }

    pub(crate) fn write_gpr(&mut self, gpr: Gpr, val: ValueId, builder: &mut IrBuilder) {
        // Successor placeholders acquire their incoming constraints during SSA;
        // a register move must already have detached the source lifetime.
        let val = if self.get_gpr(gpr) != val && self.gprs.contains(&val) {
            builder.emit(IrOp::Copy, &[val], IrType::I64)
        } else {
            val
        };
        self.set_gpr(gpr, val);
    }

    pub(crate) fn get_xmm(&self, xmm: XmmReg) -> ValueId {
        self.xmms[xmm.index()]
    }

    pub(crate) fn set_xmm(&mut self, xmm: XmmReg, val: ValueId) {
        self.xmms[xmm.index()] = val;
    }

    pub(crate) fn write_xmm(
        &mut self,
        xmm: XmmReg,
        val: ValueId,
        ty: IrType,
        builder: &mut IrBuilder,
    ) {
        let val = if self.get_xmm(xmm) != val && self.xmms.contains(&val) {
            builder.emit(IrOp::Copy, &[val], ty)
        } else {
            val
        };
        self.set_xmm(xmm, val);
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
