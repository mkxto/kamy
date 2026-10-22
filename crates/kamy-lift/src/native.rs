use std::collections::HashMap;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register, RflagsBits,
};
use kamy_core::ir::{FnSignature, Gpr, IrOp, IrType, NativeInst, PhysReg, ValueId, X86Flag};
use kamy_core::{Function, Module, Rva, Terminator};

use crate::builder::IrBuilder;
use crate::state::LiftState;
use crate::{iced_reg_to_gpr, iced_reg_to_xmm};

const ARITH_FLAGS: u32 = RflagsBits::CF
    | RflagsBits::PF
    | RflagsBits::AF
    | RflagsBits::ZF
    | RflagsBits::SF
    | RflagsBits::OF;

fn flag_bit(flag: X86Flag) -> u32 {
    match flag {
        X86Flag::Cf => RflagsBits::CF,
        X86Flag::Pf => RflagsBits::PF,
        X86Flag::Af => RflagsBits::AF,
        X86Flag::Zf => RflagsBits::ZF,
        X86Flag::Sf => RflagsBits::SF,
        X86Flag::Of => RflagsBits::OF,
    }
}

fn must_write_flags(insn: &Instruction) -> u32 {
    // A zero runtime count or zero REP iterations preserves the incoming flags.
    if insn.has_rep_prefix()
        || insn.has_repne_prefix()
        || (matches!(
            insn.mnemonic(),
            Mnemonic::Shl
                | Mnemonic::Shr
                | Mnemonic::Sal
                | Mnemonic::Sar
                | Mnemonic::Shld
                | Mnemonic::Shrd
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Rcl
                | Mnemonic::Rcr
        ) && insn.op_kind(insn.op_count() - 1) == OpKind::Register)
    {
        0
    } else {
        insn.rflags_modified()
    }
}

pub(crate) fn native_flag_liveness(
    module: &Module,
    func: &Function,
    signature: Option<&FnSignature>,
) -> Option<HashMap<Rva, u32>> {
    struct Effect {
        at: Rva,
        reads: u32,
        writes: u32,
    }

    let index: HashMap<_, _> = func
        .blocks
        .iter()
        .enumerate()
        .map(|(i, block)| (block.start, i))
        .collect();
    let mut return_live = !ARITH_FLAGS;
    if let Some(signature) = signature {
        return_live = u32::MAX;
        for clobber in &signature.clobbers {
            if let PhysReg::Flag(flag) = clobber {
                return_live &= !flag_bit(*flag);
            }
        }
        for result in &signature.returns {
            if let Some(PhysReg::Flag(flag)) = result.register_location() {
                return_live |= flag_bit(flag);
            }
        }
    }

    let n = func.blocks.len();
    let mut effects = Vec::with_capacity(n);
    let mut uses = vec![0; n];
    let mut defs = vec![0; n];
    let mut successors = vec![Vec::new(); n];
    let mut exit_live = vec![0; n];
    for (i, block) in func.blocks.iter().enumerate() {
        let len = block.end.get().checked_sub(block.start.get())? as usize;
        let bytes = module.bytes_at(block.start)?.get(..len)?;
        let mut decoder = Decoder::with_ip(
            64,
            bytes,
            module.image_base + u64::from(block.start.get()),
            DecoderOptions::NONE,
        );
        let mut block_effects = Vec::new();
        while decoder.can_decode() {
            let insn = decoder.decode();
            if insn.is_invalid() {
                return None;
            }
            let reads = if matches!(
                insn.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            ) {
                // Decoder flags do not describe a callee's contract.
                u32::MAX
            } else {
                insn.rflags_read()
            };
            let writes = must_write_flags(&insn);
            uses[i] |= reads & !defs[i];
            defs[i] |= writes;
            block_effects.push(Effect {
                at: Rva::new(u32::try_from(insn.ip().checked_sub(module.image_base)?).ok()?),
                reads,
                writes,
            });
        }
        effects.push(block_effects);

        let mut successor = |target: &Rva| {
            if let Some(&target) = index.get(target) {
                if !successors[i].contains(&target) {
                    successors[i].push(target);
                }
            } else {
                exit_live[i] = u32::MAX;
            }
        };
        for target in &block.successors {
            successor(target);
        }
        match &block.terminator {
            Terminator::Jump(target) | Terminator::Fallthrough(target) => successor(target),
            Terminator::Branch { taken, not_taken } => {
                successor(taken);
                successor(not_taken);
            }
            Terminator::Return => exit_live[i] |= return_live,
            Terminator::Indirect { .. } | Terminator::Unknown => exit_live[i] = u32::MAX,
            Terminator::Switch { .. } => {
                if block.successors.is_empty() {
                    exit_live[i] = u32::MAX;
                }
            }
        }
    }

    let mut live_in = vec![0; n];
    loop {
        let mut changed = false;
        for i in (0..n).rev() {
            let out = successors[i]
                .iter()
                .fold(exit_live[i], |live, &next| live | live_in[next]);
            let new = uses[i] | (out & !defs[i]);
            changed |= new != live_in[i];
            live_in[i] = new;
        }
        if !changed {
            break;
        }
    }

    let mut live_after = HashMap::new();
    for (i, block) in effects.iter().enumerate() {
        let mut live = successors[i]
            .iter()
            .fold(exit_live[i], |live, &next| live | live_in[next]);
        for effect in block.iter().rev() {
            live_after.insert(effect.at, live);
            live = effect.reads | (live & !effect.writes);
        }
    }
    Some(live_after)
}

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
    let modified = insn.rflags_modified();
    if modified & !ARITH_FLAGS != 0
        || (modified != 0
            && state
                .native_live_after_flags
                .is_none_or(|live| live & modified != 0))
    {
        // NativeInline has no SSA flag outputs; only proven-dead writes are safe.
        state.unsupported = true;
        return;
    }
    let mut references = Vec::new();
    if insn.is_ip_rel_memory_operand() {
        let operand = (0..insn.op_count()).find(|&op| insn.op_kind(op) == OpKind::Memory);
        let reference = operand.and_then(|op| {
            let reference = state.address_reference(
                op,
                insn.ip_rel_memory_address(),
                kamy_core::LinkField::Relative32 { bias: 0 },
            )?;
            let offset = state
                .instruction
                .get()
                .checked_sub(state.source_start.get())?
                .checked_add(u32::from(state.operand_offsets[op as usize]))?;
            (insn.memory_base() == Register::RIP
                && insn.flow_control() == FlowControl::Next
                && reference.source == state.source
                && reference.offset == offset
                && matches!(reference.field, kamy_core::LinkField::Relative32 { .. }))
            .then_some(kamy_core::OperandReference {
                instruction: state.instruction,
                operand: op,
                reference,
            })
        });
        match reference {
            Some(reference) => references.push(reference),
            None => state.unsupported = true,
        }
    }
    if state.references.iter().any(|reference| {
        reference.instruction == state.instruction && !references.contains(reference)
    }) {
        state.unsupported = true;
    }
    if insn.rflags_read() != 0 {
        // The raw bytes consume an incoming rflags bit (adc/sbb/adcx/adox/rcl/…),
        // a dependency SSA does not thread for a NativeInline: the flag-producing
        // instruction is then DCE'd and the flag the bytes read is garbage
        // (issue #23: bmi1_tzcnt's `cmp rcx,1; adc rcx,0` guard was dropped, so
        // `tzcnt` saw 73 and returned 0). Preserve residency rather than losing
        // the incoming flag dependency (D22).
        state.unsupported = true;
    }
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(insn);

    let mut reads: Vec<PhysReg> = Vec::new();
    let mut writes: Vec<PhysReg> = Vec::new();

    for used in info.used_registers() {
        let expanded = expand_reg(used.register());
        if expanded.is_empty() {
            if matches!(
                used.register(),
                Register::EIP
                    | Register::RIP
                    | Register::CS
                    | Register::DS
                    | Register::ES
                    | Register::FS
                    | Register::GS
                    | Register::SS
            ) && matches!(used.access(), OpAccess::Read | OpAccess::CondRead)
            {
                continue;
            }
            state.unsupported = true;
            return;
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
                if matches!(used.access(), OpAccess::CondWrite | OpAccess::ReadCondWrite)
                    || (used.register().is_gpr() && used.register().size() < 4)
                {
                    push_unique(&mut reads, &expanded);
                }
            }
            _ => {}
        }
    }
    if matches!(insn.mnemonic(), Mnemonic::Movsd | Mnemonic::Movss)
        && insn.op_count() == 2
        && insn.op_kind(0) == OpKind::Register
        && insn.op_kind(1) == OpKind::Register
    {
        // Legacy scalar register moves preserve the destination's upper lanes.
        push_unique(&mut reads, &expand_reg(insn.op_register(0)));
    }
    push_unique(&mut reads, &[PhysReg::Gpr(Gpr::Rsp)]);

    // Constrain the native read, not the incoming definition's entire lifetime.
    let mut read_vals: Vec<ValueId> = Vec::with_capacity(reads.len());
    for r in &reads {
        let v = match r {
            PhysReg::Gpr(g) => state.get_gpr(*g),
            PhysReg::Xmm(x) => state.get_xmm(*x),
            PhysReg::Flag(f) => state.get_flag(*f),
        };
        if *r == PhysReg::Gpr(Gpr::Rsp) {
            read_vals.push(v);
            continue;
        }
        match state.reg_pins.get(&v).copied() {
            Some(p) if p == *r => read_vals.push(v),
            _ => {
                let ty = match r {
                    PhysReg::Xmm(_) => IrType::I128,
                    _ => IrType::I64,
                };
                let copy = builder.emit(IrOp::Copy, &[v], ty);
                state.reg_pins.insert(copy, *r);
                read_vals.push(copy);
            }
        }
    }

    let native = NativeInst {
        bytes: insn_bytes.to_vec(),
        references,
        reads,
        writes: writes.clone(),
    };

    tracing::trace!(mnemonic = ?insn.mnemonic(), "native passthrough");
    builder.emit(IrOp::NativeInline(native), &read_vals, IrType::I64);

    // Distinct output definitions let selection capture writes after the bytes
    // execute, without confusing them with incoming pinned reads.
    for phys in &writes {
        match phys {
            PhysReg::Gpr(Gpr::Rsp) => {}
            PhysReg::Gpr(g) => {
                let v = builder.emit(IrOp::Undef, &[], IrType::I64);
                state.reg_pins.insert(v, *phys);
                state.set_gpr(*g, v);
            }
            PhysReg::Xmm(x) => {
                let v = builder.emit(IrOp::Undef, &[], IrType::I128);
                state.reg_pins.insert(v, *phys);
                state.set_xmm(*x, v);
            }
            PhysReg::Flag(f) => {
                let v = builder.emit(IrOp::Undef, &[], IrType::I8);
                state.reg_pins.insert(v, *phys);
                state.set_flag(*f, v);
            }
        }
    }
}
