//! x86 to SSA IR lifter and instruction semantics.

mod arith;
mod builder;
mod cond;
mod control;
mod flags;
mod native;
pub mod ssa;
mod state;
pub use ssa::construct_ssa;

use std::collections::HashMap;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, MemorySize, Mnemonic, OpKind, Register,
};
use kamy_core::ir::*;
use kamy_core::{Function, Module, Terminator};

use builder::IrBuilder;
use state::LiftState;

pub struct LiftResult {
    pub func: IrFunction,
    pub block_entry: Vec<[ValueId; 38]>,
    pub block_exit: Vec<[ValueId; 38]>,
    pub rsp_chain: std::collections::HashSet<ValueId>,
    pub reg_pins: std::collections::HashMap<ValueId, kamy_core::ir::PhysReg>,
    pub unsupported: bool,
}

pub fn lift_function(
    module: &Module,
    func: &Function,
    cc: &dyn CallingConvLookup,
    references: &[kamy_core::OperandReference],
) -> LiftResult {
    let entry_rva = func.entry;
    let source = module
        .symbols
        .iter()
        .find(|symbol| symbol.rva == entry_rva && symbol.kind == kamy_core::SymbolKind::Function)
        .map(|symbol| symbol.id.clone())
        .unwrap_or(kamy_core::SymbolId::Host { rva: entry_rva });
    let signature = cc.lookup_symbol(&source);
    let native_flag_liveness = native::native_flag_liveness(module, func, signature.as_ref());
    let _s = tracing::debug_span!("lift", rva = %entry_rva).entered();

    let mut ordered_bbs: Vec<&kamy_core::BasicBlock> = Vec::with_capacity(func.blocks.len());
    let mut rest: Vec<&kamy_core::BasicBlock> = Vec::new();
    for bb in &func.blocks {
        if bb.start == entry_rva {
            ordered_bbs.push(bb);
        } else {
            rest.push(bb);
        }
    }
    rest.sort_by_key(|bb| bb.start.get());
    ordered_bbs.extend(rest);

    let mut rva_to_block: HashMap<u32, BlockId> = HashMap::new();
    for (i, bb) in ordered_bbs.iter().enumerate() {
        rva_to_block.insert(bb.start.get(), BlockId(i as u32));
    }

    let mut ir_func = IrFunction {
        entry: BlockId(0),
        blocks: Vec::with_capacity(ordered_bbs.len()),
        next_value: 0,
    };
    for (i, _) in ordered_bbs.iter().enumerate() {
        ir_func.blocks.push(IrBlock {
            id: BlockId(i as u32),
            phis: Vec::new(),
            insts: Vec::new(),
            term: IrTerminator::Unreachable,
        });
    }
    let n = ordered_bbs.len();
    let mut block_entry = Vec::with_capacity(n);
    let mut block_exit = Vec::with_capacity(n);
    let mut rsp_chain = std::collections::HashSet::new();
    let mut reg_pins: std::collections::HashMap<ValueId, kamy_core::ir::PhysReg> =
        std::collections::HashMap::new();
    let mut unsupported = false;
    // Rung blocks synthesized for recovered switch dispatches are appended after
    // the CFG blocks; their pass-through SSA snapshots are collected here and
    // pushed after the main loop so block_entry/block_exit stay index-aligned
    // with block ids.
    let mut ladder_entries: Vec<[ValueId; 38]> = Vec::new();

    let mut builder = IrBuilder::new(&mut ir_func, BlockId(0));

    for (i, bb) in ordered_bbs.iter().enumerate() {
        let block_id = BlockId(i as u32);
        builder.switch_to(block_id);
        let mut lift_state = LiftState::new_with_undefs(&mut builder, i == 0);
        lift_state.source = source.clone();
        lift_state.source_start = entry_rva;
        lift_state.image_base = module.image_base;
        lift_state.references = references;
        lift_state.symbols = &module.symbols;
        lift_state.signature = signature.as_ref();
        if lift_state.authored() && lift_state.signature.is_none() {
            lift_state.unsupported = true;
        }
        block_entry.push(lift_state.snapshot());

        let len = bb.end.get().saturating_sub(bb.start.get()) as usize;
        let bytes = match module.bytes_at(bb.start) {
            Some(b) => &b[..len.min(b.len())],
            None => &[],
        };
        let ip = module.image_base + u64::from(bb.start.get());
        let switch_table = match &bb.terminator {
            Terminator::Switch { table } => Some(table.clone()),
            _ => None,
        };
        let mut switch_index: Option<ValueId> = None;

        let mut last_cond: Option<ValueId> = None;
        let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        while decoder.can_decode() {
            let start_pos = decoder.position();
            let insn = decoder.decode();
            lift_state.instruction = kamy_core::Rva::new((insn.ip() - module.image_base) as u32);
            lift_state.native_live_after_flags = native_flag_liveness
                .as_ref()
                .and_then(|live| live.get(&lift_state.instruction))
                .copied();
            let constants = decoder.get_constant_offsets(&insn);
            for operand in 0..insn.op_count() {
                let (offset, size) = if insn.op_kind(operand) == OpKind::Memory {
                    (
                        constants.displacement_offset(),
                        constants.displacement_size(),
                    )
                } else {
                    (constants.immediate_offset(), constants.immediate_size())
                };
                lift_state.operand_offsets[operand as usize] = offset as u8;
                lift_state.operand_biases[operand as usize] =
                    insn.len().saturating_sub(offset + size) as u8;
            }
            if insn.is_ip_rel_memory_operand()
                && !(0..insn.op_count()).any(|operand| {
                    insn.op_kind(operand) == OpKind::Memory
                        && lift_state
                            .address_reference(
                                operand,
                                insn.ip_rel_memory_address(),
                                kamy_core::LinkField::Relative32 { bias: 0 },
                            )
                            .is_some()
                })
            {
                lift_state.unsupported = true;
            }
            if insn.is_invalid() {
                break;
            }
            // A recovered switch dispatch lowers to a compare ladder, not a table
            // load + indirect jmp. Capture the index before the table-load (which
            // may reuse the index register) and stop; the terminator emits the
            // ladder.
            if let Some(tbl) = &switch_table {
                if insn.ip() == module.image_base + u64::from(tbl.dispatch_rva.get()) {
                    switch_index = Some(lift_state.get_gpr(tbl.index_reg));
                    break;
                }
            }
            let end_pos = decoder.position();
            let insn_bytes = &bytes[start_pos..end_pos];
            last_cond = dispatch(&insn, insn_bytes, &mut builder, &mut lift_state, cc);
            if lift_state.noreturn {
                break;
            }
        }

        if lift_state.noreturn {
            builder.set_terminator(IrTerminator::NoReturn);
        } else {
            match &bb.terminator {
                Terminator::Return => {
                    builder.set_terminator(IrTerminator::Ret);
                }
                Terminator::Jump(target) => {
                    if let Some(&bid) = rva_to_block.get(&target.get()) {
                        builder.set_terminator(IrTerminator::Jump(bid));
                    } else {
                        let target_va = module.image_base + u64::from(target.get());
                        control::lift_tail_call(target_va, &mut builder, &mut lift_state, cc);
                        match lift_state.address_reference(
                            0,
                            target_va,
                            kamy_core::LinkField::Relative32 { bias: 0 },
                        ) {
                            Some(reference) => {
                                builder.set_terminator(IrTerminator::Tail { target: reference })
                            }
                            None => {
                                lift_state.unsupported = true;
                                builder.set_terminator(IrTerminator::Unreachable);
                            }
                        }
                    }
                }
                Terminator::Branch { taken, not_taken } => {
                    let cond =
                        last_cond.unwrap_or_else(|| builder.emit(IrOp::Undef, &[], IrType::I8));
                    match (
                        rva_to_block.get(&taken.get()),
                        rva_to_block.get(&not_taken.get()),
                    ) {
                        (Some(&t), Some(&nt)) => {
                            builder.set_terminator(IrTerminator::Branch {
                                cond,
                                taken: t,
                                not_taken: nt,
                            });
                        }
                        _ => builder.set_terminator(IrTerminator::Unreachable),
                    }
                }
                Terminator::Fallthrough(target) => {
                    if let Some(&bid) = rva_to_block.get(&target.get()) {
                        builder.set_terminator(IrTerminator::Jump(bid));
                    } else {
                        builder.set_terminator(IrTerminator::Unreachable);
                    }
                }
                Terminator::Switch { table } => {
                    let exit_snap = lift_state.snapshot();
                    let built = switch_index.is_some_and(|idx| {
                        build_switch_ladder(
                            &mut builder,
                            block_id,
                            idx,
                            &table.entries,
                            &rva_to_block,
                            &exit_snap,
                            &mut ladder_entries,
                        )
                    });
                    if !built {
                        builder.set_terminator(IrTerminator::Unreachable);
                    }
                }
                Terminator::Indirect { .. } | Terminator::Unknown => {
                    builder.set_terminator(IrTerminator::Unreachable);
                }
            }
        }
        block_exit.push(lift_state.snapshot());
        rsp_chain.extend(&lift_state.rsp_chain);
        reg_pins.extend(&lift_state.reg_pins);
        unsupported |= lift_state.unsupported;
    }
    for snap in &ladder_entries {
        block_entry.push(*snap);
        block_exit.push(*snap);
    }
    if ir_func
        .blocks
        .iter()
        .any(|b| matches!(b.term, IrTerminator::Unreachable))
    {
        // An unresolved terminator cannot be represented by the lifted CFG.
        tracing::warn!(rva = %entry_rva, "unresolved terminator; lifting unsupported");
        unsupported = true;
    }

    LiftResult {
        func: ir_func,
        block_entry,
        block_exit,
        rsp_chain,
        reg_pins,
        unsupported,
    }
}

/// Lower a recovered switch dispatch to a tableless compare ladder: each rung
/// tests `index == k`, falling through (the *not-taken* edge) to `entries[k]`
/// and continuing on the *taken* edge (`index != k`) to the next rung; the final
/// rung's taken edge is `entries[last]` (the preceding bound check guarantees the
/// index is in range, so no table survives). Making the next rung the taken edge
/// keeps the rungs contiguous in the allocator's DFS block order, so the index's
/// live range stays tight (it does not span the case blocks). Fresh rung blocks
/// are appended; their pass-through snapshots go to `ladder_entries`. Returns
/// false (reject) when a case target has no block.
fn build_switch_ladder(
    builder: &mut IrBuilder,
    dispatch: BlockId,
    idx: ValueId,
    entries: &[kamy_core::Rva],
    rva_to_block: &HashMap<u32, BlockId>,
    exit_snap: &[ValueId; 38],
    ladder_entries: &mut Vec<[ValueId; 38]>,
) -> bool {
    let targets = entries
        .iter()
        .map(|r| rva_to_block.get(&r.get()).copied())
        .collect::<Option<Vec<BlockId>>>();
    let Some(targets) = targets else {
        return false;
    };
    let n = targets.len();
    if n == 0 {
        return false;
    }
    if n == 1 {
        builder.switch_to(dispatch);
        builder.set_terminator(IrTerminator::Jump(targets[0]));
        return true;
    }
    let mut cur = dispatch;
    for (k, &case) in targets.iter().enumerate().take(n - 1) {
        builder.switch_to(cur);
        let kval = builder.emit(IrOp::Const(k as u64), &[], IrType::I64);
        let diff = builder.emit(IrOp::Sub, &[idx, kval], IrType::I64);
        let eq = builder.emit(IrOp::IsZero, &[diff], IrType::I8);
        let ne = builder.emit(IrOp::BoolNot, &[eq], IrType::I8);
        let next = if k + 1 < n - 1 {
            let nb = builder.new_block();
            ladder_entries.push(*exit_snap);
            nb
        } else {
            targets[n - 1]
        };
        builder.set_terminator(IrTerminator::Branch {
            cond: ne,
            taken: next,
            not_taken: case,
        });
        cur = next;
    }
    true
}

fn dispatch(
    insn: &Instruction,
    insn_bytes: &[u8],
    builder: &mut IrBuilder,
    state: &mut LiftState,
    cc: &dyn CallingConvLookup,
) -> Option<ValueId> {
    // FS/GS-relative accesses (TEB/PEB, stack cookie, TLS) have a nonzero
    // segment base the flat-address SSA cannot model; lowering them as plain
    // `[disp]` reads near-null. Reject the function instead (D22). DS/SS/ES/CS
    // are flat in long mode, so only FS/GS matter.
    if matches!(insn.segment_prefix(), Register::FS | Register::GS) {
        state.unsupported = true;
        return None;
    }
    // CL-based selection has no modeled save/restore slot.
    if matches!(
        insn.mnemonic(),
        Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Rol
            | Mnemonic::Ror
    ) && insn.op_count() > 1
        && (!is_immediate(insn.op_kind(1))
            || get_immediate(insn, 1) >= u64::from(infer_operand_width(insn).bits()))
        && state
            .signature
            .is_some_and(|signature| !signature.clobbers.contains(&PhysReg::Gpr(Gpr::Rcx)))
    {
        state.unsupported = true;
        return None;
    }
    match insn.flow_control() {
        FlowControl::Return => {
            control::lift_ret(builder, state);
            return None;
        }
        FlowControl::Call | FlowControl::IndirectCall => {
            if insn.op_kind(0) == OpKind::NearBranch64 {
                control::lift_call(insn, insn.near_branch_target(), builder, state, cc);
            } else {
                let mut slot_va = None;
                let target_val = match insn.op_kind(0) {
                    OpKind::Register => {
                        iced_reg_to_gpr(insn.op_register(0)).map(|g| state.get_gpr(g))
                    }
                    OpKind::Memory => {
                        // A `call [rip+disp]` / `call [abs]` with no index names a
                        // fixed pointer slot; iced folds RIP-relative displacement
                        // into the absolute slot VA, matching the import-slot keys
                        // in the calling-convention map.
                        if insn.memory_index() == Register::None
                            && matches!(insn.memory_base(), Register::RIP | Register::None)
                        {
                            slot_va = Some(insn.memory_displacement64());
                        }
                        let addr = compute_mem_addr(insn, builder, state);
                        Some(builder.emit(IrOp::Load, &[addr], IrType::I64))
                    }
                    _ => None,
                };
                match target_val {
                    Some(t) => control::lift_call_indirect(t, slot_va, builder, state, cc),
                    None => {
                        tracing::warn!(
                            ip = %insn.ip(),
                            mnemonic = ?insn.mnemonic(),
                            "indirect call target cannot be lifted"
                        );
                        state.unsupported = true;
                    }
                }
            }
            return None;
        }
        FlowControl::ConditionalBranch => {
            return Some(cond::decode_condition(
                insn.condition_code(),
                builder,
                state,
            ));
        }
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
            return None;
        }
        _ => {}
    }

    match insn.mnemonic() {
        Mnemonic::Add => arith::lift_add(insn, builder, state),
        Mnemonic::Sub => arith::lift_sub(insn, builder, state),
        Mnemonic::Cmp => arith::lift_cmp(insn, builder, state),
        Mnemonic::Inc => arith::lift_inc(insn, builder, state),
        Mnemonic::Dec => arith::lift_dec(insn, builder, state),
        Mnemonic::Neg => arith::lift_neg(insn, builder, state),
        Mnemonic::And => arith::lift_and(insn, builder, state),
        Mnemonic::Or => arith::lift_or(insn, builder, state),
        Mnemonic::Xor => arith::lift_xor(insn, builder, state),
        Mnemonic::Test => arith::lift_test(insn, builder, state),
        Mnemonic::Not => arith::lift_not(insn, builder, state),
        Mnemonic::Shl | Mnemonic::Sal => arith::lift_shl(insn, builder, state),
        Mnemonic::Shr => arith::lift_shr(insn, builder, state),
        Mnemonic::Sar => arith::lift_sar(insn, builder, state),
        Mnemonic::Rol => arith::lift_rol(insn, builder, state),
        Mnemonic::Ror => arith::lift_ror(insn, builder, state),
        Mnemonic::Mul => arith::lift_mul(insn, builder, state),
        Mnemonic::Imul => arith::lift_imul(insn, builder, state),
        Mnemonic::Div => arith::lift_div(insn, builder, state),
        Mnemonic::Idiv => arith::lift_idiv(insn, builder, state),
        Mnemonic::Mov => arith::lift_mov(insn, builder, state),
        Mnemonic::Lea => arith::lift_lea(insn, builder, state),
        Mnemonic::Movzx => arith::lift_movzx(insn, builder, state),
        Mnemonic::Movsx | Mnemonic::Movsxd => arith::lift_movsx(insn, builder, state),
        Mnemonic::Cdq => arith::lift_cdq(builder, state),
        Mnemonic::Cqo => arith::lift_cqo(builder, state),
        Mnemonic::Cdqe => arith::lift_cdqe(builder, state),
        Mnemonic::Xchg => arith::lift_xchg(insn, builder, state),
        Mnemonic::Bswap => arith::lift_bswap(insn, builder, state),
        Mnemonic::Bsf => arith::lift_bsf(insn, builder, state),
        Mnemonic::Bsr => arith::lift_bsr(insn, builder, state),
        Mnemonic::Popcnt => arith::lift_popcnt(insn, builder, state),
        Mnemonic::Lzcnt => arith::lift_lzcnt(insn, builder, state),
        Mnemonic::Tzcnt => arith::lift_tzcnt(insn, builder, state),

        Mnemonic::Push => control::lift_push(insn, builder, state),
        Mnemonic::Pop => control::lift_pop(insn, builder, state),

        Mnemonic::Cmova
        | Mnemonic::Cmovae
        | Mnemonic::Cmovb
        | Mnemonic::Cmovbe
        | Mnemonic::Cmove
        | Mnemonic::Cmovg
        | Mnemonic::Cmovge
        | Mnemonic::Cmovl
        | Mnemonic::Cmovle
        | Mnemonic::Cmovne
        | Mnemonic::Cmovno
        | Mnemonic::Cmovnp
        | Mnemonic::Cmovns
        | Mnemonic::Cmovo
        | Mnemonic::Cmovp
        | Mnemonic::Cmovs => control::lift_cmovcc(insn, builder, state),

        Mnemonic::Seta
        | Mnemonic::Setae
        | Mnemonic::Setb
        | Mnemonic::Setbe
        | Mnemonic::Sete
        | Mnemonic::Setg
        | Mnemonic::Setge
        | Mnemonic::Setl
        | Mnemonic::Setle
        | Mnemonic::Setne
        | Mnemonic::Setno
        | Mnemonic::Setnp
        | Mnemonic::Setns
        | Mnemonic::Seto
        | Mnemonic::Setp
        | Mnemonic::Sets => control::lift_setcc(insn, builder, state),

        Mnemonic::Nop | Mnemonic::Int3 => {}

        Mnemonic::Movaps | Mnemonic::Movups => control::lift_movaps(insn, builder, state),
        Mnemonic::Movsd | Mnemonic::Movss
            if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Register =>
        {
            native::native_inline_fallback(insn, insn_bytes, builder, state);
        }
        Mnemonic::Movsd => control::lift_movsd(insn, builder, state),
        Mnemonic::Movss => control::lift_movss(insn, builder, state),
        Mnemonic::Xorps => control::lift_xorps(insn, builder, state),

        _ => native::native_inline_fallback(insn, insn_bytes, builder, state),
    }

    None
}

// ── shared helpers (pub(crate)) ─────────────────────────────────────────────

pub(crate) fn iced_reg_to_gpr(reg: Register) -> Option<Gpr> {
    match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => {
            Some(Gpr::Rax)
        }
        Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => {
            Some(Gpr::Rcx)
        }
        Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => {
            Some(Gpr::Rdx)
        }
        Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => {
            Some(Gpr::Rbx)
        }
        Register::RSP | Register::ESP | Register::SP | Register::SPL => Some(Gpr::Rsp),
        Register::RBP | Register::EBP | Register::BP | Register::BPL => Some(Gpr::Rbp),
        Register::RSI | Register::ESI | Register::SI | Register::SIL => Some(Gpr::Rsi),
        Register::RDI | Register::EDI | Register::DI | Register::DIL => Some(Gpr::Rdi),
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => Some(Gpr::R8),
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => Some(Gpr::R9),
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Some(Gpr::R10),
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Some(Gpr::R11),
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Some(Gpr::R12),
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Some(Gpr::R13),
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Some(Gpr::R14),
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Some(Gpr::R15),
        _ => None,
    }
}

pub(crate) fn iced_reg_to_xmm(reg: Register) -> Option<XmmReg> {
    match reg {
        Register::XMM0 => Some(XmmReg::Xmm0),
        Register::XMM1 => Some(XmmReg::Xmm1),
        Register::XMM2 => Some(XmmReg::Xmm2),
        Register::XMM3 => Some(XmmReg::Xmm3),
        Register::XMM4 => Some(XmmReg::Xmm4),
        Register::XMM5 => Some(XmmReg::Xmm5),
        Register::XMM6 => Some(XmmReg::Xmm6),
        Register::XMM7 => Some(XmmReg::Xmm7),
        Register::XMM8 => Some(XmmReg::Xmm8),
        Register::XMM9 => Some(XmmReg::Xmm9),
        Register::XMM10 => Some(XmmReg::Xmm10),
        Register::XMM11 => Some(XmmReg::Xmm11),
        Register::XMM12 => Some(XmmReg::Xmm12),
        Register::XMM13 => Some(XmmReg::Xmm13),
        Register::XMM14 => Some(XmmReg::Xmm14),
        Register::XMM15 => Some(XmmReg::Xmm15),
        _ => None,
    }
}

pub(crate) fn gpr_reg_type(reg: Register) -> IrType {
    match reg {
        Register::AL
        | Register::CL
        | Register::DL
        | Register::BL
        | Register::AH
        | Register::CH
        | Register::DH
        | Register::BH
        | Register::SPL
        | Register::BPL
        | Register::SIL
        | Register::DIL
        | Register::R8L
        | Register::R9L
        | Register::R10L
        | Register::R11L
        | Register::R12L
        | Register::R13L
        | Register::R14L
        | Register::R15L => IrType::I8,

        Register::AX
        | Register::CX
        | Register::DX
        | Register::BX
        | Register::SP
        | Register::BP
        | Register::SI
        | Register::DI
        | Register::R8W
        | Register::R9W
        | Register::R10W
        | Register::R11W
        | Register::R12W
        | Register::R13W
        | Register::R14W
        | Register::R15W => IrType::I16,

        Register::EAX
        | Register::ECX
        | Register::EDX
        | Register::EBX
        | Register::ESP
        | Register::EBP
        | Register::ESI
        | Register::EDI
        | Register::R8D
        | Register::R9D
        | Register::R10D
        | Register::R11D
        | Register::R12D
        | Register::R13D
        | Register::R14D
        | Register::R15D => IrType::I32,

        _ => IrType::I64,
    }
}

pub(crate) fn compute_mem_addr(insn: &Instruction, b: &mut IrBuilder, s: &LiftState) -> ValueId {
    let base_reg = insn.memory_base();

    if base_reg == Register::RIP {
        return b.emit(
            s.address_reference(
                (0..insn.op_count())
                    .find(|&operand| insn.op_kind(operand) == OpKind::Memory)
                    .unwrap_or(0),
                insn.memory_displacement64(),
                kamy_core::LinkField::Relative32 { bias: 0 },
            )
            .map_or(IrOp::Undef, IrOp::Address),
            &[],
            IrType::I64,
        );
    }

    let index_reg = insn.memory_index();
    let scale = insn.memory_index_scale();
    let disp = insn.memory_displacement64();

    let mut addr: Option<ValueId> = None;

    if base_reg != Register::None {
        if let Some(gpr) = iced_reg_to_gpr(base_reg) {
            addr = Some(s.get_gpr(gpr));
        }
    }

    if index_reg != Register::None {
        if let Some(gpr) = iced_reg_to_gpr(index_reg) {
            let mut idx = s.get_gpr(gpr);
            if scale > 1 {
                let shift_amt = scale.trailing_zeros();
                let shift_c = b.emit(IrOp::Const(u64::from(shift_amt)), &[], IrType::I64);
                idx = b.emit(IrOp::Shl, &[idx, shift_c], IrType::I64);
            }
            addr = Some(match addr {
                Some(base) => b.emit(IrOp::Add, &[base, idx], IrType::I64),
                None => idx,
            });
        }
    }

    let displacement_reference = (0..insn.op_count())
        .find(|&operand| insn.op_kind(operand) == OpKind::Memory)
        .and_then(|operand| s.operand_reference(operand));
    if disp != 0 || addr.is_none() || displacement_reference.is_some() {
        let disp_val = match displacement_reference {
            Some(reference) => b.emit(IrOp::Address(reference), &[], IrType::I64),
            None => b.emit(IrOp::Const(disp), &[], IrType::I64),
        };
        addr = Some(match addr {
            Some(base) => b.emit(IrOp::Add, &[base, disp_val], IrType::I64),
            None => disp_val,
        });
    }

    addr.unwrap_or_else(|| b.emit(IrOp::Const(0), &[], IrType::I64))
}

pub(crate) fn get_immediate(insn: &Instruction, op: u32) -> u64 {
    match insn.op_kind(op) {
        OpKind::Immediate8 => u64::from(insn.immediate8()),
        OpKind::Immediate8_2nd => u64::from(insn.immediate8_2nd()),
        OpKind::Immediate16 => u64::from(insn.immediate16()),
        OpKind::Immediate32 => u64::from(insn.immediate32()),
        OpKind::Immediate64 => insn.immediate64(),
        OpKind::Immediate8to16 => insn.immediate8to16() as u16 as u64,
        OpKind::Immediate8to32 => insn.immediate8to32() as u32 as u64,
        OpKind::Immediate8to64 => insn.immediate8to64() as u64,
        OpKind::Immediate32to64 => insn.immediate32to64() as u64,
        _ => 0,
    }
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn infer_operand_width(insn: &Instruction) -> IrType {
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Register {
            let reg = insn.op_register(i);
            if iced_reg_to_gpr(reg).is_some() {
                return gpr_reg_type(reg);
            }
            if iced_reg_to_xmm(reg).is_some() {
                return IrType::I128;
            }
        }
    }
    mem_operand_type(insn)
}

fn mem_operand_type(insn: &Instruction) -> IrType {
    match insn.memory_size() {
        MemorySize::UInt8 | MemorySize::Int8 => IrType::I8,
        MemorySize::UInt16 | MemorySize::Int16 => IrType::I16,
        MemorySize::UInt32 | MemorySize::Int32 | MemorySize::Float32 => IrType::I32,
        MemorySize::UInt64 | MemorySize::Int64 | MemorySize::Float64 | MemorySize::QwordOffset => {
            IrType::I64
        }
        MemorySize::UInt128
        | MemorySize::Int128
        | MemorySize::Packed128_Float32
        | MemorySize::Packed128_Float64 => IrType::I128,
        _ => IrType::I64,
    }
}

pub(crate) fn read_operand(
    insn: &Instruction,
    op: u32,
    builder: &mut IrBuilder,
    state: &LiftState,
) -> (ValueId, IrType) {
    match insn.op_kind(op) {
        OpKind::Register => {
            let reg = insn.op_register(op);
            if let Some(xmm) = iced_reg_to_xmm(reg) {
                return (state.get_xmm(xmm), IrType::I128);
            }
            if let Some(gpr) = iced_reg_to_gpr(reg) {
                let val = state.get_gpr(gpr);
                let ty = gpr_reg_type(reg);
                if ty == IrType::I64 {
                    return (val, ty);
                }
                let val = if matches!(
                    reg,
                    Register::AH | Register::CH | Register::DH | Register::BH
                ) {
                    let eight = builder.emit(IrOp::Const(8), &[], IrType::I64);
                    builder.emit(IrOp::Shr, &[val, eight], IrType::I64)
                } else {
                    val
                };
                return (builder.emit(IrOp::Trunc, &[val], ty), ty);
            }
            (builder.emit(IrOp::Undef, &[], IrType::I64), IrType::I64)
        }
        OpKind::Memory => {
            let addr = compute_mem_addr(insn, builder, state);
            let ty = mem_operand_type(insn);
            (builder.emit(IrOp::Load, &[addr], ty), ty)
        }
        kind if is_immediate(kind) => {
            let imm = get_immediate(insn, op);
            let ty = infer_operand_width(insn);
            let value = match state.operand_reference(op) {
                Some(reference) => builder.emit(IrOp::Address(reference), &[], ty),
                None => builder.emit(IrOp::Const(imm), &[], ty),
            };
            (value, ty)
        }
        _ => (builder.emit(IrOp::Undef, &[], IrType::I64), IrType::I64),
    }
}

pub(crate) fn write_operand(
    insn: &Instruction,
    op: u32,
    val: ValueId,
    ty: IrType,
    builder: &mut IrBuilder,
    state: &mut LiftState,
) {
    match insn.op_kind(op) {
        OpKind::Register => {
            let reg = insn.op_register(op);
            if let Some(xmm) = iced_reg_to_xmm(reg) {
                state.write_xmm(xmm, val, ty, builder);
                return;
            }
            if let Some(gpr) = iced_reg_to_gpr(reg) {
                if ty == IrType::I64 {
                    state.write_gpr(gpr, val, builder);
                } else {
                    write_gpr_sub64(gpr, val, ty, builder, state);
                }
            }
        }
        OpKind::Memory => {
            let addr = compute_mem_addr(insn, builder, state);
            builder.emit_void(IrOp::Store, &[addr, val], ty);
        }
        _ => {}
    }
}

/// Store `val` (of sub-64-bit width `ty`) into physical GPR `gpr` honoring x86
/// partial-register semantics: a 32-bit write clears bits 63:32, but an 8- or
/// 16-bit write leaves the register's upper bits intact. Modeling the narrow
/// write as a plain zero-extension would silently drop those high bytes.
pub(crate) fn write_gpr_sub64(
    gpr: Gpr,
    val: ValueId,
    ty: IrType,
    builder: &mut IrBuilder,
    state: &mut LiftState,
) {
    let stored = if ty == IrType::I32 {
        builder.emit(IrOp::Zext, &[val], IrType::I64)
    } else {
        let old = state.get_gpr(gpr);
        let keep = !((1u64 << ty.bits()) - 1);
        let mask = builder.emit(IrOp::Const(keep), &[], IrType::I64);
        let hi = builder.emit(IrOp::And, &[old, mask], IrType::I64);
        let lo = builder.emit(IrOp::Zext, &[val], IrType::I64);
        builder.emit(IrOp::Or, &[hi, lo], IrType::I64)
    };
    state.set_gpr(gpr, stored);
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::{BasicBlock, Machine, Rva, Section, SectionFlags};

    const BASE: u64 = 0x1_4000_0000;
    const TEXT_RVA: u32 = 0x1000;

    fn single_block_module(code: &[u8], term: Terminator) -> (Module, Function) {
        let rva = Rva::new(TEXT_RVA);
        let section = Section {
            name: ".text".to_string(),
            rva,
            virtual_size: code.len() as u32,
            data: code.to_vec(),
            flags: SectionFlags {
                read: true,
                write: false,
                execute: true,
            },
        };
        let bb = BasicBlock {
            start: rva,
            end: rva.checked_add(code.len() as u32).unwrap(),
            successors: vec![],
            terminator: term,
        };
        let func = Function {
            entry: rva,
            blocks: vec![bb],
        };
        let module = Module {
            image_base: BASE,
            machine: Machine::X64,
            entry_point: Some(rva),
            sections: vec![section],
            symbols: vec![],
            relocations: vec![],
            functions: vec![func.clone()],
        };
        (module, func)
    }

    #[test]
    fn host_rip_reference_keeps_actual_field_offset_and_trailing_immediate_bias() {
        let (module, func) =
            single_block_module(&[0x83, 0x3d, 0xf9, 0x0f, 0, 0, 1, 0xc3], Terminator::Return);
        let lifted = lift_function(&module, &func, &Win64Default, &[]);
        assert!(!lifted.unsupported);
        let reference = lifted.func.blocks[0]
            .insts
            .iter()
            .find_map(|inst| {
                if let IrOp::Address(reference) = &inst.op {
                    Some(reference)
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(
            reference.source,
            kamy_core::SymbolId::Host { rva: func.entry }
        );
        assert_eq!(reference.offset, 2);
        assert_eq!(
            reference.field,
            kamy_core::LinkField::Relative32 { bias: 1 }
        );
        assert_eq!(reference.origin, kamy_core::ReferenceOrigin::HostAnalysis);
        assert_eq!(
            reference.expression,
            kamy_core::SymbolicExpression::symbol(kamy_core::SymbolId::Host {
                rva: Rva::new(0x2000)
            })
        );
        let mut encoded = [0u8; 4];
        reference
            .field
            .encode_into(
                i128::from(BASE + 0x2000),
                BASE + u64::from(TEXT_RVA) + u64::from(reference.offset),
                BASE,
                &mut encoded,
            )
            .unwrap();
        assert_eq!(i32::from_le_bytes(encoded), 0xff9);
    }

    struct AuthoredCc(HashMap<kamy_core::SymbolId, FnSignature>);

    impl CallingConvLookup for AuthoredCc {
        fn lookup(&self, _: u64) -> Option<FnSignature> {
            None
        }
        fn lookup_symbol(&self, symbol: &kamy_core::SymbolId) -> Option<FnSignature> {
            self.0.get(symbol).cloned()
        }
    }

    fn authored_symbol(module: &str, name: &str) -> kamy_core::SymbolId {
        kamy_core::SymbolId::Authored {
            module: module.into(),
            symbol: name.into(),
        }
    }

    fn mark_authored(module: &mut Module, source: kamy_core::SymbolId) {
        module.symbols.push(kamy_core::Symbol {
            id: source,
            name: "caller".into(),
            rva: Rva::new(TEXT_RVA),
            kind: kamy_core::SymbolKind::Function,
        });
    }

    #[test]
    fn native_rip_trailing_immediate_and_eip_safety() {
        let (mut module, func) = single_block_module(
            &[0x66, 0x0f, 0x70, 0x05, 0xf7, 0x0f, 0, 0, 7, 0xc3],
            Terminator::Return,
        );
        let host = lift_function(&module, &func, &Win64Default, &[]);
        assert!(!host.unsupported);
        let operand = host
            .func
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find_map(|inst| match &inst.op {
                IrOp::NativeInline(native) => native.references.first().cloned(),
                _ => None,
            })
            .unwrap();
        assert_eq!(operand.reference.offset, 4);
        assert_eq!(
            operand.reference.field,
            kamy_core::LinkField::Relative32 { bias: 1 }
        );
        let source = authored_symbol("shuffle", "helper");
        mark_authored(&mut module, source.clone());
        let cc = AuthoredCc(HashMap::from([(
            source.clone(),
            Win64Default::default_signature(),
        )]));
        let mut operand = operand;
        operand.reference.source = source;
        operand.reference.origin = kamy_core::ReferenceOrigin::Authored;
        assert!(!lift_function(&module, &func, &cc, std::slice::from_ref(&operand)).unsupported);
        operand.reference.field = kamy_core::LinkField::Relative32 { bias: 0 };
        assert!(!lift_function(&module, &func, &cc, std::slice::from_ref(&operand)).unsupported);
        operand.reference.field = kamy_core::LinkField::Absolute64;
        assert!(lift_function(&module, &func, &cc, &[operand]).unsupported);
        let (module, func) = single_block_module(
            &[0x67, 0x66, 0x0f, 0xd4, 0x05, 0, 0, 0, 0, 0xc3],
            Terminator::Return,
        );
        assert!(lift_function(&module, &func, &Win64Default, &[]).unsupported);
    }

    #[test]
    fn native_aggregate_relocates_readonly_storage_through_codegen() {
        let code = [
            0x48, 0x8b, 0x42, 0x10, 0x48, 0x83, 0xc0, 7, 0xf3, 0x0f, 0x6f, 0x02, 0x66, 0x0f, 0xd4,
            0x05, 0xec, 0x0f, 0, 0, 0xf3, 0x0f, 0x7f, 0x01, 0x48, 0x89, 0x41, 0x10, 0xc3,
        ];
        let (mut module, func) = single_block_module(&code, Terminator::Return);
        module.sections.push(Section {
            name: ".rdata".into(),
            rva: Rva::new(0x2000),
            virtual_size: 16,
            data: [1u64.to_le_bytes(), 2u64.to_le_bytes()].concat(),
            flags: SectionFlags {
                read: true,
                write: false,
                execute: false,
            },
        });
        let source = authored_symbol("aggregate", "helper");
        mark_authored(&mut module, source.clone());
        let mut signature = Win64Default::default_signature();
        signature.args.truncate(2);
        signature.returns.clear();
        let cc = AuthoredCc(HashMap::from([(source.clone(), signature)]));
        let operand = kamy_core::OperandReference {
            instruction: Rva::new(TEXT_RVA + 12),
            operand: 1,
            reference: kamy_core::Reference {
                source,
                offset: 16,
                expression: kamy_core::SymbolicExpression::symbol(authored_symbol(
                    "aggregate",
                    "coff:0:section:7:piece:0",
                )),
                field: kamy_core::LinkField::Relative32 { bias: 0 },
                origin: kamy_core::ReferenceOrigin::Authored,
            },
        };
        let mut lifted = lift_function(&module, &func, &cc, std::slice::from_ref(&operand));
        assert!(!lifted.unsupported);
        ssa::construct_ssa(&mut lifted).unwrap();
        kamy_transforms::optimize(&mut lifted.func);
        let alloc =
            kamy_codegen::allocate_registers(&lifted.func, &lifted.rsp_chain, &lifted.reg_pins)
                .unwrap();
        let selected = kamy_codegen::select_instructions(&lifted.func, &alloc);
        let readonly = authored_symbol("aggregate", "coff:0:section:7:piece:0");
        let other_module = authored_symbol("other", "coff:0:section:7:piece:0");
        let code_va = BASE + 0x8000;
        for storage_va in [BASE + 0x6000, BASE + 0x1_2000] {
            let addresses = HashMap::from([
                (readonly.clone(), storage_va),
                (other_module.clone(), BASE + 0x2000),
            ]);
            let mut bound = selected.clone();
            kamy_codegen::bind_references(&mut bound, BASE, |symbol| {
                addresses.get(symbol).copied()
            })
            .unwrap();
            let encoded = kamy_codegen::relocate(&bound.instructions, code_va).unwrap();
            let decoded: Vec<_> =
                iced_x86::Decoder::with_ip(64, &encoded, code_va, iced_x86::DecoderOptions::NONE)
                    .into_iter()
                    .collect();
            let adds: Vec<_> = decoded
                .iter()
                .filter(|inst| inst.mnemonic() == iced_x86::Mnemonic::Paddq)
                .collect();
            assert_eq!(adds.len(), 1);
            assert_eq!(adds[0].op0_register(), Register::XMM0);
            assert!(adds[0].is_ip_rel_memory_operand());
            assert_eq!(adds[0].ip_rel_memory_address(), storage_va);
            assert!(decoded.iter().any(|inst| {
                (0..inst.op_count()).any(|index| {
                    matches!(
                        inst.op_kind(index),
                        OpKind::Immediate8
                            | OpKind::Immediate32
                            | OpKind::Immediate64
                            | OpKind::Immediate8to64
                            | OpKind::Immediate32to64
                    ) && inst.immediate(index) == 7
                })
            }));
        }
        let mut unresolved = selected.clone();
        assert!(
            kamy_codegen::bind_references(&mut unresolved, BASE, |symbol| {
                (symbol == &other_module).then_some(BASE + 0x6000)
            })
            .is_err()
        );
        let mut out_of_range = selected;
        kamy_codegen::bind_references(&mut out_of_range, BASE, |symbol| {
            (symbol == &readonly).then_some(code_va + 0x1_0000_0000)
        })
        .unwrap();
        assert!(kamy_codegen::relocate(&out_of_range.instructions, code_va).is_err());
        assert!(lift_function(&module, &func, &cc, &[]).unsupported);
        for invalid in 0..4 {
            let mut bad = operand.clone();
            match invalid {
                0 => bad.operand = 0,
                1 => bad.reference.offset += 1,
                2 => bad.reference.field = kamy_core::LinkField::Absolute64,
                _ => bad.reference.source = authored_symbol("other", "helper"),
            }
            assert!(lift_function(&module, &func, &cc, &[bad]).unsupported);
        }
    }

    #[test]
    fn exact_movabs_keeps_pointer_and_equal_literal_distinct_across_modules() {
        let literal = BASE + 0x2000;
        let mut code = vec![0x48, 0xb8];
        code.extend_from_slice(&literal.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&literal.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0xc2, 0xc3]);
        let mut identities = Vec::new();
        for key in ["first", "second"] {
            let (mut module, func) = single_block_module(&code, Terminator::Return);
            let source = authored_symbol(key, "object:0:symbol:7");
            let target = authored_symbol(key, "object:0:symbol:9");
            mark_authored(&mut module, source.clone());
            let cc = AuthoredCc(HashMap::from([(
                source.clone(),
                Win64Default::default_signature(),
            )]));
            let reference = kamy_core::Reference {
                source,
                offset: 2,
                expression: kamy_core::SymbolicExpression::Symbol {
                    symbol: target.clone(),
                    addend: -8,
                },
                field: kamy_core::LinkField::Absolute64,
                origin: kamy_core::ReferenceOrigin::Authored,
            };
            let operands = [kamy_core::OperandReference {
                instruction: Rva::new(TEXT_RVA),
                operand: 1,
                reference: reference.clone(),
            }];
            let mut lifted = lift_function(&module, &func, &cc, &operands);
            assert!(!lifted.unsupported);
            construct_ssa(&mut lifted).unwrap();
            let ops = &lifted.func.blocks[0].insts;
            assert!(
                ops.iter()
                    .any(|inst| matches!(&inst.op, IrOp::Address(actual) if actual == &reference))
            );
            assert!(
                ops.iter()
                    .any(|inst| matches!(inst.op, IrOp::Const(value) if value == literal))
            );
            assert_eq!(module.sections[0].data, code);
            identities.push(target);
        }
        assert_ne!(identities[0], identities[1]);
    }

    #[test]
    fn authored_calls_have_independent_integer_and_float_results_and_no_default() {
        let (mut module, func) = single_block_module(
            &[
                0x48, 0x83, 0xec, 0x28, 0xe8, 0xf7, 0x0f, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
            ],
            Terminator::Return,
        );
        let source = authored_symbol("module", "object:0:symbol:1");
        let target = authored_symbol("module", "object:0:symbol:2");
        mark_authored(&mut module, source.clone());
        let float = AbiValue {
            location: AbiLocation::Register(PhysReg::Xmm(XmmReg::Xmm0)),
            class: AbiClass::Float,
            bits: 64,
            passing: AbiPassing::Direct,
        };
        let signature = FnSignature {
            args: vec![AbiValue {
                location: AbiLocation::Register(PhysReg::Xmm(XmmReg::Xmm1)),
                ..float
            }],
            returns: vec![AbiValue::register(PhysReg::Gpr(Gpr::Rax)), float],
            clobbers: win64_volatiles(),
            noreturn: false,
        };
        let operands = [kamy_core::OperandReference {
            instruction: Rva::new(TEXT_RVA + 4),
            operand: 0,
            reference: kamy_core::Reference {
                source: source.clone(),
                offset: 5,
                expression: kamy_core::SymbolicExpression::symbol(target.clone()),
                field: kamy_core::LinkField::Relative32 { bias: 0 },
                origin: kamy_core::ReferenceOrigin::Authored,
            },
        }];
        let mut cc = AuthoredCc(HashMap::from([
            (source, signature.clone()),
            (target.clone(), signature),
        ]));
        let mut lifted = lift_function(&module, &func, &cc, &operands);
        assert!(!lifted.unsupported);
        construct_ssa(&mut lifted).unwrap();
        let results: Vec<_> = lifted.func.blocks[0]
            .insts
            .iter()
            .filter_map(|inst| {
                if let IrOp::CallResult { register } = inst.op {
                    Some((inst.dest.unwrap(), register, inst.ty))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(results.len(), 2);
        assert_ne!(results[0].0, results[1].0);
        assert_eq!(results[0].1, PhysReg::Gpr(Gpr::Rax));
        assert_eq!(results[1].1, PhysReg::Xmm(XmmReg::Xmm0));
        assert_eq!(results[1].2, IrType::I128);
        cc.0.remove(&target);
        assert!(lift_function(&module, &func, &cc, &operands).unsupported);
        cc.0.insert(
            target,
            FnSignature {
                args: vec![],
                returns: vec![],
                clobbers: win64_volatiles(),
                noreturn: true,
            },
        );
        let lifted = lift_function(&module, &func, &cc, &operands);
        assert!(!lifted.unsupported);
        assert!(matches!(lifted.func.blocks[0].term, IrTerminator::NoReturn));
        assert!(
            !lifted.func.blocks[0]
                .insts
                .iter()
                .any(|inst| matches!(inst.op, IrOp::CallResult { .. }))
        );
    }

    #[test]
    fn bounds_guard_does_not_pin_successor_placeholders() {
        let code = [
            0x48, 0x8b, 0x15, 0x01, 0x10, 0, 0, 0x48, 0x8b, 0x0d, 0xf2, 0x0f, 0, 0, 0xb8, 0x17, 0,
            0, 0, 0x48, 0x85, 0xd2, 0x74, 0x16, 0x48, 0x29, 0xd1, 0x48, 0x83, 0xf9, 0x20, 0x75,
            0x0d, 0x48, 0xc7, 0x05, 0xdc, 0xaf, 0x07, 0, 0x20, 0, 0, 0, 0x31, 0xc0, 0xc3,
        ];
        let (mut module, mut func) = single_block_module(&code, Terminator::Return);
        let local = |offset| Rva::new(TEXT_RVA + offset);
        func.blocks = vec![
            BasicBlock {
                start: local(0),
                end: local(24),
                successors: vec![local(46), local(24)],
                terminator: Terminator::Branch {
                    taken: local(46),
                    not_taken: local(24),
                },
            },
            BasicBlock {
                start: local(24),
                end: local(33),
                successors: vec![local(46), local(33)],
                terminator: Terminator::Branch {
                    taken: local(46),
                    not_taken: local(33),
                },
            },
            BasicBlock {
                start: local(33),
                end: local(46),
                successors: vec![local(46)],
                terminator: Terminator::Jump(local(46)),
            },
            BasicBlock {
                start: local(46),
                end: local(47),
                successors: vec![],
                terminator: Terminator::Return,
            },
        ];
        module.functions = vec![func.clone()];
        let source = authored_symbol("module", "guard");
        mark_authored(&mut module, source.clone());
        let mut signature = Win64Default::default_signature();
        signature.args.truncate(3);
        signature.returns[0].bits = 32;
        let cc = AuthoredCc(HashMap::from([(source.clone(), signature)]));
        let references: Vec<_> = [
            (
                0,
                1,
                3,
                kamy_core::SymbolicExpression::symbol(authored_symbol("module", "table_begin")),
            ),
            (
                7,
                1,
                10,
                kamy_core::SymbolicExpression::symbol(authored_symbol("module", "table_end")),
            ),
            (
                33,
                0,
                36,
                kamy_core::SymbolicExpression::Symbol {
                    symbol: kamy_core::SymbolId::HostImageBase,
                    addend: 507_912,
                },
            ),
        ]
        .into_iter()
        .map(
            |(instruction, operand, offset, expression)| kamy_core::OperandReference {
                instruction: local(instruction),
                operand,
                reference: kamy_core::Reference {
                    source: source.clone(),
                    offset,
                    expression,
                    field: kamy_core::LinkField::Relative32 { bias: 0 },
                    origin: kamy_core::ReferenceOrigin::Authored,
                },
            },
        )
        .collect();
        let mut lifted = lift_function(&module, &func, &cc, &references);
        assert!(!lifted.unsupported);
        assert!(
            lifted
                .block_entry
                .iter()
                .skip(1)
                .flatten()
                .all(|value| !lifted.reg_pins.contains_key(value))
        );
        construct_ssa(&mut lifted).unwrap();
        kamy_transforms::optimize(&mut lifted.func);
        assert!(
            lifted
                .func
                .blocks
                .iter()
                .flat_map(|block| &block.phis)
                .all(|phi| !lifted.reg_pins.contains_key(&phi.dest))
        );
        let alloc =
            kamy_codegen::allocate_registers(&lifted.func, &lifted.rsp_chain, &lifted.reg_pins)
                .unwrap();
        let mut selected = kamy_codegen::select_instructions(&lifted.func, &alloc);
        assert_eq!(selected.references.len(), 3);
        let addresses = HashMap::from([
            (authored_symbol("module", "table_begin"), BASE + 0x2008),
            (authored_symbol("module", "table_end"), BASE + 0x2000),
        ]);
        kamy_codegen::bind_references(&mut selected, BASE, |symbol| addresses.get(symbol).copied())
            .unwrap();
        kamy_codegen::relocate(&selected.instructions, BASE + 0x4000).unwrap();
    }

    #[test]
    fn chkstk_metadata_preserves_arguments_and_proves_extent() {
        let code = [
            0xb8, 0, 0x50, 0, 0, 0xe8, 0xf6, 0x0f, 0, 0, 0x48, 0x29, 0xc4, 0x48, 0x81, 0xc4, 0,
            0x50, 0, 0, 0xc3,
        ];
        for name in ["__chkstk", "__chkstk_like"] {
            let (mut module, func) = single_block_module(&code, Terminator::Return);
            module.symbols.push(kamy_core::Symbol {
                id: kamy_core::SymbolId::Host {
                    rva: Rva::new(0x2000),
                },
                name: name.into(),
                rva: Rva::new(0x2000),
                kind: kamy_core::SymbolKind::Function,
            });
            let mut lifted = lift_function(&module, &func, &Win64Default, &[]);
            assert!(!lifted.unsupported);
            if name != "__chkstk" {
                assert!(
                    lifted.func.blocks[0]
                        .insts
                        .iter()
                        .any(|inst| matches!(inst.op, IrOp::Call { .. }))
                );
                continue;
            }
            let probe = lifted.func.blocks[0]
                .insts
                .iter()
                .find(|inst| matches!(inst.op, IrOp::StackProbe))
                .unwrap();
            assert_eq!(probe.args[0], lifted.block_exit[0][Gpr::Rax.index()]);
            for register in [Gpr::Rcx, Gpr::Rdx, Gpr::R8, Gpr::R9, Gpr::Rbx] {
                assert_eq!(
                    lifted.block_entry[0][register.index()],
                    lifted.block_exit[0][register.index()]
                );
            }
            for register in [Gpr::R10, Gpr::R11] {
                assert_ne!(
                    lifted.block_entry[0][register.index()],
                    lifted.block_exit[0][register.index()]
                );
            }
            assert!(
                !lifted.func.blocks[0]
                    .insts
                    .iter()
                    .any(|inst| matches!(inst.op, IrOp::Call { .. }))
            );
            construct_ssa(&mut lifted).unwrap();
            kamy_transforms::optimize(&mut lifted.func);
            let analysis = kamy_core::FrameAnalysis::analyze(
                &lifted.func,
                &lifted.rsp_chain,
                &lifted.reg_pins,
            )
            .unwrap();
            assert_eq!(analysis.original_size, 0x5008);
            assert_eq!(analysis.outgoing_size, 0);
        }
    }

    #[test]
    fn unknown_host_return_keeps_integer_and_float_candidates() {
        let (module, func) = single_block_module(&[0xc3], Terminator::Return);
        let lifted = lift_function(&module, &func, &Win64Default, &[]);
        for register in [PhysReg::Gpr(Gpr::Rax), PhysReg::Xmm(XmmReg::Xmm0)] {
            assert!(
                lifted.func.blocks[0]
                    .insts
                    .iter()
                    .filter(|inst| matches!(inst.op, IrOp::Use))
                    .flat_map(|inst| &inst.args)
                    .any(|value| lifted.reg_pins.get(value) == Some(&register))
            );
        }
    }

    #[test]
    fn scalar_register_moves_preserve_destination_upper_lanes_in_emitted_code() {
        for (prefix, bits) in [(0xf2, 64), (0xf3, 32)] {
            let code = [prefix, 0x0f, 0x10, 0xc1, 0xc3];
            let (module, func) = single_block_module(&code, Terminator::Return);
            let mut lifted = lift_function(&module, &func, &Win64Default, &[]);
            assert!(!lifted.unsupported);
            assert!(
                lifted.func.blocks[0]
                    .insts
                    .iter()
                    .any(|inst| matches!(inst.op, IrOp::NativeInline(_)))
            );
            construct_ssa(&mut lifted).unwrap();
            kamy_transforms::optimize(&mut lifted.func);
            let alloc =
                kamy_codegen::allocate_registers(&lifted.func, &lifted.rsp_chain, &lifted.reg_pins)
                    .unwrap();
            let selected = kamy_codegen::select_instructions(&lifted.func, &alloc);
            let code_va = BASE + 0x4000;
            let encoded = kamy_codegen::relocate(&selected.instructions, code_va).unwrap();
            let returned = execute_boundary_code(&encoded, code_va, &[]);
            let initial = (0x1234_5678_9abc_def0u128 << 64) | 0x0fed_cba9_beef_0000;
            let mask = (1u128 << bits) - 1;
            assert_eq!(
                returned[&PhysReg::Xmm(XmmReg::Xmm0)],
                (initial & !mask) | ((initial + 1) & mask)
            );
        }
    }

    #[test]
    fn every_call_signature_retains_unpinned_logical_rsp() {
        for (register_args, stack_bits, expected_outgoing) in [
            (0, None, 32u32),
            (4, None, 32),
            (5, Some(64u16), 40),
            (5, Some(32), 40),
        ] {
            let code = [
                0x48, 0x83, 0xec, 0x28, 0xe8, 0xf7, 0x0f, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
            ];
            let (mut module, func) = single_block_module(&code, Terminator::Return);
            let source = authored_symbol("rsp", "caller");
            let target = authored_symbol("rsp", "callee");
            mark_authored(&mut module, source.clone());
            let mut signature = Win64Default::default_signature();
            signature.args.truncate(4.min(register_args));
            if let Some(bits) = stack_bits {
                for slot in signature.args.len()..register_args {
                    signature.args.push(kamy_core::ir::AbiValue {
                        location: kamy_core::ir::AbiLocation::Stack {
                            offset: 8 + 8 * slot as i32,
                        },
                        class: kamy_core::ir::AbiClass::Integer,
                        bits,
                        passing: kamy_core::ir::AbiPassing::Direct,
                    });
                }
            }
            let stack_args = signature.args.len() - 4.min(register_args);
            let cc = AuthoredCc(HashMap::from([
                (source.clone(), signature.clone()),
                (target.clone(), signature),
            ]));
            let reference = kamy_core::OperandReference {
                instruction: Rva::new(TEXT_RVA + 4),
                operand: 0,
                reference: kamy_core::Reference {
                    source,
                    offset: 5,
                    expression: kamy_core::SymbolicExpression::symbol(target),
                    field: kamy_core::LinkField::Relative32 { bias: 0 },
                    origin: kamy_core::ReferenceOrigin::Authored,
                },
            };
            let mut lifted = lift_function(&module, &func, &cc, &[reference]);
            assert!(!lifted.unsupported);
            construct_ssa(&mut lifted).unwrap();
            kamy_transforms::optimize(&mut lifted.func);
            let (index, call) = lifted.func.blocks[0]
                .insts
                .iter()
                .enumerate()
                .find(|(_, inst)| matches!(inst.op, IrOp::Call { .. }))
                .unwrap();
            assert_eq!(call.args.len(), 4.min(register_args) + stack_args + 1);
            let rsp = call.args.last().unwrap();
            assert!(lifted.rsp_chain.contains(rsp));
            assert!(!lifted.reg_pins.contains_key(rsp));
            let analysis = kamy_core::FrameAnalysis::analyze(
                &lifted.func,
                &lifted.rsp_chain,
                &lifted.reg_pins,
            )
            .unwrap();
            assert_eq!(analysis.call_deltas[&(BlockId(0), index)], -40);
            assert_eq!(analysis.original_size, 40);
            assert_eq!(analysis.outgoing_size, expected_outgoing);
        }
    }

    fn successor_module(code: &[u8]) -> (Module, Function) {
        let (mut module, mut func) = single_block_module(code, Terminator::Return);
        let successor = Rva::new(TEXT_RVA + 9);
        func.blocks[0].start = successor;
        func.blocks.insert(
            0,
            BasicBlock {
                start: func.entry,
                end: successor,
                successors: vec![successor],
                terminator: Terminator::Jump(successor),
            },
        );
        module.functions = vec![func.clone()];
        (module, func)
    }

    fn execute_boundary_code(
        code: &[u8],
        code_va: u64,
        call_returns: &[(u64, u128)],
    ) -> HashMap<PhysReg, u128> {
        struct Machine {
            registers: HashMap<PhysReg, u128>,
            memory: HashMap<u64, u8>,
            entry_rsp: u64,
        }

        impl Machine {
            fn physical(register: Register) -> PhysReg {
                if let Some(gpr) = iced_reg_to_gpr(register) {
                    PhysReg::Gpr(gpr)
                } else {
                    PhysReg::Xmm(iced_reg_to_xmm(register).unwrap())
                }
            }

            fn read_register(&self, register: Register) -> u128 {
                let value = self.registers[&Self::physical(register)];
                if matches!(
                    register,
                    Register::AH | Register::BH | Register::CH | Register::DH
                ) {
                    return (value >> 8) & 0xff;
                }
                let bits = register.size() * 8;
                if bits == 128 {
                    value
                } else {
                    value & ((1u128 << bits) - 1)
                }
            }

            fn write_register(&mut self, register: Register, value: u128) {
                let physical = Self::physical(register);
                let bits = register.size() * 8;
                let value = if bits == 128 {
                    value
                } else if matches!(
                    register,
                    Register::AH | Register::BH | Register::CH | Register::DH
                ) {
                    (self.registers[&physical] & !0xff00) | ((value & 0xff) << 8)
                } else if bits < 32 {
                    let mask = (1u128 << bits) - 1;
                    (self.registers[&physical] & !mask) | (value & mask)
                } else {
                    value & ((1u128 << bits) - 1)
                };
                self.registers.insert(physical, value);
            }

            fn address(&self, insn: &Instruction) -> u64 {
                if insn.is_ip_rel_memory_operand() {
                    return insn.ip_rel_memory_address();
                }
                let read = |register| {
                    if register == Register::None {
                        0
                    } else {
                        self.read_register(register) as u64
                    }
                };
                read(insn.memory_base())
                    .wrapping_add(
                        read(insn.memory_index())
                            .wrapping_mul(u64::from(insn.memory_index_scale())),
                    )
                    .wrapping_add(insn.memory_displacement64())
            }

            fn check_address(&self, address: u64, size: usize) {
                assert!(address >= self.entry_rsp - 16 * 1024 * 1024);
                assert!(address.checked_add(size as u64).unwrap() <= self.entry_rsp + 8);
            }

            fn read_memory(&self, address: u64, size: usize) -> u128 {
                self.check_address(address, size);
                assert!(size <= 16);
                (0..size).fold(0, |value, byte| {
                    value | (u128::from(self.memory[&(address + byte as u64)]) << (byte * 8))
                })
            }

            fn write_memory(&mut self, address: u64, size: usize, value: u128) {
                self.check_address(address, size);
                assert!(size <= 16);
                for byte in 0..size {
                    self.memory
                        .insert(address + byte as u64, (value >> (byte * 8)) as u8);
                }
            }

            fn read(&self, insn: &Instruction, operand: u32) -> u128 {
                match insn.op_kind(operand) {
                    OpKind::Register => self.read_register(insn.op_register(operand)),
                    OpKind::Memory => {
                        self.read_memory(self.address(insn), insn.memory_size().size())
                    }
                    _ => u128::from(get_immediate(insn, operand)),
                }
            }

            fn write(&mut self, insn: &Instruction, value: u128) {
                match insn.op0_kind() {
                    OpKind::Register => self.write_register(insn.op0_register(), value),
                    OpKind::Memory => {
                        self.write_memory(self.address(insn), insn.memory_size().size(), value)
                    }
                    other => panic!("unexpected boundary destination: {other:?}"),
                }
            }
        }

        let registers: HashMap<_, _> = Gpr::ALL
            .into_iter()
            .map(|gpr| (PhysReg::Gpr(gpr), 0xdead_0000 + gpr.index() as u128))
            .chain(XmmReg::ALL.into_iter().map(|xmm| {
                let index = xmm.index() as u128;
                (
                    PhysReg::Xmm(xmm),
                    ((0x1234_5678_9abc_def0u128 + index) << 64) | (0x0fed_cba9_beef_0000 + index),
                )
            }))
            .collect();
        let original = registers.clone();
        let mut machine = Machine {
            registers,
            memory: HashMap::new(),
            entry_rsp: 0x1000_0008,
        };
        machine.write_register(Register::RSP, u128::from(machine.entry_rsp));
        machine.write_memory(machine.entry_rsp, 8, 0xfeed_face);
        let decoded: Vec<_> = Decoder::with_ip(64, code, code_va, DecoderOptions::NONE)
            .into_iter()
            .collect();
        let targets: HashMap<_, _> = decoded
            .iter()
            .enumerate()
            .map(|(index, insn)| (insn.ip(), index))
            .collect();
        let mut call_returns = call_returns.iter();
        let mut pc = 0;
        for _ in 0..100_000 {
            let insn = &decoded[pc];
            pc += 1;
            match insn.mnemonic() {
                Mnemonic::Mov
                | Mnemonic::Movzx
                | Mnemonic::Movaps
                | Mnemonic::Movups
                | Mnemonic::Movdqu
                | Mnemonic::Movdqa
                | Mnemonic::Movq
                | Mnemonic::Movd => {
                    let value = machine.read(insn, 1);
                    machine.write(insn, value);
                }
                Mnemonic::Movsd | Mnemonic::Movss => {
                    let mask = if insn.mnemonic() == Mnemonic::Movsd {
                        u128::from(u64::MAX)
                    } else {
                        u128::from(u32::MAX)
                    };
                    let source = machine.read(insn, 1);
                    let value = if insn.op0_kind() == OpKind::Register
                        && insn.op1_kind() == OpKind::Register
                    {
                        (machine.read(insn, 0) & !mask) | (source & mask)
                    } else {
                        source & mask
                    };
                    machine.write(insn, value);
                }
                Mnemonic::Lea => machine.write(insn, u128::from(machine.address(insn))),
                Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::Xor
                | Mnemonic::And
                | Mnemonic::Or
                | Mnemonic::Pxor
                | Mnemonic::Xorps
                | Mnemonic::Xorpd => {
                    let left = machine.read(insn, 0);
                    let right = machine.read(insn, 1);
                    let value = match insn.mnemonic() {
                        Mnemonic::Add => left.wrapping_add(right),
                        Mnemonic::Sub => left.wrapping_sub(right),
                        Mnemonic::And => left & right,
                        Mnemonic::Or => left | right,
                        _ => left ^ right,
                    };
                    machine.write(insn, value);
                }
                Mnemonic::Call => {
                    let rsp = machine.read_register(Register::RSP) as u64;
                    assert_eq!(rsp & 15, 0);
                    machine.write_memory(rsp - 8, 8, u128::from(insn.next_ip()));
                    for byte in 0..32 {
                        machine.check_address(rsp + byte, 1);
                        machine.memory.insert(rsp + byte, 0xcc);
                    }
                    for register in win64_volatiles() {
                        machine.registers.insert(register, 0xcccc_cccc_cccc_cccc);
                    }
                    let &(integer, xmm) = call_returns.next().unwrap();
                    machine
                        .registers
                        .insert(PhysReg::Gpr(Gpr::Rax), u128::from(integer));
                    machine.registers.insert(PhysReg::Xmm(XmmReg::Xmm0), xmm);
                }
                Mnemonic::Rdtsc => {
                    machine.write_register(Register::EAX, 0x1234_5678);
                    machine.write_register(Register::EDX, 0x9abc_def0);
                }
                Mnemonic::Jmp => pc = targets[&insn.near_branch_target()],
                Mnemonic::Nop => {}
                Mnemonic::Ret => {
                    assert!(call_returns.next().is_none());
                    assert_eq!(
                        machine.read_register(Register::RSP),
                        u128::from(machine.entry_rsp)
                    );
                    assert_eq!(machine.read_memory(machine.entry_rsp, 8), 0xfeed_face);
                    for register in Gpr::ALL {
                        if register != Gpr::Rsp && !register.is_volatile_win64() {
                            let physical = PhysReg::Gpr(register);
                            assert_eq!(machine.registers[&physical], original[&physical]);
                        }
                    }
                    for register in XmmReg::ALL.into_iter().skip(6) {
                        let physical = PhysReg::Xmm(register);
                        assert_eq!(machine.registers[&physical], original[&physical]);
                    }
                    return machine.registers;
                }
                other => panic!("unexpected emitted boundary instruction: {other:?}"),
            }
        }
        panic!("boundary fixture did not return");
    }

    #[test]
    fn successor_moves_preserve_integer_and_xmm_call_results_across_a_later_call() {
        let code = [
            0x48, 0x83, 0xec, 0x28, 0xe8, 0xf7, 0x0f, 0, 0, 0x48, 0x89, 0xc3, 0x0f, 0x28, 0xf0,
            0xe8, 0xec, 0x0f, 0, 0, 0x48, 0x83, 0xc3, 1, 0x48, 0x89, 0xd8, 0x0f, 0x28, 0xc6, 0x48,
            0x83, 0xc4, 0x28, 0xc3,
        ];
        let (mut module, func) = successor_module(&code);
        let source = authored_symbol("module", "caller");
        let target = authored_symbol("module", "callee");
        mark_authored(&mut module, source.clone());
        let signature = FnSignature {
            args: vec![],
            returns: vec![
                AbiValue::register(PhysReg::Gpr(Gpr::Rax)),
                AbiValue {
                    location: AbiLocation::Register(PhysReg::Xmm(XmmReg::Xmm0)),
                    class: AbiClass::Float,
                    bits: 64,
                    passing: AbiPassing::Direct,
                },
            ],
            clobbers: win64_volatiles(),
            noreturn: false,
        };
        let cc = AuthoredCc(HashMap::from([
            (source.clone(), signature.clone()),
            (target.clone(), signature),
        ]));
        let references: Vec<_> = [4, 15]
            .into_iter()
            .map(|offset| kamy_core::OperandReference {
                instruction: Rva::new(TEXT_RVA + offset),
                operand: 0,
                reference: kamy_core::Reference {
                    source: source.clone(),
                    offset: offset + 1,
                    expression: kamy_core::SymbolicExpression::symbol(target.clone()),
                    field: kamy_core::LinkField::Relative32 { bias: 0 },
                    origin: kamy_core::ReferenceOrigin::Authored,
                },
            })
            .collect();
        let mut lifted = lift_function(&module, &func, &cc, &references);
        assert!(!lifted.unsupported);
        construct_ssa(&mut lifted).unwrap();
        kamy_transforms::optimize(&mut lifted.func);
        let instructions: Vec<_> = lifted
            .func
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .collect();
        let result = |register| {
            instructions
                .iter()
                .find_map(|inst| match inst.op {
                    IrOp::CallResult { register: actual } if actual == register => inst.dest,
                    _ => None,
                })
                .unwrap()
        };
        let integer = result(PhysReg::Gpr(Gpr::Rax));
        let floating = result(PhysReg::Xmm(XmmReg::Xmm0));
        let moved = |input, is_xmm| {
            instructions
                .iter()
                .find(|inst| {
                    inst.args == [input]
                        && if is_xmm {
                            matches!(inst.op, IrOp::Mov128)
                        } else {
                            matches!(inst.op, IrOp::Copy)
                        }
                })
                .unwrap()
                .dest
                .unwrap()
        };
        let saved_integer = moved(integer, false);
        let saved_floating = moved(floating, true);
        assert!(!lifted.reg_pins.contains_key(&saved_integer));
        assert!(!lifted.reg_pins.contains_key(&saved_floating));
        let alloc =
            kamy_codegen::allocate_registers(&lifted.func, &lifted.rsp_chain, &lifted.reg_pins)
                .unwrap();
        let mut selected = kamy_codegen::select_instructions(&lifted.func, &alloc);
        assert_eq!(selected.references.len(), 2);
        kamy_codegen::bind_references(&mut selected, BASE, |symbol| {
            (symbol == &target).then_some(BASE + 0x2000)
        })
        .unwrap();
        let code_va = BASE + 0x4000;
        let encoded = kamy_codegen::relocate(&selected.instructions, code_va).unwrap();
        let returned = execute_boundary_code(&encoded, code_va, &[(41, 3), (99, 7)]);
        assert_eq!(returned[&PhysReg::Gpr(Gpr::Rax)], 42);
        assert_eq!(returned[&PhysReg::Xmm(XmmReg::Xmm0)], 3);
    }

    #[test]
    fn successor_move_preserves_a_call_result_across_native_register_writes() {
        let code = [
            0x48, 0x83, 0xec, 0x28, 0xe8, 0xf7, 0x0f, 0, 0, 0x48, 0x89, 0xc3, 0x0f, 0x31, 0x48,
            0x83, 0xc3, 1, 0x48, 0x89, 0xd8, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ];
        let (mut module, func) = successor_module(&code);
        let source = authored_symbol("module", "native_caller");
        let target = authored_symbol("module", "callee");
        mark_authored(&mut module, source.clone());
        let mut signature = Win64Default::default_signature();
        signature.args.clear();
        let cc = AuthoredCc(HashMap::from([
            (source.clone(), signature.clone()),
            (target.clone(), signature),
        ]));
        let reference = kamy_core::OperandReference {
            instruction: Rva::new(TEXT_RVA + 4),
            operand: 0,
            reference: kamy_core::Reference {
                source,
                offset: 5,
                expression: kamy_core::SymbolicExpression::symbol(target.clone()),
                field: kamy_core::LinkField::Relative32 { bias: 0 },
                origin: kamy_core::ReferenceOrigin::Authored,
            },
        };
        let mut lifted = lift_function(&module, &func, &cc, &[reference]);
        assert!(!lifted.unsupported);
        construct_ssa(&mut lifted).unwrap();
        kamy_transforms::optimize(&mut lifted.func);
        let result = lifted.func.blocks[0]
            .insts
            .iter()
            .find_map(|inst| match inst.op {
                IrOp::CallResult {
                    register: PhysReg::Gpr(Gpr::Rax),
                } => inst.dest,
                _ => None,
            })
            .unwrap();
        let saved = lifted.func.blocks[1]
            .insts
            .iter()
            .find(|inst| matches!(inst.op, IrOp::Copy) && inst.args == [result])
            .unwrap()
            .dest
            .unwrap();
        assert!(!lifted.reg_pins.contains_key(&saved));
        let alloc =
            kamy_codegen::allocate_registers(&lifted.func, &lifted.rsp_chain, &lifted.reg_pins)
                .unwrap();
        let mut selected = kamy_codegen::select_instructions(&lifted.func, &alloc);
        kamy_codegen::bind_references(&mut selected, BASE, |symbol| {
            (symbol == &target).then_some(BASE + 0x2000)
        })
        .unwrap();
        let code_va = BASE + 0x4000;
        let encoded = kamy_codegen::relocate(&selected.instructions, code_va).unwrap();
        let returned = execute_boundary_code(&encoded, code_va, &[(41, 0)]);
        assert_eq!(returned[&PhysReg::Gpr(Gpr::Rax)], 42);
        assert!(
            iced_x86::Decoder::new(64, &encoded, iced_x86::DecoderOptions::NONE)
                .into_iter()
                .any(|inst| inst.mnemonic() == iced_x86::Mnemonic::Rdtsc)
        );
    }

    #[test]
    fn authored_callee_keeps_extra_preserved_registers_live_and_rejects_cl_scratch() {
        let source = authored_symbol("module", "object:0:symbol:1");
        let mut signature = Win64Default::default_signature();
        signature.clobbers.retain(|phys| {
            !matches!(
                phys,
                PhysReg::Gpr(Gpr::Rcx | Gpr::R11) | PhysReg::Xmm(XmmReg::Xmm1)
            )
        });
        let cc = AuthoredCc(HashMap::from([(source.clone(), signature)]));
        let (mut module, func) = single_block_module(&[0xb8, 1, 0, 0, 0, 0xc3], Terminator::Return);
        mark_authored(&mut module, source.clone());
        let mut lifted = lift_function(&module, &func, &cc, &[]);
        assert!(!lifted.unsupported);
        construct_ssa(&mut lifted).unwrap();
        for register in [
            PhysReg::Gpr(Gpr::Rcx),
            PhysReg::Gpr(Gpr::R11),
            PhysReg::Xmm(XmmReg::Xmm1),
        ] {
            assert!(
                lifted.func.blocks[0]
                    .insts
                    .iter()
                    .filter(|inst| matches!(inst.op, IrOp::Use))
                    .flat_map(|inst| &inst.args)
                    .any(|value| lifted.reg_pins.get(value) == Some(&register))
            );
        }
        let (mut module, func) = single_block_module(&[0x48, 0xd3, 0xe0, 0xc3], Terminator::Return);
        mark_authored(&mut module, source);
        assert!(lift_function(&module, &func, &cc, &[]).unsupported);
    }

    #[test]
    fn lift_add_rax_rcx_ret() {
        // 48 01 C8  = add rax, rcx
        // C3        = ret
        let code = [0x48, 0x01, 0xC8, 0xC3];
        let (module, func) = single_block_module(&code, Terminator::Return);
        let ir = lift_function(&module, &func, &Win64Default, &[]);

        assert_eq!(ir.func.blocks.len(), 1);
        let block = &ir.func.blocks[0];

        assert!(matches!(block.term, IrTerminator::Ret));

        let add_count = block
            .insts
            .iter()
            .filter(|i| matches!(i.op, IrOp::Add))
            .count();
        assert!(add_count >= 1, "expected at least one Add, got {add_count}");

        let flag_ops = block
            .insts
            .iter()
            .filter(|i| {
                matches!(
                    i.op,
                    IrOp::IsZero
                        | IrOp::IsNeg
                        | IrOp::Parity
                        | IrOp::CarryAdd
                        | IrOp::OverflowAdd
                        | IrOp::AuxCarryAdd
                )
            })
            .count();
        assert!(
            flag_ops >= 6,
            "expected at least 6 flag ops from ADD, got {flag_ops}"
        );
    }

    #[test]
    fn lift_je_produces_branch() {
        //   85 C0        test eax, eax
        //   74 04        je +4  (target = RVA 0x1008)
        //   --- block 1 (fallthrough) ---
        //   C3           ret
        //   90 90 90     nop padding
        //   --- block 2 (taken) ---
        //   C3           ret
        let data = vec![0x85, 0xC0, 0x74, 0x04, 0xC3, 0x90, 0x90, 0x90, 0xC3];
        let rva = Rva::new(TEXT_RVA);
        let section = Section {
            name: ".text".to_string(),
            rva,
            virtual_size: data.len() as u32,
            data,
            flags: SectionFlags {
                read: true,
                write: false,
                execute: true,
            },
        };

        let bb0 = BasicBlock {
            start: Rva::new(TEXT_RVA),
            end: Rva::new(TEXT_RVA + 4),
            successors: vec![Rva::new(TEXT_RVA + 8), Rva::new(TEXT_RVA + 4)],
            terminator: Terminator::Branch {
                taken: Rva::new(TEXT_RVA + 8),
                not_taken: Rva::new(TEXT_RVA + 4),
            },
        };
        let bb1 = BasicBlock {
            start: Rva::new(TEXT_RVA + 4),
            end: Rva::new(TEXT_RVA + 5),
            successors: vec![],
            terminator: Terminator::Return,
        };
        let bb2 = BasicBlock {
            start: Rva::new(TEXT_RVA + 8),
            end: Rva::new(TEXT_RVA + 9),
            successors: vec![],
            terminator: Terminator::Return,
        };

        let func = Function {
            entry: Rva::new(TEXT_RVA),
            blocks: vec![bb0, bb1, bb2],
        };
        let module = Module {
            image_base: BASE,
            machine: Machine::X64,
            entry_point: Some(rva),
            sections: vec![section],
            symbols: vec![],
            relocations: vec![],
            functions: vec![func.clone()],
        };

        let ir = lift_function(&module, &func, &Win64Default, &[]);

        assert_eq!(ir.func.blocks.len(), 3);

        let entry = &ir.func.blocks[0];
        match &entry.term {
            IrTerminator::Branch {
                cond,
                taken,
                not_taken,
            } => {
                assert_ne!(taken, not_taken);
                let cond_inst = entry.insts.iter().find(|i| i.dest == Some(*cond));
                assert!(
                    cond_inst.is_some(),
                    "branch condition must trace to an instruction in this block"
                );
                let op = &cond_inst.unwrap().op;
                assert!(
                    matches!(op, IrOp::IsZero),
                    "je condition should be ZF (IsZero), got {op:?}"
                );
            }
            other => panic!("expected Branch terminator, got {other:?}"),
        }
    }

    #[test]
    fn native_inline_for_cpuid() {
        // 0F A2  = cpuid
        // C3     = ret
        let code = [0x0F, 0xA2, 0xC3];
        let (module, func) = single_block_module(&code, Terminator::Return);
        let ir = lift_function(&module, &func, &Win64Default, &[]);

        let block = &ir.func.blocks[0];

        let native = block
            .insts
            .iter()
            .find(|i| matches!(&i.op, IrOp::NativeInline(n) if n.bytes == [0x0F, 0xA2]));
        assert!(
            native.is_some(),
            "expected a NativeInline instruction for cpuid"
        );
        let ni = match &native.unwrap().op {
            IrOp::NativeInline(n) => n,
            _ => unreachable!(),
        };
        assert!(
            !ni.reads.is_empty() || !ni.writes.is_empty(),
            "NativeInline should have reads or writes populated"
        );
    }

    #[test]
    fn switch_lowers_to_tableless_compare_ladder() {
        // Dispatch block @0x1000:
        //   83 F9 02             cmp ecx, 2
        //   48 8D 15 00 10 00 00 lea rdx,[rip+0x1000]   (dead; disp irrelevant)
        //   48 63 0C 8A          movsxd rcx,[rdx+rcx*4]  <- dispatch_rva 0x100A
        //   48 01 D1             add rcx, rdx
        //   FF E1                jmp rcx
        // case0 @0x1013: B8 0A 00 00 00 C3  mov eax,10; ret
        // case1 @0x1019: B8 14 00 00 00 C3  mov eax,20; ret
        // case2 @0x101F: B8 1E 00 00 00 C3  mov eax,30; ret
        let code = vec![
            0x83, 0xF9, 0x02, 0x48, 0x8D, 0x15, 0x00, 0x10, 0x00, 0x00, 0x48, 0x63, 0x0C, 0x8A,
            0x48, 0x01, 0xD1, 0xFF, 0xE1, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0x14, 0x00,
            0x00, 0x00, 0xC3, 0xB8, 0x1E, 0x00, 0x00, 0x00, 0xC3,
        ];
        let rva = Rva::new(TEXT_RVA);
        let section = Section {
            name: ".text".into(),
            rva,
            virtual_size: code.len() as u32,
            data: code,
            flags: SectionFlags {
                read: true,
                write: false,
                execute: true,
            },
        };
        let c0 = Rva::new(TEXT_RVA + 0x13);
        let c1 = Rva::new(TEXT_RVA + 0x19);
        let c2 = Rva::new(TEXT_RVA + 0x1F);
        let table = kamy_core::SwitchTable {
            index_reg: Gpr::Rcx,
            dispatch_rva: Rva::new(TEXT_RVA + 0x0A),
            entries: vec![c0, c1, c2],
        };
        let case = |s: Rva, e: u32| BasicBlock {
            start: s,
            end: Rva::new(e),
            successors: vec![],
            terminator: Terminator::Return,
        };
        let func = Function {
            entry: rva,
            blocks: vec![
                BasicBlock {
                    start: rva,
                    end: c0,
                    successors: vec![c0, c1, c2],
                    terminator: Terminator::Switch { table },
                },
                case(c0, TEXT_RVA + 0x19),
                case(c1, TEXT_RVA + 0x1F),
                case(c2, TEXT_RVA + 0x25),
            ],
        };
        let module = Module {
            image_base: BASE,
            machine: Machine::X64,
            entry_point: Some(rva),
            sections: vec![section],
            symbols: vec![],
            relocations: vec![],
            functions: vec![func.clone()],
        };

        let mut ir = lift_function(&module, &func, &Win64Default, &[]);
        assert!(!ir.unsupported, "a recovered switch must lift");
        assert!(
            !ir.func
                .blocks
                .iter()
                .any(|b| matches!(b.term, IrTerminator::Unreachable)),
            "no unresolved control flow should remain"
        );
        // Dispatch block is the first ladder rung: a conditional branch, not an
        // indirect/table jump.
        assert!(matches!(
            ir.func.blocks[0].term,
            IrTerminator::Branch { .. }
        ));
        // Three cases → two equality rungs (idx==0, idx==1); the last falls
        // through. One fresh rung block is appended past the 4 CFG blocks.
        assert_eq!(ir.func.blocks.len(), 5);
        assert_eq!(ir.block_entry.len(), ir.func.blocks.len());
        assert_eq!(ir.block_exit.len(), ir.func.blocks.len());
        let iszero = ir
            .func
            .blocks
            .iter()
            .flat_map(|b| &b.insts)
            .filter(|i| matches!(i.op, IrOp::IsZero))
            .count();
        assert!(iszero >= 2, "expected >=2 equality tests, got {iszero}");
        // No table reference survives: the dispatch keeps no indirect jump.
        construct_ssa(&mut ir).unwrap();
        assert!(
            !ir.func
                .blocks
                .iter()
                .any(|b| matches!(b.term, IrTerminator::Unreachable)),
            "SSA construction must preserve the ladder"
        );
    }

    fn evaluate_gpr_sequence(block: &IrBlock) -> HashMap<ValueId, u64> {
        let mut values = HashMap::new();
        for inst in &block.insts {
            let Some(dest) = inst.dest else { continue };
            let input = |index: usize| values[&inst.args[index]];
            let value = match &inst.op {
                IrOp::Undef => 0,
                IrOp::Const(value) => *value,
                IrOp::Copy | IrOp::Zext | IrOp::Trunc => input(0),
                IrOp::And => input(0) & input(1),
                IrOp::Or => input(0) | input(1),
                IrOp::Shr => input(0) >> (input(1) & 63),
                IrOp::Add => input(0).wrapping_add(input(1)),
                other => panic!("unexpected register sequence operation: {other:?}"),
            };
            let mask = match inst.ty {
                IrType::I64 | IrType::I128 => u64::MAX,
                _ => (1u64 << inst.ty.bits()) - 1,
            };
            values.insert(dest, value & mask);
        }
        values
    }

    #[test]
    fn high_byte_register_reads_extract_bits_fifteen_through_eight() {
        for (source, operand, literal, expected) in [
            (0xb8, 0xc4, 0x1122_3344_5566_7788u64, 0x78),
            (0xb9, 0xc5, 0x99aa_bbcc_ddee_ff11u64, 0x100),
            (0xba, 0xc6, 0x1122_3344_5566_12feu64, 0x13),
            (0xbb, 0xc7, 0x1122_3344_5566_8001u64, 0x81),
        ] {
            let mut code = vec![0x48, source];
            code.extend_from_slice(&literal.to_le_bytes());
            code.extend_from_slice(&[0x0f, 0xb6, operand, 0x48, 0x8d, 0x40, 1, 0xc3]);
            let (module, func) = single_block_module(&code, Terminator::Return);
            let lifted = lift_function(&module, &func, &Win64Default, &[]);
            assert!(!lifted.unsupported);
            let values = evaluate_gpr_sequence(&lifted.func.blocks[0]);
            assert_eq!(values[&lifted.block_exit[0][Gpr::Rax.index()]], expected);
        }
    }

    /// An 8-bit register write preserves the destination's upper bits, so
    /// `mov eax, 0x11223344; mov al, 0x99` must leave RAX == 0x11223399, not a
    /// zero-extended 0x99. Modeling the narrow write as a plain zero-extension
    /// silently discards the high bytes (the dormant partial-register bug).
    #[test]
    fn sub_register_write_preserves_upper_bits() {
        // B8 44 33 22 11  mov eax, 0x11223344
        // B0 99           mov al, 0x99
        // C3              ret
        let code = [0xB8, 0x44, 0x33, 0x22, 0x11, 0xB0, 0x99, 0xC3];
        let (module, func) = single_block_module(&code, Terminator::Return);
        let ir = lift_function(&module, &func, &Win64Default, &[]);

        assert_eq!(ir.func.blocks.len(), 1);
        let block = &ir.func.blocks[0];
        let rax_out = ir.block_exit[0][0];

        let vals = evaluate_gpr_sequence(block);

        assert_eq!(
            vals[&rax_out], 0x1122_3399,
            "mov al must merge into the live-in EAX, preserving bits 31:8"
        );
    }
}
