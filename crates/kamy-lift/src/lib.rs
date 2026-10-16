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

pub fn lift_function(module: &Module, func: &Function, cc: &dyn CallingConvLookup) -> LiftResult {
    let entry_rva = func.entry;

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

    let mut builder = IrBuilder::new(&mut ir_func, BlockId(0));

    for (i, bb) in ordered_bbs.iter().enumerate() {
        let block_id = BlockId(i as u32);
        builder.switch_to(block_id);
        let mut lift_state = LiftState::new_with_undefs(&mut builder);
        block_entry.push(lift_state.snapshot());

        let len = bb.end.get().saturating_sub(bb.start.get()) as usize;
        let bytes = match module.bytes_at(bb.start) {
            Some(b) => &b[..len.min(b.len())],
            None => &[],
        };
        let ip = module.image_base + u64::from(bb.start.get());

        let mut last_cond: Option<ValueId> = None;
        let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        while decoder.can_decode() {
            let start_pos = decoder.position();
            let insn = decoder.decode();
            if insn.is_invalid() {
                break;
            }
            let end_pos = decoder.position();
            let insn_bytes = &bytes[start_pos..end_pos];
            last_cond = dispatch(&insn, insn_bytes, &mut builder, &mut lift_state, cc);
        }

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
                    builder.set_terminator(IrTerminator::Tail { target: target_va });
                }
            }
            Terminator::Branch { taken, not_taken } => {
                let cond = last_cond.unwrap_or_else(|| builder.emit(IrOp::Undef, &[], IrType::I8));
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
            Terminator::Indirect { .. } | Terminator::Switch { .. } | Terminator::Unknown => {
                builder.set_terminator(IrTerminator::Unreachable);
            }
        }
        block_exit.push(lift_state.snapshot());
        rsp_chain.extend(&lift_state.rsp_chain);
        // Entry-block undefs are the true live-ins; non-entry undefs are SSA
        // placeholders construct_ssa rewrites away, so their pins become dead
        // keys. Call-return and ret-value pins may occur in any block.
        reg_pins.extend(&lift_state.reg_pins);
        unsupported |= lift_state.unsupported;
    }
    if ir_func
        .blocks
        .iter()
        .any(|b| matches!(b.term, IrTerminator::Unreachable))
    {
        // An unresolved terminator (tail-call jmp, indirect/switch jump) leaves
        // control flow unlowered; relocate verbatim.
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

fn dispatch(
    insn: &Instruction,
    insn_bytes: &[u8],
    builder: &mut IrBuilder,
    state: &mut LiftState,
    cc: &dyn CallingConvLookup,
) -> Option<ValueId> {
    match insn.flow_control() {
        FlowControl::Return => {
            control::lift_ret(builder, state);
            return None;
        }
        FlowControl::Call | FlowControl::IndirectCall => {
            if insn.op_kind(0) == OpKind::NearBranch64 {
                control::lift_call(insn, insn.near_branch_target(), builder, state, cc);
            } else {
                let target_val = match insn.op_kind(0) {
                    OpKind::Register => {
                        iced_reg_to_gpr(insn.op_register(0)).map(|g| state.get_gpr(g))
                    }
                    OpKind::Memory => {
                        let addr = compute_mem_addr(insn, builder, state);
                        Some(builder.emit(IrOp::Load, &[addr], IrType::I64))
                    }
                    _ => None,
                };
                match target_val {
                    Some(t) => control::lift_call_indirect(t, builder, state, cc),
                    None => state.unsupported = true,
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
            IrOp::RipAddr(insn.memory_displacement64()),
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

    if disp != 0 || addr.is_none() {
        let disp_val = b.emit(IrOp::Const(disp), &[], IrType::I64);
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
            (builder.emit(IrOp::Const(imm), &[], ty), ty)
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
                state.set_xmm(xmm, val);
                return;
            }
            if let Some(gpr) = iced_reg_to_gpr(reg) {
                if ty == IrType::I64 {
                    state.set_gpr(gpr, val);
                } else {
                    let extended = builder.emit(IrOp::Zext, &[val], IrType::I64);
                    state.set_gpr(gpr, extended);
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
    fn lift_add_rax_rcx_ret() {
        // 48 01 C8  = add rax, rcx
        // C3        = ret
        let code = [0x48, 0x01, 0xC8, 0xC3];
        let (module, func) = single_block_module(&code, Terminator::Return);
        let ir = lift_function(&module, &func, &Win64Default);

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

        let ir = lift_function(&module, &func, &Win64Default);

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
        let ir = lift_function(&module, &func, &Win64Default);

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
}
