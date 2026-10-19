use std::collections::HashMap;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, MemoryOperand, Register};
use kamy_core::ir::{
    BlockId, Gpr, IrFunction, IrOp, IrTerminator, IrType, PhysReg, ValueId, XmmReg,
};

use crate::regalloc::{RegAllocation, RegCopy};

// Synthetic branch-target labels: unique, non-zero IPs placed far above any real
// image VA. iced's BlockEncoder links a branch to an in-block instruction by
// matching the instruction's ip(); stamping each block's first instruction with
// its label lets intra-function branches resolve while real external targets
// (direct calls, tail-call VAs) never collide with these sentinels.
const LABEL_BASE: u64 = 0x7FFF_0000_0000;
const LANDING_BASE: u64 = 0x7FFF_8000_0000;

fn gpr_register(gpr: Gpr, ty: IrType) -> Register {
    match (gpr, ty) {
        (Gpr::Rax, IrType::I64) => Register::RAX,
        (Gpr::Rax, IrType::I32) => Register::EAX,
        (Gpr::Rax, IrType::I16) => Register::AX,
        (Gpr::Rax, IrType::I8) => Register::AL,
        (Gpr::Rcx, IrType::I64) => Register::RCX,
        (Gpr::Rcx, IrType::I32) => Register::ECX,
        (Gpr::Rcx, IrType::I16) => Register::CX,
        (Gpr::Rcx, IrType::I8) => Register::CL,
        (Gpr::Rdx, IrType::I64) => Register::RDX,
        (Gpr::Rdx, IrType::I32) => Register::EDX,
        (Gpr::Rdx, IrType::I16) => Register::DX,
        (Gpr::Rdx, IrType::I8) => Register::DL,
        (Gpr::Rbx, IrType::I64) => Register::RBX,
        (Gpr::Rbx, IrType::I32) => Register::EBX,
        (Gpr::Rbx, IrType::I16) => Register::BX,
        (Gpr::Rbx, IrType::I8) => Register::BL,
        (Gpr::Rsp, IrType::I64) => Register::RSP,
        (Gpr::Rsp, IrType::I32) => Register::ESP,
        (Gpr::Rsp, IrType::I16) => Register::SP,
        (Gpr::Rsp, IrType::I8) => Register::SPL,
        (Gpr::Rbp, IrType::I64) => Register::RBP,
        (Gpr::Rbp, IrType::I32) => Register::EBP,
        (Gpr::Rbp, IrType::I16) => Register::BP,
        (Gpr::Rbp, IrType::I8) => Register::BPL,
        (Gpr::Rsi, IrType::I64) => Register::RSI,
        (Gpr::Rsi, IrType::I32) => Register::ESI,
        (Gpr::Rsi, IrType::I16) => Register::SI,
        (Gpr::Rsi, IrType::I8) => Register::SIL,
        (Gpr::Rdi, IrType::I64) => Register::RDI,
        (Gpr::Rdi, IrType::I32) => Register::EDI,
        (Gpr::Rdi, IrType::I16) => Register::DI,
        (Gpr::Rdi, IrType::I8) => Register::DIL,
        (Gpr::R8, IrType::I64) => Register::R8,
        (Gpr::R8, IrType::I32) => Register::R8D,
        (Gpr::R8, IrType::I16) => Register::R8W,
        (Gpr::R8, IrType::I8) => Register::R8L,
        (Gpr::R9, IrType::I64) => Register::R9,
        (Gpr::R9, IrType::I32) => Register::R9D,
        (Gpr::R9, IrType::I16) => Register::R9W,
        (Gpr::R9, IrType::I8) => Register::R9L,
        (Gpr::R10, IrType::I64) => Register::R10,
        (Gpr::R10, IrType::I32) => Register::R10D,
        (Gpr::R10, IrType::I16) => Register::R10W,
        (Gpr::R10, IrType::I8) => Register::R10L,
        (Gpr::R11, IrType::I64) => Register::R11,
        (Gpr::R11, IrType::I32) => Register::R11D,
        (Gpr::R11, IrType::I16) => Register::R11W,
        (Gpr::R11, IrType::I8) => Register::R11L,
        (Gpr::R12, IrType::I64) => Register::R12,
        (Gpr::R12, IrType::I32) => Register::R12D,
        (Gpr::R12, IrType::I16) => Register::R12W,
        (Gpr::R12, IrType::I8) => Register::R12L,
        (Gpr::R13, IrType::I64) => Register::R13,
        (Gpr::R13, IrType::I32) => Register::R13D,
        (Gpr::R13, IrType::I16) => Register::R13W,
        (Gpr::R13, IrType::I8) => Register::R13L,
        (Gpr::R14, IrType::I64) => Register::R14,
        (Gpr::R14, IrType::I32) => Register::R14D,
        (Gpr::R14, IrType::I16) => Register::R14W,
        (Gpr::R14, IrType::I8) => Register::R14L,
        (Gpr::R15, IrType::I64) => Register::R15,
        (Gpr::R15, IrType::I32) => Register::R15D,
        (Gpr::R15, IrType::I16) => Register::R15W,
        (Gpr::R15, IrType::I8) => Register::R15L,
        (_, IrType::I128) => gpr_register(gpr, IrType::I64),
    }
}

fn xmm_register(xmm: XmmReg) -> Register {
    match xmm {
        XmmReg::Xmm0 => Register::XMM0,
        XmmReg::Xmm1 => Register::XMM1,
        XmmReg::Xmm2 => Register::XMM2,
        XmmReg::Xmm3 => Register::XMM3,
        XmmReg::Xmm4 => Register::XMM4,
        XmmReg::Xmm5 => Register::XMM5,
        XmmReg::Xmm6 => Register::XMM6,
        XmmReg::Xmm7 => Register::XMM7,
        XmmReg::Xmm8 => Register::XMM8,
        XmmReg::Xmm9 => Register::XMM9,
        XmmReg::Xmm10 => Register::XMM10,
        XmmReg::Xmm11 => Register::XMM11,
        XmmReg::Xmm12 => Register::XMM12,
        XmmReg::Xmm13 => Register::XMM13,
        XmmReg::Xmm14 => Register::XMM14,
        XmmReg::Xmm15 => Register::XMM15,
    }
}

fn phys_to_register(phys: PhysReg, ty: IrType) -> Register {
    match phys {
        PhysReg::Gpr(g) => gpr_register(g, ty),
        PhysReg::Xmm(x) => xmm_register(x),
        PhysReg::Flag(_) => gpr_register(Gpr::Rax, IrType::I8),
    }
}

fn reg_of(alloc: &RegAllocation, vid: ValueId, ty: IrType) -> Register {
    let phys = alloc.assignments[&vid];
    phys_to_register(phys, ty)
}

fn alu_code(op: &IrOp, ty: IrType) -> Code {
    match (op, ty) {
        (IrOp::Add, IrType::I64) => Code::Add_rm64_r64,
        (IrOp::Add, IrType::I32) => Code::Add_rm32_r32,
        (IrOp::Add, IrType::I16) => Code::Add_rm16_r16,
        (IrOp::Add, IrType::I8) => Code::Add_rm8_r8,
        (IrOp::Sub, IrType::I64) => Code::Sub_rm64_r64,
        (IrOp::Sub, IrType::I32) => Code::Sub_rm32_r32,
        (IrOp::Sub, IrType::I16) => Code::Sub_rm16_r16,
        (IrOp::Sub, IrType::I8) => Code::Sub_rm8_r8,
        (IrOp::And, IrType::I64) => Code::And_rm64_r64,
        (IrOp::And, IrType::I32) => Code::And_rm32_r32,
        (IrOp::And, IrType::I16) => Code::And_rm16_r16,
        (IrOp::And, IrType::I8) => Code::And_rm8_r8,
        (IrOp::Or, IrType::I64) => Code::Or_rm64_r64,
        (IrOp::Or, IrType::I32) => Code::Or_rm32_r32,
        (IrOp::Or, IrType::I16) => Code::Or_rm16_r16,
        (IrOp::Or, IrType::I8) => Code::Or_rm8_r8,
        (IrOp::Xor, IrType::I64) => Code::Xor_rm64_r64,
        (IrOp::Xor, IrType::I32) => Code::Xor_rm32_r32,
        (IrOp::Xor, IrType::I16) => Code::Xor_rm16_r16,
        (IrOp::Xor, IrType::I8) => Code::Xor_rm8_r8,
        _ => Code::Nopd,
    }
}

fn shift_code(op: &IrOp, ty: IrType) -> Code {
    match (op, ty) {
        (IrOp::Shl, IrType::I64) => Code::Shl_rm64_CL,
        (IrOp::Shl, IrType::I32) => Code::Shl_rm32_CL,
        (IrOp::Shl, IrType::I16) => Code::Shl_rm16_CL,
        (IrOp::Shl, IrType::I8) => Code::Shl_rm8_CL,
        (IrOp::Shr, IrType::I64) => Code::Shr_rm64_CL,
        (IrOp::Shr, IrType::I32) => Code::Shr_rm32_CL,
        (IrOp::Shr, IrType::I16) => Code::Shr_rm16_CL,
        (IrOp::Shr, IrType::I8) => Code::Shr_rm8_CL,
        (IrOp::Sar, IrType::I64) => Code::Sar_rm64_CL,
        (IrOp::Sar, IrType::I32) => Code::Sar_rm32_CL,
        (IrOp::Sar, IrType::I16) => Code::Sar_rm16_CL,
        (IrOp::Sar, IrType::I8) => Code::Sar_rm8_CL,
        (IrOp::Rol, IrType::I64) => Code::Rol_rm64_CL,
        (IrOp::Rol, IrType::I32) => Code::Rol_rm32_CL,
        (IrOp::Rol, IrType::I16) => Code::Rol_rm16_CL,
        (IrOp::Rol, IrType::I8) => Code::Rol_rm8_CL,
        (IrOp::Ror, IrType::I64) => Code::Ror_rm64_CL,
        (IrOp::Ror, IrType::I32) => Code::Ror_rm32_CL,
        (IrOp::Ror, IrType::I16) => Code::Ror_rm16_CL,
        (IrOp::Ror, IrType::I8) => Code::Ror_rm8_CL,
        _ => Code::Nopd,
    }
}

fn mov_code(ty: IrType) -> Code {
    match ty {
        IrType::I64 | IrType::I128 => Code::Mov_r64_rm64,
        IrType::I32 => Code::Mov_r32_rm32,
        IrType::I16 => Code::Mov_r16_rm16,
        IrType::I8 => Code::Mov_r8_rm8,
    }
}

fn const_value(func: &IrFunction, vid: ValueId) -> Option<u64> {
    func.blocks.iter().find_map(|b| {
        b.insts.iter().find_map(|i| match (i.dest, &i.op) {
            (Some(d), IrOp::Const(c)) if d == vid => Some(*c),
            _ => None,
        })
    })
}

fn shift_imm_code(op: &IrOp, ty: IrType) -> Code {
    match (op, ty) {
        (IrOp::Shl, IrType::I64) => Code::Shl_rm64_imm8,
        (IrOp::Shl, IrType::I32) => Code::Shl_rm32_imm8,
        (IrOp::Shl, IrType::I16) => Code::Shl_rm16_imm8,
        (IrOp::Shl, IrType::I8) => Code::Shl_rm8_imm8,
        (IrOp::Shr, IrType::I64) => Code::Shr_rm64_imm8,
        (IrOp::Shr, IrType::I32) => Code::Shr_rm32_imm8,
        (IrOp::Shr, IrType::I16) => Code::Shr_rm16_imm8,
        (IrOp::Shr, IrType::I8) => Code::Shr_rm8_imm8,
        (IrOp::Sar, IrType::I64) => Code::Sar_rm64_imm8,
        (IrOp::Sar, IrType::I32) => Code::Sar_rm32_imm8,
        (IrOp::Sar, IrType::I16) => Code::Sar_rm16_imm8,
        (IrOp::Sar, IrType::I8) => Code::Sar_rm8_imm8,
        (IrOp::Rol, IrType::I64) => Code::Rol_rm64_imm8,
        (IrOp::Rol, IrType::I32) => Code::Rol_rm32_imm8,
        (IrOp::Rol, IrType::I16) => Code::Rol_rm16_imm8,
        (IrOp::Rol, IrType::I8) => Code::Rol_rm8_imm8,
        (IrOp::Ror, IrType::I64) => Code::Ror_rm64_imm8,
        (IrOp::Ror, IrType::I32) => Code::Ror_rm32_imm8,
        (IrOp::Ror, IrType::I16) => Code::Ror_rm16_imm8,
        (IrOp::Ror, IrType::I8) => Code::Ror_rm8_imm8,
        _ => Code::Nopd,
    }
}

fn neg_code(ty: IrType) -> Code {
    match ty {
        IrType::I64 | IrType::I128 => Code::Neg_rm64,
        IrType::I32 => Code::Neg_rm32,
        IrType::I16 => Code::Neg_rm16,
        IrType::I8 => Code::Neg_rm8,
    }
}

fn not_code(ty: IrType) -> Code {
    match ty {
        IrType::I64 | IrType::I128 => Code::Not_rm64,
        IrType::I32 => Code::Not_rm32,
        IrType::I16 => Code::Not_rm16,
        IrType::I8 => Code::Not_rm8,
    }
}

fn test_code(ty: IrType) -> Code {
    match ty {
        IrType::I64 | IrType::I128 => Code::Test_rm64_r64,
        IrType::I32 => Code::Test_rm32_r32,
        IrType::I16 => Code::Test_rm16_r16,
        IrType::I8 => Code::Test_rm8_r8,
    }
}

fn cmp_code(ty: IrType) -> Code {
    match ty {
        IrType::I64 | IrType::I128 => Code::Cmp_rm64_r64,
        IrType::I32 => Code::Cmp_rm32_r32,
        IrType::I16 => Code::Cmp_rm16_r16,
        IrType::I8 => Code::Cmp_rm8_r8,
    }
}

/// Emit the x86 instruction that sets the flags a flag op reads. `IsZero`/
/// `IsNeg`/`Parity` reflect the real result value (`test r,r`); the subtract
/// comparison flags are the flags of `a - b` (`cmp a,b`). Add- and shift-based
/// flag ops reach codegen only via a branch/materialization and are rejected
/// before this point (their flags are not reconstructible without a scratch).
fn emit_flag_compare(
    func: &IrFunction,
    alloc: &RegAllocation,
    producer: &kamy_core::ir::Inst,
    out: &mut Vec<Instruction>,
) {
    match &producer.op {
        IrOp::IsZero | IrOp::IsNeg | IrOp::Parity => {
            if let Some(&arg) = producer.args.first() {
                let ty = value_type(func, arg);
                let reg = reg_of(alloc, arg, ty);
                out.push(Instruction::with2(test_code(ty), reg, reg).unwrap());
            }
        }
        IrOp::BorrowSub | IrOp::OverflowSub | IrOp::AuxBorrowSub => {
            let a = producer.args[0];
            let b = producer.args[1];
            let ty = value_type(func, a);
            let ra = reg_of(alloc, a, ty);
            let rb = reg_of(alloc, b, ty);
            out.push(Instruction::with2(cmp_code(ty), ra, rb).unwrap());
        }
        IrOp::CarryAdd | IrOp::OverflowAdd | IrOp::AuxCarryAdd => {
            let a = producer.args[0];
            let b = producer.args[1];
            let ty = value_type(func, a);
            let ra = reg_of(alloc, a, ty);
            let rb = reg_of(alloc, b, ty);
            let scratch = phys_to_register(alloc.flag_scratch.expect("flag scratch reserved"), ty);
            out.push(Instruction::with2(mov_code(ty), scratch, ra).unwrap());
            out.push(Instruction::with2(alu_code(&IrOp::Add, ty), scratch, rb).unwrap());
        }
        IrOp::CarryShl | IrOp::CarryShr | IrOp::CarrySar => {
            let orig = producer.args[0];
            let count = producer.args[1];
            let ty = value_type(func, orig);
            let ro = reg_of(alloc, orig, ty);
            let scratch = phys_to_register(alloc.flag_scratch.expect("flag scratch reserved"), ty);
            let shift_kind = match producer.op {
                IrOp::CarryShl => IrOp::Shl,
                IrOp::CarryShr => IrOp::Shr,
                _ => IrOp::Sar,
            };
            out.push(Instruction::with2(mov_code(ty), scratch, ro).unwrap());
            out.push(
                Instruction::with2(
                    shift_imm_code(&shift_kind, ty),
                    scratch,
                    const_value(func, count).expect("const count") as i32,
                )
                .unwrap(),
            );
        }
        _ => {}
    }
}

fn load_code(ty: IrType) -> Code {
    match ty {
        IrType::I64 | IrType::I128 => Code::Mov_r64_rm64,
        IrType::I32 => Code::Mov_r32_rm32,
        IrType::I16 => Code::Mov_r16_rm16,
        IrType::I8 => Code::Mov_r8_rm8,
    }
}

fn store_code(ty: IrType) -> Code {
    match ty {
        IrType::I64 | IrType::I128 => Code::Mov_rm64_r64,
        IrType::I32 => Code::Mov_rm32_r32,
        IrType::I16 => Code::Mov_rm16_r16,
        IrType::I8 => Code::Mov_rm8_r8,
    }
}

fn is_xmm(phys: PhysReg) -> bool {
    matches!(phys, PhysReg::Xmm(_))
}

/// SSE move for a memory→XMM load of `ty` bytes. Only I32 (movss), I64 (movsd),
/// and I128 (movups) ever reach an XMM operand; narrower widths have no SSE
/// producer.
fn xmm_load_code(ty: IrType) -> Code {
    match ty {
        IrType::I32 => Code::Movss_xmm_xmmm32,
        IrType::I64 => Code::Movsd_xmm_xmmm64,
        _ => Code::Movups_xmm_xmmm128,
    }
}

fn xmm_store_code(ty: IrType) -> Code {
    match ty {
        IrType::I32 => Code::Movss_xmmm32_xmm,
        IrType::I64 => Code::Movsd_xmmm64_xmm,
        _ => Code::Movups_xmmm128_xmm,
    }
}

fn emit_copy(out: &mut Vec<Instruction>, copy: &RegCopy) {
    let from_reg = phys_to_register(copy.from, copy.ty);
    let to_reg = phys_to_register(copy.to, copy.ty);
    let code = if is_xmm(copy.from) || is_xmm(copy.to) {
        Code::Movaps_xmm_xmmm128
    } else {
        mov_code(copy.ty)
    };
    out.push(Instruction::with2(code, to_reg, from_reg).unwrap());
}

fn block_order(func: &IrFunction) -> Vec<BlockId> {
    let mut order = Vec::with_capacity(func.blocks.len());
    let mut visited = vec![false; func.blocks.len()];
    let mut stack = vec![func.entry];
    while let Some(bid) = stack.pop() {
        let idx = bid.0 as usize;
        if idx >= visited.len() || visited[idx] {
            continue;
        }
        visited[idx] = true;
        order.push(bid);
        let block = func.block(bid);
        match &block.term {
            IrTerminator::Jump(t) => stack.push(*t),
            IrTerminator::Branch {
                taken, not_taken, ..
            } => {
                stack.push(*not_taken);
                stack.push(*taken);
            }
            IrTerminator::Ret | IrTerminator::Tail { .. } | IrTerminator::Unreachable => {}
        }
    }
    order
}

fn is_branch_cond_producer(func: &IrFunction, vid: ValueId) -> bool {
    for block in &func.blocks {
        if let IrTerminator::Branch { cond, .. } = &block.term {
            if *cond == vid {
                return true;
            }
        }
    }
    false
}

fn value_type(func: &IrFunction, vid: ValueId) -> IrType {
    for block in &func.blocks {
        for phi in &block.phis {
            if phi.dest == vid {
                return phi.ty;
            }
        }
        for inst in &block.insts {
            if inst.dest == Some(vid) {
                return inst.ty;
            }
        }
    }
    IrType::I64
}

fn flag_op_to_setcc(op: &IrOp) -> Code {
    match op {
        IrOp::IsZero => Code::Sete_rm8,
        IrOp::IsNeg => Code::Sets_rm8,
        IrOp::Parity => Code::Setp_rm8,
        IrOp::CarryAdd | IrOp::CarryShl | IrOp::CarryShr | IrOp::CarrySar => Code::Setb_rm8,
        IrOp::BorrowSub => Code::Setb_rm8,
        IrOp::OverflowAdd | IrOp::OverflowSub => Code::Seto_rm8,
        IrOp::AuxCarryAdd | IrOp::AuxBorrowSub => Code::Seta_rm8,
        _ => Code::Sete_rm8,
    }
}

fn flag_op_to_jcc(op: &IrOp) -> Code {
    match op {
        IrOp::IsZero => Code::Je_rel32_64,
        IrOp::IsNeg => Code::Js_rel32_64,
        IrOp::Parity => Code::Jp_rel32_64,
        IrOp::CarryAdd | IrOp::CarryShl | IrOp::CarryShr | IrOp::CarrySar => Code::Jb_rel32_64,
        IrOp::BorrowSub => Code::Jb_rel32_64,
        IrOp::OverflowAdd | IrOp::OverflowSub => Code::Jo_rel32_64,
        IrOp::AuxCarryAdd | IrOp::AuxBorrowSub => Code::Ja_rel32_64,
        _ => Code::Je_rel32_64,
    }
}

pub fn select_instructions(
    func: &IrFunction,
    alloc: &RegAllocation,
    _image_base: u64,
    _entry_va: u64,
    callee_saved_used: &[Register],
    callee_saved_xmms: &[Register],
) -> Vec<Instruction> {
    let order = block_order(func);
    let mut out: Vec<Instruction> = Vec::new();
    let mut block_labels: HashMap<BlockId, u64> = HashMap::new();
    for (bi, &bid) in order.iter().enumerate() {
        block_labels.insert(bid, LABEL_BASE + (bi as u64) * 0x1000);
    }

    let mut copy_map: HashMap<usize, Vec<&RegCopy>> = HashMap::new();
    for c in &alloc.copies {
        copy_map.entry(c.point).or_default().push(c);
    }

    for &r in callee_saved_used {
        out.push(Instruction::with1(Code::Push_r64, r).unwrap());
    }
    // Entry RSP ≡ 8 (mod 16). Each 8-byte push flips 16-alignment parity, so an
    // odd push count needs an 8-byte pad; each nonvolatile XMM save adds 16. The
    // combined `sub rsp, stack_alloc` is a multiple of 16, so the lowered body
    // still sees the %16==8 it was compiled for.
    let align_pad: u32 = if callee_saved_used.len() % 2 == 1 {
        8
    } else {
        0
    };
    let stack_alloc: u32 = align_pad + 16 * callee_saved_xmms.len() as u32;
    if stack_alloc > 0 {
        let code = if stack_alloc <= 127 {
            Code::Sub_rm64_imm8
        } else {
            Code::Sub_rm64_imm32
        };
        out.push(Instruction::with2(code, Register::RSP, stack_alloc as i32).unwrap());
    }
    // The save area sits at %16==8, so movups (unaligned), not movaps.
    for (i, &x) in callee_saved_xmms.iter().enumerate() {
        let mem = MemoryOperand::with_base_displ(Register::RSP, (16 * i) as i64);
        out.push(Instruction::with2(Code::Movups_xmmm128_xmm, mem, x).unwrap());
    }

    // A critical edge (branch predecessor -> phi-carrying successor) gets its own
    // landing block holding that edge's phi copies; collected here and emitted
    // after the body so real blocks keep their fallthrough order.
    let mut landings: Vec<(u64, BlockId, BlockId)> = Vec::new();
    let mut next_landing: u64 = LANDING_BASE;

    for (bi, &bid) in order.iter().enumerate() {
        let block = func.block(bid);
        let phi_offset = block.phis.len();
        let block_start = out.len();

        for (ii, inst) in block.insts.iter().enumerate() {
            // Mirror regalloc's `linear_point(bi, phi_offset + ii)` so eviction
            // copies land at the right instruction in multi-block functions.
            let point = bi * 1024 + phi_offset + ii;
            if let Some(copies) = copy_map.get(&point) {
                for c in copies {
                    emit_copy(&mut out, c);
                }
            }

            select_inst(func, alloc, inst, &block_labels, &mut out);
        }

        if matches!(block.term, IrTerminator::Ret | IrTerminator::Tail { .. }) {
            for (i, &x) in callee_saved_xmms.iter().enumerate() {
                let mem = MemoryOperand::with_base_displ(Register::RSP, (16 * i) as i64);
                out.push(Instruction::with2(Code::Movups_xmm_xmmm128, x, mem).unwrap());
            }
            if stack_alloc > 0 {
                let code = if stack_alloc <= 127 {
                    Code::Add_rm64_imm8
                } else {
                    Code::Add_rm64_imm32
                };
                out.push(Instruction::with2(code, Register::RSP, stack_alloc as i32).unwrap());
            }
            for &r in callee_saved_used.iter().rev() {
                out.push(Instruction::with1(Code::Pop_r64, r).unwrap());
            }
        }
        select_terminator(
            func,
            alloc,
            bid,
            &block.term,
            &block_labels,
            &mut landings,
            &mut next_landing,
            &mut out,
        );

        // Every block emits at least a terminator; stamp its first instruction
        // with the block label so branches here resolve.
        out[block_start].set_ip(block_labels[&bid]);
    }

    for (label, pred, succ) in landings {
        let start = out.len();
        if let Some(copies) = alloc.edge_copies.get(&(pred, succ)) {
            for c in copies {
                emit_copy(&mut out, c);
            }
        }
        out.push(Instruction::with_branch(Code::Jmp_rel32_64, block_labels[&succ]).unwrap());
        out[start].set_ip(label);
    }

    out
}

fn select_inst(
    func: &IrFunction,
    alloc: &RegAllocation,
    inst: &kamy_core::ir::Inst,
    _block_labels: &HashMap<BlockId, u64>,
    out: &mut Vec<Instruction>,
) {
    let ty = inst.ty;

    match &inst.op {
        IrOp::Const(imm) => {
            let dest = inst.dest.unwrap();
            let dest_reg = reg_of(alloc, dest, ty);
            if *imm == 0 {
                if is_xmm(alloc.assignments[&dest]) {
                    out.push(
                        Instruction::with2(Code::Xorps_xmm_xmmm128, dest_reg, dest_reg).unwrap(),
                    );
                    return;
                }
                let xor_code = match ty {
                    IrType::I64 | IrType::I128 => Code::Xor_rm32_r32,
                    IrType::I32 => Code::Xor_rm32_r32,
                    IrType::I16 => Code::Xor_rm16_r16,
                    IrType::I8 => Code::Xor_rm8_r8,
                };
                let zero_reg = if matches!(ty, IrType::I64 | IrType::I128) {
                    phys_to_register(alloc.assignments[&dest], IrType::I32)
                } else {
                    dest_reg
                };
                out.push(Instruction::with2(xor_code, zero_reg, zero_reg).unwrap());
            } else {
                match ty {
                    IrType::I64 | IrType::I128 => {
                        out.push(Instruction::with2(Code::Mov_r64_imm64, dest_reg, *imm).unwrap());
                    }
                    IrType::I32 => {
                        out.push(
                            Instruction::with2(Code::Mov_r32_imm32, dest_reg, *imm as u32).unwrap(),
                        );
                    }
                    IrType::I16 => {
                        out.push(
                            Instruction::with2(Code::Mov_r16_imm16, dest_reg, *imm as u32).unwrap(),
                        );
                    }
                    IrType::I8 => {
                        out.push(
                            Instruction::with2(Code::Mov_r8_imm8, dest_reg, *imm as u32).unwrap(),
                        );
                    }
                }
            }
        }

        IrOp::RipAddr(target) => {
            let dest = inst.dest.unwrap();
            let dest_reg = reg_of(alloc, dest, IrType::I64);
            let mut lea = Instruction::with2(
                Code::Lea_r64_m,
                dest_reg,
                MemoryOperand::with_base(Register::RIP),
            )
            .unwrap();
            lea.set_memory_displacement64(*target);
            out.push(lea);
        }

        IrOp::Copy => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            match (
                is_xmm(alloc.assignments[&dest]),
                is_xmm(alloc.assignments[&src]),
            ) {
                (false, false) => {
                    let dest_reg = reg_of(alloc, dest, ty);
                    let src_ty = value_type(func, src);
                    let src_reg = reg_of(alloc, src, src_ty);
                    if dest_reg != src_reg {
                        out.push(Instruction::with2(mov_code(ty), dest_reg, src_reg).unwrap());
                    }
                }
                (true, true) => {
                    let dest_reg = reg_of(alloc, dest, IrType::I128);
                    let src_reg = reg_of(alloc, src, IrType::I128);
                    if dest_reg != src_reg {
                        out.push(
                            Instruction::with2(Code::Movaps_xmm_xmmm128, dest_reg, src_reg)
                                .unwrap(),
                        );
                    }
                }
                (true, false) => {
                    let dest_reg = reg_of(alloc, dest, IrType::I128);
                    let src_reg = reg_of(alloc, src, IrType::I64);
                    out.push(Instruction::with2(Code::Movq_xmm_rm64, dest_reg, src_reg).unwrap());
                }
                (false, true) => {
                    let dest_reg = reg_of(alloc, dest, IrType::I64);
                    let src_reg = reg_of(alloc, src, IrType::I128);
                    out.push(Instruction::with2(Code::Movq_rm64_xmm, dest_reg, src_reg).unwrap());
                }
            }
        }

        IrOp::Add | IrOp::Sub | IrOp::And | IrOp::Or | IrOp::Xor => {
            let dest = inst.dest.unwrap();
            let lhs = inst.args[0];
            let rhs = inst.args[1];
            if is_xmm(alloc.assignments[&dest]) {
                // Only xorps (Xor) produces an XMM ALU value; packed logical op.
                let dest_reg = reg_of(alloc, dest, IrType::I128);
                let lhs_reg = reg_of(alloc, lhs, IrType::I128);
                let rhs_reg = reg_of(alloc, rhs, IrType::I128);
                if dest_reg == rhs_reg {
                    out.push(
                        Instruction::with2(Code::Xorps_xmm_xmmm128, dest_reg, lhs_reg).unwrap(),
                    );
                } else {
                    if dest_reg != lhs_reg {
                        out.push(
                            Instruction::with2(Code::Movaps_xmm_xmmm128, dest_reg, lhs_reg)
                                .unwrap(),
                        );
                    }
                    out.push(
                        Instruction::with2(Code::Xorps_xmm_xmmm128, dest_reg, rhs_reg).unwrap(),
                    );
                }
                return;
            }
            let dest_reg = reg_of(alloc, dest, ty);
            let lhs_reg = reg_of(alloc, lhs, ty);
            let rhs_reg = reg_of(alloc, rhs, ty);
            let code = alu_code(&inst.op, ty);
            if dest_reg == rhs_reg && dest_reg != lhs_reg {
                // `dest` already holds rhs; `mov dest, lhs` would clobber it before
                // the op reads it. Commute (dest = rhs OP lhs) for commutative ops;
                // Sub is dest = -(rhs) + lhs.
                if matches!(inst.op, IrOp::Sub) {
                    out.push(Instruction::with1(neg_code(ty), dest_reg).unwrap());
                    out.push(
                        Instruction::with2(alu_code(&IrOp::Add, ty), dest_reg, lhs_reg).unwrap(),
                    );
                } else {
                    out.push(Instruction::with2(code, dest_reg, lhs_reg).unwrap());
                }
            } else {
                if dest_reg != lhs_reg {
                    out.push(Instruction::with2(mov_code(ty), dest_reg, lhs_reg).unwrap());
                }
                out.push(Instruction::with2(code, dest_reg, rhs_reg).unwrap());
            }
        }

        IrOp::Neg => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_reg = reg_of(alloc, src, ty);
            if dest_reg != src_reg {
                out.push(Instruction::with2(mov_code(ty), dest_reg, src_reg).unwrap());
            }
            out.push(Instruction::with1(neg_code(ty), dest_reg).unwrap());
        }

        IrOp::Not => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_reg = reg_of(alloc, src, ty);
            if dest_reg != src_reg {
                out.push(Instruction::with2(mov_code(ty), dest_reg, src_reg).unwrap());
            }
            out.push(Instruction::with1(not_code(ty), dest_reg).unwrap());
        }

        IrOp::BoolNot => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, IrType::I8);
            let src_reg = reg_of(alloc, src, IrType::I8);
            if dest_reg != src_reg {
                out.push(Instruction::with2(mov_code(IrType::I8), dest_reg, src_reg).unwrap());
            }
            // Logical not of a 0/1 flag boolean: flip the low bit only, keeping
            // the value in {0,1}. Bitwise `not` would make it 0xFE/0xFF.
            out.push(Instruction::with2(Code::Xor_rm8_imm8, dest_reg, 1i32).unwrap());
        }

        IrOp::Shl | IrOp::Shr | IrOp::Sar | IrOp::Rol | IrOp::Ror => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_reg = reg_of(alloc, src, ty);
            if dest_reg != src_reg {
                out.push(Instruction::with2(mov_code(ty), dest_reg, src_reg).unwrap());
            }
            let count = inst.args[1];
            // A constant count lowers to the immediate form, which never touches
            // CL/RCX. The allocator does not model the CL clobber, so the runtime
            // path is kept only for a genuine non-constant count.
            if let Some(c) = const_value(func, count).filter(|c| *c < u64::from(ty.bits())) {
                let code = shift_imm_code(&inst.op, ty);
                out.push(Instruction::with2(code, dest_reg, c as i32).unwrap());
            } else {
                let count_reg = reg_of(alloc, count, IrType::I8);
                if count_reg != Register::CL {
                    out.push(
                        Instruction::with2(Code::Mov_r8_rm8, Register::CL, count_reg).unwrap(),
                    );
                }
                let code = shift_code(&inst.op, ty);
                out.push(Instruction::with2(code, dest_reg, Register::CL).unwrap());
            }
        }

        IrOp::Mul => {
            let dest = inst.dest.unwrap();
            let lhs = inst.args[0];
            let rhs = inst.args[1];
            let dest_reg = reg_of(alloc, dest, ty);
            let lhs_reg = reg_of(alloc, lhs, ty);
            let rhs_reg = reg_of(alloc, rhs, ty);
            let code = match ty {
                IrType::I64 | IrType::I128 => Code::Imul_r64_rm64,
                IrType::I32 => Code::Imul_r32_rm32,
                IrType::I16 => Code::Imul_r16_rm16,
                _ => Code::Imul_r32_rm32,
            };
            if dest_reg != lhs_reg {
                out.push(Instruction::with2(mov_code(ty), dest_reg, lhs_reg).unwrap());
            }
            out.push(Instruction::with2(code, dest_reg, rhs_reg).unwrap());
        }

        IrOp::Load => {
            let dest = inst.dest.unwrap();
            let addr = inst.args[0];
            let addr_reg = reg_of(alloc, addr, IrType::I64);
            let mem = MemoryOperand::with_base(addr_reg);
            if is_xmm(alloc.assignments[&dest]) {
                let dest_reg = reg_of(alloc, dest, IrType::I128);
                out.push(Instruction::with2(xmm_load_code(ty), dest_reg, mem).unwrap());
            } else {
                let dest_reg = reg_of(alloc, dest, ty);
                out.push(Instruction::with2(load_code(ty), dest_reg, mem).unwrap());
            }
        }

        IrOp::Store => {
            let addr = inst.args[0];
            let val = inst.args[1];
            let addr_reg = reg_of(alloc, addr, IrType::I64);
            let mem = MemoryOperand::with_base(addr_reg);
            if is_xmm(alloc.assignments[&val]) {
                let val_reg = reg_of(alloc, val, IrType::I128);
                out.push(Instruction::with2(xmm_store_code(ty), mem, val_reg).unwrap());
            } else {
                let val_reg = reg_of(alloc, val, ty);
                out.push(Instruction::with2(store_code(ty), mem, val_reg).unwrap());
            }
        }

        IrOp::Zext => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_ty = value_type(func, src);
            let src_reg = reg_of(alloc, src, src_ty);
            let code = match (src_ty, ty) {
                (IrType::I8, IrType::I16) => Code::Movzx_r16_rm8,
                (IrType::I8, IrType::I32) => Code::Movzx_r32_rm8,
                (IrType::I8, IrType::I64) => Code::Movzx_r64_rm8,
                (IrType::I16, IrType::I32) => Code::Movzx_r32_rm16,
                (IrType::I16, IrType::I64) => Code::Movzx_r64_rm16,
                (IrType::I32, IrType::I64) => {
                    let dest32 = phys_to_register(alloc.assignments[&dest], IrType::I32);
                    let src32 = phys_to_register(alloc.assignments[&src], IrType::I32);
                    out.push(Instruction::with2(Code::Mov_r32_rm32, dest32, src32).unwrap());
                    return;
                }
                _ => {
                    out.push(Instruction::with2(mov_code(ty), dest_reg, src_reg).unwrap());
                    return;
                }
            };
            out.push(Instruction::with2(code, dest_reg, src_reg).unwrap());
        }

        IrOp::Sext => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_ty = value_type(func, src);
            let src_reg = reg_of(alloc, src, src_ty);
            let code = match (src_ty, ty) {
                (IrType::I8, IrType::I16) => Code::Movsx_r16_rm8,
                (IrType::I8, IrType::I32) => Code::Movsx_r32_rm8,
                (IrType::I8, IrType::I64) => Code::Movsx_r64_rm8,
                (IrType::I16, IrType::I32) => Code::Movsx_r32_rm16,
                (IrType::I16, IrType::I64) => Code::Movsx_r64_rm16,
                (IrType::I32, IrType::I64) => Code::Movsxd_r64_rm32,
                _ => {
                    out.push(Instruction::with2(mov_code(ty), dest_reg, src_reg).unwrap());
                    return;
                }
            };
            out.push(Instruction::with2(code, dest_reg, src_reg).unwrap());
        }

        IrOp::Trunc => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let _src_ty = value_type(func, src);
            let src_reg = phys_to_register(alloc.assignments[&src], ty);
            if dest_reg != src_reg {
                out.push(Instruction::with2(mov_code(ty), dest_reg, src_reg).unwrap());
            }
        }

        IrOp::IsZero
        | IrOp::IsNeg
        | IrOp::Parity
        | IrOp::CarryAdd
        | IrOp::OverflowAdd
        | IrOp::BorrowSub
        | IrOp::OverflowSub
        | IrOp::AuxCarryAdd
        | IrOp::AuxBorrowSub
        | IrOp::CarryShl
        | IrOp::CarryShr
        | IrOp::CarrySar => {
            let dest = inst.dest.unwrap();
            if is_branch_cond_producer(func, dest) {
                return;
            }
            let dest_reg = reg_of(alloc, dest, IrType::I8);
            emit_flag_compare(func, alloc, inst, out);
            let setcc = flag_op_to_setcc(&inst.op);
            out.push(Instruction::with1(setcc, dest_reg).unwrap());
        }

        IrOp::SetIf => {
            let dest = inst.dest.unwrap();
            let cond = inst.args[0];
            let dest_reg = reg_of(alloc, dest, IrType::I8);
            let cond_reg = reg_of(alloc, cond, IrType::I8);
            let tc = test_code(IrType::I8);
            out.push(Instruction::with2(tc, cond_reg, cond_reg).unwrap());
            out.push(Instruction::with1(Code::Setne_rm8, dest_reg).unwrap());
        }

        IrOp::Select => {
            let dest = inst.dest.unwrap();
            let cond = inst.args[0];
            let true_val = inst.args[1];
            let false_val = inst.args[2];
            let dest_reg = reg_of(alloc, dest, ty);
            let false_reg = reg_of(alloc, false_val, ty);
            let true_reg = reg_of(alloc, true_val, ty);
            let cond_reg = reg_of(alloc, cond, IrType::I8);
            if dest_reg != false_reg {
                out.push(Instruction::with2(mov_code(ty), dest_reg, false_reg).unwrap());
            }
            out.push(Instruction::with2(test_code(IrType::I8), cond_reg, cond_reg).unwrap());
            let cmov_code = match ty {
                IrType::I64 | IrType::I128 => Code::Cmovne_r64_rm64,
                IrType::I32 => Code::Cmovne_r32_rm32,
                IrType::I16 => Code::Cmovne_r16_rm16,
                _ => Code::Cmovne_r32_rm32,
            };
            out.push(Instruction::with2(cmov_code, dest_reg, true_reg).unwrap());
        }

        IrOp::Call { target } => {
            out.push(Instruction::with_branch(Code::Call_rel32_64, *target).unwrap());
        }

        IrOp::CallIndirect => {
            let target_reg = reg_of(alloc, inst.args[0], IrType::I64);
            out.push(Instruction::with1(Code::Call_rm64, target_reg).unwrap());
        }

        IrOp::NativeInline(native) => {
            let mut decoder = Decoder::new(64, &native.bytes, DecoderOptions::NONE);
            for instr in &mut decoder {
                out.push(instr);
            }
        }

        IrOp::Mov128 => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_is_xmm = matches!(alloc.assignments[&dest], PhysReg::Xmm(_));
            let src_is_xmm = matches!(alloc.assignments[&src], PhysReg::Xmm(_));
            match (dest_is_xmm, src_is_xmm) {
                (true, true) => {
                    let dest_reg = reg_of(alloc, dest, IrType::I128);
                    let src_reg = reg_of(alloc, src, IrType::I128);
                    if dest_reg != src_reg {
                        out.push(
                            Instruction::with2(Code::Movaps_xmm_xmmm128, dest_reg, src_reg)
                                .unwrap(),
                        );
                    }
                }
                (true, false) => {
                    // load xmm <- [mem]: a 64-bit mov cannot encode xmm<-[reg]
                    let dest_reg = reg_of(alloc, dest, IrType::I128);
                    let addr_reg = reg_of(alloc, src, IrType::I64);
                    let mem = MemoryOperand::with_base(addr_reg);
                    out.push(Instruction::with2(Code::Movups_xmm_xmmm128, dest_reg, mem).unwrap());
                }
                (false, true) => {
                    // store [mem] <- xmm
                    let addr_reg = reg_of(alloc, dest, IrType::I64);
                    let mem = MemoryOperand::with_base(addr_reg);
                    let src_reg = reg_of(alloc, src, IrType::I128);
                    out.push(Instruction::with2(Code::Movups_xmmm128_xmm, mem, src_reg).unwrap());
                }
                (false, false) => {
                    let dest_reg = reg_of(alloc, dest, IrType::I64);
                    let src_reg = reg_of(alloc, src, IrType::I64);
                    if dest_reg != src_reg {
                        out.push(
                            Instruction::with2(mov_code(IrType::I64), dest_reg, src_reg).unwrap(),
                        );
                    }
                }
            }
        }

        IrOp::Bswap => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_reg = reg_of(alloc, src, ty);
            if dest_reg != src_reg {
                out.push(Instruction::with2(mov_code(ty), dest_reg, src_reg).unwrap());
            }
            let code = match ty {
                IrType::I64 | IrType::I128 => Code::Bswap_r64,
                _ => Code::Bswap_r32,
            };
            out.push(Instruction::with1(code, dest_reg).unwrap());
        }

        IrOp::Bsf => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_reg = reg_of(alloc, src, ty);
            let code = match ty {
                IrType::I64 | IrType::I128 => Code::Bsf_r64_rm64,
                IrType::I32 => Code::Bsf_r32_rm32,
                IrType::I16 => Code::Bsf_r16_rm16,
                _ => Code::Bsf_r32_rm32,
            };
            out.push(Instruction::with2(code, dest_reg, src_reg).unwrap());
        }

        IrOp::Bsr => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_reg = reg_of(alloc, src, ty);
            let code = match ty {
                IrType::I64 | IrType::I128 => Code::Bsr_r64_rm64,
                IrType::I32 => Code::Bsr_r32_rm32,
                IrType::I16 => Code::Bsr_r16_rm16,
                _ => Code::Bsr_r32_rm32,
            };
            out.push(Instruction::with2(code, dest_reg, src_reg).unwrap());
        }

        IrOp::Popcnt => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_reg = reg_of(alloc, src, ty);
            let code = match ty {
                IrType::I64 | IrType::I128 => Code::Popcnt_r64_rm64,
                IrType::I32 => Code::Popcnt_r32_rm32,
                IrType::I16 => Code::Popcnt_r16_rm16,
                _ => Code::Popcnt_r32_rm32,
            };
            out.push(Instruction::with2(code, dest_reg, src_reg).unwrap());
        }

        IrOp::Lzcnt => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_reg = reg_of(alloc, src, ty);
            let code = match ty {
                IrType::I64 | IrType::I128 => Code::Lzcnt_r64_rm64,
                IrType::I32 => Code::Lzcnt_r32_rm32,
                IrType::I16 => Code::Lzcnt_r16_rm16,
                _ => Code::Lzcnt_r32_rm32,
            };
            out.push(Instruction::with2(code, dest_reg, src_reg).unwrap());
        }

        IrOp::Tzcnt => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_reg = reg_of(alloc, dest, ty);
            let src_reg = reg_of(alloc, src, ty);
            let code = match ty {
                IrType::I64 | IrType::I128 => Code::Tzcnt_r64_rm64,
                IrType::I32 => Code::Tzcnt_r32_rm32,
                IrType::I16 => Code::Tzcnt_r16_rm16,
                _ => Code::Tzcnt_r32_rm32,
            };
            out.push(Instruction::with2(code, dest_reg, src_reg).unwrap());
        }

        IrOp::UDiv | IrOp::SDiv | IrOp::URem | IrOp::SRem | IrOp::UMulHi | IrOp::SMulHi => {
            let dest = inst.dest.unwrap();
            let dest_reg = reg_of(alloc, dest, ty);
            out.push(Instruction::with2(mov_code(ty), dest_reg, dest_reg).unwrap());
        }

        IrOp::Undef | IrOp::Use => {}
    }
}

fn find_flag_producer(func: &IrFunction, cond_vid: ValueId) -> Option<&kamy_core::ir::Inst> {
    for block in &func.blocks {
        for inst in &block.insts {
            if inst.dest == Some(cond_vid) {
                return Some(inst);
            }
        }
    }
    None
}

fn edge_target(
    alloc: &RegAllocation,
    pred: BlockId,
    succ: BlockId,
    block_labels: &HashMap<BlockId, u64>,
    landings: &mut Vec<(u64, BlockId, BlockId)>,
    next_landing: &mut u64,
) -> u64 {
    // A conditional branch always has two successors, so any phi-carrying
    // successor is reached by a critical edge: route it through a landing block
    // that performs the edge's phi copies in isolation.
    if alloc.edge_copies.contains_key(&(pred, succ)) {
        let label = *next_landing;
        *next_landing += 0x1000;
        landings.push((label, pred, succ));
        label
    } else {
        block_labels[&succ]
    }
}

#[allow(clippy::too_many_arguments)]
fn select_terminator(
    func: &IrFunction,
    alloc: &RegAllocation,
    pid: BlockId,
    term: &IrTerminator,
    block_labels: &HashMap<BlockId, u64>,
    landings: &mut Vec<(u64, BlockId, BlockId)>,
    next_landing: &mut u64,
    out: &mut Vec<Instruction>,
) {
    match term {
        IrTerminator::Ret => {
            out.push(Instruction::with(Code::Retnq));
        }
        IrTerminator::Tail { target } => {
            out.push(Instruction::with_branch(Code::Jmp_rel32_64, *target).unwrap());
        }
        IrTerminator::Jump(target) => {
            // Single successor: no critical edge, emit the phi copies inline.
            if let Some(copies) = alloc.edge_copies.get(&(pid, *target)) {
                for c in copies {
                    emit_copy(out, c);
                }
            }
            out.push(Instruction::with_branch(Code::Jmp_rel32_64, block_labels[target]).unwrap());
        }
        IrTerminator::Branch {
            cond,
            taken,
            not_taken,
        } => {
            let taken_va = edge_target(alloc, pid, *taken, block_labels, landings, next_landing);
            let not_taken_va =
                edge_target(alloc, pid, *not_taken, block_labels, landings, next_landing);

            if let Some(producer) = find_flag_producer(func, *cond) {
                match &producer.op {
                    IrOp::IsZero
                    | IrOp::IsNeg
                    | IrOp::Parity
                    | IrOp::BorrowSub
                    | IrOp::OverflowSub
                    | IrOp::AuxBorrowSub
                    | IrOp::CarryAdd
                    | IrOp::OverflowAdd
                    | IrOp::AuxCarryAdd
                    | IrOp::CarryShl
                    | IrOp::CarryShr
                    | IrOp::CarrySar => {
                        emit_flag_compare(func, alloc, producer, out);
                        let jcc = flag_op_to_jcc(&producer.op);
                        out.push(Instruction::with_branch(jcc, taken_va).unwrap());
                        out.push(
                            Instruction::with_branch(Code::Jmp_rel32_64, not_taken_va).unwrap(),
                        );
                        return;
                    }
                    _ => {}
                }
            }

            let cond_reg = reg_of(alloc, *cond, IrType::I8);
            out.push(Instruction::with2(test_code(IrType::I8), cond_reg, cond_reg).unwrap());
            out.push(Instruction::with_branch(Code::Jne_rel32_64, taken_va).unwrap());
            out.push(Instruction::with_branch(Code::Jmp_rel32_64, not_taken_va).unwrap());
        }
        IrTerminator::Unreachable => {
            out.push(Instruction::with(Code::Int3));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::ir::*;

    #[test]
    fn select_const_add_ret() {
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };

        let v0 = func.alloc_value();
        let v1 = func.alloc_value();
        let v2 = func.alloc_value();

        let block = IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(v0),
                    op: IrOp::Const(42),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v1),
                    op: IrOp::Const(58),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v2),
                    op: IrOp::Add,
                    args: vec![v0, v1],
                    ty: IrType::I64,
                },
            ],
            term: IrTerminator::Ret,
        };
        func.blocks.push(block);

        let mut assignments = HashMap::new();
        assignments.insert(v0, PhysReg::Gpr(Gpr::Rax));
        assignments.insert(v1, PhysReg::Gpr(Gpr::Rcx));
        assignments.insert(v2, PhysReg::Gpr(Gpr::Rax));

        let alloc = RegAllocation {
            assignments,
            copies: vec![],
            edge_copies: HashMap::new(),
            flag_scratch: None,
        };

        let instrs = select_instructions(&func, &alloc, 0x140000000, 0x140001000, &[], &[]);

        assert!(!instrs.is_empty());

        use iced_x86::Mnemonic;
        let mnemonics: Vec<Mnemonic> = instrs.iter().map(|i| i.mnemonic()).collect();
        assert!(
            mnemonics.contains(&Mnemonic::Mov),
            "should contain mov: {mnemonics:?}"
        );
        assert!(
            mnemonics.contains(&Mnemonic::Add),
            "should contain add: {mnemonics:?}"
        );
        assert!(
            mnemonics.contains(&Mnemonic::Ret),
            "should contain ret: {mnemonics:?}"
        );
    }

    #[test]
    fn xmm_data_movement_encodes() {
        // Regression (known bug #2): an XMM-assigned Load/Store/xorps must lower
        // to SSE moves. The GPR `mov r64,[mem]` form iced builds for an XMM
        // operand constructs fine but fails BlockEncoder, which the linker
        // swallowed into a verbatim fallback (no protection). `relocate` must now
        // succeed and the opcodes must be the SSE moves.
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let addr = func.alloc_value();
        let zero = func.alloc_value();
        let load128 = func.alloc_value();
        let load64 = func.alloc_value();

        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(addr),
                    op: IrOp::Const(0x2000),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(zero),
                    op: IrOp::Const(0),
                    args: vec![],
                    ty: IrType::I128,
                },
                Inst {
                    dest: Some(load128),
                    op: IrOp::Load,
                    args: vec![addr],
                    ty: IrType::I128,
                },
                Inst {
                    dest: None,
                    op: IrOp::Store,
                    args: vec![addr, load128],
                    ty: IrType::I128,
                },
                Inst {
                    dest: Some(load64),
                    op: IrOp::Load,
                    args: vec![addr],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Store,
                    args: vec![addr, load64],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Store,
                    args: vec![addr, zero],
                    ty: IrType::I128,
                },
            ],
            term: IrTerminator::Ret,
        });

        let mut assignments = HashMap::new();
        assignments.insert(addr, PhysReg::Gpr(Gpr::Rcx));
        assignments.insert(zero, PhysReg::Xmm(XmmReg::Xmm1));
        assignments.insert(load128, PhysReg::Xmm(XmmReg::Xmm5));
        assignments.insert(load64, PhysReg::Xmm(XmmReg::Xmm0));
        let alloc = RegAllocation {
            assignments,
            copies: vec![],
            edge_copies: HashMap::new(),
            flag_scratch: None,
        };

        let instrs = select_instructions(&func, &alloc, 0x140000000, 0x140001000, &[], &[]);

        // The exact gate the linker hit: BlockEncoder must accept every instruction.
        let bytes = crate::relocate(&instrs, 0x140001000).expect("xmm moves must encode");
        assert!(!bytes.is_empty());

        use iced_x86::Mnemonic;
        let mnem: Vec<Mnemonic> = instrs.iter().map(|i| i.mnemonic()).collect();
        assert!(
            mnem.contains(&Mnemonic::Movups),
            "movups for I128 xmm: {mnem:?}"
        );
        assert!(
            mnem.contains(&Mnemonic::Movsd),
            "movsd for I64 xmm: {mnem:?}"
        );
        assert!(
            mnem.contains(&Mnemonic::Xorps),
            "xorps zero idiom: {mnem:?}"
        );
        for ins in &instrs {
            if ins.mnemonic() == Mnemonic::Mov {
                for i in 0..ins.op_count() {
                    assert!(
                        !ins.op_register(i).is_xmm(),
                        "GPR mov must not take an XMM operand: {ins:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn odd_callee_saved_emits_rsp_align() {
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let v0 = func.alloc_value();
        let block = IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![Inst {
                dest: Some(v0),
                op: IrOp::Const(1),
                args: vec![],
                ty: IrType::I64,
            }],
            term: IrTerminator::Ret,
        };
        func.blocks.push(block);

        let mut assignments = HashMap::new();
        assignments.insert(v0, PhysReg::Gpr(Gpr::Rbx));
        let alloc = RegAllocation {
            assignments,
            copies: vec![],
            edge_copies: HashMap::new(),
            flag_scratch: None,
        };

        let instrs = select_instructions(
            &func,
            &alloc,
            0x140000000,
            0x140001000,
            &[Register::RBX],
            &[],
        );

        let push_idx = instrs
            .iter()
            .position(|i| i.mnemonic() == iced_x86::Mnemonic::Push)
            .expect("push present");
        let sub_idx = instrs
            .iter()
            .position(|i| i.mnemonic() == iced_x86::Mnemonic::Sub)
            .expect("sub rsp,8 present");
        assert!(sub_idx > push_idx, "sub rsp,8 must follow the push");

        let pop_idx = instrs
            .iter()
            .position(|i| i.mnemonic() == iced_x86::Mnemonic::Pop)
            .expect("pop present");
        let add_idx = instrs
            .iter()
            .position(|i| i.mnemonic() == iced_x86::Mnemonic::Add)
            .expect("add rsp,8 present");
        assert!(add_idx < pop_idx, "add rsp,8 must precede the pop at ret");
    }

    #[test]
    fn xmm_callee_saved_save_restore() {
        // One GPR push (odd → 8 pad) + one saved XMM → sub rsp,24; a movups save
        // in the prologue and a movups restore + add rsp in the epilogue, all of
        // which must encode.
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let v0 = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![Inst {
                dest: Some(v0),
                op: IrOp::Const(1),
                args: vec![],
                ty: IrType::I64,
            }],
            term: IrTerminator::Ret,
        });
        let mut assignments = HashMap::new();
        assignments.insert(v0, PhysReg::Gpr(Gpr::Rbx));
        let alloc = RegAllocation {
            assignments,
            copies: vec![],
            edge_copies: HashMap::new(),
            flag_scratch: None,
        };

        let instrs = select_instructions(
            &func,
            &alloc,
            0x140000000,
            0x140001000,
            &[Register::RBX],
            &[Register::XMM6],
        );
        crate::relocate(&instrs, 0x140001000).expect("xmm prologue encodes");

        use iced_x86::Mnemonic;
        let sub = instrs
            .iter()
            .position(|i| i.mnemonic() == Mnemonic::Sub)
            .expect("sub rsp present");
        let store = instrs
            .iter()
            .position(|i| i.mnemonic() == Mnemonic::Movups)
            .expect("movups save present");
        assert!(store > sub, "xmm save follows the stack allocation");
        assert_eq!(instrs[sub].immediate(1), 24, "8 align pad + 16 for one xmm");
        assert_eq!(
            instrs
                .iter()
                .filter(|i| i.mnemonic() == Mnemonic::Movups)
                .count(),
            2,
            "save in prologue, restore in epilogue"
        );
        let add = instrs
            .iter()
            .position(|i| i.mnemonic() == Mnemonic::Add)
            .expect("add rsp present");
        let pop = instrs
            .iter()
            .position(|i| i.mnemonic() == Mnemonic::Pop)
            .expect("pop present");
        assert!(add < pop, "stack free precedes the pop at ret");
    }

    #[test]
    fn multiblock_branch_lowers_cmp_and_resolves() {
        // b0: v2 = BorrowSub(v0, v1); branch v2 -> b1 : b2   (b1,b2 return)
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let v0 = func.alloc_value();
        let v1 = func.alloc_value();
        let v2 = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(v0),
                    op: IrOp::Const(5),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v1),
                    op: IrOp::Const(2),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v2),
                    op: IrOp::BorrowSub,
                    args: vec![v0, v1],
                    ty: IrType::I8,
                },
            ],
            term: IrTerminator::Branch {
                cond: v2,
                taken: BlockId(1),
                not_taken: BlockId(2),
            },
        });
        for id in [BlockId(1), BlockId(2)] {
            func.blocks.push(IrBlock {
                id,
                phis: vec![],
                insts: vec![],
                term: IrTerminator::Ret,
            });
        }

        let alloc = crate::regalloc::allocate_registers(
            &func,
            &crate::regalloc::CALLEE_SAVED_GPRS,
            &std::collections::HashSet::new(),
            &HashMap::new(),
        )
        .unwrap();
        let instrs = select_instructions(&func, &alloc, 0x140000000, 0x140001000, &[], &[]);
        // Intra-function branch targets must resolve to in-block instructions.
        crate::relocate(&instrs, 0x140001000).expect("branches resolve");
        let mnemonics: Vec<iced_x86::Mnemonic> = instrs.iter().map(|i| i.mnemonic()).collect();
        assert!(
            mnemonics.contains(&iced_x86::Mnemonic::Cmp),
            "a subtract comparison must lower to `cmp a,b`, not `test`: {mnemonics:?}"
        );
    }

    #[test]
    fn bool_not_lowers_to_xor_one_not_bitwise() {
        // A logical flag negation must flip only the low bit so the 0/1
        // invariant survives: `not` would yield 0xFE/0xFF, staying truthy
        // under `test;jnz` and making every negated/compound branch
        // unconditional.
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let v0 = func.alloc_value();
        let v1 = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(v0),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I8,
                },
                Inst {
                    dest: Some(v1),
                    op: IrOp::BoolNot,
                    args: vec![v0],
                    ty: IrType::I8,
                },
            ],
            term: IrTerminator::Ret,
        });
        let mut assignments = HashMap::new();
        assignments.insert(v0, PhysReg::Gpr(Gpr::Rcx));
        assignments.insert(v1, PhysReg::Gpr(Gpr::Rcx));
        let alloc = RegAllocation {
            assignments,
            copies: vec![],
            edge_copies: HashMap::new(),
            flag_scratch: None,
        };
        let instrs = select_instructions(&func, &alloc, 0x140000000, 0x140001000, &[], &[]);
        assert!(
            instrs
                .iter()
                .all(|i| i.mnemonic() != iced_x86::Mnemonic::Not),
            "BoolNot must not lower to bitwise `not`: {:?}",
            instrs.iter().map(|i| i.mnemonic()).collect::<Vec<_>>()
        );
        let xor = instrs
            .iter()
            .find(|i| i.mnemonic() == iced_x86::Mnemonic::Xor)
            .expect("BoolNot lowers through xor");
        assert_eq!(xor.immediate(1), 1, "logical not flips the low bit");
    }

    #[test]
    fn branch_on_add_flag_reexecutes_into_scratch() {
        // b0: a=Undef, b=Undef, r=Add(a,b), cf=CarryAdd(a,b); branch cf -> b1:b2
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let a = func.alloc_value();
        let b = func.alloc_value();
        let r = func.alloc_value();
        let cf = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(a),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(b),
                    op: IrOp::Undef,
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(r),
                    op: IrOp::Add,
                    args: vec![a, b],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(cf),
                    op: IrOp::CarryAdd,
                    args: vec![a, b],
                    ty: IrType::I8,
                },
            ],
            term: IrTerminator::Branch {
                cond: cf,
                taken: BlockId(1),
                not_taken: BlockId(2),
            },
        });
        for id in [BlockId(1), BlockId(2)] {
            func.blocks.push(IrBlock {
                id,
                phis: vec![],
                insts: vec![],
                term: IrTerminator::Ret,
            });
        }
        let mut assignments = HashMap::new();
        assignments.insert(a, PhysReg::Gpr(Gpr::Rcx));
        assignments.insert(b, PhysReg::Gpr(Gpr::Rdx));
        assignments.insert(r, PhysReg::Gpr(Gpr::R8));
        assignments.insert(cf, PhysReg::Gpr(Gpr::Rax));
        let alloc = RegAllocation {
            assignments,
            copies: vec![],
            edge_copies: HashMap::new(),
            flag_scratch: Some(PhysReg::Gpr(Gpr::R11)),
        };
        let instrs = select_instructions(&func, &alloc, 0x140000000, 0x140001000, &[], &[]);
        crate::relocate(&instrs, 0x140001000).expect("branch on add flag must encode");
        use iced_x86::Mnemonic;
        let mnemonics: Vec<Mnemonic> = instrs.iter().map(|i| i.mnemonic()).collect();
        assert!(
            mnemonics.contains(&Mnemonic::Add),
            "add flag must be re-executed as `add`: {mnemonics:?}"
        );
        assert!(
            mnemonics.contains(&Mnemonic::Jb),
            "a CarryAdd branch must lower to `jb`: {mnemonics:?}"
        );
        assert!(
            instrs
                .iter()
                .any(|i| i.mnemonic() == Mnemonic::Add
                    && i.op0_register() == iced_x86::Register::R11),
            "the flag add must re-execute into the R11 scratch: {mnemonics:?}"
        );
    }

    #[test]
    fn rip_addr_lowers_to_position_independent_lea() {
        const TARGET: u64 = 0x1_4000_5000;
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let v0 = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(v0),
                    op: IrOp::RipAddr(TARGET),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![v0],
                    ty: IrType::I64,
                },
            ],
            term: IrTerminator::Ret,
        });
        let alloc = crate::regalloc::allocate_registers(
            &func,
            &crate::regalloc::CALLEE_SAVED_GPRS,
            &std::collections::HashSet::new(),
            &HashMap::new(),
        )
        .unwrap();
        let instrs = select_instructions(&func, &alloc, 0x140000000, 0x1_4000_2000, &[], &[]);
        // Encode at two different VAs; both must still resolve to the same absolute
        // target (position independence).
        for new_va in [0x1_4000_2000u64, 0x1_4000_9000u64] {
            let bytes = crate::relocate(&instrs, new_va).unwrap();
            let mut dec = Decoder::with_ip(64, &bytes, new_va, DecoderOptions::NONE);
            let lea = dec
                .iter()
                .find(|i| i.mnemonic() == iced_x86::Mnemonic::Lea)
                .expect("lea emitted");
            assert!(lea.is_ip_rel_memory_operand(), "lea must be rip-relative");
            assert_eq!(
                lea.memory_displacement64(),
                TARGET,
                "rip-relative lea must resolve to the original absolute VA"
            );
        }
    }

    #[test]
    fn tail_terminator_lowers_to_jmp_after_epilogue() {
        const TARGET: u64 = 0x1_4000_7000;
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let v0 = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![Inst {
                dest: Some(v0),
                op: IrOp::Const(1),
                args: vec![],
                ty: IrType::I64,
            }],
            term: IrTerminator::Tail { target: TARGET },
        });

        let mut assignments = HashMap::new();
        assignments.insert(v0, PhysReg::Gpr(Gpr::Rbx));
        let alloc = RegAllocation {
            assignments,
            copies: vec![],
            edge_copies: HashMap::new(),
            flag_scratch: None,
        };

        // One callee-saved push is odd, so a realign shim is added; the frame must
        // be torn down (realign add + pop) before the tail jmp, and no ret emitted.
        let instrs = select_instructions(
            &func,
            &alloc,
            0x140000000,
            0x140001000,
            &[Register::RBX],
            &[],
        );
        let mnem: Vec<iced_x86::Mnemonic> = instrs.iter().map(|i| i.mnemonic()).collect();
        assert!(
            !mnem.contains(&iced_x86::Mnemonic::Ret),
            "a tail call must not emit ret: {mnem:?}"
        );
        let add_idx = mnem
            .iter()
            .position(|m| *m == iced_x86::Mnemonic::Add)
            .expect("realign add present");
        let pop_idx = mnem
            .iter()
            .position(|m| *m == iced_x86::Mnemonic::Pop)
            .expect("callee-saved pop present");
        let jmp_idx = mnem
            .iter()
            .rposition(|m| *m == iced_x86::Mnemonic::Jmp)
            .expect("tail jmp present");
        assert!(
            add_idx < pop_idx && pop_idx < jmp_idx,
            "frame teardown must precede the tail jmp: {mnem:?}"
        );

        // The tail jmp targets the callee's absolute VA, independent of placement.
        let bytes = crate::relocate(&instrs, 0x1_4000_2000).expect("tail jmp resolves");
        let mut dec = Decoder::with_ip(64, &bytes, 0x1_4000_2000, DecoderOptions::NONE);
        let jmp = dec
            .iter()
            .find(|i| i.mnemonic() == iced_x86::Mnemonic::Jmp)
            .expect("jmp decoded");
        assert_eq!(
            jmp.near_branch_target(),
            TARGET,
            "tail jmp must resolve to the callee VA"
        );
    }

    #[test]
    fn const_shift_uses_immediate_not_cl() {
        // A constant shift count with a live value pinned to RCX must lower to
        // the immediate form; the CL path would clobber RCX (the MBA crash).
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let v_val = func.alloc_value();
        let v_cnt = func.alloc_value();
        let v_res = func.alloc_value();
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts: vec![
                Inst {
                    dest: Some(v_val),
                    op: IrOp::Const(7),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v_cnt),
                    op: IrOp::Const(1),
                    args: vec![],
                    ty: IrType::I64,
                },
                Inst {
                    dest: Some(v_res),
                    op: IrOp::Shl,
                    args: vec![v_val, v_cnt],
                    ty: IrType::I64,
                },
                Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![v_res],
                    ty: IrType::I64,
                },
            ],
            term: IrTerminator::Ret,
        });
        let mut assignments = HashMap::new();
        assignments.insert(v_val, PhysReg::Gpr(Gpr::Rax));
        assignments.insert(v_cnt, PhysReg::Gpr(Gpr::Rcx));
        assignments.insert(v_res, PhysReg::Gpr(Gpr::Rax));
        let alloc = RegAllocation {
            assignments,
            copies: vec![],
            edge_copies: HashMap::new(),
            flag_scratch: None,
        };
        let instrs = select_instructions(&func, &alloc, 0x140000000, 0x140001000, &[], &[]);
        use iced_x86::{Mnemonic, OpKind};
        let shl = instrs
            .iter()
            .find(|i| i.mnemonic() == Mnemonic::Shl)
            .expect("shl emitted");
        assert_eq!(
            shl.op1_kind(),
            OpKind::Immediate8,
            "a constant shift must use the immediate form, not CL"
        );
        assert!(
            !instrs.iter().any(|i| i.mnemonic() == Mnemonic::Mov
                && i.op0_kind() == OpKind::Register
                && i.op0_register() == Register::CL),
            "a constant shift must not move the count into CL"
        );
    }
}
