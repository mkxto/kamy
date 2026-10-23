use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, MemoryOperand, Register};
use kamy_core::ir::{
    BlockId, Gpr, IrFunction, IrOp, IrTerminator, IrType, PhysReg, ValueId, XmmReg,
};

use crate::regalloc::RegAllocation;

mod memory;

/// Ordinary selection consumes at most three inputs and one destination.
/// Native instructions need no mapping; indirect calls map only their target.
#[derive(Default)]
struct InstructionAllocation {
    values: [Option<(ValueId, PhysReg, IrType)>; 4],
    flag_scratch: Option<PhysReg>,
}

impl InstructionAllocation {
    fn clear(&mut self) {
        self.values.fill(None);
        self.flag_scratch = None;
    }

    fn contains(&self, value: ValueId) -> bool {
        self.values.iter().flatten().any(|entry| entry.0 == value)
    }

    fn insert(&mut self, value: ValueId, register: PhysReg, ty: IrType) {
        let index = self
            .values
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.0 == value))
            .or_else(|| self.values.iter().position(Option::is_none))
            .expect("instruction-local allocation is bounded by its operands");
        self.values[index] = Some((value, register, ty));
    }

    fn get(&self, value: ValueId) -> (PhysReg, IrType) {
        self.values
            .iter()
            .flatten()
            .find_map(|&(id, register, ty)| (id == value).then_some((register, ty)))
            .expect("selected instruction operand has a local allocation")
    }

    fn register(&self, value: ValueId) -> PhysReg {
        self.get(value).0
    }

    fn ty(&self, value: ValueId) -> IrType {
        self.get(value).1
    }
}

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

fn reg_of(alloc: &InstructionAllocation, vid: ValueId, ty: IrType) -> Register {
    phys_to_register(alloc.register(vid), ty)
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

/// Reconstruct an individual SSA flag before materializing its 0/1 value.
fn emit_flag_compare(
    alloc: &InstructionAllocation,
    producer: &kamy_core::ir::Inst,
    constants: &HashMap<ValueId, u64>,
    out: &mut Vec<Instruction>,
) {
    match &producer.op {
        IrOp::IsZero | IrOp::IsNeg | IrOp::Parity => {
            if let Some(&arg) = producer.args.first() {
                let ty = alloc.ty(arg);
                let reg = reg_of(alloc, arg, ty);
                out.push(Instruction::with2(test_code(ty), reg, reg).unwrap());
            }
        }
        IrOp::BorrowSub | IrOp::OverflowSub | IrOp::AuxBorrowSub => {
            let a = producer.args[0];
            let b = producer.args[1];
            let ty = alloc.ty(a);
            let ra = reg_of(alloc, a, ty);
            let rb = reg_of(alloc, b, ty);
            out.push(Instruction::with2(cmp_code(ty), ra, rb).unwrap());
        }
        IrOp::CarryAdd | IrOp::OverflowAdd | IrOp::AuxCarryAdd => {
            let a = producer.args[0];
            let b = producer.args[1];
            let ty = alloc.ty(a);
            let ra = reg_of(alloc, a, ty);
            let rb = reg_of(alloc, b, ty);
            let scratch = phys_to_register(alloc.flag_scratch.expect("flag scratch reserved"), ty);
            out.push(Instruction::with2(mov_code(ty), scratch, ra).unwrap());
            out.push(Instruction::with2(alu_code(&IrOp::Add, ty), scratch, rb).unwrap());
        }
        IrOp::CarryShl | IrOp::CarryShr | IrOp::CarrySar => {
            let orig = producer.args[0];
            let count = producer.args[1];
            let ty = alloc.ty(orig);
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
                    constants[&count] as u8 as i32,
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
            IrTerminator::Ret
            | IrTerminator::NoReturn
            | IrTerminator::Tail { .. }
            | IrTerminator::Unreachable => {}
        }
    }
    order
}

fn value_type(alloc: &RegAllocation, vid: ValueId) -> IrType {
    alloc.value_types[&vid]
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

pub fn select_instructions(
    func: &IrFunction,
    alloc: &RegAllocation,
) -> crate::references::SelectedInstructions {
    memory::select(func, alloc)
}

fn select_inst(
    alloc: &InstructionAllocation,
    inst: &kamy_core::ir::Inst,
    constants: &HashMap<ValueId, u64>,
    out: &mut Vec<Instruction>,
    references: &mut Vec<crate::references::InstructionReference>,
) {
    let ty = inst.ty;

    match &inst.op {
        IrOp::Const(imm) => {
            let dest = inst.dest.unwrap();
            let dest_reg = reg_of(alloc, dest, ty);
            if *imm == 0 {
                if is_xmm(alloc.register(dest)) {
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
                    phys_to_register(alloc.register(dest), IrType::I32)
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

        IrOp::Address(reference) => {
            let dest = inst.dest.unwrap();
            let dest_reg = reg_of(alloc, dest, ty);
            let instruction = out.len();
            let operand = if matches!(
                reference.expression,
                kamy_core::SymbolicExpression::Symbol { .. }
            ) {
                out.push(
                    Instruction::with2(
                        Code::Lea_r64_m,
                        reg_of(alloc, dest, IrType::I64),
                        MemoryOperand::with_base(Register::RIP),
                    )
                    .unwrap(),
                );
                1
            } else {
                match ty {
                    IrType::I32 => {
                        out.push(Instruction::with2(Code::Mov_r32_imm32, dest_reg, 0u32).unwrap())
                    }
                    _ => out.push(
                        Instruction::with2(
                            Code::Mov_r64_imm64,
                            reg_of(alloc, dest, IrType::I64),
                            0u64,
                        )
                        .unwrap(),
                    ),
                }
                1
            };
            references.push(crate::references::InstructionReference {
                instruction,
                operand,
                reference: reference.clone(),
            });
        }

        IrOp::FrameOffset(offset) => {
            out.push(
                Instruction::with2(
                    Code::Lea_r64_m,
                    reg_of(alloc, inst.dest.unwrap(), IrType::I64),
                    MemoryOperand::with_base_displ(
                        reg_of(alloc, inst.args[0], IrType::I64),
                        *offset,
                    ),
                )
                .unwrap(),
            );
        }

        IrOp::Copy => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            match (is_xmm(alloc.register(dest)), is_xmm(alloc.register(src))) {
                (false, false) => {
                    let dest_reg = reg_of(alloc, dest, ty);
                    let src_ty = alloc.ty(src);
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
            if is_xmm(alloc.register(dest)) {
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
            if let Some(&c) = constants.get(&count) {
                let code = shift_imm_code(&inst.op, ty);
                out.push(Instruction::with2(code, dest_reg, c as u8 as i32).unwrap());
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
            if inst.args.len() == 1 {
                assert_eq!(
                    reg_of(alloc, inst.dest.unwrap(), ty),
                    gpr_register(Gpr::Rax, ty)
                );
                return;
            }
            let dest = inst.dest.unwrap();
            let lhs = inst.args[0];
            let rhs = inst.args[1];
            let machine_ty = if ty == IrType::I8 { IrType::I32 } else { ty };
            let dest_reg = reg_of(alloc, dest, machine_ty);
            let lhs_reg = reg_of(alloc, lhs, machine_ty);
            let rhs_reg = reg_of(alloc, rhs, machine_ty);
            let code = match machine_ty {
                IrType::I64 | IrType::I128 => Code::Imul_r64_rm64,
                IrType::I32 => Code::Imul_r32_rm32,
                IrType::I16 => Code::Imul_r16_rm16,
                IrType::I8 => unreachable!(),
            };
            if dest_reg == rhs_reg {
                out.push(Instruction::with2(code, dest_reg, lhs_reg).unwrap());
            } else {
                if dest_reg != lhs_reg {
                    out.push(Instruction::with2(mov_code(machine_ty), dest_reg, lhs_reg).unwrap());
                }
                out.push(Instruction::with2(code, dest_reg, rhs_reg).unwrap());
            }
        }

        IrOp::Load => {
            let dest = inst.dest.unwrap();
            let addr = inst.args[0];
            let addr_reg = reg_of(alloc, addr, IrType::I64);
            let mem = MemoryOperand::with_base(addr_reg);
            if is_xmm(alloc.register(dest)) {
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
            if is_xmm(alloc.register(val)) {
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
            let src_ty = alloc.ty(src);
            let src_reg = reg_of(alloc, src, src_ty);
            let code = match (src_ty, ty) {
                (IrType::I8, IrType::I16) => Code::Movzx_r16_rm8,
                (IrType::I8, IrType::I32) => Code::Movzx_r32_rm8,
                (IrType::I8, IrType::I64) => Code::Movzx_r64_rm8,
                (IrType::I16, IrType::I32) => Code::Movzx_r32_rm16,
                (IrType::I16, IrType::I64) => Code::Movzx_r64_rm16,
                (IrType::I32, IrType::I64) => {
                    let dest32 = phys_to_register(alloc.register(dest), IrType::I32);
                    let src32 = phys_to_register(alloc.register(src), IrType::I32);
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
            let src_ty = alloc.ty(src);
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
            let src_reg = phys_to_register(alloc.register(src), ty);
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
            let dest_reg = reg_of(alloc, dest, IrType::I8);
            emit_flag_compare(alloc, inst, constants, out);
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

        IrOp::Call { target, .. } => {
            references.push(crate::references::InstructionReference {
                instruction: out.len(),
                operand: 0,
                reference: target.clone(),
            });
            out.push(Instruction::with_branch(Code::Call_rel32_64, 0).unwrap());
        }

        IrOp::CallIndirect { .. } => {
            let target_reg = reg_of(alloc, inst.args[0], IrType::I64);
            out.push(Instruction::with1(Code::Call_rm64, target_reg).unwrap());
        }

        IrOp::NativeInline(native) => {
            references.extend(native.references.iter().map(|reference| {
                crate::references::InstructionReference {
                    instruction: out.len(),
                    operand: reference.operand,
                    reference: reference.reference.clone(),
                }
            }));
            let mut decoder = Decoder::new(64, &native.bytes, DecoderOptions::NONE);
            out.push(decoder.decode());
            assert!(
                !decoder.can_decode(),
                "NativeInline must contain one instruction"
            );
        }

        IrOp::Mov128 => {
            let dest = inst.dest.unwrap();
            let src = inst.args[0];
            let dest_is_xmm = matches!(alloc.register(dest), PhysReg::Xmm(_));
            let src_is_xmm = matches!(alloc.register(src), PhysReg::Xmm(_));
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

        IrOp::UDiv | IrOp::SDiv => {
            assert_eq!(reg_of(alloc, inst.args[0], ty), gpr_register(Gpr::Rdx, ty));
            assert_eq!(reg_of(alloc, inst.args[1], ty), gpr_register(Gpr::Rax, ty));
            assert_eq!(
                reg_of(alloc, inst.dest.unwrap(), ty),
                gpr_register(Gpr::Rax, ty)
            );
            let divisor = reg_of(alloc, inst.args[2], ty);
            let signed = matches!(inst.op, IrOp::SDiv);
            let code = match (signed, ty) {
                (false, IrType::I8) => Code::Div_rm8,
                (false, IrType::I16) => Code::Div_rm16,
                (false, IrType::I32) => Code::Div_rm32,
                (false, IrType::I64) => Code::Div_rm64,
                (true, IrType::I8) => Code::Idiv_rm8,
                (true, IrType::I16) => Code::Idiv_rm16,
                (true, IrType::I32) => Code::Idiv_rm32,
                (true, IrType::I64) => Code::Idiv_rm64,
                (_, IrType::I128) => unreachable!("arithmetic width preflight"),
            };
            if ty == IrType::I8 {
                out.push(Instruction::with2(Code::Mov_r8_rm8, Register::AH, Register::DL).unwrap());
            }
            out.push(Instruction::with1(code, divisor).unwrap());
            if ty == IrType::I8 {
                // AH cannot be encoded with a REX-register destination.
                out.push(Instruction::with2(Code::Mov_r8_rm8, Register::DL, Register::AH).unwrap());
            }
        }

        IrOp::URem | IrOp::SRem => {
            assert_eq!(
                reg_of(alloc, inst.dest.unwrap(), ty),
                gpr_register(Gpr::Rdx, ty)
            );
        }

        IrOp::UMulHi | IrOp::SMulHi => {
            assert_eq!(reg_of(alloc, inst.args[0], ty), gpr_register(Gpr::Rax, ty));
            assert_eq!(
                reg_of(alloc, inst.dest.unwrap(), ty),
                gpr_register(Gpr::Rdx, ty)
            );
            let signed = matches!(inst.op, IrOp::SMulHi);
            let code = match (signed, ty) {
                (false, IrType::I8) => Code::Mul_rm8,
                (false, IrType::I16) => Code::Mul_rm16,
                (false, IrType::I32) => Code::Mul_rm32,
                (false, IrType::I64) => Code::Mul_rm64,
                (true, IrType::I8) => Code::Imul_rm8,
                (true, IrType::I16) => Code::Imul_rm16,
                (true, IrType::I32) => Code::Imul_rm32,
                (true, IrType::I64) => Code::Imul_rm64,
                (_, IrType::I128) => unreachable!("arithmetic width preflight"),
            };
            out.push(Instruction::with1(code, reg_of(alloc, inst.args[1], ty)).unwrap());
            if ty == IrType::I8 {
                out.push(Instruction::with2(Code::Mov_r8_rm8, Register::DL, Register::AH).unwrap());
            }
        }

        IrOp::Undef
        | IrOp::Use
        | IrOp::CallResult { .. }
        | IrOp::FrameAddress(_)
        | IrOp::FrameLogical
        | IrOp::FrameIndex { .. }
        | IrOp::StackProbe => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::ir::*;

    fn arithmetic_fixture(
        ty: IrType,
        op: IrOp,
        sources: &[Gpr],
        remainder: bool,
    ) -> (IrFunction, RegAllocation, Vec<ValueId>) {
        let mut func = IrFunction {
            entry: BlockId(0),
            blocks: vec![],
            next_value: 0,
        };
        let mut insts = Vec::new();
        let mut pins = HashMap::new();
        let mut inputs = Vec::new();
        for &gpr in sources {
            let value = func.alloc_value();
            insts.push(Inst {
                dest: Some(value),
                op: IrOp::Undef,
                args: vec![],
                ty,
            });
            pins.insert(value, PhysReg::Gpr(gpr));
            inputs.push(value);
        }
        let mut snapshots = Vec::new();
        for input in inputs {
            let value = func.alloc_value();
            insts.push(Inst {
                dest: Some(value),
                op: IrOp::Copy,
                args: vec![input],
                ty,
            });
            snapshots.push(value);
        }
        let division = matches!(op, IrOp::UDiv | IrOp::SDiv);
        let fixed = if division {
            &[Gpr::Rdx, Gpr::Rax][..]
        } else {
            &[Gpr::Rax][..]
        };
        for (index, &gpr) in fixed.iter().enumerate() {
            let value = func.alloc_value();
            insts.push(Inst {
                dest: Some(value),
                op: IrOp::Copy,
                args: vec![snapshots[index]],
                ty,
            });
            pins.insert(value, PhysReg::Gpr(gpr));
            snapshots[index] = value;
        }
        let result = func.alloc_value();
        insts.push(Inst {
            dest: Some(result),
            op: op.clone(),
            args: snapshots,
            ty,
        });
        pins.insert(
            result,
            PhysReg::Gpr(if division { Gpr::Rax } else { Gpr::Rdx }),
        );
        let mut results = vec![result];
        if remainder {
            let value = func.alloc_value();
            insts.push(Inst {
                dest: Some(value),
                op: if matches!(op, IrOp::SDiv) {
                    IrOp::SRem
                } else {
                    IrOp::URem
                },
                args: vec![result],
                ty,
            });
            pins.insert(value, PhysReg::Gpr(Gpr::Rdx));
            results.push(value);
        }
        if !division {
            let value = func.alloc_value();
            insts.push(Inst {
                dest: Some(value),
                op: IrOp::Mul,
                args: vec![result],
                ty,
            });
            pins.insert(value, PhysReg::Gpr(Gpr::Rax));
            results.push(value);
        }
        let mut outputs = Vec::new();
        for result in results {
            let value = func.alloc_value();
            insts.push(Inst {
                dest: Some(value),
                op: IrOp::Copy,
                args: vec![result],
                ty,
            });
            outputs.push(value);
            pins.insert(
                value,
                PhysReg::Gpr(if outputs.len() == 1 { Gpr::R8 } else { Gpr::R9 }),
            );
        }
        insts.push(Inst {
            dest: None,
            op: IrOp::Use,
            args: outputs.clone(),
            ty,
        });
        func.blocks.push(IrBlock {
            id: BlockId(0),
            phis: vec![],
            insts,
            term: IrTerminator::Ret,
        });
        let alloc = crate::allocate_registers(&func, &HashSet::new(), &pins).unwrap();
        (func, alloc, outputs)
    }

    fn arithmetic_register(register: Register) -> (usize, u32, u32) {
        let full = register.full_register();
        let index = [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::RBX,
            Register::RSP,
            Register::RBP,
            Register::RSI,
            Register::RDI,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ]
        .iter()
        .position(|&candidate| candidate == full)
        .unwrap();
        (
            index,
            register.size() as u32 * 8,
            if register == Register::AH { 8 } else { 0 },
        )
    }

    fn arithmetic_read(regs: &[u64; 16], register: Register) -> u64 {
        let (index, bits, shift) = arithmetic_register(register);
        (regs[index] >> shift) & (u64::MAX >> (64 - bits))
    }

    fn arithmetic_write(regs: &mut [u64; 16], register: Register, value: u64) {
        let (index, bits, shift) = arithmetic_register(register);
        let mask = u64::MAX >> (64 - bits);
        if bits >= 32 {
            regs[index] = value & mask;
        } else {
            regs[index] = (regs[index] & !(mask << shift)) | ((value & mask) << shift);
        }
    }

    fn execute_arithmetic(
        instructions: &[Instruction],
        regs: &mut [u64; 16],
    ) -> Result<(), &'static str> {
        use iced_x86::{Mnemonic, OpKind};
        let mut memory = HashMap::<u64, u8>::new();
        for inst in instructions {
            match inst.mnemonic() {
                Mnemonic::Mov => {
                    let address = if inst.memory_base() == Register::None {
                        0
                    } else {
                        arithmetic_read(regs, inst.memory_base())
                            .wrapping_add(inst.memory_displacement64())
                    };
                    let bytes = inst.memory_size().size();
                    let value = match inst.op1_kind() {
                        OpKind::Register => arithmetic_read(regs, inst.op1_register()),
                        OpKind::Memory => (0..bytes).fold(0, |value, byte| {
                            value
                                | (u64::from(
                                    *memory
                                        .get(&address.wrapping_add(byte as u64))
                                        .expect("defined arithmetic home"),
                                ) << (8 * byte))
                        }),
                        _ => inst.immediate(1),
                    };
                    if inst.op0_kind() == OpKind::Memory {
                        for byte in 0..bytes {
                            memory.insert(
                                address.wrapping_add(byte as u64),
                                (value >> (8 * byte)) as u8,
                            );
                        }
                    } else {
                        arithmetic_write(regs, inst.op0_register(), value);
                    }
                }
                Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Movzx => {
                    let source = inst.op1_register();
                    let value = arithmetic_read(regs, source);
                    let value = if inst.mnemonic() == Mnemonic::Movzx {
                        value
                    } else {
                        let shift = 64 - source.size() * 8;
                        ((value << shift) as i64 >> shift) as u64
                    };
                    arithmetic_write(regs, inst.op0_register(), value);
                }
                Mnemonic::Div | Mnemonic::Idiv | Mnemonic::Mul | Mnemonic::Imul => {
                    let source = inst.op0_register();
                    let bits = source.size() as u32 * 8;
                    let mask = u64::MAX >> (64 - bits);
                    let low_reg = gpr_register(
                        Gpr::Rax,
                        match bits {
                            8 => IrType::I8,
                            16 => IrType::I16,
                            32 => IrType::I32,
                            64 => IrType::I64,
                            _ => unreachable!(),
                        },
                    );
                    let high_reg = if bits == 8 {
                        Register::AH
                    } else {
                        gpr_register(
                            Gpr::Rdx,
                            match bits {
                                16 => IrType::I16,
                                32 => IrType::I32,
                                64 => IrType::I64,
                                _ => unreachable!(),
                            },
                        )
                    };
                    let low = arithmetic_read(regs, low_reg);
                    let source = arithmetic_read(regs, source);
                    let signed = |value: u64| (i128::from(value) << (128 - bits)) >> (128 - bits);
                    let (lo, hi) = if matches!(inst.mnemonic(), Mnemonic::Mul | Mnemonic::Imul) {
                        let product = if inst.mnemonic() == Mnemonic::Imul {
                            (signed(low) * signed(source)) as u128
                        } else {
                            u128::from(low) * u128::from(source)
                        };
                        (product as u64, (product >> bits) as u64)
                    } else {
                        if source == 0 {
                            return Err("divide by zero");
                        }
                        let dividend =
                            (u128::from(arithmetic_read(regs, high_reg)) << bits) | u128::from(low);
                        if inst.mnemonic() == Mnemonic::Idiv {
                            let dividend = if bits == 64 {
                                dividend as i128
                            } else {
                                ((dividend << (128 - 2 * bits)) as i128) >> (128 - 2 * bits)
                            };
                            let divisor = signed(source);
                            let quotient =
                                dividend.checked_div(divisor).ok_or("quotient overflow")?;
                            if quotient < -(1i128 << (bits - 1))
                                || quotient >= (1i128 << (bits - 1))
                            {
                                return Err("quotient overflow");
                            }
                            (quotient as u64, (dividend % divisor) as u64)
                        } else {
                            let quotient = dividend / u128::from(source);
                            if quotient > u128::from(mask) {
                                return Err("quotient overflow");
                            }
                            (quotient as u64, (dividend % u128::from(source)) as u64)
                        }
                    };
                    arithmetic_write(regs, low_reg, lo);
                    arithmetic_write(regs, high_reg, hi);
                }
                Mnemonic::Add | Mnemonic::Sub => {
                    let reg = inst.op0_register();
                    let left = arithmetic_read(regs, reg);
                    let right = inst.immediate(1);
                    arithmetic_write(
                        regs,
                        reg,
                        if inst.mnemonic() == Mnemonic::Add {
                            left.wrapping_add(right)
                        } else {
                            left.wrapping_sub(right)
                        },
                    );
                }
                Mnemonic::Lea => {
                    let value = arithmetic_read(regs, inst.memory_base())
                        .wrapping_add(inst.memory_displacement64());
                    arithmetic_write(regs, inst.op0_register(), value);
                }
                Mnemonic::Ret => {}
                other => panic!("unexpected arithmetic fixture instruction {other:?}"),
            }
        }
        Ok(())
    }

    #[test]
    fn emitted_division_handles_widths_remainders_and_fixed_register_cycles() {
        use iced_x86::Mnemonic;
        for ty in [IrType::I8, IrType::I16, IrType::I32, IrType::I64] {
            let bits = ty.bits();
            let mask = u64::MAX >> (64 - bits);
            for sources in [
                [Gpr::Rax, Gpr::Rdx, Gpr::Rcx],
                [Gpr::Rcx, Gpr::Rdx, Gpr::Rax],
                [Gpr::Rax, Gpr::Rcx, Gpr::Rdx],
                [Gpr::Rdx, Gpr::R10, Gpr::R8],
            ] {
                for signed in [false, true] {
                    let (func, alloc, outputs) = arithmetic_fixture(
                        ty,
                        if signed { IrOp::SDiv } else { IrOp::UDiv },
                        &sources,
                        true,
                    );
                    let selected = select_for_test(&func, &alloc, 0);
                    assert_eq!(
                        selected
                            .iter()
                            .filter(|inst| matches!(
                                inst.mnemonic(),
                                Mnemonic::Div | Mnemonic::Idiv
                            ))
                            .count(),
                        1
                    );
                    let encoded = crate::relocate(&selected, 0x1000).unwrap();
                    let decoded: Vec<_> =
                        Decoder::with_ip(64, &encoded, 0x1000, DecoderOptions::NONE)
                            .into_iter()
                            .collect();
                    for (high, low, divisor, expected) in if signed {
                        vec![
                            (
                                mask,
                                mask - 99,
                                7,
                                Ok(((-14i64) as u64 & mask, (-2i64) as u64 & mask)),
                            ),
                            (0, 100, mask - 6, Ok(((-14i64) as u64 & mask, 2))),
                            (0, 1, 0, Err("divide by zero")),
                            (mask, 1u64 << (bits - 1), mask, Err("quotient overflow")),
                        ]
                    } else {
                        vec![
                            (0, mask, 3, Ok((mask / 3, mask % 3))),
                            (
                                1,
                                0,
                                3,
                                Ok((((1u128 << bits) / 3) as u64, ((1u128 << bits) % 3) as u64)),
                            ),
                            (0, 1, 0, Err("divide by zero")),
                            (3, 0, 3, Err("quotient overflow")),
                        ]
                    } {
                        let mut regs = [0xfeed_beef_cafe_babe; 16];
                        for (source, value) in sources.into_iter().zip([high, low, divisor]) {
                            regs[source.index()] = value;
                        }
                        let actual = execute_arithmetic(&decoded, &mut regs).map(|()| {
                            (
                                arithmetic_read(
                                    &regs,
                                    phys_to_register(alloc.pins[&outputs[0]], ty),
                                ),
                                arithmetic_read(
                                    &regs,
                                    phys_to_register(alloc.pins[&outputs[1]], ty),
                                ),
                            )
                        });
                        assert_eq!(
                            actual, expected,
                            "{ty:?} signed={signed} sources={sources:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn emitted_high_products_preserve_signed_and_unsigned_high_halves() {
        for ty in [IrType::I8, IrType::I16, IrType::I32, IrType::I64] {
            let bits = ty.bits();
            let mask = u64::MAX >> (64 - bits);
            for signed in [false, true] {
                let (func, alloc, outputs) = arithmetic_fixture(
                    ty,
                    if signed { IrOp::SMulHi } else { IrOp::UMulHi },
                    &[Gpr::Rdx, Gpr::Rax],
                    false,
                );
                let selected = select_for_test(&func, &alloc, 0);
                assert_eq!(
                    selected
                        .iter()
                        .filter(|inst| matches!(
                            inst.mnemonic(),
                            iced_x86::Mnemonic::Mul | iced_x86::Mnemonic::Imul
                        ))
                        .count(),
                    1
                );
                let encoded = crate::relocate(&selected, 0x1000).unwrap();
                let decoded: Vec<_> = Decoder::with_ip(64, &encoded, 0x1000, DecoderOptions::NONE)
                    .into_iter()
                    .collect();
                for (left, right) in [(mask, mask), (mask, 2), (1u64 << (bits - 1), 2), (0, mask)] {
                    let mut regs = [0xfeed_beef_cafe_babe; 16];
                    regs[Gpr::Rdx.index()] = left;
                    regs[Gpr::Rax.index()] = right;
                    execute_arithmetic(&decoded, &mut regs).unwrap();
                    let extend = |value: u64| (i128::from(value) << (128 - bits)) >> (128 - bits);
                    let product = if signed {
                        (extend(left) * extend(right)) as u128
                    } else {
                        u128::from(left) * u128::from(right)
                    };
                    assert_eq!(
                        arithmetic_read(&regs, phys_to_register(alloc.pins[&outputs[0]], ty)),
                        ((product >> bits) as u64) & mask,
                        "{ty:?} signed={signed}"
                    );
                    assert_eq!(
                        arithmetic_read(&regs, phys_to_register(alloc.pins[&outputs[1]], ty)),
                        product as u64 & mask,
                        "{ty:?} signed={signed}"
                    );
                }
            }
        }
    }

    #[test]
    fn emitted_extensions_preserve_signed_and_unsigned_narrow_values() {
        for (source_ty, dest_ty) in [
            (IrType::I8, IrType::I16),
            (IrType::I8, IrType::I32),
            (IrType::I8, IrType::I64),
            (IrType::I16, IrType::I32),
            (IrType::I16, IrType::I64),
            (IrType::I32, IrType::I64),
        ] {
            let mut func = IrFunction {
                entry: BlockId(0),
                blocks: vec![],
                next_value: 0,
            };
            let input = func.alloc_value();
            let narrow = func.alloc_value();
            let signed = func.alloc_value();
            let unsigned = func.alloc_value();
            func.blocks.push(IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![
                    Inst {
                        dest: Some(input),
                        op: IrOp::Undef,
                        args: vec![],
                        ty: IrType::I64,
                    },
                    Inst {
                        dest: Some(narrow),
                        op: IrOp::Trunc,
                        args: vec![input],
                        ty: source_ty,
                    },
                    Inst {
                        dest: Some(signed),
                        op: IrOp::Sext,
                        args: vec![narrow],
                        ty: dest_ty,
                    },
                    Inst {
                        dest: Some(unsigned),
                        op: IrOp::Zext,
                        args: vec![narrow],
                        ty: dest_ty,
                    },
                    Inst {
                        dest: None,
                        op: IrOp::Use,
                        args: vec![signed, unsigned],
                        ty: dest_ty,
                    },
                ],
                term: IrTerminator::Ret,
            });
            let pins = HashMap::from([
                (input, PhysReg::Gpr(Gpr::Rcx)),
                (signed, PhysReg::Gpr(Gpr::R8)),
                (unsigned, PhysReg::Gpr(Gpr::R9)),
            ]);
            let alloc = crate::allocate_registers(&func, &HashSet::new(), &pins).unwrap();
            let selected = select_for_test(&func, &alloc, 0);
            let encoded = crate::relocate(&selected, 0x1000).unwrap();
            let decoded: Vec<_> = Decoder::with_ip(64, &encoded, 0x1000, DecoderOptions::NONE)
                .into_iter()
                .collect();
            let source_bits = source_ty.bits();
            let source_mask = u64::MAX >> (64 - source_bits);
            let dest_mask = u64::MAX >> (64 - dest_ty.bits());
            for value in [0, source_mask >> 1, 1 << (source_bits - 1), source_mask] {
                let mut regs = [0xfeed_beef_cafe_babe; 16];
                // Truncation must discard unrelated high bits before extension.
                regs[Gpr::Rcx.index()] = (0xfeed_beef_cafe_babe & !source_mask) | value;
                execute_arithmetic(&decoded, &mut regs).unwrap();
                let shift = 64 - source_bits;
                let expected_signed = (((value << shift) as i64 >> shift) as u64) & dest_mask;
                assert_eq!(
                    arithmetic_read(&regs, phys_to_register(alloc.pins[&signed], dest_ty)),
                    expected_signed,
                    "{source_ty:?} -> {dest_ty:?} signed value={value:#x}"
                );
                assert_eq!(
                    arithmetic_read(&regs, phys_to_register(alloc.pins[&unsigned], dest_ty)),
                    value,
                    "{source_ty:?} -> {dest_ty:?} unsigned value={value:#x}"
                );
            }
        }
    }

    #[test]
    fn native_aggregate_pic_binds_only_declared_operand_and_checks_range() {
        use kamy_core::{
            LinkField, OperandReference, Reference, ReferenceOrigin, Rva, SymbolId,
            SymbolicExpression,
        };
        let bytes = [
            0x48, 0x8b, 0x42, 0x10, 0x48, 0x83, 0xc0, 7, 0xf3, 0x0f, 0x6f, 0x02, 0x66, 0x0f, 0xd4,
            0x05, 0xec, 0x0f, 0, 0, 0xf3, 0x0f, 0x7f, 0x01, 0x48, 0x89, 0x41, 0x10, 0xc3,
        ];
        let source = SymbolId::Authored {
            module: "aggregate".into(),
            symbol: "helper".into(),
        };
        let target = SymbolId::Authored {
            module: "aggregate".into(),
            symbol: "coff:0:section:7:piece:0".into(),
        };
        let reference = Reference {
            source,
            offset: 16,
            expression: SymbolicExpression::symbol(target.clone()),
            field: LinkField::Relative32 { bias: 0 },
            origin: ReferenceOrigin::Authored,
        };
        let native = Inst {
            dest: None,
            op: IrOp::NativeInline(NativeInst {
                bytes: bytes[12..20].to_vec(),
                references: vec![OperandReference {
                    instruction: Rva::new(0x100c),
                    operand: 1,
                    reference: reference.clone(),
                }],
                reads: vec![PhysReg::Xmm(XmmReg::Xmm0)],
                writes: vec![PhysReg::Xmm(XmmReg::Xmm0)],
            }),
            args: vec![],
            ty: IrType::I128,
        };
        let alloc = InstructionAllocation::default();
        let mut selected = crate::SelectedInstructions::default();
        selected.instructions.extend(Decoder::with_ip(
            64,
            &bytes[..12],
            0x1000,
            DecoderOptions::NONE,
        ));
        select_inst(
            &alloc,
            &native,
            &HashMap::new(),
            &mut selected.instructions,
            &mut selected.references,
        );
        selected.instructions.extend(Decoder::with_ip(
            64,
            &bytes[20..],
            0x1014,
            DecoderOptions::NONE,
        ));
        let literal = 0x2000u64;
        selected
            .instructions
            .push(Instruction::with2(Code::Mov_r64_imm64, Register::R10, literal).unwrap());
        selected
            .instructions
            .push(Decoder::with_ip(64, &bytes[12..20], 0x100c, DecoderOptions::NONE).decode());
        assert_eq!(selected.references.len(), 1);
        assert_eq!(selected.references[0].reference, reference);
        crate::bind_references(&mut selected, 0, |symbol| {
            (symbol == &target).then_some(0x9000)
        })
        .unwrap();
        let encoded = crate::relocate(&selected.instructions, 0x4000).unwrap();
        let decoded: Vec<_> = Decoder::with_ip(64, &encoded, 0x4000, DecoderOptions::NONE)
            .into_iter()
            .collect();
        assert_eq!(decoded[3].ip_rel_memory_address(), 0x9000);
        assert_eq!(decoded[7].immediate64(), literal);
        assert_eq!(decoded[8].ip_rel_memory_address(), literal);
        crate::bind_references(&mut selected, 0, |_| Some(0x1_0000_0000)).unwrap();
        assert!(crate::relocate(&selected.instructions, 0x4000).is_err());
        assert!(crate::bind_references(&mut selected, 0, |_| None).is_err());
        let mut shuffle = native.clone();
        let IrOp::NativeInline(payload) = &mut shuffle.op else {
            unreachable!()
        };
        payload.bytes = vec![0x66, 0x0f, 0x70, 0x05, 0xf7, 0x0f, 0, 0, 7];
        payload.references[0].reference.offset = 4;
        payload.references[0].reference.field = LinkField::Relative32 { bias: 0 };
        LinkField::Relative32 { bias: 0 }
            .encode_into(0x2000 - 1, 0x1004, 0, &mut payload.bytes[4..8])
            .unwrap();
        let original = Decoder::with_ip(64, &payload.bytes, 0x1000, DecoderOptions::NONE).decode();
        assert_eq!(original.ip_rel_memory_address(), 0x2000);
        let mut selected = crate::SelectedInstructions::default();
        select_inst(
            &alloc,
            &shuffle,
            &HashMap::new(),
            &mut selected.instructions,
            &mut selected.references,
        );
        crate::bind_references(&mut selected, 0, |_| Some(0x9000)).unwrap();
        let encoded = crate::relocate(&selected.instructions, 0x4000).unwrap();
        let decoded = Decoder::with_ip(64, &encoded, 0x4000, DecoderOptions::NONE).decode();
        assert_eq!(decoded.ip_rel_memory_address(), 0x9000);
        assert_eq!(decoded.immediate8(), 7);
    }

    fn host_reference(target: u64) -> kamy_core::Reference {
        kamy_core::Reference {
            source: kamy_core::SymbolId::Host {
                rva: kamy_core::Rva::new(0x1000),
            },
            offset: 0,
            expression: kamy_core::SymbolicExpression::symbol(kamy_core::SymbolId::Host {
                rva: kamy_core::Rva::new(u32::try_from(target - 0x140000000).unwrap()),
            }),
            field: kamy_core::LinkField::Relative32 { bias: 0 },
            origin: kamy_core::ReferenceOrigin::HostAnalysis,
        }
    }

    fn select_for_test(
        func: &IrFunction,
        alloc: &RegAllocation,
        image_base: u64,
    ) -> Vec<Instruction> {
        let mut selected = select_instructions(func, alloc);
        crate::bind_references(&mut selected, image_base, |symbol| match symbol {
            kamy_core::SymbolId::Host { rva } => image_base.checked_add(u64::from(rva.get())),
            _ => None,
        })
        .unwrap();
        selected.instructions
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

        let pins = HashMap::from([
            (addr, PhysReg::Gpr(Gpr::Rcx)),
            (zero, PhysReg::Xmm(XmmReg::Xmm1)),
            (load128, PhysReg::Xmm(XmmReg::Xmm5)),
            (load64, PhysReg::Xmm(XmmReg::Xmm0)),
        ]);
        let alloc = crate::allocate_registers(&func, &HashSet::new(), &pins).unwrap();

        let instrs = select_for_test(&func, &alloc, 0x140000000);

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
            &std::collections::HashSet::new(),
            &HashMap::new(),
        )
        .unwrap();
        let instrs = select_for_test(&func, &alloc, 0x140000000);
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
                Inst {
                    dest: None,
                    op: IrOp::Use,
                    args: vec![v1],
                    ty: IrType::I8,
                },
            ],
            term: IrTerminator::Ret,
        });
        let pins = HashMap::from([(v0, PhysReg::Gpr(Gpr::Rcx)), (v1, PhysReg::Gpr(Gpr::Rcx))]);
        let alloc = crate::allocate_registers(&func, &HashSet::new(), &pins).unwrap();
        let instrs = select_for_test(&func, &alloc, 0x140000000);
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
    fn branch_on_add_flag_materializes_before_branch() {
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
        let pins = HashMap::from([
            (a, PhysReg::Gpr(Gpr::Rcx)),
            (b, PhysReg::Gpr(Gpr::Rdx)),
            (r, PhysReg::Gpr(Gpr::R8)),
            (cf, PhysReg::Gpr(Gpr::Rax)),
        ]);
        let alloc = crate::allocate_registers(&func, &HashSet::new(), &pins).unwrap();
        let instrs = select_for_test(&func, &alloc, 0x140000000);
        crate::relocate(&instrs, 0x140001000).expect("branch on add flag must encode");
        use iced_x86::Mnemonic;
        let mnemonics: Vec<Mnemonic> = instrs.iter().map(|i| i.mnemonic()).collect();
        assert!(
            mnemonics.contains(&Mnemonic::Add),
            "add flag must be re-executed as `add`: {mnemonics:?}"
        );
        assert!(mnemonics.contains(&Mnemonic::Setb));
        assert!(mnemonics.contains(&Mnemonic::Jne));
    }

    #[test]
    fn symbolic_address_lowers_to_position_independent_lea() {
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
                    op: IrOp::Address(host_reference(TARGET)),
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
            &std::collections::HashSet::new(),
            &HashMap::new(),
        )
        .unwrap();
        let instrs = select_for_test(&func, &alloc, 0x140000000);
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
            term: IrTerminator::Tail {
                target: host_reference(TARGET),
            },
        });

        let pins = HashMap::from([(v0, PhysReg::Gpr(Gpr::Rbx))]);
        let alloc = crate::allocate_registers(&func, &HashSet::new(), &pins).unwrap();

        let instrs = select_for_test(&func, &alloc, 0x140000000);
        let mnem: Vec<iced_x86::Mnemonic> = instrs.iter().map(|i| i.mnemonic()).collect();
        assert!(
            !mnem.contains(&iced_x86::Mnemonic::Ret),
            "a tail call must not emit ret: {mnem:?}"
        );
        let add_idx = mnem
            .iter()
            .position(|m| *m == iced_x86::Mnemonic::Add)
            .expect("frame release present");
        let jmp_idx = mnem
            .iter()
            .rposition(|m| *m == iced_x86::Mnemonic::Jmp)
            .expect("tail jmp present");
        assert!(
            add_idx < jmp_idx,
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
        let pins = HashMap::from([
            (v_val, PhysReg::Gpr(Gpr::Rax)),
            (v_cnt, PhysReg::Gpr(Gpr::Rcx)),
            (v_res, PhysReg::Gpr(Gpr::Rax)),
        ]);
        let alloc = crate::allocate_registers(&func, &HashSet::new(), &pins).unwrap();
        let instrs = select_for_test(&func, &alloc, 0x140000000);
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
