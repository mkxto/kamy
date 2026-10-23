use super::*;
use kamy_core::{FrameHome, FramePointerBounds, ValueClass};

fn memory(offset: u32) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RSP, i64::from(offset))
}

fn class(alloc: &RegAllocation, value: ValueId, ty: IrType) -> ValueClass {
    alloc.homes.get(&value).map_or_else(
        || match alloc.pins.get(&value) {
            Some(PhysReg::Xmm(_)) => ValueClass::Xmm,
            Some(PhysReg::Flag(_)) => ValueClass::Flag,
            _ if ty == IrType::I128 => ValueClass::Xmm,
            _ => ValueClass::Gpr,
        },
        |home| home.class,
    )
}

fn load_home(out: &mut Vec<Instruction>, home: &FrameHome, register: PhysReg) {
    let code = if matches!(register, PhysReg::Xmm(_)) {
        xmm_load_code(home.ty)
    } else {
        load_code(home.ty)
    };
    out.push(
        Instruction::with2(
            code,
            phys_to_register(register, home.ty),
            memory(home.offset),
        )
        .unwrap(),
    );
}

fn store_home(out: &mut Vec<Instruction>, home: &FrameHome, register: PhysReg) {
    let code = if matches!(register, PhysReg::Xmm(_)) {
        xmm_store_code(home.ty)
    } else {
        store_code(home.ty)
    };
    out.push(
        Instruction::with2(
            code,
            memory(home.offset),
            phys_to_register(register, home.ty),
        )
        .unwrap(),
    );
}

fn load_value(
    alloc: &RegAllocation,
    value: ValueId,
    register: PhysReg,
    out: &mut Vec<Instruction>,
) {
    let ty = value_type(alloc, value);
    if let Some(&delta) = alloc.analysis.offsets.get(&value) {
        if matches!(register, PhysReg::Xmm(_)) {
            out.push(
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    memory(alloc.frame.copy_scratch),
                    Register::RAX,
                )
                .unwrap(),
            );
            out.push(
                Instruction::with2(
                    Code::Lea_r64_m,
                    Register::RAX,
                    MemoryOperand::with_base_displ(
                        Register::RSP,
                        alloc.frame.address_offset(delta),
                    ),
                )
                .unwrap(),
            );
            out.push(
                Instruction::with2(
                    Code::Movq_xmm_rm64,
                    phys_to_register(register, IrType::I128),
                    Register::RAX,
                )
                .unwrap(),
            );
            out.push(
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RAX,
                    memory(alloc.frame.copy_scratch),
                )
                .unwrap(),
            );
        } else {
            out.push(
                Instruction::with2(
                    Code::Lea_r64_m,
                    phys_to_register(register, IrType::I64),
                    MemoryOperand::with_base_displ(
                        Register::RSP,
                        alloc.frame.address_offset(delta),
                    ),
                )
                .unwrap(),
            );
        }
    } else if let Some(&constant) = alloc.constants.get(&value) {
        if matches!(register, PhysReg::Xmm(_)) {
            if constant == 0 {
                let reg = phys_to_register(register, IrType::I128);
                out.push(Instruction::with2(Code::Xorps_xmm_xmmm128, reg, reg).unwrap());
            } else {
                for (offset, value) in [
                    (0, constant as u32),
                    (4, (constant >> 32) as u32),
                    (8, 0),
                    (12, 0),
                ] {
                    out.push(
                        Instruction::with2(
                            Code::Mov_rm32_imm32,
                            memory(alloc.frame.copy_scratch + offset),
                            value,
                        )
                        .unwrap(),
                    );
                }
                out.push(
                    Instruction::with2(
                        xmm_load_code(ty),
                        phys_to_register(register, IrType::I128),
                        memory(alloc.frame.copy_scratch),
                    )
                    .unwrap(),
                );
            }
        } else {
            let code = match ty {
                IrType::I8 => Code::Mov_r8_imm8,
                IrType::I16 => Code::Mov_r16_imm16,
                IrType::I32 => Code::Mov_r32_imm32,
                IrType::I64 | IrType::I128 => Code::Mov_r64_imm64,
            };
            let reg = phys_to_register(register, ty);
            if matches!(ty, IrType::I64 | IrType::I128) {
                out.push(Instruction::with2(code, reg, constant).unwrap());
            } else {
                out.push(Instruction::with2(code, reg, constant as u32).unwrap());
            }
        }
    } else {
        let home = &alloc.homes[&value];
        if (home.class == ValueClass::Xmm) == matches!(register, PhysReg::Xmm(_)) {
            load_home(out, home, register);
        } else if matches!(register, PhysReg::Xmm(_)) {
            out.push(
                Instruction::with2(
                    if home.ty == IrType::I32 {
                        Code::Movd_xmm_rm32
                    } else {
                        Code::Movq_xmm_rm64
                    },
                    phys_to_register(register, IrType::I128),
                    memory(home.offset),
                )
                .unwrap(),
            );
        } else {
            out.push(
                Instruction::with2(
                    load_code(home.ty),
                    phys_to_register(register, home.ty),
                    memory(home.offset),
                )
                .unwrap(),
            );
        }
    }
}

fn load_logical_value(
    alloc: &RegAllocation,
    value: ValueId,
    register: PhysReg,
    scratch: Register,
    out: &mut Vec<Instruction>,
) {
    if let Some(&delta) = alloc.analysis.offsets.get(&value) {
        out.push(
            Instruction::with2(
                Code::Lea_r64_m,
                phys_to_register(register, IrType::I64),
                MemoryOperand::with_base_displ(
                    Register::RSP,
                    i64::from(alloc.frame.stack_size) + delta,
                ),
            )
            .unwrap(),
        );
        return;
    }
    load_value(alloc, value, register, out);
    let Some(bounds) = alloc.analysis.pointer_bounds.get(&value) else {
        return;
    };
    if bounds.negative.is_none() {
        return;
    }
    let register = phys_to_register(register, IrType::I64);
    let end = 0x7FFF_A000_0000 + out.len() as u64 * 16;
    if bounds.incoming.is_some() {
        out.push(
            Instruction::with2(
                Code::Lea_r64_m,
                scratch,
                MemoryOperand::with_base_displ(Register::RSP, i64::from(alloc.frame.original_size)),
            )
            .unwrap(),
        );
        out.push(Instruction::with2(Code::Cmp_rm64_r64, register, scratch).unwrap());
        out.push(Instruction::with_branch(Code::Jae_rel32_64, end).unwrap());
    }
    // Negative objects move uniformly; incoming objects retain their entry addresses.
    out.push(
        Instruction::with2(
            Code::Lea_r64_m,
            register,
            MemoryOperand::with_base_displ(
                register,
                i64::from(alloc.frame.stack_size - alloc.frame.original_size),
            ),
        )
        .unwrap(),
    );
    if bounds.incoming.is_some() {
        let mut landing = Instruction::with(Code::Nopd);
        landing.set_ip(end);
        out.push(landing);
    }
}

fn adjust_register(out: &mut Vec<Instruction>, register: Register, mut delta: i64) {
    while delta != 0 {
        let part = delta.clamp(i64::from(i32::MIN), i64::from(i32::MAX));
        out.push(
            Instruction::with2(
                Code::Lea_r64_m,
                register,
                MemoryOperand::with_base_displ(register, part),
            )
            .unwrap(),
        );
        delta -= part;
    }
}

fn runtime_pointer(
    alloc: &RegAllocation,
    register: Register,
    bounds: FramePointerBounds,
    out: &mut Vec<Instruction>,
) {
    if bounds.negative.is_none() {
        return;
    }
    let incoming = 0x7FFF_D000_0000 + out.len() as u64 * 16;
    if bounds.incoming.is_some() {
        out.push(
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RAX,
                MemoryOperand::with_base_displ(Register::RSP, i64::from(alloc.frame.stack_size)),
            )
            .unwrap(),
        );
        out.push(Instruction::with2(Code::Cmp_rm64_r64, register, Register::RAX).unwrap());
        out.push(Instruction::with_branch(Code::Jae_rel32_64, incoming).unwrap());
    }
    adjust_register(
        out,
        register,
        -i64::from(alloc.frame.stack_size - alloc.frame.original_size),
    );
    if bounds.incoming.is_some() {
        let mut landing = Instruction::with(Code::Nopd);
        landing.set_ip(incoming);
        out.push(landing);
    }
}

fn emit_frame_pointer(
    alloc: &RegAllocation,
    inst: &kamy_core::ir::Inst,
    out: &mut Vec<Instruction>,
) {
    let dest = inst.dest.expect("frame pointer destination");
    let (source, index, displacement, subtract, bounds) = match inst.op {
        IrOp::FrameOffset(offset) => (
            inst.args[0],
            None,
            offset,
            false,
            alloc.analysis.pointer_bounds[&dest],
        ),
        IrOp::FrameIndex {
            displacement,
            subtract,
            bounds,
        } => (
            inst.args[0],
            Some(inst.args[1]),
            displacement,
            subtract,
            bounds,
        ),
        _ => {
            if let Some(indexed) = alloc.analysis.indexed_offsets.get(&dest) {
                (
                    indexed.base,
                    Some(indexed.index),
                    indexed.displacement,
                    indexed.subtract,
                    indexed.bounds,
                )
            } else {
                let (source, displacement) = alloc.analysis.derived_offsets[&dest];
                (
                    source,
                    None,
                    displacement,
                    false,
                    alloc.analysis.pointer_bounds[&dest],
                )
            }
        }
    };
    let source_bounds = alloc.analysis.offsets.get(&source).map_or_else(
        || alloc.analysis.pointer_bounds.get(&source).copied(),
        |&delta| {
            Some(FramePointerBounds {
                negative: (delta < 0).then_some((delta, delta)),
                incoming: (delta >= 0).then_some((delta, delta)),
            })
        },
    );
    let identity =
        displacement == 0 && index.is_none_or(|index| alloc.constants.get(&index) == Some(&0));
    let same_zone = identity
        || source_bounds.is_some_and(|source| {
            (source.incoming.is_none() && bounds.incoming.is_none())
                || (source.negative.is_none() && bounds.negative.is_none())
        });
    let register = PhysReg::Gpr(Gpr::R11);
    if same_zone {
        load_value(alloc, source, register, out);
    } else {
        load_logical_value(alloc, source, register, Register::RAX, out);
    }
    if let Some(index) = index.filter(|index| alloc.constants.get(index) != Some(&0)) {
        load_value(alloc, index, PhysReg::Gpr(Gpr::R10), out);
        out.push(
            Instruction::with2(
                if subtract {
                    Code::Sub_rm64_r64
                } else {
                    Code::Add_rm64_r64
                },
                Register::R11,
                Register::R10,
            )
            .unwrap(),
        );
    }
    adjust_register(out, Register::R11, displacement);
    if !same_zone {
        runtime_pointer(alloc, Register::R11, bounds, out);
    }
    save_value(alloc, dest, register, out);
}

fn save_value(
    alloc: &RegAllocation,
    value: ValueId,
    register: PhysReg,
    out: &mut Vec<Instruction>,
) {
    if let Some(home) = alloc.homes.get(&value) {
        store_home(out, home, register);
    }
}

fn adjust_rsp(out: &mut Vec<Instruction>, delta: i64) {
    if delta != 0 {
        out.push(
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RSP,
                MemoryOperand::with_base_displ(Register::RSP, delta),
            )
            .unwrap(),
        );
    }
}

fn saved_register(register: PhysReg) -> Register {
    phys_to_register(register, IrType::I64)
}

fn emit_frame(alloc: &RegAllocation, out: &mut Vec<Instruction>) {
    let mut remaining = alloc.frame.stack_size;
    while remaining > 0 {
        let amount = remaining.min(4096);
        out.push(
            Instruction::with2(
                if amount <= 127 {
                    Code::Sub_rm64_imm8
                } else {
                    Code::Sub_rm64_imm32
                },
                Register::RSP,
                amount as i32,
            )
            .unwrap(),
        );
        if alloc.frame.stack_size >= 4096 {
            out.push(Instruction::with2(Code::Test_rm32_r32, memory(0), Register::EAX).unwrap());
        }
        remaining -= amount;
    }
    for save in &alloc.frame.saves {
        let code = if matches!(save.register, PhysReg::Xmm(_)) {
            Code::Movups_xmmm128_xmm
        } else {
            Code::Mov_rm64_r64
        };
        out.push(
            Instruction::with2(code, memory(save.offset), saved_register(save.register)).unwrap(),
        );
    }
}

fn emit_epilogue(
    func: &IrFunction,
    alloc: &RegAllocation,
    block: BlockId,
    out: &mut Vec<Instruction>,
) {
    for save in alloc.frame.saves.iter().rev() {
        let code = if matches!(save.register, PhysReg::Xmm(_)) {
            Code::Movups_xmm_xmmm128
        } else {
            Code::Mov_r64_rm64
        };
        out.push(
            Instruction::with2(code, saved_register(save.register), memory(save.offset)).unwrap(),
        );
    }
    // Restores must not overwrite an explicitly pinned ABI output.
    for inst in &func.block(block).insts {
        if matches!(inst.op, IrOp::Use) {
            for &value in &inst.args {
                if let Some(&register) = alloc.pins.get(&value)
                    && register != PhysReg::Gpr(Gpr::Rsp)
                {
                    load_value(alloc, value, register, out);
                }
            }
        }
    }
    if alloc.frame.stack_size != 0 {
        out.push(
            Instruction::with2(
                if alloc.frame.stack_size <= 127 {
                    Code::Add_rm64_imm8
                } else {
                    Code::Add_rm64_imm32
                },
                Register::RSP,
                alloc.frame.stack_size as i32,
            )
            .unwrap(),
        );
    }
}

struct SelectionScratch {
    allocation: InstructionAllocation,
    instruction: kamy_core::ir::Inst,
}

fn local_allocation(
    alloc: &RegAllocation,
    inst: &kamy_core::ir::Inst,
    local: &mut InstructionAllocation,
) {
    local.flag_scratch = Some(PhysReg::Gpr(Gpr::Rax));
    let gprs = [Gpr::R8, Gpr::R9, Gpr::R10];
    let xmms = [XmmReg::Xmm0, XmmReg::Xmm1, XmmReg::Xmm2];
    let mut gi = 0;
    let mut xi = 0;
    let dest_xmm = inst.dest.is_some_and(|dest| {
        matches!(
            inst.op,
            IrOp::Copy | IrOp::Mov128 | IrOp::Load | IrOp::Select
        ) && class(alloc, dest, inst.ty) == ValueClass::Xmm
    }) || (matches!(inst.op, IrOp::Xor) && inst.ty == IrType::I128);
    for (index, &arg) in inst.args.iter().enumerate() {
        if local.contains(arg) {
            continue;
        }
        let use_xmm = match inst.op {
            IrOp::Copy | IrOp::Mov128 => {
                class(alloc, arg, value_type(alloc, arg)) == ValueClass::Xmm
            }
            IrOp::Store => {
                index == 1 && class(alloc, arg, value_type(alloc, arg)) == ValueClass::Xmm
            }
            IrOp::Select => index > 0 && dest_xmm,
            IrOp::Xor => inst.ty == IrType::I128,
            _ => false,
        };
        let phys = if use_xmm {
            let phys = PhysReg::Xmm(xmms[xi]);
            xi += 1;
            phys
        } else {
            let phys = PhysReg::Gpr(gprs[gi]);
            gi += 1;
            phys
        };
        local.insert(arg, phys, value_type(alloc, arg));
    }
    if let Some(dest) = inst.dest {
        local.insert(
            dest,
            if dest_xmm {
                PhysReg::Xmm(XmmReg::Xmm3)
            } else {
                PhysReg::Gpr(Gpr::R11)
            },
            inst.ty,
        );
    }
}

fn emit_aux_flag(
    alloc: &RegAllocation,
    local: &InstructionAllocation,
    inst: &kamy_core::ir::Inst,
    out: &mut Vec<Instruction>,
) {
    let ty = value_type(alloc, inst.args[0]);
    let a = reg_of(local, inst.args[0], ty);
    let b = reg_of(local, inst.args[1], ty);
    let x = gpr_register(Gpr::Rax, ty);
    let result = gpr_register(Gpr::Rcx, ty);
    out.push(Instruction::with2(mov_code(ty), x, a).unwrap());
    out.push(Instruction::with2(alu_code(&IrOp::Xor, ty), x, b).unwrap());
    out.push(Instruction::with2(mov_code(ty), result, a).unwrap());
    let operation = if matches!(inst.op, IrOp::AuxCarryAdd) {
        IrOp::Add
    } else {
        IrOp::Sub
    };
    out.push(Instruction::with2(alu_code(&operation, ty), result, b).unwrap());
    out.push(Instruction::with2(alu_code(&IrOp::Xor, ty), x, result).unwrap());
    out.push(Instruction::with2(Code::Test_rm8_imm8, Register::AL, 0x10u32).unwrap());
    out.push(
        Instruction::with1(
            Code::Setne_rm8,
            reg_of(local, inst.dest.unwrap(), IrType::I8),
        )
        .unwrap(),
    );
}

fn emit_select(
    local: &InstructionAllocation,
    inst: &kamy_core::ir::Inst,
    out: &mut Vec<Instruction>,
) {
    let dest = local.register(inst.dest.unwrap());
    let cond = reg_of(local, inst.args[0], IrType::I8);
    if matches!(dest, PhysReg::Xmm(_)) {
        let false_label = 0x7FFF_C000_0000 + out.len() as u64 * 16;
        let end_label = false_label + 1;
        out.push(Instruction::with2(Code::Test_rm8_r8, cond, cond).unwrap());
        out.push(Instruction::with_branch(Code::Je_rel32_64, false_label).unwrap());
        out.push(
            Instruction::with2(
                Code::Movaps_xmm_xmmm128,
                phys_to_register(dest, inst.ty),
                reg_of(local, inst.args[1], inst.ty),
            )
            .unwrap(),
        );
        out.push(Instruction::with_branch(Code::Jmp_rel32_64, end_label).unwrap());
        let mut instruction = Instruction::with2(
            Code::Movaps_xmm_xmmm128,
            phys_to_register(dest, inst.ty),
            reg_of(local, inst.args[2], inst.ty),
        )
        .unwrap();
        instruction.set_ip(false_label);
        out.push(instruction);
        let mut end = Instruction::with(Code::Nopd);
        end.set_ip(end_label);
        out.push(end);
    } else if inst.ty == IrType::I8 {
        out.push(
            Instruction::with2(
                Code::Movzx_r32_rm8,
                phys_to_register(dest, IrType::I32),
                reg_of(local, inst.args[2], IrType::I8),
            )
            .unwrap(),
        );
        out.push(
            Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::EAX,
                reg_of(local, inst.args[1], IrType::I8),
            )
            .unwrap(),
        );
        out.push(Instruction::with2(Code::Test_rm8_r8, cond, cond).unwrap());
        out.push(
            Instruction::with2(
                Code::Cmovne_r32_rm32,
                phys_to_register(dest, IrType::I32),
                Register::EAX,
            )
            .unwrap(),
        );
    } else {
        let dest = phys_to_register(dest, inst.ty);
        out.push(
            Instruction::with2(
                mov_code(inst.ty),
                dest,
                reg_of(local, inst.args[2], inst.ty),
            )
            .unwrap(),
        );
        out.push(Instruction::with2(Code::Test_rm8_r8, cond, cond).unwrap());
        let code = match inst.ty {
            IrType::I16 => Code::Cmovne_r16_rm16,
            IrType::I32 => Code::Cmovne_r32_rm32,
            _ => Code::Cmovne_r64_rm64,
        };
        out.push(Instruction::with2(code, dest, reg_of(local, inst.args[1], inst.ty)).unwrap());
    }
}

fn capture_outputs(
    func: &IrFunction,
    alloc: &RegAllocation,
    block: BlockId,
    index: usize,
    out: &mut Vec<Instruction>,
) {
    for output in &func.block(block).insts[index + 1..] {
        let register = match &output.op {
            IrOp::CallResult { register } => Some(*register),
            IrOp::Undef => output.dest.and_then(|dest| alloc.pins.get(&dest).copied()),
            _ => break,
        };
        if let (Some(dest), Some(register)) = (output.dest, register) {
            save_value(alloc, dest, register, out);
        }
    }
}

fn captured_output(func: &IrFunction, block: BlockId, index: usize) -> bool {
    func.block(block).insts[..index]
        .iter()
        .rev()
        .find(|inst| !matches!(inst.op, IrOp::Undef | IrOp::CallResult { .. }))
        .is_some_and(|inst| {
            matches!(
                inst.op,
                IrOp::Call { .. } | IrOp::CallIndirect { .. } | IrOp::NativeInline(_)
            )
        })
}

fn rebase_native_address(
    alloc: &RegAllocation,
    address: &crate::regalloc::NativeFrameAddress,
    scratch: PhysReg,
    out: &mut Vec<Instruction>,
) {
    load_value(alloc, address.value, scratch, out);
    let register = phys_to_register(scratch, IrType::I64);
    out.push(Instruction::with2(Code::Sub_rm64_r64, register, Register::RSP).unwrap());
    let overhead = i64::from(alloc.frame.stack_size - alloc.frame.original_size);
    let logical = 0x7FFF_B000_0000 + out.len() as u64 * 16;
    let bounds = &alloc.analysis.pointer_bounds[&address.value];
    if bounds.negative.is_some() {
        if bounds.incoming.is_some() {
            out.push(
                Instruction::with2(
                    Code::Cmp_rm64_imm32,
                    register,
                    alloc.frame.original_size as i32,
                )
                .unwrap(),
            );
            out.push(Instruction::with_branch(Code::Jae_rel32_64, logical).unwrap());
        }
        out.push(
            Instruction::with2(
                Code::Lea_r64_m,
                register,
                MemoryOperand::with_base_displ(register, overhead),
            )
            .unwrap(),
        );
        if bounds.incoming.is_some() {
            let mut landing = Instruction::with(Code::Nopd);
            landing.set_ip(logical);
            out.push(landing);
        }
    }
    let mut adjustment = address.adjustment;
    while adjustment != 0 {
        let part = adjustment.clamp(i64::from(i32::MIN), i64::from(i32::MAX));
        out.push(
            Instruction::with2(
                Code::Lea_r64_m,
                register,
                MemoryOperand::with_base_displ(register, part),
            )
            .unwrap(),
        );
        adjustment -= part;
    }
    let incoming = 0x7FFF_B100_0000 + out.len() as u64 * 16;
    out.push(
        Instruction::with2(
            Code::Cmp_rm64_imm32,
            register,
            alloc.frame.stack_size as i32,
        )
        .unwrap(),
    );
    out.push(Instruction::with_branch(Code::Jge_rel32_64, incoming).unwrap());
    out.push(
        Instruction::with2(
            Code::Lea_r64_m,
            register,
            MemoryOperand::with_base_displ(register, -overhead),
        )
        .unwrap(),
    );
    let mut landing = Instruction::with2(Code::Add_rm64_r64, register, Register::RSP).unwrap();
    landing.set_ip(incoming);
    out.push(landing);
}

fn emit_boundary(
    func: &IrFunction,
    alloc: &RegAllocation,
    location: (BlockId, usize),
    inst: &kamy_core::ir::Inst,
    local: &mut InstructionAllocation,
    out: &mut Vec<Instruction>,
    references: &mut Vec<crate::references::InstructionReference>,
) {
    let (block, index) = location;
    local.clear();
    if let IrOp::NativeInline(native) = &inst.op {
        for (&arg, &phys) in inst.args.iter().zip(&native.reads) {
            if phys == PhysReg::Gpr(Gpr::Rsp) {
                continue;
            }
            load_value(alloc, arg, phys, out);
        }
        let decoded = Decoder::new(64, &native.bytes, DecoderOptions::NONE).decode();
        let direct_rsp = (0..decoded.op_count()).any(|operand| {
            decoded.op_kind(operand) == iced_x86::OpKind::Register
                && decoded.op_register(operand).full_register() == Register::RSP
        });
        let scratch = direct_rsp.then(|| {
            let scratch = crate::MEMORY_SCRATCH_GPRS
                .iter()
                .copied()
                .find(|phys| !native.reads.contains(phys) && !native.writes.contains(phys))
                .expect("native stack operand scratch");
            let value = native
                .reads
                .iter()
                .zip(&inst.args)
                .find_map(|(&phys, &value)| (phys == PhysReg::Gpr(Gpr::Rsp)).then_some(value))
                .expect("native stack read value");
            load_value(alloc, value, scratch, out);
            scratch
        });
        let address = crate::regalloc::native_frame_address(
            inst,
            &decoded,
            &alloc.constants,
            &alloc.analysis,
        )
        .expect("validated native frame address");
        let direct_address = address.as_ref().and_then(|address| {
            if alloc.analysis.offsets.contains_key(&address.value)
                || address.crosses_zone()
                || address.bit_index.is_none()
                || i32::try_from(address.adjustment).is_err()
            {
                return None;
            }
            native
                .reads
                .iter()
                .zip(&inst.args)
                .find_map(|(&physical, &value)| {
                    (value == address.value && matches!(physical, PhysReg::Gpr(_)))
                        .then_some(phys_to_register(physical, IrType::I64))
                })
        });
        let rebased = address.as_ref().and_then(|address| {
            if alloc.analysis.offsets.contains_key(&address.value)
                || (!address.crosses_zone() && address.bit_index.is_none())
                || direct_address.is_some()
            {
                return None;
            }
            let temporary = crate::MEMORY_SCRATCH_GPRS
                .iter()
                .copied()
                .find(|phys| {
                    Some(*phys) != scratch
                        && !native.reads.contains(phys)
                        && !native.writes.contains(phys)
                })
                .expect("native frame address scratch");
            rebase_native_address(alloc, address, temporary, out);
            Some(phys_to_register(temporary, IrType::I64))
        });
        let start = out.len();
        select_inst(local, inst, &alloc.constants, out, references);
        let instruction = &mut out[start];
        if let Some(address) = address {
            let replacement = if let Some(&delta) = alloc.analysis.offsets.get(&address.value) {
                Some((
                    Register::RSP,
                    alloc.frame.address_offset(delta + address.adjustment),
                ))
            } else if let Some(base) = direct_address {
                address.bit_index.map(|_| (base, address.adjustment))
            } else {
                rebased.map(|register| (register, 0))
            };
            if let Some((base, displacement)) = replacement {
                instruction.set_memory_base(base);
                instruction.set_memory_index(Register::None);
                instruction.set_memory_index_scale(1);
                instruction.set_memory_displacement64(displacement as u64);
                // iced declares the address width here; a 64-bit base still encodes a signed disp32.
                instruction.set_memory_displ_size(8);
            }
            if let Some((code, bit)) = address.bit_index {
                instruction.set_code(code);
                instruction.set_op1_kind(iced_x86::OpKind::Immediate8);
                instruction.set_immediate8(bit);
            }
        }
        if let Some(PhysReg::Gpr(scratch)) = scratch {
            for operand in 0..instruction.op_count() {
                let original = instruction.op_register(operand);
                if instruction.op_kind(operand) == iced_x86::OpKind::Register
                    && original.full_register() == Register::RSP
                {
                    let ty = match original.size() {
                        1 => IrType::I8,
                        2 => IrType::I16,
                        4 => IrType::I32,
                        _ => IrType::I64,
                    };
                    instruction.set_op_register(operand, gpr_register(scratch, ty));
                }
            }
        }
        capture_outputs(func, alloc, block, index, out);
        return;
    }
    for (position, &arg) in inst.args.iter().enumerate() {
        if alloc.analysis.offsets.contains_key(&arg) && !alloc.pins.contains_key(&arg) {
            continue;
        }
        let phys = if matches!(inst.op, IrOp::CallIndirect { .. }) && position == 0 {
            PhysReg::Gpr(Gpr::R11)
        } else if let Some(&phys) = alloc.pins.get(&arg) {
            phys
        } else {
            continue;
        };
        if phys == PhysReg::Gpr(Gpr::Rsp) {
            continue;
        }
        load_value(alloc, arg, phys, out);
        if matches!(inst.op, IrOp::CallIndirect { .. }) && position == 0 {
            local.insert(arg, phys, value_type(alloc, arg));
        }
    }
    let delta = alloc.analysis.call_deltas[&(block, index)];
    let adjustment = i64::from(alloc.frame.original_size) + delta;
    adjust_rsp(out, adjustment);
    select_inst(local, inst, &alloc.constants, out, references);
    adjust_rsp(out, -adjustment);
    capture_outputs(func, alloc, block, index, out);
}

fn emit_instruction(
    func: &IrFunction,
    alloc: &RegAllocation,
    location: (BlockId, usize),
    inst: &kamy_core::ir::Inst,
    scratch: &mut SelectionScratch,
    out: &mut Vec<Instruction>,
    references: &mut Vec<crate::references::InstructionReference>,
) {
    let (block, index) = location;
    if matches!(inst.op, IrOp::Const(_) | IrOp::StackProbe)
        || inst
            .dest
            .is_some_and(|dest| alloc.analysis.offsets.contains_key(&dest))
    {
        return;
    }
    if let IrOp::Call { .. } | IrOp::CallIndirect { .. } | IrOp::NativeInline(_) = &inst.op {
        emit_boundary(
            func,
            alloc,
            (block, index),
            inst,
            &mut scratch.allocation,
            out,
            references,
        );
        return;
    }
    if matches!(inst.op, IrOp::Use) {
        return;
    }
    let physical_output = matches!(inst.op, IrOp::CallResult { .. })
        || (matches!(inst.op, IrOp::Undef)
            && inst.dest.is_some_and(|dest| alloc.pins.contains_key(&dest)));
    if physical_output && captured_output(func, block, index) {
        return;
    }
    if let IrOp::CallResult { register } = &inst.op {
        if let Some(dest) = inst.dest {
            save_value(alloc, dest, *register, out);
        }
        return;
    }
    if matches!(inst.op, IrOp::Undef) {
        if let Some(dest) = inst.dest {
            if let Some(&phys) = alloc.pins.get(&dest) {
                save_value(alloc, dest, phys, out);
            } else if let Some(home) = alloc.homes.get(&dest) {
                let phys = if home.class == ValueClass::Xmm {
                    PhysReg::Xmm(XmmReg::Xmm3)
                } else {
                    PhysReg::Gpr(Gpr::R11)
                };
                let reg = phys_to_register(phys, home.ty);
                if home.class == ValueClass::Xmm {
                    out.push(Instruction::with2(Code::Xorps_xmm_xmmm128, reg, reg).unwrap());
                } else {
                    out.push(
                        Instruction::with2(
                            Code::Mov_r64_imm64,
                            phys_to_register(phys, IrType::I64),
                            0u64,
                        )
                        .unwrap(),
                    );
                }
                store_home(out, home, phys);
            }
        }
        return;
    }
    if matches!(inst.op, IrOp::URem | IrOp::SRem)
        || (matches!(inst.op, IrOp::Mul) && inst.args.len() == 1)
    {
        return;
    }
    if inst.dest.is_some_and(|dest| !alloc.used.contains(&dest))
        && !matches!(inst.op, IrOp::UDiv | IrOp::SDiv | IrOp::Store)
    {
        return;
    }
    if matches!(inst.op, IrOp::FrameLogical) {
        let register = PhysReg::Gpr(Gpr::R11);
        load_logical_value(alloc, inst.args[0], register, Register::RAX, out);
        if let Some(dest) = inst.dest {
            save_value(alloc, dest, register, out);
        }
        return;
    }
    if matches!(inst.op, IrOp::FrameOffset(_) | IrOp::FrameIndex { .. })
        || inst.dest.is_some_and(|dest| {
            alloc.analysis.indexed_offsets.contains_key(&dest)
                || alloc.analysis.derived_offsets.contains_key(&dest)
        })
    {
        emit_frame_pointer(alloc, inst, out);
        return;
    }
    let SelectionScratch {
        allocation: local,
        instruction: temporary,
    } = scratch;
    local.clear();
    let mut fixed_inst = None;
    if matches!(
        inst.op,
        IrOp::UDiv | IrOp::SDiv | IrOp::UMulHi | IrOp::SMulHi
    ) {
        let registers: &[Gpr] = if matches!(inst.op, IrOp::UDiv | IrOp::SDiv) {
            &[Gpr::Rdx, Gpr::Rax, Gpr::R8]
        } else {
            &[Gpr::Rax, Gpr::R8]
        };
        // One SSA value can occupy multiple implicit input registers.
        temporary.dest = inst.dest;
        temporary.op.clone_from(&inst.op);
        temporary.ty = inst.ty;
        temporary.args.clear();
        temporary.args.extend_from_slice(&inst.args);
        let mut next = u32::MAX;
        for (index, (&arg, &register)) in inst.args.iter().zip(registers).enumerate() {
            while Some(ValueId(next)) == inst.dest || local.contains(ValueId(next)) {
                next -= 1;
            }
            let value = ValueId(next);
            next -= 1;
            temporary.args[index] = value;
            local.insert(value, PhysReg::Gpr(register), inst.ty);
            load_value(alloc, arg, PhysReg::Gpr(register), out);
        }
        local.insert(
            inst.dest.unwrap(),
            PhysReg::Gpr(if matches!(inst.op, IrOp::UDiv | IrOp::SDiv) {
                Gpr::Rax
            } else {
                Gpr::Rdx
            }),
            inst.ty,
        );
        fixed_inst = Some(&*temporary);
    } else {
        local_allocation(alloc, inst, local);
        let logical_pair = inst.args.len() == 2
            && matches!(
                inst.op,
                IrOp::Sub | IrOp::BorrowSub | IrOp::OverflowSub | IrOp::AuxBorrowSub
            )
            && inst.args.iter().all(|value| {
                alloc.analysis.offsets.contains_key(value)
                    || alloc.analysis.pointer_bounds.contains_key(value)
            });
        for (index, &arg) in inst.args.iter().enumerate() {
            if inst.args[..index].contains(&arg) {
                continue;
            }
            if index == 1
                && alloc.constants.contains_key(&arg)
                && matches!(
                    inst.op,
                    IrOp::Shl
                        | IrOp::Shr
                        | IrOp::Sar
                        | IrOp::Rol
                        | IrOp::Ror
                        | IrOp::CarryShl
                        | IrOp::CarryShr
                        | IrOp::CarrySar
                )
            {
                continue;
            }
            if logical_pair {
                load_logical_value(alloc, arg, local.register(arg), Register::RAX, out);
            } else {
                load_value(alloc, arg, local.register(arg), out);
            }
        }
    }
    if matches!(inst.op, IrOp::AuxCarryAdd | IrOp::AuxBorrowSub) {
        emit_aux_flag(alloc, local, inst, out);
    } else if matches!(inst.op, IrOp::Select) {
        emit_select(local, inst, out);
    } else {
        select_inst(
            local,
            fixed_inst.unwrap_or(inst),
            &alloc.constants,
            out,
            references,
        );
    }
    if let Some(dest) = inst.dest {
        save_value(alloc, dest, local.register(dest), out);
        if matches!(
            inst.op,
            IrOp::UDiv | IrOp::SDiv | IrOp::UMulHi | IrOp::SMulHi
        ) {
            for projection in &func.block(block).insts {
                if projection.args == [dest]
                    && (matches!(projection.op, IrOp::URem | IrOp::SRem)
                        || (matches!(projection.op, IrOp::Mul) && projection.args.len() == 1))
                {
                    let phys = if matches!(projection.op, IrOp::Mul) {
                        Gpr::Rax
                    } else {
                        Gpr::Rdx
                    };
                    save_value(alloc, projection.dest.unwrap(), PhysReg::Gpr(phys), out);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CopyStep {
    Save(ValueId),
    Transfer {
        dest: ValueId,
        source: ValueId,
        saved: bool,
    },
}

struct ParallelCopies {
    pending: Vec<Option<(ValueId, ValueId)>>,
    dependencies: Vec<Option<usize>>,
    readers: Vec<usize>,
    ready: Vec<usize>,
    remaining: usize,
    cycle_cursor: usize,
    saved: Option<ValueId>,
    #[cfg(test)]
    work: usize,
}

impl ParallelCopies {
    fn new(copies: impl Iterator<Item = (ValueId, ValueId)>) -> Self {
        let mut pending = Vec::with_capacity(copies.size_hint().1.unwrap_or(0));
        pending.extend(copies.filter(|(dest, source)| dest != source).map(Some));
        let destinations: HashMap<_, _> = pending
            .iter()
            .enumerate()
            .map(|(index, copy)| (copy.unwrap().0, index))
            .collect();
        let mut readers = vec![0; pending.len()];
        let dependencies: Vec<_> = pending
            .iter()
            .map(|copy| {
                let dependency = destinations.get(&copy.unwrap().1).copied();
                if let Some(index) = dependency {
                    readers[index] += 1;
                }
                dependency
            })
            .collect();
        let mut ready = Vec::with_capacity(pending.len());
        ready.extend(
            readers
                .iter()
                .enumerate()
                .filter_map(|(index, &readers)| (readers == 0).then_some(index)),
        );
        Self {
            remaining: pending.len(),
            #[cfg(test)]
            work: pending.len() * 4,
            pending,
            dependencies,
            readers,
            ready,
            cycle_cursor: 0,
            saved: None,
        }
    }

    fn next(&mut self) -> Option<CopyStep> {
        if self.remaining == 0 {
            return None;
        }
        if let Some(index) = self.ready.pop() {
            let (dest, source) = self.pending[index].take().expect("pending ready copy");
            self.remaining -= 1;
            #[cfg(test)]
            {
                self.work += 1;
            }
            if let Some(dependency) = self.dependencies[index] {
                self.readers[dependency] -= 1;
                #[cfg(test)]
                {
                    self.work += 1;
                }
                if self.readers[dependency] == 0 && self.pending[dependency].is_some() {
                    self.ready.push(dependency);
                }
            }
            return Some(CopyStep::Transfer {
                dest,
                source,
                saved: self.saved == Some(source),
            });
        }
        // After leaves drain, remaining components are cycles. Drain each broken cycle
        // completely before reusing the one existing scratch slot for another component.
        while self.pending[self.cycle_cursor].is_none() {
            self.cycle_cursor += 1;
            #[cfg(test)]
            {
                self.work += 1;
            }
        }
        let value = self.pending[self.cycle_cursor].unwrap().0;
        #[cfg(test)]
        {
            self.work += 1;
        }
        self.saved = Some(value);
        self.ready.push(self.cycle_cursor);
        Some(CopyStep::Save(value))
    }
}

fn emit_edge(
    func: &IrFunction,
    alloc: &RegAllocation,
    pred: BlockId,
    succ: BlockId,
    out: &mut Vec<Instruction>,
) {
    let mut copies = ParallelCopies::new(
        func.block(succ)
            .phis
            .iter()
            .filter(|phi| alloc.homes.contains_key(&phi.dest))
            .filter_map(|phi| {
                phi.args
                    .iter()
                    .find(|(block, _)| *block == pred)
                    .map(|(_, source)| (phi.dest, *source))
            }),
    );
    while let Some(step) = copies.next() {
        let (dest, source, saved) = match step {
            CopyStep::Save(value) => (value, value, false),
            CopyStep::Transfer {
                dest,
                source,
                saved,
            } => (dest, source, saved),
        };
        let home = &alloc.homes[&dest];
        let phys = if home.class == ValueClass::Xmm {
            PhysReg::Xmm(XmmReg::Xmm0)
        } else {
            PhysReg::Gpr(Gpr::R10)
        };
        let cycle_home = FrameHome {
            offset: alloc.frame.copy_scratch,
            ty: home.ty,
            class: home.class,
        };
        match step {
            CopyStep::Save(_) => {
                load_home(out, home, phys);
                store_home(out, &cycle_home, phys);
            }
            CopyStep::Transfer { .. } => {
                if saved {
                    load_home(out, &cycle_home, phys);
                } else {
                    load_value(alloc, source, phys, out);
                }
                store_home(out, home, phys);
            }
        }
    }
}

pub(super) fn select(
    func: &IrFunction,
    alloc: &RegAllocation,
) -> crate::references::SelectedInstructions {
    let order = block_order(func);
    let labels: HashMap<_, _> = order
        .iter()
        .enumerate()
        .map(|(index, &block)| (block, LABEL_BASE + index as u64 * 0x1000))
        .collect();
    let mut out = Vec::new();
    let mut references = Vec::new();
    let mut scratch = SelectionScratch {
        allocation: InstructionAllocation::default(),
        instruction: kamy_core::ir::Inst {
            dest: None,
            op: IrOp::Undef,
            args: Vec::with_capacity(3),
            ty: IrType::I64,
        },
    };
    emit_frame(alloc, &mut out);
    let mut landings = Vec::new();
    let mut next_landing = LANDING_BASE;
    for &block_id in &order {
        let block = func.block(block_id);
        let start = out.len();
        for (index, inst) in block.insts.iter().enumerate() {
            emit_instruction(
                func,
                alloc,
                (block_id, index),
                inst,
                &mut scratch,
                &mut out,
                &mut references,
            );
        }
        match &block.term {
            IrTerminator::Ret => {
                emit_epilogue(func, alloc, block_id, &mut out);
                out.push(Instruction::with(Code::Retnq));
            }
            IrTerminator::Tail { target } => {
                emit_epilogue(func, alloc, block_id, &mut out);
                references.push(crate::references::InstructionReference {
                    instruction: out.len(),
                    operand: 0,
                    reference: target.clone(),
                });
                out.push(Instruction::with_branch(Code::Jmp_rel32_64, 0).unwrap());
            }
            IrTerminator::Jump(succ) => {
                emit_edge(func, alloc, block_id, *succ, &mut out);
                out.push(Instruction::with_branch(Code::Jmp_rel32_64, labels[succ]).unwrap());
            }
            IrTerminator::Branch {
                cond,
                taken,
                not_taken,
            } => {
                load_value(alloc, *cond, PhysReg::Gpr(Gpr::R10), &mut out);
                out.push(
                    Instruction::with2(Code::Test_rm8_r8, Register::R10L, Register::R10L).unwrap(),
                );
                let mut targets = [0; 2];
                for (index, succ) in [*taken, *not_taken].into_iter().enumerate() {
                    if func
                        .block(succ)
                        .phis
                        .iter()
                        .any(|phi| alloc.homes.contains_key(&phi.dest))
                    {
                        targets[index] = next_landing;
                        landings.push((next_landing, block_id, succ));
                        next_landing += 0x1000;
                    } else {
                        targets[index] = labels[&succ];
                    }
                }
                out.push(Instruction::with_branch(Code::Jne_rel32_64, targets[0]).unwrap());
                out.push(Instruction::with_branch(Code::Jmp_rel32_64, targets[1]).unwrap());
            }
            // A nonreturning call still needs an in-range return PC for unwinding.
            IrTerminator::Unreachable | IrTerminator::NoReturn => {
                out.push(Instruction::with(Code::Int3))
            }
        }
        if out.len() == start {
            out.push(Instruction::with(Code::Nopd));
        }
        out[start].set_ip(labels[&block_id]);
    }
    for (label, pred, succ) in landings {
        let start = out.len();
        emit_edge(func, alloc, pred, succ, &mut out);
        out.push(Instruction::with_branch(Code::Jmp_rel32_64, labels[&succ]).unwrap());
        out[start].set_ip(label);
    }
    crate::references::SelectedInstructions {
        instructions: out,
        references,
    }
}

#[cfg(test)]
mod parallel_copy_tests {
    use super::*;

    fn execute(
        copies: &[(u32, u32)],
        initial: &HashMap<u32, u128>,
    ) -> (HashMap<u32, u128>, usize, usize) {
        let mut values = initial.clone();
        let mut scratch = None;
        let mut saves = 0;
        let mut plan = ParallelCopies::new(
            copies
                .iter()
                .map(|&(dest, source)| (ValueId(dest), ValueId(source))),
        );
        while let Some(step) = plan.next() {
            match step {
                CopyStep::Save(value) => {
                    scratch = Some(values[&value.0]);
                    saves += 1;
                }
                CopyStep::Transfer {
                    dest,
                    source,
                    saved,
                } => {
                    let value = if saved {
                        scratch.unwrap()
                    } else {
                        values[&source.0]
                    };
                    values.insert(dest.0, value);
                }
            }
        }
        for &(dest, source) in copies {
            assert_eq!(values[&dest], initial[&source], "destination {dest}");
        }
        (values, plan.work, saves)
    }

    #[test]
    fn simultaneous_copies_preserve_multiple_cycles_self_copies_and_external_sources() {
        let initial: HashMap<_, _> = (0..20)
            .map(|value| {
                (
                    value,
                    (u128::from(value) + 1)
                        .wrapping_mul(0x1020_3040_5060_7081_91a2_b3c4_d5e6_f701u128),
                )
            })
            .collect();
        // Independent two- and three-cycles, fanout, a self-copy, and rematerialized sources.
        let copies = [
            (0, 1),
            (1, 0),
            (2, 3),
            (3, 4),
            (4, 2),
            (5, 0),
            (6, 6),
            (7, 18),
            (8, 19),
        ];
        let (_, work, saves) = execute(&copies, &initial);
        assert_eq!(saves, 2);
        assert!(work <= copies.len() * 8);
        let mut reverse = copies;
        reverse.reverse();
        execute(&reverse, &initial);
    }

    #[test]
    fn wide_and_reverse_chain_planning_work_is_linear_and_results_are_simultaneous() {
        for count in [64u32, 512, 4096, 16384] {
            let initial: HashMap<_, _> = (0..=count)
                .map(|value| (value, u128::from(value) * 257 + 11))
                .collect();
            let chain: Vec<_> = (0..count).map(|value| (value, value + 1)).collect();
            let wide: Vec<_> = (0..count).map(|value| (value, count)).collect();
            for (name, mut copies) in [("chain", chain), ("wide", wide)] {
                for reverse in [false, true] {
                    if reverse {
                        copies.reverse();
                    }
                    let (_, work, saves) = execute(&copies, &initial);
                    assert_eq!(saves, 0);
                    assert!(work <= count as usize * 8, "{name} n={count} work={work}");
                    eprintln!("phi-plan {name} reverse={reverse} transfers={count} work={work}");
                }
            }
        }
    }
}
