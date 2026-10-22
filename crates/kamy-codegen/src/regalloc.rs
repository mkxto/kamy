use std::collections::{HashMap, HashSet};

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, OpKind, Register,
};

use kamy_core::RejectionReason;
use kamy_core::frame::{
    ConcreteFrame, FrameAnalysis, FrameHome, FrameSave, MAX_FRAME_SIZE, ValueClass,
};
use kamy_core::ir::{
    Gpr, Inst, IrFunction, IrOp, IrTerminator, IrType, Phi, PhysReg, ValueId, XmmReg,
};

#[derive(Debug, Default)]
pub struct RegAllocation {
    // Boundary hints, not register-resident live ranges.
    pub assignments: HashMap<ValueId, PhysReg>,
    pub flag_scratch: Option<PhysReg>,
    pub homes: HashMap<ValueId, FrameHome>,
    pub frame: ConcreteFrame,
    pub analysis: FrameAnalysis,
    pub pins: HashMap<ValueId, PhysReg>,
    pub constants: HashMap<ValueId, u64>,
    pub value_types: HashMap<ValueId, IrType>,
    pub used: HashSet<ValueId>,
}

const CALLEE_SAVED_GPRS: [PhysReg; 8] = [
    PhysReg::Gpr(Gpr::Rbx),
    PhysReg::Gpr(Gpr::Rbp),
    PhysReg::Gpr(Gpr::Rsi),
    PhysReg::Gpr(Gpr::Rdi),
    PhysReg::Gpr(Gpr::R12),
    PhysReg::Gpr(Gpr::R13),
    PhysReg::Gpr(Gpr::R14),
    PhysReg::Gpr(Gpr::R15),
];

const CALLEE_SAVED_XMMS: [XmmReg; 10] = [
    XmmReg::Xmm6,
    XmmReg::Xmm7,
    XmmReg::Xmm8,
    XmmReg::Xmm9,
    XmmReg::Xmm10,
    XmmReg::Xmm11,
    XmmReg::Xmm12,
    XmmReg::Xmm13,
    XmmReg::Xmm14,
    XmmReg::Xmm15,
];

fn gpr_to_iced(gpr: Gpr) -> iced_x86::Register {
    match gpr {
        Gpr::Rax => iced_x86::Register::RAX,
        Gpr::Rcx => iced_x86::Register::RCX,
        Gpr::Rdx => iced_x86::Register::RDX,
        Gpr::Rbx => iced_x86::Register::RBX,
        Gpr::Rsp => iced_x86::Register::RSP,
        Gpr::Rbp => iced_x86::Register::RBP,
        Gpr::Rsi => iced_x86::Register::RSI,
        Gpr::Rdi => iced_x86::Register::RDI,
        Gpr::R8 => iced_x86::Register::R8,
        Gpr::R9 => iced_x86::Register::R9,
        Gpr::R10 => iced_x86::Register::R10,
        Gpr::R11 => iced_x86::Register::R11,
        Gpr::R12 => iced_x86::Register::R12,
        Gpr::R13 => iced_x86::Register::R13,
        Gpr::R14 => iced_x86::Register::R14,
        Gpr::R15 => iced_x86::Register::R15,
    }
}

#[derive(Clone, Copy)]
enum Definition<'a> {
    Inst(&'a Inst),
    Phi(&'a Phi),
}

impl Definition<'_> {
    fn ty(self) -> IrType {
        match self {
            Self::Inst(inst) => inst.ty,
            Self::Phi(phi) => phi.ty,
        }
    }

    fn push_args(self, worklist: &mut Vec<ValueId>) {
        match self {
            Self::Inst(inst) => worklist.extend(inst.args.iter().copied()),
            Self::Phi(phi) => worklist.extend(phi.args.iter().map(|(_, value)| *value)),
        }
    }
}

struct ValueModel<'a> {
    definitions: HashMap<ValueId, Definition<'a>>,
    constants: HashMap<ValueId, u64>,
    used: HashSet<ValueId>,
}

fn is_flag_op(op: &IrOp) -> bool {
    matches!(
        op,
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
            | IrOp::CarrySar
            | IrOp::SetIf
            | IrOp::BoolNot
    )
}

fn valid_arity(inst: &Inst) -> bool {
    match inst.op {
        IrOp::Const(_)
        | IrOp::Address(_)
        | IrOp::FrameAddress(_)
        | IrOp::Undef
        | IrOp::CallResult { .. } => inst.args.is_empty(),
        IrOp::Copy
        | IrOp::FrameOffset(_)
        | IrOp::FrameLogical
        | IrOp::Zext
        | IrOp::Sext
        | IrOp::Trunc
        | IrOp::Neg
        | IrOp::Not
        | IrOp::Bswap
        | IrOp::Bsf
        | IrOp::Bsr
        | IrOp::Popcnt
        | IrOp::Lzcnt
        | IrOp::Tzcnt
        | IrOp::IsZero
        | IrOp::IsNeg
        | IrOp::Parity
        | IrOp::SetIf
        | IrOp::BoolNot
        | IrOp::Load
        | IrOp::Mov128
        | IrOp::URem
        | IrOp::SRem => inst.args.len() == 1,
        IrOp::Add
        | IrOp::FrameIndex { .. }
        | IrOp::Sub
        | IrOp::UMulHi
        | IrOp::SMulHi
        | IrOp::And
        | IrOp::Or
        | IrOp::Xor
        | IrOp::Shl
        | IrOp::Shr
        | IrOp::Sar
        | IrOp::Rol
        | IrOp::Ror
        | IrOp::CarryAdd
        | IrOp::OverflowAdd
        | IrOp::BorrowSub
        | IrOp::OverflowSub
        | IrOp::AuxCarryAdd
        | IrOp::AuxBorrowSub
        | IrOp::CarryShl
        | IrOp::CarryShr
        | IrOp::CarrySar
        | IrOp::StackProbe
        | IrOp::Store => inst.args.len() == 2,
        IrOp::Mul => matches!(inst.args.len(), 1 | 2),
        IrOp::UDiv | IrOp::SDiv | IrOp::Select => inst.args.len() == 3,
        IrOp::CallIndirect { .. } => !inst.args.is_empty(),
        IrOp::NativeInline(ref native) => inst.args.len() == native.reads.len(),
        IrOp::Use | IrOp::Call { .. } => true,
    }
}

fn analyze_values(func: &IrFunction) -> Result<ValueModel<'_>, RejectionReason> {
    if func.entry.0 as usize >= func.blocks.len() {
        return Err(RejectionReason::UnsupportedInstruction);
    }
    let mut model = ValueModel {
        definitions: HashMap::new(),
        constants: HashMap::new(),
        used: HashSet::new(),
    };
    let mut worklist = Vec::new();
    for (index, block) in func.blocks.iter().enumerate() {
        if block.id.0 as usize != index {
            return Err(RejectionReason::UnsupportedInstruction);
        }
        for phi in &block.phis {
            if phi.args.is_empty()
                || phi
                    .args
                    .iter()
                    .any(|(pred, _)| pred.0 as usize >= func.blocks.len())
                || model
                    .definitions
                    .insert(phi.dest, Definition::Phi(phi))
                    .is_some()
            {
                return Err(RejectionReason::UnsupportedInstruction);
            }
        }
        for inst in &block.insts {
            if !valid_arity(inst) || (is_flag_op(&inst.op) && inst.ty != IrType::I8) {
                return Err(RejectionReason::UnsupportedInstruction);
            }
            if matches!(
                inst.op,
                IrOp::FrameAddress(_)
                    | IrOp::FrameOffset(_)
                    | IrOp::FrameLogical
                    | IrOp::FrameIndex { .. }
            ) && inst.ty != IrType::I64
            {
                return Err(RejectionReason::UnsupportedInstruction);
            }
            if inst.ty == IrType::I128
                && !matches!(
                    inst.op,
                    IrOp::Const(_)
                        | IrOp::Undef
                        | IrOp::Copy
                        | IrOp::Xor
                        | IrOp::Load
                        | IrOp::Store
                        | IrOp::Mov128
                        | IrOp::Select
                        | IrOp::Use
                        | IrOp::NativeInline(_)
                        | IrOp::CallResult { .. }
                )
            {
                return Err(RejectionReason::UnsupportedInstruction);
            }
            if let Some(dest) = inst.dest {
                if model
                    .definitions
                    .insert(dest, Definition::Inst(inst))
                    .is_some()
                {
                    return Err(RejectionReason::UnsupportedInstruction);
                }
                if let IrOp::Const(value) = inst.op {
                    model.constants.insert(dest, value);
                }
            }
            if inst.dest.is_none()
                || matches!(
                    inst.op,
                    IrOp::Store
                        | IrOp::Use
                        | IrOp::StackProbe
                        | IrOp::Call { .. }
                        | IrOp::CallIndirect { .. }
                        | IrOp::NativeInline(_)
                        | IrOp::UDiv
                        | IrOp::SDiv
                )
            {
                worklist.extend(inst.args.iter().copied());
            }
        }
        match block.term {
            IrTerminator::Jump(target) if target.0 as usize >= func.blocks.len() => {
                return Err(RejectionReason::UnsupportedInstruction);
            }
            IrTerminator::Branch {
                cond,
                taken,
                not_taken,
            } => {
                if taken.0 as usize >= func.blocks.len()
                    || not_taken.0 as usize >= func.blocks.len()
                {
                    return Err(RejectionReason::UnsupportedInstruction);
                }
                worklist.push(cond);
            }
            _ => {}
        }
    }
    for block in &func.blocks {
        if block.phis.iter().any(|phi| {
            phi.args
                .iter()
                .any(|(_, value)| !model.definitions.contains_key(value))
        }) || block.insts.iter().any(|inst| {
            inst.args
                .iter()
                .any(|value| !model.definitions.contains_key(value))
        }) {
            return Err(RejectionReason::UnsupportedInstruction);
        }
        if block.insts.iter().any(|inst| {
            matches!(inst.op, IrOp::FrameLogical | IrOp::FrameIndex { .. })
                && inst.args.iter().any(|value| {
                    model
                        .definitions
                        .get(value)
                        .is_none_or(|definition| definition.ty() != IrType::I64)
                })
        }) {
            return Err(RejectionReason::UnsupportedInstruction);
        }
    }
    while let Some(value) = worklist.pop() {
        if model.used.insert(value) {
            model
                .definitions
                .get(&value)
                .ok_or(RejectionReason::UnsupportedInstruction)?
                .push_args(&mut worklist);
        }
    }
    if model.used.iter().any(|value| {
        matches!(model.definitions[value], Definition::Inst(inst) if matches!(inst.op,
            IrOp::NativeInline(_) | IrOp::Call { .. } | IrOp::CallIndirect { .. }))
    }) {
        return Err(RejectionReason::UnsupportedInstruction);
    }
    Ok(model)
}

fn validate_implicit_arithmetic(func: &IrFunction) -> Result<(), RejectionReason> {
    for block in &func.blocks {
        let mut divisions = HashMap::new();
        let mut products = HashMap::new();
        for inst in &block.insts {
            if matches!(
                inst.op,
                IrOp::UDiv
                    | IrOp::SDiv
                    | IrOp::URem
                    | IrOp::SRem
                    | IrOp::UMulHi
                    | IrOp::SMulHi
                    | IrOp::Mul
            ) && inst.ty == IrType::I128
            {
                return Err(RejectionReason::UnsupportedInstruction);
            }
            match inst.op {
                IrOp::UDiv | IrOp::SDiv => {
                    if let Some(dest) = inst.dest {
                        divisions.insert(dest, (inst.ty, matches!(inst.op, IrOp::SDiv)));
                    }
                }
                IrOp::UMulHi | IrOp::SMulHi => {
                    if let Some(dest) = inst.dest {
                        products.insert(dest, inst.ty);
                    }
                }
                IrOp::URem | IrOp::SRem
                    if divisions.get(&inst.args[0])
                        != Some(&(inst.ty, matches!(inst.op, IrOp::SRem))) =>
                {
                    return Err(RejectionReason::UnsupportedInstruction);
                }
                IrOp::Mul
                    if inst.args.len() == 1 && products.get(&inst.args[0]) != Some(&inst.ty) =>
                {
                    return Err(RejectionReason::UnsupportedInstruction);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn register_class(register: PhysReg) -> ValueClass {
    match register {
        PhysReg::Gpr(_) => ValueClass::Gpr,
        PhysReg::Xmm(_) => ValueClass::Xmm,
        PhysReg::Flag(_) => ValueClass::Flag,
    }
}

fn class_rank(class: ValueClass) -> u8 {
    match class {
        ValueClass::Gpr => 0,
        ValueClass::Flag => 1,
        ValueClass::Xmm => 2,
    }
}

fn value_classes(
    model: &ValueModel<'_>,
    pins: &HashMap<ValueId, PhysReg>,
) -> Result<HashMap<ValueId, ValueClass>, RejectionReason> {
    let mut classes = HashMap::with_capacity(model.used.len());
    let mut fixed = HashSet::new();
    let mut edges: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
    let mut worklist = Vec::new();
    for &value in &model.used {
        let definition = model.definitions[&value];
        let ty = definition.ty();
        let mut class = (ty == IrType::I128).then_some(ValueClass::Xmm);
        if let Some(&register) = pins.get(&value) {
            class = Some(register_class(register));
        }
        if let Definition::Inst(inst) = definition {
            if let IrOp::CallResult { register } = inst.op {
                class = Some(register_class(register));
            }
            if is_flag_op(&inst.op) {
                class = Some(ValueClass::Flag);
            }
        }
        if (ty == IrType::I128 && class != Some(ValueClass::Xmm))
            || (class == Some(ValueClass::Flag) && ty != IrType::I8)
        {
            return Err(RejectionReason::UnsupportedInstruction);
        }
        if let Some(class) = class {
            fixed.insert(value);
            worklist.push((value, class));
        }
        classes.insert(value, class.unwrap_or(ValueClass::Gpr));
        let mut connect = |source| {
            edges.entry(value).or_default().push(source);
            edges.entry(source).or_default().push(value);
        };
        match definition {
            Definition::Inst(inst) if matches!(inst.op, IrOp::Copy) => connect(inst.args[0]),
            Definition::Phi(phi) => {
                for &(_, source) in &phi.args {
                    connect(source);
                }
            }
            _ => {}
        }
    }
    while let Some((value, class)) = worklist.pop() {
        if let Some(neighbors) = edges.get(&value) {
            for &neighbor in neighbors {
                if fixed.contains(&neighbor)
                    || (class == ValueClass::Flag
                        && model.definitions[&neighbor].ty() != IrType::I8)
                    || class_rank(classes[&neighbor]) >= class_rank(class)
                {
                    continue;
                }
                classes.insert(neighbor, class);
                worklist.push((neighbor, class));
            }
        }
    }
    if classes.iter().any(|(value, class)| {
        *class == ValueClass::Xmm
            && matches!(model.definitions[value].ty(), IrType::I8 | IrType::I16)
    }) {
        return Err(RejectionReason::UnsupportedInstruction);
    }
    Ok(classes)
}

fn check_frame_size(size: u32) -> Result<(), RejectionReason> {
    if size > MAX_FRAME_SIZE {
        return Err(RejectionReason::FrameResourceLimit);
    }
    Ok(())
}

fn reserve_slot(cursor: &mut u32, width: u32, alignment: u32) -> Result<u32, RejectionReason> {
    let offset = cursor
        .checked_add(alignment - 1)
        .ok_or(RejectionReason::FrameOverflow)?
        & !(alignment - 1);
    let end = offset
        .checked_add(width)
        .ok_or(RejectionReason::FrameOverflow)?;
    check_frame_size(end)?;
    *cursor = end;
    Ok(offset)
}

pub(crate) struct NativeFrameAddress {
    pub value: ValueId,
    pub adjustment: i64,
    pub ranges: [Option<(i64, i64)>; 2],
    pub bit_index: Option<(Code, u8)>,
}

impl NativeFrameAddress {
    pub(crate) fn crosses_zone(&self) -> bool {
        self.ranges.iter().flatten().any(|&(low, high)| {
            low.checked_add(self.adjustment)
                .is_some_and(|start| (low < 0) != (start < 0))
                || high
                    .checked_add(self.adjustment)
                    .is_some_and(|end| (high < 0) != (end < 0))
        })
    }
}

pub(crate) fn native_frame_address(
    inst: &Inst,
    instruction: &iced_x86::Instruction,
    constants: &HashMap<ValueId, u64>,
    analysis: &FrameAnalysis,
) -> Result<Option<NativeFrameAddress>, RejectionReason> {
    let IrOp::NativeInline(native) = &inst.op else {
        return Ok(None);
    };
    let argument = |register: Register| {
        native.reads.iter().zip(&inst.args).find_map(|(&physical, &value)| {
            matches!(physical, PhysReg::Gpr(gpr) if gpr_to_iced(gpr) == register.full_register())
                .then_some(value)
        })
    };
    let components = [
        (instruction.memory_base(), 1),
        (instruction.memory_index(), instruction.memory_index_scale()),
    ];
    let mut pointer = None;
    for &(register, scale) in &components {
        let value = argument(register);
        let ranges = value.and_then(|value| {
            analysis.offsets.get(&value).map_or_else(
                || {
                    analysis
                        .pointer_bounds
                        .get(&value)
                        .map(|bounds| [bounds.negative, bounds.incoming])
                },
                |&delta| Some([Some((delta, delta)), None]),
            )
        });
        if let Some(ranges) = ranges {
            // A frame-relative address has exactly one entry-RSP term with coefficient one.
            if pointer.is_some() || scale != 1 || register.size() != 8 {
                return Err(RejectionReason::FrameDynamic);
            }
            pointer = Some((value.unwrap(), ranges));
        }
    }
    let Some((value, ranges)) = pointer else {
        return Ok(None);
    };
    if matches!(instruction.segment_prefix(), Register::FS | Register::GS) {
        return Err(RejectionReason::FrameDynamic);
    }
    let mut adjustment = instruction.memory_displacement64() as i64;
    let mut skipped_pointer = false;
    for (register, scale) in components {
        if register == Register::None {
            continue;
        }
        let component = argument(register).ok_or(RejectionReason::FrameDynamic)?;
        if component == value && !skipped_pointer {
            skipped_pointer = true;
            continue;
        }
        let constant = constants
            .get(&component)
            .or_else(|| analysis.constants.get(&component))
            .ok_or(RejectionReason::FrameDynamic)?;
        let scaled = (*constant as i64)
            .checked_mul(i64::from(scale))
            .ok_or(RejectionReason::FrameOverflow)?;
        adjustment = adjustment
            .checked_add(scaled)
            .ok_or(RejectionReason::FrameOverflow)?;
    }
    let immediate_code = match instruction.code() {
        Code::Bt_rm16_r16 => Some(Code::Bt_rm16_imm8),
        Code::Bt_rm32_r32 => Some(Code::Bt_rm32_imm8),
        Code::Bt_rm64_r64 => Some(Code::Bt_rm64_imm8),
        Code::Bts_rm16_r16 => Some(Code::Bts_rm16_imm8),
        Code::Bts_rm32_r32 => Some(Code::Bts_rm32_imm8),
        Code::Bts_rm64_r64 => Some(Code::Bts_rm64_imm8),
        Code::Btr_rm16_r16 => Some(Code::Btr_rm16_imm8),
        Code::Btr_rm32_r32 => Some(Code::Btr_rm32_imm8),
        Code::Btr_rm64_r64 => Some(Code::Btr_rm64_imm8),
        Code::Btc_rm16_r16 => Some(Code::Btc_rm16_imm8),
        Code::Btc_rm32_r32 => Some(Code::Btc_rm32_imm8),
        Code::Btc_rm64_r64 => Some(Code::Btc_rm64_imm8),
        _ => None,
    };
    let bit_index = if let Some(code) = immediate_code {
        let value = argument(instruction.op1_register())
            .and_then(|value| {
                constants
                    .get(&value)
                    .or_else(|| analysis.constants.get(&value))
            })
            .ok_or(RejectionReason::FrameDynamic)?;
        let width = instruction.op1_register().size();
        let signed = match width {
            2 => i64::from(*value as i16),
            4 => i64::from(*value as i32),
            8 => *value as i64,
            _ => return Err(RejectionReason::UnsupportedInstruction),
        };
        // Register bit strings select a signed word before selecting a bit within that word.
        let bits = width as i64 * 8;
        let word_offset = signed.div_euclid(bits) * width as i64;
        adjustment = adjustment
            .checked_add(word_offset)
            .ok_or(RejectionReason::FrameOverflow)?;
        Some((code, (*value & (bits as u64 - 1)) as u8))
    } else {
        None
    };
    Ok(Some(NativeFrameAddress {
        value,
        adjustment,
        ranges,
        bit_index,
    }))
}

fn refine_native_frame(
    func: &IrFunction,
    constants: &HashMap<ValueId, u64>,
    analysis: &mut FrameAnalysis,
) -> Result<i64, RejectionReason> {
    let mut lowest = -i64::from(analysis.original_size);
    let mut instruction_info = None;
    let mut highest = 0;
    for block in &func.blocks {
        for inst in &block.insts {
            let IrOp::NativeInline(native) = &inst.op else {
                continue;
            };
            let mut decoder = Decoder::new(64, &native.bytes, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.is_invalid() || decoder.can_decode() {
                return Err(RejectionReason::UnsupportedInstruction);
            }
            if !matches!(
                instruction.flow_control(),
                FlowControl::Next | FlowControl::Exception
            ) {
                return Err(RejectionReason::UnsupportedInstruction);
            }
            if instruction.memory_base() == Register::None
                && instruction.memory_index() == Register::None
                && inst.args.iter().any(|value| {
                    analysis.offsets.contains_key(value)
                        || analysis.pointer_bounds.contains_key(value)
                })
                && !instruction_info
                    .get_or_insert_with(InstructionInfoFactory::new)
                    .info(&instruction)
                    .used_memory()
                    .is_empty()
            {
                return Err(RejectionReason::FrameDynamic);
            }
            if instruction.rflags_read() != 0
                || native
                    .reads
                    .iter()
                    .chain(&native.writes)
                    .any(|register| matches!(register, PhysReg::Flag(_)))
            {
                return Err(RejectionReason::UnsupportedFlags);
            }
            let direct_rsp = (0..instruction.op_count()).any(|operand| {
                instruction.op_kind(operand) == OpKind::Register
                    && instruction.op_register(operand).full_register() == Register::RSP
            });
            if direct_rsp
                && crate::MEMORY_SCRATCH_GPRS.iter().all(|register| {
                    native.reads.contains(register) || native.writes.contains(register)
                })
            {
                return Err(RejectionReason::UnsupportedInstruction);
            }
            let Some(address) = native_frame_address(inst, &instruction, constants, analysis)?
            else {
                continue;
            };
            if !analysis.offsets.contains_key(&address.value)
                && (address.crosses_zone()
                    || (address.bit_index.is_some() && i32::try_from(address.adjustment).is_err()))
                && crate::MEMORY_SCRATCH_GPRS
                    .iter()
                    .filter(|register| {
                        !native.reads.contains(register) && !native.writes.contains(register)
                    })
                    .count()
                    <= usize::from(direct_rsp)
            {
                return Err(RejectionReason::UnsupportedInstruction);
            }
            let adjustment = address.adjustment;
            let width = i64::try_from(instruction.memory_size().size())
                .map_err(|_| RejectionReason::FrameOverflow)?;
            if width == 0 {
                return Err(RejectionReason::FrameDynamic);
            }
            for (low, high) in address.ranges.into_iter().flatten() {
                let start = low
                    .checked_add(adjustment)
                    .ok_or(RejectionReason::FrameOverflow)?;
                let last = high
                    .checked_add(adjustment)
                    .ok_or(RejectionReason::FrameOverflow)?;
                let end = last
                    .checked_add(width - 1)
                    .ok_or(RejectionReason::FrameOverflow)?;
                i32::try_from(start).map_err(|_| RejectionReason::FrameOverflow)?;
                i32::try_from(end).map_err(|_| RejectionReason::FrameOverflow)?;
                if start < 0 && end >= 0 {
                    return Err(RejectionReason::FrameConflict);
                }
                lowest = lowest.min(start);
                highest = highest.max(end);
            }
        }
    }
    if lowest < 0 {
        let required = u32::try_from(lowest.checked_neg().ok_or(RejectionReason::FrameOverflow)?)
            .map_err(|_| RejectionReason::FrameOverflow)?;
        analysis.original_size = (required
            .checked_add(7)
            .ok_or(RejectionReason::FrameOverflow)?
            & !15)
            .checked_add(8)
            .ok_or(RejectionReason::FrameOverflow)?;
        check_frame_size(analysis.original_size)?;
    }
    Ok(highest)
}

fn materialized_values(func: &IrFunction, used: &HashSet<ValueId>) -> HashSet<ValueId> {
    let mut values = HashSet::new();
    for block in &func.blocks {
        for phi in &block.phis {
            if used.contains(&phi.dest) {
                values.extend(phi.args.iter().map(|(_, value)| *value));
            }
        }
        for inst in &block.insts {
            if inst.dest.is_some_and(|dest| !used.contains(&dest))
                && !matches!(
                    inst.op,
                    IrOp::Store
                        | IrOp::Use
                        | IrOp::StackProbe
                        | IrOp::Call { .. }
                        | IrOp::CallIndirect { .. }
                        | IrOp::NativeInline(_)
                        | IrOp::UDiv
                        | IrOp::SDiv
                )
            {
                continue;
            }
            // Projections depend on the producer, not on its primary result bits.
            if !(matches!(inst.op, IrOp::URem | IrOp::SRem)
                || matches!(inst.op, IrOp::Mul) && inst.args.len() == 1)
            {
                values.extend(inst.args.iter().copied());
            }
        }
        if let IrTerminator::Branch { cond, .. } = block.term {
            values.insert(cond);
        }
    }
    values
}

pub fn allocate_registers(
    func: &IrFunction,
    rsp_pinned: &HashSet<ValueId>,
    reg_pins: &HashMap<ValueId, PhysReg>,
) -> Result<RegAllocation, RejectionReason> {
    let model = analyze_values(func)?;
    let materialized = materialized_values(func, &model.used);
    validate_implicit_arithmetic(func)?;
    let mut analysis = FrameAnalysis::analyze(func, rsp_pinned, reg_pins)?;
    let native_highest = refine_native_frame(func, &model.constants, &mut analysis)?;
    check_frame_size(analysis.original_size)?;
    let mut pins: HashMap<_, _> = reg_pins
        .iter()
        .filter_map(|(&value, &register)| model.used.contains(&value).then_some((value, register)))
        .collect();
    for &value in rsp_pinned.intersection(&model.used) {
        pins.insert(value, PhysReg::Gpr(Gpr::Rsp));
    }
    for &value in &model.used {
        let Definition::Inst(inst) = model.definitions[&value] else {
            continue;
        };
        if let IrOp::CallResult { register } = inst.op {
            pins.insert(value, register);
        }
        if matches!(inst.op, IrOp::CarryShl | IrOp::CarryShr | IrOp::CarrySar) {
            let count = model
                .constants
                .get(&inst.args[1])
                .ok_or(RejectionReason::UnsupportedFlags)?;
            let width = model.definitions[&inst.args[0]].ty().bits();
            let mask = if width == 64 { 63 } else { 31 };
            if count & mask == 0 {
                return Err(RejectionReason::UnsupportedFlags);
            }
        }
    }
    if pins
        .values()
        .any(|register| matches!(register, PhysReg::Flag(_)))
    {
        return Err(RejectionReason::UnsupportedFlags);
    }
    let classes = value_classes(&model, &pins)?;
    let mut cursor = analysis.original_size;
    let mut homes = HashMap::new();
    let mut values: Vec<_> = materialized
        .iter()
        .copied()
        .filter(|value| {
            !model.constants.contains_key(value) && !analysis.offsets.contains_key(value)
        })
        .collect();
    values.sort_unstable();
    for value in values {
        let ty = model.definitions[&value].ty();
        let offset = reserve_slot(&mut cursor, ty.bytes(), ty.bytes())?;
        homes.insert(
            value,
            FrameHome {
                offset,
                ty,
                class: classes[&value],
            },
        );
    }
    let copy_scratch = reserve_slot(&mut cursor, 16, 16)?;
    let mut written: HashSet<_> = pins.values().copied().collect();
    for block in &func.blocks {
        for inst in &block.insts {
            match &inst.op {
                IrOp::NativeInline(native) => {
                    written.extend(native.reads.iter().chain(&native.writes).copied());
                }
                IrOp::Call { clobbers, .. } | IrOp::CallIndirect { clobbers } => {
                    written.extend(clobbers.iter().copied());
                }
                _ => {}
            }
        }
    }
    let mut saves = Vec::new();
    for register in CALLEE_SAVED_GPRS
        .into_iter()
        .chain(CALLEE_SAVED_XMMS.map(PhysReg::Xmm))
        .filter(|register| written.contains(register))
    {
        let width = if matches!(register, PhysReg::Xmm(_)) {
            16
        } else {
            8
        };
        let offset = reserve_slot(&mut cursor, width, width)?;
        saves.push(FrameSave { register, offset });
    }
    // Uniform relocation must preserve original entry-RSP alignment, even for empty frames.
    let overhead = cursor
        .checked_sub(analysis.original_size)
        .and_then(|size| size.checked_add(15))
        .map(|size| size & !15)
        .ok_or(RejectionReason::FrameOverflow)?;
    let stack_size = analysis
        .original_size
        .checked_add(overhead)
        .ok_or(RejectionReason::FrameOverflow)?;
    check_frame_size(stack_size)?;
    let frame = ConcreteFrame {
        stack_size,
        original_size: analysis.original_size,
        outgoing_size: analysis.outgoing_size,
        copy_scratch,
        saves,
    };
    for &delta in analysis.offsets.values() {
        i32::try_from(frame.address_offset(delta)).map_err(|_| RejectionReason::FrameOverflow)?;
    }
    i32::try_from(frame.address_offset(native_highest))
        .map_err(|_| RejectionReason::FrameOverflow)?;
    Ok(RegAllocation {
        assignments: pins.clone(),
        homes,
        frame,
        analysis,
        pins,
        constants: model.constants,
        value_types: model
            .used
            .iter()
            .map(|&value| (value, model.definitions[&value].ty()))
            .collect(),
        used: model.used,
        ..RegAllocation::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::ir::{BlockId, IrBlock, NativeInst};

    fn inst(dest: u32, op: IrOp, args: &[u32], ty: IrType) -> Inst {
        Inst {
            dest: Some(ValueId(dest)),
            op,
            args: args.iter().copied().map(ValueId).collect(),
            ty,
        }
    }

    fn used(values: &[u32]) -> Inst {
        Inst {
            dest: None,
            op: IrOp::Use,
            args: values.iter().copied().map(ValueId).collect(),
            ty: IrType::I64,
        }
    }

    fn function(insts: Vec<Inst>) -> IrFunction {
        IrFunction {
            entry: BlockId(0),
            next_value: insts
                .iter()
                .filter_map(|inst| inst.dest)
                .map(|v| v.0 + 1)
                .max()
                .unwrap_or(0),
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts,
                term: IrTerminator::Ret,
            }],
        }
    }

    fn allocate(func: &IrFunction, pins: &HashMap<ValueId, PhysReg>) -> RegAllocation {
        allocate_registers(func, &HashSet::new(), pins).unwrap()
    }

    fn call() -> Inst {
        Inst {
            dest: None,
            op: IrOp::Call {
                target: kamy_core::Reference {
                    source: kamy_core::SymbolId::Host {
                        rva: kamy_core::Rva::new(0x1000),
                    },
                    offset: 0,
                    expression: kamy_core::SymbolicExpression::symbol(kamy_core::SymbolId::Host {
                        rva: kamy_core::Rva::new(0x2000),
                    }),
                    field: kamy_core::LinkField::Relative32 { bias: 0 },
                    origin: kamy_core::ReferenceOrigin::HostAnalysis,
                },
                clobbers: kamy_core::ir::win64_volatiles(),
            },
            args: vec![],
            ty: IrType::I64,
        }
    }

    fn native(reads: Vec<PhysReg>, writes: Vec<PhysReg>, args: &[u32]) -> Inst {
        native_bytes(&[0x90], reads, writes, args)
    }

    fn native_bytes(bytes: &[u8], reads: Vec<PhysReg>, writes: Vec<PhysReg>, args: &[u32]) -> Inst {
        Inst {
            dest: None,
            op: IrOp::NativeInline(NativeInst {
                bytes: bytes.to_vec(),
                references: vec![],
                reads,
                writes,
            }),
            args: args.iter().copied().map(ValueId).collect(),
            ty: IrType::I64,
        }
    }

    #[test]
    fn only_live_nonliteral_values_receive_homes() {
        let func = function(vec![
            inst(0, IrOp::Const(10), &[], IrType::I64),
            inst(1, IrOp::Const(20), &[], IrType::I64),
            inst(2, IrOp::Add, &[0, 1], IrType::I64),
            inst(3, IrOp::Undef, &[], IrType::I64),
            inst(4, IrOp::Add, &[2, 3], IrType::I64),
            inst(5, IrOp::Undef, &[], IrType::I64),
            inst(6, IrOp::Copy, &[5], IrType::I64),
            used(&[4]),
        ]);
        let allocation = allocate(&func, &HashMap::new());
        assert_eq!(allocation.homes.len(), 3);
        for value in [2, 3, 4] {
            assert!(allocation.homes.contains_key(&ValueId(value)));
        }
        assert_eq!(allocation.constants[&ValueId(0)], 10);
        assert_eq!(allocation.constants[&ValueId(1)], 20);
        assert!(!allocation.used.contains(&ValueId(5)));
        assert!(!allocation.used.contains(&ValueId(6)));
        assert!(allocation.assignments.is_empty());
    }

    #[test]
    fn homes_preserve_width_alignment_and_disjointness() {
        let types = [
            IrType::I8,
            IrType::I16,
            IrType::I32,
            IrType::I64,
            IrType::I128,
        ];
        let mut insts: Vec<_> = types
            .iter()
            .enumerate()
            .map(|(value, &ty)| inst(value as u32, IrOp::Undef, &[], ty))
            .collect();
        insts.push(used(&[0, 1, 2, 3, 4]));
        let allocation = allocate(&function(insts), &HashMap::new());
        let mut end = allocation.analysis.original_size;
        for (value, &ty) in types.iter().enumerate() {
            let home = allocation.homes[&ValueId(value as u32)];
            assert_eq!(home.ty, ty);
            assert_eq!(home.offset % ty.bytes(), 0);
            assert!(home.offset >= end);
            end = home.offset + ty.bytes();
        }
        assert!(allocation.frame.copy_scratch >= end);
        assert_eq!(allocation.frame.copy_scratch % 16, 0);
        assert_eq!(
            (allocation.frame.stack_size - allocation.frame.original_size) % 16,
            0
        );
        assert_eq!(allocation.homes[&ValueId(4)].class, ValueClass::Xmm);
    }

    #[test]
    fn volatile_boundary_values_survive_later_definitions_and_calls() {
        let rax = PhysReg::Gpr(Gpr::Rax);
        let func = function(vec![
            inst(0, IrOp::Undef, &[], IrType::I64),
            call(),
            inst(1, IrOp::CallResult { register: rax }, &[], IrType::I64),
            call(),
            inst(2, IrOp::CallResult { register: rax }, &[], IrType::I64),
            used(&[0, 1, 2]),
        ]);
        let pins = HashMap::from([(ValueId(0), rax)]);
        let allocation = allocate(&func, &pins);
        assert_eq!(allocation.homes.len(), 3);
        assert_eq!(
            allocation.pins,
            HashMap::from([(ValueId(0), rax), (ValueId(1), rax), (ValueId(2), rax)])
        );
        assert_eq!(allocation.analysis.call_deltas.len(), 2);
        assert!(allocation.frame.saves.is_empty());
        assert!(
            allocation
                .homes
                .values()
                .all(|home| home.offset >= allocation.frame.original_size)
        );
    }

    #[test]
    fn native_inputs_and_outputs_have_independent_homes() {
        for (register, ty) in [
            (PhysReg::Gpr(Gpr::Rax), IrType::I64),
            (PhysReg::Xmm(XmmReg::Xmm0), IrType::I128),
        ] {
            let func = function(vec![
                inst(0, IrOp::Undef, &[], ty),
                native(vec![register], vec![register], &[0]),
                inst(1, IrOp::Undef, &[], ty),
                used(&[0, 1]),
            ]);
            let pins = HashMap::from([(ValueId(0), register), (ValueId(1), register)]);
            let allocation = allocate(&func, &pins);
            assert_eq!(allocation.homes.len(), 2);
            assert_ne!(
                allocation.homes[&ValueId(0)].offset,
                allocation.homes[&ValueId(1)].offset
            );
        }
    }

    #[test]
    fn scalar_xmm_class_propagates_through_copies_and_loop_phis() {
        let mut func = function(vec![inst(0, IrOp::Undef, &[], IrType::I64)]);
        func.blocks[0].term = IrTerminator::Jump(BlockId(1));
        func.blocks.push(IrBlock {
            id: BlockId(1),
            phis: vec![Phi {
                dest: ValueId(1),
                ty: IrType::I64,
                args: vec![(BlockId(0), ValueId(0)), (BlockId(1), ValueId(2))],
            }],
            insts: vec![inst(2, IrOp::Copy, &[1], IrType::I64), used(&[2])],
            term: IrTerminator::Jump(BlockId(1)),
        });
        func.next_value = 3;
        let allocation = allocate(
            &func,
            &HashMap::from([(ValueId(2), PhysReg::Xmm(XmmReg::Xmm0))]),
        );
        for value in 0..3 {
            let home = allocation.homes[&ValueId(value)];
            assert_eq!(home.class, ValueClass::Xmm);
            assert_eq!(home.ty, IrType::I64);
        }
    }

    #[test]
    fn explicit_gpr_xmm_copy_boundaries_keep_their_classes() {
        let func = function(vec![
            inst(0, IrOp::Undef, &[], IrType::I64),
            inst(1, IrOp::Copy, &[0], IrType::I64),
            used(&[1]),
        ]);
        let allocation = allocate(
            &func,
            &HashMap::from([
                (ValueId(0), PhysReg::Gpr(Gpr::Rcx)),
                (ValueId(1), PhysReg::Xmm(XmmReg::Xmm0)),
            ]),
        );
        assert_eq!(allocation.homes[&ValueId(0)].class, ValueClass::Gpr);
        assert_eq!(allocation.homes[&ValueId(1)].class, ValueClass::Xmm);
    }

    fn implicit_arithmetic(ty: IrType, signed: bool, multiply: bool) -> IrFunction {
        function(vec![
            inst(0, IrOp::Undef, &[], ty),
            inst(1, IrOp::Undef, &[], ty),
            inst(2, IrOp::Undef, &[], ty),
            inst(
                3,
                match (multiply, signed) {
                    (true, true) => IrOp::SMulHi,
                    (true, false) => IrOp::UMulHi,
                    (false, true) => IrOp::SDiv,
                    (false, false) => IrOp::UDiv,
                },
                if multiply { &[1, 2] } else { &[0, 1, 2] },
                ty,
            ),
            native(
                vec![],
                vec![PhysReg::Gpr(Gpr::Rax), PhysReg::Gpr(Gpr::Rdx)],
                &[],
            ),
            inst(
                4,
                if multiply {
                    IrOp::Mul
                } else if signed {
                    IrOp::SRem
                } else {
                    IrOp::URem
                },
                &[3],
                ty,
            ),
            used(&[0, 1, 2, 3, 4]),
        ])
    }

    #[test]
    fn implicit_arithmetic_outputs_have_homes_without_pin_lifetimes() {
        for ty in [IrType::I8, IrType::I16, IrType::I32, IrType::I64] {
            for signed in [false, true] {
                for multiply in [false, true] {
                    let func = implicit_arithmetic(ty, signed, multiply);
                    let allocation = allocate(&func, &HashMap::new());
                    assert!(allocation.homes.contains_key(&ValueId(3)));
                    assert!(allocation.homes.contains_key(&ValueId(4)));
                    assert_eq!(allocation.homes.len(), 5);
                }
            }
        }
    }

    #[test]
    fn projection_dependencies_do_not_store_dead_primary_bits() {
        for multiply in [false, true] {
            let mut func = implicit_arithmetic(IrType::I64, false, multiply);
            func.blocks[0].insts.last_mut().unwrap().args = vec![ValueId(4)];
            let allocation = allocate(&func, &HashMap::new());
            assert!(allocation.used.contains(&ValueId(3)));
            assert!(!allocation.homes.contains_key(&ValueId(3)));
            assert!(allocation.homes.contains_key(&ValueId(4)));
        }
    }

    #[test]
    fn malformed_implicit_arithmetic_fails_with_semantic_rejection() {
        for multiply in [false, true] {
            for invalid in 0..5 {
                let mut func = implicit_arithmetic(IrType::I64, false, multiply);
                match invalid {
                    0 => func.blocks[0].insts[3].args.clear(),
                    1 => func.blocks[0].insts[5].args = vec![ValueId(0)],
                    2 => func.blocks[0].insts[5].ty = IrType::I32,
                    3 => func.blocks[0].insts[3].ty = IrType::I128,
                    _ => {
                        func.blocks[0].insts[5].op = if multiply { IrOp::SRem } else { IrOp::Mul };
                    }
                }
                assert!(matches!(
                    allocate_registers(&func, &HashSet::new(), &HashMap::new()),
                    Err(RejectionReason::UnsupportedInstruction)
                ));
            }
        }
        let mut func = implicit_arithmetic(IrType::I64, false, false);
        func.blocks[0].insts[5].op = IrOp::SRem;
        assert!(matches!(
            allocate_registers(&func, &HashSet::new(), &HashMap::new()),
            Err(RejectionReason::UnsupportedInstruction)
        ));
    }

    #[test]
    fn nonvolatile_saves_follow_effects_and_live_boundary_pins() {
        let rbx = PhysReg::Gpr(Gpr::Rbx);
        let r13 = PhysReg::Gpr(Gpr::R13);
        let xmm8 = PhysReg::Xmm(XmmReg::Xmm8);
        let mut custom_call = call();
        if let IrOp::Call { clobbers, .. } = &mut custom_call.op {
            clobbers.push(PhysReg::Xmm(XmmReg::Xmm7));
        }
        let func = function(vec![
            inst(0, IrOp::Undef, &[], IrType::I64),
            inst(1, IrOp::Undef, &[], IrType::I64),
            native(vec![], vec![r13, xmm8], &[]),
            custom_call,
            used(&[0]),
        ]);
        let allocation = allocate(
            &func,
            &HashMap::from([(ValueId(0), rbx), (ValueId(1), PhysReg::Gpr(Gpr::R15))]),
        );
        let mut end = allocation.frame.copy_scratch + 16;
        for save in &allocation.frame.saves {
            let width = if matches!(save.register, PhysReg::Xmm(_)) {
                16
            } else {
                8
            };
            assert_eq!(save.offset % width, 0);
            assert!(save.offset >= end);
            end = save.offset + width;
        }
        assert!(allocation.frame.stack_size >= end);
    }

    #[test]
    fn original_stack_aliases_rematerialize_below_generated_homes() {
        let func = function(vec![
            inst(0, IrOp::Undef, &[], IrType::I64),
            inst(1, IrOp::Const(40), &[], IrType::I64),
            inst(2, IrOp::Sub, &[0, 1], IrType::I64),
            inst(3, IrOp::Copy, &[2], IrType::I64),
            inst(4, IrOp::Load, &[3], IrType::I64),
            inst(5, IrOp::Add, &[2, 1], IrType::I64),
            used(&[3, 4, 5]),
        ]);
        let allocation = allocate_registers(
            &func,
            &HashSet::from([ValueId(0), ValueId(2), ValueId(5)]),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(allocation.homes.len(), 1);
        assert_eq!(allocation.analysis.offsets[&ValueId(3)], -40);
        assert!(allocation.homes[&ValueId(4)].offset >= allocation.frame.original_size);
        assert_eq!(allocation.frame.address_offset(-40), 0);
        assert_eq!(
            allocation.frame.address_offset(8),
            i64::from(allocation.frame.stack_size) + 8
        );
    }

    #[test]
    fn slots_reject_resource_limits_and_numeric_overflow_distinctly() {
        let mut cursor = MAX_FRAME_SIZE;
        assert!(matches!(
            reserve_slot(&mut cursor, 1, 1),
            Err(RejectionReason::FrameResourceLimit)
        ));
        assert_eq!(cursor, MAX_FRAME_SIZE);
        cursor = u32::MAX;
        assert!(matches!(
            reserve_slot(&mut cursor, 16, 16),
            Err(RejectionReason::FrameOverflow)
        ));
        assert_eq!(cursor, u32::MAX);
    }

    #[test]
    fn oversized_reconstructed_frames_reject_with_resource_reason() {
        let func = function(vec![
            inst(0, IrOp::Undef, &[], IrType::I64),
            inst(1, IrOp::Const(u64::from(MAX_FRAME_SIZE)), &[], IrType::I64),
            inst(2, IrOp::Sub, &[0, 1], IrType::I64),
            inst(3, IrOp::Add, &[2, 1], IrType::I64),
            used(&[3]),
        ]);
        assert!(matches!(
            allocate_registers(
                &func,
                &HashSet::from([ValueId(0), ValueId(2), ValueId(3)]),
                &HashMap::new(),
            ),
            Err(RejectionReason::FrameResourceLimit)
        ));
    }

    #[test]
    fn native_frame_displacements_extend_the_original_zone() {
        for (base, bytes) in [
            (Gpr::Rsp, &[0x48, 0x8B, 0x44, 0x24, 0xB0][..]),
            (Gpr::Rbp, &[0x48, 0x8B, 0x45, 0xB0][..]),
        ] {
            let func = function(vec![
                inst(0, IrOp::Undef, &[], IrType::I64),
                native_bytes(
                    bytes,
                    vec![PhysReg::Gpr(base)],
                    vec![PhysReg::Gpr(Gpr::Rax)],
                    &[0],
                ),
                inst(1, IrOp::Undef, &[], IrType::I64),
                used(&[0, 1]),
            ]);
            let allocation = allocate_registers(
                &func,
                &HashSet::from([ValueId(0)]),
                &HashMap::from([(ValueId(1), PhysReg::Gpr(Gpr::Rax))]),
            )
            .unwrap();
            assert_eq!(allocation.analysis.original_size, 88);
            assert_eq!(allocation.frame.original_size, 88);
            assert!(allocation.homes[&ValueId(1)].offset >= 88);
            assert_eq!(allocation.frame.address_offset(-80), 8);
        }
    }

    #[test]
    fn native_frame_access_cannot_straddle_the_relocated_split() {
        let func = function(vec![
            inst(0, IrOp::Undef, &[], IrType::I64),
            inst(1, IrOp::Const(52), &[], IrType::I64),
            inst(2, IrOp::Sub, &[0, 1], IrType::I64),
            native_bytes(
                &[0x48, 0x8B, 0x45, 0x30],
                vec![PhysReg::Gpr(Gpr::Rbp)],
                vec![],
                &[2],
            ),
            used(&[0]),
        ]);
        assert!(matches!(
            allocate_registers(&func, &HashSet::from([ValueId(0)]), &HashMap::new()),
            Err(RejectionReason::FrameConflict)
        ));
    }

    #[test]
    fn native_frame_indices_require_checked_literal_offsets() {
        for (index, expected) in [
            (IrOp::Const(2), Ok(72)),
            (IrOp::Const(u64::MAX), Ok(88)),
            (IrOp::Undef, Err(RejectionReason::FrameDynamic)),
            (
                IrOp::Const(i64::MAX as u64),
                Err(RejectionReason::FrameOverflow),
            ),
        ] {
            let func = function(vec![
                inst(0, IrOp::Undef, &[], IrType::I64),
                inst(1, index, &[], IrType::I64),
                native_bytes(
                    &[0x48, 0x8B, 0x44, 0xCC, 0xB0],
                    vec![PhysReg::Gpr(Gpr::Rsp), PhysReg::Gpr(Gpr::Rcx)],
                    vec![],
                    &[0, 1],
                ),
                used(&[0]),
            ]);
            let result = allocate_registers(&func, &HashSet::from([ValueId(0)]), &HashMap::new());
            match expected {
                Ok(size) => assert_eq!(result.unwrap().frame.original_size, size),
                Err(reason) => assert!(matches!(result, Err(actual) if actual == reason)),
            }
        }
    }

    #[test]
    fn native_frame_extents_preserve_resource_and_overflow_causes() {
        for (bytes, reason) in [
            (
                &[0x48, 0x8B, 0x84, 0x24, 0xFF, 0xFF, 0xFF, 0x7F][..],
                RejectionReason::FrameOverflow,
            ),
            (
                &[0x48, 0x8B, 0x84, 0x24, 0x00, 0x00, 0x00, 0xFF][..],
                RejectionReason::FrameResourceLimit,
            ),
        ] {
            let func = function(vec![
                inst(0, IrOp::Undef, &[], IrType::I64),
                native_bytes(bytes, vec![PhysReg::Gpr(Gpr::Rsp)], vec![], &[0]),
                used(&[0]),
            ]);
            assert!(matches!(
                allocate_registers(&func, &HashSet::from([ValueId(0)]), &HashMap::new()),
                Err(actual) if actual == reason
            ));
        }
    }

    #[test]
    fn only_native_direct_rsp_operands_need_a_free_physical_scratch() {
        for (bytes, occupied, rejects) in [
            (&[0x48, 0x89, 0xE0][..], 7, true),
            (&[0x48, 0x89, 0xE0][..], 6, false),
            (&[0x48, 0x8B, 0x04, 0x24][..], 7, false),
        ] {
            let mut reads = vec![PhysReg::Gpr(Gpr::Rsp)];
            reads.extend_from_slice(&crate::MEMORY_SCRATCH_GPRS[..occupied]);
            let mut insts: Vec<_> = (0..=occupied as u32)
                .map(|value| inst(value, IrOp::Undef, &[], IrType::I64))
                .collect();
            insts.push(native_bytes(
                bytes,
                reads,
                vec![],
                &(0..=occupied as u32).collect::<Vec<_>>(),
            ));
            insts.push(used(&[0]));
            let result = allocate_registers(
                &function(insts),
                &HashSet::from([ValueId(0)]),
                &HashMap::new(),
            );
            if rejects {
                assert!(matches!(
                    result,
                    Err(RejectionReason::UnsupportedInstruction)
                ));
            } else {
                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn native_frame_proof_rejects_truncated_or_multiple_instructions() {
        for bytes in [&[][..], &[0x48, 0x8B][..], &[0x90, 0x90][..]] {
            let func = function(vec![native_bytes(bytes, vec![], vec![], &[])]);
            assert!(matches!(
                allocate_registers(&func, &HashSet::new(), &HashMap::new()),
                Err(RejectionReason::UnsupportedInstruction)
            ));
        }
    }

    #[test]
    fn stack_probe_keeps_its_proven_inputs_without_memory_homes() {
        let func = function(vec![
            inst(0, IrOp::Const(4096), &[], IrType::I64),
            inst(1, IrOp::FrameAddress(0), &[], IrType::I64),
            Inst {
                dest: None,
                op: IrOp::StackProbe,
                args: vec![ValueId(0), ValueId(1)],
                ty: IrType::I64,
            },
        ]);
        let allocation = allocate_registers(
            &func,
            &HashSet::from([ValueId(1)]),
            &HashMap::from([(ValueId(0), PhysReg::Gpr(Gpr::Rax))]),
        )
        .unwrap();
        assert_eq!(allocation.used, HashSet::from([ValueId(0), ValueId(1)]));
        assert!(allocation.homes.is_empty());
        assert!(allocation.analysis.original_size >= 4096);
        assert_eq!(allocation.analysis.original_size % 16, 8);
        assert_eq!(allocation.analysis.outgoing_size, 0);
        assert!(allocation.analysis.call_deltas.is_empty());
    }

    #[test]
    fn malformed_dependencies_and_flag_widths_fail_closed() {
        for func in [
            function(vec![inst(0, IrOp::Copy, &[9], IrType::I64), used(&[0])]),
            function(vec![
                inst(0, IrOp::Undef, &[], IrType::I64),
                inst(1, IrOp::BoolNot, &[0], IrType::I64),
                used(&[1]),
            ]),
            function(vec![
                inst(0, IrOp::Undef, &[], IrType::I64),
                inst(0, IrOp::Undef, &[], IrType::I64),
                used(&[0]),
            ]),
        ] {
            assert!(matches!(
                allocate_registers(&func, &HashSet::new(), &HashMap::new()),
                Err(RejectionReason::UnsupportedInstruction)
            ));
        }
    }
}
