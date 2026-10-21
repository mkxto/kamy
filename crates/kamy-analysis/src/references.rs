use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, ensure};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use kamy_core::{Module, Reference, ReferenceKind, RelocKind, Rva, Terminator};

#[derive(Debug, Clone, Default)]
pub struct FunctionReferences {
    pub incoming: Vec<usize>,
    pub outgoing: Vec<usize>,
    pub unresolved: Vec<Reference>,
}

#[derive(Debug, Clone, Default)]
pub struct ReferenceModel {
    pub references: Vec<Reference>,
    pub functions: BTreeMap<Rva, FunctionReferences>,
}

impl ReferenceModel {
    pub fn is_resolved(&self, entry: Rva) -> bool {
        self.functions
            .get(&entry)
            .is_some_and(|function| function.unresolved.is_empty())
    }
}

#[derive(Clone, Copy)]
struct Interval {
    start: u32,
    end: u32,
}

impl Interval {
    fn contains(self, address: u32) -> bool {
        self.start <= address && address < self.end
    }
}

struct Ownership {
    functions: BTreeMap<Rva, u32>,
    blocks: Vec<(Interval, Rva)>,
    uncertain: BTreeSet<Rva>,
}

impl Ownership {
    fn build(module: &Module) -> anyhow::Result<Self> {
        let mut ownership = Self {
            functions: BTreeMap::new(),
            blocks: Vec::new(),
            uncertain: BTreeSet::new(),
        };
        for function in &module.functions {
            let end = function
                .blocks
                .iter()
                .map(|block| block.end.get())
                .max()
                .unwrap_or(function.entry.get());
            ensure!(
                ownership.functions.insert(function.entry, end).is_none(),
                "duplicate recovered function entry {}",
                function.entry
            );
            if !function
                .blocks
                .iter()
                .any(|block| block.start == function.entry)
                || !module.is_executable(function.entry)
            {
                ownership.uncertain.insert(function.entry);
            }
            for block in &function.blocks {
                let interval = Interval {
                    start: block.start.get(),
                    end: block.end.get(),
                };
                let valid = interval.start >= function.entry.get()
                    && interval.start < interval.end
                    && module.section_at(block.start).is_some_and(|section| {
                        section.flags.execute
                            && section
                                .rva
                                .get()
                                .checked_add(section.virtual_size)
                                .is_some_and(|end| interval.end <= end)
                            && section.bytes_at(block.start).is_some_and(|bytes| {
                                bytes.len() >= (interval.end - interval.start) as usize
                            })
                    });
                if valid {
                    ownership.blocks.push((interval, function.entry));
                } else {
                    ownership.uncertain.insert(function.entry);
                }
            }
        }
        ownership
            .blocks
            .sort_by_key(|(range, entry)| (range.start, range.end, *entry));
        let mut previous_block: Option<(Interval, Rva)> = None;
        for &(range, entry) in &ownership.blocks {
            if let Some((previous, previous_entry)) = previous_block {
                if range.start < previous.end {
                    ownership.uncertain.insert(entry);
                    ownership.uncertain.insert(previous_entry);
                }
            }
            if previous_block.is_none_or(|(previous, _)| range.end > previous.end) {
                previous_block = Some((range, entry));
            }
        }
        let mut furthest: Option<(Rva, u32)> = None;
        for (&entry, &end) in &ownership.functions {
            if let Some((previous, previous_end)) = furthest {
                if entry.get() < previous_end {
                    ownership.uncertain.insert(previous);
                    ownership.uncertain.insert(entry);
                }
            }
            if furthest.is_none_or(|(_, previous_end)| end > previous_end) {
                furthest = Some((entry, end));
            }
        }
        Ok(ownership)
    }

    fn owner(&self, address: Rva) -> Option<Rva> {
        let (&entry, &end) = self.functions.range(..=address).next_back()?;
        (address == entry || address.get() < end).then_some(entry)
    }
}

/// Recovered blocks are decoded as instructions. Outside those blocks, possible
/// encodings and raw code pointers are evidence of uncertainty, never proof of
/// instruction boundaries or complete reference recovery (D22).
pub fn build_reference_model(
    module: &Module,
    metadata: &[Reference],
) -> anyhow::Result<ReferenceModel> {
    let ownership = Ownership::build(module).context("validating recovered reference ownership")?;
    let mut references = metadata.to_vec();
    let mut classified = Vec::new();
    let mut instruction_starts = BTreeSet::new();
    let mut cfg_edges = BTreeSet::new();
    let mut call_edges = BTreeSet::new();
    let mut uncertain = ownership.uncertain.clone();

    for reference in metadata {
        let width = match reference.kind {
            ReferenceKind::Absolute => 8,
            ReferenceKind::ImageRelative | ReferenceKind::Unwind | ReferenceKind::Opaque => 4,
            ReferenceKind::EntryPoint => continue,
            _ => continue,
        };
        if let Some(end) = reference.source.get().checked_add(width) {
            classified.push(Interval {
                start: reference.source.get(),
                end,
            });
        }
    }
    for relocation in &module.relocations {
        let width = match relocation.kind {
            RelocKind::Dir64 => 8,
            RelocKind::HighLow => 4,
            RelocKind::Absolute => continue,
        };
        if relocation.kind == RelocKind::HighLow {
            if let Some(owner) = ownership.owner(relocation.rva) {
                uncertain.insert(owner);
            }
        }
        let Some(end) = relocation.rva.get().checked_add(width) else {
            if let Some(owner) = ownership.owner(relocation.rva) {
                uncertain.insert(owner);
            }
            continue;
        };
        // Unsupported HIGHLOW fields cannot exclude overlapping full-width pointers.
        if relocation.kind == RelocKind::Dir64 {
            classified.push(Interval {
                start: relocation.rva.get(),
                end,
            });
        }
        let Some(bytes) = module
            .bytes_at(relocation.rva)
            .and_then(|bytes| bytes.get(..width as usize))
        else {
            if let Some(owner) = ownership.owner(relocation.rva) {
                uncertain.insert(owner);
            }
            continue;
        };
        let value = if width == 8 {
            u64::from_le_bytes(bytes.try_into().expect("validated relocation width"))
        } else {
            u64::from(u32::from_le_bytes(
                bytes.try_into().expect("validated relocation width"),
            ))
        };
        if let Some(target) = va_rva(module, value) {
            references.push(Reference {
                source: relocation.rva,
                target,
                kind: if relocation.kind == RelocKind::Dir64 {
                    ReferenceKind::Absolute
                } else {
                    ReferenceKind::Opaque
                },
            });
        }
    }
    if let Some(target) = module.entry_point {
        references.push(Reference {
            source: Rva::ZERO,
            target,
            kind: ReferenceKind::EntryPoint,
        });
    }

    for function in &module.functions {
        if ownership.uncertain.contains(&function.entry) {
            continue;
        }
        let mut image_base_materialized = false;
        let mut rva_immediates = Vec::new();
        for block in &function.blocks {
            if block.start.get() >= block.end.get() {
                continue;
            }
            let len = (block.end.get() - block.start.get()) as usize;
            let Some(bytes) = module
                .bytes_at(block.start)
                .and_then(|bytes| bytes.get(..len))
            else {
                continue;
            };
            let Some(ip) = module.image_base.checked_add(u64::from(block.start.get())) else {
                uncertain.insert(function.entry);
                continue;
            };
            let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
            let mut last = None;
            while decoder.can_decode() {
                let instruction = decoder.decode();
                if instruction.is_invalid() {
                    uncertain.insert(function.entry);
                    break;
                }
                let Some(source) = va_rva(module, instruction.ip()) else {
                    uncertain.insert(function.entry);
                    break;
                };
                let Some(end) = source.get().checked_add(instruction.len() as u32) else {
                    uncertain.insert(function.entry);
                    break;
                };
                if end > block.end.get() {
                    uncertain.insert(function.entry);
                    break;
                }
                instruction_starts.insert(source);
                classified.push(Interval {
                    start: source.get(),
                    end,
                });
                if (matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ) && near_target(module, &instruction).is_none())
                    || (instruction.is_ip_rel_memory_operand()
                        && static_memory_address(&instruction)
                            .is_some_and(|address| va_rva(module, address).is_none()))
                {
                    uncertain.insert(function.entry);
                }
                image_base_materialized |= collect_instruction(
                    module,
                    &instruction,
                    source,
                    None,
                    &mut references,
                    Some(&mut rva_immediates),
                );
                if instruction.flow_control() == FlowControl::Call {
                    if let Some(target) = near_target(module, &instruction) {
                        call_edges.insert((source, target));
                    }
                }
                if matches!(
                    instruction.flow_control(),
                    FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                ) {
                    if let Some(target) = near_target(module, &instruction) {
                        cfg_edges.insert((source, target));
                    }
                }
                last = Some((source, instruction));
                if end < block.end.get()
                    && matches!(
                        instruction.flow_control(),
                        FlowControl::Return
                            | FlowControl::ConditionalBranch
                            | FlowControl::UnconditionalBranch
                            | FlowControl::IndirectBranch
                            | FlowControl::Exception
                    )
                {
                    uncertain.insert(function.entry);
                    break;
                }
            }
            let Some((source, instruction)) = last else {
                uncertain.insert(function.entry);
                continue;
            };
            if Some(instruction.next_ip())
                != module.image_base.checked_add(u64::from(block.end.get()))
            {
                uncertain.insert(function.entry);
                continue;
            }
            if matches!(
                instruction.flow_control(),
                FlowControl::Next
                    | FlowControl::Call
                    | FlowControl::IndirectCall
                    | FlowControl::ConditionalBranch
                    | FlowControl::XbeginXabortXend
            ) && !matches!(block.terminator, Terminator::Return)
                && module.is_executable(block.end)
            {
                references.push(Reference {
                    source,
                    target: block.end,
                    kind: ReferenceKind::DirectBranch,
                });
                cfg_edges.insert((source, block.end));
            }
            match &block.terminator {
                Terminator::Switch { table } => {
                    for &target in &table.entries {
                        references.push(Reference {
                            source,
                            target,
                            kind: ReferenceKind::Switch,
                        });
                        cfg_edges.insert((source, target));
                        if ownership.owner(target) != Some(function.entry) {
                            uncertain.insert(function.entry);
                        }
                    }
                }
                Terminator::Unknown => {
                    uncertain.insert(function.entry);
                }
                Terminator::Fallthrough(target) if *target != block.end => {
                    uncertain.insert(function.entry);
                }
                _ => {}
            }
        }
        // Without cross-block register provenance, image-base use makes this
        // function's code-shaped immediates possible computed addresses.
        if image_base_materialized {
            references.append(&mut rva_immediates);
        }
    }

    classified.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Interval> = Vec::new();
    for range in classified {
        if let Some(last) = merged.last_mut() {
            if range.start <= last.end {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        merged.push(range);
    }
    scan_unclassified(module, &ownership, &merged, &mut references);
    for entry in uncertain {
        references.push(Reference {
            source: entry,
            target: entry,
            kind: ReferenceKind::Opaque,
        });
    }
    references.sort_by_key(reference_key);
    references.dedup();

    let mut model = ReferenceModel {
        references,
        functions: ownership
            .functions
            .keys()
            .map(|&entry| (entry, FunctionReferences::default()))
            .collect(),
    };
    for (index, &reference) in model.references.iter().enumerate() {
        let source_owner = (reference.kind != ReferenceKind::EntryPoint)
            .then(|| ownership.owner(reference.source))
            .flatten();
        let target_owner = ownership.owner(reference.target);
        if let Some(entry) = source_owner {
            let function = model.functions.get_mut(&entry).expect("known source owner");
            function.outgoing.push(index);
            if reference.kind == ReferenceKind::Opaque
                || (matches!(
                    reference.kind,
                    ReferenceKind::DirectBranch | ReferenceKind::Switch
                ) && (target_owner.is_none()
                    || !instruction_starts.contains(&reference.target)))
                || (reference.kind == ReferenceKind::RipRelative
                    && module.is_executable(reference.target)
                    && target_owner.is_none())
            {
                function.unresolved.push(reference);
            }
        }
        if let Some(entry) = target_owner {
            let function = model.functions.get_mut(&entry).expect("known target owner");
            function.incoming.push(index);
            let internal_cfg = source_owner == Some(entry)
                && matches!(
                    reference.kind,
                    ReferenceKind::DirectBranch | ReferenceKind::Switch
                )
                && cfg_edges.contains(&(reference.source, reference.target))
                && !call_edges.contains(&(reference.source, reference.target))
                && instruction_starts.contains(&reference.target);
            if reference.kind == ReferenceKind::Opaque
                || (reference.target != entry
                    && reference.kind != ReferenceKind::Unwind
                    && !internal_cfg)
            {
                function.unresolved.push(reference);
            }
        }
    }
    for (&entry, function) in &mut model.functions {
        function.unresolved.sort_by_key(reference_key);
        function.unresolved.dedup();
        if !function.unresolved.is_empty() {
            tracing::debug!(func = %entry, unresolved = function.unresolved.len(), "reference symbolization uncertain");
        }
    }
    Ok(model)
}

fn va_rva(module: &Module, address: u64) -> Option<Rva> {
    Some(Rva::new(
        u32::try_from(address.checked_sub(module.image_base)?).ok()?,
    ))
}

fn near_target(module: &Module, instruction: &Instruction) -> Option<Rva> {
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| va_rva(module, instruction.near_branch_target()))
    .flatten()
}

fn static_memory_address(instruction: &Instruction) -> Option<u64> {
    if !(0..instruction.op_count()).any(|operand| instruction.op_kind(operand) == OpKind::Memory)
        || (instruction.mnemonic() != Mnemonic::Lea
            && matches!(instruction.memory_segment(), Register::FS | Register::GS))
    {
        return None;
    }
    if instruction.is_ip_rel_memory_operand() {
        Some(instruction.ip_rel_memory_address())
    } else if instruction.memory_base() == Register::None
        && instruction.memory_index() == Register::None
        && instruction.memory_displ_size() != 0
    {
        Some(instruction.memory_displacement64())
    } else {
        None
    }
}

fn collect_instruction(
    module: &Module,
    instruction: &Instruction,
    source: Rva,
    ownership: Option<&Ownership>,
    references: &mut Vec<Reference>,
    mut rva_immediates: Option<&mut Vec<Reference>>,
) -> bool {
    let opaque = ownership.is_some();
    let accept_target = |target: &Rva| ownership.is_none_or(|owner| owner.owner(*target).is_some());
    if let Some(target) = near_target(module, instruction).filter(accept_target) {
        references.push(Reference {
            source,
            target,
            kind: if opaque {
                ReferenceKind::Opaque
            } else {
                ReferenceKind::DirectBranch
            },
        });
    }
    let memory_address = static_memory_address(instruction);
    let materializes_image_base = (instruction.mnemonic() == Mnemonic::Lea
        && instruction.op0_register().is_gpr64()
        && memory_address == Some(module.image_base))
        || (instruction.mnemonic() == Mnemonic::Mov
            && instruction.op1_kind() == OpKind::Immediate64
            && instruction.immediate64() == module.image_base);
    if let Some(target) = memory_address
        .and_then(|address| va_rva(module, address))
        .filter(accept_target)
    {
        let rip_relative = instruction.is_ip_rel_memory_operand();
        if rip_relative || module.is_executable(target) {
            references.push(Reference {
                source,
                target,
                kind: if opaque
                    || !rip_relative
                    || (instruction.mnemonic() != Mnemonic::Lea && module.is_executable(target))
                {
                    ReferenceKind::Opaque
                } else {
                    ReferenceKind::RipRelative
                },
            });
        }
    }
    for operand in 0..instruction.op_count() {
        let value = match instruction.op_kind(operand) {
            OpKind::Immediate8 => u64::from(instruction.immediate8()),
            OpKind::Immediate8_2nd => u64::from(instruction.immediate8_2nd()),
            OpKind::Immediate16 => u64::from(instruction.immediate16()),
            OpKind::Immediate8to16 => instruction.immediate8to16() as u64,
            OpKind::Immediate8to32 => instruction.immediate8to32() as u64,
            OpKind::Immediate8to64 => instruction.immediate8to64() as u64,
            OpKind::Immediate64 => instruction.immediate64(),
            OpKind::Immediate32 => u64::from(instruction.immediate32()),
            OpKind::Immediate32to64 => instruction.immediate32to64() as u64,
            _ => continue,
        };
        if let Some(candidates) = rva_immediates.as_mut() {
            if let Some(target) = u32::try_from(value)
                .ok()
                .map(Rva::new)
                .filter(|target| module.is_executable(*target))
                .filter(|_| module.image_base.checked_add(value).is_some())
            {
                candidates.push(Reference {
                    source,
                    target,
                    kind: ReferenceKind::Opaque,
                });
            }
        }
        if let Some(target) = va_rva(module, value)
            .filter(|target| module.is_executable(*target) && accept_target(target))
        {
            let relocated = module.relocations.iter().any(|relocation| {
                relocation.kind == RelocKind::Dir64
                    && relocation.rva.get() >= source.get()
                    && relocation
                        .rva
                        .get()
                        .checked_add(8)
                        .zip(source.get().checked_add(instruction.len() as u32))
                        .is_some_and(|(end, instruction_end)| end <= instruction_end)
                    && module
                        .bytes_at(relocation.rva)
                        .and_then(|bytes| bytes.get(..8))
                        .is_some_and(|bytes| {
                            u64::from_le_bytes(bytes.try_into().expect("validated pointer width"))
                                == value
                        })
            });
            if opaque || !relocated {
                references.push(Reference {
                    source,
                    target,
                    kind: ReferenceKind::Opaque,
                });
            }
        }
    }
    materializes_image_base
}

fn scan_unclassified(
    module: &Module,
    ownership: &Ownership,
    classified: &[Interval],
    references: &mut Vec<Reference>,
) {
    for section in &module.sections {
        let len = section.data.len().min(section.virtual_size as usize);
        let mut known_index = 0;
        for offset in 0..len {
            let Some(source) = u32::try_from(offset)
                .ok()
                .and_then(|offset| section.rva.get().checked_add(offset))
            else {
                break;
            };
            while known_index < classified.len() && classified[known_index].end <= source {
                known_index += 1;
            }
            let next_known = classified.get(known_index);
            if next_known.is_some_and(|range| range.contains(source)) {
                continue;
            }
            let available = next_known.map_or(len - offset, |range| {
                (len - offset).min(range.start.saturating_sub(source) as usize)
            });
            let bytes = &section.data[offset..offset + available];
            let source = Rva::new(source);
            for width in [4, 8] {
                let Some(field) = bytes.get(..width) else {
                    continue;
                };
                if field.iter().all(|&byte| byte == 0) {
                    continue;
                }
                let target = if width == 8 {
                    va_rva(
                        module,
                        u64::from_le_bytes(field.try_into().expect("validated pointer width")),
                    )
                } else {
                    Some(Rva::new(u32::from_le_bytes(
                        field.try_into().expect("validated RVA width"),
                    )))
                };
                if let Some(target) = target.filter(|&target| ownership.owner(target).is_some()) {
                    references.push(Reference {
                        source,
                        target,
                        kind: ReferenceKind::Opaque,
                    });
                }
            }
            if section.flags.execute && !matches!(bytes.first(), Some(0x90 | 0xcc)) {
                let Some(ip) = module.image_base.checked_add(u64::from(source.get())) else {
                    continue;
                };
                let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
                let instruction = decoder.decode();
                if !instruction.is_invalid() {
                    collect_instruction(
                        module,
                        &instruction,
                        source,
                        Some(ownership),
                        references,
                        None,
                    );
                }
            }
        }
    }
}

fn reference_key(reference: &Reference) -> (Rva, Rva, u8) {
    let kind = match reference.kind {
        ReferenceKind::DirectBranch => 0,
        ReferenceKind::RipRelative => 1,
        ReferenceKind::Absolute => 2,
        ReferenceKind::ImageRelative => 3,
        ReferenceKind::Switch => 4,
        ReferenceKind::Unwind => 5,
        ReferenceKind::EntryPoint => 6,
        ReferenceKind::Opaque => 7,
    };
    (reference.source, reference.target, kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::{
        BasicBlock, Function, Machine, Relocation, Section, SectionFlags, SwitchTable,
    };

    const BASE: u64 = 0x1_4000_0000;

    fn block(start: u32, end: u32, terminator: Terminator) -> BasicBlock {
        BasicBlock {
            start: Rva::new(start),
            end: Rva::new(end),
            successors: Vec::new(),
            terminator,
        }
    }

    fn function(start: u32, end: u32) -> Function {
        Function {
            entry: Rva::new(start),
            blocks: vec![block(start, end, Terminator::Return)],
        }
    }

    fn module(code: Vec<u8>, functions: Vec<Function>, data: Vec<u8>) -> Module {
        Module {
            image_base: BASE,
            machine: Machine::X64,
            entry_point: None,
            sections: vec![
                Section {
                    name: "code".into(),
                    rva: Rva::new(0x1000),
                    virtual_size: code.len() as u32,
                    data: code,
                    flags: SectionFlags {
                        read: true,
                        write: false,
                        execute: true,
                    },
                },
                Section {
                    name: "data".into(),
                    rva: Rva::new(0x2000),
                    virtual_size: data.len() as u32,
                    data,
                    flags: SectionFlags {
                        read: true,
                        write: false,
                        execute: false,
                    },
                },
            ],
            symbols: Vec::new(),
            relocations: Vec::new(),
            functions,
        }
    }

    fn reference(source: u32, target: u32, kind: ReferenceKind) -> Reference {
        Reference {
            source: Rva::new(source),
            target: Rva::new(target),
            kind,
        }
    }

    #[test]
    fn one_byte_function_is_resolved() {
        let module = module(vec![0xc3], vec![function(0x1000, 0x1001)], Vec::new());
        let model = build_reference_model(&module, &[]).unwrap();
        assert!(model.is_resolved(Rva::new(0x1000)));
        assert!(!model.is_resolved(Rva::new(0x1001)));
        assert!(model.functions[&Rva::new(0x1000)].incoming.is_empty());
        assert!(model.functions[&Rva::new(0x1000)].outgoing.is_empty());
    }

    #[test]
    fn call_rip_data_and_relocated_pointer_have_indexed_owners() {
        let mut code = vec![0xcc; 0x11];
        code[..13].copy_from_slice(&[
            0xe8, 0x0b, 0, 0, 0, 0x48, 0x8d, 0x05, 0xf4, 0x0f, 0, 0, 0xc3,
        ]);
        code[0x10] = 0xc3;
        let mut module = module(
            code,
            vec![function(0x1000, 0x100d), function(0x1010, 0x1011)],
            (BASE + 0x1010).to_le_bytes().to_vec(),
        );
        module.relocations.push(Relocation {
            rva: Rva::new(0x2000),
            kind: RelocKind::Dir64,
        });
        let model = build_reference_model(&module, &[]).unwrap();
        let caller = &model.functions[&Rva::new(0x1000)];
        let callee = &model.functions[&Rva::new(0x1010)];
        let outgoing: Vec<_> = caller
            .outgoing
            .iter()
            .map(|&index| model.references[index])
            .collect();
        assert_eq!(
            outgoing,
            vec![
                reference(0x1000, 0x1010, ReferenceKind::DirectBranch),
                reference(0x1005, 0x2000, ReferenceKind::RipRelative)
            ]
        );
        let incoming: Vec<_> = callee
            .incoming
            .iter()
            .map(|&index| model.references[index])
            .collect();
        assert_eq!(
            incoming,
            vec![
                reference(0x1000, 0x1010, ReferenceKind::DirectBranch),
                reference(0x2000, 0x1010, ReferenceKind::Absolute)
            ]
        );
        assert!(
            model
                .functions
                .values()
                .all(|function| function.unresolved.is_empty())
        );
    }

    #[test]
    fn known_directory_fields_do_not_become_unknown_pointers() {
        let module = module(
            vec![0xc3],
            vec![function(0x1000, 0x1001)],
            0x1000_u32.to_le_bytes().to_vec(),
        );
        let field = reference(0x2000, 0x1000, ReferenceKind::ImageRelative);
        let model = build_reference_model(&module, &[field, field]).unwrap();
        assert_eq!(model.references, vec![field]);
        assert!(model.is_resolved(Rva::new(0x1000)));
    }

    #[test]
    fn data_pointer_to_interior_is_not_an_entry_rewrite() {
        let mut module = module(
            vec![0x90, 0xc3],
            vec![function(0x1000, 0x1002)],
            (BASE + 0x1001).to_le_bytes().to_vec(),
        );
        module.relocations.push(Relocation {
            rva: Rva::new(0x2000),
            kind: RelocKind::Dir64,
        });
        let model = build_reference_model(&module, &[]).unwrap();
        assert_eq!(
            model.functions[&Rva::new(0x1000)].unresolved,
            vec![reference(0x2000, 0x1001, ReferenceKind::Absolute)]
        );
    }

    #[test]
    fn same_function_cfg_edges_are_safe_but_local_calls_are_not() {
        let cfg_function = Function {
            entry: Rva::new(0x1000),
            blocks: vec![
                block(0x1000, 0x1002, Terminator::Jump(Rva::new(0x1002))),
                block(0x1002, 0x1003, Terminator::Return),
            ],
        };
        let first = module(vec![0xeb, 0, 0xc3], vec![cfg_function], Vec::new());
        assert!(
            build_reference_model(&first, &[])
                .unwrap()
                .is_resolved(Rva::new(0x1000))
        );

        let module = module(
            vec![0xe8, 0, 0, 0, 0, 0xc3],
            vec![function(0x1000, 0x1006)],
            Vec::new(),
        );
        let model = build_reference_model(&module, &[]).unwrap();
        assert_eq!(
            model.functions[&Rva::new(0x1000)].unresolved,
            vec![reference(0x1000, 0x1005, ReferenceKind::DirectBranch)]
        );
    }

    #[test]
    fn resident_code_to_another_functions_interior_pins_only_the_target() {
        let mut code = vec![0xcc; 0x12];
        code[..5].copy_from_slice(&[0xe9, 0x0c, 0, 0, 0]);
        code[0x10..].copy_from_slice(&[0x90, 0xc3]);
        let mut caller = function(0x1000, 0x1005);
        caller.blocks[0].terminator = Terminator::Jump(Rva::new(0x1011));
        let module = module(code, vec![caller, function(0x1010, 0x1012)], Vec::new());
        let model = build_reference_model(&module, &[]).unwrap();
        assert!(model.is_resolved(Rva::new(0x1000)));
        assert_eq!(
            model.functions[&Rva::new(0x1010)].unresolved,
            vec![reference(0x1000, 0x1011, ReferenceKind::DirectBranch)]
        );
    }

    #[test]
    fn cross_function_fallthrough_has_incoming_and_outgoing_indices() {
        let mut first = function(0x1000, 0x1001);
        first.blocks[0].terminator = Terminator::Fallthrough(Rva::new(0x1001));
        let module = module(
            vec![0x90, 0xc3],
            vec![first, function(0x1001, 0x1002)],
            Vec::new(),
        );
        let model = build_reference_model(&module, &[]).unwrap();
        assert_eq!(
            model.references,
            vec![reference(0x1000, 0x1001, ReferenceKind::DirectBranch)]
        );
        assert_eq!(model.functions[&Rva::new(0x1000)].outgoing, vec![0]);
        assert_eq!(model.functions[&Rva::new(0x1001)].incoming, vec![0]);
    }

    #[test]
    fn recovered_switch_targets_are_cfg_edges_not_data_patch_fields() {
        let function = Function {
            entry: Rva::new(0x1000),
            blocks: vec![
                block(
                    0x1000,
                    0x1002,
                    Terminator::Switch {
                        table: SwitchTable {
                            index_reg: kamy_core::ir::Gpr::Rax,
                            dispatch_rva: Rva::new(0x1000),
                            entries: vec![Rva::new(0x1002), Rva::new(0x1002)],
                        },
                    },
                ),
                block(0x1002, 0x1003, Terminator::Return),
            ],
        };
        let module = module(vec![0xff, 0xe0, 0xc3], vec![function], Vec::new());
        let model = build_reference_model(&module, &[]).unwrap();
        assert_eq!(
            model.references,
            vec![reference(0x1000, 0x1002, ReferenceKind::Switch)]
        );
        assert!(model.is_resolved(Rva::new(0x1000)));
    }

    #[test]
    fn unowned_executable_call_is_uncertainty_only_for_its_target() {
        let mut code = vec![0xcc; 0x25];
        code[0] = 0xc3;
        code[0x10] = 0xc3;
        code[0x20..].copy_from_slice(&[0xe8, 0xeb, 0xff, 0xff, 0xff]);
        let module = module(
            code,
            vec![function(0x1000, 0x1001), function(0x1010, 0x1011)],
            Vec::new(),
        );
        let model = build_reference_model(&module, &[]).unwrap();
        assert!(model.is_resolved(Rva::new(0x1000)));
        assert_eq!(
            model.functions[&Rva::new(0x1010)].unresolved,
            vec![reference(0x1020, 0x1010, ReferenceKind::Opaque)]
        );
    }

    #[test]
    fn raw_pointers_and_opaque_metadata_pin_their_targets_deterministically() {
        let mut code = vec![0xcc; 0x11];
        code[0] = 0xc3;
        code[0x10] = 0xc3;
        let module = module(
            code,
            vec![function(0x1010, 0x1011), function(0x1000, 0x1001)],
            (BASE + 0x1010).to_le_bytes().to_vec(),
        );
        let opaque = reference(0x2000, 0x1010, ReferenceKind::Opaque);
        let model = build_reference_model(&module, &[]).unwrap();
        assert!(model.is_resolved(Rva::new(0x1000)));
        assert_eq!(model.functions[&Rva::new(0x1010)].unresolved, vec![opaque]);
        let known = build_reference_model(&module, &[opaque]).unwrap();
        assert!(!known.is_resolved(Rva::new(0x1010)));
    }

    #[test]
    fn malformed_decode_and_overlap_reject_only_affected_functions() {
        let mut code = vec![0xcc; 0x11];
        code[0] = 0xe8;
        code[0x10] = 0xc3;
        let first = module(
            code,
            vec![function(0x1000, 0x1001), function(0x1010, 0x1011)],
            Vec::new(),
        );
        let model = build_reference_model(&first, &[]).unwrap();
        assert!(!model.is_resolved(Rva::new(0x1000)));
        assert!(model.is_resolved(Rva::new(0x1010)));

        let module = module(
            vec![0x90, 0xc3],
            vec![function(0x1000, 0x1002), function(0x1001, 0x1002)],
            Vec::new(),
        );
        let model = build_reference_model(&module, &[]).unwrap();
        assert!(
            model
                .functions
                .values()
                .all(|function| !function.unresolved.is_empty())
        );
    }
    #[test]
    fn conditional_branch_and_fallthrough_keep_distinct_targets() {
        let function = Function {
            entry: Rva::new(0x1000),
            blocks: vec![
                block(
                    0x1000,
                    0x1002,
                    Terminator::Branch {
                        taken: Rva::new(0x1004),
                        not_taken: Rva::new(0x1002),
                    },
                ),
                block(0x1002, 0x1004, Terminator::Jump(Rva::new(0x1004))),
                block(0x1004, 0x1005, Terminator::Return),
            ],
        };
        let module = module(vec![0x74, 2, 0xeb, 0, 0xc3], vec![function], Vec::new());
        let model = build_reference_model(&module, &[]).unwrap();
        assert_eq!(
            model.references,
            vec![
                reference(0x1000, 0x1002, ReferenceKind::DirectBranch),
                reference(0x1000, 0x1004, ReferenceKind::DirectBranch),
                reference(0x1002, 0x1004, ReferenceKind::DirectBranch),
            ]
        );
        assert!(model.is_resolved(Rva::new(0x1000)));
    }

    #[test]
    fn absolute_immediates_need_confirmed_relocation_field_identity() {
        let mut code = vec![0xcc; 0x11];
        code[..2].copy_from_slice(&[0x48, 0xb8]);
        code[2..10].copy_from_slice(&(BASE + 0x1010).to_le_bytes());
        code[10] = 0xc3;
        code[0x10] = 0xc3;
        let mut module = module(
            code,
            vec![function(0x1000, 0x100b), function(0x1010, 0x1011)],
            Vec::new(),
        );
        let unknown = build_reference_model(&module, &[]).unwrap();
        assert_eq!(
            unknown.references,
            vec![reference(0x1000, 0x1010, ReferenceKind::Opaque)]
        );
        assert!(!unknown.is_resolved(Rva::new(0x1000)));
        assert!(!unknown.is_resolved(Rva::new(0x1010)));
        module.relocations.push(Relocation {
            rva: Rva::new(0x1002),
            kind: RelocKind::Dir64,
        });
        let known = build_reference_model(&module, &[]).unwrap();
        assert_eq!(
            known.references,
            vec![reference(0x1002, 0x1010, ReferenceKind::Absolute)]
        );
        assert!(
            known
                .functions
                .values()
                .all(|function| function.unresolved.is_empty())
        );
    }

    #[test]
    fn local_call_to_its_fallthrough_is_not_proven_cfg_only() {
        let function = Function {
            entry: Rva::new(0x1000),
            blocks: vec![
                block(0x1000, 0x1005, Terminator::Fallthrough(Rva::new(0x1005))),
                block(0x1005, 0x1006, Terminator::Return),
            ],
        };
        let module = module(vec![0xe8, 0, 0, 0, 0, 0xc3], vec![function], Vec::new());
        let model = build_reference_model(&module, &[]).unwrap();
        assert_eq!(
            model.functions[&Rva::new(0x1000)].unresolved,
            vec![reference(0x1000, 0x1005, ReferenceKind::DirectBranch)]
        );
    }
}
