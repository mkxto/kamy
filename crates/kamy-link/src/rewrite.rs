use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl};
use kamy_analysis::ReferenceModel;
use kamy_core::{Module, ReferenceKind, Rva};
use kamy_pe::BytePatch;

pub(crate) fn resident_patches(
    module: &Module,
    model: &ReferenceModel,
    addresses: &BTreeMap<Rva, Rva>,
) -> (Vec<BytePatch>, BTreeSet<Rva>) {
    let mut patches = BTreeMap::<Rva, Vec<u8>>::new();
    let mut pinned = BTreeSet::new();
    let mut moved_blocks: Vec<_> = module
        .functions
        .iter()
        .filter(|function| addresses.contains_key(&function.entry))
        .flat_map(|function| function.blocks.iter().map(|block| (block.start, block.end)))
        .collect();
    moved_blocks.sort_unstable();
    for (&entry, &target) in addresses {
        let Some(references) = model.functions.get(&entry) else {
            pinned.insert(entry);
            continue;
        };
        for &index in &references.incoming {
            let reference = model.references[index];
            if matches!(
                reference.kind,
                ReferenceKind::EntryPoint | ReferenceKind::Unwind
            ) {
                continue;
            }
            let index = moved_blocks.partition_point(|&(start, _)| start <= reference.source);
            let source_moves = index != 0 && reference.source < moved_blocks[index - 1].1;
            if source_moves {
                continue;
            }
            let patch = match reference.kind {
                ReferenceKind::DirectBranch | ReferenceKind::RipRelative => operand_patch(
                    module,
                    reference.source,
                    reference.target,
                    target,
                    reference.kind,
                ),
                ReferenceKind::Absolute | ReferenceKind::ImageRelative => continue,
                _ => None,
            };
            match patch {
                Some(patch) => {
                    if let Some(previous) = patches.get(&patch.rva) {
                        if previous != &patch.bytes {
                            pinned.insert(entry);
                        }
                    } else {
                        patches.insert(patch.rva, patch.bytes);
                    }
                }
                None => {
                    pinned.insert(entry);
                }
            }
        }
    }
    (
        patches
            .into_iter()
            .map(|(rva, bytes)| BytePatch { rva, bytes })
            .collect(),
        pinned,
    )
}

fn operand_patch(
    module: &Module,
    source: Rva,
    original: Rva,
    target: Rva,
    kind: ReferenceKind,
) -> Option<BytePatch> {
    let bytes = module.bytes_at(source)?;
    let ip = module.image_base.checked_add(u64::from(source.get()))?;
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return None;
    }
    let original_va = module.image_base.checked_add(u64::from(original.get()))?;
    let target_va = module.image_base.checked_add(u64::from(target.get()))?;
    let offsets = decoder.get_constant_offsets(&instruction);
    let (offset, width) = match kind {
        ReferenceKind::DirectBranch => {
            // A fallthrough has no encoded field to retarget in place.
            if instruction.next_ip() == original_va
                && matches!(
                    instruction.flow_control(),
                    FlowControl::Next
                        | FlowControl::Call
                        | FlowControl::IndirectCall
                        | FlowControl::ConditionalBranch
                        | FlowControl::XbeginXabortXend
                )
            {
                return None;
            }
            if !matches!(
                instruction.op0_kind(),
                iced_x86::OpKind::NearBranch16
                    | iced_x86::OpKind::NearBranch32
                    | iced_x86::OpKind::NearBranch64
            ) || instruction.near_branch_target() != original_va
            {
                return None;
            }
            (offsets.immediate_offset(), offsets.immediate_size())
        }
        ReferenceKind::RipRelative => {
            if !instruction.is_ip_rel_memory_operand()
                || instruction.ip_rel_memory_address() != original_va
            {
                return None;
            }
            (offsets.displacement_offset(), offsets.displacement_size())
        }
        _ => return None,
    };
    let displacement = i128::from(target_va) - i128::from(instruction.next_ip());
    let bytes = match width {
        1 => i8::try_from(displacement).ok()?.to_le_bytes().to_vec(),
        2 => i16::try_from(displacement).ok()?.to_le_bytes().to_vec(),
        4 => i32::try_from(displacement).ok()?.to_le_bytes().to_vec(),
        _ => return None,
    };
    if offset.checked_add(width)? > instruction.len() {
        return None;
    }
    Some(BytePatch {
        rva: Rva::new(source.get().checked_add(u32::try_from(offset).ok()?)?),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::{Machine, Section, SectionFlags};

    fn image(bytes: Vec<u8>) -> Module {
        Module {
            image_base: 0x140000000,
            machine: Machine::X64,
            entry_point: None,
            sections: vec![Section {
                name: ".text".into(),
                rva: Rva::new(0x1000),
                virtual_size: bytes.len() as u32,
                data: bytes,
                flags: SectionFlags {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            symbols: vec![],
            relocations: vec![],
            functions: vec![],
        }
    }

    #[test]
    fn resident_call_patches_only_rel32() {
        let module = image(vec![0xe8, 0xfb, 0x0f, 0, 0, 0xc3]);
        let patch = operand_patch(
            &module,
            Rva::new(0x1000),
            Rva::new(0x2000),
            Rva::new(0x5000),
            ReferenceKind::DirectBranch,
        )
        .unwrap();
        assert_eq!(patch.rva, Rva::new(0x1001));
        assert_eq!(patch.bytes, 0x3ffbi32.to_le_bytes());
        assert_eq!(module.sections[0].data[5], 0xc3);
    }

    #[test]
    fn unpatchable_rel8_stays_resident() {
        let module = image(vec![0xeb, 0x7e, 0xc3]);
        assert!(
            operand_patch(
                &module,
                Rva::new(0x1000),
                Rva::new(0x1080),
                Rva::new(0x5000),
                ReferenceKind::DirectBranch
            )
            .is_none()
        );
    }

    #[test]
    fn implicit_fallthrough_has_no_patch() {
        let module = image(vec![0x90, 0xc3]);
        assert!(
            operand_patch(
                &module,
                Rva::new(0x1000),
                Rva::new(0x1001),
                Rva::new(0x5000),
                ReferenceKind::DirectBranch
            )
            .is_none()
        );
    }
}
