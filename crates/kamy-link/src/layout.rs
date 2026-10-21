use std::collections::BTreeMap;

use anyhow::{Context, ensure};
use iced_x86::{Decoder, DecoderOptions};
use kamy_analysis::ReferenceModel;
use kamy_core::{Module, ReferenceKind, Rva, Section, SectionFlags};
use kamy_pe::{BytePatch, PeFile, SectionUpdate};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    fn new(start: u32, len: u32) -> anyhow::Result<Self> {
        Ok(Self {
            start,
            end: start.checked_add(len).context("image range overflow")?,
        })
    }

    pub(crate) fn contains(self, address: u32) -> bool {
        self.start <= address && address < self.end
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

pub(crate) struct ReadOnlyLayout {
    pub rva: u32,
    pub data: Vec<u8>,
}

impl ReadOnlyLayout {
    pub(crate) fn next_rva(&self, alignment: u32) -> anyhow::Result<u32> {
        let len = u32::try_from(self.data.len()).context("metadata size overflow")?;
        super::align_up(
            self.rva.checked_add(len).context("metadata RVA overflow")?,
            alignment,
        )
    }

    pub(crate) fn append(&mut self, alignment: u32, data: &[u8]) -> anyhow::Result<Rva> {
        let rva = self.next_rva(alignment)?;
        let offset = rva
            .checked_sub(self.rva)
            .context("invalid metadata layout")?;
        let len = u32::try_from(data.len()).context("metadata size overflow")?;
        rva.checked_add(len).context("metadata RVA overflow")?;
        self.data.resize(offset as usize, 0);
        self.data.extend_from_slice(data);
        Ok(Rva::new(rva))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct HelperSlot {
    pub index: usize,
    pub span: Span,
}

impl HelperSlot {
    pub(crate) fn reserve(&self, cursor: &mut u32, len: u32) -> anyhow::Result<Option<u32>> {
        let start = super::align_up(*cursor, super::FUNCTION_ALIGN)?;
        let end = start.checked_add(len).context("helper slot overflow")?;
        if end > self.span.end {
            return Ok(None);
        }
        *cursor = end;
        Ok(Some(start))
    }
}

fn merge_spans(ranges: &mut Vec<Span>) {
    ranges.sort_by_key(|range| range.start);
    let mut count = 0;
    for index in 0..ranges.len() {
        if count != 0 && ranges[count - 1].end >= ranges[index].start {
            ranges[count - 1].end = ranges[count - 1].end.max(ranges[index].end);
        } else {
            ranges[count] = ranges[index];
            count += 1;
        }
    }
    ranges.truncate(count);
}

fn field_is_retired(source: Span, retired: &[Span]) -> bool {
    let index = retired.partition_point(|range| range.start < source.end);
    index != 0 && retired[index - 1].end > source.start
}

pub(crate) fn regenerated_fields(pe: &PeFile, module: &Module) -> anyhow::Result<Vec<Span>> {
    let mut fields = Vec::new();
    if let Some((rva, size)) = pe.data_directory(PeFile::EXCEPTION_DIRECTORY) {
        if rva != Rva::ZERO && size != 0 {
            fields.push(Span::new(rva.get(), size)?);
        }
    }
    if let Some((rva, size)) = pe.data_directory(6) {
        ensure!(size % 28 == 0, "partial debug directory entry");
        for index in 0..size / 28 {
            let entry_rva = rva
                .get()
                .checked_add(index.checked_mul(28).context("debug index overflow")?)
                .context("debug entry overflow")?;
            let entry = module
                .bytes_at(Rva::new(entry_rva))
                .and_then(|bytes| bytes.get(..28))
                .context("debug directory is not materialized")?;
            let word = |offset| {
                u32::from_le_bytes(entry[offset..offset + 4].try_into().expect("debug field"))
            };
            if word(12) != 13 {
                continue;
            }
            let payload = word(20);
            let size = word(16);
            let bytes = module
                .bytes_at(Rva::new(payload))
                .and_then(|bytes| bytes.get(..size as usize))
                .context("POGO data is not materialized")?;
            let mut offset = 4usize;
            while offset < bytes.len() {
                let name = bytes.get(offset + 8..).context("truncated POGO entry")?;
                let len = name
                    .iter()
                    .position(|byte| *byte == 0)
                    .context("unterminated POGO name")?;
                fields.push(Span::new(
                    payload
                        .checked_add(u32::try_from(offset).context("POGO field overflow")?)
                        .context("POGO field overflow")?,
                    4,
                )?);
                offset = offset
                    .checked_add(8)
                    .and_then(|offset| offset.checked_add(len + 1))
                    .and_then(|offset| offset.checked_add(3))
                    .map(|offset| offset & !3)
                    .context("POGO entry overflow")?;
                ensure!(offset <= bytes.len(), "truncated POGO alignment");
            }
        }
    }
    merge_spans(&mut fields);
    Ok(fields)
}

fn raw_references(
    pe: &PeFile,
    module: &Module,
    ignored: &[Span],
    mut visit: impl FnMut(u32),
) -> anyhow::Result<()> {
    for (index, section) in pe.section_headers().iter().enumerate() {
        let data = pe
            .section_data(index)
            .context("section is not file-backed")?;
        for offset in 0..data.len() {
            let source = section
                .rva
                .checked_add(u32::try_from(offset).context("section offset overflow")?)
                .context("section RVA overflow")?;
            for width in [4usize, 8] {
                let Some(bytes) = data.get(offset..offset.saturating_add(width)) else {
                    continue;
                };
                if field_is_retired(Span::new(source, width as u32)?, ignored) {
                    continue;
                }
                let target = if width == 4 {
                    Some(u32::from_le_bytes(bytes.try_into().expect("RVA width")))
                } else {
                    u64::from_le_bytes(bytes.try_into().expect("VA width"))
                        .checked_sub(module.image_base)
                        .and_then(|target| u32::try_from(target).ok())
                };
                if let Some(target) = target.filter(|target| *target != 0) {
                    visit(target);
                }
            }
        }
    }
    Ok(())
}

fn instruction_references(
    instruction: &iced_x86::Instruction,
    base: u64,
    mut visit: impl FnMut(u32),
) {
    let mut address = |value: u64| {
        if let Some(rva) = value
            .checked_sub(base)
            .and_then(|value| u32::try_from(value).ok())
        {
            visit(rva);
        }
        if let Ok(rva) = u32::try_from(value) {
            visit(rva);
        }
    };
    if instruction.is_ip_rel_memory_operand() {
        address(instruction.ip_rel_memory_address());
    } else if instruction.memory_base() == iced_x86::Register::None
        && instruction.memory_index() == iced_x86::Register::None
        && instruction.memory_displ_size() != 0
    {
        address(instruction.memory_displacement64());
    }
    if matches!(
        instruction.op0_kind(),
        iced_x86::OpKind::NearBranch16
            | iced_x86::OpKind::NearBranch32
            | iced_x86::OpKind::NearBranch64
    ) {
        address(instruction.near_branch_target());
    }
    for operand in 0..instruction.op_count() {
        let value = match instruction.op_kind(operand) {
            iced_x86::OpKind::Immediate8 => u64::from(instruction.immediate8()),
            iced_x86::OpKind::Immediate8_2nd => u64::from(instruction.immediate8_2nd()),
            iced_x86::OpKind::Immediate16 => u64::from(instruction.immediate16()),
            iced_x86::OpKind::Immediate8to16 => instruction.immediate8to16() as u64,
            iced_x86::OpKind::Immediate8to32 => instruction.immediate8to32() as u64,
            iced_x86::OpKind::Immediate8to64 => instruction.immediate8to64() as u64,
            iced_x86::OpKind::Immediate32 => u64::from(instruction.immediate32()),
            iced_x86::OpKind::Immediate32to64 => instruction.immediate32to64() as u64,
            iced_x86::OpKind::Immediate64 => instruction.immediate64(),
            _ => continue,
        };
        if let Some(rva) = value
            .checked_sub(base)
            .and_then(|value| u32::try_from(value).ok())
        {
            visit(rva);
        }
        if let Ok(rva) = u32::try_from(value) {
            visit(rva);
        }
    }
}

pub(crate) fn retired_exception_slot(
    pe: &PeFile,
    module: &Module,
    model: &ReferenceModel,
    regenerated: &[Span],
) -> anyhow::Result<Option<HelperSlot>> {
    let Some((rva, size)) = pe.data_directory(PeFile::EXCEPTION_DIRECTORY) else {
        return Ok(None);
    };
    if rva == Rva::ZERO || size == 0 || size % 12 != 0 {
        return Ok(None);
    }
    let span = Span::new(rva.get(), size)?;
    let Some((index, header)) = pe
        .section_headers()
        .iter()
        .enumerate()
        .find(|(_, section)| section.rva == rva.get() && section.virtual_size == size)
    else {
        return Ok(None);
    };
    let raw = pe
        .section_data(index)
        .context("exception section is not file-backed")?;
    if raw.len() < size as usize
        || raw[size as usize..].iter().any(|byte| *byte != 0)
        || header.characteristics & 0xa000_0000 != 0
        || module
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .any(|block| {
                span.overlaps(Span {
                    start: block.start.get(),
                    end: block.end.get(),
                })
            })
        || module
            .symbols
            .iter()
            .any(|symbol| span.contains(symbol.rva.get()))
    {
        return Ok(None);
    }
    for index in 0..16 {
        if matches!(index, PeFile::EXCEPTION_DIRECTORY | 4) {
            continue;
        }
        if let Some((rva, len)) = pe.data_directory(index) {
            if rva != Rva::ZERO && len != 0 && span.overlaps(Span::new(rva.get(), len)?) {
                return Ok(None);
            }
        }
    }
    if model.references.iter().any(|reference| {
        span.contains(reference.target.get())
            && (reference.kind == ReferenceKind::Unwind
                || !field_is_retired(
                    Span {
                        start: reference.source.get(),
                        end: reference.source.get().saturating_add(1),
                    },
                    regenerated,
                ))
    }) {
        return Ok(None);
    }
    let mut owned: Vec<_> = module
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .map(|block| Span {
            start: block.start.get(),
            end: block.end.get(),
        })
        .collect();
    merge_spans(&mut owned);
    let mut ignored = regenerated.to_vec();
    ignored.extend_from_slice(&owned);
    merge_spans(&mut ignored);
    let mut referenced = false;
    raw_references(pe, module, &ignored, |target| {
        referenced |= span.contains(target);
    })?;
    for function in &module.functions {
        for instruction in kamy_disasm::function_instructions(module, function) {
            instruction_references(&instruction, module.image_base, |target| {
                referenced |= span.contains(target)
            });
        }
    }
    if referenced {
        return Ok(None);
    }
    // Unclassified instructions are not necessarily represented in the function graph.
    for section in module
        .sections
        .iter()
        .filter(|section| section.flags.execute)
    {
        for offset in 0..section.data.len() {
            let rva = section
                .rva
                .get()
                .checked_add(u32::try_from(offset).context("instruction offset overflow")?)
                .context("instruction RVA overflow")?;
            if in_ranges(&owned, rva) {
                continue;
            }
            let ip = module
                .image_base
                .checked_add(u64::from(rva))
                .context("instruction VA overflow")?;
            let instruction =
                Decoder::with_ip(64, &section.data[offset..], ip, DecoderOptions::NONE).decode();
            if instruction.is_invalid() || !instruction.is_ip_rel_memory_operand() {
                continue;
            }
            if instruction
                .ip_rel_memory_address()
                .checked_sub(module.image_base)
                .and_then(|target| u32::try_from(target).ok())
                .is_some_and(|target| span.contains(target))
            {
                return Ok(None);
            }
        }
    }
    Ok(Some(HelperSlot { index, span }))
}

fn in_ranges(ranges: &[Span], address: u32) -> bool {
    let index = ranges.partition_point(|range| range.start <= address);
    index != 0 && ranges[index - 1].contains(address)
}

fn retained_len(section: &Section, retired: &[Span], protected: &[Span]) -> anyhow::Result<u32> {
    let mut len = 0;
    for (offset, byte) in section.data.iter().enumerate() {
        let rva = section
            .rva
            .get()
            .checked_add(u32::try_from(offset).context("section size overflow")?)
            .context("section RVA overflow")?;
        if !in_ranges(retired, rva) && !matches!(byte, 0 | 0x90 | 0xcc) {
            len = u32::try_from(offset + 1).context("section size overflow")?;
        }
    }
    let extent = Span::new(section.rva.get(), section.virtual_size)?;
    for range in protected.iter().filter(|range| extent.overlaps(**range)) {
        len = len.max(range.end.min(extent.end) - extent.start);
    }
    if len == 0 {
        return Ok(0);
    }
    // An unowned zero suffix can belong to data or an instruction, not padding.
    let required = extent
        .start
        .checked_add(len)
        .context("retained code RVA overflow")?;
    let mut boundary = extent.end;
    for range in retired.iter().chain(protected) {
        if required <= range.start && extent.contains(range.start) {
            boundary = boundary.min(range.start);
        }
        if required <= range.end && range.end <= extent.end && range.end > extent.start {
            boundary = boundary.min(range.end);
        }
    }
    Ok(boundary - extent.start)
}

pub(crate) fn trim_executable_tails(
    pe: &PeFile,
    module: &Module,
    model: &ReferenceModel,
    addresses: &BTreeMap<Rva, Rva>,
    patches: &mut Vec<BytePatch>,
    scrubs: &mut Vec<BytePatch>,
    regenerated: &[Span],
) -> anyhow::Result<Vec<SectionUpdate>> {
    let mut retired = Vec::new();
    let mut protected = Vec::new();
    for function in &module.functions {
        let ranges = if addresses.contains_key(&function.entry) {
            &mut retired
        } else {
            &mut protected
        };
        for block in &function.blocks {
            ranges.push(Span {
                start: block.start.get(),
                end: block.end.get(),
            });
        }
    }
    let mut owned = retired.clone();
    owned.extend_from_slice(&protected);
    merge_spans(&mut owned);
    merge_spans(&mut retired);
    if let Some((rva, size)) = pe.data_directory(PeFile::EXCEPTION_DIRECTORY) {
        if rva != Rva::ZERO && size != 0 {
            let (index, header) = pe
                .section_headers()
                .iter()
                .enumerate()
                .find(|(_, header)| {
                    rva.get() >= header.rva && rva.get() - header.rva < header.raw_size
                })
                .context("exception directory is not file-backed")?;
            let offset = (rva.get() - header.rva) as usize;
            let bytes = pe
                .section_data(index)
                .and_then(|bytes| bytes.get(offset..offset.checked_add(size as usize)?))
                .context("exception directory exceeds section bounds")?;
            for entry in bytes.chunks_exact(12) {
                let word = |offset| {
                    u32::from_le_bytes(entry[offset..offset + 4].try_into().expect("runtime field"))
                };
                let begin = word(0);
                if addresses.contains_key(&Rva::new(begin)) {
                    continue;
                }
                protected.push(Span {
                    start: begin,
                    end: word(4),
                });
                let unwind = word(8);
                if let Some(section) = module
                    .section_at(Rva::new(unwind))
                    .filter(|section| section.flags.execute)
                {
                    protected.push(Span::new(
                        unwind,
                        section.virtual_size - (unwind - section.rva.get()),
                    )?);
                }
            }
        }
    }
    for patch in patches.iter() {
        protected.push(Span::new(
            patch.rva.get(),
            u32::try_from(patch.bytes.len()).context("patch size overflow")?,
        )?);
    }
    for relocation in &module.relocations {
        if relocation.kind != kamy_core::RelocKind::Absolute {
            protected.push(Span::new(relocation.rva.get(), 8)?);
        }
    }
    for index in 0..16 {
        if matches!(index, PeFile::EXCEPTION_DIRECTORY | 4) {
            continue;
        }
        if let Some((rva, size)) = pe.data_directory(index) {
            if rva != Rva::ZERO && size != 0 {
                protected.push(Span::new(rva.get(), size)?);
            }
        }
    }
    let mut ignored = regenerated.to_vec();
    ignored.extend_from_slice(&owned);
    for patch in patches.iter() {
        ignored.push(Span::new(
            patch.rva.get(),
            u32::try_from(patch.bytes.len()).context("patch size overflow")?,
        )?);
    }
    merge_spans(&mut ignored);
    raw_references(pe, module, &ignored, |target| {
        if in_ranges(&retired, target) {
            return;
        }
        let Some(section) = module
            .section_at(Rva::new(target))
            .filter(|section| section.flags.execute)
        else {
            return;
        };
        let end = if in_ranges(&owned, target) {
            target.saturating_add(1)
        } else {
            section.rva.get().saturating_add(section.virtual_size)
        };
        protected.push(Span { start: target, end });
    })?;
    for reference in &model.references {
        if in_ranges(&retired, reference.source.get())
            || field_is_retired(Span::new(reference.source.get(), 1)?, regenerated)
        {
            continue;
        }
        if !in_ranges(&retired, reference.target.get()) {
            protected.push(Span::new(reference.target.get(), 1)?);
        }
    }
    let mut protect_instruction = |instruction: &iced_x86::Instruction| -> anyhow::Result<()> {
        instruction_references(instruction, module.image_base, |target| {
            if in_ranges(&retired, target) {
                return;
            }
            if let Some(section) = module
                .section_at(Rva::new(target))
                .filter(|section| section.flags.execute)
            {
                let end = if in_ranges(&owned, target) {
                    target.saturating_add(1)
                } else {
                    section.rva.get().saturating_add(section.virtual_size)
                };
                protected.push(Span { start: target, end });
            }
        });
        if instruction.is_ip_rel_memory_operand()
            && instruction.mnemonic() != iced_x86::Mnemonic::Lea
        {
            if let Some(target) = instruction
                .ip_rel_memory_address()
                .checked_sub(module.image_base)
                .and_then(|target| u32::try_from(target).ok())
                .filter(|target| !in_ranges(&retired, *target))
            {
                protected.push(Span::new(
                    target,
                    u32::try_from(instruction.memory_size().size().max(1))
                        .context("memory size overflow")?,
                )?);
            }
        }
        Ok(())
    };
    for function in &module.functions {
        for instruction in kamy_disasm::function_instructions(module, function) {
            protect_instruction(&instruction)?;
        }
    }
    for section in module
        .sections
        .iter()
        .filter(|section| section.flags.execute)
    {
        for offset in 0..section.data.len() {
            let rva = section
                .rva
                .get()
                .checked_add(u32::try_from(offset).context("instruction offset overflow")?)
                .context("instruction RVA overflow")?;
            if in_ranges(&owned, rva) {
                continue;
            }
            let ip = module
                .image_base
                .checked_add(u64::from(rva))
                .context("instruction VA overflow")?;
            let instruction =
                Decoder::with_ip(64, &section.data[offset..], ip, DecoderOptions::NONE).decode();
            if !instruction.is_invalid() {
                protect_instruction(&instruction)?;
            }
        }
    }
    let mut updates = Vec::new();
    for (index, section) in module.sections.iter().enumerate() {
        if !section.flags.execute
            || !retired
                .iter()
                .any(|range| section.contains(Rva::new(range.start)))
        {
            continue;
        }
        let raw = pe
            .section_data(index)
            .context("code section is not file-backed")?;
        if raw
            .get(section.virtual_size as usize..)
            .is_some_and(|tail| tail.iter().any(|byte| !matches!(byte, 0 | 0x90 | 0xcc)))
        {
            continue;
        }
        let len = retained_len(section, &retired, &protected)?;
        if len >= section.virtual_size {
            continue;
        }
        // Resident RVAs require adjacent mapped sections, even after raw tail removal.
        // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
        let alignment = pe.section_alignment();
        let extent = section
            .virtual_size
            .max(u32::try_from(raw.len()).context("code section size overflow")?);
        let mapped_floor = super::align_up(extent, alignment)?
            .checked_sub(alignment)
            .and_then(|last_page| last_page.checked_add(1))
            .context("invalid mapped code extent")?;
        let end = section
            .rva
            .get()
            .checked_add(len)
            .context("trimmed code RVA overflow")?;
        ensure!(
            patches.iter().all(|patch| {
                !section.contains(patch.rva)
                    || patch
                        .rva
                        .get()
                        .checked_add(patch.bytes.len() as u32)
                        .is_some_and(|patch_end| patch_end <= end)
            }),
            "truncation would discard a reference patch"
        );
        let mut data = section.data[..section.data.len().min(len as usize)].to_vec();
        for patch in patches.iter().chain(scrubs.iter()) {
            if !section.contains(patch.rva) {
                continue;
            }
            let start = patch.rva.get() - section.rva.get();
            if start >= len {
                continue;
            }
            let count = patch.bytes.len().min((len - start) as usize);
            let destination = data
                .get_mut(start as usize..start as usize + count)
                .context("patch outside retained code")?;
            destination.copy_from_slice(&patch.bytes[..count]);
        }
        patches.retain(|patch| !section.contains(patch.rva));
        scrubs.retain(|patch| !section.contains(patch.rva));
        updates.push(SectionUpdate {
            index,
            name: None,
            flags: None,
            data: Some(data),
            virtual_size: Some(len.max(mapped_floor)),
        });
    }
    Ok(updates)
}

pub(crate) fn helper_update(slot: HelperSlot, blank: bool, data: Vec<u8>) -> SectionUpdate {
    SectionUpdate {
        index: slot.index,
        name: Some(if blank { "" } else { ".text" }.into()),
        flags: Some(SectionFlags {
            read: true,
            write: false,
            execute: true,
        }),
        data: Some(data),
        virtual_size: Some(slot.span.end - slot.span.start),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_alignment_and_directory_rvas_share_one_home() {
        let mut layout = ReadOnlyLayout {
            rva: 0x5000,
            data: vec![1; 3],
        };
        assert_eq!(layout.next_rva(8).unwrap(), 0x5008);
        assert_eq!(layout.append(8, &[2; 5]).unwrap(), Rva::new(0x5008));
        assert_eq!(&layout.data[3..8], &[0; 5]);
        assert_eq!(layout.append(4, &[3; 4]).unwrap(), Rva::new(0x5010));
        assert_eq!(layout.data.len(), 20);
    }

    #[test]
    fn metadata_bounds_reject_rva_overflow() {
        let mut layout = ReadOnlyLayout {
            rva: u32::MAX - 7,
            data: vec![0; 7],
        };
        assert!(layout.next_rva(8).is_err());
        assert!(layout.append(1, &[1]).is_err());
    }

    #[test]
    fn helpers_use_real_capacity_without_crossing_the_slot() {
        let slot = HelperSlot {
            index: 2,
            span: Span {
                start: 0x2000,
                end: 0x2048,
            },
        };
        let mut cursor = slot.span.start;
        assert_eq!(slot.reserve(&mut cursor, 63).unwrap(), Some(0x2000));
        assert_eq!(slot.reserve(&mut cursor, 5).unwrap(), Some(0x2040));
        assert_eq!(slot.reserve(&mut cursor, 5).unwrap(), None);
        assert_eq!(cursor, 0x2045);
    }

    #[test]
    fn tail_reclamation_keeps_survivors_data_and_referenced_padding() {
        let section = Section {
            name: ".text".into(),
            rva: Rva::new(0x1000),
            virtual_size: 16,
            data: vec![
                0xc3, 0x90, 0x90, 0x90, 0x41, 0, 0, 0, 0xc3, 0x90, 0x90, 0x90, 0xcc, 0xcc, 0, 0,
            ],
            flags: SectionFlags {
                read: true,
                write: false,
                execute: true,
            },
        };
        let retired = [Span {
            start: 0x1008,
            end: 0x100c,
        }];
        assert_eq!(
            retained_len(
                &section,
                &retired,
                &[Span {
                    start: 0x1000,
                    end: 0x1004
                }]
            )
            .unwrap(),
            8
        );
        assert_eq!(
            retained_len(
                &section,
                &retired,
                &[Span {
                    start: 0x1000,
                    end: 0x100e
                }]
            )
            .unwrap(),
            14
        );
        assert_eq!(section.rva, Rva::new(0x1000));
        let mut section = section;
        section.data[12..16].copy_from_slice(&[0x41, 0, 0, 0]);
        assert_eq!(retained_len(&section, &retired, &[]).unwrap(), 16);
    }

    fn image_bytes() -> Vec<u8> {
        let mut bytes = vec![0; 0x800];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&3u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes());
        bytes[0xb8..0xbc].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0xbc..0xc0].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0xd0..0xd4].copy_from_slice(&0x4000u32.to_le_bytes());
        bytes[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
        bytes[0x120..0x124].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[0x124..0x128].copy_from_slice(&84u32.to_le_bytes());
        for (index, name, rva, size, raw, flags) in [
            (0, ".text", 0x1000u32, 32u32, 0x200u32, 0x60000020u32),
            (1, ".odd", 0x2000, 84, 0x400, 0x42000040),
            (2, ".rdata", 0x3000, 32, 0x600, 0x40000040),
        ] {
            let header = 0x188 + index * 40;
            bytes[header..header + name.len()].copy_from_slice(name.as_bytes());
            for (offset, value) in [(8, size), (12, rva), (16, 0x200), (20, raw), (36, flags)] {
                bytes[header + offset..header + offset + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        for index in 0..7usize {
            let begin = 0x1000 + index as u32 * 2;
            bytes[0x200 + index * 2] = 0xc3;
            for (offset, value) in [(0, begin), (4, begin + 1), (8, 0x3000)] {
                let field = 0x400 + index * 12 + offset;
                bytes[field..field + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes[0x600] = 1;
        bytes
    }

    fn candidate(bytes: &[u8]) -> Option<HelperSlot> {
        let pe = PeFile::parse(bytes).unwrap();
        let module = pe.to_module();
        let model = ReferenceModel {
            references: pe.metadata_references().unwrap(),
            ..Default::default()
        };
        let regenerated = regenerated_fields(&pe, &module).unwrap();
        retired_exception_slot(&pe, &module, &model, &regenerated).unwrap()
    }

    #[test]
    fn exception_retirement_requires_coverage_and_unreferenced_padding_not_a_name() {
        let original = image_bytes();
        let slot = candidate(&original).unwrap();
        assert_eq!(slot.index, 1);
        assert_eq!(
            slot.span,
            Span {
                start: 0x2000,
                end: 0x2054
            }
        );

        let mut bytes = original.clone();
        bytes[0x124..0x128].copy_from_slice(&72u32.to_le_bytes());
        assert!(candidate(&bytes).is_none());
        let mut bytes = original.clone();
        bytes[0x454] = 1;
        assert!(candidate(&bytes).is_none());
        let mut bytes = original.clone();
        bytes[0x608..0x60c].copy_from_slice(&0x2008u32.to_le_bytes());
        assert!(candidate(&bytes).is_none());
        let mut bytes = original.clone();
        bytes[0x680..0x684].copy_from_slice(&0x2008u32.to_le_bytes());
        assert!(candidate(&bytes).is_none());
        let mut bytes = original.clone();
        bytes[0x608..0x610].copy_from_slice(&0x140002008u64.to_le_bytes());
        assert!(candidate(&bytes).is_none());
        let mut bytes = original.clone();
        bytes[0x200..0x207].copy_from_slice(&[0x48, 0x8d, 0x05, 0xf9, 0x0f, 0, 0]);
        assert!(candidate(&bytes).is_none());
        let mut bytes = original;
        bytes[0x118..0x11c].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[0x11c..0x120].copy_from_slice(&4u32.to_le_bytes());
        assert!(candidate(&bytes).is_none());
    }

    #[test]
    fn recycled_slot_keeps_ordinal_and_rva_with_live_unwind_described_code() {
        let bytes = image_bytes();
        let pe = PeFile::parse(&bytes).unwrap();
        let slot = candidate(&bytes).unwrap();
        let body =
            crate::translation::helper(iced_x86::Register::RAX, slot.span.start, 0x4000).unwrap();
        let ranges = kamy_seh::unwind_ranges(&body, 0x140002000).unwrap();
        let mut metadata = crate::translation::table(&BTreeMap::new()).unwrap();
        let mut entries: Vec<_> = pe
            .runtime_functions()
            .iter()
            .map(|entry| (entry.begin.get(), entry.end.get(), entry.unwind.get()))
            .collect();
        crate::append_unwind(
            &mut metadata,
            &mut entries,
            0x4000,
            slot.span.start,
            body.len() as u32,
            &ranges,
        )
        .unwrap();
        let pdata = crate::encode_pdata(&mut entries).unwrap();
        let mut code = body.clone();
        crate::append_nops(&mut code, 84 - body.len());
        let output = pe
            .rebuild(&kamy_pe::PeEdits {
                section_updates: vec![helper_update(slot, false, code)],
                new_sections: vec![
                    crate::section(".kamy".into(), 0x4000, false, metadata),
                    crate::section(".pdata".into(), 0x5000, false, pdata.clone()),
                ],
                directories: vec![kamy_pe::DirectoryUpdate {
                    index: PeFile::EXCEPTION_DIRECTORY,
                    rva: Rva::new(0x5000),
                    size: pdata.len() as u32,
                }],
                ..Default::default()
            })
            .unwrap();
        let rebuilt = PeFile::parse(&output).unwrap();
        let module = rebuilt.to_module();
        assert_eq!(rebuilt.section_headers()[1].rva, 0x2000);
        assert_eq!(module.sections[1].name, ".text");
        assert!(module.sections[1].flags.execute);
        assert_eq!(
            rebuilt.section_headers()[1].characteristics & 0x0200_0000,
            0
        );
        assert_eq!(&module.sections[1].data[..body.len()], body);
        assert!(
            rebuilt
                .runtime_functions()
                .iter()
                .any(|entry| entry.begin == Rva::new(0x2000))
        );
        assert_eq!(
            rebuilt.data_directory(PeFile::EXCEPTION_DIRECTORY),
            Some((Rva::new(0x5000), pdata.len() as u32))
        );
        assert_eq!(module.entry_point, Some(Rva::new(0x1000)));
    }

    #[test]
    fn tail_replacement_preserves_real_patches_and_resident_addresses() {
        let pe = PeFile::parse(&image_bytes()).unwrap();
        let mut module = pe.to_module();
        module.functions = (0..7)
            .map(|index| {
                let entry = Rva::new(0x1000 + index * 2);
                kamy_core::Function {
                    entry,
                    blocks: vec![kamy_core::BasicBlock {
                        start: entry,
                        end: Rva::new(entry.get() + 1),
                        successors: vec![],
                        terminator: kamy_core::Terminator::Return,
                    }],
                }
            })
            .collect();
        let addresses = module.functions[1..]
            .iter()
            .map(|function| (function.entry, Rva::new(0x4000 + function.entry.get())))
            .collect();
        let mut patches = vec![BytePatch {
            rva: Rva::new(0x100f),
            bytes: vec![0x90],
        }];
        let mut scrubs: Vec<_> = module.functions[1..]
            .iter()
            .map(|function| BytePatch {
                rva: function.entry,
                bytes: vec![0x90],
            })
            .collect();
        let model = ReferenceModel {
            references: pe.metadata_references().unwrap(),
            ..Default::default()
        };
        let regenerated = regenerated_fields(&pe, &module).unwrap();
        let updates = trim_executable_tails(
            &pe,
            &module,
            &model,
            &addresses,
            &mut patches,
            &mut scrubs,
            &regenerated,
        )
        .unwrap();
        let update = updates.iter().find(|update| update.index == 0).unwrap();
        assert_eq!(update.virtual_size, Some(16));
        let data = update.data.as_ref().unwrap();
        assert_eq!(data[0], 0xc3);
        assert_eq!(data[15], 0x90);
        assert!(patches.is_empty());
        assert!(scrubs.is_empty());
        assert_eq!(module.functions[0].entry, Rva::new(0x1000));
        assert_eq!(pe.section_headers()[0].rva, 0x1000);
        let mut patches = Vec::new();
        let mut scrubs = module.functions[1..]
            .iter()
            .map(|function| BytePatch {
                rva: function.entry,
                bytes: vec![0x90],
            })
            .collect();
        let updates = trim_executable_tails(
            &pe,
            &module,
            &model,
            &addresses,
            &mut patches,
            &mut scrubs,
            &regenerated,
        )
        .unwrap();
        let update = updates.iter().find(|update| update.index == 0).unwrap();
        assert_eq!(update.virtual_size, Some(1));
        assert_eq!(update.data.as_deref(), Some(&[0xc3][..]));
        assert!(scrubs.is_empty());
    }

    #[test]
    fn fully_retired_code_preserves_mapped_coverage_without_raw_bytes() {
        let mut bytes = image_bytes();
        for (offset, value) in [
            (0x188 + 8, 0x2010u32),
            (0x188 + 40 + 12, 0x4000),
            (0x188 + 80 + 12, 0x5000),
            (0x120, 0x4000),
            (0xd0, 0x6000),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for index in 0..7 {
            let offset = 0x400 + index * 12 + 8;
            bytes[offset..offset + 4].copy_from_slice(&0x5000u32.to_le_bytes());
        }
        bytes[0x200..0x400].fill(0x90);
        for index in 0..7 {
            bytes[0x200 + index * 2] = 0xc3;
        }
        let pe = PeFile::parse(&bytes).unwrap();
        let mut module = pe.to_module();
        module.functions = (0..7)
            .map(|index| {
                let entry = Rva::new(0x1000 + index * 2);
                kamy_core::Function {
                    entry,
                    blocks: vec![kamy_core::BasicBlock {
                        start: entry,
                        end: Rva::new(entry.get() + 1),
                        successors: vec![],
                        terminator: kamy_core::Terminator::Return,
                    }],
                }
            })
            .collect();
        let addresses = module
            .functions
            .iter()
            .map(|function| (function.entry, Rva::new(0x8000 + function.entry.get())))
            .collect();
        let model = ReferenceModel::default();
        let regenerated = regenerated_fields(&pe, &module).unwrap();
        let updates = trim_executable_tails(
            &pe,
            &module,
            &model,
            &addresses,
            &mut Vec::new(),
            &mut Vec::new(),
            &regenerated,
        )
        .unwrap();
        let update = updates.iter().find(|update| update.index == 0).unwrap();
        assert_eq!(update.virtual_size, Some(0x2001));
        assert_eq!(update.data.as_deref(), Some(&[][..]));
    }
}
