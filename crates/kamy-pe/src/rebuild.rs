use anyhow::{Context, ensure};
use kamy_core::{Rva, SectionFlags};

use crate::{
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PeFile, read_u16, read_u32,
};

const IMAGE_SCN_CNT_CODE: u32 = 0x20;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x40;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x80;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const SECTION_HEADER_SIZE: usize = 40;
const MAX_SECTIONS: usize = 96;

pub struct NewSection {
    pub name: String,
    pub rva: Rva,
    pub flags: SectionFlags,
    pub data: Vec<u8>,
}

/// Edits an original header slot without changing its RVA or ordinal.
/// Replacement bytes own the whole raw section and cannot overlap byte patches.
#[derive(Default)]
pub struct SectionUpdate {
    pub index: usize,
    pub name: Option<String>,
    pub flags: Option<SectionFlags>,
    /// Replacement bytes; absent virtual_size defaults to their unaligned length.
    pub data: Option<Vec<u8>>,
    /// A size-only shrink retains the original prefix and removes its raw tail.
    pub virtual_size: Option<u32>,
}

pub struct BytePatch {
    pub rva: Rva,
    pub bytes: Vec<u8>,
}

pub struct DirectoryUpdate {
    pub index: usize,
    pub rva: Rva,
    pub size: u32,
}

#[derive(Default)]
pub struct PeEdits {
    pub section_updates: Vec<SectionUpdate>,
    pub new_sections: Vec<NewSection>,
    pub patches: Vec<BytePatch>,
    pub directories: Vec<DirectoryUpdate>,
    pub entry_point: Option<Rva>,
    pub clear_guard_cf: bool,
}

struct HeaderLayout {
    coff: usize,
    opt: usize,
    section_table: usize,
    num_sections: usize,
    size_of_headers: u32,
    file_alignment: u32,
    section_alignment: u32,
    num_dirs: usize,
}

#[derive(Default)]
struct SectionChange<'a> {
    name: Option<&'a String>,
    flags: Option<&'a SectionFlags>,
    data: Option<&'a Vec<u8>>,
    virtual_size: Option<&'a u32>,
}

struct OutputSection<'a> {
    header: [u8; SECTION_HEADER_SIZE],
    rva: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
    data: &'a [u8],
    replaced: bool,
}

struct FileMapping {
    old: u32,
    length: u32,
    new: u32,
}

struct CopySpan<'a> {
    data: &'a [u8],
    offset: u32,
}

impl PeFile {
    pub fn section_alignment(&self) -> u32 {
        read_u32(&self.bytes, self.optional_header_offset() + 32).unwrap_or(0)
    }

    pub fn file_alignment(&self) -> u32 {
        read_u32(&self.bytes, self.optional_header_offset() + 36).unwrap_or(0)
    }

    /// First RVA past all existing section storage, aligned to SectionAlignment.
    pub fn next_section_rva(&self) -> Rva {
        let max_end = self
            .sections
            .iter()
            .map(|s| s.rva.saturating_add(s.virtual_size.max(s.raw_size)))
            .max()
            .unwrap_or(0);
        Rva::new(align(max_end, self.section_alignment()))
    }

    /// Repack file storage without moving existing RVAs or section-header ordinals.
    /// Preserved certificate bytes do not authenticate the mutated image.
    pub fn rebuild(&self, edits: &PeEdits) -> anyhow::Result<Vec<u8>> {
        let layout = self.header_layout()?;
        let count = layout
            .num_sections
            .checked_add(edits.new_sections.len())
            .context("section count overflow")?;
        ensure!(count <= MAX_SECTIONS, "PE exceeds 96 section headers");
        let table_end = layout
            .section_table
            .checked_add(count * SECTION_HEADER_SIZE)
            .context("section table overflow")?;
        let header_size = checked_align(
            u32::try_from(table_end).context("section table exceeds u32")?,
            layout.file_alignment,
        )?
        .max(layout.size_of_headers);
        let old_table_end = layout.section_table + layout.num_sections * SECTION_HEADER_SIZE;
        ensure!(
            self.bytes[old_table_end..table_end.min(layout.size_of_headers as usize)]
                .iter()
                .all(|byte| *byte == 0),
            "new section headers would overwrite occupied header bytes"
        );

        let mut changes: Vec<SectionChange<'_>> = (0..layout.num_sections)
            .map(|_| SectionChange::default())
            .collect();
        for update in &edits.section_updates {
            let change = changes
                .get_mut(update.index)
                .context("section update index out of range")?;
            merge_change(&mut change.name, update.name.as_ref())?;
            merge_change(&mut change.flags, update.flags.as_ref())?;
            merge_change(&mut change.data, update.data.as_ref())?;
            merge_change(&mut change.virtual_size, update.virtual_size.as_ref())?;
        }

        let mut sections = Vec::with_capacity(count);
        let mut old_raw = Vec::with_capacity(layout.num_sections);
        for (index, (source, change)) in self.sections.iter().zip(changes).enumerate() {
            let offset = layout.section_table + index * SECTION_HEADER_SIZE;
            let mut header = [0; SECTION_HEADER_SIZE];
            header.copy_from_slice(&self.bytes[offset..offset + SECTION_HEADER_SIZE]);
            if let Some(name) = change.name {
                set_name(&mut header, name)?;
            }
            let original = self
                .section_data(index)
                .context("section raw data is truncated")?;
            if source.raw_size != 0 {
                ensure!(
                    source.raw_pointer >= layout.size_of_headers
                        && source.raw_pointer % layout.file_alignment == 0
                        && source.raw_size % layout.file_alignment == 0,
                    "invalid original section raw geometry"
                );
                old_raw.push((source.raw_pointer, source.raw_size, index));
            }
            let data = if let Some(data) = change.data {
                data.as_slice()
            } else if let Some(size) = change.virtual_size {
                &original[..original.len().min(*size as usize)]
            } else {
                original
            };
            let data_size = u32::try_from(data.len()).context("section data exceeds u32")?;
            let virtual_size = change.virtual_size.copied().unwrap_or_else(|| {
                if change.data.is_some() {
                    data_size
                } else {
                    source.virtual_size
                }
            });
            ensure!(
                change.data.is_none() || data_size <= virtual_size,
                "replacement data exceeds section virtual size"
            );
            let raw_size = checked_align(data_size, layout.file_alignment)?;
            let mut characteristics = source.characteristics;
            if change.flags.is_some() || change.data.is_some() || change.virtual_size.is_some() {
                let flags = change.flags.copied().unwrap_or(SectionFlags {
                    read: characteristics & IMAGE_SCN_MEM_READ != 0,
                    write: characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    execute: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                });
                characteristics &= !(IMAGE_SCN_CNT_CODE
                    | IMAGE_SCN_CNT_INITIALIZED_DATA
                    | IMAGE_SCN_CNT_UNINITIALIZED_DATA
                    | IMAGE_SCN_MEM_READ
                    | IMAGE_SCN_MEM_WRITE
                    | IMAGE_SCN_MEM_EXECUTE);
                characteristics |= characteristics_from_flags(flags);
                if !flags.execute && raw_size == 0 && virtual_size != 0 {
                    characteristics &= !IMAGE_SCN_CNT_INITIALIZED_DATA;
                    characteristics |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
                }
                if flags.execute {
                    characteristics &= !IMAGE_SCN_MEM_DISCARDABLE;
                }
            }
            sections.push(OutputSection {
                header,
                rva: source.rva,
                virtual_size,
                raw_size,
                raw_pointer: 0,
                characteristics,
                data,
                replaced: change.data.is_some(),
            });
        }
        old_raw.sort_unstable_by_key(|&(pointer, _, _)| pointer);
        let mut old_cursor = layout.size_of_headers;
        for &(pointer, size, _) in &old_raw {
            ensure!(pointer >= old_cursor, "overlapping original raw sections");
            old_cursor = pointer
                .checked_add(size)
                .context("raw section end overflow")?;
        }
        for section in &edits.new_sections {
            let mut header = [0; SECTION_HEADER_SIZE];
            set_name(&mut header, &section.name)?;
            let virtual_size =
                u32::try_from(section.data.len()).context("section data exceeds u32")?;
            sections.push(OutputSection {
                header,
                rva: section.rva.get(),
                virtual_size,
                raw_size: checked_align(virtual_size, layout.file_alignment)?,
                raw_pointer: 0,
                characteristics: characteristics_from_flags(section.flags),
                data: &section.data,
                replaced: false,
            });
        }
        validate_virtual_sections(
            self.sections
                .iter()
                .map(|s| (s.rva, s.virtual_size.max(s.raw_size))),
            layout.size_of_headers,
            layout.section_alignment,
        )?;
        let size_of_image = validate_virtual_sections(
            sections
                .iter()
                .map(|s| (s.rva, s.virtual_size.max(s.raw_size))),
            header_size,
            layout.section_alignment,
        )?;

        let mut copies = vec![CopySpan {
            data: &self.bytes[..layout.size_of_headers as usize],
            offset: 0,
        }];
        let mut mappings = vec![FileMapping {
            old: 0,
            length: layout.size_of_headers,
            new: 0,
        }];
        let mut cursor = header_size;
        old_cursor = layout.size_of_headers;
        for &(pointer, size, index) in &old_raw {
            preserve_span(
                self,
                old_cursor,
                pointer,
                &mut cursor,
                &mut copies,
                &mut mappings,
            )?;
            place_section(
                &mut sections[index],
                &mut cursor,
                layout.file_alignment,
                &mut copies,
            )?;
            let retained = size.min(u32::try_from(sections[index].data.len())?);
            if retained != 0 {
                mappings.push(FileMapping {
                    old: pointer,
                    length: retained,
                    new: sections[index].raw_pointer,
                });
            }
            old_cursor = pointer
                .checked_add(size)
                .context("raw section end overflow")?;
        }
        for (index, section) in sections.iter_mut().enumerate() {
            if index >= layout.num_sections || self.sections[index].raw_size == 0 {
                place_section(section, &mut cursor, layout.file_alignment, &mut copies)?;
            }
        }
        preserve_span(
            self,
            old_cursor,
            u32::try_from(self.bytes.len()).context("input file exceeds u32")?,
            &mut cursor,
            &mut copies,
            &mut mappings,
        )?;
        let mut out = vec![0; cursor as usize];
        for copy in copies {
            let begin = copy.offset as usize;
            out[begin..begin + copy.data.len()].copy_from_slice(copy.data);
        }
        let mut code_size = 0u32;
        let mut initialized_size = 0u32;
        let mut uninitialized_size = 0u32;
        let mut base_of_code = None;
        for (index, section) in sections.iter().enumerate() {
            let offset = layout.section_table + index * SECTION_HEADER_SIZE;
            out[offset..offset + SECTION_HEADER_SIZE].copy_from_slice(&section.header);
            write_u32(&mut out, offset + 8, section.virtual_size)?;
            write_u32(&mut out, offset + 12, section.rva)?;
            write_u32(&mut out, offset + 16, section.raw_size)?;
            write_u32(&mut out, offset + 20, section.raw_pointer)?;
            write_u32(&mut out, offset + 36, section.characteristics)?;
            for (field, count_field, stride) in [(24, 32, 10u32), (28, 34, 6)] {
                let pointer = read_u32(&out, offset + field)?;
                if pointer != 0 {
                    let length = u32::from(read_u16(&out, offset + count_field)?)
                        .checked_mul(stride)
                        .context("section file pointer size overflow")?;
                    let mapped = map_file_range(&mappings, pointer, length.max(1))?;
                    write_u32(&mut out, offset + field, mapped)?;
                }
            }
            if section.characteristics & IMAGE_SCN_CNT_CODE != 0 {
                code_size = code_size
                    .checked_add(section.raw_size)
                    .context("SizeOfCode overflow")?;
                if section.virtual_size.max(section.raw_size) != 0 {
                    base_of_code =
                        Some(base_of_code.map_or(section.rva, |rva: u32| rva.min(section.rva)));
                }
            }
            if section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
                initialized_size = initialized_size
                    .checked_add(section.raw_size)
                    .context("SizeOfInitializedData overflow")?;
            }
            if section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                uninitialized_size = uninitialized_size
                    .checked_add(section.virtual_size)
                    .context("SizeOfUninitializedData overflow")?;
            }
            if layout.section_alignment < 0x1000 && section.raw_size != 0 {
                ensure!(
                    section.raw_pointer == section.rva,
                    "low-alignment PE requires matching raw and virtual section offsets"
                );
            }
        }
        write_u16(&mut out, layout.coff + 2, u16::try_from(count)?)?;
        write_u32(&mut out, layout.opt + 4, code_size)?;
        write_u32(&mut out, layout.opt + 8, initialized_size)?;
        write_u32(&mut out, layout.opt + 12, uninitialized_size)?;
        write_u32(&mut out, layout.opt + 20, base_of_code.unwrap_or(0))?;
        write_u32(&mut out, layout.opt + 56, size_of_image)?;
        write_u32(&mut out, layout.opt + 60, header_size)?;
        let symbols = read_u32(&out, layout.coff + 8)?;
        if symbols != 0 {
            let count = read_u32(&out, layout.coff + 12)?;
            let length = count
                .checked_mul(18)
                .context("COFF symbol table size overflow")?;
            let pointer = map_file_range(&mappings, symbols, length.max(1))?;
            write_u32(&mut out, layout.coff + 8, pointer)?;
        }
        let mut directory_updates = vec![None; layout.num_dirs];
        for update in &edits.directories {
            let slot = directory_updates
                .get_mut(update.index)
                .context("directory index out of range")?;
            let value = (update.rva.get(), update.size);
            ensure!(
                slot.is_none_or(|previous| previous == value),
                "conflicting directory updates"
            );
            *slot = Some(value);
            let base = layout.opt + 112 + update.index * 8;
            write_u32(&mut out, base, value.0)?;
            write_u32(&mut out, base + 4, value.1)?;
        }
        if layout.num_dirs > 4 {
            let base = layout.opt + 112 + 4 * 8;
            let pointer = read_u32(&out, base)?;
            let size = read_u32(&out, base + 4)?;
            ensure!((pointer == 0) == (size == 0), "invalid Security directory");
            if size != 0 {
                let pointer = if directory_updates[4].is_none() {
                    map_file_range(&mappings, pointer, size)?
                } else {
                    pointer
                };
                ensure!(
                    pointer % 8 == 0,
                    "certificate table is not eight-byte aligned"
                );
                ensure!(
                    u64::from(pointer) + u64::from(size) <= out.len() as u64,
                    "certificate table is not file-backed"
                );
                write_u32(&mut out, base, pointer)?;
            }
        }
        if let Some(entry_point) = edits.entry_point {
            write_u32(&mut out, layout.opt + 16, entry_point.get())?;
        }
        if edits.clear_guard_cf {
            let characteristics = read_u16(&out, layout.opt + 70)? & !0x4000;
            write_u16(&mut out, layout.opt + 70, characteristics)?;
        }
        let mut patch_ranges = Vec::with_capacity(edits.patches.len());
        for patch in &edits.patches {
            let length = u32::try_from(patch.bytes.len()).context("patch length exceeds u32")?;
            let end = patch
                .rva
                .get()
                .checked_add(length)
                .context("patch RVA overflow")?;
            let section = sections
                .iter()
                .find(|section| {
                    patch
                        .rva
                        .get()
                        .checked_sub(section.rva)
                        .is_some_and(|delta| (delta as usize) < section.data.len())
                })
                .context("patch targets removed or non-file-backed section storage")?;
            ensure!(
                u64::from(end) <= u64::from(section.rva) + section.data.len() as u64,
                "patch exceeds retained section bytes"
            );
            ensure!(
                !section.replaced || length == 0,
                "patch conflicts with section replacement"
            );
            let offset = section.raw_pointer as usize + (patch.rva.get() - section.rva) as usize;
            patch_ranges.push((offset, &patch.bytes));
        }
        patch_ranges.sort_unstable_by_key(|(offset, _)| *offset);
        let mut covering = 0;
        for index in 1..patch_ranges.len() {
            let (first, second) = (&patch_ranges[covering], &patch_ranges[index]);
            let first_end = first.0 + first.1.len();
            if second.0 < first_end {
                let length = (first_end - second.0).min(second.1.len());
                ensure!(
                    first.1[second.0 - first.0..second.0 - first.0 + length] == second.1[..length],
                    "conflicting byte patches"
                );
            }
            if second.0 + second.1.len() > first_end {
                covering = index;
            }
        }
        for (offset, bytes) in patch_ranges {
            out[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
        validate_directory_extents(&out, &layout, &sections)?;
        let entry = read_u32(&out, layout.opt + 16)?;
        if entry != 0 {
            ensure!(
                sections
                    .iter()
                    .any(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                        && entry >= s.rva
                        && ((entry - s.rva) as usize) < s.data.len()),
                "entry point is not in retained executable storage"
            );
        }
        rebuild_debug_file_pointers(&mut out, &layout, &sections, &mappings)?;
        let checksum = pe_checksum(&out, layout.opt + 64)?;
        write_u32(&mut out, layout.opt + 64, checksum)?;
        Ok(out)
    }

    fn optional_header_offset(&self) -> usize {
        read_u32(&self.bytes, 0x3c)
            .map(|e| e as usize + 4 + 20)
            .unwrap_or(0)
    }

    fn header_layout(&self) -> anyhow::Result<HeaderLayout> {
        let e_lfanew = read_u32(&self.bytes, 0x3c)? as usize;
        let coff = e_lfanew
            .checked_add(4)
            .context("PE header offset overflow")?;
        let num_sections = read_u16(&self.bytes, coff + 2)? as usize;
        ensure!(
            num_sections <= MAX_SECTIONS && num_sections == self.sections.len(),
            "invalid section count"
        );
        let size_of_optional = read_u16(&self.bytes, coff + 16)? as usize;
        let opt = coff
            .checked_add(20)
            .context("optional header offset overflow")?;
        ensure!(
            read_u16(&self.bytes, coff)? == 0x8664 && read_u16(&self.bytes, opt)? == 0x20b,
            "only x64 PE32+ images can be rebuilt"
        );
        ensure!(size_of_optional >= 112, "truncated PE32+ optional header");
        let num_dirs = read_u32(&self.bytes, opt + 108)? as usize;
        ensure!(
            num_dirs <= 16 && num_dirs <= (size_of_optional - 112) / 8,
            "invalid data directory count"
        );
        let section_table = opt
            .checked_add(size_of_optional)
            .context("section table offset overflow")?;
        let table_end = section_table
            .checked_add(num_sections * SECTION_HEADER_SIZE)
            .context("section table end overflow")?;
        let size_of_headers = read_u32(&self.bytes, opt + 60)?;
        let file_alignment = read_u32(&self.bytes, opt + 36)?;
        let section_alignment = read_u32(&self.bytes, opt + 32)?;
        ensure!(
            file_alignment.is_power_of_two()
                && section_alignment.is_power_of_two()
                && file_alignment <= section_alignment,
            "invalid PE alignments"
        );
        ensure!(
            (section_alignment < 0x1000 && file_alignment == section_alignment)
                || (0x200..=0x10000).contains(&file_alignment),
            "invalid PE file alignment"
        );
        ensure!(
            size_of_headers as usize >= table_end
                && size_of_headers as usize <= self.bytes.len()
                && size_of_headers % file_alignment == 0,
            "invalid SizeOfHeaders"
        );
        Ok(HeaderLayout {
            coff,
            opt,
            section_table,
            num_sections,
            size_of_headers,
            file_alignment,
            section_alignment,
            num_dirs,
        })
    }

    pub(super) fn patch_offset(&self, rva: u32, len: usize) -> anyhow::Result<usize> {
        for s in &self.sections {
            if let Some(delta) = rva.checked_sub(s.rva).filter(|delta| *delta < s.raw_size) {
                let offset = (s.raw_pointer as usize)
                    .checked_add(delta as usize)
                    .context("patch target out of section bounds")?;
                let end = offset
                    .checked_add(len)
                    .context("patch target out of section bounds")?;
                ensure!(
                    u64::from(delta) + len as u64 <= u64::from(s.raw_size)
                        && end <= self.bytes.len(),
                    "patch target out of section bounds"
                );
                return Ok(offset);
            }
        }
        anyhow::bail!("patch target out of section bounds")
    }
}

fn merge_change<'a, T: PartialEq>(
    slot: &mut Option<&'a T>,
    value: Option<&'a T>,
) -> anyhow::Result<()> {
    if let Some(value) = value {
        ensure!(
            slot.is_none_or(|previous| previous == value),
            "conflicting section updates"
        );
        *slot = Some(value);
    }
    Ok(())
}

fn set_name(header: &mut [u8; SECTION_HEADER_SIZE], name: &str) -> anyhow::Result<()> {
    ensure!(
        name.len() <= 8 && name.is_ascii() && !name.as_bytes().contains(&0),
        "section name must be at most eight ASCII bytes without NUL"
    );
    header[..8].fill(0);
    header[..name.len()].copy_from_slice(name.as_bytes());
    Ok(())
}

fn checked_align(value: u32, alignment: u32) -> anyhow::Result<u32> {
    ensure!(alignment.is_power_of_two(), "invalid alignment");
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
        .context("aligned value overflow")
}

fn validate_virtual_sections(
    ranges: impl Iterator<Item = (u32, u32)>,
    header_size: u32,
    alignment: u32,
) -> anyhow::Result<u32> {
    let mut ranges: Vec<_> = ranges.collect();
    ranges.sort_unstable_by_key(|&(rva, _)| rva);
    let header_end = checked_align(header_size, alignment)?;
    let mut end = header_end;
    for (rva, size) in ranges {
        ensure!(
            rva % alignment == 0 && rva >= header_end,
            "unaligned section or virtual header overlap"
        );
        if size == 0 {
            continue;
        }
        ensure!(rva >= end, "overlapping virtual sections");
        let section_end = rva
            .checked_add(size)
            .context("virtual section end overflow")?;
        end = checked_align(section_end, alignment)?;
    }
    Ok(end)
}

fn preserve_span<'a>(
    pe: &'a PeFile,
    begin: u32,
    end: u32,
    cursor: &mut u32,
    copies: &mut Vec<CopySpan<'a>>,
    mappings: &mut Vec<FileMapping>,
) -> anyhow::Result<()> {
    if begin == end {
        return Ok(());
    }
    let length = end
        .checked_sub(begin)
        .context("overlapping raw file spans")?;
    let data = pe
        .bytes
        .get(begin as usize..end as usize)
        .context("truncated raw file span")?;
    copies.push(CopySpan {
        data,
        offset: *cursor,
    });
    mappings.push(FileMapping {
        old: begin,
        length,
        new: *cursor,
    });
    *cursor = cursor
        .checked_add(length)
        .context("output file size overflow")?;
    Ok(())
}

fn place_section<'a>(
    section: &mut OutputSection<'a>,
    cursor: &mut u32,
    alignment: u32,
    copies: &mut Vec<CopySpan<'a>>,
) -> anyhow::Result<()> {
    if section.raw_size == 0 {
        return Ok(());
    }
    *cursor = checked_align(*cursor, alignment)?;
    section.raw_pointer = *cursor;
    copies.push(CopySpan {
        data: section.data,
        offset: *cursor,
    });
    *cursor = cursor
        .checked_add(section.raw_size)
        .context("output section size overflow")?;
    Ok(())
}

fn map_file_range(mappings: &[FileMapping], pointer: u32, length: u32) -> anyhow::Result<u32> {
    for mapping in mappings {
        if let Some(delta) = pointer
            .checked_sub(mapping.old)
            .filter(|delta| *delta < mapping.length)
        {
            ensure!(
                u64::from(delta) + u64::from(length) <= u64::from(mapping.length),
                "file pointer crosses replaced or truncated storage"
            );
            return mapping
                .new
                .checked_add(delta)
                .context("file pointer overflow");
        }
    }
    anyhow::bail!("file pointer targets replaced or truncated storage")
}

fn validate_directory_extents(
    bytes: &[u8],
    layout: &HeaderLayout,
    sections: &[OutputSection<'_>],
) -> anyhow::Result<()> {
    for index in 0..layout.num_dirs {
        if index == 4 {
            continue;
        }
        let base = layout.opt + 112 + index * 8;
        let rva = read_u32(bytes, base)?;
        let size = read_u32(bytes, base + 4)?;
        if rva != 0 {
            final_file_offset(bytes, layout, sections, rva, size.max(1)).with_context(|| {
                format!("directory {index} targets removed or non-file-backed storage")
            })?;
        } else {
            ensure!(size == 0, "directory {index} has a size without an RVA");
        }
    }
    Ok(())
}

fn rebuild_debug_file_pointers(
    bytes: &mut [u8],
    layout: &HeaderLayout,
    sections: &[OutputSection<'_>],
    mappings: &[FileMapping],
) -> anyhow::Result<()> {
    if layout.num_dirs <= 6 {
        return Ok(());
    }
    let base = layout.opt + 112 + 6 * 8;
    let rva = read_u32(bytes, base)?;
    let size = read_u32(bytes, base + 4)?;
    if rva == 0 && size == 0 {
        return Ok(());
    }
    ensure!(
        rva != 0 && size % 28 == 0,
        "invalid rebuilt debug directory"
    );
    let offset = final_file_offset(bytes, layout, sections, rva, size)?;
    for record in (offset..offset + size as usize).step_by(28) {
        let payload = read_u32(bytes, record + 20)?;
        let length = read_u32(bytes, record + 16)?;
        let pointer = read_u32(bytes, record + 24)?;
        if length == 0 {
            write_u32(bytes, record + 24, 0)?;
            continue;
        }
        let file = if payload != 0 {
            u32::try_from(final_file_offset(bytes, layout, sections, payload, length)?)?
        } else {
            ensure!(pointer != 0, "debug payload has no file location");
            map_file_range(mappings, pointer, length)?
        };
        write_u32(bytes, record + 24, file)?;
    }
    Ok(())
}

fn final_file_offset(
    bytes: &[u8],
    layout: &HeaderLayout,
    sections: &[OutputSection<'_>],
    rva: u32,
    length: u32,
) -> anyhow::Result<usize> {
    let header_size = read_u32(bytes, layout.opt + 60)?;
    if rva < header_size && u64::from(rva) + u64::from(length) <= u64::from(header_size) {
        return Ok(rva as usize);
    }
    for section in sections {
        let Some(delta) = rva
            .checked_sub(section.rva)
            .filter(|delta| (*delta as usize) < section.data.len())
        else {
            continue;
        };
        ensure!(
            u64::from(delta) + u64::from(length) <= section.data.len() as u64,
            "RVA range exceeds retained section data"
        );
        let offset = (section.raw_pointer as usize)
            .checked_add(delta as usize)
            .context("file offset overflow")?;
        ensure!(
            offset
                .checked_add(length as usize)
                .is_some_and(|end| end <= bytes.len()),
            "RVA range is not file-backed"
        );
        return Ok(offset);
    }
    anyhow::bail!("RVA {rva:#x} is not file-backed")
}

fn pe_checksum(bytes: &[u8], checksum_offset: usize) -> anyhow::Result<u32> {
    let mut sum = 0u64;
    for (index, pair) in bytes.chunks(2).enumerate() {
        let offset = index * 2;
        if (checksum_offset..checksum_offset + 4).contains(&offset) {
            continue;
        }
        sum += u64::from(u16::from_le_bytes([
            pair[0],
            pair.get(1).copied().unwrap_or(0),
        ]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    let length = u32::try_from(bytes.len()).context("checksum file length exceeds u32")?;
    (sum as u32)
        .checked_add(length)
        .context("PE checksum overflow")
}

fn align(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    match value % alignment {
        0 => value,
        remainder => value.saturating_add(alignment - remainder),
    }
}

fn characteristics_from_flags(flags: SectionFlags) -> u32 {
    let mut characteristics = 0;
    if flags.read {
        characteristics |= IMAGE_SCN_MEM_READ;
    }
    if flags.write {
        characteristics |= IMAGE_SCN_MEM_WRITE;
    }
    if flags.execute {
        characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    } else {
        characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
    }
    characteristics
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> anyhow::Result<()> {
    let end = offset
        .checked_add(2)
        .context("input truncated or out of bounds")?;
    bytes
        .get_mut(offset..end)
        .context("input truncated or out of bounds")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> anyhow::Result<()> {
    let end = offset
        .checked_add(4)
        .context("input truncated or out of bounds")?;
    bytes
        .get_mut(offset..end)
        .context("input truncated or out of bounds")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COFF: usize = 0x84;
    const OPT: usize = 0x98;
    const TABLE: usize = OPT + 0xf0;

    fn fixture(sections: &[(u32, u32, u32, u32)]) -> Vec<u8> {
        let header_size = align((TABLE + sections.len() * 40) as u32, 0x200);
        let raw_end = sections
            .iter()
            .map(|(_, _, pointer, size)| pointer + size)
            .max()
            .unwrap_or(header_size)
            .max(header_size);
        let mut bytes = vec![0; raw_end as usize];
        bytes[..2].copy_from_slice(b"MZ");
        write_u32(&mut bytes, 0x3c, 0x80).unwrap();
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        write_u16(&mut bytes, COFF, 0x8664).unwrap();
        write_u16(&mut bytes, COFF + 2, sections.len() as u16).unwrap();
        write_u16(&mut bytes, COFF + 16, 0xf0).unwrap();
        write_u16(&mut bytes, COFF + 18, 0x2022).unwrap();
        write_u16(&mut bytes, OPT, 0x20b).unwrap();
        bytes[OPT + 24..OPT + 32].copy_from_slice(&0x7ffa_0000_0000u64.to_le_bytes());
        write_u32(&mut bytes, OPT + 32, 0x1000).unwrap();
        write_u32(&mut bytes, OPT + 36, 0x200).unwrap();
        write_u32(&mut bytes, OPT + 56, 0x10000).unwrap();
        write_u32(&mut bytes, OPT + 60, header_size).unwrap();
        write_u16(&mut bytes, OPT + 70, 0x4080).unwrap();
        write_u32(&mut bytes, OPT + 108, 16).unwrap();
        for (index, &(rva, virtual_size, pointer, size)) in sections.iter().enumerate() {
            let header = TABLE + index * 40;
            bytes[header..header + 5].copy_from_slice(b".data");
            write_u32(&mut bytes, header + 8, virtual_size).unwrap();
            write_u32(&mut bytes, header + 12, rva).unwrap();
            write_u32(&mut bytes, header + 16, size).unwrap();
            write_u32(&mut bytes, header + 20, pointer).unwrap();
            write_u32(
                &mut bytes,
                header + 36,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
            )
            .unwrap();
            if size != 0 {
                bytes[pointer as usize..(pointer + size) as usize].fill((index + 1) as u8);
            }
        }
        bytes
    }

    fn flags(execute: bool) -> SectionFlags {
        SectionFlags {
            read: true,
            write: false,
            execute,
        }
    }

    fn new_section(rva: u32) -> NewSection {
        NewSection {
            name: ".kamy".into(),
            rva: Rva::new(rva),
            flags: flags(false),
            data: vec![7; 12],
        }
    }

    #[test]
    fn slot_retype_keeps_ordinal_and_rva_but_replaces_content_flags() {
        let mut bytes = fixture(&[(0x1000, 0x100, 0x200, 0x200), (0x2000, 0x100, 0x400, 0x200)]);
        write_u32(
            &mut bytes,
            TABLE + 40 + 36,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE,
        )
        .unwrap();
        let pe = PeFile::parse(&bytes).unwrap();
        let out = pe
            .rebuild(&PeEdits {
                section_updates: vec![SectionUpdate {
                    index: 1,
                    name: Some(".text".into()),
                    flags: Some(flags(true)),
                    data: Some(vec![0xc3; 17]),
                    ..Default::default()
                }],
                entry_point: Some(Rva::new(0x2000)),
                ..Default::default()
            })
            .unwrap();
        let result = PeFile::parse(&out).unwrap();
        let slot = &result.section_headers()[1];
        assert_eq!(
            (slot.name.as_str(), slot.rva, slot.virtual_size),
            (".text", 0x2000, 17)
        );
        assert_eq!(
            slot.characteristics,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE
        );
        assert_eq!(read_u32(&out, OPT + 4).unwrap(), 0x200);
        assert_eq!(read_u32(&out, OPT + 8).unwrap(), 0x200);
        assert_eq!(read_u32(&out, OPT + 20).unwrap(), 0x2000);
        assert_eq!(&out[OPT + 24..OPT + 32], &bytes[OPT + 24..OPT + 32]);
        assert_eq!(read_u16(&out, COFF + 18).unwrap(), 0x2022);
        assert_eq!(read_u16(&out, OPT + 70).unwrap(), 0x4080);
        assert_eq!(result.section_data(1).unwrap()[..17], [0xc3; 17]);
    }

    #[test]
    fn tail_truncate_reclaims_raw_bytes_without_moving_virtual_survivor() {
        let bytes = fixture(&[(0x1000, 0x600, 0x200, 0x600), (0x2000, 0x200, 0x800, 0x200)]);
        let pe = PeFile::parse(&bytes).unwrap();
        let out = pe
            .rebuild(&PeEdits {
                section_updates: vec![SectionUpdate {
                    index: 0,
                    virtual_size: Some(0x80),
                    ..Default::default()
                }],
                patches: vec![BytePatch {
                    rva: Rva::new(0x2010),
                    bytes: vec![0x55],
                }],
                ..Default::default()
            })
            .unwrap();
        let result = PeFile::parse(&out).unwrap();
        assert_eq!(out.len(), 0x600);
        assert_eq!(result.section_headers()[0].raw_size, 0x200);
        assert_eq!(
            (
                result.section_headers()[1].rva,
                result.section_headers()[1].raw_pointer
            ),
            (0x2000, 0x400)
        );
        assert_eq!(out[0x410], 0x55);
        assert!(out[0x280..0x400].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn retiring_last_storage_keeps_its_header_but_shrinks_image_and_file() {
        let bytes = fixture(&[(0x1000, 0x200, 0x200, 0x200), (0x5000, 0x200, 0x400, 0x200)]);
        let pe = PeFile::parse(&bytes).unwrap();
        let out = pe
            .rebuild(&PeEdits {
                section_updates: vec![SectionUpdate {
                    index: 1,
                    name: Some(String::new()),
                    data: Some(Vec::new()),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
        let result = PeFile::parse(&out).unwrap();
        assert_eq!(result.section_headers().len(), 2);
        let slot = &result.section_headers()[1];
        assert_eq!(
            (slot.rva, slot.virtual_size, slot.raw_size, slot.raw_pointer),
            (0x5000, 0, 0, 0)
        );
        assert_eq!(&out[TABLE + 40..TABLE + 48], &[0; 8]);
        assert_eq!(out.len(), 0x400);
        assert_eq!(read_u32(&out, OPT + 56).unwrap(), 0x2000);
    }

    #[test]
    fn expanding_headers_cannot_cover_a_resident_virtual_section() {
        let mut bytes = fixture(&[(0x200, 0x200, 0x200, 0x200)]);
        write_u32(&mut bytes, OPT + 32, 0x200).unwrap();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(
            pe.rebuild(&PeEdits {
                new_sections: vec![new_section(0x400), new_section(0x600), new_section(0x800)],
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn header_growth_shifts_raw_data_and_repairs_debug_security_and_coff_pointers() {
        let mut bytes = fixture(&[
            (0x1000, 0x200, 0x200, 0x200),
            (0x2000, 0x200, 0x400, 0x200),
            (0x3000, 0x200, 0x600, 0x200),
        ]);
        write_u32(&mut bytes, OPT + 112 + 6 * 8, 0x2000).unwrap();
        write_u32(&mut bytes, OPT + 112 + 6 * 8 + 4, 56).unwrap();
        bytes[0x400..0x438].fill(0);
        write_u32(&mut bytes, 0x400 + 16, 4).unwrap();
        write_u32(&mut bytes, 0x400 + 20, 0x2080).unwrap();
        write_u32(&mut bytes, 0x400 + 24, 0x480).unwrap();
        write_u32(&mut bytes, 0x41c + 16, 4).unwrap();
        write_u32(&mut bytes, 0x41c + 24, 0x810).unwrap();
        bytes.extend_from_slice(&[0xa5; 0x40]);
        write_u32(&mut bytes, OPT + 112 + 4 * 8, 0x800).unwrap();
        write_u32(&mut bytes, OPT + 112 + 4 * 8 + 4, 16).unwrap();
        write_u32(&mut bytes, COFF + 8, 0x820).unwrap();
        write_u32(&mut bytes, COFF + 12, 1).unwrap();
        write_u32(&mut bytes, TABLE + 24, 0x200).unwrap();
        write_u16(&mut bytes, TABLE + 32, 1).unwrap();
        let pe = PeFile::parse(&bytes).unwrap();
        let out = pe
            .rebuild(&PeEdits {
                new_sections: vec![new_section(0x4000)],
                patches: vec![BytePatch {
                    rva: Rva::new(0x1010),
                    bytes: vec![0x77],
                }],
                ..Default::default()
            })
            .unwrap();
        let result = PeFile::parse(&out).unwrap();
        assert_eq!(read_u32(&out, OPT + 60).unwrap(), 0x400);
        for (index, section) in result.section_headers()[..3].iter().enumerate() {
            assert_eq!(section.rva, (index as u32 + 1) * 0x1000);
            assert_eq!(section.raw_pointer, 0x400 + index as u32 * 0x200);
        }
        assert_eq!(out[0x410], 0x77);
        assert_eq!(read_u32(&out, 0x600 + 24).unwrap(), 0x680);
        assert_eq!(read_u32(&out, 0x61c + 24).unwrap(), 0xc10);
        assert_eq!(read_u32(&out, OPT + 112 + 4 * 8).unwrap(), 0xc00);
        assert_eq!(&out[0xc00..], &bytes[0x800..]);
        assert_eq!(read_u32(&out, COFF + 8).unwrap(), 0xc20);
        assert_eq!(read_u32(&out, TABLE + 24).unwrap(), 0x400);
        assert_eq!(read_u32(&out, OPT + 56).unwrap(), 0x5000);
    }

    #[test]
    fn bss_stays_unbacked_and_file_backed_bytes_remain_initialized() {
        let bytes = fixture(&[(0x1000, 0x900, 0, 0), (0x2000, 0x600, 0x200, 0x200)]);
        let pe = PeFile::parse(&bytes).unwrap();
        let out = pe
            .rebuild(&PeEdits {
                section_updates: vec![
                    SectionUpdate {
                        index: 0,
                        flags: Some(SectionFlags {
                            read: true,
                            write: true,
                            execute: false,
                        }),
                        ..Default::default()
                    },
                    SectionUpdate {
                        index: 1,
                        virtual_size: Some(0x800),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            })
            .unwrap();
        let result = PeFile::parse(&out).unwrap();
        assert_eq!(result.section_headers()[0].raw_size, 0);
        assert_eq!(result.section_headers()[0].raw_pointer, 0);
        assert_eq!(
            result.section_headers()[0].characteristics & 0xe0,
            IMAGE_SCN_CNT_UNINITIALIZED_DATA
        );
        assert_eq!(result.section_headers()[1].raw_size, 0x200);
        assert_eq!(read_u32(&out, OPT + 8).unwrap(), 0x200);
        assert_eq!(read_u32(&out, OPT + 12).unwrap(), 0x900);
        assert_eq!(out.len(), 0x400);
    }

    #[test]
    fn checksum_matches_independent_word_sum_and_odd_overlay() {
        let mut bytes = fixture(&[(0x1000, 0x200, 0x200, 0x200)]);
        bytes.extend_from_slice(&[0x12, 0x34, 0x56]);
        write_u32(&mut bytes, OPT + 64, 0xdead_beef).unwrap();
        let out = PeFile::parse(&bytes)
            .unwrap()
            .rebuild(&PeEdits::default())
            .unwrap();
        let mut words = 0u64;
        for index in (0..out.len()).step_by(2) {
            if !(OPT + 64..OPT + 68).contains(&index) {
                words += u64::from(out[index])
                    + (u64::from(out.get(index + 1).copied().unwrap_or(0)) << 8);
            }
        }
        while words >> 16 != 0 {
            words = (words & 0xffff) + (words >> 16);
        }
        assert_eq!(
            read_u32(&out, OPT + 64).unwrap(),
            words as u32 + out.len() as u32
        );
        assert_ne!(read_u32(&out, OPT + 64).unwrap(), 0);
    }

    #[test]
    fn invalid_overlaps_and_geometry_are_rejected() {
        for sections in [
            vec![(0x1000, 0x200, 0x200, 0x200), (0x1000, 0x200, 0x400, 0x200)],
            vec![(0x1000, 0x200, 0x200, 0x200), (0x2000, 0x200, 0x200, 0x200)],
            vec![
                (0x1000, 0x1200, 0x200, 0x200),
                (0x2000, 0x200, 0x400, 0x200),
            ],
        ] {
            assert!(
                PeFile::parse(&fixture(&sections))
                    .unwrap()
                    .rebuild(&PeEdits::default())
                    .is_err()
            );
        }
        let pe = PeFile::parse(&fixture(&[(0x1000, 0x200, 0x200, 0x200)])).unwrap();
        for name in ["123456789", "\0", "é"] {
            let mut section = new_section(0x2000);
            section.name = name.into();
            assert!(
                pe.rebuild(&PeEdits {
                    new_sections: vec![section],
                    ..Default::default()
                })
                .is_err()
            );
        }
        assert!(
            pe.rebuild(&PeEdits {
                new_sections: vec![new_section(0x1000)],
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            pe.rebuild(&PeEdits {
                new_sections: vec![new_section(0xffff_f000)],
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            pe.rebuild(&PeEdits {
                new_sections: (0..96).map(|i| new_section(0x2000 + i * 0x1000)).collect(),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            pe.rebuild(&PeEdits {
                section_updates: vec![SectionUpdate {
                    index: 1,
                    ..Default::default()
                }],
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn patch_and_replacement_ownership_conflicts_are_rejected() {
        let pe = PeFile::parse(&fixture(&[(0x1000, 0x600, 0x200, 0x600)])).unwrap();
        assert!(
            pe.rebuild(&PeEdits {
                section_updates: vec![SectionUpdate {
                    index: 0,
                    data: Some(vec![0; 0x200]),
                    ..Default::default()
                }],
                patches: vec![BytePatch {
                    rva: Rva::new(0x1010),
                    bytes: vec![1]
                }],
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            pe.rebuild(&PeEdits {
                section_updates: vec![SectionUpdate {
                    index: 0,
                    virtual_size: Some(0x100),
                    ..Default::default()
                }],
                patches: vec![BytePatch {
                    rva: Rva::new(0x1400),
                    bytes: vec![1]
                }],
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            pe.rebuild(&PeEdits {
                section_updates: vec![
                    SectionUpdate {
                        index: 0,
                        name: Some("a".into()),
                        ..Default::default()
                    },
                    SectionUpdate {
                        index: 0,
                        name: Some("b".into()),
                        ..Default::default()
                    }
                ],
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            pe.rebuild(&PeEdits {
                patches: vec![
                    BytePatch {
                        rva: Rva::new(0x1000),
                        bytes: vec![1; 10]
                    },
                    BytePatch {
                        rva: Rva::new(0x1005),
                        bytes: vec![2]
                    }
                ],
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            pe.rebuild(&PeEdits {
                section_updates: vec![SectionUpdate {
                    index: 0,
                    virtual_size: Some(0x100),
                    ..Default::default()
                }],
                patches: vec![BytePatch {
                    rva: Rva::new(0x1180),
                    bytes: vec![1]
                }],
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            pe.rebuild(&PeEdits {
                patches: vec![
                    BytePatch {
                        rva: Rva::new(0x1000),
                        bytes: vec![1; 10]
                    },
                    BytePatch {
                        rva: Rva::new(0x1005),
                        bytes: vec![1]
                    },
                    BytePatch {
                        rva: Rva::new(0x1008),
                        bytes: vec![2]
                    },
                ],
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn active_directory_cannot_be_truncated_away() {
        let mut bytes = fixture(&[(0x1000, 0x600, 0x200, 0x600)]);
        write_u32(&mut bytes, OPT + 112 + 2 * 8, 0x1400).unwrap();
        write_u32(&mut bytes, OPT + 112 + 2 * 8 + 4, 0x100).unwrap();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(
            pe.rebuild(&PeEdits {
                section_updates: vec![SectionUpdate {
                    index: 0,
                    virtual_size: Some(0x200),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .is_err()
        );
        write_u32(&mut bytes, OPT + 112 + 2 * 8, 0x1180).unwrap();
        write_u32(&mut bytes, OPT + 112 + 2 * 8 + 4, 0x10).unwrap();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(
            pe.rebuild(&PeEdits {
                section_updates: vec![SectionUpdate {
                    index: 0,
                    virtual_size: Some(0x100),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn arbitrary_original_name_bytes_and_opaque_gaps_survive() {
        let mut bytes = fixture(&[(0x1000, 0x200, 0x400, 0x200)]);
        bytes[TABLE..TABLE + 8].copy_from_slice(&[0xff, 0xfe, b'x', 0, 0xaa, 0xbb, 0xcc, 0xdd]);
        bytes[0x200..0x400].fill(0x95);
        let out = PeFile::parse(&bytes)
            .unwrap()
            .rebuild(&PeEdits {
                new_sections: vec![new_section(0x2000)],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(&out[TABLE..TABLE + 8], &bytes[TABLE..TABLE + 8]);
        assert_eq!(&out[0x200..0x400], &bytes[0x200..0x400]);
    }

    #[test]
    fn next_section_rva_includes_raw_storage_and_rounds_up() {
        let bytes = fixture(&[(0x1000, 0x100, 0x200, 0x1200)]);
        let pe = PeFile::parse(&bytes).unwrap();
        assert_eq!(pe.next_section_rva(), Rva::new(0x3000));
        assert_eq!(align(0x201, 0x200), 0x400);
        assert_eq!(align(0x1234, 0), 0x1234);
    }
}
