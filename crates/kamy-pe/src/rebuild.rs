use kamy_core::{Rva, SectionFlags};

use anyhow::Context;

use crate::{
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PeFile, read_u16, read_u32,
};

const IMAGE_SCN_CNT_CODE: u32 = 0x20;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x40;

const SECTION_HEADER_SIZE: usize = 40;

pub struct NewSection {
    pub name: String,
    pub rva: Rva,
    pub flags: SectionFlags,
    pub data: Vec<u8>,
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
    pub new_sections: Vec<NewSection>,
    pub patches: Vec<BytePatch>,
    pub directories: Vec<DirectoryUpdate>,
    pub entry_point: Option<Rva>,
    pub clear_guard_cf: bool,
}

impl PeEdits {
    fn is_empty(&self) -> bool {
        self.new_sections.is_empty()
            && self.patches.is_empty()
            && self.directories.is_empty()
            && self.entry_point.is_none()
            && !self.clear_guard_cf
    }
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

impl PeFile {
    pub fn section_alignment(&self) -> u32 {
        read_u32(&self.bytes, self.optional_header_offset() + 32).unwrap_or(0)
    }

    pub fn file_alignment(&self) -> u32 {
        read_u32(&self.bytes, self.optional_header_offset() + 36).unwrap_or(0)
    }

    /// First RVA past all existing sections, aligned up to SectionAlignment.
    pub fn next_section_rva(&self) -> Rva {
        let max_end = self
            .sections
            .iter()
            .map(|s| s.rva.saturating_add(s.virtual_size))
            .max()
            .unwrap_or(0);
        Rva::new(align(max_end, self.section_alignment()))
    }

    /// Produce a new PE image: original bytes, with appended sections, applied
    /// byte patches, an extended section table, bumped NumberOfSections and
    /// SizeOfImage, and updated data directory entries.
    pub fn rebuild(&self, edits: &PeEdits) -> anyhow::Result<Vec<u8>> {
        let mut out = self.bytes.clone();
        if edits.is_empty() {
            return Ok(out);
        }

        let layout = self.header_layout()?;

        for patch in &edits.patches {
            let offset = self.patch_offset(patch.rva.get(), patch.bytes.len())?;
            out[offset..offset + patch.bytes.len()].copy_from_slice(&patch.bytes);
        }

        let first_raw = self
            .sections
            .iter()
            .map(|s| s.raw_pointer)
            .filter(|&p| p != 0)
            .min();
        let mut header_limit = layout.size_of_headers as usize;
        if let Some(fr) = first_raw {
            header_limit = header_limit.min(fr as usize);
        }

        let mut header_cursor = layout
            .section_table
            .checked_add(layout.num_sections * SECTION_HEADER_SIZE)
            .context("no room in header for new section")?;

        for section in &edits.new_sections {
            let slot_end = header_cursor
                .checked_add(SECTION_HEADER_SIZE)
                .context("no room in header for new section")?;
            if slot_end > header_limit {
                anyhow::bail!("no room in header for new section");
            }

            let raw_pointer = align(
                u32::try_from(out.len()).context("value exceeds u32")?,
                layout.file_alignment,
            );
            out.resize(raw_pointer as usize, 0);

            let virtual_size = u32::try_from(section.data.len()).context("value exceeds u32")?;
            let raw_size = align(virtual_size, layout.file_alignment);
            out.extend_from_slice(&section.data);
            out.resize(raw_pointer as usize + raw_size as usize, 0);

            write_section_header(
                &mut out,
                header_cursor,
                section,
                raw_pointer,
                raw_size,
                virtual_size,
            )?;
            header_cursor += SECTION_HEADER_SIZE;
        }

        let new_num_sections = layout.num_sections + edits.new_sections.len();
        write_u16(
            &mut out,
            layout.coff + 2,
            u16::try_from(new_num_sections).context("no room in header for new section")?,
        )?;

        let mut size_of_image = read_u32(&out, layout.opt + 56)?;
        for section in &edits.new_sections {
            let virtual_size = u32::try_from(section.data.len()).context("value exceeds u32")?;
            let end = align(
                section.rva.get().saturating_add(virtual_size),
                layout.section_alignment,
            );
            size_of_image = size_of_image.max(end);
        }
        write_u32(&mut out, layout.opt + 56, size_of_image)?;

        for update in &edits.directories {
            if update.index >= layout.num_dirs {
                anyhow::bail!("directory index out of range");
            }
            let base = layout.opt + 112 + update.index * 8;
            write_u32(&mut out, base, update.rva.get())?;
            write_u32(&mut out, base + 4, update.size)?;
        }
        if let Some(entry_point) = edits.entry_point {
            write_u32(&mut out, layout.opt + 16, entry_point.get())?;
        }
        if edits.clear_guard_cf {
            let characteristics = read_u16(&out, layout.opt + 70)? & !0x4000;
            write_u16(&mut out, layout.opt + 70, characteristics)?;
        }
        rebuild_debug_file_pointers(&mut out, &layout, new_num_sections)?;

        write_u32(&mut out, layout.opt + 64, 0)?;

        Ok(out)
    }

    fn optional_header_offset(&self) -> usize {
        read_u32(&self.bytes, 0x3c)
            .map(|e| e as usize + 4 + 20)
            .unwrap_or(0)
    }

    fn header_layout(&self) -> anyhow::Result<HeaderLayout> {
        let e_lfanew = read_u32(&self.bytes, 0x3c)? as usize;
        let coff = e_lfanew + 4;
        let num_sections = read_u16(&self.bytes, coff + 2)? as usize;
        let size_of_optional = read_u16(&self.bytes, coff + 16)? as usize;
        let opt = coff + 20;
        Ok(HeaderLayout {
            coff,
            opt,
            section_table: opt + size_of_optional,
            num_sections,
            size_of_headers: read_u32(&self.bytes, opt + 60)?,
            file_alignment: read_u32(&self.bytes, opt + 36)?,
            section_alignment: read_u32(&self.bytes, opt + 32)?,
            num_dirs: read_u32(&self.bytes, opt + 108)? as usize,
        })
    }

    pub(super) fn patch_offset(&self, rva: u32, len: usize) -> anyhow::Result<usize> {
        for s in &self.sections {
            if rva >= s.rva && rva < s.rva.saturating_add(s.raw_size) {
                let delta = (rva - s.rva) as usize;
                let offset = (s.raw_pointer as usize)
                    .checked_add(delta)
                    .context("patch target out of section bounds")?;
                let section_raw_end = (s.raw_pointer as usize)
                    .checked_add(s.raw_size as usize)
                    .context("patch target out of section bounds")?;
                let end = offset
                    .checked_add(len)
                    .context("patch target out of section bounds")?;
                if end > section_raw_end || end > self.bytes.len() {
                    anyhow::bail!("patch target out of section bounds");
                }
                return Ok(offset);
            }
        }
        anyhow::bail!("patch target out of section bounds");
    }
}

fn rebuild_debug_file_pointers(
    bytes: &mut [u8],
    layout: &HeaderLayout,
    section_count: usize,
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
    anyhow::ensure!(
        rva != 0 && size % 28 == 0,
        "invalid rebuilt debug directory"
    );
    let offset = final_file_offset(bytes, layout, section_count, rva, size)?;
    for record in (offset..offset + size as usize).step_by(28) {
        let payload = read_u32(bytes, record + 20)?;
        if payload == 0 {
            continue;
        }
        let length = read_u32(bytes, record + 16)?;
        let file = final_file_offset(bytes, layout, section_count, payload, length)?;
        write_u32(
            bytes,
            record + 24,
            u32::try_from(file).context("debug file offset overflow")?,
        )?;
    }
    Ok(())
}

fn final_file_offset(
    bytes: &[u8],
    layout: &HeaderLayout,
    section_count: usize,
    rva: u32,
    length: u32,
) -> anyhow::Result<usize> {
    for index in 0..section_count {
        let header = layout.section_table + index * SECTION_HEADER_SIZE;
        let begin = read_u32(bytes, header + 12)?;
        let raw_size = read_u32(bytes, header + 16)?;
        let file = read_u32(bytes, header + 20)?;
        let Some(delta) = rva.checked_sub(begin).filter(|delta| *delta < raw_size) else {
            continue;
        };
        anyhow::ensure!(
            u64::from(delta) + u64::from(length) <= u64::from(raw_size),
            "debug payload exceeds section raw data"
        );
        let offset = (file as usize)
            .checked_add(delta as usize)
            .context("debug file offset overflow")?;
        anyhow::ensure!(
            offset
                .checked_add(length as usize)
                .is_some_and(|end| end <= bytes.len()),
            "debug payload is not file-backed"
        );
        return Ok(offset);
    }
    anyhow::bail!("debug RVA {rva:#x} is not file-backed")
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

fn write_section_header(
    bytes: &mut [u8],
    offset: usize,
    section: &NewSection,
    raw_pointer: u32,
    raw_size: u32,
    virtual_size: u32,
) -> anyhow::Result<()> {
    let header = bytes
        .get_mut(offset..offset + SECTION_HEADER_SIZE)
        .context("no room in header for new section")?;
    header.fill(0);

    let name = section.name.as_bytes();
    let name_len = name.len().min(8);
    header[..name_len].copy_from_slice(&name[..name_len]);

    header[8..12].copy_from_slice(&virtual_size.to_le_bytes());
    header[12..16].copy_from_slice(&section.rva.get().to_le_bytes());
    header[16..20].copy_from_slice(&raw_size.to_le_bytes());
    header[20..24].copy_from_slice(&raw_pointer.to_le_bytes());
    header[36..40].copy_from_slice(&characteristics_from_flags(section.flags).to_le_bytes());
    Ok(())
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
    use crate::SectionRecord;

    fn section(rva: u32, virtual_size: u32) -> SectionRecord {
        SectionRecord {
            name: "s".to_string(),
            rva,
            virtual_size,
            raw_size: virtual_size,
            raw_pointer: 0x400,
            characteristics: 0,
        }
    }

    fn pe_with(sections: Vec<SectionRecord>, bytes: Vec<u8>) -> PeFile {
        PeFile {
            bytes,
            image_base: 0x1_4000_0000,
            entry_point: 0,
            sections,
            data_directories: Vec::new(),
            relocations: Vec::new(),
            pdata_begins: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
        }
    }

    #[test]
    fn align_rounds_up() {
        assert_eq!(align(0, 0x200), 0);
        assert_eq!(align(1, 0x200), 0x200);
        assert_eq!(align(0x200, 0x200), 0x200);
        assert_eq!(align(0x201, 0x200), 0x400);
        assert_eq!(align(0x1234, 0x1000), 0x2000);
    }

    #[test]
    fn align_zero_alignment_is_identity() {
        assert_eq!(align(0x1234, 0), 0x1234);
    }

    #[test]
    fn next_section_rva_follows_last_section() {
        let pe = pe_with(
            vec![section(0x1000, 0x400), section(0x2000, 0x1800)],
            section_alignment_image(0x1000),
        );
        assert_eq!(pe.next_section_rva(), Rva::new(0x4000));
    }

    #[test]
    fn characteristics_execute_sets_code() {
        let flags = SectionFlags {
            read: true,
            write: false,
            execute: true,
        };
        assert_eq!(
            characteristics_from_flags(flags),
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE
        );
    }

    #[test]
    fn characteristics_data_sets_initialized_data() {
        let flags = SectionFlags {
            read: true,
            write: true,
            execute: false,
        };
        assert_eq!(
            characteristics_from_flags(flags),
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA
        );
    }

    // Minimal PE32+ header carrying only the fields the pure helpers read:
    // e_lfanew, COFF, the optional header magic and SectionAlignment.
    fn section_alignment_image(section_alignment: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..2].copy_from_slice(b"MZ");
        let e_lfanew: u32 = 0x80;
        bytes[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let coff = e_lfanew as usize + 4;
        bytes[coff - 4..coff].copy_from_slice(b"PE\0\0");
        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[opt + 32..opt + 36].copy_from_slice(&section_alignment.to_le_bytes());
        bytes
    }
}
