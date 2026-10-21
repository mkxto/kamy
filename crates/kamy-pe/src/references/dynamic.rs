use anyhow::{Context, bail, ensure};
use kamy_core::ReferenceKind;

use super::Collector;
use crate::{read_u16, read_u32, read_u64};

impl Collector<'_> {
    pub(super) fn dynamic_relocations(
        &mut self,
        load_config: u32,
        declared: u32,
        table_va: Option<u32>,
    ) -> anyhow::Result<()> {
        let section_table = if declared > 224 {
            ensure!(
                declared >= 232,
                "partial load configuration dynamic relocation locator"
            );
            let offset = read_u32(self.bytes(load_config + 224, 4)?, 0)?;
            let ordinal = read_u16(self.bytes(load_config + 228, 2)?, 0)?;
            if ordinal == 0 {
                ensure!(offset == 0, "dynamic relocation offset has no section");
                None
            } else {
                let section = self
                    .pe
                    .sections
                    .get(usize::from(ordinal) - 1)
                    .context("dynamic relocation section index is out of range")?;
                let available = section
                    .raw_size
                    .checked_sub(offset)
                    .context("dynamic relocation offset exceeds its section")?;
                ensure!(available >= 8, "truncated dynamic relocation table header");
                let table = section
                    .rva
                    .checked_add(offset)
                    .context("dynamic relocation section RVA overflow")?;
                Some((table, available))
            }
        } else {
            None
        };
        if let (Some(absolute), Some((relative, _))) = (table_va, section_table) {
            ensure!(
                absolute == relative,
                "conflicting dynamic relocation table locators"
            );
        }
        let Some(table) = table_va.or(section_table.map(|(table, _)| table)) else {
            return Ok(());
        };
        let header = self.bytes(table, 8)?;
        let version = read_u32(header, 0)?;
        let payload_size = read_u32(header, 4)?;
        // IMAGE_DYNAMIC_RELOCATION_TABLE.Size excludes its eight-byte header.
        let size = payload_size
            .checked_add(8)
            .context("dynamic relocation table size overflow")?;
        if let Some((_, available)) = section_table {
            ensure!(
                size <= available,
                "dynamic relocation table exceeds its locator section"
            );
        }
        self.bytes(table, size)?;
        ensure!(
            matches!(version, 1 | 2),
            "unsupported dynamic relocation table version {version}"
        );
        let end = table
            .checked_add(size)
            .context("dynamic relocation table RVA overflow")?;
        let mut record = table + 8;
        while record < end {
            let minimum_header = if version == 1 { 12 } else { 24 };
            ensure!(
                end - record >= minimum_header,
                "truncated dynamic relocation record header at {record:#x}"
            );
            let header = self.bytes(record, minimum_header)?;
            let (header_size, fixup_size, symbol) = if version == 1 {
                (12, read_u32(header, 8)?, read_u64(header, 0)?)
            } else {
                let header_size = read_u32(header, 0)?;
                ensure!(
                    header_size >= 24,
                    "invalid dynamic relocation V2 header size"
                );
                ensure!(
                    header_size == 24,
                    "unsupported dynamic relocation V2 extended header"
                );
                ensure!(
                    read_u32(header, 16)? == 0 && read_u32(header, 20)? == 0,
                    "unsupported dynamic relocation V2 symbol group or flags"
                );
                (header_size, read_u32(header, 4)?, read_u64(header, 8)?)
            };
            let record_size = header_size
                .checked_add(fixup_size)
                .context("dynamic relocation record size overflow")?;
            ensure!(
                record_size <= end - record,
                "truncated dynamic relocation record at {record:#x}"
            );
            let fixups = record + header_size;
            match symbol {
                7 => self.function_overrides(fixups, fixup_size)?,
                _ => bail!("unsupported x64 dynamic relocation symbol {symbol:#x} at {record:#x}"),
            }
            record += record_size;
        }
        Ok(())
    }

    fn function_overrides(&mut self, base: u32, size: u32) -> anyhow::Result<()> {
        ensure!(size >= 4, "truncated function override header");
        let functions_size = read_u32(self.bytes(base, 4)?, 0)?;
        ensure!(
            functions_size <= size - 4,
            "function override records exceed their dynamic relocation payload"
        );
        let functions = base
            .checked_add(4)
            .context("function override RVA overflow")?;
        let bdd = functions
            .checked_add(functions_size)
            .context("function override region overflow")?;
        let end = base
            .checked_add(size)
            .context("function override payload overflow")?;
        let mut bdd_offsets = Vec::new();
        let mut info = bdd;
        while info < end {
            ensure!(end - info >= 8, "truncated function override BDD header");
            let header = self.bytes(info, 8)?;
            let version = read_u32(header, 0)?;
            ensure!(
                version == 1,
                "unsupported function override BDD version {version}"
            );
            let nodes_size = read_u32(header, 4)?;
            ensure!(nodes_size % 8 == 0, "partial function override BDD node");
            let info_size = nodes_size
                .checked_add(8)
                .context("function override BDD size overflow")?;
            ensure!(
                info_size <= end - info,
                "truncated function override BDD nodes"
            );
            // BDD edges and values are selectors, not RVAs; all alternatives are pinned.
            self.bytes(info, info_size)?;
            bdd_offsets.push(info - bdd);
            info += info_size;
        }
        let mut function = functions;
        while function < bdd {
            ensure!(bdd - function >= 16, "truncated function override record");
            let header = self.bytes(function, 16)?;
            let original = read_u32(header, 0)?;
            let bdd_offset = read_u32(header, 4)?;
            let rvas_size = read_u32(header, 8)?;
            let relocs_size = read_u32(header, 12)?;
            ensure!(
                bdd_offsets.binary_search(&bdd_offset).is_ok(),
                "function override BDD offset does not identify a BDD header"
            );
            ensure!(rvas_size % 4 == 0, "partial overriding function RVA");
            let record_size = 16_u32
                .checked_add(rvas_size)
                .and_then(|size| size.checked_add(relocs_size))
                .context("function override record size overflow")?;
            ensure!(
                record_size <= bdd - function,
                "truncated function override record payload"
            );
            ensure!(original != 0, "null original function override RVA");
            self.add(function, original, ReferenceKind::Opaque, false)?;
            let rvas = function + 16;
            for index in 0..rvas_size / 4 {
                let source = rvas + index * 4;
                let target = read_u32(self.bytes(source, 4)?, 0)?;
                ensure!(target != 0, "null overriding function RVA");
                self.add(source, target, ReferenceKind::Opaque, false)?;
            }
            self.function_override_relocations(rvas + rvas_size, relocs_size)?;
            function += record_size;
        }
        Ok(())
    }

    fn function_override_relocations(&mut self, base: u32, size: u32) -> anyhow::Result<()> {
        let end = base
            .checked_add(size)
            .context("function override relocation region overflow")?;
        let mut block = base;
        while block < end {
            ensure!(
                end - block >= 8,
                "truncated function override relocation block"
            );
            let header = self.bytes(block, 8)?;
            let page = read_u32(header, 0)?;
            let block_size = read_u32(header, 4)?;
            ensure!(
                page & 0xfff == 0,
                "unaligned function override relocation page"
            );
            ensure!(
                block_size >= 8 && block_size % 4 == 0 && block_size <= end - block,
                "invalid function override relocation block size"
            );
            for offset in (8..block_size).step_by(2) {
                let source = block + offset;
                let entry = read_u16(self.bytes(source, 2)?, 0)?;
                if entry == 0 {
                    continue;
                }
                let kind = entry >> 12;
                ensure!(
                    kind == 1,
                    "unsupported x64 function override relocation type {kind} at {source:#x}"
                );
                let site = page
                    .checked_add(u32::from(entry & 0xfff))
                    .context("function override patch RVA overflow")?;
                let displacement = read_u32(self.bytes(site, 4)?, 0)? as i32;
                let next = site
                    .checked_add(4)
                    .context("function override rel32 site overflow")?;
                let target = u32::try_from(i64::from(next) + i64::from(displacement))
                    .context("function override rel32 target overflow")?;
                ensure!(target != 0, "null function override rel32 target");
                self.add(source, site, ReferenceKind::Opaque, false)?;
                self.add(site, target, ReferenceKind::Opaque, false)?;
            }
            block += block_size;
        }
        Ok(())
    }
}
