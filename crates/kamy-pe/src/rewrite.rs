use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, ensure};
use kamy_core::{ReferenceKind, RelocKind, Relocation, Rva};

use crate::{BytePatch, DirectoryUpdate, PeFile, read_u16, read_u32, read_u64};

const CFG_SLOTS: [(u32, bool); 5] = [
    (112, false),
    (120, true),
    (280, false),
    (288, true),
    (296, true),
];
const CFG_TABLES: [(u32, u32); 4] = [(128, 136), (160, 168), (176, 184), (264, 272)];
const LOAD_CONFIG_VAS: [u32; 22] = [
    40, 80, 88, 96, 112, 120, 128, 160, 176, 192, 200, 208, 216, 232, 248, 256, 264, 280, 288, 296,
    304, 312,
];
const CFG_FLAGS: u32 = 0x0000_0400 | 0x0000_4000 | 0x0000_8000 | 0x0001_0000 | 0x0080_0000;

#[derive(Default)]
pub struct ReferenceEdits {
    pub patches: Vec<BytePatch>,
    /// Replaces the original loader fixups; null CFG table fields have no fixup.
    pub relocations: Vec<Relocation>,
    pub entry_point: Option<Rva>,
}

impl PeFile {
    /// Rewrites verified function entries. Active CFG also requires `cfg_edits`.
    pub fn rebase_references(
        &self,
        addresses: &BTreeMap<Rva, Rva>,
    ) -> anyhow::Result<ReferenceEdits> {
        let references = self.metadata_references()?;
        let mut edits = PatchSet::new(self);
        let mut relocations = BTreeMap::new();
        let mut reserved = BTreeSet::new();
        let mut cleared = BTreeSet::new();
        let config = self.rewrite_load_config()?;
        let dynamic_range = config
            .map(|(base, size)| self.dynamic_rewrite_range(base, size))
            .transpose()?
            .flatten();
        let cfg = self.has_cfg();
        if let Some((base, size)) = config {
            if size >= 96 {
                let cookie = base + 88;
                self.require_resident_va(cookie, addresses)?;
                reserved.insert(cookie);
            }
            if cfg {
                for (offset, _) in CFG_SLOTS {
                    if size >= offset + 8 {
                        let field = base + offset;
                        reserved.insert(field);
                        if let Some(slot) =
                            self.image_rva(read_u64(self.rewrite_bytes(field, 8)?, 0)?)
                        {
                            reserved.insert(slot);
                        }
                    }
                }
                for (pointer, count) in CFG_TABLES {
                    if size >= count + 8 {
                        cleared.insert(base + pointer);
                        reserved.insert(base + pointer);
                        reserved.insert(base + count);
                    }
                }
            }
            for offset in [192, 248, 256] {
                if size >= offset + 8 {
                    self.require_resident_va(base + offset, addresses)?;
                    reserved.insert(base + offset);
                }
            }
            self.rebase_load_config_tables(base, size, addresses, &mut reserved, &mut edits)?;
        }
        let pogo_fields = self.pogo_fields()?;
        for reference in &references {
            if reference.kind == ReferenceKind::Opaque {
                ensure!(
                    addresses
                        .get(&reference.target)
                        .is_none_or(|target| *target == reference.target),
                    "opaque metadata target {} must remain resident",
                    reference.target
                );
            }
        }
        for relocation in &self.relocations {
            if relocation.kind == RelocKind::Absolute || cleared.contains(&relocation.rva.get()) {
                continue;
            }
            add_relocation(&mut relocations, *relocation)?;
            if relocation.kind != RelocKind::Dir64
                || reserved.contains(&relocation.rva.get())
                || dynamic_range.is_some_and(|(begin, end)| {
                    u64::from(relocation.rva.get()) < u64::from(end)
                        && u64::from(relocation.rva.get()) + 8 > u64::from(begin)
                })
            {
                continue;
            }
            self.rebase_va(
                relocation.rva.get(),
                addresses,
                &mut edits,
                &mut relocations,
            )?;
        }
        for reference in references {
            let source = reference.source.get();
            if reserved.contains(&source) || pogo_fields.contains(&source) {
                continue;
            }
            match reference.kind {
                ReferenceKind::Absolute => {
                    self.rebase_va(source, addresses, &mut edits, &mut relocations)?;
                }
                ReferenceKind::ImageRelative => {
                    if let Some(target) = addresses.get(&reference.target) {
                        edits.add(source, target.get().to_le_bytes().to_vec())?;
                    }
                }
                _ => {}
            }
        }
        Ok(ReferenceEdits {
            patches: edits.finish(),
            relocations: relocations
                .into_iter()
                .map(|(rva, kind)| Relocation {
                    rva: Rva::new(rva),
                    kind,
                })
                .collect(),
            entry_point: addresses
                .get(&Rva::new(self.entry_point))
                .copied()
                .filter(|rva| rva.get() != self.entry_point),
        })
    }

    pub fn has_cfg(&self) -> bool {
        if read_u32(&self.bytes, 0x3c)
            .ok()
            .and_then(|pe| read_u16(&self.bytes, pe as usize + 24 + 70).ok())
            .is_some_and(|flags| flags & 0x4000 != 0)
        {
            return true;
        }
        let Ok(config) = self.rewrite_load_config() else {
            return true;
        };
        let Some((base, size)) = config else {
            return false;
        };
        if size >= 148
            && self
                .u32_at_rva(base + 144)
                .is_some_and(|flags| flags & (CFG_FLAGS | 0x300) != 0)
        {
            return true;
        }
        CFG_SLOTS.iter().any(|&(offset, _)| {
            size >= offset + 8
                && self
                    .u64_at_rva(base + offset)
                    .is_some_and(|value| value != 0)
        })
    }

    pub fn has_cfg_check(&self) -> bool {
        let Ok(Some((base, size))) = self.rewrite_load_config() else {
            return false;
        };
        CFG_SLOTS.iter().any(|&(offset, dispatch)| {
            !dispatch
                && size >= offset + 8
                && self.u64_at_rva(base + offset).is_some_and(|slot| slot != 0)
        })
    }

    /// Patches CF/XFG indirection slots, not their load-config addresses.
    /// The returned fixups augment `ReferenceEdits::relocations`.
    pub fn cfg_edits(
        &self,
        check: Rva,
        dispatch: Rva,
    ) -> anyhow::Result<(Vec<BytePatch>, Vec<Relocation>)> {
        let mut edits = PatchSet::new(self);
        let mut relocations = BTreeMap::new();
        let Some((base, size)) = self.rewrite_load_config()? else {
            ensure!(
                !self.has_cfg(),
                "CFG image has no load configuration dispatch slot"
            );
            return Ok((Vec::new(), Vec::new()));
        };
        if !self.has_cfg() {
            return Ok((Vec::new(), Vec::new()));
        }
        ensure!(
            CFG_SLOTS.iter().any(|&(offset, dispatch)| {
                dispatch
                    && size >= offset + 8
                    && self.u64_at_rva(base + offset).is_some_and(|slot| slot != 0)
            }),
            "CFG image has no dispatch pointer slot for target translation"
        );
        for (offset, is_dispatch) in CFG_SLOTS {
            if size <= offset {
                continue;
            }
            ensure!(size >= offset + 8, "partial CFG pointer field");
            let pointer = read_u64(self.rewrite_bytes(base + offset, 8)?, 0)?;
            if pointer == 0 {
                continue;
            }
            let slot = self
                .image_rva(pointer)
                .context("external CFG pointer slot")?;
            let target = if is_dispatch { dispatch } else { check };
            ensure!(target != Rva::ZERO, "CFG helper RVA is zero");
            let va = self
                .image_base
                .checked_add(u64::from(target.get()))
                .context("CFG helper VA overflow")?;
            edits.add(slot, va.to_le_bytes().to_vec())?;
            add_relocation(
                &mut relocations,
                Relocation {
                    rva: Rva::new(slot),
                    kind: RelocKind::Dir64,
                },
            )?;
            add_relocation(
                &mut relocations,
                Relocation {
                    rva: Rva::new(base + offset),
                    kind: RelocKind::Dir64,
                },
            )?;
        }
        for (pointer, count) in CFG_TABLES {
            if size <= pointer {
                continue;
            }
            ensure!(size >= count + 8, "partial CFG table/count fields");
            edits.add(base + pointer, 0u64.to_le_bytes().to_vec())?;
            edits.add(base + count, 0u64.to_le_bytes().to_vec())?;
        }
        if size > 144 {
            ensure!(size >= 148, "partial GuardFlags field");
            let flags = read_u32(self.rewrite_bytes(base + 144, 4)?, 0)?;
            edits.add(base + 144, (flags & 0x100).to_le_bytes().to_vec())?;
        }
        Ok((
            edits.finish(),
            relocations
                .into_iter()
                .map(|(rva, kind)| Relocation {
                    rva: Rva::new(rva),
                    kind,
                })
                .collect(),
        ))
    }

    /// Preserves materialized POGO contributions and adds moved function ranges.
    /// Payload file pointers are resolved by `rebuild` after section placement.
    pub fn rebuild_debug_directory(
        &self,
        moves: &[(Rva, Rva, u32)],
        section_rva: Rva,
    ) -> anyhow::Result<Option<(Vec<u8>, DirectoryUpdate)>> {
        self.metadata_references()?;
        let Some(&(base, size)) = self.data_directories.get(6).filter(|&&(base, _)| base != 0)
        else {
            return Ok(None);
        };
        let mut blob = self.rewrite_bytes(base, size)?.to_vec();
        let mut sorted_moves = moves.to_vec();
        sorted_moves.sort_unstable();
        for &(old, new, length) in &sorted_moves {
            ensure!(
                length != 0 && new.get().checked_add(length).is_some(),
                "invalid moved debug range for {old}"
            );
        }
        for offset in (0..size as usize).step_by(28) {
            let length = read_u32(&blob, offset + 16)? as usize;
            let file = read_u32(&blob, offset + 24)? as usize;
            let end = file
                .checked_add(length)
                .context("debug payload file range overflow")?;
            let data = self
                .bytes
                .get(file..end)
                .context("debug payload is not file-backed")?;
            let mut payload = data.to_vec();
            if read_u32(&blob, offset + 12)? == 13 {
                let mut cursor = 4usize;
                while cursor < data.len() {
                    let begin = read_u32(data, cursor)?;
                    let end = begin
                        .checked_add(read_u32(data, cursor + 4)?)
                        .context("POGO contribution range overflow")?;
                    let tail = data
                        .get(cursor + 8..)
                        .context("truncated POGO contribution name")?;
                    let length = tail
                        .iter()
                        .position(|byte| *byte == 0)
                        .context("unterminated POGO contribution name")?
                        + 1;
                    let name = &tail[..length];
                    for &(old, new, new_length) in &sorted_moves {
                        if (begin..end).contains(&old.get()) && old != new {
                            payload.extend_from_slice(&new.get().to_le_bytes());
                            payload.extend_from_slice(&new_length.to_le_bytes());
                            payload.extend_from_slice(name);
                            while payload.len() % 4 != 0 {
                                payload.push(0);
                            }
                        }
                    }
                    cursor = (cursor + 8 + length + 3) & !3;
                }
            }
            while blob.len() % 4 != 0 {
                blob.push(0);
            }
            let payload_offset = u32::try_from(blob.len()).context("debug blob offset overflow")?;
            let payload_rva = section_rva
                .get()
                .checked_add(payload_offset)
                .context("debug payload RVA overflow")?;
            let payload_size =
                u32::try_from(payload.len()).context("debug payload size overflow")?;
            payload_rva
                .checked_add(payload_size)
                .context("debug payload range overflow")?;
            blob[offset + 16..offset + 20].copy_from_slice(&payload_size.to_le_bytes());
            blob[offset + 20..offset + 24].copy_from_slice(&payload_rva.to_le_bytes());
            blob[offset + 24..offset + 28].fill(0);
            blob.extend_from_slice(&payload);
        }
        Ok(Some((
            blob,
            DirectoryUpdate {
                index: 6,
                rva: section_rva,
                size,
            },
        )))
    }

    fn rewrite_bytes(&self, rva: u32, size: u32) -> anyhow::Result<&[u8]> {
        rva.checked_add(size)
            .context("reference field RVA overflow")?;
        self.slice_at_rva(rva)
            .and_then(|bytes| bytes.get(..size as usize))
            .with_context(|| format!("reference field {rva:#x}+{size:#x} is not file-backed"))
    }

    fn rewrite_load_config(&self) -> anyhow::Result<Option<(u32, u32)>> {
        let (base, directory_size) = self.data_directories.get(10).copied().unwrap_or_default();
        if base == 0 && directory_size == 0 {
            return Ok(None);
        }
        ensure!(
            base != 0 && directory_size >= 4,
            "invalid load configuration directory"
        );
        self.rewrite_bytes(base, directory_size)?;
        let size = read_u32(self.rewrite_bytes(base, 4)?, 0)?;
        ensure!(
            size >= 4 && size <= directory_size,
            "invalid load configuration size"
        );
        for offset in LOAD_CONFIG_VAS {
            ensure!(
                size <= offset || size >= offset + 8,
                "partial load configuration VA field"
            );
        }
        Ok(Some((base, size)))
    }

    fn dynamic_rewrite_range(&self, base: u32, size: u32) -> anyhow::Result<Option<(u32, u32)>> {
        let absolute = if size >= 200 {
            self.image_rva(read_u64(self.rewrite_bytes(base + 192, 8)?, 0)?)
        } else {
            None
        };
        let relative = if size >= 232 {
            let ordinal = read_u16(self.rewrite_bytes(base + 228, 2)?, 0)?;
            if ordinal != 0 {
                let section = self
                    .sections
                    .get(usize::from(ordinal) - 1)
                    .context("dynamic relocation section out of range")?;
                Some(
                    section
                        .rva
                        .checked_add(read_u32(self.rewrite_bytes(base + 224, 4)?, 0)?)
                        .context("dynamic relocation RVA overflow")?,
                )
            } else {
                None
            }
        } else {
            None
        };
        let Some(begin) = absolute.or(relative) else {
            return Ok(None);
        };
        let payload_size = read_u32(self.rewrite_bytes(begin, 8)?, 4)?;
        let end = begin
            .checked_add(8)
            .and_then(|begin| begin.checked_add(payload_size))
            .context("dynamic relocation range overflow")?;
        Ok(Some((begin, end)))
    }

    fn image_rva(&self, va: u64) -> Option<u32> {
        va.checked_sub(self.image_base)
            .and_then(|rva| u32::try_from(rva).ok())
    }

    fn require_resident_va(
        &self,
        source: u32,
        addresses: &BTreeMap<Rva, Rva>,
    ) -> anyhow::Result<()> {
        if let Some(rva) = self.image_rva(read_u64(self.rewrite_bytes(source, 8)?, 0)?) {
            ensure!(
                addresses
                    .get(&Rva::new(rva))
                    .is_none_or(|target| target.get() == rva),
                "load configuration data target {rva:#x} must remain resident"
            );
        }
        Ok(())
    }

    fn rebase_va(
        &self,
        source: u32,
        addresses: &BTreeMap<Rva, Rva>,
        edits: &mut PatchSet<'_>,
        relocations: &mut BTreeMap<u32, RelocKind>,
    ) -> anyhow::Result<()> {
        let value = read_u64(self.rewrite_bytes(source, 8)?, 0)?;
        let Some(target) = self
            .image_rva(value)
            .and_then(|rva| addresses.get(&Rva::new(rva)))
        else {
            return Ok(());
        };
        let rebased = self
            .image_base
            .checked_add(u64::from(target.get()))
            .context("rebased pointer VA overflow")?;
        edits.add(source, rebased.to_le_bytes().to_vec())?;
        add_relocation(
            relocations,
            Relocation {
                rva: Rva::new(source),
                kind: RelocKind::Dir64,
            },
        )
    }

    fn rebase_load_config_tables(
        &self,
        base: u32,
        size: u32,
        addresses: &BTreeMap<Rva, Rva>,
        reserved: &mut BTreeSet<u32>,
        edits: &mut PatchSet<'_>,
    ) -> anyhow::Result<()> {
        let flags = if size >= 148 {
            read_u32(self.rewrite_bytes(base + 144, 4)?, 0)?
        } else {
            0
        };
        for (offset, count_offset, stride) in [
            (96, 104, 4),
            (128, 136, 4 + (flags >> 28)),
            (160, 168, 4 + (flags >> 28)),
            (176, 184, 4 + (flags >> 28)),
            (264, 272, 4 + (flags >> 28)),
        ] {
            if size <= offset {
                continue;
            }
            ensure!(
                size >= count_offset + 8,
                "partial load configuration table/count fields"
            );
            let pointer = read_u64(self.rewrite_bytes(base + offset, 8)?, 0)?;
            let count = read_u64(self.rewrite_bytes(base + count_offset, 8)?, 0)?;
            ensure!(
                (pointer == 0) == (count == 0),
                "inconsistent load configuration table/count"
            );
            if count == 0 {
                continue;
            }
            let table = self
                .image_rva(pointer)
                .context("external load configuration table")?;
            let length = u32::try_from(count)
                .ok()
                .and_then(|count| count.checked_mul(stride))
                .context("load configuration table overflow")?;
            let data = self.rewrite_bytes(table, length)?;
            let mut records = Vec::with_capacity(count as usize);
            let mut changed = false;
            for (index, record) in data.chunks_exact(stride as usize).enumerate() {
                reserved.insert(table + index as u32 * stride);
                let original = read_u32(record, 0)?;
                let target = addresses
                    .get(&Rva::new(original))
                    .map_or(original, |rva| rva.get());
                changed |= target != original;
                records.push((target, record));
            }
            if !changed {
                continue;
            }
            records.sort_by_key(|&(target, _)| target);
            let mut rewritten = Vec::with_capacity(data.len());
            for (target, record) in records {
                rewritten.extend_from_slice(&target.to_le_bytes());
                rewritten.extend_from_slice(&record[4..]);
            }
            edits.add(table, rewritten)?;
        }
        Ok(())
    }

    fn pogo_fields(&self) -> anyhow::Result<BTreeSet<u32>> {
        let mut fields = BTreeSet::new();
        let Some(&(base, size)) = self.data_directories.get(6).filter(|&&(base, _)| base != 0)
        else {
            return Ok(fields);
        };
        for offset in (0..size).step_by(28) {
            let entry = self.rewrite_bytes(base + offset, 28)?;
            if read_u32(entry, 12)? != 13 {
                continue;
            }
            let length = read_u32(entry, 16)?;
            let payload = read_u32(entry, 20)?;
            let data = self.rewrite_bytes(payload, length)?;
            let mut cursor = 4usize;
            while cursor < data.len() {
                fields.insert(payload + cursor as u32);
                let name = data.get(cursor + 8..).context("truncated POGO name")?;
                let length = name
                    .iter()
                    .position(|byte| *byte == 0)
                    .context("unterminated POGO name")?
                    + 1;
                cursor = (cursor + 8 + length + 3) & !3;
            }
        }
        Ok(fields)
    }
}

fn add_relocation(
    relocations: &mut BTreeMap<u32, RelocKind>,
    relocation: Relocation,
) -> anyhow::Result<()> {
    if let Some(previous) = relocations.insert(relocation.rva.get(), relocation.kind) {
        ensure!(
            previous == relocation.kind,
            "conflicting relocation kinds for {}",
            relocation.rva
        );
    }
    Ok(())
}

struct PatchSet<'a> {
    pe: &'a PeFile,
    patches: BTreeMap<u32, Vec<u8>>,
}

impl<'a> PatchSet<'a> {
    fn new(pe: &'a PeFile) -> Self {
        Self {
            pe,
            patches: BTreeMap::new(),
        }
    }

    fn add(&mut self, rva: u32, bytes: Vec<u8>) -> anyhow::Result<()> {
        let offset = self.pe.patch_offset(rva, bytes.len())?;
        if self.pe.bytes[offset..offset + bytes.len()] == bytes {
            return Ok(());
        }
        if let Some(existing) = self.patches.get(&rva) {
            ensure!(
                *existing == bytes,
                "conflicting reference patches at {rva:#x}"
            );
            return Ok(());
        }
        let end = u64::from(rva) + bytes.len() as u64;
        if let Some((&previous, data)) = self.patches.range(..rva).next_back() {
            ensure!(
                u64::from(previous) + data.len() as u64 <= u64::from(rva),
                "overlapping reference patches"
            );
        }
        if let Some((&next, _)) = self.patches.range(rva..).next() {
            ensure!(end <= u64::from(next), "overlapping reference patches");
        }
        self.patches.insert(rva, bytes);
        Ok(())
    }

    fn finish(self) -> Vec<BytePatch> {
        self.patches
            .into_iter()
            .map(|(rva, bytes)| BytePatch {
                rva: Rva::new(rva),
                bytes,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NewSection, PeEdits};
    use kamy_core::SectionFlags;

    const IMAGE_BASE: u64 = 0x7ff6_0000_0000;
    const OPT: usize = 0x98;

    fn fixture() -> PeFile {
        let mut bytes = vec![0; 0x2400];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x2022u16.to_le_bytes());
        bytes[OPT..OPT + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[OPT + 16..OPT + 20].copy_from_slice(&0x1100u32.to_le_bytes());
        bytes[OPT + 24..OPT + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
        for (offset, value) in [
            (32, 0x1000u32),
            (36, 0x200),
            (56, 0x3000),
            (60, 0x400),
            (108, 16),
        ] {
            bytes[OPT + offset..OPT + offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[OPT + 70..OPT + 72].copy_from_slice(&0x4160u16.to_le_bytes());
        let section = OPT + 0xf0;
        bytes[section..section + 5].copy_from_slice(b".text");
        for (offset, value) in [
            (8, 0x2000u32),
            (12, 0x1000),
            (16, 0x2000),
            (20, 0x400),
            (36, 0x6000_0020),
        ] {
            bytes[section + offset..section + offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        PeFile::parse(&bytes).unwrap()
    }

    fn directory(pe: &mut PeFile, index: usize, rva: u32, size: u32) {
        pe.data_directories[index] = (rva, size);
        let offset = OPT + 112 + index * 8;
        pe.bytes[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
        pe.bytes[offset + 4..offset + 8].copy_from_slice(&size.to_le_bytes());
    }

    fn put32(pe: &mut PeFile, rva: u32, value: u32) {
        let offset = pe.patch_offset(rva, 4).unwrap();
        pe.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(pe: &mut PeFile, rva: u32, value: u64) {
        let offset = pe.patch_offset(rva, 8).unwrap();
        pe.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn apply(pe: &mut PeFile, patches: &[BytePatch]) {
        for patch in patches {
            let offset = pe.patch_offset(patch.rva.get(), patch.bytes.len()).unwrap();
            pe.bytes[offset..offset + patch.bytes.len()].copy_from_slice(&patch.bytes);
        }
    }

    fn moved(pairs: &[(u32, u32)]) -> BTreeMap<Rva, Rva> {
        pairs
            .iter()
            .map(|&(old, new)| (Rva::new(old), Rva::new(new)))
            .collect()
    }

    #[test]
    fn absolute_ordinal_exports_forwarders_and_tls_share_final_map() {
        let mut pe = fixture();
        directory(&mut pe, 0, 0x1700, 0x100);
        put32(&mut pe, 0x1714, 4);
        put32(&mut pe, 0x171c, 0x1740);
        for (field, target) in [
            (0x1740, 0x1100),
            (0x1744, 0),
            (0x1748, 0x1180),
            (0x174c, 0x1780),
        ] {
            put32(&mut pe, field, target);
        }
        let forwarder = pe.patch_offset(0x1780, 9).unwrap();
        pe.bytes[forwarder..forwarder + 9].copy_from_slice(b"other.#7\0");
        directory(&mut pe, 9, 0x1400, 40);
        put64(&mut pe, 0x1418, IMAGE_BASE + 0x1600);
        put64(&mut pe, 0x1600, IMAGE_BASE + 0x1100);
        put64(&mut pe, 0x1608, IMAGE_BASE + 0x1180);
        put64(&mut pe, 0x1300, IMAGE_BASE + 0x1100);
        put64(&mut pe, 0x1308, 0x1234);
        pe.relocations = vec![
            Relocation {
                rva: Rva::new(0x1300),
                kind: RelocKind::Dir64,
            },
            Relocation {
                rva: Rva::new(0x1308),
                kind: RelocKind::Dir64,
            },
            Relocation {
                rva: Rva::new(0x1600),
                kind: RelocKind::Dir64,
            },
        ];
        let edits = pe
            .rebase_references(&moved(&[
                (0x1100, 0x4000),
                (0x1180, 0x4100),
                (0x1780, 0x4200),
            ]))
            .unwrap();
        assert_eq!(edits.entry_point, Some(Rva::new(0x4000)));
        assert!(
            edits
                .patches
                .windows(2)
                .all(|pair| pair[0].rva < pair[1].rva)
        );
        apply(&mut pe, &edits.patches);
        assert_eq!(pe.u64_at_rva(0x1300), Some(IMAGE_BASE + 0x4000));
        assert_eq!(pe.u64_at_rva(0x1308), Some(0x1234));
        assert_eq!(pe.u64_at_rva(0x1600), Some(IMAGE_BASE + 0x4000));
        assert_eq!(pe.u64_at_rva(0x1608), Some(IMAGE_BASE + 0x4100));
        assert_eq!(pe.u32_at_rva(0x1740), Some(0x4000));
        assert_eq!(pe.u32_at_rva(0x1744), Some(0));
        assert_eq!(pe.u32_at_rva(0x1748), Some(0x4100));
        assert_eq!(pe.u32_at_rva(0x174c), Some(0x1780));
        assert_eq!(
            edits
                .relocations
                .iter()
                .filter(|relocation| relocation.rva == Rva::new(0x1600))
                .count(),
            1
        );
        assert!(edits.relocations.contains(&Relocation {
            rva: Rva::new(0x1608),
            kind: RelocKind::Dir64
        }));
        let delta = 0x230000u64;
        for field in [0x1300, 0x1600, 0x1608] {
            let target = pe.u64_at_rva(field).unwrap();
            assert_eq!(target + delta - (IMAGE_BASE + delta), target - IMAGE_BASE);
        }
    }

    #[test]
    fn cfg_changes_slots_preserves_cookie_unrelated_helpers_and_fixups() {
        let mut pe = fixture();
        directory(&mut pe, 10, 0x1200, 320);
        put32(&mut pe, 0x1200, 320);
        put64(&mut pe, 0x1258, IMAGE_BASE + 0x1800);
        let flags = 0x1041_7500;
        put32(&mut pe, 0x1290, flags);
        for (index, (offset, _)) in CFG_SLOTS.into_iter().enumerate() {
            let slot = 0x1900 + index as u32 * 8;
            put64(&mut pe, 0x1200 + offset, IMAGE_BASE + u64::from(slot));
            put64(&mut pe, slot, IMAGE_BASE + 0x1100);
        }
        for offset in [208, 216, 232, 304, 312] {
            put64(&mut pe, 0x1200 + offset, IMAGE_BASE + 0x1980);
        }
        put64(&mut pe, 0x1980, IMAGE_BASE + 0x1180);
        for (index, (pointer, count)) in CFG_TABLES.into_iter().enumerate() {
            let table = 0x1a00 + index as u32 * 0x20;
            put64(&mut pe, 0x1200 + pointer, IMAGE_BASE + u64::from(table));
            put64(&mut pe, 0x1200 + count, 1);
            put32(&mut pe, table, 0x1100);
            pe.relocations.push(Relocation {
                rva: Rva::new(0x1200 + pointer),
                kind: RelocKind::Dir64,
            });
        }
        assert!(pe.has_cfg());
        let rebased = pe.rebase_references(&moved(&[(0x1100, 0x4000)])).unwrap();
        let (patches, fixups) = pe.cfg_edits(Rva::new(0x5000), Rva::new(0x5010)).unwrap();
        assert!(
            patches
                .iter()
                .all(|patch| rebased.patches.iter().all(|other| patch.rva != other.rva))
        );
        apply(&mut pe, &rebased.patches);
        apply(&mut pe, &patches);
        for (index, (offset, dispatch)) in CFG_SLOTS.into_iter().enumerate() {
            let slot = 0x1900 + index as u32 * 8;
            assert_eq!(
                pe.u64_at_rva(0x1200 + offset),
                Some(IMAGE_BASE + u64::from(slot))
            );
            assert_eq!(
                pe.u64_at_rva(slot),
                Some(IMAGE_BASE + if dispatch { 0x5010 } else { 0x5000 })
            );
            assert!(fixups.contains(&Relocation {
                rva: Rva::new(slot),
                kind: RelocKind::Dir64
            }));
            assert!(fixups.contains(&Relocation {
                rva: Rva::new(0x1200 + offset),
                kind: RelocKind::Dir64
            }));
        }
        for (pointer, count) in CFG_TABLES {
            assert_eq!(pe.u64_at_rva(0x1200 + pointer), Some(0));
            assert_eq!(pe.u64_at_rva(0x1200 + count), Some(0));
            assert!(
                !rebased
                    .relocations
                    .iter()
                    .chain(&fixups)
                    .any(|relocation| relocation.rva.get() == 0x1200 + pointer)
            );
        }
        assert_eq!(pe.u64_at_rva(0x1258), Some(IMAGE_BASE + 0x1800));
        assert_eq!(pe.u64_at_rva(0x1980), Some(IMAGE_BASE + 0x1180));
        assert_eq!(pe.u32_at_rva(0x1290), Some(0x100));
        for offset in [208, 216, 232, 304, 312] {
            assert_eq!(pe.u64_at_rva(0x1200 + offset), Some(IMAGE_BASE + 0x1980));
        }
        crate::encode_base_relocations(
            &rebased
                .relocations
                .into_iter()
                .chain(fixups)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    }

    #[test]
    fn sorted_guard_records_keep_per_entry_bytes() {
        let mut pe = fixture();
        directory(&mut pe, 10, 0x1200, 280);
        put32(&mut pe, 0x1200, 280);
        put32(&mut pe, 0x1290, 0x1000_0000);
        put64(&mut pe, 0x1308, IMAGE_BASE + 0x1a00);
        put64(&mut pe, 0x1310, 2);
        put32(&mut pe, 0x1a00, 0x1100);
        put32(&mut pe, 0x1a05, 0x1180);
        let offset = pe.patch_offset(0x1a00, 10).unwrap();
        pe.bytes[offset + 4] = 0x51;
        pe.bytes[offset + 9] = 0x62;
        let edits = pe
            .rebase_references(&moved(&[(0x1100, 0x4100), (0x1180, 0x4000)]))
            .unwrap();
        apply(&mut pe, &edits.patches);
        assert_eq!(pe.u32_at_rva(0x1a00), Some(0x4000));
        assert_eq!(pe.u32_at_rva(0x1a05), Some(0x4100));
        assert_eq!(pe.rewrite_bytes(0x1a04, 1).unwrap(), &[0x62]);
        assert_eq!(pe.rewrite_bytes(0x1a09, 1).unwrap(), &[0x51]);
    }

    #[test]
    fn active_section_relative_dvrt_is_preserved_and_opaque_targets_reject() {
        let mut pe = fixture();
        directory(&mut pe, 10, 0x1200, 320);
        put32(&mut pe, 0x1200, 320);
        put32(&mut pe, 0x12e0, 0xb00);
        let ordinal = pe.patch_offset(0x12e4, 2).unwrap();
        pe.bytes[ordinal..ordinal + 2].copy_from_slice(&1u16.to_le_bytes());
        put32(&mut pe, 0x1b00, 1);
        put32(&mut pe, 0x1b04, 44);
        put64(&mut pe, 0x1b08, 7);
        put32(&mut pe, 0x1b10, 32);
        put32(&mut pe, 0x1b14, 20);
        put32(&mut pe, 0x1b18, 0x1100);
        put32(&mut pe, 0x1b20, 4);
        put32(&mut pe, 0x1b28, 0x1180);
        put32(&mut pe, 0x1b2c, 1);
        let original = pe.rewrite_bytes(0x1b00, 52).unwrap().to_vec();
        let edits = pe.rebase_references(&moved(&[(0x11c0, 0x4000)])).unwrap();
        apply(&mut pe, &edits.patches);
        assert_eq!(pe.rewrite_bytes(0x1b00, 52).unwrap(), original);
        assert_eq!(pe.u32_at_rva(0x12e0), Some(0xb00));
        assert_eq!(pe.u16_at_rva(0x12e4), Some(1));
        assert!(pe.rebase_references(&moved(&[(0x1100, 0x4000)])).is_err());
        assert!(pe.rebase_references(&moved(&[(0x1180, 0x4100)])).is_err());
    }

    #[test]
    fn debug_rebuild_preserves_contributions_and_adds_moved_function_ranges() {
        let mut pe = fixture();
        directory(&mut pe, 6, 0x1500, 56);
        put32(&mut pe, 0x150c, 13);
        put32(&mut pe, 0x1510, 20);
        put32(&mut pe, 0x1514, 0x1600);
        let file = pe.patch_offset(0x1600, 20).unwrap() as u32;
        put32(&mut pe, 0x1518, file);
        put32(&mut pe, 0x1600, 0x5350_474f);
        put32(&mut pe, 0x1604, 0x1100);
        put32(&mut pe, 0x1608, 0x100);
        let name = pe.patch_offset(0x160c, 6).unwrap();
        pe.bytes[name..name + 6].copy_from_slice(b".text\0");
        put32(&mut pe, 0x1528, 2);
        put32(&mut pe, 0x152c, 29);
        put32(&mut pe, 0x1530, 0x1700);
        let file = pe.patch_offset(0x1700, 29).unwrap() as u32;
        put32(&mut pe, 0x1534, file);
        let codeview = pe.patch_offset(0x1700, 29).unwrap();
        pe.bytes[codeview..codeview + 4].copy_from_slice(b"RSDS");
        pe.bytes[codeview + 24..codeview + 29].copy_from_slice(b"x.pdb");
        pe.bytes[codeview + 28] = 0;
        let refs = pe
            .rebase_references(&moved(&[(0x1100, 0x4000), (0x1180, 0x4100)]))
            .unwrap();
        assert!(!refs.patches.iter().any(|patch| patch.rva.get() == 0x1604));
        let (blob, update) = pe
            .rebuild_debug_directory(
                &[
                    (Rva::new(0x1180), Rva::new(0x4100), 0x28),
                    (Rva::new(0x1100), Rva::new(0x4000), 0x30),
                ],
                Rva::new(0x3000),
            )
            .unwrap()
            .unwrap();
        assert_eq!(read_u32(&blob, 24).unwrap(), 0);
        let pogo = (read_u32(&blob, 20).unwrap() - 0x3000) as usize;
        assert_eq!(read_u32(&blob, pogo).unwrap(), 0x5350_474f);
        for (offset, begin, length) in [(4, 0x1100, 0x100), (20, 0x4000, 0x30), (36, 0x4100, 0x28)]
        {
            assert_eq!(read_u32(&blob, pogo + offset).unwrap(), begin);
            assert_eq!(read_u32(&blob, pogo + offset + 4).unwrap(), length);
            assert_eq!(&blob[pogo + offset + 8..pogo + offset + 14], b".text\0");
        }
        let output = pe
            .rebuild(&PeEdits {
                new_sections: vec![NewSection {
                    name: ".kdebug".into(),
                    rva: Rva::new(0x3000),
                    flags: SectionFlags {
                        read: true,
                        write: false,
                        execute: false,
                    },
                    data: blob,
                }],
                directories: vec![update],
                entry_point: Some(Rva::new(0x4000)),
                clear_guard_cf: true,
                ..PeEdits::default()
            })
            .unwrap();
        let rebuilt = PeFile::parse(&output).unwrap();
        assert!(rebuilt.is_dll());
        assert_eq!(rebuilt.image_base, IMAGE_BASE);
        assert_eq!(rebuilt.entry_point, 0x4000);
        assert_eq!(read_u16(&output, OPT + 70).unwrap(), 0x160);
        assert_eq!(read_u16(&output, 0x96).unwrap(), 0x2022);
        for record in [0x3000, 0x301c] {
            let length = rebuilt.u32_at_rva(record + 16).unwrap();
            let payload = rebuilt.u32_at_rva(record + 20).unwrap();
            let file = rebuilt.u32_at_rva(record + 24).unwrap() as usize;
            assert_eq!(
                rebuilt.rewrite_bytes(payload, length).unwrap(),
                &output[file..file + length as usize]
            );
        }
    }

    #[test]
    fn patch_fields_require_file_backing_and_unique_nonoverlapping_ranges() {
        let pe = fixture();
        let mut patches = PatchSet::new(&pe);
        patches.add(0x1300, vec![1; 8]).unwrap();
        patches.add(0x1300, vec![1; 8]).unwrap();
        assert!(patches.add(0x1300, vec![2; 8]).is_err());
        assert!(patches.add(0x1304, vec![3; 4]).is_err());
        assert!(patches.add(0x2ffc, vec![4; 8]).is_err());
        assert_eq!(patches.finish().len(), 1);
    }

    #[test]
    fn header_only_entry_update_preserves_dll_and_other_characteristics() {
        let pe = fixture();
        let output = pe
            .rebuild(&PeEdits {
                entry_point: Some(Rva::new(0x1180)),
                clear_guard_cf: true,
                ..PeEdits::default()
            })
            .unwrap();
        let rebuilt = PeFile::parse(&output).unwrap();
        assert!(rebuilt.is_dll());
        assert_eq!(rebuilt.entry_point, 0x1180);
        assert_eq!(rebuilt.image_base, IMAGE_BASE);
        assert_eq!(read_u16(&output, 0x96).unwrap(), 0x2022);
        assert_eq!(read_u16(&output, OPT + 70).unwrap(), 0x160);
    }

    #[test]
    fn active_cfg_requires_a_dispatch_slot_and_check_query_tracks_real_slots() {
        let mut pe = fixture();
        assert!(pe.has_cfg());
        assert!(!pe.has_cfg_check());
        assert!(pe.cfg_edits(Rva::new(0x4000), Rva::new(0x4010)).is_err());
        directory(&mut pe, 10, 0x1200, 320);
        put32(&mut pe, 0x1200, 320);
        put64(&mut pe, 0x1278, IMAGE_BASE + 0x1900);
        assert!(!pe.has_cfg_check());
        assert!(pe.cfg_edits(Rva::new(0x4000), Rva::new(0x4010)).is_ok());
        put64(&mut pe, 0x1270, IMAGE_BASE + 0x1908);
        assert!(pe.has_cfg_check());
    }
}
