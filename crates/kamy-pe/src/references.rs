use std::collections::{HashMap, HashSet};

use anyhow::{Context, bail, ensure};
use kamy_core::{HostReference, MetadataReferences, ReferenceKind, Rva};

use crate::{PeFile, read_u32, read_u64};

mod dynamic;

impl PeFile {
    /// Enumerates known PE fields and validated storage that needs no raw pointer scan.
    /// Opaque references pin code whose metadata cannot be rewritten.
    /// Handler-specific payloads remain unclassified unless the handler identifies their layout.
    /// Callers MUST conservatively analyze bytes outside the classified ranges and reference fields.
    /// Unlocalizable encoded metadata and malformed records return errors.
    pub fn metadata_references(&self) -> anyhow::Result<MetadataReferences> {
        let _span = tracing::debug_span!("pe_metadata_references").entered();
        let mut collector = Collector {
            pe: self,
            references: Vec::new(),
            classified_ranges: Vec::new(),
        };
        if self.entry_point != 0 {
            collector.add(0, self.entry_point, ReferenceKind::EntryPoint, false)?;
        }
        collector.exports()?;
        collector.tls()?;
        collector.load_config()?;
        collector.debug()?;
        collector.base_relocations()?;
        collector.exceptions()?;
        Ok(MetadataReferences {
            references: collector.references,
            classified_ranges: collector.classified_ranges,
        })
    }
}

struct Collector<'a> {
    pe: &'a PeFile,
    references: Vec<HostReference>,
    classified_ranges: Vec<std::ops::Range<Rva>>,
}

#[derive(Default)]
struct UnwindState {
    active: HashSet<u32>,
    completed: HashMap<u32, bool>,
}

impl Collector<'_> {
    fn bytes(&self, rva: u32, size: u32) -> anyhow::Result<&[u8]> {
        rva.checked_add(size)
            .context("metadata RVA range overflow")?;
        self.pe
            .slice_at_rva(rva)
            .and_then(|bytes| bytes.get(..size as usize))
            .with_context(|| format!("metadata range {rva:#x}+{size:#x} is not file-backed"))
    }

    fn directory(&self, index: usize) -> anyhow::Result<Option<(u32, u32)>> {
        let (rva, size) = self
            .pe
            .data_directories
            .get(index)
            .copied()
            .unwrap_or_default();
        if rva == 0 && size == 0 {
            return Ok(None);
        }
        ensure!(rva != 0 && size != 0, "inconsistent PE directory {index}");
        self.bytes(rva, size)
            .with_context(|| format!("invalid PE directory {index}"))?;
        Ok(Some((rva, size)))
    }

    fn add(
        &mut self,
        source: u32,
        target: u32,
        kind: ReferenceKind,
        boundary: bool,
    ) -> anyhow::Result<()> {
        if target == 0 {
            return Ok(());
        }
        ensure!(
            self.pe.sections.iter().any(|section| {
                let end =
                    u64::from(section.rva) + u64::from(section.virtual_size.max(section.raw_size));
                target >= section.rva
                    && (u64::from(target) < end || (boundary && u64::from(target) == end))
            }),
            "metadata field {source:#x} targets out-of-image RVA {target:#x}"
        );
        self.references.push(HostReference {
            source: Rva::new(source),
            target: Rva::new(target),
            kind,
        });
        Ok(())
    }

    fn rva(&mut self, source: u32, kind: ReferenceKind, boundary: bool) -> anyhow::Result<u32> {
        let target = read_u32(self.bytes(source, 4)?, 0)?;
        self.add(source, target, kind, boundary)?;
        Ok(target)
    }

    fn va(&mut self, source: u32, boundary: bool) -> anyhow::Result<Option<u32>> {
        let target = read_u64(self.bytes(source, 8)?, 0)?;
        if target == 0 {
            return Ok(None);
        }
        let Some(relative) = target
            .checked_sub(self.pe.image_base)
            .and_then(|value| u32::try_from(value).ok())
        else {
            bail!("metadata VA field {source:#x} contains external pointer {target:#x}");
        };
        self.add(source, relative, ReferenceKind::Absolute, boundary)?;
        Ok(Some(relative))
    }

    fn base_relocations(&mut self) -> anyhow::Result<()> {
        let Some((base, size)) = self.directory(crate::DIR_BASERELOC)? else {
            return Ok(());
        };
        let end = base
            .checked_add(size)
            .context("base relocation directory RVA range overflow")?;
        // PeFile::parse validates every encoded block before retaining this directory.
        self.classified_ranges.push(Rva::new(base)..Rva::new(end));
        Ok(())
    }

    fn exports(&mut self) -> anyhow::Result<()> {
        let Some((base, size)) = self.directory(0)? else {
            return Ok(());
        };
        ensure!(size >= 40, "truncated export directory");
        let count = read_u32(self.bytes(base, 40)?, 20)?;
        let table = read_u32(self.bytes(base, 40)?, 28)?;
        self.bytes(
            table,
            count.checked_mul(4).context("export table overflow")?,
        )?;
        let end = base.checked_add(size).context("export range overflow")?;
        for index in 0..count {
            let source = table + index * 4;
            let target = read_u32(self.bytes(source, 4)?, 0)?;
            if (base..end).contains(&target) {
                let forwarder = self.bytes(target, end - target)?;
                ensure!(forwarder.contains(&0), "unterminated export forwarder");
            } else {
                self.add(source, target, ReferenceKind::ImageRelative, false)?;
            }
        }
        Ok(())
    }

    fn tls(&mut self) -> anyhow::Result<()> {
        let Some((base, size)) = self.directory(9)? else {
            return Ok(());
        };
        ensure!(size >= 40, "truncated TLS directory");
        let start = self.va(base, false)?;
        let end = self.va(base + 8, true)?;
        ensure!(
            matches!((start, end), (None, None))
                || matches!((start, end), (Some(a), Some(b)) if a <= b),
            "invalid TLS template bounds"
        );
        self.va(base + 16, false)?;
        if let Some(callbacks) = self.va(base + 24, false)? {
            let available = self
                .pe
                .slice_at_rva(callbacks)
                .context("TLS callback table is not file-backed")?
                .len()
                / 8;
            let mut terminated = false;
            for index in 0..available {
                let source = callbacks
                    .checked_add(
                        u32::try_from(index)
                            .context("TLS table too large")?
                            .checked_mul(8)
                            .context("TLS table overflow")?,
                    )
                    .context("TLS table overflow")?;
                if self.va(source, false)?.is_none() {
                    terminated = true;
                    break;
                }
            }
            ensure!(terminated, "unterminated TLS callback table");
        }
        Ok(())
    }

    fn load_config(&mut self) -> anyhow::Result<()> {
        let Some((base, size)) = self.directory(10)? else {
            return Ok(());
        };
        ensure!(size >= 4, "truncated load configuration");
        let declared = read_u32(self.bytes(base, 4)?, 0)?;
        ensure!(
            declared >= 4 && declared <= size,
            "invalid load configuration declared size"
        );
        let mut dynamic_table = None;
        // PE32+ fields are appended across SDK versions; partial fields are malformed.
        for offset in [
            40, 80, 88, 96, 112, 120, 128, 160, 176, 192, 200, 208, 216, 232, 248, 256, 264, 280,
            288, 296, 304, 312,
        ] {
            if declared <= offset {
                continue;
            }
            ensure!(
                declared >= offset + 8,
                "partial load configuration VA field at {offset}"
            );
            let target = self.va(base + offset, false)?;
            if let Some(target) = target {
                match offset {
                    192 => dynamic_table = Some(target),
                    200 => bail!(
                        "load configuration CHPEMetadataPointer at {target:#x}: hybrid code maps cannot be localized by the x64 reference model"
                    ),
                    248 => self.enclave_config(target)?,
                    256 => self.volatile_metadata(target)?,
                    _ => {}
                }
            }
        }
        if declared > 320 {
            ensure!(
                self.bytes(base + 320, declared - 320)?
                    .iter()
                    .all(|byte| *byte == 0),
                "load configuration extension beyond 320 bytes has unknown address encoding; function ownership cannot be established"
            );
        }
        self.dynamic_relocations(base, declared, dynamic_table)?;
        if declared > 240 {
            ensure!(
                declared >= 244,
                "partial load configuration hot patch table offset"
            );
            ensure!(
                read_u32(self.bytes(base + 240, 4)?, 0)? == 0,
                "load configuration HotPatchTableOffset uses an unparsed patch encoding; function ownership cannot be established"
            );
        }
        let flags = if declared >= 148 {
            read_u32(self.bytes(base + 144, 4)?, 0)?
        } else {
            0
        };
        for (table_offset, count_offset, stride) in [
            (96, 104, 4),
            (128, 136, 4 + (flags >> 28)),
            (160, 168, 4 + (flags >> 28)),
            (176, 184, 4 + (flags >> 28)),
            (264, 272, 4 + (flags >> 28)),
        ] {
            if declared <= table_offset {
                continue;
            }
            ensure!(
                declared >= count_offset + 8,
                "truncated load configuration table pair"
            );
            let table = read_u64(self.bytes(base + table_offset, 8)?, 0)?;
            let count = read_u64(self.bytes(base + count_offset, 8)?, 0)?;
            ensure!(
                (table == 0) == (count == 0),
                "inconsistent load configuration table/count"
            );
            if count == 0 {
                continue;
            }
            let table = table
                .checked_sub(self.pe.image_base)
                .and_then(|value| u32::try_from(value).ok())
                .context("external load configuration table")?;
            let count = u32::try_from(count).context("load configuration table count overflow")?;
            self.bytes(
                table,
                count
                    .checked_mul(stride)
                    .context("load configuration table size overflow")?,
            )?;
            for index in 0..count {
                self.rva(table + index * stride, ReferenceKind::ImageRelative, false)?;
            }
        }
        Ok(())
    }

    fn enclave_config(&mut self, base: u32) -> anyhow::Result<()> {
        let size = read_u32(self.bytes(base, 4)?, 0)?;
        ensure!(
            size >= 80,
            "truncated PE32+ enclave configuration at {base:#x}"
        );
        self.bytes(base, size)?;
        ensure!(
            size == 80,
            "enclave configuration extension at {base:#x} has unknown address encoding"
        );
        let required = read_u32(self.bytes(base + 4, 4)?, 0)?;
        ensure!(
            required <= size,
            "invalid minimum enclave configuration size"
        );
        let count = read_u32(self.bytes(base + 12, 4)?, 0)?;
        let table = self.rva(base + 16, ReferenceKind::ImageRelative, false)?;
        let stride = read_u32(self.bytes(base + 20, 4)?, 0)?;
        ensure!(
            (table == 0) == (count == 0),
            "inconsistent enclave import table/count"
        );
        if count == 0 {
            return Ok(());
        }
        ensure!(stride >= 80, "truncated enclave import record");
        ensure!(
            stride == 80,
            "enclave import extension has unknown address encoding"
        );
        self.bytes(
            table,
            count
                .checked_mul(stride)
                .context("enclave import table size overflow")?,
        )?;
        for index in 0..count {
            let name = self.rva(
                table + index * stride + 72,
                ReferenceKind::ImageRelative,
                false,
            )?;
            ensure!(name != 0, "null enclave import name");
            ensure!(
                self.pe
                    .slice_at_rva(name)
                    .context("enclave import name is not file-backed")?
                    .contains(&0),
                "unterminated enclave import name"
            );
        }
        Ok(())
    }

    fn volatile_metadata(&mut self, base: u32) -> anyhow::Result<()> {
        let size = read_u32(self.bytes(base, 4)?, 0)?;
        ensure!(size >= 24, "truncated volatile metadata at {base:#x}");
        self.bytes(base, size)?;
        ensure!(
            size == 24,
            "volatile metadata at {base:#x} has unsupported size; range encoding is unknown"
        );
        let min_version = crate::read_u16(self.bytes(base + 4, 2)?, 0)? & 0x7fff;
        let max_version = crate::read_u16(self.bytes(base + 6, 2)?, 0)? & 0x7fff;
        ensure!(
            min_version <= max_version,
            "invalid volatile metadata version bounds at {base:#x}"
        );
        for (offset, stride) in [(8, 4), (16, 8)] {
            let table = self.rva(base + offset, ReferenceKind::ImageRelative, false)?;
            let length = read_u32(self.bytes(base + offset + 4, 4)?, 0)?;
            ensure!(
                (table == 0) == (length == 0),
                "inconsistent volatile metadata table/size"
            );
            ensure!(
                length % stride == 0,
                "partial volatile metadata table entry"
            );
            if length == 0 {
                continue;
            }
            self.bytes(table, length)?;
            for index in 0..length / stride {
                let field = table + index * stride;
                let begin = self.rva(field, ReferenceKind::Opaque, false)?;
                if stride == 8 {
                    let length = read_u32(self.bytes(field + 4, 4)?, 0)?;
                    let end = begin
                        .checked_add(length)
                        .context("volatile metadata range overflow")?;
                    ensure!(begin != 0 && length != 0, "empty volatile metadata range");
                    self.add(field, end, ReferenceKind::Opaque, true)?;
                    if let Some((pdata, size)) = self.directory(3)? {
                        ensure!(size % 12 == 0, "partial exception directory record");
                        for index in 0..size / 12 {
                            let entry = read_u32(self.bytes(pdata + index * 12, 4)?, 0)?;
                            if (begin..end).contains(&entry) {
                                self.add(field, entry, ReferenceKind::Opaque, false)?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn debug(&mut self) -> anyhow::Result<()> {
        let Some((base, size)) = self.directory(6)? else {
            return Ok(());
        };
        ensure!(size % 28 == 0, "partial debug directory entry");
        for index in 0..size / 28 {
            let entry = base + index * 28;
            let kind = read_u32(self.bytes(entry, 28)?, 12)?;
            let length = read_u32(self.bytes(entry, 28)?, 16)?;
            let payload = self.rva(entry + 20, ReferenceKind::ImageRelative, false)?;
            let file_offset = read_u32(self.bytes(entry, 28)?, 24)? as usize;
            let data = self
                .pe
                .bytes
                .get(
                    file_offset
                        ..file_offset
                            .checked_add(length as usize)
                            .context("debug payload overflow")?,
                )
                .context("truncated debug payload")?;
            if payload != 0 {
                ensure!(
                    self.bytes(payload, length)? == data,
                    "debug RVA/file pointer mismatch"
                );
            }
            match kind {
                0 | 14 if length == 0 => {}
                2 => {
                    ensure!(
                        data.starts_with(b"RSDS") || data.starts_with(b"NB10"),
                        "CodeView record at {entry:#x} has an unknown symbol/address encoding; function ownership cannot be established"
                    );
                    let header = if data.starts_with(b"RSDS") { 24 } else { 16 };
                    ensure!(
                        data.get(header..).is_some_and(|path| path.contains(&0)),
                        "truncated CodeView record"
                    );
                }
                4 | 12 | 16 | 17 | 19 | 20 => {}
                13 => {
                    ensure!(length >= 4 && payload != 0, "invalid POGO debug payload");
                    ensure!(
                        matches!(
                            read_u32(data, 0)?,
                            0 | 0x4c54_4347 | 0x5047_5500 | 0x5047_4900 | 0x5047_4f00 | 0x5350_474f
                        ),
                        "POGO record at {entry:#x} has an unknown address encoding; function ownership cannot be established"
                    );
                    let mut offset = 4u32;
                    while offset < length {
                        ensure!(length - offset >= 9, "truncated POGO entry");
                        self.rva(payload + offset, ReferenceKind::ImageRelative, false)?;
                        let tail = self.bytes(payload + offset + 8, length - offset - 8)?;
                        let name_len = tail
                            .iter()
                            .position(|byte| *byte == 0)
                            .context("unterminated POGO name")?
                            as u32
                            + 1;
                        offset = offset
                            .checked_add(8 + name_len)
                            .and_then(|value| value.checked_add(3))
                            .map(|value| value & !3)
                            .context("POGO entry overflow")?;
                        ensure!(offset <= length, "truncated POGO alignment");
                    }
                }
                _ => bail!(
                    "debug type {kind} at {entry:#x} has an unparsed address encoding; function ownership cannot be established"
                ),
            }
        }
        Ok(())
    }

    fn exceptions(&mut self) -> anyhow::Result<()> {
        let Some((base, size)) = self.directory(3)? else {
            return Ok(());
        };
        ensure!(size % 12 == 0, "partial exception directory record");
        let mut state = UnwindState::default();
        for index in 0..size / 12 {
            let field = base + index * 12;
            self.runtime_function(field, &mut state, 0)
                .with_context(|| format!("runtime function at {field:#x}"))?;
        }
        Ok(())
    }

    fn runtime_function(
        &mut self,
        field: u32,
        state: &mut UnwindState,
        depth: usize,
    ) -> anyhow::Result<bool> {
        ensure!(depth < 128, "excessive chained unwind depth at {field:#x}");
        let begin = self.rva(field, ReferenceKind::Unwind, false)?;
        let end = self.rva(field + 4, ReferenceKind::Unwind, true)?;
        let unwind = self.rva(field + 8, ReferenceKind::Unwind, false)?;
        ensure!(
            begin != 0 && begin < end && unwind != 0,
            "invalid runtime function bounds at {field:#x}"
        );
        let opaque = self
            .unwind(unwind, state, depth)
            .with_context(|| format!("UNWIND_INFO at {unwind:#x}"))?;
        if opaque {
            self.add(field, begin, ReferenceKind::Opaque, false)?;
        }
        Ok(opaque)
    }

    fn unwind(
        &mut self,
        unwind: u32,
        state: &mut UnwindState,
        depth: usize,
    ) -> anyhow::Result<bool> {
        ensure!(
            !state.active.contains(&unwind),
            "cyclic chained unwind record at {unwind:#x}"
        );
        if let Some(&opaque) = state.completed.get(&unwind) {
            return Ok(opaque);
        }
        state.active.insert(unwind);
        let header = self.bytes(unwind, 4)?;
        let version = header[0] & 7;
        let flags = header[0] >> 3;
        ensure!(
            (version == 1 || version == 2) && flags & !7 == 0,
            "unsupported unwind version/flags"
        );
        ensure!(
            flags & 4 == 0 || flags & 3 == 0,
            "chained unwind record has handler flags"
        );
        let tail = unwind
            .checked_add(4 + ((u32::from(header[2]) + 1) & !1) * 2)
            .context("unwind record overflow")?;
        self.bytes(unwind, tail - unwind)?;
        self.classified_ranges
            .push(Rva::new(unwind)..Rva::new(tail));
        let opaque = if flags & 4 != 0 {
            self.bytes(tail, 12)?;
            self.runtime_function(tail, state, depth + 1)?
        } else if flags & 3 != 0 {
            let handler = self.rva(tail, ReferenceKind::Opaque, false)?;
            ensure!(handler != 0, "null unwind handler");
            if self.is_c_specific_handler(handler) {
                self.c_scope_table(tail.checked_add(4).context("scope table RVA overflow")?)?;
            }
            true
        } else {
            false
        };
        state.active.remove(&unwind);
        state.completed.insert(unwind, opaque);
        Ok(opaque)
    }

    fn is_c_specific_handler(&self, mut handler: u32) -> bool {
        let mut visited = [0; 16];
        for index in 0..visited.len() {
            if visited[..index].contains(&handler) {
                return false;
            }
            visited[index] = handler;
            let Some(bytes) = self.pe.slice_at_rva(handler) else {
                return false;
            };
            let (width, displacement, indirect) = if bytes.starts_with(&[0xff, 0x25]) {
                (6, bytes.get(2..6), true)
            } else if bytes.starts_with(&[0x48, 0xff, 0x25]) {
                (7, bytes.get(3..7), true)
            } else if bytes.first() == Some(&0xe9) {
                (5, bytes.get(1..5), false)
            } else {
                return false;
            };
            let Some(displacement) = displacement else {
                return false;
            };
            let displacement = i32::from_le_bytes(
                displacement
                    .try_into()
                    .expect("four-byte thunk displacement"),
            );
            let Ok(target) = u32::try_from(i64::from(handler) + width + i64::from(displacement))
            else {
                return false;
            };
            if indirect {
                return self.pe.imports.iter().any(|import| {
                    import.iat_rva == target && import.name == "__C_specific_handler"
                });
            }
            handler = target;
        }
        false
    }

    fn c_scope_table(&mut self, table: u32) -> anyhow::Result<()> {
        let count = read_u32(self.bytes(table, 4)?, 0)?;
        let size = count
            .checked_mul(16)
            .and_then(|size| size.checked_add(4))
            .context("C scope table size overflow")?;
        self.bytes(table, size)
            .with_context(|| format!("C scope table at {table:#x}"))?;
        for index in 0..count {
            let field = table + 4 + index * 16;
            let begin = self.rva(field, ReferenceKind::Opaque, false)?;
            let end = self.rva(field + 4, ReferenceKind::Opaque, true)?;
            ensure!(
                begin != 0 && begin < end,
                "invalid C scope bounds at {field:#x}"
            );
            let handler = read_u32(self.bytes(field + 8, 4)?, 0)?;
            if handler > 1 {
                self.add(field + 8, handler, ReferenceKind::Opaque, false)?;
            }
            self.rva(field + 12, ReferenceKind::Opaque, false)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SectionRecord;

    fn fixture() -> PeFile {
        PeFile {
            bytes: vec![0; 0x1000],
            image_base: 0x140000000,
            entry_point: 0x1100,
            sections: vec![SectionRecord {
                name: ".text".into(),
                rva: 0x1000,
                virtual_size: 0x1000,
                raw_size: 0x1000,
                raw_pointer: 0,
                characteristics: 0x60000020,
            }],
            data_directories: vec![(0, 0); 16],
            relocations: Vec::new(),
            pdata_begins: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
        }
    }

    fn put32(pe: &mut PeFile, rva: u32, value: u32) {
        let offset = (rva - 0x1000) as usize;
        pe.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(pe: &mut PeFile, rva: u32, value: u64) {
        let offset = (rva - 0x1000) as usize;
        pe.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn runtime(pe: &mut PeFile, field: u32, begin: u32, end: u32, unwind: u32) {
        put32(pe, field, begin);
        put32(pe, field + 4, end);
        put32(pe, field + 8, unwind);
    }

    fn has_opaque(references: &[HostReference], target: u32) -> bool {
        references.iter().any(|reference| {
            reference.kind == ReferenceKind::Opaque && reference.target == Rva::new(target)
        })
    }

    fn c_handler(pe: &mut PeFile) {
        pe.bytes[0x500..0x502].copy_from_slice(&[0xff, 0x25]);
        put32(pe, 0x1502, 0x7a);
        pe.imports.push(crate::imports::ImportEntry {
            name: "__C_specific_handler".into(),
            iat_rva: 0x1580,
        });
    }

    #[test]
    fn ordinal_exports_seed_code_but_not_forwarders() {
        let mut pe = fixture();
        pe.data_directories[0] = (0x1200, 0x80);
        put32(&mut pe, 0x1214, 3);
        put32(&mut pe, 0x121c, 0x1240);
        put32(&mut pe, 0x1240, 0x1180);
        put32(&mut pe, 0x1244, 0x1260);
        pe.bytes[0x260..0x268].copy_from_slice(b"dll.fun\0");
        pe.exports = crate::exports::parse_exports(&pe, 0x1200, 0x80).unwrap();
        assert_eq!(pe.seeds(), vec![Rva::new(0x1100), Rva::new(0x1180)]);
        assert!(pe.exports[0].name.is_none());
        assert!(
            pe.metadata_references()
                .unwrap()
                .references
                .iter()
                .any(|reference| reference.source == Rva::new(0x1240)
                    && reference.target == Rva::new(0x1180))
        );
        assert!(
            !pe.metadata_references()
                .unwrap()
                .references
                .iter()
                .any(|reference| reference.source == Rva::new(0x1244))
        );
    }

    #[test]
    fn malformed_directories_are_not_absent() {
        for directory in [0, 3, 6, 9, 10] {
            let mut pe = fixture();
            pe.data_directories[directory] = (0x1ff0, 0x40);
            assert!(pe.metadata_references().is_err());
            pe.data_directories[directory] = (0, 4);
            assert!(pe.metadata_references().is_err());
        }
    }

    #[test]
    fn tls_callbacks_require_a_bounded_terminator() {
        let mut pe = fixture();
        pe.data_directories[9] = (0x1200, 40);
        put64(&mut pe, 0x1218, 0x140001ff8);
        put64(&mut pe, 0x1ff8, 0x140001100);
        assert!(
            pe.metadata_references()
                .unwrap_err()
                .to_string()
                .contains("unterminated TLS")
        );
        put64(&mut pe, 0x1ff8, 0);
        assert!(pe.metadata_references().is_ok());
    }

    #[test]
    fn load_config_guard_stride_preserves_flag_bytes() {
        let mut pe = fixture();
        pe.data_directories[10] = (0x1200, 280);
        put32(&mut pe, 0x1200, 280);
        put64(&mut pe, 0x1280, 0x140001400);
        put64(&mut pe, 0x1288, 2);
        put64(&mut pe, 0x12a0, 0x140001500);
        put64(&mut pe, 0x12a8, 2);
        put64(&mut pe, 0x1308, 0x140001600);
        put64(&mut pe, 0x1310, 2);
        put32(&mut pe, 0x1290, 0x10000000);
        for (table, target) in [(0x1400, 0x1100), (0x1500, 0x1140), (0x1600, 0x1180)] {
            put32(&mut pe, table, target);
            pe.bytes[(table - 0x1000 + 4) as usize] = 0xff;
            put32(&mut pe, table + 5, target + 0x10);
        }
        let references = pe.metadata_references().unwrap().references;
        for (source, target) in [(0x1405, 0x1110), (0x1505, 0x1150), (0x1605, 0x1190)] {
            assert!(references.contains(&HostReference {
                source: Rva::new(source),
                target: Rva::new(target),
                kind: ReferenceKind::ImageRelative,
            }));
        }
    }

    #[test]
    fn plain_unwind_boundaries_do_not_pin_code() {
        let mut pe = fixture();
        pe.data_directories[3] = (0x1200, 12);
        put32(&mut pe, 0x1200, 0x1100);
        put32(&mut pe, 0x1204, 0x1180);
        put32(&mut pe, 0x1208, 0x1300);
        pe.bytes[0x300] = 1;
        let references = pe.metadata_references().unwrap().references;
        assert_eq!(
            references
                .iter()
                .filter(|reference| reference.kind == ReferenceKind::Unwind)
                .count(),
            3
        );
        assert!(
            !references
                .iter()
                .any(|reference| reference.kind == ReferenceKind::Opaque)
        );
    }

    #[test]
    fn unwind_classification_stops_before_unknown_handler_payload() {
        for flags in [0, 1, 4] {
            let mut pe = fixture();
            pe.data_directories[3] = (0x1200, 12);
            runtime(&mut pe, 0x1200, 0x1100, 0x1180, 0x1300);
            pe.bytes[0x300..0x308].copy_from_slice(&[1 | (flags << 3), 4, 1, 0, 4, 0x12, 0, 0]);
            if flags == 4 {
                runtime(&mut pe, 0x1308, 0x1600, 0x1680, 0x1400);
                pe.bytes[0x400] = 1;
            } else {
                put32(&mut pe, 0x1308, 0x1500);
                put32(&mut pe, 0x130c, 0x1140);
            }
            let metadata = pe.metadata_references().unwrap();
            let mut expected_ranges = vec![Rva::new(0x1300)..Rva::new(0x1308)];
            if flags == 4 {
                expected_ranges.push(Rva::new(0x1400)..Rva::new(0x1404));
            }
            assert_eq!(metadata.classified_ranges, expected_ranges);
            for (source, target) in [(0x1200, 0x1100), (0x1204, 0x1180), (0x1208, 0x1300)] {
                assert!(metadata.references.contains(&HostReference {
                    source: Rva::new(source),
                    target: Rva::new(target),
                    kind: ReferenceKind::Unwind,
                }));
            }
            if flags == 1 {
                assert!(metadata.references.contains(&HostReference {
                    source: Rva::new(0x1308),
                    target: Rva::new(0x1500),
                    kind: ReferenceKind::Opaque,
                }));
                assert!(
                    !metadata
                        .references
                        .iter()
                        .any(|reference| reference.source == Rva::new(0x130c))
                );
            }
        }
    }

    #[test]
    fn truncated_unwind_code_storage_remains_an_error() {
        let mut pe = fixture();
        pe.data_directories[3] = (0x1200, 12);
        runtime(&mut pe, 0x1200, 0x1100, 0x1180, 0x1ff8);
        pe.bytes[0xff8..0xffc].copy_from_slice(&[1, 4, 3, 0]);
        assert!(
            format!("{:#}", pe.metadata_references().unwrap_err())
                .contains("UNWIND_INFO at 0x1ff8")
        );
    }

    #[test]
    fn external_va_is_not_truncated_into_the_image() {
        let mut pe = fixture();
        pe.data_directories[9] = (0x1200, 40);
        put64(&mut pe, 0x1210, 0x240001100);
        assert!(
            pe.metadata_references()
                .unwrap_err()
                .to_string()
                .contains("external pointer")
        );
    }

    #[test]
    fn empty_iltcg_debug_record_preserves_payload_reference() {
        let mut pe = fixture();
        let baseline = pe.metadata_references().unwrap().references;
        pe.data_directories[6] = (0x1200, 28);
        put32(&mut pe, 0x120c, 14);
        assert_eq!(pe.metadata_references().unwrap().references, baseline);

        put32(&mut pe, 0x1214, 0x1400);
        put32(&mut pe, 0x1218, 0x400);
        let references = pe.metadata_references().unwrap().references;
        let mut expected = baseline;
        expected.push(HostReference {
            source: Rva::new(0x1214),
            target: Rva::new(0x1400),
            kind: ReferenceKind::ImageRelative,
        });
        assert_eq!(references, expected);
    }

    #[test]
    fn empty_iltcg_debug_record_still_checks_coordinates() {
        for (payload, file_offset) in [(0, 0x1001), (0x2000, 0), (0x1900, 0x900)] {
            let mut pe = fixture();
            pe.sections[0].raw_size = 0x800;
            pe.data_directories[6] = (0x1200, 28);
            put32(&mut pe, 0x120c, 14);
            put32(&mut pe, 0x1214, payload);
            put32(&mut pe, 0x1218, file_offset);
            assert!(
                pe.metadata_references().is_err(),
                "accepted invalid empty ILTCG coordinates {payload:#x}/{file_offset:#x}"
            );
        }
    }

    #[test]
    fn unsupported_debug_payloads_remain_rejected() {
        for (kind, length) in [(1, 0), (1, 4), (14, 4)] {
            for payload in [0, 0x1400] {
                let mut pe = fixture();
                pe.data_directories[6] = (0x1200, 28);
                put32(&mut pe, 0x120c, kind);
                put32(&mut pe, 0x1210, length);
                put32(&mut pe, 0x1214, payload);
                put32(&mut pe, 0x1218, 0x400);
                put32(&mut pe, 0x1400, 0x1100);
                assert!(pe.metadata_references().is_err());
            }
        }
    }

    #[test]
    fn shared_handler_unwind_pins_each_owner_but_not_plain_functions() {
        let mut pe = fixture();
        pe.data_directories[3] = (0x1200, 36);
        runtime(&mut pe, 0x1200, 0x1100, 0x1180, 0x1300);
        runtime(&mut pe, 0x120c, 0x1180, 0x11f0, 0x1300);
        runtime(&mut pe, 0x1218, 0x1600, 0x1680, 0x1400);
        pe.bytes[0x300] = 1 | (3 << 3);
        put32(&mut pe, 0x1304, 0x1700);
        put32(&mut pe, 0x1308, u32::MAX);
        pe.bytes[0x400] = 1;
        let references = pe.metadata_references().unwrap().references;
        for target in [0x1100, 0x1180, 0x1700] {
            assert!(
                has_opaque(&references, target),
                "missing opaque target {target:#x}"
            );
        }
        assert!(!has_opaque(&references, 0x1600));
    }

    #[test]
    fn shared_plain_unwind_is_not_a_cycle_or_a_reason_to_pin() {
        let mut pe = fixture();
        pe.data_directories[3] = (0x1200, 24);
        runtime(&mut pe, 0x1200, 0x1100, 0x1180, 0x1300);
        runtime(&mut pe, 0x120c, 0x1180, 0x11f0, 0x1300);
        pe.bytes[0x300] = 1;
        assert!(
            !pe.metadata_references()
                .unwrap()
                .references
                .iter()
                .any(|reference| reference.kind == ReferenceKind::Opaque)
        );
    }

    #[test]
    fn shared_chained_handler_uncertainty_reaches_each_owner() {
        let mut pe = fixture();
        pe.data_directories[3] = (0x1200, 24);
        runtime(&mut pe, 0x1200, 0x1100, 0x1180, 0x1300);
        runtime(&mut pe, 0x120c, 0x1180, 0x11f0, 0x1300);
        pe.bytes[0x300] = 1 | (4 << 3);
        runtime(&mut pe, 0x1304, 0x1600, 0x1680, 0x1400);
        pe.bytes[0x400] = 1 | (1 << 3);
        put32(&mut pe, 0x1404, 0x1700);
        let references = pe.metadata_references().unwrap().references;
        for target in [0x1100, 0x1180, 0x1600, 0x1700] {
            assert!(
                has_opaque(&references, target),
                "missing opaque target {target:#x}"
            );
        }
    }

    #[test]
    fn chained_unwind_cycles_fail_with_record_context() {
        let mut pe = fixture();
        pe.data_directories[3] = (0x1200, 12);
        runtime(&mut pe, 0x1200, 0x1100, 0x1180, 0x1300);
        pe.bytes[0x300] = 1 | (4 << 3);
        runtime(&mut pe, 0x1304, 0x1180, 0x11f0, 0x1400);
        pe.bytes[0x400] = 1 | (4 << 3);
        runtime(&mut pe, 0x1404, 0x1100, 0x1180, 0x1300);
        let error = format!("{:#}", pe.metadata_references().unwrap_err());
        assert!(error.contains("runtime function at 0x1200"));
        assert!(error.contains("cyclic chained unwind record at 0x1300"));
    }

    #[test]
    fn malformed_handler_and_chain_records_remain_errors() {
        let mut pe = fixture();
        pe.data_directories[3] = (0x1200, 12);
        runtime(&mut pe, 0x1200, 0x1100, 0x1180, 0x1ffc);
        for flags in [1, 4, 5] {
            pe.bytes[0xffc] = 1 | (flags << 3);
            let error = format!("{:#}", pe.metadata_references().unwrap_err());
            assert!(error.contains("UNWIND_INFO at 0x1ffc"));
        }
        put32(&mut pe, 0x1208, 0x1300);
        pe.bytes[0x300] = 1 | (1 << 3);
        assert!(
            format!("{:#}", pe.metadata_references().unwrap_err()).contains("null unwind handler")
        );
    }

    #[test]
    fn identified_c_scope_targets_are_opaque() {
        let mut pe = fixture();
        pe.data_directories[3] = (0x1200, 12);
        runtime(&mut pe, 0x1200, 0x1100, 0x1180, 0x1300);
        pe.bytes[0x300] = 1 | (1 << 3);
        put32(&mut pe, 0x1304, 0x1500);
        put32(&mut pe, 0x1308, 1);
        put32(&mut pe, 0x130c, 0x1120);
        put32(&mut pe, 0x1310, 0x1160);
        put32(&mut pe, 0x1314, 0x1600);
        put32(&mut pe, 0x1318, 0x1700);
        c_handler(&mut pe);
        let references = pe.metadata_references().unwrap().references;
        for target in [0x1100, 0x1120, 0x1160, 0x1500, 0x1600, 0x1700] {
            assert!(
                has_opaque(&references, target),
                "missing opaque scope target {target:#x}"
            );
        }
        put32(&mut pe, 0x1314, 1);
        put32(&mut pe, 0x1318, 0);
        assert!(pe.metadata_references().is_ok());
    }

    #[test]
    fn scope_bounds_are_checked_only_for_identified_c_handlers() {
        let mut pe = fixture();
        pe.data_directories[3] = (0x1200, 12);
        runtime(&mut pe, 0x1200, 0x1100, 0x1180, 0x1300);
        pe.bytes[0x300] = 1 | (1 << 3);
        put32(&mut pe, 0x1304, 0x1500);
        put32(&mut pe, 0x1308, u32::MAX);
        c_handler(&mut pe);
        assert!(
            format!("{:#}", pe.metadata_references().unwrap_err())
                .contains("scope table size overflow")
        );
        put32(&mut pe, 0x1308, 0x100);
        assert!(
            format!("{:#}", pe.metadata_references().unwrap_err())
                .contains("C scope table at 0x1308")
        );
        pe.imports[0].name = "__CxxFrameHandler3".into();
        let references = pe.metadata_references().unwrap().references;
        assert!(has_opaque(&references, 0x1100));
        assert!(has_opaque(&references, 0x1500));
    }

    #[test]
    fn enclave_import_addresses_are_enumerated() {
        let mut pe = fixture();
        pe.data_directories[10] = (0x1200, 256);
        put32(&mut pe, 0x1200, 256);
        put64(&mut pe, 0x12f8, 0x140001400);
        put32(&mut pe, 0x1400, 80);
        put32(&mut pe, 0x140c, 1);
        put32(&mut pe, 0x1410, 0x1500);
        put32(&mut pe, 0x1414, 80);
        put32(&mut pe, 0x1548, 0x1600);
        pe.bytes[0x600..0x608].copy_from_slice(b"lib.dll\0");
        let references = pe.metadata_references().unwrap().references;
        for (source, target) in [(0x1410, 0x1500), (0x1548, 0x1600)] {
            assert!(
                references
                    .iter()
                    .any(|reference| reference.source == Rva::new(source)
                        && reference.target == Rva::new(target))
            );
        }
        put32(&mut pe, 0x140c, u32::MAX);
        assert!(pe.metadata_references().is_err());
    }

    #[test]
    fn volatile_accesses_and_ranges_pin_interior_runtime_owners() {
        let mut pe = fixture();
        pe.data_directories[10] = (0x1200, 264);
        put32(&mut pe, 0x1200, 264);
        put64(&mut pe, 0x1300, 0x140001400);
        put32(&mut pe, 0x1400, 24);
        put32(&mut pe, 0x1408, 0x1500);
        put32(&mut pe, 0x140c, 4);
        put32(&mut pe, 0x1410, 0x1510);
        put32(&mut pe, 0x1414, 8);
        put32(&mut pe, 0x1500, 0x1120);
        put32(&mut pe, 0x1510, 0x1160);
        put32(&mut pe, 0x1514, 0x100);
        pe.data_directories[3] = (0x1600, 24);
        runtime(&mut pe, 0x1600, 0x1100, 0x1180, 0x1700);
        runtime(&mut pe, 0x160c, 0x11a0, 0x1200, 0x1700);
        pe.bytes[0x700] = 1;
        for (min, max) in [(3_u16, 3_u16), (0x8003, 0x8003), (1, 0x8003), (0x8001, 3)] {
            put32(&mut pe, 0x1404, u32::from(min) | (u32::from(max) << 16));
            let references = pe.metadata_references().unwrap().references;
            for target in [0x1120, 0x1160, 0x11a0, 0x1260] {
                assert!(
                    has_opaque(&references, target),
                    "missing opaque volatile target {target:#x}"
                );
            }
        }
        for (field, value) in [
            (0x1400, 23),
            (0x1400, 28),
            (0x1404, 3 | (2 << 16)),
            (0x1404, 0x8003 | (0x8002 << 16)),
            (0x1408, 0),
            (0x1408, 0x1ffe),
            (0x140c, 0),
            (0x140c, 5),
            (0x140c, 0xc00),
            (0x1410, 0),
            (0x1410, 0x1ffc),
            (0x1414, 0),
            (0x1414, 7),
            (0x1414, 0xb00),
            (0x1510, 0),
            (0x1510, 0x2000),
            (0x1514, 0),
            (0x1514, u32::MAX),
            (0x1514, 0xf00),
        ] {
            let original = read_u32(pe.slice_at_rva(field).unwrap(), 0).unwrap();
            put32(&mut pe, field, value);
            assert!(
                pe.metadata_references().is_err(),
                "accepted malformed volatile field {field:#x} = {value:#x}"
            );
            put32(&mut pe, field, original);
        }
    }

    #[test]
    fn pogo_numeric_signature_preserves_range_reference() {
        let mut pe = fixture();
        pe.data_directories[6] = (0x1200, 28);
        put32(&mut pe, 0x120c, 13);
        put32(&mut pe, 0x1210, 16);
        put32(&mut pe, 0x1214, 0x1400);
        put32(&mut pe, 0x1218, 0x400);
        put32(&mut pe, 0x1400, 0x4c54_4347);
        put32(&mut pe, 0x1404, 0x1100);
        put32(&mut pe, 0x1408, 0x10);
        pe.bytes[0x40c..0x410].copy_from_slice(b"f\0\0\0");
        let references = pe.metadata_references().unwrap().references;
        assert!(references.contains(&HostReference {
            source: Rva::new(0x1404),
            target: Rva::new(0x1100),
            kind: ReferenceKind::ImageRelative,
        }));
        pe.bytes[0x400..0x404].copy_from_slice(b"LTCG");
        assert!(pe.metadata_references().is_err());
    }

    #[test]
    fn chpe_load_configuration_is_rejected() {
        let mut pe = fixture();
        pe.data_directories[10] = (0x1200, 208);
        put32(&mut pe, 0x1200, 208);
        put64(&mut pe, 0x12c8, 0x140001500);
        assert!(pe.metadata_references().is_err());
    }
}
