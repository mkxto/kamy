//! PE parser and emitter: headers, sections, .reloc, .pdata/.xdata, imports/exports.

mod exports;
mod imports;
mod pdata;
mod reloc;

use kamy_core::{Machine, Module, Relocation, Rva, Section, SectionFlags, Symbol, SymbolKind};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const MAX_DATA_DIRECTORIES: usize = 16;
const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_BASERELOC: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum PeError {
    #[error("input truncated or out of bounds")]
    Truncated,
    #[error("bad DOS signature (expected MZ)")]
    BadDosSignature,
    #[error("bad PE signature (expected PE\\0\\0)")]
    BadPeSignature,
    #[error("unsupported optional-header magic (expected PE32+ 0x20b)")]
    BadOptionalMagic,
    #[error("unsupported machine (expected x86-64 0x8664)")]
    UnsupportedMachine,
    #[error("malformed PE: {0}")]
    Malformed(&'static str),
}

struct SectionRecord {
    name: String,
    rva: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
}

pub struct PeFile {
    bytes: Vec<u8>,
    image_base: u64,
    entry_point: u32,
    sections: Vec<SectionRecord>,
    data_directories: Vec<(u32, u32)>,
    relocations: Vec<Relocation>,
    pdata_begins: Vec<u32>,
    exports: Vec<exports::ExportEntry>,
    imports: Vec<imports::ImportEntry>,
}

impl PeFile {
    pub fn parse(bytes: &[u8]) -> Result<PeFile, PeError> {
        if bytes.get(0..2).ok_or(PeError::Truncated)? != b"MZ" {
            return Err(PeError::BadDosSignature);
        }
        let e_lfanew = read_u32(bytes, 0x3c)? as usize;

        if bytes
            .get(e_lfanew..e_lfanew + 4)
            .ok_or(PeError::Truncated)?
            != b"PE\0\0"
        {
            return Err(PeError::BadPeSignature);
        }

        let coff = e_lfanew + 4;
        if read_u16(bytes, coff)? != 0x8664 {
            return Err(PeError::UnsupportedMachine);
        }
        let num_sections = read_u16(bytes, coff + 2)? as usize;
        let size_of_optional = read_u16(bytes, coff + 16)? as usize;

        let opt = coff + 20;
        if read_u16(bytes, opt)? != 0x20b {
            return Err(PeError::BadOptionalMagic);
        }
        let entry_point = read_u32(bytes, opt + 16)?;
        let image_base = read_u64(bytes, opt + 24)?;
        let num_dirs = (read_u32(bytes, opt + 108)? as usize).min(MAX_DATA_DIRECTORIES);

        let mut data_directories = Vec::with_capacity(num_dirs);
        for i in 0..num_dirs {
            let base = opt + 112 + i * 8;
            data_directories.push((read_u32(bytes, base)?, read_u32(bytes, base + 4)?));
        }

        let section_table = opt + size_of_optional;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let b = section_table + i * 40;
            let name_raw = bytes.get(b..b + 8).ok_or(PeError::Truncated)?;
            let name_len = name_raw.iter().position(|&c| c == 0).unwrap_or(8);
            sections.push(SectionRecord {
                name: String::from_utf8_lossy(&name_raw[..name_len]).into_owned(),
                virtual_size: read_u32(bytes, b + 8)?,
                rva: read_u32(bytes, b + 12)?,
                raw_size: read_u32(bytes, b + 16)?,
                raw_pointer: read_u32(bytes, b + 20)?,
                characteristics: read_u32(bytes, b + 36)?,
            });
        }

        let mut pe = PeFile {
            bytes: bytes.to_vec(),
            image_base,
            entry_point,
            sections,
            data_directories,
            relocations: Vec::new(),
            pdata_begins: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
        };

        pe.relocations = pe
            .directory_slice(DIR_BASERELOC)
            .map_or_else(Vec::new, reloc::parse_relocations);
        pe.pdata_begins = pe
            .directory_slice(DIR_EXCEPTION)
            .map_or_else(Vec::new, pdata::parse_pdata);
        pe.exports = match pe.data_directories.get(DIR_EXPORT).copied() {
            Some((va, size)) if va != 0 => exports::parse_exports(&pe, va, size),
            _ => Vec::new(),
        };
        pe.imports = match pe.data_directories.get(DIR_IMPORT).copied() {
            Some((va, size)) if va != 0 => imports::parse_imports(&pe, va, size),
            _ => Vec::new(),
        };

        Ok(pe)
    }

    pub fn to_module(&self) -> Module {
        let sections = self
            .sections
            .iter()
            .map(|s| {
                let start = s.raw_pointer as usize;
                let want = s.raw_size.min(s.virtual_size) as usize;
                let data = self
                    .bytes
                    .get(start..)
                    .map(|tail| tail[..want.min(tail.len())].to_vec())
                    .unwrap_or_default();
                Section {
                    name: s.name.clone(),
                    rva: Rva::new(s.rva),
                    virtual_size: s.virtual_size,
                    data,
                    flags: section_flags(s.characteristics),
                }
            })
            .collect();

        let mut symbols = Vec::new();
        if self.entry_point != 0 {
            symbols.push(Symbol {
                name: "__entry".to_string(),
                rva: Rva::new(self.entry_point),
                kind: SymbolKind::EntryPoint,
            });
        }
        for e in &self.exports {
            symbols.push(Symbol {
                name: e.name.clone(),
                rva: Rva::new(e.rva),
                kind: SymbolKind::Export,
            });
        }
        for i in &self.imports {
            symbols.push(Symbol {
                name: i.name.clone(),
                rva: Rva::new(i.iat_rva),
                kind: SymbolKind::Import,
            });
        }

        Module {
            image_base: self.image_base,
            machine: Machine::X64,
            entry_point: (self.entry_point != 0).then(|| Rva::new(self.entry_point)),
            sections,
            symbols,
            relocations: self.relocations.clone(),
            functions: Vec::new(),
        }
    }

    /// Deduplicated function-entry seeds: entry point, export targets and
    /// `.pdata` `BeginAddress` values, in discovery order.
    pub fn seeds(&self) -> Vec<Rva> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        let mut push = |rva: u32, out: &mut Vec<Rva>| {
            if rva != 0 && seen.insert(rva) {
                out.push(Rva::new(rva));
            }
        };
        push(self.entry_point, &mut out);
        for e in &self.exports {
            push(e.rva, &mut out);
        }
        for &begin in &self.pdata_begins {
            push(begin, &mut out);
        }
        out
    }

    fn directory_slice(&self, index: usize) -> Option<&[u8]> {
        let (va, size) = self.data_directories.get(index).copied()?;
        if va == 0 {
            return None;
        }
        let slice = self.slice_at_rva(va)?;
        Some(&slice[..(size as usize).min(slice.len())])
    }

    /// Bytes from `rva` to the end of its containing section's raw data,
    /// translating the RVA through the section table to a file offset.
    fn slice_at_rva(&self, rva: u32) -> Option<&[u8]> {
        let section = self.sections.iter().find(|s| {
            let span = s.virtual_size.max(s.raw_size);
            rva >= s.rva && rva < s.rva.saturating_add(span)
        })?;
        let delta = (rva - section.rva) as usize;
        let start = (section.raw_pointer as usize).checked_add(delta)?;
        let section_end = (section.raw_pointer as usize)
            .saturating_add(section.raw_size as usize)
            .min(self.bytes.len());
        if start > section_end {
            return None;
        }
        self.bytes.get(start..section_end)
    }

    fn u16_at_rva(&self, rva: u32) -> Option<u16> {
        let s = self.slice_at_rva(rva)?;
        s.get(0..2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
    }

    fn u32_at_rva(&self, rva: u32) -> Option<u32> {
        let s = self.slice_at_rva(rva)?;
        s.get(0..4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }

    fn u64_at_rva(&self, rva: u32) -> Option<u64> {
        let s = self.slice_at_rva(rva)?;
        s.get(0..8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }

    fn read_cstr(&self, rva: u32) -> Option<String> {
        let slice = self.slice_at_rva(rva)?;
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        Some(String::from_utf8_lossy(&slice[..end]).into_owned())
    }
}

fn section_flags(characteristics: u32) -> SectionFlags {
    SectionFlags {
        read: characteristics & IMAGE_SCN_MEM_READ != 0,
        write: characteristics & IMAGE_SCN_MEM_WRITE != 0,
        execute: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PeError> {
    let end = offset.checked_add(2).ok_or(PeError::Truncated)?;
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(PeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PeError> {
    let end = offset.checked_add(4).ok_or(PeError::Truncated)?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(PeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PeError> {
    let end = offset.checked_add(8).ok_or(PeError::Truncated)?;
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(PeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::RelocKind;

    #[test]
    fn characteristics_map_to_section_flags() {
        assert_eq!(
            section_flags(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE),
            SectionFlags {
                read: true,
                write: false,
                execute: true
            }
        );
        assert_eq!(
            section_flags(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
            SectionFlags {
                read: true,
                write: true,
                execute: false
            }
        );
        assert_eq!(section_flags(0), SectionFlags::default());
        assert_eq!(
            section_flags(0xFFFF_FFFF),
            SectionFlags {
                read: true,
                write: true,
                execute: true
            }
        );
    }

    #[test]
    fn reloc_block_parses_entries() {
        // One block over page 0x1000 with three entries:
        //   HighLow @ 0x010, Dir64 @ 0x020, Absolute padder @ 0x000.
        let mut block = Vec::new();
        block.extend_from_slice(&0x0000_1000u32.to_le_bytes()); // PageRVA
        block.extend_from_slice(&(8u32 + 6).to_le_bytes()); // BlockSize: header + 3 entries
        block.extend_from_slice(&((3u16 << 12) | 0x010).to_le_bytes());
        block.extend_from_slice(&((10u16 << 12) | 0x020).to_le_bytes());
        block.extend_from_slice(&0x000u16.to_le_bytes());

        let relocs = reloc::parse_relocations(&block);
        assert_eq!(
            relocs,
            vec![
                Relocation {
                    rva: Rva::new(0x1010),
                    kind: RelocKind::HighLow
                },
                Relocation {
                    rva: Rva::new(0x1020),
                    kind: RelocKind::Dir64
                },
                Relocation {
                    rva: Rva::new(0x1000),
                    kind: RelocKind::Absolute
                },
            ]
        );
    }

    #[test]
    fn reloc_parser_rejects_truncated_block() {
        // BlockSize claims more bytes than present: no panic, no entries.
        let mut block = Vec::new();
        block.extend_from_slice(&0x0000_2000u32.to_le_bytes());
        block.extend_from_slice(&0x0000_FFFFu32.to_le_bytes());
        block.extend_from_slice(&((3u16 << 12) | 0x004).to_le_bytes());
        assert!(reloc::parse_relocations(&block).is_empty());
    }

    #[test]
    fn pdata_yields_begin_addresses() {
        let mut data = Vec::new();
        for &(begin, end, unwind) in &[(0x1000u32, 0x1040u32, 0x5000u32), (0x1040, 0x1080, 0x5010)]
        {
            data.extend_from_slice(&begin.to_le_bytes());
            data.extend_from_slice(&end.to_le_bytes());
            data.extend_from_slice(&unwind.to_le_bytes());
        }
        assert_eq!(pdata::parse_pdata(&data), vec![0x1000, 0x1040]);
    }

    #[test]
    fn pdata_ignores_partial_trailing_record() {
        let mut data = 0x2000u32.to_le_bytes().to_vec();
        data.extend_from_slice(&0x2040u32.to_le_bytes());
        data.extend_from_slice(&0x6000u32.to_le_bytes());
        data.extend_from_slice(&[0xAA, 0xBB]); // dangling partial record
        assert_eq!(pdata::parse_pdata(&data), vec![0x2000]);
    }

    #[test]
    fn parse_rejects_bad_dos_signature() {
        assert!(matches!(
            PeFile::parse(b"ZM\x00\x00"),
            Err(PeError::BadDosSignature)
        ));
    }

    #[test]
    fn parse_rejects_truncated_input() {
        assert!(matches!(PeFile::parse(b"MZ"), Err(PeError::Truncated)));
        assert!(PeFile::parse(&[]).is_err());
    }
}
