use anyhow::{Context, Result, bail, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw: u32,
    pub flags: u32,
}

pub struct Pe {
    pub bytes: Vec<u8>,
    pub image_base: u64,
    pub entry: u32,
    pub image_size: u32,
    pub sections: Vec<Section>,
    pub directories: [(u32, u32); 16],
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .context("truncated PE word")?
            .try_into()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("truncated PE dword")?
            .try_into()?,
    ))
}

impl Pe {
    pub fn read(path: &std::path::Path) -> Result<Self> {
        Self::parse(std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        ensure!(bytes.get(..2) == Some(b"MZ"), "missing DOS signature");
        let nt = u32_at(&bytes, 0x3c)? as usize;
        ensure!(
            bytes.get(nt..nt + 4) == Some(b"PE\0\0"),
            "missing PE signature"
        );
        ensure!(u16_at(&bytes, nt + 4)? == 0x8664, "fixture is not AMD64");
        let optional = nt + 24;
        ensure!(u16_at(&bytes, optional)? == 0x20b, "fixture is not PE32+");
        let image_base = u64::from_le_bytes(
            bytes
                .get(optional + 24..optional + 32)
                .context("missing preferred base")?
                .try_into()?,
        );
        let mut directories = [(0, 0); 16];
        ensure!(
            u32_at(&bytes, optional + 108)? >= 16,
            "PE has fewer than sixteen directories"
        );
        for (index, directory) in directories.iter_mut().enumerate() {
            *directory = (
                u32_at(&bytes, optional + 112 + index * 8)?,
                u32_at(&bytes, optional + 116 + index * 8)?,
            );
        }
        let table = optional + usize::from(u16_at(&bytes, nt + 20)?);
        let mut sections = Vec::new();
        for index in 0..usize::from(u16_at(&bytes, nt + 6)?) {
            let offset = table + index * 40;
            let name = bytes
                .get(offset..offset + 8)
                .context("truncated section name")?;
            let end = name.iter().position(|byte| *byte == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8(name[..end].to_vec())?,
                virtual_size: u32_at(&bytes, offset + 8)?,
                rva: u32_at(&bytes, offset + 12)?,
                raw_size: u32_at(&bytes, offset + 16)?,
                raw: u32_at(&bytes, offset + 20)?,
                flags: u32_at(&bytes, offset + 36)?,
            });
        }
        Ok(Self {
            entry: u32_at(&bytes, optional + 16)?,
            image_size: u32_at(&bytes, optional + 56)?,
            bytes,
            image_base,
            sections,
            directories,
        })
    }

    pub fn section(&self, rva: u32) -> Result<&Section> {
        self.sections
            .iter()
            .find(|section| {
                rva >= section.rva && rva - section.rva < section.virtual_size.max(section.raw_size)
            })
            .context("RVA has no mapped section")
    }

    pub fn slice(&self, rva: u32, size: usize) -> Result<&[u8]> {
        let section = self.section(rva)?;
        let offset = rva - section.rva;
        ensure!(
            u64::from(offset) + size as u64 <= u64::from(section.raw_size),
            "RVA range is not file-backed"
        );
        let raw = section.raw as usize + offset as usize;
        self.bytes
            .get(raw..raw + size)
            .context("truncated section bytes")
    }

    pub fn dword(&self, rva: u32) -> Result<u32> {
        u32_at(self.slice(rva, 4)?, 0)
    }

    pub fn qword(&self, rva: u32) -> Result<u64> {
        Ok(u64::from_le_bytes(self.slice(rva, 8)?.try_into()?))
    }

    pub fn string(&self, rva: u32) -> Result<String> {
        let section = self.section(rva)?;
        let remaining = section
            .raw_size
            .checked_sub(rva - section.rva)
            .context("string in zero-fill")?;
        let bytes = self.slice(rva, remaining as usize)?;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .context("unterminated PE string")?;
        Ok(String::from_utf8(bytes[..end].to_vec())?)
    }

    pub fn exports(&self) -> Result<BTreeMap<String, u32>> {
        let (directory, size) = self.directories[0];
        ensure!(
            directory != 0 && size >= 40,
            "host fixture has no export directory"
        );
        let mut result = BTreeMap::new();
        let functions = self.dword(directory + 28)?;
        let names = self.dword(directory + 32)?;
        let ordinals = self.dword(directory + 36)?;
        for index in 0..self.dword(directory + 24)? {
            let name = self.string(self.dword(names + index * 4)?)?;
            let ordinal = u16_at(self.slice(ordinals + index * 2, 2)?, 0)?;
            let address = self.dword(functions + u32::from(ordinal) * 4)?;
            ensure!(
                address < directory || address >= directory + size,
                "fixture export is a forwarder"
            );
            result.insert(name, address);
        }
        Ok(result)
    }

    pub fn imports(&self) -> Result<BTreeMap<(String, String), u32>> {
        let (directory, size) = self.directories[1];
        let mut result = BTreeMap::new();
        if directory == 0 {
            return Ok(result);
        }
        let mut descriptor = directory;
        while descriptor
            < directory
                .checked_add(size)
                .context("import size overflow")?
        {
            let lookup = self.dword(descriptor)?;
            let name = self.dword(descriptor + 12)?;
            let iat = self.dword(descriptor + 16)?;
            if lookup == 0 && name == 0 && iat == 0 {
                return Ok(result);
            }
            ensure!(
                lookup != 0 && iat != 0,
                "fixture import lost separate lookup/IAT"
            );
            let library = self.string(name)?.to_ascii_lowercase();
            let mut index = 0;
            loop {
                let value = self.qword(lookup + index * 8)?;
                if value == 0 {
                    break;
                }
                let symbol = if value & (1 << 63) != 0 {
                    format!("#{}", value & 0xffff)
                } else {
                    self.string(u32::try_from(value)? + 2)?
                };
                ensure!(
                    self.qword(iat + index * 8)? == value,
                    "on-disk IAT no longer agrees with import lookup"
                );
                let (iat_directory, iat_size) = self.directories[12];
                ensure!(
                    iat + index * 8 >= iat_directory
                        && u64::from(iat + index * 8) + 8
                            <= u64::from(iat_directory) + u64::from(iat_size),
                    "IAT slot outside active IAT directory"
                );
                result.insert((library.clone(), symbol), iat + index * 8);
                index += 1;
            }
            descriptor += 20;
        }
        bail!("import descriptors lack an in-directory terminator")
    }

    pub fn runtime_ranges(&self) -> Result<Vec<(u32, u32, u32)>> {
        let (directory, size) = self.directories[3];
        ensure!(
            directory != 0 && size > 0 && size % 12 == 0,
            "invalid active Exception directory"
        );
        let mut result = Vec::new();
        let mut previous_end = 0;
        for offset in (0..size).step_by(12) {
            let begin = self.dword(directory + offset)?;
            let end = self.dword(directory + offset + 4)?;
            let unwind = self.dword(directory + offset + 8)?;
            ensure!(
                begin >= previous_end && begin < end,
                "Exception ranges are not sorted/nonoverlapping"
            );
            ensure!(
                self.section(begin)?.flags & 0x2000_0000 != 0 && end <= self.image_size,
                "Exception range points outside executable code"
            );
            ensure!(
                matches!(self.slice(unwind, 4)?[0] & 7, 1 | 2),
                "invalid AMD64 unwind version"
            );
            previous_end = end;
            result.push((begin, end, unwind));
        }
        Ok(result)
    }

    pub fn relocations(&self) -> Result<BTreeSet<u32>> {
        let (directory, size) = self.directories[5];
        ensure!(
            directory != 0 && size > 0,
            "missing active BaseReloc directory"
        );
        let mut result = BTreeSet::new();
        let mut cursor = 0;
        let mut previous_page = None;
        while cursor < size {
            let page = self.dword(directory + cursor)?;
            let block_size = self.dword(directory + cursor + 4)?;
            ensure!(
                page & 0xfff == 0
                    && block_size >= 8
                    && block_size % 4 == 0
                    && block_size <= size - cursor,
                "invalid BaseReloc block"
            );
            ensure!(
                previous_page.is_none_or(|previous| page > previous),
                "BaseReloc pages are not strictly sorted"
            );
            previous_page = Some(page);
            for offset in (8..block_size).step_by(2) {
                let entry = u16_at(self.slice(directory + cursor + offset, 2)?, 0)?;
                match entry >> 12 {
                    0 => {}
                    10 => {
                        let field = page
                            .checked_add(u32::from(entry & 0xfff))
                            .context("relocation overflow")?;
                        self.slice(field, 8)?;
                        ensure!(result.insert(field), "duplicate DIR64 relocation field");
                    }
                    kind => bail!("unexpected AMD64 base relocation kind {kind}"),
                }
            }
            cursor += block_size;
        }
        ensure!(
            cursor == size,
            "BaseReloc blocks do not fill active directory"
        );
        Ok(result)
    }
}
