use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use kamy_core::Rva;

use crate::PeFile;

mod coff;
mod producer;

const MAGIC: &[u8; 8] = b"KAMYMOD\0";
const VERSION: u32 = 1;
const HEADER_SIZE: usize = 32;
const IMAGE_EXECUTE: u32 = 0x2000_0000;
const METADATA_SECTION: &str = ".kmod";

#[derive(Debug, Clone)]
pub struct AuthoredModule {
    pub image: Vec<u8>,
    pub entry: Rva,
    pub code: Vec<CodeSymbol>,
    pub data: Vec<DataSymbol>,
    pub references: Vec<ModuleReference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSymbol {
    pub name: String,
    pub start: Rva,
    pub end: Rva,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSymbol {
    pub name: String,
    pub start: Rva,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleReference {
    pub source: Rva,
    pub target: ModuleTarget,
    /// COFF field addend; REL32 can include a trailing-immediate adjustment.
    pub addend: i64,
    pub kind: ModuleReferenceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleTarget {
    /// Compiler symbol base in the original module, excluding the addend.
    Rva(Rva),
    /// Host image base, not the authored DLL's original load base.
    ImageBase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleReferenceKind {
    Absolute64,
    ImageRelative32,
    Relative32 { bias: u8 },
}

#[derive(Debug, Clone, Copy)]
struct Placement {
    object: u32,
    section: u32,
    offset: u32,
    size: u32,
    rva: u32,
}

pub fn build(objects: &[PathBuf], output: &Path, entry: &str, linker: &Path) -> anyhow::Result<()> {
    producer::build(objects, output, entry, linker)
}

impl AuthoredModule {
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let pe = PeFile::parse(bytes).context("authored module PE")?;
        validate_image(&pe, bytes)?;
        let mut sections = pe
            .section_headers()
            .iter()
            .enumerate()
            .filter(|(_, s)| s.name == METADATA_SECTION);
        let (index, section) = sections
            .next()
            .context("DLL has no authored .kmod metadata; build it with the SDK module producer")?;
        ensure!(
            sections.next().is_none(),
            "duplicate .kmod metadata sections"
        );
        ensure!(
            section.characteristics & 0xa000_0000 == 0,
            "authored metadata must not be writable or executable"
        );
        let raw = pe.section_data(index).context("truncated .kmod section")?;
        let metadata = raw
            .get(..section.virtual_size as usize)
            .context("truncated authored metadata")?;
        let DecodedMetadata {
            entry,
            objects,
            placements,
        } = decode(metadata)?;
        let authored = coff::describe(&pe, &objects, &placements, entry)?;
        validate_base_relocations(&pe, &authored.references)?;
        Ok(Self {
            image: pe.bytes,
            entry: Rva::new(entry),
            ..authored
        })
    }
}

fn validate_image(pe: &PeFile, bytes: &[u8]) -> anyhow::Result<()> {
    ensure!(pe.is_dll(), "authored module must be an AMD64 DLL");
    ensure!(
        pe.entry_point == 0,
        "authored module DLL must use /noentry; callback is metadata-selected"
    );
    let mut virtual_ranges = Vec::new();
    let mut file_ranges = Vec::new();
    for section in pe.section_headers() {
        let end = section
            .rva
            .checked_add(section.virtual_size)
            .context("module section RVA overflow")?;
        ensure!(
            section.virtual_size == 0 || section.rva != 0,
            "module section overlaps image headers"
        );
        if section.virtual_size != 0 {
            virtual_ranges.push((section.rva, end));
        }
        if section.raw_size != 0 {
            let end = section
                .raw_pointer
                .checked_add(section.raw_size)
                .context("module section file range overflow")?;
            ensure!(
                end as usize <= bytes.len(),
                "module section {} is truncated",
                section.name
            );
            file_ranges.push((section.raw_pointer, end));
        }
    }
    for mut ranges in [virtual_ranges, file_ranges] {
        ranges.sort_unstable();
        ensure!(
            ranges.windows(2).all(|p| p[0].1 <= p[1].0),
            "module sections overlap"
        );
    }
    for index in 0..16 {
        let Some((rva, size)) = pe.data_directory(index) else {
            continue;
        };
        ensure!(
            (rva.get() == 0) == (size == 0),
            "module directory {index} has inconsistent bounds"
        );
        if size == 0 {
            continue;
        }
        let expected = match index {
            3 => ".pdata",
            5 => ".reloc",
            _ => bail!(
                "authored module directory {index} is unsupported; imports, TLS, exports, load configuration and managed modules require explicit loader support"
            ),
        };
        let end = rva
            .get()
            .checked_add(size)
            .context("module directory RVA overflow")?;
        let section = pe
            .section_headers()
            .iter()
            .find(|s| s.rva == rva.get() && s.virtual_size == size && s.name == expected)
            .with_context(|| {
                format!("module directory {index} must occupy its own unmerged {expected} section")
            })?;
        ensure!(
            section.characteristics & 0xa000_0000 == 0,
            "module directory {index} has executable/writable storage"
        );
        ensure!(
            mapped(pe, rva.get(), end - rva.get(), true),
            "module directory {index} is not file-backed"
        );
        if index == 3 {
            ensure!(
                size % 12 == 0,
                "module exception directory has a partial runtime function record"
            );
        }
    }
    let runtime = pe.runtime_functions();
    for section in pe.section_headers().iter().filter(|s| s.virtual_size != 0) {
        if let Some(index) = match section.name.as_str() {
            ".pdata" => Some(3),
            ".reloc" => Some(5),
            _ => None,
        } {
            ensure!(
                pe.data_directory(index).is_some_and(
                    |(rva, size)| rva.get() == section.rva && size == section.virtual_size
                ),
                "orphaned module directory section {}",
                section.name
            );
        }
        if section.name == ".kxdata" {
            ensure!(
                section.characteristics & 0xa000_0000 == 0,
                "module unwind storage must be read-only and nonexecutable"
            );
            ensure!(
                runtime.iter().any(|f| f.unwind.get() >= section.rva
                    && f.unwind.get() < section.rva + section.virtual_size),
                "module unwind section has no runtime function provenance"
            );
        }
    }
    for function in runtime {
        ensure!(
            function.begin < function.end
                && mapped(
                    pe,
                    function.begin.get(),
                    function.end.get() - function.begin.get(),
                    true
                ),
            "module runtime function has invalid code bounds"
        );
        ensure!(
            pe.section_headers()
                .iter()
                .any(|s| s.characteristics & IMAGE_EXECUTE != 0
                    && function.begin.get() >= s.rva
                    && function.end.get() <= s.rva + s.virtual_size),
            "module runtime function is not executable"
        );
        ensure!(
            pe.section_headers().iter().any(|s| s.name == ".kxdata"
                && function.unwind.get() >= s.rva
                && function.unwind.get() < s.rva + s.virtual_size),
            "module unwind record must use dedicated .kxdata storage"
        );
        let header = field(pe, function.unwind.get(), 4)?;
        ensure!(
            header[0] & 7 == 1 && header[0] >> 3 & !7 == 0,
            "unsupported module unwind version/flags"
        );
        let flags = header[0] >> 3;
        ensure!(
            flags & 4 == 0 || flags & 3 == 0,
            "module unwind record combines chained and language-handler flags"
        );
        let length = (4 + u32::from(header[2]) * 2 + 3) & !3;
        field(
            pe,
            function.unwind.get(),
            (length
                + if flags & 4 != 0 {
                    12
                } else if flags & 3 != 0 {
                    4
                } else {
                    0
                }) as usize,
        )?;
    }
    Ok(())
}

fn mapped(pe: &PeFile, start: u32, size: u32, file_backed: bool) -> bool {
    let Some(end) = start.checked_add(size) else {
        return false;
    };
    pe.section_headers().iter().any(|s| {
        s.name != METADATA_SECTION
            && start >= s.rva
            && end
                <= s.rva.saturating_add(if file_backed {
                    s.virtual_size.min(s.raw_size)
                } else {
                    s.virtual_size
                })
    })
}

fn field(pe: &PeFile, rva: u32, size: usize) -> anyhow::Result<&[u8]> {
    ensure!(
        mapped(pe, rva, u32::try_from(size)?, true),
        "reference at RVA {rva:#x} crosses initialized contribution storage"
    );
    pe.slice_at_rva(rva)
        .and_then(|s| s.get(..size))
        .context("reference field is truncated")
}

fn reference_target(pe: &PeFile, source: u32, kind: ModuleReferenceKind) -> anyhow::Result<i64> {
    match kind {
        ModuleReferenceKind::Absolute64 => {
            let value = u64::from_le_bytes(field(pe, source, 8)?.try_into()?);
            i64::try_from(i128::from(value) - i128::from(pe.image_base))
                .context("absolute module reference exceeds signed expression range")
        }
        ModuleReferenceKind::ImageRelative32 => Ok(i64::from(u32::from_le_bytes(
            field(pe, source, 4)?.try_into()?,
        ))),
        ModuleReferenceKind::Relative32 { bias } => {
            ensure!(bias <= 5, "invalid AMD64 REL32 bias {bias}");
            let displacement = i32::from_le_bytes(field(pe, source, 4)?.try_into()?);
            Ok(i64::from(source) + 4 + i64::from(bias) + i64::from(displacement))
        }
    }
}

fn validate_base_relocations(pe: &PeFile, references: &[ModuleReference]) -> anyhow::Result<()> {
    let mut expected: Vec<_> = references
        .iter()
        .filter(|r| r.kind == ModuleReferenceKind::Absolute64)
        .map(|r| r.source.get())
        .collect();
    let mut actual = Vec::new();
    if let Some((rva, size)) = pe.data_directory(5).filter(|(_, n)| *n != 0) {
        let data = field(pe, rva.get(), size as usize)?;
        let mut offset = 0usize;
        while offset < data.len() {
            let page = u32_at(data, offset)?;
            let size = u32_at(data, offset + 4)? as usize;
            ensure!(
                size >= 8 && size % 4 == 0,
                "malformed module base relocation block"
            );
            let block = data
                .get(
                    offset + 8
                        ..offset
                            .checked_add(size)
                            .context("relocation block overflow")?,
                )
                .context("truncated module relocation block")?;
            for entry in block.chunks_exact(2) {
                let word = u16::from_le_bytes(entry.try_into()?);
                match word >> 12 {
                    0 => {}
                    10 => actual.push(
                        page.checked_add(u32::from(word & 0xfff))
                            .context("base relocation RVA overflow")?,
                    ),
                    kind => bail!("unsupported authored module base relocation type {kind}"),
                }
            }
            offset += size;
        }
    }
    expected.sort_unstable();
    actual.sort_unstable();
    ensure!(
        expected == actual,
        "module base relocations do not match compiler-authored ADDR64 provenance"
    );
    Ok(())
}

fn encode(entry: u32, objects: &[Vec<u8>], placements: &[Placement]) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    for word in [
        VERSION,
        0,
        entry,
        u32::try_from(objects.len())?,
        u32::try_from(placements.len())?,
        0,
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for object in objects {
        bytes.extend_from_slice(&u32::try_from(object.len())?.to_le_bytes());
        bytes.extend_from_slice(object);
    }
    for p in placements {
        for word in [p.object, p.section, p.offset, p.size, p.rva] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    let length = u32::try_from(bytes.len()).context("authored metadata exceeds 4 GiB")?;
    bytes[12..16].copy_from_slice(&length.to_le_bytes());
    Ok(bytes)
}

struct DecodedMetadata<'a> {
    entry: u32,
    objects: Vec<&'a [u8]>,
    placements: Vec<Placement>,
}

fn decode(bytes: &[u8]) -> anyhow::Result<DecodedMetadata<'_>> {
    ensure!(
        bytes.get(..8) == Some(MAGIC.as_slice()),
        "invalid authored module metadata magic"
    );
    ensure!(
        u32_at(bytes, 8)? == VERSION,
        "unsupported authored module metadata version"
    );
    ensure!(
        u32_at(bytes, 12)? as usize == bytes.len(),
        "authored metadata length mismatch"
    );
    ensure!(
        u32_at(bytes, 28)? == 0,
        "unsupported authored metadata flags"
    );
    let entry = u32_at(bytes, 16)?;
    let object_count = u32_at(bytes, 20)? as usize;
    let placement_count = u32_at(bytes, 24)? as usize;
    ensure!(
        object_count != 0 && object_count <= bytes.len() / 4,
        "invalid authored object count"
    );
    let mut cursor = HEADER_SIZE;
    let mut objects = Vec::with_capacity(object_count);
    for _ in 0..object_count {
        let size = u32_at(bytes, cursor)? as usize;
        cursor = cursor.checked_add(4).context("metadata offset overflow")?;
        let end = cursor
            .checked_add(size)
            .context("metadata object length overflow")?;
        objects.push(
            bytes
                .get(cursor..end)
                .context("truncated authored object provenance")?,
        );
        cursor = end;
    }
    ensure!(
        placement_count.checked_mul(20) == bytes.len().checked_sub(cursor),
        "authored placement table length mismatch"
    );
    let mut placements = Vec::with_capacity(placement_count);
    for row in bytes[cursor..].chunks_exact(20) {
        placements.push(Placement {
            object: u32_at(row, 0)?,
            section: u32_at(row, 4)?,
            offset: u32_at(row, 8)?,
            size: u32_at(row, 12)?,
            rva: u32_at(row, 16)?,
        });
    }
    Ok(DecodedMetadata {
        entry,
        objects,
        placements,
    })
}

fn u32_at(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
    let end = offset.checked_add(4).context("metadata offset overflow")?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .context("truncated authored metadata")?
            .try_into()?,
    ))
}

#[cfg(test)]
mod tests;
