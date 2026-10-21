use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, bail, ensure};
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget, SectionFlags,
    SymbolKind,
};

use super::{
    AuthoredModule, CodeSymbol, DataSymbol, ModuleReference, ModuleReferenceKind, ModuleTarget,
    Placement, field, mapped, reference_target, u32_at,
};
use crate::PeFile;
use kamy_core::Rva;

pub(super) fn parse(bytes: &[u8]) -> anyhow::Result<object::File<'_>> {
    let file = object::File::parse(bytes).context("invalid compiled COFF object")?;
    ensure!(
        file.format() == object::BinaryFormat::Coff
            && file.architecture() == object::Architecture::X86_64
            && file.kind() == object::ObjectKind::Relocatable,
        "SDK inputs must be compiled AMD64 COFF objects, not archives, DLLs or LLVM bitcode"
    );
    for section in file.sections() {
        let name = section.name().context("non-UTF-8 COFF section name")?;
        ensure!(
            !matches!(name, ".kmod" | ".kxdata" | ".kidata"),
            "COFF section {name} is reserved by the SDK producer"
        );
        ensure!(
            !name.starts_with(".CRT") && !name.starts_with(".tls"),
            "COFF section {name} requires unsupported module initialization/TLS semantics"
        );
        if name == ".drectve" {
            let text =
                std::str::from_utf8(section.data()?).context("invalid COFF linker directives")?;
            for directive in text.trim_matches('\0').split_whitespace() {
                let lower = directive.to_ascii_lowercase();
                if lower.starts_with("/include:") || lower.starts_with("-include:") {
                    let (_, name) = directive
                        .split_once(':')
                        .context("missing retained symbol name")?;
                    ensure!(
                        file.symbols().any(|symbol| symbol.is_definition()
                            && symbol.name().is_ok_and(|defined| defined == name)),
                        "retained Rust symbol {name} has no compiled definition"
                    );
                    continue;
                }
                ensure!(
                    lower.starts_with("/defaultlib:")
                        || lower.starts_with("-defaultlib:")
                        || lower.starts_with("/failifmismatch:")
                        || lower.starts_with("-failifmismatch:"),
                    "unsupported COFF linker directive {directive}; module layout and link inputs must remain producer-controlled"
                );
            }
        }
    }
    for symbol in file.symbols() {
        ensure!(
            !symbol.is_common(),
            "COFF common symbol {} has no authored contribution and is unsupported in Rust SDK objects",
            symbol.name().unwrap_or("<invalid>")
        );
    }
    Ok(file)
}

pub(super) fn retained<'a>(section: &impl ObjectSection<'a>) -> anyhow::Result<bool> {
    let SectionFlags::Coff { characteristics } = section.flags() else {
        bail!("expected COFF section characteristics")
    };
    let name = section.name()?;
    Ok(section.size() != 0
        && !characteristics
            .intersects(object::pe::IMAGE_SCN_LNK_REMOVE | object::pe::IMAGE_SCN_LNK_INFO)
        && !name.starts_with(".debug")
        && !name.starts_with(".llvm"))
}

pub(super) fn locate(
    placements: &[Placement],
    object: u32,
    section: u32,
    offset: u32,
    size: u32,
) -> anyhow::Result<u32> {
    let end = offset
        .checked_add(size)
        .context("COFF contribution offset overflow")?;
    let p = placements
        .iter()
        .find(|p| {
            p.object == object
                && p.section == section
                && offset >= p.offset
                && offset < p.offset.saturating_add(p.size)
                && end <= p.offset.saturating_add(p.size)
        })
        .or_else(|| {
            (size == 0)
                .then(|| {
                    placements
                        .iter()
                        .filter(|p| {
                            p.object == object
                                && p.section == section
                                && p.offset.checked_add(p.size) == Some(offset)
                        })
                        .max_by_key(|p| p.offset)
                })
                .flatten()
        })
        .context("COFF symbol/reference crosses an absent or split contribution")?;
    p.rva
        .checked_add(offset - p.offset)
        .context("linked COFF RVA overflow")
}

pub(super) fn describe(
    pe: &PeFile,
    objects: &[impl AsRef<[u8]>],
    placements: &[Placement],
    entry: u32,
) -> anyhow::Result<AuthoredModule> {
    let files: Vec<_> = objects
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            parse(bytes.as_ref()).with_context(|| format!("authored COFF object {i}"))
        })
        .collect::<anyhow::Result<_>>()?;
    let mut globals: BTreeMap<String, Vec<(u32, u32, u32)>> = BTreeMap::new();
    for (index, file) in files.iter().enumerate() {
        for symbol in file
            .symbols()
            .filter(|s| s.is_global() && s.is_definition())
        {
            if let Some(section) = symbol.section_index() {
                globals.entry(symbol.name()?.to_owned()).or_default().push((
                    u32::try_from(index)?,
                    u32::try_from(section.0)?,
                    u32::try_from(symbol.address())?,
                ));
            }
        }
    }
    let mut ranges = Vec::new();
    for p in placements {
        ensure!(p.size != 0, "zero-sized authored placement");
        let file = files
            .get(p.object as usize)
            .context("authored placement object index out of range")?;
        let section = file
            .section_by_index(object::SectionIndex(p.section as usize))
            .context("authored placement section index out of range")?;
        ensure!(
            retained(&section)?,
            "authored placement refers to a discarded compiler section"
        );
        ensure!(
            p.offset
                .checked_add(p.size)
                .is_some_and(|end| u64::from(end) <= section.size()),
            "authored placement exceeds original COFF contribution"
        );
        ensure!(
            mapped(pe, p.rva, p.size, !section.data()?.is_empty()),
            "authored placement is outside module storage"
        );
        let image_section = pe
            .section_headers()
            .iter()
            .find(|s| {
                p.rva >= s.rva
                    && p.rva
                        .checked_add(p.size)
                        .is_some_and(|end| end <= s.rva.saturating_add(s.virtual_size))
            })
            .context("authored contribution is not contained in one image section")?;
        let SectionFlags::Coff { characteristics } = section.flags() else {
            bail!("missing COFF section flags")
        };
        let memory = object::pe::IMAGE_SCN_MEM_READ
            | object::pe::IMAGE_SCN_MEM_WRITE
            | object::pe::IMAGE_SCN_MEM_EXECUTE;
        ensure!(
            object::pe::SectionFlags(image_section.characteristics) & memory
                == characteristics & memory,
            "compiler contribution protection flags changed during linking"
        );
        let base_name = section.name()?.split('$').next().unwrap_or("");
        let expected_name = if base_name == ".xdata" {
            ".kxdata"
        } else {
            base_name
        };
        ensure!(
            image_section.name == expected_name
                || (expected_name == ".bss" && image_section.name == ".data"),
            "compiler section {} merged into unexpected {}",
            section.name()?,
            image_section.name
        );
        ranges.push((
            p.rva,
            p.rva
                .checked_add(p.size)
                .context("placement RVA overflow")?,
        ));
    }
    ranges.sort_unstable();
    ensure!(
        ranges.windows(2).all(|p| p[0].1 <= p[1].0),
        "authored contribution placements overlap; discarded/aliased COMDAT identity is unsupported"
    );
    for (index, section) in pe.section_headers().iter().enumerate() {
        if matches!(section.name.as_str(), ".kmod" | ".reloc") || section.virtual_size == 0 {
            continue;
        }
        let mut owned: Vec<_> = ranges
            .iter()
            .copied()
            .filter(|&(start, end)| {
                start >= section.rva && end <= section.rva.saturating_add(section.virtual_size)
            })
            .collect();
        ensure!(
            !owned.is_empty(),
            "linked section {} contains no compiler-authored contribution",
            section.name
        );
        owned.sort_unstable();
        let bytes = pe.section_data(index).context("truncated linked section")?;
        let initialized_end = section
            .rva
            .checked_add(section.virtual_size.min(section.raw_size))
            .context("linked section end overflow")?;
        let mut cursor = section.rva;
        for (start, end) in owned.into_iter().chain(std::iter::once((
            section.rva + section.virtual_size,
            section.rva + section.virtual_size,
        ))) {
            let gap_end = start.min(initialized_end);
            if cursor < gap_end {
                let gap = &bytes[(cursor - section.rva) as usize..(gap_end - section.rva) as usize];
                let fill = if object::pe::SectionFlags(section.characteristics)
                    .contains(object::pe::IMAGE_SCN_MEM_EXECUTE)
                {
                    0xcc
                } else {
                    0
                };
                ensure!(
                    gap.iter().all(|b| *b == fill),
                    "linked section {} contains unauthored non-padding bytes at {cursor:#x}",
                    section.name
                );
            }
            cursor = end;
        }
    }
    let mut code = Vec::new();
    let mut data = Vec::new();
    let mut references = Vec::new();
    let runtime_functions = pe.runtime_functions();
    for (object_index, file) in files.iter().enumerate() {
        let object_index = u32::try_from(object_index)?;
        let debug_sizes = codeview_sizes(file)?;
        for section in file.sections() {
            if !retained(&section)? {
                continue;
            }
            let section_index = u32::try_from(section.index().0)?;
            let section_size =
                u32::try_from(section.size()).context("COFF contribution exceeds RVA range")?;
            let mut pieces: Vec<_> = placements
                .iter()
                .filter(|p| p.object == object_index && p.section == section_index)
                .collect();
            pieces.sort_unstable_by_key(|p| p.offset);
            let mut covered = 0;
            for p in &pieces {
                ensure!(
                    p.offset == covered,
                    "authored COFF object {object_index} section {} has missing/duplicate provenance",
                    section.name()?
                );
                covered = covered
                    .checked_add(p.size)
                    .context("contribution coverage overflow")?;
            }
            ensure!(
                covered == section_size,
                "authored COFF object {object_index} section {} was discarded or incompletely mapped",
                section.name()?
            );
            let original = section.data()?;
            let mut relocation_bytes = BTreeSet::new();
            for (offset, relocation) in section.relocations() {
                let RelocationFlags::Coff { typ } = relocation.flags() else {
                    bail!("non-COFF relocation in compiler metadata")
                };
                if typ == object::pe::IMAGE_REL_AMD64_ABSOLUTE {
                    continue;
                }
                let kind = relocation_kind(typ).with_context(|| {
                    format!(
                        "COFF object {object_index} section {} relocation at {offset:#x}",
                        section.name().unwrap_or("<invalid>")
                    )
                })?;
                let width = if kind == ModuleReferenceKind::Absolute64 {
                    8
                } else {
                    4
                };
                let offset = u32::try_from(offset)?;
                ensure!(
                    offset
                        .checked_add(width)
                        .is_some_and(|end| end <= section_size),
                    "COFF relocation field crosses contribution boundary"
                );
                ensure!(
                    !original.is_empty(),
                    "COFF relocation source is uninitialized storage"
                );
                let source = locate(placements, object_index, section_index, offset, width)?;
                let RelocationTarget::Symbol(symbol_index) = relocation.target() else {
                    bail!("unsupported COFF relocation target")
                };
                let symbol = file.symbol_by_index(symbol_index)?;
                let target = reference_target(pe, source, kind)?;
                let image_base = symbol.name()? == "__ImageBase";
                let original_field = original
                    .get(offset as usize..(offset + width) as usize)
                    .context("truncated COFF relocation addend")?;
                let addend = match kind {
                    ModuleReferenceKind::Absolute64 => {
                        i64::from_le_bytes(original_field.try_into()?)
                    }
                    ModuleReferenceKind::ImageRelative32 => {
                        i64::from(u32::from_le_bytes(original_field.try_into()?))
                    }
                    ModuleReferenceKind::Relative32 { .. } => {
                        i64::from(i32::from_le_bytes(original_field.try_into()?))
                    }
                };
                let symbol_rva = if image_base {
                    ensure!(
                        symbol.is_undefined(),
                        "__ImageBase must be the linker-defined image symbol"
                    );
                    0
                } else if let Some(section) = symbol.section_index() {
                    locate(
                        placements,
                        object_index,
                        u32::try_from(section.0)?,
                        u32::try_from(symbol.address())?,
                        0,
                    )?
                } else {
                    ensure!(
                        symbol.is_undefined(),
                        "absolute/weak COFF symbol {} is unsupported",
                        symbol.name()?
                    );
                    let definitions = globals.get(symbol.name()?).with_context(|| {
                        format!(
                            "COFF reference targets unauthored linker symbol {}",
                            symbol.name().unwrap_or("<invalid>")
                        )
                    })?;
                    ensure!(
                        definitions.len() == 1,
                        "ambiguous COFF reference target {}",
                        symbol.name()?
                    );
                    let (object, section, offset) = definitions[0];
                    locate(placements, object, section, offset, 0)?
                };
                let expected = i64::from(symbol_rva)
                    .checked_add(addend)
                    .context("COFF relocation target overflow")?;
                ensure!(
                    target == expected,
                    "linked reference at {source:#x} differs from compiler symbol/addend provenance: {target:#x} != {expected:#x}"
                );
                if !image_base {
                    ensure!(
                        mapped(pe, symbol_rva, 0, false) && symbol_rva != 0,
                        "COFF reference at {source:#x} targets non-module symbol RVA {symbol_rva:#x}"
                    );
                }
                for byte in offset..offset + width {
                    ensure!(
                        relocation_bytes.insert(byte),
                        "overlapping COFF relocation fields"
                    );
                }
                references.push(ModuleReference {
                    source: Rva::new(source),
                    target: if image_base {
                        ModuleTarget::ImageBase
                    } else {
                        ModuleTarget::Rva(Rva::new(symbol_rva))
                    },
                    addend,
                    kind,
                });
            }
            for p in &pieces {
                if original.is_empty() {
                    let image_section = pe
                        .section_headers()
                        .iter()
                        .enumerate()
                        .find(|(_, s)| {
                            p.rva >= s.rva && p.rva < s.rva.saturating_add(s.virtual_size)
                        })
                        .context("unmapped BSS contribution")?;
                    let (index, image_section) = image_section;
                    let bytes = pe
                        .section_data(index)
                        .context("truncated BSS backing storage")?;
                    let start = (p.rva - image_section.rva) as usize;
                    let end = start
                        .saturating_add(p.size as usize)
                        .min(bytes.len())
                        .min(image_section.virtual_size as usize);
                    ensure!(
                        start >= end || bytes[start..end].iter().all(|b| *b == 0),
                        "linked BSS contribution contains nonzero initialized bytes"
                    );
                    continue;
                }
                let actual = field(pe, p.rva, p.size as usize)?;
                let authored = original
                    .get(p.offset as usize..(p.offset + p.size) as usize)
                    .context("truncated original contribution bytes")?;
                for (i, (&a, &b)) in authored.iter().zip(actual).enumerate() {
                    ensure!(
                        a == b || relocation_bytes.contains(&(p.offset + u32::try_from(i)?)),
                        "linked bytes differ from compiler provenance in object {object_index} section {} at {:#x}; unsupported linker rewriting",
                        section.name()?,
                        p.offset as usize + i
                    );
                }
            }
            let SectionFlags::Coff { characteristics } = section.flags() else {
                bail!("missing COFF flags")
            };
            let executable = characteristics.contains(object::pe::IMAGE_SCN_MEM_EXECUTE);
            let mut symbols: Vec<_> = file
                .symbols()
                .filter(|s| {
                    s.section_index() == Some(section.index())
                        && !matches!(s.kind(), SymbolKind::Section | SymbolKind::File)
                })
                .collect();
            symbols.sort_unstable_by_key(|s| s.address());
            if executable {
                let functions: Vec<_> = symbols
                    .iter()
                    .filter(|s| s.kind() == SymbolKind::Text)
                    .collect();
                ensure!(
                    !functions.is_empty(),
                    "executable COFF contribution {} has no compiler-authored function symbols",
                    section.name()?
                );
                let unique_starts: BTreeSet<_> = functions.iter().map(|s| s.address()).collect();
                for symbol in functions {
                    let offset = u32::try_from(symbol.address())?;
                    let start = locate(placements, object_index, section_index, offset, 1)?;
                    let size = if symbol.size() != 0 {
                        u32::try_from(symbol.size())?
                    } else if let Some(size) = debug_sizes.get(&(section_index, offset)) {
                        *size
                    } else if let Some(function) =
                        runtime_functions.iter().find(|f| f.begin.get() == start)
                    {
                        function
                            .end
                            .get()
                            .checked_sub(start)
                            .context("invalid authored unwind function range")?
                    } else if unique_starts.len() == 1 && offset == 0 {
                        section_size
                    } else {
                        bail!(
                            "Rust COFF function {} lacks an exact compiler-authored extent; emit per-function native COFF contributions or enable -C debuginfo=2",
                            symbol.name()?
                        );
                    };
                    ensure!(size != 0, "zero-sized authored function {}", symbol.name()?);
                    locate(placements, object_index, section_index, offset, size)?;
                    code.push(CodeSymbol {
                        name: symbol.name()?.to_owned(),
                        start: Rva::new(start),
                        end: Rva::new(start.checked_add(size).context("function RVA overflow")?),
                    });
                }
            } else {
                let unique_starts: BTreeSet<_> = symbols.iter().map(|s| s.address()).collect();
                for symbol in &symbols {
                    let offset = u32::try_from(symbol.address())?;
                    let size = if symbol.size() != 0 {
                        u32::try_from(symbol.size())?
                    } else if unique_starts.len() == 1 && offset == 0 {
                        section_size
                    } else {
                        bail!(
                            "Rust COFF data symbol {} lacks an exact compiler-authored storage extent; emit separate per-static native COFF contributions",
                            symbol.name()?
                        );
                    };
                    let start = locate(placements, object_index, section_index, offset, size)?;
                    data.push(DataSymbol {
                        name: symbol.name()?.to_owned(),
                        start: Rva::new(start),
                        size,
                    });
                }
                for p in pieces {
                    data.push(DataSymbol {
                        name: format!("$coff{object_index}:{}+{:x}", section.name()?, p.offset),
                        start: Rva::new(p.rva),
                        size: p.size,
                    });
                }
            }
        }
    }
    code.sort_unstable_by_key(|s| (s.start.get(), s.end.get()));
    let mut canonical: Vec<CodeSymbol> = Vec::new();
    for symbol in code {
        if let Some(last) = canonical.last() {
            if last.start == symbol.start && last.end == symbol.end {
                ensure!(
                    last.name != symbol.name,
                    "duplicate authored code symbol {}",
                    symbol.name
                );
                continue;
            }
            ensure!(
                last.end <= symbol.start,
                "overlapping compiler-authored function extents: {} and {}",
                last.name,
                symbol.name
            );
        }
        canonical.push(symbol);
    }
    ensure!(
        canonical.iter().any(|s| s.start.get() == entry),
        "module callback must select an exact authored function entry"
    );
    references.sort_unstable_by_key(|r| r.source);
    for pair in references.windows(2) {
        let width = if pair[0].kind == ModuleReferenceKind::Absolute64 {
            8
        } else {
            4
        };
        ensure!(
            pair[0]
                .source
                .get()
                .checked_add(width)
                .is_some_and(|end| end <= pair[1].source.get()),
            "linked reference fields overlap"
        );
    }
    Ok(AuthoredModule {
        image: Vec::new(),
        entry: Rva::new(entry),
        code: canonical,
        data,
        references,
    })
}

fn relocation_kind(typ: object::pe::RelocationType) -> anyhow::Result<ModuleReferenceKind> {
    match typ {
        object::pe::IMAGE_REL_AMD64_ADDR64 => Ok(ModuleReferenceKind::Absolute64),
        object::pe::IMAGE_REL_AMD64_ADDR32NB => Ok(ModuleReferenceKind::ImageRelative32),
        object::pe::IMAGE_REL_AMD64_REL32 => Ok(ModuleReferenceKind::Relative32 { bias: 0 }),
        object::pe::IMAGE_REL_AMD64_REL32_1 => Ok(ModuleReferenceKind::Relative32 { bias: 1 }),
        object::pe::IMAGE_REL_AMD64_REL32_2 => Ok(ModuleReferenceKind::Relative32 { bias: 2 }),
        object::pe::IMAGE_REL_AMD64_REL32_3 => Ok(ModuleReferenceKind::Relative32 { bias: 3 }),
        object::pe::IMAGE_REL_AMD64_REL32_4 => Ok(ModuleReferenceKind::Relative32 { bias: 4 }),
        object::pe::IMAGE_REL_AMD64_REL32_5 => Ok(ModuleReferenceKind::Relative32 { bias: 5 }),
        _ => bail!(
            "unsupported AMD64 COFF relocation type {typ:#x}; address truncation, section-relative arithmetic and linker-generated indirection cannot be silently copied"
        ),
    }
}

fn codeview_sizes(file: &object::File<'_>) -> anyhow::Result<BTreeMap<(u32, u32), u32>> {
    let mut sizes = BTreeMap::new();
    for section in file
        .sections()
        .filter(|s| s.name().ok() == Some(".debug$S"))
    {
        let bytes = section.data()?;
        ensure!(
            u32_at(bytes, 0)? == 4,
            "unsupported CodeView symbol signature"
        );
        let mut offset = 4usize;
        while offset < bytes.len() {
            let kind = u32_at(bytes, offset)?;
            let size = u32_at(bytes, offset + 4)? as usize;
            let start = offset
                .checked_add(8)
                .context("CodeView subsection offset overflow")?;
            let end = start
                .checked_add(size)
                .context("CodeView subsection length overflow")?;
            let payload = bytes
                .get(start..end)
                .context("truncated CodeView subsection")?;
            if kind == 0xf1 {
                let mut cursor = 0usize;
                while cursor < payload.len() {
                    let record = payload
                        .get(cursor..cursor.checked_add(4).context("CodeView record overflow")?)
                        .context("truncated CodeView symbol record")?;
                    let length = usize::from(u16::from_le_bytes(record[..2].try_into()?)) + 2;
                    ensure!(length >= 4, "invalid CodeView record length");
                    let record = payload
                        .get(
                            cursor
                                ..cursor
                                    .checked_add(length)
                                    .context("CodeView record length overflow")?,
                        )
                        .context("truncated CodeView procedure")?;
                    let symbol_kind = u16::from_le_bytes(record[2..4].try_into()?);
                    if matches!(symbol_kind, 0x110f | 0x1110 | 0x1146 | 0x1147) {
                        let code_size = u32_at(record, 16)?;
                        let code_offset = u32_at(record, 32)?;
                        let location = u64::try_from(start + cursor + 32)?;
                        let (_, relocation) = section
                            .relocations()
                            .find(|(o, _)| *o == location)
                            .context(
                            "CodeView procedure lacks a compiler section-relative relocation",
                        )?;
                        ensure!(
                            matches!(
                                relocation.flags(),
                                RelocationFlags::Coff {
                                    typ: object::pe::IMAGE_REL_AMD64_SECREL
                                }
                            ),
                            "unsupported CodeView procedure relocation"
                        );
                        let RelocationTarget::Symbol(index) = relocation.target() else {
                            bail!("unsupported CodeView procedure target")
                        };
                        let symbol = file.symbol_by_index(index)?;
                        let section = symbol
                            .section_index()
                            .context("CodeView procedure target is undefined")?;
                        let offset = u32::try_from(symbol.address())?
                            .checked_add(code_offset)
                            .context("CodeView procedure offset overflow")?;
                        if let Some(previous) =
                            sizes.insert((u32::try_from(section.0)?, offset), code_size)
                        {
                            ensure!(
                                previous == code_size,
                                "conflicting CodeView procedure sizes"
                            );
                        }
                    }
                    cursor += length;
                }
            }
            offset = end.checked_add(3).context("CodeView alignment overflow")? & !3;
            ensure!(
                offset <= bytes.len(),
                "truncated CodeView subsection alignment"
            );
        }
    }
    Ok(sizes)
}
