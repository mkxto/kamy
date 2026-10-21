use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail, ensure};
use kamy_core::SectionFlags;
use object::{Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget};

use super::{
    METADATA_SECTION, Placement, coff, encode, u32_at, validate_base_relocations, validate_image,
};
use crate::{NewSection, PeEdits, PeFile};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> anyhow::Result<Self> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kamy-module-{}-{stamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).context("create SDK linker scratch directory")?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn build(
    paths: &[PathBuf],
    output: &Path,
    entry: &str,
    linker: &Path,
) -> anyhow::Result<()> {
    ensure!(
        !paths.is_empty(),
        "module build requires compiled AMD64 COFF objects"
    );
    ensure!(
        !entry.is_empty() && !entry.chars().any(char::is_whitespace),
        "module callback symbol is empty or contains whitespace"
    );
    let scratch = Scratch::new()?;
    let mut originals = Vec::with_capacity(paths.len());
    let mut anchors = Vec::new();
    let mut command = Command::new(linker);
    let dll = scratch.0.join("module.dll");
    let map = scratch.0.join("module.map");
    command
        .args([
            "/dll",
            "/noentry",
            "/nodefaultlib",
            "/machine:x64",
            "/opt:noref",
            "/opt:noicf",
            "/incremental:no",
            "/debug:none",
            "/dynamicbase",
            "/fixed:no",
            "/timestamp:0",
            "/merge:.xdata=.kxdata",
            "/merge:.idata=.kidata",
        ])
        .arg(format!("/out:{}", dll.display()))
        .arg(format!("/map:{}", map.display()));
    for (index, path) in paths.iter().enumerate() {
        let original =
            fs::read(path).with_context(|| format!("read SDK object {}", path.display()))?;
        let file =
            coff::parse(&original).with_context(|| format!("SDK object {}", path.display()))?;
        ensure!(
            file.symbols()
                .all(|s| !s.name().unwrap_or("").starts_with("__kamy_anchor_")),
            "SDK object {} uses reserved provenance symbols",
            path.display()
        );
        let mut object_anchors = Vec::new();
        for section in file.sections() {
            if !coff::retained(&section)? {
                continue;
            }
            let section_index = u32::try_from(section.index().0)?;
            let name = format!("__kamy_anchor_{index}_{section_index}");
            object_anchors.push((section_index, name.clone()));
            anchors.push((
                u32::try_from(index)?,
                section_index,
                u32::try_from(section.size())?,
                name.clone(),
            ));
            command.arg(format!("/include:{name}"));
        }
        let anchored = add_anchors(&original, &object_anchors)?;
        let object_path = scratch.0.join(format!("input-{index}.obj"));
        fs::write(&object_path, anchored).context("write provenance-anchored COFF object")?;
        command.arg(object_path);
        originals.push(original);
    }
    let result = command
        .output()
        .with_context(|| format!("run module linker {}", linker.display()))?;
    ensure!(
        result.status.success(),
        "module linker failed ({}):\n{}{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let linked = fs::read(&dll).context("read linked SDK DLL")?;
    let pe = PeFile::parse(&linked).context("parse linked SDK DLL")?;
    validate_image(&pe, &linked)?;
    let symbols = map_symbols(
        &fs::read_to_string(&map).context("read linker provenance map")?,
        pe.image_base,
    )?;
    let mut placements = Vec::with_capacity(anchors.len());
    for (object, section, size, name) in anchors {
        let rva = *symbols.get(&name).with_context(|| format!("linker omitted provenance anchor {name}; COMDAT selection, LTCG or identity-losing link is unsupported"))?;
        placements.push(Placement {
            object,
            section,
            offset: 0,
            size,
            rva,
        });
    }
    remap_pdata(&pe, &originals, &mut placements)?;
    let entry_rva = callback(&originals, &placements, entry)?;
    let authored = coff::describe(&pe, &originals, &placements, entry_rva)
        .context("linked SDK provenance validation")?;
    validate_base_relocations(&pe, &authored.references)?;
    let metadata = encode(entry_rva, &originals, &placements)?;
    let packed = pe
        .rebuild(&PeEdits {
            new_sections: vec![NewSection {
                name: METADATA_SECTION.to_owned(),
                rva: pe.next_section_rva(),
                flags: SectionFlags {
                    read: true,
                    ..SectionFlags::default()
                },
                data: metadata,
            }],
            ..PeEdits::default()
        })
        .context("embed compiler-authored module metadata")?;
    fs::write(output, packed)
        .with_context(|| format!("write authored module {}", output.display()))?;
    Ok(())
}

fn callback(objects: &[Vec<u8>], placements: &[Placement], entry: &str) -> anyhow::Result<u32> {
    let mut address = None;
    for (index, bytes) in objects.iter().enumerate() {
        let file = coff::parse(bytes)?;
        for symbol in file.symbols() {
            if symbol.name()? != entry || !symbol.is_definition() {
                continue;
            }
            ensure!(
                symbol.kind() == object::SymbolKind::Text,
                "module callback {entry} is not a compiler-authored function"
            );
            let section = symbol
                .section_index()
                .context("module callback has no code contribution")?;
            let rva = coff::locate(
                placements,
                u32::try_from(index)?,
                u32::try_from(section.0)?,
                u32::try_from(symbol.address())?,
                1,
            )?;
            ensure!(
                address.is_none(),
                "module callback {entry} is ambiguous across input objects"
            );
            address = Some(rva);
        }
    }
    address.with_context(|| {
        format!("module callback symbol {entry} is not defined by the supplied objects")
    })
}

fn add_anchors(bytes: &[u8], anchors: &[(u32, String)]) -> anyhow::Result<Vec<u8>> {
    let big = bytes.get(..4) == Some(&[0, 0, 0xff, 0xff]);
    let (pointer_offset, count_offset, symbol_size) = if big {
        (48, 52, 20usize)
    } else {
        (8, 12, 18usize)
    };
    let pointer = u32_at(bytes, pointer_offset)? as usize;
    let count = u32_at(bytes, count_offset)? as usize;
    ensure!(
        pointer != 0,
        "compiled COFF object has no authoritative symbol table"
    );
    let table_size = count
        .checked_mul(symbol_size)
        .context("COFF symbol table size overflow")?;
    let table_end = pointer
        .checked_add(table_size)
        .context("COFF symbol table offset overflow")?;
    let table = bytes
        .get(pointer..table_end)
        .context("truncated original COFF symbols")?;
    let strings_size = u32_at(bytes, table_end)? as usize;
    ensure!(strings_size >= 4, "invalid COFF string table length");
    let mut strings = bytes
        .get(
            table_end
                ..table_end
                    .checked_add(strings_size)
                    .context("COFF string table offset overflow")?,
        )
        .context("truncated COFF strings")?
        .to_vec();
    let mut output = bytes.to_vec();
    let new_pointer = u32::try_from(output.len()).context("COFF object exceeds 4 GiB")?;
    output.extend_from_slice(table);
    for (section, name) in anchors {
        let mut symbol = vec![0u8; symbol_size];
        symbol[4..8].copy_from_slice(&u32::try_from(strings.len())?.to_le_bytes());
        if big {
            symbol[12..16].copy_from_slice(&section.to_le_bytes());
            symbol[18] = object::pe::IMAGE_SYM_CLASS_EXTERNAL.0;
        } else {
            symbol[12..14].copy_from_slice(
                &u16::try_from(*section)
                    .context("COFF section number exceeds standard object range")?
                    .to_le_bytes(),
            );
            symbol[16] = object::pe::IMAGE_SYM_CLASS_EXTERNAL.0;
        }
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        output.extend_from_slice(&symbol);
    }
    let length = u32::try_from(strings.len())?;
    strings[..4].copy_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&strings);
    output[pointer_offset..pointer_offset + 4].copy_from_slice(&new_pointer.to_le_bytes());
    output[count_offset..count_offset + 4].copy_from_slice(
        &u32::try_from(
            count
                .checked_add(anchors.len())
                .context("COFF symbol count overflow")?,
        )?
        .to_le_bytes(),
    );
    Ok(output)
}

fn map_symbols(text: &str, image_base: u64) -> anyhow::Result<BTreeMap<String, u32>> {
    let mut symbols = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(address), Some(name), Some(value)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !address.contains(':') || !name.starts_with("__kamy_anchor_") {
            continue;
        }
        let value = u64::from_str_radix(value, 16)
            .with_context(|| format!("invalid linker map address for {name}"))?;
        let rva = u32::try_from(
            value
                .checked_sub(image_base)
                .context("linker provenance anchor precedes image base")?,
        )?;
        ensure!(
            symbols.insert(name.to_owned(), rva).is_none(),
            "duplicate linker provenance anchor {name}"
        );
    }
    ensure!(
        !symbols.is_empty(),
        "linker did not emit the required MSVC-compatible /map provenance symbols"
    );
    Ok(symbols)
}

fn remap_pdata(
    pe: &PeFile,
    objects: &[Vec<u8>],
    placements: &mut Vec<Placement>,
) -> anyhow::Result<()> {
    let Some((directory, directory_size)) = pe.data_directory(3).filter(|(_, size)| *size != 0)
    else {
        return Ok(());
    };
    ensure!(
        directory_size % 12 == 0,
        "linked .pdata has partial runtime function records"
    );
    let runtime = pe.runtime_functions();
    let originals = placements.clone();
    for (object, bytes) in objects.iter().enumerate() {
        let file = coff::parse(bytes)?;
        for section in file.sections().filter(|s| {
            s.name()
                .ok()
                .is_some_and(|n| n.split('$').next() == Some(".pdata"))
        }) {
            if !coff::retained(&section)? {
                continue;
            }
            let index = u32::try_from(section.index().0)?;
            let object = u32::try_from(object)?;
            let data = section.data()?;
            ensure!(
                data.len() % 12 == 0,
                "COFF .pdata contribution contains a partial function record"
            );
            placements.retain(|p| p.object != object || p.section != index);
            for offset in (0..data.len()).step_by(12) {
                let (_, relocation) = section
                    .relocations()
                    .find(|(o, _)| *o == offset as u64)
                    .context("COFF .pdata begin lacks authored relocation")?;
                ensure!(
                    matches!(
                        relocation.flags(),
                        RelocationFlags::Coff {
                            typ: object::pe::IMAGE_REL_AMD64_ADDR32NB
                        }
                    ),
                    "unsupported COFF .pdata begin relocation"
                );
                let RelocationTarget::Symbol(symbol_index) = relocation.target() else {
                    bail!("unsupported .pdata begin symbol")
                };
                let symbol = file.symbol_by_index(symbol_index)?;
                let target_section = symbol
                    .section_index()
                    .context("external .pdata begin reference is unsupported")?;
                let target_offset = u32::try_from(symbol.address())?
                    .checked_add(u32_at(data, offset)?)
                    .context(".pdata function offset overflow")?;
                let target = coff::locate(
                    &originals,
                    object,
                    u32::try_from(target_section.0)?,
                    target_offset,
                    1,
                )?;
                let mut matching = runtime
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| f.begin.get() == target);
                let (row, _) = matching
                    .next()
                    .context("linker discarded an authored runtime function")?;
                ensure!(
                    matching.next().is_none(),
                    "duplicate linked runtime function begins"
                );
                let rva = directory
                    .get()
                    .checked_add(
                        u32::try_from(row)?
                            .checked_mul(12)
                            .context(".pdata row offset overflow")?,
                    )
                    .context(".pdata row RVA overflow")?;
                placements.push(Placement {
                    object,
                    section: index,
                    offset: u32::try_from(offset)?,
                    size: 12,
                    rva,
                });
            }
        }
    }
    Ok(())
}
