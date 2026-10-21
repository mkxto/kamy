use crate::PeFile;

const ORDINAL_FLAG: u64 = 0x8000_0000_0000_0000;
const MAX_DESCRIPTORS: u32 = 4096;
const MAX_THUNKS: u32 = 65536;

pub(crate) struct ImportEntry {
    pub name: String,
    pub iat_rva: u32,
}

/// Walk the `IMAGE_IMPORT_DESCRIPTOR` array and resolve each imported symbol
/// to its name (or `#ordinal`) and the Import Address Table slot RVA.
pub(crate) fn parse_imports(pe: &PeFile, dir_rva: u32, _dir_size: u32) -> Vec<ImportEntry> {
    let mut out = Vec::new();
    let mut desc_rva = dir_rva;
    for _ in 0..MAX_DESCRIPTORS {
        let (Some(original_first_thunk), Some(name_rva), Some(first_thunk)) = (
            pe.u32_at_rva(desc_rva),
            desc_rva.checked_add(12).and_then(|r| pe.u32_at_rva(r)),
            desc_rva.checked_add(16).and_then(|r| pe.u32_at_rva(r)),
        ) else {
            break;
        };
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let lookup = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        for idx in 0..MAX_THUNKS {
            let step = idx.wrapping_mul(8);
            let Some(thunk) = lookup.checked_add(step).and_then(|r| pe.u64_at_rva(r)) else {
                break;
            };
            if thunk == 0 {
                break;
            }
            let Some(iat_rva) = first_thunk.checked_add(step) else {
                break;
            };
            let name = if thunk & ORDINAL_FLAG != 0 {
                format!("#{}", thunk & 0xffff)
            } else {
                let by_name_rva = (thunk & 0x7fff_ffff) as u32;
                by_name_rva
                    .checked_add(2)
                    .and_then(|r| pe.read_cstr(r))
                    .unwrap_or_default()
            };
            out.push(ImportEntry { name, iat_rva });
        }
        desc_rva = match desc_rva.checked_add(20) {
            Some(r) => r,
            None => break,
        };
    }
    out
}

pub(crate) struct ImportLibrary {
    pub name: Vec<u8>,
    pub first_thunk: u32,
    pub symbols: Vec<ImportSymbol>,
}

pub(crate) enum ImportSymbol {
    Ordinal(u16),
    Named { hint: u16, name: Vec<u8> },
}

pub(crate) fn checked_imports(
    pe: &PeFile,
    base: u32,
    size: u32,
) -> anyhow::Result<Vec<ImportLibrary>> {
    use anyhow::{Context, ensure};
    let mut libraries = Vec::new();
    for index in 0..MAX_DESCRIPTORS {
        let offset = index * 20;
        ensure!(
            offset.checked_add(20).is_some_and(|end| end <= size),
            "import descriptor array at {base:#x} has no complete terminator within size {size:#x}"
        );
        let rva = base
            .checked_add(offset)
            .context("import descriptor RVA overflow")?;
        let bytes = pe
            .slice_at_rva(rva)
            .and_then(|data| data.get(..20))
            .with_context(|| format!("truncated import descriptor at {rva:#x}"))?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Ok(libraries);
        }
        let lookup = crate::read_u32(bytes, 0)?;
        let timestamp = crate::read_u32(bytes, 4)?;
        let name_rva = crate::read_u32(bytes, 12)?;
        let first_thunk = crate::read_u32(bytes, 16)?;
        ensure!(
            name_rva != 0 && first_thunk != 0,
            "invalid import descriptor at {rva:#x}: Name={name_rva:#x}, FirstThunk={first_thunk:#x}"
        );
        let name = checked_string(pe, name_rva).context("invalid import DLL name")?;
        ensure!(!name.is_empty(), "empty import DLL name at {name_rva:#x}");
        let source = if lookup == 0 { first_thunk } else { lookup };
        let mut symbols = Vec::new();
        let mut terminated = false;
        for slot in 0..MAX_THUNKS {
            let step = slot * 8;
            let field = source
                .checked_add(step)
                .context("import lookup RVA overflow")?;
            let value = pe
                .u64_at_rva(field)
                .with_context(|| format!("truncated import lookup thunk at {field:#x}"))?;
            let iat = first_thunk
                .checked_add(step)
                .context("import IAT RVA overflow")?;
            ensure!(
                pe.u64_at_rva(iat).is_some(),
                "truncated import IAT slot at {iat:#x}"
            );
            if value == 0 {
                terminated = true;
                break;
            }
            let symbol = if value & ORDINAL_FLAG != 0 {
                ensure!(
                    value & !(ORDINAL_FLAG | 0xffff) == 0,
                    "invalid ordinal import thunk {value:#x} at {field:#x}"
                );
                ImportSymbol::Ordinal(value as u16)
            } else {
                let decoded = (|| -> anyhow::Result<ImportSymbol> {
                    let name =
                        u32::try_from(value).context("import Hint/Name is not a 32-bit RVA")?;
                    let hint = pe
                        .u16_at_rva(name)
                        .context("import hint is not file-backed")?;
                    let text = checked_string(
                        pe,
                        name.checked_add(2).context("import name RVA overflow")?,
                    )?;
                    ensure!(!text.is_empty(), "empty import symbol name");
                    Ok(ImportSymbol::Named { hint, name: text })
                })();
                decoded.with_context(|| {
                    if lookup == 0 {
                        format!("OFT=0 import at descriptor {rva:#x}, IAT {iat:#x}, value {value:#x}, timestamp {timestamp:#x}: original Hint/Name unavailable (bound IAT cannot be reconstructed)")
                    } else {
                        format!("invalid import Hint/Name thunk {value:#x} at {field:#x}")
                    }
                })?
            };
            symbols.push(symbol);
        }
        ensure!(
            terminated,
            "import lookup at {source:#x} exceeds {MAX_THUNKS} slots without a terminator"
        );
        libraries.push(ImportLibrary {
            name,
            first_thunk,
            symbols,
        });
    }
    anyhow::bail!("import descriptors exceed {MAX_DESCRIPTORS} records without a terminator")
}

fn checked_string(pe: &PeFile, rva: u32) -> anyhow::Result<Vec<u8>> {
    use anyhow::Context;
    let bytes = pe
        .slice_at_rva(rva)
        .with_context(|| format!("import string at {rva:#x} is not file-backed"))?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .with_context(|| format!("unterminated import string at {rva:#x}"))?;
    Ok(bytes[..end].to_vec())
}
