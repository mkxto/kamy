use anyhow::{Context, ensure};

use crate::PeFile;

pub(crate) struct ExportEntry {
    pub name: Option<String>,
    pub rva: u32,
}

pub(crate) fn parse_exports(
    pe: &PeFile,
    dir_rva: u32,
    dir_size: u32,
) -> anyhow::Result<Vec<ExportEntry>> {
    let dir = pe
        .slice_at_rva(dir_rva)
        .context("export directory is not file-backed")?;
    ensure!(
        dir_size >= 40 && dir.len() >= dir_size as usize,
        "truncated export directory"
    );
    let functions = crate::read_u32(dir, 20)?;
    let names = crate::read_u32(dir, 24)?;
    let eat = crate::read_u32(dir, 28)?;
    let name_table = crate::read_u32(dir, 32)?;
    let ordinals = crate::read_u32(dir, 36)?;
    let end = dir_rva
        .checked_add(dir_size)
        .context("export directory range overflow")?;
    let mut out = Vec::new();
    for index in 0..functions {
        let field = eat
            .checked_add(index.checked_mul(4).context("export table overflow")?)
            .context("export table overflow")?;
        let rva = pe
            .u32_at_rva(field)
            .context("truncated export address table")?;
        if rva != 0 && !(dir_rva..end).contains(&rva) {
            out.push(ExportEntry { name: None, rva });
        }
    }
    for index in 0..names {
        let name_field = name_table
            .checked_add(index.checked_mul(4).context("export names overflow")?)
            .context("export names overflow")?;
        let ordinal_field = ordinals
            .checked_add(index.checked_mul(2).context("export ordinals overflow")?)
            .context("export ordinals overflow")?;
        let ordinal = u32::from(
            pe.u16_at_rva(ordinal_field)
                .context("truncated export ordinal table")?,
        );
        ensure!(ordinal < functions, "export ordinal exceeds address table");
        let rva = pe
            .u32_at_rva(
                eat.checked_add(ordinal.checked_mul(4).context("export ordinal overflow")?)
                    .context("export ordinal overflow")?,
            )
            .context("truncated export address table")?;
        let name_rva = pe
            .u32_at_rva(name_field)
            .context("truncated export name table")?;
        let bytes = pe
            .slice_at_rva(name_rva)
            .context("export name is not file-backed")?;
        ensure!(bytes.contains(&0), "unterminated export name");
        let name = pe.read_cstr(name_rva).context("invalid export name")?;
        if let Some(entry) = out
            .iter_mut()
            .find(|entry| entry.rva == rva && entry.name.is_none())
        {
            entry.name = Some(name);
        } else if rva != 0 && !(dir_rva..end).contains(&rva) {
            out.push(ExportEntry {
                name: Some(name),
                rva,
            });
        }
    }
    Ok(out)
}
