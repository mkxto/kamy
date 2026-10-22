use std::collections::BTreeMap;

use anyhow::{Context, bail, ensure};
use kamy_core::{RelocKind, Relocation, Rva};

/// Parse complete `IMAGE_BASE_RELOCATION` blocks with DWORD-aligned headers.
/// A terminal block may end on a WORD boundary; only subsequent headers need DWORD alignment.
/// See <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only>.
/// Unsupported types fail because their entry widths and fixups are not modeled.
pub(crate) fn parse_relocations(data: &[u8]) -> anyhow::Result<Vec<Relocation>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        ensure!(
            off % 4 == 0,
            "unaligned base relocation block header at {off:#x}"
        );
        let header = data
            .get(off..)
            .and_then(|remaining| remaining.get(..8))
            .with_context(|| format!("truncated base relocation block header at {off:#x}"))?;
        let page = u32::from_le_bytes(header[..4].try_into().expect("four-byte page RVA"));
        let block_size =
            u32::from_le_bytes(header[4..8].try_into().expect("four-byte block size")) as usize;
        ensure!(
            page & 0xfff == 0,
            "unaligned base relocation page {page:#x} at block {off:#x}"
        );
        ensure!(
            block_size >= 8 && block_size % 2 == 0,
            "invalid base relocation block size {block_size:#x} at {off:#x}"
        );
        let end = off
            .checked_add(block_size)
            .with_context(|| format!("base relocation block extent overflows at {off:#x}"))?;
        let entries = data
            .get(off + 8..end)
            .with_context(|| format!("truncated base relocation block at {off:#x}"))?;
        for (index, encoded) in entries.chunks_exact(2).enumerate() {
            let entry = u16::from_le_bytes(encoded.try_into().expect("two-byte relocation entry"));
            let (kind, width) = match entry >> 12 {
                0 => (RelocKind::Absolute, 0u64),
                3 => (RelocKind::HighLow, 4),
                10 => (RelocKind::Dir64, 8),
                kind => bail!(
                    "unsupported base relocation type {kind} at block {off:#x}, entry {index}"
                ),
            };
            let rva = page
                .checked_add(u32::from(entry & 0x0fff))
                .with_context(|| {
                    format!("base relocation RVA overflow at block {off:#x}, entry {index}")
                })?;
            ensure!(
                u64::from(rva) + width <= u64::from(u32::MAX) + 1,
                "base relocation field overflows RVA space at block {off:#x}, entry {index}"
            );
            out.push(Relocation {
                rva: Rva::new(rva),
                kind,
            });
        }
        off = end;
    }
    Ok(out)
}

pub fn encode_base_relocations(relocations: &[Relocation]) -> anyhow::Result<Vec<u8>> {
    let mut sites = BTreeMap::new();
    for relocation in relocations {
        if relocation.kind == RelocKind::Absolute {
            continue;
        }
        if let Some(previous) = sites.insert(relocation.rva.get(), relocation.kind) {
            ensure!(
                previous == relocation.kind,
                "conflicting base relocation kinds"
            );
        }
    }
    let mut previous_end = 0u64;
    let mut out = Vec::new();
    let mut block_start = None;
    let mut current_page = None;
    for (site, kind) in sites {
        ensure!(
            u64::from(site) >= previous_end,
            "overlapping base relocation fields"
        );
        let (tag, width) = match kind {
            RelocKind::Dir64 => (10u16, 8u64),
            RelocKind::HighLow => (3u16, 4u64),
            RelocKind::Absolute => unreachable!(),
        };
        previous_end = u64::from(site) + width;
        ensure!(
            previous_end <= u64::from(u32::MAX) + 1,
            "base relocation field overflows RVA space"
        );
        let page = site & !0xfff;
        if current_page != Some(page) {
            if let Some(start) = block_start {
                finish_block(&mut out, start)?;
            }
            current_page = Some(page);
            block_start = Some(out.len());
            out.extend_from_slice(&page.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        out.extend_from_slice(&((tag << 12) | (site & 0xfff) as u16).to_le_bytes());
    }
    if let Some(start) = block_start {
        finish_block(&mut out, start)?;
    }
    Ok(out)
}

fn finish_block(out: &mut Vec<u8>, start: usize) -> anyhow::Result<()> {
    if (out.len() - start) % 4 != 0 {
        out.extend_from_slice(&0u16.to_le_bytes());
    }
    let size = u32::try_from(out.len() - start).context("base relocation block too large")?;
    out[start + 4..start + 8].copy_from_slice(&size.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_sorts_groups_deduplicates_and_aligns() {
        let site = |rva| Relocation {
            rva: Rva::new(rva),
            kind: RelocKind::Dir64,
        };
        let data =
            encode_base_relocations(&[site(0x3018), site(0x1020), site(0x1010), site(0x3018)])
                .unwrap();
        assert_eq!(read32(&data, 0), 0x1000);
        assert_eq!(read32(&data, 4), 12);
        assert_eq!(&data[8..12], &[0x10, 0xa0, 0x20, 0xa0]);
        assert_eq!(read32(&data, 12), 0x3000);
        assert_eq!(read32(&data, 16), 12);
        assert_eq!(&data[20..24], &[0x18, 0xa0, 0, 0]);
        let fixups: Vec<_> = parse_relocations(&data)
            .unwrap()
            .into_iter()
            .filter(|relocation| relocation.kind != RelocKind::Absolute)
            .collect();
        assert_eq!(fixups, vec![site(0x1010), site(0x1020), site(0x3018)]);
    }

    #[test]
    fn encoder_rejects_conflicting_and_overlapping_fields() {
        let dir64 = Relocation {
            rva: Rva::new(0x1000),
            kind: RelocKind::Dir64,
        };
        let highlow = Relocation {
            rva: Rva::new(0x1000),
            kind: RelocKind::HighLow,
        };
        assert!(encode_base_relocations(&[dir64, highlow]).is_err());
        let overlapping = Relocation {
            rva: Rva::new(0x1004),
            kind: RelocKind::Dir64,
        };
        assert!(encode_base_relocations(&[dir64, overlapping]).is_err());
        assert!(encode_base_relocations(&[]).unwrap().is_empty());
    }

    fn read32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }
}
