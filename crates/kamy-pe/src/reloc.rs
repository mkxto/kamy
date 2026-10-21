use std::collections::BTreeMap;

use anyhow::{Context, ensure};
use kamy_core::{RelocKind, Relocation, Rva};

/// Parse a `.reloc` directory (`IMAGE_BASE_RELOCATION` block sequence).
///
/// Each block is `{ PageRVA: u32, BlockSize: u32 }` followed by
/// `(BlockSize - 8) / 2` little-endian `u16` entries. An entry packs
/// `(type << 12) | offset`; only types `0` (Absolute padder), `3` (HighLow)
/// and `10` (Dir64) are retained, other types are skipped.
pub(crate) fn parse_relocations(data: &[u8]) -> Vec<Relocation> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= data.len() {
        let page = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let block_size = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        if block_size < 8 {
            break;
        }
        let Some(end) = off.checked_add(block_size).filter(|&e| e <= data.len()) else {
            break;
        };
        let mut e = off + 8;
        while e + 2 <= end {
            let entry = u16::from_le_bytes(data[e..e + 2].try_into().unwrap());
            e += 2;
            let offset = u32::from(entry & 0x0fff);
            let kind = match entry >> 12 {
                0 => RelocKind::Absolute,
                3 => RelocKind::HighLow,
                10 => RelocKind::Dir64,
                _ => continue,
            };
            out.push(Relocation {
                rva: Rva::new(page.saturating_add(offset)),
                kind,
            });
        }
        off = end;
    }
    out
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
