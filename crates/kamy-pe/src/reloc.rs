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
