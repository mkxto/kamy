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
