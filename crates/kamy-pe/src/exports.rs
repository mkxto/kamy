use crate::PeFile;

pub(crate) struct ExportEntry {
    pub name: String,
    pub rva: u32,
}

/// Resolve named exports from an `IMAGE_EXPORT_DIRECTORY`.
///
/// Forwarder entries (whose target RVA lies inside the export directory range)
/// are skipped since they name another module rather than local code.
pub(crate) fn parse_exports(pe: &PeFile, dir_rva: u32, dir_size: u32) -> Vec<ExportEntry> {
    let mut out = Vec::new();
    let Some(dir) = pe.slice_at_rva(dir_rva) else {
        return out;
    };
    if dir.len() < 40 {
        return out;
    }
    let number_of_names = u32::from_le_bytes(dir[24..28].try_into().unwrap());
    let addr_of_functions = u32::from_le_bytes(dir[28..32].try_into().unwrap());
    let addr_of_names = u32::from_le_bytes(dir[32..36].try_into().unwrap());
    let addr_of_name_ordinals = u32::from_le_bytes(dir[36..40].try_into().unwrap());
    let dir_end = dir_rva.saturating_add(dir_size);

    for i in 0..number_of_names {
        let Some(name_rva) = addr_of_names
            .checked_add(i.wrapping_mul(4))
            .and_then(|r| pe.u32_at_rva(r))
        else {
            break;
        };
        let Some(ordinal) = addr_of_name_ordinals
            .checked_add(i.wrapping_mul(2))
            .and_then(|r| pe.u16_at_rva(r))
        else {
            break;
        };
        let Some(func_rva) = addr_of_functions
            .checked_add(u32::from(ordinal).wrapping_mul(4))
            .and_then(|r| pe.u32_at_rva(r))
        else {
            continue;
        };
        if func_rva == 0 || (func_rva >= dir_rva && func_rva < dir_end) {
            continue;
        }
        let Some(name) = pe.read_cstr(name_rva) else {
            continue;
        };
        out.push(ExportEntry {
            name,
            rva: func_rva,
        });
    }
    out
}
