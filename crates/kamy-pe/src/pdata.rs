/// Parse a `.pdata` directory: an array of `RUNTIME_FUNCTION`
/// `{ BeginAddress: u32, EndAddress: u32, UnwindInfoAddress: u32 }`.
///
/// Returns every `BeginAddress`; these are function-entry seeds.
pub(crate) fn parse_pdata(data: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 12 <= data.len() {
        let begin = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        if begin != 0 {
            out.push(begin);
        }
        off += 12;
    }
    out
}

/// Parse a `.pdata` directory into full `RUNTIME_FUNCTION` triples
/// `(BeginAddress, EndAddress, UnwindInfoAddress)`.
pub(crate) fn parse_runtime_functions(data: &[u8]) -> Vec<(u32, u32, u32)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 12 <= data.len() {
        let begin = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let end = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
        let unwind = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
        if begin != 0 {
            out.push((begin, end, unwind));
        }
        off += 12;
    }
    out
}
