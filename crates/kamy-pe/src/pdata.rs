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
