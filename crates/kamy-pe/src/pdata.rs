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

use iced_x86::Register;

/// Encoded byte size of `push <reg>` for a callee-saved GPR:
/// R8..R15 require a REX.B prefix (2 bytes); RBX/RBP/RSI/RDI are 1 byte.
fn push_size(reg: Register) -> u32 {
    match reg {
        Register::R8
        | Register::R9
        | Register::R10
        | Register::R11
        | Register::R12
        | Register::R13
        | Register::R14
        | Register::R15 => 2,
        _ => 1,
    }
}

/// MS x64 unwind register number (RAX=0 .. R15=15).
fn unwind_reg_number(reg: Register) -> u8 {
    match reg {
        Register::RAX => 0,
        Register::RCX => 1,
        Register::RDX => 2,
        Register::RBX => 3,
        Register::RSP => 4,
        Register::RBP => 5,
        Register::RSI => 6,
        Register::RDI => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        _ => panic!("unwind_reg_number: non-GPR register {reg:?}"),
    }
}

/// Build a Win64 `UNWIND_INFO` blob for a generated push/align prologue.
///
/// `pushed` lists the callee-saved GPRs pushed in canonical order; `aligned`
/// is true when the prologue appends `sub rsp,8` (odd push count) to realign.
/// Nodes are ordered by descending prolog offset: the `sub rsp,8`
/// `UWOP_ALLOC_SMALL` (if any) first, then each push in REVERSE order. The
/// node array is padded to an even length so the structure is 4-byte sized.
pub fn build_unwind_info(pushed: &[Register], aligned: bool) -> Vec<u8> {
    // Cumulative encoded prolog offset after each push, in push order.
    let mut offset = 0u32;
    let mut after_push = Vec::with_capacity(pushed.len());
    for &reg in pushed {
        offset += push_size(reg);
        after_push.push(offset);
    }
    if aligned {
        offset += 4; // sub rsp,8 == 48 83 EC 08
    }
    let size_of_prolog = offset;

    let mut nodes: Vec<[u8; 2]> = Vec::new();
    if aligned {
        // UWOP_ALLOC_SMALL: byte0 = prolog offset after sub, byte1 = (0<<4)|0x02.
        nodes.push([size_of_prolog as u8, 0x02]);
    }
    for (i, &reg) in pushed.iter().enumerate().rev() {
        // UWOP_PUSH_NONVOL: byte0 = offset immediately after the push.
        nodes.push([after_push[i] as u8, unwind_reg_number(reg) << 4]);
    }

    let used_nodes = nodes.len();
    let mut out = Vec::with_capacity(4 + used_nodes * 2 + 2);
    out.push(0x01); // Version=1, Flags=0
    out.push(size_of_prolog as u8);
    out.push(used_nodes as u8);
    out.push(0x00); // FrameRegister=0, FrameOffset=0
    for node in &nodes {
        out.extend_from_slice(node);
    }
    if used_nodes % 2 == 1 {
        out.extend_from_slice(&[0, 0]); // pad to even node count (not counted)
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwind_info_aligned_three_pushes() {
        let info = build_unwind_info(&[Register::RBX, Register::RDI, Register::R12], true);
        assert_eq!(info[0], 0x01);
        assert_eq!(info[1], 8); // SizeOfProlog: 1+1+2 + 4(sub) = 8
        assert_eq!(info[2], 4); // 3 pushes + 1 alloc
        assert_eq!(info[3], 0x00);
        // ALLOC_SMALL first.
        assert_eq!(&info[4..6], &[8, 0x02]);
        // Pushes in reverse: R12, RDI, RBX.
        assert_eq!(&info[6..8], &[4, 0xC0]); // R12=12
        assert_eq!(&info[8..10], &[2, 0x70]); // RDI=7
        assert_eq!(&info[10..12], &[1, 0x30]); // RBX=3
        assert_eq!(info.len(), 12);
        assert_eq!(info.len() % 4, 0);
    }

    #[test]
    fn unwind_info_even_no_alloc_padded() {
        let info = build_unwind_info(&[Register::RBX, Register::RBP], false);
        assert_eq!(info[0], 0x01);
        assert_eq!(info[1], 2); // 1+1, no sub
        assert_eq!(info[2], 2); // 2 pushes, no alloc
        assert_eq!(info[3], 0x00);
        // Reverse: RBP, RBX.
        assert_eq!(&info[4..6], &[2, 0x50]); // RBP=5
        assert_eq!(&info[6..8], &[1, 0x30]); // RBX=3
        // 2 nodes is even: no pad node, length 4+4=8.
        assert_eq!(info.len(), 8);
        assert_eq!(info.len() % 4, 0);
    }
}
