//! Instruction selector, linear-scan register allocator, and assembler.

pub mod encode;
pub mod isel;
pub mod regalloc;

pub use encode::assemble;
pub use isel::select_instructions;
pub use regalloc::{RegAllocation, RegCopy, allocate_registers};

use std::fmt;

use iced_x86::{BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock};

#[derive(Debug)]
pub enum CodegenError {
    Encode(String),
}

impl fmt::Display for CodegenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodegenError::Encode(msg) => write!(f, "instruction encode failed: {msg}"),
        }
    }
}

impl std::error::Error for CodegenError {}

/// Re-encode a contiguous run of decoded instructions at a new virtual address.
/// Intra-run relative branches stay correct (targets move with the block);
/// references outside the run keep their absolute targets; rip-relative
/// displacements are recomputed so they still resolve to the same absolute VA.
pub fn relocate(instrs: &[Instruction], new_va: u64) -> Result<Vec<u8>, CodegenError> {
    let block = InstructionBlock::new(instrs, new_va);
    let result = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
        .map_err(|e| CodegenError::Encode(e.to_string()))?;
    Ok(result.code_buffer)
}

/// Emit a jump thunk from `site_va` to `target_va`:
/// 5-byte `E9 rel32` when the displacement fits in i32, else the 14-byte
/// `FF 25 00000000` + `dq target_va` rip-indirect form.
pub fn thunk(site_va: u64, target_va: u64) -> Vec<u8> {
    let rel = (target_va as i64).wrapping_sub(site_va.wrapping_add(5) as i64);
    if let Ok(rel32) = i32::try_from(rel) {
        let mut out = Vec::with_capacity(5);
        out.push(0xE9);
        out.extend_from_slice(&rel32.to_le_bytes());
        out
    } else {
        let mut out = Vec::with_capacity(14);
        out.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&target_va.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};

    fn decode(bytes: &[u8], va: u64) -> Vec<Instruction> {
        let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
        let mut out = Vec::new();
        while decoder.can_decode() {
            out.push(decoder.decode());
        }
        out
    }

    #[test]
    fn relocate_preserves_intra_run_branch() {
        let bytes = [
            0x0F, 0x84, 0x05, 0x00, 0x00, 0x00, // je +5 -> 0x100B
            0x90, 0x90, 0x90, 0x90, 0x90, // nop padding
            0xC3, // ret at 0x100B (branch target)
        ];
        let instrs = decode(&bytes, 0x1000);
        assert_eq!(instrs.last().unwrap().mnemonic(), Mnemonic::Ret);

        let code = relocate(&instrs, 0x5000).unwrap();
        let out = decode(&code, 0x5000);

        let branch = out
            .iter()
            .find(|i| i.mnemonic() == Mnemonic::Je)
            .expect("conditional branch present");
        let ret_va = out
            .iter()
            .find(|i| i.mnemonic() == Mnemonic::Ret)
            .expect("ret present")
            .ip();
        assert_eq!(branch.near_branch_target(), ret_va);
    }

    #[test]
    fn relocate_preserves_external_branch_target() {
        let bytes = [
            0x90, // nop at 0x1000
            0xE9, 0xFA, 0x7F, 0x00, 0x00, // jmp 0x9000 at 0x1001
        ];
        let instrs = decode(&bytes, 0x1000);
        assert_eq!(instrs[1].near_branch_target(), 0x9000);

        let code = relocate(&instrs, 0x5000).unwrap();
        let out = decode(&code, 0x5000);
        let jmp = out
            .iter()
            .find(|i| i.mnemonic() == Mnemonic::Jmp)
            .expect("jmp present");
        assert_eq!(jmp.near_branch_target(), 0x9000);
    }

    #[test]
    fn thunk_near_is_rel32() {
        let out = thunk(0x1000, 0x2000);
        assert_eq!(out.len(), 5);
        assert_eq!(out[0], 0xE9);
    }

    #[test]
    fn thunk_far_is_rip_indirect() {
        let out = thunk(0x1000, 0x1_0000_0000);
        assert_eq!(out.len(), 14);
        assert_eq!(&out[..2], &[0xFF, 0x25]);
        assert_eq!(&out[6..], &0x1_0000_0000u64.to_le_bytes());
    }
}
