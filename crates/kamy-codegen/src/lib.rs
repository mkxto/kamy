//! Instruction selector, linear-scan register allocator, and assembler.

pub mod encode;
pub mod isel;
mod references;
pub mod regalloc;

pub use encode::assemble;
pub use isel::select_instructions;
pub use references::rebase_instructions;
pub use regalloc::{
    CALLEE_SAVED_GPRS, RegAllocation, RegCopy, allocate_registers, callee_saved_used,
    callee_saved_xmms_used,
};

use iced_x86::{BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock};

/// Re-encode a contiguous run of decoded instructions at a new virtual address.
/// Intra-run relative branches stay correct (targets move with the block);
/// references outside the run keep their absolute targets; rip-relative
/// displacements are recomputed so they still resolve to the same absolute VA.
pub fn relocate(instrs: &[Instruction], new_va: u64) -> anyhow::Result<Vec<u8>> {
    let block = InstructionBlock::new(instrs, new_va);
    let result = BlockEncoder::encode(64, block, BlockEncoderOptions::RETURN_RELOC_INFOS)
        .map_err(|e| anyhow::anyhow!("instruction encode failed: {e}"))?;
    anyhow::ensure!(
        result.reloc_infos.is_empty(),
        "branch requires an absolute far thunk"
    );
    tracing::trace!(
        bytes = result.code_buffer.len(),
        new_va = format_args!("{new_va:#x}"),
        "relocated block"
    );
    Ok(result.code_buffer)
}

/// Re-encode `instrs` at `new_va` and return the code plus each input
/// instruction's new offset relative to `new_va`.
///
/// An offset of `u32::MAX` means BlockEncoder rewrote that instruction (e.g. a
/// short branch widened) and it has no 1:1 position; a caller building an
/// address map MUST treat `u32::MAX` as a mapping failure.
pub fn relocate_with_offsets(
    instrs: &[Instruction],
    new_va: u64,
) -> anyhow::Result<(Vec<u8>, Vec<u32>)> {
    let block = InstructionBlock::new(instrs, new_va);
    let result = BlockEncoder::encode(
        64,
        block,
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS
            | BlockEncoderOptions::RETURN_RELOC_INFOS,
    )
    .map_err(|e| anyhow::anyhow!("instruction encode failed: {e}"))?;
    anyhow::ensure!(
        result.reloc_infos.is_empty(),
        "branch requires an absolute far thunk"
    );
    tracing::trace!(
        bytes = result.code_buffer.len(),
        new_va = format_args!("{new_va:#x}"),
        "relocated block"
    );
    Ok((result.code_buffer, result.new_instruction_offsets))
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
    fn relocate_with_offsets_retargets_dispatch() {
        let bytes = [
            0x83, 0xE1, 0x03, // and ecx,3
            0x48, 0x8D, 0x15, 0xF6, 0x0F, 0x00, 0x00, // lea rdx,[rip+0xff6]
            0x48, 0x63, 0x0C, 0x8A, // movsxd rcx,[rdx+rcx*4]
            0x48, 0x01, 0xD1, // add rcx,rdx
            0xFF, 0xE1, // jmp rcx
        ];
        let mut instrs = decode(&bytes, 0x1_4000_1000);
        assert_eq!(instrs.len(), 5);
        assert_eq!(instrs[1].mnemonic(), Mnemonic::Lea);

        let new_va = 0x1_4020_0000;
        let new_table_va = new_va + 0x4000;
        instrs[1].set_memory_displacement64(new_table_va);

        let (code, offs) = relocate_with_offsets(&instrs, new_va).unwrap();
        assert_eq!(offs.len(), 5);
        assert!(offs.iter().all(|&o| o != u32::MAX));
        assert!(offs.windows(2).all(|w| w[0] <= w[1]));

        let mut decoder = Decoder::with_ip(
            64,
            &code[offs[1] as usize..],
            new_va + offs[1] as u64,
            DecoderOptions::NONE,
        );
        let lea = decoder.decode();
        assert_eq!(lea.mnemonic(), Mnemonic::Lea);
        assert_eq!(lea.memory_displacement64(), new_table_va);
    }
}
