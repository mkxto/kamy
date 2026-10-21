use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Instruction, OpKind, Register};

/// Rebase exact external address references. In-slice instruction IPs remain
/// BlockEncoder labels. Immediate literals have no address provenance and stay
/// unchanged; absolute address operands MUST be verified and patched by the caller.
pub fn rebase_instructions(
    instrs: &mut [Instruction],
    addresses: &BTreeMap<u64, u64>,
) -> anyhow::Result<()> {
    let labels: BTreeSet<_> = instrs
        .iter()
        .map(Instruction::ip)
        .filter(|ip| *ip != 0)
        .collect();
    for inst in instrs {
        for operand in 0..inst.op_count() {
            match inst.op_kind(operand) {
                OpKind::NearBranch64 | OpKind::NearBranch32 | OpKind::NearBranch16 => {
                    let target = inst.near_branch_target();
                    if labels.contains(&target) {
                        continue;
                    }
                    if let Some(&new) = addresses.get(&target) {
                        match inst.op_kind(operand) {
                            OpKind::NearBranch64 => inst.set_near_branch64(new),
                            OpKind::NearBranch32 => inst.set_near_branch32(u32::try_from(new)?),
                            OpKind::NearBranch16 => inst.set_near_branch16(u16::try_from(new)?),
                            _ => unreachable!(),
                        }
                    }
                }
                OpKind::FarBranch16 | OpKind::FarBranch32 => {
                    anyhow::bail!("far branches are not supported by reference rebasing");
                }
                _ => {}
            }
        }
        if inst.is_ip_rel_memory_operand() {
            let target = inst.ip_rel_memory_address();
            if !labels.contains(&target) {
                if let Some(&new) = addresses.get(&target) {
                    anyhow::ensure!(
                        inst.memory_base() != Register::EIP || u32::try_from(new).is_ok(),
                        "rebased EIP-relative address exceeds 32 bits"
                    );
                    inst.set_memory_displacement64(new);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Code, Decoder, DecoderOptions, MemoryOperand, Mnemonic};

    fn decode(code: &[u8], va: u64) -> Vec<Instruction> {
        Decoder::with_ip(64, code, va, DecoderOptions::NONE)
            .into_iter()
            .collect()
    }

    #[test]
    fn external_calls_branches_and_lea_rebase_but_data_does_not() {
        let old = 0x1_4000_1000;
        let new = 0x1_4001_0000;
        let data = old + 0x8000;
        let mut instrs = vec![
            Instruction::with_branch(Code::Call_rel32_64, old).unwrap(),
            Instruction::with_branch(Code::Jne_rel32_64, old).unwrap(),
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RAX,
                MemoryOperand::with_base_displ(Register::RIP, old as i64),
            )
            .unwrap(),
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base_displ(Register::RIP, data as i64),
            )
            .unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, Register::RDX, old).unwrap(),
        ];
        instrs[3].set_segment_prefix(Register::GS);
        rebase_instructions(&mut instrs, &BTreeMap::from([(old, new)])).unwrap();
        let out = decode(
            &crate::relocate(&instrs, new + 0x1000).unwrap(),
            new + 0x1000,
        );
        assert_eq!(out[0].near_branch_target(), new);
        assert_eq!(out[1].near_branch_target(), new);
        assert_eq!(out[2].ip_rel_memory_address(), new);
        assert_eq!(out[3].ip_rel_memory_address(), data);
        assert_eq!(out[3].segment_prefix(), Register::GS);
        assert_eq!(out[4].immediate64(), old);
    }

    #[test]
    fn internal_and_synthetic_labels_override_external_map() {
        for label in [0x1000, 0x7FFF_0000_0000] {
            let mut target = Instruction::with(Code::Retnq);
            target.set_ip(label);
            let mut instrs = vec![
                Instruction::with_branch(Code::Jmp_rel32_64, label).unwrap(),
                target,
            ];
            rebase_instructions(&mut instrs, &BTreeMap::from([(label, 0x8000)])).unwrap();
            let out = decode(&crate::relocate(&instrs, 0x4000).unwrap(), 0x4000);
            assert_eq!(out[0].near_branch_target(), out[1].ip());
            assert_eq!(out[1].mnemonic(), Mnemonic::Ret);
        }
    }

    #[test]
    fn far_external_branch_fails_instead_of_emitting_pointer_thunk() {
        let instrs = [Instruction::with_branch(Code::Jmp_rel32_64, 0x1_0000_0000).unwrap()];
        assert!(crate::relocate(&instrs, 0x1000).is_err());
        assert!(crate::relocate_with_offsets(&instrs, 0x1000).is_err());
    }

    #[test]
    fn eip_relative_rebase_rejects_truncation() {
        let mut instrs = decode(&[0x67, 0x48, 0x8D, 0x05, 0, 0, 0, 0], 0x1000);
        let target = instrs[0].ip_rel_memory_address();
        assert!(
            rebase_instructions(&mut instrs, &BTreeMap::from([(target, 0x1_0000_0000)])).is_err()
        );
    }
}
