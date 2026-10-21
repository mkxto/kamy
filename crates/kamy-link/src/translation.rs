use std::collections::BTreeMap;

use anyhow::{Context, ensure};
use iced_x86::{Code, FlowControl, Instruction, OpKind, Register};
use kamy_core::Rva;

pub(crate) const HELPER_LEN: u32 = 63;
pub(crate) const CHECK_BYTES: [u8; 5] = [0xf3, 0x0f, 0x1e, 0xfa, 0xc3];

pub(crate) fn instrument(
    instructions: &mut [Instruction],
) -> anyhow::Result<Vec<(usize, Register)>> {
    let mut sites = Vec::new();
    for (index, instruction) in instructions.iter_mut().enumerate() {
        let code = match instruction.flow_control() {
            FlowControl::IndirectCall if instruction.op0_kind() == OpKind::Register => {
                Code::Call_rel32_64
            }
            FlowControl::IndirectBranch if instruction.op0_kind() == OpKind::Register => {
                Code::Jmp_rel32_64
            }
            _ => continue,
        };
        let source = instruction.op0_register();
        ensure!(
            source.is_gpr64() && source != Register::RSP,
            "unsupported indirect source register"
        );
        let ip = instruction.ip();
        *instruction = Instruction::with_branch(code, 0)?;
        instruction.set_ip(ip);
        sites.push((index, source));
    }
    Ok(sites)
}

pub(crate) fn helper(source: Register, helper_rva: u32, table_rva: u32) -> anyhow::Result<Vec<u8>> {
    ensure!(
        source.is_gpr64() && source != Register::RSP,
        "unsupported indirect source register"
    );
    let register = (source as u32)
        .checked_sub(Register::RAX as u32)
        .context("invalid source register")?;
    ensure!(register < 16, "invalid source register");
    let table_next = helper_rva
        .checked_add(36)
        .context("translator RVA overflow")?;
    let table_disp = i32::try_from(i64::from(table_rva) - i64::from(table_next))
        .context("translation table outside RIP-relative range")?;
    let mut bytes = Vec::with_capacity(HELPER_LEN as usize);
    bytes.extend_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]);
    bytes.extend_from_slice(&[
        0x4c | u8::from(register >= 8),
        0x8b,
        0xd8 | (register as u8 & 7),
    ]);
    bytes.extend_from_slice(&[0x9c, 0x50, 0x41, 0x52]);
    bytes.extend_from_slice(&[0x4c, 0x8d, 0x15]);
    bytes.extend_from_slice(&(-18i32).to_le_bytes());
    bytes.push(0xb8);
    bytes.extend_from_slice(&helper_rva.to_le_bytes());
    bytes.extend_from_slice(&[0x49, 0x29, 0xc2, 0x4d, 0x29, 0xd3]);
    bytes.extend_from_slice(&[0x48, 0x8d, 0x05]);
    bytes.extend_from_slice(&table_disp.to_le_bytes());
    // The MAX/MAX sentinel makes every non-image target an unchanged miss.
    bytes.extend_from_slice(&[
        0x4c, 0x3b, 0x18, 0x72, 0x0c, 0x74, 0x06, 0x48, 0x8d, 0x40, 0x10, 0xeb, 0xf3, 0x4c, 0x8b,
        0x58, 0x08, 0x4d, 0x01, 0xd3, 0x41, 0x5a, 0x58, 0x9d, 0x41, 0xff, 0xe3,
    ]);
    Ok(bytes)
}

pub(crate) fn table(addresses: &BTreeMap<Rva, Rva>) -> anyhow::Result<Vec<u8>> {
    let capacity = addresses
        .len()
        .checked_add(1)
        .and_then(|len| len.checked_mul(16))
        .context("translation table size overflow")?;
    let mut bytes = Vec::with_capacity(capacity);
    for (&old, &new) in addresses {
        bytes.extend_from_slice(&u64::from(old.get()).to_le_bytes());
        bytes.extend_from_slice(&u64::from(new.get()).to_le_bytes());
    }
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};

    #[test]
    fn helper_preserves_dispatch_input_before_saving_scratch() {
        let bytes = helper(Register::RAX, 0x5000, 0x8000).unwrap();
        assert_eq!(bytes.len(), HELPER_LEN as usize);
        let mut decoder = Decoder::with_ip(64, &bytes, 0x140005000, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            instructions.push(decoder.decode());
        }
        assert!(
            instructions
                .iter()
                .all(|instruction| !instruction.is_invalid())
        );
        assert_eq!(instructions[1].op0_register(), Register::R11);
        assert_eq!(instructions[1].op1_register(), Register::RAX);
        assert_eq!(instructions.last().unwrap().mnemonic(), Mnemonic::Jmp);
        assert_eq!(instructions.last().unwrap().op0_register(), Register::R11);
        let pushes = instructions
            .iter()
            .filter(|instruction| instruction.mnemonic() == Mnemonic::Push)
            .count();
        let pops = instructions
            .iter()
            .filter(|instruction| instruction.mnemonic() == Mnemonic::Pop)
            .count();
        assert_eq!(pushes, pops);
    }

    #[test]
    fn translator_reads_each_source_before_clobbering_scratch() {
        for source in [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::RBX,
            Register::RBP,
            Register::RSI,
            Register::RDI,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ] {
            let bytes = helper(source, 0x5000, 0x8000).unwrap();
            let mut decoder = Decoder::with_ip(64, &bytes, 0x140005000, DecoderOptions::NONE);
            let _ = decoder.decode();
            let load = decoder.decode();
            assert_eq!(load.mnemonic(), Mnemonic::Mov);
            assert_eq!(load.op0_register(), Register::R11);
            assert_eq!(load.op1_register(), source);
        }
    }

    #[test]
    fn table_is_sorted_and_has_unchanged_miss_sentinel() {
        let addresses = BTreeMap::from([
            (Rva::new(0x2000), Rva::new(0x6000)),
            (Rva::new(0x1000), Rva::new(0x5000)),
        ]);
        let bytes = table(&addresses).unwrap();
        assert_eq!(&bytes[..8], &0x1000u64.to_le_bytes());
        assert_eq!(&bytes[16..24], &0x2000u64.to_le_bytes());
        assert_eq!(&bytes[32..], &[0xff; 16]);
    }
}
