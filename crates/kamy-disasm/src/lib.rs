//! Disassembler (iced-x86 wrapper), CFG recovery, and function discovery.

mod branch;
mod cfg;
mod discover;
mod instrs;

pub use branch::branch_target;
pub use cfg::recover_function;
pub use discover::discover_functions;
pub use instrs::function_instructions;

use kamy_core::{Module, Rva};

/// Convert an absolute VA back to an in-module executable `Rva`.
///
/// Returns `None` when the address lies below the image base, does not fit in
/// an `Rva`, or falls outside any executable section (i.e. external to the
/// code we are allowed to follow).
pub(crate) fn to_in_exec_rva(module: &Module, va: u64) -> Option<Rva> {
    let offset = va.checked_sub(module.image_base)?;
    let rva = Rva::new(u32::try_from(offset).ok()?);
    module.is_executable(rva).then_some(rva)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions, Instruction};
    use kamy_core::{Machine, Section, SectionFlags, Terminator};

    const BASE: u64 = 0x1_4000_0000;
    const TEXT_RVA: u32 = 0x1000;

    fn exec_module(data: Vec<u8>) -> Module {
        Module {
            image_base: BASE,
            machine: Machine::X64,
            entry_point: Some(Rva::new(TEXT_RVA)),
            sections: vec![Section {
                name: ".text".to_string(),
                rva: Rva::new(TEXT_RVA),
                virtual_size: 0x1000,
                data,
                flags: SectionFlags {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            symbols: Vec::new(),
            relocations: Vec::new(),
            functions: Vec::new(),
        }
    }

    fn decode_one(bytes: &[u8]) -> Instruction {
        Decoder::with_ip(64, bytes, BASE, DecoderOptions::NONE).decode()
    }

    #[test]
    fn branch_target_direct_and_gotchas() {
        // E9 00000000  jmp rel32 +0  -> BASE + 5
        let jmp = decode_one(&[0xE9, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(branch_target(&jmp), Some(BASE + 5));

        // 0F 84 00000000  je rel32 +0  -> BASE + 6
        let je = decode_one(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(branch_target(&je), Some(BASE + 6));

        // 0F 05  syscall  (FlowControl::Call, no operand)
        let syscall = decode_one(&[0x0F, 0x05]);
        assert_eq!(branch_target(&syscall), None);

        // 0F 01 C1  vmcall  (FlowControl::Call, no operand)
        let vmcall = decode_one(&[0x0F, 0x01, 0xC1]);
        assert_eq!(branch_target(&vmcall), None);
    }

    #[test]
    fn recover_conditional_branch() {
        // 0x1000: 0F 85 06000000  jne +6     -> taken 0x100C
        // 0x1006: 48 31 C0        xor rax,rax
        // 0x1009: C3              ret
        // 0x100A: 90 90           padding (unreachable)
        // 0x100C: C3              ret        (taken block)
        let data = vec![
            0x0F, 0x85, 0x06, 0x00, 0x00, 0x00, 0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0xC3,
        ];
        let module = exec_module(data);
        let function = recover_function(&module, Rva::new(TEXT_RVA));

        assert!(function.blocks.len() >= 2);
        let entry_block = function
            .blocks
            .iter()
            .find(|b| b.start == Rva::new(0x1000))
            .expect("entry block");
        match entry_block.terminator {
            Terminator::Branch { taken, not_taken } => {
                assert_eq!(taken, Rva::new(0x100C));
                assert_eq!(not_taken, Rva::new(0x1006));
            }
            ref other => panic!("expected branch terminator, got {other:?}"),
        }
        assert_eq!(
            entry_block.successors,
            vec![Rva::new(0x100C), Rva::new(0x1006)]
        );
    }

    #[test]
    fn indirect_slot_classification() {
        // 0x1000: FF 25 FA 04 00 00   jmp qword [rip+0x4fa] -> slot VA base+0x1500
        let rip_rel = recover_function(
            &exec_module(vec![0xFF, 0x25, 0xFA, 0x04, 0x00, 0x00]),
            Rva::new(TEXT_RVA),
        );
        assert_eq!(
            rip_rel.blocks[0].terminator,
            Terminator::Indirect {
                slot: Some(Rva::new(0x1500))
            }
        );

        // 0x1000: FF E0   jmp rax -> register dispatch, no static slot
        let reg = recover_function(&exec_module(vec![0xFF, 0xE0]), Rva::new(TEXT_RVA));
        assert_eq!(
            reg.blocks[0].terminator,
            Terminator::Indirect { slot: None }
        );
    }

    #[test]
    fn discover_follows_call() {
        // 0x1000: E8 0A000000  call +0x0A  -> 0x100F
        // 0x1005: C3           ret
        // 0x1006..0x100E: padding
        // 0x100F: C3           ret         (second function body)
        let mut data = vec![0xE8, 0x0A, 0x00, 0x00, 0x00, 0xC3];
        while data.len() < 0x0F {
            data.push(0x90);
        }
        data.push(0xC3);
        let module = exec_module(data);

        let functions = discover_functions(&module, &[Rva::new(TEXT_RVA)]);
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].entry, Rva::new(0x1000));
        assert_eq!(functions[1].entry, Rva::new(0x100F));
    }

    #[test]
    fn malformed_bytes_do_not_panic() {
        // 0xFF alone is an incomplete/invalid encoding; decode must degrade to Unknown.
        let module = exec_module(vec![0xFF]);
        let function = recover_function(&module, Rva::new(TEXT_RVA));
        assert_eq!(function.entry, Rva::new(TEXT_RVA));
        assert!(matches!(
            function.blocks.first().map(|b| &b.terminator),
            Some(Terminator::Unknown)
        ));
    }
}
