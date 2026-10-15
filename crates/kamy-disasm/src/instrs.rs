use iced_x86::{Decoder, DecoderOptions, Instruction};
use kamy_core::{BasicBlock, Function, Module};

/// Decode every instruction of a recovered function, ordered by address.
///
/// Each instruction keeps its original IP (`image_base + rva`), so the run can
/// be handed straight to a relocating encoder whose intra-run branch fixups rely
/// on those IPs.
pub fn function_instructions(module: &Module, func: &Function) -> Vec<Instruction> {
    let mut blocks: Vec<&BasicBlock> = func.blocks.iter().collect();
    blocks.sort_by_key(|b| b.start.get());

    let mut out = Vec::new();
    for block in blocks {
        let len = block.end.get().saturating_sub(block.start.get()) as usize;
        let Some(section_bytes) = module.bytes_at(block.start) else {
            continue;
        };
        let bytes = &section_bytes[..len.min(section_bytes.len())];
        let ip = module.image_base + u64::from(block.start.get());
        let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        while decoder.can_decode() {
            let insn = decoder.decode();
            if insn.is_invalid() {
                break;
            }
            out.push(insn);
        }
    }
    out
}
