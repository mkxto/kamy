//! Callee-side argument inference for the target's own functions.
//!
//! No metadata or PDB names these functions, so their calling convention is
//! recovered the way IDA's decompiler does it: a Win64 argument register is a
//! parameter iff it is **read before written** on some path from the entry.
//! That is the live-in set at the function entry, restricted to the argument
//! registers (`RCX/RDX/R8/R9`, `XMM0-3`).
//!
//! The result feeds caller-side argument pinning, so the analysis must never
//! *under*-count (an unpinned real argument register miscompiles the call).
//! Every approximation therefore widens the argument set, and inference is
//! restricted to the sound subset:
//! - A function containing a `call` is skipped. A call consumes its callee's
//!   argument registers, which iced does not model as reads and whose count we
//!   do not know without the callee's signature (the deferred interprocedural
//!   fixpoint); inferring one could under-count a forwarded argument. Leaf
//!   functions have only explicit reads, which iced models exactly.
//! - Partial (sub-32-bit) register writes do not count as a definition, so the
//!   register stays live-in-eligible.
//! - A block that tail-calls out of the function, or ends in an unresolved
//!   indirect/unknown transfer, is given every argument register as live-out.
//! - A non-contiguous or class-ambiguous argument prefix abandons inference for
//!   the function (it keeps the four-argument Win64 default).

use iced_x86::{Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, OpAccess, Register};
use kamy_core::ir::{FnSignature, Gpr, PhysReg, Win64Default, XmmReg};
use kamy_core::{BasicBlock, Function, Module, Rva, Terminator};
use std::collections::HashMap;

/// Live-in/def/use sets over the eight argument registers, one bit each: bits
/// 0-3 are the integer slots `RCX/RDX/R8/R9`, bits 4-7 the float slots
/// `XMM0-3`.
type ArgMask = u8;

const ALL_ARGS: ArgMask = 0xFF;
const ARG_GPRS: [Gpr; 4] = [Gpr::Rcx, Gpr::Rdx, Gpr::R8, Gpr::R9];
const ARG_XMMS: [XmmReg; 4] = [XmmReg::Xmm0, XmmReg::Xmm1, XmmReg::Xmm2, XmmReg::Xmm3];

/// Recover a narrowed Win64 signature for `func`, or `None` to keep the
/// four-argument default. Only the argument list is narrowed; the return
/// register and the full volatile clobber set stay at the Win64 default
/// (narrowing those needs the lowering-aware interprocedural pass).
pub fn infer_signature(module: &Module, func: &Function) -> Option<FnSignature> {
    if func.blocks.is_empty() {
        return None;
    }
    let index: HashMap<u32, usize> = func
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start.get(), i))
        .collect();
    let entry_bi = *index.get(&func.entry.get())?;

    let n = func.blocks.len();
    let mut uses = vec![0 as ArgMask; n];
    let mut defs = vec![0 as ArgMask; n];
    let mut exits_function = vec![false; n];
    for (i, block) in func.blocks.iter().enumerate() {
        let (u, d, has_call) = block_use_def(module, block.start, block.end);
        if has_call {
            return None;
        }
        uses[i] = u;
        defs[i] = d;
        exits_function[i] = block_leaves_function(block, &index);
    }

    let mut live_in = vec![0 as ArgMask; n];
    let mut changed = true;
    while changed {
        changed = false;
        for i in (0..n).rev() {
            let mut live_out = 0;
            if exits_function[i] {
                live_out = ALL_ARGS;
            }
            for succ in &func.blocks[i].successors {
                if let Some(&bi) = index.get(&succ.get()) {
                    live_out |= live_in[bi];
                }
            }
            let new_in = uses[i] | (live_out & !defs[i]);
            if new_in != live_in[i] {
                live_in[i] = new_in;
                changed = true;
            }
        }
    }

    args_from_mask(live_in[entry_bi]).map(|args| {
        let mut sig = Win64Default::default_signature();
        sig.args = args
            .into_iter()
            .map(kamy_core::ir::AbiValue::register)
            .collect();
        sig
    })
}

/// Build the positional argument register list from the entry live-in mask, or
/// `None` when the live-in set is not a clean, single-class contiguous prefix (a
/// gap or a slot that is live in both classes), since a skipped slot's class is
/// unknown.
fn args_from_mask(mask: ArgMask) -> Option<Vec<PhysReg>> {
    let mut max_pos: isize = -1;
    for pos in 0..4 {
        if mask & (gpr_bit(pos) | xmm_bit(pos)) != 0 {
            max_pos = pos as isize;
        }
    }
    let mut args = Vec::new();
    for pos in 0..=max_pos {
        let pos = pos as usize;
        let g = mask & gpr_bit(pos) != 0;
        let x = mask & xmm_bit(pos) != 0;
        match (g, x) {
            (true, false) => args.push(PhysReg::Gpr(ARG_GPRS[pos])),
            (false, true) => args.push(PhysReg::Xmm(ARG_XMMS[pos])),
            _ => return None,
        }
    }
    Some(args)
}

const fn gpr_bit(pos: usize) -> ArgMask {
    1 << pos
}
const fn xmm_bit(pos: usize) -> ArgMask {
    1 << (pos + 4)
}

/// `true` when control can leave the function from this block — a tail call to
/// another function, or an unresolved indirect/unknown transfer — so any
/// argument register may reach the external target and is treated as live-out.
fn block_leaves_function(block: &BasicBlock, index: &HashMap<u32, usize>) -> bool {
    let external = |rva: &Rva| !index.contains_key(&rva.get());
    match &block.terminator {
        Terminator::Indirect { .. } | Terminator::Unknown => true,
        // A direct `jmp`/conditional `jmp` whose target is another function's
        // entry is a tail call: discovery leaves that target out of this
        // function's blocks rather than absorbing the callee, so it never shows
        // up in `successors`. Inspect the terminator targets directly — missing
        // this under-counts a tail-forwarding thunk (e.g. `mov r8d,N; jmp sub`)
        // to zero arguments and drops the caller's forwarded argument setup.
        Terminator::Jump(t) | Terminator::Fallthrough(t) => external(t),
        Terminator::Branch { taken, not_taken } => external(taken) || external(not_taken),
        Terminator::Return | Terminator::Switch { .. } => block.successors.iter().any(external),
    }
}

/// Per-block use/def masks plus whether the block contains a call. A register is
/// a *use* if read before any full-width write, a *def* if full-width written
/// before any read.
fn block_use_def(module: &Module, start: Rva, end: Rva) -> (ArgMask, ArgMask, bool) {
    let len = end.get().saturating_sub(start.get()) as usize;
    let bytes = match module.bytes_at(start) {
        Some(b) => &b[..len.min(b.len())],
        None => return (0, 0, false),
    };
    let ip = module.image_base + u64::from(start.get());
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut factory = InstructionInfoFactory::new();

    let mut use_mask: ArgMask = 0;
    let mut def_mask: ArgMask = 0;
    // A slot settled once it is first read (use) or first fully written (def).
    let mut settled: ArgMask = 0;

    while decoder.can_decode() {
        let insn = decoder.decode();
        if insn.is_invalid() {
            break;
        }
        if matches!(
            insn.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) {
            return (use_mask, def_mask, true);
        }
        let info = factory.info(&insn);
        // Reads before writes within the instruction: a read-modify-write slot
        // is a use, not a def.
        for used in info.used_registers() {
            let Some((pos, is_float, _)) = arg_slot(used.register()) else {
                continue;
            };
            let bit = if is_float { xmm_bit(pos) } else { gpr_bit(pos) };
            if settled & bit != 0 {
                continue;
            }
            if is_read(used.access()) {
                use_mask |= bit;
                settled |= bit;
            }
        }
        for used in info.used_registers() {
            let Some((pos, is_float, size)) = arg_slot(used.register()) else {
                continue;
            };
            let bit = if is_float { xmm_bit(pos) } else { gpr_bit(pos) };
            if settled & bit != 0 {
                continue;
            }
            // Only a full-width write (>=32-bit GPR zero-extends to 64; a vector
            // write replaces the scalar argument bits) kills live-in. A partial
            // write leaves the slot live-in-eligible.
            if is_write(used.access()) && size >= 4 {
                def_mask |= bit;
                settled |= bit;
            }
        }
    }
    (use_mask, def_mask, false)
}

fn is_read(a: OpAccess) -> bool {
    matches!(
        a,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn is_write(a: OpAccess) -> bool {
    matches!(
        a,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Map a physical register to its Win64 argument slot `(position, is_float,
/// size_in_bytes)`, or `None` when it is not an argument register.
fn arg_slot(reg: Register) -> Option<(usize, bool, u32)> {
    let size = reg.size() as u32;
    if reg.is_gpr() {
        let pos = match reg.full_register() {
            Register::RCX => 0,
            Register::RDX => 1,
            Register::R8 => 2,
            Register::R9 => 3,
            _ => return None,
        };
        return Some((pos, false, size));
    }
    let base = if reg.is_xmm() {
        Register::XMM0
    } else if reg.is_ymm() {
        Register::YMM0
    } else if reg.is_zmm() {
        Register::ZMM0
    } else {
        return None;
    };
    let idx = reg as u32 - base as u32;
    if idx < 4 {
        Some((idx as usize, true, size))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::{BasicBlock, Function, Machine, Module, Section, SectionFlags, Terminator};

    /// A tail-forwarding thunk (`mov r8d, N; jmp sub`) reads no argument
    /// register directly but forwards RCX/RDX to the tail callee. Inference must
    /// not under-count it to zero arguments, or the caller's forwarded argument
    /// setup gets DCE'd and the call miscompiles. The tail `jmp` lands in another
    /// function, so it never appears in this block's `successors`; detection must
    /// read the terminator target, which is what this guards.
    #[test]
    fn tail_forwarding_thunk_is_not_undercounted() {
        // 41 B8 40 00 00 00  mov r8d, 0x40
        // E9 F5 0F 00 00     jmp 0x2000   (tail call to another function)
        let code = [
            0x41, 0xB8, 0x40, 0x00, 0x00, 0x00, 0xE9, 0xF5, 0x0F, 0x00, 0x00,
        ];
        let rva = Rva::new(0x1000);
        let module = Module {
            image_base: 0x1_4000_0000,
            machine: Machine::X64,
            entry_point: Some(rva),
            sections: vec![Section {
                name: ".text".to_string(),
                rva,
                virtual_size: code.len() as u32,
                data: code.to_vec(),
                flags: SectionFlags {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            symbols: vec![],
            relocations: vec![],
            functions: vec![],
        };
        let thunk = Function {
            entry: rva,
            blocks: vec![BasicBlock {
                start: rva,
                end: Rva::new(0x100B),
                successors: vec![],
                terminator: Terminator::Jump(Rva::new(0x2000)),
            }],
        };

        // None keeps the four-argument Win64 default; either way the forwarded
        // RCX/RDX must survive — never a zero/one-argument narrowing.
        let argc = infer_signature(&module, &thunk).map_or(4, |s| s.args.len());
        assert!(
            argc >= 2,
            "tail-forwarding thunk must not under-count forwarded args (got {argc})"
        );
    }
}
