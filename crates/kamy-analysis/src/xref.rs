//! Call-graph and cross-reference map over discovered functions (#18).
//!
//! For each function it records the direct call edges to other discovered
//! functions and the incoming call-site count per function. The high-xref set
//! (the most-called functions) is the free byproduct that drives high-value
//! targeting (#29).

use std::collections::{HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
use kamy_core::{Module, Rva};

/// Direct-call graph plus per-function incoming call-site counts.
#[derive(Debug, Default, Clone)]
pub struct CallGraph {
    /// Function entry RVA → direct call-site targets that are themselves
    /// discovered function entries (duplicates kept: one per call site).
    callees: HashMap<u32, Vec<u32>>,
    /// Function entry RVA → number of direct call sites that target it.
    xref_in: HashMap<u32, u32>,
}

impl CallGraph {
    /// Incoming direct call-site count for the function at `rva`.
    pub fn xref_count(&self, rva: Rva) -> u32 {
        self.xref_in.get(&rva.get()).copied().unwrap_or(0)
    }

    /// Direct call targets of the function at `rva`.
    pub fn callees(&self, rva: Rva) -> &[u32] {
        self.callees.get(&rva.get()).map_or(&[], Vec::as_slice)
    }

    /// The `n` most-called functions, highest first (ties broken by ascending
    /// RVA for determinism).
    pub fn top_xref(&self, n: usize) -> Vec<(Rva, u32)> {
        let mut ranked: Vec<(Rva, u32)> = self
            .xref_in
            .iter()
            .map(|(&rva, &count)| (Rva::new(rva), count))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.get().cmp(&b.0.get())));
        ranked.truncate(n);
        ranked
    }
}

/// Build the direct-call graph by decoding each discovered function and
/// resolving `call rel32` targets that land on another function's entry.
/// Indirect and register calls carry no static own-function target and are not
/// counted.
pub fn build_call_graph(module: &Module) -> CallGraph {
    let starts: HashSet<u32> = module.functions.iter().map(|f| f.entry.get()).collect();
    let mut xref_in: HashMap<u32, u32> = starts.iter().map(|&s| (s, 0)).collect();
    let mut callees: HashMap<u32, Vec<u32>> = HashMap::new();

    for func in &module.functions {
        let mut outs = Vec::new();
        for block in &func.blocks {
            let len = block.end.get().saturating_sub(block.start.get()) as usize;
            let bytes = match module.bytes_at(block.start) {
                Some(b) => &b[..len.min(b.len())],
                None => continue,
            };
            let ip = module.image_base + u64::from(block.start.get());
            let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
            while decoder.can_decode() {
                let insn = decoder.decode();
                if insn.is_invalid() {
                    break;
                }
                if insn.flow_control() == FlowControl::Call
                    && insn.op0_kind() == OpKind::NearBranch64
                {
                    let target = insn.near_branch_target();
                    if let Some(rva) = target.checked_sub(module.image_base) {
                        if let Ok(rva) = u32::try_from(rva) {
                            if starts.contains(&rva) {
                                outs.push(rva);
                                *xref_in.entry(rva).or_default() += 1;
                            }
                        }
                    }
                }
            }
        }
        callees.insert(func.entry.get(), outs);
    }

    CallGraph { callees, xref_in }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::{BasicBlock, Function, Machine, Section, SectionFlags, Terminator};

    #[test]
    fn counts_direct_call_sites() {
        // 0x1000 `leaf`: ret.
        // 0x1010 `caller`: call leaf; call leaf; ret  (two call sites to leaf).
        //   E8 EB FF FF FF  call 0x1000 (from 0x1010, next ip 0x1015, rel -0x15)
        //   E8 E6 FF FF FF  call 0x1000 (from 0x1015, next ip 0x101a, rel -0x1a)
        //   C3              ret
        let mut data = vec![0u8; 0x1020];
        data[0x1000] = 0xC3;
        data[0x1010..0x101a]
            .copy_from_slice(&[0xE8, 0xEB, 0xFF, 0xFF, 0xFF, 0xE8, 0xE6, 0xFF, 0xFF, 0xFF]);
        data[0x101a] = 0xC3;
        let section = Section {
            name: ".text".into(),
            rva: Rva::new(0),
            virtual_size: data.len() as u32,
            data,
            flags: SectionFlags {
                read: true,
                write: false,
                execute: true,
            },
        };
        let mk = |start: u32, end: u32| Function {
            entry: Rva::new(start),
            blocks: vec![BasicBlock {
                start: Rva::new(start),
                end: Rva::new(end),
                successors: vec![],
                terminator: Terminator::Return,
            }],
        };
        let module = Module {
            image_base: 0x1_4000_0000,
            machine: Machine::X64,
            entry_point: None,
            sections: vec![section],
            symbols: vec![],
            relocations: vec![],
            functions: vec![mk(0x1000, 0x1001), mk(0x1010, 0x101b)],
        };

        let cg = build_call_graph(&module);
        assert_eq!(cg.xref_count(Rva::new(0x1000)), 2);
        assert_eq!(cg.xref_count(Rva::new(0x1010)), 0);
        assert_eq!(cg.callees(Rva::new(0x1010)), &[0x1000, 0x1000]);
        assert_eq!(cg.top_xref(1), vec![(Rva::new(0x1000), 2)]);
    }
}
