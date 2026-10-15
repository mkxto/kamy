use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};
use kamy_core::{BasicBlock, Function, Module, Rva, Terminator};

use crate::branch::branch_target;
use crate::to_in_exec_rva;

enum EndKind {
    Normal,
    Return,
    Jump(u32),
    Indirect,
    Branch { taken: u32, not_taken: u32 },
    Unknown,
}

struct InstrRecord {
    end: u32,
    kind: EndKind,
}

pub fn recover_function(module: &Module, entry: Rva) -> Function {
    recover_impl(module, entry).0
}

/// Recover one function and report the direct call targets seen while decoding
/// it, so `discover_functions` can grow its worklist without decoding twice.
pub(crate) fn recover_impl(module: &Module, entry: Rva) -> (Function, Vec<Rva>) {
    let mut instrs: BTreeMap<u32, InstrRecord> = BTreeMap::new();
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    let mut calls: Vec<Rva> = Vec::new();
    let mut seen_calls: BTreeSet<u32> = BTreeSet::new();

    leaders.insert(entry.get());
    let mut worklist = vec![entry.get()];
    while let Some(start) = worklist.pop() {
        decode_run(
            module,
            start,
            &mut instrs,
            &mut leaders,
            &mut worklist,
            &mut calls,
            &mut seen_calls,
        );
    }

    let blocks = build_blocks(&instrs, &leaders);
    (Function { entry, blocks }, calls)
}

#[allow(clippy::too_many_arguments)]
fn decode_run(
    module: &Module,
    start: u32,
    instrs: &mut BTreeMap<u32, InstrRecord>,
    leaders: &mut BTreeSet<u32>,
    worklist: &mut Vec<u32>,
    calls: &mut Vec<Rva>,
    seen_calls: &mut BTreeSet<u32>,
) {
    if instrs.contains_key(&start) {
        return;
    }
    let start_rva = Rva::new(start);
    if !module.is_executable(start_rva) {
        return;
    }
    let Some(bytes) = module.bytes_at(start_rva) else {
        return;
    };

    let mut decoder = Decoder::with_ip(
        64,
        bytes,
        module.image_base + start as u64,
        DecoderOptions::NONE,
    );

    loop {
        let cur = (decoder.ip() - module.image_base) as u32;
        if instrs.contains_key(&cur) {
            return;
        }
        if !decoder.can_decode() {
            return;
        }
        let instr = decoder.decode();
        if instr.is_invalid() {
            return;
        }
        let Some(next) = cur.checked_add(instr.len() as u32) else {
            return;
        };

        let kind = classify(module, &instr, next, calls, seen_calls);
        let successors: Vec<u32> = match &kind {
            EndKind::Jump(target) => vec![*target],
            EndKind::Branch { taken, not_taken } => vec![*taken, *not_taken],
            _ => Vec::new(),
        };
        let ends_block = !matches!(kind, EndKind::Normal);
        instrs.insert(cur, InstrRecord { end: next, kind });

        if ends_block {
            for succ in successors {
                leaders.insert(succ);
                if !instrs.contains_key(&succ) {
                    worklist.push(succ);
                }
            }
            return;
        }
    }
}

fn classify(
    module: &Module,
    instr: &Instruction,
    next: u32,
    calls: &mut Vec<Rva>,
    seen_calls: &mut BTreeSet<u32>,
) -> EndKind {
    match instr.flow_control() {
        FlowControl::Next => EndKind::Normal,
        FlowControl::Call | FlowControl::IndirectCall => {
            if let Some(target) = branch_target(instr).and_then(|va| to_in_exec_rva(module, va)) {
                if seen_calls.insert(target.get()) {
                    calls.push(target);
                }
            }
            EndKind::Normal
        }
        FlowControl::ConditionalBranch => {
            let taken = branch_target(instr).and_then(|va| to_in_exec_rva(module, va));
            let not_taken = to_in_exec_rva(module, module.image_base + next as u64);
            match (taken, not_taken) {
                (Some(taken), Some(not_taken)) => EndKind::Branch {
                    taken: taken.get(),
                    not_taken: not_taken.get(),
                },
                _ => EndKind::Unknown,
            }
        }
        FlowControl::UnconditionalBranch => {
            match branch_target(instr).and_then(|va| to_in_exec_rva(module, va)) {
                Some(target) => EndKind::Jump(target.get()),
                None => EndKind::Unknown,
            }
        }
        FlowControl::IndirectBranch => EndKind::Indirect,
        FlowControl::Return => EndKind::Return,
        FlowControl::Interrupt => match instr.mnemonic() {
            Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq => EndKind::Return,
            _ => EndKind::Normal,
        },
        FlowControl::Exception => EndKind::Unknown,
        FlowControl::XbeginXabortXend => EndKind::Normal,
    }
}

fn build_blocks(instrs: &BTreeMap<u32, InstrRecord>, leaders: &BTreeSet<u32>) -> Vec<BasicBlock> {
    let mut blocks = Vec::with_capacity(leaders.len());
    for &leader in leaders {
        let mut cur = leader;
        let (terminator, end, successors) = loop {
            let Some(rec) = instrs.get(&cur) else {
                break (Terminator::Unknown, Rva::new(cur), Vec::new());
            };
            match &rec.kind {
                EndKind::Normal => {
                    let next = rec.end;
                    if leaders.contains(&next) {
                        if instrs.contains_key(&next) {
                            break (
                                Terminator::Fallthrough(Rva::new(next)),
                                Rva::new(next),
                                vec![Rva::new(next)],
                            );
                        }
                        break (Terminator::Unknown, Rva::new(next), Vec::new());
                    }
                    if instrs.contains_key(&next) {
                        cur = next;
                        continue;
                    }
                    break (Terminator::Unknown, Rva::new(next), Vec::new());
                }
                EndKind::Return => break (Terminator::Return, Rva::new(rec.end), Vec::new()),
                EndKind::Indirect => break (Terminator::Indirect, Rva::new(rec.end), Vec::new()),
                EndKind::Jump(target) => {
                    break (
                        Terminator::Jump(Rva::new(*target)),
                        Rva::new(rec.end),
                        vec![Rva::new(*target)],
                    );
                }
                EndKind::Branch { taken, not_taken } => {
                    break (
                        Terminator::Branch {
                            taken: Rva::new(*taken),
                            not_taken: Rva::new(*not_taken),
                        },
                        Rva::new(rec.end),
                        vec![Rva::new(*taken), Rva::new(*not_taken)],
                    );
                }
                EndKind::Unknown => break (Terminator::Unknown, Rva::new(rec.end), Vec::new()),
            }
        };
        blocks.push(BasicBlock {
            start: Rva::new(leader),
            end,
            successors,
            terminator,
        });
    }
    blocks
}
