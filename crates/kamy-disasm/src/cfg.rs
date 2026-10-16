use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use kamy_core::{BasicBlock, Function, Module, Rva, SwitchTable, Terminator};

use crate::branch::branch_target;
use crate::to_in_exec_rva;

enum EndKind {
    Normal,
    Return,
    Jump(u32),
    /// Direct `jmp` to a known function start: a tail call, not an intra-block
    /// edge. Terminates the block without absorbing the callee's body.
    TailJump(u32),
    Indirect(Option<Rva>),
    /// A trap (`ud2`, `int`) or a call to a known-noreturn import: control does
    /// not fall through, so the block ends here without a successor.
    NoReturn,
    Branch {
        taken: u32,
        not_taken: u32,
    },
    Unknown,
}

struct InstrRecord {
    end: u32,
    kind: EndKind,
}

pub fn recover_function(
    module: &Module,
    entry: Rva,
    function_starts: &BTreeSet<u32>,
    noreturn_slots: &BTreeSet<u32>,
) -> Function {
    recover_impl(module, entry, function_starts, noreturn_slots).0
}

/// Recover one function and report the direct call targets seen while decoding
/// it, so `discover_functions` can grow its worklist without decoding twice.
///
/// `function_starts` are the known function entries (`.pdata`/export/entry
/// seeds); a `jmp` to one of them is treated as a tail call so this function's
/// recovery stops at its true boundary instead of swallowing the neighbor.
pub(crate) fn recover_impl(
    module: &Module,
    entry: Rva,
    function_starts: &BTreeSet<u32>,
    noreturn_slots: &BTreeSet<u32>,
) -> (Function, Vec<Rva>) {
    let mut instrs: BTreeMap<u32, InstrRecord> = BTreeMap::new();
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    let mut calls: Vec<Rva> = Vec::new();
    let mut seen_calls: BTreeSet<u32> = BTreeSet::new();

    // .pdata/export/entry starts partition x64 code into non-overlapping
    // ranges; code at or past the next start belongs to the next function, so
    // recovery must not run into it (prevents runaway, cross-function spans).
    let limit = function_starts
        .range(entry.get().saturating_add(1)..)
        .next()
        .copied()
        .unwrap_or(u32::MAX);

    // Drain the worklist, decoding each pending run into fresh blocks. Reused
    // for the initial pass and every switch fixpoint round below.
    let drain = |instrs: &mut BTreeMap<u32, InstrRecord>,
                 leaders: &mut BTreeSet<u32>,
                 worklist: &mut Vec<u32>,
                 calls: &mut Vec<Rva>,
                 seen_calls: &mut BTreeSet<u32>| {
        while let Some(start) = worklist.pop() {
            decode_run(
                module,
                entry.get(),
                start,
                instrs,
                leaders,
                worklist,
                calls,
                seen_calls,
                function_starts,
                noreturn_slots,
                limit,
            );
        }
    };

    leaders.insert(entry.get());
    let mut worklist = vec![entry.get()];
    drain(
        &mut instrs,
        &mut leaders,
        &mut worklist,
        &mut calls,
        &mut seen_calls,
    );

    // D24 layer 2: recover jump tables (research.md §10.5) and materialize their
    // case bodies as real blocks. Newly decoded bodies can expose further
    // dispatches, so iterate to a fixpoint (capped) seeding each distinct case.
    let mut resolved: BTreeMap<u32, SwitchTable> = BTreeMap::new();
    let needs_switch = build_blocks(&instrs, &leaders)
        .iter()
        .any(|b| matches!(b.terminator, Terminator::Indirect { slot: None }));
    if needs_switch {
        let lo = entry.get();
        let section_end = module
            .section_at(entry)
            .map_or(u32::MAX, |s| s.rva.get().saturating_add(s.virtual_size));
        let hi = limit.min(section_end);
        for _ in 0..16 {
            let tmp = Function {
                entry,
                blocks: build_blocks(&instrs, &leaders),
            };
            let insns = crate::instrs::function_instructions(module, &tmp);
            let mut new_dispatch = false;
            for (jmp_end, table) in crate::jumptable::detect_switch(module, &insns, lo, hi) {
                if resolved.contains_key(&jmp_end) {
                    continue;
                }
                new_dispatch = true;
                let mut distinct = BTreeSet::new();
                for t in &table.entries {
                    let r = t.get();
                    // Never seed past the function boundary (§10.2 runaway bound).
                    if r >= limit || !distinct.insert(r) {
                        continue;
                    }
                    leaders.insert(r);
                    if !instrs.contains_key(&r) {
                        worklist.push(r);
                    }
                }
                resolved.insert(jmp_end, table);
            }
            if !new_dispatch {
                break;
            }
            drain(
                &mut instrs,
                &mut leaders,
                &mut worklist,
                &mut calls,
                &mut seen_calls,
            );
        }
    }

    let blocks = build_blocks(&instrs, &leaders);
    let mut func = Function { entry, blocks };
    for (jmp_end, table) in &resolved {
        for b in &mut func.blocks {
            if b.end.get() == *jmp_end
                && matches!(b.terminator, Terminator::Indirect { slot: None })
            {
                let mut successors = Vec::new();
                let mut seen = BTreeSet::new();
                for t in &table.entries {
                    if seen.insert(t.get()) {
                        successors.push(*t);
                    }
                }
                b.successors = successors;
                b.terminator = Terminator::Switch {
                    table: table.clone(),
                };
            }
        }
    }
    (func, calls)
}

#[allow(clippy::too_many_arguments)]
fn decode_run(
    module: &Module,
    entry: u32,
    start: u32,
    instrs: &mut BTreeMap<u32, InstrRecord>,
    leaders: &mut BTreeSet<u32>,
    worklist: &mut Vec<u32>,
    calls: &mut Vec<Rva>,
    seen_calls: &mut BTreeSet<u32>,
    function_starts: &BTreeSet<u32>,
    noreturn_slots: &BTreeSet<u32>,
    limit: u32,
) {
    if start >= limit || instrs.contains_key(&start) {
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
        if cur >= limit || instrs.contains_key(&cur) {
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

        let kind = classify(
            module,
            &instr,
            next,
            calls,
            seen_calls,
            entry,
            function_starts,
            noreturn_slots,
        );
        let successors: Vec<u32> = match &kind {
            EndKind::Jump(target) => vec![*target],
            EndKind::Branch { taken, not_taken } => vec![*taken, *not_taken],
            _ => Vec::new(),
        };
        let ends_block = !matches!(kind, EndKind::Normal);
        instrs.insert(cur, InstrRecord { end: next, kind });

        if ends_block {
            for succ in successors {
                if succ >= limit {
                    continue;
                }
                leaders.insert(succ);
                if !instrs.contains_key(&succ) {
                    worklist.push(succ);
                }
            }
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn classify(
    module: &Module,
    instr: &Instruction,
    next: u32,
    calls: &mut Vec<Rva>,
    seen_calls: &mut BTreeSet<u32>,
    entry: u32,
    function_starts: &BTreeSet<u32>,
    noreturn_slots: &BTreeSet<u32>,
) -> EndKind {
    match instr.flow_control() {
        FlowControl::Next => EndKind::Normal,
        FlowControl::Call | FlowControl::IndirectCall => {
            if let Some(target) = branch_target(instr).and_then(|va| to_in_exec_rva(module, va)) {
                if seen_calls.insert(target.get()) {
                    calls.push(target);
                }
            }
            // A call through a known-noreturn import slot does not return;
            // decoding the fallthrough would misread the next function's bytes.
            match static_slot(module, instr) {
                Some(slot) if noreturn_slots.contains(&slot.get()) => EndKind::NoReturn,
                _ => EndKind::Normal,
            }
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
                Some(target)
                    if target.get() != entry && function_starts.contains(&target.get()) =>
                {
                    if seen_calls.insert(target.get()) {
                        calls.push(target);
                    }
                    EndKind::TailJump(target.get())
                }
                Some(target) => EndKind::Jump(target.get()),
                None => EndKind::Unknown,
            }
        }
        FlowControl::IndirectBranch => EndKind::Indirect(static_slot(module, instr)),
        FlowControl::Return => EndKind::Return,
        FlowControl::Interrupt => match instr.mnemonic() {
            Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq => EndKind::Return,
            // `int3` may be a resumable breakpoint; other software interrupts
            // (`int 0x29` fastfail, etc.) do not return.
            Mnemonic::Int3 => EndKind::Normal,
            _ => EndKind::NoReturn,
        },
        FlowControl::Exception => EndKind::NoReturn,
        FlowControl::XbeginXabortXend => EndKind::Normal,
    }
}

/// Resolve `jmp qword [rip+disp]` / `jmp qword [abs]` to its fixed pointer-slot
/// RVA (D24 layer 0). Returns `None` for register dispatch, base-register or
/// table-indexed memory operands, and slots that fall outside the image — those
/// carry no statically known pointer. iced folds a RIP-relative displacement
/// into the absolute target, so `memory_displacement64` is the slot VA.
fn static_slot(module: &Module, instr: &Instruction) -> Option<Rva> {
    if instr.op0_kind() != OpKind::Memory || instr.memory_index() != Register::None {
        return None;
    }
    match instr.memory_base() {
        Register::RIP | Register::None => {}
        _ => return None,
    }
    let rva = instr
        .memory_displacement64()
        .checked_sub(module.image_base)?;
    let rva = Rva::new(u32::try_from(rva).ok()?);
    module.section_at(rva).map(|_| rva)
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
                EndKind::NoReturn => break (Terminator::Return, Rva::new(rec.end), Vec::new()),
                EndKind::TailJump(target) => {
                    break (
                        Terminator::Jump(Rva::new(*target)),
                        Rva::new(rec.end),
                        Vec::new(),
                    );
                }
                EndKind::Indirect(slot) => {
                    break (
                        Terminator::Indirect { slot: *slot },
                        Rva::new(rec.end),
                        Vec::new(),
                    );
                }
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
