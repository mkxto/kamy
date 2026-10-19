use std::collections::BTreeSet;

use kamy_core::{Function, Module, Rva, SymbolKind};

use crate::cfg::recover_impl;

/// Imports whose call never returns. A call through one of these IAT slots
/// ends the block, so recovery does not misread the following bytes (which are
/// often the next function or a jump table) as fallthrough code.
const NORETURN_IMPORTS: &[&str] = &[
    "ExitProcess",
    "ExitThread",
    "RtlExitUserProcess",
    "RtlExitUserThread",
    "RtlRaiseStatus",
    "RtlFailFast",
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "_invalid_parameter_noreturn",
    "_o__invalid_parameter_noreturn",
    "_invoke_watson",
    "longjmp",
    "_CxxThrowException",
    "terminate",
    "__std_terminate",
];

pub fn discover_functions(module: &Module, seeds: &[Rva]) -> Vec<Function> {
    let _s = tracing::info_span!("discover").entered();
    let mut worklist: Vec<Rva> = seeds
        .iter()
        .copied()
        .filter(|&rva| module.is_executable(rva))
        .collect();
    let function_starts: BTreeSet<u32> = worklist.iter().map(|r| r.get()).collect();
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    let mut functions: Vec<Function> = Vec::new();
    let noreturn_slots: BTreeSet<u32> = module
        .symbols
        .iter()
        .filter(|s| s.kind == SymbolKind::Import && NORETURN_IMPORTS.contains(&s.name.as_str()))
        .map(|s| s.rva.get())
        .collect();

    while let Some(entry) = worklist.pop() {
        if !visited.insert(entry.get()) {
            continue;
        }
        if !module.is_executable(entry) {
            continue;
        }
        let (function, calls) = recover_impl(module, entry, &function_starts, &noreturn_slots);
        for target in calls {
            if !visited.contains(&target.get()) {
                worklist.push(target);
            }
        }
        functions.push(function);
    }

    functions.sort_by_key(|f| f.entry.get());
    tracing::info!(functions = functions.len(), "discovered functions");
    functions
}
