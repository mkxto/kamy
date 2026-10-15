use std::collections::BTreeSet;

use kamy_core::{Function, Module, Rva};

use crate::cfg::recover_impl;

pub fn discover_functions(module: &Module, seeds: &[Rva]) -> Vec<Function> {
    let mut worklist: Vec<Rva> = seeds
        .iter()
        .copied()
        .filter(|&rva| module.is_executable(rva))
        .collect();
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    let mut functions: Vec<Function> = Vec::new();

    while let Some(entry) = worklist.pop() {
        if !visited.insert(entry.get()) {
            continue;
        }
        if !module.is_executable(entry) {
            continue;
        }
        let (function, calls) = recover_impl(module, entry);
        for target in calls {
            if !visited.contains(&target.get()) {
                worklist.push(target);
            }
        }
        functions.push(function);
    }

    functions.sort_by_key(|f| f.entry.get());
    functions
}
