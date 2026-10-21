//! Resolve configuration [`SymbolSelector`]s to the concrete function RVAs they
//! name, using the PDB/export/`sub_<rva>` labels. This is the bridge from a
//! profile's `symbols:` list to a [`FunctionSelector`] / per-function targeting.

use std::collections::HashSet;

use kamy_analysis::CallGraph;
use kamy_config::{Group, SymbolSelector};
use kamy_core::{Function, Rva};

/// Match a `*`/`?` wildcard `pattern` against `text` (`*` any run, `?` one
/// char). No character classes — the config patterns are simple globs.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    // Iterative wildcard match with backtracking on the last `*`.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Resolve `selectors` to the set of function entry RVAs they select. `label`
/// yields a function's display name (PDB > export > `sub_<rva>`), so name and
/// pattern matches work with or without a PDB.
pub(crate) fn resolve_targets(
    selectors: &[SymbolSelector],
    functions: &[Function],
    label: &impl Fn(Rva) -> String,
    groups: &[Group],
    cg: &CallGraph,
) -> HashSet<Rva> {
    let entries: Vec<(Rva, String)> = functions
        .iter()
        .map(|f| (f.entry, label(f.entry)))
        .collect();
    let mut out = HashSet::new();
    let mut active: HashSet<String> = HashSet::new();
    resolve_into(
        selectors,
        &entries,
        functions,
        groups,
        cg,
        &mut active,
        &mut out,
    );
    out
}

/// Recursive core; `active` guards against `!Group` reference cycles.
#[allow(clippy::too_many_arguments)]
fn resolve_into(
    selectors: &[SymbolSelector],
    entries: &[(Rva, String)],
    functions: &[Function],
    groups: &[Group],
    cg: &CallGraph,
    active: &mut HashSet<String>,
    out: &mut HashSet<Rva>,
) {
    for sel in selectors {
        match sel {
            SymbolSelector::Name(name) => {
                for (rva, lbl) in entries {
                    if lbl == name {
                        out.insert(*rva);
                    }
                }
            }
            SymbolSelector::Pattern(pat) => {
                for (rva, lbl) in entries {
                    if glob_match(pat, lbl) {
                        out.insert(*rva);
                    }
                }
            }
            SymbolSelector::Address(addr) => {
                let rva = Rva::new(*addr as u32);
                if functions.iter().any(|f| f.entry == rva) {
                    out.insert(rva);
                }
            }
            SymbolSelector::TopXref(n) => {
                for (rva, _) in cg.top_xref(*n) {
                    out.insert(rva);
                }
            }
            SymbolSelector::Group(name) => {
                if !active.insert(name.clone()) {
                    continue;
                }
                if let Some(g) = groups.iter().find(|g| &g.name == name) {
                    resolve_into(&g.symbols, entries, functions, groups, cg, active, out);
                }
                active.remove(name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::BasicBlock;
    use kamy_core::Terminator;

    fn func(rva: u32) -> Function {
        Function {
            entry: Rva::new(rva),
            blocks: vec![BasicBlock {
                start: Rva::new(rva),
                end: Rva::new(rva + 1),
                successors: vec![],
                terminator: Terminator::Return,
            }],
        }
    }

    #[test]
    fn glob_matches_prefix_and_middle() {
        assert!(glob_match("test_*", "test_init"));
        assert!(glob_match("*alloc", "__rust_alloc"));
        assert!(glob_match("core::*::drop_*", "core::ptr::drop_in_place"));
        assert!(glob_match("fn_?", "fn_a"));
        assert!(!glob_match("test_*", "prod_init"));
        assert!(!glob_match("fn_?", "fn_ab"));
    }

    #[test]
    fn resolves_name_pattern_and_address() {
        let funcs = vec![func(0x1000), func(0x1040), func(0x2000)];
        let label = |rva: Rva| match rva.get() {
            0x1000 => "main".to_string(),
            0x1040 => "helper_a".to_string(),
            other => format!("sub_{other:x}"),
        };
        let sels = vec![
            SymbolSelector::Name("main".into()),
            SymbolSelector::Pattern("helper_*".into()),
            SymbolSelector::Address(0x2000),
        ];
        let got = resolve_targets(&sels, &funcs, &label, &[], &CallGraph::default());
        let expected: HashSet<Rva> = [0x1000, 0x1040, 0x2000].into_iter().map(Rva::new).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn sub_rva_label_matched_without_pdb() {
        let funcs = vec![func(0x1000), func(0x2000)];
        let label = |rva: Rva| format!("sub_{:x}", rva.get());
        // Pattern targeting still works with the fallback labels.
        let got = resolve_targets(
            &[SymbolSelector::Pattern("sub_2*".into())],
            &funcs,
            &label,
            &[],
            &CallGraph::default(),
        );
        assert_eq!(got, [Rva::new(0x2000)].into_iter().collect());
    }

    #[test]
    fn group_selector_expands_and_guards_cycles() {
        let funcs = vec![func(0x1000), func(0x2000)];
        let label = |rva: Rva| match rva.get() {
            0x1000 => "main".to_string(),
            other => format!("sub_{other:x}"),
        };
        let groups = vec![
            Group {
                name: "a".into(),
                symbols: vec![
                    SymbolSelector::Name("main".into()),
                    SymbolSelector::Group("b".into()),
                ],
            },
            // `b` references `a` back: the cycle guard must terminate.
            Group {
                name: "b".into(),
                symbols: vec![
                    SymbolSelector::Pattern("sub_2*".into()),
                    SymbolSelector::Group("a".into()),
                ],
            },
        ];
        let got = resolve_targets(
            &[SymbolSelector::Group("a".into())],
            &funcs,
            &label,
            &groups,
            &CallGraph::default(),
        );
        assert_eq!(got, [0x1000, 0x2000].into_iter().map(Rva::new).collect());
    }
}
