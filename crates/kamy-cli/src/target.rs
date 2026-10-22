//! Resolve profile selectors against source-qualified function metadata.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::Context as _;
use kamy_analysis::CallGraph;
use kamy_config::{Config, Group, SymbolSelector};
use kamy_core::{Rva, SymbolId};

pub(crate) struct Entry {
    pub(crate) symbol: SymbolId,
    pub(crate) name: String,
}

/// Match `*` (any run) and `?` (one character), without character classes.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
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

pub(crate) fn profile_owners(
    cfg: &Config,
    entries: &[Entry],
    cg: &CallGraph,
    image_base: u64,
) -> anyhow::Result<BTreeMap<SymbolId, usize>> {
    let excluded: BTreeSet<_> = entries
        .iter()
        .filter(|entry| {
            cfg.exclude
                .iter()
                .any(|rule| glob_match(&rule.pattern, &entry.name))
        })
        .map(|entry| entry.symbol.clone())
        .collect();
    let mut owners = BTreeMap::new();
    for (index, profile) in cfg.profiles.iter().enumerate() {
        let targets = if profile.symbols.is_empty() {
            entries.iter().map(|entry| entry.symbol.clone()).collect()
        } else {
            resolve_targets(&profile.symbols, entries, &cfg.groups, cg, image_base)
                .with_context(|| format!("selecting profile {:?}", profile.name))?
        };
        for symbol in targets {
            if !excluded.contains(&symbol) {
                owners.entry(symbol).or_insert(index);
            }
        }
    }
    Ok(owners)
}

pub(crate) fn resolve_targets(
    selectors: &[SymbolSelector],
    entries: &[Entry],
    groups: &[Group],
    cg: &CallGraph,
    image_base: u64,
) -> anyhow::Result<BTreeSet<SymbolId>> {
    let mut out = BTreeSet::new();
    let mut active = HashSet::new();
    let context = TargetContext {
        entries,
        groups,
        cg,
        image_base,
    };
    resolve_into(selectors, &context, &mut active, &mut out)?;
    Ok(out)
}

struct TargetContext<'a> {
    entries: &'a [Entry],
    groups: &'a [Group],
    cg: &'a CallGraph,
    image_base: u64,
}

fn resolve_into(
    selectors: &[SymbolSelector],
    context: &TargetContext<'_>,
    active: &mut HashSet<String>,
    out: &mut BTreeSet<SymbolId>,
) -> anyhow::Result<()> {
    let entries = context.entries;
    let groups = context.groups;
    let cg = context.cg;
    let image_base = context.image_base;
    for selector in selectors {
        match selector {
            SymbolSelector::Name(name) => {
                out.extend(
                    entries
                        .iter()
                        .filter(|entry| &entry.name == name)
                        .map(|entry| entry.symbol.clone()),
                );
            }
            SymbolSelector::Pattern(pattern) => {
                out.extend(
                    entries
                        .iter()
                        .filter(|entry| glob_match(pattern, &entry.name))
                        .map(|entry| entry.symbol.clone()),
                );
            }
            SymbolSelector::Address(address) => {
                let rva = u32::try_from(*address).ok().map(Rva::new);
                let va_rva = address
                    .checked_sub(image_base)
                    .and_then(|value| u32::try_from(value).ok())
                    .map(Rva::new);
                anyhow::ensure!(
                    rva.is_some() || va_rva.is_some(),
                    "!Address {address:#x} is outside the host RVA/VA range"
                );
                let matches: BTreeSet<_> = entries
                    .iter()
                    .filter(|entry| match &entry.symbol {
                        SymbolId::Host { rva: source } => {
                            Some(*source) == rva || Some(*source) == va_rva
                        }
                        _ => false,
                    })
                    .map(|entry| entry.symbol.clone())
                    .collect();
                anyhow::ensure!(
                    matches.len() <= 1,
                    "!Address {address:#x} is ambiguous between a host RVA and VA"
                );
                out.extend(matches);
            }
            SymbolSelector::TopXref(n) => {
                for (rva, _) in cg.top_xref(*n) {
                    let symbol = SymbolId::Host { rva };
                    if entries.iter().any(|entry| entry.symbol == symbol) {
                        out.insert(symbol);
                    }
                }
            }
            SymbolSelector::Group(name) => {
                if !active.insert(name.clone()) {
                    continue;
                }
                if let Some(group) = groups.iter().find(|group| &group.name == name) {
                    resolve_into(&group.symbols, context, active, out)?;
                }
                active.remove(name);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1_4000_0000;

    fn host(rva: u32, name: &str) -> Entry {
        Entry {
            symbol: SymbolId::Host { rva: Rva::new(rva) },
            name: name.into(),
        }
    }

    fn authored(plugin: &str, symbol: &str) -> Entry {
        Entry {
            symbol: SymbolId::Authored {
                module: plugin.into(),
                symbol: symbol.into(),
            },
            name: format!("{plugin}::{symbol}"),
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
    fn resolves_host_names_patterns_rvas_and_vas() {
        let entries = [
            host(0x1000, "main"),
            host(0x1040, "helper_a"),
            host(0x2000, "sub_2000"),
        ];
        let selectors = [
            SymbolSelector::Name("main".into()),
            SymbolSelector::Pattern("helper_*".into()),
            SymbolSelector::Address(BASE + 0x2000),
        ];
        let got = resolve_targets(&selectors, &entries, &[], &CallGraph::default(), BASE).unwrap();
        assert_eq!(
            got,
            entries.iter().map(|entry| entry.symbol.clone()).collect()
        );
        let got = resolve_targets(
            &[SymbolSelector::Address(0x1000)],
            &entries,
            &[],
            &CallGraph::default(),
            BASE,
        )
        .unwrap();
        assert_eq!(got, [entries[0].symbol.clone()].into_iter().collect());
    }

    #[test]
    fn qualified_targets_do_not_collide_with_host_or_other_modules() {
        let entries = [
            host(0x1000, "same"),
            authored("first", "same"),
            authored("second", "same"),
        ];
        let got = resolve_targets(
            &[SymbolSelector::Name("first::same".into())],
            &entries,
            &[],
            &CallGraph::default(),
            BASE,
        )
        .unwrap();
        assert_eq!(got, [entries[1].symbol.clone()].into_iter().collect());
        let got = resolve_targets(
            &[SymbolSelector::Address(0x1000)],
            &entries,
            &[],
            &CallGraph::default(),
            BASE,
        )
        .unwrap();
        assert_eq!(got, [entries[0].symbol.clone()].into_iter().collect());
    }

    #[test]
    fn numeric_boundaries_never_truncate_or_select_modules() {
        let entries = [
            host(0x1000, "host"),
            host(u32::MAX, "last"),
            authored("p", "local_1000"),
        ];
        for address in [0x1_0000_1000, u64::MAX, BASE + u64::from(u32::MAX) + 1] {
            assert!(
                resolve_targets(
                    &[SymbolSelector::Address(address)],
                    &entries,
                    &[],
                    &CallGraph::default(),
                    BASE
                )
                .is_err()
            );
        }
        for address in [u64::from(u32::MAX), BASE + u64::from(u32::MAX)] {
            let got = resolve_targets(
                &[SymbolSelector::Address(address)],
                &entries,
                &[],
                &CallGraph::default(),
                BASE,
            )
            .unwrap();
            assert_eq!(got, [entries[1].symbol.clone()].into_iter().collect());
        }
        let modules = [authored("p", "local_1000")];
        assert!(
            resolve_targets(
                &[SymbolSelector::Address(0x1000)],
                &modules,
                &[],
                &CallGraph::default(),
                BASE
            )
            .unwrap()
            .is_empty()
        );
        let ambiguous = [host(0x1000, "rva"), host(0x800, "va")];
        assert!(
            resolve_targets(
                &[SymbolSelector::Address(0x1000)],
                &ambiguous,
                &[],
                &CallGraph::default(),
                0x800
            )
            .is_err()
        );
    }

    #[test]
    fn groups_preserve_first_profile_ownership_and_exclusions_win() {
        let entries = [
            host(0x1000, "main"),
            authored("p", "same"),
            authored("q", "same"),
        ];
        let cfg = Config::from_yaml_str(
            "version: '1'\nprofiles:\n- name: first\n  symbols: [!Group shared]\n- name: second\n  symbols: [!Pattern '*']\ngroups:\n- name: shared\n  symbols: [!Name main, !Name 'p::same', !Group cycle]\n- name: cycle\n  symbols: [!Group shared]\nexclude:\n- pattern: 'p::*'\n",
        ).unwrap();
        let owners = profile_owners(&cfg, &entries, &CallGraph::default(), BASE).unwrap();
        assert_eq!(owners.get(&entries[0].symbol), Some(&0));
        assert!(!owners.contains_key(&entries[1].symbol));
        assert_eq!(owners.get(&entries[2].symbol), Some(&1));
    }
}
