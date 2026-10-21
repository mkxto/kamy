//! `kamy analyze`: report discovered functions and reference-resolution rejects,
//! naming functions from an optional PDB (falling back to `sub_<rva>`).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::Context as _;
use kamy_config::SymbolSelector;
use kamy_core::{ReferenceKind, Rva, SymbolKind};
use kamy_disasm::discover_functions;
use kamy_pdb::PdbSymbols;
use kamy_pe::PeFile;

pub(crate) fn run(
    input: &Path,
    pdb: Option<&Path>,
    output: Option<&Path>,
    select: &[String],
) -> anyhow::Result<()> {
    let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let pe = PeFile::parse(&bytes).with_context(|| format!("parsing {}", input.display()))?;

    let mut module = pe.to_module();
    let seeds = pe.seeds();
    module.functions = discover_functions(&module, &seeds);
    let metadata_references = pe
        .metadata_references()
        .with_context(|| format!("reading PE references from {}", input.display()))?;
    let reference_model = kamy_analysis::build_reference_model(&module, &metadata_references)
        .with_context(|| format!("building reference model for {}", input.display()))?;
    let functions = &module.functions;
    let cg = kamy_analysis::build_call_graph(&module);
    let blocks: usize = functions.iter().map(|f| f.blocks.len()).sum();

    let pdb_syms = match pdb {
        Some(path) => Some(PdbSymbols::load(path)?),
        None => None,
    };
    // Export names are a second naming source for functions the PDB omits.
    let exports: HashMap<u32, &str> = module
        .symbols
        .iter()
        .filter(|s| s.kind == SymbolKind::Export)
        .map(|s| (s.rva.get(), s.name.as_str()))
        .collect();
    let label = |rva: Rva| -> String {
        if let Some(name) = pdb_syms.as_ref().and_then(|p| p.name(rva)) {
            return name.to_string();
        }
        if let Some(name) = exports.get(&rva.get()) {
            return (*name).to_string();
        }
        format!("sub_{:x}", rva.get())
    };

    let named = functions
        .iter()
        .filter(|f| {
            pdb_syms.as_ref().is_some_and(|p| p.name(f.entry).is_some())
                || exports.contains_key(&f.entry.get())
        })
        .count();

    let entry = module
        .entry_point
        .map_or_else(|| "<none>".to_string(), |rva| rva.to_string());

    let mut report = String::new();
    writeln!(report, "image base    {:#x}", module.image_base)?;
    writeln!(report, "entry point   {entry}")?;
    writeln!(report, "sections      {}", module.sections.len())?;
    writeln!(report, "symbols       {}", module.symbols.len())?;
    writeln!(report, "relocations   {}", module.relocations.len())?;
    writeln!(report, "discovery seeds {}", seeds.len())?;
    writeln!(report, "functions     {}", functions.len())?;
    writeln!(report, "basic blocks  {blocks}")?;
    writeln!(report, "references    {}", reference_model.references.len())?;
    for kind in [
        ReferenceKind::DirectBranch,
        ReferenceKind::RipRelative,
        ReferenceKind::Absolute,
        ReferenceKind::ImageRelative,
        ReferenceKind::Switch,
        ReferenceKind::Unwind,
        ReferenceKind::EntryPoint,
        ReferenceKind::Opaque,
    ] {
        let count = reference_model
            .references
            .iter()
            .filter(|reference| reference.kind == kind)
            .count();
        writeln!(report, "  {kind:?}: {count}")?;
    }
    let resolved = functions
        .iter()
        .filter(|function| reference_model.is_resolved(function.entry))
        .count();
    writeln!(report, "reference-resolved functions   {resolved}")?;
    writeln!(
        report,
        "reference-unresolved functions {}",
        functions.len() - resolved
    )?;
    writeln!(
        report,
        "Reference resolution does not establish SSA eligibility."
    )?;
    match &pdb_syms {
        Some(p) => writeln!(
            report,
            "pdb symbols   {} ({named}/{} functions named)",
            p.len(),
            functions.len()
        )?,
        None => writeln!(report, "pdb symbols   <none> ({named} named via exports)")?,
    }

    let selected = if select.is_empty() {
        None
    } else {
        let selectors: Vec<SymbolSelector> = select
            .iter()
            .map(|p| SymbolSelector::Pattern(p.clone()))
            .collect();
        let entries: Vec<_> = functions
            .iter()
            .map(|function| (function.entry, label(function.entry)))
            .collect();
        let set = crate::target::resolve_targets(&selectors, &entries, &[], &cg);
        writeln!(
            report,
            "selected      {} (globs: {})",
            set.len(),
            select.join(", ")
        )?;
        Some(set)
    };

    writeln!(report, "\ntop references:")?;
    for (rva, count) in cg.top_xref(8) {
        writeln!(
            report,
            "  {count:>4} calls  {:#010x}  {}",
            rva.get(),
            label(rva)
        )?;
    }

    let mut sorted: Vec<&kamy_core::Function> = functions.iter().collect();
    sorted.sort_by_key(|f| f.entry.get());
    writeln!(report, "\nfunctions:")?;
    for f in &sorted {
        let references = reference_model
            .functions
            .get(&f.entry)
            .with_context(|| format!("missing reference model for function {}", f.entry))?;
        let mark = match &selected {
            Some(s) if s.contains(&f.entry) => '*',
            _ => ' ',
        };
        writeln!(
            report,
            "{mark} {:#010x}  {:>3} blocks  {:>4} xref  incoming {}  outgoing {}  unresolved {}  {}",
            f.entry.get(),
            f.blocks.len(),
            cg.xref_count(f.entry),
            references.incoming.len(),
            references.outgoing.len(),
            references.unresolved.len(),
            label(f.entry)
        )?;
    }

    writeln!(report, "\nreference reject list:")?;
    writeln!(
        report,
        "Unresolved references prevent safe movement of the listed functions."
    )?;
    let mut rejected = false;
    for f in &sorted {
        let references = reference_model
            .functions
            .get(&f.entry)
            .with_context(|| format!("missing reference model for function {}", f.entry))?;
        if references.unresolved.is_empty() {
            continue;
        }
        rejected = true;
        writeln!(report, "  {:#010x}  {}", f.entry.get(), label(f.entry))?;
        for reference in &references.unresolved {
            writeln!(
                report,
                "    source {:#010x}  target {:#010x}  kind {:?}",
                reference.source.get(),
                reference.target.get(),
                reference.kind
            )?;
        }
    }
    if !rejected {
        writeln!(report, "  <none>")?;
    }

    match output {
        Some(path) => std::fs::write(path, report)
            .with_context(|| format!("writing report {}", path.display()))?,
        None => print!("{report}"),
    }
    Ok(())
}
