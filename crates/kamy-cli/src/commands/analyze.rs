//! `kamy analyze`: discover functions and report module statistics, naming
//! functions from an optional PDB (falling back to `sub_<rva>`).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::Context as _;
use kamy_core::{Rva, SymbolKind};
use kamy_disasm::discover_functions;
use kamy_pdb::PdbSymbols;
use kamy_pe::PeFile;

pub(crate) fn run(input: &Path, pdb: Option<&Path>, output: Option<&Path>) -> anyhow::Result<()> {
    let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let pe = PeFile::parse(&bytes).with_context(|| format!("parsing {}", input.display()))?;

    let module = pe.to_module();
    let seeds = pe.seeds();
    let functions = discover_functions(&module, &seeds);
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
    match &pdb_syms {
        Some(p) => writeln!(
            report,
            "pdb symbols   {} ({named}/{} functions named)",
            p.len(),
            functions.len()
        )?,
        None => writeln!(report, "pdb symbols   <none> ({named} named via exports)")?,
    }

    let mut sorted: Vec<&kamy_core::Function> = functions.iter().collect();
    sorted.sort_by_key(|f| f.entry.get());
    writeln!(report, "\nfunctions:")?;
    for f in sorted {
        writeln!(
            report,
            "  {:#010x}  {:>3} blocks  {}",
            f.entry.get(),
            f.blocks.len(),
            label(f.entry)
        )?;
    }

    match output {
        Some(path) => std::fs::write(path, report)
            .with_context(|| format!("writing report {}", path.display()))?,
        None => print!("{report}"),
    }
    Ok(())
}
