//! PDB symbol ingest (grilling D10, read side): map function RVAs to their
//! source names for naming and targeting. PDB is an optional input — a binary
//! without one is fully supported; names then fall back to `sub_<rva>`.
//!
//! Read-only: the OMAP/address-map *write* path for debug-map output is a later
//! (Phase 6) deliverable and is intentionally not here.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use kamy_core::Rva;
use pdb::{FallibleIterator, SymbolData};

/// Function RVA → source name, recovered from a PDB's public and procedure
/// symbols.
#[derive(Debug, Default, Clone)]
pub struct PdbSymbols {
    names: HashMap<u32, String>,
}

impl PdbSymbols {
    /// Load function names from the PDB at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let file =
            std::fs::File::open(path).with_context(|| format!("opening PDB {}", path.display()))?;
        let mut pdb =
            pdb::PDB::open(file).with_context(|| format!("parsing {}", path.display()))?;
        let address_map = pdb.address_map().context("reading PDB address map")?;

        let mut names: HashMap<u32, String> = HashMap::new();

        // Public symbols: exported and externally-visible functions.
        let globals = pdb.global_symbols().context("reading PDB global symbols")?;
        let mut syms = globals.iter();
        while let Some(sym) = syms.next().context("iterating global symbols")? {
            if let Ok(SymbolData::Public(data)) = sym.parse() {
                if data.function {
                    if let Some(rva) = data.offset.to_rva(&address_map) {
                        names
                            .entry(rva.0)
                            .or_insert_with(|| data.name.to_string().into_owned());
                    }
                }
            }
        }

        // Procedure symbols live in per-module streams and cover static/local
        // functions the public table omits. `debug_information` borrows the
        // source, not `pdb`, so `module_info` can still take `&mut pdb`.
        let dbi = pdb.debug_information().context("reading PDB debug info")?;
        let mut modules = dbi.modules().context("listing PDB modules")?;
        while let Some(module) = modules.next().context("iterating PDB modules")? {
            let Some(info) = pdb.module_info(&module)? else {
                continue;
            };
            let mut proc_syms = info.symbols().context("reading module symbols")?;
            while let Some(sym) = proc_syms.next().context("iterating module symbols")? {
                if let Ok(SymbolData::Procedure(data)) = sym.parse() {
                    if let Some(rva) = data.offset.to_rva(&address_map) {
                        names
                            .entry(rva.0)
                            .or_insert_with(|| data.name.to_string().into_owned());
                    }
                }
            }
        }

        tracing::debug!(functions = names.len(), path = %path.display(), "loaded PDB symbols");
        Ok(Self { names })
    }

    /// Source name for the function at `rva`, if the PDB named it.
    pub fn name(&self, rva: Rva) -> Option<&str> {
        self.names.get(&rva.get()).map(String::as_str)
    }

    /// Number of named functions.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Display label for the function at `rva`: its PDB name when available,
/// otherwise the `sub_<rva>` fallback. The fallback makes the naming layer
/// identical whether or not a PDB is present.
pub fn function_label(pdb: Option<&PdbSymbols>, rva: Rva) -> String {
    match pdb.and_then(|p| p.name(rva)) {
        Some(name) => name.to_string(),
        None => format!("sub_{:x}", rva.get()),
    }
}
