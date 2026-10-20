//! `kamy dump`: human-readable IR dump of a single function at a chosen stage.

use std::path::Path;

use kamy_triage::Stage;

use super::parse_rva;

/// clap-facing pipeline stage selector.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum StageArg {
    Lift,
    Ssa,
    Optimize,
    Regalloc,
}

impl From<StageArg> for Stage {
    fn from(s: StageArg) -> Self {
        match s {
            StageArg::Lift => Stage::Lift,
            StageArg::Ssa => Stage::Ssa,
            StageArg::Optimize => Stage::Optimize,
            StageArg::Regalloc => Stage::Regalloc,
        }
    }
}

pub(crate) fn run(input: &Path, rva: &str, stage: StageArg) -> anyhow::Result<()> {
    let rva = parse_rva(rva)?;
    let text = kamy_triage::dump_function(input, rva, stage.into())?;
    print!("{text}");
    Ok(())
}
