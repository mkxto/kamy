//! `kamy dump`: human-readable IR or an exact native byte range.

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
    Native,
}

pub(crate) fn run(
    input: &Path,
    rva: &str,
    stage: StageArg,
    size: Option<u32>,
) -> anyhow::Result<()> {
    let rva = parse_rva(rva)?;
    let text = match stage {
        StageArg::Native => {
            let size = size.ok_or_else(|| {
                anyhow::anyhow!(
                    "--stage native requires --size <byte count> from the exact map/report"
                )
            })?;
            kamy_triage::dump_native(input, rva, size)?
        }
        _ => {
            anyhow::ensure!(
                size.is_none(),
                "--size is supported only with --stage native"
            );
            let stage = match stage {
                StageArg::Lift => Stage::Lift,
                StageArg::Ssa => Stage::Ssa,
                StageArg::Optimize => Stage::Optimize,
                StageArg::Regalloc => Stage::Regalloc,
                StageArg::Native => unreachable!(),
            };
            kamy_triage::dump_function(input, rva, stage)?
        }
    };
    print!("{text}");
    Ok(())
}
