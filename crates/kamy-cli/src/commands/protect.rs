//! `kamy protect`: relocation-only, SSA-identity, and profile-driven protect.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use kamy_config::Config;
use kamy_core::FunctionSelector;
use kamy_disasm::discover_functions;
use kamy_pe::PeFile;

use super::{parse_rvas, report_to_coverage};

/// IR-level transform applied per function at a given D28 intensity (1.0 = full,
/// 0.0 = no-op); the linker walks a reduced-intensity ladder on register
/// pressure.
type TransformFn = dyn FnMut(&mut kamy_core::ir::IrFunction, f32);

/// Parsed `protect` arguments.
pub(crate) struct Args {
    pub(crate) input: PathBuf,
    pub(crate) profile: Option<PathBuf>,
    pub(crate) output: PathBuf,
    pub(crate) no_transform: bool,
    pub(crate) ssa_identity: bool,
    pub(crate) only_rva: Option<String>,
    pub(crate) reject_rva: Option<String>,
}

pub(crate) fn run(args: Args) -> anyhow::Result<()> {
    if args.ssa_identity {
        return ssa_identity(&args);
    }
    if args.no_transform {
        return relocation_only(&args.input, &args.output);
    }
    let profile = args.profile.ok_or_else(|| {
        anyhow::anyhow!("protect requires --profile (or --no-transform / --ssa-identity)")
    })?;
    with_profile(&args.input, &args.output, &profile)
}

/// SSA-identity protect via [`kamy_triage::protect_identity`], optionally
/// restricted by `--only-rva`/`--reject-rva` (mutually exclusive).
fn ssa_identity(args: &Args) -> anyhow::Result<()> {
    let selector = match (&args.only_rva, &args.reject_rva) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--only-rva and --reject-rva are mutually exclusive")
        }
        (Some(only), None) => Some(FunctionSelector::only(parse_rvas(only)?)),
        (None, Some(reject)) => Some(FunctionSelector::reject(parse_rvas(reject)?)),
        (None, None) => None,
    };
    let report = kamy_triage::protect_identity(&args.input, &args.output, selector.as_ref())?;
    let cov = report_to_coverage(&report);
    tracing::info!(
        ssa_lowered = cov.ssa_lowered,
        rejected = cov.rejected,
        relocated = cov.relocated,
        "protection complete"
    );
    for (reason, count) in &cov.by_reason {
        tracing::info!(reason = %reason, count, "reject summary");
    }
    Ok(())
}

/// `protect --no-transform`: relocate every function verbatim (no SSA).
fn relocation_only(input: &Path, output: &Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let pe = PeFile::parse(&bytes).with_context(|| format!("parsing {}", input.display()))?;

    let mut module = pe.to_module();
    let seeds = pe.seeds();
    module.functions = discover_functions(&module, &seeds);

    let (image, report) = kamy_link::protect(
        &pe,
        &module,
        &module.functions,
        &kamy_link::Options::default(),
    )?;
    std::fs::write(output, &image).with_context(|| format!("writing {}", output.display()))?;

    let cov = report_to_coverage(&report);
    tracing::info!(
        ssa_lowered = cov.ssa_lowered,
        rejected = cov.rejected,
        relocated = cov.relocated,
        "protection complete"
    );
    for (reason, count) in &cov.by_reason {
        tracing::info!(reason = %reason, count, "reject summary");
    }
    Ok(())
}

/// `protect --profile`: apply the profile's transforms (MBA today).
fn with_profile(input: &Path, output: &Path, profile_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::from_path(profile_path)
        .with_context(|| format!("loading profile {}", profile_path.display()))?;

    let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let pe = PeFile::parse(&bytes).with_context(|| format!("parsing {}", input.display()))?;

    let mut module = pe.to_module();
    let seeds = pe.seeds();
    module.functions = discover_functions(&module, &seeds);

    let mut mba_pass: Option<kamy_transforms::MbaPass> = None;
    for profile in &cfg.profiles {
        for pass in &profile.passes {
            if let kamy_config::Pass::MixedBooleanArithmetic(sp) = pass {
                mba_pass = Some(kamy_transforms::MbaPass {
                    config: kamy_transforms::mba::MbaConfig {
                        iterations: sp.iterations,
                        probability: sp.probability,
                        semantics: kamy_transforms::mba::MbaSemantics {
                            add: sp.semantics.add,
                            sub: sp.semantics.sub,
                            xor: sp.semantics.xor,
                        },
                        bitwidths: kamy_transforms::mba::MbaBitwidths {
                            bit8: sp.bitwidths.bit8,
                            bit16: sp.bitwidths.bit16,
                            bit32: sp.bitwidths.bit32,
                            bit64: sp.bitwidths.bit64,
                        },
                    },
                    seed: 42,
                });
            }
        }
    }

    let cc = kamy_core::ir::Win64Default;
    let mut transform_fn: Box<TransformFn> = if let Some(mba) = mba_pass {
        Box::new(
            move |func: &mut kamy_core::ir::IrFunction, intensity: f32| {
                mba.run_with_intensity(func, intensity);
            },
        )
    } else {
        Box::new(|_: &mut kamy_core::ir::IrFunction, _: f32| {})
    };

    let (image, report) = kamy_link::protect_with_transforms(
        &pe,
        &module,
        &module.functions,
        &kamy_link::Options::default(),
        &cc,
        &mut *transform_fn,
    )?;

    std::fs::write(output, &image).with_context(|| format!("writing {}", output.display()))?;

    let cov = report_to_coverage(&report);
    tracing::info!(
        ssa_lowered = report.ssa_lowered,
        rejected = report.rejected.len(),
        relocated = report.moved.len(),
        "protection complete"
    );
    for (reason, count) in &cov.by_reason {
        tracing::info!(reason = %reason, count, "reject summary");
    }
    Ok(())
}
