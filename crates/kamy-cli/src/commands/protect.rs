//! `kamy protect`: relocation-only, SSA-identity, and profile-driven protect.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use kamy_config::Config;
use kamy_core::ir::IrFunction;
use kamy_core::{FunctionSelector, Rva, SymbolKind};
use kamy_disasm::discover_functions;
use kamy_pe::PeFile;

use super::{parse_rvas, report_to_coverage};

/// IR-level transform applied per function at a given D28 intensity (1.0 = full,
/// 0.0 = no-op); the linker walks a reduced-intensity ladder on register
/// pressure.
type TransformFn = dyn FnMut(Rva, &mut IrFunction, f32);

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

/// `protect --profile`: lift, transform, and relocate. Each profile's passes
/// apply only to the functions its `symbols:` select (empty list = whole
/// module); the first profile to claim a function wins.
fn with_profile(input: &Path, output: &Path, profile_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::from_path(profile_path)
        .with_context(|| format!("loading profile {}", profile_path.display()))?;

    let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let pe = PeFile::parse(&bytes).with_context(|| format!("parsing {}", input.display()))?;

    let mut module = pe.to_module();
    let seeds = pe.seeds();
    module.functions = discover_functions(&module, &seeds);

    let cg = kamy_analysis::build_call_graph(&module);
    let exports: HashMap<u32, &str> = module
        .symbols
        .iter()
        .filter(|s| s.kind == SymbolKind::Export)
        .map(|s| (s.rva.get(), s.name.as_str()))
        .collect();
    let label = |rva: Rva| -> String {
        exports
            .get(&rva.get())
            .map_or_else(|| format!("sub_{:x}", rva.get()), |n| (*n).to_string())
    };

    let passes: Vec<Option<kamy_transforms::MbaPass>> = cfg
        .profiles
        .iter()
        .map(|p| {
            p.passes.iter().find_map(|pass| match pass {
                kamy_config::Pass::MixedBooleanArithmetic(sp) => Some(mba_from(sp)),
                _ => None,
            })
        })
        .collect();

    let mut rva_to_profile: HashMap<u32, usize> = HashMap::new();
    let mut counts = vec![0usize; cfg.profiles.len()];
    for (pi, profile) in cfg.profiles.iter().enumerate() {
        let targets: HashSet<Rva> = if profile.symbols.is_empty() {
            module.functions.iter().map(|f| f.entry).collect()
        } else {
            crate::target::resolve_targets(
                &profile.symbols,
                &module.functions,
                &label,
                &cfg.groups,
                &cg,
            )
        };
        for rva in targets {
            rva_to_profile.entry(rva.get()).or_insert_with(|| {
                counts[pi] += 1;
                pi
            });
        }
    }

    for (pi, profile) in cfg.profiles.iter().enumerate() {
        tracing::info!(
            profile = %profile.name,
            functions = counts[pi],
            mba = passes[pi].is_some(),
            "profile targets"
        );
    }
    for (rva, &pi) in &rva_to_profile {
        tracing::debug!(addr = %Rva::new(*rva), profile = %cfg.profiles[pi].name, "profile applied");
    }

    let cc = kamy_link::build_callconv(&module);
    let mut transform_fn: Box<TransformFn> =
        Box::new(move |rva: Rva, func: &mut IrFunction, intensity: f32| {
            if let Some(&pi) = rva_to_profile.get(&rva.get()) {
                if let Some(mba) = &passes[pi] {
                    mba.run_with_intensity(func, intensity);
                }
            }
        });

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

fn mba_from(sp: &kamy_config::SemanticPass) -> kamy_transforms::MbaPass {
    kamy_transforms::MbaPass {
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
    }
}
