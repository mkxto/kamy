//! `kamy` command-line entry point.
//!
//! Thin consumer of the engine library crates (grilling D15). `analyze` and
//! `protect --no-transform` run today; transform-driven `protect` and `verify`
//! await Phase 3.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use kamy_config::Config;
use kamy_disasm::discover_functions;
use kamy_pe::PeFile;

#[derive(Parser)]
#[command(name = "kamy", version, about = "Binary-to-binary protection engine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Discover functions and report transform eligibility.
    Analyze {
        /// Input PE to analyze.
        input: PathBuf,
        /// Optional PDB for symbol names.
        #[arg(long)]
        pdb: Option<PathBuf>,
        /// Write the report here instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Apply transforms per a protection profile.
    Protect {
        /// Input PE to protect.
        input: PathBuf,
        /// Protection profile (YAML). Omit together with --no-transform.
        #[arg(long)]
        profile: Option<PathBuf>,
        /// Protected output path.
        #[arg(short, long)]
        output: PathBuf,
        /// Write the old->new address map here.
        #[arg(long)]
        debug_map: Option<PathBuf>,
        /// Relocate functions through the engine without applying transforms
        /// (round-trip validation path).
        #[arg(long)]
        no_transform: bool,
    },
    /// Test-vector equivalence check between two binaries.
    Verify {
        original: PathBuf,
        protected: PathBuf,
        /// Number of random input vectors.
        #[arg(long, default_value_t = 1000)]
        vectors: u32,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze { input, output, .. } => analyze(&input, output.as_deref()),
        Command::Protect {
            input,
            profile,
            output,
            no_transform,
            ..
        } => {
            if no_transform {
                return protect_identity(&input, &output);
            }
            let profile = profile
                .ok_or_else(|| anyhow::anyhow!("protect requires --profile (or --no-transform)"))?;
            protect_with_profile(&input, &output, &profile)
        }
        Command::Verify { .. } => {
            anyhow::bail!("verify: engine pipeline not yet wired (Phase 2)");
        }
    }
}

fn analyze(input: &Path, output: Option<&Path>) -> anyhow::Result<()> {
    let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let pe = PeFile::parse(&bytes).with_context(|| format!("parsing {}", input.display()))?;

    let module = pe.to_module();
    let seeds = pe.seeds();
    let functions = discover_functions(&module, &seeds);
    let blocks: usize = functions.iter().map(|f| f.blocks.len()).sum();

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

    match output {
        Some(path) => std::fs::write(path, report)
            .with_context(|| format!("writing report {}", path.display()))?,
        None => print!("{report}"),
    }
    Ok(())
}

fn protect_identity(input: &Path, output: &Path) -> anyhow::Result<()> {
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

    let mut by_reason: std::collections::BTreeMap<&'static str, usize> = Default::default();
    for (_, reason) in &report.rejected {
        *by_reason.entry(reason.tag()).or_default() += 1;
    }
    eprintln!(
        "moved {} function(s), rejected {}",
        report.moved.len(),
        report.rejected.len()
    );
    for (reason, count) in by_reason {
        eprintln!("  reject {reason}: {count}");
    }
    Ok(())
}

fn protect_with_profile(input: &Path, output: &Path, profile_path: &Path) -> anyhow::Result<()> {
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
    let mut transform_fn: Box<dyn FnMut(&mut kamy_core::ir::IrFunction)> =
        if let Some(mba) = mba_pass {
            Box::new(move |func: &mut kamy_core::ir::IrFunction| {
                use kamy_transforms::Pass;
                mba.run(func);
            })
        } else {
            Box::new(|_: &mut kamy_core::ir::IrFunction| {})
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

    let mut by_reason: std::collections::BTreeMap<&'static str, usize> = Default::default();
    for (_, reason) in &report.rejected {
        *by_reason.entry(reason.tag()).or_default() += 1;
    }
    eprintln!(
        "moved {} function(s), rejected {}",
        report.moved.len(),
        report.rejected.len()
    );
    for (reason, count) in by_reason {
        eprintln!("  reject {reason}: {count}");
    }
    Ok(())
}
