//! `kamy` command-line entry point.
//!
//! Thin consumer of the engine library crates (grilling D15). `analyze` runs the
//! Phase 1 pipeline (parse -> discover); `protect`/`verify` await the Phase 2
//! transform/codegen pipeline.

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
        /// Protection profile (YAML).
        #[arg(long)]
        profile: PathBuf,
        /// Protected output path.
        #[arg(short, long)]
        output: PathBuf,
        /// Write the old->new address map here.
        #[arg(long)]
        debug_map: Option<PathBuf>,
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
        Command::Protect { profile, .. } => {
            let cfg = Config::from_path(&profile)
                .with_context(|| format!("loading profile {}", profile.display()))?;
            eprintln!(
                "profile '{}' ok: {} profile(s)",
                cfg.version,
                cfg.profiles.len()
            );
            anyhow::bail!("protect: engine pipeline not yet wired (Phase 2)");
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
